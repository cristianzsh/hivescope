"""
Account and credential artifacts:
  ProfileList        (SOFTWARE) - SID <-> username <-> profile path
  LastLoggedOnUser   (SOFTWARE) - LogonUI
  SAM group membership + password hints + autologon (SAM/SOFTWARE)
  SECURITY hive      - cached-logon count and audit policy
  LSA secrets        - decrypted Policy\\Secrets + cached domain creds (DCC2)
  Bootkey (syskey) + NT/LM hash decryption (SYSTEM+SAM)
"""

import struct

from .core import (open_key, kval, values, subkeys, utf16z, default_val,
                   sid_from_bytes, parse_user_V, hash_status)
from .model import Section, p_software, p_system, p_sam
from . import crypto

_ALIAS_NAMES = {
    "00000220": "Administrators", "00000221": "Users", "00000222": "Guests",
    "00000223": "Power Users", "00000227": "Backup Operators",
    "0000022b": "Remote Desktop Users", "00000229": "Replicator",
    "00000228": "Network Config Operators",
}


# ProfileList
def sec_profilelist(software):
    s = Section("profilelist", "Accounts - Profile List (SID <-> path)")
    rel = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    pl = open_key(software, rel)
    if pl is None:
        s.note("ProfileList not present.")
        return s
    s.path(p_software("Microsoft", "Windows NT", "CurrentVersion", "ProfileList"))
    rows = []
    for sk in subkeys(pl):
        path = kval(sk, "ProfileImagePath", "")
        uname = str(path).rstrip("\\").split("\\")[-1] if path else ""
        rows.append((sk.name(), uname, str(path)))
    s.table(["SID", "User", "Profile path"], rows)
    return s


# LastLoggedOnUser
def sec_lastloggedon(software):
    s = Section("lastlogon", "Accounts - Last Logged-On User (LogonUI)")
    rel = "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
    k = open_key(software, rel)
    if k is None:
        s.note("LogonUI key not present.")
        return s
    s.path(p_software("Microsoft", "Windows", "CurrentVersion",
                      "Authentication", "LogonUI"))
    s.kv([("LastLoggedOnUser", kval(k, "LastLoggedOnUser")),
          ("LastLoggedOnSAMUser", kval(k, "LastLoggedOnSAMUser")),
          ("LastLoggedOnDisplayName", kval(k, "LastLoggedOnDisplayName")),
          ("SelectedUserSID", kval(k, "SelectedUserSID"))])
    return s


# SAM group membership + password hints + autologon
def _scan_sids(blob):
    sids = []
    if not blob:
        return sids
    n = len(blob)
    i = 0
    while i < n - 8:
        if blob[i] == 0x01:
            sub = blob[i + 1]
            if 0 < sub <= 15 and i + 8 + sub * 4 <= n:
                auth = blob[i + 2:i + 8]
                if auth[:5] == b"\x00\x00\x00\x00\x00" and auth[5] in (5, 1):
                    sid = sid_from_bytes(blob[i:i + 8 + sub * 4])
                    if sid and sid.count("-") >= 3 and sid not in sids:
                        sids.append(sid)
                        i += 8 + sub * 4
                        continue
        i += 1
    return sids


def sec_sam_groups(sam, software):
    s = Section("sam_groups", "Accounts - Group Membership & Hints")
    if sam is None:
        s.note("SAM hive not loaded.")
        return s
    # SID -> name map from ProfileList + SAM Names
    sid_name = {}
    if software is not None:
        pl = open_key(software, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        for sk in subkeys(pl):
            p = kval(sk, "ProfileImagePath", "")
            if p:
                sid_name[sk.name()] = str(p).rstrip("\\").split("\\")[-1]

    any_data = False
    for dom in ("Builtin", "Account"):
        aliases = open_key(sam, "SAM\\Domains\\%s\\Aliases" % dom)
        if aliases is None:
            continue
        rows = []
        for ak in subkeys(aliases):
            if ak.name() == "Members" or not ak.name().startswith("0000"):
                continue
            C = kval(ak, "C")
            if not isinstance(C, bytes):
                continue
            members = _scan_sids(C)
            if not members:
                continue
            gname = _ALIAS_NAMES.get(ak.name().lower(), ak.name())
            for m in members:
                rows.append((gname, m, sid_name.get(m, "")))
        if rows:
            any_data = True
            s.sub("%s domain aliases" % dom)
            s.path(p_sam("SAM", "Domains", dom, "Aliases"))
            s.table(["Group", "Member SID", "User"], rows)

    # Password hints
    users = open_key(sam, "SAM\\Domains\\Account\\Users")
    hints = []
    for uk in subkeys(users):
        if uk.name() == "Names":
            continue
        h = kval(uk, "UserPasswordHint")
        if isinstance(h, bytes) and h:
            txt = utf16z(h, 0)
            if txt:
                hints.append((uk.name(), txt))
    if hints:
        any_data = True
        s.sub("Password hints")
        s.path(p_sam("SAM", "Domains", "Account", "Users", "<RID>",
                     "UserPasswordHint"))
        s.table(["RID", "Hint"], hints)

    # Autologon (cleartext) from SOFTWARE Winlogon
    if software is not None:
        wl = open_key(software, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        if wl is not None:
            au = kval(wl, "AutoAdminLogon")
            dp = kval(wl, "DefaultPassword")
            if au or dp:
                any_data = True
                s.sub("Autologon")
                s.path(p_software("Microsoft", "Windows NT", "CurrentVersion", "Winlogon"))
                s.kv([("AutoAdminLogon", au),
                      ("DefaultUserName", kval(wl, "DefaultUserName")),
                      ("DefaultDomainName", kval(wl, "DefaultDomainName")),
                      ("DefaultPassword", dp)])
    if not any_data:
        s.note("No group membership, hints, or autologon data found.")
    return s


# SECURITY hive
def sec_security_hive(security):
    s = Section("security_hive", "Accounts - SECURITY Hive (LSA)")
    if security is None:
        s.note("SECURITY hive not loaded.")
        return s
    any_data = False

    cache = open_key(security, "Cache")
    if cache is not None:
        nl = [v for v in values(cache)
              if v.name().upper().startswith("NL$")
              and isinstance(v.value(), bytes) and len(v.value()) > 100]
        iter_count = kval(cache, "NL$IterationCount")
        any_data = True
        s.sub("Cached domain logons (MSCache)")
        s.path("HKLM\\SECURITY\\Cache")
        s.kv([("Cached credential entries", len(nl)),
              ("Iteration count", iter_count)])

    if open_key(security, "Policy\\PolAdtEv") is not None:
        any_data = True
        s.sub("Audit policy")
        s.path("HKLM\\SECURITY\\Policy\\PolAdtEv")
        s.text("Audit policy blob present (PolAdtEv).")

    if not any_data:
        s.note("SECURITY hive present but no recognised LSA data.")
    return s


# Bootkey + NT hashes
def _hash_blob(V, hdr_off, base=0xCC):
    try:
        off = struct.unpack_from("<I", V, hdr_off)[0]
        length = struct.unpack_from("<I", V, hdr_off + 4)[0]
        return V[base + off:base + off + length] if length else b""
    except Exception:
        return b""


def sec_credentials(system, cs, sam):
    s = Section("credentials", "Accounts - Bootkey & Password Hashes")
    bootkey = crypto.get_bootkey(system, cs) if system is not None else None
    s.path(p_system(cs, "Control", "Lsa", "{JD,Skew1,GBG,Data}"))
    if bootkey:
        s.kv([("Bootkey (syskey)", bootkey.hex())])
    else:
        s.note("Could not derive bootkey from SYSTEM\\Control\\Lsa.")
        return s

    if sam is None:
        s.note("SAM hive not loaded - cannot decrypt hashes.")
        return s
    if not crypto.crypto_available():
        s.note("Cryptographic support is unavailable in this build; showing the bootkey only.")
        return s

    F = kval(open_key(sam, "SAM\\Domains\\Account"), "F")
    hbk, status = crypto.derive_sam_key(bootkey, F)
    if status != "ok":
        msg = {"checksum_failed": "SAM key checksum failed - the SYSTEM and "
               "SAM hives are from different machines, or a syskey startup "
               "password is set.",
               "unsupported": "Unsupported SAM key revision.",
               "no_data": "SAM domain F value missing."}.get(
                   status, "SAM key error (%s)." % status)
        s.note(msg)
        return s

    users = open_key(sam, "SAM\\Domains\\Account\\Users")
    rows = []
    for uk in subkeys(users):
        if uk.name() == "Names":
            continue
        try:
            rid = int(uk.name(), 16)
        except Exception:
            continue
        V = kval(uk, "V")
        if not isinstance(V, bytes):
            continue
        info = parse_user_V(V)
        nt_blob = _hash_blob(V, 0xA8)
        lm_blob = _hash_blob(V, 0x9C)
        lm, nt = crypto.decrypt_user_hashes(hbk, rid, nt_blob, lm_blob)
        rows.append((info.get("username", ""), rid,
                     lm or hash_status(len(lm_blob)),
                     nt or hash_status(len(nt_blob))))
    s.path(p_sam("SAM", "Domains", "Account", "Users"))
    s.text("pwdump-style (User : RID : LM : NT). Empty NT hash "
           "31d6cfe0... means a blank password.")
    s.table(["User", "RID", "LM hash", "NT hash"], rows)
    return s


def _dbytes(reg, path):
    k = open_key(reg, path)
    if k is None:
        return None
    v = default_val(k)
    return v if isinstance(v, bytes) else None


def _as_text(b):
    if not b:
        return None
    try:
        t = b.decode("utf-16-le").rstrip("\x00")
    except Exception:
        return None
    if t and all(ch.isprintable() or ch in "\t " for ch in t):
        return t
    return None


def _hex_full(b):
    return b.hex()


def _interpret_secret(name, dec):
    if not dec:
        return ("", "(empty)")
    up = name.upper()
    if up == "DPAPI_SYSTEM":
        mk, uk = crypto.dpapi_keys(dec)
        return ("DPAPI machine/user keys", "machine=%s  user=%s" % (mk, uk))
    if up == "NL$KM":
        return ("cached-cred key", _hex_full(dec))
    if up == "$MACHINE.ACC":
        h = crypto.nt_hash(dec)
        return ("machine account", "NTLM=%s  (password %d bytes)"
                % (h or "?", len(dec)))
    if up.startswith("_SC_"):
        txt = _as_text(dec)
        return ("service account (%s)" % name[4:],
                txt if txt is not None else _hex_full(dec))
    if up == "DEFAULTPASSWORD":
        txt = _as_text(dec)
        return ("autologon password",
                txt if txt is not None else _hex_full(dec))
    txt = _as_text(dec)
    if txt is not None:
        return ("cleartext", txt)
    return ("binary", _hex_full(dec))


def sec_lsa_secrets(system, cs, security):
    s = Section("lsa_secrets", "Accounts - LSA Secrets (decrypted)")
    if security is None:
        s.note("SECURITY hive not loaded.")
        return s
    secrets_root = open_key(security, "Policy\\Secrets")
    if secrets_root is None:
        s.note("No Policy\\Secrets in the SECURITY hive.")
        return s
    s.path("HKLM\\SECURITY\\Policy\\Secrets")

    bootkey = crypto.get_bootkey(system, cs) if system is not None else None
    lsa_key = crypto.get_lsa_key(
        bootkey, _dbytes(security, "Policy\\PolEKList"),
        _dbytes(security, "Policy\\PolSecretEncryptionKey"))

    if lsa_key is None:
        if not crypto.crypto_available():
            s.note("Cryptographic support unavailable in this build; listing secret names only.")
        elif bootkey is None:
            s.note("SYSTEM hive required to derive the bootkey / LSA key; listing secret names only.")
        else:
            s.note("Could not derive the LSA key from the SECURITY hive.")
        s.listing([k.name() for k in subkeys(secrets_root)])
        return s

    rows = []
    nlkm = None
    for sk in subkeys(secrets_root):
        name = sk.name()
        curr = _dbytes(security, "Policy\\Secrets\\%s\\CurrVal" % name)
        dec = crypto.decrypt_lsa_secret(lsa_key, curr) if curr else None
        if name.upper() == "NL$KM" and dec:
            nlkm = dec
        if name.upper() == "DPAPI_SYSTEM" and dec:
            mk, uk = crypto.dpapi_keys(dec)
            rows.append((name, "DPAPI machine key", mk or ""))
            rows.append((name, "DPAPI user key", uk or ""))
            continue
        interp, value = _interpret_secret(name, dec)
        rows.append((name, interp, value))
    s.text("Decrypted from Policy\\Secrets with the bootkey-derived LSA key. "
           "Cleartext service/autologon passwords and DPAPI keys appear here.")
    s.table(["Secret", "Type", "Value"], rows)

    cache = open_key(security, "Cache")
    if cache is not None and nlkm is not None:
        dcc = []
        for v in values(cache):
            if not v.name().upper().startswith("NL$"):
                continue
            try:
                blob = v.value()
            except Exception:
                continue
            if not isinstance(blob, bytes):
                continue
            rec = crypto.decrypt_cached_cred(nlkm, blob)
            if rec:
                dcc.append((v.name(), "%s\\%s" % (rec["domain"], rec["user"]),
                            rec["dcc2"]))
        if dcc:
            s.sub("Cached domain credentials (DCC2 / mscash2, hashcat -m 2100)")
            s.path("HKLM\\SECURITY\\Cache")
            s.text("Note: NL_RECORD parsing is best-effort.")
            s.table(["Slot", "Account", "DCC2 hash"], dcc)
        else:
            s.sub("Cached domain credentials")
            s.note("Cache slots present but empty (no cached logons stored).")
    return s
