"""
Network and remote-access artifacts:
  NetworkList profiles + SSIDs + gateway MAC + connect times (SOFTWARE)
  Terminal Server Client (outbound RDP targets)              (NTUSER)
  PuTTY / WinSCP saved sessions & host keys                  (NTUSER)
  Windows Firewall rules                                     (SYSTEM)
  Proxy / AutoConfig settings                                (NTUSER)
"""

import struct

from .core import open_key, kval, values, subkeys
from .model import Section, p_software, p_system, p_user


def _systemtime(b):
    if not isinstance(b, bytes) or len(b) < 16:
        return ""
    (yr, mo, dow, day, hh, mm, ss, ms) = struct.unpack_from("<8H", b, 0)
    if yr == 0:
        return ""
    return "%04d-%02d-%02d %02d:%02d:%02d" % (yr, mo, day, hh, mm, ss)


def _mac(b):
    if not isinstance(b, bytes) or len(b) < 6:
        return ""
    return ":".join("%02x" % x for x in b[:6])


# NetworkList
def sec_networklist(software):
    s = Section("networklist", "Network - Profiles & Wireless SSIDs")
    base = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
    profiles = open_key(software, base + "\\Profiles")
    if profiles is None:
        s.note("NetworkList not present.")
        return s

    # signatures: ProfileGuid -> (SSID, gateway MAC)
    sig = {}
    for kind in ("Unmanaged", "Managed"):
        sk = open_key(software, base + "\\Signatures\\" + kind)
        for hk in subkeys(sk):
            g = kval(hk, "ProfileGuid")
            if g:
                sig[str(g)] = (kval(hk, "Description") or kval(hk,
                               "FirstNetwork"), _mac(kval(hk,
                               "DefaultGatewayMac")))

    rows = []
    for pk in subkeys(profiles):
        name = kval(pk, "ProfileName", "")
        nt = kval(pk, "NameType")
        cat = kval(pk, "Category")
        created = _systemtime(kval(pk, "DateCreated"))
        last = _systemtime(kval(pk, "DateLastConnected"))
        ssid, mac = sig.get(pk.name(), ("", ""))
        rows.append((str(name), created, last, str(ssid or ""), mac,
                     {6: "wired", 71: "wireless", 23: "VPN",
                      243: "mobile broadband"}.get(nt, str(nt)),
                     {0: "public", 1: "private", 2: "domain"}.get(
                         cat, "" if cat is None else str(cat))))
    s.path(p_software("Microsoft", "Windows NT", "CurrentVersion", "NetworkList", "Profiles"))
    s.text("Type = connection medium; Category: public / private / domain. Times are local (SYSTEMTIME).")
    s.table(["Profile", "First connected", "Last connected", "SSID/Signature", "Gateway MAC", "Type", "Category"], rows)
    return s


# Terminal Server Client (outbound RDP)
def sec_rdp_client(ntusers):
    s = Section("rdp_client", "Network - Outbound RDP (Terminal Server Client)")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        base = "Software\\Microsoft\\Terminal Server Client"
        servers = open_key(u["reg"], base + "\\Servers")
        rows = []
        for hk in subkeys(servers):
            rows.append((hk.name(), kval(hk, "UsernameHint", "")))
        # Default MRU list
        default = open_key(u["reg"], base + "\\Default")
        mru = []
        for v in values(default):
            if v.name().startswith("MRU"):
                mru.append(str(v.value()))
        if rows or mru:
            found = True
            s.sub(uname)
            s.path(p_user(uname, base))
            if rows:
                s.table(["Server", "Username hint"], rows)
            if mru:
                s.listing(["MRU: " + m for m in mru])
    if not found:
        s.note("No outbound RDP history found.")
    return s


# PuTTY / WinSCP
def sec_ssh_clients(ntusers):
    s = Section("ssh_clients", "Network - PuTTY / WinSCP Sessions")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        reg = u["reg"]

        psess = open_key(reg, "Software\\SimonTatham\\PuTTY\\Sessions")
        rows = []
        for sk in subkeys(psess):
            rows.append((sk.name(), kval(sk, "HostName", ""),
                         str(kval(sk, "PortNumber", "")),
                         kval(sk, "UserName", "")))
        khost = open_key(reg, "Software\\SimonTatham\\PuTTY\\SshHostKeys")
        hosts = [v.name() for v in values(khost)]
        if rows or hosts:
            found = True
            s.sub("%s - PuTTY" % uname)
            s.path(p_user(uname, "Software\\SimonTatham\\PuTTY"))
            if rows:
                s.table(["Session", "Host", "Port", "User"], rows)
            if hosts:
                s.listing(["Known host: " + h for h in hosts])

        wsess = open_key(reg, "Software\\Martin Prikryl\\WinSCP 2\\Sessions")
        wrows = []
        for sk in subkeys(wsess):
            wrows.append((sk.name(), kval(sk, "HostName", ""),
                          kval(sk, "UserName", "")))
        if wrows:
            found = True
            s.sub("%s - WinSCP" % uname)
            s.path(p_user(uname, "Software\\Martin Prikryl\\WinSCP 2\\Sessions"))
            s.table(["Session", "Host", "User"], wrows)
    if not found:
        s.note("No PuTTY/WinSCP sessions found.")
    return s


# Firewall rules
def _parse_fw_rule(raw):
    d = {}
    for part in str(raw).split("|"):
        if "=" in part:
            k, _, v = part.partition("=")
            d[k] = v
    return d


def sec_firewall(system, cs):
    s = Section("firewall", "Network - Windows Firewall Rules")
    rel = (cs + "\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules")
    k = open_key(system, rel)
    if k is None:
        s.note("FirewallRules not present.")
        return s
    rows = []
    for v in values(k):
        d = _parse_fw_rule(v.value())
        rows.append((d.get("Name", v.name()), d.get("Dir", ""),
                     d.get("Action", ""), d.get("App", "")))
    s.path(p_system(cs, "Services", "SharedAccess", "Parameters", "FirewallPolicy", "FirewallRules"))
    s.text("%d rules (showing first 800). Dir In/Out, Action Allow/Block." % len(rows))
    s.table(["Name", "Dir", "Action", "Application"], rows[:800])
    return s


# Proxy
def sec_proxy(ntusers):
    s = Section("proxy", "Network - Proxy Settings")
    rel = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        k = open_key(u["reg"], rel)
        if k is None:
            continue
        pe = kval(k, "ProxyEnable")
        ps = kval(k, "ProxyServer")
        acu = kval(k, "AutoConfigURL")
        if pe or ps or acu:
            found = True
            s.sub(uname)
            s.path(p_user(uname, rel))
            s.kv([("ProxyEnable", pe), ("ProxyServer", ps),
                  ("ProxyOverride", kval(k, "ProxyOverride")),
                  ("AutoConfigURL", acu)])
    if not found:
        s.note("No non-default proxy configuration found.")
    return s
