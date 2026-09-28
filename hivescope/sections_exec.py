"""
Program-execution artifacts:
  ShimCache / AppCompatCache  (SYSTEM) - Win10/8.1/8/7/XP formats
  UserAssist                  (NTUSER) - ROT13 names, run count, last run
  BAM / DAM                   (SYSTEM) - last execution per exe per user
  MUICache                    (UsrClass/NTUSER)
"""

import codecs
import struct

from .core import (open_key, kval, values, subkeys, filetime_to_dt, fmt_dt,
                   bytes_filetime, u16, u32)
from .model import Section, p_system, p_user


# ShimCache / AppCompatCache
_TS_SIGS = (b"10ts", b"00ts")


def _shim_ts_entries(data, start):
    """
    Parse the 'tsNN'-signature cache entries shared by Windows 8.0/8.1/10.
    Layout per entry: sig(4) unknown(4) entry_data_size(4) path_len(2)
    path(UTF-16LE) last_modified(FILETIME 8) ... Advancement uses the
    entry_data_size field; on any mismatch it resyncs to the next signature.
    """
    rows = []
    off = start
    n = len(data)
    while off + 14 <= n:
        if data[off:off + 4] not in _TS_SIGS:
            nxts = [x for x in (data.find(b"10ts", off + 1),
                                data.find(b"00ts", off + 1)) if x >= 0]
            if not nxts:
                break
            off = min(nxts)
            continue
        entry_size = u32(data, off + 8)
        path_size = u16(data, off + 12)
        p = off + 14
        try:
            path = data[p:p + path_size].decode("utf-16-le", "replace")
        except Exception:
            path = ""
        p += path_size
        ts = filetime_to_dt(bytes_filetime(data, p)) if p + 8 <= n else None
        rows.append((path, ts))
        if entry_size <= 0:
            break
        off = off + 12 + entry_size
    return rows


def _shim_win7(data):
    rows = []
    num = u32(data, 4)
    # detect 32 vs 64 bit by checking the padding dword of the first entry
    is64 = True
    if len(data) >= 128 + 8:
        # x64 has 4 bytes padding at entry offset 4-8 that are zero
        pad = u32(data, 128 + 4)
        is64 = (pad == 0)
    entry_len = 48 if is64 else 32
    off = 128
    n = len(data)
    count = 0
    while off + entry_len <= n and count < num:
        wlen = u16(data, off)
        if is64:
            path_off = struct.unpack_from("<Q", data, off + 8)[0]
            ts = filetime_to_dt(bytes_filetime(data, off + 16))
        else:
            path_off = u32(data, off + 4)
            ts = filetime_to_dt(bytes_filetime(data, off + 8))
        path = ""
        if 0 < path_off < n:
            try:
                path = data[path_off:path_off + wlen].decode(
                    "utf-16-le", "replace")
            except Exception:
                path = ""
        rows.append((path, ts))
        off += entry_len
        count += 1
    return rows


def parse_shimcache(data):
    """Return (format_label, [(path, last_modified), ...])."""
    if not data or len(data) < 8:
        return ("(empty)", [])
    sig0 = u32(data, 0)
    if sig0 in (0x34, 0x30):
        return ("Windows 10", _shim_ts_entries(data, sig0))
    if sig0 == 0xBADC0FEE:
        return ("Windows 7 / Vista", _shim_win7(data))
    if sig0 == 0xDEADBEEF:
        return ("Windows XP", [])          # XP layout omitted (rare)
    if sig0 == 0x80:
        if data[128:132] == b"00ts":
            return ("Windows 8.0", _shim_ts_entries(data, 128))
        if data[128:132] == b"10ts":
            return ("Windows 8.1", _shim_ts_entries(data, 128))
    # some Win10 builds put the signature slightly differently
    if data[0x34:0x38] == b"10ts":
        return ("Windows 10", _shim_ts_entries(data, 0x34))
    if data[0x30:0x34] == b"10ts":
        return ("Windows 10", _shim_ts_entries(data, 0x30))
    return ("(unrecognised)", [])


def sec_shimcache(system, cs):
    s = Section("shimcache", "Program Execution - ShimCache (AppCompatCache)")
    rel = cs + "\\Control\\Session Manager\\AppCompatCache"
    data = kval(open_key(system, rel), "AppCompatCache")
    s.path(p_system(cs, "Control", "Session Manager", "AppCompatCache"))
    if not data:
        s.note("AppCompatCache value not present.")
        return s
    fmt, rows = parse_shimcache(data)
    s.text("Format: %s   |   entries: %d   (order = most-recent first; "
           "presence = the binary existed / was run)" % (fmt, len(rows)))
    if rows:
        s.table(["Path", "Last modified (std info)"],
                [(path, fmt_dt(ts)) for path, ts in rows])
    else:
        s.note("No entries decoded for this format.")
    return s


# UserAssist
_UA_GUID_LABEL = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executables",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcuts",
    "{5E6AB780-7743-11CF-A12B-00AA004AE837}": "IE / links",
    "{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}": "Modern apps",
    "{B267E3AD-A825-4A09-82B9-EEC22AA3B847}": "Modern apps",
    "{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}": "Modern apps",
}


def _rot13(s):
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s


def sec_userassist(ntusers):
    s = Section("userassist", "Program Execution - UserAssist")
    if not ntusers:
        s.note("No NTUSER.DAT loaded.")
        return s
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    any_rows = False
    for u in ntusers:
        uname = u.get("name", "?")
        root = open_key(u["reg"], base)
        for gk in subkeys(root):
            count = open_key(u["reg"], base + "\\" + gk.name() + "\\Count")
            if count is None:
                continue
            rows = []
            for v in values(count):
                try:
                    name = _rot13(v.name())
                    data = v.value()
                except Exception:
                    continue
                runs = last = None
                if isinstance(data, bytes) and len(data) >= 68:
                    try:
                        runs = u32(data, 4)
                        last = filetime_to_dt(bytes_filetime(data, 60))
                    except Exception:
                        pass
                rows.append((name, runs if runs is not None else "",
                             fmt_dt(last) if last else ""))
            if rows:
                any_rows = True
                label = _UA_GUID_LABEL.get(gk.name().upper(), gk.name())
                s.sub("%s - %s" % (uname, label))
                s.path(p_user(uname, base, gk.name(), "Count"))
                s.table(["Name (ROT13-decoded)", "Run count", "Last executed"], rows)
    if not any_rows:
        s.note("No UserAssist entries found.")
    return s


# BAM / DAM
def sec_bam(system, cs):
    s = Section("bam", "Program Execution - BAM/DAM (last run per user)")
    found = False
    for svc in ("bam", "dam"):
        for mid in ("State\\UserSettings", "UserSettings"):
            root = open_key(system, cs + "\\Services\\%s\\%s" % (svc, mid))
            if root is None:
                continue
            for sidk in subkeys(root):
                rows = []
                for v in values(sidk):
                    try:
                        nm = v.name()
                        data = v.value()
                    except Exception:
                        continue
                    if nm in ("Version", "SequenceNumber"):
                        continue
                    ts = None
                    if isinstance(data, bytes) and len(data) >= 8:
                        ts = filetime_to_dt(bytes_filetime(data, 0))
                    if ts:
                        rows.append((nm, fmt_dt(ts)))
                if rows:
                    found = True
                    s.sub("%s - SID %s" % (svc.upper(), sidk.name()))
                    s.path(p_system(cs, "Services", svc, mid, sidk.name()))
                    s.table(["Executable", "Last executed"],
                            sorted(rows, key=lambda r: r[1], reverse=True))
    if not found:
        s.note("No BAM/DAM data (feature is Windows 10 1709+).")
    return s


# MUICache
def sec_muicache(ntusers):
    s = Section("muicache", "Program Execution - MUICache")
    rels = [
        ("Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "usrclass"),
        ("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "ntuser"),
        ("Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", "ntuser"),
    ]
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        for rel, which in rels:
            reg = u.get("usrclass") if which == "usrclass" else u["reg"]
            if reg is None:
                continue
            key = open_key(reg, rel)
            rows = []
            for v in values(key):
                try:
                    nm = v.name()
                    val = v.value()
                except Exception:
                    continue
                if nm.endswith(".FriendlyAppName") or nm.endswith(
                        ".ApplicationCompany") or ("." in nm and "\\" in nm):
                    rows.append((nm, str(val)))
                elif "\\" in nm:
                    rows.append((nm, str(val)))
            if rows:
                found = True
                s.sub("%s (%s)" % (uname, which))
                s.path((p_user(uname, rel) if which == "ntuser"
                        else "HKU\\%s_Classes\\%s" % (uname, rel)))
                s.table(["Value name", "Data"], rows[:500])
    if not found:
        s.note("No MUICache entries found.")
    return s

