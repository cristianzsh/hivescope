"""
Persistence artifacts beyond the classic Run keys:
  Scheduled Tasks (TaskCache)                             (SOFTWARE)
  DLL-load persistence: AppInit_DLLs, AppCertDlls,
    LSA Security/Authentication/Notification packages,
    IFEO debuggers, Active Setup, print monitors, netsh   (SOFTWARE/SYSTEM)
  StartupApproved (enabled/disabled autoruns)             (NTUSER)
  Per-user COM hijacks (Classes\\CLSID\\InprocServer32)   (NTUSER/UsrClass)
"""

import re

from .core import open_key, kval, values, subkeys, default_val
from .model import Section, p_software, p_system, p_user

_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")


def _utf16_strings(data):
    out = []
    for m in _UTF16_RUN.finditer(data or b""):
        try:
            out.append(m.group().decode("utf-16-le"))
        except Exception:
            pass
    return out


# Scheduled Tasks
def sec_scheduled_tasks(software):
    s = Section("sched_tasks", "Persistence - Scheduled Tasks (TaskCache)")
    base = ("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks")
    tasks = open_key(software, base)
    if tasks is None:
        s.note("TaskCache\\Tasks not present.")
        return s
    s.path(p_software("Microsoft", "Windows NT", "CurrentVersion", "Schedule", "TaskCache", "Tasks"))
    rows = []
    for gk in subkeys(tasks):
        path = kval(gk, "Path", "")
        actions = kval(gk, "Actions")
        cmd = ""
        if isinstance(actions, bytes):
            cand = [x for x in _utf16_strings(actions)
                    if ("\\" in x or "." in x)]
            cmd = " ; ".join(cand[:3])
        rows.append((str(path), gk.name(), cmd))
    rows.sort(key=lambda r: r[0].lower())
    s.text("%d tasks. 'Command' is best-effort text extracted from the Actions blob." % len(rows))
    s.table(["Task path", "GUID", "Action (extracted)"], rows)
    return s


# Machine-wide DLL / debugger persistence
def _packages(val):
    if isinstance(val, list):
        return ", ".join(str(x) for x in val if x)
    if isinstance(val, (bytes, bytearray)):
        return ", ".join(_utf16_strings(bytes(val)))
    return "" if val is None else str(val)


def sec_dll_persistence(software, system, cs):
    s = Section("dll_persistence", "Persistence - DLL Load Points & Debuggers")
    any_data = False

    # AppInit_DLLs (both native and Wow6432Node)
    for rel, label in (
            ("Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs"),
            ("Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
             "AppInit_DLLs (WoW64)")):
        k = open_key(software, rel)
        if k is None:
            continue
        dlls = kval(k, "AppInit_DLLs", "")
        load = kval(k, "LoadAppInit_DLLs", "")
        if dlls:
            any_data = True
            s.sub(label)
            s.path(p_software(*rel.split("\\")))
            s.kv([("AppInit_DLLs", dlls), ("LoadAppInit_DLLs", load)])

    # AppCertDlls
    ac = open_key(system, cs + "\\Control\\Session Manager\\AppCertDlls")
    if ac is not None:
        rows = [(v.name(), str(v.value())) for v in values(ac)]
        if rows:
            any_data = True
            s.sub("AppCertDlls")
            s.path(p_system(cs, "Control", "Session Manager", "AppCertDlls"))
            s.table(["Name", "DLL"], rows)

    # LSA packages
    lsa = open_key(system, cs + "\\Control\\Lsa")
    if lsa is not None:
        pk = [("Security Packages", _packages(kval(lsa, "Security Packages"))),
              ("Authentication Packages", _packages(kval(lsa, "Authentication Packages"))),
              ("Notification Packages", _packages(kval(lsa, "Notification Packages")))]
        pk = [(a, b) for a, b in pk if b]
        if pk:
            any_data = True
            s.sub("LSA packages (password filters / SSP)")
            s.path(p_system(cs, "Control", "Lsa"))
            s.kv(pk)

    # IFEO debuggers / silent-process-exit
    ifeo = open_key(software, "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
    if ifeo is not None:
        rows = []
        for exek in subkeys(ifeo):
            dbg = kval(exek, "Debugger")
            gf = kval(exek, "GlobalFlag")
            if dbg:
                rows.append((exek.name(), "Debugger", str(dbg)))
            if gf not in (None, 0):
                rows.append((exek.name(), "GlobalFlag/SilentExit", "GlobalFlag=%s" % gf))
        if rows:
            any_data = True
            s.sub("Image File Execution Options (debugger hijacks)")
            s.path(p_software("Microsoft", "Windows NT", "CurrentVersion", "Image File Execution Options"))
            s.table(["Image", "Kind", "Value"], rows)

    # Active Setup
    act = open_key(software, "Microsoft\\Active Setup\\Installed Components")
    if act is not None:
        rows = []
        for ck in subkeys(act):
            stub = kval(ck, "StubPath")
            if stub:
                rows.append((default_val(ck) or ck.name(), str(stub)))
        if rows:
            any_data = True
            s.sub("Active Setup (StubPath runs at logon)")
            s.path(p_software("Microsoft", "Active Setup", "Installed Components"))
            s.table(["Component", "StubPath"], rows)

    # Print monitors
    pm = open_key(system, cs + "\\Control\\Print\\Monitors")
    if pm is not None:
        rows = []
        for mk in subkeys(pm):
            drv = kval(mk, "Driver")
            if drv:
                rows.append((mk.name(), str(drv)))
        if rows:
            any_data = True
            s.sub("Print monitors")
            s.path(p_system(cs, "Control", "Print", "Monitors"))
            s.table(["Monitor", "Driver DLL"], rows)

    # Netsh helper DLLs
    ns = open_key(software, "Microsoft\\Netsh")
    if ns is not None:
        rows = [(v.name(), str(v.value())) for v in values(ns)]
        if rows:
            any_data = True
            s.sub("Netsh helper DLLs")
            s.path(p_software("Microsoft", "Netsh"))
            s.table(["Name", "DLL"], rows)

    if not any_data:
        s.note("No DLL load-point or debugger persistence found.")
    return s


# StartupApproved (which autoruns are enabled/disabled)
def sec_startup_approved(ntusers):
    s = Section("startup_approved",
                "Persistence - StartupApproved (enabled/disabled)")
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        for leaf in ("Run", "Run32", "StartupFolder"):
            k = open_key(u["reg"], base + "\\" + leaf)
            if k is None:
                continue
            rows = []
            for v in values(k):
                try:
                    data = v.value()
                    enabled = True
                    if isinstance(data, bytes) and data:
                        enabled = data[0] in (0x02, 0x06)
                    rows.append((v.name(),
                                 "enabled" if enabled else "DISABLED"))
                except Exception:
                    pass
            if rows:
                found = True
                s.sub("%s - %s" % (uname, leaf))
                s.path(p_user(uname, base + "\\" + leaf))
                s.table(["Autorun entry", "State"], rows)
    if not found:
        s.note("No StartupApproved data found.")
    return s


# Per-user COM hijacks
def sec_com_hijack(ntusers):
    s = Section("com_hijack", "Persistence - Per-User COM (Classes\\CLSID InprocServer32)")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        for reg, relbase, label in (
                (u["reg"], "Software\\Classes\\CLSID", "NTUSER"),
                (u.get("usrclass"), "CLSID", "UsrClass")):
            if reg is None:
                continue
            clsid = open_key(reg, relbase)
            if clsid is None:
                continue
            rows = []
            for ck in subkeys(clsid):
                for server in ("InprocServer32", "LocalServer32"):
                    sk = open_key(reg, relbase + "\\" + ck.name() + "\\"
                                  + server)
                    if sk is None:
                        continue
                    dll = default_val(sk)
                    if dll:
                        rows.append((ck.name(), server, str(dll)))
            if rows:
                found = True
                s.sub("%s (%s) - user-registered COM servers" %
                      (uname, label))
                note = ("HKU\\%s_Classes\\CLSID" % uname if label == "UsrClass"
                        else p_user(uname, relbase))
                s.path(note)
                s.table(["CLSID", "Server", "Path"], rows[:500])
    if not found:
        s.note("No per-user COM server registrations found.")
    return s
