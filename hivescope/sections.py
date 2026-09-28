"""
Section builders.

Each builder reads a category of forensic data from the hives and
returns a Section. Every block records the full registry key path
it was read from via .path() / .paths().
"""

import datetime

from .const import TOOL_NAME, VERSION
from .core import (
    UTC, open_key, kval, rget, default_val, subkeys, values,
    to_signed32, filetime_to_dt, bytes_filetime, unixdw_to_dt, fmt_dt,
    fmt_tz_offset, strip_resource, hexdump_short, svc_type_str, svc_start_str,
    current_controlset, machine_sid, parse_user_V, parse_user_F, hash_status,
    ACB_DISABLED, ACB_PWNOTREQ, ACB_PWNOEXP, ACB_AUTOLOCK,
)
from .model import Section, p_system, p_software, p_sam, p_user
from . import (sections_exec, sections_files, sections_persist,
               sections_accounts, sections_network, sections_usb,
               sections_system)


# Shared helpers
def compute_ips(system, cs):
    ips = []
    iroot = open_key(system, cs + "\\Services\\Tcpip\\Parameters\\Interfaces")
    for ik in subkeys(iroot):
        dhcp_ip = kval(ik, "DhcpIPAddress")
        static = kval(ik, "IPAddress")
        cand = []
        if dhcp_ip:
            cand.append(dhcp_ip)
        if static:
            cand.extend(static if isinstance(static, (list, tuple)) else [static])
        for c in cand:
            c = (c or "").strip()
            if c and c != "0.0.0.0" and c not in ips:
                ips.append(c)
    return ips


def build_summary(system, software, cs):
    swcv = open_key(software, "Microsoft\\Windows NT\\CurrentVersion")
    product = kval(swcv, "ProductName")
    name = rget(system, cs + "\\Control\\ComputerName\\ComputerName",
                "ComputerName")
    install = (filetime_to_dt(kval(swcv, "InstallTime"))
               or unixdw_to_dt(kval(swcv, "InstallDate")))
    shutdown = filetime_to_dt(bytes_filetime(
        rget(system, cs + "\\Control\\Windows", "ShutdownTime")))
    tz = open_key(system, cs + "\\Control\\TimeZoneInformation")
    active_bias = to_signed32(kval(tz, "ActiveTimeBias"))
    bias = to_signed32(kval(tz, "Bias"))
    tz_off = fmt_tz_offset(active_bias if active_bias is not None else bias)
    ips = compute_ips(system, cs)
    return {
        "name": name or "(unknown)",
        "ips": ips,
        "ip_str": ", ".join(ips) if ips else "(none found)",
        "os": product or "(unknown)",
        "tz": tz_off,
        "install": fmt_dt(install),
        "shutdown": fmt_dt(shutdown),
    }


# Sections
def sec_summary(summary, hives):
    """Combined overview: key facts + the hive files this report was built from."""
    s = Section("summary", "Summary")
    s.kv([
        ("Computer name", summary["name"]),
        ("Computer IP(s)", summary["ip_str"]),
        ("Operating System", summary["os"]),
        ("System timezone", summary["tz"]),
        ("OS install date", summary["install"]),
        ("Last shutdown", summary["shutdown"]),
    ])
    s.sub("Selected registry files")
    files = [
        ("SYSTEM", hives.get("system_path") or "(not loaded)"),
        ("SOFTWARE", hives.get("software_path") or "(not loaded)"),
        ("SAM", hives.get("sam_path") or "(not loaded)"),
    ]
    if hives.get("security_path"):
        files.append(("SECURITY", hives.get("security_path")))
    s.kv(files)
    errs = hives.get("load_errors") or []
    if errs:
        s.sub("Hives that failed to load")
        s.table(["Hive", "Error"], [[n, e] for n, e in errs])
    nts = hives.get("ntusers") or []
    if nts:
        s.sub("User hives (NTUSER.DAT / UsrClass.dat)")
        s.table(["User", "NTUSER.DAT", "UsrClass.dat"],
                [[u.get("name", "?"), u.get("path") or "(none)",
                  "loaded" if u.get("usrclass") is not None else ""]
                 for u in nts])
    s.kv([("Report generated", fmt_dt(datetime.datetime.now(UTC))),
          ("Tool", "%s %s" % (TOOL_NAME, VERSION))])
    return s


def sec_os(system, software, cs):
    s = Section("os", "Operating System")
    swcv = open_key(software, "Microsoft\\Windows NT\\CurrentVersion")
    cver = kval(swcv, "CurrentVersion")
    build = kval(swcv, "CurrentBuildNumber") or kval(swcv, "CurrentBuild")
    ubr = kval(swcv, "UBR")
    display_ver = kval(swcv, "DisplayVersion") or kval(swcv, "ReleaseId")
    vernum = ".".join([x for x in [cver, str(build) if build else None] if x])
    if ubr:
        vernum = vernum + "." + str(ubr)
    sysroot = kval(swcv, "SystemRoot") or kval(swcv, "PathName")
    boot_dir = ""
    if sysroot and len(sysroot) >= 2 and sysroot[1] == ":":
        boot_dir = sysroot[:2] + "\\"
    install = (filetime_to_dt(kval(swcv, "InstallTime"))
               or unixdw_to_dt(kval(swcv, "InstallDate")))
    owner = kval(swcv, "RegisteredOwner")
    org = kval(swcv, "RegisteredOrganization")
    prod_id = kval(swcv, "ProductId")
    shell = rget(software, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                 "Shell")
    boot_opts = rget(system, cs + "\\Control", "SystemStartOptions")
    name = rget(system, cs + "\\Control\\ComputerName\\ComputerName",
                "ComputerName")
    shutdown = filetime_to_dt(bytes_filetime(
        rget(system, cs + "\\Control\\Windows", "ShutdownTime")))
    domain = rget(system, cs + "\\Services\\Tcpip\\Parameters", "Domain") \
        or rget(system, cs + "\\Services\\Tcpip\\Parameters", "NV Domain")

    s.paths([
        p_software("Microsoft\\Windows NT\\CurrentVersion"),
        p_software("Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        p_system(cs, "Control", "ComputerName", "ComputerName"),
        p_system(cs, "Control"),
        p_system(cs, "Control", "Windows"),
        p_system(cs, "Services", "Tcpip", "Parameters"),
    ])
    s.kv([
        ("Operating system", kval(swcv, "ProductName")),
        ("Version number", vernum),
        ("Display version", display_ver),
        ("Installed in", sysroot),
        ("Boot drive", boot_dir),
        ("Install date", fmt_dt(install)),
        ("Registered owner", owner),
        ("Registered organisation", org),
        ("Product ID", prod_id),
        ("Current shell", shell),
        ("Active ControlSet", cs),
        ("Active boot options", boot_opts),
        ("Computer name", name),
        ("Primary DNS domain", domain or "(none)"),
        ("Last shutdown", fmt_dt(shutdown)),
    ])
    return s


def sec_country(system, cs, ntusers):
    s = Section("country", "Country / Locale Settings")
    tz = open_key(system, cs + "\\Control\\TimeZoneInformation")
    bias = to_signed32(kval(tz, "Bias"))
    std_bias = to_signed32(kval(tz, "StandardBias"))
    dlt_bias = to_signed32(kval(tz, "DaylightBias"))
    active = to_signed32(kval(tz, "ActiveTimeBias"))
    s.sub("System timezone")
    s.path(p_system(cs, "Control", "TimeZoneInformation"))
    s.kv([
        ("TimeZoneKeyName", kval(tz, "TimeZoneKeyName")),
        ("Standard name", kval(tz, "StandardName")),
        ("Daylight name", kval(tz, "DaylightName")),
        ("Bias (min from UTC)", "%s  ->  %s"
         % (bias, fmt_tz_offset(bias)) if bias is not None else None),
        ("Standard bias (min)", std_bias),
        ("Daylight bias (min)", dlt_bias),
        ("Active bias (min)", "%s  ->  %s"
         % (active, fmt_tz_offset(active)) if active is not None else None),
    ])
    for u in (ntusers or []):
        intl = open_key(u["reg"], "Control Panel\\International")
        if intl is None:
            continue
        s.sub("User locale: %s" % u.get("name", "?"))
        s.path(p_user(u.get("name", "?"), "Control Panel", "International"))
        s.kv([
            ("Locale", kval(intl, "Locale")),
            ("Locale name", kval(intl, "LocaleName")),
            ("Country", kval(intl, "sCountry")),
            ("Short date", kval(intl, "sShortDate")),
            ("Long date", kval(intl, "sLongDate")),
            ("Time format", kval(intl, "sTimeFormat")),
        ])
    return s


def sec_environment(system, cs, ntusers):
    s = Section("env", "Environment Variables")
    sysenv = open_key(system, cs + "\\Control\\Session Manager\\Environment")
    rows = []
    for v in values(sysenv):
        try:
            rows.append((v.name(), v.value()))
        except Exception:
            continue
    if rows:
        s.sub("System variables")
        s.path(p_system(cs, "Control", "Session Manager", "Environment"))
        s.table(["Name", "Value"], sorted(rows, key=lambda r: r[0].lower()))
    for u in (ntusers or []):
        for path_rel, label in (("Environment", "Environment"),
                                ("Volatile Environment", "Volatile Environment")):
            urows = []
            for v in values(open_key(u["reg"], path_rel)):
                try:
                    urows.append((v.name(), v.value()))
                except Exception:
                    continue
            if urows:
                s.sub("User variables (%s): %s"
                      % (label, u.get("name", "?")))
                s.path(p_user(u.get("name", "?"), path_rel))
                s.table(["Name", "Value"],
                        sorted(urows, key=lambda r: r[0].lower()))
    return s


def _dump_run_key(key):
    rows = []
    for v in values(key):
        try:
            rows.append((v.name(), v.value()))
        except Exception:
            continue
    return rows


def sec_autorun(system, software, cs, ntusers):
    s = Section("autorun", "AutoRun / Persistence")
    machine_run = [
        ("Machine Run", "Microsoft\\Windows\\CurrentVersion\\Run"),
        ("Machine RunOnce", "Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("Machine RunServices",
         "Microsoft\\Windows\\CurrentVersion\\RunServices"),
        ("Machine Policies Run",
         "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
        ("Machine Run (WOW6432Node, 32-bit)",
         "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ]
    any_machine = False
    for label, rel in machine_run:
        rows = _dump_run_key(open_key(software, rel))
        if rows:
            any_machine = True
            s.sub(label)
            s.path(p_software(rel))
            s.table(["Name", "Command"], rows)
    if not any_machine:
        s.note("No machine-level Run/RunOnce entries found.")

    wl_rel = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    wl = open_key(software, wl_rel)
    if wl is not None:
        s.sub("Winlogon")
        s.path(p_software(wl_rel))
        s.kv([
            ("Shell", kval(wl, "Shell")),
            ("Userinit", kval(wl, "Userinit")),
            ("VmApplet", kval(wl, "VmApplet")),
            ("Taskman", kval(wl, "Taskman")),
            ("GinaDLL", kval(wl, "GinaDLL")),
            ("AutoAdminLogon", kval(wl, "AutoAdminLogon")),
            ("DefaultUserName", kval(wl, "DefaultUserName")),
            ("DefaultDomainName", kval(wl, "DefaultDomainName")),
        ])

    be = rget(system, cs + "\\Control\\Session Manager", "BootExecute")
    if be:
        s.sub("Session Manager BootExecute")
        s.path(p_system(cs, "Control", "Session Manager"))
        if isinstance(be, (list, tuple)):
            s.listing([x for x in be if x])
        else:
            s.text(str(be))

    bho_rel = ("Microsoft\\Windows\\CurrentVersion\\Explorer\\"
               "Browser Helper Objects")
    bho = open_key(software, bho_rel)
    bho_rows = []
    for sk in subkeys(bho):
        clsid = sk.name()
        cls = open_key(software, "Classes\\CLSID\\%s" % clsid)
        name = default_val(cls) or ""
        path = default_val(open_key(
            software, "Classes\\CLSID\\%s\\InprocServer32" % clsid)) or ""
        progid = default_val(open_key(
            software, "Classes\\CLSID\\%s\\ProgID" % clsid)) or ""
        bho_rows.append((clsid, name, progid, path))
    if bho_rows:
        s.sub("Browser Helper Objects")
        s.path(p_software(bho_rel))
        s.note("CLSIDs resolved via %s" % p_software("Classes\\CLSID\\{CLSID}"))
        s.table(["CLSID", "Name", "ProgID", "Path"], bho_rows)

    for u in (ntusers or []):
        uname = u.get("name", "?")
        for label, rel in (
            ("Run", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("RunOnce",
             "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ):
            rows = _dump_run_key(open_key(u["reg"], rel))
            if rows:
                s.sub("User %s: %s" % (uname, label))
                s.path(p_user(uname, rel))
                s.table(["Name", "Command"], rows)
        win_rel = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        win = open_key(u["reg"], win_rel)
        load = kval(win, "Load")
        run = kval(win, "Run")
        if load or run:
            s.sub("User %s: Windows Load/Run" % uname)
            s.path(p_user(uname, win_rel))
            s.kv([("Load", load), ("Run", run)])
    return s


def _collect_uninstall(reg, base):
    rows = []
    for sk in subkeys(open_key(reg, base)):
        dn = kval(sk, "DisplayName")
        if not dn:
            continue
        rows.append((
            dn,
            kval(sk, "DisplayVersion") or "",
            kval(sk, "Publisher") or "",
            kval(sk, "InstallLocation") or "",
            kval(sk, "InstallDate") or "",
        ))
    return rows


def sec_software(software, ntusers):
    s = Section("software", "Installed Software")
    src = [
        p_software("Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        p_software("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
    ]
    for u in (ntusers or []):
        src.append(p_user(u.get("name", "?"),
                          "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"))
    s.paths(src)

    rows = []
    rows += _collect_uninstall(
        software, "Microsoft\\Windows\\CurrentVersion\\Uninstall")
    rows += _collect_uninstall(
        software, "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    for u in (ntusers or []):
        rows += _collect_uninstall(
            u["reg"], "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    seen = set()
    uniq = []
    for r in rows:
        k = (r[0].lower(), str(r[1]).lower())
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    uniq.sort(key=lambda r: r[0].lower())
    if uniq:
        s.table(["Name", "Version", "Publisher", "Install location",
                 "Install date"], uniq)
    else:
        s.note("No uninstall entries found.")
    return s


def _mru_names_from_key(key):
    from .core import utf16z
    names = []
    for v in values(key):
        try:
            nm = v.name()
            if nm in ("MRUListEx", "MRUList", ""):
                continue
            data = v.value()
            if isinstance(data, bytes):
                text = utf16z(data)
                if text:
                    names.append(text)
            elif isinstance(data, str) and data:
                names.append(data)
        except Exception:
            continue
    return names


def sec_objects(ntusers):
    s = Section("objects", "Objects / User Activity (MRU)")
    if not ntusers:
        s.note("No NTUSER.DAT loaded - user MRU data unavailable.")
        return s
    for u in ntusers:
        reg = u["reg"]
        uname = u.get("name", "?")
        added = False
        exp = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"

        recent = _mru_names_from_key(open_key(reg, exp + "\\RecentDocs"))
        if recent:
            s.sub("%s: Recent documents" % uname)
            s.path(p_user(uname, exp, "RecentDocs"))
            s.listing(recent)
            added = True

        rm = []
        for v in values(open_key(reg, exp + "\\RunMRU")):
            try:
                if v.name() in ("MRUList", ""):
                    continue
                rm.append(v.value())
            except Exception:
                continue
        if rm:
            s.sub("%s: Run (RunMRU) commands" % uname)
            s.path(p_user(uname, exp, "RunMRU"))
            s.listing(rm)
            added = True

        turls = []
        for v in values(open_key(
                reg, "Software\\Microsoft\\Internet Explorer\\TypedURLs")):
            try:
                turls.append(v.value())
            except Exception:
                continue
        if turls:
            s.sub("%s: Typed URLs (Internet Explorer)" % uname)
            s.path(p_user(uname, "Software\\Microsoft\\Internet Explorer\\TypedURLs"))
            s.listing(turls)
            added = True

        tp = []
        for v in values(open_key(reg, exp + "\\TypedPaths")):
            try:
                tp.append(v.value())
            except Exception:
                continue
        if tp:
            s.sub("%s: Typed paths (Explorer address bar)" % uname)
            s.path(p_user(uname, exp, "TypedPaths"))
            s.listing(tp)
            added = True

        clear = kval(open_key(
            reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
            "ClearRecentDocsOnExit")
        s.kv([("%s: delete recent docs at logoff" % uname,
               "Yes" if clear else "No")])
        if not added:
            s.note("%s: no MRU artifacts found." % uname)
    return s


def _fmt_devkey(name):
    return name.replace("&", ", ").replace("_", " ")


def _enum_devices(system, cs, subpath):
    rows = []
    root = open_key(system, cs + "\\Enum\\" + subpath)
    for dev in subkeys(root):
        devname = _fmt_devkey(dev.name())
        insts = subkeys(dev)
        for inst in insts:
            fn = (kval(inst, "FriendlyName")
                  or strip_resource(kval(inst, "DeviceDesc")) or "")
            mfg = strip_resource(kval(inst, "Mfg") or "")
            rows.append((devname, fn, mfg, inst.name()))
        if not insts:
            rows.append((devname, "", "", ""))
    return rows


def sec_devices(system, cs):
    s = Section("devices", "Devices")
    for title, path in (("USB storage (USBSTOR)", "USBSTOR"),
                        ("USB devices", "USB"),
                        ("SCSI devices", "SCSI"),
                        ("IDE devices", "IDE"),
                        ("PCI devices", "PCI")):
        rows = _enum_devices(system, cs, path)
        if rows:
            s.sub(title)
            s.path(p_system(cs, "Enum", path))
            s.table(["Device", "Name / Description", "Manufacturer",
                     "Instance / Serial"], rows)
    md = open_key(system, "MountedDevices")
    mrows = []
    for v in values(md):
        try:
            data = v.value()
            hx, asc = hexdump_short(
                data if isinstance(data, bytes) else b"", maxlen=None)
            mrows.append((v.name(), hx, asc))
        except Exception:
            continue
    if mrows:
        s.sub("Mounted devices")
        s.path(p_system("MountedDevices"))
        s.table(["Symbolic link", "Data (hex)", "Data (ascii)"],
                sorted(mrows, key=lambda r: r[0]))
    return s


def sec_network(system, software, cs):
    s = Section("network", "Network")
    cards_rel = "Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
    cards = open_key(software, cards_rel)
    crows = []
    for sk in subkeys(cards):
        crows.append((kval(sk, "Description") or "",
                      kval(sk, "ServiceName") or ""))
    if crows:
        s.sub("Network cards")
        s.path(p_software(cards_rel))
        s.table(["Description", "ServiceName (GUID)"], crows)

    iroot = open_key(system, cs + "\\Services\\Tcpip\\Parameters\\Interfaces")
    for ik in subkeys(iroot):
        gw = kval(ik, "DhcpDefaultGateway") or kval(ik, "DefaultGateway")
        if isinstance(gw, (list, tuple)):
            gw = ", ".join([x for x in gw if x])
        ip = kval(ik, "DhcpIPAddress")
        static = kval(ik, "IPAddress")
        if isinstance(static, (list, tuple)):
            static = ", ".join([x for x in static if x and x != "0.0.0.0"])
        pairs = [
            ("Interface", ik.name()),
            ("DHCP enabled", "Yes" if kval(ik, "EnableDHCP") else "No"),
            ("DHCP IP address", ip),
            ("Static IP address", static),
            ("Subnet mask", kval(ik, "SubnetMask")
             or kval(ik, "DhcpSubnetMask")),
            ("Default gateway", gw),
            ("DHCP server", kval(ik, "DhcpServer")),
            ("Name server", kval(ik, "NameServer")
             or kval(ik, "DhcpNameServer")),
            ("Domain", kval(ik, "Domain") or kval(ik, "DhcpDomain")),
        ]
        if any(v for (k, v) in pairs[2:]):
            s.sub("Interface %s" % ik.name())
            s.path(p_system(cs, "Services", "Tcpip", "Parameters",
                            "Interfaces", ik.name()))
            s.kv(pairs)

    lsp_rel = cs + "\\Services\\LanmanServer\\Parameters"
    lsp = open_key(system, lsp_rel)
    ashare_srv = kval(lsp, "AutoShareServer")
    ashare_wks = kval(lsp, "AutoShareWks")
    ts_rel = cs + "\\Control\\Terminal Server"
    ts = open_key(system, ts_rel)
    deny = kval(ts, "fDenyTSConnections")
    rdp_port = rget(system, ts_rel + "\\WinStations\\RDP-Tcp", "PortNumber")
    s.sub("Sharing / Remote access")
    s.paths([p_system(lsp_rel), p_system(ts_rel)])
    s.kv([
        ("Admin auto-shares (Server)",
         "Disabled" if ashare_srv == 0 else "Enabled (default)"),
        ("Admin auto-shares (Workstation)",
         "Disabled" if ashare_wks == 0 else "Enabled (default)"),
        ("Remote Desktop (RDP)",
         "Unknown" if deny is None else ("Enabled" if deny == 0 else "Disabled")),
        ("RDP port", rdp_port),
    ])
    return s


def sec_printers(system, cs):
    s = Section("printers", "Printers")
    rel = cs + "\\Control\\Print\\Printers"
    proot = open_key(system, rel)
    rows = []
    for sk in subkeys(proot):
        rows.append((
            sk.name(),
            kval(sk, "Port") or "",
            kval(sk, "Printer Driver") or "",
            kval(sk, "Location") or "",
            kval(sk, "Share Name") or "",
        ))
    s.path(p_system(rel))
    if rows:
        s.table(["Name", "Port", "Driver", "Location", "Share"], rows)
    else:
        s.note("No printers found in the Print\\Printers key.")
    return s


def sec_users(sam):
    s = Section("users", "Users and Groups (SAM)")
    if sam is None:
        s.note("No SAM hive loaded - account data unavailable.")
        return s
    msid = machine_sid(sam)
    s.path(p_sam("Domains", "Account"))
    s.kv([("Machine SID", msid or "(not resolved)")])

    names_key = open_key(sam, "SAM\\Domains\\Account\\Users\\Names")
    account_names = [sk.name() for sk in subkeys(names_key)]
    if account_names:
        s.sub("Local accounts")
        s.path(p_sam("Domains", "Account", "Users", "Names"))
        s.listing(sorted(account_names, key=str.lower))

    users_key = open_key(sam, "SAM\\Domains\\Account\\Users")
    detail = []
    for sk in subkeys(users_key):
        if sk.name() == "Names":
            continue
        try:
            rid = int(sk.name(), 16)
        except ValueError:
            continue
        vi = parse_user_V(kval(sk, "V"))
        fi = parse_user_F(kval(sk, "F"))
        flags = fi.get("flags", 0)
        sid = "%s-%d" % (msid, rid) if msid else str(rid)
        detail.append((rid, sk.name(), vi, fi, flags, sid))
    detail.sort(key=lambda r: r[0])
    for rid, keyname, vi, fi, flags, sid in detail:
        s.sub("%s (RID %d)" % (vi["username"] or "(no name)", rid))
        s.path(p_sam("Domains", "Account", "Users", keyname))
        s.kv([
            ("SID", sid),
            ("Full name", vi["fullname"]),
            ("Description", vi["comment"]),
            ("Account disabled", "Yes" if flags & ACB_DISABLED else "No"),
            ("Password required", "No" if flags & ACB_PWNOTREQ else "Yes"),
            ("Password never expires", "Yes" if flags & ACB_PWNOEXP else "No"),
            ("Account locked out", "Yes" if flags & ACB_AUTOLOCK else "No"),
            ("LM hash stored", hash_status(vi["lm_len"])),
            ("NT hash stored", hash_status(vi["nt_len"])),
            ("Logon count", fi.get("logon_count", "")),
            ("Failed logons", fi.get("failed_count", "")),
            ("Last logon", fmt_dt(fi.get("last_logon"))),
            ("Password last set", fmt_dt(fi.get("pw_last_set"))),
        ])

    groups = []
    group_srcs = []
    for base_rel, disp in (
            ("SAM\\Domains\\Builtin\\Aliases\\Names",
             p_sam("Domains", "Builtin", "Aliases", "Names")),
            ("SAM\\Domains\\Account\\Aliases\\Names",
             p_sam("Domains", "Account", "Aliases", "Names"))):
        found = [sk.name() for sk in subkeys(open_key(sam, base_rel))]
        if found:
            group_srcs.append(disp)
            groups.extend(found)
    groups = sorted(set(groups), key=str.lower)
    if groups:
        s.sub("Local groups")
        s.paths(group_srcs)
        s.listing(groups)
    return s


def sec_services(system, cs):
    s = Section("services", "Services and Drivers")
    rel = cs + "\\Services"
    sroot = open_key(system, rel)
    rows = []
    for sk in subkeys(sroot):
        typ = kval(sk, "Type")
        start = kval(sk, "Start")
        img = kval(sk, "ImagePath") or ""
        disp = kval(sk, "DisplayName") or ""
        obj = kval(sk, "ObjectName") or ""
        if typ is None and start is None and not img and not disp:
            continue
        rows.append((sk.name(), disp, svc_type_str(typ), svc_start_str(start),
                     img, obj))
    rows.sort(key=lambda r: r[0].lower())
    s.path(p_system(rel))
    s.text("Total entries: %d   (each row is a subkey of the path above)"
           % len(rows))
    s.table(["Key", "Display name", "Type", "Start", "Image path", "Account"],
            rows)
    return s


# Assembly
def build_report(hives):
    """
    hives: dict with optional keys system, software, sam (Registry objects),
    matching *_path strings, and ntusers -> [{"name","reg","path"}].
    Returns (summary_dict, [Section, ...]).
    """
    system = hives.get("system")
    software = hives.get("software")
    sam = hives.get("sam")
    security = hives.get("security")
    ntusers = hives.get("ntusers") or []

    cs = current_controlset(system) if system else "ControlSet001"
    summary = build_summary(system, software, cs)

    sections = [sec_summary(summary, hives)]
    if software or system:
        sections.append(sec_os(system, software, cs))
    if system:
        sections.append(sec_country(system, cs, ntusers))
        sections.append(sec_environment(system, cs, ntusers))
    if software or system or ntusers:
        sections.append(sec_autorun(system, software, cs, ntusers))
    if software or ntusers:
        sections.append(sec_software(software, ntusers))
    sections.append(sec_objects(ntusers))

    # Program execution
    if system or ntusers:
        sections.append(sections_exec.sec_shimcache(system, cs))
        sections.append(sections_exec.sec_userassist(ntusers))
        sections.append(sections_exec.sec_bam(system, cs))
        sections.append(sections_exec.sec_muicache(ntusers))

    # File & folder access
    if ntusers:
        sections.append(sections_files.sec_shellbags(ntusers))
        sections.append(sections_files.sec_comdlg32(ntusers))
        sections.append(sections_files.sec_wordwheel(ntusers))
        sections.append(sections_files.sec_office_mru(ntusers))

    # Persistence
    if software or system or ntusers:
        sections.append(sections_persist.sec_scheduled_tasks(software))
        sections.append(sections_persist.sec_dll_persistence(
            software, system, cs))
        sections.append(sections_persist.sec_startup_approved(ntusers))
        sections.append(sections_persist.sec_com_hijack(ntusers))

    # Devices / USB
    if system:
        sections.append(sec_devices(system, cs))
        sections.append(sections_usb.sec_usb(system, cs, software))

    # Network
    if system:
        sections.append(sec_network(system, software, cs))
    if software:
        sections.append(sections_network.sec_networklist(software))
    if ntusers:
        sections.append(sections_network.sec_rdp_client(ntusers))
        sections.append(sections_network.sec_ssh_clients(ntusers))
    if system:
        sections.append(sections_network.sec_firewall(system, cs))
    if ntusers:
        sections.append(sections_network.sec_proxy(ntusers))
    if system:
        sections.append(sec_printers(system, cs))

    # Accounts & credentials
    sections.append(sec_users(sam))
    if software:
        sections.append(sections_accounts.sec_profilelist(software))
        sections.append(sections_accounts.sec_lastloggedon(software))
    if sam or software:
        sections.append(sections_accounts.sec_sam_groups(sam, software))
    if security:
        sections.append(sections_accounts.sec_security_hive(security))
        sections.append(sections_accounts.sec_lsa_secrets(system, cs, security))
    if system:
        sections.append(sections_accounts.sec_credentials(system, cs, sam))

    # Services
    if system:
        sections.append(sec_services(system, cs))

    # System context
    if software or system:
        sections.append(sections_system.sec_product_key(software))
        sections.append(sections_system.sec_crash_pagefile(system, cs))
        sections.append(sections_system.sec_prefetch(system, cs))
    hive_pairs = [(lbl, hives.get(k)) for lbl, k in (
        ("SYSTEM", "system"), ("SOFTWARE", "software"), ("SAM", "sam"),
        ("SECURITY", "security"))
        if hives.get(k) is not None]
    for u in ntusers:
        if u.get("reg") is not None:
            hive_pairs.append(("NTUSER:" + u.get("name", "?"), u["reg"]))
    if hive_pairs:
        sections.append(sections_system.sec_reg_timeline(hive_pairs))

    return summary, sections
