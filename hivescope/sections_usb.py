"""
USB / removable-media artifacts:
  Connection timestamps (first install / last connect / last removal) from the
    device-property store under Enum\\USBSTOR ... Properties\\{83da6326-...}
  WPD volume friendly names (SOFTWARE\\...\\Windows Portable Devices)
  USB <-> drive-letter correlation via SYSTEM\\MountedDevices
"""

import struct

from .core import (open_key, kval, values, subkeys, filetime_to_dt, fmt_dt)
from .model import Section, p_system, p_software

_TS_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
_TS_PID = {
    "0064": "First install",
    "0066": "First install (alt)",
    "0067": "Last connected",
    "0068": "Last removed",
}


def _raw(v):
    try:
        return v._vkrecord.raw_data()
    except Exception:
        try:
            val = v.value()
            return val if isinstance(val, bytes) else None
        except Exception:
            return None


def _ts_group(props):
    """Return the {83da6326-...} property subkey once, or None."""
    for g in subkeys(props):
        if g.name().lower() == _TS_GUID:
            return g
    return None


def _dev_time(ts_group, pid):
    """Read a FILETIME from <ts_group>\\<pid>\\<default value>."""
    if ts_group is None:
        return ""
    for p in subkeys(ts_group):
        if p.name().lower() == pid:
            for v in values(p):
                raw = _raw(v)
                if raw and len(raw) >= 8:
                    return fmt_dt(filetime_to_dt(
                        struct.unpack_from("<Q", raw, 0)[0]))
    return ""


def _wpd_labels(software):
    """serial-substring -> friendly (volume) name."""
    out = {}
    wpd = open_key(software, "Microsoft\\Windows Portable Devices\\Devices")
    for dk in subkeys(wpd):
        fn = kval(dk, "FriendlyName")
        if fn:
            out[dk.name().upper()] = str(fn)
    return out


def _drive_letters(system):
    """serial-substring -> drive letter, best-effort from MountedDevices."""
    out = {}
    md = open_key(system, "MountedDevices")
    for v in values(md):
        name = v.name()
        if "\\DosDevices\\" not in name:
            continue
        letter = name.split("\\")[-1]
        raw = _raw(v) or b""
        try:
            txt = raw.decode("utf-16-le", "ignore")
        except Exception:
            txt = ""
        out[letter] = txt
    return out


def sec_usb(system, cs, software):
    s = Section("usb", "USB / Removable Media - Timeline")
    usbstor = open_key(system, cs + "\\Enum\\USBSTOR")
    if usbstor is None:
        s.note("Enum\\USBSTOR not present.")
        return s

    wpd = _wpd_labels(software) if software is not None else {}
    letters = _drive_letters(system)

    rows = []
    for dev in subkeys(usbstor):
        # e.g. Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.20
        parts = {}
        for tok in dev.name().split("&"):
            if "_" in tok:
                k, _, val = tok.partition("_")
                parts[k] = val
        vp = " ".join(x for x in (parts.get("Ven"), parts.get("Prod"))
                      if x) or dev.name()
        for inst in subkeys(dev):
            serial = inst.name().split("&")[0]
            fn = kval(inst, "FriendlyName", "")
            props = None
            for sk in subkeys(inst):
                if sk.name() == "Properties":
                    props = sk
            first = last = removed = ""
            if props is not None:
                tsg = _ts_group(props)
                first = _dev_time(tsg, "0064") or _dev_time(tsg, "0066")
                last = _dev_time(tsg, "0067")
                removed = _dev_time(tsg, "0068")
            # correlate label + drive letter by serial substring
            label = ""
            for wk, wn in wpd.items():
                if serial.upper() in wk:
                    label = wn
                    break
            drive = ""
            for lt, txt in letters.items():
                if serial.upper() in txt.upper():
                    drive = lt
                    break
            rows.append((vp, serial, str(fn or label), drive,
                         first, last, removed))
    s.path(p_system(cs, "Enum", "USBSTOR"))
    s.text("Timestamps from device-property store {83da6326-...}. "
           "Drive letter/label correlated via MountedDevices + WPD.")
    s.table(["Device", "Serial", "Friendly name", "Drive", "First install",
             "Last connected", "Last removed"], rows)

    # WPD devices list (volume friendly names, incl. non-USBSTOR)
    if wpd:
        s.sub("Windows Portable Devices (friendly names)")
        s.path(p_software("Microsoft", "Windows Portable Devices", "Devices"))
        s.table(["Device ID", "Friendly name"],
                [(k, v) for k, v in sorted(wpd.items())][:500])
    return s
