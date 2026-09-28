"""
Consolidated forensic timeline.

All times are UTC: FILETIME and key LastWrite values are already UTC;
NetworkList SYSTEMTIME values (local) are converted with the machine's
ActiveTimeBias.
"""

import codecs
import csv
import datetime
import io
import json
import struct

from .core import (open_key, kval, values, subkeys, bytes_filetime,
                   filetime_to_dt, current_controlset)
from .shellitems import parse_shell_item, items_from_key_values
from .sections_exec import parse_shimcache
from .sections_usb import _ts_group, _raw

UTC = datetime.timezone.utc


def _ev(events, ts, source, artifact, detail):
    if ts is None:
        return
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    if ts.year < 1980:                 # uninitialized / bogus FILETIME
        return
    events.append({"ts": ts, "source": source, "artifact": artifact,
                   "detail": detail})


def _rot13(s):
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s


def _tl_key_writes(events, reg, source):
    if reg is None:
        return
    try:
        root = reg.root()
    except Exception:
        return
    stack = []
    try:
        for sk in root.subkeys():
            stack.append((sk, sk.name()))
    except Exception:
        return
    while stack:
        k, path = stack.pop()
        try:
            ts = k.timestamp()
        except Exception:
            ts = None
        _ev(events, ts, source, "Registry key written", path)
        try:
            for sk in k.subkeys():
                stack.append((sk, path + "\\" + sk.name()))
        except Exception:
            pass


def _tl_userassist(events, ntusers):
    base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    for u in ntusers:
        reg = u.get("reg")
        if reg is None:
            continue
        src = "NTUSER:" + u.get("name", "?")
        for gk in subkeys(open_key(reg, base)):
            count = open_key(reg, base + "\\" + gk.name() + "\\Count")
            for v in values(count):
                try:
                    name = _rot13(v.name())
                    data = v.value()
                except Exception:
                    continue
                if name.startswith("UEME_"):    # session/rollup counters
                    continue
                if not isinstance(data, bytes) or len(data) < 68:
                    continue
                ts = filetime_to_dt(bytes_filetime(data, 60))
                runs = struct.unpack_from("<I", data, 4)[0]
                _ev(events, ts, src, "UserAssist (last run)",
                    "%s (run count %d)" % (name, runs))


def _tl_shimcache(events, system, cs):
    data = kval(open_key(
        system, cs + "\\Control\\Session Manager\\AppCompatCache"),
        "AppCompatCache")
    if not isinstance(data, bytes):
        return
    _fmt, rows = parse_shimcache(data)
    for path, ts in rows:
        _ev(events, ts, "SYSTEM", "ShimCache (file modified)", path)


def _tl_bam(events, system, cs):
    for svc in ("bam", "dam"):
        for mid in ("State\\UserSettings", "UserSettings"):
            root = open_key(system, cs + "\\Services\\%s\\%s" % (svc, mid))
            for sidk in subkeys(root):
                for v in values(sidk):
                    try:
                        nm = v.name()
                        data = v.value()
                    except Exception:
                        continue
                    if nm in ("Version", "SequenceNumber"):
                        continue
                    if not isinstance(data, bytes) or len(data) < 8:
                        continue
                    ts = filetime_to_dt(bytes_filetime(data, 0))
                    _ev(events, ts, "SYSTEM", "BAM (last run)",
                        "%s [%s]" % (nm, sidk.name()))


def _tl_usb(events, system, cs):
    usbstor = open_key(system, cs + "\\Enum\\USBSTOR")
    for dev in subkeys(usbstor):
        for inst in subkeys(dev):
            serial = inst.name().split("&")[0]
            props = None
            for sk in subkeys(inst):
                if sk.name() == "Properties":
                    props = sk
            if props is None:
                continue
            tsg = _ts_group(props)
            if tsg is None:
                continue
            label = "%s serial %s" % (dev.name(), serial)
            for pid, art in (("0064", "USB first install"),
                             ("0066", "USB first install"),
                             ("0067", "USB last connected"),
                             ("0068", "USB last removed")):
                for p in subkeys(tsg):
                    if p.name().lower() != pid:
                        continue
                    for v in values(p):
                        raw = _raw(v)
                        if raw and len(raw) >= 8:
                            _ev(events, filetime_to_dt(
                                struct.unpack_from("<Q", raw, 0)[0]),
                                "SYSTEM", art, label)
                    break


def _tl_shellbags(events, ntusers):
    def walk(key, prefix, src, depth=0):
        if key is None or depth > 12:
            return
        items = items_from_key_values(key)
        subs = {}
        for sk in subkeys(key):
            if sk.name().isdigit():
                subs[int(sk.name())] = sk
        for num in sorted(items):
            name, _kind = parse_shell_item(items[num])
            path = prefix.rstrip("\\") + "\\" + (name or "?").rstrip("\\")
            child = subs.get(num)
            if child is not None:
                try:
                    ts = child.timestamp()
                except Exception:
                    ts = None
                _ev(events, ts, src, "ShellBags (folder)", path)
                walk(child, path, src, depth + 1)

    for u in ntusers:
        src = "NTUSER:" + u.get("name", "?")
        uc = u.get("usrclass")
        if uc is not None:
            walk(open_key(uc, "Local Settings\\Software\\Microsoft\\Windows"
                              "\\Shell\\BagMRU"), "Desktop", src)
        reg = u.get("reg")
        if reg is not None:
            walk(open_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion"
                               "\\Explorer\\BagMRU"), "Desktop", src)


def _active_bias(system, cs):
    tz = open_key(system, cs + "\\Control\\TimeZoneInformation")
    b = kval(tz, "ActiveTimeBias")
    if b is None:
        b = kval(tz, "Bias")
    try:
        return int(b)
    except Exception:
        return None


def _systemtime_utc(b, bias):
    if not isinstance(b, bytes) or len(b) < 16:
        return None
    yr, mo, dow, day, hh, mm, ss, ms = struct.unpack_from("<8H", b, 0)
    if yr == 0:
        return None
    try:
        dt = datetime.datetime(yr, mo, day, hh, mm, ss, tzinfo=UTC)
    except Exception:
        return None
    if bias is not None:
        dt = dt + datetime.timedelta(minutes=bias)      # local -> UTC
    return dt


def _tl_networklist(events, software, bias):
    base = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
    for pk in subkeys(open_key(software, base)):
        name = kval(pk, "ProfileName", "") or pk.name()
        _ev(events, _systemtime_utc(kval(pk, "DateCreated"), bias),
            "SOFTWARE", "Network first connected", str(name))
        _ev(events, _systemtime_utc(kval(pk, "DateLastConnected"), bias),
            "SOFTWARE", "Network last connected", str(name))


def _tl_system_events(events, system, software, cs):
    cv = open_key(software, "Microsoft\\Windows NT\\CurrentVersion")
    _ev(events, _install_date(software), "SOFTWARE", "OS install",
        kval(cv, "ProductName", "") or "")
    st = kval(open_key(system, cs + "\\Control\\Windows"), "ShutdownTime")
    if isinstance(st, bytes) and len(st) >= 8:
        _ev(events, filetime_to_dt(struct.unpack_from("<Q", st, 0)[0]),
            "SYSTEM", "Last shutdown", "")


def _install_date(software):
    if software is None:
        return None
    inst = kval(open_key(software, "Microsoft\\Windows NT\\CurrentVersion"),
                "InstallDate")
    if isinstance(inst, int) and inst > 0:
        try:
            return datetime.datetime.fromtimestamp(inst, UTC)
        except Exception:
            return None
    return None


def timeline_since(hives, since=None, apply_floor=True):
    """The lower time bound applied to the timeline: an explicit 'since', else
    the OS install date (default), else None (no floor)."""
    if since is not None:
        return since
    return _install_date(hives.get("software")) if apply_floor else None


def build_timeline(hives, include_key_writes=True, since=None,
                   apply_floor=True):
    """Return a UTC-sorted list of timeline events across every loaded hive.
    Events before the floor (OS install date by default) are dropped as
    pre-install noise; pass apply_floor=False for everything."""
    events = []
    system = hives.get("system")
    software = hives.get("software")
    ntusers = hives.get("ntusers") or []
    cs = current_controlset(system) if system else "ControlSet001"

    if system is not None:
        _tl_shimcache(events, system, cs)
        _tl_bam(events, system, cs)
        _tl_usb(events, system, cs)
    _tl_userassist(events, ntusers)
    _tl_shellbags(events, ntusers)
    if software is not None:
        bias = _active_bias(system, cs) if system is not None else None
        _tl_networklist(events, software, bias)
    if system is not None and software is not None:
        _tl_system_events(events, system, software, cs)

    if include_key_writes:
        for lbl, key in (("SYSTEM", "system"), ("SOFTWARE", "software"),
                         ("SAM", "sam"), ("SECURITY", "security")):
            _tl_key_writes(events, hives.get(key), lbl)
        for u in ntusers:
            if u.get("reg") is not None:
                _tl_key_writes(events, u["reg"], "NTUSER:" + u.get("name", "?"))

    floor = timeline_since(hives, since=since, apply_floor=apply_floor)
    if floor is not None:
        events = [e for e in events if e["ts"] >= floor]
    events.sort(key=lambda e: e["ts"])
    return events


def render_timeline_csv(events):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp_utc", "source", "artifact", "detail"])
    for e in events:
        w.writerow([e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["source"],
                    e["artifact"], e["detail"]])
    return buf.getvalue()


def render_timeline_json(events):
    return json.dumps(
        [{"timestamp_utc": e["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
          "source": e["source"], "artifact": e["artifact"],
          "detail": e["detail"]} for e in events],
        indent=2, ensure_ascii=False)
