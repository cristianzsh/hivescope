"""
Low-level helpers shared across the tool.
"""

import datetime
import struct


# little-endian scalar reads shared by the binary parsers
def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# Safe accessors
def open_key(reg, path):
    """Open a key by backslash path relative to hive root. None if missing."""
    if reg is None:
        return None
    try:
        return reg.open(path)
    except Exception:
        return None


def kval(key, name, default=None):
    """Decoded value of name under key, or default."""
    if key is None:
        return default
    try:
        return key.value(name).value()
    except Exception:
        return default


def rget(reg, path, name, default=None):
    return kval(open_key(reg, path), name, default)


def default_val(key):
    """The unnamed/(default) value of a key, decoded."""
    if key is None:
        return None
    try:
        for v in key.values():
            if v.name() in ("", "(default)"):
                return v.value()
    except Exception:
        pass
    return None


def _safe_iter(gen_factory):
    """Collect items from a python-registry generator, tolerating a corrupt
    entry: return everything gathered up to the point iteration fails rather
    than losing the whole key's contents."""
    out = []
    try:
        it = iter(gen_factory())
    except Exception:
        return out
    while True:
        try:
            out.append(next(it))
        except StopIteration:
            break
        except Exception:
            break
    return out


def subkeys(key):
    if key is None:
        return []
    return _safe_iter(key.subkeys)


def values(key):
    if key is None:
        return []
    return _safe_iter(key.values)


# Conversions / formatting
UTC = datetime.timezone.utc
EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=UTC)
EPOCH_1970 = datetime.datetime(1970, 1, 1, tzinfo=UTC)


def to_signed32(v):
    if v is None:
        return None
    v &= 0xFFFFFFFF
    return v - 0x100000000 if (v & 0x80000000) else v


def filetime_to_dt(ft):
    """100-ns intervals since 1601-01-01 UTC -> datetime (UTC). None if 0/invalid."""
    if not ft:
        return None
    try:
        return EPOCH_1601 + datetime.timedelta(microseconds=ft / 10.0)
    except Exception:
        return None


def bytes_filetime(b, off=0):
    if b is None or len(b) < off + 8:
        return 0
    try:
        return struct.unpack_from("<Q", b, off)[0]
    except Exception:
        return 0


def unixdw_to_dt(v):
    if not v:
        return None
    try:
        return EPOCH_1970 + datetime.timedelta(seconds=int(v))
    except Exception:
        return None


def fmt_dt(dt):
    if dt is None:
        return "(not set)"
    try:
        if dt.year < 1601 or dt.year > 9000:
            return "(not set)"
    except Exception:
        return "(not set)"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_tz_offset(bias_minutes):
    """
    Windows stores: UTC = local + Bias  =>  local = UTC - Bias.
    So the human offset is -Bias. Bias 180 -> UTC-3.
    """
    if bias_minutes is None:
        return "(unknown)"
    off = -int(bias_minutes)
    sign = "+" if off >= 0 else "-"
    a = abs(off)
    h, m = divmod(a, 60)
    return "UTC%s%d:%02d" % (sign, h, m) if m else "UTC%s%d" % (sign, h)


def utf16z(data, start=0):
    """Decode a NUL-terminated UTF-16LE string starting at start."""
    if not data:
        return ""
    out = []
    i = start
    n = len(data)
    while i + 1 < n:
        c = data[i] | (data[i + 1] << 8)
        if c == 0:
            break
        out.append(chr(c))
        i += 2
    return "".join(out)


def strip_resource(s):
    """Turn '@file.dll,-100;Friendly Name' -> 'Friendly Name' (best effort)."""
    if not isinstance(s, str):
        return s
    if ";" in s and s.startswith("@"):
        return s.split(";", 1)[1].strip()
    return s


def hexdump_short(data, maxlen=32):
    if not data:
        return ("", "")
    d = data if maxlen is None else data[:maxlen]
    hx = " ".join("%02X" % b for b in d)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in d)
    if maxlen is not None and len(data) > maxlen:
        hx += " ..."
    return (hx, asc)


def sid_from_bytes(data):
    if not data or len(data) < 8:
        return None
    try:
        rev = data[0]
        cnt = data[1]
        auth = int.from_bytes(data[2:8], "big")
        subs = []
        for i in range(cnt):
            off = 8 + i * 4
            if off + 4 > len(data):
                break
            subs.append(struct.unpack_from("<I", data, off)[0])
        return "S-%d-%d-%s" % (rev, auth, "-".join(str(s) for s in subs))
    except Exception:
        return None


# Service enum maps
def svc_type_str(t):
    if t is None:
        return "(unknown)"
    base = t & 0xFF
    if base & 0x10:
        s = "Win32 application (own process, started by SCM)"
    elif base & 0x20:
        s = "Win32 service (shared process)"
    elif base & 0x01:
        s = "Kernel driver"
    elif base & 0x02:
        s = "File system driver"
    elif base & 0x04:
        s = "Adapter"
    elif base & 0x08:
        s = "Recognizer driver"
    else:
        s = "(unknown 0x%X)" % t
    if t & 0x100:
        s += " [interactive]"
    return s


def svc_start_str(s):
    if s is None:
        return "(unknown)"
    words = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
    w = words.get(s, "0x%X" % s)
    suffix = "(Boot Loader)" if s in (0, 1) else "(Service Control Manager)"
    return "%s %s" % (w, suffix)


# ControlSet resolution
def current_controlset(system):
    cur = rget(system, "Select", "Current", None)
    if cur is None:
        cur = 1
    cs = "ControlSet%03d" % int(cur)
    if open_key(system, cs) is None:
        cs = "ControlSet001"
    return cs


# SAM parsing
# Account control bits
ACB_DISABLED = 0x0001
ACB_PWNOTREQ = 0x0004
ACB_PWNOEXP = 0x0200
ACB_AUTOLOCK = 0x0400


def machine_sid(sam):
    v = kval(open_key(sam, "SAM\\Domains\\Account"), "V")
    if not v or len(v) < 12:
        return None
    try:
        a, b, c = struct.unpack("<III", v[-12:])
        return "S-1-5-21-%d-%d-%d" % (a, b, c)
    except Exception:
        return None


def _v_str(V, hdr_off, base=0xCC):
    try:
        off = struct.unpack_from("<I", V, hdr_off)[0]
        length = struct.unpack_from("<I", V, hdr_off + 4)[0]
    except Exception:
        return ""
    if length == 0:
        return ""
    start = base + off
    raw = V[start:start + length]
    try:
        return raw.decode("utf-16-le", errors="replace")
    except Exception:
        return ""


def _v_len(V, hdr_off):
    try:
        return struct.unpack_from("<I", V, hdr_off + 4)[0]
    except Exception:
        return 0


def parse_user_V(V):
    out = {"username": "", "fullname": "", "comment": "",
           "lm_len": 0, "nt_len": 0}
    if not V or len(V) < 0xCC:
        return out
    out["username"] = _v_str(V, 0x0C)
    out["fullname"] = _v_str(V, 0x18)
    out["comment"] = _v_str(V, 0x24)
    out["lm_len"] = _v_len(V, 0x9C)
    out["nt_len"] = _v_len(V, 0xA8)
    return out


def parse_user_F(F):
    out = {}
    if not F or len(F) < 0x44:
        return out
    try:
        out["last_logon"] = filetime_to_dt(struct.unpack_from("<Q", F, 0x08)[0])
        out["pw_last_set"] = filetime_to_dt(struct.unpack_from("<Q", F, 0x18)[0])
        out["acct_expires"] = filetime_to_dt(struct.unpack_from("<Q", F, 0x20)[0])
        out["last_bad_pw"] = filetime_to_dt(struct.unpack_from("<Q", F, 0x28)[0])
        out["rid"] = struct.unpack_from("<I", F, 0x30)[0]
        out["flags"] = struct.unpack_from("<H", F, 0x38)[0]
        out["failed_count"] = struct.unpack_from("<H", F, 0x40)[0]
        out["logon_count"] = struct.unpack_from("<H", F, 0x42)[0]
    except Exception:
        pass
    return out


def hash_status(length):
    """
    In Vista+ the hash field carries a small header when a hash is present.
    length >= 20 -> a real 16-byte hash (RC4) is stored; larger for AES.
    length == 4  -> header only (no hash stored, e.g. blank/disabled).
    length == 0  -> field absent.
    """
    if length is None:
        return "Unknown"
    if length >= 20:
        return "Yes"
    if length == 4:
        return "No (empty)"
    return "No"
