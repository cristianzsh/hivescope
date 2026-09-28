"""
Best-effort Windows shell-item (PIDL) parser, used by ShellBags and the
common-dialog MRUs.
"""

import struct

from .core import u16

# A small map of well-known delegate/root folder GUIDs -> friendly names.
WELL_KNOWN_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "User Profile",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access / Home",
    "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
}


def _utf16z_at(b, off):
    if off < 0 or off + 2 > len(b):
        return None
    out = []
    i = off
    while i + 1 < len(b):
        c = b[i] | (b[i + 1] << 8)
        if c == 0:
            break
        out.append(c)
        i += 2
    if not out:
        return None
    try:
        return "".join(chr(c) for c in out)
    except Exception:
        return None


def _ansiz_at(b, off):
    if off < 0 or off >= len(b):
        return None
    end = b.find(b"\x00", off)
    if end < 0:
        end = len(b)
    try:
        return b[off:end].decode("latin-1")
    except Exception:
        return None


def _plausible(s):
    if not s:
        return False
    if len(s) > 255:
        return False
    if any(ord(ch) < 0x20 for ch in s):
        return False
    return len(s.strip()) > 0


def _guid_str(b):
    if len(b) < 16:
        return None
    return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
        struct.unpack_from("<I", b, 0)[0], struct.unpack_from("<H", b, 4)[0],
        struct.unpack_from("<H", b, 6)[0], b[8], b[9], b[10], b[11], b[12],
        b[13], b[14], b[15])


def _beef_long_name(item):
    s = item.find(b"\x04\x00\xef\xbe")
    if s < 4:
        return None
    ver = u16(item, s - 2)
    if ver >= 8:
        cands = [s + 42, s + 46, s + 38]
    elif ver == 7:
        cands = [s + 38, s + 42, s + 34]
    else:
        cands = [s + 14, s + 16, s + 18]
    for off in cands:
        nm = _utf16z_at(item, off)
        if _plausible(nm):
            return nm
    return None


def parse_shell_item(data):
    """Return (name, kind) for one shell item."""
    if not data or len(data) < 3:
        return (None, "empty")
    typ = data[2]
    cls = typ & 0x70
    try:
        if typ == 0x1F:                                    # root / GUID folder
            guid = _guid_str(data[4:20]) if len(data) >= 20 else None
            if guid:
                return (WELL_KNOWN_GUIDS.get(guid.lower(), "{%s}" % guid),
                        "guid")
            return ("(root)", "guid")
        if cls == 0x20 or typ in (0x2F, 0x23, 0x25, 0x2E):  # volume / drive
            drv = _ansiz_at(data, 3)
            if drv and _plausible(drv):
                return (drv.rstrip("\x00"), "volume")
            return ("(volume)", "volume")
        if cls == 0x30:                                     # file / folder
            longn = _beef_long_name(data)
            kind = "folder" if (typ & 0x01) else "file"
            if longn:
                return (longn, kind)
            shortn = _ansiz_at(data, 14)
            if shortn and _plausible(shortn):
                return (shortn.rstrip("\x00"), kind)
            return ("(file 0x%02X)" % typ, kind)
        # URIs and control-panel/delegate items
        return ("(0x%02X item)" % typ, "other")
    except Exception:
        return ("(unparsed 0x%02X)" % typ, "other")


def items_from_key_values(key):
    """Return {index: bytes} for the numbered shell-item values under a key."""
    out = {}
    try:
        for v in key.values():
            nm = v.name()
            if nm.isdigit():
                try:
                    out[int(nm)] = v.value()
                except Exception:
                    pass
    except Exception:
        pass
    return out


def walk_bagmru(key, prefix, rows, depth=0, maxdepth=12):
    """
    Recursively walk a BagMRU key, appending (path, kind, last_write) rows.
    """
    if key is None or depth > maxdepth:
        return
    items = items_from_key_values(key)
    subs = {}
    try:
        for sk in key.subkeys():
            if sk.name().isdigit():
                subs[int(sk.name())] = sk
    except Exception:
        pass
    for num in sorted(items):
        name, kind = parse_shell_item(items[num])
        pn = (name or "?").rstrip("\\")
        path = prefix.rstrip("\\") + "\\" + pn
        child = subs.get(num)
        lw = ""
        if child is not None:
            try:
                lw = child.timestamp().strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                lw = ""
        rows.append((path, kind, lw))
        if child is not None:
            walk_bagmru(child, path, rows, depth + 1, maxdepth)
