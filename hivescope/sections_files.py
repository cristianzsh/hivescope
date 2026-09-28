"""
File and folder access artifacts:
  ShellBags             (UsrClass.dat + NTUSER)
  ComDlg32 MRUs         (NTUSER) - Open/Save + last-visited
  WordWheelQuery        (NTUSER) - Explorer search-box terms
  Office File/Place MRU (NTUSER)
"""


from .core import open_key, values, subkeys, utf16z, u16
from .model import Section, p_user
from .shellitems import parse_shell_item, walk_bagmru


def _pidl_names(data):
    """Return the ordered list of shell-item names in a concatenated PIDL."""
    names = []
    off = 0
    n = len(data)
    while off + 2 <= n:
        size = u16(data, off)
        if size == 0:
            break
        item = data[off:off + size]
        nm, _ = parse_shell_item(item)
        if nm:
            names.append(nm)
        off += size
    return names


# ShellBags
def sec_shellbags(ntusers):
    s = Section("shellbags", "File & Folder Access - ShellBags")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        uc = u.get("usrclass")
        if uc is not None:
            key = open_key(uc, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
            if key is not None:
                rows = []
                walk_bagmru(key, "Desktop", rows)
                if rows:
                    found = True
                    s.sub("%s - UsrClass.dat" % uname)
                    s.path("HKU\\%s_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" % uname)
                    s.table(["Folder path", "Type", "Bag last written"],
                            [[r[0], r[1], r[2]] for r in rows])
        # NTUSER BagMRU (older location / desktop namespace).
        key = open_key(u["reg"], "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BagMRU")
        if key is not None:
            rows = []
            walk_bagmru(key, "Desktop", rows)
            if rows:
                found = True
                s.sub("%s - NTUSER.DAT" % uname)
                s.path(p_user(uname, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BagMRU"))
                s.table(["Folder path", "Type", "Bag last written"],
                        [[r[0], r[1], r[2]] for r in rows])
    if not found:
        s.note("No ShellBags found (UsrClass.dat not collected?).")
    return s


# ComDlg32 - Open/Save and Last-Visited PIDL MRUs
def sec_comdlg32(ntusers):
    s = Section("comdlg32", "File & Folder Access - Open/Save Dialog MRUs")
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        reg = u["reg"]

        osp = open_key(reg, base + "\\OpenSavePidlMRU")
        if osp is not None:
            rows = []
            for extk in subkeys(osp):
                for v in values(extk):
                    if v.name() in ("MRUListEx",):
                        continue
                    try:
                        names = _pidl_names(v.value())
                    except Exception:
                        names = []
                    if names:
                        rows.append((extk.name(), names[-1],
                                     " > ".join(names)))
            if rows:
                found = True
                s.sub("%s - OpenSavePidlMRU (files chosen in dialogs)" % uname)
                s.path(p_user(uname, base + "\\OpenSavePidlMRU"))
                s.table(["Ext", "File", "Full shell path"], rows[:500])

        lvp = open_key(reg, base + "\\LastVisitedPidlMRU")
        if lvp is not None:
            rows = []
            for v in values(lvp):
                if v.name() in ("MRUListEx",):
                    continue
                try:
                    data = v.value()
                    exe = utf16z(data, 0)
                    off = (len(exe) + 1) * 2
                    names = _pidl_names(data[off:])
                    folder = " > ".join(names) if names else ""
                    rows.append((exe, folder))
                except Exception:
                    continue
            if rows:
                found = True
                s.sub("%s - LastVisitedPidlMRU (app -> folder)" % uname)
                s.path(p_user(uname, base + "\\LastVisitedPidlMRU"))
                s.table(["Executable", "Folder last browsed"], rows[:500])
    if not found:
        s.note("No common-dialog MRU data found.")
    return s


# WordWheelQuery - Explorer search terms
def sec_wordwheel(ntusers):
    s = Section("wordwheel", "File & Folder Access - Explorer Search Terms")
    rel = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        key = open_key(u["reg"], rel)
        if key is None:
            continue
        terms = []
        for v in values(key):
            if v.name() == "MRUListEx":
                continue
            try:
                data = v.value()
                if isinstance(data, bytes):
                    terms.append(utf16z(data, 0))
                else:
                    terms.append(str(data))
            except Exception:
                pass
        terms = [t for t in terms if t]
        if terms:
            found = True
            s.sub(uname)
            s.path(p_user(uname, rel))
            s.listing(terms)
    if not found:
        s.note("No Explorer search terms recorded.")
    return s


# Office File / Place MRU
def _clean_office_mru(val):
    # e.g. [F00000000][T01D5...][O00000000]*C:\Users\...\file.docx
    if "*" in val:
        return val.split("*", 1)[1]
    return val


def sec_office_mru(ntusers):
    s = Section("office_mru", "File & Folder Access - Microsoft Office MRU")
    found = False
    for u in ntusers:
        uname = u.get("name", "?")
        office = open_key(u["reg"], "Software\\Microsoft\\Office")
        if office is None:
            continue
        for verk in subkeys(office):                     # 16.0, 15.0, ...
            for appk in subkeys(verk):                   # Word, Excel, ...
                for leaf in ("File MRU", "Place MRU"):
                    node = open_key(u["reg"], "Software\\Microsoft\\Office\\%s\\%s\\%s" % (verk.name(), appk.name(), leaf))
                    if node is None:
                        continue
                    rows = []
                    for v in values(node):
                        if v.name() in ("Max Display",):
                            continue
                        try:
                            rows.append((_clean_office_mru(str(v.value())),))
                        except Exception:
                            pass
                    if rows:
                        found = True
                        s.sub("%s - %s %s / %s" % (uname, appk.name(), verk.name(), leaf))
                        s.path(p_user(uname, "Software\\Microsoft\\Office\\%s\\%s\\%s" % (verk.name(), appk.name(), leaf)))
                        s.listing([r[0] for r in rows])
    if not found:
        s.note("No Microsoft Office MRU entries found.")
    return s
