"""
Hive loading, REGF detection, folder auto-discovery and opening a set of
hives into python-registry objects.
"""

import os
import re


def _resolve_username(reg, fallback):
    """Best-effort real account name from an NTUSER hive; falls back to the
    folder-derived name. Tries Volatile Environment, then a resolved Shell
    Folders path (which contains \\Users\\<name>\\)."""
    if reg is None:
        return fallback
    try:
        ve = reg.open("Volatile Environment")
        for v in ve.values():
            if v.name().upper() == "USERNAME" and v.value():
                return str(v.value())
    except Exception:
        pass
    try:
        sf = reg.open("Software\\Microsoft\\Windows\\CurrentVersion"
                      "\\Explorer\\Shell Folders")
        for v in sf.values():
            try:
                val = str(v.value())
            except Exception:
                continue
            m = re.search(r"\\Users\\([^\\]+)\\", val, re.IGNORECASE)
            if m:
                return m.group(1)
    except Exception:
        pass
    return fallback

_REGmod = None


def _load_registry_module():
    global _REGmod
    if _REGmod is not None:
        return _REGmod
    try:
        from Registry import Registry as _R
        _REGmod = _R
        return _R
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "python-registry is required. Install with:\n"
            "    pip install python-registry\n"
            "(import error: %s)" % e)


def load_hive(path):
    """Return a Registry object for a hive file, or raise a friendly error."""
    R = _load_registry_module()
    return R.Registry(path)


def is_hive_file(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"regf"
    except Exception:
        return False


def discover_hives_in_folder(folder):
    """
    Walk folder and auto-identify SYSTEM/SOFTWARE/SAM/SECURITY (by basename +
    REGF magic), NTUSER.DAT, and per-user UsrClass.dat. Returns a dict of
    paths (caller loads).
    """
    found = {"system_path": None, "software_path": None, "sam_path": None,
             "security_path": None,
             "ntusers": [], "usrclass": []}
    targets = {"system": "system_path", "software": "software_path",
               "sam": "sam_path", "security": "security_path"}
    for root, _dirs, files in os.walk(folder):
        for fn in files:
            low = fn.lower()
            full = os.path.join(root, fn)
            if low in targets:
                if found[targets[low]] is None and is_hive_file(full):
                    found[targets[low]] = full
            elif low == "ntuser.dat":
                if is_hive_file(full):
                    uname = os.path.basename(os.path.dirname(full)) or "user"
                    found["ntusers"].append({"name": uname, "path": full})
            elif low == "usrclass.dat":
                if is_hive_file(full):
                    found["usrclass"].append(
                        {"name": _user_from_path(full), "path": full})
    return found


def _user_from_path(full):
    """Derive the account name from a path containing \\Users\\<name>\\..."""
    parts = full.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p.lower() == "users" and i + 1 < len(parts):
            return parts[i + 1]
    return os.path.basename(os.path.dirname(full)) or "user"


def open_hives_from_paths(paths):
    """
    paths: dict with system/software/sam/security paths, ntusers
    [{name,path}] and usrclass [{name,path}]. Returns a hives dict with loaded
    Registry objects. A hive that fails to load is left as None and recorded in
    hives["load_errors"]; the report is still built from whatever loaded.
    """
    hives = {"system": None, "software": None, "sam": None, "security": None,
             "ntusers": [], "load_errors": [],
             "system_path": paths.get("system_path"),
             "software_path": paths.get("software_path"),
             "sam_path": paths.get("sam_path"),
             "security_path": paths.get("security_path")}

    def _try_load(label, path):
        try:
            return load_hive(path)
        except Exception as e:
            hives["load_errors"].append((label, str(e)))
            return None

    if paths.get("system_path"):
        hives["system"] = _try_load("SYSTEM", paths["system_path"])
    if paths.get("software_path"):
        hives["software"] = _try_load("SOFTWARE", paths["software_path"])
    if paths.get("sam_path"):
        hives["sam"] = _try_load("SAM", paths["sam_path"])
    if paths.get("security_path"):
        hives["security"] = _try_load("SECURITY", paths["security_path"])

    # Load UsrClass hives keyed by user name for later attachment.
    usrclass_by_user = {}
    for uc in paths.get("usrclass", []):
        reg = _try_load("UsrClass.dat (%s)" % uc.get("name", "user"),
                        uc["path"])
        if reg is not None:
            usrclass_by_user[uc.get("name", "user")] = reg

    for u in paths.get("ntusers", []):
        folder_name = u.get("name", "user")
        reg = _try_load("NTUSER.DAT (%s)" % folder_name, u["path"])
        display = folder_name if u.get("explicit") \
            else _resolve_username(reg, folder_name)
        hives["ntusers"].append(
            {"name": display, "path": u["path"], "reg": reg,
             "usrclass": usrclass_by_user.pop(folder_name, None)})

    # UsrClass hives with no matching NTUSER still get their own entry so
    # ShellBags/COM parsers can use them.
    for name, reg in usrclass_by_user.items():
        hives["ntusers"].append({"name": name, "path": None, "reg": None,
                                  "usrclass": reg})
    return hives
