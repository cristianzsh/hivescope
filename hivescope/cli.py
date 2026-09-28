"""
Command-line interface and the shared main() entry point.
"""

import argparse
import datetime
import os
import sys

from .const import TOOL_NAME, VERSION

UTC = datetime.timezone.utc
from .hives import (discover_hives_in_folder, open_hives_from_paths,
                    _user_from_path)
from .sections import build_report
from .reporting import render_text, render_html, render_json


def build_argparser():
    p = argparse.ArgumentParser(
        prog="HiveScope.py",
        description="%s %s - Windows registry forensic report. By Cristian Souza (cristianmsbr@gmail.com)"
        % (TOOL_NAME, VERSION))

    p.add_argument("--gui", action="store_true", help="launch the graphical interface (default with no args)")
    p.add_argument("--system", help="path to SYSTEM hive")
    p.add_argument("--software", help="path to SOFTWARE hive")
    p.add_argument("--sam", help="path to SAM hive")
    p.add_argument("--security", help="path to SECURITY hive")
    p.add_argument("--ntuser", action="append", metavar="[name=]PATH", help="path to an NTUSER.DAT")
    p.add_argument("--usrclass", action="append", metavar="[name=]PATH", help="path to a UsrClass.dat")
    p.add_argument("--folder", help="auto-detect hives under this folder")
    p.add_argument("--html", metavar="FILE", help="write an HTML report")
    p.add_argument("--text", metavar="FILE", help="write a text report")
    p.add_argument("--json", metavar="FILE", help="write a JSON report")
    p.add_argument("--timeline", metavar="FILE", help="write an UTC timeline")
    p.add_argument("--timeline-no-keys", action="store_true", help="exclude registry key LastWrite events from --timeline")
    p.add_argument("--timeline-since", metavar="YYYY-MM-DD", help="only timeline events on/after this date (default: OS install date)")
    p.add_argument("--timeline-all", action="store_true", help="include all timeline events, even before install date")
    p.add_argument("--version", action="version", version="%s %s\n\n by Cristian Souza (cristianmsbr@gmail.com)" % (TOOL_NAME, VERSION))
    return p


def run_cli(args):
    paths = {"system_path": args.system, "software_path": args.software,
             "sam_path": args.sam, "security_path": args.security,
             "ntusers": [], "usrclass": []}
    for spec in (args.ntuser or []):
        if "=" in spec:
            name, pth = spec.split("=", 1)
            explicit = True
        else:
            name, pth = os.path.basename(os.path.dirname(spec)) or "user", spec
            explicit = False
        paths["ntusers"].append({"name": name, "path": pth,
                                 "explicit": explicit})
    for spec in (args.usrclass or []):
        if "=" in spec:
            name, pth = spec.split("=", 1)
        else:
            name, pth = _user_from_path(spec), spec
        paths["usrclass"].append({"name": name, "path": pth})

    if args.folder:
        found = discover_hives_in_folder(args.folder)
        for k in ("system_path", "software_path", "sam_path",
                  "security_path"):
            paths[k] = paths.get(k) or found.get(k)
        paths["ntusers"].extend(found["ntusers"])
        paths["usrclass"].extend(found.get("usrclass", []))
        sys.stderr.write(
            "[folder] SYSTEM=%s SOFTWARE=%s SAM=%s SECURITY=%s NTUSER=%d "
            "UsrClass=%d\n" % (
                paths["system_path"], paths["software_path"],
                paths["sam_path"], paths.get("security_path"),
                len(paths["ntusers"]), len(paths["usrclass"])))

    if not (any(paths.get(k) for k in ("system_path", "software_path",
                                       "sam_path", "security_path"))
            or paths["ntusers"] or paths["usrclass"]):
        sys.stderr.write("error: no hives specified. Use --system/--software/"
                         "--sam/--security/--ntuser/--usrclass or "
                         "--folder.\n")
        return 2

    hives = open_hives_from_paths(paths)
    for name, err in hives.get("load_errors", []):
        sys.stderr.write("[warn] could not load %s hive: %s\n" % (name, err))
    summary, sections = build_report(hives)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(summary, sections))
        sys.stderr.write("[html] %s\n" % args.html)
    if args.text:
        with open(args.text, "w", encoding="utf-8") as f:
            f.write(render_text(summary, sections))
        sys.stderr.write("[text] %s\n" % args.text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(render_json(summary, sections))
        sys.stderr.write("[json] %s\n" % args.json)
    if args.timeline:
        from .timeline import (build_timeline, render_timeline_csv,
                               render_timeline_json, timeline_since)
        since = None
        if args.timeline_since:
            try:
                since = datetime.datetime.strptime(
                    args.timeline_since, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                sys.stderr.write("error: --timeline-since must be "
                                 "YYYY-MM-DD\n")
                return 2
        floor = timeline_since(hives, since=since,
                               apply_floor=not args.timeline_all)
        events = build_timeline(
            hives, include_key_writes=not args.timeline_no_keys,
            since=since, apply_floor=not args.timeline_all)
        out = (render_timeline_json(events)
               if args.timeline.lower().endswith(".json")
               else render_timeline_csv(events))
        with open(args.timeline, "w", encoding="utf-8", newline="") as f:
            f.write(out)
        sys.stderr.write("[timeline] %s (%d events%s)\n" % (
            args.timeline, len(events),
            " since " + floor.strftime("%Y-%m-%d") if floor else ""))
    if not (args.html or args.text or args.json or args.timeline):
        print(render_text(summary, sections))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_argparser().parse_args(argv)

    no_inputs = not any([args.system, args.software, args.sam, args.folder,
                         args.ntuser, args.html, args.text, args.json,
                         args.timeline])
    if args.gui or no_inputs:
        try:
            from .gui import launch_gui
            launch_gui()
        except ImportError:
            sys.stderr.write(
                "The GUI needs PyQt6.  Install it with:\n"
                "    pip install PyQt6\n"
                "Or run headless, e.g.:\n"
                "    python3 HiveScope.py --folder <dir> --html out.html\n")
            return 1
        except Exception as e:  # pragma: no cover
            sys.stderr.write("GUI could not start (%s).\n"
                             "Run headless instead, e.g.:\n"
                             "  python3 HiveScope.py --folder <dir> "
                             "--html out.html\n" % e)
            return 1
        return 0

    return run_cli(args)
