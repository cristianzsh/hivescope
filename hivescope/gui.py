"""
PyQt6 GUI.
"""

import os
import sys

from .const import TOOL_NAME, VERSION
from .hives import (is_hive_file, discover_hives_in_folder,
                    open_hives_from_paths, _user_from_path)
from .sections import build_report
from .reporting import render_text, render_html, render_json
from .timeline import (build_timeline, render_timeline_csv,
                       render_timeline_json, timeline_since)


# Small font helper
def _asset(name):
    """Resolve a bundled asset path."""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(here, "assets", name)]
    base = getattr(sys, "_MEIPASS", None)
    if base:
        cands.append(os.path.join(base, "hivescope", "assets", name))
        cands.append(os.path.join(base, "assets", name))
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[0]


def _mono(size=9):
    from PyQt6.QtGui import QFont
    f = QFont()
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setFamilies(["Cascadia Mono", "Cascadia Code", "Consolas",
                   "DejaVu Sans Mono", "Menlo", "Monaco", "Courier New"])
    f.setPointSize(size)
    return f


def _fit_table(t, has_header=True, allow_hbar=False):
    from PyQt6.QtCore import Qt
    t.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    t.setHorizontalScrollBarPolicy(
        Qt.ScrollBarPolicy.ScrollBarAsNeeded if allow_hbar
        else Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    total = 2 * t.frameWidth() + 2
    if has_header and not t.horizontalHeader().isHidden():
        total += t.horizontalHeader().height()
    for r in range(t.rowCount()):
        if not t.isRowHidden(r):
            h = t.rowHeight(r)
            total += h if h > 0 else 24
    if allow_hbar:
        total += t.horizontalScrollBar().sizeHint().height()
    t.setMinimumHeight(total)
    t.setMaximumHeight(total)


def _fit_list(lw):
    from PyQt6.QtCore import Qt
    lw.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    total = 2 * lw.frameWidth() + 6
    for i in range(lw.count()):
        if not lw.isRowHidden(i):
            h = lw.sizeHintForRow(i)
            total += h if h and h > 0 else 22
    lw.setMinimumHeight(total)
    lw.setMaximumHeight(total)


# filter adapters
class _TableFilter:
    def __init__(self, table, has_header, allow_hbar):
        self.t = table
        self.hh = has_header
        self.hbar = allow_hbar

    def filter(self, q):
        vis = 0
        t = self.t
        for r in range(t.rowCount()):
            if not q:
                t.setRowHidden(r, False)
                vis += 1
                continue
            joined = []
            for c in range(t.columnCount()):
                it = t.item(r, c)
                if it:
                    joined.append(it.text())
            hid = q not in " ".join(joined).lower()
            t.setRowHidden(r, hid)
            if not hid:
                vis += 1
        _fit_table(t, self.hh, self.hbar)
        return vis


class _ListFilter:
    def __init__(self, lw):
        self.lw = lw

    def filter(self, q):
        vis = 0
        for i in range(self.lw.count()):
            it = self.lw.item(i)
            hid = bool(q) and q not in it.text().lower()
            it.setHidden(hid)
            if not hid:
                vis += 1
        _fit_list(self.lw)
        return vis


class _TextFilter:
    def __init__(self, text):
        self.text = (text or "").lower()

    def filter(self, q):
        return 1 if (not q or q in self.text) else 0


class _Group:
    """A heading + source-key labels + one body widget that hide together."""
    def __init__(self, headers, body_widget, body_filter):
        self.headers = headers
        self.body = body_widget
        self.bf = body_filter

    def filter(self, q):
        if self.bf is not None:
            n = self.bf.filter(q)
        else:
            text = " ".join(h.text() for h in self.headers).lower()
            n = 1 if (not q or q in text) else 0
        show = (not q) or n > 0
        for h in self.headers:
            h.setVisible(show)
        if self.body is not None:
            self.body.setVisible(show)
        return n


def _make_copy_table():
    from PyQt6.QtWidgets import QTableWidget, QApplication
    from PyQt6.QtGui import QKeySequence

    class CopyTable(QTableWidget):
        def keyPressEvent(self, e):
            if e.matches(QKeySequence.StandardKey.Copy):
                rngs = self.selectedRanges()
                if rngs:
                    r0 = rngs[0]
                    lines = []
                    for r in range(r0.topRow(), r0.bottomRow() + 1):
                        if self.isRowHidden(r):
                            continue
                        cells = []
                        for c in range(r0.leftColumn(), r0.rightColumn() + 1):
                            it = self.item(r, c)
                            cells.append(it.text() if it else "")
                        lines.append("\t".join(cells))
                    QApplication.clipboard().setText("\n".join(lines))
                return
            super().keyPressEvent(e)

    return CopyTable


def launch_gui(initial_paths=None, _test=False):
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QStackedWidget,
        QTableWidgetItem, QHeaderView, QScrollArea, QFrame, QFileDialog,
        QMessageBox, QSplitter, QAbstractItemView, QSizePolicy,
    )
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import (QAction, QKeySequence, QShortcut, QPalette,
                             QIcon, QPixmap)

    CopyTable = _make_copy_table()

    class Window(QMainWindow):
        def __init__(self, paths=None):
            super().__init__()
            self.setWindowTitle("%s %s" % (TOOL_NAME, VERSION))
            self.resize(1240, 820)
            _ic = QIcon(_asset("icon.png"))
            if not _ic.isNull():
                self.setWindowIcon(_ic)
            self.paths = {"system_path": None, "software_path": None,
                          "sam_path": None, "security_path": None,
                          "ntusers": [], "usrclass": []}
            if paths:
                self.paths.update(paths)
            self.paths.setdefault("usrclass", [])
            self.summary = None
            self.sections = []
            self.hives = None
            self._groups = [] # per page: list of _Group
            self._titles = [] # per page: base title
            pal = self.palette()
            self._muted = pal.color(QPalette.ColorGroup.Disabled,
                                    QPalette.ColorRole.WindowText)
            self._build_menus()
            self._build_body()
            if self._has_any():
                self.parse()
            else:
                self._show_placeholder()

        # menus
        def _mkact(self, text, slot, shortcut=None):
            a = QAction(text, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(shortcut)
            return a

        def _build_menus(self):
            mb = self.menuBar()
            filem = mb.addMenu("&File")
            filem.addAction(self._mkact(
                "Open SYSTEM\u2026", lambda: self.open_one("system_path")))
            filem.addAction(self._mkact(
                "Open SOFTWARE\u2026", lambda: self.open_one("software_path")))
            filem.addAction(self._mkact(
                "Open SAM\u2026", lambda: self.open_one("sam_path")))
            filem.addAction(self._mkact(
                "Open SECURITY\u2026", lambda: self.open_one("security_path")))
            filem.addAction(self._mkact(
                "Add NTUSER.DAT\u2026", self.add_ntuser))
            filem.addAction(self._mkact(
                "Add UsrClass.dat\u2026", self.add_usrclass))
            filem.addSeparator()
            filem.addAction(self._mkact(
                "Import from folder\u2026", self.import_folder,
                QKeySequence("Ctrl+O")))
            filem.addAction(self._mkact(
                "Parse / Refresh", self.parse, QKeySequence("F5")))
            filem.addSeparator()
            filem.addAction(self._mkact(
                "Export HTML report\u2026", self.export_html,
                QKeySequence("Ctrl+E")))
            filem.addAction(self._mkact(
                "Export text report\u2026", self.export_text))
            filem.addAction(self._mkact(
                "Export JSON report\u2026", self.export_json))
            filem.addAction(self._mkact(
                "Export timeline (CSV)\u2026", self.export_timeline))
            filem.addSeparator()
            filem.addAction(self._mkact("Clear", self.clear))
            filem.addAction(self._mkact(
                "Exit", self.close, QKeySequence("Ctrl+Q")))

            editm = mb.addMenu("&Edit")
            editm.addAction(self._mkact(
                "Find\u2026", lambda: self.search.setFocus(),
                QKeySequence.StandardKey.Find))
            editm.addAction(self._mkact(
                "Clear search", lambda: self.search.clear()))

            helpm = mb.addMenu("&Help")
            helpm.addAction(self._mkact("About", self.about))

        # body
        def _build_body(self):
            central = QWidget()
            outer = QVBoxLayout(central)
            outer.setContentsMargins(10, 8, 10, 6)
            outer.setSpacing(8)

            srow = QHBoxLayout()
            srow.addWidget(QLabel("Search:"))
            self.search = QLineEdit()
            self.search.setPlaceholderText(
                "Filter the whole report\u2026  (Ctrl+F, Esc to clear)")
            self.search.setClearButtonEnabled(True)
            self.search.textChanged.connect(self._on_search)
            srow.addWidget(self.search, 1)
            self.count = QLabel("")
            srow.addWidget(self.count)
            outer.addLayout(srow)

            split = QSplitter(Qt.Orientation.Horizontal)
            self.sidebar = QListWidget()
            self.sidebar.setMinimumWidth(210)
            self.sidebar.setMaximumWidth(320)
            self.sidebar.currentRowChanged.connect(self._on_section)
            split.addWidget(self.sidebar)
            self.stack = QStackedWidget()
            split.addWidget(self.stack)
            split.setStretchFactor(0, 0)
            split.setStretchFactor(1, 1)
            split.setSizes([240, 980])
            outer.addWidget(split, 1)

            self.setCentralWidget(central)
            self.statusBar().showMessage("Ready.")

            QShortcut(QKeySequence("Esc"), self.search,
                      activated=self.search.clear)

        # label builders
        def _title_label(self, text):
            lb = QLabel(text)
            f = lb.font()
            f.setPointSize(f.pointSize() + 4)
            f.setBold(True)
            lb.setFont(f)
            return lb

        def _subhead_label(self, text):
            lb = QLabel(text.upper())
            f = lb.font()
            f.setBold(True)
            lb.setFont(f)
            return lb

        def _srckey_label(self, text):
            lb = QLabel(text)
            lb.setFont(_mono(9))
            lb.setWordWrap(True)
            lb.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            pal = lb.palette()
            pal.setColor(QPalette.ColorRole.WindowText, self._muted)
            lb.setPalette(pal)
            return lb

        def _note_label(self, text):
            lb = QLabel(text)
            lb.setWordWrap(True)
            f = lb.font()
            f.setItalic(True)
            lb.setFont(f)
            pal = lb.palette()
            pal.setColor(QPalette.ColorRole.WindowText, self._muted)
            lb.setPalette(pal)
            return lb

        # widget builders
        def _kv_table(self, pairs):
            pairs = [(k, v) for (k, v) in pairs if v not in ("", None)]
            t = CopyTable(len(pairs), 2)
            t.horizontalHeader().setVisible(False)
            t.verticalHeader().setVisible(False)
            t.setShowGrid(False)
            t.setWordWrap(False)
            t.setFont(_mono(9))
            t.setSelectionBehavior(
                QAbstractItemView.SelectionBehavior.SelectItems)
            t.setSelectionMode(
                QAbstractItemView.SelectionMode.ExtendedSelection)
            t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            t.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
            for i, (k, v) in enumerate(pairs):
                ki = QTableWidgetItem(str(k))
                ki.setForeground(self._muted)
                ki.setToolTip(str(k))
                vi = QTableWidgetItem(str(v))
                vi.setToolTip(str(v))
                t.setItem(i, 0, ki)
                t.setItem(i, 1, vi)
            hdr = t.horizontalHeader()
            hdr.setSectionResizeMode(
                0, QHeaderView.ResizeMode.ResizeToContents)
            hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            t.setTextElideMode(Qt.TextElideMode.ElideRight)
            t.resizeRowsToContents()
            _fit_table(t, has_header=False, allow_hbar=False)
            t.setSizePolicy(QSizePolicy.Policy.Expanding,
                            QSizePolicy.Policy.Fixed)
            return t

        def _data_table(self, headers, rows):
            t = CopyTable(len(rows), len(headers))
            t.setHorizontalHeaderLabels([str(h) for h in headers])
            t.verticalHeader().setVisible(False)
            t.setFont(_mono(9))
            t.setAlternatingRowColors(True)
            t.setWordWrap(False)
            t.setTextElideMode(Qt.TextElideMode.ElideRight)
            t.setSelectionBehavior(
                QAbstractItemView.SelectionBehavior.SelectRows)
            t.setSelectionMode(
                QAbstractItemView.SelectionMode.ExtendedSelection)
            t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            t.setSortingEnabled(False)
            for r, row in enumerate(rows):
                for c in range(len(headers)):
                    val = str(row[c]) if c < len(row) else ""
                    it = QTableWidgetItem(val)
                    it.setToolTip(val)
                    t.setItem(r, c, it)
            hdr = t.horizontalHeader()
            hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            t.resizeColumnsToContents()
            for c in range(t.columnCount()):
                t.setColumnWidth(c, min(max(t.columnWidth(c), 64), 360))
            hdr.setStretchLastSection(True)
            t.setSortingEnabled(True)
            t.sortByColumn(0, Qt.SortOrder.AscendingOrder)
            t.resizeRowsToContents()
            _fit_table(t, has_header=True, allow_hbar=True)
            t.setSizePolicy(QSizePolicy.Policy.Expanding,
                            QSizePolicy.Policy.Fixed)
            return t

        def _list_widget(self, items):
            lw = QListWidget()
            lw.setFont(_mono(9))
            for it in items:
                lw.addItem(str(it))
            _fit_list(lw)
            lw.setSizePolicy(QSizePolicy.Policy.Expanding,
                             QSizePolicy.Policy.Fixed)
            return lw

        def _build_page(self, sec):
            page = QWidget()
            v = QVBoxLayout(page)
            v.setContentsMargins(10, 6, 12, 14)
            v.setSpacing(7)
            v.addWidget(self._title_label(sec.title))

            groups = []
            pending = []   # header widgets awaiting a body

            def flush_body(widget, bf):
                groups.append(_Group(pending[:], widget, bf))
                pending.clear()

            for el in sec.elements:
                kind = el[0]
                if kind == "sub":
                    lb = self._subhead_label(str(el[1]))
                    v.addWidget(lb)
                    pending.append(lb)
                elif kind == "path":
                    lb = self._srckey_label(str(el[1]))
                    v.addWidget(lb)
                    pending.append(lb)
                elif kind == "paths":
                    for p in el[1]:
                        lb = self._srckey_label(str(p))
                        v.addWidget(lb)
                        pending.append(lb)
                elif kind == "kv":
                    w = self._kv_table(el[1])
                    v.addWidget(w)
                    flush_body(w, _TableFilter(w, False, False))
                elif kind == "table":
                    w = self._data_table(el[1], el[2])
                    v.addWidget(w)
                    flush_body(w, _TableFilter(w, True, True))
                elif kind == "list":
                    w = self._list_widget(el[1])
                    v.addWidget(w)
                    flush_body(w, _ListFilter(w))
                elif kind == "text":
                    lb = QLabel(str(el[1]))
                    lb.setWordWrap(True)
                    v.addWidget(lb)
                    flush_body(lb, _TextFilter(str(el[1])))
                elif kind == "note":
                    lb = self._note_label(str(el[1]))
                    v.addWidget(lb)
                    flush_body(lb, _TextFilter(str(el[1])))
            if pending:
                groups.append(_Group(pending[:], None, None))
                pending.clear()

            v.addStretch(1)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(page)
            return scroll, groups

        # populate
        def _clear_stack(self):
            self.sidebar.clear()
            while self.stack.count():
                w = self.stack.widget(0)
                self.stack.removeWidget(w)
                w.deleteLater()
            self._groups = []
            self._titles = []

        def _show_placeholder(self):
            self._clear_stack()
            page = QWidget()
            lay = QVBoxLayout(page)
            lay.addStretch(1)
            t = QLabel("Open SYSTEM / SOFTWARE / SAM hives, or use "
                       "File \u2192 Import from folder\u2026 to begin.")
            t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(t)
            lay.addStretch(1)
            self.stack.addWidget(page)

        def _populate(self):
            self._clear_stack()
            for sec in self.sections:
                page, groups = self._build_page(sec)
                self.stack.addWidget(page)
                self._groups.append(groups)
                self._titles.append(sec.title)
                self.sidebar.addItem(QListWidgetItem(sec.title))
            if self.sidebar.count():
                self.sidebar.setCurrentRow(0)
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            self.count.setText("")

        # actions
        def _has_any(self):
            if any(self.paths.get(k) for k in
                   ("system_path", "software_path", "sam_path",
                    "security_path")):
                return True
            return bool(self.paths.get("ntusers") or self.paths.get("usrclass"))

        def _pathinfo(self):
            bits = []
            for lbl, key in (("SYSTEM", "system_path"),
                             ("SOFTWARE", "software_path"),
                             ("SAM", "sam_path"),
                             ("SECURITY", "security_path")):
                bits.append("%s %s" % (lbl,
                            "\u2713" if self.paths[key] else "\u2717"))
            bits.append("NTUSER %d" % len(self.paths["ntusers"]))
            if self.paths.get("usrclass"):
                bits.append("UsrClass %d" % len(self.paths["usrclass"]))
            return "   ".join(bits)

        def open_one(self, key):
            fn, _ = QFileDialog.getOpenFileName(
                self, "Select %s hive" % key.split("_")[0].upper())
            if not fn:
                return
            if not is_hive_file(fn):
                if QMessageBox.question(
                        self, "Not a REGF file",
                        "This file does not start with 'regf'.\nLoad anyway?"
                        ) != QMessageBox.StandardButton.Yes:
                    return
            self.paths[key] = fn
            self.parse()

        def add_ntuser(self):
            fn, _ = QFileDialog.getOpenFileName(self, "Select NTUSER.DAT")
            if not fn:
                return
            uname = os.path.basename(os.path.dirname(fn)) or "user"
            self.paths["ntusers"].append({"name": uname, "path": fn})
            self.parse()

        def add_usrclass(self):
            fn, _ = QFileDialog.getOpenFileName(self, "Select UsrClass.dat")
            if not fn:
                return
            self.paths.setdefault("usrclass", []).append(
                {"name": _user_from_path(fn), "path": fn})
            self.parse()

        def import_folder(self):
            d = QFileDialog.getExistingDirectory(
                self, "Select folder")
            if not d:
                return
            self.statusBar().showMessage("Scanning %s\u2026" % d)
            QApplication.processEvents()
            found = discover_hives_in_folder(d)
            for k in ("system_path", "software_path", "sam_path",
                      "security_path"):
                if found.get(k):
                    self.paths[k] = found[k]
            have = {u["path"] for u in self.paths["ntusers"]}
            for u in found["ntusers"]:
                if u["path"] not in have:
                    self.paths["ntusers"].append(u)
            self.paths.setdefault("usrclass", [])
            have_uc = {u["path"] for u in self.paths["usrclass"]}
            for u in found.get("usrclass", []):
                if u["path"] not in have_uc:
                    self.paths["usrclass"].append(u)
            if not self._has_any():
                QMessageBox.warning(
                    self, "Nothing found",
                    "No registry hives were found under:\n%s" % d)
                self.statusBar().showMessage("No hives found.")
                return
            self.parse()

        def parse(self):
            if not self._has_any():
                self.statusBar().showMessage("Load at least one hive first.")
                return
            self.statusBar().showMessage("Parsing\u2026")
            QApplication.processEvents()
            try:
                hives = open_hives_from_paths(self.paths)
                self.hives = hives
                self.summary, self.sections = build_report(hives)
            except Exception as e:
                QMessageBox.critical(self, "Parse error", str(e))
                self.statusBar().showMessage("Parse failed: %s" % e)
                return
            self._populate()
            self.statusBar().showMessage(
                "%s   |   %d sections parsed."
                % (self._pathinfo(), len(self.sections)))

        def clear(self):
            self.paths = {"system_path": None, "software_path": None,
                          "sam_path": None, "security_path": None,
                          "ntusers": [], "usrclass": []}
            self.summary = None
            self.sections = []
            self.hives = None
            self._show_placeholder()
            self.search.clear()
            self.count.setText("")
            self.statusBar().showMessage("Cleared.")

        def export_html(self):
            if not self.sections:
                self.statusBar().showMessage("Nothing to export - parse first.")
                return
            default = "HiveScope_%s.html" % (
                self.summary["name"] if self.summary else "report")
            fn, _ = QFileDialog.getSaveFileName(
                self, "Export HTML report", default, "HTML (*.html)")
            if not fn:
                return
            with open(fn, "w", encoding="utf-8") as f:
                f.write(render_html(self.summary, self.sections))
            self.statusBar().showMessage("HTML written: %s" % fn)
            QMessageBox.information(self, "Exported",
                                    "HTML report saved to:\n%s" % fn)

        def export_text(self):
            if not self.sections:
                self.statusBar().showMessage("Nothing to export - parse first.")
                return
            fn, _ = QFileDialog.getSaveFileName(
                self, "Export text report",
                "HiveScope.txt", "Text (*.txt)")
            if not fn:
                return
            with open(fn, "w", encoding="utf-8") as f:
                f.write(render_text(self.summary, self.sections))
            self.statusBar().showMessage("Text written: %s" % fn)

        def export_json(self):
            if not self.sections:
                self.statusBar().showMessage("Nothing to export - parse first.")
                return
            fn, _ = QFileDialog.getSaveFileName(
                self, "Export JSON report",
                "HiveScope.json", "JSON (*.json)")
            if not fn:
                return
            with open(fn, "w", encoding="utf-8") as f:
                f.write(render_json(self.summary, self.sections))
            self.statusBar().showMessage("JSON written: %s" % fn)

        def export_timeline(self):
            if not self.hives:
                self.statusBar().showMessage("Nothing to export - parse first.")
                return
            fn, _ = QFileDialog.getSaveFileName(
                self, "Export timeline", "HiveScope-timeline.csv",
                "CSV (*.csv);;JSON (*.json)")
            if not fn:
                return
            self.statusBar().showMessage("Building timeline\u2026")
            QApplication.processEvents()
            events = build_timeline(self.hives)
            floor = timeline_since(self.hives)
            out = (render_timeline_json(events) if fn.lower().endswith(".json")
                   else render_timeline_csv(events))
            with open(fn, "w", encoding="utf-8", newline="") as f:
                f.write(out)
            self.statusBar().showMessage(
                "Timeline written: %s (%d events%s)" % (
                    fn, len(events),
                    " since " + floor.strftime("%Y-%m-%d") if floor else ""))

        def about(self):
            QMessageBox.about(self, f"About {TOOL_NAME}", f"""
<h3>{TOOL_NAME} {VERSION}</h3>
<p>Windows registry forensic report tool.<br><a href="https://github.com/cristianzsh/hivescope">https://github.com/cristianzsh/hivescope</a></p>
<p>By Cristian Souza<br>
<a href="https://cristian.sh">https://cristian.sh</a><br>cristianmsbr@gmail.com</p>""")

        # navigation + search
        def _on_section(self, row):
            if 0 <= row < self.stack.count():
                self.stack.setCurrentIndex(row)

        def _on_search(self, text):
            q = text.strip().lower()
            total = 0
            for i in range(self.stack.count()):
                if i >= len(self._groups):
                    break
                sm = 0
                for g in self._groups[i]:
                    sm += g.filter(q)
                item = self.sidebar.item(i)
                if item is None:
                    continue
                base = self._titles[i]
                if q:
                    item.setHidden(sm == 0)
                    item.setText("%s   (%d)" % (base, sm))
                else:
                    item.setHidden(False)
                    item.setText(base)
                total += sm
            self.count.setText(("%d match%s" %
                               (total, "" if total == 1 else "es")) if q else "")
            if q:
                cur = self.sidebar.currentRow()
                if cur < 0 or (self.sidebar.item(cur)
                               and self.sidebar.item(cur).isHidden()):
                    for i in range(self.sidebar.count()):
                        if not self.sidebar.item(i).isHidden():
                            self.sidebar.setCurrentRow(i)
                            break

    app = QApplication.instance() or QApplication(sys.argv)
    _app_ic = QIcon(_asset("icon.png"))
    if not _app_ic.isNull():
        app.setWindowIcon(_app_ic)
    win = Window(initial_paths)
    if _test:
        return app, win
    win.show()
    app.exec()
