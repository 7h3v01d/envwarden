# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""EnvWarden main window. All slow work goes through TaskRunner; nothing blocks the GUI thread."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QAction, QCloseEvent, QColor, QKeySequence
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
                             QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
                             QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                             QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .. import APP_NAME, __version__, pypi
from ..backend import discover_pythons
from ..core import EnvInfo, EnvManager, OpResult
from ..versions import version_key
from . import theme
from .dialogs import confirm
from .workers import TaskRunner


# ---------------------------------------------------------------------- small widget helpers
def _label(text: str, obj: str = "Section") -> QLabel:
    lab = QLabel(text)
    lab.setObjectName(obj)
    return lab


def _button(text: str, slot: Callable[[], None], obj: str = "", tip: str = "") -> QPushButton:
    btn = QPushButton(text)
    if obj:
        btn.setObjectName(obj)
    if tip:
        btn.setToolTip(tip)
    btn.clicked.connect(slot)
    return btn


def _console(height: int | None = None) -> QPlainTextEdit:
    view = QPlainTextEdit()
    view.setObjectName("Console")
    view.setReadOnly(True)
    view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    if height:
        view.setFixedHeight(height)
    return view


def _table(headers: list[str], stretch: int = -1) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.setSortingEnabled(True)
    t.sortByColumn(0, Qt.SortOrder.AscendingOrder)
    hdr = t.horizontalHeader()
    for i in range(len(headers)):
        hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
    hdr.setSectionResizeMode(stretch if stretch >= 0 else len(headers) - 1, QHeaderView.ResizeMode.Stretch)
    return t


def _fill(table: QTableWidget, rows: list[list[Any]], colours: dict[tuple[int, int], str] | None = None) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            item = QTableWidgetItem("" if value is None else str(value))
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                item.setData(Qt.ItemDataRole.EditRole, value)
            if colours and (r, c) in colours:
                item.setForeground(QColor(colours[(r, c)]))
            table.setItem(r, c, item)
    table.setSortingEnabled(True)


def _browse_dir(parent: QWidget, target: QLineEdit, title: str = "Select folder") -> None:
    path = QFileDialog.getExistingDirectory(parent, title, target.text() or str(Path.home()))
    if path:
        target.setText(path)


def _row(*widgets: QWidget, stretch_last: bool = False) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(6)
    for w in widgets:
        lay.addWidget(w)
    if not stretch_last:
        lay.addStretch(1)
    return lay


class MainWindow(QMainWindow):
    def __init__(self, manager: EnvManager | None = None) -> None:
        super().__init__()
        self.mgr = manager or EnvManager()
        self.runner = TaskRunner(self)
        self.runner.busy_changed.connect(self._on_busy)
        self.envs: dict[str, EnvInfo] = {}
        self._refreshing = False
        self._refresh_pending = False
        self.drifts: dict[str, Any] = {}
        self._scan_report: Any = None
        self._audit_report: Any = None
        self._pypi_info: pypi.PackageInfo | None = None
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.resize(1480, 940)
        self.setMinimumSize(1100, 720)
        self.setStyleSheet(theme.STYLE)
        self._build()
        QTimer.singleShot(0, self.refresh)
        QTimer.singleShot(50, self._discover_pythons)
        self._pythons: list[Any] = []
        QTimer.singleShot(120, self._startup_maintenance)

    # ================================================================== layout
    def _build(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(12, 10, 12, 8)
        body_lay.setSpacing(8)
        body_lay.addLayout(self._build_metrics())

        self.tabs = QTabWidget()
        for title, builder in (
            ("OVERVIEW", self._tab_overview), ("PROJECTS", self._tab_projects), ("LIFECYCLE", self._tab_lifecycle), ("PACKAGES", self._tab_packages),
            ("SCAN", self._tab_scan), ("SECURITY", self._tab_security), ("PYPI", self._tab_pypi),
            ("SNAPSHOTS", self._tab_snapshots), ("TEMPLATES", self._tab_templates),
            ("COMPARE", self._tab_compare), ("AUDIT", self._tab_audit),
        ):
            widget = builder()
            assert widget is not None, f"tab builder for {title} returned None"
            self.tabs.addTab(widget, title)

        self.console = _console()
        self.console.setMaximumBlockCount(4000)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.tabs)
        split.addWidget(self.console)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 1)
        split.setSizes([700, 150])
        body_lay.addWidget(split, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        body_lay.addWidget(self.progress)
        root.addWidget(body, 1)

        sb = self.statusBar()
        self.busy_label = QLabel("Ready")
        sb.addWidget(self.busy_label, 1)
        sb.addPermanentWidget(QLabel(f"BACKEND {self.mgr.backend.label}"))
        sb.addPermanentWidget(QLabel(f"HOME {self.mgr.paths.home}"))

        refresh = QAction("Refresh", self)
        refresh.setShortcut(QKeySequence.StandardKey.Refresh)
        refresh.triggered.connect(self.refresh)
        self.addAction(refresh)

    def _build_header(self) -> QFrame:
        hdr = QFrame()
        hdr.setObjectName("Header")
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(16, 10, 16, 10)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(_label("ENVWARDEN", "Title"))
        titles.addWidget(_label(f"GOVERNED VIRTUAL-ENVIRONMENT CONSOLE · v{__version__}", "Edition"))
        lay.addLayout(titles)
        lay.addStretch(1)
        lay.addWidget(_label("ACTIVE ENV"))
        self.env_combo = QComboBox()
        self.env_combo.setMinimumWidth(240)
        self.env_combo.currentTextChanged.connect(self._on_active_changed)
        lay.addWidget(self.env_combo)
        lay.addWidget(_button("REFRESH", self.refresh, "Primary", "Re-inspect all environments (F5)"))
        lay.addWidget(_button("OPEN SHELL", self.open_shell, tip="Open a terminal with the environment activated"))
        lay.addWidget(_button("COPY ACTIVATE", self.copy_activate, tip="Copy the activation command"))
        lay.addWidget(_button("APP FOLDER", self.open_home))
        return hdr

    def _build_metrics(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)
        self.metric: dict[str, QLabel] = {}
        for key, title in (("envs", "ENVIRONMENTS"), ("ok", "HEALTHY"), ("warn", "NEEDS ATTENTION"), ("novenv", "PROJECTS W/O VENV"),
                           ("pkgs", "PACKAGES"), ("size", "DISK (MB)")):
            card = QFrame()
            card.setObjectName("Card")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 8, 12, 8)
            cl.setSpacing(2)
            cl.addWidget(_label(title))
            val = _label("—", "Metric")
            cl.addWidget(val)
            self.metric[key] = val
            row.addWidget(card)
        return row

    # ------------------------------------------------------------------ OVERVIEW
    def _tab_overview(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.env_filter = QLineEdit()
        self.env_filter.setPlaceholderText("Filter by name, project, Python, path…")
        self.env_filter.textChanged.connect(self._apply_env_filter)
        lay.addLayout(_row(_label("ENVIRONMENT INVENTORY"), self.env_filter, stretch_last=True))
        self.env_table = _table(["NAME", "HEALTH", "PYTHON", "PKGS", "SIZE MB", "KIND", "PROJECT", "PATH"], stretch=7)
        self.env_table.itemSelectionChanged.connect(self._on_table_selection)
        lay.addWidget(self.env_table, 3)
        lower = QHBoxLayout()
        g1 = QGroupBox("SELECTED ENVIRONMENT")
        QVBoxLayout(g1).addWidget(detail := _console())
        self.detail_view = detail
        g2 = QGroupBox("HISTORY")
        QVBoxLayout(g2).addWidget(hist := _console())
        self.history_view = hist
        lower.addWidget(g1, 1)
        lower.addWidget(g2, 1)
        lay.addLayout(lower, 2)
        return w

    # ------------------------------------------------------------------ PROJECTS
    def _tab_projects(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        g = QGroupBox("WORKSPACE FOLDERS")
        gl = QVBoxLayout(g)
        self.ws_table = _table(["FOLDER"], stretch=0)
        self.ws_table.setMaximumHeight(110)
        gl.addWidget(self.ws_table)
        gl.addLayout(_row(_button("ADD FOLDER…", self.add_workspace, "Primary"),
                          _button("REMOVE", self.remove_workspace, "Danger"),
                          _button("RESCAN", lambda: self.discover_workspaces(), "Safe",
                                  "Find project venvs (.venv, venv, env…) and projects without one")))
        top.addWidget(g, 2)
        g = QGroupBox("SELECTED PROJECT")
        gl = QGridLayout(g)
        self.proj_python = QComboBox()
        self.proj_python.setEditable(True)
        self.proj_python.setMinimumWidth(220)
        self.proj_python.lineEdit().setPlaceholderText("default · 3.12 · path")
        self.proj_venv_name = QLineEdit(".venv")
        self.proj_sync = QCheckBox("Install project deps after creating")
        self.proj_sync.setChecked(True)
        gl.addWidget(QLabel("Python"), 0, 0)
        gl.addWidget(self.proj_python, 0, 1)
        gl.addWidget(QLabel("Folder"), 0, 2)
        gl.addWidget(self.proj_venv_name, 0, 3)
        gl.addWidget(self.proj_sync, 1, 0, 1, 4)
        gl.addWidget(_button("CREATE VENV IN PROJECT", self.create_project_venv, "Primary",
                             "Refused if the project already has a venv"), 2, 0, 1, 2)
        gl.addWidget(_button("USE AS ACTIVE", self.use_project_env), 2, 2)
        gl.addWidget(_button("SYNC DEPS", lambda: self.sync_project(self._selected_project_env()), "Safe"), 2, 3)
        gl.addWidget(_button("SCAN IMPORTS", self.scan_selected_project), 3, 0, 1, 2)
        gl.addWidget(_button("OPEN FOLDER", self.open_project_folder), 3, 2, 1, 2)
        top.addWidget(g, 3)
        lay.addLayout(top)
        self.proj_filter = QLineEdit()
        self.proj_filter.setPlaceholderText("Filter projects…")
        self.proj_filter.textChanged.connect(self._apply_proj_filter)
        self.proj_only_missing = QCheckBox("Only projects without a venv")
        self.proj_only_missing.toggled.connect(lambda _c: self._apply_proj_filter(self.proj_filter.text()))
        self.proj_summary = _label("No workspace scanned yet — add a folder such as C:\\dev.", "Muted")
        lay.addLayout(_row(_label("PROJECTS"), self.proj_filter, self.proj_only_missing, stretch_last=True))
        lay.addWidget(self.proj_summary)
        self.proj_table = _table(["PROJECT", "VENV", "ENV", "PYTHON", "HEALTH", "DRIFT", "SOURCE", "PATH"], stretch=7)
        self.proj_table.itemDoubleClicked.connect(lambda _i: self.use_project_env())
        self.proj_table.itemSelectionChanged.connect(self._show_project_drift)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.proj_table)
        side = QGroupBox("DEPENDENCY DRIFT")
        sl = QVBoxLayout(side)
        self.drift_view = _console()
        self.drift_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.drift_view.setPlainText("Select a project with a venv to compare its lock / requirements "
                                     "against what is installed.")
        sl.addWidget(self.drift_view)
        split.addWidget(side)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        return w

    # ------------------------------------------------------------------ LIFECYCLE
    def _tab_lifecycle(self) -> QWidget:
        w = QWidget()
        outer = QHBoxLayout(w)
        left = QVBoxLayout()
        right = QVBoxLayout()
        outer.addLayout(left, 1)
        outer.addLayout(right, 1)

        g = QGroupBox("CREATE ENVIRONMENT")
        gl = QGridLayout(g)
        self.create_name = QLineEdit()
        self.create_name.setPlaceholderText("e.g. vibe-dev")
        self.create_python = QComboBox()
        self.create_python.setEditable(True)
        self.create_python.addItem("")
        self.create_python.lineEdit().setPlaceholderText("default · or 3.12 · or path to python.exe")
        self.create_template = QComboBox()
        self.create_project = QLineEdit()
        self.create_project.setPlaceholderText("Project / purpose label")
        self.create_reqs = QLineEdit()
        self.create_reqs.setPlaceholderText("Optional requirements.txt to install")
        browse_req = _button("…", lambda: self._browse_file(self.create_reqs))
        rows = [("Name", self.create_name), ("Python", self.create_python), ("Template", self.create_template),
                ("Project", self.create_project)]
        for i, (lab, wid) in enumerate(rows):
            gl.addWidget(QLabel(lab), i, 0)
            gl.addWidget(wid, i, 1, 1, 2)
        gl.addWidget(QLabel("Requirements"), 4, 0)
        gl.addWidget(self.create_reqs, 4, 1)
        gl.addWidget(browse_req, 4, 2)
        note = _label("With uv, a missing Python version is downloaded automatically.", "Muted")
        gl.addWidget(note, 5, 0, 1, 3)
        gl.addWidget(_button("CREATE", self.create_env, "Primary"), 6, 0, 1, 3)
        left.addWidget(g)

        g = QGroupBox("ADOPT EXISTING VENV")
        gl = QGridLayout(g)
        self.adopt_path = QLineEdit()
        self.adopt_path.setPlaceholderText("Folder containing pyvenv.cfg (e.g. C:\\dev\\proj\\.venv)")
        self.adopt_name = QLineEdit()
        self.adopt_project = QLineEdit()
        gl.addWidget(QLabel("Path"), 0, 0)
        gl.addWidget(self.adopt_path, 0, 1)
        gl.addWidget(_button("…", lambda: _browse_dir(self, self.adopt_path)), 0, 2)
        gl.addWidget(QLabel("Name"), 1, 0)
        gl.addWidget(self.adopt_name, 1, 1, 1, 2)
        gl.addWidget(QLabel("Project"), 2, 0)
        gl.addWidget(self.adopt_project, 2, 1, 1, 2)
        gl.addWidget(_label("Registered in place — files are never moved or copied.", "Muted"), 3, 0, 1, 3)
        gl.addWidget(_button("ADOPT", self.adopt_env, "Primary"), 4, 0, 1, 3)
        left.addWidget(g)

        g = QGroupBox("TEMPORARY ENVIRONMENTS")
        gl = QGridLayout(g)
        self.temp_project = QLineEdit()
        self.temp_project.setPlaceholderText("Optional project folder to scan & install")
        gl.addWidget(self.temp_project, 0, 0)
        gl.addWidget(_button("…", lambda: _browse_dir(self, self.temp_project)), 0, 1)
        gl.addWidget(_button("CREATE TEMP", self.create_temp, "Safe"), 1, 0)
        gl.addWidget(_button("PURGE ALL", self.purge_temp, "Danger"), 1, 1)
        left.addWidget(g)
        left.addStretch(1)

        g = QGroupBox("ACTIVE ENVIRONMENT ACTIONS")
        gl = QGridLayout(g)
        self.clone_target = QLineEdit()
        self.clone_target.setPlaceholderText("New name")
        self.rename_target = QLineEdit()
        self.rename_target.setPlaceholderText("New name")
        self.project_label = QLineEdit()
        self.project_label.setPlaceholderText("Project label")
        self.project_dir = QLineEdit()
        self.project_dir.setPlaceholderText("Project folder (used as shell start dir & scan default)")
        gl.addWidget(QLabel("Clone to"), 0, 0)
        gl.addWidget(self.clone_target, 0, 1)
        gl.addWidget(_button("CLONE", self.clone_env, tip="Rebuilds a fresh env with identical pinned packages"), 0, 2)
        gl.addWidget(QLabel("Rename to"), 1, 0)
        gl.addWidget(self.rename_target, 1, 1)
        gl.addWidget(_button("RENAME", self.rename_env, tip="Managed envs are rebuilt under the new name"), 1, 2)
        gl.addWidget(QLabel("Project"), 2, 0)
        gl.addWidget(self.project_label, 2, 1)
        gl.addWidget(QLabel("Folder"), 3, 0)
        gl.addWidget(self.project_dir, 3, 1)
        gl.addWidget(_button("…", lambda: _browse_dir(self, self.project_dir)), 3, 2)
        gl.addWidget(_button("SAVE LABELS", self.save_labels), 4, 0, 1, 3)
        gl.addWidget(_button("SNAPSHOT", self.snapshot_env, "Safe"), 5, 0)
        gl.addWidget(_button("WIPE PACKAGES", self.wipe_env, "Danger", "Auto-snapshots first"), 5, 1)
        gl.addWidget(_button("DELETE…", self.delete_env, "Danger",
                             "Managed: delete. Project/external: unregister, or delete the venv folder"), 5, 2)
        gl.addWidget(_button("RECREATE IN PLACE", self.recreate_env, "Primary",
                             "Rebuild at the same path with the same Python and pins (fixes moved/broken venvs)"), 6, 0, 1, 2)
        gl.addWidget(_button("SYNC PROJECT DEPS", self.sync_project, "Safe",
                             "requirements.txt, else editable install of pyproject/setup.py"), 6, 2)
        right.addWidget(g)
        note = QLabel(
            "Why clone/rename rebuild instead of copy: a virtualenv hard-codes its own absolute path in its "
            "launchers and activate scripts. A copied venv keeps driving the original — installs into the "
            "'copy' land in the source. EnvWarden recreates the environment and reinstalls the exact pins.")
        note.setWordWrap(True)
        note.setObjectName("Muted")
        right.addWidget(note)
        right.addStretch(1)
        return w

    # ------------------------------------------------------------------ PACKAGES
    def _tab_packages(self) -> QWidget:
        w = QWidget()
        outer = QHBoxLayout(w)
        left = QVBoxLayout()
        right = QVBoxLayout()
        outer.addLayout(left, 1)
        outer.addLayout(right, 1)

        self.pkg_filter = QLineEdit()
        self.pkg_filter.setPlaceholderText("Filter installed packages…")
        self.pkg_filter.textChanged.connect(self._apply_pkg_filter)
        left.addLayout(_row(_label("INSTALLED"), self.pkg_filter, stretch_last=True))
        self.pkg_table = _table(["PACKAGE", "VERSION"], stretch=0)
        left.addWidget(self.pkg_table, 1)
        left.addLayout(_row(_button("UNINSTALL SELECTED", self.uninstall_selected, "Danger"),
                            _button("EXPORT REQUIREMENTS", self.export_requirements)))

        g = QGroupBox("INSTALL")
        gl = QGridLayout(g)
        self.install_spec = QLineEdit()
        self.install_spec.setPlaceholderText("requests  httpx>=0.27  'rich[jupyter]'")
        self.install_spec.returnPressed.connect(self.install_specs)
        gl.addWidget(self.install_spec, 0, 0, 1, 2)
        gl.addWidget(_button("INSTALL", self.install_specs, "Primary"), 0, 2)
        self.req_file = QLineEdit()
        self.req_file.setPlaceholderText("requirements.txt")
        gl.addWidget(self.req_file, 1, 0)
        gl.addWidget(_button("…", lambda: self._browse_file(self.req_file)), 1, 1)
        gl.addWidget(_button("INSTALL FILE", self.install_req_file), 1, 2)
        gl.addWidget(_label("Pip options (-i, -e, URLs, paths) are refused in the package box.", "Muted"), 2, 0, 1, 3)
        right.addWidget(g)

        g = QGroupBox("OUTDATED")
        gl = QVBoxLayout(g)
        gl.addLayout(_row(_button("CHECK OUTDATED", self.check_outdated, "Primary"),
                          _button("UPGRADE SELECTED", self.upgrade_selected, "Safe"),
                          _button("UPGRADE ALL", self.upgrade_all, "Danger", "Auto-snapshots first")))
        self.outdated_table = _table(["PACKAGE", "INSTALLED", "LATEST"], stretch=0)
        gl.addWidget(self.outdated_table)
        right.addWidget(g, 1)

        g = QGroupBox("DEPENDENCY CONSISTENCY")
        gl = QVBoxLayout(g)
        gl.addLayout(_row(_button("RUN DEPENDENCY CHECK", self.dep_check, "Primary"),
                          _label("Real resolver check (pip check / uv pip check)", "Muted")))
        self.check_view = _console(90)
        gl.addWidget(self.check_view)
        right.addWidget(g)
        return w

    # ------------------------------------------------------------------ SCAN
    def _tab_scan(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.scan_dir = QLineEdit()
        self.scan_dir.setPlaceholderText("Project folder to scan (imports resolved against the ACTIVE environment)")
        lay.addLayout(_row(self.scan_dir, _button("…", lambda: _browse_dir(self, self.scan_dir)),
                           _button("SCAN PROJECT", self.scan_project, "Primary"),
                           _button("INSTALL MISSING", self.install_missing, "Safe"), stretch_last=True))
        self.scan_summary = _label("No scan yet.", "Muted")
        lay.addWidget(self.scan_summary)
        split = QHBoxLayout()
        self.scan_table = _table(["DISTRIBUTION", "IMPORT", "INSTALLED", "USED IN"], stretch=3)
        split.addWidget(self.scan_table, 3)
        side = QGroupBox("DECLARATIONS (pyproject / requirements)")
        sl = QVBoxLayout(side)
        self.scan_decl = _console()
        sl.addWidget(self.scan_decl)
        split.addWidget(side, 2)
        lay.addLayout(split, 1)
        return w

    # ------------------------------------------------------------------ SECURITY
    def _tab_security(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addLayout(_row(_button("RUN VULNERABILITY AUDIT", self.run_audit, "Primary"),
                           _button("UPGRADE SELECTED TO FIX", self.upgrade_to_fix, "Safe"),
                           _label("Queries OSV.dev with exact installed versions — only names and versions are sent.",
                                  "Muted")))
        self.sec_summary = _label("Not run yet.", "Muted")
        lay.addWidget(self.sec_summary)
        self.sec_table = _table(["PACKAGE", "VERSION", "ADVISORY", "SEVERITY", "FIXED IN", "SUMMARY"], stretch=5)
        lay.addWidget(self.sec_table, 1)
        return w

    # ------------------------------------------------------------------ PYPI
    def _tab_pypi(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.pypi_query = QLineEdit()
        self.pypi_query.setPlaceholderText("Exact project name, e.g. httpx")
        self.pypi_query.returnPressed.connect(self.pypi_lookup)
        self.pypi_pre = QCheckBox("Include pre-releases")
        lay.addLayout(_row(self.pypi_query, self.pypi_pre, _button("LOOK UP", self.pypi_lookup, "Primary"),
                           stretch_last=True))
        self.pypi_view = _console()
        lay.addWidget(self.pypi_view, 1)
        self.pypi_versions = QComboBox()
        self.pypi_versions.setMinimumWidth(160)
        lay.addLayout(_row(QLabel("Version"), self.pypi_versions,
                           _button("INSTALL INTO ACTIVE ENV", self.pypi_install, "Safe")))
        return w

    # ------------------------------------------------------------------ SNAPSHOTS
    def _tab_snapshots(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.snap_scope = QCheckBox("Only active environment")
        self.snap_scope.toggled.connect(self.refresh_snapshots)
        lay.addLayout(_row(_label("SNAPSHOT STORE"), self.snap_scope, _button("REFRESH", self.refresh_snapshots)))
        split = QHBoxLayout()
        self.snap_table = _table(["SNAPSHOT", "ENV", "TAKEN", "REASON", "PKGS", "PYTHON"], stretch=0)
        self.snap_table.itemSelectionChanged.connect(self._preview_snapshot)
        split.addWidget(self.snap_table, 3)
        self.snap_preview = _console()
        split.addWidget(self.snap_preview, 2)
        lay.addLayout(split, 1)
        self.restore_name = QLineEdit()
        self.restore_name.setPlaceholderText("New environment name")
        lay.addLayout(_row(QLabel("Restore as"), self.restore_name,
                           _button("RESTORE → NEW ENV", self.restore_snapshot, "Primary"),
                           _button("DELETE SNAPSHOT", self.delete_snapshot, "Danger")))
        return w

    # ------------------------------------------------------------------ TEMPLATES
    def _tab_templates(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        left = QVBoxLayout()
        self.tmpl_table = _table(["TEMPLATE", "ENTRIES"], stretch=0)
        self.tmpl_table.itemSelectionChanged.connect(self._preview_template)
        left.addWidget(self.tmpl_table, 1)
        left.addWidget(_button("DELETE TEMPLATE", self.delete_template, "Danger"))
        lay.addLayout(left, 1)
        right = QVBoxLayout()
        g = QGroupBox("SAVE ACTIVE ENV AS TEMPLATE")
        gl = QGridLayout(g)
        self.tmpl_name = QLineEdit()
        self.tmpl_name.setPlaceholderText("e.g. fastapi-base")
        self.tmpl_unpinned = QCheckBox("Unpinned (names only — always resolve latest)")
        gl.addWidget(self.tmpl_name, 0, 0)
        gl.addWidget(_button("SAVE", self.save_template, "Primary"), 0, 1)
        gl.addWidget(self.tmpl_unpinned, 1, 0, 1, 2)
        right.addWidget(g)
        self.tmpl_preview = _console()
        right.addWidget(self.tmpl_preview, 1)
        lay.addLayout(right, 1)
        return w

    # ------------------------------------------------------------------ COMPARE
    def _tab_compare(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.cmp_a = QComboBox()
        self.cmp_b = QComboBox()
        for c in (self.cmp_a, self.cmp_b):
            c.setMinimumWidth(220)
        lay.addLayout(_row(QLabel("A"), self.cmp_a, QLabel("B"), self.cmp_b,
                           _button("COMPARE", self.compare, "Primary")))
        self.cmp_view = _console()
        lay.addWidget(self.cmp_view, 1)
        return w

    # ------------------------------------------------------------------ AUDIT
    def _tab_audit(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.chain_label = _label("Chain not verified yet.", "Muted")
        lay.addLayout(_row(_label("AUDIT LOG"), _button("REFRESH", self.refresh_audit),
                           _button("VERIFY CHAIN", self.verify_audit, "Primary"),
                           _button("EXPORT", self.export_audit), self.chain_label))
        self.audit_table = _table(["#", "TIME (UTC)", "EVENT", "STATUS", "DETAIL"], stretch=4)
        lay.addWidget(self.audit_table, 1)
        return w

    # ================================================================== task plumbing
    def log(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{stamp}] {text.rstrip()}")
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    @pyqtSlot(bool, str)
    def _on_busy(self, busy: bool, label: str) -> None:
        self.progress.setVisible(busy)
        self.busy_label.setText(f"⟳ {label}…" if busy and label else ("Working…" if busy else "Ready"))

    def _fail(self, message: str) -> None:
        self.log(f"ERROR  {message}")
        QMessageBox.critical(self, APP_NAME, message[:3000])

    def mutate(self, label: str, fn: Callable[..., OpResult], *args: Any,
               after: Callable[[OpResult], None] | None = None, **kwargs: Any) -> None:
        def done(res: OpResult) -> None:
            self.log(f"{'OK ' if res.ok else 'FAIL'}  {label}\n{res.message}")
            if not res.ok:
                QMessageBox.warning(self, APP_NAME, res.message[-3000:])
            if after:
                after(res)
            self.refresh()

        if not self.runner.submit(label, fn, *args, on_done=done, on_error=self._fail, mutating=True, **kwargs):
            QMessageBox.information(self, APP_NAME, "Another change is still running. Wait for it to finish.")
        else:
            self.log(f"…    {label}")

    def read(self, label: str, fn: Callable[..., Any], *args: Any, on_done: Callable[[Any], None]) -> None:
        self.runner.submit(label, fn, *args, on_done=on_done, on_error=self._fail)

    def active(self, warn: bool = True) -> str:
        name = self.env_combo.currentText().strip()
        if not name and warn:
            QMessageBox.information(self, APP_NAME, "Select or create an environment first.")
        return name

    # ================================================================== refresh / population
    def refresh(self) -> None:
        if self._refreshing:
            self._refresh_pending = True  # coalesce: run once more after the current pass
            return
        self._refreshing = True
        self._refresh_pending = False

        def done(envs: list[EnvInfo]) -> None:
            self._refreshing = False
            self._populate(envs)
            self.read("Checking project drift", self.mgr.drift_all, envs, on_done=self._on_drift)
            if self._refresh_pending:
                QTimer.singleShot(0, self.refresh)

        def failed(msg: str) -> None:
            self._refreshing = False
            self._fail(msg)

        self.runner.submit("Inspecting environments", self.mgr.inventory, on_done=done, on_error=failed)
        self.refresh_templates()
        self.refresh_snapshots()
        self.refresh_audit()

    def _populate(self, envs: list[EnvInfo]) -> None:
        self.envs = {e.name: e for e in envs}
        names = sorted(self.envs, key=str.lower)
        for combo in (self.env_combo, self.cmp_a, self.cmp_b):
            prev = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(names)
            if prev in names:
                combo.setCurrentText(prev)
            combo.blockSignals(False)
        if self.cmp_b.count() > 1 and self.cmp_b.currentText() == self.cmp_a.currentText():
            self.cmp_b.setCurrentIndex(1)

        rows, colours = [], {}
        for r, e in enumerate(sorted(envs, key=lambda x: x.name.lower())):
            rows.append([e.name, e.health.upper(), e.python_version, len(e.packages), e.size_mb,
                         e.kind, e.project, e.path])
            colours[(r, 1)] = theme.HEALTH_COLOURS.get(e.health, theme.TEXT)
        _fill(self.env_table, rows, colours)
        self._apply_env_filter(self.env_filter.text())

        self.metric["envs"].setText(str(len(envs)))
        self.metric["ok"].setText(str(sum(e.health == "ok" for e in envs)))
        self.metric["warn"].setText(str(sum(e.health != "ok" for e in envs)))
        self.metric["pkgs"].setText(str(sum(len(e.packages) for e in envs)))
        self.metric["size"].setText(f"{sum(e.size_mb for e in envs):,.0f}")
        self.refresh_projects()
        self._on_active_changed(self.env_combo.currentText())

    def _on_drift(self, drifts: dict[str, Any]) -> None:
        self.drifts = drifts
        self.refresh_projects()
        self._show_project_drift()

    def _discover_pythons(self) -> None:
        def done(found: list[Any]) -> None:
            current = self.create_python.currentText()
            self.create_python.clear()
            self.create_python.addItem("")
            self._pythons = list(found)
            self.proj_python.clear()
            self.proj_python.addItem("")
            for p in found:
                self.proj_python.addItem(f"{p.version}", p.path)
            for p in found:
                self.create_python.addItem(f"{p.version}", p.path)
                self.create_python.setItemData(self.create_python.count() - 1, f"{p.path}  ({p.source})",
                                               Qt.ItemDataRole.ToolTipRole)
            self.create_python.setCurrentText(current)
            self.log(f"Found {len(found)} Python interpreter(s): " + ", ".join(p.version for p in found[:8]))

        self.read("Discovering Python interpreters", discover_pythons, self.mgr.backend, on_done=done)

    @pyqtSlot(str)
    def _on_active_changed(self, name: str) -> None:
        info = self.envs.get(name)
        if not info:
            self.detail_view.setPlainText("No environment selected.")
            self.history_view.clear()
            _fill(self.pkg_table, [])
            return
        meta = info.meta
        details = [
            f"Name          {info.name}",
            f"Kind          {info.kind}" + ("" if info.managed else "  (lives in place — never moved)"),
            f"Path          {info.path}",
            f"Health        {info.health.upper()} — {info.health_detail}",
            f"Python        {info.python_version}",
            f"Base python   {info.base_executable or '—'}",
            f"Packages      {len(info.packages)}   pip present: {'yes' if info.has_pip else 'no'}",
            f"Size          {info.size_mb:,.1f} MB",
            f"Project       {info.project}",
            f"Folder        {meta.get('project_dir', '—')}",
            f"Template      {info.template}",
            f"Drift         {self.drifts[name].status if name in self.drifts else '— (not linked to a project)'}",
            f"Created       {meta.get('created', '—')}   via {meta.get('backend', '—')}",
            "",
            f"Activate      {self.mgr.activation_command(name)}",
        ]
        self.detail_view.setPlainText("\n".join(details))
        hist = meta.get("history", [])
        self.history_view.setPlainText("\n".join(
            f"{h.get('ts', '')}  {h.get('action', ''):<20} "
            + " ".join(f"{k}={v}" for k, v in h.items() if k not in ('ts', 'action'))
            for h in reversed(hist)) or "No history yet.")
        _fill(self.pkg_table, [[n, v] for n, v in sorted(info.packages.items(), key=lambda kv: kv[0].lower())])
        self._apply_pkg_filter(self.pkg_filter.text())
        self.project_label.setText(meta.get("project", ""))
        self.project_dir.setText(meta.get("project_dir", ""))
        if meta.get("project_dir") and not self.scan_dir.text():
            self.scan_dir.setText(meta["project_dir"])
        self._select_row(name)
        if self.snap_scope.isChecked():
            self.refresh_snapshots()

    def _select_row(self, name: str) -> None:
        for r in range(self.env_table.rowCount()):
            item = self.env_table.item(r, 0)
            if item and item.text() == name and self.env_table.currentRow() != r:
                self.env_table.blockSignals(True)
                self.env_table.selectRow(r)
                self.env_table.blockSignals(False)
                break

    def _on_table_selection(self) -> None:
        row = self.env_table.currentRow()
        item = self.env_table.item(row, 0) if row >= 0 else None
        if item and item.text() != self.env_combo.currentText():
            self.env_combo.setCurrentText(item.text())

    def _apply_env_filter(self, text: str) -> None:
        needle = text.lower().strip()
        for r in range(self.env_table.rowCount()):
            hay = " ".join((self.env_table.item(r, c).text() if self.env_table.item(r, c) else "")
                           for c in range(self.env_table.columnCount())).lower()
            self.env_table.setRowHidden(r, bool(needle) and needle not in hay)

    def _apply_pkg_filter(self, text: str) -> None:
        needle = text.lower().strip()
        for r in range(self.pkg_table.rowCount()):
            item = self.pkg_table.item(r, 0)
            self.pkg_table.setRowHidden(r, bool(needle) and (item is None or needle not in item.text().lower()))

    # ================================================================== lifecycle actions
    def create_env(self) -> None:
        name = self.create_name.text().strip()
        idx = self.create_python.currentIndex()
        typed = self.create_python.currentText().strip()
        python = (self.create_python.itemData(idx) if idx > 0 and self.create_python.itemText(idx) == typed else typed) or ""
        template = self.create_template.currentText() if self.create_template.currentIndex() > 0 else ""
        reqs_file = self.create_reqs.text().strip()
        lines: list[str] = []
        if reqs_file:
            try:
                lines = [ln.strip() for ln in Path(reqs_file).read_text(encoding="utf-8").splitlines()
                         if ln.strip() and not ln.lstrip().startswith("#")]
            except OSError as exc:
                self._fail(f"Cannot read requirements: {exc}")
                return
        summary = (f"Create '{name}'\n\nPython: {python or 'default'}\nTemplate: {template or 'none'}\n"
                   f"Extra requirements: {len(lines)}\nBackend: {self.mgr.backend.label}")
        if not name or not confirm(self, "Create environment", summary):
            if not name:
                QMessageBox.information(self, APP_NAME, "Enter a name for the new environment.")
            return
        self.mutate(f"Create {name}", self.mgr.create, name, python, template, self.create_project.text().strip(),
                    lines, after=lambda r: r.ok and self._select_after(name))

    def _select_after(self, name: str) -> None:
        QTimer.singleShot(600, lambda: self.env_combo.setCurrentText(name))

    def adopt_env(self) -> None:
        path, name = self.adopt_path.text().strip(), self.adopt_name.text().strip()
        if not name and path:
            p = Path(path)
            name = (p.parent.name if p.name.startswith(".") or p.name in ("venv", "env") else p.name)
            self.adopt_name.setText(name)
        if not path or not name:
            QMessageBox.information(self, APP_NAME, "Pick a venv folder and a name.")
            return
        self.mutate(f"Adopt {name}", self.mgr.adopt, path, name, self.adopt_project.text().strip())

    def clone_env(self) -> None:
        src, dst = self.active(), self.clone_target.text().strip()
        if not src or not dst:
            return
        if confirm(self, "Clone", f"Rebuild '{src}' as a new environment '{dst}' with identical pinned packages?"):
            self.mutate(f"Clone {src} → {dst}", self.mgr.clone, src, dst, after=lambda r: self.clone_target.clear())

    def rename_env(self) -> None:
        old, new = self.active(), self.rename_target.text().strip()
        if not old or not new:
            return
        info = self.envs.get(old)
        how = ("It will be rebuilt as '%s' and the old directory deleted once the rebuild succeeds." % new
               if info and info.managed else "Only the label changes; the adopted files stay put.")
        if confirm(self, "Rename", f"Rename '{old}' → '{new}'.\n\n{how}", phrase=old if info and info.managed else ""):
            self.mutate(f"Rename {old} → {new}", self.mgr.rename, old, new, after=lambda r: self.rename_target.clear())

    def save_labels(self) -> None:
        name = self.active()
        if name:
            self.mgr.set_project(name, self.project_label.text().strip(), self.project_dir.text().strip())
            self.log(f"Saved labels for '{name}'.")
            self.refresh()

    def snapshot_env(self) -> None:
        name = self.active()
        if name:
            self.mutate(f"Snapshot {name}", self.mgr.snapshot, name, "manual")

    def wipe_env(self) -> None:
        name = self.active()
        if name and confirm(self, "Wipe packages",
                            f"Uninstall everything except pip/setuptools/wheel from '{name}'.\n"
                            "A safety snapshot is taken first so you can restore.", phrase=name, danger=True):
            self.mutate(f"Wipe {name}", self.mgr.wipe, name)

    def delete_env(self) -> None:
        name = self.active()
        if not name:
            return
        info = self.envs.get(name)
        if info and not info.managed:
            box = QMessageBox(self)
            box.setWindowTitle("Remove environment")
            box.setText(f"'{name}' lives at:\n{info.path}\n\nUnregister keeps the folder. Delete folder removes "
                        "the venv from disk (project files are never touched).")
            unreg = box.addButton("Unregister only", QMessageBox.ButtonRole.AcceptRole)
            wipe = box.addButton("Delete venv folder…", QMessageBox.ButtonRole.DestructiveRole)
            box.addButton(QMessageBox.StandardButton.Cancel)
            box.exec()
            if box.clickedButton() is unreg:
                self.mutate(f"Unregister {name}", self.mgr.delete, name)
            elif box.clickedButton() is wipe and confirm(
                    self, "Delete venv folder", f"Permanently delete the folder\n{info.path}", phrase=name, danger=True):
                self.mutate(f"Delete venv folder {name}", self.mgr.delete, name, True)
            return
        if confirm(self, "Delete environment", f"Permanently delete '{name}' and its directory.\n"
                   "Take a snapshot first if you may need it back.", phrase=name, danger=True):
            self.mutate(f"Delete {name}", self.mgr.delete, name)

    def recreate_env(self) -> None:
        name = self.active()
        info = self.envs.get(name)
        if not name or not info:
            return
        from PyQt6.QtWidgets import QInputDialog
        keep = f"Keep current (Python {info.python_version})"
        choices = [keep] + [f"{p.version}  —  {p.path}" for p in self._pythons]
        picked, ok = QInputDialog.getItem(self, "Recreate in place", "Python for the rebuilt venv\n"
                                          "(pick a newer one to upgrade, or type a version such as 3.13):",
                                          choices, 0, True)
        if not ok:
            return
        python = "" if picked == keep else (picked.split("—", 1)[1].strip() if "—" in picked else picked.strip())
        if confirm(self, "Recreate in place",
                   f"Rebuild '{name}' at\n{info.path}\nPython: {python or info.python_version}\n\n"
                   "The package list is snapshotted, the old folder is moved aside, a new venv is built and "
                   "the pins reinstalled. If anything fails the original is restored unchanged.",
                   phrase=name, danger=True):
            self.mutate(f"Recreate {name}", self.mgr.recreate, name, python)

    def sync_project(self, name: str = "") -> None:
        name = name or self.active()
        if not name:
            return
        plan = self.mgr.sync_plan(name)
        if plan.blocked:
            QMessageBox.information(self, APP_NAME, plan.blocked)
            return
        drift = self.drifts.get(name)
        current = f"\n\nCurrent state: {drift.status}" if drift is not None else ""
        project_dir = self.mgr.meta(name).get("project_dir", "")
        if not self.mgr.is_trusted(project_dir) and not self._ask_trust(project_dir):
            return
        if confirm(self, "Sync project dependencies", f"{plan.summary()}\n\ninto '{name}'?{current}",
                   phrase=name if plan.exact and drift is not None and drift.extra else "", danger=plan.exact):
            self.mutate(f"Sync {name}", self.mgr.sync_project, name, True)

    def _ask_trust(self, project_dir: str) -> bool:
        from ..core import TRUST_WARNING
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Trust this project?")
        box.setText(TRUST_WARNING.format(project=project_dir))
        ok = box.addButton("I trust this project", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return box.clickedButton() is ok

    def create_temp(self) -> None:
        self.mutate("Create temp env", self.mgr.create_temp, self.temp_project.text().strip())

    def purge_temp(self) -> None:
        if confirm(self, "Purge temp envs", "Delete every temporary environment?", danger=True):
            self.mutate("Purge temp envs", self.mgr.purge_temp)

    def open_shell(self) -> None:
        name = self.active()
        if name:
            res = self.mgr.open_shell(name)
            self.log(res.message)
            if not res.ok:
                QMessageBox.information(self, APP_NAME, res.message)

    def copy_activate(self) -> None:
        name = self.active()
        if name:
            cmd = self.mgr.activation_command(name)
            QApplication.clipboard().setText(cmd)
            self.statusBar().showMessage(f"Copied: {cmd}", 5000)

    def open_home(self) -> None:
        path = str(self.mgr.paths.home)
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except OSError as exc:
            self._fail(f"Cannot open folder: {exc}")

    # ================================================================== package actions
    def install_specs(self) -> None:
        name = self.active()
        specs = self.install_spec.text().replace(",", " ").split()
        specs = [s.strip("'\"") for s in specs if s.strip("'\"")]
        if name and specs and confirm(self, "Install", f"Install into '{name}':\n\n" + "\n".join(specs)):
            self.mutate(f"Install {' '.join(specs)}", self.mgr.install, name, specs,
                        after=lambda r: r.ok and self.install_spec.clear())

    def install_req_file(self) -> None:
        name, path = self.active(), self.req_file.text().strip()
        if name and path and confirm(self, "Install requirements", f"Install '{path}' into '{name}'?"):
            self.mutate("Install requirements", self.mgr.install_requirements, name, path)

    def uninstall_selected(self) -> None:
        name = self.active()
        rows = sorted({i.row() for i in self.pkg_table.selectedItems()})
        pkgs = [self.pkg_table.item(r, 0).text() for r in rows if self.pkg_table.item(r, 0)]
        if name and pkgs and confirm(self, "Uninstall", f"Remove from '{name}':\n\n" + "\n".join(pkgs), danger=True):
            self.mutate(f"Uninstall {' '.join(pkgs)}", self.mgr.uninstall, name, pkgs)

    def export_requirements(self) -> None:
        name = self.active()
        if not name:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export requirements", str(Path.home() / f"{name}-requirements.txt"),
                                              "Text (*.txt)")
        if path:
            self.read("Export requirements", self.mgr.export_requirements, name, path,
                      on_done=lambda r: self.log(r.message))

    def check_outdated(self) -> None:
        name = self.active()
        if not name:
            return

        def done(res: OpResult) -> None:
            if not res.ok:
                self._fail(res.message)
                return
            rows = sorted(res.data, key=lambda d: d.get("name", "").lower())
            _fill(self.outdated_table, [[d.get("name"), d.get("version"), d.get("latest_version")] for d in rows])
            self.log(res.message)

        self.read(f"Checking outdated in {name}", self.mgr.outdated, name, on_done=done)

    def upgrade_selected(self) -> None:
        name = self.active()
        rows = sorted({i.row() for i in self.outdated_table.selectedItems()})
        specs = [f"{self.outdated_table.item(r, 0).text()}=={self.outdated_table.item(r, 2).text()}"
                 for r in rows if self.outdated_table.item(r, 0) and self.outdated_table.item(r, 2)]
        if name and specs and confirm(self, "Upgrade", "Upgrade:\n\n" + "\n".join(specs)):
            self.mutate("Upgrade selected", self.mgr.install, name, specs, after=lambda r: self.check_outdated())

    def upgrade_all(self) -> None:
        name = self.active()
        if name and confirm(self, "Upgrade all", f"Upgrade every package in '{name}' to its latest version?\n"
                            "This can introduce breaking changes. A safety snapshot is taken first.",
                            phrase=name, danger=True):
            self.mutate(f"Upgrade all in {name}", self.mgr.upgrade_all, name)

    def dep_check(self) -> None:
        name = self.active()
        if name:
            self.read("Dependency check", self.mgr.check, name,
                      on_done=lambda r: self.check_view.setPlainText(
                          ("✓ " if r.data.get("clean") else "✗ ") + r.message))

    # ================================================================== scan
    def scan_project(self) -> None:
        name, folder = self.active(), self.scan_dir.text().strip()
        if not name or not folder:
            if name:
                QMessageBox.information(self, APP_NAME, "Choose a project folder to scan.")
            return

        def done(res: OpResult) -> None:
            if not res.ok:
                self._fail(res.message)
                return
            rep = res.data["report"]
            self._scan_report = rep
            self.scan_summary.setText(rep.summary().replace("\n", "   ·   "))
            rows, colours = [], {}
            for r, f in enumerate(rep.findings):
                rows.append([f.distribution, f.module, f.installed_version or "MISSING", ", ".join(f.files[:4])])
                if f.missing:
                    colours[(r, 2)] = theme.AMBER
            _fill(self.scan_table, rows, colours)
            text = [f"Declared ({len(rep.declared)}): " + (", ".join(rep.declared) or "none found"), ""]
            text.append(f"Imported but NOT declared ({len(rep.undeclared)}):")
            text += [f"  ! {n}" for n in rep.undeclared] or ["  (none)"]
            text.append(f"\nDeclared but not imported ({len(rep.unused_declared)}) — may be tools/plugins:")
            text += [f"  ? {n}" for n in rep.unused_declared] or ["  (none)"]
            if rep.parse_errors:
                text.append(f"\nUnparseable files ({len(rep.parse_errors)}):")
                text += [f"  {e}" for e in rep.parse_errors[:30]]
            text.append(f"\nRequirements draft: {res.data['requirements_file']}")
            self.scan_decl.setPlainText("\n".join(text))
            self.log(res.message)

        self.read(f"Scanning {folder}", self.mgr.scan, name, folder, on_done=done)

    def install_missing(self) -> None:
        name = self.active()
        rep = self._scan_report
        missing = [f.distribution for f in rep.missing] if rep else []
        if not name or not missing:
            QMessageBox.information(self, APP_NAME, "Run a scan first — nothing missing to install.")
            return
        if confirm(self, "Install missing", f"Install into '{name}':\n\n" + "\n".join(missing) +
                   "\n\nCheck these names: an import name does not always match its PyPI project."):
            self.mutate("Install missing imports", self.mgr.install, name, missing, after=lambda r: self.scan_project())

    # ================================================================== security
    def run_audit(self) -> None:
        name = self.active()
        if not name:
            return
        self.sec_summary.setText("Querying OSV.dev…")

        def done(res: OpResult) -> None:
            rep = res.data
            self._audit_report = rep
            if not res.ok:
                self.sec_summary.setText(res.message)
                self._fail(res.message)
                return
            colours, rows = {}, []
            for r, f in enumerate(sorted(rep.findings, key=lambda x: (x.package.lower(), x.vuln_id))):
                rows.append([f.package, f.version, f.headline_id, f.severity or "—",
                             ", ".join(f.fixed_in) or "no fix", f.summary])
                colours[(r, 2)] = theme.RED if (f.severity or "").upper() in ("CRITICAL", "HIGH") else theme.AMBER
            _fill(self.sec_table, rows, colours)
            note = f"   ({len(rep.errors)} lookup error(s))" if rep.errors else ""
            self.sec_summary.setObjectName("Good" if not rep.findings else "Warn")
            self.sec_summary.setStyleSheet("")
            self.sec_summary.style().polish(self.sec_summary)
            self.sec_summary.setText(("✓ " if not rep.findings else "⚠ ") + res.message + note)
            self.log(res.message + note)

        self.read(f"Auditing {name}", self.mgr.security_audit, name, on_done=done)

    def upgrade_to_fix(self) -> None:
        name = self.active()
        row = self.sec_table.currentRow()
        if not name or row < 0:
            return
        pkg = self.sec_table.item(row, 0).text()
        installed = self.sec_table.item(row, 1).text()
        fixed = [v.strip() for v in self.sec_table.item(row, 4).text().split(",") if v.strip() and v != "no fix"]
        newer = sorted((v for v in fixed if version_key(v) > version_key(installed)), key=version_key)
        if not newer:
            QMessageBox.information(self, APP_NAME, f"No fixed release newer than {installed} is recorded for {pkg}.")
            return
        spec = f"{pkg}>={newer[0]}"
        if confirm(self, "Upgrade to fixed version", f"Install '{spec}' into '{name}'?"):
            self.mutate(f"Install {spec}", self.mgr.install, name, [spec], after=lambda r: self.run_audit())

    # ================================================================== pypi
    def pypi_lookup(self) -> None:
        q = self.pypi_query.text().strip()
        if not q:
            return
        self.pypi_view.setPlainText(f"Looking up '{q}'…")

        def done(info: pypi.PackageInfo) -> None:
            self._pypi_info = info
            self.pypi_view.setPlainText(info.describe())
            self.pypi_versions.clear()
            self.pypi_versions.addItems(info.versions[:60] or [info.latest])

        def failed(msg: str) -> None:
            self._pypi_info = None
            self.pypi_versions.clear()
            self.pypi_view.setPlainText(msg)

        self.runner.submit("PyPI lookup", pypi.lookup, q, self.pypi_pre.isChecked(), on_done=done, on_error=failed)

    def pypi_install(self) -> None:
        name, info = self.active(), self._pypi_info
        version = self.pypi_versions.currentText().strip()
        if not name or not info or not version:
            return
        spec = f"{info.name}=={version}"
        if confirm(self, "Install", f"Install '{spec}' into '{name}'?"):
            self.mutate(f"Install {spec}", self.mgr.install, name, [spec])

    # ================================================================== snapshots & templates
    def refresh_snapshots(self) -> None:
        env = self.env_combo.currentText() if self.snap_scope.isChecked() else ""
        snaps = self.mgr.list_snapshots(env)
        _fill(self.snap_table, [[s.get("id"), s.get("env"), s.get("taken"), s.get("reason"),
                                 s.get("package_count", 0), s.get("python_version")] for s in snaps])

    def _selected_snapshot(self) -> str:
        row = self.snap_table.currentRow()
        item = self.snap_table.item(row, 0) if row >= 0 else None
        return item.text() if item else ""

    def _preview_snapshot(self) -> None:
        sid = self._selected_snapshot()
        self.snap_preview.setPlainText(self.mgr.snapshot_requirements(sid) if sid else "")
        if sid and not self.restore_name.text():
            self.restore_name.setText(f"{sid.split('@')[0]}-restored")

    def restore_snapshot(self) -> None:
        sid, target = self._selected_snapshot(), self.restore_name.text().strip()
        if not sid or not target:
            QMessageBox.information(self, APP_NAME, "Select a snapshot and enter a new environment name.")
            return
        if confirm(self, "Restore snapshot", f"Create '{target}' from {sid}?"):
            self.mutate(f"Restore {sid}", self.mgr.restore_snapshot, sid, target)

    def delete_snapshot(self) -> None:
        sid = self._selected_snapshot()
        if sid and confirm(self, "Delete snapshot", f"Delete {sid}?", danger=True):
            self.mutate(f"Delete {sid}", self.mgr.delete_snapshot, sid)

    def refresh_templates(self) -> None:
        templates = self.mgr.list_templates()
        _fill(self.tmpl_table, [[n, c] for n, c in templates])
        prev = self.create_template.currentText()
        self.create_template.clear()
        self.create_template.addItem("(none)")
        self.create_template.addItems([n for n, _ in templates])
        if prev:
            self.create_template.setCurrentText(prev)

    def _preview_template(self) -> None:
        row = self.tmpl_table.currentRow()
        item = self.tmpl_table.item(row, 0) if row >= 0 else None
        path = self.mgr.template_path(item.text()) if item else None
        self.tmpl_preview.setPlainText(path.read_text(encoding="utf-8") if path and path.exists() else "")

    def save_template(self) -> None:
        name, tmpl = self.active(), self.tmpl_name.text().strip()
        if name and tmpl:
            self.mutate(f"Save template {tmpl}", self.mgr.save_template, name, tmpl, self.tmpl_unpinned.isChecked(),
                        after=lambda r: self.tmpl_name.clear())

    def delete_template(self) -> None:
        row = self.tmpl_table.currentRow()
        item = self.tmpl_table.item(row, 0) if row >= 0 else None
        if item and confirm(self, "Delete template", f"Delete template '{item.text()}'?", danger=True):
            self.mutate(f"Delete template {item.text()}", self.mgr.delete_template, item.text())

    # ================================================================== compare / audit
    def compare(self) -> None:
        a, b = self.cmp_a.currentText(), self.cmp_b.currentText()
        if not a or not b or a == b:
            QMessageBox.information(self, APP_NAME, "Pick two different environments.")
            return
        self.read("Comparing", self.mgr.compare, a, b, on_done=lambda r: self.cmp_view.setPlainText(r.message))

    def refresh_audit(self) -> None:
        recs = list(reversed(self.mgr.audit.tail(500)))
        rows, colours = [], {}
        for r, rec in enumerate(recs):
            ctx = rec.get("context") or {}
            detail = rec.get("detail", "")
            if ctx:
                detail = f"{detail}  {json.dumps(ctx, ensure_ascii=False)}"
            rows.append([rec.get("seq", ""), str(rec.get("ts", "")).replace("+00:00", ""), rec.get("event", ""),
                         rec.get("status", ""), detail[:400]])
            st = str(rec.get("status", ""))
            if st in ("failed", "corrupt", "vulnerable", "conflicts", "error"):
                colours[(r, 3)] = theme.RED
            elif st in ("partial", "warning"):
                colours[(r, 3)] = theme.AMBER
        _fill(self.audit_table, rows, colours)

    def verify_audit(self) -> None:
        def done(res: Any) -> None:
            if res.ok:
                self.chain_label.setObjectName("Good")
                self.chain_label.setText(f"✓ Chain intact — {res.records} records (tamper-evident, not keyed)")
            else:
                self.chain_label.setObjectName("Bad")
                self.chain_label.setText(f"✗ Broken at record #{res.first_bad_seq}: {res.reason}")
            self.chain_label.style().polish(self.chain_label)

        self.read("Verifying audit chain", self.mgr.audit.verify, on_done=done)

    def export_audit(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export audit log", str(Path.home() / "envwarden-audit.jsonl"),
                                              "JSON Lines (*.jsonl)")
        if path:
            Path(path).write_bytes(self.mgr.paths.audit.read_bytes() if self.mgr.paths.audit.exists() else b"")
            self.log(f"Audit log exported to {path}")

    # ================================================================== projects / workspaces
    def discover_workspaces(self, quiet: bool = False) -> None:
        if not self.mgr.workspaces():
            if not quiet:
                QMessageBox.information(self, APP_NAME, "Add a workspace folder first (e.g. C:\\dev).")
            return

        def done(res: OpResult) -> None:
            self.log(("OK   " if res.ok else "FAIL ") + res.message)
            if res.ok and res.data and res.data.get("added"):
                self.log("Registered: " + ", ".join(res.data["added"]))
            self.refresh()

        ok = self.runner.submit("Scanning workspaces", self.mgr.discover, on_done=done, on_error=self._fail,
                                mutating=True)
        if not ok and not quiet:
            QMessageBox.information(self, APP_NAME, "Another change is still running.")

    def _startup_maintenance(self) -> None:
        auto = bool(self.mgr._settings().get("auto_discover", True))

        def done(res: OpResult) -> None:
            if res.message != "Nothing to do.":
                self.log(res.message)
            self.refresh()

        self.runner.submit("Start-up maintenance", self.mgr.startup_maintenance, auto,
                           on_done=done, on_error=self._fail, mutating=True)

    def add_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Add workspace folder (holds your projects)", str(Path.home()))
        if not path:
            return
        res = self.mgr.add_workspace(path)
        self.log(res.message)
        if not res.ok:
            QMessageBox.warning(self, APP_NAME, res.message)
            return
        self.refresh_projects()
        self.discover_workspaces()

    def remove_workspace(self) -> None:
        row = self.ws_table.currentRow()
        item = self.ws_table.item(row, 0) if row >= 0 else None
        if item and confirm(self, "Remove workspace", f"Stop scanning {item.text()}?\n\n"
                            "Environments already registered stay registered."):
            self.log(self.mgr.remove_workspace(item.text()).message)
            self.refresh_projects()

    def refresh_projects(self) -> None:
        _fill(self.ws_table, [[w] for w in self.mgr.workspaces()])
        snap = self.mgr.projects()
        projects = snap.get("projects", [])
        rows, colours = [], {}
        for r, proj in enumerate(sorted(projects, key=lambda p: p["name"].lower())):
            venvs = proj.get("venvs", [])
            env = next((v["env"] for v in venvs if v.get("env") in self.envs), venvs[0]["env"] if venvs else "")
            info = self.envs.get(env)
            vname = ", ".join(Path(v["path"]).name for v in venvs) or "— none"
            health = info.health.upper() if info else ("—" if not venvs else "UNREGISTERED")
            drift = self.drifts.get(env) if env else None
            dtext = drift.status if drift is not None else ("…" if info and not self.drifts else "—")
            source = drift.source.kind if drift is not None and drift.source else " ".join(proj.get("markers", []))
            rows.append([proj["name"], vname, env or "", info.python_version if info else "", health,
                         dtext, source, proj["path"]])
            if drift is not None:
                if dtext.startswith("in sync"):
                    colours[(r, 5)] = theme.PHOSPHOR
                elif dtext.startswith(("managed by", "no deps")):
                    colours[(r, 5)] = theme.MUTED
                else:
                    colours[(r, 5)] = theme.AMBER
            if not venvs:
                colours[(r, 1)] = theme.AMBER
            elif len(venvs) > 1:
                colours[(r, 1)] = theme.AMBER
            if info:
                colours[(r, 4)] = theme.HEALTH_COLOURS.get(info.health, theme.TEXT)
        _fill(self.proj_table, rows, colours)
        missing = sum(1 for p in projects if not p.get("venvs"))
        drifted = sum(1 for d in self.drifts.values() if d.drifted or d.stale)
        self.metric["novenv"].setText(str(missing) if projects else "—")
        if projects:
            self.proj_summary.setText(f"{len(projects)} projects · {len(projects) - missing} with a venv · "
                                      f"{missing} without · {drifted} drifted · last scan {snap.get('scanned', '?')}")
        self._apply_proj_filter(self.proj_filter.text())

    def _apply_proj_filter(self, text: str) -> None:
        needle = text.lower().strip()
        only_missing = self.proj_only_missing.isChecked()
        for r in range(self.proj_table.rowCount()):
            hay = " ".join((self.proj_table.item(r, c).text() if self.proj_table.item(r, c) else "")
                           for c in range(self.proj_table.columnCount())).lower()
            venv_item = self.proj_table.item(r, 1)
            hide = (bool(needle) and needle not in hay) or (only_missing and venv_item is not None
                                                             and venv_item.text() != "— none")
            self.proj_table.setRowHidden(r, hide)

    def _selected_project(self) -> tuple[str, str]:
        row = self.proj_table.currentRow()
        if row < 0 or not self.proj_table.item(row, 7):
            return "", ""
        return self.proj_table.item(row, 7).text(), self.proj_table.item(row, 2).text()

    def _show_project_drift(self) -> None:
        path, env = self._selected_project()
        if not path:
            return
        if not env:
            self.drift_view.setPlainText("This project has no venv yet — CREATE VENV IN PROJECT makes one.")
            return
        drift = self.drifts.get(env)
        self.drift_view.setPlainText(drift.describe() if drift is not None else "Checking…")

    def _selected_project_env(self) -> str:
        path, env = self._selected_project()
        if not path:
            QMessageBox.information(self, APP_NAME, "Select a project first.")
        elif not env:
            QMessageBox.information(self, APP_NAME, "This project has no registered venv yet.")
        return env

    def use_project_env(self) -> None:
        env = self._selected_project_env()
        if env:
            self.env_combo.setCurrentText(env)
            self.tabs.setCurrentIndex(0)

    def create_project_venv(self) -> None:
        path, env = self._selected_project()
        if not path:
            QMessageBox.information(self, APP_NAME, "Select a project first.")
            return
        if env:
            QMessageBox.information(self, APP_NAME, f"This project already has a venv (registered as '{env}').\n"
                                    "Use RECREATE IN PLACE on it if it is broken.")
            return
        idx = self.proj_python.currentIndex()
        typed = self.proj_python.currentText().strip()
        python = (self.proj_python.itemData(idx) if idx > 0 and self.proj_python.itemText(idx) == typed else typed) or ""
        folder = self.proj_venv_name.text().strip() or ".venv"
        sync = self.proj_sync.isChecked()
        if sync and not self.mgr.is_trusted(path) and not self._ask_trust(path):
            return
        if confirm(self, "Create project venv", f"Create {Path(path) / folder}\nPython: {python or 'default'}\n"
                   f"Install project deps afterwards: {'yes' if sync else 'no'}"):
            self.mutate(f"Create venv in {Path(path).name}", self.mgr.create_in_project, path, python, folder, "", sync,
                        sync, after=lambda r: self.discover_workspaces(quiet=True))

    def scan_selected_project(self) -> None:
        path, env = self._selected_project()
        if not path:
            return
        if env:
            self.env_combo.setCurrentText(env)
        self.scan_dir.setText(path)
        self.tabs.setCurrentIndex([self.tabs.tabText(i) for i in range(self.tabs.count())].index("SCAN"))
        self.scan_project()

    def open_project_folder(self) -> None:
        path, _env = self._selected_project()
        if path:
            self._open_path(path)

    def _open_path(self, path: str) -> None:
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except OSError as exc:
            self._fail(f"Cannot open folder: {exc}")

    # ================================================================== misc
    def _browse_file(self, target: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select requirements file", "",
                                              "Requirements (*.txt *.in);;All files (*)")
        if path:
            target.setText(path)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.runner.mutating_busy:
            if QMessageBox.question(self, APP_NAME, "A change is still running. Quit anyway and wait for it?") \
                    != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self.runner.shutdown()
        super().closeEvent(event)
