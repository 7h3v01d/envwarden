# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Design system: Obsidian/Panel/Border, Teal accent, flat zero-radius, JetBrains Mono."""

OBSIDIAN = "#0b0f14"
PANEL = "#11161d"
BORDER = "#1e2831"
TEAL = "#2fd6c3"
PHOSPHOR = "#4be08a"
AMBER = "#ffb454"
RED = "#ff6b6b"
TEXT = "#c8d3da"
MUTED = "#6b7a86"
RAISED = "#161d26"

MONO = "'JetBrains Mono', 'Cascadia Mono', 'Consolas', monospace"

HEALTH_COLOURS = {"ok": PHOSPHOR, "warn": AMBER, "bad": RED}

STYLE = f"""
* {{ font-family: {MONO}; font-size: 12px; }}
QWidget {{ background: {OBSIDIAN}; color: {TEXT}; }}
QToolTip {{ background: {PANEL}; color: {TEXT}; border: 1px solid {TEAL}; padding: 4px; }}

QFrame#Header {{ background: {PANEL}; border: none; border-bottom: 2px solid {TEAL}; }}
QFrame#Card, QGroupBox {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 0; }}
QGroupBox {{ margin-top: 14px; padding: 10px 8px 8px 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; color: {TEAL};
                    font-weight: 700; letter-spacing: 1px; }}

QLabel {{ background: transparent; }}
QLabel#Title {{ color: {TEXT}; font-size: 18px; font-weight: 700; letter-spacing: 2px; }}
QLabel#Edition {{ color: {TEAL}; font-size: 10px; letter-spacing: 3px; }}
QLabel#Section {{ color: {TEAL}; font-size: 10px; font-weight: 700; letter-spacing: 2px; }}
QLabel#Muted {{ color: {MUTED}; }}
QLabel#Metric {{ color: {TEXT}; font-size: 22px; font-weight: 700; }}
QLabel#Good {{ color: {PHOSPHOR}; font-weight: 700; }}
QLabel#Warn {{ color: {AMBER}; font-weight: 700; }}
QLabel#Bad  {{ color: {RED}; font-weight: 700; }}

QLineEdit, QComboBox, QPlainTextEdit, QTableWidget, QListWidget, QSpinBox {{
    background: {OBSIDIAN}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 0;
    padding: 5px 8px; selection-background-color: #12403b; selection-color: {TEXT};
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTableWidget:focus {{ border-color: {TEAL}; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {MUTED}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; border: 1px solid {TEAL}; selection-background-color: #12403b; }}

QPushButton {{ background: {RAISED}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 0;
               padding: 6px 12px; font-weight: 600; }}
QPushButton:hover {{ border-color: {TEAL}; color: {TEAL}; }}
QPushButton:pressed {{ background: {OBSIDIAN}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; }}
QPushButton#Primary {{ border-color: {TEAL}; color: {TEAL}; }}
QPushButton#Primary:hover {{ background: #0f2a28; }}
QPushButton#Danger {{ border-color: {RED}; color: {RED}; }}
QPushButton#Danger:hover {{ background: #2a1414; }}
QPushButton#Safe {{ border-color: {PHOSPHOR}; color: {PHOSPHOR}; }}
QPushButton#Safe:hover {{ background: #11281a; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-top: none; top: 0; }}
QTabBar::tab {{ background: {OBSIDIAN}; color: {MUTED}; border: 1px solid {BORDER}; border-bottom: none;
                padding: 8px 14px; margin-right: -1px; font-weight: 700; letter-spacing: 1px; }}
QTabBar::tab:selected {{ background: {PANEL}; color: {TEAL}; border-top: 2px solid {TEAL}; }}
QTabBar::tab:hover:!selected {{ color: {TEXT}; }}

QHeaderView::section {{ background: {PANEL}; color: {TEAL}; border: none; border-right: 1px solid {BORDER};
                        border-bottom: 1px solid {BORDER}; padding: 6px 8px; font-weight: 700; }}
QTableWidget {{ gridline-color: {BORDER}; alternate-background-color: #0e1319; }}
QTableWidget::item:selected {{ background: #12403b; }}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}

QPlainTextEdit#Console {{ color: #9fb3bf; font-size: 11px; }}
QProgressBar {{ background: {OBSIDIAN}; border: 1px solid {BORDER}; border-radius: 0; max-height: 4px; }}
QProgressBar::chunk {{ background: {TEAL}; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; border-top: 1px solid {BORDER}; }}
QStatusBar QLabel {{ color: {MUTED}; padding: 0 8px; }}
QCheckBox {{ spacing: 6px; background: transparent; }}
QCheckBox::indicator {{ width: 13px; height: 13px; border: 1px solid {BORDER}; background: {OBSIDIAN}; }}
QCheckBox::indicator:checked {{ background: {TEAL}; border-color: {TEAL}; }}
QScrollBar:vertical {{ background: {OBSIDIAN}; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {TEAL}; }}
QScrollBar:horizontal {{ background: {OBSIDIAN}; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QSplitter::handle {{ background: {BORDER}; }}
QDialog {{ background: {PANEL}; }}
"""
