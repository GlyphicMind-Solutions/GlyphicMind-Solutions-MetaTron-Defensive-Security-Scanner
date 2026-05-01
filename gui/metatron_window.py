# ./MetaTron/engine/metatron_window.py
# MetaTron Security Tool - GUI Interface
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



# system imports
from pathlib import Path
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QLineEdit, QMessageBox, QTabWidget,
    QGroupBox, QCheckBox, QApplication, QSizePolicy, QMainWindow
)

# local imports
from engine.tool_adapter import run_recon
from engine.llm_adapter import run_analysis
from engine.db_adapter import save_session, list_sessions, load_session
from engine.llm_engine import LLMEngine
from engine.tool_detector import detect_tools, install_command



# ===============================================
# METATRON WINDOW CLASS
# ===============================================
class MetatronWindow(QMainWindow):
    # ---------------
    # Initialize
    # ---------------
    def __init__(self, mind_root: Path):
        super().__init__()

        #engine - pathing
        self.mind_root = Path(mind_root)
        self.engine = LLMEngine(self.mind_root)

        #window title - size
        self.setWindowTitle("GlyphicMind Solutions — MetaTron — Defensive Security Scanner")
        self.setMinimumSize(1024, 768)

        #darkmode - autoscroll
        self.dark_mode_enabled = False
        self.auto_scroll_enabled = True

        #build ui
        self._build_ui()


# ===============================================
# Build Section
# ===============================================
    # ---------------
    # Build UI
    # ---------------
    def _build_ui(self):

        central = QWidget()
        central.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout = QVBoxLayout(central)

        # Tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Build each tab
        self._build_scan_tab()
        self._build_history_tab()
        self._build_tools_tab()
        self._build_settings_tab()

        self.setCentralWidget(central)
        self._refresh_sessions()

    # ---------------
    # Build Scan Tab
    # ---------------
    def _build_scan_tab(self):
        scan_tab = QWidget()
        v = QVBoxLayout()

        # Target input
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target (IP or Domain):"))
        self.target_input = QLineEdit()
        self.target_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        target_row.addWidget(self.target_input)
        v.addLayout(target_row)

        # Run scan Button
        btn_row = QHBoxLayout()
        self.run_button = QPushButton("Run Scan")
        btn_row.addWidget(self.run_button)
        self.run_button.clicked.connect(self._run_scan)

        # Clear Output Button
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(lambda: self.scan_output.clear())
        btn_row.addWidget(clear_btn)

        v.addLayout(btn_row)

        # Auto-scroll toggle
        self.auto_scroll_box = QCheckBox("Auto-scroll output")
        self.auto_scroll_box.setChecked(True)
        self.auto_scroll_box.stateChanged.connect(self._toggle_autoscroll)
        v.addWidget(self.auto_scroll_box)

        # Recon section
        self.recon_box = QGroupBox("Recon Results")
        self.recon_box.setCheckable(True)
        self.recon_box.setChecked(True)
        recon_layout = QVBoxLayout()
        self.recon_output = QTextEdit()
        self.recon_output.setReadOnly(True)
        self.recon_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        recon_layout.addWidget(self.recon_output)
        self.recon_box.setLayout(recon_layout)
        v.addWidget(self.recon_box)

        # Analysis section
        self.analysis_box = QGroupBox("LLM Analysis")
        self.analysis_box.setCheckable(True)
        self.analysis_box.setChecked(True)
        analysis_layout = QVBoxLayout()
        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        analysis_layout.addWidget(self.analysis_output)
        self.analysis_box.setLayout(analysis_layout)
        v.addWidget(self.analysis_box)

        # Risk level section
        self.risk_box = QGroupBox("Risk Level")
        self.risk_box.setCheckable(True)
        self.risk_box.setChecked(True)
        self.risk_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        risk_layout = QVBoxLayout()
        self.risk_label = QLabel("No scan yet.")
        risk_layout.addWidget(self.risk_label)
        self.risk_box.setLayout(risk_layout)
        v.addWidget(self.risk_box)

        # Hardening Checklist section
        self.hardening_box = QGroupBox("Hardening Checklist")
        self.hardening_box.setCheckable(True)
        self.hardening_box.setChecked(True)
        hard_layout = QVBoxLayout()
        self.hardening_output = QTextEdit()
        self.hardening_output.setReadOnly(True)
        self.hardening_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        hard_layout.addWidget(self.hardening_output)
        self.hardening_box.setLayout(hard_layout)
        v.addWidget(self.hardening_box)

        # Final combined output
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        v.addWidget(self.scan_output)

        # Stretch to fill space
        v.addStretch(1)

        #tab title
        scan_tab.setLayout(v)
        self.tabs.addTab(scan_tab, "Scan")


    # --------------------
    # Build History Tab
    # --------------------
    def _build_history_tab(self):

        #--- HISTORY TAB ---#
        history_tab = QWidget()
        v = QVBoxLayout()

        #past sessions
        v.addWidget(QLabel("Past Sessions:"))
        self.session_box = QComboBox()
        self.session_box.currentIndexChanged.connect(self._load_session)
        v.addWidget(self.session_box)

        #summary box
        self.hist_summary_box = self._make_collapsible("Summary")

        #vulnerabilities box
        self.hist_vuln_box = self._make_collapsible("Vulnerabilities")

        #fixes box
        self.hist_fix_box = self._make_collapsible("Fixes")

        #exploit box
        self.hist_exploit_box = self._make_collapsible("Exploits Attempted")

        #hardening box
        self.hist_hardening_box = self._make_collapsible("Hardening Checklist")

        #box layout
        v.addWidget(self.hist_summary_box)
        v.addWidget(self.hist_vuln_box)
        v.addWidget(self.hist_fix_box)
        v.addWidget(self.hist_exploit_box)
        v.addWidget(self.hist_hardening_box)

        #make stretchable
        v.addStretch(1)
        history_tab.setLayout(v)

        #tab title
        self.tabs.addTab(history_tab, "History")


    # -----------------
    # Build Tools Tab
    # -----------------
    def _build_tools_tab(self):
        tools_tab = QWidget()
        v = QVBoxLayout()

        v.addWidget(QLabel("Recon Tool Availability:"))

        #tools output
        self.tools_output = QTextEdit()
        self.tools_output.setReadOnly(True)
        self.tools_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        v.addWidget(self.tools_output)

        #refresh tools
        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Tools")
        refresh_btn.clicked.connect(self._refresh_tools)
        btn_row.addWidget(refresh_btn)

        #copy install commands
        copy_btn = QPushButton("Copy Install Commands")
        copy_btn.clicked.connect(self._copy_install_commands)
        btn_row.addWidget(copy_btn)
        v.addLayout(btn_row)

        #layout
        v.addStretch(1)
        tools_tab.setLayout(v)

        #tab title
        self.tabs.addTab(tools_tab, "Tools")
        self._refresh_tools()

    # -------------------
    # Build Settings Tab
    # -------------------
    def _build_settings_tab(self):
        settings_tab = QWidget()
        v = QVBoxLayout()

        #enable darkmode checkbox
        self.dark_mode_box = QCheckBox("Enable Dark Mode")
        self.dark_mode_box.stateChanged.connect(self._toggle_dark_mode)
        v.addWidget(self.dark_mode_box)

        v.addStretch(1)
        settings_tab.setLayout(v)
        #Settings tab
        self.tabs.addTab(settings_tab, "Settings")


# ===============================================
# Helper Section
# ===============================================
    # -----------------
    # Make Collapsible
    # -----------------
    def _make_collapsible(self, title):
        box = QGroupBox(title)
        box.setCheckable(True)
        box.setChecked(True)
        layout = QVBoxLayout()
        text = QTextEdit()
        text.setReadOnly(True)
        text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(text)
        box.setLayout(layout)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        return box


# ===============================================
# Loading Section
# ===============================================
    # ---------------
    # Load Session
    # ---------------
    def _load_session(self):
        sl_no = self.session_box.currentData()
        if sl_no is None:
            return

        data = load_session(sl_no)

        # Summary
        s = data["summary"]
        if s:
            self.hist_summary_box.layout().itemAt(0).widget().setText(
                f"{s['ai_analysis']}\n\nRisk Level: {s['risk_level']}"
            )

        # Vulnerabilities
        vuln_text = ""
        for v in data["vulnerabilities"]:
            vuln_text += f"- {v['vuln_name']} ({v['severity']})\n"
            vuln_text += f"  Port: {v['port']}  Service: {v['service']}\n"
            vuln_text += f"  Desc: {v['description']}\n\n"
        self.hist_vuln_box.layout().itemAt(0).widget().setText(vuln_text)

        # Fixes
        fix_text = ""
        for f in data["fixes"]:
            fix_text += f"- {f['fix_text']}\n"
        self.hist_fix_box.layout().itemAt(0).widget().setText(fix_text)

        # Exploits
        exp_text = ""
        for e in data["exploits"]:
            exp_text += f"- {e['exploit_name']} ({e['tool_used']})\n"
            exp_text += f"  Payload: {e['payload']}\n"
            exp_text += f"  Result:  {e['result']}\n"
            exp_text += f"  Notes:   {e['notes']}\n\n"
        self.hist_exploit_box.layout().itemAt(0).widget().setText(exp_text)

        # Hardening Checklist
        hard_text = ""
        for item in data.get("hardening", []):
            hard_text += f"- {item}\n"
        self.hist_hardening_box.layout().itemAt(0).widget().setText(hard_text)


# ===============================================
# Running Section
# ===============================================
    # ---------------
    # Run Scan
    # ---------------
    def _run_scan(self):
        target = self.target_input.text().strip()

        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target IP or domain.")
            return

        # Recon
        self.recon_output.setText(f"🔍 Running recon on: {target} ...")
        recon_data = run_recon(target)
        self.recon_output.append(recon_data)

        # LLM analysis
        self.analysis_output.setText("🧠 Running LLM analysis...")
        analysis = run_analysis(self.engine, recon_data, target)
        self.analysis_output.append(analysis["full_response"])

        # Risk level + score
        risk = analysis["risk_level"]
        score = analysis.get("risk_score", 0)

        color_map = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "gold",
            "LOW": "green",
            "UNKNOWN": "gray"
        }
        color = color_map.get(risk, "gray")

        self.risk_label.setText(
            f"<span style='color:{color}; font-weight:bold;'>{risk}</span>"
            f"<br>Score: {score} / 100"
        )

        # Hardening checklist
        hardening_items = analysis.get("hardening", [])
        hard_text = ""
        for item in hardening_items:
            hard_text += f"- {item}\n"
        self.hardening_output.setText(hard_text)

        # Save session
        session_payload = {
            "target": target,
            "raw_scan": recon_data,
            "full_response": analysis["full_response"],
            "vulnerabilities": analysis["vulnerabilities"],
            "exploits": analysis["exploits"],
            "risk_level": analysis["risk_level"],
            "risk_score": analysis.get("risk_score", 0),
            "hardening": analysis.get("hardening", []),
            "summary": analysis["summary"]
        }
        save_session(session_payload)
        self.scan_output.append("\n💾 Session saved.")

        self._refresh_sessions()

        if self.auto_scroll_enabled:
            self.scan_output.moveCursor(self.scan_output.textCursor().End)


# ===============================================
# TOOL PANEL FUNCTIONS
# ===============================================
    # ---------------
    # Refresh Tools
    # ---------------
    def _refresh_tools(self):
        tools = detect_tools()
        text = "Detected Tools:\n\n"
        for tool, ok in tools.items():
            mark = "✔" if ok else "✖"
            text += f"{mark} {tool}\n"
        self.tools_output.setText(text)

    # ----------------------
    # Copy Install Commands
    # ----------------------
    def _copy_install_commands(self):
        cmd = install_command()
        clipboard = QApplication.clipboard()
        clipboard.setText(cmd)
        QMessageBox.information(self, "Copied", "Install commands copied to clipboard.")


# ===============================================
# SETTINGS FUNCTIONS
# ===============================================
    # ------------------
    # Toggle Dark Mode
    # ------------------
    def _toggle_dark_mode(self):
        self.dark_mode_enabled = self.dark_mode_box.isChecked()

        if self.dark_mode_enabled:
            self.setStyleSheet("""
                QWidget { background-color: #1e1e1e; color: #dddddd; }
                QTextEdit { background-color: #2b2b2b; color: #ffffff; }
            """)
        else:
            self.setStyleSheet("")

    # ------------------
    # Toggle AutoScroll
    # ------------------
    def _toggle_autoscroll(self):
        self.auto_scroll_enabled = self.auto_scroll_box.isChecked()

# ==================================
# Sessions Section
# ==================================
    # -----------------
    # Refresh Sessions
    # -----------------
    def _refresh_sessions(self):
        self.session_box.clear()
        sessions = list_sessions()
        for s in sessions:
            sl_no, target, scan_date, status = s
            label = f"{sl_no} — {target} — {scan_date}"
            self.session_box.addItem(label, sl_no)

