import sys
import threading
import os
import glob

from PyQt6.QtWidgets import (
    QApplication, QWidget, QMainWindow,
    QLabel, QPushButton, QTextEdit,
    QLineEdit, QVBoxLayout, QHBoxLayout,
    QTabWidget, QProgressBar, QFrame,
    QSplitter, QScrollArea
)
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QTextCursor, QFont, QPalette

from engine import run_scan

class StreamBridge(QObject):
    recon    = pyqtSignal(str)
    port     = pyqtSignal(str)
    vuln     = pyqtSignal(str)

    # ADDED
    endpoint = pyqtSignal(str)

    status   = pyqtSignal(str)
    progress = pyqtSignal(int)
    report   = pyqtSignal(dict)
    error    = pyqtSignal(str)
    counter  = pyqtSignal(str, int)

BRIDGE = StreamBridge()

class IntroScreen(QWidget):
    finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setFixedSize(1200, 700)
        self.setWindowTitle("KAGURA")
        self.setStyleSheet("background: white;")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        self.katana = QLabel("")
        self.katana.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.katana.setStyleSheet(
            "color: darkred; font-size: 38px;")

        self.title = QLabel("")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet("""
            color: darkred;
            font-size: 72px;
            font-weight: bold;
            font-family: Times New Roman;
        """)

        self.subtitle = QLabel("")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setStyleSheet("""
            color: goldenrod;
            font-size: 18px;
            font-weight: bold;
            letter-spacing: 4px;
        """)

        self.version = QLabel("")
        self.version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.version.setStyleSheet(
            "color: #aaaaaa; font-size: 12px;")

        layout.addWidget(self.katana)
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addWidget(self.version)
        self.setLayout(layout)

        self.frames = ["⚔", "⚔ ⚔", "⚔ ⚔ ⚔", "⚔ ⚔ ⚔ ⚔"]
        self.frame_index = 0
        self.text        = "KAGURA"
        self.index       = 0

        self.timer = QTimer()
        self.timer.timeout.connect(self.animate)
        self.timer.start(180)

    def animate(self):
        if self.frame_index < len(self.frames):
            self.katana.setText(self.frames[self.frame_index])
            self.frame_index += 1
            return
        if self.index < len(self.text):
            self.title.setText(
                self.title.text() + self.text[self.index])
            self.index += 1
            return
        self.subtitle.setText("FOR RED TEAMERS")
        self.version.setText(
            "Offensive Security Intelligence Framework  v1.0")
        self.timer.stop()
        QTimer.singleShot(1800, self.finish)

    def finish(self):
        self.finished.emit()
        self.close()

class StatCard(QFrame):
    def __init__(self, label, color="#1565c0"):
        super().__init__()
        self.color = color
        self.setStyleSheet(f"""
            QFrame {{
                background: white;
                border: 2px solid {color};
                border-radius: 10px;
                padding: 8px;
            }}
        """)
        layout = QVBoxLayout()
        layout.setSpacing(2)

        self.value_label = QLabel("0")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setStyleSheet(f"""
            color: {color};
            font-size: 28px;
            font-weight: bold;
            font-family: Consolas;
        """)

        self.title_label = QLabel(label)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("""
            color: #555555;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        """)

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
        self.setLayout(layout)

    def set_value(self, val):
        self.value_label.setText(str(val))

class KaguraGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("KAGURA  ⚔  Security Intelligence Platform")
        self.resize(1500, 900)
        self.sub_count  = 0
        self.port_count = 0
        self.vuln_count = 0

        # ADDED
        self.ep_count = 0

        self.last_domain = ""
        self.build_ui()
        self.connect_signals()

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout()
        main.setSpacing(10)
        main.setContentsMargins(16, 12, 16, 12)

        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0d1b2a,
                    stop:1 #1565c0
                );
                border-radius: 10px;
                padding: 10px;
            }
        """)
        hlay = QHBoxLayout()

        brand = QLabel("⚔  KAGURA")
        brand.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            font-family: Times New Roman;
        """)

        tag = QLabel("FOR RED TEAMERS")
        tag.setAlignment(Qt.AlignmentFlag.AlignRight |
                          Qt.AlignmentFlag.AlignVCenter)
        tag.setStyleSheet("""
            color: goldenrod;
            font-size: 13px;
            font-weight: bold;
            letter-spacing: 3px;
        """)

        hlay.addWidget(brand)
        hlay.addStretch()
        hlay.addWidget(tag)
        header.setLayout(hlay)
        main.addWidget(header)

        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background: #f8f9fa;
                border: 1px solid #d0d7de;
                border-radius: 10px;
                padding: 8px;
            }
        """)
        ilay = QHBoxLayout()

        domain_label = QLabel("TARGET:")
        domain_label.setStyleSheet("""
            color: #1565c0;
            font-weight: bold;
            font-size: 13px;
        """)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "Enter target domain  (e.g. target.com)")
        self.target_input.setStyleSheet("""
            background: white;
            color: black;
            padding: 10px 14px;
            border-radius: 8px;
            border: 1px solid #d0d7de;
            font-size: 14px;
        """)
        self.target_input.returnPressed.connect(self.start_scan)

        self.scan_btn = QPushButton("⚔  START SCAN")
        self.scan_btn.setFixedWidth(160)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #1565c0;
                color: white;
                padding: 10px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover { background: #0d47a1; }
            QPushButton:disabled {
                background: #aaaaaa;
                color: #eeeeee;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)

        self.clear_btn = QPushButton(" CLEAR")
        self.clear_btn.setFixedWidth(110)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background: #f1f3f4;
                color: #555;
                padding: 10px;
                border-radius: 8px;
                border: 1px solid #d0d7de;
                font-weight: bold;
            }
            QPushButton:hover { background: #e0e0e0; }
        """)
        self.clear_btn.clicked.connect(self.clear_all)

        ilay.addWidget(domain_label)
        ilay.addWidget(self.target_input)
        ilay.addWidget(self.scan_btn)
        ilay.addWidget(self.clear_btn)
        input_frame.setLayout(ilay)
        main.addWidget(input_frame)

        cards_row = QHBoxLayout()

        self.card_sub  = StatCard("SUBDOMAINS",      "#1565c0")
        self.card_port = StatCard("OPEN PORTS",      "#2e7d32")
        self.card_vuln = StatCard("VULNERABILITIES", "#b71c1c")

        self.card_ep = StatCard("ENDPOINTS", "#6a1b9a")

        self.card_time = StatCard("SCAN TIME (s)",   "#6a1b9a")

        for c in [self.card_sub, self.card_port,
                  self.card_vuln]:

            cards_row.addWidget(c)

        cards_row.addWidget(self.card_ep)

        cards_row.addWidget(self.card_time)

        main.addLayout(cards_row)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFormat(" %p%  —  Scanning...")
        self.progress.setFixedHeight(28)
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #f1f3f4;
                border: 1px solid #d0d7de;
                border-radius: 8px;
                text-align: center;
                color: black;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1565c0,
                    stop:1 #42a5f5
                );
                border-radius: 8px;
            }
        """)
        main.addWidget(self.progress)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                background: white;
                border: 1px solid #d0d7de;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #f4f6f8;
                padding: 10px 24px;
                min-width: 140px;
                color: #333;
                border: 1px solid #d0d7de;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                font-weight: bold;
                font-size: 13px;
            }
            QTabBar::tab:selected {
                background: #1565c0;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background: #e3f2fd;
            }
        """)

        self.recon_tab  = self.make_text_box()
        self.port_tab   = self.make_text_box()
        self.vuln_tab   = self.make_text_box()

        self.endpoint_tab = self.make_text_box()

        self.report_tab = self.make_text_box()

        self.tabs.addTab(self.recon_tab,  " Recon")
        self.tabs.addTab(self.port_tab,   " Ports")
        self.tabs.addTab(self.vuln_tab,   " Vulnerabilities")

        self.tabs.addTab(self.endpoint_tab, " Endpoints")

        self.tabs.addTab(self.report_tab, " Report")
        main.addWidget(self.tabs)

        status_row = QHBoxLayout()

        self.status = QLabel("⬤  READY")
        self.status.setStyleSheet("""
            color: #2e7d32;
            font-weight: bold;
            font-size: 13px;
            padding: 6px;
        """)

        self.open_report_btn = QPushButton(
            "📂  Open HTML Report")
        self.open_report_btn.setVisible(False)
        self.open_report_btn.setStyleSheet("""
            QPushButton {
                background: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #2e7d32;
                padding: 6px 14px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #c8e6c9; }
        """)
        self.open_report_btn.clicked.connect(
            self.open_html_report)

        status_row.addWidget(self.status)
        status_row.addStretch()
        status_row.addWidget(self.open_report_btn)
        main.addLayout(status_row)

        root.setLayout(main)

    def make_text_box(self):
        box = QTextEdit()
        box.setReadOnly(True)
        box.setStyleSheet("""
            background: #fafafa;
            color: #111111;
            border: none;
            font-family: Consolas, Courier New;
            font-size: 13px;
            padding: 12px;
        """)
        return box

    def connect_signals(self):
        BRIDGE.recon.connect(
            lambda x: self.log(self.recon_tab, x, "#1a237e"))

        BRIDGE.port.connect(
            lambda x: self.log(self.port_tab, x, "#1b5e20"))

        BRIDGE.vuln.connect(
            lambda x: self.log(self.vuln_tab, x, "#b71c1c"))

        BRIDGE.endpoint.connect(
            lambda x: self.log(
                self.endpoint_tab, x, "#6a1b9a"))

        BRIDGE.status.connect(self.update_status)
        BRIDGE.progress.connect(self.progress.setValue)
        BRIDGE.report.connect(self.render_report)
        BRIDGE.counter.connect(self.update_counter)

    def log(self, widget, text, color="#111111"):
        widget.setTextColor(QColor(color))
        widget.append(text)
        widget.moveCursor(QTextCursor.MoveOperation.End)

    def update_status(self, text):
        self.status.setText(f"⬤  {text}")
        if "error" in text.lower():
            self.status.setStyleSheet(
                "color: #b71c1c; font-weight: bold; "
                "font-size: 13px; padding: 6px;")
        elif "complete" in text.lower():
            self.status.setStyleSheet(
                "color: #2e7d32; font-weight: bold; "
                "font-size: 13px; padding: 6px;")
        else:
            self.status.setStyleSheet(
                "color: #1565c0; font-weight: bold; "
                "font-size: 13px; padding: 6px;")

    def update_counter(self, kind, val):
        if kind == "sub":
            self.card_sub.set_value(val)

        elif kind == "port":
            self.card_port.set_value(val)

        elif kind == "vuln":
            self.card_vuln.set_value(val)

        # ADDED
        elif kind == "ep":
            self.card_ep.set_value(val)

    def render_report(self, meta):
        self.report_tab.clear()

        domain    = meta.get('target', 'N/A')
        subs      = meta.get('subdomain_count', 0)
        assets    = meta.get('asset_count', 0)
        vulns     = meta.get('vuln_count', 0)
        scan_time = meta.get('scan_time', 0)
        findings  = meta.get('findings', [])

        self.card_time.set_value(scan_time)

        div = "─" * 56

        self.log(self.report_tab,
            "╔══════════════════════════════════════════════════════╗",
            "#1565c0")

        self.log(self.report_tab,
            "║          KAGURA  SECURITY  ASSESSMENT  REPORT        ║",
            "#1565c0")

        self.log(self.report_tab,
            "╚══════════════════════════════════════════════════════╝",
            "#1565c0")

        self.log(self.report_tab, "", "#111")

        self.log(self.report_tab,
            f"  Target            :  {domain}", "#111111")

        self.log(self.report_tab,
            f"  Subdomains Found  :  {subs}", "#1565c0")

        self.log(self.report_tab,
            f"  Assets Found      :  {assets}", "#2e7d32")

        self.log(self.report_tab,
            f"  Endpoints Found   :  "
            f"{meta.get('endpoint_count', 0)}", "#6a1b9a")

        self.log(self.report_tab,
            f"  Vulnerabilities   :  {vulns}", "#b71c1c")

        self.log(self.report_tab,
            f"  Scan Time         :  {scan_time}s", "#6a1b9a")

        self.log(self.report_tab, div, "#cccccc")

        crit = sum(1 for v in findings
                   if v.get('severity') == 'CRITICAL')

        high = sum(1 for v in findings
                   if v.get('severity') == 'HIGH')

        med  = sum(1 for v in findings
                   if v.get('severity') == 'MEDIUM')

        low  = sum(1 for v in findings
                   if v.get('severity') == 'LOW')

        self.log(self.report_tab,
            "  SEVERITY BREAKDOWN:", "#333333")

        self.log(self.report_tab,
            f"  🔴  CRITICAL  :  {crit}", "#b71c1c")

        self.log(self.report_tab,
            f"  🟠  HIGH      :  {high}", "#e65100")

        self.log(self.report_tab,
            f"  🟡  MEDIUM    :  {med}", "#f57f17")

        self.log(self.report_tab,
            f"  🔵  LOW       :  {low}", "#1565c0")

        self.log(self.report_tab, div, "#cccccc")

        if findings:
            self.log(self.report_tab,
                "  FINDINGS:", "#333333")

            for v in findings:
                sev   = v.get('severity', 'LOW')
                title = v.get('title', '')
                host  = v.get('host', '')
                cvss  = v.get('cvss', 'N/A')

                color = (
                    "#b71c1c" if sev == "CRITICAL" else
                    "#e65100" if sev == "HIGH" else
                    "#f57f17" if sev == "MEDIUM" else
                    "#1565c0"
                )

                self.log(self.report_tab,
                    f"  [{sev}]  CVSS:{cvss}  "
                    f"{host}  —  {title}", color)

        else:
            self.log(self.report_tab,
                "  No vulnerabilities detected.", "#888888")

        self.log(self.report_tab, div, "#cccccc")

        reports_dir = os.path.expanduser("~/KAGURA/reports/")

        files = sorted(glob.glob(
            f"{reports_dir}KAGURA_REPORT_{domain}_*.html"))

        if files:
            self.last_domain = domain

            self.log(self.report_tab,
                f"  Report saved:", "#555555")

            self.log(self.report_tab,
                f"  {files[-1]}", "#2e7d32")

            self.open_report_btn.setVisible(True)

        self.log(self.report_tab,
            "\n  ⚔  KAGURA Scan Complete.", "#1565c0")

        self.tabs.setCurrentIndex(3)

    def open_html_report(self):
        reports_dir = os.path.expanduser("~/KAGURA/reports/")

        files = sorted(glob.glob(
            f"{reports_dir}KAGURA_REPORT_"
            f"{self.last_domain}_*.html"))

        if files:
            os.system(f"xdg-open '{files[-1]}'")

    def clear_all(self):
        for box in [self.recon_tab, self.port_tab,
                    self.vuln_tab, self.endpoint_tab,
                    self.report_tab]:
            box.clear()

        self.progress.setValue(0)

        self.card_sub.set_value(0)
        self.card_port.set_value(0)
        self.card_vuln.set_value(0)

        self.card_ep.set_value(0)

        self.card_time.set_value(0)

        self.open_report_btn.setVisible(False)

        self.status.setText("⬤  READY")

        self.status.setStyleSheet(
            "color: #2e7d32; font-weight: bold; "
            "font-size: 13px; padding: 6px;")

    def start_scan(self):
        domain = self.target_input.text().strip()

        if not domain:
            self.update_status("Please enter a target domain.")
            return

        self.clear_all()

        self.scan_btn.setEnabled(False)

        self.last_domain = domain
        self.sub_count   = 0
        self.port_count  = 0
        self.vuln_count  = 0

        self.ep_count = 0

        thread = threading.Thread(
            target=self.scan_thread,
            args=(domain,),
            daemon=True
        )

        thread.start()

    def scan_thread(self, domain):

        def bus(event, data):

            if event == "recon":
                self.sub_count += 1
                BRIDGE.counter.emit("sub", self.sub_count)
                BRIDGE.recon.emit(f"  [+]  {data}")
                pct = min(30, self.sub_count * 2)
                BRIDGE.progress.emit(pct)

            elif event == "port":
                self.port_count += 1
                BRIDGE.counter.emit("port", self.port_count)
                BRIDGE.port.emit(f"  [PORT]  {data}")
                pct = min(60, 30 + self.port_count * 2)
                BRIDGE.progress.emit(pct)

            elif event == "vuln":
                self.vuln_count += 1
                BRIDGE.counter.emit("vuln", self.vuln_count)
                BRIDGE.vuln.emit(f"  [!]  {data}")
                pct = min(85, 60 + self.vuln_count * 2)
                BRIDGE.progress.emit(pct)

            elif event == "endpoint":
                self.ep_count += 1
                BRIDGE.counter.emit("ep", self.ep_count)
                BRIDGE.endpoint.emit(f"  [URL]  {data}")

            elif event == "status":
                BRIDGE.status.emit(data)

            elif event == "progress":
                BRIDGE.progress.emit(data)

            elif event == "error":
                BRIDGE.error.emit(data)

        BRIDGE.status.emit(f"Scanning {domain}...")

        result = run_scan(domain, event_bus=bus)

        meta = result.get("meta", {})
        meta["findings"] = result.get("vulnerabilities", [])

        BRIDGE.progress.emit(100)

        BRIDGE.report.emit(meta)

        BRIDGE.status.emit("Scan Complete  ✓")

        BRIDGE.counter.emit("vuln",
            meta.get("vuln_count", 0))

        self.scan_btn.setEnabled(True)

class Launcher:
    def __init__(self):
        self.app   = QApplication(sys.argv)
        self.intro = IntroScreen()
        self.intro.finished.connect(self.start_main)
        self.intro.show()

    def start_main(self):
        self.window = KaguraGUI()
        self.window.show()

    def run(self):
        sys.exit(self.app.exec())

if __name__ == "__main__":
    Launcher().run()
