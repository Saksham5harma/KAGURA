import sys, threading, os, glob, math

from PyQt6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QLabel, QPushButton, QTextEdit,
    QLineEdit, QVBoxLayout, QHBoxLayout, QTabWidget, QProgressBar, QFrame,
    QGraphicsOpacityEffect
)
from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, QTimer, QRectF, QPointF,
    QPropertyAnimation, QEasingCurve
)
from PyQt6.QtGui import (
    QColor, QTextCursor, QFont, QPainter, QPen, QBrush,
    QLinearGradient, QRadialGradient, QPainterPath
)

from widgets_viz import NetworkGraph, SeverityDonut

C = {
    "blue":   "#1565c0",
    "blue_d": "#0d47a1",
    "blue_l": "#42a5f5",
    "green":  "#2e7d32",
    "red":    "#b71c1c",
    "purple": "#6a1b9a",
    "orange": "#e65100",
    "gold":   "#f57f17",
    "bg":     "#ffffff",
    "panel":  "#f8f9fa",
    "border": "#d0d7de",
    "text":   "#222222",
    "text2":  "#555555",
}

class HeaderBar(QFrame):
    def __init__(self):
        super().__init__()
        self._sheen_x = -0.4
        self.setFixedHeight(64)
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(60)  

    def _tick(self):
        self._sheen_x += 0.010
        if self._sheen_x > 1.4:
            self._sheen_x = -0.4
        self.update()

    def paintEvent(self, _):
        W, H = self.width(), self.height()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        base = QLinearGradient(0, 0, W, 0)
        base.setColorAt(0, QColor("#0d1b2a"))
        base.setColorAt(1, QColor(C["blue"]))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(base))
        p.drawRoundedRect(0, 0, W, H, 10, 10)

        sx = self._sheen_x * W
        sheen = QLinearGradient(sx - 90, 0, sx + 90, 0)
        sheen.setColorAt(0.0, QColor(255, 255, 255, 0))
        sheen.setColorAt(0.5, QColor(255, 255, 255, 28))
        sheen.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setBrush(QBrush(sheen))
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, W, H), 10, 10)
        p.setClipPath(path)
        p.drawRect(0, 0, W, H)
        p.end()


class StreamBridge(QObject):
    recon    = pyqtSignal(str)
    port     = pyqtSignal(str)
    vuln     = pyqtSignal(str)
    endpoint = pyqtSignal(str)
    status   = pyqtSignal(str)
    progress = pyqtSignal(int)
    report   = pyqtSignal(dict)
    error    = pyqtSignal(str)
    counter  = pyqtSignal(str, int)

BRIDGE = StreamBridge()


class StatCard(QFrame):
    def __init__(self, label, color=C["blue"]):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: white;
                border: 2px solid {color};
                border-radius: 10px;
            }}
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(4)

        self.value_label = QLabel("0")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setStyleSheet(f"""
            color: {color};
            font-size: 30px;
            font-weight: bold;
            font-family: Consolas;
            background: transparent;
        """)

        self.title_label = QLabel(label)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("""
            color: #555555;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
            background: transparent;
        """)

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
        self.setLayout(layout)

    def set_value(self, val):
        self.value_label.setText(str(val))


class RootCanvas(QWidget):
    """Central widget that paints the KAGURA watermark as its own
    background — avoids z-order/resize-tracking issues of a separate
    overlay widget."""
    def __init__(self):
        super().__init__()

    def paintEvent(self, ev):
 
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        cx, cy = W * 0.5, H * 0.46
        scale = min(W, H) * 0.34

        col = QColor(C["blue"])
        col.setAlpha(42)  
        pen = QPen(col, max(4, scale * 0.05))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        for sign in (1, -1):
            p.save()
            p.translate(cx, cy)
            p.rotate(35 * sign)
            p.drawLine(QPointF(-scale, 0), QPointF(scale, 0))

            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(col))
            p.drawRect(int(scale * 0.40), int(-scale * 0.09), int(scale * 0.08), int(scale * 0.18))

            p.drawEllipse(QPointF(-scale * 0.96, 0), scale * 0.035, scale * 0.035)
            p.restore()
            p.setPen(pen)

        wm_col = QColor(C["text"])
        wm_col.setAlpha(26) 
        p.setPen(wm_col)
        f = QFont("Times New Roman", int(scale * 0.62))
        f.setBold(True)
        f.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 115)
        p.setFont(f)
        p.drawText(QRectF(0, cy + scale * 0.55, W, scale * 0.8),
                   Qt.AlignmentFlag.AlignHCenter, "KAGURA")
        p.end()
        super().paintEvent(ev)


class KaguraGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KAGURA  ⚔  Security Intelligence Platform")
        self.resize(1500, 900)
        self.setStyleSheet(f"background: {C['bg']};")
        self.sub_count = self.port_count = self.vuln_count = self.ep_count = 0
        self.last_domain = ""
        self.build_ui()
        self.connect_signals()

    def build_ui(self):
        root = RootCanvas()
        self.setCentralWidget(root)

        main = QVBoxLayout()
        main.setSpacing(12)
        main.setContentsMargins(18, 14, 18, 14)

        header = HeaderBar()
        hlay = QHBoxLayout()
        hlay.setContentsMargins(18, 0, 18, 0)
        brand = QLabel("⚔  KAGURA")
        brand.setStyleSheet("color: white; font-size: 28px; font-weight: bold; font-family: 'Times New Roman'; background: transparent;")
        tag = QLabel("FOR RED TEAMERS")
        tag.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        tag.setStyleSheet("color: #ffca28; font-size: 13px; font-weight: bold; letter-spacing: 3px; background: transparent;")
        hlay.addWidget(brand)
        hlay.addStretch()
        hlay.addWidget(tag)
        header.setLayout(hlay)
        main.addWidget(header)

        input_frame = QFrame()
        input_frame.setStyleSheet(f"""
            QFrame {{ background: {C['panel']}; border: 1px solid {C['border']}; border-radius: 10px; }}
        """)
        ilay = QHBoxLayout()
        ilay.setContentsMargins(14, 10, 14, 10)
        domain_label = QLabel("TARGET:")
        domain_label.setStyleSheet(f"color: {C['blue']}; font-weight: bold; font-size: 13px; background: transparent;")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target domain  (e.g. target.com)")
        self.target_input.setStyleSheet(f"""
            background: white; color: black; padding: 10px 14px;
            border-radius: 8px; border: 1px solid {C['border']}; font-size: 14px;
        """)
        self.target_input.returnPressed.connect(self.start_scan)

        self.scan_btn = QPushButton("⚔  START SCAN")
        self.scan_btn.setFixedWidth(160)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setStyleSheet(f"""
            QPushButton {{ background: {C['blue']}; color: white; padding: 10px;
                border-radius: 8px; font-weight: bold; font-size: 13px; }}
            QPushButton:hover {{ background: {C['blue_d']}; }}
            QPushButton:disabled {{ background: #aaaaaa; color: #eeeeee; }}
        """)
        self.scan_btn.clicked.connect(self.start_scan)

        self.clear_btn = QPushButton(" CLEAR")
        self.clear_btn.setFixedWidth(110)
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.setStyleSheet(f"""
            QPushButton {{ background: #f1f3f4; color: #555; padding: 10px;
                border-radius: 8px; border: 1px solid {C['border']}; font-weight: bold; }}
            QPushButton:hover {{ background: #e0e0e0; }}
        """)
        self.clear_btn.clicked.connect(self.clear_all)

        ilay.addWidget(domain_label)
        ilay.addWidget(self.target_input)
        ilay.addWidget(self.scan_btn)
        ilay.addWidget(self.clear_btn)
        input_frame.setLayout(ilay)
        main.addWidget(input_frame)

        # stat cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.card_sub  = StatCard("SUBDOMAINS",      C["blue"])
        self.card_port = StatCard("OPEN PORTS",      C["green"])
        self.card_vuln = StatCard("VULNERABILITIES", C["red"])
        self.card_ep   = StatCard("ENDPOINTS",       C["purple"])
        self.card_time = StatCard("SCAN TIME (s)",   C["purple"])
        for c in [self.card_sub, self.card_port, self.card_vuln, self.card_ep, self.card_time]:
            cards_row.addWidget(c)
        main.addLayout(cards_row)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFormat(" %p%  —  Scanning...")
        self.progress.setFixedHeight(28)
        self.progress.setStyleSheet(f"""
            QProgressBar {{ background: #f1f3f4; border: 1px solid {C['border']};
                border-radius: 8px; text-align: center; color: black; font-weight: bold; }}
            QProgressBar::chunk {{ background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0, stop:0 {C['blue']}, stop:1 {C['blue_l']});
                border-radius: 8px; }}
        """)
        main.addWidget(self.progress)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{ background: white; border: 1px solid {C['border']}; border-radius: 8px; }}
            QTabBar::tab {{ background: #f4f6f8; padding: 10px 24px; min-width: 140px;
                color: #333; border: 1px solid {C['border']}; border-bottom: none;
                border-radius: 6px 6px 0 0; font-weight: bold; font-size: 13px; }}
            QTabBar::tab:selected {{ background: {C['blue']}; color: white; }}
            QTabBar::tab:hover:!selected {{ background: #e3f2fd; }}
        """)
        self.recon_tab    = self.make_text_box()
        self.port_tab     = self.make_text_box()
        self.vuln_tab     = self.make_text_box()
        self.endpoint_tab = self.make_text_box()
        self.report_tab   = self.make_text_box()
        self.graph_tab    = self._make_graph_page()
        self.tabs.addTab(self.recon_tab,    " Recon")
        self.tabs.addTab(self.port_tab,     " Ports")
        self.tabs.addTab(self.vuln_tab,     " Vulnerabilities")
        self.tabs.addTab(self.endpoint_tab, " Endpoints")
        self.tabs.addTab(self.graph_tab,    " Graph")
        self.tabs.addTab(self.report_tab,   " Report")
        main.addWidget(self.tabs)

        status_row = QHBoxLayout()
        self.status = QLabel("⬤  READY")
        self.status.setStyleSheet(f"color: {C['green']}; font-weight: bold; font-size: 13px; padding: 6px; background: transparent;")
        self.open_report_btn = QPushButton("📂  Open HTML Report")
        self.open_report_btn.setVisible(False)
        self.open_report_btn.setStyleSheet(f"""
            QPushButton {{ background: #e8f5e9; color: {C['green']}; border: 1px solid {C['green']};
                padding: 6px 14px; border-radius: 6px; font-weight: bold; }}
            QPushButton:hover {{ background: #c8e6c9; }}
        """)
        self.open_report_btn.clicked.connect(self.open_html_report)
        status_row.addWidget(self.status)
        status_row.addStretch()
        status_row.addWidget(self.open_report_btn)
        main.addLayout(status_row)

        root.setLayout(main)

    def make_text_box(self):
        box = QTextEdit()
        box.setReadOnly(True)
        box.setFocusPolicy(Qt.FocusPolicy.NoFocus)  
        
        box.setStyleSheet("""
            background: #fafafa; color: #111111; border: none;
            font-family: Consolas, 'Courier New'; font-size: 13px; padding: 14px;
        """)
        return box

    def _make_graph_page(self):
        page = QWidget()
        page.setStyleSheet("background: #fafafa;")
        lay = QHBoxLayout()
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(20)

        graph_frame = QFrame()
        graph_frame.setStyleSheet(f"""
            QFrame {{ background: white; border: 1px solid {C['border']}; border-radius: 10px; }}
        """)
        gl = QVBoxLayout()
        gl.setContentsMargins(6, 6, 6, 6)
        self.network_graph = NetworkGraph()
        gl.addWidget(self.network_graph)
        graph_frame.setLayout(gl)

        right = QVBoxLayout()
        right.setSpacing(14)

        donut_frame = QFrame()
        donut_frame.setStyleSheet(f"""
            QFrame {{ background: white; border: 1px solid {C['border']}; border-radius: 10px; }}
        """)
        dl = QVBoxLayout()
        dtitle = QLabel("SEVERITY DISTRIBUTION")
        dtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dtitle.setStyleSheet(f"color: {C['text2']}; font-size: 10px; font-weight: bold; letter-spacing: 1px; background: transparent;")
        self.severity_donut = SeverityDonut(track_color="#EDEFF2", text_color=C["text"])
        dl.addWidget(dtitle)
        dl.addWidget(self.severity_donut)
        donut_frame.setLayout(dl)

        legend_frame = QFrame()
        legend_frame.setStyleSheet(f"""
            QFrame {{ background: white; border: 1px solid {C['border']}; border-radius: 10px; }}
        """)
        ll = QVBoxLayout()
        ll.setSpacing(8)
        for label, col in [("Subdomain", C["blue"]), ("Open Port", C["green"]),
                            ("Vulnerability", C["red"]), ("Endpoint", C["purple"])]:
            row = QHBoxLayout()
            dot = QLabel()
            dot.setFixedSize(10, 10)
            dot.setStyleSheet(f"background: {col}; border-radius: 5px;")
            txt = QLabel(label)
            txt.setStyleSheet(f"color: {C['text']}; font-size: 12px; font-weight: 600; background: transparent;")
            row.addWidget(dot)
            row.addWidget(txt)
            row.addStretch()
            ll.addLayout(row)
        legend_frame.setLayout(ll)

        right.addWidget(donut_frame)
        right.addWidget(legend_frame)
        right.addStretch()

        right_wrap = QWidget()
        right_wrap.setLayout(right)
        right_wrap.setFixedWidth(220)

        lay.addWidget(graph_frame, stretch=2)
        lay.addWidget(right_wrap)
        page.setLayout(lay)
        return page

    def connect_signals(self):
        BRIDGE.recon.connect(lambda x: self.log(self.recon_tab, x, "#1a237e"))
        BRIDGE.port.connect(lambda x: self.log(self.port_tab, x, "#1b5e20"))
        BRIDGE.vuln.connect(lambda x: self.log(self.vuln_tab, x, "#b71c1c"))
        BRIDGE.endpoint.connect(lambda x: self.log(self.endpoint_tab, x, "#6a1b9a"))
        BRIDGE.status.connect(self.update_status)
        BRIDGE.progress.connect(self.progress.setValue)
        BRIDGE.report.connect(self.render_report)

        BRIDGE.recon.connect(lambda x: self._graph_add(x, "sub"))
        BRIDGE.port.connect(lambda x: self._graph_add(x, "port"))
        BRIDGE.vuln.connect(lambda x: self._graph_add(x, "vuln"))
        BRIDGE.endpoint.connect(lambda x: self._graph_add(x, "endpoint"))
        BRIDGE.counter.connect(self.update_counter)

    def log(self, widget, text, color="#111111"):
        widget.setTextColor(QColor(color))
        widget.append(text)
        widget.moveCursor(QTextCursor.MoveOperation.End)

    GRAPH_NODE_CAP = 60

    def _graph_add(self, text, kind):
        if len(self.network_graph.nodes) >= self.GRAPH_NODE_CAP:
            return
        self.network_graph.add_node(text[:18], kind)

    def update_status(self, text):
        self.status.setText(f"⬤  {text}")
        if "error" in text.lower():
            col = C["red"]
        elif "complete" in text.lower():
            col = C["green"]
        else:
            col = C["blue"]
        self.status.setStyleSheet(f"color: {col}; font-weight: bold; font-size: 13px; padding: 6px; background: transparent;")

    def update_counter(self, kind, val):
        m = {"sub": self.card_sub, "port": self.card_port, "vuln": self.card_vuln, "ep": self.card_ep}
        if kind in m:
            m[kind].set_value(val)

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
        self.log(self.report_tab, "╔══════════════════════════════════════════════════════╗", C["blue"])
        self.log(self.report_tab, "║          KAGURA  SECURITY  ASSESSMENT  REPORT        ║", C["blue"])
        self.log(self.report_tab, "╚══════════════════════════════════════════════════════╝", C["blue"])
        self.log(self.report_tab, "", "#111")
        self.log(self.report_tab, f"  Target            :  {domain}", "#111111")
        self.log(self.report_tab, f"  Subdomains Found  :  {subs}", C["blue"])
        self.log(self.report_tab, f"  Assets Found      :  {assets}", C["green"])
        self.log(self.report_tab, f"  Endpoints Found   :  {meta.get('endpoint_count', 0)}", C["purple"])
        self.log(self.report_tab, f"  Vulnerabilities   :  {vulns}", C["red"])
        self.log(self.report_tab, f"  Scan Time         :  {scan_time}s", C["purple"])
        self.log(self.report_tab, div, "#cccccc")

        crit = sum(1 for v in findings if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in findings if v.get('severity') == 'HIGH')
        med  = sum(1 for v in findings if v.get('severity') == 'MEDIUM')
        low  = sum(1 for v in findings if v.get('severity') == 'LOW')
        self.severity_donut.set_values(crit, high, med, low)
        self.log(self.report_tab, "  SEVERITY BREAKDOWN:", "#333333")
        self.log(self.report_tab, f"  🔴  CRITICAL  :  {crit}", C["red"])
        self.log(self.report_tab, f"  🟠  HIGH      :  {high}", C["orange"])
        self.log(self.report_tab, f"  🟡  MEDIUM    :  {med}", C["gold"])
        self.log(self.report_tab, f"  🔵  LOW       :  {low}", C["blue"])
        self.log(self.report_tab, div, "#cccccc")

        if findings:
            self.log(self.report_tab, "  FINDINGS:", "#333333")
            for v in findings:
                sev   = v.get('severity', 'LOW')
                title = v.get('title', '')
                host  = v.get('host', '')
                cvss  = v.get('cvss', 'N/A')
                color = (C["red"] if sev == "CRITICAL" else
                         C["orange"] if sev == "HIGH" else
                         C["gold"] if sev == "MEDIUM" else C["blue"])
                self.log(self.report_tab, f"  [{sev}]  CVSS:{cvss}  {host}  —  {title}", color)
        else:
            self.log(self.report_tab, "  No vulnerabilities detected.", "#888888")

        self.log(self.report_tab, div, "#cccccc")
        reports_dir = os.path.expanduser("~/KAGURA/reports/")
        files = sorted(glob.glob(f"{reports_dir}KAGURA_REPORT_{domain}_*.html"))
        if files:
            self.last_domain = domain
            self.log(self.report_tab, f"  Report saved:", "#555555")
            self.log(self.report_tab, f"  {files[-1]}", C["green"])
            self.open_report_btn.setVisible(True)

        self.log(self.report_tab, "\n  ⚔  KAGURA Scan Complete.", C["blue"])
        self.tabs.setCurrentIndex(5)

    def open_html_report(self):
        reports_dir = os.path.expanduser("~/KAGURA/reports/")
        files = sorted(glob.glob(f"{reports_dir}KAGURA_REPORT_{self.last_domain}_*.html"))
        if files:
            os.system(f"xdg-open '{files[-1]}'")

    def clear_all(self):
        for box in [self.recon_tab, self.port_tab, self.vuln_tab, self.endpoint_tab, self.report_tab]:
            box.clear()
        self.progress.setValue(0)
        for c in [self.card_sub, self.card_port, self.card_vuln, self.card_ep, self.card_time]:
            c.set_value(0)
        self.network_graph.clear_nodes()
        self.severity_donut.set_values(0, 0, 0, 0)
        self.open_report_btn.setVisible(False)
        self.status.setText("⬤  READY")
        self.status.setStyleSheet(f"color: {C['green']}; font-weight: bold; font-size: 13px; padding: 6px; background: transparent;")

    def start_scan(self):
        domain = self.target_input.text().strip()
        if not domain:
            self.update_status("Please enter a target domain.")
            return
        self.clear_all()
        self.scan_btn.setEnabled(False)
        self.last_domain = domain
        self.sub_count = self.port_count = self.vuln_count = self.ep_count = 0
        threading.Thread(target=self.scan_thread, args=(domain,), daemon=True).start()

    def scan_thread(self, domain):
        def bus(event, data):
            if event == "recon":
                self.sub_count += 1
                BRIDGE.counter.emit("sub", self.sub_count)
                BRIDGE.recon.emit(f"  [+]  {data}")
                BRIDGE.progress.emit(min(30, self.sub_count * 2))
            elif event == "port":
                self.port_count += 1
                BRIDGE.counter.emit("port", self.port_count)
                BRIDGE.port.emit(f"  [PORT]  {data}")
                BRIDGE.progress.emit(min(60, 30 + self.port_count * 2))
            elif event == "vuln":
                self.vuln_count += 1
                BRIDGE.counter.emit("vuln", self.vuln_count)
                BRIDGE.vuln.emit(f"  [!]  {data}")
                BRIDGE.progress.emit(min(85, 60 + self.vuln_count * 2))
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
        try:
            from engine import run_scan
            result = run_scan(domain, event_bus=bus)
        except ImportError:
            result = {"meta": {"target": domain, "subdomain_count": 0, "asset_count": 0,
                               "vuln_count": 0, "scan_time": 0, "endpoint_count": 0},
                      "vulnerabilities": []}
        meta = result.get("meta", {})
        meta["findings"] = result.get("vulnerabilities", [])
        BRIDGE.progress.emit(100)
        BRIDGE.report.emit(meta)
        BRIDGE.status.emit("Scan Complete  ✓")
        BRIDGE.counter.emit("vuln", meta.get("vuln_count", 0))
        self.scan_btn.setEnabled(True)


from intro_screen_light import IntroScreen


class Launcher:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setStyle("Fusion")  
        self.intro = IntroScreen()
        self.intro.finished.connect(self._start_main)
        self.intro.show()

    def _start_main(self):
        self.window = KaguraGUI()
        self.window.show()

    def run(self):
        sys.exit(self.app.exec())


if __name__ == "__main__":
    Launcher().run()
