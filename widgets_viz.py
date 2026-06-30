import math
import random
from collections import deque

from PyQt6.QtWidgets import QWidget, QSizePolicy
from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont,
    QLinearGradient, QRadialGradient, QPainterPath
)
C = {
    "bg":       "#06080A",
    "bg2":      "#0C0F12",
    "panel":    "#0E1215",
    "border":   "#2A0A0A",
    "borderac": "#8B0000",
    "accent":   "#E8002A",
    "accent2":  "#AA0020",
    "green":    "#00FF88",
    "cyan":     "#00C8FF",
    "purple":   "#CC44FF",
    "gold":     "#FFB800",
    "text":     "#D0C8C0",
    "text2":    "#6A5A52",
    "crit":     "#FF0033",
    "high":     "#FF5500",
    "med":      "#FFAA00",
    "low":      "#0088FF",
}

class Icon(QWidget):
    """
    Hand-painted vector icon. Avoids relying on system font glyph
    coverage for symbols (many Linux minimal installs lack them).
    kind: 'sword' | 'target' | 'port' | 'warn' | 'hex' | 'graph' |
          'doc' | 'clock' | 'refresh' | 'logo'
    """
    def __init__(self, kind, color="#E8002A", size=16):
        super().__init__()
        self.kind = kind
        self.color = QColor(color)
        self._size = size
        self.setFixedSize(size, size)

    def set_color(self, color):
        self.color = QColor(color)
        self.update()

    def paintEvent(self, _):
        s = self._size
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self.color, max(1.2, s * 0.09))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        m = s * 0.18  

        if self.kind == "sword":
            p.drawLine(QPointF(m, s - m), QPointF(s - m, m))
            p.setBrush(QBrush(self.color))
            p.setPen(Qt.PenStyle.NoPen)

            p.save()
            p.translate(s * 0.62, s * 0.38)
            p.rotate(-45)
            p.drawRect(int(-s*0.16), int(-s*0.05), int(s*0.32), int(s*0.1))
            p.restore()
            p.setPen(pen)
            p.drawLine(QPointF(m, s - m), QPointF(m + s*0.18, s - m - s*0.18))

        elif self.kind == "target_dot":
            c = s / 2
            p.drawEllipse(QPointF(c, c), s*0.38, s*0.38)
            p.drawEllipse(QPointF(c, c), s*0.18, s*0.18)
            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(c, c), s*0.07, s*0.07)

        elif self.kind == "port":
            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            r = s * 0.16
            p.drawEllipse(QPointF(s*0.3, s*0.3), r, r)
            p.drawEllipse(QPointF(s*0.7, s*0.3), r, r)
            p.drawEllipse(QPointF(s*0.3, s*0.7), r, r)
            p.drawEllipse(QPointF(s*0.7, s*0.7), r, r)

        elif self.kind == "warn":
            tri = QPainterPath()
            tri.moveTo(s*0.5, s*0.15)
            tri.lineTo(s*0.88, s*0.85)
            tri.lineTo(s*0.12, s*0.85)
            tri.closeSubpath()
            p.drawPath(tri)
            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            p.drawRect(int(s*0.47), int(s*0.42), int(s*0.06), int(s*0.2))
            p.drawEllipse(QPointF(s*0.5, s*0.72), s*0.035, s*0.035)

        elif self.kind == "hex":
            path = QPainterPath()
            cx, cy, r = s/2, s/2, s*0.4
            for i in range(6):
                ang = math.pi/6 + i * math.pi/3
                pt = QPointF(cx + r*math.cos(ang), cy + r*math.sin(ang))
                if i == 0: path.moveTo(pt)
                else: path.lineTo(pt)
            path.closeSubpath()
            p.drawPath(path)

        elif self.kind == "graph":
            cx, cy = s*0.5, s*0.5
            sat = [(s*0.5, s*0.14), (s*0.86, s*0.5), (s*0.5, s*0.86), (s*0.14, s*0.5)]
            p.setPen(pen)
            for (ex, ey) in sat:
                p.drawLine(QPointF(cx, cy), QPointF(ex, ey))
            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(cx, cy), s*0.1, s*0.1)
            for (ex, ey) in sat:
                p.drawEllipse(QPointF(ex, ey), s*0.075, s*0.075)

        elif self.kind == "doc":
            p.drawRoundedRect(int(s*0.22), int(s*0.12), int(s*0.56), int(s*0.76), 2, 2)
            for yy in (0.34, 0.5, 0.66):
                p.drawLine(QPointF(s*0.32, s*yy), QPointF(s*0.68, s*yy))

        elif self.kind == "clock":
            c = s/2
            p.drawEllipse(QPointF(c, c), s*0.38, s*0.38)
            p.drawLine(QPointF(c, c), QPointF(c, s*0.28))
            p.drawLine(QPointF(c, c), QPointF(s*0.65, c))

        elif self.kind == "refresh":
            rect = QRectF(s*0.15, s*0.15, s*0.7, s*0.7)
            p.drawArc(rect, 30*16, 280*16)
            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            ang = math.radians(30)
            ax, ay = s/2 + math.cos(ang)*s*0.35, s/2 - math.sin(ang)*s*0.35
            path = QPainterPath()
            path.moveTo(ax, ay - s*0.08)
            path.lineTo(ax + s*0.12, ay)
            path.lineTo(ax, ay + s*0.08)
            path.closeSubpath()
            p.drawPath(path)

        elif self.kind == "logo":

            p.setBrush(QBrush(self.color)); p.setPen(Qt.PenStyle.NoPen)
            diamond = QPainterPath()
            diamond.moveTo(s*0.5, s*0.08)
            diamond.lineTo(s*0.74, s*0.5)
            diamond.lineTo(s*0.5, s*0.92)
            diamond.lineTo(s*0.26, s*0.5)
            diamond.closeSubpath()
            p.drawPath(diamond)

            p.setBrush(QBrush(QColor(self.color).darker(180)))
            inner = QPainterPath()
            inner.moveTo(s*0.5, s*0.08)
            inner.lineTo(s*0.58, s*0.5)
            inner.lineTo(s*0.5, s*0.92)
            inner.lineTo(s*0.42, s*0.5)
            inner.closeSubpath()
            p.drawPath(inner)

        p.end()

class Sparkline(QWidget):
    def __init__(self, color=C["accent"], maxlen=40):
        super().__init__()
        self._color = color
        self._data = deque([0] * maxlen, maxlen=maxlen)
        self.setFixedHeight(28)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)

    def push(self, value):
        self._data.append(value)
        self.update()

    def paintEvent(self, _):
        W, H = self.width(), self.height()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        data = list(self._data)
        mx = max(data) if max(data) > 0 else 1
        n = len(data)
        if n < 2:
            p.end(); return

        step = W / (n - 1)
        pts = []
        for i, v in enumerate(data):
            x = i * step
            y = H - 4 - (v / mx) * (H - 8)
            pts.append(QPointF(x, y))

        path = QPainterPath()
        path.moveTo(pts[0].x(), H)
        for pt in pts:
            path.lineTo(pt)
        path.lineTo(pts[-1].x(), H)
        path.closeSubpath()

        grad = QLinearGradient(0, 0, 0, H)
        c0 = QColor(self._color); c0.setAlpha(110)
        c1 = QColor(self._color); c1.setAlpha(0)
        grad.setColorAt(0, c0); grad.setColorAt(1, c1)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad))
        p.drawPath(path)

        p.setPen(QPen(QColor(self._color), 1.6))
        for i in range(n - 1):
            p.drawLine(pts[i], pts[i + 1])

        p.setBrush(QBrush(QColor(self._color)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(pts[-1], 2.2, 2.2)
        p.end()

class SeverityDonut(QWidget):
    def __init__(self, track_color=None, text_color=None):
        super().__init__()
        self.setMinimumSize(140, 140)
        self._vals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._anim = 0.0
        self._target = 0.0

        self._track_color = track_color or C["bg2"]
        self._text_color = text_color or C["text"]
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def set_values(self, crit, high, med, low):
        self._vals = {"CRITICAL": crit, "HIGH": high,
                       "MEDIUM": med, "LOW": low}
        self._target = 1.0
        if not self._timer.isActive():
            self._timer.start(20)  
        self.update()

    def _tick(self):
        if self._anim < self._target:
            self._anim = min(self._target, self._anim + 0.08)
            self.update()
        else:
            self._timer.stop() 

    def paintEvent(self, _):
        W, H = self.width(), self.height()
        side = min(W, H) - 20
        cx, cy = W / 2, H / 2
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        total = sum(self._vals.values())
        rect = QRectF(cx - side/2, cy - side/2, side, side)
        thickness = side * 0.16

        pen = QPen(QColor(self._track_color), thickness)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        p.setPen(pen)
        p.drawArc(rect.adjusted(thickness/2, thickness/2,
                                 -thickness/2, -thickness/2),
                  0, 360 * 16)

        if total > 0:
            colors = {"CRITICAL": C["crit"], "HIGH": C["high"],
                      "MEDIUM": C["med"], "LOW": C["low"]}
            start = 90 * 16
            for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                v = self._vals[k]
                if v <= 0: continue
                span = -int(360 * 16 * (v / total) * self._anim)
                pen = QPen(QColor(colors[k]), thickness)
                pen.setCapStyle(Qt.PenCapStyle.FlatCap)
                p.setPen(pen)
                p.drawArc(rect.adjusted(thickness/2, thickness/2,
                                         -thickness/2, -thickness/2),
                          start, span)
                start += span

        p.setPen(QColor(self._text_color))
        p.setFont(QFont("Consolas", int(side * 0.18), QFont.Weight.Bold))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(total))
        p.end()

class NetworkNode:
    __slots__ = ("label", "kind", "angle", "dist", "x", "y",
                 "pulse", "target_dist")

    def __init__(self, label, kind, angle, dist):
        self.label = label
        self.kind = kind         
        self.angle = angle
        self.dist = 0.0
        self.target_dist = dist
        self.x = 0.0
        self.y = 0.0
        self.pulse = random.uniform(0, math.pi * 2)


class NetworkGraph(QWidget):
    KIND_COLOR = {
        "sub": C["cyan"], "port": C["green"],
        "vuln": C["accent"], "endpoint": C["purple"],
    }

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(260)
        self.nodes = []
        self._rot = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)  

    def add_node(self, label, kind):
        n = len(self.nodes)
        angle = (n * 47) % 360 * math.pi / 180.0  
        dist = random.uniform(0.55, 0.95)
        node = NetworkNode(label, kind, angle, dist)
        self.nodes.append(node)
        if not self._timer.isActive():
            self._timer.start(50)
        self.update()

    def clear_nodes(self):
        self.nodes = []
        self.update()

    def _tick(self):
        if not self.nodes:
            return  
        self._rot += 0.004
        moved = False
        for n in self.nodes:
            if n.dist < n.target_dist:
                n.dist = min(n.target_dist, n.dist + 0.05)
                moved = True
            n.pulse += 0.05

        self.update()

    def paintEvent(self, _):
        W, H = self.width(), self.height()
        cx, cy = W / 2, H / 2
        R = min(W, H) / 2 - 24
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        p.setPen(QPen(QColor(C["border"]), 1))
        for frac in (0.35, 0.65, 1.0):
            r = R * frac
            p.drawEllipse(QRectF(cx - r, cy - r, r * 2, r * 2))

        for n in self.nodes:
            ang = n.angle + self._rot
            x = cx + math.cos(ang) * R * n.dist
            y = cy + math.sin(ang) * R * n.dist
            n.x, n.y = x, y
            col = QColor(self.KIND_COLOR.get(n.kind, C["text2"]))
            col.setAlpha(70)
            p.setPen(QPen(col, 1))
            p.drawLine(QPointF(cx, cy), QPointF(x, y))

        pulse = 4 * math.sin(self._rot * 40)
        glow = QRadialGradient(cx, cy, 26 + pulse)
        gc = QColor(C["accent"]); gc.setAlpha(120)
        gc_edge = QColor(C["accent"]); gc_edge.setAlpha(0)
        glow.setColorAt(0, gc)
        glow.setColorAt(1, gc_edge)
        p.setBrush(QBrush(glow))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(cx, cy), 26 + pulse, 26 + pulse)

        p.setBrush(QBrush(QColor(C["accent"])))
        p.setPen(QPen(QColor("#FFFFFF"), 1.4))
        p.drawEllipse(QPointF(cx, cy), 9, 9)

        for n in self.nodes:
            col = QColor(self.KIND_COLOR.get(n.kind, C["text2"]))
            r = 4.5 + 0.8 * math.sin(n.pulse)
            glow2 = QRadialGradient(n.x, n.y, r * 3)
            gc2 = QColor(col); gc2.setAlpha(90)
            glow2.setColorAt(0, gc2)
            glow2.setColorAt(1, QColor(col.red(), col.green(), col.blue(), 0))
            p.setBrush(QBrush(glow2))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(n.x, n.y), r * 3, r * 3)

            p.setBrush(QBrush(col))
            p.setPen(QPen(QColor("#000000"), 1))
            p.drawEllipse(QPointF(n.x, n.y), r, r)

        p.end()
