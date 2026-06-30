import math
import random

from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QRectF, QPointF
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont,
    QLinearGradient, QRadialGradient, QFontMetrics
)

RED  = "#B71C1C"
GOLD = "#B8860B"
INK  = "#1A1A1A"
GREY = "#9A9A9A"


class Wisp:
    """A single soft smoke wisp — rises slowly, very low opacity,
    grey-red tinted so it reads as 'atmosphere' not 'background noise'."""
    def __init__(self, w, h):
        self.w, self.h = w, h
        self._spawn()

    def _spawn(self):
        self.x = random.uniform(0, self.w)
        self.y = random.uniform(self.h * 0.6, self.h * 1.05)
        self.vx = random.uniform(-0.15, 0.15)
        self.vy = random.uniform(-0.35, -0.7)
        self.r = random.uniform(20, 60)
        self.a = random.uniform(0.015, 0.045)
        self.da = random.uniform(0.0003, 0.0009)

    def step(self):
        self.x += self.vx
        self.y += self.vy
        self.r += 0.08
        self.a -= self.da
        if self.a <= 0 or self.y < -self.r * 2:
            self._spawn()


class IntroScreen(QWidget):
    finished = pyqtSignal()

    # timeline (ms)
    T_SLASH_START   = 250
    T_SLASH_END     = 850
    T_KATANA_START  = 350
    T_TYPE_START    = 950
    T_UNDERLINE     = 1750
    T_SUBTITLE      = 2050
    T_VERSION       = 2350
    T_DONE          = 3900

    def __init__(self):
        super().__init__()
        W, H = 1200, 700
        self.setFixedSize(W, H)
        self.setWindowTitle("KAGURA")
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)

        self._elapsed = 0
        self.wisps = [Wisp(W, H) for _ in range(26)]

        self.frames = ["⚔", "⚔  ⚔", "⚔  ⚔  ⚔", "⚔  ⚔  ⚔  ⚔"]
        self.frame_idx = 0
        self.title_text = "KAGURA"
        self.title_idx = 0

        self._pt = QTimer(self); self._pt.timeout.connect(self._tick); self._pt.start(16)
        self._wt = QTimer(self); self._wt.timeout.connect(self._tick_wisps); self._wt.start(40)

    def _tick(self):
        self._elapsed += 16
        e = self._elapsed

        if e >= self.T_KATANA_START:
            target_frame = min(len(self.frames) - 1,
                                (e - self.T_KATANA_START) // 130)
            if target_frame != self.frame_idx:
                self.frame_idx = target_frame

        if e >= self.T_TYPE_START:
            target_idx = min(len(self.title_text),
                              (e - self.T_TYPE_START) // 95)
            if target_idx != self.title_idx:
                self.title_idx = target_idx

        if e >= self.T_DONE:
            self._pt.stop()
            self._wt.stop()
            self.finished.emit()
            self.close()
            return

        self.update()

    def _tick_wisps(self):
        for w in self.wisps:
            w.step()

    def paintEvent(self, _):
        W, H = self.width(), self.height()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        e = self._elapsed

        p.fillRect(0, 0, W, H, QColor("#ffffff"))

        for w in self.wisps:
            if w.a <= 0:
                continue
            rad = QRadialGradient(w.x, w.y, w.r)
            c0 = QColor(180, 40, 40); c0.setAlphaF(w.a)
            c1 = QColor(180, 40, 40); c1.setAlphaF(0)
            rad.setColorAt(0, c0)
            rad.setColorAt(1, c1)
            p.setBrush(QBrush(rad))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QRectF(w.x - w.r, w.y - w.r, w.r * 2, w.r * 2))

        cx = W / 2

        if e >= self.T_KATANA_START:
            frame_text = self.frames[self.frame_idx]
            fk = QFont("Arial", 32)
            p.setFont(fk)
            p.setPen(QColor(RED))
            p.drawText(QRectF(0, H * 0.28, W, 60),
                       Qt.AlignmentFlag.AlignHCenter, frame_text)

        if self.title_idx > 0:
            visible = self.title_text[:self.title_idx]
            ft = QFont("Times New Roman", 76)
            ft.setBold(True)
            p.setFont(ft)
            p.setPen(QColor(INK))
            title_rect = QRectF(0, H * 0.36, W, 110)
            p.drawText(title_rect, Qt.AlignmentFlag.AlignHCenter, visible)

            if self.title_idx < len(self.title_text):
                blink = (e // 220) % 2 == 0
                if blink:
                    fm = QFontMetrics(ft)
                    tw = fm.horizontalAdvance(visible)
                    cx2 = (W + tw) // 2 + 6
                    cy2 = int(H * 0.36 + 18)
                    p.setPen(QPen(QColor(RED), 3))
                    p.drawLine(cx2, cy2, cx2, cy2 + fm.height() - 30)

        if e >= self.T_UNDERLINE:
            prog = min(1.0, (e - self.T_UNDERLINE) / 380.0)
            prog = 1 - (1 - prog) ** 3  
            uw = 180 * prog
            uy = H * 0.36 + 92
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(RED)))
            p.drawRect(QRectF(cx - uw / 2, uy, uw, 2.4))

        if e >= self.T_SUBTITLE:
            a = min(1.0, (e - self.T_SUBTITLE) / 420.0)
            fs = QFont("Segoe UI", 16)
            fs.setBold(True)
            fs.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 5)
            p.setFont(fs)
            c = QColor(GOLD); c.setAlphaF(a)
            p.setPen(c)
            p.drawText(QRectF(0, H * 0.36 + 112, W, 36),
                       Qt.AlignmentFlag.AlignHCenter, "FOR RED TEAMERS")

        if e >= self.T_VERSION:
            a = min(1.0, (e - self.T_VERSION) / 380.0)
            fv = QFont("Consolas", 11)
            p.setFont(fv)
            c = QColor(GREY); c.setAlphaF(a)
            p.setPen(c)
            p.drawText(QRectF(0, H * 0.36 + 152, W, 28),
                       Qt.AlignmentFlag.AlignHCenter,
                       "Offensive Security Intelligence Framework   v1.0")

        if self.T_SLASH_START <= e <= self.T_SLASH_END:
            prog = (e - self.T_SLASH_START) / (self.T_SLASH_END - self.T_SLASH_START)
            prog = prog * prog * (3 - 2 * prog)  
            sx = -250 + prog * (W + 500)
            sw = 130
            sg = QLinearGradient(sx - sw, 0, sx + sw, 0)
            sg.setColorAt(0.0,  QColor(211, 47, 47, 0))
            sg.setColorAt(0.45, QColor(211, 47, 47, 18))
            sg.setColorAt(0.5,  QColor(120, 10, 10, 70))
            sg.setColorAt(0.55, QColor(211, 47, 47, 18))
            sg.setColorAt(1.0,  QColor(211, 47, 47, 0))
            p.fillRect(0, 0, W, H, sg)

            core = QPen(QColor(255, 255, 255, int(140 * (1 - abs(prog - 0.5) * 2))), 2)
            p.setPen(core)
            p.drawLine(int(sx), 0, int(sx), H)

        p.end()
