import ctypes
import json
import math
import os
import random
import sys
import threading
import time
from ctypes import wintypes

if sys.platform != "win32":
    raise SystemExit("仅支持 Windows")

import psutil
from PySide6.QtCore import (
    QEasingCurve,
    QFileInfo,
    QPoint,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontMetrics,
    QIcon,
    QLinearGradient,
    QMovie,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileIconProvider,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSlider,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi")
advapi32 = ctypes.WinDLL("advapi32")
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_QUOTA = 0x0100
ERROR_ALREADY_EXISTS = 183

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "AccelBall"
WINDOW_SIZE = 150


def _enable_debug_privilege():
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        kernel32.CloseHandle(token)
        return
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    kernel32.CloseHandle(token)


def release_memory():
    _enable_debug_privilege()
    self_pid = os.getpid()
    for pid in psutil.pids():
        if pid == 0 or pid == self_pid:
            continue
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, False, pid
        )
        if handle:
            psapi.EmptyWorkingSet(handle)
            kernel32.CloseHandle(handle)


def acquire_single_instance():
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, "Global\\AccelBall_SingleInstance")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        return None
    return handle


BLOCKLIST = {
    "system",
    "registry",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "winlogon.exe",
    "explorer.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "runtimebroker.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "textinputhost.exe",
    "applicationframehost.exe",
    "securityhealthsystray.exe",
    "conhost.exe",
    "python.exe",
    "pythonw.exe",
}


def _windowed_pids():
    pids = set()
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _callback(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        if user32.GetWindowTextLengthW(hwnd) == 0:
            return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value:
            pids.add(pid.value)
        return True

    user32.EnumWindows(callback_type(_callback), 0)
    return pids


def list_user_programs():
    self_pid = os.getpid()
    aggregated = {}
    for pid in _windowed_pids():
        if pid == self_pid:
            continue
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            if name.lower() in BLOCKLIST:
                continue
            memory = proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        try:
            exe = proc.exe()
        except Exception:
            exe = ""
        if name not in aggregated:
            aggregated[name] = [0, [], exe]
        aggregated[name][0] += memory
        aggregated[name][1].append(pid)
    items = [(name, data[0], data[1], data[2]) for name, data in aggregated.items()]
    items.sort(key=lambda item: item[1], reverse=True)
    return items


def close_processes(pids):
    self_pid = os.getpid()
    procs = []
    for pid in pids:
        if pid == self_pid:
            continue
        try:
            procs.append(psutil.Process(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    for proc in procs:
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if procs:
        _, alive = psutil.wait_procs(procs, timeout=1.5)
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


def _autostart_command():
    if FROZEN:
        return f'"{sys.executable}"'
    exe = sys.executable
    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pythonw):
        exe = pythonw
    return f'"{exe}" "{os.path.abspath(__file__)}"'


def is_autostart_enabled():
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def set_autostart(enabled):
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _autostart_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


APP_DIR = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, "frozen", False)
if FROZEN:
    APP_DIR = os.path.dirname(sys.executable)
BUNDLE_DIR = getattr(sys, "_MEIPASS", APP_DIR)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
ASSETS_DIR = os.path.join(BUNDLE_DIR, "assets")
NORMAL_GIF = os.path.join(ASSETS_DIR, "normal.gif")
WORK_GIF = os.path.join(ASSETS_DIR, "work.gif")
HOVER_GIFS = [os.path.join(ASSETS_DIR, f"hover_{i}.gif") for i in range(1, 9)]
DEFAULT_CONFIG = {
    "size": WINDOW_SIZE,
    "topmost": True,
    "edge_hide": True,
    "anim_seconds": 5,
}
MIN_SIZE = 90
MAX_SIZE = 220
MIN_ANIM = 1
MAX_ANIM = 30
DOCK_HANDLE = 10
DOCK_THRESHOLD = 22


def load_config():
    config = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for key in DEFAULT_CONFIG:
            if key in data:
                config[key] = data[key]
    except (OSError, ValueError):
        pass
    config["size"] = max(MIN_SIZE, min(MAX_SIZE, int(config.get("size", WINDOW_SIZE))))
    config["anim_seconds"] = max(
        MIN_ANIM, min(MAX_ANIM, int(config.get("anim_seconds", 5)))
    )
    return config


def save_config(config):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
    except OSError:
        pass


PANEL_STYLE = """
QFrame#card {
    background-color: #141b24;
    border: 1px solid #273343;
    border-radius: 16px;
}
QLabel#title { color: #eaf1f8; font-size: 15px; font-weight: 600; }
QLabel#hint { color: #7f8ea3; font-size: 12px; }
QPushButton#close {
    color: #8894a3; background: transparent; border: none; font-size: 14px;
}
QPushButton#close:hover { color: #ffffff; background: #232e3c; border-radius: 13px; }
QScrollArea#scroll { background: transparent; border: none; }
QScrollArea#scroll > QWidget > QWidget { background: transparent; }
QCheckBox { color: #dbe4ee; font-size: 13px; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px; border-radius: 9px;
    border: 1px solid #3a475a; background: #1b2431;
}
QCheckBox::indicator:checked { background: #22c3e6; border: 1px solid #22c3e6; }
QLabel#mem { color: #8894a3; font-size: 12px; }
QPushButton#ghost {
    color: #c6d2df; background: #1c2632; border: 1px solid #2b3848;
    border-radius: 8px; padding: 6px 14px;
}
QPushButton#ghost:hover { background: #243141; }
QPushButton#primary {
    color: #08131a; background: #22c3e6; border: none; border-radius: 9px;
    padding: 8px 20px; font-weight: 600;
}
QPushButton#primary:hover { background: #3ad0ef; }
QPushButton#primary:disabled { background: #2a3844; color: #66727f; }
QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #2b3848; border-radius: 4px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QLabel#sizeLabel { color: #8894a3; font-size: 12px; }
QLabel#sizeValue { color: #22c3e6; font-size: 12px; font-weight: 600; }
QSlider::groove:horizontal {
    height: 4px; background: #2b3848; border-radius: 2px;
}
QSlider::sub-page:horizontal { background: #22c3e6; border-radius: 2px; }
QSlider::handle:horizontal {
    width: 14px; height: 14px; margin: -6px 0; border-radius: 7px;
    background: #eaf1f8; border: 1px solid #22c3e6;
}
QSlider::handle:horizontal:hover { background: #ffffff; }
"""


def _format_memory(num_bytes):
    gb = num_bytes / 1073741824
    if gb >= 1:
        return f"{gb:.1f} GB"
    return f"{num_bytes / 1048576:.0f} MB"


class ProgramPanel(QWidget):
    def __init__(self, ball):
        super().__init__(None)
        self.ball = ball
        self._checks = {}
        self._all_checked = False

        self.setWindowTitle("加速")
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(384, 524)
        self._drag_pos = None
        self._icon_provider = QFileIconProvider()
        self._icon_cache = {}
        self._build_ui()

    def _icon_for(self, exe):
        if not exe:
            return None
        if exe in self._icon_cache:
            return self._icon_cache[exe]
        pixmap = self._icon_provider.icon(QFileInfo(exe)).pixmap(QSize(18, 18))
        self._icon_cache[exe] = pixmap
        return pixmap

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)

        card = QFrame(self)
        card.setObjectName("card")
        outer.addWidget(card)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 170))
        shadow.setOffset(0, 6)
        card.setGraphicsEffect(shadow)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("正在运行的程序")
        title.setObjectName("title")
        header.addWidget(title)
        header.addStretch(1)
        close_btn = QPushButton("✕")
        close_btn.setObjectName("close")
        close_btn.setFixedSize(26, 26)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.hide)
        header.addWidget(close_btn)
        lay.addLayout(header)

        hint = QLabel("勾选要关闭的程序，点“一键加速”结束它们并释放内存")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.scroll = QScrollArea()
        self.scroll.setObjectName("scroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(2)
        self.list_layout.addStretch(1)
        self.scroll.setWidget(self.list_host)
        lay.addWidget(self.scroll, 1)

        size_row = QHBoxLayout()
        size_row.setSpacing(10)
        size_label = QLabel("球体大小")
        size_label.setObjectName("sizeLabel")
        size_row.addWidget(size_label)
        self.size_slider = QSlider(Qt.Horizontal)
        self.size_slider.setRange(MIN_SIZE, MAX_SIZE)
        self.size_slider.setValue(int(self.ball.cfg.get("size", WINDOW_SIZE)))
        self.size_slider.setCursor(Qt.PointingHandCursor)
        self.size_slider.valueChanged.connect(self._on_size_changed)
        size_row.addWidget(self.size_slider, 1)
        self.size_value = QLabel(f"{self.size_slider.value()}px")
        self.size_value.setObjectName("sizeValue")
        self.size_value.setFixedWidth(42)
        self.size_value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        size_row.addWidget(self.size_value)
        lay.addLayout(size_row)

        anim_row = QHBoxLayout()
        anim_row.setSpacing(10)
        anim_label = QLabel("动画时长")
        anim_label.setObjectName("sizeLabel")
        anim_row.addWidget(anim_label)
        self.anim_slider = QSlider(Qt.Horizontal)
        self.anim_slider.setRange(MIN_ANIM, MAX_ANIM)
        self.anim_slider.setValue(int(self.ball.cfg.get("anim_seconds", 5)))
        self.anim_slider.setCursor(Qt.PointingHandCursor)
        self.anim_slider.valueChanged.connect(self._on_anim_changed)
        anim_row.addWidget(self.anim_slider, 1)
        self.anim_value = QLabel(f"{self.anim_slider.value()}s")
        self.anim_value.setObjectName("sizeValue")
        self.anim_value.setFixedWidth(42)
        self.anim_value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        anim_row.addWidget(self.anim_value)
        lay.addLayout(anim_row)

        footer = QHBoxLayout()
        self.select_all_btn = QPushButton("全选")
        self.select_all_btn.setObjectName("ghost")
        self.select_all_btn.setCursor(Qt.PointingHandCursor)
        self.select_all_btn.clicked.connect(self._toggle_all)
        footer.addWidget(self.select_all_btn)
        footer.addStretch(1)
        self.go_btn = QPushButton("一键加速 (0)")
        self.go_btn.setObjectName("primary")
        self.go_btn.setCursor(Qt.PointingHandCursor)
        self.go_btn.setEnabled(False)
        self.go_btn.clicked.connect(self._on_go)
        footer.addWidget(self.go_btn)
        lay.addLayout(footer)

        self.setStyleSheet(PANEL_STYLE)

    def _clear_rows(self):
        self._checks.clear()
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def refresh_list(self):
        self._clear_rows()
        self._all_checked = False
        self.select_all_btn.setText("全选")
        entries = list_user_programs()
        if not entries:
            empty = QLabel("没有检测到可关闭的程序")
            empty.setObjectName("hint")
            self.list_layout.insertWidget(0, empty)
            self._update_count()
            return
        for name, memory, pids, exe in entries:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(6, 1, 6, 1)
            row_layout.setSpacing(8)
            icon_label = QLabel()
            icon_label.setFixedSize(18, 18)
            icon_label.setAlignment(Qt.AlignCenter)
            pixmap = self._icon_for(exe)
            if pixmap is not None and not pixmap.isNull():
                icon_label.setPixmap(pixmap)
            row_layout.addWidget(icon_label)
            checkbox = QCheckBox(name)
            checkbox.stateChanged.connect(self._update_count)
            row_layout.addWidget(checkbox, 1)
            mem_label = QLabel(_format_memory(memory))
            mem_label.setObjectName("mem")
            row_layout.addWidget(mem_label)
            self.list_layout.insertWidget(self.list_layout.count() - 1, row)
            self._checks[name] = (checkbox, pids)
        self._update_count()

    def _checked_pids(self):
        pids = []
        for checkbox, item_pids in self._checks.values():
            if checkbox.isChecked():
                pids.extend(item_pids)
        return pids

    def _update_count(self):
        pids = self._checked_pids()
        self.go_btn.setText(f"一键加速 ({len(pids)})")
        self.go_btn.setEnabled(bool(pids))

    def _toggle_all(self):
        self._all_checked = not self._all_checked
        for checkbox, _ in self._checks.values():
            checkbox.blockSignals(True)
            checkbox.setChecked(self._all_checked)
            checkbox.blockSignals(False)
        self.select_all_btn.setText("取消全选" if self._all_checked else "全选")
        self._update_count()

    def _on_go(self):
        pids = self._checked_pids()
        if not pids:
            return
        names = [
            name
            for name, (checkbox, _) in self._checks.items()
            if checkbox.isChecked()
        ]
        preview = "、".join(names[:12]) + (" …" if len(names) > 12 else "")
        box = QMessageBox(self)
        box.setWindowTitle("确认加速")
        box.setIcon(QMessageBox.Warning)
        box.setText(f"将强制关闭以下 {len(names)} 个程序，未保存的数据会丢失：")
        box.setInformativeText(preview)
        ok = box.addButton("关闭并加速", QMessageBox.AcceptRole)
        box.addButton("取消", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is not ok:
            return
        self.hide()
        close_processes(pids)
        self.ball.accelerate()

    def _on_size_changed(self, value):
        self.size_value.setText(f"{value}px")
        self.ball.set_size(value)

    def _on_anim_changed(self, value):
        self.anim_value.setText(f"{value}s")
        self.ball.set_anim_seconds(value)

    def popup(self):
        self.refresh_list()
        screen = QApplication.primaryScreen().availableGeometry()
        ball_geo = self.ball.frameGeometry()
        x = ball_geo.left() - self.width() - 6
        y = ball_geo.bottom() - self.height()
        x = max(screen.left() + 8, min(x, screen.right() - self.width() - 8))
        y = max(screen.top() + 8, min(y, screen.bottom() - self.height() - 8))
        self.move(x, y)
        self.show()
        self.raise_()
        self.activateWindow()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = (
                event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            )
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None
        event.accept()


class SpeechBubble(QWidget):
    def __init__(self):
        super().__init__(None)
        self._text = ""
        self.setWindowTitle("内存气泡")
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self._font = QFont("Microsoft YaHei UI")
        self._font.setPixelSize(13)

    def set_text(self, text):
        self._text = text
        metrics = QFontMetrics(self._font)
        width = metrics.horizontalAdvance(text) + 28
        height = metrics.height() + 20
        self.resize(max(width, 64), height)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        body = QRectF(2, 2, self.width() - 4, self.height() - 12)
        path = QPainterPath()
        path.addRoundedRect(body, 10, 10)
        tail = QPainterPath()
        cx = self.width() / 2.0
        tail.moveTo(cx - 7, body.bottom() - 1)
        tail.lineTo(cx, body.bottom() + 9)
        tail.lineTo(cx + 7, body.bottom() - 1)
        tail.closeSubpath()
        path = path.united(tail)

        p.setPen(Qt.NoPen)
        p.setBrush(QColor(20, 27, 36, 240))
        p.drawPath(path)
        p.setPen(QPen(QColor(34, 195, 230, 190), 1.5))
        p.setBrush(Qt.NoBrush)
        p.drawPath(path)

        p.setPen(QColor(234, 241, 248))
        p.setFont(self._font)
        p.drawText(body, Qt.AlignCenter, self._text)


class AccelBall(QWidget):
    released = Signal(int)

    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.percent = 0.0
        self.phase = 0.0
        self.busy = False
        self.hover = False
        self.status_label = "内存"
        self._moved = False
        self._press_pos = None
        self._start_pos = None
        self.dock_edge = None
        self._dragging = False
        self._docked_hidden = False

        self.setWindowTitle("加速球")
        flags = Qt.FramelessWindowHint | Qt.Tool | Qt.NoDropShadowWindowHint
        if self.cfg.get("topmost", True):
            flags |= Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setMouseTracking(True)
        self.resize(int(self.cfg["size"]), int(self.cfg["size"]))

        self.dock_anim = QPropertyAnimation(self, b"pos", self)
        self.dock_anim.setDuration(180)
        self.dock_anim.setEasingCurve(QEasingCurve.OutCubic)
        self.dock_anim.finished.connect(self._update_bubble_position)

        self.normal_movie = QMovie(NORMAL_GIF)
        self.work_movie = QMovie(WORK_GIF)
        self.hover_movies = []
        for path in HOVER_GIFS:
            if not os.path.exists(path):
                continue
            movie = QMovie(path)
            movie.setCacheMode(QMovie.CacheNone)
            movie.frameChanged.connect(self._on_movie_frame)
            self.hover_movies.append(movie)
        self._last_hover_index = -1
        for movie in (self.normal_movie, self.work_movie):
            movie.setCacheMode(QMovie.CacheAll)
            movie.frameChanged.connect(self._on_movie_frame)
        self._active_movie = None
        self._working = False
        self.work_timer = QTimer(self)
        self.work_timer.setSingleShot(True)
        self.work_timer.timeout.connect(self._end_work_animation)
        self._set_active_movie(self.normal_movie)

        self.bubble = SpeechBubble()

        self._build_menu()
        self._build_tray()
        self.panel = ProgramPanel(self)
        self.released.connect(self.on_released)

        self.mem_timer = QTimer(self)
        self.mem_timer.timeout.connect(self.refresh)
        self.mem_timer.start(1200)

        self.anim_timer = QTimer(self)
        self.anim_timer.timeout.connect(self._tick)
        self.anim_timer.start(33)

        self.refresh()
        self._move_to_corner()

    def _build_menu(self):
        self.menu = QMenu(self)
        act_panel = QAction("打开加速面板", self)
        act_panel.triggered.connect(self._toggle_panel)
        self.menu.addAction(act_panel)

        act_accel = QAction("仅释放内存", self)
        act_accel.triggered.connect(self.accelerate)
        self.menu.addAction(act_accel)

        self.menu.addSeparator()
        self.act_top = QAction("窗口置顶", self, checkable=True)
        self.act_top.setChecked(self.cfg.get("topmost", True))
        self.act_top.toggled.connect(self._set_topmost)
        self.menu.addAction(self.act_top)

        self.act_edge = QAction("贴边隐藏", self, checkable=True)
        self.act_edge.setChecked(self.cfg.get("edge_hide", True))
        self.act_edge.toggled.connect(self._set_edge_hide)
        self.menu.addAction(self.act_edge)

        self.act_auto = QAction("开机自启", self, checkable=True)
        self.act_auto.setChecked(is_autostart_enabled())
        self.act_auto.toggled.connect(self._set_autostart)
        self.menu.addAction(self.act_auto)

        self.menu.addSeparator()
        act_quit = QAction("退出", self)
        act_quit.triggered.connect(QApplication.instance().quit)
        self.menu.addAction(act_quit)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self.make_icon(QColor("#33d17a"), 0), self)
        self.tray.setToolTip("加速球")
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._on_tray)
        self.tray.show()

    def _set_topmost(self, checked):
        self.setWindowFlag(Qt.WindowStaysOnTopHint, checked)
        self.cfg["topmost"] = checked
        save_config(self.cfg)
        self.show()

    def _set_edge_hide(self, checked):
        self.cfg["edge_hide"] = checked
        save_config(self.cfg)
        if not checked:
            self.dock_edge = None
            self._docked_hidden = False
            self.dock_anim.stop()
            self.update()
        else:
            self._check_dock()

    def _set_autostart(self, checked):
        try:
            set_autostart(checked)
        except OSError:
            self.act_auto.setChecked(is_autostart_enabled())

    def set_size(self, size):
        size = int(max(MIN_SIZE, min(MAX_SIZE, size)))
        center = self.frameGeometry().center()
        self.resize(size, size)
        self.move(center.x() - size // 2, center.y() - size // 2)
        self.cfg["size"] = size
        save_config(self.cfg)
        self._clamp_to_screen()
        if self.dock_edge:
            self._check_dock()
        self.update()

    def set_anim_seconds(self, seconds):
        seconds = int(max(MIN_ANIM, min(MAX_ANIM, seconds)))
        self.cfg["anim_seconds"] = seconds
        save_config(self.cfg)
        if self._working:
            self.work_timer.start(seconds * 1000)

    def _on_movie_frame(self, frame):
        self.update()

    def _set_active_movie(self, movie):
        if movie is None or not movie.isValid():
            if self._active_movie is not None:
                self._active_movie.stop()
            self._active_movie = None
            self.update()
            return
        if self._active_movie is not None and self._active_movie is not movie:
            self._active_movie.stop()
        self._active_movie = movie
        if movie.state() != QMovie.Running:
            movie.jumpToFrame(0)
            movie.start()
        self.update()

    def _start_work_animation(self):
        if not self.work_movie.isValid():
            return
        self._working = True
        self._set_active_movie(self.work_movie)
        self.work_timer.start(int(self.cfg.get("anim_seconds", 5)) * 1000)

    def _end_work_animation(self):
        self._working = False
        if self.hover and self.hover_movies and not self._dragging:
            self._play_random_hover()
        else:
            self._set_active_movie(self.normal_movie)

    def _play_random_hover(self):
        if not self.hover_movies:
            return
        index = random.randrange(len(self.hover_movies))
        if len(self.hover_movies) > 1 and index == self._last_hover_index:
            index = (index + 1) % len(self.hover_movies)
        self._last_hover_index = index
        self._set_active_movie(self.hover_movies[index])

    def _show_bubble(self):
        self.bubble.set_text(f"内存占用 {int(self.percent)}%")
        self._update_bubble_position()
        self.bubble.show()
        self.bubble.raise_()

    def _update_bubble_position(self):
        if not self.bubble.isVisible():
            return
        if self.dock_edge:
            flush, _ = self._edge_positions()
            base_x, base_y = flush.x(), flush.y()
        else:
            base_x, base_y = self.x(), self.y()
        width = self.bubble.width()
        height = self.bubble.height()
        x = base_x + self.width() // 2 - width // 2
        y = base_y - height + 6
        screen = self._screen_rect()
        x = max(screen.x() + 4, min(x, screen.x() + screen.width() - width - 4))
        y = max(screen.y() + 4, y)
        self.bubble.move(int(x), int(y))

    def _screen_rect(self):
        return QApplication.primaryScreen().availableGeometry()

    def _clamp_to_screen(self):
        screen = self._screen_rect()
        x = max(screen.x(), min(self.x(), screen.x() + screen.width() - self.width()))
        y = max(screen.y(), min(self.y(), screen.y() + screen.height() - self.height()))
        self.move(x, y)

    def _move_to_corner(self):
        screen = self._screen_rect()
        x = screen.x() + screen.width() - self.width() - 32
        y = screen.y() + screen.height() - self.height() - 72
        self.move(x, y)

    def _check_dock(self):
        if not self.cfg.get("edge_hide", True) or self._dragging:
            self.dock_edge = None
            return
        geo = self.frameGeometry()
        screen = self._screen_rect()
        gaps = {
            "left": geo.left() - screen.x(),
            "right": screen.x() + screen.width() - geo.right() - 1,
            "top": geo.top() - screen.y(),
            "bottom": screen.y() + screen.height() - geo.bottom() - 1,
        }
        edge = min(gaps, key=gaps.get)
        if gaps[edge] <= DOCK_THRESHOLD:
            self.dock_edge = edge
            self.hide_to_edge()
        else:
            self.dock_edge = None

    def _edge_positions(self):
        screen = self._screen_rect()
        right = screen.x() + screen.width()
        bottom = screen.y() + screen.height()
        width = self.width()
        height = self.height()
        if self.dock_edge == "left":
            return (
                QPoint(screen.x(), self.y()),
                QPoint(screen.x() - width + DOCK_HANDLE, self.y()),
            )
        if self.dock_edge == "right":
            return (
                QPoint(right - width, self.y()),
                QPoint(right - DOCK_HANDLE, self.y()),
            )
        if self.dock_edge == "top":
            return (
                QPoint(self.x(), screen.y()),
                QPoint(self.x(), screen.y() - height + DOCK_HANDLE),
            )
        return (
            QPoint(self.x(), bottom - height),
            QPoint(self.x(), bottom - DOCK_HANDLE),
        )

    def _slide_to(self, point):
        self.dock_anim.stop()
        self.dock_anim.setStartValue(self.pos())
        self.dock_anim.setEndValue(point)
        self.dock_anim.start()

    def show_from_edge(self):
        if self.dock_edge:
            self._docked_hidden = False
            flush, _ = self._edge_positions()
            self._slide_to(flush)
            self.update()

    def hide_to_edge(self):
        if self.dock_edge:
            self._docked_hidden = True
            _, hidden = self._edge_positions()
            self._slide_to(hidden)
            self.update()

    def current_color(self):
        if self.busy:
            return QColor("#22c3e6")
        if self.percent < 60:
            return QColor("#33d17a")
        if self.percent < 85:
            return QColor("#f5a623")
        return QColor("#ff5b5b")

    def make_icon(self, color, percent):
        pm = QPixmap(64, 64)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(6, 6, 52, 52)
        path = QPainterPath()
        path.addEllipse(rect)
        p.setClipPath(path)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#121821"))
        p.drawEllipse(rect)
        level = rect.bottom() - rect.height() * percent / 100.0
        p.setBrush(color)
        p.drawRect(QRectF(rect.left(), level, rect.width(), rect.bottom() - level))
        p.setClipping(False)
        p.setPen(QPen(color, 4))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(rect)
        p.end()
        return QIcon(pm)

    def _tick(self):
        self.phase += 0.15
        self.update()

    def refresh(self):
        vm = psutil.virtual_memory()
        self.percent = float(vm.percent)
        used = vm.total - vm.available
        self.setToolTip(
            f"内存占用 {vm.percent}%\n"
            f"已用 {used / 1073741824:.1f} / {vm.total / 1073741824:.1f} GB\n"
            "左键打开面板 · 拖动移动 · 右键菜单"
        )
        self.tray.setIcon(self._tray_icon())
        if self.bubble.isVisible():
            self.bubble.set_text(f"内存占用 {int(self.percent)}%")
            self._update_bubble_position()
        self.update()

    def _tray_icon(self):
        movie = self._active_movie
        if movie is not None and movie.isValid():
            pixmap = movie.currentPixmap()
            if not pixmap.isNull():
                return QIcon(
                    pixmap.scaled(
                        QSize(64, 64), Qt.KeepAspectRatio, Qt.SmoothTransformation
                    )
                )
        return self.make_icon(self.current_color(), self.percent)

    def _draw_wave(self, painter, rect, level, phase, color, alpha, amp):
        path = QPainterPath()
        steps = 48
        for i in range(steps + 1):
            x = rect.left() + rect.width() * i / steps
            y = level + math.sin(i / steps * 2 * math.pi + phase) * amp
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        path.lineTo(rect.right(), rect.bottom())
        path.lineTo(rect.left(), rect.bottom())
        path.closeSubpath()

        top = QColor(color)
        top.setAlpha(alpha)
        bottom = QColor(color).darker(165)
        bottom.setAlpha(alpha)
        grad = QLinearGradient(rect.left(), level - amp, rect.left(), rect.bottom())
        grad.setColorAt(0.0, top)
        grad.setColorAt(1.0, bottom)
        painter.setPen(Qt.NoPen)
        painter.setBrush(grad)
        painter.drawPath(path)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)
        if not self._paint_gif(p):
            self._paint_ball(p)
        self._paint_dock_handle(p)

    def _paint_gif(self, painter):
        movie = self._active_movie
        if movie is None or not movie.isValid():
            return False
        pixmap = movie.currentPixmap()
        if pixmap.isNull():
            return False
        scaled = pixmap.scaled(
            self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        x = (self.width() - scaled.width()) // 2
        y = (self.height() - scaled.height()) // 2
        painter.drawPixmap(x, y, scaled)
        return True

    def _paint_ball(self, painter):
        p = painter
        side = min(self.width(), self.height())
        m = side * 0.11
        rect = QRectF(m, m, side - 2 * m, side - 2 * m)
        center = rect.center()
        radius = rect.width() / 2.0

        p.setPen(Qt.NoPen)
        shadow = QRadialGradient(center + QPointF(0, radius * 0.08), radius * 1.14)
        shadow.setColorAt(0.0, QColor(0, 0, 0, 120))
        shadow.setColorAt(0.72, QColor(0, 0, 0, 70))
        shadow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setBrush(shadow)
        p.drawEllipse(center, radius * 1.14, radius * 1.14)

        path = QPainterPath()
        path.addEllipse(rect)
        p.save()
        p.setClipPath(path)

        glass = QRadialGradient(
            rect.topLeft() + QPointF(radius * 0.5, radius * 0.5), radius * 1.5
        )
        glass.setColorAt(0.0, QColor(40, 50, 64) if self.hover else QColor(33, 41, 53))
        glass.setColorAt(1.0, QColor(13, 17, 23))
        p.setBrush(glass)
        p.drawEllipse(rect)

        color = self.current_color()
        level = rect.bottom() - rect.height() * self.percent / 100.0
        self._draw_wave(p, rect, level, self.phase + 1.4, color, 90, 4.0)
        self._draw_wave(p, rect, level, self.phase, color, 255, 3.0)

        gloss = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        gloss.setColorAt(0.0, QColor(255, 255, 255, 80))
        gloss.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setBrush(gloss)
        p.drawEllipse(
            QRectF(
                rect.left() + rect.width() * 0.18,
                rect.top() + rect.height() * 0.09,
                rect.width() * 0.64,
                rect.height() * 0.42,
            )
        )
        p.restore()

        ring = QPen(color, max(2.0, side * 0.02))
        p.setPen(ring)
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(rect)

        font = QFont("Segoe UI")
        font.setPixelSize(int(side * 0.30))
        font.setBold(True)
        p.setFont(font)
        text_rect = rect.adjusted(0, -rect.height() * 0.05, 0, -rect.height() * 0.05)
        text = f"{int(self.percent)}%"
        p.setPen(QColor(0, 0, 0, 150))
        p.drawText(text_rect.translated(1, 2), Qt.AlignCenter, text)
        p.setPen(QColor(255, 255, 255))
        p.drawText(text_rect, Qt.AlignCenter, text)

        label_font = QFont("Microsoft YaHei UI")
        label_font.setPixelSize(max(11, int(side * 0.082)))
        p.setFont(label_font)
        label_rect = rect.adjusted(0, rect.height() * 0.32, 0, rect.height() * 0.32)
        p.setPen(QColor(0, 0, 0, 160))
        p.drawText(label_rect.translated(1, 1), Qt.AlignCenter, self.status_label)
        p.setPen(QColor(224, 232, 242, 235))
        p.drawText(label_rect, Qt.AlignCenter, self.status_label)

    def _paint_dock_handle(self, painter):
        if not (self.dock_edge and self._docked_hidden):
            return
        color = self.current_color()
        side = min(self.width(), self.height())
        length = side * 0.42
        radius = DOCK_HANDLE / 2.0
        if self.dock_edge in ("left", "right"):
            if self.dock_edge == "right":
                center_x = DOCK_HANDLE / 2.0
            else:
                center_x = self.width() - DOCK_HANDLE / 2.0
            handle = QRectF(
                center_x - radius, self.height() / 2 - length / 2, DOCK_HANDLE, length
            )
        else:
            if self.dock_edge == "bottom":
                center_y = DOCK_HANDLE / 2.0
            else:
                center_y = self.height() - DOCK_HANDLE / 2.0
            handle = QRectF(
                self.width() / 2 - length / 2, center_y - radius, length, DOCK_HANDLE
            )

        painter.setPen(Qt.NoPen)
        glow = QColor(color)
        glow.setAlpha(80)
        painter.setBrush(glow)
        painter.drawRoundedRect(handle.adjusted(-3, -3, 3, 3), radius + 3, radius + 3)
        painter.setBrush(color)
        painter.drawRoundedRect(handle, radius, radius)

        highlight = QColor(255, 255, 255, 150)
        painter.setPen(highlight)
        if self.dock_edge in ("left", "right"):
            line_x = handle.left() + radius
            painter.drawLine(
                QPointF(line_x, handle.top() + 6), QPointF(line_x, handle.bottom() - 6)
            )
        else:
            line_y = handle.top() + radius
            painter.drawLine(
                QPointF(handle.left() + 6, line_y), QPointF(handle.right() - 6, line_y)
            )

    def accelerate(self):
        if self.busy:
            return
        self.busy = True
        self.status_label = "释放中…"
        self._start_work_animation()
        self.update()
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        before = psutil.virtual_memory().available
        try:
            release_memory()
        except Exception:
            pass
        time.sleep(0.4)
        after = psutil.virtual_memory().available
        self.released.emit(int(max(0, after - before)))

    @Slot(int)
    def on_released(self, freed):
        self.busy = False
        self.status_label = f"释放 {freed / 1048576:.0f} MB"
        self.refresh()
        QTimer.singleShot(2200, self._reset_label)

    def _reset_label(self):
        if not self.busy:
            self.status_label = "内存"
            self.update()

    def _on_tray(self, reason):
        if reason in (
            QSystemTrayIcon.Trigger,
            QSystemTrayIcon.DoubleClick,
        ):
            self._toggle_panel()

    def _toggle_panel(self):
        if self.panel.isVisible():
            self.panel.hide()
        else:
            self.panel.popup()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dock_anim.stop()
            self._dragging = True
            self._press_pos = event.globalPosition().toPoint()
            self._start_pos = self.pos()
            self._moved = False
        elif event.button() == Qt.RightButton:
            self.menu.popup(event.globalPosition().toPoint())

    def mouseMoveEvent(self, event):
        if self._press_pos is not None and event.buttons() & Qt.LeftButton:
            delta = event.globalPosition().toPoint() - self._press_pos
            if delta.manhattanLength() > 3:
                self._moved = True
            self.move(self._start_pos + delta)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            was_drag = self._moved
            self._press_pos = None
            self._dragging = False
            if not was_drag:
                self._toggle_panel()
            self._check_dock()

    def enterEvent(self, event):
        self.hover = True
        if self.dock_edge:
            self.show_from_edge()
        if not self._working and not self._dragging and self.hover_movies:
            self._play_random_hover()
        self._show_bubble()
        self.update()

    def leaveEvent(self, event):
        self.hover = False
        self.bubble.hide()
        if self.dock_edge and not self._dragging:
            self.hide_to_edge()
        if not self._working:
            self._set_active_movie(self.normal_movie)
        self.update()


def main():
    mutex = acquire_single_instance()
    if mutex is None:
        return
    app = QApplication(sys.argv)
    app.setApplicationName("AccelBall")
    app.setQuitOnLastWindowClosed(False)
    ball = AccelBall()
    ball.show()
    code = app.exec()
    if ball.tray:
        ball.tray.hide()
    sys.exit(code)


if __name__ == "__main__":
    main()
