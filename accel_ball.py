import ctypes
import json
import math
import os
import random
import sys
import threading
import time
import urllib.request
from ctypes import wintypes

if sys.platform != "win32":
    raise SystemExit("仅支持 Windows")

import psutil
import PySide6
from PySide6.QtCore import (
    QEasingCurve,
    QFileInfo,
    QPoint,
    QPointF,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    QTranslator,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QCursor,
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
    QColorDialog,
    QDialog,
    QFileIconProvider,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", wintypes.DWORD),
    ]


user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
user32.GetWindowRect.restype = wintypes.BOOL
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(wintypes.DWORD),
]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.MonitorFromWindow.restype = wintypes.HMONITOR
user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFO)]
user32.GetMonitorInfoW.restype = wintypes.BOOL

MONITOR_DEFAULTTONEAREST = 2

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


def foreground_is_fullscreen():
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return False
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == os.getpid():
        return False
    if not user32.IsWindowVisible(hwnd):
        return False
    class_buffer = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, class_buffer, 256)
    if class_buffer.value in ("Progman", "WorkerW", "Shell_TrayWnd", "Button"):
        return False
    rect = RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return False
    monitor = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
    info = MONITORINFO()
    info.cbSize = ctypes.sizeof(MONITORINFO)
    if not user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
        return False
    mon = info.rcMonitor
    tolerance = 2
    return (
        rect.left <= mon.left + tolerance
        and rect.top <= mon.top + tolerance
        and rect.right >= mon.right - tolerance
        and rect.bottom >= mon.bottom - tolerance
    )


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
    "skip_confirm": False,
    "handle_color": "#33d17a",
    "hide_fullscreen": True,
}
MIN_SIZE = 90
MAX_SIZE = 220
MIN_ANIM = 1
MAX_ANIM = 30
DOCK_HANDLE = 10
DOCK_THRESHOLD = 22
DOCK_HOVER_MARGIN = 12


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


def format_speed(bytes_per_second):
    if bytes_per_second >= 1048576:
        return f"{bytes_per_second / 1048576:.1f} MB/s"
    if bytes_per_second >= 1024:
        return f"{bytes_per_second / 1024:.0f} KB/s"
    return f"{bytes_per_second:.0f} B/s"


DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=5000000"
UPLOAD_URL = "https://speed.cloudflare.com/__up"


def measure_download_mbps(timeout=25):
    start = time.time()
    total = 0
    request = urllib.request.Request(DOWNLOAD_URL, headers={"User-Agent": "accel-ball"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
    elapsed = time.time() - start
    if elapsed <= 0 or total <= 0:
        return 0.0
    return total * 8 / elapsed / 1e6


def measure_upload_mbps(size=2000000, timeout=30):
    payload = os.urandom(size)
    request = urllib.request.Request(
        UPLOAD_URL,
        data=payload,
        method="POST",
        headers={"User-Agent": "accel-ball", "Content-Type": "application/octet-stream"},
    )
    start = time.time()
    urllib.request.urlopen(request, timeout=timeout).read()
    elapsed = time.time() - start
    if elapsed <= 0:
        return 0.0
    return size * 8 / elapsed / 1e6


def normalize_proxy(value):
    if not value:
        return None
    value = value.strip()
    if "=" in value:
        parts = {}
        for chunk in value.split(";"):
            if "=" in chunk:
                key, val = chunk.split("=", 1)
                parts[key.strip().lower()] = val.strip()
        value = parts.get("https") or parts.get("http") or next(iter(parts.values()), "")
        if not value:
            return None
    if "://" not in value:
        value = "http://" + value
    return value


def detect_system_proxy():
    for var in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        if os.environ.get(var):
            return normalize_proxy(os.environ[var])
    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enable:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                return normalize_proxy(server)
    except Exception:
        pass
    return None


def detect_proxy_country(proxy, timeout=6):
    if not proxy:
        return None, None
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        request = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,country,countryCode&lang=zh-CN",
            headers={"User-Agent": "accel-ball"},
        )
        with opener.open(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "ignore"))
        if data.get("status") == "success":
            code = data.get("countryCode")
            name = data.get("country") or code
            return code, name
    except Exception:
        return None, None
    return None, None


def fetch_flag_bytes(code, proxy=None, timeout=6):
    if not code or len(code) != 2:
        return None
    url = f"https://flagcdn.com/48x36/{code.lower()}.png"
    try:
        if proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            )
        else:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(url, headers={"User-Agent": "accel-ball"})
        with opener.open(request, timeout=timeout) as response:
            return response.read()
    except Exception:
        return None


def measure_latency(url, proxy=None, timeout=6):
    if "://" not in url:
        url = "https://" + url
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last_exc = None
    for method in ("HEAD", "GET"):
        try:
            start = time.time()
            request = urllib.request.Request(
                url, method=method, headers={"User-Agent": "accel-ball"}
            )
            opener.open(request, timeout=timeout).read(1024)
            return (time.time() - start) * 1000
        except Exception as exc:
            last_exc = exc
    raise last_exc


DIALOG_STYLE = """
QDialog { background-color: #141b24; }
QLabel { color: #dbe4ee; font-size: 13px; }
QLineEdit {
    background: #1b2431; color: #eaf1f8; border: 1px solid #2b3848;
    border-radius: 8px; padding: 6px 10px; selection-background-color: #22c3e6;
}
QPushButton {
    color: #c6d2df; background: #1c2632; border: 1px solid #2b3848;
    border-radius: 8px; padding: 6px 14px;
}
QPushButton:hover { background: #243141; }
QPushButton:disabled { color: #66727f; }
"""


class LatencyDialog(QDialog):
    infoReady = Signal(object, object)
    resultReady = Signal(str, str)

    def __init__(self, proxy):
        super().__init__(None)
        self.proxy = proxy
        self._testing = False
        self.setWindowTitle("网络延迟测试")
        self.setWindowFlags(Qt.Window | Qt.WindowStaysOnTopHint)
        self.setMinimumWidth(400)
        self.setStyleSheet(DIALOG_STYLE)
        self._build_ui()
        self.infoReady.connect(self._on_info)
        self.resultReady.connect(self._on_result)
        self._refresh_info()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        info_row = QHBoxLayout()
        info_row.setSpacing(10)
        self.flag_label = QLabel()
        self.flag_label.setFixedSize(36, 27)
        self.flag_label.setAlignment(Qt.AlignCenter)
        info_row.addWidget(self.flag_label, 0, Qt.AlignTop)
        self.info_label = QLabel("正在检测代理…")
        self.info_label.setWordWrap(True)
        info_row.addWidget(self.info_label, 1)
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.clicked.connect(self._refresh_info)
        info_row.addWidget(self.refresh_btn, 0, Qt.AlignTop)
        lay.addLayout(info_row)

        row = QHBoxLayout()
        self.url_edit = QLineEdit("https://www.google.com")
        row.addWidget(self.url_edit, 1)
        self.test_btn = QPushButton("测试延迟")
        self.test_btn.setCursor(Qt.PointingHandCursor)
        self.test_btn.clicked.connect(self._on_test)
        row.addWidget(self.test_btn)
        lay.addLayout(row)

        self.direct_label = QLabel("直连延迟：--")
        self.proxy_label = QLabel("代理延迟：--")
        lay.addWidget(self.direct_label)
        lay.addWidget(self.proxy_label)

    def _refresh_info(self):
        self.proxy = detect_system_proxy()
        self.flag_label.clear()
        self.info_label.setText("正在检测代理…")
        self.refresh_btn.setEnabled(False)
        threading.Thread(target=self._detect_worker, daemon=True).start()

    def _detect_worker(self):
        if self.proxy:
            code, name = detect_proxy_country(self.proxy)
            if name:
                self.infoReady.emit(
                    f"检测到代理：{self.proxy}\n代理地区：{name}",
                    fetch_flag_bytes(code, self.proxy),
                )
            else:
                self.infoReady.emit(
                    f"检测到代理：{self.proxy}\n代理地区：获取失败", None
                )
        else:
            self.infoReady.emit(
                "未检测到系统代理（可能为直连，或代理处于 TUN 模式）", None
            )

    def _on_info(self, text, flag_bytes):
        self.info_label.setText(text)
        self.refresh_btn.setEnabled(True)
        if flag_bytes:
            pixmap = QPixmap()
            if pixmap.loadFromData(flag_bytes):
                self.flag_label.setPixmap(
                    pixmap.scaled(
                        self.flag_label.size(),
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation,
                    )
                )
            else:
                self.flag_label.clear()
        else:
            self.flag_label.clear()

    def _on_test(self):
        if self._testing:
            return
        self._testing = True
        self.test_btn.setEnabled(False)
        self.test_btn.setText("测试中…")
        self.direct_label.setText("直连延迟：测试中…")
        self.proxy_label.setText("代理延迟：测试中…")
        url = self.url_edit.text().strip()
        threading.Thread(target=self._test_worker, args=(url,), daemon=True).start()

    def _test_worker(self, url):
        try:
            direct = f"{measure_latency(url, None):.0f} ms"
        except Exception:
            direct = "失败 / 超时"
        if self.proxy:
            try:
                proxied = f"{measure_latency(url, self.proxy):.0f} ms"
            except Exception:
                proxied = "失败 / 超时"
        else:
            proxied = "未检测到代理"
        self.resultReady.emit(direct, proxied)

    def _on_result(self, direct, proxied):
        self._testing = False
        self.test_btn.setEnabled(True)
        self.test_btn.setText("测试延迟")
        self.direct_label.setText(f"直连延迟：{direct}")
        self.proxy_label.setText(f"代理延迟：{proxied}")


class ProgramPanel(QWidget):
    speedtestDone = Signal(object, object, object)

    def __init__(self, ball):
        super().__init__(None)
        self.ball = ball
        self._checks = {}
        self._all_checked = False
        self._testing = False

        self.setWindowTitle("加速")
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(384, 620)
        self._drag_pos = None
        self._icon_provider = QFileIconProvider()
        self._icon_cache = {}
        self.speedtestDone.connect(self._finish_speedtest)
        self._build_ui()

        self.net_timer = QTimer(self)
        self.net_timer.timeout.connect(self._update_net)
        self.net_timer.start(800)

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
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.setObjectName("ghost")
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.clicked.connect(self.refresh_list)
        header.addWidget(self.refresh_btn)
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

        net_row = QHBoxLayout()
        net_row.setSpacing(10)
        net_title = QLabel("实时网速")
        net_title.setObjectName("sizeLabel")
        net_row.addWidget(net_title)
        self.net_value = QLabel("↓ 0 B/s   ↑ 0 B/s")
        self.net_value.setObjectName("sizeValue")
        self.net_value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        net_row.addWidget(self.net_value, 1)
        self.test_btn = QPushButton("测网速")
        self.test_btn.setObjectName("ghost")
        self.test_btn.setCursor(Qt.PointingHandCursor)
        self.test_btn.clicked.connect(self._on_speedtest)
        net_row.addWidget(self.test_btn)
        lay.addLayout(net_row)

        self.speed_result = QLabel("")
        self.speed_result.setObjectName("hint")
        self.speed_result.setVisible(False)
        lay.addWidget(self.speed_result)

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

        self.skip_confirm = QCheckBox("加速时不再弹出确认提示")
        self.skip_confirm.setChecked(bool(self.ball.cfg.get("skip_confirm", False)))
        self.skip_confirm.toggled.connect(self._on_skip_confirm)
        lay.addWidget(self.skip_confirm)

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
        if not self.ball.cfg.get("skip_confirm", False):
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

    def _on_skip_confirm(self, checked):
        self.ball.set_skip_confirm(checked)

    def _update_net(self):
        self.net_value.setText(
            f"↓ {format_speed(self.ball.down_speed)}   "
            f"↑ {format_speed(self.ball.up_speed)}"
        )

    def _on_speedtest(self):
        if self._testing:
            return
        self._testing = True
        self.test_btn.setEnabled(False)
        self.test_btn.setText("测速中…")
        self.speed_result.setVisible(True)
        self.speed_result.setText("正在测试下载 / 上传速度…")
        threading.Thread(target=self._run_speedtest, daemon=True).start()

    def _run_speedtest(self):
        down = None
        up = None
        error = ""
        try:
            down = measure_download_mbps()
        except Exception as exc:
            error = f"下载测速失败（{exc}）"
        else:
            try:
                up = measure_upload_mbps()
            except Exception as exc:
                error = f"上传测速失败（{exc}）"
        self.speedtestDone.emit(down, up, error)

    def _finish_speedtest(self, down, up, error):
        self._testing = False
        self.test_btn.setEnabled(True)
        self.test_btn.setText("测网速")
        parts = []
        if down is not None:
            parts.append(f"↓ {down:.1f} Mbps")
        if up is not None:
            parts.append(f"↑ {up:.1f} Mbps")
        text = "　".join(parts)
        if error:
            text = (text + "  " if text else "") + error
        self.speed_result.setText(text or "测速完成")

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
        self._fullscreen_hidden = False

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
            movie.jumpToFrame(0)
            movie.frameChanged.connect(self._on_movie_frame)
            self.hover_movies.append(movie)
        self._last_hover_index = -1
        for movie in (self.normal_movie, self.work_movie):
            movie.setCacheMode(QMovie.CacheAll)
            movie.jumpToFrame(0)
            movie.frameChanged.connect(self._on_movie_frame)
        self._active_movie = None
        self._working = False
        self.work_timer = QTimer(self)
        self.work_timer.setSingleShot(True)
        self.work_timer.timeout.connect(self._end_work_animation)
        self._set_active_movie(self.normal_movie)

        self.bubble = SpeechBubble()

        self.down_speed = 0.0
        self.up_speed = 0.0
        self._net_prev = psutil.net_io_counters()
        self._net_prev_time = time.time()

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

        self.hover_timer = QTimer(self)
        self.hover_timer.timeout.connect(self._poll_dock)
        self.hover_timer.start(80)

        self.fs_timer = QTimer(self)
        self.fs_timer.timeout.connect(self._check_fullscreen)
        self.fs_timer.start(1000)

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

        self.act_fullscreen = QAction("全屏应用时自动隐藏", self, checkable=True)
        self.act_fullscreen.setChecked(self.cfg.get("hide_fullscreen", True))
        self.act_fullscreen.toggled.connect(self._set_hide_fullscreen)
        self.menu.addAction(self.act_fullscreen)

        handle_menu = self.menu.addMenu("贴边小条颜色")
        act_handle_custom = QAction("自定义正常颜色…", self)
        act_handle_custom.triggered.connect(self._pick_handle_color)
        handle_menu.addAction(act_handle_custom)
        act_handle_reset = QAction("恢复默认颜色", self)
        act_handle_reset.triggered.connect(self._reset_handle_color)
        handle_menu.addAction(act_handle_reset)

        act_latency = QAction("网络延迟测试…", self)
        act_latency.triggered.connect(self._open_latency)
        self.menu.addAction(act_latency)

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
        if not self._fullscreen_hidden:
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

    def _set_hide_fullscreen(self, checked):
        self.cfg["hide_fullscreen"] = checked
        save_config(self.cfg)
        if not checked and self._fullscreen_hidden:
            self._restore_from_fullscreen()

    def _check_fullscreen(self):
        if not self.cfg.get("hide_fullscreen", True):
            return
        fullscreen = foreground_is_fullscreen()
        if fullscreen:
            self.bubble.hide()
            if self.panel.isVisible():
                self.panel.hide()
            if not self._fullscreen_hidden:
                self._fullscreen_hidden = True
                self.anim_timer.stop()
                self.hover_timer.stop()
            if self.isVisible():
                self.hide()
        elif self._fullscreen_hidden:
            self._restore_from_fullscreen()

    def _restore_from_fullscreen(self):
        self._fullscreen_hidden = False
        self.show()
        self.anim_timer.start(33)
        self.hover_timer.start(80)
        if self.dock_edge:
            self._check_dock()

    def _set_autostart(self, checked):
        try:
            set_autostart(checked)
        except OSError:
            self.act_auto.setChecked(is_autostart_enabled())

    def _pick_handle_color(self):
        initial = QColor(self.cfg.get("handle_color", "#33d17a"))
        dialog = QColorDialog(initial, self)
        dialog.setOption(QColorDialog.DontUseNativeDialog, True)
        dialog.setWindowTitle("选择贴边小条颜色")
        if dialog.exec():
            color = dialog.selectedColor()
            if color.isValid():
                self.cfg["handle_color"] = color.name()
                save_config(self.cfg)
                self.update()

    def _reset_handle_color(self):
        self.cfg["handle_color"] = "#33d17a"
        save_config(self.cfg)
        self.update()

    def _open_latency(self):
        LatencyDialog(detect_system_proxy()).exec()

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

    def set_skip_confirm(self, value):
        self.cfg["skip_confirm"] = bool(value)
        save_config(self.cfg)

    def _on_movie_frame(self, frame):
        self.update()

    def _set_active_movie(self, movie, restart=False):
        if movie is None or not movie.isValid():
            if self._active_movie is not None:
                self._active_movie.stop()
            self._active_movie = None
            self.update()
            return
        if self._active_movie is not movie:
            if self._active_movie is not None:
                self._active_movie.stop()
            restart = True
        self._active_movie = movie
        if restart or movie.state() != QMovie.Running:
            movie.stop()
            movie.jumpToFrame(0)
            movie.start()
        self.update()

    def _start_work_animation(self):
        if not self.work_movie.isValid():
            return
        self._working = True
        self._set_active_movie(self.work_movie, restart=True)
        self.update()
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
        self._update_net_speed()
        self.setToolTip(
            f"内存占用 {vm.percent}%\n"
            f"已用 {used / 1073741824:.1f} / {vm.total / 1073741824:.1f} GB\n"
            f"网速 ↓ {format_speed(self.down_speed)}  ↑ {format_speed(self.up_speed)}\n"
            "左键打开面板 · 拖动移动 · 右键菜单"
        )
        self.tray.setIcon(self._tray_icon())
        if self.bubble.isVisible():
            self.bubble.set_text(f"内存占用 {int(self.percent)}%")
            self._update_bubble_position()
        self.update()

    def _update_net_speed(self):
        now = time.time()
        counters = psutil.net_io_counters()
        elapsed = now - self._net_prev_time
        if elapsed > 0:
            self.down_speed = max(
                0.0, (counters.bytes_recv - self._net_prev.bytes_recv) / elapsed
            )
            self.up_speed = max(
                0.0, (counters.bytes_sent - self._net_prev.bytes_sent) / elapsed
            )
        self._net_prev = counters
        self._net_prev_time = now

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

    def _handle_color(self):
        if self.busy:
            return QColor("#22c3e6")
        if self.percent >= 85:
            return QColor("#ff5b5b")
        if self.percent >= 60:
            return QColor("#f5a623")
        return QColor(self.cfg.get("handle_color", "#33d17a"))

    def _paint_dock_handle(self, painter):
        if not (self.dock_edge and self._docked_hidden):
            return
        color = self._handle_color()
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
        if self.dock_edge and self._docked_hidden:
            self.show_from_edge()
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
            self.bubble.hide()
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
        if self.dock_edge:
            self.show_from_edge()
        else:
            self.hover = True
            if not self._working and not self._dragging and self.hover_movies:
                self._play_random_hover()
            self._show_bubble()
        self.update()

    def leaveEvent(self, event):
        if self.dock_edge:
            return
        self.hover = False
        self.bubble.hide()
        if not self._working:
            self._set_active_movie(self.normal_movie)
        self.update()

    def _dock_active_rect(self):
        if self.dock_edge:
            flush, _ = self._edge_positions()
            rect = QRect(flush.x(), flush.y(), self.width(), self.height())
        else:
            rect = self.frameGeometry()
        return rect.adjusted(
            -DOCK_HOVER_MARGIN, -DOCK_HOVER_MARGIN, DOCK_HOVER_MARGIN, DOCK_HOVER_MARGIN
        )

    def _poll_dock(self):
        if self.dock_edge is None or self._dragging:
            return
        if self._working:
            if self._docked_hidden:
                self.show_from_edge()
            return
        inside = self._dock_active_rect().contains(QCursor.pos())
        if inside:
            if self._docked_hidden:
                self.show_from_edge()
            if not self.hover:
                self.hover = True
                if not self._working and self.hover_movies:
                    self._play_random_hover()
                self._show_bubble()
        else:
            if not self._docked_hidden:
                self.hide_to_edge()
            if self.hover:
                self.hover = False
                self.bubble.hide()
                if not self._working:
                    self._set_active_movie(self.normal_movie)


def install_translations(app):
    translator = QTranslator(app)
    search_dirs = [os.path.join(os.path.dirname(PySide6.__file__), "translations")]
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        search_dirs.append(os.path.join(bundle, "translations"))
        search_dirs.append(
            os.path.join(bundle, "PySide6", "translations")
        )
    for directory in search_dirs:
        if translator.load("qtbase_zh_CN", directory):
            app.installTranslator(translator)
            return translator
    return None


def main():
    mutex = acquire_single_instance()
    if mutex is None:
        return
    app = QApplication(sys.argv)
    install_translations(app)
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
