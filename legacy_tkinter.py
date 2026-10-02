import ctypes
import os
import sys
import threading
import time
import tkinter as tk
from ctypes import wintypes

if sys.platform != "win32":
    raise SystemExit("仅支持 Windows")

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi")
advapi32 = ctypes.WinDLL("advapi32")

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_QUOTA = 0x0100

TRANSPARENT = "#ff00ff"
BG_OUTER = "#151b24"
RING_TRACK = "#2b333d"
COLOR_LOW = "#3ddc84"
COLOR_MID = "#ffb020"
COLOR_HIGH = "#ff4d4f"
COLOR_BUSY = "#22c3e6"

SIZE = 130


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def get_memory():
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
    return int(st.dwMemoryLoad), int(st.ullAvailPhys), int(st.ullTotalPhys)


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


def _list_pids():
    count = 1024
    while count <= 65536:
        arr = (wintypes.DWORD * count)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return []
        n = needed.value // ctypes.sizeof(wintypes.DWORD)
        if n < count:
            return [arr[i] for i in range(n)]
        count *= 2
    return []


def release_memory():
    _enable_debug_privilege()
    self_pid = os.getpid()
    for pid in _list_pids():
        if pid == 0 or pid == self_pid:
            continue
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, False, pid
        )
        if handle:
            psapi.EmptyWorkingSet(handle)
            kernel32.CloseHandle(handle)


class AccelBall:
    def __init__(self):
        self.busy = False
        self._dragging = False
        self._drag_moved = False
        self._dx = 0
        self._dy = 0

        self.root = tk.Tk()
        self.root.title("加速球")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg=TRANSPARENT)
        try:
            self.root.attributes("-transparentcolor", TRANSPARENT)
        except tk.TclError:
            pass

        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = sw - SIZE - 30
        y = sh - SIZE - 80
        self.root.geometry(f"{SIZE}x{SIZE}+{x}+{y}")

        self.canvas = tk.Canvas(
            self.root,
            width=SIZE,
            height=SIZE,
            bg=TRANSPARENT,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack()

        pad = 13
        box = (pad, pad, SIZE - pad, SIZE - pad)
        center = SIZE // 2

        self.canvas.create_oval(box, fill=BG_OUTER, outline="")
        self.canvas.create_arc(
            box,
            start=90,
            extent=-359.9,
            style="arc",
            outline=RING_TRACK,
            width=9,
        )
        self.arc = self.canvas.create_arc(
            box,
            start=90,
            extent=-0.1,
            style="arc",
            outline=COLOR_LOW,
            width=9,
        )
        self.pct_text = self.canvas.create_text(
            center,
            center - 6,
            text="--%",
            fill="#ffffff",
            font=("Segoe UI", 24, "bold"),
        )
        self.status_text = self.canvas.create_text(
            center,
            center + 21,
            text="内存",
            fill="#8894a3",
            font=("Microsoft YaHei UI", 9),
        )

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_motion)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<Button-3>", self._on_right)
        self.root.bind("<Escape>", lambda e: self.root.destroy())

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="立即加速", command=self.accelerate)
        self.topmost_var = tk.BooleanVar(value=True)
        self.menu.add_checkbutton(
            label="窗口置顶",
            variable=self.topmost_var,
            command=self._toggle_topmost,
        )
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=self.root.destroy)

        self.refresh()

    def _toggle_topmost(self):
        self.root.attributes("-topmost", self.topmost_var.get())

    def _on_press(self, event):
        self._dragging = True
        self._drag_moved = False
        self._dx = event.x_root - self.root.winfo_x()
        self._dy = event.y_root - self.root.winfo_y()

    def _on_motion(self, event):
        nx = event.x_root - self._dx
        ny = event.y_root - self._dy
        if abs(nx - self.root.winfo_x()) + abs(ny - self.root.winfo_y()) > 3:
            self._drag_moved = True
        self.root.geometry(f"+{nx}+{ny}")

    def _on_release(self, event):
        self._dragging = False
        if not self._drag_moved:
            self.accelerate()

    def _on_right(self, event):
        self.menu.tk_popup(event.x_root, event.y_root)

    def refresh(self):
        percent, avail, total = get_memory()
        if percent < 60:
            color = COLOR_LOW
        elif percent < 85:
            color = COLOR_MID
        else:
            color = COLOR_HIGH
        if not self.busy:
            extent = max(0.1, min(359.9, 360 * percent / 100))
            self.canvas.itemconfig(self.arc, outline=color, extent=-extent)
            self.canvas.itemconfig(self.pct_text, text=f"{percent}%", fill=color)
        self.root.after(1500, self.refresh)

    def accelerate(self):
        if self.busy:
            return
        self.busy = True
        self.canvas.itemconfig(self.arc, outline=COLOR_BUSY)
        self.canvas.itemconfig(self.pct_text, text="加速", fill=COLOR_BUSY, font=("Microsoft YaHei UI", 15, "bold"))
        self.canvas.itemconfig(self.status_text, text="释放中...")

        def work():
            before = get_memory()[1]
            release_memory()
            time.sleep(0.4)
            after = get_memory()[1]
            self.root.after(0, lambda: self._finish(max(0, after - before)))

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, freed_bytes):
        self.busy = False
        mb = freed_bytes / (1024 * 1024)
        self.canvas.itemconfig(self.pct_text, font=("Segoe UI", 24, "bold"))
        self.canvas.itemconfig(self.status_text, text=f"释放 {mb:.0f}MB")
        self.root.after(2200, lambda: self.canvas.itemconfig(self.status_text, text="内存"))
        self.refresh()

    def run(self):
        self.root.mainloop()


def main():
    AccelBall().run()


if __name__ == "__main__":
    main()
