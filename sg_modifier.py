# -*- coding: utf-8 -*-
"""
《我独自开炮》存档数值修改器（CE 式内存扫描 + 预设清单一键写回）
================================================================
仅依赖 Python 标准库（Windows 自带 tkinter），无任何第三方包。

用法：
    python sg_modifier.py        （建议右键"以管理员身份运行"）

功能：
  1. 选择进程附加（war3.exe / KK 客户端）
  2. CE 式数值搜索：首次扫描(精确值/未知初始) → 变化后再次扫描(变大/变小/变动/未变动/精确值)
  3. 搜索结果双击加入地址表，可修改、冻结
  4. 地址表可保存为预设（presets.json），下次一键按预设批量写回
     —— "一键修改存档数量" 的核心：先用搜索把 金币/木材/杀敌/道具数量 等定位一次，
        存进预设，以后每次进图点一下"应用预设"即可全部写入。

免责声明：本工具仅用于本地学习研究游戏内存结构。
"""

import os
import sys
import json
import time
import struct
import ctypes
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from array import array

IS_WIN = sys.platform == "win32"
if IS_WIN:
    import ctypes.wintypes as wt

APP_TITLE = "我独自开炮 · 存档数值修改器 v1.0"
PRESET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "presets.json")

# ---------------- Windows API 常量 ----------------
PROCESS_ALL = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
WRITABLE_PROTECT = {0x04, 0x08, 0x40, 0x80}      # READWRITE / WRITECOPY / EXECUTE_READWRITE / EXECUTE_WRITECOPY
READABLE_PROTECT = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
TH32CS_SNAPPROCESS = 0x2

TYPES = {
    "4字节整数": ("i", 4, "int"),
    "2字节整数": ("h", 2, "int"),
    "8字节整数": ("q", 8, "int"),
    "4字节浮点": ("f", 4, "float"),
    "8字节浮点": ("d", 8, "float"),
}
DEFAULT_TYPE = "4字节整数"
MAX_RESULTS = 2_000_000        # 候选地址上限
MAX_SHOW_ROWS = 1000           # 列表最多显示行数
SNAPSHOT_LIMIT = 3 * 1024 * 1024 * 1024  # 未知初始值快照上限 3GB

if IS_WIN:
    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_size_t),
            ("AllocationBase", ctypes.c_size_t),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi


# ================= 进程操作 =================
class Proc:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name
        self.handle = None

    def open(self):
        self.handle = k32.OpenProcess(PROCESS_ALL, False, self.pid)
        return bool(self.handle)

    def close(self):
        if self.handle:
            k32.CloseHandle(self.handle)
            self.handle = None

    def is_alive(self):
        if not self.handle:
            return False
        return bool(k32.WaitForSingleObject(self.handle, 0) == 0x102)  # WAIT_TIMEOUT = 存活

    def readable_regions(self, writable_only=True):
        """枚举可读(可选仅可写)的已提交区域 -> [(addr, size)]"""
        out = []
        addr = 0
        max_addr = 0x7FFFFFFEFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFE
        mbi = MBI()
        size = ctypes.sizeof(mbi)
        while addr < max_addr:
            res = k32.VirtualQueryEx(self.handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), size)
            if not res:
                break
            if mbi.State == MEM_COMMIT:
                prot = mbi.Protect & 0xFF
                guarded = bool(mbi.Protect & PAGE_GUARD)
                ok = prot in (WRITABLE_PROTECT if writable_only else READABLE_PROTECT)
                if ok and not guarded and mbi.RegionSize > 0:
                    out.append((mbi.BaseAddress, mbi.RegionSize))
            addr = mbi.BaseAddress + mbi.RegionSize
        return out

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr),
                                   buf, size, ctypes.byref(got))
        if not ok:
            return None
        return buf.raw[:got.value]

    def write(self, addr, data):
        old = ctypes.c_ulong(0)
        prot_ok = k32.VirtualProtectEx(self.handle, ctypes.c_void_p(addr),
                                       len(data), 0x40, ctypes.byref(old))
        got = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(self.handle, ctypes.c_void_p(addr),
                                    data, len(data), ctypes.byref(got))
        if prot_ok:
            k32.VirtualProtectEx(self.handle, ctypes.c_void_p(addr),
                                 len(data), old.value, ctypes.byref(old))
        return bool(ok and got.value == len(data))


def list_processes():
    """返回 [(name, pid, Proc)]，按名称排序"""
    out = []
    if not IS_WIN:
        return out
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return out
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            name = pe.szExeFile
            out.append((name, pe.th32ProcessID, Proc(pe.th32ProcessID, name)))
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    out.sort(key=lambda x: (0 if "war3" in x[0].lower() or "kk" in x[0].lower() else 1, x[0].lower()))
    return out


# ================= 数值打包/比较工具 =================
def pack_value(type_name, text):
    fmt, size, kind = TYPES[type_name]
    if kind == "int":
        v = int(float(text))
        return struct.pack("<" + fmt, v), v
    else:
        v = float(text)
        return struct.pack("<" + fmt, v), v


def unpack_one(type_name, data):
    fmt, size, kind = TYPES[type_name]
    return struct.unpack_from("<" + fmt, data, 0)[0]


def values_equal(type_name, a, b):
    _, _, kind = TYPES[type_name]
    if kind == "int":
        return a == b
    return abs(a - b) <= max(1e-3, abs(b) * 1e-5)


# ================= 扫描引擎 =================
class Scanner:
    """维护候选地址集合并执行扫描/重扫"""

    def __init__(self, log):
        self.log = log
        self.reset()

    def reset(self):
        self.candidates = None       # None=未扫描; list=候选地址
        self.snapshot = None         # 未知初始值模式下的 [(addr, bytes)]
        self.snapshot_mode = False
        self.type_name = DEFAULT_TYPE

    # ---------- 首次扫描：精确值 ----------
    def first_scan_exact(self, proc, type_name, text):
        fmt, size, kind = TYPES[type_name]
        data, value = pack_value(type_name, text)
        needle = data
        found = []
        regions = proc.readable_regions(writable_only=True)
        total = sum(r[1] for r in regions)
        done = 0
        self.log(f"首次扫描[精确值 {text} / {type_name}]，可写区域 {len(regions)} 个，共 {total/1024/1024:.0f} MB")
        for base, rsize in regions:
            step = 8 * 1024 * 1024
            off = 0
            while off < rsize:
                n = min(step, rsize - off)
                blob = proc.read(base + off, n)
                done += n
                if blob is None:
                    break
                # 用 bytes.find 做 C 级速度的定位
                pos = 0
                base_addr = base + off
                extend = len(needle) - 1  # 让跨块边界的值也能命中
                search_blob = blob + (b"\x00" * 0)
                while True:
                    idx = search_blob.find(needle, pos)
                    if idx < 0 or idx >= len(blob):
                        break
                    found.append(base_addr + idx)
                    pos = idx + 1
                    if len(found) >= MAX_RESULTS:
                        break
                if len(found) >= MAX_RESULTS:
                    break
                off += n - extend if n > extend else n
            if len(found) >= MAX_RESULTS:
                break
        self.candidates = list(dict.fromkeys(found))  # 去重（分块重叠导致）
        self.snapshot_mode = False
        self.type_name = type_name
        self.log(f"扫描完成，命中 {len(found):,} 个地址" + ("（已达上限）" if len(found) >= MAX_RESULTS else ""))

    # ---------- 首次扫描：未知初始值 ----------
    def first_scan_unknown(self, proc, type_name):
        regions = proc.readable_regions(writable_only=True)
        total = sum(r[1] for r in regions)
        self.log(f"未知初始值扫描[{type_name}]，可写区域 {len(regions)} 个，共 {total/1024/1024:.0f} MB")
        if total > SNAPSHOT_LIMIT:
            self.log(f"警告：内存超过 {SNAPSHOT_LIMIT/1024/1024/1024:.0f}GB，只截取前 {SNAPSHOT_LIMIT/1024/1024:.0f}MB")
        snap = []
        total = 0
        for base, rsize in regions:
            if total >= SNAPSHOT_LIMIT:
                break
            n = min(rsize, SNAPSHOT_LIMIT - total)
            blob = proc.read(base, n)
            if blob:
                snap.append((base, blob))
                total += len(blob)
        self.snapshot = snap
        self.snapshot_mode = True
        self.type_name = type_name
        self.log(f"快照完成，共 {total/1024/1024:.0f} MB，请在游戏里让数值变化后再点[再次扫描]")

    # ---------- 再次扫描 ----------
    def rescan(self, proc, mode, text=None):
        type_name = self.type_name
        fmt, size, kind = TYPES[type_name]

        # 未知初始值模式：先从快照中筛出"变化了"的地址
        if self.snapshot_mode:
            self.log("再次扫描（快照模式）...")
            cand = []
            new_snap = []
            for base, blob in self.snapshot:
                cur = proc.read(base, len(blob))
                if cur is None:
                    continue
                new_snap.append((base, cur))
                n = len(blob) - (len(blob) % size)
                arr_old = array(fmt)
                arr_old.frombytes(blob[:n])
                arr_new = array(fmt)
                arr_new.frombytes(cur[:n])
                for j in range(len(arr_old)):
                    a, b = arr_old[j], arr_new[j]
                    if kind == "float":
                        if abs(a - b) < 1e-6:
                            continue
                    elif a == b:
                        continue
                    cand.append(base + j * size)
            self.snapshot_mode = False
            self.snapshot = new_snap
            self.candidates = cand[:MAX_RESULTS]
            self.log(f"筛出变化地址 {len(self.candidates):,} 个")
            return

        if not self.candidates:
            self.log("没有候选地址，请先扫描")
            return

        cand = self.candidates
        self.log(f"再次扫描[{mode}]，候选 {len(cand):,} ...")
        # 分组读取
        cand = sorted(set(cand))
        groups = []
        start = prev = cand[0]
        for a in cand[1:]:
            if a - prev <= 4096 and a - start < 1024 * 1024:
                prev = a
            else:
                groups.append((start, prev))
                start = prev = a
        groups.append((start, prev))

        out = []
        limit = MAX_RESULTS
        for g0, g1 in groups:
            if len(out) >= limit:
                break
            span = g1 - g0 + size
            blob = proc.read(g0, span)
            if blob is None:
                for a in range(g0, g1 + 1, size):
                    d = proc.read(a, size)
                    if d:
                        self._match(d, 0, a, mode, text, kind, size, out, limit)
                continue
            # 区间内逐候选判断
            for a in cand:
                if a < g0:
                    continue
                if a > g1:
                    break
                off = a - g0
                if off + size > len(blob):
                    continue
                self._match(blob, off, a, mode, text, kind, size, out, limit)
        self.candidates = out
        self.log(f"剩余候选 {len(out):,} 个")

    def _match(self, blob, off, addr, mode, text, kind, size, out, limit):
        last = self._last.get(addr)
        if mode in ("变大", "变小", "变动", "未变动") and last is None:
            return
        v = struct.unpack_from("<" + TYPES[self.type_name][0], blob, off)[0]
        if mode == "精确值":
            data, target = pack_value(self.type_name, text)
            if kind == "float":
                if abs(v - target) > max(1e-3, abs(target) * 1e-5):
                    return
            elif v != target:
                return
        elif mode == "变大":
            if not v > last:
                return
        elif mode == "变小":
            if not v < last:
                return
        elif mode == "变动":
            if values_equal(self.type_name, v, last):
                return
        elif mode == "未变动":
            if not values_equal(self.type_name, v, last):
                return
        out.append(addr)

    _last = {}  # addr -> 上次值（用于变大/变小判断）

    def cache_last_values(self, proc):
        """重扫前缓存当前所有候选的值，供变大/变小判断"""
        if not self.candidates:
            self._last = {}
            return
        vals = {}
        cand = sorted(set(self.candidates))
        fmt = "<" + TYPES[self.type_name][0]
        size = TYPES[self.type_name][1]
        groups = []
        start = prev = cand[0]
        for a in cand[1:]:
            if a - prev <= 4096 and a - start < 1024 * 1024:
                prev = a
            else:
                groups.append((start, prev))
                start = prev = a
        groups.append((start, prev))
        for g0, g1 in groups:
            span = g1 - g0 + size
            blob = proc.read(g0, span)
            if blob is None:
                continue
            for a in cand:
                if a < g0:
                    continue
                if a > g1:
                    break
                off = a - g0
                if off + size <= len(blob):
                    vals[a] = struct.unpack_from(fmt, blob, off)[0]
        self._last = vals


# ================= 主窗口 =================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1080x680")
        self.minsize(920, 560)
        self.proc = None
        self.scanner = Scanner(lambda s: self.log(s))
        self.frozen = {}          # addr -> (type_name, value_text)
        self.presets = self.load_presets()
        self._build_ui()
        self._refresh_processes()
        self._start_freezer()

    # ---------- UI ----------
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except Exception:
            pass

        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="进程：").pack(side="left")
        self.proc_var = tk.StringVar()
        self.proc_combo = ttk.Combobox(top, textvariable=self.proc_var, width=40, state="readonly")
        self.proc_combo.pack(side="left", padx=4)
        ttk.Button(top, text="刷新列表", command=self._refresh_processes).pack(side="left", padx=2)
        ttk.Button(top, text="附加进程", command=self._attach).pack(side="left", padx=6)
        self.attach_label = ttk.Label(top, text="未附加", foreground="#b00")
        self.attach_label.pack(side="left", padx=10)

        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True)

        # ---- 左：扫描 ----
        left = ttk.Frame(body, padding=6)
        left.pack_propagate(False)
        body.add(left, weight=3)
        f = ttk.Frame(left)
        f.pack(fill="x")
        ttk.Label(f, text="类型：").grid(row=0, column=0)
        self.type_var = tk.StringVar(value=DEFAULT_TYPE)
        ttk.Combobox(f, textvariable=self.type_var, values=list(TYPES), width=11,
                     state="readonly").grid(row=0, column=1)
        ttk.Label(f, text="数值：").grid(row=0, column=2, padx=(8, 0))
        self.value_var = tk.StringVar()
        ve = ttk.Entry(f, textvariable=self.value_var, width=14)
        ve.grid(row=0, column=3, padx=4)
        ttk.Label(f, text="过滤：").grid(row=0, column=4, padx=(8, 0))
        self.mode_var = tk.StringVar(value="精确值")
        ttk.Combobox(f, textvariable=self.mode_var,
                     values=["精确值", "变大", "变小", "变动", "未变动"],
                     width=8, state="readonly").grid(row=0, column=5)
        ttk.Button(f, text="首次扫描", command=self._first_scan).grid(row=0, column=6, padx=6)
        ttk.Button(f, text="再次扫描", command=self._rescan).grid(row=0, column=7)
        ttk.Button(f, text="重置", command=self._reset_scan).grid(row=0, column=8, padx=6)

        self.scan_stat = tk.StringVar(value="候选: -")
        ttk.Label(left, textvariable=self.scan_stat, foreground="#555").pack(anchor="w", pady=2)

        cols = ("addr", "value")
        self.result_tree = ttk.Treeview(left, columns=cols, show="headings", height=14)
        self.result_tree.heading("addr", text="地址")
        self.result_tree.heading("value", text="当前值")
        self.result_tree.column("addr", width=140, anchor="center")
        self.result_tree.column("value", width=120, anchor="e")
        ys = ttk.Scrollbar(left, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=ys.set)
        self.result_tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="left", fill="y")
        self.result_tree.bind("<Double-1>", self._add_from_result)

        # ---- 右：地址表 ----
        right = ttk.Frame(body, padding=6)
        right.pack_propagate(False)
        body.add(right, weight=2)
        rf = ttk.Frame(right)
        rf.pack(fill="x")
        ttk.Label(rf, text="名称：").pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(rf, textvariable=self.name_var, width=16).pack(side="left", padx=2)
        ttk.Label(rf, text="新值：").pack(side="left", padx=(8, 0))
        self.edit_var = tk.StringVar()
        ttk.Entry(rf, textvariable=self.edit_var, width=12).pack(side="left", padx=2)
        ttk.Button(rf, text="写入", command=self._write_selected).pack(side="left", padx=4)
        ttk.Button(rf, text="冻结", command=lambda: self._toggle_freeze(True)).pack(side="left", padx=2)
        ttk.Button(rf, text="解冻", command=lambda: self._toggle_freeze(False)).pack(side="left", padx=2)
        ttk.Button(rf, text="删除", command=self._delete_entry).pack(side="left", padx=2)

        cols2 = ("name", "addr", "type", "value", "frozen")
        self.table_tree = ttk.Treeview(right, columns=cols2, show="headings", height=16)
        for c, t, w in [("name", "名称", 110), ("addr", "地址", 110), ("type", "类型", 80),
                        ("value", "值", 90), ("frozen", "冻结", 45)]:
            self.table_tree.heading(c, text=t)
            self.table_tree.column(c, width=w, anchor=("center" if c in ("addr", "type", "frozen") else "w"))
        self.table_tree.pack(fill="both", expand=True, pady=4)
        self.table_tree.bind("<Double-1>", self._load_entry_to_edit)

        pf = ttk.LabelFrame(right, text="预设（一键修改存档数量）", padding=6)
        pf.pack(fill="x")
        row1 = ttk.Frame(pf); row1.pack(fill="x")
        ttk.Label(row1, text="预设名：").pack(side="left")
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(row1, textvariable=self.preset_var, width=14)
        self.preset_combo.pack(side="left", padx=2)
        ttk.Button(row1, text="保存当前地址表", command=self._save_preset).pack(side="left", padx=2)
        ttk.Button(row1, text="应用(全部写入)", command=self._apply_preset).pack(side="left", padx=6)
        row2 = ttk.Frame(pf); row2.pack(fill="x", pady=(4, 0))
        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="写入前校验旧值一致（地址挪位则跳过并提示）",
                        variable=self.verify_var).pack(side="left")

        # ---- 底部日志 ----
        bottom = ttk.LabelFrame(self, text="日志", padding=4)
        bottom.pack(fill="x", padx=6, pady=(0, 6))
        self.log_text = tk.Text(bottom, height=6, state="disabled", font=("Consolas", 9))
        self.log_text.pack(fill="x")

        if IS_WIN:
            try:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self.attach_label.config(text="未附加（建议管理员运行）", foreground="#b60")
            except Exception:
                pass

    # ---------- 工具 ----------
    def log(self, s):
        def _do():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", time.strftime("[%H:%M:%S] ") + s + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(0, _do)

    def _refresh_processes(self):
        procs = list_processes()
        self.procs = procs
        names = [f"{n} (pid={p})" for n, p, _ in procs]
        self.proc_combo["values"] = names
        if names:
            self.proc_combo.current(0)

    def _attach(self):
        idx = self.proc_combo.current()
        if idx < 0 or idx >= len(getattr(self, "procs", [])):
            messagebox.showwarning(APP_TITLE, "请先选择进程")
            return
        name, pid, proc = self.procs[idx]
        proc.close()
        if not proc.open():
            messagebox.showerror(APP_TITLE, f"打开进程失败(pid={pid})\n请以管理员身份运行本工具")
            return
        if self.proc:
            self.proc.close()
        self.proc = proc
        self.scanner.reset()
        self._reset_scan()
        self.attach_label.config(text=f"已附加: {name} pid={pid}", foreground="#070")
        self.log(f"已附加 {name} (pid={pid})")

    # ---------- 扫描 ----------
    def _first_scan(self):
        if not self.proc:
            messagebox.showwarning(APP_TITLE, "请先附加进程")
            return
        text = self.value_var.get().strip()
        mode_unknown = text == ""
        tn = self.type_var.get()
        if not mode_unknown:
            try:
                pack_value(tn, text)
            except Exception:
                messagebox.showerror(APP_TITLE, "数值格式错误")
                return

        def work():
            try:
                if mode_unknown:
                    self.scanner.first_scan_unknown(self.proc, tn)
                else:
                    self.scanner.first_scan_exact(self.proc, tn, text)
                self.after(0, self._refresh_results)
            except Exception as e:
                self.log(f"扫描出错: {e!r}")
        threading.Thread(target=work, daemon=True).start()

    def _rescan(self):
        if not self.proc:
            messagebox.showwarning(APP_TITLE, "请先附加进程")
            return
        mode = self.mode_var.get()
        text = self.value_var.get().strip()
        if mode == "精确值" and not text:
            messagebox.showwarning(APP_TITLE, "精确值过滤需要填数值")
            return

        def work():
            try:
                self.scanner.cache_last_values(self.proc)
                self.scanner.rescan(self.proc, mode, text or None)
                self.after(0, self._refresh_results)
            except Exception as e:
                self.log(f"重扫出错: {e!r}")
        threading.Thread(target=work, daemon=True).start()

    def _reset_scan(self):
        self.scanner.reset()
        self.scanner._last = {}
        for i in self.result_tree.get_children():
            self.result_tree.delete(i)
        self.scan_stat.set("候选: -")
        self.log("已重置扫描状态")

    def _refresh_results(self):
        for i in self.result_tree.get_children():
            self.result_tree.delete(i)
        cand = self.scanner.candidates
        if cand is None:
            self.scan_stat.set("候选: -")
            return
        self.scan_stat.set(f"候选: {len(cand):,}" + ("（仅显示前%d）" % MAX_SHOW_ROWS if len(cand) > MAX_SHOW_ROWS else ""))
        tn = self.scanner.type_name
        fmt = "<" + TYPES[tn][0]
        size = TYPES[tn][1]
        proc = self.proc
        if not proc:
            return
        shown = cand[:MAX_SHOW_ROWS]
        # 分组读取显示值
        vals = {}
        for a in shown:
            d = proc.read(a, size)
            if d:
                try:
                    vals[a] = struct.unpack(fmt, d)[0]
                except Exception:
                    pass
        for a in shown:
            v = vals.get(a, "?")
            self.result_tree.insert("", "end", values=(hex(a), v))

    def _add_from_result(self, event):
        item = self.result_tree.identify_row(event.y)
        if not item:
            return
        addr_s = self.result_tree.set(item, "addr")
        val = self.result_tree.set(item, "value")
        addr = int(addr_s, 16)
        name = self.name_var.get().strip() or ("条目%d" % (len(self.table_tree.get_children()) + 1))
        self._add_entry(name, addr, self.scanner.type_name, val)
        self.log(f"已加入地址表: {name} @ {addr_s}")

    def _add_entry(self, name, addr, tn, value=""):
        self.table_tree.insert("", "end", values=(name, hex(addr), tn, value, "否"))

    # ---------- 地址表操作 ----------
    def _selected_entry(self):
        sel = self.table_tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "请先在地址表中选择一行")
            return None
        return sel[0]

    def _load_entry_to_edit(self, event):
        item = self.table_tree.identify_row(event.y)
        if not item:
            return
        v = self.table_tree.set(item, "value")
        self.edit_var.set(str(v))

    def _write_selected(self):
        item = self._selected_entry()
        if not item:
            return
        self._write_items([item])

    def _write_items(self, items, extra_value=None):
        if not self.proc:
            messagebox.showwarning(APP_TITLE, "请先附加进程")
            return
        text = extra_value if extra_value is not None else self.edit_var.get().strip()
        ok = 0
        for item in items:
            name, addr_s, tn, oldv, frozen = self.table_tree.set(item, "name", "addr", "type", "value", "frozen")
            try:
                data, v = pack_value(tn, text)
            except Exception:
                messagebox.showerror(APP_TITLE, "新值格式错误")
                return
            addr = int(addr_s, 16)
            if self.proc.write(addr, data):
                ok += 1
                self.table_tree.set(item, "value", v)
                if frozen == "是":
                    self.frozen[addr] = (tn, str(v))
            else:
                self.log(f"写入失败: {name} @ {addr_s}（地址可能已失效）")
        self.log(f"写入完成 {ok}/{len(items)}")

    def _toggle_freeze(self, on):
        item = self._selected_entry()
        if not item:
            return
        name, addr_s, tn, val, _ = self.table_tree.set(item, "name", "addr", "type", "value", "frozen")
        addr = int(addr_s, 16)
        if on:
            if str(val) == "":
                messagebox.showinfo(APP_TITLE, "该条目还没有值，先写入一次")
                return
            self.frozen[addr] = (tn, str(val))
            self.table_tree.set(item, "frozen", "是")
            self.log(f"冻结 {name} @ {addr_s} = {val}")
        else:
            self.frozen.pop(addr, None)
            self.table_tree.set(item, "frozen", "否")

    def _delete_entry(self):
        item = self._selected_entry()
        if not item:
            return
        addr_s = self.table_tree.set(item, "addr")
        self.frozen.pop(int(addr_s, 16), None)
        self.table_tree.delete(item)

    # ---------- 预设 ----------
    def load_presets(self):
        try:
            with open(PRESET_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _refresh_preset_combo(self):
        self.preset_combo["values"] = list(self.presets.keys())

    def _save_preset(self):
        items = self.table_tree.get_children()
        if not items:
            messagebox.showinfo(APP_TITLE, "地址表为空")
            return
        name = self.preset_var.get().strip() or "默认预设"
        entries = []
        for item in items:
            n, addr_s, tn, val, _ = self.table_tree.set(item, "name", "addr", "type", "value", "frozen")
            entries.append({"name": n, "addr": int(addr_s, 16), "type": tn, "last_value": str(val)})
        self.presets[name] = entries
        try:
            with open(PRESET_FILE, "w", encoding="utf-8") as f:
                json.dump(self.presets, f, ensure_ascii=False, indent=2)
            self._refresh_preset_combo()
            self.log(f"预设[{name}]已保存（{len(entries)} 条）→ presets.json")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"保存失败: {e}")

    def _apply_preset(self):
        name = self.preset_var.get().strip()
        if name not in self.presets:
            messagebox.showinfo(APP_TITLE, "请选择已保存的预设")
            return
        if not self.proc:
            messagebox.showwarning(APP_TITLE, "请先附加进程")
            return
        entries = self.presets[name]
        new_text = self.edit_var.get().strip() or "9999999"
        try:
            for tn in {e["type"] for e in entries}:
                pack_value(tn, new_text)
        except Exception:
            messagebox.showerror(APP_TITLE, "新值格式错误")
            return
        ok, skip = 0, []
        for e in entries:
            addr, tn = e["addr"], e["type"]
            cur = self.proc.read(addr, TYPES[tn][1])
            if cur is None:
                skip.append(f"{e['name']}(读取失败)")
                continue
            if self.verify_var.get() and e.get("last_value", "") not in ("", "None"):
                try:
                    v = unpack_one(tn, cur)
                    v_last = unpack_one(tn, pack_value(tn, e["last_value"])[0])
                    if not values_equal(tn, v, v_last):
                        skip.append(f"{e['name']}(旧值不符:当前={v})")
                        continue
                except Exception:
                    pass
            try:
                data, v = pack_value(tn, new_text)
            except Exception:
                messagebox.showerror(APP_TITLE, "新值格式错误")
                return
            if self.proc.write(addr, data):
                ok += 1
            else:
                skip.append(f"{e['name']}(写入失败)")
        self.log(f"预设[{name}]应用完成：写入 {ok} 条，跳过 {len(skip)} 条，写入值={new_text}")
        if skip:
            self.log("跳过明细: " + ", ".join(skip))
            messagebox.showwarning(APP_TITLE,
                f"写入 {ok} 条，跳过 {len(skip)} 条。\n跳过的条目地址可能已变化，"
                f"请在游戏里重新搜索定位后再保存预设。\n\n" + "\n".join(skip[:10]))

    # ---------- 冻结线程 ----------
    def _start_freezer(self):
        def loop():
            while True:
                time.sleep(0.25)
                p = self.proc
                if not p or not p.handle or not self.frozen:
                    continue
                for addr, (tn, text) in list(self.frozen.items()):
                    try:
                        data, _ = pack_value(tn, text)
                        p.write(addr, data)
                    except Exception:
                        pass
        threading.Thread(target=loop, daemon=True).start()


def main():
    if not IS_WIN:
        print("本工具仅支持 Windows（读取其他进程内存）。")
        sys.exit(1)
    App().mainloop()


if __name__ == "__main__":
    main()
