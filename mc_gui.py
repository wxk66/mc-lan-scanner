#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
我的世界局域网/VPN 服务器扫描工具 - 图形界面版

特性:
  - 三种扫描模式: 监听局域网广播 / 主动扫描指定范围 / 自动检测本机网段扫描
  - 顶部淡蓝渐变 + 简约白色背景
  - 蓝色扫描按钮, 点击后才开始
  - 结果以彩色卡片形式逐个呈现
  - 可一键导出 JSON

复用 mc_scanner.py 的核心探测逻辑, 仅依赖 Python 标准库(tkinter)。
"""

import json
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import mc_scanner as core


# ----------------------------- 高 DPI 适配 -----------------------------

# 全局缩放因子(相对 96 DPI), 由 setup_dpi() 在启动时确定
SCALE = 1.0


def setup_dpi():
    """声明进程 DPI 感知并返回主显示器缩放因子(相对 96 DPI)。

    不声明感知时, Windows 会把整个窗口位图拉伸, 在高分屏上字体发虚;
    声明后由程序自己按真实 DPI 绘制, 再据此放大尺寸即可清晰。
    """
    if not sys.platform.startswith("win"):
        return 1.0
    try:
        import ctypes
        try:
            # Per-Monitor v2 (Win10 1703+), 效果最好
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            # 旧系统回退: System DPI Aware
            ctypes.windll.user32.SetProcessDPIAware()
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return (dpi / 96.0) if dpi else 1.0
    except Exception:
        return 1.0


def px(value):
    """按 DPI 缩放像素值"""
    return int(round(value * SCALE))


# ----------------------------- 配色 -----------------------------

class Theme:
    BG_TOP = "#dce9fb"        # 顶部渐变起始(淡蓝)
    BG_BOTTOM = "#ffffff"     # 渐变结束(白)
    BG = "#ffffff"            # 主体白色
    CARD_BG = "#ffffff"       # 卡片背景
    CARD_BORDER = "#e2e8f0"   # 卡片边框
    ACCENT = "#2563eb"        # 主蓝色(按钮)
    ACCENT_HOVER = "#1d4ed8"  # 按钮悬停
    ACCENT_ACTIVE = "#1e40af" # 按钮按下
    TITLE = "#1e293b"         # 标题深灰蓝
    LABEL = "#475569"         # 普通标签
    MUTED = "#94a3b8"         # 次要灰
    ADDR = "#0ea5e9"          # 地址(青蓝)
    VERSION = "#d97706"       # 版本(琥珀)
    ONLINE = "#16a34a"        # 有人在线(绿)
    OFFLINE = "#94a3b8"       # 无人(灰)
    PLAYERS = "#2563eb"       # 玩家名(蓝)
    MOTD = "#334155"          # MOTD 文本
    FAIL = "#dc2626"          # 失败(红)
    STRIP = "#3b82f6"         # 卡片左侧色条


def signal_level(ms):
    """把延迟值映射为 (亮起格数 0-5, 颜色)。

    仿 Minecraft Java 版玩家列表的延迟信号: 延迟越低亮起的格子越多。
    """
    if ms is None:
        return 0, Theme.MUTED
    if ms < 50:
        return 5, Theme.ONLINE
    if ms < 100:
        return 4, Theme.ONLINE
    if ms < 200:
        return 3, Theme.VERSION
    if ms < 400:
        return 2, Theme.FAIL
    return 1, Theme.FAIL


def make_signal_icon(parent, ms, bg):
    """画一个 Minecraft 风格的 5 格递增高度延迟信号图标, 返回 Canvas widget。

    5 根从矮到高的竖条; 按延迟亮起对应格数, 亮的用延迟颜色, 暗的用浅灰。
    延迟未知时全部暗格。
    """
    n = 5
    bar_w = px(3)
    gap = px(2)
    max_h = px(15)
    pad = px(2)
    w = n * bar_w + (n - 1) * gap + pad * 2
    h = max_h + pad * 2
    lit, color = signal_level(ms)
    off_color = "#dbe1ea"
    cv = tk.Canvas(parent, width=w, height=h, bg=bg,
                   highlightthickness=0, bd=0)
    for i in range(n):
        bar_h = max(px(2), int(round(max_h * (i + 1) / n)))
        x0 = pad + i * (bar_w + gap)
        x1 = x0 + bar_w
        y1 = pad + max_h
        y0 = y1 - bar_h
        cv.create_rectangle(x0, y0, x1, y1,
                            fill=(color if i < lit else off_color),
                            outline="")
    return cv


MCAST_GRP = "224.0.2.60"
MCAST_PORT = 4445


# ----------------------------- 扫描后台逻辑 -----------------------------

class ScanWorker:
    """在后台线程执行扫描, 通过队列把事件回传给 GUI 主线程。

    事件格式: (类型, 数据)
      ("found",   info_dict)   发现一个服务器
      ("status",  文本)        状态提示
      ("progress", (done,total)) 进度
      ("done",    None)        本次扫描结束
    """

    def __init__(self, event_q):
        self.q = event_q
        self._stop = threading.Event()
        self.thread = None
        self.seen = set()

    def stop(self):
        self._stop.set()

    def is_running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, mode, targets, ports, timeout, lan_time, workers):
        self._stop.clear()
        self.seen.clear()
        self.thread = threading.Thread(
            target=self._run,
            args=(mode, targets, ports, timeout, lan_time, workers),
            daemon=True,
        )
        self.thread.start()

    # --- 内部 ---

    def _emit(self, kind, data=None):
        self.q.put((kind, data))

    def _add_found(self, info):
        key = (info.get("ip"), str(info.get("port")))
        if key in self.seen:
            return
        self.seen.add(key)
        # 测一次 TCP 延迟(端口已知可达, 取多次握手最小值)
        try:
            info["latency"] = core.measure_latency(
                info.get("ip"), int(info.get("port")))
        except Exception:
            info["latency"] = None
        self._emit("found", info)

    def _run(self, mode, targets, ports, timeout, lan_time, workers):
        try:
            if mode == "listen":
                self._listen(lan_time)
            elif mode == "scan":
                self._scan(targets, ports, timeout, workers)
            elif mode == "auto":
                self._auto_scan(ports, timeout, workers)
        except Exception as e:
            self._emit("status", "扫描出错: %s" % e)
        finally:
            self._emit("done", None)

    def _listen(self, duration):
        self._emit("status", "正在监听局域网广播 %s:%d (%d 秒)…"
                   % (MCAST_GRP, MCAST_PORT, duration))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", MCAST_PORT))
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            self._emit("status", "无法加入多播组: %s" % e)
            return
        sock.settimeout(0.5)
        end = time.time() + duration
        while time.time() < end and not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except Exception:
                break
            text = data.decode("utf-8", errors="replace")
            import re
            m_motd = re.search(r"\[MOTD\](.*?)\[/MOTD\]", text)
            m_ad = re.search(r"\[AD\](.*?)\[/AD\]", text)
            if not m_ad:
                continue
            port = m_ad.group(1).strip()
            motd = core.extract_motd(m_motd.group(1)) if m_motd else ""
            key = (addr[0], port)
            if key in self.seen:
                continue
            # 广播包不含版本/人数, 做一次 SLP 探测补全
            info = None
            try:
                info = core.slp_ping(addr[0], int(port), 2.0)
            except Exception:
                info = None
            if info:
                info["motd"] = info.get("motd") or motd
                info["source"] = "广播+探测"
                self._add_found(info)
            else:
                self._add_found({
                    "ip": addr[0], "port": port, "motd": motd,
                    "version": "(探测失败, 仅广播信息)", "protocol": "?",
                    "online": "?", "max": "?", "players": [], "ok": False,
                    "source": "广播",
                })
        try:
            sock.close()
        except Exception:
            pass

    def _probe_targets(self, ips, ports, timeout, workers):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        total = len(ips) * len(ports)
        if total == 0:
            self._emit("status", "目标或端口为空")
            return
        self._emit("status", "开始扫描: %d IP × %d 端口 = %d 个目标…"
                   % (len(ips), len(ports), total))
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(core.scan_one, ip, p, timeout): (ip, p)
                    for ip in ips for p in ports}
            for fut in as_completed(futs):
                if self._stop.is_set():
                    break
                done += 1
                self._emit("progress", (done, total))
                info = fut.result()
                if info:
                    info["source"] = "主动扫描"
                    self._add_found(info)

    def _scan(self, targets, ports, timeout, workers):
        ips = core.parse_targets(targets)
        self._probe_targets(ips, ports, timeout, workers)

    def _auto_scan(self, ports, timeout, workers):
        nets = core.detect_local_networks()
        if not nets:
            self._emit("status", "未能自动检测到网段")
            return
        self._emit("status", "检测到本机网段: "
                   + ", ".join("%s/%s" % (ip, m) for ip, m in nets))
        ips = core.networks_to_targets(nets)
        self._probe_targets(ips, ports, timeout, workers)


# ----------------------------- 渐变背景画布 -----------------------------

class GradientFrame(tk.Canvas):
    """从顶部淡蓝平滑过渡到白色的背景画布"""

    def __init__(self, master, color_top, color_bottom, height=160, **kw):
        super().__init__(master, highlightthickness=0, bd=0, **kw)
        self.color_top = color_top
        self.color_bottom = color_bottom
        self.fade_height = height
        self.bind("<Configure>", self._draw)

    def _draw(self, event=None):
        self.delete("grad")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 1 or h <= 1:
            return
        r1, g1, b1 = self.winfo_rgb(self.color_top)
        r2, g2, b2 = self.winfo_rgb(self.color_bottom)
        fade = min(self.fade_height, h)
        steps = max(fade, 1)
        for i in range(steps):
            t = i / steps
            r = int((r1 + (r2 - r1) * t) / 256)
            g = int((g1 + (g2 - g1) * t) / 256)
            b = int((b1 + (b2 - b1) * t) / 256)
            color = "#%02x%02x%02x" % (r, g, b)
            self.create_line(0, i, w, i, fill=color, tags="grad")
        # 渐变以下填充纯白
        if fade < h:
            self.create_rectangle(0, fade, w, h, fill=self.color_bottom,
                                  outline="", tags="grad")
        self.tag_lower("grad")


# ----------------------------- 服务器卡片 -----------------------------

class ServerCard(tk.Frame):
    """单个服务器的彩色信息卡片"""

    def __init__(self, master, info, index):
        super().__init__(master, bg=Theme.CARD_BG,
                         highlightbackground=Theme.CARD_BORDER,
                         highlightthickness=1, bd=0)
        ok = info.get("ok", True)
        strip_color = Theme.STRIP if ok else Theme.FAIL

        # 左侧色条
        strip = tk.Frame(self, bg=strip_color, width=px(6))
        strip.pack(side="left", fill="y")

        body = tk.Frame(self, bg=Theme.CARD_BG)
        body.pack(side="left", fill="both", expand=True, padx=14, pady=10)

        # 第一行: 序号 + 地址 + 来源标签
        top = tk.Frame(body, bg=Theme.CARD_BG)
        top.pack(fill="x")
        tk.Label(top, text="#%d" % index, font=("Segoe UI", 11, "bold"),
                 fg=Theme.MUTED, bg=Theme.CARD_BG).pack(side="left")
        addr = "%s:%s" % (info.get("ip"), info.get("port"))
        tk.Label(top, text=addr, font=("Consolas", 13, "bold"),
                 fg=Theme.ADDR, bg=Theme.CARD_BG).pack(side="left", padx=(8, 0))

        # 地址旁的复制按钮
        copy_btn = tk.Button(top, text="复制", font=("Microsoft YaHei UI", 8),
                             fg=Theme.ACCENT, bg=Theme.CARD_BG,
                             activebackground="#eef2ff", activeforeground=Theme.ACCENT,
                             relief="flat", bd=0, cursor="hand2", padx=6, pady=0)

        def do_copy(addr=addr, btn=copy_btn):
            try:
                self.clipboard_clear()
                self.clipboard_append(addr)
            except Exception:
                pass
            btn.config(text="已复制", fg=Theme.ONLINE)
            btn.after(1200, lambda: btn.config(text="复制", fg=Theme.ACCENT))

        copy_btn.config(command=do_copy)
        copy_btn.pack(side="left", padx=(6, 0))

        source = info.get("source", "")
        if source:
            tk.Label(top, text=source, font=("Microsoft YaHei UI", 8),
                     fg=Theme.MUTED, bg=Theme.CARD_BG).pack(side="right")

        # MOTD
        motd = info.get("motd") or "(空)"
        tk.Label(body, text=motd, font=("Microsoft YaHei UI", 10),
                 fg=Theme.MOTD, bg=Theme.CARD_BG, anchor="w",
                 justify="left", wraplength=px(520)).pack(fill="x", pady=(6, 2))

        # 版本 + 在线 一行
        meta = tk.Frame(body, bg=Theme.CARD_BG)
        meta.pack(fill="x", pady=(2, 0))

        ver = info.get("version", "未知")
        proto = info.get("protocol", "?")
        ver_color = Theme.VERSION if ok else Theme.FAIL
        tk.Label(meta, text="版本 %s" % ver, font=("Microsoft YaHei UI", 9, "bold"),
                 fg=ver_color, bg=Theme.CARD_BG).pack(side="left")
        tk.Label(meta, text="协议 %s" % proto, font=("Microsoft YaHei UI", 8),
                 fg=Theme.MUTED, bg=Theme.CARD_BG).pack(side="left", padx=(6, 0))

        online = info.get("online", "?")
        max_ = core.fmt_max(info.get("max", "?"))
        try:
            on_color = Theme.ONLINE if int(online) > 0 else Theme.OFFLINE
        except (ValueError, TypeError):
            on_color = Theme.MUTED
        tk.Label(meta, text="在线 %s / %s" % (online, max_),
                 font=("Microsoft YaHei UI", 9, "bold"),
                 fg=on_color, bg=Theme.CARD_BG).pack(side="right")

        # 延迟信号: Minecraft 风格的 5 格递增竖条图标 + 毫秒数
        latency = info.get("latency")
        _, lat_color = signal_level(latency)
        lat_num = "-- ms" if latency is None else "%d ms" % latency
        lat = tk.Frame(meta, bg=Theme.CARD_BG)
        lat.pack(side="right", padx=(0, 12))
        icon = make_signal_icon(lat, latency, Theme.CARD_BG)
        icon.pack(side="left")
        tk.Label(lat, text=lat_num, font=("Microsoft YaHei UI", 9, "bold"),
                 fg=lat_color, bg=Theme.CARD_BG).pack(side="left", padx=(4, 0))

        # 玩家列表
        players = info.get("players") or []
        if players:
            tk.Label(body, text="在线玩家: " + ", ".join(players),
                     font=("Microsoft YaHei UI", 9), fg=Theme.PLAYERS,
                     bg=Theme.CARD_BG, anchor="w", justify="left",
                     wraplength=px(520)).pack(fill="x", pady=(6, 0))


# ----------------------------- 主窗口 -----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        # 让所有 pt 字体按 DPI 自动缩放(1.3333 = 96/72 基准, 再乘以 DPI 因子)
        try:
            self.tk.call("tk", "scaling", 1.3333 * SCALE)
        except Exception:
            pass
        self.title("我的世界局域网扫描器")
        self.geometry("%dx%d" % (px(680), px(720)))
        self.minsize(px(560), px(560))
        self.configure(bg=Theme.BG)

        self.event_q = queue.Queue()
        self.worker = ScanWorker(self.event_q)
        self.results = []
        self.card_index = 0

        self._build_ui()
        self.after(80, self._poll_queue)

    # --- UI 构建 ---

    def _build_ui(self):
        # 顶部渐变标题区
        header = GradientFrame(self, Theme.BG_TOP, Theme.BG_BOTTOM,
                               height=px(150))
        header.pack(fill="x")
        header.configure(height=px(118))

        title = tk.Label(header, text="我的世界局域网扫描器",
                         font=("Microsoft YaHei UI", 20, "bold"),
                         fg=Theme.TITLE, bg=Theme.BG_TOP)
        header.create_window(px(24), px(30), anchor="w", window=title)
        subtitle = tk.Label(header,
                            text="扫描局域网 / Radmin VPN 中的 Minecraft 服务器",
                            font=("Microsoft YaHei UI", 10),
                            fg=Theme.LABEL, bg=Theme.BG_TOP)
        header.create_window(px(26), px(68), anchor="w", window=subtitle)

        # 控制区
        ctrl = tk.Frame(self, bg=Theme.BG)
        ctrl.pack(fill="x", padx=24, pady=(16, 8))

        # 模式选择
        row1 = tk.Frame(ctrl, bg=Theme.BG)
        row1.pack(fill="x", pady=4)
        tk.Label(row1, text="扫描模式", font=("Microsoft YaHei UI", 10),
                 fg=Theme.LABEL, bg=Theme.BG, width=10, anchor="w").pack(side="left")
        self.mode_var = tk.StringVar(value="监听局域网广播")
        self.mode_box = ttk.Combobox(
            row1, textvariable=self.mode_var, state="readonly",
            values=["监听局域网广播", "主动扫描指定范围", "自动检测本机网段"],
            font=("Microsoft YaHei UI", 10), width=24)
        self.mode_box.pack(side="left")
        self.mode_box.bind("<<ComboboxSelected>>", self._on_mode_change)

        # 扫描范围(IP)
        self.row_targets = tk.Frame(ctrl, bg=Theme.BG)
        self.row_targets.pack(fill="x", pady=4)
        tk.Label(self.row_targets, text="扫描范围", font=("Microsoft YaHei UI", 10),
                 fg=Theme.LABEL, bg=Theme.BG, width=10, anchor="w").pack(side="left")
        self.targets_var = tk.StringVar(value="26.0.0.0/24")
        self.targets_entry = tk.Entry(self.row_targets, textvariable=self.targets_var,
                                      font=("Consolas", 10), relief="solid", bd=1)
        self.targets_entry.pack(side="left", fill="x", expand=True, ipady=3)

        # 端口范围
        self.row_ports = tk.Frame(ctrl, bg=Theme.BG)
        self.row_ports.pack(fill="x", pady=4)
        tk.Label(self.row_ports, text="端口范围", font=("Microsoft YaHei UI", 10),
                 fg=Theme.LABEL, bg=Theme.BG, width=10, anchor="w").pack(side="left")
        self.ports_var = tk.StringVar(value="25565-25600")
        self.ports_entry = tk.Entry(self.row_ports, textvariable=self.ports_var,
                                    font=("Consolas", 10), relief="solid", bd=1)
        self.ports_entry.pack(side="left", fill="x", expand=True, ipady=3)

        # 监听时长
        self.row_lan = tk.Frame(ctrl, bg=Theme.BG)
        self.row_lan.pack(fill="x", pady=4)
        tk.Label(self.row_lan, text="监听时长", font=("Microsoft YaHei UI", 10),
                 fg=Theme.LABEL, bg=Theme.BG, width=10, anchor="w").pack(side="left")
        self.lantime_var = tk.StringVar(value="15")
        tk.Entry(self.row_lan, textvariable=self.lantime_var, width=8,
                 font=("Consolas", 10), relief="solid", bd=1).pack(side="left", ipady=3)
        tk.Label(self.row_lan, text="秒", font=("Microsoft YaHei UI", 9),
                 fg=Theme.MUTED, bg=Theme.BG).pack(side="left", padx=(6, 0))

        # 按钮区
        btn_row = tk.Frame(ctrl, bg=Theme.BG)
        btn_row.pack(fill="x", pady=(10, 4))
        self.scan_btn = tk.Button(
            btn_row, text="开始扫描", font=("Microsoft YaHei UI", 12, "bold"),
            fg="white", bg=Theme.ACCENT, activebackground=Theme.ACCENT_ACTIVE,
            activeforeground="white", relief="flat", bd=0, cursor="hand2",
            command=self._on_scan_click, padx=28, pady=8)
        self.scan_btn.pack(side="left")
        self.scan_btn.bind("<Enter>", lambda e: self.scan_btn.config(bg=Theme.ACCENT_HOVER))
        self.scan_btn.bind("<Leave>", lambda e: self.scan_btn.config(bg=Theme.ACCENT))

        self.export_btn = tk.Button(
            btn_row, text="导出结果", font=("Microsoft YaHei UI", 10),
            fg=Theme.ACCENT, bg=Theme.BG, activebackground="#eef2ff",
            relief="solid", bd=1, cursor="hand2", command=self._on_export,
            padx=14, pady=7, state="disabled")
        self.export_btn.pack(side="left", padx=(10, 0))

        self.clear_btn = tk.Button(
            btn_row, text="清空", font=("Microsoft YaHei UI", 10),
            fg=Theme.LABEL, bg=Theme.BG, activebackground="#f1f5f9",
            relief="solid", bd=1, cursor="hand2", command=self._clear_results,
            padx=14, pady=7)
        self.clear_btn.pack(side="left", padx=(8, 0))

        # 状态条
        self.status_var = tk.StringVar(value="就绪。选择模式后点击「开始扫描」。")
        status_bar = tk.Frame(self, bg=Theme.BG)
        status_bar.pack(fill="x", padx=24)
        self.status_label = tk.Label(status_bar, textvariable=self.status_var,
                                     font=("Microsoft YaHei UI", 9), fg=Theme.MUTED,
                                     bg=Theme.BG, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)
        self.count_label = tk.Label(status_bar, text="", font=("Microsoft YaHei UI", 9, "bold"),
                                    fg=Theme.ACCENT, bg=Theme.BG)
        self.count_label.pack(side="right")

        # 结果区(可滚动)
        self._build_scroll_area()

        self._on_mode_change()

    def _build_scroll_area(self):
        container = tk.Frame(self, bg=Theme.BG)
        container.pack(fill="both", expand=True, padx=18, pady=(8, 16))

        self.canvas = tk.Canvas(container, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(container, orient="vertical",
                                  command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.cards_frame = tk.Frame(self.canvas, bg=Theme.BG)
        self.cards_window = self.canvas.create_window(
            (0, 0), window=self.cards_frame, anchor="nw")

        self.cards_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(self.cards_window, width=e.width))
        # 鼠标滚轮
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # 占位提示
        self.placeholder = tk.Label(
            self.cards_frame, text="\n暂无结果\n点击上方「开始扫描」开始查找服务器\n",
            font=("Microsoft YaHei UI", 11), fg=Theme.MUTED, bg=Theme.BG)
        self.placeholder.pack(pady=40)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")

    # --- 交互 ---

    def _on_mode_change(self, event=None):
        mode = self.mode_var.get()
        # 根据模式显示/隐藏对应输入行
        if mode == "监听局域网广播":
            self._set_row_visible(self.row_targets, False)
            self._set_row_visible(self.row_ports, False)
            self._set_row_visible(self.row_lan, True)
        elif mode == "主动扫描指定范围":
            self._set_row_visible(self.row_targets, True)
            self._set_row_visible(self.row_ports, True)
            self._set_row_visible(self.row_lan, False)
        else:  # 自动检测本机网段
            self._set_row_visible(self.row_targets, False)
            self._set_row_visible(self.row_ports, True)
            self._set_row_visible(self.row_lan, False)

    def _set_row_visible(self, row, visible):
        if visible:
            row.pack(fill="x", pady=4)
        else:
            row.pack_forget()

    def _on_scan_click(self):
        if self.worker.is_running():
            # 正在扫描 -> 作为停止按钮
            self.worker.stop()
            self.status_var.set("正在停止…")
            return

        mode_text = self.mode_var.get()
        mode = {"监听局域网广播": "listen",
                "主动扫描指定范围": "scan",
                "自动检测本机网段": "auto"}[mode_text]

        try:
            ports = core.parse_ports(self.ports_var.get()) if mode != "listen" else []
        except Exception:
            messagebox.showerror("端口格式错误", "请检查端口范围输入, 例如 25565-25600")
            return

        if mode == "scan" and not self.targets_var.get().strip():
            messagebox.showwarning("缺少扫描范围", "请填写扫描范围, 例如 26.0.0.0/24")
            return

        try:
            lan_time = int(self.lantime_var.get())
        except ValueError:
            lan_time = 15

        self._clear_results()
        self._set_scanning(True)
        self.worker.start(mode, self.targets_var.get().strip(), ports,
                          timeout=1.0, lan_time=lan_time, workers=200)

    def _set_scanning(self, scanning):
        if scanning:
            self.scan_btn.config(text="停止扫描", bg="#ef4444")
            self.scan_btn.unbind("<Enter>")
            self.scan_btn.unbind("<Leave>")
            self.export_btn.config(state="disabled")
        else:
            self.scan_btn.config(text="开始扫描", bg=Theme.ACCENT)
            self.scan_btn.bind("<Enter>", lambda e: self.scan_btn.config(bg=Theme.ACCENT_HOVER))
            self.scan_btn.bind("<Leave>", lambda e: self.scan_btn.config(bg=Theme.ACCENT))
            if self.results:
                self.export_btn.config(state="normal")

    def _clear_results(self):
        for w in self.cards_frame.winfo_children():
            w.destroy()
        self.results = []
        self.card_index = 0
        self.count_label.config(text="")
        self.export_btn.config(state="disabled")
        self.placeholder = tk.Label(
            self.cards_frame, text="\n暂无结果\n点击上方「开始扫描」开始查找服务器\n",
            font=("Microsoft YaHei UI", 11), fg=Theme.MUTED, bg=Theme.BG)
        self.placeholder.pack(pady=40)

    def _add_card(self, info):
        if self.placeholder is not None:
            self.placeholder.destroy()
            self.placeholder = None
        self.card_index += 1
        self.results.append(info)
        card = ServerCard(self.cards_frame, info, self.card_index)
        card.pack(fill="x", pady=6, padx=4)
        self.count_label.config(text="已发现 %d 个" % self.card_index)

    # --- 队列轮询(主线程更新 UI) ---

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.event_q.get_nowait()
                if kind == "found":
                    self._add_card(data)
                elif kind == "status":
                    self.status_var.set(data)
                elif kind == "progress":
                    done, total = data
                    self.status_var.set("扫描进度 %d / %d" % (done, total))
                elif kind == "done":
                    self._set_scanning(False)
                    n = len(self.results)
                    self.status_var.set("扫描完成, 共发现 %d 个服务器。" % n
                                        if n else "扫描完成, 未发现服务器。")
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    # --- 导出 ---

    def _on_export(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="导出扫描结果", defaultextension=".json",
            filetypes=[("JSON 文件", "*.json"), ("文本文件", "*.txt")],
            initialfile="mc_servers.json")
        if not path:
            return
        try:
            clean = []
            for r in self.results:
                clean.append({k: (core.strip_ansi(v) if isinstance(v, str) else v)
                              for k, v in r.items()})
            if path.lower().endswith(".txt"):
                lines = []
                for i, r in enumerate(clean, 1):
                    lines.append("#%d  %s:%s" % (i, r.get("ip"), r.get("port")))
                    lines.append("    MOTD : %s" % (r.get("motd") or ""))
                    lines.append("    版本 : %s (协议 %s)"
                                 % (r.get("version"), r.get("protocol")))
                    lines.append("    在线 : %s / %s"
                                 % (r.get("online"), core.fmt_max(r.get("max"))))
                    if r.get("players"):
                        lines.append("    玩家 : %s" % ", ".join(r["players"]))
                    lines.append("")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(clean, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("导出成功", "已导出 %d 条结果到\n%s"
                                % (len(clean), path))
        except Exception as e:
            messagebox.showerror("导出失败", str(e))


def main():
    global SCALE
    SCALE = setup_dpi()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
