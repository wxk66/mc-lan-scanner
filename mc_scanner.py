#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
我的世界(Minecraft Java版)局域网/VPN 服务器扫描工具

功能:
  1. 自动检测本机所有网卡子网(包含 Radmin VPN 的 26.x.x.x 网段)
  2. 在指定 IP 范围 + 端口范围上扫描
  3. 使用真正的 MC 服务器列表 Ping(SLP)协议确认, 输出 MOTD / 版本 / 在线人数
  4. 可选: 监听"对局域网开放"世界的 UDP 多播广播(224.0.2.60:4445)

只依赖 Python 标准库, 兼容 Python 3.8+。

示例:
  # 默认: 只监听局域网"对局域网开放"广播(不主动扫描)
  python mc_scanner.py

  # 自动检测本机网段并主动扫描默认端口段
  python mc_scanner.py --scan

  # 指定 Radmin 网段 + 端口段
  python mc_scanner.py -t 26.0.0.0/24 -p 25565-25600

  # 指定多个目标和端口
  python mc_scanner.py -t 192.168.1.0/24,26.158.0.1-26.158.0.50 -p 25565,25566,30000-30010
"""

import argparse
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Windows 控制台默认 GBK, 强制 stdout/stderr 用 UTF-8 输出, 避免中文乱码
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ----------------------------- 终端色彩 -----------------------------

def _enable_windows_vt():
    """在 Windows 10+ 控制台启用 ANSI 虚拟终端处理, 让颜色码生效"""
    if not sys.platform.startswith("win"):
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE, 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        return True
    except Exception:
        return False


def _stdout_is_tty():
    """安全判断 stdout 是否为终端(GUI/windowed exe 下 stdout 可能为 None)"""
    try:
        return bool(sys.stdout) and sys.stdout.isatty()
    except Exception:
        return False


# 是否启用颜色(非 TTY 或环境不支持时自动关闭)
_COLOR = _enable_windows_vt() and _stdout_is_tty()


class C:
    """ANSI 颜色常量, 关闭颜色时全部为空串"""
    RESET = "\033[0m"   if _COLOR else ""
    BOLD = "\033[1m"    if _COLOR else ""
    DIM = "\033[2m"     if _COLOR else ""
    RED = "\033[91m"    if _COLOR else ""
    GREEN = "\033[92m"  if _COLOR else ""
    YELLOW = "\033[93m" if _COLOR else ""
    BLUE = "\033[94m"   if _COLOR else ""
    MAGENTA = "\033[95m" if _COLOR else ""
    CYAN = "\033[96m"   if _COLOR else ""
    WHITE = "\033[97m"  if _COLOR else ""
    GRAY = "\033[90m"   if _COLOR else ""


def c(text, color):
    """给文本包裹颜色"""
    return "%s%s%s" % (color, text, C.RESET)


def players_color(online, max_):
    """按在线人数选择颜色: 有人绿色, 无人灰色, 未知黄色"""
    try:
        n = int(online)
    except (ValueError, TypeError):
        return C.YELLOW
    return C.GREEN if n > 0 else C.GRAY


def fmt_max(max_):
    """格式化最大人数: 负数(部分服务器表示无上限)显示为 ∞"""
    try:
        n = int(max_)
    except (ValueError, TypeError):
        return str(max_)
    return "∞" if n < 0 else str(n)


def info_line(msg):
    """蓝色 [*] 提示行"""
    print("%s %s" % (c("[*]", C.CYAN), msg))


def warn_line(msg):
    """黄色 [!] 警告行"""
    print("%s %s" % (c("[!]", C.YELLOW), msg))


def ok_line(msg):
    """绿色 [+] 成功行"""
    print("%s %s" % (c("[+]", C.GREEN), msg))


# ----------------------------- MC 协议(SLP) -----------------------------

def write_varint(value):
    """将整数编码为 Minecraft VarInt 字节"""
    out = bytearray()
    value &= 0xFFFFFFFF  # 当作无符号 32 位处理
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def read_varint(sock):
    """从 socket 读取一个 VarInt"""
    num = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("读取 VarInt 时连接中断")
        b = byte[0]
        num |= (b & 0x7F) << (7 * i)
        if not (b & 0x80):
            break
    return num


def recv_all(sock, length):
    """精确读取 length 字节"""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("连接中断")
        data.extend(chunk)
    return bytes(data)


def slp_ping(ip, port, timeout):
    """
    对目标执行 Minecraft 服务器列表 Ping。
    成功返回解析后的服务器信息 dict, 失败返回 None。
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            host_bytes = ip.encode("utf-8")
            # 握手包: 包ID(0x00) + 协议版本 + 服务器地址 + 端口 + 下一状态(1=status)
            handshake = (
                write_varint(0x00)
                + write_varint(47)            # 协议版本(任意较通用值)
                + write_varint(len(host_bytes)) + host_bytes
                + struct.pack(">H", port)     # 无符号短整型端口
                + write_varint(1)             # 下一状态: 1 = 查询状态
            )
            sock.sendall(write_varint(len(handshake)) + handshake)

            # 状态请求包: 包ID(0x00), 空载荷
            request = write_varint(0x00)
            sock.sendall(write_varint(len(request)) + request)

            # 读取响应
            _packet_len = read_varint(sock)     # 整包长度
            packet_id = read_varint(sock)       # 包ID, 应为 0x00
            if packet_id != 0x00:
                return None
            json_len = read_varint(sock)        # JSON 字符串长度
            json_bytes = recv_all(sock, json_len)
            data = json.loads(json_bytes.decode("utf-8", errors="replace"))
            return parse_status(data, ip, port)
    except Exception:
        return None


def fix_mojibake(text):
    """修复"双重/多重编码"乱码(mojibake)。

    部分服务器(常见于老版本 + 某些插件/启动器)把 UTF-8 中文 MOTD
    错当成 Latin-1/CP1252 解码后再写进 SLP 响应, 导致我们收到形如
    'æ¬¢è¿' 甚至夹带大量 'Â' 的乱码。把它按 Latin-1 编回字节、
    再用 UTF-8 解码即可还原; 对多重编码用容错方式尽量恢复。

    仅在"还原后明显更像正常文本(中文增多)"时才采用, 避免误伤正常内容。
    """
    if not text:
        return text

    def cjk_count(s):
        return sum(1 for ch in s if 0x4E00 <= ord(ch) <= 0x9FFF)

    def latin_supp_count(s):
        # Latin-1 补充区(0x80-0xFF), 正常中文/英文 MOTD 不会出现
        return sum(1 for ch in s if 0x80 <= ord(ch) <= 0xFF)

    # 不含可疑字符则无需处理
    if latin_supp_count(text) < 2:
        return text

    def cleanup(s):
        s = s.replace("�", "").replace("\x00", "")
        s = re.sub("§.", "", s)   # 残留的 §颜色代码
        return " ".join(s.split())

    best = text
    best_cjk = cjk_count(text)
    cur = text
    # 多重编码: 最多尝试还原 3 轮, 取中文最多的结果
    for _ in range(3):
        try:
            cur = cur.encode("latin-1", "ignore").decode("utf-8", "replace")
        except Exception:
            break
        cleaned = cleanup(cur)
        if cjk_count(cleaned) > best_cjk:
            best = cleaned
            best_cjk = cjk_count(cleaned)
        # 没有可疑字符了就停止
        if latin_supp_count(cur) < 2:
            break

    return best

def extract_motd(desc):
    """从 description 字段(可能是字符串或聊天组件)提取纯文本 MOTD"""
    if isinstance(desc, str):
        text = desc
    elif isinstance(desc, dict):
        parts = []
        if "text" in desc:
            parts.append(desc.get("text", ""))
        for extra in desc.get("extra", []):
            if isinstance(extra, dict):
                parts.append(extra.get("text", ""))
            elif isinstance(extra, str):
                parts.append(extra)
        text = "".join(parts)
    else:
        text = str(desc)
    # 去掉颜色代码(§x)和多余空白
    text = re.sub(r"§.", "", text)
    text = " ".join(text.split())
    # 尝试修复部分服务器的双重编码乱码
    return fix_mojibake(text)


def parse_status(data, ip, port):
    """解析 SLP 返回的 JSON 为简洁结构"""
    version = data.get("version", {})
    players = data.get("players", {})
    sample = players.get("sample", []) or []
    names = [p.get("name", "") for p in sample if isinstance(p, dict)]
    return {
        "ip": ip,
        "port": port,
        "motd": extract_motd(data.get("description", "")),
        "version": version.get("name", "未知"),
        "protocol": version.get("protocol", -1),
        "online": players.get("online", 0),
        "max": players.get("max", 0),
        "players": names,
    }


# ----------------------------- 本机网段检测 -----------------------------

def detect_local_networks():
    """
    检测本机所有 IPv4 网卡的网段。
    返回 [(ip, netmask), ...]。Windows 解析 ipconfig, 其它平台尽量回退。
    """
    results = []
    try:
        if sys.platform.startswith("win"):
            out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL
            ).decode("gbk", errors="replace")
            ip = mask = None
            for line in out.splitlines():
                m_ip = re.search(r"IPv4.*?:\s*([\d.]+)", line)
                m_mask = re.search(r"(?:子网掩码|Subnet Mask).*?:\s*([\d.]+)", line)
                if m_ip:
                    ip = m_ip.group(1)
                if m_mask:
                    mask = m_mask.group(1)
                    if ip:
                        results.append((ip, mask))
                        ip = mask = None
        else:
            out = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr", "show"], stderr=subprocess.DEVNULL
            ).decode(errors="replace")
            for line in out.splitlines():
                m = re.search(r"inet\s+([\d.]+)/(\d+)", line)
                if m:
                    cidr = ipaddress.ip_network(
                        "%s/%s" % (m.group(1), m.group(2)), strict=False
                    )
                    results.append((m.group(1), str(cidr.netmask)))
    except Exception:
        pass
    # 过滤回环
    return [(ip, mask) for ip, mask in results if not ip.startswith("127.")]


def networks_to_targets(nets, max_hosts=1024):
    """
    将检测到的网卡网段转换为待扫描的 IP 列表。
    网段过大(如 Radmin 的 /8)时, 收窄为本机所在 /24, 避免扫描上百万地址。
    """
    targets = []
    for ip, mask in nets:
        try:
            net = ipaddress.ip_network("%s/%s" % (ip, mask), strict=False)
        except Exception:
            continue
        if net.num_addresses > max_hosts:
            # 收窄为本机所在的 /24
            net = ipaddress.ip_network("%s/24" % ip, strict=False)
            print("[!] 网段 %s/%s 过大, 仅扫描 %s (如需更大范围请用 -t 指定)"
                  % (ip, mask, net))
        targets.extend(str(h) for h in net.hosts())
    return targets


# ----------------------------- 目标/端口解析 -----------------------------

def parse_targets(spec):
    """
    解析目标字符串, 支持逗号分隔的:
      单个IP / 主机名 / CIDR(1.2.3.0/24) / 范围(1.2.3.1-1.2.3.50 或 1.2.3.1-50)
    """
    ips = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:  # CIDR
            net = ipaddress.ip_network(part, strict=False)
            ips.extend(str(h) for h in net.hosts())
        elif "-" in part:  # 范围
            start, end = part.split("-", 1)
            start = start.strip()
            end = end.strip()
            start_ip = ipaddress.ip_address(start)
            if "." in end:
                end_ip = ipaddress.ip_address(end)
            else:  # 简写形式: 只给最后一段
                base = ".".join(start.split(".")[:-1])
                end_ip = ipaddress.ip_address("%s.%s" % (base, end))
            cur = int(start_ip)
            while cur <= int(end_ip):
                ips.append(str(ipaddress.ip_address(cur)))
                cur += 1
        else:  # 单 IP 或主机名
            try:
                ipaddress.ip_address(part)
                ips.append(part)
            except ValueError:
                ips.append(socket.gethostbyname(part))
    return ips


def parse_ports(spec):
    """解析端口字符串: 25565 / 25565-25600 / 25565,25566,30000-30010"""
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    # 去重保序
    seen = set()
    result = []
    for p in ports:
        if 0 < p <= 65535 and p not in seen:
            seen.add(p)
            result.append(p)
    return result


# ----------------------------- 扫描主流程 -----------------------------

_print_lock = threading.Lock()


def scan_one(ip, port, timeout):
    """先快速 TCP 探测端口, 开放再做 SLP 确认"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except Exception:
        return None
    return slp_ping(ip, port, timeout)


def measure_latency(ip, port, timeout=2.0, attempts=3):
    """测量到服务器的延迟(毫秒)。

    用 TCP 三次握手的往返耗时近似延迟: 比 ICMP ping 更可靠, 因为很多
    Radmin/VPN 主机禁 ping, 而能开 MC 服务器的端口必然可连。
    多次取最小值以减少抖动。失败返回 None。
    """
    import time
    best = None
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                pass
        except Exception:
            continue
        elapsed = (time.perf_counter() - start) * 1000.0
        if best is None or elapsed < best:
            best = elapsed
    return round(best, 1) if best is not None else None


def latency_color(ms):
    """按延迟值选择 ANSI 颜色: 低绿, 中黄, 高红, 未知灰"""
    if ms is None:
        return C.GRAY
    if ms < 80:
        return C.GREEN
    if ms < 200:
        return C.YELLOW
    return C.RED


def print_server_card(info, title="找到 Minecraft 服务器", idx=None):
    """以彩色卡片形式打印一个服务器信息(线程安全)"""
    num = "" if idx is None else c("#%d " % idx, C.BOLD + C.MAGENTA)
    addr = c("%s:%s" % (info["ip"], info["port"]), C.BOLD + C.CYAN)
    online = info.get("online", "?")
    max_ = fmt_max(info.get("max", "?"))
    pc = players_color(online, info.get("max", "?"))
    with _print_lock:
        print("\n%s %s%s" % (c("┌─", C.GREEN), num, addr))
        print("%s %s %s" % (c("│", C.GREEN), c("MOTD", C.DIM),
                            c(info.get("motd") or "(空)", C.WHITE)))
        ver = info.get("version", "未知")
        proto = info.get("protocol", "?")
        print("%s %s %s %s" % (c("│", C.GREEN), c("版本", C.DIM),
                               c(ver, C.YELLOW), c("(协议 %s)" % proto, C.GRAY)))
        print("%s %s %s" % (c("│", C.GREEN), c("在线", C.DIM),
                            c("%s / %s" % (online, max_), pc)))
        if info.get("players"):
            print("%s %s %s" % (c("│", C.GREEN), c("玩家", C.DIM),
                                c(", ".join(info["players"]), C.BLUE)))
        print(c("└─", C.GREEN))


def print_server(info):
    print_server_card(info)


def run_scan(ips, ports, timeout, workers):
    total = len(ips) * len(ports)
    print("[*] 开始扫描: %d 个 IP × %d 个端口 = %d 个目标, 线程 %d"
          % (len(ips), len(ports), total, workers))
    found = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_one, ip, port, timeout): (ip, port)
            for ip in ips for port in ports
        }
        for fut in as_completed(futures):
            done += 1
            if done % 500 == 0 or done == total:
                with _print_lock:
                    sys.stdout.write("\r[*] 进度 %d/%d" % (done, total))
                    sys.stdout.flush()
            info = fut.result()
            if info:
                print_server(info)
                found.append(info)
    print()
    return found


# ----------------------------- 局域网广播监听 -----------------------------

def listen_lan(duration):
    """
    监听"对局域网开放"世界发出的 UDP 多播广播。
    格式: [MOTD]内容[/MOTD][AD]端口[/AD]  发往 224.0.2.60:4445
    """
    MCAST_GRP = "224.0.2.60"
    MCAST_PORT = 4445
    info_line("监听局域网广播 %s:%d (%d 秒)..." % (MCAST_GRP, MCAST_PORT, duration))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception as e:
        warn_line("无法加入多播组: %s" % e)
        return []
    sock.settimeout(duration)
    seen = set()
    found = []
    import time
    end = time.time() + duration
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            break
        except Exception:
            break
        text = data.decode("utf-8", errors="replace")
        m_motd = re.search(r"\[MOTD\](.*?)\[/MOTD\]", text)
        m_ad = re.search(r"\[AD\](.*?)\[/AD\]", text)
        if m_ad:
            port = m_ad.group(1).strip()
            motd = extract_motd(m_motd.group(1)) if m_motd else ""
            key = (addr[0], port)
            if key in seen:
                continue
            seen.add(key)
            idx = len(found) + 1
            # 广播包不含版本/人数, 对该服务器做一次 SLP 探测补全信息
            info = None
            try:
                info = slp_ping(addr[0], int(port), 2.0)
            except (ValueError, Exception):
                info = None
            if info:
                # 用 SLP 的 MOTD 覆盖(更完整), 但保留广播 MOTD 作兜底
                info["motd"] = info["motd"] or motd
                print_server_card(info, title="发现对局域网开放的世界", idx=idx)
                found.append(info)
            else:
                fallback = {"ip": addr[0], "port": port, "motd": motd,
                            "version": c("(SLP 探测失败, 仅广播信息)", C.RED),
                            "protocol": "?", "online": "?", "max": "?",
                            "players": []}
                print_server_card(fallback, title="发现对局域网开放的世界", idx=idx)
                found.append(fallback)
    return found


# ----------------------------- 命令行入口 -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Minecraft 局域网/VPN 服务器扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--targets",
                        help="目标(逗号分隔): IP / CIDR / 范围。留空则自动检测本机网段")
    parser.add_argument("-p", "--ports", default="25565-25600",
                        help="端口(逗号分隔, 支持范围), 默认 25565-25600")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="单个连接超时秒数, 默认 1.0")
    parser.add_argument("--workers", type=int, default=200,
                        help="并发线程数, 默认 200")
    parser.add_argument("--scan", action="store_true",
                        help="自动检测本机网段并主动扫描(不指定 -t 时需要此开关才扫描)")
    parser.add_argument("--lan", action="store_true",
                        help="主动扫描的同时监听局域网'对局域网开放'广播")
    parser.add_argument("--lan-time", type=int, default=15,
                        help="局域网广播监听时长(秒), 默认 15")
    parser.add_argument("-o", "--output",
                        help="将结果导出到文件。按扩展名自动判断格式: .json 导出 JSON, 其它(如 .txt)导出纯文本")
    parser.add_argument("--format", choices=["json", "txt"],
                        help="强制指定导出格式(覆盖按扩展名的自动判断)")
    args = parser.parse_args()

    all_found = []

    # 默认行为: 不指定 -t / --scan 时, 只监听局域网广播
    if not args.targets and not args.scan:
        all_found += listen_lan(args.lan_time)
        summary(all_found)
        export_results(all_found, args.output, args.format)
        return

    # 确定目标 IP 列表
    if args.targets:
        ips = parse_targets(args.targets)
    else:  # --scan: 自动检测本机网段
        nets = detect_local_networks()
        if not nets:
            print("[!] 未能自动检测到网段, 请用 -t 指定目标")
            return
        print("[*] 检测到本机网段:")
        for ip, mask in nets:
            print("      %s / %s" % (ip, mask))
        ips = networks_to_targets(nets)

    ports = parse_ports(args.ports)
    if not ips or not ports:
        print("[!] 目标或端口为空")
        return

    all_found += run_scan(ips, ports, args.timeout, args.workers)

    if args.lan:
        all_found += listen_lan(args.lan_time)

    summary(all_found)
    export_results(all_found, args.output, args.format)


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text):
    """去掉字符串里的 ANSI 颜色码, 用于写入文件"""
    return _ANSI_RE.sub("", str(text))


def clean_record(f):
    """把一条服务器记录清洗成纯文本(去颜色码), 供导出使用"""
    return {
        "ip": f.get("ip", ""),
        "port": f.get("port", ""),
        "motd": strip_ansi(f.get("motd", "")),
        "version": strip_ansi(f.get("version", "未知")),
        "protocol": f.get("protocol", "?"),
        "online": f.get("online", "?"),
        "max": f.get("max", "?"),
        "players": [strip_ansi(p) for p in f.get("players", [])],
    }


def export_results(found, output, fmt):
    """将结果导出到文件。output 为路径, fmt 可强制 'json'/'txt', 否则按扩展名判断"""
    if not output:
        return
    if not found:
        warn_line("没有结果可导出, 跳过写文件")
        return
    # 确定格式
    if not fmt:
        fmt = "json" if output.lower().endswith(".json") else "txt"
    records = [clean_record(f) for f in found]
    try:
        if fmt == "json":
            with open(output, "w", encoding="utf-8") as fp:
                json.dump(records, fp, ensure_ascii=False, indent=2)
        else:
            with open(output, "w", encoding="utf-8") as fp:
                fp.write("# Minecraft 服务器扫描结果  共 %d 个\n\n" % len(records))
                for i, r in enumerate(records, 1):
                    fp.write("[%d] %s:%s\n" % (i, r["ip"], r["port"]))
                    fp.write("    MOTD : %s\n" % (r["motd"] or "(空)"))
                    fp.write("    版本 : %s (协议 %s)\n" % (r["version"], r["protocol"]))
                    fp.write("    在线 : %s / %s\n" % (r["online"], fmt_max(r["max"])))
                    if r["players"]:
                        fp.write("    玩家 : %s\n" % ", ".join(r["players"]))
                    fp.write("\n")
        ok_line("已导出 %d 条结果到 %s (%s)" % (len(records), output, fmt))
    except OSError as e:
        warn_line("写文件失败: %s" % e)


def summary(found):
    print("\n" + "=" * 50)
    if found:
        print("[*] 共找到 %d 个 Minecraft 服务器:" % len(found))
        for f in found:
            print("      %s:%s  %s" % (f["ip"], f["port"], f.get("motd", "")))
    else:
        print("[*] 未找到任何 Minecraft 服务器")
    print("=" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已中断")
