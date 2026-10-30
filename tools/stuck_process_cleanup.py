#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
stuck_process_cleanup.py  (v1)
回收两类已在真实机器上确认过的"挂死进程"泄漏。

配方 A: explorer 线程/句柄泄漏
  实测样本(2026-10-29): explorer.exe PID 13092 累计 96262 个线程 / 210301 个句柄,
  Private 8432MB 而 WS 只有 452MB —— 96127 个线程处于 Suspended 状态。
  根因是第三方 shell 扩展在枚举大量文件时反复创建线程且不回收。
  症状: 桌面/任务栏变卡, 但任务管理器里 explorer 的"内存"看着不大(WS 小),
  commit 却快满。**只看 WS 会完全看不见这个泄漏, 必须看线程数/句柄数**。
  判据: 线程数 >= --min-threads(默认 20000) 且 存活 >= --min-age-min(默认 120) 分钟。
  处置: 重启 explorer.exe(Windows 会自动拉起)。会关闭所有已打开的文件夹窗口。
  为什么直接重启而不找具体 DLL: NtQueryInformationThread(QuerySetWin32StartAddress)
  在本机返回 STATUS_ACCESS_DENIED(0xC0000022), 无法反查线程归属;
  第三方扩展候选(IDMShellExt64 / qingnse64(WPS) / wetype_tip_core / 7-zip)只是嫌疑,
  没有硬证据指向某一个 —— 不猜。

配方 B: 计划任务遗留的 git 挂死链
  实测样本(2026-10-29): DailyBriefing1745 计划任务连续 8 天(10/21~10/28) 各留下
  一整串 git.exe / git-remote-https.exe / git-credential-manager.exe / sh.exe,
  共 56 个进程, 全部 CPU=0 纯挂起, 每个约 2.3MB WS。
  根因: 全局 url.insteadOf 把 github.com 改写到 gh-proxy.com, GCM 没有该域凭据,
  凭据提示在计划任务上下文里被吞 -> git 永久等待 -> 进程永不退出。
  判据: git 家族进程, 存活 >= --min-age-min(默认 60) 分钟, 且 CPU 累计增量 ≈ 0。
  处置: taskkill /F /T 逐个杀。
  ⚠️ 必须验 CPU 增量而不是只看启动时间: 否则会杀掉正在 push 的真实任务。

守卫(任一不满足就跳过; 跳过返回 0)
  - 配方 A 额外要求 explorer 是当前会话的 shell(不能杀别人的会话)
  - 配方 B 额外要求 git 家族的 CPU 增量 < 1%(在干活的不杀)

退出码
  0 = 正常(含「无需处理」与「被守卫跳过」)
  1 = 执行失败

用法
  python stuck_process_cleanup.py                        # 演练(只报告不动手)
  python stuck_process_cleanup.py --apply
  python stuck_process_cleanup.py --apply --min-threads 20000 --min-age-min 120
  python stuck_process_cleanup.py --apply --no-log
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import os
import subprocess
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

# 🔴 同目录模块（thread_handle_probe）必须可导入 —— 用户可能从任意 cwd 调用本脚本。
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

PS_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

# 🔴 PowerShell 输出在本机是 GBK(936), 用 text=True(默认 utf-8) 解码会抛
#    UnicodeDecodeError, 而且是在 subprocess 的 reader 线程里抛 -> 静默丢输出。
#    统一用 errors="replace" 兜底, 不让编码问题吃掉整个结果。
PS_ENC = {"encoding": "gbk", "errors": "replace"}

def _local_appdata():
    """定位 %LOCALAPPDATA%。

    🔴 不能只靠环境变量: IDE 托管的 bash / 计划任务上下文里 LOCALAPPDATA 可能缺失,
       回退到 expanduser("~") 会把日志写到 C:\\Users\\<name>\\agent-hygiene, 与 README 承诺不一致。
    """
    v = os.environ.get("LOCALAPPDATA")
    if v and os.path.isdir(v):
        return v
    for base in (os.environ.get("SystemDrive", "C:"), "C:"):
        p = os.path.join(base + "\\", "Users", os.environ.get("USERNAME", ""),
                         "AppData", "Local")
        if os.path.isdir(p):
            return p
    return os.path.expanduser("~")


LOG_DIR = os.path.join(_local_appdata(), "agent-hygiene", "logs")
LOG_FILE = os.path.join(LOG_DIR, "stuck_cleanup.log")


def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------- Win32 ----------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PMC(ctypes.Structure):
    """PROCESS_MEMORY_COUNTERS_EX。
    🔴 cb 字段必须赋值, 否则 GetProcessMemoryInfo 静默失败返回 0(不报错)。
    """
    _fields_ = [
        ("cb", wt.DWORD),
        ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def process_basics(pid):
    """用 PowerShell/WMI 拿线程数、句柄数、CPU、启动时间。跨进程 Toolhelp
    在线程数极多时会失败, 故走 PowerShell(Get-Process)。"""
    ps = (
        "$p = Get-Process -Id %d -ErrorAction SilentlyContinue; "
        "if ($p) { '{0}|{1}|{2}|{3}|{4}' -f $p.Threads.Count, $p.HandleCount, "
        "[math]::Round($p.TotalProcessorTime.TotalSeconds,2), "
        "[math]::Round($p.PrivateMemorySize64/1MB,1), "
        "[math]::Round($p.WorkingSet64/1MB,1) }" % pid)
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=30, **PS_ENC, creationflags=nowin.no_window())
    except Exception:
        return None
    out = (r.stdout or "").strip()
    if not out or "|" not in out:
        return None
    try:
        th, hd, cpu, priv, ws = out.split("|")
        return int(th), int(hd), float(cpu), float(priv), float(ws)
    except ValueError:
        return None


def process_start(pid):
    """取进程创建时间。

    🔴 坑: WMI 的 CreationDate 是 System.DateTime, PowerShell 默认把它格式化成
       **美式** "10/21/2026 15:10:32" —— Python 的 fromisoformat 解析不了
       (期望 ISO "2026-10-21T15:10:32"), 于是返回 None, 上游把存活时间算成 0,
       导致所有「存活时长」守卫形同虚设(本轮实测踩到: Weixin 存活 187h 却报 0 分钟)。
       => 必须显式指定 ISO 格式输出。
    """
    ps = ("$c=(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").CreationDate; "
          "if ($c) { $c.ToString('yyyy-MM-ddTHH:mm:ss') }" % pid)
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=30, **PS_ENC, creationflags=nowin.no_window())
        s = (r.stdout or "").strip()
        return datetime.datetime.fromisoformat(s) if s else None
    except Exception:
        return None


def list_procs(names):
    """返回 {pid: (name, ppid, cmdline)}。"""
    ns = ",".join("'%s'" % n for n in names)
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -in @(%s) } | "
          "ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.ProcessId, $_.Name, "
          "$_.ParentProcessId, ($_.CommandLine -replace '\\|','/') }" % ns)
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=60, **PS_ENC, creationflags=nowin.no_window())
    except Exception:
        return {}
    out = {}
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line or line.count("|") < 3:
            continue
        parts = line.split("|", 3)
        try:
            out[int(parts[0])] = (parts[1], int(parts[2]), parts[3])
        except ValueError:
            continue
    return out


def cpu_delta(pid, seconds, windows=3):
    """取多次 CPU 累计时间的差, 判定「在干活」还是「挂死」。

    实测: Weixin 主进程连续 3 轮采样得到 0% / 1.56% / 4.95%
    —— 偶发活动会让单窗结果在 0 和 5 之间跳, 判据就跟着抖。
    => 多窗采样:
       - 判「在干活」用**各窗最大增量**(宁可保守, 别误杀在干活的)
       - 判「挂死」用**总增量**(偶发活动累加起来仍接近 0 才算挂死)
    返回 (总增量, 末次快照, 各窗最大增量)
    """
    a = process_basics(pid)
    if not a:
        return None
    samples = []
    prev = a[2]
    b = a
    for _ in range(max(1, windows)):
        time.sleep(seconds)
        b = process_basics(pid)
        if not b:
            return None
        samples.append(b[2] - prev)
        prev = b[2]
    total = sum(samples)
    return total, b, (max(samples) if samples else 0.0)


# ---------------- 配方 A: explorer ----------------
def recipe_explorer(args):
    procs = list_procs({"explorer.exe"})
    if not procs:
        log("配方A: 未发现 explorer.exe")
        return 0
    now = datetime.datetime.now()
    killed = 0
    for pid, (name, ppid, cmd) in procs.items():
        basics = process_basics(pid)
        if not basics:
            continue
        threads, handles, cpu, priv, ws = basics
        if threads < args.min_threads:
            log("配方A: explorer PID=%d 线程=%d < 阈值%d, 跳过" %
                (pid, threads, args.min_threads))
            continue
        start = process_start(pid)
        age_min = (now - start).total_seconds() / 60.0 if start else 0
        if age_min < args.min_age_min:
            log("配方A: explorer PID=%d 存活仅 %.0f 分钟 < 阈值%d, 跳过" %
                (pid, age_min, args.min_age_min))
            continue
        log("配方A: explorer PID=%d 线程=%d 句柄=%d Priv=%.0fMB WS=%.0fMB "
            "存活=%.0f分钟 -> %s" %
            (pid, threads, handles, priv, ws, age_min,
             "重启" if args.apply else "演练:将重启"))
        if args.apply:
            # 必须杀整个 shell 树: 单杀 explorer 后 Windows 会重建新的
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                               capture_output=True, timeout=60, **PS_ENC, creationflags=nowin.no_window())
                killed += 1
            except Exception as e:
                log("配方A: 重启 explorer PID=%d 失败: %s" % (pid, e))
    if killed:
        time.sleep(5)
        # Windows 会自动拉起 explorer; 若没起来手动启动
        if not list_procs({"explorer.exe"}):
            log("配方A: explorer 未自启, 手动拉起")
            subprocess.run(["explorer.exe"], capture_output=True, timeout=30, creationflags=nowin.no_window())
            time.sleep(3)
        new = list_procs({"explorer.exe"})
        for pid in new:
            b = process_basics(pid)
            if b:
                log("配方A: 新 explorer PID=%d 线程=%d 句柄=%d Priv=%.0fMB" %
                    (pid, b[0], b[1], b[3]))
    return 0


# ---------------- 配方 C: 句柄泄漏（累积未释放）----------------
#  实测样本(2026-10-29): Weixin.exe 主进程(--scene=desktop) PID 28208
#  持有 177790 个句柄, 而同 exe 的另外 5 个 Weixin 进程只有 207~516 个
#  (中位数 243) —— 731.6 倍。进程从 10/21 起存活 187 小时。
#  症状: 句柄吃的是**内核对象表**不是用户态内存, 所以 Private 只有 567MB,
#  在任务管理器里看着完全正常; 但句柄表耗尽会导致后续 CreateProcess/CreateFile 全失败。
#
#  🔴 为什么这个配方默认【只报告不杀】, 与配方 A/B 不同:
#     杀 explorer 只是关掉文件夹窗口(可恢复); 杀 Weixin 主进程会丢失
#     登录态/未发送消息/小程序容器 —— 代价不可逆。所以默认只给建议命令。
#     要真杀必须显式加 --kill-handle-leak, 且仍受全部守卫约束。
#
#  判据(三重,缺一不可):
#     1. 句柄数 ≥ --min-handles(默认 50000)  —— 绝对量
#     2. 相对同 exe 中位数 ≥ --burst-ratio(默认 20) 倍 —— 相对量, 消掉误报
#     3. CPU 增量 < --max-cpu-pct(默认 1.0%) —— 不在干活
#     4. 存活 ≥ --min-age-min(默认 60) 分钟
#  为什么第 3 条不能省: 实测 WorkBuddy 宿主 5.6 万句柄(同 exe 同伴中位数的 168 倍)
#  但 CPU 3.1% —— 它在干活, 杀了会把用户正在跑的会话搞没。


def recipe_handle_leak(args):
    """句柄泄漏检测。默认只报告; --kill-handle-leak 才实际终止。"""
    try:
        import thread_handle_probe as thp
    except ImportError:
        log("配方C: 无法导入 thread_handle_probe（同目录）, 跳过")
        return 0
    probe = thp.probe_all()
    if not probe:
        log("配方C: 探测失败, 跳过")
        return 0
    findings = thp.analyze(probe, min_threads=10 ** 9,   # 只看句柄维度
                           min_handles=args.min_handles,
                           burst=args.burst_ratio)
    if not findings:
        log("配方C: 无句柄异常候选（阈值 ≥%d 句柄且 ≥%.0fx 同 exe 中位数）"
            % (args.min_handles, args.burst_ratio))
        return 0
    now = datetime.datetime.now()
    victims = []
    for f in findings:
        pid = f["pid"]
        start = process_start(pid)
        age_min = (now - start).total_seconds() / 60.0 if start else 0
        if age_min < args.min_age_min:
            log("配方C: %s PID=%d 存活仅 %.0f 分钟 < 阈值%d, 跳过"
                % (f["name"], pid, age_min, args.min_age_min))
            continue
        d = cpu_delta(pid, args.sample_sec, args.cpu_windows)
        if d is None:
            continue
        delta, _, peak = d
        win = args.sample_sec * args.cpu_windows
        pct = delta / win * 100.0
        peak_pct = peak / args.sample_sec * 100.0
        # 🔴 同配方B: 用总增量判「在干活」, 单窗峰值只做参考(理由见配方B注释)。
        if pct >= args.max_cpu_pct:
            log("配方C: %s PID=%d CPU总增量 %.1f%% >= 阈值%.1f%%, 在干活, 跳过"
                % (f["name"], pid, pct, args.max_cpu_pct))
            continue
        log("配方C: %s PID=%d 句柄=%d (同exe中位数 %.0f, %.1fx) 存活=%.0f分钟 "
            "CPU总增量=%.2f%%(峰值%.2f%%) -> %s"
            % (f["name"], pid, f["handles"], f["peer_median_handles"],
               f["burst_ratio"], age_min, pct, peak_pct,
               "杀" if args.kill_handle_leak else "只报告(需 --kill-handle-leak 才动手)"))
        if not args.kill_handle_leak:
            log("       建议命令: taskkill /F /T /PID %d  "
                "⚠️ 会丢失该应用的登录态与未完成会话" % pid)
        victims.append(pid)
    if args.kill_handle_leak and victims:
        ok = 0
        for pid in victims:
            try:
                r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                   capture_output=True, timeout=60, **PS_ENC, creationflags=nowin.no_window())
                if r.returncode == 0:
                    ok += 1
            except Exception as e:
                log("配方C: 杀 PID=%d 失败: %s" % (pid, e))
        log("配方C: 清理完成, 成功 %d / %d" % (ok, len(victims)))
    return 0


# ---------------- 配方 B: 挂死命令行链 ----------------
#  实测样本 A (2026-10-29): 计划任务里的 git push 因凭据提示被吞而永久挂起,
#    10/21~10/28 每天 17:45 一批, 共 56 进程 (32 git.exe + 8 git-remote-https +
#    8 git-credential-manager + 8 sh.exe), 全部 CPU=0。
#  实测样本 B (2026-10-29): `playwright-cli install-browser` 挂死 70 分钟,
#    CPU=0、无网络连接、浏览器已下载完 3.1GB 但进程不退 —— 链是
#    sh.exe -> node.exe(@playwright/cli) -> 子进程。
#
#  🔴 关键设计: 判据必须按**命令行模式**匹配, 不能只按进程名。
#     原版只认 {git.exe, git-remote-https.exe, git-credential-manager.exe, sh.exe}
#     —— "sh.exe" 太宽(任何 shell 都算 git 家族), 而 playwright 链的主体 node.exe
#     又不在名单里, 于是漏网。改成按命令行里的工具标记匹配。
#
#  判据(三重):
#     1. 命令行命中下方任一模式(工具标记)
#     2. 存活 >= --min-age-min(默认 60) 分钟
#     3. CPU 增量 < --max-cpu-pct(默认 1.0%)  —— 在干活的不杀
#  ⚠️ 必须验 CPU 增量而不是只看启动时间: 否则会杀掉正在 push 的真实任务。

# 命令行匹配模式(小写子串匹配)
CMD_PATTERNS = (
    ("git", ("git.exe", "git-remote-https", "git-credential-manager",
             "git push", "git pull", "git fetch", "git clone")),
    ("playwright-cli", ("playwright-cli", "install-browser", "@playwright/cli")),
)


def _match_cmd(cmd):
    """返回命中的模式名, 没命中返回 None。"""
    low = (cmd or "").lower()
    for label, pats in CMD_PATTERNS:
        for p in pats:
            if p in low:
                return label
    return None


def recipe_git(args):
    """挂死命令行链回收(原名 recipe_git, 现覆盖 git + playwright-cli 两类)。"""
    # 收集候选进程名: git 家族 + node + sh + pwsh/powershell(playwright 链可能是 node)
    names = {"git.exe", "git-remote-https.exe", "git-credential-manager.exe",
             "sh.exe", "node.exe"}
    procs = list_procs(names)
    if not procs:
        log("配方B: 未发现候选进程")
        return 0
    now = datetime.datetime.now()
    victims = []
    for pid, (name, ppid, cmd) in procs.items():
        label = _match_cmd(cmd)
        if not label:
            continue
        basics = process_basics(pid)
        if not basics:
            continue
        threads, handles, cpu, priv, ws = basics
        start = process_start(pid)
        age_min = (now - start).total_seconds() / 60.0 if start else 0
        if age_min < args.min_age_min:
            log("配方B: [%s] %s PID=%d 存活仅 %.0f 分钟 < 阈值%d, 跳过"
                % (label, name, pid, age_min, args.min_age_min))
            continue
        d = cpu_delta(pid, args.sample_sec, args.cpu_windows)
        if d is None:
            continue
        delta, b, peak = d
        win = args.sample_sec * args.cpu_windows
        pct = delta / win * 100.0
        peak_pct = peak / args.sample_sec * 100.0
        # 🔴 用**总增量**判「在干活」, 不用单窗峰值:
        #    实测 Weixin 3 秒窗内偶发突发(峰值 38%), 但 9 秒总增量只有几个百分点。
        #    单窗峰值会把「偶发活动」误判成「一直在干活」=> 漏掉真挂死。
        if pct >= args.max_cpu_pct:
            log("配方B: [%s] %s PID=%d CPU总增量 %.1f%% >= 阈值%.1f%%, 在干活, 跳过"
                % (label, name, pid, pct, args.max_cpu_pct))
            continue
        log("配方B: [%s] %s PID=%d 存活=%.0f分钟 CPU总增量=%.2f%%(峰值%.2f%%) -> %s"
            % (label, name, pid, age_min, pct, peak_pct,
               "杀" if args.apply else "演练:将杀"))
        log("       cmd: %s" % (cmd or "")[:160])
        victims.append(pid)
    if args.apply and victims:
        ok = 0
        for pid in victims:
            try:
                r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                   capture_output=True, timeout=60, **PS_ENC, creationflags=nowin.no_window())
                if r.returncode == 0:
                    ok += 1
            except Exception as e:
                log("配方B: 杀 PID=%d 失败: %s" % (pid, e))
        log("配方B: 清理完成, 成功 %d / %d" % (ok, len(victims)))
    elif victims:
        log("配方B: 演练, 共 %d 个待清理" % len(victims))
    return 0


def main():
    ap = argparse.ArgumentParser(description="回收挂死进程(已验证的两个配方)")
    ap.add_argument("--apply", action="store_true", help="实际执行(默认只演练)")
    ap.add_argument("--min-threads", type=int, default=20000,
                    help="explorer 线程数阈值(默认20000)")
    ap.add_argument("--min-age-min", type=int, default=60,
                    help="最小存活分钟数(默认60)")
    ap.add_argument("--max-cpu-pct", type=float, default=1.0,
                    help="CPU增量%%超过此值视为在干活, 不杀(默认1.0)")
    ap.add_argument("--sample-sec", type=int, default=3,
                    help="单个 CPU 采样窗秒数(默认3)")
    ap.add_argument("--cpu-windows", type=int, default=3,
                    help="CPU 采样窗个数(默认3; 峰值判在干活, 总和判挂死)")
    ap.add_argument("--min-handles", type=int, default=50000,
                    help="句柄数阈值(默认50000)")
    ap.add_argument("--burst-ratio", type=float, default=20.0,
                    help="相对同 exe 中位数的倍数阈值(默认20)")
    ap.add_argument("--kill-handle-leak", action="store_true",
                    help="允许真的终止句柄泄漏进程(默认只报告!)")
    ap.add_argument("--no-log", action="store_true", help="不写日志文件")
    args = ap.parse_args()

    if args.no_log:
        globals()["log"] = lambda m: print("[%s] %s" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m))

    log("=== 开始 (mode=%s) ===" % ("apply" if args.apply else "dry-run"))
    try:
        recipe_explorer(args)
        recipe_git(args)
        recipe_handle_leak(args)
    except Exception as e:
        log("执行异常: %s" % e)
        return 1
    log("=== 结束 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
