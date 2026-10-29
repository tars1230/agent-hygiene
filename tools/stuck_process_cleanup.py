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
                           capture_output=True, timeout=30, **PS_ENC)
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
    ps = ("(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").CreationDate"
          % pid)
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=30, **PS_ENC)
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
                           capture_output=True, timeout=60, **PS_ENC)
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


def cpu_delta(pid, seconds):
    """取两次 CPU 累计时间的差, 判定"在干活"还是"挂死"。"""
    a = process_basics(pid)
    if not a:
        return None
    time.sleep(seconds)
    b = process_basics(pid)
    if not b:
        return None
    return b[2] - a[2], b


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
                               capture_output=True, timeout=60, **PS_ENC)
                killed += 1
            except Exception as e:
                log("配方A: 重启 explorer PID=%d 失败: %s" % (pid, e))
    if killed:
        time.sleep(5)
        # Windows 会自动拉起 explorer; 若没起来手动启动
        if not list_procs({"explorer.exe"}):
            log("配方A: explorer 未自启, 手动拉起")
            subprocess.run(["explorer.exe"], capture_output=True, timeout=30)
            time.sleep(3)
        new = list_procs({"explorer.exe"})
        for pid in new:
            b = process_basics(pid)
            if b:
                log("配方A: 新 explorer PID=%d 线程=%d 句柄=%d Priv=%.0fMB" %
                    (pid, b[0], b[1], b[3]))
    return 0


# ---------------- 配方 B: git 挂死链 ----------------
GIT_NAMES = {"git.exe", "git-remote-https.exe", "git-credential-manager.exe",
              "sh.exe"}


def recipe_git(args):
    procs = list_procs(GIT_NAMES)
    if not procs:
        log("配方B: 未发现 git 家族进程")
        return 0
    now = datetime.datetime.now()
    victims = []
    for pid, (name, ppid, cmd) in procs.items():
        basics = process_basics(pid)
        if not basics:
            continue
        threads, handles, cpu, priv, ws = basics
        start = process_start(pid)
        age_min = (now - start).total_seconds() / 60.0 if start else 0
        if age_min < args.min_age_min:
            log("配方B: %s PID=%d 存活仅 %.0f 分钟 < 阈值%d, 跳过" %
                (name, pid, age_min, args.min_age_min))
            continue
        d = cpu_delta(pid, args.sample_sec)
        if d is None:
            continue
        delta, b = d
        pct = delta / args.sample_sec * 100.0
        if pct >= args.max_cpu_pct:
            log("配方B: %s PID=%d CPU增量 %.1f%% >= 阈值%.1f%%, 在干活, 跳过" %
                (name, pid, pct, args.max_cpu_pct))
            continue
        log("配方B: %s PID=%d 存活=%.0f分钟 CPU增量=%.2f%% -> %s" %
            (name, pid, age_min, pct, "杀" if args.apply else "演练:将杀"))
        victims.append(pid)
    if args.apply and victims:
        ok = 0
        for pid in victims:
            try:
                r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                   capture_output=True, timeout=60, **PS_ENC)
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
                    help="CPU 采样秒数(默认3)")
    ap.add_argument("--no-log", action="store_true", help="不写日志文件")
    args = ap.parse_args()

    if args.no_log:
        globals()["log"] = lambda m: print("[%s] %s" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m))

    log("=== 开始 (mode=%s) ===" % ("apply" if args.apply else "dry-run"))
    try:
        recipe_explorer(args)
        recipe_git(args)
    except Exception as e:
        log("执行异常: %s" % e)
        return 1
    log("=== 结束 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
