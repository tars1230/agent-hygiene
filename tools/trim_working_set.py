"""内存 trim 实验：对指定进程组调用 EmptyWorkingSet，把闲置内存页还给系统。

原理：
  进程的工作集（WorkingSet）里有一部分是「已提交但当前没用到的页」。
  `EmptyWorkingSet` 让系统把这些页从物理内存里撤走（可换出/可丢弃），
  **不杀进程、不丢数据、不影响功能**，下次访问时由缺页中断换回来。

这正好命中本机的实际情况：微信的 WMPF 小程序容器 9 个进程 CPU = 0.00%，
工作集 940 MB 但私有提交只有 707 MB —— 多出来的 232 MB 就是躺着没用的页。

⚠️ 边界：
  - 只对**低 CPU 占用**的进程做（否则会拖慢正在干活的进程）
  - 默认目标进程：WeChatAppEx.exe（微信小程序容器）、wetype_*.exe（微信输入法）
  - 不碰 Weixin.exe 主进程（聊天本体，工作集回收会卡顿）

用法：
    python trim_working_set.py                 # 演练
    python trim_working_set.py --apply         # 真执行
    python trim_working_set.py --apply --target Weixin.exe
    python trim_working_set.py --apply --all   # 所有低 CPU 进程
"""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
import time
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fast_probe  # noqa: E402

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]

# 🔴 EmptyWorkingSet 导出在 **psapi.dll**（kernel32 没有这个导出）。
psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
psapi.EmptyWorkingSet.restype = wintypes.BOOL

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_QUOTA = 0x0100
PROCESS_VM_OPERATION = 0x0008
MEM_RESET = 0x8000


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def counters(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | 0x1000, False, pid)
    if not h:
        return None
    c = PROCESS_MEMORY_COUNTERS()
    c.cb = ctypes.sizeof(c)
    ok = psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
    k32.CloseHandle(h)
    return c if ok else None


def phys_mem():
    m = fast_probe.memory_status()
    return (m.get("avail_phys_mb", 0) / 1024.0,
            (m.get("total_commit_mb", 0) - m.get("avail_commit_mb", 0)) / 1024.0,
            m.get("load_pct"))


def trim_pid(pid):
    """返回释放的工作集 MB；失败返回 None。"""
    h = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return None
    ok = psapi.EmptyWorkingSet(h)
    k32.CloseHandle(h)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="真执行（默认演练）")
    ap.add_argument("--target", action="append", default=[],
                    help="目标进程名，可重复。默认 WeChatAppEx.exe + wetype_*.exe")
    ap.add_argument("--max-cpu", type=float, default=5.0,
                    help="CPU 增量超过此百分比（%%）的进程跳过，默认 5")
    ap.add_argument("--all", action="store_true", help="对所有低 CPU 进程做")
    ap.add_argument("--wait", type=int, default=5, help="执行后等待秒数再采样")
    args = ap.parse_args()

    targets = args.target or ["WeChatAppEx.exe", "wetype_server.exe",
                              "wetype_renderer.exe", "wetype_service.exe"]

    print("=" * 70)
    print("内存 trim 实验（EmptyWorkingSet）—— 不杀进程，只把闲置页还给系统")
    print("=" * 70)

    # 先采一次 CPU 增量，判断哪些进程"在干活"
    procs, _ = fast_probe.snapshot()
    ticks = fast_probe.collect_cpu_ticks(procs)
    time.sleep(10)
    procs2, _ = fast_probe.snapshot()
    cpu = fast_probe.cpu_delta(ticks, procs2)

    cands = []
    for pid, p in procs2.items():
        nm = (p.get("name") or "")
        if args.all:
            ok = True
        else:
            ok = any(t.lower() == nm.lower() for t in targets)
        if not ok:
            continue
        c = counters(pid)
        if not c:
            continue
        pct = cpu.get(pid) or 0.0
        if pct > args.max_cpu:
            print("  跳过 pid=%-7s %-22s CPU=%.2f%% > %.1f%%（在干活）"
                  % (pid, nm, pct, args.max_cpu))
            continue
        cands.append((pid, nm, pct, c.WorkingSetSize / 1048576))

    if not cands:
        print("没有符合条件的进程。")
        return 0

    a0, c0, l0 = phys_mem()
    total_ws = sum(x[3] for x in cands)
    print()
    print("目标进程 %d 个，工作集合计 %.1f MB" % (len(cands), total_ws))
    print("物理可用 %.2f GB | 已提交 %.1f GB | 负载 %s%%" % (a0, c0, l0))
    print()
    print("%-8s %-22s %8s %10s" % ("pid", "name", "CPU%", "工作集MB"))
    for pid, nm, pct, ws in sorted(cands, key=lambda x: -x[3]):
        print("%-8s %-22s %7.2f%% %9.1f" % (pid, nm, pct, ws))

    if not args.apply:
        print("\n（演练，没有动任何进程。加 --apply 才真执行）")
        return 0

    print("\n执行 EmptyWorkingSet …")
    okc = 0
    for pid, nm, pct, ws in cands:
        if trim_pid(pid):
            okc += 1
        else:
            print("  失败 pid=%s (%d)" % (pid, k32.get_last_error()))
    print("成功 %d / %d" % (okc, len(cands)))

    time.sleep(args.wait)
    a1, c1, l1 = phys_mem()
    procs3, _ = fast_probe.snapshot()
    ws1 = sum((counters(pid).WorkingSetSize / 1048576)
              for pid, nm, pct, ws in cands if counters(pid))
    print()
    print("=" * 70)
    print("工作集：%.1f MB -> %.1f MB（回收 %.1f MB）" % (total_ws, ws1, total_ws - ws1))
    print("物理可用：%.2f GB -> %.2f GB（%+.2f GB）" % (a0, a1, a1 - a0))
    print("已提交：%.1f GB -> %.1f GB（%+.1f GB）" % (c0, c1, c1 - c0))
    print("负载：%s%% -> %s%%" % (l0, l1))

    # 确认进程没被杀掉、微信没重启容器
    alive = [pid for pid, nm, pct, ws in cands if pid in procs3]
    print("存活目标进程 %d / %d" % (len(alive), len(cands)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
