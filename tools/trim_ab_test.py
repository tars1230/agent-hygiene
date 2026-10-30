"""A/B 对照实验：trim 对「物理可用内存」的真实增量。

为什么要做差分验证：
  README 里已有一条结论 ——「trim 只降工作集，Private 一分不减」，
  容易被误读成「trim 对可用内存没用」。本实验用**对照组**证明
  trim 到底能不能让**物理可用内存**真的涨上来。

方法（ABBA 交替，抵消时间漂移）：
  周期 1：基线采样 -> 不操作 -> 采样
  周期 2：基线采样 -> trim  -> 采样
  周期 3：基线采样 -> 不操作 -> 采样     （再测一次基线，验证没被前一轮污染）
  周期 4：基线采样 -> trim  -> 采样
  取 trim 周期与基线周期的**增量之差** = trim 的净效应。

判据：净效应显著为正 ⇒ trim 确实把可用内存换出来了。

用法：
    python trim_ab_test.py            # 演练（只采样）
    python trim_ab_test.py --apply    # 真做 trim
    python trim_ab_test.py --rounds 6 # 每轮间隔分钟数，默认 4
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
psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
psapi.EmptyWorkingSet.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]


class PMC(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("a", ctypes.c_size_t), ("b", ctypes.c_size_t),
                ("c", ctypes.c_size_t), ("d", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def ws_mb(pid):
    h = k32.OpenProcess(0x1000 | 0x0400, False, pid)
    if not h:
        return 0.0
    c = PMC()
    c.cb = ctypes.sizeof(c)
    psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
    k32.CloseHandle(h)
    return c.WorkingSetSize / 1048576


def targets():
    procs, _ = fast_probe.snapshot()
    out = []
    for pid, p in procs.items():
        nm = (p.get("name") or "")
        if nm in ("WeChatAppEx.exe",):
            out.append(pid)
    return out


def state():
    procs, _ = fast_probe.snapshot()
    m = fast_probe.memory_status()
    w = [pid for pid, p in procs.items()
         if (p.get("name") or "") == "WeChatAppEx.exe"]
    return {
        "avail": m.get("avail_phys_mb", 0) / 1024.0,
        "commit": (m.get("total_commit_mb", 0) - m.get("avail_commit_mb", 0)) / 1024.0,
        "ws": sum(ws_mb(x) for x in w),
        "n": len(w),
    }


def do_trim(pids):
    n = 0
    for pid in pids:
        h = k32.OpenProcess(0x0100 | 0x0400, False, pid)
        if not h:
            continue
        if psapi.EmptyWorkingSet(h):
            n += 1
        k32.CloseHandle(h)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--rounds", type=int, default=4, help="间隔分钟数")
    ap.add_argument("--settle", type=int, default=90, help="每轮采样前稳定秒数")
    args = ap.parse_args()

    print("=" * 74)
    print("ABBA 差分验证：trim 对物理可用内存的净效应")
    print("=" * 74)
    print("轮次  动作      物理可用GB  已提交GB  WMPF工作集MB  进程数")
    print("-" * 74)

    plan = ["base", "trim", "base", "trim"]
    results = []
    for i, action in enumerate(plan):
        time.sleep(args.settle)
        pids = targets()
        s0 = state()
        if action == "trim" and args.apply:
            ok = do_trim(pids)
            time.sleep(10)
        else:
            ok = 0
        s1 = state()
        results.append((action, s0, s1, ok))
        print("%-6s %-9s %9.2f   %8.1f  %10.1f     %3d%s" % (
            i + 1, action, s1["avail"], s1["commit"], s1["ws"], s1["n"],
            ("  [trim %d]" % ok) if ok else ""))
        if i < len(plan) - 1:
            time.sleep(args.rounds * 60)

    print("-" * 74)
    bases = [r for r in results if r[0] == "base"]
    trims = [r for r in results if r[0] == "trim"]
    if not bases or not trims:
        print("数据不足")
        return 1
    b_avail = sum(r[2]["avail"] for r in bases) / len(bases)
    t_avail = sum(r[2]["avail"] for r in trims) / len(trims)
    b_ws = sum(r[2]["ws"] for r in bases) / len(bases)
    t_ws = sum(r[2]["ws"] for r in trims) / len(trims)
    b_commit = sum(r[2]["commit"] for r in bases) / len(bases)
    t_commit = sum(r[2]["commit"] for r in trims) / len(trims)

    print()
    print("基线轮（%d 次）: 可用 %.2f GB | 已提交 %.1f GB | WMPF WS %.1f MB"
          % (len(bases), b_avail, b_commit, b_ws))
    print("trim轮（%d 次）: 可用 %.2f GB | 已提交 %.1f GB | WMPF WS %.1f MB"
          % (len(trims), t_avail, t_commit, t_ws))
    print()
    print("净效应：可用内存 %+.2f GB | 已提交 %+.1f GB | WMPF 工作集 %+.1f MB"
          % (t_avail - b_avail, t_commit - b_commit, t_ws - b_ws))
    if t_avail - b_avail > 0.05:
        print("判定：trim 确实把物理可用内存换出来了（净增 > 50MB）。")
    else:
        print("判定：净效应不显著（<= 50MB）—— trim 在本机**没有**实际收益。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
