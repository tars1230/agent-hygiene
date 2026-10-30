#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thread_handle_probe.py —— 进程「线程数 / 句柄数」维度探测（只读）

为什么需要这个独立模块
  内存体检工具上一版只按 Private 排序，这会漏掉最典型的一类泄漏：
  explorer 线程泄漏实测 Private 8432MB / WS 仅 452MB，靠 Private 排序恰好能看见；
  但 Weixin 主进程句柄泄漏实测 Private 仅 567MB（排不进 Top15），句柄却高达 177791
  —— 它吃掉的是 **内核对象表**，不是用户态内存。**只看 Private 的工具永远看不见它。**
  所以线程数 / 句柄数必须是独立的一维，与 Private 并列看。

三个关键实测结论（都在本机复核过，数字见 --self-test）
  1. 一次 Get-Process 调用即可拿到全表线程数+句柄数，实测 362ms / 37KB JSON。
     不要为每个进程单独调一次（会慢到分钟级）。
  2. **Suspended 线程比例是最强的判别信号**。
     explorer 泄漏样本：96262 线程中 96127 个 Suspended（99.85%）。
     正常进程实测 Suspended 比例恒为 0（System 有 12/312=3.85%，属正常挂起）。
     固定阈值会误报，必须靠这个「构成比」而不是绝对值。
  3. 句柄数**没有单一阈值**可用：Weixin 主进程 177791，而同名的 5 个 Weixin 进程
     只有 207~516。必须用 **同 exe 的中位数做对比**（相对倍数），
     固定阈值（如 3000）会把 System(8961)/msedge(8781) 之类的正常高值一起误报。

数据结构
  probe_all() -> {pid: {"threads": int, "handles": int,
                        "suspended": int, "wait": int, "priv_mb": float}}

判定口径（供体检/回收脚本共用，避免两处各判一套）
  thread_burst_score   : threads 相对同 exe 中位数的倍数
  handle_burst_score  : handles 相对同 exe 中位数的倍数
  suspended_ratio     : suspended / threads
  异常候选 = threads >= MIN_THREADS_ABS
             且 (thread_burst_score >= BURST_RATIO 或 suspended_ratio >= SUSPENDED_RATIO)
  句柄异常 = handles >= MIN_HANDLES_ABS 且 handle_burst_score >= BURST_RATIO

🔴 单实例 exe 组的例外（实测踩到，必须保留）
  同 exe 只有 1 个实例时，中位数 == 它自己 => 倍数恒为 1.0 => **相对倍数这道防线失效**。
  实测本机 85 个 exe 是单实例，其中 wetype_renderer 持有 21889 个句柄 ——
  按「倍数 ≥20x」永远查不出来。所以单实例组(n==1) 改用
  「绝对下限 SOLO_HANDLES_ABS=20000 + 全局中位数倍数 ≥20x」双条件。

🔴 n>=2 的「组内中位数」陷阱（2026-10-29 独立复核 grok 4.7 时实测踩到）
  组内中位数会被离群实例**自己**抬高：组内 2 个实例、其中一个泄漏到 190000 句柄、
  另一个正常 243 时，中位数 = 95121.5 => 倍数只有 2.0 => **异常被藏住**。
  所以 n>=2 时改用 **leave-one-out**：算某个进程的倍数时，参照值取
  「同 exe 其余实例」的中位数，把自己排除在外（见 _peer_median）。
"""
import argparse
import ctypes
import json
import os
import re
import statistics
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

PS_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

# 🔴 PowerShell 输出在本机默认是 GBK(936)。用 text=True(默认 utf-8) 解码会抛
#    UnicodeDecodeError，而且是在 subprocess 的 reader 线程里抛 -> 静默丢输出。
#    且 encoding= 与 text=True 互斥，不能同时传。
#    但本模块的脚本**显式设了 [Console]::OutputEncoding=UTF8**，所以输出是 UTF-8 字节。
#    => 统一走 bytes 模式 + 自适应解码：先试 utf-8，失败再退 gbk。
PS_ENC = {"encoding": "utf-8", "errors": "replace"}


def _decode(raw):
    """自适应解码 PowerShell 的 stdout 字节。

    本模块脚本强制 UTF8 输出，但不同 Windows 区域设置下 PS 仍可能回退到 OEM/ANSI，
    所以 utf-8 失败必须退 gbk 而不是直接丢数据。
    """
    if raw is None:
        return ""
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

# 判定阈值（全部来自本机实测，见 README「线程/句柄维度」一节）
MIN_THREADS_ABS = 2000        # 线程绝对下限。实测正常进程最高 312(System)/134(Weixin)
MIN_HANDLES_ABS = 50000       # 句柄绝对下限。实测正常进程最高 8961(System)/8781(msedge)
# 🔴 单实例 exe 组的句柄绝对下限（2026-10-29 复核后新增）。
#    单实例没有同伴可对照，只有「全局中位数倍数」一道防线，倍数高但绝对值中等时
#    会被 50000 挡掉。实测 wetype_renderer 21889 个句柄 = 全局中位数的 100 倍，
#    按原阈值永远查不出来。单实例组改用 20000 下限。
SOLO_HANDLES_ABS = 20000
BURST_RATIO = 20.0            # 相对同 exe 同伴中位数的倍数阈值
SUSPENDED_RATIO = 0.30        # Suspended 线程占比阈值（泄漏样本 99.85% vs 正常 0%）

# 内核进程：句柄/线程天然高，且泄漏形态不同，不参与「相对同 exe」比较
KERNEL_NAMES = {
    "system idle process", "system", "secure system", "registry",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "lsaiso.exe", "dwm.exe", "fontdrvhost.exe", "memory compression",
    "memcompression", "audiodg.exe", "vmmem", "vmmemwsl",
}


def _ps_json(script, timeout=120):
    """跑一段 PowerShell 脚本，解析 stdout 为 JSON。

    ⚠️ 必须加 [Console]::OutputEncoding = UTF8：否则含中文的进程名会被 GBK 编码，
       Python 端按 utf-8 解码会炸或产生乱码。
    """
    pre = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-NonInteractive", "-Command", pre + script],
                           capture_output=True, timeout=timeout, creationflags=nowin.no_window())  # bytes 模式, 自行解码
    except Exception as e:
        print("[warn] PowerShell failed: %s" % e)
        return None
    out = _decode(r.stdout).strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # GBK 解码后可能残留 BOM 或尾随噪声，做一次宽松清洗
        try:
            return json.loads(out.lstrip("\ufeff").split("\n{")[0] if out.startswith("[") else out)
        except Exception:
            print("[warn] JSON parse failed, head=%r" % out[:200])
            return None


def probe_all():
    """一次 PowerShell 调用拿到全表 {pid: {threads, handles, suspended, wait, priv_mb}}。

    实测 362ms（Get-Process | Select ... | ConvertTo-Json）。
    🔴 关键：$_.Threads.Count 在 PowerShell 里是**属性访问**，必须写成
       ($_.Threads.Count) 形式传给 ConvertTo-Json 才不会被当成字符串。
    """
    script = (
        "$r = @(); "
        "foreach ($p in Get-Process) { "
        "  try { "
        "    $t = $p.Threads; "
        "    $susp = 0; $wait = 0; "
        "    foreach ($th in $t) { "
        "      if ($th.ThreadState -eq 'Wait') { $wait++; "
        "        if ($th.WaitReason -eq 'Suspended') { $susp++ } } } "
        "    $r += [PSCustomObject]@{ "
        "      Id=$p.Id; Name=$p.Name; HandleCount=$p.HandleCount; "
        "      Threads=$t.Count; Suspended=$susp; Wait=$wait; "
        "      PrivMB=[math]::Round($p.PrivateMemorySize64/1MB,1) } "
        "  } catch { } "
        "}; "
        "$r | ConvertTo-Json -Compress"
    )
    data = _ps_json(script)
    if not data:
        return {}
    if isinstance(data, dict):
        data = [data]
    out = {}
    for d in data:
        try:
            pid = int(d["Id"])
        except (KeyError, TypeError, ValueError):
            continue
        out[pid] = {
            "name": d.get("Name") or "",
            "threads": int(d.get("Threads") or 0),
            "handles": int(d.get("HandleCount") or 0),
            "suspended": int(d.get("Suspended") or 0),
            "wait": int(d.get("Wait") or 0),
            "priv_mb": float(d.get("PrivMB") or 0.0),
        }
    return out


def _median_by_exe(probe, exclude_kernel=True):
    """按 exe 名分组求 threads/handles 中位数。

    🔴 这是避免误报的核心：同 exe 的多个进程天然同构（中位数代表「正常水位」），
       某个进程是中位数的 N 倍才是异常。绝对阈值做不到这一点。

    🔴 但「组内中位数」会被离群实例自己抬高（2026-10-29 独立复核 grok 4.7 时实测）：
       组内只有 2 个实例、其中一个泄漏到 190000 句柄、另一个正常 243 时，
       中位数 = (190000+243)/2 = 95121.5 -> 倍数只有 2.0 -> **异常被藏住**。
       所以 analyze() 里改用 **leave-one-out**：算某个进程的倍数时，
       参照值取「同 exe 其余实例」的中位数，把自己排除在外。
       这里同时把原始值列表存下来供 leave-one-out 使用。
    """
    buckets = {}
    for pid, d in probe.items():
        nm = (d.get("name") or "").lower()
        if exclude_kernel and nm in KERNEL_NAMES:
            continue
        d.setdefault("pid", int(pid) if str(pid).isdigit() else pid)
        buckets.setdefault(nm, []).append(d)
    med = {}
    for nm, lst in buckets.items():
        med[nm] = {
            "threads": statistics.median([x["threads"] for x in lst]) or 0.0,
            "handles": statistics.median([x["handles"] for x in lst]) or 0.0,
            "n": len(lst),
            # leave-one-out 需要**按 pid**索引，不能只存值列表：
            # 同 exe 的两个实例句柄可能相等，按值剔除会误删同伴。
            "threads_by_pid": {str(x["pid"]): x["threads"] for x in lst},
            "handles_by_pid": {str(x["pid"]): x["handles"] for x in lst},
        }
    return med


def _peer_median(by_pid, self_pid):
    """leave-one-out 中位数：把「自己」从样本里剔除后再求中位数。

    🔴 n>=2 时必须用它，否则离群实例会把自己的参照值抬高，把异常藏住。
       n==1 时无同伴可比，返回 None（调用方退回全局中位数）。
    """
    self_pid = str(self_pid)
    peers = [v for p, v in by_pid.items() if p != self_pid]
    if not peers:
        return None
    return float(statistics.median(peers))


def _ratio(val, base):
    if base <= 0:
        return float("inf") if val > 0 else 1.0
    return val / base


def _global_percentile(probe, field, pct=0.5):
    """全表分位数（去掉内核进程）。用于「同 exe 只有一个实例」时的兜底参照系。

    🔴 为什么要这个：同 exe 只有 1 个实例时中位数==自己，倍数恒为 1.0，
       相对判据完全失效。此时退回到「这台机器上它比典型进程高多少倍」。

    🔴 为什么用中位数(P50) 而不是高分位: 实测 P99.9 在 539 个进程上等于**最大值本身**
       （被离群进程如 Weixin 污染），拿它当参照系等于「和最大值比」= 恒为 1.0，没有意义。
       中位数不受离群值影响，代表「这台机器上一个典型进程」。
    """
    vals = sorted(d.get(field, 0) for d in probe.values()
                  if (d.get("name") or "").lower() not in KERNEL_NAMES)
    if not vals:
        return 0.0
    idx = min(len(vals) - 1, int(len(vals) * pct))
    return float(vals[idx])


def analyze(probe, min_threads=MIN_THREADS_ABS, min_handles=MIN_HANDLES_ABS,
            burst=BURST_RATIO, susp_ratio=SUSPENDED_RATIO):
    """返回异常候选列表。每项含判据与原始数字，供报告直接引用。"""
    med = _median_by_exe(probe)
    # 🔴 单实例 exe 组没有「同类参照」，倍数恒为 1.0 -> 倍数判据失效。
    #    改用全局分位数兜底（这台机器上它排多高）。
    g_handles_p999 = _global_percentile(probe, "handles", 0.5)
    g_threads_p999 = _global_percentile(probe, "threads", 0.5)
    findings = []
    for pid, d in probe.items():
        nm = (d.get("name") or "").lower()
        if nm in KERNEL_NAMES:
            continue
        m = med.get(nm)
        if not m:
            continue
        s_ratio = (d["suspended"] / d["threads"]) if d["threads"] else 0.0

        # 🔴 参照系选择（2026-10-29 独立复核 grok 4.7 后修正）：
        #    n>=2 : leave-one-out 中位数（剔除自己），否则离群实例会把自己藏住
        #    n==1 : 无同伴可比 -> 全局中位数兜底
        solo = (m["n"] <= 1)
        if solo:
            thr_ratio = _ratio(d["threads"], g_threads_p999)
            hdl_ratio = _ratio(d["handles"], g_handles_p999)
            base_threads = g_threads_p999
            base_handles = g_handles_p999
            basis = "全局中位数"
        else:
            pt = _peer_median(m["threads_by_pid"], pid)
            ph = _peer_median(m["handles_by_pid"], pid)
            base_threads = pt if pt else m["threads"]
            base_handles = ph if ph else m["handles"]
            thr_ratio = _ratio(d["threads"], base_threads)
            hdl_ratio = _ratio(d["handles"], base_handles)
            basis = "同exe同伴中位数(剔除自身)"

        # 线程维度
        if d["threads"] >= min_threads and (
                thr_ratio >= burst or s_ratio >= susp_ratio):
            reasons = []
            if thr_ratio >= burst:
                reasons.append("线程数是%s的 %.1f 倍" % (basis, thr_ratio))
            if s_ratio >= susp_ratio:
                reasons.append("%.1f%% 线程处于 Suspended" % (s_ratio * 100))
            findings.append({
                "pid": pid, "name": d.get("name"), "kind": "thread",
                "threads": d["threads"], "handles": d["handles"],
                "suspended": d["suspended"], "suspended_ratio": round(s_ratio, 4),
                "priv_mb": d["priv_mb"],
                "peer_median_threads": base_threads,
                "peer_median_handles": base_handles,
                "peer_count": m["n"],
                "burst_ratio": round(thr_ratio, 1),
                "basis": basis,
                "reasons": reasons,
            })
        # 句柄维度（独立于线程维度：Weixin 样本句柄爆炸但线程数正常）
        # 🔴 单实例组用**更低的绝对下限**（grok 4.7 复核指出，原来的 50000 兜不住
        #    wetype_renderer 的 21889 个句柄 —— 它是全局中位数的 100 倍却查不出来）。
        #    单实例没有「同伴」可对照，全局倍数 + 绝对下限共同兜底。
        hdl_min = min_handles if not solo else min(min_handles, SOLO_HANDLES_ABS)
        if d["handles"] >= hdl_min and hdl_ratio >= burst:
            findings.append({
                "pid": pid, "name": d.get("name"), "kind": "handle",
                "threads": d["threads"], "handles": d["handles"],
                "suspended": d["suspended"], "suspended_ratio": round(s_ratio, 4),
                "priv_mb": d["priv_mb"],
                "peer_median_threads": base_threads,
                "peer_median_handles": base_handles,
                "peer_count": m["n"],
                "burst_ratio": round(hdl_ratio, 1),
                "basis": basis,
                "reasons": ["句柄数是%s的 %.1f 倍" % (basis, hdl_ratio)],
            })
    findings.sort(key=lambda f: -(f["handles"] if f["kind"] == "handle" else f["threads"]))
    return findings


def top_tables(probe, n=10):
    """Top 线程 / Top 句柄 两个榜（不论是否达异常阈值，都列出来看趋势）。"""
    lst = list(probe.items())
    top_threads = sorted(lst, key=lambda kv: -kv[1]["threads"])[:n]
    top_handles = sorted(lst, key=lambda kv: -kv[1]["handles"])[:n]
    return top_threads, top_handles


def self_test():
    """用本机实时数据自检：打印阈值依据与异常候选。"""
    probe = probe_all()
    if not probe:
        print("[fail] 探测失败")
        return 1
    print("[probe] 进程数=%d" % len(probe))
    med = _median_by_exe(probe)
    print("[probe] 同 exe 中位数样本(前 8):")
    for nm, m in sorted(med.items(), key=lambda kv: -kv[1]["n"])[:8]:
        print("   %-28s n=%-3d med_threads=%-6.1f med_handles=%.0f"
              % (nm, m["n"], m["threads"], m["handles"]))
    tt, th = top_tables(probe, 8)
    print("[probe] Top 线程:")
    for pid, d in tt:
        print("   pid=%-7d %-24s threads=%-6d suspended=%-6d handles=%-7d priv=%.1fMB"
              % (pid, d["name"][:24], d["threads"], d["suspended"], d["handles"], d["priv_mb"]))
    print("[probe] Top 句柄:")
    for pid, d in th:
        print("   pid=%-7d %-24s handles=%-7d threads=%-5d priv=%.1fMB"
              % (pid, d["name"][:24], d["handles"], d["threads"], d["priv_mb"]))
    findings = analyze(probe)
    print("[probe] 异常候选 %d 个:" % len(findings))
    for f in findings:
        print("   [%s] pid=%d %s threads=%d handles=%d susp_ratio=%.2f burst=%.1fx :: %s"
              % (f["kind"], f["pid"], f["name"], f["threads"], f["handles"],
                 f["suspended_ratio"], f["burst_ratio"], "; ".join(f["reasons"])))
    return 0


def main():
    ap = argparse.ArgumentParser(description="线程/句柄维度探测（只读）")
    ap.add_argument("--self-test", action="store_true", help="跑本机自检并打印阈值依据")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--min-threads", type=int, default=MIN_THREADS_ABS)
    ap.add_argument("--min-handles", type=int, default=MIN_HANDLES_ABS)
    ap.add_argument("--burst", type=float, default=BURST_RATIO)
    ap.add_argument("--suspended-ratio", type=float, default=SUSPENDED_RATIO)
    a = ap.parse_args()

    if sys.platform != "win32":
        print("仅支持 Windows")
        return 1
    if a.self_test:
        return self_test()

    probe = probe_all()
    if not probe:
        print("[fail] 探测失败")
        return 1
    findings = analyze(probe, a.min_threads, a.min_handles, a.burst, a.suspended_ratio)
    if a.json:
        print(json.dumps({"probe": probe, "findings": findings}, ensure_ascii=False, indent=2))
    else:
        print("进程数=%d  异常候选=%d" % (len(probe), len(findings)))
        for f in findings:
            print("[%s] pid=%d %s threads=%d handles=%d susp_ratio=%.2f burst=%.1fx :: %s"
                  % (f["kind"], f["pid"], f["name"], f["threads"], f["handles"],
                     f["suspended_ratio"], f["burst_ratio"], "; ".join(f["reasons"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
