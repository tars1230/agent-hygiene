#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
handle_type_breakdown.py —— 句柄「类型分解」（只读）

为什么需要这个
  上一版工具能回答「这个进程句柄很多」（Weixin 主进程 178029 个），但**答不出
  「为什么」**。而「句柄多」本身不是一个可行动结论 —— 同样是 10 万句柄：
    · 10 万个 Event   = 某个组件反复 CreateEvent 后不 CloseHandle
    · 10 万个 Token   = 每次开子进程 DuplicateHandle 了访问令牌没关
    · 10 万个 Process = 指向**已退出**的子进程的僵尸句柄
    · 10 万个 Key/File = 配置或文件句柄泄漏
  这四种的处置与归属完全不同，必须分解到类型层。

🔴 实测的关键坑（别重踩）
  1. `handle64.exe -p <pid>` **默认只列「有名字」的句柄**。Weixin 主进程 19 万个句柄，
     默认输出只有 **489 行**（全部有名字，含 0xBBBF0 这样的高位句柄值），
     加 `-a`（全部）才输出 **19 万+ 行**。
     🔴 拿默认输出下结论 = 结论完全错。
     🔴 2026-10-29 更正：早期版本把机制误记成「只枚举了前 4020 号槽位」——
        那是因为用 `grep | sort` 做十六进制排序，**那是字符串比较不是数值比较**
        （0xBBBF0 字符串序 < 0xFB4）。Python `int(x, 16)` 才排得对。
        实测 489 行里 427 行（87.3%）句柄值 > 0xFB4，机制就是「只列有名字的」。
  2. 无名句柄的「名字」列是空的，所以统计类型时不能靠名字列，
     要靠 `类型:` 那一列（行首 `  <hex>: <Type> <name>`）。
  3. Process 句柄指向已退出进程时显示 `<Nonexistent process>(pid)` —— 这不是
     Handle 的 bug，是**僵尸句柄的直接证据**。
     🔴 但反过来说：文本里**没有** Nonexistent 的 Process 句柄，目标就**还活着**。
        把两类混在一起印，会把活着的 explorer 印成「已退出」（2026-10-29 实测踩到）。
  4. `ALPC Port` 是**两个词**的类型名，类型正则必须允许，否则会被截断成 `ALPC`。

数据来源：Sysinternals Handle（Microsoft，EULA 接受后使用）。
本工具只调用只读的枚举命令，不修改任何进程状态。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

# Handle.exe 位置优先级：
#   1) 环境变量 AGENT_HYGIENE_HANDLE_EXE
#   2) 仓库内 _vendor/Handle/handle64.exe（若用户放了）
#   3) PATH
# 找不到就明确报错，不猜。
_HANDLE_ENV = "AGENT_HYGIENE_HANDLE_EXE"

# 类型正则。🔴 Handle 的行格式是 `  <hex>: <Type>[ <Name>]`，
#    绝大多数类型是**一个词**（Token / Key / Process / Event / File / Section ...）。
#    但存在少数**两个词**的类型名（如 `ALPC Port`）——
#    早期版本只匹配一个词，会把 `ALPC Port` 截断成 `ALPC`（实测 23 行）。
#    🔴 但**不能**笼统地允许第二个词：那会把「名字」误当成类型的一部分，
#    例如 `Token  TARS\Administrator:6fa1c` 会变成类型 "Token TARS"、
#    `Key  HKLM\...` 变成 "Key HKLM" —— 类型统计直接被污染。
#    => 用**白名单**精确处理已知的两词类型名，其余一律单词。
_TWO_WORD_TYPES = ("ALPC Port",)
_TYPE_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s+([A-Za-z_][A-Za-z_0-9]*)")
_PROC_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s+Process\s+(.*)$")


def _type_of(line):
    """取一行的类型名，正确处理 `ALPC Port` 这类两词类型。"""
    m = _TYPE_RE.match(line)
    if not m:
        return None
    t = m.group(2)
    for two in _TWO_WORD_TYPES:
        # 行内紧跟类型词的两个词必须精确等于白名单项
        if re.match(r"^\s*[0-9A-Fa-f]+:\s+%s\b" % re.escape(two), line):
            return two
    return t


def find_handle_exe():
    """定位 handle64.exe。找不到返回 None。"""
    cand = os.environ.get(_HANDLE_ENV)
    if cand and os.path.isfile(cand):
        return cand
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    for rel in ("_vendor/Handle/handle64.exe",
                "_vendor/handle64.exe",
                "_vendor/Handle.exe/handle64.exe"):
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            return p
    # PATH
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for n in ("handle64.exe", "handle.exe"):
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


def _decode(raw):
    """自适应解码。Handle 输出多为 ASCII，但路径可能含非 ASCII。"""
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return ""


def ps_exe():
    """PowerShell 绝对路径。某些受控环境 PATH 不含 System32\\WindowsPowerShell。"""
    return os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def list_handles(handle_exe, pid, timeout=420):
    """调用 handle64.exe -p <pid> -a，返回 (原始文本, 行数)。"""
    cmd = [handle_exe, "-accepteula", "-p", str(pid), "-a"]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=nowin.no_window())
    text = _decode(p.stdout or b"")
    # stderr 里是 banner（Copyright/Nthandle），stdout 才是句柄列表
    lines = [l for l in text.splitlines() if _type_of(l) is not None]
    return text, lines


def parse_types(lines):
    """统计类型分布。返回 (type_counter_dict, proc_refs_dict)。

    🔴 proc_refs 的结构（2026-10-29 独立复核 grok 4.7 时发现并修复的真 bug）：
       旧版把「已退出目标」和「存活目标」混在**同一个字典**里，
       打印时只排除 "__gone__" 就把剩下的全标成「泄漏源 pid」——
       结果活着的 explorer.exe(425444) 被印成「已退出」。
       现在分成两个独立字典：
         gone_refs : {pid: 句柄数}  —— 目标文本含 "Nonexistent"，**确实已退出**
         live_refs : {pid: 句柄数}  —— 目标文本含真实进程名，**还活着**
         live_names: {pid: 进程名}  —— 活目标的原始名字（如 "explorer.exe(425444)"）
    """
    types = {}
    gone_refs = {}
    live_refs = {}
    live_names = {}
    for l in lines:
        t = _type_of(l)
        if t is None:
            continue
        types[t] = types.get(t, 0) + 1
        pm = _PROC_RE.match(l)
        if pm:
            name = pm.group(2).strip()
            # name 形如 "<Nonexistent process>(20764)" 或 "Weixin.exe(1234)"
            mm = re.search(r"\((\d+)\)\s*$", name)
            key = mm.group(1) if mm else name
            if "Nonexistent" in name:
                gone_refs[key] = gone_refs.get(key, 0) + 1
            else:
                live_refs[key] = live_refs.get(key, 0) + 1
                live_names[key] = name
    proc_refs = {
        "gone_refs": gone_refs,
        "live_refs": live_refs,
        "live_names": live_names,
        "gone_total": sum(gone_refs.values()),
        "live_total": sum(live_refs.values()),
    }
    return types, proc_refs


def process_handle_count(ps, pid):
    """用 Get-Process 拿该 pid 的句柄数（校验 Handle 输出完整性）。"""
    script = ("$p=Get-Process -Id %d -ErrorAction SilentlyContinue; "
              "if($p){ $p.HandleCount }" % int(pid))
    try:
        p = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=60, creationflags=nowin.no_window())
        t = _decode(p.stdout or b"").strip()
        return int(t) if t.isdigit() else None
    except Exception:
        return None


def cross_check(truth_before, total, truth_after):
    """交叉校验：枚举前后的 HandleCount 之间才算「一致」。

    🔴 为什么不能要求完全相等（grok 4.7 独立复核指出，实测确认）：
       Handle 枚举要几秒，期间进程可能自己开/关句柄。所以
       「枚举行数 == 枚举后 HandleCount」这种单点比对，
       在增长中的进程上会**必然不等**，印成「不一致 ✗」会被误读成「枚举残缺」。
    正确判据：行数落在 [truth_before, truth_after] 区间内 = 一致（在采样窗口内）。
    """
    if truth_before is None or truth_after is None:
        return "未知", None
    lo = min(truth_before, truth_after)
    hi = max(truth_before, truth_after)
    if lo <= total <= hi:
        return "一致（落在枚举前后 HandleCount 之间）", 0
    return "不一致（超出区间，差 %+d）" % (total - truth_after), total - truth_after


def main():
    ap = argparse.ArgumentParser(description="句柄类型分解（只读）")
    ap.add_argument("pid", type=int, help="目标进程 PID")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--top", type=int, default=20, help="类型榜条数")
    ap.add_argument("--handle-exe", help="指定 handle64.exe 路径")
    ap.add_argument("--diff", action="store_true",
                    help="连续采样并对比，定位『增长源』（判稳态 vs 持续增长）")
    ap.add_argument("--interval", type=int, default=60, help="--diff 的采样间隔秒数")
    ap.add_argument("--rounds", type=int, default=8, help="--diff 的采样轮数")
    a = ap.parse_args()

    if sys.platform != "win32":
        print("仅支持 Windows")
        return 1

    exe = a.handle_exe or find_handle_exe()
    if not exe:
        print("[fail] 找不到 Sysinternals Handle。")
        print("       获取方式：")
        print("       1) 下载 https://download.sysinternals.com/files/Handle.zip")
        print("       2) 解压后放到 %s\\_vendor\\Handle\\handle64.exe" %
              os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        print("       3) 或设环境变量 %s 指向 handle64.exe" % _HANDLE_ENV)
        return 2

    ps = ps_exe()

    if a.diff:
        try:
            return run_diff(exe, a.pid, ps, max(5, a.interval), max(2, a.rounds))
        except subprocess.TimeoutExpired:
            print("[fail] Handle 执行超时")
            return 1
        except Exception as e:
            print("[fail] %s" % e)
            return 1

    truth_before = process_handle_count(ps, a.pid)
    try:
        text, lines = list_handles(exe, a.pid)
    except subprocess.TimeoutExpired:
        print("[fail] Handle 执行超时（PID %d 句柄过多时可能发生）" % a.pid)
        return 1
    except Exception as e:
        print("[fail] Handle 执行失败: %s" % e)
        return 1
    truth_after = process_handle_count(ps, a.pid)

    types, proc_refs = parse_types(lines)
    total = len(lines)

    if a.json:
        print(json.dumps({
            "pid": a.pid,
            "handle_total": total,
            "process_handle_count_before": truth_before,
            "process_handle_count_after": truth_after,
            "types": types,
            "gone_refs": proc_refs["gone_refs"],
            "live_refs": proc_refs["live_refs"],
            "live_names": proc_refs["live_names"],
        }, ensure_ascii=False, indent=2))
        return 0

    print("PID %d 句柄类型分解" % a.pid)
    print("  Handle -a 列出 %d 个句柄" % total)
    if truth_before is not None and truth_after is not None:
        ok, delta = cross_check(truth_before, total, truth_after)
        print("  Get-Process 枚举前 %d / 枚举后 %d  ->  %s"
              % (truth_before, truth_after, ok))
    print()
    print("  %-22s %8s %7s" % ("类型", "数量", "占比"))
    for t, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top]:
        pct = (c * 100.0 / total) if total else 0
        print("  %-22s %8d %6.2f%%" % (t, c, pct))
    if total > sum(c for _, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top]):
        rest = total - sum(c for _, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top])
        print("  %-22s %8d %6.2f%%" % ("(其余)", rest, rest * 100.0 / total if total else 0))

    gone_total = proc_refs["gone_total"]
    n_proc = types.get("Process", 0)
    if gone_total:
        print()
        print("  🔴 指向**已退出进程**的僵尸句柄: %d 个" % gone_total)
        print("     · 占全部句柄 %.2f%%（分母 = 全部 %d 个）"
              % (gone_total * 100.0 / total if total else 0, total))
        print("     · 占 Process 类句柄 %.2f%%（分母 = Process %d 个）"
              % (gone_total * 100.0 / n_proc if n_proc else 0, n_proc))
        refs = sorted(proc_refs["gone_refs"].items(), key=lambda kv: -kv[1])[:10]
        print("     已退出目标 pid 分布:")
        for pid_k, cnt in refs:
            print("       pid=%-8s %6d 个句柄" % (pid_k, cnt))
        print("     判读: 这些进程**确已退出**，但句柄仍被持有且从未 CloseHandle。")

    live_total = proc_refs["live_total"]
    if live_total:
        print()
        print("  ⚪ 指向**存活进程**的 Process 句柄: %d 个（非泄漏存量）" % live_total)
        refs = sorted(proc_refs["live_refs"].items(), key=lambda kv: -kv[1])[:10]
        print("     存活目标 pid 分布（名字取自 Handle 输出）:")
        for pid_k, cnt in refs:
            print("       pid=%-8s %6d 个句柄  %s"
                  % (pid_k, cnt, proc_refs["live_names"].get(pid_k, "")))
        print("     判读: 目标仍活着。**新增**的这类句柄 = 进程仍在增长，")
        print("           增长源就在下面的逐 pid Δ 里，别默认归给已退出的僵尸。")
    return 0


def snapshot(exe, pid, ps):
    """取一次完整快照，供 diff 用。"""
    truth_before = process_handle_count(ps, pid)
    _, lines = list_handles(exe, pid)
    truth_after = process_handle_count(ps, pid)
    types, proc_refs = parse_types(lines)
    return {
        "ts": time.time(),
        "total": len(lines),
        "truth_before": truth_before,
        "truth_after": truth_after,
        "types": types,
        "gone": proc_refs["gone_total"],
        "gone_refs": proc_refs["gone_refs"],
        "live_refs": proc_refs["live_refs"],
        "live_names": proc_refs["live_names"],
        "proc_refs": proc_refs,
    }


def _pid_delta(a_map, b_map, limit=8):
    """逐 pid 差值。返回 [(pid, delta), ...]，按 |delta| 降序。"""
    keys = set(a_map) | set(b_map)
    rows = []
    for k in keys:
        d = b_map.get(k, 0) - a_map.get(k, 0)
        if d:
            rows.append((k, d))
    rows.sort(key=lambda kv: -abs(kv[1]))
    return rows[:limit]


def diff_snapshots(a, b):
    """对比两次快照，回答「增长源在哪」。"""
    out = []
    dt = b["total"] - a["total"]
    dg = b["gone"] - a["gone"]
    dl = b["live_refs"] and sum(b["live_refs"].values()) or 0
    al = sum(a["live_refs"].values()) or 0
    dlive = dl - al
    out.append("  总句柄: %d -> %d  (%+d)" % (a["total"], b["total"], dt))
    out.append("  僵尸句柄(指向已退出进程): %d -> %d  (%+d)" % (a["gone"], b["gone"], dg))
    out.append("  存活目标句柄(指向活进程): %d -> %d  (%+d)" % (al, dl, dlive))
    out.append("")
    out.append("  %-22s %10s %10s %10s" % ("类型", "前", "后", "Δ"))
    keys = set(a["types"]) | set(b["types"])
    rows = []
    for k in keys:
        d = b["types"].get(k, 0) - a["types"].get(k, 0)
        if d:
            rows.append((d, k, a["types"].get(k, 0), b["types"].get(k, 0)))
    rows.sort(reverse=True)
    for d, k, av, bv in rows[:12]:
        out.append("  %-22s %10d %10d %+10d" % (k, av, bv, d))

    # 逐 pid 差值：这是「增长源在哪」的唯一可靠答案
    out.append("")
    out.append("  === 逐目标 pid 差值（增长源定位）===")
    gdelta = _pid_delta(a["gone_refs"], b["gone_refs"])
    ldelta = _pid_delta(a["live_refs"], b["live_refs"])
    if gdelta:
        out.append("  已退出目标 Δ:")
        for k, d in gdelta:
            out.append("    pid=%-10s %+d" % (k, d))
    else:
        out.append("  已退出目标 Δ: 无")
    if ldelta:
        out.append("  存活目标 Δ（名字取自 Handle 输出）:")
        for k, d in ldelta:
            out.append("    pid=%-10s %+d   %s"
                       % (k, d, b["live_names"].get(k, a["live_names"].get(k, ""))))
    else:
        out.append("  存活目标 Δ: 无")

    out.append("")
    if dt == 0:
        out.append("  判读: 总数**没变**。")
    elif dt > 0:
        out.append("  判读: 总数在涨 (+%d)。" % dt)
        if dg == 0 and dlive == 0:
            out.append("     僵尸与存活目标都没变 -> 增长来自**其他类型**（看上方逐类型 Δ）。")
        elif dg == 0 and dlive > 0:
            out.append("     僵尸数不变，**存活目标句柄在涨 (+%d)** -> 新增的 Process 句柄"
                       % dlive)
            out.append("     指向的进程**还活着**。查上方「存活目标 Δ」里的 pid，")
            out.append("     增长源就是那个 pid，别归给已退出的僵尸。")
        elif dg > 0 and abs(dg) >= abs(dt) * 0.5:
            out.append("     增长**主要来自僵尸句柄 (+%d)** -> 泄漏源是某个已退出的进程。" % dg)
            out.append("     查上方「已退出目标 Δ」里的 pid，治本在那个源。")
        else:
            out.append("     僵尸 %+d / 存活目标 %+d -> 增长混合，逐 pid Δ 已列出。" % (dg, dlive))
    else:
        out.append("  判读: 总数在**降** (-%d)。" % abs(dt))
        if dlive < 0:
            out.append("     存活目标句柄减少了 %d -> 有对象被关闭/退出了。" % abs(dlive))

    # Δ 比例（以 Process 为基准）—— 🔴 分母太小时这个比例毫无意义，必须抑制
    dp = b["types"].get("Process", 0) - a["types"].get("Process", 0)
    MIN_DP = 50
    if dp >= MIN_DP:
        out.append("")
        out.append("  Δ 比例（以 Process +%d 为基准，+1 Process 配套多少其它类型）:" % dp)
        for k in ("Event", "Token", "Key"):
            d = b["types"].get(k, 0) - a["types"].get(k, 0)
            if d:
                out.append("    %-8s %.2f" % (k, d / float(dp)))
    elif dp > 0:
        out.append("")
        out.append("  （Δ 比例已抑制：Process 只涨了 %d 个，低于下限 %d，比例无意义。）"
                   % (dp, MIN_DP))
    return "\n".join(out)


def run_diff(exe, pid, ps, interval, rounds):
    """连续采样并对比，捕捉「间歇性突跳」。"""
    snaps = []
    for i in range(rounds):
        s = snapshot(exe, pid, ps)
        snaps.append(s)
        print("[%d] %s 总句柄=%-8d 僵尸=%-7d 存活目标=%-6d | %s"
              % (i,
                 __import__("time").strftime("%H:%M:%S", __import__("time").localtime(s["ts"])),
                 s["total"], s["gone"], sum(s["live_refs"].values()),
                 " ".join("%s=%d" % (k, v)
                          for k, v in sorted(s["types"].items(), key=lambda kv: -kv[1])[:4])),
              flush=True)
        if i < rounds - 1:
            time.sleep(interval)
    print()
    print("=== 逐段增量 ===")
    segs = []
    for i in range(1, len(snaps)):
        d = snaps[i]["total"] - snaps[i - 1]["total"]
        dg = snaps[i]["gone"] - snaps[i - 1]["gone"]
        dl = (sum(snaps[i]["live_refs"].values())
              - sum(snaps[i - 1]["live_refs"].values()))
        dur = snaps[i]["ts"] - snaps[i - 1]["ts"]
        rate = d / dur * 60.0 if dur > 0 else 0.0
        segs.append((d, dur, rate))
        print("  [%d->%d] Δ总=%+7d  Δ僵尸=%+7d  Δ存活目标=%+7d  %6.1f 秒  %+8.1f 个/分钟"
              % (i - 1, i, d, dg, dl, dur, rate))
    # 🔴 突跳判定必须相对本轮各段，不能用固定阈值。
    #    固定阈值（如 500）在匀速增长时会把每一段都标成「突跳」，毫无信息量。
    if segs:
        rates = sorted(s[2] for s in segs)
        med = rates[len(rates) // 2]
        print()
        print("  各段速率中位数 = %+.1f 个/分钟" % med)
        # 🔴 突跳阈值必须相对**正**的基准。中位数可能是负数（整体在收缩），
        #    此时「> 3x 中位数」对负数没有意义。改用「显著高于中位数一个固定量」或
        #    直接与各段的最大值比较。
        spikes = []
        if med > 0:
            thr = max(med * 3, med + 5)
            spikes = [(i + 1, s) for i, s in enumerate(segs) if s[2] > thr]
        else:
            # 中位数 <= 0：只有明显为正且远高于其余段的才算突跳
            pos = [s[2] for s in segs if s[2] > 0]
            if pos:
                thr = max(pos) * 0.8
                spikes = [(i + 1, s) for i, s in enumerate(segs) if s[2] >= thr]
            else:
                print("  各段速率全部 ≤ 0（整体在收缩），无突跳可言。")
        if spikes:
            print("  相对基准的**突跳段**:")
            for idx, (d, dur, rate) in spikes:
                print("    段[%d->%d]  %+.1f 个/分钟" % (idx - 1, idx, rate))
        elif med > 0:
            print("  未见突跳段（各段速率都在中位数的 3 倍以内）。")
    print()
    print("=== 首尾对比 ===")
    print(diff_snapshots(snaps[0], snaps[-1]))
    print()
    print("  🔴 判读纪律:")
    print("     1) 单段平坦**不能**判定「稳态」——必须采样覆盖到至少一个突跳周期。")
    print("     2) 「僵尸数不变」只说明**存量僵尸不是增长源**，不等于「增长来自子进程容器」。")
    print("        增长源要看上方「逐目标 pid 差值」，分清是已退出目标还是存活目标。")
    print("     3) 本工具不预设「+X/分钟」的常数——各次实测速率不同，请引用当次输出。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
