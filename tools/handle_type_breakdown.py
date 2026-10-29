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
  1. `handle64.exe -p <pid>` **默认只列「有名字」的句柄**。Weixin 主进程 178029 个句柄，
     默认输出只有 **487 行**，最大句柄值只到 0xFB4(4020) —— 看着像句柄很少，
     实际是**只枚举了前 4020 号槽位**。必须加 `-a`（全部）才输出 178034 行。
     🔴 拿默认输出下结论 = 结论完全错。
  2. 无名句柄的「名字」列是空的，所以 `sed` 统计类型时不能靠名字列，
     要靠 `类型:` 那一列（行首 `  <hex>: <Type> <name>`）。
  3. Process 句柄指向已退出进程时显示 `<Nonexistent process>(pid)` —— 这不是
     Handle 的 bug，是**僵尸句柄的直接证据**。

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

# Handle.exe 位置优先级：
#   1) 环境变量 AGENT_HYGIENE_HANDLE_EXE
#   2) 仓库内 _vendor/Handle/handle64.exe（若用户放了）
#   3) PATH
# 找不到就明确报错，不猜。
_HANDLE_ENV = "AGENT_HYGIENE_HANDLE_EXE"

_TYPE_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s+([A-Za-z_][A-Za-z_0-9]*)")
_PROC_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s+Process\s+(.*)$")


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
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    text = _decode(p.stdout or b"")
    # stderr 里是 banner（Copyright/Nthandle），stdout 才是句柄列表
    lines = [l for l in text.splitlines() if _TYPE_RE.match(l)]
    return text, lines


def parse_types(lines):
    """统计类型分布。返回 (type_counter_list, process_ref_counter)。"""
    types = {}
    proc_refs = {}
    for l in lines:
        m = _TYPE_RE.match(l)
        if not m:
            continue
        t = m.group(2)
        types[t] = types.get(t, 0) + 1
        pm = _PROC_RE.match(l)
        if pm:
            name = pm.group(2).strip()
            # name 形如 "<Nonexistent process>(20764)" 或 "Weixin.exe(1234)"
            mm = re.search(r"\((\d+)\)\s*$", name)
            key = mm.group(1) if mm else name
            gone = "Nonexistent" in name
            proc_refs[key] = proc_refs.get(key, 0) + 1
            if gone:
                proc_refs.setdefault("__gone__", 0)
                proc_refs["__gone__"] += 1
    return types, proc_refs


def process_handle_count(ps, pid):
    """用 Get-Process 拿该 pid 的句柄数（校验 Handle 输出完整性）。"""
    script = ("$p=Get-Process -Id %d -ErrorAction SilentlyContinue; "
              "if($p){ $p.HandleCount }" % int(pid))
    try:
        p = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=60)
        t = _decode(p.stdout or b"").strip()
        return int(t) if t.isdigit() else None
    except Exception:
        return None


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

    truth = process_handle_count(ps, a.pid)
    try:
        text, lines = list_handles(exe, a.pid)
    except subprocess.TimeoutExpired:
        print("[fail] Handle 执行超时（PID %d 句柄过多时可能发生）" % a.pid)
        return 1
    except Exception as e:
        print("[fail] Handle 执行失败: %s" % e)
        return 1

    types, proc_refs = parse_types(lines)
    total = len(lines)

    if a.json:
        print(json.dumps({
            "pid": a.pid,
            "handle_total": total,
            "process_handle_count": truth,
            "types": types,
            "process_refs": proc_refs,
        }, ensure_ascii=False, indent=2))
        return 0

    print("PID %d 句柄类型分解" % a.pid)
    print("  Handle -a 列出 %d 个句柄" % total)
    if truth is not None:
        ok = "一致" if truth == total else "不一致(差 %d)" % (total - truth)
        print("  Get-Process 报告 %d 个  ->  %s" % (truth, ok))
    print()
    print("  %-22s %8s %7s" % ("类型", "数量", "占比"))
    for t, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top]:
        pct = (c * 100.0 / total) if total else 0
        print("  %-22s %8d %6.2f%%" % (t, c, pct))
    if total > sum(c for _, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top]):
        rest = total - sum(c for _, c in sorted(types.items(), key=lambda kv: -kv[1])[:a.top])
        print("  %-22s %8d %6.2f%%" % ("(其余)", rest, rest * 100.0 / total if total else 0))

    gone = proc_refs.get("__gone__", 0)
    if gone:
        print()
        print("  🔴 指向**已退出进程**的僵尸句柄: %d 个 (占 %.2f%%)"
              % (gone, gone * 100.0 / total if total else 0))
        refs = sorted(((k, v) for k, v in proc_refs.items()
                       if k != "__gone__"), key=lambda kv: -kv[1])[:10]
        print("     泄漏源 pid 分布:")
        for pid_k, cnt in refs:
            print("       pid=%-8s %6d 个句柄" % (pid_k, cnt))
        print("     判读: 这些进程已退出，但句柄仍被持有且从未 CloseHandle")
        print("           -> 典型的 DuplicateHandle/CreateProcess 后未清理。")
    return 0


def snapshot(exe, pid, ps):
    """取一次完整快照，供 diff 用。"""
    _, lines = list_handles(exe, pid)
    types, proc_refs = parse_types(lines)
    truth = process_handle_count(ps, pid)
    return {
        "ts": time.time(),
        "total": len(lines),
        "truth": truth,
        "types": types,
        "gone": proc_refs.get("__gone__", 0),
        "proc_refs": proc_refs,
    }


def diff_snapshots(a, b):
    """对比两次快照，回答「增长源在哪」。"""
    out = []
    out.append("  总句柄: %d -> %d  (%+d)" % (a["total"], b["total"], b["total"] - a["total"]))
    out.append("  僵尸句柄(指向已退出进程): %d -> %d  (%+d)"
               % (a["gone"], b["gone"], b["gone"] - a["gone"]))
    dt = b["total"] - a["total"]
    dg = b["gone"] - a["gone"]
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

    out.append("")
    if dg == 0 and dt != 0:
        out.append("  🔴 判读: **僵尸句柄数不变，但总数在涨** -> 增长源是**存活对象**的句柄")
        out.append("     （如频繁创建/退出的子进程容器，创建了却没 CloseHandle）。")
        out.append("     处置含义: 重启只能回收**存量**，治本要关掉触发频繁创建的行为。")
    elif dg != 0 and dt != 0 and abs(dg) >= abs(dt) * 0.5:
        out.append("  🔴 判读: 增长**主要来自僵尸句柄** -> 泄漏源是某个已退出的进程")
        out.append("     （查下面的泄漏源 pid 分布，治本在那个源）。")
    else:
        out.append("  判读: 僵尸与存活的增长混合，需看上表逐类型 Δ。")
    # Δ 比例（以 Process 为基准）
    dp = b["types"].get("Process", 0) - a["types"].get("Process", 0)
    if dp > 0:
        out.append("")
        out.append("  Δ 比例（以 Process 为基准，+1 Process 配套多少其它类型）:")
        for k in ("Event", "Token", "Key"):
            d = b["types"].get(k, 0) - a["types"].get(k, 0)
            if d:
                out.append("    %-8s %.2f" % (k, d / float(dp)))
    return "\n".join(out)


def run_diff(exe, pid, ps, interval, rounds):
    """连续采样并对比，捕捉「间歇性突跳」。"""
    snaps = []
    for i in range(rounds):
        s = snapshot(exe, pid, ps)
        snaps.append(s)
        print("[%d] 总句柄=%-8d 僵尸=%-8d 类型: %s"
              % (i, s["total"], s["gone"],
                 " ".join("%s=%d" % (k, v)
                          for k, v in sorted(s["types"].items(), key=lambda kv: -kv[1])[:3])),
              flush=True)
        if i < rounds - 1:
            time.sleep(interval)
    print()
    print("=== 逐段增量 ===")
    for i in range(1, len(snaps)):
        d = snaps[i]["total"] - snaps[i - 1]["total"]
        dg = snaps[i]["gone"] - snaps[i - 1]["gone"]
        print("  [%d->%d] Δ总=%+7d  Δ僵尸=%+7d  %s"
              % (i - 1, i, d, dg, "← 突跳" if d > 500 else ""))
    print()
    print("=== 首尾对比 ===")
    print(diff_snapshots(snaps[0], snaps[-1]))
    print()
    print("  🔴 判读纪律: 单段平坦**不能**判定「稳态」。")
    print("     必须采样覆盖到至少一个突跳周期（实测 Weixin 前 7 分钟平坦，"
          "第 8 分钟 +2053 突跳，随后 +675/分钟）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
