#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
stale_session_cleanup.py  (v1)
回收「已关闭的 WorkBuddy/CodeBuddy 会话窗口」遗留的空壳进程组。

═══ 问题现象（2026-10-30 实测本机）═══
WorkBuddy 每个会话开一个 utility 进程（`WorkBuddy.exe <app.asar>`，
Electron 的 utility-main 类型），这个进程会带出一整棵子孙树
（node MCP server / cmd / conhost / python …）。
**会话窗口关掉后，这棵树不会被回收** —— Electron 只在应用整体退出时才清理。

实测：31 个 WorkBuddy.exe 里只有 **1 个**有可见窗口（当前这个），
另外 30 个是空壳；其中 19 个会话窗口创建于 26–48 小时前，
带着 **164 个进程 / 9.84GB** —— 相当于白占内存的一半。

═══ 为什么不能只按「创建时间」筛 ═══
🔴 容器进程（`utility-main`）里会**再开新会话**：
实测 417520 建于 48.5 小时前，但它的 3 个直接子会话是**今天**开的
（0.1h / 0.7h / 2.3h 前），正在干活。
按「创建时间 > 12h」一刀切，会把正在跑的会话一起杀掉。
→ 所以必须按**直接子进程**划界 + 组内「近期会话」安全阀。

═══ 判据 ═══
候选 = broker(utility-main 主进程) 的**直接子进程**中：
  1. 命令行含 `app.asar` 且**不含** `--type=`（排除 renderer/gpu/utility/crashpad 等基础设施）
  2. 进程年龄 >= --min-age-h（默认 6 小时）
  3. 组内**不含**年龄 < --min-age-h 的 WorkBuddy 会话（安全阀：有活跃会话就整组放弃）
  4. **没有活跃会话**（主判据，见下）
  5. CPU 增量 < --max-cpu（默认 1.0%，45 秒窗口实测）

═══ 主判据：会话心跳文件 ═══
🔴 **不要用 CPU 增量当主判据** —— 实测被关闭 43 小时的窗口里，
MCP server（`mcp/start.mjs` / `cli.cjs` / `rea.mjs`）仍在 4.7%–21.9% 的
「心跳式」空转，看起来像在干活，实际是**没有客户端在读它的 stdout 管道**。

真正可靠的判据是 **会话心跳文件**：
`%USERPROFILE%/.workbuddy/sessions/<PID>.json` —— WorkBuddy 给每个**活着的**
会话窗口写一个心跳文件（`lastHeartbeat` / `sessionId` / `url`）。
会话窗口关闭后，这个文件**不会留下**。

实测（2026-10-30）：24 个会话窗口进程里，**只有 4 个**有会话文件
（3 个 interactive + 1 个 prewarm），其余 20 个全是空壳 ——
这 20 个占 9.84GB。

主判据 = **没有 sessions/<PID>.json**，这是「确实已关闭」的硬证据。
CPU 增量降级为**次要守卫**（只拦极端值），不再当主判据。

受保护（永不动）：当前会话的整棵子树、broker 自身、Electron 基础设施子进程（--type=*）、
**所有有会话心跳文件且心跳新鲜的进程**、
**用户主动开着的工具进程**（见 `TOOL_PATTERNS`）。

═══ 实测踩到的坑：工具进程会挂在旧会话窗口下 ═══
🔴 2026-10-30 实测：本地控制台（`console_server.py`）当时正挂在某个
43 小时前的旧会话窗口下，第一次清理时**被一起带走了** ——
会话窗口没了，它也跟着死，端口 8765 直接不通。
→ 所以凡是「用户主动开着的东西」都必须显式保护，
不能指望它挂在当前会话下（本项目自己的 `console_server.py` 就不是）。

═══ 主判据：会话心跳文件 ═══

═══ 处置 ═══
对每个候选组的**根进程**执行 `taskkill /F /T`（/T = 连子孙一起）。
只杀根，让 Windows 正常回收子孙，避免逐个杀导致半死不活。
会话窗口已关闭，杀掉不影响任何可见界面。

守卫（任一不满足就跳过整组）
  - 当前会话的祖先链上的进程，一个都不碰
  - 组内有任何近期的活跃会话 -> 整组跳过
  - CPU 增量超阈值 -> 整组跳过（正在干活）

退出码
  0 = 正常（含「无需处理」与「被守卫跳过」）
  1 = 执行失败

用法
  python stale_session_cleanup.py                        # 演练（只报告不动手）
  python stale_session_cleanup.py --apply
  python stale_session_cleanup.py --apply --min-age-h 6
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fast_cmdline  # noqa: E402
import fast_probe  # noqa: E402
import nowin  # noqa: E402
import safe_print  # noqa: E402,F401

_k32 = ctypes.windll.kernel32
_k32.OpenProcess.restype = ctypes.c_void_p
_k32.GetProcessTimes.restype = ctypes.c_bool
_FT = ctypes.wintypes.FILETIME

# 主进程名候选（不同产品名）
APP_NAMES = ("workbuddy.exe", "codebuddy.exe")

# 🔴 用户主动开着的工具进程 —— 必须保护。
#    这些东西不一定挂在当前会话下（本项目的 console_server.py 就是
#    被挂在旧会话窗口下被误杀的），只能靠命令行特征显式认出来。
TOOL_PATTERNS = (
    "console_server.py",     # 本地控制台
    "agent_hygiene_audit.py",
    "stuck_process_cleanup.py",
    "stale_session_cleanup.py",
    "codex_sandbox_cleanup.py",
    "handle_type_breakdown.py",
    "trim_experiment.py",
)


def is_tool_process(cmdline):
    """命令行里命中工具特征 -> 是用户主动开着的工具，不能杀。"""
    if not cmdline:
        return False
    return any(p in cmdline for p in TOOL_PATTERNS)


def proc_create_time(pid):
    """返回进程创建时间（unix 时间戳），取不到返回 None。"""
    h = _k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    c, k, e, u = _FT(), _FT(), _FT(), _FT()
    ok = _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(k),
                              ctypes.byref(e), ctypes.byref(u))
    _k32.CloseHandle(h)
    if not ok:
        return None
    return ((c.dwHighDateTime << 32) | c.dwLowDateTime) / 10000000.0 - 11644473600


def children_map(procs):
    m = {}
    for pid, p in procs.items():
        pp = p.get("ppid")
        if pp is not None:
            m.setdefault(pp, []).append(pid)
    return m


def descendants(kids, pid):
    out = set()
    stack = list(kids.get(pid, []))
    while stack:
        x = stack.pop()
        if x in out:
            continue
        out.add(x)
        stack.extend(kids.get(x, []))
    return out


def my_ancestors(procs, pid):
    """自身 -> 根 的祖先链（含自身）。"""
    out = set()
    cur = pid
    for _ in range(16):
        if cur is None or cur in out:
            break
        out.add(cur)
        p = procs.get(cur)
        if not p:
            break
        cur = p.get("ppid")
    return out


def find_broker(procs, cmds):
    """broker = utility-main 类型的父进程（它自己直接持有会话子进程）。

    特征：命令行含 app.asar，且**没有** --type=，且是若干会话窗口的父。
    取「是 >=2 个会话窗口的父」里年龄最大的那个。
    """
    kids = children_map(procs)
    cand = []
    for pid, p in procs.items():
        if (p.get("name") or "").lower() not in APP_NAMES:
            continue
        cl = cmds.get(pid) or ""
        if "--type=" in cl or "app.asar" not in cl:
            continue
        n = sum(1 for c in kids.get(pid, [])
                if (procs.get(c, {}).get("name") or "").lower() in APP_NAMES
                and "--type=" not in (cmds.get(c) or "")
                and "app.asar" in (cmds.get(c) or ""))
        if n >= 1:
            cand.append((pid, n))
    if not cand:
        return None
    # 优先选子会话最多的；并列时取年龄最大的（更可能是 broker 而非某会话）
    best = None
    for pid, n in cand:
        ts = proc_create_time(pid) or 0
        key = (n, ts)
        if best is None or key > best[0]:
            best = (key, pid)
    return best[1]


def session_heartbeats():
    """读 `%USERPROFILE%\\.workbuddy\\sessions\\<PID>.json`。

    返回 {pid: {"sessionId":..., "lastHeartbeat": ms, "kind":...}}
    没有文件的 pid = 该会话窗口已关闭（残留空壳）。
    """
    import json
    d = os.path.join(os.path.expanduser("~"), ".workbuddy", "sessions")
    out = {}
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        stem = fn[:-5]
        if not stem.isdigit():
            continue
        try:
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                j = json.load(f)
            out[int(stem)] = {
                "sessionId": j.get("sessionId"),
                "kind": j.get("kind"),
                "lastHeartbeat": j.get("lastHeartbeat") or 0,
                "cwd": j.get("cwd"),
            }
        except Exception:
            continue
    return out


def build_plan(min_age_h, max_cpu, sample_s, probe_window_s):
    procs, meta = fast_probe.snapshot()
    cmds = fast_cmdline.all_cmdlines()
    kids = children_map(procs)
    now = time.time()
    hb = session_heartbeats()

    broker = find_broker(procs, cmds)
    if broker is None:
        return {"error": "找不到 broker 进程（utility-main 父进程）"}, None

    # 受保护：当前进程的祖先链 + broker 自身 + broker 的基础设施子进程
    protected = set(my_ancestors(procs, os.getpid()))
    protected.add(broker)
    for c in kids.get(broker, []):
        cl = cmds.get(c) or ""
        if "--type=" in cl:
            protected.add(c)
            protected |= descendants(kids, c)

    # 候选根 = broker 的直接子进程里的会话窗口
    roots = []
    skipped = []
    for pid in kids.get(broker, []):
        p = procs.get(pid)
        if not p or pid in protected:
            continue
        cl = cmds.get(pid) or ""
        if "--type=" in cl or "app.asar" not in cl:
            continue
        ts = proc_create_time(pid)
        age_h = (now - ts) / 3600.0 if ts else 0
        if age_h < min_age_h:
            continue
        grp = [pid] + sorted(descendants(kids, pid))
        # 安全阀 A：组内含近期活跃会话 -> 整组放弃
        recent = []
        for x in grp:
            if x == pid:
                continue
            if (procs.get(x, {}).get("name") or "").lower() not in APP_NAMES:
                continue
            t2 = proc_create_time(x)
            if t2 and (now - t2) / 3600.0 < min_age_h:
                recent.append(x)
        if recent:
            skipped.append({"pid": pid, "age_h": round(age_h, 1),
                            "reason": "含 %d 个近 %.0fh 内的活跃会话" % (len(recent), min_age_h),
                            "recent": recent})
            continue
        # 安全阀 C：组内含「用户主动开着的工具进程」-> 整组放弃
        tools = [x for x in grp if is_tool_process(cmds.get(x))]
        if tools:
            skipped.append({"pid": pid, "age_h": round(age_h, 1),
                            "reason": "组内含 %d 个用户主动开着的工具进程" % len(tools),
                            "tools": [(x, (cmds.get(x) or "")[-60:]) for x in tools[:3]]})
            continue
        # 安全阀 B（主判据）：组内任一进程有**新鲜的**会话心跳 -> 整组放弃
        alive_sess = []
        for x in grp:
            h = hb.get(x)
            if not h:
                continue
            age_ms = now * 1000 - (h["lastHeartbeat"] or 0)
            if age_ms < 10 * 60 * 1000:      # 心跳 10 分钟内 = 活着
                alive_sess.append((x, h["sessionId"], round(age_ms / 60000.0, 1)))
        if alive_sess:
            skipped.append({"pid": pid, "age_h": round(age_h, 1),
                            "reason": "组内有 %d 个活跃会话心跳" % len(alive_sess),
                            "alive": alive_sess[:5]})
            continue
        roots.append(pid)

    # 目标集合
    targets = set()
    for r in roots:
        targets.add(r)
        targets |= descendants(kids, r)

    # CPU 增量窗口（次要守卫）
    print("[*] 采样 CPU 增量，窗口 %ds ..." % probe_window_s)
    t1 = fast_probe.collect_cpu_ticks(procs)
    time.sleep(probe_window_s)
    procs2, _ = fast_probe.snapshot()
    delta = fast_probe.cpu_delta(t1, procs2)

    groups = []
    for r in roots:
        grp = [r] + sorted(descendants(kids, r))
        grp = [x for x in grp if x in procs2]
        mem = sum((procs2.get(x, {}).get("priv_mb") or 0) for x in grp)
        hd = sum((procs2.get(x, {}).get("handles") or 0) for x in grp)
        cpu = max([delta.get(x) or 0 for x in grp] or [0])
        ts = proc_create_time(r)
        item = {
            "root": r,
            "age_h": round((now - ts) / 3600.0, 1) if ts else None,
            "created": datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S") if ts else None,
            "n_proc": len(grp),
            "priv_mb": round(mem, 1),
            "handles": hd,
            "max_cpu": round(cpu, 2),
            "pids": sorted(grp),
            "hb": hb.get(r),
        }
        if cpu > max_cpu:
            item["skip"] = "CPU %.2f%% > 阈值 %.2f%%（疑似真在干活，保守跳过）" % (cpu, max_cpu)
        groups.append(item)

    plan = {
        "broker": broker,
        "min_age_h": min_age_h,
        "max_cpu": max_cpu,
        "protected_count": len(protected),
        "active_sessions": sorted(hb.keys()),
        "groups": groups,
        "skipped": skipped,
        "total_procs": len(targets),
        "total_mb": round(sum(g["priv_mb"] for g in groups if "skip" not in g), 1),
        "total_handles": sum(g["handles"] for g in groups if "skip" not in g),
    }
    return plan, procs2


def report(plan):
    print()
    print("=" * 68)
    print("stale_session_cleanup 演练报告")
    print("=" * 68)
    print("broker 进程 = %s   受保护进程 = %d 个（含当前会话整棵子树）"
          % (plan["broker"], plan["protected_count"]))
    print("活跃会话（有心跳文件）PID = %s" % (plan.get("active_sessions") or "无"))
    print()
    print("%-9s %8s %-14s %7s %9s %9s %8s" %
          ("ROOT", "年龄h", "创建于", "进程", "内存MB", "句柄", "CPU%"))
    print("-" * 78)
    for g in sorted(plan["groups"], key=lambda x: -x["priv_mb"]):
        flag = "  [跳过]" if "skip" in g else ""
        print("%-9s %8s %-14s %7d %9.1f %9d %8.2f%s" %
              (g["root"], g["age_h"], g["created"] or "-", g["n_proc"],
               g["priv_mb"], g["handles"], g["max_cpu"], flag))
    print("-" * 78)
    print("合计: %d 个进程, %.1f MB (%.2f GB), %d 句柄"
          % (plan["total_procs"], plan["total_mb"],
             plan["total_mb"] / 1024.0, plan["total_handles"]))
    if plan["skipped"]:
        print()
        print("安全阀跳过的组：")
        for s in plan["skipped"]:
            print("  PID=%-8s age=%sh  %s" % (s["pid"], s["age_h"], s["reason"]))
    print("=" * 78)


def apply_plan(plan):
    ok = 0
    fail = 0
    for g in plan["groups"]:
        if "skip" in g:
            print("  [跳过] PID=%s  %s" % (g["root"], g["skip"]))
            continue
        print("  杀 PID=%s (age=%sh, %d 进程, %.1fMB) ..." %
              (g["root"], g["age_h"], g["n_proc"], g["priv_mb"]))
        r = subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(g["root"])],
            capture_output=True, creationflags=nowin.no_window())
        if r.returncode == 0:
            ok += 1
        else:
            fail += 1
            print("     失败: %s" % (r.stderr or r.stdout).decode("mbcs", "ignore").strip())
    print()
    print("处置完成: 成功 %d 组, 失败 %d 组" % (ok, fail))
    return fail


def main():
    ap = argparse.ArgumentParser(description="回收已关闭会话窗口遗留的空壳进程组")
    ap.add_argument("--apply", action="store_true", help="真正动手（默认只演练）")
    ap.add_argument("--min-age-h", type=float, default=6.0, help="会话窗口最小年龄（小时），默认 6")
    ap.add_argument("--max-cpu", type=float, default=50.0,
                    help="CPU 增量阈值（%%），超过则保守跳过。默认 50 —— "
                         "主判据是会话心跳文件，CPU 只拦极端值")
    ap.add_argument("--probe-window-s", type=float, default=45.0, help="CPU 采样窗口（秒）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--no-log", action="store_true", help="不写日志")
    args = ap.parse_args()

    plan, _ = build_plan(args.min_age_h, args.max_cpu, args.probe_window_s, args.probe_window_s)
    if plan.get("error"):
        print("[!] %s" % plan["error"])
        return 0
    if args.json:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    report(plan)
    if not args.apply:
        print("（这是演练，没有动任何进程。要真清理加 --apply）")
        return 0
    if plan["total_mb"] <= 0:
        print("无需处理。")
        return 0
    fail = apply_plan(plan)
    if not args.no_log:
        try:
            from agent_hygiene_audit import _local_appdata
            d = os.path.join(_local_appdata(), "agent-hygiene", "logs")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "stale_session.log"), "a", encoding="utf-8") as f:
                f.write("%s 清理会话空壳 %d 组 / %.1f MB\n" %
                        (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         len([g for g in plan["groups"] if "skip" not in g]),
                         plan["total_mb"]))
        except Exception as e:
            print("  (写日志失败: %s)" % e)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
