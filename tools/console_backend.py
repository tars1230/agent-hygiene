#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
console_backend.py —— 本地控制台的后端逻辑（纯标准库，只读为主）

提供四类能力，供 console_server.py 的 HTTP API 调用：
  1. status()     即时状态（44ms 采样）：内存、句柄、异常候选、进程组
  2. audit()      完整体检（走现有 agent_hygiene_audit.py，含 Suspended 与类型分解）
  3. recipes()    建议清单：哪些已知配方现在可动、代价是什么、能不能自动执行
  4. tasks()      计划任务读写：看当前配置、改触发频率
  5. history()    历史管控记录：从 reports/ 与 logs/ 解析出时间序列

🔴 判据复用，不另造一套
  句柄/线程的异常判定直接复用 thread_handle_probe 的常量与思路，
  但**不 import 它**（它会拖进 PowerShell 路径）——
  这里只 import 常量，判据逻辑用 fast_probe 的数据重算。
  🔴 理由：两处各判一套 = 迟早分叉（这个项目已经吃过一次亏）。
"""
import glob
import json
import os
import re
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import fast_probe as fp  # noqa: E402
import nowin  # noqa: E402

# 🔴 数据目录定位必须复用 agent_hygiene_audit 的 _local_appdata(),
#    不能自己写 os.environ.get("LOCALAPPDATA") —— IDE 托管的 bash /
#    某些计划任务上下文里这个变量是 None, 回退到 expanduser("~") 会得到
#    C:\Users\<name>\agent-hygiene, 与真实目录 %LOCALAPPDATA%\agent-hygiene 不符,
#    结果是历史报告解析出 0 条(实测踩过)。
#    复用而非复制 = 避免两处各判一套(这个项目已经吃过一次亏)。
from agent_hygiene_audit import _local_appdata  # noqa: E402

# ---- 判据常量（与 thread_handle_probe.py 保持一致，改一处必须改两处）----
MIN_THREADS_ABS = 2000
MIN_HANDLES_ABS = 50000
SOLO_HANDLES_ABS = 20000
BURST_RATIO = 20.0

KERNEL_NAMES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "lsm.exe", "wininit.exe", "csrss.exe", "winlogon.exe",
    "fontdrvhost.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "explorer.exe",
    "spoolsv.exe", "memory compression", "registry", "secure system",
    "system idle process", "system interrupts",
}

APP_DATA = _local_appdata()
BASE_DIR = os.path.join(APP_DATA, "agent-hygiene")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
SNAP_DIR = os.path.join(BASE_DIR, "snapshots")

TASKS = [
    ("AgentHygiene-Weekly", "每周一体检（只读）"),
    ("CodexSandbox-Cleanup", "Codex 沙箱 VM 回收"),
    ("StuckProcess-Cleanup", "挂死进程 / 句柄泄漏扫描"),
]


def _median(xs):
    return statistics.median(xs) if xs else 0


def _peer_median(by_pid, self_pid):
    """leave-one-out：算自己的倍数时把「自己」从同伴里剔除。

    🔴 不剔除的话，离群实例会把自己藏住（组内 2 个：190000 + 243 -> 中位数 95121 -> 倍数 2.0）。
    """
    peers = [v for k, v in by_pid.items() if k != self_pid]
    return _median(peers) if peers else None


def analyze(procs):
    """用 fast_probe 的快照做异常判定。返回 (findings, groups)。"""
    by_exe = {}
    for pid, r in procs.items():
        nm = (r["name"] or "").lower()
        if nm in KERNEL_NAMES:
            continue
        by_exe.setdefault(nm, []).append(pid)

    all_h = [r["handles"] for r in procs.values() if r.get("handles")]
    all_t = [r["threads"] for r in procs.values() if r.get("threads")]
    g_h_med = _median(all_h) or 1
    g_t_med = _median(all_t) or 1

    findings = []
    for nm, pids in by_exe.items():
        solo = len(pids) == 1
        h_by = {p: (procs[p]["handles"] or 0) for p in pids}
        t_by = {p: (procs[p]["threads"] or 0) for p in pids}
        for pid in pids:
            r = procs[pid]
            h, t = r["handles"], r["threads"]
            if h is None:
                continue
            if solo:
                base_h = g_h_med
                base_t = g_t_med
                basis = "全局中位数"
            else:
                base_h = _peer_median(h_by, pid) or g_h_med
                base_t = _peer_median(t_by, pid) or g_t_med
                basis = "同exe同伴中位数(剔除自身)"
            hr = (h / base_h) if base_h else 0
            tr = (t / base_t) if base_t else 0

            if t >= MIN_THREADS_ABS and tr >= BURST_RATIO:
                findings.append({
                    "pid": pid, "name": r["name"], "kind": "thread",
                    "threads": t, "handles": h, "priv_mb": r["priv_mb"],
                    "burst_ratio": round(tr, 1), "basis": basis,
                    "reason": "线程数是%s的 %.1f 倍" % (basis, tr),
                })
            hdl_min = MIN_HANDLES_ABS if not solo else SOLO_HANDLES_ABS
            if h >= hdl_min and hr >= BURST_RATIO:
                findings.append({
                    "pid": pid, "name": r["name"], "kind": "handle",
                    "threads": t, "handles": h, "priv_mb": r["priv_mb"],
                    "burst_ratio": round(hr, 1), "basis": basis,
                    "reason": "句柄数是%s的 %.1f 倍" % (basis, hr),
                })

    findings.sort(key=lambda f: -(f["handles"] or 0))
    groups = _group_clusters(procs)
    return findings, groups


def _group_clusters(procs):
    """进程组聚类：同一入口脚本起了多少套（会话堆积检测）。

    🔴 必须排除包装壳：cmd 包装层与真解释器层都带同一脚本路径，
    按进程计数会双倍虚高。
    """
    SHELLS = {"cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
              "bash.exe", "sh.exe", "wscript.exe", "cscript.exe"}
    groups = {}
    for pid, r in procs.items():
        nm = (r["name"] or "").lower()
        if nm in SHELLS:
            continue
        cmd = _cmdline(pid)
        if not cmd:
            continue
        m = re.search(r"[\\/]([^\s\\/]+\.(?:js|cjs|mjs))", cmd)
        if not m:
            continue
        script = m.group(1)
        pkg = ""
        pm = re.search(r"[\\/](node_modules[\\/]([^\s\\/]+))", cmd)
        if pm:
            pkg = pm.group(1)
        else:
            pm2 = re.search(r"[\\/]plugins[\\/]cache[\\/]([^\s\\/]+)", cmd)
            if pm2:
                pkg = "cache\\" + pm2.group(1)
        g = groups.setdefault(pkg + "\\" + script, {"pids": [], "priv": 0.0})
        g["pids"].append(pid)
        g["priv"] += r["priv_mb"] or 0.0

    out = []
    for key, g in groups.items():
        if len(g["pids"]) < 5 or g["priv"] < 200.0:
            continue
        parts = key.replace("/", "\\").split("\\")
        short = "\\".join(parts[-2:]) if len(parts) > 2 else key
        out.append({"script": short, "count": len(g["pids"]),
                    "priv_mb": round(g["priv"], 1), "pids": g["pids"]})
    out.sort(key=lambda x: -x["priv_mb"])
    return out


_CMD_CACHE = {}


def _cmdline(pid):
    """取命令行。走一次 WMI 全表并缓存（fast_probe 的 ToolHelp 拿不到命令行）。"""
    if _CMD_CACHE.get("_ts", 0) < time.time() - 20:
        _CMD_CACHE.clear()
        _CMD_CACHE["_ts"] = time.time()
        try:
            import fast_cmdline
            _CMD_CACHE.update(fast_cmdline.all_cmdlines())
        except Exception:
            pass
    return _CMD_CACHE.get(pid)


# ---------------------------------------------------------------- 状态


def status(cpu_state=None):
    """即时状态。cpu_state 用于算 CPU 增量（跨请求保持）。"""
    procs, meta = fp.snapshot()
    mem = fp.memory_status()
    findings, groups = analyze(procs)

    now = time.time()
    prev = (cpu_state or {}).get("ticks") or {}
    prev_t = (cpu_state or {}).get("ts") or 0
    cpu_delta = {}
    if prev and (now - prev_t) >= 1.0:
        cpu_delta = fp.cpu_delta(prev, procs)
        window = now - prev_t
    else:
        window = 0

    if cpu_state is not None:
        cpu_state["ticks"] = fp.collect_cpu_ticks(procs)
        cpu_state["ts"] = now

    total_h = sum(r["handles"] or 0 for r in procs.values())
    total_priv = sum(r["priv_mb"] or 0 for r in procs.values())
    top_mem = sorted(procs.items(), key=lambda kv: -(kv[1]["priv_mb"] or 0))[:8]
    top_h = sorted([kv for kv in procs.items() if kv[1]["handles"]],
                    key=lambda kv: -kv[1]["handles"])[:8]

    # ---- 「我这个套装自己占了多少」 ----
    # 🔴 用户场景是「我觉得卡，点开看一眼」。
    #    全系统里有多少是本套装（WorkBuddy + node 家族）造成的，
    #    这个数字比「全系统已用」更能直接回答问题。
    #
    # 🔴 口径必须是**父进程链归属**，不能按进程名猜：
    #    实测（2026-10-30）按名字算 conhost+powershell 会多算 391MB：
    #      powershell.exe 780.7MB 里，318.8MB 的父进程已死（孤儿，
    #        不是本套装的）、72.6MB 属于 uuyc-mux.exe（别的软件）；
    #      conhost.exe 632.2MB 里，13.2MB 属于 nssm.exe（别的服务）。
    #    正确口径：向上回溯父进程链，链上出现 WorkBuddy.exe / node.exe
    #    才算本套装的。
    SUITE_ROOTS = ("workbuddy.exe", "node.exe")
    SUITE_HELPER = ("conhost.exe", "powershell.exe", "python.exe", "pythonw.exe")

    def belongs_to_suite(pid):
        """向上回溯父进程链，看是否归根到 WorkBuddy.exe / node.exe。"""
        seen = set()
        cur = pid
        for _ in range(12):          # 防御环
            if cur is None or cur in seen:
                break
            seen.add(cur)
            info = procs.get(cur)
            if not info:
                return False          # 父进程已死 -> 不算本套装
            nm = (info["name"] or "").lower()
            if nm in SUITE_ROOTS:
                return True
            cur = info.get("ppid")
        return False

    suite = {"priv_mb": 0.0, "procs": 0}
    suite_procs = []
    for pid, r in procs.items():
        nm = (r["name"] or "").lower()
        if nm not in SUITE_ROOTS and nm not in SUITE_HELPER:
            continue
        if not belongs_to_suite(pid):
            continue
        suite["priv_mb"] += r["priv_mb"] or 0.0
        suite["procs"] += 1
        suite_procs.append((pid, nm, r["priv_mb"] or 0.0))
    suite["priv_mb"] = round(suite["priv_mb"], 1)
    suite["pct_of_used"] = (
        round(suite["priv_mb"] / total_priv * 100, 1) if total_priv else 0)
    fam = {}
    for pid, nm, mbv in suite_procs:
        f = fam.setdefault(nm, {"priv_mb": 0.0, "procs": 0})
        f["priv_mb"] += mbv
        f["procs"] += 1
    suite["families"] = [
        {"name": k, "priv_mb": round(v["priv_mb"], 1), "procs": v["procs"]}
        for k, v in sorted(fam.items(), key=lambda kv: -kv[1]["priv_mb"])]

    return {
        "ts": now,
        "mem": mem,
        "sample_ms": meta["elapsed_ms"],
        "proc_count": meta["total"],
        "degraded": meta["degraded"],
        "total_handles": total_h,
        "total_priv_mb": round(total_priv, 1),
        "suite": suite,
        "findings": findings,
        "groups": groups,
        "cpu_window_sec": round(window, 1),
        "cpu_delta": {str(k): v for k, v in
                      sorted(cpu_delta.items(), key=lambda kv: -kv[1])[:12]},
        "top_mem": [{"pid": p, "name": r["name"], "priv_mb": r["priv_mb"],
                     "handles": r["handles"], "threads": r["threads"]}
                    for p, r in top_mem],
        "top_handles": [{"pid": p, "name": r["name"], "handles": r["handles"],
                         "priv_mb": r["priv_mb"], "threads": r["threads"]}
                        for p, r in top_h],
    }


# ---------------------------------------------------------------- 建议


RECIPES = [
    {
        "id": "explorer",
        "name": "重启桌面外壳 explorer.exe",
        "symptom": "explorer 线程数爆炸 / 句柄泄漏",
        "apply_cmd": ["python", "tools/stuck_process_cleanup.py", "--apply"],
        "auto": False,
        "cost": "关掉所有文件夹窗口（可恢复）",
        "risk": "low",
    },
    {
        "id": "git",
        "name": "杀挂死的 git 进程",
        "symptom": "git push 因凭据提示被吞而永久挂起",
        "apply_cmd": ["python", "tools/stuck_process_cleanup.py", "--apply"],
        "auto": True,
        "cost": "中断未完成的 push（可重试）",
        "risk": "low",
    },
    {
        "id": "handle",
        "name": "杀句柄泄漏进程（微信等）",
        "symptom": "句柄数是同exe同伴中位数的 20 倍以上且 CPU≈0",
        "apply_cmd": ["python", "tools/stuck_process_cleanup.py", "--apply",
                      "--kill-handle-leak"],
        "auto": False,
        "cost": "丢失登录态 / 未发送消息 / 小程序容器（不可逆）",
        "risk": "high",
    },
    {
        "id": "codex",
        "name": "回收 Codex 沙箱 VM 残留",
        "symptom": "vmmem 常驻且无 worker",
        "apply_cmd": ["python", "tools/codex_sandbox_cleanup.py", "--apply"],
        "auto": True,
        "cost": "无（下次用时自动重建）",
        "risk": "low",
    },
]


def recipes(status_data=None):
    """给建议清单，并标注每条现在能不能动。"""
    out = []
    for r in RECIPES:
        item = dict(r)
        item["apply_cmd_str"] = " ".join(r["apply_cmd"])
        if r["id"] == "handle" and status_data:
            hits = [f for f in status_data.get("findings", [])
                    if f["kind"] == "handle"]
            item["hit_count"] = len(hits)
            item["hit_now"] = bool(hits)
            item["hit_names"] = sorted({f["name"] for f in hits})
        elif r["id"] == "explorer" and status_data:
            hits = [f for f in status_data.get("findings", [])
                    if f["kind"] == "thread" and f["name"].lower() == "explorer.exe"]
            item["hit_count"] = len(hits)
            item["hit_now"] = bool(hits)
        else:
            item["hit_count"] = 0
            item["hit_now"] = False
        out.append(item)
    return out


# ---------------------------------------------------------------- 计划任务

TASK_SCRIPT = os.path.join(HERE, "console_tasks.py")


def tasks(force=False):
    """读计划任务状态（走 console_tasks.py，隔离 PowerShell 调用）。

    🔴 必须缓存：实测每次查询要 spawn PowerShell，**冷启动 6.3 秒**。
    页面首屏 + 10 秒轮询都打这个接口，不缓存的话每次刷新都卡 6 秒。
    缓存 30 秒：任务触发器/参数的改动频率极低，30 秒延迟完全可接受。
    改动操作走 console_tasks.py 的 _log 落盘，不依赖这里的缓存失效。
    """
    now = time.time()
    if not force and now - _TASK_CACHE.get("_ts", 0) < 30:
        return _TASK_CACHE["data"]
    try:
        r = subprocess.run([nowin.py_exe(), TASK_SCRIPT, "list"],
                           capture_output=True, timeout=60,
                           creationflags=nowin.no_window())
        data = json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    except Exception as e:
        data = {"error": str(e), "tasks": []}
    _TASK_CACHE["_ts"] = now
    _TASK_CACHE["data"] = data
    return data


_TASK_CACHE = {}


# ---------------------------------------------------------------- 历史


def _parse_reports():
    """从 reports/*.md 解析历史体检数据 -> 时间序列。

    🔴 三条纪律（都是实测踩出来的）：
    1. **「没有该字段」≠「值为 0」**。旧报告（如 10-22 / 10-29 09:25）
       根本没有 4b 章节，此时 anomaly_candidates 必须给 None（缺证据），
       不能给 0——给了 0，趋势图上就是一段假的「零异常」低谷。
       判据：先找「判定: N 个异常候选」这行；找不到就 None。
    2. **僵尸句柄要跨进程求和**。4c 章节里每个被分解的进程各有一行
       「指向已退出进程的僵尸句柄 N 个」。只取第一行会漏掉另外两个
       （实测 10-29 报告：Weixin 29641 + WorkBuddy 6441 + wetype 4842 = 40924）。
    3. **commit 缺失就是缺失**。有的旧报告根本没输出 commit 行 -> None。
    """
    rows = []
    for f in sorted(glob.glob(os.path.join(REPORTS_DIR, "hygiene-*.md"))):
        try:
            t = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        ts = None
        m = re.search(r"体检报告\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", t)
        if m:
            ts = m.group(1)
        else:
            m2 = re.search(r"hygiene-(\d{8})-(\d{6})", os.path.basename(f))
            if m2:
                ts = "%s-%s-%s %s:%s:%s" % (m2.group(1)[:4], m2.group(1)[4:6],
                                           m2.group(1)[6:], m2.group(2)[:2],
                                           m2.group(2)[2:4], m2.group(2)[4:])
        avail = commit = None
        ma = re.search(r"可用\s+(\d+)MB\s*/\s*共\s*(\d+)MB,\s*load\s*(\d+)%", t)
        if ma:
            avail = int(ma.group(1))
        mc = re.search(r"commit:\s*(\d+)MB\s*/\s*(\d+)MB", t)
        if mc:
            commit = int(mc.group(1))

        # 异常候选数：只认「判定: N 个异常候选」这一行，取不到 = 缺数据(None)
        cand = None
        mm = re.search(r"判定:\s*(\d+)\s*个异常候选", t)
        if mm:
            cand = int(mm.group(1))

        # 僵尸句柄：跨所有被分解的进程求和
        zl = [int(x) for x in
              re.findall(r"指向\*\*已退出进程\*\*的僵尸句柄\s*\*\*(\d+)\s*个\*\*", t)]
        zombie = sum(zl) if zl else None

        rows.append({"ts": ts, "avail_mb": avail, "commit_mb": commit,
                     "anomaly_candidates": cand, "zombie_handles": zombie,
                     "zombie_parts": len(zl),
                     "file": os.path.basename(f)})
    return rows


def _parse_logs():
    """从 logs/*.log 解析管控动作记录（回收日志）。

    🔴 「建议命令」不等于「已执行」。
       实测日志里这一行：
         建议命令: taskkill /F /T /PID 11788  ⚠️ 会丢失该应用的登录态与未完成会话
       说的是「**如果**开了 --kill-handle-leak 就会这么杀」，
       实际这一行对应的是「只报告(需 --kill-handle-leak 才动手)」。
       早先用 `if "taskkill" in msg` 判 kill，会把**建议**误报成**已终止**——
       图表上「终止次数」虚高，是假数据。
       判据顺序：先看「建议命令」→ 归为 report（建议），再看真执行痕迹。
    """
    out = []
    for f in sorted(glob.glob(os.path.join(LOGS_DIR, "*.log"))):
        try:
            lines = open(f, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        for line in lines:
            m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*(.*)", line)
            if not m:
                continue
            ts, msg = m.group(1), m.group(2).strip()
            action = "info"
            if "建议命令" in msg:
                action = "report"          # 只是建议，没动手
            elif re.search(r"清理完成,\s*成功\s*[1-9]\d*\s*/", msg):
                action = "kill"            # 真杀了：成功数 > 0
            elif "杀 PID=" in msg and "失败" in msg:
                action = "kill_failed"
            elif "跳过" in msg or "在干活" in msg or "只报告" in msg:
                action = "skip"
            elif "开始" in msg:
                action = "start"
            elif "结束" in msg:
                action = "end"
            out.append({"ts": ts, "action": action, "msg": msg,
                        "file": os.path.basename(f)})
    return out


def history():
    """历史管控记录 + 趋势时间序列。"""
    reports = _parse_reports()
    logs = _parse_logs()
    snaps = []
    for f in sorted(glob.glob(os.path.join(SNAP_DIR, "*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
            snaps.append({"file": os.path.basename(f), "ts": d.get("ts"),
                          "avail_mb": d.get("avail_mb"),
                          "total_handles": d.get("total_handles"),
                          "anomaly_count": d.get("anomaly_count")})
        except Exception:
            continue
    kills = [l for l in logs if l["action"] == "kill"]
    skips = [l for l in logs if l["action"] == "skip"]
    reports = [l for l in logs if l["action"] == "report"]
    failed = [l for l in logs if l["action"] == "kill_failed"]
    return {
        "reports": reports,
        "logs": logs[-200:],
        "snapshots": snaps,
        "stats": {
            # 🔴 键名不能撞车：体检报告份数 vs 建议条数，两个都是「条数」，
            #    之前都叫 report_count / suggest_count 混在一起，
            #    前端读 report_count 显示「6 份体检」——实际是 22 份，
            #    真实值被覆盖成了建议数。改用互不相同的名字。
            "audit_count": len(reports),
            "log_count": len(logs),
            "kill_count": len(kills),
            "skip_count": len(skips),
            "suggest_count": len(reports),
            "kill_failed_count": len(failed),
        },
    }


def save_snapshot(st):
    """存档一次即时快照，供趋势图使用。"""
    try:
        os.makedirs(SNAP_DIR, exist_ok=True)
        p = os.path.join(SNAP_DIR, "snap-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(),
                       "iso": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "avail_mb": st["mem"]["avail_phys_mb"],
                       "total_handles": st["total_handles"],
                       "anomaly_count": len(st["findings"]),
                       "load_pct": st["mem"]["load_pct"]}, f, ensure_ascii=False)
        return p
    except Exception:
        return None
