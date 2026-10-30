#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
agent_hygiene_audit.py —— AI 宿主/多 agent 电脑的内存体检（只读，绝不杀进程）

定位
  给装了多个 AI agent（WorkBuddy / Codex / MiniMax / opencode / cursor-agent / TDX 桥…）的
  Windows 工作站做定期体检。回答三个问题：
    1. 内存压力到底在哪（commit / Private，不是 WS）
    2. 谁是「在干活」，谁是「疑似泄漏」（用 CPU 采样区分，不靠名字猜）
    3. 有没有已知模式的泄漏（孤儿进程 / HCS 沙箱遗留 / shim 重复计数）

纪律（这条 skill 的灵魂，都是实测换来的）
  - 只读。任何回收动作只打印建议命令，绝不执行 —— 「在干活」和「泄漏」机器分不清，
    opencode 954MB 看着像泄漏，实际在跑任务（CPU 530s）。
  - 报占用用 Private/Commit，不报 WS。WS 会被系统 trim，SetProcessWorkingSetSize(-1,-1)
    实测只降 WS 不降 Private（tools/trim_experiment.py）。
  - 服务的进程常驻是设计（父进程=services.exe / StartMode=Auto），不算泄漏。
  - 「可用内存低」≠「有泄漏」，先查进程在不在干活。
  - 每条结论都要能从报告里的原始数字复核出来。

用法
    python agent_hygiene_audit.py                  # 体检, 输出到控制台 + 报告文件
    python agent_hygiene_audit.py --sample-sec 8   # 拉长 CPU 采样窗(默认 5s)
    python agent_hygiene_audit.py --top 20         # 详列前 N 个进程
    python agent_hygiene_audit.py --no-report      # 不写报告文件
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import json
import os
import re
import subprocess
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402
import safe_print  # noqa: E402,F401  (pythonw 下 print 不炸)

# 🔴 同目录模块（thread_handle_probe）必须可导入 —— 用户可能从任意 cwd 调用本脚本。
#    sys.path[0] 只在「以脚本路径直接运行」时才是脚本目录，从别处 import 就找不到了。
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

def _local_appdata():
    """定位 %LOCALAPPDATA%。

    🔴 不能只靠 os.environ.get("LOCALAPPDATA"): IDE 托管的 bash / 某些计划任务上下文里
       这个变量可能缺失 -> 回退到 expanduser("~") 会把报告写到 C:\\Users\\<name>\\agent-hygiene,
       与 README 承诺的 %LOCALAPPDATA%\\agent-hygiene 不一致(实测踩过: 报告落在家目录)。
       Windows 上直接按已知路径推导, 不依赖环境变量。
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


DEFAULT_REPORT_DIR = os.path.join(_local_appdata(), "agent-hygiene", "reports")
MIN_ORPHAN_AGE_H = 1.0
ORPHAN_MIN_PRIV_MB = 50.0
# 会话堆积判据: 同一入口脚本起这么多实例, 且合计占用这么多内存
GROUP_MIN_INSTANCES = 5
GROUP_MIN_PRIV_MB = 200.0
RENDERER_BIG_MB = 500.0

# 内核/系统进程: 没有 Private 概念(cb=0), 放进榜单只会污染排序
KERNEL_NAMES = {
    "system idle process", "system", "secure system", "registry",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "lsaiso.exe", "dwm.exe", "fontdrvhost.exe", "memory compression",
    "memcompression", "audiodg.exe", "vmmem", "vmmemwsl",
}

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

TH32CS_SNAPPROCESS = 0x00000002
PQLI = 0x1000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


def snap_processes():
    """[(pid, name, ppid)]"""
    s = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if s in (-1, 0xFFFFFFFF):
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    out, ok = [], k32.Process32FirstW(s, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.szExeFile, pe.th32ParentProcessID))
        ok = k32.Process32NextW(s, ctypes.byref(pe))
    k32.CloseHandle(s)
    return out


def proc_times(pid):
    h = k32.OpenProcess(PQLI, False, pid)
    if not h:
        return None, None
    try:
        c, e, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)):
            return None, None
        ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
        return ft / 1e7 - 11644473600.0, (kt.dwHighDateTime << 32 | kt.dwLowDateTime) / 1e7 + \
            (ut.dwHighDateTime << 32 | ut.dwLowDateTime) / 1e7
    finally:
        k32.CloseHandle(h)


class PMC(ctypes.Structure):
    """PROCESS_MEMORY_COUNTERS_EX。cb 必须先赋 sizeof, 否则 GetProcessMemoryInfo 静默失败"""
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t)]


def proc_priv_mb(pid):
    h = k32.OpenProcess(PQLI, False, pid)
    if not h:
        return None
    try:
        psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD]
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), ctypes.sizeof(PMC)):
            return round(pmc.PrivateUsage / 1048576, 1)
        return None
    finally:
        k32.CloseHandle(h)


# 绝对路径: 某些受控环境(IDE 托管的 bash)PATH 不含 System32\WindowsPowerShell,
# 裸 "powershell" 会 WinError 2 —— 这也是第一用户兼容性 bug
PS_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                      "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def wmi_processes():
    """[{pid,ppid,name,exe,cmd}]  —— 走一次 WMI 拿命令行, 体检类工具可以慢"""
    cmd = ("Get-CimInstance Win32_Process | "
           "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
           "ConvertTo-Json -Compress -Depth 2")
    try:
        p = subprocess.run([PS_EXE, "-NoProfile", "-NonInteractive", "-Command", cmd],
                           capture_output=True, text=True, timeout=120,
                           encoding="utf-8", errors="replace", creationflags=nowin.no_window())
        data = json.loads(p.stdout or "[]")
        if isinstance(data, dict):
            data = [data]
        for d in data:
            d["cmd"] = d.get("CommandLine") or ""
            d["exe"] = d.get("ExecutablePath") or ""
        return data
    except Exception as e:
        print("[warn] WMI failed: %s" % e)
        return []


def parse_prev_report(path):
    """从旧报告解析家族表/commit/avail; 解析失败或明显无效(最大 Priv<100MB)返回 None"""
    fam, commit, avail = {}, None, None
    try:
        for line in open(path, encoding="utf-8"):
            line = line.rstrip("\n")
            if line.startswith("- commit:"):
                try:
                    commit = float(line.split(":")[1].split("MB")[0].strip())
                except Exception:
                    pass
            elif line.startswith("- 物理:"):
                try:
                    avail = float(line.split("可用")[1].split("MB")[0].strip())
                except Exception:
                    pass
            elif line.startswith("| ") and line.endswith(" |"):
                parts = [x.strip() for x in line.split("|")[1:-1]]
                if len(parts) == 4 and parts[1].isdigit():
                    try:
                        fam[parts[0]] = (int(parts[1]), float(parts[2]))
                    except Exception:
                        pass
    except Exception:
        return None
    if not fam or max(v[1] for v in fam.values()) < 100:
        return None  # 早期 bug 版报告(Priv 全 0), 不能当基线
    return {"path": path, "fam": fam, "commit": commit, "avail": avail}


def find_latest_baseline(rdir):
    import glob
    files = sorted(glob.glob(os.path.join(rdir, "hygiene-*.md")),
                   key=os.path.getmtime, reverse=True)
    for f in files:
        b = parse_prev_report(f)
        if b:
            return b
    return None


def mem_global():
    class M(ctypes.Structure):
        _fields_ = [("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    m = M(); m.dwLength = ctypes.sizeof(M)
    k32.GlobalMemoryStatusEx(ctypes.byref(m))
    perf = None
    try:
        out = subprocess.run(
            [PS_EXE, "-NoProfile", "-Command",
             "$p=Get-CimInstance Win32_PerfRawData_PerfOS_Memory; "
             "'{0},{1}' -f ($p.CommittedBytes/1MB),($p.CommitLimit/1MB)"],
            capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace", creationflags=nowin.no_window())
        commit, limit = (out.stdout or "").strip().split(",")
        perf = (float(commit), float(limit))
    except Exception:
        pass
    return {"load": m.dwMemoryLoad, "avail_mb": round(m.ullAvailPhys / 1048576),
            "total_mb": round(m.ullTotalPhys / 1048576), "commit": perf}


def hcs_state():
    try:
        p = subprocess.run(["hcsdiag", "list"], capture_output=True, text=True,
                           timeout=20, encoding="utf-8", errors="replace", creationflags=nowin.no_window())
    except Exception as e:
        return None, "hcsdiag failed: %s" % e
    raw = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    if "hcsdiag <command>" in raw:
        return None, raw
    states = []
    for line in raw.splitlines():
        if "VM," in line:
            parts = line.split(",")
            if len(parts) >= 2:
                states.append(parts[1].strip())
    return states, raw


def classify_cmd(cmd):
    """Electron 子进程类型: --type=renderer 等; 无 --type= 视为 main"""
    if not cmd:
        return ""
    i = cmd.find("--type=")
    if i < 0:
        return ""
    rest = cmd[i + 7:]
    return rest.split()[0].split('"')[0] if rest.split() else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample-sec", type=int, default=5)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--report", default=None)
    ap.add_argument("--no-report", action="store_true")
    a = ap.parse_args()

    if sys.platform != "win32":
        print("仅支持 Windows（ctypes/服务/hcsdiag 都是 Win 专有）。Mac 端待适配。")
        return 1

    L = []          # 报告行
    def out(s=""):
        print(s)
        L.append(s)

    out("# 进程刷新 · Process Refresh for Windows — 体检报告  %s"
        % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    out()
    out("## 0 环境")
    out("- admin=%s  python=%s" % (bool(shell32.IsUserAnAdmin()), sys.version.split()[0]))

    # ---- 1 内存压力 ----
    g = mem_global()
    out()
    out("## 1 内存压力")
    out("- 物理: 可用 %sMB / 共 %sMB, load %s%%" % (g["avail_mb"], g["total_mb"], g["load"]))
    if g["commit"]:
        out("- commit: %.0fMB / %.0fMB" % g["commit"])
    out("- 口径: 以下全部用 Private; WS 会被 trim, 不作数")

    # ---- 2 进程清单 ----
    procs = wmi_processes()
    if not procs:
        print("[fail] 拿不到进程清单")
        return 1
    pids = {p["ProcessId"] for p in procs}

    by_pid = {}
    for p in procs:
        priv = proc_priv_mb(p["ProcessId"])
        p["priv"] = priv if priv is not None else 0.0
        p["etype"] = classify_cmd(p["cmd"])
        p["created"], p["cpu0"] = proc_times(p["ProcessId"])
        by_pid[p["ProcessId"]] = p

    out()
    out("## 2 进程家族 Top（Private 汇总, 按 exe 分组, 标 Electron 子进程类型）")
    fam = {}
    for p in procs:
        if p["Name"].lower() in KERNEL_NAMES:
            continue
        key = os.path.basename(p["exe"]) if p["exe"] else p["Name"]
        fam.setdefault(key, {"n": 0, "priv": 0.0, "types": {}})
        fam[key]["n"] += 1
        fam[key]["priv"] += p["priv"]
        if p["etype"]:
            fam[key]["types"][p["etype"]] = fam[key]["types"].get(p["etype"], 0) + 1
    top = sorted(fam.items(), key=lambda kv: -kv[1]["priv"])[:a.top]
    out()
    out("| 进程 | 数 | PrivMB | 子进程类型 |")
    out("|---|---|---|---|")
    for name, d in top:
        t = ",".join("%s×%d" % kv for kv in sorted(d["types"].items())) or "-"
        out("| %s | %d | %.1f | %s |" % (name, d["n"], d["priv"], t))
    big_rend = [(p["ProcessId"], p["priv"], os.path.basename(p["exe"]))
                for p in procs if p["etype"] == "renderer" and p["priv"] > RENDERER_BIG_MB]
    if big_rend:
        out()
        out("**判定: 单个 renderer > %.0fMB 的存在（通常是某个标签页/某个会话吃内存, 不是泄漏）:**" % RENDERER_BIG_MB)
        for pid, mb, name in big_rend:
            out("- pid=%s %s %.1fMB" % (pid, name, mb))

    # ---- 3 孤儿 / 泄漏模式 ----
    # 判据（v2, 修正了 v1 的假阳性）:
    #   「父进程已退出」对顶层应用是常态(启动器/资源管理器退出很正常), 不是泄漏。
    #   真正可疑的是: Electron 子进程(renderer/gpu/utility/crashpad) 的宿主 main 已不在,
    #   或 helper 型 exe 住在别的产品的安装目录里却没了主。
    out()
    out("## 3 疑似泄漏 / 孤儿（只列, 不动）")
    services_pid = {p["ProcessId"] for p in procs
                    if os.path.basename(p["exe"]).lower() == "services.exe"}
    CHILD_TYPES = {"renderer", "gpu-process", "utility", "crashpad-handler"}
    mains_by_exe = {}
    for p in procs:
        if not p["etype"]:
            mains_by_exe.setdefault(p["exe"].lower(), []).append(p["ProcessId"])
    orphans, top_norm = [], 0
    for p in procs:
        ppid = p["ParentProcessId"]
        if ppid in pids or ppid in services_pid or ppid == 0:
            continue
        if p["Name"].lower() in KERNEL_NAMES:
            continue
        created, _ = p["created"], None
        age_h = (time.time() - created) / 3600.0 if created else None
        et = p["etype"]
        if et in CHILD_TYPES:
            if mains_by_exe.get(p["exe"].lower()):
                continue  # 宿主健在, 正常
            if p["priv"] >= ORPHAN_MIN_PRIV_MB:
                orphans.append((p["ProcessId"], p["Name"], p["priv"], age_h,
                                "Electron 子进程(%s)但宿主 main 已死" % et))
        else:
            top_norm += 1  # 顶层应用父进程退出 = 常态, 不列
    if orphans:
        out()
        out("| pid | 进程 | PrivMB | 存活h | 说明 |")
        out("|---|---|---|---|---|")
        for pid, name, priv, age, why in orphans:
            out("| %s | %s | %.1f | %s | %s |"
                % (pid, name, priv, ("%.1f" % age) if age is not None else "?", why))
    else:
        out("- 无孤儿候选（Electron/Helper 子进程但宿主 main 已死 且 ≥%.0fMB）" % ORPHAN_MIN_PRIV_MB)
        out("- 说明: 顶层应用「父进程已退出」是常态(启动器退出), 不算孤儿, 不列。")

    # ---- 3b 进程组聚类（会话堆积）----
    # 🔴 为什么需要: 「孤儿」判据只能查「父进程已死」。但本机最大的一笔内存占用
    #    (72 个 node.exe ≈ 8GB) 是**父进程 WorkBuddy 全都活着**的会话堆积——
    #    孤儿判据 100% 查不到, 逐个进程看也永远看不出来。
    #    唯一能看见的办法: 按**入口脚本**聚类, 看「同一个脚本起了多少套」。
    #    实测: rea.mjs / cli.cjs / mcp-server.mjs / npx-cli.js / start.mjs
    #    各 13~14 个 = 14 组「5 件套」, 24 小时内起了 14 轮。
    out()
    out("### 3b 进程组聚类（同一入口脚本起了多套 = 会话堆积）")
    out()
    out("- 🔴 这不是泄漏，是**会话组没被回收**：宿主进程都活着，孤儿判据查不到。")
    out("- 判据: 同一入口脚本 ≥%d 个实例, 且该组 Private 合计 ≥%.0fMB。" %
        (GROUP_MIN_INSTANCES, GROUP_MIN_PRIV_MB))
    groups = {}
    for p in procs:
        cmd = p.get("cmd") or ""
        # 🔴 必须排除「包装壳」: 实测同一组 MCP server 会同时出现
        #    cmd.exe /d /s /c "..." 包装层 + 真正的 node.exe 执行层。
        #    两层都带同一个脚本路径, 若按进程计数会**双倍虚高**
        #    (实测 mcp-server.mjs: cmd.exe 14 + node.exe 14 = 28, 真实是 14 组)。
        #    → 只认「自己就是解释器」的那一层: 进程名是 node/deno/bun/python 等。
        name = (p.get("Name") or "").lower()
        if name in ("cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "bash.exe",
                    "sh.exe", "wscript.exe", "cscript.exe"):
            continue
        m = re.search(r"[\\/]([^\s\\/]+\.(?:js|cjs|mjs))", cmd)
        if not m:
            continue
        script = m.group(1)
        # 🔴 同名脚本可能来自不同包（实测 mcp-server.mjs 同时存在于
        #    rea-agents 与 plugins/cache/workbuddy-builtin 两个来源）。
        #    只按文件名合并会把两个不同的组算成一组, 实例数虚高一倍。
        #    → 补上包路径做区分。
        pkg = ""
        pm = re.search(r"[\\/](node_modules[\\/]([^\s\\/]+))", cmd)
        if pm:
            pkg = pm.group(1)
        else:
            pm = re.search(r"[\\/]plugins[\\/]cache[\\/]([^\s\\/]+)", cmd)
            if pm:
                pkg = "cache\\" + pm.group(1)
        groups.setdefault(pkg + "\\" + script, []).append(p)
    hot = []
    for script, items in groups.items():
        if len(items) < GROUP_MIN_INSTANCES:
            continue
        tot = sum(p["priv"] for p in items)
        if tot < GROUP_MIN_PRIV_MB:
            continue
        hot.append((script, items, tot))
    hot.sort(key=lambda x: -x[2])
    if hot:
        out("| 入口脚本 | 实例数 | Priv合计MB | 平均MB | 最早启动 | 最晚启动 |")
        out("|---|---|---|---|---|---|")
        for script, items, tot in hot:
            ages = []
            for p in items:
                c = p.get("created")
                if c:
                    ages.append(c)
            e = time.strftime("%m-%d %H:%M", time.localtime(min(ages))) if ages else "?"
            l = time.strftime("%m-%d %H:%M", time.localtime(max(ages))) if ages else "?"
            # 只显示最后两段路径, 免得表格被长路径撑爆
            short = script.replace("/", "\\").split("\\")
            short = "\\".join(short[-2:]) if len(short) > 2 else script
            out("| %s | %d | %.1f | %.1f | %s | %s |"
                % (short, len(items), tot, tot / len(items), e, l))
        out()
        out("- **解读**: 每个「组」= 一个会话起的一整套进程。组数远大于你今天实际开过的会话数")
        out("  → 就是历史会话没回收。处置顺序: **先关掉宿主的对应会话/窗口**（宿主会带走整组）,")
        out("  再考虑直接 taskkill。**别逐个杀**——杀了还会被宿主再拉起。")
        out("- ⚠️ 本项**只报告不动手**：宿主可能正在用其中某几个。")
    else:
        out("- 无会话堆积候选（同一入口脚本 ≥%d 个且合计 ≥%.0fMB）"
            % (GROUP_MIN_INSTANCES, GROUP_MIN_PRIV_MB))

    # vmmem / HCS
    states, raw = hcs_state()
    vmmem = [p for p in procs if p["Name"].lower() == "vmmem"]
    vmwp = [p for p in procs if p["Name"].lower() == "vmwp.exe"]
    out()
    if vmmem:
        for p in vmmem:
            created, _ = p["created"], None
            age_h = (time.time() - created) / 3600.0 if created else None
            out("- vmmem pid=%s priv=%.1fMB age=%s hcs_states=%s vmwp=%d"
                % (p["ProcessId"], p["priv"], ("%.1f" % age_h) if age_h else "?", states, len(vmwp)))
            if not vmwp:
                out("  **判定: 无 vmwp = VM 无 worker, 疑似孤儿泄漏（本机已证实的 Codex 模式）**")
                out("  建议: `python codex_sandbox_cleanup.py`（与本脚本同目录, 先演练）")
    else:
        out("- 无 vmmem, 无 HCS VM 占用")
    if states:
        bad = [s for s in states if s != "SavedAsTemplate"]
        if bad:
            out("- **注意**: 存在非 SavedAsTemplate 的 compute system: %s（可能有活跃 VM）" % bad)

    # shim 重复计数
    out()
    shims = [p for p in procs if p["exe"].lower().endswith(("\\scripts\\python.exe", "\\scripts\\pythonw.exe"))]
    if shims:
        out("- shim 提示: %d 个 venv\\Scripts\\python.exe（~1MB 壳, 真实解释器在子进程）——"
            "按进程名统计内存会重复计数, 别被工具骗" % len(shims))

    # ---- 4 空转 vs 在干活 ----
    out()
    out("## 4 空转 vs 在干活（对 Private Top%d 采样 %ds CPU 增量）" % (a.top, a.sample_sec))
    cand = sorted([p for p in procs if p["Name"].lower() not in KERNEL_NAMES],
                  key=lambda p: -p["priv"])[:a.top]
    t0 = time.time()
    for p in cand:
        _, c = proc_times(p["ProcessId"])
        p["cpu0"] = c
    time.sleep(a.sample_sec)
    dt = time.time() - t0
    out()
    out("| pid | 进程 | PrivMB | CPU%% | 判定 |")
    out("|---|---|---|---|---|")
    for p in cand:
        _, c1 = proc_times(p["ProcessId"])
        cpu_pct = 0.0
        if p["cpu0"] is not None and c1 is not None:
            cpu_pct = (c1 - p["cpu0"]) / dt * 100.0
        verdict = ("在干活(CPU %.0f%%)" % cpu_pct) if cpu_pct >= 1.0 else \
                  ("空闲/阻塞等待(CPU %.1f%%)" % cpu_pct)
        out("| %s | %s | %.1f | %.1f | %s |" % (p["ProcessId"], p["Name"], p["priv"], cpu_pct, verdict))
    out()
    out("> 判读纪律: CPU 持续 >1% = 在干活, 别杀; CPU≈0 且内存大 = 等待/缓存, 回收收益看 Private;")
    out("> 上一轮实测: opencode 954MB/CPU530s 是在跑任务, 不是泄漏 —— 这就是为什么本工具只读不杀。")

    # ---- 4b 线程 / 句柄维度（独立于 Private 排序）----
    # 🔴 为什么必须单列一维: 上一版只按 Private 排序, 结果漏掉了 Weixin 主进程
    #    的句柄泄漏(Private 仅 567MB 排不进 Top15, 句柄却 177790)。
    #    句柄吃的是内核对象表, 不是用户态内存 —— **只看 Private 的工具永远看不见它**。
    out()
    out("## 4b 线程 / 句柄维度（与 Private 并列的独立维度）")
    try:
        import thread_handle_probe as thp
        probe = thp.probe_all()
        if not probe:
            out("- [warn] 线程/句柄探测失败（不影响本次其余结论）")
        else:
            tt, th = thp.top_tables(probe, 8)
            out("- 采样进程数: %d（一次 Get-Process 调用取全表, 实测 ~360ms）" % len(probe))
            out()
            out("| 排名 | 线程数 Top | 进程 | 句柄数 | Suspended | PrivMB |")
            out("|---|---|---|---|---|---|")
            for i, (pid, d) in enumerate(tt, 1):
                out("| T%d | %d | %s | %d | %d | %.1f |"
                    % (i, d["threads"], d["name"], d["handles"], d["suspended"], d["priv_mb"]))
            out()
            out("| 排名 | 句柄数 Top | 进程 | 线程数 | Suspended | PrivMB |")
            out("|---|---|---|---|---|---|")
            for i, (pid, d) in enumerate(th, 1):
                out("| H%d | %d | %s | %d | %d | %.1f |"
                    % (i, d["handles"], d["name"], d["threads"], d["suspended"], d["priv_mb"]))
            findings = thp.analyze(probe)
            out()
            if findings:
                out("**判定: %d 个异常候选（判据 = 绝对阈值 + 相对参照系的倍数）**" % len(findings))
                out()
                out("| 类型 | pid | 进程 | 线程 | 句柄 | Suspended占比 | 参照值 | 参照系 | 倍数 | CPU增量 | 存活h | 结论 |")
                out("|---|---|---|---|---|---|---|---|---|---|---|---|")
                for f in findings:
                    base_v = (f["peer_median_threads"] if f["kind"] == "thread"
                              else f["peer_median_handles"])
                    basis = f.get("basis", "同exe中位数")
                    # 🔴 必须交叉验证 CPU: 句柄/线程高 ≠ 该杀。
                    #    实测 Weixin 主进程 177790 句柄 CPU 3.7%(在干活), WorkBuddy 宿主
                    #    51500 句柄 CPU 2.7%(在干活) —— 两个都不能杀。
                    pid = int(f["pid"])
                    # 🔴 CPU 采样窗必须够长: 3 秒窗口实测不稳（同一进程两次测出
                    #    3.7% 和 0.0%）, 因为 TotalProcessorTime 增量在低负载下
                    #    落在计时器分辨率边缘。统一用 a.sample_sec（默认 5s）取两次。
                    cpu_win = max(2, a.sample_sec)
                    _, c0 = proc_times(pid)
                    time.sleep(cpu_win)
                    _, c1 = proc_times(pid)
                    cpu_pct = 0.0
                    if c0 is not None and c1 is not None:
                        cpu_pct = (c1 - c0) / float(cpu_win) * 100.0
                    created = proc_times(pid)[0]
                    age_h = (time.time() - created) / 3600.0 if created else None
                    if cpu_pct >= 1.0:
                        verdict = "在干活 → **不要杀**"
                    elif age_h is not None and age_h >= 24:
                        verdict = "空闲且长期累积 → 疑似泄漏, 需人工确认"
                    else:
                        verdict = "空闲但刚启动 → 观察"
                    out("| %s | %s | %s | %d | %d | %.1f%% | %.0f | %s | %.1fx | %.1f%% | %s | %s |"
                        % (f["kind"], f["pid"], f["name"], f["threads"], f["handles"],
                           f["suspended_ratio"] * 100, base_v, basis, f["burst_ratio"],
                           cpu_pct, ("%.1f" % age_h) if age_h is not None else "?",
                           verdict))
                out()
                out("> 判读: **句柄/线程高 ≠ 该杀**。必须同时看 CPU 增量与存活时长——")
                out("> 实测 WorkBuddy 宿主 6.1 万句柄但 CPU 增量 1.2%（在干活）→ **不能杀**；")
                out("> `wetype_renderer` 2.2 万句柄、CPU 0%、存活 193 小时 → 才是「累积未释放」的嫌疑信号。")
                out("> 判据必须三合一：**句柄/线程异常 + CPU≈0 + 存活时间长** → 才值得动。")
                out("> （SysWatch 这类工具只按固定阈值报「句柄泄漏」，会连 System(8582)/msedge(9158) 一起误报——")
                out(">  本工具用「绝对阈值 + 相对参照系倍数」两道判据来消掉这类误报。）")
            else:
                out("- 无异常候选（线程 ≥%d 或 句柄 ≥%d，且相对参照系 ≥%.0fx）"
                    % (thp.MIN_THREADS_ABS, thp.MIN_HANDLES_ABS, thp.BURST_RATIO))

            # ---- 4c 句柄类型分解（把「句柄多」变成可行动的根因）----
            # 🔴 为什么需要: 光知道「178029 个句柄」不是可行动结论。同样 10 万句柄,
            #    Event/Token/Process/Key 的归属与处置完全不同。分解到类型层才知道该找谁。
            #    只对句柄异常候选跑(枚举 18 万句柄要几秒), 不对全表跑。
            handle_cands = [f for f in findings if f["kind"] == "handle"]
            if handle_cands:
                try:
                    import handle_type_breakdown as htb
                    htb_exe = htb.find_handle_exe()
                    if not htb_exe:
                        out()
                        out("### 4c 句柄类型分解")
                        out()
                        out("- [skip] 未安装 Sysinternals Handle，跳过类型分解。")
                        out("  获取: https://download.sysinternals.com/files/Handle.zip → "
                            "解压到 %s\\_vendor\\Handle\\handle64.exe"
                            % os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                        out("  手动查看: python tools/handle_type_breakdown.py <pid>")
                    else:
                        out()
                        out("### 4c 句柄类型分解（把「句柄多」变成可行动的根因）")
                        out()
                        out("- 工具: Sysinternals Handle `-p <pid> -a`")
                        out("- 🔴 必须加 `-a`: 默认只列**有名字**的句柄。实测 Weixin 主进程")
                        out("  19 万个句柄，默认输出仅 **489 行**（全部有名字，最大句柄值 0xBBBF0）——")
                        out("  拿默认输出下结论会得出完全相反的判断。")
                        for f in handle_cands[:3]:
                            pid = int(f["pid"])
                            out()
                            out("#### pid=%d (%s) 句柄=%d" % (pid, f["name"], f["handles"]))
                            try:
                                truth_before = htb.process_handle_count(htb.ps_exe(), pid)
                                _, hlines = htb.list_handles(htb_exe, pid)
                                truth_after = htb.process_handle_count(htb.ps_exe(), pid)
                                htypes, hprocs = htb.parse_types(hlines)
                                ck, _ = htb.cross_check(truth_before, len(hlines), truth_after)
                                out("- Handle -a 列出 %d 个；Get-Process 枚举前 %s / 枚举后 %s -> %s"
                                    % (len(hlines),
                                       truth_before if truth_before is not None else "?",
                                       truth_after if truth_after is not None else "?",
                                       ck))
                                out()
                                out("| 句柄类型 | 数量 | 占比 |")
                                out("|---|---|---|")
                                tot = len(hlines) or 1
                                for t, c in sorted(htypes.items(), key=lambda kv: -kv[1])[:8]:
                                    out("| %s | %d | %.2f%% |" % (t, c, c * 100.0 / tot))
                                n_proc = htypes.get("Process", 0)
                                gone = hprocs.get("gone_total", 0)
                                if gone:
                                    out()
                                    out("- 🔴 指向**已退出进程**的僵尸句柄 **%d 个**" % gone)
                                    out("  · 占全部句柄 %.2f%%（分母 %d）"
                                        % (gone * 100.0 / tot, tot))
                                    out("  · 占 Process 类句柄 %.2f%%（分母 %d）"
                                        % (gone * 100.0 / n_proc if n_proc else 0, n_proc))
                                    refs = sorted(hprocs.get("gone_refs", {}).items(),
                                                  key=lambda kv: -kv[1])[:5]
                                    out("  已退出目标 pid: " + ", ".join(
                                        "%s(%d)" % (k, v) for k, v in refs))
                                    out("  → 这些进程**确已退出**，句柄仍被持有且从未 CloseHandle")
                                live = hprocs.get("live_total", 0)
                                if live:
                                    out()
                                    out("- ⚪ 指向**存活进程**的 Process 句柄 **%d 个**（非泄漏存量）" % live)
                                    refs = sorted(hprocs.get("live_refs", {}).items(),
                                                  key=lambda kv: -kv[1])[:5]
                                    names = hprocs.get("live_names", {})
                                    out("  存活目标 pid: " + ", ".join(
                                        "%s(%d, %s)" % (k, v, names.get(k, "?"))
                                        for k, v in refs))
                                    out("  → 目标**还活着**。新增的这类句柄 = 增长源在此，")
                                    out("    别默认归给已退出的僵尸。")
                            except Exception as e:
                                out("- [warn] 分解失败: %s" % e)
                except Exception as e:
                    out()
                    out("### 4c 句柄类型分解")
                    out()
                    out("- [warn] %s" % e)
    except Exception as e:
        out("- [warn] 线程/句柄维度异常: %s" % e)

    # ---- 5 与上次对比 ----
    out()
    base = find_latest_baseline(a.report or DEFAULT_REPORT_DIR) if not a.no_report else None
    if not base:
        out("## 5 对比（无有效历史报告, 本次为首个基线）")
    else:
        out("## 5 与上次对比（基线: %s, %s）"
            % (os.path.basename(base["path"]),
               datetime.datetime.fromtimestamp(os.path.getmtime(base["path"])).strftime("%m-%d %H:%M")))
        prev = base["fam"]
        rows = []
        for n in set(prev) | set(fam):
            pn, pp = prev.get(n, (0, 0.0))
            fam_v = fam.get(n)
            cn, cp = (fam_v["n"], fam_v["priv"]) if fam_v else (0, 0.0)
            d = cp - pp
            if abs(d) >= 50 or (pp == 0 and cp >= 200) or (cp == 0 and pp >= 200):
                rows.append((n, pn, pp, cn, cp, d))
        rows.sort(key=lambda r: -abs(r[5]))
        if rows:
            out()
            out("| 进程 | 上次(数/MB) | 本次(数/MB) | ΔMB | 判定 |")
            out("|---|---|---|---|---|")
            for n, pn, pp, cn, cp, d in rows:
                if pp == 0 and cp >= 200:
                    v = "新增大户"
                elif cp == 0 and pp >= 200:
                    v = "已退出"
                elif d >= 300 and (pp == 0 or cp >= pp * 1.5):
                    v = "**显著增长, 疑似新泄漏, 值得追**"
                elif d >= 300:
                    v = "增长(可能是在干活/开了更多会话)"
                elif d <= -300:
                    v = "明显回落"
                else:
                    v = "波动"
                out("| %s | %d/%.0f | %d/%.0f | %+d | %s |" % (n, pn, pp, cn, cp, d, v))
        else:
            out("- 各家族 Private 变化均在 ±50MB 内, 无显著漂移")
        if base["commit"] and g["commit"]:
            out("- commit: %.0fMB -> %.0fMB (%+.0f)" % (base["commit"], g["commit"][0],
                                                        g["commit"][0] - base["commit"]))
        if base["avail"]:
            out("- 可用: %.0fMB -> %dMB (%+d)  注: 差额会被其他进程涨落吃掉, 只看趋势"
                % (base["avail"], g["avail_mb"], g["avail_mb"] - base["avail"]))

    # ---- 报告 ----
    if not a.no_report:
        rdir = a.report or DEFAULT_REPORT_DIR
        os.makedirs(rdir, exist_ok=True)
        path = os.path.join(rdir, "hygiene-%s.md" % datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(L) + "\n")
        print("\n[report] %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
