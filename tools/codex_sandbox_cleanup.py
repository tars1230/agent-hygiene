#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
codex_sandbox_cleanup.py  (v3)
回收 Codex 沙箱遗留的 Hyper-V 虚拟机（vmmem）内存。

背景（实测）
  Codex 通过 HCS 起一个 utility VM 做 Windows 沙箱。退出 Codex 后该 VM 不回收:
  实测一个 SavedAsTemplate 状态的 compute system + vmmem 872.8MB 存活 25 小时,
  vmmem 父进程已退出、全机无 vmwp.exe -> 孤儿泄漏。
  守护它的是 Windows 服务 CodexSandboxService.OpenAI.Codex
  (DisplayName=ChatGPT, AUTO_START, LocalSystem, WIN32_PACKAGED_PROCESS)。

回收策略(按「连坐面」从小到大, 前一档成功就不进下一档)
  档 1  停守护服务 CodexSandboxService -> 等 vmmem 消失 -> 立刻起回服务
        只影响 Codex 自己。**必须起回**: 服务是 AUTO_START, 但本会话内若停了,
        Codex 以普通用户身份起不了它, 沙箱会直接不可用。
  档 2  兜底: Stop-Service vmcompute -> 等 vmmem 消失 -> Start-Service vmcompute
        会拆掉全部 compute system, 所以档 1 之外还有守卫 2/4 挡着。
  不使用 Stop-Process vmmem(杀宿主, 留脏 compute 状态)。
  不使用 computecore.dll 的 HcsTerminateComputeSystem:
    本机 computecore.dll (10.0.19041.5794) 的 ABI 与 hcsdiag/hcsshim 的三参形态不符,
    按文档签名用 ctypes 调用实测触发 STATUS_HEAP_CORRUPTION (0xC0000374),
    已连错三次, 按纪律停止猜 ABI。有 VM 时再考虑「HcsCreateOperation -> Terminate ->
    WaitForOperationResult」的正确序列, 没有实测样本前不写进生产脚本。

守卫 (任一不满足就跳过; 跳过不算失败, 返回 0, 免得计划任务天天标红)
  1. 没有 Codex App 在跑。判据 = 进程名 ∈ CODEX_APP_NAMES, 或可执行路径含 'OpenAI.Codex',
     但排除包内常驻服务(否则服务自身会被当成 App -> 守卫永远触发 -> 脚本形同失效, 实测踩过)。
  2. 没有其他 HCS 使用者: Docker / WSL / Windows Sandbox / vmmemWSL。
  3. 存在 vmmem, 且其存活时长 >= --min-age-hours (默认 2h), 防拆掉刚起的沙箱。
  4. hcsdiag list 的内容判据: compute system 数量 <= 1 且状态全为 SavedAsTemplate。
     这是比进程名更硬的判据(进程名黑名单永远列不全)。
     hcsdiag 取不到时只记 WARN 不阻断 —— 否则工具一变, 清理就永久静默失效。

退出码
  0 = 正常(含「无需处理」与「被守卫跳过」)
  1 = 执行失败(权限不足 / 服务操作出错 / 该消失却没消失)

用法
    python codex_sandbox_cleanup.py                       # 演练
    python codex_sandbox_cleanup.py --apply               # 实际执行
    python codex_sandbox_cleanup.py --apply --min-age-hours 6
    python codex_sandbox_cleanup.py --apply --skip-service-tier   # 只走 vmcompute 兜底
    python codex_sandbox_cleanup.py --apply --no-log
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

# ---------------- 判据表 ----------------
CODEX_APP_NAMES = {
    "codex.exe",
    "chatgpt.exe",
    "codex-code-mode-host.exe",
    "codex-command-runner.exe",
}
# 路径判据命中即算 Codex(防 exe 改名); 用子串不钉版本号
CODEX_PATH_MARK = "openai.codex"
# 包内常驻服务/安装器: 它们一直在跑, 不代表 App 在忙
CODEX_SERVICE_EXES = {
    "codex-windows-sandbox-service.exe",
    "codex-windows-sandbox-setup.exe",
    "elevated_tracing_service.exe",
    "elevation_service.exe",
}
# 其他 HCS 使用者: 与 Codex 共用 vmcompute, 停服务会连坐
OTHER_HCS_NAMES = {
    "docker.exe", "dockerd.exe", "com.docker.backend.exe", "com.docker.build.exe",
    "docker-desktop.exe", "vpnkit.exe",
    "wsl.exe", "wslhost.exe", "wslservice.exe", "wslg.exe", "vmmemwsl",
    "windowssandbox.exe", "windowssandboxclient.exe",
    "windowssandboxserver.exe", "windowssandboxremotesession.exe",
}

CODEX_SERVICE = "CodexSandboxService.OpenAI.Codex"
DEFAULT_LOG = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "agent-hygiene", "logs", "codex_cleanup.log")
SAFE_STATE = "SavedAsTemplate"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

_log_fp = None


def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    if _log_fp:
        try:
            _log_fp.write(line + "\n")
            _log_fp.flush()
        except Exception:
            pass


# ---------------- 内存快照 ----------------
class MEMSTATUS(ctypes.Structure):
    _fields_ = [
        ("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def mem_snapshot():
    m = MEMSTATUS()
    m.dwLength = ctypes.sizeof(MEMSTATUS)
    k32.GlobalMemoryStatusEx(ctypes.byref(m))
    return {"avail_mb": int(round(m.ullAvailPhys / 1048576)),
            "load_pct": m.dwMemoryLoad,
            "total_mb": int(round(m.ullTotalPhys / 1048576))}


# ---------------- 进程枚举 (Toolhelp32, 不走 WMI) ----------------
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def list_processes():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap == 0xFFFFFFFF:
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.szExeFile, pe.th32ParentProcessID))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


def exe_path(pid):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        k32.QueryFullProcessImageNameW.argtypes = [
            wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(1024)
        return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else ""
    finally:
        k32.CloseHandle(h)


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


def proc_times(pid):
    """返回 (creation_epoch, cpu_seconds) ; 失败返回 (None, None)"""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None, None
    try:
        c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                   ctypes.byref(k), ctypes.byref(u)):
            return None, None
        ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
        # FILETIME 是 1601-01-01 起的 100ns
        epoch = ft / 1e7 - 11644473600.0
        cpu = (((k.dwHighDateTime << 32) | k.dwLowDateTime) +
               ((u.dwHighDateTime << 32) | u.dwLowDateTime)) / 1e7
        return epoch, cpu
    finally:
        k32.CloseHandle(h)


def find_codex_procs():
    hit = []
    for pid, name, ppid in list_processes():
        if pid == 0:
            continue
        low = name.lower()
        if low in CODEX_SERVICE_EXES:
            continue
        if low in CODEX_APP_NAMES:
            hit.append((pid, name, "by-name"))
            continue
        if "codex" in low or "chatgpt" in low:
            p = exe_path(pid)
            if CODEX_PATH_MARK in p.lower():
                hit.append((pid, name, "by-path:" + p))
    return hit


def find_other_hcs():
    return [(pid, name) for pid, name, ppid in list_processes()
            if name.lower() in OTHER_HCS_NAMES]


def find_vmmem():
    return [(pid, ppid) for pid, name, ppid in list_processes() if name.lower() == "vmmem"]


class PMC(ctypes.Structure):
    """PROCESS_MEMORY_COUNTERS_EX。cb 必须先赋 sizeof, 否则 GetProcessMemoryInfo 静默失败"""
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t)]


def vmmem_private_mb(pid):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
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


# ---------------- hcsdiag ----------------
def hcs_info():
    """返回 (count, states, raw); hcsdiag 不可用时 count=None"""
    try:
        p = subprocess.run(["hcsdiag", "list"], capture_output=True, text=True,
                           timeout=20, encoding="utf-8", errors="replace", creationflags=nowin.no_window())
    except Exception as e:
        return None, [], "hcsdiag invoke failed: %s" % e
    raw = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    if "hcsdiag <command>" in raw:  # 只吐了 usage
        return None, [], raw
    states = []
    for line in raw.splitlines():
        if "VM," in line:
            parts = line.split(",")
            if len(parts) >= 2:
                states.append(parts[1].strip())
    return len(states), states, raw


# ---------------- 服务操作 ----------------
# 绝对路径: 受控环境(IDE 托管的 bash)PATH 可能不含 powershell, 裸名字会 WinError 2
PS_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                      "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _ps(cmd, timeout=90):
    p = subprocess.run(
        [PS_EXE, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
         "-Command", cmd],
        capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace", creationflags=nowin.no_window(),
    )
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def service_state(name):
    rc, out, err = _ps("(Get-Service -Name '%s' -ErrorAction SilentlyContinue).Status" % name)
    return out if rc == 0 and out else None


def stop_service(name, force=True):
    return _ps("Stop-Service -Name '%s'%s -ErrorAction Stop"
               % (name, " -Force" if force else ""))


def start_service(name):
    return _ps("Start-Service -Name '%s' -ErrorAction Stop" % name)


def wait_vmmem_gone(seconds):
    for _ in range(max(1, seconds)):
        if not find_vmmem():
            return True
        time.sleep(1)
    return False


# ---------------- 主流程 ----------------
def main():
    global _log_fp
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际执行 (默认仅演练)")
    ap.add_argument("--stop-service", action="store_true",
                    help="清理后不重启 Codex 沙箱服务 (省 2.1MB, 但本会话内 Codex 沙箱会不可用)")
    ap.add_argument("--skip-service-tier", action="store_true",
                    help="跳过档 1, 直接走 vmcompute 兜底 (仅用于验证兜底路径)")
    ap.add_argument("--min-age-hours", type=float, default=2.0,
                    help="vmmem 至少存活多少小时才动 (默认 2)")
    ap.add_argument("--wait", type=int, default=20, help="等 vmmem 释放的秒数上限")
    ap.add_argument("--no-log", action="store_true")
    ap.add_argument("--log", default=DEFAULT_LOG)
    args = ap.parse_args()

    if not args.no_log:
        try:
            os.makedirs(os.path.dirname(args.log), exist_ok=True)
            _log_fp = open(args.log, "a", encoding="utf-8")
        except Exception as e:
            print("[warn] cannot open log %s: %s" % (args.log, e))

    admin = bool(shell32.IsUserAnAdmin())
    log("==== run start  admin=%s mode=%s min_age=%sh ===="
        % (admin, "APPLY" if args.apply else "DRY-RUN", args.min_age_hours))
    before = mem_snapshot()
    log("before avail=%sMB load=%s%% total=%sMB"
        % (before["avail_mb"], before["load_pct"], before["total_mb"]))

    # ---- 守卫 1: Codex App ----
    apps = find_codex_procs()
    if apps:
        log("guard1 SKIP: codex app running -> %s" % apps)
        log("==== run end  skipped(codex busy) ====")
        return 0
    log("guard1 ok: no codex app process")

    # ---- 守卫 2: 其他 HCS 使用者 ----
    others = find_other_hcs()
    if others:
        log("guard2 SKIP: other HCS users -> %s" % others)
        log("==== run end  skipped(hcs busy) ====")
        return 0
    log("guard2 ok: no docker/wsl/sandbox process")

    # ---- 守卫 3: vmmem 存在 + 年龄 ----
    vm = find_vmmem()
    if not vm:
        log("guard3 ok: no vmmem -> nothing to reclaim")
        log("==== run end  nothing to do ====")
        return 0
    pid, ppid = vm[0]
    created, cpu = proc_times(pid)
    age_h = (time.time() - created) / 3600.0 if created else None
    log("target vmmem pid=%s parent=%s priv=%sMB age=%s cpu=%s"
        % (pid, ppid, vmmem_private_mb(pid),
           ("%.2fh" % age_h) if age_h is not None else "?", cpu))
    if age_h is not None and age_h < args.min_age_hours:
        log("guard3 SKIP: vmmem age %.2fh < %.2fh (可能正在初始化)" % (age_h, args.min_age_hours))
        log("==== run end  skipped(too young) ====")
        return 0

    # ---- 守卫 4: hcsdiag 内容 ----
    count, states, raw = hcs_info()
    if count is None:
        log("guard4 WARN: hcsdiag unusable -> %s" % raw.replace("\n", " | ")[:200])
    else:
        log("guard4 hcs count=%s states=%s" % (count, states))
        if count > 1:
            log("guard4 SKIP: more than one compute system")
            log("==== run end  skipped(multi-hcs) ====")
            return 0
        bad = [s for s in states if s != SAFE_STATE]
        if bad:
            log("guard4 SKIP: non-%s state -> %s" % (SAFE_STATE, bad))
            log("==== run end  skipped(hcs busy state) ====")
            return 0

    if not args.apply:
        tier = "service-then-vmcompute" if not args.skip_service_tier else "vmcompute"
        log("dry-run: would reclaim via %s" % tier)
        log("==== run end  dry-run ====")
        return 0

    if not admin:
        log("FAIL: need admin")
        return 1

    gone = False
    used = None

    # ---- 档 1: 停守护服务 ----
    if not args.skip_service_tier:
        st = service_state(CODEX_SERVICE)
        log("tier1: %s = %s" % (CODEX_SERVICE, st))
        if st == "Running":
            rc, out, err = stop_service(CODEX_SERVICE)
            if rc != 0:
                log("tier1 WARN stop failed rc=%s err=%s" % (rc, err))
            else:
                gone = wait_vmmem_gone(args.wait)
                log("tier1: vmmem gone=%s" % gone)
                if gone:
                    used = "service"
            # 无论如何都要起回: 本会话内 Codex 以普通用户身份起不了 AUTO_START 服务
            if args.stop_service:
                log("tier1: leaving %s stopped (per --stop-service)" % CODEX_SERVICE)
            else:
                rc, out, err = start_service(CODEX_SERVICE)
                log("tier1: restart %s rc=%s -> %s %s"
                    % (CODEX_SERVICE, rc, service_state(CODEX_SERVICE), err))
        else:
            log("tier1: service not Running, skip to tier2")

    # ---- 档 2: vmcompute 兜底 ----
    if not gone:
        log("tier2: Stop-Service vmcompute")
        rc, out, err = _ps("Stop-Service vmcompute -Force -ErrorAction Stop")
        if rc != 0:
            log("FAIL tier2 stop rc=%s err=%s" % (rc, err))
            return 1
        gone = wait_vmmem_gone(args.wait)
        used = "vmcompute" if gone else None
        log("tier2: vmmem gone=%s" % gone)
        rc, out, err = _ps("Start-Service vmcompute -ErrorAction Stop")
        if rc != 0:
            log("WARN tier2 restart rc=%s err=%s (Manual, 下次按需自启)" % (rc, err))
        else:
            log("tier2: vmcompute = %s" % service_state("vmcompute"))

    time.sleep(2)
    after = mem_snapshot()
    log("after avail=%sMB load=%s%% (delta avail=%+dMB)"
        % (after["avail_mb"], after["load_pct"], after["avail_mb"] - before["avail_mb"]))
    log("note: delta 受同期其他进程涨落影响, 不是回收量的干净度量; 回收量看上面 vmmem priv")
    log("==== run end  done via=%s gone=%s ====" % (used, gone))
    return 0 if gone else 1


if __name__ == "__main__":
    sys.exit(main())
