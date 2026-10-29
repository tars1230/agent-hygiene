"""验证 EmptyWorkingSet / SetProcessWorkingSetSize 到底降什么：WS 还是 Private。

结论用于「内存优化方案集」第 C 条，避免空谈。
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

PSAPI = ctypes.WinDLL("psapi.dll")
KERNEL32 = ctypes.WinDLL("kernel32.dll")

# 🔴 绝对路径: 某些受控环境(IDE 托管的 bash / 计划任务上下文)PATH 里
#    没有 System32\WindowsPowerShell, 裸 "powershell" 会 WinError 2。
#    这是本项目踩过两次的同一类兼容性 bug。
PS_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

# 🔴 PowerShell 输出在本机默认是 GBK(936): 用 text=True(默认 utf-8) 解码会抛
#    UnicodeDecodeError, 而且是在 subprocess 的 reader 线程里抛 -> 静默丢输出。
#    encoding= 与 text=True 互斥, 不能同时传。
PS_ENC = {"encoding": "utf-8", "errors": "replace"}


def _decode(raw):
    """自适应解码 PowerShell stdout 字节(utf-8 -> gbk -> 兜底)。"""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
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


def counters(h):
    c = PROCESS_MEMORY_COUNTERS_EX()
    c.cb = ctypes.sizeof(c)
    PSAPI.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
    mb = lambda v: round(v / 1048576, 1)
    return {
        "WS": mb(c.WorkingSetSize),
        "Private": mb(c.PrivateUsage),
        "Pagefile": mb(c.PagefileUsage),
    }


def trim(h):
    KERNEL32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))


def main():
    # 起一个子进程，分配 ~300MB 并触碰每一页（保证真的在物理内存里）
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import time\n"
         "b = bytearray(300 * 1024 * 1024)\n"
         "for i in range(0, len(b), 4096):\n"
         "    b[i] = 1\n"
         "print('allocated', flush=True)\n"
         "time.sleep(120)\n"],
        stdout=subprocess.PIPE, text=True,
    )
    child.stdout.readline()
    time.sleep(1.0)

    # 注意：venv 的 python.exe 是 uv 的 shim，真正吃内存的是它的子进程。
    # 必须挑「子树里 Private 最大的那个」来测，否则测到的是 1MB 的壳。
    def pick_heavy(pid):
        ps = subprocess.run(
            [PS_EXE, "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | "
             "Select-Object ProcessId,ParentProcessId,WorkingSetSize | ConvertTo-Json -Compress"],
            capture_output=True, timeout=30, **PS_ENC,
        )
        import json
        raw = _decode(ps.stdout)
        rows = json.loads(raw or "[]")
        if isinstance(rows, dict):
            rows = [rows]
        kids = [r for r in rows if r.get("ParentProcessId") == pid]
        if not kids:
            return pid
        kids.sort(key=lambda r: r.get("WorkingSetSize") or 0, reverse=True)
        return kids[0]["ProcessId"]

    target_pid = pick_heavy(child.pid)
    print(f"目标进程 PID={target_pid}（子进程壳 PID={child.pid}）")

    ACCESS = 0x0400 | 0x0100  # QUERY_INFORMATION | SET_QUOTA
    h = KERNEL32.OpenProcess(ACCESS, False, target_pid)
    if not h:
        print("OpenProcess 失败:", ctypes.GetLastError())
        child.kill()
        return

    before = counters(h)
    trim(h)
    time.sleep(2.5)  # 给系统时间把页踢出去
    after = counters(h)

    print(f"trim 前  WS={before['WS']:>8} MB  Private={before['Private']:>8} MB  Pagefile={before['Pagefile']:>8} MB")
    print(f"trim 后  WS={after['WS']:>8} MB  Private={after['Private']:>8} MB  Pagefile={after['Pagefile']:>8} MB")
    print(f"差值     WS={round(before['WS'] - after['WS'], 1):>8} MB  "
          f"Private={round(before['Private'] - after['Private'], 1):>8} MB  "
          f"Pagefile={round(before['Pagefile'] - after['Pagefile'], 1):>8} MB")

    # 在子进程里再读一次自己，确认它自己看到的 Private 是否变化
    child.kill()
    child.wait()
    print("子进程已结束")


if __name__ == "__main__":
    main()
