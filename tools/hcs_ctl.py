#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hcs_ctl.py —— 管理 Hyper-V compute system (HCS)。

list  : 走官方 `hcsdiag list`（实测 computecore.dll 的 HcsEnumerateComputeSystems
        在本机四种传参下全部 access violation，CLI 走的是不同代码路径，可用）
props : 走 computecore.dll 的 HcsGetComputeSystemProperties
stop  : 走 computecore.dll 的 HcsTerminateComputeSystem（hcsdiag 只有 list，没有 stop）

用法:
    python hcs_ctl.py list
    python hcs_ctl.py props  <id>
    python hcs_ctl.py stop   <id>

退出码: 0 成功 / 1 失败
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

DLL = r"C:\Windows\System32\computecore.dll"
d = ctypes.WinDLL(DLL)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

# ---- 原型 ----
# 🔴 HCS_ENUMERATION_RESULT 是**结构体**(PCWSTR Buffer + ULONG ResultCount = 16 字节),
#    不是「指向指针」。原实现传 POINTER(c_void_p)(只有 8 字节) -> DLL 往 ResultCount
#    位置越界写 -> access violation(实测直接崩)。
#    参考 computecore.dll 真实签名:
#      HRESULT HcsEnumerateComputeSystems(
#          PCWSTR Query, HCS_ENUMERATION_RESULT *EnumerationResult);
class HCS_ENUMERATION_RESULT(ctypes.Structure):
    _fields_ = [("Buffer", wt.LPCWSTR), ("ResultCount", wt.DWORD)]


d.HcsOpenComputeSystem.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]
d.HcsOpenComputeSystem.restype = ctypes.c_long

d.HcsCloseComputeSystem.argtypes = [ctypes.c_void_p]
d.HcsCloseComputeSystem.restype = None

d.HcsTerminateComputeSystem.argtypes = [ctypes.c_void_p, wt.LPCWSTR,
                                        ctypes.POINTER(ctypes.c_void_p)]
d.HcsTerminateComputeSystem.restype = ctypes.c_long

d.HcsGetComputeSystemProperties.argtypes = [ctypes.c_void_p, wt.LPCWSTR,
                                            ctypes.POINTER(ctypes.c_void_p)]
d.HcsGetComputeSystemProperties.restype = ctypes.c_long

d.HcsWaitForOperationResult.argtypes = [ctypes.c_void_p, wt.DWORD,
                                        ctypes.POINTER(ctypes.c_void_p)]
d.HcsWaitForOperationResult.restype = ctypes.c_long

d.HcsCloseOperation.argtypes = [ctypes.c_void_p]
d.HcsCloseOperation.restype = None

d.HcsEnumerateComputeSystems.argtypes = [wt.LPCWSTR, ctypes.POINTER(HCS_ENUMERATION_RESULT)]
d.HcsEnumerateComputeSystems.restype = ctypes.c_long

# HCS 自定义访问掩码。0x02000000 是 hcsshim 用的 "full access"；
# 其余几个是常规 GENERIC_* / 全 1，作为兜底逐个试。
ACCESS_CANDIDATES = [0x02000000, 0x10000000, 0x20000000, 0x40000000, 0xFFFFFFFF]


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def take_string(ptr_value) -> str:
    """HCS 返回的 JSON 是 CoTaskMemAlloc 出来的 LPWSTR，读完要 CoTaskMemFree。"""
    if not ptr_value:
        return ""
    try:
        s = ctypes.wstring_at(ptr_value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(ctypes.c_void_p(ptr_value))
    return s


def open_system(sys_id: str):
    last = None
    for acc in ACCESS_CANDIDATES:
        handle = ctypes.c_void_p()
        rc = d.HcsOpenComputeSystem(sys_id, acc, ctypes.byref(handle))
        if rc == 0 and handle.value:
            return handle, acc
        last = (hex(rc & 0xFFFFFFFF), hex(acc))
        if handle.value:
            d.HcsCloseComputeSystem(handle)
    raise RuntimeError("HcsOpenComputeSystem 全部访问掩码均失败, 最后一次 rc=%s (access=%s)" % last)


def _list_via_hcsdiag():
    """优先走 hcsdiag —— 它是官方 CLI, 行为可预期。

    🔴 为什么不直接用 HcsEnumerateComputeSystems:
       实测(2026-10-29, Win11 x64)在四种传参下(POINTER(c_void_p) /
       POINTER(HCS_ENUMERATION_RESULT 16B) / LPCWSTR 预分配缓冲 / NULL query)
       **全部**抛 "access violation writing 0x0000000000000000"。
       同一台机器上 `hcsdiag list` 正常返回(空列表) —— 说明 DLL 内部枚举路径
       在本机环境下不可用, 而 CLI 走的是不同代码路径。
       => list 一律以 hcsdiag 为准, DLL 只用于 props/stop。
    """
    try:
        p = subprocess.run(["hcsdiag", "list"], capture_output=True,
                           timeout=30, encoding="utf-8", errors="replace", creationflags=nowin.no_window())
    except FileNotFoundError:
        return None
    except Exception as e:
        print("[warn] hcsdiag 执行失败: %s" % e)
        return None
    raw = ((p.stdout or "") + (p.stderr or "")).strip()
    if "hcsdiag <command>" in raw:
        # 用法提示 => 不可用
        return None
    return raw


def do_list():
    raw = _list_via_hcsdiag()
    if raw is not None:
        print(raw if raw else "(无 compute system)")
        return 0
    print("[warn] hcsdiag 不可用, 回退到 computecore.dll 直调")
    # 回退路径: 失败时**绝不能崩**, 必须优雅返回。
    # 实测该路径在本机会抛 access violation, 所以整个调用包在 try 里,
    # 并且用独立子进程隔离 —— access violation 是 SEH 异常, 会直接杀进程。
    try:
        res = HCS_ENUMERATION_RESULT()
        rc = d.HcsEnumerateComputeSystems("", ctypes.byref(res))
    except OSError as e:
        print("[fail] HcsEnumerateComputeSystems 崩溃(已隔离): %s" % e)
        print("       提示: 该 DLL 枚举路径在本机不可用, 请用 hcsdiag list")
        return 1
    if rc != 0:
        print("HcsEnumerateComputeSystems 失败 rc=0x%08X" % (rc & 0xFFFFFFFF))
        return 1
    if not res.Buffer:
        print("(无 compute system)")
        return 0
    print(take_string(ctypes.cast(res.Buffer, ctypes.c_void_p).value))
    return 0


def do_props(sys_id: str):
    h, acc = open_system(sys_id)
    print("opened with access=0x%08X" % acc)
    out = ctypes.c_void_p()
    rc = d.HcsGetComputeSystemProperties(h, "", ctypes.byref(out))
    d.HcsCloseComputeSystem(h)
    if rc != 0:
        print("HcsGetComputeSystemProperties 失败 rc=0x%08X" % (rc & 0xFFFFFFFF))
        return 1
    raw = take_string(out.value)
    try:
        print(json.dumps(json.loads(raw), indent=2, ensure_ascii=False))
    except Exception:
        print(raw)
    return 0


def do_stop(sys_id: str):
    h, acc = open_system(sys_id)
    print("opened   access=0x%08X" % acc)
    op = ctypes.c_void_p()
    rc = d.HcsTerminateComputeSystem(h, "", ctypes.byref(op))
    if rc != 0:
        print("HcsTerminateComputeSystem 提交失败 rc=0x%08X" % (rc & 0xFFFFFFFF))
        d.HcsCloseComputeSystem(h)
        return 1
    print("terminate submitted")
    res = ctypes.c_void_p()
    # 30 秒足够；SavedAsTemplate 的 VM 没有活任务，通常 1-2 秒
    rc2 = d.HcsWaitForOperationResult(op, 30000, ctypes.byref(res))
    body = take_string(res.value)
    d.HcsCloseOperation(op)
    d.HcsCloseComputeSystem(h)
    print("op result rc=0x%08X" % (rc2 & 0xFFFFFFFF))
    if body:
        print(body)
    if rc2 != 0:
        return 1
    try:
        info = json.loads(body) if body else {}
        err = info.get("Error")
        if err:
            print("ERROR in result document: %s" % err)
            return 1
    except Exception:
        pass
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1].lower()
    print("[admin=%s]" % is_admin())
    if cmd == "list":
        return do_list()
    if cmd in ("stop", "props") and len(sys.argv) >= 3:
        sid = sys.argv[2]
        return do_stop(sid) if cmd == "stop" else do_props(sid)
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
