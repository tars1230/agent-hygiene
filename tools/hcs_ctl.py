#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hcs_ctl.py —— 通过 HCS 原生 API (computecore.dll) 管理 Hyper-V compute system。
hcsdiag 只有 list，没有 stop，所以停止只能走这个 API。

用法:
    python hcs_ctl.py list
    python hcs_ctl.py props  <id>
    python hcs_ctl.py stop   <id>

退出码: 0 成功 / 1 失败
"""
import ctypes
import ctypes.wintypes as wt
import json
import sys

DLL = r"C:\Windows\System32\computecore.dll"
d = ctypes.WinDLL(DLL)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

# ---- 原型 ----
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

d.HcsEnumerateComputeSystems.argtypes = [wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
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


def do_list():
    out = ctypes.c_void_p()
    # 注意: query 传 NULL 会被实现当字符串解引用 -> access violation。必须传空串。
    rc = d.HcsEnumerateComputeSystems("", ctypes.byref(out))
    if rc != 0:
        print("HcsEnumerateComputeSystems 失败 rc=0x%08X" % (rc & 0xFFFFFFFF))
        return 1
    print(take_string(out.value))
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
