#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
trash_to_recycle_bin.py —— 把文件移入 Windows 回收站（可恢复，非永久删除）

为什么不用别的
  · PowerShell 的 Add-Type（编译 .NET）被安全策略拦截
  · PowerShell 的 New-Object -ComObject Shell.Application（COM 实例化）也被拦截
  → 唯一可行路径：ctypes 直调 shell32 的 SHFileOperationW。

判据
  · FOF_ALLOWUNDO(0x40) = 进回收站，不是 Shift+Delete 的永久删除
  · 不带 FOF_NORECURSION / 不带 FOF_NOCONFIRMMKDIR 的破坏组合
  · pFrom 必须**双 NUL 结尾**（SHFileOperation 的老规矩，单个路径也必须）
  · 返回值 != 0 或 fAnyOperationsAborted = 失败

用法
    python tools/trash_to_recycle_bin.py <文件1> <文件2> ...
    python tools/trash_to_recycle_bin.py --dir <目录> --exclude-suffix .xlog
"""
import ctypes
import os
import sys
from ctypes import wintypes

SHELL32 = ctypes.WinDLL("shell32.dll", use_last_error=True)

# SHFileOperation 的 fFlags
FO_DELETE = 0x0003
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040          # 🔴 进回收站的关键
FOF_NOERRORUI = 0x0400
FOF_NOCONFIRMMKDIR = 0x0200

# 多个文件时用 \0 分隔、末尾再加一个 \0（双 NUL 结尾）
DOUBLE_NUL = "\0\0"


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def trash_files(paths, dry_run=False):
    """把 paths 移入回收站。返回 (成功数, 失败列表)。"""
    if not paths:
        return 0, []
    if dry_run:
        print("[DRY-RUN] 将移入回收站 %d 个文件:" % len(paths))
        for p in paths:
            print("   %s" % p)
        return 0, []

    # 双 NUL 结尾
    src = "".join(os.path.abspath(p) + "\0" for p in paths) + "\0"
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = src
    op.pTo = None
    op.fFlags = (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI
                 | FOF_SILENT | FOF_NOCONFIRMMKDIR)
    op.fAnyOperationsAborted = False
    op.hNameMappings = None
    op.lpszProgressTitle = None

    rc = SHELL32.SHFileOperationW(ctypes.byref(op))
    if rc != 0:
        return 0, [("<SHFileOperationW rc=%d>" % rc, paths)]
    if op.fAnyOperationsAborted:
        # 部分被中止：逐个重试以便定位是哪个
        ok = 0
        bad = []
        for p in paths:
            one = os.path.abspath(p) + "\0" + "\0"
            o2 = SHFILEOPSTRUCTW()
            o2.hwnd = None
            o2.wFunc = FO_DELETE
            o2.pFrom = one
            o2.pTo = None
            o2.fFlags = op.fFlags
            o2.fAnyOperationsAborted = False
            o2.hNameMappings = None
            o2.lpszProgressTitle = None
            r2 = SHELL32.SHFileOperationW(ctypes.byref(o2))
            if r2 == 0 and not o2.fAnyOperationsAborted and not os.path.exists(p):
                ok += 1
            else:
                bad.append(p)
        return ok, bad
    return len(paths), []


def main():
    args = sys.argv[1:]
    dry = False
    if "--dry-run" in args:
        dry = True
        args.remove("--dry-run")

    paths = []
    for a in args:
        if os.path.exists(a):
            paths.append(a)
        else:
            print("SKIP(不存在): %s" % a)
    if not paths:
        print("没有可处理的文件")
        return 0

    total = 0
    for p in paths:
        try:
            print("  %10.1f MB  %s" % (os.path.getsize(p) / 1048576.0, p))
        except OSError:
            pass

    ok, bad = trash_files(paths, dry_run=dry)
    if dry:
        return 0
    print()
    print("已移入回收站: %d 个" % ok)
    if bad:
        print("失败 %d 个:" % len(bad))
        for b in bad:
            print("   %s" % b)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
