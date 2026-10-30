#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
nowin.py —— 「启动子进程时不弹控制台窗口」的唯一入口

🔴 为什么需要这个模块（2026-10-30 实测踩出来的）
  Windows 上 `subprocess.run([...])` 默认给子进程**分配一个新控制台**。
  父进程在 Session 1（交互桌面）时，这个控制台就会在用户桌面上闪一下。
  本机实测：agent-hygiene 的本地控制台每 20 秒 spawn 一次
  `powershell.exe Get-CimInstance Win32_Process`，每 30 秒 spawn 一次
  `python.exe console_tasks.py list` + `schtasks.exe`，
  全都会在桌面闪出「管理员:」窗口。

🔴 关键知识点：`creationflags=CREATE_NO_WINDOW` 是**唯一可靠**的抑制手段
  · `-WindowStyle Hidden` 只是让 PowerShell 自己隐藏窗口，
    但 Windows 可能先分配控制台再隐藏 → 仍有「分配→隐藏」的可见瞬间。
  · `DETACHED_PROCESS` 会让子进程脱离父进程的控制台，
    但和管道重定向组合时行为不可靠。
  · `CREATE_NO_WINDOW` 明确告诉 Windows「不要为这个子进程分配控制台」，
    且不与 stdout/stderr 管道重定向冲突。→ 本项目统一用这个。

🔴 为什么不用 pythonw.exe 跑子进程
  pythonw.exe 没有 sys.stdout（print 会直接失败或丢输出），
  console_tasks.py / agent_hygiene_audit.py 都靠 print 输出 JSON，
  用 pythonw 会直接把功能改坏。
  → 服务**自身**可以用 pythonw（它只写日志不 print JSON），
    但**子进程**必须用 python.exe + CREATE_NO_WINDOW。
    两者由 py_exe() 区分：调用方要的是「能 print 的解释器」就用 py_exe()。
"""
import os
import subprocess
import sys

# Windows 进程创建标志（subprocess 只在 Windows 上有这几个常量，
# 这里兜底写死数值，保证在非 Windows 上 import 也不会炸）
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
DETACHED_PROCESS = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)


def no_window():
    """子进程 creationflags：抑制控制台窗口。"""
    if os.name != "nt":
        return 0
    return CREATE_NO_WINDOW


def py_exe():
    """要 print/写 stdout 的解释器路径（pythonw → python）。"""
    exe = sys.executable or "python"
    if exe.lower().endswith("pythonw.exe"):
        exe = exe[:-len("pythonw.exe")] + "python.exe"
    return exe


def pyw_exe():
    """不分配控制台的解释器路径（python → pythonw）。找不到就退回 python.exe。"""
    exe = sys.executable or "python"
    if exe.lower().endswith("pythonw.exe"):
        return exe
    cand = exe[:-len("python.exe")] + "pythonw.exe"
    if os.path.exists(cand):
        return cand
    return exe
