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

🔴 关键知识点（2026-10-30 受控实测结论，勿再推翻）：
  父进程 = pythonw.exe（真正无控制台，等价 Electron GUI 父进程）时：

  | spawn 方式                       | 桌面上是否闪窗 |
  |----------------------------------|----------------|
  | 无 flags                          | 🔴 闪          |
  | `-WindowStyle Hidden`（仅 PS 参数）| 🔴 闪          |
  | `DETACHED_PROCESS`                | 🔴 闪          |
  | `DETACHED_PROCESS|CREATE_NO_WINDOW`| 🔴 **仍闪**    |
  | `CREATE_NO_WINDOW`                | ✅ 不闪        |

  · `CREATE_NO_WINDOW` 是**唯一可靠**的抑制手段，且与 stdout/stderr 管道重定向不冲突。
  · 🔴 `DETACHED_PROCESS` 会**覆盖** `CREATE_NO_WINDOW`：它强制子进程分配
    一个**全新**的控制台（原先继承父控制台），于是必然在 Session 1 桌面上显示。
    两者同用比不用还糟 —— 本项目 2026-10-30 的 console_server.py 就踩过这个坑。
  · `-WindowStyle Hidden` 只是 PowerShell 自己隐藏窗口，分配控制台的瞬间仍可见。
  · 父进程若**自身有控制台**（如 python.exe），子进程会直接继承 → 不会闪；
    所以做实验时必须用 pythonw 当父进程，否则测不出真实行为。

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
