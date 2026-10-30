#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
fast_cmdline.py —— 一次 WMI 取全表命令行（进程组聚类需要）

🔴 为什么不用 ToolHelp 快照
  ToolHelp32 只有进程名，没有命令行。进程组聚类必须按**入口脚本**分组，
  所以要命令行。WMI 的 Win32_Process 一次能拿全表 CommandLine。

🔴 为什么单独一个模块而不是塞进 fast_probe
  fast_probe 的定位是「44ms 的高频采样」，**不能拖进任何 spawn 子进程的调用**——
  那会让每 10 秒一次的轮询都多花 1.5 秒。
  命令行只做**低频**（20 秒缓存一次），且只在需要聚类时才取。
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

PS_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def all_cmdlines():
    """返回 {pid: command_line}。失败返回空 dict（调用方自己降级）。"""
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress -Depth 2"
    )
    try:
        r = subprocess.run([PS_EXE, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=90,
                           creationflags=nowin.no_window())
    except Exception:
        return {}
    out = (r.stdout or b"").decode("utf-8", "replace").strip()
    if not out:
        return {}
    try:
        data = json.loads(out)
    except Exception:
        return {}
    if isinstance(data, dict):
        data = [data]
    res = {}
    for d in data:
        try:
            res[int(d["ProcessId"])] = d.get("CommandLine") or ""
        except (KeyError, TypeError, ValueError):
            continue
    return res


if __name__ == "__main__":
    cl = all_cmdlines()
    print("取到 %d 个进程的命令行" % len(cl))
    for pid, cmd in list(cl.items())[:5]:
        print("  %-8d %s" % (pid, cmd[:120]))
