#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""probe_task_health.py —— 验证「任务可执行文件是否还活着」这条信号的判别力

核心想法：应用被卸载后，它留下的计划任务还在，
动作指向的 exe 已经不存在 —— 这样的任务是**纯垃圾**，
既占资源又会让用户困惑（「这啥玩意」）。

这条信号是否够强？拿本机 31 个非 Microsoft 任务实测。
"""
import csv
import io
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402

MS_PATH_MARK = "Microsoft" + os.sep


def main():
    r = subprocess.run(
        ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
        capture_output=True, timeout=60,
        creationflags=nowin.no_window())
    text = r.stdout.decode("gb18030", "replace")
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    header[0] = header[0].lstrip("\ufeff")

    idx = {name: i for i, name in enumerate(header)}

    def g(row, cn):
        i = idx.get(cn)
        return row[i] if i is not None and i < len(row) else ""

    print("=== 非 Microsoft 任务：exe 存活 / 上次结果 / 触发节奏 ===\n")
    n_ok = n_miss = n_unknown = 0
    for row in rows[1:]:
        if len(row) < 15:
            continue
        name = g(row, "任务名")
        if MS_PATH_MARK in name:
            continue
        action = g(row, "要运行的任务")
        m = re.match(r'^"?([^"\s]+)', action)
        exe = m.group(1).strip('"') if m else ""
        if exe and os.path.exists(exe):
            state, n_ok = "OK  ", n_ok + 1
        elif exe:
            state, n_miss = "MISS", n_miss + 1
        else:
            state, n_unknown = "?   ", n_unknown + 1
        res = g(row, "上次结果")
        rep = g(row, "重复: 每")
        user = g(row, "作为用户运行")
        print("  %-4s %-40s res=%-12s rep=%-16s user=%s"
              % (state, name.replace("\\", "")[:40], res[:12], rep[:16], user))
        if state == "MISS":
            print("        exe 不存在: %s" % exe[:100])

    print("\n存在=%d  不存在=%d  无法判定=%d  (共 %d 个非 Microsoft 任务)"
          % (n_ok, n_miss, n_unknown, n_ok + n_miss + n_unknown))


if __name__ == "__main__":
    main()
