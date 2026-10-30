#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""probe_schtasks_csv.py —— 验证 schtasks CSV /v 的编码与字段稳定性

目的：在写正式实现前，先把「怎么读」这件事一次性测准，
避免写到一半才发现编码/字段对不上。

要验证的 4 件事：
  1. stdout 是 GBK 还是 UTF-8？（schtasks 在中文 Windows 上通常是 OEM/ANSI）
  2. 表头是否稳定（列数、列名）
  3. CSV 里的换行/引号怎么转义（动作路径里可能有逗号）
  4. 单次调用耗时（决定能不能实时读）
"""
import csv
import io
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nowin  # noqa: E402


def main():
    t0 = time.time()
    r = subprocess.run(
        ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
        capture_output=True, timeout=60,
        creationflags=nowin.no_window())
    dt = time.time() - t0
    raw = r.stdout or b""
    print("bytes=%d  elapsed=%.2fs  returncode=%s" % (len(raw), dt, r.returncode))
    print("stderr=%r" % (r.stderr or b"")[:200])

    # 1. 编码探测
    text = None
    used = None
    for enc in ("utf-8-sig", "gb18030", "gbk", "cp936", "mbcs"):
        try:
            text = raw.decode(enc)
            used = enc
            print("decoded with %s -> OK" % enc)
            break
        except Exception as e:
            print("decode %s -> FAIL %s" % (enc, e))
    if text is None:
        print("ALL DECODE FAILED")
        return 1

    # 2. 表头
    rows = list(csv.reader(io.StringIO(text)))
    print("\nrows=%d" % len(rows))
    header = rows[0]
    print("header cols=%d" % len(header))
    for i, h in enumerate(header):
        print("  [%2d] %r" % (i, h))

    # 3. 列数一致性
    bad = [(i, len(r)) for i, r in enumerate(rows) if len(r) != len(header)]
    print("\n列数不一致的行: %d %s" % (len(bad), bad[:10]))

    # 4. 抽样非 Microsoft 行
    print("\n=== 抽样：含中文路径的动作列 ===")
    shown = 0
    for r in rows[1:]:
        if len(r) < 9:
            continue
        name = r[1]
        action = r[8]
        if "Microsoft\\" in name:
            continue
        if shown >= 3:
            break
        print("name=%r" % name)
        print("  action=%r" % action[:160])
        print("  user=%r status=%r next=%r lastresult=%r"
              % (r[13], r[3], r[2], r[6]))
        shown += 1

    # 5. 检查「上次结果」字段的取值分布 —— 这是判断任务是否健康的信号
    from collections import Counter
    c = Counter()
    for r in rows[1:]:
        if len(r) > 6:
            c[r[6]] += 1
    print("\n=== 上次结果分布（TOP 12）===")
    for k, v in c.most_common(12):
        print("  %-14s %d" % (k, v))

    return 0


if __name__ == "__main__":
    sys.exit(main())
