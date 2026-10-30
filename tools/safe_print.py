#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
safe_print.py —— 让脚本在 pythonw.exe 下也能安全 print

🔴 为什么需要
  pythonw.exe 没有 sys.stdout / sys.stderr（对象是 None），
  直接 `print("x")` 会抛 AttributeError: 'NoneType' object has no attribute 'write'。
  脚本一旦在 pythonw 下跑，print 就会把整个流程炸掉
  —— 而计划任务里 pythonw 是「不弹窗」的唯一手段。

🔴 做法
  把 sys.stdout / sys.stderr 重定向到一个「丢弃型」文件对象：
  既不报错，也不占控制台，也不丢日志（真正的日志都另外写文件）。
"""
import io
import os
import sys


class _NullWriter(io.TextIOBase):
    """写哪儿都不去，但保证 write/flush 可用。"""

    def write(self, s):
        return len(s) if s is not None else 0

    def flush(self):
        pass

    def writable(self):
        return True

    def readable(self):
        return False


def install():
    """若 stdout/stderr 为 None（pythonw），替换成空写入器。"""
    if getattr(sys, "stdout", None) is None:
        sys.stdout = _NullWriter()
    if getattr(sys, "stderr", None) is None:
        sys.stderr = _NullWriter()


install()
