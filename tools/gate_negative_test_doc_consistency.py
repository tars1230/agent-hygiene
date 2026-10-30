#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
gate_negative_test_doc_consistency.py —— check_doc_consistency.py 的负向验证

纪律：门禁必须自己被负向验证过。
「实现了检查」不等于「检查有效」——只有把文档改坏、门禁报 FAIL，才算证据。

🔴 本脚本的第一次版本有个真 bug（2026-10-30 踩到）：
   备份用的 `backups[path] = text` 在**循环里被反复覆盖**，
   第 2 个场景开始备份的就是「已被上一个场景污染过的文本」→ 还原后文件是脏的。
   → 现在改成**每个场景独立备份自己的原文**，逐场景还原。
   这正是「门禁的负向验证脚本本身也会错」——同一个坑的第二个版本。

用法:
    python tools/gate_negative_test_doc_consistency.py
退出码 0 = 所有破坏场景都被抓住且还原后 PASS。
"""
import io
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
SKILL = os.path.join(ROOT, "skill", "agent-hygiene", "SKILL.md")
INST = os.path.expanduser("~/.workbuddy/skills/agent-hygiene/SKILL.md")
GATE = os.path.join(ROOT, "tools", "check_doc_consistency.py")


def run_gate():
    r = subprocess.run([sys.executable, GATE], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return r.returncode


def apply(path, old, new):
    """改一处，返回该文件改前的完整原文（供还原）。"""
    text = io.open(path, encoding="utf-8").read()
    if old not in text:
        return None
    io.open(path, "w", encoding="utf-8", newline="").write(text.replace(old, new, 1))
    return text


# (场景名, 文件, 原文, 替换为, 期望 FAIL)
SCENARIOS = [
    # --- 第 2 类：同指标一致性 ---
    ("N1 WMPF 容器 Private 698.6 -> 699.9（只改 README）",
     README, "698.6 MB", "699.9 MB"),
    ("N2 WMPF 占比 49.3% -> 50.3%（只改 README）",
     README, "49.3%", "50.3%"),
    ("N3 微信合计 1415.7 -> 1500.0（只改 README）",
     README, "1415.7 MB", "1500.0 MB"),
    ("N4 trim 净效应 0.68 -> 0.69（只改 README）",
     README, "0.68GB", "0.69GB"),
    ("N5 trim 已提交 0.9 -> 1.9（只改 README）",
     README, "0.9GB", "1.9GB"),
    # --- 第 2b 类：同值校验（SKILL 侧改） ---
    ("N6 WMPF 占比在 SKILL 侧被改掉",
     SKILL, "49.3%", "五成左右"),
    ("N7 微信合计在 SKILL 侧被改掉",
     SKILL, "1415.7MB", "1500.0MB"),
    # --- 第 4 类：skill 副本不同步 ---
    ("N8 已安装 skill 副本被改成旧版",
     INST, "698.6MB", "旧版数字"),
]


def main():
    print("=== 基线门禁 ===")
    rc = run_gate()
    print("基线退出码 = %d（期望 0）" % rc)
    if rc != 0:
        print("❌ 基线就不 PASS，先修文档再谈负向验证")
        return 1

    print()
    print("=" * 70)
    print("check_doc_consistency.py 负向验证结果")
    print("=" * 70)

    missed = []
    for name, path, old, new in SCENARIOS:
        orig = apply(path, old, new)
        if orig is None:
            print("  [SETUP-ERR] %s —— 原文 '%s' 不在 %s" % (name, old, path))
            missed.append(name)
            continue
        try:
            # SKILL 改了要同步安装副本，否则第 4 类检查先炸，测的就不是目标判据
            if path == SKILL:
                shutil.copyfile(SKILL, INST)
            rc = run_gate()
            ok = rc != 0
            print("  [%s] %s" % ("ok  " if ok else "MISS", name))
            if not ok:
                missed.append(name)
        finally:
            # 🔴 逐场景还原，且**还原的是这个场景开始前的原文**
            io.open(path, "w", encoding="utf-8", newline="").write(orig)
            if path == SKILL:
                shutil.copyfile(SKILL, INST)

    rc = run_gate()
    print()
    print("还原后门禁退出码 = %d（期望 0）" % rc)
    if missed or rc != 0:
        print("❌ %d 个场景未被捕获：%s" % (len(missed), "、".join(missed)))
        return 1
    print("✅ %d/%d 场景全部被捕获，且还原后 PASS"
          % (len(SCENARIOS), len(SCENARIOS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
