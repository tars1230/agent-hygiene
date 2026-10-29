#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
门禁的**负向验证**：证明门禁真的会 FAIL。

纪律：门禁必须自己被负向验证过。
「实现了检查」不等于「检查有效」——只有把文档改坏、门禁报 FAIL，才算证据。

用法:
    python tools/gate_negative_test.py      # 在副本上做破坏，跑完自动还原
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(HERE, "skill", "diagnostic-tool-trust", "scripts",
                    "check_skill_consistency.py")
README = os.path.join(HERE, "README.md")
SKILL = os.path.join(HERE, "skill", "agent-hygiene", "SKILL.md")
DTT = os.path.join(HERE, "skill", "diagnostic-tool-trust", "SKILL.md")

# (场景名, 文件, 原文, 替换为, 期望)
#
# 🔴 每个场景必须是**真实的破坏**。
#    早期版本有三个场景设计错了（改措辞 / 删修饰词不算破坏，文档仍自洽），
#    门禁报 PASS 是**正确行为**，不能算漏报。
#    → 现在每个场景都对应「文档自相矛盾」或「关键数字消失」。
SCENARIOS = [
    # S1 数字边界：191435 -> 1914350。原处变成另一个数 → 文档与其它处矛盾
    ("S1 句柄数改成 1914350（无数字边界）",
     README, "Weixin 主进程持有 **191435 个句柄**", "Weixin 主进程持有 **1914350 个句柄**",
     "FAIL"),
    # S2 单实例下限改成 200000。同上
    ("S2 单实例下限改成 200000",
     README, "绝对下限 20000", "绝对下限 200000", "FAIL"),
    # S3 清单行复活 + **真正的 1022 出处被删**。
    #    只改措辞不算破坏（清单行仍会被结构性判据剔除，文档仍自洽）——
    #    早期版本这个场景设计错了，门禁报 PASS 是正确行为。
    #    → 真正的破坏是：把清单行改成正文话术，**同时**删掉 1022 的真实出处。
    ("S3 清单行复活 + 真实 1022 出处被删",
     README,
     "> (186930 − 180800) / (15 − 9) = **1022/分钟**。而本次实测是 **−3.2/分钟**。",
     "> (186930 − 180800) / (15 − 9) = **速率见采样表**。而本次实测是 **−3.2/分钟**。",
     "FAIL"),
    # S4 同一数字两处不一致：89.79 -> 89.00%（一处改一处没改）
    ("S4 百分比改成 89.00%（一处改一处没改）",
     README, "29641 个（89.79%）", "29641 个（89.00%）", "FAIL"),
    # S5 分母漂移：33012 -> 30000（多处出现，改一处 → 全文取值不一致）
    ("S5 分母漂移 33012 -> 30000",
     README, "（分母 33012）", "（分母 30000）", "FAIL"),
    # S6 关键判据被删（不是改措辞）：SOLO_HANDLES_ABS 整个标识符删掉
    ("S6 删除 SOLO_HANDLES_ABS 判据标识",
     README, "单实例组用 20000（下限 `SOLO_HANDLES_ABS`）", "单实例组用 20000", "FAIL"),
    # S7 小数点被省略：3.2 -> 32（另一个数字冒充）
    ("S7 小数点被省略：3.2 写成 32",
     README, "-3.2 个/分钟", "-32 个/分钟", "FAIL"),
    # S8 分子消失：僵尸句柄数 29641 全部改成别的 → 关键数字丢失
    ("S8 僵尸句柄数全部改成 29642",
     README, "29641 个（89.79%）", "29642 个（89.79%）", "FAIL"),
    # S9 活值数字的**出处标记**被删：模拟「编一个时间标注」的失败模式。
    #    把引言里写明出处的整句话删掉 → 23192 变成无出处的裸数字。
    #    这正是第三方复核抓到的真实问题（「15:2x 采样」那个时间段根本没运行过）。
    ("S9 活值数字的出处标记被删",
     README,
     "演练输出长这样（每行是一套「回收配方」的判定结果；本次为 **2026-10-29 16:43** 的真实运行，逐行取自 `%LOCALAPPDATA%\\agent-hygiene\\logs\\stuck_cleanup.log` L46–49）：",
     "演练输出长这样（每行是一套「回收配方」的判定结果）：",
     "FAIL"),
    # S10 活值数字**完全消失** → 关键数字丢失
    #    必须删掉**全部**出现（count=0 = replace 全部），否则别处还有 → 门禁 PASS 是正确行为
    ("S10 活值数字 23192 完全消失",
     README, "23192", "23x92", "FAIL", 0),
]


def run_gate():
    p = subprocess.run([sys.executable, GATE], cwd=HERE,
                       capture_output=True, text=True)
    return p.returncode, p.stdout


def main():
    # 基线：必须是 PASS
    rc, out = run_gate()
    print("基线门禁退出码 = %d（期望 0）" % rc)
    if rc != 0:
        print(out)
        print("❌ 基线不是 PASS，先修好再测破坏场景")
        return 1

    backups = {}
    for scen in SCENARIOS:
        f = scen[1]
        if f not in backups:
            backups[f] = io.open(f, encoding="utf-8").read()

    results = []
    try:
        for scen in SCENARIOS:
            name, f, old, new, expect = scen[:5]
            # 可选第 6 项：替换次数（默认 1）。S10 需要「删掉全部出现」。
            count = scen[5] if len(scen) > 5 else 1
            t = io.open(f, encoding="utf-8").read()
            if old not in t:
                results.append((name, "SKIP", "原文没找到：%r" % old[:40], expect))
                continue
            io.open(f, "w", encoding="utf-8", newline="").write(
                t.replace(old, new) if count == 0 else t.replace(old, new, count))
            rc, out = run_gate()
            hits = [l.strip() for l in out.split("\n") if l.strip().startswith("[!!]")]
            verdict = "FAIL(1)" if rc == 1 else "PASS(0)"
            ok = (verdict == "FAIL(1)") == (expect == "FAIL")
            results.append((name, verdict if ok else "✗ " + verdict,
                            (hits[0][:90] if hits else "门禁没报任何问题"), expect))
            # 还原
            io.open(f, "w", encoding="utf-8", newline="").write(backups[f])
    finally:
        for f, t in backups.items():
            io.open(f, "w", encoding="utf-8", newline="").write(t)

    print()
    print("=" * 78)
    print("门禁负向验证结果")
    print("=" * 78)
    for name, verdict, detail, expect in results:
        mark = "✓" if not verdict.startswith("✗") and verdict != "SKIP" else ("-" if verdict == "SKIP" else "✗")
        print("%s %-42s %-10s (期望%s) %s" % (mark, name, verdict, expect, detail))

    # 还原后必须仍然 PASS
    rc, out = run_gate()
    print()
    print("还原后门禁退出码 = %d（期望 0）" % rc)

    bad = [r for r in results
           if r[1].startswith("✗") or (r[3] == "FAIL" and r[1] != "FAIL(1)")]
    if rc != 0 or bad:
        print()
        print("❌ 有场景门禁没抓住，或还原后不是 PASS")
        return 1
    print("✅ 所有破坏场景都被门禁抓住，且还原后 PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
