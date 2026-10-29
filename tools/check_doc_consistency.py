#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
check_doc_consistency.py —— 文档一致性核验（只读）

为什么需要这个
  同一个数字在 README.md 和 skill/agent-hygiene/SKILL.md 里各写一遍，
  改了一处忘了另一处，就产生互相矛盾的数字。
  2026-10-29 的第三方独立复核（grok 4.7）发现 README 的构成表
  「80849+61193+30632+3752+601 = 177027」与它自己声明的 178033 对不上——
  纯靠人眼发现不了。

判据
  1) 构成表各行必须加总等于声明的总数（不等的 = FAIL）
  2) 同一个指标在 README 与 SKILL 里必须出现同一个值（不一致 = FAIL）
  3) 已废弃的旧数字不得再出现（例如已作废的「+675/分钟」「487 行」）

退出码 0 = 全一致；非 0 = 有 FAIL。
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
SKILL = os.path.join(ROOT, "skill", "agent-hygiene", "SKILL.md")

# (指标名, 必须同时出现的两个文档里的正则, 说明)
PAIR_CHECKS = [
    ("Weixin 句柄总数", r"191435", "Weixin 主进程句柄总数"),
    ("同 exe 中位数倍数", r"788", "Weixin 相对同伴中位数的倍数"),
    ("Event 数量", r"87031", "Event 类句柄数"),
    ("Token 数量", r"65949", "Token 类句柄数"),
    ("Process 数量", r"33012", "Process 类句柄数"),
    ("僵尸句柄数", r"29641", "指向已退出进程的僵尸句柄数"),
    ("explorer 泄漏 pid", r"13092", "explorer 泄漏样本 pid"),
    ("Handle 默认输出行数", r"489", "不加 -a 的输出行数"),
    ("Handle 最大句柄值", r"0xBBBF0", "不加 -a 的最大句柄值"),
]

# 已作废、不得再出现在正文里的旧说法
BANNED = [
    (r"只枚举了前 4020 号槽位", "已作废的『只枚举前 4020 号槽位』机制解释"),
    (r"\+675/分钟", "已作废的写死速率『+675/分钟』"),
    (r"487 行", "已作废的默认输出行数 487"),
    (r"172674", "已作废的『6×僵尸数=172674』"),
    (r"96\.8%", "已作废的僵尸占比 96.8%"),
]

# 「构成表」类表格：抓 `| Event | 87031 |` 这种行并加总
TABLE_ROW_RE = re.compile(r"^\|\s*(Event|Token|Process|Key)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%\s*\|$",
                          re.M)


def read(p):
    return io.open(p, encoding="utf-8").read()


def main():
    files = {README: read(README), SKILL: read(SKILL)}
    fails = []
    warns = []

    print("=== 1) 构成表加总校验 ===")
    for path, text in files.items():
        rows = TABLE_ROW_RE.findall(text)
        if not rows:
            print("  [skip] %s 没有构成表" % os.path.basename(path))
            continue
        total_declared = None
        # 找同一张表里声明的总数
        m = re.search(r"(\d{5,})\s*个句柄", text)
        if m:
            total_declared = int(m.group(1))
        s = sum(int(c) for _, c, _ in rows)
        pct = sum(float(p) for _, _, p in rows)
        name = os.path.basename(path)
        if total_declared and abs(s - total_declared) > 2000:
            fails.append("%s 构成表加总 %d 与声明的 %d 相差 %d"
                         % (name, s, total_declared, s - total_declared))
            print("  [FAIL] %-14s 加总 %d vs 声明 %d" % (name, s, total_declared))
        else:
            print("  [ok]   %-14s 加总 %d（声明 %s），占比合计 %.2f%%"
                  % (name, s, total_declared, pct))

    print()
    print("=== 2) 两份文档的同指标一致性 ===")
    for label, pat, desc in PAIR_CHECKS:
        in_r = bool(re.search(pat, files[README]))
        in_s = bool(re.search(pat, files[SKILL]))
        if in_r and in_s:
            print("  [ok]   %-22s 两边都有" % label)
        elif in_r != in_s:
            warns.append("%s（%s）只在 %s 出现"
                         % (desc, pat, "README" if in_r else "SKILL"))
            print("  [WARN] %-22s 只在 %s 出现" % (label, "README" if in_r else "SKILL"))
        else:
            fails.append("%s（%s）两份文档都没有" % (desc, pat))
            print("  [FAIL] %-22s 两边都没有" % label)

    print()
    print("=== 3) 已作废说法残留检查 ===")
    for path, text in files.items():
        name = os.path.basename(path)
        for pat, desc in BANNED:
            # 允许出现在「已作废/早期版本/踩过的坑」这类说明性上下文里
            for m in re.finditer(pat, text):
                ctx = text[max(0, m.start() - 160):m.start()]
                excused = any(k in ctx for k in
                              ("已作废", "早期版本", "踩过的坑", "错的", "不成立",
                               "纠正", "修正", "不是", "早期"))
                if excused:
                    print("  [ok]   %-14s %s（在说明性上下文中，已标注）" % (name, desc))
                else:
                    fails.append("%s 里残留未标注的已作废说法：%s" % (name, desc))
                    print("  [FAIL] %-14s %s <- %s"
                          % (name, desc, text[max(0, m.start() - 60):m.end() + 20]
                             .replace("\n", " ")))

    print()
    print("=" * 60)
    if fails:
        print("VERDICT: FAIL (%d 项)" % len(fails))
        for f in fails:
            print("  - %s" % f)
        return 1
    print("VERDICT: PASS（%d 项警告）" % len(warns))
    for w in warns:
        print("  - %s" % w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
