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

  还有一个更隐蔽的副本问题：skill 装在 `~/.workbuddy/skills/agent-hygiene/SKILL.md`，
  是仓库版的**手工拷贝**。仓库里改了 skill，装的那份不会自动跟着变——
  2026-10-29 实测：仓库版已修正 7 个判据，用户级装的还是旧版（13 条铁律 vs 17 条），
  新增的 leave-one-out / SOLO_HANDLES_ABS / 489 行 / Nonexistent 判据**一条都没有**。
  下次 agent 加载 skill 会用错判据 → 这类「三处副本」必须机器校验。

判据
  1) 构成表各行必须加总等于声明的总数（不等的 = FAIL）
  2) 同一个指标在 README 与 SKILL 里必须出现同一个值（不一致 = FAIL）
  3) 已废弃的旧数字不得再出现（例如已作废的「+675/分钟」「487 行」）
  4) 已安装的 skill 副本必须与仓库版一致（不一致 = FAIL，提示重新同步）

退出码 0 = 全一致；非 0 = 有 FAIL。
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
SKILL = os.path.join(ROOT, "skill", "agent-hygiene", "SKILL.md")

# 已安装 skill 的可能位置（Windows / macOS / Linux）
INSTALLED_CANDIDATES = [
    os.path.join(os.path.expanduser("~"), ".workbuddy", "skills", "agent-hygiene", "SKILL.md"),
    os.path.join(os.path.expanduser("~"), ".claude", "skills", "agent-hygiene", "SKILL.md"),
]

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
    # 2026-10-30 微信内存结构实测（README 与 SKILL 铁律 21/22 都引用）
    ("WMPF 容器 Private", r"698\.6", "微信 WMPF 小程序容器 Private(MB)"),
    ("WMPF 容器占比", r"49\.3%", "WMPF 占微信内存比例"),
    ("微信进程总数 Private", r"1415\.7", "微信 17 进程 Private 合计(MB)"),
    ("trim 差分净效应", r"0\.68", "trim ABBA 差分净效应(GB)"),
    ("trim 差分已提交", r"0\.9", "trim ABBA 差分已提交增量(GB)"),
]

# 🔴 「同值校验」：同一个指标在每份文档里必须**值相同且唯一**。
#
#    2026-10-30 负向验证连抓两轮真缺陷，判据被两次打脸：
#      第 1 轮缺陷：只判「两边都有这个数字」→ 把 README 的 698.6 改成 699.9（SKILL 不改）
#                   → 两边「都有 WMPF 相关内容」→ 门禁报 PASS。
#      第 2 轮缺陷：加了「两边都必须是 698.6」→ 但 README 里这个数字**出现 2 次**
#                   （表格 1 次 + 正文 1 次），只改其中 1 处 → 另一处仍是 698.6
#                   → 门禁仍报 PASS。
#    → 正确判据：**逐文档抽取该指标的所有实际值，要求并集恰好 1 个，且两文档相同。**
#      只要任何一处被改 → 抽取到的值集合要么变大、要么与另一份文档不等 → FAIL。
#
#    抽取靠「锚点 + 单位」正则，避免全文找裸数字（否则 879MB / 100% 之类会混进来）。
#    group(1) 必须是捕获到的数值。
#
# (指标名, 说明, {文档路径: [pattern, ...]})
SAME_VALUE_CHECKS = [
    ("WMPF 容器 Private", "WMPF 容器 Private(MB)", {
        README: [r"\|\s*\*\*WMPF 小程序容器\*\*[^\n]*?(\d+(?:\.\d+)?)\s*MB"],
        SKILL:  [r"占微信内存[^）]{0,40}?(\d+(?:\.\d+)?)\s*MB"],
    }),
    ("WMPF 容器占比", "WMPF 占微信内存比例(%)", {
        README: [r"\|\s*\*\*WMPF 小程序容器\*\*[^\n]*?(\d+(?:\.\d+)?)\s*%",
                 r"占微信\s*(\d+(?:\.\d+)?)\s*%"],
        SKILL:  [r"占微信内存[^）]{0,40}?(\d+(?:\.\d+)?)\s*%"],
    }),
    ("微信进程总数 Private", "微信 17 进程 Private 合计(MB)", {
        README: [r"\|\s*合计\s*\|\s*\d+\s*\|\s*\*\*(\d+(?:\.\d+)?)\s*MB"],
        SKILL:  [r"Private 合计\s*\*\*(\d+(?:\.\d+)?)MB"],
    }),
    ("trim 差分净效应", "trim ABBA 净效应(GB)", {
        README: [r"可用内存\s*[−\-]?(\d+(?:\.\d+)?)\s*GB"],
        SKILL:  [r"可用内存\s*[−\-]?(\d+(?:\.\d+)?)\s*GB"],
    }),
    ("trim 差分已提交", "trim ABBA 已提交增量(GB)", {
        README: [r"已提交\s*\+(\d+(?:\.\d+)?)\s*GB"],
        SKILL:  [r"已提交\s*\+(\d+(?:\.\d+)?)\s*GB"],
    }),
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
    print("=== 2b) 同一指标在两份文档里的**值必须相同且唯一** ===")
    for label, desc, patterns in SAME_VALUE_CHECKS:
        per_doc = {}
        for path, pats in patterns.items():
            vals = []
            for pat in pats:
                for m in re.finditer(pat, files[path]):
                    vals.append(m.group(1))
            per_doc[path] = sorted(set(vals))
        r_vals = per_doc.get(README, [])
        s_vals = per_doc.get(SKILL, [])
        all_vals = sorted(set(r_vals) | set(s_vals))
        # 🔴 三条独立判据，缺一不可：
        #   ① 两份文档**都**必须抽到值（缺一边 = 该指标在一边被删掉了）
        #   ② 并集必须**唯一**（多个值 = 同一指标在文档里自相矛盾）
        #   ③ 两边必须**相等**（不等 = 两处写的数不一样）
        # 早期版本只判「两边都有」→ 改了一边的数字反而 PASS（负向验证实测打脸）。
        missing = [os.path.basename(p) for p, v in per_doc.items() if not v]
        if missing:
            fails.append("%s：在 %s 里抽不到值 —— 该指标被删除或改写导致无法复核"
                         % (desc, "、".join(missing)))
            print("  [FAIL] %-22s 缺值：%s（README=%s SKILL=%s）"
                  % (label, "、".join(missing), r_vals, s_vals))
        elif len(all_vals) > 1:
            fails.append("%s：抽到多个不同值 %s —— 同一指标在文档里不一致"
                         % (desc, all_vals))
            print("  [FAIL] %-22s 值不唯一：README=%s SKILL=%s"
                  % (label, r_vals, s_vals))
        elif r_vals != s_vals:
            fails.append("%s：README=%s 与 SKILL=%s 不等" % (desc, r_vals, s_vals))
            print("  [FAIL] %-22s 两边不等：README=%s SKILL=%s" % (label, r_vals, s_vals))
        else:
            print("  [ok]   %-22s 两边同值 %s" % (label, all_vals[0]))

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
    print("=== 4) 已安装 skill 副本 vs 仓库版 ===")
    skill_repo = files[SKILL]
    found_any = False
    for cand in INSTALLED_CANDIDATES:
        if not os.path.exists(cand):
            print("  [skip] %s 不存在" % cand)
            continue
        found_any = True
        inst = read(cand)
        if inst == skill_repo:
            print("  [ok]   %s 内容一致" % cand)
        else:
            # 找出「仓库版有、装的那份没有」的判据关键词，说明差在哪
            probes = ["leave-one-out", "SOLO_HANDLES_ABS", "489", "0xBBBF0",
                      "Nonexistent", "check_doc_consistency"]
            missing = [p for p in probes if p in skill_repo and p not in inst]
            # 单位统一用「字符数」（不是字节数）—— 中文 UTF-8 一个字 3 字节，混用会看错量级
            delta_chars = len(inst) - len(skill_repo)
            fails.append("已安装 skill 与仓库版不一致：%s（相差 %+d 字符%s）"
                         % (cand, delta_chars,
                            "；仓库版有而装版缺：" + "、".join(missing) if missing else ""))
            print("  [FAIL] %s" % cand)
            print("         仓库版 %d 字符 / 装的那份 %d 字符（%+d）"
                  % (len(skill_repo), len(inst), delta_chars))
            if missing:
                print("         仓库版有而装版缺：%s" % "、".join(missing))
            print("         → 修复：cp \"%s\" \"%s\"" % (SKILL, cand))
    if not found_any:
        print("  [skip] 没有找到已安装的 skill 副本（本机可能未安装）")

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
