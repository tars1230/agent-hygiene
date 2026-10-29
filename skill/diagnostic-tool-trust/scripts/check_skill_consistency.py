#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
校验纪律类 Skill 的关键判据是否还在，且**所有副本内容一致**。

为什么需要这个门禁：
  纪律类 Skill 最容易被「写完就忘」。本项目实测过 skill 有三份副本
  （仓库版 / 安装版 / 可能的其他 agent 目录），改了其中一份不会同步另外几份，
  而且**没有任何东西会报错**。
  → 这个脚本把「关键判据还在不在 + 副本有没有分叉」变成机器可复核的。

四道检查：
  1) 关键判据是否还在（来自真实事故，不是想象的）
  2) 基准源 vs 所有副本是否逐字节一致
  3) 与 agent-hygiene 仓库的共享数字是否一致（防手抄漂移）
  4) 副本缺失 / 读不出 = FAIL（不许静默降级）

用法:
    python check_skill_consistency.py            # 检查全部
    python check_skill_consistency.py --json     # 机器可读输出
    python check_skill_consistency.py --base <dir>   # 指定基准源目录

退出码: 0 = 全一致；1 = 有缺失或分叉
"""
import io
import json
import os
import re
import sys

HOME = os.path.expanduser("~")

# ---------------------------------------------------------------- 路径解析
# 本脚本位于 <root>/diagnostic-tool-trust/scripts/check_skill_consistency.py
# 往上三层 = <root>，其中 <root> 可能是 skills 根目录，也可能是仓库的 skill/ 目录
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # <root>
_PARENT = os.path.dirname(_ROOT)                          # <root> 的上级

# 基准源候选：优先仓库版，其次安装版
_BASE_CANDIDATES = [
    _ROOT,                                              # 仓库内 skill/ 目录（_ROOT 本身就是它）
    os.path.join(HOME, ".workbuddy", "skills"),
    os.path.join(_PARENT, "agent-hygiene", "skill"),
]

# 每个 Skill 的所有副本路径（相对基准源 + 绝对路径）
def _copies(name, base):
    """返回 (label, path) 列表。base 是基准源根目录。

    🔴 基准源必须是**第一个**元素，且必须真的存在且可读。
       `check_one()` 会把第一个可读副本当比较基准 ——
       如果基准源读不出来却继续往下找，就会**静默降级**到安装版，
       于是「仓库版被改坏」会被报成「安装版缺判据」，归因指错对象。
    """
    out = []
    # 1) 基准源自身（永远排第一）
    out.append(("基准源", os.path.join(base, name, "SKILL.md")))
    # 2) 仓库版（若基准是 skills 根目录，则仓库在别处）
    for repo in (os.path.join(_PARENT, "agent-hygiene"), "C:\\agent-hygiene"):
        p = os.path.join(repo, "skill", name, "SKILL.md")
        if os.path.exists(p) and p not in [x[1] for x in out]:
            out.append(("仓库版", p))
    # 3) 安装副本
    for d in (".workbuddy", ".claude", ".codex"):
        p = os.path.join(HOME, d, "skills", name, "SKILL.md")
        if os.path.exists(p) and p not in [x[1] for x in out]:
            out.append(("安装版:" + d, p))
    return out


def _pick_base():
    """选基准源。

    优先选**仓库版**（`agent-hygiene/skill/`）——它是 git 管理的单一真源。
    退而求其次才用安装目录。
    理由：基准源错了，「分叉」的方向就反了——比如以安装版为基准时，
    仓库版被改坏会被报成「安装版缺判据」，归因指错对象。
    """
    repo = find_repo()
    if repo:
        cand = os.path.join(repo, "skill")
        if os.path.isdir(os.path.join(cand, "diagnostic-tool-trust")):
            return cand
    for b in _BASE_CANDIDATES:
        if os.path.isdir(os.path.join(b, "diagnostic-tool-trust")):
            return b
    return _ROOT


# ---------------------------------------------------------------- 判据清单
# 来自真实事故，不是想象的
REQUIRED = {
    "diagnostic-tool-trust": [
        "leave-one-out",
        "SOLO_HANDLES_ABS",          # 单实例下限
        "分母",                       # 百分比必须写清分母
        "字符数",                     # 字符数 != 字节数
        "缺关键键",                   # 缺证据 != 通过
        "静默降级",
        "退出码",
        "绑定采样窗口",               # 结论绑窗口
        "交叉验证",
    ],
    "long-running-sample-discipline": [
        "增量落盘",
        "JSONL",
        "flush",
        "中位数",
        "稳态",
        "持续增长",
        "突跳",
        "逐目标",
        "退出码 0",                   # 被静默回收的特征
        "nohup",
    ],
}

# 与 agent-hygiene 仓库共享的数字（手抄容易漂移 → 必须机器比对）
#
# 🔴 判据用「带上下文的正则」而不是裸子串。
#    裸子串有三个实测出来的漏报：
#    ① README 的「共享数字清单」那行本身就含全部数字 → README 正文改了也照样 PASS（平凡成立）
#    ② SKILL.md:186 的「线程数 ≥20000」是另一个含义 → 句柄下限改错也能「巧合命中」
#    ③ 语义（分母/口径）完全不在比对范围
#    → 改为「该数字必须出现在带指定上下文的句子里」，且排除元描述行。
#
# 🔴 上下文正则**必须锚定数字本身**，不能只靠邻近词组。
#    实测反例（第三方复核找出，已复现）：
#    · 191435 的 ctx 若只是 `191\s*435`，那它等于数字本身 = 零语义约束；
#    · 89.79 的 ctx 若含 `Process\s*类`，该分支与数字无关，会把无关行算成命中。
#    → 现在 ctx 统一要求「数字附近 ±ANCHOR_WINDOW 字符内出现锚词」。
#
# expect_in_skills = 应包含该数字的 Skill 名列表。
#   不在列表里的 skill 不检查（否则会误报「long-running 缺 89.79」这种本该没有的）。
SHARED_NUMBERS = [
    # (说明, 数字, 锚词正则, 仓库文件列表, 应含此数的 skill 列表)
    ("单实例句柄下限", "20000",
     r"(?:绝对下限|下限|SOLO_HANDLES_ABS|单实例组)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    # 🔴 判据标识符本身也必须存在（第三方复核指出 S6 这类漏洞，已复现）。
    #    只查「数字 + 邻近锚词」会漏：删掉 `SOLO_HANDLES_ABS` 这个**标识符**后，
    #    同一行的「单实例组」锚词还在 → 命中数不变 → 门禁照样 PASS。
    #    → 单独要求这个标识符在文件里至少出现一次。
    ("SOLO_HANDLES_ABS 标识符", "SOLO_HANDLES_ABS",
     r"(?:SOLO_HANDLES_ABS|下限)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("僵尸占 Process 类", "89.79",
     r"(?:占|Process|僵尸|分母)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("Weixin 句柄总数", "191435",
     r"(?:句柄|Weixin|handle|分母)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("早期速率", "1022",
     r"(?:个/分钟|/分钟|速率|每分钟|采样)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust", "long-running-sample-discipline"]),
    ("复核后速率", "3.2",
     r"(?:个/分钟|/分钟|速率|采样)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust", "long-running-sample-discipline"]),
    # 🔴 分母也必须在覆盖范围内（第三方复核指出）。
    #    `REQUIRED` 里明明有「分母」这条判据、SKILL.md 也把「百分比必须写清分母」列为铁律，
    #    但门禁只检查「这三个字在不在」，不检查分母本身的值 —— 口径漂移完全不在射程内。
    ("Process 类句柄数（分母）", "33012",
     r"(?:分母|Process|句柄|类)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("僵尸句柄数", "29641",
     r"(?:僵尸|已退出|指向|句柄)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
]

# 🔴 **活值数字**（living values）：会随时间增长的测量值。
#
#    这类数字**不能**用「全文取值唯一」来判 —— 同一个进程的句柄数在不同时刻
#    本来就不一样（实测 wetype_renderer: 22012 → 23192 → 23488）。
#    但它们**也不能没有出处**：文档里出现一个句柄数，读者必须能知道它是哪一次采样的。
#
#    第三方复核（opencode）指出过这个问题：README 写「2026-10-29 15:2x 采样」，
#    但日志里 15:2x 时段**根本没有运行记录** —— 那个时间标注是编的。
#
#    → 判据：每个活值数字**在文件中至少出现一次**，
#      且该数字所在行 ±CITE_WINDOW 字符内必须出现**出处标记**（时间戳 / 文档路径 / 日志行号）。
#      多个合法取值是允许的（那是事实），但**每个取值都得能追溯**。
LIVING_NUMBERS = [
    # (说明, 数字, 锚词正则, 仓库文件列表, 出处标记正则)
    ("wetype_renderer 句柄数（活值）", "22012",
     r"(?:wetype|单实例|句柄)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     r"(?:independent-review|A9|复测|采样)"),
    ("wetype_renderer 句柄数（活值）", "23192",
     r"(?:wetype|句柄|129\.6|同exe)",
     ["README.md"],
     r"(?:16:43|stuck_cleanup\.log|采样)"),
    ("wetype_renderer 句柄数（活值）", "23488",
     r"(?:wetype|句柄|119\.8|同exe)",
     ["README.md"],
     r"(?:16:56|stuck_cleanup\.log|采样)"),
]

# 活值数字的出处标记搜索窗口（字符）
CITE_WINDOW = 200

# 数字边界窗口：数字左右多少字符内必须出现锚词
ANCHOR_WINDOW = 60

# 元描述行识别：**结构性**，不靠字面短语。
# 🔴 实测反例（第三方复核找出，已复现）：
#   原来用两个字面短语（"是否仍然对得上" / "与本仓库共享的数字"）识别元描述行，
#   把其中一句改个说法 → 元描述行不再被剔除 → 它同时承载全部共享数字
#   → 成为每个数字的合法命中行 → 「平凡成立」被重新武装。
#   → 改为：**同一行里出现 ≥ META_MIN_NUMBERS 个共享数字 → 判定为元描述行**。
#      这样无论怎么改措辞，只要它还是「清单行」，就一定会被剔除。
META_MIN_NUMBERS = 3

# 元描述行的字面模式（保留作为补充判定，但**不再是唯一依据**）
META_LINE_PATTERNS = [
    r"是否仍然对得上",
    r"与本仓库共享的数字",
]

REPO_CANDIDATES = [
    "C:\\agent-hygiene",
    os.path.join(_PARENT, "agent-hygiene"),
    os.path.join(_ROOT, ".."),          # <root> 可能是 skills/ 目录，其上一级才是仓库
]


def read(path):
    if not path or not os.path.exists(path):
        return None
    try:
        return io.open(path, encoding="utf-8").read()
    except Exception:
        return None


def find_repo():
    for p in REPO_CANDIDATES:
        p = os.path.normpath(p)
        if os.path.isdir(os.path.join(p, "tools")):
            return p
    return None


def check_one(name, probes, base):
    result = {"skill": name, "issues": [], "probes": {}, "copies": {}}

    copies = _copies(name, base)
    src = None
    for idx, (label, path) in enumerate(copies):
        t = read(path)
        if t is None:
            state = "not-found" if not os.path.exists(path) else "unreadable"
            result["copies"]["%s | %s" % (label, path)] = state
            # 🔴 基准源读不出来 = 硬失败，不许静默降级到别的副本
            if idx == 0:
                result["issues"].append(
                    "基准源不可读：%s（%s）—— 不许静默降级到其它副本" % (path, state))
            continue
        result["copies"]["%s | %s" % (label, path)] = "identical"
        if src is None:
            src = t
            result["copies"]["%s | %s" % (label, path)] = "BASE"

    if src is None:
        result["issues"].append("找不到任何副本：%s" % name)
        return result

    # 1) 关键判据
    for p in probes:
        hit = p in src
        result["probes"][p] = hit
        if not hit:
            result["issues"].append("缺少关键判据：%r" % p)

    # 2) 副本一致性
    for label, path in copies:
        t = read(path)
        if t is None:
            continue
        if t != src:
            result["copies"]["%s | %s" % (label, path)] = "DIFFERS"
            delta = len(t) - len(src)
            missing = [p for p in probes if p in src and p not in t]
            result["issues"].append(
                "副本分叉：%s（%s，字符差 %+d）%s"
                % (path, label, delta,
                   ("，缺判据：%s" % ", ".join(repr(m) for m in missing)) if missing else ""))
    return result


def _num_regex(num):
    """数字的精确匹配正则。

    🔴 关键：**必须有数字边界**，且小数点**不可省略**。
    实测反例（第三方复核找出，已复现）：
      · 无边界时 `191435` 匹配 `1914350`、`20000` 匹配 `200000`
      · 小数点写成 `\\.?`（可选）时，裸 `32` 会冒充 `3.2`、裸 `8979` 会冒充 `89.79`
    → 整数：`(?<!\\d)N(?!\\d)`
      小数：`(?<!\\d)N\\s*\\.\\s*N(?!\\d)`，且允许数字内部有空格分隔（191 435 / 191.435）
    """
    if "." in num:
        a, b = num.split(".", 1)
        return r"(?<!\d)%s\s*\.\s*%s(?!\d)" % (re.escape(a), re.escape(b))
    return r"(?<!\d)%s(?!\d)" % re.escape(num)


def _find_value_variants(text, num, ctx_pat):
    """找出文中该数字的**所有不同取值写法**（用于「同一数字全文一致」检查）。

    🔴 为什么需要这个检查（第三方复核指出，已复现）：
    门禁原来只数「多少行命中」，不检查**同一个数字在全文是不是同一个值**。
    → 同一节里 L236 写 89.00%、L240 写 89.79%，两行都命中 → 门禁照样 PASS。
    → 「行数下限」抓不住这种「一处改了另一处没改」的分叉。

    🔴 关键：只比对**带上下文锚词**的那些行。
       不加这个限定会误捕：文档里 `3.1x`（倍数）、`3.4`（别的指标）会被当成「3.2 的不同写法」。
       实测踩到过：README 里的 `3.1` / `3.10` / `3.4` / `3.85` 全被误判成「3.2 的一致性冲突」。

    返回：[(该处读到的数字字符串, 行内容)]
    """
    t = _strip_meta_lines(text)
    # 找「数字附近可能带修饰」的写法：整数带 1~2 位小数、或本身带小数点
    if "." in num:
        a, b = num.split(".", 1)
        pat = r"(?<!\d)%s\s*\.\s*\d{1,2}(?!\d)" % re.escape(a)
    else:
        pat = r"(?<!\d)%s(?:\s*\.\s*\d{1,2})?(?!\d)" % re.escape(num)
    ctx_re = re.compile(ctx_pat)
    out = []
    for line in t.split("\n"):
        for m in re.finditer(pat, line):
            raw = m.group(0)
            lo = max(0, m.start() - ANCHOR_WINDOW)
            hi = min(len(line), m.end() + ANCHOR_WINDOW)
            if not ctx_re.search(line[lo:hi]):
                continue      # ← 没有锚词 = 这不是本指标的那个数，跳过
            norm = re.sub(r"\s+", "", raw)
            out.append((norm, line.strip()[:80]))
    return out


def _check_value_consistency(repo_text, label, num, rels, ctx_pat):
    """同一数字在同一文件里必须只有一个取值。

    例外：允许**同一数值**的不同写法（`191435` vs `191 435` vs `191,435`）——
    规范化后必须完全相同。
    """
    issues = []
    for rel in rels:
        t = repo_text.get(rel)
        if not t:
            continue
        variants = _find_value_variants(t, num, ctx_pat)
        norms = {}
        for norm, line in variants:
            norms.setdefault(norm, line)
        if len(norms) > 1:
            issues.append(
                "数字 %r（%s）在 %s 里有 %d 个不同取值：%s —— 同一数字必须全文一致"
                % (num, label, rel, len(norms),
                   ", ".join("%r" % k for k in sorted(norms))))
    return issues


def _check_living_values(repo_text):
    """活值数字：允许多个合法取值，但**每个取值都必须能追溯到出处**。

    🔴 为什么不能用「全文取值唯一」判（第三方复核指出，已复现）：
       `wetype_renderer` 的句柄数实测是 22012 → 23192 → 23488（同一 pid，不同时刻）。
       这是**事实**，不是漂移 → 用唯一性判会误报。
    🔴 但也不能没有出处（第三方复核同时指出，已复现）：
       README 曾写「2026-10-29 15:2x 采样」，而日志里 15:2x 时段**根本没有运行记录**——
       那个时间标注是编的。读者无法判断「23192」是哪一次采样的。
    → 判据：数字所在行 ±CITE_WINDOW 字符内必须出现出处标记
       （时间戳 / 文档路径 / 日志行号）。多个取值允许，但每个都得能追溯。
    """
    issues = []
    for label, num, ctx, rels, cite in LIVING_NUMBERS:
        num_pat = _num_regex(num)
        ctx_re = re.compile(ctx)
        cite_re = re.compile(cite)
        for rel in rels:
            t = repo_text.get(rel)
            if not t:
                issues.append("活值数字 %r（%s）在 %s 所在文件读不出来" % (num, label, rel))
                continue
            cited = 0
            total = 0
            lines = t.split("\n")
            for i, line in enumerate(lines):
                m = re.search(num_pat, line)
                if not m:
                    continue
                total += 1
                lo = max(0, m.start() - CITE_WINDOW)
                hi = min(len(line), m.end() + CITE_WINDOW)
                window = line[lo:hi]
                # 出处标记必须在本行，或在**所属段落**里。
                # 🔴 为什么要看整段而不只看前后 1 行：
                #    真实排版是「引言段写明出处 → 下面代码块贴原始输出」，
                #    出处标记在代码块**上面**若干行（实测隔了 4 行）。
                #    只看前后 1 行 → 会把这种规范写法误判成「无出处的裸数字」。
                near = _paragraph_context(lines, i)
                if not (cite_re.search(window) or cite_re.search(near)):
                    continue
                cited += 1
            if total == 0:
                issues.append(
                    "活值数字 %r（%s）在 %s 中完全没出现 —— 关键数字消失"
                    % (num, label, rel))
            elif cited == 0:
                issues.append(
                    "活值数字 %r（%s）在 %s 里有 %d 处，但**没有一处绑定出处标记**"
                    "（%s）—— 读者无法判断它是哪次采样的"
                    % (num, label, rel, total, cite))
            elif cited < total:
                issues.append(
                    "活值数字 %r（%s）在 %s 里 %d 处只有 %d 处绑定了出处标记 —— "
                    "另外 %d 处是无出处的裸数字"
                    % (num, label, rel, total, cited, total - cited))
    return issues


def _neighbor_lines(text, line):
    """取某行前后各 1 行，拼成「邻近上下文」。

    用于：出处标记写在**上一行**或**下一行**的引用块/表格脚注里的情况。
    """
    lines = text.split("\n")
    try:
        i = lines.index(line)
    except ValueError:
        return ""
    lo = max(0, i - 1)
    hi = min(len(lines), i + 2)
    return "\n".join(lines[lo:hi])


def _paragraph_context(lines, i):
    """取第 i 行**上方最近的说明段**（跨过代码围栏与空行）。

    🔴 为什么必须跨围栏：
       Markdown 的规范排版是「引言段写明出处 → 空行 → ```代码块``` 贴原始输出」。
       出处标记在引言里，裸数字在代码块里，两者在字节上隔着空行和围栏。
       实测（README L104 引言 → L108 代码块）：引言写明「2026-10-29 16:43 的真实运行」，
       代码块里是 `句柄=23192`——两者**必须**能关联上。

    步骤：
      ① 若当前行在代码围栏内 → 向上找到围栏的**开启行**；
      ② 继续向上跳过空行 / 围栏行，落到第一行正文；
      ③ 取该正文所在的那一段（到下一个空行为止）。
    """
    j = i - 1
    # ① 一路上行，跳过空行、围栏行、围栏内的内容，直到找到第一行正文。
    #    🔴 必须能跨**多层**围栏：
    #       - L108 在代码块**内**（上方是 L103 的引言段，中间隔 L105 的围栏开启）
    #       - L115 在代码块**后**的解读列表里（上方是 L110 围栏结束 + L106-109 块内内容）
    #       两种都要能关联到 L103 的说明段。
    while j >= 0:
        s = lines[j].strip()
        if s == "" or s.startswith("```"):
            j -= 1
            continue
        # 这一行是不是「围栏内的内容」？
        # 向上数围栏的奇偶性：遇到 ``` 就翻转状态
        # → 用一次扫描判断 lines[j] 是否在围栏内
        if _inside_fence(lines, j):
            j -= 1
            continue
        break
    if j < 0:
        return ""
    # ② 取该正文所在的那一段（到下一个空行为止）
    k = j
    while k < len(lines) and lines[k].strip() != "":
        k += 1
    ctx = "\n".join(lines[j:k])

    # ③ 🔴 若这一段是「代码块之后的解读列表」→ 还要关联**被解读的那个代码块**
    #    上方的引言段。实测（README L115）：
    #      L103 引言（写明出处） → L105-110 代码块 → L112-117 解读列表
    #    L115 所在段是解读列表，本身没有出处；但它解读的代码块有。
    #    → 继续向上找最近的代码块，再跨过它取其上方的引言。
    if _looks_like_commentary(lines, j):
        up = j - 1
        while up >= 0 and lines[up].strip() == "":
            up -= 1
        # up 指向代码块结束行 ```（或块内最后一行）
        while up >= 0 and not lines[up].strip().startswith("```"):
            up -= 1
        if up >= 0:
            # 找到围栏开启行
            while up >= 0:
                if lines[up].strip().startswith("```"):
                    break
                up -= 1
            if up > 0:
                lead = _paragraph_context(lines, up - 1) if up - 1 > 0 else ""
                if lead:
                    ctx = ctx + "\n" + lead
    return ctx


def _looks_like_commentary(lines, start):
    """这一段是不是「代码块之后的解读列表」。

    判据：段内**过半**的行以列表符号（- / * / 数字.）开头。
    → 实测 README L113-117 是解读列表；L103 是普通引言段（单行，不算列表）。
    """
    seg = []
    k = start
    while k < len(lines) and lines[k].strip() != "":
        seg.append(lines[k])
        k += 1
    if not seg:
        return False
    bullets = [s for s in seg if s.lstrip().startswith(("- ", "* ", "+ "))
               or re.match(r"^\s*\d+\.\s", s)]
    return len(bullets) * 2 > len(seg)


def _inside_fence(lines, idx):
    """判断 lines[idx] 是否在 Markdown 代码围栏内部。

    实现：从文件头扫到 idx，统计 ``` 的出现次数——
    奇数说明当前在围栏内（围栏是成对出现的 ``` ... ```）。
    """
    count = 0
    for i in range(idx):
        if lines[i].strip().startswith("```"):
            count += 1
    return count % 2 == 1





def _is_number_listing(line):
    """判断这一行是不是「数字清单行」（元描述行）。

    🔴 判据必须是「相邻数字之间**只隔着分隔符**」，不能只是「一行里出现了 ≥N 个共享数字」。
       实测踩过两次：
       ① `29641 个（89.79%）…33012…` 这类正文行里恰好提到 3 个共享数字，
          按「数量」判会被误当清单行剔除 → 真正的正文命中被漏掉。
       ② 正文行里数字之间夹着中文（「个里，」「＝占 Process 类」），
          而真正的清单行是 `20000 / 89.79 / 191435` 这种**纯分隔符枚举**。
       → 判据：≥META_MIN_NUMBERS 个共享数字，且**相邻数字之间只含分隔符/空白**。
    """
    shared = [n for (_, n, _, _, _) in SHARED_NUMBERS]
    spans = []
    for n in shared:
        m = re.search(_num_regex(n), line)
        if m:
            spans.append((m.start(), m.end()))
    if len(spans) < META_MIN_NUMBERS:
        return False
    spans.sort()
    # 相邻两个数字之间只允许：分隔符 / 空白 / 括号
    for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
        gap = line[e1:s2]
        if not re.fullmatch(r"[\s/、,，·\(\)（）]*", gap):
            return False
    return True


def _strip_meta_lines(text):
    """剔除「元描述行」——**结构性识别**。

    实测漏报（已复现）：README 里有一行专门列出共享数字清单，
    它本身就含全部数字 → 用子串判断时，只要这行还在，
    README 正文里的数字改成任何别的值，检查照样 PASS（平凡成立）。
    而如果只靠两个字面短语识别，**把这行改个说法**就会让平凡成立复活。

    → 现在两条判据：
      ① **连续数字清单**：一行里相邻出现 ≥META_MIN_NUMBERS 个共享数字
         （`_is_number_listing`）→ 无论怎么改措辞，只要它还是清单就一定被剔除
      ② 命中字面模式 META_LINE_PATTERNS
    """
    keep = []
    for line in text.split("\n"):
        if any(re.search(p, line) for p in META_LINE_PATTERNS):
            continue
        if _is_number_listing(line):
            continue
        keep.append(line)
    return "\n".join(keep)


def _count_number_with_context(text, num, ctx_pat):
    """统计「数字与指定上下文同现」的行数。

    🔴 关键设计（两处）：
    1) **用行数下限，不是「任意一行命中」**。
       实测漏报：README 里「20000」出现在两行。只改掉其中一行 → 另一行仍命中
       → 检查照样 PASS（平凡成立）。→ 必须要求**所有**关键上下文句都还在。
    2) **数字必须精确匹配（带边界）**，且**锚词必须在数字附近 ±ANCHOR_WINDOW 字符内**。
       实测反例：ctx 写成 `191\\s*435` 等于数字本身 = 零语义约束；
       ctx 写成 `Process\\s*类` 与数字无关，会把无关行算成命中。
    """
    t = _strip_meta_lines(text)
    num_pat = _num_regex(num)
    ctx_re = re.compile(ctx_pat)
    hits = []
    for line in t.split("\n"):
        m = re.search(num_pat, line)
        if not m:
            continue
        # 锚词必须在数字附近
        lo = max(0, m.start() - ANCHOR_WINDOW)
        hi = min(len(line), m.end() + ANCHOR_WINDOW)
        window = line[lo:hi]
        if ctx_re.search(window):
            hits.append(line.strip()[:60])
    return hits


# 每个数字在每个文件里**必须**出现的上下文句数量下限。
# 🔴 按**文件分别**设定（不是全局共用）。
#    设计要点：下限不能是「实际出现次数」（零余量 → 正常改写文风就误报），
#    也不能太低（need=1 而实际 10 次 → 改 9 处都发现不了）。
#    → 用**比例下限**：至少保留实际次数的 60%（向上取整），且至少 1。
#    → 实际次数随文档改写会变，比例下限随之浮动，不会因为多写一句就误报。
#
#    实测实际次数（2026-10-29，README 重写后）：
#      README.md            : 20000×2  89.79×2  191435×10  1022×1  3.2×2
#      skill/agent-hygiene/ : 20000×2  89.79×3  191435×8   1022×2  3.2×2
#
#    （注：191435 的实际次数里含 2 行**纯数据表行**和若干**纯分母行**，
#      这些行天然不含「句柄/Weixin」这类锚词 → 锚词命中数会少于数字出现数。
#      所以对 191435 单独给出实测命中数下限。）
MIN_CONTEXT_LINES = {
    #  (文件相对路径, 数字) -> 最少命中行数
    ("README.md", "20000"): 2,
    ("README.md", "89.79"): 2,
    ("README.md", "191435"): 8,
    ("README.md", "1022"): 1,
    ("README.md", "3.2"): 2,
    ("README.md", "33012"): 4,
    ("README.md", "29641"): 12,
    ("skill/agent-hygiene/SKILL.md", "20000"): 2,
    ("skill/agent-hygiene/SKILL.md", "89.79"): 3,
    ("skill/agent-hygiene/SKILL.md", "191435"): 8,
    ("skill/agent-hygiene/SKILL.md", "1022"): 2,
    ("skill/agent-hygiene/SKILL.md", "3.2"): 2,
    ("skill/agent-hygiene/SKILL.md", "33012"): 5,
    ("skill/agent-hygiene/SKILL.md", "29641"): 4,
}

# Skill 侧各数字必须出现的上下文句数量下限（Skill 里出现次数通常少于仓库）
MIN_SKILL_CONTEXT_LINES = {
    ("diagnostic-tool-trust", "20000"): 1,
    ("diagnostic-tool-trust", "89.79"): 1,
    ("diagnostic-tool-trust", "191435"): 1,
    ("diagnostic-tool-trust", "1022"): 1,
    ("diagnostic-tool-trust", "3.2"): 1,
    ("long-running-sample-discipline", "1022"): 1,
    ("long-running-sample-discipline", "3.2"): 1,
}


def check_shared_numbers(skills_src):
    out = {"checked": [], "issues": []}
    repo = find_repo()
    if repo is None:
        out["issues"].append("未找到 agent-hygiene 仓库 —— 这是 FAIL，不是跳过")
        out["skipped"] = True
        return out

    repo_text = {}
    for rel in ("README.md", os.path.join("skill", "agent-hygiene", "SKILL.md")):
        t = read(os.path.join(repo, rel))
        if t:
            repo_text[rel.replace(os.sep, "/")] = t
    if not repo_text:
        out["issues"].append("仓库内未读到 README.md / SKILL.md —— 这是 FAIL，不是跳过")
        out["skipped"] = True
        return out

    # skill 侧：逐文件判断（不合并）——合并会让「一个 skill 改了另一个没改」被掩盖
    for label, num, ctx, rels, expect_in in SHARED_NUMBERS:
        per_file = {}
        missing_repo = []
        for rel in rels:
            if rel not in repo_text:
                per_file[rel] = "not-read"
                missing_repo.append(rel)
                continue
            hits = _count_number_with_context(repo_text[rel], num, ctx)
            need = MIN_CONTEXT_LINES.get((rel, num), 1)
            ok = len(hits) >= need
            per_file[rel] = "%d/%d" % (len(hits), need)
            if not ok:
                missing_repo.append(rel)

        # skill 侧：只检查「应该带这个数字的 skill」
        skill_hit = {}
        skill_ok = {}
        missing_skill = []
        for n in expect_in:
            t = skills_src.get(n)
            if t is None:
                missing_skill.append(n)
                skill_hit[n] = "not-found"
                skill_ok[n] = False
                continue
            hits = _count_number_with_context(t, num, ctx)
            skill_need = MIN_SKILL_CONTEXT_LINES.get((n, num), 1)
            ok = len(hits) >= skill_need
            skill_hit[n] = "%d/%d" % (len(hits), skill_need)
            skill_ok[n] = ok
            if not ok:
                missing_skill.append(n)

        in_repo = bool(rels) and not missing_repo
        # 🔴 in_skill 必须对**布尔 ok 标志**取值，不能对 "0/1" 字符串取真值
        #    （"0/1" 是非空字符串 → 永远为真 → 汇总表与 issues 自相矛盾）
        in_skill = bool(skill_ok) and all(skill_ok.values())
        out["checked"].append({
            "label": label, "number": num,
            "in_skill": in_skill,
            "in_repo": in_repo,
            "per_file": per_file,
            "per_skill": skill_hit,
        })

        if missing_repo:
            out["issues"].append(
                "数字 %r（%s）在仓库中 %s 未以正确口径出现 —— 手抄漂移或仓库分叉"
                % (num, label, ", ".join(missing_repo)))
        if missing_skill:
            out["issues"].append(
                "数字 %r（%s）在 Skill %s 中缺失或口径不符 —— Skill 侧手抄漂移"
                % (num, label, ", ".join(missing_skill)))

        # 🔴 同一数字在文件里必须只有一个取值（「一处改了另一处没改」抓不住）
        out["issues"].extend(
            _check_value_consistency(repo_text, label, num, rels, ctx))

    # 🔴 活值数字：允许多个合法取值，但每个取值都必须绑定出处
    out["issues"].extend(_check_living_values(repo_text))
    return out


def main():
    args = sys.argv[1:]
    base = None
    if "--base" in args:
        base = args[args.index("--base") + 1]
    if not base:
        base = _pick_base()

    results = [check_one(name, probes, base) for name, probes in REQUIRED.items()]
    total = sum(len(r["issues"]) for r in results)

    skills_src = {}
    for name in REQUIRED:
        t = read(os.path.join(base, name, "SKILL.md"))
        if t:
            skills_src[name] = t
    shared = check_shared_numbers(skills_src)
    total += len(shared["issues"])

    if "--json" in args:
        print(json.dumps({"base": base, "results": results, "shared": shared, "issues": total},
                         ensure_ascii=False, indent=2))
        return 1 if total else 0

    print("=== 纪律类 Skill 一致性校验 ===")
    print("基准源根目录：%s\n" % base)
    for r in results:
        print("[%s] %s" % (r["skill"], "FAIL" if r["issues"] else "PASS"))
        for p, hit in r["probes"].items():
            print("   [%s] 判据 %s" % ("ok" if hit else "MISS", p))
        for path, state in r["copies"].items():
            mark = {"BASE": "ok", "identical": "ok", "not-found": "skip",
                    "unreadable": "!!", "DIFFERS": "!!"}.get(state, "ok")
            print("   [%s] %s -> %s" % (mark, path, state))
        for i in r["issues"]:
            print("   [!!] %s" % i)
        print()

    print("=== 3) 与 agent-hygiene 仓库的共享数字比对 ===")
    if shared.get("skipped"):
        for i in shared["issues"]:
            print("   [!!] %s" % i)
    else:
        for c in shared["checked"]:
            mark = "ok" if (c["in_skill"] and c["in_repo"]) else "!!"
            print("   [%s] %-22s %-8s skill=%s repo=%s  %s / %s"
                  % (mark, c["label"], c["number"],
                     "有" if c["in_skill"] else "无", "有" if c["in_repo"] else "无",
                     c["per_skill"], c["per_file"]))
        for i in shared["issues"]:
            print("   [!!] %s" % i)
    print()

    print("=" * 60)
    if total:
        print("VERDICT: FAIL (%d 项)" % total)
        print("修复: 把基准源 cp 到各副本路径，再重跑")
        return 1
    print("VERDICT: PASS（0 项警告）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
