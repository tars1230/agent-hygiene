#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
校验纪律类 Skill 的关键判据是否还在，且**所有副本内容一致**。

为什么需要这个门禁：
  纪律类 Skill 最容易被「写完就忘」。本项目实测过 skill 有三份副本
  （仓库版 / 安装版 / 可能的其他 agent 目录），改了其中一份不会同步另外几份，
  而且**没有任何东西会报错**。
  → 这个脚本把「关键判据还在不在 + 副本有没有分叉」变成机器可复核的。

三道检查：
  1) 关键判据是否还在（来自真实事故，不是想象的）
  2) 基准源 vs 所有副本是否逐字节一致
  3) 与 agent-hygiene 仓库的共享数字是否一致（防手抄漂移）

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
    os.path.join(_ROOT, "skill"),     # 仓库内 skill/ 目录
    os.path.join(HOME, ".workbuddy", "skills"),
    _ROOT,
]

# 每个 Skill 的所有副本路径（相对基准源 + 绝对路径）
def _copies(name, base):
    """返回 (label, path) 列表。base 是基准源根目录。"""
    out = []
    # 1) 基准源自身
    out.append(("基准源", os.path.join(base, name, "SKILL.md")))
    # 2) 仓库版（若基准是 skills 根目录，则仓库在别处）
    for repo in ("C:\\agent-hygiene", os.path.join(_PARENT, "agent-hygiene")):
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
# expect_in_skills = 应包含该数字的 Skill 名列表。
#   不在列表里的 skill 不检查（否则会误报「long-running 缺 89.79」这种本该没有的）。
SHARED_NUMBERS = [
    # (说明, 数字, 上下文正则, 仓库文件列表, 应含此数的 skill 列表)
    ("单实例句柄下限", "20000",
     r"(?:绝对下限|下限|SOLO_HANDLES_ABS|句柄\s*[≥>=]+\s*20000|单实例组用\s*20000)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("僵尸占 Process 类", "89.79",
     r"(?:89\.79\s*%|占\s*Process|Process\s*类)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("Weixin 句柄总数", "191435",
     r"(?:191\s*435|191435)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust"]),
    ("早期速率", "1022",
     r"(?:1022|1\s*022)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust", "long-running-sample-discipline"]),
    ("复核后速率", "3.2",
     r"(?:-3\.2|−3\.2|3\.2\s*个/分钟|3\.2/分钟)",
     ["README.md", "skill/agent-hygiene/SKILL.md"],
     ["diagnostic-tool-trust", "long-running-sample-discipline"]),
]

# 元描述行（含数字清单的那行）必须排除，否则检查平凡成立
META_LINE_PATTERNS = [
    r"是否仍然对得上",
    r"与本仓库共享的数字",
]

REPO_CANDIDATES = [
    r"C:\agent-hygiene",
    os.path.join(_PARENT, "agent-hygiene"),
    os.path.join(_ROOT, "..", "agent-hygiene"),
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
    for label, path in copies:
        t = read(path)
        if t is None:
            result["copies"]["%s | %s" % (label, path)] = "not-found"
            continue
        result["copies"]["%s | %s" % (label, path)] = t
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


def _strip_meta_lines(text):
    """剔除「元描述行」。

    实测漏报：README 里有一行专门列出共享数字清单（"…是否仍然对得上"），
    它本身就含全部数字 → 用子串判断时，只要这行还在，
    README 正文里的数字改成任何别的值，检查照样 PASS（平凡成立）。
    → 必须剔除，否则这个检查等于没做。
    """
    keep = []
    for line in text.split("\n"):
        if any(re.search(p, line) for p in META_LINE_PATTERNS):
            continue
        keep.append(line)
    return "\n".join(keep)


def _count_number_with_context(text, num, ctx_pat):
    """统计「数字与指定上下文同现」的行数。

    🔴 关键设计：**用行数下限，不是「任意一行命中」**。
    实测漏报：README 里「20000」出现在两行（83 行「绝对下限 20000」+ 89 行「单实例组用 20000」）。
    只改掉 83 行 → 89 行仍然命中 → 检查照样 PASS（平凡成立）。
    → 必须要求**所有**关键上下文句都还在，才能判 PASS。
    """
    t = _strip_meta_lines(text)
    num_pat = re.escape(num).replace(r"\.", r"\s*\.?\s*")
    hits = []
    for line in t.split("\n"):
        has_num = bool(re.search(num_pat, line.replace(" ", "").replace("\u00a0", ""))) \
            or bool(re.search(num_pat, line))
        if has_num and re.search(ctx_pat, line):
            hits.append(line.strip()[:60])
    return hits


# 每个数字在每个文件里**必须**出现的上下文句数量下限。
# 实测：README 的 20000 有 2 处关键上下文（83 行 + 89 行）；
#      agent-hygiene/SKILL.md 的 20000 有 2 处（46 行 + 215 行）。
#      186 行「线程数 ≥20000」是另一个含义，**不算**。
MIN_CONTEXT_LINES = {
    "20000": 2,
    "89.79": 1,
    "191435": 1,
    "1022": 1,
    "3.2": 1,
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
        out["issues"].append("未找到 agent-hygiene 仓库，跳过共享数字比对")
        out["skipped"] = True
        return out

    repo_text = {}
    for rel in ("README.md", os.path.join("skill", "agent-hygiene", "SKILL.md")):
        t = read(os.path.join(repo, rel))
        if t:
            repo_text[rel.replace(os.sep, "/")] = t
    if not repo_text:
        out["issues"].append("仓库内未读到 README.md / SKILL.md，跳过共享数字比对")
        out["skipped"] = True
        return out

    # skill 侧：逐文件判断（不合并）——合并会让「一个 skill 改了另一个没改」被掩盖
    for label, num, ctx, rels, expect_in in SHARED_NUMBERS:
        need = MIN_CONTEXT_LINES.get(num, 1)
        per_file = {}
        missing_repo = []
        for rel in rels:
            if rel not in repo_text:
                per_file[rel] = "not-read"
                missing_repo.append(rel)
                continue
            hits = _count_number_with_context(repo_text[rel], num, ctx)
            ok = len(hits) >= need
            per_file[rel] = "%d/%d" % (len(hits), need)
            if not ok:
                missing_repo.append(rel)

        # skill 侧：只检查「应该带这个数字的 skill」
        # Skill 里的出现次数通常少于仓库（下限独立设定），
        # 但**不能是 0** —— 数字整个消失也算漂移。
        skill_hit = {}
        missing_skill = []
        for n in expect_in:
            t = skills_src.get(n)
            if t is None:
                continue
            hits = _count_number_with_context(t, num, ctx)
            skill_need = MIN_SKILL_CONTEXT_LINES.get((n, num), 1)
            ok = len(hits) >= skill_need
            skill_hit[n] = "%d/%d" % (len(hits), skill_need)
            if not ok:
                missing_skill.append(n)

        in_repo = bool(rels) and not missing_repo
        out["checked"].append({
            "label": label, "number": num,
            "in_skill": any(skill_hit.values()) if skill_hit else None,
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

    if "--json" in sys.argv:
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
            mark = {"BASE": "ok", "identical": "ok", "not-found": "skip", "DIFFERS": "!!"}.get(state, "ok")
            shown = state if state in ("BASE", "identical", "not-found", "DIFFERS") else "identical"
            print("   [%s] %s -> %s" % (mark, path, shown))
        for i in r["issues"]:
            print("   [!!] %s" % i)
        print()

    print("=== 3) 与 agent-hygiene 仓库的共享数字比对 ===")
    if shared.get("skipped"):
        print("   [skip] %s" % "; ".join(shared["issues"]))
    else:
        for c in shared["checked"]:
            mark = "ok" if (c["in_skill"] and c["in_repo"]) else "!!"
            print("   [%s] %-22s %-8s skill=%s repo=%s"
                  % (mark, c["label"], c["number"],
                     "有" if c["in_skill"] else "无", "有" if c["in_repo"] else "无"))
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
