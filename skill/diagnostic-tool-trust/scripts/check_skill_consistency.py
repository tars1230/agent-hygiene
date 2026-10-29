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
SHARED_NUMBERS = [
    ("单实例句柄下限", "20000", ["README.md", "skill/agent-hygiene/SKILL.md"]),
    ("僵尸占 Process 类", "89.79", ["README.md", "skill/agent-hygiene/SKILL.md"]),
    ("Weixin 句柄总数", "191435", ["README.md", "skill/agent-hygiene/SKILL.md"]),
    ("早期速率", "1022", ["README.md", "skill/agent-hygiene/SKILL.md"]),
    ("复核后速率", "3.2", ["README.md", "skill/agent-hygiene/SKILL.md"]),
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

    skill_text = "\n".join(v for v in skills_src.values() if v)

    for label, num, rels in SHARED_NUMBERS:
        in_skill = num in skill_text
        # 🔴 必须是「每个相关文件都含有」，不能用 any()。
        #    any() 会让「一个文件改了、另一个没改」被掩盖 —— 实测这正是漏报的原因：
        #    故意把 README 里的 20000 改成 99999，SKILL.md 里仍是 20000，
        #    any() 判 True → 门禁漏报。分叉必须报错。
        per_file = {}
        missing = []
        for rel in rels:
            if rel not in repo_text:
                per_file[rel] = "not-read"
                missing.append(rel)
                continue
            hit = num in repo_text[rel]
            per_file[rel] = hit
            if not hit:
                missing.append(rel)
        in_repo = bool(rels) and not missing
        out["checked"].append({
            "label": label, "number": num,
            "in_skill": in_skill, "in_repo": in_repo, "per_file": per_file,
        })
        if in_skill and missing:
            out["issues"].append(
                "数字 %r（%s）出现在 Skill 里，但仓库中 %s 已无此值 —— 手抄漂移或仓库分叉，需核对"
                % (num, label, ", ".join(missing)))
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
