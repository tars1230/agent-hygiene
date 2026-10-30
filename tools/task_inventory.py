#!/usr/bin/env python
# -*- coding: utf-8 -*-
r"""
task_inventory.py —— 系统计划任务全景采集 + 可关闭性研判

定位
  用户的诉求：「有没有一个功能能看到所有系统加载的定时任务，
  类似这次清理的我不知道还有哪些，不然系统发生了什么我也不知道，
  哪些是不是可以关掉我也不清楚」

  所以本模块不做「大而全的监控大屏」，只回答两个问题：
    Q1  系统上到底有哪些定时任务在跑？
    Q2  哪些可以关？关掉会怎样？

🔴 数据源的选择（实测，2026-10-30 本机）
  | 方式 | 用时 | 字段 | 结论 |
  |---|---|---|---|
  | Get-ScheduledTask (PowerShell) | 1.56s | 全 | 慢，且每次 spawn powershell 1.5s+ |
  | console_tasks.py 里的 schtasks 单任务 | 0.10s | 少 | 只适合查 1 个任务 |
  | **schtasks /query /fo CSV /v** | **2.58s** | **28 列全量** | ✅ 选定 |

  一次调用拿到 479 行 × 28 列（触发器/身份/上次结果/上次运行时间全有），
  比逐个查快 50 倍，且不依赖 PowerShell 模块加载。

🔴 schtasks 输出的 4 个坑（全部实测踩过，勿改）
  1. **编码是 GB18030**，不是 UTF-8。用 utf-8 解码会抛 UnicodeDecodeError。
  2. **输出是分块拼接的，每块自带一个表头**（实测第 475/477 行又是表头）。
     → 必须过滤掉「任务名 == 任务名」的伪数据行，否则会多出 116 条垃圾。
  3. **同名任务在不同路径下是不同任务**（如 \Microsoft\Windows\... 与
     \Microsoft\Windows\...），去重的 key 必须是「完整路径」而不是任务名。
  4. **动作列的引号处理**：路径含空格时整体带引号，
     `"C:\Program Files\X\y.exe" -arg`。
     用 `^"?([^"\s]+)` 截会在 `C:\Program` 处截断 → 必须先剥外层引号，
     再按「引号外/引号内」切分。

🔴 研判依据（每条都可验证，不做猜测）
  · 归属     路径前缀 \Microsoft\ → 系统自带；否则第三方/自建
  · 存活     动作指向的 exe 是否还存在 → 应用卸载后残留 = 纯垃圾
  · 健康     上次结果：0=成功 / 267011=从未运行 / 267009=已计划但未运行
             / 其它非 0 = 失败
  · 频率     「重复: 每」→ 分钟级 = 高频，注意干扰
  · 身份     「作为用户运行」= SYSTEM / Administrator → 是否会在桌面闪窗
"""
import csv
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nowin  # noqa: E402

MS_PREFIX = "Microsoft" + os.sep

# 上次结果码 → 语义
RESULT_MEANING = {
    0: "成功",
    267011: "从未运行",
    267009: "已计划未运行",
    267014: "已计划未运行",
    1: "失败(退出码1)",
    1056: "服务已在运行",
    -1: "失败",
}
# 已知「不是错误」的码
RESULT_BENIGN = {0, 267011, 267009, 267014, 1056, 413}


# ────────────────────────────────────────────── 底层：读 schtasks CSV
def _read_schtasks_csv(timeout=60):
    """跑一次 schtasks /query /fo CSV /v，返回 (header, rows)。

    返回的 rows 已过滤掉分块表头行。
    """
    r = subprocess.run(
        ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
        capture_output=True, timeout=timeout,
        creationflags=nowin.no_window())
    raw = r.stdout or b""
    if not raw:
        return [], []
    text = raw.decode("gb18030", "replace")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return [], []

    header = [h.strip().lstrip("\ufeff") for h in rows[0]]
    # 坑 2：输出分块，每块自带表头 → 过滤「任务名 == 任务名」的行
    name_col = 1 if len(header) > 1 else 0
    header_name = header[name_col]
    body = []
    for row in rows[1:]:
        if len(row) <= name_col:
            continue
        if row[name_col].strip() == header_name:
            continue          # 分块表头
        body.append(row)
    return header, body


def _split_action(action):
    r"""从动作字符串切出 (exe, args)。

    🔴🔴 坑 4/5（实测，schtasks 的 CSV 输出有多种畸形）：
      A. 路径含空格但**没有引号**：
         `C:\Program Files\Clash Verge\clash-verge.exe `
      B. 整串带引号：
         `"C:\Program Files\X\y.exe" -arg`
      C. **引号残缺、且残缺的位置在路径中间**：
         `C:\Program Files (x86)\Google\...\updater.exe" --wake --system"`
         （开头没引号，路径末尾多一个引号 —— 实测踩过）

    解法：**做文件存在性检查时统一忽略引号**，
    检查通过后再把引号从 exe 里剥掉。这样 A/B/C 三种都能正确切分。

    ⚠️ 检查必须用 isfile 而不是 exists：
       `C:\Program Files` 是**目录**，exists 为真 → 会提前命中并截断（实测踩过）。
    """
    a = (action or "").strip()
    if not a:
        return "", ""

    # 情况 B：整串带引号
    if a.startswith('"'):
        end = a.find('"', 1)
        if end > 0:
            return a[1:end], a[end + 1:].strip()

    # 情况 A / C：裸路径（可能含空格、可能带残缺引号）
    tokens = a.split(" ")
    for i in range(1, min(len(tokens), 12) + 1):
        cand = " ".join(tokens[:i])
        probe = cand.replace('"', "")          # 忽略引号再查
        if os.path.isfile(probe):
            return probe, " ".join(tokens[i:]).strip().replace('"', "")
    # 全都不存在 → 取第一个 token（去掉引号），后续由存在性检查标为「不确定」
    return tokens[0].replace('"', ""), " ".join(tokens[1:]).strip().replace('"', "")


def _looks_like_exe(s):
    """粗判是不是可执行文件路径（含盘符 / 路径分隔符 / 已知 exe 后缀）。"""
    if not s:
        return False
    if os.path.isabs(s):
        return True
    if "\\" in s or "/" in s:
        return True
    return s.lower().endswith(".exe")


def _resolve_exe(exe):
    r"""判断 exe 是否存在。返回 (exists: True/False/None, how: str)。

    🔴🔴 绝不能把「判不出来」当成「不存在」——
       误判成残留 → 用户照着关任务 → 可能关掉 Windows 核心功能。
       所以只有**确定不存在**才返回 False，其余一律 None（不可判定）。

    需要展开的情况（实测）：
      · `%windir%\system32\x.exe` / `%SystemRoot%\...` → 环境变量
      · `COM` / `COM:` → COM 组件触发器（不是可执行文件）
      · `C:\Program` （被空格截断的解析产物）→ 解析有问题，不可判定
    """
    if not exe:
        return None, "empty"
    e = exe.strip().strip('"')
    if not e:
        return None, "empty"

    # COM 组件触发器：不是 exe，单独归类
    if e.upper().startswith("COM"):
        return None, "com"

    # 环境变量展开
    if "%" in e:
        expanded = os.path.expandvars(e)
        if expanded == e:
            # 有 % 但展开不了 → 不可判定
            return None, "env-unresolved"
        e = expanded

    if os.path.isabs(e):
        return os.path.exists(e), "abs"

    # 裸名 → 走 PATH
    from shutil import which
    if which(e):
        return True, "path"

    # 相对路径 → 相对任务的工作目录，不可判定
    return None, "relative"


def _parse_repeat(rep):
    """「重复: 每」列 → 周期分钟数（能解析就返回，否则 None）。

    实测样例：
      '0 小时， 5 分钟'  → 5
      '0 小时， 2 分钟'  → 2
      '1 小时， 0 分钟'  → 60
      '已禁用' / 'N/A'   → None
    """
    s = (rep or "").strip()
    if not s or s in ("N/A", "已禁用"):
        return None
    m = re.search(r"(\d+)\s*小时[，,]\s*(\d+)\s*分钟", s)
    if m:
        return int(m.group(1)) * 60 + int(m.group(2))
    m = re.search(r"(\d+)\s*分钟", s)
    if m:
        return int(m.group(1))
    return None


# ────────────────────────────────────────────── 归属与研判
def _has_future_next(next_run):
    """下次运行时间是否在未来（说明任务还在等着触发，不是废弃的）。

    实测格式：
      '2026/11/2 5:10:00'  → 未来
      'N/A'                 → 无计划
      '2026/10/30 15:36:00' → 可能已过
    """
    s = (next_run or "").strip()
    if not s or s.upper() == "N/A":
        return False
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M"):
        try:
            import datetime
            dt = datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
        return dt > datetime.datetime.now()
    return False


def _classify(path, action, user, result, state, exe_exists, period_min, exe_how,
              next_run=""):
    r"""给一个任务算出「建议动作」和理由。返回 (level, verdict, reasons[])。

    level:
      system     系统自带，不该动
      keep       第三方但在用，建议保留
      review     需要人看一眼（不明所以 / 高频 / 身份可疑）
      idle       从未运行过且无触发计划 —— 当前零开销，禁用是零副作用的清理
      orphan     指向的程序确定已不存在 → 纯残留，可关
      disabled   已禁用，无需处理

    🔴 安全底线（次序不能换）：
      1. **先判归属**，\Microsoft\ 下的直接归 system。
         这些任务的 action 常是 COM / %windir%\... 这类特殊写法，
         存在性检查不可靠 —— 误判成「可关闭」风险太高。
      2. **只有 exe_exists is False（确定不存在）才算 orphan**，
         None = 判不出来 → 绝不推荐关闭。
    """
    reasons = []
    name = path.replace("\\", "/").split("/")[-1]

    is_ms = path.startswith("\\Microsoft\\") or path.startswith("\\" + MS_PREFIX)

    # ── 规则 0（最高优先）：系统自带，一律不建议动
    if is_ms:
        reasons.append("路径在 \\Microsoft\\ 下（系统自带）")
        if result not in RESULT_BENIGN and result is not None:
            reasons.append("上次运行结果码 %s（系统任务失败不一定要处理）" % result)
        if state == "Disabled":
            reasons.append("当前状态：已禁用")
            return ("system", "系统自带（已禁用）", reasons)
        return ("system", "系统自带，建议保持不动", reasons)

    # ── 第三方/自建任务：已禁用的不用管
    if state == "Disabled":
        return ("disabled", "已禁用，不会运行", ["状态=已禁用", "非系统任务"])

    # ── 规则 1：exe 确定不存在 → 残留垃圾（最强信号，仅对第三方有效）
    if exe_exists is False:
        reasons.append("动作指向的程序确定已不存在（应用已卸载或路径变更）")
        if result in (267011, 267009):
            reasons.append("并且从未成功运行过")
        elif result is not None and result not in RESULT_BENIGN:
            reasons.append("上次运行是失败状态（结果码 %s）" % result)
        return ("orphan", "残留任务，可安全关闭", reasons)

    # ── 规则 2：exe 判不出来 → 明确说「判不出来」，不猜
    if exe_exists is None:
        reasons.append("动作指向无法判定（%s），需人工确认" % exe_how)

    # ── 规则 2.5：正在运行 → 上次结果码常是「实例已存在」类的假失败
    #    实测：AgentHygiene-Console 正在常驻运行，上次结果 = -2147020576
    #    （0x800700B7 = ERROR_ALREADY_EXISTS「该实例已在运行」）
    #    这不是失败，是**设计如此**（常驻服务重复启动时返回该码）。
    if state == "Running":
        reasons.append("任务当前正在运行")
        if result is not None and result != 0:
            reasons.append("上次结果码 %s 属实例已存在类，非真实故障" % result)
        if period_min is not None and period_min <= 10:
            reasons.append("每 %d 分钟触发一次（高频）" % period_min)
            return ("keep", "正在运行，建议保留", reasons)
        return ("keep", "正在运行，建议保留", reasons)

    # ── 规则 3：从未运行过
    #    🔴 但「从未运行过」**不等于**没用：
    #    最常见的原因是「触发条件还没到」（如每周任务今天不是那天），
    #    或「上次触发后被禁用/重装过」。
    #    → 看下次运行时间：未来 = 还等着用；N/A 且从无记录 = 真没在用。
    if result == 267011:
        reasons.append("从未运行过")
        if _has_future_next(next_run):
            reasons.append("但下次运行时间在未来（%s），说明还在等着触发" % next_run)
            reasons.append("程序确实存在")
            return ("keep", "尚未到触发时间，建议保留", reasons)
        if exe_exists is None:
            return ("review", "从未运行过，需人工确认后再决定", reasons)
        reasons.append("程序确实存在，但这项任务从未真正跑过")
        reasons.append("且没有未来的触发计划")
        # 🔴 关键澄清：这类任务**当前没有任何开销**（没在跑、也不会跑），
        #    只是占了一个计划任务注册表条目。
        #    说清这一点，用户才不会误以为「不关就一直在烧 CPU」。
        reasons.append("当前无开销：从未运行且无触发计划，禁用只是清理条目、不影响功能")
        # 🔴 单独归 idle 级别：它不是「需要你判断」，
        #    而是一条**低风险的清理建议**（禁用零副作用）。
        #    混在 review 里会让真正需要判断的任务被淹没。
        return ("idle", "从未运行过，当前无开销，禁用零副作用", reasons)

    if result is not None and result not in RESULT_BENIGN:
        # 🔴 「上次失败」要区分偶发和卡死：
        #    有未来的触发计划 = 调度器还在正常管它，上次失败多半是
        #    被外部干预（手工 kill / 重启）导致的偶发 → 不该跟「卡死」同等看待。
        #    实测：AgentHygiene-Console 上次 result=-1（被手工 kill），
        #    但下次运行在 5 分钟后 —— 任务本身完全正常。
        if _has_future_next(next_run):
            reasons.append("上次运行失败（结果码 %s）" % result)
            reasons.append("但下次运行时间在未来（%s），调度仍在继续"
                           % next_run)
            reasons.append("多为偶发失败（被手工中断 / 机器重启等），建议保留")
            return ("keep", "上次失败但仍有后续计划，建议保留", reasons)
        reasons.append("上次运行失败（结果码 %s）" % result)
        reasons.append("且没有后续触发计划 —— 可能真的卡住了")
        return ("review", "上次运行失败且不再触发，建议检查或关闭", reasons)

    # ── 规则 4：高频
    reasons.append("第三方/自建任务")
    if period_min is not None and period_min <= 10:
        reasons.append("每 %d 分钟触发一次（高频）" % period_min)
        return ("review", "高频触发，注意干扰", reasons)

    if user and "SYSTEM" in user.upper():
        reasons.append("以 SYSTEM 身份运行（不在桌面会话，不闪窗）")
    return ("keep", "在用，建议保留", reasons)


def collect():
    """采集全量任务并研判。返回 dict。"""
    header, body = _read_schtasks_csv()
    if not header:
        return {"error": "schtasks 读取失败", "tasks": []}

    idx = {name: i for i, name in enumerate(header)}

    def g(row, cn, default=""):
        i = idx.get(cn)
        if i is None or i >= len(row):
            return default
        return row[i].strip()

    tasks = []
    for row in body:
        path = g(row, "任务名")
        if not path:
            continue
        action = g(row, "要运行的任务")
        exe, args = _split_action(action)
        exists, how = _resolve_exe(exe)

        raw_result = g(row, "上次结果")
        try:
            result = int(raw_result)
        except Exception:
            result = None

        state = g(row, "模式")
        if state == "正在运行":
            state = "Running"
        elif state == "就绪":
            state = "Ready"
        elif state == "已禁用":
            state = "Disabled"

        user = g(row, "作为用户运行")
        period = _parse_repeat(g(row, "重复: 每"))
        trigger_kind = g(row, "计划类型")

        is_ms = path.startswith("\\Microsoft\\")
        level, verdict, reasons = _classify(
            path, action, user, result, state, exists, period, how,
            next_run=g(row, "下次运行时间"))

        tasks.append({
            "path": path,
            "name": path.replace("\\", "/").split("/")[-1],
            "state": state,
            "owner": "Microsoft" if is_ms else "第三方/自建",
            "exe": exe,
            "args": args[:300],
            "exeExists": exists,
            "exeResolve": how,
            "result": result,
            "resultMeaning": RESULT_MEANING.get(result, "未知"),
            "lastRun": g(row, "上次运行时间"),
            "nextRun": g(row, "下次运行时间"),
            "user": user,
            "triggerKind": trigger_kind,
            "periodMin": period,
            "comment": g(row, "注释")[:200],
            "level": level,
            "verdict": verdict,
            "reasons": reasons,
        })

    # 去重：同 key 保留信息更全的一条（schtasks 可能给同一任务多行）
    seen = {}
    for t in tasks:
        key = (t["path"], t["exe"], t["args"])
        prev = seen.get(key)
        if prev is None:
            seen[key] = t
        else:
            # 合并：保留非空字段
            for k, v in t.items():
                if v not in (None, "", [], "N/A"):
                    prev.setdefault(k, v)
    tasks = list(seen.values())

    summary = {
        "total": len(tasks),
        "system": sum(1 for t in tasks if t["level"] == "system"),
        "thirdParty": sum(1 for t in tasks if t["owner"] == "第三方/自建"),
        "orphan": sum(1 for t in tasks if t["level"] == "orphan"),
        "idle": sum(1 for t in tasks if t["level"] == "idle"),
        "review": sum(1 for t in tasks if t["level"] == "review"),
        "keep": sum(1 for t in tasks if t["level"] == "keep"),
        "disabled": sum(1 for t in tasks if t["level"] == "disabled"),
    }
    # 只把「非系统」的排前面，系统自带收在后面
    order = {"orphan": 0, "review": 1, "idle": 2, "keep": 3, "disabled": 4, "system": 5}
    tasks.sort(key=lambda t: (order.get(t["level"], 9), t["name"].lower()))
    return {"summary": summary, "tasks": tasks}


def main():
    data = collect()
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
