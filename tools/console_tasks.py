#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
console_tasks.py —— 计划任务的读 / 改（隔离 PowerShell 调用）

为什么单独一个模块
  任务管理必须用 PowerShell（Get-ScheduledTask / Set-ScheduledTask），
  这是**低频且需要提权**的操作，不能混进高频采样路径。
  独立成进程 = 后端可以放心用 subprocess 调它，出错也不会带崩服务。

支持的动作：
  list                 列出本项目相关的三个任务及其完整配置
  set-trigger <名称> <触发器> [时间]
        触发器 = daily | weekly | logon
  set-arg <名称> <完整参数字符串>
        ⚠️ 改参数意味着改「会不会真的动手」——见下方安全规则

🔴 安全规则（不可绕过）
  · 只允许操作 TASKS 白名单里的三个任务，其他一律拒绝。
  · 改参数时**不允许**凭空加 `--kill-handle-leak`——
    那是「会杀微信」的开关，属于不可逆动作，必须由用户在界面上明确勾选后，
    才由本模块显式传入 `--allow-kill-switch` 才生效。
  · 每次改动都写日志到 logs/tasks.log，可追溯。
"""
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# 🔴 与 console_backend 同理：不能只靠 os.environ.get("LOCALAPPDATA")，
#    IDE 托管 bash / 计划任务上下文里该变量可能是 None -> 日志会落错目录。
from agent_hygiene_audit import _local_appdata  # noqa: E402
import nowin  # noqa: E402

LOG_DIR = os.path.join(_local_appdata(), "agent-hygiene", "logs")

TASKS = ["AgentHygiene-Weekly", "CodexSandbox-Cleanup", "StuckProcess-Cleanup"]

PS = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _run_schtasks_pairs(name):
    """用 schtasks.exe 查单个任务，返回 {"pairs": [(key, value), ...]}。

    🔴 为什么不用 Get-ScheduledTask
      实测（2026-10-30 本机，同一台机器同一时刻）：
        Get-ScheduledTask 单任务 5.23 秒
        COM Schedule.Service    3.27 秒
        schtasks.exe /query       0.10 秒   ← 快了 52 倍
      差距来自 PowerShell 自身的模块加载（裸启动就要 1.55 秒）。
      本地控制台首屏要读 3 个任务，用 Get-ScheduledTask 就是 15 秒起，
      用户体验上等于「卡住了」。

    🔴 schtasks 输出是 **GBK**（本机中文 Windows），不是 UTF-8。
      直接 decode('utf-8') 会抛 UnicodeDecodeError。

    🔴 返回 list 而不是 dict：一个任务可能有多个触发器，
       schtasks 会重复输出「计划类型」「开始时间」等字段，
       用 dict 存会把前一个触发器覆盖掉（实测 CodexSandbox-Cleanup
       同时有「登陆时」和「每天」两个触发器，被覆盖后只剩一个）。
    """
    try:
        r = subprocess.run(
            ["schtasks.exe", "/query", "/tn", name, "/fo", "LIST", "/v"],
            capture_output=True, timeout=30,
            creationflags=nowin.no_window())
    except Exception:
        return None
    raw = r.stdout or b""
    if not raw:
        return None
    text = None
    for enc in ("gb18030", "gbk", "utf-8"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        return None
    pairs = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        pairs.append((k.strip(), v.strip()))
    if not pairs:
        return None
    return {"pairs": pairs}


# schtasks 中文输出 -> 本项目统一字段名
# 🔴 字段名是「计划类型」不是「计划」。「计划」那行是「计划数据在此格式中不可用。」
# 🔴 「登陆时」是 schtasks 的用字（不是「登录时」）
_ST_KIND = {"每天": "Daily", "每周": "Weekly", "登陆时": "Logon",
            "登录时": "Logon", "一次性": "Once"}
_ST_MODE = {"就绪": "Ready", "运行中": "Running", "正在运行": "Running",
            "已计划": "Ready", "禁用": "Disabled", "已禁用": "Disabled",
            "未计划": "Ready"}


def list_tasks_schtasks():
    """用 schtasks 列三个任务。

    🔴 schtasks 的 LIST 格式**一个任务可能有多个触发器**，
       表现为「计划类型」「开始时间」等字段**重复出现**
       （实测 CodexSandbox-Cleanup 同时有「登陆时」和「每天」两个触发器）。
       所以不能用 dict 存——后者会把前一个覆盖掉。
       这里改存 list[(key, value)]，同名 key 全部保留。
    """
    out = []
    for n in TASKS:
        d = _run_schtasks_pairs(n)
        if not d:
            out.append({"Name": n, "Missing": True, "State": "Missing",
                        "Triggers": [], "LastResult": None})
            continue
        pairs = d["pairs"]
        first = {}
        for k, v in pairs:
            first.setdefault(k, v)

        trigs = []
        # 逐个触发器：LIST 里「计划类型」与「开始时间」成对出现
        kinds = [(i, v) for i, (k, v) in enumerate(pairs) if k == "计划类型"]
        starts = [(i, v) for i, (k, v) in enumerate(pairs) if k == "开始时间"]
        for idx, (ki, kv) in enumerate(kinds):
            kind = "Logon"
            for kk, vv in _ST_KIND.items():
                if kk in kv:
                    kind = vv
                    break
            at = "登录时"
            if kind != "Logon":
                nxt = [sv for si, sv in starts if si > ki]
                # 🔴 时间取值不能靠 [:5] 切片：
                #    '6:00:00'[:5] == '6:00:'（带尾冒号），count(':')==2，
                #    结果会误判为「格式不对」而回退到默认 05:10
                #    —— 实测就是这么把 06:00 的任务读成 05:10 的。
                #    正确做法：按 ':' 切分取前两段再拼。
                if nxt:
                    seg = nxt[0].split(":")
                    if len(seg) >= 2 and seg[0].isdigit() and seg[1].isdigit():
                        at = "%02d:%02d" % (int(seg[0]), int(seg[1]))
                    else:
                        at = "05:10"
                else:
                    at = "05:10"
            trigs.append({"Kind": "MSFT_Task%sTrigger" % kind, "At": at})

        args = first.get("要运行的任务") or first.get("Task To Run") or ""
        exe = args
        argstr = ""
        if PY_EXE and PY_EXE in args:
            exe = PY_EXE
            argstr = args.split(PY_EXE, 1)[1].strip()

        last = first.get("上次运行时间") or first.get("Last Run Time") or ""
        nxt = first.get("下次运行时间") or first.get("Next Run Time") or ""
        res = first.get("上次结果") or first.get("Last Result") or "0"
        try:
            res = int(res)
        except Exception:
            res = None

        # 🔴 身份不能硬编码。实测 2026-10-30：这几个任务早已改成 SYSTEM 运行，
        #    但这里一直写死 UserId=os.environ["USERNAME"] / LogonType="Interactive"，
        #    面板上显示的运行身份是错的（会误导判断「是否在桌面会话弹窗」）。
        #    schtasks 的 LIST 输出里「作为用户运行」才是真值，直接读它。
        user_id = (first.get("作为用户运行") or first.get("Run As User") or "").strip()
        if not user_id:
            user_id = os.environ.get("USERNAME", "")
        logon_type = "Interactive"
        if user_id.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "S-1-5-18"):
            logon_type = "ServiceAccount"

        out.append({
            "Name": n, "Missing": False,
            "State": _ST_MODE.get(first.get("模式") or "",
                                  first.get("模式") or "Ready"),
            "LastRun": last, "NextRun": nxt, "LastResult": res,
            "Execute": exe, "Arguments": argstr,
            "UserId": user_id,
            "LogonType": logon_type,
            "Triggers": trigs,
        })
    for t in out:
        args = t.get("Arguments") or ""
        t["has_kill_switch"] = "--kill-handle-leak" in args
        t["kill_switch_effect"] = (
            "已开启：每天会自动终止句柄泄漏进程（会丢登录态）" if t["has_kill_switch"]
            else "未开启：只报告，不会杀任何进程")
    return {"tasks": out}

# 🔴 任务动作（要改的其实是 Trigger，不是 Action；Action 里带的是 --apply）
ACTION_ARGS = {
    "AgentHygiene-Weekly": '"C:\\agent-hygiene\\tools\\agent_hygiene_audit.py" --top 15',
    "CodexSandbox-Cleanup": '"C:\\agent-hygiene\\tools\\codex_sandbox_cleanup.py" --apply',
    "StuckProcess-Cleanup": '"C:\\agent-hygiene\\tools\\stuck_process_cleanup.py" --apply --sample-sec 3',
}

PY_EXE = os.path.join(
    os.environ.get("USERPROFILE", ""), ".workbuddy", "binaries", "python",
    "versions", "3.13.12", "python.exe")


def _run_ps(script, timeout=60):
    try:
        r = subprocess.run([PS, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=timeout,
                           creationflags=nowin.no_window())
        return (r.stdout or b"").decode("utf-8", "replace").strip()
    except Exception as e:
        return json.dumps({"error": str(e)})


def list_tasks():
    """列出三个任务的完整配置。

    🔴 默认走 schtasks（快 52 倍），PowerShell 版本保留为兜底
       （schtasks 在部分 Windows 版本的字段名上不一致时用）。
    """
    data = list_tasks_schtasks()
    if data.get("tasks") and all(t.get("Missing") for t in data["tasks"]):
        data = list_tasks_powershell()
    return data


def list_tasks_powershell():
    """PowerShell 版（兜底）。慢，但字段最准。"""
    names = ",".join("'%s'" % t for t in TASKS)
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "$r = @(); "
        "foreach ($n in @(%s)) { "
        "  $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; "
        "  if (-not $t) { $r += [PSCustomObject]@{ Name=$n; Missing=$true }; continue } "
        "  $i = Get-ScheduledTaskInfo -TaskName $n -ErrorAction SilentlyContinue; "
        "  $a = $t.Actions[0]; "
        "  $trigs = @(); "
        "  foreach ($tr in $t.Triggers) { "
        "    $kind = $tr.CimClass.CimClassName; "
        "    $at = ''; "
        "    if ($tr.StartBoundary) { $at = ([datetime]$tr.StartBoundary).ToString('HH:mm') } "
        "    if ($kind -eq 'MSFT_TaskLogonTrigger') { $at = '登录时' } "
        "    $trigs += [PSCustomObject]@{ Kind=$kind; At=$at } "
        "  } "
        "  $r += [PSCustomObject]@{ "
        "    Name=$n; Missing=$false; State=[string]$t.State; "
        "    LastRun=[string]$i.LastRunTime; NextRun=[string]$i.NextRunTime; "
        "    LastResult=[int]$i.LastTaskResult; "
        "    Execute=$a.Execute; Arguments=$a.Arguments; "
        "    UserId=[string]$t.Principal.UserId; "
        "    LogonType=[string]$t.Principal.LogonType; "
        "    Triggers=$trigs } "
        "}; "
        "$r | ConvertTo-Json -Compress -Depth 4"
    ) % names
    out = _run_ps(script)
    try:
        data = json.loads(out or "[]")
    except Exception:
        return {"error": "解析失败", "raw": out[:500], "tasks": []}
    if isinstance(data, dict):
        data = [data]
    for t in data:
        t.setdefault("Missing", False)
        t.setdefault("Triggers", [])
        # 🔴 标出「当前参数里有没有那个会杀进程的开关」
        args = t.get("Arguments") or ""
        t["has_kill_switch"] = "--kill-handle-leak" in args
        t["kill_switch_effect"] = (
            "已开启：每天会自动终止句柄泄漏进程（会丢登录态）" if t["has_kill_switch"]
            else "未开启：只报告，不会杀任何进程")
    return {"tasks": data}


def set_trigger(name, kind, at=None):
    """改触发器。kind = daily | weekly | logon。"""
    if name not in TASKS:
        return {"error": "不在白名单内：%s" % name}
    if kind not in ("daily", "weekly", "logon"):
        return {"error": "触发器只能是 daily / weekly / logon"}
    if kind == "logon":
        new_trig = ("$trig = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME")
    else:
        hh, mm = (at or "05:10").split(":")
        hh, mm = int(hh), int(mm)
        if kind == "daily":
            new_trig = ("$trig = New-ScheduledTaskTrigger -Daily -At "
                        "'%02d:%02d'" % (hh, mm))
        else:
            new_trig = ("$trig = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday "
                        "-At '%02d:%02d'" % (hh, mm))
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "$t = Get-ScheduledTask -TaskName '%s'; "
        "%s "
        "$a = $t.Actions; "
        "Set-ScheduledTask -TaskName '%s' -Trigger $trig -Action $a | Out-Null; "
        "'OK'" % (name, new_trig, name)
    )
    out = _run_ps(script)
    ok = out.strip() == "OK"
    _log("set-trigger", name, "kind=%s at=%s -> %s" % (kind, at, "OK" if ok else out[:200]))
    return {"ok": ok, "name": name, "kind": kind, "at": at, "raw": out[:300]}


def set_args(name, args, allow_kill_switch=False):
    """改任务参数。

    🔴 安全规则：若新参数里含 `--kill-handle-leak` 而调用方没显式
       传 allow_kill_switch=True，直接拒绝。
       理由：这个开关会让每天的任务**真的杀掉微信**（丢登录态/未发消息），
       属于不可逆动作，不能被一个手滑的参数改写触发。
    """
    if name not in TASKS:
        return {"error": "不在白名单内：%s" % name}
    if "--kill-handle-leak" in args and not allow_kill_switch:
        return {"error": "拒绝：--kill-handle-leak 会真的终止进程（不可逆）。"
                         "需要用户明确勾选后重试。",
                "need_explicit_confirm": True}
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "$t = Get-ScheduledTask -TaskName '%s'; "
        "$a = New-ScheduledTaskAction -Execute '%s' -Argument '%s'; "
        "Set-ScheduledTask -TaskName '%s' -Action $a | Out-Null; "
        "'OK'" % (name, PY_EXE, args.replace("'", "''"), name)
    )
    out = _run_ps(script)
    ok = out.strip() == "OK"
    _log("set-args", name, "%s -> %s" % (ACTION_ARGS.get(name), args))
    return {"ok": ok, "name": name, "args": args, "raw": out[:300]}


def _log(action, name, detail):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "tasks.log"), "a", encoding="utf-8") as f:
            f.write("[%s] %s | %s | %s\n"
                    % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       action, name, detail))
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "用法: list | set-trigger | set-args"}, ensure_ascii=False))
        return 1
    cmd = sys.argv[1]
    if cmd == "list":
        print(json.dumps(list_tasks(), ensure_ascii=False))
    elif cmd == "set-trigger":
        if len(sys.argv) < 4:
            print(json.dumps({"error": "用法: set-trigger <名称> <daily|weekly|logon> [HH:mm]"},
                             ensure_ascii=False))
            return 1
        at = sys.argv[4] if len(sys.argv) > 4 else None
        print(json.dumps(set_trigger(sys.argv[2], sys.argv[3], at), ensure_ascii=False))
    elif cmd == "set-args":
        if len(sys.argv) < 4:
            print(json.dumps({"error": "用法: set-args <名称> <参数> [--allow-kill-switch]"},
                             ensure_ascii=False))
            return 1
        allow = "--allow-kill-switch" in sys.argv[4:]
        print(json.dumps(set_args(sys.argv[2], sys.argv[3], allow), ensure_ascii=False))
    else:
        print(json.dumps({"error": "未知命令"}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
