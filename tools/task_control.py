# -*- coding: utf-8 -*-
r"""
task_control.py —— 计划任务的启停（**唯一会动系统的部分**）

安全规则（不可绕过，写死在代码里，不靠前端自觉）
  1. **只允许「启用 / 禁用」**，都是可逆的：
     禁用 = 任务不再触发，但配置全保留；想恢复随时启用回来。
     本模块**不提供删除**（schtasks /delete 会连配置一起抹掉，不可逆）。
  2. **拒绝操作 \Microsoft\* 路径下的任务** ——
     那是 Windows 系统自带任务，关掉可能影响更新、证书、磁盘管理等功能。
     这条是硬拒绝，前端传什么都不放行。
  3. 每次动作写日志（logs/task-control.log），可追溯。
  4. 需要调用方显式传 confirm=True —— 防止误触/被前端自动触发。

🔴 为什么用 schtasks.exe 而不是 PowerShell
  实测（2026-10-30 本机）：
    schtasks.exe /change  →  ~0.3 秒
    Set-ScheduledTask (PowerShell) → 冷启动 1.55s + 模块加载，实测 3~5 秒
  且 schtasks 不需要提权（改自己的任务不需要管理员）。

用法
  python task_control.py set-state <任务名> <enable|disable> --confirm
"""
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nowin  # noqa: E402

LOG_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "agent-hygiene", "logs")

# 硬拒绝前缀（大小写不敏感）
FORBIDDEN_PREFIX = ("\\Microsoft\\",)

# Windows 计划任务自身的保留路径，不该出现在业务任务里
RESERVED_PREFIX = ("\\MicrosoftTaskScheduler",)


def _log(action, name, detail):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "task-control.log"), "a",
                  encoding="utf-8") as f:
            f.write("[%s] %s | %s | %s\n"
                    % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       action, name, detail))
    except Exception:
        pass


def _full_path(name):
    """任务名 → 完整路径（schtasks 的 /tn 接受 \\路径\\名字 或 名字）。"""
    n = (name or "").strip()
    if not n:
        return ""
    if n.startswith("\\"):
        return n
    return "\\" + n


def set_state(name, enable, confirm=False):
    """启用/禁用一个任务。返回 dict。"""
    full = _full_path(name)
    if not full:
        return {"ok": False, "error": "任务名为空"}

    # ── 规则 2：系统任务硬拒绝
    for p in FORBIDDEN_PREFIX:
        if full.lower().startswith(p.lower()):
            msg = "拒绝操作系统自带任务：%s" % full
            _log("reject", full, msg)
            return {"ok": False, "error": msg,
                    "reason": "系统自带任务不可在此修改"}

    for p in RESERVED_PREFIX:
        if full.lower().startswith(p.lower()):
            msg = "拒绝操作系统保留任务：%s" % full
            _log("reject", full, msg)
            return {"ok": False, "error": msg,
                    "reason": "系统保留任务不可修改"}

    # ── 规则 4：必须显式确认
    if not confirm:
        return {"ok": False, "error": "需要显式确认",
                "need_confirm": True}

    flag = "/enable" if enable else "/disable"
    try:
        r = subprocess.run(
            ["schtasks.exe", "/change", "/tn", full, flag],
            capture_output=True, timeout=30,
            creationflags=nowin.no_window())
    except Exception as e:
        _log("error", full, str(e))
        return {"ok": False, "error": str(e)}

    out = (r.stdout or b"").decode("gb18030", "replace").strip()
    err = (r.stderr or b"").decode("gb18030", "replace").strip()
    ok = r.returncode == 0

    # schtasks 成功时输出「SUCCESS: 计划任务 ... 已启用。」到 stdout
    if not ok and not out:
        out = err
    _log("enable" if enable else "disable", full,
         "ok=%s %s" % (ok, out[:160]))
    # 🔴 失败时不要报 state —— 「任务不存在」却返回 state=disabled，
    #    前端会以为「已经禁用了」，实际是啥也没改成。
    if not ok:
        return {
            "ok": False,
            "name": full,
            "message": out[:300],
            "error": (err or out)[:300] or "操作失败",
        }
    return {
        "ok": True,
        "name": full,
        "state": "enabled" if enable else "disabled",
        "message": out[:300],
        "error": None,
    }


def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "用法: set-state <名称> <enable|disable> --confirm"},
                         ensure_ascii=False))
        return 1
    name = sys.argv[2]
    action = sys.argv[3].lower()
    confirm = "--confirm" in sys.argv[4:]
    if action not in ("enable", "disable"):
        print(json.dumps({"error": "动作只能是 enable 或 disable"},
                         ensure_ascii=False))
        return 1
    r = set_state(name, action == "enable", confirm=confirm)
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
