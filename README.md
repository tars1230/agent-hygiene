# Agent Hygiene

**English**: Read-only memory hygiene toolkit for Windows workstations running multiple AI agents (Electron-based IDEs/CLIs, helper services, VM sandboxes). It diagnoses, never kills. Windows 10/11 + Python 3.10+. Details below (Chinese).

---

给装了多个 AI agent（WorkBuddy / Codex / Cursor / MiniMax / opencode / cline / 各类桥接服务…）的 Windows 工作站做**内存体检与定点回收**。

它不是「内存清理器」。恰恰相反——这个项目存在的前提是我们实测推翻了主流清理工具的三类做法：

| 被证伪的做法 | 实测结论 |
|---|---|
| 定时 trim 工作集 | `SetProcessWorkingSetSize(-1,-1)` 只降 WS，**Private 一分不减**（`tools/trim_experiment.py`） |
| 「释放了 X GB」式汇报 | 释放 872.8MB 的当天，可用物理内存只涨 38MB——空出来的立刻被别的进程吃掉。**收益必须双报** |
| 「看起来占内存=泄漏=该杀」 | 一个 954MB 的 agent 进程其实正在跑任务（CPU 530 秒）。**杀错正在干活的 agent，比泄漏本身更伤** |

## 它做什么 / 不做什么

**做（只读）：**
- 内存压力（Private / Commit 口径，明说 WS 不作数）
- 进程家族 Top（按 exe 汇总，标注 Electron `--type=` 子进程结构）
- 孤儿检测（只判「renderer/gpu/utility 子进程但宿主 main 已死」）
- HCS 沙箱遗留检测（vmmem 无 worker = 已证实的泄漏模式）
- 空转 vs 在干活（GetProcessTimes 两次采样 CPU 增量）
- 与上次报告对比（家族 ΔPrivate 趋势，>300MB 且 1.5x 才标「疑似新泄漏」）

**做（会动系统，先演练后 `--apply`）：**
- 已知泄漏模式的定点回收。目前只有一个配方：**Codex 沙箱 VM 泄漏**（App 退出后 `SavedAsTemplate` 的 utility VM 永不回收，实测挂 25 小时 / 872.8MB）

**永远不做：**
- 通用「动态清理进程」/ 自动杀进程
- 定时 trim、Defender 排除省内存之类的伪优化
- 常驻后台 / 状态栏 / 轮询（体检是周级低频任务，配常驻形态是错配）

## 环境要求

- Windows 10 / 11（用了 hcsdiag、服务控制、MSIX 路径等 Win 专有机制；**Mac 版暂无**，见文末）
- Python 3.10+（仅标准库，无第三方依赖）
- 体检**不需要**管理员；「定点回收」和注册计划任务需要管理员

## 快速开始

```powershell
# 1. 体检（只读, ~30 秒, 报告写在 %LOCALAPPDATA%\agent-hygiene\reports\）
python tools\agent_hygiene_audit.py --top 15

# 2. 泄漏回收 —— 永远先演练
python tools\codex_sandbox_cleanup.py

# 3. 确认演练输出符合预期后再实清
python tools\codex_sandbox_cleanup.py --apply
```

体检报告每份都自带「与上次对比」，连续跑第二次起就能看到趋势和「疑似新泄漏」报警。

## 可选：注册计划任务

或者手动（管理员 PowerShell）：

```powershell
# 每日 05:00 + 登录后 15 分钟：回收 Codex 沙箱泄漏（需要提权）
python windows\install-tasks.ps1 -Python (Get-Command python).Source -ScriptDir <本仓库tools目录绝对路径>
```

```powershell
$py  = (Get-Command python).Source
$dir = "<本仓库 tools 目录绝对路径>"
# Codex 泄漏回收
$act  = New-ScheduledTaskAction -Execute $py -Argument ('"' + "$dir\codex_sandbox_cleanup.py" + '" --apply')
$t1   = New-ScheduledTaskTrigger -AtLogOn; $t1.Delay = "PT15M"
$t2   = New-ScheduledTaskTrigger -Daily -At 05:00
$pr   = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "CodexSandbox-Cleanup" -Action $act -Trigger @($t1,$t2) -Principal $pr -Force | Out-Null
# 每周一 05:10 体检（只读, 不需要提权）
$act2 = New-ScheduledTaskAction -Execute $py -Argument ('"' + "$dir\agent_hygiene_audit.py" + '" --top 15')
$t3   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 05:10
$pr2  = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "AgentHygiene-Weekly" -Action $act2 -Trigger $t3 -Principal $pr2 -Force | Out-Null
```

卸载：`Unregister-ScheduledTask -TaskName 'CodexSandbox-Cleanup','AgentHygiene-Weekly' -Confirm:$false`

## 安全模型

回收脚本有四道守卫，**任一命中就跳过（跳过不算失败）**：

1. 任何 Codex App 进程在跑（进程名或可执行路径含 `OpenAI.Codex`，但排除包内常驻服务）
2. 任何其他 HCS 使用者（Docker / WSL / Windows Sandbox / vmmemWSL）
3. vmmem 存活不足 2 小时（防止拆掉刚初始化的沙箱）
4. `hcsdiag list` 里 compute system 不止一个、或状态不是 `SavedAsTemplate`

回收动作是「停守护服务→等 vmmem 消失→**立刻起回服务**」两档：档 1 只影响 Codex 自己；档 2 才退到全机 `vmcompute` 停起。绝不 `Stop-Process vmmem`（会留下更脏的 HCS 状态）。

已知局限（诚实版）：守卫全部失效时最坏后果 = 正在跑的沙箱任务被掐断（该次任务失败），**不会**损坏 VBS / Credential Guard / 已装应用。装了 Docker / WSL 后守卫 2 会让清理静默跳过——宁可不清，不可清错。

## WorkBuddy / CodeBuddy 用户：Skill

`skill/agent-hygiene/SKILL.md` 是给 agent 用的说明书（铁律、工作流、配方、输出格式）。拷到 `~/.workbuddy/skills/agent-hygiene/`（或对应 skill 目录）后，对话里说「按 agent-hygiene 查一下内存」即可。

## 工具一览

| 工具 | 用途 | 权限 |
|---|---|---|
| `tools/agent_hygiene_audit.py` | 体检 + 对比报告 | 普通 |
| `tools/codex_sandbox_cleanup.py` | Codex 沙箱泄漏定点回收 | 管理员 |
| `tools/stuck_process_cleanup.py` | 挂死进程回收（explorer 线程泄漏 / git 挂死链） | 管理员 |
| `tools/hcs_ctl.py` | HCS compute system 枚举/属性（取证用） | 管理员 |
| `tools/trim_experiment.py` | 复现「trim 只降 WS 不降 Private」的实验脚本 | 普通 |

## 已验证的泄漏配方（都有真实样本）

| # | 症状 | 根因 | 处置 | 样本 |
|---|---|---|---|---|
| 1 | 内存紧张，但找不到占内存的进程 | Codex 沙箱 VM 退出不回收（`SavedAsTemplate` 孤儿，`vmmem` 872.8MB 存活 25 小时） | 停 `CodexSandboxService` → 等 `vmmem` 消失 → 起回服务 | 2026-10-22 |
| 2 | 任务栏出现关不掉的 Chromium 搜索图标 | WorkBuddy 自带 `agent-browser` 拉起的 headless Chromium 残留（16 进程 ≈984MB） | `taskkill /T` 掉 `agent-browser` 宿主 | 2026-10-28 |
| 3 | 桌面/任务栏变卡，commit 快满，但 explorer「内存」看着不大 | 第三方 shell 扩展在 explorer 里泄漏线程（96262 个线程 / 96127 个 Suspended，Private 8432MB 而 WS 只有 452MB） | 重启 `explorer.exe` | 2026-10-29 |
| 4 | 每天固定时间多出一串 git 进程且永不退出 | 计划任务里的 `git push` 因凭据提示被吞而永久挂起（8 天累积 56 进程） | `taskkill` + 修脚本（超时 + `credential.interactive=never` + 显式代理） | 2026-10-29 |

**配方 3 的关键教训**：explorer 的泄漏**在任务管理器里几乎看不见**——它的 WS 只有 452MB，看「内存」列完全正常；吃掉的是 commit。**必须看线程数/句柄数**（9.6 万线程 / 21 万句柄）。

## Mac 版？

**暂无，也不在路线图上**——不是不想做，是条件不具备：① Mac 端还没有任何真实泄漏样本（配方制没有配方就没有意义）② 与 Windows 的机制零复用（hcsdiag/服务 vs launchd/psutil），等于重写。触发条件：攒到第一个 Mac 端已验证的泄漏模式，再考虑一个 psutil 版的只读体检。

## License

MIT
