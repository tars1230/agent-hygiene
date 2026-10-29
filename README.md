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
| 「句柄数 > 3000 就是句柄泄漏」 | 实测 System 9142 / msedge 8777 / WeChatAppEx 8354 全是正常的。**必须看「相对同 exe 中位数的倍数」** |

## 它做什么 / 不做什么

**做（只读）：**
- 内存压力（Private / Commit 口径，明说 WS 不作数）
- 进程家族 Top（按 exe 汇总，标注 Electron `--type=` 子进程结构）
- **线程 / 句柄维度**（独立于 Private 排序，见下）
- 孤儿检测（只判「renderer/gpu/utility 子进程但宿主 main 已死」）
- HCS 沙箱遗留检测（vmmem 无 worker = 已证实的泄漏模式）
- 空转 vs 在干活（GetProcessTimes 多次采样 CPU 总增量）
- 与上次报告对比（家族 ΔPrivate 趋势，>300MB 且 1.5x 才标「疑似新泄漏」）

**做（会动系统，先演练后 `--apply`）：**
- 已知泄漏模式的定点回收，三个配方：Codex 沙箱 VM、explorer 线程泄漏、挂死命令行链、句柄泄漏

**永远不做：**
- 通用「动态清理进程」/ 自动杀进程
- 定时 trim、Defender 排除省内存之类的伪优化
- 常驻后台 / 状态栏 / 轮询（体检是周级低频任务，配常驻形态是错配）

## 线程 / 句柄维度（这一节是本项目与所有同类工具的关键差异）

**上一版工具只按 Private 排序，结果漏掉了整整一类泄漏。**

实测样本：Weixin 主进程持有 **177790 个句柄**，而它的 Private 只有 **567MB** —— 在任务管理器里看着完全正常。但句柄吃的是**内核对象表**，耗尽后 `CreateProcess` / `CreateFile` 会全失败。

所以体检报告把「线程 / 句柄」**单列一维**，并且用两个判据：

**① Suspended 线程占比**——最强判别信号

| 进程 | 线程数 | Suspended | 占比 |
|---|---|---|---|
| explorer（泄漏样本） | 96262 | 96127 | **99.85%** |
| System | 325 | 12 | 3.85% |
| Weixin / msedge / GameViewer 等正常进程 | ≤134 | 0 | **0%** |

**② 相对同 exe 中位数的倍数**——消掉固定阈值的误报

同一台机器上实测：

| 进程 | 句柄数 | 同 exe 中位数 | 倍数 | 判定 |
|---|---|---|---|---|
| Weixin 主进程 | 177790 | 243 | **731.6x** | 异常 |
| WorkBuddy 宿主 | 51527 | 336 | 153.4x | 异常，但 **CPU 5.8% 在干活 → 不能杀** |
| System | 9142 | — | — | 正常 |
| msedge | 8777 | — | — | 正常 |
| WeChatAppEx | 8354 | — | — | 正常 |

全表 616 个进程里，只有 Weixin 主进程同时满足「句柄 ≥50000」和「≥20 倍中位数」。

**🔴 倍数判据的例外：同 exe 只有一个实例时它会失效**

同 exe 只有 1 个实例时，**中位数 == 它自己，倍数恒为 1.0**，这道防线完全失灵。
实测本机 **80 个 exe 是单实例**，其中 `wetype_renderer` 持 **21724 个句柄** —— 按「≥20 倍」永远查不出来。

正确做法：**单实例组（n==1）退回「绝对阈值 + 全局中位数倍数」**，报告里 `参照系` 列会标成「全局中位数」。

🔴 **兜底参照系不能用高分位**：实测 P99.9 在 539 个进程上等于**最大值本身**（被 Weixin 这类离群值污染），
拿它当基准等于「和最大值比」= 恒为 1.0，毫无意义。用**全局中位数**才有判别力。

修正后实测（把绝对阈值临时降到 10000 验证单实例路径）：

```
[handle] pid=28208  Weixin              handles=190829  burst=785.3x  basis=同exe中位数  peer_count=5
[handle] pid=404204 WorkBuddy           handles=55863   burst=166.3x  basis=同exe中位数  peer_count=29
[handle] pid=11788  wetype_renderer     handles=21722   burst=100.6x  basis=全局中位数    peer_count=1  ← 修正前漏报
[handle] pid=3828   MaintenanceService  handles=12814   burst=59.3x   basis=全局中位数    peer_count=1  ← 修正前漏报
```

**③ 交叉验证 CPU 总增量**——区分「在干活」与「泄漏」

判据必须三合一：**句柄/线程异常 + CPU≈0 + 存活时间长** → 才值得动。
（实测 Weixin 3 秒窗内偶发 CPU 突发 38%，但 16 秒总增量只有 3.4%——所以判「在干活」要用**总增量**而不是单窗峰值。）

## 句柄类型分解（把「句柄多」变成可行动的根因）

**这一节是本项目最硬的能力，也是所有同类工具都没有的。**

竞品最多能告诉你「这个进程句柄很多」。本项目能告诉你：**是哪类句柄、泄漏源是哪些已退出的 pid、被多少个进程分摊**。

实测 Weixin 主进程 178033 个句柄，分解后：

| 句柄类型 | 数量 | 占比 |
|---|---|---|
| Event | 80849 | 45.4% |
| Token | 61193 | 34.4% |
| Process | 30632 | 17.2% |
| Key | 3752 | 2.1% |
| 其余 | 601 | 0.3% |

再往下挖，得到三个硬结论：

- **Process 句柄 30632 个里，29641 个（96.8%）指向「已退出」的进程**，泄漏源只有 3 个 pid：`13092 / 20764 / 425444`
- **Token 61193 个全部是同一个用户 `TARS\Administrator` 的重复副本**（LUID 全同 = `6fa1c`）
- 全系统扫描（`handle64 -a`，465055 个句柄）确认：这 3 个 pid 被 **15+ 个互不相关的进程**同时持有僵尸句柄，合计 43076 个

**pid 13092 就是那个 explorer.exe 线程泄漏样本**（Private 8436.5MB / 96127 个 Suspended 线程）。它崩溃退出后，多个子进程各留了一份指向它的句柄。

比例验证：**每个僵尸进程对应约 6 个泄漏句柄**（1 Process + 2 Token + 3 Event），合计 172674 / 178033 = **97%**。

> **结论翻转**：只看句柄数 → 「Weixin 有问题，杀了吧」。
> 分解到类型层 → 「**explorer 泄漏崩溃的连带后果，治本在 explorer + 重启 Weixin**」。
> 这个结论不可能从任何竞品的输出里得到。

时间序列实测（每分钟采样，16 分钟）：

| 时段 | Weixin 主进程句柄 |
|---|---|
| 00–06 分 | 178028 → 178030（**完全平坦**） |
| 07 分 | 178072 → **180125**（+2053 突跳） |
| 09–15 分 | 180800 → **186930**（稳定 **+675/分钟**） |

→ **不是稳态高水位，是「间歇性突跳 + 稳定线性增长」。**

🔴 两次分解对比定位增长源：`Event +3001 / Token +2356 / Process +1178`，
Δ 比例 = **2.55 : 2.00 : 1.00**（与「每泄漏 1 个 Process 配套 2 Token + 3 Event」的规律一致）；
而**僵尸句柄总数三次采样恒为 29641（完全不变）** → 增长全部来自**存活子进程**的句柄。

**处置含义**：重启 Weixin 只能回收**存量**；治本要关掉触发频繁创建的行为（小程序容器 / 插件进程）。

🔴 **方法论教训**：只看前 7 分钟会写成「稳态高水位，重启即可回收」——**结论完全相反**。
判断「是否还在增长」必须采样 ≥15 分钟以覆盖突跳周期，并做两次类型分解对比。

**用法**：

```bash
# 手动分解某个进程
python tools/handle_type_breakdown.py 28208

# 连续采样并对比，定位「增长源」（判稳态 vs 持续增长）
python tools/handle_type_breakdown.py 28208 --diff --interval 60 --rounds 10

# 或随体检自动跑（报告第 4c 节，只对句柄异常候选跑）
python tools/agent_hygiene_audit.py --top 15
```

`--diff` 模式输出逐段增量 + 首尾对比 + Δ 比例，并自动给出判读。
实测输出（Weixin pid 28208，4 轮 × 45 秒）：

```
[0] 总句柄=187006   僵尸=29641    类型: Event=84982 Token=64395 Process=32233
[1] 总句柄=188012   僵尸=29641    类型: Event=85445 Token=64761 Process=32416
[2] 总句柄=188808   僵尸=29641    类型: Event=85810 Token=65047 Process=32559
[3] 总句柄=188794   僵尸=29641    类型: Event=85806 Token=65047 Process=32559

  总句柄: 187006 -> 188794  (+1788)
  僵尸句柄(指向已退出进程): 29641 -> 29641  (+0)

  🔴 判读: **僵尸句柄数不变，但总数在涨** -> 增长源是**存活对象**的句柄
  Δ 比例（以 Process 为基准）: Event 2.53 / Token 2.00
```

**⚠️ 必须注意的坑**：Sysinternals Handle **默认只列「有名字」的句柄**。实测 Weixin 主进程真实 178033 个句柄，
`handle64.exe -p <pid>`（默认）只输出 **487 行**，最大句柄值仅到 `0xFB4`(4020) —— 看着像句柄很少，
实际是**只枚举了前 4020 号槽位**。必须加 `-a`，并用 `Get-Process` 的 HandleCount **交叉校验行数**。

**依赖**：Sysinternals Handle（Microsoft，EULA 接受后使用）。放到 `_vendor/Handle/handle64.exe`，
或设环境变量 `AGENT_HYGIENE_HANDLE_EXE` 指向它。未安装时体检报告会显示 `[skip]` 并给出下载指引，其余功能不受影响。

## 环境要求

- Windows 10 / 11（用了 hcsdiag、服务控制、MSIX 路径等 Win 专有机制；**Mac 版暂无**，见文末）
- Python 3.10+（仅标准库，无第三方依赖）
- 体检**不需要**管理员；「定点回收」和注册计划任务需要管理员

## 快速开始

```powershell
# 1. 体检（只读, ~30 秒, 报告写在 %LOCALAPPDATA%\agent-hygiene\reports\）
python tools\agent_hygiene_audit.py --top 15

# 2. 只看线程 / 句柄维度（~1 秒, 一次 Get-Process 取全表）
python tools\thread_handle_probe.py --self-test

# 3. 泄漏回收 —— 永远先演练
python tools\stuck_process_cleanup.py

# 4. 确认演练输出符合预期后再实清
python tools\stuck_process_cleanup.py --apply
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

卸载：`Unregister-ScheduledTask -TaskName 'CodexSandbox-Cleanup','AgentHygiene-Weekly','StuckProcess-Cleanup' -Confirm:$false`

## 安全模型

回收脚本有多道守卫，**任一命中就跳过（跳过不算失败）**：

1. 任何 Codex App 进程在跑（进程名或可执行路径含 `OpenAI.Codex`，但排除包内常驻服务）
2. 任何其他 HCS 使用者（Docker / WSL / Windows Sandbox / vmmemWSL）
3. vmmem 存活不足 2 小时（防止拆掉刚初始化的沙箱）
4. `hcsdiag list` 里 compute system 不止一个、或状态不是 `SavedAsTemplate`
5. **CPU 总增量 ≥1% = 在干活，一律跳过**（实测守住了 WorkBuddy 宿主 51527 句柄 / 5.8% CPU 的误杀风险）

已知局限（诚实版）：守卫全部失效时最坏后果 = 正在跑的沙箱任务被掐断（该次任务失败），**不会**损坏 VBS / Credential Guard / 已装应用。装了 Docker / WSL 后守卫 2 会让清理静默跳过——宁可不清，不可清错。

🔴 **句柄泄漏配方默认只报告不杀**：杀 explorer 只是关掉文件夹窗口（可恢复），
杀 Weixin 主进程会丢失**登录态 / 未发送消息 / 小程序容器**（不可逆）。要真杀必须显式加 `--kill-handle-leak`。

## WorkBuddy / CodeBuddy 用户：Skill

`skill/agent-hygiene/SKILL.md` 是给 agent 用的说明书（铁律、工作流、配方、竞品对比、输出格式）。拷到 `~/.workbuddy/skills/agent-hygiene/`（或对应 skill 目录）后，对话里说「按 agent-hygiene 查一下内存」即可。

## 工具一览

| 工具 | 用途 | 权限 |
|---|---|---|
| `tools/agent_hygiene_audit.py` | 体检 + 线程/句柄维度 + 对比报告 | 普通 |
| `tools/thread_handle_probe.py` | 线程/句柄探测（中位数倍数判据） | 普通 |
| `tools/handle_type_breakdown.py` | 句柄**类型分解**（Event/Token/Process… + 僵尸进程句柄定位） | 普通（需 Sysinternals Handle） |
| `tools/codex_sandbox_cleanup.py` | Codex 沙箱泄漏定点回收 | 管理员 |
| `tools/stuck_process_cleanup.py` | 挂死进程回收（explorer / 挂死命令行链 / 句柄泄漏） | 管理员 |
| `tools/hcs_ctl.py` | HCS compute system 枚举/属性（取证用） | 管理员 |
| `tools/trim_experiment.py` | 复现「trim 只降 WS 不降 Private」的实验脚本 | 普通 |

## 已验证的泄漏配方（都有真实样本）

| # | 症状 | 根因 | 处置 | 样本 |
|---|---|---|---|---|
| 1 | 内存紧张，但找不到占内存的进程 | Codex 沙箱 VM 退出不回收（`SavedAsTemplate` 孤儿，`vmmem` 872.8MB 存活 25 小时） | 停 `CodexSandboxService` → 等 `vmmem` 消失 → 起回服务 | 2026-10-22 |
| 2 | 任务栏出现关不掉的 Chromium 搜索图标 | WorkBuddy 自带 `agent-browser` 拉起的 headless Chromium 残留（16 进程 ≈984MB） | `taskkill /T` 掉 `agent-browser` 宿主 | 2026-10-28 |
| 3 | 桌面/任务栏变卡，commit 快满，但 explorer「内存」看着不大 | 第三方 shell 扩展在 explorer 里泄漏线程（96262 个线程 / 96127 个 Suspended，Private 8432MB 而 WS 只有 452MB） | 重启 `explorer.exe` | 2026-10-29 |
| 4 | 每天固定时间多出一串 git 进程且永不退出 | 计划任务里的 `git push` 因凭据提示被吞而永久挂起（8 天累积 56 进程） | `taskkill` + 修脚本（超时 + `credential.interactive=never` + 显式代理） | 2026-10-29 |
| 5 | 内存看着正常，但某进程句柄数 17 万 | Weixin 主进程句柄累积未释放（178033 句柄 = 同 exe 中位数 243 的 **732.6 倍**，存活 188 小时）。**分解到类型层后定根因**：29641 个僵尸 Process 句柄指向已退出的 explorer（pid 13092），连带 61193 个重复 Token + 80849 个 Event，占总数 97% | 治本 = 重启 explorer 消掉泄漏源；Weixin 侧默认只报告，`--kill-handle-leak` 才动手 | 2026-10-29 |
| 6 | playwright 浏览器下载完 3.1GB 但进程不退 | `playwright-cli install-browser` 挂死（CPU=0、无网络连接，链为 sh.exe → node.exe） | `taskkill /T`（配方按**命令行模式**匹配，不是按进程名） | 2026-10-29 |

**配方 3 的关键教训**：explorer 的泄漏**在任务管理器里几乎看不见**——它的 WS 只有 452MB，看「内存」列完全正常；吃掉的是 commit。**必须看线程数/句柄数**（9.6 万线程 / 21 万句柄）。

**配方 5 的关键教训**：句柄泄漏**按 Private 排序的工具必然漏掉**——它的 Private 只有 567MB，排在 Top15 之外。**线程/句柄必须是独立一维**。
更进一步：**光知道「句柄多」还不是结论**，必须分解到类型层才知道该找谁——配方 5 的根因最终指向 explorer，不是 Weixin 自己。

## 与同类工具的差异

调研过的同类项目（2026-10）：

| 工具 | 定位 | 为什么不直接用 |
|---|---|---|
| **SysWatch**（GitHub） | 最接近的同类：psutil + Flask + AI 建议，能报「句柄泄漏 / 线程爆炸」 | **只读，永不处置**；判据是固定阈值（句柄>3000 / 线程>100），实测会把 System(9142)/msedge(8777) 一起误报；重度依赖 AI API |
| **WinMemoryCleaner** | 托盘 RAM cleaner（5000+ stars） | 口径是「trim 工作集」= 已被本项目实测证伪（只降 WS 不降 Private） |
| **Process Hacker / System Informer** | 进程管理器 | 只做**观察**，无泄漏判定与定点回收；内核驱动带来权限与安全负担 |
| **wtop**（Rust TUI） | htop for Windows，线程/句柄面板做得很好 | 纯交互式 TUI，不产出可复核的**报告**，也不做处置 |
| **Dr. Memory** | DynamoRIO 内存调试器，能查 handle 泄漏 | 需插桩、面向 C/C++ 开发者、不是常驻系统工具 |
| **psleak** | Python C 扩展泄漏回归测试框架 | 测试框架定位，不面向「系统级进程体检」 |

**我们独有、现成项目都没有的组合**：
Private/commit 口径 + **线程/句柄独立维度** + **相对同 exe 中位数倍数**判据 + **CPU 总增量交叉验证**
+ **句柄类型分解定位根因** + 配方制定点回收 + 只读体检 + 计划任务闭环。

🔴 **句柄类型分解是最大的差异化点**：竞品最多告诉你「这个进程句柄很多」，本项目告诉你
「**是哪种句柄、泄漏源是哪些已退出的 pid、被多少个进程分摊**」。
实测价值：把「Weixin 178033 句柄，杀了吧」变成「explorer 泄漏的连带后果，治本在 explorer」——
这个结论**不可能**从任何竞品的输出里得到。

**借鉴自它们的设计**：
SysWatch 的线程/句柄维度 → 我们体检报告的第 4b 节（判据换成中位数倍数）；
wtop 的线程/句柄面板 → Top 线程 / Top 句柄两张榜；
WinMemoryCleaner 的排除列表 / 阈值分级 → 守卫 + 分级阈值；
Process Hacker 的进程树 + 句柄检查 → 孤儿判定与家族分组；
Process Hacker 的「查看句柄详情」→ Sysinternals Handle 类型分解（`handle_type_breakdown.py`），
但加了三件它们没有的：`-a` 全量枚举的坑位警告、与 Get-Process 的交叉校验、僵尸进程句柄聚类。

## Mac 版？

**暂无，也不在路线图上**——不是不想做，是条件不具备：① Mac 端还没有任何真实泄漏样本（配方制没有配方就没有意义）② 与 Windows 的机制零复用（hcsdiag/服务 vs launchd/psutil），等于重写。触发条件：攒到第一个 Mac 端已验证的泄漏模式，再考虑一个 psutil 版的只读体检。

## License

MIT
