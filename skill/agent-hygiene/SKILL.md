---
name: agent-hygiene
description: AI 宿主/多 agent 电脑的内存体检与定点回收。只读审计区分「在干活」与「泄漏」，识别 Electron 家族、孤儿子进程、HCS 沙箱遗留、shim 重复计数，以及独立于内存口径的线程/句柄泄漏，输出报告与建议命令，默认绝不杀进程。触发词：内存占用、电脑负载、体检、泄漏、清理进程、agent 占用、电脑卡、句柄泄漏、线程泄漏。
---

# Agent Hygiene —— 多 agent 电脑的内存体检

给装了多个 AI agent（WorkBuddy / Codex / Cursor / MiniMax / opencode / cline / 各类桥接…）的
Windows 工作站做定期体检。
**核心立场：只读诊断优先，定点回收其次，通用自动清理永远不做。**

## 铁律（违反 = 结论不可信，全部实测换来的）

1. **默认只读**。任何回收动作只打印建议命令；要执行必须先复述目标进程/PID/服务名并获得用户明确确认。
2. **报占用用 Private/Commit，不用 WS**。WS 会被系统 trim；`SetProcessWorkingSetSize(-1,-1)`
   实测只降 WS 不降 Private（`tools/trim_experiment.py` 可复现）。
3. **「在干活」和「泄漏」不能靠名字/内存量判断**，必须用 CPU 时间采样（GetProcessTimes 多次采样取增量）。
   实测教训：一个 954MB 的 agent 进程看着像泄漏，实际在跑任务（CPU 530 秒）。CPU 持续 >1% = 在干活，别动。
4. **顶层应用「父进程已退出」是常态**（启动器/资源管理器退出），不是孤儿。孤儿只判
   「Electron 子进程（renderer/gpu/utility/crashpad）但宿主 main 已死」。
5. **服务的常驻是设计**（父进程=services.exe / StartMode=Auto），不算泄漏，别建议杀。
6. **不做的事，别再当方案提**：定时 trim（伪优化+伤体验）、Defender 排除项省内存（伪优化，
   排除不减特征库）、盲目关浏览器扩展（真实收益 50–150MB 且伤体验）、任何「动态清理进程」的通用自动化。
7. 每条结论必须能从报告里的原始数字复核；自己估的数字标注「估算」，并尽快用实测替换。
   差值法推出的归属（「A→B 差了 250MB，一定是 X」）必须单独量过才能写进结论。
8. **回收量与可用内存增量要分开报**。实测：释放 872.8MB 的当天可用只涨 38MB，
   因为同窗口别的进程涨了 2.5GB——单点收益必须在静默窗口测，且不承诺「释放 X 内存」。
9. 🔴 **explorer 这类进程的泄漏在任务管理器里几乎看不见**。实测样本：Private 8432MB 而
   WS 只有 452MB，96127 个线程处于 Suspended 状态——**看「内存」列完全正常，吃掉的是 commit**。
   **必须看线程数/句柄数**，阈值：线程 >2 万即异常。只看 WS/「内存」列会漏掉这类最大泄漏。
10. 🔴 **「计划任务失败」和「进程挂死」是两个独立 bug**，别混成一个。实测：DailyBriefing1745
    连续 8 天 LastTaskResult=267014（SCHED_E_TASK_NOT_RUN，因为计划任务上下文里 `git` 不在 PATH，
    报 FileNotFoundError）；同时又有另一批 git 进程因凭据提示被吞而永久挂起。修的时候两个都要改。
11. 🔴 **句柄泄漏是一整类独立于 Private 的泄漏，按 Private 排序的工具必然漏掉**。
    实测：Weixin 主进程 177790 句柄，而 Private 只有 567MB —— 在任务管理器里看着完全正常，
    但句柄吃的是**内核对象表**，耗尽后 CreateProcess/CreateFile 会全失败。
    **体检报告必须把「线程/句柄」单列一维**，不能只按 Private 排。
12. 🔴 **判「句柄/线程异常」不能用固定阈值，必须用「相对同 exe 中位数的倍数」**。
    实测同一台机器上：System 9142 句柄、msedge 8777、WeChatAppEx 8354 —— 都是正常的。
    而 Weixin 主进程 177790，是同 exe 中位数（243）的 **731.6 倍**。
    固定阈值（如 3000）会把正常高值全报成泄漏——**这是 SysWatch 这类工具的实际误报来源**。
13. 🔴 **判「在干活」要用 CPU 总增量，不要用单窗峰值**。实测 Weixin 3 秒窗内偶发突发
    （峰值 38%），但 16 秒总增量只有 3.4%。用单窗峰值会把「偶发活动」误判成「一直在干活」
    → 漏掉真挂死；用总增量才稳。多窗采样：总增量判「在干活」，峰值仅作参考。
14. 🔴 **WMI 的 `CreationDate` 是 `System.DateTime`，PowerShell 默认输出成美式
    `10/21/2026 15:10:32`**，Python `fromisoformat` 解析不了 → 返回 None → 存活时长算成 0 →
    所有「存活时长」守卫形同虚设。必须显式 `$c.ToString('yyyy-MM-ddTHH:mm:ss')`。
    （本项目真实踩过：Weixin 存活 187 小时却报「存活仅 0 分钟」。）

## 工具（本仓库 `tools/` 目录）

| 工具 | 用途 | 性质 |
|---|---|---|
| `agent_hygiene_audit.py` | 体检：内存压力 + 家族 Top + **线程/句柄维度** + 孤儿/HCS/shim + 空转 vs 干活 + 对比 | **只读** |
| `thread_handle_probe.py` | 线程/句柄探测（一次 PS 调用取全表，~360ms）+ 中位数倍数判据 | **只读** |
| `codex_sandbox_cleanup.py` | Codex 沙箱 VM 泄漏回收（两档 + 四守卫 + 年龄门槛） | 会动服务，需 `--apply` |
| `stuck_process_cleanup.py` | 挂死进程回收（explorer 线程泄漏 / 挂死命令行链 / 句柄泄漏） | 会杀进程，需 `--apply` |
| `hcs_ctl.py` | HCS compute system 枚举/属性（取证用） | list/props 只读 |
| `trim_experiment.py` | 复现「trim 只降 WS 不降 Private」 | 只读 |

仅支持 Windows。报告默认写 `%LOCALAPPDATA%\agent-hygiene\reports\`，回收日志在 `..\logs\`。

## 工作流

1. **先体检**：`python tools/agent_hygiene_audit.py --top 15`（约 30 秒）。
   报告第 4b 节是**线程/句柄维度**——它独立于 Private 排序，专门抓「Private 不大但
   句柄/线程爆了」的那一类。
2. **读报告，按判定说话**：
   - 「在干活(CPU>1%)」→ 不动，如实告知用户这是正在工作的成本。
   - 「空闲/阻塞等待 + Private 大」→ 是缓存/等待，回收收益看 Private，且会立刻被其他进程吃掉。
   - 「孤儿」/「vmmem 无 worker」→ 给定点建议（见配方），等用户确认。
   - 「句柄/线程异常 + CPU≈0 + 存活长」→ 才是真泄漏候选，等用户确认再动手。
3. **定点回收**：只对已知模式的泄漏动手，且永远先演练（不带 `--apply`）再实做。

## 已知泄漏配方

### Codex 沙箱 VM（SavedAsTemplate 孤儿，实测挂 25h / 872.8MB）
```
python tools/codex_sandbox_cleanup.py            # 演练
python tools/codex_sandbox_cleanup.py --apply    # 实清（档1停CodexSandboxService→档2退vmcompute）
```
守卫自动跳过：Codex App 在跑 / 有 Docker、WSL、WindowsSandbox / vmmem 年龄 <2h /
compute system 不止一个或非 SavedAsTemplate。
其它 agent 的泄漏按同一套路适配：**先找守护服务 → 停→验→起回；别用未文档 ABI，别 `Stop-Process` VM 宿主。**
没有真实泄漏样本前，不要预防性地写新配方。

### explorer 线程/句柄泄漏（实测 96262 线程 / Private 8432MB / WS 仅 452MB）
```
python tools/stuck_process_cleanup.py            # 演练
python tools/stuck_process_cleanup.py --apply    # 实清（会关掉所有已打开的文件夹窗口）
```
判据：线程数 ≥20000 且存活 ≥120 分钟。根因是第三方 shell 扩展（IDM / WPS qingnse / WeType / 7-zip
都是嫌疑，但**没有硬证据指向某一个**，不猜）。`NtQueryInformationThread` 反查线程归属在本机被拒
（STATUS_ACCESS_DENIED 0xC0000022），所以不做精确归因，直接重启 explorer。
⚠️ 重启 explorer 会关闭所有文件夹窗口——动手前要告知用户。

### 挂死命令行链（实测：git 挂死链 56 进程 + playwright-cli install-browser 70 分钟）
```
python tools/stuck_process_cleanup.py            # 演练
python tools/stuck_process_cleanup.py --apply    # 实清
```
判据：**按命令行模式匹配**（不是按进程名）+ 存活 ≥60 分钟 + CPU 总增量 <1%。
样本 A：计划任务里的 `git push` 因凭据提示被吞而永久挂起，10/21~10/28 每天 17:45 一批，共 56 进程。
样本 B：`playwright-cli install-browser` 挂死 70 分钟，CPU=0、无网络连接、浏览器已下载完 3.1GB 但进程不退
（链为 `sh.exe` → `node.exe(@playwright/cli)` → 子进程）。
🔴 **不要只按进程名匹配**：原版名单含 `sh.exe`（太宽，任何 shell 都算 git 家族），
而 playwright 链的主体 `node.exe` 又不在名单里 → 漏网。改成匹配命令行里的工具标记。
根治 git 挂死要改根因，不只是杀进程：
① remote 用 `https://github.com:443/<owner>/<repo>.git`（不命中 insteadOf 前缀匹配）
② 脚本里 `git -c credential.interactive=never push` + `timeout=120`
③ git 不读 Windows 系统代理 → 必须显式 `-c http.proxy=http://127.0.0.1:<port>`
④ 脚本必须**失败时返回非零退出码**，否则计划任务 LastTaskResult=0 = 失败被完全吞掉

### 句柄泄漏（实测 Weixin 主进程 177790 句柄 / 同 exe 中位数的 731.6 倍）
```
python tools/stuck_process_cleanup.py            # 演练（只报告）
python tools/stuck_process_cleanup.py --apply --kill-handle-leak   # 实清（不可逆！）
```
判据：句柄 ≥50000 **且** 相对同 exe 中位数 ≥20 倍 **且** CPU 总增量 <1% **且** 存活 ≥60 分钟。
🔴 **这个配方默认只报告不杀**，与前两个不同：杀 explorer 只是关文件夹窗口（可恢复），
杀 Weixin 主进程会丢失**登录态 / 未发送消息 / 小程序容器**——代价不可逆。
所以必须显式加 `--kill-handle-leak` 才动手，且仍受全部守卫约束。
实测中它正确地**放过了 WorkBuddy 宿主**（51527 句柄 = 同 exe 中位数 153 倍，但 CPU 5.8% 在干活）。

## 与同类工具的差异（为什么不用现成的）

调研过的同类项目（2026-10）：

| 工具 | 定位 | 为什么不直接用 |
|---|---|---|
| **SysWatch**（GitHub） | 最接近的同类：psutil + Flask + AI 建议，能报「句柄泄漏 / 线程爆炸」 | **只读，永不处置**；判据是固定阈值（句柄>3000 / 线程>100），实测会把 System(9142)/msedge(8777) 一起误报；重度依赖 AI API |
| **WinMemoryCleaner** | 托盘 RAM cleaner（5000+ stars） | 口径是「trim 工作集」= 已被本项目实测证伪（只降 WS 不降 Private） |
| **Process Hacker / System Informer** | 进程管理器 | 只做**观察**，没有泄漏判定与定点回收；内核驱动带来权限与安全负担 |
| **wtop**（Rust TUI） | htop for Windows，线程/句柄面板做得很好 | 纯交互式 TUI，不产出可复核的**报告**，也不做处置 |
| **Dr. Memory** | DynamoRIO 内存调试器，能查 handle 泄漏 | 需插桩、面向 C/C++ 开发者、不是常驻系统工具 |
| **psleak** | Python C 扩展的泄漏回归测试框架 | 测试框架定位，不面向「系统级进程体检」 |

**我们独有、现成项目都没有的组合**：
Private/commit 口径 + **线程/句柄独立维度** + **相对同 exe 中位数倍数**判据（消固定阈值误报）
+ **CPU 总增量交叉验证**（区分在干活 vs 泄漏）+ 配方制定点回收 + 只读体检 + 计划任务闭环。

**从它们借鉴的**：
- SysWatch 的「线程/句柄维度」思路 → 变成我们体检报告的第 4b 节（但判据换成中位数倍数）
- wtop 的「线程/句柄面板」呈现方式 → 变成 Top 线程 / Top 句柄两张榜
- WinMemoryCleaner 的「排除列表 / 阈值分级」产品形态 → 变成守卫 + 分级阈值
- Process Hacker 的「进程树 + 句柄检查」→ 变成孤儿判定与家族分组

## 输出格式要求

向用户汇报时：判定 + 依据（原始数字）+ 建议命令三者齐备；不确定的写「待验证」，估算的标「估算」；
「可用内存低」≠「有泄漏」，先查在不在干活；不奉承、不渲染，直接给结论。
