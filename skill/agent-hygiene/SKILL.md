---
name: agent-hygiene
description: AI 宿主/多 agent 电脑的内存体检与定点回收。只读审计区分「在干活」与「泄漏」，识别 Electron 家族、孤儿子进程、HCS 沙箱遗留、shim 重复计数，输出报告与建议命令，默认绝不杀进程。触发词：内存占用、电脑负载、体检、泄漏、清理进程、agent 占用、电脑卡。
---

# Agent Hygiene —— 多 agent 电脑的内存体检

给装了多个 AI agent（WorkBuddy / Codex / Cursor / MiniMax / opencode / cline / 各类桥接…）的
Windows 工作站做定期体检。
**核心立场：只读诊断优先，定点回收其次，通用自动清理永远不做。**

## 铁律（违反 = 结论不可信，全部实测换来的）

1. **默认只读**。任何回收动作只打印建议命令；要执行必须先复述目标进程/PID/服务名并获得用户明确确认。
2. **报占用用 Private/Commit，不用 WS**。WS 会被系统 trim；`SetProcessWorkingSetSize(-1,-1)`
   实测只降 WS 不降 Private（`tools/trim_experiment.py` 可复现）。
3. **「在干活」和「泄漏」不能靠名字/内存量判断**，必须用 CPU 时间采样（GetProcessTimes 两次采样取增量）。
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

## 工具（本仓库 `tools/` 目录）

| 工具 | 用途 | 性质 |
|---|---|---|
| `agent_hygiene_audit.py` | 体检：内存压力 + 家族 Top + 孤儿/HCS/shim + 空转 vs 干活 + 对比 | **只读** |
| `codex_sandbox_cleanup.py` | Codex 沙箱 VM 泄漏回收（两档 + 四守卫 + 年龄门槛） | 会动服务，需 `--apply` |
| `stuck_process_cleanup.py` | 挂死进程回收（explorer 线程泄漏 / git 挂死链） | 会杀进程，需 `--apply` |
| `hcs_ctl.py` | HCS compute system 枚举/属性（取证用） | list/props 只读 |
| `trim_experiment.py` | 复现「trim 只降 WS 不降 Private」 | 只读 |

仅支持 Windows。报告默认写 `%LOCALAPPDATA%\agent-hygiene\reports\`，回收日志在 `..\logs\`。

## 工作流

1. **先体检**：`python tools/agent_hygiene_audit.py --top 15`（约 30 秒）。
2. **读报告，按判定说话**：
   - 「在干活(CPU>1%)」→ 不动，如实告知用户这是正在工作的成本。
   - 「空闲/阻塞等待 + Private 大」→ 是缓存/等待，回收收益看 Private，且会立刻被其他进程吃掉。
   - 「孤儿」/「vmmem 无 worker」→ 给定点建议（见配方），等用户确认。
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

### 计划任务遗留的 git 挂死链（实测 8 天累积 56 进程）
```
python tools/stuck_process_cleanup.py --apply
```
判据：git 家族进程存活 ≥60 分钟 **且 CPU 增量 <1%**（在 push 的真实任务会被跳过）。
根因：全局 `url.insteadOf` 把 github.com 改写到 gh-proxy.com，GCM 无该域凭据，
凭据提示在计划任务上下文里被吞 → git 永久等待。**根治要改根因，不只是杀进程**：
① remote 用 `https://github.com:443/<owner>/<repo>.git`（不命中 insteadOf 前缀匹配）
② 脚本里 `git -c credential.interactive=never push` + `timeout=120`
③ git 不读 Windows 系统代理 → 必须显式 `-c http.proxy=http://127.0.0.1:<port>`
④ 脚本必须**失败时返回非零退出码**，否则计划任务 LastTaskResult=0 = 失败被完全吞掉

## 输出格式要求

向用户汇报时：判定 + 依据（原始数字）+ 建议命令三者齐备；不确定的写「待验证」，估算的标「估算」；
「可用内存低」≠「有泄漏」，先查在不在干活；不奉承、不渲染，直接给结论。
