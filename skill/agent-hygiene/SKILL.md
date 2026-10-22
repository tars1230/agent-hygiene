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

## 工具（本仓库 `tools/` 目录）

| 工具 | 用途 | 性质 |
|---|---|---|
| `agent_hygiene_audit.py` | 体检：内存压力 + 家族 Top + 孤儿/HCS/shim + 空转 vs 干活 + 对比 | **只读** |
| `codex_sandbox_cleanup.py` | Codex 沙箱 VM 泄漏回收（两档 + 四守卫 + 年龄门槛） | 会动服务，需 `--apply` |
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

## 输出格式要求

向用户汇报时：判定 + 依据（原始数字）+ 建议命令三者齐备；不确定的写「待验证」，估算的标「估算」；
「可用内存低」≠「有泄漏」，先查在不在干活；不奉承、不渲染，直接给结论。
