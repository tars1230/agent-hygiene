# install-shortcut.ps1 —— 在桌面创建「进程刷新」快捷方式
#
# 用途：让用户双击就能打开本地控制台，不需要记命令。
# 用户需求原话：「我的设想是在win上有我这个套装的一个入口」——
#   桌面图标 = 那个「入口」。
#
# 用法（普通 PowerShell 即可，不需要管理员）：
#   powershell -ExecutionPolicy Bypass -File .\windows\install-shortcut.ps1
#
# 卸载：
#   Remove-Item "$env:USERPROFILE\Desktop\进程刷新.lnk" -ErrorAction SilentlyContinue
#
# 🔴 为什么不用计划任务常驻：
#   计划任务常驻 = 后台一直挂着一个服务，而本工具的核心是
#   「你觉得卡的时候才点开」。常驻反而违背「极其轻便」的前提。
#   改成：快捷方式启动时拉起服务（已后台化、无控制台窗口），用完不管。

param(
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$ToolsDir   = Join-Path $RepoRoot 'tools'
$ServerPy   = Join-Path $ToolsDir 'console_server.py'

if (-not (Test-Path $ServerPy)) {
    throw "找不到 $ServerPy —— 请在仓库根目录下运行本脚本。"
}

# ---- 找 python.exe（有 pythonw 的优先用 pythonw，跑起来不闪窗口）----
function Find-Python {
    $cands = @()
    # 已知的内置解释器（WorkBuddy/CodeBuddy 自带）
    $cands += Get-ChildItem -Path "$env:USERPROFILE\.workbuddy\binaries\python\versions" `
                -Directory -ErrorAction SilentlyContinue |
              Sort-Object Name -Descending |
              ForEach-Object { Join-Path $_.FullName 'python.exe' }
    # PATH 里的
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { $cands += $cmd.Source }
    foreach ($c in $cands) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    throw '找不到 python.exe。请先安装 Python 3.10+，或在 PATH 里配置好。'
}
Write-Host "解释器: $py"

# ---- 定位 %LOCALAPPDATA% ----
# 🔴 不能只靠 $env:LOCALAPPDATA：
#    IDE 托管的 PowerShell / 某些计划任务上下文里这个变量可能是空的
#    （本机实测：USERPROFILE、APPDATA 都有，唯独 LOCALAPPDATA 为空），
#    Join-Path 会直接抛 "参数绑定失败：Path 为空值"。
#    修法与 Python 侧 agent_hygiene_audit._local_appdata() 一致：
#    环境变量 -> 已知路径推导 -> 兜底家目录。
function Resolve-LocalAppData {
    $v = $env:LOCALAPPDATA
    if ($v -and (Test-Path $v)) { return $v }
    foreach ($base in @($env:SystemDrive, 'C:')) {
        if (-not $base) { continue }
        # 🔴 PowerShell 5.1 的 Join-Path 只吃两个参数（-Path + -ChildPath），
        #    不能一次串四个路径段 —— 必须嵌套调用。
        $p = Join-Path (Join-Path (Join-Path $base '\Users') $env:USERNAME) 'AppData\Local'
        if (Test-Path $p) { return $p }
    }
    return (Join-Path $env:USERPROFILE 'AppData\Local')
}

# ---- 写一个启动器 cmd（双击走它）----
$launcherDir = Join-Path (Resolve-LocalAppData) 'agent-hygiene'
$launcher = Join-Path $launcherDir 'open-console.cmd'
New-Item -ItemType Directory -Force -Path $launcherDir | Out-Null

# 🔴 用 pythonw.exe 而不是 python.exe：
#    python.exe 一定会分配一个控制台 -> 双击快捷方式时桌面上会闪一个黑框。
#    pythonw.exe 没有 stdout，但 console_server.py 里所有 print 都走 _say()
#    （已经 try/except 包住），所以换 pythonw 不会破坏任何功能。
$pyw = $py -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path $pyw)) { $pyw = $py }

$cmdContent = @"
@echo off
REM 进程刷新 · 本地控制台启动器（自动生成，勿手改）
REM 作用：后台拉起控制台并打开浏览器；已在运行则直接开浏览器。
start "" "$pyw" "$ServerPy" --bg --open
exit /b 0
"@
# 🔴 批处理文件必须用 CRLF：
#    here-string 在 PowerShell 里是 CRLF，但末尾换行会被去掉，
#    Set-Content 再补一个自己的换行 —— 结果是 CRLF/LF 混杂。
#    cmd.exe 对纯 LF 的批处理解析不稳定（尤其 `exit /b` 后无换行会吞掉最后一条命令），
#    所以这里显式把换行全部规整成 CRLF 再写盘。
#    编码用 OEM（GBK）：.cmd 默认按 OEM 代码页解释，中文注释才不会乱码。
$cmdContent = ($cmdContent -replace "`r`n", "`n") -replace "`n", "`r`n"
[System.IO.File]::WriteAllText($launcher, $cmdContent, [System.Text.Encoding]::GetEncoding(936))
Write-Host "启动器: $launcher（解释器 $pyw）"

# ---- 建桌面快捷方式 ----
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop '进程刷新.lnk'

# 🔴 快捷方式直接指向 pythonw.exe，而不是 open-console.cmd：
#    .lnk 指向 .cmd 时，cmd.exe 一定会分配一个控制台 —— 哪怕脚本内部
#    用 CREATE_NO_WINDOW 起服务，**启动器本身**那一下黑框照样闪。
#    直接指向 pythonw.exe + 参数，服务本体由 pythonw 承载，
#    没有 cmd.exe 参与，全链路零控制台窗口。
#    （open-console.cmd 仍然生成，保留给「想在终端里手动跑」的场景。）
$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($lnkPath)
$sc.TargetPath       = $pyw
$sc.Arguments        = '"' + $ServerPy + '" --bg --open'
$sc.WorkingDirectory = $ToolsDir
$sc.Description      = '进程刷新 · 本地控制台（体检 / 建议 / 定时任务 / 历史图表）'
$sc.IconLocation    = "$py,0"
$sc.WindowStyle     = 7   # 7 = 最小化启动，不弹窗
$sc.Save()

Write-Host ''
Write-Host "✅ 桌面快捷方式已创建：$lnkPath"
Write-Host '   双击它会自动启动控制台并打开浏览器（已在运行则直接开浏览器）。'
Write-Host "   卸载：Remove-Item '$lnkPath' -ErrorAction SilentlyContinue"

if (-not $NoLaunch) {
    Start-Process $launcher
    Write-Host '   已启动，浏览器应该会自动打开。'
}
