# Nextcloud Sentinel Edition - KDE Craft dependency installer (Windows)
#
# SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Installs everything the build needs (Qt 6, ECM, KF6 Archive/GuiAddons,
# QtKeychain, OpenSSL, SQLite, zlib, ...) through KDE Craft, driven by
# CraftMaster exactly like .github/workflows/windows-sentinel-ci.yml does.
# The repository's craftmaster.ini is the single source of truth (Qt version,
# blueprint revisions, binary cache); this script only adds the machine
# specific bits (root folder, Python path).
#
# Result layout (default root C:\CraftRoot, override with -CraftRoot or the
# SENTINEL_CRAFT_ROOT environment variable):
#
#   C:\CraftRoot\CraftMaster\                  CraftMaster checkout
#   C:\CraftRoot\craft-clone\                  Craft itself
#   C:\CraftRoot\windows-msvc2022_64-cl\       the prefix: bin\, lib\cmake\Qt6, lib\cmake\KF6Archive, ...
#   C:\CraftRoot\craftmaster-local.ini         generated override (Python path)
#
# Qt comes from Craft. No separate Qt installation in C:\Qt is needed, and
# compile-sentinel.ps1 / test-sentinel.ps1 use this prefix first, so there is
# only ever one Qt in play.
#
# Usage (any PowerShell, Developer PowerShell not required):
#   .\install-craft.ps1                       # full install, resumable
#   .\install-craft.ps1 -CraftRoot D:\Craft
#   .\install-craft.ps1 -Verify               # only check an existing install
#
# Every step is checked; the script stops at the first failure with a hint,
# writes a transcript under <repo>\logs\ and returns a non-zero exit code.
# Re-running after a failure resumes: CraftMaster and Craft are idempotent.

[CmdletBinding()]
param(
    [string]$CraftRoot = "",
    [string]$Target = "windows-msvc2022_64-cl",
    [string]$PythonExe = "",
    [switch]$Verify,
    [int]$MinFreeSpaceGB = 30
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# Paths
# ============================================================================

$Script:RepoDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
if (-not $CraftRoot) {
    if ($env:SENTINEL_CRAFT_ROOT) { $CraftRoot = $env:SENTINEL_CRAFT_ROOT } else { $CraftRoot = "C:\CraftRoot" }
}
$Script:CraftRoot = $CraftRoot
$Script:MasterDir = Join-Path $CraftRoot "CraftMaster"
$Script:MasterScript = Join-Path $Script:MasterDir "CraftMaster.py"
$Script:BaseConfig = Join-Path $Script:RepoDir "craftmaster.ini"
$Script:LocalConfig = Join-Path $CraftRoot "craftmaster-local.ini"
$Script:Prefix = Join-Path $CraftRoot $Target
$Script:LogDir = Join-Path $Script:RepoDir "logs"
$Script:LogFile = Join-Path $Script:LogDir ("install-craft-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$Script:Results = [ordered]@{}

# ============================================================================
# Helpers
# ============================================================================

function Write-Header { param([string]$Message) Write-Host ""; Write-Host ("=" * 72) -ForegroundColor Cyan; Write-Host " $Message" -ForegroundColor Cyan; Write-Host ("=" * 72) -ForegroundColor Cyan }
function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "    $Message" }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host "[X] $Message" -ForegroundColor Red }

function Test-CommandAvailable { param([string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = "",
        [string]$FailureHint = ""
    )
    # stderr lines must not become terminating errors (PowerShell 5.1 + 2>&1)
    $ErrorActionPreference = "Continue"
    $display = "$Exe $($Arguments -join ' ')"
    Write-Info "> $display"
    $previous = Get-Location
    try {
        if ($WorkingDirectory) { Set-Location $WorkingDirectory }
        & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        Set-Location $previous
    }
    if ($code -ne 0) {
        $msg = "Command failed (exit code $code): $display"
        if ($FailureHint) { $msg += "`n    Hint: $FailureHint" }
        throw $msg
    }
}

function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$Attempts = 3, [int]$DelaySeconds = 10, [string]$What = "operation")
    for ($i = 1; $i -le $Attempts; $i++) {
        try { & $Action; return }
        catch {
            if ($i -eq $Attempts) { throw }
            Write-Warn "$What failed (attempt $i of $Attempts): $($_.Exception.Message.Split("`n")[0])"
            Write-Info "Retrying in $DelaySeconds s..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Craft is run through CraftMaster, with the repository ini as base config and
# a generated local override, exactly like the CI workflow.
function Invoke-Craft {
    param([string[]]$CraftArguments, [string]$FailureHint = "")
    $cmdArgs = @($Script:MasterScript,
                 "--config", $Script:BaseConfig,
                 "--config-override", $Script:LocalConfig,
                 "--variables", "Root=$Script:CraftRoot",
                 "--targets", $Target,
                 "-c") + $CraftArguments
    Invoke-Native $Script:Python $cmdArgs -WorkingDirectory $Script:CraftRoot -FailureHint $FailureHint
}

function Find-Python {
    if ($PythonExe) {
        if (-not (Test-Path $PythonExe)) { throw "Python given with -PythonExe does not exist: $PythonExe" }
        return $PythonExe
    }
    $candidates = @()
    if (Test-CommandAvailable "py") {
        $fromLauncher = & py -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $fromLauncher) { $candidates += "$fromLauncher".Trim() }
    }
    foreach ($name in @("python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and $cmd.Source -notmatch "WindowsApps") { $candidates += $cmd.Source }
    }
    foreach ($candidate in $candidates | Select-Object -Unique) {
        $version = & $candidate -c "import sys,platform; print(sys.version_info.major, sys.version_info.minor, platform.architecture()[0])" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $version) { continue }
        $parts = "$version".Trim().Split(" ")
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 9 -and $parts[2] -eq "64bit") { return $candidate }
    }
    return $null
}

# ============================================================================
# Steps
# ============================================================================

function Step-Prerequisites {
    Write-Header "Checking prerequisites"

    if (-not (Test-Path $Script:BaseConfig)) { throw "craftmaster.ini not found at $Script:BaseConfig (is this script inside the repository?)" }
    Write-Step "Repository: $Script:RepoDir"
    Write-Step "Craft root: $Script:CraftRoot (prefix: $Script:Prefix)"

    if ($Script:CraftRoot -match "\s") {
        throw "The Craft root path contains spaces ($Script:CraftRoot). Craft and several build tools break on that; use e.g. -CraftRoot C:\CraftRoot"
    }
    if ($Script:CraftRoot.Length -gt 40) {
        Write-Warn "Long Craft root path ($($Script:CraftRoot.Length) chars). Some packages hit the Windows path limit; C:\CraftRoot is safer."
    }

    if (-not (Test-CommandAvailable "git")) { throw "git not found. Install it with: winget install Git.Git (then open a new PowerShell)" }
    Write-Step "git: $(git --version)"

    $py = Find-Python
    if (-not $py) {
        throw "No 64-bit Python 3.9+ found. Install it with: winget install Python.Python.3.12 (then open a new PowerShell), or pass -PythonExe <path\python.exe>"
    }
    $Script:Python = $py
    Write-Step "Python: $py ($(& $py --version 2>&1))"

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = $null
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
    if (-not $vsPath) {
        throw "Visual Studio 2022 with the C++ workload not found. Install Build Tools 2022 with 'Desktop development with C++' (see SENTINEL-BUILD-PLAN.md, step 2.1)."
    }
    Write-Step "Visual Studio: $vsPath"

    $drive = Split-Path $Script:CraftRoot -Qualifier      # e.g. "C:"
    $disk = Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction SilentlyContinue
    if ($disk) {
        $freeGB = [math]::Round($disk.Free / 1GB)
        if ($freeGB -lt $MinFreeSpaceGB) {
            throw "Only $freeGB GB free on $drive. Craft with Qt and KF6 needs about $MinFreeSpaceGB GB. Free space or choose another root with -CraftRoot."
        }
        Write-Step "Free space on ${drive}: $freeGB GB"
    }

    foreach ($hostName in @("invent.kde.org", "github.com", "download.nextcloud.com")) {
        $ok = Test-NetConnection -ComputerName $hostName -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $ok) { throw "Cannot reach $hostName on port 443. Craft downloads from there; check network/proxy." }
    }
    Write-Step "Network: invent.kde.org, github.com, download.nextcloud.com reachable"
}

function Step-CraftMaster {
    Write-Header "CraftMaster"

    if (-not (Test-Path $Script:CraftRoot)) {
        New-Item -ItemType Directory -Path $Script:CraftRoot -Force | Out-Null
        Write-Step "Created $Script:CraftRoot"
    }

    if (Test-Path $Script:MasterScript) {
        Write-Step "CraftMaster already present, updating"
        try {
            Invoke-Native "git" @("-C", $Script:MasterDir, "pull", "--ff-only", "-q")
        } catch {
            Write-Warn "Could not update CraftMaster (offline or local changes); keeping the existing checkout"
        }
    } else {
        Invoke-WithRetry -What "CraftMaster clone" -Action {
            Invoke-Native "git" @("clone", "-q", "--depth=1", "https://invent.kde.org/packaging/craftmaster.git", $Script:MasterDir)
        }
    }
    if (-not (Test-Path $Script:MasterScript)) { throw "CraftMaster.py missing after clone: $Script:MasterScript" }
}

function Step-LocalConfig {
    Write-Header "Local CraftMaster override"

    # Craft wants the directory that holds python.exe.
    $pythonDir = Split-Path -Parent $Script:Python
    $content = @"
# Generated by install-craft.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm") - machine specific overrides.
# The base configuration is <repo>\craftmaster.ini; do not copy settings here.
[$Target]
Paths/Python = $pythonDir
"@
    Set-Content -Path $Script:LocalConfig -Value $content -Encoding ASCII
    Write-Step "Wrote $Script:LocalConfig (Paths/Python = $pythonDir)"
}

function Step-InstallCraft {
    Write-Header "Installing Craft and the blueprint repositories"

    Invoke-WithRetry -What "blueprint repositories" -Action {
        Invoke-Craft @("--add-blueprint-repository", "https://github.com/nextcloud/craft-blueprints-kde.git|stable-4.0|")
        Invoke-Craft @("--add-blueprint-repository", "https://github.com/nextcloud/desktop-client-blueprints.git|stable-4.0|")
    }
    Invoke-WithRetry -What "craft craft" -Action {
        Invoke-Craft @("craft") -FailureHint "Craft bootstrap failed; read the Python traceback above. Re-run this script, it resumes."
    }

    if (-not (Test-Path (Join-Path $Script:Prefix "craft\craftenv.ps1"))) {
        throw "Craft did not create $Script:Prefix\craft\craftenv.ps1"
    }
    Write-Step "Craft ready in $Script:Prefix"
}

function Step-InstallDependencies {
    Write-Header "Installing the Nextcloud client dependencies (Qt, KF6, OpenSSL, ...)"
    Write-Info "Binary cache: download.nextcloud.com (see craftmaster.ini). First run: 20-60 minutes depending on bandwidth."

    Invoke-WithRetry -Attempts 3 -DelaySeconds 30 -What "craft --install-deps nextcloud-client" -Action {
        Invoke-Craft @("--install-deps", "nextcloud-client") -FailureHint "A package failed to download or build. Re-run this script: Craft skips what is already installed."
    }
}

function Step-Verify {
    Write-Header "Verifying the prefix $Script:Prefix"

    $required = @(
        "lib\cmake\Qt6\Qt6Config.cmake",
        "bin\Qt6Core.dll",
        "share\ECM\cmake\ECMConfig.cmake",
        "lib\cmake\KF6Archive\KF6ArchiveConfig.cmake",
        "lib\cmake\KF6GuiAddons\KF6GuiAddonsConfig.cmake",
        "lib\cmake\Qt6Keychain\Qt6KeychainConfig.cmake",
        "lib\cmake\OpenSSL\OpenSSLConfig.cmake",
        "bin\sqlite3.dll"
    )
    $missing = @()
    foreach ($rel in $required) {
        $full = Join-Path $Script:Prefix $rel
        if (Test-Path $full) {
            Write-Step "ok   $rel"
        } else {
            # Some packages lay files out slightly differently between versions; look for the file name anywhere in the prefix before failing.
            $leaf = Split-Path $rel -Leaf
            $found = Get-ChildItem -Path $Script:Prefix -Recurse -Filter $leaf -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                Write-Step "ok   $leaf (at $($found.FullName.Substring($Script:Prefix.Length + 1)))"
            } else {
                Write-Fail "MISSING $rel"
                $missing += $rel
            }
        }
    }
    if ($missing.Count -gt 0) {
        throw "The prefix is incomplete ($($missing.Count) missing). Re-run without -Verify to install, or run: craft --install-deps nextcloud-client"
    }

    $qtVersion = ""
    $versionFile = Join-Path $Script:Prefix "lib\cmake\Qt6\Qt6ConfigVersion.cmake"
    if (Test-Path $versionFile) {
        $m = Select-String -Path $versionFile -Pattern 'PACKAGE_VERSION "([^"]+)"' | Select-Object -First 1
        if ($m) { $qtVersion = $m.Matches[0].Groups[1].Value }
    }
    Write-Step "Qt from Craft: $qtVersion"
    Write-Info ""
    Write-Info "Next: build with   admin\win\scripts\compile-sentinel.ps1 -Dev -Configure -Build"
    Write-Info "   or everything:  admin\win\scripts\test-sentinel.ps1 -All"
    if ($Script:CraftRoot -ne "C:\CraftRoot") {
        Write-Info "This root is not the default: set SENTINEL_CRAFT_ROOT=$Script:CraftRoot (user environment variable) so the build scripts find it."
    }
}

# ============================================================================
# Main
# ============================================================================

New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
try { Start-Transcript -Path $Script:LogFile -Append | Out-Null } catch { Write-Warn "Could not start transcript: $($_.Exception.Message)" }

Write-Header "Nextcloud Sentinel - KDE Craft installer"
Write-Info "Log: $Script:LogFile"

$steps = @()
$steps += @{ Name = "Prerequisites"; Enabled = $true;          Action = { Step-Prerequisites } }
$steps += @{ Name = "CraftMaster";   Enabled = (-not $Verify); Action = { Step-CraftMaster } }
$steps += @{ Name = "LocalConfig";   Enabled = (-not $Verify); Action = { Step-LocalConfig } }
$steps += @{ Name = "Craft";         Enabled = (-not $Verify); Action = { Step-InstallCraft } }
$steps += @{ Name = "Dependencies";  Enabled = (-not $Verify); Action = { Step-InstallDependencies } }
$steps += @{ Name = "Verify";        Enabled = $true;          Action = { Step-Verify } }

$exitCode = 0
$stopped = $false
foreach ($step in $steps) {
    if (-not $step.Enabled) { $Script:Results[$step.Name] = "SKIPPED"; continue }
    if ($stopped) { $Script:Results[$step.Name] = "NOT RUN"; continue }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $step.Action
        $Script:Results[$step.Name] = "OK ({0:n0} s)" -f $watch.Elapsed.TotalSeconds
    } catch {
        $Script:Results[$step.Name] = "FAILED"
        Write-Host ""
        Write-Fail "$($step.Name) failed:"
        $_.Exception.Message.Split("`n") | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        $exitCode = 1
        $stopped = $true
    }
}

Write-Header "Summary"
foreach ($entry in $Script:Results.GetEnumerator()) {
    $color = switch -Wildcard ($entry.Value) { "OK*" { "Green" } "FAILED" { "Red" } default { "DarkGray" } }
    Write-Host ("  {0,-14} {1}" -f $entry.Key, $entry.Value) -ForegroundColor $color
}
Write-Info ""
Write-Info "Log file: $Script:LogFile"
if ($exitCode -ne 0) { Write-Info "Re-running the script resumes where it stopped. Send the log file when asking for help." }

try { Stop-Transcript | Out-Null } catch { }
exit $exitCode
