# Nextcloud Sentinel Edition - Windows test pipeline
#
# SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
# SPDX-License-Identifier: GPL-2.0-or-later
#
# One script for the whole test loop on a Windows workstation:
#
#   -Update    fetch and fast-forward the working branch (refuses to touch local changes)
#   -Build     configure + build the "NextcloudDev" variant (nextclouddev.exe, own config folder,
#              runs next to the standard Nextcloud client and never sees its accounts)
#   -Test      run the Kill Switch test suites with ctest
#   -Run       start nextclouddev.exe with the right PATH (Qt + Craft DLLs)
#   -Simulate  drive test/scripts/simulate-ransomware.py against a sentinel-sandbox folder
#   -All       Update + Build + Test
#
# Examples:
#   .\test-sentinel.ps1 -All
#   .\test-sentinel.ps1 -Update -Build
#   .\test-sentinel.ps1 -Run
#   .\test-sentinel.ps1 -Simulate -Mode seed   -Sandbox "D:\TestNextcloud\sentinel-sandbox"
#   .\test-sentinel.ps1 -Simulate -Mode header -Sandbox "D:\TestNextcloud\sentinel-sandbox"
#   .\test-sentinel.ps1 -Simulate -Mode reset  -Sandbox "D:\TestNextcloud\sentinel-sandbox"
#
# Every step is checked; the script stops at the first failure, prints what
# went wrong and how to fix it, writes a full log under <repo>\logs\, and
# returns a non-zero exit code. Written for Windows PowerShell 5.1 and later.

[CmdletBinding()]
param(
    [string]$Branch = "claude/hopeful-goldberg-7iu995",

    [ValidateSet("Release", "Debug", "RelWithDebInfo")]
    [string]$BuildType = "Release",

    [switch]$Update,
    [switch]$Build,
    [switch]$Test,
    [switch]$Run,
    [switch]$Simulate,
    [switch]$All,

    # -Build only: wipe the build directory first
    [switch]$Clean,

    # -Simulate only
    [string]$Sandbox = "",
    [ValidateSet("seed", "rename", "inplace", "header", "chunked", "delete-recreate", "notes", "canary", "mass-delete", "reset")]
    [string]$Mode = "seed",
    [int]$Count = 0,

    # -Test only: ctest regex (default: the three Kill Switch suites)
    [string]$TestFilter = "KillSwitch|FormatSignature",

    [string]$QtPath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# Paths
# ============================================================================

$Script:RepoDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$Script:CompileScript = Join-Path $PSScriptRoot "compile-sentinel.ps1"
$Script:SimulatorScript = Join-Path $Script:RepoDir "test\scripts\simulate-ransomware.py"
$Script:BuildDir = Join-Path $Script:RepoDir "build-windows-$BuildType-dev"
$Script:ExePath = Join-Path $Script:BuildDir "bin\nextclouddev.exe"
$Script:CraftTarget = "windows-msvc2022_64-cl"
$Script:CraftRoot = if ($env:SENTINEL_CRAFT_ROOT) { $env:SENTINEL_CRAFT_ROOT } else { "C:\CraftRoot" }
$Script:InstallCraftScript = Join-Path $PSScriptRoot "install-craft.ps1"
$Script:LogDir = Join-Path $Script:RepoDir "logs"
$Script:LogFile = Join-Path $Script:LogDir ("test-sentinel-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

$Script:QtSearchPaths = @(
    "C:\Qt\6.8.3\msvc2022_64",
    "C:\Qt\6.8.2\msvc2022_64",
    "C:\Qt\6.8.1\msvc2022_64",
    "C:\Qt\6.8.0\msvc2022_64",
    "$env:USERPROFILE\Qt\6.8.0\msvc2022_64"
)

# Step results for the final summary: name -> "OK" | "FAILED" | "SKIPPED"
$Script:Results = [ordered]@{}

# ============================================================================
# Output helpers
# ============================================================================

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "    $Message" }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host "[X] $Message" -ForegroundColor Red }

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Run a native command, stream its output, and throw with a clear message if
# it returns a non-zero exit code. $ErrorActionPreference = Stop does NOT
# catch native exit codes, hence this wrapper.
function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = "",
        [string]$FailureHint = ""
    )
    # In Windows PowerShell 5.1, "2>&1" turns stderr lines (git progress,
    # compiler notes) into error records, and Stop would abort on the first
    # one. Relax it for the duration of the native call only.
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

# Same, but returns the output instead of streaming it (for git queries).
function Get-NativeOutput {
    param([Parameter(Mandatory)] [string]$Exe, [string[]]$Arguments = @())
    $ErrorActionPreference = "Continue"
    $out = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit code $LASTEXITCODE): $Exe $($Arguments -join ' ')`n$out"
    }
    return ($out | Out-String).Trim()
}

function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$Attempts = 3, [int]$DelaySeconds = 3, [string]$What = "operation")
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            & $Action
            return
        } catch {
            if ($i -eq $Attempts) { throw }
            Write-Warn "$What failed (attempt $i of $Attempts): $($_.Exception.Message.Split("`n")[0])"
            Write-Info "Retrying in $DelaySeconds s..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Find-QtPath {
    if ($QtPath) {
        if (Test-Path $QtPath) { return $QtPath }
        throw "Qt path given with -QtPath does not exist: $QtPath"
    }
    if ($env:Qt6_DIR -and (Test-Path $env:Qt6_DIR)) { return $env:Qt6_DIR }
    foreach ($candidate in $Script:QtSearchPaths) {
        if (Test-Path $candidate) { return $candidate }
    }
    # Last resort: any C:\Qt\6.*\msvc2022_64
    if (Test-Path "C:\Qt") {
        $found = Get-ChildItem "C:\Qt" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^6\." } |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "msvc2022_64" } |
            Where-Object { Test-Path $_ } |
            Select-Object -First 1
        if ($found) { return $found }
    }
    return $null
}

function Find-CraftPrefix {
    foreach ($candidate in @((Join-Path $Script:CraftRoot $Script:CraftTarget),
                             "C:\CraftRoot\$Script:CraftTarget",
                             "$env:USERPROFILE\CraftRoot\$Script:CraftTarget")) {
        if (Test-Path (Join-Path $candidate "bin\Qt6Core.dll")) { return $candidate }
    }
    return $null
}

# nextclouddev.exe and the test binaries need the Qt and Craft DLLs. They must
# be the ones the build was linked against: the Craft prefix (which holds Qt)
# goes first; a standalone C:\Qt is only used when there is no Craft prefix.
function Set-RuntimePath {
    $parts = @()
    $craft = Find-CraftPrefix
    if ($craft) {
        $parts += "$craft\bin"
        $env:Qt6_DIR = "$craft\lib\cmake\Qt6"
        Write-Step "Runtime PATH: Craft prefix $craft (Qt from Craft)"
    } else {
        $qt = Find-QtPath
        if (-not $qt) {
            throw "No KDE Craft prefix and no standalone Qt found. Run .\install-craft.ps1 (recommended), or pass -QtPath C:\Qt\6.8.x\msvc2022_64"
        }
        $parts += "$qt\bin"
        $env:Qt6_DIR = $qt
        Write-Warn "No Craft prefix; using standalone Qt $qt. The build must have used the same Qt."
    }
    if (Test-Path "$Script:BuildDir\bin") { $parts += "$Script:BuildDir\bin" }
    $env:PATH = ($parts -join ";") + ";" + $env:PATH
}

function Find-Python {
    $ErrorActionPreference = "Continue"
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = $candidate[0]
        if (Test-CommandAvailable $exe) {
            $extra = @()
            if ($candidate.Count -gt 1) { $extra = @($candidate[1..($candidate.Count - 1)]) }
            $version = & $exe @extra --version 2>&1
            if ($LASTEXITCODE -eq 0 -and "$version" -match "Python 3\.") {
                return @{ Exe = $exe; Args = $extra; Version = "$version" }
            }
        }
    }
    return $null
}

# ============================================================================
# Steps
# ============================================================================

function Step-Prerequisites {
    Write-Header "Checking prerequisites"

    if (-not (Test-Path (Join-Path $Script:RepoDir ".git"))) {
        throw "Not a git checkout: $Script:RepoDir (this script must live in admin\win\scripts of the repository)"
    }
    Write-Step "Repository: $Script:RepoDir"

    if (-not (Test-CommandAvailable "git")) {
        throw "git not found. Install it with: winget install Git.Git (then open a new PowerShell)"
    }
    Write-Step "git: $(git --version)"

    if ($Build -or $Test) {
        if (-not (Test-Path $Script:CompileScript)) { throw "Missing $Script:CompileScript" }
        if (-not (Test-CommandAvailable "cmake")) {
            throw "cmake not found. Install it with: winget install Kitware.CMake (then open a new PowerShell)"
        }
        Write-Step "cmake: $((cmake --version | Select-Object -First 1))"
        if (-not (Find-CraftPrefix)) {
            Write-Warn "No KDE Craft prefix found (expected $Script:CraftRoot\$Script:CraftTarget). Run .\install-craft.ps1 first unless you build against a standalone Qt."
        }
        if ($Build -and -not (Test-CommandAvailable "inkscape") -and -not (Test-Path "C:\Program Files\Inkscape\bin\inkscape.exe")) {
            throw "Inkscape not found; CMake needs it to generate the icons. Install it with: winget install --id Inkscape.Inkscape -e (then open a new PowerShell)"
        }
    }

    if ($Simulate) {
        $py = Find-Python
        if (-not $py) {
            throw "Python 3 not found. Install it with: winget install Python.Python.3.12 (then open a new PowerShell)"
        }
        Write-Step "Python: $($py.Version)"
        if (-not (Test-Path $Script:SimulatorScript)) {
            throw "Simulator not found: $Script:SimulatorScript (run -Update to get the latest branch)"
        }
    }
}

function Step-Update {
    Write-Header "Updating repository (branch: $Branch)"

    Set-Location $Script:RepoDir

    # Never clobber local work.
    $dirty = Get-NativeOutput "git" @("status", "--porcelain", "--untracked-files=no")
    if ($dirty) {
        Write-Fail "You have uncommitted local changes:"
        $dirty.Split("`n") | ForEach-Object { Write-Info $_ }
        throw "Refusing to update over local changes. Commit them (git commit), stash them (git stash) or discard them (git checkout -- <file>) and run again."
    }

    Invoke-WithRetry -What "git fetch" -Action {
        Invoke-Native "git" @("fetch", "origin", $Branch) -FailureHint "Check your network / proxy, and that the branch exists on https://github.com/jlacerte/nextcloud-sentinel"
    }

    $current = Get-NativeOutput "git" @("rev-parse", "--abbrev-ref", "HEAD")
    if ($current -ne $Branch) {
        Write-Step "Switching from '$current' to '$Branch'"
        $exists = & git show-ref --verify --quiet "refs/heads/$Branch"; $localExists = ($LASTEXITCODE -eq 0)
        if ($localExists) {
            Invoke-Native "git" @("checkout", $Branch)
        } else {
            Invoke-Native "git" @("checkout", "-b", $Branch, "--track", "origin/$Branch")
        }
    }

    try {
        Invoke-Native "git" @("merge", "--ff-only", "origin/$Branch")
    } catch {
        throw "Your local '$Branch' has diverged from origin (local commits not on the server). Either push them, or reset: git reset --hard origin/$Branch (this DISCARDS local commits)."
    }

    $head = Get-NativeOutput "git" @("log", "-1", "--format=%h %ad %s", "--date=short")
    Write-Step "Now at: $head"
}

function Step-Build {
    Write-Header "Building the NextcloudDev variant ($BuildType)"

    $running = Get-Process -Name "nextclouddev" -ErrorAction SilentlyContinue
    if ($running) {
        throw "nextclouddev.exe is running (PID $($running.Id -join ', ')). Close it (tray icon > Quit) before building: the linker cannot overwrite a running executable."
    }

    $cmdArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:CompileScript,
                 "-Dev", "-BuildType", $BuildType, "-Configure", "-Build")
    if ($Clean) { $cmdArgs += "-Clean" }
    if ($QtPath) { $cmdArgs += @("-QtPath", $QtPath) }

    # compile-sentinel.ps1 calls `exit` on failure, so it has to run in its
    # own process; the exit code is what we check.
    Invoke-Native "powershell.exe" $cmdArgs -FailureHint "Read the first [X] line above. Most common causes: Qt 6.8 not installed in C:\Qt (pass -QtPath), Visual Studio 2022 C++ tools missing, KDE Craft dependencies not installed (run .\install-dependencies.ps1 -UseCraft)."

    if (-not (Test-Path $Script:ExePath)) {
        throw "Build reported success but $Script:ExePath is missing. Check the log."
    }
    Write-Step "Built: $Script:ExePath"
}

function Step-Test {
    Write-Header "Running tests (ctest -R `"$TestFilter`")"

    if (-not (Test-Path $Script:BuildDir)) {
        throw "Build directory not found: $Script:BuildDir. Run with -Build first."
    }
    Set-RuntimePath

    $output = New-Object System.Collections.Generic.List[string]
    $cmdArgs = @("-R", $TestFilter, "--output-on-failure", "-C", $BuildType, "--timeout", "600")
    Write-Info "> ctest $($cmdArgs -join ' ')"
    Push-Location $Script:BuildDir
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & ctest @cmdArgs 2>&1 | ForEach-Object { Write-Host $_; $output.Add("$_") }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
        Pop-Location
    }

    $summary = $output | Where-Object { $_ -match "tests passed" } | Select-Object -Last 1
    if ($summary) { Write-Step $summary.Trim() }

    if (-not $summary -or $summary -match "No tests were found") {
        throw "No test matched '$TestFilter'. Was the build configured with -DBUILD_TESTING=ON (compile-sentinel.ps1 does that)?"
    }

    # On Windows the QtTest executables have been seen to print nothing on
    # the console (issue #24), which leaves --output-on-failure empty. Run each
    # suite once more with "-o <file>,txt": the file always carries the
    # per-test results and the Totals line, and is printed here.
    Write-Step "Collecting per-suite results"
    $suiteRegex = $TestFilter
    $exes = Get-ChildItem -Path (Join-Path $Script:BuildDir "bin") -Filter "*Test.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.BaseName -match $suiteRegex }
    $suiteFailures = @()
    foreach ($exe in $exes) {
        $report = Join-Path $Script:LogDir ("{0}-{1}.txt" -f $exe.BaseName, (Get-Date -Format "yyyyMMdd-HHmmss"))
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        Push-Location $exe.DirectoryName
        try {
            & $exe.FullName -o "$report,txt" 2>&1 | Out-Null
            $suiteCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedPreference
            Pop-Location
        }
        $totals = ""
        if (Test-Path $report) {
            $totals = (Select-String -Path $report -Pattern "^Totals:" | Select-Object -Last 1).Line
            Select-String -Path $report -Pattern "^FAIL!|^   Loc:|^   Actual|^   Expected" | ForEach-Object { Write-Host "    $($_.Line)" -ForegroundColor Red }
        }
        if ($suiteCode -ne 0 -or -not $totals -or $totals -notmatch ", 0 failed") {
            Write-Fail ("{0}: {1} (exit {2}) - {3}" -f $exe.BaseName, $totals, $suiteCode, $report)
            $suiteFailures += $exe.BaseName
        } else {
            Write-Step ("{0}: {1}" -f $exe.BaseName, $totals)
        }
    }

    if ($code -ne 0 -or $suiteFailures.Count -gt 0) {
        $failed = $output | Where-Object { $_ -match "\*\*\*Failed|Failed\s+\d" }
        throw "Tests failed (ctest exit $code; failing suites: $($suiteFailures -join ', ')).`n    $($failed -join "`n    ")`n    Reports: $Script:LogDir`n    Full log: $Script:LogFile"
    }
}

function Step-Run {
    Write-Header "Starting the test client"

    if (-not (Test-Path $Script:ExePath)) {
        throw "Not built yet: $Script:ExePath. Run with -Build first."
    }
    $running = Get-Process -Name "nextclouddev" -ErrorAction SilentlyContinue
    if ($running) {
        Write-Warn "nextclouddev.exe is already running (PID $($running.Id -join ', ')); not starting a second one."
        return
    }
    if (Get-Process -Name "nextcloud" -ErrorAction SilentlyContinue) {
        Write-Info "The standard Nextcloud client is running: that is fine, the Dev variant has its own config folder (%APPDATA%\NextcloudDev)."
    }

    Set-RuntimePath
    Start-Process -FilePath $Script:ExePath -WorkingDirectory (Split-Path $Script:ExePath)
    Start-Sleep -Seconds 3
    if (-not (Get-Process -Name "nextclouddev" -ErrorAction SilentlyContinue)) {
        throw "nextclouddev.exe exited immediately. Usually a missing or mismatched DLL: run it from a console to see the message, and make sure the build and this script use the same Craft prefix (install-craft.ps1 -Verify)."
    }
    Write-Step "nextclouddev.exe is running (look for the tray icon)"
    Write-Info "First start: add ONLY your TEST account, with your TEST folder as the sync folder."
    Write-Info "Never add your real account to this client while you simulate attacks."
}

function Step-Simulate {
    Write-Header "Simulation: $Mode"

    if (-not $Sandbox) {
        throw "-Simulate needs -Sandbox <path to a folder named sentinel-sandbox inside the test client's sync folder>"
    }
    $resolved = $Sandbox
    if ($Mode -eq "seed" -and -not (Test-Path $Sandbox)) {
        Write-Step "Creating sandbox folder $Sandbox"
        New-Item -ItemType Directory -Path $Sandbox -Force | Out-Null
    }
    if (-not (Test-Path $Sandbox)) { throw "Sandbox folder does not exist: $Sandbox" }
    $resolved = (Resolve-Path $Sandbox).Path
    if ($resolved -notmatch "(^|[\\/])sentinel-sandbox([\\/]|$)") {
        throw "Refusing: the sandbox path must contain a folder named 'sentinel-sandbox' (got: $resolved). This is the only folder the simulator is allowed to damage."
    }

    $py = Find-Python
    $cmdArgs = @()
    $cmdArgs += $py.Args
    $cmdArgs += @("-I", $Script:SimulatorScript)
    switch ($Mode) {
        "seed"  { $cmdArgs += @("seed", $resolved, "--yes") }
        "reset" { $cmdArgs += @("reset", $resolved, "--yes") }
        default {
            $cmdArgs += @("attack", "--mode", $Mode, $resolved, "--yes")
            if ($Count -gt 0) { $cmdArgs += @("--count", "$Count") }
        }
    }

    Invoke-Native $py.Exe $cmdArgs -FailureHint "Read the simulator's message above (REFUSED lines explain the safety rule that stopped it)."

    switch ($Mode) {
        "seed"  { Write-Info "Now wait until the test client shows the folder as fully synced (green), then run an attack mode." }
        "reset" { Write-Info "Sandbox restored. If the Kill Switch is still triggered, reset it in the client (Settings > Kill Switch > Reset)." }
        default { Write-Info "Watch the test client: the Kill Switch dialog should appear and the folder should show as paused within one sync run. Then reset it in the client and run -Mode reset." }
    }
}

# ============================================================================
# Main
# ============================================================================

if ($All) { $Update = $true; $Build = $true; $Test = $true }
if (-not ($Update -or $Build -or $Test -or $Run -or $Simulate)) {
    Write-Host "Nothing to do. Use -All, or any of -Update -Build -Test -Run -Simulate. See the header of this script for examples."
    exit 2
}

New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
try { Start-Transcript -Path $Script:LogFile -Append | Out-Null } catch { Write-Warn "Could not start transcript: $($_.Exception.Message)" }

Write-Header "Nextcloud Sentinel - test pipeline"
Write-Info "Repository : $Script:RepoDir"
Write-Info "Branch     : $Branch"
Write-Info "Build dir  : $Script:BuildDir"
Write-Info "Log        : $Script:LogFile"

$exitCode = 0
$steps = @()
$steps += @{ Name = "Prerequisites"; Enabled = $true;      Action = { Step-Prerequisites } }
$steps += @{ Name = "Update";        Enabled = $Update;    Action = { Step-Update } }
$steps += @{ Name = "Build";         Enabled = $Build;     Action = { Step-Build } }
$steps += @{ Name = "Test";          Enabled = $Test;      Action = { Step-Test } }
$steps += @{ Name = "Run";           Enabled = $Run;       Action = { Step-Run } }
$steps += @{ Name = "Simulate";      Enabled = $Simulate;  Action = { Step-Simulate } }

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
if ($exitCode -ne 0) { Write-Info "Send the log file and the red lines above when asking for help." }

try { Stop-Transcript | Out-Null } catch { }
Set-Location $Script:RepoDir
exit $exitCode
