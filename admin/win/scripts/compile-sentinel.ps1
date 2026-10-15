# Nextcloud Sentinel Edition - Windows Build Script
#
# SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Usage: .\compile-sentinel.ps1 [-BuildType Release|Debug] [-Clean] [-Configure] [-Build] [-Test] [-Dev]
#
# -Dev builds the "NextcloudDev" variant: separate executable (nextclouddev.exe),
# separate configuration folder (%APPDATA%\NextcloudDev) and separate
# single-instance lock, so it can run next to the standard Nextcloud client
# and never picks up its accounts and sync folders. Use it for every test
# session. The build directory gets a "-dev" suffix.

param(
    [ValidateSet("Release", "Debug", "RelWithDebInfo")]
    [string]$BuildType = "Release",

    [switch]$Clean,
    [switch]$Configure,
    [switch]$Build,
    [switch]$Test,
    [switch]$All,
    [switch]$Dev,

    [string]$QtPath = "",
    [string]$Generator = "Ninja",
    [int]$Jobs = 0
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# Configuration
# ============================================================================

$Script:SourceDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$Script:VariantSuffix = if ($Dev) { "-dev" } else { "" }
$Script:BuildDir = Join-Path $Script:SourceDir "build-windows-$BuildType$Script:VariantSuffix"
$Script:InstallDir = Join-Path $Script:SourceDir "install-windows-$BuildType$Script:VariantSuffix"

# Default Qt paths to search
$Script:QtSearchPaths = @(
    "C:\Qt\6.8.0\msvc2022_64",
    "C:\Qt\6.7.0\msvc2022_64",
    "$env:USERPROFILE\Qt\6.8.0\msvc2022_64",
    "$env:USERPROFILE\Qt\6.7.0\msvc2022_64"
)

# KDE Craft path (alternative dependency management)
$Script:CraftRoot = "$env:USERPROFILE\CraftRoot"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Find-QtPath {
    if ($Script:QtPath -ne "") {
        if (Test-Path $Script:QtPath) {
            return $Script:QtPath
        }
        Write-Error "Specified Qt path not found: $Script:QtPath"
        return $null
    }

    foreach ($path in $Script:QtSearchPaths) {
        if (Test-Path $path) {
            Write-Step "Found Qt at: $path"
            return $path
        }
    }

    # Check environment variable
    if ($env:Qt6_DIR -and (Test-Path $env:Qt6_DIR)) {
        return $env:Qt6_DIR
    }

    return $null
}

function Find-VSEnvironment {
    # Find Visual Studio installation
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path $vswhere)) {
        return $null
    }

    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if ($vsPath -and (Test-Path $vsPath)) {
        return $vsPath
    }

    return $null
}

function Initialize-VSEnvironment {
    param([string]$VSPath)

    $vcvarsall = Join-Path $VSPath "VC\Auxiliary\Build\vcvars64.bat"

    if (-not (Test-Path $vcvarsall)) {
        Write-Error "vcvars64.bat not found at: $vcvarsall"
        return $false
    }

    Write-Step "Initializing Visual Studio environment..."

    # Run vcvars64.bat and capture environment
    $envVars = cmd /c "`"$vcvarsall`" && set" 2>&1

    foreach ($line in $envVars) {
        if ($line -match "^([^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }

    return $true
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

function Test-Prerequisites {
    Write-Header "Checking Prerequisites"

    $allGood = $true

    # Check Visual Studio
    $vsPath = Find-VSEnvironment
    if ($vsPath) {
        Write-Step "Visual Studio found: $vsPath"
        if (-not (Initialize-VSEnvironment $vsPath)) {
            $allGood = $false
        }
    } else {
        Write-Error "Visual Studio 2022 with C++ workload not found"
        Write-Host "  Install from: https://visualstudio.microsoft.com/downloads/"
        $allGood = $false
    }

    # Check CMake
    if (Test-Command "cmake") {
        $cmakeVersion = (cmake --version | Select-Object -First 1)
        Write-Step "CMake found: $cmakeVersion"
    } else {
        Write-Error "CMake not found"
        Write-Host "  Install: winget install Kitware.CMake"
        $allGood = $false
    }

    # Check Ninja (if selected)
    if ($Generator -eq "Ninja") {
        if (Test-Command "ninja") {
            Write-Step "Ninja found"
        } else {
            Write-Warning "Ninja not found, falling back to MSBuild"
            $Script:Generator = "Visual Studio 17 2022"
        }
    }

    # Check Qt
    $qtPath = Find-QtPath
    if ($qtPath) {
        Write-Step "Qt6 found: $qtPath"
        $Script:QtPath = $qtPath
        $env:Qt6_DIR = $qtPath
        $env:PATH = "$qtPath\bin;$env:PATH"
    } else {
        Write-Error "Qt 6.7+ not found"
        Write-Host "  Install from: https://www.qt.io/download-qt-installer"
        Write-Host "  Or set -QtPath parameter"
        $allGood = $false
    }

    # Check Git
    if (Test-Command "git") {
        Write-Step "Git found"
    } else {
        Write-Error "Git not found"
        Write-Host "  Install: winget install Git.Git"
        $allGood = $false
    }

    # Check for ECM/KF6 (via Craft or vcpkg)
    $ecmFound = $false

    # Check Craft
    if (Test-Path "$Script:CraftRoot\craft\craftenv.ps1") {
        Write-Step "KDE Craft found at: $Script:CraftRoot"
        $ecmFound = $true
    }

    # Check vcpkg
    if ($env:VCPKG_ROOT -and (Test-Path $env:VCPKG_ROOT)) {
        Write-Step "vcpkg found at: $env:VCPKG_ROOT"
        $ecmFound = $true
    }

    if (-not $ecmFound) {
        Write-Warning "ECM/KF6 not found via Craft or vcpkg"
        Write-Host "  Run: .\install-dependencies.ps1 to install via KDE Craft"
    }

    return $allGood
}

# ============================================================================
# Build Steps
# ============================================================================

function Invoke-Clean {
    Write-Header "Cleaning Build Directory"

    if (Test-Path $Script:BuildDir) {
        Write-Step "Removing: $Script:BuildDir"
        Remove-Item -Recurse -Force $Script:BuildDir
    }

    if (Test-Path $Script:InstallDir) {
        Write-Step "Removing: $Script:InstallDir"
        Remove-Item -Recurse -Force $Script:InstallDir
    }

    Write-Step "Clean complete"
}

function Invoke-Configure {
    Write-Header "Configuring CMake"

    if (-not (Test-Path $Script:BuildDir)) {
        New-Item -ItemType Directory -Path $Script:BuildDir | Out-Null
    }

    Push-Location $Script:BuildDir

    try {
        $cmakeArgs = @(
            "-S", $Script:SourceDir,
            "-B", $Script:BuildDir,
            "-G", $Script:Generator,
            "-DCMAKE_BUILD_TYPE=$BuildType",
            "-DCMAKE_INSTALL_PREFIX=$Script:InstallDir",
            "-DCMAKE_PREFIX_PATH=$Script:QtPath",
            "-DBUILD_TESTING=ON",
            "-DBUILD_UPDATER=ON",
            "-DWITH_CRASHREPORTER=OFF"
        )

        if ($Dev) {
            # NextcloudDev identity: own exe name, own config folder, own
            # single-instance lock. Safe to run next to the real client.
            $cmakeArgs += "-DNEXTCLOUD_DEV=ON"
            Write-Step "Dev variant: building nextclouddev.exe (separate config folder)"
        }

        # Add Ninja-specific options
        if ($Script:Generator -eq "Ninja") {
            $cmakeArgs += "-DCMAKE_C_COMPILER=cl"
            $cmakeArgs += "-DCMAKE_CXX_COMPILER=cl"
        }

        # Add vcpkg toolchain if available
        if ($env:VCPKG_ROOT) {
            $toolchain = Join-Path $env:VCPKG_ROOT "scripts\buildsystems\vcpkg.cmake"
            if (Test-Path $toolchain) {
                $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchain"
                $cmakeArgs += "-DVCPKG_TARGET_TRIPLET=x64-windows"
            }
        }

        # Add Craft paths if available
        if (Test-Path "$Script:CraftRoot\craft") {
            $cmakeArgs += "-DCMAKE_PREFIX_PATH=$Script:CraftRoot;$Script:QtPath"
        }

        Write-Step "Running CMake configure..."
        Write-Host "cmake $($cmakeArgs -join ' ')"

        & cmake @cmakeArgs

        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed"
        }

        Write-Step "Configuration complete"
    }
    finally {
        Pop-Location
    }
}

function Invoke-Build {
    Write-Header "Building Project"

    if (-not (Test-Path $Script:BuildDir)) {
        throw "Build directory not found. Run -Configure first."
    }

    $buildArgs = @(
        "--build", $Script:BuildDir,
        "--config", $BuildType
    )

    if ($Jobs -gt 0) {
        $buildArgs += "--parallel"
        $buildArgs += $Jobs
    } else {
        $buildArgs += "--parallel"
    }

    Write-Step "Building..."
    & cmake @buildArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    Write-Step "Build complete"
}

function Invoke-Test {
    Write-Header "Running Tests"

    if (-not (Test-Path $Script:BuildDir)) {
        throw "Build directory not found. Run -Configure and -Build first."
    }

    Push-Location $Script:BuildDir

    try {
        Write-Step "Running CTest..."

        $ctestArgs = @(
            "--output-on-failure",
            "-C", $BuildType,
            "--timeout", "300"
        )

        & ctest @ctestArgs

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Some tests failed"
        } else {
            Write-Step "All tests passed"
        }
    }
    finally {
        Pop-Location
    }
}

# ============================================================================
# Main
# ============================================================================

Write-Header "Nextcloud Sentinel Edition - Windows Build"
Write-Host "Source:     $Script:SourceDir"
Write-Host "Build:      $Script:BuildDir"
Write-Host "Build Type: $BuildType"
Write-Host "Generator:  $Generator"
Write-Host ""

# If no action specified, default to Configure + Build
if (-not ($Clean -or $Configure -or $Build -or $Test -or $All)) {
    $All = $true
}

if ($All) {
    $Configure = $true
    $Build = $true
}

# Check prerequisites
if (-not (Test-Prerequisites)) {
    Write-Error "Prerequisites check failed. Please install missing dependencies."
    exit 1
}

# Execute requested actions
try {
    if ($Clean) {
        Invoke-Clean
    }

    if ($Configure) {
        Invoke-Configure
    }

    if ($Build) {
        Invoke-Build
    }

    if ($Test) {
        Invoke-Test
    }

    Write-Header "Build Completed Successfully"
    Write-Host "Output: $Script:BuildDir\bin"
    Write-Host ""

} catch {
    Write-Error $_.Exception.Message
    exit 1
}
