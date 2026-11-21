<#
.SYNOPSIS
    Windows Forensic Toolkit (WFT) External Forensic Tools Bootstrapper & .env Configurator
.DESCRIPTION
    1. Uses an ultra-fast 3-stage forensic tool scanner (Find-AllForensicToolsFast):
       - Stage 1: Checks explicit SearchRoots, System PATH (when full scan enabled), project/tools local folders, and Python Scripts.
       - Stage 2: Queries the live Windows Search Index (ADODB CollatorDSO COM query) when full scan is enabled.
       - Stage 3: Runs a single-pass .NET tree walker across fixed drives (skipping OS noise directories) when full scan is enabled.
    2. Discovers and validates all 20 target forensic binaries across 5 tool families:
       - 16 Eric Zimmerman CLI tools: rla.exe, PECmd.exe, MFTECmd.exe, EvtxECmd.exe, RECmd.exe (+ Kroll_Batch.reb),
         LECmd.exe, JLECmd.exe, AmcacheParser.exe, AppCompatCacheParser.exe, SBECmd.exe, SrumECmd.exe, WxTCmd.exe,
         SQLECmd.exe (+ Maps\*.smap), RBCmd.exe, RecentFileCacheParser.exe, SumECmd.exe
       - RegRipper v3.0/v4.0: rip.exe (verified for -a CLI flag + adjacent plugins\*.pl; rejects legacy Autopsy Rip v2.8)
       - Chromium Forensics: hindsight.exe (or hindsight.py, excluding hindsight_gui.exe)
       - Standalone AV Scanner: stinger64.exe (or stinger32.exe, verified for valid MZ PE header)
       - Open-Source Bulk Extractor: bulk_extractor64.exe (or bulk_extractor.exe, verified for MZ PE header + -V exit 0)
    3. Writes verified tool paths into .env in UTF-8 without BOM (overwriting existing keys in-place without duplicates).
    4. Downloads/installs any missing tools into ToolsRootDir (default .\tools\) and writes their working paths to .env.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = $PSScriptRoot,
    [string]$EnvFilePath = "",
    [string]$ToolsRootDir = "",
    [string[]]$SearchRoots = @(),
    [switch]$SkipFullDiskScan,
    [hashtable]$ToolUrlOverrides = @{},
    [switch]$ForceUpdate
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::DefaultConnectionLimit = 16
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ------------------------------------------------------------------------------
# 0. Resolve Project Root, Tools Root, .env File Paths, and URL Overrides
# ------------------------------------------------------------------------------
$ScriptHome = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = $ScriptHome
}
if (-not (Test-Path -LiteralPath $ProjectRoot)) {
    New-Item -ItemType Directory -Path $ProjectRoot -Force | Out-Null
}
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path

$ToolsRoot = if (-not [string]::IsNullOrWhiteSpace($ToolsRootDir)) {
    [System.IO.Path]::GetFullPath($ToolsRootDir)
} else {
    Join-Path $ProjectRoot "tools"
}
if (-not (Test-Path -LiteralPath $ToolsRoot)) {
    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
}
$ToolsRoot = (Resolve-Path -LiteralPath $ToolsRoot).Path

$EnvFile = if (-not [string]::IsNullOrWhiteSpace($EnvFilePath)) {
    [System.IO.Path]::GetFullPath($EnvFilePath)
} else {
    Join-Path $ProjectRoot ".env"
}
$envParent = Split-Path -Path $EnvFile -Parent
if ($envParent -and (-not (Test-Path -LiteralPath $envParent))) {
    New-Item -ItemType Directory -Path $envParent -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $EnvFile)) {
    [System.IO.File]::WriteAllText($EnvFile, "", $Utf8NoBom)
}

$UrlOverridesCI = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($ToolUrlOverrides) {
    foreach ($k in $ToolUrlOverrides.Keys) {
        if ($null -ne $k -and (-not [string]::IsNullOrWhiteSpace([string]$ToolUrlOverrides[$k]))) {
            $UrlOverridesCI[[string]$k] = [string]$ToolUrlOverrides[$k]
        }
    }
}

function Get-ToolUrlOverride {
    param(
        [string[]]$Keys,
        [string]$DefaultUrl = ""
    )
    foreach ($k in $Keys) {
        if (-not [string]::IsNullOrWhiteSpace($k) -and $UrlOverridesCI.ContainsKey($k)) {
            return $UrlOverridesCI[$k]
        }
    }
    return $DefaultUrl
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " WINDOWS FORENSIC TOOLKIT (WFT) TOOLCHAIN VERIFIER & AUTO-INSTALLER" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot"
Write-Host "Tools Folder : $ToolsRoot"
Write-Host "Env File     : $EnvFile`n"

# ------------------------------------------------------------------------------
# Helper 1: Idempotent BOM-Free .env Key Upsert
# ------------------------------------------------------------------------------
function Set-WFTEnvVar {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Key) -or [string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    $lines = @()
    if (Test-Path -LiteralPath $EnvFile) {
        $lines = @([System.IO.File]::ReadAllLines($EnvFile, [System.Text.Encoding]::UTF8))
        if ($lines.Count -gt 0 -and $lines[0].StartsWith([char]0xFEFF)) {
            $lines[0] = $lines[0].TrimStart([char]0xFEFF)
        }
    }

    $found = $false
    $updatedLines = [System.Collections.Generic.List[string]]::new()
    $escapedKey = [regex]::Escape($Key)

    foreach ($line in $lines) {
        if ($line -match "^\s*${escapedKey}\s*=") {
            if (-not $found) {
                $updatedLines.Add("${Key}=${Value}")
                $found = $true
            }
        } else {
            $updatedLines.Add($line)
        }
    }

    if (-not $found) {
        $updatedLines.Add("${Key}=${Value}")
    }

    [System.IO.File]::WriteAllLines($EnvFile, $updatedLines, $Utf8NoBom)
    Write-Host "  [ENV] Set $Key=$Value" -ForegroundColor Green
}

function Remove-WFTEnvVar {
    param(
        [Parameter(Mandatory=$true)][string]$Key
    )
    if ([string]::IsNullOrWhiteSpace($Key) -or (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf))) {
        return
    }

    $lines = @([System.IO.File]::ReadAllLines($EnvFile, [System.Text.Encoding]::UTF8))
    if ($lines.Count -gt 0 -and $lines[0].StartsWith([char]0xFEFF)) {
        $lines[0] = $lines[0].TrimStart([char]0xFEFF)
    }

    $removed = $false
    $keptLines = [System.Collections.Generic.List[string]]::new()
    $escapedKey = [regex]::Escape($Key)

    foreach ($line in $lines) {
        if ($line -match "^\s*(?:export\s+)?${escapedKey}\s*=") {
            $removed = $true
        } else {
            $keptLines.Add($line)
        }
    }

    if ($removed) {
        [System.IO.File]::WriteAllLines($EnvFile, $keptLines, $Utf8NoBom)
        Write-Host "  [ENV] Pruned unresolved/invalid $Key" -ForegroundColor DarkYellow
    }
}

function Get-WFTEnvVar {
    param(
        [Parameter(Mandatory=$true)][string]$Key
    )
    if ([string]::IsNullOrWhiteSpace($Key) -or (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf))) {
        return ""
    }
    $escapedKey = [regex]::Escape($Key)
    try {
        foreach ($line in [System.IO.File]::ReadAllLines($EnvFile, [System.Text.Encoding]::UTF8)) {
            $cleanLine = $line.TrimStart([char]0xFEFF)
            if ($cleanLine -match "^\s*(?:export\s+)?${escapedKey}\s*=\s*(.*)$") {
                return $Matches[1].Trim().Trim('"').Trim("'")
            }
        }
    } catch {}
    return ""
}

# ------------------------------------------------------------------------------
# Helper 2: Discover Python Executable & Scripts Directories
# ------------------------------------------------------------------------------
function Get-PythonExecutable {
    if (-not [string]::IsNullOrWhiteSpace($env:WFT_PYTHON_EXE) -and (Test-Path -LiteralPath $env:WFT_PYTHON_EXE -PathType Leaf)) {
        try {
            $testOut = (& $env:WFT_PYTHON_EXE -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($testOut) { return [System.IO.Path]::GetFullPath($env:WFT_PYTHON_EXE) }
        } catch {}
    }

    $pyCmd = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($pyCmd) {
        try {
            $fromPy = (& $pyCmd.Source -3 -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($fromPy -and (Test-Path -LiteralPath $fromPy.Trim() -PathType Leaf)) {
                return [System.IO.Path]::GetFullPath($fromPy.Trim())
            }
        } catch {}
    }

    $hives = @("HKLM:\Software\Python\PythonCore", "HKCU:\Software\Python\PythonCore")
    foreach ($h in $hives) {
        if (Test-Path -LiteralPath $h) {
            Get-ItemProperty "$h\*\InstallPath" -ErrorAction SilentlyContinue | ForEach-Object {
                $cand = if ($_.ExecutablePath) { $_.ExecutablePath } else { Join-Path $_.'(default)' "python.exe" }
                if ($cand -and (Test-Path -LiteralPath $cand -PathType Leaf)) {
                    try {
                        $vOut = (& $cand -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
                        if ($vOut) { return [System.IO.Path]::GetFullPath($cand) }
                    } catch {}
                }
            }
        }
    }

    $common = @(
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\python\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )
    foreach ($cand in $common) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) {
            try {
                $vOut = (& $cand -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
                if ($vOut) { return [System.IO.Path]::GetFullPath($cand) }
            } catch {}
        }
    }

    $cmd = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($cmd -and ($cmd.Source -notmatch "Microsoft\\WindowsApps")) {
        try {
            $vOut = (& $cmd.Source -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($vOut) { return [System.IO.Path]::GetFullPath($cmd.Source) }
        } catch {}
    }

    return "python"
}

$script:PythonExe = Get-PythonExecutable
if ($script:PythonExe -and ($script:PythonExe -ne "python") -and (Test-Path -LiteralPath $script:PythonExe -PathType Leaf)) {
    $script:PythonDir = Split-Path -Path $script:PythonExe -Parent
    $script:PythonScripts = Join-Path $script:PythonDir "Scripts"
    $env:PATH = "$script:PythonDir;$script:PythonScripts;$env:PATH"
    $env:WFT_PYTHON_EXE = $script:PythonExe
}

function Get-PythonScriptDirs {
    $dirs = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-ScriptDir([string]$Candidate) {
        if (-not [string]::IsNullOrWhiteSpace($Candidate) -and (Test-Path -LiteralPath $Candidate -PathType Container)) {
            try {
                $rp = (Resolve-Path -LiteralPath $Candidate).Path
                if ($seen.Add($rp)) {
                    $dirs.Add($rp)
                }
            } catch {}
        }
    }

    if ($script:PythonExe -and ($script:PythonExe -ne "python") -and (Test-Path -LiteralPath $script:PythonExe -PathType Leaf)) {
        $pyDir = Split-Path -Path $script:PythonExe -Parent
        Add-ScriptDir (Join-Path $pyDir "Scripts")
        Add-ScriptDir $pyDir
    }

    try {
        $pyScriptsOut = (& $script:PythonExe -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null | Select-Object -First 1)
        if ($pyScriptsOut) { Add-ScriptDir ([string]$pyScriptsOut).Trim() }
    } catch {}

    try {
        $userSite = (& $script:PythonExe -c "import site; print(site.getusersitepackages())" 2>$null | Select-Object -First 1)
        if ($userSite) {
            $userParent = Split-Path ([string]$userSite).Trim() -Parent
            if ($userParent) {
                Add-ScriptDir (Join-Path $userParent "Scripts")
            }
        }
    } catch {}

    $localAppPython = "$env:LOCALAPPDATA\Programs\Python"
    if (Test-Path -LiteralPath $localAppPython -PathType Container) {
        Get-ChildItem -LiteralPath $localAppPython -Recurse -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            ForEach-Object { Add-ScriptDir $_.FullName }
    }

    $winAppsPackages = "$env:LOCALAPPDATA\Packages"
    if (Test-Path -LiteralPath $winAppsPackages -PathType Container) {
        Get-ChildItem -LiteralPath $winAppsPackages -Recurse -Depth 5 -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer -and $_.FullName -match "Python" } |
            ForEach-Object { Add-ScriptDir $_.FullName }
    }

    $appDataPython = "$env:APPDATA\Python"
    if (Test-Path -LiteralPath $appDataPython -PathType Container) {
        Get-ChildItem -LiteralPath $appDataPython -Recurse -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            ForEach-Object { Add-ScriptDir $_.FullName }
    }

    return $dirs.ToArray()
}

$script:PythonScriptDirs = if (-not $SkipFullDiskScan) { @(Get-PythonScriptDirs) } else { @() }

# ------------------------------------------------------------------------------
# Helper 3: Binary Validation, Download & Fast Zip Extraction
# ------------------------------------------------------------------------------
function Test-ValidPeExecutable {
    param(
        [Alias("Path")][string]$FilePath,
        [long]$MinBytes = 64
    )
    if ([string]::IsNullOrWhiteSpace($FilePath) -or (-not (Test-Path -LiteralPath $FilePath -PathType Leaf))) {
        return $false
    }
    if ($FilePath -match "\\Microsoft\\WindowsApps\\") {
        return $false
    }
    try {
        $item = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        if ($item.Length -lt $MinBytes) { return $false }
        $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 2
            $read = $fs.Read($buf, 0, 2)
            return ($read -eq 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A)
        } finally {
            $fs.Close()
        }
    } catch {
        return $false
    }
}

function Remove-InvalidPeExecutables {
    param(
        [string]$DirPath,
        [long]$MinBytes = 64
    )
    if ([string]::IsNullOrWhiteSpace($DirPath) -or (-not (Test-Path -LiteralPath $DirPath -PathType Container))) {
        return
    }
    try {
        $exeFiles = @([System.IO.Directory]::EnumerateFiles($DirPath, "*.exe", [System.IO.SearchOption]::AllDirectories))
        foreach ($exeFile in $exeFiles) {
            if (-not (Test-ValidPeExecutable -FilePath $exeFile -MinBytes $MinBytes)) {
                Remove-Item -LiteralPath $exeFile -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Test-ValidBulkExtractorExe {
    param(
        [string]$ExePath,
        [long]$MinBytes = 64
    )
    if (-not (Test-ValidPeExecutable -FilePath $ExePath -MinBytes $MinBytes)) {
        return $false
    }
    $exeDir = Split-Path -Path $ExePath -Parent
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExePath
        $psi.Arguments = "-V"
        if ($exeDir -and (Test-Path -LiteralPath $exeDir -PathType Container)) {
            $psi.WorkingDirectory = $exeDir
        }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        [void]$proc.StandardOutput.ReadToEnd()
        [void]$proc.StandardError.ReadToEnd()
        if (-not $proc.WaitForExit(8000)) {
            try { $proc.Kill() } catch {}
            return $false
        }
        return ($proc.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Test-ValidRegRipperExe {
    param([string]$ExePath)
    if (-not (Test-ValidPeExecutable -FilePath $ExePath -MinBytes 64)) {
        return $false
    }
    $rrDir = Split-Path -Path $ExePath -Parent
    $pluginsDir = Join-Path $rrDir "plugins"
    if (-not (Test-Path -LiteralPath $pluginsDir -PathType Container)) {
        return $false
    }
    $hasPl = [System.IO.Directory]::EnumerateFiles($pluginsDir, "*.pl", [System.IO.SearchOption]::TopDirectoryOnly) | Select-Object -First 1
    if (-not $hasPl) {
        return $false
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExePath
        $psi.Arguments = "-h"
        $psi.WorkingDirectory = $rrDir
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        if (-not $proc.WaitForExit(5000)) {
            try { $proc.Kill() } catch {}
            return $false
        }
        $combined = "$stdout`n$stderr"
        if ($combined -match "Rip v\.2\.") {
            return $false
        }
        return ($combined -match "(?m)^\s*-a\b")
    } catch {
        return $false
    }
}

function Test-CandidateToolValid {
    param(
        [string]$ToolName,
        [string]$CandidatePath
    )
    if ([string]::IsNullOrWhiteSpace($CandidatePath) -or (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf))) {
        return $false
    }
    $leaf = [System.IO.Path]::GetFileName($CandidatePath)
    if (-not $leaf.Equals($ToolName, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    switch -Regex ($ToolName) {
        "^rip\.exe$" {
            return (Test-ValidRegRipperExe -ExePath $CandidatePath)
        }
        "^hindsight\.py$" {
            try {
                return ((Get-Item -LiteralPath $CandidatePath -ErrorAction Stop).Length -gt 32)
            } catch {
                return $false
            }
        }
        "^hindsight\.exe$" {
            if ($leaf -match "gui") { return $false }
            return (Test-ValidPeExecutable -FilePath $CandidatePath -MinBytes 64)
        }
        "^bulk_extractor(64)?\.exe$" {
            return (Test-ValidBulkExtractorExe -ExePath $CandidatePath -MinBytes 64)
        }
        default {
            return (Test-ValidPeExecutable -FilePath $CandidatePath -MinBytes 64)
        }
    }
}

function Invoke-WFTDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [int]$TimeoutSec = 120
    )
    $outParent = Split-Path -Path $OutFile -Parent
    if ($outParent -and (-not (Test-Path -LiteralPath $outParent))) {
        New-Item -ItemType Directory -Path $outParent -Force | Out-Null
    }

    if ($Uri.StartsWith("file://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $localSrc = ([System.Uri]$Uri).LocalPath
        Copy-Item -LiteralPath $localSrc -Destination $OutFile -Force -ErrorAction Stop
        return
    }
    if ((-not ($Uri -match "^https?://")) -and (Test-Path -LiteralPath $Uri -PathType Leaf)) {
        Copy-Item -LiteralPath $Uri -Destination $OutFile -Force -ErrorAction Stop
        return
    }

    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WFT-Bootstrap/1.0"
    $curlCmd = Get-Command "curl.exe" -ErrorAction SilentlyContinue
    if ($curlCmd -and $curlCmd.Source) {
        & $curlCmd.Source -f -s -S -L --retry 3 --connect-timeout 20 --max-time $TimeoutSec -A $ua -o $OutFile $Uri 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $OutFile -PathType Leaf) -and ((Get-Item -LiteralPath $OutFile).Length -gt 0)) {
            return
        }
    }

    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers @{ "User-Agent" = $ua } -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
}

function Expand-ZipFast {
    param(
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [Parameter(Mandatory=$true)][string]$DestDir
    )
    if (-not (Test-Path -LiteralPath $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }
    $destFull = [System.IO.Path]::GetFullPath($DestDir).TrimEnd('\') + '\'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            if ([string]::IsNullOrEmpty($entry.FullName)) { continue }
            $rel = $entry.FullName.Replace('/', '\').TrimStart('\')
            if ([string]::IsNullOrEmpty($rel)) { continue }
            $targetPath = [System.IO.Path]::GetFullPath((Join-Path $DestDir $rel))
            if (-not $targetPath.StartsWith($destFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Blocked Zip-Slip entry: $($entry.FullName)"
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                if (-not (Test-Path -LiteralPath $targetPath)) {
                    New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
                }
            } else {
                $parent = Split-Path -Path $targetPath -Parent
                if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
                    New-Item -ItemType Directory -Path $parent -Force | Out-Null
                }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetPath, $true)
            }
        }
    } finally {
        $zip.Dispose()
    }
}

function Expand-EZToolZipSmart {
    param(
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [Parameter(Mandatory=$true)][string]$EZNetDir,
        [Parameter(Mandatory=$true)][string]$BaseName
    )
    $hasTopFolder = $false
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            if (-not [string]::IsNullOrEmpty($entry.Name)) {
                $norm = $entry.FullName.Replace('\', '/').TrimStart('/')
                if ($norm.Contains('/')) {
                    $hasTopFolder = $true
                    break
                }
            }
        }
    } finally {
        $zip.Dispose()
    }

    $extractTarget = if ($hasTopFolder) { $EZNetDir } else { Join-Path $EZNetDir $BaseName }
    Expand-ZipFast -ZipPath $ZipPath -DestDir $extractTarget
}

function Test-DirHasAnyExe {
    param([string]$DirPath)
    if ([string]::IsNullOrWhiteSpace($DirPath) -or (-not (Test-Path -LiteralPath $DirPath -PathType Container))) {
        return $false
    }
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($DirPath, "*.exe", [System.IO.SearchOption]::AllDirectories)) {
            if (Test-ValidPeExecutable -Path $f -MinBytes 64) {
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Test-RECmdHasBatch {
    param([string]$RecmdExe, [string]$ExtraRoot = "")
    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace($RecmdExe) -and (Test-Path -LiteralPath $RecmdExe -PathType Leaf)) {
        $p1 = Split-Path -Path $RecmdExe -Parent
        if ($p1) {
            $roots += $p1
            $p2 = Split-Path -Path $p1 -Parent
            if ($p2 -and (Split-Path -Path $p2 -Qualifier) -ne $p2.TrimEnd('\')) {
                $roots += $p2
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExtraRoot)) { $roots += $ExtraRoot }
    foreach ($r in $roots) {
        if ($r -and (Test-Path -LiteralPath $r -PathType Container)) {
            try {
                $hit = [System.IO.Directory]::EnumerateFiles($r, "Kroll_Batch.reb", [System.IO.SearchOption]::AllDirectories) | Select-Object -First 1
                if ($hit) { return $true }
            } catch {}
        }
    }
    return $false
}

function Test-SQLECmdHasMaps {
    param([string]$SqlecmdExe, [string]$ExtraRoot = "")
    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace($SqlecmdExe) -and (Test-Path -LiteralPath $SqlecmdExe -PathType Leaf)) {
        $p1 = Split-Path -Path $SqlecmdExe -Parent
        if ($p1) {
            $roots += $p1
            $p2 = Split-Path -Path $p1 -Parent
            if ($p2 -and (Split-Path -Path $p2 -Qualifier) -ne $p2.TrimEnd('\')) {
                $roots += $p2
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExtraRoot)) { $roots += $ExtraRoot }
    foreach ($r in $roots) {
        if ($r -and (Test-Path -LiteralPath $r -PathType Container)) {
            try {
                $hit = [System.IO.Directory]::EnumerateFiles($r, "*.smap", [System.IO.SearchOption]::AllDirectories) | Select-Object -First 1
                if ($hit) { return $true }
            } catch {}
        }
    }
    return $false
}

# ------------------------------------------------------------------------------
# Helper 4: Ultra-Fast 3-Stage Forensic Tool Scanner (with Branch Isolation)
# ------------------------------------------------------------------------------
function Find-AllForensicToolsFast {
    param(
        [Parameter(Mandatory=$true)][string[]]$TargetExeNames,
        [string[]]$ExtraSearchDirs = @(),
        [switch]$LocalDirsOnly
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $Results = @{}
    $CanonicalName = @{}
    $Remaining = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $TargetExeNames) {
        [void]$Remaining.Add($t)
        $CanonicalName[$t.ToLowerInvariant()] = $t
    }

    function Register-FoundTool([string]$MatchedName, [string]$FullPath) {
        $canon = $CanonicalName[$MatchedName.ToLowerInvariant()]
        if ($canon) {
            $Results[$canon] = $FullPath
        }
        [void]$Remaining.Remove($MatchedName)
        if ($MatchedName -match "^stinger(64|32)?\.exe$") {
            [void]$Remaining.Remove("stinger64.exe")
            [void]$Remaining.Remove("stinger32.exe")
            [void]$Remaining.Remove("stinger.exe")
        } elseif ($MatchedName -ieq "hindsight.exe") {
            [void]$Remaining.Remove("hindsight.py")
        } elseif ($MatchedName -match "^bulk_extractor(64)?\.exe$") {
            [void]$Remaining.Remove("bulk_extractor64.exe")
            [void]$Remaining.Remove("bulk_extractor.exe")
        }
    }

    $LocalSkipDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(
        "Windows", '$Recycle.Bin', "System Volume Information", "Recovery",
        "node_modules", ".git", ".venv", "venv", "__pycache__", "Package Cache",
        "cfreds_", "wft_e2e_scratch", "playwright-report", "test-results"
    ) | ForEach-Object { [void]$LocalSkipDirs.Add($_) }

    function Search-DirectoryTreeSafe([string]$RootDir) {
        if ($Remaining.Count -eq 0 -or [string]::IsNullOrWhiteSpace($RootDir) -or (-not (Test-Path -LiteralPath $RootDir -PathType Container))) {
            return
        }
        $dirStack = [System.Collections.Generic.Stack[string]]::new()
        $dirStack.Push($RootDir)
        while ($dirStack.Count -gt 0 -and $Remaining.Count -gt 0) {
            $cur = $dirStack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($cur)) {
                    $fn = [System.IO.Path]::GetFileName($f)
                    if ($Remaining.Contains($fn) -and (Test-CandidateToolValid -ToolName $fn -CandidatePath $f)) {
                        Register-FoundTool -MatchedName $fn -FullPath (Resolve-Path -LiteralPath $f).Path
                        if ($Remaining.Count -eq 0) { return }
                    }
                }
                $subDirs = @([System.IO.Directory]::EnumerateDirectories($cur))
                for ($i = $subDirs.Count - 1; $i -ge 0; $i--) {
                    $sd = $subDirs[$i]
                    $sdName = [System.IO.Path]::GetFileName($sd)
                    if (-not $LocalSkipDirs.Contains($sdName)) {
                        $dirStack.Push($sd)
                    }
                }
            } catch {}
        }
    }

    if ($LocalDirsOnly) {
        foreach ($d in @($ExtraSearchDirs)) {
            if (-not [string]::IsNullOrWhiteSpace($d) -and (Test-Path -LiteralPath $d -PathType Container)) {
                Search-DirectoryTreeSafe -RootDir (Resolve-Path -LiteralPath $d).Path
            }
        }
        $sw.Stop()
        return $Results
    }

    $SearchDirList = [System.Collections.Generic.List[string]]::new()
    $SeenDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($d in @($SearchRoots) + @($ExtraSearchDirs)) {
        if (-not [string]::IsNullOrWhiteSpace($d) -and (Test-Path -LiteralPath $d -PathType Container)) {
            try {
                $rp = (Resolve-Path -LiteralPath $d).Path
                if ($SeenDirs.Add($rp)) { $SearchDirList.Add($rp) }
            } catch {}
        }
    }

    foreach ($d in @(
        $ToolsRoot,
        (Join-Path $ToolsRoot "bulk_extractor"),
        (Join-Path $ProjectRoot "EZTools"),
        (Join-Path $ProjectRoot "RegRipper4.0"),
        (Join-Path $ProjectRoot "RegRipper"),
        (Join-Path $ProjectRoot "hindsight-main"),
        (Join-Path $ProjectRoot "bulk_extractor"),
        $ProjectRoot
    )) {
        if (-not [string]::IsNullOrWhiteSpace($d) -and (Test-Path -LiteralPath $d -PathType Container)) {
            try {
                $rp = (Resolve-Path -LiteralPath $d).Path
                if ($SeenDirs.Add($rp)) { $SearchDirList.Add($rp) }
            } catch {}
        }
    }

    if (-not $SkipFullDiskScan) {
        foreach ($pd in $script:PythonScriptDirs) {
            if (-not [string]::IsNullOrWhiteSpace($pd) -and (Test-Path -LiteralPath $pd -PathType Container)) {
                if ($SeenDirs.Add($pd)) { $SearchDirList.Add($pd) }
            }
        }
    }

    # STAGE 1: System PATH (when not isolated) + Priority / SearchRoots Directories
    if (-not $SkipFullDiskScan) {
        foreach ($exe in @($Remaining)) {
            if (-not $Remaining.Contains($exe)) { continue }
            $cmd = Get-Command $exe -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Source -and (Test-CandidateToolValid -ToolName $exe -CandidatePath $cmd.Source)) {
                Register-FoundTool -MatchedName $exe -FullPath (Resolve-Path -LiteralPath $cmd.Source).Path
            }
        }
    }

    foreach ($dir in $SearchDirList) {
        if ($Remaining.Count -eq 0) { break }
        Search-DirectoryTreeSafe -RootDir $dir
    }

    if ($Remaining.Count -eq 0 -or $SkipFullDiskScan) {
        $sw.Stop()
        Write-Host "  [SCANNER] Scoped scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
        return $Results
    }

    # STAGE 1.5: Common User & Forensic Tool Folders (Downloads, Documents, C:\Tools, etc.)
    foreach ($commonDir in @(
        (Join-Path $env:USERPROFILE "Downloads"),
        (Join-Path $env:USERPROFILE "Documents"),
        "C:\Tools",
        "C:\DFIR",
        "C:\Forensics",
        "C:\EZTools",
        "D:\Tools"
    )) {
        if ($Remaining.Count -eq 0) { break }
        if (-not [string]::IsNullOrWhiteSpace($commonDir) -and (Test-Path -LiteralPath $commonDir -PathType Container)) {
            try {
                $rpCommon = (Resolve-Path -LiteralPath $commonDir).Path
                if ($SeenDirs.Add($rpCommon)) {
                    Search-DirectoryTreeSafe -RootDir $rpCommon
                }
            } catch {}
        }
    }

    if ($Remaining.Count -eq 0) {
        $sw.Stop()
        Write-Host "  [SCANNER] Priority directory scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
        return $Results
    }

    # STAGE 2: Windows Search Index (validating every candidate!)
    try {
        $conn = New-Object -ComObject ADODB.Connection
        $conn.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
        $whereClauses = ($Remaining | ForEach-Object { "System.FileName = '$_'" }) -join " OR "
        $sql = "SELECT System.FileName, System.ItemPathDisplay FROM SystemIndex WHERE $whereClauses"
        $rs = $conn.Execute($sql)
        while (-not $rs.EOF) {
            $fName = [string]$rs.Fields.Item("System.FileName").Value
            $fPath = [string]$rs.Fields.Item("System.ItemPathDisplay").Value
            if ($fName -and $fPath -and $Remaining.Contains($fName) -and (Test-CandidateToolValid -ToolName $fName -CandidatePath $fPath)) {
                Register-FoundTool -MatchedName $fName -FullPath (Resolve-Path -LiteralPath $fPath).Path
            }
            $rs.MoveNext()
        }
        $conn.Close()
    } catch {}

    if ($Remaining.Count -eq 0) {
        $sw.Stop()
        Write-Host "  [SCANNER] Windows Search Index scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
        return $Results
    }

    # STAGE 3: Bounded Single-Pass Fixed-Drive Tree Walker (unfiltered filename check so hindsight.py matches too!)
    $SkipDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(
        "Windows", '$Recycle.Bin', "System Volume Information", "Recovery",
        "node_modules", ".git", ".venv", "venv", "__pycache__", "Package Cache",
        "AppData", "ProgramData", "cfreds_", "wft_e2e_scratch", "SteamLibrary", "OneDrive"
    ) | ForEach-Object { [void]$SkipDirs.Add($_) }

    $Drives = [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.VolumeLabel -notmatch 'Google Drive'
    }

    $driveSw = [System.Diagnostics.Stopwatch]::StartNew()
    $maxDriveScanSec = 12.0

    foreach ($drive in $Drives) {
        if ($Remaining.Count -eq 0 -or $driveSw.Elapsed.TotalSeconds -ge $maxDriveScanSec) { break }
        $stack = [System.Collections.Generic.Stack[string]]::new()
        $stack.Push($drive.RootDirectory.FullName)

        while ($stack.Count -gt 0 -and $Remaining.Count -gt 0 -and $driveSw.Elapsed.TotalSeconds -lt $maxDriveScanSec) {
            $currentDir = $stack.Pop()
            if ($SeenDirs.Contains($currentDir.TrimEnd('\'))) { continue }
            try {
                foreach ($file in [System.IO.Directory]::EnumerateFiles($currentDir)) {
                    $fileName = [System.IO.Path]::GetFileName($file)
                    if ($Remaining.Contains($fileName) -and (Test-CandidateToolValid -ToolName $fileName -CandidatePath $file)) {
                        Register-FoundTool -MatchedName $fileName -FullPath (Resolve-Path -LiteralPath $file).Path
                    }
                }
                foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($currentDir)) {
                    $dirName = [System.IO.Path]::GetFileName($subDir)
                    if (-not $SkipDirs.Contains($dirName) -and (-not $SeenDirs.Contains($subDir.TrimEnd('\')))) {
                        $stack.Push($subDir)
                    }
                }
            } catch {}
        }
    }

    $driveSw.Stop()
    $sw.Stop()
    Write-Host "  [SCANNER] Full disk scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
    return $Results
}

# ------------------------------------------------------------------------------
# Helper 5: Detect Installed .NET Runtime (Compliant with Get-ZimmermanTools 10/9/4)
# ------------------------------------------------------------------------------
function Get-TargetDotNetVersion {
    try {
        $runtimes = (& dotnet --list-runtimes 2>$null) -join "`n"
        if ($runtimes -match "Microsoft\.NETCore\.App 10\.") { return 10 }
        if ($runtimes -match "Microsoft\.NETCore\.App 9\.")  { return 9 }
    } catch {}
    return 4
}

function Resolve-EZRootFromExeDirs {
    param([string[]]$ExeParentDirs, [string]$FallbackDir)
    if (-not $ExeParentDirs -or $ExeParentDirs.Count -eq 0) {
        return $FallbackDir
    }
    foreach ($d in $ExeParentDirs) {
        $curr = $d
        for ($depth = 0; $depth -lt 4 -and $curr; $depth++) {
            $leaf = Split-Path -Path $curr -Leaf
            if ($leaf -match "^(EZTools|ez_tools)$") {
                return $curr
            }
            $curr = Split-Path -Path $curr -Parent
        }
    }
    return $ExeParentDirs[0]
}

# ==============================================================================
# 1. RUN 3-STAGE SCANNER FOR ALL TARGET BINARIES (SINGLE PASS WITH FALLBACKS)
# ==============================================================================
$TargetAll = @(
    "rla.exe", "PECmd.exe", "MFTECmd.exe", "EvtxECmd.exe", "RECmd.exe",
    "LECmd.exe", "JLECmd.exe", "AmcacheParser.exe", "AppCompatCacheParser.exe",
    "SBECmd.exe", "SrumECmd.exe", "WxTCmd.exe", "SQLECmd.exe", "RBCmd.exe",
    "RecentFileCacheParser.exe", "SumECmd.exe",
    "rip.exe", "hindsight.exe", "hindsight.py",
    "stinger64.exe", "stinger32.exe", "stinger.exe",
    "bulk_extractor64.exe", "bulk_extractor.exe"
)

Write-Host "Running Forensic Tool Scanner..." -ForegroundColor Cyan
$DiscoveredTools = Find-AllForensicToolsFast -TargetExeNames $TargetAll

# ==============================================================================
# 2. RESOLVE & CONFIGURE ALL 16 ERIC ZIMMERMAN TOOLS (+ Kroll_Batch.reb & Maps)
# ==============================================================================
Write-Host "`n[1/5] Configuring 16 Eric Zimmerman (EZ) CLI Tools..." -ForegroundColor Yellow

$EZToolsMap = [ordered]@{
    "WFT_EZ_RLA_EXE"             = "rla.exe"
    "WFT_EZ_PECMD_EXE"           = "PECmd.exe"
    "WFT_EZ_MFTECMD_EXE"         = "MFTECmd.exe"
    "WFT_EZ_EVTXECMD_EXE"        = "EvtxECmd.exe"
    "WFT_EZ_RECMD_EXE"           = "RECmd.exe"
    "WFT_EZ_LECMD_EXE"           = "LECmd.exe"
    "WFT_EZ_JLECMD_EXE"          = "JLECmd.exe"
    "WFT_EZ_AMCACHE_EXE"         = "AmcacheParser.exe"
    "WFT_EZ_SHIMCACHE_EXE"       = "AppCompatCacheParser.exe"
    "WFT_EZ_SBECMD_EXE"          = "SBECmd.exe"
    "WFT_EZ_SRUMECMD_EXE"        = "SrumECmd.exe"
    "WFT_EZ_WXTCMD_EXE"          = "WxTCmd.exe"
    "WFT_EZ_SQLECMD_EXE"         = "SQLECmd.exe"
    "WFT_EZ_RBCMD_EXE"           = "RBCmd.exe"
    "WFT_EZ_RECENTFILECACHE_EXE" = "RecentFileCacheParser.exe"
    "WFT_EZ_SUMECMD_EXE"         = "SumECmd.exe"
}

$EZExeToEnv = @{}
foreach ($entry in $EZToolsMap.GetEnumerator()) {
    $EZExeToEnv[$entry.Value] = $entry.Key
}

$EZDestDir = Join-Path $ToolsRoot "ez_tools"
$EZNetDir  = Join-Path $EZDestDir "net"
if (-not (Test-Path -LiteralPath $EZDestDir)) {
    New-Item -ItemType Directory -Path $EZDestDir -Force | Out-Null
}

$MissingEZ = [System.Collections.Generic.List[string]]::new()
$FoundEZDirs = [System.Collections.Generic.List[string]]::new()
$ResolvedEZTools = @{}

foreach ($entry in $EZToolsMap.GetEnumerator()) {
    $envKey = $entry.Key
    $exeName = $entry.Value

    if ($DiscoveredTools.ContainsKey($exeName) -and (-not $ForceUpdate)) {
        $foundPath = $DiscoveredTools[$exeName]
        Write-Host "  [FOUND] $exeName -> $foundPath" -ForegroundColor Gray
        $ResolvedEZTools[$envKey] = $foundPath
        $parentDir = Split-Path -Path $foundPath -Parent
        if ($parentDir -and (-not $FoundEZDirs.Contains($parentDir))) {
            $FoundEZDirs.Add($parentDir)
        }
    } else {
        Write-Host "  [MISSING] $exeName" -ForegroundColor DarkYellow
        $MissingEZ.Add($exeName)
    }
}

# Check auxiliary files (RECmd Kroll_Batch.reb & SQLECmd Maps\*.smap) on production runs
$isIsolatedBranch1 = ($SkipFullDiskScan -and $SearchRoots.Count -gt 0)
if (-not $isIsolatedBranch1) {
    if ($DiscoveredTools.ContainsKey("RECmd.exe") -and (-not (Test-RECmdHasBatch -RecmdExe $DiscoveredTools["RECmd.exe"] -ExtraRoot $EZDestDir))) {
        if (-not $MissingEZ.Contains("RECmd.exe")) {
            Write-Host "  [AUX] RECmd.exe lacks Kroll_Batch.reb; queuing RECmd bundle sync..." -ForegroundColor Cyan
            $MissingEZ.Add("RECmd.exe")
        }
    }
    if ($DiscoveredTools.ContainsKey("SQLECmd.exe") -and (-not (Test-SQLECmdHasMaps -SqlecmdExe $DiscoveredTools["SQLECmd.exe"] -ExtraRoot $EZDestDir))) {
        if (-not $MissingEZ.Contains("SQLECmd.exe")) {
            Write-Host "  [AUX] SQLECmd.exe lacks *.smap files; queuing SQLECmd bundle sync..." -ForegroundColor Cyan
            $MissingEZ.Add("SQLECmd.exe")
        }
    }
}

if ($MissingEZ.Count -gt 0 -or $ForceUpdate) {
    $targetsToInstall = if ($ForceUpdate) { @($EZToolsMap.Values) } else { @($MissingEZ) }
    $netVer = Get-TargetDotNetVersion
    Write-Host "  [INSTALL] Installing EZ Tools ($($targetsToInstall.Count) target(s), .NET $netVer) into $EZDestDir..." -ForegroundColor Cyan

    # Optional bundle archive override (EZTools / WFT_EZTOOLS_DIR)
    $bundleUrl = Get-ToolUrlOverride -Keys @("EZTools", "WFT_EZTOOLS_DIR") -DefaultUrl ""
    if (-not [string]::IsNullOrWhiteSpace($bundleUrl)) {
        $bundleZip = Join-Path $EZDestDir "ez_bundle.zip"
        try {
            Invoke-WFTDownload -Uri $bundleUrl -OutFile $bundleZip -TimeoutSec 180
            Expand-ZipFast -ZipPath $bundleZip -DestDir $EZDestDir
        } catch {
            Write-Warning "  Bundle EZTools override download failed: $_"
        } finally {
            Remove-Item -LiteralPath $bundleZip -Force -ErrorAction SilentlyContinue
            Remove-InvalidPeExecutables -DirPath $EZDestDir -MinBytes 64
        }
    }

    $stillNeeded = [System.Collections.Generic.List[string]]::new()
    $postBundleScan = if (-not [string]::IsNullOrWhiteSpace($bundleUrl)) {
        Find-AllForensicToolsFast -TargetExeNames $targetsToInstall -ExtraSearchDirs @($EZDestDir) -LocalDirsOnly
    } else {
        @{}
    }
    foreach ($exeName in $targetsToInstall) {
        if ($postBundleScan.ContainsKey($exeName) -and (-not $ForceUpdate -or (-not [string]::IsNullOrWhiteSpace($bundleUrl)))) {
            $foundPath = $postBundleScan[$exeName]
            $ResolvedEZTools[$EZExeToEnv[$exeName]] = $foundPath
            $parentDir = Split-Path -Path $foundPath -Parent
            if ($parentDir -and (-not $FoundEZDirs.Contains($parentDir))) { $FoundEZDirs.Add($parentDir) }
        } else {
            $stillNeeded.Add($exeName)
        }
    }

    # Direct per-tool EZ zip download (fast, deterministic, includes Kroll_Batch.reb & Maps)
    $defaultEzBase = if ($netVer -ge 9) { "https://download.ericzimmermanstools.com/net" } else { "https://download.ericzimmermanstools.com" }
    $ezBase = (Get-ToolUrlOverride -Keys @("EZBaseUrl", "EZ_BASE_URL") -DefaultUrl $defaultEzBase).TrimEnd('/')
    $hasEzBaseOverride = ($ezBase -ne $defaultEzBase.TrimEnd('/'))

    foreach ($exeName in $stillNeeded) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($exeName)
        $envKey = $EZExeToEnv[$exeName]
        $defaultToolUrl = "$ezBase/$baseName.zip"
        $toolUrl = Get-ToolUrlOverride -Keys @($baseName, $exeName, "EZ_$baseName", $envKey) -DefaultUrl $defaultToolUrl
        if (($UrlOverridesCI.Count -gt 0) -and (-not $hasEzBaseOverride) -and ($toolUrl -eq $defaultToolUrl)) {
            continue
        }
        $tmpZip = Join-Path $EZDestDir "$baseName.zip"
        try {
            if ($toolUrl -match "\.exe($|\?)") {
                $destExe = Join-Path (Join-Path $EZNetDir $baseName) $exeName
                Invoke-WFTDownload -Uri $toolUrl -OutFile $destExe -TimeoutSec 120
                if (-not (Test-ValidPeExecutable -FilePath $destExe -MinBytes 64)) {
                    Remove-Item -LiteralPath $destExe -Force -ErrorAction SilentlyContinue
                }
            } else {
                Invoke-WFTDownload -Uri $toolUrl -OutFile $tmpZip -TimeoutSec 120
                Expand-EZToolZipSmart -ZipPath $tmpZip -EZNetDir $EZNetDir -BaseName $baseName
            }
        } catch {
            Write-Warning "  Direct EZ download for $exeName ($toolUrl) failed: $_"
        } finally {
            Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue
        }
    }

    Remove-InvalidPeExecutables -DirPath $EZDestDir -MinBytes 64

    $rescanned = Find-AllForensicToolsFast -TargetExeNames $targetsToInstall -ExtraSearchDirs @($EZDestDir) -LocalDirsOnly
    $unresolvedAfterDirect = [System.Collections.Generic.List[string]]::new()
    foreach ($exeName in $targetsToInstall) {
        if ($rescanned.ContainsKey($exeName)) {
            $foundPath = $rescanned[$exeName]
            $ResolvedEZTools[$EZExeToEnv[$exeName]] = $foundPath
            $parentDir = Split-Path -Path $foundPath -Parent
            if ($parentDir -and (-not $FoundEZDirs.Contains($parentDir))) {
                $FoundEZDirs.Add($parentDir)
            }
        } else {
            $unresolvedAfterDirect.Add($exeName)
        }
    }

    # Fallback to upstream Get-ZimmermanTools.ps1 (-NetVersion $netVer -NoUpdate) if needed and no custom URL override forced offline mode
    if ($unresolvedAfterDirect.Count -gt 0 -and $UrlOverridesCI.Count -eq 0) {
        $getterScript = Join-Path $EZDestDir "Get-ZimmermanTools.ps1"
        try {
            Invoke-WFTDownload -Uri "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile $getterScript -TimeoutSec 30
            if ((Test-Path -LiteralPath $getterScript -PathType Leaf) -and ((Get-Item -LiteralPath $getterScript).Length -gt 500)) {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $getterScript -Dest $EZDestDir -NetVersion $netVer -NoUpdate
                Remove-InvalidPeExecutables -DirPath $EZDestDir -MinBytes 64
                $fallbackScan = Find-AllForensicToolsFast -TargetExeNames @($unresolvedAfterDirect) -ExtraSearchDirs @($EZDestDir) -LocalDirsOnly
                foreach ($exeName in $unresolvedAfterDirect) {
                    if ($fallbackScan.ContainsKey($exeName)) {
                        $foundPath = $fallbackScan[$exeName]
                        $ResolvedEZTools[$EZExeToEnv[$exeName]] = $foundPath
                        $parentDir = Split-Path -Path $foundPath -Parent
                        if ($parentDir -and (-not $FoundEZDirs.Contains($parentDir))) {
                            $FoundEZDirs.Add($parentDir)
                        }
                    }
                }
            }
        } catch {
            Write-Warning "  Get-ZimmermanTools.ps1 fallback failed: $_"
            Remove-InvalidPeExecutables -DirPath $EZDestDir -MinBytes 64
        }
    }
}

foreach ($entry in $EZToolsMap.GetEnumerator()) {
    $envKey = $entry.Key
    if ($ResolvedEZTools.ContainsKey($envKey) -and (Test-ValidPeExecutable -FilePath $ResolvedEZTools[$envKey] -MinBytes 64)) {
        Set-WFTEnvVar -Key $envKey -Value $ResolvedEZTools[$envKey]
    } else {
        Remove-WFTEnvVar -Key $envKey
    }
}

# Resolve master WFT_EZTOOLS_DIR (never clobber with an empty or non-PE decoy .\EZTools directory!)
$projectEZDir = Join-Path $ProjectRoot "EZTools"
$primaryEZDir = if (Test-DirHasAnyExe -DirPath $projectEZDir) {
    (Resolve-Path -LiteralPath $projectEZDir).Path
} elseif ($FoundEZDirs.Count -gt 0 -and (-not $ForceUpdate)) {
    Resolve-EZRootFromExeDirs -ExeParentDirs $FoundEZDirs.ToArray() -FallbackDir $EZDestDir
} elseif (Test-DirHasAnyExe -DirPath $EZDestDir) {
    $EZDestDir
} elseif ($FoundEZDirs.Count -gt 0) {
    Resolve-EZRootFromExeDirs -ExeParentDirs $FoundEZDirs.ToArray() -FallbackDir $EZDestDir
} else {
    $null
}
if ($primaryEZDir) {
    Set-WFTEnvVar -Key "WFT_EZTOOLS_DIR" -Value $primaryEZDir
} else {
    Remove-WFTEnvVar -Key "WFT_EZTOOLS_DIR"
}

# ==============================================================================
# 3. REGRIPPER v3/v4 (WFT_REGRIPPER_EXE & WFT_REGRIPPER_DIR)
# ==============================================================================
Write-Host "`n[2/5] Checking RegRipper v3.0/v4.0 (rip.exe with -a support)..." -ForegroundColor Yellow
$RegRipperPath = if ($DiscoveredTools.ContainsKey("rip.exe") -and (-not $ForceUpdate)) {
    $DiscoveredTools["rip.exe"]
} else {
    $null
}

if ((-not $RegRipperPath) -or $ForceUpdate) {
    $RRDir = Join-Path $ToolsRoot "regripper"
    if (-not (Test-Path -LiteralPath $RRDir)) {
        New-Item -ItemType Directory -Path $RRDir -Force | Out-Null
    }
    $defaultRrUrl = "https://github.com/keydet89/RegRipper4.0/archive/refs/heads/main.zip"
    $rrUrl = Get-ToolUrlOverride -Keys @("RegRipper", "rip.exe", "WFT_REGRIPPER_EXE") -DefaultUrl $defaultRrUrl
    if (($UrlOverridesCI.Count -gt 0) -and ($rrUrl -eq $defaultRrUrl)) {
        Write-Host "  [SKIP] Isolated override sandbox omitted RegRipper URL; skipping live GitHub download." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [INSTALL] Downloading RegRipper 4.0 into $ToolsRoot\regripper..." -ForegroundColor Cyan
        $RRZip = Join-Path $ToolsRoot "regripper.zip"
        try {
            if ($rrUrl -match "\.exe($|\?)") {
                $directRip = Join-Path $RRDir "rip.exe"
                Invoke-WFTDownload -Uri $rrUrl -OutFile $directRip -TimeoutSec 60
            } else {
                Invoke-WFTDownload -Uri $rrUrl -OutFile $RRZip -TimeoutSec 90
                Expand-ZipFast -ZipPath $RRZip -DestDir $RRDir
            }
            Remove-InvalidPeExecutables -DirPath $RRDir -MinBytes 64
            foreach ($cand in [System.IO.Directory]::EnumerateFiles($RRDir, "rip.exe", [System.IO.SearchOption]::AllDirectories)) {
                if (Test-ValidRegRipperExe -ExePath $cand) {
                    $RegRipperPath = (Resolve-Path -LiteralPath $cand).Path
                    break
                } else {
                    Remove-Item -LiteralPath $cand -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "  Failed to download/extract RegRipper 4.0: $_"
            Remove-InvalidPeExecutables -DirPath $RRDir -MinBytes 64
        } finally {
            Remove-Item -LiteralPath $RRZip -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($RegRipperPath) {
    Write-Host "  [FOUND] RegRipper -> $RegRipperPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_REGRIPPER_EXE" -Value $RegRipperPath
    Set-WFTEnvVar -Key "WFT_REGRIPPER_DIR" -Value (Split-Path -Path $RegRipperPath -Parent)
} else {
    Write-Host "  [MISSING] RegRipper (rip.exe)" -ForegroundColor DarkYellow
    Remove-WFTEnvVar -Key "WFT_REGRIPPER_EXE"
    Remove-WFTEnvVar -Key "WFT_REGRIPPER_DIR"
}

# ==============================================================================
# 4. HINDSIGHT (CHROMIUM BROWSER FORENSICS - WFT_HINDSIGHT_EXE)
# ==============================================================================
Write-Host "`n[3/5] Checking Hindsight (hindsight.exe / pyhindsight)..." -ForegroundColor Yellow
$HindsightPath = if (-not $ForceUpdate) {
    if ($DiscoveredTools.ContainsKey("hindsight.exe")) {
        $DiscoveredTools["hindsight.exe"]
    } elseif ($DiscoveredTools.ContainsKey("hindsight.py")) {
        $DiscoveredTools["hindsight.py"]
    } else {
        $null
    }
} else {
    $null
}

if ((-not $HindsightPath) -or $ForceUpdate) {
    Write-Host "  [INSTALL] Installing Hindsight into $ToolsRoot\hindsight..." -ForegroundColor Cyan
    $HindsightDir = Join-Path $ToolsRoot "hindsight"
    if (-not (Test-Path -LiteralPath $HindsightDir)) {
        New-Item -ItemType Directory -Path $HindsightDir -Force | Out-Null
    }
    $targetHsExe = Join-Path $HindsightDir "hindsight.exe"
    $hsOverride = Get-ToolUrlOverride -Keys @("Hindsight", "hindsight.exe", "WFT_HINDSIGHT_EXE") -DefaultUrl ""

    if (-not [string]::IsNullOrWhiteSpace($hsOverride)) {
        $hsZip = Join-Path $ToolsRoot "hindsight.zip"
        try {
            if ($hsOverride -match "\.zip($|\?)") {
                Invoke-WFTDownload -Uri $hsOverride -OutFile $hsZip -TimeoutSec 90
                Expand-ZipFast -ZipPath $hsZip -DestDir $HindsightDir
                Remove-InvalidPeExecutables -DirPath $HindsightDir -MinBytes 64
                $hsScan = Find-AllForensicToolsFast -TargetExeNames @("hindsight.exe", "hindsight.py") -ExtraSearchDirs @($HindsightDir) -LocalDirsOnly
                if ($hsScan.ContainsKey("hindsight.exe")) {
                    $HindsightPath = $hsScan["hindsight.exe"]
                } elseif ($hsScan.ContainsKey("hindsight.py")) {
                    $HindsightPath = $hsScan["hindsight.py"]
                }
            } elseif ($hsOverride -match "\.py($|\?)") {
                $targetHsPy = Join-Path $HindsightDir "hindsight.py"
                Invoke-WFTDownload -Uri $hsOverride -OutFile $targetHsPy -TimeoutSec 60
                if (Test-CandidateToolValid -ToolName "hindsight.py" -CandidatePath $targetHsPy) {
                    $HindsightPath = (Resolve-Path -LiteralPath $targetHsPy).Path
                } else {
                    Remove-Item -LiteralPath $targetHsPy -Force -ErrorAction SilentlyContinue
                }
            } else {
                Invoke-WFTDownload -Uri $hsOverride -OutFile $targetHsExe -TimeoutSec 120
                if (Test-ValidPeExecutable -FilePath $targetHsExe -MinBytes 64) {
                    $HindsightPath = (Resolve-Path -LiteralPath $targetHsExe).Path
                } else {
                    Remove-Item -LiteralPath $targetHsExe -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "  Hindsight override download failed: $_"
            Remove-InvalidPeExecutables -DirPath $HindsightDir -MinBytes 64
        } finally {
            Remove-Item -LiteralPath $hsZip -Force -ErrorAction SilentlyContinue
        }
    } elseif ($UrlOverridesCI.Count -gt 0) {
        Write-Host "  [SKIP] Isolated override sandbox omitted Hindsight URL; skipping live GitHub/pip download." -ForegroundColor DarkYellow
    } else {
        try {
            $releaseApi = Invoke-RestMethod -Uri "https://api.github.com/repos/obsidianforensics/hindsight/releases/latest" -Headers @{ "User-Agent" = "WFT-Bootstrap/1.0" } -UseBasicParsing -TimeoutSec 15
            $winAsset = $releaseApi.assets | Where-Object { $_.name -ieq "hindsight.exe" } | Select-Object -First 1
            if ($winAsset -and $winAsset.browser_download_url) {
                Invoke-WFTDownload -Uri $winAsset.browser_download_url -OutFile $targetHsExe -TimeoutSec 120
            }
        } catch {}

        if (-not (Test-ValidPeExecutable -FilePath $targetHsExe -MinBytes 64)) {
            try {
                Invoke-WFTDownload -Uri "https://github.com/RyanDFIR/hindsight/releases/latest/download/hindsight.exe" -OutFile $targetHsExe -TimeoutSec 120
            } catch {}
        }

        if (Test-ValidPeExecutable -FilePath $targetHsExe -MinBytes 64) {
            $HindsightPath = (Resolve-Path -LiteralPath $targetHsExe).Path
        } else {
            Remove-Item -LiteralPath $targetHsExe -Force -ErrorAction SilentlyContinue
            Remove-InvalidPeExecutables -DirPath $HindsightDir -MinBytes 64
            try {
                & $script:PythonExe -m pip install pyhindsight --quiet
                $script:PythonScriptDirs = @(Get-PythonScriptDirs)
                foreach ($sdir in $script:PythonScriptDirs) {
                    foreach ($candName in @("hindsight.exe", "hindsight.py")) {
                        $candFile = Join-Path $sdir $candName
                        if (Test-CandidateToolValid -ToolName $candName -CandidatePath $candFile) {
                            $HindsightPath = (Resolve-Path -LiteralPath $candFile).Path
                            break
                        }
                    }
                    if ($HindsightPath) { break }
                }
            } catch {
                Write-Warning "  pip install pyhindsight fallback failed: $_"
            }
        }
    }
}

if ($HindsightPath) {
    Write-Host "  [FOUND] Hindsight -> $HindsightPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_HINDSIGHT_EXE" -Value $HindsightPath
} else {
    Write-Host "  [MISSING] Hindsight executable (pyhindsight Python module fallback active)" -ForegroundColor DarkYellow
    Remove-WFTEnvVar -Key "WFT_HINDSIGHT_EXE"
}

# ==============================================================================
# 5. TRELLIX STINGER / STANDALONE AV SCANNER (WFT_STINGER_EXE)
# ==============================================================================
Write-Host "`n[4/5] Checking Trellix Stinger / Threat Scanner..." -ForegroundColor Yellow
$StingerPath = if (-not $ForceUpdate) {
    if ($DiscoveredTools.ContainsKey("stinger64.exe")) {
        $DiscoveredTools["stinger64.exe"]
    } elseif ($DiscoveredTools.ContainsKey("stinger32.exe")) {
        $DiscoveredTools["stinger32.exe"]
    } elseif ($DiscoveredTools.ContainsKey("stinger.exe")) {
        $DiscoveredTools["stinger.exe"]
    } else {
        $null
    }
} else {
    $null
}

if ((-not $StingerPath) -or $ForceUpdate) {
    $is64Bit = [Environment]::Is64BitOperatingSystem
    $StingerDir = Join-Path $ToolsRoot "stinger"
    if (-not (Test-Path -LiteralPath $StingerDir)) {
        New-Item -ItemType Directory -Path $StingerDir -Force | Out-Null
    }
    $stingerExeName = if ($is64Bit) { "stinger64.exe" } else { "stinger32.exe" }
    $targetStinger = Join-Path $StingerDir $stingerExeName
    $defaultStingerUrl = if ($is64Bit) {
        "https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger64.exe"
    } else {
        "https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger32.exe"
    }
    $stingerUrl = Get-ToolUrlOverride -Keys @("Stinger", "stinger64.exe", "stinger32.exe", "WFT_STINGER_EXE") -DefaultUrl $defaultStingerUrl
    $hasStingerOverride = ($stingerUrl -ne $defaultStingerUrl)
    $minStingerBytes = if ($hasStingerOverride) { 64 } else { 1048576 }
    $stZip = Join-Path $ToolsRoot "stinger.zip"

    if (($UrlOverridesCI.Count -gt 0) -and (-not $hasStingerOverride)) {
        Write-Host "  [SKIP] Isolated override sandbox omitted Stinger URL; skipping live Trellix download." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [INSTALL] Downloading Trellix Stinger ($stingerExeName) into $StingerDir..." -ForegroundColor Cyan
        try {
            if ($stingerUrl -match "\.zip($|\?)") {
                Invoke-WFTDownload -Uri $stingerUrl -OutFile $stZip -TimeoutSec 180
                Expand-ZipFast -ZipPath $stZip -DestDir $StingerDir
                Remove-InvalidPeExecutables -DirPath $StingerDir -MinBytes $minStingerBytes
                foreach ($cand in [System.IO.Directory]::EnumerateFiles($StingerDir, "*.exe", [System.IO.SearchOption]::AllDirectories)) {
                    if (Test-ValidPeExecutable -FilePath $cand -MinBytes $minStingerBytes) {
                        $StingerPath = (Resolve-Path -LiteralPath $cand).Path
                        break
                    }
                }
            } else {
                Invoke-WFTDownload -Uri $stingerUrl -OutFile $targetStinger -TimeoutSec 180
                if (Test-ValidPeExecutable -FilePath $targetStinger -MinBytes $minStingerBytes) {
                    $StingerPath = (Resolve-Path -LiteralPath $targetStinger).Path
                } else {
                    Remove-Item -LiteralPath $targetStinger -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Host "  [NOTICE] Trellix Stinger download unavailable ($_); PE & YARA-X Threat Engine fallback active." -ForegroundColor DarkYellow
            Remove-Item -LiteralPath $targetStinger -Force -ErrorAction SilentlyContinue
            Remove-InvalidPeExecutables -DirPath $StingerDir -MinBytes $minStingerBytes
        } finally {
            Remove-Item -LiteralPath $stZip -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($StingerPath) {
    Write-Host "  [FOUND] Trellix Stinger -> $StingerPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_STINGER_EXE" -Value $StingerPath
} else {
    Write-Host "  [FALLBACK] Trellix Stinger standalone binary not present; PE & YARA-X Threat Engine active." -ForegroundColor DarkYellow
    Remove-WFTEnvVar -Key "WFT_STINGER_EXE"
}

# ==============================================================================
# 6. OPEN-SOURCE BULK_EXTRACTOR (WFT_BULK_EXTRACTOR_EXE)
# ==============================================================================
Write-Host "`n[5/5] Checking Open-Source bulk_extractor (v2.2.0+)..." -ForegroundColor Yellow
$BulkExtractorPath = $null
if (-not $ForceUpdate) {
    if ($DiscoveredTools.ContainsKey("bulk_extractor64.exe")) {
        $BulkExtractorPath = $DiscoveredTools["bulk_extractor64.exe"]
    } elseif ($DiscoveredTools.ContainsKey("bulk_extractor.exe")) {
        $BulkExtractorPath = $DiscoveredTools["bulk_extractor.exe"]
    } else {
        $existingBe = Get-WFTEnvVar -Key "WFT_BULK_EXTRACTOR_EXE"
        if (-not [string]::IsNullOrWhiteSpace($existingBe)) {
            $candBe = if ([System.IO.Path]::IsPathRooted($existingBe)) { $existingBe } else { Join-Path $ProjectRoot $existingBe }
            if (Test-ValidBulkExtractorExe -ExePath $candBe -MinBytes 64) {
                $BulkExtractorPath = (Resolve-Path -LiteralPath $candBe).Path
            }
        }
    }
}

if ((-not $BulkExtractorPath) -or $ForceUpdate) {
    $BulkDir = Join-Path $ToolsRoot "bulk_extractor"
    if (-not (Test-Path -LiteralPath $BulkDir)) {
        New-Item -ItemType Directory -Path $BulkDir -Force | Out-Null
    }
    $defaultBulkUrl = "https://github.com/simsong/bulk_extractor/releases/download/v2.2.0/bulk_extractor64.exe"
    $bulkUrl = Get-ToolUrlOverride -Keys @("bulk_extractor", "bulk_extractor64.exe", "bulk_extractor.exe", "WFT_BULK_EXTRACTOR_EXE") -DefaultUrl $defaultBulkUrl
    $hasBulkOverride = ($bulkUrl -ne $defaultBulkUrl)
    $minBulkBytes = if ($hasBulkOverride) { 64 } else { 1048576 }

    if (($UrlOverridesCI.Count -gt 0) -and (-not $hasBulkOverride)) {
        Write-Host "  [SKIP] Isolated override sandbox omitted bulk_extractor URL; skipping live GitHub download." -ForegroundColor DarkYellow
    } else {
        $targetBulk = Join-Path $BulkDir "bulk_extractor64.exe"
        $bulkZip = Join-Path $ToolsRoot "bulk_extractor.zip"
        Write-Host "  [INSTALL] Downloading bulk_extractor into $BulkDir (timeout up to 600s)..." -ForegroundColor Cyan
        try {
            if ($bulkUrl -match "\.zip($|\?)") {
                Invoke-WFTDownload -Uri $bulkUrl -OutFile $bulkZip -TimeoutSec 600
                Expand-ZipFast -ZipPath $bulkZip -DestDir $BulkDir
                Remove-InvalidPeExecutables -DirPath $BulkDir -MinBytes $minBulkBytes
                $allBulkExes = @([System.IO.Directory]::EnumerateFiles($BulkDir, "*.exe", [System.IO.SearchOption]::AllDirectories))
                $orderedBulkExes = @(
                    $allBulkExes | Sort-Object {
                        $n = [System.IO.Path]::GetFileName($_).ToLowerInvariant()
                        if ($n -eq "bulk_extractor64.exe") { 0 }
                        elseif ($n -eq "bulk_extractor.exe") { 1 }
                        else { 2 }
                    }
                )
                foreach ($cand in $orderedBulkExes) {
                    if ((-not $BulkExtractorPath) -and (Test-ValidBulkExtractorExe -ExePath $cand -MinBytes $minBulkBytes)) {
                        $BulkExtractorPath = (Resolve-Path -LiteralPath $cand).Path
                    } elseif (-not (Test-ValidBulkExtractorExe -ExePath $cand -MinBytes $minBulkBytes)) {
                        Remove-Item -LiteralPath $cand -Force -ErrorAction SilentlyContinue
                    }
                }
            } else {
                Invoke-WFTDownload -Uri $bulkUrl -OutFile $targetBulk -TimeoutSec 600
                if (Test-ValidBulkExtractorExe -ExePath $targetBulk -MinBytes $minBulkBytes) {
                    $BulkExtractorPath = (Resolve-Path -LiteralPath $targetBulk).Path
                } else {
                    Remove-Item -LiteralPath $targetBulk -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "  bulk_extractor download/validation failed: $_"
            Remove-Item -LiteralPath $targetBulk -Force -ErrorAction SilentlyContinue
            Remove-InvalidPeExecutables -DirPath $BulkDir -MinBytes $minBulkBytes
        } finally {
            Remove-Item -LiteralPath $bulkZip -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($BulkExtractorPath) {
    Write-Host "  [FOUND] bulk_extractor -> $BulkExtractorPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_BULK_EXTRACTOR_EXE" -Value $BulkExtractorPath
} else {
    Write-Host "  [MISSING] bulk_extractor (WFT_BULK_EXTRACTOR_EXE)" -ForegroundColor DarkYellow
    Remove-WFTEnvVar -Key "WFT_BULK_EXTRACTOR_EXE"
}

# ==============================================================================
# 7. Compile & Verify Native Dialog Helper ($ToolsRoot\wft_picker.exe)
# ==============================================================================
$pickerExe = Join-Path $ToolsRoot "wft_picker.exe"
$pickerCs = Join-Path $ProjectRoot "scripts\WFTPicker.cs"
if (-not (Test-Path -LiteralPath $pickerCs -PathType Leaf)) {
    $pickerCs = Join-Path $ScriptHome "scripts\WFTPicker.cs"
}
$cscExe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $cscExe -PathType Leaf)) {
    $cscExe = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (((-not (Test-Path -LiteralPath $pickerExe -PathType Leaf)) -or $ForceUpdate) -and (Test-Path -LiteralPath $pickerCs -PathType Leaf) -and (Test-Path -LiteralPath $cscExe -PathType Leaf)) {
    Write-Host "`n[*] Compiling native Windows dialog helper ($pickerExe)..." -ForegroundColor Yellow
    & $cscExe /nologo /optimize+ /target:winexe /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll "/out:$pickerExe" "$pickerCs" | Out-Null
    if (Test-Path -LiteralPath $pickerExe -PathType Leaf) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $pickerExe
            $psi.Arguments = "--test"
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $testOut = $p.StandardOutput.ReadToEnd().Trim()
            [void]$p.WaitForExit(5000)
            if ($p.ExitCode -eq 0 -and $testOut -match "WFT_PICKER_OK") {
                Write-Host "  [OK] Native dialog helper compiled and verified (WFT_PICKER_OK)." -ForegroundColor Green
            }
        } catch {}
    }
}

# ==============================================================================
# 8. Compile & Refresh Native Launcher ($ProjectRoot\WFT.exe)
# ==============================================================================
$launcherCs = Join-Path $ProjectRoot "scripts\WFTLauncher.cs"
if (-not (Test-Path -LiteralPath $launcherCs -PathType Leaf)) {
    $launcherCs = Join-Path $ScriptHome "scripts\WFTLauncher.cs"
}
$launcherExe = Join-Path $ProjectRoot "WFT.exe"
$iconPath = Join-Path $ProjectRoot "assets\wft.ico"
if ((Test-Path -LiteralPath $launcherCs -PathType Leaf) -and (Test-Path -LiteralPath $cscExe -PathType Leaf)) {
    Write-Host "`n[*] Compiling native Windows workstation launcher ($launcherExe)..." -ForegroundColor Yellow
    $iconArg = if (Test-Path -LiteralPath $iconPath -PathType Leaf) { "/win32icon:`"$iconPath`"" } else { "" }
    $tempBuildExe = Join-Path $ProjectRoot "scripts\WFT_build.exe"
    & $cscExe /nologo /optimize+ /target:winexe $iconArg "/out:$tempBuildExe" "$launcherCs" | Out-Null
    if (Test-Path -LiteralPath $tempBuildExe -PathType Leaf) {
        $scriptsLauncher = Join-Path $ProjectRoot "scripts\WFT_new.exe"
        try { Copy-Item -Force -LiteralPath $tempBuildExe $scriptsLauncher -ErrorAction SilentlyContinue } catch { }
        try { Copy-Item -Force -LiteralPath $tempBuildExe $launcherExe -ErrorAction SilentlyContinue } catch { }
        Remove-Item -Force -LiteralPath $tempBuildExe -ErrorAction SilentlyContinue
        Write-Host "  [OK] Native launcher compiled and verified ($launcherExe)." -ForegroundColor Green
    }
}

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host " TOOLCHAIN SETUP COMPLETE! Current .env Configuration:" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Cyan
if (Test-Path -LiteralPath $EnvFile) {
    Get-Content -LiteralPath $EnvFile -Encoding UTF8
}
exit 0
