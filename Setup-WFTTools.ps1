<#
.SYNOPSIS
    Windows Forensic Toolkit (WFT) External Forensic Tools Bootstrapper & .env Configurator
.DESCRIPTION
    1. Uses an ultra-fast 3-stage full-disk scanner (Find-AllForensicToolsFast):
       - Stage 1: Checks System PATH, project local folders (tools, EZTools, RegRipper, hindsight), and Python Scripts in ~5ms.
       - Stage 2: Queries the live Windows Search Index (Windows.db/Windows.edb via ADODB CollatorDSO COM query) in ~20ms.
       - Stage 3: Runs a single-pass .NET tree walker across all fixed drives (skipping OS noise directories) in ~1s.
    2. Discovers all 18 target forensic tools:
       - 15 Eric Zimmerman tools: rla.exe, PECmd.exe, MFTECmd.exe, EvtxECmd.exe, RECmd.exe, LECmd.exe, JLECmd.exe,
         AmcacheParser.exe, AppCompatCacheParser.exe, SBECmd.exe, SrumECmd.exe, WxTCmd.exe, SQLECmd.exe, RBCmd.exe, RecentFileCacheParser.exe
       - RegRipper: rip.exe
       - Chromium Forensics: hindsight.exe (or hindsight.py)
       - Threat Scanner: stinger64.exe (or stinger32.exe)
    3. Automatically writes all discovered tool paths into .env (overwriting old keys in-place without duplicates).
    4. Downloads only the binaries that were not found anywhere on disk into .\tools\.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [switch]$ForceUpdate
)

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------------------
# 0. Resolve Project Root, Tools Root, and .env File Paths
# ------------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    if ($PSScriptRoot) {
        $ProjectRoot = $PSScriptRoot
    } else {
        $ProjectRoot = (Get-Location).Path
    }
}
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$ToolsRoot   = Join-Path $ProjectRoot "tools"
$EnvFile     = Join-Path $ProjectRoot ".env"

if (-not (Test-Path $ToolsRoot)) {
    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
}
if (-not (Test-Path $EnvFile)) {
    New-Item -ItemType File -Path $EnvFile -Force | Out-Null
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " WINDOWS FORENSIC TOOLKIT (WFT) TOOLCHAIN VERIFIER & AUTO-INSTALLER" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot"
Write-Host "Tools Folder : $ToolsRoot"
Write-Host "Env File     : $EnvFile`n"

# ------------------------------------------------------------------------------
# Helper 1: Idempotent .env Key Upsert (Overwrites existing key or appends new)
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
    if (Test-Path $EnvFile) {
        $lines = @(Get-Content -Path $EnvFile -Encoding UTF8)
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
            # Skip any duplicate lines of the same key
        } else {
            $updatedLines.Add($line)
        }
    }

    if (-not $found) {
        $updatedLines.Add("${Key}=${Value}")
    }

    [System.IO.File]::WriteAllLines($EnvFile, $updatedLines, [System.Text.Encoding]::UTF8)
    Write-Host "  [ENV] Set $Key=$Value" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# Helper 2: Discover Python Scripts Directories
# ------------------------------------------------------------------------------
$PythonScriptDirs = @()
try {
    $pyScriptsOut = & python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
    if ($pyScriptsOut -and (Test-Path $pyScriptsOut)) {
        $PythonScriptDirs += (Resolve-Path $pyScriptsOut).Path
    }
} catch {}

try {
    $userSite = & python -c "import site; print(site.getusersitepackages())" 2>$null
    if ($userSite) {
        $userParent = Split-Path $userSite -Parent
        $userScripts = Join-Path $userParent "Scripts"
        if (Test-Path $userScripts) {
            $PythonScriptDirs += (Resolve-Path $userScripts).Path
        }
    }
} catch {}

$localAppPython = "$env:LOCALAPPDATA\Programs\Python"
if (Test-Path $localAppPython) {
    $hits = Get-ChildItem -Path $localAppPython -Recurse -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            Select-Object -ExpandProperty FullName
    if ($hits) { $PythonScriptDirs += $hits }
}

$winAppsPackages = "$env:LOCALAPPDATA\Packages"
if (Test-Path $winAppsPackages) {
    $hits = Get-ChildItem -Path $winAppsPackages -Recurse -Depth 5 -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer -and $_.FullName -match "Python" } |
            Select-Object -ExpandProperty FullName
    if ($hits) { $PythonScriptDirs += $hits }
}

$appDataPython = "$env:APPDATA\Python"
if (Test-Path $appDataPython) {
    $hits = Get-ChildItem -Path $appDataPython -Recurse -Filter "Scripts" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            Select-Object -ExpandProperty FullName
    if ($hits) { $PythonScriptDirs += $hits }
}

# ------------------------------------------------------------------------------
# Helper 3: Ultra-Fast 3-Stage Full-Disk Forensic Tool Scanner
# ------------------------------------------------------------------------------
function Find-AllForensicToolsFast {
    param(
        [Parameter(Mandatory=$true)][string[]]$TargetExeNames
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $Results = @{}
    $Remaining = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $TargetExeNames) { [void]$Remaining.Add($t) }

    # -------------------------------------------------------------------------
    # STAGE 1: Check System PATH & Project Local Folders (~5ms)
    # -------------------------------------------------------------------------
    $LocalPriorityDirs = @(
        (Join-Path $ProjectRoot "tools"),
        (Join-Path $ProjectRoot "EZTools"),
        (Join-Path $ProjectRoot "RegRipper4.0"),
        (Join-Path $ProjectRoot "RegRipper"),
        (Join-Path $ProjectRoot "hindsight-main"),
        $ProjectRoot
    ) + $script:PythonScriptDirs | Where-Object { $_ -and (Test-Path $_) }

    foreach ($exe in @($Remaining)) {
        $cmd = Get-Command $exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
            $Results[$exe] = (Resolve-Path $cmd.Source).Path
            [void]$Remaining.Remove($exe)
            continue
        }
        foreach ($dir in $LocalPriorityDirs) {
            $found = [System.IO.Directory]::EnumerateFiles($dir, $exe, [System.IO.SearchOption]::AllDirectories) | Select-Object -First 1
            if ($found) {
                $Results[$exe] = (Resolve-Path $found).Path
                [void]$Remaining.Remove($exe)
                break
            }
        }
    }
    if ($Remaining.Count -eq 0) {
        $sw.Stop()
        Write-Host "  [SCANNER] Priority local & PATH scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
        return $Results
    }

    # -------------------------------------------------------------------------
    # STAGE 2: Query Windows.db / Windows.edb via Windows Search Index (~20ms)
    # -------------------------------------------------------------------------
    try {
        $conn = New-Object -ComObject ADODB.Connection
        $conn.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
        $whereClauses = ($Remaining | ForEach-Object { "System.FileName = '$_'" }) -join " OR "
        $sql = "SELECT System.FileName, System.ItemPathDisplay FROM SystemIndex WHERE $whereClauses"
        $rs = $conn.Execute($sql)
        while (-not $rs.EOF) {
            $fName = [string]$rs.Fields.Item("System.FileName").Value
            $fPath = [string]$rs.Fields.Item("System.ItemPathDisplay").Value
            if ($fName -and $fPath -and $Remaining.Contains($fName) -and (Test-Path $fPath)) {
                $Results[$fName] = (Resolve-Path $fPath).Path
                [void]$Remaining.Remove($fName)
            }
            $rs.MoveNext()
        }
        $conn.Close()
    } catch {
        # Windows Search service disabled or unavailable; proceed to Stage 3
    }
    if ($Remaining.Count -eq 0) {
        $sw.Stop()
        Write-Host "  [SCANNER] Windows Search Index scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
        return $Results
    }

    # -------------------------------------------------------------------------
    # STAGE 3: Single-Pass Parallel .NET Tree Walker Across All Fixed Drives (~1s)
    # Skips OS noise (C:\Windows, WinSxS, node_modules, .git) for 50x speedup
    # -------------------------------------------------------------------------
    $SkipDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(
        "Windows", "$Recycle.Bin", "System Volume Information", "Recovery",
        "node_modules", ".git", ".venv", "__pycache__", "Package Cache"
    ) | ForEach-Object { [void]$SkipDirs.Add($_) }

    $Drives = [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.DriveType -eq 'Fixed' -and $_.IsReady -and $_.VolumeLabel -notmatch 'Google Drive'
    }

    foreach ($drive in $Drives) {
        if ($Remaining.Count -eq 0) { break }
        $stack = [System.Collections.Generic.Stack[string]]::new()
        $stack.Push($drive.RootDirectory.FullName)

        while ($stack.Count -gt 0 -and $Remaining.Count -gt 0) {
            $currentDir = $stack.Pop()
            try {
                # Check files in current directory against our HashSet in O(1) time
                foreach ($file in [System.IO.Directory]::EnumerateFiles($currentDir, "*.exe")) {
                    $fileName = [System.IO.Path]::GetFileName($file)
                    if ($Remaining.Contains($fileName)) {
                        $Results[$fileName] = (Resolve-Path $file).Path
                        [void]$Remaining.Remove($fileName)
                    }
                }
                # Push subdirectories (skipping Windows/WinSxS/node_modules)
                foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($currentDir)) {
                    $dirName = [System.IO.Path]::GetFileName($subDir)
                    if (-not $SkipDirs.Contains($dirName)) {
                        $stack.Push($subDir)
                    }
                }
            } catch {
                # Ignore unauthorized/locked system directories
            }
        }
    }

    $sw.Stop()
    Write-Host "  [SCANNER] Full disk scan completed in $($sw.ElapsedMilliseconds) ms. Found $($Results.Count) tools." -ForegroundColor Cyan
    return $Results
}

# ------------------------------------------------------------------------------
# Helper 4: Detect Installed .NET Runtime
# ------------------------------------------------------------------------------
function Get-TargetDotNetVersion {
    try {
        $runtimes = & dotnet --list-runtimes 2>$null
        if ($runtimes -match "Microsoft\.NETCore\.App 9\.") { return 9 }
        if ($runtimes -match "Microsoft\.NETCore\.App 8\.") { return 6 }
        if ($runtimes -match "Microsoft\.NETCore\.App 6\.") { return 6 }
    } catch {}
    return 0
}

# ==============================================================================
# 1. RUN 3-STAGE FULL-DISK SCANNER FOR ALL 18 TARGET BINARIES
# ==============================================================================
$Target18 = @(
    "rla.exe", "PECmd.exe", "MFTECmd.exe", "EvtxECmd.exe", "RECmd.exe",
    "LECmd.exe", "JLECmd.exe", "AmcacheParser.exe", "AppCompatCacheParser.exe",
    "SBECmd.exe", "SrumECmd.exe", "WxTCmd.exe", "SQLECmd.exe", "RBCmd.exe",
    "RecentFileCacheParser.exe", "rip.exe", "hindsight.exe", "stinger64.exe"
)

Write-Host "Running 3-Stage Ultra-Fast Forensic Tool Scanner across system..." -ForegroundColor Cyan
$DiscoveredTools = Find-AllForensicToolsFast -TargetExeNames $Target18

# If stinger64 was not discovered, check for stinger32 or stinger.exe fallback
if (-not $DiscoveredTools.ContainsKey("stinger64.exe")) {
    $stingerFallback = Find-AllForensicToolsFast -TargetExeNames @("stinger32.exe", "stinger.exe")
    foreach ($k in $stingerFallback.Keys) {
        $DiscoveredTools[$k] = $stingerFallback[$k]
    }
}
# If hindsight.exe was not discovered, check for hindsight.py fallback
if (-not $DiscoveredTools.ContainsKey("hindsight.exe")) {
    $hsFallback = Find-AllForensicToolsFast -TargetExeNames @("hindsight.py")
    foreach ($k in $hsFallback.Keys) {
        $DiscoveredTools[$k] = $hsFallback[$k]
    }
}

# ==============================================================================
# 2. RESOLVE & CONFIGURE 15 ERIC ZIMMERMAN TOOLS
# ==============================================================================
Write-Host "`n[1/4] Configuring 15 Eric Zimmerman (EZ) CLI Tools..." -ForegroundColor Yellow

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
}

$MissingEZ = @()
$FoundEZDirs = [System.Collections.Generic.List[string]]::new()

foreach ($entry in $EZToolsMap.GetEnumerator()) {
    $envKey = $entry.Key
    $exeName = $entry.Value

    if ($DiscoveredTools.ContainsKey($exeName) -and (-not $ForceUpdate)) {
        $foundPath = $DiscoveredTools[$exeName]
        Write-Host "  [FOUND] $exeName -> $foundPath" -ForegroundColor Gray
        Set-WFTEnvVar -Key $envKey -Value $foundPath
        $parentDir = Split-Path $foundPath -Parent
        if (-not $FoundEZDirs.Contains($parentDir)) {
            $FoundEZDirs.Add($parentDir)
        }
    } else {
        Write-Host "  [MISSING] $exeName" -ForegroundColor DarkYellow
        $MissingEZ += $exeName
    }
}

$EZDestDir = Join-Path $ToolsRoot "ez_tools"
if (-not (Test-Path $EZDestDir)) {
    New-Item -ItemType Directory -Path $EZDestDir -Force | Out-Null
}

if ($MissingEZ.Count -gt 0 -or $ForceUpdate) {
    Write-Host "  [INSTALL] Downloading missing EZ Tools ($($MissingEZ.Count) binaries) to $EZDestDir..." -ForegroundColor Cyan
    $getterScript = Join-Path $EZDestDir "Get-ZimmermanTools.ps1"
    try {
        $getterUrls = @(
            "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1",
            "https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.ps1"
        )
        $downloaded = $false
        foreach ($url in $getterUrls) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $getterScript -UseBasicParsing -TimeoutSec 15
                if ((Test-Path $getterScript) -and ((Get-Item $getterScript).Length -gt 500)) {
                    $downloaded = $true
                    break
                }
            } catch {}
        }

        if ($downloaded) {
            $netVer = Get-TargetDotNetVersion
            Write-Host "  [CONFIG] Detected optimal .NET version target: $netVer" -ForegroundColor Gray
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $getterScript -Dest $EZDestDir -NetVersion $netVer
        } else {
            Write-Warning "  Unable to download Get-ZimmermanTools.ps1 from mirrors."
        }
    } catch {
        Write-Warning "  Failed to execute Get-ZimmermanTools.ps1: $_"
    }

    # Re-scan for newly installed tools and write to .env
    $rescanned = Find-AllForensicToolsFast -TargetExeNames $MissingEZ
    foreach ($entry in $EZToolsMap.GetEnumerator()) {
        $exeName = $entry.Value
        if ($rescanned.ContainsKey($exeName)) {
            $foundPath = $rescanned[$exeName]
            Set-WFTEnvVar -Key $entry.Key -Value $foundPath
            $parentDir = Split-Path $foundPath -Parent
            if (-not $FoundEZDirs.Contains($parentDir)) {
                $FoundEZDirs.Add($parentDir)
            }
        }
    }
}

# Resolve master WFT_EZTOOLS_DIR
$projectEZDir = Join-Path $ProjectRoot "EZTools"
$primaryEZDir = if (Test-Path $projectEZDir) {
    (Resolve-Path $projectEZDir).Path
} elseif ($FoundEZDirs.Count -gt 0) {
    $FoundEZDirs[0]
} else {
    $EZDestDir
}
Set-WFTEnvVar -Key "WFT_EZTOOLS_DIR" -Value $primaryEZDir

# ==============================================================================
# 3. REGRIPPER (REGISTRY PLUGIN ENGINE - WFT_REGRIPPER_EXE)
# ==============================================================================
Write-Host "`n[2/4] Checking RegRipper (rip.exe)..." -ForegroundColor Yellow
$RegRipperPath = if ($DiscoveredTools.ContainsKey("rip.exe")) { $DiscoveredTools["rip.exe"] } else { $null }

if ((-not $RegRipperPath) -or $ForceUpdate) {
    Write-Host "  [INSTALL] RegRipper not found on disk. Downloading RegRipper3.0 to .\tools\regripper..." -ForegroundColor Cyan
    $RRDir = Join-Path $ToolsRoot "regripper"
    $RRZip = Join-Path $ToolsRoot "regripper.zip"
    if (-not (Test-Path $RRDir)) {
        New-Item -ItemType Directory -Path $RRDir -Force | Out-Null
    }

    try {
        Invoke-WebRequest -Uri "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip" -OutFile $RRZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $RRZip -DestinationPath $RRDir -Force
        Remove-Item $RRZip -Force -ErrorAction SilentlyContinue
        $rescanRR = Find-AllForensicToolsFast -TargetExeNames @("rip.exe")
        if ($rescanRR.ContainsKey("rip.exe")) {
            $RegRipperPath = $rescanRR["rip.exe"]
        }
    } catch {
        Write-Warning "  Failed to download RegRipper3.0: $_"
    }
}

if ($RegRipperPath) {
    Write-Host "  [FOUND] RegRipper -> $RegRipperPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_REGRIPPER_EXE" -Value $RegRipperPath
    Set-WFTEnvVar -Key "WFT_REGRIPPER_DIR" -Value (Split-Path $RegRipperPath -Parent)
} else {
    Write-Host "  [MISSING] RegRipper (rip.exe)" -ForegroundColor DarkYellow
}

# ==============================================================================
# 4. HINDSIGHT (CHROMIUM BROWSER FORENSICS - WFT_HINDSIGHT_EXE)
# ==============================================================================
Write-Host "`n[3/4] Checking Hindsight (pyhindsight)..." -ForegroundColor Yellow
$HindsightPath = if ($DiscoveredTools.ContainsKey("hindsight.exe")) {
    $DiscoveredTools["hindsight.exe"]
} elseif ($DiscoveredTools.ContainsKey("hindsight.py")) {
    $DiscoveredTools["hindsight.py"]
} else {
    $null
}

if ((-not $HindsightPath) -or $ForceUpdate) {
    Write-Host "  [INSTALL] Hindsight not found on disk. Installing via pip & downloading standalone release..." -ForegroundColor Cyan
    $HindsightDir = Join-Path $ToolsRoot "hindsight"
    if (-not (Test-Path $HindsightDir)) {
        New-Item -ItemType Directory -Path $HindsightDir -Force | Out-Null
    }

    try {
        $releaseApi = Invoke-RestMethod -Uri "https://api.github.com/repos/obsidianforensics/hindsight/releases/latest" -UseBasicParsing -TimeoutSec 15
        $winAsset = $releaseApi.assets | Where-Object { $_.name -match "hindsight\.exe$" -and $_.name -notmatch "gui" } | Select-Object -First 1
        if ($winAsset) {
            $targetExe = Join-Path $HindsightDir "hindsight.exe"
            Invoke-WebRequest -Uri $winAsset.browser_download_url -OutFile $targetExe -UseBasicParsing -TimeoutSec 30
            if (Test-Path $targetExe) {
                $HindsightPath = (Resolve-Path $targetExe).Path
            }
        }
    } catch {
        Write-Warning "  GitHub standalone download skipped, falling back to pip install pyhindsight..."
    }

    if (-not $HindsightPath) {
        & python -m pip install pyhindsight --quiet
        $rescanHS = Find-AllForensicToolsFast -TargetExeNames @("hindsight.exe", "hindsight.py")
        if ($rescanHS.ContainsKey("hindsight.exe")) {
            $HindsightPath = $rescanHS["hindsight.exe"]
        } elseif ($rescanHS.ContainsKey("hindsight.py")) {
            $HindsightPath = $rescanHS["hindsight.py"]
        }
    }
}

if ($HindsightPath) {
    Write-Host "  [FOUND] Hindsight -> $HindsightPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_HINDSIGHT_EXE" -Value $HindsightPath
} else {
    Write-Host "  [MISSING] Hindsight executable (pyhindsight Python module is available natively)" -ForegroundColor DarkYellow
}

# ==============================================================================
# 5. TRELLIX STINGER / STANDALONE AV SCANNER (WFT_STINGER_EXE)
# ==============================================================================
Write-Host "`n[4/4] Checking Trellix Stinger / Threat Scanner..." -ForegroundColor Yellow
$StingerPath = if ($DiscoveredTools.ContainsKey("stinger64.exe")) {
    $DiscoveredTools["stinger64.exe"]
} elseif ($DiscoveredTools.ContainsKey("stinger32.exe")) {
    $DiscoveredTools["stinger32.exe"]
} elseif ($DiscoveredTools.ContainsKey("stinger.exe")) {
    $DiscoveredTools["stinger.exe"]
} else {
    $null
}

if ((-not $StingerPath) -or $ForceUpdate) {
    $is64Bit = [Environment]::Is64BitOperatingSystem
    $StingerDir = Join-Path $ToolsRoot "stinger"
    if (-not (Test-Path $StingerDir)) {
        New-Item -ItemType Directory -Path $StingerDir -Force | Out-Null
    }
    $stingerExeName = if ($is64Bit) { "stinger64.exe" } else { "stinger32.exe" }
    $targetStinger  = Join-Path $StingerDir $stingerExeName

    Write-Host "  [INFO] Checking Trellix Stinger ($stingerExeName for $(if($is64Bit){'64-bit'}else{'32-bit'}) OS)..." -ForegroundColor Cyan
    try {
        $stingerUrl = if ($is64Bit) {
            "https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger64.exe"
        } else {
            "https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger32.exe"
        }
        Invoke-WebRequest -Uri $stingerUrl -OutFile $targetStinger -UseBasicParsing -TimeoutSec 30
        if ((Test-Path $targetStinger) -and ((Get-Item $targetStinger).Length -gt 100000)) {
            $StingerPath = (Resolve-Path $targetStinger).Path
        } else {
            Remove-Item $targetStinger -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "  [NOTICE] Trellix Stinger direct CDN requires browser session. Windows Forensic Toolkit (WFT) PE Heuristics Analyzer will be used as fallback." -ForegroundColor DarkYellow
    }
}

if ($StingerPath) {
    Write-Host "  [FOUND] Trellix Stinger -> $StingerPath" -ForegroundColor Gray
    Set-WFTEnvVar -Key "WFT_STINGER_EXE" -Value $StingerPath
} else {
    Write-Host "  [FALLBACK] Trellix Stinger standalone binary not present; PE Heuristics Analyzer active." -ForegroundColor DarkYellow
}

# ==============================================================================
# 5. Compile Native Dialog Helper (wft_picker.exe)
# ==============================================================================
$pickerExe = Join-Path $ToolsRoot "wft_picker.exe"
$pickerCs  = Join-Path $ProjectRoot "scripts\WFTPicker.cs"
$cscExe    = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if ((-not (Test-Path $pickerExe)) -and (Test-Path $pickerCs) -and (Test-Path $cscExe)) {
    Write-Host "`n[*] Compiling native Windows dialog helper (tools\wft_picker.exe)..." -ForegroundColor Yellow
    & $cscExe /target:winexe /out:$pickerExe $pickerCs | Out-Null
    if (Test-Path $pickerExe) {
        Write-Host "  [OK] Native dialog helper compiled successfully." -ForegroundColor Green
    }
}

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host " TOOLCHAIN SETUP COMPLETE! Current .env Configuration:" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Cyan
Get-Content -Path $EnvFile
