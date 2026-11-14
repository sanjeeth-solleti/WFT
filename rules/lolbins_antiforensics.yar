/*
    WFT Enterprise DFIR Suite - Obfuscated Scripts, LOLBins, InfoStealers & Anti-Forensics
    Zero-false-positive rules for PowerShell cradles, AMSI bypasses, LOLBin stagers, Stealers, and Anti-Forensics
*/

rule LOLBin_Suspicious_PowerShell_Cradle {
    meta:
        description = "Detects obfuscated PowerShell download cradles, Base64 reflection, and hidden window execution"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1059.001"
        category = "LOLBins & Scripts"
    strings:
        $s1 = "FromBase64String(" ascii wide nocase
        $s2 = "IO.Compression.DeflateStream" ascii wide nocase
        $s3 = "Net.WebClient).DownloadString(" ascii wide nocase
        $s4 = "Net.WebClient).DownloadFile(" ascii wide nocase
        $s5 = "Invoke-WebRequest" ascii wide nocase
        $m1 = "-WindowStyle Hidden" ascii wide nocase
        $m2 = " -w hidden " ascii wide nocase
        $m3 = "-EncodedCommand " ascii wide nocase
        $m4 = " -enc " ascii wide nocase
        $m5 = "IEX(" ascii wide nocase
        $m6 = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 10MB and (
            ($s3 or $s4) or
            (($s1 or $s2 or $s5) and any of ($m*)) or
            (($m1 or $m2) and ($m3 or $m4))
        )
}

rule LOLBin_PowerShell_AMSI_ETW_Bypass {
    meta:
        description = "Detects in-memory patching of AMSI (AmsiScanBuffer) or ETW (EtwEventWrite)"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1562.001"
        category = "Defense Evasion"
    strings:
        $a1 = "AmsiScanBuffer" ascii wide nocase
        $a2 = "amsiInitFailed" ascii wide nocase
        $a3 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $a4 = "EtwEventWrite" ascii wide nocase
        $p1 = "VirtualProtect" ascii wide nocase
        $p2 = "SetValue($null,$true)" ascii wide nocase
        $p3 = "[Ref].Assembly.GetType" ascii wide nocase
    condition:
        filesize < 10MB and (
            $a2 or $a3 or
            (($a1 or $a4) and ($p1 or $p2 or $p3))
        )
}

rule LOLBin_Certutil_Bitsadmin_Mshta_Regsvr32 {
    meta:
        description = "Detects LOLBin remote payload downloading and proxy execution (certutil, bitsadmin, mshta, regsvr32)"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1218"
        category = "LOLBins & Scripts"
    strings:
        $c1 = "certutil -urlcache -split -f http" ascii wide nocase
        $c2 = "certutil.exe -urlcache -split -f http" ascii wide nocase
        $b1 = "bitsadmin /transfer" ascii wide nocase
        $b2 = "bitsadmin.exe /transfer" ascii wide nocase
        $m1 = "mshta.exe vbscript:" ascii wide nocase
        $m2 = "mshta vbscript:" ascii wide nocase
        $m3 = "mshta.exe http" ascii wide nocase
        $m4 = "mshta http" ascii wide nocase
        $r1 = "regsvr32 /s /n /u /i:http" ascii wide nocase
        $r2 = "regsvr32.exe /s /n /u /i:http" ascii wide nocase
        $r3 = "regsvr32 /s /u /i:http" ascii wide nocase
        $j1 = "rundll32.exe javascript:" ascii wide nocase
    condition:
        filesize < 10MB and any of them
}

rule Infostealer_Credential_And_Crypto_Harvester {
    meta:
        description = "Detects InfoStealer binaries (RedLine, Raccoon, Lumma, Vidar) targeting multiple browsers, DPAPI, and crypto wallets"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1555.003"
        category = "RAT & Stealers"
    strings:
        $b1 = "\\Google\\Chrome\\User Data\\Local State" ascii wide nocase
        $b2 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $b3 = "\\Login Data" ascii wide nocase
        $b4 = "os_crypt" ascii wide
        $b5 = "CryptUnprotectData" ascii wide
        $w1 = "\\Exodus\\exodus.wallet" ascii wide nocase
        $w2 = "\\Electrum\\wallets" ascii wide nocase
        $w3 = "\\atomic\\Local Storage\\leveldb" ascii wide nocase
        $t1 = "Telegram Desktop\\tdata" ascii wide nocase
        $d1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 25MB and (
            (2 of ($w*)) or
            (($b1 or $b2) and $b3 and $b4 and $b5 and ($t1 or $d1 or any of ($w*)))
        )
}

rule AntiForensics_EventLog_And_Defender_Tampering {
    meta:
        description = "Detects event log wiping via wevtutil/PowerShell and disabling Windows Defender real-time monitoring"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1070.001"
        category = "Anti-Forensics"
    strings:
        $l1 = "wevtutil cl Security" ascii wide nocase
        $l2 = "wevtutil cl System" ascii wide nocase
        $l3 = "wevtutil cl Application" ascii wide nocase
        $l4 = "wevtutil.exe cl " ascii wide nocase
        $l5 = "Clear-EventLog -LogName" ascii wide nocase
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii wide nocase
        $d2 = "Set-MpPreference -DisableIOAVProtection $true" ascii wide nocase
        $d3 = "Add-MpPreference -ExclusionPath" ascii wide nocase
    condition:
        filesize < 10MB and any of them
}

rule AntiForensics_SDelete_And_USN_Wiping {
    meta:
        description = "Detects Sysinternals SDelete secure file/free-space wiping and NTFS USN journal deletion"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1070"
        category = "Anti-Forensics"
    strings:
        $u1 = "fsutil usn deletejournal /d" ascii wide nocase
        $u2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $u3 = "cipher /w:C" ascii wide nocase
        $s_bin1 = "SDelete - Secure Delete" ascii wide
        $s_bin2 = "Mark Russinovich" ascii wide
        $s_bin3 = "SDeleteEulaAccepted" ascii wide
        $s_cmd1 = "sdelete.exe -accepteula" ascii wide nocase
        $s_cmd2 = "sdelete -accepteula" ascii wide nocase
        $s_cmd3 = "sdelete.exe -p " ascii wide nocase
        $s_cmd4 = "sdelete.exe -z " ascii wide nocase
        $s_cmd5 = "sdelete.exe -c " ascii wide nocase
    condition:
        filesize < 15MB and (
            any of ($u*) or
            any of ($s_cmd*) or
            (uint16(0) == 0x5A4D and 2 of ($s_bin*))
        )
}