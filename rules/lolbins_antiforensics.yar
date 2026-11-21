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
        $m1 = "-WindowStyle Hidden" ascii wide nocase
        $m2 = " -w hidden" ascii wide nocase
        $m3 = "-EncodedCommand " ascii wide nocase
        $m4 = " -enc " ascii wide nocase
        $m_iex1 = "IEX(" ascii wide
        $m_iex2 = "IEX (" ascii wide
        $m_iex3 = "Invoke-Expression" ascii wide nocase
        $m_byp1 = "-ep bypass" ascii wide nocase
        $m_byp2 = "-ExecutionPolicy Bypass" ascii wide nocase
        $m_nop1 = " -nop " ascii wide nocase
        $m_nop2 = "-NoProfile" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            (($s3 or ($s1 and $s2)) and ($m_iex1 or $m_iex2 or $m_iex3) and ($m1 or $m2 or $m_byp1 or $m_byp2 or $m_nop1 or $m_nop2)) or
            (($m1 or $m2) and ($m3 or $m4) and ($m_byp1 or $m_byp2 or $m_nop1 or $m_nop2))
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
        $p2_sp = "SetValue($null, $true)" ascii wide nocase
        $p3 = "[Ref].Assembly.GetType" ascii wide nocase
        $marshal = "Marshal]::Copy" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            ($a2 and $a3 and ($p2 or $p2_sp or $p3)) or
            (($a1 or $a4) and $p1 and ($marshal or $p3))
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
        $c_dec = "certutil -decode" ascii wide nocase
        $c_dec2 = "certutil.exe -decode" ascii wide nocase
        $exec1 = "cmd.exe /c" ascii wide nocase
        $exec2 = "Start-Process" ascii wide nocase
        $m1 = "mshta.exe vbscript:" ascii wide nocase
        $m2 = "mshta vbscript:" ascii wide nocase
        $m_exec1 = "Execute(" ascii wide nocase
        $m_exec2 = "CreateObject(" ascii wide nocase
        $r1 = "regsvr32 /s /n /u /i:http" ascii wide nocase
        $r2 = "regsvr32.exe /s /n /u /i:http" ascii wide nocase
        $r3 = "regsvr32 /s /u /i:http" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $j1 = "rundll32.exe javascript:" ascii wide nocase
        $mshtml = "RunHTMLApplication" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            (($r1 or $r2 or $r3) and $scrobj) or
            (($m1 or $m2) and ($m_exec1 or $m_exec2)) or
            ($j1 and $mshtml) or
            (($c1 or $c2) and ($c_dec or $c_dec2 or $exec1 or $exec2))
        )
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
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 25MB and (
            (3 of ($w*) and $b5) or
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
        $l1b = "wevtutil.exe cl Security" ascii wide nocase
        $l2 = "wevtutil cl System" ascii wide nocase
        $l2b = "wevtutil.exe cl System" ascii wide nocase
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii wide nocase
        $d2 = "Set-MpPreference -DisableIOAVProtection $true" ascii wide nocase
        $d_behav = "Set-MpPreference -DisableBehaviorMonitoring $true" ascii wide nocase
        $d3 = "Add-MpPreference -ExclusionPath" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            (($l1 or $l1b) and ($l2 or $l2b)) or
            ($d1 and ($d2 or $d_behav or $d3 or $l1 or $l1b))
        )
}

rule AntiForensics_SDelete_And_USN_Wiping {
    meta:
        description = "Detects coordinated NTFS USN journal deletion and secure free-space/log wiping"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1070"
        category = "Anti-Forensics"
    strings:
        $u1 = "fsutil usn deletejournal /d" ascii wide nocase
        $u2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $u3 = "cipher /w:C" ascii wide nocase
        $wevt_sec = "wevtutil cl Security" ascii wide nocase
        $vss_del = "vssadmin delete shadows" ascii wide nocase
        $s_cmd1 = "sdelete.exe -accepteula" ascii wide nocase
        $s_cmd2 = "sdelete -accepteula" ascii wide nocase
        $s_cmd3 = "sdelete.exe -z " ascii wide nocase
        $s_cmd4 = "sdelete -z " ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and
        ($u1 or $u2) and ($u3 or $wevt_sec or $vss_del or any of ($s_cmd*))
}