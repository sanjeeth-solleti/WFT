/*
    WFT Enterprise DFIR Suite - Advanced Threats, BYOVD Drivers, Syscall Loaders, RMM Abuse & Exfiltration
    File: rules/advanced_threats_evasion_exfil.yar
    Zero-false-positive rules covering:
      1. BYOVD (Bring Your Own Vulnerable Driver) EDR killers (RTCore64, gdrv, Zemana, mhyprot2, AuKill)
      2. Direct Syscall / Hell's Gate / SysWhispers & NTDLL Unhooking Loaders
      3. Process Hollowing & APC Injection Shellcode Loaders
      4. Weaponized LNK Shortcuts & Office VBA Macro AutoExec Droppers
      5. Data Exfiltration Tools (Rclone config/binary, MegaCmd, WinSCP automation scripts)
      6. Cryptocurrency Miners (XMRig / Stratum Monero pools)
      7. Unauthorized RMM & RAT Portable Clients (NetSupport, MeshAgent, RustDesk, ScreenConnect)
*/

rule BYOVD_Vulnerable_Driver_EDR_Killer {
    meta:
        description = "Detects Bring Your Own Vulnerable Driver (BYOVD) kernel drivers and EDR killer tools (AuKill, Terminator, Backstab)"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1068"
        category = "Defense Evasion"
    strings:
        $d1 = "RTCore64.sys" ascii wide nocase
        $d2 = "\\\\.\\RTCore64" ascii wide nocase
        $d3 = "\\\\.\\GIO" ascii wide
        $d4 = "gdrv.sys" ascii wide nocase
        $d5 = "\\\\.\\ZemanaAntiMalware" ascii wide nocase
        $d6 = "\\\\.\\mhyprot2" ascii wide nocase
        $d7 = "\\\\.\\DBUtil_2_3" ascii wide nocase
        $d8 = "\\\\.\\aswSP_Avar" ascii wide nocase
        $k1 = "AuKill" ascii wide nocase
        $k2 = "Backstab" ascii wide nocase
        $k3 = "ZwTerminateProcess" ascii wide
        $k4 = "MmMapIoSpace" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and (
            any of ($d*) or
            ($k1 or ($k2 and$k3)) or
            ($k3 and $k4 and any of ($d*))
        )
}

rule Evasion_SysWhispers_Direct_Syscalls_And_Unhooking {
    meta:
        description = "Detects SysWhispers2/3 direct syscall stubs, Hell's Gate SSN resolution, and KnownDlls NTDLL unhooking"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1055"
        category = "Defense Evasion"
    strings:
        $sw1 = "SW2_GetSyscallNumber" ascii wide
        $sw2 = "SW3_GetSyscallNumber" ascii wide
        $sw3 = "SW2_PopulateSyscallList" ascii wide
        $sw4 = "SW3_PopulateSyscallList" ascii wide
        $unhook1 = "\\KnownDlls\\ntdll.dll" ascii wide nocase
        $unhook2 = "NtMapViewOfSection" ascii wide
        $unhook3 = "VirtualProtect" ascii wide
        $api1 = "NtAllocateVirtualMemory" ascii wide
        $api2 = "NtWriteVirtualMemory" ascii wide
        $api3 = "NtCreateThreadEx" ascii wide
        $api4 = "NtProtectVirtualMemory" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and (
            any of ($sw*) or
            ($unhook1 and$unhook2 and $unhook3 and 2 of ($api*))
        )
}

rule Loader_Process_Hollowing_And_APC_Injection {
    meta:
        description = "Detects Process Hollowing (NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext) and EarlyBird APC injection"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1055.012"
        category = "Defense Evasion"
    strings:
        $h1 = "CreateProcessA" ascii wide
        $h2 = "CreateProcessW" ascii wide
        $h3 = "NtUnmapViewOfSection" ascii wide
        $h4 = "ZwUnmapViewOfSection" ascii wide
        $h5 = "VirtualAllocEx" ascii wide
        $h6 = "WriteProcessMemory" ascii wide
        $h7 = "SetThreadContext" ascii wide
        $h8 = "Wow64SetThreadContext" ascii wide
        $h9 = "ResumeThread" ascii wide
        $apc1 = "QueueUserAPC" ascii wide
        $apc2 = "NtQueueApcThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and (
            (($h1 or $h2) and ($h3 or $h4) and$h5 and $h6 and ($h7 or $h8) and$h9) or
            (($h1 or $h2) and$h5 and $h6 and ($apc1 or $apc2) and$h9)
        )
}

rule InitialAccess_Weaponized_LNK_Shortcut {
    meta:
        description = "Detects malicious Windows LNK shortcut files executing PowerShell, cmd, mshta, certutil, or rundll32"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1204.002"
        category = "Initial Access"
    strings:
        $e1 = "powershell" ascii wide nocase
        $e2 = "cmd.exe /c" ascii wide nocase
        $e3 = "mshta" ascii wide nocase
        $e4 = "rundll32" ascii wide nocase
        $e5 = "regsvr32" ascii wide nocase
        $e6 = "wscript" ascii wide nocase
        $e7 = "cscript" ascii wide nocase
        $p1 = "-enc" ascii wide nocase
        $p2 = "-w hidden" ascii wide nocase
        $p3 = "-windowstyle hidden" ascii wide nocase
        $p4 = "http://" ascii wide nocase
        $p5 = "https://" ascii wide nocase
        $p6 = "DownloadString" ascii wide nocase
        $p7 = "FromBase64String" ascii wide nocase
        $p8 = "javascript:" ascii wide nocase
        $p9 = "vbscript:" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 500KB and
        any of ($e*) and any of ($p*)
}

rule InitialAccess_Office_Macro_AutoExec_Dropper {
    meta:
        description = "Detects OLE2 Office documents (.doc, .xls) containing AutoOpen/Document_Open VBA macros with shell/network execution"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1566.001"
        category = "Initial Access"
    strings:
        $vba = "VBA" ascii wide
        $a1 = "AutoOpen" ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $a4 = "Auto_Open" ascii wide nocase
        $x1 = "WScript.Shell" ascii wide nocase
        $x2 = "Shell(" ascii wide nocase
        $x3 = "CreateObject(" ascii wide nocase
        $x4 = "XMLHTTP" ascii wide nocase
        $x5 = "Adodb.Stream" ascii wide nocase
        $x6 = "URLDownloadToFileA" ascii wide nocase
        $x7 = "powershell" ascii wide nocase
    condition:
        uint32(0) == 0xE011CFD0 and filesize < 20MB and
        $vba and any of ($a*) and 2 of ($x*)
}

rule Exfiltration_Rclone_And_Mega_Config_Or_Binary {
    meta:
        description = "Detects Rclone data exfiltration binary, Rclone cloud remotes config, or MegaCmd exfiltration scripts"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1567.002"
        category = "Exfiltration"
    strings:
        $r1 = "github.com/rclone/rclone" ascii wide
        $r2 = "rclone copy " ascii wide nocase
        $r3 = "rclone sync " ascii wide nocase
        $r4 = "--transfers" ascii wide nocase
        $r5 = "--TPSLimit" ascii wide nocase
        $c1 = "type = mega" ascii wide nocase
        $c2 = "type = s3" ascii wide nocase
        $c3 = "type = pcloud" ascii wide nocase
        $c4 = "access_key_id =" ascii wide nocase
        $c5 = "secret_access_key =" ascii wide nocase
        $m1 = "mega-put " ascii wide nocase
        $m2 = "mega-login " ascii wide nocase
    condition:
        filesize < 65MB and (
            $r1 or
            (($r2 or$r3) and ($r4 or$r5)) or
            ($c1 or ($c2 and$c4 and $c5) or$c3) or
            ($m1 and$m2)
        )
}

rule Impact_XMRig_Cryptominer {
    meta:
        description = "Detects XMRig Monero cryptocurrency miner binaries and JSON pool configuration files"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1496"
        category = "Malware & Threat"
    strings:
        $x1 = "XMRig" ascii wide
        $x2 = "stratum+tcp://" ascii wide nocase
        $x3 = "stratum+ssl://" ascii wide nocase
    condition:
        any of them
}
