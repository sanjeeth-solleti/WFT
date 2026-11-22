/*
    WFT Enterprise DFIR Suite - Advanced Threats, BYOVD Drivers, Syscall Loaders & Exfiltration
    File: rules/advanced_threats_evasion_exfil.yar
*/

private rule _wft_adv_is_pe {
    condition:
        uint16(0) == 0x5A4D and
        filesize > 0x40 and
        uint32(0x3C) < filesize - 4 and
        uint32(uint32(0x3C)) == 0x00004550
}

private rule _wft_adv_is_non_binary_container {
    condition:
        uint16(0) != 0x5A4D and                                      // PE
        not (uint32(0) == 0x0000004C and uint32(4) == 0x00021401) and // LNK
        uint32(0) != 0x46666C45 and                                  // EVTX (ElfFile)
        uint32(0) != 0x66676572 and                                  // Registry hive (regf)
        uint32(0) != 0x694C5153 and                                  // SQLite
        uint16(0) != 0x4B50 and                                      // ZIP/DOCX/JAR
        uint32(0) != 0xE011CFD0 and                                  // OLE2
        uint32(0) != 0x46445025 and                                  // PDF
        uint32(0) != 0x464C457F and                                  // ELF
        uint16(0) != 0x8B1F                                          // GZIP
}

rule BYOVD_Vulnerable_Driver_EDR_Killer {
    meta:
        description = "Detects Bring Your Own Vulnerable Driver (BYOVD) EDR killer loaders and known abused kernel drivers"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1068"
        category = "Defense Evasion"
    strings:
        $ms_corp = "Microsoft Corporation" wide
        $ms_os1 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $ms_os2 = "Microsoft Windows Operating System" wide
        $dev1 = "\\\\.\\RTCore64" ascii wide nocase
        $dev2 = "\\\\.\\GIO" ascii wide fullword
        $dev3 = "\\\\.\\ZemanaAntiMalware" ascii wide nocase
        $dev4 = "\\\\.\\mhyprot2" ascii wide nocase
        $dev5 = "\\\\.\\DBUtil_2_3" ascii wide nocase
        $dev6 = "\\\\.\\aswSP_Avar" ascii wide nocase
        $ioctl = "DeviceIoControl" ascii wide
        $priv1 = "SeDebugPrivilege" ascii wide
        $priv2 = "SeLoadDriverPrivilege" ascii wide
        $edr1 = "MsMpEng.exe" ascii wide nocase
        $edr2 = "CSFalconService.exe" ascii wide nocase
        $edr3 = "SentinelAgent.exe" ascii wide nocase
        $edr4 = "PPL" ascii wide fullword
        $k1 = "AuKill" ascii wide
        $k2 = "Backstab" ascii wide
        $k3 = "ZwTerminateProcess" ascii wide
        $k4 = "MmMapIoSpace" ascii wide
        $drv1 = "IoCreateDevice" ascii wide
    condition:
        _wft_adv_is_pe and filesize < 10MB and not ($ms_corp and ($ms_os1 or $ms_os2)) and (
            // Known vulnerable driver binary itself (kernel-mode)
            (any of ($dev1, $dev3, $dev4, $dev5, $dev6) and $drv1 and ($k3 or $k4)) or
            // User-mode EDR killer abusing a vulnerable driver
            (any of ($dev*) and $ioctl and (any of ($priv*) or any of ($edr*) or $k3)) or
            // Named EDR killers
            (($k1 or $k2) and $ioctl and ($k3 or any of ($priv*)))
        )
}

rule Evasion_SysWhispers_Direct_Syscalls_And_Unhooking {
    meta:
        description = "Detects SysWhispers2/3 direct syscall stubs and KnownDlls NTDLL unhooking loaders"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1055"
        category = "Defense Evasion"
    strings:
        $ms_corp = "Microsoft Corporation" wide
        $ms_os1 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $ms_os2 = "Microsoft Windows Operating System" wide
        $sw1 = "SW2_GetSyscallNumber" ascii wide
        $sw2 = "SW3_GetSyscallNumber" ascii wide
        $sw3 = "SW2_PopulateSyscallList" ascii wide
        $sw4 = "SW3_PopulateSyscallList" ascii wide
        $unhook1 = "\\KnownDlls\\ntdll.dll" ascii wide nocase
        $unhook2 = "NtOpenSection" ascii wide
        $unhook3 = "NtMapViewOfSection" ascii wide
        $unhook4 = "VirtualProtect" ascii wide
        $api1 = "NtAllocateVirtualMemory" ascii wide
        $api2 = "NtWriteVirtualMemory" ascii wide
        $api3 = "NtCreateThreadEx" ascii wide
        $api4 = "NtProtectVirtualMemory" ascii wide
    condition:
        _wft_adv_is_pe and filesize < 10MB and not ($ms_corp and ($ms_os1 or $ms_os2)) and (
            2 of ($sw*) or
            (filesize < 5MB and $unhook1 and $unhook2 and $unhook3 and $unhook4 and 3 of ($api*))
        )
}

rule Loader_Process_Hollowing_And_APC_Injection {
    meta:
        description = "Detects Process Hollowing (NtUnmapViewOfSection + WriteProcessMemory + Get/SetThreadContext) and EarlyBird APC injection"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1055.012"
        category = "Defense Evasion"
    strings:
        $ms_corp = "Microsoft Corporation" wide
        $ms_os1 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $ms_os2 = "Microsoft Windows Operating System" wide
        $excl1 = "_CorExeMain" ascii
        $excl2 = "_CorDllMain" ascii
        $excl3 = "cygwin1.dll" ascii nocase
        $excl4 = "msys-2.0.dll" ascii nocase
        $excl5 = "Go build ID:" ascii
        $excl6 = "PyInstaller" ascii
        $excl7 = "Inno Setup" ascii wide
        $excl8 = "NullsoftInst" ascii
        $h1 = "CreateProcessA" ascii wide
        $h2 = "CreateProcessW" ascii wide
        $h3 = "NtUnmapViewOfSection" ascii wide
        $h4 = "ZwUnmapViewOfSection" ascii wide
        $h5 = "VirtualAllocEx" ascii wide
        $h6 = "WriteProcessMemory" ascii wide
        $h7 = "GetThreadContext" ascii wide
        $h8 = "Wow64GetThreadContext" ascii wide
        $h9 = "SetThreadContext" ascii wide
        $h10 = "Wow64SetThreadContext" ascii wide
        $h11 = "ResumeThread" ascii wide
        $apc1 = "NtQueueApcThread" ascii wide
        $apc2 = "NtTestAlert" ascii wide
    condition:
        _wft_adv_is_pe and filesize < 3MB and
        not ($ms_corp and ($ms_os1 or $ms_os2)) and
        not any of ($excl*) and (
            (($h3 or $h4) and $h5 and $h6 and ($h9 or $h10) and $h11) or
            (($h1 or $h2) and ($h7 or $h8) and $h5 and $h6 and ($h9 or $h10) and $h11) or
            (($h1 or $h2) and $h5 and $h6 and $apc1 and $apc2 and $h11)
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
        $p1 = " -enc " ascii wide nocase
        $p2 = "-encodedcommand" ascii wide nocase
        $p3 = "-w hidden" ascii wide nocase
        $p4 = "-windowstyle hidden" ascii wide nocase
        $p5 = "DownloadString(" ascii wide nocase
        $p6 = "FromBase64String(" ascii wide nocase
        $p7 = "Invoke-Expression" ascii wide nocase
        $p8 = "IEX(" ascii wide nocase
        $p9 = "javascript:" ascii wide nocase
        $p10 = "vbscript:" ascii wide nocase
        $p11 = "/i:http" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 500KB and
        any of ($e*) and any of ($p*)
}

rule InitialAccess_Office_Macro_AutoExec_Dropper {
    meta:
        description = "Detects OLE2 Office documents (.doc, .xls) containing AutoOpen/Document_Open VBA macros with shell/network dropper behavior"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1566.001"
        category = "Initial Access"
    strings:
        $vba1 = "_VBA_PROJECT" ascii wide
        $vba2 = "Attribut" ascii
        $a1 = "AutoOpen" ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $a4 = "Auto_Open" ascii wide nocase
        $s1 = "WScript.Shell" ascii wide nocase
        $s2 = "Shell(" ascii wide nocase
        $s3 = "CreateObject(" ascii wide nocase
        $net1 = "XMLHTTP" ascii wide nocase
        $net2 = "Adodb.Stream" ascii wide nocase
        $net3 = "URLDownloadToFileA" ascii wide nocase
        $net4 = "powershell" ascii wide nocase
        $net5 = "cmd.exe" ascii wide nocase
        $net6 = "mshta" ascii wide nocase
        $net7 = "certutil" ascii wide nocase
    condition:
        uint32(0) == 0xE011CFD0 and filesize < 20MB and
        ($vba1 or $vba2) and any of ($a*) and any of ($s*) and any of ($net*)
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
        $r_flag1 = "--ignore-existing" ascii wide
        $r_flag2 = "backend/mega" ascii wide
        $r2 = "rclone copy " ascii wide nocase
        $r3 = "rclone sync " ascii wide nocase
        $c1 = "type = mega" ascii wide nocase
        $c3 = "type = pcloud" ascii wide nocase
        $c_user = "\nuser =" ascii wide nocase
        $c_pass = "\npass =" ascii wide nocase
        $m1 = "mega-put " ascii wide nocase
        $m2 = "mega-login " ascii wide nocase
        $arch = ".7z" ascii wide nocase
    condition:
        (
            _wft_adv_is_pe and filesize < 65MB and $r1 and $r_flag1 and $r_flag2
        ) or (
            _wft_adv_is_non_binary_container and filesize < 1MB and (
                (($c1 or $c3) and $c_user and $c_pass) or
                ($m1 and $m2 and ($r2 or $r3 or $arch))
            )
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
        $rx = "rx/0" ascii wide
        $cfg_pools = "\"pools\"" ascii wide
        $cfg_donate = "\"donate-level\"" ascii wide
    condition:
        (
            _wft_adv_is_pe and filesize < 30MB and $x1 and ($x2 or $x3) and ($rx or $cfg_donate)
        ) or (
            _wft_adv_is_non_binary_container and filesize < 1MB and ($x2 or $x3) and $cfg_pools and $cfg_donate
        )
}