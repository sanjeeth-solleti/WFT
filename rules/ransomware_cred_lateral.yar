/*
    WFT Enterprise DFIR Suite - Credential Access, Ransomware, Lateral Movement & Tunneling
    Detects Mimikatz, Rubeus, BloodHound, VSS wiping, Ransomware notes, PsExec/Impacket, Chisel, Ligolo-ng, and Ngrok
*/

rule CredDump_Mimikatz_Nanodump_LSASS {
    meta:
        description = "Detects Mimikatz binaries/scripts, DCSync, Nanodump, and LSASS credential harvesting"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1003.001"
        category = "Credential Access"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "sekurlsa::minidump" ascii wide nocase
        $m3 = "sekurlsa::tickets" ascii wide nocase
        $m4 = "lsadump::dcsync" ascii wide nocase
        $m5 = "lsadump::sam" ascii wide nocase
        $m6 = "lsadump::lsa" ascii wide nocase
        $m7 = "gentilkiwi" ascii wide nocase
        $m8 = "benjamin@gentilkiwi.com" ascii wide nocase
        $m9 = "nanodump" ascii wide nocase
        $m10 = "SafetyKatz" ascii wide nocase
        $m11 = "Invoke-Mimikatz" ascii wide nocase
        $ps_pebytes = "PEBytes" ascii wide nocase
    condition:
        (
            uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
            filesize < 25MB and 2 of ($m1, $m2, $m3, $m4, $m5, $m6, $m7, $m8, $m9, $m10)
        ) or (
            uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 10MB and (
                ($m11 and ($ps_pebytes or any of ($m1, $m2, $m3, $m4, $m5, $m6))) or
                2 of ($m1, $m2, $m3, $m4, $m5, $m6)
            )
        )
}

rule CredDump_Kerberoasting_Rubeus {
    meta:
        description = "Detects Rubeus Kerberoasting, AS-REP roasting, S4U delegation, and Golden/Silver ticket abuse"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1558.003"
        category = "Credential Access"
    strings:
        $r1 = "Rubeus.Program" ascii wide
        $r2 = "Rubeus.exe" ascii wide nocase
        $r3 = "asreproast" ascii wide nocase
        $r4 = "kerberoast" ascii wide nocase
        $r5 = "tgtdeleg" ascii wide nocase
        $r6 = "createnetonly /program:" ascii wide nocase
        $r7 = "ptt /ticket:" ascii wide nocase
        $nowrap = "/nowrap" ascii wide nocase
    condition:
        (
            uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
            filesize < 20MB and $r1 and 2 of ($r3, $r4, $r5, $r6, $r7)
        ) or (
            uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and
            $r2 and ($r6 or $r7 or ($r4 and $nowrap))
        )
}

rule CredDump_ProcDump_Comsvcs_SAM_Dump {
    meta:
        description = "Detects LSASS memory dumping via comsvcs.dll/procdump and Registry SAM/SECURITY hive extraction"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1003.001"
        category = "Credential Access"
    strings:
        $p1 = "procdump.exe -accepteula -ma lsass" ascii wide nocase
        $p2 = "procdump -accepteula -ma lsass" ascii wide nocase
        $p3 = "procdump64.exe -accepteula -ma lsass" ascii wide nocase
        $rundll = "rundll32" ascii wide nocase
        $c1 = "comsvcs.dll, MiniDump" ascii wide nocase
        $c2 = "comsvcs.dll,MiniDump" ascii wide nocase
        $c3 = "comsvcs.dll #24" ascii wide nocase
        $full = " full" ascii wide nocase
        $reg1 = "reg save HKLM\\SAM" ascii wide nocase
        $reg2 = "reg save HKLM\\SYSTEM" ascii wide nocase
        $reg3 = "reg save HKLM\\SECURITY" ascii wide nocase
        $ntds = "ntdsutil" ascii wide nocase
        $ntds_ifm = "\"ac i ntds\" \"ifm\"" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            ($rundll and ($c1 or $c2 or $c3) and $full) or
            ($p1 or $p2 or $p3) or
            ($reg1 and ($reg2 or $reg3)) or
            ($ntds and $ntds_ifm)
        )
}

rule Recon_BloodHound_SharpHound {
    meta:
        description = "Detects BloodHound and SharpHound Active Directory enumeration collectors"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1087.002"
        category = "AD Recon"
    strings:
        $b2 = "Invoke-BloodHound" ascii wide nocase
        $b3 = "CollectionMethod" ascii wide nocase
        $b4 = "Sharphound.Producers" ascii wide nocase
        $b5 = "BloodHound.Common" ascii wide nocase
    condition:
        (
            uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
            filesize < 25MB and $b4 and $b5
        ) or (
            uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 15MB and $b2 and $b3
        )
}

rule Ransomware_ShadowCopy_VSS_Wipe {
    meta:
        description = "Detects Volume Shadow Copy, boot recovery, and backup catalog deletion commands"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1490"
        category = "Ransomware"
    strings:
        $v1 = "vssadmin delete shadows /all" ascii wide nocase
        $v2 = "vssadmin.exe delete shadows /all" ascii wide nocase
        $v3 = "wmic shadowcopy delete" ascii wide nocase
        $v4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $v5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $v6 = "wbadmin delete catalog -quiet" ascii wide nocase
        $v7 = "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and 2 of ($v*)
}

rule Ransomware_LockBit_BlackCat_And_RansomNotes {
    meta:
        description = "Detects LockBit 3.0, BlackCat/ALPHV, Akira, Play, and generic ransomware notes"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1486"
        category = "Ransomware"
    strings:
        $n1 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $n2 = "All your important files are encrypted" ascii wide nocase
        $n4 = "README_TO_DECRYPT" ascii wide nocase
        $n5 = "HOW_TO_DECRYPT" ascii wide nocase
        $l1 = "LockBit 3.0" ascii wide nocase
        $b1 = "ACCESS-ALPHV-HERE" ascii wide nocase
        $t2 = ".onion" ascii wide nocase
        $tor = "Tor Browser" ascii wide nocase
        $decrypt_id = "personal ID" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 200KB and
        2 of ($n1, $n2, $n4, $n5, $l1, $b1) and $t2 and ($tor or $decrypt_id)
}

rule Lateral_Movement_PsExec_Impacket_WMI {
    meta:
        description = "Detects Impacket wmiexec/smbexec command redirection and remote WMI lateral execution"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1570"
        category = "Lateral Movement"
    strings:
        $i1 = "cmd.exe /Q /c " ascii wide nocase
        $i2 = "1> \\\\127.0.0.1\\ADMIN$\\__1" ascii wide nocase
        $redir = "2>&1" ascii wide
        $w1 = "wmic /node:" ascii wide nocase
        $w2 = "process call create" ascii wide nocase
        $admin_share = "\\\\ADMIN$\\" ascii wide nocase
        $ps_exec = "powershell.exe -nop -w hidden" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and uint32(0) != 0x00021401 and filesize < 2MB and (
            ($i1 and $i2 and $redir) or
            ($w1 and $w2 and ($admin_share or $ps_exec))
        )
}

rule Tunnel_Chisel_Ligolo_FRP_Ngrok {
    meta:
        description = "Detects covert Go network tunneling and SOCKS5 pivoting binaries (Chisel, Ligolo-ng, FRP)"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1572"
        category = "Tunneling & Proxy"
    strings:
        $go_buildid = "Go build ID:" ascii
        $c1 = "github.com/jpillora/chisel" ascii wide
        $c_flag = "--reverse" ascii wide
        $l1 = "github.com/nicocha30/ligolo-ng" ascii wide
        $l_flag = "-ignore-cert" ascii wide
        $f1 = "github.com/fatedier/frp" ascii wide
        $f_flag = "remote_port" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 35MB and $go_buildid and (
            ($c1 and $c_flag) or
            ($l1 and $l_flag) or
            ($f1 and $f_flag)
        )
}