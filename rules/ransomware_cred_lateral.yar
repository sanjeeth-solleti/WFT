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
    condition:
        filesize < 25MB and any of them
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
    condition:
        filesize < 20MB and any of them
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
        $c1 = "comsvcs.dll, MiniDump" ascii wide nocase
        $c2 = "comsvcs.dll,MiniDump" ascii wide nocase
        $c3 = "comsvcs.dll #24" ascii wide nocase
        $reg1 = "reg save HKLM\\SAM" ascii wide nocase
        $reg2 = "reg save HKLM\\SYSTEM" ascii wide nocase
        $reg3 = "reg save HKLM\\SECURITY" ascii wide nocase
        $ntds = "ntdsutil \"ac i ntds\" \"ifm\"" ascii wide nocase
    condition:
        filesize < 15MB and any of them
}

rule Recon_BloodHound_SharpHound {
    meta:
        description = "Detects BloodHound and SharpHound Active Directory enumeration collectors"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1087.002"
        category = "AD Recon"
    strings:
        $b1 = "SharpHound" ascii wide nocase
        $b2 = "Invoke-BloodHound" ascii wide nocase
        $b3 = "--CollectionMethods" ascii wide nocase
        $b4 = "Sharphound.Producers" ascii wide nocase
        $b5 = "BloodHound.Common" ascii wide nocase
    condition:
        filesize < 25MB and any of them
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
        filesize < 15MB and any of them
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
        $n3 = "Restore-My-Files.txt" ascii wide nocase
        $n4 = "README_TO_DECRYPT" ascii wide nocase
        $n5 = "HOW_TO_DECRYPT" ascii wide nocase
        $l1 = "LockBit 3.0" ascii wide nocase
        $b1 = "ACCESS-ALPHV-HERE" ascii wide nocase
        $t1 = "http://" ascii wide nocase
        $t2 = ".onion" ascii wide nocase
    condition:
        filesize < 20MB and (
            $l1 or $b1 or $n3 or
            (($n1 or $n2 or $n4 or $n5) and $t1 and $t2)
        )
}

rule Lateral_Movement_PsExec_Impacket_WMI {
    meta:
        description = "Detects Sysinternals PsExec service binaries, Impacket wmiexec/smbexec, and remote WMI/WinRM execution"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1570"
        category = "Lateral Movement"
    strings:
        $p1 = "PSEXESVC.EXE" ascii wide nocase
        $p2 = "\\\\.\\pipe\\PSEXESVC" ascii wide nocase
        $p3 = "PsExec - Executes processes remotely" ascii wide
        $i1 = "cmd.exe /Q /c " ascii wide nocase
        $i2 = "1> \\\\127.0.0.1\\ADMIN$\\__1" ascii wide nocase
        $i3 = "wmiexec.py" ascii wide nocase
        $i4 = "smbexec.py" ascii wide nocase
        $i5 = "atexec.py" ascii wide nocase
        $w1 = "wmic /node:" ascii wide nocase
        $w2 = "process call create" ascii wide nocase
    condition:
        filesize < 15MB and (
            any of ($p*) or
            $i2 or $i3 or $i4 or $i5 or
            ($i1 and $i2) or
            ($w1 and $w2)
        )
}

rule Tunnel_Chisel_Ligolo_FRP_Ngrok {
    meta:
        description = "Detects covert network tunneling and SOCKS5 pivoting tools (Chisel, Ligolo-ng, FRP, Ngrok, Cloudflared)"
        author = "WFT Enterprise DFIR Suite"
        severity = "High"
        mitre_attack = "T1572"
        category = "Tunneling & Proxy"
    strings:
        $c1 = "github.com/jpillora/chisel" ascii wide
        $l1 = "github.com/nicocha30/ligolo-ng" ascii wide
        $f1 = "github.com/fatedier/frp" ascii wide
        $n1 = "ngrok.com/tunnel" ascii wide
        $n2 = "ngrok http " ascii wide nocase
        $n3 = "ngrok tcp " ascii wide nocase
        $cf1 = "cloudflared.exe tunnel run --token" ascii wide nocase
        $cf2 = "cloudflared tunnel run --token" ascii wide nocase
    condition:
        filesize < 35MB and any of them
}