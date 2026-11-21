/*
    WFT Enterprise DFIR Suite - C2 Frameworks, Implants & Remote Access Trojans (RATs)
    Detects Cobalt Strike, Sliver, Metasploit Meterpreter, Havoc Demon, AsyncRAT, Quasar, Remcos, and AgentTesla
*/

private rule _wft_c2_is_pe {
    condition:
        uint16(0) == 0x5A4D and
        filesize > 0x40 and
        uint32(0x3C) < filesize - 4 and
        uint32(uint32(0x3C)) == 0x00004550
}

private rule _wft_c2_is_script_target {
    condition:
        uint16(0) != 0x5A4D and
        not (uint32(0) == 0x0000004C and uint32(4) == 0x00021401) and
        uint32(0) != 0x46666C45 and // EVTX
        uint32(0) != 0x66676572 and // Registry hive (regf)
        uint32(0) != 0x694C5153 and // SQLite
        uint16(0) != 0x4B50 and     // ZIP/DOCX/JAR
        uint32(0) != 0xE011CFD0 and // OLE2
        uint32(0) != 0x46445025 and // PDF
        uint32(0) != 0x464C457F and // ELF
        uint16(0) != 0x8B1F         // GZIP
}

rule C2_CobaltStrike_Beacon_Indicators {
    meta:
        description = "Detects Cobalt Strike Beacon default/custom named pipes, reflective loader exports, and sleep mask signatures"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1071.001"
        category = "C2 & Beacons"
    strings:
        $p1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $p2 = "\\\\.\\pipe\\postex_" ascii wide
        $p3 = "\\\\.\\pipe\\status_" ascii wide
        $p4 = "\\\\.\\pipe\\msagent_" ascii wide
        $fmt = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii wide
        $ref = "ReflectiveLoader" ascii wide
        $bcn1 = "beacon.dll" ascii wide nocase
        $bcn2 = "beacon.x64.dll" ascii wide nocase
        $cfg = { 00 01 00 01 00 02 00 01 00 02 00 02 }$cradle_cs = "DownloadString('http://127.0.0.1:" ascii wide nocase
        $iex1 = "IEX" ascii wide nocase
        $iex2 = "Invoke-Expression" ascii wide nocase
    condition:
        (
            _wft_c2_is_pe and filesize < 25MB and (
                $fmt or
                ($ref and ($cfg or any of ($bcn*) or any of ($p*))) or
                2 of ($p*)
            )
        ) or (
            _wft_c2_is_script_target and filesize < 2MB and $cradle_cs and ($iex1 or$iex2)
        )
}

rule C2_CobaltStrike_Malleable_Profile {
    meta:
        description = "Detects Cobalt Strike Malleable C2 profile configuration files"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1071.001"
        category = "C2 & Beacons"
    strings:
        $m1 = "set sleeptime" ascii wide
        $m2 = "http-get {" ascii wide
        $m3 = "http-post {" ascii wide
        $m4 = "http-stager {" ascii wide
        $m5 = "stage {" ascii wide
        $m6 = "process-inject {" ascii wide
    condition:
        _wft_c2_is_script_target and filesize < 2MB and $m1 and 3 of ($m2, $m3,$m4, $m5,$m6)
}

rule C2_Sliver_Implant {
    meta:
        description = "Detects BishopFox Sliver C2 implant Go symbols and Protobuf IPC structures"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1071"
        category = "C2 & Beacons"
    strings:
        $s1 = "github.com/bishopfox/sliver" ascii wide
        $s2 = "sliverpb.Envelope" ascii wide
        $s3 = "sliverpb.Register" ascii wide
        $s4 = "ExecuteAssemblyReq" ascii wide
        $s5 = "RevToSelfReq" ascii wide
        $s6 = "ImpersonateReq" ascii wide
    condition:
        _wft_c2_is_pe and filesize < 50MB and
        ($s1 or$s2 or $s3) and 2 of ($s2, $s3,$s4, $s5,$s6)
}

rule C2_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter payload stages, metsrv.dll, and stdapi reflective extensions"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1059"
        category = "C2 & Beacons"
    strings:
        $m1 = "metsrv.dll" ascii wide nocase
        $m2 = "ext_server_stdapi.dll" ascii wide nocase
        $m3 = "stdapi_sys_process_execute" ascii wide
        $m4 = "stdapi_net_config_get_interfaces" ascii wide
        $m5 = "ReflectiveLoader" ascii wide
    condition:
        _wft_c2_is_pe and filesize < 25MB and (
            (($m1 or $m2) and ($m3 or $m4 or$m5)) or
            ($m3 and$m4)
        )
}

rule C2_Havoc_Demon {
    meta:
        description = "Detects Havoc C2 Demon implant symbols and command dispatchers"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1071"
        category = "C2 & Beacons"
    strings:
        $h1 = "Demon.x64.dll" ascii wide nocase
        $h2 = "Demon.x86.dll" ascii wide nocase
        $h3 = "DemonMain" ascii wide
        $h4 = "PackageAddInt32" ascii wide
        $h5 = "DemonConfig" ascii wide
    condition:
        _wft_c2_is_pe and filesize < 20MB and (
            (($h1 or $h2) and any of ($h3, $h4,$h5)) or
            2 of ($h3, $h4,$h5)
        )
}

rule RAT_AsyncRAT_Quasar_DcRat {
    meta:
        description = "Detects AsyncRAT, DcRat, VenomRAT, and Quasar RAT .NET client configurations"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1219"
        category = "RAT & Stealers"
    strings:
        $q1 = "AsyncClient.exe" ascii wide nocase
        $q2 = "AsyncRAT" ascii wide
        $q3 = "Quasar.Client" ascii wide
        $q4 = "Quasar.Common" ascii wide
        $q5 = "Settings.Ports" ascii wide
        $q6 = "Pastebin" ascii wide
        $q7 = "Anti_Analysis" ascii wide
        $q8 = "RunAntiAnalysis" ascii wide
    condition:
        _wft_c2_is_pe and filesize < 15MB and (
            (($q1 or$q2) and any of ($q5,$q6, $q7,$q8)) or
            ($q3 and$q4) or
            ($q5 and 2 of ($q6, $q7,$q8))
        )
}

rule RAT_Remcos_AgentTesla {
    meta:
        description = "Detects Remcos RAT and AgentTesla credential stealer / keylogger payloads"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1056.001"
        category = "RAT & Stealers"
    strings:
        $cor = "_CorExeMain" ascii
        $r1 = "Remcos_Mutex_Inj" ascii wide
        $r2 = "Breaking-Security.Net" ascii wide nocase
        $r3 = "remcos.exe" ascii wide nocase
        $a1 = "AgentTesla" ascii wide
        $a2 = "SmtpClient" ascii wide
        $a3 = "moz_logins" ascii wide
        $a4 = "Opera Stable\\Login Data" ascii wide
        $a5 = "GetKeyboardState" ascii wide
    condition:
        _wft_c2_is_pe and filesize < 20MB and (
            2 of ($r*) or
            ($a1 and 2 of ($a2,$a3, $a4,$a5)) or
            ($cor and $a2 and$a3 and $a4 and$a5)
        )
}