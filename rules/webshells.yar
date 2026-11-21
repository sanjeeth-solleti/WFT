/*
    WFT Enterprise DFIR Suite - High-Precision Webshell Detection Ruleset
    Strictly requires web script markers (JSP, ASPX/ASP, PHP) + untrusted input + execution sinks
*/

private rule _wft_web_is_script_target {
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

rule Webshell_Java_JSP_Tomcat_Exec {
    meta:
        description = "Detects Java JSP/JSPX webshells executing system commands from HTTP request parameters"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1505.003"
        category = "Webshells"
    strings:
        $jsp1 = "<%" ascii wide
        $jsp2 = "<jsp:scriptlet>" ascii wide
        $exec1 = "Runtime.getRuntime().exec(" ascii wide
        $exec2 = "new ProcessBuilder(" ascii wide
        $param1 = "request.getParameter(" ascii wide
        $param2 = "request.getHeader(" ascii wide
        $param3 = "request.getInputStream(" ascii wide
    condition:
        _wft_web_is_script_target and filesize < 1MB and
        any of ($jsp*) and any of ($exec*) and any of ($param*)
}

rule Webshell_Java_JSP_Godzilla_Behinder {
    meta:
        description = "Detects Godzilla and Behinder encrypted Java JSP webshells using custom ClassLoader.defineClass"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1505.003"
        category = "Webshells"
    strings:
        $jsp1 = "<%" ascii wide
        $c1 = "Cipher.getInstance(\"AES\"" ascii wide
        $c2 = "SecretKeySpec(" ascii wide
        $d1 = "super.defineClass(" ascii wide
        $d2 = ".defineClass(" ascii wide
    condition:
        _wft_web_is_script_target and filesize < 1MB and
        $jsp1 and ($c1 or $c2) and ($d1 or $d2)
}

rule Webshell_ASP_NET_IIS {
    meta:
        description = "Detects IIS ASP/ASPX/ASHX webshells executing cmd.exe/powershell or JScript eval(Request)"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1505.003"
        category = "Webshells"
    strings:
        $asp1 = "<%@" ascii wide nocase
        $asp2 = "<script runat=\"server\"" ascii wide nocase
        $asp3 = "IHttpHandler" ascii wide
        $eval1 = "eval(Request.Item[" ascii wide nocase
        $eval2 = "eval(Request.Form[" ascii wide nocase
        $eval3 = "eval(Request[" ascii wide nocase
        $exec1 = "ProcessStartInfo" ascii wide
        $exec2 = "System.Diagnostics.Process" ascii wide
        $shell1 = "cmd.exe" ascii wide nocase
        $shell2 = "cmd /c" ascii wide nocase
        $shell3 = "powershell" ascii wide nocase
        $req1 = "Request.Form[" ascii wide nocase
        $req2 = "Request.QueryString[" ascii wide nocase
        $req3 = "Request.Item[" ascii wide nocase
    condition:
        _wft_web_is_script_target and filesize < 1MB and
        any of ($asp*) and (
            any of ($eval*) or
            (($exec1 or $exec2) and any of ($shell*) and any of ($req*))
        )
}

rule Webshell_ASPX_SharPyShell_Godzilla {
    meta:
        description = "Detects Godzilla ASPX and SharPyShell in-memory Assembly.Load encrypted .NET webshells"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1505.003"
        category = "Webshells"
    strings:
        $asp1 = "<%@" ascii wide nocase
        $asp2 = "<script runat=\"server\"" ascii wide nocase
        $c1 = "CreateDecryptor(" ascii wide
        $c2 = "RijndaelManaged" ascii wide
        $a1 = "System.Reflection.Assembly.Load(" ascii wide
        $a2 = "Assembly.Load(" ascii wide
        $r1 = "Request.BinaryRead(" ascii wide
        $r2 = "Request.InputStream" ascii wide
    condition:
        _wft_web_is_script_target and filesize < 1MB and
        any of ($asp*) and ($c1 or$c2) and ($a1 or$a2) and ($r1 or$r2)
}

rule Webshell_PHP_Execution {
    meta:
        description = "Detects PHP webshells combining $_GET/$_POST/$_REQUEST/base64_decode with command execution"
        author = "WFT Enterprise DFIR Suite"
        severity = "Critical"
        mitre_attack = "T1505.003"
        category = "Webshells"
    strings:
        $php = "<?php" ascii wide nocase
        $php_short = "<?=" ascii wide
        $direct1 = "shell_exec($_" ascii wide nocase
        $direct2 = "passthru($_" ascii wide nocase
        $direct3 = "system($_" ascii wide nocase
        $direct4 = "proc_open($_" ascii wide nocase
        $direct5 = "popen($_" ascii wide nocase
        $b64_in = "base64_decode($_" ascii wide nocase
        $e1 = "shell_exec(" ascii wide nocase
        $e2 = "passthru(" ascii wide nocase
        $e3 = "system(" ascii wide nocase
        $e4 = "proc_open(" ascii wide nocase
        $e5 = "popen(" ascii wide nocase
        $obf1 = "eval(base64_decode(" ascii wide nocase
        $obf2 = "eval(gzinflate(" ascii wide nocase
        $obf3 = "eval(gzuncompress(" ascii wide nocase
        $obf4 = "@eval($_POST[" ascii wide nocase
        $obf5 = "@eval($_GET[" ascii wide nocase
        $obf6 = "@eval($_REQUEST[" ascii wide nocase
        $obf7 = "eval($_POST[" ascii wide nocase
        $obf8 = "eval($_GET[" ascii wide nocase
        $obf9 = "assert($_POST[" ascii wide nocase
    condition:
        _wft_web_is_script_target and filesize < 1MB and
        ($php or$php_short) and (
            any of ($direct*) or
            any of ($obf*) or
            ($b64_in and any of ($e*))
        )
}