/*
    WFT Enterprise DFIR Suite - High-Precision Webshell Detection Ruleset
    Strictly requires web script markers (JSP, ASPX/ASP, PHP) + untrusted input + execution sinks
*/

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
        filesize < 2MB and uint16(0) != 0x5A4D and
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
        $d2 = ".defineClass(b, 0, b.length)" ascii wide
        $s1 = "session.getAttribute(" ascii wide
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and
        $jsp1 and ($c1 or $c2) and ($d1 or $d2 or $s1)
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
        $req1 = "Request.Form[" ascii wide nocase
        $req2 = "Request.QueryString[" ascii wide nocase
        $req3 = "Request.Item[" ascii wide nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and (
            any of ($eval*) or
            (any of ($asp*) and ($exec1 or $exec2) and any of ($req*))
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
        filesize < 2MB and uint16(0) != 0x5A4D and
        any of ($asp*) and ($c1 or $c2) and ($a1 or $a2) and ($r1 or $r2)
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
        $e1 = "shell_exec(" ascii wide nocase
        $e2 = "passthru(" ascii wide nocase
        $e3 = "system(" ascii wide nocase
        $e4 = "proc_open(" ascii wide nocase
        $e5 = "popen(" ascii wide nocase
        $r1 = "$_GET[" ascii wide nocase
        $r2 = "$_POST[" ascii wide nocase
        $r3 = "$_REQUEST[" ascii wide nocase
        $r4 = "$_COOKIE[" ascii wide nocase
        $obf1 = "eval(base64_decode(" ascii wide nocase
        $obf2 = "eval(gzinflate(" ascii wide nocase
        $obf3 = "eval(gzuncompress(" ascii wide nocase
        $obf4 = "@eval($_POST[" ascii wide nocase
        $obf5 = "assert($_POST[" ascii wide nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and (
            any of ($obf*) or
            (($php or $php_short) and any of ($e*) and any of ($r*))
        )
}