/*
   Chronos-DFIR YARA Rules – Web Shell Detection
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - https://github.com/Neo23x0/signature-base/tree/master/yara
     - CISA AA21-092A
     - https://attack.mitre.org/techniques/T1505/003/
*/

rule Webshell_Generic_PHP {
    meta:
        description = "Detects generic PHP webshells using eval + base64 or system command execution"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1505.003 – Server Software Component: Web Shell"
        tags = "webshell, php, t1505"
    strings:
        $php_tag = "<?php" ascii
        $eval = "eval(" ascii
        $base64_decode = "base64_decode(" ascii
        $gzinflate = "gzinflate(" ascii
        $str_rot13 = "str_rot13(" ascii
        $assert = "assert(" ascii
        $system = "system(" ascii
        $exec = "exec(" ascii
        $passthru = "passthru(" ascii
        $shell_exec = "shell_exec(" ascii
        $popen = "popen(" ascii
        $proc_open = "proc_open(" ascii
        $cmd_get = "$_GET" ascii
        $cmd_post = "$_POST" ascii
        $cmd_request = "$_REQUEST" ascii
        $cmd_cookie = "$_COOKIE" ascii
        $cmd_server = "$_SERVER" ascii
    condition:
        $php_tag and
        (($eval and any of ($base64_decode, $gzinflate, $str_rot13, $assert)) or
         (any of ($system, $exec, $passthru, $shell_exec, $popen, $proc_open) and
          any of ($cmd_get, $cmd_post, $cmd_request, $cmd_cookie, $cmd_server)))
}

rule Webshell_China_Chopper {
    meta:
        description = "Detects China Chopper webshell – one-liner eval pattern and WScritp.Shell"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1505.003"
        tags = "webshell, china_chopper, t1505"
    strings:
        $chopper_aspx = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" ascii
        $chopper_asp = "<%eval request(" ascii nocase
        $chopper_php = "<?php @eval($_POST[" ascii
        $wscript = "WScript.Shell" ascii nocase wide
        $createobject = "CreateObject" ascii wide
        $response_write = "Response.Write" ascii nocase
    condition:
        any of ($chopper_*) or
        ($wscript and $createobject and $response_write)
}

rule Webshell_ASPX_Generic {
    meta:
        description = "Detects generic ASPX webshells executing OS commands via Request parameters"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1505.003"
        tags = "webshell, aspx, t1505"
    strings:
        $aspx1 = "<%@ Page" ascii
        $process_start = "Process.Start" ascii
        $cmd_process = "cmd.exe" ascii nocase
        $request_params = "Request[" ascii
        $request_form = "Request.Form[" ascii
        $request_query = "Request.QueryString[" ascii
        $exec_cmd1 = "cmd /c" ascii nocase
        $exec_cmd2 = "/bin/sh" ascii
        $exec_cmd3 = "/bin/bash" ascii
        $convert_base64 = "Convert.FromBase64String" ascii
    condition:
        $aspx1 and
        ($process_start or ($exec_cmd1 or $exec_cmd2 or $exec_cmd3)) and
        any of ($request_params, $request_form, $request_query)
}

rule Webshell_JSP_Generic {
    meta:
        description = "Detects JSP webshells using Runtime.exec or ProcessBuilder"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1505.003"
        tags = "webshell, jsp, java, t1505"
    strings:
        $jsp = "<%@" ascii
        $runtime_exec = "Runtime.getRuntime().exec(" ascii
        $process_builder = "ProcessBuilder" ascii
        $request_param = "request.getParameter(" ascii
        $base64 = "Base64" ascii
        $cmd = "cmd" ascii nocase
        $sh = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
    condition:
        $jsp and
        ($runtime_exec or $process_builder) and
        $request_param
}
