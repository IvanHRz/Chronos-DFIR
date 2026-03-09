/*
   Chronos-DFIR YARA Rules – C2 Framework Implant Detection
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - https://github.com/Neo23x0/signature-base
     - https://github.com/WithSecureLabs/chainsaw
     - DFIRArtifactMuseum
*/

import "pe"

rule C2_CobaltStrike_Beacon_Strings {
    meta:
        description = "Detects Cobalt Strike Beacon strings and configuration artifacts"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1071.001 – Application Layer Protocol: Web Protocols"
        tags = "c2, cobalt_strike, beacon, t1071"
    strings:
        $cs1 = "beacon.dll" ascii nocase
        $cs2 = "ReflectiveLoader" ascii
        $cs3 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $cs4 = "beacon" ascii nocase
        $cs5 = "Cobalt Strike" ascii
        $cs6 = "MSSE-" ascii
        $cs7 = "beacon_gate" ascii
        $cs8 = "watermark" ascii
        $metadata = "metadata" ascii
        $sleep_mask = "SleepMask" ascii
        $pipe_name = "\\\\.\\pipe\\MSSE-" ascii
        $named_pipe = "\\pipe\\" ascii
    condition:
        pe.is_pe and (2 of ($cs*) or ($pipe_name or $sleep_mask or $metadata or $named_pipe)) or
        (not pe.is_pe and 3 of ($cs*))
}

rule C2_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter payload strings and reverse shell artifacts"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1059 – Command and Scripting Interpreter"
        tags = "c2, metasploit, meterpreter, t1059"
    strings:
        $msf1 = "meterpreter" ascii nocase
        $msf2 = "Metasploit" ascii nocase
        $msf3 = "ReflectiveDll" ascii
        $msf4 = "ReflectiveLoader" ascii
        $msf5 = "msfvenom" ascii nocase
        $msf6 = "payload.dll" ascii nocase
        $msf7 = "reverse_tcp" ascii nocase
        $msf8 = "reverse_https" ascii nocase
        $msf9 = "EXITFUNC" ascii
        $msf10 = "core_channel_open" ascii
    condition:
        2 of them
}

rule C2_Sliver_Implant {
    meta:
        description = "Detects Sliver C2 framework implant artifacts"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1071, T1573"
        tags = "c2, sliver, t1071"
    strings:
        $sliver1 = "SliverC2" ascii nocase
        $sliver2 = "sliver" ascii nocase
        $sliver3 = "github.com/bishopfox/sliver" ascii
        $sliver4 = "implant_name" ascii
        $sliver5 = "MTLS" ascii
        $sliver6 = "ghostTunnel" ascii
    condition:
        2 of them
}

rule C2_Generic_Reverse_Shell_PowerShell {
    meta:
        description = "Detects PowerShell-based reverse shells connecting back to attacker infrastructure"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1059.001 – PowerShell"
        tags = "c2, powershell, reverse_shell, t1059"
    strings:
        $tcp_connect = "Net.Sockets.TcpClient" ascii wide
        $stream_reader = "System.IO.StreamReader" ascii wide
        $stream_writer = "System.IO.StreamWriter" ascii wide
        $getstream = ".GetStream()" ascii wide
        $invoke_exp = "IEX" ascii wide
        $invoke_expr = "Invoke-Expression" ascii wide
        $encoded = "-EncodedCommand" ascii nocase wide
        $hidden = "-WindowStyle Hidden" ascii nocase wide
        $bypass = "-ExecutionPolicy Bypass" ascii nocase wide
        $nop = "-NoProfile" ascii nocase wide
        $reverse_shell = "reverse shell" ascii nocase
    condition:
        ($tcp_connect and $getstream and ($stream_reader or $stream_writer)) or
        ($invoke_exp or $invoke_expr) and ($encoded and ($hidden or $bypass or $nop)) or
        $reverse_shell
}

rule C2_Generic_DNS_Tunneling {
    meta:
        description = "Detects DNS tunneling patterns used for C2 covert channels"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1071.004 – DNS"
        tags = "c2, dns_tunneling, t1071"
    strings:
        $iodine = "iodine" ascii nocase
        $dnscat = "dnscat" ascii nocase
        $dns_query = "DnsQueryA" ascii wide
        $txt_record = "DNS_TYPE_TEXT" ascii wide
        $base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" ascii
        $base64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $long_subdomain = /[a-zA-Z0-9]{40,}\.[a-zA-Z]{2,10}/ ascii
    condition:
        $iodine or $dnscat or
        ($dns_query and $txt_record and ($base32 or $base64_alpha)) or
        $long_subdomain
}
