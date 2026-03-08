/*
   Chronos-DFIR YARA Rules – Living off the Land Binary (LOLBin) Abuse
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - https://lolbas-project.github.io/
     - https://github.com/WithSecureLabs/chainsaw
*/

rule LOLBin_Certutil_Encode_Decode {
    meta:
        description = "Detects certutil.exe used for encoding/decoding or downloading – common LOLBin abuse for payload staging"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1105, T1027"
        tags = "lolbin, certutil, t1105"
    strings:
        $certutil = "certutil" ascii nocase wide
        $urlcache = "-urlcache" ascii nocase wide
        $decode = "-decode" ascii nocase wide
        $encode = "-encode" ascii nocase wide
        $f_flag = "-f " ascii nocase
        $split = "-split" ascii nocase wide
        $http = "http://" ascii nocase wide
        $https = "https://" ascii nocase wide
    condition:
        $certutil and ($urlcache or $decode or $encode) and ($http or $https or $f_flag or $split)
}

rule LOLBin_Regsvr32_Squiblydoo {
    meta:
        description = "Detects regsvr32.exe Squiblydoo attack – remote COM object execution bypassing AppLocker"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1218.010 – Regsvr32"
        tags = "lolbin, regsvr32, applocker_bypass, t1218"
    strings:
        $regsvr32 = "regsvr32" ascii nocase wide
        $scrobj = "scrobj.dll" ascii nocase wide
        $s_flag = "/s" ascii nocase
        $u_flag = "/u" ascii nocase
        $i_flag = "/i:" ascii nocase
        $http = "http" ascii nocase wide
    condition:
        $regsvr32 and ($scrobj or ($i_flag and $http)) and ($s_flag or $u_flag)
}

rule LOLBin_MSHTA_Execution {
    meta:
        description = "Detects mshta.exe executing remote scripts – common for initial access payloads"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1218.005 – Mshta"
        tags = "lolbin, mshta, t1218"
    strings:
        $mshta = "mshta" ascii nocase wide
        $vbscript = "vbscript:" ascii nocase wide
        $javascript = "javascript:" ascii nocase wide
        $http = "http://" ascii nocase wide
        $https = "https://" ascii nocase wide
        $about = "about:" ascii nocase wide
    condition:
        $mshta and ($vbscript or $javascript or $http or $https or $about)
}

rule LOLBin_Rundll32_Suspicious_Execution {
    meta:
        description = "Detects rundll32.exe abused to execute malicious code via DLL entrypoints or JavaScript"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "medium"
        mitre = "T1218.011 – Rundll32"
        tags = "lolbin, rundll32, t1218"
    strings:
        $rundll32 = "rundll32" ascii nocase wide
        $comsvcs = "comsvcs.dll" ascii nocase wide
        $minidump = "MiniDump" ascii nocase wide
        $advpack = "advpack.dll" ascii nocase wide
        $ieadvpack = "ieadvpack.dll" ascii nocase wide
        $shell32_shellexec = "shell32.dll,ShellExec_RunDLL" ascii nocase wide
        $syssetup = "syssetup.dll" ascii nocase wide
        $javascript = "javascript" ascii nocase wide
    condition:
        $rundll32 and (
            ($comsvcs and $minidump) or
            $advpack or $ieadvpack or
            $shell32_shellexec or
            $syssetup or
            $javascript
        )
}

rule LOLBin_BITSAdmin_Download {
    meta:
        description = "Detects BITSAdmin used to download files from external URLs"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "medium"
        mitre = "T1197, T1105"
        tags = "lolbin, bitsadmin, t1197"
    strings:
        $bitsadmin = "bitsadmin" ascii nocase wide
        $transfer = "/transfer" ascii nocase wide
        $addfile = "/addfile" ascii nocase wide
        $download = "/download" ascii nocase wide
        $http = "http" ascii nocase wide
        $setnotifycmdline = "/SetNotifyCmdLine" ascii nocase wide
    condition:
        $bitsadmin and ($transfer or $addfile or $download) and ($http or $setnotifycmdline)
}

rule LOLBin_WMI_Lateral_Movement {
    meta:
        description = "Detects WMI-based lateral movement and remote code execution"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1047 – Windows Management Instrumentation"
        tags = "lolbin, wmi, lateral_movement, t1047"
    strings:
        $wmic = "wmic" ascii nocase wide
        $node = "/node:" ascii nocase wide
        $process_call = "process call create" ascii nocase wide
        $wmiexec = "wmiexec" ascii nocase
        $wbemscripting = "WbemScripting" ascii wide
        $spawn_remote = "Win32_Process" ascii wide
    condition:
        ($wmic and $node and $process_call) or
        $wmiexec or
        ($wbemscripting and $spawn_remote)
}
