/*
   Chronos-DFIR YARA Rules – macOS Persistence Indicators
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - https://attack.mitre.org/techniques/T1543/001/
     - https://objective-see.org/blog.html
     - DFIRArtifactMuseum
*/

rule macOS_Persistence_LaunchAgent_Suspicious {
    meta:
        description = "Detects suspicious LaunchAgent or LaunchDaemon plist with network or shell execution keys"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1543.001 – Launch Agent, T1543.004 – Launch Daemon"
        tags = "macos, launchagent, persistence, t1543"
    strings:
        $plist_header = "<?xml version=\"1.0\"" ascii
        $plist_key = "<key>ProgramArguments</key>" ascii
        $launch_agent_path1 = "Library/LaunchAgents/" ascii
        $launch_agent_path2 = "Library/LaunchDaemons/" ascii
        $run_at_load = "<key>RunAtLoad</key>" ascii
        $keep_alive = "<key>KeepAlive</key>" ascii
        $network_connect = "NetworkState" ascii
        $bash = "/bin/bash" ascii
        $sh = "/bin/sh" ascii
        $python = "/usr/bin/python" ascii
        $curl_cmd = "curl " ascii
        $base64 = "base64" ascii
        $encoded_pl = "EncodedCommand" ascii nocase
    condition:
        ($plist_header and $plist_key) and
        ($run_at_load or $keep_alive) and
        ($launch_agent_path1 or $launch_agent_path2 or $network_connect) and
        ($bash or $sh or $python or $curl_cmd or $base64 or $encoded_pl)
}

rule macOS_Persistence_Cron_Job {
    meta:
        description = "Detects suspicious cron job entries pointing to shell scripts or curl commands"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "medium"
        mitre = "T1053.003 – Cron"
        tags = "macos, cron, persistence, t1053"
    strings:
        $crontab_header = "MAILTO" ascii
        $cron_curl = "curl " ascii
        $cron_wget = "wget " ascii
        $cron_bash = "/bin/bash" ascii
        $cron_sh = "/bin/sh" ascii
        $cron_python = "python" ascii nocase
        $hidden_dir = "/tmp/" ascii
        $var_folder = "/var/folders" ascii
        $base64_decode = "base64 -d" ascii
        $pipe_bash = "| bash" ascii
        $pipe_sh = "| sh" ascii
    condition:
        ($crontab_header or $cron_bash or $cron_sh or $cron_python) and
        ($cron_curl or $cron_wget) and
        ($pipe_bash or $pipe_sh or $base64_decode or $hidden_dir or $var_folder)
}

rule macOS_Persistence_Login_Item_Suspicious {
    meta:
        description = "Detects suspicious macOS Login Items referencing hidden paths or scripts"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "medium"
        mitre = "T1547.015 – Login Item"
        tags = "macos, login_item, persistence, t1547"
    strings:
        $lsui = "LSUIElement" ascii
        $background_only = "LSBackgroundOnly" ascii
        $hidden_true = "<true/>" ascii
        $tmp_path = "/tmp/" ascii
        $var_tmp = "/var/tmp/" ascii
        $private_tmp = "/private/tmp/" ascii
        $dot_file = "/." ascii
    condition:
        ($lsui or $background_only) and $hidden_true and
        ($tmp_path or $var_tmp or $private_tmp or $dot_file)
}

rule macOS_Stealer_Keychain_Access {
    meta:
        description = "Detects attempts to access macOS Keychain for credential theft"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1555.001 – Keychain"
        tags = "macos, keychain, infostealer, t1555"
    strings:
        $keychain_path1 = "login.keychain" ascii nocase
        $keychain_path2 = "login.keychain-db" ascii nocase
        $keychain_path3 = "Library/Keychains/" ascii nocase
        $security_dump = "security dump-keychain" ascii nocase
        $security_find = "security find-generic-password" ascii nocase
        $security_find2 = "security find-internet-password" ascii nocase
        $securityd = "/usr/bin/security" ascii
        $chainbreaker = "chainbreaker" ascii nocase
    condition:
        any of them
}

rule macOS_Adware_DYLIB_Injection {
    meta:
        description = "Detects DYLD injection environment variable abuse for code injection on macOS"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1574.006 – Dynamic Linker Hijacking"
        tags = "macos, dylib_injection, t1574"
    strings:
        $dyld_insert = "DYLD_INSERT_LIBRARIES" ascii wide
        $dyld_force = "DYLD_FORCE_FLAT_NAMESPACE" ascii wide
        $dyld_path = "DYLD_LIBRARY_PATH" ascii wide
        $dylib_ext = ".dylib" ascii
        $tmp_dylib = "/tmp/" ascii
        $hidden_dylib = "/." ascii
    condition:
        ($dyld_insert or $dyld_force or $dyld_path) and ($dylib_ext or $tmp_dylib or $hidden_dylib)
}
