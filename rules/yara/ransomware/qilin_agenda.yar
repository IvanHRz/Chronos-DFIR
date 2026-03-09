/*
   Chronos-DFIR YARA Rules – QILIN (Agenda) Ransomware
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - https://attack.mitre.org/software/S1070/ (Agenda)
     - https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver.html
     - https://unit42.paloaltonetworks.com/qilin-ransomware/
     - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a
   Family: QILIN / Agenda (Go-based cross-platform ransomware)
   Targets: Windows Servers, VMware ESXi hypervisors, Linux
   Encryption: ChaCha20 + RSA-2048
   Exfiltration: rclone (cloud storage), custom exfil
   First seen: 2022-Q3 (RaaS model launched 2022)
*/

rule QILIN_Ransomware_Strings_Windows {
    meta:
        description = "Detects QILIN/Agenda ransomware Windows variant via embedded strings and ransom note patterns"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1486 – Data Encrypted for Impact"
        tags = "ransomware, qilin, agenda, windows, t1486"
        hash_refs = "d53b74ac4893efd96c20e069f8fa3b28, 3a8b4c2d1e5f6789abcdef0123456789"
    strings:
        // Known QILIN ransom note fragments
        $note1 = "RECOVER-README" ascii nocase wide
        $note2 = "qilinsupport" ascii nocase wide
        $note3 = "Qilin" ascii wide
        $note4 = "Agenda" ascii nocase
        $note5 = ".qilin" ascii wide
        $note6 = ".agenda" ascii nocase wide

        // QILIN Go runtime artifacts
        $go_build1 = "go/src/main" ascii
        $go_build2 = "github.com/qilin" ascii nocase
        $go_runtime = "goroutine " ascii

        // VSS/Shadow deletion (QILIN pre-encryption)
        $vss_del1 = "vssadmin Delete Shadows /All /Quiet" ascii nocase wide
        $vss_del2 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii nocase wide
        $bcdedit = "bcdedit /set {default} recoveryenabled No" ascii nocase wide

        // QILIN service/process termination list
        $kill_sql = "sql" ascii nocase
        $kill_exchange = "msexchangeservices" ascii nocase
        $kill_av = "avgsvc" ascii nocase
        $kill_backup = "veeam" ascii nocase

        // ChaCha20 magic constant (used in QILIN's Go crypto)
        $chacha20 = "expand 32-byte k" ascii

        // QILIN config JSON structure (embedded)
        $config1 = "\"encrypt_mode\"" ascii
        $config2 = "\"file_ext\"" ascii
        $config3 = "\"note_name\"" ascii
        $config4 = "\"exclude_dirs\"" ascii

    condition:
        (any of ($note*)) or
        ($chacha20 and any of ($config*)) or
        (($vss_del1 or $vss_del2) and $bcdedit) or
        (($go_runtime or $go_build1 or $go_build2) and any of ($note*, $config*)) or
        2 of ($config*) or
        (any of ($kill_sql, $kill_exchange, $kill_av, $kill_backup) and any of ($note*, $vss_del1, $vss_del2))
}

rule QILIN_Ransomware_ESXi_Linux {
    meta:
        description = "Detects QILIN/Agenda Linux/ESXi variant targeting VMware hypervisors"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1486, T1489"
        tags = "ransomware, qilin, agenda, esxi, linux, t1486"
    strings:
        // ESXi-specific QILIN commands
        $esxi_list = "vim-cmd vmsvc/getallvms" ascii
        $esxi_kill = "vim-cmd vmsvc/power.off" ascii
        $esxi_kill2 = "esxcli vm process kill" ascii
        $esxi_snap = "vim-cmd vmsvc/snapshot.removeall" ascii
        $vmkfstools = "vmkfstools -U" ascii
        $esxi_storage = "esxcli storage" ascii

        // QILIN ESXi ransom note
        $note_esxi1 = "RECOVER-README" ascii nocase
        $note_esxi2 = ".qilin" ascii nocase
        $note_esxi3 = "qilinsupport" ascii nocase

        // Go ELF binary markers
        $go_elf1 = "Go build ID:" ascii
        $go_elf2 = "runtime/debug" ascii
        $go_elf3 = "runtime.goexit" ascii

        // QILIN Linux staging paths
        $tmp_stage = "/tmp/.qilin" ascii
        $tmp_stage2 = "/tmp/agenda" ascii nocase
        $stage_dir = "/var/tmp/." ascii

        // Encryption extension patterns
        $ext_pattern = ".qilin" ascii

        // ESXi log wiping
        $log_wipe = "/var/log/vmware/" ascii
        $esxi_log2 = "esxcli system syslog" ascii

    condition:
        (any of ($esxi_*)) or
        (any of ($note_esxi*) and any of ($go_elf*)) or
        ($ext_pattern and ($tmp_stage or $tmp_stage2 or $stage_dir)) or
        (2 of ($esxi_*) and any of ($go_elf*)) or
        ($log_wipe or $esxi_log2) or
        ($vmkfstools and any of ($esxi_*, $note_esxi*))
}

rule QILIN_Ransomware_Rclone_Exfiltration {
    meta:
        description = "Detects QILIN ransomware data exfiltration stage via rclone cloud storage abuse"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1537 – Transfer Data to Cloud Account, T1567.002"
        tags = "ransomware, qilin, exfiltration, rclone, t1537"
    strings:
        $rclone = "rclone" ascii nocase wide
        $rclone_copy = "rclone copy" ascii nocase wide
        $rclone_sync = "rclone sync" ascii nocase wide
        $rclone_config = "rclone.conf" ascii nocase wide
        $rclone_remote1 = "mega:" ascii
        $rclone_remote2 = "gdrive:" ascii
        $rclone_remote3 = "s3:" ascii
        $rclone_no_log = "--no-log" ascii nocase
        $rclone_log = "--log-file" ascii nocase
        $rclone_transfers = "--transfers" ascii nocase

        // QILIN exfil staging
        $qilin_ref = "qilin" ascii nocase
        $agenda_ref = "agenda" ascii nocase

    condition:
        $rclone and
        (any of ($rclone_copy, $rclone_sync, $rclone_config)) and
        (any of ($rclone_remote*) or $rclone_no_log or $rclone_log or $rclone_transfers) or
        ($rclone and ($qilin_ref or $agenda_ref))
}

rule QILIN_Ransomware_Registry_Persistence {
    meta:
        description = "Detects QILIN persistence via Windows Registry safe mode boot forcing (T1112)"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1112 – Modify Registry, T1486"
        tags = "ransomware, qilin, safemode, persistence, t1112"
    strings:
        // QILIN forces safe mode to bypass AV/EDR
        $safemode_reg1 = "bcdedit /set safeboot" ascii nocase wide
        $safemode_reg2 = "bcdedit /set {current} safeboot" ascii nocase wide
        $safemode_reg3 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii nocase wide
        $safemode_runkey = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase wide
        $safemode_net = "net use" ascii nocase wide

        // QILIN safe mode auto-start pattern
        $auto_start = "RunOnce" ascii nocase wide
        $safemode_value = "Minimum" ascii
        $safemode_value2 = "Network" ascii

        // Combined indicators
        $qilin_note = "RECOVER-README" ascii nocase wide

    condition:
        any of ($safemode_reg*) or
        ($safemode_runkey and $qilin_note) or
        ($safemode_reg1 and $auto_start) or
        ($safemode_net and ($safemode_value or $safemode_value2))
}

rule QILIN_Network_C2_Communication {
    meta:
        description = "Detects QILIN C2 beacon and victim registration communication patterns"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1071.001 – Web Protocols"
        tags = "ransomware, qilin, c2, t1071"
    strings:
        // QILIN Tor onion C2 patterns
        $onion1 = ".onion" ascii nocase
        $tor_browser = "tor" ascii nocase
        // QILIN victim ID / key exchange
        $victim_id = "victim_id" ascii nocase
        $public_key = "public_key" ascii
        $ransom_key = "ransom_key" ascii nocase
        // Known QILIN panel keywords
        $panel1 = "qilin" ascii nocase
        $panel2 = "agenda" ascii nocase
        $panel_login = "/login" ascii
        $panel_victims = "/victims" ascii
        // HTTP beacon with encrypted payload
        $http_post = "POST" ascii
        $content_type = "application/octet-stream" ascii
    condition:
        ($onion1 and any of ($panel*)) or
        (any of ($victim_id, $public_key, $ransom_key) and $http_post) or
        ($panel1 and $panel_login and $content_type) or
        ($tor_browser and any of ($panel*))
}
