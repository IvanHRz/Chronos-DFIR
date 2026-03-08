/*
   Chronos-DFIR YARA Rules – Infostealer Indicators
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - DFIRArtifactMuseum
     - https://github.com/Yara-Rules/rules
     - CISA / US-CERT advisories
*/

import "pe"

rule Infostealer_Generic_Browser_Data_Theft {
    meta:
        description = "Detects infostealer accessing browser credential stores and cookies"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1555.003 – Credentials from Web Browsers"
        tags = "infostealer, t1555, browser"
    strings:
        $chrome_login = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase wide
        $chrome_cookies = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii nocase wide
        $chrome_local_state = "\\Google\\Chrome\\User Data\\Local State" ascii nocase wide
        $firefox_login = "\\Mozilla\\Firefox\\Profiles" ascii nocase wide
        $firefox_key = "key4.db" ascii nocase wide
        $edge_login = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii nocase wide
        $brave_login = "\\BraveSoftware\\Brave-Browser\\User Data" ascii nocase wide
        $opera_login = "\\Opera Software\\Opera Stable" ascii nocase wide
        $dpapi_decrypt = "CryptUnprotectData" ascii wide
        $sqlite_magic = "SQLite format" ascii
    condition:
        (2 of ($chrome_*, $firefox_*, $edge_*, $brave_*, $opera_*)) or
        ($dpapi_decrypt and any of ($chrome_*, $edge_*)) or
        ($sqlite_magic and any of ($firefox_*))
}

rule Infostealer_RedLine_Stealer {
    meta:
        description = "Detects RedLine Stealer C2 communication and credential harvesting strings"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1555, T1041"
        tags = "infostealer, redline, t1555"
    strings:
        $rl1 = "RedLine" ascii nocase
        $rl2 = "ScanData" ascii
        $rl3 = "GetSystemInfo" ascii
        $rl4 = "wallets" ascii nocase
        $rl5 = "telegram" ascii nocase
        $crypto_wallet_eth = "\\Ethereum\\keystore" ascii nocase wide
        $crypto_wallet_btc = "wallet.dat" ascii nocase wide
        $crypto_wallet_metamask = "MetaMask" ascii nocase wide
        $ftp_cred = "FileZilla\\recentservers.xml" ascii nocase wide
        $steam_cred = "Steam\\config\\loginusers.vdf" ascii nocase wide
    condition:
        (any of ($rl*) and 2 of ($crypto_wallet_*, $ftp_cred, $steam_cred)) or
        (3 of ($crypto_wallet_*, $ftp_cred, $steam_cred))
}

rule Infostealer_Keylogger_Generic {
    meta:
        description = "Detects keylogger patterns using SetWindowsHookEx or GetAsyncKeyState"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1056.001 – Input Capture: Keylogging"
        tags = "keylogger, t1056, infostealer"
    strings:
        $hook = "SetWindowsHookEx" ascii wide
        $hook_kb = "WH_KEYBOARD_LL" ascii wide
        $getkey = "GetAsyncKeyState" ascii wide
        $lowlevel_hook = "SetWindowsHookExA" ascii wide
        $unhook = "UnhookWindowsHookEx" ascii wide
        $log_key = "keylogger" ascii nocase
        $log_key2 = "keystroke" ascii nocase
    condition:
        pe.is_pe and
        (($hook or $hook_kb or $lowlevel_hook) and ($getkey or $unhook)) or
        ($log_key or $log_key2)
}

rule Infostealer_Clipboard_Hijacker {
    meta:
        description = "Detects clipboard hijacking for cryptocurrency address replacement"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1115 – Clipboard Data"
        tags = "clipper, t1115, crypto"
    strings:
        $get_clipboard = "GetClipboardData" ascii wide
        $set_clipboard = "SetClipboardData" ascii wide
        $open_clipboard = "OpenClipboard" ascii wide
        $btc_regex = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth_regex = /0x[a-fA-F0-9]{40}/ ascii
        $monero_regex = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
    condition:
        pe.is_pe and
        ($get_clipboard and $set_clipboard and $open_clipboard) and
        ($btc_regex or $eth_regex or $monero_regex)
}

rule Infostealer_Credential_Dump_DPAPI {
    meta:
        description = "Detects DPAPI-based credential decryption typical of infostealers targeting Windows credential manager"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1555.004 – Windows Credential Manager"
        tags = "infostealer, dpapi, t1555"
    strings:
        $dpapi1 = "CryptUnprotectData" ascii wide
        $dpapi2 = "NCryptOpenKey" ascii wide
        $cred_manager = "Windows Credentials" ascii nocase wide
        $cred_vault = "Vault" ascii
        $cred_target = "CredReadW" ascii wide
        $cred_enum = "CredEnumerateW" ascii wide
    condition:
        pe.is_pe and
        any of ($dpapi*) and
        any of ($cred_manager, $cred_vault, $cred_target, $cred_enum)
}
