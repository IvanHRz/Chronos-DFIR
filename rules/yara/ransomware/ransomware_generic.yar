/*
   Chronos-DFIR YARA Rules – Ransomware Generic Indicators
   Author: Chronos-DFIR / Ivan Huerta
   Date: 2026-03-07
   References:
     - DFIRArtifactMuseum (https://github.com/AndrewRathbun/DFIRArtifactMuseum)
     - https://github.com/advanced-threat-research/Yara-Rules
     - https://github.com/Yara-Rules/rules
*/

import "pe"

rule Ransomware_Generic_FileExtension_Rename {
    meta:
        description = "Detects generic ransomware behavior: mass file extension renaming or deletion combined with ransom note creation"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1486 – Data Encrypted for Impact"
        tags = "ransomware, t1486, encryption"
    strings:
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase wide
        $ransom_note2 = "All your files are encrypted" ascii nocase wide
        $ransom_note3 = "HOW TO RECOVER YOUR FILES" ascii nocase wide
        $ransom_note4 = "DECRYPT_INSTRUCTION" ascii nocase wide
        $ransom_note5 = "README_RECOVER" ascii nocase wide
        $ransom_note6 = "RESTORE_FILES" ascii nocase wide
        $ransom_note7 = "YOUR DATA HAS BEEN STOLEN" ascii nocase wide
        $tor_link = ".onion" ascii nocase wide
        $bitcoin = "bitcoin" ascii nocase wide
        $monero = "monero" ascii nocase wide
        $decryptor = "decryptor" ascii nocase wide
    condition:
        any of ($ransom_note*) and ($tor_link or $bitcoin or $monero or $decryptor)
}

rule Ransomware_LockBit_Indicators {
    meta:
        description = "Detects LockBit ransomware family artifacts and IOCs"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1486, T1489, T1562.001"
        tags = "ransomware, lockbit, t1486"
    strings:
        $lb1 = "LockBit" ascii nocase wide
        $lb2 = "lockbit" ascii
        $lb3 = ".lockbit" ascii wide
        $lb4 = "lb_config.ini" ascii nocase
        $lb5 = "Restore-My-Files.txt" ascii nocase wide
        $lb6 = "LockBit_Ransomware.hta" ascii nocase wide
        $del_shadow = "vssadmin Delete Shadows /All /Quiet" ascii nocase wide
        $bcdedit = "bcdedit /set {default} recoveryenabled No" ascii nocase wide
    condition:
        any of ($lb*) or ($del_shadow and $bcdedit)
}

rule Ransomware_Conti_Indicators {
    meta:
        description = "Detects Conti ransomware family artifacts"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "critical"
        mitre = "T1486, T1489"
        tags = "ransomware, conti, t1486"
    strings:
        $conti1 = "CONTI" ascii nocase wide
        $conti2 = "readme.txt" ascii nocase
        $conti3 = "Conti_Decrypt.txt" ascii nocase wide
        $conti4 = "CryptoLibrary" ascii
        $wipe_cmd = "wmic shadowcopy delete" ascii nocase wide
        $net_stop = "net stop" ascii nocase wide
        $iis_stop = "iisreset /stop" ascii nocase wide
    condition:
        (any of ($conti*) and ($wipe_cmd or $net_stop)) or
        ($wipe_cmd and $iis_stop and $net_stop)
}

rule Ransomware_ShadowCopy_Wipe {
    meta:
        description = "Detects VSS shadow copy deletion – universal ransomware pre-encryption step"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1490 – Inhibit System Recovery"
        tags = "ransomware, t1490, vss"
    strings:
        $vssadmin = "vssadmin delete shadows" ascii nocase wide
        $wmic_vss = "wmic shadowcopy delete" ascii nocase wide
        $diskshadow = "diskshadow /s" ascii nocase wide
        $bcdedit_no_recovery = "recoveryenabled no" ascii nocase wide
        $wbadmin = "wbadmin delete catalog" ascii nocase wide
        $sdelete = "sdelete -p" ascii nocase wide
    condition:
        2 of them
}

rule Ransomware_Encryption_API_Calls {
    meta:
        description = "Detects PE files calling Windows CryptEncrypt and file enumeration APIs typical of ransomware"
        author = "Chronos-DFIR / Ivan Huerta"
        date = "2026-03-07"
        severity = "high"
        mitre = "T1486"
        tags = "ransomware, crypto, pe"
    strings:
        $crypt_encrypt = "CryptEncrypt" ascii wide
        $crypt_gen_key = "CryptGenKey" ascii wide
        $crypt_derive = "CryptDeriveKey" ascii wide
        $find_first_file = "FindFirstFileW" ascii wide
        $find_next_file = "FindNextFileW" ascii wide
        $move_file = "MoveFileExW" ascii wide
        $delete_file = "DeleteFileW" ascii wide
    condition:
        pe.is_pe and
        ($crypt_encrypt or $crypt_gen_key or $crypt_derive) and
        ($find_first_file and $find_next_file) and
        ($move_file or $delete_file)
}
