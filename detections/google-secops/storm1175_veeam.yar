/*
   Storm-1175 Veeam Credential Recovery Detection
   Targets: credential recovery scripts, SQL access patterns, memory-resident variants
   Author:  Generated for defensive use
   Date:    2026-05-01
*/

rule Storm1175_Veeam_CredRecovery_Script
{
    meta:
        description  = "Detects scripts targeting Veeam credential store via PowerShell snap-in or direct SQL access"
        author       = "Detection Engineering"
        date         = "2026-05-01"
        severity     = "high"
        mitre_attack = "T1555 - Credentials from Password Stores"
        reference    = "Storm-1175 Veeam credential harvesting activity"

    strings:
        // Veeam PowerShell snap-in loading
        $ps_snapin    = "Veeam.Backup.PowerShell" ascii wide nocase

        // Direct SQL table access patterns seen in recovery tooling
        $sql_creds1   = "VeeamBackup" ascii wide nocase
        $sql_creds2   = "DbCredentials" ascii wide nocase
        $sql_creds3   = "select" ascii wide nocase

        // Known credential column names in Veeam DB schema
        $col_user     = "user_name" ascii wide nocase
        $col_pass     = "password" ascii wide nocase
        $col_desc     = "description" ascii wide nocase

        // Veeam encryption/decryption helper commonly abused
        $enc_helper   = "Veeam.Backup.Common.CryptoHelper" ascii wide nocase

        // Alternate: direct DLL load
        $dll_load     = "Veeam.Backup.Core.dll" ascii wide nocase

    condition:
        filesize < 2MB and
        (
            $ps_snapin or
            $enc_helper or
            $dll_load or
            (
                $sql_creds1 and $sql_creds2 and $sql_creds3 and
                2 of ($col_user, $col_pass, $col_desc)
            )
        )
}


rule Storm1175_Veeam_CredRecovery_Memory
{
    meta:
        description  = "Memory scan — detects Veeam credential recovery tooling loaded in process space"
        author       = "Detection Engineering"
        date         = "2026-05-01"
        severity     = "high"
        mitre_attack = "T1555 - Credentials from Password Stores"
        note         = "Use with -m flag; best targeted at powershell.exe, cmd.exe, wscript.exe"

    strings:
        // Decrypted credential markers that appear in memory after extraction
        $mem_marker1  = "VeeamBackup" wide ascii
        $mem_marker2  = "DbCredentials" wide ascii
        $mem_marker3  = "CryptoHelper" wide ascii

        // Plaintext patterns following decryption
        $cred_label   = "Password:" ascii wide nocase
        $host_label   = "Host:"     ascii wide nocase

        // Connection string fragments common to Veeam SQL instance
        $conn_str1    = "VeeamBackup;Integrated Security" ascii wide nocase
        $conn_str2    = "Data Source=.\\VEEAMSQL" ascii wide nocase

    condition:
        (
            ($mem_marker1 and $mem_marker2) or
            $mem_marker3 or
            $conn_str1 or
            $conn_str2
        ) and
        (
            $cred_label or $host_label
        )
}


rule Storm1175_Veeam_LateralMovement_Prep
{
    meta:
        description  = "Detects batch scripts or tooling that pair recovered Veeam credentials with lateral movement primitives (PsExec, WMI, SMB)"
        author       = "Detection Engineering"
        date         = "2026-05-01"
        severity     = "critical"
        mitre_attack = "T1021 - Remote Services, T1555 - Credentials from Password Stores"
        note         = "High-confidence when Veeam strings co-occur with remote exec primitives"

    strings:
        // Veeam credential access
        $veeam_ref    = "VeeamBackup" ascii wide nocase

        // Remote execution primitives often paired post-credential recovery
        $exec_psexec  = "psexec"              ascii wide nocase
        $exec_wmic    = "wmic"                ascii wide nocase
        $exec_invoke  = "Invoke-Command"      ascii wide nocase
        $exec_enter   = "Enter-PSSession"     ascii wide nocase
        $exec_net     = "net use"             ascii wide nocase
        $exec_schtask = "schtasks"            ascii wide nocase

        // Ransomware staging patterns sometimes bundled in same script
        $ransom_ext   = ".encrypted"          ascii wide nocase
        $ransom_vss   = "vssadmin delete"     ascii wide nocase
        $ransom_bcd   = "bcdedit /set"        ascii wide nocase

    condition:
        filesize < 5MB and
        $veeam_ref and
        (
            2 of ($exec_psexec, $exec_wmic, $exec_invoke, $exec_enter, $exec_net, $exec_schtask) or
            1 of ($ransom_ext, $ransom_vss, $ransom_bcd)
        )
}
