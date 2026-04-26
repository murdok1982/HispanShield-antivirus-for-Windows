/*
 * HispanShield Antivirus - Network Threat Detection Rules
 * Purpose: Defensive detection of known C2 frameworks and network threats
 * Author: HispanShield Team
 * License: GPL-3.0
 */

rule HispanShield_Generic_PE_in_Temp
{
    meta:
        description = "PE/MZ executable dropped in temporary directory"
        author      = "HispanShield Team"
        severity    = "medium"
        score       = 20
        tags        = "suspicious,dropper"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}

rule HispanShield_Suspicious_AutoRun_Script
{
    meta:
        description = "Script file placed in common autorun locations"
        author      = "HispanShield Team"
        severity    = "high"
        score       = 35
        tags        = "persistence,autorun"
        reference   = "https://attack.mitre.org/techniques/T1547/001/"

    strings:
        $run1 = "CurrentVersion\\Run"       ascii wide nocase
        $run2 = "CurrentVersion\\RunOnce"   ascii wide nocase
        $startup = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase

    condition:
        1 of them
}

rule HispanShield_Suspicious_Base64_Blob
{
    meta:
        description = "Unusually long Base64-encoded string, possible encoded payload"
        author      = "HispanShield Team"
        severity    = "medium"
        score       = 20
        tags        = "obfuscation,encoding"

    strings:
        // Long Base64 string (>200 chars of valid B64 alphabet)
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii

    condition:
        $b64
}

rule HispanShield_Reverse_Shell_Indicators
{
    meta:
        description = "Common reverse shell command patterns in scripts"
        author      = "HispanShield Team"
        severity    = "critical"
        score       = 60
        tags        = "reverse-shell,c2"

    strings:
        $nc1 = "nc.exe"           ascii wide nocase
        $nc2 = "ncat"             ascii wide nocase
        $ps_tcp = "Net.Sockets.TcpClient" ascii wide nocase
        $ps_stream = "System.Net.Sockets.NetworkStream" ascii wide nocase

    condition:
        1 of them
}

rule HispanShield_Credential_Access_Patterns
{
    meta:
        description = "Patterns associated with credential dumping from memory or files"
        author      = "HispanShield Team"
        severity    = "critical"
        score       = 70
        tags        = "credential-access,lsass"
        reference   = "https://attack.mitre.org/techniques/T1003/"

    strings:
        $lsass   = "lsass.exe"      ascii wide nocase
        $ntds    = "ntds.dit"       ascii wide nocase
        $sam     = "\\SAM"          ascii wide nocase
        $shadow  = "vssadmin"       ascii wide nocase
        $sekurl  = "sekurlsa"       ascii wide nocase

    condition:
        2 of them
}
