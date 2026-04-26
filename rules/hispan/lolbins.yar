/*
 * HispanShield Antivirus - LOLBins Detection Rules
 * Purpose: Defensive detection of Living-off-the-Land Binaries abuse
 * These rules help identify suspicious use of legitimate Windows tools
 * Author: HispanShield Team
 * License: GPL-3.0
 */

rule HispanShield_LOLBin_PowerShell_Encoded
{
    meta:
        description = "PowerShell invoked with encoded command and hidden window"
        author      = "HispanShield Team"
        severity    = "medium"
        score       = 25
        tags        = "lolbin,powershell,evasion"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc "           ascii wide nocase
        $hidden   = "-WindowStyle Hidden"      ascii wide nocase
        $bypass   = "-ExecutionPolicy Bypass"  ascii wide nocase
        $noprof   = "-NonInteractive"          ascii wide nocase

    condition:
        1 of ($enc*) and 1 of ($hidden, $bypass, $noprof)
}

rule HispanShield_LOLBin_Certutil_Decode
{
    meta:
        description = "Certutil used to decode or download files - common abuse vector"
        author      = "HispanShield Team"
        severity    = "high"
        score       = 25
        tags        = "lolbin,certutil"
        reference   = "https://attack.mitre.org/techniques/T1140/"

    strings:
        $decode   = "-decode"   ascii nocase
        $urlcache = "-urlcache" ascii nocase
        $split    = "-split"    ascii nocase

    condition:
        1 of them
}

rule HispanShield_LOLBin_Bitsadmin_Transfer
{
    meta:
        description = "Bitsadmin used to transfer or download files"
        author      = "HispanShield Team"
        severity    = "high"
        score       = 25
        tags        = "lolbin,bitsadmin"
        reference   = "https://attack.mitre.org/techniques/T1197/"

    strings:
        $transfer = "/transfer" ascii nocase
        $create   = "/create"   ascii nocase
        $addfile  = "/addfile"  ascii nocase

    condition:
        1 of them
}

rule HispanShield_LOLBin_Mshta_Remote
{
    meta:
        description = "MSHTA loading remote or script content"
        author      = "HispanShield Team"
        severity    = "high"
        score       = 25
        tags        = "lolbin,mshta"
        reference   = "https://attack.mitre.org/techniques/T1218/005/"

    strings:
        $http  = "http://"    ascii nocase
        $https = "https://"   ascii nocase
        $vbs   = "vbscript:"  ascii nocase
        $js    = "javascript:" ascii nocase

    condition:
        1 of them
}

rule HispanShield_LOLBin_Regsvr32_Scrobj
{
    meta:
        description = "Regsvr32 loading scriptlet via scrobj.dll (Squiblydoo technique)"
        author      = "HispanShield Team"
        severity    = "critical"
        score       = 40
        tags        = "lolbin,regsvr32"
        reference   = "https://attack.mitre.org/techniques/T1218/010/"

    strings:
        $scrobj  = "scrobj.dll" ascii nocase
        $regsvr  = "regsvr32"   ascii nocase
        $http    = "http"       ascii nocase

    condition:
        ($scrobj and $regsvr) or ($scrobj and $http)
}

rule HispanShield_Ransomware_NoteIndicators
{
    meta:
        description = "Ransom note filenames commonly dropped by ransomware families"
        author      = "HispanShield Team"
        severity    = "critical"
        score       = 50
        tags        = "ransomware,behavior"

    strings:
        $note1 = "HOW_TO_DECRYPT"          ascii wide nocase
        $note2 = "RECOVER_FILES"           ascii wide nocase
        $note3 = "README_RANSOMWARE"       ascii wide nocase
        $note4 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $note5 = "RESTORE_FILES"           ascii wide nocase
        $note6 = "DECRYPT_INSTRUCTIONS"   ascii wide nocase
        $note7 = "FILES_ENCRYPTED"        ascii wide nocase

    condition:
        1 of them
}

rule HispanShield_Suspicious_DoubleExtension
{
    meta:
        description = "Executable with double extension used to disguise malware as document"
        author      = "HispanShield Team"
        severity    = "medium"
        score       = 30
        tags        = "suspicious,social-engineering"

    strings:
        $pdf_exe  = ".pdf.exe"  ascii wide nocase
        $doc_exe  = ".doc.exe"  ascii wide nocase
        $xlsx_exe = ".xlsx.exe" ascii wide nocase
        $jpg_exe  = ".jpg.exe"  ascii wide nocase
        $png_exe  = ".png.exe"  ascii wide nocase
        $zip_exe  = ".zip.exe"  ascii wide nocase

    condition:
        1 of them
}

rule HispanShield_Wscript_Remote_Download
{
    meta:
        description = "WScript or CScript executing remote or downloaded scripts"
        author      = "HispanShield Team"
        severity    = "high"
        score       = 30
        tags        = "lolbin,wscript,cscript"
        reference   = "https://attack.mitre.org/techniques/T1059/005/"

    strings:
        $http  = "http://"  ascii wide nocase
        $https = "https://" ascii wide nocase
        $temp  = "\\Temp\\"  ascii wide nocase
        $appd  = "AppData"   ascii wide nocase

    condition:
        1 of ($http, $https) and 1 of ($temp, $appd)
}
