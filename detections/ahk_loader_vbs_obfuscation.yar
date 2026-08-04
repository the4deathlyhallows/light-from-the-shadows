/*
    AHK RAT Loader Campaign - VBScript Obfuscation Detector
    Ref: https://blog.morphisec.com/ahk-rat-loader-leveraged-in-unique-delivery-campaigns
    Ref: https://thehackernews.com/2021/05/experts-warn-about-ongoing-autohotkey.html

    Detects VBS droppers using StrReverse()-wrapped Execute() calls plus a custom
    Chr(Asc(Mid(...))) character-shift decoder to reconstruct a PowerShell
    HttpWebRequest download cradle at runtime (observed pulling payloads from
    stikked.ch and executing them via IEX). This matches the dropper stage that
    delivers LimeRAT/AsyncRAT/RevengeRAT/Houdini/Vjw0rm.
*/

rule AHK_Loader_VBS_StrReverse_Obfuscation
{
    meta:
        author      = "Detection Engineering"
        date        = "2026-08-04"
        description = "VBScript using StrReverse+Execute with a Chr/Asc/Mid decoder, consistent with AHK RAT loader campaign"
        reference1  = "https://blog.morphisec.com/ahk-rat-loader-leveraged-in-unique-delivery-campaigns"
        reference2  = "https://thehackernews.com/2021/05/experts-warn-about-ongoing-autohotkey.html"
        confidence  = "high"

    strings:
        $execute_reverse = "Execute(StrReverse(" nocase
        $strreverse      = "StrReverse(" nocase
        $char_decoder     = /Chr\s*\(\s*Asc\s*\(\s*Mid\s*\(/ nocase
        $ps_marker1      = "HttpWebRequest" nocase
        $ps_marker2      = "GetResponseStream" nocase
        $ps_marker3      = "StreamReader" nocase
        $paste_host       = "stikked.ch" nocase

    condition:
        filesize < 500KB
        and $execute_reverse
        and #strreverse >= 3
        and $char_decoder
        and (1 of ($ps_marker*) or $paste_host)
}

rule AHK_Loader_Compiled_AHK_Dropper_Heuristic
{
    meta:
        author      = "Detection Engineering"
        date        = "2026-08-04"
        description = "Heuristic for compiled AutoHotkey executables embedding a VBScript/FileInstall payload (AHK loader campaign pattern)"
        reference1  = "https://blog.morphisec.com/ahk-rat-loader-leveraged-in-unique-delivery-campaigns"
        confidence  = "medium"

    strings:
        $ahk_marker1 = "AutoHotkey" ascii wide
        $ahk_marker2 = ">AUTOHOTKEY SCRIPT<" ascii
        $fileinstall = "FileInstall" ascii nocase
        $vbs_ext     = ".vbs" ascii wide nocase
        $ps_flag1    = "-windowstyle hidden" ascii wide nocase
        $ps_flag2    = "-nop" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D // PE file
        and 1 of ($ahk_marker*)
        and $fileinstall
        and $vbs_ext
        and 1 of ($ps_flag*)
}
