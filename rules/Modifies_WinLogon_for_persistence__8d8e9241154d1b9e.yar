import "pe"

rule Modifies_WinLogon_for_persistence__8d8e9241154d1b9e {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-efcptazxfx"
    sha256 = "8d8e9241154d1b9eb46755fe3b83639a071dfa732390ad14b1accfac4d341804"
    filename = "2025-09-16_d47aa35344fd1d951dac1adfbfafb7b3_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "explorer.exe, \\\"C:\\Program Files (x86)\\MSBuild\\sppsvc.exe\\\", \\\"C:\\589ba37997a284d35c\\fontdrvhost.exe\\\", \\\"C:\\Recovery\\WindowsRE\\SearchApp.exe\\\", \\\"C:\\Program Files (x86)\\Internet Explorer\\it-IT\\fontdrvhost.exe\\\"" ascii wide nocase
    $s3 = "explorer.exe, \\\"C:\\Program Files (x86)\\MSBuild\\sppsvc.exe\\\"" ascii wide nocase
    $s4 = "explorer.exe, \\\"C:\\Program Files (x86)\\MSBuild\\sppsvc.exe\\\", \\\"C:\\589ba37997a284d35c\\fontdrvhost.exe\\\"" ascii wide nocase
    $s5 = "explorer.exe, \\\"C:\\Program Files (x86)\\MSBuild\\sppsvc.exe\\\", \\\"C:\\589ba37997a284d35c\\fontdrvhost.exe\\\", \\\"C:\\Recovery\\WindowsRE\\SearchApp.exe\\\"" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}