import "pe"

rule Modifies_WinLogon_for_persistence__a2b9723133ec293f {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250915-nzw28sap7s"
    sha256 = "a2b9723133ec293f8267b44a382f014a6b41910629364b6dd329b123499847b5"
    filename = "2025-09-15_8ddea63141a794bfe879beb0b432b82b_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "explorer.exe, \\\"C:\\Program Files (x86)\\Windows Media Player\\unsecapp.exe\\\"" ascii wide nocase
    $s3 = "explorer.exe, \\\"C:\\Program Files (x86)\\Windows Media Player\\unsecapp.exe\\\", \\\"C:\\Program Files (x86)\\MSBuild\\Microsoft\\Windows Workflow Foundation\\Registry.exe\\\"" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}