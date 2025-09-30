import "pe"

rule Modifies_WinLogon_for_persistence__13a9a8f631312a3e {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250915-nw95paxpz3"
    sha256 = "13a9a8f631312a3e08e3a2bdef6a2e7dbc59047c02c13504a407076eae1dca31"
    filename = "2025-09-15_6db53bb4e410ed75a91b5c49e23c95b0_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "explorer.exe, \\\"C:\\Windows\\twain_32\\dllhost.exe\\\"" ascii wide nocase
    $s3 = "explorer.exe, \\\"C:\\Windows\\twain_32\\dllhost.exe\\\", \\\"C:\\Recovery\\WindowsRE\\System.exe\\\"" ascii wide nocase
    $s4 = "explorer.exe, \\\"C:\\Windows\\twain_32\\dllhost.exe\\\", \\\"C:\\Recovery\\WindowsRE\\System.exe\\\", \\\"C:\\Recovery\\WindowsRE\\unsecapp.exe\\\"" ascii wide nocase
    $s5 = "explorer.exe, \\\"C:\\Windows\\twain_32\\dllhost.exe\\\", \\\"C:\\Recovery\\WindowsRE\\System.exe\\\", \\\"C:\\Recovery\\WindowsRE\\unsecapp.exe\\\", \\\"C:\\Program Files\\Crashpad\\reports\\fontdrvhost.exe\\\"" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}