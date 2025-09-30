import "pe"

rule Modifies_WinLogon_for_persistence__d7ff13e98dc6cf37 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250915-npep7san3y"
    sha256 = "d7ff13e98dc6cf37ab516440484a4d3f604570b2068a807d23fd21091b00a3b5"
    filename = "2025-09-15_2540bec534b951cf97a12cbc72a196da_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "explorer.exe, \\\"C:\\Program Files\\edge_BITS_4528_994486946\\SearchApp.exe\\\"" ascii wide nocase
    $s3 = "explorer.exe, \\\"C:\\Program Files\\edge_BITS_4528_994486946\\SearchApp.exe\\\", \\\"C:\\Program Files\\Windows Media Player\\Network Sharing\\Idle.exe\\\"" ascii wide nocase
    $s4 = "explorer.exe, \\\"C:\\Program Files\\edge_BITS_4528_994486946\\SearchApp.exe\\\", \\\"C:\\Program Files\\Windows Media Player\\Network Sharing\\Idle.exe\\\", \\\"C:\\Program Files\\edge_BITS_4384_762409323\\spoolsv.exe\\\"" ascii wide nocase
    $s5 = "explorer.exe, \\\"C:\\Program Files\\edge_BITS_4528_994486946\\SearchApp.exe\\\", \\\"C:\\Program Files\\Windows Media Player\\Network Sharing\\Idle.exe\\\", \\\"C:\\Program Files\\edge_BITS_4384_762409323\\spoolsv.exe\\\", \\\"C:\\076010aa" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}