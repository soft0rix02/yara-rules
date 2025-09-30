import "pe"

rule Modifies_WinLogon_for_persistence__aacdedb7b3afbf6f {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250915-ny5yraxp15"
    sha256 = "aacdedb7b3afbf6f6ab60068c79c5fd551f9388617a059f6018ce490db1474d2"
    filename = "2025-09-15_f432cdb0de19d39dc7be12ad223b909f_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk_vidar"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}