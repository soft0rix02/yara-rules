import "pe"

rule Modifies_WinLogon_for_persistence__df8fe34b5cfa2dab {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-eh9sbsyqs7"
    sha256 = "df8fe34b5cfa2dabe6b9ea70b21b8634f8788018e10a72f291b6218aab13a786"
    filename = "2025-09-16_f8257fa61e2c9319b0223c7e21316130_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}