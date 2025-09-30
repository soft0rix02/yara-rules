import "pe"

rule Modifies_WinLogon_for_persistence__dead14036b572eee {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-ef8r9azxhv"
    sha256 = "dead14036b572eeee55458d9b61c871dde1935d55f80301664b478d5527351fe"
    filename = "2025-09-16_591d8391c11855904a969d6a82672092_darkgate_elex_luca-stealer_necurs_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}