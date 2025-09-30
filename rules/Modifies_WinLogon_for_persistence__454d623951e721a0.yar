import "pe"

rule Modifies_WinLogon_for_persistence__454d623951e721a0 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-ejyrfsyqv4"
    sha256 = "454d623951e721a0a4c3ea2fa5cbad0dca4ffae862d5fff4762ec8defb333856"
    filename = "2025-09-16_779e9a45cabab650cc91fe85091e0f90_darkgate_elex_luca-stealer_necurs_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}