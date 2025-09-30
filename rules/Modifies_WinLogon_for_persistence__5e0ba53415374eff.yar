import "pe"

rule Modifies_WinLogon_for_persistence__5e0ba53415374eff {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-elxxyaer4s"
    sha256 = "5e0ba53415374effd2fbb7b4a269352ac0955415710963e75afa9a84dfc1c483"
    filename = "2025-09-16_a95c50c949f892d73fdd6fb9a190bb53_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk_vidar"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}