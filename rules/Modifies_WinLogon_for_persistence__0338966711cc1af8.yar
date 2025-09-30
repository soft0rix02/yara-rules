import "pe"

rule Modifies_WinLogon_for_persistence__0338966711cc1af8 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250915-n5hrssaq2x"
    sha256 = "0338966711cc1af8e720088704e352d07880970513e4c6c956a5d2df607d769b"
    filename = "2025-09-15_b51c78bdbc68a8f36365571b9e97857e_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}