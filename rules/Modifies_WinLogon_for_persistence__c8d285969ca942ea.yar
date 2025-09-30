import "pe"

rule Modifies_WinLogon_for_persistence__c8d285969ca942ea {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-eg85eaeq5w"
    sha256 = "c8d285969ca942ea136b7265a04c25ec020f85398a6e57c142e7525b7da7e649"
    filename = "2025-09-16_eaaf6cf23b3e979187713f4a16b29067_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}