import "pe"

rule Modifies_WinLogon_for_persistence__0bb59a58296e5627 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-eh9gkaeq71"
    sha256 = "0bb59a58296e5627e8c26aa76ae2f3344501abdff54a0d33ba78b9e85905c281"
    filename = "2025-09-16_76358145b747efc7c2f0fd5661a3f4f7_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}