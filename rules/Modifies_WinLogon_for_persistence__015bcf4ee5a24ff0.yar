import "pe"

rule Modifies_WinLogon_for_persistence__015bcf4ee5a24ff0 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-efh7laeq2y"
    sha256 = "015bcf4ee5a24ff0f1b789c16fab40baa5dd14a4fd5fbe68b058928f191b97e3"
    filename = "2025-09-16_4e211e7e6367290d27c937d537f70b1e_amadey_elex_smoke-loader"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}