import "pe"

rule Modifies_WinLogon_for_persistence__ccff5ae87eb6a3fd {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-ej3emszyby"
    sha256 = "ccff5ae87eb6a3fd58275a829da35fc5f4ae50a018b90d996b9bc525e6197f42"
    filename = "2025-09-16_81b6f9ff713ee8dbb7e9c640074c8880_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk_vidar"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}