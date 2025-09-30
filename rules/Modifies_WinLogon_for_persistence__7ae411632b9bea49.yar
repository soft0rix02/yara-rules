import "pe"

rule Modifies_WinLogon_for_persistence__7ae411632b9bea49 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-ejectayqt4"
    sha256 = "7ae411632b9bea4993a2c6ff803e62f778c4be1bd74277d0486fe60714f45656"
    filename = "2025-09-16_7f9090cc518ee2c3d833d9252a4bbef1_darkgate_elex_luca-stealer_njrat_rhadamanthys_ryuk"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "Explorer.exe  HelpMe.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}