import "pe"

rule Boot_or_Logon_Autostart_Execution_Active_Setup__bf5c1d591f2e05a1 {
  meta:
    source = "Recorded Future Triage"
    description = "Boot or Logon Autostart Execution: Active Setup"
    triage_id = "250914-znnghaykz6"
    sha256 = "bf5c1d591f2e05a1b741feff2db7dc34fae66432bcce18e92fcbf5a0dcc18e9b"
    filename = "JaffaCakes118_2d1ad317dccdd5c9f8f69a6b08ca6fce"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components" ascii wide nocase
    $s2 = "{46F6AEF2-8B9A-11D5-EBA1-F78EEEEEE983}" ascii wide nocase
    $s3 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components\\{46F6AEF2-8B9A-11D5-EBA1-F78EEEEEE983}\\StubPath" ascii wide nocase
    $s4 = "msjgu32.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}