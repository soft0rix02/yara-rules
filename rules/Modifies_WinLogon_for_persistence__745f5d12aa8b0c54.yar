import "pe"

rule Modifies_WinLogon_for_persistence__745f5d12aa8b0c54 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies WinLogon for persistence"
    triage_id = "250916-ee1egsypy9"
    sha256 = "745f5d12aa8b0c544ce0a6433bb7962effbf06bdd36b8256c0304ca1a1196da1"
    filename = "2025-09-16_46878b50d252cf8d81c2bde23861f090_amadey_elex_emotet_smoke-loader_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide nocase
    $s2 = "explorer.exe C:\\WINDOWS\\system32\\drivers\\svchost.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}