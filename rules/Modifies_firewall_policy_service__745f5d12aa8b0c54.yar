import "pe"

rule Modifies_firewall_policy_service__745f5d12aa8b0c54 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies firewall policy service"
    triage_id = "250916-ee1egsypy9"
    sha256 = "745f5d12aa8b0c544ce0a6433bb7962effbf06bdd36b8256c0304ca1a1196da1"
    filename = "2025-09-16_46878b50d252cf8d81c2bde23861f090_amadey_elex_emotet_smoke-loader_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts" ascii wide nocase
    $s2 = "List" ascii wide nocase
    $s3 = "\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy" ascii wide nocase
    $s4 = "StandardProfile" ascii wide nocase
    $s5 = "\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" ascii wide nocase
    $s6 = "GloballyOpenPorts" ascii wide nocase
    $s7 = "\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List\\10003:UDP" ascii wide nocase
    $s8 = "10003:UDP:*:Enabled:socketeser" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}