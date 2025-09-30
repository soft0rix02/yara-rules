import "pe"

rule Windows_security_bypass__0cc416acb6670d7b {
  meta:
    source = "Recorded Future Triage"
    description = "Windows security bypass"
    triage_id = "250914-zxntmaylx5"
    sha256 = "0cc416acb6670d7b3425894d7227226f8530754fd49a05f500240bc8661b53f8"
    filename = "JaffaCakes118_2d1b9bb14b6247540c9b9851bed71d93"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Security Center\\AntiVirusDisableNotify" ascii wide nocase
    $s2 = "1" ascii wide nocase
    $s3 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Security Center\\FirewallDisableNotify" ascii wide nocase
    $s4 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Security Center\\UpdatesDisableNotify" ascii wide nocase
    $s5 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Security Center\\AntiVirusOverride" ascii wide nocase
    $s6 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Security Center\\FirewallOverride" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}