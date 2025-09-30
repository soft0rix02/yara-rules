import "pe"

rule Disables_RegEdit_via_registry_modification__0cc416acb6670d7b {
  meta:
    source = "Recorded Future Triage"
    description = "Disables RegEdit via registry modification"
    triage_id = "250914-zxntmaylx5"
    sha256 = "0cc416acb6670d7b3425894d7227226f8530754fd49a05f500240bc8661b53f8"
    filename = "JaffaCakes118_2d1b9bb14b6247540c9b9851bed71d93"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-4144907350-1836498122-2806216936-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" ascii wide nocase
    $s2 = "1" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}