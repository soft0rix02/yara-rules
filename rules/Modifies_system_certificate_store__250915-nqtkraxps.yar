import "pe"

rule Modifies_system_certificate_store__250915-nqtkraxps {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250915-nqtkraxps5"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates" ascii wide nocase
    $s2 = "CABD2A79A1076A31F21D253635CB039D4329A5E8" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}