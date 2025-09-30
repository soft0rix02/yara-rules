import "pe"

rule Modifies_system_certificate_store__2dff4a2e4d4c0fed {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250915-ny8dwaxp17"
    sha256 = "2dff4a2e4d4c0fedcb1204725afa9bd7e38e67aa8efdf667713ffc157e6d11ef"
    filename = "NOTEPAD.txt"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates" ascii wide nocase
    $s2 = "CABD2A79A1076A31F21D253635CB039D4329A5E8" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}