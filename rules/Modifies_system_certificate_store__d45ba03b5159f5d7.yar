import "pe"

rule Modifies_system_certificate_store__d45ba03b5159f5d7 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250915-nwb8naxpy3"
    sha256 = "d45ba03b5159f5d7df37287eed04e252fed8196407556e167376b3b26be090b6"
    filename = "2025-09-15_3a84e7aa2009b5065f6c60baee4a85d3_dosia_frostygoop_ghostlocker_knight_luca-stealer_poet-rat_quasar-rat_sliver_snatch"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates" ascii wide nocase
    $s2 = "CABD2A79A1076A31F21D253635CB039D4329A5E8" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}