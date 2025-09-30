import "pe"

rule Modifies_system_certificate_store__250914-znevcsz1e {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250914-znevcsz1ez"
    triage_score = "9"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates" ascii wide nocase
    $s2 = "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4" ascii wide nocase
    $s3 = "5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}