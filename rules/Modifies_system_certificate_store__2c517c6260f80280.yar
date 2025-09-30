import "pe"

rule Modifies_system_certificate_store__2c517c6260f80280 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250914-zm75hsz1es"
    sha256 = "2c517c6260f80280da0f0c840e83eba000f138f7f36880cf2f4be5466f144ec6"
    filename = "Installer2.0.zip"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates" ascii wide nocase
    $s2 = "8CF427FD790C3AD166068DE81E57EFBB932272D4" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}