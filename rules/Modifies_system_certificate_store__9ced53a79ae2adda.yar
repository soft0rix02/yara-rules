import "pe"

rule Modifies_system_certificate_store__9ced53a79ae2adda {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system certificate store"
    triage_id = "250915-h6fqyafl8s"
    sha256 = "9ced53a79ae2addaf032f572a382c791823e7cdbd16ed1a057a677ac80a9d45d"
    filename = "2025-09-15_6a2d876bf09c0c4f7e30589f1a72bde2_cryptolocker_elex"
    triage_score = "7"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-3001560346-2020497773-4190896137-1000\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates" ascii wide nocase
    $s2 = "40CEF3046C916ED7AE557F60E76842828B51DE53" ascii wide nocase
    $s3 = "\\REGISTRY\\USER\\S-1-5-21-3001560346-2020497773-4190896137-1000\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\40CEF3046C916ED7AE557F60E76842828B51DE53\\Blob" ascii wide nocase
    $s4 = "03000000010000001400000040cef3046c916ed7ae557f60e76842828b51de5314000000010000001400000017d9d6252767f931c24943d93036448c6ca94feb040000000100000010000000886ea78b530e0fd5bda4e12527ab6a2c0f00000001000000300000005d2164164eb6f3820b9b8d7a5601b60e" ascii wide nocase
    $s5 = "D89E3BD43D5D909B47A18977AA9D5CE36CEE184C" ascii wide nocase
    $s6 = "\\REGISTRY\\USER\\S-1-5-21-3001560346-2020497773-4190896137-1000\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\D89E3BD43D5D909B47A18977AA9D5CE36CEE184C\\Blob" ascii wide nocase
    $s7 = "030000000100000014000000d89e3bd43d5d909b47a18977aa9d5ce36cee184c1400000001000000140000005379bf5aaa2b4acf5480e1d89bc09df2b20366cb040000000100000010000000285ec909c4ab0d2d57f5086b225799aa0f000000010000003000000013baa039635f1c5292a8c2f36aae7e1d" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}