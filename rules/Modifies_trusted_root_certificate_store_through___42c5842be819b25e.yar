import "pe"

rule Modifies_trusted_root_certificate_store_through___42c5842be819b25e {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies trusted root certificate store through registry"
    triage_id = "250915-n49twsyzhv"
    sha256 = "42c5842be819b25ea6329e75d4caecd81e7b160abdddff6cdd98277e23145cae"
    filename = "plua.txt"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\CABD2A79A1076A31F21D253635CB039D4329A5E8\\Blob" ascii wide nocase
    $s2 = "0400000001000000100000000cd2f9e0da1773e9ed864da5e370e74e14000000010000001400000079b459e67bb6e5e40173800888c81a58f6e99b6e030000000100000014000000cabd2a79a1076a31f21d253635cb039d4329a5e80f00000001000000200000003f0411ede9c4477057d57e57883b1f20" ascii wide nocase
    $s3 = "5c0000000100000004000000001000001900000001000000100000002fe1f70bb05d7c92335bc5e05b984da60f00000001000000200000003f0411ede9c4477057d57e57883b1f205b20cdc0f3263129b1ee0269a2678f63030000000100000014000000cabd2a79a1076a31f21d253635cb039d4329a5e8" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}