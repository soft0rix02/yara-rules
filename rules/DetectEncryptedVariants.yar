rule DetectEncryptedVariants
{
    meta:
        description = "Detects ransomware-style encryption indicators"
        author = "Metin Yiğit"
        date = "2025-06-20"
        yarahub_reference_md5 = "b0fd45162c2219e14bdccab76f33946e"
        yarahub_uuid = "0d185fc2-9c49-498e-b7ce-b28db1b9f36b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $ascii = "encrypted" wide ascii
        $note1 = "All your files have been encrypted" wide ascii
        $note2 = "To recover your data" wide ascii
        $ext1  = ".encrypted" wide ascii
        $ext2  = ".locked" wide ascii

    condition:
        uint16(0) == 0x5A4D and ( $note1 or $note2 or ( $ascii and ( $ext1 or $ext2 ) ) )
}
