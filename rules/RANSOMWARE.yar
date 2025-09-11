rule RANSOMWARE {
    meta:
        author = "Metin Yiğit"
        description = "Detect ransomware ransom notes and executables with reduced false positives"
        date = "2024-09-02"
        yarahub_reference_md5 = "b0fd45162c2219e14bdccab76f33946e"
        yarahub_uuid = "960a3047-a95b-44b2-acf3-307196a680c2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $note1 = "All your files have been encrypted" wide ascii
        $note2 = "To recover your data" wide ascii
        $note3 = "payment in Bitcoin" wide ascii
        $onion = ".onion" ascii
        $tor   = "torproject.org" ascii
        $ext1  = ".encrypted" wide ascii
        $ext2  = ".locked" wide ascii

    condition:
        // Executables with ransom strings
        (uint16(0) == 0x5A4D and ( $note1 or $note2 or $note3 ) and ( $onion or $tor ))

        or

        // Ransom notes (text files under 200KB)
        (filesize < 200KB and ( $note1 or $note2 or $note3 ) and ( $onion or $tor ))
}
