import "pe"
import "math"

rule Sus_Obf_Enc_Spoof_Hide_PE {
    meta:
        author = "Metin Yiğit"
        description = "Suspicious PE heuristics (reduced FP)"
        date = "2024-11-21"
        yarahub_license = "CC0 1.0"

    condition:
        pe.is_pe and uint16(0) == 0x5A4D and filesize < 50MB and
        (
            // Require at least 2 strong indicators
            2 of (
                (pe.number_of_imports == 0 and pe.number_of_exports > 0),
                (pe.number_of_sections > 11),
                (pe.overlay.size > 100KB),
                (math.entropy(0, filesize) > 7.5),
                (for any s in pe.sections :
                    (s.size > 0x200 and math.entropy(s.raw_data_offset, s.raw_data_size) > 7.8)
                )
            )
        )
}
