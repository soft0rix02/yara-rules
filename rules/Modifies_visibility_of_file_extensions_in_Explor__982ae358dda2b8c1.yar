import "pe"

rule Modifies_visibility_of_file_extensions_in_Explor__982ae358dda2b8c1 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies visibility of file extensions in Explorer"
    triage_id = "250916-ehpgdseq6t"
    sha256 = "982ae358dda2b8c16d555dcda2518c7e0738077d2a97cdfff4bdbe840134a004"
    filename = "2025-09-16_6fa409acdf1e22bb7a0a99ae0e100417_amadey_elex_rhadamanthys_smoke-loader_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-2866795425-63786011-2927312124-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" ascii wide nocase
    $s2 = "1" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}