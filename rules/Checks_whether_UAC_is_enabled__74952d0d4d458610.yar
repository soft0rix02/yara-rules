import "pe"

rule Checks_whether_UAC_is_enabled__74952d0d4d458610 {
  meta:
    source = "Recorded Future Triage"
    description = "Checks whether UAC is enabled"
    triage_id = "250916-egycxaeq4z"
    sha256 = "74952d0d4d458610402331689c40ec62607ce81d8a2037688b207fdc0cfca17d"
    filename = "2025-09-16_5caa9f31ebcfb60809e4f02ad931aa9b_acrstealer_amadey_darkgate_datper_elex_smoke-loader"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA" ascii wide nocase
    $s2 = "0" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}