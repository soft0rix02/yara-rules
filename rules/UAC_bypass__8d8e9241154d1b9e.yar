import "pe"

rule UAC_bypass__8d8e9241154d1b9e {
  meta:
    source = "Recorded Future Triage"
    description = "UAC bypass"
    triage_id = "250916-efcptazxfx"
    sha256 = "8d8e9241154d1b9eb46755fe3b83639a071dfa732390ad14b1accfac4d341804"
    filename = "2025-09-16_d47aa35344fd1d951dac1adfbfafb7b3_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA" ascii wide nocase
    $s2 = "0" ascii wide nocase
    $s3 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin" ascii wide nocase
    $s4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}