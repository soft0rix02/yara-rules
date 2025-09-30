import "pe"

rule System_policy_modification__d7ff13e98dc6cf37 {
  meta:
    source = "Recorded Future Triage"
    description = "System policy modification"
    triage_id = "250915-npep7san3y"
    sha256 = "d7ff13e98dc6cf37ab516440484a4d3f604570b2068a807d23fd21091b00a3b5"
    filename = "2025-09-15_2540bec534b951cf97a12cbc72a196da_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
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