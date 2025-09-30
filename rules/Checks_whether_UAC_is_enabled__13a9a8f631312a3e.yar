import "pe"

rule Checks_whether_UAC_is_enabled__13a9a8f631312a3e {
  meta:
    source = "Recorded Future Triage"
    description = "Checks whether UAC is enabled"
    triage_id = "250915-nw95paxpz3"
    sha256 = "13a9a8f631312a3e08e3a2bdef6a2e7dbc59047c02c13504a407076eae1dca31"
    filename = "2025-09-15_6db53bb4e410ed75a91b5c49e23c95b0_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA" ascii wide nocase
    $s2 = "0" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}