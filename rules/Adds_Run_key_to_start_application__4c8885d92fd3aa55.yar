rule Adds_Run_key_to_start_application__4c8885d92fd3aa55 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-egh8zseq4w"
    sha256 = "4c8885d92fd3aa5551ba5f8e7915bd676ef48d764a6a93cc7ad08eae361a2fb1"
    filename = "2025-09-16_dfc44a1d0adcc1e1c008b6ed3b2a290c_cobalt-strike_poet-rat_sliver_snatch"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "c:\\Windows\\System32\\FWPLMaf.exe" ascii wide nocase
	$s3 = "FWPLMaf" ascii wide nocase
    $s4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s5 = "c:\\Windows\\System32\\mJRRf.exe" ascii wide nocase
	$s6 = "mJRRf" ascii wide nocase
    $s7 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s8 = "c:\\Windows\\System32\\iFiELmIrx.exe" ascii wide nocase
	$s9 = "iFiELmIrx" ascii wide nocase
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6) or ($s7 and $s8 and $s9)
}