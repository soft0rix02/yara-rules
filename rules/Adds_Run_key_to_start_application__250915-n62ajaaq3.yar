rule Adds_Run_key_to_start_application__250915-n62ajaaq3 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-n62ajaaq3w"
    filename = "2025-09-15_bf4f0c5eaef0a5a75ece5135e3676c41_cobalt-strike_poet-rat_sliver_snatch"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "c:\\Windows\\System32\\Gj.exe" ascii wide nocase
	$s3 = "Gj" ascii wide nocase
    $s4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s5 = "c:\\Windows\\System32\\bAvpYmh.exe" ascii wide nocase
	$s6 = "bAvpYmh" ascii wide nocase
    $s7 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s8 = "c:\\Windows\\System32\\HtRKEOq.exe" ascii wide nocase
	$s9 = "HtRKEOq" ascii wide nocase
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6) or ($s7 and $s8 and $s9)
}