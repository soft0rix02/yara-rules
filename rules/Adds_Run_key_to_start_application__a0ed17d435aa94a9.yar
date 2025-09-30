rule Adds_Run_key_to_start_application__a0ed17d435aa94a9 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-egbtxaeq3z"
    sha256 = "a0ed17d435aa94a9179711bd5ac89d3657491b1db4be3e5ef3469a858e3378b6"
    filename = "2025-09-16_68b53f984dcbb155eedec4d52dc4b4db_poet-rat_sliver_snatch"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "c:\\Windows\\System32\\KhSLm.exe" ascii wide nocase
	$s3 = "KhSLm" ascii wide nocase
    $s4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s5 = "c:\\Windows\\System32\\PRkKzZF.exe" ascii wide nocase
	$s6 = "PRkKzZF" ascii wide nocase
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6)
}