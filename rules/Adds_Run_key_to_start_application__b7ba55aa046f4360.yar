rule Adds_Run_key_to_start_application__b7ba55aa046f4360 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-jbfm5afm7y"
    sha256 = "b7ba55aa046f4360f88b704867c56b4407e66939eeb408109b9a4c234ef32893"
    filename = "2025-09-15_7ee39ff9ddeee49bfcc78910d6c62caf_elex_qilin"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\Windows\\microsofthelp.exe" ascii wide nocase
	$s3 = microsofthelp" ascii wide nocase
  condition:
    all of them
}