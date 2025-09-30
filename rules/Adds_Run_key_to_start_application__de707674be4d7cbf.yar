rule Adds_Run_key_to_start_application__de707674be4d7cbf {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-elwd4ser3y"
    sha256 = "de707674be4d7cbfe793583d717410866681d33783b30d908ab480029e28649a"
    filename = "2025-09-16_101fed558c84aa02b42fc293108a4ef7_elex_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\ProgramData\\winmgr107.exe" ascii wide nocase
	$s3 = "2" ascii wide nocase
  condition:
    all of them
}