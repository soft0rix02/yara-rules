rule Adds_Run_key_to_start_application__ccba1572239975bf {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-efn3vaeq2z"
    sha256 = "ccba1572239975bf5f60b65c9f21778321e44783dd0212a29a038189b88f1e54"
    filename = "073e42bd_file.fpx"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$s3 = "Vba32Loader" ascii wide nocase
    $s2 = "\\"C:\\Program Files (x86)\\Vba32\\Vba32Ldr.exe\\"" ascii wide nocase
  condition:
    all of them
}