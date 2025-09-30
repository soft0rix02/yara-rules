rule Adds_Run_key_to_start_application__a70c31eb46384341 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-h8lpzafm3w"
    sha256 = "a70c31eb4638434115018f3c18f5ae73c2e8a1febdf04500fee0f1c3cf7b629a"
    filename = "a70c31eb4638434115018f3c18f5ae73c2e8a1febdf04500fee0f1c3cf7b629a"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe" ascii wide nocase
	$s3 = "MicroMedia" ascii wide nocase
  condition:
    all of them
}