rule Adds_Run_key_to_start_application__250915-jb8c5sfm8 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-jb8c5sfm8y"
    filename = "2025-09-15_7fdbe40c711a250163045fccec17ea4c_amadey_elex_rhadamanthys_sakula_smoke-loader_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$s3 = "AdobeUpdate" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\AdobeUpdate.exe" ascii wide nocase
  condition:
    all of them
}