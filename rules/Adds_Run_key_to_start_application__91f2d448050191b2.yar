rule Adds_Run_key_to_start_application__91f2d448050191b2 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nqr2xsan5t"
    sha256 = "91f2d448050191b242113d86e4d593a629eb517436b91a2e13e92d94efb121b2"
    filename = "91f2d448050191b242113d86e4d593a629eb517436b91a2e13e92d94efb121b2.exe"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\AdobeUpdate.exe" ascii wide nocase
	$s3 = AdobeUpdate" ascii wide nocase
  condition:
    all of them
}