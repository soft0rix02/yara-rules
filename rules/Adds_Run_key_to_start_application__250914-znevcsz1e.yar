rule Adds_Run_key_to_start_application__250914-znevcsz1e {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250914-znevcsz1ez"
    triage_score = "9"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-1153236273-2212388449-1493869963-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$s3 = "GX Stable" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Programs\\Opera GX\\opera.exe" ascii wide nocase
  condition:
    all of them
}