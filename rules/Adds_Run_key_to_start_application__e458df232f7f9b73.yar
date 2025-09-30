rule Adds_Run_key_to_start_application__e458df232f7f9b73 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nsqa4san7t"
    sha256 = "e458df232f7f9b73398043bcfc1dff13b62ef31592239ead71925061321badd4"
    filename = "15092025_1139_JINX MAKINE SPECIFICATION.rar"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$s3 = "AddInProcess32" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Roaming\\AddInProcess32.exe" ascii wide nocase
  condition:
    all of them
}