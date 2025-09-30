rule Adds_Run_key_to_start_application__f35b817360b6a1b4 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nxrpqsap4t"
    sha256 = "f35b817360b6a1b4da04e3d13838f80eaef6c84a6403a70f4d4c2cacfec42270"
    filename = "server.exe"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "c:\\Games\\Updater\\install\\server.exe" ascii wide nocase
	$s3 = "HKLM" ascii wide nocase
	$s4 = "HKCU" ascii wide nocase
  condition:
    ($s1 and $s2 and ($s3 or $s4))
}