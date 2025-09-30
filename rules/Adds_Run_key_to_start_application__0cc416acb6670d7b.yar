rule Adds_Run_key_to_start_application__0cc416acb6670d7b {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250914-zxntmaylx5"
    sha256 = "0cc416acb6670d7b3425894d7227226f8530754fd49a05f500240bc8661b53f8"
    filename = "JaffaCakes118_2d1b9bb14b6247540c9b9851bed71d93"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "pmiqghre" ascii wide nocase
	$s3 = "vxpaallrag.exe" ascii wide nocase
    $s4 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$s5 = "sabgjkwq" ascii wide nocase
    $s6 = "dsiaosjidrirghl.exe" ascii wide nocase
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6)
}