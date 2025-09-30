rule Adds_Run_key_to_start_application__d79c1175188b3411 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-h5cynafl6v"
    sha256 = "d79c1175188b3411bbf6e55dd9212f40f0162cbd73bb817ad13085c71a496305"
    filename = "d79c1175188b3411bbf6e55dd9212f40f0162cbd73bb817ad13085c71a496305"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\wiseman.exe" ascii wide nocase
	$s3 = "Wiseman" ascii wide nocase

  condition:
    all of them
}