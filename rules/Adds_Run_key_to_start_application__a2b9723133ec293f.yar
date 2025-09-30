rule Adds_Run_key_to_start_application__a2b9723133ec293f {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nzw28sap7s"
    sha256 = "a2b9723133ec293f8267b44a382f014a6b41910629364b6dd329b123499847b5"
    filename = "2025-09-15_8ddea63141a794bfe879beb0b432b82b_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "\\"C:\\Program Files (x86)\\Windows Media Player\\unsecapp.exe\\"" ascii wide nocase
	$s3 = "unsecapp" ascii wide nocase
    $s4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s5 = "\\"C:\\Program Files (x86)\\MSBuild\\Microsoft\\Windows Workflow Foundation\\Registry.exe\\"" ascii wide nocase
	$s6 = "Registry" ascii wide nocase
	
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6)
}