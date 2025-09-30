rule Adds_Run_key_to_start_application__8d8e9241154d1b9e {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-efcptazxfx"
    sha256 = "8d8e9241154d1b9eb46755fe3b83639a071dfa732390ad14b1accfac4d341804"
    filename = "2025-09-16_d47aa35344fd1d951dac1adfbfafb7b3_drokbk_elex_rhadamanthys_smoke-loader_stealc_stop_tofsee"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\sppsvc" ascii wide nocase
    $s2 = "\\\"C:\\Program Files (x86)\\MSBuild\\sppsvc.exe\\\"" ascii wide nocase
	
    $s3 = "\\REGISTRY\\USER\\S-1-5-21-636600838-1632888396-3521553955-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\fontdrvhost" ascii wide nocase
    $s4 = "\\\"C:\\589ba37997a284d35c\\fontdrvhost.exe\\\"" ascii wide nocase
	
    $s5 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\fontdrvhost" ascii wide nocase
	$s9 = "\\\"C:\\Program Files (x86)\\Internet Explorer\\it-IT\\fontdrvhost.exe\\\"" ascii wide nocase

    $s6 = "\\REGISTRY\\USER\\S-1-5-21-636600838-1632888396-3521553955-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SearchApp" ascii wide nocase
    $s7 = "\\\"C:\\Recovery\\WindowsRE\\SearchApp.exe\\\"" ascii wide nocase
	
  condition:
    all of them
}