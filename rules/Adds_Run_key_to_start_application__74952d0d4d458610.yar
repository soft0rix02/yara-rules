rule Adds_Run_key_to_start_application__74952d0d4d458610 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250916-egycxaeq4z"
    sha256 = "74952d0d4d458610402331689c40ec62607ce81d8a2037688b207fdc0cfca17d"
    filename = "2025-09-16_5caa9f31ebcfb60809e4f02ad931aa9b_acrstealer_amadey_darkgate_datper_elex_smoke-loader"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "\\"C:\\Users\\Admin\\AppData\\Local\\Microsoft Windows\\taskWin.exe\\"" ascii wide nocase
	$s3 = "Kernel System" ascii wide nocase
    $s4 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s5 = "\\"C:\\Users\\Admin\\AppData\\Local\\Microsoft Windows\\winPrsv.exe\\"" ascii wide nocase
	$s6 = "Kernel System" ascii wide nocase
  condition:
    ($s1 and $s2 and $s3) or ($s4 and $s5 and $s6)
}