rule Adds_Run_key_to_start_application__696bed8f4512dbdb {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-h7q83afl9z"
    sha256 = "696bed8f4512dbdb239329e817451e489201cf74ba59e86a51c3908e22e83ecb"
    filename = "2025-09-15_6e22c55f60eeba0aa99ae3d5a17326b5_elex_gandcrab_rhadamanthys"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\2025-09-15_6e22c55f60eeba0aa99ae3d5a17326b5_elex_gandcrab_rhadamanthys.exe" ascii wide nocase
	$s3 = "dbbyburhiqc" ascii wide nocase
  condition:
    all of them
}