rule Adds_Run_key_to_start_application__b9155c7b93e0e48a {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nqh41syygt"
    sha256 = "b9155c7b93e0e48a18a9a73fa81083b73e640826fbd76b4421de9990c3941668"
    filename = "2025-09-15_2c8d0d88b47c8f0c4f2e5db4435f5bba_amadey_elex_rhadamanthys_sakula_smoke-loader_stop"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\AdobeUpdate.exe" ascii wide nocase
	$s3 = "AdobeUpdate" ascii wide nocase
  condition:
    all of them
}