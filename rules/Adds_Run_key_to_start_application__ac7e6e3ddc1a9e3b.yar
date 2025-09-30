
rule Adds_Run_key_to_start_application__ac7e6e3ddc1a9e3b {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250914-rs584svlv4"
    sha256 = "ac7e6e3ddc1a9e3b961dfe896e6758f3915ceb62bd31b7dc1ccd1d01d296690e"
    filename = "2025-09-14_911b568d7bdcd3fbcc74647b99977f16_cobalt-strike_poet-rat_sliver_snatch"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | opened | value queried"
  strings:
    $reg1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
	$reg2 = "dHtqMfb" ascii wide nocase
    $reg3 = "c:\\Windows\\System32\\dHtqMfb.exe" ascii wide nocase
  condition:
    all of them
}