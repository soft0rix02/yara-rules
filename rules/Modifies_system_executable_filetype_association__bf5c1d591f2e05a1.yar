rule Modifies_system_executable_filetype_association__bf5c1d591f2e05a1 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies system executable filetype association"
    triage_id = "250914-znnghaykz6"
    sha256 = "bf5c1d591f2e05a1b741feff2db7dc34fae66432bcce18e92fcbf5a0dcc18e9b"
    filename = "JaffaCakes118_2d1ad317dccdd5c9f8f69a6b08ca6fce"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s2 = "C:\\Windows\\SysWow64\\concp32.exe \\\"%1\\\" %*" ascii wide nocase
	$s1 = "\\shell\\open\\command" wide nocase

  condition:
    all of them
}