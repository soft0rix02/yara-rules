rule Event_Triggered_Execution_Image_File_Execution_O__2c517c6260f80280 {
  meta:
    source = "Recorded Future Triage"
    description = "Event Triggered Execution: Image File Execution Options Injection"
    triage_id = "250914-zm75hsz1es"
    sha256 = "2c517c6260f80280da0f0c840e83eba000f138f7f36880cf2f4be5466f144ec6"
    filename = "Installer2.0.zip"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" ascii wide nocase
	$s3 = "MicrosoftEdgeUpdate.exe" ascii nocase
    $s4 = "C:\\Windows\\System32\\cmd.exe /c start install.exe" ascii wide nocase
  condition:
    all of them
}