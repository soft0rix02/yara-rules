import "pe"

rule Boot_or_Logon_Autostart_Execution_Active_Setup__f35b817360b6a1b4 {
  meta:
    source = "Recorded Future Triage"
    description = "Boot or Logon Autostart Execution: Active Setup"
    triage_id = "250915-nxrpqsap4t"
    sha256 = "f35b817360b6a1b4da04e3d13838f80eaef6c84a6403a70f4d4c2cacfec42270"
    filename = "server.exe"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\Software\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components" ascii wide nocase
    $s2 = "{Q5066N8G-3T4R-6L2U-SSHO-TH2E8432Y407}" ascii wide nocase
    $s3 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components\\{Q5066N8G-3T4R-6L2U-SSHO-TH2E8432Y407}\\StubPath" ascii wide nocase
    $s4 = "c:\\Games\\Updater\\install\\server.exe Restart" ascii wide nocase
    $s5 = "c:\\Games\\Updater\\install\\server.exe" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}