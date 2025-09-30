import "pe"

rule Adds_policy_Run_key_to_start_application__f35b817360b6a1b4 {
  meta:
    source = "Recorded Future Triage"
    description = "Adds policy Run key to start application"
    triage_id = "250915-nxrpqsap4t"
    sha256 = "f35b817360b6a1b4da04e3d13838f80eaef6c84a6403a70f4d4c2cacfec42270"
    filename = "server.exe"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-155457276-1657131288-1088518942-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide nocase
    $s2 = "Run" ascii wide nocase
    $s3 = "\\REGISTRY\\USER\\S-1-5-21-155457276-1657131288-1088518942-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\Policies" ascii wide nocase
    $s4 = "c:\\Games\\Updater\\install\\server.exe" ascii wide nocase
    $s5 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide nocase
    $s6 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\Policies" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}