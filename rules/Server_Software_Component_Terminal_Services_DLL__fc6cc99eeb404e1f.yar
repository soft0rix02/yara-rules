import "pe"

rule Server_Software_Component_Terminal_Services_DLL__fc6cc99eeb404e1f {
  meta:
    source = "Recorded Future Triage"
    description = "Server Software Component: Terminal Services DLL"
    triage_id = "250914-zn3anaykz9"
    sha256 = "fc6cc99eeb404e1f74ac93dabdae76014ce09d53736b6bff5bf6e9b1d2a6053c"
    filename = "JaffaCakes118_2d1b0547b145489482a20b1afbc4ff3f"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Services\\FastUserSwitchingCompatibility\\Parameters\\ServiceDll" ascii wide nocase
    $s2 = "C:\\Windows\\system32\\actmove.dll" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}