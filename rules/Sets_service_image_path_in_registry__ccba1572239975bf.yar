import "pe"

rule Sets_service_image_path_in_registry__ccba1572239975bf {
  meta:
    source = "Recorded Future Triage"
    description = "Sets service image path in registry"
    triage_id = "250916-efn3vaeq2z"
    sha256 = "ccba1572239975bf5f60b65c9f21778321e44783dd0212a29a038189b88f1e54"
    filename = "073e42bd_file.fpx"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Services\\Vba32dNT\\ImagePath" ascii wide nocase
    $s2 = "SysWOW64\\Drivers\\Vba32d64.sys" ascii wide nocase
    $s3 = "\\SYSTEM\\ControlSet001\\Services\\Vba32mNT\\ImagePath" ascii wide nocase
    $s4 = "\\??\\C:\\Program Files (x86)\\Vba32\\Vba32m64.sys" ascii wide nocase
    $s5 = "System32\\Drivers\\Vba32dNT.sys" ascii wide nocase
    $s6 = "\\??\\C:\\Program Files (x86)\\Vba32\\Vba32mNT.sys" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}