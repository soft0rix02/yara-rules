import "pe"

rule Sets_service_image_path_in_registry__0d56134aa2887590 {
  meta:
    source = "Recorded Future Triage"
    description = "Sets service image path in registry"
    triage_id = "250914-zztsnagj7v"
    sha256 = "0d56134aa2887590595b26a41e8cf12e80d0e419b567c1fde0c14de6cd174bb5"
    filename = "Statement.msi"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Services\\ScreenConnect Client (4205d3d2c4079896)\\ImagePath" ascii wide nocase
    $s2 = "\\\"C:\\Program Files (x86)\\ScreenConnect Client (4205d3d2c4079896)\\ScreenConnect.ClientService.exe\\\" \\\"?e=Access&y=Guest&h=administrator.smartlaunchzone.com&p=8041&s=2b03ad68-a1b3-43f3-88bb-b9ab08e93aaa&k=BgIAAACkAABSU0ExAAgAAAEAAQDh" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}