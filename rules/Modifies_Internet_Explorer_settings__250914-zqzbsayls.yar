import "pe"

rule Modifies_Internet_Explorer_settings__250914-zqzbsayls {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies Internet Explorer settings"
    triage_id = "250914-zqzbsayls3"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-1356459344-867796871-4222869140-1000\\Software\\Microsoft\\Internet Explorer" ascii wide nocase
    $s2 = "Toolbar" ascii wide nocase
    $s3 = "\\REGISTRY\\USER\\S-1-5-21-1356459344-867796871-4222869140-1000\\SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar\\Locked" ascii wide nocase
    $s4 = "1" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}