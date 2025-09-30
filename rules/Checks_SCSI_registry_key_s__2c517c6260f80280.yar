import "pe"

rule Checks_SCSI_registry_key_s__2c517c6260f80280 {
  meta:
    source = "Recorded Future Triage"
    description = "Checks SCSI registry key(s)"
    triage_id = "250914-zm75hsz1es"
    sha256 = "2c517c6260f80280da0f0c840e83eba000f138f7f36880cf2f4be5466f144ec6"
    filename = "Installer2.0.zip"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters" ascii wide nocase
    $s2 = "Partmgr" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}