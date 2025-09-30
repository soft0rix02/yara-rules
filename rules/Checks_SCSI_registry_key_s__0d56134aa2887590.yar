import "pe"

rule Checks_SCSI_registry_key_s__0d56134aa2887590 {
  meta:
    source = "Recorded Future Triage"
    description = "Checks SCSI registry key(s)"
    triage_id = "250914-zztsnagj7v"
    sha256 = "0d56134aa2887590595b26a41e8cf12e80d0e419b567c1fde0c14de6cd174bb5"
    filename = "Statement.msi"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters" ascii wide nocase
    $s2 = "Partmgr" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}