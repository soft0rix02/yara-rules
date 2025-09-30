import "pe"

rule Checks_SCSI_registry_key_s__250915-nxz14sxpz {
  meta:
    source = "Recorded Future Triage"
    description = "Checks SCSI registry key(s)"
    triage_id = "250915-nxz14sxpz9"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters" ascii wide nocase
    $s2 = "Partmgr" ascii wide nocase
    $s3 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters\\Partmgr\\PartitionTableCache" ascii wide nocase
    $s4 = "0000000004000000c2be3778b8b6b5f50000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000c01200000000ffffffff000000002701010000080000c2be377800000000000010000000000000000000000000000000000000000000" ascii wide nocase
    $s5 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters\\Partmgr\\SnapshotDataCache" ascii wide nocase
    $s6 = "534e41505041525401000000700000008ec7416a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}