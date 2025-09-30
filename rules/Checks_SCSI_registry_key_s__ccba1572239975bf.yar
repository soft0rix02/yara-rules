import "pe"

rule Checks_SCSI_registry_key_s__ccba1572239975bf {
  meta:
    source = "Recorded Future Triage"
    description = "Checks SCSI registry key(s)"
    triage_id = "250916-efn3vaeq2z"
    sha256 = "ccba1572239975bf5f60b65c9f21778321e44783dd0212a29a038189b88f1e54"
    filename = "073e42bd_file.fpx"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters" ascii wide nocase
    $s2 = "Partmgr" ascii wide nocase
    $s3 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters\\Partmgr\\PartitionTableCache" ascii wide nocase
    $s4 = "00000000040000001cfceb9b5e7901d20000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000c01200000000ffffffff0000000027010100000800001cfceb9b00000000000010000000000000000000000000000000000000000000" ascii wide nocase
    $s5 = "\\SYSTEM\\ControlSet001\\Enum\\SCSI\\Disk&Ven_WDC&Prod_WDS100T2B0A\\4&215468a5&0&000000\\Device Parameters\\Partmgr\\SnapshotDataCache" ascii wide nocase
    $s6 = "534e41505041525401000000700000008ec7416a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}