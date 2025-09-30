import "pe"

rule Modifies_Internet_Explorer_settings__3b3c0a882f7460f9 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies Internet Explorer settings"
    triage_id = "250915-nqy58syygx"
    sha256 = "3b3c0a882f7460f9f1c83c3f52b81b6e689cc07cf2da3698478f40b81e838000"
    filename = "15092025_1136_6841059370.exe.iso"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\Registry\\User\\S-1-5-21-1419306801-3438187156-704942707-1000\\SOFTWARE\\Microsoft\\Internet Explorer\\IntelliForms" ascii wide nocase
    $s2 = "Storage2" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}