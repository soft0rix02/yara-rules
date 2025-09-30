import "pe"

rule Modifies_visibility_of_hidden_system_files_in_Ex__21c007d92aab822f {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies visibility of hidden/system files in Explorer"
    triage_id = "250914-zrc5yayls7"
    sha256 = "21c007d92aab822fd3e4ad4fab72dbbe222a615c43cdb90308fc41893712fc90"
    filename = "JaffaCakes118_2d1b4cbceeb91fce39f596f9f49ac0bc"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-3008489981-1977616533-741913813-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden" ascii wide nocase
    $s2 = "0" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}