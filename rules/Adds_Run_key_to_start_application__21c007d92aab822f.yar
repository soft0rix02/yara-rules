rule Adds_Run_key_to_start_application__21c007d92aab822f {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250914-zrc5yayls7"
    sha256 = "21c007d92aab822fd3e4ad4fab72dbbe222a615c43cdb90308fc41893712fc90"
    filename = "JaffaCakes118_2d1b4cbceeb91fce39f596f9f49ac0bc"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $s2 = "jeahuz" ascii wide nocase
    $s3 = "C:\\Users\\Admin\\jeahuz.exe" ascii wide nocase

  condition:
    all of them
}