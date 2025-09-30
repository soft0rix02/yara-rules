import "pe"

rule Installs_modifies_Browser_Helper_Object__57aaf88482c026fa {
  meta:
    source = "Recorded Future Triage"
    description = "Installs/modifies Browser Helper Object"
    triage_id = "250914-zywwmayms9"
    sha256 = "57aaf88482c026fac9c64db1bda6621e459537debb23139ac0ea15b81159d46a"
    filename = "JaffaCakes118_2d1bb91b47c574b45aade3185a27d699"
    triage_score = "7"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{904ACAE8-2539-1053-6285-D84476CAAB9E}\\" ascii wide nocase
    $s2 = "ssavvenshAre" ascii wide nocase
    $s3 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{904ACAE8-2539-1053-6285-D84476CAAB9E}\\NoExplorer" ascii wide nocase
    $s4 = "1" ascii wide nocase
    $s5 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii wide nocase
    $s6 = "{904ACAE8-2539-1053-6285-D84476CAAB9E}" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}