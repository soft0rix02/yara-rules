import "pe"

rule Modifies_Internet_Explorer_settings__dc1dc2c0daed9915 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies Internet Explorer settings"
    triage_id = "250915-h5rf2sfl7t"
    sha256 = "dc1dc2c0daed9915f54fa3e0b61e7582c68b86d69c607a2197c4b9f9dd04a5d3"
    filename = "dc1dc2c0daed9915f54fa3e0b61e7582c68b86d69c607a2197c4b9f9dd04a5d3.rar"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-2012121138-1878458325-808874697-1000\\SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar\\Locked" ascii wide nocase
    $s2 = "1" ascii wide nocase
    $s3 = "\\REGISTRY\\USER\\S-1-5-21-2012121138-1878458325-808874697-1000\\SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar" ascii wide nocase
    $s4 = "ShellBrowser" ascii wide nocase
    $s5 = "\\REGISTRY\\USER\\S-1-5-21-2012121138-1878458325-808874697-1000\\SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser\\ITBar7Layout" ascii wide nocase
    $s6 = "13000000000000000000000020000000100000000000000001000000010700005e010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii wide nocase
    $s7 = "\\REGISTRY\\USER\\S-1-5-21-2012121138-1878458325-808874697-1000\\Software\\Microsoft\\Internet Explorer" ascii wide nocase
    $s8 = "Toolbar" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}