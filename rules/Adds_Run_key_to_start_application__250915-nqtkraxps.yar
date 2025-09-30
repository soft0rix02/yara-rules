import "pe"

rule Adds_Run_key_to_start_application__250915-nqtkraxps {
  meta:
    source = "Recorded Future Triage"
    description = "Adds Run key to start application"
    triage_id = "250915-nqtkraxps5"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\REGISTRY\\USER\\S-1-5-21-2012121138-1878458325-808874697-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Steam" ascii wide nocase
    $s2 = "\\\"C:\\Program Files (x86)\\Steam\\steam.exe\\\" -silent" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}