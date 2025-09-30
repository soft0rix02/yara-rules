import "pe"

rule Sets_service_image_path_in_registry__2bd7a337f1fd73f4 {
  meta:
    source = "Recorded Future Triage"
    description = "Sets service image path in registry"
    triage_id = "250915-h7528afm2w"
    sha256 = "2bd7a337f1fd73f4797bf1f97d16ea87902f2dbb7725095c23c72b929bfc6b5c"
    filename = "2bd7a337f1fd73f4797bf1f97d16ea87902f2dbb7725095c23c72b929bfc6b5c"
    triage_score = "8"
    indicators = "registry: created | set(str) | set(int) | set(data)"
  strings:
    $s1 = "\\SYSTEM\\ControlSet001\\Services\\\\ImagePath" ascii wide nocase
    $s2 = "\\??\\e" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    1 of them
}