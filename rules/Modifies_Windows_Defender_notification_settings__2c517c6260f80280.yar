import "pe"

rule Modifies_Windows_Defender_notification_settings__2c517c6260f80280 {
  meta:
    source = "Recorded Future Triage"
    description = "Modifies Windows Defender notification settings"
    triage_id = "250914-zm75hsz1es"
    sha256 = "2c517c6260f80280da0f0c840e83eba000f138f7f36880cf2f4be5466f144ec6"
    filename = "Installer2.0.zip"
    triage_score = "10"
    indicators = "registry: created | set(str) | set(int)"
  strings:
    $s1 = "\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications\\DisableNotifications" ascii wide nocase
    $s2 = "1" ascii wide nocase
    $s3 = "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center" ascii wide nocase
    $s4 = "Notifications" ascii wide nocase
    $s5 = "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications\\DisableNotifications" ascii wide nocase
    $s6 = "\\SOFTWARE\\Microsoft\\Windows Defender Security Center" ascii wide nocase
  condition:
    ( uint16(0) == 0x5A4D or defined(pe) ) and
    2 of them
}