rule njRat_suspicious_functionality_and_dropped_payloads
{
    meta:
        author = "R4ruk"
        date = "2025-09-07"
        description = "Matches NjRat payload with strings representing rat functionality calls or payloads delivered."
        reference = "https://sidequest-lab.com/2025/09/07/njrat-part-2-c2-command-investigation/"
        yarahub_uuid                 = "f8d2fa88-2c10-4313-bf3a-3b7121a23f3a"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        yarahub_reference_md5        = "9a5289879140239767ecd6437f6ffd3b"

    strings:
        $s1="89c43fcf-5e52-4be7-a719-a26139ce636a.exe" base64wide
        $s2="3d847c5c-4f5a-4918-9e07-a96cea49048d.exe" base64wide
        $s3="\\ngrok.exe" base64wide
        $s4="HKEY_CURRENT_USER\\SOFTWARE" base64wide
        $s5="7zip\\7z.exe" base64wide
        $s6="Xchat" base64wide
        $s7="GETWsoundPlu" base64wide
        $s8="GETWCamPlu" base64wide
        $s9="RunBotKiller" base64wide
        $s10="WinSc32.exe" wide
        $s11="Blackbullet" base64wide
        $s12="<Violet>" base64wide

    condition:
        any of them
}