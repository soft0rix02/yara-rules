rule botnet_plaintext_c2
{
    meta:
        description = "Attempts to match at least some of the strings used in some botnet variants which use plaintext communication protocols."
        author = "cip"
        family = "Gafgyt"
        date = "2025-06-02"
        yarahub_uuid = "f300f8ce-396b-4951-8489-780ea26f5435"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "334a50e61b94fd70971bee04d0a99a43"

    strings:
        $tcp = "TCP"
        $udp = "UDP"
        $udpraw = "UDPRAW"
        $randhex = "RANDHEX"
        $game = "GAME"
        $std = "STD"
        $hex = "HEX"
        $stdhex = "STDHEX"
        $vse = "VSE"
        $xmas = "XMAS"
        $crush = "CRUSH"
        $stomp = "STOMP"
        $nfodrop = "NFODROP"
        $ovh = "OVH"
        $ovhkill = "OVHKILL"


        $stop = "STOP"
        $dup = "DUP"
        $ping = "PING"

    condition:
        8 of them

}
